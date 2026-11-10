"""Actual six-operation API/CLI/SDK parity, separate stdio process and restart."""
import argparse
import asyncio
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'runtime'))
from candidate import i7_api


async def run(config, output, package_id):
    output.mkdir(parents=True,exist_ok=False)
    reports=output/'reports'
    api=i7_api.engineering_profile(package_root=config,output_root=reports)
    trace=[]
    params=StdioServerParameters(command=sys.executable,args=['-B','-m','pg_i7_mcp.server','--profile','engineering-local','--package-root',str(config),'--output-root',str(reports)],cwd=str(ROOT),env={'PYTHONDONTWRITEBYTECODE':'1'})
    def cli(operation,args):
        cmd=[sys.executable,'-B',str(ROOT/'runtime/candidate/pg_i7.py'),'--profile','engineering-local','--package-root',str(config),'--output-root',str(reports),'--json',operation]
        if operation in {'query','verify','generate'}:cmd.append(args['package_id'])
        if operation=='generate':cmd += [args['receipt_id'],args['request_key']]
        if operation=='read':cmd += [args['report_id'],'--artifact',args.get('artifact','FINAL_HANDOFF.md'),'--offset',str(args.get('offset',0)),'--limit',str(args.get('limit',8000))]
        result=subprocess.run(cmd,capture_output=True,text=True,timeout=25)
        assert result.returncode==0,result.stderr+result.stdout
        return json.loads(result.stdout)
    async def call(session,operation,args,error=False):
        result=await session.call_tool(operation,args)
        trace.append({'operation':operation,'arguments':args,'result':result.model_dump(mode='json',by_alias=True)})
        assert bool(result.is_error)==error,str(result)
        if not error:
            value=result.structured_content
            assert value==getattr(api,operation)(**args)==cli(operation,args),operation
            return value
    with (output/'stderr.log').open('w',encoding='utf8') as err:
        async with stdio_client(params,errlog=err) as (reader,writer):
            async with ClientSession(reader,writer,read_timeout_seconds=25) as session:
                await session.initialize();tools=await session.list_tools()
                trace.append({'tools':tools.model_dump(mode='json',by_alias=True)})
                assert {t.name for t in tools.tools}=={'availability','catalog','query','verify','generate','read'}
                assert all(t.output_schema is not None for t in tools.tools)
                assert all(t.input_schema.get('additionalProperties') is False for t in tools.tools)
                for t in tools.tools:
                    assert not ({'path','source_root','package_root','output_root','script','shell'} & set(t.input_schema.get('properties',{})))
                await call(session,'availability',{});await call(session,'catalog',{})
                await call(session,'query',{'package_id':package_id})
                receipt=await call(session,'verify',{'package_id':package_id})
                args={'package_id':package_id,'receipt_id':receipt['receipt_id'],'request_key':'engineering-sdk-parity-001'}
                generated=await call(session,'generate',args)
                hashes={}
                for artifact in ['REPORT.json','FINAL_HANDOFF.md','MANIFEST.json']:
                    parts=[];offset=0
                    while True:
                        page=await call(session,'read',{'report_id':generated['report_id'],'artifact':artifact,'offset':offset,'limit':997})
                        parts.append(page['content'])
                        if page['next_offset'] is None:break
                        offset=page['next_offset']
                    body=''.join(parts).encode('utf8');hashes[artifact]=hashlib.sha256(body).hexdigest()
                    assert hashes[artifact]==page['sha256']==hashlib.sha256((reports/generated['report_id']/artifact).read_bytes()).hexdigest()
                for name,arguments in [('query',{'package_id':'../secret'}),('verify',{'package_id':package_id,'verdict':'PASS'}),('catalog',{'offset':'0'}),('query',{'package_id':package_id,'path':'private'}),('read',{'report_id':generated['report_id'],'artifact':'REQUEST.json'})]:
                    await call(session,name,arguments,error=True)
        async with stdio_client(params,errlog=err) as (reader,writer):
            async with ClientSession(reader,writer,read_timeout_seconds=25) as session:
                await session.initialize();assert await call(session,'generate',args)==generated
                await call(session,'read',{'report_id':generated['report_id'],'limit':16000})
    (output/'MCP_TRACE.json').write_text(json.dumps(trace,indent=2)+'\n',encoding='utf8')
    result={'CLI_ENGINEERING_E2E':'PASS','MCP_SDK_ENGINEERING_E2E':'PASS','API_CLI_MCP_PARITY':'EXACT_NO_EXCLUSIONS','restart':'PASS','pagination':'ALL_THREE_ARTIFACTS_NEXT_OFFSET_NULL','receipt_id':receipt['receipt_id'],'report':generated,'hashes':hashes,'CODEX_ENGINEERING_MCP_E2E':'NOT_EXECUTED_BY_SDK_TEST'}
    (output/'RESULT.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8');print(json.dumps(result))


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('config',type=Path);parser.add_argument('output',type=Path);parser.add_argument('package_id');a=parser.parse_args()
    asyncio.run(run(a.config.absolute(),a.output.absolute(),a.package_id))
