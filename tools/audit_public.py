"""Reproduce actual public checks from this distribution; keep all attempts."""
import importlib.metadata,json,os,platform,subprocess,sys,uuid
from pathlib import Path
ROOT=Path(__file__).absolute().parents[1]

def main():
    output=ROOT/'audit-output'/uuid.uuid4().hex[:12];output.mkdir(parents=True,exist_ok=False)
    receipts=[];env={k:v for k,v in os.environ.items() if k.upper()!='PYTHONPATH' and not k.upper().startswith('GIT_')}
    env['PYTHONDONTWRITEBYTECODE']='1'
    fixtures=Path(env.get('PGOP1_TEST_ROOT',str(output/'fixtures'))).absolute();fixtures.mkdir(parents=True,exist_ok=True)
    env['PGOP1_TEST_ROOT']=str(fixtures)
    def run(label,args):
        p=subprocess.run([sys.executable,'-B',*args],cwd=ROOT,env=env,capture_output=True)
        (output/(label+'.stdout.log')).write_bytes(p.stdout);(output/(label+'.stderr.log')).write_bytes(p.stderr)
        receipts.append({'label':label,'command':[sys.executable,'-B',*map(str,args)],'cwd':str(ROOT),'exit_code':p.returncode})
        if p.returncode:raise RuntimeError(label+' failed; preserved stdout/stderr')
        return p.stdout
    status='PASS';error=None
    try:
        run('integrity',['tools/audit_distribution.py','--output',str(output/'HISTORY_GRAPH_AND_OBJECTS.json')])
        run('pip-check',['-m','pip','check'])
        run('tests',['-m','unittest','discover','-s','tests','-p','test_*.py','-v'])
        for op,args in [('availability',[]),('catalog',[]),('query',['RUN012_PUBLIC']),('verify',['RUN012_PUBLIC'])]:
            run('cli-'+op,['runtime/candidate/pg_i7.py','--profile','public','--json',op,*args])
        demo=json.loads(run('demo',['tools/demo_public.py','--output',str(output/'reports')]))
        run('artifacts',['tools/audit_distribution.py','--artifacts',str(Path(demo['handoff']).parent),'--output',str(output/'ARTIFACT_VERIFICATION.json')])
        run('sdk-public',['tools/test_public_mcp.py',str(output/'sdk-public')])
        if (ROOT/'runtime/candidate/evidence_handoff.py').exists():
            run('demo-evidence',['tools/create_evidence_demo.py',str(output/'evidence-demo')])
            results=json.loads((output/'evidence-demo/DEMO_RESULTS.json').read_bytes())
            for label,case in results.items():
                run('sdk-'+label,['tools/test_evidence_mcp.py',case['catalog_root'],str(output/('sdk-'+label)),'FIXTURE'])
            sys.path[:0]=[str(ROOT/'runtime'),str(ROOT/'tests')]
            from test_engineering_handoff_v02 import fixture
            b=output/'engineering-demo';b.mkdir();_,cfg,_=fixture(b.absolute())
            run('sdk-engineering',['tools/test_engineering_mcp.py',str(cfg),str(output/'sdk-engineering'),'SYNTHETIC_A'])
        run('integrity-final',['tools/audit_distribution.py','--expected-inventory',str(output/'HISTORY_GRAPH_AND_OBJECTS.json')])
    except Exception as exc:status='FAIL';error=str(exc)
    result={'status':status,'error':error,'python':sys.version,'os':platform.platform(),'dependencies':sorted([{'name':d.metadata['Name'],'version':d.version,'license_expression':d.metadata.get('License-Expression'),'license':d.metadata.get('License')} for d in importlib.metadata.distributions()],key=lambda x:x['name'].lower()),'commands':receipts,'linux':'EXECUTED' if sys.platform.startswith('linux') else 'NOT_EXECUTED','scope':'public/synthetic distribution only; no historical re-execution'}
    (output/'TEST_RESULTS.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':status,'error':error,'results':str(output/'TEST_RESULTS.json')}))
    return 0 if status=='PASS' else 1
if __name__=='__main__':sys.exit(main())
