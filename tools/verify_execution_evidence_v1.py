"""Independent evaluator/reopener. No execution producer or worker import.

Requires two external trust roots and expected request ID from trusted caller.
Shared CPython/native I/O/Engine are explicit limits, not external attestation.
"""
from pathlib import Path
import math
import os
import tempfile
import sys
ROOT=Path(__file__).absolute().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'runtime')]
from candidate.execution_contract_v1 import (SCHEMA,SCOPE,HANDOFF,MAX_PACKET,MAX_STREAM,
    require,strict_json,canonical,digest,pin,hash_value,validate_catalog,packet_identity,envelope,closed_formulation)
from candidate.document_claims_v1 import document_span
from candidate.semantic_memory_v1 import recover
from candidate.windows_safe_io_v2 import Directory,absolute,component,safe_read
from tools import verify_semantic_engine_v1 as static_verifier


def _static(files,members,expected):
    require(type(members) is dict and set(members)==set(static_verifier.LIMITS)|{'MANIFEST.json'},'STATIC_MEMBERSHIP')
    require(all(type(n) is str and n in files for n in members.values()),'STATIC_FILE')
    with tempfile.TemporaryDirectory(prefix='execution-static-reopen-') as tmp:
        for name,member in members.items():(Path(tmp)/name).write_bytes(files[member])
        result,_=static_verifier.verify_bundle(Path(tmp),expected)
    return result


def derive(catalog,static,receipt,files):
    """Recalculate closed predicates from pinned raw bytes; text never decides."""
    require(type(receipt) is dict and set(receipt)=={'schema','run_id','request_id','identities_unchanged','cases'}
            and receipt['schema']=='pgop1.execution-receipt.v1'
            and receipt['run_id']==packet_identity(digest(canonical(catalog)),receipt['request_id'])
            and type(receipt['identities_unchanged']) is bool,'RECEIPT_SCHEMA')
    cases=receipt['cases'];require(type(cases) is list and len(cases)==len(catalog['cases']),'RECEIPT_CASES')
    bodies={p['path']:bytes.fromhex(p['raw_hex']) for p in strict_json(files['BASE_SNAPSHOT.json'])['captures']}
    rows=[];number=0;used=set()
    static_sha=digest(canonical(catalog['static_catalog']))
    for claim,case in zip(catalog['cases'],cases):
        require(type(case) is dict and set(case)=={'case_id','steps','effects'} and case['case_id']==claim['case_id'],'CASE_IDENTITY')
        action=claim['action']
        actions=(['static_generate','static_recover']+(['static_reject'] if action=='snapshot_rejection' else [])
                 if action.startswith('snapshot_') else [action])
        steps=case['steps'];effects=case['effects']
        require(type(steps) is list and 1<=len(steps)<=len(actions) and type(effects) is dict
                and set(effects)<= {'artifact','bundle','recovered','mutation','rejection'},'EFFECT_SCHEMA')
        complete=len(steps)==len(actions);exits=[]
        for index,step in enumerate(steps):
            require(type(step) is dict and set(step)=={'start','close','prefix'},'STEP_SCHEMA')
            prefix=f'STEP_{number:02d}';start=step['start'];close=step['close']
            require(step['prefix']==prefix and type(start) is dict and type(close) is dict,'STEP_ORDER')
            require(set(start) in [set(['schema','step','action','test_identity','argv','cwd','env_allowlist','env_redactions','timeout_seconds','max_stream_bytes','started_at','pid','process_state']),
                                   set(['schema','step','action','test_identity','argv','cwd','env_allowlist','env_redactions','timeout_seconds','max_stream_bytes','started_at','pid','process_state','error'])],'START_FIELDS')
            require(set(close)=={'schema','step','action','pid','process_state','exit_code','ended_at','reader_errors','streams'},'CLOSE_FIELDS')
            require(start['schema']=='pgop1.execution-start.v1' and close['schema']=='pgop1.execution-close.v1'
                    and type(start['step']) is int and type(close['step']) is int and start['step']==close['step']==number
                    and start['action']==close['action']==actions[index]
                    and start['test_identity']=='tools/execution_worker_v1.py:'+actions[index],'TEST_IDENTITY')
            require(type(start['argv']) is list and len(start['argv'])==8 and all(type(x) is str for x in start['argv']), 'ARGV')
            require(start['argv'][0]==str(ROOT/'.venv/Scripts/python.exe') and start['argv'][1:4]==['-I','-B','-X']
                    and start['argv'][5]==str(ROOT/'tools/execution_worker_v1.py')
                    and start['argv'][6]==actions[index] and start['argv'][7]==start['cwd'],'FIXED_COMMAND')
            require(start['argv'][4]=='pycache_prefix='+str(Path(start['cwd'])/f'cache{number}'),'PYCACHE_IDENTITY')
            require(type(start['cwd']) is str and absolute(start['cwd'])[0].upper()=='D:\\','CWD')
            require(start['max_stream_bytes']==MAX_STREAM and type(start['max_stream_bytes']) is int,'STREAM_LIMIT')
            require(type(start['env_allowlist']) is dict and set(start['env_allowlist'])<= {'SystemRoot','WINDIR','TEMP','TMP','PYTHONIOENCODING'}
                    and {'TEMP','TMP','PYTHONIOENCODING'}<=set(start['env_allowlist'])
                    and start['env_redactions']=='ALL_OTHER_VARIABLES_EXCLUDED','ENVIRONMENT')
            env=start['env_allowlist'];temp=str(Path(start['cwd'])/f'temp{number}')
            require(all(type(value) is str and 1<=len(value)<=1024 for value in env.values())
                    and env['TEMP']==env['TMP']==temp and env['PYTHONIOENCODING']=='utf-8','ENVIRONMENT_VALUES')
            for name in ('SystemRoot','WINDIR'):
                if name in env:absolute(env[name])
            expected_timeout=0.15 if actions[index]=='timeout' else (45 if actions[index].startswith('static_') else 5)
            require(type(start['timeout_seconds']) is type(expected_timeout)
                    and start['timeout_seconds']==expected_timeout,'TIMEOUT_POLICY_TYPE')
            for value in (start['started_at'],close['ended_at']):
                require(type(value) in (int,float) and math.isfinite(value) and value>=0,'TIMESTAMP_TYPE')
            require(start['process_state'] in {'STARTED','LAUNCH_FAILED'}
                    and (start['process_state']=='LAUNCH_FAILED')==(close['process_state']=='LAUNCH_FAILED'),'STATE_TRANSITION')
            require(('error' in start)==(start['process_state']=='LAUNCH_FAILED'),'LAUNCH_ERROR_FIELDS')
            if 'error' in start:require(type(start['error']) is str and 1<=len(start['error'])<=64,'LAUNCH_ERROR_TYPE')
            require(type(close['pid']) is int and close['pid']>0 and type(start['pid']) is int and close['pid']==start['pid']
                    or (close['pid'] is None and start['pid'] is None and close['process_state']=='LAUNCH_FAILED'),'PID')
            require(close['process_state'] in {'COMPLETED','TRUNCATED','TIMED_OUT','LAUNCH_FAILED','INTERRUPTED'},'PROCESS_STATE')
            require(type(close['exit_code']) is int or close['exit_code'] is None,'EXIT_TYPE')
            require(type(close['reader_errors']) is list and all(type(x) is str for x in close['reader_errors']),'READER_ERRORS')
            require(type(close['streams']) is dict and set(close['streams'])=={'stdout','stderr'},'STREAM_MEMBERSHIP')
            for name in ('stdout','stderr'):
                member=prefix+'.'+name+'.bin';used.add(member)
                stream=close['streams'][name]
                require(type(stream) is dict and set(stream)=={'bytes','sha256','truncated'} and type(stream['bytes']) is int
                        and type(stream['truncated']) is bool and 0<=stream['bytes']<=MAX_STREAM,'STREAM_PIN')
                require(member in files and pin(files[member])=={k:stream[k] for k in ('bytes','sha256')},'STREAM_BYTES')
                complete=complete and not stream['truncated']
            for kind,value in [('START',start),('CLOSE',close)]:
                member=prefix+'.'+kind+'.json';used.add(member)
                require(member in files and files[member]==canonical(value),'STATE_RECEIPT_BYTES')
            complete=complete and close['process_state']=='COMPLETED' and start['process_state']=='STARTED' and not close['reader_errors'] and type(close['exit_code']) is int
            exits.append(close['exit_code']);number+=1
        # An incomplete sequence never admits a definitive behavioral verdict.
        doc=claim['document'];span=document_span(bodies[doc['path']],doc['start_line'],doc['end_line'])
        literal_ok=digest(span)==doc['span_sha256']
        row=dict(claim=claim,run_id=receipt['run_id'],snapshot_id=static['snapshot_id'],literal_span_hex=span.hex(),
                 expected=claim['expected'],observed=None,verdict='INSUFFICIENT_EVIDENCE',reason='INCOMPLETE_OBSERVATION',
                 coverage='THIS_RUN_ONLY',documentary_claim_verdict='NOT_PROVEN',limitations=SCOPE)
        if claim['scope']!='THIS_RUN_ONLY':row['reason']='GENERAL_GUARANTEE_NOT_PROVEN'
        elif claim['formulation']!=closed_formulation(claim):row['reason']='FORMULATION_OUTSIDE_CLOSED_CONTRACT'
        elif not literal_ok:row['reason']='DOCUMENT_SPAN_NOT_VERIFIED'
        elif not receipt['identities_unchanged']:row['reason']='IDENTITY_CHANGED'
        elif complete:
            predicate=claim['predicate'];observed=None;admitted=True
            if predicate=='process_exit_observed':observed=exits[-1]
            elif predicate=='artifact_bytes_observed':
                if 'artifact' in effects:
                    member=effects['artifact'];require(member==claim['case_id']+'.artifact.bin' and member in files,'ARTIFACT_MEMBER');used.add(member)
                    observed=pin(files[member])
                else:admitted=False;row['reason']='ARTIFACT_NOT_OBSERVED'
            else:
                admitted=action in {'snapshot_roundtrip','snapshot_rejection'} and set(effects)==({'bundle','recovered','mutation','rejection'} if action=='snapshot_rejection' else {'bundle','recovered'})
                row['reason']='EFFECT_RELATION_NOT_ADMITTED'
                if admitted:
                    members=effects['bundle'];used.update(members.values())
                    actual=_static(files,members,static_sha)
                    recovered=effects['recovered'];require(recovered==claim['case_id']+'.recovered.json' and recovered in files,'RECOVERY_MEMBER');used.add(recovered)
                    require(canonical(actual)==canonical(static) and files[recovered]==canonical(actual),'ROUNDTRIP_BYTES')
                    require(exits[:2]==[0,0],'ROUNDTRIP_PROCESS_RESULT')
                    observed='ROUNDTRIP'
                    if action=='snapshot_rejection':
                        mutation=effects['mutation'];require(type(mutation) is dict and set(mutation)=={'member','before_hex','after_hex','after_step','before_step'},'MUTATION_FIELDS')
                        before=bytes.fromhex(mutation['before_hex']);after=bytes.fromhex(mutation['after_hex'])
                        require(mutation['member']=='INTEGRATION.json' and before==files[members['INTEGRATION.json']] and after==before+b' '
                                and mutation['after_step']==steps[1]['prefix'] and mutation['before_step']==steps[2]['prefix'],'MUTATION_WITNESS')
                        with tempfile.TemporaryDirectory(prefix='execution-rejection-replay-') as tmp:
                            for n,m in members.items():(Path(tmp)/n).write_bytes(after if n=='INTEGRATION.json' else files[m])
                            reason=None
                            try:static_verifier.verify_bundle(Path(tmp),static_sha)
                            except ValueError as exc:reason=str(exc)
                        member=effects['rejection'];require(member==claim['case_id']+'.rejection.json' and member in files,'REJECTION_MEMBER');used.add(member)
                        require(reason=='SOURCE_HASH' and files[member]==canonical(dict(reason=reason,exception='ValueError')) and exits[2]==23,'EXACT_REJECTION_WITNESS')
                        observed='REJECTION'
            if admitted:
                row.update(observed=observed,verdict='SUPPORTED' if canonical(observed)==canonical(claim['expected']) else 'CONTRADICTED',reason='CLOSED_PREDICATE_OBSERVATION')
        # Every effect member is accounted even for abstentions, never silently omitted.
        for key in ('artifact','recovered','rejection'):
            if key in effects:
                require(type(effects[key]) is str and effects[key] in files,'EFFECT_MEMBER');used.add(effects[key])
        if 'bundle' in effects:
            require(type(effects['bundle']) is dict,'EFFECT_BUNDLE');used.update(effects['bundle'].values())
        rows.append(row)
    fixed={'CATALOG.json','REQUEST.json','RECEIPT.json','CODE.json','EXECUTABLE.json'}|{'BASE_'+n for n in (*static_verifier.LIMITS,'MANIFEST.json')}
    require(set(files)==fixed|used or set(files)==fixed|used|{'REPORT.json','MEMORY.json','FINAL_HANDOFF.md'},'PACKET_MEMBERSHIP')
    return rows


def verify_bundle(folder,catalog_sha256,trusted_run_sha256,expected_request_id):
    require(os.name=='nt','WINDOWS_ONLY');hash_value(catalog_sha256);hash_value(trusted_run_sha256)
    with Directory(folder) as held:
        raw=safe_read(folder,'MANIFEST.json',trusted_run_sha256,1_000_000).raw
        manifest=strict_json(raw)
        require(raw==canonical(manifest) and type(manifest) is dict and set(manifest)=={'schema','catalog_sha256','run_id','files'}
                and manifest['schema']=='pgop1.execution-manifest.v1' and manifest['catalog_sha256']==catalog_sha256
                and manifest['run_id']==packet_identity(catalog_sha256,expected_request_id),'EXTERNAL_RUN_ANCHOR')
        members=manifest['files'];require(type(members) is dict and 1<=len(members)<=400,'MANIFEST_COUNT')
        require(set(os.listdir(folder))==set(members)|{'MANIFEST.json'},'DIRECTORY_MEMBERSHIP')
        files={};total=0
        for name,meta in members.items():
            component(name)
            require(type(meta) is dict and set(meta)=={'bytes','sha256'} and type(meta['bytes']) is int and 0<=meta['bytes']<=MAX_PACKET,'FILE_PIN')
            hash_value(meta['sha256']);total+=meta['bytes'];require(total<=MAX_PACKET,'PACKET_LIMIT')
            body=safe_read(folder,name,meta['sha256'],meta['bytes']).raw
            require(len(body)==meta['bytes'],'FILE_LENGTH');files[name]=body
        catalog=validate_catalog(strict_json(files['CATALOG.json']),catalog_sha256)
        require(files['CATALOG.json']==canonical(catalog),'CANONICAL_CATALOG')
        request=dict(schema=SCHEMA,request_id=expected_request_id,run_id=manifest['run_id'],catalog_sha256=catalog_sha256)
        require(files['REQUEST.json']==canonical(request),'REQUEST_REPLAY')
        code=strict_json(files['CODE.json']);require(type(code) is dict and set(code)==set(catalog['code_pins']),'CODE_CAPTURE_MEMBERSHIP')
        for name,text in code.items():
            require(type(text) is str and len(text)<=524288,'CODE_CAPTURE_SIZE')
            body=bytes.fromhex(text);require(body.hex()==text and digest(body)==catalog['code_pins'][name],'CODE_CAPTURE_HASH')
        executable=strict_json(files['EXECUTABLE.json'])
        require(type(executable) is dict and set(executable)=={'bytes','sha256'} and type(executable['bytes']) is int and executable['bytes']>0
                and executable['sha256']==catalog['executable_sha256'],'EXECUTABLE_IDENTITY')
        static=_static(files,{n:'BASE_'+n for n in (*static_verifier.LIMITS,'MANIFEST.json')},digest(canonical(catalog['static_catalog'])))
        receipt=strict_json(files['RECEIPT.json']);require(receipt['request_id']==expected_request_id,'RECEIPT_REQUEST')
        rows=derive(catalog,static,receipt,files);result=envelope(catalog,static,rows,manifest['run_id'])
        require(files['REPORT.json']==canonical(result) and files['FINAL_HANDOFF.md']==HANDOFF,'RESULT_DERIVATION')
        recovered=recover(strict_json(files['MEMORY.json']),result)
        held.validate()
    return result,recovered


def query_bundle(folder,catalog_sha256,trusted_run_sha256,expected_request_id,*,offset=0,limit=50):
    result,_=verify_bundle(folder,catalog_sha256,trusted_run_sha256,expected_request_id)
    require(type(offset) is int and 0<=offset<=len(result['claims']) and type(limit) is int and 1<=limit<=100,'INVALID_PAGE')
    rows=result['claims'][offset:offset+limit];following=offset+len(rows)
    return dict(integration_id=result['integration_id'],items=rows,total=len(result['claims']),next_offset=following if following<len(result['claims']) else None,scope=SCOPE)
