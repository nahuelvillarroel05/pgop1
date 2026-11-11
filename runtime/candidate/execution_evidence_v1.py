"""Opt-in trusted local observer for a closed set of reviewed demonstrations."""
from contextlib import ExitStack
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time

from .execution_contract_v1 import (ROOT, SCHEMA, SCOPE, HANDOFF, MAX_STREAM, MAX_PACKET,
    canonical, digest, strict_json, require, pin, token, code_paths, validate_catalog, packet_identity, envelope)


def _new(path,raw):
    with path.open('xb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())


def _observe(action, work, number, executable):
    """Streams are byte files from launch; caps mark incomplete, never PASS."""
    prefix=f'STEP_{number:02d}'
    temp=work/f'temp{number}';temp.mkdir()
    cache=work/f'cache{number}';cache.mkdir()
    argv=[str(executable),'-I','-B','-X','pycache_prefix='+str(cache),str(ROOT/'tools/execution_worker_v1.py'),action,str(work)]
    timeout=0.15 if action=='timeout' else (45 if action.startswith('static_') else 5)
    env={k:os.environ[k] for k in ('SystemRoot','WINDIR') if k in os.environ}
    env.update(TEMP=str(temp),TMP=str(temp),PYTHONIOENCODING='utf-8')
    start=dict(schema='pgop1.execution-start.v1',step=number,action=action,test_identity='tools/execution_worker_v1.py:'+action,
               argv=argv,cwd=str(work),env_allowlist=env,env_redactions='ALL_OTHER_VARIABLES_EXCLUDED',
               timeout_seconds=timeout,max_stream_bytes=MAX_STREAM,started_at=time.time())
    files={};stop=threading.Event();truncated={};reader_errors=[]
    handles={n:(work/(prefix+'.'+n+'.bin')).open('xb') for n in ('stdout','stderr')}
    child=None; state='LAUNCH_FAILED';code=None
    def read(pipe,name):
        count=0;truncated[name]=False
        try:
            while True:
                block=pipe.read(8192)
                if not block:break
                keep=block[:max(0,MAX_STREAM-count)]
                handles[name].write(keep);count+=len(keep)
                if len(keep)<len(block):truncated[name]=True;stop.set();break
        except OSError as exc:reader_errors.append(type(exc).__name__);stop.set()
        finally:pipe.close()
    try:
        child=subprocess.Popen(argv,cwd=work,env=env,shell=False,stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        start.update(pid=child.pid,process_state='STARTED')
        _new(work/(prefix+'.START.json'),canonical(start))
        readers=[threading.Thread(target=read,args=(pipe,name),daemon=True)
                 for name,pipe in [('stdout',child.stdout),('stderr',child.stderr)]]
        for thread in readers:thread.start()
        began=time.monotonic();state='COMPLETED'
        while child.poll() is None:
            if stop.is_set():state='TRUNCATED';child.kill();break
            if time.monotonic()-began>timeout:state='TIMED_OUT';child.kill();break
            time.sleep(0.01)
        code=child.wait(timeout=5)
        for thread in readers:thread.join(timeout=5)
        if any(t.is_alive() for t in readers):raise RuntimeError('STREAM_EOF_NOT_PROVEN_NO_ACK')
        if any(truncated.values()):state='TRUNCATED'
        if reader_errors:state='INTERRUPTED'
    except OSError as exc:
        start.update(pid=None,process_state='LAUNCH_FAILED',error=type(exc).__name__)
        _new(work/(prefix+'.START.json'),canonical(start))
    finally:
        for handle in handles.values():handle.close()
    for name in ('stdout','stderr'):
        files[prefix+'.'+name+'.bin']=(work/(prefix+'.'+name+'.bin')).read_bytes()
    close=dict(schema='pgop1.execution-close.v1',step=number,action=action,pid=start.get('pid'),
               process_state=state,exit_code=code,ended_at=time.time(),reader_errors=reader_errors,
               streams={name:dict(pin(files[prefix+'.'+name+'.bin']),truncated=truncated.get(name,False)) for name in ('stdout','stderr')})
    _new(work/(prefix+'.CLOSE.json'),canonical(close))
    files[prefix+'.START.json']=canonical(start);files[prefix+'.CLOSE.json']=canonical(close)
    return dict(start=start,close=close,prefix=prefix),files


class ExecutionEvidenceRunner:
    """No arbitrary command API. Each request requires externally anchored policy."""
    def __init__(self,*,source_root,catalog_path,catalog_sha256):
        self.source_root=source_root;self.catalog_path=catalog_path;self.sha=catalog_sha256

    def run(self,output,*,request_id):
        require(os.name=='nt','WINDOWS_ONLY');token(request_id)
        from .windows_safe_io_v2 import Directory, absolute, reject_membership, safe_read, safe_create_artifacts
        from .semantic_engine_v1 import RealStaticV2Profile
        from .semantic_memory_v1 import create_archive
        from tools.verify_semantic_engine_v1 import verify_bundle as verify_static, LIMITS
        from tools.verify_execution_evidence_v1 import derive
        absolute(self.catalog_path);drive,parts=absolute(output)
        require(drive.upper()=='D:\\' and bool(parts),'D_DRIVE_REQUIRED')
        executable=ROOT/'.venv/Scripts/python.exe'
        with ExitStack() as held:
            source=held.enter_context(Directory(self.source_root));repo=held.enter_context(Directory(ROOT))
            config=held.enter_context(Directory(Path(self.catalog_path).parent))
            parent=held.enter_context(Directory(drive+'\\'.join(parts[:-1])))
            for protected in (source,repo,config):reject_membership(parent,protected)
            require(not Path(output).exists(),'OUTPUT_EXISTS')
            raw=safe_read(Path(self.catalog_path).parent,Path(self.catalog_path).name,self.sha,262144).raw
            catalog=validate_catalog(strict_json(raw),self.sha);require(raw==canonical(catalog),'CANONICAL_CATALOG')
            require(sorted(catalog['code_pins'])==code_paths(),'CODE_INSTALLATION_MEMBERSHIP')
            code={n:safe_read(ROOT,n,h,262144).raw for n,h in catalog['code_pins'].items()}
            exe=safe_read(executable.parent,executable.name,catalog['executable_sha256'],2_000_000).raw
            inputs={p['path']:safe_read(self.source_root,p['path'],p['sha256'],262144).raw for p in catalog['static_catalog']['catalog']['sources']}
            run_id=packet_identity(self.sha,request_id)
            work=Path(output).parent/('unacknowledged-'+request_id);absolute(work)
            work.mkdir(exist_ok=False)
            # Never remove failed/partial evidence. Successful work is retained privately too.
            with Directory(work) as custody:
                src=work/'source';src.mkdir();cfg=work/'config';cfg.mkdir()
                for n,b in inputs.items():
                    path=src/n;path.parent.mkdir(parents=True,exist_ok=True);_new(path,b)
                static_raw=canonical(catalog['static_catalog']);_new(cfg/'CATALOG.json',static_raw)
                base_dir=work/'base'
                RealStaticV2Profile(source_root=src,catalog_path=cfg/'CATALOG.json',catalog_sha256=digest(static_raw)).generate(base_dir)
                static,_=verify_static(base_dir,digest(static_raw))
                files={'CATALOG.json':raw,'REQUEST.json':canonical(dict(schema=SCHEMA,request_id=request_id,run_id=run_id,catalog_sha256=self.sha))}
                for n in (*LIMITS,'MANIFEST.json'):files['BASE_'+n]=safe_read(base_dir,n,None,MAX_PACKET).raw
                files['CODE.json']=canonical({n:b.hex() for n,b in code.items()})
                files['EXECUTABLE.json']=canonical(pin(exe))
                cases=[];step_number=0
                for case in catalog['cases']:
                    case_work=work/case['case_id'];case_work.mkdir()
                    for directory in ('source','config'):
                        (case_work/directory).mkdir()
                    for n,b in inputs.items():
                        path=case_work/'source'/n;path.parent.mkdir(parents=True,exist_ok=True);_new(path,b)
                    _new(case_work/'config/CATALOG.json',static_raw)
                    action=case['action'];steps=[];effects={}
                    actions=(['static_generate','static_recover']+(['static_reject'] if action=='snapshot_rejection' else [])
                             if action.startswith('snapshot_') else [action])
                    for selected in actions:
                        if selected=='static_reject':
                            tampered=case_work/'tampered';tampered.mkdir()
                            for n in (*LIMITS,'MANIFEST.json'):_new(tampered/n,safe_read(case_work/'bundle',n,None,MAX_PACKET).raw)
                            before=safe_read(tampered,'INTEGRATION.json',None,MAX_PACKET).raw
                            after=before+b' '
                            # Mutate only this newly created private copy. Preserve original and changed bytes.
                            (tampered/'INTEGRATION.json').write_bytes(after)
                            effects['mutation']=dict(member='INTEGRATION.json',before_hex=before.hex(),after_hex=after.hex(),
                                                     after_step=steps[-1]['prefix'],before_step=f'STEP_{step_number:02d}')
                        observation,streams=_observe(selected,case_work,step_number,executable)
                        files.update(streams);steps.append(observation);step_number+=1
                        if observation['close']['process_state']!='COMPLETED':break
                    if (case_work/'result.bin').exists():
                        body=safe_read(case_work,'result.bin',None,MAX_STREAM).raw
                        name=case['case_id']+'.artifact.bin';files[name]=body;effects['artifact']=name
                    if (case_work/'bundle').exists():
                        effects['bundle']={}
                        for n in (*LIMITS,'MANIFEST.json'):
                            name=case['case_id']+'.'+n
                            files[name]=safe_read(case_work/'bundle',n,None,MAX_PACKET).raw;effects['bundle'][n]=name
                    if (case_work/'recovered.json').exists():
                        name=case['case_id']+'.recovered.json';files[name]=safe_read(case_work,'recovered.json',None,MAX_PACKET).raw;effects['recovered']=name
                    if (case_work/'rejection.json').exists():
                        name=case['case_id']+'.rejection.json';files[name]=safe_read(case_work,'rejection.json',None,1024).raw;effects['rejection']=name
                    cases.append(dict(case_id=case['case_id'],steps=steps,effects=effects))
                unchanged=True
                for n,h in catalog['code_pins'].items():
                    if digest(safe_read(ROOT,n,None,262144).raw)!=h:unchanged=False
                if digest(safe_read(executable.parent,executable.name,None,2_000_000).raw)!=catalog['executable_sha256']:unchanged=False
                for p in catalog['static_catalog']['catalog']['sources']:
                    if digest(safe_read(self.source_root,p['path'],None,262144).raw)!=p['sha256']:unchanged=False
                if safe_read(Path(self.catalog_path).parent,Path(self.catalog_path).name,None,262144).raw!=raw:unchanged=False
                receipt=dict(schema='pgop1.execution-receipt.v1',run_id=run_id,request_id=request_id,identities_unchanged=unchanged,cases=cases)
                files['RECEIPT.json']=canonical(receipt)
                rows=derive(catalog,static,receipt,files)
                result=envelope(catalog,static,rows,run_id)
                files['REPORT.json']=canonical(result);files['MEMORY.json']=canonical(create_archive(result));files['FINAL_HANDOFF.md']=HANDOFF
                require(sum(map(len,files.values()))<=MAX_PACKET,'PACKET_LIMIT')
                manifest=dict(schema='pgop1.execution-manifest.v1',catalog_sha256=self.sha,run_id=run_id,files={n:pin(b) for n,b in files.items()})
                files['MANIFEST.json']=canonical(manifest)
                for directory in (source,repo,config,parent,custody):directory.validate()
                safe_create_artifacts(self.source_root,output,files,(ROOT,Path(self.catalog_path).parent,work))
        return dict(schema='pgop1.execution-ack.v1',operation_completed=True,run_id=run_id,request_id=request_id,
                    catalog_sha256=self.sha,trusted_run_sha256=digest(files['MANIFEST.json']),
                    integration_id=result['integration_id'],scope=SCOPE)
