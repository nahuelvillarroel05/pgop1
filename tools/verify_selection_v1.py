"""Independent E7 replay. Imports no selection producer or E3/E4 resolver."""
import argparse,json,os,sys
from contextlib import ExitStack
from pathlib import Path
ROOT=Path(__file__).absolute().parents[1]
sys.path[:0]=[str(ROOT/'runtime'),str(ROOT)]
from candidate import selection_contract_v1 as C
from candidate import windows_safe_io_v2 as IO
from tools.verify_source_v2 import verify_structure

def replay(c,p,code_sha,captured,structures):
    """Independent list/cursor implementation of specified FIFO policy."""
    table={r['path']:r for r in c['sources']}; paths=sorted(table)
    admitted=[];cursor=0;seen_bytes={};errors={};history=[];used=0;spent=0;success_bytes=0
    def record(kind,**kw):history.append(dict(event=kind,**kw))
    base='' if c['scope']=='.' else c['scope']+'/'
    root='' if c['package_root']=='.' else c['package_root']+'/'
    def try_group(target,why,origin=None):
        nonlocal used,spent,success_bytes
        if target in admitted:
            record('DEDUPLICATED',path=target,reason=why,origin=origin);return False
        ancestors=[]
        directory=target.rsplit('/',1)[0] if '/' in target else ''
        while directory:
            init=directory+'/__init__.py'
            if init in table and init.startswith(base):ancestors.insert(0,init)
            directory=directory.rsplit('/',1)[0] if '/' in directory else ''
        batch=[]
        for n in ancestors+[target]:
            if n not in admitted and n not in batch:batch.append(n)
        if len(batch)+len(admitted)>p['max_selected']:
            record('GROUP_REJECTED',path=target,group=batch,reason='SELECTED_BUDGET_EXCEEDED',origin=origin);return False
        for n in batch:
            if n in seen_bytes:continue
            if n in errors:
                record('GROUP_REJECTED',path=target,group=batch,reason='SOURCE_NOT_ADMITTED',unavailable=n,origin=origin);return False
            if used==p['max_planning_files'] or 2*(table[n]['bytes']+spent)>p['max_total_read_bytes']:
                errors[n]='BUDGET_EXCEEDED';record('READ_BLOCKED',path=n,reason=errors[n])
            else:
                used+=1;spent+=table[n]['bytes']
                try:
                    rr=IO.safe_read(c['source_root'],n,table[n]['sha256'],min(p['max_file_bytes'],table[n]['bytes']))
                    C.need(len(rr.raw)==table[n]['bytes'],'SOURCE_CHANGED')
                    C.need(captured.get(n)==rr.raw,'CAPTURE_PIN_MISMATCH')
                    seen_bytes[n]=rr.raw;success_bytes+=len(rr.raw)
                    record('READ',path=n,bytes=len(rr.raw),sha256=rr.sha256)
                except (OSError,ValueError) as exc:
                    val=getattr(exc,'code',str(exc))
                    if val=='CAPTURE_PIN_MISMATCH':raise
                    errors[n]='SOURCE_CHANGED' if val in {'SOURCE_HASH_MISMATCH','SIZE_LIMIT'} else val
                    record('READ_FAILED',path=n,reason=errors[n])
            if n in errors:
                record('GROUP_REJECTED',path=target,group=batch,reason='SOURCE_NOT_ADMITTED',unavailable=n,origin=origin);return False
        for n in batch:
            admitted.append(n)
            record('ADMITTED',path=n,ordinal=len(admitted),reason=why if n==target else 'REQUIRED_PARENT_INIT',origin=origin)
        return True
    starts={}
    for path in paths:
        relative=path[len(base):].split('/')
        if len(relative)<=2 and relative[-1]!='__init__.py':
            folder='/'.join(relative[:-1])
            if folder not in starts:starts[folder]=path
    seeds=sorted(list(starts.values())+([base+'__init__.py'] if base+'__init__.py' in table else []))
    record('SEEDS',paths=seeds)
    for n in seeds:try_group(n,'FIXED_SEED')
    while True:
        if cursor==len(admitted):
            if len(admitted)==p['max_selected']:break
            added=False
            for n in paths:
                if n in admitted or n.split('/')[-1]=='__init__.py':continue
                if try_group(n,'LEXICOGRAPHIC_FILL'):added=True;break
            if not added:break
        path=admitted[cursor];cursor+=1;record('DEQUEUED',path=path)
        C.need(path in structures,'MISSING_AST_REPORT')
        sr=structures[path]
        C.need('execution_metrics' not in sr,'UNEXPECTED_AST_METADATA')
        C.need(sr.get('status') not in {'RESOURCE_ERROR','UNKNOWN','UNSUPPORTED'},'AST_ABSTENTION_NOT_INDEPENDENTLY_REDERIVABLE')
        expected_limits={'bytes':p['max_file_bytes'],'nodes':p['ast_nodes'],'depth':p['ast_depth'],
                         'unit_nodes':p['ast_unit_nodes'],'output_bytes':64000000,'timeout_seconds':p['parse_timeout_seconds']}
        C.need(sr.get('budgets')==expected_limits,'AST_BUDGETS')
        # Recomputes exact syntax, relations, spans, coverage and identities from captured bytes.
        verify_structure(None,sr,captured={path:seen_bytes[path]})
        record('AST',path=path,status=sr['status'],reason=sr.get('reason'))
        if sr['status']!='COMPLETE':continue
        package=path[len(root):].split('/')[:-1];offers=[]
        for row in sr['relations']:
            if row['kind']!='imports':continue
            for i,a in enumerate(row['aliases']):
                ref={'source':path,'line':row['line'],'column':row['column'],'alias_index':i}
                if row['module'] is None and row['level']==0:
                    requested=[a['name']]
                elif row['level']>len(package):
                    record('REFERENCE',origin=ref,requested=[],candidates=[],reason='RELATIVE_ESCAPE');continue
                else:
                    parts=package[:len(package)+1-row['level']] if row['level'] else []
                    if row['module']:parts+=row['module'].split('.')
                    requested=['.'.join(parts)]
                    if a['name']!='*' and a['name'].isidentifier():requested.append('.'.join(parts+[a['name']]))
                found=set()
                for mod in requested:
                    if not mod or any(x=='WITHHELD' for x in mod.split('.')):continue
                    stem=root+'/'.join(mod.split('.'))
                    for n in (stem+'.py',stem+'/__init__.py'):
                        if n in table:found.add(n)
                found=sorted(found)
                record('REFERENCE',origin=ref,requested=requested,candidates=found,reason='SYNTACTIC_CANDIDATE_ONLY' if found else 'NO_CALLER_CATALOG_CANDIDATE')
                offers.extend((n,ref) for n in found)
        offers.sort(key=lambda x:x[0])
        for n,ref in offers:try_group(n,'SYNTACTIC_IMPORT_CANDIDATE',ref)
    C.need(set(captured)==set(seen_bytes),'CAPTURE_MEMBERSHIP')
    C.need(set(structures)==set(admitted),'AST_MEMBERSHIP')
    checked_bytes=0
    for n in admitted:
        try:
            rr=IO.safe_read(c['source_root'],n,table[n]['sha256'],min(p['max_file_bytes'],table[n]['bytes']));checked_bytes+=len(rr.raw)
            C.need(rr.raw==seen_bytes[n],'SOURCE_CHANGED')
            record('SOURCE_RECHECK',path=n,status='MATCH')
        except (OSError,ValueError) as exc:
            v=getattr(exc,'code',str(exc));errors[n]='SOURCE_CHANGED' if v in {'SOURCE_HASH_MISMATCH','SIZE_LIMIT'} else v
            record('SOURCE_RECHECK',path=n,status=errors[n])
    for n in paths:
        if n not in seen_bytes and n not in errors:record('NOT_READ',path=n,reason='NOT_REACHED_IN_CALLER_CATALOG')
    equal={}
    for n in paths:equal.setdefault(table[n]['sha256'],[]).append(n)
    return dict(schema='pgop1.autonomous-source-selection.v1',algorithm=C.ALGORITHM,mode='AUTHORIZED_CATALOG',
        autonomous_from_root='BLOCKED_NOT_IMPLEMENTED',catalog_sha256=C.digest(C.canonical(c)),
        policy_sha256=C.digest(C.canonical(p)),code_sha256=code_sha,source_root=c['source_root'],scope=c['scope'],package_root=c['package_root'],
        inventory=c['sources'],seeds=seeds,selected=[table[n] for n in admitted],trace=history,
        source_errors=[dict(path=n,reason=v) for n,v in sorted(errors.items())],
        duplicate_bytes=[dict(sha256=h,paths=ns) for h,ns in sorted(equal.items()) if len(ns)>1],
        budgets=dict(catalog_files=len(paths),planning_attempted=used,planning_successful=len(seen_bytes),planning_bytes=success_bytes,
                     planning_bytes_reserved=spent,selected=len(admitted),recheck_attempted=len(admitted),recheck_bytes=checked_bytes),
        status='PARTIAL' if errors or any(v['status']!='COMPLETE' for v in structures.values()) else 'CATALOG_SELECTION_COMPLETE',
        limits=dict(source_current_at_ack='NOT_PROVEN',artifact_current_at_ack='NOT_PROVEN',atomic_snapshot='NOT_PROVEN',
                    root_inventory_completeness='NOT_PROVEN',candidates='SYNTAX_ONLY_NO_BINDING_AUTHORITY',io_deadline='NOT_GUARANTEED',memory_isolation='NOT_IMPLEMENTED'))

def verify(artifacts,catalog_sha256,policy_sha256,code_sha256):
    C.need(os.name=='nt','WINDOWS_ONLY');IO.absolute(artifacts)
    caps={'PLAN.json':64000000,'CAPTURES.json':36000000,'AST_REPORTS.json':128000000,
          'SOURCE_CATALOG.json':262144,'POLICY.json':262144,'CODE_IDENTITY.json':262144}
    with ExitStack() as tx:
        bundle=tx.enter_context(IO.Directory(artifacts))
        manifest=C.strict(IO.safe_read(artifacts,'MANIFEST.json',None,262144).raw)
        C.need(set(manifest)=={'schema','files'} and manifest['schema']=='pgop1.selection-artifacts.v1','MANIFEST_SCHEMA')
        C.need(set(manifest['files'])==set(caps),'ARTIFACT_MEMBERSHIP')
        values={}
        for name,cap in caps.items():
            pin=manifest['files'][name];C.need(set(pin)=={'bytes','sha256'} and type(pin['bytes']) is int and 0<=pin['bytes']<=cap,'MEMBER_SCHEMA')
            raw=IO.safe_read(artifacts,name,pin['sha256'],cap).raw;C.need(len(raw)==pin['bytes'],'MEMBER_SIZE')
            values[name]=C.strict(raw)
        c=values['SOURCE_CATALOG.json'];p=C.policy(values['POLICY.json']);C.catalog(c,p)
        code=C.code_manifest(values['CODE_IDENTITY.json'])
        for value,pin in ((c,catalog_sha256),(p,policy_sha256),(code,code_sha256)):
            C.need(C.digest(C.canonical(value))==pin,'EXTERNAL_AUTHORIZATION_ANCHOR')
        source=tx.enter_context(IO.Directory(c['source_root']));product=tx.enter_context(IO.Directory(ROOT))
        for pin in code['files']:
            raw=IO.safe_read(ROOT,pin['path'],pin['sha256'],262144).raw;C.need(len(raw)==pin['bytes'],'CODE_CHANGED')
        captures={n:bytes.fromhex(h) for n,h in values['CAPTURES.json'].items()}
        for n,b in captures.items():
            C.need(n in {x['path'] for x in c['sources']},'CAPTURE_PATH')
            row=next(x for x in c['sources'] if x['path']==n)
            C.need(len(b)==row['bytes'] and C.digest(b)==row['sha256'],'CAPTURE_HASH')
        expected=replay(c,p,code_sha256,captures,values['AST_REPORTS.json'])
        C.need(C.canonical(expected)==C.canonical(values['PLAN.json']),'SELECTION_SEMANTIC_MISMATCH')
        bundle.validate();source.validate();product.validate()
    return dict(schema='pgop1.selection-verification.v1',status='SELECTION_VERIFIED',selected=len(expected['selected']),
                plan_sha256=C.digest(C.canonical(expected)),autonomous_from_root='BLOCKED_NOT_IMPLEMENTED',
                scope='CATALOG_SELECTION_REPLAY_WITH_POINT_SOURCE_RECAPTURE',producer_imported=False,
                parser='SHARED_CPYTHON_AST',independent_parser_timeout='NOT_IMPLEMENTED',memory_isolation='NOT_IMPLEMENTED',
                artifact_extra_directory_entries='NOT_ENUMERATED_NOT_AUTHORITY',source_current_at_ack='NOT_PROVEN',artifact_current_at_ack='NOT_PROVEN')
def main():
    p=argparse.ArgumentParser(description=__doc__)
    for n in ('artifacts','catalog-sha256','policy-sha256','code-sha256'):p.add_argument('--'+n,required=True)
    a=p.parse_args()
    try:result=verify(a.artifacts,a.catalog_sha256,a.policy_sha256,a.code_sha256)
    except (OSError,ValueError,KeyError,TypeError,MemoryError,RecursionError) as exc:
        print(json.dumps(dict(status='ERROR',reason=getattr(exc,'code',str(exc)))));return 2
    print(json.dumps(result,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
