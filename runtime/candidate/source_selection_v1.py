"""Opt-in E7 selection from an external authorized catalog. No directory discovery."""
from collections import deque
from contextlib import ExitStack
import os
from pathlib import Path
from . import selection_contract_v1 as C
from . import windows_safe_io_v2 as IO
from .static_ast_v2 import analyze_captured

def select_catalog(catalog, policy, code_sha256):
    """Caller supplies authenticated canonical inputs; CLI owns the transaction."""
    p=C.policy(policy); c=C.catalog(catalog,p);C.need(C.hash_value(code_sha256),'CODE_HASH')
    pins={r['path']:r for r in c['sources']}; names=list(pins)
    selected=[]; queue=deque(); captures={}; reports={}; failures={}
    trace=[]; attempted=0; total=0; reserved=0; rechecked=0; recheck_bytes=0
    def event(kind,**fields):trace.append(dict(event=kind,**fields))
    scope='' if c['scope']=='.' else c['scope']+'/'
    prefix='' if c['package_root']=='.' else c['package_root']+'/'
    def parents(path):
        parts=path.split('/')
        return [n for i in range(1,len(parts)) if (n:='/'.join(parts[:i])+'/__init__.py') in pins and n.startswith(scope)]
    def read(path):
        nonlocal attempted,total,reserved
        if path in captures:return True
        if path in failures:return False
        if attempted>=p['max_planning_files'] or 2*(reserved+pins[path]['bytes'])>p['max_total_read_bytes']:
            failures[path]='BUDGET_EXCEEDED';event('READ_BLOCKED',path=path,reason=failures[path]);return False
        attempted+=1;reserved+=pins[path]['bytes']
        try:
            rr=IO.safe_read(c['source_root'],path,pins[path]['sha256'],min(p['max_file_bytes'],pins[path]['bytes']))
            total+=len(rr.raw)
            C.need(len(rr.raw)==pins[path]['bytes'],'SOURCE_CHANGED')
            captures[path]=rr.raw
            event('READ',path=path,bytes=len(rr.raw),sha256=rr.sha256)
            return True
        except (OSError,ValueError) as exc:
            reason=getattr(exc,'code',str(exc))
            failures[path]='SOURCE_CHANGED' if reason in {'SOURCE_HASH_MISMATCH','SIZE_LIMIT'} else reason
            event('READ_FAILED',path=path,reason=failures[path]);return False
    def admit(path,reason,origin=None):
        if path in selected:
            event('DEDUPLICATED',path=path,reason=reason,origin=origin);return False
        group=list(dict.fromkeys(x for x in parents(path)+[path] if x not in selected))
        if len(selected)+len(group)>p['max_selected']:
            event('GROUP_REJECTED',path=path,group=group,reason='SELECTED_BUDGET_EXCEEDED',origin=origin);return False
        for member in group:
            if not read(member):
                event('GROUP_REJECTED',path=path,group=group,reason='SOURCE_NOT_ADMITTED',unavailable=member,origin=origin);return False
        for member in group:
            selected.append(member);queue.append(member)
            event('ADMITTED',path=member,ordinal=len(selected),reason=reason if member==path else 'REQUIRED_PARENT_INIT',origin=origin)
        return True
    groups={}
    for name in names:
        rel=name[len(scope):]; parts=rel.split('/')
        if parts[-1]!='__init__.py' and len(parts)<=2:
            groups.setdefault('/'.join(parts[:-1]),[]).append(name)
    initial=scope+'__init__.py'
    seeds=sorted(set(([initial] if initial in pins else [])+[min(v) for v in groups.values()]))
    event('SEEDS',paths=seeds)
    for name in seeds:admit(name,'FIXED_SEED')
    while True:
        if not queue:
            if len(selected)>=p['max_selected']:break
            rest=[n for n in names if n not in selected and not n.endswith('/__init__.py') and n!='__init__.py']
            if not any(admit(n,'LEXICOGRAPHIC_FILL') for n in rest):break
        source=queue.popleft();event('DEQUEUED',path=source)
        report=analyze_captured(captures[source],source,pins[source]['sha256'],budgets={
            'bytes':p['max_file_bytes'],'nodes':p['ast_nodes'],'depth':p['ast_depth'],
            'unit_nodes':p['ast_unit_nodes'],'timeout_seconds':p['parse_timeout_seconds']})
        report.pop('execution_metrics',None);reports[source]=report
        event('AST',path=source,status=report['status'],reason=report.get('reason'))
        if report['status']!='COMPLETE':continue
        rel=source[len(prefix):];package=rel.split('/')[:-1]
        candidates=[]
        for edge in report['relations']:
            if edge['kind']!='imports':continue
            for ai,alias in enumerate(edge['aliases']):
                origin=dict(source=source,line=edge['line'],column=edge['column'],alias_index=ai)
                if edge['module'] is None and edge['level']==0:modules=[alias['name']]
                else:
                    level=edge['level'];module=edge['module']
                    if level>len(package):
                        event('REFERENCE',origin=origin,requested=[],candidates=[],reason='RELATIVE_ESCAPE');continue
                    base=(package[:len(package)-level+1] if level else [])+((module or '').split('.') if module else [])
                    modules=['.'.join(base)]
                    if alias['name']!='*' and alias['name'].isidentifier():modules+=['.'.join(base+[alias['name']])]
                targets=[]
                for module in modules:
                    if not module or 'WITHHELD' in module.split('.'):continue
                    stem=prefix+module.replace('.','/')
                    targets.extend(n for n in (stem+'.py',stem+'/__init__.py') if n in pins)
                targets=sorted(set(targets))
                event('REFERENCE',origin=origin,requested=modules,candidates=targets,reason='SYNTACTIC_CANDIDATE_ONLY' if targets else 'NO_CALLER_CATALOG_CANDIDATE')
                candidates.extend((n,origin) for n in targets)
        for target,origin in sorted(candidates,key=lambda pair:pair[0]):admit(target,'SYNTACTIC_IMPORT_CANDIDATE',origin)
    for path in selected:
        try:
            rechecked+=1
            rr=IO.safe_read(c['source_root'],path,pins[path]['sha256'],min(p['max_file_bytes'],pins[path]['bytes']));recheck_bytes+=len(rr.raw)
            C.need(rr.raw==captures[path],'SOURCE_CHANGED')
            event('SOURCE_RECHECK',path=path,status='MATCH')
        except (OSError,ValueError) as exc:
            failures[path]='SOURCE_CHANGED' if getattr(exc,'code',str(exc))in {'SOURCE_HASH_MISMATCH','SIZE_LIMIT'} else getattr(exc,'code',str(exc))
            event('SOURCE_RECHECK',path=path,status=failures[path])
    for path in names:
        if path not in captures and path not in failures:event('NOT_READ',path=path,reason='NOT_REACHED_IN_CALLER_CATALOG')
    duplicates={}
    for pin in c['sources']:duplicates.setdefault(pin['sha256'],[]).append(pin['path'])
    plan=dict(schema='pgop1.autonomous-source-selection.v1',algorithm=C.ALGORITHM,
        mode='AUTHORIZED_CATALOG',autonomous_from_root='BLOCKED_NOT_IMPLEMENTED',
        catalog_sha256=C.digest(C.canonical(c)),policy_sha256=C.digest(C.canonical(p)),
        code_sha256=code_sha256,source_root=c['source_root'],scope=c['scope'],package_root=c['package_root'],
        inventory=c['sources'],seeds=seeds,selected=[pins[n] for n in selected],trace=trace,
        source_errors=[dict(path=n,reason=v) for n,v in sorted(failures.items())],
        duplicate_bytes=[dict(sha256=h,paths=v) for h,v in sorted(duplicates.items()) if len(v)>1],
        budgets=dict(catalog_files=len(names),planning_attempted=attempted,planning_successful=len(captures),
                     planning_bytes=total,planning_bytes_reserved=reserved,selected=len(selected),recheck_attempted=rechecked,recheck_bytes=recheck_bytes),
        status='PARTIAL' if failures or any(r['status']!='COMPLETE' for r in reports.values()) else 'CATALOG_SELECTION_COMPLETE',
        limits=dict(source_current_at_ack='NOT_PROVEN',artifact_current_at_ack='NOT_PROVEN',
                    atomic_snapshot='NOT_PROVEN',root_inventory_completeness='NOT_PROVEN',
                    candidates='SYNTAX_ONLY_NO_BINDING_AUTHORITY',io_deadline='NOT_GUARANTEED',memory_isolation='NOT_IMPLEMENTED'))
    return plan,captures,reports

def execute(source_root,catalog_path,catalog_sha256,policy_path,policy_sha256,code_path,code_sha256,output):
    C.need(os.name=='nt','WINDOWS_ONLY')
    # Reject traversal before any Path normalization.
    for path in (source_root,catalog_path,policy_path,code_path,output):IO.absolute(path)
    product=Path(__file__).absolute().parents[2]
    with ExitStack() as tx:
        held=[tx.enter_context(IO.Directory(p)) for p in (source_root,product,Path(catalog_path).parent,Path(policy_path).parent,Path(code_path).parent,Path(output).parent)]
        for d in held[:-1]:IO.reject_membership(held[-1],d)
        def load(path,pin,cap):
            raw=IO.safe_read(Path(path).parent,Path(path).name,pin,cap).raw;return C.strict(raw)
        p=C.policy(load(policy_path,policy_sha256,262144));c=C.catalog(load(catalog_path,catalog_sha256,262144),p)
        C.need(str(source_root).replace('/','\\')==c['source_root'].replace('/','\\'),'SOURCE_ROOT_AUTHORIZATION')
        code=C.code_manifest(load(code_path,code_sha256,262144))
        for pin in code['files']:
            rr=IO.safe_read(product,pin['path'],pin['sha256'],262144);C.need(len(rr.raw)==pin['bytes'],'CODE_CHANGED')
        plan,captures,reports=select_catalog(c,p,code_sha256)
        files={'PLAN.json':C.canonical(plan),'CAPTURES.json':C.canonical({n:b.hex() for n,b in sorted(captures.items())}),
               'AST_REPORTS.json':C.canonical(reports),'SOURCE_CATALOG.json':C.canonical(c),'POLICY.json':C.canonical(p),'CODE_IDENTITY.json':C.canonical(code)}
        for d in held:d.validate()
        files['MANIFEST.json']=C.canonical(dict(schema='pgop1.selection-artifacts.v1',files={n:dict(bytes=len(b),sha256=C.digest(b)) for n,b in files.items()}))
        IO.safe_create_artifacts(source_root,output,files,(product,Path(catalog_path).parent,Path(policy_path).parent,Path(code_path).parent))
        for d in held:d.validate()
    return dict(status='SELECTION_WRITTEN',plan_sha256=C.digest(files['PLAN.json']),operation_completed=True,
                autonomous_from_root='BLOCKED_NOT_IMPLEMENTED',source_current_at_ack='NOT_PROVEN',artifact_current_at_ack='NOT_PROVEN')
