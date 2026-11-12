"""Opt-in two-stage native discovery. Never calls or authorizes E7 itself."""
from contextlib import ExitStack
from pathlib import Path
import time
from . import selection_contract_v1 as C
from . import admission_contract_v2 as A
from . import discovery_contract_v1 as D
from . import windows_directory_enumeration_v1 as N
from . import windows_safe_io_v2 as IO

PRODUCT=Path(__file__).absolute().parents[2]
DiscoveryAuthority=D.DiscoveryAuthority

def discover(owner_raw, selection_raw, code_raw, authority, limits=None):
    a,p,code=D.authenticate(owner_raw,selection_raw,code_raw,authority)
    budget=D.limits(limits);trace=[];observations=[];rows=[];failure=None
    counts=dict(physical_entries=0,directories=0,pages=0,eligible_files=0,captured_files=0,
                captured_bytes=0,owner_omissions=0,non_source_omissions=0,unparsed_pages=0)
    started=time.monotonic()
    def check_time():
        if time.monotonic()-started>budget['timeout_seconds']:
            raise IO.SafeIOError('DISCOVERY_COOPERATIVE_TIMEOUT')
    with IO.Directory(PRODUCT) as product, ExitStack() as root_tx:
        for row in code['files']:
            rr=IO.safe_read(PRODUCT,row['path'],row['sha256'],262144)
            C.need(len(rr.raw)==row['bytes'],'CODE_CHANGED')
        root=root_tx.enter_context(IO.Directory(authority.source_root))
        IO.reject_membership(root,product);IO.reject_membership(product,root)
        try:
            with ExitStack() as tx:
                held=[];files=[];identities=set()
                parent=root.handle
                if authority.scope!='.':
                    prefix=[]
                    for part in IO.relative(authority.scope):
                        prefix.append(part)
                        C.need(not D.directory_denied('/'.join(prefix),a),'OWNER_SCOPE_DENIED')
                        parent=tx.enter_context(N.open_metadata(parent,part,directory=True))
                def walk(handle,path,depth):
                    check_time();counts['directories']+=1
                    if counts['directories']>budget['max_directories']:
                        raise IO.SafeIOError('DISCOVERY_DIRECTORY_BUDGET')
                    before=IO.metadata(handle,True);held.append((handle,True,before))
                    observations.append(D.metadata_row(path or '.',before))
                    remaining_pages=budget['max_pages']-counts['pages']
                    remaining_entries=budget['max_entries']-counts['physical_entries']
                    if remaining_pages<=0:raise IO.SafeIOError('DISCOVERY_PAGE_BUDGET')
                    if remaining_entries<=0:raise IO.SafeIOError('DISCOVERY_ENTRY_BUDGET')
                    pages=[]
                    try:
                        entries=N.enumerate_directory(handle,dict(budget,max_pages=remaining_pages,
                            max_entries=remaining_entries),pages,deadline=check_time)
                    finally:
                        counts['pages']+=len(pages)
                        counts['physical_entries']+=sum(e['decoded_entries'] or 0 for e in pages)
                        counts['unparsed_pages']+=sum(e['decoded_entries'] is None for e in pages)
                        trace.extend(dict(event,directory=path or '.') for event in pages)
                    if counts['pages']>budget['max_pages']:
                        raise IO.SafeIOError('DISCOVERY_PAGE_BUDGET')
                    if counts['physical_entries']>budget['max_entries']:
                        raise IO.SafeIOError('DISCOVERY_ENTRY_BUDGET')
                    for entry in entries:
                        check_time();name=entry['name'];relative=(path+'/' if path else '')+name
                        if len(relative)>budget['max_path_chars']:
                            raise IO.SafeIOError('DISCOVERY_PATH_BUDGET')
                        is_dir=bool(entry['attributes']&16)
                        denied=D.directory_denied(relative,a) if is_dir else A.denied(relative,a)
                        if denied:
                            counts['owner_omissions']+=1
                            trace.append(dict(event='OWNER_OMITTED',locator_sha256=C.digest(relative.encode('ascii')),directory=is_dir))
                            continue
                        if entry['tag'] or entry['attributes']&N.UNSAFE_ATTRIBUTES:
                            raise IO.SafeIOError('UNSAFE_PATH_REPARSE_OR_PROVIDER')
                        if any(any(s in part.lower() for s in C.SENSITIVE) for part in relative.split('/')):
                            trace.append(dict(event='SENSITIVE_OMITTED',locator_sha256=C.digest(relative.encode('ascii'))))
                            counts['non_source_omissions']+=1
                            continue
                        if is_dir:
                            if not name.isidentifier():
                                counts['non_source_omissions']+=1
                                trace.append(dict(event='NON_MODULE_DIRECTORY_OMITTED',locator_sha256=C.digest(relative.encode('ascii'))))
                                continue
                            if depth>=min(budget['max_depth'],p['max_depth']):
                                raise IO.SafeIOError('DISCOVERY_DEPTH_BUDGET')
                            if counts['directories']>=budget['max_directories']:
                                raise IO.SafeIOError('DISCOVERY_DIRECTORY_BUDGET')
                            child=tx.enter_context(N.open_metadata(handle,name,directory=True))
                            N.matches(entry,IO.metadata(child,True));walk(child,relative,depth+1)
                        else:
                            if not name.endswith('.py'):
                                counts['non_source_omissions']+=1;continue
                            C.source_path(relative)
                            counts['eligible_files']+=1
                            if counts['eligible_files']>min(budget['max_files'],p['max_catalog_files']):
                                raise IO.SafeIOError('DISCOVERY_FILE_BUDGET')
                            meta_handle=tx.enter_context(N.open_metadata(handle,name,directory=False))
                            meta=IO.metadata(meta_handle,False);N.matches(entry,meta)
                            if meta.identity in identities:
                                raise IO.SafeIOError('CATALOG_IDENTITY_COLLISION')
                            identities.add(meta.identity)
                            if meta.size>min(budget['max_file_bytes'],p['max_file_bytes']):
                                raise IO.SafeIOError('DISCOVERY_SOURCE_SIZE_BUDGET')
                            held.append((meta_handle,False,meta))
                            observations.append(D.metadata_row(relative,meta))
                            files.append((relative,handle,name,meta_handle,meta))
                walk(parent,'' if authority.scope=='.' else authority.scope,0)
                for handle,directory,meta in held:
                    if IO.metadata(handle,directory)!=meta:raise IO.SafeIOError('SOURCE_CHANGED')
                if not files:raise IO.SafeIOError('DISCOVERY_EMPTY_CATALOG')
                if sum(f[4].size for f in files)>min(budget['max_total_bytes'],p['max_total_read_bytes']):
                    raise IO.SafeIOError('DISCOVERY_TOTAL_BYTES_BUDGET')
                for path,parent,name,retained,meta in sorted(files,key=lambda f:f[0]):
                    check_time();body=N.capture(parent,name,retained,meta,meta.size)
                    rows.append(dict(path=path,sha256=C.digest(body),bytes=len(body)))
                    counts['captured_files']+=1;counts['captured_bytes']+=len(body)
                    trace.append(dict(event='CAPTURED',path=path,bytes=len(body),sha256=C.digest(body)))
                for handle,directory,meta in held:
                    if IO.metadata(handle,directory)!=meta:raise IO.SafeIOError('SOURCE_CHANGED')
                root.validate();product.validate()
                C.catalog(dict(schema='pgop1.selection-catalog.v1',source_root=authority.source_root,
                    scope=authority.scope,package_root=authority.package_root,sources=rows),p)
        except (IO.SafeIOError,ValueError,OSError) as exc:
            failure=getattr(exc,'code',str(exc) if isinstance(exc,ValueError) else 'DISCOVERY_IO_FAILED')
    return D.result(authority,budget,rows,trace,observations,counts,failure)

def execute(owner_path,selection_path,code_path,output,authority,limits=None):
    C.need(type(authority) is D.DiscoveryAuthority,'DISCOVERY_AUTHORITY_REQUIRED')
    authority.validate()
    paths=[Path(p) for p in (owner_path,selection_path,code_path)]
    for path in [*paths,Path(output)]:
        IO.absolute(path)
        text=str(path).replace('/','\\').lower();root=authority.source_root.lower().rstrip('\\')
        C.need(text!=root and not text.startswith(root+'\\'),'CONFIG_OR_OUTPUT_INSIDE_SOURCE')
    with ExitStack() as tx:
        configs=[tx.enter_context(IO.Directory(path.parent)) for path in paths]
        destination=tx.enter_context(IO.Directory(Path(output).parent))
        source=tx.enter_context(IO.Directory(authority.source_root))
        product=tx.enter_context(IO.Directory(PRODUCT))
        for held in [*configs,source,product]:IO.reject_membership(destination,held)
        raw=[IO.safe_read(path.parent,path.name,pin,262144).raw for path,pin in zip(paths,
            [authority.admission_policy_sha256,authority.selection_policy_sha256,authority.code_sha256])]
        value=discover(*raw,authority,limits)
        payload={'DISCOVERY.json':C.canonical(value),'CATALOG_CANDIDATE.json':C.canonical(value['catalog']),
            'OWNER_POLICY.json':raw[0],'SELECTION_POLICY.json':raw[1],'CODE_IDENTITY.json':raw[2]}
        payload['MANIFEST.json']=C.canonical(dict(schema='pgop1.discovery-artifacts.v1',
            files={n:dict(bytes=len(b),sha256=C.digest(b)) for n,b in payload.items()}))
        for held in [*configs,destination,source,product]:held.validate()
        IO.safe_create_artifacts(authority.source_root,output,payload,(PRODUCT,*(p.parent for p in paths)))
        for held in [*configs,destination,source,product]:held.validate()
    return dict(status=value['status'],operation_completed=True,manifest_sha256=C.digest(payload['MANIFEST.json']),
                catalog_candidate_sha256=value['catalog_candidate_sha256'],catalog_authority='CANDIDATE_NOT_EXTERNALLY_ADMITTED',
                autonomous_from_root='PARTIAL_TWO_STAGE',source_current_at_ack='NOT_PROVEN',artifact_current_at_ack='NOT_PROVEN')
