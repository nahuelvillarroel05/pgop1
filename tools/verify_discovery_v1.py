"""Independent E8 native observation replay. Imports neither E8 producer module."""
import argparse
from contextlib import ExitStack
import ctypes as T
from ctypes import wintypes as W
import json
from pathlib import Path
import struct
import sys
import time
ROOT=Path(__file__).absolute().parents[1]
sys.path[:0]=[str(ROOT/'runtime'),str(ROOT)]
from candidate import windows_safe_io_v2 as IO
from candidate import selection_contract_v1 as C
from candidate import admission_contract_v2 as A
from candidate import discovery_contract_v1 as D

def _scan(handle,budget):
    """Independent bounded class60 query/parser; shared provider only."""
    fn=IO.api()[1].NtQueryDirectoryFile
    fn.restype=W.LONG
    fn.argtypes=[W.HANDLE,W.HANDLE,W.LPVOID,W.LPVOID,T.POINTER(IO.IO_STATUS_BLOCK),
                W.LPVOID,W.ULONG,T.c_int,T.c_ubyte,T.POINTER(IO.UNICODE_STRING),T.c_ubyte]
    if T.sizeof(IO.IO_STATUS_BLOCK)!=16 or IO.IO_STATUS_BLOCK.Information.offset!=8:
        raise ValueError('VERIFIER_ABI')
    initial=IO.metadata(handle,True);entries={};events=[]
    for page in range(budget['max_pages']):
        buffer=T.create_string_buffer(budget['buffer_bytes']);ios=IO.IO_STATUS_BLOCK()
        C.need(T.addressof(buffer)%8==0,'VERIFIER_ABI')
        status=fn(handle.value,None,None,None,T.byref(ios),buffer,len(buffer),60,0,None,int(page==0))&0xffffffff
        used=ios.Information
        event=dict(event='QUERY',page=page,ntstatus=status,returned_bytes=used,
                   decoded_entries=None if used else 0,page_state='NOT_PARSED')
        events.append(event)
        if status==0x80000006:
            event['page_state']='END'
            C.need(used==0 and IO.metadata(handle,True)==initial,'VERIFIER_DIRECTORY_CHANGED')
            return [entries[k] for k in sorted(entries)],events
        C.need(status==0 and 0<used<=len(buffer),'VERIFIER_QUERY')
        raw=buffer.raw[:used];cursor=0;decoded=0
        while True:
            C.need(cursor%8==0 and used-cursor>=88,'VERIFIER_FRAME')
            step=struct.unpack_from('<I',raw,cursor)[0]
            length=struct.unpack_from('<I',raw,cursor+60)[0]
            end=cursor+88+length
            C.need(length%2==0 and 0<length<=510 and end<=used,'VERIFIER_FRAME')
            if step:C.need(step%8==0 and step>=88+length and cursor+step<used,'VERIFIER_FRAME')
            else:C.need(used-end<8,'VERIFIER_FRAME')
            name=raw[cursor+88:end].decode('utf-16-le')
            if name not in ('.','..'):
                IO.component(name)
                C.need(name.lower() not in {n.lower() for n in entries},'VERIFIER_COLLISION')
                ident=raw[cursor+72:cursor+88]
                size=struct.unpack_from('<q',raw,cursor+40)[0]
                C.need(any(ident) and size>=0,'VERIFIER_FRAME')
                entries[name]=dict(name=name,attributes=struct.unpack_from('<I',raw,cursor+56)[0],
                    tag=struct.unpack_from('<I',raw,cursor+68)[0],file_id=ident.hex(),size=size,
                    times=[struct.unpack_from('<q',raw,cursor+i)[0] for i in [8,24,32]])
                decoded+=1
                C.need(len(entries)<=budget['max_entries'],'VERIFIER_ENTRY_BUDGET')
            if step==0:break
            cursor+=step
        event.update(decoded_entries=decoded,page_state='PARSED')
    raise ValueError('VERIFIER_PAGE_BUDGET')

def _metadata_handle(parent,name,directory):
    IO.component(name);k,n=IO.api();text=T.create_unicode_buffer(name)
    length=len(name.encode('utf-16-le'))
    us=IO.UNICODE_STRING(length,length+2,T.cast(text,W.LPWSTR))
    attr=IO.OBJECT_ATTRIBUTES(T.sizeof(IO.OBJECT_ATTRIBUTES),parent.value,T.pointer(us),0x1000,None,None)
    ios=IO.IO_STATUS_BLOCK();out=W.HANDLE()
    status=n.NtCreateFile(T.byref(out),0x100081 if directory else 0x100080,
        T.byref(attr),T.byref(ios),None,0x80,1,1,0x200020|(1 if directory else 0x40),None,0)
    if status:
        if out.value:k.CloseHandle(out)
        raise ValueError('VERIFIER_METADATA_OPEN')
    result=IO.Handle(out.value)
    try:
        meta=IO.metadata(result,directory)
        C.need(meta.identity[0]==IO.metadata(parent,True).identity[0],'VERIFIER_VOLUME')
        C.need(IO.basename(result)==name,'VERIFIER_CASE')
        return result
    except BaseException:
        result.close();raise

def _deny(path,owner,directory):
    bits=path.lower().split('/')
    for rule in owner['deny_prefixes']:
        prefix=rule[:-1].lower().split('/')
        if bits[:len(prefix)]==prefix and (directory or len(bits)>len(prefix)):return True
    if any(n in [r.lower() for r in owner['deny_components']] for n in bits):return True
    name='/'.join(bits)
    if not directory and name in [r.lower() for r in owner['deny_exact']]:return True
    allow=[r.lower() for r in owner['allow_exact']]
    if not allow:return False
    if directory:return not any(n.split('/')[:len(bits)]==bits and len(n.split('/'))>len(bits) for n in allow)
    return name not in allow

def observe(owner,policy,code,authority,budget):
    """Reconstruct a second observation, not a producer assertion or snapshot."""
    trace=[];observations=[];sources=[];held=[];files=[];seen=set()
    counts=dict(physical_entries=0,directories=0,pages=0,eligible_files=0,captured_files=0,
                captured_bytes=0,owner_omissions=0,non_source_omissions=0,unparsed_pages=0)
    tick=time.monotonic()
    def deadline():C.need(time.monotonic()-tick<=budget['timeout_seconds'],'VERIFIER_COOPERATIVE_TIMEOUT')
    with ExitStack() as stack:
        product=stack.enter_context(IO.Directory(ROOT))
        root=stack.enter_context(IO.Directory(authority.source_root))
        IO.reject_membership(root,product);IO.reject_membership(product,root)
        for pin in code['files']:
            body=IO.safe_read(ROOT,pin['path'],pin['sha256'],262144).raw
            C.need(len(body)==pin['bytes'],'CODE_CHANGED')
        def walk(handle,folder,depth):
            deadline();counts['directories']+=1
            C.need(counts['directories']<=budget['max_directories'],'VERIFIER_DIRECTORY_BUDGET')
            baseline=IO.metadata(handle,True);held.append((handle,True,baseline))
            observations.append(D.metadata_row(folder or '.',baseline))
            remaining_pages=budget['max_pages']-counts['pages']
            remaining_entries=budget['max_entries']-counts['physical_entries']
            C.need(remaining_pages>0 and remaining_entries>0,'VERIFIER_INVENTORY_BUDGET')
            entries,events=_scan(handle,dict(budget,max_pages=remaining_pages,max_entries=remaining_entries))
            counts['pages']+=len(events)
            C.need(counts['pages']<=budget['max_pages'],'VERIFIER_PAGE_BUDGET')
            trace.extend(dict(e,directory=folder or '.') for e in events)
            counts['physical_entries']+=sum(e['decoded_entries'] for e in events)
            C.need(counts['physical_entries']<=budget['max_entries'],'VERIFIER_ENTRY_BUDGET')
            for entry in entries:
                deadline();name=entry['name'];path=(folder+'/' if folder else '')+name
                C.need(len(path)<=budget['max_path_chars'],'VERIFIER_PATH_BUDGET')
                directory=bool(entry['attributes']&16)
                if _deny(path,owner,directory):
                    counts['owner_omissions']+=1
                    trace.append(dict(event='OWNER_OMITTED',locator_sha256=C.digest(path.encode('ascii')),directory=directory));continue
                C.need(not entry['tag'] and not entry['attributes']&0x445440,'VERIFIER_UNSAFE_ATTRIBUTES')
                if any(any(s in n.lower() for s in C.SENSITIVE) for n in path.split('/')):
                    counts['non_source_omissions']+=1
                    trace.append(dict(event='SENSITIVE_OMITTED',locator_sha256=C.digest(path.encode('ascii'))));continue
                if directory and not name.isidentifier():
                    counts['non_source_omissions']+=1
                    trace.append(dict(event='NON_MODULE_DIRECTORY_OMITTED',locator_sha256=C.digest(path.encode('ascii'))));continue
                if not directory and not name.endswith('.py'):
                    counts['non_source_omissions']+=1;continue
                if directory:C.need(depth<min(budget['max_depth'],policy['max_depth']),'VERIFIER_DEPTH_BUDGET')
                else:
                    C.source_path(path);counts['eligible_files']+=1
                    C.need(counts['eligible_files']<=min(budget['max_files'],policy['max_catalog_files']),'VERIFIER_FILE_BUDGET')
                child=stack.enter_context(_metadata_handle(handle,name,directory));meta=IO.metadata(child,directory)
                C.need(meta.identity[1]==entry['file_id'] and meta.attributes==entry['attributes']
                    and meta.tag==entry['tag'],'VERIFIER_ENUMERATED_ID')
                if directory:walk(child,path,depth+1)
                else:
                    C.need(meta.size==entry['size'] and list(meta.times)==entry['times'],'VERIFIER_ENUMERATED_METADATA')
                    C.need(meta.identity not in seen,'VERIFIER_IDENTITY_COLLISION');seen.add(meta.identity)
                    C.need(meta.size<=min(budget['max_file_bytes'],policy['max_file_bytes']),'VERIFIER_FILE_SIZE')
                    held.append((child,False,meta));observations.append(D.metadata_row(path,meta));files.append((path,child,meta))
        current=root.handle
        if authority.scope!='.':
            components=[]
            for name in authority.scope.split('/'):
                components.append(name);C.need(not _deny('/'.join(components),owner,True),'OWNER_SCOPE_DENIED')
                current=stack.enter_context(_metadata_handle(current,name,True))
        walk(current,'' if authority.scope=='.' else authority.scope,0)
        for handle,directory,meta in held:C.need(IO.metadata(handle,directory)==meta,'VERIFIER_SOURCE_CHANGED')
        C.need(files and sum(m.size for _,_,m in files)<=min(budget['max_total_bytes'],policy['max_total_read_bytes']),'VERIFIER_TOTAL_BYTES')
        for path,retained,meta in sorted(files):
            deadline();C.need(IO.metadata(retained,False)==meta,'VERIFIER_SOURCE_CHANGED')
            rr=IO.safe_read(authority.source_root,path,None,meta.size)
            C.need(rr.metadata==meta and IO.metadata(retained,False)==meta,'VERIFIER_SOURCE_CHANGED')
            sources.append(dict(path=path,sha256=rr.sha256,bytes=len(rr.raw)))
            counts['captured_files']+=1;counts['captured_bytes']+=len(rr.raw)
            trace.append(dict(event='CAPTURED',path=path,bytes=len(rr.raw),sha256=rr.sha256))
        for handle,directory,meta in held:C.need(IO.metadata(handle,directory)==meta,'VERIFIER_SOURCE_CHANGED')
        product.validate();root.validate()
    value=D.result(authority,budget,sources,trace,observations,counts,None)
    C.catalog(value['catalog'],policy)
    return value

def verify(artifacts,owner_raw,selection_raw,code_raw,authority,manifest_sha256):
    owner,policy,code=D.authenticate(owner_raw,selection_raw,code_raw,authority)
    C.need(C.hash_value(manifest_sha256),'ARTIFACT_MANIFEST_ANCHOR_REQUIRED')
    with IO.Directory(artifacts) as bundle, IO.Directory(authority.source_root) as source:
        IO.reject_membership(bundle,source)
        manifest=C.strict(IO.safe_read(artifacts,'MANIFEST.json',manifest_sha256,262144).raw)
        C.need(type(manifest) is dict and set(manifest)=={'schema','files'} and manifest['schema']=='pgop1.discovery-artifacts.v1'
               and type(manifest['files']) is dict and set(manifest['files'])==D.PAYLOADS,'DISCOVERY_MANIFEST_SCHEMA')
        budget=D.limits()
        members,_=_scan(bundle.handle,budget)
        C.need({m['name'] for m in members}==D.PAYLOADS|{'MANIFEST.json'} and
               all(not m['attributes']&(16|0x445440) and not m['tag'] for m in members),'DISCOVERY_MEMBERSHIP')
        def load(name,cap=262144):
            pin=manifest['files'][name]
            C.need(type(pin) is dict and set(pin)=={'sha256','bytes'} and type(pin['bytes']) is int
                   and 0<=pin['bytes']<=cap and C.hash_value(pin['sha256']),'DISCOVERY_MEMBER_PIN')
            body=IO.safe_read(artifacts,name,pin['sha256'],cap).raw
            C.need(len(body)==pin['bytes'],'DISCOVERY_MEMBER_SIZE');return body
        C.need(load('OWNER_POLICY.json')==owner_raw and load('SELECTION_POLICY.json')==selection_raw
               and load('CODE_IDENTITY.json')==code_raw,'DISCOVERY_INPUT_SUBSTITUTION')
        claimed=C.strict(load('DISCOVERY.json',16000000))
        catalog=C.strict(load('CATALOG_CANDIDATE.json'))
        C.need(type(claimed) is dict and claimed.get('status')=='CATALOG_DISCOVERED','DISCOVERY_INCOMPLETE_NOT_VERIFIED')
        budget=D.limits(claimed.get('limits'))
        expected=observe(owner,policy,code,authority,budget)
        C.need(C.canonical(claimed)==C.canonical(expected) and catalog==expected['catalog'],'DISCOVERY_SEMANTIC_MISMATCH')
        bundle.validate();source.validate()
    return dict(status='DISCOVERY_VERIFIED',manifest_sha256=manifest_sha256,
        catalog_candidate_sha256=expected['catalog_candidate_sha256'],members=len(catalog['sources']),
        scope='TWO_BOUNDED_NATIVE_OBSERVATIONS',producer_imported=False,
        catalog_authority='CANDIDATE_NOT_EXTERNALLY_ADMITTED',autonomous_from_root='PARTIAL_TWO_STAGE',
        source_current_at_ack='NOT_PROVEN',artifact_current_at_ack='NOT_PROVEN',atomic_snapshot='NOT_PROVEN')

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['artifacts','manifest-sha256','source-root','admission-policy','admission-policy-sha256',
                 'policy','policy-sha256','code-manifest','code-sha256']:p.add_argument('--'+name,required=True)
    p.add_argument('--scope',default='.');p.add_argument('--package-root',default='.')
    a=p.parse_args()
    authority=D.DiscoveryAuthority(a.source_root,a.admission_policy_sha256,a.policy_sha256,a.code_sha256,a.scope,a.package_root)
    def control(path,pin):return IO.safe_read(Path(path).parent,Path(path).name,pin,262144).raw
    try:
        result=verify(a.artifacts,control(a.admission_policy,a.admission_policy_sha256),control(a.policy,a.policy_sha256),
            control(a.code_manifest,a.code_sha256),authority,a.manifest_sha256)
        print(json.dumps(result,sort_keys=True));return 0
    except (ValueError,OSError):
        print(json.dumps(dict(status='REJECTED',reason='DISCOVERY_VERIFICATION_FAILED')),file=sys.stderr);return 1
if __name__=='__main__':sys.exit(main())
