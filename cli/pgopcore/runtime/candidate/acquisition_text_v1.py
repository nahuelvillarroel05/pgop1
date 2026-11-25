"""Opt-in ASCII-path text acquisition. External caller pins are mandatory.

No grant generation, discovery authority, Python dispatch or persistent memory.
Native E8 primitives are reused without changing their contracts.
"""
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
import json
import math
import time
from . import selection_contract_v1 as C
from . import windows_safe_io_v2 as IO
from . import windows_directory_enumeration_v1 as N

SCHEMA='pgop1.acquisition-text.v1'
VERSION='strict-utf8-text-json-v1'
SCHEMA_V2='pgop1.acquisition-text.v2'
VERSION_V2='strict-utf8-text-json-v2'
LEGACY_FORMATS=('.json','.md','.txt')
FORMATS=('.csv','.json','.md','.py','.txt')
PRODUCT=Path(__file__).absolute().parents[2]
CODE_FILES=tuple('runtime/candidate/'+n+'.py' for n in (
    'acquisition_text_v1','windows_safe_io_v2','windows_directory_enumeration_v1',
    'selection_contract_v1','discovery_contract_v1','admission_contract_v2'))

@dataclass(frozen=True)
class Authority:
    root_id:str
    source_root:str
    catalog_sha256:str
    policy_sha256:str
    grant_sha256:str
    code_sha256:str

def code_digest():
    try:
        return C.digest(C.canonical({n:IO.safe_read(PRODUCT,n,None,262144).sha256 for n in CODE_FILES}))
    except IO.SafeIOError as exc:
        if exc.code.startswith(('UNSUPPORTED_SAFE_READ', 'UNSUPPORTED_WINDOWS')):
            raise
        raise ValueError('INSTALLED_CODE_UNAVAILABLE') from None
    except OSError:
        raise ValueError('INSTALLED_CODE_UNAVAILABLE') from None

def pinned(raw,pin):
    C.need(type(raw) is bytes and len(raw)<=262144 and C.hash_value(pin) and C.digest(raw)==pin,'EXTERNAL_PIN')
    return C.strict(raw)

def identity(value):
    C.need(type(value) is list and len(value)==2 and type(value[0]) is int
           and value[0]>=0 and type(value[1]) is str and len(value[1])==32
           and all(c in '0123456789abcdef' for c in value[1]),'PHYSICAL_IDENTITY')

def schema_for(formats):
    return SCHEMA if all(fmt in LEGACY_FORMATS for fmt in formats) else SCHEMA_V2

def path(name, *, legacy=False):
    parts=IO.relative(name)
    C.need(len(name)<=1024 and len(parts)-1<=5,'PATH_BUDGET')
    C.need(not any(any(s in part.lower() for s in C.SENSITIVE) for part in parts),'SENSITIVE_PATH')
    fmt=Path(name).suffix
    C.need(fmt in (LEGACY_FORMATS if legacy else FORMATS),'UNSUPPORTED_FORMAT')
    return fmt

def authenticate(catalog_raw,policy_raw,grant_raw,authority):
    C.need(type(authority) is Authority,'EXTERNAL_AUTHORITY_REQUIRED')
    IO.component(authority.root_id);IO.absolute(authority.source_root)
    p=pinned(policy_raw,authority.policy_sha256)
    C.need(type(p) is dict and set(p)=={'schema','root_id','source_root','root_identity','scope','enabled','formats','deny_prefixes','deny_exact','allow_exact'},'POLICY_SCHEMA')
    C.need(p['root_id']==authority.root_id and p['source_root']==authority.source_root,'ROOT_AUTHORITY')
    identity(p['root_identity'])
    C.need(p['scope']=='.' and type(p['enabled']) is bool,'POLICY_SCOPE')
    C.need(p['enabled'],'REVOKED_POLICY')
    C.need(type(p['formats']) is list and p['formats']==sorted(set(p['formats'])) and set(p['formats'])<=set(FORMATS) and p['formats'],'FORMAT_GRANT')
    schema=schema_for(p['formats'])
    C.need(p['schema']==schema+'.policy','POLICY_SCHEMA')
    for field in ('deny_prefixes','deny_exact','allow_exact'):
        rules=p[field];C.need(type(rules) is list and len(rules)<=256 and all(type(v) is str for v in rules),'POLICY_RULES')
        C.need(rules==sorted(rules) and len(set(v.lower() for v in rules))==len(rules),'POLICY_COLLISION')
        for v in rules:
            if field=='deny_prefixes':C.need(v.endswith('/'),'POLICY_PREFIX');IO.relative(v[:-1])
            else:IO.relative(v)
    c=pinned(catalog_raw,authority.catalog_sha256)
    C.need(type(c) is dict and set(c)=={'schema','root_id','source_root','scope','sources'} and c['schema']==schema+'.candidate','CATALOG_SCHEMA')
    C.need(c['root_id']==p['root_id'] and c['source_root']==p['source_root'] and c['scope']==p['scope'],'ROOT_AUTHORITY')
    rows=c['sources'];C.need(type(rows) is list and 1<=len(rows)<=256,'CATALOG_LIMIT')
    C.need(len(rows)<=32,'SELECTION_LIMIT')
    names=[];ids=[];total=0
    for r in rows:
        C.need(type(r) is dict and set(r)=={'path','sha256','bytes','identity','times'},'SOURCE_SCHEMA')
        fmt=path(r['path']);name=r['path'].lower();names.append(r['path'])
        C.need(fmt in p['formats'],'FORMAT_GRANT')
        C.need(not any(name.startswith(v.lower()) for v in p['deny_prefixes']) and name not in [v.lower() for v in p['deny_exact']]
               and (not p['allow_exact'] or name in [v.lower() for v in p['allow_exact']]),'OWNER_DENIED')
        C.need(C.hash_value(r['sha256']) and type(r['bytes']) is int and 0<=r['bytes']<=262144,'SOURCE_LIMIT')
        identity(r['identity']);ids.append(tuple(r['identity']))
        C.need(type(r['times']) is list and len(r['times'])==3 and all(type(v) is int for v in r['times']),'SOURCE_TIMES')
        total+=r['bytes']
    C.need(names==sorted(names) and len(set(v.lower() for v in names))==len(names),'PATH_COLLISION')
    C.need(len(set(ids))==len(ids),'IDENTITY_COLLISION');C.need(total<=16777216,'TOTAL_BYTE_LIMIT')
    g=pinned(grant_raw,authority.grant_sha256)
    C.need(type(g) is dict and set(g)=={'schema','root_id','source_root','catalog_sha256','policy_sha256','code_sha256','formats','external_admission_ref','batch_id'},'GRANT_SCHEMA')
    C.need(g['schema']==schema+'.external-grant' and g['root_id']==authority.root_id and g['source_root']==authority.source_root,'ROOT_AUTHORITY')
    C.need(g['catalog_sha256']==authority.catalog_sha256 and g['policy_sha256']==authority.policy_sha256 and g['code_sha256']==authority.code_sha256,'GRANT_BINDING')
    C.need(g['formats']==p['formats'],'FORMAT_GRANT')
    IO.component(g['batch_id']);IO.component(g['external_admission_ref'])
    C.need(code_digest()==authority.code_sha256,'CODE_CHANGED')
    return c,p,g

def extract(raw,fmt):
    C.need(type(raw) is bytes and len(raw)<=262144,'SOURCE_LIMIT')
    C.need(fmt in FORMATS,'UNSUPPORTED_FORMAT')
    C.need(not raw.startswith(b'\xef\xbb\xbf'),'BOM_REJECTED')
    try:text=raw.decode('utf8',errors='strict')
    except UnicodeError:raise ValueError('UTF8_INVALID') from None
    C.need('\x00' not in text,'NUL_REJECTED')
    schema=schema_for([fmt])
    report=dict(schema=schema+'.extraction',extractor_version=VERSION if schema==SCHEMA else VERSION_V2,
                format=fmt,scope='UNTRUSTED_DATA_NO_EXECUTION',text=text)
    if fmt=='.json':
        # Lexical bound precedes json.loads, including deeply nested invalid input.
        depth=0;quoted=False;escaped=False
        for ch in text:
            if quoted:
                if escaped:escaped=False
                elif ch=='\\':escaped=True
                elif ch=='"':quoted=False
            elif ch=='"':quoted=True
            elif ch in '[{':depth+=1;C.need(depth<=32,'JSON_DEPTH_LIMIT')
            elif ch in ']}':depth-=1
        def pairs(items):
            out={}
            for k,v in items:C.need(k not in out,'JSON_DUPLICATE_KEY');out[k]=v
            return out
        try:value=json.loads(text,object_pairs_hook=pairs,parse_constant=lambda _:C.need(False,'JSON_NONFINITE'))
        except (json.JSONDecodeError,RecursionError):raise ValueError('JSON_INVALID') from None
        stack=[value];count=0
        while stack:
            v=stack.pop();count+=1;C.need(count<=4096,'JSON_ELEMENT_LIMIT')
            if type(v) is dict:stack.extend(v.values());stack.extend(v.keys())
            elif type(v) is list:stack.extend(v)
            elif type(v) is float:C.need(math.isfinite(v),'JSON_NONFINITE')
            elif type(v) is str:C.need(not any(0xd800<=ord(ch)<=0xdfff for ch in v),'JSON_INVALID_UNICODE')
        report.update(value=value,json_elements=count)
    return report

def acquire(catalog_raw,policy_raw,grant_raw,authority, *, visible=False):
    started=time.perf_counter();c,p,g=authenticate(catalog_raw,policy_raw,grant_raw,authority)
    records=[]
    schema=schema_for(p['formats'])
    with IO.Directory(PRODUCT) as product,IO.Directory(authority.source_root) as root:
        IO.reject_membership(root,product);IO.reject_membership(product,root)
        C.need(list(root.ids[-1])==p['root_identity'],'ROOT_IDENTITY_CHANGED')
        for row in c['sources']:
            C.need(time.perf_counter()-started<=30,'ACQUISITION_TIMEOUT');t=time.perf_counter()
            with ExitStack() as tx:
                parent=root.handle
                parts=IO.relative(row['path'])
                for part in parts[:-1]:parent=tx.enter_context(N.open_metadata(parent,part,directory=True))
                retained=tx.enter_context(N.open_metadata(parent,parts[-1],directory=False))
                if visible:
                    N.validate_visible(root)
                meta=N.visible_metadata(retained,False) if visible else IO.metadata(retained,False)
                C.need(list(meta.identity)==row['identity'] and list(meta.times)==row['times'],'SOURCE_IDENTITY_CHANGED')
                C.need(meta.size==row['bytes'],'SOURCE_SIZE_CHANGED')
                raw=N.capture(parent,parts[-1],retained,meta,row['bytes'])
                C.need(C.digest(raw)==row['sha256'],'SOURCE_HASH_MISMATCH')
                read_ms=(time.perf_counter()-t)*1000;t=time.perf_counter()
                report=extract(raw,path(row['path']))
                if visible:
                    N.validate_visible(root)
                else:
                    root.validate()
                source_id=C.digest(C.canonical([authority.root_id,p['root_identity'],row['path']]))
                receipt=dict(schema=schema+'.read-receipt',root_id=authority.root_id,source_root=authority.source_root,
                    root_identity=p['root_identity'],source_id=source_id,relative_path=row['path'],format=report['format'],
                    batch_id=g['batch_id'],catalog_digest=authority.catalog_sha256,external_admission_ref=g['external_admission_ref'],
                    external_grant_digest=authority.grant_sha256,policy_digest=authority.policy_sha256,path_identity=row['identity'],
                    source_hash=row['sha256'],bytes=len(raw),metadata_times=list(meta.times),adapter_version=report['extractor_version'],
                    code_digest=authority.code_sha256,validated_report_digest=C.digest(C.canonical(report)),result='SAFELY_READ_AND_EXTRACTED',
                    read_ms=read_ms,extract_ms=(time.perf_counter()-t)*1000,currentness='VERIFIED_DURING_HELD_NATIVE_READ_NOT_AT_FUTURE_ACK')
                records.append(dict(receipt=receipt,report=report,receipt_digest=C.digest(C.canonical(receipt))))
        root.validate()
    return dict(schema=schema,records=records,counts=dict(CANDIDATE=len(records),EXTERNALLY_ADMITTED=len(records),SAFELY_READ=len(records),DECODED=len(records),
        PARSED=sum(r['report']['format']=='.json' for r in records),TEXT_EXTRACTED=len(records),AST_ANALYZED=0,STORED=0,INDEXED=0,RETRIEVABLE_CURRENT=0),
        wall_ms=(time.perf_counter()-started)*1000,authority='EXTERNAL_CALLER_PINS_ONLY',atomic_snapshot='NOT_PROVEN')
