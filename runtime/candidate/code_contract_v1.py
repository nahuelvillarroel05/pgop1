"""Pure opt-in E3 schema/serialization. No source analysis or publication."""
import os
import hashlib
import json
import re
import unicodedata
from .windows_safe_io_v2 import absolute, relative

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')

def digest(raw):
    return hashlib.sha256(raw).hexdigest()

def require(ok,code):
    if not ok:raise ValueError(code)

CATALOG = 'pgop1.code-only-catalog.v1'
CLAIM = 'pgop1.code-only-claims.v1'
RESOLUTION = 'pgop1.static-module-resolution.v1'
SCOPE = dict(source_current_at_ack='NOT_PROVEN', artifact_current_at_ack='NOT_PROVEN',
             execution='NOT_PERFORMED', BEHAVIORAL_LINK='NOT_PROVEN',
             MEMORY_INTEGRATION='DEFERRED', parser_independence='SHARED_CPYTHON_AST')
HANDOFF = b'# Code-only v1\n\nSyntax of pinned captured bytes only. Current at ACK: NOT_PROVEN.\n'
FILES = {'CATALOG.json':262144,'SNAPSHOT.json':36_000_000,'AST_REPORT.json':128_000_000,
         'SNAPSHOT_MANIFEST.json':1_000_000,'SNAPSHOT_HANDOFF.md':1_000_000,
         'REPORT.json':128_000_000,'PAGES.json':128_000_000,'FINAL_HANDOFF.md':1_000_000}

def identifier(s):
    return (isinstance(s,str) and 1<=len(s)<=120 and s.isidentifier()
            and unicodedata.normalize('NFKC',s)==s and s!='WITHHELD')

def dotted(s):
    return isinstance(s,str) and len(s)<=1024 and all(identifier(n) for n in s.split('.'))

def check_catalog(c, expected):
    require(isinstance(c,dict) and set(c)=={'schema','authorized_root','mode','package_roots','sources','claims'},'CATALOG_SCHEMA')
    require(c['schema']==CATALOG and digest(canonical(c))==expected,'EXTERNAL_CATALOG_ANCHOR')
    absolute(c['authorized_root'])
    require(c['mode'] in {'STRICT_RAW','CODE_TREE'},'MODE')
    roots=c['package_roots']; require(isinstance(roots,list) and len(roots)<=8,'ROOTS')
    require(all(isinstance(r,str) for r in roots) and roots==sorted(set(roots)),'ROOTS')
    require(len({r.casefold() for r in roots})==len(roots),'ROOT_COLLISION')
    for root in roots:
        if root!='.':
            relative(root); require(all(identifier(p) for p in root.split('/')),'PACKAGE_ROOT')
    require((c['mode']=='STRICT_RAW' and not roots) or (c['mode']=='CODE_TREE' and roots),'ROOT_MODE')
    pins=c['sources']; require(isinstance(pins,list) and 1<=len(pins)<=32,'SOURCE_COUNT')
    seen=set()
    for p in pins:
        require(isinstance(p,dict) and set(p)=={'path','sha256','bytes','kind'},'SOURCE_SCHEMA')
        relative(p['path']); require(p['path'].endswith('.py'),'SOURCE_TYPE')
        require(p['kind']=='python' and type(p['bytes']) is int and 0<=p['bytes']<=262144,'SOURCE_SIZE')
        require(isinstance(p['sha256'],str) and re.fullmatch('[a-f0-9]{64}',p['sha256']) is not None,'SOURCE_HASH')
        require(p['path'].casefold() not in seen,'SOURCE_COLLISION');seen.add(p['path'].casefold())
        if c['mode']=='STRICT_RAW':require(re.fullmatch(r'RAW_[0-9]{4}\.py',p['path']) is not None,'RAW_NAME')
        else:require(all(identifier(s) for s in p['path'][:-3].split('/')),'MODULE_PATH')
    require(pins==sorted(pins,key=lambda p:p['path']),'SOURCE_ORDER')
    module_spellings={}
    for p in pins:
        for root in roots:
            prefix='' if root=='.' else root+'/'
            if not p['path'].startswith(prefix):continue
            parts=p['path'][len(prefix):-3].split('/')
            if parts[-1]=='__init__':parts=parts[:-1]
            name='.'.join(parts)
            if not name:continue
            key=name.casefold()
            require(key not in module_spellings or module_spellings[key]==name,'MODULE_CASEFOLD_COLLISION')
            module_spellings[key]=name
    qs=c['claims'];require(isinstance(qs,list) and len(qs)<=256,'CLAIM_COUNT')
    require(all(isinstance(q,dict) and isinstance(q.get('claim_id'),str) and re.fullmatch(r'[A-Za-z0-9_-]{1,120}',q['claim_id']) for q in qs),'QUERY_ID')
    require(len({q['claim_id'] for q in qs})==len(qs),'DUPLICATE_CLAIM')
    require(qs==sorted(qs,key=lambda q:q['claim_id']),'CLAIM_ORDER')
    return c

def check_claim(q,c):
    require(set(q)=={'schema','claim_id','predicate','source_ref','scope','parameters','expected'},'CLAIM_SCHEMA')
    require(q['schema']==CLAIM and type(q['expected']) is bool,'CLAIM_TYPE')
    require(q['source_ref'] in {p['path'] for p in c['sources']},'UNREGISTERED_SOURCE')
    require(isinstance(q['scope'],str) and (q['scope']=='<module>' or dotted(q['scope']) or re.fullmatch('node-[a-f0-9]{64}',q['scope'])),'SCOPE')
    p=q['parameters'];require(isinstance(p,dict),'PARAMETERS')
    f=q['predicate'];require(f in {'symbol_defined','class_method_declared','function_parameter_declared','module_import_declared'},'PREDICATE_OUTSIDE_CONTRACT')
    if f=='module_import_declared':
        require(set(p)=={'form','module','name','asname','level'} and q['scope']=='<module>','IMPORT_PARAMETERS')
        require(p['form'] in {'import','from'} and type(p['level']) is int and 0<=p['level']<=160,'IMPORT_FORM')
        require(p['module']=='' or dotted(p['module']),'IMPORT_MODULE')
        require(p['asname'] is None or identifier(p['asname']),'IMPORT_ALIAS')
        require((p['form']=='import' and p['module']=='' and p['level']==0 and dotted(p['name'])) or
                (p['form']=='from' and identifier(p['name']) and (p['module']!='' or p['level']>0)),'IMPORT_NAME')
    else:
        require(identifier(p.get('name')),'NAME')
        require(set(p)==({'name'} if f=='class_method_declared' else {'name','kind'}),'PARAMETERS')
        if f=='symbol_defined':require(p['kind'] in {'any','ClassDef','FunctionDef','AsyncFunctionDef'},'SYMBOL_KIND')
        if f=='function_parameter_declared':require(p['kind'] in {'posonly','positional','kwonly','vararg','kwarg'},'PARAMETER_KIND')
    return True

def position(n):
    return dict(line=getattr(n,'lineno',0),column=getattr(n,'col_offset',0),
                end_line=getattr(n,'end_lineno',0),end_column=getattr(n,'end_col_offset',0),node=type(n).__name__)

def finish_report(c, snapshot_id, claims, relations):
    r=dict(schema='pgop1.code-only-report.v1',catalog_sha256=digest(canonical(c)),snapshot_id=snapshot_id,
           selected_universe_id=digest(canonical(c)),resolution_schema=RESOLUTION,
           claims=claims,relations=relations,scope=dict(SCOPE))
    r['report_id']=digest(canonical(r));return r

def pages(report):
    return {kind:[dict(offset=i,items=report[kind][i:i+17]) for i in range(0,len(report[kind]),17)] for kind in ('claims','relations')}

def check_page(offset,limit,total):
    require(type(offset) is int and 0<=offset<=total and type(limit) is int and 1<=limit<=100,'INVALID_PAGE')
