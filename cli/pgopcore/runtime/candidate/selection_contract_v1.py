"""E7 pure schemas only; no discovery, selection, source reads or resolution."""
import hashlib
import json
import re
from .windows_safe_io_v2 import absolute, relative

ALGORITHM = 'catalog-fifo-e6-compat-v1.0.0'
POLICY = {
    'schema':'pgop1.selection-policy.v1', 'algorithm':ALGORITHM,
    'max_catalog_files':256, 'max_planning_files':128, 'max_selected':32,
    'max_file_bytes':262144, 'max_total_read_bytes':16777216, 'max_depth':5,
    'ast_nodes':50000, 'ast_depth':160, 'ast_unit_nodes':12000,
    'parse_timeout_seconds':6, 'seed_rule':'sorted-root-init-and-first-noninit-per-immediate-directory',
    'frontier':'FIFO-admission-order-per-origin-path-sort',
    'parents':'existing-shallow-first-atomic-group',
    'fill':'lexicographic-noninit-skip-unfittable',
}
SENSITIVE = ('.git','__pycache__','.venv','venv','secret','credential','private_key',
             'token','dataset','corpus','model','checkpoint','gold','holdout')
def canonical(v):
    return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode('ascii')
def digest(b): return hashlib.sha256(b).hexdigest()
def need(ok,code):
    if not ok: raise ValueError(code)
def strict(raw):
    def pairs(items):
        d={}
        for k,v in items:
            need(k not in d,'DUPLICATE_JSON_KEY');d[k]=v
        return d
    v=json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'NONFINITE_JSON'))
    need(canonical(v)==raw,'CANONICAL_JSON_REQUIRED')
    return v
def hash_value(s): return isinstance(s,str) and re.fullmatch('[a-f0-9]{64}',s) is not None
def policy(v):
    need(isinstance(v,dict) and set(v)==set(POLICY),'POLICY_SCHEMA')
    for key,default in POLICY.items():
        if type(default) is int:
            need(type(v[key]) is int and 1<=v[key]<=default,'POLICY_LIMIT_'+key)
        else: need(v[key]==default,'POLICY_RULE_'+key)
    return v
def source_path(name):
    relative(name)
    need(name.endswith('.py') and all(p.isidentifier() for p in name[:-3].split('/')),'MODULE_PATH')
def catalog(c,p):
    need(isinstance(c,dict) and set(c)=={'schema','source_root','scope','package_root','sources'},'CATALOG_SCHEMA')
    need(c['schema']=='pgop1.selection-catalog.v1','CATALOG_SCHEMA')
    absolute(c['source_root'])
    for field in ('scope','package_root'):
        if c[field]!='.':
            relative(c[field]);need(all(n.isidentifier() for n in c[field].split('/')),'CATALOG_SCOPE')
    pref='' if c['package_root']=='.' else c['package_root']+'/'
    need(not pref or (c['scope']!='.' and (c['scope']+'/').startswith(pref)),'PACKAGE_ROOT_SCOPE')
    rows=c['sources'];need(isinstance(rows,list) and 1<=len(rows)<=p['max_catalog_files'],'CATALOG_BUDGET')
    names=[]
    for r in rows:
        need(isinstance(r,dict) and set(r)=={'path','sha256','bytes'},'SOURCE_SCHEMA')
        source_path(r['path']);need(hash_value(r['sha256']),'SOURCE_HASH')
        need(type(r['bytes']) is int and 0<=r['bytes']<=p['max_file_bytes'],'SOURCE_SIZE')
        name=r['path'];scope='' if c['scope']=='.' else c['scope']+'/'
        need(name.startswith(scope),'SOURCE_OUTSIDE_SCOPE')
        parts=name[len(scope):].split('/')
        need(len(parts)-1<=p['max_depth'],'SOURCE_DEPTH')
        need(not any(any(s in part.casefold() for s in SENSITIVE) for part in name.split('/')),'SENSITIVE_PATH')
        names.append(name)
    need(names==sorted(names) and len(set(n.casefold() for n in names))==len(names),'SOURCE_ORDER_OR_COLLISION')
    return c
def code_manifest(v):
    need(isinstance(v,dict) and set(v)=={'schema','files'},'CODE_SCHEMA')
    need(v['schema']=='pgop1.selection-code.v1' and isinstance(v['files'],list) and 1<=len(v['files'])<=512,'CODE_SCHEMA')
    names=[]
    for r in v['files']:
        need(set(r)=={'path','sha256','bytes'},'CODE_FILE_SCHEMA')
        relative(r['path']);need(hash_value(r['sha256']) and type(r['bytes']) is int and 0<=r['bytes']<=262144,'CODE_PIN')
        names.append(r['path'])
    need(names==sorted(set(names)),'CODE_ORDER')
    required={'runtime/candidate/selection_contract_v1.py','runtime/candidate/source_selection_v1.py',
              'runtime/candidate/static_ast_v2.py','runtime/candidate/windows_safe_io_v2.py',
              'tools/source_selection_v1.py','tools/verify_selection_v1.py','tools/verify_source_v2.py'}
    need(required<=set(names),'CODE_CLOSURE_REQUIRED')
    return v
