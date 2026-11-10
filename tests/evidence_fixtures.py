"""Synthetic, inert fixture contracts; expectations are outside source manifests."""
import copy
from pathlib import Path
from candidate.public_handoff import encoded,sha
from candidate.evidence_handoff import EvidenceProfile

def event(ident,role,requires=(),version='v1',event_id=None,result=None,supersedes=None,run='FIXTURE001'):
    return {'schema':'pgop1.fixture-event.v1','id':ident,'role':role,'run_id':run,'version':version,'event_id':event_id or ident+'-event','requires':list(requires),'result':result,'supersedes':supersedes}

def multi_docs():
    return {'CONFIG.json':event('config','config'), 'EXECUTION.json':event('execution','execution',['config@v1']), 'TEST_RESULTS.json':event('tests','tests',['execution@v1'],result='PASS'), 'RECOVERY.json':event('recovery','recovery',['tests@v1'])}

def setup(base,documents=None,code=None,claims=()):
    base=Path(base);base.mkdir(parents=True,exist_ok=True)
    inputs=base/'sources';config=base/'config';inputs.mkdir();config.mkdir()
    files={};sources={}
    if code is None:
        documents=documents if documents is not None else multi_docs()
        for path,data in documents.items():
            raw=encoded(data);(inputs/path).write_bytes(raw);files[path]=sha(raw)
            sources[path]={'id':data['id'],'role':data['role'],'version':data['version'],'bytes':len(raw),'language':'json'}
        fmt='multisource-v1';roles=['config','execution','tests','recovery']
    else:
        for index,(path,raw) in enumerate(code.items()):
            if isinstance(raw,str):raw=raw.encode('utf8')
            (inputs/path).write_bytes(raw);files[path]=sha(raw)
            sources[path]={'id':'code'+str(index),'role':'code','version':'v1','bytes':len(raw),'language':'python' if path.endswith('.py') else 'javascript'}
        fmt='source-static-v1';roles=[]
    entry={'format':fmt,'synthetic':True,'run_id':'FIXTURE001','files':files,'sources':sources,'required_roles':roles,'claims':list(claims),'summary':next(iter(files))}
    catalog={'schema':'pgop1.evidence-catalog.v1','profile':'evidence-local-v1','source_root':str(inputs.absolute()),'packages':{'FIXTURE':entry}}
    (config/'CATALOG.json').write_bytes(encoded(catalog))
    return EvidenceProfile(config,base/'reports'),catalog

def repin(api,catalog):
    (api.catalog_path).write_bytes(encoded(catalog))
    return EvidenceProfile(api.catalog_path.parent,api.out)
