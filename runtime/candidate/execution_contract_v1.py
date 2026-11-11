"""Closed admission contract; a catalog cannot choose commands or code."""
from pathlib import Path
import re
from .document_claims_v1 import require, strict_json, document_span
from .static_ast_v2 import canonical, digest

SCHEMA = 'pgop1.execution-evidence.v1'
CATALOG = 'pgop1.execution-catalog.v1'
ROOT = Path(__file__).absolute().parents[2]
ACTIONS = {'exit_zero','exit_seven','stderr_zero','forged_stdout','artifact_good',
           'artifact_missing','timeout','overflow','snapshot_roundtrip','snapshot_rejection'}
SCOPE = dict(source_current_at_ack='NOT_PROVEN', artifact_current_at_ack='NOT_PROVEN',
             windows_security_qualification='PARTIAL', resource_isolation='NOT_PROVEN',
             observation_kind='EXECUTION_OBSERVED_WITHIN_TRUSTED_LOCAL_RUNNER',
             provenance='CALLER_HELD_RUN_ANCHOR_REQUIRES_TRUSTED_LOCAL_LAUNCH',
             functional_guarantee='NOT_PROVEN', atomic_multifile_capture='NOT_PROVEN',
             host_authentication='NOT_PROVEN', imported_receipts='NOT_SUPPORTED')
HANDOFF = b'# Execution evidence v1\n\nHistorical local observations only. General functional guarantees NOT_PROVEN.\n'
PAYLOAD = b'PGOP1 synthetic artifact v1\x00\xff\n'
MAX_STREAM = 65536
MAX_PACKET = 64_000_000

def hash_value(value):
    require(type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None,'HASH_TYPE')
    return value

def token(value):
    require(type(value) is str and re.fullmatch('[A-Za-z0-9_-]{1,64}',value) is not None,'TOKEN')
    return value

def pin(raw): return dict(bytes=len(raw),sha256=digest(raw))

def code_paths():
    # Deliberate closed installation membership, independent of catalog commands.
    return sorted([p.relative_to(ROOT).as_posix() for directory in ('runtime/candidate','tools')
                   for p in (ROOT/directory).glob('*.py')])

def validate_catalog(catalog, expected):
    from tools.verify_semantic_engine_v1 import check_catalog
    hash_value(expected)
    require(type(catalog) is dict and set(catalog)=={'schema','static_catalog','code_pins','executable_sha256','cases'},'CATALOG_FIELDS')
    require(catalog['schema']==CATALOG and digest(canonical(catalog))==expected,'EXTERNAL_CATALOG_ANCHOR')
    check_catalog(catalog['static_catalog'],digest(canonical(catalog['static_catalog'])))
    require(all(p['kind'] in {'document','file'} for p in catalog['static_catalog']['catalog']['sources'])
            and not catalog['static_catalog']['catalog']['claims'],'DEMO_NO_AST_DESCENDANTS')
    require(len(catalog['static_catalog']['sources'])<=8 and sum(p['bytes'] for p in catalog['static_catalog']['sources'])<=65536,'DEMO_INPUT_BUDGET')
    hash_value(catalog['executable_sha256'])
    require(type(catalog['code_pins']) is dict and 1<=len(catalog['code_pins'])<=100,'CODE_MEMBERSHIP')
    for name,sha in catalog['code_pins'].items():
        require(type(name) is str and re.fullmatch(r'(?:runtime/candidate|tools)/[A-Za-z0-9_]+\.py',name) is not None,'CODE_PATH')
        hash_value(sha)
    cases=catalog['cases']; require(type(cases) is list and 1<=len(cases)<=16,'CASE_COUNT')
    ids=set(); pins={p['path']:p for p in catalog['static_catalog']['catalog']['sources']}
    for case in cases:
        require(type(case) is dict and set(case)=={'case_id','action','predicate','expected','document','scope','formulation'},'CASE_FIELDS')
        token(case['case_id']); require(case['case_id'] not in ids,'DUPLICATE_CASE');ids.add(case['case_id'])
        require(case['action'] in ACTIONS,'ACTION_NOT_ALLOWLISTED')
        require(case['predicate'] in {'process_exit_observed','artifact_bytes_observed','roundtrip_or_rejection_observed'},'PREDICATE')
        require(case['scope'] in {'THIS_RUN_ONLY','GENERAL'},'SCOPE')
        require(type(case['formulation']) is str and 1<=len(case['formulation'])<=500,'FORMULATION')
        if case['predicate']=='process_exit_observed':require(type(case['expected']) is int and -2147483648<=case['expected']<=4294967295,'EXPECTED_EXIT_TYPE')
        elif case['predicate']=='artifact_bytes_observed':
            require(type(case['expected']) is dict and set(case['expected'])=={'bytes','sha256'} and type(case['expected']['bytes']) is int and 0<=case['expected']['bytes']<=MAX_STREAM,'EXPECTED_ARTIFACT_TYPE')
            hash_value(case['expected']['sha256'])
        else:require(type(case['expected']) is str and case['expected'] in {'ROUNDTRIP','REJECTION'},'EXPECTED_EFFECT_TYPE')
        doc=case['document'];require(type(doc) is dict and set(doc)=={'path','sha256','start_line','end_line','span_sha256'},'DOCUMENT_FIELDS')
        require(doc['path'] in pins and pins[doc['path']]['kind']=='document' and pins[doc['path']]['sha256']==doc['sha256'],'DOCUMENT_MEMBERSHIP')
        require(type(doc['start_line']) is int and type(doc['end_line']) is int and 1<=doc['start_line']<=doc['end_line']<=100000,'DOCUMENT_SPAN')
        hash_value(doc['span_sha256'])
    return catalog

def packet_identity(catalog_sha,request_id):
    token(request_id);hash_value(catalog_sha)
    return digest(canonical(dict(schema=SCHEMA,catalog_sha256=catalog_sha,request_id=request_id)))


def closed_formulation(case):
    """Finite language for the observed predicate, never arbitrary prose truth."""
    action=case['action'];expected=case['expected']
    if case['predicate']=='process_exit_observed':
        return f'In this run, action {action} returned the exact integer exit code {expected}.'
    if case['predicate']=='artifact_bytes_observed':
        return f'In this run, action {action} produced result.bin with {expected["bytes"]} bytes and SHA256 {expected["sha256"]}.'
    if expected=='ROUNDTRIP':
        return f'In this run, action {action} reproduced the exact historical static envelope in a separate process.'
    return f'In this run, action {action} rejected a private copy whose INTEGRATION.json had one trailing space, with SOURCE_HASH.'

def envelope(catalog, static, rows, run_id):
    semantic=dict(schema=SCHEMA,catalog_sha256=digest(canonical(catalog)),snapshot_id=static['snapshot_id'],
                  claims=[{k:v for k,v in row.items() if k!='run_id'} for row in rows])
    identity=dict(schema=SCHEMA,catalog_sha256=digest(canonical(catalog)),snapshot_id=static['snapshot_id'],
                  static_integration_id=static['integration_id'],run_id=run_id,scope=SCOPE,
                  behavioral_semantic_id='behavior-'+digest(canonical(semantic)),
                  sources=static['sources'],structures=static['structures'],claims=rows)
    return dict(identity,integration_id='execution-'+digest(canonical(identity)))
