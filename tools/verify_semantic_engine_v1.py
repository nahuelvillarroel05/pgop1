"""Separate integration verifier. No integrated producer import or native source reopen."""
from contextlib import ExitStack
import os
from pathlib import Path
import sys

ROOT = Path(__file__).absolute().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'runtime')]
from tools.verify_snapshot_v1 import verify_values, HANDOFF, SCOPE as SNAPSHOT_SCOPE
from tools import verify_source_v2 as v
from candidate.semantic_memory_v1 import recover

CATALOG = 'pgop1.real-static-catalog.v2'
SCHEMA = 'pgop1.semantic-integration.v1'
SCOPE = dict(source_current_at_ack='NOT_PROVEN', artifact_current_at_ack='NOT_PROVEN',
             source_state='COMMITTED_SNAPSHOT', execution='NOT_PERFORMED',
             semantics='TYPED_PREDICATES_AND_SYNTACTIC_RELATIONS_ONLY',
             prose_truth='NOT_PROVEN', security='NOT_PROVEN', behavior='NOT_PROVEN',
             relationship_mapping='PAYLOAD_ONLY_NO_ENGINE_EDGES')
LIMITS = {'CATALOG.json':262144, 'SNAPSHOT.json':36_000_000,
          'SNAPSHOT_MANIFEST.json':1_000_000,
          'REPORT.json':128_000_000, 'INTEGRATION.json':128_000_000,
          'MEMORY.json':512_000_000, 'FINAL_HANDOFF.md':1_000_000}


def check_catalog(catalog, expected):
    v.check_hash(expected)
    v.require(isinstance(catalog, dict) and set(catalog) == {'schema','profile','catalog','sources'}, 'REAL_V2_CATALOG')
    v.require(catalog['schema'] == CATALOG and catalog['profile'] == 'real-static-v2'
              and v.digest(v.compact(catalog)) == expected, 'EXTERNAL_REAL_CATALOG_ANCHOR')
    pins = v.check_catalog(catalog['catalog'])
    v.require(isinstance(catalog['sources'], list) and len(catalog['sources']) == len(pins), 'REAL_SOURCE_MEMBERSHIP')
    for meta, pin in zip(catalog['sources'], catalog['catalog']['sources']):
        v.require(isinstance(meta, dict) and set(meta) == {'path','sha256','bytes','version','language','scope'}
                  and meta['path'] == pin['path'] and meta['sha256'] == pin['sha256']
                  and type(meta['bytes']) is int and 0 <= meta['bytes'] <= 262144
                  and isinstance(meta['version'],str) and __import__('re').fullmatch(r'[A-Za-z0-9._-]{1,80}',meta['version'])
                  and meta['language'] == {'python':'python','document':'markdown','file':'bytes'}[pin['kind']]
                  and meta['scope'] == 'REGISTERED_FILE_ONLY', 'REAL_SOURCE_DESCRIPTOR')
    return catalog


def derive(catalog, snapshot, report, expected):
    """Authoritative semantics recomputed by existing independent snapshot verifier."""
    check_catalog(catalog, expected)
    inner = v.digest(v.compact(catalog['catalog']))
    v.require(v.compact(report['catalog']) == v.compact(catalog['catalog']), 'REAL_INNER_CATALOG')
    verify_values(report, snapshot, inner)
    sources = []
    bodies = {}
    for meta, capture in zip(catalog['sources'], snapshot['captures']):
        raw = bytes.fromhex(capture['raw_hex'])
        v.require(meta['bytes'] == len(raw), 'REAL_SOURCE_SIZE')
        bodies[meta['path']] = raw
        structure = next((s for s in report['structures'] if s['source']['path'] == meta['path']), None)
        sources.append(dict(meta, start_line=1 if raw else 0, end_line=len(raw.splitlines()),
                            snapshot_id=snapshot['snapshot_id'], coverage=structure['AST_COVERAGE'] if structure else 'CAPTURE_BYTES_ONLY'))
    claims = []
    for row in report['document_claims']['claims']:
        doc = row['claim']['document']
        raw = bodies[doc['path']]
        # Invalid authorized spans remain abstentions. Never manufacture a span.
        lines = raw.splitlines(keepends=True)
        span = b''.join(lines[doc['start_line']-1:doc['end_line']]) if doc['end_line'] <= len(lines) else None
        claims.append(dict(row, literal_span_hex=span.hex() if span is not None else None,
                           evidence_snapshot_id=snapshot['snapshot_id'],
                           qualification='EXACT_TYPED_PREDICATE_ONLY'))
    identity = dict(schema=SCHEMA, catalog_sha256=expected, snapshot_id=snapshot['snapshot_id'],
                    report_sha256=v.digest(v.compact(report)), scope=SCOPE,
                    sources=sources, structures=report['structures'], claims=claims)
    return dict(identity, integration_id='integration-' + v.digest(v.compact(identity)))


def verify_bundle(folder, expected):
    v.require(os.name == 'nt', 'WINDOWS_ONLY')
    from candidate.windows_safe_io_v2 import Directory
    with Directory(folder) as held:
        manifest = v.strict(v.read_source(folder,'MANIFEST.json',None,1_000_000))
        v.require(isinstance(manifest,dict) and set(manifest) == {'schema','catalog_sha256','files'}
                  and manifest['schema'] == 'pgop1.semantic-manifest.v1'
                  and manifest['catalog_sha256'] == expected and isinstance(manifest['files'],dict)
                  and set(manifest['files']) == set(LIMITS), 'INTEGRATION_MANIFEST')
        files = {}
        for name, limit in LIMITS.items():
            pin = manifest['files'][name]
            v.require(isinstance(pin,dict) and set(pin) == {'bytes','sha256'}
                      and type(pin['bytes']) is int and 0 <= pin['bytes'] <= limit, 'ARTIFACT_PIN')
            v.check_hash(pin['sha256'])
            raw = v.read_source(folder,name,pin['sha256'],limit)
            v.require(len(raw) == pin['bytes'], 'ARTIFACT_LENGTH')
            files[name] = raw
        v.require(files['FINAL_HANDOFF.md'] == HANDOFF, 'HANDOFF_SCOPE')
        catalog, snapshot, report = (v.strict(files[n]) for n in ('CATALOG.json','SNAPSHOT.json','REPORT.json'))
        sm = v.strict(files['SNAPSHOT_MANIFEST.json'])
        original_files = {n:dict(bytes=len(files[n]),sha256=v.digest(files[n]))
                          for n in ('SNAPSHOT.json','REPORT.json','FINAL_HANDOFF.md')}
        v.require(v.compact(sm) == v.compact(dict(schema='pgop1.evidence-snapshot-manifest.v1',
                            catalog_sha256=v.digest(v.compact(catalog['catalog'])),
                            snapshot_id=snapshot['snapshot_id'], files=original_files)), 'SNAPSHOT_MANIFEST')
        envelope = derive(catalog,snapshot,report,expected)
        v.require(v.compact(v.strict(files['INTEGRATION.json'])) == v.compact(envelope), 'INTEGRATION_DERIVATION')
        rows = recover(v.strict(files['MEMORY.json']), envelope)
        held.validate()
    return envelope, rows


def query_bundle(folder, expected, *, kind='claims', source=None, offset=0, limit=50):
    envelope, rows = verify_bundle(folder,expected)
    v.require(type(offset) is int and offset >= 0 and type(limit) is int and 1 <= limit <= 100, 'INVALID_PAGE')
    v.require(kind in {'claims','sources','structures','declarations','relations','units','currency'}, 'INVALID_KIND')
    v.require(source is None or source in {s['path'] for s in envelope['sources']}, 'UNREGISTERED_SOURCE')
    if kind == 'currency':
        v.require(offset == 0, 'INVALID_OFFSET')
        return dict(schema=SCHEMA,integration_id=envelope['integration_id'],scope=SCOPE,
                    status='INSUFFICIENT_EVIDENCE',reason='HISTORICAL_SNAPSHOT_ONLY_NO_CURRENT_SOURCE_READ',
                    source=source,items=[],total=0,offset=0,returned=0,remaining=0,next_offset=None)
    if kind in {'declarations','relations','units'}:
        v.require(source is not None, 'EXACT_SOURCE_REQUIRED')
        selected = next((s[kind] for s in envelope['structures'] if s['source']['path'] == source), [])
    else:
        selected = [r['value'] for r in rows if r['kind'] == kind]
        selected.sort(key=lambda r:v.compact(r))
        if source is not None:
            selected = [r for r in selected if (r.get('path') or r.get('source',{}).get('path') or r.get('claim',{}).get('source',{}).get('path')) == source]
    v.require(offset <= len(selected), 'INVALID_OFFSET')
    page = selected[offset:offset+limit]; following = offset+len(page)
    return dict(schema=SCHEMA, integration_id=envelope['integration_id'], scope=SCOPE,
                items=page, offset=offset, total=len(selected), returned=len(page),
                remaining=len(selected)-following, next_offset=following if following < len(selected) else None)
