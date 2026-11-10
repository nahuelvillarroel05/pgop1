"""Opt-in persistence of captured V2 reports, not native source admission.

The caller explicitly supplies report bytes and their expected hash. Schema and
integrity checks do not independently recompute source facts or claim verdicts.
The Engine store uses its existing trusted Engineering metadata-store contract.
"""
import re

from .context_engine import Engine, pointer
from .document_claims_v1 import RULE, strict_json, validate_catalog
from .public_handoff import checked
from .static_ast_v2 import canonical, digest, validate_report

SCHEMA = 'pgop1.source-audit-memory.v1'
MAX_REPORT_BYTES = 16_000_000
# Reserve one extra Engine query slot to detect unexpected membership.
MAX_RECORDS = 999
QUALIFICATION = 'CAPTURED_REPORT_NOT_SOURCE_RECOMPUTED'
SCOPE = {'source_integrity': 'PINS_CHECKED_SEPARATELY_FROM_CLAIM_TRUTH',
         'execution': 'NOT_PERFORMED', 'legacy_integration': 'DEFERRED',
         'context_engine_persistence': 'NOT_IMPLEMENTED',
         'natural_language_extraction': 'MANUAL_TYPED_CLAIMS_ONLY'}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def report_hash(value):
    require(isinstance(value, str) and re.fullmatch('[a-f0-9]{64}', value), 'INVALID_REPORT_HASH')
    return value


def records(raw, expected_sha256):
    """Validate a captured report envelope and return pointer-bound records.

    Original producer scope is preserved verbatim, including historical deferred
    persistence. This adapter's receipt describes the new persistence separately.
    """
    report_hash(expected_sha256)
    require(type(raw) is bytes and len(raw) <= MAX_REPORT_BYTES, 'REPORT_BYTE_LIMIT')
    require(digest(raw) == expected_sha256, 'REPORT_HASH_MISMATCH')
    report = strict_json(raw.decode('utf-8-sig'))
    require(isinstance(report, dict) and set(report) == {
        'schema', 'catalog', 'catalog_sha256', 'structures', 'document_claims', 'scope'
    } and report['schema'] == 'pgop1.source-audit-report.v2', 'REPORT_SCHEMA')
    validate_catalog(report['catalog'])
    require(report['catalog_sha256'] == digest(canonical(report['catalog'])), 'CATALOG_HASH')
    require(report['scope'] == SCOPE, 'REPORT_SCOPE')
    pins = {pin['path']: pin for pin in report['catalog']['sources']}
    rows = [('scope', '/scope')]
    structures = report['structures']
    require(isinstance(structures, list) and len(structures) <= 64, 'STRUCTURES_LIMIT')
    seen = set()
    for index, structure in enumerate(structures):
        validate_report(structure)
        source = structure['source']
        pin = pins.get(source['path'])
        require(pin is not None and pin['kind'] == 'python' and pin['sha256'] == source['sha256']
                and source['path'] not in seen, 'STRUCTURE_SOURCE_BINDING')
        seen.add(source['path'])
        prefix = f'/structures/{index}'
        # Bind the complete structure once, preserving partial/unknown coverage,
        # then individual typed rows. Never create VERIFIED_* Engine edges.
        rows.append(('structure', prefix))
        for collection in ('units', 'declarations', 'relations'):
            rows.extend((collection, f'{prefix}/{collection}/{n}')
                        for n in range(len(structure[collection])))
    results = report['document_claims']
    require(isinstance(results, dict) and set(results) == {
        'schema', 'rule_version', 'claims', 'source_errors', 'temporal_verdicts'
    } and results['schema'] == 'pgop1.doc-claims.results.v1' and results['rule_version'] == RULE
        and results['temporal_verdicts'] == 'NOT_IMPLEMENTED_NO_STALE_INFERENCE', 'CLAIMS_SCHEMA')
    require(isinstance(results['claims'], list) and isinstance(results['source_errors'], list), 'CLAIMS_ROWS')
    claims = {c['claim_id']: c for c in report['catalog']['claims']}
    seen_claims = set()
    for index, result in enumerate(results['claims']):
        require(isinstance(result, dict) and set(result) == {
            'claim', 'verdict', 'reason', 'coverage', 'rule_version', 'evidence', 'scope'
        }, 'CLAIM_RESULT_SCHEMA')
        claim = result['claim']
        require(isinstance(claim, dict) and claim.get('claim_id') in claims
                and claim == claims[claim['claim_id']] and claim['claim_id'] not in seen_claims,
                'CLAIM_RESULT_BINDING')
        seen_claims.add(claim['claim_id'])
        require(result['verdict'] in {'SUPPORTED', 'CONTRADICTED', 'INSUFFICIENT_EVIDENCE'}
                and result['rule_version'] == RULE
                and result['scope'] == 'DECLARATIONS_ONLY_NO_EXECUTION'
                and isinstance(result['coverage'], str)
                and result['coverage'] in {'ABSENT', 'COMPLETE', 'PARTIAL', 'BUDGET_EXCEEDED',
                                           'PARSE_FAILED', 'RESOURCE_ERROR', 'UNSUPPORTED', 'UNKNOWN'}
                and isinstance(result['reason'], str)
                and re.fullmatch('[A-Z][A-Z0-9_]{0,159}', result['reason'])
                and isinstance(result['evidence'], list) and len(result['evidence']) <= 1,
                'CLAIM_RESULT_SCOPE')
        require(result['verdict'] == 'INSUFFICIENT_EVIDENCE'
                or result['coverage'] == 'COMPLETE' and len(result['evidence']) == 1,
                'CLAIM_RESULT_COVERAGE')
        for evidence in result['evidence']:
            required = {'path', 'sha256', 'verifier', 'field', 'document_span_sha256'}
            optional = {'scope_id', 'snapshot_id', 'definition_ids', 'line', 'column',
                        'end_line', 'end_column', 'observed_value_sha256'}
            require(isinstance(evidence, dict) and required <= set(evidence) <= required | optional,
                    'CLAIM_EVIDENCE_SCHEMA')
            require(evidence['path'] == claim['source']['path']
                    and evidence['sha256'] == claim['source']['sha256']
                    and evidence['verifier'] == claim['predicate']
                    and evidence['field'] == claim['parameters']
                    and evidence['document_span_sha256'] == claim['document']['span_sha256'],
                    'CLAIM_EVIDENCE_BINDING')
            for key in ('snapshot_id', 'observed_value_sha256'):
                if key in evidence:
                    report_hash(evidence[key])
            for key in ('scope_id',):
                if key in evidence:
                    require(isinstance(evidence[key], str) and
                            re.fullmatch('node-[a-f0-9]{64}', evidence[key]), 'CLAIM_SCOPE_ID')
            if 'definition_ids' in evidence:
                require(isinstance(evidence['definition_ids'], list)
                        and len(evidence['definition_ids']) <= 50000
                        and all(isinstance(v, str) and re.fullmatch('node-[a-f0-9]{64}', v)
                                for v in evidence['definition_ids']), 'CLAIM_DEFINITION_IDS')
            for key in ('line', 'column', 'end_line', 'end_column'):
                if key in evidence:
                    require(type(evidence[key]) is int and 0 <= evidence[key] <= 262144,
                            'CLAIM_POSITION')
        rows.append(('claims', f'/document_claims/claims/{index}'))
    require(seen_claims == set(claims), 'CLAIM_RESULT_MEMBERSHIP')
    require(len(results['source_errors']) <= len(pins), 'SOURCE_ERROR_LIMIT')
    error_paths = set()
    for index, error in enumerate(results['source_errors']):
        require(isinstance(error, dict) and set(error) == {'path', 'reason'}
                and error['path'] in pins and error['path'] not in error_paths
                and isinstance(error['reason'], str), 'SOURCE_ERROR_BINDING')
        error_paths.add(error['path'])
        rows.append(('source_errors', f'/document_claims/source_errors/{index}'))
    python_paths = {path for path, pin in pins.items() if pin['kind'] == 'python'}
    require(not seen & error_paths and python_paths == seen | (python_paths & error_paths),
            'PYTHON_SOURCE_ACCOUNTING')
    require(len(rows) <= MAX_RECORDS, 'MEMORY_RECORD_LIMIT')
    return [dict(id='astmem-' + digest(canonical([SCHEMA, expected_sha256, path])),
                 task_id=expected_sha256, artifact_id=expected_sha256,
                 kind='source_audit_v2.' + kind, adapter_schema=SCHEMA,
                 qualification=QUALIFICATION, value=pointer(report, path),
                 evidence_binding={'source_id': 'source-audit-' + expected_sha256,
                                   'sha256': expected_sha256, 'pointer': path})
            for kind, path in rows]


class SourceAuditMemory:
    """Append-only snapshots; no source discovery, reanalysis or V1 dispatch."""

    def __init__(self, memory_root):
        self.root = checked(memory_root)

    def ingest(self, report_bytes, expected_sha256):
        observations = records(report_bytes, expected_sha256)
        engine = Engine(checked(self.root))
        snapshots = checked(self.root / 'captured-reports-v1')
        snapshots.mkdir(exist_ok=True)
        snapshot = checked(snapshots / (expected_sha256 + '.json'))
        Engine._immutable(snapshot, report_bytes)
        engine.admit_source(snapshot, expected_sha256, scope='ENGINEERING_RESULT',
                            source_id='source-audit-' + expected_sha256)
        graph = engine.ingest(observations)
        return {'schema': SCHEMA, 'status': 'PERSISTED', 'report_sha256': expected_sha256,
                'records': len(observations), 'graph': graph, 'qualification': QUALIFICATION,
                'source_recomputation': 'NOT_PERFORMED', 'authority_effect': 'NONE'}

    def read(self, expected_sha256, *, offset=0, limit=50, kind=None):
        report_hash(expected_sha256)
        require(type(offset) is int and offset >= 0 and type(limit) is int and 1 <= limit <= 100,
                'INVALID_PAGE')
        require(kind is None or kind in {'scope', 'structure', 'units', 'declarations',
                                         'relations', 'claims', 'source_errors'}, 'INVALID_KIND')
        # Avoid creating an empty store when recovery points at an unavailable root.
        require(checked(self.root / 'versions').is_dir(), 'MEMORY_UNAVAILABLE')
        engine = Engine(checked(self.root))
        raw = engine.read_source('source-audit-' + expected_sha256)
        expected = records(raw, expected_sha256)
        stored = engine.query(task_id=expected_sha256, limit=MAX_RECORDS + 1)
        # _binding adds value_sha256; compare both membership and all caller fields.
        by_id = {row['id']: row for row in stored}
        require(len(stored) == len(expected), 'MEMORY_RECORD_MEMBERSHIP')
        for row in expected:
            actual = by_id.get(row['id'])
            require(actual is not None and all(actual.get(k) == v for k, v in row.items()
                    if k != 'evidence_binding'), 'MEMORY_RECORD_MISMATCH')
            require(all(actual['evidence_binding'].get(k) == v
                        for k, v in row['evidence_binding'].items()), 'MEMORY_BINDING_MISMATCH')
        selected = sorted((r for r in stored if kind is None or r['kind'] == 'source_audit_v2.' + kind),
                          key=lambda r: r['id'])
        require(offset <= len(selected), 'INVALID_OFFSET')
        page = selected[offset:offset + limit]
        following = offset + len(page)
        return {'schema': SCHEMA, 'report_sha256': expected_sha256, 'graph': engine.latest(),
                'qualification': QUALIFICATION, 'items': page, 'offset': offset,
                'total': len(selected), 'returned': len(page), 'remaining': len(selected) - following,
                'next_offset': following if following < len(selected) else None,
                'source_recomputation': 'NOT_PERFORMED', 'authority_effect': 'NONE'}
