"""Experimental Windows extension around the unchanged RealStaticV2Profile."""
from contextlib import ExitStack
import os
from pathlib import Path
import tempfile
from .claim_contract_v2 import validate_claim
from .document_claims_v1 import strict_json, document_span, require
from .static_ast_v2 import canonical, digest, read_registered

CATALOG = 'pgop1.claim-coverage-catalog.v1'
SCHEMA = 'pgop1.claim-coverage.v1'


def check_catalog(catalog, expected):
    from tools.verify_semantic_engine_v1 import check_catalog as base_check
    require(isinstance(catalog, dict) and set(catalog) == {'schema', 'base', 'claims'})
    require(catalog['schema'] == CATALOG and digest(canonical(catalog)) == expected, 'EXTERNAL_COVERAGE_ANCHOR')
    base_check(catalog['base'], digest(canonical(catalog['base'])))
    require(isinstance(catalog['claims'], list) and len(catalog['claims']) <= 64)
    require(catalog['claims'] == sorted(catalog['claims'], key=lambda c: c['claim_id']))
    ids = set(); pins = {s['path']: s for s in catalog['base']['catalog']['sources']}
    for claim in catalog['claims']:
        validate_claim(claim)
        require(claim['claim_id'] not in ids, 'DUPLICATE_CLAIM'); ids.add(claim['claim_id'])
        for label, kind in [('source', 'python'), ('document', 'document')]:
            pin = claim[label]
            require(pin['path'] in pins and pins[pin['path']]['kind'] == kind
                    and pins[pin['path']]['sha256'] == pin['sha256'], 'CLAIM_SOURCE_MEMBERSHIP')
    return catalog


def derive(catalog, base, snapshot, *, independent=False):
    """Admission and document binding are shared, predicate evaluation is separate."""
    bodies = {c['path']: bytes.fromhex(c['raw_hex']) for c in snapshot['captures']}
    valid = []; invalid = []
    from .claim_contract_v2 import row
    for claim in catalog['claims']:
        doc = claim['document']
        try:
            span = document_span(bodies[doc['path']], doc['start_line'], doc['end_line'])
            require(digest(span) == doc['span_sha256'])
        except ValueError:
            result = row(claim); result['reason'] = 'DOCUMENT_SPAN_NOT_VERIFIED'; invalid.append(result)
        else: valid.append(claim)
    if independent:
        from tools.verify_claims_v2 import evaluate
    else:
        from .document_claims_v2 import evaluate
    rows = evaluate(valid, bodies, base['structures']) + invalid
    for result in rows:
        doc = result['claim']['document']
        result['evidence_snapshot_id'] = snapshot['snapshot_id']
        result['literal_span_hex'] = (document_span(bodies[doc['path']], doc['start_line'], doc['end_line']).hex()
                                      if doc['end_line'] <= len(bodies[doc['path']].splitlines()) else None)
    identity = dict(schema=SCHEMA, catalog_sha256=digest(canonical(catalog)),
                    base_integration_id=base['integration_id'], snapshot_id=snapshot['snapshot_id'],
                    scope=dict(base['scope']), sources=base['sources'], structures=base['structures'],
                    claims=sorted(rows, key=lambda r: r['claim']['claim_id']))
    return dict(identity, integration_id='coverage-' + digest(canonical(identity)))


class ClaimCoverageProfile:
    def __init__(self, *, source_root=None, catalog_path=None, catalog_sha256):
        self.source_root = source_root; self.catalog_path = catalog_path; self.sha = catalog_sha256

    def generate(self, output):
        require(os.name == 'nt', 'WINDOWS_ONLY')
        from .windows_safe_io_v2 import Directory, absolute, reject_membership, safe_create_artifacts
        from .semantic_engine_v1 import RealStaticV2Profile
        from .semantic_memory_v1 import create_archive, recover
        from tools import verify_semantic_engine_v1 as legacy
        absolute(self.catalog_path); drive, parts = absolute(output); require(bool(parts))
        with ExitStack() as transaction:
            held = [transaction.enter_context(Directory(p)) for p in
                    (self.source_root, Path(self.catalog_path).parent, legacy.ROOT)]
            parent = transaction.enter_context(Directory(drive + '\\'.join(parts[:-1])))
            for directory in held: reject_membership(parent, directory)
            raw = read_registered(Path(self.catalog_path).parent, Path(self.catalog_path).name, self.sha)
            require(len(raw) <= 262144, 'CATALOG_SIZE')
            catalog = check_catalog(strict_json(raw), self.sha); require(raw == canonical(catalog))
            with tempfile.TemporaryDirectory(prefix='coverage-transaction-') as tmp:
                tmp = Path(tmp); config = tmp/'config'; config.mkdir()
                base_raw = canonical(catalog['base']); pin = digest(base_raw)
                path = config/'catalog.json'; path.write_bytes(base_raw)
                stage = tmp/'base'
                ack = RealStaticV2Profile(source_root=self.source_root, catalog_path=path, catalog_sha256=pin).generate(stage)
                require(ack['operation_completed'])
                base, _ = legacy.verify_bundle(stage, pin)
                files = {n: legacy.v.read_source(stage, n, None, limit) for n, limit in legacy.LIMITS.items()}
                files['BASE_MANIFEST.json'] = legacy.v.read_source(stage, 'MANIFEST.json', None, 1_000_000)
                envelope = derive(catalog, base, strict_json(files['SNAPSHOT.json']))
                require(canonical(envelope) == canonical(derive(catalog, base, strict_json(files['SNAPSHOT.json']), independent=True)), 'INDEPENDENT_DERIVATION')
                files['COVERAGE_CATALOG.json'] = raw
                files['COVERAGE.json'] = canonical(envelope)
                archive = create_archive(envelope); recover(archive, envelope)
                files['COVERAGE_MEMORY.json'] = canonical(archive)
                manifest = dict(schema='pgop1.claim-coverage-manifest.v1', catalog_sha256=self.sha,
                                files={n: dict(bytes=len(b), sha256=digest(b)) for n, b in files.items()})
                files['MANIFEST.json'] = canonical(manifest)
                for directory in (*held, parent): directory.validate()
                safe_create_artifacts(self.source_root, output, files, (legacy.ROOT, Path(self.catalog_path).parent))
                for directory in (*held, parent): directory.validate()
        return dict(status='COVERAGE_WRITTEN', operation_completed=True, integration_id=envelope['integration_id'],
                    catalog_sha256=self.sha, source_current_at_ack='NOT_PROVEN', artifact_current_at_ack='NOT_PROVEN')

    def verify(self, artifacts):
        from tools.verify_claim_coverage_v2 import verify_bundle
        envelope, _ = verify_bundle(artifacts, self.sha)
        return dict(status='COVERAGE_VERIFIED', integration_id=envelope['integration_id'], scope=envelope['scope'])

    def query(self, artifacts, *, offset=0, limit=50):
        from tools.verify_claim_coverage_v2 import verify_bundle
        envelope, _ = verify_bundle(artifacts, self.sha)
        require(type(offset) is int and 0 <= offset <= len(envelope['claims'])
                and type(limit) is int and 1 <= limit <= 100, 'INVALID_PAGE')
        rows = envelope['claims'][offset:offset+limit]; following = offset+len(rows)
        return dict(integration_id=envelope['integration_id'], items=rows, total=len(envelope['claims']),
                    next_offset=following if following < len(envelope['claims']) else None)
