"""Verify all base artifacts and independently rederive new predicates from captures."""
import os
from pathlib import Path
import tempfile
from tools import verify_semantic_engine_v1 as base
from candidate.claim_coverage_v2 import check_catalog, derive
from candidate.semantic_memory_v1 import recover

LIMITS = dict(base.LIMITS)
LIMITS.update({'BASE_MANIFEST.json': 1_000_000, 'COVERAGE_CATALOG.json': 262144,
               'COVERAGE.json': 128_000_000, 'COVERAGE_MEMORY.json': 512_000_000})


def verify_bundle(folder, expected):
    base.v.require(os.name == 'nt', 'WINDOWS_ONLY')
    from candidate.windows_safe_io_v2 import Directory
    with Directory(folder) as held:
        manifest = base.v.strict(base.v.read_source(folder, 'MANIFEST.json', None, 1_000_000))
        base.v.require(isinstance(manifest, dict) and set(manifest) == {'schema', 'catalog_sha256', 'files'}
                       and manifest['schema'] == 'pgop1.claim-coverage-manifest.v1'
                       and manifest['catalog_sha256'] == expected and isinstance(manifest['files'], dict)
                       and set(manifest['files']) == set(LIMITS), 'COVERAGE_MANIFEST')
        files = {}
        for name, limit in LIMITS.items():
            pin = manifest['files'][name]
            base.v.require(isinstance(pin, dict) and set(pin) == {'bytes', 'sha256'}
                           and type(pin['bytes']) is int and 0 <= pin['bytes'] <= limit, 'COVERAGE_PIN')
            base.v.check_hash(pin['sha256'])
            raw = base.v.read_source(folder, name, pin['sha256'], limit)
            base.v.require(len(raw) == pin['bytes'], 'COVERAGE_LENGTH'); files[name] = raw
        catalog = check_catalog(base.v.strict(files['COVERAGE_CATALOG.json']), expected)
        base.v.require(base.v.compact(catalog) == files['COVERAGE_CATALOG.json'], 'CANONICAL_CATALOG')
        base.v.require(base.v.compact(catalog['base']) == files['CATALOG.json'], 'BASE_CATALOG')
        # Only bounded verified artifact bytes enter this private reconstruction.
        # Legacy verifier owns its schema and never reopens original source paths.
        with tempfile.TemporaryDirectory(prefix='coverage-base-verify-') as tmp:
            tmp = Path(tmp)
            for name in base.LIMITS: (tmp/name).write_bytes(files[name])
            (tmp/'MANIFEST.json').write_bytes(files['BASE_MANIFEST.json'])
            envelope, _ = base.verify_bundle(tmp, base.v.digest(files['CATALOG.json']))
        derived = derive(catalog, envelope, base.v.strict(files['SNAPSHOT.json']), independent=True)
        base.v.require(base.v.compact(derived) == base.v.compact(base.v.strict(files['COVERAGE.json'])), 'COVERAGE_DERIVATION')
        rows = recover(base.v.strict(files['COVERAGE_MEMORY.json']), derived)
        held.validate()
    return derived, rows
