"""V2 serialization and verified snapshot loading; no binding analysis."""
import os
import re
from .code_contract_v1 import canonical, digest, require, FILES, SCOPE

SCHEMA = 'pgop1.static-binding-resolution.v2'
ALGORITHM = 'explicit-module-reference-v2.0.2'
MAX_ALIASES = 4096


def alias_budget(value):
    require(type(value) is int and 1 <= value <= MAX_ALIASES, 'ALIAS_BUDGET')
    return value


def universe(catalog):
    return digest(canonical(dict(mode=catalog['mode'], package_roots=catalog['package_roots'],
                                 sources=catalog['sources'])))


def finish(catalog, snapshot, rows, coverage, total, limit):
    counts = {}
    for row in rows:
        counts[row['resolution']] = counts.get(row['resolution'], 0) + 1
    report = dict(schema=SCHEMA, algorithm=ALGORITHM,
                  catalog_sha256=digest(canonical(catalog)), snapshot_id=snapshot,
                  universe_id=universe(catalog), mode=catalog['mode'], alias_limit=limit,
                  status='COMPLETE' if total == len(rows) and all(v == 'COMPLETE' for v in coverage.values()) else 'PARTIAL',
                  coverage=coverage, total_import_aliases=total, examined=len(rows),
                  omitted=total-len(rows), counts=counts, relations=rows,
                  scope=dict(SCOPE, endpoint='MODULE_REFERENCE_ONLY', object_binding='NOT_PROVEN'))
    report['report_id'] = digest(canonical(report))
    return report


def load_verified_bundle(folder, expected):
    """Read each pinned member once under existing Windows custody, then verify E3."""
    from .windows_safe_io_v2 import Directory
    from tools.verify_source_v2 import read_source, strict
    from tools.verify_code_only_v1 import verify_values
    require(os.name == 'nt', 'WINDOWS_ONLY')
    with Directory(folder) as held:
        m = strict(read_source(folder, 'MANIFEST.json', None, 1_000_000))
        require(isinstance(m, dict) and set(m) == {'schema', 'catalog_sha256', 'files'} and
                m['schema'] == 'pgop1.code-only-manifest.v1' and m['catalog_sha256'] == expected, 'MANIFEST_SCHEMA')
        require(isinstance(m['files'], dict) and set(m['files']) == set(FILES), 'MANIFEST_MEMBERSHIP')
        require(set(os.listdir(folder)) == set(FILES) | {'MANIFEST.json'}, 'PHYSICAL_ARTIFACT_MEMBERSHIP')
        files = {}
        for name, cap in FILES.items():
            pin = m['files'][name]
            require(isinstance(pin, dict) and set(pin) == {'bytes', 'sha256'} and
                    type(pin['bytes']) is int and 0 <= pin['bytes'] <= cap, 'ARTIFACT_PIN')
            require(isinstance(pin['sha256'], str) and re.fullmatch('[a-f0-9]{64}', pin['sha256']) is not None, 'ARTIFACT_HASH')
            raw = read_source(folder, name, pin['sha256'], cap)
            require(len(raw) == pin['bytes'], 'ARTIFACT_LENGTH')
            files[name] = raw
        verify_values(files, expected)
        held.validate()
    return tuple(strict(files[name]) for name in ('CATALOG.json', 'SNAPSHOT.json', 'AST_REPORT.json'))
