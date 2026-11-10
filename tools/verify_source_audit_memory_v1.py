"""Independent stdlib verifier of captured-report storage, not source truth.

Does not import the Engine, adapter or AST producer. The store is trusted local
metadata, with link rejection; this is not hostile concurrent Windows admission.
Original source paths in descriptors are never opened.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat

SCHEMA = 'pgop1.source-audit-memory.v1'


def require(value):
    if not value:
        raise ValueError('MEMORY_VERIFICATION_FAILED')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value, ascii=False):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=ascii,
                      allow_nan=False).encode('utf-8')


def strict(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            require(key not in result)
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('NONFINITE_JSON')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def read(path, limit=64_000_000):
    path = Path(os.path.abspath(path))
    for component in (*reversed(path.parents), path):
        info = component.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) & 0x400)
    require(stat.S_ISREG(info.st_mode) and info.st_size <= limit)
    with path.open('rb') as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit)
    return raw


def verify(root, report_sha256):
    require(isinstance(report_sha256, str) and re.fullmatch('[a-f0-9]{64}', report_sha256))
    root = Path(os.path.abspath(root))
    parent = None
    versions = sorted((root / 'versions').iterdir())
    require(versions and len(versions) <= 10000)
    for number, folder in enumerate(versions, 1):
        require(folder.name == f'{number:08d}-' + folder.name[9:]
                and re.fullmatch(r'\d{8}-[a-f0-9]{64}', folder.name))
        graph_raw = read(folder / 'graph.json')
        provenance_raw = read(folder / 'provenance.json')
        manifest = strict(read(folder / 'manifest.json', 1_000_000))
        require(manifest == {'version': number, 'parent_sha256': parent,
                             'graph_sha256': sha(graph_raw), 'provenance_sha256': sha(provenance_raw)})
        graph = strict(graph_raw)
        require(graph['version'] == number and graph['parent_sha256'] == parent
                and folder.name == f'{number:08d}-' + sha(graph_raw))
        provenance = strict(provenance_raw)
        require(provenance['graph_version'] == number and provenance['graph_sha256'] == sha(graph_raw))
        parent = sha(graph_raw)
    source_id = 'source-audit-' + report_sha256
    sources = [row for row in graph['sources'] if row['source_id'] == source_id]
    require(len(sources) == 1 and sources[0]['sha256'] == report_sha256
            and sources[0]['scope'] == 'ENGINEERING_RESULT')
    descriptor = canonical(sources[0])
    require(read(root / 'sources' / (sha(descriptor) + '.json'), 1_000_000) == descriptor)
    raw = read(root / 'objects' / report_sha256, 16_000_000)
    require(sha(raw) == report_sha256 and len(raw) == sources[0]['byte_length'])
    require(read(root / 'captured-reports-v1' / (report_sha256 + '.json'), 16_000_000) == raw)
    report = strict(raw)
    require(report['schema'] == 'pgop1.source-audit-report.v2')
    values = [('scope', '/scope', report['scope'])]
    for index, structure in enumerate(report['structures']):
        prefix = f'/structures/{index}'
        values.append(('structure', prefix, structure))
        for kind in ('units', 'declarations', 'relations'):
            values.extend((kind, f'{prefix}/{kind}/{n}', row) for n, row in enumerate(structure[kind]))
    for kind in ('claims', 'source_errors'):
        values.extend((kind, f'/document_claims/{kind}/{n}', row)
                      for n, row in enumerate(report['document_claims'][kind]))
    actual = [r for r in graph['observations'] if r.get('task_id') == report_sha256]
    require(len(values) == len(actual) <= 999)
    expected = []
    for kind, pointer, value in values:
        expected.append({'id': 'astmem-' + sha(canonical([SCHEMA, report_sha256, pointer], ascii=True)),
            'task_id': report_sha256, 'artifact_id': report_sha256,
            'kind': 'source_audit_v2.' + kind, 'adapter_schema': SCHEMA,
            'qualification': 'CAPTURED_REPORT_NOT_SOURCE_RECOMPUTED', 'value': value,
            'evidence_binding': {'source_id': source_id, 'sha256': report_sha256,
                                 'pointer': pointer, 'value_sha256': sha(canonical(value))}})
    require(sorted(actual, key=lambda r: r['id']) == sorted(expected, key=lambda r: r['id']))
    identifiers = {row['id'] for row in actual}
    require(not any(edge['from'] in identifiers or edge['to'] in identifiers for edge in graph['edges']))
    return {'status': 'PASS', 'scope': 'CAPTURED_REPORT_STORAGE_AND_BINDINGS_ONLY',
            'versions': len(versions), 'report_sha256': report_sha256, 'records': len(actual),
            'engine_imported': False, 'source_recomputation': 'NOT_PERFORMED', 'authority_effect': 'NONE'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--memory-root', type=Path, required=True)
    parser.add_argument('--report-sha256', required=True)
    args = parser.parse_args()
    try:
        result = verify(args.memory_root, args.report_sha256)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        result = {'status': 'FAIL', 'scope': 'CAPTURED_REPORT_STORAGE_AND_BINDINGS_ONLY'}
    print(json.dumps(result, sort_keys=True))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
