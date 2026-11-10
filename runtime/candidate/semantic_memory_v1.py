"""Portable, immutable Engine observations; native sources never enter Engine.

Only private fresh temporary stores are opened by Engine. The published archive
is read by Windows safe I/O and restored with exact, bounded membership. SQLite
is derived on reopen. This does not upgrade the legacy mutable store contract.
"""
import re
import tempfile
from pathlib import Path

from .context_engine import Engine, canonical_json, pointer, strict_json_loads
from .static_ast_v2 import canonical, digest

SCHEMA = 'pgop1.semantic-memory.v1'
MEMBER = re.compile(r'(?:objects/[a-f0-9]{64}|sources/[a-f0-9]{64}\.json|versions/00000001-[a-f0-9]{64}/(?:graph|provenance|manifest)\.json)\Z')


def require(ok, code):
    if not ok:
        raise ValueError(code)


def observations(envelope):
    """Bound aggregate rows avoid Engine's 1000-row query cap without dropping facts."""
    eid = envelope['integration_id']
    paths = [('scope', '/scope')]
    for key in ('sources', 'structures', 'claims'):
        paths.extend((key, f'/{key}/{i}') for i in range(len(envelope[key])))
    raw = canonical(envelope)
    sha = digest(raw)
    return [dict(id='sem-' + digest(canonical([SCHEMA, eid, path])), task_id=eid,
                 kind=kind, value=pointer(envelope, path), adapter_schema=SCHEMA,
                 evidence_binding=dict(source_id='semantic-' + sha, sha256=sha, pointer=path))
            for kind, path in paths]


def create_archive(envelope):
    raw = canonical(envelope)
    sha = digest(raw)
    with tempfile.TemporaryDirectory(prefix='sem-engine-build-') as tmp:
        root = Path(tmp)
        engine = Engine(root)
        source = root / 'envelope.json'
        source.write_bytes(raw)
        engine.admit_source(source, sha, scope='ENGINEERING_RESULT', source_id='semantic-' + sha)
        rows = observations(envelope)
        first = engine.ingest(rows)
        require(engine.ingest(rows) == first, 'MEMORY_IDEMPOTENCE')
        files = {p.relative_to(root).as_posix(): p.read_bytes().hex()
                 for base in ('objects', 'sources', 'versions')
                 for p in sorted((root/base).rglob('*')) if p.is_file()}
        return dict(schema=SCHEMA, files=files)


def recover(archive, envelope):
    require(isinstance(archive, dict) and set(archive) == {'schema', 'files'}
            and archive['schema'] == SCHEMA and isinstance(archive['files'], dict)
            and len(archive['files']) == 5, 'MEMORY_ARCHIVE_SCHEMA')
    # One object, one source descriptor, one graph/provenance/manifest version.
    files = archive['files']
    require(all(isinstance(n, str) and MEMBER.fullmatch(n) for n in files), 'MEMORY_ARCHIVE_PATH')
    require(sum(n.startswith('objects/') for n in files) == 1
            and sum(n.startswith('sources/') for n in files) == 1
            and len({n.split('/')[1] for n in files if n.startswith('versions/')}) == 1,
            'MEMORY_ARCHIVE_MEMBERSHIP')
    with tempfile.TemporaryDirectory(prefix='sem-engine-recover-') as tmp:
        root = Path(tmp)
        for name, text in files.items():
            require(isinstance(text, str) and len(text) <= 256_000_000, 'MEMORY_ARCHIVE_SIZE')
            raw = bytes.fromhex(text)
            require(raw.hex() == text, 'MEMORY_ARCHIVE_HEX')
            path = root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
        engine = Engine(root)
        require(engine.verify() == {'status':'PASS','versions':1,'sources':1}, 'MEMORY_ENGINE_VERIFY')
        sha = digest(canonical(envelope))
        require(engine.read_source('semantic-' + sha) == canonical(envelope), 'MEMORY_ENVELOPE')
        descriptor = engine._graph['sources'][0]
        require(set(descriptor) == {'source_id','sha256','path','scope','byte_length'}
                and descriptor['scope'] == 'ENGINEERING_RESULT'
                and descriptor['source_id'] == 'semantic-' + sha
                and descriptor['sha256'] == sha and descriptor['byte_length'] == len(canonical(envelope))
                and isinstance(descriptor['path'],str), 'MEMORY_SOURCE_SCOPE')
        require(set(engine._graph) == {'schema','sources','observations','edges','version','parent_sha256'}
                and engine._graph['schema'] == 'I4-NEXT-v0.1', 'MEMORY_GRAPH_SCHEMA')
        expected = observations(envelope)
        actual = engine.query(task_id=envelope['integration_id'], limit=1000)
        require(len(actual) == len(expected), 'MEMORY_MEMBERSHIP')
        by_id = {r['id']: r for r in actual}
        for row in expected:
            bound = dict(row['evidence_binding'], value_sha256=digest(canonical_json(row['value'])))
            require(by_id.get(row['id']) == dict(row, evidence_binding=bound), 'MEMORY_OBSERVATION')
        # Membership is global, not just filtered query membership; no injected edges.
        require(engine._graph['observations'] == sorted(actual, key=lambda r:r['id'])
                and engine._graph['edges'] == [] and len(engine._graph['sources']) == 1,
                'MEMORY_GRAPH_SCOPE')
        version = next((root/'versions').iterdir())
        provenance = strict_json_loads((version/'provenance.json').read_bytes())
        expected_provenance = []
        for row in sorted(actual,key=lambda r:r['id']):
            expected_provenance.append(dict(observation_id=row['id'],graph_version=1,
                graph_sha256=engine.latest()['graph_sha256'],evidence_binding=row['evidence_binding'],
                source_artifact_identity='semantic-'+sha,authority_read_scope='ENGINEERING_RESULT',
                task_id=envelope['integration_id'],run_id='UNKNOWN',session_id='UNKNOWN',
                declared_actor_identity='UNKNOWN',provider_identity='UNKNOWN',process_identity='UNKNOWN',
                tool_identity='UNKNOWN',timestamp='UNKNOWN',invocation_evidence='UNKNOWN',independent_custody='NOT_PROVEN'))
        require(provenance == dict(schema='I5-NEXT-v0.1',graph_version=1,
                                  graph_sha256=engine.latest()['graph_sha256'],records=expected_provenance),
                'MEMORY_PROVENANCE_SCOPE')
        require(engine.ingest(expected) == engine.latest(), 'MEMORY_REINGEST')
        return sorted(actual, key=lambda r:r['id'])
