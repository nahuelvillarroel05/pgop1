"""Opt-in historical byte snapshot. Never certifies source currency at ACK."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / 'runtime'))
from candidate.document_claims_v1 import audit_catalog, strict_json, validate_catalog
from candidate.static_ast_v2 import canonical, digest, read_registered
from tools.audit_source_v2 import cli_path, _directory

SCOPE = {'mode': 'HISTORICAL_SNAPSHOT', 'source_current_at_ack': 'NOT_PROVEN',
         'artifact_current_at_ack': 'NOT_PROVEN',
         'origin_authentication': 'CALLER_PIN_NOT_SIGNED_ATTESTATION',
         'continuous_retention': 'NOT_PROVEN', 'atomic_multi_file_capture': 'NOT_PROVEN'}
HANDOFF = (b'# Historical evidence snapshot v1\n\n'
           b'Content and derivation only. Source current at ACK: NOT_PROVEN.\n'
           b'No signed origin, continuous retention or atomic multi-file instant.\n'
           b'Manifest existence is not a successful ACK; require operation return.\n')


def _publish(source_root, output, files):
    if os.name == 'nt':
        from candidate.windows_safe_io_v2 import safe_create_artifacts
        safe_create_artifacts(source_root, output, files, (ROOT,))
        return
    source_root = Path(os.path.abspath(source_root)); output = Path(os.path.abspath(output))
    for protected in (source_root, ROOT):
        if output.is_relative_to(protected) or protected.is_relative_to(output):
            raise ValueError('OUTPUT_OVERLAPS_INPUT')
    with ExitStack() as stack:
        parent = _directory(output.parent); stack.callback(os.close, parent)
        os.mkdir(output.name, mode=0o700, dir_fd=parent)
        directory = os.open(output.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        stack.callback(os.close, directory)
        for name, raw in files.items():
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            stack.callback(os.close, fd)
            with os.fdopen(fd, 'r+b', closefd=False) as stream:
                stream.write(raw); stream.flush(); os.fsync(fd); stream.seek(0)
                if stream.read(len(raw) + 1) != raw:
                    raise ValueError('OUTPUT_INTEGRITY_FAILED')


def snapshot_and_write(source_root, catalog_path, catalog_sha256, output, *, mode='HISTORICAL_SNAPSHOT'):
    """Own capture, analysis, publication and resource close. No split authority."""
    if mode != 'HISTORICAL_SNAPSHOT':
        raise ValueError('SOURCE_CURRENT_AT_ACK_NOT_PROVEN')
    with ExitStack() as transaction:
        held = []
        if os.name == 'nt':
            from candidate.windows_safe_io_v2 import Directory, absolute, reject_membership
            absolute(catalog_path)
            drive, parts = absolute(output)
            if not parts:
                raise ValueError('UNSAFE_PATH')
            for path in (source_root, Path(catalog_path).parent, ROOT):
                held.append(transaction.enter_context(Directory(path)))
            parent = transaction.enter_context(Directory(drive + '\\'.join(parts[:-1])))
            for protected in (held[0], held[2]):
                reject_membership(parent, protected)
            held.append(parent)
        catalog_path = Path(os.path.abspath(catalog_path))
        catalog_raw = read_registered(catalog_path.parent, catalog_path.name, catalog_sha256)
        catalog = strict_json(catalog_raw); validate_catalog(catalog)
        if (canonical(catalog) != catalog_raw or
                catalog['sources'] != sorted(catalog['sources'], key=lambda p:p['path']) or
                catalog['claims'] != sorted(catalog['claims'], key=lambda c:c['claim_id'])):
            raise ValueError('CANONICAL_CATALOG_REQUIRED')
        bodies = {p['path']: read_registered(source_root, p['path'], p['sha256']) for p in catalog['sources']}
        captures = [dict(path=p['path'], sha256=p['sha256'], bytes=len(bodies[p['path']]),
                         raw_hex=bodies[p['path']].hex()) for p in catalog['sources']]
        inventory = [{k:r[k] for k in ('path','sha256','bytes')} for r in captures]
        snapshot_id = digest(canonical({'schema':'pgop1.evidence-snapshot.v1','inventory':inventory}))
        snapshot = dict(schema='pgop1.evidence-snapshot.v1', snapshot_id=snapshot_id,
                        captures=captures, scope=dict(SCOPE))
        report = audit_catalog(None, catalog, captured=bodies)
        # Independent semantic recomputation before publication; never source reopen.
        from tools.verify_snapshot_v1 import verify_values
        verify_values(report, snapshot, catalog_sha256)
        files = {'SNAPSHOT.json':canonical(snapshot)+b'\n', 'REPORT.json':canonical(report)+b'\n',
                 'FINAL_HANDOFF.md':HANDOFF}
        manifest = dict(schema='pgop1.evidence-snapshot-manifest.v1',catalog_sha256=catalog_sha256,
                        snapshot_id=snapshot_id,files={n:dict(bytes=len(b),sha256=digest(b)) for n,b in files.items()})
        files['MANIFEST.json'] = canonical(manifest)+b'\n'
        for directory in held:
            directory.validate()
        _publish(source_root, output, files)
        for directory in held:
            directory.validate()
    return {'schema':'pgop1.evidence-snapshot-ack.v1','status':'SNAPSHOT_ARTIFACTS_WRITTEN',
            'operation':'CAPTURE_ANALYZE_PUBLISH_HISTORICAL_SNAPSHOT','snapshot_id':snapshot_id,
            'catalog_sha256':catalog_sha256,'manifest_sha256':digest(files['MANIFEST.json']),
            'source_current_at_ack':'NOT_PROVEN','artifact_current_at_ack':'NOT_PROVEN',
            'operation_completed':True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('source-root','catalog','output'):
        parser.add_argument('--'+name, required=True, type=cli_path)
    parser.add_argument('--catalog-sha256', required=True, help='Externally authorized canonical catalog bytes, no newline')
    parser.add_argument('--mode', choices=('HISTORICAL_SNAPSHOT','CURRENT_AT_ACK'), default='HISTORICAL_SNAPSHOT')
    a = parser.parse_args()
    try:
        result = snapshot_and_write(a.source_root,a.catalog,a.catalog_sha256,a.output,mode=a.mode)
    except (OSError,ValueError,TypeError,KeyError,UnicodeError,RecursionError,MemoryError) as exc:
        reason = 'SOURCE_CURRENT_AT_ACK_NOT_PROVEN' if str(exc) == 'SOURCE_CURRENT_AT_ACK_NOT_PROVEN' else 'SNAPSHOT_OPERATION_FAILED'
        print(json.dumps({'schema':'pgop1.evidence-snapshot-ack.v1','status':'ERROR','reason':reason,
                          'source_current_at_ack':'NOT_PROVEN','operation_completed':False}))
        return 2
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == '__main__':
    # Executable by absolute filename as well as -m, without a caller PYTHONPATH.
    raise SystemExit(main())
