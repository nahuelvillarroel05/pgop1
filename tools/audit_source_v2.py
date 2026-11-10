"""Opt-in audit of explicitly authorized, SHA-256-pinned sources. No target execution."""
import argparse
from pathlib import Path
import json
import os
import sys
from contextlib import ExitStack

ROOT = Path(__file__).absolute().parents[1]
sys.path.insert(0,str(ROOT/'runtime'))
from candidate.document_claims_v1 import audit_catalog, strict_json
from candidate.static_ast_v2 import AdmissionError, canonical, digest, read_registered


def cli_path(value):
    if os.name == 'nt':
        from candidate.windows_safe_io_v2 import absolute
        absolute(value)  # before Path/abspath can normalize the raw argument
    return Path(value)


def _directory(path):
    """Open existing directory from / without following any symlink ancestor."""
    path = Path(os.path.abspath(path))
    descriptor = os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            nxt = os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=descriptor)
            os.close(descriptor)
            descriptor = nxt
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def write_artifacts(source_root, output, report, *, protected_roots=()):
    if os.name == 'nt':
        from candidate.windows_safe_io_v2 import safe_create_artifacts
        files, manifest = artifact_bytes(report)
        safe_create_artifacts(source_root, output, files, (ROOT, *protected_roots))
        return manifest
    source_root = Path(os.path.abspath(source_root));output = Path(os.path.abspath(output))
    if output.is_relative_to(source_root) or source_root.is_relative_to(output):
        raise ValueError('OUTPUT_MUST_BE_DISJOINT_FROM_SOURCE')
    # Validate source ancestry even for an empty/no-Python catalog.
    source_fd = _directory(source_root)
    os.close(source_fd)
    parent_fd = _directory(output.parent)
    directory_fd = None
    try:
        os.mkdir(output.name,mode=0o700,dir_fd=parent_fd)
        directory_fd = os.open(output.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=parent_fd)
        counts = {}
        for row in report['document_claims']['claims']:
            counts[row['verdict']] = counts.get(row['verdict'],0)+1
        handoff = ('# Source audit V2\n\n'
                   'Scope: pinned source declarations and manually typed documentary claims.\n'
                   'Target execution: NOT_PERFORMED. Behavioral correctness: NOT_PROVEN.\n'
                   'Legacy backend integration: DEFERRED. Context Engine persistence: NOT_IMPLEMENTED.\n\n'
                   f"Catalog SHA-256: `{report['catalog_sha256']}`\n\n"
                   f"Structural reports: {len(report['structures'])}; claims: {len(report['document_claims']['claims'])}.\n"
                   f"Verdict counts: `{json.dumps(counts,sort_keys=True)}`.\n\n"
                   'Source integrity and claim verdicts remain separate fields in REPORT.json.\n'
                   'No STALE verdict is inferred; no natural-language extraction or execution receipt is implemented.\n').encode()
        files = {'REPORT.json':canonical(report)+b'\n','FINAL_HANDOFF.md':handoff}
        manifest = {'schema':'pgop1.source-audit-manifest.v2','catalog_sha256':report['catalog_sha256'],
                    'files':{name:{'bytes':len(body),'sha256':digest(body)} for name,body in files.items()}}
        files['MANIFEST.json'] = canonical(manifest)+b'\n'
        for name,body in files.items():
            descriptor = os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=directory_fd)
            try:
                with os.fdopen(descriptor,'wb',closefd=False) as stream:
                    stream.write(body)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                os.close(descriptor)
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(parent_fd)
    return manifest


def artifact_bytes(report):
    """Same published artifact contract; Windows I/O is a separate provider."""
    counts = {}
    for row in report['document_claims']['claims']:
        counts[row['verdict']] = counts.get(row['verdict'], 0) + 1
    handoff = ('# Source audit V2\n\n'
               'Scope: pinned source declarations and manually typed documentary claims.\n'
               'Target execution: NOT_PERFORMED. Behavioral correctness: NOT_PROVEN.\n'
               'Legacy backend integration: DEFERRED. Context Engine persistence: NOT_IMPLEMENTED.\n\n'
               f"Catalog SHA-256: `{report['catalog_sha256']}`\n\n"
               f"Structural reports: {len(report['structures'])}; claims: {len(report['document_claims']['claims'])}.\n"
               f"Verdict counts: `{json.dumps(counts,sort_keys=True)}`.\n\n"
               'Source integrity and claim verdicts remain separate fields in REPORT.json.\n'
               'No STALE verdict is inferred; no natural-language extraction or execution receipt is implemented.\n').encode()
    files = {'REPORT.json': canonical(report) + b'\n', 'FINAL_HANDOFF.md': handoff}
    manifest = {'schema': 'pgop1.source-audit-manifest.v2', 'catalog_sha256': report['catalog_sha256'],
                'files': {name: {'bytes': len(body), 'sha256': digest(body)} for name, body in files.items()}}
    files['MANIFEST.json'] = canonical(manifest) + b'\n'
    return files, manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',required=True,type=cli_path)
    parser.add_argument('--catalog',required=True,type=cli_path)
    parser.add_argument('--catalog-sha256',required=True)
    parser.add_argument('--output',required=True,type=cli_path,help='New directory; parent must exist, disjoint from source root')
    args = parser.parse_args()
    try:
        with ExitStack() as transaction:
            if os.name == 'nt':
                from candidate.windows_safe_io_v2 import Directory
                transaction.enter_context(Directory(args.source_root))
                transaction.enter_context(Directory(args.catalog.parent))
            return execute(args)
    except (OSError, ValueError):
        print(json.dumps({'status':'ERROR','reason':'INVALID_ADMISSION_CONTRACT_OR_OUTPUT'}))
        return 2


def execute(args):
    try:
        catalog_path = Path(os.path.abspath(args.catalog))
        raw = read_registered(catalog_path.parent,catalog_path.name,args.catalog_sha256)
        catalog = strict_json(raw)
        report = audit_catalog(args.source_root,catalog)
        manifest = write_artifacts(args.source_root,args.output,report)
        print(json.dumps({'status':'ARTIFACTS_WRITTEN','catalog_sha256':report['catalog_sha256'],
                          'manifest_sha256':digest(canonical(manifest)+b'\n'),
                          'source_error_count':len(report['document_claims']['source_errors']),
                          'claim_count':len(report['document_claims']['claims'])},sort_keys=True))
        return 0
    except (AdmissionError,OSError,ValueError,TypeError,KeyError,UnicodeError,RecursionError):
        print(json.dumps({'status':'ERROR','reason':'INVALID_ADMISSION_CONTRACT_OR_OUTPUT'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
