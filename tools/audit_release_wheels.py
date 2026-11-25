"""PGOP1_RELEASE_R2_WHEELS_V1: pinned release, checkout, and approved wheels.

This successor retains the R2 tree, object, storage and checkout procedure.
The historical R1 and R2 entry points retain their original behavior.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys

from audit_distribution import (
    GENERATED, MANIFEST, artifacts, digest, git, manifest, need, no_links, path_ok, read,
    scan, storage,
)

from audit_release import full_oid, output_path
from release_wheel_review import EXTERNAL_PINS_SHA256, inspect_wheel, load_pins, select_wheels

CONTRACT = 'PGOP1_RELEASE_R2_WHEELS_V1'
SCOPE = 'Externally pinned commit, complete release tree, checkout and approved offline wheels.'


def verify(root, revision, expected_commit, expected_tree, pins_path):
    root = root.absolute()
    full_oid(expected_commit)
    full_oid(expected_tree)
    storage(root)  # before invoking Git or reading any object bodies
    gitdir = root / '.git'
    for directory, _, files in os.walk(gitdir / 'objects', followlinks=False):
        for name in files:
            need((Path(directory) / name).stat().st_nlink == 1, 'hardlinked Git storage forbidden')
    need(Path(git(root, 'rev-parse', '--absolute-git-dir').decode().strip()) == gitdir,
         'external Git directory forbidden')
    common = Path(git(root, 'rev-parse', '--path-format=absolute', '--git-common-dir').decode().strip())
    need(common == gitdir, 'external common Git directory forbidden')
    need(git(root, 'rev-parse', '--show-object-format').strip() == b'sha1', 'SHA-1 repository required')
    config = git(root, 'config', '--local', '--list').decode()
    need(not re.search(r'(?im)^(remote\..*\.promisor|extensions\.partialclone)=', config),
         'partial clone forbidden')
    refs = dict(line.split() for line in git(root, 'for-each-ref', '--format=%(refname) %(objectname)').decode().splitlines())
    need(not any(n.startswith('refs/replace/') for n in refs), 'object replacement forbidden')
    # Resolve the caller's reference ONCE; every subsequent content read uses OIDs.
    commit = git(root, 'rev-parse', '--verify', '--end-of-options', revision + '^{commit}').decode().strip()
    need(commit == expected_commit, 'external commit pin mismatch')
    tree = git(root, 'rev-parse', commit + '^{tree}').decode().strip()
    need(tree == expected_tree, 'external tree pin mismatch')
    # Require available complete ancestry, without claiming to audit ancestor content.
    git(root, 'rev-list', '--parents', commit)
    members, objects = {}, {commit: 'commit', tree: 'tree'}
    entries = []
    for item in git(root, 'ls-tree', '-r', '-t', '-z', tree).split(b'\0'):
        if not item:
            continue
        meta, raw_name = item.split(b'\t')
        mode, kind, oid = meta.decode().split()
        name = raw_name.decode('utf-8')
        path_ok(name)
        need(mode in ('040000', '100644', '100755') and kind in ('tree', 'blob'), 'unsafe tree mode/type')
        need((mode == '040000') == (kind == 'tree'), 'inconsistent tree mode/type')
        parts = name.split('/')
        need(parts[0] not in GENERATED and '__pycache__' not in parts,
             'tracked generated path forbidden')
        entries.append({'path': name, 'mode': mode, 'type': kind, 'oid': oid})
        objects[oid] = kind
        if kind == 'blob':
            need(name not in members, 'duplicate tree member')
            members[name] = (mode, oid)
    need(MANIFEST in members, 'manifest missing')
    pins = load_pins(root, pins_path)
    wheel_objects = select_wheels(members, pins)
    wheels = []
    bodies, inventory = {}, []
    for oid, kind in sorted(objects.items()):
        body = git(root, 'cat-file', kind, oid)  # existing size/type gate before body read
        need(hashlib.sha1(f'{kind} {len(body)}\0'.encode() + body).hexdigest() == oid, 'Git OID mismatch')
        if kind == 'blob' and oid in wheel_objects:
            wheels.append({'oid': oid, **inspect_wheel(wheel_objects[oid], body, pins)})
        elif kind in ('commit', 'blob'):
            scan(body)
        bodies[oid] = body
        inventory.append({'oid': oid, 'type': kind, 'bytes': len(body), 'sha256': digest(body)})
    get = lambda name: bodies[members[name][1]]
    count = manifest(get(MANIFEST), members, get)
    # No objects-only success: the files a user will execute must match the pin.
    names = set()
    for directory, dirs, files in os.walk(root, followlinks=False):
        current = Path(directory)
        for name in dirs + files:
            if current == root and name in GENERATED and name in dirs:
                continue
            no_links(current / name)
        dirs[:] = [n for n in dirs if not (current == root and n in GENERATED) and n != '__pycache__']
        for name in files:
            names.add((current / name).relative_to(root).as_posix())
    need(names == set(members), 'checkout membership differs from pinned tree')
    for name, (mode, oid) in members.items():
        need(read(root / name) == bodies[oid], 'checkout differs from pinned tree: ' + name)
        if os.name != 'nt':
            need(bool((root / name).stat().st_mode & 0o111) == (mode == '100755'), 'checkout executable mode differs')
    need(git(root, 'rev-parse', 'HEAD').decode().strip() == commit, 'checkout HEAD differs from pinned commit')
    return {
        'status': 'PASS', 'contract': CONTRACT, 'scope': SCOPE,
        'commit': commit, 'tree': tree, 'expected_commit': expected_commit,
        'expected_tree': expected_tree,
        'wheel_pins_sha256': EXTERNAL_PINS_SHA256,
        'wheel_inspections': sorted(wheels, key=lambda result: result['path']),
        'manifest': {'path': MANIFEST, 'oid': members[MANIFEST][1], 'sha256': digest(get(MANIFEST))},
        'coverage': {'tree_files': len(members), 'manifest_files': count, 'self_manifest_git_bound': True,
                     'checkout_files': len(names), 'objects': len(inventory), 'wheels': len(wheels),
                     'wheel_members': sum(result['members'] for result in wheels),
                     'wheel_record_hashes': sum(result['record_hashed'] for result in wheels)},
        'checks': {'storage': 'PASS', 'ancestry_available': 'PASS', 'tree_and_manifest': 'PASS',
                   'checkout': 'PASS', 'other_refs_content': 'NOT_RUN', 'ancestor_content': 'NOT_RUN',
                   'wheel_pins_crc_record_privacy': 'PASS',
                   'all_local_objects': 'NOT_RUN', 'producer_authenticity': 'NOT_PROVEN',
                   'semantic_correctness': 'NOT_RUN',
                   'checkout_executable_mode': 'NOT_APPLICABLE_WINDOWS' if os.name == 'nt' else 'PASS'},
        'refs_outside_content_audit': refs,
        'entries': entries, 'objects': inventory,
        'limitations': [
            'Expected identity must come from a trusted channel; a local manifest alone is not authentication.',
            'Generated directories declared in the manifest and nested __pycache__ are outside source coverage.',
            'No other branch content, full history, unrelated objects, licenses or security certification.',
            'Point-in-time verification, not a lock against concurrent or subsequent writes.',
        ],
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, default=Path(__file__).absolute().parents[1])
    p.add_argument('--commit', default='HEAD', help='Reference resolved once at audit start')
    p.add_argument('--expected-commit', required=True, help='Full OID from an external trusted delivery')
    p.add_argument('--expected-tree', required=True, help='Full tree OID from the external delivery')
    p.add_argument('--wheel-pins', required=True, type=Path, help='Approved ANCLAS.json outside the checkout')
    p.add_argument('--artifacts', type=Path, help='Also verify a generated report independently')
    p.add_argument('--output', type=Path)
    args = p.parse_args()
    target = None
    try:
        if args.output:
            target = output_path(args.root.absolute(), args.output)
        result = verify(args.root, args.commit, args.expected_commit, args.expected_tree, args.wheel_pins)
        if args.artifacts:
            result['artifacts'] = artifacts(args.artifacts)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as exc:
        result = {'status': 'FAIL', 'contract': CONTRACT, 'scope': SCOPE,
                  'expected_commit': args.expected_commit, 'expected_tree': args.expected_tree,
                  'expected_wheel_pins_sha256': EXTERNAL_PINS_SHA256,
                  'error': str(exc), 'checks': {'release_verification': 'NOT_COMPLETED'}}
    if target is not None:
        target.parent.mkdir(parents=True, exist_ok=True)
        no_links(target.parent)
        with target.open('x', encoding='utf-8') as f:
            f.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    sys.exit(main())
