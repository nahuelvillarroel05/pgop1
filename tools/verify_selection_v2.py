"""Independent V2 admission and V1 selection replay; imports no producer."""
import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import sys
ROOT = Path(__file__).absolute().parents[1]
sys.path[:0] = [str(ROOT / 'runtime'), str(ROOT)]
from candidate import selection_contract_v1 as C
from candidate import admission_contract_v2 as A
from candidate import windows_safe_io_v2 as IO
from tools.verify_selection_v1 import replay

CAPS = {'PLAN.json': 64000000, 'CAPTURES.json': 36000000, 'AST_REPORTS.json': 128000000,
        'SOURCE_CATALOG.json': 262144, 'POLICY.json': 262144,
        'ADMISSION_POLICY.json': 262144, 'CODE_IDENTITY.json': 262144}

def forbidden(name, owner):
    """Independent component-based evaluator, not producer deny/decision code."""
    parts = name.lower().split('/')
    if any(parts[:len(rule[:-1].split('/'))] == rule[:-1].lower().split('/')
           and len(parts) > len(rule[:-1].split('/')) for rule in owner['deny_prefixes']):
        return True
    if any(part in [r.lower() for r in owner['deny_components']] for part in parts):
        return True
    if '/'.join(parts) in [r.lower() for r in owner['deny_exact']]:
        return True
    return bool(owner['allow_exact']) and '/'.join(parts) not in [r.lower() for r in owner['allow_exact']]

def independent_envelope(plan, catalog, owner):
    refs = []
    base = '' if plan['package_root'] == '.' else plan['package_root'] + '/'
    for event in plan['trace']:
        if event['event'] != 'REFERENCE':
            continue
        locators = set()
        for mod in event['requested']:
            if not mod or 'WITHHELD' in mod.split('.'):
                continue
            path = base + '/'.join(mod.split('.'))
            for target in [path + '.py', path + '/__init__.py']:
                if forbidden(target, owner):
                    locators.add(C.digest(target.encode('utf8')))
        if locators:
            refs.append(dict(origin=event['origin'], reason='OWNER_DENIED_REFERENCE',
                             locator_sha256=sorted(locators), authority='SYNTAX_ONLY_NO_BINDING_AUTHORITY'))
    normal = dict(owner)
    for k in ('deny_prefixes', 'deny_components', 'deny_exact', 'allow_exact'):
        normal[k] = sorted(s.lower() for s in owner[k])
    decision = dict(schema='pgop1.selection-admission-decision.v2', status='ADMITTED',
                    catalog_sha256=C.digest(C.canonical(catalog)),
                    admission_policy_sha256=C.digest(C.canonical(owner)),
                    normalized_policy_sha256=C.digest(C.canonical(normal)),
                    catalog_members=len(catalog['sources']),
                    stages=['OWNER_POLICY_AUTHENTICATED', 'CATALOG_AUTHENTICATED',
                            'CATALOG_POLICY_ADMITTED', 'CODE_AUTHENTICATED', 'PATH_IDENTITIES_PREFLIGHTED'])
    return dict(schema='pgop1.autonomous-source-selection.v2', admission=decision,
                admission_references=refs, legacy_plan=plan,
                legacy_v1='LEGACY_V1_DOES_NOT_ENFORCE_OWNER_DENY')

def verify(artifacts, admission_policy_raw, authority, manifest_sha256):
    C.need(type(authority) is A.AuthorityContext, 'AUTHORITY_CONTEXT_REQUIRED')
    authority.validate()
    owner = A.owner_policy(A.pinned(admission_policy_raw, authority.admission_policy_sha256, 'OWNER_POLICY_REQUIRED'))
    C.need(A.same_root(owner['source_root'], authority.source_root), 'OWNER_POLICY_ROOT')
    C.need(C.hash_value(manifest_sha256), 'ARTIFACT_MANIFEST_ANCHOR_REQUIRED')
    IO.absolute(artifacts)
    artifact_path = str(artifacts).replace('/', '\\').lower()
    source_path = authority.source_root.replace('/', '\\').lower().rstrip('\\')
    C.need(artifact_path != source_path and not artifact_path.startswith(source_path + '\\'), 'ARTIFACTS_INSIDE_SOURCE')
    with ExitStack() as tx:
        bundle = tx.enter_context(IO.Directory(artifacts))
        manifest = C.strict(IO.safe_read(artifacts, 'MANIFEST.json', manifest_sha256, 262144).raw)
        C.need(set(manifest) == {'schema', 'files'} and
               manifest['schema'] == 'pgop1.selection-artifacts.v2' and
               type(manifest['files']) is dict and set(manifest['files']) == set(CAPS), 'MANIFEST_SCHEMA')
        for name, row in manifest['files'].items():
            C.need(type(row) is dict and set(row) == {'bytes', 'sha256'} and
                   type(row['bytes']) is int and 0 <= row['bytes'] <= CAPS[name] and
                   C.hash_value(row['sha256']), 'MEMBER_SCHEMA')
        def read(name):
            pin = manifest['files'][name]
            raw = IO.safe_read(artifacts, name, pin['sha256'], CAPS[name]).raw
            C.need(len(raw) == pin['bytes'], 'MEMBER_SIZE')
            return raw
        # Caller-pinned metadata and full deny evaluation precede capture/report reads.
        ar = read('ADMISSION_POLICY.json')
        C.need(ar == admission_policy_raw, 'OWNER_POLICY_SUBSTITUTION')
        cr, pr, code_raw = read('SOURCE_CATALOG.json'), read('POLICY.json'), read('CODE_IDENTITY.json')
        c, p, a, code = A.authenticate(cr, pr, ar, code_raw, authority)
        for row in c['sources']:
            C.need(not forbidden(row['path'], a), 'OWNER_CATALOG_DENIED')
        product = tx.enter_context(IO.Directory(ROOT))
        source = tx.enter_context(IO.Directory(c['source_root']))
        IO.reject_membership(source, product)
        IO.reject_membership(product, source)
        IO.reject_membership(bundle, source)
        for row in code['files']:
            raw = IO.safe_read(ROOT, row['path'], row['sha256'], 262144).raw
            C.need(len(raw) == row['bytes'], 'CODE_CHANGED')
        directories = []; identities = set()
        for row in c['sources']:
            directory = tx.enter_context(IO.Directory(c['source_root']))
            for part in row['path'].split('/')[:-1]:
                directory.add(IO.open_component(directory.handle, part, directory=True))
            directories.append(directory)
            with IO.open_component(directory.handle, row['path'].split('/')[-1], directory=False) as handle:
                meta = IO.metadata(handle, False)
                C.need(meta.identity not in identities, 'CATALOG_IDENTITY_COLLISION')
                C.need(meta.size == row['bytes'], 'SOURCE_METADATA_SIZE')
                identities.add(meta.identity)
        # Check membership before decoding or recapturing any source.
        captured_hex = C.strict(read('CAPTURES.json'))
        structures = C.strict(read('AST_REPORTS.json'))
        claimed = C.strict(read('PLAN.json'))
        pins = {r['path']: r for r in c['sources']}
        C.need(type(captured_hex) is dict and set(captured_hex) <= set(pins), 'CAPTURE_MEMBERSHIP')
        C.need(type(structures) is dict and set(structures) <= set(pins), 'AST_MEMBERSHIP')
        captures = {}
        for path, h in captured_hex.items():
            C.need(type(h) is str, 'CAPTURE_ENCODING')
            raw = bytes.fromhex(h); row = pins[path]
            C.need(len(raw) == row['bytes'] and C.digest(raw) == row['sha256'], 'CAPTURE_HASH')
            captures[path] = raw
        expected_legacy = replay(c, p, authority.code_sha256, captures, structures)
        expected = independent_envelope(expected_legacy, c, a)
        C.need(C.canonical(claimed) == C.canonical(expected), 'SELECTION_V2_SEMANTIC_MISMATCH')
        for directory in [bundle, product, source, *directories]:
            directory.validate()
    return dict(schema='pgop1.selection-verification.v2', status='SELECTION_V2_VERIFIED',
                selected=len(expected_legacy['selected']), producer_imported=False,
                plan_sha256=C.digest(C.canonical(expected)), manifest_sha256=manifest_sha256,
                admission_policy_sha256=authority.admission_policy_sha256,
                scope='OWNER_ADMISSION_AND_CATALOG_REPLAY_WITH_POINT_SOURCE_RECAPTURE',
                autonomous_from_root='BLOCKED_NOT_IMPLEMENTED', source_current_at_ack='NOT_PROVEN',
                artifact_current_at_ack='NOT_PROVEN', atomic_snapshot='NOT_PROVEN',
                instrumentation='PROVIDER_AND_PYTHON_ONLY_NOT_KERNEL')

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('artifacts', 'source-root', 'catalog-sha256', 'policy-sha256',
                'admission-policy', 'admission-policy-sha256', 'code-sha256', 'manifest-sha256'):
        parser.add_argument('--' + key, required=True)
    a = parser.parse_args()
    try:
        authority = A.AuthorityContext(a.source_root, a.catalog_sha256, a.policy_sha256,
                                       a.admission_policy_sha256, a.code_sha256)
        IO.absolute(a.admission_policy); IO.absolute(a.artifacts)
        # Policy config cannot be supplied from the source tree being protected.
        text = a.admission_policy.replace('/', '\\').lower()
        source = a.source_root.replace('/', '\\').lower().rstrip('\\')
        C.need(text != source and not text.startswith(source + '\\'), 'CONFIG_OR_OUTPUT_INSIDE_SOURCE')
        raw = IO.safe_read(Path(a.admission_policy).parent, Path(a.admission_policy).name,
                           a.admission_policy_sha256, 262144).raw
        result = verify(a.artifacts, raw, authority, a.manifest_sha256)
    except (OSError, ValueError, TypeError, KeyError, MemoryError, RecursionError):
        # No arbitrary exception/path/bytes projections into the CLI receipt.
        exc = sys.exception()
        known = getattr(exc, 'code', None) or (str(exc) if type(exc) is ValueError else 'V2_INPUT_OR_IO_ERROR')
        print(json.dumps(dict(status='ERROR', reason=known, operation_completed=False))); return 2
    print(json.dumps(result, sort_keys=True)); return 0
if __name__ == '__main__':
    raise SystemExit(main())