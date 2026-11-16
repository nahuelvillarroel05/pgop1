"""R2 release identity and checkout attacks; R1 retains its separate tests."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(ROOT / 'tools'))
from audit_distribution import MANIFEST, history
from update_manifest import update
from audit_release import verify


class ReleaseAuditTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='release-', dir=os.environ.get('PGOP1_TEST_ROOT')))
        self.git('init', '--initial-branch=main', '--template=')
        self.git('config', 'user.name', 'Synthetic release test')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'core.autocrlf', 'false')
        (self.root / 'code.py').write_bytes(b'def add(a,b): return a+b\n')
        self.commit()
        self.pin = self.git('rev-parse', 'HEAD').decode().strip()
        self.git('branch', 'experiment')
        self.git('branch', 'feature/extra')

    def git(self, *args):
        p = subprocess.run(['git', '-C', str(self.root), *args], capture_output=True)
        self.assertEqual(p.returncode, 0, p.stderr.decode(errors='replace'))
        return p.stdout

    def commit(self):
        update(self.root)
        self.git('add', '--all')
        self.git('commit', '-m', 'Synthetic release')

    def audit(self, expected=None, **kwargs):
        return verify(self.root, 'HEAD', expected or self.pin, **kwargs)

    def test_extra_ref_accepted_with_explicit_scope(self):
        r = self.audit()
        self.assertEqual(r['contract'], 'PGOP1_RELEASE_R2')
        self.assertEqual(r['commit'], self.pin)
        self.assertEqual(r['checks']['checkout'], 'PASS')
        self.assertIn('refs/heads/feature/extra', r['refs_outside_content_audit'])
        self.assertEqual(r['checks']['other_refs_content'], 'NOT_RUN')

    def test_r1_still_rejects_extra_ref(self):
        with self.assertRaisesRegex(ValueError, 'ref/tag'):
            history(self.root)

    def test_wrong_external_identity(self):
        with self.assertRaisesRegex(ValueError, 'external commit'):
            self.audit('0' * 40)

    def test_mutable_or_abbreviated_external_identity(self):
        for pin in ['main', self.pin[:12]]:
            with self.subTest(pin=pin), self.assertRaisesRegex(ValueError, 'full'):
                self.audit(pin)

    def test_wrong_external_tree(self):
        with self.assertRaisesRegex(ValueError, 'external tree'):
            self.audit(expected_tree='0' * 40)

    def test_changed_checkout(self):
        (self.root / 'code.py').write_bytes(b'changed\n')
        with self.assertRaisesRegex(ValueError, 'checkout differs'):
            self.audit()

    def test_missing_checkout_file(self):
        (self.root / 'code.py').unlink()
        with self.assertRaisesRegex(ValueError, 'checkout membership'):
            self.audit()

    def test_untracked_product_file(self):
        (self.root / 'unlisted.py').write_bytes(b'pass\n')
        with self.assertRaisesRegex(ValueError, 'checkout membership'):
            self.audit()

    def test_regenerated_checkout_manifest_cannot_hide_edit(self):
        (self.root / 'code.py').write_bytes(b'changed\n')
        update(self.root)
        with self.assertRaisesRegex(ValueError, 'checkout differs'):
            self.audit()

    def test_new_coherent_commit_cannot_impersonate_old_anchor(self):
        (self.root / 'code.py').write_bytes(b'new release\n')
        self.commit()
        with self.assertRaisesRegex(ValueError, 'external commit'):
            self.audit()

    def test_invalid_committed_manifests(self):
        original = (self.root / MANIFEST).read_bytes()
        data = json.loads(original)
        variants = [
            {**data, 'files': []},
            {**data, 'files': data['files'] * 2},
            {**data, 'files': [{**data['files'][0], 'path': '../escape'}]},
            {**data, 'files': [{**data['files'][0], 'sha256': '0' * 64}]},
        ]
        for value in variants:
            with self.subTest(value=value):
                (self.root / MANIFEST).write_text(json.dumps(value), encoding='utf-8')
                self.git('add', MANIFEST)
                self.git('commit', '-m', 'Malformed synthetic manifest')
                pin = self.git('rev-parse', 'HEAD').decode().strip()
                with self.assertRaises(ValueError):
                    self.audit(pin)

    def test_duplicate_json_key_rejected(self):
        p = self.root / MANIFEST
        p.write_bytes(p.read_bytes().replace(b'"schema":', b'"schema":"duplicate", "schema":', 1))
        self.git('add', MANIFEST)
        self.git('commit', '-m', 'Duplicate key')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON'):
            self.audit(self.git('rev-parse', 'HEAD').decode().strip())

    def test_replacement_ref_rejected(self):
        self.git('replace', self.pin, self.pin)
        with self.assertRaisesRegex(ValueError, 'replacement'):
            self.audit()

    def test_partial_clone_config_rejected(self):
        self.git('config', 'remote.origin.promisor', 'true')
        with self.assertRaisesRegex(ValueError, 'partial clone'):
            self.audit()

    def test_alternate_storage_rejected(self):
        p = self.root / '.git/objects/info/alternates'
        p.write_text(str(self.root / 'outside'), encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'genealogy'):
            self.audit()

    def test_shallow_rejected(self):
        (self.root / '.git/shallow').write_text(self.pin + '\n', encoding='ascii')
        with self.assertRaisesRegex(ValueError, 'genealogy'):
            self.audit()

    def test_checkout_link_rejected(self):
        target = self.root / 'audit-output'
        target.mkdir()
        link = self.root / 'escape'
        if os.name == 'nt':
            p = subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(link), str(target)], capture_output=True)
            self.assertEqual(p.returncode, 0, p.stderr.decode(errors='replace'))
        else:
            link.symlink_to(target, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'reparse'):
            self.audit()

    def test_tracked_generated_path_cannot_be_excluded(self):
        p = self.root / 'audit-output/hidden.py'
        p.parent.mkdir()
        p.write_bytes(b'pass\n')
        self.git('add', '-f', 'audit-output/hidden.py')
        self.git('commit', '-m', 'Excluded product attack')
        with self.assertRaisesRegex(ValueError, 'generated'):
            self.audit(self.git('rev-parse', 'HEAD').decode().strip())

    def test_hardlinked_git_storage_rejected(self):
        obj = self.root / '.git/objects' / self.pin[:2] / self.pin[2:]
        os.link(obj, self.root / 'shared-object')
        with self.assertRaisesRegex(ValueError, 'hardlinked'):
            self.audit()

    def test_cli_receipt_cannot_escape_generated_directory(self):
        (self.root / 'audit-output').mkdir()
        for target in ['audit-output/../untracked.json', 'audit-output/../.git/changed', 'code.py']:
            with self.subTest(target=target):
                before = (self.root / 'code.py').read_bytes()
                p = subprocess.run([sys.executable, '-B', str(ROOT / 'tools/audit_release.py'),
                                    '--root', str(self.root), '--expected-commit', self.pin,
                                    '--output', str(self.root / target)], capture_output=True)
                self.assertEqual(p.returncode, 1, p.stderr.decode(errors='replace'))
                self.assertEqual(json.loads(p.stdout)['status'], 'FAIL')
                self.assertEqual((self.root / 'code.py').read_bytes(), before)
                self.assertFalse((self.root / 'untracked.json').exists())
                self.assertFalse((self.root / '.git/changed').exists())

    def test_cli_receipt_binds_success_and_refuses_overwrite(self):
        out = self.root / 'audit-output/receipt.json'
        command = [sys.executable, '-B', str(ROOT / 'tools/audit_release.py'),
                   '--root', str(self.root), '--expected-commit', self.pin, '--output', str(out)]
        first = subprocess.run(command, capture_output=True)
        self.assertEqual(first.returncode, 0, first.stderr.decode(errors='replace'))
        receipt = out.read_bytes()
        self.assertEqual(json.loads(receipt)['commit'], self.pin)
        second = subprocess.run(command, capture_output=True)
        self.assertEqual(second.returncode, 1)
        self.assertEqual(out.read_bytes(), receipt)

    def test_public_wrapper_requires_explicit_consistent_contract(self):
        for args in [[], ['--contract', 'release-r2'],
                     ['--contract', 'historical-r1', '--expected-commit', self.pin],
                     ['--contract', 'release-r2', '--expected-commit', self.pin, '--expected-main', self.pin]]:
            with self.subTest(args=args):
                p = subprocess.run([sys.executable, '-B', str(ROOT / 'tools/audit_public.py'), *args], capture_output=True)
                self.assertEqual(p.returncode, 2)
                self.assertIn(b'error:', p.stderr)


if __name__ == '__main__':
    unittest.main()
