"""Inert fixtures for the wheel-aware audit, isolated from production pins."""
import base64
import csv
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZIP_STORED, ZipFile, ZipInfo

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from audit_distribution import LIMIT, digest
from audit_release_wheels import verify
from release_wheel_review import (
    PLATFORM_WHEEL, PREFIX, PUBLIC_EXAMPLE, PUBLIC_EXAMPLE_MEMBER, inspect_wheel,
    load_pins, member_names, scan_member, select_wheels,
)
from update_manifest import update


SAMPLE = PREFIX + 'synthetic-1-py3-none-any.whl'
RECORD = 'synthetic-1.dist-info/RECORD'
INERT = b'Synthetic wheel data\n'
SIMULATED_TOKEN = b'ghp_' + b'A' * 36
SIMULATED_USER_PATH = b'Q:' + bytes([92]) + b'Users' + bytes([92]) + b'SyntheticOperator'


def pin(body):
    return {'bytes': len(body), 'sha256': digest(body)}


def synthetic_wheel(entries, change_record=lambda rows: rows, compression=ZIP_STORED):
    raw = io.BytesIO()
    with ZipFile(raw, 'w', compression=compression) as archive:
        rows = []
        for name, body in entries:
            archive.writestr(name, body)
            encoded = base64.urlsafe_b64encode(bytes.fromhex(digest(body))).rstrip(b'=').decode('ascii')
            rows.append([name, 'sha256=' + encoded, str(len(body))])
        rows.append([RECORD, '', ''])
        output = io.StringIO(newline='')
        csv.writer(output).writerows(change_record(rows))
        archive.writestr(RECORD, output.getvalue())
    return raw.getvalue()


class WheelReviewTests(unittest.TestCase):
    def check(self, raw):
        return inspect_wheel(SAMPLE, raw, {SAMPLE: pin(raw)})

    def test_valid_wheel_and_external_pin_mismatch(self):
        raw = synthetic_wheel([('sample.py', INERT)])
        receipt = self.check(raw)
        self.assertEqual((receipt['members'], receipt['record_hashed']), (2, 1))
        for expected in ({**pin(raw), 'sha256': '0' * 64}, {**pin(raw), 'bytes': len(raw) - 1}):
            with self.subTest(expected=expected), self.assertRaisesRegex(ValueError, 'pin mismatch'):
                inspect_wheel(SAMPLE, raw, {SAMPLE: expected})
        with self.assertRaisesRegex(ValueError, 'pin mismatch'):
            inspect_wheel(SAMPLE, raw[:-1] + b'x', {SAMPLE: pin(raw)})

    def test_pin_path_coverage_and_duplicate_blob(self):
        pins = {SAMPLE: {}}
        expected = {SAMPLE: ('100644', 'a' * 40)}
        self.assertEqual(select_wheels(expected, pins), {'a' * 40: SAMPLE})
        for name in ('renamed.whl', 'case.WHL'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'membership'):
                select_wheels({**expected, name: ('100644', 'b' * 40)}, pins)
        with self.assertRaisesRegex(ValueError, 'membership'):
            select_wheels({}, pins)
        with self.assertRaisesRegex(ValueError, 'alias'):
            select_wheels({**expected, 'alias.txt': expected[SAMPLE]}, pins)
        with self.assertRaisesRegex(ValueError, 'alias'):
            select_wheels({**expected, SAMPLE + '.whl': expected[SAMPLE]}, {**pins, SAMPLE + '.whl': {}})

    def test_crc_checked_even_with_test_pin_matching(self):
        raw = synthetic_wheel([('sample.py', INERT)])
        changed = raw.replace(INERT, b'X' + INERT[1:], 1)
        with self.assertRaisesRegex(ValueError, 'invalid wheel archive'):
            self.check(changed)

    def test_invalid_record_variants(self):
        changes = {
            'missing': lambda rows: rows[1:],
            'duplicate': lambda rows: [rows[0], rows[0]],
            'foreign': lambda rows: [rows[0], ['foreign', '', '']],
            'hash': lambda rows: [[rows[0][0], rows[0][1] + 'x', rows[0][2]], rows[1]],
            'size': lambda rows: [[rows[0][0], rows[0][1], '1'], rows[1]],
            'self': lambda rows: [rows[0], [RECORD, '', '1']],
        }
        for label, change in changes.items():
            with self.subTest(label=label), self.assertRaisesRegex(ValueError, 'RECORD'):
                self.check(synthetic_wheel([('sample.txt', INERT)], change))

    def test_unsafe_members_or_aliases(self):
        cases = (('../outside.txt',), ('/outside.txt',), ('data/AUX.txt',), ('bad:name',),
                 ('data.',), ('DATA/one', 'data/two'), ('file', 'file/child'), ('same', 'SAME'))
        for names in cases:
            with self.subTest(names=names), self.assertRaisesRegex(ValueError, 'path|collision'):
                self.check(synthetic_wheel([(name, INERT) for name in names]))

    def test_nonregular_encrypted_and_metadata_entries(self):
        for flags, mode, message in ((1, stat.S_IFREG, 'unsupported'), (64, stat.S_IFREG, 'unsupported'),
                                     (0, stat.S_IFLNK, 'nonregular')):
            with self.subTest(flags=flags, mode=mode), self.assertRaisesRegex(ValueError, message):
                info = ZipInfo('sample.py')
                info.flag_bits = flags
                info.external_attr = mode << 16
                member_names([info])
        modified = ZipInfo('sample.py')
        modified.comment = INERT
        with self.assertRaisesRegex(ValueError, 'metadata'):
            member_names([modified])

    def test_body_and_member_budgets(self):
        with self.assertRaisesRegex(ValueError, 'pin mismatch'):
            self.check(b'x' * (LIMIT + 1))
        huge = synthetic_wheel([('large.txt', b'x' * (LIMIT + 1))], compression=ZIP_DEFLATED)
        with self.assertRaisesRegex(ValueError, 'unsupported'):
            self.check(huge)
        many = synthetic_wheel([(f'{n}.txt', b'') for n in range(1000)])
        with self.assertRaisesRegex(ValueError, 'member budget'):
            self.check(many)
        aggregate = synthetic_wheel([(f'{n}.txt', b'x' * LIMIT) for n in range(9)], compression=ZIP_DEFLATED)
        with self.assertRaisesRegex(ValueError, 'member budget'):
            self.check(aggregate)

    def test_inner_strict_utf8_and_sensitive_content(self):
        for contents in (SIMULATED_TOKEN, SIMULATED_USER_PATH):
            with self.subTest(contents=contents), self.assertRaisesRegex(ValueError, 'sensitive'):
                self.check(synthetic_wheel([('sample.txt', contents)]))
        with self.assertRaises(UnicodeDecodeError):
            self.check(synthetic_wheel([('binary.dat', bytes([255]))]))

    def test_public_example_exception_requires_exact_identity(self):
        changed = PUBLIC_EXAMPLE + b' (changed member)\n'
        with self.assertRaisesRegex(ValueError, 'sensitive'):
            scan_member(PLATFORM_WHEEL, PUBLIC_EXAMPLE_MEMBER, changed)
        with self.assertRaisesRegex(ValueError, 'sensitive'):
            scan_member(SAMPLE, PUBLIC_EXAMPLE_MEMBER, PUBLIC_EXAMPLE)

    def test_external_pin_rejects_unbound_or_internal_input(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('PGOP1_TEST_ROOT')) as tmp:
            outer = Path(tmp)
            root = outer / 'checkout'
            root.mkdir()
            path = outer / 'ANCLAS.json'
            path.write_bytes(b'{"wheels":{}}')
            with self.assertRaisesRegex(ValueError, 'SHA-256'):
                load_pins(root, path)
            with self.assertRaisesRegex(ValueError, 'outside'):
                load_pins(root, root / 'ANCLAS.json')


class WheelReleaseTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='synthetic-wheel-', dir=os.environ.get('PGOP1_TEST_ROOT')))
        self.git('init', '--initial-branch=main', '--template=')
        self.git('config', 'user.name', 'Synthetic wheel test')
        self.git('config', 'user.email', 'test@example.invalid')
        self.git('config', 'core.autocrlf', 'false')
        raw = synthetic_wheel([('sample.py', INERT)])
        target = self.root / SAMPLE
        target.parent.mkdir(parents=True)
        target.write_bytes(raw)
        self.pins = {SAMPLE: pin(raw)}

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], stderr=subprocess.PIPE).decode().strip()

    def commit(self):
        update(self.root)
        self.git('add', '--all')
        self.git('commit', '-m', 'Synthetic wheel-aware audit fixture')
        return self.git('rev-parse', 'HEAD'), self.git('rev-parse', 'HEAD^{tree}')

    def audit(self, commit, tree):
        # Only this test supplies a synthetic pin. The public CLI always calls the exact-file loader.
        with patch('audit_release_wheels.load_pins', return_value=self.pins):
            return verify(self.root, 'HEAD', commit, tree, self.root.parent / 'synthetic-pins.json')

    def test_complete_tree_and_checkout_remain_required(self):
        commit, tree = self.commit()
        result = self.audit(commit, tree)
        self.assertEqual(result['contract'], 'PGOP1_RELEASE_R2_WHEELS_V1')
        self.assertEqual(result['coverage']['wheels'], 1)
        self.assertEqual(result['checks']['checkout'], 'PASS')
        with self.assertRaisesRegex(ValueError, 'external tree'):
            self.audit(commit, '0' * 40)
        (self.root / SAMPLE).write_bytes(INERT)
        with self.assertRaisesRegex(ValueError, 'checkout differs'):
            self.audit(commit, tree)

    def test_sensitive_nonwheel_blob_uses_original_scanner(self):
        for contents in (SIMULATED_TOKEN, SIMULATED_USER_PATH):
            with self.subTest(contents=contents):
                (self.root / 'ordinary.txt').write_bytes(contents)
                commit, tree = self.commit()
                with self.assertRaisesRegex(ValueError, 'sensitive'):
                    self.audit(commit, tree)


if __name__ == '__main__':
    unittest.main()
