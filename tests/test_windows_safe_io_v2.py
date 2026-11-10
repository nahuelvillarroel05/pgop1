"""Native Windows hostile-name fixtures; existing POSIX expectations stay intact."""
import ctypes as C
from ctypes import wintypes as W
import hashlib
import os
from pathlib import Path
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch

from runtime.candidate import windows_safe_io_v2 as w


def junction(handle, target):
    """Fixture-only mount-point mutation; never used by product code."""
    k, _ = w.api()
    k.DeviceIoControl.argtypes = [W.HANDLE, W.DWORD, W.LPVOID, W.DWORD,
                                 W.LPVOID, W.DWORD, C.POINTER(W.DWORD), W.LPVOID]
    k.DeviceIoControl.restype = W.BOOL
    substitute = ('\\??\\' + str(target)).encode('utf-16-le')
    printable = str(target).encode('utf-16-le')
    data = (struct.pack('<HHHH', 0, len(substitute), len(substitute)+2, len(printable))
            + substitute + b'\0\0' + printable + b'\0\0')
    body = struct.pack('<IHH', 0xa0000003, len(data), 0) + data
    returned = W.DWORD()
    w.checked(k.DeviceIoControl(handle, 0x900a4, body, len(body), None, 0,
                               C.byref(returned), None), 'FIXTURE_REPARSE_FAILED')


@unittest.skipUnless(os.name == 'nt', 'Native Windows qualification only')
class WindowsSafeIOTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='native-io-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base/'source'
        self.source.mkdir()
        self.outside = self.base/'outside'
        self.outside.mkdir()
        self.body = b'def inside(): pass\n'
        (self.source/'x.py').write_bytes(self.body)
        self.secret = b'OUTSIDE_SENTINEL_MUST_NOT_BE_READ'
        (self.outside/'sentinel').write_bytes(self.secret)

    def read(self, name='x.py', expected=None, limit=262144):
        return w.safe_read(self.source, name, expected or hashlib.sha256(self.body).hexdigest(), limit)

    def test_regular_nested_and_exact_identity(self):
        (self.source/'nested').mkdir()
        (self.source/'nested'/'y.py').write_bytes(self.body)
        a, b = self.read(), self.read('nested/y.py')
        self.assertEqual(a.raw, self.body)
        self.assertEqual(b.raw, self.body)
        self.assertNotEqual(a.metadata.identity, b.metadata.identity)

    def test_names_traversal_namespaces_ads_unicode_case_alias(self):
        for name in ('', '.', '..', '../x.py', '/x.py', 'C:x.py', 'C:/x.py',
                     '//server/share/x', '\\\\?\\C:\\x', '\\??\\x', 'x.py:s', 'x\0.py',
                     'dir\\x.py', 'CON', 'NUL.txt', 'COM1', 'LPT9.py', 'x.', 'x ',
                     'x//y', 'a/../x.py', 'a/./x.py', 'caf\u00e9.py', 'X.PY', 'X~1.PY'):
            with self.subTest(name=repr(name)), self.assertRaises((ValueError, OSError)):
                self.read(name)

    def test_hardlinks_rejected_without_provenance_claim(self):
        os.link(self.source/'x.py', self.outside/'hard.py')
        with self.assertRaisesRegex(w.SafeIOError, 'HARDLINK'):
            self.read()

    def test_file_and_directory_symlinks_rejected(self):
        (self.source/'link.py').symlink_to(self.outside/'sentinel')
        (self.source/'linked').symlink_to(self.outside, target_is_directory=True)
        for name in ('link.py', 'linked/sentinel'):
            with self.assertRaises((ValueError, OSError)):
                w.safe_read(self.source, name, hashlib.sha256(self.secret).hexdigest(), 262144)

    def test_junction_and_chain_rejected(self):
        for name, target in [('j1', self.outside), ('j2', self.source/'j1')]:
            path = self.source/name
            path.mkdir()
            k, _ = w.api()
            value = k.CreateFileW(str(path), 0x100, 7, None, 3, 0x02200000, None)
            self.assertNotEqual(value, C.c_void_p(-1).value)
            with w.Handle(value):
                junction(value, target)
        for name in ('j1/sentinel', 'j2/sentinel'):
            with self.assertRaises((ValueError, OSError)):
                w.safe_read(self.source, name, hashlib.sha256(self.secret).hexdigest(), 262144)
        self.assertEqual((self.outside/'sentinel').read_bytes(), self.secret)

    def test_attribute_only_reparse_mutation_read_and_create(self):
        for create in (False, True):
            name = 'new-empty' if create else 'existing-empty'
            if not create:
                (self.source/name).mkdir()
            with w.Directory(self.source) as directory:
                directory.add(w.open_component(directory.handle, name, directory=True, create=create))
                k, _ = w.api()
                value = k.CreateFileW(str(self.source/name), 0x100, 7, None, 3, 0x02200000, None)
                self.assertNotEqual(value, C.c_void_p(-1).value)
                with w.Handle(value):
                    junction(value, self.outside)
                for filename, make in [('sentinel', False), ('escaped', True)]:
                    with self.assertRaises((ValueError, OSError)):
                        with w.open_component(directory.handle, filename, directory=False, create=make, write=make):
                            self.fail('Reparse parent accepted')
                with self.assertRaises(w.SafeIOError):
                    directory.validate()
        self.assertEqual(sorted(p.name for p in self.outside.iterdir()), ['sentinel'])
        self.assertEqual((self.outside/'sentinel').read_bytes(), self.secret)

    def test_concurrent_rename_target_and_directory_200_attempts(self):
        outcomes = []
        (self.source/'nested').mkdir()
        (self.source/'nested'/'x.py').write_bytes(self.body)
        with w.Directory(self.source/'nested') as directory:
            with w.open_component(directory.handle, 'x.py', directory=False):
                def actor():
                    for index in range(100):
                        for path in (self.source/'nested', self.source/'nested'/'x.py'):
                            try:
                                os.rename(path, path.with_name(path.name+'-moved'))
                                outcomes.append('RENAMED')
                            except OSError:
                                outcomes.append('REJECTED')
                thread = threading.Thread(target=actor)
                thread.start()
                thread.join(10)
                self.assertFalse(thread.is_alive())
                self.assertEqual(outcomes, ['REJECTED']*200)
                directory.validate()
        self.assertEqual(self.read('nested/x.py').raw, self.body)

    def test_changed_pin_size_and_ordinary_writer_excluded(self):
        with self.assertRaisesRegex(w.SafeIOError, 'HASH_MISMATCH'):
            self.read(expected='0'*64)
        with self.assertRaisesRegex(w.SafeIOError, 'SIZE_LIMIT'):
            self.read(limit=1)
        with w.Directory(self.source) as d:
            with w.open_component(d.handle, 'x.py', directory=False):
                with self.assertRaises(OSError):
                    (self.source/'x.py').write_bytes(b'changed')
        self.assertEqual(self.read().raw, self.body)
        (self.source/'x.py').write_bytes(b'changed')
        with self.assertRaisesRegex(w.SafeIOError, 'HASH_MISMATCH'):
            self.read()

    def test_create_new_overlap_existing_junction_and_file_collision(self):
        path = self.base/'new.json'
        w.safe_create_new(path, b'{}', [self.source])
        with self.assertRaises(FileExistsError):
            w.safe_create_new(path, b'changed', [self.source])
        self.assertEqual(path.read_bytes(), b'{}')
        with self.assertRaisesRegex(w.SafeIOError, 'OVERLAPS'):
            w.safe_create_new(self.source/'new', b'bad', [self.source])
        (self.base/'linked').symlink_to(self.outside, target_is_directory=True)
        with self.assertRaises((ValueError, OSError)):
            w.safe_create_new(self.base/'linked'/'new', b'bad', [self.source])
        self.assertFalse((self.outside/'new').exists())

    def test_partial_write_has_no_completed_manifest_retry_no_overwrite(self):
        out = self.base/'artifacts'
        files = {'REPORT.json': b'{}', 'FINAL_HANDOFF.md': b'fixture', 'MANIFEST.json': b'{}'}
        with patch.object(w.os, 'write', side_effect=OSError('injected disk failure')):
            with self.assertRaises(OSError):
                w.safe_create_artifacts(self.source, out, files)
        self.assertFalse((out/'MANIFEST.json').exists())
        with self.assertRaises(FileExistsError):
            w.safe_create_artifacts(self.source, out, files)

    def test_artifacts_stay_exclusive_through_publication(self):
        out = self.base/'artifacts'
        files = {'REPORT.json': b'{}', 'FINAL_HANDOFF.md': b'fixture', 'MANIFEST.json': b'{}'}
        original = w.created_file
        attempts = []
        def hook(directory, name, body):
            if name == 'MANIFEST.json':
                for old in ('REPORT.json', 'FINAL_HANDOFF.md'):
                    try:
                        (out/old).write_bytes(b'attacker')
                        attempts.append('CHANGED')
                    except OSError:
                        attempts.append('REJECTED')
            return original(directory, name, body)
        with patch.object(w, 'created_file', side_effect=hook):
            w.safe_create_artifacts(self.source, out, files)
        self.assertEqual(attempts, ['REJECTED', 'REJECTED'])
        for name, body in files.items():
            self.assertEqual((out/name).read_bytes(), body)

    def test_api_failure_closes_ancestor_handles(self):
        k, _ = w.api()
        k.GetProcessHandleCount.argtypes = [W.HANDLE, C.POINTER(W.DWORD)]
        k.GetProcessHandleCount.restype = W.BOOL
        k.GetCurrentProcess.restype = W.HANDLE
        def count():
            result = W.DWORD()
            w.checked(k.GetProcessHandleCount(k.GetCurrentProcess(), C.byref(result)))
            return result.value
        before = count()
        for _ in range(100):
            with self.assertRaises(w.SafeIOError):
                self.read('missing/file.py')
        self.assertEqual(count(), before)

    def test_root_and_destination_replacement_denied_and_existing_writer_rejected(self):
        with (self.source/'x.py').open('r+b'):
            with self.assertRaises(w.SafeIOError):
                self.read()
        out = self.base/'output'
        out.mkdir()
        for path in (self.source, out):
            with w.Directory(path):
                for _ in range(50):
                    with self.assertRaises(OSError):
                        os.rename(path, path.with_name(path.name+'-moved'))
        self.assertEqual(self.read().raw, self.body)

    def test_verifier_rejects_input_name_even_after_input_deleted(self):
        from tools.verify_source_v2 import write_verification
        report = self.base/'REPORT.json'
        report.write_bytes(b'{}')
        report.unlink()
        with self.assertRaisesRegex(ValueError, 'OVERLAPS_INPUT'):
            write_verification(report, self.source, '{}', report_path=report)
        self.assertFalse(report.exists())

    def test_provider_refusals_independently_verified_as_abstentions(self):
        from runtime.candidate.document_claims_v1 import audit_catalog
        from tools.verify_source_v2 import verify_report
        catalog = {'schema': 'pgop1.source-audit-catalog.v2', 'claims': [],
                   'sources': [{'path': 'x.py', 'sha256': hashlib.sha256(self.body).hexdigest(),
                                'kind': 'python'}]}
        os.link(self.source/'x.py', self.outside/'hard.py')
        report = audit_catalog(self.source, catalog)
        self.assertEqual(report['document_claims']['source_errors'][0]['reason'], 'UNSAFE_PATH_HARDLINK')
        result = verify_report(self.source, report)
        self.assertEqual(result['source_integrity'], 'FAILED_PINS_WITH_VERIFIED_ABSTENTIONS')
        report['document_claims']['source_errors'][0]['reason'] = 'SOURCE_HASH_MISMATCH'
        with self.assertRaises(ValueError):
            verify_report(self.source, report)

    def test_output_reparse_substitution_before_first_file_fails_closed(self):
        out = self.base/'artifacts'
        original = w.created_file
        def substitute(directory, name, body):
            k, _ = w.api()
            value = k.CreateFileW(str(out), 0x100, 7, None, 3, 0x02200000, None)
            self.assertNotEqual(value, C.c_void_p(-1).value)
            with w.Handle(value):
                junction(value, self.outside)
            return original(directory, name, body)
        with patch.object(w, 'created_file', side_effect=substitute):
            with self.assertRaises(w.SafeIOError):
                w.safe_create_artifacts(self.source, out, {'REPORT.json': b'{}', 'MANIFEST.json': b'{}'})
        self.assertEqual(sorted(p.name for p in self.outside.iterdir()), ['sentinel'])

    def test_cli_retains_source_identity_across_capture_and_publication(self):
        import json
        import sys
        from tools import audit_source_v2 as producer, verify_source_v2 as verifier
        raw = producer.canonical({'schema': 'pgop1.source-audit-catalog.v2', 'claims': [],
                                 'sources': [{'path': 'x.py', 'sha256': hashlib.sha256(self.body).hexdigest(),
                                              'kind': 'python'}]})
        catalog = self.base/'catalog.json'
        catalog.write_bytes(raw)
        out = self.base/'artifacts'
        original = producer.audit_catalog
        def capture(*args, **kwargs):
            with self.assertRaises(OSError):
                os.rename(self.source, self.base/'renamed-original-source')
            return original(*args, **kwargs)
        command = ['audit_source_v2', '--source-root', str(self.source), '--catalog', str(catalog),
                   '--catalog-sha256', hashlib.sha256(raw).hexdigest(), '--output', str(out)]
        with patch.object(sys, 'argv', command), patch.object(producer, 'audit_catalog', side_effect=capture):
            self.assertEqual(producer.main(), 0)
        verify = verifier.verify_report
        def check(*args, **kwargs):
            for path in (self.source, out):
                with self.assertRaises(OSError):
                    os.rename(path, self.base/('renamed-'+path.name))
            return verify(*args, **kwargs)
        command = ['verify_source_v2', '--source-root', str(self.source), '--artifacts', str(out)]
        with patch.object(sys, 'argv', command), patch.object(verifier, 'verify_report', side_effect=check):
            self.assertEqual(verifier.main(), 0)


if __name__ == '__main__':
    unittest.main()
