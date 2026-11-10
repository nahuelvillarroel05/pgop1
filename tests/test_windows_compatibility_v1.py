"""Versioned acceptance; never substitutes for the original Windows suite."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import audit_source_v2 as p, verify_source_v2 as v
from tools.source_publication_v1 import publish_audit_v1, publish_verification_v1
from candidate import windows_safe_io_v2 as w
from runtime.candidate.static_ast_v2 import AdmissionError, read_registered


@unittest.skipUnless(os.name == 'nt', 'Windows compatibility acceptance v1')
class WindowsCompatibilityV1(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='compat-v1-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base/'source'; self.source.mkdir()
        self.raw = b'x=1\n'
        self.file = self.source/'x.py'; self.file.write_bytes(self.raw)
        self.catalog = self.base/'catalog.json'
        self.catalog.write_bytes(p.canonical(dict(schema='pgop1.source-audit-catalog.v2',
            sources=[dict(path='x.py', sha256=p.digest(self.raw), kind='python')], claims=[])))
        self.output = self.base/'artifacts'

    def produce(self):
        return publish_audit_v1(self.source, self.catalog,
                                p.digest(self.catalog.read_bytes()), self.output)

    def test_blocked_writer_does_not_invent_source_changed(self):
        original = w.os.read
        denied = []
        def read(fd, size):
            try:
                self.file.write_bytes(b'x=2\n')
            except OSError as exc:
                denied.append(isinstance(exc, PermissionError))
            else:
                self.fail('writer unexpectedly succeeded')
            return original(fd, size)
        with patch.object(w.os, 'read', side_effect=read):
            self.assertEqual(read_registered(self.source, 'x.py', p.digest(self.raw)), self.raw)
        self.assertTrue(denied)
        self.assertTrue(all(denied), denied)
        self.assertEqual(self.file.read_bytes(), self.raw)

    def test_read_error_is_not_mutation(self):
        with patch.object(w.os, 'read', side_effect=OSError('injected read failure')):
            with self.assertRaisesRegex(AdmissionError, '^SOURCE_READ_FAILED$'):
                read_registered(self.source, 'x.py', p.digest(self.raw))
        self.assertEqual(self.file.read_bytes(), self.raw)

    def test_propagated_blocked_write_retains_historical_read_failure(self):
        denied = []
        def read(fd, size):
            try:
                self.file.write_bytes(b'x=2\n')
            except OSError as exc:
                denied.append(isinstance(exc, PermissionError))
                raise
            self.fail('writer unexpectedly succeeded')
        with patch.object(w.os, 'read', side_effect=read):
            with self.assertRaisesRegex(AdmissionError, '^SOURCE_READ_FAILED$'):
                read_registered(self.source, 'x.py', p.digest(self.raw))
        self.assertEqual(denied, [True])
        self.assertEqual(self.file.read_bytes(), self.raw)

    def test_effective_change_after_close_rejects_old_pin(self):
        captured = read_registered(self.source, 'x.py', p.digest(self.raw))
        self.file.write_bytes(b'x=2\n')
        self.assertNotEqual(self.file.read_bytes(), captured)
        self.assertEqual(captured, self.raw)
        with self.assertRaisesRegex(AdmissionError, '^SOURCE_HASH_MISMATCH$'):
            read_registered(self.source, 'x.py', p.digest(self.raw))
        self.assertEqual(read_registered(self.source, 'x.py', p.digest(b'x=2\n')), b'x=2\n')

    def test_versioned_migration_preserves_artifact_bytes(self):
        report, manifest = self.produce()
        expected, expected_manifest = p.artifact_bytes(report)
        self.assertEqual(manifest, expected_manifest)
        for name, raw in expected.items():
            self.assertEqual((self.output/name).read_bytes(), raw)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(publish_verification_v1(self.source, self.output, self.base/'verified.json'), 0)
        self.assertEqual(json.loads((self.base/'verified.json').read_bytes())['status'], 'PASS')
        with self.assertRaises(FileExistsError): self.produce()

    def test_migration_custody_blocks_root_and_output_parent_relocation(self):
        original = p.audit_catalog
        attempts = []
        def capture(*args, **kwargs):
            for path in (self.source, self.base):
                with self.assertRaises(OSError) as raised:
                    path.rename(path.with_name(path.name+'-moved'))
                attempts.append(raised.exception.winerror)
            return original(*args, **kwargs)
        with patch.object(p, 'audit_catalog', side_effect=capture): self.produce()
        self.assertEqual(len(attempts), 2)
        self.assertEqual(v.verify_report(self.source, v.read_artifacts(self.output)[0])['status'], 'PASS')

    def test_migration_does_not_enable_split_writers(self):
        report, _ = self.produce()
        with self.assertRaisesRegex(ValueError, 'WINDOWS_SPLIT_PUBLICATION_REQUIRES_TRANSACTION'):
            p.write_artifacts(self.source, self.base/'split', report)
        with self.assertRaisesRegex(ValueError, 'WINDOWS_SPLIT_PUBLICATION_REQUIRES_TRANSACTION'):
            v.write_verification(self.base/'split.json', self.source, '{"status":"PASS"}')
        self.assertFalse((self.base/'split').exists())
        self.assertFalse((self.base/'split.json').exists())

    def test_verification_migration_detects_changed_source(self):
        self.produce()
        self.file.write_bytes(b'x=2\n')
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(publish_verification_v1(self.source, self.output, self.base/'failed.json'), 1)
        self.assertEqual(json.loads((self.base/'failed.json').read_bytes())['status'], 'FAIL')
