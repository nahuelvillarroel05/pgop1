"""Whole-operation Windows custody regressions. Original tests remain immutable."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from tools import audit_source_v2 as p, verify_source_v2 as v
from candidate import windows_safe_io_v2 as w


@unittest.skipUnless(os.name == 'nt', 'Windows custody contract')
class CustodyConvergenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='custody-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base/'source'; self.source.mkdir()
        self.raw = b'def admitted():\n return 1\n'
        (self.source/'x.py').write_bytes(self.raw)
        self.catalog = self.base/'catalog.json'
        self.catalog.write_bytes(p.canonical({'schema':'pgop1.source-audit-catalog.v2',
            'sources':[{'path':'x.py','sha256':hashlib.sha256(self.raw).hexdigest(),'kind':'python'}], 'claims':[]}))
        self.sha = hashlib.sha256(self.catalog.read_bytes()).hexdigest()
        self.output_parent = self.base/'output'; self.output_parent.mkdir()
        self.output = self.output_parent/'artifacts'

    def produce(self):
        return p.audit_and_write(self.source, self.catalog, self.sha, self.output)

    def test_original_split_attack_refuses_even_identical_replacement(self):
        report = p.audit_catalog(self.source, json.loads(self.catalog.read_bytes()))
        moved = self.output_parent/'original'; self.source.rename(moved)
        self.source.mkdir(); (self.source/'x.py').write_bytes(self.raw)
        for captured in (report, json.loads(json.dumps(report))):
            with self.assertRaisesRegex(ValueError, 'WINDOWS_SPLIT_PUBLICATION_REQUIRES_TRANSACTION'):
                p.write_artifacts(self.source, moved/'artifacts', captured)
        self.assertFalse((moved/'artifacts').exists())
        self.assertEqual((moved/'x.py').read_bytes(), self.raw)

    def test_split_verification_body_has_no_publication_authority(self):
        with self.assertRaisesRegex(ValueError, 'WINDOWS_SPLIT_PUBLICATION_REQUIRES_TRANSACTION'):
            v.write_verification(self.output_parent/'verification.json', self.source, '{"status":"PASS"}')
        self.assertEqual(list(self.output_parent.iterdir()), [])

    def test_capture_boundary_pins_source_output_parent_and_ancestors(self):
        original = p.audit_catalog
        def capture(*args, **kwargs):
            for path in (self.source, self.output_parent, self.base):
                with self.assertRaises(OSError): path.rename(path.with_name(path.name+'-moved'))
            return original(*args, **kwargs)
        with patch.object(p, 'audit_catalog', side_effect=capture): self.produce()
        self.assertEqual(v.verify_report(self.source, v.read_artifacts(self.output)[0])['status'], 'PASS')

    def test_verify_boundary_pins_all_inputs_and_output_parent(self):
        self.produce()
        dest = self.base/'verification'; dest.mkdir()
        args = argparse.Namespace(source_root=self.source,artifacts=self.output,report=None,pages=None,output=dest/'result.json')
        original = v.verify_report
        def verify(*a, **kw):
            for path in (self.source,self.output,dest):
                with self.assertRaises(OSError): path.rename(path.with_name(path.name+'-moved'))
            return original(*a, **kw)
        with patch.object(v,'verify_report',side_effect=verify): self.assertEqual(v.execute(args),0)
        self.assertEqual(json.loads(args.output.read_bytes())['status'],'PASS')

    def test_capture_error_closes_custody_without_output(self):
        with patch.object(p, 'audit_catalog', side_effect=RuntimeError('cancelled')):
            with self.assertRaisesRegex(RuntimeError,'cancelled'): self.produce()
        self.assertFalse(self.output.exists())
        self.source.rename(self.base/'released-source')
        self.output_parent.rename(self.base/'released-output')

    def test_fsync_error_never_returns_success_and_does_not_retry(self):
        with patch.object(w.os,'fsync',side_effect=OSError('injected flush')):
            with self.assertRaisesRegex(OSError,'injected flush'): self.produce()
        self.assertFalse((self.output/'MANIFEST.json').exists())
        with self.assertRaises(FileExistsError): self.produce()

    def test_report_perturbation_after_capture_fails_before_manifest(self):
        original = p.audit_catalog
        def capture(*a, **kw):
            result=original(*a, **kw); result['document_claims']=None; return result
        with patch.object(p,'audit_catalog',side_effect=capture):
            with self.assertRaises(TypeError): self.produce()
        self.assertFalse(self.output.exists())

    def test_independent_operations_concurrent_single_destination_exclusive(self):
        barrier=threading.Barrier(2); original=p.audit_catalog; outcomes=[]
        def capture(*a, **kw):
            result=original(*a, **kw); barrier.wait(20); return result
        def actor():
            try:self.produce();outcomes.append('SUCCESS')
            except (ValueError,OSError):outcomes.append('REJECTED')
        with patch.object(p,'audit_catalog',side_effect=capture):
            workers=[threading.Thread(target=actor) for _ in range(2)]
            for t in workers:t.start()
            for t in workers:t.join(30)
            self.assertFalse(any(t.is_alive() for t in workers))
        self.assertEqual(sorted(outcomes),['REJECTED','SUCCESS'])

    def test_native_read_injection_preserves_failed_mutation_semantics(self):
        original=w.os.read; attempts=[]
        def read(fd,n):
            try:(self.source/'x.py').write_bytes(b'changed')
            except OSError as exc:attempts.append(getattr(exc,'winerror',None));raise
            return original(fd,n)
        with patch.object(w.os,'read',side_effect=read):
            with self.assertRaisesRegex(w.SafeIOError,'SOURCE_READ_FAILED'):
                w.safe_read(self.source,'x.py',hashlib.sha256(self.raw).hexdigest(),262144)
        self.assertTrue(attempts)
        self.assertEqual((self.source/'x.py').read_bytes(),self.raw)

    def test_successful_later_byte_change_is_hash_mismatch(self):
        self.produce(); (self.source/'x.py').write_bytes(b'def other(): pass\n')
        with self.assertRaises(ValueError): v.verify_report(self.source,v.read_artifacts(self.output)[0])

    def test_existing_output_rejects_without_overwrite(self):
        self.produce(); before=(self.output/'REPORT.json').read_bytes()
        with self.assertRaises(FileExistsError):self.produce()
        self.assertEqual((self.output/'REPORT.json').read_bytes(),before)

    def test_output_inside_source_refuses_before_capture(self):
        self.output=self.source/'artifacts'
        with patch.object(p,'audit_catalog',side_effect=AssertionError('must not capture')):
            with self.assertRaisesRegex(ValueError,'OVERLAPS'):self.produce()
        self.assertFalse(self.output.exists())
