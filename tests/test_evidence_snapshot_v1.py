"""Versioned historical capture tests; previous tests remain byte-identical."""
import argparse
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from tools import audit_snapshot_v1 as p, verify_snapshot_v1 as v


class SnapshotContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='snapshot-');self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.source=self.base/'source';self.source.mkdir()
        self.raw=b'N=7\ndef original():\n return N\n';(self.source/'x.py').write_bytes(self.raw)
        doc=b'N is seven.\n';(self.source/'DOC.md').write_bytes(doc)
        from candidate.document_claims_v1 import make_claim,typed
        source=dict(path='x.py',sha256=p.digest(self.raw))
        document=dict(path='DOC.md',sha256=p.digest(doc),start_line=1,end_line=1,span_sha256=p.digest(doc))
        claim=make_claim('constant_equal',document,source,dict(scope='<module>',name='N',definition_line=1),typed(7))
        catalog=dict(schema='pgop1.source-audit-catalog.v2',sources=[dict(path='DOC.md',sha256=p.digest(doc),kind='document'),dict(source,kind='python')],claims=[claim])
        self.catalog=self.base/'catalog.json';self.catalog.write_bytes(p.canonical(catalog));self.sha=p.digest(self.catalog.read_bytes())
        self.output=self.base/'artifacts'

    def produce(self,**kwargs):
        return p.snapshot_and_write(self.source,self.catalog,self.sha,self.output,**kwargs)

    def verify(self,**kwargs):
        return v.verify_bundle(self.output,self.sha,**kwargs)

    def args(self,**kwargs):
        return argparse.Namespace(artifacts=self.output,catalog_sha256=self.sha,source_root=self.source,
                                  output=kwargs.get('output'),mode=kwargs.get('mode','HISTORICAL_SNAPSHOT'))

    def mutate(self):
        q=subprocess.run([sys.executable,'-c',
            'import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(b"N=8\\ndef changed(): pass\\n")',
            str(self.source/'x.py')],capture_output=True)
        self.assertEqual(q.returncode,0,q.stderr);self.assertNotEqual((self.source/'x.py').read_bytes(),self.raw)

    def rehash(self,name,raw):
        (self.output/name).write_bytes(raw)
        manifest=json.loads((self.output/'MANIFEST.json').read_bytes())
        manifest['files'][name]=dict(bytes=len(raw),sha256=p.digest(raw))
        (self.output/'MANIFEST.json').write_bytes(p.canonical(manifest)+b'\n')

    def test_historical_bundle_verifies_without_original_source(self):
        ack=self.produce();self.assertTrue(ack['operation_completed'])
        (self.source/'x.py').unlink();(self.source/'DOC.md').unlink()
        result=self.verify();self.assertEqual(result['status'],'SNAPSHOT_VERIFIED')
        self.assertEqual(result['source_current_at_ack'],'NOT_PROVEN')
        self.assertEqual(result['derivation']['claims'][0]['verdict'],'SUPPORTED')

    def test_mutation_between_capture_and_analysis_uses_original_bytes(self):
        original=p.audit_catalog
        def analyze(*a,**kw):self.mutate();return original(*a,**kw)
        with patch.object(p,'audit_catalog',side_effect=analyze):self.produce()
        result=self.verify(source_root=self.source)
        self.assertEqual(result['status'],'SNAPSHOT_VERIFIED')
        self.assertEqual(result['source_observation']['files'][1]['status'],'MISMATCH')
        self.assertEqual(result['derivation']['claims'][0]['verdict'],'SUPPORTED')

    def test_after_verification_before_ack_is_never_current_pass(self):
        self.produce();original=v.verify_bundle
        def verified(*a,**kw):result=original(*a,**kw);self.mutate();return result
        out=io.StringIO()
        with patch.object(v,'verify_bundle',side_effect=verified),contextlib.redirect_stdout(out):
            self.assertEqual(v.execute(self.args(output=self.base/'verification.json')),0)
        result=json.loads(out.getvalue());self.assertEqual(result['source_current_at_ack'],'NOT_PROVEN')
        self.assertEqual(result['source_observation']['files'][1]['status'],'MATCH')
        self.assertEqual(self.verify(source_root=self.source)['source_observation']['files'][1]['status'],'MISMATCH')

    def test_post_ack_change_keeps_historical_validity(self):
        self.produce();before=self.verify();self.mutate();after=self.verify(source_root=self.source)
        self.assertEqual(before['snapshot_id'],after['snapshot_id'])
        self.assertEqual(after['status'],'SNAPSHOT_VERIFIED')
        self.assertEqual(after['source_current_at_ack'],'NOT_PROVEN')

    def test_current_at_ack_claim_rejected_without_output(self):
        with self.assertRaisesRegex(ValueError,'SOURCE_CURRENT_AT_ACK_NOT_PROVEN'):self.produce(mode='CURRENT_AT_ACK')
        self.assertFalse(self.output.exists());self.produce()
        dest=self.base/'verification.json'
        with contextlib.redirect_stdout(io.StringIO()):self.assertEqual(v.execute(self.args(mode='CURRENT_AT_ACK',output=dest)),1)
        self.assertFalse(dest.exists());self.assertEqual(self.verify()['status'],'SNAPSHOT_VERIFIED')

    def test_semantic_tamper_with_recalculated_manifest_rejected(self):
        self.produce();report=json.loads((self.output/'REPORT.json').read_bytes())
        report['document_claims']['claims'][0]['verdict']='CONTRADICTED'
        self.rehash('REPORT.json',p.canonical(report)+b'\n')
        with self.assertRaises(ValueError):self.verify()

    def test_coverage_tamper_with_rehashed_snapshot_ids_rejected(self):
        self.produce();report=json.loads((self.output/'REPORT.json').read_bytes());structure=report['structures'][0]
        structure['AST_COVERAGE']['observed_nodes']+=1
        structure['snapshot_id']=p.digest(p.canonical({k:x for k,x in structure.items() if k!='snapshot_id'}))
        self.rehash('REPORT.json',p.canonical(report)+b'\n')
        with self.assertRaises(ValueError):self.verify()

    def test_captured_bytes_tamper_even_with_manifest_rehash_rejected(self):
        self.produce();snapshot=json.loads((self.output/'SNAPSHOT.json').read_bytes())
        snapshot['captures'][1]['raw_hex']=b'N=8\ndef original():\n return N\n'.hex()
        self.rehash('SNAPSHOT.json',p.canonical(snapshot)+b'\n')
        with self.assertRaises(ValueError):self.verify()

    def test_temporal_handoff_forgery_rejected_after_rehash(self):
        self.produce();self.rehash('FINAL_HANDOFF.md',b'SOURCE_CURRENT_AT_ACK=PASS\n')
        with self.assertRaisesRegex(ValueError,'HANDOFF_SCOPE'):self.verify()

    def test_wrong_external_anchor_rejects(self):
        self.produce()
        with self.assertRaises(ValueError):v.verify_bundle(self.output,'0'*64)

    def test_capture_membership_and_scope_fail_closed(self):
        self.produce();report=json.loads((self.output/'REPORT.json').read_bytes());snapshot=json.loads((self.output/'SNAPSHOT.json').read_bytes())
        for label in ('missing','duplicate','currency','length_bool'):
            bad=copy.deepcopy(snapshot)
            if label=='missing':bad['captures'].pop()
            elif label=='duplicate':bad['captures'][1]=bad['captures'][0]
            elif label=='currency':bad['scope']['source_current_at_ack']='PASS'
            else:bad['captures'][1]['bytes']=True
            with self.subTest(label=label),self.assertRaises(ValueError):v.verify_values(report,bad,self.sha)

    def test_exclusive_output_retry_preserves_original(self):
        self.produce();before=(self.output/'MANIFEST.json').read_bytes()
        with self.assertRaises(FileExistsError):self.produce()
        self.assertEqual((self.output/'MANIFEST.json').read_bytes(),before)

    def test_source_hash_failure_does_not_publish(self):
        self.mutate()
        with self.assertRaisesRegex(ValueError,'SOURCE_HASH_MISMATCH'):self.produce()
        self.assertFalse(self.output.exists())

    def test_output_overlap_rejected(self):
        self.output=self.source/'artifacts'
        with self.assertRaises(ValueError):self.produce()
        self.assertFalse(self.output.exists())

    def test_capture_only_analysis_never_reads_path(self):
        from candidate.static_ast_v2 import analyze_captured
        with patch('candidate.static_ast_v2.read_registered',side_effect=AssertionError('source reopen')):
            report=analyze_captured(self.raw,'x.py',p.digest(self.raw))
        self.assertEqual(report['declarations'][0]['name'],'original')

    def test_snapshot_id_and_bytes_deterministic(self):
        first=self.produce();raw=(self.output/'SNAPSHOT.json').read_bytes();report=(self.output/'REPORT.json').read_bytes()
        self.output=self.base/'artifacts-two';second=self.produce()
        self.assertEqual(first['snapshot_id'],second['snapshot_id'])
        self.assertEqual(raw,(self.output/'SNAPSHOT.json').read_bytes())
        self.assertEqual(report,(self.output/'REPORT.json').read_bytes())

    @unittest.skipUnless(os.name=='nt','Windows native custody faults')
    def test_flush_and_close_failures_never_ack_success(self):
        from candidate import windows_safe_io_v2 as w
        with patch.object(w.os,'fsync',side_effect=OSError('injected flush')):
            with self.assertRaises(OSError):self.produce()
        self.assertFalse((self.output/'MANIFEST.json').exists())
        self.output=self.base/'close-failure';original=w.Directory.__exit__
        def close(obj,*args):original(obj,*args);raise OSError('injected close')
        with patch.object(w.Directory,'__exit__',close):
            with self.assertRaises(OSError):self.produce()

    def test_cancel_does_not_publish_and_releases_source(self):
        with patch.object(p,'audit_catalog',side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):self.produce()
        self.assertFalse(self.output.exists())
        self.source.rename(self.base/'released')


if __name__=='__main__':unittest.main()
