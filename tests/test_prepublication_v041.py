"""Prospective synthetic controls; no examined module is imported or executed."""
import json,os,subprocess,sys,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'runtime'),str(ROOT/'tests')]
from candidate.evidence_handoff import static_properties,profile_service,EvidenceProfile
from candidate.public_handoff import PublicError,encoded,sha
import test_real_handoff_v04 as real_fixture
from types import SimpleNamespace

class ConsolidationTests(unittest.TestCase):
    def case(self):return real_fixture.RealTests().setup_case()
    def generated(self):
        b,c,api=self.case();v=api.verify('CONTROL');g=api.generate('CONTROL',v['receipt_id'],'shared-key')
        return b,c,api,v,g
    def rejected(self,fn,code):
        with self.assertRaises(PublicError) as e:fn()
        self.assertEqual(e.exception.code,code)
    def test_module_declarations_and_duplicates(self):
        raw=b'class A: pass\nasync def af(): pass\ndef _f():\n class Nested: pass\nclass A: pass\n'
        r=static_properties(raw,'python',[],inventory=True)
        self.assertEqual(r['AST_COVERAGE']['status'],'COMPLETE')
        self.assertEqual([x['name'] for x in r['DECLARATION_INVENTORY']['items']],['A','af','_f','A'])
        self.assertEqual([x['node'] for x in r['DECLARATION_INVENTORY']['items']],['ClassDef','AsyncFunctionDef','FunctionDef','ClassDef'])
        self.assertEqual(r['DECLARATION_INVENTORY']['source_sha256'],sha(raw))
    def test_large_tree_has_no_definitive_claim(self):
        c={'kind':'symbol_exists','name':'Ghost','present':False}
        r=static_properties(b'x=1\n'*4000,'python',[c],inventory=True)
        self.assertEqual(r['PYTHON_SYNTAX'],'UNKNOWN');self.assertEqual(r['STATIC_CLAIMS'],[])
        self.assertEqual(r['AST_COVERAGE']['observed_nodes'],12000)
        self.assertIsNone(r['AST_COVERAGE']['total_nodes'])
        self.assertEqual(r['DECLARATION_INVENTORY']['items'],[])
    def test_inventory_truncation_is_explicit(self):
        r=static_properties(b'class A: pass\n'*260,'python',[],inventory=True)['DECLARATION_INVENTORY']
        self.assertEqual((r['status'],r['observed'],r['skipped']),('TRUNCATED',256,4))
    def test_invalid_syntax_and_inert_literals(self):
        r=static_properties(b'def bad(:','python',[],inventory=True)
        self.assertEqual(r['DECLARATION_INVENTORY']['status'],'PARSE_FAILED')
        r=static_properties(b'"class Ghost: pass"\n# class Ghost: pass\n__import__("missing")\nraise RuntimeError\n','python',[],inventory=True)
        self.assertEqual(r['PYTHON_SYNTAX'],'PASS');self.assertEqual(r['DECLARATION_INVENTORY']['items'],[])
    def test_size_and_timeout_are_unknown(self):
        r=static_properties(b'x'*262145,'python',[],inventory=True)
        self.assertEqual(r['disposition'],'SIZE_LIMIT');self.assertEqual(r['STATIC_CLAIMS'],[])
        with patch('candidate.evidence_handoff.subprocess.run',side_effect=subprocess.TimeoutExpired('worker',6)):
            r=static_properties(b'x=1','python',[],inventory=True)
        self.assertEqual(r['AST_COVERAGE']['status'],'PARSER_RESOURCE_ERROR')
    def test_parser_resource_error_is_not_syntax_failure(self):
        from candidate.evidence_handoff import _static_properties
        with patch('candidate.evidence_handoff.ast.parse',side_effect=MemoryError):
            r=_static_properties(b'x=1','python',[],inventory=True)
        self.assertEqual(r['PYTHON_SYNTAX'],'UNKNOWN')
    def test_source_changed_during_handle_read(self):
        from candidate.evidence_handoff import safe_read
        b,c,a=self.case();p=b/'source/module.py';original=os.fstat
        def measured(fd):
            first=original(fd)
            later=SimpleNamespace(**{k:getattr(first,k) for k in ['st_ino','st_dev','st_size','st_mtime_ns','st_ctime_ns']})
            later.st_mtime_ns+=1
            return first,later
        # Capture a real handle's stat, then supply a changed post-read signature.
        with p.open('rb') as h:first,later=measured(h.fileno())
        with patch('candidate.evidence_handoff.os.fstat',side_effect=[first,later]):
            self.rejected(lambda:safe_read(p),'SOURCE_CHANGED')
    def test_scoped_ref_and_idempotence(self):
        b,c,a,v,g=self.generated()
        self.assertEqual(g,a.generate('CONTROL',v['receipt_id'],'shared-key'))
        self.assertEqual(g,a.completed(g['report_id']))
        self.assertEqual(g['qualified_report_ref']['report_id'],g['report_id'])
        self.assertNotIn(str(b),json.dumps(g))
    def test_distinct_stores_same_id_own_bytes(self):
        b,c,a,v,g=self.generated();other=profile_service(b/'config',b/'other-store')
        h=other.generate('CONTROL',other.verify('CONTROL')['receipt_id'],'shared-key')
        self.assertEqual(g['report_id'],h['report_id'])
        self.assertNotEqual(g['report_scope']['store_namespace'],h['report_scope']['store_namespace'])
        self.assertNotEqual(a.read(g['report_id'])['sha256'],other.read(h['report_id'])['sha256'])
    def test_foreign_catalog_read_fails(self):
        b,c,a,v,g=self.generated();c['packages']['CONTROL']['run_id']='OTHER'
        cfg=b/'other-config';cfg.mkdir();(cfg/'CATALOG.json').write_bytes(encoded(c))
        other=profile_service(cfg,a.out)
        self.rejected(lambda:other.read(g['report_id']),'REPORT_SCOPE_MISMATCH')
    def test_legacy_reader_cannot_read_new_real_report(self):
        b,c,a,v,g=self.generated()
        # Exercise the inherited legacy completed implementation on the same store.
        legacy=object.__new__(EvidenceProfile);legacy.out=a.out
        self.rejected(lambda:legacy.read(g['report_id']),'REPORT_SCOPE_MISMATCH')
    def test_tampered_request_rejected(self):
        b,c,a,v,g=self.generated();p=a.out/g['report_id']/'REQUEST.json';d=json.loads(p.read_bytes());d['receipt_id']='0'*64;p.write_bytes(encoded(d))
        self.rejected(lambda:a.read(g['report_id']),'REPORT_SCOPE_MISMATCH')
    def test_incomplete_retry_retained(self):
        b,c,a=self.case();v=a.verify('CONTROL');rid='report-'+sha(b'interrupted')[:40]
        folder=a.out/rid;folder.mkdir(parents=True)
        self.rejected(lambda:a.generate('CONTROL',v['receipt_id'],'interrupted'),'ATTEMPT_IN_PROGRESS_OR_INTERRUPTED')
        self.assertTrue(folder.exists())
    def test_traversal_read_rejected(self):
        b,c,a,v,g=self.generated()
        with self.assertRaises(PublicError):a.read('../outside')
    def test_new_store_cannot_resolve_foreign_id(self):
        b,c,a,v,g=self.generated();other=profile_service(b/'config',b/'empty-store')
        self.rejected(lambda:other.read(g['report_id']),'ATTEMPT_IN_PROGRESS_OR_INTERRUPTED')

if __name__=='__main__':unittest.main()
