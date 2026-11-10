"""Typed claims against inert fixtures, with transparent positive/negative labels."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from runtime.candidate.document_claims_v1 import (CATALOG_SCHEMA, audit_catalog, canonical,
    claim_identity, document_span, evaluate_claims, make_claim, strict_json, typed,
    validate_catalog, validate_claim)
from runtime.candidate.static_ast_v2 import analyze_source, digest

ROOT = Path(__file__).absolute().parents[1]


class DocumentClaimTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='doc-claims-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)/'sources';self.root.mkdir()
        self.doc = b'Fixture claims below are explicit test proposals, not production promises.\nN is 10; verify is declared; function f is declared.\n'
        (self.root/'CLAIMS.md').write_bytes(self.doc)

    def fixture(self, body='N=10\nOPERATIONS=("verify", "read")\ndef f():\n pass\n'):
        raw = body.encode();(self.root/'x.py').write_bytes(raw)
        self.pin = {'path':'x.py','sha256':digest(raw)}
        self.document = {'path':'CLAIMS.md','sha256':digest(self.doc),'start_line':2,'end_line':2,
                         'span_sha256':digest(document_span(self.doc,2,2))}
        self.catalog = {'schema':CATALOG_SCHEMA,'sources':[
            {**self.pin,'kind':'python'},{'path':'CLAIMS.md','sha256':digest(self.doc),'kind':'document'}], 'claims':[]}
        return raw

    def claim(self,predicate,params,expected):
        c = make_claim(predicate,self.document,self.pin,params,typed(expected))
        self.catalog['claims'].append(c)
        return c

    def run_claims(self,**kwargs):
        results = evaluate_claims(self.root,self.catalog,**kwargs)['claims']
        return {r['claim']['claim_id']:r for r in results}

    def test_two_positive_two_negative_closed_claims(self):
        self.fixture()
        good = self.claim('constant_equal',{'scope':'<module>','name':'N','definition_line':1},10)
        operation = self.claim('public_operation_declared',{'scope':'<module>','name':'OPERATIONS','definition_line':2,'operation':'verify'},True)
        wrong = self.claim('constant_equal',{'scope':'<module>','name':'N','definition_line':1},11)
        absent = self.claim('symbol_defined',{'scope':'<module>','name':'missing'},True)
        negative = self.claim('symbol_defined',{'scope':'<module>','name':'missing'},False)
        rows = self.run_claims()
        for c in (good,operation,negative):self.assertEqual(rows[c['claim_id']]['verdict'],'SUPPORTED')
        for c in (wrong,absent):self.assertEqual(rows[c['claim_id']]['verdict'],'CONTRADICTED')
        self.assertNotIn('literal',json.dumps(rows))
        self.assertIn('NO_OPERATION_EXECUTION',rows[operation['claim_id']]['reason'])

    def test_nonliteral_redefined_conditional_and_dynamic_abstain(self):
        for body in ('N=[10]\n','N=10\nN=11\n','if True:\n N=10\n','N=10\nexec("N=20")\n','N=10\ndef f():\n global N\n N=12\n'):
            with self.subTest(body_sha=digest(body.encode())):
                self.fixture(body)
                c = self.claim('constant_equal',{'scope':'<module>','name':'N','definition_line':1},10)
                self.assertEqual(self.run_claims()[c['claim_id']]['verdict'],'INSUFFICIENT_EVIDENCE')

    def test_source_and_document_alteration_abstain(self):
        raw = self.fixture();c = self.claim('symbol_defined',{'scope':'<module>','name':'f'},True)
        (self.root/'x.py').write_bytes(raw+b'# changed\n')
        self.assertEqual(self.run_claims()[c['claim_id']]['verdict'],'INSUFFICIENT_EVIDENCE')
        (self.root/'x.py').write_bytes(raw)
        (self.root/'CLAIMS.md').write_bytes(self.doc+b'changed\n')
        self.assertEqual(self.run_claims()[c['claim_id']]['verdict'],'INSUFFICIENT_EVIDENCE')

    def test_exact_document_span_boundaries_and_hash(self):
        self.fixture();c = self.claim('symbol_defined',{'scope':'<module>','name':'f'},True)
        c['document']['span_sha256'] = '0'*64;c['claim_id'] = claim_identity(c)
        self.assertEqual(self.run_claims()[c['claim_id']]['reason'],'DOCUMENT_SPAN_NOT_VERIFIED')
        c['document']['end_line'] = 900;c['claim_id'] = claim_identity(c)
        self.assertEqual(self.run_claims()[c['claim_id']]['verdict'],'INSUFFICIENT_EVIDENCE')

    def test_ambiguous_repeated_scope_and_exact_identity(self):
        raw = self.fixture('class A:\n def m(self):\n  pass\nclass A:\n def n(self):\n  pass\n')
        ambiguous = self.claim('symbol_defined',{'scope':'A','name':'m'},True)
        report = analyze_source(self.root,'x.py',digest(raw))
        first = next(u['id'] for u in report['units'] if u['qualified_name']=='A')
        exact = self.claim('symbol_defined',{'scope':first,'name':'m'},True)
        rows = self.run_claims()
        self.assertEqual(rows[ambiguous['claim_id']]['verdict'],'INSUFFICIENT_EVIDENCE')
        self.assertEqual(rows[exact['claim_id']]['verdict'],'SUPPORTED')

    def test_conditional_ancestor_constant_abstains(self):
        self.fixture('if True:\n class A:\n  N=10\n')
        c = self.claim('constant_equal',{'scope':'A','name':'N','definition_line':3},10)
        self.assertEqual(self.run_claims()[c['claim_id']]['verdict'],'INSUFFICIENT_EVIDENCE')

    def test_partial_or_unknown_never_support_absence(self):
        self.fixture('def big():\n'+' x=1\n'*20+'def small():\n pass\n')
        c = self.claim('symbol_defined',{'scope':'<module>','name':'missing'},False)
        for budget in ({'unit_nodes':10},{'nodes':3}):
            rows = self.run_claims(budgets=budget)
            self.assertEqual(rows[c['claim_id']]['verdict'],'INSUFFICIENT_EVIDENCE')

    def test_bool_int_typed_and_stale_without_temporal_anchor(self):
        self.fixture();c = self.claim('constant_equal',{'scope':'<module>','name':'N','definition_line':1},True)
        row = self.run_claims()[c['claim_id']]
        self.assertEqual(row['verdict'],'CONTRADICTED')
        self.assertNotEqual(row['verdict'],'STALE')
        bad = copy.deepcopy(c);bad['expected']['type']='int';bad['claim_id']=claim_identity(bad)
        with self.assertRaises(ValueError):validate_claim(bad)
        bad = copy.deepcopy(c);bad['temporal_note']='old';bad['claim_id']=claim_identity(bad)
        with self.assertRaises(ValueError):validate_claim(bad)

    def test_file_exists_is_pinned_presence_only(self):
        self.fixture()
        yes = self.claim('declared_file_exists',{},True)
        no = self.claim('declared_file_exists',{},False)
        rows = self.run_claims()
        self.assertEqual(rows[yes['claim_id']]['verdict'],'SUPPORTED')
        self.assertEqual(rows[no['claim_id']]['verdict'],'CONTRADICTED')
        (self.root/'x.py').unlink()
        self.assertEqual(self.run_claims()[no['claim_id']]['verdict'],'INSUFFICIENT_EVIDENCE')

    def test_registry_mutable_and_wrong_definition_line_abstain(self):
        for body,line in [('OPERATIONS=["verify"]\n',1),('OPERATIONS=("verify",)\n',2)]:
            self.fixture(body)
            c = self.claim('public_operation_declared',{'scope':'<module>','name':'OPERATIONS','definition_line':line,'operation':'verify'},True)
            self.assertEqual(self.run_claims()[c['claim_id']]['verdict'],'INSUFFICIENT_EVIDENCE')

    def test_identifier_queries_require_cpython_nfkc_spelling(self):
        for spelling,canonical_name in [('K','K'),('ｆ','f')]:
            with self.subTest(spelling=spelling):
                self.fixture('def '+spelling+'():\n pass\n')
                c = self.claim('symbol_defined',{'scope':'<module>','name':canonical_name},True)
                self.assertEqual(self.run_claims()[c['claim_id']]['verdict'],'SUPPORTED')
                for expected in (True,False):
                    with self.assertRaisesRegex(ValueError,'NONCANONICAL_IDENTIFIER'):
                        self.claim('symbol_defined',{'scope':'<module>','name':spelling},expected)
                self.fixture('class '+spelling+':\n def m(self):\n  pass\n')
                c = self.claim('symbol_defined',{'scope':canonical_name,'name':'m'},True)
                self.assertEqual(self.run_claims()[c['claim_id']]['verdict'],'SUPPORTED')
                with self.assertRaisesRegex(ValueError,'NONCANONICAL_IDENTIFIER'):
                    self.claim('symbol_defined',{'scope':spelling,'name':'missing'},False)

    def test_exact_scope_id_with_redacted_unicode_ancestor(self):
        raw = self.fixture('class a\u0332:\n class B:\n  N=10\n')
        report = analyze_source(self.root,'x.py',digest(raw))
        scope = next(u for u in report['units'] if u['name']=='B')
        self.assertEqual(scope['scope_chain'][0]['name'],'WITHHELD')
        c = self.claim('constant_equal',{'scope':scope['id'],'name':'N','definition_line':3},10)
        self.assertEqual(self.run_claims()[c['claim_id']]['verdict'],'SUPPORTED')

    def test_redacted_name_sentinel_never_becomes_a_symbol(self):
        self.fixture('def '+('a'*121)+'():\n pass\n')
        c = self.claim('symbol_defined',{'scope':'<module>','name':'WITHHELD'},True)
        row = self.run_claims()[c['claim_id']]
        self.assertEqual(row['verdict'],'INSUFFICIENT_EVIDENCE')
        self.assertEqual(row['reason'],'REDACTED_IDENTIFIER_QUERY')

    def test_contracts_reject_unregistered_sources_duplicate_keys_and_identity(self):
        self.fixture();c = self.claim('symbol_defined',{'scope':'<module>','name':'f'},True)
        bad = copy.deepcopy(self.catalog);bad['sources'].pop()
        with self.assertRaises(ValueError):validate_catalog(bad)
        bad = copy.deepcopy(c);bad['expected']=typed(False)
        with self.assertRaises(ValueError):validate_claim(bad)
        with self.assertRaises(ValueError):strict_json(b'{"a":1,"a":2}')
        with self.assertRaises(ValueError):strict_json(b'{"a":NaN}')

    def test_reordering_catalog_is_semantically_identical(self):
        self.fixture();self.claim('symbol_defined',{'scope':'<module>','name':'f'},True)
        self.claim('constant_equal',{'scope':'<module>','name':'N','definition_line':1},10)
        first = audit_catalog(self.root,self.catalog)
        reversed_catalog = copy.deepcopy(self.catalog)
        reversed_catalog['sources'].reverse();reversed_catalog['claims'].reverse()
        second = audit_catalog(self.root,reversed_catalog)
        self.assertEqual(canonical(first),canonical(second))

    def test_claim_worker_timeout_abstains_without_echo(self):
        raw = self.fixture('N=10\n')
        c = self.claim('constant_equal',{'scope':'<module>','name':'N','definition_line':1},10)
        from runtime.candidate.document_claims_v1 import inspect_literal
        report = analyze_source(self.root,'x.py',digest(raw))
        scope_id = next(u['id'] for u in report['units'] if u['node']=='Module')
        with patch('runtime.candidate.document_claims_v1.subprocess.run',side_effect=subprocess.TimeoutExpired('worker',6)):
            info = inspect_literal(raw,'x.py',digest(raw),scope_id,'N',1)
        with patch('runtime.candidate.document_claims_v1.inspect_literal',return_value=info):
            row = self.run_claims()[c['claim_id']]
        self.assertEqual(row['verdict'],'INSUFFICIENT_EVIDENCE')
        self.assertEqual(row['reason'],'CLAIM_WORKER_RESOURCE_ERROR')

    def test_cli_manifest_repeat_output_and_unsafe_output(self):
        self.fixture();self.claim('symbol_defined',{'scope':'<module>','name':'f'},True)
        catalog_path = Path(self.tmp.name)/'CATALOG.json';body=canonical(self.catalog)+b'\n';catalog_path.write_bytes(body)
        output = Path(self.tmp.name)/'output'
        command = [sys.executable,str(ROOT/'tools/audit_source_v2.py'),'--source-root',str(self.root),
                   '--catalog',str(catalog_path),'--catalog-sha256',digest(body),'--output',str(output)]
        p = subprocess.run(command,capture_output=True,timeout=30)
        self.assertEqual(p.returncode,0,p.stdout)
        manifest = json.loads((output/'MANIFEST.json').read_bytes())
        for name,pin in manifest['files'].items():
            body = (output/name).read_bytes();self.assertEqual(pin,{'bytes':len(body),'sha256':digest(body)})
        p = subprocess.run(command,capture_output=True,timeout=30)
        self.assertEqual(p.returncode,2);self.assertNotIn(b'Traceback',p.stderr)
        command[-1]=str(self.root/'output')
        p = subprocess.run(command,capture_output=True,timeout=30)
        self.assertEqual(p.returncode,2);self.assertFalse((self.root/'output').exists())


if __name__ == '__main__':
    unittest.main()
