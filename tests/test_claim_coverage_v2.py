"""New opt-in contract tests; original regression methods remain unchanged."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from candidate.claim_contract_v2 import make_claim, validate_claim
from candidate.claim_coverage_v2 import ClaimCoverageProfile, check_catalog, derive
from candidate.static_ast_v2 import canonical, digest
from tools.verify_claim_coverage_v2 import verify_bundle

ROOT = Path(__file__).absolute().parents[1]


@unittest.skipUnless(os.name == 'nt', 'Windows-only contract')
class CoverageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='claim-coverage-test-'); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name); self.source = self.root/'source'; self.source.mkdir()
        self.config = self.root/'config'; self.config.mkdir(); self.output = self.root/'output'
        self.code = b'import os as operating\nfrom .abc import Thing as T\nclass A:\n @decorator\n def same(self, x, /, y=1, *args, z=2, **kw):\n  def nested(hidden): pass\nclass B:\n async def same(self): pass\n'
        self.doc = b'Typed fixture declaration.\n'
        self.prepare()

    def prepare(self):
        (self.source/'x.py').write_bytes(self.code); (self.source/'DOC.md').write_bytes(self.doc)
        self.document = dict(path='DOC.md', sha256=digest(self.doc), start_line=1, end_line=1, span_sha256=digest(self.doc))
        self.pin = dict(path='x.py', sha256=digest(self.code))
        pins = [dict(path='DOC.md', sha256=digest(self.doc), kind='document'), dict(self.pin, kind='python')]
        self.catalog = dict(schema='pgop1.claim-coverage-catalog.v1', claims=[], base=dict(
            schema='pgop1.real-static-catalog.v2', profile='real-static-v2',
            catalog=dict(schema='pgop1.source-audit-catalog.v2', sources=pins, claims=[]),
            sources=[dict(path=p['path'], sha256=p['sha256'], bytes=len(self.doc if p['kind']=='document' else self.code),
                          version='synthetic-1', language='markdown' if p['kind']=='document' else 'python', scope='REGISTERED_FILE_ONLY') for p in pins]))

    def claim(self, family, **params):
        return make_claim(family, self.document, self.pin, params)

    def save(self, claims):
        self.catalog['claims'] = sorted(claims, key=lambda c:c['claim_id'])
        self.path = self.config/'catalog.json'; raw = canonical(self.catalog); self.path.write_bytes(raw)
        self.sha = digest(raw)
        self.profile = ClaimCoverageProfile(source_root=self.source, catalog_path=self.path, catalog_sha256=self.sha)

    def run_claims(self, claims):
        self.save(claims); self.profile.generate(self.output)
        return verify_bundle(self.output, self.sha)[0]['claims']

    def import_claim(self, **overrides):
        params = dict(scope='<module>', form='import', module='', name='os', asname='operating', level=0)
        params.update(overrides); return self.claim('module_import_declared', **params)

    def rehash(self, name, data):
        raw = canonical(data); (self.output/name).write_bytes(raw)
        manifest = json.loads((self.output/'MANIFEST.json').read_bytes())
        manifest['files'][name] = dict(bytes=len(raw), sha256=digest(raw))
        (self.output/'MANIFEST.json').write_bytes(canonical(manifest))

    def test_three_families_positive(self):
        claims = [self.claim('class_method_declared', scope='A', name='same'), self.import_claim(),
                  self.claim('function_parameter_declared', scope='A.same', name='z', kind='kwonly')]
        rows = self.run_claims(claims)
        self.assertEqual([r['verdict'] for r in rows], ['SUPPORTED']*3)
        self.assertTrue(all(r['evidence'][0]['node_id'].startswith('fact-') for r in rows))

    def test_absence_only_exact_direct_syntax(self):
        rows = self.run_claims([self.claim('class_method_declared', scope='B', name='nested'),
                               self.claim('class_method_declared', scope='A', name='nested'),
                               self.import_claim(asname=None),
                               self.claim('function_parameter_declared', scope='A.same', name='hidden', kind='positional')])
        self.assertEqual([r['verdict'] for r in rows], ['CONTRADICTED']*4)

    def test_missing_and_wrong_scope_abstain(self):
        rows = self.run_claims([self.claim('class_method_declared', scope='missing', name='same'),
                               self.claim('class_method_declared', scope='A.same', name='nested'),
                               self.claim('function_parameter_declared', scope='A', name='x', kind='positional')])
        self.assertEqual([r['verdict'] for r in rows], ['INSUFFICIENT_EVIDENCE']*3)

    def test_redefinitions_qualified_abstain_node_id_selects(self):
        self.code += b'class A:\n def other(self): pass\n'; self.prepare()
        self.save([self.claim('class_method_declared', scope='A', name='same')]); self.profile.generate(self.output)
        envelope = verify_bundle(self.output, self.sha)[0]
        self.assertEqual(envelope['claims'][0]['verdict'], 'INSUFFICIENT_EVIDENCE')
        unit = next(u for u in envelope['structures'][0]['units'] if u['node']=='ClassDef' and u['line']==3)
        result = derive(self.catalog | {'claims':[self.claim('class_method_declared', scope=unit['id'], name='same')]},
                        envelope, json.loads((self.output/'SNAPSHOT.json').read_bytes()))
        self.assertEqual(result['claims'][0]['verdict'], 'SUPPORTED')

    def test_all_parameter_kinds(self):
        rows = self.run_claims([self.claim('function_parameter_declared', scope='A.same', name=name, kind=kind)
                               for name,kind in [('x','posonly'),('y','positional'),('args','vararg'),('z','kwonly'),('kw','kwarg')]])
        self.assertEqual([r['verdict'] for r in rows], ['SUPPORTED']*5)

    def test_relative_import_exact_level_alias(self):
        rows = self.run_claims([self.import_claim(form='from', module='abc', name='Thing', asname='T', level=1),
                               self.import_claim(form='from', module='abc', name='Thing', asname='T', level=0)])
        self.assertEqual(sorted(r['verdict'] for r in rows), ['CONTRADICTED','SUPPORTED'])

    def test_star_and_dynamic_import_do_not_prove_members(self):
        self.code = b'from pkg import *\nx=__import__("os")\n'; self.prepare()
        rows = self.run_claims([self.import_claim(name='os', asname=None), self.import_claim(form='from', module='pkg', name='Thing', asname=None)])
        self.assertEqual([r['verdict'] for r in rows], ['CONTRADICTED']*2)

    def test_partial_budget_abstains(self):
        self.code += b'x=1\n'*3200; self.prepare()
        rows = self.run_claims([self.import_claim()])
        self.assertEqual(rows[0]['verdict'], 'INSUFFICIENT_EVIDENCE')

    def test_span_forgery_abstains(self):
        claim = self.import_claim(); claim['document']['span_sha256']='0'*64
        from candidate.document_claims_v1 import claim_identity
        claim['claim_id']=claim_identity(claim)
        rows = self.run_claims([claim]); self.assertEqual(rows[0]['reason'], 'DOCUMENT_SPAN_NOT_VERIFIED')

    def test_strict_types_unicode_and_scope_admission(self):
        from candidate.document_claims_v1 import claim_identity
        for field, value in [('expected', {'type':'bool','value':1}), ('parameters',dict(scope='<module>',form='import',module='',name='os',asname=None,level=True))]:
            claim=self.import_claim(); claim[field]=value; claim['claim_id']=claim_identity(claim)
            with self.assertRaises(ValueError): validate_claim(claim)
        with self.assertRaises(ValueError): self.claim('class_method_declared',scope='A',name='\u212a')

    def test_manifest_and_rehashed_fact_tampering_rejected(self):
        self.run_claims([self.import_claim()]); data=json.loads((self.output/'COVERAGE.json').read_bytes())
        data['claims'][0]['evidence'][0]['column']+=1
        self.rehash('COVERAGE.json',data)
        with self.assertRaisesRegex(ValueError,'COVERAGE_DERIVATION'): verify_bundle(self.output,self.sha)

    def test_catalog_external_anchor_and_duplicate_rejected(self):
        claim=self.import_claim(); self.save([claim,claim])
        with self.assertRaises(ValueError): check_catalog(self.catalog,self.sha)
        self.save([claim])
        with self.assertRaises(ValueError): check_catalog(self.catalog,'0'*64)

    def test_restart_pagination_and_captured_bytes_only(self):
        claims=[self.claim('function_parameter_declared',scope='A.same',name=n,kind=k)
                for n,k in [('x','posonly'),('y','positional'),('z','kwonly')]]
        self.run_claims(claims); (self.source/'x.py').unlink(); (self.source/'DOC.md').unlink()
        rows=[]; offset=0
        while True:
            page=self.profile.query(self.output,offset=offset,limit=1); rows+=page['items']
            if page['next_offset'] is None: break
            offset=page['next_offset']
        self.assertEqual([r['claim'] for r in rows],sorted(claims,key=lambda c:c['claim_id']))
        command=[sys.executable,str(ROOT/'tools/claim_coverage_v2.py'),'--catalog-sha256',self.sha,'verify','--artifacts',str(self.output)]
        result=subprocess.run(command,cwd=ROOT,capture_output=True)
        self.assertEqual(result.returncode,0,result.stdout+result.stderr)

    def test_output_collision_hardlinks_and_unsafe_paths(self):
        self.run_claims([self.import_claim()])
        with self.assertRaises(OSError): self.profile.generate(self.output)
        os.link(self.output/'COVERAGE.json',self.root/'hardlink')
        with self.assertRaises(ValueError): verify_bundle(self.output,self.sha)
        with self.assertRaises(ValueError): self.profile.generate(str(self.root)+'\\..\\escape')

    def test_two_processes_same_semantic_identity(self):
        self.save([self.import_claim()]); command=[sys.executable,str(ROOT/'tools/claim_coverage_v2.py'),'--catalog-sha256',self.sha,'generate','--source-root',str(self.source),'--catalog',str(self.path)]
        results=[]
        for i in range(2):
            out=self.root/f'process-{i}'
            result=subprocess.run(command+['--output',str(out)],cwd=ROOT,capture_output=True)
            self.assertEqual(result.returncode,0,result.stdout+result.stderr)
            results.append((out/'COVERAGE.json').read_bytes())
        self.assertEqual(*results)
