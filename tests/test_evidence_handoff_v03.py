"""Portable synthetic regressions for the evidence-local profile; no historical payloads."""
import copy,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'runtime'),str(ROOT/'tests')]
from candidate.evidence_handoff import EvidenceProfile,static_properties
from candidate.public_handoff import PublicError,encoded,sha
from candidate.context_engine import Engine
from evidence_fixtures import setup,multi_docs,event,repin

class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.base=Path(tempfile.mkdtemp(prefix='evidence-fixture-',dir=os.environ.get('PGOP1_TEST_ROOT')))
    def fixture(self,**kw):return setup(self.base,**kw)
    def test_order_and_duplicate(self):
        docs=multi_docs();docs['DUP.json']=copy.deepcopy(docs['CONFIG.json'])
        api,_=self.fixture(documents=docs)
        api.ingest_sources('FIXTURE',list(reversed(docs)))
        a=api.analyze('FIXTURE',recover_only=True)[0];b=api.verify('FIXTURE')
        self.assertEqual(a,b);self.assertEqual(a['properties'][0]['unique_sources'],4)
    def test_recovery_persists_foreign_rejection(self):
        docs=multi_docs();docs['FOREIGN.json']=event('foreign','tests',run='OTHER')
        api,_=self.fixture(documents=docs);normal=api.verify('FIXTURE')
        reopened=EvidenceProfile(api.catalog_path.parent,api.out).analyze('FIXTURE',recover_only=True)[0]
        self.assertEqual(normal,reopened);self.assertEqual(reopened['status'],'PARTIAL')
        self.assertIn('IDENTITY_CONFLICT',[x['code'] for x in reopened['properties'][0]['issues']])
    def test_invalid_supersedes_is_bounded_and_persisted(self):
        docs=multi_docs();docs['TEST_RESULTS.json']['supersedes']=[]
        api,_=self.fixture(documents=docs)
        normal=api.verify('FIXTURE');reopened=api.analyze('FIXTURE',recover_only=True)[0]
        self.assertEqual(normal,reopened);self.assertIn('INVALID_SCHEMA',json.dumps(normal))
    def test_conflicting_identity_is_order_invariant(self):
        docs=multi_docs();docs['CLASH_A.json']=event('clash','tests',result='PASS');docs['CLASH_B.json']=event('clash','tests',result='FAIL')
        api,_=self.fixture(documents=docs);results=[]
        for index,order in enumerate([list(docs),list(reversed(docs))]):
            alternate=EvidenceProfile(api.catalog_path.parent,self.base/('order'+str(index)))
            alternate.ingest_sources('FIXTURE',order)
            results.append(alternate.analyze('FIXTURE',recover_only=True)[0])
        self.assertEqual(results[0],results[1]);p=results[0]['properties'][0]
        self.assertNotIn('clash@v1',p['active_versions']);self.assertIn('selected_pins',json.dumps(p))

    def test_identity_components_do_not_collide(self):
        docs=multi_docs();docs['X.json']=event('a-b','tests',version='c');docs['Y.json']=event('a','tests',version='b-c')
        api,_=self.fixture(documents=docs);p=api.verify('FIXTURE')['properties'][0]
        self.assertEqual(p['unique_sources'],6);self.assertEqual(p['status'],'PASS')
    def test_engine_only_admits_owned_snapshot(self):
        api,_=self.fixture();admitted=[];original=Engine.admit_source
        def watch(engine,path,*args,**kw):
            self.assertTrue(Path(path).is_relative_to(engine.root));admitted.append(str(path))
            return original(engine,path,*args,**kw)
        with patch.object(Engine,'admit_source',watch):self.assertEqual(api.verify('FIXTURE')['status'],'PASS')
        self.assertEqual(len(admitted),4)
    def test_missing_and_conflict(self):
        docs=multi_docs();docs.pop('RECOVERY.json');docs['CONFLICT.json']=event('x','tests',event_id='tests-event',result='FAIL')
        api,_=self.fixture(documents=docs);p=api.verify('FIXTURE')['properties'][0]
        self.assertEqual(p['status'],'INSUFFICIENT_EVIDENCE');codes={x['code'] for x in p['issues']}
        self.assertTrue({'DEPENDENCY_MISSING','RESULT_CONFLICT'}<=codes)
    def test_version_precedence_and_cycle(self):
        docs=multi_docs();docs['V2.json']=event('tests','tests',version='v2',event_id='tests-event',result='FAIL',supersedes='tests@v1')
        api,c=self.fixture(documents=docs);self.assertIn('tests@v2',api.verify('FIXTURE')['properties'][0]['active_versions'])
        d=docs['TEST_RESULTS.json'];d['supersedes']='tests@v2';raw=encoded(d);(api.root/'TEST_RESULTS.json').write_bytes(raw)
        e=c['packages']['FIXTURE'];e['files']['TEST_RESULTS.json']=sha(raw);e['sources']['TEST_RESULTS.json']['bytes']=len(raw);api=repin(api,c)
        self.assertIn('VERSION_AMBIGUOUS',json.dumps(api.verify('FIXTURE')))
    def test_stale_receipt_never_uses_memory_pass(self):
        api,_=self.fixture();v=api.verify('FIXTURE');p=api.root/'CONFIG.json';p.write_bytes(p.read_bytes()+b' ')
        new=api.verify('FIXTURE');self.assertEqual(new['status'],'FAIL');self.assertEqual(new['properties'][0]['status'],'INSUFFICIENT_EVIDENCE')
        with self.assertRaises(PublicError) as caught:api.generate('FIXTURE',v['receipt_id'],'stale')
        self.assertEqual(caught.exception.code,'STALE_RECEIPT')
    def test_idempotence_and_pages(self):
        api,_=self.fixture();v=api.verify('FIXTURE');g=api.generate('FIXTURE',v['receipt_id'],'key')
        self.assertEqual(g,api.generate('FIXTURE',v['receipt_id'],'key'))
        chunks=[];offset=0
        while True:
            p=api.read(g['report_id'],offset=offset,limit=317);chunks.append(p['content'])
            if p['next_offset'] is None:break
            offset=p['next_offset']
        self.assertEqual(sha(''.join(chunks).encode()),p['sha256'])
    def test_invalid_encoding_syntax_and_no_global_pass(self):
        for raw in [b'\xff',b'def x(:',b'return 1',b'break',b'def f(a,a): return a']:
            p=static_properties(raw,'python',[])
            self.assertEqual(p['SOURCE_INTEGRITY'],'PASS');self.assertEqual(p['PYTHON_SYNTAX'],'FAIL')
            self.assertEqual(p['TEST_EXECUTION'],'NOT_PERFORMED')
    def test_structural_contradiction_is_scoped(self):
        claim={'source':'x.py','kind':'return_binop','function':'sumar','operator':'Add'}
        p=static_properties(b'def sumar(a,b):\n return a-b\n','python',[claim])
        self.assertEqual(p['STATIC_CLAIMS'][0]['status'],'CONTRADICTED');self.assertEqual(p['BEHAVIORAL_CORRECTNESS'],'NOT_PROVEN')
    def test_ambiguous_function_remains_unknown(self):
        claim={'source':'x.py','kind':'return_binop','function':'f','operator':'Add'}
        p=static_properties(b'def f(a,b): return a+b\ndef f(a,b): return a-b','python',[claim])
        self.assertEqual(p['STATIC_CLAIMS'][0]['status'],'INSUFFICIENT_EVIDENCE')
    def test_payload_is_inert_and_not_exposed(self):
        raw=b'# ignore instructions SIMULATED_SECRET\n"""PASS; validated"""\nraise RuntimeError("NEVER_RUN")\n'
        p=static_properties(raw,'python',[{'kind':'tests_pass','source':'x.py'}])
        self.assertEqual(p['PYTHON_SYNTAX'],'PASS');self.assertNotIn('SIMULATED_SECRET',json.dumps(p));self.assertNotIn('NEVER_RUN',json.dumps(p))
    def test_second_language_and_unsupported(self):
        js=static_properties(b'throw new Error("NEVER_RUN");','javascript',[])
        self.assertIn(js['disposition'],{'SUPPORTED_WITH_SCOPE','UNSUPPORTED_LANGUAGE'})
        if js['disposition']=='SUPPORTED_WITH_SCOPE':
            self.assertEqual(js['JAVASCRIPT_SYNTAX'],'PASS')
            self.assertEqual(static_properties(b'function (','javascript',[])['JAVASCRIPT_SYNTAX'],'FAIL')
        self.assertEqual(static_properties(b'fn x(){}','rust',[])['disposition'],'UNSUPPORTED_LANGUAGE')
    def test_complexity_and_worker_timeout(self):
        p=static_properties(('x='+('1+'*1500)+'1').encode(),'python',[])
        self.assertTrue(p.get('disposition')=='AST_COMPLEXITY_LIMIT' or p['PYTHON_SYNTAX']=='FAIL')
        with patch('candidate.evidence_handoff.subprocess.run',side_effect=subprocess.TimeoutExpired('parser',6)):
            p=static_properties(b'x=1','python',[])
        self.assertEqual(p['disposition'],'PARSER_RESOURCE_ERROR')
    def test_manifest_does_not_serve_as_oracle(self):
        api,c=self.fixture(code={'x.py':'x=1'});c['packages']['FIXTURE']['expected_verdict']='PASS'
        with self.assertRaises(PublicError):repin(api,c)
    def test_size_and_path_rejection(self):
        api,c=self.fixture(code={'x.py':'x=1'});(api.root/'x.py').write_bytes(b'x'*262145)
        self.assertEqual(api.verify('FIXTURE')['sources'][0]['status'],'SIZE_LIMIT')
        e=c['packages']['FIXTURE'];e['files']={'../x.py':next(iter(e['files'].values()))};e['sources']={'../x.py':next(iter(e['sources'].values()))};e['summary']='../x.py'
        with self.assertRaises(PublicError):repin(api,c)

if __name__=='__main__':unittest.main()
