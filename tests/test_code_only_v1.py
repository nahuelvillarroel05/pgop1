"""E3 own development cases. Inert fixtures, never imported or executed."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from candidate.code_contract_v1 import canonical,digest,check_catalog,check_page
from candidate.code_only_v1 import CodeOnlyProfile
from tools.verify_code_only_v1 import verified_report,verify_bundle

ROOT=Path(__file__).absolute().parents[1]

@unittest.skipUnless(os.name=='nt','Windows contract only')
class CodeOnlyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='e3-test-');self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.src=self.base/'sources';self.src.mkdir();self.cfg=self.base/'config';self.cfg.mkdir()

    def catalog(self,sources,claims=(),mode='CODE_TREE',roots=None):
        pins=[]
        for name,text in sorted(sources.items()):
            raw=text.encode();p=self.src/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
            pins.append(dict(path=name,bytes=len(raw),sha256=digest(raw),kind='python'))
        c=dict(schema='pgop1.code-only-catalog.v1',authorized_root=str(self.src),mode=mode,
               package_roots=(['.'] if roots is None else roots) if mode=='CODE_TREE' else [],sources=pins,claims=sorted(claims,key=lambda q:q['claim_id']))
        raw=canonical(c);p=self.cfg/'catalog.json';p.write_bytes(raw)
        self.pin=digest(raw);self.c=c;self.profile=CodeOnlyProfile(source_root=self.src,catalog_path=p,catalog_sha256=self.pin)

    def q(self,id='q',family='symbol_defined',scope='<module>',params=None,path='a.py',expected=True):
        return dict(schema='pgop1.code-only-claims.v1',claim_id=id,predicate=family,source_ref=path,
                    scope=scope,parameters=params or dict(name='f',kind='any'),expected=expected)

    def generate(self):
        self.out=self.base/'out';ack=self.profile.generate(self.out);self.assertTrue(ack['operation_completed'])
        return verified_report(self.out,self.pin)

    def test_code_only_positive_negative_and_rejected(self):
        self.catalog({'a.py':'def f(x,/,y,*args,z,**kwargs):\n    pass\n'},[
            self.q('a'),self.q('b',params=dict(name='missing',kind='any')),self.q('c',family='calls')])
        r=self.generate();self.assertEqual([x['verdict'] for x in r['claims']],['SUPPORTED','CONTRADICTED',None])
        self.assertEqual(r['claims'][2]['status'],'REJECTED')

    def test_ambiguous_conditional_decorated_and_missing_scopes(self):
        self.catalog({'a.py':'def f():pass\ndef f():pass\n@dec\nclass C:\n    def m(self):pass\n'},[
            self.q('a'),self.q('b','class_method_declared','C',dict(name='m')),self.q('c',scope='absent')])
        self.assertTrue(all(q['verdict']=='INSUFFICIENT_EVIDENCE' for q in self.generate()['claims']))

    def test_partial_cannot_prove_absence(self):
        self.catalog({'a.py':'def bad(:\n'},[self.q()]);self.assertEqual(self.generate()['claims'][0]['verdict'],'INSUFFICIENT_EVIDENCE')

    def test_import_local_from_and_raw(self):
        self.catalog({'pkg/__init__.py':'','pkg/a.py':'','use.py':'import pkg.a as a\nfrom pkg import a as b\n'})
        rel=self.generate()['relations'];self.assertEqual([r['resolution'] for r in rel],['LOCAL_MODULE_MATCH','CANDIDATE_ONLY'])
        self.assertTrue(all(r['BEHAVIORAL_LINK']=='NOT_PROVEN' for r in rel))

    def test_raw_has_no_module_target(self):
        self.catalog({'RAW_0001.py':'import a\n','RAW_0002.py':'def f():pass\n'},mode='STRICT_RAW')
        r=self.generate()['relations'][0];self.assertEqual(r['resolution'],'UNRESOLVED');self.assertNotIn('to_source',r)

    def test_relative_circular_and_incomplete(self):
        self.catalog({'pkg/__init__.py':'','pkg/a.py':'from . import b\n','pkg/b.py':'import pkg.a\n','use.py':'import absent.x\n'})
        r=self.generate()['relations'];self.assertEqual([x['resolution'] for x in r],['CANDIDATE_ONLY','LOCAL_MODULE_MATCH','OUTSIDE_SELECTED_UNIVERSE'])

    def test_dynamic_shadowing_local_condition_star(self):
        self.catalog({'a.py':'import b\nb=3\n','b.py':'','c.py':'if flag:\n import b\n','d.py':'def f():\n import b\n','e.py':'from b import *\nimport b\n'})
        self.assertTrue(all(x['resolution']=='AMBIGUOUS' and 'to_source' not in x for x in self.generate()['relations']))

    def test_exception_and_pattern_captures_abstain(self):
        self.catalog({'b.py':'','a.py':'import b as f\ntry:\n pass\nexcept Exception as f:\n pass\n',
                      'c.py':'import b as f\nmatch value:\n case {"x": x, **f}: pass\n',
                      'd.py':'def f():pass\nmatch value:\n case [*f]:pass\n'},[self.q(path='d.py')])
        r=self.generate();self.assertEqual(r['claims'][0]['verdict'],'INSUFFICIENT_EVIDENCE')
        self.assertTrue(all(x['resolution']=='AMBIGUOUS' and 'to_source' not in x for x in r['relations'] if x['kind']=='imports'))

    def test_two_roots_ambiguous_and_repeated_alias_ids(self):
        self.catalog({'r1/a.py':'','r2/a.py':'','r1/use.py':'import a\nimport b, b\n'},roots=['r1','r2'])
        r=self.generate()['relations'];self.assertEqual(r[0]['resolution'],'AMBIGUOUS');self.assertNotIn('to_source',r[0]);self.assertEqual(len({x['relation_id'] for x in r}),len(r))

    def test_output_exclusive_and_tamper_rehashed(self):
        self.catalog({'a.py':'def f():pass\n'},[self.q()]);self.generate()
        with self.assertRaises(FileExistsError):self.profile.generate(self.out)
        p=self.out/'REPORT.json';r=json.loads(p.read_bytes());r['claims'][0]['verdict']='CONTRADICTED';p.write_bytes(canonical(r))
        m=json.loads((self.out/'MANIFEST.json').read_bytes());m['files']['REPORT.json']=dict(bytes=p.stat().st_size,sha256=digest(p.read_bytes()));(self.out/'MANIFEST.json').write_bytes(canonical(m))
        with self.assertRaises(ValueError):verify_bundle(self.out,self.pin)

    def test_source_tamper_external_anchor_and_page_types(self):
        self.catalog({'a.py':'def f():pass\n'},[self.q()]);(self.src/'a.py').write_text('def g():pass\n')
        with self.assertRaises(ValueError):self.profile.generate(self.base/'out')
        for offset,limit in [(True,1),(-1,1),(0,True),(0,101)]:
            with self.assertRaises(ValueError):check_page(offset,limit,2)
        with self.assertRaises(ValueError):check_catalog(self.c,'0'*64)

    def test_fresh_process_verifier_and_pagination(self):
        self.catalog({'a.py':'def f():pass\n'},[self.q(str(i)) for i in range(40)]);r=self.generate()
        p=subprocess.run([sys.executable,str(ROOT/'tools/verify_code_only_v1.py'),'--artifacts',str(self.out),'--catalog-sha256',self.pin],capture_output=True)
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout)['report_id'],r['report_id'])
        allrows=[]
        for offset in range(0,40,7):allrows.extend(self.profile.query(self.out,offset=offset,limit=7)['items'])
        self.assertEqual(allrows,r['claims'])

    def test_casefold_collision_duplicate_queries(self):
        self.catalog({'a.py':''},[self.q()]);c=json.loads(canonical(self.c));c['sources'].append(dict(c['sources'][0],path='A.py'))
        with self.assertRaises(ValueError):check_catalog(c,digest(canonical(c)))
        c=json.loads(canonical(self.c));c['sources']=[dict(c['sources'][0],path='Foo.py'),dict(c['sources'][0],path='foo/__init__.py')]
        with self.assertRaisesRegex(ValueError,'MODULE_CASEFOLD_COLLISION'):check_catalog(c,digest(canonical(c)))
        c=json.loads(canonical(self.c));c['claims']*=2
        with self.assertRaises(ValueError):check_catalog(c,digest(canonical(c)))
