"""Selected-source structural associations and independent tamper rejection."""
import copy,json,pathlib,sys,tempfile,unittest
from candidate.code_contract_v1 import canonical,digest
from candidate.code_only_v1 import CodeOnlyProfile
from candidate.static_binding_v2 import analyze_bundle
from tools.verify_binding_v2 import verify_bytes


class StaticBindingV2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=pathlib.Path(self.tmp.name);self.counter=0
    def tearDown(self):self.tmp.cleanup()
    def bundle(self,sources,mode='CODE_TREE',roots=None):
        self.counter+=1;base=self.root/str(self.counter);base.mkdir();source=base/'sources';source.mkdir()
        pins=[]
        for name,body in sorted(sources.items()):
            raw=body.encode();p=source/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_bytes(raw)
            pins.append(dict(path=name,sha256=digest(raw),bytes=len(raw),kind='python'))
        c=dict(schema='pgop1.code-only-catalog.v1',authorized_root=str(source),mode=mode,package_roots=(roots or ['.']) if mode=='CODE_TREE' else [],sources=pins,claims=[])
        config=base/'config';config.mkdir();cat=config/'CATALOG.json';cat.write_bytes(canonical(c));sha=digest(canonical(c));out=base/'bundle'
        CodeOnlyProfile(source_root=source,catalog_path=cat,catalog_sha256=sha).generate(out)
        report=analyze_bundle(out,sha);verify_bytes(canonical(report),out,sha)
        return out,sha,report
    def test_relative_module_and_object_have_different_authority(self):
        _,_,r=self.bundle({'p/__init__.py':'','p/m.py':'class C: pass\n','p/use.py':'from .m import C as Alias\n'})
        row=r['relations'][0];self.assertEqual(row['to_source'],'p/m.py');self.assertEqual(row['resolution'],'LOCAL_MODULE_MATCH')
        self.assertEqual(row['object']['resolution'],'CANDIDATE_ONLY');self.assertEqual(row['object']['runtime_target'],'NOT_PROVEN')
        self.assertEqual(row['bound_name'],'Alias');self.assertEqual(len(row['package_evidence']),1)
    def test_from_package_does_not_select_submodule_as_object(self):
        _,_,r=self.bundle({'p/__init__.py':'m = 4\n','p/m.py':'','use.py':'from p import m\n'})
        self.assertEqual(r['relations'][0]['to_source'],'p/__init__.py')
        self.assertEqual(r['relations'][0]['requested_module'],'p')
    def test_absolute_alias_unrelated_child_scope_is_not_rebinding(self):
        _,_,r=self.bundle({'m.py':'','use.py':'import m as local\ndef f(local):\n return local\n'})
        self.assertEqual(r['relations'][0]['resolution'],'LOCAL_MODULE_MATCH')
    def test_repeated_alias_and_conditional_abstain(self):
        _,_,r=self.bundle({'m.py':'','use.py':'import m\nimport m\nif True:\n import m as other\n'})
        self.assertTrue(all(x['resolution']=='AMBIGUOUS' for x in r['relations']))
        self.assertEqual(len({x['relation_id'] for x in r['relations']}),3)
    def test_missing_parent_and_relative_escape(self):
        _,_,r=self.bundle({'p/m.py':'','p/use.py':'from .m import C\n'})
        self.assertEqual(r['relations'][0]['resolution'],'OUTSIDE_SELECTED_UNIVERSE')
        _,_,r=self.bundle({'use.py':'from ..m import C\n','m.py':''})
        self.assertEqual(r['relations'][0]['resolution'],'AMBIGUOUS')
    def test_raw_never_uses_spelled_module_for_target(self):
        _,_,r=self.bundle({'RAW_0001.py':'import m\n','RAW_0002.py':''},mode='STRICT_RAW')
        self.assertEqual(r['relations'][0]['resolution'],'UNRESOLVED');self.assertIsNone(r['relations'][0]['to_source'])
    def test_alias_environment_and_parent_wildcard_abstain(self):
        _,_,r=self.bundle({'m.py':'','use.py':'import sys as s\nimport m\n'})
        self.assertTrue(all(x['resolution']=='AMBIGUOUS' for x in r['relations']))
        _,_,r=self.bundle({'p/__init__.py':'from external import *\n','p/m.py':'','use.py':'import p.m\n'})
        self.assertEqual(r['relations'][-1]['resolution'],'AMBIGUOUS')
    def test_parent_module_collision_abstains(self):
        _,_,r=self.bundle({'p.py':'','p/__init__.py':'','p/m.py':'','use.py':'import p.m\n'})
        self.assertEqual(r['relations'][0]['rule'],'PACKAGE_IDENTITY_COLLISION')
    def test_strict_budget_prefix_and_determinism(self):
        out,sha,r=self.bundle({'a.py':'','b.py':'','use.py':'import a\nimport b\n'})
        short=analyze_bundle(out,sha,alias_limit=1);self.assertEqual((short['status'],short['examined'],short['omitted']),('PARTIAL',1,1))
        verify_bytes(canonical(short),out,sha)
        self.assertEqual(r,analyze_bundle(out,sha))
        for bad in [True,False,0,4097,1.0]:
            with self.assertRaises(ValueError):analyze_bundle(out,sha,alias_limit=bad)
    def test_independent_verifier_rejects_rehashed_semantic_tamper(self):
        out,sha,r=self.bundle({'m.py':'','use.py':'import m as alias\n'})
        mutations=[('to_source','use.py'),('source_sha256','0'*64),('scope_id','node-'+'0'*64),('asname','wrong'),('alias_index',True),('resolution','AMBIGUOUS')]
        for field,value in mutations:
            bad=copy.deepcopy(r);row=bad['relations'][0];row[field]=value
            row['relation_id']=digest(canonical({k:v for k,v in row.items() if k!='relation_id'}))
            bad['report_id']=digest(canonical({k:v for k,v in bad.items() if k!='report_id'}))
            with self.assertRaises(ValueError):verify_bytes(canonical(bad),out,sha)
        with self.assertRaises(ValueError):verify_bytes(canonical(dict(r,alias_limit=True)),out,sha)
    def test_verifier_does_not_import_producer(self):
        out,sha,r=self.bundle({'m.py':'','use.py':'import m\n'})
        old=sys.modules.pop('candidate.static_binding_v2');sys.modules['candidate.static_binding_v2']=None
        try:self.assertEqual(verify_bytes(canonical(r),out,sha)['status'],'STATIC_BINDING_VERIFIED')
        finally:sys.modules['candidate.static_binding_v2']=old
    def test_partial_source_cannot_emit_a_local_match(self):
        source='\n'.join('x=1' for _ in range(4000))+'\ndef f():\n import m\n'
        _,_,r=self.bundle({'m.py':'','use.py':source})
        self.assertEqual(r['status'],'PARTIAL');self.assertTrue(all(x['resolution']!='LOCAL_MODULE_MATCH' for x in r['relations']))
    def test_definition_default_rebinding_abstains(self):
        for body in ['import m as ref\ndef f(value=(ref := 0)):\n return value\n',
                     'import m as ref\nclass C((ref := object)):\n pass\n',
                     'import m as ref\nvalues=[(ref := x) for x in range(2)]\n']:
            _,_,r=self.bundle({'m.py':'','use.py':body})
            self.assertEqual(r['relations'][0]['resolution'],'AMBIGUOUS')
            self.assertIsNone(r['relations'][0]['to_source'])
    def test_conditional_assigned_and_imported_hooks_abstain(self):
        for hook in ['if True:\n def __getattr__(name): return 1\n',
                     'try:\n def __getattr__(name): return 1\nexcept Exception:\n pass\n',
                     '__getattr__ = lambda name: 1\n',
                     'from external import hook as __getattr__\n']:
            _,_,r=self.bundle({'p/__init__.py':hook,'p/m.py':'','use.py':'import p.m\n'})
            row=next(x for x in r['relations'] if x['from_source']=='use.py')
            self.assertEqual(row['resolution'],'AMBIGUOUS');self.assertIsNone(row['to_source'])


if __name__=='__main__':unittest.main()
