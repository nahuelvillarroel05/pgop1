"""E7 synthetic selection, confinement, external-anchor and independent replay tests."""
import copy,json,os,pathlib,subprocess,sys,tempfile,unittest
from unittest import mock
from candidate import selection_contract_v1 as C
from candidate import source_selection_v1 as S
from candidate import windows_safe_io_v2 as IO
from tools.verify_selection_v1 import verify
PRODUCT=pathlib.Path(__file__).absolute().parents[1]
class SourceSelectionV1Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='e7-');self.base=pathlib.Path(self.tmp.name)
        self.source=self.base/'source';self.source.mkdir();self.config=self.base/'config';self.config.mkdir()
        self.p=copy.deepcopy(C.POLICY)
    def tearDown(self):self.tmp.cleanup()
    def catalog(self,files,scope='.',package_root='.'):
        rows=[]
        for name,raw in sorted(files.items()):
            if isinstance(raw,str):raw=raw.encode()
            path=self.source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(raw)
            rows.append(dict(path=name,sha256=C.digest(raw),bytes=len(raw)))
        return dict(schema='pgop1.selection-catalog.v1',source_root=str(self.source),scope=scope,package_root=package_root,sources=rows)
    def plan(self,files,limit=32,**kwargs):
        c=self.catalog(files,**kwargs);p=dict(self.p,max_selected=limit);return S.select_catalog(c,p,'a'*64)[0]
    def bundle(self,files):
        c=self.catalog(files);code=dict(schema='pgop1.selection-code.v1',files=[
            dict(path=n,sha256=C.digest((PRODUCT/n).read_bytes()),bytes=len((PRODUCT/n).read_bytes()))
            for n in sorted(['runtime/candidate/selection_contract_v1.py','runtime/candidate/source_selection_v1.py','tools/source_selection_v1.py','tools/verify_selection_v1.py','runtime/candidate/static_ast_v2.py','runtime/candidate/windows_safe_io_v2.py','tools/verify_source_v2.py'])])
        pins=[]
        for name,value in [('catalog',c),('policy',self.p),('code',code)]:
            raw=C.canonical(value);path=self.config/(name+'.json');path.write_bytes(raw);pins.extend([str(path),C.digest(raw)])
        out=self.base/'output';S.execute(str(self.source),*pins,str(out));return out,pins
    def test_simple_nested_namespace_absolute_relative_and_cycle(self):
        r=self.plan({'p/__init__.py':'from . import a\n','p/a.py':'import p.b\n','p/b.py':'from .a import X\n','p/ns/deep.py':'from .. import b\n'})
        self.assertEqual(len(r['selected']),4);self.assertEqual(r['source_errors'],[])
        self.assertTrue(any(x['event']=='DEDUPLICATED' for x in r['trace']))
        self.assertNotIn('p/ns/__init__.py',[x['path'] for x in r['selected']])
    def test_seed_fifo_and_per_origin_path_sort(self):
        r=self.plan({'__init__.py':'','a.py':'import z\nimport y\n','b.py':'','y.py':'','z.py':''})
        self.assertEqual([x['path'] for x in r['selected']],['__init__.py','a.py','y.py','z.py','b.py'])
        self.assertEqual([x['path'] for x in r['trace'] if x['event']=='DEQUEUED'],['__init__.py','a.py','y.py','z.py','b.py'])
    def test_budget_1_2_31_32_and_atomic_parent_group(self):
        files={'p/__init__.py':'','p/a.py':'import p.deep.z\n','p/deep/__init__.py':'','p/deep/z.py':''}
        for cap in (1,2,31,32):
            r=self.plan(files,limit=cap);self.assertLessEqual(len(r['selected']),cap)
            selected={x['path'] for x in r['selected']}
            self.assertTrue('p/a.py' not in selected or 'p/__init__.py' in selected)
            self.assertTrue('p/deep/z.py' not in selected or 'p/deep/__init__.py' in selected)
    def test_duplicates_by_path_reject_but_identical_bytes_keep_members(self):
        c=self.catalog({'a.py':'','b.py':''});c['sources'].append(copy.deepcopy(c['sources'][0]))
        with self.assertRaises(ValueError):C.catalog(c,self.p)
        r=S.select_catalog(self.catalog({'a.py':'','b.py':''}),self.p,'a'*64)[0]
        self.assertEqual(len(r['selected']),2);self.assertEqual(len(r['duplicate_bytes']),1)
    def test_external_missing_from_object_wildcard_and_relative_escape(self):
        r=self.plan({'p/__init__.py':'','p/a.py':'from p import b\nfrom external import absent\nfrom ... import escape\nfrom p import *\n','p/b.py':''})
        refs=[x for x in r['trace'] if x['event']=='REFERENCE']
        self.assertTrue(any(x['reason']=='RELATIVE_ESCAPE' for x in refs))
        self.assertTrue(any(x['reason']=='NO_CALLER_CATALOG_CANDIDATE' for x in refs))
        self.assertTrue(any('p/b.py' in x['candidates'] for x in refs))
        self.assertNotIn('LOCAL_MODULE_MATCH',C.canonical(r).decode())
    def test_hazards_conditional_nested_namedexpr_are_only_syntax(self):
        r=self.plan({'a.py':'import b\nb=1\nif True:\n import b\nx=(b:=0)\ndef __getattr__(n):return n\ndef f():\n import b\n','b.py':''})
        self.assertEqual(len([x for x in r['trace'] if x['event']=='REFERENCE']),3)
    def test_syntax_and_encoding_and_provider_lower_budgets(self):
        c=self.catalog({'a.py':'def broken(\n','b.py':b'# coding: latin-1\nx="\xe9"\n'})
        r=S.select_catalog(c,self.p,'a'*64)[0]
        self.assertEqual(r['status'],'PARTIAL')
        self.assertTrue(any(x['event']=='AST' and x['status']=='PARSE_FAILED' for x in r['trace']))
        p=dict(self.p,ast_nodes=1)
        r=S.select_catalog(c,p,'a'*64)[0]
        self.assertTrue(any(x['event']=='AST' and x['status']=='BUDGET_EXCEEDED' for x in r['trace']))
    def test_read_budget_charges_aborted_groups(self):
        c=self.catalog({'p/__init__.py':'','p/a.py':'pass\n'});p=dict(self.p,max_planning_files=1)
        r=S.select_catalog(c,p,'a'*64)[0]
        self.assertEqual(r['selected'],[]);self.assertEqual(r['budgets']['planning_attempted'],1)
        self.assertEqual(r['budgets']['planning_successful'],1)
    def test_file_bytes_and_total_limits_are_distinct(self):
        c=self.catalog({'a.py':'x=1\n','b.py':'x=2\n'});p=dict(self.p,max_total_read_bytes=4)
        r=S.select_catalog(c,p,'a'*64)[0];self.assertLessEqual(r['budgets']['planning_bytes_reserved'],4)
        with self.assertRaises(ValueError):C.catalog(c,dict(self.p,max_file_bytes=1))
        with self.assertRaises(ValueError):C.policy(dict(self.p,max_selected=33))
        with self.assertRaises(ValueError):C.policy(dict(self.p,max_selected=True))
        with self.assertRaises(ValueError):C.catalog(dict(c,scope='.',package_root='src'),self.p)
        self.assertLessEqual(r['budgets']['planning_bytes_reserved']+r['budgets']['recheck_bytes'],p['max_total_read_bytes'])
    def test_sensitive_case_collisions_and_outside_paths_reject(self):
        for name in ['../evil.py','a.py:ads','secret.py','model/a.py','p/HOLDOUT/a.py']:
            c=dict(schema='pgop1.selection-catalog.v1',source_root=str(self.source),scope='.',package_root='.',
                   sources=[dict(path=name,sha256='a'*64,bytes=0)])
            with self.assertRaises(ValueError):C.catalog(c,self.p)
        c=self.catalog({'a.py':''});c['sources'].append(dict(c['sources'][0],path='A.py'));c['sources'].sort(key=lambda x:x['path'])
        with self.assertRaises(ValueError):C.catalog(c,self.p)
    def test_unc_ads_device_traversal_root_reject(self):
        for root in ['D:\\x\\..\\source','\\\\server\\share','\\\\?\\D:\\source','D:\\source:ads','D:\\CON','relative']:
            with self.assertRaises(ValueError):IO.absolute(root)
    def test_provider_denial_is_typed_without_fallback(self):
        c=self.catalog({'a.py':'pass\n'})
        with mock.patch.object(IO,'safe_read',side_effect=IO.SafeIOError('SOURCE_UNAVAILABLE_OR_UNSAFE')) as read:
            r=S.select_catalog(c,self.p,'a'*64)[0]
        self.assertEqual(read.call_count,1);self.assertEqual(r['selected'],[])
        self.assertEqual(r['source_errors'][0]['reason'],'SOURCE_UNAVAILABLE_OR_UNSAFE')
    def test_source_changed_after_catalog_and_final_recheck(self):
        c=self.catalog({'a.py':'x=1\n'});(self.source/'a.py').write_text('x=2\n')
        r=S.select_catalog(c,self.p,'a'*64)[0];self.assertEqual(r['source_errors'][0]['reason'],'SOURCE_CHANGED')
        c=self.catalog({'a.py':'pass\n'});original=IO.safe_read;calls=[]
        def reader(*args,**kwargs):
            calls.append(args)
            self.assertLessEqual(args[-1],c['sources'][0]['bytes'])
            if len(calls)>1:raise IO.SafeIOError('SOURCE_HASH_MISMATCH')
            return original(*args,**kwargs)
        with mock.patch.object(IO,'safe_read',side_effect=reader):r=S.select_catalog(c,self.p,'a'*64)[0]
        self.assertEqual(r['status'],'PARTIAL');self.assertEqual(r['source_errors'][0]['reason'],'SOURCE_CHANGED')
    def test_side_effect_sentinel_is_not_executed(self):
        sentinel=self.base/'never-created.txt'
        r=self.plan({'a.py':"from pathlib import Path\nPath("+repr(str(sentinel))+").write_text('UNAUTHORIZED')\n"})
        self.assertFalse(sentinel.exists());self.assertEqual(r['budgets']['selected'],1)
    def test_independent_verifier_and_existing_output_refusal(self):
        out,pins=self.bundle({'__init__.py':'','a.py':'import b\n','b.py':''})
        self.assertEqual(verify(str(out),pins[1],pins[3],pins[5])['status'],'SELECTION_VERIFIED')
        with self.assertRaises(FileExistsError):S.execute(str(self.source),*pins,str(out))
    def test_independent_verifier_blocks_producer_imports(self):
        out,pins=self.bundle({'a.py':'import b\n','b.py':''})
        code="import sys;sys.path[:0]=["+repr(str(PRODUCT/'runtime'))+","+repr(str(PRODUCT))+"];sys.modules['candidate.source_selection_v1']=None;from tools.verify_selection_v1 import verify;print(verify("+repr(str(out))+","+repr(pins[1])+","+repr(pins[3])+","+repr(pins[5])+")['status'])"
        proc=subprocess.run([sys.executable,'-c',code],capture_output=True,env=os.environ.copy())
        self.assertEqual(proc.returncode,0,proc.stderr.decode());self.assertIn(b'SELECTION_VERIFIED',proc.stdout)
    def test_rehashed_semantic_tampering_rejected(self):
        out,pins=self.bundle({'__init__.py':'','a.py':'import b\n','b.py':''})
        original=json.loads((out/'PLAN.json').read_bytes())
        attacks=[]
        bad=copy.deepcopy(original);bad['selected'].reverse();attacks.append(bad)
        bad=copy.deepcopy(original);bad['selected'][0]['sha256']='0'*64;attacks.append(bad)
        bad=copy.deepcopy(original);bad['selected'].pop();attacks.append(bad)
        bad=copy.deepcopy(original);bad['selected'].append(dict(path='../evil.py',sha256='0'*64,bytes=0));attacks.append(bad)
        bad=copy.deepcopy(original);bad['seeds'].reverse();attacks.append(bad)
        bad=copy.deepcopy(original);bad['metadata']='injected';attacks.append(bad)
        bad=copy.deepcopy(original);bad['budgets']['selected']=33;attacks.append(bad)
        bad=copy.deepcopy(original);bad['trace'][1]['event']='FAKE_PRIORITY';attacks.append(bad)
        bad=copy.deepcopy(original);bad['selected'][0]['path']='imagined/__init__.py';attacks.append(bad)
        for bad in attacks:
            raw=C.canonical(bad);(out/'PLAN.json').write_bytes(raw)
            m=json.loads((out/'MANIFEST.json').read_bytes());m['files']['PLAN.json']=dict(bytes=len(raw),sha256=C.digest(raw));(out/'MANIFEST.json').write_bytes(C.canonical(m))
            with self.assertRaises(ValueError):verify(str(out),pins[1],pins[3],pins[5])
    def test_ast_metadata_and_code_closure_tampering_reject(self):
        out,pins=self.bundle({'a.py':'pass\n'})
        reports=json.loads((out/'AST_REPORTS.json').read_bytes());reports['a.py']['execution_metrics']={'fabricated':True}
        raw=C.canonical(reports);(out/'AST_REPORTS.json').write_bytes(raw)
        m=json.loads((out/'MANIFEST.json').read_bytes());m['files']['AST_REPORTS.json']=dict(bytes=len(raw),sha256=C.digest(raw));(out/'MANIFEST.json').write_bytes(C.canonical(m))
        with self.assertRaises(ValueError):verify(str(out),pins[1],pins[3],pins[5])
        with self.assertRaises(ValueError):C.code_manifest(dict(schema='pgop1.selection-code.v1',files=[dict(path='a.py',sha256='a'*64,bytes=0)]))
    def test_read_write_failure_retained_and_root_mode_blocked(self):
        out,pins=self.bundle({'a.py':'pass\n'})
        with mock.patch('os.write',side_effect=OSError('injected write failure')):
            with self.assertRaises(OSError):S.execute(str(self.source),*pins,str(self.base/'write-failed'))
        self.assertTrue((self.base/'write-failed').exists())
        proc=subprocess.run([sys.executable,str(PRODUCT/'tools/source_selection_v1.py'),'--source-root',str(self.source)],capture_output=True)
        self.assertEqual(proc.returncode,3);self.assertIn(b'SAFE_DIRECTORY_ENUMERATION_UNAVAILABLE',proc.stdout)
    def test_depth_and_unknown_metadata_reject(self):
        c=self.catalog({'a.py':''});c['extra']='bad'
        with self.assertRaises(ValueError):C.catalog(c,self.p)
        c=self.catalog({'a.py':''});c['sources'][0]['extra']='bad'
        with self.assertRaises(ValueError):C.catalog(c,self.p)
        c=self.catalog({'p/q/r/s/t/u/deep.py':''})
        with self.assertRaises(ValueError):C.catalog(c,self.p)
    def test_root_authorization_and_flush_failure(self):
        out,pins=self.bundle({'a.py':'pass\n'})
        other=self.base/'other';other.mkdir()
        with self.assertRaises(ValueError):S.execute(str(other),*pins,str(self.base/'different'))
        with mock.patch('os.fsync',side_effect=OSError('injected flush failure')):
            with self.assertRaises(OSError):S.execute(str(self.source),*pins,str(self.base/'flush-failed'))
    def test_native_junction_and_hardlink_denial(self):
        c=self.catalog({'a.py':'pass\n'})
        junction=self.base/'junction'
        p=subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(junction),str(self.source)],capture_output=True)
        self.assertEqual(p.returncode,0,p.stderr.decode(errors='replace'))
        try:
            with self.assertRaises(ValueError):IO.safe_read(junction,'a.py',None,100)
        finally:os.rmdir(junction)
        hard=self.base/'alias.py';os.link(self.source/'a.py',hard)
        try:
            r=S.select_catalog(c,self.p,'a'*64)[0]
            self.assertEqual(r['source_errors'][0]['reason'],'UNSAFE_PATH_HARDLINK')
        finally:hard.unlink()
if __name__=='__main__':unittest.main()
