"""Adversarial reusable-reader tests. These are synthetic controls, not real cohorts."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'runtime'))
from candidate.evidence_handoff import profile_service, static_properties
from candidate.public_handoff import PublicError, encoded, sha


class RealTests(unittest.TestCase):
    def setup_case(self):
        base=Path(tempfile.mkdtemp(prefix='real-reader-',dir=os.environ.get('PGOP1_TEST_ROOT')))
        src=base/'source';src.mkdir();cfg=base/'config';cfg.mkdir()
        raw=b'def _private():\n    return 1\n';(src/'module.py').write_bytes(raw)
        claim={'source':'module.py','kind':'symbol_exists','name':'_private','node':'definition','present':True}
        e={'format':'real-static-v1','target_role':'REAL_PYTHON_PROJECT','run_id':'CONTROL','files':{'module.py':sha(raw)},'sources':{'module.py':{'id':'s1','role':'code','version':'v1','bytes':len(raw),'language':'python'}},'required_roles':[],'claims':[claim],'summary':'module.py'}
        c={'schema':'pgop1.real-evidence-catalog.v1','profile':'real-evidence-local-v1','source_root':str(src),'packages':{'CONTROL':e}}
        (cfg/'CATALOG.json').write_bytes(encoded(c))
        return base,c,profile_service(cfg,base/'reports')

    def test_underscore_definition_and_false_claim(self):
        _,_,api=self.setup_case();p=api.verify('CONTROL')['properties'][0]
        self.assertEqual(p['STATIC_CLAIMS'][0]['status'],'SUPPORTED')
        c={'source':'module.py','kind':'symbol_exists','name':'absent','node':'definition','present':True}
        self.assertEqual(static_properties(b'x=1','python',[c])['STATIC_CLAIMS'][0]['status'],'CONTRADICTED')

    def test_stale_current_bytes_do_not_reuse_memory(self):
        b,_,api=self.setup_case();old=api.verify('CONTROL');(b/'source/module.py').write_bytes(b'def broken(:')
        new=profile_service(b/'config',b/'reports').verify('CONTROL')
        self.assertEqual(new['status'],'FAIL');self.assertEqual(new['coverage']['passed'],0)
        with self.assertRaises(PublicError):api.generate('CONTROL',old['receipt_id'],'stale')

    def test_snapshot_only_recovery_is_explicit(self):
        b,_,api=self.setup_case();api.verify('CONTROL');(b/'source/module.py').unlink()
        r=api.analyze('CONTROL',recover_only=True)[0]
        self.assertEqual(r['memory']['mode'],'COMMITTED_SNAPSHOT_ONLY')
        self.assertEqual(r['sources'][0]['status'],'SOURCE_UNAVAILABLE')
        self.assertEqual(api.verify('CONTROL')['status'],'PARTIAL')

    def test_syntax_failure_is_distinct_from_integrity(self):
        r=static_properties(b'def broken(:','python',[])
        self.assertEqual(r['SOURCE_INTEGRITY'],'PASS');self.assertEqual(r['PYTHON_SYNTAX'],'FAIL')
        self.assertEqual(r['TEST_EXECUTION'],'NOT_PERFORMED')

    def test_flow_contract_is_syntactic_only(self):
        c={'source':'x.py','kind':'function_node','function':'f','node':'Raise','present':True}
        r=static_properties(b'def f():\n    raise ValueError\n','python',[c])
        self.assertEqual(r['STATIC_CLAIMS'][0]['status'],'SUPPORTED')
        self.assertEqual(r['BEHAVIORAL_CORRECTNESS'],'NOT_PROVEN')

    def test_target_statements_are_never_invoked(self):
        r=static_properties(b'raise RuntimeError("must never run")\n','python',[])
        self.assertEqual(r['PYTHON_SYNTAX'],'PASS')

    def test_traversal_catalog_is_rejected(self):
        b,c,_=self.setup_case();c['packages']['CONTROL']['files']['../escape.py']='0'*64
        c['packages']['CONTROL']['sources']['../escape.py']=c['packages']['CONTROL']['sources']['module.py']
        (b/'config/CATALOG.json').write_bytes(encoded(c))
        with self.assertRaises(PublicError):profile_service(b/'config',b/'other')

    def test_resource_bounds_remain_fixed(self):
        _,_,api=self.setup_case();self.assertEqual(api.availability()['limits'],{'file_bytes':262144,'files':16,'page_chars':16000,'ast_nodes':12000,'ast_depth':80})

    def test_same_identity_same_hash_alias_keeps_both_paths(self):
        b,c,_=self.setup_case();e=c['packages']['CONTROL']
        (b/'source/alias.py').write_bytes((b/'source/module.py').read_bytes())
        e['files']['alias.py']=e['files']['module.py'];e['sources']['alias.py']=dict(e['sources']['module.py'])
        (b/'config/CATALOG.json').write_bytes(encoded(c));api=profile_service(b/'config',b/'alias-reports')
        r=api.verify('CONTROL');self.assertEqual(r['coverage'],{'passed':2,'registered':2})
        self.assertEqual(r['memory']['retrieved'],1)

    def test_source_change_during_analysis_invalidates_all_properties(self):
        b,_,api=self.setup_case();api.verify('CONTROL');original=api.snapshot;calls=[]
        def capture(key):
            result=original(key);calls.append(key)
            if len(calls)==1:(b/'source/module.py').write_bytes(b'def replacement():\n    return 2\n')
            return result
        with patch.object(api,'snapshot',side_effect=capture):r=api.verify('CONTROL')
        self.assertEqual(r['status'],'FAIL');self.assertIn({'code':'SOURCE_CHANGED'},r['issues'])
        self.assertEqual(r['coverage']['passed'],0)
        self.assertFalse(any(c['status']=='SUPPORTED' for p in r['properties'] for c in p.get('STATIC_CLAIMS',[])))


if __name__=='__main__':unittest.main()
