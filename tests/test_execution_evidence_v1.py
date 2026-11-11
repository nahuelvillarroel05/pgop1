"""New synthetic controls only. Historical tests and goldens are untouched."""
import copy
import os
from pathlib import Path
import shutil
import tempfile
import unittest

from candidate.execution_contract_v1 import ROOT, CATALOG, PAYLOAD, canonical, digest, pin, code_paths, validate_catalog,closed_formulation
from candidate.execution_evidence_v1 import ExecutionEvidenceRunner
from tools.verify_execution_evidence_v1 import verify_bundle, query_bundle


def fixture(base, *, document=None, cases=None):
    source=base/'source';source.mkdir();config=base/'config';config.mkdir()
    doc=document or b'Observe a bounded execution in this run.\n'
    bodies={'DOC.md':doc,'payload.bin':b'synthetic immutable input\x00\xff'}
    for name,body in bodies.items():(source/name).write_bytes(body)
    pins=[dict(path=n,sha256=digest(b),kind='document' if n.endswith('.md') else 'file') for n,b in sorted(bodies.items())]
    static=dict(schema='pgop1.real-static-catalog.v2',profile='real-static-v2',
                catalog=dict(schema='pgop1.source-audit-catalog.v2',sources=pins,claims=[]),
                sources=[dict(path=p['path'],sha256=p['sha256'],bytes=len(bodies[p['path']]),version='synthetic-e1',
                         language='markdown' if p['kind']=='document' else 'bytes',scope='REGISTERED_FILE_ONLY') for p in pins])
    document_pin=dict(path='DOC.md',sha256=digest(doc),start_line=1,end_line=1,span_sha256=digest(doc.splitlines(keepends=True)[0]))
    specs=cases or [('exit','exit_zero','process_exit_observed',0),('wrong_exit','exit_seven','process_exit_observed',0),
      ('stderr','stderr_zero','process_exit_observed',0),('artifact','artifact_good','artifact_bytes_observed',pin(PAYLOAD)),
      ('wrong_artifact','artifact_good','artifact_bytes_observed',pin(b'wrong')),('missing','artifact_missing','artifact_bytes_observed',pin(PAYLOAD)),
      ('forged','forged_stdout','artifact_bytes_observed',pin(PAYLOAD)),('timeout','timeout','process_exit_observed',0),
      ('overflow','overflow','process_exit_observed',0),('roundtrip','snapshot_roundtrip','roundtrip_or_rejection_observed','ROUNDTRIP'),
      ('rejection','snapshot_rejection','roundtrip_or_rejection_observed','REJECTION'),('general','exit_zero','process_exit_observed',0)]
    rows=[dict(case_id=i,action=a,predicate=p,expected=e,document=document_pin,scope='GENERAL' if i=='general' else 'THIS_RUN_ONLY',
               formulation='In this identified run, observe the exact closed predicate '+p+'.') for i,a,p,e in specs]
    for row in rows:row['formulation']=closed_formulation(row)
    catalog=dict(schema=CATALOG,static_catalog=static,code_pins={n:digest((ROOT/n).read_bytes()) for n in code_paths()},
                 executable_sha256=digest((ROOT/'.venv/Scripts/python.exe').read_bytes()),cases=rows)
    path=config/'CATALOG.json';path.write_bytes(canonical(catalog));sha=digest(canonical(catalog))
    return source,path,sha,catalog


@unittest.skipUnless(os.name=='nt','Windows-only execution evidence')
class ExecutionEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='execution-v1-tests-');cls.base=Path(cls.tmp.name)
        cls.source,cls.path,cls.sha,cls.catalog=fixture(cls.base)
        cls.output=cls.base/'packet';cls.request='synthetic-tests'
        cls.ack=ExecutionEvidenceRunner(source_root=cls.source,catalog_path=cls.path,catalog_sha256=cls.sha).run(cls.output,request_id=cls.request)
        cls.anchor=cls.ack['trusted_run_sha256']
        cls.result,_=verify_bundle(cls.output,cls.sha,cls.anchor,cls.request)
        cls.rows={r['claim']['case_id']:r for r in cls.result['claims']}
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def test_observed_exit_exact_and_contradiction(self):
        self.assertEqual(self.rows['exit']['verdict'],'SUPPORTED');self.assertEqual(self.rows['wrong_exit']['verdict'],'CONTRADICTED')
        self.assertEqual(self.rows['wrong_exit']['observed'],7)
    def test_stderr_does_not_mean_failure(self):self.assertEqual(self.rows['stderr']['verdict'],'SUPPORTED')
    def test_observed_artifact_bytes_and_contradiction(self):
        self.assertEqual(self.rows['artifact']['verdict'],'SUPPORTED');self.assertEqual(self.rows['wrong_artifact']['verdict'],'CONTRADICTED')
    def test_missing_artifact_and_fake_stdout_abstain(self):
        for key in ('missing','forged'):self.assertEqual(self.rows[key]['verdict'],'INSUFFICIENT_EVIDENCE')
    def test_timeout_and_overflow_abstain(self):
        for key in ('timeout','overflow'):self.assertEqual(self.rows[key]['verdict'],'INSUFFICIENT_EVIDENCE')
    def test_general_guarantee_abstains(self):self.assertEqual(self.rows['general']['reason'],'GENERAL_GUARANTEE_NOT_PROVEN')
    def test_unrelated_exit_cannot_support_documentary_formulation(self):
        with tempfile.TemporaryDirectory(prefix='execution-unrelated-') as tmp:
            base=Path(tmp);source,path,sha,catalog=fixture(base,document=b'PGOP1 rejects every possible tampering of all files in this run.\n',cases=[('unrelated','exit_zero','process_exit_observed',0)])
            catalog['cases'][0]['formulation']='PGOP1 rejects every possible tampering of all files in this run.'
            path.write_bytes(canonical(catalog));sha=digest(path.read_bytes())
            ack=ExecutionEvidenceRunner(source_root=source,catalog_path=path,catalog_sha256=sha).run(base/'packet',request_id='unrelated')
            result,_=verify_bundle(base/'packet',sha,ack['trusted_run_sha256'],'unrelated')
            self.assertEqual(result['claims'][0]['verdict'],'INSUFFICIENT_EVIDENCE')
            self.assertEqual(result['claims'][0]['reason'],'FORMULATION_OUTSIDE_CLOSED_CONTRACT')
            self.assertEqual(result['claims'][0]['documentary_claim_verdict'],'NOT_PROVEN')
    def test_roundtrip_and_exact_rejection(self):
        for key in ('roundtrip','rejection'):self.assertEqual(self.rows[key]['verdict'],'SUPPORTED')
    def test_caller_anchor_and_request_replay(self):
        for sha,anchor,request in [('0'*64,self.anchor,self.request),(self.sha,'0'*64,self.request),(self.sha,self.anchor,'another-request')]:
            with self.assertRaises(ValueError):verify_bundle(self.output,sha,anchor,request)
    def test_rehashed_forgery_cannot_replace_external_anchor(self):
        with tempfile.TemporaryDirectory(prefix='execution-forgery-') as tmp:
            target=Path(tmp)/'copy';shutil.copytree(self.output,target)
            receipt=__import__('json').loads((target/'RECEIPT.json').read_bytes());receipt['cases'][0]['steps'][0]['close']['exit_code']=99
            raw=canonical(receipt);(target/'RECEIPT.json').write_bytes(raw)
            manifest=__import__('json').loads((target/'MANIFEST.json').read_bytes());manifest['files']['RECEIPT.json']=pin(raw)
            (target/'MANIFEST.json').write_bytes(canonical(manifest))
            with self.assertRaises(ValueError):verify_bundle(target,self.sha,self.anchor,self.request)
    def test_receipt_metadata_types_reject_even_with_new_test_anchor(self):
        for mode in ('timeout','environment','timestamps'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory(prefix='execution-metadata-') as tmp:
                target=Path(tmp)/'copy';shutil.copytree(self.output,target)
                import json
                receipt=json.loads((target/'RECEIPT.json').read_bytes());step=receipt['cases'][0]['steps'][0]
                if mode=='timeout':step['start']['timeout_seconds']=True
                elif mode=='environment':step['start']['env_allowlist'].update(TEMP=7,TMP={},PYTHONIOENCODING=False)
                else:step['start']['started_at']='fabricated-time';step['close']['ended_at']=[]
                changed={'RECEIPT.json':canonical(receipt),step['prefix']+'.START.json':canonical(step['start']),step['prefix']+'.CLOSE.json':canonical(step['close'])}
                manifest=json.loads((target/'MANIFEST.json').read_bytes())
                for name,body in changed.items():(target/name).write_bytes(body);manifest['files'][name]=pin(body)
                (target/'MANIFEST.json').write_bytes(canonical(manifest));new_test_anchor=digest(canonical(manifest))
                with self.assertRaises(ValueError):verify_bundle(target,self.sha,new_test_anchor,self.request)
    def test_extra_file_rejected_before_page(self):
        with tempfile.TemporaryDirectory(prefix='execution-membership-') as tmp:
            target=Path(tmp)/'copy';shutil.copytree(self.output,target);(target/'extra.bin').write_bytes(b'injected')
            with self.assertRaisesRegex(ValueError,'DIRECTORY_MEMBERSHIP'):query_bundle(target,self.sha,self.anchor,self.request)
    def test_memory_pagination_no_loss(self):
        rows=[];offset=0
        while True:
            page=query_bundle(self.output,self.sha,self.anchor,self.request,offset=offset,limit=5);rows+=page['items']
            if page['next_offset'] is None:break
            offset=page['next_offset']
        self.assertEqual(canonical(rows),canonical(self.result['claims']))
    def test_bool_int_and_unknown_command_admission(self):
        for field,value in [('expected',True),('action','powershell')]:
            catalog=copy.deepcopy(self.catalog);catalog['cases'][0][field]=value
            with self.assertRaises(ValueError):validate_catalog(catalog,digest(canonical(catalog)))
    def test_python_kind_demo_rejected(self):
        catalog=copy.deepcopy(self.catalog)
        p=next(p for p in catalog['static_catalog']['catalog']['sources'] if p['kind']=='file');p['kind']='python'
        next(s for s in catalog['static_catalog']['sources'] if s['path']==p['path'])['language']='python'
        with self.assertRaisesRegex(ValueError,'DEMO_NO_AST_DESCENDANTS'):validate_catalog(catalog,digest(canonical(catalog)))
    def test_source_change_before_launch_rejected(self):
        with tempfile.TemporaryDirectory(prefix='execution-stale-') as tmp:
            base=Path(tmp);source,path,sha,_=fixture(base,cases=[('one','exit_zero','process_exit_observed',0)])
            (source/'payload.bin').write_bytes(b'changed')
            with self.assertRaises(ValueError):ExecutionEvidenceRunner(source_root=source,catalog_path=path,catalog_sha256=sha).run(base/'packet',request_id='stale')
            self.assertFalse((base/'packet').exists())
    def test_output_collision_never_overwrites(self):
        original=(self.output/'MANIFEST.json').read_bytes()
        with self.assertRaises(ValueError):ExecutionEvidenceRunner(source_root=self.source,catalog_path=self.path,catalog_sha256=self.sha).run(self.output,request_id=self.request)
        self.assertEqual((self.output/'MANIFEST.json').read_bytes(),original)
    def test_duplicate_and_nonfinite_json_rejected(self):
        from candidate.document_claims_v1 import strict_json
        for raw in (b'{"x":1,"x":2}',b'{"x":NaN}'):
            with self.assertRaises(ValueError):strict_json(raw)

if __name__=='__main__':unittest.main()
