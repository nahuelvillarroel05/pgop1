"""Compatibility goldens captured from the untouched anchored Ubuntu baseline."""
import hashlib
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(ROOT / 'runtime'))
from candidate.evidence_handoff import _static_properties


class LegacyParityTests(unittest.TestCase):
    def test_exact_legacy_output_goldens(self):
        cases = [b'x=1\ndef f():\n return x\n',
                 ''.join(f'def f{i:03}():\n return {i}\n' for i in range(400)).encode(),
                 (ROOT/'runtime/candidate/pg_i7.py').read_bytes(), b'def (']
        expected = ['802ea088aad2771e2b31ba94aa153bece72305f307140e9a56875537f23e884d',
                    '7b883580e50f4b84aeac070ce058d58733fc74f8d47243ca7f2d2791130a5db7',
                    'e66212c98d69e466e8995d619dd3d2445b521b80363fe90de692ce5e206be6a9',
                    '84146c3f916f084a0cb99aee9802e1e92c22de13eef66261e17ca8a33c06d986']
        for raw, golden in zip(cases, expected):
            with self.subTest(source=hashlib.sha256(raw).hexdigest()):
                row = {'input_sha256': hashlib.sha256(raw).hexdigest(),
                       'v1': _static_properties(raw, 'python', []),
                       'legacy_inventory': _static_properties(raw, 'python', [], inventory=True)}
                # The declared interpreter version is environmental metadata.
                for key in ('v1', 'legacy_inventory'):
                    row[key].pop('python_version')
                body = json.dumps(row, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()
                self.assertEqual(hashlib.sha256(body).hexdigest(), golden)


class IndependentVerifierTests(unittest.TestCase):
    def test_source_based_verification_and_forged_snapshot(self):
        import copy
        import tempfile
        from runtime.candidate.static_ast_v2 import analyze_source, canonical, digest
        sys.path.insert(0,str(ROOT/'tools'))
        from verify_source_v2 import verify_structure
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            body = b'class A:\n def m(self):\n  return f()()\nclass B:\n def m(self):\n  pass\n'
            (root/'x.py').write_bytes(body)
            report = analyze_source(root,'x.py',digest(body))
            self.assertEqual(verify_structure(root,report)['verified'],'SOURCE_NODES_SCOPES_COVERAGE_RELATIONS')
            for key in ('declarations','relations'):
                altered = copy.deepcopy(report)
                altered[key].pop()
                altered['snapshot_id'] = digest(canonical({k:v for k,v in altered.items() if k not in ('snapshot_id','execution_metrics')}))
                with self.assertRaises(ValueError):
                    verify_structure(root,altered)
            (root/'x.py').write_bytes(body+b'# changed\n')
            with self.assertRaises(ValueError):
                verify_structure(root,report)

    def test_forged_metadata_and_execution_are_rejected(self):
        import copy
        import tempfile
        from runtime.candidate.static_ast_v2 import analyze_source,canonical,digest,validate_report
        sys.path.insert(0,str(ROOT/'tools'))
        from verify_source_v2 import verify_structure
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            raw = b'def actual():\n pass\n'
            (root/'x.py').write_bytes(raw)
            report = analyze_source(root,'x.py',digest(raw))
            for field,value in [('name','forged'),('qualified_name','forged'),('line',999),('column',999),('node','ClassDef'),('conditional',True),('decorated',True)]:
                forged = copy.deepcopy(report)
                for row in forged['units'] + forged['declarations']:
                    if row['node'] != 'Module':
                        row[field] = value
                forged['snapshot_id'] = digest(canonical({k:v for k,v in forged.items() if k not in ('snapshot_id','execution_metrics')}))
                with self.subTest(field=field), self.assertRaises(ValueError):
                    verify_structure(root,forged)
            for field,value in [('execution','PERFORMED_SUCCESSFULLY'),('behavior','FUNCTIONAL_CORRECTNESS_PROVEN')]:
                forged = copy.deepcopy(report)
                forged[field] = value
                forged['snapshot_id'] = digest(canonical({k:v for k,v in forged.items() if k not in ('snapshot_id','execution_metrics')}))
                with self.assertRaises(ValueError):
                    validate_report(forged)
                with self.assertRaises(ValueError):
                    verify_structure(root,forged)

    def test_missing_page_cannot_verify_complete_inventory(self):
        import tempfile
        from runtime.candidate.static_ast_v2 import analyze_source,page,digest
        sys.path.insert(0,str(ROOT/'tools'))
        from verify_source_v2 import verify_pages
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            raw=b'def a():pass\ndef b():pass\ndef c():pass\n'
            (root/'x.py').write_bytes(raw)
            report=analyze_source(root,'x.py',digest(raw))
            first=page(report,limit=1)
            second=page(report,cursor=first['cursor'],limit=1)
            last=page(report,cursor=second['cursor'],limit=1)
            self.assertEqual(verify_pages(report,[first,second,last])[0]['items'],3)
            with self.assertRaises(ValueError):verify_pages(report,[first,last])
            with self.assertRaises(ValueError):verify_pages(report,[first,second])

    def test_transport_handles_inventory_larger_than_a_page(self):
        import tempfile
        from runtime.candidate.static_ast_v2 import analyze_source,canonical,digest,page
        sys.path.insert(0,str(ROOT/'tools'))
        from verify_source_v2 import verify_structure
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            # Repeated lexical chains amplify metadata without exceeding source budgets.
            lines=[]
            for depth in range(90):
                lines.append(' '*depth+'def '+('a'*117+f'{depth:03}')+'():')
            lines.extend(' '*90+'def f():pass' for _ in range(1200))
            raw=('\n'.join(lines)+'\n').encode()
            (root/'x.py').write_bytes(raw)
            report=analyze_source(root,'x.py',digest(raw),budgets={'output_bytes':4_000_000})
            self.assertEqual(report['status'],'COMPLETE')
            self.assertEqual(report['total_detected'],1290)
            self.assertGreater(len(canonical({k:v for k,v in report.items() if k!='execution_metrics'})),64_000_000)
            self.assertEqual(verify_structure(root,report)['declarations'],1290)
            cursor=None
            total=0
            while True:
                chunk=page(report,cursor=cursor,limit=37)
                total+=chunk['returned']
                cursor=chunk['cursor']
                if cursor is None:break
            self.assertEqual(total,1290)

    def test_combining_unicode_identifiers_follow_declared_policy(self):
        import tempfile
        from runtime.candidate.static_ast_v2 import analyze_source,digest
        sys.path.insert(0,str(ROOT/'tools'))
        from verify_source_v2 import verify_structure
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            raw='import a\u0332 as b\u0332\ndef a\u0332():\n a\u0332()\n'.encode()
            (root/'x.py').write_bytes(raw)
            report=analyze_source(root,'x.py',digest(raw))
            self.assertEqual(verify_structure(root,report)['status'],'COMPLETE')

    def test_partial_scope_verified_without_absence(self):
        import tempfile
        from runtime.candidate.static_ast_v2 import analyze_source,digest
        sys.path.insert(0,str(ROOT/'tools'))
        from verify_source_v2 import verify_structure
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            body = ('def big():\n'+' x=1\n'*20+'def small():\n pass\n').encode()
            (root/'x.py').write_bytes(body)
            report = analyze_source(root,'x.py',digest(body),budgets={'unit_nodes':10})
            self.assertEqual(verify_structure(root,report)['status'],'PARTIAL')

class IndependentDocumentVerifierTests(unittest.TestCase):
    def fixture(self, root):
        from runtime.candidate.document_claims_v1 import make_claim,typed,audit_catalog
        from runtime.candidate.static_ast_v2 import digest
        (root/'DOC.md').write_bytes(b'Fixture N=7, function present; no behavior promised.\n')
        (root/'x.py').write_bytes(b'N=7\nOPERATIONS=("verify",)\ndef present():\n pass\n')
        document={'path':'DOC.md','sha256':digest((root/'DOC.md').read_bytes()),'start_line':1,'end_line':1,
                  'span_sha256':digest((root/'DOC.md').read_bytes())}
        source={'path':'x.py','sha256':digest((root/'x.py').read_bytes())}
        claims=[make_claim('constant_equal',document,source,{'scope':'<module>','name':'N','definition_line':1},typed(7)),
                make_claim('public_operation_declared',document,source,{'scope':'<module>','name':'OPERATIONS','definition_line':2,'operation':'verify'},typed(True)),
                make_claim('symbol_defined',document,source,{'scope':'<module>','name':'absent'},typed(False)),
                make_claim('declared_file_exists',document,source,{},typed(True))]
        catalog={'schema':'pgop1.source-audit-catalog.v2','sources':[{k:document[k] for k in ('path','sha256')}|{'kind':'document'},source|{'kind':'python'}],
                 'claims':claims}
        return audit_catalog(root,catalog)

    def test_independent_claim_verdict_and_evidence_tampering(self):
        import copy,tempfile
        sys.path.insert(0,str(ROOT/'tools'))
        from verify_source_v2 import verify_report
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);report=self.fixture(root)
            self.assertEqual(verify_report(root,report)['source_integrity'],'PASS')
            for label in ('verdict','evidence','span','document_link','typed_location'):
                bad=copy.deepcopy(report);row=bad['document_claims']['claims'][0]
                if label=='verdict':row['verdict']='CONTRADICTED'
                elif label=='evidence':row['evidence'][0]['sha256']='0'*64
                elif label=='span':row['claim']['document']['span_sha256']='0'*64
                elif label=='document_link':row['claim']['document']['path']='x.py'
                else:row['evidence'][0]['line']=True
                with self.subTest(label=label),self.assertRaises(ValueError):verify_report(root,bad)

    def test_artifact_rehash_cannot_hide_semantic_tampering(self):
        import copy,tempfile
        sys.path.insert(0,str(ROOT/'tools'))
        from audit_source_v2 import write_artifacts
        from verify_source_v2 import read_artifacts,verify_report
        from runtime.candidate.static_ast_v2 import canonical,digest
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);root=base/'source';root.mkdir();report=self.fixture(root)
            output=base/'artifacts';write_artifacts(root,output,report)
            read,meta=read_artifacts(output)
            self.assertEqual(verify_report(root,read)['status'],'PASS')
            altered=copy.deepcopy(report);altered['document_claims']['claims'][0]['verdict']='CONTRADICTED'
            raw=canonical(altered)+b'\n';(output/'REPORT.json').write_bytes(raw)
            manifest=json.loads((output/'MANIFEST.json').read_bytes())
            manifest['files']['REPORT.json']={'bytes':len(raw),'sha256':digest(raw)}
            (output/'MANIFEST.json').write_bytes(canonical(manifest)+b'\n')
            read,meta=read_artifacts(output)
            with self.assertRaises(ValueError):verify_report(root,read)
            manifest['files']['../escape']={'bytes':0,'sha256':digest(b'')}
            (output/'MANIFEST.json').write_bytes(canonical(manifest)+b'\n')
            with self.assertRaises(ValueError):read_artifacts(output)

    def test_rehashed_catalog_cannot_relabel_document_span(self):
        import copy,tempfile
        from runtime.candidate.static_ast_v2 import canonical,digest
        from runtime.candidate.document_claims_v1 import claim_identity
        sys.path.insert(0,str(ROOT/'tools'))
        from verify_source_v2 import verify_report
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);report=self.fixture(root)
            bad=copy.deepcopy(report)
            # Keep all claim/catalog commitments coherent while making the cited span false.
            target=bad['catalog']['claims'][0]
            old_id=target['claim_id'];target['document']['span_sha256']='0'*64
            target['claim_id']=claim_identity(target)
            for row in bad['document_claims']['claims']:
                if row['claim']['claim_id']==old_id:row['claim']=copy.deepcopy(target)
            bad['catalog']['claims'].sort(key=lambda c:c['claim_id'])
            bad['document_claims']['claims'].sort(key=lambda r:r['claim']['claim_id'])
            bad['catalog_sha256']=digest(canonical(bad['catalog']))
            with self.assertRaises(ValueError):verify_report(root,bad)

    def test_source_failure_remains_separate_from_report_verification(self):
        import tempfile
        from runtime.candidate.document_claims_v1 import audit_catalog
        sys.path.insert(0,str(ROOT/'tools'))
        from verify_source_v2 import verify_report
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);original=self.fixture(root)
            (root/'x.py').write_bytes(b'N=8\n')
            report=audit_catalog(root,original['catalog'])
            result=verify_report(root,report)
            self.assertEqual(result['status'],'PASS')
            self.assertEqual(result['source_integrity'],'FAILED_PINS_WITH_VERIFIED_ABSTENTIONS')
            self.assertTrue(all(c['verdict']=='INSUFFICIENT_EVIDENCE' for c in result['claims']))
            report['document_claims']['source_errors']=[]
            with self.assertRaises(ValueError):verify_report(root,report)


class IndependentContractTypeTests(unittest.TestCase):
    def test_boolean_counts_and_invalid_unknown_budgets_rejected(self):
        import copy,tempfile
        from runtime.candidate.static_ast_v2 import analyze_source,canonical,digest
        sys.path.insert(0,str(ROOT/'tools'))
        from verify_source_v2 import verify_structure
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'empty.py').write_bytes(b'')
            report=analyze_source(root,'empty.py',digest(b''))
            for container,key in [('coverage','observed_nodes'),('coverage','total_nodes'),('coverage','max_observed_depth'),
                                  ('coverage','pending_units'),('report','returned'),('report','units_complete'),
                                  ('unit','owned_nodes'),('unit','line')]:
                altered=copy.deepcopy(report)
                target=altered['AST_COVERAGE'] if container=='coverage' else altered['units'][0] if container=='unit' else altered
                target[key]=bool(target[key])
                altered['snapshot_id']=digest(canonical({k:v for k,v in altered.items() if k not in ('snapshot_id','execution_metrics')}))
                with self.subTest(container=container,key=key),self.assertRaises(ValueError):verify_structure(root,altered)
            altered=copy.deepcopy(report);altered.update(status='RESOURCE_ERROR',PYTHON_SYNTAX='UNKNOWN',units=[],declarations=[],relations=[])
            altered['AST_COVERAGE']['status']='RESOURCE_ERROR';altered['budgets']['nodes']=True
            altered['snapshot_id']=digest(canonical({k:v for k,v in altered.items() if k not in ('snapshot_id','execution_metrics')}))
            with self.assertRaises(ValueError):verify_structure(root,altered)


class IndependentAdmissionAndRelationTests(unittest.TestCase):
    def test_relation_reason_extra_fields_and_base_index_forgery(self):
        import copy,tempfile
        from runtime.candidate.static_ast_v2 import analyze_source,canonical,digest
        sys.path.insert(0,str(ROOT/'tools'))
        from verify_source_v2 import verify_structure
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);raw=b'class A(X,Y):\n def m(self):\n  return f()\n'
            (root/'x.py').write_bytes(raw)
            report=analyze_source(root,'x.py',digest(raw))
            self.assertEqual(verify_structure(root,report)['status'],'COMPLETE')
            for mode in ('reason','extra','base_index','envelope'):
                forged=copy.deepcopy(report)
                if mode=='reason':forged['relations'][0]['reason']='PROVEN_EXECUTION'
                elif mode=='extra':forged['relations'][0]['runtime_target']='guaranteed'
                elif mode=='base_index':next(e for e in forged['relations'] if e['kind']=='inherits')['base_index']=999
                else:forged['security']='PASS'
                forged['snapshot_id']=digest(canonical({k:v for k,v in forged.items() if k not in ('snapshot_id','execution_metrics')}))
                with self.subTest(mode=mode),self.assertRaises(ValueError):verify_structure(root,forged)

    def test_page_file_symlink_and_size_admission(self):
        import subprocess,tempfile
        from runtime.candidate.static_ast_v2 import analyze_source,canonical,digest
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'x.py').write_bytes(b'')
            report=analyze_source(root,'x.py',digest(b''))
            (root/'report.json').write_bytes(canonical(report))
            (root/'actual.json').write_bytes(b'[]')
            (root/'link.json').symlink_to(root/'actual.json')
            with (root/'large.json').open('wb') as stream:stream.truncate(512_000_001)
            for name in ('link.json','large.json'):
                result=subprocess.run([sys.executable,str(ROOT/'tools/verify_source_v2.py'),'--source-root',str(root),'--report',str(root/'report.json'),'--pages',str(root/name)],capture_output=True,timeout=10)
                self.assertEqual(result.returncode,1)
                self.assertEqual(json.loads(result.stdout)['reason'],'ARTIFACT_VERIFICATION_FAILED')
                self.assertEqual(result.stderr,b'')


if __name__ == '__main__':
    unittest.main()
