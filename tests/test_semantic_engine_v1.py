"""Independent opt-in integration tests; historical tests are unchanged."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import audit_snapshot_v1 as snapshot
from tools import verify_semantic_engine_v1 as verifier
from candidate.semantic_engine_v1 import RealStaticV2Profile
from candidate.static_ast_v2 import canonical, digest
from candidate.document_claims_v1 import make_claim, typed

ROOT = Path(__file__).absolute().parents[1]


@unittest.skipUnless(os.name == 'nt','Windows-only integration intervention')
class SemanticIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='sem-test-'); self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.source = self.base/'source'; self.source.mkdir()
        self.config = self.base/'config'; self.config.mkdir()
        self.code = b'N=7\ndef original():\n return N\n'
        self.doc = b'N is seven.\nN is eight.\nUnknown scope.\n'
        self.configure()

    def configure(self):
        (self.source/'x.py').write_bytes(self.code); (self.source/'DOC.md').write_bytes(self.doc)
        source = dict(path='x.py',sha256=digest(self.code))
        def claim(line,expected,scope='<module>'):
            span = self.doc.splitlines(keepends=True)[line-1]
            document = dict(path='DOC.md',sha256=digest(self.doc),start_line=line,end_line=line,span_sha256=digest(span))
            return make_claim('constant_equal',document,source,dict(scope=scope,name='N',definition_line=1),typed(expected))
        pins = [dict(path='DOC.md',sha256=digest(self.doc),kind='document'),dict(source,kind='python')]
        claims = [claim(1,7),claim(2,8),claim(3,7,'missing')]
        self.catalog = dict(schema=verifier.CATALOG,profile='real-static-v2',
                            catalog=dict(schema='pgop1.source-audit-catalog.v2',sources=pins,claims=sorted(claims,key=lambda r:r['claim_id'])),
                            sources=[dict(path=p['path'],sha256=p['sha256'],bytes=len(self.doc if p['kind']=='document' else self.code),
                                          version='fixture-1',language='markdown' if p['kind']=='document' else 'python',scope='REGISTERED_FILE_ONLY') for p in pins])
        self.save_catalog()

    def save_catalog(self):
        self.raw = canonical(self.catalog); self.sha = digest(self.raw)
        self.path = self.config/'catalog.json'; self.path.write_bytes(self.raw)
        self.profile = RealStaticV2Profile(source_root=self.source,catalog_path=self.path,catalog_sha256=self.sha)
        self.output = self.base/'artifacts'

    def produce(self):
        return self.profile.generate(self.output)

    def rehash(self,name,value):
        raw = canonical(value); (self.output/name).write_bytes(raw)
        manifest = json.loads((self.output/'MANIFEST.json').read_bytes())
        manifest['files'][name] = dict(bytes=len(raw),sha256=digest(raw))
        (self.output/'MANIFEST.json').write_bytes(canonical(manifest))

    def cli(self,operation,*args):
        return subprocess.run([sys.executable,str(ROOT/'tools/semantic_engine_v1.py'),
                               '--catalog-sha256',self.sha,operation,*map(str,args)],cwd=ROOT,capture_output=True)

    def test_supported_contradicted_abstained_and_literal_binding(self):
        ack=self.produce(); self.assertTrue(ack['operation_completed'])
        envelope,rows=verifier.verify_bundle(self.output,self.sha)
        self.assertEqual({r['verdict'] for r in envelope['claims']},{'SUPPORTED','CONTRADICTED','INSUFFICIENT_EVIDENCE'})
        self.assertEqual(len(rows),7)
        for row in envelope['claims']:
            self.assertEqual(digest(bytes.fromhex(row['literal_span_hex'])),row['claim']['document']['span_sha256'])
        self.assertEqual(envelope['scope']['source_current_at_ack'],'NOT_PROVEN')
        self.assertEqual(envelope['scope']['relationship_mapping'],'PAYLOAD_ONLY_NO_ENGINE_EDGES')

    def test_distinct_processes_deterministic_semantics_recovery_without_sources(self):
        first=self.cli('generate','--source-root',self.source,'--catalog',self.path,'--output',self.output)
        self.assertEqual(first.returncode,0,first.stderr+first.stdout)
        second=self.base/'artifacts2'
        p=self.cli('generate','--source-root',self.source,'--catalog',self.path,'--output',second)
        self.assertEqual(p.returncode,0,p.stderr+p.stdout)
        self.assertEqual((self.output/'INTEGRATION.json').read_bytes(),(second/'INTEGRATION.json').read_bytes())
        self.assertEqual(json.loads(first.stdout)['integration_id'],json.loads(p.stdout)['integration_id'])
        (self.source/'x.py').unlink(); (self.source/'DOC.md').unlink()
        for operation in ('verify','query'):
            proc=self.cli(operation,'--artifacts',self.output)
            self.assertEqual(proc.returncode,0,proc.stderr+proc.stdout)
        self.assertEqual(self.profile.verify(self.output)['scope']['source_state'],'COMMITTED_SNAPSHOT')
        self.assertEqual(self.profile.query(self.output,kind='currency')['status'],'INSUFFICIENT_EVIDENCE')

    def test_changed_source_new_identity_old_snapshot_immutable(self):
        old=self.produce(); original=(self.output/'INTEGRATION.json').read_bytes()
        self.code=b'N=9\ndef original(): return N\n'; self.configure(); self.output=self.base/'new'
        new=self.produce()
        self.assertNotEqual(old['integration_id'],new['integration_id'])
        self.assertEqual((self.base/'artifacts/INTEGRATION.json').read_bytes(),original)

    def test_rehashed_integration_verdict_literal_metadata_and_link_rejected(self):
        self.produce(); original=json.loads((self.output/'INTEGRATION.json').read_bytes())
        for field in ('verdict','literal','metadata','link','bool_line'):
            value=copy.deepcopy(original)
            if field=='verdict': value['claims'][0]['verdict']='SUPPORTED' if value['claims'][0]['verdict']!='SUPPORTED' else 'CONTRADICTED'
            elif field=='literal': value['claims'][0]['literal_span_hex']='00'
            elif field=='metadata': value['sources'][0]['version']='forged'
            elif field=='bool_line': value['sources'][0]['start_line']=True
            else: value['claims'][0]['evidence_snapshot_id']='0'*64
            self.rehash('INTEGRATION.json',value)
            with self.assertRaises(ValueError): verifier.verify_bundle(self.output,self.sha)
        self.rehash('INTEGRATION.json',original)
        verifier.verify_bundle(self.output,self.sha)

    def test_report_snapshot_and_external_catalog_rehash_rejected(self):
        self.produce()
        for name in ('REPORT.json','SNAPSHOT.json','CATALOG.json','SNAPSHOT_MANIFEST.json'):
            original=json.loads((self.output/name).read_bytes()); value=copy.deepcopy(original)
            if name=='REPORT.json': value['document_claims']['claims'][0]['verdict']='FORGED'
            elif name=='SNAPSHOT.json': value['captures'][0]['raw_hex']='00'*value['captures'][0]['bytes']
            elif name=='SNAPSHOT_MANIFEST.json': value['files']['FINAL_HANDOFF.md']['bytes']=float(value['files']['FINAL_HANDOFF.md']['bytes'])
            else: value['sources'][0]['version']='forged'
            self.rehash(name,value)
            with self.assertRaises(ValueError): verifier.verify_bundle(self.output,self.sha)
            self.rehash(name,original)
        with self.assertRaises(ValueError): verifier.verify_bundle(self.output,'0'*64)

    def test_archive_traversal_membership_and_corruption_rejected(self):
        self.produce(); original=json.loads((self.output/'MEMORY.json').read_bytes())
        for mode in ('traversal','missing','corrupt'):
            value=copy.deepcopy(original); name=next(iter(value['files']))
            if mode=='traversal': value['files']['../escape']=value['files'].pop(name)
            elif mode=='missing': value['files'].pop(name)
            else: value['files'][name]='00'
            self.rehash('MEMORY.json',value)
            with self.assertRaises((ValueError,KeyError)): verifier.verify_bundle(self.output,self.sha)
        self.assertFalse((self.base/'escape').exists())

    def test_independent_audit_rehashed_manifest_fields_and_bool_versions_rejected(self):
        from candidate.context_engine import canonical_json
        self.produce(); original=json.loads((self.output/'MEMORY.json').read_bytes())
        for mode in ('extra','bool_manifest','bool_graph','bool_provenance','bool_record','bool_observation','float_descriptor'):
            value=copy.deepcopy(original); files=value['files']
            prefix=next(n.rsplit('/',1)[0] for n in files if n.endswith('/manifest.json'))
            manifest=json.loads(bytes.fromhex(files[prefix+'/manifest.json']))
            graph=json.loads(bytes.fromhex(files[prefix+'/graph.json']))
            provenance=json.loads(bytes.fromhex(files[prefix+'/provenance.json']))
            if mode=='extra': manifest.update(source_current_at_ack='PASS',independent_custody='PROVEN')
            if mode=='bool_manifest': manifest['version']=True
            if mode=='bool_graph': graph['version']=True
            if mode=='bool_provenance': provenance['graph_version']=True
            if mode=='bool_record': provenance['records'][0]['graph_version']=True
            if mode=='bool_observation':
                row=next(r for r in graph['observations'] if r['kind']=='sources')
                row['value']['start_line']=True
            if mode=='float_descriptor':
                name=next(n for n in files if n.startswith('sources/'))
                descriptor=json.loads(bytes.fromhex(files.pop(name)))
                descriptor['byte_length']=float(descriptor['byte_length'])
                raw=canonical_json(descriptor)
                files['sources/'+digest(raw)+'.json']=raw.hex()
                graph['sources']=[descriptor]
            graph_raw=canonical_json(graph); graph_sha=digest(graph_raw)
            provenance['graph_sha256']=graph_sha
            for row in provenance['records']: row['graph_sha256']=graph_sha
            prov_raw=canonical_json(provenance)
            manifest.update(graph_sha256=graph_sha,provenance_sha256=digest(prov_raw))
            for name in list(files):
                if name.startswith(prefix+'/'): del files[name]
            new_prefix='versions/00000001-'+graph_sha
            for name,raw in [('graph.json',graph_raw),('provenance.json',prov_raw),('manifest.json',canonical_json(manifest))]:
                files[new_prefix+'/'+name]=raw.hex()
            self.rehash('MEMORY.json',value)
            with self.assertRaisesRegex(ValueError,'MEMORY_VERSION_|MEMORY_OBSERVATION|MEMORY_SOURCE_SCOPE'): verifier.verify_bundle(self.output,self.sha)

    def test_output_collision_and_source_or_catalog_membership_rejected(self):
        self.produce(); original=(self.output/'MANIFEST.json').read_bytes()
        with self.assertRaises(OSError): self.produce()
        self.assertEqual((self.output/'MANIFEST.json').read_bytes(),original)
        for parent in (self.source,self.config,ROOT):
            with self.assertRaises(ValueError): self.profile.generate(parent/'forbidden-semantic-output')
            self.assertFalse((parent/'forbidden-semantic-output').exists())

    def test_metadata_size_mismatch_has_no_final_output(self):
        self.catalog['sources'][0]['bytes']+=1; self.save_catalog()
        with self.assertRaisesRegex(ValueError,'REAL_SOURCE_SIZE'): self.produce()
        self.assertFalse(self.output.exists())

    def test_dynamic_literal_abstains_no_causal_edges(self):
        self.code=b'N=7\nvars()["N"]=8\nclass A:\n def same(self): return getattr(self,"f")()\nclass A:\n def same(self): return external()\n'
        self.configure(); self.produce()
        envelope,_=verifier.verify_bundle(self.output,self.sha)
        self.assertTrue(all(r['verdict']=='INSUFFICIENT_EVIDENCE' for r in envelope['claims']))
        structure=envelope['structures'][0]
        self.assertEqual(len([d for d in structure['declarations'] if d['name']=='same']),2)
        for r in structure['relations']:
            if r['kind']=='calls': self.assertIn(r['resolution'],('AMBIGUOUS','UNRESOLVED'))

    def test_400_functions_paginate_without_loss(self):
        self.code=b'N=7\n'+b''.join(f'def f{i}(): return {i}\n'.encode() for i in range(400))
        self.configure(); self.produce()
        found=[]; offset=0
        while True:
            page=self.profile.query(self.output,kind='declarations',source='x.py',offset=offset,limit=100)
            found.extend(page['items'])
            if page['next_offset'] is None: break
            offset=page['next_offset']
        self.assertEqual(len(found),400); self.assertEqual(len({r['id'] for r in found}),400)

    def test_mutation_after_capture_before_ack_keeps_historical_bytes(self):
        original=snapshot.audit_catalog
        def mutate(*args,**kwargs):
            (self.source/'x.py').write_bytes(b'N=8\n')
            return original(*args,**kwargs)
        with patch.object(snapshot,'audit_catalog',side_effect=mutate): self.produce()
        envelope,_=verifier.verify_bundle(self.output,self.sha)
        self.assertEqual(envelope['sources'][1]['sha256'],digest(self.code))
        self.assertIn('SUPPORTED',{r['verdict'] for r in envelope['claims']})
        self.assertEqual(envelope['scope']['artifact_current_at_ack'],'NOT_PROVEN')

    def test_publication_failure_is_not_ack_or_retry(self):
        from candidate import windows_safe_io_v2 as w
        original=w.safe_create_artifacts
        def fail(source,output,files,*args):
            if Path(output)==self.output:
                raise OSError('injected before final publication')
            return original(source,output,files,*args)
        with patch.object(w,'safe_create_artifacts',side_effect=fail):
            with self.assertRaises(OSError): self.produce()
        self.assertFalse(self.output.exists())

    def test_partial_scope_does_not_support_or_contradict_absence(self):
        self.code=b'N=7\n'+b'x=1\n'*3200
        self.configure(); self.produce()
        envelope,_=verifier.verify_bundle(self.output,self.sha)
        self.assertEqual(envelope['structures'][0]['status'],'PARTIAL')
        self.assertTrue(all(r['verdict']=='INSUFFICIENT_EVIDENCE' for r in envelope['claims']))
        self.assertIn(envelope['sources'][1]['coverage']['status'],('PARTIAL','BUDGET_EXCEEDED'))

    def test_duplicate_source_and_claim_rejected(self):
        for field in ('sources','claims'):
            original=copy.deepcopy(self.catalog)
            self.catalog['catalog'][field].append(self.catalog['catalog'][field][0])
            self.save_catalog()
            with self.assertRaises(ValueError): self.produce()
            self.assertFalse(self.output.exists()); self.catalog=original

    def test_unsafe_paths_rejected_and_rename_blocked_through_publication(self):
        from candidate import windows_safe_io_v2 as w
        for suffix in ('../escape','bad.','NUL','bad:stream'):
            with self.assertRaises(ValueError): self.profile.generate(str(self.base)+'\\'+suffix)
        original=w.safe_create_artifacts; attempted=[]
        def checked(source,output,files,*args):
            if Path(output)==self.output:
                for path in (self.source,self.config,self.base):
                    with self.assertRaises(OSError): path.rename(path.with_name(path.name+'-moved'))
                    attempted.append(str(path))
            return original(source,output,files,*args)
        with patch.object(w,'safe_create_artifacts',side_effect=checked): self.produce()
        self.assertEqual(len(attempted),3)

    def test_hardlinked_source_and_artifact_rejected(self):
        os.link(self.source/'x.py',self.base/'hardlink.py')
        with self.assertRaises(ValueError): self.produce()
        self.assertFalse(self.output.exists()); (self.base/'hardlink.py').unlink()
        self.produce(); os.link(self.output/'REPORT.json',self.base/'report-hardlink.json')
        with self.assertRaises(ValueError): verifier.verify_bundle(self.output,self.sha)

    def test_all_predicates_and_unsupported_partial_controls(self):
        self.code=b'N=7\nOPS=("read", "verify")\ndef original(): return N\n'
        self.configure()
        old=self.catalog['catalog']['claims'][0]
        document=old['document']; source=old['source']
        extra=[make_claim('public_operation_declared',document,source,
                          dict(scope='<module>',name='OPS',definition_line=2,operation='verify'),typed(True)),
               make_claim('declared_file_exists',document,source,{},typed(True)),
               make_claim('symbol_defined',document,source,dict(scope='<module>',name='absent'),typed(False))]
        self.catalog['catalog']['claims']=sorted(extra,key=lambda c:c['claim_id']); self.save_catalog(); self.produce()
        envelope,_=verifier.verify_bundle(self.output,self.sha)
        self.assertEqual([r['verdict'] for r in envelope['claims']],['SUPPORTED']*3)

    def test_real_pgop1_doc_and_code(self):
        raw=(ROOT/'runtime/candidate/static_ast_v2.py').read_bytes()
        doc=(ROOT/'docs/STATIC_AST_V2.md').read_bytes()
        # Only explicitly selected documentation/code are authorized, no discovery.
        pins=[dict(path='docs/STATIC_AST_V2.md',sha256=digest(doc),kind='document'),
              dict(path='runtime/candidate/static_ast_v2.py',sha256=digest(raw),kind='python')]
        document=dict(path=pins[0]['path'],sha256=pins[0]['sha256'],start_line=1,end_line=1,span_sha256=digest(doc.splitlines(keepends=True)[0]))
        claim=make_claim('symbol_defined',document,dict(path=pins[1]['path'],sha256=pins[1]['sha256']),dict(scope='<module>',name='analyze_captured'),typed(True))
        self.catalog=dict(schema=verifier.CATALOG,profile='real-static-v2',catalog=dict(schema='pgop1.source-audit-catalog.v2',sources=pins,claims=[claim]),
                          sources=[dict(path=p['path'],sha256=p['sha256'],bytes=len(doc if i==0 else raw),version='base-5335a390',language='markdown' if i==0 else 'python',scope='REGISTERED_FILE_ONLY') for i,p in enumerate(pins)])
        self.save_catalog(); self.profile.source_root=ROOT
        self.produce(); envelope,_=verifier.verify_bundle(self.output,self.sha)
        self.assertEqual(envelope['claims'][0]['verdict'],'SUPPORTED')
        self.assertEqual(envelope['claims'][0]['qualification'],'EXACT_TYPED_PREDICATE_ONLY')
