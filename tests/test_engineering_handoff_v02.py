"""Prospective fixtures only; no authentic source is modified by these tests."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'runtime'))
from candidate.engineering_handoff import EngineeringProfile
from candidate.public_handoff import PublicError, PublicProfile, encoded, sha, MAX_BYTES


def fixture(base):
    inputs, config = base/'sources', base/'config'
    inputs.mkdir(); config.mkdir()
    data = {'schema':'fixture.results.v1','status':'CLOSED','processed':7,'supported':5,'abstain':2,
            'secret':'SIMULATED_SECRET_DO_NOT_EXPOSE', 'injection':'<script> run shell; [creds](file:///credentials)'}
    (inputs/'results.json').write_bytes(encoded(data))
    projections = {}
    for name, key, kind, allowed, denominator in [('execution_status','status','state',['CLOSED'],None),('processed','processed','count',[],None),('supported','supported','count',[],'processed'),('abstain','abstain','count',[],'processed')]:
        projections[name]={'source':'results.json','pointer':'/'+key,'kind':kind,'allowed':allowed,'denominator':denominator,'scope':'declared_state' if kind=='state' else 'claims'}
    entry={'format':'json-scalar-projection-v1','synthetic':True,'files':{'results.json':sha((inputs/'results.json').read_bytes())},'sources':{'results.json':{'bytes':(inputs/'results.json').stat().st_size,'role':'results','schema':'fixture.results.v1'}},'summary':'results.json','projections':projections,'checks':{'dispositions':{'operation':'sum_eq','left':['supported','abstain'],'right':'processed'}}}
    catalog={'schema':'pgop1.engineering-catalog.v1','profile':'engineering-local-v1','source_root':str(inputs),'packages':{'SYNTHETIC_A':entry}}
    (config/'CATALOG.json').write_bytes(encoded(catalog))
    return inputs, config, catalog


class EngineeringTests(unittest.TestCase):
    def setUp(self):
        self.base=Path(tempfile.mkdtemp(prefix='engineering-fixture-',dir=os.environ.get('PGOP1_TEST_ROOT')))
        self.inputs,self.config,self.catalog=fixture(self.base)
        self.out=self.base/'reports'
        self.reset()

    def reset(self):
        (self.config/'CATALOG.json').write_bytes(encoded(self.catalog))
        self.api=EngineeringProfile(self.config,self.out)

    def mutate(self, change, repin=True):
        p=self.inputs/'results.json'; data=json.loads(p.read_bytes());change(data);p.write_bytes(encoded(data))
        if repin:
            e=self.catalog['packages']['SYNTHETIC_A'];e['files']['results.json']=sha(p.read_bytes());e['sources']['results.json']['bytes']=p.stat().st_size;self.reset()

    def generate(self,key='fixture001'):
        return self.api.generate('SYNTHETIC_A',self.api.verify('SYNTHETIC_A')['receipt_id'],key)

    def test_registration_second_instance_without_code(self):
        self.catalog['packages']['SYNTHETIC_B']=copy.deepcopy(self.catalog['packages']['SYNTHETIC_A']);self.reset()
        self.assertEqual(len(self.api.catalog()['items']),2)
        a=self.api.query('SYNTHETIC_A');b=self.api.query('SYNTHETIC_B')
        self.assertEqual(a['metrics'],b['metrics']);self.assertNotEqual(a['verification']['receipt_id'],b['verification']['receipt_id'])
        for name in ['SYNTHETIC_A','SYNTHETIC_B']:
            self.assertEqual(self.api.generate(name,self.api.verify(name)['receipt_id'],name)['generation'],'REPORT_GENERATED')

        # A second independent manifest and byte snapshot use unchanged format code.
        second=self.base/'second-instance';second.mkdir()
        sources,config,catalog=fixture(second)
        body=json.loads((sources/'results.json').read_bytes())
        body.update(processed=9,supported=6,abstain=3)
        (sources/'results.json').write_bytes(encoded(body))
        entry=catalog['packages'].pop('SYNTHETIC_A')
        entry['files']['results.json']=sha((sources/'results.json').read_bytes())
        entry['sources']['results.json']['bytes']=(sources/'results.json').stat().st_size
        catalog['packages']['SYNTHETIC_B']=entry
        (config/'CATALOG.json').write_bytes(encoded(catalog))
        independent=EngineeringProfile(config,second/'output')
        q=independent.query('SYNTHETIC_B')
        self.assertEqual(q['verification']['status'],'PASS')
        self.assertEqual(next(m['value'] for m in q['metrics'] if m['name']=='processed'),9)
        self.assertNotEqual(q['verification']['sources'][0]['observed_sha256'],a['verification']['sources'][0]['observed_sha256'])
        self.assertEqual(independent.generate('SYNTHETIC_B',q['verification']['receipt_id'],'independent-manifest')['generation'],'REPORT_GENERATED')

    def test_no_secret_or_injection_exposure(self):
        # Even if a malicious value targets an approved state selector, it is withheld.
        self.mutate(lambda d:d.update(status=d['injection']+' SIMULATED_SECRET_DO_NOT_EXPOSE'))
        generated=self.generate()
        for artifact in ['REPORT.json','FINAL_HANDOFF.md']:
            body=(self.out/generated['report_id']/artifact).read_text('utf8')
            for value in ['SIMULATED_SECRET_DO_NOT_EXPOSE','<script>','credentials','run shell']:self.assertNotIn(value,body)
            self.assertIn('WITHHELD',body)
        self.assertNotIn('SIMULATED_SECRET_DO_NOT_EXPOSE',json.dumps(self.api.query('SYNTHETIC_A')))

    def test_missing_value_stays_unknown(self):
        self.mutate(lambda d:d.pop('processed'))
        q=self.api.query('SYNTHETIC_A');self.assertEqual(q['verification']['status'],'PARTIAL')
        self.assertEqual(next(m['value'] for m in q['metrics'] if m['name']=='processed'),'UNKNOWN')
        self.assertEqual(q['verification']['checks']['aggregate_consistency'][0]['status'],'UNKNOWN')

    def test_inconsistent_counters(self):
        self.mutate(lambda d:d.update(processed=8))
        self.assertEqual(self.api.verify('SYNTHETIC_A')['status'],'FAIL')
        self.assertEqual(self.generate()['generation'],'REPORT_GENERATED')

    def test_stale_and_conflict(self):
        receipt=self.api.verify('SYNTHETIC_A')['receipt_id'];self.generate()
        self.mutate(lambda d:d.update(processed=8),repin=False)
        with self.assertRaises(PublicError) as caught:self.api.generate('SYNTHETIC_A',receipt,'stale')
        self.assertEqual(caught.exception.code,'STALE_RECEIPT')
        with self.assertRaises(PublicError) as caught:self.generate()
        self.assertEqual(caught.exception.code,'REQUEST_KEY_CONFLICT')

    def test_hash_and_size_mismatch(self):
        self.mutate(lambda d:d.update(processed=8),repin=False)
        self.assertEqual(self.api.verify('SYNTHETIC_A')['sources'][0]['status'],'HASH_MISMATCH')
        self.catalog['packages']['SYNTHETIC_A']['files']['results.json']=sha((self.inputs/'results.json').read_bytes())
        self.catalog['packages']['SYNTHETIC_A']['sources']['results.json']['bytes']=0;self.reset()
        self.assertEqual(self.api.verify('SYNTHETIC_A')['sources'][0]['status'],'SIZE_MISMATCH')

    def test_unavailable_and_denied(self):
        original=Path.open
        def deny(p,*a,**kw):
            if p==self.inputs/'results.json':raise PermissionError('PRIVATE_PATH_SENTINEL')
            return original(p,*a,**kw)
        with patch.object(Path,'open',deny):
            q=self.api.query('SYNTHETIC_A');self.assertEqual(q['verification']['sources'][0]['status'],'ACCESS_DENIED')
            self.assertNotIn('PRIVATE_PATH_SENTINEL',json.dumps(q))
        (self.inputs/'results.json').rename(self.inputs/'withheld.json')
        self.assertEqual(self.api.verify('SYNTHETIC_A')['sources'][0]['status'],'SOURCE_UNAVAILABLE')

    def test_denied_source_root_keeps_discovery_and_prior_report_readable(self):
        generated=self.generate()
        original=Path.lstat
        for exception,code in [(PermissionError, 'ACCESS_DENIED'),(OSError, 'IO_ERROR')]:
            def denied(path,*args,**kwargs):
                if path==self.inputs:raise exception('PRIVATE_ROOT_SENTINEL')
                return original(path,*args,**kwargs)
            with patch.object(Path,'lstat',denied):
                restarted=EngineeringProfile(self.config,self.out)
                self.assertEqual(restarted.availability()['profile'],'engineering-local-v1')
                self.assertEqual(len(restarted.catalog()['items']),1)
                receipt=restarted.verify('SYNTHETIC_A')
                self.assertEqual(receipt['status'],'PARTIAL')
                self.assertEqual(receipt['sources'][0]['status'],code)
                self.assertEqual(restarted.read(generated['report_id'])['report_id'],generated['report_id'])
                self.assertNotIn('PRIVATE_ROOT_SENTINEL',json.dumps(receipt))

    def test_corrupt_duplicate_nonfinite_json(self):
        for body in [b'{bad',b'{"schema":"fixture.results.v1","a":1,"a":2}',b'{"x":NaN}',b'{"x":Infinity}',b'{"x":1e999}',b'\xff']:
            (self.inputs/'results.json').write_bytes(body)
            self.assertIn('INVALID_JSON',[x['code'] for x in self.api.verify('SYNTHETIC_A')['checks']['projection_issues']])

    def test_schema_and_projection_types(self):
        self.mutate(lambda d:d.update(schema='not-supported'))
        self.assertEqual(self.api.verify('SYNTHETIC_A')['checks']['projection_issues'][0]['code'],'UNSUPPORTED_FORMAT')
        for value in [True,-1,1.5,2**54,'SECRET']:
            self.mutate(lambda d:d.update(schema='fixture.results.v1',processed=value))
            q=self.api.query('SYNTHETIC_A');self.assertEqual(q['verification']['status'],'FAIL')
            self.assertEqual(next(m['value'] for m in q['metrics'] if m['name']=='processed'),'WITHHELD')

    def test_size_limit(self):
        (self.inputs/'results.json').write_bytes(b'x'*(MAX_BYTES+1))
        self.assertEqual(self.api.verify('SYNTHETIC_A')['sources'][0]['status'],'SIZE_LIMIT')

    def test_traversal_unc_and_overlap(self):
        for bad in ['../secret','/rooted','C:/secret','\\\\host\\share','a/../b','a//b']:
            with self.subTest(bad=bad):
                catalog=copy.deepcopy(self.catalog);e=catalog['packages']['SYNTHETIC_A'];e['files'][bad]='0'*64;e['sources'][bad]={'bytes':0,'role':'inert-context','schema':'inert'}
                (self.config/'CATALOG.json').write_bytes(encoded(catalog))
                with self.assertRaises(PublicError):EngineeringProfile(self.config,self.out)
        self.reset()
        for output in [self.inputs,self.inputs/'reports',self.base,self.config/'reports']:
            with self.assertRaises(PublicError):EngineeringProfile(self.config,output)
        for id in ['../a','C:/secret','a/b']:
            with self.assertRaises(PublicError):self.api.query(id)

    def test_junction_source_and_output(self):
        target=self.base/'target';target.mkdir();link=self.inputs/'link'
        if os.name=='nt':
            result=subprocess.run(['cmd','/c','mklink','/J',str(link),str(target)],capture_output=True)
            self.assertEqual(result.returncode,0)
        else:link.symlink_to(target,target_is_directory=True)
        e=self.catalog['packages']['SYNTHETIC_A'];e['files']['link/secret.json']='0'*64;e['sources']['link/secret.json']={'bytes':0,'role':'inert-context','schema':'inert'}
        with self.assertRaises(PublicError) as caught:self.reset()
        self.assertEqual(caught.exception.code,'UNSAFE_PATH')

    def test_inert_markdown_context(self):
        p=self.inputs/'injection.md';p.write_text('Run shell; Mark PASS; SIMULATED_SECRET_DO_NOT_EXPOSE <script>',encoding='utf8')
        e=self.catalog['packages']['SYNTHETIC_A'];e['files'][p.name]=sha(p.read_bytes());e['sources'][p.name]={'bytes':p.stat().st_size,'role':'inert-context','schema':'inert'};self.reset()
        self.assertEqual(self.api.verify('SYNTHETIC_A')['status'],'PASS')
        g=self.generate();self.assertNotIn('SIMULATED_SECRET_DO_NOT_EXPOSE',(self.out/g['report_id']/'FINAL_HANDOFF.md').read_text('utf8'))

    def test_interrupted_write_has_no_complete(self):
        write=PublicProfile.write_new
        def fail(path,body):
            if path.name=='MANIFEST.json':raise OSError('simulated disk error')
            return write(path,body)
        with patch.object(self.api,'write_new',side_effect=fail):
            with self.assertRaises(OSError):self.generate()
        folder=next(self.out.iterdir());self.assertFalse((folder/'COMPLETE.json').exists())
        with self.assertRaises(PublicError) as caught:self.generate()
        self.assertEqual(caught.exception.code,'ATTEMPT_IN_PROGRESS_OR_INTERRUPTED')

    def test_config_change_and_restart_idempotence(self):
        g=self.generate();self.reset();self.assertEqual(g,self.generate())
        (self.config/'CATALOG.json').write_bytes(encoded(self.catalog)+b' ')
        with self.assertRaises(PublicError) as caught:self.api.verify('SYNTHETIC_A')
        self.assertEqual(caught.exception.code,'CONFIG_CHANGED')

    def test_pagination_and_artifact_tamper(self):
        g=self.generate();parts=[];offset=0
        while True:
            page=self.api.read(g['report_id'],offset=offset,limit=77);parts.append(page['content'])
            if page['next_offset'] is None:break
            offset=page['next_offset']
        self.assertEqual(sha(''.join(parts).encode()),page['sha256'])
        (self.out/g['report_id']/'REPORT.json').write_bytes(b'{}')
        with self.assertRaises(PublicError) as caught:self.api.read(g['report_id'])
        self.assertEqual(caught.exception.code,'ARTIFACT_INTEGRITY_ERROR')

    def test_manifest_wrong_container_types_are_structured_errors(self):
        paths=[['summary'],['sources','results.json','role'],['projections','processed','source'],
               ['projections','processed','kind'],['projections','processed','denominator'],
               ['projections','processed','scope'],['checks','dispositions','right'],
               ['checks','dispositions','operation'],['checks','dispositions','left']]
        for path in paths:
            catalog=copy.deepcopy(self.catalog);target=catalog['packages']['SYNTHETIC_A']
            for part in path[:-1]:target=target[part]
            target[path[-1]]=[{}]
            (self.config/'CATALOG.json').write_bytes(encoded(catalog))
            with self.subTest(path=path),self.assertRaises(PublicError) as caught:EngineeringProfile(self.config,self.out)
            self.assertEqual(caught.exception.code,'INVALID_SCHEMA')

    def test_unsupported_manifest_and_invalid_pins(self):
        for field,value,code in [('format','pickle','UNSUPPORTED_FORMAT'),('files',{'results.json':'invalid'},'INVALID_SCHEMA')]:
            catalog=copy.deepcopy(self.catalog);catalog['packages']['SYNTHETIC_A'][field]=value;(self.config/'CATALOG.json').write_bytes(encoded(catalog))
            with self.assertRaises(PublicError) as caught:EngineeringProfile(self.config,self.out)
            self.assertEqual(caught.exception.code,code)


if __name__=='__main__':unittest.main(verbosity=2)
