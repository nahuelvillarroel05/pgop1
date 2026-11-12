"""E8 controlled fixtures. Source bytes are parsed, never imported/executed."""
import copy
import ctypes as T
from dataclasses import replace
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from admission_test_support import Fixture,CODE_PATHS,PRODUCT
from candidate import discovery_contract_v1 as D
from candidate import selection_contract_v1 as C
from candidate import admission_contract_v2 as A
from candidate import windows_directory_enumeration_v1 as N
from candidate import root_source_discovery_v1 as E
from candidate import windows_safe_io_v2 as IO
from candidate import source_selection_v2 as V2
from tools.verify_discovery_v1 import verify
from tools.verify_selection_v2 import verify as verify_selection

def frame(name='a.py',**changes):
    raw=bytearray(88+len(name.encode('utf-16-le')))
    struct.pack_into('<q',raw,40,1)
    struct.pack_into('<I',raw,56,0x20)
    struct.pack_into('<I',raw,60,len(name.encode('utf-16-le')))
    raw[72]=1;raw[88:]=name.encode('utf-16-le')
    for offset,value in changes.items():struct.pack_into('<I',raw,int(offset),value)
    return bytes(raw)

@unittest.skipUnless(os.name=='nt','Windows-only exact-host E8')
class DirectoryDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='e8-test-');self.base=Path(self.temp.name);self.n=0
    def tearDown(self):self.temp.cleanup()
    def fixture(self,files=None,**rules):
        self.n+=1
        f=Fixture(self.base/str(self.n),files or {'a.py':'VALUE=1\n'},rules)
        pins=[]
        for path in sorted(set(CODE_PATHS)|D.EXTRA_CODE):
            body=(PRODUCT/path).read_bytes();pins.append(dict(path=path,bytes=len(body),sha256=C.digest(body)))
        f.code=C.canonical(dict(schema='pgop1.selection-code.v1',files=pins))
        f.authority=replace(f.authority,code_sha256=C.digest(f.code))
        f.discovery=D.DiscoveryAuthority(str(f.source),C.digest(f.ar),C.digest(f.pr),C.digest(f.code))
        (f.config/'code.json').write_bytes(f.code)
        return f
    def discover(self,f,limits=None):return E.discover(f.ar,f.pr,f.code,f.discovery,limits)
    def publish(self,f):
        output=f.base/'discovery'
        receipt=E.execute(f.config/'owner.json',f.config/'policy.json',f.config/'code.json',output,f.discovery)
        return output,receipt
    def test_positive_native_catalog_independent_replay_and_later_external_e7(self):
        f=self.fixture({'pkg/__init__.py':'','pkg/a.py':'from . import b\n','pkg/b.py':'VALUE=1\n'})
        external_pin=C.digest(f.cr)  # Fixture caller freezes expected catalog BEFORE E8.
        output,receipt=self.publish(f)
        self.assertEqual(receipt['status'],'CATALOG_DISCOVERED')
        self.assertEqual(receipt['catalog_candidate_sha256'],external_pin)
        self.assertEqual(verify(output,f.ar,f.pr,f.code,f.discovery,receipt['manifest_sha256'])['status'],'DISCOVERY_VERIFIED')
        self.assertEqual((output/'CATALOG_CANDIDATE.json').read_bytes(),f.cr)
        selection=f.base/'selection'
        ack=V2.execute(*f.args(selection))
        result=verify_selection(selection,f.ar,f.authority,ack['manifest_sha256'])
        self.assertEqual(result['selected'],3)
        self.assertEqual(receipt['catalog_authority'],'CANDIDATE_NOT_EXTERNALLY_ADMITTED')
    def test_owner_deny_precedes_every_file_metadata_open_and_capture(self):
        f=self.fixture({'a.py':'VALUE=1\n','private/canary.py':'FICTITIOUS\n','z.py':'VALUE=2\n'})
        calls=[];opened=N.open_metadata
        with mock.patch.object(N,'open_metadata',side_effect=lambda parent,name,**kw:(calls.append(name),opened(parent,name,**kw))[1]):
            result=self.discover(f)
        self.assertEqual(result['status'],'CATALOG_DISCOVERED')
        self.assertNotIn('private',calls);self.assertNotIn('canary.py',calls)
        self.assertEqual([r['path'] for r in result['catalog']['sources']],['a.py','z.py'])
        self.assertEqual(result['counts']['captured_files'],2)
    def test_allow_exact_prunes_unrelated_subtree_and_deny_wins(self):
        f=self.fixture({'private/a.py':'VALUE=1\n','public/b.py':'VALUE=2\n','spare/c.py':'VALUE=3\n'},
                       deny_prefixes=['private/'],allow_exact=['private/a.py','public/b.py'])
        opened=[];original=N.open_metadata
        with mock.patch.object(N,'open_metadata',side_effect=lambda p,n,**kw:(opened.append(n),original(p,n,**kw))[1]):result=self.discover(f)
        self.assertEqual(result['status'],'CATALOG_DISCOVERED')
        self.assertEqual([r['path'] for r in result['catalog']['sources']],['public/b.py'])
        self.assertNotIn('spare',opened);self.assertNotIn('private',opened)
    def test_private_name_allowed_without_deny(self):
        f=self.fixture({'private/a.py':'VALUE=1\n'},deny_prefixes=[])
        self.assertEqual(self.discover(f)['status'],'CATALOG_DISCOVERED')
    def test_hardlink_rejects_global_preflight_before_any_capture(self):
        f=self.fixture({'a.py':'VALUE=1\n','z.py':'VALUE=2\n'})
        os.link(f.source/'z.py',f.base/'alias.py')
        with mock.patch.object(N,'capture',side_effect=AssertionError('CAPTURE_BEFORE_GLOBAL_PREFLIGHT')):
            result=self.discover(f)
        self.assertEqual(result['status'],'INCOMPLETE');self.assertIsNone(result['catalog'])
        self.assertEqual(result['counts']['captured_bytes'],0)
        self.assertEqual(result['failure'],'UNSAFE_PATH_HARDLINK')
    def test_junction_rejects_without_traversal_or_capture(self):
        f=self.fixture({'a.py':'VALUE=1\n'});outside=f.base/'outside';outside.mkdir();(outside/'x.py').write_text('VALUE=99\n')
        process=subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(f.source/'z'),str(outside)],capture_output=True)
        if process.returncode:self.skipTest('Normal-token junction unavailable: '+repr(process.stderr))
        try:
            with mock.patch.object(N,'capture',side_effect=AssertionError('CAPTURE_BEFORE_GLOBAL_PREFLIGHT')):result=self.discover(f)
            self.assertEqual(result['status'],'INCOMPLETE');self.assertEqual(result['counts']['captured_bytes'],0)
        finally:os.rmdir(f.source/'z')
    def test_metadata_file_handle_requests_no_data_rights(self):
        f=self.fixture();api=IO.api()[1];native=api.NtCreateFile;rights=[]
        def observe(*args):
            rights.append(int(args[1]));return native(*args)
        with IO.Directory(f.source) as root,mock.patch.object(api,'NtCreateFile',side_effect=observe):
            with N.open_metadata(root.handle,'a.py',directory=False) as handle:
                self.assertEqual(IO.metadata(handle,False).size,8)
        self.assertEqual(rights,[0x100080])
    def test_more_than_one_page_and_33_eligible(self):
        files={f'm{i:03}.py':'VALUE=1\n' for i in range(40)}
        f=self.fixture(files);result=self.discover(f,dict(buffer_bytes=512))
        self.assertEqual(result['status'],'CATALOG_DISCOVERED')
        self.assertEqual(len(result['catalog']['sources']),40)
        self.assertGreater(result['counts']['pages'],2)
        plan,_,_=V2.select_catalog(f.cr,f.pr,f.ar,f.code,f.authority)
        self.assertEqual(len(plan['legacy_plan']['selected']),32)
    def test_budget_exhaustion_never_emits_prefix_catalog(self):
        f=self.fixture({'a.py':'VALUE=1\n','b.py':'VALUE=2\n'})
        for limits in [dict(max_files=1),dict(max_entries=1),dict(max_pages=1),dict(max_total_bytes=1),dict(max_file_bytes=1)]:
            with self.subTest(limits=limits):
                value=self.discover(f,limits);self.assertEqual(value['status'],'INCOMPLETE');self.assertIsNone(value['catalog'])
                self.assertEqual(value['counts']['captured_files'],0)
    def test_invalid_budget_and_external_policy_anchor_rejected(self):
        f=self.fixture()
        for value in [dict(max_files=True),dict(buffer_bytes=95),dict(max_depth=6),dict(extra=1)]:
            with self.assertRaises(ValueError):self.discover(f,value)
        with mock.patch.object(N,'open_metadata',side_effect=AssertionError('OPEN_BEFORE_AUTH')):
            with self.assertRaises(ValueError):E.discover(f.ar,f.pr,f.code,replace(f.discovery,admission_policy_sha256='0'*64))
    def test_parser_uses_information_offsets_and_utf16_bounds(self):
        raw=frame();self.assertEqual(N.parse_page(raw,len(raw))[0]['name'],'a.py')
        for raw,used in [(raw,len(raw)-1),(raw,0),(raw,len(raw)+1),(frame(**{'0':8}),len(raw)),
                         (frame(**{'60':3}),len(raw)),(frame('CON.py'),100),(frame('a.py',**{'60':600}),len(raw))]:
            with self.subTest(used=used):
                with self.assertRaises((ValueError,IO.SafeIOError)):N.parse_page(raw,used)
    def test_native_unexpected_status_zero_progress_and_page_limit(self):
        f=self.fixture()
        with IO.Directory(f.source) as d:
            for status in [0x103,0x80000005,0xc0000022]:
                with mock.patch.object(N,'query_api',return_value=lambda *args:status):
                    with self.assertRaises(IO.SafeIOError):N.enumerate_directory(d.handle)
            with mock.patch.object(N,'query_api',return_value=lambda *args:0):
                with self.assertRaisesRegex(IO.SafeIOError,'DIRECTORY_NO_PROGRESS'):N.enumerate_directory(d.handle)
    def test_failed_inventory_keeps_every_actual_query_and_partial_denominator(self):
        f=self.fixture({'a.py':'VALUE=1\n','b.py':'VALUE=2\n'})
        for budget in [dict(max_pages=1),dict(max_entries=1)]:
            value=self.discover(f,budget)
            queries=[e for e in value['trace'] if e['event']=='QUERY']
            self.assertEqual(value['status'],'INCOMPLETE')
            self.assertGreater(len(queries),0)
            self.assertEqual(value['counts']['pages'],len(queries))
            self.assertEqual(value['counts']['physical_entries'],sum(e['decoded_entries'] or 0 for e in queries))
            self.assertGreater(value['counts']['physical_entries'],0)
            self.assertEqual(value['counts']['captured_files'],0)
    def test_global_page_budget_is_checked_before_next_directory_query(self):
        f=self.fixture({'pkg/a.py':'VALUE=1\n','z.py':'VALUE=2\n'})
        value=self.discover(f,dict(max_pages=2))
        self.assertEqual(value['status'],'INCOMPLETE')
        self.assertEqual(value['counts']['pages'],2)
        self.assertEqual(len([e for e in value['trace'] if e['event']=='QUERY']),2)
        self.assertEqual(value['counts']['captured_files'],0)
    def test_malformed_page_retains_status_bytes_and_unknown_entry_denominator(self):
        f=self.fixture()
        with mock.patch.object(N,'parse_page',side_effect=IO.SafeIOError('DIRECTORY_MALFORMED_PAGE')):
            value=self.discover(f)
        self.assertEqual(value['status'],'INCOMPLETE')
        self.assertEqual(value['counts']['pages'],1)
        self.assertEqual(value['counts']['unparsed_pages'],1)
        query=next(e for e in value['trace'] if e['event']=='QUERY')
        self.assertGreater(query['returned_bytes'],0);self.assertIsNone(query['decoded_entries'])
        self.assertEqual(query['page_state'],'MALFORMED_OR_UNSAFE')
    def test_code_pins_checked_before_any_source_directory_handle(self):
        f=self.fixture();changed=C.strict(f.code);changed['files'][0]['sha256']='0'*64
        raw=C.canonical(changed);authority=replace(f.discovery,code_sha256=C.digest(raw))
        enter=IO.Directory.__enter__;source_opens=[]
        def watch(directory):
            if str(directory.path)==str(f.source):source_opens.append(str(directory.path))
            return enter(directory)
        with mock.patch.object(IO.Directory,'__enter__',watch):
            with self.assertRaises(ValueError):E.discover(f.ar,f.pr,raw,authority)
        self.assertEqual(source_opens,[])
    def test_rehashed_semantic_tampering_and_extra_member_rejected(self):
        f=self.fixture();out,receipt=self.publish(f)
        body=C.strict((out/'DISCOVERY.json').read_bytes());body['counts']['captured_files']=999
        raw=C.canonical(body);(out/'DISCOVERY.json').write_bytes(raw)
        manifest=C.strict((out/'MANIFEST.json').read_bytes());manifest['files']['DISCOVERY.json']=dict(bytes=len(raw),sha256=C.digest(raw))
        changed=C.canonical(manifest);(out/'MANIFEST.json').write_bytes(changed)
        with self.assertRaisesRegex(ValueError,'DISCOVERY_SEMANTIC_MISMATCH'):verify(out,f.ar,f.pr,f.code,f.discovery,C.digest(changed))
        (out/'EXTRA.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'DISCOVERY_MEMBERSHIP'):verify(out,f.ar,f.pr,f.code,f.discovery,C.digest(changed))
    def test_output_existing_and_in_source_refused(self):
        f=self.fixture();out,_=self.publish(f)
        with self.assertRaises((ValueError,OSError)):E.execute(f.config/'owner.json',f.config/'policy.json',f.config/'code.json',out,f.discovery)
        with self.assertRaises(ValueError):E.execute(f.config/'owner.json',f.config/'policy.json',f.config/'code.json',f.source/'out',f.discovery)
    def test_verifier_in_new_process_blocks_both_producer_imports(self):
        f=self.fixture();out,receipt=self.publish(f)
        script="""import sys
class Guard:
 def find_spec(self,name,*args):
  if name in ('candidate.root_source_discovery_v1','candidate.windows_directory_enumeration_v1'):raise AssertionError(name)
sys.meta_path.insert(0,Guard())
from tools.verify_discovery_v1 import main
sys.exit(main())
"""
        args=['--artifacts',str(out),'--manifest-sha256',receipt['manifest_sha256'],'--source-root',str(f.source),
              '--admission-policy',str(f.config/'owner.json'),'--admission-policy-sha256',C.digest(f.ar),
              '--policy',str(f.config/'policy.json'),'--policy-sha256',C.digest(f.pr),
              '--code-manifest',str(f.config/'code.json'),'--code-sha256',C.digest(f.code)]
        proc=subprocess.run([sys.executable,'-c',script,*args],capture_output=True)
        self.assertEqual(proc.returncode,0,proc.stderr.decode());self.assertIn(b'DISCOVERY_VERIFIED',proc.stdout)

if __name__=='__main__':unittest.main()
