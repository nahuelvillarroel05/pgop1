"""Owner admission: direct API, real CLI, independent verification and Windows I/O."""
import copy
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from admission_test_support import Fixture, Observation, PRODUCT
from candidate import admission_contract_v2 as A
from candidate import selection_contract_v1 as C
from candidate import source_selection_v1 as V1
from candidate import source_selection_v2 as V2
from candidate import windows_safe_io_v2 as IO
from tools.verify_selection_v2 import verify

class AdmissionV2Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='admission-v2-')
        self.base = Path(self.temp.name); self.count = 0
    def tearDown(self):
        self.temp.cleanup()
    def fixture(self, files=None, **rules):
        self.count += 1
        return Fixture(self.base / str(self.count), files or {'a.py': 'VALUE=1\n'}, rules)
    def denied(self, f, call=None, reason=None):
        with Observation(f.source) as obs:
            with self.assertRaises((ValueError, OSError)) as caught:
                (call or f.direct)()
        if reason:
            self.assertEqual(getattr(caught.exception, 'code', str(caught.exception)), reason)
        self.assertEqual(obs.summary()['provider_requests'], 0)
        self.assertEqual(obs.summary()['os_read_attempts'], 0)
        self.assertEqual(obs.summary()['native_file_opens'], 0)
        self.assertEqual(obs.summary()['python_opens'], 0)
        return obs
    def publish(self, f):
        out = f.base / 'output'
        receipt = V2.execute(*f.args(out))
        return out, receipt
    def rehash(self, out, name, value):
        raw = C.canonical(value); (out / name).write_bytes(raw)
        m = C.strict((out / 'MANIFEST.json').read_bytes())
        m['files'][name] = dict(bytes=len(raw), sha256=C.digest(raw))
        manifest = C.canonical(m); (out / 'MANIFEST.json').write_bytes(manifest)
        return C.digest(manifest)
    def test_n17_v1_exposed_baseline_preserved(self):
        f = self.fixture({'private/canary.py': 'FICTITIOUS_PGOP1_CANARY_001_NO_REAL_SECRET\n'})
        with Observation(f.source) as obs:
            plan, _, _ = V1.select_catalog(f.c, f.p, f.authority.code_sha256)
        self.assertEqual(len(plan['selected']), 1)
        self.assertEqual(obs.summary()['native_file_opens'], 2)
        self.assertEqual(obs.summary()['bytes'], 86)
    def test_n17_v2_direct_denied_before_any_source_open(self):
        f = self.fixture({'private/canary.py': 'FICTITIOUS_V2_CANARY\n'})
        self.denied(f, reason='OWNER_CATALOG_DENIED')
    def test_late_denied_member_blocks_earlier_allowed_and_budget_fill(self):
        f = self.fixture({'a.py': 'import z.private.mod\n', 'z/private/mod.py': 'FICTITIOUS\n'}, deny_components=['private'])
        f.p['max_selected'] = 1; f.refresh()
        self.denied(f, reason='OWNER_CATALOG_DENIED')
    def test_prefix_boundary_nested_scope_and_ascii_case(self):
        for path, rules, reject in [
            ('private/a.py', {}, True), ('Private/a.py', {}, True),
            ('privateer.py', {}, False), ('pkg/private/a.py', {}, False),
            ('pkg/private/a.py', {'deny_components': ['private']}, True),
            ('private/__init__.py', {}, True), ('pkg/privateer/a.py', {'deny_components': ['private']}, False)]:
            with self.subTest(path=path, rules=rules):
                f = self.fixture({path: 'VALUE=1\n'}, **rules)
                if reject:
                    self.denied(f, reason='OWNER_CATALOG_DENIED')
                else:
                    self.assertEqual(len(f.direct()[0]['legacy_plan']['selected']), 1)
    def test_owner_can_explicitly_allow_private_when_no_deny(self):
        f = self.fixture({'private/a.py': 'VALUE=1\n'}, deny_prefixes=[])
        self.assertEqual(len(f.direct()[0]['legacy_plan']['selected']), 1)
    def test_exact_allowlist_and_deny_priority(self):
        f = self.fixture({'private/a.py': 'FICTITIOUS\n'}, allow_exact=['private/a.py'])
        self.denied(f, reason='OWNER_CATALOG_DENIED')
        f = self.fixture({'a.py': 'VALUE=1\n', 'b.py': 'VALUE=2\n'}, deny_prefixes=[], allow_exact=['a.py'])
        self.denied(f, reason='OWNER_CATALOG_DENIED')
        f = self.fixture({'a.py': 'VALUE=1\n'}, deny_prefixes=[], deny_exact=['a.py'], allow_exact=['a.py'])
        self.denied(f, reason='OWNER_CATALOG_DENIED')
    def test_missing_policy_context_and_external_anchor_mismatch(self):
        f = self.fixture()
        args = [f.cr, f.pr, f.ar, f.code, f.authority]
        for index in [0, 1, 2, 3, 4]:
            modified = args[:]; modified[index] = None
            self.denied(f, lambda: V2.select_catalog(*modified))
        for field in ['catalog_sha256', 'selection_policy_sha256', 'admission_policy_sha256', 'code_sha256']:
            ctx = replace(f.authority, **{field: '0' * 64})
            self.denied(f, lambda: V2.select_catalog(f.cr, f.pr, f.ar, f.code, ctx), 'EXTERNAL_AUTHORIZATION_ANCHOR')
    def test_duplicate_noncanonical_unknown_keys_and_bad_rules_fail_closed(self):
        f = self.fixture()
        invalid = [b'{"x":1,"x":2}', b' '+f.ar,
                   C.canonical(dict(f.a, extra=True)), C.canonical(dict(f.a, case='sensitive'))]
        for raw in invalid:
            ctx = replace(f.authority, admission_policy_sha256=C.digest(raw))
            self.denied(f, lambda: V2.select_catalog(f.cr, f.pr, raw, f.code, ctx))
        for rules in [{'deny_prefixes': ['private']}, {'deny_prefixes': ['a/../private/']},
                      {'deny_prefixes': ['private*']}, {'deny_prefixes': ['Private/', 'private/']},
                      {'deny_components': ['a/b']}, {'deny_exact': ['x.py:ads']},
                      {'allow_exact': ['../a.py']}, {'deny_components': ['prívate']}]:
            f = self.fixture(**rules); self.denied(f)
    def test_catalog_traversal_ads_external_roots_and_case_collisions(self):
        for path in ['a/../private/x.py', 'a.py:ads', 'E:/a.py', '../a.py', 'a\\b.py']:
            f = self.fixture(); f.c['sources'][0]['path'] = path; f.refresh(); self.denied(f)
        f = self.fixture(); f.c['sources'].append(dict(f.c['sources'][0], path='A.py'))
        f.c['sources'].sort(key=lambda r:r['path']); f.refresh(); self.denied(f)
        f = self.fixture(); ctx = replace(f.authority, source_root='E:\\other')
        self.denied(f, lambda: V2.select_catalog(f.cr, f.pr, f.ar, f.code, ctx), 'OWNER_POLICY_ROOT')
    def test_scope_inheritance_and_out_of_scope_rule_rejected(self):
        f = self.fixture({'pkg/a.py': 'VALUE=1\n', 'pkg/private/x.py': 'FICTITIOUS\n'}, deny_prefixes=['pkg/private/'])
        f.c['scope'] = 'pkg'; f.a['scope'] = 'pkg'; f.refresh()
        self.denied(f, reason='OWNER_CATALOG_DENIED')
        f.a['deny_prefixes'] = ['private/']; f.refresh(); self.denied(f, reason='OWNER_POLICY_RULE_OUTSIDE_SCOPE')
    def test_fifo_relative_wildcard_parent_and_module_package_denies(self):
        for target, rules in [('p/private/m.py', {'deny_components': ['private']}),
                              ('p/__init__.py', {'deny_exact': ['p/__init__.py']}),
                              ('p/mod/__init__.py', {'deny_prefixes': ['p/mod/']})]:
            files = {'a.py': 'import p.mod\n', 'p/__init__.py': 'from . import mod\n',
                     'p/use.py': 'from .. import p\nfrom p.mod import *\n',
                     'p/mod.py': 'VALUE=1\n', target: 'FICTITIOUS\n'}
            f = self.fixture(files, **rules); self.denied(f, reason='OWNER_CATALOG_DENIED')
    def test_denied_import_reference_outside_catalog_has_no_target_read_or_match(self):
        f = self.fixture({'a.py': 'import private.canary\nfrom private import canary\n'})
        outside = f.source / 'private' / 'canary.py'; outside.parent.mkdir(); outside.write_bytes(b'FICTITIOUS\n')
        with Observation(f.source) as obs:
            plan, _, _ = f.direct()
        self.assertTrue(plan['admission_references'])
        self.assertTrue(all('private' not in e['path'].lower() for e in obs.source_events('NATIVE_FILE_OPEN_ATTEMPT')))
        self.assertNotIn('LOCAL_MODULE_MATCH', C.canonical(plan).decode())
        self.assertTrue(any(e.get('reason') == 'NO_CALLER_CATALOG_CANDIDATE' for e in plan['legacy_plan']['trace']))
    def test_positive_universe_matches_v1_and_independent_verifier(self):
        f = self.fixture({'__init__.py': '', 'a.py': 'import p.b\n', 'p/__init__.py': '', 'p/b.py': 'VALUE=1\n'})
        old, oldcaps, oldreports = V1.select_catalog(f.c, f.p, f.authority.code_sha256)
        with Observation(f.source) as obs:
            plan, captures, reports = f.direct()
        self.assertEqual((plan['legacy_plan'], captures, reports), (old, oldcaps, oldreports))
        self.assertGreater(obs.summary()['bytes'], 0)
        out, r = self.publish(f)
        self.assertEqual(verify(str(out), f.ar, f.authority, r['manifest_sha256'])['status'], 'SELECTION_V2_VERIFIED')
    def test_verifier_independent_with_both_producer_imports_blocked(self):
        f = self.fixture(); out, r = self.publish(f)
        code = "import sys;sys.path[:0]=" + repr([str(PRODUCT/'runtime'),str(PRODUCT)]) + ";sys.modules['candidate.source_selection_v1']=None;sys.modules['candidate.source_selection_v2']=None;from candidate.admission_contract_v2 import AuthorityContext;from tools.verify_selection_v2 import verify;print(verify(" + repr(str(out)) + ',' + repr(f.ar) + ',AuthorityContext(**' + repr(vars(f.authority)) + '),' + repr(r['manifest_sha256']) + ")[\"status\"])"
        result = subprocess.run([sys.executable, '-B', '-c', code], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode()); self.assertIn(b'SELECTION_V2_VERIFIED', result.stdout)
    def test_verifier_rejects_consistently_rehashed_denied_catalog_before_source_open(self):
        f = self.fixture(); out, _ = self.publish(f)
        bad = copy.deepcopy(f.c); bad['sources'] = [dict(path='private/canary.py', bytes=12, sha256=C.digest(b'FICTITIOUS\n'))]
        mh = self.rehash(out, 'SOURCE_CATALOG.json', bad)
        ctx = replace(f.authority, catalog_sha256=C.digest(C.canonical(bad)))
        self.denied(f, lambda: verify(str(out), f.ar, ctx, mh), 'OWNER_CATALOG_DENIED')
    def test_verifier_rejects_policy_substitution_and_unanchored_manifest(self):
        f = self.fixture(); out, r = self.publish(f)
        changed = C.canonical(dict(f.a, deny_prefixes=[]))
        self.denied(f, lambda: verify(str(out), changed, f.authority, r['manifest_sha256']), 'EXTERNAL_AUTHORIZATION_ANCHOR')
        self.denied(f, lambda: verify(str(out), f.ar, f.authority, '0' * 64))
    def test_rehashed_trace_membership_and_admission_tampering_rejected(self):
        for change in ['stages', 'trace', 'captures', 'policy']:
            f = self.fixture({'a.py': 'import b\n', 'b.py': 'VALUE=1\n'}); out, r = self.publish(f)
            if change == 'captures':
                v = C.strict((out/'CAPTURES.json').read_bytes());v['outside.py']='00'; mh=self.rehash(out,'CAPTURES.json',v)
            elif change == 'policy':
                mh=self.rehash(out,'ADMISSION_POLICY.json',dict(f.a,deny_prefixes=[]))
            else:
                v=C.strict((out/'PLAN.json').read_bytes())
                if change=='stages':v['admission']['stages'].reverse()
                else:v['legacy_plan']['trace'][1]['event']='FORGED'
                mh=self.rehash(out,'PLAN.json',v)
            with self.assertRaises(ValueError):verify(str(out),f.ar,f.authority,mh)
    def test_full_identity_preflight_rejects_hardlink_before_any_content_read(self):
        f=self.fixture({'a.py':'VALUE=1\n','z.py':'VALUE=2\n'}); alias=f.base/'alias.py';os.link(f.source/'z.py',alias)
        try:
            with Observation(f.source) as obs:
                with self.assertRaises(ValueError):f.direct()
            self.assertEqual(obs.summary()['os_read_attempts'],0)
        finally:alias.unlink()
    def test_junction_rejected_without_content_read(self):
        f=self.fixture({'a.py':'VALUE=1\n','p/b.py':'VALUE=2\n'})
        target=f.base/'target';(f.source/'p').rename(target)
        result=subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(f.source/'p'),str(target)],capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
        try:
            with Observation(f.source) as obs:
                with self.assertRaises(ValueError):f.direct()
            self.assertEqual(obs.summary()['os_read_attempts'],0)
        finally:os.rmdir(f.source/'p')
    def test_source_read_failure_and_drift_are_partial_without_fallback(self):
        f=self.fixture(); original=IO.safe_read; calls=[]
        def drift(root,name,pin,cap):
            if str(root)==str(f.source):
                calls.append(name)
                if len(calls)>1:raise IO.SafeIOError('SOURCE_HASH_MISMATCH')
            return original(root,name,pin,cap)
        with mock.patch.object(IO,'safe_read',drift):plan,_,_=f.direct()
        self.assertEqual(plan['legacy_plan']['status'],'PARTIAL')
        self.assertEqual(plan['legacy_plan']['source_errors'][0]['reason'],'SOURCE_CHANGED')
        def failure(root,name,pin,cap):
            if str(root)==str(f.source):raise IO.SafeIOError('SOURCE_READ_FAILED')
            return original(root,name,pin,cap)
        with mock.patch.object(IO,'safe_read',failure):plan,_,_=f.direct()
        self.assertEqual(plan['legacy_plan']['source_errors'][0]['reason'],'SOURCE_READ_FAILED')
    def test_changed_owner_policy_requires_new_external_anchor(self):
        f=self.fixture();old=f.authority;new=C.canonical(dict(f.a,deny_exact=['a.py']))
        self.denied(f,lambda:V2.select_catalog(f.cr,f.pr,new,f.code,old),'EXTERNAL_AUTHORIZATION_ANCHOR')
        ctx=replace(old,admission_policy_sha256=C.digest(new))
        self.denied(f,lambda:V2.select_catalog(f.cr,f.pr,new,f.code,ctx),'OWNER_CATALOG_DENIED')
    def test_code_manifest_cannot_omit_v2_closure(self):
        f=self.fixture(); code=C.strict(f.code);code['files']=[r for r in code['files'] if r['path'] not in A.EXTRA_CODE]
        raw=C.canonical(code);ctx=replace(f.authority,code_sha256=C.digest(raw))
        self.denied(f,lambda:V2.select_catalog(f.cr,f.pr,f.ar,raw,ctx),'V2_CODE_CLOSURE_REQUIRED')
    def test_real_cli_positive_negative_and_missing_policy(self):
        for forbidden in [False,True]:
            f=self.fixture({'private/canary.py' if forbidden else 'a.py':'FICTITIOUS\n'})
            out=f.base/'cli-output';result=subprocess.run([sys.executable,'-B',str(PRODUCT/'tools/source_selection_v2.py'),*f.cli(out)],capture_output=True)
            self.assertEqual(result.returncode,2 if forbidden else 0,result.stderr.decode())
            if forbidden:self.assertIn(b'OWNER_CATALOG_DENIED',result.stdout);self.assertFalse(out.exists())
            else:
                receipt=json.loads(result.stdout)
                args=['--artifacts',str(out),'--source-root',str(f.source),'--catalog-sha256',f.authority.catalog_sha256,
                      '--policy-sha256',f.authority.selection_policy_sha256,'--admission-policy',str(f.config/'owner.json'),
                      '--admission-policy-sha256',f.authority.admission_policy_sha256,'--code-sha256',f.authority.code_sha256,
                      '--manifest-sha256',receipt['manifest_sha256']]
                verified=subprocess.run([sys.executable,'-B',str(PRODUCT/'tools/verify_selection_v2.py'),*args],capture_output=True)
                self.assertEqual(verified.returncode,0,verified.stderr.decode())
        result=subprocess.run([sys.executable,'-B',str(PRODUCT/'tools/source_selection_v2.py'),'--source-root',str(f.source)],capture_output=True)
        self.assertEqual(result.returncode,2)
    def test_output_existing_refusal_and_configuration_disjointness(self):
        f=self.fixture();out,_=self.publish(f)
        with self.assertRaises(FileExistsError):V2.execute(*f.args(out))
        self.denied(f,lambda:V2.execute(*f.args(f.source/'output')),'CONFIG_OR_OUTPUT_INSIDE_SOURCE')
    def test_lower_budget_keeps_all_members_admission_and_max32(self):
        f=self.fixture({f'a{i:02}.py':'VALUE=1\n' for i in range(35)})
        plan,_,_=f.direct();self.assertEqual(len(plan['legacy_plan']['selected']),32)
        f.p['max_selected']=True;f.refresh();self.denied(f)

if __name__=='__main__':unittest.main()