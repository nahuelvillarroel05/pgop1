"""Disposable, fully synthetic history/manifest attacks against the separate verifier."""
import json,os,subprocess,sys,tempfile,unittest
from unittest.mock import patch
from pathlib import Path
ROOT=Path(__file__).absolute().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from audit_distribution import history,worktree,scan,strict,git as audit_git,LIMIT
from update_manifest import update

class DistributionAuditTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(tempfile.mkdtemp(prefix='git-negative-',dir=os.environ.get('PGOP1_TEST_ROOT')))
        self.git('init','--initial-branch=main','--template=')
        self.git('config','user.name','PGOP1 synthetic test')
        self.git('config','user.email','pgop1-test@example.invalid')
        self.git('config','core.autocrlf','false')
        (self.root/'README.md').write_text('Synthetic inert fixture\n',encoding='utf-8')
        self.commit('synthetic root');self.main=self.git('rev-parse','HEAD').decode().strip()
        self.git('switch','-c','experiment')
        (self.root/'extra.txt').write_text('Synthetic experiment\n',encoding='utf-8')
        self.commit('synthetic child');self.exp=self.git('rev-parse','HEAD').decode().strip()
    def git(self,*args,input=None):
        r=subprocess.run(['git','-c','safe.directory='+self.root.as_posix(),'-C',str(self.root),*args],input=input,capture_output=True)
        self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'));return r.stdout
    def commit(self,message):
        update(self.root);self.git('add','--all');self.git('commit','-m',message)
    def test_clean_complete_inventory(self):
        self.assertGreater(worktree(self.root),0)
        r=history(self.root,self.main,self.exp)
        self.assertEqual(len(r['commits']),2)
        self.assertEqual(set(x['oid'] for x in r['union']),set(r['by_branch']['main'])|set(r['by_branch']['experiment']))
    def test_forged_manifest(self):
        p=self.root/'manifests/PUBLIC_SOURCE_MANIFEST.json';d=json.loads(p.read_bytes());d['files'][0]['sha256']='0'*64;p.write_text(json.dumps(d))
        with self.assertRaisesRegex(ValueError,'hash'):worktree(self.root)
    def test_incomplete_member_list(self):
        p=self.root/'manifests/PUBLIC_SOURCE_MANIFEST.json';d=json.loads(p.read_bytes());d['files'].pop();p.write_text(json.dumps(d))
        with self.assertRaisesRegex(ValueError,'membership'):worktree(self.root)
    def test_changed_source(self):
        (self.root/'extra.txt').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'hash'):worktree(self.root)
    def test_changed_source_and_regenerated_manifest(self):
        (self.root/'extra.txt').write_text('coherent but not committed',encoding='utf-8')
        update(self.root)
        with self.assertRaisesRegex(ValueError,'differs from HEAD'):worktree(self.root)
    def test_missing_file(self):
        (self.root/'extra.txt').unlink()
        with self.assertRaisesRegex(ValueError,'membership'):worktree(self.root)
    def test_unexpected_parent(self):
        (self.root/'third.txt').write_text('unexpected extra generation',encoding='utf-8')
        self.commit('unexpected third commit')
        with self.assertRaisesRegex(ValueError,'graph'):history(self.root)
    def test_extra_tag(self):
        self.git('tag','unexpected')
        with self.assertRaisesRegex(ValueError,'ref/tag'):history(self.root)
    def test_extra_old_blob_without_grafting(self):
        self.git('hash-object','-w','--stdin',input=b'SIMULATED_UNADMITTED_OLD_BLOB')
        with self.assertRaisesRegex(ValueError,'extra or missing'):history(self.root)
    def test_sensitive_simulation_reachable(self):
        self.git('switch','-C','experiment','main')
        (self.root/'extra.txt').write_text('ghp_'+'A'*36,encoding='utf-8')
        self.commit('synthetic sensitive pattern')
        with self.assertRaisesRegex(ValueError,'sensitive'):history(self.root)
    def test_missing_object(self):
        oid=self.git('rev-parse','main:README.md').decode().strip()
        object_path=self.root/'.git/objects'/oid[:2]/oid[2:]
        object_path.chmod(0o600)  # clear read-only attribute of this disposable test object
        object_path.unlink()
        with self.assertRaisesRegex(ValueError,'git command failed'):history(self.root)
    def test_external_anchor(self):
        with self.assertRaisesRegex(ValueError,'pin'):history(self.root,'0'*40,self.exp)
    def test_inherited_git_directory_is_ignored(self):
        with patch.dict(os.environ,{'GIT_DIR':str(self.root/'missing-git'),'GIT_OBJECT_DIRECTORY':str(self.root/'missing-objects')}):
            self.assertEqual(len(history(self.root)['commits']),2)
    def test_object_size_gate_before_body(self):
        oid=self.git('hash-object','-w','--stdin',input=b'x'*(LIMIT+1)).decode().strip()
        with self.assertRaisesRegex(ValueError,'size bound'):audit_git(self.root,'cat-file','blob',oid)
    def test_duplicate_and_nonfinite_json(self):
        for b in [b'{"a":1,"a":2}',b'{"a":NaN}']:
            with self.assertRaises(ValueError):strict(b)
    def test_link_escape(self):
        target=Path(tempfile.mkdtemp(prefix='inert-link-target-',dir=os.environ.get('PGOP1_TEST_ROOT')))
        link=self.root/'escaped'
        if os.name=='nt':
            r=subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(link),str(target)],capture_output=True)
            self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'))
        else:link.symlink_to(target,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'reparse'):worktree(self.root)
    def test_git_object_storage_link_escape(self):
        original=self.root/'.git/objects';target=self.root/'simulated-external-objects'
        original.rename(target)
        if os.name=='nt':
            r=subprocess.run(['cmd.exe','/d','/c','mklink','/J',str(original),str(target)],capture_output=True)
            self.assertEqual(r.returncode,0,r.stderr.decode(errors='replace'))
        else:original.symlink_to(target,target_is_directory=True)
        with self.assertRaisesRegex(ValueError,'reparse'):history(self.root)

if __name__=='__main__':unittest.main()
