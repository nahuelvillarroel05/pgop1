"""Independent stdlib verifier. Does not import the report producer or target code.

Integrity against local manifests is not external authenticity or a rights grant.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys

MANIFEST='manifests/PUBLIC_SOURCE_MANIFEST.json'
GENERATED={'.git','.venv','audit-output','public-handoffs','verification-output','__pycache__'}
LIMIT=2_000_000

def need(ok,message):
    if not ok:raise ValueError(message)

def digest(body):return hashlib.sha256(body).hexdigest()

def strict(body):
    def pairs(items):
        result={}
        for k,v in items:
            need(k not in result,'duplicate JSON key');result[k]=v
        return result
    def invalid(x):raise ValueError('nonfinite JSON')
    return json.loads(body,object_pairs_hook=pairs,parse_constant=invalid)

def path_ok(name):
    need(isinstance(name,str) and name and '\\' not in name and ':' not in name,'unsafe member')
    p=PurePosixPath(name)
    need(not p.is_absolute() and all(x not in ('','.','..') for x in name.split('/')),'unsafe member')

def no_links(path):
    for p in (*reversed(path.absolute().parents),path.absolute()):
        s=p.lstat()
        need(not stat.S_ISLNK(s.st_mode) and not getattr(s,'st_file_attributes',0)&0x400,'symlink/reparse denied')

def read(path):
    no_links(path);need(path.is_file(),'not a regular file')
    need(path.stat().st_size<=LIMIT,'body exceeds audit size bound')
    return path.read_bytes()

def storage(root):
    """Inspect metadata only, before Git may follow its internal storage paths."""
    gitdir=root/'.git';no_links(gitdir)
    need(gitdir.is_dir(),'standalone .git directory required')
    for name in ['objects/info/alternates','shallow','info/grafts','commondir']:
        need(not os.path.lexists(gitdir/name),'external/partial genealogy forbidden')
    for directory,dirs,files in os.walk(gitdir,followlinks=False):
        for name in dirs+files:no_links(Path(directory)/name)

def scan(body):
    text=body.decode('utf-8')
    # Concrete credentials and host PII. Synthetic controls use SIMULATED_* markers.
    patterns=[r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',r'gh[pousr]_[A-Za-z0-9]{30,}',r'AKIA[A-Z0-9]{16}',r'[A-Za-z]:[\\/]Users[\\/][^\s"\']+',r'[A-Za-z]:[\\/]PGOP1_DATA[\\/]',r'(?i)https?://[^/\s]+:[^@\s]+@']
    need(not any(re.search(p,text) for p in patterns),'sensitive-content pattern')

def manifest(body,members,get):
    m=strict(body)
    need(m['schema']=='pgop1.source-manifest.v1','unsupported manifest')
    need(m['exclusions']=={'self':MANIFEST,'generated_top_level':sorted(GENERATED)},'exclusions changed')
    rows=m['files'];need(isinstance(rows,list),'invalid members')
    names=[r['path'] for r in rows]
    need(len(names)==len(set(names)) and names==sorted(names),'duplicate/unsorted membership')
    need(set(names)==set(members)-{MANIFEST},'incomplete/extra manifest membership')
    for r in rows:
        path_ok(r['path']);data=get(r['path'])
        need(r=={'path':r['path'],'bytes':len(data),'sha256':digest(data)},'size/hash mismatch: '+r['path'])
    if 'manifests/SOURCE_PROVENANCE.json' in members:
        provenance=strict(get('manifests/SOURCE_PROVENANCE.json'))
        seen=set()
        for r in provenance['files']:
            name=r['path'];path_ok(name);need(name in members and name not in seen,'invalid provenance membership');seen.add(name)
            data=get(name)
            need(r['transformation'] in ('IDENTICAL_BYTES','IDENTICAL_BYTES_RELOCATED'),'unknown identity transform')
            need(digest(data)==r['source_sha256'],'provenance SHA-256 mismatch')
            need(hashlib.sha1(f'blob {len(data)}\0'.encode()+data).hexdigest()==r['source_oid'],'provenance OID mismatch')
            need(r['license']=='Apache-2.0','unexpected source license declaration')
        for r in provenance.get('adaptations',[]):
            path_ok(r['path']);need(r['path'] in members,'adaptation missing')
            need(digest(get(r['path']))==r['current_sha256'],'derived adaptation hash stale')
    return len(rows)

def worktree(root):
    storage(root)
    no_links(root)
    names=[]
    for directory,dirs,files in os.walk(root,followlinks=False):
        d=Path(directory)
        for name in dirs+files:
            if d==root and name in GENERATED:continue
            no_links(d/name)
        dirs[:]=[n for n in dirs if not(d==root and n in GENERATED) and n!='__pycache__']
        for name in files:
            names.append((d/name).relative_to(root).as_posix())
    count=manifest(read(root/MANIFEST),names,lambda n:read(root/n))
    # The editable worktree/manifest must match the reviewed commit, not just each other.
    head=git(root,'rev-parse','HEAD').decode().strip()
    admitted={git(root,'rev-parse',b).decode().strip() for b in ['main','experiment']}
    need(head in admitted,'worktree HEAD is not an admitted tip')
    tracked={}
    for item in git(root,'ls-tree','-r','-z','HEAD').split(b'\0'):
        if not item:continue
        meta,name=item.split(b'\t');mode,kind,oid=meta.decode().split()
        need(kind=='blob' and mode in ('100644','100755'),'unsafe worktree tree mode')
        tracked[name.decode()]=(mode,oid)
    need(set(names)==set(tracked),'worktree does not match HEAD membership')
    for name,(mode,oid) in tracked.items():
        data=read(root/name)
        need(hashlib.sha1(f'blob {len(data)}\0'.encode()+data).hexdigest()==oid,'worktree differs from HEAD: '+name)
        if os.name!='nt':need(bool((root/name).stat().st_mode&0o111)==(mode=='100755'),'worktree executable mode differs')
    return count

def git(root,*args):
    if len(args)>=3 and args[0]=='cat-file' and args[1] in ('blob','tree','commit'):
        # Gate before subprocess buffers any object body, including manifests.
        need(git(root,'cat-file','-t',args[2]).decode().strip()==args[1],'object type mismatch')
        need(int(git(root,'cat-file','-s',args[2]))<=LIMIT,'Git object size bound')
    env={k:v for k,v in os.environ.items() if not k.upper().startswith('GIT_')}
    env.update(GIT_NO_REPLACE_OBJECTS='1',GIT_NO_LAZY_FETCH='1')
    p=subprocess.run(['git','--no-optional-locks','-c','safe.directory='+root.as_posix(),'-C',str(root),*args],capture_output=True,env=env)
    need(p.returncode==0,'git command failed: '+' '.join(args))
    return p.stdout

def history(root,expected_main=None,expected_experiment=None):
    storage(root)
    gitdir=Path(git(root,'rev-parse','--absolute-git-dir').decode().strip())
    for name in ['objects/info/alternates','shallow','info/grafts']:
        need(not (gitdir/name).exists(),'external/partial genealogy forbidden')
    no_links(gitdir)
    need((root/'.git').is_dir(),'standalone .git directory required')
    need(gitdir.resolve()==(root/'.git').resolve(),'external Git directory forbidden')
    common=Path(git(root,'rev-parse','--path-format=absolute','--git-common-dir').decode().strip())
    need(common.resolve()==gitdir.resolve(),'external common Git directory forbidden')
    config=git(root,'config','--local','--list').decode()
    need(not re.search(r'(?im)^(remote\..*\.promisor|extensions\.partialclone)=',config),'partial clone forbidden')
    refs={line.split()[0]:line.split()[1] for line in git(root,'for-each-ref','--format=%(refname) %(objectname)').decode().splitlines()}
    need('refs/heads/main' in refs and 'refs/heads/experiment' in refs,'both local branches required; see AUDIT.md')
    main,exp=refs['refs/heads/main'],refs['refs/heads/experiment']
    for pin,observed in [(expected_main,main),(expected_experiment,exp)]:
        if pin:need(pin==observed,'external commit pin mismatch')
    allowed={'refs/heads/main':main,'refs/heads/experiment':exp,'refs/remotes/origin/main':main,'refs/remotes/origin/experiment':exp,'refs/remotes/origin/HEAD':main}
    need(all(k in allowed and allowed[k]==v for k,v in refs.items()),'unexpected ref/tag')
    commits=git(root,'rev-list','--parents','main','experiment').decode().splitlines()
    need(set(commits)=={main,exp+' '+main},'unexpected commit graph')
    objects={};bybranch={};commit_rows=[]
    for branch,oid in [('main',main),('experiment',exp)]:
        members={};tree_rows=[]
        for item in git(root,'ls-tree','-r','-t','-z',oid).split(b'\0'):
            if not item:continue
            meta,name=item.split(b'\t');mode,kind,obj=meta.decode().split();name=name.decode();path_ok(name)
            need(mode in ('040000','100644','100755'),'symlink/submodule mode')
            need(kind in ('tree','blob'),'unexpected tree member')
            tree_rows.append({'path':name,'mode':mode,'type':kind,'oid':obj})
            if kind=='blob':members[name]=obj
        need(MANIFEST in members,'manifest missing')
        # Full fixed membership/types/sizes known before any blob body reads.
        for obj in set(members.values()):
            need(git(root,'cat-file','-t',obj).decode().strip()=='blob','member type mismatch')
            need(int(git(root,'cat-file','-s',obj))<=LIMIT,'Git object size bound')
        manifest(git(root,'cat-file','blob',members[MANIFEST]),members,lambda n:git(root,'cat-file','blob',members[n]))
        reachable=git(root,'rev-list','--objects',oid).decode().splitlines()
        ids=sorted({x.split()[0] for x in reachable});bybranch[branch]=ids
        for obj in ids:
            if obj in objects:continue
            kind=git(root,'cat-file','-t',obj).decode().strip();need(kind in ('commit','tree','blob'),'unexpected object kind')
            size=int(git(root,'cat-file','-s',obj));need(size<=LIMIT,'Git object size bound')
            data=git(root,'cat-file',kind,obj);need(len(data)==size,'object size mismatch')
            computed=hashlib.sha1(f'{kind} {size}\0'.encode()+data).hexdigest()
            need(computed==obj,'Git OID mismatch')
            if kind in ('blob','commit'):scan(data)
            objects[obj]={'oid':obj,'type':kind,'bytes':size,'sha256':digest(data)}
        body=git(root,'cat-file','commit',oid).decode()
        commit_rows.append({'branch':branch,'commit':oid,'tree':git(root,'rev-parse',oid+'^{tree}').decode().strip(),'parents':[x[7:] for x in body.splitlines() if x.startswith('parent ')],'members':tree_rows})
    all_local={x.split()[0] for x in git(root,'cat-file','--batch-all-objects','--batch-check=%(objectname)').decode().splitlines()}
    need(all_local==set(objects),'extra or missing local objects')
    git(root,'fsck','--full','--strict','--no-reflogs')
    return {'refs':refs,'commits':commit_rows,'by_branch':bybranch,'union':sorted(objects.values(),key=lambda x:x['oid']),'review':'Automated integrity and pattern scan; manual rights/content review separate. No external authenticity claim.'}

def artifacts(folder):
    m=strict(read(folder/'MANIFEST.json'));complete=strict(read(folder/'COMPLETE.json'))
    need(complete['manifest_sha256']==digest(read(folder/'MANIFEST.json')),'completion binding mismatch')
    need(set(m['files'])=={'REPORT.json','FINAL_HANDOFF.md'},'unexpected artifacts')
    for name,expected in m['files'].items():
        b=read(folder/name);need(expected=={'bytes':len(b),'sha256':digest(b)},'artifact altered')
    report=strict(read(folder/'REPORT.json'))
    need(report['generation']=='REPORT_GENERATED','generation marker')
    need(report['report_id']==folder.name==m['report_id'],'report binding')
    return {'generation':report['generation'],'verification':report['verification']['status'],'historical_tests':'NOT_RERUN','report_id':folder.name}

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--root',type=Path,default=Path(__file__).absolute().parents[1]);p.add_argument('--output',type=Path);p.add_argument('--expected-main');p.add_argument('--expected-experiment');p.add_argument('--expected-inventory',type=Path);p.add_argument('--artifacts',type=Path)
    a=p.parse_args()
    try:
        result={'status':'PASS','worktree_members':worktree(a.root.absolute()),'history':history(a.root.absolute(),a.expected_main,a.expected_experiment)}
        if a.expected_inventory:
            expected=strict(read(a.expected_inventory));expected=expected.get('history',expected)
            for field in ['commits','by_branch','union']:need(result['history'][field]==expected[field],'inventory mismatch: '+field)
        if a.artifacts:result['artifacts']=artifacts(a.artifacts)
    except (OSError,ValueError,KeyError,TypeError,UnicodeError) as e:
        result={'status':'FAIL','error':str(e)}
    data=json.dumps(result,indent=2)+'\n'
    if a.output:a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(data,encoding='utf-8')
    print(json.dumps({'status':result['status'],'error':result.get('error'),'objects':len(result.get('history',{}).get('union',[]))}))
    return 0 if result['status']=='PASS' else 1
if __name__=='__main__':sys.exit(main())
