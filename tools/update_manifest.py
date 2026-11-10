"""Deterministic prospective manifest maintenance; never grants publication rights."""
import json,os
from pathlib import Path
from audit_distribution import GENERATED,MANIFEST,read,digest

def update(root):
    rows=[]
    for directory,dirs,files in os.walk(root,followlinks=False):
        d=Path(directory)
        dirs[:]=[n for n in dirs if not(d==root and n in GENERATED) and n!='__pycache__']
        for name in files:
            p=d/name;relative=p.relative_to(root).as_posix()
            if relative==MANIFEST:continue
            b=read(p);rows.append({'path':relative,'bytes':len(b),'sha256':digest(b)})
    result={'schema':'pgop1.source-manifest.v1','exclusions':{'self':MANIFEST,'generated_top_level':sorted(GENERATED)},'files':sorted(rows,key=lambda x:x['path'])}
    (root/MANIFEST).parent.mkdir(exist_ok=True)
    (root/MANIFEST).write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    return result
if __name__=='__main__':
    print('Manifest members:',len(update(Path(__file__).absolute().parents[1])['files']))
