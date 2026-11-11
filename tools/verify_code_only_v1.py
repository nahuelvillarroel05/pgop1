"""Independent E3 replay. Does not import code_only_v1 or its resolver."""
import argparse
import ast
from contextlib import ExitStack
import os
import re
from pathlib import Path
import sys
ROOT=Path(__file__).absolute().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'runtime'))
from candidate.code_contract_v1 import (check_catalog,check_claim,canonical,digest,position,
    finish_report,pages,check_page,FILES,HANDOFF,SCOPE)
from candidate.windows_safe_io_v2 import Directory
from tools.verify_source_v2 import strict,require,read_source
from tools.verify_snapshot_v1 import verify_values as verify_snapshot

DEFS=(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef)

def risky(n):
    for x in ast.walk(n):
        if isinstance(x,ast.ImportFrom) and any(a.name=='*' for a in x.names):return True
        if isinstance(x,ast.Call) and isinstance(x.func,ast.Name) and x.func.id in ('exec','eval','globals','locals','vars','setattr','delattr','__import__','getattr'):return True
        if isinstance(x,ast.Attribute) and isinstance(x.value,ast.Name):
            if x.value.id=='importlib' or x.value.id=='sys' and x.attr=='path':return True
    return False

def owned(n):
    result=[]
    def visit(x):
        result.append(x)
        if isinstance(x,DEFS+(ast.Lambda,)):return
        for child in ast.iter_child_nodes(x):visit(child)
    for x in n.body:visit(x)
    return result

def claims_replay(c,captures,reports):
    results=[]
    for query in c['claims']:
        out={'claim_id':query['claim_id'],'status':'ADMITTED','verdict':'INSUFFICIENT_EVIDENCE',
             'reason':'RELEVANT_TREE_NOT_COMPLETE','coverage':'ABSENT','evidence':[]};results.append(out)
        try:check_claim(query,c)
        except ValueError as exc:
            out.update(status='REJECTED',verdict=None,reason=str(exc));continue
        except (KeyError,TypeError):
            out.update(status='REJECTED',verdict=None,reason='INVALID_CLAIM_CONTRACT');continue
        report=reports[query['source_ref']]
        out.update(source_sha256=report['source_sha256'],ast_snapshot_id=report['snapshot_id'])
        if report['status']!='COMPLETE':continue
        selected=[]
        for u in report['units']:
            s=query['scope']
            if s=='<module>':yes=u['node']=='Module'
            elif s.startswith('node-'):yes=u['id']==s
            else:yes=u['qualified_name']==s
            if yes:selected.append(u)
        if len(selected)!=1:out['reason']='SCOPE_MISSING_OR_AMBIGUOUS';continue
        u=selected[0];out.update(scope_id=u['id'],coverage=u['status'])
        if u['status']!='COMPLETE':continue
        tree=ast.parse(captures[query['source_ref']]);scope=None
        for n in ast.walk(tree):
            if (type(n).__name__,getattr(n,'lineno',0),getattr(n,'col_offset',0))==(u['node'],u['line'],u['column']):scope=n;break
        blocked=False
        for v in report['units']:
            is_ancestor=v['id']==u['id'] or any((v['line'],v['column'],v['node'])==(a['line'],a['column'],a['node']) for a in u['scope_chain'])
            if is_ancestor and (v.get('conditional') or v.get('decorated')):blocked=True
        if blocked:out['reason']='CONDITIONAL_OR_DECORATED_SCOPE';continue
        family=query['predicate'];p=query['parameters']
        if (family=='class_method_declared' and not isinstance(scope,ast.ClassDef) or
            family=='function_parameter_declared' and not isinstance(scope,(ast.FunctionDef,ast.AsyncFunctionDef)) or
            family=='module_import_declared' and not isinstance(scope,ast.Module)):
            out['reason']='WRONG_SCOPE_KIND';continue
        found=[];uncertain=False
        if family=='function_parameter_declared':
            a=scope.args
            groups=dict(posonly=a.posonlyargs,positional=a.args,kwonly=a.kwonlyargs,
                        vararg=[] if a.vararg is None else [a.vararg],kwarg=[] if a.kwarg is None else [a.kwarg])
            for n in groups[p['kind']]:
                if n.arg==p['name']:found.append(n)
        elif family=='module_import_declared':
            pairs=[]
            for n in owned(scope):
                if p['form']=='import':matches=isinstance(n,ast.Import)
                else:matches=isinstance(n,ast.ImportFrom) and n.level==p['level'] and (n.module or '')==p['module']
                if matches:
                    for alias in n.names:
                        if (alias.name,alias.asname)==(p['name'],p['asname']):pairs.append((n,alias))
            uncertain=len(pairs)>1 or any(n not in scope.body for n,a in pairs) or risky(scope)
            found=[a for n,a in pairs if n in scope.body]
        else:
            name=p['name'];targets=[]
            for n in owned(scope):
                if isinstance(n,DEFS) and n.name==name:targets.append(n)
                if isinstance(n,ast.Name) and n.id==name and isinstance(n.ctx,(ast.Store,ast.Del)):uncertain=True
                if isinstance(n,ast.alias) and (n.asname or n.name.split('.')[0])==name:uncertain=True
                if isinstance(n,(ast.ExceptHandler,ast.MatchAs,ast.MatchStar)) and n.name==name:uncertain=True
                if isinstance(n,ast.MatchMapping) and n.rest==name:uncertain=True
                if isinstance(n,(ast.Global,ast.Nonlocal)) and name in n.names:uncertain=True
            uncertain=uncertain or len(targets)>1 or any(n not in scope.body or n.decorator_list for n in targets) or risky(scope)
            for n in scope.body:
                if not isinstance(n,DEFS) or n.name!=name:continue
                if family=='class_method_declared' and isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)):found.append(n)
                if family=='symbol_defined' and (p['kind']=='any' or p['kind']==type(n).__name__):found.append(n)
        if uncertain:out['reason']='AMBIGUOUS_CONDITIONAL_DECORATED_OR_DYNAMIC';continue
        out.update(verdict='SUPPORTED' if bool(found)==query['expected'] else 'CONTRADICTED',reason='EXACT_DIRECT_SYNTAX_ONLY',evidence=[position(n) for n in found])
    return results

def resolution_replay(c,captures,reports):
    table={};inverse={};pins={p['path']:p for p in c['sources']};rows=[]
    for root in c['package_roots']:
        for path in pins:
            prefix='' if root=='.' else root+'/'
            if not path.startswith(prefix):continue
            components=path[len(prefix):-3].split('/')
            if components[-1]=='__init__':components.pop()
            if components:
                module='.'.join(components)
                table.setdefault(module,[]).append((path,root));inverse.setdefault(path,[]).append((module,root))
    def parents_present(path,root):
        prefix='' if root=='.' else root+'/'
        folder=path[len(prefix):].split('/')[:-1]
        for length in range(1,len(folder)+1):
            if prefix+'/'.join(folder[:length])+'/__init__.py' not in pins:return False
        return True
    for pin in c['sources']:
        source=pin['path'];report=reports[source]
        tree=ast.parse(captures[source]) if report['status']=='COMPLETE' else None
        for number,e in enumerate(report['relations']):
            if e['kind']=='defines':continue
            for alias_number,a in enumerate(e['aliases'] if e['kind']=='imports' else [None]):
                out=dict(schema='pgop1.static-module-resolution.v1',from_source=source,source_sha256=pin['sha256'],
                         selected_universe_id=digest(canonical(c)),scope=e['scope_id'],line=e['line'],column=e['column'],
                         kind=e['kind'],legacy_relation_index=number,alias_index=alias_number,
                         used_name=a['name'] if a is not None else e.get('expression'),resolution=e['resolution'],
                         rule='NO_RUNTIME_TARGET',uncertainty='STATIC_SYNTAX_ONLY',BEHAVIORAL_LINK='NOT_PROVEN')
                if a is not None:
                    out.update(resolution='UNRESOLVED',rule='RAW_HAS_NO_MODULE_STRUCTURE')
                    if c['mode']=='CODE_TREE':
                        out.update(resolution='AMBIGUOUS',rule='IMPORT_CONTEXT_OR_BINDING_AMBIGUOUS')
                        direct=None;module_unit=False;count=0
                        if tree is not None:
                            module_unit=any(u['node']=='Module' and u['id']==e['scope_id'] for u in report['units'])
                            direct=next((x for x in tree.body if isinstance(x,(ast.Import,ast.ImportFrom)) and (x.lineno,x.col_offset)==(e['line'],e['column'])),None)
                            bound=a['asname'] or a['name'].split('.')[0]
                            for x in ast.walk(tree):
                                if (isinstance(x,ast.Name) and isinstance(x.ctx,(ast.Store,ast.Del)) and x.id==bound or
                                    isinstance(x,ast.arg) and x.arg==bound or isinstance(x,DEFS) and x.name==bound or
                                    isinstance(x,(ast.ExceptHandler,ast.MatchAs,ast.MatchStar)) and x.name==bound or
                                    isinstance(x,ast.MatchMapping) and x.rest==bound or
                                    isinstance(x,ast.alias) and (x.asname or x.name.split('.')[0])==bound):count+=1
                        if direct is not None and module_unit and count==1 and not risky(tree):
                            from_import=isinstance(direct,ast.ImportFrom);name=(direct.module or '') if from_import else a['name'];ok=True
                            if from_import and direct.level:
                                owning=inverse.get(source,[])
                                if len(owning)!=1:ok=False
                                else:
                                    full,base=owning[0];context=full.split('.')
                                    if not source.endswith('/__init__.py'):context=context[:-1]
                                    if direct.level>len(context):ok=False
                                    elif not parents_present(source,base):
                                        out.update(resolution='OUTSIDE_SELECTED_UNIVERSE',rule='INCOMPLETE_PACKAGE_CHAIN');ok=False
                                    else:name='.'.join(context[:len(context)+1-direct.level]+([name] if name else []))
                            if ok:
                                if from_import and name+'.'+a['name'] in table:name=name+'.'+a['name']
                                choices=table.get(name,[])
                                if len(choices)>1:out['rule']='MULTIPLE_SELECTED_MODULES'
                                elif len(choices)==0:out.update(resolution='OUTSIDE_SELECTED_UNIVERSE',rule='NO_SELECTED_MODULE')
                                else:
                                    dest,base=choices[0]
                                    if not parents_present(dest,base):out.update(resolution='OUTSIDE_SELECTED_UNIVERSE',rule='INCOMPLETE_PACKAGE_CHAIN')
                                    elif reports[dest]['status']!='COMPLETE':out['rule']='TARGET_AST_NOT_COMPLETE'
                                    else:out.update(to_source=dest,to_source_sha256=pins[dest]['sha256'],
                                        resolution='CANDIDATE_ONLY' if from_import else 'LOCAL_MODULE_MATCH',
                                        rule='FROM_ATTRIBUTE_OR_SUBMODULE' if from_import else 'UNIQUE_CLOSED_MODULE_SYNTAX')
                out['relation_id']=digest(canonical(out));rows.append(out)
    return rows

def verify_values(files,external_sha):
    require(set(files)==set(FILES),'ARTIFACT_MEMBERSHIP')
    require(all(type(files[n]) is bytes and len(files[n])<=cap for n,cap in FILES.items()),'ARTIFACT_SIZE')
    c=check_catalog(strict(files['CATALOG.json']),external_sha)
    require(canonical(c)==files['CATALOG.json'],'CATALOG_CANONICAL')
    snap=strict(files['SNAPSHOT.json']);ar=strict(files['AST_REPORT.json'])
    expected_base=dict(schema='pgop1.source-audit-catalog.v2',sources=[{k:p[k] for k in ('path','sha256','kind')} for p in c['sources']],claims=[])
    require(canonical(ar['catalog'])==canonical(expected_base),'SNAPSHOT_CATALOG')
    verify_snapshot(ar,snap,digest(canonical(expected_base)))
    sm=strict(files['SNAPSHOT_MANIFEST.json'])
    require(set(sm)=={'schema','catalog_sha256','snapshot_id','files'} and sm['schema']=='pgop1.evidence-snapshot-manifest.v1' and
            sm['catalog_sha256']==digest(canonical(expected_base)) and sm['snapshot_id']==snap['snapshot_id'],'SNAPSHOT_MANIFEST')
    require(set(sm['files'])=={'REPORT.json','SNAPSHOT.json','FINAL_HANDOFF.md'},'SNAPSHOT_MANIFEST_MEMBERSHIP')
    for old,new in [('REPORT.json','AST_REPORT.json'),('SNAPSHOT.json','SNAPSHOT.json'),('FINAL_HANDOFF.md','SNAPSHOT_HANDOFF.md')]:
        p=sm['files'][old];require(set(p)=={'bytes','sha256'} and type(p['bytes']) is int and p==dict(bytes=len(files[new]),sha256=digest(files[new])),'SNAPSHOT_MANIFEST_PIN')
    from tools.verify_snapshot_v1 import HANDOFF as LEGACY_HANDOFF
    require(files['SNAPSHOT_HANDOFF.md']==LEGACY_HANDOFF and files['FINAL_HANDOFF.md']==HANDOFF,'HANDOFF_SCOPE')
    captures={r['path']:bytes.fromhex(r['raw_hex']) for r in snap['captures']}
    for p in c['sources']:require(len(captures[p['path']])==p['bytes'],'SOURCE_LENGTH')
    reports={r['source']['path']:r for r in ar['structures']}
    claims=claims_replay(c,captures,reports);relations=resolution_replay(c,captures,reports)
    report=finish_report(c,snap['snapshot_id'],claims,relations)
    require(files['REPORT.json']==canonical(report),'INDEPENDENT_REPORT_DERIVATION')
    require(files['PAGES.json']==canonical(pages(report)),'PAGINATION')
    return report

def verified_report(folder,expected):
    require(os.name=='nt','WINDOWS_ONLY')
    with Directory(folder) as held:
        raw=read_source(folder,'MANIFEST.json',None,1_000_000);m=strict(raw)
        require(set(m)=={'schema','catalog_sha256','files'} and m['schema']=='pgop1.code-only-manifest.v1' and m['catalog_sha256']==expected,'MANIFEST_SCHEMA')
        require(isinstance(m['files'],dict) and set(m['files'])==set(FILES),'MANIFEST_MEMBERSHIP')
        # Enumerate the held Windows directory only for exact artifact membership;
        # no discovered source path is ever opened.
        require(set(os.listdir(folder))==set(FILES)|{'MANIFEST.json'},'PHYSICAL_ARTIFACT_MEMBERSHIP')
        files={}
        for name,limit in FILES.items():
            pin=m['files'][name]
            require(isinstance(pin,dict) and set(pin)=={'bytes','sha256'} and type(pin['bytes']) is int and 0<=pin['bytes']<=limit,'ARTIFACT_PIN')
            require(isinstance(pin['sha256'],str) and re.fullmatch('[a-f0-9]{64}',pin['sha256']) is not None,'ARTIFACT_HASH')
            files[name]=read_source(folder,name,pin['sha256'],limit)
            require(len(files[name])==pin['bytes'],'ARTIFACT_LENGTH')
        report=verify_values(files,expected);held.validate()
    return report

def verify_bundle(folder,expected):
    r=verified_report(folder,expected)
    return dict(status='CODE_ONLY_VERIFIED',operation_completed=True,report_id=r['report_id'],catalog_sha256=expected,
                claims=len(r['claims']),relations=len(r['relations']),**SCOPE)

def query_bundle(folder,expected,*,kind='claims',offset=0,limit=50):
    require(kind in {'claims','relations'},'PAGE_KIND');r=verified_report(folder,expected)
    check_page(offset,limit,len(r[kind]));items=r[kind][offset:offset+limit];end=offset+len(items)
    return dict(report_id=r['report_id'],kind=kind,items=items,total=len(r[kind]),next_offset=end if end<len(r[kind]) else None,**SCOPE)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--artifacts',required=True);p.add_argument('--catalog-sha256',required=True)
    a=p.parse_args()
    try:result=verify_bundle(a.artifacts,a.catalog_sha256)
    except (OSError,ValueError,KeyError,TypeError,UnicodeError,RecursionError,MemoryError):
        print(canonical(dict(status='ERROR',reason='CODE_ONLY_VERIFICATION_FAILED',operation_completed=False,**SCOPE)).decode());return 1
    print(canonical(result).decode());return 0
if __name__=='__main__':raise SystemExit(main())
