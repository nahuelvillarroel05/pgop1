"""Additive syntax-only claims and conservative static module associations."""
import ast
from contextlib import ExitStack
import os
from pathlib import Path
import tempfile
from .code_contract_v1 import (check_catalog,check_claim,position,finish_report,pages,
                               canonical,digest,HANDOFF)
from .document_claims_v1 import strict_json,require
from .static_ast_v2 import read_registered

DECL=(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)
DYNAMIC={'exec','eval','globals','locals','vars','setattr','delattr','__import__','getattr'}

def local_nodes(scope):
    stack=list(reversed(scope.body))
    while stack:
        n=stack.pop();yield n
        if not isinstance(n,DECL+(ast.Lambda,)):
            stack.extend(reversed(list(ast.iter_child_nodes(n))))

def dynamic(tree):
    return any((isinstance(n,ast.ImportFrom) and any(a.name=='*' for a in n.names)) or
               (isinstance(n,ast.Call) and isinstance(n.func,ast.Name) and n.func.id in DYNAMIC) or
               (isinstance(n,ast.Attribute) and isinstance(n.value,ast.Name) and
                ((n.value.id=='sys' and n.attr=='path') or n.value.id=='importlib')) for n in ast.walk(tree))

def evaluate(c,bodies,structures):
    outputs=[];trees={}
    for q in c['claims']:
        row=dict(claim_id=q['claim_id'],status='ADMITTED',verdict='INSUFFICIENT_EVIDENCE',
                 reason='RELEVANT_TREE_NOT_COMPLETE',coverage='ABSENT',evidence=[])
        outputs.append(row)
        try:check_claim(q,c)
        except ValueError as exc:
            row.update(status='REJECTED',verdict=None,reason=str(exc));continue
        except (TypeError,KeyError):
            row.update(status='REJECTED',verdict=None,reason='INVALID_CLAIM_CONTRACT');continue
        path=q['source_ref'];report=structures[path]
        row['source_sha256']=report['source_sha256'];row['ast_snapshot_id']=report['snapshot_id']
        if report['status']!='COMPLETE':continue
        selector=q['scope']
        units=[u for u in report['units'] if (u['node']=='Module' if selector=='<module>' else
                u['id']==selector if selector.startswith('node-') else u['qualified_name']==selector)]
        if len(units)!=1:row['reason']='SCOPE_MISSING_OR_AMBIGUOUS';continue
        unit=units[0];row.update(scope_id=unit['id'],coverage=unit['status'])
        if unit['status']!='COMPLETE':continue
        if path not in trees:trees[path]=ast.parse(bodies[path])
        tree=trees[path]
        node=next(n for n in ast.walk(tree) if type(n).__name__==unit['node'] and
                  getattr(n,'lineno',0)==unit['line'] and getattr(n,'col_offset',0)==unit['column'])
        ancestors=[u for u in report['units'] if u['id']==unit['id'] or any(
            u['line']==s['line'] and u['column']==s['column'] and u['node']==s['node'] for s in unit['scope_chain'])]
        if any(u.get('conditional') or u.get('decorated') for u in ancestors):
            row['reason']='CONDITIONAL_OR_DECORATED_SCOPE';continue
        f=q['predicate'];p=q['parameters']
        wanted={'symbol_defined':{'Module','ClassDef','FunctionDef','AsyncFunctionDef'},
                'class_method_declared':{'ClassDef'},'function_parameter_declared':{'FunctionDef','AsyncFunctionDef'},
                'module_import_declared':{'Module'}}[f]
        if unit['node'] not in wanted:row['reason']='WRONG_SCOPE_KIND';continue
        matches=[];hazard=False
        if f in {'symbol_defined','class_method_declared'}:
            name=p['name'];decls=[n for n in local_nodes(node) if isinstance(n,DECL) and n.name==name]
            if len(decls)>1 or any(n not in node.body or n.decorator_list for n in decls):hazard=True
            if any((isinstance(n,ast.Name) and isinstance(n.ctx,(ast.Store,ast.Del)) and n.id==name) or
                   (isinstance(n,ast.alias) and (n.asname or n.name.split('.')[0])==name) or
                   (isinstance(n,(ast.ExceptHandler,ast.MatchAs,ast.MatchStar)) and n.name==name) or
                   (isinstance(n,ast.MatchMapping) and n.rest==name) or
                   (isinstance(n,(ast.Global,ast.Nonlocal)) and name in n.names) for n in local_nodes(node)):hazard=True
            matches=[n for n in node.body if isinstance(n,DECL) and n.name==name and
                     (f=='class_method_declared' and isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) or
                      f=='symbol_defined' and (p['kind']=='any' or type(n).__name__==p['kind']))]
            hazard=hazard or dynamic(node)
        elif f=='function_parameter_declared':
            args=node.args
            values={'posonly':args.posonlyargs,'positional':args.args,'kwonly':args.kwonlyargs,
                    'vararg':[args.vararg] if args.vararg else [],'kwarg':[args.kwarg] if args.kwarg else []}
            matches=[n for n in values[p['kind']] if n.arg==p['name']]
        else:
            def matching(n):
                return ((p['form']=='import' and isinstance(n,ast.Import)) or
                        (p['form']=='from' and isinstance(n,ast.ImportFrom) and (n.module or '')==p['module'] and n.level==p['level']))
            pairs=[(n,a) for n in local_nodes(node) if matching(n) for a in n.names if a.name==p['name'] and a.asname==p['asname']]
            hazard=any(n not in node.body for n,a in pairs) or len(pairs)>1 or dynamic(node)
            matches=[a for n,a in pairs if n in node.body]
        if hazard:row['reason']='AMBIGUOUS_CONDITIONAL_DECORATED_OR_DYNAMIC';continue
        row.update(verdict='SUPPORTED' if bool(matches)==q['expected'] else 'CONTRADICTED',
                   reason='EXACT_DIRECT_SYNTAX_ONLY',evidence=[position(n) for n in matches])
    return outputs

def module_index(c):
    index={};owners={}
    for pin in c['sources']:
        path=pin['path']
        for root in c['package_roots']:
            prefix='' if root=='.' else root+'/'
            if not path.startswith(prefix):continue
            rel=path[len(prefix):];parts=rel[:-3].split('/')
            if parts[-1]=='__init__':parts=parts[:-1]
            if not parts:continue
            name='.'.join(parts)
            index.setdefault(name,[]).append((path,root))
            owners.setdefault(path,[]).append((name,root))
    return index,owners

def complete_chain(path,root,pins):
    prefix='' if root=='.' else root+'/'
    parts=path[len(prefix):].split('/')[:-1]
    return all(prefix+'/'.join(parts[:i])+'/__init__.py' in pins for i in range(1,len(parts)+1))

def resolve(c,bodies,structures):
    universe=digest(canonical(c));pins={p['path']:p for p in c['sources']}
    index,owners=module_index(c);rows=[]
    for pin in c['sources']:
        path=pin['path'];r=structures[path]
        tree=ast.parse(bodies[path]) if r['status']=='COMPLETE' else None
        for ri,edge in enumerate(r['relations']):
            if edge['kind']=='defines':continue
            aliases=edge.get('aliases',[None])
            for ai,alias in enumerate(aliases):
                row=dict(schema='pgop1.static-module-resolution.v1',from_source=path,source_sha256=pin['sha256'],
                         selected_universe_id=universe,scope=edge['scope_id'],line=edge['line'],column=edge['column'],
                         kind=edge['kind'],legacy_relation_index=ri,alias_index=ai,
                         used_name=alias['name'] if alias else edge.get('expression'),
                         resolution=edge['resolution'],rule='NO_RUNTIME_TARGET',uncertainty='STATIC_SYNTAX_ONLY',BEHAVIORAL_LINK='NOT_PROVEN')
                if edge['kind']=='imports':
                    row.update(resolution='UNRESOLVED',rule='RAW_HAS_NO_MODULE_STRUCTURE')
                    if c['mode']=='CODE_TREE':
                        row.update(resolution='AMBIGUOUS',rule='IMPORT_CONTEXT_OR_BINDING_AMBIGUOUS')
                        module_scope=next((u for u in r['units'] if u['id']==edge['scope_id'] and u['node']=='Module'),None)
                        n=next((n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom)) and n.lineno==edge['line'] and n.col_offset==edge['column']),None) if tree else None
                        bound=(alias['asname'] or alias['name'].split('.')[0])
                        bindings=[x for x in ast.walk(tree) if
                                  isinstance(x,ast.Name) and isinstance(x.ctx,(ast.Store,ast.Del)) and x.id==bound or
                                  isinstance(x,ast.arg) and x.arg==bound or
                                  isinstance(x,(ast.ExceptHandler,ast.MatchAs,ast.MatchStar)) and x.name==bound or
                                  isinstance(x,ast.MatchMapping) and x.rest==bound or
                                  isinstance(x,DECL) and x.name==bound or
                                  isinstance(x,ast.alias) and (x.asname or x.name.split('.')[0])==bound] if tree else []
                        if module_scope and n and not dynamic(tree) and len(bindings)==1:
                            from_form=isinstance(n,ast.ImportFrom)
                            mod=(n.module or '') if from_form else alias['name']
                            valid=True
                            if from_form and n.level:
                                owner=owners.get(path,[])
                                if len(owner)!=1:valid=False
                                else:
                                    own,root=owner[0];package=own.split('.') if path.endswith('/__init__.py') else own.split('.')[:-1]
                                    if n.level>len(package):valid=False
                                    elif not complete_chain(path,root,pins):
                                        row.update(resolution='OUTSIDE_SELECTED_UNIVERSE',rule='INCOMPLETE_PACKAGE_CHAIN');valid=False
                                    else:mod='.'.join(package[:len(package)-n.level+1]+([mod] if mod else []))
                            if valid:
                                target=mod+'.'+alias['name'] if from_form and mod+'.'+alias['name'] in index else mod
                                candidates=index.get(target,[])
                                if len(candidates)>1:row['rule']='MULTIPLE_SELECTED_MODULES'
                                elif not candidates:row.update(resolution='OUTSIDE_SELECTED_UNIVERSE',rule='NO_SELECTED_MODULE')
                                else:
                                    dest,root=candidates[0]
                                    if not complete_chain(dest,root,pins):row.update(resolution='OUTSIDE_SELECTED_UNIVERSE',rule='INCOMPLETE_PACKAGE_CHAIN')
                                    elif structures[dest]['status']!='COMPLETE':row['rule']='TARGET_AST_NOT_COMPLETE'
                                    else:row.update(resolution='CANDIDATE_ONLY' if from_form else 'LOCAL_MODULE_MATCH',
                                                    rule='FROM_ATTRIBUTE_OR_SUBMODULE' if from_form else 'UNIQUE_CLOSED_MODULE_SYNTAX',
                                                    to_source=dest,to_source_sha256=pins[dest]['sha256'])
                row['relation_id']=digest(canonical(row));rows.append(row)
    return rows

def derive(c,snapshot,ast_report):
    bodies={p['path']:bytes.fromhex(p['raw_hex']) for p in snapshot['captures']}
    structures={r['source']['path']:r for r in ast_report['structures']}
    return finish_report(c,snapshot['snapshot_id'],evaluate(c,bodies,structures),resolve(c,bodies,structures))

class CodeOnlyProfile:
    def __init__(self,*,source_root,catalog_path,catalog_sha256):
        self.source_root=source_root;self.catalog_path=catalog_path;self.sha=catalog_sha256

    def generate(self,output):
        require(os.name=='nt','WINDOWS_ONLY')
        from .windows_safe_io_v2 import Directory,absolute,reject_membership,safe_create_artifacts
        from tools.audit_snapshot_v1 import snapshot_and_write
        from tools.verify_source_v2 import read_source
        from tools.verify_code_only_v1 import verify_values
        root=Path(__file__).absolute().parents[2]
        absolute(self.catalog_path);drive,parts=absolute(output);require(bool(parts),'UNSAFE_PATH')
        with ExitStack() as tx:
            held=[tx.enter_context(Directory(p)) for p in (self.source_root,Path(self.catalog_path).parent,root)]
            parent=tx.enter_context(Directory(drive+'\\'.join(parts[:-1])))
            for d in held:reject_membership(parent,d)
            raw=read_registered(Path(self.catalog_path).parent,Path(self.catalog_path).name,self.sha)
            c=check_catalog(strict_json(raw),self.sha);require(raw==canonical(c),'CANONICAL_CATALOG')
            require(os.path.normcase(str(self.source_root).replace('/','\\'))==os.path.normcase(c['authorized_root'].replace('/','\\')),'AUTHORIZED_ROOT')
            with tempfile.TemporaryDirectory(prefix='code-only-') as tmp:
                tmp=Path(tmp);config=tmp/'config';config.mkdir()
                base=dict(schema='pgop1.source-audit-catalog.v2',sources=[{k:p[k] for k in ('path','sha256','kind')} for p in c['sources']],claims=[])
                base_raw=canonical(base);(config/'base.json').write_bytes(base_raw)
                stage=tmp/'snapshot'
                snapshot_and_write(self.source_root,config/'base.json',digest(base_raw),stage)
                files={}
                for old,new in [('SNAPSHOT.json','SNAPSHOT.json'),('REPORT.json','AST_REPORT.json'),('MANIFEST.json','SNAPSHOT_MANIFEST.json'),('FINAL_HANDOFF.md','SNAPSHOT_HANDOFF.md')]:
                    files[new]=read_source(stage,old,None,128_000_000)
                snapshot=strict_json(files['SNAPSHOT.json']);ar=strict_json(files['AST_REPORT.json'])
                report=derive(c,snapshot,ar)
                files.update({'CATALOG.json':raw,'REPORT.json':canonical(report),'PAGES.json':canonical(pages(report)),'FINAL_HANDOFF.md':HANDOFF})
                verify_values(files,self.sha)
                files['MANIFEST.json']=canonical(dict(schema='pgop1.code-only-manifest.v1',catalog_sha256=self.sha,
                    files={n:dict(bytes=len(b),sha256=digest(b)) for n,b in files.items()}))
                for d in (*held,parent):d.validate()
                safe_create_artifacts(self.source_root,output,files,(root,Path(self.catalog_path).parent))
                for d in (*held,parent):d.validate()
        return dict(status='CODE_ONLY_WRITTEN',operation_completed=True,report_id=report['report_id'],catalog_sha256=self.sha,
                    source_current_at_ack='NOT_PROVEN',artifact_current_at_ack='NOT_PROVEN')

    def verify(self,artifacts):
        from tools.verify_code_only_v1 import verify_bundle
        return verify_bundle(artifacts,self.sha)

    def query(self,artifacts,*,kind='claims',offset=0,limit=50):
        from tools.verify_code_only_v1 import query_bundle
        return query_bundle(artifacts,self.sha,kind=kind,offset=offset,limit=limit)
