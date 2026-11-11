"""Independent V2 replay. Never imports the V2 producer or its semantic helpers."""
import argparse
import ast
from pathlib import Path
import sys
ROOT = Path(__file__).absolute().parents[1]
sys.path[:0] = [str(ROOT/'runtime'), str(ROOT)]
from candidate.binding_contract_v2 import SCHEMA, alias_budget, universe, finish, load_verified_bundle
from candidate.code_contract_v1 import canonical, digest, position, require


def replay(c, snap, ar, limit):
    alias_budget(limit)
    pin = {s['path']: s for s in c['sources']}
    structures = {s['source']['path']: s for s in ar['structures']}
    parsed = {}
    blocked = {}
    names = {}
    defs = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    for capture in snap['captures']:
        p = capture['path']
        if structures[p]['status'] != 'COMPLETE':
            continue
        t = ast.parse(bytes.fromhex(capture['raw_hex'])); parsed[p] = t
        risky = False
        for x in ast.walk(t):
            if (isinstance(x, defs) and x.name == '__getattr__' or
                    isinstance(x, ast.Name) and x.id == '__getattr__' or
                    isinstance(x, ast.alias) and '__getattr__' in (x.name, x.asname) or
                    isinstance(x, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and x.name == '__getattr__' or
                    isinstance(x, ast.MatchMapping) and x.rest == '__getattr__'):
                risky = True
            if isinstance(x, ast.Name) and x.id in ('exec','eval','globals','locals','vars','setattr','delattr','__import__','getattr','__builtins__'):
                risky = True
            if isinstance(x, (ast.Global, ast.Nonlocal, ast.NamedExpr)):
                risky = True
            if isinstance(x, ast.Attribute) and type(x.ctx) in (ast.Store, ast.Del):
                risky = True
            if isinstance(x, ast.Import):
                if any(a.name.split('.')[0] in ('sys','importlib','builtins') for a in x.names): risky = True
            if isinstance(x, ast.ImportFrom):
                if '*' in [a.name for a in x.names] or (x.module or '').split('.')[0] in ('sys','importlib','builtins'): risky = True
        blocked[p] = risky
        found = {}
        def visit(x):
            if isinstance(x, defs): values = [x.name]
            elif isinstance(x, ast.Import): values = [a.asname or a.name.partition('.')[0] for a in x.names]
            elif isinstance(x, ast.ImportFrom): values = [a.asname or a.name for a in x.names]
            elif isinstance(x, ast.Name) and type(x.ctx) in (ast.Store, ast.Del): values = [x.id]
            elif isinstance(x, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and x.name: values = [x.name]
            elif isinstance(x, ast.MatchMapping) and x.rest: values = [x.rest]
            else: values = []
            for name in values: found[name] = found.get(name, 0) + 1
            if not isinstance(x, defs + (ast.Lambda, ast.Import, ast.ImportFrom)):
                for child in ast.iter_child_nodes(x): visit(child)
        for x in t.body: visit(x)
        names[p] = found
    modules = {}; owning = {}
    for root in c['package_roots']:
        prefix = root+'/' if root != '.' else ''
        for p in pin:
            if p.startswith(prefix):
                bits = p[len(prefix):-3].split('/')
                if bits[-1] == '__init__': bits = bits[:-1]
                if bits:
                    key = '.'.join(bits)
                    modules.setdefault(key, []).append((p, root))
                    owning.setdefault(p, []).append((key, root))
    def parents(p, root):
        prefix = '' if root == '.' else root+'/'
        components = p[len(prefix):].split('/')[:-1]
        required = []
        for i in range(len(components)):
            q = prefix + '/'.join(components[:i+1]) + '/__init__.py'
            if q not in pin: return 'OUTSIDE_SELECTED_UNIVERSE','INCOMPLETE_PACKAGE_CHAIN',[]
            if modules.get('.'.join(components[:i+1])) != [(q,root)]: return 'AMBIGUOUS','PACKAGE_IDENTITY_COLLISION',[]
            if q not in parsed: return 'INSUFFICIENT_EVIDENCE','PACKAGE_AST_NOT_COMPLETE',[]
            if blocked[q]: return 'AMBIGUOUS','PACKAGE_DYNAMIC_HAZARD',[]
            required.append(q)
        return None,None,required
    def destination(p, node, alias, bound):
        default = ('AMBIGUOUS','IMPORT_CONTEXT_OR_BINDING_HAZARD',None,None,[])
        t = parsed[p]
        if node not in t.body or blocked[p] or names[p].get(bound) != 1: return default
        owner = owning.get(p, [])
        if len(owner) != 1: return ('AMBIGUOUS' if owner else 'OUTSIDE_SELECTED_UNIVERSE','IMPORTER_MODULE_IDENTITY',None,None,[])
        source_module, root = owner[0]
        state, rule, left = parents(p, root)
        if state: return state,rule,None,None,[]
        is_from = isinstance(node, ast.ImportFrom)
        ref = (node.module or '') if is_from else alias.name
        if is_from:
            package = source_module.split('.') if p.endswith('/__init__.py') else source_module.split('.')[:-1]
            if node.level > len(package): return 'AMBIGUOUS','RELATIVE_IMPORT_ESCAPES_ROOT',None,None,[]
            if node.level: ref = '.'.join(package[:len(package)+1-node.level] + ([ref] if ref else []))
        matches = modules.get(ref, [])
        if not matches: return 'OUTSIDE_SELECTED_UNIVERSE','NO_SELECTED_REFERENCED_MODULE',ref,None,[]
        if len(matches) != 1: return 'AMBIGUOUS','MULTIPLE_SELECTED_MODULES',ref,None,[]
        target, base = matches[0]
        state, rule, right = parents(target, base)
        if state: return state,rule,ref,None,[]
        if target not in parsed: return 'INSUFFICIENT_EVIDENCE','TARGET_AST_NOT_COMPLETE',ref,None,[]
        if blocked[target]: return 'AMBIGUOUS','TARGET_DYNAMIC_HAZARD',ref,None,[]
        return 'LOCAL_MODULE_MATCH','EXPLICIT_SELECTED_MODULE_REFERENCE',ref,target,sorted(set(left+right))
    rows = []; total = 0; uid = universe(c)
    for s in c['sources']:
        p = s['path']; r = structures[p]; t = parsed.get(p)
        observations = {(x.lineno,x.col_offset):x for x in ast.walk(t) if isinstance(x,(ast.Import,ast.ImportFrom))} if t else {}
        for edge in r['relations']:
            if edge['kind'] != 'imports': continue
            total += len(edge['aliases'])
            for i, a in enumerate(edge['aliases']):
                if len(rows) == limit: break
                node = observations.get((edge['line'],edge['column']))
                alias = node.names[i] if node else None
                from_form = isinstance(node, ast.ImportFrom) if node else edge.get('form') == 'from'
                name = alias.name if alias else a['name']; asname = alias.asname if alias else a['asname']
                bound = asname or (name if from_form else name.partition('.')[0])
                state,rule,ref,target,evidence = 'UNRESOLVED','RAW_NO_PACKAGE_STRUCTURE',None,None,[]
                if t is None: state,rule = 'INSUFFICIENT_EVIDENCE','SOURCE_AST_NOT_COMPLETE'
                elif c['mode'] == 'CODE_TREE': state,rule,ref,target,evidence = destination(p,node,alias,bound)
                out = dict(schema=SCHEMA,universe_id=uid,from_source=p,source_sha256=s['sha256'],ast_snapshot_id=r['snapshot_id'],scope_id=edge['scope_id'],
                           source_span=position(node) if node else dict(line=edge['line'],column=edge['column'],end_line=None,end_column=None,node='UNKNOWN'),
                           alias_span=position(alias) if alias else None,alias_index=i,form=('from' if from_form else 'import') if node else 'UNKNOWN',
                           module=((node.module or '') if from_form else '') if node else None,level=(node.level if from_form else 0) if node else None,
                           name=name,asname=asname,bound_name=bound if node else None,endpoint_kind='MODULE_REFERENCE',requested_module=ref,resolution=state,rule=rule,
                           to_source=target,to_source_sha256=pin[target]['sha256'] if target else None,
                           package_evidence=[dict(path=q,sha256=pin[q]['sha256']) for q in evidence],
                           object=dict(name=name,resolution='CANDIDATE_ONLY' if state=='LOCAL_MODULE_MATCH' else 'UNRESOLVED',runtime_target='NOT_PROVEN'),BEHAVIORAL_LINK='NOT_PROVEN')
                out['relation_id'] = digest(canonical(out)); rows.append(out)
    return finish(c,snap['snapshot_id'],rows,{p:structures[p]['status'] for p in pin},total,limit)


def verify_bytes(raw, artifacts, catalog_sha256):
    from tools.verify_source_v2 import strict
    actual = strict(raw)
    require(isinstance(actual,dict), 'REPORT_TYPE')
    limit = alias_budget(actual.get('alias_limit'))
    c,snap,ar = load_verified_bundle(artifacts,catalog_sha256)
    expected = replay(c,snap,ar,limit)
    require(raw == canonical(expected), 'INDEPENDENT_BINDING_DERIVATION')
    return dict(status='STATIC_BINDING_VERIFIED',report_id=expected['report_id'],examined=expected['examined'],
                source_current_at_ack='NOT_PROVEN',artifact_current_at_ack='NOT_PROVEN',parser_independence='SHARED_CPYTHON_AST')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('artifacts','catalog-sha256','report','report-sha256'): parser.add_argument('--'+name,required=True)
    a=parser.parse_args()
    try:
        from tools.verify_source_v2 import read_source
        from candidate.windows_safe_io_v2 import Directory
        path=Path(a.report)
        with Directory(path.parent) as held:
            raw=read_source(path.parent,path.name,a.report_sha256,64_000_000);held.validate()
        result=verify_bytes(raw,a.artifacts,a.catalog_sha256)
    except (OSError,ValueError,KeyError,TypeError,UnicodeError,RecursionError,MemoryError):
        print(canonical(dict(status='ERROR',reason='STATIC_BINDING_VERIFICATION_FAILED')).decode());return 1
    print(canonical(result).decode());return 0


if __name__=='__main__': raise SystemExit(main())
