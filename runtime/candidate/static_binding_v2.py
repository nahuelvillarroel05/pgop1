"""Opt-in selected-source module references, never executed-object bindings."""
import ast
from .binding_contract_v2 import SCHEMA, alias_budget, universe, finish, load_verified_bundle
from .code_contract_v1 import canonical, digest, position

DEFS = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
REFLECTION = {'exec', 'eval', 'globals', 'locals', 'vars', 'setattr', 'delattr',
              '__import__', 'getattr', '__builtins__'}
ENVIRONMENT = {'sys', 'importlib', 'builtins'}


def _hazard(tree):
    # Source-wide by design, including defaults/decorators and nested scopes.
    for node in ast.walk(tree):
        if (isinstance(node, DEFS) and node.name == '__getattr__' or
                isinstance(node, ast.Name) and node.id == '__getattr__' or
                isinstance(node, ast.alias) and (node.name == '__getattr__' or node.asname == '__getattr__') or
                isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name == '__getattr__' or
                isinstance(node, ast.MatchMapping) and node.rest == '__getattr__'):
            return True
        if isinstance(node, ast.Name) and node.id in REFLECTION:
            return True
        if isinstance(node, (ast.Global, ast.Nonlocal, ast.NamedExpr)):
            return True
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, (ast.Store, ast.Del)):
            return True
        if isinstance(node, ast.Import) and any(a.name.split('.')[0] in ENVIRONMENT for a in node.names):
            return True
        if isinstance(node, ast.ImportFrom) and (any(a.name == '*' for a in node.names) or
                                                (node.module or '').split('.')[0] in ENVIRONMENT):
            return True
    return False


def _module_bindings(tree):
    counts = {}
    stack = list(reversed(tree.body))
    while stack:
        n = stack.pop()
        names = []
        if isinstance(n, DEFS):
            names = [n.name]
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            names = [a.asname or (a.name.split('.')[0] if isinstance(n, ast.Import) else a.name) for a in n.names]
        elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            names = [n.id]
        elif isinstance(n, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and n.name:
            names = [n.name]
        elif isinstance(n, ast.MatchMapping) and n.rest:
            names = [n.rest]
        for name in names:
            counts[name] = counts.get(name, 0) + 1
        if not isinstance(n, DEFS + (ast.Lambda, ast.Import, ast.ImportFrom)):
            stack.extend(reversed(list(ast.iter_child_nodes(n))))
    return counts


def _derive_verified(catalog, snapshot, ast_report, alias_limit=4096):
    limit = alias_budget(alias_limit)
    pins = {p['path']: p for p in catalog['sources']}
    structures = {r['source']['path']: r for r in ast_report['structures']}
    bodies = {p['path']: bytes.fromhex(p['raw_hex']) for p in snapshot['captures']}
    trees = {p: ast.parse(bodies[p]) for p in pins if structures[p]['status'] == 'COMPLETE'}
    unsafe = {p: _hazard(t) for p, t in trees.items()}
    counts = {p: _module_bindings(t) for p, t in trees.items()}
    index, owners = {}, {}
    for path in pins:
        for root in catalog['package_roots']:
            prefix = '' if root == '.' else root + '/'
            if not path.startswith(prefix):
                continue
            parts = path[len(prefix):-3].split('/')
            if parts[-1] == '__init__':
                parts.pop()
            if parts:
                name = '.'.join(parts)
                index.setdefault(name, []).append((path, root))
                owners.setdefault(path, []).append((name, root))

    def chain(path, root):
        prefix = '' if root == '.' else root + '/'
        parts = path[len(prefix):].split('/')[:-1]
        paths = []
        for length in range(1, len(parts) + 1):
            parent = prefix + '/'.join(parts[:length]) + '/__init__.py'
            if parent not in pins:
                return 'OUTSIDE_SELECTED_UNIVERSE', 'INCOMPLETE_PACKAGE_CHAIN', []
            if index.get('.'.join(parts[:length])) != [(parent, root)]:
                return 'AMBIGUOUS', 'PACKAGE_IDENTITY_COLLISION', []
            if parent not in trees:
                return 'INSUFFICIENT_EVIDENCE', 'PACKAGE_AST_NOT_COMPLETE', []
            if unsafe[parent]:
                return 'AMBIGUOUS', 'PACKAGE_DYNAMIC_HAZARD', []
            paths.append(parent)
        return None, None, paths

    uid = universe(catalog)
    rows = []
    total = sum(len(e['aliases']) for r in structures.values() for e in r['relations'] if e['kind'] == 'imports')
    for pin in catalog['sources']:
        path = pin['path']; report = structures[path]; tree = trees.get(path)
        nodes = {(n.lineno, n.col_offset): n for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom))} if tree else {}
        direct = {(n.lineno, n.col_offset) for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))} if tree else set()
        for edge in report['relations']:
            if edge['kind'] != 'imports':
                continue
            for ai, observed in enumerate(edge['aliases']):
                if len(rows) >= limit:
                    break
                node = nodes.get((edge['line'], edge['column']))
                alias = node.names[ai] if node else None
                from_form = isinstance(node, ast.ImportFrom) if node else edge.get('form') == 'from'
                name = alias.name if alias else observed['name']
                asname = alias.asname if alias else observed['asname']
                bound = asname or (name if from_form else name.split('.')[0])
                row = dict(schema=SCHEMA, universe_id=uid, from_source=path, source_sha256=pin['sha256'],
                           ast_snapshot_id=report['snapshot_id'], scope_id=edge['scope_id'],
                           source_span=position(node) if node else dict(line=edge['line'], column=edge['column'], end_line=None, end_column=None, node='UNKNOWN'),
                           alias_span=position(alias) if alias else None, alias_index=ai,
                           form=('from' if from_form else 'import') if node else 'UNKNOWN', module=((node.module or '') if from_form else '') if node else None,
                           level=(node.level if from_form else 0) if node else None, name=name, asname=asname, bound_name=bound if node else None,
                           endpoint_kind='MODULE_REFERENCE', requested_module=None, resolution='UNRESOLVED', rule='RAW_NO_PACKAGE_STRUCTURE',
                           to_source=None, to_source_sha256=None, package_evidence=[],
                           object=dict(name=name, resolution='UNRESOLVED', runtime_target='NOT_PROVEN'), BEHAVIORAL_LINK='NOT_PROVEN')
                if tree is None:
                    row.update(resolution='INSUFFICIENT_EVIDENCE', rule='SOURCE_AST_NOT_COMPLETE')
                elif catalog['mode'] == 'CODE_TREE':
                    row.update(resolution='AMBIGUOUS', rule='IMPORT_CONTEXT_OR_BINDING_HAZARD')
                    if (edge['line'], edge['column']) in direct and not unsafe[path] and counts[path].get(bound) == 1:
                        own = owners.get(path, [])
                        if len(own) != 1:
                            row.update(resolution='AMBIGUOUS' if own else 'OUTSIDE_SELECTED_UNIVERSE', rule='IMPORTER_MODULE_IDENTITY')
                        else:
                            own_name, root = own[0]
                            state, reason, source_parents = chain(path, root)
                            if state:
                                row.update(resolution=state, rule=reason)
                            else:
                                requested = (node.module or '') if from_form else name
                                package = own_name.split('.') if path.endswith('/__init__.py') else own_name.split('.')[:-1]
                                if from_form and node.level > len(package):
                                    row.update(rule='RELATIVE_IMPORT_ESCAPES_ROOT')
                                else:
                                    if from_form and node.level:
                                        requested = '.'.join(package[:len(package)-node.level+1] + ([requested] if requested else []))
                                    row['requested_module'] = requested
                                    candidates = index.get(requested, [])
                                    if not candidates:
                                        row.update(resolution='OUTSIDE_SELECTED_UNIVERSE', rule='NO_SELECTED_REFERENCED_MODULE')
                                    elif len(candidates) != 1:
                                        row['rule'] = 'MULTIPLE_SELECTED_MODULES'
                                    else:
                                        dest, dest_root = candidates[0]
                                        state, reason, target_parents = chain(dest, dest_root)
                                        if state:
                                            row.update(resolution=state, rule=reason)
                                        elif dest not in trees:
                                            row.update(resolution='INSUFFICIENT_EVIDENCE', rule='TARGET_AST_NOT_COMPLETE')
                                        elif unsafe[dest]:
                                            row['rule'] = 'TARGET_DYNAMIC_HAZARD'
                                        else:
                                            row.update(resolution='LOCAL_MODULE_MATCH', rule='EXPLICIT_SELECTED_MODULE_REFERENCE', to_source=dest, to_source_sha256=pins[dest]['sha256'],
                                                       package_evidence=[dict(path=p, sha256=pins[p]['sha256']) for p in sorted(set(source_parents + target_parents))])
                                            row['object']['resolution'] = 'CANDIDATE_ONLY'
                row['relation_id'] = digest(canonical(row))
                rows.append(row)
    return finish(catalog, snapshot['snapshot_id'], rows, {p: structures[p]['status'] for p in pins}, total, limit)


def analyze_bundle(artifacts, catalog_sha256, *, alias_limit=4096):
    alias_budget(alias_limit)
    catalog, snapshot, report = load_verified_bundle(artifacts, catalog_sha256)
    return _derive_verified(catalog, snapshot, report, alias_limit)
