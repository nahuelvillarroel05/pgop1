"""Producer: new predicates consume only already verified captured bytes."""
import ast
from .claim_contract_v2 import row, finish, fact


def evaluate(claims, bodies, structures):
    results = []
    trees = {}
    for claim in claims:
        result = row(claim); results.append(result)
        path = claim['source']['path']; p = claim['parameters']
        report = next((r for r in structures if r['source']['path'] == path), None)
        if report is None or report['status'] != 'COMPLETE':
            continue
        selector = p['scope']
        scopes = [u for u in report['units'] if (u['node'] == 'Module' if selector == '<module>'
                  else u['id'] == selector if selector.startswith('node-') else u['qualified_name'] == selector)]
        if len(scopes) != 1:
            result['reason'] = 'SCOPE_MISSING_OR_AMBIGUOUS'; continue
        scope = scopes[0]
        if scope['status'] != 'COMPLETE': continue
        family = claim['predicate']
        wanted = {'class_method_declared': {'ClassDef'}, 'module_import_declared': {'Module'},
                  'function_parameter_declared': {'FunctionDef', 'AsyncFunctionDef'}}[family]
        if scope['node'] not in wanted:
            result['reason'] = 'WRONG_SCOPE_KIND'; continue
        if path not in trees: trees[path] = ast.parse(bodies[path])
        node = next((n for n in ast.walk(trees[path]) if type(n).__name__ == scope['node']
                     and getattr(n, 'lineno', 0) == scope['line'] and getattr(n, 'col_offset', 0) == scope['column']), None)
        if node is None: result['reason'] = 'SCOPE_NODE_UNAVAILABLE'; continue
        found = []
        if family == 'class_method_declared':
            found = [n for n in node.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == p['name']]
        elif family == 'module_import_declared':
            for n in node.body:
                if p['form'] == 'import' and isinstance(n, ast.Import):
                    found.extend(a for a in n.names if a.name == p['name'] and a.asname == p['asname'])
                elif p['form'] == 'from' and isinstance(n, ast.ImportFrom) and (n.module or '') == p['module'] and n.level == p['level']:
                    found.extend(a for a in n.names if a.name == p['name'] and a.asname == p['asname'])
        else:
            args = node.args
            values = {'posonly': args.posonlyargs, 'positional': args.args, 'kwonly': args.kwonlyargs,
                      'vararg': [args.vararg] if args.vararg else [], 'kwarg': [args.kwarg] if args.kwarg else []}
            found = [n for n in values[p['kind']] if n.arg == p['name']]
        finish(result, scope, [fact(n, scope, claim) for n in found])
    return results
