"""Separate evaluator: parses captures, never calls the claim producer."""
import ast
from candidate.claim_contract_v2 import row, finish, fact


def evaluate(claims, bodies, structures):
    results = []
    for claim in claims:
        out = row(claim); results.append(out)
        params = claim['parameters']; source = claim['source']['path']
        structure = next((s for s in structures if s['source']['path'] == source), None)
        if structure is None or structure['status'] != 'COMPLETE': continue
        selected = []
        for unit in structure['units']:
            query = params['scope']
            if ((query == '<module>' and unit['node'] == 'Module') or unit['id'] == query
                    or (query != '<module>' and not query.startswith('node-') and unit['qualified_name'] == query)):
                selected.append(unit)
        if len(selected) != 1: out['reason'] = 'SCOPE_MISSING_OR_AMBIGUOUS'; continue
        unit = selected[0]
        if unit['status'] != 'COMPLETE': continue
        predicate = claim['predicate']
        if ((predicate == 'class_method_declared' and unit['node'] != 'ClassDef')
                or (predicate == 'function_parameter_declared' and unit['node'] not in ('FunctionDef', 'AsyncFunctionDef'))
                or (predicate == 'module_import_declared' and unit['node'] != 'Module')):
            out['reason'] = 'WRONG_SCOPE_KIND'; continue
        pending = [ast.parse(bodies[source])]; target = None
        while pending:
            current = pending.pop()
            if (current.__class__.__name__ == unit['node'] and getattr(current, 'lineno', 0) == unit['line']
                    and getattr(current, 'col_offset', 0) == unit['column']):
                target = current; break
            pending.extend(ast.iter_child_nodes(current))
        if target is None: out['reason'] = 'SCOPE_NODE_UNAVAILABLE'; continue
        matches = []
        if predicate == 'class_method_declared':
            for child in target.body:
                if type(child) in (ast.FunctionDef, ast.AsyncFunctionDef) and child.name == params['name']:
                    matches.append(child)
        elif predicate == 'function_parameter_declared':
            for attribute, kind in [('posonlyargs', 'posonly'), ('args', 'positional'), ('kwonlyargs', 'kwonly'), ('vararg', 'vararg'), ('kwarg', 'kwarg')]:
                value = getattr(target.args, attribute)
                values = value if isinstance(value, list) else [value] if value is not None else []
                if kind == params['kind']:
                    matches.extend(v for v in values if v.arg == params['name'])
        else:
            for statement in target.body:
                form = 'import' if type(statement) is ast.Import else 'from' if type(statement) is ast.ImportFrom else None
                if form != params['form']: continue
                if form == 'from' and ((statement.module or '') != params['module'] or statement.level != params['level']): continue
                for alias in statement.names:
                    if (alias.name, alias.asname) == (params['name'], params['asname']): matches.append(alias)
        finish(out, unit, [fact(n, unit, claim) for n in matches])
    return results
