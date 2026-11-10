"""Opt-in syntax-only claim admission; legacy contracts are never extended in place."""
import re
import unicodedata
from .document_claims_v1 import validate_pin, claim_identity, require
from .static_ast_v2 import canonical, digest

SCHEMA = 'pgop1.doc-claims.v2'
RULE = 'pgop1.doc-claims.evaluator.v2'
FAMILIES = {'class_method_declared', 'module_import_declared', 'function_parameter_declared'}
KINDS = {'posonly', 'positional', 'vararg', 'kwonly', 'kwarg'}


def identifier(value):
    return (isinstance(value, str) and re.fullmatch(r'[^\W\d]\w{0,119}', value) is not None
            and unicodedata.normalize('NFKC', value) == value and value != 'WITHHELD')


def validate_claim(claim):
    require(isinstance(claim, dict) and set(claim) == {
        'claim_schema', 'claim_id', 'predicate', 'document', 'source', 'parameters', 'expected'})
    require(claim['claim_schema'] == SCHEMA and claim['predicate'] in FAMILIES)
    require(claim['claim_id'] == claim_identity(claim))
    validate_pin(claim['document'], True); validate_pin(claim['source'])
    require(isinstance(claim['expected'], dict) and set(claim['expected']) == {'type', 'value'}
            and claim['expected']['type'] == 'bool' and type(claim['expected']['value']) is bool)
    p = claim['parameters']; require(isinstance(p, dict))
    scope = p.get('scope')
    require(isinstance(scope, str) and 1 <= len(scope) <= 1024 and (
        scope == '<module>' or re.fullmatch(r'node-[a-f0-9]{64}', scope) is not None
        or all(identifier(n) for n in scope.split('.'))))
    if claim['predicate'] == 'module_import_declared':
        require(set(p) == {'scope', 'form', 'module', 'name', 'asname', 'level'} and scope == '<module>')
        require(p['form'] in {'import', 'from'} and type(p['level']) is int and 0 <= p['level'] <= 160)
        require(isinstance(p['module'], str) and len(p['module']) <= 1024
                and (p['module'] == '' or all(identifier(n) for n in p['module'].split('.'))))
        require(p['asname'] is None or identifier(p['asname']))
        require(isinstance(p['name'], str) and 1 <= len(p['name']) <= 1024)
        if p['form'] == 'import':
            require(p['module'] == '' and p['level'] == 0 and all(identifier(n) for n in p['name'].split('.')))
        else:
            require(identifier(p['name']) and (p['module'] != '' or p['level'] > 0))
    else:
        require(identifier(p.get('name')))
        require(set(p) == ({'scope', 'name', 'kind'} if claim['predicate'] == 'function_parameter_declared'
                           else {'scope', 'name'}))
        if 'kind' in p: require(p['kind'] in KINDS)
    return True


def make_claim(predicate, document, source, parameters, expected=True):
    claim = dict(claim_schema=SCHEMA, predicate=predicate, document=document, source=source,
                 parameters=parameters, expected=dict(type='bool', value=expected))
    claim['claim_id'] = claim_identity(claim)
    validate_claim(claim)
    return claim


def fact(node, scope, claim):
    """Distinct lexical scope and source identities, including arg/alias nodes."""
    position = dict(line=node.lineno, column=node.col_offset,
                    end_line=node.end_lineno, end_column=node.end_col_offset, node=type(node).__name__)
    return dict(position, node_id='fact-' + digest(canonical([
        RULE, claim['source'], scope['id'], position])), scope_id=scope['id'])


def row(claim):
    return dict(claim=claim, verdict='INSUFFICIENT_EVIDENCE', reason='RELEVANT_SCOPE_NOT_COMPLETE',
                coverage='ABSENT', rule_version=RULE, evidence=[], scope='SYNTAX_ONLY_NO_RESOLUTION_OR_EXECUTION')


def finish(result, scope, matches):
    result.update(coverage='COMPLETE', reason='EXACT_DIRECT_SYNTAX_ONLY', evidence=matches,
                  scope_id=scope['id'], verdict='SUPPORTED' if bool(matches) is result['claim']['expected']['value'] else 'CONTRADICTED')
    return result
