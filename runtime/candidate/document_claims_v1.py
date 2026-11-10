"""Manually typed, deterministic documentary claims; no natural-language oracle."""
import ast
import io
import json
import re
from pathlib import Path
import subprocess
import sys
import tempfile
import tokenize
import unicodedata

if __package__:
    from .static_ast_v2 import (AdmissionError, analyze_source, canonical, digest,
                                node_identity, path_parts, read_registered, validate_report)
else:
    sys.path.insert(0, str(Path(__file__).absolute().parent))
    from static_ast_v2 import (AdmissionError, analyze_source, canonical, digest,
                               node_identity, path_parts, read_registered, validate_report)

CLAIM_SCHEMA = 'pgop1.doc-claims.v1'
RULE = 'pgop1.doc-claims.evaluator.v1'
CATALOG_SCHEMA = 'pgop1.source-audit-catalog.v2'
PREDICATES = {'constant_equal', 'symbol_defined', 'public_operation_declared', 'declared_file_exists'}
IDENTIFIER = re.compile(r'[^\W\d]\w{0,119}\Z', re.UNICODE)
HASH = re.compile(r'[a-f0-9]{64}\Z')


def require(ok, code='INVALID_CLAIM_CONTRACT'):
    if not ok:
        raise ValueError(code)


def strict_json(raw):
    def pairs(items):
        result = {}
        for k, v in items:
            require(k not in result, 'DUPLICATE_JSON_KEY')
            result[k] = v
        return result
    def invalid(value):
        raise ValueError('NONFINITE_JSON')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def typed(value):
    """Explicit JSON typing avoids bool/int equality and mutable literal claims."""
    if value is None:
        return {'type':'none'}
    if type(value) is bool:
        return {'type':'bool', 'value':value}
    if type(value) is int and abs(value) < 10**100:
        return {'type':'int', 'value':value}
    if type(value) is str and len(value) <= 120 and re.fullmatch(r'[\w .-]*', value):
        return {'type':'str', 'value':value}
    if type(value) is tuple and len(value) <= 64:
        return {'type':'tuple', 'items':[typed(v) for v in value]}
    raise ValueError('UNSUPPORTED_EXPECTED_VALUE')


def validate_typed(value, depth=0):
    require(isinstance(value, dict) and depth <= 8)
    kind = value.get('type')
    if kind == 'tuple':
        require(set(value) == {'type','items'} and isinstance(value['items'], list) and len(value['items']) <= 64)
        for item in value['items']:
            validate_typed(item, depth+1)
    elif kind == 'none':
        require(set(value) == {'type'})
    else:
        require(set(value) == {'type','value'} and kind in {'int','bool','str'})
        require(typed(value['value']) == value)


def claim_identity(claim):
    return 'claim-' + digest(canonical({k:v for k,v in claim.items() if k != 'claim_id'}))


def make_claim(predicate, document, source, parameters, expected):
    claim = {'claim_schema':CLAIM_SCHEMA, 'predicate':predicate, 'document':document,
             'source':source, 'parameters':parameters, 'expected':expected}
    claim['claim_id'] = claim_identity(claim)
    validate_claim(claim)
    return claim


def validate_pin(pin, document=False):
    keys = {'path','sha256','start_line','end_line','span_sha256'} if document else {'path','sha256'}
    require(isinstance(pin, dict) and set(pin) == keys)
    path_parts(pin['path'])
    require(isinstance(pin['sha256'],str) and HASH.fullmatch(pin['sha256']))
    if document:
        require(type(pin['start_line']) is int and type(pin['end_line']) is int and
                1 <= pin['start_line'] <= pin['end_line'] <= 262144)
        require(isinstance(pin['span_sha256'],str) and HASH.fullmatch(pin['span_sha256']))


def validate_claim(claim):
    require(isinstance(claim,dict) and set(claim) == {'claim_schema','claim_id','predicate','document','source','parameters','expected'})
    require(claim['claim_schema'] == CLAIM_SCHEMA and claim['predicate'] in PREDICATES)
    require(claim['claim_id'] == claim_identity(claim))
    validate_pin(claim['document'],True)
    validate_pin(claim['source'])
    validate_typed(claim['expected'])
    p = claim['parameters']
    require(isinstance(p,dict))
    if claim['predicate'] == 'declared_file_exists':
        require(p == {} and claim['expected']['type'] == 'bool')
    else:
        required = {'scope','name','definition_line'} if claim['predicate'] in {'constant_equal','public_operation_declared'} else {'scope','name'}
        if claim['predicate'] == 'public_operation_declared':
            required.add('operation')
        require(set(p) == required)
        require(isinstance(p['scope'],str) and 1 <= len(p['scope']) <= 1024 and
                (p['scope'] == '<module>' or p['scope'].startswith('node-') and HASH.fullmatch(p['scope'][5:]) or
                 all(IDENTIFIER.fullmatch(x) for x in p['scope'].split('.'))))
        require(isinstance(p['name'],str) and IDENTIFIER.fullmatch(p['name']))
        require(unicodedata.normalize('NFKC',p['name']) == p['name'], 'NONCANONICAL_IDENTIFIER')
        if p['scope'] != '<module>' and not p['scope'].startswith('node-'):
            require(all(unicodedata.normalize('NFKC',part) == part for part in p['scope'].split('.')),
                    'NONCANONICAL_IDENTIFIER')
        if 'definition_line' in p:
            require(type(p['definition_line']) is int and 1 <= p['definition_line'] <= 262144)
        if claim['predicate'] == 'symbol_defined':
            require(claim['expected']['type'] == 'bool')
        if claim['predicate'] == 'public_operation_declared':
            require(claim['expected']['type'] == 'bool' and isinstance(p['operation'],str) and IDENTIFIER.fullmatch(p['operation']))
    return True


def validate_catalog(catalog):
    require(isinstance(catalog,dict) and set(catalog) == {'schema','sources','claims'}, 'INVALID_CATALOG')
    require(catalog['schema'] == CATALOG_SCHEMA and isinstance(catalog['sources'],list) and
            isinstance(catalog['claims'],list) and 1 <= len(catalog['sources']) <= 64 and len(catalog['claims']) <= 64, 'INVALID_CATALOG')
    pins = {}
    for source in catalog['sources']:
        require(isinstance(source,dict) and set(source) == {'path','sha256','kind'}, 'INVALID_SOURCE_DESCRIPTOR')
        validate_pin({k:source[k] for k in ('path','sha256')})
        require(source['kind'] in {'python','document','file'} and source['path'] not in pins, 'INVALID_SOURCE_DESCRIPTOR')
        pins[source['path']] = source
    seen = set()
    for claim in catalog['claims']:
        validate_claim(claim)
        require(claim['claim_id'] not in seen, 'DUPLICATE_CLAIM')
        seen.add(claim['claim_id'])
        for pin, kind in [(claim['document'],'document'), (claim['source'],None)]:
            require(pin['path'] in pins and pins[pin['path']]['sha256'] == pin['sha256'], 'UNREGISTERED_CLAIM_SOURCE')
            require(kind is None or pins[pin['path']]['kind'] == kind, 'INVALID_DOCUMENT_KIND')
        if claim['predicate'] != 'declared_file_exists':
            require(pins[claim['source']['path']]['kind'] == 'python', 'INVALID_VERIFIER_KIND')
    return True


def document_span(raw, start, end):
    """Byte-preserving lines including original line terminators, never echoed."""
    lines = raw.splitlines(keepends=True)
    require(1 <= start <= end <= len(lines), 'DOCUMENT_SPAN_OUT_OF_RANGE')
    return b''.join(lines[start-1:end])


def _literal(node):
    if isinstance(node,ast.Constant):
        return typed(node.value)
    if isinstance(node,ast.Tuple):
        return {'type':'tuple','items':[_literal(n) for n in node.elts]}
    # No ast.literal_eval: operators, calls, containers and names are not admitted.
    raise ValueError('NON_IMMUTABLE_LITERAL')


def _scope_identifier(name):
    # Match AST V2's identifier privacy policy when reconstructing scope IDs.
    return name if isinstance(name,str) and re.fullmatch(r'[\w.]{1,120}|\*',name) else 'WITHHELD'


def _inspect(raw, path, sha, scope_id, name, definition_line):
    encoding,_ = tokenize.detect_encoding(io.BytesIO(raw).readline)
    tree = ast.parse(raw.decode(encoding), filename='<registered-source>')
    compile(tree,'<registered-source>','exec',dont_inherit=True)
    found = None
    conditional_scope = False
    stack = [(tree, [], False)]
    while stack:
        node, chain, inherited_conditional = stack.pop()
        if isinstance(node,(ast.Module,ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)):
            identity = node_identity(sha,path,chain,getattr(node,'lineno',0),getattr(node,'col_offset',0),type(node).__name__)
            if identity == scope_id:
                found = node
                conditional_scope = inherited_conditional
            if not isinstance(node,ast.Module):
                chain = chain + [{'name':_scope_identifier(node.name),'line':node.lineno,'column':node.col_offset,'node':type(node).__name__}]
        branch = inherited_conditional or isinstance(node,(ast.If,ast.For,ast.AsyncFor,ast.While,ast.Try,ast.TryStar,ast.With,ast.AsyncWith,ast.Match))
        stack.extend((child,chain,branch) for child in reversed(list(ast.iter_child_nodes(node))))
    if found is None or conditional_scope:
        return {'status':'UNKNOWN','reason':'CONDITIONAL_OR_MISSING_SCOPE'}
    bindings = []
    hazards = False
    for node in ast.walk(tree):
        if isinstance(node,ast.Name) and isinstance(node.ctx,(ast.Store,ast.Del)) and node.id == name:
            bindings.append(node)
        elif isinstance(node,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)) and node.name == name:
            bindings.append(node)
        elif isinstance(node,ast.arg) and node.arg == name:
            bindings.append(node)
        elif isinstance(node,ast.alias) and (node.asname or node.name.split('.')[0]) == name:
            bindings.append(node)
        elif isinstance(node,ast.ExceptHandler) and node.name == name:
            bindings.append(node)
        elif isinstance(node,(ast.Global,ast.Nonlocal)) and name in node.names:
            hazards = True
        elif isinstance(node,ast.ImportFrom) and any(a.name == '*' for a in node.names):
            hazards = True
        elif isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in {'exec','eval','globals','locals','setattr','delattr','vars'}:
            hazards = True
        elif isinstance(node,(ast.MatchAs,ast.MatchStar)) and node.name == name:
            hazards = True
        elif isinstance(node,ast.MatchMapping) and node.rest == name:
            hazards = True
    candidates = []
    for statement in found.body:
        target = None
        if isinstance(statement,ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
        elif isinstance(statement,ast.AnnAssign) and statement.value is not None:
            target = statement.target
        if isinstance(target,ast.Name) and target.id == name:
            candidates.append((statement,target))
    if hazards or len(bindings) != 1 or len(candidates) != 1 or candidates[0][0].lineno != definition_line:
        return {'status':'UNKNOWN','reason':'NONUNIQUE_CONDITIONAL_OR_DYNAMIC_BINDING'}
    statement,target = candidates[0]
    if bindings[0] is not target:
        return {'status':'UNKNOWN','reason':'NONUNIQUE_CONDITIONAL_OR_DYNAMIC_BINDING'}
    try:
        value = _literal(statement.value)
        validate_typed(value)
    except ValueError:
        return {'status':'UNKNOWN','reason':'NON_IMMUTABLE_LITERAL'}
    return {'status':'COMPLETE','reason':'UNIQUE_DIRECT_IMMUTABLE_LITERAL_DECLARATION_ONLY',
            'literal':value,'line':statement.lineno,'column':statement.col_offset,
            'end_line':statement.end_lineno,'end_column':statement.end_col_offset}


def inspect_literal(raw, path, sha, scope_id, name, definition_line):
    payload = canonical({'raw_hex':raw.hex(),'path':path,'sha':sha,'scope_id':scope_id,'name':name,'definition_line':definition_line})
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as error:
        try:
            proc = subprocess.run([sys.executable,'-I',str(Path(__file__).absolute()),'--worker'],input=payload,
                                  stdout=output,stderr=error,timeout=6,check=False)
            output.seek(0)
            body = output.read(1_000_001)
            if proc.returncode == 0 and len(body) <= 1_000_000:
                result = strict_json(body)
                require(isinstance(result,dict) and result.get('status') in {'COMPLETE','UNKNOWN'})
                return result
        except (OSError,ValueError,subprocess.TimeoutExpired):
            pass
    return {'status':'UNKNOWN','reason':'CLAIM_WORKER_RESOURCE_ERROR'}


def _select_scope(report, selector):
    if selector == '<module>':
        matches = [u for u in report['units'] if u['node'] == 'Module']
    elif selector.startswith('node-'):
        matches = [u for u in report['units'] if u['id'] == selector]
    else:
        matches = [u for u in report['units'] if u['qualified_name'] == selector]
    return matches[0] if len(matches) == 1 else None


def _capture_and_evaluate(source_root, catalog, *, budgets=None, captured=None):
    """Evaluate only registered pins. Source/admission errors become abstentions."""
    validate_catalog(catalog)
    bodies = {}
    errors = {}
    if captured is not None:
        require(set(captured) == {p['path'] for p in catalog['sources']}, 'CAPTURE_MEMBERSHIP')
        for pin in catalog['sources']:
            raw = captured[pin['path']]
            require(type(raw) is bytes and len(raw) <= 262144 and digest(raw) == pin['sha256'], 'CAPTURE_PIN')
            bodies[pin['path']] = raw
    else:
        for pin in sorted(catalog['sources'],key=lambda p:p['path']):
            try:
                bodies[pin['path']] = read_registered(source_root,pin['path'],pin['sha256'])
            except AdmissionError as exc:
                errors[pin['path']] = str(exc)
    reports = {}
    for pin in catalog['sources']:
        if pin['kind'] == 'python' and pin['path'] in bodies and pin['path'] not in reports:
            try:
                if captured is None:
                    reports[pin['path']] = analyze_source(source_root,pin['path'],pin['sha256'],budgets=budgets)
                else:
                    from .static_ast_v2 import analyze_captured
                    reports[pin['path']] = analyze_captured(bodies[pin['path']],pin['path'],pin['sha256'],budgets=budgets)
            except AdmissionError as exc:
                errors[pin['path']] = str(exc)
                bodies.pop(pin['path'],None)
    for path,report in reports.items():
        validate_report(report)
        require(path in bodies and digest(bodies[path]) == report['source_sha256'],'REPORT_SOURCE_MISMATCH')
    results = []
    for claim in sorted(catalog['claims'],key=lambda c:c['claim_id']):
        source = claim['source'];document = claim['document'];predicate = claim['predicate'];params = claim['parameters']
        row = {'claim':claim,'verdict':'INSUFFICIENT_EVIDENCE','reason':'SOURCE_OR_DOCUMENT_UNAVAILABLE',
               'coverage':'ABSENT','rule_version':RULE,'evidence':[], 'scope':'DECLARATIONS_ONLY_NO_EXECUTION'}
        results.append(row)
        if source['path'] not in bodies or document['path'] not in bodies:
            continue
        try:
            span = document_span(bodies[document['path']],document['start_line'],document['end_line'])
            require(digest(span) == document['span_sha256'],'DOCUMENT_SPAN_HASH_MISMATCH')
        except ValueError:
            row['reason'] = 'DOCUMENT_SPAN_NOT_VERIFIED'
            continue
        row['evidence'] = [{'path':source['path'],'sha256':source['sha256'],'verifier':predicate,'field':params,
                            'document_span_sha256':digest(span)}]
        if predicate == 'declared_file_exists':
            row.update(coverage='COMPLETE',reason='REGISTERED_PINNED_FILE_EXISTS_ONLY',
                       verdict='SUPPORTED' if claim['expected']['value'] else 'CONTRADICTED')
            continue
        report = reports.get(source['path'])
        if report is None:
            continue
        if params['name'] == 'WITHHELD' or (not params['scope'].startswith('node-') and 'WITHHELD' in params['scope'].split('.')):
            row['reason'] = 'REDACTED_IDENTIFIER_QUERY'
            continue
        scope = _select_scope(report,params['scope'])
        if scope is None:
            row['reason'] = 'SCOPE_MISSING_OR_AMBIGUOUS'
            continue
        row['coverage'] = scope['status']
        row['evidence'][0].update(scope_id=scope['id'],snapshot_id=report['snapshot_id'])
        if scope['status'] != 'COMPLETE':
            row['reason'] = 'RELEVANT_SCOPE_NOT_COMPLETE'
            continue
        if predicate == 'symbol_defined':
            matches = [d for d in report['declarations'] if d['parent_id'] == scope['id'] and d['name'] == params['name']]
            row.update(reason='SYNTACTIC_LEXICAL_DECLARATION_EXISTENCE_ONLY',
                       verdict='SUPPORTED' if bool(matches) == claim['expected']['value'] else 'CONTRADICTED')
            row['evidence'][0]['definition_ids'] = [d['id'] for d in matches]
            continue
        info = inspect_literal(bodies[source['path']],source['path'],source['sha256'],scope['id'],params['name'],params['definition_line'])
        if info['status'] != 'COMPLETE':
            row['reason'] = info['reason']
            continue
        value = info['literal']
        row['evidence'][0].update({k:info[k] for k in ('line','column','end_line','end_column')})
        row['evidence'][0]['observed_value_sha256'] = digest(canonical(value))
        row['reason'] = info['reason']
        if predicate == 'public_operation_declared':
            if value['type'] != 'tuple' or any(i.get('type') != 'str' for i in value['items']):
                row['reason'] = 'REGISTRY_NOT_IMMUTABLE_STRING_TUPLE'
                continue
            observed = {'type':'bool','value':typed(params['operation']) in value['items']}
            row['reason'] = 'STATIC_REGISTRY_MEMBERSHIP_ONLY_NO_OPERATION_EXECUTION'
        else:
            observed = value
        row['verdict'] = 'SUPPORTED' if observed == claim['expected'] else 'CONTRADICTED'
    return {'schema':'pgop1.doc-claims.results.v1','rule_version':RULE,'claims':results,
            'source_errors':[{'path':path,'reason':reason} for path,reason in sorted(errors.items())],
            'temporal_verdicts':'NOT_IMPLEMENTED_NO_STALE_INFERENCE'}, list(reports.values())


def evaluate_claims(source_root, catalog, *, budgets=None):
    return _capture_and_evaluate(source_root,catalog,budgets=budgets)[0]


def audit_catalog(source_root, catalog, *, budgets=None, captured=None):
    validate_catalog(catalog)
    catalog = {'schema':catalog['schema'], 'sources':sorted(catalog['sources'],key=lambda p:p['path']),
               'claims':sorted(catalog['claims'],key=lambda p:p['claim_id'])}
    claims, structures = _capture_and_evaluate(source_root,catalog,budgets=budgets,captured=captured)
    for report in structures:
        report.pop('execution_metrics',None)
    return {'schema':'pgop1.source-audit-report.v2','catalog':catalog,'catalog_sha256':digest(canonical(catalog)),
            'structures':structures,'document_claims':claims,
            'scope':{'source_integrity':'PINS_CHECKED_SEPARATELY_FROM_CLAIM_TRUTH','execution':'NOT_PERFORMED',
                     'legacy_integration':'DEFERRED','context_engine_persistence':'NOT_IMPLEMENTED',
                     'natural_language_extraction':'MANUAL_TYPED_CLAIMS_ONLY'}}


def _worker():
    payload = strict_json(sys.stdin.buffer.read(600000))
    raw = bytes.fromhex(payload['raw_hex'])
    require(len(raw) <= 262144 and digest(raw) == payload['sha'])
    result = _inspect(raw,payload['path'],payload['sha'],payload['scope_id'],payload['name'],payload['definition_line'])
    sys.stdout.buffer.write(canonical(result))
    return 0


if __name__ == '__main__':
    try:
        raise SystemExit(_worker() if sys.argv[1:] == ['--worker'] else 2)
    except (ValueError,KeyError,TypeError,SyntaxError,UnicodeError,LookupError,MemoryError,RecursionError):
        raise SystemExit(2)
