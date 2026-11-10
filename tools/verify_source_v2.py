"""Independent stdlib artifact verifier; never imports the V2 producer.

Shares CPython ast with the producer: not an independent parser or truth oracle.
Only explicitly registered source paths are opened. Does not execute target code.
"""
import argparse
import ast
import hashlib
import io
import json
import os
import math
import re
from pathlib import Path
import stat
import tokenize
import unicodedata
import sys
from contextlib import ExitStack

if os.name == 'nt':
    sys.path.insert(0, str(Path(__file__).absolute().parents[1] / 'runtime'))
    from candidate.windows_safe_io_v2 import SafeIOError, safe_read, safe_create_new

MAX_BYTES = 262144


def canonical(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False) + '\n').encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def require(ok, code):
    if not ok:
        raise ValueError(code)


def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, 'DUPLICATE_KEY')
            result[key] = value
        return result
    def invalid(value):
        raise ValueError('NONFINITE_JSON')
    return json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid)


def read_source(root, name, expected, max_bytes=MAX_BYTES):
    """Walk descriptors with O_NOFOLLOW; bind read bytes and metadata to a pin."""
    if os.name == 'nt':
        try:
            return safe_read(root, name, expected, max_bytes).raw
        except SafeIOError as exc:
            if exc.code == 'SOURCE_HASH_MISMATCH':
                raise ValueError('SOURCE_HASH') from None
            if exc.code in {'SIZE_LIMIT', 'NOT_REGULAR_FILE'}:
                raise ValueError('SOURCE_SIZE_OR_TYPE') from None
            if exc.code == 'SOURCE_CHANGED':
                raise ValueError('SOURCE_CHANGED') from None
            raise  # actual provider refusal, independently recomputed
    require(isinstance(name, str) and name and '\\' not in name and ':' not in name, 'UNSAFE_PATH')
    parts = name.split('/')
    require(not name.startswith('/') and all(p not in ('', '.', '..') for p in parts), 'UNSAFE_PATH')
    root = Path(os.path.abspath(root))
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in root.parts[1:] + tuple(parts[:-1]):
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        source = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            before = os.fstat(source)
            require(stat.S_ISREG(before.st_mode) and before.st_size <= max_bytes, 'SOURCE_SIZE_OR_TYPE')
            raw = bytearray()
            while len(raw) <= max_bytes:
                block = os.read(source, min(65536, max_bytes + 1 - len(raw)))
                if not block:
                    break
                raw.extend(block)
            after = os.fstat(source)
            require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                    (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns), 'SOURCE_CHANGED')
            final = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
            require((final.st_dev, final.st_ino) == (after.st_dev, after.st_ino), 'SOURCE_CHANGED')
        finally:
            os.close(source)
    finally:
        os.close(fd)
    require(len(raw) <= max_bytes and (expected is None or digest(raw) == expected), 'SOURCE_HASH')
    return bytes(raw)


def parse_source(raw):
    encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
    tree = ast.parse(raw.decode(encoding), filename='<registered-source>')
    compile(tree, '<registered-source>', 'exec', dont_inherit=True)
    return tree



def write_verification(output, source_root, body, *, report_path=None, pages_path=None, artifacts=None):
    """Legacy split publication is unavailable on Windows without capture custody."""
    if os.name == 'nt':
        for item in (report_path, pages_path):
            if item is not None:
                require(os.path.normcase(os.fspath(output)) != os.path.normcase(os.fspath(item)),
                        'OUTPUT_OVERLAPS_INPUT')
        raise SafeIOError('WINDOWS_SPLIT_PUBLICATION_REQUIRES_TRANSACTION')
    return _write_verification(output, source_root, body, report_path=report_path,
                               pages_path=pages_path, artifacts=artifacts)


def _write_verification(output, source_root, body, *, report_path=None, pages_path=None, artifacts=None):
    """Internal byte sink, called only inside the whole verification operation."""
    if os.name == 'nt':
        # New-file exclusivity also prevents collisions with report/pages inputs.
        from candidate.windows_safe_io_v2 import absolute
        absolute(output)
        for item in (report_path, pages_path):
            if item is not None:
                absolute(item)
                require(os.path.normcase(os.fspath(output)) != os.path.normcase(os.fspath(item)),
                        'OUTPUT_OVERLAPS_INPUT')
        protected = [source_root, Path(__file__).absolute().parents[1]]
        if artifacts is not None:
            protected.append(artifacts)
        safe_create_new(output, body.encode('utf-8'), protected)
        return
    output = Path(os.path.abspath(output))
    source_root = Path(os.path.abspath(source_root))
    require(not output.is_relative_to(source_root), 'OUTPUT_OVERLAPS_SOURCE')
    if artifacts is not None:
        require(not output.is_relative_to(Path(os.path.abspath(artifacts))), 'OUTPUT_OVERLAPS_ARTIFACTS')
    for item in (report_path,pages_path):
        if item is not None:
            require(output != Path(os.path.abspath(item)), 'OUTPUT_OVERLAPS_INPUT')
    fd = os.open('/',os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in output.parent.parts[1:]:
            next_fd = os.open(part,os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd)
            fd = next_fd
        target = os.open(output.name,os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,0o600,dir_fd=fd)
        try:
            with os.fdopen(target,'wb',closefd=False) as stream:
                stream.write(body.encode('utf-8'))
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            os.close(target)
    finally:
        os.close(fd)


def cli_path(value):
    if os.name == 'nt':
        from candidate.windows_safe_io_v2 import absolute
        absolute(value)
    return Path(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', required=True, type=cli_path)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--report', type=cli_path)
    inputs.add_argument('--artifacts', type=cli_path)
    parser.add_argument('--output', type=cli_path)
    parser.add_argument('--pages', type=cli_path)
    args = parser.parse_args()
    try:
        return execute(args)
    except (OSError, ValueError):
        print(json.dumps({'status':'FAIL','reason':'ARTIFACT_VERIFICATION_FAILED'}))
        return 1


def _verify_inputs(args):
    try:
        if args.artifacts:
            report, manifest = read_artifacts(args.artifacts)
        else:
            report = strict(read_source(args.report.absolute().parent, args.report.name, None, 512_000_000))
            manifest = None
        result = verify_report(args.source_root, report)
        if manifest is not None:
            result['artifacts'] = manifest
        if args.pages:
            pages_path = args.pages.absolute()
            pages_raw = read_source(pages_path.parent,pages_path.name,None,512_000_000)
            result['pagination'] = verify_pages(report, strict(pages_raw))
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, MemoryError):
        result = {'status': 'FAIL', 'reason': 'ARTIFACT_VERIFICATION_FAILED'}
    return result


def execute(args):
    try:
        with ExitStack() as transaction:
            held = []
            if os.name == 'nt':
                from candidate.windows_safe_io_v2 import Directory, absolute, reject_membership
                for folder in (args.source_root, Path(__file__).absolute().parents[1],
                               args.artifacts, args.report.parent if args.report else None,
                               args.pages.parent if args.pages else None):
                    if folder is not None:
                        held.append(transaction.enter_context(Directory(folder)))
                if args.output:
                    drive, parts = absolute(args.output)
                    if not parts:
                        raise ValueError('UNSAFE_PATH')
                    parent = transaction.enter_context(Directory(drive + '\\'.join(parts[:-1])))
                    # File-input parents need custody, not subtree exclusion.
                    for protected in held[:2] + (held[2:3] if args.artifacts else []):
                        reject_membership(parent, protected)
                    held.append(parent)
            result = _verify_inputs(args)
            for directory in held:
                directory.validate()
            body = json.dumps(result, indent=2, sort_keys=True) + '\n'
            if args.output:
                _write_verification(args.output, args.source_root, body, report_path=args.report,
                                    pages_path=args.pages, artifacts=args.artifacts)
            for directory in held:
                directory.validate()
        # No acknowledgement until all handles have closed successfully.
    except (OSError, ValueError):
        result = {'status':'FAIL','reason':('INVALID_NEW_EXTERNAL_OUTPUT' if args.output
                                            else 'ARTIFACT_VERIFICATION_FAILED')}
        body = json.dumps(result, sort_keys=True) + '\n'
    print(body, end='')
    return 0 if result['status'] == 'PASS' else 1


# verify_report is defined below after the artifact contracts.

def verify_structure(root, report, *, captured=None):
    require(report['schema'] == 'pgop1.static-ast.v2', 'SCHEMA')
    fields = {'schema','source','source_sha256','parser','python_version','budgets','status','PYTHON_SYNTAX','AST_COVERAGE','declarations','relations','units','total_detected','returned','remaining','omitted_by_budget','units_complete','units_unknown','execution','behavior','snapshot_id'}
    require(fields <= set(report) <= fields | {'execution_metrics','reason'}, 'STRUCTURE_ENVELOPE')
    require(set(report['source']) == {'path','sha256','bytes'}, 'SOURCE_DESCRIPTOR')
    coverage_fields = {'status','observed_nodes','total_nodes','max_observed_depth','pending_units'}
    require(coverage_fields <= set(report['AST_COVERAGE']) <= coverage_fields | {'pending_nodes'}, 'COVERAGE_SCHEMA')
    semantic = {k:v for k,v in report.items() if k not in ('snapshot_id', 'execution_metrics')}
    require(report['snapshot_id'] == digest(canonical(semantic).rstrip(b'\n')), 'SNAPSHOT')
    require(report['execution'] == 'NOT_PERFORMED' and report['behavior'] == 'NOT_PROVEN', 'EXECUTION_SCOPE')
    require(report['parser'] == 'CPython.ast+compile-no-execution', 'PARSER_SCOPE')
    limits = report['budgets']
    require(set(limits) == {'bytes','nodes','depth','unit_nodes','output_bytes','timeout_seconds'}, 'BUDGET_SCHEMA')
    require(type(limits['timeout_seconds']) in (int,float) and math.isfinite(limits['timeout_seconds']) and 0 < limits['timeout_seconds'] <= 6, 'TIMEOUT_BUDGET')
    for key, ceiling in [('bytes',262144),('nodes',50000),('depth',160),('unit_nodes',12000),('output_bytes',64_000_000)]:
        require(type(limits[key]) is int and 1 <= limits[key] <= ceiling, 'BUDGET')
    for key in ('returned','units_complete','units_unknown'):
        require(type(report[key]) is int and report[key] >= 0, 'COUNT_TYPE')
    for key in ('remaining','total_detected','omitted_by_budget'):
        require(report[key] is None or type(report[key]) is int and report[key] >= 0, 'COUNT_TYPE')
    coverage = report['AST_COVERAGE']
    for key in ('observed_nodes','max_observed_depth'):
        require(type(coverage[key]) is int and coverage[key] >= 0, 'COVERAGE_COUNT_TYPE')
    for key in ('total_nodes','pending_units'):
        require(coverage[key] is None or type(coverage[key]) is int and coverage[key] >= 0, 'COVERAGE_COUNT_TYPE')
    if 'pending_nodes' in coverage:
        require(type(coverage['pending_nodes']) is int and coverage['pending_nodes'] >= 0, 'COVERAGE_COUNT_TYPE')
    for row in report['units'] + report['declarations']:
        for key in ('line','column','end_line','end_column','owned_nodes'):
            if key in row:
                require(type(row[key]) is int and row[key] >= 0, 'UNIT_INTEGER_TYPE')
        for key in ('conditional','decorated'):
            if key in row:
                require(type(row[key]) is bool, 'UNIT_BOOLEAN_TYPE')
        for ancestor in row['scope_chain']:
            require(type(ancestor['line']) is int and type(ancestor['column']) is int, 'ANCESTOR_INTEGER_TYPE')
    for edge in report['relations']:
        require(type(edge['line']) is int and type(edge['column']) is int, 'RELATION_POSITION_TYPE')
        for key in ('base_index','level'):
            if key in edge:
                require(type(edge[key]) is int and edge[key] >= 0, 'RELATION_INTEGER_TYPE')
    source = report['source']
    require(report['source_sha256'] == source['sha256'], 'SOURCE_BINDING')
    raw = (read_source(root, source['path'], source['sha256']) if captured is None
           else captured[source['path']])
    require(type(raw) is bytes and digest(raw) == source['sha256'], 'CAPTURE_PIN')
    require(len(raw) == source['bytes'], 'SOURCE_SIZE')
    require(type(source['bytes']) is int and source['bytes'] <= report['budgets']['bytes'], 'ADMISSION_BUDGET')
    require(report['AST_COVERAGE']['status'] == report['status'], 'COVERAGE_STATE')
    require(report['returned'] == len(report['declarations']), 'RETURNED_COUNT')
    if report['status'] in ('COMPLETE','PARTIAL'):
        require(report['remaining'] == 0 and type(report['remaining']) is int, 'REMAINING')
    status = report['status']
    require(status in {'COMPLETE','PARTIAL','BUDGET_EXCEEDED','PARSE_FAILED','RESOURCE_ERROR','UNKNOWN','UNSUPPORTED'}, 'STATUS')
    if status in {'RESOURCE_ERROR','UNKNOWN','UNSUPPORTED'}:
        require(not report['units'] and not report['declarations'] and not report['relations'] and report['PYTHON_SYNTAX'] == 'UNKNOWN', 'UNKNOWN_FACTS')
        return {'path':source['path'], 'status':status, 'verified':'SOURCE_IDENTITY_AND_ABSTENTION_ONLY'}
    try:
        tree = parse_source(raw)
    except (SyntaxError, UnicodeError, LookupError, ValueError):
        require(status == 'PARSE_FAILED' and report['PYTHON_SYNTAX'] == 'FAIL', 'PARSE_VERDICT')
        require(not report['declarations'] and not report['relations'], 'PARSE_FACTS')
        return {'path':source['path'], 'status':status, 'verified':'PARSE_REJECTION'}
    require(report['PYTHON_SYNTAX'] == 'PASS', 'SYNTAX')
    def public(name):
        return name if isinstance(name,str) and re.fullmatch(r'[\w.]{1,120}|\*',name) else 'WITHHELD'
    def identity(chain, node):
        line = getattr(node, 'lineno', 0)
        column = getattr(node, 'col_offset', 0)
        return 'node-' + digest(canonical([source['sha256'], source['path'], chain, line, column, type(node).__name__]).rstrip(b'\n'))
    declarations = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
    module = identity([], tree)
    units = {module: {'count':0, 'parent':None, 'chain':[], 'node':tree}}
    stack = [(tree, 0, module, [], False)]
    metadata = {module:{'id':module,'name':'<module>','qualified_name':'<module>','scope_chain':[],'line':0,'column':0,'node':'Module','parent_id':None}}
    visited = 0
    max_depth = 0
    node_rows = []
    exceeded = False
    while stack:
        node, depth, owner, chain, conditional = stack.pop()
        max_depth = max(depth,max_depth)
        if visited >= limits['nodes'] or depth > limits['depth']:
            exceeded = True
            break
        visited += 1
        if isinstance(node,declarations):
            node_id = identity(chain,node)
            units[node_id] = {'count':0,'parent':owner,'chain':chain,'node':node}
            name = public(node.name)
            metadata[node_id] = {'id':node_id,'name':name,'qualified_name':'.'.join([part['name'] for part in chain]+[name]),'scope_chain':chain,'line':node.lineno,'column':node.col_offset,'end_line':node.end_lineno,'end_column':node.end_col_offset,'node':type(node).__name__,'parent_id':owner,'conditional':conditional,'decorated':bool(node.decorator_list)}
            owner = node_id
            conditional = False
            chain = chain + [{'name':name,'line':node.lineno,'column':node.col_offset,'node':type(node).__name__}]
        units[owner]['count'] += 1
        node_rows.append((node,owner))
        branch = conditional or isinstance(node,(ast.If,ast.For,ast.AsyncFor,ast.While,ast.Try,ast.TryStar,ast.With,ast.AsyncWith,ast.Match))
        stack.extend((child, depth+1, owner, chain, branch) for child in reversed(list(ast.iter_child_nodes(node))))
    coverage = report['AST_COVERAGE']
    require(coverage['observed_nodes'] == visited and coverage['max_observed_depth'] == max_depth, 'NODE_COUNTS')
    if exceeded:
        require(status == 'BUDGET_EXCEEDED' and coverage['total_nodes'] is None, 'GLOBAL_COVERAGE')
        require(not report['declarations'] and not report['relations'], 'GLOBAL_BUDGET_FACTS')
        return {'path':source['path'],'status':status,'verified':'GLOBAL_BUDGET_AND_NO_ABSENCE'}
    require(coverage['total_nodes'] == visited, 'TOTAL_NODES')
    if status == 'BUDGET_EXCEEDED' and report.get('reason') == 'OUTPUT_BYTE_LIMIT':
        require(not report['units'] and not report['declarations'] and not report['relations'], 'OUTPUT_BUDGET_FACTS')
        require(report['units_unknown'] == len(units) and report['units_complete'] == 0, 'OUTPUT_BUDGET_UNITS')
        require(report['total_detected'] == len(units)-1 and report['omitted_by_budget'] == len(units)-1 and report['returned'] == 0, 'OUTPUT_BUDGET_COUNTS')
        return {'path':source['path'],'status':status,'verified':'COUNTED_TREE_WITH_OUTPUT_ABSTENTION','nodes':visited}
    rows = {u['id']:u for u in report['units']}
    require(len(rows) == len(report['units']) == len(units), 'UNIT_MEMBERSHIP')
    expected_declarations = []
    unknown = 0
    for key,value in units.items():
        row = rows[key]
        require(set(row) == set(metadata[key]) | {'owned_nodes','own_status','status'}, 'UNIT_SCHEMA')
        require(all(canonical(row[k]) == canonical(v) for k,v in metadata[key].items()), 'UNIT_SOURCE_METADATA')
        expected_own = 'COMPLETE' if value['count'] <= limits['unit_nodes'] else 'BUDGET_EXCEEDED'
        require(row['owned_nodes'] == value['count'] and row['own_status'] == expected_own, 'UNIT_COVERAGE')
        require(row['parent_id'] == value['parent'] and row['scope_chain'] == value['chain'], 'UNIT_BINDING')
        require(row['id'] == identity(row['scope_chain'],value['node']), 'NODE_ID')
        value['status'] = expected_own
        if expected_own != 'COMPLETE':
            unknown += 1
        elif key != module:
            expected_declarations.append(key)
    for key in reversed(list(units)):
        value = units[key]
        if value['status'] != 'COMPLETE' and value['parent'] is not None:
            parent = units[value['parent']]
            if parent['status'] == 'COMPLETE':
                parent['status'] = 'PARTIAL'
    require(all(rows[key]['status'] == val['status'] for key,val in units.items()), 'SCOPE_COMPLETENESS')
    expected_declarations.sort(key=lambda k:(rows[k]['line'], rows[k]['column'], rows[k]['node'], k))
    require([d['id'] for d in report['declarations']] == expected_declarations, 'DECLARATIONS')
    for declaration in report['declarations']:
        require(canonical(declaration) == canonical(metadata[declaration['id']]), 'DECLARATION_BINDING')
    require(report['units_complete'] == len(units)-unknown and report['units_unknown'] == unknown, 'UNIT_TOTALS')
    require(status == ('PARTIAL' if unknown else 'COMPLETE'), 'FILE_COVERAGE')
    require(report['total_detected'] == len(units)-1 and report['returned'] == len(expected_declarations), 'INVENTORY_TOTALS')
    require(report['omitted_by_budget'] == len(units)-1-len(expected_declarations), 'OMISSIONS')
    # Relation matching is source-based; runtime execution/resolution is never inferred.
    expected = []
    for node,owner in node_rows:
        if units[owner]['count'] > limits['unit_nodes']:
            continue
        location = (getattr(node,'lineno',0),getattr(node,'col_offset',0),owner)
        if isinstance(node,declarations):
            expected.append((*location,'defines',node))
            if isinstance(node,ast.ClassDef):
                expected.extend((*location,'inherits',base) for base in node.bases)
        elif isinstance(node,(ast.Import,ast.ImportFrom)):
            expected.append((*location,'imports',node))
        elif isinstance(node,ast.Call):
            expected.append((*location,'calls',node))
    actual = report['relations']
    require(len(actual) == len(expected), 'RELATION_TOTAL')
    by_location = {}
    for line,column,owner,kind,node in expected:
        by_location.setdefault((line,column,owner,kind),[]).append(node)
    def expression(node):
        if isinstance(node,ast.Name):
            return {'node':'Name','name':public(node.id)}
        if isinstance(node,ast.Attribute):
            return {'node':'Attribute','attribute':public(node.attr),'base':expression(node.value)}
        return {'node':type(node).__name__,'value':'WITHHELD'}
    seen_bases = set()
    common = {'scope_id','line','column','rule_version','scope','kind','resolution','reason'}
    contracts = {
        'defines':({'from_id','to_id'},'LEXICAL_CONTAINMENT_ONLY'),
        'inherits':({'base_index','expression'},'BASE_EXPRESSION_NOT_RUNTIME_HIERARCHY'),
        'imports':({'module','level','aliases'},'NO_IMPORT_RESOLUTION_OR_EXECUTION'),
        'calls':({'expression'},'CALLEE_CANDIDATE_ONLY_NO_RUNTIME_TARGET')}
    require(actual == sorted(actual,key=lambda r:(r['line'],r['column'],r['kind'],compact(r))), 'RELATION_ORDER')
    for edge in actual:
        require(edge['kind'] in contracts, 'RELATION_KIND')
        fields,reason = contracts[edge['kind']]
        require(set(edge) == common | fields and edge['reason'] == reason, 'RELATION_SCHEMA_OR_REASON')
        if edge['kind'] == 'inherits':
            base_key = (edge['scope_id'],edge['base_index'])
            require(base_key not in seen_bases, 'DUPLICATE_BASE_INDEX')
            seen_bases.add(base_key)
            source_bases = units[edge['scope_id']]['node'].bases
            require(0 <= edge['base_index'] < len(source_bases) and edge['expression'] == expression(source_bases[edge['base_index']]), 'BASE_INDEX')
        key = (edge['line'],edge['column'],edge['scope_id'],edge['kind'])
        require(key in by_location and by_location[key], 'RELATION_LOCATION')
        candidates = by_location[key]
        if edge['kind'] == 'calls':
            index = next((i for i,n in enumerate(candidates) if expression(n.func) == edge['expression']), None)
            require(index is not None, 'CALL_EXPRESSION')
        elif edge['kind'] == 'inherits':
            index = next((i for i,n in enumerate(candidates) if expression(n) == edge['expression']), None)
            require(index is not None, 'BASE_EXPRESSION')
        else:
            index = 0
        node = candidates.pop(index)
        require(edge['scope'] == 'SYNTACTIC_ONLY' and edge['rule_version'] == report['schema'], 'RELATION_SCOPE')
        if edge['kind'] == 'defines':
            require(edge['from_id'] == units[edge['scope_id']]['parent'] and edge['to_id'] == edge['scope_id'] and edge['resolution'] == 'RESOLVED_STATIC', 'DEFINES')
        elif edge['kind'] == 'calls':
            require(edge['expression'] == expression(node.func) and edge['resolution'] == ('UNRESOLVED' if isinstance(node.func,ast.Name) and node.func.id != 'getattr' else 'AMBIGUOUS'), 'CALL_TARGET')
        elif edge['kind'] == 'inherits':
            require(edge['expression'] == expression(node) and edge['resolution'] == 'UNRESOLVED', 'BASE_TARGET')
        else:
            require(edge['aliases'] == [{'name':public(a.name),'asname':public(a.asname) if a.asname else None} for a in node.names], 'IMPORT_ALIASES')
            require(edge['level'] == (node.level if isinstance(node,ast.ImportFrom) else 0), 'IMPORT_LEVEL')
            require(edge['module'] == (public(node.module) if isinstance(node,ast.ImportFrom) and node.module else None), 'IMPORT_MODULE')
            require(edge['resolution'] == ('AMBIGUOUS' if any(a.name=='*' for a in node.names) else 'UNRESOLVED'), 'IMPORT_RESOLUTION')
    return {'path':source['path'],'status':status,'verified':'SOURCE_NODES_SCOPES_COVERAGE_RELATIONS','nodes':visited,'declarations':len(expected_declarations),'relations':len(actual)}


def verify_report(root, report):
    if isinstance(report, dict) and report.get('schema') == 'pgop1.source-audit-report.v2':
        return verify_document_audit(root, report)
    reports = report if isinstance(report,list) else [report]
    return {'status':'PASS','parser_independence':'SHARED_CPYTHON_AST','structures':[verify_structure(root,row) for row in reports]}


def verify_pages(reports, pages):
    if isinstance(reports,dict) and reports.get('schema') == 'pgop1.source-audit-report.v2':
        reports = reports['structures']
    reports = reports if isinstance(reports,list) else [reports]
    snapshots = {r['snapshot_id']:r for r in reports}
    require(isinstance(pages,list), 'PAGES_SCHEMA')
    grouped = {}
    for p in pages:
        require(p['snapshot_id'] in snapshots and p['kind'] in ('declarations','relations'), 'PAGE_SNAPSHOT')
        grouped.setdefault((p['snapshot_id'],p['kind']),[]).append(p)
    require(grouped, 'NO_PAGES')
    verified = []
    for (snapshot,kind),rows in grouped.items():
        report = snapshots[snapshot]
        rows.sort(key=lambda p:p['offset'])
        offset = 0
        actual = []
        for p in rows:
            require(p['schema'] == report['schema'] and p['source_sha256'] == report['source_sha256'], 'PAGE_SOURCE')
            require(p['offset'] == offset and p['returned'] == len(p['items']), 'PAGE_GAP_OR_DUPLICATE')
            actual.extend(p['items'])
            offset += p['returned']
            remaining = len(report[kind])-offset
            require(p['remaining'] == remaining, 'PAGE_REMAINING')
            expected_cursor = f"{snapshot}:{kind}:{offset}" if remaining else None
            require(p['cursor'] == expected_cursor, 'PAGE_CURSOR')
            require(p['analysis_status'] == report['status'], 'PAGE_COVERAGE')
            expected_status = 'PARTIAL' if p['offset'] or remaining else report['status']
            require(p['status'] == expected_status, 'PAGE_STATUS')
            for field in ('omitted_by_budget','units_complete','units_unknown'):
                require(p[field] == report[field], 'PAGE_BUDGET')
            require(p['total_detected'] == (report['total_detected'] if kind=='declarations' else len(report[kind])), 'PAGE_TOTAL')
        require(actual == report[kind], 'MISSING_PAGE_OR_ITEMS')
        verified.append({'snapshot_id':snapshot,'kind':kind,'pages':len(rows),'items':len(actual),'status':'ALL_PAGES_VERIFIED'})
    return verified


# Documentary contract validation and evaluation intentionally do not import the
# producer. They share CPython's parser, with separately implemented scope,
# binding, literal, provenance and verdict checks. This verifier runs locally in
# this process: it has no per-source timeout or OS memory isolation.
def compact(value):
    return canonical(value).rstrip(b'\n')


def check_path(name):
    require(isinstance(name,str) and name and not name.startswith('/') and '\\' not in name and ':' not in name and
            all(part not in ('','.','..') for part in name.split('/')), 'CLAIM_PATH')


def check_hash(value):
    require(isinstance(value,str) and re.fullmatch('[0-9a-f]{64}',value), 'CLAIM_HASH')


def check_pin(pin, document=False):
    keys = {'path','sha256'} | ({'start_line','end_line','span_sha256'} if document else set())
    require(isinstance(pin,dict) and set(pin) == keys, 'CLAIM_PIN_SCHEMA')
    check_path(pin['path']); check_hash(pin['sha256'])
    if document:
        require(type(pin['start_line']) is int and type(pin['end_line']) is int and
                1 <= pin['start_line'] <= pin['end_line'] <= 262144, 'CLAIM_SPAN')
        check_hash(pin['span_sha256'])


def literal_value(node, depth=0):
    require(depth <= 8, 'LITERAL_DEPTH')
    if isinstance(node, ast.Tuple):
        require(len(node.elts) <= 64, 'LITERAL_TUPLE_SIZE')
        return {'type':'tuple','items':[literal_value(n,depth+1) for n in node.elts]}
    require(isinstance(node,ast.Constant), 'NON_IMMUTABLE_LITERAL')
    value = node.value
    if value is None:
        return {'type':'none'}
    if type(value) is bool:
        return {'type':'bool','value':value}
    if type(value) is int and abs(value) < 10**100:
        return {'type':'int','value':value}
    if type(value) is str and len(value) <= 120 and re.fullmatch(r'[\w .-]*',value):
        return {'type':'str','value':value}
    raise ValueError('UNSUPPORTED_LITERAL')


def check_typed(value, depth=0):
    require(isinstance(value,dict) and depth <= 8, 'CLAIM_EXPECTED_TYPE')
    kind = value.get('type')
    if kind == 'none':
        require(set(value) == {'type'}, 'CLAIM_EXPECTED_TYPE')
    elif kind == 'tuple':
        require(set(value) == {'type','items'} and isinstance(value['items'],list) and len(value['items']) <= 64, 'CLAIM_EXPECTED_TYPE')
        for item in value['items']:
            check_typed(item,depth+1)
    else:
        require(set(value) == {'type','value'}, 'CLAIM_EXPECTED_TYPE')
        observed = literal_value(ast.Constant(value=value['value']))
        require(observed == value and kind in {'bool','int','str'}, 'CLAIM_EXPECTED_TYPE')


def check_catalog(catalog):
    require(isinstance(catalog,dict) and set(catalog) == {'schema','sources','claims'} and
            catalog['schema'] == 'pgop1.source-audit-catalog.v2', 'CATALOG_SCHEMA')
    require(isinstance(catalog['sources'],list) and 1 <= len(catalog['sources']) <= 64 and
            isinstance(catalog['claims'],list) and len(catalog['claims']) <= 64, 'CATALOG_SIZE')
    pins = {}
    for pin in catalog['sources']:
        require(isinstance(pin,dict) and set(pin) == {'path','sha256','kind'}, 'CATALOG_PIN')
        check_pin({k:pin[k] for k in ('path','sha256')})
        require(pin['kind'] in {'python','document','file'} and pin['path'] not in pins, 'CATALOG_PIN')
        pins[pin['path']] = pin
    require(catalog['sources'] == sorted(catalog['sources'],key=lambda p:p['path']), 'CATALOG_ORDER')
    seen = set()
    identifier = lambda x: isinstance(x,str) and re.fullmatch(r'[^\W\d]\w{0,119}',x,re.UNICODE)
    canonical_identifier = lambda x: identifier(x) and unicodedata.normalize('NFKC',x) == x
    for claim in catalog['claims']:
        require(isinstance(claim,dict) and set(claim) == {'claim_schema','claim_id','predicate','document','source','parameters','expected'}, 'CLAIM_SCHEMA')
        require(claim['claim_schema'] == 'pgop1.doc-claims.v1' and claim['predicate'] in
                {'constant_equal','symbol_defined','public_operation_declared','declared_file_exists'}, 'CLAIM_PREDICATE')
        expected_id = 'claim-' + digest(compact({k:v for k,v in claim.items() if k != 'claim_id'}))
        require(claim['claim_id'] == expected_id and expected_id not in seen, 'CLAIM_IDENTITY')
        seen.add(expected_id)
        check_pin(claim['document'],True); check_pin(claim['source']); check_typed(claim['expected'])
        for label in ('document','source'):
            pin = claim[label]
            require(pin['path'] in pins and pin['sha256'] == pins[pin['path']]['sha256'], 'CLAIM_ADMISSION_LINK')
        require(pins[claim['document']['path']]['kind'] == 'document', 'DOCUMENT_KIND')
        params = claim['parameters']; predicate = claim['predicate']
        require(isinstance(params,dict), 'CLAIM_PARAMETERS')
        if predicate == 'declared_file_exists':
            require(params == {} and claim['expected']['type'] == 'bool', 'FILE_CLAIM_TYPE')
            continue
        require(pins[claim['source']['path']]['kind'] == 'python', 'CLAIM_SOURCE_KIND')
        fields = {'scope','name'}
        if predicate in {'constant_equal','public_operation_declared'}:
            fields.add('definition_line')
        if predicate == 'public_operation_declared':
            fields.add('operation')
            require(identifier(params.get('operation')), 'OPERATION_IDENTIFIER')
        require(set(params) == fields and canonical_identifier(params['name']), 'CLAIM_PARAMETERS')
        scope = params['scope']
        require(isinstance(scope,str) and 1 <= len(scope) <= 1024 and
                (scope == '<module>' or re.fullmatch('node-[0-9a-f]{64}',scope) or all(canonical_identifier(n) for n in scope.split('.'))), 'CLAIM_SCOPE')
        if 'definition_line' in params:
            require(type(params['definition_line']) is int and 1 <= params['definition_line'] <= 262144, 'DEFINITION_LINE')
        if predicate in {'symbol_defined','public_operation_declared'}:
            require(claim['expected']['type'] == 'bool', 'BOOLEAN_CLAIM_TYPE')
    require(catalog['claims'] == sorted(catalog['claims'],key=lambda c:c['claim_id']), 'CLAIM_ORDER')
    return pins


def independent_literal(tree, scope, name, definition_line):
    """Closed binding proof: one direct assignment, no same-name bind anywhere.

    The deliberately global rebinding test is stricter than Python name lookup;
    it reproduces this contract's conservative abstention, not runtime semantics.
    """
    selected = None
    conditional = False
    pending = [(tree,False)]
    branch_types = (ast.If,ast.For,ast.AsyncFor,ast.While,ast.Try,ast.TryStar,ast.With,ast.AsyncWith,ast.Match)
    for_node = (ast.Module,ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)
    while pending:
        node, flag = pending.pop()
        if (isinstance(node,for_node) and type(node).__name__ == scope['node'] and
                getattr(node,'lineno',0) == scope['line'] and getattr(node,'col_offset',0) == scope['column']):
            selected = node
            conditional = flag
        pending.extend((child,flag or isinstance(node,branch_types)) for child in ast.iter_child_nodes(node))
    if selected is None or conditional:
        return {'status':'UNKNOWN','reason':'CONDITIONAL_OR_MISSING_SCOPE'}
    count = 0
    binder = None
    unsafe = False
    for node in ast.walk(tree):
        binding = ((isinstance(node,ast.Name) and isinstance(node.ctx,(ast.Store,ast.Del)) and node.id == name)
                   or (isinstance(node,(ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)) and node.name == name)
                   or (isinstance(node,ast.arg) and node.arg == name)
                   or (isinstance(node,ast.alias) and (node.asname or node.name.split('.')[0]) == name)
                   or (isinstance(node,ast.ExceptHandler) and node.name == name))
        if binding:
            count += 1
            binder = node
        if (isinstance(node,(ast.Global,ast.Nonlocal)) and name in node.names
                or isinstance(node,ast.ImportFrom) and any(a.name == '*' for a in node.names)
                or isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in {'exec','eval','globals','locals','setattr','delattr','vars'}
                or isinstance(node,(ast.MatchAs,ast.MatchStar)) and node.name == name
                or isinstance(node,ast.MatchMapping) and node.rest == name):
            unsafe = True
    direct = []
    for statement in selected.body:
        if isinstance(statement,ast.Assign) and len(statement.targets) == 1:
            target = statement.targets[0]
        elif isinstance(statement,ast.AnnAssign) and statement.value is not None:
            target = statement.target
        else:
            continue
        if isinstance(target,ast.Name) and target.id == name:
            direct.append((statement,target))
    if unsafe or count != 1 or len(direct) != 1 or direct[0][0].lineno != definition_line or direct[0][1] is not binder:
        return {'status':'UNKNOWN','reason':'NONUNIQUE_CONDITIONAL_OR_DYNAMIC_BINDING'}
    statement = direct[0][0]
    try:
        value = literal_value(statement.value)
    except ValueError:
        return {'status':'UNKNOWN','reason':'NON_IMMUTABLE_LITERAL'}
    return {'status':'COMPLETE','reason':'UNIQUE_DIRECT_IMMUTABLE_LITERAL_DECLARATION_ONLY',
            'literal':value,'line':statement.lineno,'column':statement.col_offset,
            'end_line':statement.end_lineno,'end_column':statement.end_col_offset}


def verify_document_audit(root, report, *, captured=None):
    require(set(report) == {'schema','catalog','catalog_sha256','structures','document_claims','scope'}, 'AUDIT_REPORT_SCHEMA')
    catalog = report['catalog']; pins = check_catalog(catalog)
    require(report['catalog_sha256'] == digest(compact(catalog)), 'CATALOG_DIGEST')
    require(report['scope'] == {'source_integrity':'PINS_CHECKED_SEPARATELY_FROM_CLAIM_TRUTH','execution':'NOT_PERFORMED',
                               'legacy_integration':'DEFERRED','context_engine_persistence':'NOT_IMPLEMENTED',
                               'natural_language_extraction':'MANUAL_TYPED_CLAIMS_ONLY'}, 'AUDIT_SCOPE')
    require(isinstance(report['structures'],list), 'AUDIT_STRUCTURES')
    bodies = {}; failures = {}
    if captured is not None:
        require(set(captured) == set(pins), 'CAPTURE_MEMBERSHIP')
    for path,pin in pins.items():
        try:
            if captured is None:
                bodies[path] = read_source(root,path,pin['sha256'])
            else:
                raw = captured[path]
                require(type(raw) is bytes and len(raw) <= MAX_BYTES and digest(raw) == pin['sha256'], 'CAPTURE_PIN')
                bodies[path] = raw
        except ValueError as exc:
            code = str(exc)
            failures[path] = ({'SOURCE_HASH_MISMATCH'} if code == 'SOURCE_HASH' else
                              {'SOURCE_CHANGED'} if code == 'SOURCE_CHANGED' else
                              {'SIZE_LIMIT','NOT_REGULAR_FILE'} if code == 'SOURCE_SIZE_OR_TYPE' else
                              {exc.code} if os.name == 'nt' and isinstance(exc, SafeIOError) else set())
            require(failures[path], 'UNKNOWN_SOURCE_FAILURE')
        except OSError:
            failures[path] = {'SOURCE_UNAVAILABLE_OR_UNSAFE'}
    structural = {}
    structure_results = []
    for structure in report['structures']:
        path = structure['source']['path']
        require(path in pins and pins[path]['kind'] == 'python' and path in bodies and path not in structural, 'STRUCTURE_CATALOG_BINDING')
        require(structure['source_sha256'] == pins[path]['sha256'], 'STRUCTURE_SOURCE_PIN')
        structure_results.append(verify_structure(root,structure,captured=captured))
        structural[path] = structure
    require(set(structural) == {p for p,v in pins.items() if v['kind'] == 'python' and p in bodies}, 'STRUCTURE_MEMBERSHIP')
    claims = report['document_claims']
    require(isinstance(claims,dict) and set(claims) == {'schema','rule_version','claims','source_errors','temporal_verdicts'} and
            claims['schema'] == 'pgop1.doc-claims.results.v1' and claims['rule_version'] == 'pgop1.doc-claims.evaluator.v1' and
            claims['temporal_verdicts'] == 'NOT_IMPLEMENTED_NO_STALE_INFERENCE', 'CLAIM_RESULTS_SCHEMA')
    require(isinstance(claims['source_errors'],list) and len(claims['source_errors']) == len(failures), 'SOURCE_ERROR_COUNT')
    error_paths = []
    for error in claims['source_errors']:
        require(isinstance(error,dict) and set(error) == {'path','reason'} and error['path'] in failures and
                error['reason'] in failures[error['path']], 'SOURCE_ERROR_EVIDENCE')
        error_paths.append(error['path'])
    require(error_paths == sorted(failures), 'SOURCE_ERROR_MEMBERSHIP')
    require(isinstance(claims['claims'],list) and len(claims['claims']) == len(catalog['claims']), 'CLAIM_RESULT_COUNT')
    trees = {}
    outcomes = []
    for claim,actual in zip(catalog['claims'],claims['claims']):
        predicate = claim['predicate']; params = claim['parameters']; source = claim['source']; document = claim['document']
        expected = {'claim':claim,'verdict':'INSUFFICIENT_EVIDENCE','reason':'SOURCE_OR_DOCUMENT_UNAVAILABLE',
                    'coverage':'ABSENT','rule_version':'pgop1.doc-claims.evaluator.v1','evidence':[],
                    'scope':'DECLARATIONS_ONLY_NO_EXECUTION'}
        if source['path'] in bodies and document['path'] in bodies:
            lines = bodies[document['path']].splitlines(keepends=True)
            start,end = document['start_line'],document['end_line']
            span = b''.join(lines[start-1:end]) if end <= len(lines) else None
            if span is None or digest(span) != document['span_sha256']:
                expected['reason'] = 'DOCUMENT_SPAN_NOT_VERIFIED'
            else:
                expected['evidence'] = [{'path':source['path'],'sha256':source['sha256'],'verifier':predicate,
                                         'field':params,'document_span_sha256':digest(span)}]
                if predicate == 'declared_file_exists':
                    expected.update(coverage='COMPLETE',reason='REGISTERED_PINNED_FILE_EXISTS_ONLY',
                                    verdict='SUPPORTED' if claim['expected']['value'] else 'CONTRADICTED')
                elif params['name'] == 'WITHHELD' or not params['scope'].startswith('node-') and 'WITHHELD' in params['scope'].split('.'):
                    expected['reason'] = 'REDACTED_IDENTIFIER_QUERY'
                else:
                    structure = structural[source['path']]
                    units = structure['units']; selector = params['scope']
                    selected = [u for u in units if (u['node']=='Module' if selector=='<module>' else u['id']==selector if selector.startswith('node-') else u['qualified_name']==selector)]
                    if len(selected) != 1:
                        expected['reason'] = 'SCOPE_MISSING_OR_AMBIGUOUS'
                    else:
                        unit = selected[0]
                        expected['coverage'] = unit['status']
                        evidence = expected['evidence'][0]
                        evidence.update(scope_id=unit['id'],snapshot_id=structure['snapshot_id'])
                        if unit['status'] != 'COMPLETE':
                            expected['reason'] = 'RELEVANT_SCOPE_NOT_COMPLETE'
                        elif predicate == 'symbol_defined':
                            matches = [d['id'] for d in structure['declarations'] if d['parent_id']==unit['id'] and d['name']==params['name']]
                            evidence['definition_ids'] = matches
                            expected.update(reason='SYNTACTIC_LEXICAL_DECLARATION_EXISTENCE_ONLY',
                                            verdict='SUPPORTED' if bool(matches)==claim['expected']['value'] else 'CONTRADICTED')
                        else:
                            if source['path'] not in trees:
                                trees[source['path']] = parse_source(bodies[source['path']])
                            info = independent_literal(trees[source['path']],unit,params['name'],params['definition_line'])
                            expected['reason'] = info['reason']
                            if info['status'] == 'COMPLETE':
                                value = info['literal']
                                evidence.update({key:info[key] for key in ('line','column','end_line','end_column')})
                                evidence['observed_value_sha256'] = digest(compact(value))
                                if predicate == 'public_operation_declared':
                                    if value['type'] != 'tuple' or any(v['type'] != 'str' for v in value['items']):
                                        expected['reason'] = 'REGISTRY_NOT_IMMUTABLE_STRING_TUPLE'
                                    else:
                                        observed = any(v['value']==params['operation'] for v in value['items'])
                                        expected.update(reason='STATIC_REGISTRY_MEMBERSHIP_ONLY_NO_OPERATION_EXECUTION',
                                                        verdict='SUPPORTED' if observed==claim['expected']['value'] else 'CONTRADICTED')
                                else:
                                    expected['verdict'] = 'SUPPORTED' if value==claim['expected'] else 'CONTRADICTED'
        require(compact(actual) == compact(expected), 'CLAIM_VERDICT_OR_PROVENANCE_MISMATCH')
        outcomes.append({'claim_id':claim['claim_id'],'verdict':expected['verdict'],'verified':'SOURCE_DERIVED_TYPED_PREDICATE_AND_PROVENANCE'})
    return {'status':'PASS','scope':'REPORT_CONSISTENCY_NOT_ALL_SOURCES_PASS',
            'source_integrity':'PASS' if not failures else 'FAILED_PINS_WITH_VERIFIED_ABSTENTIONS',
            'source_errors':claims['source_errors'],'parser_independence':'SHARED_CPYTHON_AST',
            'verifier_resource_isolation':'NOT_IMPLEMENTED_NO_PER_SOURCE_TIMEOUT',
            'catalog_sha256':report['catalog_sha256'],'structures':structure_results,'claims':outcomes}


def read_artifacts(folder):
    """Check only the three fixed artifact filenames, never manifest-directed paths."""
    raw = read_source(folder,'MANIFEST.json',None,1_000_000)
    manifest = strict(raw)
    require(isinstance(manifest,dict) and set(manifest)=={'schema','catalog_sha256','files'} and
            manifest['schema']=='pgop1.source-audit-manifest.v2' and
            isinstance(manifest['files'],dict) and set(manifest['files'])=={'REPORT.json','FINAL_HANDOFF.md'}, 'MANIFEST_SCHEMA')
    check_hash(manifest['catalog_sha256'])
    files = {}
    for name in ('REPORT.json','FINAL_HANDOFF.md'):
        pin = manifest['files'][name]
        require(isinstance(pin,dict) and set(pin)=={'bytes','sha256'} and type(pin['bytes']) is int and pin['bytes'] >= 0, 'ARTIFACT_PIN')
        check_hash(pin['sha256'])
        files[name] = read_source(folder,name,pin['sha256'],512_000_000 if name=='REPORT.json' else 1_000_000)
        require(len(files[name]) == pin['bytes'], 'ARTIFACT_BYTES')
    report = strict(files['REPORT.json'])
    require(report.get('schema')=='pgop1.source-audit-report.v2' and report.get('catalog_sha256')==manifest['catalog_sha256'], 'MANIFEST_CATALOG_BINDING')
    # Handoff is explanatory prose. Its bytes are verified, never used as claim evidence.
    return report, {'status':'HASHES_AND_CATALOG_BINDING_VERIFIED','manifest_sha256':digest(raw),'files':sorted(files)}


if __name__ == '__main__':
    raise SystemExit(main())
