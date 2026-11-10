"""Opt-in, bounded syntactic observations. Never imports or executes target code."""
import ast
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import time
import tokenize

SCHEMA = 'pgop1.static-ast.v2'
DEFAULT_BUDGETS = {'bytes': 262144, 'nodes': 50000, 'depth': 160,
                   'unit_nodes': 12000, 'output_bytes': 64_000_000, 'timeout_seconds': 6.0}
STATES = {'COMPLETE', 'PARTIAL', 'BUDGET_EXCEEDED', 'PARSE_FAILED',
          'RESOURCE_ERROR', 'UNSUPPORTED', 'UNKNOWN'}
DECLARATIONS = (ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                      allow_nan=False).encode('ascii')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


class AdmissionError(ValueError):
    """Only fixed codes, never source text, host paths or exception details."""


def path_parts(name):
    if (not isinstance(name, str) or not name or '\\' in name or ':' in name
            or name.startswith('/') or any(p in ('', '.', '..') for p in name.split('/'))):
        raise AdmissionError('UNSAFE_PATH')
    return name.split('/')


def read_registered(root, name, expected_sha256, max_bytes=262144):
    """Ubuntu descriptor-relative no-follow read; final bytes pinned by SHA-256.

    Directory descriptors prevent parent substitution escaping admission during a
    read. Metadata and path identity are checked after read as well. A later edit
    cannot change the captured bytes; a subsequent read must satisfy the pin again.
    """
    parts = path_parts(name)
    if not isinstance(expected_sha256, str) or not re.fullmatch('[0-9a-f]{64}', expected_sha256):
        raise AdmissionError('INVALID_HASH')
    if os.name == 'nt':
        if __package__:
            from .windows_safe_io_v2 import SafeIOError, safe_read
        else:
            from windows_safe_io_v2 import SafeIOError, safe_read
        try:
            return safe_read(root, name, expected_sha256, max_bytes).raw
        except SafeIOError as exc:
            raise AdmissionError(exc.code) from None
        except OSError:
            raise AdmissionError('SOURCE_UNAVAILABLE_OR_UNSAFE') from None
    if not hasattr(os, 'O_NOFOLLOW'):
        raise AdmissionError('UNSUPPORTED_SAFE_READ_PLATFORM')
    root = Path(root).absolute()
    descriptors = []
    try:
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
        descriptors.append(fd)
        for p in root.parts[1:] + tuple(parts[:-1]):
            fd = os.open(p, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            descriptors.append(fd)
        file_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        descriptors.append(file_fd)
        before = os.fstat(file_fd)
        if not stat.S_ISREG(before.st_mode):
            raise AdmissionError('NOT_REGULAR_FILE')
        if before.st_size > max_bytes:
            raise AdmissionError('SIZE_LIMIT')
        chunks = []
        remaining = max_bytes + 1
        while remaining:
            chunk = os.read(file_fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b''.join(chunks)
        after = os.fstat(file_fd)
        current = os.stat(parts[-1], dir_fd=fd, follow_symlinks=False)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(before) != identity(after) or identity(after) != identity(current):
            raise AdmissionError('SOURCE_CHANGED')
        if len(raw) > max_bytes:
            raise AdmissionError('SIZE_LIMIT')
        if digest(raw) != expected_sha256:
            raise AdmissionError('SOURCE_HASH_MISMATCH')
        return raw
    except OSError:
        raise AdmissionError('SOURCE_UNAVAILABLE_OR_UNSAFE') from None
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _budgets(values):
    result = dict(DEFAULT_BUDGETS)
    if values is not None:
        if not isinstance(values, dict) or set(values) - set(result):
            raise ValueError('INVALID_BUDGET')
        result.update(values)
    for key in ('bytes', 'nodes', 'depth', 'unit_nodes', 'output_bytes'):
        if type(result[key]) is not int or not 1 <= result[key] <= DEFAULT_BUDGETS[key]:
            raise ValueError('INVALID_BUDGET')
    if type(result['timeout_seconds']) not in (int, float) or not 0 < result['timeout_seconds'] <= 6:
        raise ValueError('INVALID_BUDGET')
    return result


def node_identity(sha, path, scopes, line, column, kind):
    return 'node-' + digest(canonical([sha, path, scopes, line, column, kind]))


def _public(name):
    return name if isinstance(name, str) and re.fullmatch(r'[\w.]{1,120}|\*', name) else 'WITHHELD'


def _expression(node):
    # Values and source segments are deliberately excluded.
    if isinstance(node, ast.Name):
        return {'node': 'Name', 'name': _public(node.id)}
    if isinstance(node, ast.Attribute):
        return {'node': 'Attribute', 'attribute': _public(node.attr), 'base': _expression(node.value)}
    return {'node': type(node).__name__, 'value': 'WITHHELD'}


def _base(path, sha, size, budgets):
    return {'schema': SCHEMA, 'source': {'path': path, 'sha256': sha, 'bytes': size},
            'source_sha256': sha, 'parser': 'CPython.ast+compile-no-execution',
            'python_version': sys.version.split()[0], 'budgets': budgets,
            'status': 'UNKNOWN', 'PYTHON_SYNTAX': 'UNKNOWN',
            'AST_COVERAGE': {'status': 'UNKNOWN', 'observed_nodes': 0, 'total_nodes': None,
                             'max_observed_depth': 0, 'pending_units': None},
            'declarations': [], 'relations': [], 'units': [],
            'total_detected': None, 'returned': 0, 'remaining': None,
            'omitted_by_budget': None, 'units_complete': 0, 'units_unknown': 0,
            'execution': 'NOT_PERFORMED', 'behavior': 'NOT_PROVEN'}


def _finish(result):
    result['snapshot_id'] = digest(canonical(result))
    return result


def _analyze(raw, path, sha, budgets):
    result = _base(path, sha, len(raw), budgets)
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        tree = ast.parse(raw.decode(encoding), filename='<registered-source>', mode='exec')
        compile(tree, '<registered-source>', 'exec', dont_inherit=True, optimize=0)
    except (SyntaxError, UnicodeError, LookupError, ValueError) as exc:
        result.update(status='PARSE_FAILED', PYTHON_SYNTAX='FAIL', reason=type(exc).__name__)
        result['AST_COVERAGE']['status'] = 'PARSE_FAILED'
        return _finish(result)
    except (MemoryError, RecursionError):
        result.update(status='RESOURCE_ERROR', reason='PARSER_RESOURCE_ERROR')
        result['AST_COVERAGE']['status'] = 'RESOURCE_ERROR'
        return _finish(result)
    result['PYTHON_SYNTAX'] = 'PASS'
    # Enumerate globally before applying per-unit cuts. This walk is bounded too.
    module_id = node_identity(sha, path, [], 0, 0, 'Module')
    units = {module_id: {'id': module_id, 'name': '<module>', 'qualified_name': '<module>',
                         'scope_chain': [], 'line': 0, 'column': 0, 'node': 'Module',
                         'parent_id': None, 'owned_nodes': 0}}
    records = []
    pending = [(tree, 0, module_id, [], False)]
    observed = 0
    max_depth = 0
    while pending:
        node, depth, owner, scopes, conditional = pending.pop()
        max_depth = max(max_depth, depth)
        if observed >= budgets['nodes'] or depth > budgets['depth']:
            result.update(status='BUDGET_EXCEEDED', reason='GLOBAL_NODE_LIMIT' if observed >= budgets['nodes'] else 'DEPTH_LIMIT')
            result['AST_COVERAGE'].update(status='BUDGET_EXCEEDED', observed_nodes=observed,
                                         max_observed_depth=max_depth, pending_units=None, pending_nodes=len(pending)+1)
            return _finish(result)
        observed += 1
        if isinstance(node, DECLARATIONS):
            parent_id = owner
            owner = node_identity(sha, path, scopes, node.lineno, node.col_offset, type(node).__name__)
            unit = {'id': owner, 'name': _public(node.name),
                    'qualified_name': '.'.join([s['name'] for s in scopes] + [_public(node.name)]),
                    'scope_chain': scopes, 'line': node.lineno, 'column': node.col_offset,
                    'end_line': node.end_lineno, 'end_column': node.end_col_offset,
                    'node': type(node).__name__, 'parent_id': parent_id, 'owned_nodes': 0,
                    'conditional': conditional, 'decorated': bool(node.decorator_list)}
            units[owner] = unit
            scopes = scopes + [{'name': _public(node.name), 'line': node.lineno,
                                 'column': node.col_offset, 'node': type(node).__name__}]
            conditional = False
        units[owner]['owned_nodes'] += 1
        records.append((node, owner, scopes, conditional))
        branch = conditional or isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.TryStar, ast.With, ast.AsyncWith, ast.Match))
        for child in reversed(list(ast.iter_child_nodes(node))):
            pending.append((child, depth+1, owner, scopes, branch))
    for unit in units.values():
        unit['own_status'] = 'COMPLETE' if unit['owned_nodes'] <= budgets['unit_nodes'] else 'BUDGET_EXCEEDED'
        unit['status'] = unit['own_status']
    # Scope completeness includes descendants, so absence queries cannot overlook an omitted child.
    for unit in reversed(list(units.values())):
        if unit['status'] != 'COMPLETE' and unit['parent_id'] is not None:
            parent = units[unit['parent_id']]
            if parent['status'] == 'COMPLETE':
                parent['status'] = 'PARTIAL'
    declarations = []
    relations = []
    omitted = 0
    for node, owner, scopes, conditional in records:
        unit = units[owner]
        if unit['own_status'] != 'COMPLETE':
            if isinstance(node, DECLARATIONS):
                omitted += 1
            continue
        location = {'line': getattr(node, 'lineno', 0), 'column': getattr(node, 'col_offset', 0)}
        fact = {'scope_id': owner, **location, 'rule_version': SCHEMA, 'scope': 'SYNTACTIC_ONLY'}
        if isinstance(node, DECLARATIONS):
            declarations.append({k: v for k, v in unit.items() if k not in ('owned_nodes', 'own_status', 'status')})
            relations.append({**fact, 'kind': 'defines', 'from_id': unit['parent_id'],
                              'to_id': owner, 'resolution': 'RESOLVED_STATIC',
                              'reason': 'LEXICAL_CONTAINMENT_ONLY'})
            if isinstance(node, ast.ClassDef):
                for index, base in enumerate(node.bases):
                    relations.append({**fact, 'kind': 'inherits', 'base_index': index,
                                      'expression': _expression(base), 'resolution': 'UNRESOLVED',
                                      'reason': 'BASE_EXPRESSION_NOT_RUNTIME_HIERARCHY'})
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            relations.append({**fact, 'kind': 'imports',
                              'module': _public(node.module) if isinstance(node, ast.ImportFrom) and node.module else None,
                              'level': node.level if isinstance(node, ast.ImportFrom) else 0,
                              'aliases': [{'name': _public(a.name), 'asname': _public(a.asname) if a.asname else None} for a in node.names],
                              'resolution': 'AMBIGUOUS' if any(a.name == '*' for a in node.names) else 'UNRESOLVED',
                              'reason': 'NO_IMPORT_RESOLUTION_OR_EXECUTION'})
        elif isinstance(node, ast.Call):
            relations.append({**fact, 'kind': 'calls', 'expression': _expression(node.func),
                              'resolution': 'UNRESOLVED' if isinstance(node.func, ast.Name) and node.func.id != 'getattr' else 'AMBIGUOUS',
                              'reason': 'CALLEE_CANDIDATE_ONLY_NO_RUNTIME_TARGET'})
    declarations.sort(key=lambda r: (r['line'], r['column'], r['node'], r['id']))
    relations.sort(key=lambda r: (r['line'], r['column'], r['kind'], canonical(r)))
    result['units'] = sorted(units.values(), key=lambda r: (r['line'], r['column'], r['node'], r['id']))
    result['declarations'] = declarations
    result['relations'] = relations
    unknown = sum(u['own_status'] != 'COMPLETE' for u in units.values())
    status = 'PARTIAL' if unknown else 'COMPLETE'
    result.update(status=status, total_detected=len(declarations)+omitted, returned=len(declarations),
                  remaining=0, omitted_by_budget=omitted, units_complete=len(units)-unknown,
                  units_unknown=unknown)
    result['AST_COVERAGE'].update(status=status, observed_nodes=observed, total_nodes=observed,
                                 max_observed_depth=max_depth, pending_units=unknown)
    return _finish(result)


def analyze_source(source_root, relative_path, expected_sha256, *, budgets=None):
    """Read one explicitly registered file, then parse only in a timed child process."""
    budgets = _budgets(budgets)
    raw = read_registered(source_root, relative_path, expected_sha256, budgets['bytes'])
    started = time.perf_counter()
    payload = canonical({'raw_hex': raw.hex(), 'path': relative_path,
                         'sha': expected_sha256, 'budgets': budgets})
    result = None
    # File-backed output avoids unbounded communicate() buffering of child stdout.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        try:
            proc = subprocess.run([sys.executable, '-I', str(Path(__file__).absolute()), '--worker'],
                                  input=payload, stdout=output, stderr=errors,
                                  timeout=budgets['timeout_seconds'], check=False)
            output.seek(0)
            if proc.returncode == 0:
                result = _read_transport(output, budgets)
            else:
                reason = 'WORKER_RESOURCE_ERROR'
        except subprocess.TimeoutExpired:
            reason = 'WORKER_TIMEOUT'
        except (OSError, ValueError):
            reason = 'WORKER_UNAVAILABLE_OR_INVALID_RESULT'
    if result is None:
        result = _base(relative_path, expected_sha256, len(raw), budgets)
        result.update(status='RESOURCE_ERROR', reason=reason)
        result['AST_COVERAGE']['status'] = 'RESOURCE_ERROR'
        result = _finish(result)
    validate_report(result)
    result['execution_metrics'] = {'elapsed_seconds': time.perf_counter()-started,
                                   'memory_isolation': 'NOT_IMPLEMENTED', 'memory_bytes': None}
    return result


def validate_report(report):
    """Validate the versioned envelope, identities, types and coverage arithmetic."""
    required = {'schema', 'source', 'source_sha256', 'parser', 'python_version',
                'budgets', 'status', 'PYTHON_SYNTAX', 'AST_COVERAGE', 'declarations',
                'relations', 'units', 'total_detected', 'returned', 'remaining',
                'omitted_by_budget', 'units_complete', 'units_unknown', 'execution',
                'behavior', 'snapshot_id'}
    if (not isinstance(report, dict) or not required <= set(report)
            or set(report)-required-{'reason','execution_metrics'}
            or report.get('schema') != SCHEMA or report.get('status') not in STATES):
        raise ValueError('INVALID_REPORT_SCHEMA')
    if report.get('execution') != 'NOT_PERFORMED' or report.get('behavior') != 'NOT_PROVEN' or report.get('parser') != 'CPython.ast+compile-no-execution':
        raise ValueError('INVALID_EXECUTION_SCOPE')
    semantic = {k: v for k, v in report.items() if k not in ('snapshot_id', 'execution_metrics')}
    if report['snapshot_id'] != digest(canonical(semantic)):
        raise ValueError('INVALID_REPORT_SNAPSHOT')
    source = report['source']
    if (not isinstance(source, dict) or set(source) != {'path','sha256','bytes'}
            or type(source['bytes']) is not int or not 0 <= source['bytes'] <= 262144
            or not isinstance(source['sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', source['sha256'])
            or report['source_sha256'] != source['sha256']):
        raise ValueError('INVALID_SOURCE_BINDING')
    path_parts(source['path'])
    _budgets(report['budgets'])
    if source['bytes'] > report['budgets']['bytes']:
        raise ValueError('SOURCE_EXCEEDS_ADMISSION_BUDGET')
    if report['PYTHON_SYNTAX'] not in {'PASS','FAIL','UNKNOWN'}:
        raise ValueError('INVALID_SYNTAX_STATE')
    for key in ('units','declarations','relations'):
        if not isinstance(report[key], list) or not all(isinstance(r,dict) for r in report[key]):
            raise ValueError('INVALID_REPORT_ROWS')
    coverage = report['AST_COVERAGE']
    if (not isinstance(coverage, dict) or coverage.get('status') != report['status']
            or type(coverage.get('observed_nodes')) is not int or coverage['observed_nodes'] < 0):
        raise ValueError('INVALID_COVERAGE_STATE')
    if len({r['id'] for r in report['units']}) != len(report['units']):
        raise ValueError('DUPLICATE_UNIT')
    units = {r['id']:r for r in report['units']}
    for row in units.values():
        if row['id'] != node_identity(report['source_sha256'], source['path'], row['scope_chain'], row['line'], row['column'], row['node']):
            raise ValueError('INVALID_NODE_IDENTITY')
        if (type(row['owned_nodes']) is not int or row['owned_nodes'] < 0
                or row['own_status'] not in {'COMPLETE','BUDGET_EXCEEDED'}
                or row['status'] not in {'COMPLETE','BUDGET_EXCEEDED','PARTIAL'}
                or row['parent_id'] is not None and row['parent_id'] not in units):
            raise ValueError('INVALID_UNIT_COVERAGE')
    for row in report['declarations']:
        if row['id'] != node_identity(report['source_sha256'], source['path'], row['scope_chain'], row['line'], row['column'], row['node']):
            raise ValueError('INVALID_DECLARATION_IDENTITY')
        if row['id'] in units and row != {k:v for k,v in units[row['id']].items() if k not in ('owned_nodes','own_status','status')}:
            raise ValueError('INVALID_DECLARATION_BINDING')
        if row['id'] not in units or units[row['id']]['own_status'] != 'COMPLETE':
            raise ValueError('UNCOVERED_DECLARATION')
    for row in report['relations']:
        if (row.get('kind') not in {'defines','calls','inherits','imports'}
                or row.get('resolution') not in {'RESOLVED_STATIC','AMBIGUOUS','UNRESOLVED','NOT_APPLICABLE'}
                or row.get('scope_id') not in units
                or units[row['scope_id']]['own_status'] != 'COMPLETE'):
            raise ValueError('INVALID_RELATION')
    if report['status'] in ('COMPLETE', 'PARTIAL'):
        unknown = sum(u['own_status'] != 'COMPLETE' for u in units.values())
        if (report['PYTHON_SYNTAX'] != 'PASS'
                or report['total_detected'] != len(report['declarations']) + report['omitted_by_budget']
                or report['returned'] != len(report['declarations']) or report['remaining'] != 0
                or report['units_unknown'] != unknown or report['units_complete'] != len(units)-unknown
                or report['status'] != ('PARTIAL' if unknown else 'COMPLETE')):
            raise ValueError('INVALID_INVENTORY_COUNT')
        if (coverage['total_nodes'] != sum(u['owned_nodes'] for u in units.values())
                or coverage['observed_nodes'] != coverage['total_nodes']
                or coverage['pending_units'] != unknown):
            raise ValueError('INVALID_COVERAGE_COUNT')
    return True


def page(report, kind='declarations', cursor=None, limit=100):
    validate_report(report)
    if kind not in ('declarations', 'relations') or type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError('INVALID_PAGE_REQUEST')
    offset = 0
    if cursor is not None:
        if not isinstance(cursor, str):
            raise ValueError('INVALID_CURSOR')
        try:
            snapshot, cursor_kind, number = cursor.split(':')
            offset = int(number)
        except (ValueError, TypeError):
            raise ValueError('INVALID_CURSOR') from None
        if snapshot != report['snapshot_id'] or cursor_kind != kind or str(offset) != number:
            raise ValueError('INVALID_CURSOR')
    items = report[kind]
    if not 0 <= offset <= len(items):
        raise ValueError('INVALID_CURSOR')
    rows = items[offset:offset+limit]
    remaining = len(items)-offset-len(rows)
    return {'schema': SCHEMA, 'source_sha256': report['source_sha256'],
            'snapshot_id': report['snapshot_id'], 'kind': kind,
            'status': 'PARTIAL' if offset or remaining else report['status'],
            'analysis_status': report['status'],
            'total_detected': report['total_detected'] if kind == 'declarations' else len(items),
            'returned': len(rows), 'remaining': remaining, 'offset': offset,
            'cursor': f"{report['snapshot_id']}:{kind}:{offset+len(rows)}" if remaining else None,
            'omitted_by_budget': report['omitted_by_budget'],
            'units_complete': report['units_complete'], 'units_unknown': report['units_unknown'],
            'items': rows}


def _write_transport(result, budgets):
    """Bound each source-ordered transport page before writing any of its bytes."""
    maximum = budgets['output_bytes']
    def emit(frame):
        body = canonical(frame)
        if len(body) + 1 > maximum:
            raise ValueError('OUTPUT_PAGE_BYTE_LIMIT')
        sys.stdout.buffer.write(body + b'\n')
    emit({'transport':SCHEMA, 'header':{k:v for k,v in result.items() if k not in ('units','declarations','relations')}})
    for kind in ('units','declarations','relations'):
        rows = result[kind]
        offset = 0
        while offset < len(rows):
            count = min(100, len(rows)-offset)
            while True:
                frame = {'transport':SCHEMA,'snapshot_id':result['snapshot_id'],'kind':kind,
                         'offset':offset,'total':len(rows),'items':rows[offset:offset+count]}
                if len(canonical(frame)) + 1 <= maximum:
                    break
                if count == 1:
                    raise ValueError('OUTPUT_ROW_BYTE_LIMIT')
                count = max(1,count//2)
            emit(frame)
            offset += count
    emit({'transport':SCHEMA,'snapshot_id':result['snapshot_id'],'end':True})


def _read_transport(handle, budgets):
    maximum = budgets['output_bytes']
    def receive():
        body = handle.readline(maximum + 1)
        if not body or len(body) > maximum or not body.endswith(b'\n'):
            raise ValueError('INVALID_OUTPUT_PAGE')
        frame = json.loads(body)
        if not isinstance(frame,dict) or frame.get('transport') != SCHEMA:
            raise ValueError('INVALID_OUTPUT_TRANSPORT')
        return frame
    first = receive()
    if set(first) != {'transport','header'} or not isinstance(first['header'],dict):
        raise ValueError('INVALID_OUTPUT_HEADER')
    result = first['header']
    for kind in ('units','declarations','relations'):
        result[kind] = []
    total_rows = 0
    totals = {}
    for _ in range(4 * budgets['nodes'] + 4):
        frame = receive()
        if frame.get('snapshot_id') != result.get('snapshot_id'):
            raise ValueError('INVALID_OUTPUT_SNAPSHOT')
        if frame.get('end') is True:
            if set(frame) != {'transport','snapshot_id','end'} or handle.read(1):
                raise ValueError('INVALID_OUTPUT_END')
            if any(len(result[k]) != n for k,n in totals.items()):
                raise ValueError('MISSING_OUTPUT_PAGE')
            return result
        kind = frame.get('kind')
        if kind not in ('units','declarations','relations') or set(frame) != {'transport','snapshot_id','kind','offset','total','items'}:
            raise ValueError('INVALID_OUTPUT_COLLECTION')
        rows = frame['items']
        if (not isinstance(rows,list) or not 1 <= len(rows) <= 100
                or frame['offset'] != len(result[kind]) or type(frame['total']) is not int
                or not len(result[kind])+len(rows) <= frame['total'] <= 4*budgets['nodes']):
            raise ValueError('INVALID_OUTPUT_PAGINATION')
        if kind in totals and totals[kind] != frame['total']:
            raise ValueError('INVALID_OUTPUT_TOTAL')
        totals[kind] = frame['total']
        total_rows += len(rows)
        if total_rows > 4*budgets['nodes']:
            raise ValueError('OUTPUT_ROW_LIMIT')
        result[kind].extend(rows)
    raise ValueError('OUTPUT_FRAME_LIMIT')


def _worker():
    payload = json.loads(sys.stdin.buffer.read(600000))
    raw = bytes.fromhex(payload['raw_hex'])
    budgets = _budgets(payload['budgets'])
    if len(raw) > budgets['bytes'] or digest(raw) != payload['sha']:
        return 2
    path_parts(payload['path'])
    result = _analyze(raw, payload['path'], payload['sha'], budgets)
    _write_transport(result, budgets)
    return 0


if __name__ == '__main__':
    if sys.argv[1:] == ['--worker']:
        try:
            sys.exit(_worker())
        except (MemoryError, RecursionError, ValueError, KeyError, TypeError):
            sys.exit(2)
    sys.exit(2)
