"""Prospective bounded source properties on the existing factual report service."""
import ast
import io
import json
import subprocess
import shutil
import os
from pathlib import Path
import re
import stat
import sys
import tokenize

try:
    from .public_handoff import PublicProfile, PublicError, checked, relative, read_bytes, parse, encoded, sha, identifier, MAX_BYTES, OPERATIONS, render
    from .engineering_handoff import require, disjoint
    from .context_engine import Engine, EngineError
except ImportError:
    from public_handoff import PublicProfile, PublicError, checked, relative, read_bytes, parse, encoded, sha, identifier, MAX_BYTES, OPERATIONS, render
    from engineering_handoff import require, disjoint
    from context_engine import Engine, EngineError

PROFILE = 'evidence-local-v1'
ROLES = {'config', 'execution', 'tests', 'recovery'}
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z')
PATH = re.compile(r'[A-Za-z0-9_./-]{1,160}\Z')
RULE_VERSION = 'pgop1.static-ast.v1'
MAX_NODES = 12000
MAX_DEPTH = 80


def safe_read(path):
    """Bound bytes and verify path/handle identity before and after reading."""
    checked(path)
    try:
        before = path.lstat()
        require(stat.S_ISREG(before.st_mode), 'UNSAFE_PATH')
        with path.open('rb') as handle:
            opened = os.fstat(handle.fileno())
            require(os.path.samestat(before, opened), 'SOURCE_CHANGED')
            raw = handle.read(MAX_BYTES + 1)
            after_handle = os.fstat(handle.fileno())
        checked(path)
        after = path.lstat()
        signature = lambda s: (s.st_size, s.st_mtime_ns)
        # Python 3.14 Windows lstat/fstat disagree on ctime semantics. Compare
        # ctime within each API, plus file ID/size/mtime across both APIs.
        require(os.path.samestat(opened, after) and signature(before) == signature(after_handle) == signature(after)
                and before.st_ctime_ns == after.st_ctime_ns and opened.st_ctime_ns == after_handle.st_ctime_ns, 'SOURCE_CHANGED')
    except FileNotFoundError as exc:
        raise PublicError('SOURCE_UNAVAILABLE', 'Registered source unavailable') from exc
    except OSError as exc:
        raise PublicError('ACCESS_DENIED' if isinstance(exc, PermissionError) else 'IO_ERROR', 'Registered source read failed') from exc
    require(len(raw) <= MAX_BYTES, 'SIZE_LIMIT')
    return raw


def _static_properties(raw, language, claims, *, inventory=False):
    result = {'rule_version': RULE_VERSION, 'parser': 'stdlib.ast+compile-validation-no-execution', 'python_version': sys.version.split()[0],
              'decoding': 'PEP263-strict-tokenize.detect_encoding', 'SOURCE_INTEGRITY': 'PASS',
              'PYTHON_SYNTAX': 'UNKNOWN', 'STRUCTURAL_FACTS': [], 'STATIC_CLAIMS': [],
              'DEPENDENCY_RESOLUTION': 'UNKNOWN', 'TEST_EXECUTION': 'NOT_PERFORMED',
              'BEHAVIORAL_CORRECTNESS': 'NOT_PROVEN', 'SECURITY_ABSENCE_OF_VULNERABILITIES': 'NOT_PROVEN'}
    if inventory:
        result['rule_version'] = 'pgop1.static-ast.inventory.v2'
        result['DECLARATION_INVENTORY'] = {
            'schema': 'pgop1.declarations.v1', 'scope': 'MODULE_BODY_ONLY',
            'source_sha256': sha(raw), 'status': 'UNSUPPORTED', 'items': [],
            'observed': 0, 'skipped': None, 'budget_exceeded': False}
        result['AST_COVERAGE'] = {'status': 'UNSUPPORTED', 'observed_nodes': 0,
            'total_nodes': None, 'max_observed_depth': 0,
            'node_limit': MAX_NODES, 'depth_limit': MAX_DEPTH}
    if language != 'python':
        node = shutil.which('node') if language == 'javascript' else None
        if node:
            env = {k:v for k,v in os.environ.items() if k.upper() not in {'NODE_OPTIONS','NODE_PATH'}}
            try:
                proc = subprocess.run([node, '--check', '--input-type=commonjs', '-'], input=raw, capture_output=True, timeout=3, env=env)
                version = subprocess.run([node, '--version'], capture_output=True, timeout=2, env=env).stdout.decode('ascii').strip()
                result.update(disposition='SUPPORTED_WITH_SCOPE', parser='Node-V8-check-commonjs', parser_version=version,
                              JAVASCRIPT_SYNTAX='PASS' if proc.returncode == 0 else 'FAIL')
            except (OSError, subprocess.TimeoutExpired):
                result.update(disposition='PARSER_UNAVAILABLE', JAVASCRIPT_SYNTAX='UNKNOWN')
        else:
            result.update(disposition='UNSUPPORTED_LANGUAGE', parser='NONE')
        return result
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(raw).readline)
        text = raw.decode(encoding, errors='strict')
        tree = ast.parse(text, filename='<registered-source>', mode='exec')
    except (SyntaxError, UnicodeError, LookupError, ValueError, RecursionError, MemoryError) as exc:
        # Never return exception text: it may include untrusted source literals.
        result.update(PYTHON_SYNTAX='FAIL', diagnostic={'code': type(exc).__name__, 'line': getattr(exc, 'lineno', None), 'column': getattr(exc, 'offset', None)})
        if inventory:
            result['AST_COVERAGE']['status'] = 'PARSE_FAILED'
            result['DECLARATION_INVENTORY']['status'] = 'PARSE_FAILED'
            if isinstance(exc,(MemoryError,RecursionError)):
                result.update(PYTHON_SYNTAX='UNKNOWN',disposition='PARSER_RESOURCE_ERROR')
                result['AST_COVERAGE']['status'] = 'RESOURCE_ERROR'
                result['DECLARATION_INVENTORY']['status'] = 'RESOURCE_ERROR'
        return result
    queue = [(tree, 0)]; nodes = []; max_depth = 0
    while queue:
        node, depth = queue.pop()
        max_depth = max(max_depth, depth)
        if depth > MAX_DEPTH or len(nodes) >= MAX_NODES:
            result.update(disposition='AST_COMPLEXITY_LIMIT', PYTHON_SYNTAX='UNKNOWN', STRUCTURAL_FACTS=[])
            if inventory:
                result['AST_COVERAGE'].update(status='BUDGET_EXCEEDED', observed_nodes=len(nodes),
                    max_observed_depth=max_depth, pending_nodes=len(queue)+1,
                    reason='DEPTH_LIMIT' if depth > MAX_DEPTH else 'NODE_LIMIT')
                result['DECLARATION_INVENTORY'].update(status='BUDGET_EXCEEDED', budget_exceeded=True)
            return result
        nodes.append(node)
        queue.extend((child, depth+1) for child in ast.iter_child_nodes(node))
    try:
        # Compiler validation catches return/break scope and duplicate arguments.
        # The code object is discarded; it is never executed or imported.
        compile(tree, '<registered-source>', 'exec', dont_inherit=True, optimize=0)
    except (SyntaxError, ValueError, RecursionError, MemoryError) as exc:
        result.update(PYTHON_SYNTAX='FAIL', diagnostic={'code':type(exc).__name__, 'line':getattr(exc,'lineno',None), 'column':getattr(exc,'offset',None)})
        if inventory:
            result['AST_COVERAGE'].update(status='COMPILER_REJECTED', observed_nodes=len(nodes),
                total_nodes=len(nodes), max_observed_depth=max_depth)
            result['DECLARATION_INVENTORY']['status'] = 'COMPILER_REJECTED'
            if isinstance(exc,(MemoryError,RecursionError)):
                result.update(PYTHON_SYNTAX='UNKNOWN',disposition='PARSER_RESOURCE_ERROR')
                result['AST_COVERAGE']['status'] = 'RESOURCE_ERROR'
                result['DECLARATION_INVENTORY']['status'] = 'RESOURCE_ERROR'
        return result
    result['PYTHON_SYNTAX'] = 'PASS'
    if inventory:
        result['AST_COVERAGE'].update(status='COMPLETE', observed_nodes=len(nodes),
            total_nodes=len(nodes), max_observed_depth=max_depth)
        declarations = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
        items = [{'node':type(n).__name__, 'name':n.name if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}',n.name) else 'WITHHELD',
                  'line':n.lineno, 'end_line':n.end_lineno, 'column':n.col_offset,
                  'end_column':n.end_col_offset} for n in declarations[:256]]
        result['DECLARATION_INVENTORY'].update(status='COMPLETE' if len(declarations)<=256 else 'TRUNCATED',
            items=items, observed=len(items), skipped=max(0,len(declarations)-256),
            budget_exceeded=len(declarations)>256)
    for node in nodes:
        fact = {'node': type(node).__name__, 'line': getattr(node, 'lineno', None), 'column': getattr(node, 'col_offset', None)}
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fact['name'] = node.name if TOKEN.fullmatch(node.name) else 'WITHHELD'
            fact['test_structure'] = node.name.startswith('test_')
        elif isinstance(node, ast.BinOp):
            fact['operator'] = type(node.op).__name__
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            # Import syntax observations only; availability never executes resolution.
            fact['references'] = [a.name if re.fullmatch(r'[A-Za-z0-9_.]{1,120}', a.name) else 'WITHHELD' for a in node.names]
            if isinstance(node, ast.ImportFrom):
                fact['module'] = node.module if node.module and re.fullmatch(r'[A-Za-z0-9_.]{1,120}', node.module) else 'WITHHELD'
                fact['level'] = node.level
            result['DEPENDENCY_RESOLUTION'] = 'PARTIAL'
        else:
            continue
        result['STRUCTURAL_FACTS'].append(fact)
    result['STRUCTURAL_FACTS_TRUNCATED'] = len(result['STRUCTURAL_FACTS']) > 256
    result['STRUCTURAL_FACTS'] = result['STRUCTURAL_FACTS'][:256]
    result['STRUCTURAL_FACTS'].sort(key=lambda f:(f['line'] or 0, f['column'] or 0, f['node']))
    for claim in claims:
        verdict, reason, location = 'INSUFFICIENT_EVIDENCE', 'PROPERTY_NOT_PROVEN', {}
        if claim['kind'] == 'symbol_exists':
            matches = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name == claim['name']]
            verdict = 'SUPPORTED' if bool(matches) == claim['present'] else 'CONTRADICTED'
            reason = 'TOP_LEVEL_SYNTACTIC_DEFINITION_EXISTENCE_ONLY'
        elif claim['kind'] == 'function_node':
            matches = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == claim['function']]
            if len(matches) == 1:
                found = any(type(n).__name__ == claim['node'] for n in ast.walk(matches[0]))
                verdict = 'SUPPORTED' if found == claim['present'] else 'CONTRADICTED'
                reason = 'SYNTACTIC_SUBTREE_CONTAINMENT_INCLUDING_NESTED_SCOPES_ONLY'
        elif claim['kind'] == 'return_binop':
            matches = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == claim['function']]
            if len(matches) == 1 and not matches[0].decorator_list:
                body = matches[0].body
                if len(body) == 1 and isinstance(body[0], ast.Return) and isinstance(body[0].value, ast.BinOp):
                    value = body[0].value
                    verdict = 'SUPPORTED' if type(value.op).__name__ == claim['operator'] else 'CONTRADICTED'
                    reason = 'EXACT_TOP_LEVEL_FUNCTION_SINGLE_RETURN_OPERATOR'
                    location = {'line': value.lineno, 'column': value.col_offset}
        result['STATIC_CLAIMS'].append({'contract': claim, 'status': verdict, 'reason': reason, **location})
    return result


def static_properties(raw, language, claims, *, inventory=False):
    # Execute only this trusted parser worker. Examined bytes arrive through stdin;
    # neither Python nor Node imports or executes the examined module.
    command = [sys.executable, '-B', str(Path(__file__).absolute()), '--parser-worker']
    failure = 'PARSER_RESOURCE_ERROR'
    try:
        require(len(raw) <= MAX_BYTES, 'SIZE_LIMIT')
        proc = subprocess.run(command, input=encoded({'raw_hex':raw.hex(),'language':language,'claims':claims,'inventory':inventory}), capture_output=True, timeout=6)
        require(proc.returncode == 0, 'PARSER_FAILED')
        return parse(proc.stdout)
    except (OSError, subprocess.TimeoutExpired, PublicError) as exc:
        if inventory and isinstance(exc,PublicError) and exc.code=='SIZE_LIMIT':failure='SIZE_LIMIT'
        result = {'SOURCE_INTEGRITY':'PASS','PYTHON_SYNTAX':'UNKNOWN','disposition':failure,
                'TEST_EXECUTION':'NOT_PERFORMED','BEHAVIORAL_CORRECTNESS':'NOT_PROVEN',
                'SECURITY_ABSENCE_OF_VULNERABILITIES':'NOT_PROVEN'}
        if inventory:
            result.update(rule_version='pgop1.static-ast.inventory.v2',
                AST_COVERAGE={'status':failure,'observed_nodes':0,'total_nodes':None,'node_limit':MAX_NODES,'depth_limit':MAX_DEPTH},
                DECLARATION_INVENTORY={'schema':'pgop1.declarations.v1','scope':'MODULE_BODY_ONLY','source_sha256':sha(raw),
                    'status':failure,'items':[],'observed':0,'skipped':None,'budget_exceeded':True},STATIC_CLAIMS=[])
        return result


def identity_conflicts(entry):
    groups = {}
    for path, spec in entry['sources'].items():
        key = spec['id']+'@'+spec['version']
        groups.setdefault(key,[]).append({'source_id':path,'sha256':entry['files'][path]})
    return {key:sorted(values,key=lambda v:v['source_id']) for key,values in groups.items() if len({v['sha256'] for v in values})>1}


class EvidenceProfile(PublicProfile):
    profile = PROFILE
    version = '0.3.0'

    def __init__(self, package_root, output_root):
        require(package_root is not None and output_root is not None)
        config_root = checked(package_root)
        self.catalog_path = config_root/'CATALOG.json'
        self.catalog_bytes = read_bytes(self.catalog_path)
        self.config = parse(self.catalog_bytes)
        require(set(self.config) == {'schema','profile','source_root','packages'})
        require(self.config['schema'] == 'pgop1.evidence-catalog.v1' and self.config['profile'] == PROFILE)
        root = self.config['source_root']
        require(isinstance(root,str) and Path(root).is_absolute() and not root.startswith(('//','\\\\')), 'UNSAFE_PATH')
        self.root, self.out = checked(root), checked(output_root)
        disjoint(self.root,self.out); disjoint(config_root,self.out)
        self.entries = self.config['packages']
        require(isinstance(self.entries,dict) and 1 <= len(self.entries) <= 20)
        for name, e in self.entries.items():
            identifier(name)
            require(isinstance(e,dict) and set(e) == {'format','synthetic','run_id','files','sources','required_roles','claims','summary'})
            require(e['format'] in {'multisource-v1','source-static-v1'} and e['synthetic'] is True)
            identifier(e['run_id'])
            require(isinstance(e['files'],dict) and 1 <= len(e['files']) <= 16 and set(e['files']) == set(e['sources']))
            require(e['summary'] in e['files'])
            require(isinstance(e['required_roles'],list) and set(e['required_roles']) <= ROLES)
            require(set(e['required_roles']) == ROLES if e['format']=='multisource-v1' else e['required_roles']==[])
            for path,digest in e['files'].items():
                require(isinstance(path,str) and PATH.fullmatch(path) and all(path.split('/')), 'UNSAFE_PATH')
                relative(self.root,path)
                require(isinstance(digest,str) and re.fullmatch('[a-f0-9]{64}',digest))
                s=e['sources'][path]
                require(isinstance(s,dict) and set(s)=={'id','role','version','bytes','language'})
                identifier(s['id']); identifier(s['version'])
                require(type(s['bytes']) is int and 0 <= s['bytes'] <= MAX_BYTES)
                require(s['role'] in ROLES if e['format']=='multisource-v1' else s['role']=='code')
                require(s['language'] in {'json','python','javascript','rust','c'})
            require(isinstance(e['claims'],list) and len(e['claims']) <= 16)
            for c in e['claims']:
                require(isinstance(c,dict) and c.get('source') in e['files'])
                if c.get('kind') == 'return_binop':
                    require(set(c)=={'source','kind','function','operator'})
                    identifier(c['function']);require(c['operator'] in {'Add','Sub','Mult','Div'})
                else:
                    require(set(c)=={'source','kind'} and c['kind'] in {'tests_pass','behavior'})

    def availability(self):
        return {'schema':'pgop1.evidence.v1','profile':self.profile,'version':self.version,'capabilities':list(OPERATIONS),
                'registered_packages':sorted(self.entries),'limits':{'file_bytes':MAX_BYTES,'files':16,'page_chars':16000,'ast_nodes':MAX_NODES,'ast_depth':MAX_DEPTH},
                'memory_backend':'candidate.context_engine.Engine','scope':'SYNTHETIC_TEST_FIXTURE','authority_effect':'NONE',
                'test_execution':'NOT_PERFORMED','os_sandbox':'NOT_PROVEN'}

    def catalog(self,offset=0,limit=10):
        r=super().catalog(offset,limit)
        for item in r['items']:item['evidence_scope']='SYNTHETIC_TEST_FIXTURE'
        return r

    def snapshot(self,package_id):
        require(read_bytes(self.catalog_path)==self.catalog_bytes,'CONFIG_CHANGED')
        e=self.entry(package_id);sources=[];bodies={}
        for path,digest in sorted(e['files'].items()):
            s=e['sources'][path]
            row={'source_id':path,'expected_sha256':digest,'identity':s['id'],'role':s['role'],'version':s['version'],'expected_bytes':s['bytes']}
            try:
                raw=safe_read(relative(self.root,path)); observed=sha(raw)
                row.update(observed_sha256=observed,bytes=len(raw),status='HASH_MISMATCH' if observed!=digest else 'SIZE_MISMATCH' if len(raw)!=s['bytes'] else 'PASS')
                if row['status']=='PASS':bodies[path]=raw
            except PublicError as exc:row.update(observed_sha256=None,status=exc.code)
            sources.append(row)
        # Catalog order is immaterial; substantive setup fields remain bound.
        binding={'package_id':package_id,'entry':e,'sources':sources}
        return e,sources,bodies,sha(encoded(binding))

    def memory_root(self,package_id):
        e=self.entry(package_id)
        return checked(self.out/'_memory'/package_id/sha(encoded(e)))

    def ingest_sources(self,package_id,order):
        """Trusted setup API only. MCP accepts package IDs, never paths/order/grants."""
        e,sources,bodies,_=self.snapshot(package_id)
        require(e['format']=='multisource-v1','UNSUPPORTED_FORMAT')
        require(isinstance(order,list) and len(order)<=32 and all(p in e['files'] for p in order))
        grants=[{'path':str(relative(self.root,p)),'sha256':e['files'][p],'scope':'SYNTHETIC'} for p in order if p in bodies]
        root=self.memory_root(package_id)
        if root.exists():
            for p in root.rglob('*'):checked(p)
        engine=Engine(root,grants=grants)
        errors=[]
        conflicts=identity_conflicts(e)
        for p in order:
            if p not in bodies:continue
            s=e['sources'][p];sid=s['id']+'@'+s['version'];raw=bodies[p]
            try:
                require(sid not in conflicts,'IDENTITY_CONFLICT')
                data=parse(raw)
                require(data.get('schema')=='pgop1.fixture-event.v1','INVALID_SCHEMA')
                for key,value in [('id',s['id']),('role',s['role']),('version',s['version']),('run_id',e['run_id'])]:
                    require(data.get(key)==value,'IDENTITY_CONFLICT')
                require(isinstance(data.get('requires'),list) and len(data['requires']) <= 16, 'INVALID_SCHEMA')
                require(all(isinstance(x,str) and re.fullmatch('[A-Za-z0-9_-]{1,80}@[A-Za-z0-9_-]{1,80}',x) for x in data['requires']), 'INVALID_SCHEMA')
                require(isinstance(data.get('event_id'),str) and TOKEN.fullmatch(data['event_id']), 'INVALID_SCHEMA')
                require(data.get('supersedes') is None or (isinstance(data['supersedes'],str) and re.fullmatch('[A-Za-z0-9_-]{1,80}@[A-Za-z0-9_-]{1,80}',data['supersedes'])), 'INVALID_SCHEMA')
                require(data.get('result') is None or (isinstance(data['result'],str) and data['result'] in {'PASS','FAIL','UNKNOWN'}), 'INVALID_SCHEMA')
                # Duplicates by identity retain first immutable descriptor, not last arrival.
                existing=engine._sources().get(sid)
                if existing:
                    require(existing['sha256']==sha(raw),'IDENTITY_CONFLICT')
                else:
                    snapshot_path = checked(root/'snapshots'/sha(raw))
                    snapshot_path.parent.mkdir(exist_ok=True)
                    Engine._immutable(snapshot_path,raw)
                    engine.admit_source(snapshot_path,sha(raw),scope='SYNTHETIC',source_id=sid)
                engine.ingest([{'id':sid,'kind':'fixture_source','task_id':package_id,'run_id':e['run_id'],'source_id':sid,'evidence_pointer':''}])
            except (PublicError,EngineError) as exc:
                record = {'source_id':p,'code':getattr(exc,'code','IDENTITY_CONFLICT'),'sha256':sha(raw)}
                rejection_raw = encoded(record); rid = 'rejected-' + sha(rejection_raw)
                rejection_path = checked(root/'rejections'/rid)
                rejection_path.parent.mkdir(exist_ok=True)
                Engine._immutable(rejection_path,rejection_raw)
                engine.admit_source(rejection_path,sha(rejection_raw),scope='SYNTHETIC',source_id=rid)
                engine.ingest([{'id':rid,'kind':'source_rejection','task_id':package_id,'source_id':rid,'evidence_pointer':''}])
                errors.append({'source_id':p,'code':record['code']})
        return {'admitted':len(engine.query(task_id=package_id,limit=1000)),'errors':errors,'engine_metrics':engine.metrics,'pid':os.getpid()}

    def multisource(self,package_id,e,bodies,recover_only=False):
        errors=[]
        if not recover_only:
            errors.extend(self.ingest_sources(package_id,list(e['files']))['errors'])
        root=self.memory_root(package_id)
        if root.exists():
            for p in root.rglob('*'):checked(p)
        engine=Engine(root)
        rows=engine.query(task_id=package_id,kind='fixture_source',limit=1000)
        for row in engine.query(task_id=package_id,kind='source_rejection',limit=1000):
            record=parse(engine.read_source(row['evidence_binding']['source_id']))
            require(e['files'].get(record['source_id']) == record['sha256'], 'IDENTITY_CONFLICT')
            errors.append({'source_id':record['source_id'],'code':record['code']})
        conflicts=identity_conflicts(e)
        for key,values in sorted(conflicts.items()):
            errors.append({'code':'IDENTITY_CONFLICT','identity':key,'selected_pins':values})
        docs={};bindings=[]
        allowed={s['id']+'@'+s['version']:e['files'][p] for p,s in e['sources'].items()}
        for row in rows:
            sid=row['evidence_binding']['source_id']
            if sid in conflicts:continue
            require(row['evidence_binding']['sha256']==allowed.get(sid),'IDENTITY_CONFLICT')
            data=parse(engine.read_source(sid));key=data['id']+'@'+data['version']
            docs[key]=data
            bindings.append({'id':sid,'sha256':row['evidence_binding']['sha256']})
        if recover_only:
            expected = {s['id']+'@'+s['version'] for s in e['sources'].values()}
            for missing in sorted(expected-set(docs)):
                errors.append({'code':'DEPENDENCY_MISSING','identity':missing})
        # Inspect selected metadata as well: conflicts cannot disappear behind Engine rejection.
        identities={}
        for p,raw in bodies.items():
            try:
                d=parse(raw);s=e['sources'][p];key=s['id']+'@'+s['version']
                if key in identities and identities[key]!=sha(raw):errors.append({'code':'IDENTITY_CONFLICT','identity':key})
                identities[key]=sha(raw)
            except PublicError:errors.append({'code':'PARSE_ERROR','source_id':p})
        for key,d in sorted(docs.items()):
            require(isinstance(d.get('requires'),list) and len(d['requires'])<=16,'INVALID_SCHEMA')
            require(all(isinstance(x,str) and re.fullmatch('[A-Za-z0-9_-]{1,80}@[A-Za-z0-9_-]{1,80}',x) for x in d['requires']),'INVALID_SCHEMA')
            for dep in d['requires']:
                if dep not in docs:errors.append({'code':'DEPENDENCY_MISSING','identity':key,'dependency':dep})
            require(isinstance(d.get('event_id'),str) and TOKEN.fullmatch(d['event_id']),'INVALID_SCHEMA')
            require(d.get('result') in {None,'PASS','FAIL','UNKNOWN'},'INVALID_SCHEMA')
            if d.get('supersedes') is not None:
                previous=docs.get(d['supersedes'])
                if previous is None:errors.append({'code':'DEPENDENCY_MISSING','identity':key})
                elif previous['id']!=d['id'] or previous['event_id']!=d['event_id']:errors.append({'code':'IDENTITY_CONFLICT','identity':key})
        grouped={}
        for key,d in docs.items():grouped.setdefault(d['id'],[]).append(key)
        active=[]
        for ident,keys in sorted(grouped.items()):
            superseded={docs[k].get('supersedes') for k in keys}
            tips=[k for k in keys if k not in superseded]
            # Require a single acyclic chain containing every selected version.
            visited=set();cursor=tips[0] if len(tips)==1 else None
            while cursor in keys and cursor not in visited:
                visited.add(cursor);cursor=docs[cursor].get('supersedes')
            if len(tips)!=1 or visited!=set(keys) or cursor is not None:
                errors.append({'code':'VERSION_AMBIGUOUS','identity':ident})
            else:active.append(tips[0])
        by_event={}
        for key in active:
            d=docs[key]
            if d.get('result') is not None:by_event.setdefault(d['event_id'],set()).add(d['result'])
        for event,values in sorted(by_event.items()):
            if len(values)>1:errors.append({'code':'RESULT_CONFLICT','event_id':event})
        expected = {s['id']+'@'+s['version'] for s in e['sources'].values()}
        for missing in sorted(expected-set(docs)):
            errors.append({'code':'DEPENDENCY_MISSING','identity':missing})
        present={d['role'] for d in docs.values()}
        for role in sorted(set(e['required_roles'])-present):errors.append({'code':'DEPENDENCY_MISSING','role':role})
        errors=sorted({encoded(x).decode():x for x in errors}.values(),key=lambda x:encoded(x))
        return {'property':'EXPLICIT_SOURCE_RELATIONS','status':'INSUFFICIENT_EVIDENCE' if errors else 'PASS',
                'memory':{'backend':'candidate.context_engine.Engine','backend_connected':True,'retrieved_from_committed_index':len(rows)},
                'bindings':sorted(bindings,key=lambda x:x['id']),'associations':[{'identity':k,'requires':docs[k]['requires'],'supersedes':docs[k].get('supersedes'),'event_id':docs[k]['event_id'],'result':docs[k].get('result')} for k in sorted(docs)],
                'active_versions':sorted(active),'issues':errors,'unique_sources':len(docs)}

    def analyze(self,package_id,*,recover_only=False):
        e,sources,bodies,snapshot=self.snapshot(package_id)
        properties=[]
        if e['format']=='multisource-v1':
            try:properties=[self.multisource(package_id,e,bodies,recover_only)]
            except (EngineError,PublicError) as exc:
                properties=[{'property':'EXPLICIT_SOURCE_RELATIONS','status':'INSUFFICIENT_EVIDENCE','issues':[{'code':getattr(exc,'code','MEMORY_INTEGRITY_ERROR')}]}]
        else:
            for src in sources:
                p=src['source_id']
                result=static_properties(bodies[p],e['sources'][p]['language'],[c for c in e['claims'] if c['source']==p]) if p in bodies else {'SOURCE_INTEGRITY':'FAIL' if src['status'] in {'HASH_MISMATCH','SIZE_MISMATCH'} else 'UNKNOWN','PYTHON_SYNTAX':'UNKNOWN','reason':src['status'],'TEST_EXECUTION':'NOT_PERFORMED','BEHAVIORAL_CORRECTNESS':'NOT_PROVEN','SECURITY_ABSENCE_OF_VULNERABILITIES':'NOT_PROVEN'}
                properties.append({'source_id':p,'sha256':src['observed_sha256'],**result})
        if e['format']=='multisource-v1' and not recover_only:
            for source in sources:
                if source['status'] != 'PASS':
                    properties[0].setdefault('issues',[]).append({'source_id':source['source_id'],'code':source['status']})
                    properties[0]['status']='INSUFFICIENT_EVIDENCE'
        # Receipt status is integrity/coverage only; static results remain per-property.
        failed=any(s['status'] in {'HASH_MISMATCH','SIZE_MISMATCH','SOURCE_CHANGED'} for s in sources)
        partial=any(s['status']!='PASS' for s in sources) or any(p.get('status')=='INSUFFICIENT_EVIDENCE' for p in properties)
        receipt={'schema':'pgop1.verification.v1','profile':self.profile,'package_id':package_id,'snapshot_id':snapshot,'status':'FAIL' if failed else 'PARTIAL' if partial else 'PASS','status_scope':'SOURCE_INTEGRITY_AND_COVERAGE_ONLY','sources':sources,'properties':properties,'checks':{'original_tests':'NOT_PERFORMED','semantic_regrade':'NOT_PERFORMED'},'coverage':{'passed':sum(s['status']=='PASS' for s in sources),'registered':len(sources)}}
        receipt['receipt_id']=sha(encoded(receipt))
        return receipt,[], 'NOT_APPLICABLE_SYNTHETIC'

    def query(self,package_id):
        receipt,metrics,historical=self.analyze(package_id)
        return {'package_id':package_id,'snapshot_id':receipt['snapshot_id'],'historical_result':historical,'metrics':metrics,'verification':receipt,'limitations':self.limits()}

    @staticmethod
    def limits():
        return ['SYNTHETIC_TEST_FIXTURE; finite explicit identity/relation contracts only.',
                'SOURCE_INTEGRITY_AND_COVERAGE_ONLY is not a global code verdict.',
                'TEST_EXECUTION=NOT_PERFORMED; BEHAVIORAL_CORRECTNESS=NOT_PROVEN; SECURITY_ABSENCE_OF_VULNERABILITIES=NOT_PROVEN.',
                'No original code execution, semantic RUN, training, external authentication or independent custody.',
                'Parser bounds: 262144 original bytes, 12000 AST nodes, depth 80; parser errors are bounded diagnostics, no source text.',
                'Filesystem identity checks detect observed swaps; adversarial OS isolation NOT_PROVEN. Parser worker hard timeout 6 seconds; no OS memory quota.',
                'REPORT_GENERATED grants no authority; continuity NO_NEW_AUTHORIZATION.']

    def project_report(self,report):
        report.update(template_version='evidence-1',synthetic='SYNTHETIC_TEST_FIXTURE',limitations=self.limits())
        report['historical_source']={'status':'NOT_APPLICABLE_SYNTHETIC'}
        report['operations']['performed']=['READ_SHA256','CONTEXT_ENGINE_RETRIEVAL_OR_STATIC_AST','CHECK_PROPERTY_CONTRACT','RENDER_HANDOFF']
        return report

    def render_report(self,report):
        return render(report)


def profile_service(package_root=None, output_root=None):
    """Trusted catalog schema chooses the versioned reader; wire operations unchanged."""
    if package_root is not None:
        config = parse(read_bytes(checked(package_root)/'CATALOG.json'))
        if config.get('schema') == 'pgop1.real-evidence-catalog.v1':
            from candidate.real_handoff import RealEvidenceProfile
            return RealEvidenceProfile(package_root, output_root)
    return EvidenceProfile(package_root, output_root)


if __name__ == "__main__" and sys.argv[1:] == ["--parser-worker"]:
    payload = json.loads(sys.stdin.buffer.read(MAX_BYTES*3+1))
    raw = bytes.fromhex(payload["raw_hex"])
    require(len(raw) <= MAX_BYTES, "SIZE_LIMIT")
    sys.stdout.buffer.write(encoded(_static_properties(raw,payload["language"],payload["claims"],inventory=payload.get('inventory',False))))
