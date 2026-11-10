"""Versioned, manifest-bound authentic source projections; no target execution."""
import ast
import os
import re
from .evidence_handoff import (EvidenceProfile, Engine, EngineError, PublicError, checked,
    read_bytes, safe_read, parse, encoded, sha, identifier, relative, require, disjoint,
    PATH, MAX_BYTES, identity_conflicts, static_properties)
from pathlib import Path


def validate_claim(c, files, fmt):
    require(isinstance(c, dict) and c.get('source') in files)
    kind = c.get('kind')
    if fmt == 'real-records-v1':
        require(kind == 'json_equal' and set(c) == {'kind','source','pointer','other','other_pointer'})
        require(c['other'] in files)
        for key in ['pointer','other_pointer']:
            require(isinstance(c[key],list) and 1 <= len(c[key]) <= 8)
            for part in c[key]: identifier(part)
    elif kind == 'symbol_exists':
        require(set(c) == {'kind','source','name','node','present'} and c['node']=='definition')
        require(isinstance(c['name'],str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}',c['name']))
        require(type(c['present']) is bool)
    elif kind == 'function_node':
        require(set(c) == {'kind','source','function','node','present'})
        require(isinstance(c['function'],str) and re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,79}',c['function']))
        require(c['node'] in {'Return','Raise','If','Try','For','While','With','Call'})
        require(type(c['present']) is bool)
    else:
        require(False,'UNSUPPORTED_CLAIM')


class RealEvidenceProfile(EvidenceProfile):
    version = '0.4.1'

    def __init__(self, package_root, output_root):
        config_root=checked(package_root);self.catalog_path=config_root/'CATALOG.json'
        self.catalog_bytes=read_bytes(self.catalog_path);self.config=parse(self.catalog_bytes)
        require(set(self.config)=={'schema','profile','source_root','packages'})
        require(self.config['schema']=='pgop1.real-evidence-catalog.v1' and self.config['profile']=='real-evidence-local-v1')
        root=self.config['source_root']
        require(isinstance(root,str) and Path(root).is_absolute() and not root.startswith(('//','\\\\')),'UNSAFE_PATH')
        self.root,self.out=checked(root),checked(output_root)
        disjoint(self.root,self.out);disjoint(config_root,self.out)
        self.entries=self.config['packages'];require(isinstance(self.entries,dict) and 1<=len(self.entries)<=20)
        for name,e in self.entries.items():
            identifier(name)
            require(isinstance(e,dict) and set(e)=={'format','target_role','run_id','files','sources','required_roles','claims','summary'})
            require(e['format'] in {'real-records-v1','real-static-v1'})
            require(e['target_role'] in {'REAL_ENGINEERING','REAL_PYTHON_PROJECT','PGOP1_FROZEN_CORE','PGOP1_SELF_CODE'})
            identifier(e['run_id']);require(e['required_roles']==[])
            require(isinstance(e['files'],dict) and 1<=len(e['files'])<=16 and set(e['files'])==set(e['sources']))
            require(e['summary'] in e['files'])
            for p,d in e['files'].items():
                require(isinstance(p,str) and PATH.fullmatch(p) and all(p.split('/')),'UNSAFE_PATH');relative(self.root,p)
                require(isinstance(d,str) and len(d)==64 and all(ch in '0123456789abcdef' for ch in d))
                s=e['sources'][p];require(isinstance(s,dict) and set(s)=={'id','role','version','bytes','language'})
                identifier(s['id']);identifier(s['version']);require(s['role']=='code' and s['language'] in {'python','json','text'})
                require(type(s['bytes']) is int and 0<=s['bytes']<=MAX_BYTES)
                require(s['language']=='python' if e['format']=='real-static-v1' else s['language'] in {'json','text'})
            require(isinstance(e['claims'],list) and len(e['claims'])<=16)
            for c in e['claims']:validate_claim(c,e['files'],e['format'])

    def availability(self):
        r=super().availability();r.update(version=self.version,scope='AUTHORIZED_REAL_SOURCE_METADATA',catalog_schema='pgop1.real-evidence-catalog.v1',report_scope=self.report_scope());return r

    def report_scope(self):
        # Locator for this configured store/catalog, not global identity or custody.
        store = os.path.normcase(str(self.out.absolute()))
        return {'schema':'pgop1.report-scope.v1', 'profile':self.config['profile'],
                'store_namespace':'store-'+sha(store.encode('utf8')),
                'catalog_sha256':sha(self.catalog_bytes)}

    def completed(self, report_id):
        result = super().completed(report_id)
        folder = checked(self.out / identifier(report_id))
        report = parse(read_bytes(folder/'REPORT.json'))
        request = parse(read_bytes(folder/'REQUEST.json'))
        receipt = report.get('verification', {})
        expected = {'package_id':report.get('package_id'), 'receipt_id':receipt.get('receipt_id'),
                    'request_key':request.get('request_key'), 'profile':self.profile}
        require(request == expected and report.get('profile') == self.profile
                and report.get('template_version') == 'real-evidence-1'
                and report.get('report_id') == report_id, 'REPORT_SCOPE_MISMATCH')
        identifier(request['request_key'])
        require(report_id == 'report-'+sha(request['request_key'].encode())[:40], 'REPORT_SCOPE_MISMATCH')
        # Legacy real reports carry source pins but no catalog/store scope. Never
        # rewrite them; allow only an explicitly matching package/source selection.
        entry = self.entry(report['package_id'])
        pins = {row['source_id']:row['expected_sha256'] for row in receipt.get('sources', [])}
        require(pins == entry['files'], 'REPORT_SCOPE_MISMATCH')
        snapshot = sha(encoded({'package_id':report['package_id'],'entry':entry,'sources':receipt.get('sources', [])}))
        require(receipt.get('snapshot_id') == snapshot, 'REPORT_SCOPE_MISMATCH')
        scope = self.report_scope()
        if 'report_scope' in report:
            require(report['report_scope'] == scope, 'REPORT_SCOPE_MISMATCH')
        result.update(report_scope=scope, scope_binding='CATALOG_AND_STORE' if 'report_scope' in report else 'LEGACY_ENTRY_AND_SOURCE_PINS',
                      qualified_report_ref={**scope, 'report_id':report_id, 'manifest_sha256':result['manifest_sha256']})
        return result

    def read(self, report_id, artifact='FINAL_HANDOFF.md', offset=0, limit=8000):
        result = super().read(report_id,artifact,offset,limit)
        result['report_scope'] = self.report_scope()
        return result

    def catalog(self,offset=0,limit=10):
        r=super().catalog(offset,limit)
        for row in r['items']:row['evidence_scope']='AUTHORIZED_REAL_SOURCE_METADATA'
        return r

    def ingest_sources(self, package_id, order):
        return self._ingest_capture(package_id,order,self.snapshot(package_id))

    def _ingest_capture(self, package_id, order, capture):
        e,sources,bodies,_=capture
        require(isinstance(order,list) and len(order)<=32 and all(p in e['files'] for p in order))
        root=self.memory_root(package_id)
        if root.exists():
            for p in root.rglob('*'):checked(p)
        engine=Engine(root);conflicts=identity_conflicts(e);admitted=[]
        for p in order:
            if p not in bodies:continue
            s=e['sources'][p];sid=s['id']+'@'+s['version']
            if sid in conflicts:continue
            # Explicit derived envelope, not a retrospective fixture/event rewrite.
            raw=encoded({'schema':'pgop1.real-source-envelope.v1','sha256':sha(bodies[p]),'raw_hex':bodies[p].hex()})
            snap=checked(root/'envelopes'/sha(raw));snap.parent.mkdir(exist_ok=True)
            Engine._immutable(snap,raw);engine.admit_source(snap,sha(raw),scope='ENGINEERING_RESULT',source_id=sid)
            engine.ingest([{'id':sid,'kind':'real_source','task_id':package_id,'source_id':sid,'evidence_pointer':''}]);admitted.append(p)
        return {'pid':os.getpid(),'admitted':admitted,'engine_metrics':engine.metrics}

    def analyze(self, package_id, *, recover_only=False):
        capture=self.snapshot(package_id)
        e,sources,current,snapshot=capture
        if not recover_only:self._ingest_capture(package_id,list(e['files']),capture)
        root=self.memory_root(package_id)
        if root.exists():
            for p in root.rglob('*'):checked(p)
        engine=Engine(root);rows=engine.query(task_id=package_id,kind='real_source',limit=1000)
        bodies={};issues=[];conflicts=identity_conflicts(e)
        for sid,values in sorted(conflicts.items()):issues.append({'code':'IDENTITY_CONFLICT','identity':sid,'pins':values})
        allowed={}
        for p,s in e['sources'].items():allowed.setdefault(s['id']+'@'+s['version'],[]).append(p)
        for row in rows:
            sid=row['evidence_binding']['source_id'];require(sid in allowed,'IDENTITY_CONFLICT')
            if sid in conflicts:continue
            env=parse(engine.read_source(sid))
            require(env['schema']=='pgop1.real-source-envelope.v1','IDENTITY_CONFLICT')
            raw=bytes.fromhex(env['raw_hex'])
            for p in allowed[sid]:
                require(sha(raw)==env['sha256']==e['files'][p],'HASH_MISMATCH')
                if recover_only or p in current:bodies[p]=raw
        for p in sorted(set(e['files'])-set(bodies)):issues.append({'code':'SOURCE_UNAVAILABLE','source_id':p})
        props=[]
        if e['format']=='real-static-v1':
            for p in sorted(e['files']):
                if p in bodies:
                    result=static_properties(bodies[p],'python',[c for c in e['claims'] if c['source']==p],inventory=True)
                else:result={'SOURCE_INTEGRITY':'UNKNOWN','PYTHON_SYNTAX':'UNKNOWN','STATIC_CLAIMS':[], 'TEST_EXECUTION':'NOT_PERFORMED','BEHAVIORAL_CORRECTNESS':'NOT_PROVEN','SECURITY_ABSENCE_OF_VULNERABILITIES':'NOT_PROVEN'}
                props.append({'source_id':p,'sha256':e['files'][p],**result})
        else:
            claims=[]
            for c in e['claims']:
                status='INSUFFICIENT_EVIDENCE'
                try:
                    def scalar(p,keys):
                        value=parse(bodies[p])
                        for key in keys:value=value[key]
                        require(value is None or type(value) in {str,int,bool},'UNSUPPORTED_SCALAR')
                        return value
                    a=scalar(c['source'],c['pointer']);b=scalar(c['other'],c['other_pointer'])
                    status='SUPPORTED' if type(a)==type(b) and a==b else 'CONTRADICTED'
                except (KeyError,TypeError,PublicError):pass
                claims.append({'contract':c,'status':status,'reason':'EXACT_JSON_SCALAR_EQUALITY_ONLY'})
            props=[{'property':'SOURCE_RELATIONS','status':'INSUFFICIENT_EVIDENCE' if issues else 'CHECKED_WITH_SCOPE','STATIC_CLAIMS':claims,'HISTORICAL_ASSERTIONS':'NOT_VERIFIED','SEMANTIC_TRUTH':'NOT_PROVEN','TEST_EXECUTION':'NOT_PERFORMED'}]
        changed=False
        if not recover_only:
            _,latest,_,latest_snapshot=self.snapshot(package_id)
            if latest_snapshot != snapshot:
                changed=True;sources=latest;snapshot=latest_snapshot
                issues.append({'code':'SOURCE_CHANGED'})
                props=[{'property':'SOURCE_PROPERTIES','status':'INSUFFICIENT_EVIDENCE','reason':'SOURCE_CHANGED',
                        'STATIC_CLAIMS':[],'TEST_EXECUTION':'NOT_PERFORMED','BEHAVIORAL_CORRECTNESS':'NOT_PROVEN',
                        'SECURITY_ABSENCE_OF_VULNERABILITIES':'NOT_PROVEN'}]
                bodies={}
        failed=changed or any(s['status'] in {'HASH_MISMATCH','SIZE_MISMATCH','SOURCE_CHANGED'} for s in sources)
        receipt={'schema':'pgop1.verification.v1','profile':self.profile,'target_role':e['target_role'],'package_id':package_id,'snapshot_id':snapshot,
                 'status':'FAIL' if failed and not recover_only else 'PARTIAL' if issues else 'PASS','status_scope':'SOURCE_INTEGRITY_AND_COVERAGE_ONLY',
                 'sources':sources,'properties':props,'issues':issues,'memory':{'backend':'candidate.context_engine.Engine','retrieved':len(rows),'mode':'COMMITTED_SNAPSHOT_ONLY' if recover_only else 'CURRENT_BYTES_REVALIDATED'},
                 'coverage':{'passed':len(bodies),'registered':len(e['files'])},'checks':{'original_tests':'NOT_PERFORMED','semantic_regrade':'NOT_PERFORMED'}}
        receipt['receipt_id']=sha(encoded(receipt));return receipt,[],'HISTORICAL_ASSERTIONS_NOT_VERIFIED'

    @staticmethod
    def limits():
        return ['Authentic source metadata only; hashes do not establish semantic truth or custody.',
                'Finite JSON scalar equality and syntactic top-level symbol/AST containment contracts; no dynamic dependency resolution.',
                'TEST_EXECUTION=NOT_PERFORMED; BEHAVIORAL_CORRECTNESS=NOT_PROVEN; SECURITY_ABSENCE_OF_VULNERABILITIES=NOT_PROVEN.',
                'SELF_BEHAVIORAL_CORRECTNESS=NOT_PROVEN; SELF_SECURITY_CERTIFICATION=NOT_PROVEN; INDEPENDENT_SELF_CERTIFICATION=NOT_PROVEN.',
                'Bounds unchanged: 16 files, 262144 bytes/file, 12000 AST nodes, depth80, 256 facts,16claims,6s parser worker.',
                'Declaration inventory v1 covers module-body FunctionDef, AsyncFunctionDef and ClassDef only; nested declarations excluded. Budget failure exports no partial claims or declarations.',
                'Committed memory recovery proves snapshot recovery, not current original-file availability.',
                'REPORT_GENERATED grants no authority; no source execution, RUN, training, push or promotion.']

    def project_report(self,report):
        report.update(template_version='real-evidence-1',synthetic=False,target_role=self.entry(report['package_id'])['target_role'],limitations=self.limits())
        report['report_scope'] = self.report_scope()
        report['historical_source']={'status':'HISTORICAL_ASSERTIONS_NOT_VERIFIED'}
        report['operations']['performed']=['READ_SHA256','CONTEXT_ENGINE_SNAPSHOT_RETRIEVAL','BOUNDED_STATIC_PROPERTIES','RENDER_HANDOFF']
        return report
