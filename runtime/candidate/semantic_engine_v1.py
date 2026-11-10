"""Opt-in real-static-v2 profile; legacy RealEvidenceProfile stays unchanged."""
from contextlib import ExitStack
import os
from pathlib import Path
import tempfile

from .static_ast_v2 import canonical, digest, read_registered
from .document_claims_v1 import strict_json
from .semantic_memory_v1 import create_archive


class RealStaticV2Profile:
    """One explicitly authorized catalog, immutable exclusive outputs, no dispatch migration."""

    def __init__(self, *, source_root, catalog_path, catalog_sha256):
        self.source_root = source_root
        self.catalog_path = catalog_path
        self.catalog_sha256 = catalog_sha256

    def generate(self, output):
        if os.name != 'nt':
            raise ValueError('WINDOWS_ONLY')
        from .windows_safe_io_v2 import Directory, absolute, reject_membership, safe_create_artifacts
        from tools.audit_snapshot_v1 import snapshot_and_write
        from tools.verify_source_v2 import read_source
        from tools.verify_semantic_engine_v1 import ROOT, check_catalog, derive, verify_bundle
        # Check unnormalized API inputs before Path can erase unsafe components.
        absolute(self.catalog_path)
        drive, parts = absolute(output)
        if not parts:
            raise ValueError('UNSAFE_PATH')
        with ExitStack() as transaction:
            held = [transaction.enter_context(Directory(p))
                    for p in (self.source_root, Path(self.catalog_path).parent, ROOT)]
            parent = transaction.enter_context(Directory(drive+'\\'.join(parts[:-1])))
            for protected in held:
                reject_membership(parent,protected)
            raw = read_registered(Path(self.catalog_path).parent, Path(self.catalog_path).name, self.catalog_sha256)
            catalog = check_catalog(strict_json(raw),self.catalog_sha256)
            if canonical(catalog) != raw:
                raise ValueError('CANONICAL_CATALOG_REQUIRED')
            # Staging is process-private derived data; all native sources are captured
            # only by snapshot V1. Final output is published once as an exclusive set.
            with tempfile.TemporaryDirectory(prefix='semantic-operation-') as tmp:
                tmp = Path(tmp)
                inner = canonical(catalog['catalog'])
                inner_path = tmp/'catalog.json'
                inner_path.write_bytes(inner)
                stage = tmp/'snapshot'
                ack = snapshot_and_write(self.source_root, inner_path, digest(inner), stage)
                if not ack['operation_completed']:
                    raise ValueError('SNAPSHOT_NOT_ACKNOWLEDGED')
                names = ('SNAPSHOT.json','REPORT.json','FINAL_HANDOFF.md','MANIFEST.json')
                captured = {n:read_source(stage,n,None,max_bytes=128_000_000) for n in names}
                snapshot = strict_json(captured['SNAPSHOT.json'])
                report = strict_json(captured['REPORT.json'])
                envelope = derive(catalog,snapshot,report,self.catalog_sha256)
                files = {n:captured[n] for n in names if n != 'MANIFEST.json'}
                files['SNAPSHOT_MANIFEST.json'] = captured['MANIFEST.json']
                files['CATALOG.json'] = raw
                files['INTEGRATION.json'] = canonical(envelope)
                files['MEMORY.json'] = canonical(create_archive(envelope))
                # Reopen the exported Engine in another fresh store before publishing.
                from .semantic_memory_v1 import recover
                recover(strict_json(files['MEMORY.json']),envelope)
                manifest = dict(schema='pgop1.semantic-manifest.v1',catalog_sha256=self.catalog_sha256,
                                files={n:dict(bytes=len(b),sha256=digest(b)) for n,b in files.items()})
                files['MANIFEST.json'] = canonical(manifest)
                for directory in (*held,parent):
                    directory.validate()
                safe_create_artifacts(self.source_root,output,files,(ROOT,Path(self.catalog_path).parent))
                for directory in (*held,parent):
                    directory.validate()
        return dict(schema='pgop1.semantic-ack.v1', status='INTEGRATION_WRITTEN', operation_completed=True,
                    integration_id=envelope['integration_id'], snapshot_id=snapshot['snapshot_id'],
                    catalog_sha256=self.catalog_sha256, manifest_sha256=digest(files['MANIFEST.json']),
                    storage_identity='PRIVATE_ENGINE_LOCATORS_NOT_SEMANTIC_IDENTITY',
                    source_current_at_ack='NOT_PROVEN', artifact_current_at_ack='NOT_PROVEN')

    def verify(self, artifacts):
        from tools.verify_semantic_engine_v1 import verify_bundle
        envelope, _ = verify_bundle(artifacts,self.catalog_sha256)
        return dict(schema='pgop1.semantic-verification.v1', status='INTEGRATION_VERIFIED',
                    integration_id=envelope['integration_id'], scope=envelope['scope'])

    def query(self, artifacts, **page):
        from tools.verify_semantic_engine_v1 import query_bundle
        return query_bundle(artifacts,self.catalog_sha256,**page)
