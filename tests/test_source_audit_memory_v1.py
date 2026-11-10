"""Captured-report adapter tests. No native source-admission qualification."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from runtime.candidate.context_engine import Engine
from runtime.candidate.document_claims_v1 import CATALOG_SCHEMA, RULE, make_claim, typed
from runtime.candidate.source_audit_memory_v1 import SourceAuditMemory, SCOPE, QUALIFICATION
from runtime.candidate.static_ast_v2 import _analyze, _budgets, canonical, digest

ROOT = Path(__file__).absolute().parents[1]


def fixture(body=b'class A:\n def m(self):\n  return missing()\n', budgets=None):
    """Build an explicitly captured test report, not a production source read."""
    structure = _analyze(body, 'x.py', digest(body), _budgets(budgets))
    source = {'path': 'x.py', 'sha256': digest(body)}
    doc = {'path': 'README.md', 'sha256': digest(b'm is declared.\n'),
           'span_sha256': digest(b'm is declared.\n'), 'start_line': 1, 'end_line': 1}
    claim = make_claim('symbol_defined', doc, source, {'scope': 'A', 'name': 'm'}, typed(True))
    catalog = {'schema': CATALOG_SCHEMA, 'sources': [dict(source, kind='python'),
               {'path': doc['path'], 'sha256': doc['sha256'], 'kind': 'document'}], 'claims': [claim]}
    return {'schema': 'pgop1.source-audit-report.v2', 'catalog': catalog,
            'catalog_sha256': digest(canonical(catalog)), 'structures': [structure],
            'document_claims': {'schema': 'pgop1.doc-claims.results.v1', 'rule_version': RULE,
                'claims': [{'claim': claim, 'verdict': 'INSUFFICIENT_EVIDENCE',
                            'reason': 'FIXTURE_DECLARATION_NOT_INDEPENDENTLY_VERIFIED', 'coverage': 'ABSENT',
                            'rule_version': RULE, 'evidence': [], 'scope': 'DECLARATIONS_ONLY_NO_EXECUTION'}],
                'source_errors': [], 'temporal_verdicts': 'NOT_IMPLEMENTED_NO_STALE_INFERENCE'},
            'scope': copy.deepcopy(SCOPE)}


class SourceAuditMemoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ast-memory-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.memory = SourceAuditMemory(self.root / 'memory')

    def ingest(self, report=None):
        raw = canonical(report or fixture()) + b'\n'
        sha = digest(raw)
        return self.memory.ingest(raw, sha), sha, raw

    def test_typed_relations_claims_coverage_and_exact_bindings(self):
        receipt, sha, raw = self.ingest()
        self.assertEqual(receipt['status'], 'PERSISTED')
        rows = self.memory.read(sha, limit=100)['items']
        self.assertTrue(all(r['qualification'] == QUALIFICATION for r in rows))
        self.assertTrue(all(r['evidence_binding']['sha256'] == sha for r in rows))
        relations = self.memory.read(sha, kind='relations')['items']
        self.assertIn('calls', {r['value']['kind'] for r in relations})
        self.assertTrue(all('relationship' not in r for r in relations))
        claim = self.memory.read(sha, kind='claims')['items'][0]['value']
        self.assertEqual(claim['verdict'], 'INSUFFICIENT_EVIDENCE')
        engine = Engine(self.memory.root)
        manifest = engine.latest()
        version = engine.root / 'versions' / f"{manifest['version']:08d}-{manifest['graph_sha256']}"
        self.assertEqual(json.loads((version / 'graph.json').read_bytes())['edges'], [])
        self.assertEqual(engine.read_source('source-audit-' + sha), raw)

    def test_idempotency_pagination_and_other_source_snapshot(self):
        receipt, sha, raw = self.ingest()
        self.assertEqual(self.memory.ingest(raw, sha), receipt)
        all_rows, offset = [], 0
        while True:
            result = self.memory.read(sha, offset=offset, limit=2)
            all_rows.extend(result['items'])
            if result['next_offset'] is None:
                break
            offset = result['next_offset']
        self.assertEqual(len(all_rows), result['total'])
        self.assertEqual(len({r['id'] for r in all_rows}), len(all_rows))
        changed, other, _ = self.ingest(fixture(b'class A:\n def m(self):\n  return other()\n'))
        self.assertNotEqual(other, sha)
        self.assertEqual(changed['graph']['version'], 2)
        self.assertEqual(self.memory.read(sha, limit=100)['items'], all_rows)

    def test_cli_cross_process_recovery_original_unavailable(self):
        _, sha, raw = self.ingest()
        original = self.root / 'captured.json'
        original.write_bytes(raw)
        original.unlink()
        process = subprocess.run([sys.executable, str(ROOT / 'tools/source_audit_memory_v1.py'),
            '--memory-root', str(self.memory.root), 'read', '--report-sha256', sha, '--kind', 'relations'],
            capture_output=True, text=True, cwd=self.root, timeout=20)
        self.assertEqual(process.returncode, 0, process.stderr)
        result = json.loads(process.stdout)
        self.assertGreater(result['returned'], 0)
        self.assertEqual(result['source_recomputation'], 'NOT_PERFORMED')

    def test_partial_empty_and_source_errors_are_not_absence(self):
        report = fixture(b'def f():\n x=1\n y=2\n', {'unit_nodes': 1})
        _, sha, _ = self.ingest(report)
        structure = self.memory.read(sha, kind='structure')['items'][0]['value']
        self.assertEqual(structure['status'], 'PARTIAL')
        report = fixture()
        report['structures'] = []
        report['document_claims']['source_errors'] = [{'path': 'x.py', 'reason': 'UNSUPPORTED_SAFE_READ_PLATFORM'}]
        _, sha, _ = self.ingest(report)
        self.assertEqual(self.memory.read(sha, kind='declarations')['total'], 0)
        self.assertEqual(self.memory.read(sha, kind='source_errors')['items'][0]['value']['reason'],
                         'UNSUPPORTED_SAFE_READ_PLATFORM')

    def test_hash_duplicate_json_scope_and_catalog_tamper_rejected(self):
        raw = canonical(fixture())
        with self.assertRaisesRegex(ValueError, 'HASH_MISMATCH'):
            self.memory.ingest(raw, '0' * 64)
        bad = b'{"schema":1,"schema":2}'
        with self.assertRaises(ValueError):
            self.memory.ingest(bad, digest(bad))
        for change in ('scope', 'catalog', 'relation'):
            report = fixture()
            if change == 'scope':
                report['scope']['execution'] = 'PERFORMED'
            elif change == 'catalog':
                report['catalog_sha256'] = '0' * 64
            else:
                report['structures'][0]['relations'][0]['kind'] = 'VERIFIED_CAUSAL'
            raw = canonical(report)
            with self.assertRaises(ValueError):
                self.memory.ingest(raw, digest(raw))
        self.assertFalse(self.memory.root.exists())

    def test_missing_memory_and_invalid_pages_do_not_reconstruct(self):
        with self.assertRaisesRegex(ValueError, 'MEMORY_UNAVAILABLE'):
            self.memory.read('0' * 64)
        self.assertFalse(self.memory.root.exists())
        _, sha, _ = self.ingest()
        for kw in ({'limit': True}, {'offset': True}, {'offset': -1}, {'limit': 101},
                   {'offset': 99999}, {'kind': 'VERIFIED_CAUSAL'}):
            with self.subTest(kw=kw), self.assertRaises(ValueError):
                self.memory.read(sha, **kw)

    def test_tampered_object_and_snapshot_rejected(self):
        _, sha, raw = self.ingest()
        obj = self.memory.root / 'objects' / sha
        obj.write_bytes(raw + b' ')
        with self.assertRaises(ValueError):
            self.memory.read(sha)
        obj.write_bytes(raw)
        (self.memory.root / 'captured-reports-v1' / (sha + '.json')).write_bytes(b'{}')
        with self.assertRaises(ValueError):
            self.memory.ingest(raw, sha)

    def test_record_limit_is_rejection_without_partial_commit(self):
        report = fixture(b''.join(f'def f{i}():pass\n'.encode() for i in range(400)))
        raw = canonical(report)
        with self.assertRaisesRegex(ValueError, 'MEMORY_RECORD_LIMIT'):
            self.memory.ingest(raw, digest(raw))
        self.assertFalse(self.memory.root.exists())

    def test_independent_storage_verifier_rejects_rehashed_pointer_forgery(self):
        _, sha, _ = self.ingest()
        command = [sys.executable, str(ROOT / 'tools/verify_source_audit_memory_v1.py'),
                   '--memory-root', str(self.memory.root), '--report-sha256', sha]
        verified = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(verified.returncode, 0, verified.stderr + verified.stdout)
        self.assertFalse(json.loads(verified.stdout)['engine_imported'])
        engine = Engine(self.memory.root)
        manifest = engine.latest()
        folder = self.memory.root / 'versions' / f"{manifest['version']:08d}-{manifest['graph_sha256']}"
        graph = json.loads((folder / 'graph.json').read_bytes())
        graph['observations'][0]['qualification'] = 'VERIFIED_CAUSAL'
        from runtime.candidate.context_engine import canonical_json
        raw = canonical_json(graph)
        new_sha = digest(raw)
        (folder / 'graph.json').write_bytes(raw)
        provenance = json.loads((folder / 'provenance.json').read_bytes())
        provenance['graph_sha256'] = new_sha
        prov_raw = canonical_json(provenance)
        (folder / 'provenance.json').write_bytes(prov_raw)
        manifest['graph_sha256'] = new_sha
        manifest['provenance_sha256'] = digest(prov_raw)
        (folder / 'manifest.json').write_bytes(canonical_json(manifest))
        folder.rename(folder.with_name(f"{manifest['version']:08d}-{new_sha}"))
        rejected = subprocess.run(command, capture_output=True, text=True, timeout=20)
        self.assertEqual(rejected.returncode, 1, rejected.stderr + rejected.stdout)

    def test_independent_verifier_rejects_missing_source_descriptor(self):
        _, sha, _ = self.ingest()
        descriptor = next((self.memory.root / 'sources').glob('*.json'))
        descriptor.unlink()
        result = subprocess.run([sys.executable, str(ROOT / 'tools/verify_source_audit_memory_v1.py'),
            '--memory-root', str(self.memory.root), '--report-sha256', sha],
            capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_store_symlink_rejected(self):
        actual = self.root / 'actual'
        actual.mkdir()
        link = self.root / 'link'
        link.symlink_to(actual, target_is_directory=True)
        with self.assertRaises(ValueError):
            SourceAuditMemory(link)

    def test_malformed_claim_metadata_rejected_before_store_creation(self):
        for key, value in [('reason', {}), ('coverage', []), ('evidence', [123])]:
            report = fixture()
            report['document_claims']['claims'][0][key] = value
            raw = canonical(report)
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.memory.ingest(raw, digest(raw))
        self.assertFalse(self.memory.root.exists())

    def test_utf16_report_rejected_before_any_store_write(self):
        raw = json.dumps(fixture()).encode('utf-16')
        with self.assertRaises(UnicodeError):
            self.memory.ingest(raw, digest(raw))
        self.assertFalse(self.memory.root.exists())

    def test_missing_or_conflicting_python_accounting_rejected(self):
        for drop in (True, False):
            report = fixture()
            if drop:
                report['structures'] = []
            else:
                report['document_claims']['source_errors'] = [{'path': 'x.py', 'reason': 'SOURCE_CHANGED'}]
            raw = canonical(report)
            with self.subTest(drop=drop), self.assertRaisesRegex(ValueError, 'PYTHON_SOURCE_ACCOUNTING'):
                self.memory.ingest(raw, digest(raw))
        self.assertFalse(self.memory.root.exists())

    def test_cli_ingest_and_api_recovery(self):
        raw = canonical(fixture())
        sha = digest(raw)
        captured = self.root / 'captured.json'
        captured.write_bytes(raw)
        process = subprocess.run([sys.executable, str(ROOT / 'tools/source_audit_memory_v1.py'),
            '--memory-root', str(self.memory.root), 'ingest', '--captured-report', str(captured),
            '--report-sha256', sha], capture_output=True, text=True, cwd=self.root, timeout=20)
        self.assertEqual(process.returncode, 0, process.stderr + process.stdout)
        self.assertEqual(json.loads(process.stdout)['status'], 'PERSISTED')
        captured.unlink()
        self.assertGreater(self.memory.read(sha)['total'], 0)

    def test_unexpected_same_task_observation_is_not_hidden_by_query_limit(self):
        _, sha, _ = self.ingest()
        engine = Engine(self.memory.root)
        engine.ingest([{'id': 'zz-unexpected', 'task_id': sha, 'kind': 'other',
                       'evidence_binding': {'source_id': 'source-audit-' + sha, 'pointer': '/scope'}}])
        with self.assertRaisesRegex(ValueError, 'MEMORY_RECORD_MEMBERSHIP'):
            self.memory.read(sha)


if __name__ == '__main__':
    unittest.main()
