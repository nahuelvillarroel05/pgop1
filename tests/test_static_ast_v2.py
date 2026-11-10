"""Inert source fixtures: analysis never imports or executes them."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from runtime.candidate.static_ast_v2 import (
    AdmissionError, analyze_source, canonical, digest, page, read_registered,
    validate_report, DEFAULT_BUDGETS)
from runtime.candidate.evidence_handoff import _static_properties

ROOT = Path(__file__).absolute().parents[1]


class StaticASTV2Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='ast-v2-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def analyze(self, text, budgets=None, name='fixture.py'):
        raw = text.encode('utf-8') if isinstance(text, str) else text
        (self.root / name).write_bytes(raw)
        return analyze_source(self.root, name, digest(raw), budgets=budgets)

    def test_real_pg_i7_v1_stays_limited_v2_complete(self):
        name = 'runtime/candidate/pg_i7.py'
        raw = (ROOT/name).read_bytes()
        old = _static_properties(raw, 'python', [], inventory=True)
        self.assertEqual(old['AST_COVERAGE']['status'], 'BUDGET_EXCEEDED')
        self.assertEqual(old['STRUCTURAL_FACTS'], [])
        result = analyze_source(ROOT, name, digest(raw))
        self.assertEqual(result['status'], 'COMPLETE')
        self.assertEqual(result['AST_COVERAGE']['total_nodes'], 21657)
        self.assertGreater(len(result['declarations']), 50)
        self.assertGreater(len(result['relations']), 100)
        self.assertEqual(sum(u['owned_nodes'] for u in result['units']), 21657)

    def test_four_hundred_source_order_pages_and_snapshot(self):
        result = self.analyze(''.join(f'def f{i:03}():\n    return {i}\n' for i in range(400)))
        cursor = None
        rows = []
        while True:
            p = page(result, cursor=cursor, limit=37)
            self.assertEqual(p['snapshot_id'], result['snapshot_id'])
            self.assertEqual(p['total_detected'], 400)
            rows.extend(p['items'])
            cursor = p['cursor']
            if cursor is None:
                break
        self.assertEqual([r['name'] for r in rows], [f'f{i:03}' for i in range(400)])
        self.assertEqual(len({r['id'] for r in rows}), 400)
        self.assertEqual(rows[0]['name'], 'f000')
        self.assertEqual(rows[-1]['name'], 'f399')
        self.assertEqual(page(result, limit=1000)['status'], 'COMPLETE')
        self.assertEqual(page(result, limit=10)['status'], 'PARTIAL')
        with self.assertRaises(ValueError):
            page(result, cursor='0'*64+':declarations:10')

    def test_scopes_redefinitions_async_conditional(self):
        r = self.analyze('''class A:
    def m(self):
        async def inner():
            return 1
        return inner
    def m(self):
        pass
class B:
    def m(self):
        pass
if True:
    def conditional():
        pass
''')
        names = [d['qualified_name'] for d in r['declarations']]
        self.assertIn('A.m.inner', names)
        self.assertIn('B.m', names)
        self.assertEqual(names.count('A.m'), 2)
        self.assertEqual(len(set(d['id'] for d in r['declarations'])), len(names))
        self.assertTrue(next(d for d in r['declarations'] if d['name']=='conditional')['conditional'])
        self.assertEqual(next(d for d in r['declarations'] if d['name']=='inner')['node'], 'AsyncFunctionDef')

    def test_dynamic_relations_stay_uncertain(self):
        r = self.analyze('''from .external import Base as Alias
from ..other import *
import dynamic as mutable
@decorate
class A(Alias):
    def m(self):
        mutable = unknown
        getattr(self, "PRIVATE_LITERAL")()
        mutable()
        self.dispatch()
''')
        self.assertEqual({r['kind'] for r in r['relations']}, {'defines','imports','inherits','calls'})
        for rel in r['relations']:
            if rel['kind'] != 'defines':
                self.assertIn(rel['resolution'], ('UNRESOLVED','AMBIGUOUS'))
        imports = [x for x in r['relations'] if x['kind']=='imports']
        self.assertEqual([x['level'] for x in imports], [1,2,0])
        self.assertEqual(imports[0]['aliases'], [{'name':'Base','asname':'Alias'}])
        self.assertNotIn('PRIVATE_LITERAL', canonical(r).decode())
        self.assertTrue(next(d for d in r['declarations'] if d['name']=='A')['decorated'])

    def test_unicode_comments_and_string_code_are_inert(self):
        r = self.analyze('# def fake(): pass\ntext="def phantom(): pass"\ndef café():\n    return "SECRET_LITERAL"\n')
        self.assertEqual([d['name'] for d in r['declarations']], ['café'])
        self.assertNotIn('SECRET_LITERAL', canonical(r).decode())
        self.assertEqual(r['PYTHON_SYNTAX'], 'PASS')

    def test_syntax_errors_never_echo_source(self):
        for raw in ('def SECRET_PRIVATE(:\n', 'return "SECRET_PRIVATE"\n'):
            r = self.analyze(raw)
            self.assertEqual(r['status'], 'PARSE_FAILED')
            self.assertEqual(r['PYTHON_SYNTAX'], 'FAIL')
            self.assertNotIn('SECRET_PRIVATE', canonical(r).decode())

    def test_encoding_detection(self):
        r = self.analyze(b'# coding: latin-1\ndef caf\xe9():\n    pass\n')
        self.assertEqual(r['PYTHON_SYNTAX'], 'PASS')
        self.assertEqual(r['declarations'][0]['name'], 'café')

    def test_global_nodes_depth_and_parser_depth_limits(self):
        r = self.analyze('x=1\ny=2\n', {'nodes':3})
        self.assertEqual(r['status'], 'BUDGET_EXCEEDED')
        self.assertIsNone(r['AST_COVERAGE']['total_nodes'])
        self.assertEqual(r['declarations'], [])
        r = self.analyze('x=a.b.c.d.e\n', {'depth':3})
        self.assertEqual(r['reason'], 'DEPTH_LIMIT')
        r = self.analyze('x='+ '(' * 1000 + '1' + ')' * 1000)
        self.assertEqual(r['status'], 'PARSE_FAILED')

    def test_partial_unit_keeps_other_units_and_syntax(self):
        r = self.analyze('def big():\n'+''.join('    x=1\n' for _ in range(20))+'def small():\n    pass\n', {'unit_nodes':10})
        self.assertEqual(r['status'], 'PARTIAL')
        self.assertEqual(r['PYTHON_SYNTAX'], 'PASS')
        self.assertEqual([d['name'] for d in r['declarations']], ['small'])
        self.assertEqual(r['omitted_by_budget'], 1)
        self.assertEqual(r['total_detected'], 2)
        self.assertEqual(r['units_unknown'], 1)
        module = next(u for u in r['units'] if u['node']=='Module')
        self.assertEqual(module['status'], 'PARTIAL')
        self.assertEqual(sum(u['owned_nodes'] for u in r['units']), r['AST_COVERAGE']['total_nodes'])

    def test_size_hash_symlinks_traversal(self):
        with self.assertRaisesRegex(AdmissionError, 'SIZE_LIMIT'):
            self.analyze(b'#' * 262145)
        raw = b'x=1\n'
        (self.root/'x.py').write_bytes(raw)
        for path in ('../x.py', '/x.py', 'x/../x.py', './x.py', 'x\\y.py'):
            with self.assertRaises(AdmissionError):
                read_registered(self.root, path, digest(raw))
        (self.root/'link.py').symlink_to(self.root/'x.py')
        with self.assertRaises(AdmissionError):
            read_registered(self.root, 'link.py', digest(raw))
        (self.root/'linked-dir').symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(AdmissionError):
            read_registered(self.root, 'linked-dir/x.py', digest(raw))
        with self.assertRaisesRegex(AdmissionError, 'HASH_MISMATCH'):
            read_registered(self.root, 'x.py', '0'*64)
        self.assertEqual(len(self.analyze(b'#'*262144)['declarations']), 0)

    def test_toctou_changed_during_and_after_read(self):
        raw = b'x=1\n'
        p = self.root/'x.py'
        p.write_bytes(raw)
        original_read = os.read
        changed = False
        def mutate(fd, amount):
            nonlocal changed
            body = original_read(fd, amount)
            if not changed:
                changed = True
                p.write_bytes(b'x=2\n')
            return body
        with patch('runtime.candidate.static_ast_v2.os.read', side_effect=mutate):
            with self.assertRaisesRegex(AdmissionError, 'SOURCE_CHANGED'):
                read_registered(self.root, 'x.py', digest(raw))
        with self.assertRaisesRegex(AdmissionError, 'HASH_MISMATCH'):
            read_registered(self.root, 'x.py', digest(raw))

    def test_timeout_resource_not_syntax_failure(self):
        (self.root/'x.py').write_bytes(b'x=1\n')
        with patch('runtime.candidate.static_ast_v2.subprocess.run', side_effect=subprocess.TimeoutExpired('worker',1)):
            r = analyze_source(self.root, 'x.py', digest(b'x=1\n'))
        self.assertEqual(r['status'], 'RESOURCE_ERROR')
        self.assertEqual(r['PYTHON_SYNTAX'], 'UNKNOWN')
        self.assertEqual(r['reason'], 'WORKER_TIMEOUT')

    def test_determinism_across_processes_input_order_and_validation(self):
        a = self.analyze('class A:\n    def m(self):\n        return foo()\n',name='a.py')
        self.analyze('def b():\n    pass\n',name='b.py')
        b = analyze_source(self.root,'a.py',a['source_sha256'])
        a.pop('execution_metrics');b.pop('execution_metrics')
        self.assertEqual(canonical(a),canonical(b))
        self.assertTrue(validate_report(a))
        a['declarations'][0]['line'] = 999
        with self.assertRaises(ValueError):
            validate_report(a)

    def test_invalid_budgets_and_pages(self):
        for bad in ({'nodes':0},{'bytes':262145},{'depth':True},{'unknown':1},{'timeout_seconds':float('nan')}):
            with self.assertRaises(ValueError):
                self.analyze('x=1',bad)
        r=self.analyze('x=1')
        for kwargs in ({'limit':0},{'limit':True},{'kind':'unknown'},{'cursor':'malformed'}):
            with self.assertRaises(ValueError):page(r,**kwargs)


if __name__ == '__main__':
    unittest.main()
