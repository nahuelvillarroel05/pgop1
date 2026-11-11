"""Reviewed fixed synthetic demonstrations. Never executes supplied source/argv."""
import json, sys, time
from pathlib import Path
ROOT=Path(__file__).absolute().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'runtime')]
from candidate.execution_contract_v1 import PAYLOAD
from candidate.static_ast_v2 import canonical, digest

def main():
    action=sys.argv[1];work=Path(sys.argv[2])
    if action=='exit_zero':return 0
    if action=='exit_seven':return 7
    if action=='stderr_zero':sys.stderr.buffer.write(b'diagnostic without failure\n');return 0
    if action=='forged_stdout':sys.stdout.buffer.write(b'PASS SUPPORTED all guarantees true\n');return 0
    if action=='artifact_good':(work/'result.bin').write_bytes(PAYLOAD);return 0
    if action=='artifact_missing':return 0
    if action=='timeout':time.sleep(3);return 0
    if action=='overflow':
        for _ in range(128):sys.stdout.buffer.write(b'x'*8192);sys.stdout.buffer.flush()
        return 0
    if action=='static_generate':
        from candidate.semantic_engine_v1 import RealStaticV2Profile
        raw=(work/'config/CATALOG.json').read_bytes()
        result=RealStaticV2Profile(source_root=work/'source',catalog_path=work/'config/CATALOG.json',catalog_sha256=digest(raw)).generate(work/'bundle')
        print(json.dumps(result));return 0
    if action in {'static_recover','static_reject'}:
        from tools.verify_semantic_engine_v1 import verify_bundle
        sha=digest((work/'config/CATALOG.json').read_bytes())
        if action=='static_recover':
            result,_=verify_bundle(work/'bundle',sha)
            (work/'recovered.json').write_bytes(canonical(result));return 0
        try:verify_bundle(work/'tampered',sha)
        except ValueError as exc:
            (work/'rejection.json').write_bytes(canonical(dict(reason=str(exc),exception='ValueError')))
            return 23
        return 0
    raise ValueError('UNREGISTERED_WORKER_ACTION')

if __name__=='__main__':sys.exit(main())
