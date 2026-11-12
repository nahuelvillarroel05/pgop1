"""Private opt-in E7 CLI. An authorized catalog is required; no enumeration fallback."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).absolute().parents[1]
sys.path[:0]=[str(ROOT/'runtime'),str(ROOT)]
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root',required=True)
    for name in ('catalog','catalog-sha256','policy','policy-sha256','code-manifest','code-sha256','output'):
        parser.add_argument('--'+name)
    a=parser.parse_args()
    if not a.catalog:
        print(json.dumps(dict(status='BLOCKED_NOT_IMPLEMENTED',reason='SAFE_DIRECTORY_ENUMERATION_UNAVAILABLE',autonomous_from_root='BLOCKED_NOT_IMPLEMENTED')));return 3
    if any(getattr(a,k) is None for k in ('catalog_sha256','policy','policy_sha256','code_manifest','code_sha256','output')):
        parser.error('catalog, policy, code identity pins and new output are required')
    try:
        from candidate.source_selection_v1 import execute
        result=execute(a.source_root,a.catalog,a.catalog_sha256,a.policy,a.policy_sha256,a.code_manifest,a.code_sha256,a.output)
    except (OSError,ValueError,TypeError,KeyError,MemoryError,RecursionError) as exc:
        print(json.dumps(dict(status='ERROR',reason=getattr(exc,'code',str(exc)),operation_completed=False)));return 2
    print(json.dumps(result,sort_keys=True));return 0
if __name__=='__main__':raise SystemExit(main())
