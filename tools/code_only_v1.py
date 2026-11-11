"""Opt-in versioned code-only analysis/query CLI; public MCP unchanged."""
import argparse
from pathlib import Path
import sys
ROOT=Path(__file__).absolute().parents[1]
sys.path.insert(0,str(ROOT));sys.path.insert(0,str(ROOT/'runtime'))
from candidate.code_contract_v1 import canonical,SCOPE

def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='operation',required=True)
    a=sub.add_parser('analyze')
    for arg in ('source-root','catalog','catalog-sha256','output'):a.add_argument('--'+arg,required=True)
    q=sub.add_parser('query')
    q.add_argument('--artifacts',required=True);q.add_argument('--catalog-sha256',required=True)
    q.add_argument('--kind',choices=['claims','relations'],default='claims');q.add_argument('--offset',type=int,default=0);q.add_argument('--limit',type=int,default=50)
    args=p.parse_args()
    try:
        if args.operation=='analyze':
            from candidate.code_only_v1 import CodeOnlyProfile
            result=CodeOnlyProfile(source_root=args.source_root,catalog_path=args.catalog,catalog_sha256=args.catalog_sha256).generate(args.output)
        else:
            from tools.verify_code_only_v1 import query_bundle
            result=query_bundle(args.artifacts,args.catalog_sha256,kind=args.kind,offset=args.offset,limit=args.limit)
    except (OSError,ValueError,KeyError,TypeError,UnicodeError,RecursionError,MemoryError):
        print(canonical(dict(status='ERROR',reason='CODE_ONLY_OPERATION_FAILED',operation_completed=False,**SCOPE)).decode());return 2
    print(canonical(result).decode());return 0
if __name__=='__main__':raise SystemExit(main())
