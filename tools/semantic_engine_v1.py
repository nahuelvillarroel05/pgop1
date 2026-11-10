"""Windows opt-in real-static-v2: generate, independently verify, recover/query."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).absolute().parents[1]
sys.path[:0] = [str(ROOT),str(ROOT/'runtime')]
from candidate.semantic_engine_v1 import RealStaticV2Profile
from tools.verify_source_v2 import cli_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog-sha256', required=True, help='Trusted external real-static-v2 catalog SHA256')
    sub = parser.add_subparsers(dest='operation',required=True)
    generate = sub.add_parser('generate')
    generate.add_argument('--source-root',required=True,type=cli_path)
    generate.add_argument('--catalog',required=True,type=cli_path)
    generate.add_argument('--output',required=True,type=cli_path)
    verify = sub.add_parser('verify'); verify.add_argument('--artifacts',required=True,type=cli_path)
    query = sub.add_parser('query'); query.add_argument('--artifacts',required=True,type=cli_path)
    query.add_argument('--kind',default='claims')
    query.add_argument('--source')
    query.add_argument('--offset',type=int,default=0); query.add_argument('--limit',type=int,default=50)
    args = parser.parse_args()
    try:
        profile = RealStaticV2Profile(source_root=getattr(args,'source_root',None),
                                      catalog_path=getattr(args,'catalog',None),catalog_sha256=args.catalog_sha256)
        if args.operation == 'generate':
            result = profile.generate(args.output)
        elif args.operation == 'verify':
            result = profile.verify(args.artifacts)
        else:
            result = profile.query(args.artifacts,kind=args.kind,source=args.source,offset=args.offset,limit=args.limit)
    except (OSError,ValueError,TypeError,KeyError,UnicodeError,RecursionError,MemoryError):
        print(json.dumps(dict(schema='pgop1.semantic-ack.v1',status='ERROR',
                              operation_completed=False,reason='SEMANTIC_OPERATION_FAILED',
                              source_current_at_ack='NOT_PROVEN',artifact_current_at_ack='NOT_PROVEN')))
        return 2
    print(json.dumps(result,sort_keys=True))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
