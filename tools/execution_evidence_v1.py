"""Explicit opt-in CLI. No catalog-supplied command execution."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).absolute().parents[1]
sys.path[:0]=[str(ROOT),str(ROOT/'runtime')]
from candidate.windows_safe_io_v2 import absolute

def path(value):absolute(value);return Path(value)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--catalog-sha256',required=True)
    sub=p.add_subparsers(dest='operation',required=True)
    run=sub.add_parser('run');run.add_argument('--source-root',type=path,required=True)
    run.add_argument('--catalog',type=path,required=True);run.add_argument('--output',type=path,required=True)
    run.add_argument('--request-id',required=True)
    for name in ('verify','query'):
        q=sub.add_parser(name);q.add_argument('--artifacts',type=path,required=True)
        q.add_argument('--trusted-run-sha256',required=True);q.add_argument('--request-id',required=True)
        if name=='query':q.add_argument('--offset',type=int,default=0);q.add_argument('--limit',type=int,default=50)
    args=p.parse_args()
    try:
        if args.operation=='run':
            from candidate.execution_evidence_v1 import ExecutionEvidenceRunner
            result=ExecutionEvidenceRunner(source_root=args.source_root,catalog_path=args.catalog,catalog_sha256=args.catalog_sha256).run(args.output,request_id=args.request_id)
        else:
            from tools.verify_execution_evidence_v1 import verify_bundle,query_bundle
            values=(args.artifacts,args.catalog_sha256,args.trusted_run_sha256,args.request_id)
            if args.operation=='query':result=query_bundle(*values,offset=args.offset,limit=args.limit)
            else:
                envelope,rows=verify_bundle(*values)
                result=dict(status='HISTORICAL_PACKET_VERIFIED',integration_id=envelope['integration_id'],claims=envelope['claims'],engine_observations=len(rows),scope=envelope['scope'])
        print(json.dumps(result,sort_keys=True));return 0
    except (ValueError,OSError,KeyError,TypeError) as exc:
        print(json.dumps(dict(status='REJECTED',reason=str(exc))),file=sys.stderr);return 2

if __name__=='__main__':sys.exit(main())
