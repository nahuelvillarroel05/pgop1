"""Opt-in Windows claim coverage. No change to the six public MCP tools."""
import argparse
import json
from pathlib import Path
import sys
ROOT = Path(__file__).absolute().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'runtime')]
from candidate.claim_coverage_v2 import ClaimCoverageProfile
from tools.verify_source_v2 import cli_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--catalog-sha256', required=True)
    commands = parser.add_subparsers(dest='operation', required=True)
    generate = commands.add_parser('generate')
    for name in ('source-root', 'catalog', 'output'): generate.add_argument('--'+name, type=cli_path, required=True)
    for name in ('verify', 'query'):
        command = commands.add_parser(name); command.add_argument('--artifacts', type=cli_path, required=True)
        if name == 'query':
            command.add_argument('--offset', type=int, default=0); command.add_argument('--limit', type=int, default=50)
    args = parser.parse_args()
    profile = ClaimCoverageProfile(source_root=getattr(args, 'source_root', None), catalog_path=getattr(args, 'catalog', None), catalog_sha256=args.catalog_sha256)
    try:
        if args.operation == 'generate': result = profile.generate(args.output)
        elif args.operation == 'verify': result = profile.verify(args.artifacts)
        else: result = profile.query(args.artifacts, offset=args.offset, limit=args.limit)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, MemoryError, RecursionError):
        print(json.dumps(dict(status='ERROR', operation_completed=False, reason='COVERAGE_OPERATION_FAILED'))); return 2
    print(json.dumps(result, sort_keys=True)); return 0


if __name__ == '__main__': raise SystemExit(main())
