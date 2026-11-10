"""Opt-in CLI for trusted captured-report metadata; never admits native sources."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).absolute().parents[1] / 'runtime'))
from candidate.i7_api import source_audit_memory_v1
from candidate.public_handoff import checked
from candidate.source_audit_memory_v1 import MAX_REPORT_BYTES


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--memory-root', type=Path, required=True)
    sub = parser.add_subparsers(dest='operation', required=True)
    ingest = sub.add_parser('ingest', help='Import a trusted captured report, not its original sources')
    ingest.add_argument('--captured-report', type=Path, required=True)
    ingest.add_argument('--report-sha256', required=True)
    read = sub.add_parser('read')
    read.add_argument('--report-sha256', required=True)
    read.add_argument('--offset', type=int, default=0)
    read.add_argument('--limit', type=int, default=50)
    read.add_argument('--kind')
    args = parser.parse_args()
    try:
        memory = source_audit_memory_v1(memory_root=args.memory_root)
        if args.operation == 'ingest':
            # This is the preexisting trusted metadata path contract, explicitly
            # separate from descriptor-relative source admission in AST V2.
            with checked(args.captured_report).open('rb') as stream:
                raw = stream.read(MAX_REPORT_BYTES + 1)
            result = memory.ingest(raw, args.report_sha256)
        else:
            result = memory.read(args.report_sha256, offset=args.offset, limit=args.limit, kind=args.kind)
        print(json.dumps(result, sort_keys=True, ensure_ascii=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        print(json.dumps({'schema': 'pgop1.source-audit-memory.v1', 'status': 'ERROR',
                          'reason': 'INVALID_CAPTURED_REPORT_OR_MEMORY', 'authority_effect': 'NONE'}))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
