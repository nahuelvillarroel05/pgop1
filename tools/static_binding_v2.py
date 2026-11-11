"""Analyze verified historical E3 bytes; canonical V2 report on stdout only."""
import argparse
from pathlib import Path
import sys
ROOT = Path(__file__).absolute().parents[1]
sys.path[:0] = [str(ROOT/'runtime'), str(ROOT)]
from candidate.code_contract_v1 import canonical


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', required=True)
    parser.add_argument('--catalog-sha256', required=True)
    parser.add_argument('--alias-limit', type=int, default=4096)
    args = parser.parse_args()
    try:
        from candidate.static_binding_v2 import analyze_bundle
        result = analyze_bundle(args.artifacts, args.catalog_sha256, alias_limit=args.alias_limit)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError, MemoryError):
        print(canonical(dict(status='ERROR', reason='STATIC_BINDING_ANALYSIS_FAILED')).decode())
        return 2
    print(canonical(result).decode())
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
