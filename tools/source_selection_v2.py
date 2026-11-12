"""Opt-in V2 source selection with mandatory externally pinned owner admission."""
import argparse
import json
from pathlib import Path
import sys
ROOT = Path(__file__).absolute().parents[1]
sys.path[:0] = [str(ROOT / 'runtime'), str(ROOT)]

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('source-root', 'catalog', 'catalog-sha256', 'policy', 'policy-sha256',
                'admission-policy', 'admission-policy-sha256', 'code-manifest', 'code-sha256', 'output'):
        parser.add_argument('--' + key, required=True)
    a = parser.parse_args()
    try:
        from candidate.admission_contract_v2 import AuthorityContext
        from candidate.source_selection_v2 import execute
        authority = AuthorityContext(a.source_root, a.catalog_sha256, a.policy_sha256,
                                     a.admission_policy_sha256, a.code_sha256)
        result = execute(a.catalog, a.policy, a.admission_policy, a.code_manifest, a.output, authority)
    except (OSError, ValueError, TypeError, KeyError, MemoryError, RecursionError):
        exc = sys.exception()
        reason = getattr(exc, 'code', None) or (str(exc) if type(exc) is ValueError else 'V2_INPUT_OR_IO_ERROR')
        print(json.dumps(dict(status='ERROR', reason=reason, operation_completed=False))); return 2
    print(json.dumps(result, sort_keys=True)); return 0
if __name__ == '__main__':
    raise SystemExit(main())