"""Opt-in Windows root discovery; emits an unadmitted catalog, never invokes E7."""
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).absolute().parents[1]
sys.path[:0]=[str(ROOT/'runtime'),str(ROOT)]
from candidate.discovery_contract_v1 import DiscoveryAuthority
from candidate.root_source_discovery_v1 import execute

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ['source-root','admission-policy','admission-policy-sha256','policy','policy-sha256',
                 'code-manifest','code-sha256','output']:
        p.add_argument('--'+name,required=True)
    p.add_argument('--scope',default='.');p.add_argument('--package-root',default='.')
    a=p.parse_args()
    authority=DiscoveryAuthority(a.source_root,a.admission_policy_sha256,a.policy_sha256,a.code_sha256,a.scope,a.package_root)
    try:
        receipt=execute(a.admission_policy,a.policy,a.code_manifest,a.output,authority)
        print(json.dumps(receipt,sort_keys=True))
        return 0 if receipt['status']=='CATALOG_DISCOVERED' else 2
    except (ValueError,OSError) as exc:
        print(json.dumps(dict(status='REJECTED',reason=getattr(exc,'code','DISCOVERY_FAILED'))),file=sys.stderr)
        return 1
if __name__=='__main__':sys.exit(main())
