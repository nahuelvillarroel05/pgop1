"""Create only fresh inert synthetic demonstrations, using the registered service."""
import argparse
import json
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'runtime'),str(ROOT/'tests')]
from evidence_fixtures import setup
from candidate.public_handoff import encoded,sha
from candidate.evidence_handoff import EvidenceProfile

def main():
    parser=argparse.ArgumentParser();parser.add_argument('output',type=Path)
    base=parser.parse_args().output.absolute();base.mkdir(parents=True,exist_ok=False)
    results={}
    for label,kw in [('MULTISOURCE',{}),('SOURCE_ONLY',{'code':{'calculadora.py':'def sumar(a,b):\n    return a-b\n'},'claims':[{'source':'calculadora.py','kind':'return_binop','function':'sumar','operator':'Add'},{'source':'calculadora.py','kind':'behavior'}]})]:
        api,_=setup(base/label,**kw);receipt=api.verify('FIXTURE')
        generated=api.generate('FIXTURE',receipt['receipt_id'],'synthetic-demo-'+label.lower())
        results[label]={'catalog_root':str(api.catalog_path.parent),'output_root':str(api.out),'report':generated,
                        'receipt_id':receipt['receipt_id'],'handoff':str(api.out/generated['report_id']/'FINAL_HANDOFF.md')}
    (base/'DEMO_RESULTS.json').write_bytes(encoded(results));print(json.dumps(results,indent=2))

if __name__=='__main__':main()
