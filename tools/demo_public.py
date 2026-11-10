"""Run the existing public API and recover its handoff through paginated reads."""
import argparse,json,sys
from pathlib import Path
ROOT=Path(__file__).absolute().parents[1]
sys.path.insert(0,str(ROOT/'runtime'))
from candidate.i7_api import public_profile

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,default=ROOT/'public-handoffs');a=p.parse_args()
    api=public_profile(output_root=a.output.absolute())
    q=api.query('RUN012_PUBLIC');v=api.verify('RUN012_PUBLIC')
    result=api.generate('RUN012_PUBLIC',v['receipt_id'],'public-example-001')
    pieces=[];offset=0
    while True:
        page=api.read(result['report_id'],offset=offset,limit=4000);pieces.append(page['content'])
        if page['next_offset'] is None:break
        offset=page['next_offset']
    folder=a.output.absolute()/result['report_id']
    assert ''.join(pieces)==(folder/'FINAL_HANDOFF.md').read_text('utf-8')
    print(json.dumps({'report':result,'verification':v['status'],'handoff':str(folder/'FINAL_HANDOFF.md'),'historical_result_declared':q['historical_result']}))
if __name__=='__main__':main()
