"""Independent historical snapshot verifier; imports no producer or Engine."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).absolute().parents[1]
sys.path.insert(0, str(ROOT))
from tools import verify_source_v2 as v

SCOPE = {'mode':'HISTORICAL_SNAPSHOT','source_current_at_ack':'NOT_PROVEN',
         'artifact_current_at_ack':'NOT_PROVEN',
         'origin_authentication':'CALLER_PIN_NOT_SIGNED_ATTESTATION',
         'continuous_retention':'NOT_PROVEN','atomic_multi_file_capture':'NOT_PROVEN'}
HANDOFF = (b'# Historical evidence snapshot v1\n\n'
           b'Content and derivation only. Source current at ACK: NOT_PROVEN.\n'
           b'No signed origin, continuous retention or atomic multi-file instant.\n'
           b'Manifest existence is not a successful ACK; require operation return.\n')
LIMITS = {'SNAPSHOT.json':36_000_000,'REPORT.json':512_000_000,'FINAL_HANDOFF.md':1_000_000}


def verify_values(report, snapshot, catalog_sha256):
    v.check_hash(catalog_sha256)
    v.require(isinstance(snapshot,dict) and set(snapshot)=={'schema','snapshot_id','captures','scope'}
              and snapshot['schema']=='pgop1.evidence-snapshot.v1' and snapshot['scope']==SCOPE,'SNAPSHOT_SCHEMA')
    pins = v.check_catalog(report['catalog'])
    v.require(v.digest(v.compact(report['catalog']))==catalog_sha256,'EXTERNAL_CATALOG_ANCHOR')
    rows=snapshot['captures']
    v.require(isinstance(rows,list) and len(rows)==len(pins),'CAPTURE_MEMBERSHIP')
    bodies={}; inventory=[]
    for row,pin in zip(rows, report['catalog']['sources']):
        v.require(isinstance(row,dict) and set(row)=={'path','sha256','bytes','raw_hex'},'CAPTURE_SCHEMA')
        v.require(row['path']==pin['path'] and row['sha256']==pin['sha256'] and
                  type(row['bytes']) is int and 0<=row['bytes']<=262144 and
                  isinstance(row['raw_hex'],str) and len(row['raw_hex'])==2*row['bytes'],'CAPTURE_PIN')
        raw=bytes.fromhex(row['raw_hex'])
        v.require(raw.hex()==row['raw_hex'] and len(raw)==row['bytes'] and v.digest(raw)==pin['sha256'],'CAPTURE_BYTES')
        bodies[row['path']]=raw; inventory.append({k:row[k] for k in ('path','sha256','bytes')})
    expected_id=v.digest(v.compact({'schema':'pgop1.evidence-snapshot.v1','inventory':inventory}))
    v.require(snapshot['snapshot_id']==expected_id,'SNAPSHOT_ID')
    derived=v.verify_document_audit(None,report,captured=bodies)
    v.require(not derived['source_errors'] and derived['source_integrity']=='PASS','CAPTURE_DERIVATION')
    # Legacy PASS is scoped to recomputation from captured bytes, never currency.
    derived.pop('status'); derived.pop('source_integrity')
    result={'schema':'pgop1.evidence-snapshot-verification.v1','status':'SNAPSHOT_VERIFIED',
            'verification_scope':'HISTORICAL_CAPTURE_CONTENT_AND_DERIVATION',
            'snapshot_id':expected_id,'catalog_sha256':catalog_sha256,
            'source_current_at_ack':'NOT_PROVEN','source_observation':'NOT_REQUESTED',
            'artifact_current_at_ack':'NOT_PROVEN',
            'origin_authentication':'CALLER_PIN_NOT_SIGNED_ATTESTATION',
            'continuous_retention':'NOT_PROVEN','artifact_record':'CONTENT_ONLY_ACK_REQUIRED',
            'derivation':derived}
    return result


def verify_bundle(folder, catalog_sha256, *, source_root=None):
    manifest_raw=v.read_source(folder,'MANIFEST.json',None,1_000_000)
    manifest=v.strict(manifest_raw)
    v.require(isinstance(manifest,dict) and set(manifest)=={'schema','catalog_sha256','snapshot_id','files'}
              and manifest['schema']=='pgop1.evidence-snapshot-manifest.v1'
              and manifest['catalog_sha256']==catalog_sha256 and isinstance(manifest['files'],dict)
              and set(manifest['files'])==set(LIMITS),'MANIFEST_SCHEMA')
    files={}
    for name,limit in LIMITS.items():
        pin=manifest['files'][name]
        v.require(isinstance(pin,dict) and set(pin)=={'sha256','bytes'} and type(pin['bytes']) is int
                  and 0<=pin['bytes']<=limit,'ARTIFACT_PIN')
        v.check_hash(pin['sha256'])
        raw=v.read_source(folder,name,pin['sha256'],limit)
        v.require(len(raw)==pin['bytes'],'ARTIFACT_LENGTH');files[name]=raw
    v.require(files['FINAL_HANDOFF.md']==HANDOFF,'HANDOFF_SCOPE')
    report=v.strict(files['REPORT.json']); snapshot=v.strict(files['SNAPSHOT.json'])
    result=verify_values(report,snapshot,catalog_sha256)
    v.require(manifest['snapshot_id']==result['snapshot_id'],'MANIFEST_SNAPSHOT')
    result['manifest_sha256']=v.digest(manifest_raw)
    if source_root is not None:
        observations=[]
        for pin in report['catalog']['sources']:
            try:
                raw=v.read_source(source_root,pin['path'],None)
                observed=v.digest(raw)
                row=dict(path=pin['path'],status='MATCH' if observed==pin['sha256'] else 'MISMATCH',
                         observed_sha256=observed,bytes=len(raw))
            except (OSError,ValueError) as exc:
                code=getattr(exc,'code',str(exc))
                status={'SOURCE_CHANGED':'CHANGED','SOURCE_READ_FAILED':'READ_FAILED'}.get(code,'UNAVAILABLE_OR_UNSAFE')
                row=dict(path=pin['path'],status=status)
            observations.append(row)
        result['source_observation']={'scope':'POINT_OBSERVATIONS_NOT_INVARIANCE', 'files':observations}
    return result


def execute(args):
    try:
        if args.mode!='HISTORICAL_SNAPSHOT':
            raise ValueError('SOURCE_CURRENT_AT_ACK_NOT_PROVEN')
        with ExitStack() as transaction:
            held=[]
            if os.name=='nt':
                from candidate.windows_safe_io_v2 import Directory, absolute, reject_membership
                for path in (args.artifacts, ROOT, args.source_root):
                    if path is not None:held.append(transaction.enter_context(Directory(path)))
                if args.output:
                    drive,parts=absolute(args.output)
                    if not parts:raise ValueError('UNSAFE_PATH')
                    parent=transaction.enter_context(Directory(drive+'\\'.join(parts[:-1])))
                    for protected in held:reject_membership(parent,protected)
                    held.append(parent)
            result=verify_bundle(args.artifacts,args.catalog_sha256,source_root=args.source_root)
            for directory in held:directory.validate()
            if args.output:
                v._write_verification(args.output,args.source_root or args.artifacts,
                    json.dumps(result,sort_keys=True)+'\n',artifacts=args.artifacts)
            for directory in held:directory.validate()
        result['operation_completed']=True
    except (OSError,ValueError,TypeError,KeyError,UnicodeError,RecursionError,MemoryError) as exc:
        reason='SOURCE_CURRENT_AT_ACK_NOT_PROVEN' if str(exc)=='SOURCE_CURRENT_AT_ACK_NOT_PROVEN' else 'SNAPSHOT_VERIFICATION_FAILED'
        result={'schema':'pgop1.evidence-snapshot-verification.v1','status':'ERROR','reason':reason,
                'source_current_at_ack':'NOT_PROVEN','operation_completed':False}
    print(json.dumps(result,sort_keys=True))
    return 0 if result['status']=='SNAPSHOT_VERIFIED' else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts',type=v.cli_path,required=True)
    parser.add_argument('--catalog-sha256',required=True,help='Trusted external canonical catalog SHA256; never copy from attacked bundle')
    parser.add_argument('--source-root',type=v.cli_path,help='Optional point comparison; no invariance claim')
    parser.add_argument('--output',type=v.cli_path)
    parser.add_argument('--mode',choices=('HISTORICAL_SNAPSHOT','CURRENT_AT_ACK'),default='HISTORICAL_SNAPSHOT')
    return execute(parser.parse_args())


if __name__=='__main__':
    raise SystemExit(main())
