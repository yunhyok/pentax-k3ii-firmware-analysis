"""Replay twenty K-3 II recipe-scale cases and three embedded-input copies.

SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

MANIFEST_SHA256='4ee458eda62f059e75e072ff1093387b8167cd81f296d00d5042e1f556921444'
IMAGE_SHA256='1b87bf35b290e4b4e8910beb4055c34f97504b65e249ad65e5ccc0402bd14cfc'
IMAGE_SIZE=16838656
SCALE_CASES_SHA256='5c52f6208ab1ee433f988e0b771aa10dd0db21c620b4e8fc83da1aa7472750c0'
OWNERSHIP_CASES_SHA256='c49b4651e0e79e68265950e7e2b48b88e895e09831ad03ae20b2fcd910ca0b68'
RANGES_SHA256='7acc2193e6bec952c176a7507bbaee73cd184606185a4092b7e7de34611a82d1'

def require(actual,expected,note):
    if actual!=expected:raise ValueError(note)

def capture_sources(repository,candidate=None):
    """Capture all project bytes before executing even the pinned shared loader."""
    candidate=Path(candidate or Path(__file__).resolve().parent)
    raw=(candidate/'tools/tone_provenance/scale-sources.json').read_bytes().replace(b'\r\n',b'\n')
    require(sha256(raw).hexdigest(),MANIFEST_SHA256,'scale source manifest identity')
    manifest=json.loads(raw);captured={}
    for name,item in manifest['modules'].items():
        base=Path(repository) if item['location']=='repository' else candidate
        source=(base/item['path']).read_bytes().replace(b'\r\n',b'\n')
        require(sha256(source).hexdigest(),item['sha256'],'captured source '+name)
        captured[name]=(source,item['path'],item['sha256'])
    loader=manifest['loader'];loader_raw=(Path(repository)/loader['path']).read_bytes().replace(b'\r\n',b'\n')
    require(sha256(loader_raw).hexdigest(),loader['sha256'],'captured shared loader identity')
    item=manifest['ranges'];ranges_raw=(candidate/item['path']).read_bytes().replace(b'\r\n',b'\n')
    require(sha256(ranges_raw).hexdigest(),item['sha256'],'captured range manifest identity')
    return dict(modules=captured,loader=(loader_raw,loader['path'],loader['sha256']),ranges=json.loads(ranges_raw),range_sha256=item['sha256'])

def load_captured(captured):
    raw,path,pin=captured['loader']
    require(sha256(raw).hexdigest(),pin,'captured loader before execution')
    ns={'__name__':'captured_tone_provenance','__file__':path}
    exec(compile(raw,path,'exec',dont_inherit=True),ns)
    return ns,ns['load_captured'](captured['modules'])

def project_checked(scale_cases,ownership_cases,canonical):
    """Check complete typed observations before adding any new public metadata."""
    require(sha256(canonical(scale_cases)).hexdigest(),SCALE_CASES_SHA256,'complete II29 scale identity before publication')
    require(sha256(canonical(ownership_cases)).hexdigest(),OWNERSHIP_CASES_SHA256,'complete II29 ownership identity before publication')
    return scale_cases,ownership_cases

LIMITS=[
    'Separated scale entries preserve the original frame, with LR reset per entry; omitted classifier/config/selector services and unrelated recipe stores.',
    'R5, global magic/halfword and config0x53 response are fixtures. Original instructions produce R8 from the supplied RAM and response.',
    'The native setter can write 0 to recipe+0x9C. Low R8=0 stops before the Thumb2E0486 handler body; high R8=0 can complete a store of8192.',
    'The R6==0x4000 side store is static-only in these unchanged twenty cases. No additional review-only case is merged.',
    'The three ownership cases use separate VMs and prepared owner+220 pointers/source bytes. They do not establish capture ordering or buffer reuse.',
    'F154 reads unrelated SP+8; F188 replaces R1 from SP+18. No selector9 field provenance is inferred.',
    'No current shooting defaults, physical units, Q format, gamma, SuperResolution menu reach, boot or camera behavior are established.',
    'No firmware bytes/assets are distributed. The caller supplies the exact decoded input independently.',
]

def run(data,captured,shared,load):
    require(len(data),IMAGE_SIZE,'decoded input size');require(sha256(data).hexdigest(),IMAGE_SHA256,'decoded input identity')
    canonical=shared['canonical'];ranges=captured['ranges']
    require(sha256(canonical(ranges)).hexdigest(),RANGES_SHA256,'complete II29 source ranges')
    for r in ranges['scale_allowed']+ranges['ownership_allowed']+ranges['static']:
        require(0<=r['start']<r['end_exclusive']<=len(data),True,'bounded original source span')
        require(sha256(data[r['start']:r['end_exclusive']]).hexdigest(),r['sha256'],'original source span identity')
    scale=load('tone_scale');ownership=load('tone_ownership')
    require(scale.uc.__version__,'2.1.4','validated Unicorn version');require(ownership.uc.__version__,'2.1.4','validated Unicorn version')
    scale_cases=scale.run_cases(data,[(r['start'],r['end_exclusive']) for r in ranges['scale_allowed']])
    ownership_cases=ownership.run_cases(data)
    scale_cases,ownership_cases=project_checked(scale_cases,ownership_cases,canonical)
    return dict(schema='k3ii-tone-scale-v1',input_sha256=IMAGE_SHA256,input_bytes=IMAGE_SIZE,engine='Unicorn2.1.4',accepted_complete_scale_cases_sha256=SCALE_CASES_SHA256,accepted_complete_ownership_cases_sha256=OWNERSHIP_CASES_SHA256,source_manifest_sha256=MANIFEST_SHA256,shared_loader_sha256=captured['loader'][2],source_sha256={k:v[2] for k,v in captured['modules'].items()},range_manifest_sha256=captured['range_sha256'],source_ranges=ranges,limits=LIMITS,scale_cases=scale_cases,ownership_cases=ownership_cases)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('decoded',type=Path,help='exact 16,838,656-byte decoded image; size and full SHA-256 are enforced')
    parser.add_argument('--repository',type=Path,default=Path(__file__).resolve().parent,help='checkout with the existing pinned tone-provenance verifier and helpers')
    parser.add_argument('--output',type=Path,required=True,help='new JSON path; existing files, aliases and links are rejected')
    parser.add_argument('--compare',type=Path,help='compare complete typed public JSON before creating output')
    args=parser.parse_args(argv)
    require(os.path.lexists(args.output),False,'output already exists (including aliases or links)')
    captured=capture_sources(args.repository);shared,load=load_captured(captured)
    data=load('verify_tone_path').load_image(args.decoded)
    result=run(data,captured,shared,load)
    if args.compare:require(shared['canonical'](result),shared['canonical'](json.loads(args.compare.read_bytes())),'complete typed public JSON mismatch')
    payload=(json.dumps(result,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
    shared['write_new'](args.output,payload)
    print(json.dumps(dict(status='passed',scale_cases=len(result['scale_cases']),ownership_cases=len(result['ownership_cases']),bytes=len(payload),sha256=sha256(payload).hexdigest())))

if __name__=='__main__':
    try:main()
    except (ValueError,OSError) as error:
        print(str(error),file=sys.stderr)
        raise SystemExit(1)
