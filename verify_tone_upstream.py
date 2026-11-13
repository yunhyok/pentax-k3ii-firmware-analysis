"""Replay seven K-3 II upstream cases and four zero-consumer boundaries.

SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import stat

MANIFEST_SHA256='e2273e47cea6350aa8c5179298130b50ecb779e157f2b7e812701bd27d7233f6'
IMAGE_SHA256='1b87bf35b290e4b4e8910beb4055c34f97504b65e249ad65e5ccc0402bd14cfc'
IMAGE_SIZE=16838656
RESEARCH_SNAPSHOT_SHA256='a3f4509f2dc1c3fd34e21364e7b7290599ab2ace8613cb5663de66183c16dc27'
RESEARCH_CANONICAL_SHA256='998129ae85301db78e38e0a0e2055ec01a6f5eef9e02125224ac5a7395c17bdf'
RANGES_SHA256='d2e543c956c81e5b819fe4d7e9c1adab76853595f4fcdb037749f55cebe8e230'

def require(actual,expected,note):
    if actual!=expected:raise ValueError(note)

def capture_sources(repository,candidate=None):
    """Capture all project bytes before executing even the pinned shared loader."""
    candidate=Path(candidate or Path(__file__).resolve().parent)
    raw=(candidate/'tools/tone_provenance/upstream-sources.json').read_bytes().replace(b'\r\n',b'\n')
    require(sha256(raw).hexdigest(),MANIFEST_SHA256,'upstream source manifest identity')
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

def project_checked(snapshot,canonical):
    """Validate all original fields before adding public provenance metadata."""
    require(sha256(canonical(snapshot)).hexdigest(),RESEARCH_CANONICAL_SHA256,'complete II31 typed observation identity before publication')
    raw=(json.dumps(snapshot,indent=2)+'\n').encode('utf-8')
    require(sha256(raw).hexdigest(),RESEARCH_SNAPSHOT_SHA256,'complete II31 serialized snapshot identity before publication')
    return snapshot

LIMITS=[
    'All original II31 metadata and seven upstream plus four consumer observations are checked before public metadata is added.',
    'Original probe_sha256 identifies the frozen research script; public_source_sha256 identifies the separate portable helper.',
    'The 43 upstream and 30 config source windows are static address/hash records, not executed paths or firmware bytes.',
    'Config file reading, token conversion, TLS/error state, actual buffer ordering and the Thumb zero-handler body are not executed.',
    'job+52 and setter arguments are fixtures. Optional arithmetic is entered directly; no capture predicate is established.',
    'No physical units, Q format, gamma, actual capture defaults, buffer reuse or SuperResolution menu reach are established.',
    'The exact decoded firmware must be supplied independently. Camera, boot and hardware behavior are not tested.',
]

def run(data,captured,shared,load):
    require(len(data),IMAGE_SIZE,'decoded input size')
    require(sha256(data).hexdigest(),IMAGE_SHA256,'decoded input identity')
    canonical=shared['canonical'];ranges=captured['ranges']
    require(sha256(canonical(ranges)).hexdigest(),RANGES_SHA256,'complete II31 source ranges')
    for r in ranges['allowed']+ranges['static']+ranges['config_static']:
        require(0<=r['start']<r['end_exclusive']<=len(data),True,'bounded original source span')
        require(sha256(data[r['start']:r['end_exclusive']]).hexdigest(),r['sha256'],'original source span identity')
    upstream=load('tone_upstream')
    require(upstream.uc.__version__,'2.1.4','validated Unicorn version')
    snapshot=upstream.run_snapshot(data,[(r['start'],r['end_exclusive']) for r in ranges['allowed']])
    snapshot=project_checked(snapshot,canonical)
    return dict(schema='k3ii-tone-upstream-v1',input_sha256=IMAGE_SHA256,input_bytes=IMAGE_SIZE,engine='Unicorn2.1.4',accepted_research_snapshot_sha256=RESEARCH_SNAPSHOT_SHA256,accepted_research_canonical_sha256=RESEARCH_CANONICAL_SHA256,original_research_probe_sha256=snapshot['probe_sha256'],public_source_sha256=captured['modules']['tone_upstream'][2],source_manifest_sha256=MANIFEST_SHA256,shared_loader_sha256=captured['loader'][2],source_sha256={k:v[2] for k,v in captured['modules'].items()},range_manifest_sha256=captured['range_sha256'],source_ranges=ranges,limits=LIMITS,observations=snapshot)

def capture_image(path):
    require(stat.S_ISREG(path.stat().st_mode),True,'decoded regular file required')
    flags=os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NONBLOCK',0)
    with os.fdopen(os.open(path,flags),'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),True,'decoded regular file required')
        data=stream.read(IMAGE_SIZE+1)
    require(len(data),IMAGE_SIZE,'decoded length')
    require(sha256(data).hexdigest(),IMAGE_SHA256,'decoded identity')
    return data

def capture_compare(path,limit):
    require(stat.S_ISREG(path.stat().st_mode),True,'compare regular file required')
    flags=os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NONBLOCK',0)
    with os.fdopen(os.open(path,flags),'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),True,'compare regular file required')
        data=stream.read(limit+1)
    require(len(data)<=limit,True,'compare exceeds four times the serialized result size')
    return json.loads(data)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('decoded',type=Path,help='exact decoded image; size and full SHA-256 are enforced')
    parser.add_argument('--repository',type=Path,default=Path(__file__).resolve().parent,help='checkout with the pinned shared verifier and helpers')
    parser.add_argument('--output',type=Path,required=True,help='new JSON path; existing files, aliases and links are rejected')
    parser.add_argument('--compare',type=Path,help='compare typed JSON from a regular file, limited to four times the serialized result size')
    args=parser.parse_args(argv)
    require(os.path.lexists(args.output),False,'output already exists (including aliases or links)')
    captured=capture_sources(args.repository);shared,load=load_captured(captured)
    data=capture_image(args.decoded)
    result=run(data,captured,shared,load)
    payload=(json.dumps(result,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
    if args.compare:require(shared['canonical'](result),shared['canonical'](capture_compare(args.compare,len(payload)*4)),'complete typed public JSON mismatch')
    shared['write_new'](args.output,payload)
    print(json.dumps(dict(status='passed',upstream_cases=len(result['observations']['upstream']),zero_cases=len(result['observations']['zero_consumers']),bytes=len(payload),sha256=sha256(payload).hexdigest())))

if __name__=='__main__':
    try:main()
    except (ValueError,OSError) as error:
        print(str(error),file=sys.stderr)
        raise SystemExit(1)
