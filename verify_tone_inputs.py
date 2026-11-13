"""Replay eight bounded K-3 II tone-input cases from one pinned decoded image.

SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
import sys

MANIFEST_SHA256='ed928e2480d2d48ff10e8cc1b473392af769a9900d30e580a98b87a1acf161fd'
IMAGE_SHA256='1b87bf35b290e4b4e8910beb4055c34f97504b65e249ad65e5ccc0402bd14cfc'
IMAGE_SIZE=16838656
CASES_SHA256='61e819bd5300c37259b03b31d46b5df225b8cd5ce5636082472f01b7fc55767a'
ALLOWED_SHA256='e9e0fcc52da2060fe2df8b7c70ca389e2365e7c7c8e979c5dc12672eca62d5e9'

def require(actual,expected,note):
    if actual!=expected:raise ValueError(note)

def capture_sources(repository,candidate=None):
    """Capture all project bytes before executing even the pinned shared loader."""
    candidate=Path(candidate or Path(__file__).resolve().parent)
    raw=(candidate/'tools/tone_provenance/inputs-sources.json').read_bytes().replace(b'\r\n',b'\n')
    require(sha256(raw).hexdigest(),MANIFEST_SHA256,'input source manifest identity')
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

def project_checked(cases,canonical):
    """Complete typed observations must match before dropping any repeated event."""
    require(sha256(canonical(cases)).hexdigest(),CASES_SHA256,'complete II27 case identity before projection')
    projected=[]
    for c in cases:
        out={k:c[k] for k in ('name','job','recipe','context','constructor','inputs','producer_fixture','prepared','calculation','segments','formula_writes','instruction_counts','trace_sha256','executed_range_hashes','invalid','actual_capture_history_proven')}
        writes=c['writes'];context=c['context'];recipe=c['recipe']
        out['write_events']=dict(count=len(writes),canonical_sha256=sha256(canonical(writes)).hexdigest(),phase_counts=dict(sorted(Counter(w['phase'] for w in writes).items())))
        out['constructor_context_stores']=[w for w in writes if w['phase']=='constructors' and w['address'] in [context+i for i in (8,10,12,14,0x60DC,0x7A68)]]
        out['constructor_recipe_stores']=[w for w in writes if w['phase']=='constructors' and w['address'] in [recipe+i for i in (0x92,0xA4,0xBC,0x9C)]]
        out['recipe_producer_stores']=[w for w in writes if w['phase']=='recipe_producer' and recipe<=w['address']<recipe+0x104]
        require(len(out['constructor_context_stores']),6,'six native context constructor stores per case')
        require(len(out['constructor_recipe_stores']),4,'four native recipe constructor stores per case')
        projected.append(out)
    return projected

LIMITS=[
    'Separated original-code entries and prepared upstream job fields; omitted classifier/middle services. No continuous capture or scheduling proof.',
    'Original constructor values are not established current shooting defaults. Four halfwords have no proven physical channel assignment.',
    'Recipe+A4 is copied from job+2080; any nonzero byte retains context+7A68/+60DC in this bounded consumer.',
    'Later recipe+92 and+9C producers are static only. Configuration IDs are hexadecimal0x42/0x53. Their live values remain unknown.',
    'Endpoint is context+7A74 and getter4FA83C. No tone-curve rerun, SuperResolution reach, buffer reuse, motor, boot or hardware proof.',
    'No firmware bytes/assets are included. The caller supplies the exact decoded input independently.',
]

def run(data,captured,shared,load):
    require(len(data),IMAGE_SIZE,'decoded input size');require(sha256(data).hexdigest(),IMAGE_SHA256,'decoded input identity')
    canonical=shared['canonical'];ranges=captured['ranges']
    require(sha256(canonical(ranges['allowed'])).hexdigest(),ALLOWED_SHA256,'complete II27 allowed ranges')
    for r in ranges['allowed']+ranges['static']:
        require(0<=r['start']<r['end_exclusive']<=len(data),True,'bounded input source span')
        require(sha256(data[r['start']:r['end_exclusive']]).hexdigest(),r['sha256'],'original source span identity')
    module=load('tone_inputs');require(module.uc.__version__,'2.1.4','validated Unicorn version')
    cases=module.run_cases(data,[(r['start'],r['end_exclusive']) for r in ranges['allowed']])
    compact=project_checked(cases,canonical)
    return dict(schema='k3ii-tone-inputs-v1',input_sha256=IMAGE_SHA256,input_bytes=IMAGE_SIZE,engine='Unicorn2.1.4',accepted_complete_cases_sha256=CASES_SHA256,source_manifest_sha256=MANIFEST_SHA256,shared_loader_sha256=captured['loader'][2],source_sha256={k:v[2] for k,v in captured['modules'].items()},range_manifest_sha256=captured['range_sha256'],allowed_range_hashes=ranges['allowed'],static_source_windows=ranges['static'],limits=LIMITS,cases=compact)

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
    print(json.dumps(dict(status='passed',cases=len(result['cases']),constructor_context_stores=sum(len(c['constructor_context_stores']) for c in result['cases']),bytes=len(payload),sha256=sha256(payload).hexdigest())))

if __name__=='__main__':
    try:main()
    except (ValueError,OSError) as error:
        print(str(error),file=sys.stderr)
        raise SystemExit(1)
