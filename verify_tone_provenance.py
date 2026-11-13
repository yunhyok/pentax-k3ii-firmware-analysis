"""Replay bounded tone provenance stages; never run a camera or patch firmware.

SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import builtins
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
from types import ModuleType

SOURCE_MANIFEST_SHA256 = 'd423ba10d254257e05837cb4520f11cd232b773c7149296c15cc982d39b94435'
IMAGE_SHA256 = '1b87bf35b290e4b4e8910beb4055c34f97504b65e249ad65e5ccc0402bd14cfc'
IMAGE_SIZE = 16838656
STAGE_PINS = dict(rom_producer='37d3399572710a1e0c85ac2ec28baf5790b7b35c9445c81b228ae9293bd0c499',context_producer='765834c96dc1cb340ecde4d8d298fb6523a4de9b70c0cfb277428a5027227bd8',shared_identity='7e50957fd65616761feee55ed30e7d5cff708be169f31d892551444f8f7dae70',conditional_copy='57ce6bb1e2b11b04ccea552c89b1c884ddef0c80ec803ae34200c015f85f07d8')

def require(actual, expected, note):
    if actual != expected:
        raise ValueError(f'{note}: expected {expected!r}, got {actual!r}')

def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')

def project_checked(name,cases,project,data):
    require(sha256(canonical(cases)).hexdigest(),STAGE_PINS[name],'accepted complete stage '+name)
    return [project(c,data) for c in cases]

def capture_sources(repository, candidate=None):
    """Capture every project source before executing any, with LF canonical hashes."""
    candidate = Path(candidate or Path(__file__).resolve().parent)
    manifest = (candidate/'tools/tone_provenance/sources.json').read_bytes().replace(b'\r\n', b'\n')
    require(sha256(manifest).hexdigest(), SOURCE_MANIFEST_SHA256, 'source manifest identity')
    pins = json.loads(manifest)
    captured = {}
    for name, item in pins.items():
        root = Path(repository) if item['location'] == 'repository' else candidate
        path = root/item['path']
        raw = path.read_bytes().replace(b'\r\n', b'\n')
        require(sha256(raw).hexdigest(), item['sha256'], 'captured source '+name)
        captured[name] = (raw, item['path'], item['sha256'])
    return captured

def load_captured(captured):
    """Local imports use this capture only: no project sys.modules or pyc lookup."""
    loaded = {}
    original_import = builtins.__import__
    def local_import(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in captured:
            return load(name)
        return original_import(name, globals, locals, fromlist, level)
    def load(name):
        if name not in loaded:
            raw, filename, expected = captured[name]
            require(sha256(raw).hexdigest(), expected, 'captured bytes before exec '+name)
            module = ModuleType(name)
            module.__file__ = filename
            module.__dict__['__builtins__'] = {**vars(builtins), '__import__': local_import}
            loaded[name] = module
            try:
                exec(compile(raw, filename, 'exec', dont_inherit=True), module.__dict__)
            except BaseException:
                loaded.pop(name, None)
                raise
        return loaded[name]
    return load

def code_ranges(case, data):
    spans = []
    for i in sorted(case.get('executed', []), key=lambda x: x['offset']):
        a, z = i['offset'], i['offset']+i['size']
        if spans and a <= spans[-1][1]:
            spans[-1][1] = max(z, spans[-1][1])
        else:
            spans.append([a, z])
    return [dict(start=a, end_exclusive=z, sha256=sha256(data[a:z]).hexdigest()) for a,z in spans]

def project_tone(c, data):
    if c.get('expected_failure'):
        return {k:c[k] for k in ('case','expected_failure','invalid_reads','pc_offset')}
    keys = ('case','curve','curve_sha256','minimum','maximum','monotone','cap_count','interpolation','expanded_sha256','expanded_min','expanded_max','negative_control','native_output_writes','segments','trace_sha256','mmio_accesses')
    out = {k:c[k] for k in keys}
    out['defaults'] = {k:v for k,v in c['defaults'].items() if k!='record_hex'}
    out['producer_calls'] = [dict(producer=x['producer'],parameters=list(struct.unpack('<7I',bytes.fromhex(x['params_hex']))),output=x['output']) for x in c['producer_calls']]
    if 'calculation' in c:
        out['calculation'] = c['calculation']
        out['context_result_stores'] = [w for w in c['upstream_writes'] if w['address']==0x10057A74]
    out['executed_range_hashes'] = code_ranges(c,data)
    return out

def project_identity(c, data):
    keys = ('delta','job','producer_command','tone_command','paired_tone_context','producer_fifth','constructor_halfwords','pair_writes','segments','prepared','invalid','paired_native_binding_identity_proven','actual_capture_history_proven')
    return {**{k:c[k] for k in keys},'executed_range_hashes':code_ranges(c,data)}

def project_copy(c, data):
    keys = ('name','job','command','source_context','destination_context','source_halfwords','before_halfwords','after_halfwords','copied','pointer_writes','copy_writes','segments','invalid','actual_capture_history_proven')
    out = {k:c[k] for k in keys}
    out['source_block_sha256'] = sha256(bytes.fromhex(c['source_block'])).hexdigest()
    out['after_block_sha256'] = sha256(bytes.fromhex(c['after_block'])).hexdigest()
    out['executed_range_hashes'] = code_ranges(c,data)
    return out

def run_stages(data, load):
    require(len(data), IMAGE_SIZE, 'decoded image size')
    require(sha256(data).hexdigest(), IMAGE_SHA256, 'decoded image identity')
    rom = load('tone_rom'); ctx = load('tone_context')
    require(rom.uc.__version__, '2.1.4', 'validated Unicorn version')
    rom_specs = [(('Natural',0),{'stress':True}),(('Bright',1),{}),(('Reversal_Film',6),{}),(('Bright_control_c4',1),{'control_c_override':4}),(('Natural_selector1',0),{'selector_override':1}),(('Reversal_selector1',6),{'selector_override':1}),(('Natural_context4096',0),{'scale':4096}),(('missing_startup_copy',0),{'boot':False})]
    rom_cases = project_checked('rom_producer',[rom.run_case(data,*args,**kw) for args,kw in rom_specs],project_tone,data)
    fixture = dict(flag92=0,flagA4=0,wordBC=3,word9C=8192,prior60DC=123,prior7A68=456,channels=[256,256,256,256])
    specs = [('native_8192',0,{}),('native_4096',0,{'word9C':16384}),('special_flag92',0,{'flag92':1}),('retain_context',0,{'flagA4':1,'prior60DC':4000,'prior7A68':8000,'channels':[128,256,512,1024]}),('clip_side_outputs',0,{'channels':[32,1024,2048,65535]}),('truncate_9C',0,{'word9C':0x12000}),('native_reversal',6,{}),('constructor_upstream',0,{'use_constructor':True})]
    contexts = project_checked('context_producer',[ctx.run_case(data,n,p,upstream={**fixture,**changes}) for n,p,changes in specs],project_tone,data)
    for i,j in ((0,0),(1,6),(6,2)):
        require(contexts[i]['curve'],rom_cases[j]['curve'],'context producer matches supplied-context stage')
    require([c['calculation']['result'] for c in contexts],[8192,4096,8192,68710,65536,8192,8192,8192],'context results')
    require(rom_cases[0]['curve'],rom_cases[3]['curve'],'neutralized control matches')
    require(rom_cases[0]['curve'],rom_cases[4]['curve'],'regular selector control')
    require(rom_cases[0]['curve'],rom_cases[5]['curve'],'special selector removed control')
    require(contexts[3]['curve'],contexts[4]['curve'],'different context integers can share capped curve')
    identity = load('tone_identity'); copy = load('tone_copy')
    identities = project_checked('shared_identity',[identity.replay(data,delta) for delta in (0,0x100000)],project_identity,data)
    copies = project_checked('conditional_copy',[copy.replay(data,n,**kw) for n,kw in [('constructor',{}),('varied',{'variant':True}),('relocated',{'delta':0x100000,'variant':True}),('guard80',{'variant':True,'gate80':1}),('guardbb',{'variant':True,'gatebb':0}),('null_reference',{'variant':True,'nullref':True})]],project_copy,data)
    return dict(rom_producer=rom_cases,context_producer=contexts,shared_identity=identities,conditional_copy=copies)

LIMITS = [
    'Separated original-code entries, prepared allocations/inputs, omitted services and allocators; no continuous capture or queue-order proof.',
    'Original context constructors and their values are not established capture defaults. Physical input/output domains, EV, Q format and gamma are unknown.',
    'Producer cap 0x4000 does not make every downstream kernel a universal saturator; synthetic FFFF control gives interpolator65535 and expander tail65535.',
    'Selector3 command job+2684 reference is job+26C0, correcting earlier job+225C. Native writer stores job+2730 at job+D828; selector4 copies into job+E608.',
    'Actual same-job scheduling, intervening overwrites, source-value history, pixel buffer reuse, SuperResolution menu reach and hardware output are unproven here.',
]

def reject_existing_output(path):
    if os.path.lexists(path):
        raise ValueError('output already exists (including aliases or links): '+str(path))

def write_new(path, payload):
    reject_existing_output(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(prefix='.tone-',dir=Path(path).parent,delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary,path)
    finally:
        if temporary is not None:
            temporary.unlink()

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('decoded',type=Path)
    parser.add_argument('--repository',type=Path,default=Path(__file__).resolve().parent,help='checkout containing the four pinned existing helper sources')
    parser.add_argument('--output',type=Path,required=True,help='new JSON path; existing paths/aliases/links are rejected')
    parser.add_argument('--compare',type=Path,help='compare semantic JSON before creating output')
    args = parser.parse_args(argv)
    reject_existing_output(args.output)
    captured = capture_sources(args.repository)
    load = load_captured(captured)
    data = load('verify_tone_path').load_image(args.decoded)
    result = dict(schema='k3ii-tone-provenance-v1',input_sha256=IMAGE_SHA256,input_bytes=IMAGE_SIZE,engine='Unicorn 2.1.4',source_sha256={k:v[2] for k,v in captured.items()},accepted_stage_sha256=STAGE_PINS,limits=LIMITS,stages=run_stages(data,load))
    if args.compare:
        require(canonical(result)==canonical(json.loads(args.compare.read_bytes())),True,'complete typed stage snapshot')
    payload = (json.dumps(result,ensure_ascii=False,indent=2)+'\n').encode('utf-8')
    write_new(args.output,payload)
    print(json.dumps(dict(status='passed',sha256=sha256(payload).hexdigest(),bytes=len(payload),cases={k:len(v) for k,v in result['stages'].items()})))

if __name__=='__main__':
    try:
        main()
    except (ValueError,OSError) as error:
        print(str(error),file=sys.stderr)
        raise SystemExit(1)
