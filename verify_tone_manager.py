"""Verify K-3 II manager static data flow using an independently supplied image.

No firmware execution, runtime observation, or source listing export.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
from hashlib import sha256
import argparse,json,os,stat,struct,sys,tempfile

IMAGE_SIZE=16838656
IMAGE_SHA256='1b87bf35b290e4b4e8910beb4055c34f97504b65e249ad65e5ccc0402bd14cfc'
RANGES_SHA256='e2256737f2e77936a007f9220bd7d9f091e82364beb3d88424a4e8987941bb3c'
RESEARCH_CAPSTONE_VERSION='5.0.7'
RESEARCH_SOURCE_SHA256='b65c0a468c9469f37c3da26fe75b3c290e7ca70b60fb208fb52775f46f7a7b69'
RESEARCH_LISTING_SHA256='17e40759dcb2abad4d2f7186d433a6efc31316e12e6030a267f2b907ce456a14'
RESEARCH_SNAPSHOT_SHA256='bd2b718be32432eb0870d1a0aaf8b021414260fb5b1eee9cd2e68e054014e1f3'
RESEARCH_CANONICAL_SHA256='d706b05011c9de1a1d6f507771edc990f42472e1096f1d6994c26521b04c0bb7'

def require(value,expected,note):
    if value!=expected:raise ValueError(note)

def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode('ascii')

def read_image(path):
    require(stat.S_ISREG(path.stat().st_mode),True,'regular decoded file required')
    flags=os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NONBLOCK',0)
    with os.fdopen(os.open(path,flags),'rb') as f:
        require(stat.S_ISREG(os.fstat(f.fileno()).st_mode),True,'regular decoded descriptor required')
        data=f.read(IMAGE_SIZE+1)
    require(len(data),IMAGE_SIZE,'decoded size');require(sha256(data).hexdigest(),IMAGE_SHA256,'decoded SHA256')
    return data

def write_new(path,payload):
    require(os.path.lexists(path),False,'existing output or alias rejected')
    fd,name=tempfile.mkstemp(prefix='.tone-manager-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as f:f.write(payload);f.flush();os.fsync(f.fileno())
        os.link(name,path)
    finally:os.unlink(name)

def analyze(data,ranges):
    word=lambda a:struct.unpack_from('<I',data,a)[0]
    def branch(a,target):
        w=word(a);require((w>>25)&7,5,'A32 branch encoding');require(w>>28,14,'unconditional branch')
        delta=w&0xFFFFFF
        if delta&0x800000:delta-=0x1000000
        require(a+8+4*delta,target,'direct branch target')
        return dict(site=a,target=target,link=bool(w&0x1000000))
    def literal(a):
        w=word(a);require(w&0x0FFF0000,0x059F0000,'positive PC-relative LDR')
        address=a+8+(w&0xFFF)
        return dict(instruction=a,rom=address,value=word(address))
    branches=[branch(a,t) for a,t in [
      (0x4BDAC4,0x70D180),(0x4BDAC8,0x78591C),(0x4BDAF8,0x6EAD78),(0x4BDB1C,0x6EAEBC),(0x4BDB2C,0x6EB284),(0x4BDB3C,0x6EAF70),
      (0x4BF194,0x70D180),(0x4BF198,0x78591C),(0x4BF1C8,0x6EAD78),(0x4BF6A0,0x6EAEBC),(0x4BF6B0,0x6EB284),(0x4BF6C0,0x6EAF70),
      (0x6EAF98,0x719AE8),(0x719B04,0x7129D0),(0x6EAFB0,0x6EF248),(0x6EAFC4,0x70D180),(0x6EAFC8,0x73E08C),(0x6EAFD0,0x6992CC)]]
    literals=[literal(a) for a in [0x4BD838,0x4BDAF4,0x4BDB10,0x4BDB20,0x4BDB30,0x4BF170,0x4BF1C4,0x4BF694,0x4BF6A4,0x4BF6B4,0x70D1C0,0x6EB29C]]
    expect=[0x4040B9D8,0x40481A58,0x40481A58,0x40481A58,0x40481A58,0x4040B9D8,0x40481974,0x40481974,0x40481974,0x40481974,0x4047B754,0x029DEA90]
    require([r['value'] for r in literals],expect,'decoded literal identities')
    for a,w in [(0x4BDB34,0xE3A02000),(0x4BF6B8,0xE3A02000),(0x4BDB14,0xE3A02001),(0x4BF698,0xE3A02001),(0x719AF8,0xE3A02030),(0x78591C,0xE5900014)]:require(word(a),w,'argument and copy-width opcode')
    desc=[]
    for s in (0x1E,0x2B):
        a=0x9DEA90+8*s;offset,mask,shift,pad=struct.unpack_from('<IBBH',data,a)
        desc.append(dict(selector=s,record=a,offset=offset,mask=mask,shift=shift,destination_offset=offset+4,special_two_byte_path=s==0x1E))
    require([(r['offset'],r['mask'],r['shift']) for r in desc],[(0x20,255,0),(0x27,64,6)],'descriptor fields')
    derived=[]
    for old in [0,1,0x8000,0x8001,0xFFFFFFFF]:
        index=1&~old;busy=index|0x8000;reader_during=1&~busy
        derived.append(dict(supplied_symbolic_old=old,writer_index=index,busy_state=busy,reader_index_while_busy=reader_during,committed_state=index,not_executed=True))
    calls=[dict(callsite=0x4BDB3C,caller_entry=0x4BD7A4,cache_slot=0x4040BA28,cache_guard=0x4040BA24,scratch=0x40481A58,source_payload=[0x40481A5C,0x40481A8C],reader_call=0x4BDB1C,reader_r2=1,setter_call=0x4BDB2C,selector=0x2B,setter_argument=1,modified_offsets=[0x2B],setter_expression='byte(object+0x2B) = old_byte | 0x40',writer_r2=0),dict(callsite=0x4BF6C0,caller_entry=0x4BF134,cache_slot=0x4040B9F0,cache_guard=0x4040B9EC,scratch=0x40481974,source_payload=[0x40481978,0x404819A8],reader_call=0x4BF6A0,reader_r2=1,setter_call=0x4BF6B0,selector=0x1E,setter_argument='word(R5); inspected path at4BF580 sets R5=caller_object+0x6C80',modified_offsets=[0x24,0x25],setter_expression='object+0x24=(value>>8)&255; object+0x25=value&255',writer_r2=0)]
    return dict(schema='II-TONE-MANAGER-33-static-v1',input_sha256=IMAGE_SHA256,input_bytes=IMAGE_SIZE,capstone_version=RESEARCH_CAPSTONE_VERSION,source_ranges=ranges['spans'],direct_caller_budget=2,caller_depth=1,branches=branches,literals=literals,descriptors=desc,callers=calls,writer_order=[dict(pc=0x6EAF8C,action='manager+0x18 = (1 & ~old_state) | 0x8000'),dict(pc=0x6EAF98,action='copy 48-byte payload from incoming object+4 to selected member+4'),dict(pc=0x6EAF9C,action='manager+0x18 = new_index; only after copy helper returns'),dict(pc=0x6EAFB0,action='if manager+0x0C != 0 call6EF248; then zero manager+0x0C'),dict(pc=0x6EAFBC,action='saved entry R2==0 returns; nonzero continues to70D180,73E08C,tail6992CC')],symbolic_state_examples=derived,limits=['Static instruction order only, not execution, synchronization proof, observed reuse history or camera reachability.','Guarded cache producers return singleton4047B754+14 manager; actual initialized cache contents and guard success are not observed.','R2=0 disables only the final notification tail; it does not disable the separate manager+0x0C helper call.','Both selected setters modify other payload fields, not selector5/6 bytes object+15/+16. Existing payload values are copied; their earlier producers remain unresolved.','The immediate setter argument is word(R5); the inspected path sets R5=caller_object+6C80 at4BF580. No exhaustive caller CFG or alias-free intervening calls are proved.','All aligned A32 scan matches outside these two callers remain syntactic candidates. No exhaustive Thumb/indirect caller recovery or actual menu event attribution.'])

def read_regular(path,limit,label):
    require(stat.S_ISREG(path.stat().st_mode),True,label+' regular file required')
    flags=os.O_RDONLY|getattr(os,'O_BINARY',0)|getattr(os,'O_NONBLOCK',0)
    with os.fdopen(os.open(path,flags),'rb') as stream:
        require(stat.S_ISREG(os.fstat(stream.fileno()).st_mode),True,label+' regular descriptor required')
        data=stream.read(limit+1)
    require(len(data)<=limit,True,label+' exceeds bounded size')
    return data

def project_checked(snapshot):
    """Accept the complete historical record before attaching public metadata."""
    require(sha256(canonical(snapshot)).hexdigest(),RESEARCH_CANONICAL_SHA256,'complete II33 typed record identity')
    raw=(json.dumps(snapshot,indent=2)+'\n').encode()
    require(sha256(raw).hexdigest(),RESEARCH_SNAPSHOT_SHA256,'complete II33 serialized record identity')
    return snapshot

def check_decoder(data,ranges):
    """Optional original listing identity check in memory, after input validation."""
    require(len(data),IMAGE_SIZE,'decoded size before optional import')
    require(sha256(data).hexdigest(),IMAGE_SHA256,'decoded identity before optional import')
    import capstone
    require(capstone.__version__,RESEARCH_CAPSTONE_VERSION,'validated optional decoder version')
    md=capstone.Cs(capstone.CS_ARCH_ARM,capstone.CS_MODE_ARM);lines=[];count=0
    for r in ranges['spans']:
        x,z=r['start'],r['end_exclusive']
        lines.append(f"{r['kind']} {r['label']} [{x:08X},{z:08X}) {r['sha256']}")
        if r['kind']=='ARM':
            instructions=list(md.disasm(data[x:z],x))
            require(sum(i.size for i in instructions),z-x,'complete optional ARM decoding')
            for i in instructions:lines.append(f'{i.address:08X} {i.bytes.hex():8} {i.mnemonic:10} {i.op_str}')
            count+=len(instructions)
        else:lines.append(data[x:z].hex())
        lines.append('')
    require(count,312,'optional decoder instruction count')
    require(sha256(('\n'.join(lines)+'\n').encode()).hexdigest(),RESEARCH_LISTING_SHA256,'historical source listing identity')

PUBLIC_LIMITS=[
    'The complete II33 record, including original code/decoder/listing provenance, is checked before public metadata is added.',
    'callers and writer_order contain manual static interpretations checked against pinned original ranges; they are not automatically inferred execution traces.',
    'Default verification uses only Python standard-library checks of image, source ranges, branch words, literal words and descriptors. It does not import Capstone.',
    'capstone_version, decoded_instruction_count, reproduction_source_sha256 and source_listing_sha256 inside observations preserve historical II33 provenance.',
    'Optional Capstone checking re-creates the old listing in memory after exact image verification. No listing, firmware bytes or assets are exported.',
    'The two inputs are 48-byte internal parameter records, not pixel buffers. No menu reachability, actual capture order, concurrency safety or reuse history is established.',
]

def run(data,ranges,public_source_sha256,decoder_check=False):
    require(len(data),IMAGE_SIZE,'decoded size');require(sha256(data).hexdigest(),IMAGE_SHA256,'decoded identity')
    for r in ranges['spans']:
        x,z=r['start'],r['end_exclusive']
        require(0<=x<z<=len(data),True,'bounded original span')
        require(r['kind'] in ('ARM','DATA'),True,'classified source span')
        require(sha256(data[x:z]).hexdigest(),r['sha256'],'original span identity')
    snapshot=analyze(data,ranges)
    snapshot['decoded_instruction_count']=sum((r['end_exclusive']-r['start'])//4 for r in ranges['spans'] if r['kind']=='ARM')
    snapshot['reproduction_source_sha256']=RESEARCH_SOURCE_SHA256
    snapshot['range_manifest_sha256']=RANGES_SHA256
    snapshot['source_listing_sha256']=RESEARCH_LISTING_SHA256
    snapshot=project_checked(snapshot)
    if decoder_check:check_decoder(data,ranges)
    return dict(schema='k3ii-tone-manager-v1',accepted_research_snapshot_sha256=RESEARCH_SNAPSHOT_SHA256,accepted_research_canonical_sha256=RESEARCH_CANONICAL_SHA256,original_research_source_sha256=RESEARCH_SOURCE_SHA256,public_checker_sha256=public_source_sha256,range_manifest_sha256=RANGES_SHA256,capstone_rechecked=bool(decoder_check),manual_static_fields=['callers','writer_order','limits','descriptors.special_two_byte_path','symbolic_state_examples formula'],public_limits=PUBLIC_LIMITS,observations=snapshot)

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('decoded',type=Path,help='exact original decoded image, supplied separately')
    parser.add_argument('--output',type=Path,required=True,help='new JSON path; parent must exist')
    parser.add_argument('--compare',type=Path,help='regular JSON file capped at four times the generated payload size')
    parser.add_argument('--check-decoder',action='store_true',help='optionally import Capstone5.0.7 after exact input validation; no listing is exported')
    args=parser.parse_args(argv)
    require(os.path.lexists(args.output),False,'existing output or alias rejected')
    here=Path(__file__).resolve().parent
    raw=read_regular(here/'tools/tone_provenance/manager-ranges.json',65536,'range manifest').replace(b'\r\n',b'\n')
    require(sha256(raw).hexdigest(),RANGES_SHA256,'range manifest identity')
    ranges=json.loads(raw)
    source=read_regular(Path(__file__),131072,'checker source').replace(b'\r\n',b'\n')
    data=read_image(args.decoded)
    result=run(data,ranges,sha256(source).hexdigest(),args.check_decoder)
    payload=(json.dumps(result,ensure_ascii=False,indent=2)+'\n').encode()
    if args.compare:
        reference=json.loads(read_regular(args.compare,len(payload)*4,'compare'))
        require(canonical(result),canonical(reference),'complete typed public JSON mismatch')
    write_new(args.output,payload)
    print(json.dumps(dict(status='passed',bytes=len(payload),sha256=sha256(payload).hexdigest(),capstone_rechecked=args.check_decoder,firmware_executed=False)))

if __name__=='__main__':
    try:main()
    except (ValueError,OSError,ImportError) as error:
        print(str(error),file=sys.stderr)
        raise SystemExit(1)
