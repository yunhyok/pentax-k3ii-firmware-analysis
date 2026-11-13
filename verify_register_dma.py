"""Replay K-3 II register readout and DMA preparation as separate bounded tests.

SPDX-License-Identifier: GPL-2.0-only
Supplied MMIO snapshots are not hardware output. DMA preparation stops before MMIO.
"""
if not __debug__:
    raise RuntimeError("Assertions required; -O unsupported")

import argparse
from collections import Counter
from hashlib import sha256
import json
import os
from pathlib import Path
from struct import pack
import sys
from types import ModuleType

ROOT = Path(__file__).resolve().parent
DECODED_SIZE = 16838656
DECODED_SHA = "1b87bf35b290e4b4e8910beb4055c34f97504b65e249ad65e5ccc0402bd14cfc"
DEPENDENCIES = {
    "inspect_firmware.py": "5813ab545e4c5bd14b9c52b47e0c0af4ad34e3ca06aa7c843d9cd3a2238cf871",
    "verify_findings.py": "9086a9ec89aee7932799353278e1c666d8defc9e55d3c72923388d555fec7a41",
    "verify_tone_path.py": "b1c01007af2dd921077289d05204a6c846ea57059f0aceda6c5101149358f344",
}

def require(actual, expected, context):
    if actual != expected:
        raise ValueError(f"{context}: expected {expected!r}, got {actual!r}")

def pinned_sources():
    sources = {}
    for name, expected in DEPENDENCIES.items():
        path = ROOT / name
        source = path.read_bytes().replace(b"\r\n", b"\n")
        if sha256(source).hexdigest() != expected:
            raise ValueError(f"Dependency SHA-256 mismatch: {name}")
        sources[path] = source
    return sources

def load_dependencies():
    sources = pinned_sources()
    for path, source in sources.items():
        module = ModuleType(path.stem)
        module.__file__ = str(path)
        # Execute checked source bytes, never cached bytecode.
        exec(compile(source, module.__file__, "exec"), module.__dict__)
        sys.modules[path.stem] = module
    return sys.modules["verify_tone_path"]

def read_decoded(path):
    if not path.is_file() or path.stat().st_size != DECODED_SIZE:
        raise ValueError(f"Original decoded carrier of {DECODED_SIZE:,} bytes is required")
    tone = load_dependencies()
    try:
        return tone.load_image(path)
    except ValueError as error:
        raise ValueError("Decoded input SHA-256 or size mismatch") from error

def canonical_sha256(value):
    return sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
                             separators=(",", ":")).encode()).hexdigest()

def verify_projection(payload, expected_digest, label):
    actual = canonical_sha256(payload)
    require(actual, expected_digest, f"{label} full evidence SHA-256")
    return actual

EVIDENCE_SHA = {'register_readout': '7a517f593a4eb6baa8c9fb48b5cf7f94e42e995e2b8d10d74ed04e6f20c75fde', 'dma_preparation': '2af9346b533ee1d43a383ea73d5a14a6e5c57e9c5ec56fae9f91bccd52128823'}
CODE_RANGES = {
    'register_readout': [
    (0x755CD4,0x755CD8),(0x755D50,0x755D6C),(0x4E61E4,0x4E61EC),
    (0x72077C,0x720854),(0x7196EC,0x719758),(0x71C370,0x71C378),
    (0x56B478,0x56B480),(0x71C14C,0x71C154),(0x54CA2C,0x54CA34),
    (0x71C124,0x71C134),(0x597CF0,0x597D00),
    (0x6C58E4,0x6C5914),(0x6C5944,0x6C5978),(0x6C59A8,0x6C5A3C),
    (0x4E1DC0,0x4E1DCC),(0x6C5848,0x6C58E4),(0x4E1934,0x4E196C),
    (0x4E2EE4,0x4E2EF4),(0x4E6240,0x4E6280),(0x4E6290,0x4E62A4),
    (0x4E62B4,0x4E62C8),(0x4E62D8,0x4E6300),(0x4E6320,0x4E6360),
    (0x722140,0x7221E4),(0x72D7A4,0x72D7AC),(0x73E0F4,0x73E0FC),
    (0x71ADF0,0x71ADF8),(0x71BDBC,0x71BDCC),(0x71A634,0x71A654),
],
    'dma_preparation': [
 (0x74E5D4,0x74E8A8),(0x754B5C,0x754B64),(0x74EBF0,0x74ECBC),
 (0x72E1E0,0x72E1E8),(0x72E0E4,0x72E0EC),(0x72DFC8,0x72DFD0),(0x72DECC,0x72DED4),(0x754B4C,0x754B54),
 (0x755CD4,0x755CD8),(0x755FDC,0x755FFC),(0x71DBD8,0x71DBE0),
 (0x6C087C,0x6C089C),(0x754720,0x75472C),
 (0x754970,0x754A54),(0x72D09C,0x72D144),(0x72D510,0x72D52C),
 (0x6352A0,0x6352B0),(0x6352D4,0x6352DC),(0x63542C,0x63545C),(0x635488,0x6354A0),
 (0x74F92C,0x74F944),(0x754CBC,0x754CC4),(0x754920,0x754930),
 (0x74F9A4,0x74F9BC),(0x754CCC,0x754CD4),(0x71AE08,0x71AE10),
 (0x635528,0x635534),(0x63495C,0x634970),(0x634D88,0x634D94),(0x72D364,0x72D36C),
 (0x634F68,0x634FB0),(0x597CF0,0x597D00),(0x635070,0x635084),(0x56B478,0x56B480),
 (0x72077C,0x720850),(0x7196EC,0x719748),(0x71C370,0x71C378),
 (0x71C14C,0x71C154),(0x54CA2C,0x54CA34),(0x71C124,0x71C134),
 (0x6C58E4,0x6C58FC),(0x6C5914,0x6C5944),(0x6C5948,0x6C5960),(0x6C5978,0x6C59A8),
 (0x73D7C4,0x73D7F4),(0x6C4DE8,0x6C4E08),(0x4E263C,0x4E2644),(0x71DC34,0x71DC38),
]
}

def replay_register_readout(data,label,limit,snapshots,initial_upper=3):
    import unicorn as uc
    from unicorn import arm_const as arm
    BASE = 0x02000000
    TABLE = 0x404797E0
    DEVICE, COLLECTOR, ENGINE, PARAMS, SENSOR = (
        0x10020000, 0x10030000, 0x10040000, 0x10050000, 0x10060000
    )
    WRAPPERS = (0x10070000, 0x10070004)
    MMIO = (0x20004B00, 0x20004C00)
    SP, SENTINEL = 0x100D0000, 0x100F1000
    ALLOWED = CODE_RANGES['register_readout']

    vm=uc.Uc(uc.UC_ARCH_ARM,uc.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    for a,n in ((BASE,0x1000000),(0x10000000,0x100000),(0x40400000,0x100000),(0x20004000,0x1000)):
        vm.mem_map(a,n)
    vm.mem_write(BASE,data[:0x1000000])
    vm.mem_protect(BASE,0x1000000,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
    writes,reads,prepared,segments,pcs=[],[],[],[],set()
    widths,trace=Counter(),sha256()

    def reg(name,value=None):
        key=getattr(arm,'UC_ARM_REG_'+name.upper())
        if value is None:return vm.reg_read(key)
        vm.reg_write(key,value)

    def word(a,n=4):return int.from_bytes(vm.mem_read(a,n),'little')

    def host(a,value,n,note):
        vm.mem_write(a,value.to_bytes(n,'little'))
        prepared.append(dict(address=a,size=n,value=value,provenance=note))

    def code(cpu,pc,n,_):
        offset=pc-BASE
        require(n,4,'A32 width')
        require(any(a<=offset and offset+n<=e for a,e in ALLOWED),True,'allowlisted code')
        raw=bytes(cpu.mem_read(pc,n))
        require(raw,data[offset:offset+n],'original instruction')
        pcs.add(offset);widths[n]+=1;trace.update(pack('<II',offset,n)+raw)

    def on_write(cpu,_kind,a,n,value,_):
        writes.append(dict(pc_offset=reg('pc')-BASE,address=a,size=n,value=value))

    def on_read(cpu,_kind,a,n,_value,_):
        if 0x20004000<=a<0x20005000:
            reads.append(dict(pc_offset=reg('pc')-BASE,address=a,size=n,value=word(a,n)))

    vm.hook_add(uc.UC_HOOK_CODE,code)
    vm.hook_add(uc.UC_HOOK_MEM_WRITE,on_write)
    vm.hook_add(uc.UC_HOOK_MEM_READ,on_read)

    def run(entry,end,note):
        state={k:reg(k) for k in ('r0','r1','r2','r4','r5','r7','sp','lr')}
        vm.ctl_flush_tb()
        try:vm.emu_start(BASE+entry,end,count=100000)
        except uc.UcError as error:raise ValueError(f'{entry:#x}: PC={reg("pc"):#x}: {error}') from error
        require(reg('pc'),end,note)
        segments.append(dict(entry_offset=entry,stop_va=end,note=note,entry_registers=state))

    reg('sp',SP);reg('lr',SENTINEL)
    run(0x755CD4,BASE+0x755CD8,'original literal load supplies peripheral base')
    require(reg('r7'),0x20000000,'peripheral base from original literal')
    for i,wrapper in enumerate(WRAPPERS):
        reg('r0',wrapper);reg('r4',TABLE);reg('r5',i)
        run(0x755D50,BASE+0x755D6C,'prepared allocation result; original register-base arithmetic and table stores')
        require(word(wrapper),MMIO[i],'native wrapper MMIO base')
        require(word(TABLE+0x2C+4*i),wrapper,'native channel slot')

    host(DEVICE+0x10,TABLE,4,'device-table alias supplied; lifecycle not executed')
    host(COLLECTOR+4,DEVICE,4,'collector-device alias supplied')
    host(ENGINE+0x10C,PARAMS,4,'parameter link supplied; II-18 not rerun')
    host(PARAMS+0xB,1,1,'readout gate supplied, distinct from success flag')
    host(ENGINE+0x70,limit,4,'input byte limit; production from capture/config not executed')
    host(ENGINE+0x74,0x1234,2,'input detection threshold')
    for offset,value in ((0x7A,101),(0x7C,83),(0x7E,65),(0x80,49)):
        host(SENSOR+offset,value,2,'geometry field supplied; vertical fields are halved by original code')
    for address,(count,size64) in zip(MMIO,snapshots):
        host(address+0x24,count,4,'synthetic NRDNCNT register snapshot; not computed')
        host(address+0x28,size64,8,'synthetic NRDNSIZE register snapshot; not computed')
        host(address+0x34,initial_upper,4,'synthetic initial NRDNLIMIT upper word; not a hardware-validity claim')

    reg('r0',COLLECTOR);reg('r1',SENSOR);reg('r2',ENGINE)
    reg('sp',SP);reg('lr',SENTINEL)
    run(0x72077C,BASE+0x6C5914,'original configuration producer and channel0 register setup; stop before DMA preparation')
    run(0x6C5944,BASE+0x6C5978,'skip channel0 DMA setup; original return/call/channel1 register setup')
    run(0x6C59A8,SENTINEL,'skip channel1 DMA setup; original nested returns')
    expected_limit=((initial_upper & 0xFFFFFFFC)<<32) | (limit & 0xFFFFFFF8)
    for address in MMIO:
        require(word(address+0x30,8),expected_limit,'low word aligned down8; upper word bits1:0 cleared, others preserved')
        require([word(address+x) for x in (0xC,0x10,0x14,0x18,0x1C,0x20)],
                [41,100,24,65,0x1234,0],'native geometry and threshold programming')
    metadata_addresses={a+x for a in MMIO for x in (0x24,0x28,0x2C)}
    require([w for w in writes if w['address'] in metadata_addresses],[],
            'configuration does not fabricate measured count/size')
    reg('r0',COLLECTOR);reg('r1',0);reg('r2',ENGINE);reg('sp',SP);reg('lr',SENTINEL)
    run(0x722140,BASE+0x7221E4,'original two-channel result readout; stop before service/debug tail')
    expected=[snapshots[0][0],snapshots[1][0],snapshots[0][1]&0xFFFFFFFF,snapshots[1][1]&0xFFFFFFFF]
    observed=[word(ENGINE+x) for x in (0xFC,0x100,0x104,0x108)]
    require(observed,expected,'count copied and 64-bit size narrowed to low32')
    require(word(ENGINE+0xF8,1),0,'numeric metadata does not set success flag')
    metadata_reads=[x for x in reads if x['address'] in metadata_addresses]
    require([(x['address'],x['value']) for x in metadata_reads],
            [(a+x,v) for a,(count,size64) in zip(MMIO,snapshots) for x,v in ((0x24,count),(0x28,size64&0xFFFFFFFF),(0x2C,size64>>32))],
            'exact count/size MMIO reads including high word')
    require(sha256(bytes(vm.mem_read(BASE,0x1000000))).hexdigest(),sha256(data[:0x1000000]).hexdigest(),'mapped original image preserved')
    return dict(case=label,input_limit=limit,initial_limit_upper=initial_upper,programmed_limit=expected_limit,
        synthetic_register_snapshots=[dict(count=c,size64=n) for c,n in snapshots],
        result_fields=observed,result_flag=word(ENGINE+0xF8,1),
        prepared_inputs=prepared,segments=segments,metadata_reads=metadata_reads,
        native_mmio_writes=[w for w in writes if 0x20004000<=w['address']<0x20005000],
        native_result_writes=[w for w in writes if ENGINE+0xF8<=w['address']<ENGINE+0x10C],
        image_guest_writes=[w for w in writes if BASE<=w['address']<BASE+0x1000000],
        executed_offsets=sorted(pcs),instruction_widths=dict(widths),trace_sha256=trace.hexdigest())

def replay_dma_preparation(data,label,indices,buffers,capacity,channel,native_pool=False):
 import unicorn as uc
 from unicorn import arm_const as arm
 BASE=0x02000000
 CFG,JOB,WORKER,DEVICE,COLLECTOR,SENSOR=(0x10010000,0x10020000,0x10050000,0x10060000,0x10070000,0x10080000)
 ENGINE=JOB+0x2440
 TABLE=0x404797E0
 WRAPPERS=(0x10090000,0x10090004)
 DMA_BASES=(0x20005400,0x20005500)
 WORKER_SP,AUX_SP,SENTINEL=0x100D0000,0x100B0000,0x100F1000
 ALLOWED = CODE_RANGES['dma_preparation']

 vm=uc.Uc(uc.UC_ARCH_ARM,uc.UC_MODE_ARM)
 vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
 for a,n in ((BASE,0x1000000),(0x10000000,0x100000),(0x40400000,0x100000)):vm.mem_map(a,n)
 vm.mem_write(BASE,data[:0x1000000]);vm.mem_protect(BASE,0x1000000,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
 vm.reg_write(arm.UC_ARM_REG_C1_C0_2,0xF00000);vm.reg_write(arm.UC_ARM_REG_FPEXC,0x40000000)
 writes,prepared,segments,calls=[],[],[],[]
 widths,trace,pcs=Counter(),sha256(),set()

 def reg(name,value=None):
  key=getattr(arm,'UC_ARM_REG_'+name.upper())
  if value is None:return vm.reg_read(key)
  vm.reg_write(key,value)

 def word(a,n=4):return int.from_bytes(vm.mem_read(a,n),'little')

 def host(a,value,n,note):
  vm.mem_write(a,value.to_bytes(n,'little'));prepared.append(dict(address=a,size=n,value=value,provenance=note))

 def code(cpu,pc,n,_):
  offset=pc-BASE
  require(n,4,'A32 width')
  require(any(a<=offset and offset+n<=e for a,e in ALLOWED),True,f'allowlisted original code {offset:08X}')
  raw=bytes(cpu.mem_read(pc,n));require(raw,data[offset:offset+n],'original instruction')
  widths[n]+=1;pcs.add(offset);trace.update(pack('<II',offset,n)+raw)
  if offset in (0x74F92C,0x74F9A4,0x597CF0,0x597CF8,0x6C58E4,0x6C5948,0x6C4DE8,0x71DC34):
   calls.append(dict(pc_offset=offset,registers={x:reg(x) for x in ('r0','r1','r2','r3','sp','lr')}))

 def on_write(cpu,_kind,a,n,value,_):writes.append(dict(pc_offset=reg('pc')-BASE,address=a,size=n,value=value))

 def reject_device(cpu,kind,a,n,value,_):
  raise ValueError(f'forbidden MMIO or target-buffer access kind={kind} address={a:#x}')

 vm.hook_add(uc.UC_HOOK_CODE,code);vm.hook_add(uc.UC_HOOK_MEM_WRITE,on_write)
 vm.hook_add(uc.UC_HOOK_MEM_READ|uc.UC_HOOK_MEM_WRITE,reject_device,begin=0x20000000,end=0x3FFFFFFF)
 vm.hook_add(uc.UC_HOOK_MEM_READ|uc.UC_HOOK_MEM_WRITE,reject_device,begin=0x11000000,end=0x11FFFFFF)
 vm.hook_add(uc.UC_HOOK_MEM_READ|uc.UC_HOOK_MEM_WRITE,reject_device,begin=0x80000000,end=0x8001FFFF)

 def run(entry,end,note):
  state={x:reg(x) for x in ('r0','r1','r2','r4','r5','r6','r7','r8','sp','lr')}
  vm.ctl_flush_tb()
  try:vm.emu_start(BASE+entry,end,count=100000)
  except uc.UcError as error:raise ValueError(f'{entry:#x}: PC={reg("pc"):#x}: {error}') from error
  require(reg('pc'),end,note);segments.append(dict(entry_offset=entry,stop_va=end,note=note,entry_registers=state))

 def ctor(address):
  reg('r0',address);reg('sp',AUX_SP);reg('lr',SENTINEL)
  run(0x754970,SENTINEL,'original engine/frame constructor')

 host(DEVICE+0x10,TABLE,4,'device-table alias supplied; startup unrun')
 host(COLLECTOR+4,DEVICE,4,'collector-device alias supplied')
 host(WORKER+0x21C,JOB,4,'worker-job alias supplied')
 if native_pool:
  reg('r0',CFG+0x18);reg('r6',0);reg('sp',AUX_SP);reg('lr',SENTINEL)
  run(0x74E5D4,BASE+0x74E8A8,'after omitted generic array constructor; native capacity and list production; before epilogue')
  reg('r0',CFG);reg('sp',AUX_SP);reg('lr',SENTINEL)
  run(0x74EBF0,BASE+0x74ECBC,'native pool-base literals and cumulative descriptor addresses; before validity checks')
  buffers=tuple(word(CFG+0x18+16*i) for i in indices)
  capacity=word(CFG+0x1C+16*indices[0])
  require(buffers,(0x80019E90,0x8001B250),'native default record24/25 buffers')
  require(capacity,0x13C0,'native default record24 capacity')
  require(word(CFG+0x1C+16*indices[1]),capacity,'same native record25 capacity')
 else:
  for index,buffer in zip(indices,buffers):
   descriptor=CFG+0x18+16*index
   host(descriptor,buffer,4,'record-buffer pointer supplied in config descriptor; allocation/history unrun')
   host(descriptor+4,capacity,4,'descriptor capacity in bytes supplied')
 for offset,value in ((0x7A,101),(0x7C,83),(0x7E,65),(0x80,49)):
  host(SENSOR+offset,value,2,'geometry supplied; image processing unrun')

 reg('sp',AUX_SP);reg('lr',SENTINEL)
 run(0x755CD4,BASE+0x755CD8,'original peripheral base literal')
 for index,wrapper in zip((7,8),WRAPPERS):
  reg('r0',wrapper);reg('r4',TABLE);reg('r5',index)
  run(0x755FDC,BASE+0x755FFC,'prepared allocator result; native DMA wrapper address and table stores')
 reg('r4',DEVICE)
 run(0x6C087C,BASE+0x6C089C,'original device binding chooses DMA indexes7 and8')
 require([word(DEVICE+x) for x in (0x8C,0x90)],list(WRAPPERS),'native channel wrappers')
 require([word(w) for w in WRAPPERS],list(DMA_BASES),'native DMA bases')

 ctor(ENGINE)
 reg('r0',WORKER);reg('r1',0x100A0000);reg('sp',WORKER_SP);reg('lr',SENTINEL)
 run(0x6352A0,BASE+0x6352B0,'native worker prologue; stop before singleton getter')
 frame=reg('sp')
 run(0x6352D4,BASE+0x6352DC,'skip singleton/request getters; native worker frame constructor')
 reg('sb',CFG);reg('r8',indices[0]);reg('sl',indices[1])
 run(0x63542C,BASE+0x63545C,'skip unrelated worker setup; native config buffer getters and command stores')
 run(0x635488,BASE+0x6354A0,'native first descriptor capacity getter and command+70 store')
 require([word(frame+x) for x in (0x54,0x58,0x70)],[*buffers,capacity],'native worker buffer/capacity fields')
 run(0x635528,BASE+0x634970,'skip worker clearing and unrelated setup; native core call/prologue')
 core_sp=reg('sp');require(word(core_sp+0x18),frame,'actual saved caller frame')
 run(0x634D88,BASE+0x634D94,'skip core service/preparation; derive same inner engine')
 require(reg('r8'),ENGINE,'native job engine alias')
 run(0x634F68,BASE+0x634FB0,'original nonnull buffer forwarding from actual saved frame')
 run(0x635070,BASE+0x635084,'original capacity forwarding from same frame')
 require([word(ENGINE+x) for x in (0x54,0x58,0x70)],[*buffers,capacity],'same values reach engine')

 reg('r0',COLLECTOR);reg('r1',SENSOR);reg('r2',ENGINE);reg('sp',AUX_SP);reg('lr',SENTINEL)
 run(0x72077C,BASE+0x720818,'original temporary PixelDetect settings; no MMIO')
 outer_sp=reg('sp')
 if channel==0:
  run(0x720818,BASE+0x6C58FC,'native engine buffer0 getter and channel0 call/prologue')
  packet=reg('sp')
  run(0x6C5914,BASE+0x71DC38,'skip PixelDetect register setup; native DMA packet and call; stop before first MMIO')
 else:
  run(0x720834,BASE+0x6C5960,'skip channel0 call; native engine buffer1 getter and channel1 prologue')
  packet=reg('sp')
  run(0x6C5978,BASE+0x71DC38,'skip PixelDetect register setup; native DMA packet and call; stop before first MMIO')
 expected_buffer=buffers[channel]
 require([word(packet+x,n) for x,n in ((0,1),(4,4),(8,4),(0xC,1),(0xD,1))],
         [0,expected_buffer,0,0,1],'original DMA packet fields')
 require(reg('r0'),DMA_BASES[channel],'first-MMIO base from original wrapper load')
 require(reg('r1'),0,'first-MMIO pending mode value')
 require(reg('r4'),packet,'native6C4DE8 holds actual packet address')
 require(reg('r5'),WRAPPERS[channel],'native6C4DE8 holds correct channel wrapper')
 require(reg('lr'),BASE+0x6C4E08,'actual first-MMIO setter call return link')
 require(word(reg('sp')+12),BASE+(0x6C5944 if channel==0 else 0x6C59A8),'native DMA helper saved channel return link')
 require(word(ENGINE+0xF8,1),0,'no result production')
 require(sha256(bytes(vm.mem_read(BASE,0x1000000))).hexdigest(),sha256(data[:0x1000000]).hexdigest(),'mapped original image preserved')
 interesting={frame+0x54,frame+0x58,frame+0x70,ENGINE+0x54,ENGINE+0x58,ENGINE+0x70,packet,packet+4,packet+8,packet+0xC,packet+0xD}
 if native_pool:interesting.update(CFG+0x18+16*i+offset for i in indices for offset in (0,4))
 return dict(case=label,channel=channel,indices=list(indices),source_buffers=list(buffers),capacity_bytes=capacity,native_pool_producer=native_pool,
  frames=dict(worker=frame,core=core_sp,settings=outer_sp,dma_packet=packet),
  dma_packet=dict(mode=word(packet,1),buffer=word(packet+4),second_word=word(packet+8),byte_C=word(packet+0xC,1),byte_D=word(packet+0xD,1)),
  pending_mmio=dict(pc_offset=0x71DC38,address=reg('r0')+4,size=4,access='read',executed=False),
  native_channel_binding=dict(device_field=0x8C+4*channel,dma_index=7+channel,wrapper=WRAPPERS[channel],base=DMA_BASES[channel]),
  supplied_inputs=prepared,segments=segments,calls=calls,relevant_native_writes=[w for w in writes if w['address'] in interesting],
  executed_offsets=sorted(pcs),instruction_widths=dict(widths),trace_sha256=trace.hexdigest(),
  mmio_accesses=0,target_buffer_accesses=0,image_guest_writes=[w for w in writes if BASE<=w['address']<BASE+0x1000000])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.path.lexists(args.output):
        raise FileExistsError(args.output)
    sys.dont_write_bytecode = True
    data = read_decoded(args.decoded)
    import unicorn

    registers = [replay_register_readout(data, *case) for case in (
        ("zero", 0, ((0, 0), (0, 0))),
        ("below_alignment", 7, ((1, 7), (2, 8))),
        ("high_word", 8, ((3, 0x100000008), (4, 0x100000000))),
        ("maximum_low32_preserve_upper", 0xFFFFFFFF,
         ((5, 0x1FFFFFFFF), (6, 0x200000001)), 0xA5A50003),
    )]
    dma = [replay_dma_preparation(data, label, indices, buffers, capacity, channel, native)
           for label, indices, buffers, capacity, native in (
               ("native_default_pool", (24, 25), None, None, True),
               ("aligned", (0, 1), (0x11010000, 0x11020000), 8, False),
               ("unaligned", (24, 25), (0x11010003, 0x11020007), 63, False))
           for channel in (0, 1)]
    report = dict(schema="K3II-register-dma-v1", verified=True,
                  decoded_sha256=DECODED_SHA, decoded_size=DECODED_SIZE,
                  public_dependencies_sha256_lf=DEPENDENCIES,
                  engine=dict(name="Unicorn", version=unicorn.__version__, cpu="Cortex-A9"),
                  trace_digest_format="SHA-256 over compact sorted-key ASCII JSON of all cases and allowed original code range hashes. No evidence fields omitted.")
    for name, cases in (("register_readout", registers), ("dma_preparation", dma)):
        ranges = [dict(start=a, end_exclusive=e, sha256=sha256(data[a:e]).hexdigest())
                  for a, e in CODE_RANGES[name]]
        payload = dict(cases=cases, allowed_code_ranges=ranges)
        fingerprint = verify_projection(payload, EVIDENCE_SHA[name], name)
        report[name] = dict(full_evidence_sha256=fingerprint, **payload)
    require(sha256(read_decoded(args.decoded)).hexdigest(), DECODED_SHA, "Decoded input unchanged")
    report["disk_input_unchanged"] = True
    report["limits"] = [
        "The register experiment supplies byte-backed MMIO snapshots. Original code transforms limits and reads counts/64-bit sizes; it does not compute camera results.",
        "The DMA experiment maps no device or target-buffer memory and stops before the first DMA MMIO read71DC38. Prior PixelDetect MMIO and worker clearing are skipped.",
        "Default record24/25 pointer and capacity stores execute after an omitted generic constructor. Full startup, allocation lifetime, owner aliases and capture/request selection remain prepared or unrun.",
        "72077C is a separate entry using the engine populated through native worker/core slices. The channels use independent VMs and channel1 skips channel0.",
        "DMA packet+8 zero, capacity/NRDNLIMIT, byte length, entry count, setup/result flag, validity markers and listmask are distinct.",
        "No actual DMA transfer, completion, data production, buffer reuse history, auxiliary scaler activation or SuperResolution menu reachability is established.",
        "These result-record addresses are not established as processed-pixel or JPEG image buffers.",
    ]
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(json.dumps(dict(verified=True, register_cases=len(registers), dma_cases=len(dma))))
    return 0

if __name__ == "__main__":
    sys.exit(main())
