# SPDX-License-Identifier: GPL-2.0-only
"""Replay ROM-backed tone producers; physical sample/color domains remain unknown."""
from collections import Counter
from hashlib import sha256
import json
from pathlib import Path
from struct import pack,unpack
import sys

from verify_findings import require
from verify_tone_path import load_image
from verify_tone_numeric import interpolate,expand
import unicorn as uc
from unicorn import arm_const as arm

BASE=0x02000000
OBJ,RECIPE,CONTEXT,PACKED,PROFILES=0x10010000,0x10040000,0x10050000,0x10070000,0x10080000
SP,STOP=0x100E0000,0x100F1000
ALLOWED = [
 (0x288,0x2A0),
 (0x85D8,0x8618),
 (0x2E1BDC,0x2E1BF4),
 (0x2E1BFE,0x2E1C1A),
 (0x2E1C1C,0x2E1C22),
 (0x4BCEA8,0x4BCEB4),
 (0x4BCF3C,0x4BCFC4),
 (0x4BD008,0x4BD018),
 (0x4BD048,0x4BD050),
 (0x4BD078,0x4BD080),
 (0x4C48EC,0x4C48F4),
 (0x4C491C,0x4C4924),
 (0x4C4934,0x4C493C),
 (0x4C4944,0x4C494C),
 (0x4DABD8,0x4DB150),
 (0x4DB1CC,0x4DB1DC),
 (0x4DB1EC,0x4DB1FC),
 (0x4DB21C,0x4DB22C),
 (0x4DB23C,0x4DB24C),
 (0x4DBC14,0x4DC494),
 (0x4DC910,0x4DCEE4),
 (0x4DCF34,0x4DCF48),
 (0x4DCFA0,0x4DCFCC),
 (0x4DD3EC,0x4DD42C),
 (0x4DD924,0x4DDB64),
 (0x4DDB84,0x4DDBA8),
 (0x4DDBFC,0x4DDC54),
 (0x4DDC68,0x4DDC94),
 (0x4DE1F4,0x4DE218),
 (0x4E312C,0x4E3134),
 (0x4E313C,0x4E3144),
 (0x4E31EC,0x4E31F4),
 (0x4FA83C,0x4FA848),
 (0x4FA948,0x4FA950),
 (0x52671C,0x526724),
 (0x712898,0x7128AC),
 (0x7128C4,0x7128FC),
 (0x712AC8,0x712B58),
 (0x712B78,0x712B98),
 (0x712BB4,0x712C2C),
 (0x712C44,0x712C68),
 (0x712D08,0x712D44),
]


def run_case(data,label,profile,control_c_override=None,selector_override=None,scale=8192,boot=True,stress=False):
 vm=uc.Uc(uc.UC_ARCH_ARM,uc.UC_MODE_ARM);vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
 for a,n in ((BASE,0x1000000),(0x10000000,0x100000),(0x40400000,0x100000)):vm.mem_map(a,n)
 vm.mem_write(BASE,data[:0x1000000]);vm.mem_protect(BASE,0x1000000,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
 vm.reg_write(arm.UC_ARM_REG_CPSR,0xD3)
 vm.reg_write(arm.UC_ARM_REG_C1_C0_2,0xF00000);vm.reg_write(arm.UC_ARM_REG_FPEXC,0x40000000)
 phase='startup';trace=sha256();counts=Counter();pcs=set();reads=Counter();writes=[];segments=[];prepared=[];calls=[];invalid_reads=[]
 def reg(name,value=None):
  key=getattr(arm,'UC_ARM_REG_'+name.upper())
  if value is None:return vm.reg_read(key)
  vm.reg_write(key,value)
 def word(address,n=4):return int.from_bytes(vm.mem_read(address,n),'little')
 def host(address,value,n,note):
  vm.mem_write(address,value.to_bytes(n,'little'));prepared.append(dict(address=address,size=n,value=value,note=note))
 def code(cpu,pc,n,_):
  offset=pc-BASE
  require(any(a<=offset and offset+n<=e for a,e in ALLOWED),True,'audited code ranges only')
  raw=bytes(cpu.mem_read(pc,n));require(raw,data[offset:offset+n],'original instruction bytes')
  counts[(phase,n)]+=1;pcs.add((offset,n));trace.update(pack('<II',offset,n)+raw)
  if offset in (0x4DC980,0x4DD924):
   calls.append(dict(producer=offset,params_hex=bytes(cpu.mem_read(reg('r2'),0x1C)).hex(),output=reg('r1')))
 def read(cpu,_kind,a,n,_value,_):
  if phase=='tone' and BASE+0xA00000<=a<BASE+0xA80000:reads[(a,n)]+=1
 def write(cpu,_kind,a,n,value,_):
  if phase=='tone' and OBJ+8<=a<OBJ+0x208:writes.append(dict(pc=reg('pc')-BASE,address=a,size=n,value=value))
 def invalid(cpu,kind,a,n,value,_):
  invalid_reads.append(dict(pc_offset=reg('pc')-BASE,kind=kind,address=a,size=n));return False
 vm.hook_add(uc.UC_HOOK_MEM_READ_UNMAPPED,invalid)
 vm.hook_add(uc.UC_HOOK_CODE,code);vm.hook_add(uc.UC_HOOK_MEM_READ,read);vm.hook_add(uc.UC_HOOK_MEM_WRITE,write)
 def run(offset,r0=0,r1=0,r2=0,end=STOP):
  for name,value in (('r0',r0),('r1',r1),('r2',r2),('sp',SP),('lr',STOP)):reg(name,value)
  vm.ctl_flush_tb()
  try:vm.emu_start(BASE+offset,end,count=400000)
  except uc.UcError as error:raise ValueError(f'entry {offset:X}, phase {phase}, PC {reg("pc"):X}: {error}') from error
  require(reg('pc'),end,'bounded return');segments.append(dict(phase=phase,entry=offset,stop=end))
  return reg('r0')
 if boot:
  run(0x288,end=BASE+0x2A0)
  require(bytes(vm.mem_read(0x404094B0,0x15EB0)),data[0xA84504:0xA9A3B4],'native startup initialized-data copy')
 phase='profile'
 run(0x4DBC14);run(0x4DABD8,PROFILES)
 selector=run(0x4DB21C,PROFILES,profile)
 control_c=run(0x4DB1CC,PROFILES,profile)
 control_84=run(0x4DB1EC,PROFILES,profile)
 split=run(0x4DB23C,PROFILES,profile)
 node=word(PROFILES+profile*4);record=word(node+4)
 defaults=dict(profile=profile,record_va=record,record_hex=bytes(vm.mem_read(record,12)).hex(),selector=selector,control_c=control_c,control_84=control_84,split_parameter=split)
 if control_c_override is not None:control_c=control_c_override
 if selector_override is not None:selector=selector_override
 host(OBJ+0x18A18,RECIPE,4,'prepared recipe owner alias')
 host(OBJ+0x18A0C,CONTEXT,4,'prepared context alias')
 host(OBJ+0x18A58,0xFFFFFFFF,4,'force native cache miss; real capture cache history unrun')
 host(RECIPE+0x44,selector,4,'native default getter result or explicit counterfactual override')
 host(RECIPE+0xC,control_c,4,'native default getter result or explicit control_c override; recipe binding prepared')
 host(RECIPE+0x84,control_84,4,'native default getter result; recipe binding prepared')
 host(RECIPE+0x90,int(split==1),1,'native default property converted through static equality contract; binding prepared')
 host(RECIPE+0x73,1,1,'context flag supplied; real setting provenance unrun')
 host(CONTEXT+0x7A74,scale,4,'context integer supplied; physical units unknown')
 phase='tone'
 try:run(0x4DDAB8,OBJ)
 except ValueError as error:
  if boot:raise
  require(reg('pc'),BASE+0x4DCB68,'negative stop at missing row dereference')
  require('UC_ERR_READ_UNMAPPED' in str(error),True,'negative must fail on unmapped read')
  require(len(invalid_reads),1,'one negative invalid read')
  require([(r['address'],r['size']) for r in invalid_reads],[(4,4)],'negative zero row pointer plus4')
  return dict(case=label,expected_failure=True,invalid_reads=invalid_reads,error=str(error),pc_offset=reg('pc')-BASE,defaults=defaults,prepared=prepared)
 require(boot,True,'negative missing-data-copy case must not succeed')
 curve=unpack('<256H',bytes(vm.mem_read(OBJ+8,512)))
 require([(w['pc'],w['address'],w['size']) for w in writes],[(0x4DDAA8 if selector==6 else 0x4DCFBC,OBJ+8+2*i,2) for i in range(256)],'exact original producer stores')
 require(max(curve)<=0x4000,True,'producer numeric cap')
 phase='interpolate'
 samples=sorted(set([0,1,63,64,65,0x3FBF,0x3FC0,0x3FC1,0x3FFF,0x4000,0xFFFF,0xFFFFFFFF]+[64*i for i in range(256)]))
 sampled=[]
 for x in samples:
  actual=run(0x4DD3EC,r1=OBJ+8,r2=x);require(actual,interpolate(curve,x),'original interpolation vs existing reference')
  sampled.append([x,actual])
 phase='expand'
 run(0x4DE1F4)
 run(0x4DC910,r1=OBJ+8,r2=PACKED)
 packed=unpack('<1280H',bytes(vm.mem_read(PACKED,2560)))
 require(packed,expand(curve),'original expansion vs existing reference')
 negative=None
 if stress:
  phase='stress'
  fixture=(0xFFFF,)*256
  vm.mem_write(OBJ+8,pack('<256H',*fixture))
  value=run(0x4DD3EC,r1=OBJ+8,r2=0)
  require(value,0xFFFF,'interpolator is not a 14bit saturator')
  run(0x4DC910,r1=OBJ+8,r2=PACKED)
  expanded=unpack('<1280H',bytes(vm.mem_read(PACKED,2560)))
  require(expanded[:1024],(0,)*1024,'signed SIMD clamp for FFFF fixture')
  require(expanded[1024:],(0xFFFF,)*256,'unclamped copied tail')
  negative=dict(kind='synthetic all-FFFF kernel control; not ROM producer output',interpolate=value,expanded_prefix_value=0,expanded_tail_value=65535)
 require(sha256(bytes(vm.mem_read(BASE,0x1000000))).hexdigest(),sha256(data[:0x1000000]).hexdigest(),'original image preserved')
 rom_tables=sorted({(a-BASE-0xA31D94)//512 for a,n in reads if 0xA31D94<=a-BASE<0xA34994})
 return dict(case=label,defaults=defaults,prepared=prepared,producer_calls=calls,curve=list(curve),curve_sha256=sha256(pack('<256H',*curve)).hexdigest(),
  minimum=min(curve),maximum=max(curve),monotone=all(a<=b for a,b in zip(curve,curve[1:])),cap_count=curve.count(0x4000),
  rom_curve_indices_read=rom_tables,rom_reads=[dict(address=a,size=n,count=c) for (a,n),c in sorted(reads.items())],
  interpolation=sampled,expanded_sha256=sha256(pack('<1280H',*packed)).hexdigest(),expanded_min=min(packed),expanded_max=max(packed),
  negative_control=negative,native_output_writes=writes,segments=segments,executed=[dict(offset=a,size=n) for a,n in sorted(pcs)],
  instruction_counts=[dict(phase=p,size=n,count=c) for (p,n),c in sorted(counts.items())],trace_sha256=trace.hexdigest(),mmio_accesses=0)
