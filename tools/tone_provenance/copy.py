# SPDX-License-Identifier: GPL-2.0-only
"""Original same-instance pointer writer and conditional copy; split entries explicit."""
from pathlib import Path
from hashlib import sha256
import json,sys
from verify_tone_path import load_image
from verify_findings import require
import unicorn as uc
from unicorn import arm_const as arm
B=0x02000000
def replay(data,name,delta=0,variant=False,gate80=0,gatebb=1,nullref=False):
 vm=uc.Uc(uc.UC_ARCH_ARM,uc.UC_MODE_ARM);vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
 for a,n in ((B,0x1000000),(0x10000000,0x400000),(0x40400000,0x100000)):vm.mem_map(a,n)
 vm.mem_write(B,data[:0x1000000]);vm.mem_protect(B,0x1000000,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
 vm.reg_write(arm.UC_ARM_REG_CPSR,0xD3);vm.reg_write(arm.UC_ARM_REG_C1_C0_2,0xF00000);vm.reg_write(arm.UC_ARM_REG_FPEXC,0x40000000)
 job=0x10100000+delta;cmd=job+0x2684;src=job+0x2730;dst=job+0xE608;sp=0x103E0000;stop=0x103F0000
 phase='';writes=[];pcs={};segments=[];prepared=[];invalid=[]
 def reg(n,v=None):
  key=getattr(arm,'UC_ARM_REG_'+n.upper())
  if v is None:return vm.reg_read(key)
  vm.reg_write(key,v)
 def word(a,n=4):return int.from_bytes(vm.mem_read(a,n),'little')
 def host(a,v,n,note):vm.mem_write(a,v.to_bytes(n,'little'));prepared.append(dict(address=a,value=v,size=n,note=note))
 def code(cpu,pc,n,_):
  off=pc-B;require(0<=off<0x1000000,True,'original image execution');raw=bytes(cpu.mem_read(pc,n));require(raw,data[off:off+n],'original bytes');pcs[(off,n)]=raw.hex()
 def write(cpu,kind,a,n,v,_):
  if phase!='startup':writes.append(dict(phase=phase,pc=reg('pc')-B,address=a,size=n,value=v))
 def fault(cpu,kind,a,n,v,_):invalid.append(dict(phase=phase,pc=reg('pc')-B,kind=kind,address=a,size=n));return False
 vm.hook_add(uc.UC_HOOK_CODE,code);vm.hook_add(uc.UC_HOOK_MEM_WRITE,write);vm.hook_add(uc.UC_HOOK_MEM_INVALID,fault)
 def run(label,entry,regs=None,end=None,reset=True):
  nonlocal phase
  phase=label
  if reset:reg('sp',sp);reg('lr',stop)
  for k,v in (regs or {}).items():reg(k,v)
  target=B+end if end is not None else stop
  try:vm.emu_start(B+entry,target,count=200000)
  except uc.UcError as e:raise ValueError(f'{label}: pc {reg("pc")-B:X}, {e}, {invalid}') from e
  require(reg('pc'),target,'bounded stop reached');segments.append(dict(phase=label,entry=entry,end=target,reset_frame=reset,registers={k:reg(k) for k in ('r0','r1','r4','r5','r6','sb','sp')}))
 run('startup',0x288,end=0x2A0)
 require(bytes(vm.mem_read(0x404094B0,0x15EB0)),data[0xA84504:0xA9A3B4],'native initialized data')
 run('command_constructor',0x653ACC,{'r0':job},0x653AD8)
 run('destination_context_constructor',0x859ACC,{'r0':dst})
 require([word(src+o,2) for o in (8,10,12,14)],[420,256,256,320],'native source context constructor')
 if variant:
  for entry,value in zip((0x719628,0x719638,0x719630,0x719620),(0,0x800,0xFFFF,0x1234)):
   run('prepared_scalar_via_original_setter',entry,{'r0':src,'r1':value})
  for i in range(0x68):host(src+0x6100+i,(i*37+11)&255,1,'prepared payload byte, not observed capture')
 source_half=[word(src+o,2) for o in (8,10,12,14)];before_half=[word(dst+o,2) for o in (8,10,12,14)]
 source_block=bytes(vm.mem_read(src+0x6100,0x68));before_block=bytes(vm.mem_read(dst+0x6100,0x68))
 host(job+0x4F,1,1,'prepared processing enable')
 host(job+0x2080,gate80,1,'prepared selector4 skip guard')
 host(job+0x20BB,gatebb,1,'prepared selector4 enable guard')
 run('selector3_native_frame',0x6593B0,{'r0':job,'r1':3},0x65A480)
 frame=reg('sp');require(word(frame+0x20),cmd,'SP20 is job2684');require(word(frame+0x28),job+0x2220,'SP28 is job2220')
 run('selector3_processing_enable',0x65A480,end=0x65A48C,reset=False)
 run('selector3_command_inner',0x65A588,end=0x65A594,reset=False)
 run('selector3_reference_derive',0x65A61C,end=0x65A630,reset=False)
 run('selector3_reference_store',0x65A780 if nullref else 0x65A77C,{'r1':0} if nullref else None,0x65A788,False)
 require(word(job+0x26C0),0 if nullref else job+0xC2F8,'native reference store')
 run('selector3_command_getter',0x656984,{'r0':job,'r1':3})
 require(reg('r0'),cmd,'selector3 returns same command')
 run('writer_native_frame',0x586758,{'r0':0x10080000+delta,'r1':reg('r0')},0x585E40)
 require(word(reg('sp')+0x68),cmd,'original writer frame saved command')
 run('writer_command_inner',0x585E4C,end=0x585E58,reset=False)
 run('writer_mode_getter',0x585E68,end=0x585E74,reset=False)
 run('writer_reference_guards',0x585EAC,end=0x5863FC if nullref else 0x585EDC,reset=False)
 if not nullref:
  run('writer_nested_receiver',0x585F2C,end=0x585F38,reset=False)
  require(word(reg('sp')+0x1C),job+0xC30C,'original nested receiver identity')
  run('writer_context_store',0x585FE4,end=0x585FF8,reset=False)
 require(word(job+0xD828),0 if nullref else src,'native same-instance nonzero population')
 run('selector4_native_frame',0x6593B0,{'r0':job,'r1':4},0x65AE74)
 require(word(reg('sp')+0x20),cmd,'selector4 derives same command')
 require(reg('sb'),dst,'selector4 derives destination context')
 run('selector4_conditional_copy',0x65AE74,end=0x65AF30,reset=False)
 copied=not (gate80 or not gatebb or nullref)
 after_half=[word(dst+o,2) for o in (8,10,12,14)];after_block=bytes(vm.mem_read(dst+0x6100,0x68))
 require(after_half,source_half if copied else before_half,'four halfword copy or unchanged destination')
 require(after_block,source_block if copied else before_block,'0x68 byte block copy or unchanged destination')
 pointer_writes=[w for w in writes if w['address']==job+0xD828]
 require([(w['pc'],w['value']) for w in pointer_writes],[] if nullref else [(0x87BAB0,src)],'exact original nonzero setter')
 copy_writes=[w for w in writes if w['phase']=='selector4_conditional_copy' and dst<=w['address']<dst+0x7BC4]
 require(len(copy_writes),56 if copied else 0,'52 block halfwords and four scalar halfwords')
 require(sha256(bytes(vm.mem_read(B,0x1000000))).hexdigest(),sha256(data[:0x1000000]).hexdigest(),'image unchanged')
 return dict(name=name,job=job,command=cmd,source_context=src,destination_context=dst,source_halfwords=source_half,before_halfwords=before_half,after_halfwords=after_half,source_block=source_block.hex(),after_block=after_block.hex(),copied=copied,pointer_writes=pointer_writes,copy_writes=copy_writes,segments=segments,writes=writes,prepared=prepared,executed=[dict(offset=a,size=n,hex=h) for (a,n),h in sorted(pcs.items())],invalid=invalid,actual_capture_history_proven=False)
