# SPDX-License-Identifier: GPL-2.0-only
"""Original pointer construction and consumption, with explicit entry boundaries."""
from pathlib import Path
from hashlib import sha256
from struct import pack
import json,sys
from verify_tone_path import load_image
from verify_findings import require
import unicorn as uc
from unicorn import arm_const as arm
B=0x02000000
def replay(data,delta=0):
 vm=uc.Uc(uc.UC_ARCH_ARM,uc.UC_MODE_ARM);vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
 for a,n in ((B,0x1000000),(0x10000000,0x400000),(0x40400000,0x100000)):vm.mem_map(a,n)
 vm.mem_write(B,data[:0x1000000]);vm.mem_protect(B,0x1000000,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
 vm.reg_write(arm.UC_ARM_REG_CPSR,0xD3);vm.reg_write(arm.UC_ARM_REG_C1_C0_2,0xF00000);vm.reg_write(arm.UC_ARM_REG_FPEXC,0x40000000)
 owner=0x10010000+delta;cmd=owner+0xC0C;context=owner+0xDC0;outer=0x10040000+delta;stage=0x10080000+delta;helper=0x10090000+delta;manager=0x100A0000+delta
 sp=0x103E0000;stop=0x103F0000;phase='';writes=[];pcs={};events=[];segments=[];prepared=[];invalid=[]
 def reg(n,v=None):
  key=getattr(arm,'UC_ARM_REG_'+n.upper())
  if v is None:return vm.reg_read(key)
  vm.reg_write(key,v)
 def word(a,n=4):return int.from_bytes(vm.mem_read(a,n),'little')
 def host(a,v,n,note):vm.mem_write(a,v.to_bytes(n,'little'));prepared.append(dict(address=a,value=v,size=n,note=note))
 def code(cpu,pc,n,_):
  off=pc-B;require(0<=off<0x1000000,True,'execution stays in original image')
  raw=bytes(cpu.mem_read(pc,n));require(raw,data[off:off+n],'original instruction bytes');pcs[(off,n)]=raw.hex()
  if off in (0x754B08,0x4BABBC,0x4BABF4,0x4BC880,0x4BCB70,0x4C360C,0x4E02F8,0x4DE1B0):events.append(dict(phase=phase,pc=off,r0=reg('r0'),r1=reg('r1'),r2=reg('r2'),r3=reg('r3'),sp=reg('sp'),stack0=word(reg('sp'))))
 def write(cpu,kind,a,n,v,_):
  if phase!='startup':writes.append(dict(phase=phase,pc=reg('pc')-B,address=a,size=n,value=v))
 def fault(cpu,kind,a,n,v,_):invalid.append(dict(phase=phase,pc=reg('pc')-B,kind=kind,address=a,size=n));return False
 vm.hook_add(uc.UC_HOOK_CODE,code);vm.hook_add(uc.UC_HOOK_MEM_WRITE,write);vm.hook_add(uc.UC_HOOK_MEM_INVALID,fault)
 def run(name,entry,regs=None,end=None):
  nonlocal phase
  phase=name;reg('sp',sp);reg('lr',stop)
  for k,v in (regs or {}).items():reg(k,v)
  target=B+end if end is not None else stop
  try:vm.emu_start(B+entry,target,count=200000)
  except uc.UcError as e:raise ValueError(f'{name}: pc {reg("pc")-B:X}, {e}, {invalid}') from e
  require(reg('pc'),target,'bounded entry reached stop');segments.append(dict(phase=name,entry=entry,end=target,registers={k:reg(k) for k in ('r0','r1','r2','r3','sp')},stack0=word(reg('sp'))))
 run('startup',0x288,end=0x2A0)
 require(bytes(vm.mem_read(0x404094B0,0x15EB0)),data[0xA84504:0xA9A3B4],'original initialized-data copy')
 run('command_constructor',0x785898,{'r0':cmd})
 run('command_member_binding',0x628BAC,{'r0':owner,'r1':0,'r2':0},0x628C14)
 require(word(cmd+0x90),context,'original member binding derives pointer from owner')
 run('outer_constructor_prefix',0x4BA63C,{'r0':outer},0x4BA64C)
 run('helper_constructor_prefix',0x4C35B0,{'r0':helper},0x4C35C0)
 run('manager_constructor',0x4D5F28,{'r0':manager})
 run('manager_outer_store',0x4D5FB0,{'r0':outer,'r4':manager},0x4D5FB4)
 run('manager_helper_store',0x4D5FD0,{'r0':helper,'r4':manager},0x4D5FD4)
 host(stage+4,stage+0x100,4,'prepared stage allocation carrier; no context pointer')
 run('stage_outer_binding',0x565D74,{'sb':manager,'r4':stage},0x565D88)
 tone_stage=stage+0x100
 require(word(tone_stage+0x34),outer,'source manager getter and native stage setter')
 # These are separate entry boundaries; no host context pointer is written to the consumer.
 run('tone_command_consumption',0x57C118,{'r4':tone_stage,'r6':cmd},0x4BABF4)
 tone_context=reg('r3')
 require(tone_context,context,'native member pointer reaches outer wrapper R3')
 require(reg('r0'),outer,'native vtable dispatch targets original outer object')
 host(stage+0x48,stage+0x200,4,'prepared producer stage allocation carrier; no context pointer')
 run('stage_helper_binding',0x56614C,{'sb':manager,'r4':stage},0x566160)
 producer_stage=stage+0x200
 require(word(producer_stage+0x2C),helper,'source getter and native producer stage setter')
 job=0x10100000+delta
 run('job_recipe_context_constructors',0x653BF8,{'r0':job},0x653C38)
 context2=job+0xE608;recipe2=job+0xE0C4
 require([word(context2+o,2) for o in (8,10,12,14)],[420,256,256,320],'original context constructor halfwords')
 require(word(context2+0x7A74),8192,'constructor context integer; not capture default')
 run('paired_command_binding',0x653E48,{'r4':job},0x653F14)
 producer_cmd=job+0xA3FC;tone_cmd=job+0xA41C
 require(word(producer_cmd+0x14),context2,'original producer binding from context-derived R6')
 require(word(tone_cmd+0x90),context2,'same native R6 forwarded to tone binding')
 require(word(producer_cmd+0xC),recipe2,'recipe separated from context')
 pair_writes=[w for w in writes if w['phase']=='paired_command_binding' and w['address'] in (producer_cmd+0x14,tone_cmd+0x90)]
 require([(w['pc'],w['value']) for w in pair_writes],[(0x7855A4,context2),(0x785868,context2)],'two original stores consume preserved R6')
 run('select_tone_command',0x656984,{'r0':job,'r1':0})
 require(reg('r0'),tone_cmd,'native selector0 pointer')
 run('paired_tone_consumption',0x57C118,{'r4':tone_stage,'r6':reg('r0')},0x4BABF4)
 paired_tone=reg('r3');require(paired_tone,context2,'native paired tone R3')
 run('select_producer_command',0x656984,{'r0':job,'r1':4})
 require(reg('r0'),producer_cmd,'native selector4 pointer')
 run('paired_producer_consumption',0x583A8C,{'r4':producer_stage,'sl':reg('r0')},0x4E0310)
 producer_fifth=word(reg('sp')+0x250)
 require(reg('fp'),producer_fifth,'original producer prologue loads fifth argument into FP')
 require(word(reg('sp')+0x224),recipe2,'original stack+224 is saved entryR2 recipe')
 require(producer_fifth,paired_tone,'native shared context identity across separate consumer entries')
 require(reg('r2'),recipe2,'producer recipe is entry R2 and distinct from fifth context')
 require(reg('r3'),job+0xE1C8,'producer fourth arg is distinct descriptor')
 require(sha256(bytes(vm.mem_read(B,0x1000000))).hexdigest(),sha256(data[:0x1000000]).hexdigest(),'original image preserved')
 
 return dict(legacy_tone_context=tone_context,paired_tone_context=paired_tone,producer_fifth=producer_fifth,paired_native_binding_identity_proven=True,actual_capture_history_proven=False,job=job,producer_command=producer_cmd,tone_command=tone_cmd,constructor_halfwords=[word(context2+o,2) for o in (8,10,12,14)],pair_writes=pair_writes,delta=delta,owner=owner,command=cmd,context=context,outer=outer,helper=helper,manager=manager,outer_vtable=word(outer),helper_vtable=word(helper),segments=segments,events=events,writes=writes,prepared=prepared,executed=[dict(offset=a,size=n,hex=h) for (a,n),h in sorted(pcs.items())],invalid=invalid)
