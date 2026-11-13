"""Bounded original-code replay; callers supply the exact decoded image.

SPDX-License-Identifier: GPL-2.0-only
"""
from hashlib import sha256
import struct
import unicorn as uc
from unicorn import arm_const as arm
B=0x02000000

def require(a,b,note):
    if a!=b:raise ValueError(note)

def replay(data,label,value,delta=0):
    vm=uc.Uc(uc.UC_ARCH_ARM,uc.UC_MODE_ARM);vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    vm.mem_map(B,0x1000000);vm.mem_map(0x10000000,0x400000);vm.mem_write(B,data[:0x1000000]);vm.mem_protect(B,0x1000000,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
    owner=0x10010000+delta;job=0x10100000+delta;sp=0x103E0000;allowed=[(0x63106C,0x631074),(0x65606C,0x65608C),(0x73DFC0,0x73DFC8),(0x71BD0C,0x71BD14)];writes=[];reads=[];trace=[];invalid=[]
    reg=lambda n:vm.reg_read(getattr(arm,'UC_ARM_REG_'+n.upper()))
    word=lambda a:int.from_bytes(vm.mem_read(a,4),'little')
    vm.mem_write(owner+0x220,struct.pack('<I',job));vm.mem_write(job+0x24D8,bytes([value]));vm.mem_write(job+0x6D,b'\xA5')
    def code(cpu,pc,n,_):
        off=pc-B;require(any(a<=off and off+n<=z for a,z in allowed),True,'bounded original address');raw=bytes(cpu.mem_read(pc,n));require(raw,data[off:off+n],'original instruction');trace.append(dict(offset=off,size=n))
    def write(cpu,kind,a,n,v,_):
        require(sp-0x48<=a and a+n<=sp or (a,n,reg('pc')-B)==(job+0x6D,1,0x656088),True,'native write boundary');writes.append(dict(pc=reg('pc')-B,address=a,size=n,value=v))
    def read(cpu,kind,a,n,v,_):
        if a in (owner+0x220,job+0x24D8):reads.append(dict(pc=reg('pc')-B,address=a,size=n))
    def fault(cpu,kind,a,n,v,_):invalid.append(dict(pc=reg('pc')-B,address=a,size=n,kind=kind));return False
    vm.hook_add(uc.UC_HOOK_CODE,code);vm.hook_add(uc.UC_HOOK_MEM_WRITE,write);vm.hook_add(uc.UC_HOOK_MEM_READ,read);vm.hook_add(uc.UC_HOOK_MEM_INVALID,fault)
    for n,v in [('CPSR',0xD3),('R4',owner),('SP',sp),('LR',0x103F0000)]:vm.reg_write(getattr(arm,'UC_ARM_REG_'+n),v)
    vm.emu_start(B+0x63106C,B+0x65608C,count=1000)
    require(reg('pc'),B+0x65608C,'stop before subsequent processing');require(reg('r4'),job,'caller-loaded job retained by callee');require(reg('sp'),sp-0x48,'native combined frame')
    require(word(reg('sp')+4),job+0x24C0,'embedded address, not loaded pointer');require(bytes(vm.mem_read(job+0x6D,1)),bytes([value]),'native byte copy')
    require(reads,[dict(pc=0x63106C,address=owner+0x220,size=4),dict(pc=0x71BD0C,address=job+0x24D8,size=1)],'exact pointer then embedded-byte reads')
    require([(w['pc'],w['address'],w['size'],w['value']) for w in writes if w['address']==job+0x6D],[(0x656088,job+0x6D,1,value)],'one original byte store');require(invalid,[],'no faults');require(bytes(vm.mem_read(B,0x1000000)),data[:0x1000000],'RX image preserved')
    return dict(case=label,owner=owner,job=job,embedded_input=job+0x24C0,source_byte=job+0x24D8,output_byte=job+0x6D,value=value,frame=reg('sp'),fixtures=['owner+220 pointer','embedded source byte','destination A5 canary'],reads=reads,writes=writes,executed=trace,source_ranges=[dict(start=a,end_exclusive=z,sha256=sha256(data[a:z]).hexdigest()) for a,z in allowed],actual_capture_proven=False)


def run_cases(data):
    return [replay(data,"zero",0),replay(data,"byte_ff",255),replay(data,"relocated",128,0x100000)]
