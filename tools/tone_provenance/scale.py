"""Bounded original-code replay; callers supply the exact decoded image.

SPDX-License-Identifier: GPL-2.0-only
"""
from hashlib import sha256
import struct
import unicorn as uc
from unicorn import arm_const as arm
B=0x02000000

def require(a,b,note):
    if a!=b:raise ValueError(f'{note}: {a!r} != {b!r}')

def model(r5,r8):
    p=min(r5,0x800000);seed=8192;threshold=None;path='high'
    if p<8192:
        if r8==0:return dict(boundary='divide_zero_handler',p=p)
        threshold=0x4000000//r8;q=(p<<13)//threshold
        if p<threshold:seed=q;r7=8192;path='low_overwrite'
        else:r7=q;path='low_retain'
    elif p<=0x20000:r7=((p*r8)&0xFFFFFFFF)>>13;path='high_direct'
    elif p<=0x100000:r7=(((p>>2)*(r8>>1))&0xFFFFFFFF)>>10;path='high_shift2_1'
    else:r7=(((p>>3)*(r8>>3))&0xFFFFFFFF)>>7;path='high_shift3_3'
    r6=((r7>>4)&0x1FFFFF) if r7>0x20000 else 8192
    sb=min(r7,0x20000);sl=8192;sp0=sp4=8192
    if r6<0x4000:sp0=r6
    elif r6==0x4000:sp4=0x4000
    else:
        sp4=0x4000;x=r6>>1
        if x<=0xFFE0:sp0=x
        else:
            if x>0x7FF00:sl=8192
            elif x>0x3FF80:sl=0x10000
            elif x>0x1FFC0:sl=0x8000
            else:sl=0x4000
            sp0=((x<<12)&0xFFFFFFFF)//(sl>>1)
    return dict(p=p,r8=r8,threshold=threshold,path=path,r7=r7,r6=r6,sb=sb,sl=sl,sp0=sp0,sp4=sp4,sp18=seed)

def replay(data,allowed,name,r5,half=8192,magic=True,config53=0,delta=0):
    vm=uc.Uc(uc.UC_ARCH_ARM,uc.UC_MODE_ARM);vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    for a,n in ((B,0x1000000),(0x10000000,0x400000),(0x40400000,0x100000)):vm.mem_map(a,n)
    vm.mem_write(B,data[:0x1000000]);vm.mem_protect(B,0x1000000,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
    vm.reg_write(arm.UC_ARM_REG_CPSR,0xD3);vm.reg_write(arm.UC_ARM_REG_C1_C0_2,0xF00000);vm.reg_write(arm.UC_ARM_REG_FPEXC,0x40000000)
    job=0x10100000+delta;recipe=job+0xE0C4;sp=0x103E0000;stop=0x103F0000;phase='';writes=[];segments=[];pcs={};invalid=[];trace=sha256();reads=[]
    def reg(n,v=None):
        k=getattr(arm,'UC_ARM_REG_'+n.upper())
        if v is None:return vm.reg_read(k)
        vm.reg_write(k,v)
    def word(a,n=4):return int.from_bytes(vm.mem_read(a,n),'little')
    def code(cpu,pc,n,_):
        off=pc-B;require(any(a<=off and off+n<=z for a,z in allowed),True,f'audited instruction {off:X}')
        raw=bytes(cpu.mem_read(pc,n));require(raw,data[off:off+n],'original RX instruction');pcs[(off,n)]=raw.hex();trace.update(struct.pack('<II',off,n)+raw)
    def write(cpu,kind,a,n,v,_):
        stack=sp-0x4000<=a and a+n<=sp
        ok=stack or phase=='recipe_constructor' and recipe<=a and a+n<=recipe+0x104 or phase=='frame' and job+0x240<=a and a+n<=job+0x264 or phase=='recipe_store' and (a,n,reg('pc')-B)==(recipe+0x9C,4,0x7198D4)
        require(ok,True,f'write boundary {phase}:{a:X}/{n}');writes.append(dict(phase=phase,pc=reg('pc')-B,address=a,size=n,value=v))
    def read(cpu,kind,a,n,v,_):
        if 0x4041F420<=a<0x4041F426:reads.append(dict(phase=phase,pc=reg('pc')-B,address=a,size=n))
    def fault(cpu,kind,a,n,v,_):invalid.append(dict(phase=phase,pc=reg('pc')-B,address=a,size=n,kind=kind));return False
    vm.hook_add(uc.UC_HOOK_CODE,code);vm.hook_add(uc.UC_HOOK_MEM_WRITE,write);vm.hook_add(uc.UC_HOOK_MEM_READ,read);vm.hook_add(uc.UC_HOOK_MEM_INVALID,fault)
    def run(label,entry,regs=None,end=None,keep=False):
        nonlocal phase
        phase=label
        if not keep:reg('sp',sp)
        reg('lr',stop)
        for k,v in (regs or {}).items():reg(k,v)
        begin={k:reg(k) for k in ('r0','r4','r5','r8','sp')};target=B+end if end is not None else stop
        vm.emu_start(B+entry,target,count=100000);require(reg('pc'),target,'bounded entry endpoint')
        segments.append(dict(phase=label,entry=entry,end=target,entry_registers=begin,exit_sp=reg('sp')))
    run('recipe_constructor',0x7B1D4C,{'r0':recipe});require(word(recipe+0x9C),8192,'native recipe initial word')
    run('frame',0x65EED0,{'r0':job},0x65EF08);frame=reg('sp');require(frame,sp-0x40,'original combined frame')
    fixture_magic=0xA55A5AA5 if magic else 0
    vm.mem_write(0x4041F420,struct.pack('<IH',fixture_magic,half))
    run('global_input',0x65EF1C,end=0x65EF3C,keep=True)
    from_ram=half if magic else 8192;require(reg('r8'),from_ram,'original magic and halfword source')
    run('config53_guard',0x65EF48,{'r0':config53},0x65EF54,True)
    r8=8192 if config53 else from_ram;require(reg('r8'),r8,'native config53 conditional reset')
    expected=model(r5,r8);negative=expected.get('boundary')=='divide_zero_handler'
    run('arithmetic',0x65F008,{'r5':r5},0x2E0486 if negative else 0x65F0D8,True)
    seed_writes=[w for w in writes if w['address']==frame+0x18]
    if negative:
        require([(w['pc'],w['value']) for w in seed_writes],[(0x65F024,8192)],'seed exists before zero-handler boundary')
        observed=dict(boundary_pc=reg('pc')-B,thumb=bool(reg('cpsr')&0x20),recipe_word=word(recipe+0x9C),recipe_store_executed=False)
        require(observed['thumb'],True,'original BLX reached Thumb boundary')
    else:
        observed={k:reg(k) for k in ('r5','r6','r7','r8','sb','sl')};observed.update(sp0=word(frame),sp4=word(frame+4),sp18=word(frame+0x18))
        require(observed,dict(r5=expected['p'],r6=expected['r6'],r7=expected['r7'],r8=r8,sb=expected['sb'],sl=expected['sl'],sp0=expected['sp0'],sp4=expected['sp4'],sp18=expected['sp18']),'native arithmetic and side values vs independent width model')
        expected_writes=[(0x65F024,8192)]+([(0x65F04C,expected['sp18'])] if expected['path']=='low_overwrite' else[])
        require([(w['pc'],w['value']) for w in seed_writes],expected_writes,'exact seed/overwrite history')
        require(reg('sp'),frame,'arithmetic keeps original frame')
        run('recipe_receiver',0x65F150,end=0x65F160,keep=True);require(reg('fp'),recipe,'same job recipe pointer derived natively')
        run('recipe_store',0x65F188,end=0x65F194,keep=True)
        stores=[w for w in writes if w['phase']=='recipe_store'];require(stores,[dict(phase='recipe_store',pc=0x7198D4,address=recipe+0x9C,size=4,value=expected['sp18'])],'full word store from same stack slot')
        require(word(recipe+0x9C),expected['sp18'],'final recipe word')
    require(bytes(vm.mem_read(B,0x1000000)),data[:0x1000000],'RX image preserved');require(invalid,[],'no invalid memory access')
    ranges=[]
    for a,n in sorted(pcs):
        if ranges and a<=ranges[-1][1]:ranges[-1][1]=max(ranges[-1][1],a+n)
        else:ranges.append([a,a+n])
    return dict(name=name,job=job,recipe=recipe,frame=frame,fixtures=dict(r5_at65F008=r5,global_magic=fixture_magic,global_halfword=half,config53_return=config53),ram_r8=from_ram,effective_r8=r8,model=expected,observed=observed,seed_writes=seed_writes,global_reads=reads,writes=writes,segments=segments,trace_sha256=trace.hexdigest(),executed_range_hashes=[dict(start=a,end_exclusive=z,sha256=sha256(data[a:z]).hexdigest()) for a,z in ranges],invalid=invalid,actual_capture_proven=False)

SPECS=[('zero_p', 0, 8192, True, 0, 0), ('one_p', 1, 8192, True, 0, 0), ('low8191', 8191, 8192, True, 0, 0), ('threshold_below', 4095, 16384, True, 0, 0), ('threshold_equal', 4096, 16384, True, 0, 0), ('threshold_above', 4097, 16384, True, 0, 0), ('high8192', 8192, 8192, True, 0, 0), ('high_direct_edge', 131072, 65535, True, 0, 0), ('high_shift2', 131073, 65535, True, 0, 0), ('high_shift2_edge', 1048576, 65535, True, 0, 0), ('high_shift3', 1048577, 65535, True, 0, 0), ('cap_edge', 8388608, 65535, True, 0, 0), ('cap_u32', 4294967295, 65535, True, 0, 0), ('integer_zero', 8191, 1, True, 0, 0), ('magic_invalid', 4096, 65535, False, 0, 0), ('config53_reset', 4096, 65535, True, 1, 0), ('config53_nonboolean', 4096, 65535, True, 255, 0), ('zero_r8_low', 4096, 0, True, 0, 0), ('zero_r8_high', 8192, 0, True, 0, 0), ('relocated', 4095, 16384, True, 0, 1048576)]

def run_cases(data,allowed):
    return [replay(data,allowed,*spec) for spec in SPECS]
