"""Original II27 bounded replay; no physical shooting defaults are inferred.

SPDX-License-Identifier: GPL-2.0-only
"""
from hashlib import sha256
import struct
import unicorn as uc
from unicorn import arm_const as arm
B=0x02000000

def require(a,b,note):
    if a!=b:raise ValueError(f'{note}: {a!r} != {b!r}')

def replay(data,allowed,name,delta=0,producer=None):
    vm=uc.Uc(uc.UC_ARCH_ARM,uc.UC_MODE_ARM);vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    for a,n in ((B,0x1000000),(0x10000000,0x400000),(0x40400000,0x100000)):vm.mem_map(a,n)
    vm.mem_write(B,data[:0x1000000]);vm.mem_protect(B,0x1000000,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
    vm.reg_write(arm.UC_ARM_REG_CPSR,0xD3);vm.reg_write(arm.UC_ARM_REG_C1_C0_2,0xF00000);vm.reg_write(arm.UC_ARM_REG_FPEXC,0x40000000)
    job=0x10100000+delta;recipe=job+0xE0C4;context=job+0xE608
    sp=0x103E0000;stop=0x103F0000;phase='';segments=[];writes=[];prepared=[];pcs={};invalid=[];trace=sha256();counts={}
    def reg(n,v=None):
        k=getattr(arm,'UC_ARM_REG_'+n.upper())
        if v is None:return vm.reg_read(k)
        vm.reg_write(k,v)
    def word(a,n=4):return int.from_bytes(vm.mem_read(a,n),'little')
    def host(off,v,n):
        # Host fixtures are upstream job fields, never recipe/context inputs.
        require((off,n) in {(0x3C,1),(0x6D,1),(0x2080,1)}|{(i,2) for i in range(0x264,0x26C,2)}|{(i,2) for i in range(0x274,0x284,2)},True,'upstream fixture boundary')
        vm.mem_write(job+off,v.to_bytes(n,'little'));prepared.append(dict(job_offset=off,size=n,value=v))
    def code(cpu,pc,n,_):
        off=pc-B;require(any(a<=off and off+n<=z for a,z in allowed),True,f'audited instruction {off:X}')
        raw=bytes(cpu.mem_read(pc,n));require(raw,data[off:off+n],'unchanged original instruction')
        pcs[(off,n)]=raw.hex();trace.update(struct.pack('<II',off,n)+raw);counts[phase]=counts.get(phase,0)+1
    def write(cpu,kind,a,n,v,_):
        pc=reg('pc')-B
        stack=sp-0x4000<=a and a+n<=sp
        if phase=='startup':ok=0x404094B0<=a and a+n<=0x4041F360
        elif phase=='constructors':ok=stack or job+0xE0A4<=a and a+n<=context+0x7BC4
        elif phase=='recipe_producer':ok=stack or (a,n,pc) in {(recipe+0xBC,4,0x784CA0),(recipe+0xA4,1,0x7198C4)}
        elif phase=='formula':ok=stack or (a,n) in {(context+0x7A68,4),(context+0x60DC,2),(context+0x7A74,4)}|{(context+i,2) for i in range(0x6010,0x6018,2)}
        else:ok=stack
        require(ok,True,f'write boundary {phase}:{pc:X}:{a:X}/{n}')
        if phase!='startup':writes.append(dict(phase=phase,pc=pc,address=a,size=n,value=v))
    def fault(cpu,kind,a,n,v,_):invalid.append(dict(phase=phase,pc=reg('pc')-B,kind=kind,address=a,size=n));return False
    vm.hook_add(uc.UC_HOOK_CODE,code);vm.hook_add(uc.UC_HOOK_MEM_WRITE,write);vm.hook_add(uc.UC_HOOK_MEM_INVALID,fault)
    def run(label,entry,regs=None,end=None,keep_stack=False):
        nonlocal phase
        phase=label
        if not keep_stack:reg('sp',sp)
        reg('lr',stop)
        for k,v in (regs or {}).items():reg(k,v)
        begin={k:reg(k) for k in ('r0','r1','r2','r4','r5','r6','sp')}
        target=B+end if end is not None else stop
        vm.emu_start(B+entry,target,count=200000)
        require(reg('pc'),target,'bounded entry return')
        segments.append(dict(phase=label,entry=entry,end=target,entry_registers=begin,exit_sp=reg('sp')))
    def snapshot():return dict(flag92=word(recipe+0x92,1),flagA4=word(recipe+0xA4,1),wordBC=word(recipe+0xBC),word9C=word(recipe+0x9C),prior60DC=word(context+0x60DC,2),prior7A68=word(context+0x7A68),channels=[word(context+i,2) for i in (8,10,12,14)])
    run('startup',0x288,end=0x2A0)
    require(bytes(vm.mem_read(0x404094B0,0x15EB0)),data[0xA84504:0xA9A3B4],'native initialized-data copy')
    run('constructors',0x653BF8,{'r0':job},0x653C38)
    ctor=snapshot();require(ctor,dict(flag92=0,flagA4=0,wordBC=0,word9C=8192,prior60DC=8192,prior7A68=4096,channels=[420,256,256,320]),'native constructor inputs')
    if producer is not None:
        for off,n,v in [(0x3C,1,producer['gate3c']),(0x6D,1,producer['gate6d']),(0x2080,1,producer['gate2080'])]+[(0x264+2*i,2,v) for i,v in enumerate(producer['halves'])]+[(0x274+2*i,2,v) for i,v in enumerate(producer['sums'])]:host(off,v,n)
        run('recipe_producer',0x658EBC,{'r0':job},0x658EC8)
        frame=reg('sp');require(frame,sp-0xE70,'original producer stack frame')
        run('recipe_producer',0x658ED4,end=0x658EE0,keep_stack=True)
        require(reg('r4'),recipe,'original same-job recipe address derivation')
        run('recipe_producer',0x658F84,end=0x658F88,keep_stack=True)
        require(reg('r6'),job+0x2000,'original guard base derivation')
        run('recipe_producer',0x659048,end=0x65911C,keep_stack=True)
        require(reg('sp'),frame,'same original frame across separated slices')
        summed=[(producer['sums'][i]+producer['sums'][i+4])&0xFFFF for i in range(4)]
        expected_bc=(max(producer['halves'])//10+100)&0xFFFF if producer['gate3c'] or producer['gate6d'] else max(summed)
        require(word(recipe+0xBC),expected_bc,'native recipe BC vs independent width-correct formula')
        require(word(recipe+0xA4,1),producer['gate2080'],'native A4 copied from job2080')
        require([(w['pc'],w['address'],w['size'],w['value']) for w in writes if w['phase']=='recipe_producer' and recipe<=w['address']<recipe+0x104],[(0x784CA0,recipe+0xBC,4,expected_bc),(0x7198C4,recipe+0xA4,1,producer['gate2080'])],'two ordered native recipe writes including zero A4')
    inputs=snapshot()
    run('formula',0x4DF834,{'r0':0x10010000,'r1':recipe,'r2':context})
    c=0xFFBF if inputs['flag92'] else 0xFFFB
    d=inputs['prior7A68'] if inputs['flagA4'] else ((c-inputs['wordBC'])&0xFFFFFFFF)>>2
    x=inputs['prior60DC'] if inputs['flagA4'] else inputs['word9C']&0xFFFF
    m=min([256]+inputs['channels']);den=(d<<2)&0xFFFFFFFF
    require(den!=0 and x!=0 and m!=0,True,'nonzero model denominators')
    a=((c<<13)&0xFFFFFFFF)//den;k=((a<<8)&0xFFFFFFFF)//m;expected=((k<<13)&0xFFFFFFFF)//x
    side=[min((((g*k)&0xFFFFFFFF)>>13)&0xFFFF,0x7FF) for g in inputs['channels']]
    require(word(context+0x7A68),d,'retained or overwritten context word');require(word(context+0x60DC,2),x,'context halfword')
    require(word(context+0x7A74),expected,'native context result');require([word(context+i,2) for i in range(0x6010,0x6018,2)],side,'four native side outputs')
    formula_writes=[w for w in writes if w['phase']=='formula' and w['address']>=context and w['address']<context+0x7BC4]
    require([(w['pc'],w['size']) for w in formula_writes],([] if inputs['flagA4'] else [(0x719618,4),(0x71960C,2)])+[(0x4F98DC,2),(0x4F9954,2),(0x4F9948,2),(0x4F98D0,2),(0x72D094,4)],'exact native overwrite guard and output store order')
    run('getter',0x4FA83C,{'r0':context});require(reg('r0'),expected,'native result getter')
    require(bytes(vm.mem_read(B,0x1000000)),data[:0x1000000],'RX image unchanged');require(invalid,[],'no invalid memory access')
    ranges=[]
    for off,n in sorted(pcs):
        if ranges and off<=ranges[-1][1]:ranges[-1][1]=max(ranges[-1][1],off+n)
        else:ranges.append([off,off+n])
    return dict(name=name,job=job,recipe=recipe,context=context,constructor=ctor,inputs=inputs,producer_fixture=producer,prepared=prepared,calculation=dict(c=c,d=d,x=x,minimum=m,a=a,k=k,result=expected,side=side),segments=segments,writes=writes,formula_writes=formula_writes,instruction_counts=counts,trace_sha256=trace.hexdigest(),executed_range_hashes=[dict(start=a,end_exclusive=z,sha256=sha256(data[a:z]).hexdigest()) for a,z in ranges],invalid=invalid,actual_capture_history_proven=False)

def run_cases(data,allowed):
    base=dict(gate3c=0,gate6d=0,gate2080=0,halves=[10,100,1000,65535],sums=[1,2,3,4,5,6,7,8])
    specs=[('constructors',0,None),('sum',0,base),('sum_wrap',0,{**base,'sums':[65535,65534,65533,65532,2,4,6,8]}),('divide_3c',0,{**base,'gate3c':1}),('divide_6d',0,{**base,'gate6d':1}),('retain',0,{**base,'gate2080':1}),('retain_nonboolean',0,{**base,'gate2080':255}),('relocated',0x100000,{**base,'gate3c':1})]
    cases=[replay(data,allowed,n,d,p) for n,d,p in specs]
    require(cases[3]['calculation'],cases[4]['calculation'],'either guard chooses divide branch');require(cases[5]['calculation'],cases[6]['calculation'],'any nonzero A4 retains context');require(cases[3]['calculation'],cases[7]['calculation'],'relocated input producer calculation')
    return cases
