"""Original II31 instruction replay; firmware supplied separately.

SPDX-License-Identifier: GPL-2.0-only
"""
from hashlib import sha256
import json,struct
import unicorn as uc
from unicorn import arm_const as arm
B=0x02000000

def require(a,b,n):
    if a!=b:raise ValueError(f'{n}: {a!r} != {b!r}')

def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode('ascii')

class VM:
    def __init__(self,data,allowed,delta=0):
        self.data=data;self.allowed=allowed;self.job=0x10100000+delta;self.recipe=self.job+0xE0C4;self.context=self.job+0xE608;self.sp=0x103E0000;self.stop=0x103F0000;self.phase='';self.writes=[];self.reads=[];self.divisions=[];self.segments=[];self.pcs=set();self.trace=sha256();self.constructor_hash=sha256();self.constructor_count=0
        self.vm=uc.Uc(uc.UC_ARCH_ARM,uc.UC_MODE_ARM);self.vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
        for base,size in [(B,0x1000000),(0x10000000,0x400000),(0x40400000,0x100000)]:self.vm.mem_map(base,size)
        self.vm.mem_write(B,data[:0x1000000]);self.vm.mem_protect(B,0x1000000,uc.UC_PROT_READ|uc.UC_PROT_EXEC)
        for n,v in [('cpsr',0xD3),('c1_c0_2',0xF00000),('fpexc',0x40000000)]:self.reg(n,v)
        self.vm.hook_add(uc.UC_HOOK_CODE,self.code);self.vm.hook_add(uc.UC_HOOK_MEM_WRITE,self.write);self.vm.hook_add(uc.UC_HOOK_MEM_READ,self.read)
    def reg(self,n,v=None):
        k=getattr(arm,'UC_ARM_REG_'+n.upper())
        if v is None:return self.vm.reg_read(k)
        self.vm.reg_write(k,v)
    def word(self,a,n=4):return int.from_bytes(self.vm.mem_read(a,n),'little')
    def code(self,cpu,pc,n,_):
        off=pc-B;require(any(a<=off and off+n<=z for a,z in self.allowed),True,f'allowed original instruction {off:X}')
        raw=bytes(cpu.mem_read(pc,n));require(raw,self.data[off:off+n],'original RX instruction');self.pcs.add((off,n));self.trace.update(struct.pack('<II',off,n)+raw)
        if off==0x712C44:self.divisions.append(dict(phase=self.phase,numerator=self.reg('r0'),denominator=self.reg('r1'),lr=self.reg('lr'),sp=self.reg('sp')))
    def write(self,cpu,kind,a,n,v,_):
        pc=self.reg('pc')-B;stack=self.sp-0x4000<=a and a+n<=self.sp
        if self.phase=='startup':ok=0x404094B0<=a and a+n<=0x4041F360
        elif self.phase=='tone_constructor':ok=stack or self.job+0xE0A4<=a and a+n<=self.context+0x7BC4
        elif self.phase=='owner_constructor':ok=stack or self.job+0x30C<=a and a+n<=self.job+0x368
        elif self.phase.startswith('setter'):ok=stack or (pc,a,n)==(0x6EB2C8,self.job+0x349,1) or (pc,a,n)==(0x6EB2C8,self.job+0x34A,1)
        elif self.phase=='scale_frame':ok=stack or self.job+0x240<=a and a+n<=self.job+0x264
        elif self.phase=='scale_store':ok=stack or (pc,a,n)==(0x7198D4,self.recipe+0x9C,4)
        elif self.phase=='retain_control':ok=stack or (pc,a,n)==(0x7198C4,self.recipe+0xA4,1)
        elif self.phase=='consumer':ok=stack or (a,n) in {(self.context+0x7A68,4),(self.context+0x60DC,2),(self.context+0x7A74,4)}|{(self.context+i,2) for i in range(0x6010,0x6018,2)}
        else:ok=stack
        require(ok,True,f'write boundary {self.phase}:{pc:X}:{a:X}/{n}')
        event=dict(phase=self.phase,pc=pc,address=a,size=n,value=v)
        if self.phase in ('startup','tone_constructor'):
            self.constructor_count+=1;self.constructor_hash.update(canonical(event)+b'\n')
        else:self.writes.append(event)
    def read(self,cpu,kind,a,n,v,_):
        if self.phase in ('r5_lookup','optional_scale') and (a==self.job+0x52 or self.job+0x334<=a<self.job+0x368 or B+0x9E651C<=a<B+0x9E691C or B+0x9DDFB4<=a<B+0x9DDFF8 or B+0x9DEAB8<=a<B+0x9DEAC8 or B+0xA77CAC<=a<B+0xA77CD4):self.reads.append(dict(phase=self.phase,pc=self.reg('pc')-B,address=a,size=n))
    def run(self,label,entry,regs=None,end=None,keep=False):
        self.phase=label
        if not keep:self.reg('sp',self.sp)
        self.reg('lr',self.stop)
        for k,v in (regs or {}).items():self.reg(k,v)
        before={k:self.reg(k) for k in ('r0','r1','r2','r4','r5','sp')};target=B+end if end is not None else self.stop
        self.vm.emu_start(B+entry,target,count=250000);require(self.reg('pc'),target,'bounded endpoint')
        self.segments.append(dict(phase=label,entry=entry,end=target,entry_registers=before,exit_sp=self.reg('sp')))
    def finish(self):
        require(bytes(self.vm.mem_read(B,0x1000000)),self.data[:0x1000000],'RX image preserved')
        spans=[]
        for a,n in sorted(self.pcs):
            if spans and a<=spans[-1][1]:spans[-1][1]=max(spans[-1][1],a+n)
            else:spans.append([a,a+n])
        return dict(job=self.job,writes=self.writes,reads=self.reads,divisions=self.divisions,segments=self.segments,trace_sha256=self.trace.hexdigest(),constructor_events=dict(count=self.constructor_count,ordered_sha256=self.constructor_hash.hexdigest()),executed_ranges=[dict(start=a,end_exclusive=z,sha256=sha256(self.data[a:z]).hexdigest()) for a,z in spans],actual_capture_proven=False)

def upstream(data,allowed,name,value6=None,value5=None,flag52=0,delta=0):
    v=VM(data,allowed,delta);obj=v.job+0x334
    v.run('owner_constructor',0x65379C,{'r0':v.job,'r1':0},0x82DEF8)
    require(v.reg('r0'),obj,'native nested object address');require(v.word(obj),B+0xA77CAC,'native vtable');require((v.word(obj+0x15,1),v.word(obj+0x16,1)),(0,32),'native selector5/6 initial bytes')
    for selector,value in [(6,value6),(5,value5)]:
        if value is not None:v.run('setter'+str(selector),0x6EB284,{'r0':obj,'r1':selector,'r2':value})
    if flag52:v.vm.mem_write(v.job+0x52,bytes([flag52]))
    actual6=v.word(obj+0x16,1);actual5=v.word(obj+0x15,1);idx=(actual6-8 if flag52 else actual6)&255
    require(idx<120,True,'only audited ROM table prefix indices')
    expected=struct.unpack_from('<I',data,0x9E651C+4*idx)[0]
    v.run('r5_lookup',0x65EF4C,{'r4':v.job},0x65EF84);require(v.reg('r5'),expected,'native descriptor getter and ROM index')
    before=expected;factor=struct.unpack_from('<I',data,0x9DDFB4+4*(actual5-0x44))[0] if 0x44<=actual5<=0x54 else 8192
    expected=(((expected>>3)*(factor>>3))&0xFFFFFFFF)>>7 if factor!=8192 else expected
    v.run('optional_scale',0x65EFAC,{'r4':v.job,'r6':0},0x65EFE8);require(v.reg('r5'),expected,'optional original mapper and width-correct multiply')
    return dict(name=name,fixture=dict(setter6=value6,setter5=value5,job52=flag52,optional_path_entered_directly=True),native_fields=dict(selector6=actual6,selector5=actual5,vtable=v.word(obj)),index=idx,rom_r5=before,optional_factor=factor,adjusted_r5=expected,**v.finish())

def zero_consumer(data,allowed,name,r5,retain=False,delta=0):
    v=VM(data,allowed,delta)
    v.run('startup',0x288,end=0x2A0);require(bytes(v.vm.mem_read(0x404094B0,0x15EB0)),data[0xA84504:0xA9A3B4],'native initialized data copy')
    v.run('tone_constructor',0x653BF8,{'r0':v.job},0x653C38)
    require((v.word(v.recipe+0x9C),v.word(v.recipe+0xA4,1),v.word(v.context+0x60DC,2),v.word(v.context+0x7A68)),(8192,0,8192,4096),'native recipe/context initial values')
    v.run('scale_frame',0x65EED0,{'r0':v.job},0x65EF08);frame=v.reg('sp')
    v.run('scale_arithmetic',0x65F008,{'r5':r5},0x65F0D8,True)
    v.run('scale_receiver',0x65F150,end=0x65F160,keep=True)
    v.run('scale_store',0x65F188,end=0x65F194,keep=True)
    require(v.word(v.recipe+0x9C),r5,'same native recipe word from low arithmetic')
    if retain:v.run('retain_control',0x7198C4,{'r0':v.recipe,'r1':1})
    negative=r5==0 and not retain
    v.run('consumer',0x4DF834,{'r0':0x10010000,'r1':v.recipe,'r2':v.context},0x2E0486 if negative else None)
    target_writes=[w for w in v.writes if w['phase']=='consumer' and w['address']==v.context+0x7A74]
    if negative:
        require(v.word(v.context+0x60DC,2),0,'zero narrowed and stored');require(v.reg('sl'),0,'zero final denominator');require(target_writes,[],'no result store before handler');require(bool(v.reg('cpsr')&0x20),True,'Thumb handler entry');require(v.reg('lr'),B+0x712C40,'division BLX continuation')
    else:
        expected=32765 if retain else 67108864//r5
        require(v.word(v.context+0x7A74),expected,'completed native consumer result');require(len(target_writes),1,'one native result store')
    return dict(name=name,supplied_r5=r5,retain_control=retain,recipe=v.recipe,context=v.context,frame=frame,recipe9c=v.word(v.recipe+0x9C),context60dc=v.word(v.context+0x60DC,2),context7a68=v.word(v.context+0x7A68),observed_result=v.word(v.context+0x7A74) if target_writes else None,boundary='Thumb2E0486_before_first_handler_instruction' if negative else 'original_consumer_return',**v.finish())

def run_snapshot(data,allowed):
    specs=[('constructor',None,None,0,0),('selector6_40',40,None,0,0),('flag52_shift',40,None,1,0),('selector5_44',40,0x44,0,0),('selector5_54',40,0x54,0,0),('setter_byte_truncate',256,None,0,0),('relocated',40,0x44,0,0x100000)]
    result=dict(schema='II-TONE-UPSTREAM-31-native-v1',input_sha256=sha256(data).hexdigest(),probe_sha256='91840905f60cd926760378cb879d77318d68b405f0583aa1beb42d8c473f106e',engine=uc.__version__,allowed_ranges=[dict(start=x,end_exclusive=z,sha256=sha256(data[x:z]).hexdigest()) for x,z in allowed],upstream=[upstream(data,allowed,*s) for s in specs],zero_consumers=[zero_consumer(data,allowed,'zero',0),zero_consumer(data,allowed,'one',1),zero_consumer(data,allowed,'zero_retained',0,True),zero_consumer(data,allowed,'zero_relocated',0,False,0x100000)],limits=['Constructor prefix, setter, getter/table and optional arithmetic use separate original entries; actual upstream updates/config services are not executed.','Optional path entered directly: no claim that job7A/service predicate allows it in a live capture. R6 fixture0 is passed to mapper but mapper replaces R0 before use.','Zero consumer uses native recipe/context constructors and native scale arithmetic/store in sameVM, with supplied R5 and omitted global/config services. Retain control uses original A4 setter with supplied1.','Stops before first Thumb handler instruction; no handler return, exception semantics or hardware result inferred.'])
    return result
