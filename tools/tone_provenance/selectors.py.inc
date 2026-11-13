"""Pinned original leaf replay; no filesystem, services, MMIO or CP15. GPL-2.0-only."""
import hashlib,json,struct
import capstone
import unicorn as uc
from unicorn import arm_const as arm
BASE = 33554432
PIN = '1b87bf35b290e4b4e8910beb4055c34f97504b65e249ad65e5ccc0402bd14cfc'
SIZE = 16838656
sha = lambda b: hashlib.sha256(b).hexdigest()
SPANS = [('ARM', 5159672, 5159936), ('ARM', 5159396, 5159672), ('ARM', 7108808, 7108840), ('ARM', 7254660, 7254736), ('ARM', 7253368, 7253432), ('ARM', 5148500, 5148568), ('ARM', 5682108, 5682116), ('ARM', 7253872, 7253972), ('DATA', 5159248, 5159252), ('DATA', 5160452, 5160460), ('DATA', 7254796, 7254800), ('DATA', 10349240, 10349256), ('DATA', 10380700, 10380704), ('DATA', 10380732, 10380736)]
ALLOWED = [(5159500, 5159512), (5159832, 5159880), (7108808, 7108840), (7254660, 7254736)]

def require(ok, note):
    if not ok:
        raise ValueError(note)

def static(data):
    word = lambda a: struct.unpack_from('<I', data, a)[0]
    branches = []
    for a, target in [(5159680, 5159552), (5159560, 5159396), (5159508, 7108824), (5159836, 7108816), (5159852, 7254660), (5159860, 7108832), (5159876, 7254660), (5159804, 7253692), (5159932, 7253872), (5159720, 7887132), (5148544, 5221996), (5148548, 5682108)]:
        w = word(a)
        imm = w & 16777215
        if imm & 8388608:
            imm -= 16777216
        require(w >> 24 == 235 and a + 8 + 4 * imm == target, 'raw A32 BL target')
        branches.append({'site': hex(a), 'target': hex(target), 'link': True, 'condition': 'AL'})
    literals = []
    for a, expected in [(5159684, 1077978460), (5159844, 1078439452), (5159868, 1078439452), (5159920, 1078439452), (7254684, 43903632)]:
        w = word(a)
        require(w & 259981312 == 85917696, 'PC literal load')
        loc = a + 8 + (w & 4095 if w & 8388608 else -(w & 4095))
        require(word(loc) == expected, 'literal target')
        literals.append({'pc': hex(a), 'literal_offset': hex(loc), 'value': hex(expected)})
    desc = []
    for selector, offset in [(5, 17), (6, 18)]:
        a = 10349200 + 8 * selector
        off, mask, shift, pad = struct.unpack_from('<IBBH', data, a)
        require((off, mask, shift) == (offset, 255, 0), 'descriptor')
        desc.append({'selector': selector, 'record': hex(a), 'payload_offset': off, 'object_offset': off + 4, 'mask': mask, 'shift': shift, 'expression': 'u8(input_halfword)'})
    ranges = [{'kind': kind, 'start': hex(lo), 'end_exclusive': hex(hi), 'bytes': hi - lo, 'sha256': sha(data[lo:hi])} for kind, lo, hi in SPANS]
    return {'source_ranges': ranges, 'direct_branches': branches, 'literal_loads': literals, 'descriptors': desc, 'paths': [{'selector': 5, 'caller_entry': '0x4ebaf8', 'call': '0x4ebbac', 'getter': '0x6c78d0', 'owner': 'entry R0 preserved in R4', 'input': 'u16(word(owner+0x1c)+0x24)', 'receiver': '0x4047ae1c', 'destination': '0x4047ae31', 'immediate_storage_writer_leaf': '0x6c78c8; caller/lifecycle not established'}, {'selector': 6, 'caller_entry': '0x4ebaf8', 'call': '0x4ebbc4', 'getter': '0x6c78e0', 'owner': 'entry R0 preserved in R4', 'input': 'u16(word(owner+0x1c)+0x26)', 'receiver': '0x4047ae1c', 'destination': '0x4047ae32', 'default_producer': '4EBAF8 calls4EBA80, which calls4EB9E4;4EBA50 sets R1=0x20 then4EBA54 calls6C78D8'}], 'manager_flow': {'cache_base': '0x4040a55c', 'manager_cache_slot': '0x4040a5dc', 'guard': '0x4040a5d8', 'reader_call': '0x4ebb7c', 'reader_r2': 1, 'writer_call': '0x4ebbfc', 'writer_r2': 1, 'scratch_payload': '[0x4047ae20,0x4047ae50)', 'services_executed': False}, 'owner_slot_static_candidate': {'setup_entry': '0x4e8f54', 'sequence': '4E8F80→4FAE6C;4E8F84→56B3BC loads returned object+0x10;4E8F88 stores owner+0x1C', 'same_runtime_owner_instance_proven': False}, 'prior_tone_cross_reference': {'job_member_offset': '0x334', 'selector5_job_offset': '0x349', 'selector6_job_offset': '0x34a', 'constructor_defaults': [0, 32], 'selector6_ROM_table': '0x029e651c', 'ROM_words_for_indices32_40': [word(10380700), word(10380732)], 'new_scratch_to_job_copy_proven': False}}

def native(data, name, value5, value6, reset6=False, delta=0):
    cpu = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    cpu.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    code_size = len(data) + 4095 & ~4095
    cpu.mem_map(BASE, code_size)
    cpu.mem_write(BASE, data)
    cpu.mem_protect(BASE, code_size, uc.UC_PROT_READ | uc.UC_PROT_EXEC)
    owner = 269484032 + delta
    src = owner + 4096
    scratch = 1078439452
    sp = 272498688
    stop = 272564224
    for a, n in [(269484032, 65536), (1078435840, 4096), (272433152, 131072)]:
        cpu.mem_map(a, n)
    cpu.mem_write(owner + 28, struct.pack('<I', src))
    cpu.mem_write(scratch, b'\xa5' * 52)
    phase = ''
    writes = []
    reads = []
    trace = []
    entries = []
    reg = lambda k: cpu.reg_read(getattr(arm, 'UC_ARM_REG_' + k.upper()))

    def code(c, a, n, u):
        off = a - BASE
        require(any((lo <= off and off + n <= hi for lo, hi in ALLOWED)), 'outside allowed original code')
        require(bytes(c.mem_read(a, n)) == data[off:off + n], 'original instruction changed')
        trace.append({'phase': phase, 'pc': hex(off)})
        if off == 7254660:
            entries.append({'phase': phase, 'r0': hex(reg('r0')), 'selector': reg('r1'), 'value': reg('r2')})

    def memwrite(c, k, a, n, v, u):
        pc = reg('pc') - BASE
        stack = sp - 256 <= a and a + n <= sp
        require(stack or (pc, a, n) in {(7108808, src + 36, 2), (7108824, src + 38, 2), (7254728, scratch + 21, 1), (7254728, scratch + 22, 1)}, 'unexpected write')
        if not stack:
            writes.append({'phase': phase, 'pc': hex(pc), 'address': hex(a), 'bytes': n, 'value': v})

    def memread(c, k, a, n, v, u):
        require(BASE <= a and a + n <= BASE + len(data) or (owner <= a and a + n <= src + 256) or (1078435840 <= a and a + n <= 1078439936) or (sp - 256 <= a and a + n <= sp), 'unexpected read or MMIO')
        if not (sp - 256 <= a and a + n <= sp):
            reads.append({'phase': phase, 'pc': hex(reg('pc') - BASE), 'address': hex(a), 'bytes': n})
    cpu.hook_add(uc.UC_HOOK_CODE, code)
    cpu.hook_add(uc.UC_HOOK_MEM_WRITE, memwrite)
    cpu.hook_add(uc.UC_HOOK_MEM_READ, memread)

    def run(label, entry, regs, end=None):
        nonlocal phase
        phase = label
        cpu.reg_write(arm.UC_ARM_REG_CPSR, 211)
        cpu.reg_write(arm.UC_ARM_REG_SP, sp)
        cpu.reg_write(arm.UC_ARM_REG_LR, stop)
        for key, value in regs.items():
            cpu.reg_write(getattr(arm, 'UC_ARM_REG_' + key.upper()), value)
        until = BASE + end if end else stop
        cpu.emu_start(BASE + entry, until, count=1000)
        require(reg('pc') == until, 'bounded return/stop')
    run('supplied_source5_through_original_leaf', 7108808, {'r0': src, 'r1': value5})
    run('supplied_source6_through_original_leaf', 7108824, {'r0': src, 'r1': value6})
    if reset6:
        run('original_default_prefix', 5159500, {'r4': owner}, 5159512)
    source_values = [int.from_bytes(cpu.mem_read(src + off, 2), 'little') for off in (36, 38)]
    run('continuous_getter_setter_pair', 5159832, {'r4': owner}, 5159880)
    expected = bytes([source_values[0] & 255, source_values[1] & 255])
    actual = bytes(cpu.mem_read(scratch + 21, 2))
    require(actual == expected, 'independent low-byte formula')
    entire = bytes(cpu.mem_read(scratch, 52))
    require(entire[:21] + entire[23:] == b'\xa5' * 50, 'adjacent scratch unchanged')
    require([(x['r0'], x['selector'], x['value']) for x in entries] == [(hex(scratch), 5, source_values[0]), (hex(scratch), 6, source_values[1])], 'actual call arguments')
    require(bytes(cpu.mem_read(BASE, len(data))) == data, 'ROM preserved')
    return {'name': name, 'fixture': {'source5_argument': value5, 'source6_argument': value6, 'default_prefix_entered_separately': reset6, 'owner': hex(owner), 'source_pointer_host_supplied': hex(src), 'scratch_before': 'A5', 'actual_camera_state': False}, 'source_halfwords': source_values, 'setter_entries': entries, 'destination_bytes': list(actual), 'all_other_scratch_bytes_unchanged': True, 'writes': writes, 'reads': reads, 'trace': trace, 'services_MMIO_CP15_executed': False, 'full_entry_or_menu_reached': False}

HISTORICAL_SCRIPT_SHA256='bb6e7451174f9902a6991e66be91059a209f9e51fc7a2c9409f5ef8f5716a7e0'
HISTORICAL_LIMITS=['Only two selected direct A32 call paths admitted; all84 pattern hits remain candidates unless explicitly inspected.', 'No exhaustive Thumb, indirect-call, receiver-alias or alternate-entry search.', 'Owner+1C pointer and source leaf inputs are supplied fixtures; setup candidate does not prove same runtime object.', 'Default prefix and source setters are separate entries; intervening service/guard calls and preservation across them are not emulated.', 'No menu label, menu event, physical field name, actual capture reachability, scratch-to-job copy, full boot or buffer-reuse history established.', 'Existing job constructor defaults and ROM tone lookup are previous evidence, not a new continuous chain from this scratch object.']
def reconstruct(data):
    require(len(data)==SIZE and sha(data)==PIN,'input identity before replay')
    facts=static(data)
    cases=[native(data,*args) for args in [('baseline',0,0x20,False,0),('high_bytes',0x144,0x128,False,0),('maximum',0xffff,0xffff,False,0),('default_overwrites_source6',0x154,0x1234,True,0),('relocated_owner',0x144,0x128,False,0x4000)]]
    return {'schema':'II-TONE-SELECTOR-PRODUCER-35-v1','input_bytes':len(data),'input_sha256':PIN,'script_sha256':HISTORICAL_SCRIPT_SHA256,'versions':{'capstone':capstone.__version__,'unicorn':uc.__version__},'static':facts,'native_cases':cases,'confirmed_setter_calls':2,'limits':HISTORICAL_LIMITS}
