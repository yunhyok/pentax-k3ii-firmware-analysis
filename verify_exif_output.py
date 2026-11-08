"""Verify Exif JPEG scatter output and its StoreImage service route.

SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import json
from pathlib import Path
import struct

from verify_findings import DECODED_SHA256, require, sha256
from verify_raw_path import branch_target
from verify_tone_path import BASE, check_words, load_image


EDGES = (
    (0x5662FC, 0x7DBB9C), (0x566308, 0x59779C),
    (0x513F2C, 0x7B2CC0), (0x7885E4, 0x76252C),
    (0x5A7D80, 0x833F3C), (0x762608, 0x7625D4), (0x76261C, 0x7C643C),
    (0x7625E8, 0x7C6810), (0x7625EC, 0x7C727C),
    (0x7C6480, 0x78497C), (0x7C6494, 0x6FEA38),
    (0x7C674C, 0x7C6658), (0x7C6678, 0x7C65D0),
    (0x7C692C, 0x7C6428), (0x7C6B90, 0x7CD064),
    (0x7CD4C8, 0x81D26C), (0x7CD4D0, 0x7DBB7C),
    (0x7CD4DC, 0x7CD3F0), (0x7CD498, 0x82D8B8),
    (0x7CD4A4, 0x7CD1E0), (0x7CD220, 0x81C110), (0x7CD234, 0x834340),
    (0x7EB15C, 0x7B2E98), (0x7EB1A4, 0x81C67C),
    (0x7EB1D8, 0x81C66C), (0x7EB1E4, 0x81C684),
    (0x74353C, 0x82AD28), (0x743568, 0x833D38),
    (0x82B928, 0x7437D8), (0x82B3D4, 0x82ADC8),
    (0x744850, 0x78497C), (0x744860, 0x6FEA38),
    (0x74399C, 0x75472C), (0x7621FC, 0x6EFE24),
    (0x74577C, 0x745508), (0x745654, 0x833358), (0x74566C, 0x833378),
    (0x6F01BC, 0x6F012C), (0x6F0250, 0x6F01C0),
    (0x6F014C, 0x597C2C), (0x6F0158, 0x6EFF30), (0x6F0170, 0x597C34),
)
WORDS = {
    0x59779C: 0xE3002844, 0x5977A0: 0xE7801002,
    0x7DBB9C: 0xE5900008, 0x7B2CC0: 0xE5900004,
    0x762538: 0xE5801000, 0x7626D0: BASE + 0xA68D4C,
    0xA68D60: BASE + 0x7625F8,
    0x5A7DA4: 0xE3000844, 0x5A7DB0: 0xE5913014,
    0x5A7DB8: 0xE12FFF33, 0x7C6474: 0xE1A02007,
    0x7C6478: 0xE3A01000, 0x7C6488: 0xE2850008,
    0xA715D8: BASE + 0x7C678C, 0x7C678C: 0xE2400008,
    0x7C66A8: 0xE5902014, 0x7C66B0: 0xE12FFF32,
    0x7C6924: 0xE3A01002, 0x7C6928: 0xE5942014,
    0x7C6C2C: 0xE5A46014, 0x7CD654: BASE + 0xA5C274,
    0xA5C288: BASE + 0x7CD4B4, 0xA5C294: BASE + 0x7EB150,
    0xA5C298: BASE + 0x7CD63C, 0xA5C29C: BASE + 0x7CD64C,
    0x81C110: 0xE5900034, 0x834340: 0xE5900028,
    0x7DBB7C: 0xE5900018, 0x7B2E98: 0xE5900004,
    0x81C674: 0xE5801008, 0x81C68C: 0xE5801000,
    0x81C694: 0xE5801004, 0x7CD64C: 0xE3A00002,
    0x7EB1B8: 0xE5907018, 0x7EB1C0: 0xE12FFF37,
    0x7EB1F8: 0xE590C014, 0x7EB200: 0xE12FFF3C,
    0xA74904: BASE + 0x744784, 0x744838: 0xE3A01802,
    0x7885E8: 0xE5840004, 0x513F30: 0xE5840008,
    0x75472C: 0xE5900010, 0x762200: 0xE5840010,
    0x7439A0: 0xE5840050, 0x745660: 0x12801004,
    0x833378: 0xE5801018, 0x833358: 0xE5801004,
    0x6F0C30: BASE + 0xA62054, 0x6EFE40: 0xE2811038,
    0xA620A0: BASE + 0x6F01B8, 0xA620A4: BASE + 0x6F024C,
    0x6F01B8: 0xE2400004, 0x6F024C: 0xE2400004,
    0x6F0184: 0xE590601C, 0x6F018C: 0xE12FFF36,
    0x6F0218: 0xE5906020, 0x6F0220: 0xE12FFF36,
}
RANGES = {
    'store_write_request': (0x5A7D5C, 0x5A7E08),
    'writer_service_submit': (0x7C643C, 0x7C6498),
    'writer_selection': (0x7C65D0, 0x7C6658),
    'writer_service_receive': (0x7C6658, 0x7C678C),
    'request_descriptor_get': (0x82D8B8, 0x82D8EC),
    'exif_scatter_prepare': (0x7CD1E0, 0x7CD248),
    'scatter_emitter': (0x7EB150, 0x7EB234),
    'storage_setup_request': (0x744784, 0x744868),
    'filesystem_adapter': (0x6F012C, 0x6F0254),
    'filesystem_output_binding': (0x745634, 0x745670),
}


def verify(data):
    for source, target in EDGES:
        require(branch_target(data, source), target, f'branch at {source:#x}')
    check_words(data, WORDS)
    return {
        'decoded_sha256': DECODED_SHA256,
        'offset_convention': 'file offsets; add 0x02000000 for code VA',
        'edges': [{'call': hex(a), 'target': hex(b)} for a, b in EDGES],
        'words': {hex(o): hex(w) for o, w in WORDS.items()},
        'ranges': {k: {'start': hex(a), 'end_exclusive': hex(b),
                       'sha256': sha256(data[a:b])} for k, (a, b) in RANGES.items()},
        'scatter_records': {
            'header': {'writer_offset': '0x54', 'file_offset': 0,
                       'source': 'writer+0x18', 'length': 'writer+0x50'},
            'compressed_image': {'writer_offset': '0x60', 'file_offset': 'writer+0x50',
                                 'source': 'input descriptor+0x34', 'length': 'input descriptor+0x28'},
            'record_layout': ['file_offset', 'source_pointer', 'byte_count'],
        },
        'request': 'StoreImage+0x420 -> service command 0 -> writer entry 0x7cd4b4; descriptor bank getter 0x82d8b8(index 2)',
        'storage_setup_correction': '0x5a6be8 -> router 0x82b3c0 -> ordinary slot target 0x744784 submits storage setup command 0x20000; this is not the JPEG payload write.',
        'filesystem_route': 'Normal storage open path 0x745508 binds parent+0x18 to filesystem object+4. Vtable 0x02a6208c routes write/seek through 0x6f01b8/0x6f024c, selecting backend by handle+4 and forwarding handle+0, pointer and count.',
        'limits': [
            'Original descriptor builder and emitter execute with synthetic RAM and an intercepted seek/write interface.',
            'The ordinary filesystem adapter is resolved; the selected backend implementation, SD command/data DMA and physical writes are not resolved or executed here.',
            'Writer selection depends on request and parent format fields; not every request selects Exif JPEG.',
        ],
    }


def emulate(data):
    import unicorn
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                   UC_ARM_REG_R3, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
    scratch = 0x10000000
    writer, descriptor, parent, sink, sink_vtable = [scratch + n for n in (0, 0x1000, 0x2000, 0x3000, 0x4000)]
    header, payload, seek_stub, write_stub, stop = [scratch + n for n in (0x5000, 0x6000, 0xD000, 0xD004, 0xE000)]
    records = []
    for route, failure in [(route, fail) for route in ('interface', 'filesystem_adapter') for fail in (None, 0, 1, 2, 3)]:
        vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
        vm.mem_map(BASE, 0x1000000)
        vm.mem_write(BASE, data[:0x1000000])
        vm.mem_map(scratch, 0x10000)
        def put(address, value):
            vm.mem_write(address, struct.pack('<I', value))
        for address, value in ((writer, BASE + 0xA5C274), (writer+0x10, parent),
                (writer+0x14, sink), (writer+0x18, header), (writer+0x50, 32),
                (descriptor+0x34, payload), (descriptor+0x28, 47),
                (parent+4, 0x2468), (sink, sink_vtable),
                (sink_vtable+0x18, seek_stub), (sink_vtable+0x14, write_stub)):
            put(address, value)
        handle, backend, backend_table, status_stub = scratch+0x7000, scratch+0x8000, scratch+0x9000, scratch+0xD008
        output_object = sink
        if route == 'filesystem_adapter':
            put(writer+0x14, sink+4)
            put(sink+4, BASE+0xA6208C)
            put(sink+0x14, backend_table)
            put(backend_table+4, backend)
            put(parent+4, handle)
            put(handle, 0x2468)
            put(handle+4, 1)
            put(backend, sink_vtable)
            put(sink_vtable+0x1C, write_stub)
            put(sink_vtable+0x20, seek_stub)
            put(sink_vtable+0x64, status_stub)
            output_object = backend
        header_bytes = bytes(range(32))
        payload_bytes = bytes(range(100, 147))
        vm.mem_write(header, header_bytes)
        vm.mem_write(payload, payload_bytes)
        calls = []
        def intercept(uc, address, _size, _user):
            if address in (BASE+0x704038, BASE+0x704044, status_stub):
                uc.reg_write(UC_ARM_REG_R0, 0)
                uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
                return
            args = [uc.reg_read(r) for r in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)]
            require(args[:2], [output_object, 0x2468], 'output object and file handle')
            success = len(calls) != failure
            record = {'operation': 'seek' if address == seek_stub else 'write',
                      'args': args[1:], 'success': success}
            if address == write_stub:
                record['source_sha256'] = sha256(bytes(uc.mem_read(args[2], args[3])))
            calls.append(record)
            uc.reg_write(UC_ARM_REG_R0, int(success))
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
        vm.hook_add(unicorn.UC_HOOK_CODE, intercept, begin=seek_stub, end=status_stub)
        if route == 'filesystem_adapter':
            for function in (0x704038, 0x704044):
                vm.hook_add(unicorn.UC_HOOK_CODE, intercept, begin=BASE+function, end=BASE+function)
        def run(offset, r0, r1=0):
            vm.reg_write(UC_ARM_REG_R0, r0)
            vm.reg_write(UC_ARM_REG_R1, r1)
            vm.reg_write(UC_ARM_REG_SP, scratch+0xF000)
            vm.reg_write(UC_ARM_REG_LR, stop)
            vm.emu_start(BASE+offset, stop, count=10000)
            require(vm.reg_read(UC_ARM_REG_PC), stop, 'bounded original return')
            return vm.reg_read(UC_ARM_REG_R0)
        run(0x7CD1E0, writer, descriptor)
        scatter = struct.unpack('<6I', vm.mem_read(writer+0x54, 24))
        require(scatter, (0, header, 32, 32, payload, 47), 'two scatter records')
        result = run(0x7EB150, writer)
        expected = [('seek', [0x2468, 0, 0]), ('write', [0x2468, header, 32]),
                    ('seek', [0x2468, 32, 0]), ('write', [0x2468, payload, 47])]
        if failure is not None:
            expected = expected[:failure+1]
        require([(c['operation'], c['args']) for c in calls], expected, 'output order and pointer identity')
        require(result, int(failure is None), 'failure propagation')
        require(bytes(vm.mem_read(header, 32)), header_bytes, 'header data preserved')
        require(bytes(vm.mem_read(payload, 47)), payload_bytes, 'source data preserved')
        records.append({'route': route, 'failure_at_call': failure, 'return_value': result, 'scatter': list(scatter), 'calls': calls})
    return {'engine': 'Unicorn '+unicorn.__version__, 'cases': records,
            'original_entries': ['0x7cd1e0', '0x7eb150'],
            'stubs': ['seek/write at output interface or backend interface', 'filesystem mutex lock/unlock', 'backend status'],
            'physical_file_output': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('decoded', type=Path)
    parser.add_argument('--compare', type=Path)
    args = parser.parse_args()
    data = load_image(args.decoded)
    result = verify(data)
    result['numeric'] = emulate(data)
    if args.compare:
        require(result, json.loads(args.compare.read_text(encoding='utf-8')), 'published Exif evidence')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
