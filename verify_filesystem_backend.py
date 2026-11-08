"""Verify K-3 II filesystem dispatch and whole/partial-sector buffer paths.

SPDX-License-Identifier: GPL-2.0-only
Code locations are decoded file offsets. Device execution is intercepted.
"""
import argparse
import json
from pathlib import Path
import struct

from verify_findings import DECODED_SHA256, require, sha256, u32
from verify_raw_path import branch_target
from verify_tone_path import BASE, load_image


EDGES = (
    (0x762124, 0x572B0C), (0x762198, 0x5CB39C),
    (0x762220, 0x59761C), (0x762238, 0x597624),
    (0x573048, 0x572FCC), (0x572FF0, 0xE8A1D8),
    (0x5CB864, 0x5CB814), (0x5CB82C, 0xE86818),
    (0xE8A1F0, 0xEB48A8), (0xEB4918, 0xEB4530),
    (0xEB460C, 0xEBEF2C), (0xEBF478, 0xEBFB30),
    (0xEBFC74, 0xEB78BC), (0xEB7ACC, 0xEBB190),
    (0xEB7D70, 0xE88D34), (0xEB7D7C, 0xEB7590),
    (0xEB6A10, 0xEBB190), (0x572C20, 0xE8B570),
    (0x5729F4, 0x572840), (0x5729CC, 0x572900),
    (0x572860, 0x736B78), (0x7620C4, 0x7413D8),
    (0x7620E4, 0x736A4C), (0x7410A8, 0x757890),
)
RANGES = {
    'backend_constructors_and_registration': (0x762118, 0x762250),
    'backend_choice': (0x6F0B60, 0x6F0BC0),
    'backend_a_write': (0x572FCC, 0x57304C),
    'backend_b_write': (0x5CB814, 0x5CB868),
    'library_write_entry': (0xE8A1D8, 0xE8A208),
    'library_write_dispatch': (0xEB48A8, 0xEB4948),
    'library_write_body': (0xEB4530, 0xEB4618),
    'file_to_extents': (0xEBEF2C, 0xEBF72C),
    'extent_to_sector': (0xEBFB30, 0xEBFD2C),
    'whole_and_partial_sectors': (0xEB78BC, 0xEB7E20),
    'dirty_cache_flush': (0xEB69AC, 0xEB6A98),
    'block_callback_loop': (0xEBB190, 0xEBB2A8),
    'block_callback_registration': (0xE8B630, 0xE8B654),
    'block_callback': (0x572970, 0x5729FC),
    'card_write_bridge': (0x572840, 0x572900),
    'volume_registration': (0x7620B4, 0x762118),
}


def verify(data):
    for site, target in EDGES:
        require(branch_target(data, site), target, f'branch at {site:#x}')
    words = {
        0x572EB8: BASE+0xA68AC8, 0x5CBF6C: BASE+0xA6CB90,
        0xA68B64: BASE+0x573044, 0xA6CC2C: BASE+0x5CB860,
        0x6F0C34: 0x04040000, 0x6F0B80: 0xE7810107,
        0xE8B644: 0xE5848440, 0xEBB234: 0xE595C440,
        0xEBB244: 0xE12FFF3C, 0x5728DC: 0xE590C018,
        0x5728E4: 0xE12FFF3C, 0xA5D224: BASE+0x7589E8,
    }
    for site, expected in words.items():
        require(u32(data, site), expected, f'word at {site:#x}')
    return {'edges': [[hex(a), hex(b)] for a, b in EDGES],
            'words': {hex(a): hex(b) for a, b in words.items()},
            'ranges': {k: {'start': hex(a), 'end_exclusive': hex(b), 'sha256': sha256(data[a:b])}
                       for k, (a, b) in RANGES.items()}}


def emulate(data):
    import unicorn
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                   UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R7,
                                   UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC)
    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    ram, stop, stack = 0x10000000, 0x1003F000, 0x1003E000
    vm.mem_map(ram, 0x40000)
    vm.mem_map(0x4040A000, 0x1000)
    obj, vol, cache, cache_data, source, card, table = [ram+x for x in (0, 0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000)]
    regids = (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3)

    def put(address, *values):
        vm.mem_write(address, struct.pack('<'+'I'*len(values), *values))

    def read(address):
        return struct.unpack('<I', vm.mem_read(address, 4))[0]

    calls, stubs = [], set()
    failure_at = None
    library_result = 0

    def intercept(uc, address, _size, _user):
        offset = address-BASE
        args = [uc.reg_read(r) for r in regids]
        result = 0
        if offset == 0xE89324:
            result = vol
        elif offset == 0xE8BA94:
            vm.mem_write(args[1], b'C:\0')
        elif offset == 0x736B78:
            require(bytes(vm.mem_read(args[1], 3)), b'C:\0', 'selected volume name')
            result = card
        elif offset in (0xEBACE8, 0x97C550):
            result = 1
        elif offset == 0x7589E8:
            require(args[0], card, 'same card object')
            calls.append({'lba': args[1], 'blocks': args[2], 'source': args[3]})
            result = int(len(calls)-1 != failure_at)
        elif offset in (0xE8A1D8, 0xE86818):
            calls.append({'entry': hex(offset), 'handle': args[0], 'source': args[1], 'bytes': args[2]})
            result = library_result & 0xFFFFFFFF
        elif offset == 0xE89C00:
            result = 5
        stubs.add(hex(offset))
        uc.reg_write(UC_ARM_REG_R0, result)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    hooked = (0xE89324, 0xE8BA94, 0x736B78, 0x78607C, 0x78609C,
              0xEBACE8, 0xEB6854, 0x7580A8, 0x75810C, 0x97C550, 0x7589E8,
              0xE8A1D8, 0xE86818, 0xE89C00, 0xE89C30, 0x572EC8, 0x5CB748)
    for offset in hooked:
        vm.hook_add(unicorn.UC_HOOK_CODE, intercept, begin=BASE+offset, end=BASE+offset)

    def run(entry, *args, end=None, extra=()):
        vm.reg_write(UC_ARM_REG_SP, stack)
        vm.reg_write(UC_ARM_REG_LR, stop)
        for register, value in zip(regids, args):
            vm.reg_write(register, value)
        for register, value in extra:
            vm.reg_write(register, value)
        until = stop if end is None else BASE+end
        try:
            vm.emu_start(BASE+entry, until, count=100000)
        except unicorn.UcError as error:
            raise RuntimeError(f'probe {entry:#x}, args={args}, PC={vm.reg_read(UC_ARM_REG_PC):#x}') from error
        require(vm.reg_read(UC_ARM_REG_PC), until, 'bounded original execution')
        return vm.reg_read(UC_ARM_REG_R0)

    selection = []
    put(obj+0xC, ram+0x8000, ram+0x9000, table)
    for value in (0x0403FFFF, 0x04040000, 0x04040001):
        run(0x6F0B6C, value, end=0x6F0B84, extra=((UC_ARM_REG_R4, obj), (UC_ARM_REG_R7, 1)))
        expected = ram+(0x8000 if value < 0x04040000 else 0x9000)
        require(read(table+4), expected, 'backend threshold selection')
        selection.append({'device_word': value, 'backend_field': '0xc' if value < 0x04040000 else '0x10'})

    wrappers = []
    for entry in (0x573044, 0x5CB860):
        for library_result in (47, 0, -1):
            calls.clear()
            result = run(entry, obj+4, 5, source, 47)
            require(result, int(library_result >= 0), 'backend return conversion')
            require([(c['handle'], c['source'], c['bytes']) for c in calls], [(5, source, 47)], 'backend pointer/length forwarding')
            wrappers.append({'entry': hex(entry), 'library_return': library_result, 'result': result, 'calls': list(calls)})

    def prepare():
        vm.mem_write(obj, bytes(0x8000))
        put(obj+0x2C, vol)
        put(vol+8, 2)
        put(vol+0x54, 512, 511, 9)
        put(vol+0x41C, 1)
        put(vol+0x440, BASE+0x572970)
        put(card, BASE+0xA5D20C)
        put(0x4040AC58, 0, ram+0x7000, 0, ram+0x7100)
        calls.clear()

    prepare()
    put(stack, source, 0, 0)
    require(run(0xEB78BC, obj, 0x100, 0, 1024), 1, 'whole-sector helper')
    require(calls, [{'lba': 0x100, 'blocks': 2, 'source': source}], 'whole-sector card request')
    whole = list(calls)

    prepare()
    put(obj+0x24, 0x10, cache, vol)
    put(cache+0x14, vol, 0, 0x100, 512, cache_data)
    vm.mem_write(cache_data, bytes([0xCC])*512)
    payload = b'JPEG-PARTIAL'
    vm.mem_write(source, payload)
    put(stack, source, 0, 0)
    require(run(0xEB78BC, obj, 0x100, 7, len(payload)), 1, 'partial-sector helper')
    require(calls, [], 'partial bytes held in cache before flush')
    expected = bytes([0xCC])*7+payload+bytes([0xCC])*(512-7-len(payload))
    require(bytes(vm.mem_read(cache_data, 512)), expected, 'cache bytes and untouched surroundings')
    require(read(obj+0x44)&1, 1, 'cache marked dirty')
    require(run(0xEB69AC, obj), 1, 'original dirty cache flush')
    require(calls, [{'lba': 0x100, 'blocks': 1, 'source': cache_data}], 'flush uses cache pointer')
    partial = {'offset': 7, 'bytes': len(payload), 'cache_sha256': sha256(expected), 'calls': list(calls)}

    chunks = []
    for count, failure_at in ((0, None), (65535, None), (65536, None), (65536, 0)):
        prepare()
        put(stack, 0, 0)
        result = run(0xEBB190, vol, 0x100, source, count)
        expected = [] if count == 0 else [{'lba': 0x100, 'blocks': min(count,65535), 'source': source}]
        if count == 65536 and failure_at is None:
            expected.append({'lba': 0x100+65535, 'blocks': 1, 'source': source+65535*512})
        require(calls, expected, '16-bit block splitting and source advancement')
        require(result, int(failure_at is None), 'callback failure propagation')
        chunks.append({'blocks': count, 'failure_at': failure_at, 'result': result, 'calls': list(calls)})
    return {'engine': 'Unicorn '+unicorn.__version__, 'backend_choices': selection, 'backend_writes': wrappers,
            'whole_sector': whole, 'partial_sector': partial, 'block_chunks': chunks,
            'intercepted_entries': sorted(stubs), 'physical_media_executed': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('decoded', type=Path)
    parser.add_argument('--compare', type=Path)
    args = parser.parse_args()
    data = load_image(args.decoded)
    result = {'decoded_sha256': DECODED_SHA256, 'static': verify(data), 'numeric': emulate(data),
              'limits': [
                  'Backend A is traced through its registered block callback; backend B is resolved only through its file-write entry.',
                  'File allocation, cluster-chain construction and complete Exif-to-media execution are not emulated.',
                  'Sector helper fixtures start with initialized volume/cache state; volume lookup, locking, preflight, error policy and card execution are intercepted. Error policy returns zero, so the failure case does not retry.',
                  'Whole sectors preserve the source pointer; partial sectors copy into a distinct cache buffer before a separate original flush.',
                  'The 0x04040000 backend threshold is an unsigned device-word comparison. The separate verify_sd_controller.py trace establishes card+0x14 as a CSD-derived count of 512-byte logical sectors.',
              ]}
    if args.compare:
        require(result, json.loads(args.compare.read_text(encoding='utf-8')), 'filesystem evidence snapshot')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
