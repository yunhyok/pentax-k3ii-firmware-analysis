"""Verify K-3 II B2Y, scaler, JPEG and StoreImage buffer handoffs.

SPDX-License-Identifier: GPL-2.0-only
Instruction locations are decoded file offsets.
"""
import argparse
import json
from pathlib import Path
from struct import pack, unpack

from verify_findings import (
    DECODED_SHA256,
    literal_offset,
    require,
    require_snapshot,
    sha256,
    u32,
)
from verify_raw_path import branch_target
from verify_tone_path import BASE, check_words, load_image


EDGES = {
    "b2y_to_scaler": (
        (0x6594D4, 0x659528), (0x659798, 0x6597E0),
        (0x6597E8, 0x7543D4), (0x6597F4, 0x7543DC), (0x659800, 0x7543E4),
        (0x57BF30, 0x754B10), (0x57BF40, 0x58C078), (0x58C094, 0x58B500),
        (0x58BC88, 0x4E3084), (0x58BCB8, 0x4E3094), (0x58BCE8, 0x4E309C),
        (0x58BDAC, 0x5506E8), (0x58BDB8, 0x55073C), (0x58BDC4, 0x550790),
        (0x659AD0, 0x81CFB0), (0x659ADC, 0x81CFB8), (0x659AE8, 0x81CFC0),
        (0x6594DC, 0x659E78), (0x65A174, 0x71B010),
        (0x580044, 0x71B008), (0x580A08, 0x580034),
    ),
    "scaler_to_jpeg": (
        (0x6DC2F4, 0x6593B0), (0x6DC334, 0x656984),
        (0x65A180, 0x71B050), (0x65A18C, 0x71B058),
        (0x58095C, 0x71B038), (0x58096C, 0x57FC04),
        (0x580984, 0x71B040), (0x580994, 0x57FC04),
        (0x57FD14, 0x57F904), (0x57FD48, 0x57F904),
        (0x57FA90, 0x702B8C), (0x57FAA4, 0x7B3290), (0x57FAB8, 0x7B3298),
        (0x57FA9C, 0x754794), (0x57FAB0, 0x73DF78), (0x57FAC4, 0x73DF80),
        (0x57FBBC, 0x728EE0), (0x6569F4, 0x656A7C), (0x656A80, 0x656A94),
        (0x659514, 0x65D450), (0x65D4EC, 0x71B6A0), (0x65D4F8, 0x71B6A8),
        (0x65D528, 0x71B6E8), (0x65D538, 0x71B6F0),
    ),
    "jpeg_input_output": (
        (0x6DB764, 0x81D3BC), (0x566488, 0x575EB8), (0x577120, 0x576CFC),
        (0x576D68, 0x72D8CC), (0x576D70, 0x71B688), (0x576DA0, 0x71B6D0),
        (0x576E54, 0x576AC4), (0x576E90, 0x71B690), (0x576E9C, 0x71B6D8),
        (0x576EFC, 0x576AC4), (0x576B04, 0x702B8C), (0x576B10, 0x71AED8),
        (0x576B18, 0x7B3290), (0x576B24, 0x71AEE0),
        (0x576B2C, 0x7B3298), (0x576B38, 0x71AEE8),
        (0x576B40, 0x71C290), (0x576B4C, 0x71AF40), (0x576C24, 0x53D700),
        (0x53D884, 0x4E1FB0), (0x53D898, 0x4B7CD4),
        (0x53D8A0, 0x4E1FB8), (0x53D8B4, 0x4B7CE4),
        (0x53D8BC, 0x4E1FC0), (0x53D8D0, 0x4B7CF4),
        (0x53D8D8, 0x4E1FF0), (0x53D8EC, 0x4B7E8C),
        (0x66081C, 0x65420C), (0x660830, 0x65420C), (0x660838, 0x65420C),
        (0x660864, 0x7DC618), (0x6608A0, 0x78557C), (0x576C74, 0x576C80),
        (0x576C98, 0x576780),
    ),
    "jpeg_length_to_store": (
        (0x53D534, 0x53D3A8), (0x53D3B8, 0x4B8234), (0x53D574, 0x6FE97C),
        (0x576048, 0x576008), (0x576038, 0x70C3CC),
        (0x576C54, 0x78557C), (0x57676C, 0x78557C),
        (0x6DBBA8, 0x6DBDB4), (0x6DBDB8, 0x65DC34), (0x65DCB8, 0x65E154),
        (0x65E168, 0x7DD780), (0x6594F8, 0x65C174), (0x65C2EC, 0x65784C),
        (0x6578E0, 0x72D4BC), (0x657940, 0x832FB0), (0x65798C, 0x8598E0),
        (0x5A97E8, 0x5A8790), (0x5A88B4, 0x72D808), (0x5A88DC, 0x5A820C),
        (0x5A8278, 0x72D4BC), (0x5A8288, 0x82D878),
        (0x5A8AF0, 0x82D868), (0x5A8AFC, 0x5A7D5C), (0x5A7D80, 0x833F3C),
    ),
}
LITERALS = {
    0x5506F0: 0x20022440, 0x550744: 0x20022450, 0x550798: 0x20022460,
    0x6DB774: 0x00C00002, 0x575ED8: 0x02A75BC8,
    0x4B7CD8: 0x200E2000, 0x4B7CE8: 0x200E2000,
    0x4B7CF8: 0x200E2000, 0x4B7E90: 0x200E2000,
    0x4B8234: 0x200E0000, 0x53D568: 0x02060001, 0x576008: 0x02060001,
    0x577080: 0x03000002,
}
WORDS = {
    # B2Y direct branch and scaler source/destination.
    0x659794: 0xE3100044,
    0x6597E0: 0xE5941160,
    0x6597EC: 0xE5941164,
    0x6597F8: 0xE5941168,
    0x7543D4: 0xE580102C,
    0x7543DC: 0xE5801030,
    0x7543E4: 0xE5801034,
    0x4E3084: 0xE590002C,
    0x4E3094: 0xE5900030,
    0x4E309C: 0xE5900034,
    0x5506EC: 0xE3C02007,
    0x5506F8: 0xE5802000,
    0x55074C: 0xE5802000,
    0x5507A0: 0xE5802000,
    0x659AC8: 0xE5941160,
    0x659AD4: 0xE5941164,
    0x659AE0: 0xE5941168,
    0x81CFB0: 0xE5801004,
    0x81CFB8: 0xE5801008,
    0x81CFC0: 0xE580100C,
    0x659454: 0xE30251B0,
    0x659458: 0xE084B005,
    0x659450: 0xE88D0021,
    0x65A16C: 0xE2841D85,
    0x71B010: 0xE5801000,
    0x71B050: 0xE5801004,
    0x71B058: 0xE5801008,
    0x71B038: 0xE5900004,
    0x71B040: 0xE5900008,
    0x580964: 0xE1A02000,
    0x58098C: 0xE1A02000,
    # Module 16 binding and input/output registers.
    0x81D3BC: 0xE5900074,
    0x56648C: 0xE5840074,
    0x575EF4: 0xE5801008,
    0x6DB770: 0xE5840078,
    0x6DB778: 0xE58400CC,
    0x57711C: 0xE2400008,
    0x576D30: 0xE2401503,
    0x576D38: 0xE2511002,
    0x656A7C: 0xE30A081C,
    0x65D454: 0xE30A081C,
    0x71B6A0: 0xE5801000,
    0x71B6A8: 0xE5801004,
    0x71B6E8: 0xE5801014,
    0x71B6F0: 0xE5801018,
    0x71AED8: 0xE5801000,
    0x71AEE0: 0xE5801004,
    0x71AEE8: 0xE5801008,
    0x71AF40: 0xE580100C,
    0x660854: 0xE5971190,
    0x7DC618: 0xE5801000,
    0x4B7CD4: 0xE3C1000F,
    0x4B7CDC: 0xE5810028,
    0x4B7CEC: 0xE581002C,
    0x4B7CFC: 0xE5810030,
    0x4B7E8C: 0xE3C1000F,
    0x4B7E94: 0xE5810050,
    # Codec output count to job then StoreImage request.
    0x4B8238: 0xE5900020,
    0x53D56C: 0xE1A02006,
    0x576014: 0x05802028,
    0x576C4C: 0xE5941028,
    0x78557C: 0xE580100C,
    0x57708C: 0xE12FFF33,
    0x6DBBA4: 0x03A01010,
    0x65E178: 0xE58102EC,
    0x657938: 0xE59712EC,
    0x657984: 0xE5971190,
    0x832FB0: 0xE5801028,
    0x8598E0: 0xE5801034,
    0x82D8A0: 0xE5805018,
    0x82D8E0: 0xE5905018,
    0x81C110: 0xE5900034,
    0x834340: 0xE5900028,
    0x5A7D9C: 0xE2842E42,
    0x5A7DB8: 0xE12FFF33,
    0x65420C: 0xE281000F,
    0x654210: 0xE3C0000F,
    0x660820: 0xE5840190,
    0x660840: 0xE5840194,
    0x576C70: 0xE1500001,
    0x576C78: 0xE3500000,
}
RANGES = {
    "b2y_job_output_planes": (0x6597E0, 0x659804),
    "b2y_output_programming": (0x58BC84, 0x58BDC8),
    "b2y_scaler_source_descriptor": (0x659AC8, 0x659AEC),
    "scaler_buffer_binding": (0x65A16C, 0x65A190),
    "scaler_buffer_use": (0x58091C, 0x580998),
    "jpeg_recipe_dispatch": (0x6DB764, 0x6DB77C),
    "jpeg_job_binding": (0x65D450, 0x65D560),
    "jpeg_first_descriptor_construction": (0x576AF8, 0x576B50),
    "jpeg_mmio": (0x53D880, 0x53D8F0),
    "jpeg_completion_counter": (0x53D51C, 0x53D578),
    "jpeg_completion_job_update": (0x65E154, 0x65E180),
    "jpeg_destination_alignment": (0x660808, 0x660844),
    "jpeg_output_descriptor_init": (0x660844, 0x6608B0),
    "store_descriptor_init": (0x6578DC, 0x657990),
    "store_request_descriptor": (0x5A8274, 0x5A828C),
    "store_write_image_send": (0x5A7D5C, 0x5A7DBC),
}
RECIPE_STAGES = {
    "b2y_tone": 0, "scaler": 2, "jpeg": 16, "store_image": 9,
}
RECIPE_SELECTORS = (0x0C, 0x10, 0x13, 0x15)
B2Y_DEST = (0x20022440, 0x20022450, 0x20022460)
JPEG_IO = (0x200E2028, 0x200E202C, 0x200E2030, 0x200E2050)


def verify_static(data):
    for edges in EDGES.values():
        for site, target in edges:
            require(branch_target(data, site), target, f"branch at {site:#x}")
    for site, value in LITERALS.items():
        require(u32(data, literal_offset(data, site)), value, f"literal at {site:#x}")
    check_words(data, WORDS)
    require(u32(data, 0xA75C10), BASE + 0x57711C, "module 16 receiver vtable slot")
    require(u32(data, 0xA75BF8), BASE + 0x576044, "module 16 completion vtable slot")
    return {
        "edges": EDGES, "literal_reads": LITERALS, "instruction_offsets": list(WORDS),
        "vtable_slots": {0xA75C10: 0x57711C, 0xA75BF8: 0x576044},
        "ranges": {
            label: {"start": start, "end_exclusive": end, "sha256": sha256(data[start:end])}
            for label, (start, end) in RANGES.items()
        },
    }


def emulate(data):
    from unicorn import Uc, UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, __version__
    from unicorn.arm_const import (
        UC_ARM_REG_FP, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
        UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6,
        UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_SB, UC_ARM_REG_SP, UC_ARM_REG_R3,
    )

    emulator = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    emulator.mem_map(BASE, 0x1000000)
    emulator.mem_write(BASE, data[:0x1000000])
    ram, job, device, request = 0x10000000, 0x10000000, 0x10020000, 0x10024000
    store, scratch, sp, ret = 0x10026000, 0x10030000, 0x10038000, 0x1003E000
    emulator.mem_map(ram, 0x40000)
    emulator.mem_map(0x20022000, 0x1000)
    emulator.mem_map(0x200E0000, 0x3000)

    def read(address):
        return unpack("<I", emulator.mem_read(address, 4))[0]

    def write(address, *values):
        emulator.mem_write(address, pack(f"<{len(values)}I", *values))

    def run(start, end=None, **registers):
        stop = ret if end is None else BASE + end
        values = {UC_ARM_REG_SP: sp, UC_ARM_REG_LR: ret}
        ids = {
            "r0": UC_ARM_REG_R0, "r1": UC_ARM_REG_R1, "r2": UC_ARM_REG_R2, "r3": UC_ARM_REG_R3,
            "r4": UC_ARM_REG_R4, "r5": UC_ARM_REG_R5, "r6": UC_ARM_REG_R6, "r7": UC_ARM_REG_R7,
            "r8": UC_ARM_REG_R8, "sb": UC_ARM_REG_SB, "fp": UC_ARM_REG_FP,
        }
        values.update({ids[name]: value for name, value in registers.items()})
        for register, value in values.items():
            emulator.reg_write(register, value)
        emulator.emu_start(BASE + start, stop, count=100_000)
        require(emulator.reg_read(UC_ARM_REG_PC), stop, f"probe stop from {start:#x}")
        return emulator.reg_read(UC_ARM_REG_R0)

    allocations = []

    def allocate(uc, _address, _size, _user_data):
        allocations.append(uc.reg_read(UC_ARM_REG_R0))
        uc.reg_write(UC_ARM_REG_R0, scratch)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    allocator = BASE + 0x712828
    hook = emulator.hook_add(UC_HOOK_CODE, allocate, begin=allocator, end=allocator)
    recipes = {}
    for selector in RECIPE_SELECTORS:
        allocations.clear()
        emulator.mem_write(scratch, bytes(0x302))
        require(run(0x76E7AC, r1=selector), scratch, "recipe buffer")
        require(allocations, [0x302], "recipe allocation size")
        values = unpack("<385H", emulator.mem_read(scratch, 0x302))
        stages = {
            name: [i for i in range(128) if values[i] == 5 and values[i + 128] == module]
            for name, module in RECIPE_STAGES.items()
        }
        tone, scaler, jpeg, output = stages.values()
        require(len(tone) == len(scaler) == len(jpeg) == 1, True, "one stage of each kind")
        require(tone[0] < scaler[0] < jpeg[0], True, "recipe stage order")
        require(all(index > jpeg[0] for index in output), True, "storage after JPEG")
        recipes[hex(selector)] = stages
    emulator.hook_del(hook)

    emulator.mem_write(job + 0x6B, bytes([1]))
    write(job + 0x2E4, 0x1003)
    run(0x660808, 0x660844, r4=job, r3=0x8600300F, r0=0)
    allocated_destinations = tuple(read(job + offset) for offset in (0x190, 0x194))
    require(allocated_destinations, (0x86003010, 0x86004020), "two aligned JPEG destinations")

    # Populate the job's original module-16 payload and the shared scaler pointers.
    require(run(0x656984, r0=job, r1=16), job + 0xA81C, "encoder payload")
    require(run(0x656984, r0=job, r1=2), job + 0xA7B4, "scaler payload")
    require(run(0x656984, r0=job, r1=9), job + 0xA850, "store payload")
    run(0x6593B0, r0=job, r1=16)
    jpeg = job + 0xA81C
    require([read(jpeg + index) for index in (0, 4, 0x14, 0x18)],
            [job + index for index in (0x21B0, 0x21CC, 0x23C4, 0x23DC)], "job encoder bindings")
    write(sp + 4, job + 0x21CC)
    run(0x65A16C, 0x65A190, r4=job, r7=job + 0xA7B4, fp=job + 0x21B0)
    require([read(job + 0xA7B4 + i) for i in (0, 4, 8)],
            [job + i for i in (0x2140, 0x21B0, 0x21CC)], "job scaler bindings")

    src = (0x81003000, 0x82004000, 0x83005000)
    write(job + 0x160, *src)
    write(sp + 4, job + 0xA41C)
    run(0x6597E0, 0x659804, r4=job)
    run(0x58BC84, 0x58BDC8, r4=device, fp=job + 0xA41C)
    require(tuple(map(read, B2Y_DEST)), src, "B2Y output writes")
    run(0x659AC8, 0x659AEC, r4=job)
    require(tuple(read(job + 0x2144 + 4 * i) for i in range(3)), src, "scaler source planes")

    bases = (0x8600100F, 0x86002000)
    lengths = (0x123456, 0x789AB)
    write(job + 0x190, *bases)
    run(0x660844, 0x6608B0, r4=job)
    results = []
    for stream, (base, length) in enumerate(zip(bases, lengths)):
        pixels = job + 0x21B0 + 0x1C * stream
        out = job + 0x23C4 + 0x18 * stream
        planes = (0x87002007 + 0x8000 * stream, 0x88003000, 0x8900400F)
        write(pixels + 4, *planes)
        run(0x576AF8, 0x576B50, r8=pixels, sb=out)
        descriptor = sp + 8
        require(tuple(read(descriptor + 4 * i) for i in range(4)),
                (*planes, base), "codec descriptor planes and output pointer")
        run(0x53D880, 0x53D8F0, sb=descriptor, r4=device)
        expected = tuple(address & ~15 for address in (*planes, base))
        require(tuple(map(read, JPEG_IO)), expected, "codec MMIO plane and output writes")
        write(0x200E0020, length)
        require(run(0x53D3A8, r0=device), length, "codec count")
        run(0x576008, 0x576030, r0=device, r1=0x02060001, r2=length)
        run(0x576C4C, 0x576C58, r4=device, sb=out)
        require(read(out + 0xC), length, "codec output descriptor length")
        results.append({"stream": stream, "planes": planes, "destination": base,
                        "programmed_mmio": expected, "completed_size": length})

    # Execute the original module completion and exact StoreImage assignment slices.
    run(0x6DBA14, 0x6DBDB4, r6=0x03000002)
    module = emulator.reg_read(UC_ARM_REG_R1)
    require(module, 16, "JPEG completion module")
    run(0x65DC34, r0=job, r1=module)
    for stream, result in enumerate(results):
        stream_job = job + 4 * stream
        record = store + stream * 0x3FC
        descriptor = record + 4
        run(0x657938, 0x657944, r7=stream_job, r8=descriptor)
        run(0x657984, 0x657990, r7=stream_job, r8=descriptor)
        run(0x5A8274, 0x5A828C, r4=request - 0x420, r6=record)
        require(run(0x82D8B8, r0=request, r1=2), descriptor, "StoreImage request index 2")
        source = run(0x81C110, r0=descriptor)
        size = run(0x834340, r0=descriptor)
        require((source, size), (result["destination"], result["completed_size"]), "stored buffer and size")
        result["store_source"] = source
        result["store_size"] = size
        result["store_pointer_matches_programmed_dma"] = source == result["programmed_mmio"][3]
    return {
        "engine": f"Unicorn {__version__}", "allocator_stub": 0x712828,
        "step_limit_per_probe": 100_000, "b2y_to_scaler_planes": src,
        "aligned_destination_layout": allocated_destinations,
        "completion_message": {"command": 0x03000002, "module": module},
        "recipes": recipes, "synthetic_streams": results,
    }


def analyze(data):
    return {
        "decoded_sha256": DECODED_SHA256,
        "base": BASE,
        "offset_convention": "Code and vtable locations are file offsets. MMIO addresses are absolute.",
        "static": verify_static(data),
        "buffer_layout": {
            "b2y_job_output_planes": [0x160, 0x164, 0x168],
            "b2y_mmio_first_slot_by_plane": B2Y_DEST,
            "scaler_payload": 0xA7B4, "scaler_source": 0x2140,
            "scaler_destinations_and_jpeg_inputs": [0x21B0, 0x21CC],
            "image_plane_fields": [4, 8, 0xC],
            "jpeg_payload": 0xA81C, "jpeg_output_descriptors": [0x23C4, 0x23DC],
            "jpeg_codec": 0x53D700, "jpeg_plane_and_destination_mmio": JPEG_IO,
            "jpeg_count_mmio": 0x200E0020, "jpeg_destination_fields": [0x190, 0x194],
            "jpeg_completed_length_fields": [0x2EC, 0x2F0],
            "store_payload": 0xA850, "store_main_record_base": 0x10,
            "store_main_record_stride": 0x3FC, "store_record_descriptor_offset": 4,
            "store_descriptor_length": 0x28, "store_descriptor_address": 0x34,
            "store_request": 0x420, "store_request_main_index": 2,
        },
        "replay": emulate(data),
        "limits": [
            "Observed chain is conditional on the direct B2Y output branch, scaler and encoder stream flags, and the main-JPEG StoreImage branch.",
            "B2Y hardware clears three address bits and the JPEG codec clears four. Equality of descriptor and programmed address therefore requires alignment.",
            "The checked two-destination layout rounds each destination up to 16 bytes. The deliberately unaligned replay uses a synthetic pointer outside that layout.",
            "The initial JPEG result is accepted when its count is nonzero and within the descriptor capacity. The original retry branch is identified statically.",
            "Synthetic replay exercises original descriptor and register slices, with mapped MMIO and supplied completion values. No hardware pixels or JPEG bytes were generated.",
            "The earlier module 8 encoder uses a different register block and is distinct from the module 16 path in the tested RAW recipes.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = json.dumps(analyze(load_image(args.decoded)), indent=2)
    if args.compare:
        require_snapshot(
            json.loads(result), args.compare, "published JPEG buffer evidence"
        )
    print(result)


if __name__ == "__main__":
    main()
