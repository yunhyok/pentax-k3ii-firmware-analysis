"""Verify alternate K-3 II CPP output and JPEG destination/retry paths.

SPDX-License-Identifier: GPL-2.0-only
Instruction locations are decoded file offsets.
"""
import argparse
import json
from pathlib import Path
from struct import pack, unpack

from verify_findings import DECODED_SHA256, literal_offset, require, sha256, u32
from verify_raw_path import branch_target
from verify_tone_path import BASE, check_words, load_image


EDGES = {
    "cpp_producers": (
        (0x654274, 0x654354), (0x65436C, 0x654120), (0x6543F8, 0x81CFB0),
        (0x654404, 0x81CFB8), (0x654410, 0x81CFC0),
        (0x660B00, 0x660D5C), (0x660D78, 0x81CFB0), (0x660D84, 0x81CFB8),
        (0x660D90, 0x81CFC0), (0x659550, 0x71B548), (0x65955C, 0x71B580),
        (0x659538, 0x785878), (0x653EF8, 0x785880),
        (0x659798, 0x6597E0), (0x6597A0, 0x702B8C), (0x6597B4, 0x7B3290),
        (0x6597C8, 0x7B3298), (0x6597AC, 0x7543D4), (0x6597C0, 0x7543DC),
        (0x6597D4, 0x7543E4), (0x6597E8, 0x7543D4), (0x6597F4, 0x7543DC),
        (0x659800, 0x7543E4),
    ),
    "cpp_consumer": (
        (0x57BB64, 0x71C520), (0x57C024, 0x57BB80),
        (0x57BB9C, 0x57BBB0), (0x57BBA4, 0x754B14), (0x57BBAC, 0x719894),
        (0x57BCE8, 0x71C528), (0x57BCF0, 0x57C000), (0x57BDFC, 0x57BE60),
        (0x57BE04, 0x71B578), (0x57BE08, 0x702B8C), (0x57BE1C, 0x7543D4),
        (0x57BE24, 0x71B578), (0x57BE28, 0x7B3290), (0x57BE3C, 0x7543DC),
        (0x57BE44, 0x71B578), (0x57BE48, 0x7B3298), (0x57BE5C, 0x7543E4),
        (0x57BF40, 0x58C078), (0x58C094, 0x58B500), (0x58BDAC, 0x5506E8),
        (0x58BDB8, 0x55073C), (0x58BDC4, 0x550790),
        (0x659AD0, 0x81CFB0), (0x659ADC, 0x81CFB8), (0x659AE8, 0x81CFC0),
    ),
    "jpeg_destinations": (
        (0x660780, 0x656ABC), (0x660794, 0x660808), (0x6607A0, 0x654120),
        (0x6607B0, 0x77F1D4), (0x6607D8, 0x654120), (0x6607E8, 0x77F1CC),
        (0x6607F4, 0x654120), (0x660818, 0x660838), (0x66081C, 0x65420C),
        (0x660830, 0x65420C), (0x660838, 0x65420C), (0x660864, 0x7DC618),
        (0x660870, 0x785584), (0x66087C, 0x785574), (0x6608A0, 0x78557C),
    ),
    "jpeg_retry": (
        (0x576C64, 0x71C278), (0x576C74, 0x576C80), (0x576C7C, 0x576CA0),
        (0x576C98, 0x576780), (0x5767E8, 0x5765D8), (0x5767F0, 0x71C278),
        (0x576800, 0x57680C), (0x576808, 0x576814), (0x576810, 0x5767C4),
        (0x576608, 0x702B8C), (0x576614, 0x71AED8), (0x57661C, 0x7B3290),
        (0x576628, 0x71AEE0), (0x576630, 0x7B3298), (0x57663C, 0x71AEE8),
        (0x576644, 0x71C290), (0x576650, 0x71AF40), (0x5766E0, 0x71AF20),
        (0x576700, 0x71AEF8), (0x57673C, 0x53D700), (0x57676C, 0x78557C),
    ),
}

WORDS = {
    # Plane selection, producer and consumer fields.
    0x653C08: 0xE30EB0C4,
    0x653E70: 0xE084100B,
    0x653E78: 0xE1A08001,
    0x653EE8: 0xE30A041C,
    0x653EEC: 0xE1A01008,
    0x653EF0: 0xE0800004,
    0x785880: 0xE5801088,
    0x659528: 0xE30A041C,
    0x65952C: 0xE3A01001,
    0x785878: 0xE5C01084,
    0x754B14: 0xE5900088,
    0x719894: 0xE5C010E0,
    0x654238: 0x308FF106,
    0x654354: 0xE58410C8,
    0x654358: 0xE1D502B4,
    0x65435C: 0xE1D522B6,
    0x654360: 0xE0020290,
    0x654368: 0xE1A030A2,
    0x654378: 0xE0800080,
    0x6543E0: 0xE3020194,
    0x654120: 0xE281001F,
    0x654124: 0xE3C0001F,
    0x660AF4: 0xE1D60BB2,
    0x660AF8: 0xE3500001,
    0x660B0C: 0xE5840160,
    0x660B14: 0xE5840164,
    0x660B1C: 0xE5840168,
    0x660D60: 0xE3020354,
    0x6593BC: 0xE3020194,
    0x6593C8: 0xE58D0034,
    0x6594AC: 0xE3020354,
    0x6594C0: 0xE0848000,
    0x6594C8: 0xE2845A02,
    0x659548: 0xE5D41059,
    0x659554: 0xE59D1034,
    0x659790: 0xE5D500B4,
    0x659794: 0xE3100044,
    0x65980C: 0xE5C4007F,
    0x71B548: 0xE5C010A8,
    0x71B578: 0xE59000AC,
    0x71B580: 0xE58010AC,
    0x71C520: 0xE5D000A8,
    0x71C528: 0xE5D00084,
    0x57BB70: 0x13A00002,
    0x57BB74: 0x03A00001,
    0x57BB88: 0xE3570001,
    0x57BB8C: 0x03A08001,
    0x57BDF8: 0xE3580000,
    0x702B8C: 0xE5900004,
    0x7B3290: 0xE5900008,
    0x7B3298: 0xE590000C,
    0x7543D4: 0xE580102C,
    0x7543DC: 0xE5801030,
    0x7543E4: 0xE5801034,
    0x81CFB0: 0xE5801004,
    0x81CFB8: 0xE5801008,
    0x81CFC0: 0xE580100C,
    0x5506EC: 0xE3C02007,
    0x550740: 0xE3C02007,
    0x550794: 0xE3C02007,
    0x659AC8: 0xE5941160,
    0x659AD4: 0xE5941164,
    0x659AE0: 0xE5941168,
    # JPEG destination alignment, slot fields and retry conditions.
    0x660784: 0xE5D41065,
    0x66078C: 0x159600F4,
    0x6607A8: 0xE58401D8,
    0x6607B8: 0xE5840190,
    0x6607BC: 0xE5840194,
    0x6607C0: 0xE5D4103E,
    0x6607C8: 0x159412E4,
    0x6607CC: 0x059412E8,
    0x6607E0: 0xE58401DC,
    0x6607F8: 0xE58401E0,
    0x660808: 0xE5D4106B,
    0x660820: 0xE5840190,
    0x660824: 0xE59412E4,
    0x66083C: 0xE5840190,
    0x660840: 0xE5840194,
    0x660848: 0xE30293C4,
    0x660854: 0xE5971190,
    0x660874: 0xE59712E4,
    0x77F1D4: 0xE3A00010,
    0x576C6C: 0xE5940028,
    0x576C70: 0xE1500001,
    0x576C78: 0xE3500000,
    0x5767B4: 0x03A05FFA,
    0x5767C0: 0x03A05E7D,
    0x5767C8: 0xE0444005,
    0x5767D8: 0xB3A04064,
    0x5767FC: 0xE1510000,
    0x576804: 0xE3500000,
    0x57680C: 0xE3540064,
    0x71C278: 0xE5900008,
    0x71C290: 0xE5900000,
    0x71AF40: 0xE580100C,
    0x71AEF8: 0xE5801020,
    0x78557C: 0xE580100C,
}
LITERALS = {
    0x5506F0: 0x20022440, 0x550744: 0x20022450, 0x550798: 0x20022460,
    0x77F1CC: 0xDBC00,
}
RANGES = {
    "slot_13_layout": (0x654218, 0x654414),
    "masked_layout_setup": (0x6609AC, 0x660D94),
    "cpp_descriptor_setup": (0x6593B0, 0x659814),
    "ordinary_scaler_source": (0x659AC8, 0x659AEC),
    "cpp_second_pass_descriptor": (0x653E70, 0x653EFC),
    "cpp_pass_count_and_marker": (0x57BB60, 0x57BBB0),
    "cpp_replace_and_apply": (0x57BCE4, 0x57BF44),
    "cpp_pass_loop": (0x57C018, 0x57C028),
    "b2y_program_planes": (0x58BC84, 0x58BDC8),
    "jpeg_layout_and_init": (0x660778, 0x6608B0),
    "jpeg_retry_attempt_and_loop": (0x5765D8, 0x576824),
    "jpeg_initial_result_gate": (0x576C60, 0x576C9C),
}


def verify_static(data):
    for edges in EDGES.values():
        for site, target in edges:
            require(branch_target(data, site), target, f"branch at {site:#x}")
    for site, value in LITERALS.items():
        require(u32(data, literal_offset(data, site)), value, f"literal at {site:#x}")
    check_words(data, WORDS)
    return {
        "edges": EDGES,
        "instruction_offsets": list(WORDS),
        "literal_reads": LITERALS,
        "ranges": {
            name: {"start": start, "end_exclusive": end, "sha256": sha256(data[start:end])}
            for name, (start, end) in RANGES.items()
        },
    }


def round_up(value, alignment):
    return (value + alignment - 1) & -alignment


def plane_layout(start, area, padding):
    y = round_up(round_up(start, 32) + 3 * padding, 32)
    c1 = round_up(round_up(y + area, 32) + 3 * padding, 32)
    c2 = round_up(round_up(c1 + (area >> 1), 32) + 3 * padding, 32)
    return [y, c1, c2]


def emulate(data):
    from unicorn import Uc, UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, __version__
    from unicorn import arm_const as arm

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(BASE, 0x1000000)
    uc.mem_write(BASE, data[:0x1000000])
    job, device, sp, ret = 0x10000000, 0x10020000, 0x10038000, 0x1003E000
    uc.mem_map(job, 0x40000)
    uc.mem_map(0x20022000, 0x1000)
    uc.reg_write(arm.UC_ARM_REG_FPEXC, 0x40000000)

    def write(address, *values, fmt="I"):
        uc.mem_write(address, pack(f"<{len(values)}{fmt}", *values))

    def read(address, count=1):
        return list(unpack(f"<{count}I", uc.mem_read(address, 4 * count)))

    def run(start, end=None, **regs):
        stop = ret if end is None else BASE + end
        for name, value in dict(sp=sp, lr=ret, **regs).items():
            uc.reg_write(getattr(arm, f"UC_ARM_REG_{name.upper()}"), value)
        uc.emu_start(BASE + start, stop, count=100_000)
        require(uc.reg_read(arm.UC_ARM_REG_PC), stop, f"probe stop from {start:#x}")
        return uc.reg_read(arm.UC_ARM_REG_R0)

    cpp_cases = []
    payload = job + 0xA41C
    for mask, builder_mode, second_flag, process_gate in (
        (0x00, 0, 0, 1), (0x04, 1, 0, 1), (0x40, 1, 1, 1),
        (0x44, 1, 1, 1), (0x80, 0, 2, 1), (0x04, 1, 1, 0),
        (0x00, 1, 1, 1), (0x44, 0, 0, 1),
    ):
        uc.mem_write(job, bytes(0x17000))
        width, height, padding = 19, 7, 11
        direct_base, second_base = 0x11000103, 0x11100205
        write(job + 0x224, width, height, fmt="H")
        write(job + 0x130, padding)
        write(job + 0xD8, direct_base)
        write(job + 0x20B2, builder_mode, fmt="H")
        write(job + 0x20B4, mask, fmt="B")
        # The builders have independent predicates. Seed the unused layout with a distinct triplet.
        other = [0x11200003, 0x11300005, 0x11400007]
        write(job + 0x160, *other)
        write(job + 0x2358, *other)
        masked = bool(mask & 0x44)
        run(0x6609AC, 0x660D94 if builder_mode else 0x660B20, r0=job)
        built_at = job + (0x2358 if builder_mode else 0x160)
        built = plane_layout(direct_base, width * height, padding)
        require(read(built_at, 3), built, "initial CPP layout producer")
        initial = built if masked == bool(builder_mode) else other
        run(0x654218, 0x654414, r0=job, r1=13, r2=second_base)
        second = plane_layout(second_base, width * height, padding)
        require(read(job + 0x2198, 3), second, "slot 13 alternate plane producer")
        write(job + 0x59, second_flag, fmt="B")
        companion = job + 0xE0C4
        run(0x653EE8, 0x653EFC, r4=job, r8=companion)
        write(sp + 0x34, job + 0x2194)
        write(sp + 0x40, job + 0x2680)
        run(0x659528, 0x659588, r4=job)
        require(uc.mem_read(payload + 0x84, 1)[0], 1, "CPP producer processing gate")
        if not process_gate:
            write(payload + 0x84, 0, fmt="B")
        require(read(payload + 0xAC), [job + 0x2194], "CPP alternate descriptor pointer")
        run(0x659790, 0x659810, r4=job, r5=job + 0x2000, r8=job + 0x2354)
        require(read(payload + 0x2C, 3), initial, "CPP initial address selection")
        require(uc.mem_read(job + 0x7F, 1)[0], int(masked), "CPP initial branch state")
        pass_count = 2 if second_flag else 1
        run(0x57BB60, 0x57C01C)
        require(read(sp + 0x20), [pass_count], "CPP pass count")
        passes = []
        for index in range(pass_count):
            write(sp + 4, payload)
            run(0x57BB80, 0x57BBB0, sb=second_flag, r7=index)
            require(uc.mem_read(companion + 0xE0, 1)[0], index, "CPP second-pass marker")
            run(0x57BCE4, 0x57BCF4 if process_gate else 0x57C000)
            if not process_gate:
                continue
            run(0x57BDF8, 0x57BE60)
            expected = second if index else initial
            require(read(payload + 0x2C, 3), expected, "CPP pass plane addresses")
            run(0x58BC84, 0x58BDC8, r4=device, fp=payload)
            mmio = [read(address)[0] for address in (0x20022440, 0x20022450, 0x20022460)]
            require(mmio, [address & ~7 for address in expected], "B2Y output address registers")
            passes.append({"index": index, "planes": expected, "b2y_first_slot": mmio})
        cpp_cases.append({
            "mask_byte": mask, "layout_builder_mode": builder_mode,
            "second_pass_flag": second_flag, "process_gate": process_gate,
            "second_pass_marker": uc.mem_read(companion + 0xE0, 1)[0],
            "initial_address_source": "job+0x2354" if masked else "job+0x160",
            "pass_count": pass_count, "passes_entering_output_branch": passes,
        })

    jpeg_layouts = []
    for reserved, separate, pick_primary, add_offset in (
        (0, 0, 0, 0), (0, 1, 0, 1), (1, 0, 0, 1), (1, 1, 1, 0),
    ):
        uc.mem_write(job, bytes(0x2400))
        base, offset, cap0, cap1 = 0x12000013, 29, 273, 301
        write(job + 0x40, add_offset, fmt="B")
        write(job + 0x20F4, offset)
        write(job + 0x65, reserved, fmt="B")
        write(job + 0x6B, separate, fmt="B")
        write(job + 0x3E, pick_primary, fmt="B")
        write(job + 0x2E4, cap0, cap1)
        # +0x2e8 serves as slot 1 capacity and as the reserved path's secondary span.
        adjusted = base + (offset if add_offset else 0)
        run(0x660778, 0x6608B0, r0=base, r3=base, r4=job, r6=job + 0x2000)
        if reserved:
            prefix = round_up(adjusted, 32)
            selected_span = cap0 if pick_primary else cap1
            first = second = prefix + 16
            next_start = round_up(first + selected_span, 32)
            regions = [prefix, next_start, next_start + 0xDBC00]
            require(read(job + 0x1D8, 3), regions, "reserved JPEG layout")
        else:
            first = round_up(adjusted, 16)
            second = round_up(first + cap0, 16) if separate else first
            regions = None
        require(read(job + 0x190, 2), [first, second], "JPEG slot destination fields")
        for i, (address, capacity) in enumerate(((first, cap0), (second, cap1))):
            require(read(job + 0x23C4 + 0x18 * i, 4), [address, 0, capacity, 0],
                    f"JPEG output descriptor {i}")
        jpeg_layouts.append({
            "reserved_prefix_flag": reserved, "separate_flag": separate,
            "primary_span_flag": pick_primary, "add_job_offset_flag": add_offset,
            "slot_addresses": [first, second], "slot_capacities": [cap0, cap1],
            "reserved_region_starts": regions,
        })

    jpeg_input, jpeg_output = job + 0x2500, job + 0x2600
    planes, destination, capacity = [0x12100100, 0x12200200, 0x12300300], 0x12400400, 800
    write(jpeg_input + 4, *planes)
    write(jpeg_output, destination, 0, capacity, 0)
    initial_gates = []
    for count, retries in ((0, True), (1, False), (capacity, False), (capacity + 1, True)):
        write(device + 0x28, count)
        run(0x576C60, 0x576C80 if retries else 0x576CA0, r4=device, sb=jpeg_output)
        initial_gates.append({"count": count, "capacity": capacity, "calls_retry_path": retries})

    calls = []
    counts = iter(())

    def hardware_boundary(emulator, address, _size, _user_data):
        if address == BASE + 0x53D700:
            descriptor = emulator.reg_read(arm.UC_ARM_REG_R2)
            require(read(descriptor, 4), planes + [destination], "retry device descriptor pointers")
            require(read(descriptor + 0x18), [capacity], "retry device descriptor capacity")
            count = next(counts)
            calls.append({"quality": read(descriptor + 0x20)[0], "reported_count": count})
            write(device + 0x28, count)
        emulator.reg_write(arm.UC_ARM_REG_PC, emulator.reg_read(arm.UC_ARM_REG_LR))

    for site in (0x53D700, 0x70C408, 0x70C3E8, 0x53DC10):
        uc.hook_add(UC_HOOK_CODE, hardware_boundary, begin=BASE + site, end=BASE + site)

    retry_cases = []
    for selector, quality, reported, expected_qualities in (
        (0, 1300, [capacity, 260], [800, 300]),
        (1, 1850, [0, capacity + 1], [850, 100]),
        (2, 2100, [capacity], [100]),
        (9, 1300, [1], [800]),
    ):
        calls.clear()
        counts = iter(reported)
        write(sp, selector, 0)
        result = run(0x576780, r0=device, r1=jpeg_input, r2=jpeg_output, r3=quality)
        require(calls, [
            {"quality": q, "reported_count": n} for q, n in zip(expected_qualities, reported)
        ], "retry schedule")
        require(result, expected_qualities[-1], "retry returned last quality")
        require(read(jpeg_output + 0xC), [reported[-1]], "retry last count writeback")
        retry_cases.append({
            "selector": selector, "initial_quality": quality, "attempts": list(calls),
            "returned_quality": result, "final_descriptor_count": reported[-1],
        })
    return {
        "engine": f"Unicorn {__version__}",
        "cpp_cases": cpp_cases, "jpeg_layouts": jpeg_layouts,
        "jpeg_initial_gates": initial_gates, "jpeg_retry_cases": retry_cases,
        "retry_shared_planes": planes, "retry_shared_destination": destination,
        "retry_capacity": capacity,
        "hooked_retry_boundaries": [0x53D700, 0x70C408, 0x70C3E8, 0x53DC10],
    }


def analyze(data):
    return {
        "decoded_sha256": DECODED_SHA256,
        "candidate_load_base": BASE,
        "location_units": "decoded file offsets except absolute MMIO and synthetic addresses",
        "static": verify_static(data),
        "synthetic_a32": emulate(data),
        "limits": [
            "CPP initial address selection uses job+0x20b4 masked by 0x44. The layout builder uses "
            "job+0x20b2 equal to one. The probes also vary these predicates independently "
            "using a synthetic triplet for the layout the builder does not populate.",
            "CPP payload+0xa8 comes from job+0x59. Its nonzero path schedules a second iteration. "
            "The payload+0x84 gate must also permit processing for its address replacement to run. "
            "The ordinary producer sets this gate to one. The bypass probe injects zero.",
            "The ordinary scaler source builder uses job+0x160/+0x164/+0x168. "
            "A downstream alias from the alternate CPP planes to module 16 input is unresolved.",
            "Address calculations use 32-bit A32 arithmetic. Probes use small synthetic layouts "
            "without overflow. They establish neither allocation bounds nor pixel or DMA behavior.",
            "JPEG retries use the original descriptor assembly and count writeback. Device launch, "
            "event clear/wait and teardown are hooked; reported counts are supplied by the harness. "
            "No JPEG payload is generated.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = json.dumps(analyze(load_image(args.decoded)), indent=2)
    if args.compare:
        require(json.loads(result), json.loads(args.compare.read_text(encoding="utf-8")),
                "published alternate-buffer evidence")
    print(result)


if __name__ == "__main__":
    main()
