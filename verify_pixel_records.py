"""Replay K-3 II preserved pixel record loading, correction and save requests.

SPDX-License-Identifier: GPL-2.0-only
"""

import argparse
from hashlib import shake_256
import json
from pathlib import Path
from struct import pack, unpack_from

from verify_findings import literal_offset, require, sha256, u32
from verify_preserved_record import SECTOR_BYTES, STAGING
from verify_raw_path import branch_target
from verify_tone_path import BASE, adr_r0_target, check_edge, check_words, load_image


BANK_BYTES = 0x10000
FLASH, RAM, PROVIDER = 0x021E0000, 0x40130000, 0x4040AF30
FIRST_ID, BANKS, MARKER = 0x58, 10, 0xA55A5AA5
LIMIT, RECORD_BYTES = 0x2A94, 6
LOADER, CONSUMER, KERNEL = 0x73A204, 0x73A5EC, 0x739F80
CONSUMER_VTABLE = 0xA76A20
DX = (-2, 2, 0, 0, -2, 2, -2, 2, -4, 4, -4, 4, -4, 4, 0, 0)
DY = (0, 0, -2, 2, -2, -2, 2, 2, 0, 0, -2, -2, 2, 2, 0, 0)
AXES = ((0x739FD0, 0x73A4A8, 0x9E7328, DX), (0x739FE0, 0x73A4AC, 0x9E7368, DY))
CALLS = (
    (0x73A1F4, 0x76B478),
    (0x73A1F8, 0x785804),
    (0x73A210, 0x73A1F0),
    (0x6E84DC, 0x6E7E9C),
    (0x73A61C, 0x784248),
    (0x73A624, 0x785F70),
    (0x73A670, KERNEL),
    (0x739FC0, 0x739F44),
    (0x73A03C, 0x739F40),
    (0x73A098, 0x739F40),
    (0x73A0CC, 0x712C44),
    (0x73A0E0, 0x739F20),
    (0x73A0F8, 0x7073EC),
    (0x6E854C, 0x599D18),
    (0x6E8758, 0x599D6C),
    (0x6E877C, 0x599D18),
    (0x6E8858, 0x599D18),
    (0x6E8934, 0x599D18),
    (0x6E8A10, 0x599D18),
    (0x6E8AEC, 0x599D18),
    (0x6E87DC, 0x599E88),
    (0x6E883C, 0x599E88),
    (0x6E88B8, 0x599E88),
    (0x6E8918, 0x599E88),
    (0x6E8994, 0x599E88),
    (0x6E89F4, 0x599E88),
    (0x6E8A70, 0x599E88),
    (0x6E8AD0, 0x599E88),
    (0x6E8B4C, 0x599E88),
    (0x6E8BAC, 0x599E88),
    (0x6E8848, 0x599D6C),
    (0x6E8924, 0x599D6C),
    (0x6E8A00, 0x599D6C),
    (0x6E8ADC, 0x599D6C),
    (0x6E8BB8, 0x599D6C),
    (0x599DB0, 0x599914),
    (0x65D664, 0x71A880),
    (0x65D670, 0x71A870),
    (0x65D67C, 0x71A8A0),
    (0x65D688, 0x71A8A8),
    (0x65D694, 0x71A898),
    (0x65D6A0, 0x71A888),
    (0x65D6B0, 0x71A890),
    (0x581750, 0x72D8C4),
    (0x581784, 0x72D8CC),
    (0x5817A8, 0x739E88),
    (0x5817F8, 0x71C310),
    (0x581808, 0x71C300),
    (0x581814, CONSUMER),
)
TAILS = ((0x73A200, 0x6E84C8), (0x739F20, 0x739F00), (0x739F40, 0x739F24))
WORDS = {
    0x6E84D0: 0xE3A05058,
    0x6E8514: 0xE3550062,
    0x6E851C: 0xA5C602CA,
    0x6E8764: 0xE5D402CA,
    0x6E876C: 0x0A00011C,
    0x739D20: 0xE5C02012,
    0x73A1D0: 0xE3024A94,
    0x73A1DC: 0x83022A94,
    0x73A1E4: 0xE1C424BE,
    0x73A1E8: 0xE5803064,
    0x73A5E0: 0xE5C46012,
    0x73A5F4: 0xE5D00012,
    0x73A604: 0x0BFFFEFE,
    0x73A638: 0x0A00001F,
    0x73A650: 0xE1D400B2,
    0x73A654: 0xE5951020,
    0x73A65C: 0xE1D430B4,
    0x73A664: 0xE1D410B0,
    0x73A674: 0xE2844006,
    0x73A68C: 0xE08AA007,
    0x739FA4: 0xE1A00725,
    0x739FA8: 0xE2800001,
    0x739FAC: 0xE1D111B0,
    0x739FB4: 0x8A00004A,
    0x739FC8: 0x0A000045,
    0x739FF8: 0xE31500FF,
    0x73A054: 0xE3580002,
    0x73A0B0: 0xE3580002,
    0x597AB4: 0xE580101C,
    0x65D650: 0xE59D0040,
    0x65D658: 0xE30A03E8,
    0x65D668: 0xE594113C,
    0x65D68C: 0xE5D41049,
    0x581800: 0x0A000004,
    0x71C300: 0xE5900004,
    0x71C310: 0xE5D0000A,
    0x71A898: 0xE5C0100A,
    0x597F90: 0xE1D000B4,
    0x739F38: 0xE1D000B0,
    0x739F18: 0xE1C030B0,
    0x73A028: 0xE6FF2070,
    0x73A034: 0xE6FF1070,
    0x73A080: 0xE6FF2070,
    0x73A090: 0xE6FF1070,
    0x73A668: 0xE6FF2070,
}
RANGES = (
    (0x76B830, 0x76B8D0),
    (0x6E84C8, 0x6E8528),
    (0x6E8528, 0x6E8C08),
    (0x597F44, 0x599574),
    (0xA732B0, 0xA732B0 + 7 * 0x3C),
    (0xA74208, 0xA74208 + 3 * 0x3C),
    (0x739CF4, 0x739D88),
    (0x739F00, 0x73A100),
    (0x73A1C4, 0x73A6C8),
    (0x9E7328, 0x9E73A8),
    (0x65D650, 0x65D6B4),
    (0x58174C, 0x581818),
    (0x739E88, 0x739EE8),
)


def verify_static(data):
    check_words(data, WORDS)
    for site, target in CALLS:
        check_edge(data, site, target)
    for site, target in TAILS:
        check_edge(data, site, target, link=False)
    require(branch_target(data, 0x73A604), LOADER, "lazy loader")
    require(branch_target(data, 0x73A638), 0x73A6BC, "first invalid bank exits")
    require(
        u32(data, literal_offset(data, 0x739CFC)),
        BASE + CONSUMER_VTABLE,
        "consumer vtable",
    )
    for site, literal, table, expected in AXES:
        require(literal_offset(data, site), literal, "neighbor table literal offset")
        require(u32(data, literal), BASE + table, "neighbor table VA")
        require(unpack_from("<16i", data, table), expected, "neighbor offsets")
    for site, expected in (
        (0x65D6A4, 0x1646C),
        (0x581774, 0x01180001),
        (0x76B478, 0x4040AE64),
        (0x76B4B8, 0x4040B0EC),
    ):
        require(
            u32(data, literal_offset(data, site)),
            expected,
            "packet or singleton literal",
        )
    diagnostic = adr_r0_target(data, 0x73A0F4)
    require(diagnostic, 0x73A4B0, "zero-mask diagnostic offset")
    prefix = b"Adjust Data Err! Pixel Correct Data Around All Dead."
    require(data[diagnostic : diagnostic + len(prefix)], prefix, "zero-mask diagnostic")

    providers = []
    for index in range(BANKS):
        start = 0x76C628 + index * 0x14
        registration = 0x76B830 + index * 0x10
        ctor = 0x5980A8 + index * 0x238
        table = 0xA732B0 + index * 0x3C if index < 7 else 0xA74208 + (index - 7) * 0x3C
        literal = 0x76C00C + index * 4
        flash, ram = FLASH + index * BANK_BYTES, RAM + index * BANK_BYTES
        object_va = PROVIDER + index * 4
        check_edge(data, start + 4, ctor)
        check_edge(data, registration + 0xC, 0x6E9494)
        require(
            u32(data, registration + 4),
            0xE3A01000 + FIRST_ID + index,
            "registration ID",
        )
        for site in (start, registration):
            require(
                literal_offset(data, site),
                literal,
                "startup and register share object literal",
            )
        require(u32(data, literal), object_va, "provider object VA")
        for site, value in (
            (ctor + 8, BASE + table),
            (ctor + 0x28, flash),
            (ctor + 0x40, ram),
            (ctor + 0x74, flash),
            (ctor + 0x7C, ram),
        ):
            require(u32(data, literal_offset(data, site)), value, "provider literal")
        for slot, delta in (
            (0xC, 0x28),
            (0x18, 0x40),
            (0x1C, 0x74),
            (0x20, 0x84),
            (0x24, 0x8C),
            (0x28, 0x94),
        ):
            require(
                u32(data, table + slot), BASE + ctor + delta, "native provider slot"
            )
        require(u32(data, ctor + 0x94), 0xE3A00902, "bank size in halfwords")
        require(
            unpack_from("<2I", data, flash - BASE),
            (0xFFFFFFFF, 0x3FFE0000),
            "original image bank header",
        )
        providers.append(
            {
                "id": FIRST_ID + index,
                "startup_file_offset": start,
                "registration_file_offset": registration,
                "constructor_file_offset": ctor,
                "provider_va": object_va,
                "vtable_file_offset": table,
                "flash_va": flash,
                "ram_va": ram,
            }
        )
    return {
        "calls": [list(edge) for edge in CALLS],
        "tail_branches": [list(edge) for edge in TAILS],
        "word_checks": len(WORDS),
        "providers": providers,
        "neighbor_table_file_offsets": [entry[2] for entry in AXES],
        "neighbor_dx": list(DX),
        "neighbor_dy": list(DY),
        "zero_mask_diagnostic_file_offset": diagnostic,
        "original_bank_header_words": [0xFFFFFFFF, 0x3FFE0000],
        "range_sha256": [
            {"start": lo, "end_exclusive": hi, "sha256": sha256(data[lo:hi])}
            for lo, hi in RANGES
        ],
    }


def emulate(data, providers):
    import unicorn as uc
    from unicorn import arm_const as arm

    vm = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    for address, size in (
        (BASE, 0x1000000),
        (0x40400000, 0x100000),
        (RAM, BANKS * BANK_BYTES),
        (0x10000000, 0x100000),
    ):
        vm.mem_map(address, size)
    vm.mem_write(BASE, data[:0x1000000])
    manager, obj, image = 0x10010000, 0x10020000, 0x10030000
    stack, stop, owner = 0x100F0000, 0x100F1000, 0x4040B0EC

    def read(address, size):
        return bytes(vm.mem_read(address, size))

    def get(address, size=4):
        return int.from_bytes(read(address, size), "little")

    def put(address, value, size=4):
        vm.mem_write(address, value.to_bytes(size, "little"))

    def reg(name, value=None):
        index = getattr(arm, f"UC_ARM_REG_{name.upper()}")
        if value is None:
            return vm.reg_read(index)
        vm.reg_write(index, value)

    def run(entry, *argv, end=None, **registers):
        for name, value in dict(sp=stack, lr=stop, **registers).items():
            reg(name, value)
        for index, value in enumerate(argv):
            reg(f"r{index}", value)
        finish = stop if end is None else BASE + end
        vm.ctl_flush_tb()
        vm.emu_start(BASE + entry, finish, count=10000000)
        require(reg("pc"), finish, f"native boundary from {entry:#x}")
        return reg("r0")

    run(0x6E80BC, manager)
    require(get(manager + 0x2CA, 1), 0, "native manager constructor")
    put(0x4040AE64, 1)
    put(owner + 4, manager)
    for row in providers:
        start = row["startup_file_offset"]
        require(
            run(start, end=start + 8), row["provider_va"], "original constructor result"
        )
        require(
            get(row["provider_va"]),
            BASE + row["vtable_file_offset"],
            "constructed provider table",
        )
    run(0x76B830, end=0x76B8D0, r4=owner)
    for row in providers:
        provider = run(0x6E7E9C, manager, row["id"])
        require(provider, row["provider_va"], "native registration lookup")
        for slot, expected in (
            (0x20, row["ram_va"]),
            (0x24, row["flash_va"]),
            (0x28, BANK_BYTES // 2),
        ):
            require(
                run(get(get(provider) + slot) - BASE, provider),
                expected,
                "native provider getter",
            )

    records_seen, calls = [], []

    def observe(_vm, pc, _size, _user):
        off = pc - BASE
        calls.append(off)
        if off == KERNEL:
            require(reg("r0"), obj, "native kernel owner")
            require(get(reg("sp")), 1, "native kernel threshold-gate argument")
            records_seen.append(tuple(reg(name) for name in ("r1", "r2", "r3")))
        if off == 0x785F70:
            reg("r0", 0)
            reg("pc", reg("lr"))

    for off in (LOADER, CONSUMER, 0x739E88, 0x785F70, KERNEL, 0x739F00):
        vm.hook_add(uc.UC_HOOK_CODE, observe, begin=BASE + off, end=BASE + off)

    def construct(threshold):
        put(obj + 0x12, 0xA5, 1)
        run(0x739CF4, obj)
        require(get(obj), BASE + CONSUMER_VTABLE, "original consumer vtable")
        require(get(obj + 0x12, 1), 0, "original lazy-load flag default")
        require(read(obj + 0x44, 72), bytes(72), "original descriptor defaults")
        put(obj + 4, 16, 2)
        put(obj + 6, 16, 2)
        put(obj + 0x10, threshold, 2)

    invalid_default = pack("<2I", 0xFFFFFFFF, 0x3FFE) + bytes(BANK_BYTES - 8)

    def stage_banks(fixture, poison_ram=True):
        expected_ram, expected_descriptors = [], []
        for index, row in enumerate(providers):
            count, records = fixture.get(index, (None, [(8, 8, 1)]))
            valid = count is not None
            payload = pack("<II", MARKER if valid else 0, count if valid else 1)
            payload += b"".join(pack("<3H", *record) for record in records)
            payload += bytes([index + 0x50]) * (BANK_BYTES - len(payload))
            vm.mem_write(row["flash_va"], payload)
            if poison_ram:
                vm.mem_write(row["ram_va"], bytes([0xA5]) * BANK_BYTES)
            expected_ram.append(payload if valid else invalid_default)
            expected_descriptors.append(
                (1, min(count & 0xFFFF, LIMIT), row["ram_va"] + 8)
                if valid
                else (0, 0, 0)
            )
        return expected_ram, expected_descriptors

    def descriptors():
        return [
            (
                get(obj + 0x44 + i, 1),
                get(obj + 0x4E + 2 * i, 2),
                get(obj + 0x64 + 4 * i),
            )
            for i in range(BANKS)
        ]

    def check_banks(expected):
        require(
            [read(row["ram_va"], BANK_BYTES) for row in providers],
            expected,
            "native bank load/default bytes",
        )

    def process(initial, changes, expected_records, lazy):
        expected = initial.copy()
        for (x, y), value in changes.items():
            expected[16 * y + x] = value
        vm.mem_write(image - 2, pack("<258H", 0xABCD, *initial, 0xDCBA))
        calls.clear()
        records_seen.clear()
        count = run(CONSUMER, obj, image)
        require(count, len(expected_records), "visited record count")
        require(
            records_seen, expected_records, "native record arguments in execution order"
        )
        record_path = [KERNEL, 0x739F00] if changes else [KERNEL]
        require(
            calls,
            [CONSUMER] + [LOADER] * lazy + [0x785F70] + record_path * count,
            "observed load, timer, record and write order",
        )
        require(get(obj + 0xC), image, "native image pointer")
        require(
            read(image - 2, 516),
            pack("<258H", 0xABCD, *expected, 0xDCBA),
            "whole image and canaries",
        )
        return {
            "visited_records": count,
            "kernel_arguments": [list(row) for row in records_seen],
            "native_writes": calls.count(0x739F00),
            "lazy_loader_calls": calls.count(LOADER),
            "changed_centers": [
                {
                    "x": x,
                    "y": y,
                    "before": initial[16 * y + x],
                    "after": get(image + 2 * (16 * y + x), 2),
                }
                for x, y in changes
            ],
            "image_sha256": sha256(read(image, 512)),
        }

    def image_fixture(*pixels):
        initial = list(range(256))
        for x, y, value in pixels:
            initial[16 * y + x] = value
        return initial

    first, second = (8, 8, 3), (8, 10, 12)
    initial = image_fixture(
        (6, 8, 200), (10, 8, 400), (8, 8, 9999), (8, 12, 600), (8, 10, 8888)
    )
    construct(1)
    banks, ordered_descriptors = stage_banks({0: (1, [first]), 1: (1, [second])})
    ordered = process(initial, {(8, 8): 300, (8, 10): 450}, [first, second], True)
    check_banks(banks)
    require(descriptors(), ordered_descriptors, "native two-bank descriptors")
    require(get(obj + 0x12, 1), 1, "original lazy-load flag set")
    require(get(manager + 0x2CA, 1), 1, "original later-save flag set")
    initialized, save_enabled = get(obj + 0x12, 1), get(manager + 0x2CA, 1)
    save = replay_save(vm, uc, manager, providers, read, reg, run)

    packet_cases = replay_packet(
        vm, obj, image, initial, read, get, put, run, calls, records_seen
    )

    invalid_banks, _ = stage_banks({}, poison_ram=False)
    cached = process(initial, {(8, 8): 300, (8, 10): 450}, [first, second], False)
    check_banks(banks)
    require(
        descriptors(), ordered_descriptors, "lazy entry preserves cached descriptors"
    )
    run(LOADER, obj)
    check_banks(invalid_banks)
    retained_descriptors = descriptors()
    require(
        retained_descriptors,
        ordered_descriptors,
        "explicit reload leaves existing descriptor fields",
    )
    reloaded_header = list(unpack_from("<2I", read(RAM, 8)))

    cases = []
    for label, threshold, fixture, image_before, changes, visited in (
        (
            "reversed_bank_order",
            1,
            {0: (1, [second]), 1: (1, [first])},
            initial,
            {(8, 10): 5299, (8, 8): 300},
            [second, first],
        ),
        (
            "two_records_one_bank",
            1,
            {0: (2, [first, second])},
            initial,
            {(8, 8): 300, (8, 10): 450},
            [first, second],
        ),
        (
            "first_invalid_bank_ends_walk",
            1,
            {0: (1, [first]), 2: (1, [second])},
            initial,
            {(8, 8): 300},
            [first],
        ),
        ("all_invalid_markers_on_fresh_object", 1, {}, initial, {}, []),
        (
            "low_group_precedes_high_group",
            1,
            {0: (1, [(8, 8, 0x0301)])},
            initial,
            {(8, 8): 200},
            [(8, 8, 0x0301)],
        ),
        (
            "first_two_bits_in_low_group",
            1,
            {0: (1, [(8, 8, 7)])},
            initial,
            {(8, 8): 300},
            [(8, 8, 7)],
        ),
        (
            "upper_group_uses_four_pixel_offsets",
            1,
            {0: (1, [(8, 8, 0x0300)])},
            image_fixture((4, 8, 120), (12, 8, 401)),
            {(8, 8): 260},
            [(8, 8, 0x0300)],
        ),
        (
            "upper_threshold_bits_reject",
            1,
            {0: (1, [(8, 8, 0x4001)])},
            initial,
            {},
            [(8, 8, 0x4001)],
        ),
        (
            "upper_threshold_bits_pass_at_equality",
            2,
            {0: (1, [(8, 8, 0x4001)])},
            initial,
            {(8, 8): 200},
            [(8, 8, 0x4001)],
        ),
        (
            "center_x_equal_to_width",
            1,
            {0: (1, [(16, 8, 1)])},
            initial,
            {},
            [(16, 8, 1)],
        ),
    ):
        construct(threshold)
        expected_ram, expected_descriptors = stage_banks(fixture)
        result = process(image_before, changes, visited, True)
        check_banks(expected_ram)
        require(descriptors(), expected_descriptors, "fresh native descriptor state")
        cases.append(
            {
                "case": label,
                "threshold": threshold,
                "descriptors": descriptors(),
                **result,
            }
        )

    construct(1)
    count_inputs = (0xA5A50000 | (LIMIT - 1), LIMIT, 0xFFFF)
    expected_ram, expected_descriptors = stage_banks(
        {i: (count, []) for i, count in enumerate(count_inputs)}
    )
    run(LOADER, obj)
    check_banks(expected_ram)
    require(descriptors(), expected_descriptors, "native count clamp")
    clamp = [
        {
            "bank_index": index,
            "injected_count_word": count,
            "descriptor_count": descriptors()[index][1],
        }
        for index, count in enumerate(count_inputs)
    ]

    boundary_controls = replay_boundaries(
        vm, uc, obj, image, stack, read, put, reg, run
    )
    return {
        "unicorn_version": uc.__version__,
        "separate_pixel_boundary_controls": boundary_controls,
        "registered_ids": [row["id"] for row in providers],
        "record_bytes": RECORD_BYTES,
        "initialized_flag": initialized,
        "manager_later_save_flag": save_enabled,
        "ordered_native_correction": {"descriptors": ordered_descriptors, **ordered},
        "cached_entry_after_source_invalidated": cached,
        "explicit_reload_without_constructor": {
            "bank_headers_after_reload": reloaded_header,
            "descriptors_after_reload": retained_descriptors,
        },
        "fresh_object_controls": cases,
        "loader_count_clamp": clamp,
        "packet_bridge_cases": packet_cases,
        "save": save,
        "correction_execution_replacements": {
            "0x785f70": "Elapsed-time query returns zero."
        },
    }


def replay_boundaries(vm, uc, obj, image, stack, read, put, reg, run):
    loads, stores, cases = [], [], []

    def observe(_vm, _access, address, size, _value, _user):
        off = reg("pc") - BASE
        if off == 0x739F38:
            loads.append([address - image, size])
        elif off == 0x739F18:
            stores.append([address - image, size])

    hook = vm.hook_add(
        uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE,
        observe,
    )

    def prepare(samples):
        run(0x739CF4, obj)
        for off, val, size in ((4, 16, 2), (6, 16, 2), (0xC, image, 4), (0x10, 1, 2)):
            put(obj + off, val, size)
        vm.mem_write(image - 2, pack("<258H", 0xABCD, *range(256), 0xDCBA))
        for offset, value in samples:
            put(image + offset, value, 2)
        loads.clear()
        stores.clear()
        return read(image - 2, 516)

    def check(label, initial, samples, center, value):
        require(loads, [[off, 2] for off, _ in samples], "exact original sample reads")
        require(
            stores,
            [] if value is None else [[center, 2]],
            "exact original pixel stores",
        )
        expected = (
            initial
            if value is None
            else initial[: center + 2] + pack("<H", value) + initial[center + 4 :]
        )
        require(read(image - 2, 516), expected, "entire boundary image and canaries")
        cases.append(
            {
                "case": label,
                "load_offsets_bytes": loads.copy(),
                "store_offsets_bytes": stores.copy(),
                "value": value,
            }
        )

    for label, x, y, flags, samples, value in (
        ("right_neighbor_crosses_row", 15, 8, 2, ((290, 4567),), 4567),
        (
            "left_neighbor_wraps_outside_logical_image",
            0,
            8,
            1,
            ((131324, 0xBEEF),),
            0xBEEF,
        ),
        ("two_maximum_range_samples", 8, 8, 3, ((268, 65535), (276, 65534)), 65534),
        ("center_x_equals_width", 16, 8, 1, (), None),
        ("center_y_equals_height", 8, 16, 4, (), None),
    ):
        initial = prepare(samples)
        put(stack, 1)
        run(KERNEL, obj, x, y, flags)
        check(label, initial, samples, 2 * (16 * y + x), value)

    initial = prepare(())
    record = 0x10028000
    for off, value, size in (
        (0x12, 1, 1),
        (0x20, 2, 4),
        (0x44, 1, 1),
        (0x4E, 1, 2),
        (0x64, record, 4),
    ):
        put(obj + off, value, size)
    vm.mem_write(record, pack("<3H", 8, 0xFFFF, 2))
    count = run(CONSUMER, obj, image)
    require(count, 1, "wrapped row visited count")
    check("consumer_row_offset_wraps_to_1", initial, ((52, 26),), 48, 26)
    cases[-1]["visited_records"] = count
    vm.hook_del(hook)
    return {
        "logical_image_bytes": 512,
        "cases": cases,
    }


def replay_packet(vm, obj, image, initial, read, get, put, run, calls, records_seen):
    capture, frame, ref = 0x10040000, 0x10070000, 0x10072000
    handler, event, stack = 0x10073000, 0x10074000, 0x100F0000
    payload = capture + 0xA3E8
    for offset, value, size in (
        (0x3C, 16, 2),
        (0x3E, 16, 2),
        (0x4A, 32, 2),
        (0x4E, 0, 2),
        (0x50, 0, 2),
        (0x150, 0, 4),
    ):
        put(frame + offset, value, size)
    put(ref, frame)
    put(stack + 0x40, ref)
    put(stack + 0x30, 0xA55A1234)
    put(capture + 0x13C, image)
    put(capture + 0x1646C, 1, 2)
    run(0x597AB4, handler, obj)
    require(get(handler + 0x1C), obj, "native handler binding")
    put(event + 8, payload)
    put(event + 0xC, 0x01180001)

    cases = []
    for enabled in (0, 1):
        vm.mem_write(payload, bytes([0xA5]) * 0x14)
        for offset, value in ((0x47, 0), (0x48, 0), (0x49, enabled)):
            put(capture + offset, value, 1)
        run(0x65D650, end=0x65D6B4, r4=capture)
        payload_flags = [get(payload + offset, 1) for offset in (8, 9, 0xA)]
        require(payload_flags, [0, 0, enabled], "native payload flags")
        require(
            [get(payload), get(payload + 4)],
            [frame, image],
            "native frame and image pointers",
        )
        require(get(payload + 0xC, 2), 1, "native payload threshold")
        require(get(payload + 0x10), 0xA55A1234, "native payload stack argument")
        vm.mem_write(image - 2, pack("<258H", 0xABCD, *initial, 0xDCBA))
        calls.clear()
        records_seen.clear()
        put(obj + 4, 1, 2)
        put(obj + 6, 1, 2)
        put(obj + 0x10, 0, 2)
        put(obj + 0xC, 0)
        run(0x58174C, end=0x581818, r4=handler, r5=event)
        expected = initial.copy()
        if enabled:
            expected[16 * 8 + 8], expected[16 * 10 + 8] = 300, 450
        require(
            get(obj + 0xC),
            image if enabled else 0,
            "image binding follows native enable",
        )
        path = [0x739E88]
        if enabled:
            path += [CONSUMER, 0x785F70, KERNEL, 0x739F00, KERNEL, 0x739F00]
        require(calls, path, "native packet correction route")
        require(
            records_seen,
            [(8, 8, 3), (8, 10, 12)] if enabled else [],
            "packet record arguments",
        )
        require(
            [get(obj + 4, 2), get(obj + 6, 2), get(obj + 0x10, 2)],
            [16, 16, 1],
            "native frame and threshold setup",
        )
        require(
            read(image - 2, 516),
            pack("<258H", 0xABCD, *expected, 0xDCBA),
            "whole packet image and canaries",
        )
        cases.append(
            {
                "injected_capture_0x49": enabled,
                "payload_flags": payload_flags,
                "observed_entries": calls.copy(),
                "payload_pointers_match_inputs": True,
                "center_values": [get(image + 2 * (16 * y + 8), 2) for y in (8, 10)],
                "image_sha256": sha256(read(image, 512)),
            }
        )
    return cases


def replay_save(vm, uc, manager, providers, read, reg, run):
    replacements = {
        0x599F20: "Leading mailbox helper returns zero.",
        0x599F6C: "Trailing mailbox helper returns zero.",
        0x72C988: "Privileged CPU helper returns zero.",
        0x599914: "Records the original request and returns an injected status before media operations.",
    }
    addresses = [FLASH - SECTOR_BYTES + SECTOR_BYTES * i for i in range(6)]
    vm.mem_write(
        addresses[0], shake_256(b"K-3 II pixel record save canary").digest(SECTOR_BYTES)
    )
    source_sectors = [read(va, SECTOR_BYTES) for va in addresses]
    ram_banks = [read(row["ram_va"], BANK_BYTES) for row in providers]
    expected_staging = [source_sectors[0]] + [
        ram_banks[i] + ram_banks[i + 1] for i in range(0, BANKS, 2)
    ]
    observed_reads, overlays, requests, replaced = [], [], [], []

    def hook(_vm, pc, _size, _user):
        off = pc - BASE
        if off == 0x599D18:
            observed_reads.append(reg("r1"))
            return
        if off == 0x599E88:
            overlays.append([reg("r1"), reg("r2"), reg("r3")])
            return
        replaced.append(off)
        if off == 0x72C988:
            require(reg("r0"), manager, "native save manager")
            require(reg("r1"), replaced.count(off) - 1, "native save CPU helper phase")
        if off == 0x599914:
            index = len(requests)
            require(reg("r1"), addresses[index], "native save request destination")
            require(reg("r2"), SECTOR_BYTES // 2, "native save request size")
            staged = read(STAGING, SECTOR_BYTES)
            require(staged, expected_staging[index], "entire native staging sector")
            requests.append(
                {
                    "destination_va": reg("r1"),
                    "halfwords": reg("r2"),
                    "staging_sha256": sha256(staged),
                    "injected_status": statuses[index],
                }
            )
            reg("r0", statuses[index])
        else:
            reg("r0", 0)
        reg("pc", reg("lr"))

    hooks = [
        vm.hook_add(uc.UC_HOOK_CODE, hook, begin=BASE + off, end=BASE + off)
        for off in (*replacements, 0x599D18, 0x599E88)
    ]
    cases = []
    for statuses in ((0, 1, 2, 0, 0, 1), (3, 0, 1, 2, 0, 1), (0, 0, 0, 0, 0, 0)):
        observed_reads.clear()
        overlays.clear()
        requests.clear()
        replaced.clear()
        vm.mem_write(STAGING - 1, bytes([0xA6]) * (SECTOR_BYTES + 2))
        status = run(0x6E8528, manager)
        require(status, max(statuses), "native combined positive status")
        require(observed_reads, addresses, "native reads for sectors 14 to 19")
        require(len(requests), len(addresses), "one request per sector")
        require(
            overlays,
            [[row["flash_va"], row["ram_va"], BANK_BYTES // 2] for row in providers],
            "native half-bank overlays",
        )
        require(
            replaced,
            [0x599F20, 0x72C988] + [0x599914] * 6 + [0x72C988, 0x599F6C],
            "all substituted boundaries in order",
        )
        require(
            [read(va, SECTOR_BYTES) for va in addresses],
            source_sectors,
            "mapped sector sources unchanged",
        )
        require(
            [read(row["ram_va"], BANK_BYTES) for row in providers],
            ram_banks,
            "provider RAM unchanged by save",
        )
        require(
            read(STAGING - 1, 1) + read(STAGING + SECTOR_BYTES, 1),
            b"\xA6\xA6",
            "staging canaries",
        )
        cases.append({"manager_return": status, "requests": requests.copy()})
    for hook_id in hooks:
        vm.hook_del(hook_id)
    return {
        "entry_file_offset": 0x6E8528,
        "request_entry_file_offset": 0x599914,
        "staging_va": STAGING,
        "registered_provider_ids": [row["id"] for row in providers],
        "read_addresses": observed_reads,
        "sector_14_provider_overlay": False,
        "overlay_arguments": overlays,
        "execution_replacements": {
            f"0x{off:x}": role for off, role in replacements.items()
        },
        "cases": cases,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    data = load_image(args.decoded)
    static = verify_static(data)
    result = {
        "firmware_version": "1.12",
        "decoded_sha256": sha256(data),
        "image_base": BASE,
        "bank_bytes": BANK_BYTES,
        "static": static,
        "replay": emulate(data, static["providers"]),
        "scope": [
            "Prepared owner and singleton guard skip full startup. Native constructors and registration slices bind the ten providers to the same manager.",
            "Mapped flash and image inputs are synthetic. Native correction reads and writes the same 16-bit image buffer. Return value counts records visited, including per-record rejects. Selected neighbors stay within the synthetic image in the primary correction and packet cases; separate boundary controls deliberately differ.",
            "The consumer stops at the first invalid descriptor. A fresh constructor leaves invalid slots zero; explicit loader re-entry can leave older descriptor fields in place after RAM is reinitialized.",
            "The event envelope, frame and capture flag inputs are prepared. The replay runs the original payload writer and handler slice, skipping handler base construction and task scheduling.",
            "Five separate boundary cases call the kernel with prepared coordinates, flags and stack argument, including two invalid centers. One consumer case prepares an already-loaded descriptor and row offset. The existing synthetic RAM includes a sample beyond the logical image. These controls establish original address arithmetic, not real sensor-table contents or live capture reachability.",
            "Save requests cover sectors 14 through 19 with only the ten pixel providers registered. Sector 14 is carried through unchanged in this fixture. Physical writes, retention, calibration, sensor input and normal capture reachability are outside the replay.",
        ],
    }
    output = json.dumps(result, indent=2)
    if args.compare:
        require(
            json.loads(output),
            json.loads(args.compare.read_text(encoding="utf-8")),
            "snapshot replay",
        )
    print(output)


if __name__ == "__main__":
    main()
