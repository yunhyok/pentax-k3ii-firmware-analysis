"""Replay the K-3 II pixel-record policy and its native packet handoff.

SPDX-License-Identifier: GPL-2.0-only
"""

import argparse
from bisect import bisect_left, bisect_right
from itertools import product
import json
from pathlib import Path
from struct import pack, unpack_from

from verify_findings import literal_offset, require, sha256, u32
from verify_pixel_records import (
    BANK_BYTES,
    BANKS,
    CONSUMER,
    FIRST_ID,
    FLASH,
    MARKER,
    RAM,
)
from verify_tone_path import BASE, check_edge, check_words, load_image


POLICY, LOOKUP, FORCE = 0x65EA68, 0x5A0EF0, 0x5A1054
TABLE, TABLE_BYTES = 0x9E6242, 104
A_UPPER = (0x4000, 0x8000, 0x10000)
B_LOWER = tuple(range(0x7C, 0x23, -8))
C_LOWER = (0, 10, 20, 30, 40, 50)
DEBUG, ID3_WORD = 0x4045859C, 0x4041F3C4
DEBUG_KEYS = {
    0x0F: (0x706DB4, 0xB),
    0x19: (0x706D7C, 0xC),
    0x1A: (0x706D84, 0xD),
    0x1B: (0x706D8C, 0xE),
    0x1C: (0x706D94, 0xF),
    0x1D: (0x706D9C, 0x10),
    0x1E: (0x706DA4, 0x11),
}
CALLS = (
    (0x65EA70, 0x565C68),
    (0x65EA74, 0x78595C),
    (0x65EA94, 0x74F9BC),
    (0x65EACC, 0x6EFE04),
    (0x65EAD4, 0x6EF450),
    (0x65EAF8, FORCE),
    (0x65EB04, 0x784E50),
    (0x65EB24, 0x712AC8),
    (0x65EB38, LOOKUP),
    (0x65EB94, 0x706B30),
    (0x65EBA8, 0x706B30),
    (0x65EBBC, 0x719338),
    (0x65EBF4, 0x706B30),
    (0x65EC08, 0x706B30),
    (0x65EC1C, 0x706B30),
    (0x65EC30, 0x706B30),
    (0x65EC40, 0x706B18),
    (0x65EC50, 0x785AB0),
    (0x65EC88, 0x706B30),
    (0x65ECAC, 0x74F92C),
    (0x65ECBC, 0x74F92C),
    (0x65ECCC, 0x74F95C),
    (0x65ECDC, 0x74F95C),
    (0x65ECF0, 0x82E6E0),
    (0x65ED00, 0x82E6E0),
    (0x65ED10, 0x82E6E0),
    (0x706B24, 0x6FCEEC),
    (0x706B3C, 0x706B10),
    (0x6FCEFC, 0x6E7E9C),
    (0x6FCF00, 0x72DDAC),
    (0x74F9C8, 0x72E1E0),
    (0x74F9CC, 0x72E004),
    (0x74F9E8, 0x72DFC8),
    (0x74F9EC, 0x72DDEC),
    (0x65D694, 0x71A898),
    (0x5817A8, 0x739E88),
    (0x5817F8, 0x71C310),
    (0x581808, 0x71C300),
    (0x581814, CONSUMER),
)
TAILS = (
    (0x6FCF08, 0x72DA8C),
    (0x74F940, 0x754CBC),
    (0x74F970, 0x754CC4),
)
WORDS = {
    0x65EA80: 0xE5C4A047,
    0x65EA88: 0xE5C4A048,
    0x65EA8C: 0xE5C49049,
    0x65EAA0: 0xE5C4004A,
    0x65EAA8: 0xE1CBA6BC,
    0x65EAAC: 0xE5D4003C,
    0x65EAB0: 0xE5D4105F,
    0x65EAE0: 0xE1D70BB6,
    0x65EB0C: 0xE5912008,
    0x65EB10: 0xE3A01004,
    0x65EB14: 0xE12FFF32,
    0x65EB20: 0xE1D709FA,
    0x65EB2C: 0xE5941240,
    0x65EB7C: 0xE5C4A049,
    0x65EB9C: 0x15C4A049,
    0x65EBFC: 0x15C49049,
    0x65EC6C: 0xE5D70084,
    0x65EC70: 0xE3500006,
    0x65EC74: 0x05C49047,
    0x65EC78: 0x05C49048,
    0x65EC7C: 0x05C49049,
    0x706B10: 0xE5D00004,
    0x706B28: 0xE5C40005,
    0x6FCEF8: 0xE3A01003,
    0x6FCF04: 0xE8BD4010,
    0x72DA8C: 0xE5900004,
    0x785AB0: 0xE5D0009A,
    0x78595C: 0xE590003C,
    0x784E50: 0xE2800028,
    0x6EB1B8: 0xE5D22004,
    0x754CBC: 0xE5900000,
    0x754CC4: 0xE5900008,
    0x82E6E0: 0xE3013734,
    0x82E6EC: 0xE1C020B0,
    0x5A0FDC: 0xE1D000B0,
    0x5A1054: 0xE3A00004,
    0x581800: 0x0A000004,
    0x597AB4: 0xE580101C,
    0x65D68C: 0xE5D41049,
    0x71A898: 0xE5C0100A,
    0x71C310: 0xE5D0000A,
    0x6552C0: 0xE5C51084,
    0x655374: 0xE5D50080,
    0x65537C: 0x1A00001F,
    0x6553D4: 0xE5901028,
    0x6553DC: 0xE12FFF31,
}
LITERALS = (
    (0x565C68, 0x4040B7A4),
    (0x565CA8, 0x4047D108),
    (0x704458, 0x404099F0),
    (0x704498, DEBUG),
    (0x6F1708, 0x4041D890),
    (0x76B478, 0x4040AE64),
    (0x76B4B8, 0x4040B0EC),
    (0x72DDAC, ID3_WORD - 4),
    (0x72DA90, 0x5AA5A55A),
    (0x72E1E0, 0x80000000),
    (0x72DFC8, 0x80010000),
    (0x6EAD80, BASE + 0xA77CAC),
    (0x6EB194, BASE + 0x9DEA90),
)
RANGES = (
    (POLICY, 0x65ED18),
    (LOOKUP, 0x5A1078),
    (0x6EAD78, 0x6EADB8),
    (0x6EB180, 0x6EB1DC),
    (0x74F92C, 0x74F9F8),
    (0x706B10, 0x707128),
    (0x6FCEEC, 0x6FCF0C),
    (0x82E6E0, 0x82E6F4),
    (0x65D650, 0x65D6B4),
    (0x58174C, 0x581818),
    (0x6552B0, 0x655400),
)


def verify_static(data):
    check_words(data, WORDS)
    for site, target in CALLS:
        check_edge(data, site, target)
    for site, target in TAILS:
        check_edge(data, site, target, link=False)
    for key, (target, offset) in DEBUG_KEYS.items():
        check_edge(data, 0x706B54 + key * 4, target, link=False)
        require(u32(data, target), 0xE5D32000 | offset, "debug byte getter")
    for site, value in LITERALS:
        require(u32(data, literal_offset(data, site)), value, "native literal")
    require(u32(data, 0xA77CAC + 8), BASE + 0x6EB180, "native key-reader vtable")
    require(u32(data, 0xA684E0 + 0x28), BASE + POLICY, "capture policy vtable slot")
    require(
        unpack_from("<IBB", data, 0x9DEA90 + 4 * 8),
        (0x10, 0xFF, 0),
        "key 4 field layout",
    )
    tables = []
    for index in range(7):
        offset = TABLE + TABLE_BYTES * index
        require(u32(data, 0x5A105C + 4 * index), BASE + offset, "table pointer")
        tables.append(
            {
                "file_offset": offset,
                "sha256": sha256(data[offset : offset + TABLE_BYTES]),
            }
        )
    return {
        "calls": [list(edge) for edge in CALLS],
        "tail_branches": [list(edge) for edge in TAILS],
        "word_checks": len(WORDS),
        "literal_uses": [list(row) for row in LITERALS],
        "range_sha256": [
            {"start": lo, "end_exclusive": hi, "sha256": sha256(data[lo:hi])}
            for lo, hi in RANGES
        ],
        "lookup": {
            "tables": tables,
            "table_shape": [7, 4, 13],
            "entry_bytes": 2,
            "capture_fields": {"A": 0x240, "B": 0x348, "C": 0x209A},
            "key_4_descriptor_file_offset": 0x9DEAB0,
            "A_unsigned_upper_inclusive": list(A_UPPER),
            "B_unsigned_lower_descending": list(B_LOWER),
            "C_after_signed_divide_10_lower": list(C_LOWER),
        },
        "configuration_layout": {
            "slot_base": 0x18,
            "slot_stride": 16,
            "word_offsets_in_slot": [0, 8],
            "capture_output_offsets": [0x1C8, 0x1CC, 0x1D0, 0x1D4],
            "flag_0x4a_marker_vas": [0x80000000, 0x80010000],
        },
        "tag_layout": {
            "pointer_offset": 0x30C + 0x1734,
            "halfword_tags": [0x3F, 0x40, 0x41],
        },
        "debug_keys": [
            {"key": key, "byte_offset": offset, "entry_file_offset": entry}
            for key, (entry, offset) in DEBUG_KEYS.items()
        ],
    }


def cell(a, b, c):
    row = bisect_left(A_UPPER, a)
    column = sum(b < bound for bound in B_LOWER)
    table = bisect_right(C_LOWER, c)
    return TABLE + TABLE_BYTES * table + 2 * (13 * row + column)


def emulate(data):
    import unicorn as uc
    from unicorn import arm_const as arm

    vm = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    for address, size in (
        (BASE, 0x1000000),
        (0x40400000, 0x100000),
        (RAM, BANKS * BANK_BYTES),
        (0x10000000, 0x100000),
        (0x80000000, 0x20000),
    ):
        vm.mem_map(address, size)
    vm.mem_write(BASE, data[:0x1000000])
    manager, capture, config, tags = 0x10010000, 0x10040000, 0x10076000, 0x10078000
    owner, stack, stop = 0x4040B0EC, 0x100F0000, 0x100F1000

    def get(address, size=4):
        return int.from_bytes(vm.mem_read(address, size), "little")

    def put(address, value, size=4):
        vm.mem_write(address, value.to_bytes(size, "little"))

    def reg(name, value=None):
        index = getattr(arm, f"UC_ARM_REG_{name.upper()}")
        if value is None:
            return vm.reg_read(index)
        vm.reg_write(index, value)

    def run(entry, *args, end=None, **registers):
        for name, value in dict(sp=stack, lr=stop, **registers).items():
            reg(name, value)
        for index, value in enumerate(args):
            reg(f"r{index}", value)
        finish = stop if end is None else BASE + end
        vm.ctl_flush_tb()
        vm.emu_start(BASE + entry, finish, count=3000000)
        require(reg("pc"), finish, f"native boundary from {entry:#x}")
        return reg("r0")

    def flags():
        return tuple(get(capture + off, 1) for off in (0x47, 0x48, 0x49, 0x4A))

    table_addresses, selector_args, force_calls, results, id3_results = (
        [],
        [],
        [],
        [],
        [],
    )

    def observe(_vm, pc, _size, _user):
        off = pc - BASE
        if off == 0x5A0FDC:
            table_addresses.append(reg("r0") - BASE)
        elif off == LOOKUP:
            selector_args.append(tuple(reg(name) for name in ("r1", "r2", "r3")))
        elif off == FORCE:
            force_calls.append(off)
        elif off == 0x65EB3C:
            results.append(reg("r0"))
        elif off == 0x706B28:
            id3_results.append(reg("r0"))
        else:
            require(flags(), (1, 1, 0, 0xA5), "native policy defaults before config")

    for offset in (0x5A0FDC, LOOKUP, FORCE, 0x65EB3C, 0x706B28, 0x65EA90):
        vm.hook_add(uc.UC_HOOK_CODE, observe, begin=BASE + offset, end=BASE + offset)

    cell_results = bytearray()
    coverage = list(product((*A_UPPER, 0x10001), (*B_LOWER, 0x23), (-1, *C_LOWER)))
    boundary = [
        *((a + 1, 0x7C, 0) for a in A_UPPER),
        *((0x8000, b - 1, 0) for b in B_LOWER),
        *((0x8000, 0x24, c - 1) for c in C_LOWER),
    ]
    for a, b, c in coverage + boundary:
        table_addresses.clear()
        selector_args.clear()
        offset = cell(a, b, c)
        result = run(LOOKUP, 0, a, b, c & 0xFFFFFFFF)
        require(table_addresses, [offset], "native selected cell address")
        require(
            result, unpack_from("<H", data, offset)[0], "native selected cell value"
        )
        cell_results += pack("<H", result)
    require(
        len({cell(*row) for row in coverage}),
        7 * 4 * 13,
        "one test per native table cell",
    )

    run(0x6E80BC, manager)
    for guard in (0x4040B7A4, 0x404099F0, 0x4041D890, 0x4040AE64):
        put(guard, 1)
    put(owner + 4, manager)
    put(0x4047D108 + 0x3C, config)
    put(capture + 0x30C + 0x1734, tags)
    for index in range(6):
        put(config + 0x18 + index * 16, 100 + index)
        put(config + 0x1C + index * 16, 0xAAAAAAAA)
        put(config + 0x20 + index * 16, 200 + index)
    run(0x6EAD78, capture + 0x334)
    require(get(capture + 0x334), BASE + 0xA77CAC, "native nested reader")
    require(get(capture + 0x348, 1), 0x7C, "native key-4 initial byte")

    put(capture, BASE + 0xA684E0)
    prepare_gate = []
    for job_kind in range(12):
        run(0x6552B0, capture, job_kind, end=0x655344)
        produced = [get(capture + off, 1) for off in (0x2080, 0x2081, 0x2082)]
        expected = [
            int(job_kind in (5, 7, 8, 11)),
            int(job_kind in (7, 8)),
            int(job_kind == 11),
        ]
        require(produced, expected, "native prepare flags")
        require(get(capture + 0x2084, 1), job_kind, "native prepare job kind")
        # Three intervening virtual calls are outside this bounded gate replay.
        prepare_boundary = 0x655400 if produced[0] else 0x655380
        run(0x655374, end=prepare_boundary, r4=capture, r5=capture + 0x2000)
        if not produced[0]:
            run(0x6553D0, end=POLICY, r4=capture)
            require(reg("r0"), capture, "separate original policy dispatch argument")
        prepare_gate.append(
            {
                "job_kind": job_kind,
                "native_flags_2080_2081_2082": produced,
                "gate_boundary": prepare_boundary,
                "policy_block_skipped": bool(produced[0]),
            }
        )

    def policy(
        label,
        *,
        a=0x4000,
        b=0x7C,
        c=0,
        job_kind=0,
        force=0,
        option=(0, 0, 0),
        debug=False,
        keys=(),
        debug_pair=0,
        id3=False,
        clear_byte=0,
        config4a=(0, 0, 0),
        expected_flags=(1, 1, 0, 0),
        expected_pair=None,
    ):
        tag_prefix = bytes([0xA5]) * 0x86
        vm.mem_write(tags, tag_prefix)
        vm.mem_write(capture + 0x47, bytes([0xA5]) * 4)
        vm.mem_write(capture + 0x1C8, bytes([0xA5]) * 16)
        put(DEBUG + 5, 0xA5, 1)
        put(capture + 0x1646C, 0xA5A5, 2)
        put(capture + 0x240, a)
        put(capture + 0x348, b, 1)
        put(capture + 0x209A, c & 0xFFFF, 2)
        put(capture + 0x2084, job_kind, 1)
        for off in (0x3C, 0x5F):
            put(capture + off, int(force == off), 1)
        put(capture + 0x4F, option[0], 1)
        put(capture + 0x164D, option[1], 1)
        put(capture + 0x20B6, option[2], 2)
        put(DEBUG + 4, int(debug), 1)
        for key, (_, offset) in DEBUG_KEYS.items():
            put(DEBUG + offset, int(key in keys), 1)
        put(DEBUG + 0x12, debug_pair, 2)
        put(DEBUG + 0x9A, clear_byte, 1)
        put(ID3_WORD, 0x5AA5A55A if id3 else 0)
        put(0x80000000, MARKER if config4a[0] else 0)
        put(0x80010000, MARKER if config4a[1] else 0)
        put(config + 0xC, config4a[2], 1)
        for observations in (
            table_addresses,
            selector_args,
            force_calls,
            results,
            id3_results,
        ):
            observations.clear()
        run(POLICY, capture)
        force_expected = bool(
            force or (option[0] and option[1] == 1 and option[2] >= 2)
        )
        normalized = -(abs(c) // 10) if c < 0 else c // 10
        offset = cell(a, b, normalized)
        selected = 4 if force_expected else unpack_from("<H", data, offset)[0]
        require(force_calls, [FORCE] if force_expected else [], "native forced route")
        require(
            table_addresses, [] if force_expected else [offset], "native table route"
        )
        require(
            selector_args,
            [] if force_expected else [(a, b, normalized & 0xFFFFFFFF)],
            "whole-policy table arguments",
        )
        require(results, [selected], "native selector return")
        require(id3_results, [int(id3)], "native ID 3 secondary marker check")
        require(get(DEBUG + 5, 1), int(id3), "native ID 3 result cache")
        require(flags(), expected_flags, f"native final flags {label}")
        require(get(capture + 0x1646C, 2), 1, "native threshold")
        pair = (
            expected_pair
            if expected_pair is not None
            else {1: 0, 2: 2, 3: 4, 4: 4}[selected]
        )
        cfg = tuple(get(capture + off) for off in (0x1C8, 0x1CC, 0x1D0, 0x1D4))
        require(
            cfg,
            (100 + pair, 101 + pair, 200 + pair, 201 + pair),
            "native configuration pair",
        )
        tag_values = (expected_flags[3], expected_flags[2], selected)
        expected_tags = tag_prefix[:0x7E] + pack("<3H", *tag_values) + tag_prefix[0x84:]
        require(
            bytes(vm.mem_read(tags, 0x86)),
            expected_tags,
            "only native tag slots 3f/40/41 change",
        )
        return {
            "case": label,
            "inputs": {
                "A": a,
                "B": b,
                "C": c,
                "job_kind": job_kind,
                "force_byte_offset": force,
                "option_4f_f5_20b6": list(option),
                "debug_enable": debug,
                "debug_keys": list(keys),
                "debug_pair": debug_pair,
                "id3_marker_valid": id3,
                "debug_0x9a": clear_byte,
                "config_4a_markers_and_byte": list(config4a),
            },
            "forced": bool(force_calls),
            "cell_file_offset": table_addresses[0] if table_addresses else None,
            "selector_result": results[0],
            "flags_47_to_4a": list(flags()),
            "threshold": get(capture + 0x1646C, 2),
            "id3_marker_check": id3_results[0],
            "config_words_1c8_to_1d4": list(cfg),
            "tags_3f_40_41": [get(tags + 2 * tag, 2) for tag in (0x3F, 0x40, 0x41)],
        }

    cases = [
        policy("native_result_1"),
        policy("native_result_2", b=0x44),
        policy("native_result_3", b=0x24),
        policy("native_result_4", a=0x8000, b=0, expected_flags=(1, 1, 1, 1)),
        policy(
            "native_result_4_job_kind_6",
            a=0x8000,
            b=0,
            job_kind=6,
            expected_flags=(0, 0, 0, 1),
        ),
    ]
    require(
        [row["selector_result"] for row in cases],
        [1, 2, 3, 4, 4],
        "representative native result cases",
    )
    for job_kind in (5, 11):
        cases.append(
            policy(
                f"native_result_4_job_kind_{job_kind}",
                a=0x8000,
                b=0,
                job_kind=job_kind,
                expected_flags=(1, 1, 1, 1),
            )
        )
    for offset, job_kind in product((0x3C, 0x5F), (0, 6)):
        final = (0, 0, 0, 1) if job_kind == 6 else (1, 1, 1, 1)
        cases.append(
            policy(
                f"force_{offset:x}_job_kind_{job_kind}",
                force=offset,
                job_kind=job_kind,
                expected_flags=final,
            )
        )
    for option, forced in (
        ((0, 1, 2), False),
        ((1, 0, 2), False),
        ((1, 1, 1), False),
        ((1, 1, 2), True),
    ):
        cases.append(
            policy(
                "three_field_force_gate",
                option=option,
                expected_flags=(1, 1, 1, 1) if forced else (1, 1, 0, 0),
            )
        )
    for gates in product((0, 1), repeat=3):
        cases.append(
            policy(
                "configuration_4a_gate",
                config4a=gates,
                expected_flags=(1, 1, 0, int(all(gates))),
            )
        )
    for label, enabled, keys, active_result, expected in (
        ("debug_disabled_ignores_keys", False, tuple(DEBUG_KEYS), False, (1, 1, 0, 0)),
        ("debug_1d_enables_49", True, (0x1D,), False, (1, 1, 1, 0)),
        ("debug_1a_clears_result_4", True, (0x1A,), True, (1, 1, 0, 1)),
        ("debug_1a_after_1d", True, (0x1D, 0x1A), False, (1, 1, 0, 0)),
        ("debug_1b_clears_47", True, (0x1B,), True, (0, 1, 1, 1)),
        ("debug_1c_clears_48", True, (0x1C,), True, (1, 0, 1, 1)),
        ("debug_0f_clears_all", True, (0x0F, 0x1D), True, (0, 0, 0, 0)),
    ):
        cases.append(
            policy(
                label,
                a=0x8000 if active_result else 0x4000,
                b=0 if active_result else 0x7C,
                debug=enabled,
                keys=keys,
                expected_flags=expected,
            )
        )
    for debug_pair, keys, flags_after in (
        (1, (0x1E,), (1, 1, 0, 1)),
        (2, (0x1E, 0x19), (1, 1, 0, 0)),
        (3, (0x1E,), (1, 1, 0, 1)),
    ):
        cases.append(
            policy(
                "debug_1e_config_pair",
                debug=True,
                keys=keys,
                debug_pair=debug_pair,
                expected_flags=flags_after,
                expected_pair=2 * (debug_pair - 1),
            )
        )
    for id3, clear_byte in product((False, True), (0, 1)):
        cases.append(
            policy(
                "id3_marker_and_debug_9a",
                a=0x8000,
                b=0,
                id3=id3,
                clear_byte=clear_byte,
                expected_flags=(0, 0, 0, 0) if id3 and clear_byte else (1, 1, 1, 1),
            )
        )
    for c in (
        -32768,
        -10,
        -9,
        -1,
        0,
        99,
        100,
        199,
        200,
        299,
        300,
        399,
        400,
        499,
        500,
        32767,
    ):
        selected = unpack_from("<H", data, cell(0x8000, 0x24, int(c / 10)))[0]
        enabled = int(selected == 4)
        cases.append(
            policy(
                "signed_C_boundary",
                a=0x8000,
                b=0x24,
                c=c,
                expected_flags=(1, 1, enabled, enabled),
            )
        )

    connected = replay_connected(
        vm, uc, manager, capture, owner, stack, get, put, reg, run, policy
    )
    return {
        "unicorn_version": uc.__version__,
        "lookup_checks": {
            "distinct_cells": len(coverage),
            "additional_boundaries": len(boundary),
            "observed_result_sha256": sha256(cell_results),
        },
        "bounded_prepare_gate_cases": prepare_gate,
        "whole_policy_cases": cases,
        "policy_execution_replacements": [],
        "connected_packet_cases": connected,
        "connected_execution_replacements": {
            "0x785f70": "Elapsed-time query returns zero."
        },
    }


def replay_connected(
    vm, uc, manager, capture, owner, stack, get, put, reg, run, policy
):
    obj, image = 0x10020000, 0x10030000
    frame, ref, handler, event = 0x10070000, 0x10072000, 0x10073000, 0x10074000
    payload = capture + 0xA3E8
    for index in range(BANKS):
        start = 0x76C628 + index * 0x14
        run(start, end=start + 8)
        address = FLASH + index * BANK_BYTES
        vm.mem_write(address, bytes(BANK_BYTES))
        put(address, MARKER if index < 2 else 0xFFFFFFFF)
        put(address + 4, 1)
    run(0x76B830, end=0x76B8D0, r4=owner)
    for index in range(BANKS):
        require(
            run(0x6E7E9C, manager, FIRST_ID + index),
            0x4040AF30 + 4 * index,
            "connected native provider registration",
        )
    for index, (x, y, mask) in enumerate(((8, 8, 3), (8, 10, 12))):
        vm.mem_write(FLASH + index * BANK_BYTES + 8, pack("<3H", x, y, mask))

    run(0x597AB4, handler, obj)
    require(get(handler + 0x1C), obj, "native handler binding")
    for off, val, size in (
        (0x3C, 16, 2),
        (0x3E, 16, 2),
        (0x4A, 32, 2),
        (0x4E, 0, 2),
        (0x50, 0, 2),
        (0x150, 0, 4),
    ):
        put(frame + off, val, size)
    put(ref, frame)
    put(stack + 0x40, ref)
    put(stack + 0x30, 0xA55A1234)
    put(capture + 0x13C, image)
    put(event + 8, payload)
    put(event + 0xC, 0x01180001)

    visited = []

    def observe(_vm, pc, _size, _user):
        visited.append(pc - BASE)
        if pc == BASE + CONSUMER:
            require(
                (reg("r0"), reg("r1")), (obj, image), "native policy-to-image pointer"
            )
        if pc == BASE + 0x785F70:
            reg("r0", 0)
            reg("pc", reg("lr"))

    for off in (0x739E88, CONSUMER, 0x73A204, 0x785F70, 0x739F80, 0x739F00):
        vm.hook_add(uc.UC_HOOK_CODE, observe, begin=BASE + off, end=BASE + off)

    initial = list(range(256))
    for x, y, value in (
        (6, 8, 200),
        (10, 8, 400),
        (8, 8, 9999),
        (8, 12, 600),
        (8, 10, 8888),
    ):
        initial[16 * y + x] = value
    cases = []
    for job_kind in (0, 6):
        run(0x739CF4, obj)
        enabled = int(job_kind == 0)
        row = policy(
            f"connected_job_kind_{job_kind}",
            a=0x8000,
            b=0,
            job_kind=job_kind,
            debug=True,
            keys=(0x1B, 0x1C),
            expected_flags=(0, 0, enabled, 1),
        )
        require(
            row["selector_result"], 4, "same table result in both connected policies"
        )
        vm.mem_write(payload, bytes([0xA5]) * 0x14)
        run(0x65D650, end=0x65D6B4, r4=capture)
        payload_flags = [get(payload + i, 1) for i in (8, 9, 0xA)]
        require(payload_flags, [0, 0, enabled], "native packet copies policy flags")
        require(
            [get(payload), get(payload + 4), get(payload + 0xC, 2)],
            [frame, image, 1],
            "native frame, image and threshold",
        )
        vm.mem_write(image - 2, pack("<258H", 0xABCD, *initial, 0xDCBA))
        put(obj + 0xC, 0)
        visited.clear()
        run(0x58174C, end=0x581818, r4=handler, r5=event)
        expected = initial.copy()
        route = [0x739E88]
        if enabled:
            expected[16 * 8 + 8], expected[16 * 10 + 8] = 300, 450
            route += [
                CONSUMER,
                0x73A204,
                0x785F70,
                0x739F80,
                0x739F00,
                0x739F80,
                0x739F00,
            ]
        require(visited, route, "policy packet correction route")
        require(
            get(obj + 0x12, 1),
            enabled,
            "native consumer lazy initialization follows enable",
        )
        require(
            get(obj + 0xC),
            image if enabled else 0,
            "native image pointer follows enable",
        )
        require(
            bytes(vm.mem_read(image - 2, 516)),
            pack("<258H", 0xABCD, *expected, 0xDCBA),
            "entire image with guard halfwords",
        )
        cases.append(
            {
                "policy": row,
                "event_id": get(event + 0xC),
                "payload_flags_8_9_a": payload_flags,
                "observed_entries": visited.copy(),
                "center_values": [get(image + 2 * (16 * y + 8), 2) for y in (8, 10)],
                "image_sha256": sha256(bytes(vm.mem_read(image, 512))),
            }
        )
    return cases


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    data = load_image(args.decoded)
    result = {
        "firmware_version": "1.12",
        "decoded_sha256": sha256(data),
        "image_base": BASE,
        "static": verify_static(data),
        "replay": emulate(data),
        "scope": [
            "Policy fixtures prepare capture input fields, initialized guards, configuration slots, marker words and debug fields. The nested key reader is constructed by original code; the complete capture constructor and upstream producers are outside these slices.",
            "A, B and C name three inputs by their object offsets and observed arithmetic. Their physical units and camera menu mappings remain unestablished. The fixture supplies the internal job kind at capture +0x2084.",
            "A separate bounded preparation replay produces flags from job kinds0..11, skips three intervening virtual calls, and follows the original +0x2080 branch. The separate policy-entry dispatch slice also skips five preceding calls after the fall-through boundary. Direct whole-policy cases for kinds5/11 are conditional controls, not evidence that normal preparation invokes the policy for those kinds.",
            "Connected cases use the same capture state for policy and packet construction. A prepared event envelope supplies the original payload to the handler slice; frame, image, records and debug overrides are synthetic.",
            "No execution replacements are used in the policy. The only replacement in the connected path is the correction elapsed-time query. The replay stops inside the handler; task scheduling, live capture and sensor data are outside scope.",
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
