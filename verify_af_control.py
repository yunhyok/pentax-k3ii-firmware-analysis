"""Verify K-3 II v1.12 lens capability acquisition and AF target handoff.

SPDX-License-Identifier: GPL-2.0-only
"""

import argparse
import json
from pathlib import Path

from verify_af_drive import COPY_ROWS, code_va
from verify_findings import DECODED_SHA256, require, require_snapshot, sha256, u32
from verify_raw_path import branch_target
from verify_tone_path import BASE, check_words, load_image


CLASSES = {
    "14CAfApplication": (0xD13BB, 0xD0570, 0xD2EE0),
    "8CAfMotor": (0xD2610, 0xD0F90, 0xD4F9C),
    "8CAfPulse": (0xD261A, 0xD0FB0, 0xD4FD8),
}
WORDS = {
    0x21D78: 0x020D2EE0,
    0x52C2C: 0x020D4F9C,
    0x58C78: 0x020D4FD8,
    0xD766C: 0x05940020,
    0xD7764: 0xE5940020,
    0xD62F0: 0x000002C7,
    0xD60FC: 0xE3500001,
    0xD6100: 0x1350000B,
    0xD6108: 0xE350000C,
    0xD610C: 0x1350000D,
    0xD6110: 0x13500013,
    0xB9E80: 0xE5900024,
    0xB9E84: 0xE5900000,
    0x7A5A4: 0xE59F0DB4,
    0x7B360: 0x40081240,
    0x7B43C: 0xEA00003C,
    0x7B534: 0xE3A020FF,
    0x7B538: 0xE3A0100B,
    0x54510: 0xE1E00000,
    0x54620: 0xE0450000,
    0x54648: 0xE3C05801,
    0x54654: 0xE3500001,
    0x54670: 0xE1A00840,
    0x546F4: 0xE3A01000,
    0x546C0: 0x4A00000A,
    0x4ED6C: 0x00008211,
    0xB9964: 0xE0810400,
    0x949B8: 0xE58D8000,
    0xB7DA0: 0x001030E2,
    0x548D4: 0xE35600E6,
    0x548E8: 0xE3560E19,
    0x54904: 0xE5C40060,
    0x54934: 0xE3A01008,
    0x54A14: 0xE3A01008,
    0x54DD4: 0x0000016D,
    0x57FBC: 0xE5801168,
    0x57FC4: 0xE580116C,
    0xB686C: 0x40006064,
    0xB6860: 0xE2000040,
    0xB70D0: 0xE5D00C5F,
    0xB753C: 0x0010316E,
    0xB7B90: 0x001030AB,
    0xB7ED4: 0xE1C016B6,
    0xB7EE8: 0xE1C016B4,
    0xB80BC: 0xE1D00BB0,
    0xB9748: 0x00103168,
    0xB9764: 0xE1C019BE,
    0xB9814: 0xE1D00BBC,
    0xB982C: 0xE1C01BBC,
    0xD9168: 0xE5D000D6,
    0x955C4: 0x00008205,
    0x94DDC: 0x08BD8070,
    0x94E04: 0xE3100001,
    0xB9B48: 0xE5D00006,
    0xB9B5C: 0xE5C01006,
}
EDGES = (
    (0xD7674, 0x0100F708),
    (0xE7F68, BASE + 0x5455C),
    (0xD7768, 0x0100F710),
    (0xE7F70, BASE + 0x547CC),
    (0x54520, BASE + 0xB7500),
    (0xE7D04, 0x26E4),
    (0xD7B1C, 0x0100F744),
    (0xE7FA4, BASE + 0x33420),
    (0x33420, BASE + 0xB9E80),
    (0x54534, 0x0100F4A4),
    (0x54540, BASE + 0xB976C),
    (0x5454C, BASE + 0xB7500),
    (0x54570, BASE + 0x545E8),
    (0x545B8, BASE + 0x4C500),
    (0x545C0, BASE + 0x54604),
    (0x54610, BASE + 0xB975C),
    (0x5461C, BASE + 0xB973C),
    (0x54640, BASE + 0xB7530),
    (0x54650, BASE + 0xB70D0),
    (0x54688, BASE + 0x4E684),
    (0x546CC, BASE + 0xB982C),
    (0x546E8, BASE + 0xB97FC),
    (0x546F8, BASE + 0xB982C),
    (0x4E694, BASE + 0x94204),
    (0x4E6A0, BASE + 0xB995C),
    (0x945A8, BASE + 0x949B8),
    (0x949BC, BASE + 0x94468),
    (0x94478, BASE + 0x93F94),
    (0x547DC, BASE + 0xB9814),
    (0x547F8, BASE + 0x54AD8),
    (0x54800, BASE + 0x41AE0),
    (0x41AE4, BASE + 0xB80BC),
    (0x5480C, BASE + 0xB7EE4),
    (0x54814, BASE + 0x4C500),
    (0x5481C, BASE + 0x5486C),
    (0x54878, BASE + 0x548D4),
    (0x548D8, BASE + 0x5490C),
    (0x54910, 0x0100F4E8),
    (0xE7D48, 0xC68),
    (0xD6088, 0x3D4C),
    (0x54918, BASE + 0x548A0),
    (0x54924, BASE + 0xB7ED0),
    (0x54930, BASE + 0xB9764),
    (0x5493C, BASE + 0x52E38),
    (0x54A1C, BASE + 0x52E38),
    (0x54AD0, BASE + 0xB9764),
    (0x54AEC, BASE + 0x57FBC),
    (0x900A4, BASE + 0x94DC4),
    (0x91DA8, BASE + 0x94DC4),
    (0x94DD4, BASE + 0x34D04),
    (0x34D08, BASE + 0xB6854),
    (0x94DE4, BASE + 0xB9B48),
    (0x94DEC, BASE + 0x94E78),
    (0x94DF8, BASE + 0x94204),
    (0x94858, BASE + 0x93F94),
    (0x94868, BASE + 0xB9B5C),
    (0x94E08, BASE + 0x94E70),
    (0x94E14, BASE + 0x94204),
    (0x4C508, BASE + 0xB9B48),
    (0x52E84, BASE + 0x4C500),
    (0x52E94, BASE + 0x52ED4),
)
RANGES = {
    "application_dispatch": (0xD7664, 0xD7774),
    "relocated_motor_veneers": (0xE7F68, 0xE7F74),
    "motor_target_calculation": (0x544EC, 0x547CC),
    "motor_target_handoff": (0x547CC, 0x54AF8),
    "motor_prepare_prefix": (0x52E38, 0x52EF4),
    "lens_acquisition_prefix": (0x94DC4, 0x94E18),
    "lens_response_store": (0x94844, 0x94870),
    "lens_control_query": (0x4E684, 0x4E6A4),
}


def verify(data):
    check_words(data, WORDS)
    for site, target in EDGES:
        require(
            code_va(site) + branch_target(data, site) - site,
            target,
            f"A32 branch at {site:#x}",
        )
    for row, (source, dest, length) in COPY_ROWS.items():
        require(
            [u32(data, row + i) for i in range(0, 16, 4)],
            [BASE + source, dest, length, BASE + 0x21540],
            f"copy row {row:#x}",
        )
    for name, (offset, info, table) in CLASSES.items():
        marker = name.encode("ascii") + b"\0"
        require(data[offset : offset + len(marker)], marker, f"RTTI name {name}")
        require(u32(data, info + 4), BASE + offset, f"RTTI pointer {name}")
        require(u32(data, table - 4), BASE + info, f"vtable RTTI {name}")
    return {
        "decoded_sha256": DECODED_SHA256,
        "firmware_version": "1.12",
        "image_base": BASE,
        "offset_units": "Decoded file offsets except execution addresses, memory addresses and object fields.",
        "word_check_count": len(WORDS),
        "class_records": {
            name: {"name_offset": offset, "rtti": info, "vtable": table}
            for name, (offset, info, table) in CLASSES.items()
        },
        "branch_checks": [
            {"file_offset": site, "target_va": target} for site, target in EDGES
        ],
        "ranges": {
            name: {
                "start": start,
                "end_exclusive": end,
                "sha256": sha256(data[start:end]),
            }
            for name, (start, end) in RANGES.items()
        },
        "acquisition": {
            "entry": 0x94DC4,
            "status_pointer_va": 0x40006064,
            "status_byte_offset": 1,
            "status_mask": 0x40,
            "cached_capability_offset": 6,
            "cached_nonzero_continuation": 0x94E78,
            "query_if_cache_zero": 0x8205,
            "query_payload_size": 1,
            "status_zero_store": 0xB9B5C,
            "post_query_raw_bit0_continuations": {
                "clear": 0x94E70,
                "set": 0x94E0C,
            },
            "drive_predicate": 0x4C500,
            "drive_predicate_mask": 0x40,
        },
        "control": {
            "application_motor_pointer_offset": 0x20,
            "producer_call": 0xD7674,
            "producer_entry": 0x5455C,
            "consumer_call": 0xD7768,
            "consumer_entry": 0x547CC,
            "body_calculation_gate_config_key": 0x2C7,
            "body_calculation_gate_raw_values": [1, 11, 12, 13, 19],
            "body_calculation_gate_source_va": 0x4008124B,
            "calculation_state_va": 0x001030E2,
            "fixture_calculation_state": 3,
            "body_calculation_formula": "With global 0x001030ab clear and accessor+0xc5f equal to 1, use the low 16 bits of pulse+0xc2 minus [0x00103168] plus [0x0010316e], and clear the result if its signed interpretation is negative. Other values of the accessor gate also clear the result in this branch.",
            "lens_calculation_query": {
                "entry": 0x4E684,
                "command": 0x8211,
                "reply_bytes": 2,
                "response_word_order": "big-endian",
                "calculation_entry": 0x54688,
                "calculation_flag_offset": 0xC5F,
                "nonnegative_result_store": 0x546CC,
                "pulse_bookkeeping_offset": 0xBA,
            },
            "body_calculation_input": {
                "pulse_offset_after_initial_copy": 0xC2,
                "direction_flag_va": 0x00103116,
                "input_entry": 0x544EC,
                "raw_word_accessor": 0xB9E80,
                "input_object_pointer_path": [8, 4, 0x24],
                "input_normalization": "For a zero direction flag, copy the input to pulse+0xc2 and clear the subtract halfword. For a nonzero flag, clear pulse+0xc2 and store the low 16 bits of the complemented input in the subtract halfword.",
                "subtract_halfword_va": 0x00103168,
                "add_halfword_va": 0x0010316E,
                "exact_one_accessor_byte_offset": 0xC5F,
            },
            "producer_output_pulse_offset": 0xBC,
            "consumer_low_request_cutoff": 230,
            "body_large_request_band_cutoffs": [365, 400],
            "body_large_request_band_motor_offset": 0x60,
            "position_copy_from_accessor_record_offset": 0xB0,
            "position_copy_destination_offset": 0x164,
            "target_position_offset": 0x166,
            "target_pulse_offset": 0x9E,
            "motor_prepare": 0x52E38,
            "motor_prepare_arg": 8,
        },
    }


def emulate(data):
    import unicorn
    from unicorn import arm_const as arm

    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    for address, length in (
        (0, 0x4000),
        (0x00102000, 0x2000),
        (0x01002000, 0xE000),
        (0x10000000, 0x20000),
        (0x40006000, 0x1000),
        (0x40081000, 0x1000),
    ):
        vm.mem_map(address, length)
    for source, dest, length in COPY_ROWS.values():
        vm.mem_write(dest, data[source : source + length])

    (
        app,
        motor,
        accessor,
        pulse,
        position,
        record,
        lens,
        kaf,
        comm,
        body,
        body_inner,
        step_input,
        operation,
        operation_inner,
        app_state,
    ) = (0x10000000 + i * 0x1000 for i in range(1, 16))
    sdm, transport, status_record, ret = (
        0x10010000,
        0x10015000,
        0x10016000,
        0x1001F000,
    )

    def write(address, value, width=4):
        vm.mem_write(address, value.to_bytes(width, "little"))

    def read(address, width=1):
        return int.from_bytes(vm.mem_read(address, width), "little")

    def reg(name, value=None):
        register = getattr(arm, f"UC_ARM_REG_{name.upper()}")
        if value is None:
            return vm.reg_read(register)
        vm.reg_write(register, value)

    def run(entry, end, **registers):
        for name, value in dict(sp=ret - 0x1000, lr=ret, **registers).items():
            reg(name, value)
        vm.emu_start(entry, end, count=20000)
        require(reg("pc"), end, f"original execution from {entry:#x}")
        return reg("r0")

    for obj, fields in (
        (app, {0x20: motor}),
        (
            motor,
            {
                4: accessor,
                8: body,
                0xC: lens,
                0x10: comm,
                0x14: position,
                0x18: pulse,
                0x28: operation,
            },
        ),
        (accessor, {0x234: record}),
        (lens, {0x1C: kaf, 0x24: transport}),
        (
            comm,
            {
                4: accessor,
                0x18: lens,
                0x20: position,
                0x24: pulse,
                0x2C: kaf,
                0x30: sdm,
            },
        ),
        (body, {4: body_inner}),
        (body_inner, {0x24: step_input}),
        (operation, {0x10: operation_inner}),
        (sdm, {0x4128: transport, 0x412C: kaf, 0x4134: accessor}),
        (0x40006064, {0: status_record}),
    ):
        for offset, pointer in fields.items():
            write(obj + offset, pointer)

    transactions = []
    reply = transport_status = 0
    observed_prepare = []

    def lens_reply(_vm, _address, _size, _user):
        require(reg("r0"), sdm, "lens transport object")
        require(reg("r3"), sdm + 4, "lens response destination")
        command = reg("r1") << 8 | reg("r2")
        count = read(reg("sp"), 4)
        transactions.append([command, count])
        if command == 0x8205 or transport_status == 0:
            vm.mem_write(reg("r3"), reply.to_bytes(count, "big"))
        reg("r0", transport_status)
        reg("pc", reg("lr"))

    vm.hook_add(
        unicorn.UC_HOOK_CODE, lens_reply, begin=BASE + 0x93F94, end=BASE + 0x93F94
    )

    def observe_prepare(_vm, _address, _size, _user):
        observed_prepare.append([reg("r0"), reg("r1")])

    vm.hook_add(
        unicorn.UC_HOOK_CODE,
        observe_prepare,
        begin=BASE + 0x52E38,
        end=BASE + 0x52E38,
    )

    acquisition_cases = []
    for name, status_byte, prior, reply, transport_status, expected, end in (
        ("status_bit_clear", 0x80, 0, 0x40, 0, 0, ret),
        ("nonzero_cached_body", 0x40, 0x80, 0x40, 0, 0x80, BASE + 0x94E78),
        ("nonzero_cached_lens", 0x40, 0x40, 0x80, 0, 0x40, BASE + 0x94E78),
        ("fresh_zero", 0x40, 0, 0, 0, 0, BASE + 0x94E70),
        ("fresh_lens", 0x40, 0, 0x40, 0, 0x40, BASE + 0x94E70),
        ("fresh_bit_zero_set", 0x40, 0, 0x41, 0, 0x41, BASE + 0x94E0C),
        ("failed_reply", 0x40, 0, 0x41, 7, 0, BASE + 0x94E70),
        ("fresh_body", 0x40, 0, 0x80, 0, 0x80, BASE + 0x94E70),
    ):
        write(status_record + 1, status_byte, 1)
        write(kaf + 6, prior, 1)
        transactions.clear()
        run(BASE + 0x94DC4, end, r0=sdm)
        expected_tx = (
            [[0x8205, 1]] if name.startswith("fresh") or name == "failed_reply" else []
        )
        require(transactions, expected_tx, f"{name} transport calls")
        require(read(kaf + 6), expected, f"{name} capability byte")
        predicate = run(BASE + 0x4C500, ret, r0=lens)
        require(predicate, int(expected in (0x40, 0x41)), f"{name} drive predicate")
        acquisition_cases.append(
            {
                "case": name,
                "injected_status_byte": status_byte,
                "prior_capability": prior,
                "reply": reply if expected_tx else None,
                "transport_status": transport_status if expected_tx else None,
                "transactions": transactions.copy(),
                "stored_capability": expected,
                "drive_predicate": predicate,
                "end_va": end if end != ret else None,
            }
        )

    require(read(kaf + 6), 0x80, "capability inherited by body control")
    control_cases = []
    for name, sample, direction, add, config, gate, ready, expected, band, forward in (
        ("reverse_below_zero", 65435, 1, 90, 1, 1, 1, 0, None, False),
        ("reverse_positive", 65435, 1, 331, 1, 1, 0, 231, 0, True),
        ("signed_upper_boundary", 32767, 0, 1, 1, 1, 1, 0, None, False),
        ("large_at_signed_limit", 32767, 0, 0, 1, 1, 0, 32767, 2, True),
        ("calculation_flag_clear", 225, 0, 5, 1, 0, 1, 0, None, False),
        ("calculation_flag_other", 225, 0, 5, 1, 2, 1, 0, None, False),
        ("configuration_denies", 225, 0, 5, 0, 1, 1, 0, None, False),
        ("low_unready", 225, 0, 5, 1, 1, 0, 230, None, False),
        ("low_ready", 225, 0, 5, 1, 1, 1, 230, None, True),
        ("first_band_lower", 226, 0, 5, 1, 1, 0, 231, 0, True),
        ("first_band_upper", 360, 0, 5, 1, 1, 0, 365, 0, True),
        ("second_band_lower", 361, 0, 5, 1, 1, 0, 366, 1, True),
        ("second_band_upper", 395, 0, 5, 1, 1, 0, 400, 1, True),
        ("third_band_lower", 396, 0, 5, 1, 1, 0, 401, 2, True),
    ):
        write(0x4008124B, config, 1)
        write(0x001030AB, 0, 1)
        write(0x001030E2, 3, 1)
        write(0x00103116, direction, 1)
        write(0x00103168, 0xA5A5, 2)
        write(0x0010316E, add, 2)
        write(step_input, sample)
        write(accessor + 0xC5F, gate, 1)
        write(accessor + 0x3FD, 0xA5, 1)
        write(operation_inner + 0xD6, ready, 1)
        write(record + 0x5E, 1, 1)
        write(record + 0xB0, 0x1234, 2)
        write(motor + 0x60, 0xA5, 1)
        write(pulse + 0xC2, 0xA5A5, 2)
        write(pulse + 0xBC, 0xA5A5, 2)
        write(pulse + 0x9E, 0xA5A5, 2)
        write(pulse + 0x168, 0xA5A5A5A5)
        write(pulse + 0x16C, 0xA5A5A5A5)
        write(position + 0x164, 0xA5A5, 2)
        write(position + 0x166, 0xA5A5, 2)
        transactions.clear()
        run(0x2248, 0x225C, r4=app, r8=app_state)
        calculated = read(pulse + 0xBC, 2)
        require(calculated, expected, f"{name} computed request")
        pulse_input = read(pulse + 0xC2, 2)
        subtract = read(0x00103168, 2)
        require(
            pulse_input,
            (0 if direction else sample) if config else 0xA5A5,
            f"{name} pulse input copy",
        )
        require(
            subtract,
            (100 if direction else 0) if config else 0xA5A5,
            f"{name} subtract input copy",
        )
        require(read(0x00103116), 0, f"{name} direction flag reset")

        observed_prepare.clear()
        end = BASE + 0x52ED4 if forward else 0x2350
        outcome = run(0x2348, end, r4=app)
        require(
            observed_prepare, [[motor, 8]] if forward else [], f"{name} prepare calls"
        )
        if not forward:
            require(outcome, int(expected == 0), f"{name} handler result")
        require(
            read(pulse + 0x9E, 2),
            expected if forward else 0xA5A5,
            f"{name} pulse destination",
        )
        require(
            read(position + 0x166, 2),
            expected if forward else 0xA5A5,
            f"{name} position destination",
        )
        require(
            read(position + 0x164, 2),
            0x1234 if expected else 0xA5A5,
            f"{name} position record copy",
        )
        require(read(motor + 0x60), 0xA5 if band is None else band, f"{name} band")
        require(
            read(accessor + 0x3FD), 0xA5 if band is None else 1, f"{name} band flag"
        )
        for offset in (0x168, 0x16C):
            require(
                read(pulse + offset, 4),
                0xA5A5A5A5 if expected else 0,
                f"{name} zero request cleanup at {offset:#x}",
            )
        require(transactions, [], f"{name} lens transport calls")
        control_cases.append(
            {
                "case": name,
                "step_halfword": sample,
                "direction_flag": direction,
                "normalized_pulse_halfword": pulse_input if config else None,
                "normalized_subtract_halfword": subtract if config else None,
                "add_halfword": add,
                "configuration_value": config,
                "calculation_flag": gate,
                "ready_byte": ready,
                "computed_request": calculated,
                "band": band,
                "prepare_argument": 8 if forward else None,
                "continuation_va": end,
                "no_prepare_return": None if forward else outcome,
            }
        )
    lens_control_cases = []
    write(status_record + 1, 0x40, 1)
    write(kaf + 6, 0, 1)
    transactions.clear()
    reply, transport_status = 0x40, 0
    run(BASE + 0x94DC4, BASE + 0x94E70, r0=sdm)
    require(transactions, [[0x8205, 1]], "lens control capability transaction")
    require(read(kaf + 6), 0x40, "capability inherited by lens control")
    for name, reply, transport_status, prior_reply, expected, remaining in (
        ("lens_positive_reply", 0x0102, 0, 0x0201, 0x0102, 0x02FE),
        ("lens_signed_negative", 0xFFFF, 0, 0x0201, 0, 0x0400),
        ("lens_error_without_reply_write", 0xA5A5, 7, 0x0201, 0x0201, 0x01FF),
    ):
        write(0x4008124B, 1, 1)
        write(0x001030AB, 0, 1)
        write(0x001030E2, 3, 1)
        write(kaf + 0x1A, 0, 1)
        write(accessor + 0xC5F, 1, 1)
        write(pulse + 0xBA, 0x0400, 2)
        write(pulse + 0xBC, 0xA5A5, 2)
        write(pulse + 0x9E, 0xA5A5, 2)
        write(position + 0x166, 0xA5A5, 2)
        vm.mem_write(sdm + 4, prior_reply.to_bytes(2, "big"))
        transactions.clear()
        run(0x2248, 0x225C, r4=app, r8=app_state)
        require(transactions, [[0x8211, 2]], f"{name} lens query")
        require(read(pulse + 0xBC, 2), expected, f"{name} computed request")
        require(read(pulse + 0xBA, 2), remaining, f"{name} pulse bookkeeping")

        observed_prepare.clear()
        end = BASE + 0x52E98 if expected else 0x2350
        outcome = run(0x2348, end, r4=app)
        require(
            observed_prepare, [[motor, 8]] if expected else [], f"{name} prepare calls"
        )
        require(read(pulse + 0x9E, 2), expected or 0xA5A5, f"{name} pulse destination")
        require(
            read(position + 0x166, 2),
            expected or 0xA5A5,
            f"{name} position destination",
        )
        require(transactions, [[0x8211, 2]], f"{name} total lens transactions")
        if not expected:
            require(outcome, 1, f"{name} handler result")
        lens_control_cases.append(
            {
                "case": name,
                "transport_status": transport_status,
                "reply": reply if transport_status == 0 else None,
                "previous_response_word": prior_reply,
                "transactions": transactions.copy(),
                "computed_request": expected,
                "pulse_remaining_halfword": remaining,
                "prepare_argument": 8 if expected else None,
                "continuation_va": end,
            }
        )

    return {
        "unicorn_version": unicorn.__version__,
        "stubbed_file_offsets": [0x93F94],
        "acquisition_cases": acquisition_cases,
        "body_control_cases": control_cases,
        "lens_control_cases": lens_control_cases,
        "boundaries": [
            "Acquisition starts at 0x94dc4 with a prepared CLensSdm object and a synthetic byte through [0x40006064]. The only execution replacement is the 0x93f94 lens transfer hook. It injects a reply and status, or status alone for the explicitly modeled 0x8211 failure without a reply write. Probes stop at the unready return, cached continuation, or first branch after the original 0x8205 query.",
            "The AF control fixtures execute two original slices of the same ITCM routine, VA 0x2248 through 0x225c and VA 0x2348 until the first body/lens split inside CAfMotor 0x52e38 (file 0x52ed4 / 0x52e98) or return to VA 0x2350. A read-only hook observes the actual prepare arguments. The slices share the same prepared application, motor, pulse and position objects. Firmware between the two slices and drive execution past that split are outside these cases.",
            "Control fixtures use capability bytes written by the original 0x8205 acquisition path. Both sets use global 0x001030ab clear and preparation state 3. The lens-control fixtures also use raw CLensKaf2+0x1a bit 0 clear and accessor+0xc5f equal to 1. The status-only failure case shows caller behavior under the specified reply-buffer boundary, while the physical transport's failure behavior remains untested. Hardware sample sources, AF sensor/optics algorithms, full scheduler, remaining lens initialization and physical movement are outside the probes.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded_image", type=Path)
    parser.add_argument("--emulate", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    data = load_image(args.decoded_image)
    result = verify(data)
    if args.emulate:
        result["numeric"] = emulate(data)
    if args.compare:
        require_snapshot(result, args.compare, "AF control evidence")
        print(f"AF control evidence matches {args.compare}")
    if args.output:
        args.output.write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
    if not args.compare and not args.output:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
