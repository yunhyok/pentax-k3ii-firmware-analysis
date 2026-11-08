"""Verify the K-3 II v1.12 body AF counter input and additive request state.

SPDX-License-Identifier: GPL-2.0-only
"""

import argparse
import json
from pathlib import Path

from verify_af_drive import COPY_ROWS, code_va
from verify_findings import DECODED_SHA256, require, sha256, u32
from verify_raw_path import branch_target
from verify_tone_path import BASE, check_words, load_image


CLASSES = {
    "8CAfMotor": (0xD2610, 0xD0F90, 0xD4F9C),
    "9CAfDriver": (0xD2657, 0xD0FEC, 0xD5084),
    "10CUdcDriver": (0xD112A, 0xD038C, 0xD2930),
    "17CUdcDriverFactory": (0xD18C4, 0xD090C, 0xD3C04),
    "19CTimerDriverFactory": (0xD1ADE, 0xD0A38, 0xD3FA8),
    "23C32bitReloadTimerDriver": (0xD1E3B, 0xD0C00, 0xD44E4),
}
WORDS = {
    0xD3C0C: BASE + 0x33710,
    0xD3FB0: BASE + 0x32010,
    0x32764: BASE + 0xD3FA8,
    0x335FC: BASE + 0xD44E4,
    0x34278: BASE + 0xD2930,
    0x4771C: BASE + 0xD5084,
    0x47738: 0x4000B25C,
    0x3221C: 0xE3A070D1,
    0x32220: 0xE3A08082,
    0x32798: 0x30011020,
    0x3279C: 0x30011028,
    0x327A0: 0x3001102C,
    0x327A4: 0x30011024,
    0x32E44: 0xE5840024,
    0x33994: 0xE3A0105F,
    0x33BBC: 0x00000117,
    0x33BAC: 0x30014060,
    0x33C44: 0xE584001C,
    0xB90EC: 0xE5801014,
    0xB9EB4: 0xE5900014,
    0xB6BD8: 0xE580100C,
    0xB9CC4: 0xE590000C,
    0x26C40: 0x15801008,
    0x26CC4: 0xE0805101,
    0x46BC4: 0xE3A010D1,
    0x47720: 0x00000117,
    0x46BD0: 0xE5840004,
    0x46C10: 0xE5840018,
    0x48EEC: 0xE5840020,
    0xB66C0: 0xE5900020,
    0x51E10: 0xE5840008,
    0xD7B0C: 0xE5900018,
    0xD7B18: 0xE5900004,
    0xB9E80: 0xE5900024,
    0xB9E84: 0xE5900000,
    0xB9C98: 0xE590001C,
    0xB9C9C: 0xE5900000,
    0xD8DA4: 0x0010316E,
    0xD8D9C: 0xE1C010B0,
    0xD6E0C: 0xE3A01000,
    0xD7558: 0xE5940020,
    0xD766C: 0x05940020,
    0xD7764: 0xE5940020,
    0x542D8: 0xE5D4004D,
    0x542E4: 0xE3560028,
    0x542E8: 0xE3A05028,
    0x53EC0: 0x00103120,
    0x54DC4: 0x0010311A,
    0x54DC8: 0x00103116,
    0x54348: 0xE0460005,
    0x5439C: 0xE3A05000,
    0x543A0: 0xE0672807,
    0x54414: 0xE5C10000,
    0xB713C: 0x001030E2,
    0xB753C: 0x0010316E,
    0x54510: 0xE1E00000,
    0x54644: 0xE0800005,
    0x54670: 0xE1A00840,
    0xB982C: 0xE1C01BBC,
}
# Branch destinations are execution addresses, including relocated code.
EDGES = (
    (0x32274, BASE + 0xB90EC),
    (0x32294, BASE + 0xAB71C),
    (0x3229C, BASE + 0x32DE0),
    (0x32E40, BASE + 0xB9EB4),
    (0x32E64, BASE + 0x26AA4),
    (0x32E78, BASE + 0x26AE0),
    (0x33960, BASE + 0xB6BD8),
    (0x339A4, BASE + 0xAB71C),
    (0x339AC, BASE + 0x33BF8),
    (0x33C40, BASE + 0xB9CC4),
    (0x33C88, BASE + 0x26AA4),
    (0x33C9C, BASE + 0x26AE0),
    (0x26AC8, BASE + 0x26C48),
    (0x26C94, BASE + 0x26C3C),
    (0x26B04, BASE + 0x27334),
    (0x46BCC, BASE + 0x26CB0),
    (0x46C0C, BASE + 0x26CB0),
    (0x48EE8, BASE + 0x46CF0),
    (0x51E0C, BASE + 0xB66C0),
    (0xD7B08, 0x26FC),
    (0xD7B14, 0x0100F740),
    (0xD7B1C, 0x0100F744),
    (0xE7FA0, BASE + 0x3408C),
    (0xE7FA4, BASE + 0x33420),
    (0x33420, BASE + 0xB9E80),
    (0x34090, BASE + 0xB9C98),
    (0xD6E10, 0x397C),
    (0xD755C, 0x0100F6E8),
    (0xE7F48, BASE + 0x54284),
    (0x54298, BASE + 0x4C500),
    (0x542AC, 0x0100F3D8),
    (0xE7C38, 0x2994),
    (0xD7DE8, 0x26E4),
    (0x542CC, 0x0100F3B0),
    (0xE7C10, 0x3B4),
    (0xD57FC, 0x2B98),
    (0x542EC, BASE + 0x5435C),
    (0x54304, BASE + 0x54398),
    (0x54314, BASE + 0x5234C),
    (0x54324, BASE + 0x5234C),
    (0x54344, BASE + 0xB97FC),
    (0x54358, 0x0100F4E0),
    (0xE7D40, 0x397C),
    (0x543AC, BASE + 0x5234C),
    (0x543B4, BASE + 0x5431C),
    (0x54408, 0x0100F414),
    (0xE7C74, 0x2A60),
    (0x54424, BASE + 0xB7130),
    (0xD7674, 0x0100F708),
    (0xE7F68, BASE + 0x5455C),
    (0x54608, BASE + 0x544EC),
    (0x5450C, 0x0100F4A4),
    (0x54534, 0x0100F4A4),
    (0xE7D04, 0x26E4),
    (0x54640, BASE + 0xB7530),
    (0x546F8, BASE + 0xB982C),
    (0xD7768, 0x0100F710),
    (0xE7F70, BASE + 0x547CC),
    (0x5493C, BASE + 0x52E38),
)
RANGES = {
    "timer_factory_d1": (0x3221C, 0x322AC),
    "timer_constructor": (0x32DE0, 0x32E84),
    "udc_factory_117": (0x3391C, 0x339B4),
    "udc_constructor": (0x33BF8, 0x33CA8),
    "body_registry_lookups": (0x46BC4, 0x46C14),
    "itcm_counter_select": (0xD7B00, 0xD7B2C),
    "itcm_additive_store": (0xD8D98, 0xD8DA8),
    "motor_additive_producer": (0x54284, 0x54428),
    "motor_request_calculator": (0x544EC, 0x547CC),
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
        "schema_version": 1,
        "firmware_version": "1.12",
        "decoded_sha256": DECODED_SHA256,
        "image_base": BASE,
        "offset_units": "Decoded file offsets except fields explicitly named VA or object offsets.",
        "word_check_count": len(WORDS),
        "classes": {
            name: {
                "name_file_offset": offset,
                "rtti_file_offset": info,
                "vtable_file_offset": table,
            }
            for name, (offset, info, table) in CLASSES.items()
        },
        "branches": [
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
        "counter_binding": {
            "body_singleton_va": 0x4000B25C,
            "registry_va": 0x40006944,
            "registry_entry_stride": 12,
            "composite_driver_object_offset": 0x20,
            "motor_driver_object_offset": 8,
            "counter_getter_va": 0x26E4,
            "zero_selector": {
                "registry_id": 0xD1,
                "event_table_slot": 0x82,
                "body_timer_object_offset": 4,
                "timer_register_pointer_object_offset": 0x24,
                "counter_mmio_va": 0x30011024,
            },
            "nonzero_selector": {
                "registry_id": 0x117,
                "event_table_slot": 0x5F,
                "body_udc_object_offset": 0x18,
                "udc_register_pointer_object_offset": 0x1C,
                "counter_mmio_va": 0x30014060,
            },
        },
        "additive_and_request": {
            "additive_halfword_va": 0x0010316E,
            "additive_writer_va": 0x397C,
            "reset_call_va": 0x19F4,
            "producer_dispatch_call_va": 0x2140,
            "producer_file_offset": 0x54284,
            "unsigned_counter_exclusive_threshold": 40,
            "normal_subtrahend": 40,
            "alternate_subtrahend": 0,
            "alternate_selection": "After the producer gates, global 0x00103120 is zero or global 0x0010311a equals 2.",
            "native_direction_write_file_offset": 0x54414,
            "direction_flag_va": 0x00103116,
            "calculator_dispatch_call_va": 0x2258,
            "calculator_file_offset": 0x5455C,
            "request_halfword_pulse_object_offset": 0xBC,
            "prepare_handoff_dispatch_call_va": 0x234C,
            "prepare_entry_file_offset": 0x52E38,
        },
    }


def emulate(data):
    import unicorn
    from unicorn import arm_const as arm

    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    for address, size in (
        (0, 0x4000),
        (0x00102000, 0x2000),
        (0x01002000, 0xE000),
        (0x10000000, 0x14000),
        (0x30011000, 0x4000),
        (0x40006000, 0x3000),
        (0x4000B000, 0x1000),
        (0x40080000, 0x2000),
    ):
        vm.mem_map(address, size)
    for source, destination, length in COPY_ROWS.values():
        vm.mem_write(destination, data[source : source + length])

    app, factory, timer, motor, accessor, pulse, lens, kaf, record, operation, state = (
        0x10000000 + 0x1000 * i for i in range(1, 12)
    )
    udc, position, operation_inner = 0x1000C000, 0x1000D000, 0x1000E000
    udc_factory = 0x1000F000
    body = 0x4000B25C
    composite = 0x4000B30C
    registry = 0x40006944
    count = 0x30011024
    udc_count = 0x30014060
    additive = 0x0010316E
    stack = 0x10012000
    ret = 0x10013000

    def write(address, value, width=4):
        vm.mem_write(address, value.to_bytes(width, "little"))

    def read(address, width=4):
        return int.from_bytes(vm.mem_read(address, width), "little")

    def reg(name, value=None):
        register = getattr(arm, f"UC_ARM_REG_{name.upper()}")
        if value is None:
            return vm.reg_read(register)
        vm.reg_write(register, value)

    def run(begin, end, **registers):
        for name, value in dict(sp=stack, lr=ret, **registers).items():
            reg(name, value)
        vm.ctl_flush_tb()
        try:
            vm.emu_start(begin, end, count=20000)
        except unicorn.UcError as error:
            raise ValueError(
                f"{begin:#x} -> {end:#x}, PC {reg('pc'):#x}, R0 {reg('r0'):#x}, R1 {reg('r1'):#x}"
            ) from error
        require(reg("pc"), end, f"original execution from {begin:#x}")
        return reg("r0")

    alloc_sizes = []
    drive_prepares = []
    counter_reads = []
    completion_calls = []
    additive_writes = []

    def stub(_vm, address, _size, _user):
        if address == BASE + 0xAB71C:
            size = reg("r0")
            alloc_sizes.append(size)
            reg("r0", {0x2C: timer, 0x30: udc}[size])
        elif address == BASE + 0x5234C:
            require(reg("r0"), motor, "prepared motor object")
            drive_prepares.append([reg("r1"), reg("r2")])
            reg("r0", 0)
        else:
            require(reg("r0"), motor, "completion motor object")
            completion_calls.append(reg("r1"))
            reg("r0", 0)
        reg("pc", reg("lr"))

    vm.hook_add(unicorn.UC_HOOK_CODE, stub, begin=0x2A60, end=0x2A60)

    def counter_access(_vm, _kind, address, size, _value, _user):
        counter_reads.append([address, size])

    for offset in (0xAB71C, 0x5234C):
        vm.hook_add(unicorn.UC_HOOK_CODE, stub, begin=BASE + offset, end=BASE + offset)
    for address in (count, udc_count):
        vm.hook_add(
            unicorn.UC_HOOK_MEM_READ, counter_access, begin=address, end=address + 3
        )

    def observe_additive(_vm, _kind, address, size, value, _user):
        additive_writes.append(
            {
                "address_va": address,
                "size": size,
                "value": value,
                "writer_va": reg("pc"),
            }
        )

    vm.hook_add(
        unicorn.UC_HOOK_MEM_WRITE, observe_additive, begin=additive, end=additive + 1
    )

    write(0x40006040, 1)
    write(0x40006048, 1)
    vm.mem_write(stack, bytes(0x20))
    run(BASE + 0x3221C, BASE + 0x322AC, r4=factory, r6=registry)
    require(alloc_sizes, [0x2C], "one original timer allocation")
    require(read(factory + 0x10), timer, "timer slot")
    require(read(timer), BASE + 0xD44E4, "timer vtable")
    require(read(timer + 4), 0xD1, "timer registration ID")
    require(
        [read(timer + offset) for offset in (0x18, 0x1C, 0x20, 0x24)],
        [0x30011020, 0x30011028, 0x3001102C, count],
        "native timer register pointers",
    )
    entry = registry + 0xD1 * 12
    require(
        [read(entry, 1), read(entry + 4), read(entry + 8)],
        [1, 0xD1, timer],
        "native timer registry entry",
    )
    require(read(0x40007820 + 0x82 * 4), timer + 8, "native event-table entry")

    vm.mem_write(stack, bytes(0x24))
    run(BASE + 0x3391C, BASE + 0x339B4, r4=udc_factory)
    require(alloc_sizes, [0x2C, 0x30], "original timer and UDC allocations")
    require(read(udc_factory + 0x10), udc, "UDC factory slot")
    require(read(udc), BASE + 0xD2930, "UDC vtable")
    require(read(udc + 4), 0x117, "UDC registration ID")
    require(read(udc + 0x1C), udc_count, "native UDC count pointer")
    entry = registry + 0x117 * 12
    require(
        [read(entry, 1), read(entry + 4), read(entry + 8)],
        [1, 0x117, udc],
        "native UDC registry entry",
    )
    require(read(0x40007820 + 0x5F * 4), udc + 8, "native UDC event-table entry")

    # Supply the initialized guards and run the native lookups.
    write(0x4000623C, 1)
    run(BASE + 0x46BC4, BASE + 0x46BD4, r4=body, r5=registry)
    require(read(body + 4), timer, "CAfDriver timer pointer")
    run(BASE + 0x46C04, BASE + 0x46C14, r4=body, r5=registry)
    require(read(body + 0x18), udc, "CAfDriver UDC pointer")
    run(BASE + 0x48EE8, BASE + 0x48EF0, r4=composite)
    require(read(composite + 0x20), body, "composite driver pointer")
    run(BASE + 0x51E08, BASE + 0x51E14, r4=motor, r6=composite)
    require(read(motor + 8), body, "CAfMotor body pointer")
    for obj, fields in (
        (app, {0x20: motor, 0x28: pulse}),
        (motor, {4: accessor, 0xC: lens, 0x14: position, 0x18: pulse, 0x28: operation}),
        (accessor, {0x20: lens, 0x234: record}),
        (lens, {0x1C: kaf}),
        (operation, {0x10: operation_inner}),
    ):
        for offset, value in fields.items():
            write(obj + offset, value)

    write(count, 0xAAAA1234)
    write(udc_count, 0xBBBB5678)
    getter_cases = []
    for selector, address, expected in (
        (0, count, 0x1234),
        (1, udc_count, 0x5678),
        (2, udc_count, 0x5678),
    ):
        counter_reads.clear()
        value = run(0x26E4, ret, r0=body, r1=selector)
        require(value, expected, "native getter value")
        require(counter_reads, [[address, 4]], "native getter selected register")
        getter_cases.append({"r1": selector, "register": address, "result": value})

    write(0x40080090, 0x44, 1)
    write(operation_inner + 0xD6, 1, 1)
    write(record + 0xB0, 0x1234, 2)
    write(additive, 0xA5A5, 2)
    run(0x19EC, 0x19F8, r4=app)
    require(read(additive, 2), 0, "native additive reset")
    require(
        additive_writes,
        [{"address_va": additive, "size": 2, "value": 0, "writer_va": 0x3980}],
        "native reset write",
    )
    reset_writes = additive_writes.copy()
    cases = []
    for (
        name,
        raw,
        state_a,
        state_b,
        blocked,
        mode,
        capability,
        next_raw,
        direction,
        expected_add,
        expected_calls,
        expected_request,
    ) in (
        (
            "normal",
            0xA5A50190,
            1,
            1,
            0,
            0,
            0,
            0xFEED0007,
            0,
            360,
            [[0, 40], [1, 80]],
            367,
        ),
        (
            "alternate_state_2",
            50,
            1,
            2,
            0,
            0,
            0,
            0xA5A5FFF5,
            1,
            50,
            [[0, 0xFFFF], [1, 0]],
            40,
        ),
        (
            "normal_unchanged_counter_fixture",
            0x12340032,
            1,
            1,
            0,
            0,
            0,
            0x12340032,
            0,
            10,
            [[0, 40], [1, 80]],
            60,
        ),
        (
            "alternate_control_clear",
            50,
            0,
            1,
            0,
            0,
            0,
            0xA5A5FFF5,
            1,
            50,
            [[0, 0xFFFF], [1, 0]],
            40,
        ),
        ("threshold_40", 40, 1, 1, 0, 0, 0, 5, 0, 12, [], 17),
        ("threshold_41", 41, 1, 1, 0, 0, 0, 5, 0, 1, [[0, 40], [1, 80]], 6),
        ("halfword_wrap", 0xFFFF, 1, 1, 0, 0, 0, 42, 0, 0xFFD7, [[0, 40], [1, 80]], 1),
        (
            "signed_positive_limit",
            41,
            1,
            1,
            0,
            0,
            0,
            0x7FFE,
            0,
            1,
            [[0, 40], [1, 80]],
            0x7FFF,
        ),
        (
            "signed_negative_clamp",
            41,
            1,
            1,
            0,
            0,
            0,
            0x7FFF,
            0,
            1,
            [[0, 40], [1, 80]],
            0,
        ),
        ("state_predicate_five", 400, 1, 5, 0, 0, 0, 5, 0, 12, [], 17),
        ("state_predicate_clear", 400, 1, 0, 0, 0, 0, 5, 0, 12, [], 17),
        ("motor_flag_set", 400, 1, 1, 1, 0, 0, 5, 0, 12, [], 17),
        ("mode_flag_set", 400, 1, 1, 0, 1, 0, None, 0, 12, [], None),
        ("lens_capability_set", 400, 1, 1, 0, 0, 0x40, None, 0, 12, [], None),
    ):
        write(count, raw)
        write(0x00103120, state_a, 1)
        write(0x0010311A, state_b, 1)
        write(0x001030AB, mode, 1)
        write(motor + 0x4D, blocked, 1)
        write(kaf + 6, capability, 1)
        write(additive, 12, 2)
        previous_additive = read(additive, 2)
        write(pulse + 0xBA, 1024, 2)
        write(pulse + 0x98, 0, 1)
        write(0x001030E2, 0xA5, 1)
        drive_prepares.clear()
        completion_calls.clear()
        additive_writes.clear()
        counter_reads.clear()
        write(0x00103116, 0, 1)
        write(position + 0x40, 0xA5A5, 2)
        complete = name in ("normal", "alternate_state_2")
        stop = 0x2144 if complete else BASE + (0x543CC if capability else 0x5435C)
        run(0x213C, stop, r4=app)
        require(
            completion_calls,
            [0] if name == "alternate_state_2" else [],
            f"{name} reset calls",
        )
        require(
            read(0x00103116, 1),
            direction if complete else 0,
            f"{name} native direction flag",
        )
        require(read(0x001030E2, 1), 2 if complete else 0xA5, f"{name} state result")
        if complete:
            require(read(position + 0x40, 2), 0x400, f"{name} position record result")
        require(
            counter_reads,
            [] if capability else [[count, 4]],
            f"{name} original counter access",
        )
        require(drive_prepares, expected_calls, f"{name} drive preparation")
        require(read(additive, 2), expected_add, f"{name} native additive store")
        expected_writes = (
            [
                {
                    "address_va": additive,
                    "size": 2,
                    "value": expected_add,
                    "writer_va": 0x3980,
                }
            ]
            if expected_calls
            else []
        )
        require(additive_writes, expected_writes, f"{name} additive writes")
        producer_direction = read(0x00103116, 1)
        require(
            read(pulse + 0xBA, 2),
            (1024 - expected_add) & 0xFFFF if expected_calls else 1024,
            f"{name} pulse remainder",
        )

        if next_raw is not None:
            write(count, next_raw)
            if not complete:
                write(0x00103116, direction, 1)
                write(0x001030E2, 3, 1)
            write(0x4008124B, 1, 1)
            write(record + 0x5E, 1, 1)
            write(accessor + 0xC5F, 1, 1)
            write(pulse + 0xBC, 0xA5A5, 2)
            counter_reads.clear()
            run(0x2248, 0x225C, r4=app, r8=state)
            require(counter_reads, [[count, 4]], f"{name} subsequent counter access")
            require(read(pulse + 0xBC, 2), expected_request, f"{name} original request")
            require(read(0x00103116, 1), 0, f"{name} original direction flag clear")
            require(
                additive_writes,
                expected_writes,
                f"{name} calculator leaves additive unchanged",
            )
            require(
                read(additive, 2), expected_add, f"{name} additive survives calculation"
            )
        if complete:
            write(pulse + 0x9E, 0xA5A5, 2)
            write(position + 0x166, 0xA5A5, 2)
            run(0x2348, BASE + 0x52E38, r4=app)
            require(
                [reg("r0"), reg("r1")], [motor, 8], f"{name} native prepare arguments"
            )
            require(read(pulse + 0x9E, 2), expected_request, f"{name} pulse target")
            require(
                read(position + 0x166, 2), expected_request, f"{name} position target"
            )
        cases.append(
            {
                "case": name,
                "injected_counter_word": raw,
                "previous_additive": previous_additive,
                "native_additive": read(additive, 2),
                "native_additive_writes": additive_writes.copy(),
                "initial_counter_read": capability == 0,
                "control_103120": state_a,
                "state_10311a": state_b,
                "motor_flag_4d": blocked,
                "mode_flag_1030ab": mode,
                "lens_capability_byte": capability,
                "body_prepare_calls": drive_prepares.copy(),
                "completion_reset_calls": completion_calls.copy(),
                "producer_stop_va": stop,
                "native_direction_flag_after_producer": producer_direction,
                "calculator_uses_producer_direction": (
                    complete if next_raw is not None else None
                ),
                "calculator_direction": direction if next_raw is not None else None,
                "next_injected_counter_word": next_raw,
                "native_request": expected_request,
                "verified_prepare_entry_file_offset": 0x52E38 if complete else None,
                "native_prepare_argument": 8 if complete else None,
            }
        )

    return {
        "engine": f"Unicorn {unicorn.__version__}",
        "emulated_cpu": "Cortex-A9",
        "getter_cases": getter_cases,
        "native_reset_writes": reset_writes,
        "execution_replacements": [
            {
                "file_offset": 0xAB71C,
                "role": "Supplies scratch storage of 0x2c or 0x30 bytes for the native driver constructors.",
            },
            {
                "file_offset": 0x5234C,
                "role": "Records the original direction and target arguments and returns without running body hardware preparation.",
            },
            {
                "file_offset": 0xD7E7C,
                "execution_va": 0x2A60,
                "role": "Records the alternate completion reset helper's argument and returns without reconfiguring hardware.",
            },
        ],
        "cases": cases,
        "limits": [
            "The driver factory slices use prepared stack, factory objects, initialized registry guards and RAM-backed device addresses. Driver constructors, registry writes and driver pointer wiring are original instructions.",
            "The producer slice starts at ITCM VA 0x213c, after its parent state gate. Normal and alternate-state-2 cases run its tail through VA 0x2144. Other cases stop at file 0x5435c or 0x543cc after the tested decision.",
            "The calculator slice is VA 0x2248 through 0x225c. Its MMIO input is supplied separately from the initial counter word. Full-tail cases retain the resulting direction and state into the calculator: normal retains seeded direction zero, alternate writes direction one, and both write state two. Prefix-only cases supply those fields explicitly.",
            "Two cases continue at VA 0x2348 to drive-prepare entry 0x52e38. Scheduling between slices, device updates between injected counter samples, physical counter units, optical sensing and motor movement are outside the probes.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded_image", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    data = load_image(args.decoded_image)
    result = verify(data)
    result["numeric"] = emulate(data)
    if args.compare:
        require(
            result,
            json.loads(args.compare.read_text(encoding="utf-8")),
            "AF input evidence",
        )
        print(f"AF input evidence matches {args.compare}")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
