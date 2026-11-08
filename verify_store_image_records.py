"""Replay K-3 II embedded StoreImage records and native JPEG completion links.

Only bounded original instructions run; objects and device state are synthetic.
SPDX-License-Identifier: GPL-2.0-only
"""

import argparse
import json
from pathlib import Path

import unicorn as uc
from unicorn import arm_const as arm

from verify_findings import require, require_snapshot, sha256
from verify_tone_path import BASE, check_edge, check_words, load_image


def emulate_records(data):
    vm = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    for address, size in (
        (BASE, 0x1000000),
        (0x10000000, 0x100000),
    ):
        vm.mem_map(address, size)
    vm.mem_write(BASE, data[:0x1000000])
    capture, stack, stop = 0x10040000, 0x100F0000, 0x100F1000

    def get(address, size=4):
        return int.from_bytes(vm.mem_read(address, size), "little")

    def reg(name, value=None):
        index = getattr(arm, f"UC_ARM_REG_{name.upper()}")
        if value is None:
            return vm.reg_read(index)
        vm.reg_write(index, value)

    def run(entry, *args, end=None, **regs):
        for name, value in dict(sp=stack, lr=stop, **regs).items():
            reg(name, value)
        for i, value in enumerate(args):
            reg(f"r{i}", value)
        finish = stop if end is None else BASE + end
        vm.ctl_flush_tb()
        try:
            vm.emu_start(BASE + entry, finish, count=1000000)
        except uc.UcError as error:
            raise ValueError(f"{entry:#x}: stopped at VA {reg('pc'):#x}") from error
        require(reg("pc"), finish, f"native boundary from {entry:#x}")
        return reg("r0")

    for site, target in (
        (0x653BAC, 0x5AA3DC),
        (0x653D8C, 0x72D808),
        (0x653DA4, 0x72D7F4),
        (0x653DB4, 0x72D818),
        (0x6DB6AC, 0x7DD140),
        (0x6DC2E4, 0x81C770),
        (0x6DC2F4, 0x6593B0),
        (0x65C2EC, 0x65784C),
        (0x65C31C, 0x656FA4),
        (0x65C348, 0x656D68),
        (0x657940, 0x832FB0),
        (0x65798C, 0x8598E0),
        (0x6DC334, 0x656984),
        (0x6DC340, 0x7DB910),
        (0x6DC34C, 0x7DB918),
        (0x5A97D4, 0x72D8CC),
        (0x5A97E8, 0x5A8790),
        (0x5A88B4, 0x72D808),
        (0x5A8BEC, 0x72D7F4),
        (0x5A91E8, 0x72D818),
        (0x5A88DC, 0x5A820C),
        (0x5A8C14, 0x5A820C),
        (0x5A920C, 0x5A820C),
        (0x5A8288, 0x82D878),
    ):
        check_edge(data, site, target)
    for site, target in (
        (0x6594F8, 0x65C174),
        (0x6569D8, 0x656A40),
        (0x6DC360, 0x6FEA38),
    ):
        check_edge(data, site, target, link=False)
    check_words(
        data,
        {
            0x6DC16C: 0x00800001,
            0x656A40: 0xE30A0850,
            0x7DB910: 0xE5801008,
            0x72D8CC: 0xE5900008,
            0x82D8A0: 0xE5805018,
            0x82D8E0: 0xE5905018,
            0x832FB0: 0xE5801028,
            0x8598E0: 0xE5801034,
        },
    )
    reg("fpexc", 0x40000000)

    def put(address, value, size=4):
        vm.mem_write(address, value.to_bytes(size, "little"))

    vm.mem_map(0x40400000, 0x100000)
    for guard in (0x404099F0, 0x4041D97C):
        put(guard, 1)
    controller, recipe, queue = 0x10010000, 0x10020000, 0x10030000
    registry, store = 0x10060000, 0x10070000
    put(registry + 0x58, queue - 8)
    run(0x6DB6A8, end=0x6DB6C4, r4=controller, r5=registry)
    require(
        (get(controller + 0x5C), get(controller + 0xB0)),
        (queue, 0x00800001),
        "original module 9 registration",
    )

    record_offsets = (0xA860, 0xAC5C, 0xB058, 0xB454, 0xB850, 0xBC4C)
    records = [capture + off for off in record_offsets]
    groups = (0x3E, 0x40, 0x42)
    spans = (4, 0x50, 0x9C, 0xE8)
    payload, event, request = capture + 0xA850, capture + 8, store + 0x420
    buffer_fields = {
        0x190: 0x11000000,
        0x194: 0x11001000,
        0x198: 0x12000000,
        0x19C: 0x13000000,
        0x1A0: 0x14000000,
        0x1A4: 0x15000000,
        0x1A8: 0x16000000,
        0x1AC: 0x17000000,
    }
    length_fields = {
        0x2EC: 0x1234,
        0x2F0: 0x5678,
        0x2FC: 0x9ABC,
        0x2F4: 0xA456,
        0x2F8: 0xB789,
        0x20F8: 0xC678,
    }
    expected_record = (
        (0, [(0x11000000, 0x1234), (0x12000000, 0xA456), (0x13000000, 0xB789), (0, 0)]),
        (0, [(0x11001000, 0x5678), (0x12000000, 0xA456), (0x13000000, 0xB789), (0, 0)]),
        (
            5,
            [
                (0x14000000, 0x9ABC),
                (0x12000000, 0xA456),
                (0x13000000, 0xB789),
                (0x15000000, 0),
            ],
        ),
        (
            5,
            [
                (0x14000000, 0x9ABC),
                (0x12000000, 0xA456),
                (0x13000000, 0xB789),
                (0x15000000, 0),
            ],
        ),
        (9, [(0x17000000, 0x600), (0x12000000, 0xA456), (0x16000000, 0xC678), (0, 0)]),
        (9, [(0x17000000, 0x600), (0x12000000, 0xA456), (0x16000000, 0xC678), (0, 0)]),
    )
    calls = []

    def observe(_vm, pc, _size, _user):
        calls.append((pc - BASE, reg("r0"), reg("r1")))

    for off in (
        0x65784C,
        0x656FA4,
        0x656D68,
        0x5AA3B0,
        0x656984,
        0x7DB910,
        0x7DB918,
        0x5A8790,
        0x5A820C,
    ):
        vm.hook_add(uc.UC_HOOK_CODE, observe, begin=BASE + off, end=BASE + off)

    def fields(record):
        return get(record, 1), [
            (get(record + i + 0x34), get(record + i + 0x28)) for i in spans
        ]

    cases = []
    fixtures = [((0, 1, 2), 0)] + [
        ((group,), index) for group in range(3) for index in (0, 1)
    ]
    for enabled, index in fixtures:
        vm.mem_write(capture, bytes(0x16470))
        vm.mem_write(store, bytes(0x1000))
        put(capture, BASE + 0xA684E0)
        run(0x653BAC, payload, end=0x5AA434)
        run(0x653D74, end=0x653DC8, r4=capture)
        slots = [get(capture + off) for off in range(0xC2C4, 0xC2D9, 4)]
        require(slots, records, "native constructor aliases")
        run(0x6554F4, end=0x655554, r4=capture)

        put(capture + 0x34, recipe)
        put(capture + 0x38, 7)
        put(recipe + 0x10E, 9, 2)
        for group in enabled:
            put(capture + groups[group] + index, 1, 1)
        put(capture + 0x207C + index, 1, 1)
        put(capture + 0x20B4, 1, 1)
        for off, value in buffer_fields.items():
            put(capture + off, value)
        for off, value in length_fields.items():
            put(capture + off, value)
        for off, value in (
            (0x2D0, 32),
            (0x2D2, 64),
            (0x2D4, 16),
            (0x2D6, 32),
            (0x20D6, 16),
            (0x20D8, 8),
            (0x20DA, 8),
            (0x20DC, 4),
        ):
            put(capture + off, value, 2)

        calls.clear()
        run(0x6DC2D0, controller, capture, 0, end=0x6FEA38)
        require(
            tuple(reg(name) for name in ("r0", "r1", "r2")),
            (queue, event, 2),
            "native queue-entry registers",
        )
        require(
            [get(event + off) for off in (4, 8, 0xC, 0x10)],
            [controller + 4, payload, 0x00800001, capture],
            "native queue envelope",
        )
        expected_dispatch = []
        for group in enabled:
            target = (0x65784C, 0x656FA4, 0x656D68)[group]
            expected_dispatch.extend(
                (target, capture, i if group == 0 else records[2 * group + i])
                for i in (0, 1)
            )
        require(
            [row for row in calls if row[0] in (0x65784C, 0x656FA4, 0x656D68)],
            expected_dispatch,
            "native indexed consumer inputs",
        )
        require(
            [r0 for off, r0, _ in calls if off == 0x5AA3B0],
            [records[2 * g + i] for g in enabled for i in (0, 1)],
            "native record reuse arguments",
        )
        require(
            [row for row in calls if row[0] in (0x656984, 0x7DB910, 0x7DB918)],
            [
                (0x656984, capture, 9),
                (0x7DB910, event, payload),
                (0x7DB918, event, capture),
            ],
            "native module9 payload and job binding",
        )

        flags = list(vm.mem_read(payload, 6))
        require(
            flags,
            [int(g in enabled and i == index) for g in range(3) for i in (0, 1)],
            "native availability flags",
        )
        observed_records = [fields(addr) for addr in records]
        require(
            observed_records,
            [
                row if i // 2 in enabled else (0, [(0, 0)] * 4)
                for i, row in enumerate(expected_record)
            ],
            "native descriptor pointer and length fields",
        )

        # Connect the already constructed envelope to original consumer code.
        # This enters after StoreImage's queue receive and event validation.
        require(run(0x72D8C4, event), 0x00800001, "native event code getter")
        put(stack, event)
        calls.clear()
        run(0x5A97D0, end=0x5A8848, r5=store)
        require(
            calls,
            [(0x5A8790, store, payload)],
            "same queue payload reaches original receiver",
        )
        chosen = 2 * enabled[0] + index
        selected_record = reg("r0")
        require(
            selected_record, records[chosen], "same native record selected by receiver"
        )

        vm.mem_write(request + 0x18, bytes([0xA5]) * 16)
        caller, index_register = ((0x5A88AC, "r5"), (0x5A8BE4, "fp"), (0x5A91E0, "r6"))[
            enabled[0]
        ]
        put(stack + 0x30, get(event + 8))
        calls.clear()
        run(caller, end=0x5A8340, r4=store, **{index_register: index})
        require(
            calls,
            [(0x5A820C, store, selected_record)],
            "original caller reselects the same record",
        )
        require(get(store + 0x82, 1), index, "native selected index for StoreImage")
        mode = (0, 1, 3)[enabled[0]]
        require(get(store + 0x83, 1), mode, "original record type mapping")
        request_slots = [run(0x82D8B8, request, i) for i in range(4)]
        require(
            request_slots,
            [selected_record + off for off in (0x9C, 0x50, 4, 0xE8)],
            "native four descriptor aliases",
        )
        main_descriptor = (get(request_slots[2] + 0x34), get(request_slots[2] + 0x28))
        require(
            main_descriptor,
            expected_record[chosen][1][0],
            "same buffer address and size in request slot 2",
        )
        cases.append(
            {
                "enabled_record_groups": list(enabled),
                "available_index": index,
                "queue_event_id": get(event + 0xC),
                "payload_capture_offset": get(event + 8) - capture,
                "availability_bytes": flags,
                "selected_record_offset": selected_record - capture,
                "store_type_byte": mode,
                "request_caller_file_offset": caller,
                "request_slot_2_buffer_and_size": list(main_descriptor),
                "record_types_and_descriptors": observed_records,
            }
        )
    return {
        "decoded_sha256": sha256(data),
        "record_offsets": list(record_offsets),
        "descriptor_offsets_in_record": list(spans),
        "descriptor_pointer_offset": 0x34,
        "descriptor_length_offset": 0x28,
        "execution_replacements": [],
        "execution_boundaries": {
            "constructor_prefix": [0x653BAC, 0x5AA434],
            "pointer_publication": [0x653D74, 0x653DC8],
            "prepare_reset": [0x6554F4, 0x655554],
            "queue_entry": [0x6DC2D0, 0x6FEA38],
            "receiver_selection": [0x5A97D0, 0x5A8848],
            "request_end_exclusive": 0x5A8340,
        },
        "cases": cases,
    }


def emulate_jpeg_completion(data):
    vm = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    for address, size in (
        (BASE, 0x1000000),
        (0x10000000, 0x100000),
        (0x40400000, 0x100000),
        (0x200E0000, 0x3000),
    ):
        vm.mem_map(address, size)
    vm.mem_write(BASE, data[:0x1000000])
    capture, stack, stop = 0x10040000, 0x100F0000, 0x100F1000

    def get(address, size=4):
        return int.from_bytes(vm.mem_read(address, size), "little")

    def reg(name, value=None):
        index = getattr(arm, f"UC_ARM_REG_{name.upper()}")
        if value is None:
            return vm.reg_read(index)
        vm.reg_write(index, value)

    def run(entry, *args, end=None, **regs):
        for name, value in dict(sp=stack, lr=stop, **regs).items():
            reg(name, value)
        for i, value in enumerate(args):
            reg(f"r{i}", value)
        finish = stop if end is None else BASE + end
        vm.ctl_flush_tb()
        try:
            vm.emu_start(BASE + entry, finish, count=1000000)
        except uc.UcError as error:
            raise ValueError(f"{entry:#x}: stopped at VA {reg('pc'):#x}") from error
        require(reg("pc"), finish, f"native boundary from {entry:#x}")
        return reg("r0")

    for site, target in (
        (0x53D534, 0x53D3A8),
        (0x53D574, 0x6FE97C),
        (0x576C24, 0x53D700),
        (0x53D710, 0x6FE900),
        (0x6FE920, 0x6EF268),
        (0x576038, 0x70C3CC),
        (0x576C54, 0x78557C),
        (0x576C64, 0x71C278),
        (0x6DBDB8, 0x65DC34),
        (0x65E168, 0x7DD780),
        (0x66081C, 0x65420C),
        (0x660830, 0x65420C),
        (0x660838, 0x65420C),
        (0x653BAC, 0x5AA3DC),
        (0x6DB6AC, 0x7DD140),
        (0x6DC2F4, 0x6593B0),
        (0x65C2EC, 0x65784C),
        (0x657940, 0x832FB0),
        (0x65798C, 0x8598E0),
        (0x6DC334, 0x656984),
        (0x6DC340, 0x7DB910),
        (0x5A97E8, 0x5A8790),
        (0x5A88B4, 0x72D808),
        (0x5A88DC, 0x5A820C),
        (0x5A8288, 0x82D878),
    ):
        check_edge(data, site, target)
    for site, target in (
        (0x53D3B8, 0x4B8234),
        (0x576048, 0x576008),
        (0x65DCB8, 0x65E154),
        (0x6594F8, 0x65C174),
        (0x6DC360, 0x6FEA38),
    ):
        check_edge(data, site, target, link=False)
    check_words(
        data,
        {
            0x4B8338: 0x200E0000,
            0x4B8238: 0xE5900020,
            0x53DCA4: 0x80000040,
            0x53DCB8: 0x02060001,
            0x575EEC: 0xE5801004,
            0xA75BF8: BASE + 0x576044,
            0x576C20: 0xE2841004,
            0x6FE924: 0xE5A45004,
            0x6FE988: 0xE5943004,
            0x6FE998: 0xE590C008,
            0x6FE9A0: 0xE12FFF3C,
            0x576014: 0x05802028,
            0x576028: 0x05801028,
            0x576C74: 0x8A000001,
            0x576C7C: 0x1A000007,
            0x65E178: 0xE58102EC,
            0x65E1A0: 0x058402F0,
            0x657938: 0xE59712EC,
            0x657984: 0xE5971190,
            0x7DB910: 0xE5801008,
            0x82D8A0: 0xE5805018,
            0x82D8E0: 0xE5905018,
        },
    )
    reg("fpexc", 0x40000000)

    def put(address, value, size=4):
        vm.mem_write(address, value.to_bytes(size, "little"))

    controller, recipe, queue = 0x10010000, 0x10020000, 0x10030000
    registry, store, codec, receiver = 0x10060000, 0x10070000, 0x10080000, 0x10081000
    payload, event, request = capture + 0xA850, capture + 8, store + 0x420
    records = (payload + 0x10, payload + 0x40C)
    out_desc = (capture + 0x23C4, capture + 0x23DC)
    mmio = 0x200E0000
    for guard in (0x404099F0, 0x4041D97C):
        put(guard, 1)
    put(registry + 0x58, queue - 8)
    run(0x6DB6A8, end=0x6DB6C4, r4=controller, r5=registry)
    require(
        [get(controller + off) for off in (0x5C, 0xB0)],
        [queue, 0x00800001],
        "native StoreImage controller route",
    )

    run(0x575ED8, receiver + 0x20, end=0x575F14)
    require(get(receiver + 4), BASE + 0xA75BF0, "native secondary receiver table")
    # Run only the post-wait binder suffix with the caller's original pointer roles.
    run(0x6FE924, end=0x6FE934, r4=codec + 0x14, r5=receiver + 4)
    require(get(codec + 0x18), receiver + 4, "native post-wait recipient attachment")
    mmio_reads, mmio_writes, callbacks, length_writes, builds = [], [], [], [], []

    def observe_mmio(_vm, access, address, size, value, _user):
        if access == uc.UC_MEM_READ:
            mmio_reads.append((reg("pc") - BASE, address, size, get(address, size)))
        else:
            mmio_writes.append((reg("pc") - BASE, address, size, value))

    def observe_callback(_vm, pc, _size, _user):
        callbacks.append((pc - BASE, reg("r0"), reg("r1"), reg("r2")))

    def observe_length_write(_vm, _access, address, size, value, _user):
        length_writes.append((reg("pc") - BASE, address - capture, size, value))

    def observe_build(_vm, pc, _size, _user):
        builds.append((pc - BASE, reg("r0"), reg("r1")))

    vm.hook_add(
        uc.UC_HOOK_MEM_READ | uc.UC_HOOK_MEM_WRITE,
        observe_mmio,
        begin=mmio,
        end=mmio + 0x2FFF,
    )
    vm.hook_add(
        uc.UC_HOOK_MEM_WRITE,
        observe_length_write,
        begin=capture + 0x2EC,
        end=capture + 0x2F3,
    )
    for offset in (0x6FE97C, 0x576044, 0x576008):
        vm.hook_add(
            uc.UC_HOOK_CODE, observe_callback, begin=BASE + offset, end=BASE + offset
        )
    for offset in (0x65DC34, 0x65784C, 0x5AA3B0, 0x5A8790, 0x5A820C):
        vm.hook_add(
            uc.UC_HOOK_CODE, observe_build, begin=BASE + offset, end=BASE + offset
        )

    def codec_completion(counter, *, selector=0x80000040, status=1, enabled=True):
        put(mmio + 0x20, counter)
        put(receiver + 0x28, 0xDEADBEEF)
        for off in (0x1000, 0x2000, 0x2040):
            put(mmio + off, 0xFFFFFFFF)
        mmio_reads.clear()
        mmio_writes.clear()
        callbacks.clear()
        run(
            0x53D51C,
            end=0x576030 if enabled else 0x53D578,
            r4=codec,
            r5=selector,
            r6=status,
        )
        if not enabled:
            require(
                mmio_reads + mmio_writes,
                [],
                "disabled codec completion does not touch codec MMIO",
            )
            require(callbacks, [], "disabled codec completion does not call receiver")
            require(
                get(receiver + 0x28),
                0xDEADBEEF,
                "disabled codec completion leaves receiver untouched",
            )
            return
        require(
            mmio_reads,
            [
                (0x4B8238, mmio + 0x20, 4, counter),
                (0x4B7A24, mmio + 0x1000, 4, 0xFFFFFFFF),
                (0x4B7ABC, mmio + 0x2000, 4, 0xFFFFFFFF),
                (0x4B7D38, mmio + 0x2040, 4, 0xFFFFFFFF),
            ],
            "original codec reads count and three control words",
        )
        require(
            mmio_writes,
            [
                (0x4B7A34, mmio + 0x1000, 4, 0x10),
                (0x4B7AD0, mmio + 0x2000, 4, 0x373F0),
                (0x4B7D4C, mmio + 0x2040, 4, 0x03770110),
            ],
            "native completion updates three synthetic control registers",
        )
        require(
            callbacks,
            [
                (0x6FE97C, codec + 0x14, 0x02060001, counter),
                (0x576044, receiver + 4, 0x02060001, counter),
                (0x576008, receiver, 0x02060001, counter),
            ],
            "native synchronous codec completion callback",
        )
        require(
            get(receiver + 0x28),
            counter,
            "native receiver saves the original completion count",
        )

    def store_descriptor(count, out):
        run(0x576C4C, end=0x576C58, r4=receiver, sb=out)
        require(get(out + 0xC), count, "native encoder output descriptor")
        return get(out + 0xC)

    gated = []
    for selector, status in ((0x80000041, 1), (0x80000040, 0), (0x80000040, 2)):
        codec_completion(0x1234, selector=selector, status=status, enabled=False)
        gated.append(
            {
                "selector": selector,
                "status": status,
                "mmio_reads": len(mmio_reads),
                "mmio_writes": len(mmio_writes),
                "callbacks": len(callbacks),
                "receiver_count": get(receiver + 0x28),
                "end_exclusive": 0x53D578,
            }
        )

    count_guards = []
    for count, limit, accepted in (
        (0, 0x1000, False),
        (0x1000, 0x1000, True),
        (0x1001, 0x1000, False),
    ):
        put(out_desc[0] + 8, limit)
        codec_completion(count)
        observed = store_descriptor(count, out_desc[0])
        end = 0x576CA0 if accepted else 0x576C80
        run(0x576C60, end=end, r4=receiver, sb=out_desc[0])
        count_guards.append(
            {
                "injected_count": count,
                "limit": limit,
                "descriptor_count": observed,
                "accepted": accepted,
                "end_exclusive": end,
            }
        )
    put(receiver + 0x28, 0x1234)
    callbacks.clear()
    run(0x6FE97C, codec + 0x14, 0x02060002, 0x1234, end=0x576030)
    require(
        callbacks,
        [
            (0x6FE97C, codec + 0x14, 0x02060002, 0x1234),
            (0x576044, receiver + 4, 0x02060002, 0x1234),
            (0x576008, receiver, 0x02060002, 0x1234),
        ],
        "prepared cancel event through native codec dispatcher",
    )
    cancel_receiver_count = get(receiver + 0x28)
    require(cancel_receiver_count, 0, "native cancel clears receiver count")

    cases = []
    for split, counts in ((True, (0x1234, 0x1000)), (False, (0x1579,))):
        vm.mem_write(capture, bytes(0x16470))
        vm.mem_write(store, bytes(0x1000))
        put(capture, BASE + 0xA684E0)
        run(0x653BAC, payload, end=0x5AA434)
        run(0x653D74, end=0x653DC8, r4=capture)
        require(
            [get(capture + off) for off in (0xC2C4, 0xC2C8)],
            list(records),
            "same embedded record pointers",
        )
        run(0x6554F4, end=0x655554, r4=capture)
        put(capture + 0x6B, int(split), 1)
        put(capture + 0x20B4, 1, 1)
        for off in (0x3E, 0x3F, 0x207C, 0x207D):
            put(capture + off, 1, 1)
        for off, cap in ((0x2E4, 0x2000), (0x2E8, 0x1000)):
            put(capture + off, cap)
        for off in (0x2EC, 0x2F0):
            put(capture + off, 0xA5A5A5A5)

        run(0x660808, end=0x660844, r4=capture, r3=0x11000003, r0=0)
        destinations = [get(capture + off) for off in (0x190, 0x194)]
        require(
            destinations,
            [0x11000010, 0x11002010 if split else 0x11000010],
            "native split or shared destinations",
        )
        run(0x660844, end=0x6608B0, r4=capture)
        run(0x6593B0, capture, 16)
        require(
            [get(capture + 0xA81C + off) for off in (0x14, 0x18)],
            list(out_desc),
            "original encoder payload points at native output descriptors",
        )
        require(
            [get(addr + 0xC) for addr in out_desc],
            [0, 0],
            "original native output length initializers",
        )

        completions = []
        for index, counter in enumerate(counts):
            pixels = capture + 0x21B0 + 0x1C * index
            planes = tuple(
                address + 0x1000 * index
                for address in (0x12000007, 0x13000000, 0x1400000F)
            )
            for off, address in zip((4, 8, 0xC), planes):
                put(pixels + off, address)
            run(0x576AF8, end=0x576B50, r8=pixels, sb=out_desc[index])
            descriptor = stack + 8
            require(
                get(descriptor + 0xC),
                destinations[index],
                "original codec descriptor output pointer",
            )
            run(0x53D880, end=0x53D8F0, r4=codec, sb=descriptor)
            mmio_addresses = tuple(
                get(mmio + off) for off in (0x2028, 0x202C, 0x2030, 0x2050)
            )
            require(
                mmio_addresses,
                tuple(address & ~15 for address in (*planes, destinations[index])),
                "native synthetic MMIO plane and destination values",
            )
            codec_completion(counter)
            observed = store_descriptor(counter, out_desc[index])
            run(0x576C60, end=0x576CA0, r4=receiver, sb=out_desc[index])
            completions.append(
                {
                    "stream": index,
                    "synthetic_count": counter,
                    "native_callback_args": list(callbacks),
                    "completion_mmio_reads": list(mmio_reads),
                    "completion_mmio_writes": list(mmio_writes),
                    "programmed_mmio_addresses": mmio_addresses,
                    "descriptor_count": observed,
                }
            )

        completed_lengths = list(counts) if split else [counts[0], counts[0]]
        require(
            [get(addr + 0xC) for addr in out_desc],
            list(counts) if split else [counts[0], 0],
            "per-stream descriptor count before completion",
        )
        # Native completion dispatch obtains module 16 from its command code.
        length_writes.clear()
        builds.clear()
        run(0x6DBA14, end=0x6DBDBC, r4=capture, r6=0x03000002)
        require(
            builds, [(0x65DC34, capture, 16)], "native module 16 completion dispatch"
        )
        observed_lengths = [get(capture + off) for off in (0x2EC, 0x2F0)]
        require(
            observed_lengths, completed_lengths, "native capture completion lengths"
        )
        expected_writes = [
            (0x65E178, 0x2EC, 4, counts[0]),
            (0x65E178, 0x2F0, 4, counts[1] if split else 0),
        ]
        if not split:
            expected_writes.append((0x65E1A0, 0x2F0, 4, counts[0]))
        require(
            length_writes,
            expected_writes,
            "native capture completion length write order",
        )

        put(capture + 0x34, recipe)
        put(capture + 0x38, 7)
        put(recipe + 0x10E, 9, 2)
        builds.clear()
        run(0x6DC2D0, controller, capture, 0, end=0x6FEA38)
        require(
            tuple(reg(name) for name in ("r0", "r1", "r2")),
            (queue, event, 2),
            "native StoreImage queue entry",
        )
        require(
            [get(event + off) for off in (4, 8, 0xC, 0x10)],
            [controller + 4, payload, 0x00800001, capture],
            "native StoreImage event payload",
        )
        require(
            builds,
            [
                (0x65784C, capture, 0),
                (0x5AA3B0, records[0], 0),
                (0x65784C, capture, 1),
                (0x5AA3B0, records[1], 1),
            ],
            "same constructed pair",
        )
        require(
            list(vm.mem_read(payload, 6)),
            [1, 1, 0, 0, 0, 0],
            "two main records available",
        )

        put(stack, event)
        builds.clear()
        run(0x5A97D0, end=0x5A8848, r5=store)
        require(
            builds,
            [(0x5A8790, store, payload)],
            "same event delivered to native StoreImage selector",
        )
        require(reg("r0"), records[0], "native first record selection")

        requests = []
        for index, record in enumerate(records):
            put(stack + 0x30, get(event + 8))
            vm.mem_write(request + 0x18, bytes([0xA5]) * 16)
            builds.clear()
            run(0x5A88AC, end=0x5A8340, r4=store, r5=index)
            require(
                builds,
                [(0x5A820C, store, record)],
                "native caller reselects same indexed record",
            )
            require(get(store + 0x82, 1), index, "native StoreImage index")
            slots = [run(0x82D8B8, request, i) for i in range(4)]
            require(
                slots,
                [record + off for off in (0x9C, 0x50, 4, 0xE8)],
                "native descriptor aliases",
            )
            destination = run(0x81C110, slots[2])
            size = run(0x834340, slots[2])
            require(
                (destination, size),
                (destinations[index], completed_lengths[index]),
                "original completion count reaches same indexed request",
            )
            requests.append(
                {
                    "index": index,
                    "record_offset": record - capture,
                    "descriptor_offset": slots[2] - capture,
                    "address": destination,
                    "length": size,
                }
            )
        cases.append(
            {
                "split_destinations": split,
                "injected_codec_counts": list(counts),
                "codec_completions": completions,
                "capture_lengths": observed_lengths,
                "native_length_writes": list(length_writes),
                "store_event": get(event + 0xC),
                "requests": requests,
            }
        )

    return {
        "decoded_sha256": sha256(data),
        "code_va_base": BASE,
        "unicorn_version": uc.__version__,
        "execution_replacements": [],
        "codec_gate_cases": gated,
        "count_boundary_cases": count_guards,
        "cancel_receiver_count": cancel_receiver_count,
        "connected_cases": cases,
        "boundaries": {
            "embedded_constructor_prefix": [0x653BAC, 0x5AA434],
            "embedded_pointer_stores": [0x653D74, 0x653DC8],
            "embedded_reset_loop": [0x6554F4, 0x655554],
            "module9_binding": [0x6DB6A8, 0x6DB6C4],
            "destination_setup": [0x660808, 0x660844],
            "output_descriptor_setup": [0x660844, 0x6608B0],
            "module16_binding_entry": 0x6593B0,
            "codec_descriptor": [0x576AF8, 0x576B50],
            "codec_mmio_addresses": [0x53D880, 0x53D8F0],
            "receiver_constructor_suffix": [0x575ED8, 0x575F14],
            "recipient_bind_post_wait": [0x6FE924, 0x6FE934],
            "codec_callback_before_wake": [0x53D51C, 0x576030],
            "descriptor_length": [0x576C4C, 0x576C58],
            "count_guard_entry": 0x576C60,
            "prepared_cancel_before_wake": [0x6FE97C, 0x576030],
            "leaf_return_sentinel_va": stop,
            "controller_completion": [0x6DBA14, 0x6DBDBC],
            "store_queue_entry": [0x6DC2D0, 0x6FEA38],
            "store_receiver": [0x5A97D0, 0x5A8848],
            "store_request": [0x5A88AC, 0x5A8340],
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    data = load_image(args.decoded)
    result = {
        "schema_version": 1,
        "firmware_version": "1.12",
        "decoded_sha256": sha256(data),
        "engine": f"Unicorn {uc.__version__}",
        "record_handoff": emulate_records(data),
        "jpeg_completion_bridge": emulate_jpeg_completion(data),
        "limits": [
            "All capture objects, flags, buffer-address values and device registers are synthetic. Pixel/bitstream buffers are not dereferenced.",
            "The six embedded records use original constructor-prefix and pointer-store code. The complete outer/container constructors and allocation are not executed.",
            "JPEG completion uses a prepared callback binding and original synchronous dispatch up to the receiver wake boundary. Registration locking, wake and scheduling are not executed.",
            "Encoder descriptor storage resumes at576C4C after an unexecuted wait; cleanup576C58 is skipped and controller command03000002 is prepared at6DBA14.",
            "StoreImage queue entry is end-exclusive. The same event is supplied to bounded receive code, and request callers use separately prepared stack frames.",
            "Completion lengths pass through original native stores; MMIO counters remain injected inputs, not measured encoder results.",
            "Real capture, sensor/CPP/scaler/encoder hardware, request validation, write-service and SD output are not executed.",
        ],
    }
    if args.compare:
        require_snapshot(result, args.compare, "StoreImage records replay")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
