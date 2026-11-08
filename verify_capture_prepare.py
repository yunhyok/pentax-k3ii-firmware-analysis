"""Replay native K-3 II preparation calls through pixel policy.

SPDX-License-Identifier: GPL-2.0-only
"""

import argparse
from pathlib import Path
import json
from struct import unpack_from

from verify_findings import require, require_snapshot, u32, sha256
from verify_pixel_policy import cell
from verify_tone_path import BASE, check_edge, check_words, load_image


def emulate(data):
    import unicorn as uc
    from unicorn import arm_const as arm

    vm = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    for address, size in (
        (BASE, 0x1000000),
        (0x40400000, 0x100000),
        (0x40100000, 0x10000),
        (0x10000000, 0x100000),
        (0x80000000, 0x20000),
    ):
        vm.mem_map(address, size)
    vm.mem_write(BASE, data[:0x1000000])
    manager, capture, config, tags = 0x10010000, 0x10040000, 0x10076000, 0x10078000
    stack, stop, owner, debug = 0x100F0000, 0x100F1000, 0x4040B0EC, 0x4045859C

    def get(address, size=4):
        return int.from_bytes(vm.mem_read(address, size), "little")

    def put(address, value, size=4):
        vm.mem_write(address, value.to_bytes(size, "little"))

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

    reg("fpexc", 0x40000000)
    run(0x6E80BC, manager)
    put(owner + 4, manager)
    for guard in (0x4040AE64, 0x4040A654, 0x4040B7A4, 0x404099F0, 0x4041D890):
        put(guard, 1)
    run(0x4FAE38, 0x4047B100)
    require(get(0x4047B104), 0, "original lookup singleton default")
    put(0x4047D108 + 0x3C, config)
    for i in range(6):
        put(config + 0x18 + 16 * i, 100 + i)
        put(config + 0x20 + 16 * i, 200 + i)
    for i in range(4):
        put(0x4041F364 + i * 2, 0x2000 + i, 2)

    check_words(
        data,
        {
            0x65537C: 0x1A00001F,
            0x6553DC: 0xE12FFF31,
            0x65E5DC: 0xE5C4005F,
            0x65FE8C: 0xE1C50BB8,
            0x65ED90: 0xE5C40052,
            0x65EF78: 0x12400008,
            0x65F194: 0xE5849240,
            0x65E6AC: 0xE5C4003C,
            0x65E710: 0x15C4A03C,
            0x65E724: 0x15C4903C,
            0x739AF0: BASE + 0x9E6202,
            0x65FD7C: BASE + 0x9E651C,
            0x4FB0D8: 0x4040A654,
            0x4FB0DC: 0x4047B100,
        },
    )
    for site, target in (
        (0x65FEA0, 0x82E6F4),
        (0x65ED8C, 0x658B88),
        (0x65EF84, 0x4FAE6C),
        (0x65EF88, 0x72D894),
        (0x65EFCC, 0x4EBD70),
        (0x65E6EC, 0x739A38),
        (0x65E7E8, 0x6E7E9C),
        (0x65E7F4, 0x73EA94),
    ):
        check_edge(data, site, target)
    for base, key, fields in (
        (0x9DE7F8, 0, (0, 0xFF, 0)),
        (0x9DE7F8, 0x2F, (0x12, 2, 1)),
        (0x9DEA90, 4, (0x10, 0xFF, 0)),
        (0x9DEA90, 6, (0x12, 0xFF, 0)),
        (0x9DEA90, 0x22, (0x23, 8, 3)),
    ):
        require(
            unpack_from("<IBB", data, base + 8 * key), fields, "native descriptor field"
        )
    targets = (
        0x65E5A8,
        0x65FE58,
        0x65ED80,
        0x65EED0,
        0x65ED98,
        0x65E5E4,
        0x6601B8,
        0x65E7B0,
        0x65EA68,
    )
    calls = (
        0x655350,
        0x655360,
        0x655370,
        0x65538C,
        0x65539C,
        0x6553AC,
        0x6553BC,
        0x6553CC,
        0x6553DC,
    )
    for call, slot, target in zip(
        calls, (0x1C, 0x70, 0x30, 0x38, 0x34, 0x20, 0x7C, 0x24, 0x28), targets
    ):
        require(u32(data, call - 8), 0xE5901000 | slot, "original vtable load")
        require(u32(data, call), 0xE12FFF31, "original indirect call")
        require(u32(data, 0xA684E0 + slot), BASE + target, "actual prepare vtable slot")

    path, thresholds, selector, force = [], [], [], []

    def observe(_vm, pc, _size, _user):
        entry = pc - BASE
        if entry in targets:
            require(reg("r0"), capture, "same native capture argument")
            path.append(entry)
        elif entry == 0x739A38:
            thresholds.append([reg("r1"), reg("r2"), reg("r3"), get(reg("sp"))])
        elif entry == 0x5A0EF0:
            selector.append([reg("r1"), reg("r2"), reg("r3")])
        else:
            force.append(entry)

    for entry in (*targets, 0x739A38, 0x5A0EF0, 0x5A1054):
        vm.hook_add(uc.UC_HOOK_CODE, observe, begin=BASE + entry, end=BASE + entry)

    def prepare_inputs(
        *,
        key0=0,
        key2f=0,
        key22=0,
        debug66=0,
        b=0x7C,
        key6=0x20,
        c=0,
        tag95=0,
        debug25=0,
        debug26=0,
        tagf5=0,
        word20b6=0,
        provider8=0,
        provider62=False,
    ):
        vm.mem_write(capture, bytes(0x18000))
        vm.mem_write(debug, bytes(0xC0))
        vm.mem_write(tags, bytes(0x200))
        put(capture, BASE + 0xA684E0)
        run(0x6EBF5C, capture + 0x30C)
        run(0x6EAD78, capture + 0x334)
        require(get(capture + 0x30C), BASE + 0xA78008, "root reader vtable")
        require(get(capture + 0x334), BASE + 0xA77CAC, "child reader vtable")
        put(capture + 0x1A40, tags)
        put(capture + 0x310, key0, 1)
        put(capture + 0x322, 0xA5 | (key2f << 1), 1)
        put(capture + 0x35B, 0xA5 | (key22 << 3), 1)
        put(capture + 0x348, b, 1)
        put(capture + 0x34A, key6, 1)
        put(capture + 0x209A, c & 0xFFFF, 2)
        put(capture + 0x15ED, tag95, 1)
        put(capture + 0x164D, tagf5, 1)
        put(capture + 0x20B6, word20b6, 2)
        put(0x4041F420, 0xA55A5AA5 if provider8 else 0)
        put(0x4041F424, provider8, 2)
        put(0x40106980, 0xA55A5AA5 if provider62 else 0)
        for offset, val in (
            (0x14, 0x1000),
            (0x18, 0x2000),
            (0x1C, 0x3000),
            (0x20, 0x4000),
            (0x24, 0x12),
            (0x28, 0x34),
            (0x30, 700),
        ):
            put(0x40106980 + offset, val)
        put(capture + 0x1649, 0x12, 1)
        put(capture + 0x164A, 0x34, 1)
        for offset, value in (
            (4, bool(debug66 or debug25 or debug26)),
            (0x29, debug66),
            (0x1A, debug25),
            (0x98, debug26),
        ):
            put(debug + offset, int(value), 1)
        path.clear()
        thresholds.clear()
        selector.clear()
        force.clear()

    prefix_cases = []
    for key0, key2f, key22, debug66, kind in (
        *((0, 0, 0, 0, kind) for kind in range(12)),
        (8, 1, 0, 0, 0),
        (9, 0, 1, 0, 6),
        (0xA, 1, 1, 0, 0),
        (0xC, 1, 1, 1, 6),
        (0xD, 0, 1, 0, 6),
        (0, 0, 1, 1, 0),
        (0, 0, 1, 0, 0),
        (9, 1, 1, 0, 5),
        (0xC, 1, 1, 0, 11),
    ):
        prepare_inputs(key0=key0, key2f=key2f, key22=key22, debug66=debug66)
        end = 0x655400 if kind in (5, 7, 8, 11) else 0x655380
        run(0x6552B0, capture, kind, end=end)
        require(path, list(targets[:3]), "three native calls before kind gate")
        require(
            [get(capture + off, 1) for off in (0x2080, 0x2081, 0x2082)],
            [int(kind in (5, 7, 8, 11)), int(kind in (7, 8)), int(kind == 11)],
            "native prepare kind flags",
        )
        actual = [
            get(capture + off, size)
            for off, size in ((0x5F, 1), (0x4F, 1), (0x20B8, 2), (0x52, 1), (0x2084, 1))
        ]
        require(
            actual,
            [
                int(key0 in (9, 12)),
                key2f,
                0x1234 if key2f else 0,
                key22 & (not debug66),
                kind,
            ],
            "native producer fields",
        )
        prefix_cases.append(
            {
                "inputs": [key0, key2f, key22, debug66, kind],
                "outputs": actual,
                "end_file_offset": end,
            }
        )

    full_cases = []
    for kind, kwargs, expected_a, expected_3c, expected_flags in (
        (0, {}, 0x2000, 0, [1, 1, 0, 0]),
        (6, {}, 0x2000, 0, [0, 0, 0, 0]),
        (0, {"b": 0, "key6": 0x30, "tag95": 1}, 0x8000, 0, [1, 1, 1, 1]),
        (6, {"b": 0, "key6": 0x30, "tag95": 1}, 0x8000, 0, [0, 0, 0, 1]),
        (0, {"b": 0x44}, 0x2000, 1, [1, 1, 1, 1]),
        (0, {"b": 0x45}, 0x2000, 0, [1, 1, 0, 0]),
        (0, {"b": 0x24, "tag95": 2, "c": 599}, 0x2000, 0, None),
        (0, {"b": 0x24, "tag95": 2, "c": 600}, 0x2000, 1, [1, 1, 1, 1]),
        (0, {"tag95": 1, "debug25": 1}, 0x2000, 1, [1, 1, 1, 1]),
        (0, {"tag95": 1, "debug25": 1, "debug26": 1}, 0x2000, 0, [1, 1, 0, 0]),
        (0, {"key0": 9, "tag95": 1}, 0x2000, 0, [1, 1, 1, 1]),
        (6, {"key0": 12, "tag95": 1}, 0x2000, 0, [0, 0, 0, 1]),
        (0, {"key2f": 1, "tagf5": 1, "word20b6": 1}, 0x2000, 0, [1, 1, 0, 0]),
        (0, {"key2f": 1, "tagf5": 1, "word20b6": 2}, 0x2000, 0, [1, 1, 1, 1]),
        (0, {"key22": 1, "key6": 0x38}, 0x8000, 0, [1, 1, 0, 0]),
        (0, {"key22": 1, "debug66": 1, "key6": 0x38}, 0x10000, 0, [1, 1, 0, 0]),
        (0, {"provider8": 0x4000, "key6": 0x30}, 0x10000, 0, [1, 1, 0, 0]),
        (0, {"provider62": True}, 0x2000, 0, [1, 1, 0, 0]),
        (0, {"provider62": True, "key0": 9, "tag95": 1}, 0x2000, 0, [1, 1, 1, 1]),
        (0, {"b": 0x44, "tag95": 2, "c": 32767}, 0x2000, 0, None),
        (0, {"b": 0x44, "tag95": 2, "c": -32768, "key0": 9}, 0x2000, 1, [1, 1, 1, 1]),
    ):
        prepare_inputs(**kwargs)
        run(0x6552B0, capture, kind, end=0x6553E0)
        require(path, list(targets), "all nine original prepare calls through policy")
        require(get(capture + 0x240), expected_a, "native A producer")
        require(get(capture + 0x3C, 1), expected_3c, "native CAP +0x3c producer")
        mode95 = kwargs.get("tag95", 0)
        require(
            [get(capture + off, 1) for off in (0x60, 0x61)],
            [int(mode95 == 0), int(mode95 == 2)],
            "native tag95 side flags",
        )
        b, c = kwargs.get("b", 0x7C), int(kwargs.get("c", 0) / 10)
        flag5f = int(kwargs.get("key0", 0) in (9, 12))
        flag4f = kwargs.get("key2f", 0)
        flag52 = kwargs.get("key22", 0) and not kwargs.get("debug66", 0)
        early = [
            get(capture + off, size)
            for off, size in ((0x5F, 1), (0x4F, 1), (0x20B8, 2), (0x52, 1), (0x2084, 1))
        ]
        require(
            early,
            [flag5f, flag4f, 0x1234 if flag4f else 0, flag52, kind],
            "early fields preserved through native policy",
        )
        is_forced = bool(
            expected_3c
            or flag5f
            or (flag4f and kwargs.get("tagf5") == 1 and kwargs.get("word20b6", 0) >= 2)
        )
        result = 4 if is_forced else unpack_from("<H", data, cell(expected_a, b, c))[0]
        require(
            selector,
            [] if is_forced else [[expected_a, b, c & 0xFFFFFFFF]],
            "policy consumes native A",
        )
        require(
            force,
            [0x5A1054] if is_forced else [],
            "policy force follows earlier native fields",
        )
        if mode95 == 2:
            require(
                thresholds[-1],
                [expected_a, b, c & 0xFFFFFFFF, flag5f],
                "tag95 threshold receives native arguments",
            )
        tags_62 = [
            get(tags + index * 2, 2)
            for index in (0x31, 0x32, 0x33, 0x34, 0x35, 0x4E, 0x4F)
        ]
        require(
            tags_62,
            [0x12, 5, 10, 15, 20, 0x34, 7] if kwargs.get("provider62") else [0] * 7,
            "native provider62 short and valid paths",
        )
        flag3d = int(bool(kwargs.get("provider62") and flag5f))
        require(get(capture + 0x3D, 1), flag3d, "native fixed-mirror dependent flag")
        require(get(tags + 0x82, 2), result, "native policy result tag")
        flags = [get(capture + off, 1) for off in range(0x47, 0x4B)]
        if expected_flags is None:
            expected_flags = [1, 1, int(result == 4), int(result == 4)]
        require(flags, expected_flags, "native policy outputs")
        full_cases.append(
            {
                "job_kind": kind,
                "inputs": kwargs,
                "A": expected_a,
                "CAP_3c": expected_3c,
                "CAP_3d": flag3d,
                "policy_result": result,
                "policy_flags": flags,
                "threshold_call_arguments": thresholds.copy(),
                "early_fields": early,
                "forced": is_forced,
                "provider62_tags": tags_62,
            }
        )

    put(0x4040B9A4, 1)
    run(0x4D5F28, 0x4047DA40)
    put(0x4041D51C, 0x10080000)
    put(0x10080000 + 4 * 12, 0x10081000)
    slots = (
        0x1C,
        0x70,
        0x30,
        0x38,
        0x34,
        0x20,
        0x7C,
        0x24,
        0x28,
        0x3C,
        0x2C,
        0x40,
        0x44,
        0x48,
        0x4C,
        0x54,
        0x58,
        0x5C,
        0x60,
        0x50,
        0x64,
        0x74,
        0x68,
        0x6C,
        0x78,
    )
    tail_targets = [u32(data, 0xA684E0 + slot) - BASE for slot in slots]
    for offset in tail_targets[9:] + [0x654EBC, 0x654EB8]:
        vm.hook_add(
            uc.UC_HOOK_CODE,
            lambda _vm, pc, _size, _user: path.append(pc - BASE),
            begin=BASE + offset,
            end=BASE + offset,
        )
    require(u32(data, 0x65557C), 0xEAFFFE4D, "native final tail")
    require(u32(data, 0x654EB8), 0xE12FFF1E, "native return")
    put(0x10081000, 1, 1)
    buffer = 0x10088000
    writes, metadata_writes = [], []

    def observe_metadata(_vm, _access, address, size, value, _user):
        if reg("pc") - BASE in (0x75451C, 0x754510):
            metadata_writes.append([address - capture, size, value])

    vm.hook_add(uc.UC_HOOK_MEM_WRITE, observe_metadata)
    for address, size in ((capture + 0x13C, 4), (buffer, 512)):
        vm.hook_add(
            uc.UC_HOOK_MEM_WRITE,
            lambda _vm, _access, address, size, _value, _user: writes.append(
                (address, size)
            ),
            begin=address,
            end=address + size - 1,
        )
    image_canary = bytes(range(256)) * 2
    metadata_slots = (0xC2C4, 0xC2C8, 0xC2CC, 0xC2D0, 0xC2D4, 0xC2D8)
    record_offsets = (0xA860, 0xAC5C, 0xB058, 0xB454, 0xB850, 0xBC4C)
    element_entries = []
    vm.hook_add(
        uc.UC_HOOK_CODE,
        lambda _vm, _pc, _size, _user: element_entries.append(reg("r0") - capture),
        begin=BASE + 0x73DD60,
        end=BASE + 0x73DD60,
    )
    for site, target in (
        (0x653BAC, 0x5AA3DC),
        (0x653D8C, 0x72D808),
        (0x653DA4, 0x72D7F4),
        (0x653DB4, 0x72D818),
    ):
        check_edge(data, site, target)
    returned_cases = []
    for kind in (0, 6, 11):
        prepare_inputs(b=0, key6=0x30, tag95=1)
        run(0x6EB764, capture + 0x368)
        run(0x654218, capture, 1, buffer, 1)
        require(get(capture + 0x98), buffer, "native slot 1 owner")
        require(get(capture + 0x13C), buffer, "native slot 1 direct image alias")
        if kind == 11:
            vm.mem_write(capture + 0x47, bytes([0xA1, 0xB2, 0xC3, 0xD4]))
        put(capture + 0x160, buffer + 0x1000)
        put(capture + 0x204, buffer + 0x2000)
        element_entries.clear()
        run(0x653BAC, capture + 0xA850, end=0x5AA434)
        require(
            element_entries, list(record_offsets), "six original embedded constructors"
        )
        run(0x653D74, end=0x653DC8, r4=capture)
        require(
            [get(capture + off) - capture for off in metadata_slots],
            list(record_offsets),
            "native six interior pointer stores",
        )
        records_before = []
        for i, off in enumerate(record_offsets):
            addr = capture + off
            require(get(addr + 0x3F0), 0, "original metadata constructor defaults")
            run(0x754518, addr, 0x1234 + i)
            run(0x75450C, addr, 0x5678 + i)
            vm.mem_write(addr + 0x3EE, bytes([0xA0 + i, 0xB0 + i]))
            vm.mem_write(addr + 0x3F4, bytes([0xC0 + i, 0xD0 + i]))
            vm.mem_write(addr + 0x3FA, bytes([0xE0 + i, 0xF0 + i]))
            records_before.append(bytes(vm.mem_read(addr, 0x3FC)))
        vm.mem_write(buffer, image_canary)
        writes.clear()
        metadata_writes.clear()
        require(run(0x6552B0, capture, kind), capture, "original prepare return value")
        require(
            writes, [], "no writes to image pointer or synthetic image during prepare"
        )
        require(bytes(vm.mem_read(buffer, 512)), image_canary, "complete image canary")
        require(reg("sp"), stack, "original stack restored")
        expected_path = (
            tail_targets if kind != 11 else tail_targets[:3] + tail_targets[11:-1]
        )
        require(
            path,
            expected_path + [0x654EBC, 0x654EB8],
            "actual prepare call order through return",
        )
        flags = [get(capture + off, 1) for off in (0x47, 0x48, 0x49, 0x4A)]
        require(
            flags,
            {0: [1, 1, 1, 1], 6: [0, 0, 0, 1], 11: [0xA1, 0xB2, 0xC3, 0xD4]}[kind],
            "pixel flags through return",
        )
        require(
            get(capture + 0x20B4, 1),
            0x40 if kind == 11 else 1,
            "native mask through return",
        )
        require(
            [get(capture + off, 1) for off in (0x5A, 0x8E)],
            [1, 1],
            "native selector table row flag",
        )
        require(
            [get(capture + off) for off in (0x98, 0x13C, 0x160, 0x204)],
            [buffer, buffer, buffer + 0x1000, buffer + 0x2000],
            "buffer addresses through return",
        )
        for off, before in zip(record_offsets, records_before):
            after = bytes(vm.mem_read(capture + off, 0x3FC))
            require(
                after,
                before[:0x3F0] + bytes(4) + before[0x3F4:],
                "entire original embedded record through prepare",
            )
        require(
            [get(capture + off) - capture for off in metadata_slots],
            list(record_offsets),
            "native interior pointers retained through prepare",
        )
        require(
            metadata_writes,
            [
                [record_offsets[i] + off, 2, 0]
                for i in (0, 2, 4, 1, 3, 5)
                for off in (0x3F0, 0x3F2)
            ],
            "native metadata writes in order",
        )
        returned_cases.append(
            {
                "job_kind": kind,
                "call_path": path.copy(),
                "returned": capture,
                "pixel_flags": flags,
                "mask": get(capture + 0x20B4, 1),
                "observed_image_or_0x13c_writes": len(writes),
                "metadata_writes_relative_to_capture": metadata_writes.copy(),
                "initial_pixel_flags": (
                    [0xA1, 0xB2, 0xC3, 0xD4] if kind == 11 else [0, 0, 0, 0]
                ),
                "unchanged_capture_pointer_offsets": [0x98, 0x13C, 0x160, 0x204],
            }
        )
    return {
        "unicorn_version": uc.__version__,
        "virtual_calls": [
            {"call_file_offset": call, "slot": slot, "target_file_offset": target}
            for call, slot, target in zip(
                calls, (0x1C, 0x70, 0x30, 0x38, 0x34, 0x20, 0x7C, 0x24, 0x28), targets
            )
        ],
        "stop_file_offset": 0x6553E0,
        "whole_prepare": {
            "slots_in_order": slots,
            "targets_in_order": tail_targets,
            "caller_return_sentinel_va": stop,
            "returned_cases": returned_cases,
            "metadata_pointer_offsets": [
                0xC2C4,
                0xC2C8,
                0xC2CC,
                0xC2D0,
                0xC2D4,
                0xC2D8,
            ],
            "metadata_record_offsets": record_offsets,
            "container_constructor_slice": {
                "entry_file_offset": 0x653BAC,
                "stop_before_file_offset": 0x5AA434,
            },
            "pointer_publication_slice": [0x653D74, 0x653DC8],
            "metadata_constructor_entry_offsets": element_entries,
            "metadata_objects_checked_bytes": 0x3FC,
            "only_changed_metadata_offsets": [0x3F0, 0x3F1, 0x3F2, 0x3F3],
            "image_canary_sha256": sha256(image_canary),
        },
        "prefix_cases": prefix_cases,
        "complete_cases": full_cases,
        "execution_replacements": [],
        "ordered_file_offsets": list(targets),
        "threshold_table_sha256": sha256(data[0x9E6202:0x9E6242]),
        "prepare_prefix_sha256": sha256(data[0x6552B0:0x6553E0]),
    }


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
        "replay": emulate(data),
        "scope": [
            "The original manager, lookup singleton and two nested reader constructors execute in prefix controls; full-return controls also execute the third nested reader and a second singleton constructor. Capture vtable, initialization guards, configuration slots, settings, markers, fixed RAM mirrors and debug bytes are prepared. The complete capture constructor and whole startup are not executed.",
            "Twenty-one prefix controls execute the first three calls and the original job-kind branch. Kinds5/7/8/11 stop at the alternate boundary655400; other tested kinds stop at655380. The second set contains twenty-one independent executions from6552B0 through the ninth virtual call and native policy return, stopping at6553E0 before the remaining preparation calls. Prepare itself has not returned at this prefix stop; three separate controls then execute prepare through its actual return.",
            "The code hook only observes entries and arguments; no execution is replaced. Native stores create A at capture+240 and flags3C/5F/4F/52, which the policy consumes in the same execution. Child B, signed C and other inputs are synthetic; physical units and actual menu selection remain unestablished.",
            "ID8/9/62 registry lookups execute on an empty manager. Their following getters return fixed RAM addresses independently of the lookup result. A valid ID62-associated mirror is tested only on B>=7C; the low-B valid-marker floating-point path is outside scope.",
            "Three separate full-return controls add a prepared pointer table row and a singleton initialized guard. The original constructor call653BAC is stopped inside5AA3DC at5AA434 after the six73DD60 element constructors; later container sibling initialization is omitted. Separate original pointer publication slice653D74..653DC8 binds the six embedded3FC-byte records; no six independent allocations or supplied record pointers. Native setters seed two halfwords and neighboring bytes are canaries before prepare. Whole capture construction and its outer allocation remain outside scope. They execute65557C then654EB8 BX LR to the caller sentinel, with R0 and SP checked. The slot1 direct-alias setter produces98/13C;160/204 are prepared. Kind11 starts with nonzero A1/B2/C3/D4 pixel-flag canaries and retains them; the fixture does not claim original flag clearing. Whole capture construction, allocation, subsequent scheduling, image processing, live sensor data, JPEG output and physical capture are not executed.",
        ],
    }
    if args.compare:
        require_snapshot(result, args.compare, "snapshot replay")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
