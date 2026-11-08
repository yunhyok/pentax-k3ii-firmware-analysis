"""Replay bounded command callers and ID63 packet dispatch with explicit runtime gaps.

SPDX-License-Identifier: GPL-2.0-only
"""

from pathlib import Path
from struct import pack, unpack
import json
import argparse
from hashlib import shake_256
import unicorn as uc
from unicorn import arm_const as arm

from verify_preserved_config import (
    BACKUP,
    CAPACITY,
    GROUPS,
    MANAGER_OWNER,
    MARKER,
    PROVIDERS,
    RAM,
    SERVICE_OWNER,
)
from verify_findings import require, require_snapshot, sha256
from verify_tone_path import BASE, check_edge, check_words, load_image


PLAN = (
    ((0, 1, 0), (2, 3, 0), (4, 5, 0)),
    ((6, 7, 2), (8, 9, 3)),
    ((10, 11, 4), (12, 13, 5)),
    ((14, 15, 6), (16, 17, 7)),
    ((24, 25, 8),),
)


def check_caller_source(data):
    calls = {
        0x7B5968: 0x87BE74,
        0x7B5974: 0x87BE6C,
        0x7B4EC0: 0x565C68,
        0x7B4EC4: 0x78595C,
        0x7B4ED4: 0x6C9E34,
        0x7B5124: 0x632CC4,
        0x632CD4: 0x712898,
        0x632CEC: 0x630DB0,
        0x630DC0: 0x704038,
        0x630DD8: 0x70C3CC,
        0x632D04: 0x70C408,
        0x7B5130: 0x74ED98,
        0x7B513C: 0x6C9E50,
        0x7B514C: 0x6C9E28,
        0x6366E0: 0x6355D0,
        0x635618: 0x6352A0,
        0x6352B0: 0x565C68,
        0x6352B4: 0x78595C,
        0x6352C0: 0x545084,
        0x6352CC: 0x54508C,
        0x635538: 0x71ADF0,
        0x63553C: 0x545268,
        0x635558: 0x545258,
        0x635570: 0x545260,
        0x635588: 0x545248,
        0x6355A0: 0x545250,
        0x635568: 0x74F974,
        0x635580: 0x74F974,
        0x635598: 0x74F944,
        0x6355B0: 0x74F944,
        0x635F48: 0x6355D0,
        0x635F80: 0x74ED98,
        0x635FB4: 0x74FA8C,
    }
    jumps = {0x7B5A00: 0x7B5A90, 0x7B5A9C: 0x7B4EB4}
    for edges, link in ((calls, True), (jumps, False)):
        for site, target in edges.items():
            check_edge(data, site, target, link=link)
    words = {
        0x87BE74: 0xE5D00858,
        0x87BE6C: 0xE5D00859,
        0x7B5988: 0xE3550002,
        0x7B59E4: 0xE3540018,
        0x7B59E8: 0x308FF104,
        0x7B4EF4: 0xE35B0005,
        0x7B4F68: 0x308FF10B,
        0x7B512C: 0xE59D011C,
        0x7B5138: 0xE3A01019,
        0x632CCC: 0xE3A02040,
        0x632CD0: 0xE2800FA3,
        0x632CE4: 0xE3A01002,
        0x630DD0: 0xE5840380,
        0xA71148: BASE + 0x7B5E50,
        0x63669C: 0xE5906380,
        0x6366D0: 0xE3160002,
        0x6352C4: 0xE20080FF,
        0x6352D0: 0xE200A0FF,
        0x71ADF0: 0xE28000F8,
        0x545268: 0xE5D00000,
        0x545258: 0xE5900004,
        0x545260: 0xE5900008,
        0x545248: 0xE590000C,
        0x545250: 0xE5900010,
        0x635F7C: 0x1A00000C,
        0x74F974: 0xE351001A,
        0x74F944: 0xE351001A,
        0x635D54: BASE + 0xA49110,
    }
    check_words(data, words)
    require(
        unpack("<10H", data[0xA49110:0xA49124]),
        tuple(1 << i for i in range(10)),
        "native completion mask table",
    )
    return {
        "branches": len(calls) + len(jumps),
        "words": len(words),
        "mask_table_halfwords": 10,
    }


def emulate_config_callers(data):
    static = check_caller_source(data)
    vm = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    for address, size in (
        (BASE, 0x1000000),
        (0x40400000, 0x100000),
        (0x40106000, 0x1000),
        (0x10000000, 0x100000),
        (RAM[0], 0x20000),
    ):
        vm.mem_map(address, size)
    vm.mem_write(BASE, data[:0x1000000])
    manager, config, controller, worker, command = range(
        0x10010000, 0x10060000, 0x10000
    )
    command_stack, worker_stack, sentinel = 0x100F0000, 0x100E0000, 0x100F1000

    def read(address, size=4):
        return bytes(vm.mem_read(address, size))

    def put(address, value, size=4):
        vm.mem_write(address, value.to_bytes(size, "little"))

    def get(address, size=4):
        return int.from_bytes(read(address, size), "little")

    def reg(name, value=None):
        idx = getattr(arm, "UC_ARM_REG_" + name.upper())
        if value is None:
            return vm.reg_read(idx)
        vm.reg_write(idx, value)

    def run(entry, *args, end=None, sp=command_stack, **regs):
        for name, value in dict(sp=sp, lr=sentinel, **regs).items():
            reg(name, value)
        for i, value in enumerate(args):
            reg(f"r{i}", value)
        stop = sentinel if end is None else BASE + end
        vm.ctl_flush_tb()
        try:
            vm.emu_start(BASE + entry, stop, count=1_000_000)
        except uc.UcError as error:
            raise ValueError(f"{entry:#x} stopped at VA {reg('pc'):#x}") from error
        require(reg("pc"), stop, f"original slice from {entry:#x}")
        return reg("r0")

    run(0x565BC8, SERVICE_OWNER)
    run(0x5660B0, config, end=0x5660C8, r4=SERVICE_OWNER)
    run(0x6E80BC, manager)
    put(MANAGER_OWNER + 4, manager)
    for guard in (0x4040B7A4, 0x4040AE64, 0x4041D97C):
        put(guard, 1)
    for entry, obj in zip((0x76C6F0, 0x76C704, 0x76C718), PROVIDERS):
        require(run(entry, end=entry + 8), obj, "native startup provider object")
    run(0x76B8D0, end=0x76B900, r4=MANAGER_OWNER)
    for bank, group in enumerate(GROUPS):
        image = bytearray((0x10000, 0xE000)[bank])
        image[:4] = pack("<I", MARKER)
        offset = 0x90
        for position, idx in enumerate(group):
            image[0x10 + 8 * position : 0x18 + 8 * position] = pack("<II", 4, 1)
            image[offset : offset + 4] = pack("<HH", 0x100 + idx, 0xB000)
            offset += CAPACITY[idx]
        vm.mem_write(BACKUP[bank], bytes(image))
    run(0x6E7EB0, manager)
    run(0x5666FC, end=0x566710, r4=SERVICE_OWNER)
    require(
        read(config + 0xC, 2), b"\1\1", "native config initially validates both groups"
    )

    calls = []

    def trace_call(_vm, pc, _size, _user):
        calls.append((pc - BASE, reg("r0"), reg("r1"), reg("r2")))

    for offset in (0x632CC4, 0x6355D0, 0x6352A0, 0x74F944, 0x74F974, 0x74ED98):
        vm.hook_add(uc.UC_HOOK_CODE, trace_call, begin=BASE + offset, end=BASE + offset)

    put(controller + 0x30, worker)
    command_words = (
        (0x101, 0x201, 0x310),
        (0x102, 0x202, 0xFFFF),
        (0x103, 0x203, 0x330),
    )

    def plan(selector, subtype=4):
        calls.clear()
        vm.mem_write(command_stack - 0x200, bytes([0xA5]) * 0x200)
        vm.mem_write(worker + 0x28C, bytes([0x5A]) * 0x40)
        put(command + 0x858, 2, 1)
        put(command + 0x859, subtype, 1)
        put(command + 8, selector)
        for i, words in enumerate(command_words):
            vm.mem_write(command + 0xC + 0xC * i, pack("<III", *words))
        put(command + 4, 0xDD)
        if subtype != 4:
            require(
                run(0x7B5954, controller, 0, command), 0x81, "unhandled subtype return"
            )
            require(calls, [], "unhandled subtype never submits a request")
            require(
                read(worker + 0x28C, 0x40),
                bytes([0x5A]) * 0x40,
                "unhandled subtype preserves work list",
            )
            return {"type": 2, "subtype": subtype, "selector": selector, "requests": []}
        run(0x7B5954, controller, 0, command, end=0x632CD8)
        require(len(calls), 1, "one native worker submission")
        entry, observed_worker, list_addr, _ = calls[0]
        require(
            (entry, observed_worker), (0x632CC4, worker), "native request submit call"
        )
        require(
            read(worker + 0x28C, 0x40),
            read(list_addr, 0x40),
            "native full request list copy",
        )
        plan_sp = list_addr - 0xC4
        require(get(plan_sp + 0x11C), config, "dispatcher stores native config alias")
        expected = PLAN[selector] if selector < 5 else ((0, 0, 0),)
        requests = []
        for idx, (left, right, kind) in enumerate(expected):
            request = get(worker + 0x28C + 4 * idx)
            require(request, plan_sp + 0x1C * idx, "native request pointer alias")
            command_arg1, command_arg2, command_arg3 = command_words[idx]
            actual = (
                get(request, 1),
                get(request + 1, 1),
                get(request + 4),
                get(request + 8),
                get(request + 0xC),
                get(request + 0x10),
                get(request + 0x14, 2),
                get(request + 0x18, 1),
            )
            require(
                actual,
                (
                    1,
                    kind,
                    left,
                    right,
                    command_arg1,
                    command_arg2,
                    (command_arg3 + 0x1000) & 0xFFFF,
                    int(selector == 0 and idx in (1, 2)),
                ),
                "native request parameter mapping",
            )
            requests.append({"address": request, "fields": actual})
        require(
            get(worker + 0x28C + 4 * len(expected)),
            0,
            "native null-terminated work list",
        )
        return {
            "type": 2,
            "subtype": subtype,
            "selector": selector,
            "requests": requests,
            "request_list": list_addr,
            "plan_stack": plan_sp,
        }

    # Put selector 0 last so its native output remains in VM for the worker.
    planning = [plan(i) for i in (1, 2, 3, 4, 5, 0xFFFFFFFF)]
    unhandled = plan(0, 7)
    planning.append(plan(0))
    active = planning[-1]
    native_request = active["requests"][0]["address"]
    plan_sp = active["plan_stack"]
    put(worker + 0x380, 0)
    calls.clear()
    run(0x636694, worker, end=0x6366FC, sp=worker_stack)
    require(calls, [], "worker skips update if bit value 2 is clear")

    def worker_prefix(request=None):
        calls.clear()
        if request is None:
            put(worker + 0x380, 0)
            run(0x630DC4, end=0x630DD4, r4=worker, r5=2)
            require(get(worker + 0x380), 2, "native post-lock worker flag producer")
            run(0x636694, worker, end=0x6352D4, sp=worker_stack)
            require(
                [(pc, r0, r1) for pc, r0, r1, _ in calls],
                [
                    (0x6355D0, worker, worker + 0x28C),
                    (0x6352A0, worker, native_request),
                ],
                "native worker dispatch follows the copied request pointer",
            )
        else:
            run(0x6352A0, worker, request, end=0x6352D4, sp=worker_stack)
        require(reg("sb"), config, "original worker looks up same config")
        return reg("sp"), (reg("r8"), reg("sl"))

    def result_tail(result_stack, flag, counts, lengths):
        vm.mem_write(result_stack + 0xF8, pack("<B3x4I", flag, *counts, *lengths))
        calls.clear()
        run(0x635534, end=0x6355B4, sp=result_stack)
        return list(calls)

    def full_desc(idx):
        return config + 0x18 + 0x10 * idx

    original_mirrors = [
        read(address, size) for address, size in zip(RAM, (0x10000, 0xE000))
    ]
    linked = []
    for flag, counts, expected_counts, expected_flags, worker_return in (
        (0, (2, 3), (1, 1), (1, 1), 0),
        (1, (2, 1), (2, 1), (0, 1), 0),
        (1, (1, 1), (1, 1), (1, 1), 0x3FF),
    ):
        result_stack, indices = worker_prefix()
        require(indices, (0, 1), "native command selector0 pair")
        lengths = (4, 4)
        actual = result_tail(result_stack, flag, counts, lengths)
        expected_calls = (
            [(0x74F974, config, i, value) for i, value in enumerate(counts)]
            if flag
            else []
        )
        expected_calls.extend(
            (0x74F944, config, i, value) for i, value in enumerate(lengths)
        )
        require(actual, expected_calls, "original result flag gates count writes only")
        require(
            tuple(get(full_desc(i) + 0xC) for i in (0, 1)),
            expected_counts,
            "native descriptor counts",
        )
        # Resume after the caller's wait with a prepared return value in R0.
        calls.clear()
        run(0x7B5128, worker_return, end=0x7B5150, sp=plan_sp)
        require(
            [(pc, r0) for pc, r0, _, _ in calls],
            [(0x74ED98, config)],
            "native writer unconditionally uses the same config",
        )
        require(
            (get(command + 4), get(command + 8)),
            (0x19, worker_return),
            "native response words",
        )
        expected_mirror = bytearray(original_mirrors[0])
        for offset, value in zip((0x14, 0x1C), expected_counts):
            expected_mirror[offset : offset + 4] = pack("<I", value)
        require(
            read(RAM[0], 0x10000),
            bytes(expected_mirror),
            "whole ID63 mirror changes only requested counts",
        )
        require(
            read(RAM[1], 0xE000), original_mirrors[1], "whole ID64 mirror unchanged"
        )
        require(
            read(config + 0xC, 2),
            bytes(expected_flags),
            "native independent validity flags",
        )
        linked.append(
            {
                "prepared_result_flag": flag,
                "prepared_counts": counts,
                "prepared_lengths": lengths,
                "resolved_indices": indices,
                "setter_calls": actual,
                "prepared_wait_result": worker_return,
                "observed_counts": expected_counts,
                "config_bytes": expected_flags,
                "response": [get(command + 4), get(command + 8)],
            }
        )

    # The command planner cannot emit these indices; this separate control
    # exercises the native u8 conversion and setter range guard.
    malformed = 0x10070000
    vm.mem_write(malformed, pack("<III", 1, 0x101, 26))
    result_stack, indices = worker_prefix(malformed)
    require(indices, (1, 26), "native worker masks index words to u8")
    config_before = read(config, 0x228)
    actual = result_tail(result_stack, 1, (3, 9), (4, 0xAABBCCDD))
    require(
        actual,
        [
            (0x74F974, config, 1, 3),
            (0x74F974, config, 26, 9),
            (0x74F944, config, 1, 4),
            (0x74F944, config, 26, 0xAABBCCDD),
        ],
        "native out-of-range call arguments",
    )
    off = full_desc(1) + 0xC - config
    require(
        read(config, 0x228),
        config_before[:off] + pack("<I", 3) + config_before[off + 4 :],
        "index 26 writes no descriptor bytes",
    )
    range_case = {
        "prepared_index_words": [0x101, 26],
        "resolved_indices": indices,
        "setter_calls": actual,
    }

    masks = []
    for mask, end in ((0x3FF, 0x635F84), (0x1FF, 0x635FB4), (0x7FF, 0x635FB4)):
        calls.clear()
        state = read(config, 0x228)
        run(0x635F4C, mask, end=end, r8=config)
        committed = end == 0x635F84
        require(
            [(pc, r0) for pc, r0, _, _ in calls],
            [(0x74ED98, config)] if committed else [],
            "alternate caller requires exact completion mask",
        )
        if not committed:
            require(
                read(config, 0x228),
                state,
                "failed mask reaches restore entry without committing",
            )
        else:
            require(get(RAM[0] + 0x1C), 3, "alternate caller commits same descriptor")
            require(
                read(config + 0xC, 2),
                b"\0\1",
                "alternate caller recomputes separate flags",
            )
        masks.append(
            {"prepared_mask": mask, "writer_called": committed, "end_exclusive": end}
        )

    return {
        "decoded_sha256": sha256(data),
        "code_va_base": BASE,
        "unicorn_version": uc.__version__,
        "static_checks": static,
        "execution_replacements": [],
        "planning_cases": planning,
        "unhandled_subtype": unhandled,
        "worker_without_flag2_stop": 0x6366FC,
        "linked_caller_cases": linked,
        "setter_range_control": range_case,
        "alternate_mask_cases": masks,
        "boundaries": {
            "command_through_native_copy": [0x7B5954, 0x632CD8],
            "worker_post_lock_flag_slice": [0x630DC4, 0x630DD4],
            "worker_through_native_pair_lookup": [0x636694, 0x6352D4],
            "prepared_result_caller": [0x635534, 0x6355B4],
            "prepared_wait_return_through_writer": [0x7B5128, 0x7B5150],
            "alternate_mask_caller_entry": 0x635F4C,
        },
    }


def emulate_packets(data):
    edges = {
        0x83DC44: 0x87BE6C,
        0x83DC54: 0x6C9E50,
        0x83E278: 0x83DAEC,
        0x83E420: 0x83DAAC,
        0x83DACC: 0x6E7E9C,
        0x83DB54: 0x6E7E9C,
        0x83E430: 0x6C9E50,
    }
    for a, b in edges.items():
        check_edge(data, a, b)
    check_words(
        data,
        {
            0xA71CB0: BASE + 0x72E1F8,
            0xA71CB4: BASE + 0x72E200,
            0x83DB5C: 0xE591202C,
            0x83DAD4: 0xE5912030,
            0x83DB08: 0xAA00000C,
            0x83DAC4: 0xA8BD8070,
        },
    )
    vm = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    for a, n in [
        (BASE, 0x1000000),
        (0x40400000, 0x100000),
        (0x10000000, 0x100000),
        (0x80000000, 0x20000),
    ]:
        vm.mem_map(a, n)
    vm.mem_write(BASE, data[:0x1000000])
    manager, handler, cmd, stack, sentinel = (
        0x10010000,
        0x10020000,
        0x10030000,
        0x100F0000,
        0x100F1000,
    )
    ram = 0x80000000

    def reg(k, v=None):
        k = getattr(arm, "UC_ARM_REG_" + k.upper())
        if v is None:
            return vm.reg_read(k)
        vm.reg_write(k, v)

    def read(a, n=4):
        return bytes(vm.mem_read(a, n))

    def word(a):
        return int.from_bytes(read(a), "little")

    def put(a, v, n=4):
        vm.mem_write(a, v.to_bytes(n, "little"))

    def resume(entry, end):
        vm.ctl_flush_tb()
        vm.emu_start(BASE + entry, BASE + end, count=1000000)
        require(reg("pc"), BASE + end, "native stop")
        return reg("r0")

    def call(entry, *args, end=None, **regs):
        reg("sp", stack)
        reg("lr", sentinel)
        for i, v in enumerate(args):
            reg("r" + str(i), v)
        for k, v in regs.items():
            reg(k, v)
        vm.ctl_flush_tb()
        stop = sentinel if end is None else BASE + end
        vm.emu_start(BASE + entry, stop, count=1000000)
        require(reg("pc"), stop, "native call stop")
        return reg("r0")

    call(0x6E80BC, manager)
    put(0x4040B0F0, manager)
    put(0x4040AE64, 1)
    call(0x76C704, end=0x76C70C)
    call(0x76B8E0, end=0x76B8F0, r4=0x4040B0EC)
    call(0x83DA6C, handler, end=0x83DA80)
    require(word(handler + 8), manager, "native handler manager bind")
    observed = []

    def hook(_vm, pc, _size, _u):
        observed.append(dict(pc=pc - BASE, r0=reg("r0"), r1=reg("r1"), r2=reg("r2")))

    for off in (
        0x83E278,
        0x83E420,
        0x83DB64,
        0x83DADC,
        0x72E1F8,
        0x72E200,
        0x72E0EC,
        0x72E130,
    ):
        vm.hook_add(uc.UC_HOOK_CODE, hook, begin=BASE + off, end=BASE + off)

    def prepare(sub, words):
        call(0x6C9D74, cmd)
        put(cmd + 0x859, sub, 1)
        for i, v in enumerate(words):
            put(cmd + 8 + 4 * i, v)
        observed.clear()
        call(0x83DC2C, handler, 0, cmd, end=0x83DC5C)
        require(reg("r6"), sub, "native subcommand getter")
        require(word(cmd + 4), 0, "native output length reset")

    rows = []
    for sub, selector in [(6, 0x63), (10, 3)]:
        for idx in (0, 1, 31):
            original = shake_256(f"packet route {sub}/{idx}".encode()).digest(0x20000)
            vm.mem_write(ram, original)
            count = 508 if idx == 31 else 512
            body = shake_256(f"payload {sub}/{idx}".encode()).digest(count * 4)
            payload = [selector, idx] + ([0x12345678] if idx == 0 else [])
            prepare(sub, payload)
            bodyoff = cmd + 8 + 4 * len(payload)
            vm.mem_write(bodyoff, body)
            command_before = read(cmd, 0x85A)
            resume(0x83DC98, 0x83DB0C)
            require(reg("r6"), 0x63, "native direct or mapped provider selector")
            require(
                reg("r7"),
                cmd + 12,
                "native packet argument points after provider selector",
            )
            # State snapshot setup/check is omitted; retained nested frame enters its success body.
            resume(0x83DB4C, 0x83DB38)
            # State snapshot cleanup is omitted; native epilogue returns to the original caller.
            resume(0x83DB40, 0x83E434)
            expected = bytearray(original)
            expected[0x10 + idx * 0x800 : 0x10 + idx * 0x800 + len(body)] = body
            if idx == 0:
                expected[4:6] = pack("<H", 0x5678)
            require(
                read(ram, 0x20000),
                bytes(expected),
                "complete ID63 and adjacent backing",
            )
            require(
                read(cmd, 0x85A), command_before, "command unchanged by write dispatch"
            )
            require(reg("r4"), 0, "native write status")
            require(
                [x["pc"] for x in observed],
                [0x83E278, 0x83DB64, 0x72E1F8, 0x72E0EC],
                "native write dispatch order",
            )
            require(
                [observed[-1]["r0"], observed[-1]["r1"]],
                [ram, cmd + 12],
                "native fixed RAM packet writer args",
            )
            write_trace = list(observed)
            readsub = 7 if sub == 6 else 11
            prepare(readsub, [selector, idx])
            before = read(cmd, 0x85A)
            resume(0x83DC98, 0x83E434)
            response = (pack("<I", 0x5678) if idx == 0 else b"") + body
            expected_cmd = bytearray(before)
            expected_cmd[4:8] = pack("<I", count + int(idx == 0))
            expected_cmd[8 : 8 + len(response)] = response
            require(
                read(cmd, 0x85A),
                bytes(expected_cmd),
                "entire response including tail and size",
            )
            require(read(ram, 0x20000), bytes(expected), "read preserves backing")
            require(reg("r4"), 0, "read status")
            require(
                [x["pc"] for x in observed],
                [0x83E420, 0x83DADC, 0x72E200, 0x72E130],
                "native read dispatch order",
            )
            require(
                [observed[-1]["r0"], observed[-1]["r1"]],
                [ram, cmd + 8],
                "native fixed RAM packet reader args",
            )
            rows.append(
                dict(
                    write_subcommand=sub,
                    read_subcommand=readsub,
                    provider_selector=selector,
                    block_index=idx,
                    read_words=word(cmd + 4),
                    backing_sha256=sha256(expected),
                    write_trace=write_trace,
                    read_trace=list(observed),
                )
            )
    rejected = []
    for sub, selector in ((6, 0x66), (7, 0x66), (10, 16), (11, 16)):
        before = read(ram, 0x20000)
        prepare(sub, [selector, 0])
        resume(0x83DC98, 0x83E434)
        require(reg("r4"), 0x83, "invalid provider rejected")
        require(read(ram, 0x20000), before, "rejected provider unchanged")
        require(
            any(x["pc"] in (0x72E1F8, 0x72E200) for x in observed),
            False,
            "invalid provider never reaches ID63",
        )
        rejected.append(dict(subcommand=sub, selector=selector, status=reg("r4")))
    before = read(ram, 0x20000)
    prepare(10, [3, 32])
    resume(0x83DC98, 0x83DB0C)
    resume(0x83DB4C, 0x72E08C)
    require(reg("r5") + 0x10, ram + 0x10010, "index32 first pending write")
    require(read(ram, 0x20000), before, "stop before write")
    return dict(
        decoded_sha256=sha256(data),
        cases=rows,
        rejected_providers=rejected,
        index32_prefix=dict(
            subcommand=10,
            provider_selector=3,
            stop_before=0x72E08C,
            pending_write_va=reg("r5") + 0x10,
            store_executed=False,
        ),
        execution_replacements=[],
        limits=[
            "Synthetic command and RAM. Handler manager binding and native registered ID63 are real code with supplied guards/manager link.",
            "Dispatcher prefix stops before state snapshot construction/copy/check; resume at83DC98 bypasses that outer gate. Nested writes resume83DB4C after omitted state check and83DB40 after omitted snapshot cleanup. No snapshot state result is executed or inferred.",
            "Stop83E434 before outer cleanup/return; no transport producer or actual device reachability proof.",
            "Provider ID rejection and block index are separate. Index32 only reaches first store boundary; store is not executed.",
        ],
    )


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
        "config_callers": emulate_config_callers(data),
        "packets": emulate_packets(data),
        "limits": [
            "Synthetic command/config/worker objects and Flash records; original constructor and binding slices use supplied allocator result, manager link and initialization guards.",
            "Config command reaches original pointer-list copy, stopping before wait/state work. The post-lock flag OR/store runs with prepared value2. Computation-result fields and wait return value are supplied; no scheduler or computation algorithm is run.",
            "Only the first pair of selector0 is joined to result setters and writer. All seven selectors have separately checked planning output; this is not all work items completing.",
            "Alternate completion-mask caller starts after its worker return and stops before restore on rejection; no restore body or preceding calculation is run.",
            "Packet dispatcher omits outer state snapshot/copy/check, write-side state snapshot/check and cleanup, and outer cleanup/return. Original saved frames are retained across those explicit resume boundaries.",
            "Index32 packet control stops before its first out-of-span store. No transport or real device reachability and no exploitability claim.",
            "No physical Flash/DMA/capture or menu activation is exercised; these command selectors are not shown to be user menu values.",
        ],
    }
    if args.compare:
        require_snapshot(result, args.compare, "preserved command dispatch replay")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
