"""Replay bounded K-3 II update transport and write/error control in synthetic RAM.

SPDX-License-Identifier: GPL-2.0-only
No camera I/O, flash programming, boot or physical acceptance is performed.
"""

import argparse
import json
from pathlib import Path
import struct

from verify_findings import DECODED_SHA256, require, require_snapshot, sha256, u32
from verify_raw_path import branch_target
from verify_tone_path import BASE, check_words, load_image


WORDS = {
    0x5D5C20: 0x0101E000,
    0x5D6344: 0xE3A04000,
    0x5D6374: 0xE3A04001,
    0x5D6380: 0xE1A00004,
    0x5D5198: 0xE2833A0F,
    0x5D51B8: 0xE3510B0F,
    0x5D51E0: 0xE3A03A0F,
    0x5D5298: 0xE3A03040,
    0x5D52A0: 0xE3A010F0,
    0x5D52E0: 0xE3560D0F,
    0x5D5484: 0xE3550003,
    0x556248: 0xE1550008,
    0x55624C: 0x13A01004,
    0x73D114: 0x62C,
    0x73D118: 0x0200B324,
    0x73D11C: 0x40304000,
    0x630118: 0x403040C4,
    0x630120: 0x40304144,
    0x630160: 0x40304034,
    0xDA2A8: 0xEBFFFF01,
    0xDA2AC: 0xE3A0000A,
    0xDA2B0: 0xEA00000D,
    0xD9E54: 0xE3A0107F,
    0xD9E78: 0xE3510080,
    0x599948: 0xE3500003,
    0x599954: 0xE3550003,
    0x59A028: 0x40459204,
}
EDGES = (
    (0x5D640C, 0x73CF94),
    (0x5D666C, 0x73CFF4),
    (0x5D6678, 0x630174),
    (0xC010, 0xB358),
    (0xC02C, 0xB3E8),
    (0xC050, 0xB468),
    (0xC078, 0xB358),
    (0xC148, 0xBFD0),
    (0xC254, 0xBFD0),
    (0x5D663C, 0x5D633C),
    (0x5D6358, 0x5D5370),
    (0x5D53F8, 0x5D523C),
    (0x5D542C, 0x5D51C4),
    (0x5D543C, 0x5D5180),
    (0x5D52A4, 0x55601C),
    (0x5D51FC, 0x556180),
    (0x5560AC, 0x6CA780),
    (0x55611C, 0x6CA780),
    (0x556220, 0x6CA4FC),
    (0x5562A4, 0x6CA4FC),
    (0xDA278, 0xD9B68),
    (0xDA28C, 0xD9DF8),
    (0xDA2A8, 0xD9EB4),
    (0xD9E08, 0xD9DAC),
    (0xD9EDC, 0xD9E48),
    (0x599930, 0x63013C),
    (0x599944, 0x63015C),
    (0x599970, 0x630114),
    (0x599988, 0x63011C),
    (0x5999A0, 0x63015C),
)
RANGES = {
    "update_sector_control": (0xBFD0, 0xC2F0),
    "update_entry_after_auxiliary": (0x5D6664, 0x5D6680),
    "update_receive_allocation": (0x5D6428, 0x5D643C),
    "auxiliary_program_read_compare_retry": (0x5D50F8, 0x5D54B0),
    "auxiliary_serial_transactions": (0x55601C, 0x5562FC),
    "ram_copy": (0x73CFF4, 0x73D024),
    "ram_copy_literals": (0x73D114, 0x73D120),
    "ram_mailbox_senders": (0xB324, 0xB950),
    "mailbox_receiver": (0xDA078, 0xDA30C),
    "nor_commands": (0xD9B68, 0xD9F68),
    "sector_rewrite_control": (0x599914, 0x5999C0),
}


def verify(data):
    check_words(data, WORDS)
    for site, dest in EDGES:
        require(branch_target(data, site), dest, f"A32 edge {site:#x}")
    return {
        "decoded_sha256": DECODED_SHA256,
        "firmware_version": "1.12",
        "offset_units": "Decoded file offsets; addresses and object fields explicitly marked.",
        "word_check_count": len(WORDS),
        "branch_checks": [{"site": a, "target": b} for a, b in EDGES],
        "range_sha256": {key: sha256(data[a:b]) for key, (a, b) in RANGES.items()},
        "auxiliary": {
            "controller": 0x5D5370,
            "write": 0x5D523C,
            "readback": 0x5D51C4,
            "compare": 0x5D5180,
            "image_relative_source": 0x1000000,
            "image_relative_readback": 0x100F000,
            "bytes": 0xF000,
            "write_chunk_bytes": 0x40,
            "write_chunks": 0x3C0,
            "serial_tag": 0xF0,
            "compare_retries_total_attempts": 3,
            "transport_error_retries": 0,
        },
        "primary": {
            "sender_source_offset": 0xB324,
            "sender_copy_function": 0x73CFF4,
            "sender_destination_va": 0x40304000,
            "sender_copy_bytes": 0x62C,
            "receiver": 0xDA078,
            "mailbox_va": 0xC0001FD0,
            "generic_sector_write_controller": 0x599914,
            "actual_update_entry": 0xC278,
            "actual_update_sector_pass": 0xC07C,
            "actual_update_block_controller": 0xBFD0,
            "staging_va": 0x40459204,
            "commands": {
                "compare": 8,
                "erase": 9,
                "program": 10,
                "reset": 11,
                "staging_sum": 12,
            },
            "nor_program_chunk_halfwords": 0x80,
            "program_status_published_to_result_slot": False,
        },
        "limits": [
            "Synthetic RAM and explicit transport/status stubs; no physical writes or acceptance.",
            "No full updater, interruption recovery, power-loss safety, reboot or capture validation.",
            "NOR command patterns do not establish a manufacturer or exact chip part number.",
            "Auxiliary tag 0xf0 is verified at the sender; the remote receiver and flash destination remain untraced.",
            "Sequential CPU contexts do not model concurrent timing or cache coherency.",
        ],
    }


def auxiliary_cases(data):
    import unicorn
    from unicorn import arm_const as arm

    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    image, obj, sp, ret = 0x10000000, 0x12000000, 0x12008000, 0x12009000
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    vm.mem_map(image, 0x1020000)
    vm.mem_map(obj, 0x10000)
    vm.mem_map(0x40307000, 0x1000)
    vm.mem_write(0x40307E14, struct.pack("<I", image))
    payload = data[0x1000000:0x100F000]
    vm.mem_write(image + 0x1000000, payload)
    # These fixtures replace only external UI, serial, synchronization and GPIO boundaries.
    zero = {
        0x70BC28,
        0x8471A0,
        0x847340,
        0x847308,
        0x847324,
        0x8472A4,
        0x84758C,
        0x8475A8,
        0x8475C4,
        0x6FEB30,
        0x6FEBAC,
        0x59FC40,
        0x59FBD0,
        0x59FD0C,
        0x59FD14,
        0x55581C,
        0x5557AC,
        0x556314,
        0x556374,
        0x556354,
        0x55630C,
        0x5563B4,
    }
    state = {}

    def hook(uc, address, size, _):
        off = address - BASE
        if off not in zero and off not in {0x55601C, 0x556180}:
            return
        value = 0
        if off == 0x847340:
            state["attempts"] += 1
        elif off == 0x55601C:
            i = state["writes"] % 960
            args = [uc.reg_read(getattr(arm, f"UC_ARM_REG_R{n}")) for n in (1, 2, 3)]
            require(
                args,
                [0xF0, image + 0x1000000 + i * 64, 64],
                "auxiliary chunk arguments",
            )
            require(
                bytes(uc.mem_read(args[1], 64)),
                payload[i * 64 : (i + 1) * 64],
                "auxiliary source bytes",
            )
            state["writes"] += 1
            if state["failure"] == f"write_{i}":
                value = 7
        elif off == 0x556180:
            args = [uc.reg_read(getattr(arm, f"UC_ARM_REG_R{n}")) for n in (1, 2, 3)]
            require(args, [0xF0, image + 0x100F000, 0xF000], "auxiliary read arguments")
            state["reads"] += 1
            uc.mem_write(args[1], payload)
            if state["failure"] == "read":
                value = 7
            elif state["failure"] in {"first_word", "last_word", "once"}:
                if state["failure"] != "once" or state["reads"] == 1:
                    index = 0xEFFC if state["failure"] == "last_word" else 0
                    uc.mem_write(args[1] + index, bytes([payload[index] ^ 1]))
        elif off in {0x84758C, 0x8475A8, 0x8475C4}:
            state["errors"].append(off)
        uc.reg_write(arm.UC_ARM_REG_R0, value)
        uc.reg_write(arm.UC_ARM_REG_PC, uc.reg_read(arm.UC_ARM_REG_LR))

    vm.hook_add(unicorn.UC_HOOK_CODE, hook)
    results = []
    cases = [
        ("none", 1, 1, 960, 1, []),
        ("write_0", 0, 1, 1, 0, [0x8475C4]),
        ("write_959", 0, 1, 960, 0, [0x8475C4]),
        ("read", 0, 1, 960, 1, [0x8475A8]),
        ("first_word", 0, 3, 2880, 3, [0x84758C] * 3),
        ("last_word", 0, 3, 2880, 3, [0x84758C] * 3),
        ("once", 1, 2, 1920, 2, [0x84758C]),
    ]
    for failure, expected, attempts, writes, reads, errors in cases:
        state.clear()
        state.update(failure=failure, attempts=0, writes=0, reads=0, errors=[])
        for reg, value in [
            (arm.UC_ARM_REG_SP, sp),
            (arm.UC_ARM_REG_LR, ret),
            (arm.UC_ARM_REG_R0, obj),
            (arm.UC_ARM_REG_R1, 2),
            (arm.UC_ARM_REG_R2, 0),
        ]:
            vm.reg_write(reg, value)
        vm.emu_start(BASE + 0x5D5370, ret, count=10_000_000)
        require(vm.reg_read(arm.UC_ARM_REG_PC), ret, "auxiliary controller return")
        result = vm.reg_read(arm.UC_ARM_REG_R0)
        require(
            [
                result,
                state["attempts"],
                state["writes"],
                state["reads"],
                state["errors"],
            ],
            [expected, attempts, writes, reads, errors],
            failure,
        )
        results.append({**state, "return": result})
    return {
        "cases": results,
        "stub_offsets": sorted(zero | {0x55601C, 0x556180}),
        "readback_source": "Synthetic serial reply copied from auxiliary image; selected errors injected at that boundary.",
    }


def serial_cases(data):
    import unicorn
    from unicorn import arm_const as arm

    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    obj, source, sp, ret = 0x12000000, 0x12002000, 0x12008000, 0x12009000
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    vm.mem_map(obj, 0x10000)
    put = lambda address, value: vm.mem_write(address, struct.pack("<I", value))
    put(obj + 0x1C, obj + 0x100)
    put(obj + 0x100, obj + 0x200)
    put(obj + 0x230, ret + 4)
    payload = bytes(range(64))
    zero = {
        0x6CAB78,
        0x6CA7F8,
        0x5556D8,
        0x703BA4,
        0x703B78,
        0x555B18,
        0x555A34,
        0x5559E4,
        0x6CA80C,
    }
    state = {}

    def hook(uc, address, size, _):
        off = address - BASE
        if off not in zero | {0x6CA780, 0x6CA4FC} and address != ret + 4:
            return
        value = 0
        if off == 0x555B18 and state["case"] == "handshake_error":
            put(obj + 0x24, 7)
        elif off == 0x6CA780:
            state["tx"].append(uc.reg_read(arm.UC_ARM_REG_R1))
        elif off == 0x6CA4FC:
            i = state["rx_count"]
            if state["direction"] == "read":
                value = (
                    (0xEF if state["case"] == "wrong_tag" else 0xF0)
                    if i == 0
                    else payload[i - 1]
                )
            state["rx_count"] += 1
        uc.reg_write(arm.UC_ARM_REG_R0, value)
        uc.reg_write(arm.UC_ARM_REG_PC, uc.reg_read(arm.UC_ARM_REG_LR))

    vm.hook_add(unicorn.UC_HOOK_CODE, hook)
    result = []
    for direction, case, expected in [
        ("write", "ok", 0),
        ("write", "handshake_error", 7),
        ("read", "ok", 0),
        ("read", "wrong_tag", 0x10004),
    ]:
        state.clear()
        state.update(direction=direction, case=case, tx=[], rx_count=0)
        vm.mem_write(source, payload if direction == "write" else bytes([0xA5]) * 64)
        for name, value in {
            "sp": sp,
            "lr": ret,
            "r0": obj,
            "r1": 0xF0,
            "r2": source,
            "r3": 64,
        }.items():
            vm.reg_write(getattr(arm, "UC_ARM_REG_" + name.upper()), value)
        vm.emu_start(
            BASE + (0x55601C if direction == "write" else 0x556180), ret, count=100_000
        )
        require(vm.reg_read(arm.UC_ARM_REG_PC), ret, "serial return")
        require(vm.reg_read(arm.UC_ARM_REG_R0), expected, "serial status")
        require(u32(vm.mem_read(obj + 0x28, 4), 0), 0xFFFF, "serial final phase")
        if case == "ok":
            require(
                state["tx"],
                [0xF0, *payload] if direction == "write" else [0] * 65,
                "serial bytes",
            )
            if direction == "read":
                require(bytes(vm.mem_read(source, 64)), payload, "serial read bytes")
        else:
            require(
                len(state["tx"]),
                0 if case == "handshake_error" else 1,
                "early serial termination",
            )
        result.append(
            {
                "direction": direction,
                "case": case,
                "return": expected,
                "tx_bytes": len(state["tx"]),
                "rx_calls": state["rx_count"],
                "tx_sha256": sha256(bytes(state["tx"])),
            }
        )
    return {
        "cases": result,
        "stub_offsets": sorted(zero | {0x6CA780, 0x6CA4FC}),
        "other_stub": "Synthetic mutex virtual callback",
        "payload": "Synthetic byte sequence 0..63",
    }


def primary_mailbox_cases(data):
    import unicorn
    from unicorn import arm_const as arm

    ram, source, dest = 0x40304000, 0x12002000, 0x02080000
    sp, ret = 0x12008000, 0x12009000
    relocated = lambda off: ram + off - 0xB324
    fixtures = [
        ("compare_equal", 8, 1, 0),
        ("compare_first", 8, 1, 3),
        ("compare_last", 8, 1, 3),
        ("erase_poll_success", 9, 1, 0),
        ("erase_poll_failure", 9, 0, 1),
        ("program_poll_success", 10, 1, 0),
        ("program_poll_failure", 10, 0, 0),
        ("sum_equal", 12, 1, 0),
        ("sum_changed_after_send", 12, 1, 3),
    ]
    result = []
    for label, command, poll_status, expected in fixtures:
        vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
        vm.mem_map(BASE, 0x1000000)
        vm.mem_write(BASE, data[:0x1000000])
        vm.mem_map(0x12000000, 0x10000)
        vm.mem_map(ram, 0x1000)
        vm.mem_map(0xC0001000, 0x1000)
        payload = bytes(range(256)) * 2
        vm.mem_write(source, payload)
        vm.mem_write(dest, payload)
        if label.startswith("compare_") and label != "compare_equal":
            index = 0 if label == "compare_first" else 510
            vm.mem_write(dest + index, bytes([payload[index] ^ 1]))
        writes, polls, native_returns = [], [], []

        def hook(uc, address, size, _):
            if address == BASE + 0xD9CD0:
                polls.append(
                    [uc.reg_read(arm.UC_ARM_REG_R0), uc.reg_read(arm.UC_ARM_REG_R1)]
                )
                uc.reg_write(arm.UC_ARM_REG_R0, poll_status)
                uc.reg_write(arm.UC_ARM_REG_PC, uc.reg_read(arm.UC_ARM_REG_LR))
            elif address == BASE + 0xDA2AC:
                native_returns.append(uc.reg_read(arm.UC_ARM_REG_R0))

        def written(uc, access, address, size, value, _):
            writes.append([address, size, value])

        vm.hook_add(unicorn.UC_HOOK_CODE, hook)
        vm.hook_add(unicorn.UC_HOOK_MEM_WRITE, written, begin=BASE, end=BASE + 0xFFFFFF)

        def run(start, stop, **registers):
            for name, value in registers.items():
                vm.reg_write(getattr(arm, "UC_ARM_REG_" + name.upper()), value)
            vm.emu_start(start, stop, count=1_000_000)
            require(vm.reg_read(arm.UC_ARM_REG_PC), stop, f"mailbox stop {start:#x}")

        run(BASE + 0x73CFF4, ret, sp=sp, lr=ret)
        require(
            bytes(vm.mem_read(ram, 0x62C)),
            data[0xB324:0xB950],
            "original RAM relocation",
        )
        run(BASE + 0xDA078, BASE + 0xDA0DC, sp=sp - 0x2000, lr=ret)
        receiver = vm.context_save()
        entry, poll = {
            8: (0x63015C, 0xB398),
            9: (0x630114, 0xB418),
            10: (0x63011C, 0xB4A8),
            12: (0x63013C, 0xB7E8),
        }[command]
        args = {"r0": dest, "r1": source, "r2": 256}
        if command == 12:
            args = {"r0": source, "r1": 256}
        run(BASE + entry, relocated(poll), sp=sp, lr=ret, **args)
        sender = vm.context_save()
        request = list(struct.unpack("<5I", vm.mem_read(0xC0001FD0, 20)))
        require([request[0], request[4]], [command, command], "matching request slots")
        if command in (8, 10):
            require(request[1:4], [dest, source, 256], "sender pointer/count order")
        if label == "sum_changed_after_send":
            vm.mem_write(source, bytes([payload[0] ^ 1]))
        vm.context_restore(receiver)
        run(BASE + 0xDA0DC, BASE + 0xDA2F4)
        receiver = vm.context_save()
        reply = list(struct.unpack("<3I", vm.mem_read(0xC0001FE8, 12)))
        require(reply, [command, expected, command], "native mailbox reply")
        vm.context_restore(sender)
        run(relocated(poll), relocated(0xB328))
        sender = vm.context_save()
        require(
            [u32(vm.mem_read(a, 4), 0) for a in (0xC0001FD0, 0xC0001FE0)],
            [0, 0],
            "sender clears requests",
        )
        vm.context_restore(receiver)
        run(BASE + 0xDA2F4, BASE + 0xDA0DC)
        require(
            list(struct.unpack("<3I", vm.mem_read(0xC0001FE8, 12))),
            [0, 0, 0],
            "receiver clears response",
        )
        vm.context_restore(sender)
        run(relocated(0xB328), ret)
        require(vm.reg_read(arm.UC_ARM_REG_R0), expected, "original sender return")
        if command == 9:
            require(
                writes,
                [
                    [BASE + 0xAAA, 2, 0xAA],
                    [BASE + 0x554, 2, 0x55],
                    [BASE + 0xAAA, 2, 0x80],
                    [BASE + 0xAAA, 2, 0xAA],
                    [BASE + 0x554, 2, 0x55],
                    [dest, 2, 0x30],
                ],
                "erase command writes",
            )
        if command == 10:
            chunks = 2 if poll_status else 1
            require(
                native_returns,
                [0 if poll_status else 2],
                "native program result before receiver overwrites R0",
            )
            expected_writes = [
                [BASE + 0xAAA, 2, 0xAA],
                [BASE + 0x554, 2, 0x55],
                [BASE + 0xAAA, 2, 0x20],
            ]
            for i in range(chunks):
                ptr = dest + i * 256
                expected_writes += [[ptr, 2, 0x25], [ptr, 2, 0x7F]]
                expected_writes += [
                    [
                        ptr + j * 2,
                        2,
                        int.from_bytes(
                            payload[i * 256 + j * 2 : i * 256 + j * 2 + 2], "little"
                        ),
                    ]
                    for j in range(128)
                ]
                expected_writes += [[ptr, 2, 0x29]]
            if not poll_status:
                expected_writes += [[BASE + 0xAAA, 2, 0xF0]]
            expected_writes += [[BASE + 0xAAA, 2, 0x90], [BASE + 0xAAA, 2, 0]]
            require(writes, expected_writes, "program command and payload writes")
        result.append(
            {
                "case": label,
                "request": request,
                "reply": reply,
                "sender_return": expected,
                "flash_memory_write_count": len(writes),
                "flash_memory_writes_sha256": sha256(json.dumps(writes).encode()),
                "poll_arguments": polls,
                "native_program_return": native_returns,
                "acknowledgments_cleared_by_receiver": True,
            }
        )
    return {
        "cases": result,
        "status_stub_offset": 0xD9CD0,
        "status_limit": "NOR polling returns a supplied 0/1; writes are recorded in synthetic mapped RAM, not a flash model.",
        "program_result_loss": "Original receiver resets result slot to zero and never stores D9EB4 return before command-A acknowledgment.",
    }


def primary_control_cases(data):
    import unicorn
    from unicorn import arm_const as arm

    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    vm.mem_map(0x12000000, 0x10000)
    sp, ret, dest, halfwords = 0x12008000, 0x12009000, 0x02080000, 256
    zero = {
        0x72C988,
        0x63012C,
        0x630134,
        0x81B5D8,
        0x81B674,
        0x81B68C,
        0x630144,
        0x63014C,
        0x630124,
    }
    state = {}

    def hook(uc, address, size, _):
        off = address - BASE
        if off not in zero | {0x63013C, 0x63015C, 0x630114, 0x63011C}:
            return
        value = 0
        if off == 0x63013C:
            state["calls"].append("sum")
            value = state["sum"]
            require(
                [uc.reg_read(arm.UC_ARM_REG_R0), uc.reg_read(arm.UC_ARM_REG_R1)],
                [0x40459204, halfwords],
                "staging sum arguments",
            )
        elif off == 0x63015C:
            state["calls"].append("compare")
            value = state["compare"].pop(0)
        elif off == 0x630114:
            state["calls"].append("erase")
            value = state["erase"]
        elif off == 0x63011C:
            state["calls"].append("program")
            value = state["program"]
        if off in {0x63015C, 0x630114, 0x63011C}:
            require(uc.reg_read(arm.UC_ARM_REG_R0), dest, "controller destination")
            if off != 0x630114:
                require(
                    [uc.reg_read(arm.UC_ARM_REG_R1), uc.reg_read(arm.UC_ARM_REG_R2)],
                    [0x40459204, halfwords],
                    "controller source/count",
                )
        uc.reg_write(arm.UC_ARM_REG_R0, value)
        uc.reg_write(arm.UC_ARM_REG_PC, uc.reg_read(arm.UC_ARM_REG_LR))

    vm.hook_add(unicorn.UC_HOOK_CODE, hook)
    results = []
    for label, total, before, erase, program, after, expected, calls in [
        ("already_equal", 0, 0, 0, 0, 0, 0, ["sum", "compare"]),
        ("equal_with_bad_staging_sum", 3, 0, 0, 0, 0, 0, ["sum", "compare"]),
        ("bad_staging_sum", 3, 3, 0, 0, 0, 3, ["sum", "compare"]),
        ("erase_failure", 0, 3, 1, 0, 0, 1, ["sum", "compare", "erase"]),
        (
            "supplied_program_failure",
            0,
            3,
            0,
            2,
            0,
            2,
            ["sum", "compare", "erase", "program"],
        ),
        (
            "zero_program_reply_but_mismatch",
            0,
            3,
            0,
            0,
            3,
            3,
            ["sum", "compare", "erase", "program", "compare"],
        ),
        (
            "write_and_compare_ok",
            0,
            3,
            0,
            0,
            0,
            0,
            ["sum", "compare", "erase", "program", "compare"],
        ),
    ]:
        state.clear()
        state.update(
            sum=total, compare=[before, after], erase=erase, program=program, calls=[]
        )
        for name, value in {"sp": sp, "lr": ret, "r1": dest, "r2": halfwords}.items():
            vm.reg_write(getattr(arm, "UC_ARM_REG_" + name.upper()), value)
        vm.emu_start(BASE + 0x599914, ret, count=10000)
        require(vm.reg_read(arm.UC_ARM_REG_PC), ret, "primary controller return")
        require(vm.reg_read(arm.UC_ARM_REG_R0), expected, label)
        require(state["calls"], calls, label + " call order")
        results.append(
            {
                "case": label,
                "supplied_sum": total,
                "supplied_compare": [before, after],
                "supplied_erase": erase,
                "supplied_program": program,
                "return": expected,
                "calls": calls,
            }
        )
    return {
        "cases": results,
        "stub_offsets": sorted(zero | {0x63013C, 0x63015C, 0x630114, 0x63011C}),
        "limit": "Controller decision tests supply wrapper results independently. They are not an end-to-end flash run; the actual command-A receiver never publishes the native failure value 2.",
    }


def updater_cases(data):
    import unicorn
    from unicorn import arm_const as arm

    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    vm.mem_map(0x12000000, 0x10000)
    vm.mem_map(0x40304000, 0x4000)
    image, sp, ret = 0x10000000, 0x12008000, 0x12009000
    vm.mem_write(0x40307E14, struct.pack("<I", image))
    va = lambda off: 0x40304000 + off - 0xB324
    state = {}
    ui = {
        0xC4AC,
        0xC4D8,
        0xC50C,
        0xC540,
        0xC644,
        0xC660,
        0xC67C,
        0xC438,
        0xC698,
        0xC6F0,
        0xC858,
    }
    system = {BASE + n for n in (0x73D6A8, 0x72C988, 0x72CE58, 0x7B1664)}

    def hook(uc, address, size, _):
        off = address - 0x40304000 + 0xB324
        value = 0
        if off in ui or off in {0xB4F8, 0xB588} or address in system:
            pass
        elif state.get("mode") == "block" and off in {0xB358, 0xB3E8, 0xB468}:
            names = {0xB358: "compare", 0xB3E8: "erase", 0xB468: "program"}
            name = names[off]
            state["calls"].append(name)
            require(
                uc.reg_read(arm.UC_ARM_REG_R0),
                state["dest"],
                "update block destination",
            )
            if name != "erase":
                require(
                    [uc.reg_read(arm.UC_ARM_REG_R1), uc.reg_read(arm.UC_ARM_REG_R2)],
                    [image + state["dest"] - BASE, 0x10000],
                    "image-relative update source",
                )
            value = state[name].pop(0)
        elif state.get("mode") == "sectors" and off == 0xBFD0:
            destination = uc.reg_read(arm.UC_ARM_REG_R0)
            require(uc.reg_read(arm.UC_ARM_REG_R1), 0x10000, "sector halfword count")
            state["destinations"].append(destination)
            value = 3 if destination == state["fail_address"] else 0
        elif state.get("mode") == "retries" and off == 0xC07C:
            state["attempts"] += 1
            value = 3 if state["attempts"] <= state["failures"] else 0
        else:
            return
        uc.reg_write(arm.UC_ARM_REG_R0, value)
        uc.reg_write(arm.UC_ARM_REG_PC, uc.reg_read(arm.UC_ARM_REG_LR))

    vm.hook_add(unicorn.UC_HOOK_CODE, hook)

    def run(start, stop=ret, **registers):
        for name, value in {"sp": sp, "lr": ret, **registers}.items():
            vm.reg_write(getattr(arm, "UC_ARM_REG_" + name.upper()), value)
        vm.emu_start(start, stop, count=1_000_000)
        require(vm.reg_read(arm.UC_ARM_REG_PC), stop, "update fixture stop")
        return vm.reg_read(arm.UC_ARM_REG_R0)

    run(BASE + 0x73CF94)
    require(
        bytes(vm.mem_read(va(0xB950), 0x361E)), data[0xB950:0xEF6E], "update RAM copy"
    )
    run(BASE + 0x73CFF4)
    entries = []
    for auxiliary_result in (0, 1):
        stop = va(0xC278) if auxiliary_result else BASE + 0x5D667C
        run(BASE + 0x5D6664, stop, r4=auxiliary_result)
        args = [vm.reg_read(arm.UC_ARM_REG_R0), vm.reg_read(arm.UC_ARM_REG_R1)]
        if auxiliary_result:
            require(args, [2, 0], "normal update kind and variant")
        entries.append(
            {
                "auxiliary_return": auxiliary_result,
                "entered_ram_updater": bool(auxiliary_result),
                "stop_va": stop,
            }
        )
    blocks = []
    for before, erase, program, after in [
        (0, 0, 0, 0),
        (3, 1, 0, 0),
        (3, 0, 2, 0),
        (3, 0, 0, 3),
        (3, 0, 0, 0),
    ]:
        state.clear()
        state.update(
            mode="block",
            dest=0x02020000,
            compare=[before, after],
            erase=[erase],
            program=[program],
            calls=[],
        )
        expected = before if before != 3 else erase or program or after
        got = run(va(0xBFD0), r0=state["dest"], r1=0x10000, r2=2, r3=0)
        require(got, expected, "actual update block result")
        calls = ["compare"] + (
            []
            if before != 3
            else ["erase"]
            + ([] if erase else ["program"] + ([] if program else ["compare"]))
        )
        require(state["calls"], calls, "actual update block order")
        blocks.append(
            {
                "supplied_before_erase_program_after": [before, erase, program, after],
                "return": got,
                "calls": calls,
            }
        )
    sectors = []
    base_order = [BASE + i * 0x20000 for i in range(1, 128) if i not in range(13, 23)]
    for variant, fail in [
        (0, None),
        (1, None),
        (0, BASE + 0x20000),
        (1, BASE + 0x1A0000),
        (1, BASE + 0x2C0000),
        (0, BASE),
    ]:
        state.clear()
        state.update(mode="sectors", fail_address=fail, destinations=[])
        got = run(va(0xC07C), r0=2, r1=variant)
        expected = base_order.copy()
        if fail in expected:
            expected = expected[: expected.index(fail) + 1]
        else:
            if variant == 1:
                expected += [BASE + 0x1A0000, BASE + 0x2C0000]
            if fail != BASE + 0x2C0000:
                expected += [BASE]
        require(state["destinations"], expected, "actual update sector schedule")
        expected_return = 3 if fail is not None and fail != BASE + 0x1A0000 else 0
        require(got, expected_return, "sector failure propagation")
        sectors.append(
            {
                "variant": variant,
                "supplied_failure_address": fail,
                "return": got,
                "sector_indices": [(x - BASE) // 0x20000 for x in expected],
            }
        )
    retries = []
    for failures in (0, 1, 16):
        state.clear()
        state.update(mode="retries", failures=failures, attempts=0)
        run(BASE + 0x630174, va(0xC2F0), r0=2, r1=0)
        require(state["attempts"], min(failures + 1, 16), "whole-pass retry count")
        retries.append(
            {
                "supplied_failed_passes": failures,
                "attempts": state["attempts"],
                "stop": "before final MMIO/power loop",
            }
        )
    return {
        "post_auxiliary_entries": entries,
        "block_control_cases": blocks,
        "sector_cases": sectors,
        "whole_pass_retry_cases": retries,
        "normal_update_variant": 0,
        "normal_update_skipped_sector_indices": list(range(13, 23)),
        "sector_bytes": 0x20000,
        "normal_update_first_sector_last": True,
        "variant1_first_special_sector_status_overwritten": True,
        "stub_ram_offsets": sorted(ui | {0xB4F8, 0xB588}),
        "stub_system_vas": sorted(system),
        "limits": "Block tests supply mailbox-wrapper statuses; sector tests supply block results; pass-retry tests supply sector-pass results. Original decisions execute, but these layers are not an end-to-end flash model.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--emulate", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    data = load_image(args.decoded)
    result = verify(data)
    if args.emulate:
        result["emulation"] = {
            "auxiliary": auxiliary_cases(data),
            "serial": serial_cases(data),
            "primary_mailbox": primary_mailbox_cases(data),
            "primary_control": primary_control_cases(data),
            "actual_updater": updater_cases(data),
        }
    if args.compare:
        require_snapshot(result, args.compare, "installation snapshot")
    text = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")


if __name__ == "__main__":
    main()
