"""Replay native preserved-config callers and both live RAM marker checks.

SPDX-License-Identifier: GPL-2.0-only
"""

from pathlib import Path
from struct import pack
from collections import Counter
import hashlib
import json
import argparse
import os
import tempfile
from inspect_firmware import FIRMWARE_SIZE
from verify_findings import DECODED_SHA256, require, require_snapshot, sha256
from verify_tone_path import load_image


def probe(data):
    """Run a single-threaded replay; temporarily capture the baseline's VM factory."""
    require(len(data), FIRMWARE_SIZE, "decoded length")
    require(
        sha256(data),
        DECODED_SHA256,
        "decoded identity",
    )
    import unicorn as uc
    from unicorn import arm_const as arm
    import verify_preserved_config as cfg
    import verify_preserved_dispatch as dispatch

    source_checks = dispatch.check_caller_source(data)
    original_uc = uc.Uc
    holder, widths = [], Counter()
    instruction_digest = hashlib.sha256()

    def factory(*args, **kwargs):
        vm = original_uc(*args, **kwargs)
        holder.append(vm)

        def audit(cpu, pc, size, _):
            offset = pc - cfg.BASE
            require(
                0 <= offset < len(data) - size, True, "instruction inside decoded image"
            )
            actual = bytes(cpu.mem_read(pc, size))
            require(
                actual,
                data[offset : offset + size],
                "executed bytes equal original image",
            )
            widths[size] += 1
            instruction_digest.update(pack("<II", offset, size) + actual)

        original_model = vm.ctl_set_cpu_model

        def set_model(model):
            original_model(model)
            vm.hook_add(uc.UC_HOOK_CODE, audit)

        vm.ctl_set_cpu_model = set_model
        return vm

    cfg.uc.Uc = factory
    try:
        baseline = cfg.probe(data)
    finally:
        cfg.uc.Uc = original_uc
    expected = json.loads(
        (Path(__file__).parent / "analysis/preserved-config.json").read_bytes()
    )["replay"]
    require(
        json.dumps(baseline, sort_keys=True),
        json.dumps(expected, sort_keys=True),
        "original config baseline unchanged",
    )
    require(len(holder), 1, "one connected VM")
    vm = holder[0]
    config, capture = 0x10020000, 0x10030000
    controller, worker, command = 0x10040000, 0x10050000, 0x10060000
    command_stack, worker_stack, consumer_stack, sentinel = (
        0x100D0000,
        0x100C0000,
        0x100F0000,
        0x100F1000,
    )

    def reg(name, value=None):
        key = getattr(arm, "UC_ARM_REG_" + name.upper())
        if value is None:
            return vm.reg_read(key)
        vm.reg_write(key, value)

    def read(address, size=4):
        return bytes(vm.mem_read(address, size))

    def word(address, size=4):
        return int.from_bytes(read(address, size), "little")

    def put(address, value, size=4):
        vm.mem_write(address, value.to_bytes(size, "little"))

    segments, calls, marker_reads, flag_reads, flag_writes, validations = (
        [],
        [],
        [],
        [],
        [],
        [],
    )

    def run(entry, *args, end=None, sp=command_stack, **registers):
        for name, value in dict(sp=sp, lr=sentinel, **registers).items():
            reg(name, value)
        for i, value in enumerate(args):
            reg("r" + str(i), value)
        stop = sentinel if end is None else cfg.BASE + end
        vm.ctl_flush_tb()
        vm.emu_start(cfg.BASE + entry, stop, count=1000000)
        require(reg("pc"), stop, "native segment ends at declared boundary")
        segments.append(
            {
                "entry": entry,
                "stop_va": stop,
                "prepared_sp": sp,
                "prepared_args": list(args),
                "prepared_registers": registers,
            }
        )
        return reg("r0")

    def call_hook(_vm, pc, _size, _):
        calls.append((pc - cfg.BASE, reg("r0"), reg("r1"), reg("r2")))

    for pc in (
        0x632CC4,
        0x6355D0,
        0x6352A0,
        0x74F974,
        0x74F944,
        0x74ED98,
        0x78595C,
        0x74F9BC,
        0x74F9F8,
    ):
        vm.hook_add(uc.UC_HOOK_CODE, call_hook, begin=cfg.BASE + pc, end=cfg.BASE + pc)

    def memory_read(_vm, _kind, address, size, _value, _):
        item = (reg("pc") - cfg.BASE, address, size, word(address, size))
        (marker_reads if address in cfg.RAM else flag_reads).append(item)

    for address in (*cfg.RAM, config + 0xC, config + 0xD):
        vm.hook_add(uc.UC_HOOK_MEM_READ, memory_read, begin=address, end=address)

    def memory_write(_vm, _kind, address, size, value, _):
        flag_writes.append((reg("pc") - cfg.BASE, address, size, value))

    for address in (config + 0xC, config + 0xD):
        vm.hook_add(uc.UC_HOOK_MEM_WRITE, memory_write, begin=address, end=address)
    vm.hook_add(uc.UC_HOOK_MEM_WRITE, memory_write, begin=capture, end=capture + 0x7F)

    vm.hook_add(
        uc.UC_HOOK_CODE,
        lambda _vm, _pc, _sz, _: validations.append(
            (reg("r1") - config - 0x18) // 0x10
        ),
        begin=cfg.BASE + 0x74E8D0,
        end=cfg.BASE + 0x74E8D0,
    )
    put(controller + 0x30, worker)
    expected_ram = bytearray(read(cfg.RAM[0], 0x20000))
    require(read(config + 0xC, 2), b"\1\1", "baseline native flags both valid")

    def consume(flags):
        cases = []
        for name, markers in (
            ("both_valid", (cfg.MARKER, cfg.MARKER)),
            ("first_invalid", (0, cfg.MARKER)),
            ("second_invalid", (cfg.MARKER, 0)),
            ("both_invalid", (0, 0)),
            ("restored", (cfg.MARKER, cfg.MARKER)),
        ):
            for address, value in zip(cfg.RAM, markers):
                put(address, value)
            before_config = read(config, 0x224)
            before_ram = read(cfg.RAM[0], 0x20000)
            marker_reads.clear()
            flag_reads.clear()
            flag_writes.clear()
            calls.clear()
            put(capture + 0x4A, 0xA5, 1)
            before_capture = bytearray(read(capture, 0x80))
            run(0x65EA68, capture, end=0x65EAA4, sp=consumer_stack)
            c = word(capture + 0x4A, 1)
            d = run(0x593740, end=0x59374C, sp=consumer_stack)
            result = tuple(
                int(all(x == cfg.MARKER for x in markers)) * value for value in flags
            )
            require((c, d), result, "two live markers gate both native consumers")
            require(
                read(config, 0x224), before_config, "consumer preserves entire config"
            )
            require(
                read(cfg.RAM[0], 0x20000),
                before_ram,
                "consumer preserves entire backing",
            )
            require(
                marker_reads,
                [
                    (0x72E004, cfg.RAM[0], 4, markers[0]),
                    (0x72DDEC, cfg.RAM[1], 4, markers[1]),
                ]
                * 2,
                "both native marker reads in both consumers",
            )
            expected_reads = (
                [
                    (0x74F9D4, config + 0xC, 1, flags[0]),
                    (0x74FA10, config + 0xD, 1, flags[1]),
                ]
                if markers[0] == cfg.MARKER
                else []
            )
            require(flag_reads, expected_reads, "native conditional C/D reads")
            require(
                flag_writes,
                [
                    (0x65EA80, capture + 0x47, 1, 1),
                    (0x65EA88, capture + 0x48, 1, 1),
                    (0x65EA8C, capture + 0x49, 1, 0),
                    (0x65EAA0, capture + 0x4A, 1, result[0]),
                ],
                "four original stores in watched capture prefix",
            )
            before_capture[0x47:0x4B] = bytes([1, 1, 0, result[0]])
            require(
                read(capture, 0x80),
                bytes(before_capture),
                "entire watched capture prefix",
            )
            require(
                [(pc, r0) for pc, r0, _, _ in calls],
                [
                    (0x78595C, cfg.SERVICE_OWNER),
                    (0x74F9BC, config),
                    (0x78595C, cfg.SERVICE_OWNER),
                    (0x74F9F8, config),
                ],
                "same service-config alias at both consumers",
            )
            cases.append(
                {
                    "case": name,
                    "live_ram_markers": markers,
                    "native_config_flags": flags,
                    "capture_4a": c,
                    "neighbor_getter_r0": d,
                    "neighbor_stop_before": 0x59374C,
                    "marker_reads": list(marker_reads),
                    "config_flag_reads": list(flag_reads),
                    "native_writes": list(flag_writes),
                    "config_sha256_unchanged": sha256(before_config),
                    "backing_sha256_unchanged": sha256(before_ram),
                }
            )
        return cases

    linked = []
    for label, selector, flag, counts, flags, wait in (
        ("C_count_suppressed", 0, 0, (2, 3), (1, 1), 0),
        ("C_count_invalid", 0, 1, (2, 1), (0, 1), 0),
        ("C_restored", 0, 1, (1, 1), (1, 1), 0x3FF),
        ("D_count_invalid", 1, 1, (2, 1), (1, 0), 0),
        ("D_restored", 1, 1, (1, 1), (1, 1), 0x3FF),
        ("D_count_suppressed", 1, 0, (2, 3), (1, 1), 0),
    ):
        put(command + 0x858, 2, 1)
        put(command + 0x859, 4, 1)
        put(command + 8, selector)
        for i in range(3):
            vm.mem_write(
                command + 0xC + 0xC * i, pack("<III", 0x101 + i, 0x201 + i, 0x310 + i)
            )
        calls.clear()
        run(0x7B5954, controller, 0, command, end=0x632CD8)
        submit = next(item for item in calls if item[0] == 0x632CC4)
        require(submit[1], worker, "planner submits supplied controller worker")
        list_address = submit[2]
        plan_sp = list_address - 0xC4
        request = word(worker + 0x28C)
        require(request, plan_sp, "original first request stays on caller frame")
        require(
            read(worker + 0x28C, 0x40),
            read(list_address, 0x40),
            "original full pointer-list copy",
        )
        require(word(plan_sp + 0x11C), config, "caller saves same native config")
        indices = (0, 1) if selector == 0 else (6, 7)
        require(
            (word(request + 4), word(request + 8)),
            indices,
            "native selector resolves requested group",
        )
        put(worker + 0x380, 0)
        run(0x630DC4, end=0x630DD4, r4=worker, r5=2)
        calls.clear()
        run(0x636694, worker, end=0x6352D4, sp=worker_stack)
        require(
            [(pc, r0, r1) for pc, r0, r1, _ in calls if pc in (0x6355D0, 0x6352A0)],
            [(0x6355D0, worker, worker + 0x28C), (0x6352A0, worker, request)],
            "worker follows original copied request",
        )
        require(
            (reg("sb"), reg("r8"), reg("sl")),
            (config, *indices),
            "worker resolves same config and indices",
        )
        frame = reg("sp")
        # shortcut: calculation and wait results are supplied; scheduler is unrun.
        vm.mem_write(frame + 0xF8, pack("<B3x4I", flag, *counts, 4, 4))
        calls.clear()
        run(0x635534, end=0x6355B4, sp=frame)
        expected_setters = (
            [(0x74F974, config, index, count) for index, count in zip(indices, counts)]
            if flag
            else []
        )
        expected_setters += [(0x74F944, config, index, 4) for index in indices]
        require(calls, expected_setters, "native result gate and setters")
        setter_calls = list(calls)
        if flag:
            for index, count in zip(indices, counts):
                bank = int(index >= 6)
                offset = (
                    cfg.RAM[bank]
                    - cfg.RAM[0]
                    + 0x14
                    + 8 * cfg.GROUPS[bank].index(index)
                )
                expected_ram[offset : offset + 4] = pack("<I", count)
        calls.clear()
        validations.clear()
        flag_writes.clear()
        run(0x7B5128, wait, end=0x7B5150, sp=plan_sp)
        require(
            [(pc, r0) for pc, r0, _, _ in calls],
            [(0x74ED98, config)],
            "same original caller commits saved config",
        )
        require(
            read(cfg.RAM[0], 0x20000),
            bytes(expected_ram),
            "only expected header counts change in full backing",
        )
        require(
            read(config + 0xC, 2),
            bytes(flags),
            "original independent validity producers",
        )
        require(
            flag_writes,
            [
                (0x74EE3C, config + 0xC, 1, flags[0]),
                (0x74EE48, config + 0xD, 1, flags[1]),
            ],
            "original C/D producer writes",
        )
        expected_visits = ([0] if flags[0] == 0 else list(cfg.GROUPS[0])) + (
            [6] if flags[1] == 0 else list(cfg.GROUPS[1])
        )
        require(
            validations, expected_visits, "native group error exits are independent"
        )
        require(
            (word(command + 4), word(command + 8)),
            (0x19, wait),
            "original command response",
        )
        writes, visits = list(flag_writes), list(validations)
        linked.append(
            {
                "case": label,
                "selector": selector,
                "request_va": request,
                "caller_frame_va": plan_sp,
                "worker_frame_va": frame,
                "config_va": config,
                "prepared_result_flag": flag,
                "prepared_counts": counts,
                "prepared_lengths": [4, 4],
                "prepared_wait_result": wait,
                "native_setters": setter_calls,
                "native_flag_writes": writes,
                "validated_indices": visits,
                "native_flags": flags,
                "marker_controls": consume(flags),
            }
        )

    return {
        "schema_version": 1,
        "firmware_version": "1.12",
        "cpu_model": "Unicorn Cortex-A9; not a full camera emulator",
        "decoded_sha256": sha256(data),
        "code_va_base": cfg.BASE,
        "unicorn_version": uc.__version__,
        "original_instruction_checks": {
            "width_counts": dict(widths),
            "ordered_pc_bytes_sha256": instruction_digest.hexdigest(),
        },
        "static_caller_checks": source_checks,
        "baseline_replay_unchanged": True,
        "execution_replacements": [],
        "connected_cases": linked,
        "execution_segments": segments,
        "limits": [
            "Same VM and native config object; original provider load/init and caller plan/copy/worker update/commit/consumer slices execute in prepared call frames.",
            "Only the first request from each original copied list is executed by the worker prefix/tail. Remaining planned requests and the full processing loop are unrun.",
            "Controller worker link, command inputs, result flag/counts/lengths, post-lock bit inputs and wait return are supplied; computation, lock/wake/wait scheduling and actual transport are unrun.",
            "Live marker words are changed by the host fixture only between consumer runs. Native flag bytes are produced by original validators; consumers do not rewrite the flags or backing.",
            "The +0xC/+0xD bytes are config validity flags, distinct from the 32-bit marker words at80000000/80010000. D count-error and both live-marker branches execute, but this does not establish real event/menu/camera reachability.",
            "Neighbor R0 is the original74F9F8 getter result observed before59374C; the enclosing caller does not return. Capture execution stops before65EAA4 after four stores at+47/+48/+49/+4A; the whole capture is unrun.",
            "No physical Flash, DMA, SD, UART, camera operation or device I/O occurs. The input image is read-only; the CLI rechecks its complete identity before emitting evidence.",
        ],
    }


def write_output(path, payload):
    """Create a fresh evidence file without replacing existing paths or aliases."""
    with tempfile.TemporaryDirectory(
        dir=path.parent, prefix=".preserved-marker-"
    ) as directory:
        staged = Path(directory) / "evidence.json"
        with staged.open("x", encoding="utf-8", newline="\n") as stream:
            stream.write(payload)
        os.link(staged, path)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument(
        "--compare", type=Path, help="compare all JSON values and types"
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="also save JSON to a new file; existing paths are rejected",
    )
    args = parser.parse_args(argv)
    try:
        if args.output is not None and os.path.lexists(args.output):
            raise FileExistsError("refusing to replace existing output")
        data = load_image(args.decoded)
        result = probe(data)
        require(load_image(args.decoded), data, "input bytes unchanged after replay")
        result["input_file_rechecked"] = True
        if args.compare:
            require_snapshot(result, args.compare, "preserved live marker replay")
        payload = json.dumps(result, indent=2) + "\n"
        if args.output:
            write_output(args.output, payload)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(payload, end="")


if __name__ == "__main__":
    main()
