"""Replay K-3 II preserved-result continuity and parameter production separately.

SPDX-License-Identifier: GPL-2.0-only
The input is the original decoded image. These are bounded CPU and RAM replays.
"""

if not __debug__:
    raise RuntimeError("Assertions required; -O unsupported")

import argparse
from collections import Counter
from hashlib import sha256 as digest
import json
import os
from pathlib import Path
from struct import pack
import sys
from types import ModuleType


ROOT = Path(__file__).resolve().parent
DECODED_SIZE = 16838656
DECODED_SHA = "1b87bf35b290e4b4e8910beb4055c34f97504b65e249ad65e5ccc0402bd14cfc"
BASE = 0x02000000
DEPENDENCIES = {
    "inspect_firmware.py": "5813ab545e4c5bd14b9c52b47e0c0af4ad34e3ca06aa7c843d9cd3a2238cf871",
    "verify_findings.py": "9086a9ec89aee7932799353278e1c666d8defc9e55d3c72923388d555fec7a41",
    "verify_tone_path.py": "b1c01007af2dd921077289d05204a6c846ea57059f0aceda6c5101149358f344",
    "verify_preserved_config.py": "16024df64a6af3c914c634303838a51d8bda202ee548bf1523cb92cbcc39f6db",
    "analysis/preserved-config.json": "0a9e21c25e40846710732fa15ba7f252cf04a6a6d69ab94d02ef0c8899cafa9b",
}
CASE_SHA = {
    "result_to_response": "c92ad83585de9ccba377b6a31ba0155e144c2a4cfb4e26d84ee15de03624263f",
    "worker_parameter_production": "4381a0824181fc9ae43c2f6ae4e13fc69d90159ec4ed89e62c4b2321dc3372d9",
}


def sha256(data):
    return digest(data).hexdigest()


def require(actual, expected, context):
    if actual != expected:
        raise ValueError(f"{context}: expected {expected!r}, got {actual!r}")


def read_decoded(path):
    if not path.is_file() or path.stat().st_size != DECODED_SIZE:
        raise ValueError(
            f"Original decoded carrier of {DECODED_SIZE:,} bytes is required"
        )
    with path.open("rb") as stream:
        data = stream.read(DECODED_SIZE + 1)
    require(len(data), DECODED_SIZE, "Decoded input size")
    require(sha256(data), DECODED_SHA, "Decoded input SHA-256")
    return data


def pinned_sources():
    sources = {}
    for name, expected in DEPENDENCIES.items():
        path = ROOT / name
        source = path.read_bytes().replace(b"\r\n", b"\n")
        if sha256(source) != expected:
            raise ValueError(f"Dependency SHA-256 mismatch: {name}")
        sources[path] = source
    return sources


def load_dependencies():
    sources = pinned_sources()
    for path, source in sources.items():
        if path.suffix == ".py":
            # Execute checked bytes, bypassing cached bytecode.
            module = ModuleType(path.stem)
            module.__file__ = str(path)
            exec(compile(source, module.__file__, "exec"), module.__dict__)
            sys.modules[path.stem] = module
    return (
        sys.modules["verify_preserved_config"],
        json.loads(sources[ROOT / "analysis/preserved-config.json"])["replay"],
    )


def replay_response(data, label, mode, gate, counts, cfg, expected):
    import unicorn as uc
    from unicorn import arm_const as arm

    original_uc = uc.Uc
    holder, widths = [], Counter()
    code_digest = digest()

    def factory(*args, **kwargs):
        vm = original_uc(*args, **kwargs)
        holder.append(vm)
        original_model = vm.ctl_set_cpu_model

        def set_model(model):
            original_model(model)

            def audit(cpu, pc, size, _):
                offset = pc - cfg.BASE
                require(0 <= offset <= len(data) - size, True, "original image code")
                raw = bytes(cpu.mem_read(pc, size))
                require(raw, data[offset : offset + size], "original executed bytes")
                widths[size] += 1
                code_digest.update(pack("<II", offset, size) + raw)

            vm.hook_add(uc.UC_HOOK_CODE, audit)

        vm.ctl_set_cpu_model = set_model
        return vm

    cfg.uc.Uc = factory
    try:
        baseline = cfg.probe(data)
    finally:
        cfg.uc.Uc = original_uc
    require(
        json.dumps(baseline, sort_keys=True),
        json.dumps(expected, sort_keys=True),
        "baseline preserved",
    )
    require(len(holder), 1, "one VM")
    vm = holder[0]
    baseline_image = bytes(vm.mem_read(cfg.BASE, 0x1000000))
    expected_baseline_image = bytearray(data[:0x1000000])
    fixture_overlays = []
    for address, size in zip(
        (*cfg.PRIMARY, *cfg.BACKUP), (0x10000, 0xE000, 0x10000, 0xE000)
    ):
        offset = address - cfg.BASE
        expected_baseline_image[offset : offset + size] = baseline_image[
            offset : offset + size
        ]
        fixture_overlays.append({"address": address, "size": size})
    require(
        sha256(baseline_image),
        sha256(expected_baseline_image),
        "baseline only overlays declared synthetic Flash records",
    )
    vm.reg_write(arm.UC_ARM_REG_C1_C0_2, 0xF00000)
    vm.reg_write(arm.UC_ARM_REG_FPEXC, 0x40000000)
    config, controller, worker, command = 0x10020000, 0x10040000, 0x10050000, 0x10060000
    engine_command, parameters, owner = 0x10070000, 0x10072000, 0x10074000
    command_sp, worker_sp, auxiliary_sp, sentinel = (
        0x100D0000,
        0x100C0000,
        0x100B0000,
        0x100F1000,
    )
    segments, calls, writes, host_inputs, image_writes, mailbox_reads = (
        [],
        [],
        [],
        [],
        [],
        [],
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

    def put(address, value, size=4, provenance="prepared input"):
        host_inputs.append(
            {"address": address, "size": size, "value": value, "provenance": provenance}
        )
        vm.mem_write(address, value.to_bytes(size, "little"))

    def resume(entry, stop, note):
        before = {
            key: reg(key)
            for key in ("sp", "lr", "r0", "r1", "r4", "r7", "r8", "r9", "r10")
        }
        vm.ctl_flush_tb()
        try:
            vm.emu_start(cfg.BASE + entry, stop, count=1000000)
        except uc.UcError as error:
            raise ValueError(
                f"{entry:#x}: stopped at PC {reg('pc'):#x}: {error}"
            ) from error
        require(reg("pc"), stop, f"stop {note}")
        segments.append(
            {
                "entry_offset": entry,
                "stop_va": stop,
                "note": note,
                "entry_registers": before,
            }
        )

    def invoke(entry, args=(), end=None, sp=auxiliary_sp, **registers):
        for name, value in dict(sp=sp, lr=sentinel, **registers).items():
            reg(name, value)
        for index, value in enumerate(args):
            reg("r" + str(index), value)
        resume(
            entry, sentinel if end is None else cfg.BASE + end, "prepared invocation"
        )

    def observe_call(_vm, pc, _size, _):
        calls.append(
            {
                "pc_offset": pc - cfg.BASE,
                "r0": reg("r0"),
                "r1": reg("r1"),
                "r2": reg("r2"),
                "sp": reg("sp"),
            }
        )

    for offset in (
        0x78558C,
        0x71ADF0,
        0x712898,
        0x545268,
        0x74F974,
        0x74F944,
        0x74ED98,
        0x6352A0,
        0x63561C,
        0x6366E4,
        0x632D1C,
        0x7B5128,
    ):
        vm.hook_add(
            uc.UC_HOOK_CODE,
            observe_call,
            begin=cfg.BASE + offset,
            end=cfg.BASE + offset,
        )

    def observe_write(_vm, _kind, address, size, value, _):
        writes.append(
            {
                "pc_offset": reg("pc") - cfg.BASE,
                "address": address,
                "size": size,
                "value": value,
            }
        )

    vm.hook_add(
        uc.UC_HOOK_MEM_WRITE,
        lambda _vm, _kind, address, size, value, _: image_writes.append(
            {
                "pc_offset": reg("pc") - cfg.BASE,
                "address": address,
                "size": size,
                "value": value,
            }
        ),
        begin=cfg.BASE,
        end=cfg.BASE + 0xFFFFFF,
    )
    vm.hook_add(
        uc.UC_HOOK_MEM_READ,
        lambda _vm, _kind, address, size, _value, _: mailbox_reads.append(
            {
                "pc_offset": reg("pc") - cfg.BASE,
                "address": address,
                "size": size,
                "value": word(address, size),
            }
        ),
        begin=worker + 0x2CC,
        end=worker + 0x2CD,
    )

    response_stores = []

    def observe_response(_vm, _kind, address, size, value, _):
        response_stores.append((reg("pc") - BASE, address, size, value))

    for start, end in (
        (engine_command + 0xF8, engine_command + 0x10B),
        (config + 0xC, config + 0xD),
        (worker + 0x2CC, worker + 0x2CD),
    ):
        vm.hook_add(uc.UC_HOOK_MEM_WRITE, observe_write, begin=start, end=end)
    put(controller + 0x30, worker, provenance="controller-to-worker link")
    put(command + 0x858, 2, 1, "command family")
    put(command + 0x859, 4, 1, "command type")
    put(command + 8, 4, provenance="native selector4 has one active request")
    for index in range(3):
        for field, value in enumerate((0x101 + index, 0x201 + index, 0x310 + index)):
            put(
                command + 0xC + 12 * index + 4 * field,
                value,
                provenance="source command payload",
            )
    invoke(0x7B5954, (controller, 0, command), end=0x632CD8, sp=command_sp)
    submit_context = vm.context_save()
    submit_sp = reg("sp")
    plan_sp = submit_sp + 8
    require(word(submit_sp + 4), cfg.BASE + 0x7B5128, "actual submit return link")
    require(reg("r4"), worker, "actual submit owner")
    request = word(worker + 0x28C)
    require(request, plan_sp, "first original request on caller frame")
    require(word(worker + 0x290), 0, "native selector4 list terminator")
    require((word(request + 4), word(request + 8)), (24, 25), "selector4 indices")
    require(word(plan_sp + 0x11C), config, "same saved native config")

    put(worker + 0x380, 0, provenance="initial worker flags")
    invoke(0x630DC4, end=0x630DD4, r4=worker, r5=2)
    put(worker + 0x2D9, 1, 1, "no-retry state supplied; upstream lifecycle unrun")
    put(
        worker + 0x2CC,
        0xA55A,
        2,
        "stale mailbox sentinel; original STRH must replace it",
    )
    put(0x4041D88C, 1, provenance="singleton initialization guard")
    put(
        0x40483EC4 + 0x7C,
        1,
        provenance="property0x1E already satisfied; no notification",
    )
    invoke(0x636694, (worker,), end=0x6352DC, sp=worker_sp)
    frame = reg("sp")
    require(
        read(frame + 0xF8, 0x14),
        bytes(0x14),
        "native worker constructor initializes result",
    )
    worker_context = vm.context_save()
    vm.hook_add(
        uc.UC_HOOK_MEM_WRITE, observe_write, begin=frame + 0xF8, end=frame + 0x10B
    )
    resume(
        0x635528,
        cfg.BASE + 0x634970,
        "after omitted worker parameter setup/output clearing; original BL and core prologue; before service calls",
    )
    core_context = vm.context_save()
    core_sp = reg("sp")
    require(
        word(core_sp + 0x18), frame, "native core prologue saved worker-frame pointer"
    )

    invoke(0x754970, (engine_command,))
    require(
        read(engine_command + 0xF8, 0x14),
        bytes(0x14),
        "native engine constructor initializes result",
    )
    put(
        engine_command + 0x10C,
        parameters,
        provenance="processing parameter object link",
    )
    put(
        parameters,
        mode,
        provenance="parameter mode word; bit2 consumed by original UBFX",
    )
    put(
        parameters + 0xB, gate, 1, "parameter byte+B; source production not established"
    )
    for offset, value in zip((0xFC, 0x100, 0x104, 0x108), (*counts, 4, 4)):
        put(
            engine_command + offset,
            value,
            provenance="counts/lengths remain prepared, not algorithm outputs",
        )
    before_flag = read(engine_command + 0xF8, 0x14)
    invoke(0x58FFCC, (owner, engine_command, 0), end=0x58FFEC)
    flag_sp = reg("sp")
    require(word(flag_sp + 0x24), engine_command, "native flag caller saved command")
    resume(
        0x58FFF0,
        cfg.BASE + 0x5901D4,
        "after omitted event clear; native flag predicate and store",
    )
    flag = int(bool(mode & 4) and bool(gate & 1))
    require(
        word(engine_command + 0xF8, 1),
        flag,
        "flag from native mode bit2 AND parameter byte+B",
    )
    require(
        read(engine_command + 0xF9, 0x13),
        before_flag[1:],
        "producer only changes result flag",
    )
    require(
        [item["value"] for item in writes if item["pc_offset"] == 0x78558C],
        [1] if flag else [],
        "conditional original flag setter",
    )
    engine_result = read(engine_command + 0xF8, 0x14)

    vm.context_restore(core_context)
    reg("r8", engine_command)
    resume(
        0x635214,
        cfg.BASE + 0x63523C,
        "omitted processing; prepared engine object; native result copy",
    )
    require(
        read(frame + 0xF8, 0x14),
        engine_result,
        "original20byte copy reaches actual worker frame",
    )
    copy_call = [
        item for item in calls if item["pc_offset"] == 0x712898 and item["r2"] == 0x14
    ]
    require(
        [(item["r0"], item["r1"]) for item in copy_call],
        [(frame + 0xF8, engine_command + 0xF8)],
        "same native result-copy aliases",
    )
    vm.context_restore(worker_context)
    resume(
        0x635534,
        cfg.BASE + 0x6366F4,
        "native setters, list return, result halfword; before event signal",
    )
    expected_mask = flag
    require(
        word(worker + 0x2CC, 2),
        expected_mask,
        "native first-pass slot0 completion mask",
    )
    require(
        [item for item in writes if item["address"] == worker + 0x2CC],
        [
            {
                "pc_offset": 0x6366E8,
                "address": worker + 0x2CC,
                "size": 2,
                "value": expected_mask,
            }
        ],
        "original mailbox store replaces sentinel",
    )
    require(
        len([item for item in calls if item["pc_offset"] == 0x6352A0]),
        1,
        "one planned request; no retry",
    )
    require(
        [item["r0"] for item in calls if item["pc_offset"] == 0x63561C],
        [flag],
        "native result flag returns to list",
    )
    require(
        [item["r0"] for item in calls if item["pc_offset"] == 0x6366E4],
        [expected_mask],
        "list aggregate returns to worker",
    )
    setter_calls = [item for item in calls if item["pc_offset"] in (0x74F974, 0x74F944)]
    require(
        [
            (item["pc_offset"], item["r0"], item["r1"], item["r2"])
            for item in setter_calls
        ],
        (
            [(0x74F974, config, index, count) for index, count in zip((24, 25), counts)]
            if flag
            else []
        )
        + [(0x74F944, config, index, 4) for index in (24, 25)],
        "unchanged native setters",
    )

    vm.hook_add(
        uc.UC_HOOK_MEM_WRITE, observe_response, begin=command + 8, end=command + 11
    )
    vm.context_restore(submit_context)
    resume(
        0x632D14,
        cfg.BASE + 0x7B5150,
        "after omitted clear/lock/wait/clear; original mailbox read and caller commit",
    )
    require(
        [item["r0"] for item in calls if item["pc_offset"] == 0x632D1C],
        [expected_mask],
        "mailbox halfword zero-extended",
    )
    require(
        mailbox_reads,
        [
            {
                "pc_offset": 0x632D18,
                "address": worker + 0x2CC,
                "size": 2,
                "value": expected_mask,
            }
        ],
        "same original mailbox read",
    )
    require(
        [item["r0"] for item in calls if item["pc_offset"] == 0x7B5128],
        [expected_mask],
        "actual submit return reaches caller",
    )
    require(
        (word(command + 4), word(command + 8)),
        (0x19, expected_mask),
        "native response payload",
    )
    require(
        response_stores,
        [(0x6C9E2C, command + 8, 4, expected_mask)],
        "original response +8 store",
    )
    native_flags = (1, int(not flag or counts == (1, 1)))
    require(
        tuple(read(config + 0xC, 2)), native_flags, "independent native record validity"
    )
    require(
        read(engine_command + 0xF8, 0x14),
        engine_result,
        "transport and validator preserve source result",
    )
    require(image_writes, [], "no guest writes to mapped image")
    require(
        sha256(read(cfg.BASE, 0x1000000)),
        sha256(baseline_image),
        "mapped image unchanged after baseline fixture",
    )
    return {
        "case": label,
        "mode_word": mode,
        "parameter_byte_b": gate,
        "prepared_counts": counts,
        "prepared_lengths": [4, 4],
        "native_result_flag": flag,
        "native_list_mask": expected_mask,
        "native_mailbox_halfword": word(worker + 0x2CC, 2),
        "native_command_response": [word(command + 4), word(command + 8)],
        "native_config_flags": native_flags,
        "addresses": {
            "engine_command": engine_command,
            "parameters": parameters,
            "worker_frame": frame,
            "core_frame": core_sp,
            "flag_frame": flag_sp,
            "submit_frame": submit_sp,
            "plan_frame": plan_sp,
            "request": request,
        },
        "result_bytes": engine_result.hex(),
        "native_calls": calls,
        "native_writes": writes,
        "native_mailbox_reads": mailbox_reads,
        "host_inputs": host_inputs,
        "segments": segments,
        "original_instruction_checks": {
            "width_counts": dict(widths),
            "ordered_pc_bytes_sha256": code_digest.hexdigest(),
        },
        "mapped_image_baseline_sha256": sha256(baseline_image),
        "baseline_fixture_overlays": fixture_overlays,
        "guest_image_writes": image_writes,
        "execution_replacements": [],
    }


JOB, WORKER, OWNER = 0x10020000, 0x10050000, 0x10060000
ENGINE, PARAMS = JOB + 0x2440, JOB + 0x162E4
WORKER_SP, AUX_SP, SENTINEL = 0x100D0000, 0x100B0000, 0x100F1000


def replay_parameters(data, selector, native_constant):
    import unicorn as uc
    from unicorn import arm_const as arm

    vm = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    vm.mem_protect(BASE, 0x1000000, uc.UC_PROT_READ | uc.UC_PROT_EXEC)
    vm.mem_map(0x10000000, 0x100000)
    vm.reg_write(arm.UC_ARM_REG_C1_C0_2, 0xF00000)
    vm.reg_write(arm.UC_ARM_REG_FPEXC, 0x40000000)
    segments, writes, reads, prepared, pcs = [], [], [], [], set()
    widths, code_digest = Counter(), digest()

    def reg(name, value=None):
        key = getattr(arm, "UC_ARM_REG_" + name.upper())
        if value is None:
            return vm.reg_read(key)
        vm.reg_write(key, value)

    def word(address, size=4):
        return int.from_bytes(vm.mem_read(address, size), "little")

    def host(address, value, provenance):
        prepared.append(
            dict(address=address, size=4, value=value, provenance=provenance)
        )
        vm.mem_write(address, pack("<I", value))

    def code(cpu, pc, size, _):
        offset = pc - BASE
        require(0 <= offset <= len(data) - size, True, "original image execution")
        raw = bytes(cpu.mem_read(pc, size))
        require(raw, data[offset : offset + size], "unchanged executed instruction")
        pcs.add(offset)
        widths[size] += 1
        code_digest.update(pack("<II", offset, size) + raw)

    def write(cpu, _kind, address, size, value, _):
        writes.append(
            dict(pc_offset=reg("pc") - BASE, address=address, size=size, value=value)
        )

    def read(cpu, _kind, address, size, _value, _):
        if address in (ENGINE + 0x10C, ENGINE + 0x51, PARAMS, PARAMS + 0xB):
            reads.append(
                dict(
                    pc_offset=reg("pc") - BASE,
                    address=address,
                    size=size,
                    value=word(address, size),
                )
            )

    vm.hook_add(uc.UC_HOOK_CODE, code)
    vm.hook_add(uc.UC_HOOK_MEM_WRITE, write)
    vm.hook_add(uc.UC_HOOK_MEM_READ, read)

    def run(entry, stop, note):
        state = {
            name: reg(name) for name in ("r0", "r1", "r2", "r4", "r7", "r8", "sp", "lr")
        }
        vm.ctl_flush_tb()
        try:
            vm.emu_start(BASE + entry, stop, count=100000)
        except uc.UcError as error:
            raise ValueError(f'{entry:#x}: PC={reg("pc"):#x}: {error}') from error
        require(reg("pc"), stop, note)
        segments.append(
            dict(entry_offset=entry, stop_va=stop, note=note, entry_registers=state)
        )

    def call(entry, argument):
        reg("r0", argument)
        reg("sp", AUX_SP)
        reg("lr", SENTINEL)
        run(entry, SENTINEL, "original constructor; prepared object address")

    host(
        WORKER + 0x21C,
        JOB,
        "worker-to-job owner link; allocation lifecycle not executed",
    )
    call(0x754970, ENGINE)
    call(0x7191B8, PARAMS)

    # Native arithmetic binds the same in-job engine and parameter object.
    reg("r4", JOB)
    run(
        0x655284,
        BASE + 0x655294,
        "original binding slice; caller lifecycle not executed",
    )
    require(word(ENGINE + 0x10C), PARAMS, "native engine parameter alias")

    reg("r0", WORKER)
    reg("r1", 0x10070000)
    reg("sp", WORKER_SP)
    reg("lr", SENTINEL)
    run(
        0x6352A0,
        BASE + 0x6352B0,
        "native worker prologue; stop before singleton getter",
    )
    frame = reg("sp")
    run(
        0x6352D4,
        BASE + 0x6352DC,
        "skip singleton/request getters; native frame constructor",
    )
    require(word(frame + 0x51, 1), 0, "native constructor zero gate")
    if native_constant:
        run(
            0x635420,
            BASE + 0x63542C,
            "skip intervening worker setters; native MOV1 and byte51 store",
        )
    require(word(frame + 0x51, 1), int(native_constant), "native worker gate value")
    run(
        0x635528,
        BASE + 0x634970,
        "skip remaining setup/buffer clearing; native core call and prologue",
    )
    core_sp = reg("sp")
    require(word(core_sp + 0x18), frame, "actual caller frame saved by core prologue")
    run(
        0x634D88,
        BASE + 0x634D94,
        "skip service/preparation calls; derive engine from same worker/job",
    )
    require(reg("r8"), ENGINE, "native engine alias")
    run(
        0x635048,
        BASE + 0x63505C,
        "native saved-frame gate getter and engine gate setter",
    )
    require(word(ENGINE + 0x51, 1), int(native_constant), "same gate reaches engine")
    entry = 0x6350E8 if selector == 1 else 0x63518C
    run(
        entry,
        BASE + 0x655B24,
        "native caller chooses builder mode; stop before service checks",
    )
    require(word(PARAMS), 0x14 + selector, "native builder mode word")
    require(word(PARAMS + 0xB, 1), int(native_constant), "native builder gate")
    builder_snapshot = bytes(vm.mem_read(PARAMS, 0x40)).hex()

    reg("r0", OWNER)
    reg("r1", ENGINE)
    reg("r2", 0)
    reg("sp", AUX_SP)
    reg("lr", SENTINEL)
    run(
        0x58FFCC,
        BASE + 0x58FFEC,
        "native flag function prologue; owner supplied, mask0",
    )
    require(word(reg("sp") + 0x24), ENGINE, "actual flag frame saved engine")
    run(
        0x58FFF0,
        BASE + 0x5901D4,
        "skip event clear; original II-17 predicate and flag setter",
    )
    require(
        word(ENGINE + 0xF8, 1),
        int(native_constant),
        "producer output reaches native flag predicate",
    )
    require(
        reg("r6"), int(native_constant), "R6 derived by original AND, never injected"
    )
    require(
        sha256(bytes(vm.mem_read(BASE, 0x1000000))),
        sha256(data[:0x1000000]),
        "entire mapped image unchanged",
    )
    require(
        [
            w["value"]
            for w in writes
            if w["address"] == PARAMS and w["pc_offset"] == 0x7191B0
        ],
        [0, 0x14 + selector],
        "builder reset and native literal mode writes",
    )
    require(
        [
            w["value"]
            for w in writes
            if w["address"] == PARAMS + 0xB and w["pc_offset"] == 0x719148
        ],
        [0, int(native_constant)],
        "builder reset and copied native gate writes",
    )
    require(
        [w["value"] for w in writes if w["pc_offset"] == 0x78558C],
        [1] if native_constant else [],
        "conditional native result flag write",
    )
    interesting = {
        frame + 0x51,
        ENGINE + 0x51,
        ENGINE + 0x10C,
        PARAMS,
        PARAMS + 0xB,
        ENGINE + 0xF8,
    }
    return dict(
        selector=selector,
        native_worker_constant=native_constant,
        addresses=dict(
            job=JOB,
            worker=WORKER,
            engine=ENGINE,
            parameters=PARAMS,
            worker_frame=frame,
            core_frame=core_sp,
        ),
        mode_word=word(PARAMS),
        gate=word(PARAMS + 0xB, 1),
        result_flag=word(ENGINE + 0xF8, 1),
        owner_flags=word(OWNER + 0x70),
        builder_parameter_hex=builder_snapshot,
        prepared_memory=prepared,
        segments=segments,
        relevant_native_writes=[w for w in writes if w["address"] in interesting],
        parameter_reads=reads,
        instruction_widths=dict(sorted(widths.items())),
        instruction_trace_sha256=code_digest.hexdigest(),
        executed_offsets=sorted(pcs),
        image_guest_writes=[
            w for w in writes if BASE <= w["address"] < BASE + 0x1000000
        ],
    )


def checked_cases(cases, name):
    encoded = json.dumps(
        cases, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode()
    actual = sha256(encoded)
    require(actual, CASE_SHA[name], f"{name} full case trace SHA-256")
    return actual


def compact_case(case, omitted):
    result = {key: value for key, value in case.items() if key not in omitted}
    result["segments"] = [
        {key: value for key, value in item.items() if key != "entry_registers"}
        for item in case["segments"]
    ]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if os.path.lexists(args.output):
        raise FileExistsError(args.output)
    data = read_decoded(args.decoded)

    sys.dont_write_bytecode = True
    cfg, baseline = load_dependencies()
    import unicorn

    response_cases = [
        replay_response(data, *case, cfg, baseline)
        for case in (
            ("enabled_valid", 4, 1, (1, 1)),
            ("enabled_count_mismatch", 4, 1, (2, 1)),
            ("mode_bit_clear_count_mismatch", 0, 1, (2, 1)),
            ("parameter_gate_clear_count_mismatch", 4, 0, (2, 1)),
        )
    ]
    parameter_cases = [
        replay_parameters(data, *case)
        for case in (
            (1, True),
            (1, False),
            (2, True),
        )
    ]
    require(sha256(read_decoded(args.decoded)), DECODED_SHA, "Decoded input unchanged")
    report = dict(
        verified=True,
        decoded_sha256=DECODED_SHA,
        decoded_size=DECODED_SIZE,
        public_dependencies_sha256_lf=DEPENDENCIES,
        engine=dict(
            name="Unicorn",
            version=unicorn.__version__,
            cpu="Cortex-A9",
            code_base_va=BASE,
        ),
        trace_digest_format="SHA-256 over compact sorted-key ASCII JSON of full case data before projection.",
        result_to_response=dict(
            case_trace_sha256=checked_cases(response_cases, "result_to_response"),
            cpu_context_restore_order=["core", "worker", "submit"],
            response_word_store=dict(pc_offset=0x6C9E2C, command_offset=8, size=4),
            cases=[compact_case(case, {"native_calls"}) for case in response_cases],
            limits=[
                "Prepared parameter mode, byte+B, engine-command pointer, counts and lengths; original predicate, worker frame, 20-byte copy, list and mailbox code execute in slices.",
                "The host restores CPU registers while the VM retains RAM; the source result is not copied by the host.",
                "Selector 4 contributes one active request at indices 24 and 25; the no-retry condition is supplied.",
                "RTOS event clear, locking, waking, waiting and notification, worker setup/buffer initialization and image processing are omitted.",
                "Response +8 is the zero-extended list halfword; historical synthetic 0x3ff is a separate input.",
            ],
        ),
        worker_parameter_production=dict(
            case_trace_sha256=checked_cases(
                parameter_cases, "worker_parameter_production"
            ),
            cases=[
                compact_case(case, {"executed_offsets", "builder_parameter_hex"})
                for case in parameter_cases
            ],
            limits=[
                "Independent replay with its own VM per case. Does not execute the prior result copy, list or mailbox.",
                "Host supplies worker+0x21c, object addresses and predicate entry state. Native binder executes separately from its static virtual call path.",
                "Builder argument selects a local mode literal; the separate +B byte comes from the worker gate through engine+0x51.",
                "The zero-gate control skips the entire original constant/store slice. Builder 2 starts after its real guard.",
                "Builder service tail, owner scheduling, event clear, buffer work and image processing are omitted.",
            ],
        ),
        disk_input_unchanged=True,
    )
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print(
        json.dumps(
            {
                "verified": True,
                "response_cases": len(response_cases),
                "parameter_cases": len(parameter_cases),
            }
        )
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
