"""Replay the K-3 II v1.12 Color Space notification to the allocation boundary.

SPDX-License-Identifier: GPL-2.0-only
"""

import argparse
import json
from pathlib import Path
from struct import unpack_from

from verify_color_ui import DETAIL_ID, GROUP, GROUP_ROW, PARENT_VTABLE, PARENT_WIDGET

from verify_findings import require, require_snapshot, sha256, u32
from verify_raw_path import branch_target
from verify_tone_path import BASE, load_image


FILTER_BRANCHES = (
    (0x2F78B8, 0x308BC0),
    (0x3090D0, 0x6F1708),
    (0x70D458, 0x6EB3F4),
    (0x6F17B4, 0x73E08C),
    (0x6F17D8, 0x7DD0DC),
    (0x698D2C, 0x7DD0DC),
    (0x52370C, 0x73E08C),
    (0x523D3C, 0x69B61C),
    (0x69B650, 0x6EB6F4),
    (0x69B660, 0x6EB4E4),
    (0x30A3C4, 0x6F8360),
    (0x6F8388, 0x6EB664),
    (0x6F837C, 0x6EB44C),
    (0x6EB484, 0x50F550),
    (0x2FB44C, 0x2FB524),
    (0x30B254, 0x30B7AC),
    (0x2FA3EC, 0x6F83A4),
    (0x6F83A8, 0x69B61C),
    (0x2FE308, 0x6F8360),
    (0x2FE414, 0x6F82C0),
    (0x2FE41C, 0x2FE49C),
    (0x2FE424, 0x2FE49C),
    (0x3097C0, 0x3097D8),
)

DISPATCH_BRANCHES = (
    (0x70D454, 0x712828),
    (0x4A5C28, 0x6D5FF0),
    (0x6D9568, 0x712828),
    (0x6D956C, 0x4A3894),
    (0x6DA1A0, 0x4AD120),
    (0x30BE94, 0x30B904),
    (0x30BEA4, 0x70C3CC),
    (0x30B92C, 0x30B944),
    (0x30B948, 0x32B6D8),
    (0x30A20C, 0x32B6D8),
    (0x30A218, 0x309990),
    (0x30A228, 0x32B710),
    (0x30A508, 0x30A210),
    (0x30A510, 0x30A208),
    (0x30AA68, 0x3099A0),
    (0x3099F4, 0x309CAC),
    (0x309A00, 0x6DA238),
    (0x309A10, 0x6DA238),
    (0x2F8AD8, 0x6F6D1C),
    (0x2F91A0, 0x2F9234),
    (0x2F91A8, 0x6FA050),
    (0x6F8568, 0x59CC30),
    (0x6F8580, 0x506AC0),
    (0x6DA260, 0x6D8F00),
    (0x6D8F18, 0x704038),
    (0x6DA234, 0x704044),
    (0x6D9220, 0x6D9E7C),
    (0x6D9E80, 0x712828),
    (0x6D9E84, 0x4377A0),
)

RECORD_FIELDS = {
    "target": (4, 1),
    "source": (5, 1),
    "kind": (6, 1),
    "action": (8, 4),
    "arg_byte": (0xC, 1),
    "arg0": (0x10, 4),
    "arg1": (0x14, 4),
}
CLEARED_RECORD = dict.fromkeys(RECORD_FIELDS, 0) | {"kind": 0x17}
RANGES = (
    (0x308D80, 0x308DA8),
    (0x2F78BC, 0x2F7914),
    (0x70D450, 0x70D470),
    (0x6EB3F4, 0x6EB44C),
    (0x6F17AC, 0x6F17E0),
    (0x523D34, 0x523D40),
    (0x69B61C, 0x69B66C),
    (0x30A3A8, 0x30A3D0),
    (0x2FB408, 0x2FB52C),
    (0x2FE2F8, 0x2FE4A8),
    (0x6D5F38, 0x6D6024),
    (0x30BE40, 0x30BEB4),
    (0x30B904, 0x30B9B4),
    (0x30A4F8, 0x30A550),
    (0x32B6D8, 0x32B74C),
    (0x30A714, 0x30A758),
    (0x30AA38, 0x30AA70),
    (0x3099A0, 0x309CB0),
    (0x6D9E7C, 0x6D9E90),
    (0x2F8A84, 0x2F915C),
    (0x2F915C, 0x2F923C),
    (0x6DA238, 0x6DA26C),
)


def verify_static(data):
    for site, destination in FILTER_BRANCHES + DISPATCH_BRANCHES:
        require(branch_target(data, site), destination, f"branch {site:#x}")

    for table in (0xA63B14, 0xA6C18C):
        for slot, entry in ((0xC, 0x3090C8), (0x38, 0x30A324), (0x80, 0x30AF2C)):
            require(u32(data, table + slot), BASE + entry, f"app vtable slot {slot:#x}")
    require(u32(data, 0xA63C3C), BASE + 0x2FB408, "derived filter slot 0x128")
    require(u32(data, 0xA63CD4), BASE + 0x2FE2F8, "derived runtime slot 0x1c0")
    for offset, expected in (
        (0x308DA4, 0xE7C04001),
        (0x30A3CC, 0xE7C40001),
        (0x30B250, 0x07C49000),
        (0x2FE498, 0xE5C60000),
    ):
        require(u32(data, offset), expected, "original filter byte store")
    require(unpack_from("<IBB", data, 0x9DFA98), (6, 4, 2), "config key 0x1d")
    require(unpack_from("<IBB", data, 0x9DFB00), (10, 8, 3), "separate key 0x2a")
    require(u32(data, 0x9DEA88), 29, "separate key 0x52 byte offset")

    for offset, expected in (
        (0xA5E2A8, BASE + 0x4A5888),
        (0xA63BF4, BASE + 0x2F8A84),
        (0xA63BF8, BASE + 0x2F915C),
        (0xA63DCC, BASE + 0x30BE40),
        (0x6D9570, 0xE5840108),
        (0x6D9E7C, 0xE3A000E8),
        (0x308C40, 0xE5C04056),
        (0x30A724, 0xE5C49056),
        (0x30A72C, 0xE5C49058),
        (0x30A754, 0xE5C4B056),
    ):
        require(u32(data, offset), expected, f"notification anchor {offset:#x}")
    require(u32(data, 0x9B48DC), PARENT_WIDGET, "Color Space parent widget")
    require(
        tuple(data[GROUP_ROW : GROUP_ROW + 8]),
        (0x43, 0xB0, 0xB1, 0xB2, 0xB3, 0xAF, 0xB4, 0xB5),
        "Color Space category row",
    )
    return {
        "branch_checks": [list(edge) for edge in FILTER_BRANCHES + DISPATCH_BRANCHES],
        "config_map": {
            "0x1d": {
                "file_offset": 0x9DFA98,
                "payload_offset": 6,
                "mask": 4,
                "shift": 2,
            },
            "0x2a": {
                "file_offset": 0x9DFB00,
                "payload_offset": 10,
                "mask": 8,
                "shift": 3,
            },
            "0x52": {"file_offset": 0x9DEA88, "payload_offset": 29},
        },
        "ui_mapping": {
            "parent_widget_word_offset": 0x9B48DC,
            "parent_widget": PARENT_WIDGET,
            "category_row_offset": GROUP_ROW,
            "category": GROUP,
            "detail_id": DETAIL_ID,
            "parent_vtable_file_offset": PARENT_VTABLE,
            "derived_app_vtable_file_offset": 0xA63B14,
            "derived_secondary_vtable_file_offset": 0xA63DC4,
        },
        "range_sha256": [
            {"start": start, "end_exclusive": end, "sha256": sha256(data[start:end])}
            for start, end in RANGES
        ],
    }


def emulate(data):
    import unicorn as uc
    from unicorn import arm_const as arm

    vm = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    for address, size in (
        (BASE, 0x1000000),
        (0x10000000, 0x40000),
        (0x40409000, 0x2000),
        (0x4041D000, 0x1000),
        (0x4047B000, 0x2000),
        (0x40483000, 0x2000),
    ):
        vm.mem_map(address, size)
    vm.mem_write(BASE, data[:0x1000000])
    app, writer, owner, provider, bank0, bank1, registry = (
        0x10000000 + 0x4000 * i for i in range(7)
    )
    other_provider, other_bank = 0x1001C000, 0x10020000
    stack, stop = 0x1003D000, 0x1003F000
    service, context = 0x4047B754, 0x40483F7C

    def write(address, value, size=4):
        vm.mem_write(address, value.to_bytes(size, "little"))

    def read(address, size=4):
        return int.from_bytes(vm.mem_read(address, size), "little")

    def reg(name, value=None):
        index = getattr(arm, f"UC_ARM_REG_{name.upper()}")
        if value is None:
            return vm.reg_read(index)
        vm.reg_write(index, value)

    def run(entry, end=None, **registers):
        for name, value in dict(sp=stack, lr=stop, **registers).items():
            reg(name, value)
        finish = stop if end is None else BASE + end
        vm.ctl_flush_tb()
        vm.emu_start(BASE + entry, finish, count=20000)
        require(reg("pc"), finish, f"execution boundary from {entry:#x}")
        return reg("r0")

    allocations = []
    publications = []

    def stub(_vm, pc, _size, _user):
        if pc == BASE + 0x712828:
            index = len(allocations)
            size, destination = ((0x28, provider), (0x14, bank0), (0x14, bank1))[index]
            require(reg("r0"), size, "native allocation argument")
            vm.mem_write(destination, bytes([0xA5 + index]) * size)
            allocations.append(size)
            reg("r0", destination)
        else:
            require(reg("r0"), writer, "native publication recipient")
            publications.append(read(provider + 0x10))
            reg("r0", 0)
        reg("pc", reg("lr"))

    allocation_hook = vm.hook_add(
        uc.UC_HOOK_CODE, stub, begin=BASE + 0x712828, end=BASE + 0x712828
    )
    vm.hook_add(uc.UC_HOOK_CODE, stub, begin=BASE + 0x698F28, end=BASE + 0x698F28)

    # Initialized singleton guards avoid running the rest of camera boot.
    write(0x4040A7F4, 1)
    write(0x4041D890, 1)
    run(0x70D450, 0x70D470, r4=service)
    require(allocations, [0x28, 0x14, 0x14], "original provider initialization")
    vm.hook_del(allocation_hook)
    require(read(service + 0x54), provider, "service provider slot")
    require(
        [read(provider + offset) for offset in (8, 0xC, 0x10)],
        [bank0, bank1, 0],
        "native banks and initial active selection",
    )
    for bank in (bank0, bank1):
        require(
            bytes(vm.mem_read(bank + 4, 13)), bytes(13), "original initialized payload"
        )

    run(0x70D57C, 0x70D580, r0=writer, r4=service)
    run(0x698D28, 0x698D34, r4=writer, r5=service)
    write(service + 0x10, other_provider)
    write(other_provider + 0x10, other_bank)
    run(0x6F17AC, 0x6F17E0, r4=context)
    require(read(context + 0x20), other_provider, "separate settings provider binding")
    require(read(context + 0x1C), writer, "context writer binding")
    require(read(context + 0x28), provider, "context provider binding")
    require(read(writer + 0x18), provider, "same provider at writer")
    run(0x523708, 0x523714, r4=owner, r5=service)
    require(read(owner + 0x38), writer, "literal-one callsite owner")

    write(app + 0x14B4, 0xA5, 1)
    run(0x308D80, 0x308DA8, r0=app, r4=0)
    require(read(app + 0x14B4, 1), 0, "constructor tail default")
    run(0x2F78BC, 0x2F7914, r0=app)
    require(read(app), BASE + 0xA63B14, "derived app table")
    run(0x3090CC, 0x3090D8, r0=app)
    require(read(app + 0x15C), context, "native app context binding")

    write(app + 0x64, registry)
    write(registry + 0x2700, 0x42, 1)
    write(app + 0x184 + 8, 6, 1)  # Prepared downstream condition.
    write(app + 0x184 + 0x14, 0)

    visited = []
    observed = (0x2FB440, 0x2FB450, 0x2FB520, 0x2FB524)
    for site in observed:
        vm.hook_add(
            uc.UC_HOOK_CODE,
            lambda _vm, pc, _size, _user: visited.append(pc - BASE),
            begin=BASE + site,
            end=BASE + site,
        )

    def active_byte():
        active = read(provider + 0x10)
        require(active in (0, 1), True, "stable active bank")
        return read((bank0, bank1)[active] + 0xA, 1)

    def snapshot(expected):
        run(0x30A3A8, 0x30A3D0, r4=app)
        require(read(app + 0x14B4, 1), expected, "native app snapshot")

    def filter_case(label, target, expected, route):
        visited.clear()
        result = run(0x2FB408, r0=app, r1=target, r2=1, r3=0x1D)
        require(result, expected, label)
        require(visited, route, f"{label} path")
        return {
            "case": label,
            "active_byte": active_byte(),
            "cached": read(app + 0x14B4, 1),
            "target": target,
            "result": result,
            "filter_path": visited.copy(),
        }

    reject = [0x2FB440, 0x2FB450, 0x2FB520, 0x2FB524]
    early = [0x2FB440, 0x2FB524]
    target = DETAIL_ID
    cases = []
    snapshot(0)
    cases.append(filter_case("constructor_state", target, 0, reject))

    # A fixture with other bits set tests isolation of the native bit writer.
    source_payload = bytes.fromhex("11233547596ba37d8f91adbecf")
    expected_payload = source_payload[:6] + bytes([0xA7]) + source_payload[7:]
    vm.mem_write(bank0 + 4, source_payload)
    vm.mem_write(bank1 + 4, bytes([0xF1]) * 13)
    run(0x523D34, 0x523D40, r4=owner)
    require(bytes(vm.mem_read(bank0 + 4, 13)), source_payload, "source bank unchanged")
    require(
        bytes(vm.mem_read(bank1 + 4, 13)),
        expected_payload,
        "entire bank copy and isolated bit",
    )
    # The distinct-bit copy control is separate from the connected filter fixture.
    vm.mem_write(bank0 + 4, bytes(6) + bytes([0xA3]) + bytes(6))
    vm.mem_write(bank1 + 4, bytes(6) + bytes([0xA7]) + bytes(6))
    require(active_byte(), 0xA7, "literal-one native setter and adjacent bits")
    require(publications, [1], "native bank flip before publication boundary")
    require(read(app + 0x14B4, 1), 0, "setter does not itself update app cache")
    cases.append(filter_case("setter_before_app_snapshot", target, 0, reject))

    snapshot(1)
    cases.append(filter_case("app_snapshot_set", target, target, early))
    write(app + 0x59, 1, 1)
    cases.append(
        filter_case("higher_priority_be_reject", 0xBE, 0, [0x2FB520, 0x2FB524])
    )
    write(app + 0x59, 0, 1)

    run(0x30AF2C, r0=app, r1=0x0112005E, r2=0)
    require(read(app + 0x14B4, 1), 0, "native app cache reset event")
    require(active_byte(), 0xA7, "app event leaves provider state")
    cases.append(filter_case("app_cache_reset_event", target, 0, reject))
    snapshot(1)
    cases.append(filter_case("app_resnapshot", target, target, early))

    run(0x2FA3E4, 0x2FA3F0, r4=app)
    require(active_byte(), 0xA3, "original app-side clear and adjacent bits")
    require(publications, [1, 0], "native bank flips on set and clear")
    cases.append(
        filter_case("provider_clear_before_app_snapshot", target, target, early)
    )
    snapshot(0)
    cases.append(filter_case("app_resnapshot_clear", target, 0, reject))

    runtime_cases = []
    write(registry + 0x2700, 0, 1)
    runtime_store = []
    vm.hook_add(
        uc.UC_HOOK_CODE,
        lambda _vm, pc, _size, _user: runtime_store.append(pc - BASE),
        begin=BASE + 0x2FE498,
        end=BASE + 0x2FE498,
    )
    for key1d, raw_key52, expected in (
        (0, 0, 0),
        (0, 1, 0),
        (1, 0, 0),
        (1, 0xFFFFFFFF, 0),
        (1, 1, 1),
    ):
        if bool(active_byte() & 4) != bool(key1d):
            require(key1d, 1, "only one state transition in ordered cases")
            run(0x523D34, 0x523D40, r4=owner)
        require((active_byte() >> 2) & 1, key1d, "runtime provider bit")
        run(0x30AF2C, r0=app, r1=0x0112005E, r2=0)
        vm.mem_write(other_bank + 0x21, raw_key52.to_bytes(4, "big"))
        runtime_store.clear()
        run(0x3097B4, 0x3097EC, r4=app, r5=0)
        require(read(app + 0x14B4, 1), expected, "runtime cached value")
        require(
            runtime_store, [0x2FE498] if expected else [], "runtime store execution"
        )
        runtime_cases.append(
            {
                "active_key_1d": key1d,
                "key_52_word": raw_key52,
                "cached": read(app + 0x14B4, 1),
                "writer_file_offsets": runtime_store.copy(),
            }
        )
    write(registry + 0x2700, 0x42, 1)
    cases.append(
        filter_case("runtime_set_then_prepared_registry_42", target, target, early)
    )

    # Reset the cache through the original event and repopulate it through
    # the normal snapshot. The connected route uses these same app and banks.
    run(0x30AF2C, r0=app, r1=0x0112005E, r2=0)
    require(read(app + 0x14B4, 1), 0, "cache before connected snapshot")
    snapshot(1)
    require(publications, [1, 0, 1], "all native source bank flips")
    current_bank = (bank0, bank1)[read(provider + 0x10)]
    payload = bytes(vm.mem_read(current_bank + 4, 13))
    require(
        payload, bytes(6) + bytes([0xA7]) + bytes(6), "retained source bank at dispatch"
    )
    dispatch = replay_dispatch(
        vm, uc, app, registry, context, stack, write, read, reg, run
    )
    return {
        "unicorn_version": uc.__version__,
        "config_key": 0x1D,
        "payload_object_offset": 0xA,
        "mask": 4,
        "app_filter_object_offset": 0x14B4,
        "publications_seen_after_bank_flip": publications,
        "initial_allocation_sizes": allocations,
        "allocation_fill_bytes": [0xA5, 0xA6, 0xA7],
        "separate_bank_copy_control": {
            "source": source_payload.hex(),
            "destination": expected_payload.hex(),
            "source_unchanged": True,
        },
        "filter_cases": cases,
        "runtime_virtual_dispatch_slice": [0x3097B4, 0x3097EC],
        "runtime_setter_cases": runtime_cases,
        "connected_source": {
            "snapshot": [0x30A3A8, 0x30A3D0],
            "key_0x1d": (payload[6] >> 2) & 1,
            "key_0x2a": (payload[10] >> 3) & 1,
            "source_payload_size": len(payload),
            "byte_6_with_neighbor_canaries": payload[6],
        },
        "dispatch": dispatch,
        "execution_replacements": {
            "0x712828": "Returns scratch storage for three initial provider/bank allocations. Hook removed before stopping at the later detail allocator entry.",
            "0x698f28": "Returns zero from post-bank-flip publication callback.",
            "0x70c3cc": "Records original wake recipient and flag; returns zero.",
            "0x704038": "Returns zero at registry lock acquisition.",
            "0x704044": "Returns zero at registry lock release.",
        },
        "scope": [
            "Prepared memory supplies service bootstrap guards, app/screen registry and panel state, context +0x33a/+0x33c zero, and the separate global provider's zeroed 13-byte payload for key 0x17.",
            "Filter/runtime fixtures prepare app +0x18c = 6 and +0x198 = 0. The runtime cases supply key 0x52 words through the separate context provider and current screen ID zero. The ninth filter case separately prepares current screen ID 0x42.",
            "The connected fixture retains app +0x18c = 6 and the provider/context installed by the original slices. The active payload has key 0x1d set, neighboring byte canaries, and key 0x2a clear.",
            "Task replay enters bounded slices with injected wake values and registers. It skips intervening task code. A logical parent action is supplied at function entry. Live input, RTOS delivery, lock behavior, screen allocation/constructor and rendering are outside the replay.",
        ],
    }


def replay_dispatch(vm, uc, app, registry, context, stack, write, read, reg, run):
    parent, panel = 0x10024000, 0x10028000
    global_provider, global_bank = 0x1002C000, 0x10030000
    pending, active, secondary, alternate = (app + i for i in (0xB0, 0x68, 0x80, 0x98))
    reg("fpexc", 0x40000000)
    write(parent, BASE + PARENT_VTABLE)
    write(parent + 4, panel)
    write(parent + 0xD4, PARENT_WIDGET)
    write(panel + 0x26, GROUP, 1)
    write(0x40409514, 1)
    write(registry + 0x2708, app)
    write(registry + 0x108, parent)
    require(read(registry + DETAIL_ID * 4), 0, "uncached target screen")
    require(read(registry + 0x2700, 1), 0x42, "prepared current screen ID")
    run(0x6DA188, 0x6DA1A4, r4=registry, r7=parent)
    require(read(parent + 0xC4), app + 0x4C, "native secondary-interface binding")
    require(read(app + 0x4C), BASE + 0xA63DC4, "native secondary interface")
    require(read(app + 0x15C), context, "retained native settings context")

    write(0x4040A8B0, 1)
    write(0x4047C094 + 0x44, global_provider)
    write(global_provider + 0x3C, global_bank)
    require(
        bytes(vm.mem_read(global_bank + 4, 13)), bytes(13), "prepared key 0x17 bank"
    )
    require(read(context + 0x33A, 1), 0, "prepared context +0x33a")
    require(read(context + 0x33C, 1), 0, "prepared context +0x33c")

    calls, wakes, locks, lookups, acceptance_results, key17 = [], [], [], [], [], []

    def observe(_vm, pc, _size, _user):
        if pc == BASE + 0x3099F0:
            acceptance_results.append(reg("r0"))
            return
        if pc == BASE + 0x6F8598:
            key17.append(reg("r0"))
            return
        calls.append(pc - BASE)
        if pc == BASE + 0x30BE40:
            require(reg("r0"), app + 0x4C, "caller interface argument")
        elif pc == BASE + 0x2FB408:
            require(reg("r0"), app, "native filter owner")
            require(reg("r1"), DETAIL_ID, "native filter target")
        elif pc == BASE + 0x30B904:
            require(reg("r0"), app, "native pending owner")
        elif pc in (BASE + 0x2F8A84, BASE + 0x2F915C):
            require(reg("r0"), app, "native transition app")
            require(reg("r1"), active, "native transition record")
            require(fields(active), expected_fields, "live typed transition fields")
        elif pc == BASE + 0x6DA238:
            require(reg("r0"), registry, "native registry argument")
            lookups.append(reg("r1"))

    def boundary(_vm, pc, _size, _user):
        if pc == BASE + 0x70C3CC:
            require(reg("r0"), app + 0x14D4, "wake recipient")
            wakes.append(reg("r1"))
        else:
            require(reg("r0"), registry + 0x2730, "registry lock argument")
            locks.append(pc - BASE)
        reg("r0", 0)
        reg("pc", reg("lr"))

    notification_path = [0x4A5888, 0x6D5FF0, 0x30BE40, 0x2FB408, 0x30B904]
    transition_path = [0x3099A0, 0x2F8A84, 0x2F915C, 0x6DA238, 0x6DA238, 0x6D9E7C]
    for offset in set(notification_path + transition_path + [0x3099F0, 0x6F8598]):
        vm.hook_add(uc.UC_HOOK_CODE, observe, begin=BASE + offset, end=BASE + offset)
    for offset in (0x70C3CC, 0x704038, 0x704044):
        vm.hook_add(uc.UC_HOOK_CODE, boundary, begin=BASE + offset, end=BASE + offset)

    def fields(record):
        return {
            name: read(record + off, size)
            for name, (off, size) in RECORD_FIELDS.items()
        }

    def canaries(record):
        return [read(record), read(record + 7, 1), read(record + 0xD, 3)]

    def fill_record(record, byte, target):
        vm.mem_write(record, bytes([byte]) * 24)
        write(record + 4, target, 1)

    def notify():
        calls.clear()
        wakes.clear()
        run(0x6D5F38, r0=parent, r1=0x1D, r2=0)
        require(calls, notification_path, "native parent notification path")
        require(wakes, [2, 0x800], "native wake requests")

    # Change only the native cache before the same parent action.
    fill_record(pending, 0xA5, 0)
    before = bytes(vm.mem_read(pending, 24))
    run(0x30AF2C, r0=app, r1=0x0112005E, r2=0)
    require(read(app + 0x14B4, 1), 0, "native connected cache reset")
    calls.clear()
    wakes.clear()
    run(0x6D5F38, r0=parent, r1=0x1D, r2=0)
    require(calls, notification_path[:-1], "cache-zero parent rejected before queue")
    require(wakes, [2], "cache-zero parent only pre-interface wake")
    require(bytes(vm.mem_read(pending, 24)), before, "cache-zero pending unchanged")
    cache_rejection = {
        "cached": 0,
        "path": calls.copy(),
        "wake_flags": wakes.copy(),
        "pending_unchanged": True,
    }
    run(0x30A3A8, 0x30A3D0, r4=app)
    require(read(app + 0x14B4, 1), 1, "native connected cache resnapshot")

    notification_cases = []
    expected_fields = {
        "target": DETAIL_ID,
        "source": 0x42,
        "kind": 1,
        "action": 0x1D,
        "arg_byte": 0,
        "arg0": 0,
        "arg1": 0,
    }
    for target in (0x55, 0):
        fill_record(pending, 0xA5, target)
        before = bytes(vm.mem_read(pending, 24))
        padding = canaries(pending)
        notify()
        unchanged = bytes(vm.mem_read(pending, 24)) == before
        require(
            unchanged, bool(target), "occupied request policy through parent action"
        )
        require(canaries(pending), padding, "queue leaves vtable and padding")
        if not target:
            require(fields(pending), expected_fields, "parent typed notification")
        notification_cases.append(
            {
                "initial_target": target,
                "pending_unchanged": unchanged,
                "pending": fields(pending),
                "wake_flags": wakes.copy(),
            }
        )

    for record, byte in ((active, 0x5A), (secondary, 0x3C), (alternate, 0xC3)):
        fill_record(record, byte, 0x55)
    padding = [canaries(record) for record in (pending, active, secondary, alternate)]
    write(app + 0xE5, 0xFF, 1)
    write(app + 0xE6, 0xFF, 1)
    write(stack + 0xC, wakes[-1])
    run(0x30A4F8, 0x30A550, r4=app)
    require(fields(active), expected_fields, "native typed notification copy")
    require(
        [read(app + off, 1) for off in (0xE5, 0xE6)], [0, 0], "native task flag reset"
    )
    for record in (pending, secondary, alternate):
        require(fields(record), CLEARED_RECORD, "native typed reset")
    require(
        [canaries(record) for record in (pending, active, secondary, alternate)],
        padding,
        "native task preserves record vtable and padding",
    )
    task_copy = {
        "injected_wake": read(stack + 0xC),
        "active": fields(active),
        "pending_after": fields(pending),
        "other_active_records_cleared": True,
        "record_vtable_and_padding_preserved": True,
    }

    write(app + 0x56, 0xA5, 1)
    run(0x308C40, 0x308C44, r0=app, r4=0)
    require(read(app + 0x56, 1), 0, "original constructor zero store")
    run(0x30A3A8, 0x30A3B0, r4=app)
    require((reg("fp"), reg("sb")), (1, 0), "original task constants")
    write(stack + 0xC, 8)
    run(0x30A744, 0x30A758, r4=app)
    require(read(app + 0x56, 1), 1, "native wake 8 acceptance write")
    wake8_flag = read(app + 0x56, 1)

    calls.clear()
    run(0x30AA38, 0x712828, r4=app, r0=0x800)
    require(calls, transition_path, "native transition and factory path")
    require(lookups, [0x42, DETAIL_ID], "native current and target registry lookups")
    require(acceptance_results, [1], "native acceptance result")
    require(key17, [0], "native global key 0x17")
    require(reg("r0"), 0xE8, "detail factory allocator argument")
    require(reg("lr"), BASE + 0x6D9E84, "detail factory allocator return address")
    require(
        fields(active), expected_fields, "live active record at allocation boundary"
    )
    require(locks, [0x704038, 0x704044, 0x704038], "observed lock boundaries")
    allocation = {
        "entry": reg("pc") - BASE,
        "requested_bytes": reg("r0"),
        "return_file_offset": reg("lr") - BASE,
        "path": calls.copy(),
        "registry_ids": lookups.copy(),
        "acceptance_return": acceptance_results[-1],
        "global_key_0x17_return": key17[-1],
        "lock_boundaries": locks.copy(),
        "injected_task_flags": 0x800,
    }

    write(app + 0x58, 1, 1)
    write(stack + 0xC, 0x10)
    run(0x30A714, 0x30A730, r4=app, r9=0)
    require(
        [read(app + off, 1) for off in (0x56, 0x58)],
        [0, 0],
        "native wake 0x10 clears flags",
    )
    calls.clear()
    lookups.clear()
    run(0x3099A0, 0x309CAC, r0=app, r1=active)
    require(calls, [0x3099A0, 0x2F8A84, 0x2F915C], "rejection before registry lookup")
    require(lookups, [], "rejected transition does not enter registry")
    require(acceptance_results, [1, 0], "native rejection result")
    rejection = {
        "injected_wake": 0x10,
        "app_0x56": read(app + 0x56, 1),
        "app_0x58": read(app + 0x58, 1),
        "end_exclusive": reg("pc") - BASE,
        "acceptance_return": acceptance_results[-1],
        "path": calls.copy(),
    }

    policy = []
    for kind, action, accept in (
        (1, 0x1D, False),
        (1, 0xB, True),
        (1, 0x2E, True),
        (2, 0xB, False),
        (2, 0x2E, False),
    ):
        fill_record(pending, 0xA5, 0x55)
        before = bytes(vm.mem_read(pending, 24))
        padding = canaries(pending)
        for off, arg in ((0, 0x33), (4, 0x11223344), (8, 0x55667788)):
            write(stack + off, arg)
        run(0x30B904, r0=app, r1=DETAIL_ID, r2=kind, r3=action)
        changed = bytes(vm.mem_read(pending, 24)) != before
        require(changed, accept, "direct native occupied queue policy")
        require(
            canaries(pending),
            padding,
            "direct queue policy preserves vtable and padding",
        )
        if accept:
            require(
                fields(pending),
                expected_fields
                | {
                    "kind": kind,
                    "action": action,
                    "arg_byte": 0x33,
                    "arg0": 0x11223344,
                    "arg1": 0x55667788,
                },
                "direct native accepted record",
            )
        policy.append({"kind": kind, "action": action, "changed": changed})

    fill_record(pending, 0xA5, 0)
    notify()
    before = bytes(vm.mem_read(pending, 24))
    for record in (active, secondary, alternate):
        fill_record(record, 0xC3, 0x55)
    padding = [canaries(record) for record in (active, secondary, alternate)]
    write(stack + 0xC, 0)
    run(0x30A4F8, 0x30A550, r4=app)
    require(bytes(vm.mem_read(pending, 24)), before, "no-wake preserves pending record")
    for record in (active, secondary, alternate):
        require(fields(record), CLEARED_RECORD, "no-wake resets active record")
    require(
        [canaries(record) for record in (active, secondary, alternate)],
        padding,
        "no-wake preserves vtable and padding",
    )
    calls.clear()
    run(0x30AA38, 0x30AA70, r4=app, r0=0)
    require(calls, [], "no-wake and empty alternate do not dispatch")
    write(active + 4, DETAIL_ID, 1)
    write(alternate + 4, 0x55, 1)
    run(0x30AA38, 0x3099A0, r4=app, r0=0x800)
    require((reg("r0"), reg("r1")), (app, alternate), "alternate record priority")
    selected_record = reg("r1")

    rich = expected_fields | {
        "action": 0xB,
        "arg_byte": 0x33,
        "arg0": 0x11223344,
        "arg1": 0x55667788,
    }
    high = app + 0xC8
    high_fields = rich | {"target": 0x77, "kind": 2, "arg0": 0x99AABBCC}
    copy_controls = []
    for flags in (0x800, 0x80000000, 0x80000800):
        fill_record(pending, 0xA5, 0x55)
        for off, arg in ((0, 0x33), (4, 0x11223344), (8, 0x55667788)):
            write(stack + off, arg)
        run(0x30B904, r0=app, r1=DETAIL_ID, r2=1, r3=0xB)
        require(fields(pending), rich, "native nonzero argument producer")
        for destination, byte in (
            (active, 0x5A),
            (secondary, 0x3C),
            (alternate, 0xC3),
            (high, 0x96),
        ):
            fill_record(destination, byte, 0x55)
        for key, (off, width) in RECORD_FIELDS.items():
            write(high + off, high_fields[key], width)
        guarded = (pending, active, secondary, alternate, high)
        padding = [canaries(record) for record in guarded]
        write(stack + 0xC, flags)
        run(0x30A4F8, 0x30A550, r4=app)
        regular = bool(flags & 0x800)
        require(fields(active), rich if regular else CLEARED_RECORD, "regular copy")
        require(
            fields(secondary),
            CLEARED_RECORD if regular else high_fields,
            "high-bit copy",
        )
        require(
            fields(pending),
            CLEARED_RECORD if regular else rich,
            "regular pending reset",
        )
        require(
            fields(high),
            high_fields if regular else CLEARED_RECORD,
            "high pending reset",
        )
        require([canaries(record) for record in guarded], padding, "typed copy padding")
        copy_controls.append(
            {
                "wake": flags,
                "active": fields(active),
                "secondary": fields(secondary),
                "pending": fields(pending),
                "high_pending": fields(high),
            }
        )

    return {
        "record_fields": RECORD_FIELDS,
        "notification_path": notification_path,
        "parent_notification_cases": notification_cases,
        "connected_cache_zero_rejection": cache_rejection,
        "task_copy_reset": task_copy,
        "nonzero_typed_copy_controls": copy_controls,
        "task_slices": {
            "constants": [0x30A3A8, 0x30A3B0],
            "copy_reset": [0x30A4F8, 0x30A550],
            "wake_8": [0x30A744, 0x30A758],
            "wake_0x10": [0x30A714, 0x30A730],
            "dispatch_entry": 0x30AA38,
        },
        "wake_8_acceptance": {"injected_wake": 8, "app_0x56": wake8_flag},
        "allocation_boundary": allocation,
        "wake_0x10_rejection": rejection,
        "direct_occupied_queue_cases": policy,
        "no_wake": {
            "injected_wake": 0,
            "pending_preserved": True,
            "active_records_cleared": True,
            "transition_entered": False,
        },
        "alternate_priority": {
            "injected_flags": 0x800,
            "selected_record_offset": selected_record - app,
        },
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
        "static": verify_static(data),
        "replay": emulate(data),
    }
    output = json.dumps(result, indent=2)
    if args.compare:
        require_snapshot(result, args.compare, "snapshot replay")
    print(output)


if __name__ == "__main__":
    main()
