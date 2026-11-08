"""Replay K-3 II preserved settings-bank selection and staged save requests.

SPDX-License-Identifier: GPL-2.0-only
Flash writes and mailbox synchronization are explicit emulation boundaries.
"""

import argparse
import json
from pathlib import Path
from struct import pack, unpack_from

from verify_findings import DECODED_SHA256, require, sha256, u32
from verify_tone_path import BASE, check_edge, check_words, load_image

FLASH = (0x021A0000, 0x022C0000)
STAGE, MIRROR, META, EXTRA = 0x40459204, 0x404A4F20, 0x404A4628, 0x404A4728
MARKER = 0xA55A5AA5
REGIONS = ((0, 0x23B4, MIRROR), (0x4000, 0x100, META), (0x6000, 0x7F8, EXTRA))
RANGES = (
    (0x517CF0, 0x517D10),
    (0x517E24, 0x517FB8),
    (0x537B98, 0x537C3C),
    (0x537FE8, 0x538058),
    (0x54C6FC, 0x54C790),
    (0x54C8A8, 0x54C918),
    (0x599844, 0x599F20),
    (0x6E7FE0, 0x6E8068),
    (0x6E8194, 0x6E83A8),
    (0x6FD928, 0x6FD94C),
    (0x700760, 0x7007C8),
    (0x700E84, 0x700F08),
)
EDGES = {
    0x6E803C: 0x517F08,
    0x6E804C: 0x537FE8,
    0x6E805C: 0x54C8A8,
    0x6E81C8: 0x599D18,
    0x6E8224: 0x599E88,
    0x6E8280: 0x599E88,
    0x6E82DC: 0x599E88,
    0x6E82F4: 0x599DC0,
    0x6E8320: 0x517D68,
    0x6E836C: 0x599E88,
    0x6E8384: 0x599D6C,
    0x599DB0: 0x599914,
    0x700778: 0x537C2C,
    0x7007B8: 0x712898,
}
WORDS = {
    0x538048: FLASH[0],
    0x53804C: FLASH[1],
    0x538054: MIRROR,
    0x517FA8: FLASH[0] + 0x4000,
    0x517FAC: FLASH[1] + 0x4000,
    0x517FB4: META,
    0x54C914: EXTRA,
    0x59A028: STAGE,
    0x6E837C: 0x13A0178B,
    0x6E8380: 0x01A01009,
    0x70077C: 0xE584000C,
    0x517D6C: 0xE5802004,
}


def emulate(data):
    import unicorn as uc
    from unicorn import arm_const as arm

    vm = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    vm.mem_map(0x40400000, 0x100000)
    vm.mem_map(0x10000000, 0x100000)
    manager, provider, meta_provider, extra_provider, cfg = (
        0x10010000,
        0x10011000,
        0x10012000,
        0x10013000,
        0x10020000,
    )
    stack, stop = 0x100F0000, 0x100F1000
    state = {}

    def reg(name, value=None):
        index = getattr(arm, "UC_ARM_REG_" + name.upper())
        if value is None:
            return vm.reg_read(index)
        vm.reg_write(index, value)

    def write(address, value, fmt="I"):
        vm.mem_write(address, pack("<" + fmt, value))

    def read(address, fmt="I"):
        size = 1 if fmt == "B" else 4
        return unpack_from("<" + fmt, vm.mem_read(address, size))[0]

    def run(entry, *args, end=None, **registers):
        finish = stop if end is None else BASE + end
        for name, value in dict(sp=stack, lr=stop, **registers).items():
            reg(name, value)
        for i, value in enumerate(args):
            reg(f"r{i}", value)
        vm.emu_start(BASE + entry, finish, count=3_000_000)
        require(reg("pc"), finish, f"original boundary {entry:#x}")
        return reg("r0")

    def reset():
        for address in FLASH:
            vm.mem_write(address, data[address - BASE : address - BASE + 0x20000])
        vm.mem_write(0x40400000, bytes(0x100000))
        run(0x6E80BC, manager)
        for entry, obj in (
            (0x537B98, provider),
            (0x517E24, meta_provider),
            (0x54C6FC, extra_provider),
        ):
            run(entry, obj)
        for off, obj in ((8, provider), (12, meta_provider), (16, extra_provider)):
            write(manager + off, obj)

    selections = []
    for valid_a in (False, True):
        for valid_b in (False, True):
            for preferred in (0, 1):
                reset()
                for address, canary in zip(FLASH, (0x11, 0x22)):
                    write(address + 0x400, canary, "B")
                for address, valid in zip(FLASH, (valid_a, valid_b)):
                    if not valid:
                        write(address + 0x23B0, 0)
                actual = run(0x537FE8, provider, preferred)
                expected = preferred if valid_a and valid_b else (0 if valid_b else 1)
                require(actual, expected, "main settings copy selected")
                require(
                    run(0x537BC8, provider), int(valid_a or valid_b), "marker validity"
                )
                run(0x6E7FE0, manager)
                source = FLASH[1 - expected] if valid_a or valid_b else BASE + 0x8F70
                copied = bytes(vm.mem_read(MIRROR, 0x23B4))
                require(
                    copied, bytes(vm.mem_read(source, 0x23B4)), "selected/default copy"
                )
                selections.append(
                    dict(
                        valid_a=valid_a,
                        valid_b=valid_b,
                        preferred=preferred,
                        selected=actual,
                        loaded_from=source,
                        sha256=sha256(copied),
                    )
                )
    require(
        len({row["sha256"] for row in selections}),
        3,
        "A/B/default copies distinguished",
    )

    generations = []
    for a, b, valid_a, valid_b, selected in (
        (0, 0, True, True, 1),
        (5, 4, True, True, 1),
        (4, 5, True, True, 0),
        (0xFFFFFFFE, 0xFFFFFFFF, True, True, 0),
        (0xFFFFFFFF, 0, True, True, 0),
        (0, 0xFFFFFFFF, True, True, 1),
        (0xFFFFFFFF, 0xFFFFFFFF, True, True, 1),
        (9, 2, False, True, 0),
        (2, 9, True, False, 1),
        (0, 0, False, False, 1),
    ):
        reset()
        for address, count, valid in zip(FLASH, (a, b), (valid_a, valid_b)):
            write(address + 0x40E4, count)
            if not valid:
                write(address + 0x40FC, 0)
        actual = run(0x517F08, meta_provider, 1)
        require(actual, selected, "metadata generation selects bank")
        generations.append(
            dict(a=a, b=b, valid_a=valid_a, valid_b=valid_b, selected=actual)
        )

    def boundary(_vm, address, _size, _user):
        off = address - BASE
        if off == 0x599914:
            dest, count = reg("r1"), reg("r2")
            expected = bytearray(vm.mem_read(state["source"], 0x20000))
            for region, size, ram in REGIONS:
                expected[region : region + size] = vm.mem_read(ram, size)
            staged = bytes(vm.mem_read(STAGE, 0x20000))
            require(staged, bytes(expected), "staged sector preserves all other bytes")
            require(
                [dest, count], [state["target"], 0x10000], "opposite sector request"
            )
            state["requests"].append(
                dict(
                    destination=dest,
                    halfwords=count,
                    staged_sha256=sha256(staged),
                    metadata_counter=u32(staged, 0x40E4),
                )
            )
            reg("r0", state["status"])
        else:
            state.setdefault("sync", []).append(off)
            reg("r0", 0)
        reg("pc", reg("lr"))

    for off in (0x599F20, 0x599F6C, 0x72C988, 0x599914):
        vm.hook_add(uc.UC_HOOK_CODE, boundary, begin=BASE + off, end=BASE + off)

    writes = []

    def observe_store(_vm, _address, _size, _user):
        writes.append([reg(f"r{i}") for i in range(4)])

    vm.hook_add(
        uc.UC_HOOK_CODE, observe_store, begin=BASE + 0x6FE52C, end=BASE + 0x6FE52C
    )
    saves = []
    for name, a, b, key, initial, value, status, mixed in (
        ("same_color_srgb", 5, 4, 0x15C, 0, 0, 0, False),
        ("same_color_adobergb", 5, 4, 0x15C, 1, 1, 0, False),
        ("color_adobergb_a_to_b", 5, 4, 0x15C, 0, 1, 0, False),
        ("color_adobergb_b_to_a", 4, 5, 0x15C, 0, 1, 0, False),
        ("color_srgb_a_to_b", 5, 4, 0x15C, 1, 0, 0, False),
        ("raw_dng_a_to_b", 5, 4, 0x97, 0, 1, 0, False),
        ("write_status_1", 5, 4, 0x15C, 0, 1, 1, False),
        ("write_status_2", 5, 4, 0x15C, 0, 1, 2, False),
        ("write_status_3", 5, 4, 0x15C, 0, 1, 3, False),
        ("generation_rollover", 0xFFFFFFFF, 0xFFFFFFFE, 0x15C, 0, 1, 0, False),
        ("metadata_a_main_b", 5, 4, 0x15C, 0, 1, 0, True),
    ):
        reset()
        for address, count in zip(FLASH, (a, b)):
            write(address + 0x40E4, count)
            write(address + 0x588 + key, initial, "B")
        if mixed:
            write(FLASH[0] + 0x23B0, 0)
            for address, canary in zip(FLASH, (0x11, 0x22)):
                write(address + 0x400, canary, "B")
                write(address + 0x10000, canary, "B")
        run(0x6E802C, manager)
        selected = read(manager + 0x2CB, "B")
        main_selected = read(manager + 0x2CC, "B")
        if mixed:
            require(
                [selected, main_selected], [1, 0], "independent metadata/main selectors"
            )
        source, target = FLASH[1 - selected], FLASH[selected]
        for obj in (provider, meta_provider, extra_provider):
            run(read(read(obj) + 0x1C) - BASE, obj)
        if mixed:
            require(read(MIRROR + 0x400, "B"), 0x22, "valid main payload loaded from B")
        # The binding slice starts after the singleton accessors return the manager.
        run(0x700770, manager, end=0x70078C, r4=cfg)
        require(read(cfg + 0xC), MIRROR, "native configuration mirror binding")
        run(0x7007A4, cfg)
        require(
            bytes(vm.mem_read(cfg + 0x14, 0x23B4)),
            bytes(vm.mem_read(MIRROR, 0x23B4)),
            "live configuration reload",
        )
        write(cfg + 0x23C8, 0, "B")
        writes.clear()
        run(0x700E84, cfg, key, value, 0xFF)
        require(
            writes,
            [[cfg + 0x14, key, value, 0], [MIRROR, key, value, 0]],
            "native live/mirror setting writes",
        )
        before = bytes(vm.mem_read(MIRROR, 0x23B4))
        counter = read(META + 0xE4)
        flash_before = [bytes(vm.mem_read(address, 0x20000)) for address in FLASH]
        state.clear()
        state.update(source=source, target=target, status=status, requests=[])
        result = run(0x6E8194, manager)
        changed = value != initial
        require(result, status if changed else 0, "save return propagation")
        require(
            len(state["requests"]),
            int(changed),
            "changed vs same-value sector write",
        )
        require(
            read(META + 0xE4),
            (counter + int(changed)) & 0xFFFFFFFF,
            "metadata increments only when staged content differs",
        )
        require(
            bytes(vm.mem_read(MIRROR, 0x23B4)),
            before,
            "save preserves pending RAM settings",
        )
        require(
            [bytes(vm.mem_read(address, 0x20000)) for address in FLASH],
            flash_before,
            "write boundary does not simulate flash mutation",
        )
        if mixed:
            require(
                [read(STAGE + 0x400, "B"), read(STAGE + 0x10000, "B")],
                [0x22, 0x11],
                "main B overlaid on full-sector A background",
            )
        saves.append(
            dict(
                name=name,
                selected=selected,
                main_selected=main_selected,
                main_marker_fallback=mixed,
                source=source,
                key=key,
                initial=initial,
                value=value,
                ram_setting_writes=len(writes),
                sector_requests=state["requests"],
                boundary_status=status,
                returned=result,
                counter_before=counter,
                counter_after=read(META + 0xE4),
                sync_boundaries=state["sync"],
            )
        )
    return dict(
        unicorn_version=uc.__version__,
        main_selection_cases=selections,
        metadata_generation_cases=generations,
        connected_save_cases=saves,
        execution_replacement_offsets=[0x599F20, 0x599F6C, 0x72C988, 0x599914],
        readonly_observer_offsets=[0x6FE52C],
    )


def analyze(data):
    check_words(data, WORDS)
    for source, target in EDGES.items():
        check_edge(data, source, target)
    require(data[0x1A0000:0x1C0000], data[0x2C0000:0x2E0000], "package settings copies")
    return dict(
        decoded_sha256=DECODED_SHA256,
        sector_bytes=0x20000,
        preserved_sector_indices=list(range(13, 23)),
        settings_sector_indices=[13, 22],
        settings_sector_package_sha256=sha256(data[0x1A0000:0x1C0000]),
        settings_copies_byte_identical=True,
        regions=[
            dict(sector_offset=o, bytes=n, ram_address=ram) for o, n, ram in REGIONS
        ],
        words_checked=len(WORDS),
        branches_checked=len(EDGES),
        range_hashes={f"{a:#x}..{b:#x}": sha256(data[a:b]) for a, b in RANGES},
        original_a32=emulate(data),
        limits=[
            "Selection and save input objects are constructed fixtures with original vtables; no camera startup or menu scheduler executes.",
            "The configuration binding slice begins after singleton accessors; the live/mirror copy, setter, bank mapping, staging and comparisons execute unchanged.",
            "Mailbox handshakes, a synchronization wrapper and the sector-write controller are replaced. No flash write, cache timing, power loss or reboot recovery is simulated.",
            "Success or error at the sector-write boundary is supplied. Physical durability, retries and active-copy switching after save remain unverified.",
            "This identifies settings in sectors 13 and 22. It does not assign all contents of preserved sectors 14 through 21.",
        ],
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = analyze(load_image(args.decoded))
    if args.compare:
        require(
            result,
            json.loads(args.compare.read_text(encoding="utf-8")),
            "settings storage snapshot",
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
