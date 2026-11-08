"""Verify K-3 II job-mode producers and masked/second-pass predicates.

SPDX-License-Identifier: GPL-2.0-only
Code locations are decoded file offsets. No physical camera is executed.
"""

import argparse
import json
from pathlib import Path

from verify_findings import DECODED_SHA256, require, sha256, u32
from verify_raw_path import branch_target
from verify_tone_path import BASE, check_words, load_image


WORDS = {
    0xA684F4: BASE + 0x6552B0,
    0xA6853C: BASE + 0x65FAE0,
    0xA68554: BASE + 0x65FEA8,
    0x52A8B4: 0xE3A01005,
    0x52A8BC: 0xE5902014,
    0x52A8C4: 0xE12FFF32,
    0x52BA90: 0x13A00008,
    0x52BA94: 0x03A00007,
    0x52BAC4: 0xE5912014,
    0x52BAC8: 0xE59D1024,
    0x52BACC: 0xE12FFF32,
    0x7B5600: 0xE3A01005,
    0x7B5604: 0xE5902014,
    0x6552C0: 0xE5C51084,
    0x655328: 0xE5C50080,
    0x655334: 0xE5C50081,
    0x655340: 0xE5C50082,
    0x655464: 0xE590105C,
    0x65546C: 0xE12FFF31,
    0x6554A4: 0xE5901074,
    0x6554AC: 0xE12FFF31,
    0x65FAFC: 0xE3500005,
    0x65FB0C: 0xE3001245,
    0x65FB14: 0xE3500001,
    0x65FB1C: 0x05C40059,
    0x6EF454: 0xE5D000EC,
    0x85A568: 0xE1D000B0,
    0x65DC40: 0xE3510015,
    0x65DD94: 0xE3A01008,
    0x65DDA4: 0x03A00080,
    0x9D1904: 0x032900EB,
    0x9D1908: 4,
    0x9D190C: BASE + 0xE405C0,
    0x94CD70: 0x032900EB,
    0x5E73B4: 0xE30004B5,
    0x5E73BC: 0xE58D0024,
    0x5E8D38: 0xE30014B5,
    0x5E8D40: 0xE58D102C,
    0x5E9B5C: 0xE59D002C,
    0x5E9B60: 0xE5D01000,
    0x5E7CD0: 0xE59D0024,
    0x5E7CD4: 0xE5D01000,
    0x61A094: 0x15D468C9,
    0x61A0DC: 0xE3001245,
    0x72D370: 0xE1C01BB2,
    0x7B5720: 0xE3A0100B,
    0x7B5724: 0xE5902014,
    0x6F4D98: 0xE3A01098,
    0x5297E4: 0xE3A01098,
    0x5297EC: 0xE3500000,
    0x5297F4: 0xE59D0020,
    0x52989C: 0xE3A06004,
    0x5298A0: 0xE58D0028,
}
EDGES = (
    (0x65FB08, 0x6EFE04),
    (0x65FB10, 0x6EF450),
    (0x65FF40, 0x784E88),
    (0x65FF74, 0x784E88),
    (0x784E8C, 0x85A564),
    (0x65DCC8, 0x65DD90),
    (0x52A7F4, 0x6EF444),
    (0x7B55C0, 0x7073EC),
    (0x5E9B68, 0x94C9E8),
    (0x5E7AD4, 0x5E5DB8),
    (0x5E5E1C, 0x5E5E94),
    (0x5E7CDC, 0x61A898),
    (0x61A068, 0x619960),
    (0x61A07C, 0x7031F4),
    (0x61A08C, 0x619934),
    (0x61A0E4, 0x6EF444),
    (0x52A05C, 0x72D36C),
    (0x52A068, 0x72D36C),
    (0x52A074, 0x72D36C),
    (0x52A080, 0x72D36C),
    (0x5296F0, 0x7B3240),
    (0x5297E0, 0x6EFE04),
    (0x5297E8, 0x6EF450),
    (0x529810, 0x5A1618),
    (0x529820, 0x5A1618),
    (0x529830, 0x5A1618),
    (0x7B55B0, 0x6F4D98),
    (0x7B55B8, 0x7B56DC),
    (0x7B56E0, 0x7073EC),
    (0x7B5728, 0x7B5608),
    (0x6F4D9C, 0x6F1A50),
    (0x6F1A58, 0x701EF4),
)
RANGES = {
    "prepare_mode_prefix": (0x6552B0, 0x655344),
    "second_pass_producer": (0x65FAE0, 0x65FB2C),
    "mask_producer": (0x65FEA8, 0x65FFA0),
    "module20_completion_mask": (0x65DD90, 0x65DDB8),
    "development_mode5_call": (0x52A8B0, 0x52A8C8),
    "alternate_mode7_8_call": (0x52BA8C, 0x52BAD0),
    "color_fringe_toggle": (0x5E5DB8, 0x5E5ED0),
    "color_fringe_config_setter": (0x61A898, 0x61A8B0),
    "color_fringe_guards_and_export": (0x61A060, 0x61A0E8),
    "color_fringe_label_display": (0x94C9E8, 0x94CA90),
    "four_job_kind_assignment": (0x52A048, 0x52A084),
    "development_input_kind": (0x5296EC, 0x529744),
    "development_multiframe_condition": (0x5297DC, 0x5298A4),
    "superresolution_mode11_call": (0x7B56DC, 0x7B572C),
    "superresolution_condition": (0x7B55AC, 0x7B55C4),
}


def emulate(data):
    import unicorn
    from unicorn import arm_const as arm

    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    job, capture, array = 0x10000000, 0x10020000, 0x10021000
    sp, ret = 0x1003F000, 0x1003FF00
    vm.mem_map(job, 0x40000)

    def write(address, value, width=4):
        vm.mem_write(address, value.to_bytes(width, "little"))

    def read(address, width=1):
        return int.from_bytes(vm.mem_read(address, width), "little")

    def run(start, end=None, **registers):
        stop = ret if end is None else BASE + end
        for name, value in dict(sp=sp, lr=ret, **registers).items():
            vm.reg_write(getattr(arm, "UC_ARM_REG_" + name.upper()), value)
        vm.ctl_flush_tb()
        vm.emu_start(BASE + start, stop, count=10000)
        require(vm.reg_read(arm.UC_ARM_REG_PC), stop, f"stop {start:#x}")

    def prepare(mode):
        vm.mem_write(job, bytes(0x18000))
        write(job, BASE + 0xA684E0)
        write(job + 0x34, capture)
        run(0x6552B0, 0x655344, r0=job, r1=mode)
        expected = [int(mode in (5, 7, 8, 11)), int(mode in (7, 8)), int(mode == 11)]
        actual = [read(job + i) for i in (0x2080, 0x2081, 0x2082)]
        require(actual, expected, "mode-derived flags")
        require(read(job + 0x2084), mode, "mode field")
        return actual

    flag_cases = []
    for mode in range(12):
        flags = prepare(mode)
        outputs = []
        for tag_value in (0, 1, 2):
            write(job + 0x30C + 0x1160 + 0xEC + 0x245, tag_value, 1)
            write(job + 0x59, 0xA5, 1)
            write(job + 0x8D, 0xA5, 1)
            run(0x65FAE0, r0=job)
            expected = int(mode == 5 and tag_value == 1)
            require(
                [read(job + 0x59), read(job + 0x8D)],
                [expected] * 2,
                "second-pass producer and mirror",
            )
            outputs.append(expected)
        flag_cases.append(
            {
                "job_mode": mode,
                "flags_2080_2081_2082": flags,
                "second_pass_for_tag245_values_0_1_2": outputs,
            }
        )

    # This real call site selects mode 5 through the firmware's original vtable.
    prepare(0)
    write(array, job)
    run(0x52A8B0, 0x655344, r8=array, r4=0)
    require(read(job + 0x2084), 5, "DevelopmentRawImage virtual prepare mode")
    run(0x7B571C, 0x655344, r5=job)
    require(
        read(job + 0x2084), 11, "SuperResolution diagnostic branch virtual prepare mode"
    )

    masks = []
    for mode in (0, 5, 7, 11):
        for kind in (0, 1, 2):
            for capture_enum in (0, 3):
                prepare(mode)
                write(job + 0x20B2, kind, 2)
                write(capture + 0x300, capture_enum, 2)
                run(0x65FEA8, r0=job)
                if mode == 11:
                    expected = 0x40
                elif kind == 0:
                    expected = 1
                elif mode in (5, 7):
                    expected = 4 if kind == 1 else 2
                elif kind == 1:
                    expected = 0x40 if capture_enum == 3 else 4
                else:
                    expected = 0x20 if capture_enum == 3 else 2
                require(read(job + 0x20B4), expected, "mask producer")
                masks.append(
                    {
                        "job_mode": mode,
                        "layout_kind": kind,
                        "capture_enum": capture_enum,
                        "mask": expected,
                        "masked_cpp": bool(expected & 0x44),
                    }
                )

    transitions = []
    for before in (1, 2, 4, 0x40, 0x20, 8, 0x80):
        prepare(0)
        write(job + 0x20B4, before, 1)
        run(0x65DC34, r0=job, r1=20)
        after = 0x80 if before == 0x40 else 8
        require(read(job + 0x20B4), after, "module20 completion mask")
        transitions.append(
            {
                "before": before,
                "after": after,
                "masked_cpp_after": bool(after & 0x44),
                "planar_input_after": bool(after & 0x88),
            }
        )
    return {
        "engine": f"Unicorn {unicorn.__version__}",
        "hooks": [],
        "mode_and_second_pass": flag_cases,
        "second_pass_runs": 36,
        "original_raw_development_virtual_call_mode": 5,
        "original_superresolution_virtual_call_mode": 11,
        "mask_cases": masks,
        "module20_completion_cases": transitions,
    }


def analyze(data):
    check_words(data, WORDS)
    for source, target in EDGES:
        require(branch_target(data, source), target, f"edge {source:#x}")
    marker = b"[CCA] Normal DevMode \n\0"
    require(data[0x7B58B8 : 0x7B58B8 + len(marker)], marker, "development diagnostic")
    marker = b"[CCA] SuperResolution DevMode \n\0"
    require(
        data[0x7B58D4 : 0x7B58D4 + len(marker)], marker, "SuperResolution diagnostic"
    )
    glyph = u32(data, 0xE405C0) - BASE
    require(glyph, 0xE4C919, "Color Fringe English glyph pointer")
    encoded = data[glyph : data.index(0, glyph, glyph + 64)]
    require(
        "".join(chr(x + 0x1E) for x in encoded), "Color Fringe Correction", "menu label"
    )
    return {
        "decoded_sha256": DECODED_SHA256,
        "code_address_units": "decoded file offsets",
        "static": {
            "edges": EDGES,
            "words": WORDS,
            "ranges": {
                name: {"start": a, "end_exclusive": z, "sha256": sha256(data[a:z])}
                for name, (a, z) in RANGES.items()
            },
        },
        "original_a32": emulate(data),
        "ui_and_kind_a32": emulate_ui_and_kind(data),
        "color_fringe_label": {
            "widget_id": 0x032900EB,
            "widget_record": 0x9D1904,
            "locale_record": 0xE405C0,
            "english_glyph_offset": glyph,
            "decoded": "Color Fringe Correction",
            "glyph_sha256": sha256(encoded),
        },
        "limits": [
            "The mode preparation prefix stops before unrelated virtual initialization methods. "
            "The second-pass producer, mask producer and module20 completion handler then run "
            "as separate original functions without hooks on synthetic state.",
            "Mode 5 is tied to a real DevelopmentRawImage call site and a separate Normal DevMode "
            "diagnostic path. Numeric job modes are not exposure-dial labels.",
            "The standalone mask cases seed layout kind and capture enum. Separate RAW expansion "
            "cases execute the four-job kind producer with an intercepted allocator. Their "
            "physical camera menu producers and all permitted combinations remain unresolved.",
            "The module20 completion handler establishes state transitions; these probes do not "
            "execute the device, upstream eligibility or complete asynchronous recipe.",
        ],
    }


def emulate_ui_and_kind(data):
    import unicorn
    from unicorn import arm_const as arm

    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    screen, config, job = 0x10000000, 0x10002000, 0x10010000
    sp, ret = 0x1008F000, 0x1008FF00
    vm.mem_map(screen, 0x90000)

    def write(address, value, width=4):
        vm.mem_write(address, value.to_bytes(width, "little"))

    def read(address, width=1):
        return int.from_bytes(vm.mem_read(address, width), "little")

    def run(start, end=None, **registers):
        stop = ret if end is None else BASE + end
        for name, value in dict(sp=sp, lr=ret, **registers).items():
            vm.reg_write(getattr(arm, "UC_ARM_REG_" + name.upper()), value)
        vm.ctl_flush_tb()
        vm.emu_start(BASE + start, stop, count=10000)
        require(vm.reg_read(arm.UC_ARM_REG_PC), stop, f"UI stop {start:#x}")

    toggles = []
    for direction in (0, 1):
        for before in (0, 1):
            write(screen + 0x49F, 4, 1)
            write(screen + 0x4B5, before, 1)
            write(config + 0x8A9, 0xA5, 1)
            write(config + 0x8C9, 0xA5, 1)
            run(0x5E5DB8, r0=screen, r1=direction)
            after = read(screen + 0x4B5)
            require(after, 1 - before, "Color Fringe choice toggle")
            run(0x5E73B4, 0x5E73C0, r4=screen)
            write(screen, config)
            run(0x5E7CD0, 0x5E7CE0, r5=screen)
            require(
                [read(config + 0x8A9), read(config + 0x8C9)],
                [1, after],
                "screen choice committed through original setter",
            )
            toggles.append({"direction": direction, "before": before, "after": after})

    state = {}

    def guard(_vm, address, _size, _data):
        value = state["blocked"] if address == BASE + 0x619960 else state["capable"]
        vm.reg_write(arm.UC_ARM_REG_R0, value)
        vm.reg_write(arm.UC_ARM_REG_PC, vm.reg_read(arm.UC_ARM_REG_LR))

    for offset in (0x619960, 0x619934):
        vm.hook_add(unicorn.UC_HOOK_CODE, guard, begin=BASE + offset, end=BASE + offset)
    recipes = job + 0x30C + 0x1160
    cases = []
    for selected in (0, 1):
        for blocked in (0, 1):
            for enum in (0, 0x14):
                for capable in (0, 1):
                    state.update(blocked=blocked, capable=capable)
                    write(config + 0x8C9, selected, 1)
                    write(config + 4 + 0x244 + 0x20 * 4, enum)
                    write(recipes + 0xEC + 0x245, 0xA5, 1)
                    run(0x61A060, 0x61A0E8, r4=config, sl=recipes)
                    actual = read(recipes + 0xEC + 0x245)
                    expected = (
                        selected if not blocked and enum != 0x14 and capable else 0
                    )
                    require(actual, expected, "guarded Color Fringe tag export")
                    write(job + 0x2084, 5, 1)
                    run(0x65FAE0, r0=job)
                    require(
                        read(job + 0x59), expected, "exported tag to mode5 second pass"
                    )
                    cases.append(
                        {
                            "selected": selected,
                            "blocked_query": blocked,
                            "config_enum20": enum,
                            "capable_query": capable,
                            "tag245_and_second_pass": actual,
                        }
                    )

    kinds = []
    jobs = [job + 0x18000 * i for i in range(4)]
    for enabled in (0, 1):
        for i, obj in enumerate(jobs):
            write(sp + 4 * i, obj)
            write(obj + 0x20B2, 0, 2)
        write(sp + 0x28, enabled)
        run(0x52A048, 0x52A084)
        actual = [read(obj + 0x20B2, 2) for obj in jobs]
        require(
            actual, [1, 2, 3, 4] if enabled else [0] * 4, "four-job kind assignment"
        )
        kinds.append({"multiframe_expanded": enabled, "assigned_kinds": actual})

    allocations = []

    def allocate(_vm, _address, _size, _data):
        target = jobs[len(allocations) + 1]
        allocations.append(target)
        vm.reg_write(arm.UC_ARM_REG_R0, target)
        vm.reg_write(arm.UC_ARM_REG_PC, vm.reg_read(arm.UC_ARM_REG_LR))

    vm.hook_add(
        unicorn.UC_HOOK_CODE, allocate, begin=BASE + 0x5A1618, end=BASE + 0x5A1618
    )
    expansion_cases = []
    request = screen + 0x1000
    for tag98, input_kind in ((0, 3), (1, 0), (1, 3)):
        vm.mem_write(sp, bytes(0x100))
        for obj in jobs:
            write(obj, BASE + 0xA684E0)
            write(obj + 0x20B2, 0, 2)
        write(request, input_kind, 1)
        write(sp, job)
        write(sp + 0xDC, request)
        write(sp + 0x68, job + 0x30C)
        write(recipes + 0xEC + 0x98, tag98, 1)
        allocations.clear()
        run(0x5296EC, 0x529744)
        run(0x5297DC, 0x5298A4, r5=config, r6=1)
        expanded = tag98 != 0 and input_kind not in (0, 1, 2)
        require(read(sp + 0x28, 4), int(expanded), "RAW expansion flag")
        require(vm.reg_read(arm.UC_ARM_REG_R6), 4 if expanded else 1, "RAW job count")
        require(len(allocations), 3 if expanded else 0, "RAW extra allocations")
        run(0x52A048, 0x52A084)
        actual = [read(obj + 0x20B2, 2) for obj in jobs]
        require(actual, [1, 2, 3, 4] if expanded else [0] * 4, "RAW-derived job kinds")
        masks = []
        for obj in jobs[: 4 if expanded else 1]:
            run(0x6552B0, 0x655344, r0=obj, r1=5)
            run(0x65FEA8, r0=obj)
            masks.append(read(obj + 0x20B4))
        require(masks, [4, 2, 2, 2] if expanded else [1], "RAW mode5 masks")
        expansion_cases.append(
            {
                "tag98": tag98,
                "input_kind": input_kind,
                "extra_allocations": len(allocations),
                "kinds": actual,
                "mode5_masks": masks,
                "inhibit20": read(sp + 0x20, 4),
            }
        )
    return {
        "toggle_cases": toggles,
        "guarded_export_cases": cases,
        "kind_assignment_cases": kinds,
        "raw_expansion_cases": expansion_cases,
        "hooked_allocator_offset": 0x5A1618,
        "hooked_guard_offsets": [0x619960, 0x619934],
        "limits": "UI drawing and physical input are not executed. The two capability/metadata "
        "queries are supplied as booleans; their firmware predicates and real availability "
        "are not established. Original UI toggle, commit segment, guarded exporter, tag getter "
        "and mode5 producer run as separate segments. Export cases independently seed "
        "the UI config value. The four-job segment first receives a seeded expansion flag; "
        "separate RAW cases derive it from original input-kind and tag branches with "
        "an intercepted allocator. Complete RAW jobs and metadata validity are untested.",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = json.loads(json.dumps(analyze(load_image(args.decoded))))
    if args.compare:
        require(
            result,
            json.loads(args.compare.read_text(encoding="utf-8")),
            "mode reachability snapshot",
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
