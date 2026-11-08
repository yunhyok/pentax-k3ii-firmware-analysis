"""Verify the K-3 II Custom Image event, label resource and tone-selector binding.

SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import json
from pathlib import Path
import struct

from verify_findings import DECODED_SHA256, literal_offset, require, sha256, u32
from verify_tone_path import BASE, check_edge, check_words, load_image


MENU = (
    (1, "Bright"), (0, "Natural"), (2, "Portrait"), (3, "Landscape"),
    (4, "Vibrant"), (8, "Radiant"), (5, "Muted"), (7, "Bleach Bypass"),
    (6, "Reversal Film"), (10, "Monochrome"), (9, "Cross Processing"),
)
EVENT_BASE = 0x01205008
CHOICE_WIDGET = 0x01205006
ROOT_WIDGET = 0x01205001
WIDGET_TABLE = 0x981FD4
CHOICE_TABLE = 0x981F74
VTABLE = 0xA5DF60
DISPATCH = 0x6D5ED0
EVENT_HANDLER = 0x346848
EVENT_EXIT = 0x3468DC
EVENT_BRANCHES = (0x3468C0, 0x3468CC, *(0x346964 + 12 * i for i in range(9)))


def verify(data):
    for site, target, link in (
        (0x3446A0, 0x70916C, True), (0x344744, 0x70A1B8, True), (0x344834, 0x70A1B8, True),
        (0x70A32C, 0x70A6C4, False), (0x70A6D4, 0x7093B4, True),
        (0x7093E8, 0x4ED6C0, True), (0x3468D8, 0x3466EC, True),
        (0x346764, 0x6F5148, True), (0x346774, 0x6F29E0, True),
        (0x346788, 0x6D60E8, True), (0x34679C, 0x4ED518, True), (0x4ED580, 0x873B08, True),
        (0x6F5150, 0x6F1A38, False), (0x6F1A40, 0x700E84, False),
        (0x700ED4, 0x4B14C4, True), (0x700EEC, 0x6FE52C, True),
        (0x6F2A08, 0x6F29C0, False), (0x6F29CC, 0x6F2770, True),
        (0x6F2914, 0x6F2768, False), (0x6F29DC, 0x6F2728, False),
        (0x6F273C, 0x701340, True), (0x701364, 0x6FE0F8, True), (0x701378, 0x6FE0F8, False),
        (0x701624, 0x6FE128, True), (0x702944, 0x701434, True),
        (0x7029A8, 0x70145C, True), (0x7014B0, 0x6FE150, True), (0x7014A0, 0x6FE180, True),
        (0x7029B8, 0x6EF39C, True), (0x658BE8, 0x6EFE04, True), (0x658BF0, 0x6EF3B8, True),
        (0x658C04, 0x73DC74, True), (0x4DDAD0, 0x4FA948, True),
        (0x4DDAE0, 0x4FA83C, True), (0x4DDAEC, 0x52671C, True), (0x4DDC74, 0x4DD924, True),
    ):
        check_edge(data, site, target, link=link)

    for site, value in (
        (0x34347C, BASE + VTABLE), (0x344698, BASE + WIDGET_TABLE), (0x344730, CHOICE_WIDGET),
        (0x34482C, EVENT_BASE + 8), (0x346780, CHOICE_WIDGET), (0x346880, -EVENT_BASE & 0xFFFFFFFF),
        (0x34617C, ROOT_WIDGET), (0x346220, EVENT_BASE + 8),
        (0x8739AC, 0x02DDDB88), (0x4DDAD8, 0x18A0C),
    ):
        require(u32(data, literal_offset(data, site)), value, f"literal at {site:#x}")
    require(u32(data, VTABLE + 0xC0), BASE + EVENT_HANDLER, "screen event vtable slot")
    require(u32(data, VTABLE + 0xBC), BASE + 0x34617C, "screen reverse selection slot")
    require(data[0xDDDB88], 1, "English locale uses byte glyphs")
    require(u32(data, 0x982054), BASE + CHOICE_TABLE, "choice widget payload")
    require((u32(data, 0x98204C), u32(data, 0x982050)), (CHOICE_WIDGET, 0x1E), "choice widget descriptor")
    check_words(data, {
        0x343488: 0xE5801000, 0x6D5ED0: 0xE5902000, 0x6D5ED4: 0xE59220C0, 0x6D5ED8: 0xE12FFF12,
        0x34684C: 0xE1A07001, 0x34686C: 0xE5D400EF, 0x346874: 0x18BD81F0,
        0x346884: 0xE0800007, 0x346888: 0xE350000B, 0x34688C: 0x308FF100,
        0x346700: 0xE5D61104, 0x346708: 0xE1500001, 0x34670C: 0x1A000019, 0x34676C: 0xE1C450BA,
        0x346820: 0xE3A01006, 0x4ED6D0: 0xE583101C, 0x4ED548: 0xE5940020,
        0x4ED558: 0xE5D03000, 0x4ED560: 0x05901004, 0x4ED568: 0x12800008,
        0x8739B0: 0xE7951106, 0x873B0C: 0xE5801090,
        0x6F514C: 0xE3A01039, 0x6FE544: 0xE7C02001, 0x6FE108: 0xE1C012B0, 0x6FE19C: 0xE5D00328,
        0x70297C: 0xE350000C, 0x7029B0: 0xE1A01004, 0x7029C8: 0x3AFFFFF2,
        0x6EF3A0: 0xE5C0209C, 0x658BE4: 0xE2800FC3, 0x658BEC: 0xE3A01000, 0x658BF8: 0xE30E00C4,
        0x73DC74: 0xE5801044, 0x4DDABC: 0xE2805B62, 0x4DDAC0: 0xE2855F86, 0x4DDAE8: 0xE5950000, 0x4DDB08: 0xE3500006, 0x4DDB28: 0x0A00003F,
    })
    check_edge(data, 0x3468B4, 0x3469AC, link=False)
    check_edge(data, 0x3469B4, 0x3468D4, link=False)
    check_edge(data, 0x346734, 0x346818, link=False)
    check_edge(data, 0x346824, 0x346764, link=False)
    check_edge(data, 0x3461CC, 0x346220, link=False)

    rows = []
    for i, ((key, name), target) in enumerate(zip(MENU, EVENT_BRANCHES)):
        event = EVENT_BASE + i
        child = 0x982074 + 20 * i
        require((u32(data, child), u32(data, child + 4)), (event, 2), "mode child widget")
        check_edge(data, 0x346894 + 4 * i, target, link=False)
        require(u32(data, target + 4), 0xE1A01002 if i == 0 else 0xE3A01000 | key,
                f"event key at {target:#x}")

        row = CHOICE_TABLE + 8 * i
        require(u32(data, row), key, "choice resource key")
        locale_record = u32(data, row + 4) - BASE
        string = u32(data, locale_record) - BASE
        require(0 <= string < len(data), True, "glyph string within image")
        encoded = data[string:data.index(0, string, string + 64)]
        require("".join(chr(x + 0x1E) for x in encoded), name, "English glyph resource")
        rows.append({"index": i, "event": event, "selector": key, "name": name,
                     "event_branch": target, "child_widget_record": child, "choice_row": row,
                     "locale_record": locale_record, "english_glyph_offset": string,
                     "glyph_sha256": sha256(encoded)})
    require(u32(data, CHOICE_TABLE + 8 * len(MENU) + 4), 0, "choice table terminator")

    return {
        "decoded_sha256": DECODED_SHA256,
        "offset_space": "Decoded file offsets unless explicitly an event, widget ID, object offset or address.",
        "screen": {"constructor": 0x343474, "vtable": VTABLE, "dispatch": DISPATCH,
                   "event_slot_offset": 0xC0, "event_handler": EVENT_HANDLER,
                   "widget_table": WIDGET_TABLE, "choice_widget_id": CHOICE_WIDGET, "choice_table": CHOICE_TABLE,
                   "english_encoding": "Locale pointer slot 0. Zero-terminated glyph codes plus 0x1e."},
        "configuration": {
            "event_base": EVENT_BASE, "choice_entry": 0x3466EC, "parameter_id": 0x39, "parameter_object_offset": 0x5D5,
            "active_profile_writer": 0x701340, "active_profile_getter": 0x701434,
            "active_profile_object_offset": 0x334, "bank_stride": 1048,
            "profile_row_object_offset": 0x33C, "profile_row_stride": 10,
            "parameter_zero_copy": 0x7029B8, "recipe_byte_offset": 0x9C,
            "processing_word_setter": 0x73DC74, "processing_word_offset": 0x44,
            "tone_selector_entry": 0x4DDAB8, "tone_recipe_pointer_offset": 0x18A18,
            "selector_6_branch": 0x4DDC2C, "selector_6_producer_call": 0x4DDC74,
        },
        "rows": rows,
        "code_range_sha256": {f"{a:#x}..{b:#x}": sha256(data[a:b]) for a, b in (
            (0x3466EC, 0x3469D0), (0x34617C, 0x346238), (0x4ED518, 0x4ED598),
            (0x6F2728, 0x6F2768), (0x701340, 0x70137C), (0x70293C, 0x7029CC),
            (0x658BE4, 0x658C08), (0x4DDAB8, 0x4DDB2C),
            (CHOICE_TABLE, 0x981FD4), (WIDGET_TABLE, 0x982150),
        )},
        "limits": [
            "The event ID is the screen handler input and the corresponding child widget ID.",
            "Physical button/dial input and actual LCD drawing were not executed.",
            "The configuration flow is tested with an initialized default bank in RAM. Persistent storage I/O is outside this check.",
        ],
    }


def emulate(data):
    import unicorn
    from unicorn.arm_const import (
        UC_ARM_REG_C1_C0_2, UC_ARM_REG_FPEXC, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP,
        UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
        UC_ARM_REG_R7, UC_ARM_REG_R8, UC_CPU_ARM_CORTEX_A9,
    )

    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    vm.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
    scratch = 0x10000000
    stop = scratch + 0x4F000
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    vm.mem_map(scratch, 0x50000)
    vm.mem_map(0x40400000, 0x100000)
    vm.reg_write(UC_ARM_REG_C1_C0_2, 0xF00000)
    vm.reg_write(UC_ARM_REG_FPEXC, 0x40000000)

    def write(addr, fmt, *values):
        vm.mem_write(addr, struct.pack("<" + fmt, *values))

    def read(addr, fmt):
        return struct.unpack("<" + fmt, vm.mem_read(addr, struct.calcsize(fmt)))[0]

    def run(entry, *args, end=None, registers=()):
        vm.reg_write(UC_ARM_REG_SP, stop - 0x1000)
        vm.reg_write(UC_ARM_REG_LR, stop)
        for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            vm.reg_write(reg, value)
        for reg, value in registers:
            vm.reg_write(reg, value)
        until = stop if end is None else BASE + end
        vm.emu_start(BASE + entry, until, count=200000)
        require(vm.reg_read(UC_ARM_REG_PC), until, f"bounded execution at {entry:#x}")
        return vm.reg_read(UC_ARM_REG_R0)

    ui, core, cfg, mirror, widget, label, notifier, manager = (
        scratch + x for x in (0x1000, 0x3000, 0x5000, 0x8000, 0xB000, 0xB800, 0xC000, 0xC800)
    )
    job = scratch + 0x14000
    tone = scratch + 0x24000
    return_only = scratch + 0xF000
    lookup = return_only + 4
    write(return_only, "4I", 0xE12FFF1E, 0xE59F0000, 0xE12FFF1E, widget)
    write(ui, "I", BASE + VTABLE)
    write(ui + 0xB4, "I", core)
    write(ui + 0xC4, "I", notifier)
    write(ui + 0x24, "I", manager)
    for obj, slot, method in ((notifier, 0x18, return_only), (manager, 8, lookup), (widget, 0xC, return_only)):
        write(obj, "I", obj + 0x100)
        write(obj + 0x100 + slot, "I", method)
    write(widget + 4, "I", label)
    write(widget + 0x20, "I", BASE + CHOICE_TABLE)
    write(core + 0xC, "I", cfg)
    for i, offset in enumerate((0x3C, 0x30, 0x20)):
        record = scratch + 0xD000 + i * 0x300
        write(core + offset, "I", record)
        write(record + (4 if offset == 0x3C else 0x10), "I", record + 0x100)
    write(ui + 0x104, "B", 1)

    def check_lookup(uc, address, size, user):
        require(uc.reg_read(UC_ARM_REG_R1), CHOICE_WIDGET, "fixture widget lookup ID")

    def skip_refresh(uc, address, size, user):
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    vm.hook_add(unicorn.UC_HOOK_CODE, check_lookup, begin=lookup, end=lookup)
    vm.hook_add(unicorn.UC_HOOK_CODE, skip_refresh, begin=BASE + 0x346238, end=BASE + 0x346238)

    bank = 2
    cfg_row = cfg + 1048 * bank
    write(cfg + 0xC, "I", mirror)
    write(cfg + 0x23C8, "B", bank)
    run(0x4DBC14)
    run(0x4DABD8, 0x40481C50)
    write(0x4040BA6C, "I", 1)
    run(0x7015D4, cfg, bank)
    require([read(cfg_row + 0x33C + 10 * i, "B") for i in range(11)], list(range(11)), "initialized profile rows")

    cases = []
    source = job + 0x146C
    write(tone + 0x18A18, "I", job + 0xE0C4)
    write(tone + 0x18A0C, "I", tone)
    for i, (key, name) in enumerate(MENU):
        event = EVENT_BASE + i
        write(ui + 0x10A, "H", 0xFFFF)
        write(widget + 0x25, "B", 0)
        run(DISPATCH, ui, event, end=EVENT_EXIT)
        require(read(ui + 0x10A, "H"), key, "screen choice")
        require(read(cfg_row + 0x334, "H"), key, "active profile")
        require(read(cfg_row + 0x5D5, "B"), key, "configuration parameter 0x39")
        require(read(mirror + 1048 * bank + 0x320, "H"), key, "mirrored active profile")
        pointer = read(label + 0x90, "I")
        require(pointer, u32(data, CHOICE_TABLE + 8 * i + 4), "widget selected locale record")
        require(run(0x34617C, ui, ROOT_WIDGET), event, "reverse event ID")

        run(0x70293C, end=0x7029CC, registers=((UC_ARM_REG_R7, cfg), (UC_ARM_REG_R8, source), (UC_ARM_REG_R5, bank)))
        require(read(source + 0x9C, "B"), key, "recipe byte")
        run(0x658BE4, job, end=0x658C08, registers=((UC_ARM_REG_R4, job),))
        require(read(job + 0xE108, "I"), key, "processing selector")
        target = 0x4DDC2C if key == 6 else 0x4DDB2C
        run(0x4DDAB8, tone, end=target)
        cases.append({"event": event, "name": name, "selector": key,
                      "selected_locale_record": pointer - BASE, "tone_branch": target})

    initial = bytes(vm.mem_read(cfg, 0x2400))
    initial_choice = read(ui + 0x10A, "H")
    for event in (EVENT_BASE - 1, EVENT_BASE + len(MENU)):
        run(DISPATCH, ui, event, end=EVENT_EXIT)
        require(bytes(vm.mem_read(cfg, 0x2400)) == initial, True, "unmapped event kept configuration")
        require(read(ui + 0x10A, "H"), initial_choice, "unmapped event kept choice")
    write(ui + 0xEF, "B", 1)
    run(DISPATCH, ui, EVENT_BASE + 8)
    require(bytes(vm.mem_read(cfg, 0x2400)) == initial, True, "blocked event kept configuration")
    require(read(ui + 0x10A, "H"), initial_choice, "blocked event kept choice")

    return {"unicorn_version": unicorn.__version__, "bank": bank, "mode_events": cases,
            "unmapped_events": [EVENT_BASE - 1, EVENT_BASE + len(MENU)],
            "blocked_event": EVENT_BASE + 8,
            "boundaries": [
                "Fixture callback for the screen notification and widget activation.",
                "Fixture widget lookup verifies the requested ID and returns a RAM widget.",
                "Screen-layout refresh 0x346238 skipped at entry. Outer handler stops at 0x3468dc.",
                "Recipe copy checks start at internal entry points with explicit register preconditions.",
                "Tone selector runs from its entry to the chosen branch. Curve generation is outside this check.",
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded_image", type=Path)
    parser.add_argument("--emulate", action="store_true")
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--output", type=Path)
    output.add_argument("--compare", type=Path)
    args = parser.parse_args()
    data = load_image(args.decoded_image)
    result = verify(data)
    if args.emulate:
        result["numeric"] = emulate(data)
    if args.compare:
        require(result, json.loads(args.compare.read_text(encoding="utf-8")), "menu event evidence")
        print(f"Menu event evidence matches {args.compare}")
    elif args.output:
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
