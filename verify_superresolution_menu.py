"""Verify the K-3 II Pixel Shift menu-to-SuperResolution job branch.

SPDX-License-Identifier: GPL-2.0-only
Firmware locations are decoded file offsets unless explicitly stated otherwise.
"""

import argparse
import json
from pathlib import Path

from verify_findings import DECODED_SHA256, literal_offset, require, sha256, u32
from verify_raw_path import branch_target
from verify_tone_path import BASE, check_words, load_image


VTABLE = 0xA70BFC
WIDGET_TABLE = 0x98ED88
CHOICE_TABLE = 0x98ED70
CHOICE_WIDGET = 0x01306004
OFF, ON = 0x01306006, 0x01306005
COMMIT_EVENTS = (0, 1, 6, 0x10, 0x11, 0x1D)
SETTING_ID = 0x98
BANK_STRIDE = 1048
BANK_OFFSET = 0x588 + SETTING_ID
GLOBAL = 0x40483F7C
GLOBAL_INITIALIZED = 0x4041D890
DIAGNOSTICS = {
    5: (0x7B58B8, "[CCA] Normal DevMode \n"),
    11: (0x7B58D4, "[CCA] SuperResolution DevMode \n"),
}
SETUP_STUBS = (0x7073EC, 0x76E764, 0x7774E4, 0x6540BC, 0x76D5E4, 0x76DAF0)
ON_SIDE_EFFECT_STUBS = (0x6F5E6C, 0x6F83AC)

WORDS = {
    0x3C5E70: 0xE5801000,
    0x3C6000: 0xE3A01098,
    0x3C6008: 0xE5C400E7,
    0x6D5EC8: 0xE59220BC,
    0x6D5ED4: 0xE59220C0,
    0x6D5F7C: 0xE59030D4,
    0x3C64D0: 0xE0900005,
    0x3C64D4: 0x03A00001,
    0x3C64DC: 0xE3500001,
    0x3C64E0: 0x03A00000,
    0x3C64E8: 0xE5C400E7,
    0x3C6528: 0xE5D420E7,
    0x3C652C: 0xE3A01098,
    0x6DA5E4: 0xE59000B4,
    0x6F1A38: 0xE590000C,
    0x6F1A3C: 0xE3A030FF,
    0x6F1A50: 0xE590000C,
    0x6F1A54: 0xE3A020FF,
    0x700ECC: 0x05D023C8,
    0x700ED0: 0xE59003CC,
    0x700EE8: 0xE2840014,
    0x700EF0: 0xE594000C,
    0x701F20: 0x05D023C8,
    0x701F24: 0xE59003CC,
    0x701F34: 0xE2840014,
    0x4B14C8: 0xE0800201,
    0x4B14CC: 0xE0800082,
    0x4B14D0: 0xE1D000B0,
    0x6FE540: 0xE3001588,
    0x6FE544: 0xE7C02001,
    0x6FE5CC: 0xE5D00588,
    0x6F4D98: 0xE3A01098,
    0x7B55B4: 0xE3500001,
    0x7B54C8: 0xE2476002,
    0x7B5538: 0xE3560010,
    0x7B553C: 0x308FF106,
    0x7B5954: 0xE92D41F0,
    0x7B5988: 0xE3550002,
    0x7B59E8: 0x308FF104,
    0x74C6E4: 0xE3520004,
    0x7DD7E8: 0xE1D000B4,
    0x7B5600: 0xE3A01005,
    0x7B5604: 0xE5902014,
    0x7B560C: 0xE12FFF32,
    0x7B5720: 0xE3A0100B,
    0x7B5724: 0xE5902014,
    0x6552C0: 0xE5C51084,
    0x74C9D8: 0xE300123B,
    0x74C9F4: 0xE3500008,
    0x749720: 0xE3500001,
    0x749724: 0xE595000C,
    0x74972C: 0xE3A01098,
    0x6EF448: 0xE5C020EC,
    0x5297E4: 0xE3A01098,
    0x5297EC: 0xE3500000,
}
EDGES = (
    (0x3C5E68, 0x6D5A38),
    (0x3C6004, 0x6F1A50),
    (0x3C6188, 0x70916C),
    (0x3C61E4, 0x70A1B8),
    (0x3C61FC, 0x70A1B8),
    (0x3C6214, 0x70A1B8),
    (0x3C622C, 0x70A1B8),
    (0x3C64F4, 0x6D60E8),
    (0x3C6500, 0x4ED518),
    (0x4ED580, 0x873B08),
    (0x3C6524, 0x6DA5E4),
    (0x3C6530, 0x6F1A38),
    (0x3C654C, 0x6F5E6C),
    (0x3C6560, 0x6F83AC),
    (0x3C65F4, 0x3C651C),
    (0x3C6618, 0x3C651C),
    (0x3C664C, 0x3C651C),
    (0x6F1A40, 0x700E84),
    (0x700ED4, 0x4B14C4),
    (0x700EEC, 0x6FE52C),
    (0x700F04, 0x6FE52C),
    (0x6F4D9C, 0x6F1A50),
    (0x6F1A58, 0x701EF4),
    (0x701F28, 0x4B14C4),
    (0x701F3C, 0x6FE5BC),
    (0x7B5540, 0x7B55AC),
    (0x7B55AC, 0x6F1708),
    (0x7B5994, 0x7B59E4),
    (0x7B59F4, 0x7B5A60),
    (0x7B5A6C, 0x7B572C),
    (0x7B57BC, 0x632E44),
    (0x7B58B0, 0x7B5400),
    (0x7B5424, 0x784E90),
    (0x7B545C, 0x7544B0),
    (0x7B5460, 0x6EFE04),
    (0x74C6FC, 0x7DD7E8),
    (0x7B55B0, 0x6F4D98),
    (0x7B55B8, 0x7B56DC),
    (0x7B5728, 0x7B5608),
    (0x74CA00, 0x7496DC),
    (0x74971C, 0x6C61BC),
    (0x749738, 0x6EF444),
    (0x5297E8, 0x6EF450),
)
RANGES = (
    (0x3C5E64, 0x3C5E84),
    (0x3C5FF8, 0x3C600C),
    (0x3C617C, 0x3C6234),
    (0x3C6474, 0x3C6660),
    (0x6D5EC4, 0x6D5EDC),
    (0x6D5F38, 0x6D5F8C),
    (0x700E84, 0x700F08),
    (0x701EF4, 0x701F40),
    (0x7B5538, 0x7B5610),
    (0x7B5400, 0x7B5538),
    (0x7B56DC, 0x7B572C),
    (0x7B572C, 0x7B58B4),
    (0x7B5954, 0x7B5A70),
    (0x74C6E0, 0x74CA08),
    (0x7496DC, 0x74973C),
    (CHOICE_TABLE, 0x98EE14),
)


def verify(data):
    check_words(data, WORDS)
    for site, target in EDGES:
        require(branch_target(data, site), target, f"branch at {site:#x}")
    for site, value in (
        (0x3C5E6C, BASE + VTABLE),
        (0x3C6180, BASE + WIDGET_TABLE),
        (0x3C61D8, 0x01306003),
        (0x3C61F4, CHOICE_WIDGET),
        (0x3C6208, ON),
        (0x3C6220, OFF),
        (0x3C64CC, -ON & 0xFFFFFFFF),
        (0x3C64F0, CHOICE_WIDGET),
        (0x4B14C4, BASE + 0xA52680),
        (0x6F1708, GLOBAL_INITIALIZED),
        (0x6F1748, GLOBAL),
    ):
        require(u32(data, literal_offset(data, site)), value, f"literal at {site:#x}")
    check_words(
        data,
        {
            VTABLE + 0xBC: BASE + 0x3C6474,
            VTABLE + 0xC0: BASE + 0x3C64A8,
            VTABLE + 0xD4: BASE + 0x3C6564,
            0xA684F4: BASE + 0x6552B0,
            0x98EDC4: 0x01306003,
            0x98EDC8: 3,
            0x98EDCC: BASE + 0xE3F9F0,
            0x98EDD8: CHOICE_WIDGET,
            0x98EDDC: 0x1E,
            0x98EDE0: BASE + CHOICE_TABLE,
            0x98EDEC: ON,
            0x98EDF0: 2,
            0x98EE00: OFF,
            0x98EE04: 2,
            0x98ED80: 0,
            0x98ED84: 0,
        },
    )

    def glyph(locale, expected_offset, name):
        offset = u32(data, locale) - BASE
        require(offset, expected_offset, "English glyph pointer")
        encoded = data[offset : data.index(0, offset, offset + 64)]
        require(
            "".join(chr(code + 0x1E) for code in encoded), name, "English glyph text"
        )
        return {
            "name": name,
            "locale_record": locale,
            "english_glyph_offset": offset,
            "glyph_sha256": sha256(encoded),
        }

    label = glyph(0xE3F9F0, 0xE4C6D8, "Pixel Shift Resolution")
    choices = []
    for key, event, widget, locale, offset, name in (
        (0, OFF, 0x98EE00, 0xE39978, 0xE4B996, "Off"),
        (1, ON, 0x98EDEC, 0xE39924, 0xE4B993, "On"),
    ):
        row = CHOICE_TABLE + 8 * key
        check_words(data, {row: key, row + 4: BASE + locale})
        choices.append(
            {
                "key": key,
                "event": event,
                "widget_record": widget,
                **glyph(locale, offset, name),
            }
        )
    for offset, label_text in DIAGNOSTICS.values():
        marker = label_text.encode("ascii") + b"\0"
        require(data[offset : offset + len(marker)], marker, "mode diagnostic")
    bank_row = 0xA52680 + SETTING_ID * 16
    banks = [
        int.from_bytes(data[pos : pos + 2], "little")
        for pos in range(bank_row, bank_row + 16, 2)
    ]
    require(banks, list(range(8)), "Pixel Shift bank mapping by active index")

    return {
        "decoded_sha256": DECODED_SHA256,
        "offset_space": "Decoded file offsets except object fields, IDs and runtime addresses.",
        "menu": {
            "constructor": 0x3C5E64,
            "vtable": VTABLE,
            "widget_table": WIDGET_TABLE,
            "label_widget": 0x98EDC4,
            "label": label,
            "choice_widget": CHOICE_WIDGET,
            "choice_table": CHOICE_TABLE,
            "choices": choices,
            "selection_byte": 0xE7,
            "reverse_selection_dispatch": 0x6D5EC4,
            "event_dispatch": 0x6D5ED0,
            "commit_dispatch": 0x6D5F38,
            "commit_event_codes": list(COMMIT_EVENTS),
            "selection_handler": 0x3C64A8,
            "commit_handler": 0x3C6564,
        },
        "profile_setting": {
            "id": SETTING_ID,
            "bank_stride": BANK_STRIDE,
            "bank_byte_offset": BANK_OFFSET,
            "primary_base_object_offset": 0x14,
            "mirror_pointer_object_offset": 0xC,
            "active_index_object_offset": 0x23C8,
            "bank_lookup_row": bank_row,
            "banks_by_active_index": banks,
            "write_entry": 0x3C651C,
            "reader_entry": 0x6F4D98,
        },
        "mode_branch": {
            "cca_dispatcher": 0x7B5954,
            "dispatch_keys": [2, 1],
            "devmode_helper": 0x7B5400,
            "verified_subtypes": [0, 1],
            "compare": 0x7B55B4,
            "normal_path": 0x7B55BC,
            "superresolution_path": 0x7B56DC,
            "prepare": 0x6552B0,
        },
        "raw_import": {
            "makernote_tag": 0x243,
            "dispatch": 0x74C6E0,
            "handler": 0x7496DC,
            "recipe_tag": 0x98,
            "recipe_object_offset": 0xEC + 0x98,
            "raw_development_reader_call": 0x5297E8,
            "payload_first_byte_equals": 1,
        },
        "branch_checks": [list(edge) for edge in EDGES],
        "range_sha256": {
            f"{start:#x}..{end:#x}": sha256(data[start:end]) for start, end in RANGES
        },
        "external_references": {
            "Ricoh K-3 II operating manual, printed p. 60": "https://www.ricoh-imaging.co.jp/english/support/man-pdf/k-3-2.pdf#page=62",
            "Ricoh K-3 II specifications": "https://www.ricoh-imaging.co.jp/english/products/k-3-2/spec/",
            "ExifTool Pentax MakerNote 0x0243 mapping": "https://github.com/exiftool/exiftool/blob/9b8664dfcf2c609d3cc8925d380e98ad2a379f9b/lib/Image/ExifTool/Pentax.pm#L3129-L3132",
        },
    }


def emulate(data):
    import unicorn
    from unicorn import arm_const as arm

    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    vm.mem_map(0x10000000, 0x50000)
    vm.mem_map(0x40400000, 0x100000)
    vm.reg_write(arm.UC_ARM_REG_C1_C0_2, 0xF00000)
    vm.reg_write(arm.UC_ARM_REG_FPEXC, 0x40000000)

    ui, notifier, manager, widget, label, panel = (
        0x10000000 + 0x200 * i for i in range(1, 7)
    )
    profile, mirror, job = 0x10002000, 0x10006000, 0x10010000
    controller, pool, command = 0x10018000, 0x10019000, 0x1001A000
    importer, record, payload, auxiliary = (
        0x10020000,
        0x10020200,
        0x10020400,
        0x10021000,
    )
    recipe = job + 0x30C + 0x1160
    recipe_setting = recipe + 0xEC + SETTING_ID
    callbacks, ret = 0x1004D000, 0x1004F000

    def put(addr, value, width=4):
        vm.mem_write(addr, value.to_bytes(width, "little"))

    def get(addr, width=1):
        return int.from_bytes(vm.mem_read(addr, width), "little")

    def reg(name):
        return getattr(arm, f"UC_ARM_REG_{name.upper()}")

    def run(entry, end=None, **registers):
        until = ret if end is None else BASE + end
        for name, value in dict(sp=ret - 0x1000, lr=ret, **registers).items():
            vm.reg_write(reg(name), value)
        vm.emu_start(BASE + entry, until, count=10000)
        require(vm.reg_read(reg("pc")), until, f"bounded execution at {entry:#x}")
        return vm.reg_read(reg("r0"))

    put(ui, BASE + VTABLE)
    put(ui + 4, panel)
    put(ui + 0x24, manager)
    put(ui + 0xB4, GLOBAL)
    put(ui + 0xC4, notifier)
    put(panel + 1, 5, 1)
    put(ui + 0xE4, 1, 1)
    for i, (obj, slot) in enumerate(
        ((notifier, 0x18), (notifier, 8), (manager, 8), (widget, 0xC))
    ):
        entry = callbacks + 4 * i
        put(entry, 0xE12FFF1E)  # BX LR, return from fixture virtual callback.
        put(obj, obj + 0x100)
        put(obj + 0x100 + slot, entry)
    put(widget + 4, label)
    put(widget + 0x20, BASE + CHOICE_TABLE)
    put(GLOBAL_INITIALIZED, 1)
    put(GLOBAL + 0xC, profile)
    put(profile + 0xC, mirror)
    put(job, BASE + 0xA684E0)
    put(job + 0x30, 4, 1)  # Prepared state required by the original readiness test.
    put(controller + 0x30, pool)
    put(pool + 0x33C, job)
    put(command + 0x858, 2, 1)
    put(command + 0x859, 1, 1)
    put(command + 8, 0xFF)  # Select the pool's fallback job pointer.

    traces = []

    def fixture(uc, address, size, user):
        r0, r1 = (uc.reg_read(reg(name)) for name in ("r0", "r1"))
        if address == callbacks + 8:
            require(r1, CHOICE_WIDGET, "lookup of Pixel Shift choice widget")
            uc.reg_write(reg("r0"), widget)
        elif address >= BASE and address < BASE + 0x1000000:
            offset = address - BASE
            traces.append((offset, r0, r1))
            uc.reg_write(reg("r0"), 0)
            uc.reg_write(reg("pc"), uc.reg_read(reg("lr")))

    vm.hook_add(unicorn.UC_HOOK_CODE, fixture, begin=callbacks + 8, end=callbacks + 8)
    for offset in (*ON_SIDE_EFFECT_STUBS, *SETUP_STUBS):
        vm.hook_add(
            unicorn.UC_HOOK_CODE, fixture, begin=BASE + offset, end=BASE + offset
        )

    def run_mode(value, subtype=0):
        traces.clear()
        put(job + 0x2084, 0xA5, 1)
        recipe_before = get(recipe_setting)
        put(command + 0xC, subtype)
        run(0x7B5954, 0x655344, r0=controller, r1=0, r2=command)
        require(
            get(job + 4, 4), controller + 4, "original dispatcher selected fixture job"
        )
        require(get(recipe + 0xEC + 0x97), subtype, "CCA helper retained subtype")
        require(
            get(recipe_setting),
            recipe_before,
            "mode path retains its job recipe tag 0x98",
        )
        expected = 11 if value == 1 else 5
        require([row[0] for row in traces], list(SETUP_STUBS), "mode setup boundary")
        require(traces[0][1], BASE + DIAGNOSTICS[expected][0], "selected diagnostic")
        require(traces[2][2], 9 if value == 1 else 8, "branch-specific setup code")
        require(get(job + 0x2084), expected, "original virtual prepare mode")
        require(
            [get(job + i) for i in (0x2080, 0x2081, 0x2082)],
            [1, 0, int(value == 1)],
            "original prepare flags",
        )
        return expected

    primary = [profile + 0x14 + BANK_OFFSET + BANK_STRIDE * i for i in range(2)]
    shadow = [mirror + BANK_OFFSET + BANK_STRIDE * i for i in range(2)]
    cases = []
    for bank, event, initial, commit in (
        (1, ON, 0, 0),
        (1, ON, 0, 1),
        (1, ON, 0, 6),
        (1, ON, 0, 0x10),
        (1, ON, 0, 0x11),
        (1, ON, 0, 0x1D),
        (0, OFF, 1, 6),
        (1, ON, 0, 3),
        (1, ON, 0, 0xF),
        (1, CHOICE_WIDGET, 0, 6),
    ):
        put(profile + 0x23C8, bank, 1)
        before = [0xA5, 0xA5]
        before[bank] = initial
        for addr, value in zip(primary + shadow, before * 2):
            put(addr, value, 1)
        put(ui + 0xE7, 0xA5, 1)
        run(0x3C5FF8, 0x3C600C, r4=ui)
        require(get(ui + 0xE7), initial, "original initialization reads selected bank")
        put(widget + 0x25, 0, 1)
        run(0x6D5ED0, r0=ui, r1=event)
        selected = 1 if event == ON else 0 if event == OFF else initial
        require(get(ui + 0xE7), selected, "original screen choice")
        require(
            get(label + 0x90, 4),
            BASE + (0xE39924 if selected else 0xE39978),
            "selected locale",
        )
        require(
            run(0x6D5EC4, r0=ui, r1=0x01306001),
            ON if selected else OFF,
            "reverse selection",
        )
        require(
            [get(addr) for addr in primary + shadow],
            before * 2,
            "selection leaves profile alone",
        )

        traces.clear()
        run(0x6D5F38, r0=ui, r1=commit, r2=0)
        committed = selected if commit in COMMIT_EVENTS else initial
        require(
            traces,
            (
                [(offset, GLOBAL, 0) for offset in ON_SIDE_EFFECT_STUBS]
                if committed == 1 and commit in COMMIT_EVENTS
                else []
            ),
            "On side-effect calls",
        )
        after = before.copy()
        after[bank] = committed
        require(
            [get(addr) for addr in primary + shadow],
            after * 2,
            "both selected profile copies",
        )
        require(run(0x6F4D98, r0=GLOBAL), committed, "original active profile read")
        cases.append(
            {
                "active_index": bank,
                "bank": bank,
                "initial": initial,
                "event": event,
                "selected": selected,
                "commit_event": commit,
                "stored": committed,
                "job_mode": run_mode(committed),
            }
        )

    # Both storage copies differ deliberately for the read. The active primary value decides.
    put(primary[1], 2, 1)
    put(shadow[1], 1, 1)
    require(run(0x6F4D98, r0=GLOBAL), 2, "read returns primary byte as stored")
    malformed_mode = run_mode(2, subtype=1)

    put(importer + 0xC, recipe)
    put(importer + 0x10, auxiliary)
    put(record + 4, 0x243, 2)
    put(record + 0x10, payload)
    raw_cases = []
    for profile_value in (0, 1):
        put(primary[1], profile_value, 1)
        put(shadow[1], profile_value, 1)
        for first_byte in (0, 1, 2):
            encoded = bytes([first_byte]) + bytes(range(1, 0x8C))
            vm.mem_write(payload, encoded)
            put(recipe_setting, 0xA5, 1)
            require(
                run(0x74C6E0, r0=importer, r1=record, r2=4),
                1,
                "MakerNote dispatcher status",
            )
            require(
                bytes(vm.mem_read(auxiliary + 0x7B32, 0x8C)),
                encoded,
                "MakerNote payload copy",
            )
            require(get(recipe_setting), int(first_byte == 1), "imported recipe tag")
            require(
                [get(primary[1]), get(shadow[1])],
                [profile_value] * 2,
                "RAW import leaves both active profile copies unchanged",
            )
            raw_cases.append(
                {
                    "payload_first_byte": first_byte,
                    "recipe_tag": int(first_byte == 1),
                    "profile_setting": profile_value,
                    "job_mode": run_mode(profile_value),
                }
            )

    return {
        "unicorn_version": unicorn.__version__,
        "menu_cases": cases,
        "other_value": {
            "primary": 2,
            "mirror": 1,
            "subtype": 1,
            "job_mode": malformed_mode,
        },
        "raw_import_cases": raw_cases,
        "boundaries": {
            "ui": "Fixture notifier slots 0x18/0x08 and widget activation slot 0x0c return immediately. Fixture manager slot 0x08 verifies the widget ID and returns the RAM widget.",
            "profile": "Initialized singleton and profile RAM. On-only sibling setting helpers are stubbed.",
            "on_only_helpers_stubbed": list(ON_SIDE_EFFECT_STUBS),
            "job": "Starts at CCA dispatcher 0x7b5954 with prepared controller, job pool and command keys 2/1. Stops at prepare prefix end 0x655344.",
            "job_setup_helpers_stubbed": list(SETUP_STUBS),
            "raw": "Prepared MakerNote record passed to the original importer. The imported recipe belongs to the same job later used for the profile branch. RAW file parsing and capture are outside the fixture.",
            "hardware": "Physical input, actual capture, pixels and persistent writes are outside the fixture.",
        },
    }


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
        require(
            result,
            json.loads(args.compare.read_text(encoding="utf-8")),
            "Pixel Shift evidence",
        )
        print(f"Pixel Shift evidence matches {args.compare}")
    elif args.output:
        args.output.write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
