"""Verify the K-3 II RAW File Format resource, text ABI and setting events.

SPDX-License-Identifier: GPL-2.0-only
"""

import argparse
import json
from pathlib import Path
from struct import pack, unpack, unpack_from

from verify_findings import DECODED_SHA256, literal_offset, require, sha256, u32
from verify_tone_path import BASE, check_edge, check_words, load_image

TABLE, VTABLE, RENDERER_VTABLE = 0x993334, 0xA629E4, 0xA5D1AC
ITEM, PEF, DNG = 0x0150000A, 0x01500043, 0x01500044
LOCALE_KIND = 0xDDDB88
SETTING, STRIDE = 0x97, 1048
BANK_ROW = 0xA52680 + SETTING * 16
BANKS = (0, 0, 2, 3, 4, 5, 6, 7)
COMMIT = (0, 1, 6, 0x10, 0x11, 0x1D, 0x20)
RESOURCES = (
    ("RAW File Format", 0x01500040, 0x993834, 0xE3FE34, 0xE4C7C5, 0x3E4320),
    ("PEF", PEF, 0x993870, 0xE3FE88, 0xE4C7D5, 0x3E4368),
    ("DNG", DNG, 0x993884, 0xE3FEDC, 0xE4C7D9, 0x3E4380),
)
DISPATCHES = (
    (0x6D5EC4, 0xBC, 0x3E54A8),
    (0x6D5ED0, 0xC0, 0x3E5E84),
    (0x6D5EDC, 0xC4, 0x3E6030),
    (0x6D5F00, 0xD0, 0x3E6344),
)
CALLS = {
    0x3E2C40: 0x6D5A38,
    0x3E3C3C: 0x70916C,
    0x3E4638: 0x82DE2C,
    0x3E5504: 0x3E53A4,
    0x3E601C: 0x3E5598,
    0x3E637C: 0x3E6148,
    0x3E35F4: 0x6DA5E4,
    0x3E35FC: 0x6F1A50,
    0x3E6194: 0x6DA5E4,
    0x700ED4: 0x4B14C4,
    0x700EEC: 0x6FE52C,
    0x701F28: 0x4B14C4,
    0x70A2A0: 0x712898,
    0x70A3A0: 0x70A0E8,
    0x70A0F4: 0x709000,
    0x70A10C: 0x82DE20,
    0x709058: 0x873B08,
    0x873A54: 0x873964,
    0x8739C4: 0x8C4924,
    0x8739CC: 0x8C4974,
    0x8739FC: 0x8C48D4,
    0x873A10: 0x8C48FC,
}
TAILS = {
    0x3E61A4: 0x6F1A38,
    0x3E611C: 0x3E5598,
    0x6F1A40: 0x700E84,
    0x6F1A58: 0x701EF4,
    0x700F04: 0x6FE52C,
    0x701F3C: 0x6FE5BC,
    0x70A2C4: 0x70A390,
}
WORDS = {
    0x3E2C48: 0xE5801000,
    0x3E3600: 0xE5C400F4,
    0x3E361C: 0xE5C400F9,
    0x3E5678: 0x15C4A0F9,
    0x3E5754: 0x15C400F9,
    0x3E6170: 0xE5C400F9,
    0x3E618C: 0xE5C400F4,
    0x3E619C: 0xE3A01097,
    0x3E53AC: 0x051F01C8,
    0x3E53B8: 0x051F01D0,
    0x3E6010: 0xE3A02001,
    0x3E610C: 0xE3A02000,
    0x6FE544: 0xE7C02001,
    0x6FE5CC: 0xE5D00588,
    0x82DE24: 0x1580105C,
    0x82DE30: 0x15801060,
    0x82DE68: 0x15941060,
    0x82DE6C: 0x0594105C,
    0x873B08: 0xE1C028B4,
    0x873B0C: 0xE5801090,
    0x8739B0: 0xE7951106,
    0x8739B4: 0xE7D07006,
}
RANGES = (
    (0x3E2C3C, 0x3E2C88),
    (0x3E35F0, 0x3E3620),
    (0x3E53A4, 0x3E53C0),
    (0x3E54A8, 0x3E57B0),
    (0x3E5E84, 0x3E61A8),
    (0x3E6344, 0x3E639C),
    (0x70A1B8, 0x70A3A8),
    (0x82DE20, 0x82DE7C),
    (0x873964, 0x873A58),
    (0x8C48D4, 0x8C49C0),
)
REFRESH_STUBS = (0x3E31E8, 0x3E3370, 0x51F4A8, 0x3E2C9C, 0x708774)


def glyph_record(data, row, locale):
    glyph = u32(data, row + 4 * locale) - BASE
    require(0 <= glyph <= len(data) - 128, True, "glyph source bounds")
    width = 1 if data[LOCALE_KIND + locale] else 2
    for size in range(width, 129, width):
        if not any(data[glyph + size - width : glyph + size]):
            payload = data[glyph : glyph + size]
            return glyph, width, payload
    raise ValueError(f"unterminated glyph resource at {glyph:#x}")


def verify_static(data):
    check_words(data, WORDS)
    for site, target in CALLS.items():
        check_edge(data, site, target)
    for site, target in TAILS.items():
        check_edge(data, site, target, link=False)
    for entry, slot, target in DISPATCHES:
        require(u32(data, VTABLE + slot), BASE + target, "screen vtable target")
        register = 3 if slot == 0xD0 else 2
        require(
            u32(data, entry + 4),
            0xE5900000 | register << 16 | register << 12 | slot,
            "screen virtual dispatch slot",
        )
    for site, expected in (
        (0x3E2C44, BASE + VTABLE),
        (0x3E3C34, BASE + TABLE),
        (0x3E4630, BASE + 0xE3FE34),
        (0x8739AC, BASE + LOCALE_KIND),
    ):
        require(u32(data, literal_offset(data, site)), expected, "embedded literal")
    require((u32(data, 0x3E51EC), u32(data, 0x3E51F0)), (PEF, DNG), "reverse literals")
    require(u32(data, RENDERER_VTABLE + 0xC), BASE + 0x873A1C, "renderer vtable target")
    require(unpack_from("<8H", data, BANK_ROW), BANKS, "setting bank map")
    resources = []
    for name, widget, record, row, english, setup in RESOURCES:
        require(
            unpack_from("<5I", data, record),
            (widget, 4, BASE + row, 3, 0),
            "type 4 widget record",
        )
        require((record - TABLE) % 20, 0, "widget record alignment")
        require(u32(data, literal_offset(data, setup)), widget, "screen widget ID")
        check_edge(data, setup + 8, 0x70A1B8)
        offset, width, payload = glyph_record(data, row, 0)
        require((offset, width), (english, 1), "English resource source")
        require(
            "".join(chr(code + 0x1E) for code in payload[:-1]), name, "English label"
        )
        resources.append(
            {
                "label": name,
                "widget_id": widget,
                "record": record,
                "locale_row": row,
                "english_glyphs": offset,
                "setup": setup,
                "english_glyph_sha256": sha256(payload),
            }
        )
    require(
        unpack_from("<5I", data, 0x9938E8),
        (0x01500049, 3, BASE + 0xE3FE34, 3, 0),
        "type 3 record also points to title row",
    )
    return resources


def emulate(data):
    import unicorn as uc
    from unicorn import arm_const as arm

    vm = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    vm.mem_map(0x40400000, 0x100000)
    vm.mem_map(0x10000000, 0x100000)
    stack, stop = 0x100F0000, 0x100F1000

    def reg(name, value=None):
        index = getattr(arm, f"UC_ARM_REG_{name.upper()}")
        if value is None:
            return vm.reg_read(index)
        vm.reg_write(index, value)

    def write(address, value, fmt="I"):
        vm.mem_write(address, pack("<" + fmt, value))

    def read(address, fmt="I"):
        width = {"B": 1, "H": 2, "I": 4}[fmt]
        return unpack("<" + fmt, vm.mem_read(address, width))[0]

    def run(entry, *args, end=None, **registers):
        finish = stop if end is None else BASE + end
        for name, value in dict(sp=stack, lr=stop, **registers).items():
            reg(name, value)
        for i, value in enumerate(args):
            reg(f"r{i}", value)
        vm.emu_start(BASE + entry, finish, count=200_000)
        require(reg("pc"), finish, f"original code boundary at {entry:#x}")
        return reg("r0")

    def hook(address, callback):
        vm.hook_add(uc.UC_HOOK_CODE, callback, begin=address, end=address)

    allocated, glyph_sizes = 0x10010000, []

    def allocate(_vm, address, _size, _user):
        nonlocal allocated
        size = reg("r0")
        require(
            0 < size <= 0x1000 and allocated + size <= 0x10020000, True, "fixture heap"
        )
        if reg("lr") == BASE + 0x8739E0:
            require(address, BASE + 0x712860, "glyph heap entry")
            glyph_sizes.append(size)
        reg("r0", allocated)
        allocated += (size + 15) & ~15
        reg("pc", reg("lr"))

    for offset in (0x712828, 0x712860):
        hook(BASE + offset, allocate)
    reg("fpexc", 0x40000000)
    manager, renderer_global = 0x4047CC04, 0x404A2C3C
    write(0x4040B120, 1)
    write(0x4041DE9C, 1)
    require(run(0x832184, manager, 0), manager, "resource manager object")
    write(stack + 0x160, manager)
    run(0x3E3C34, end=0x3E3C40, r0=manager)

    text_cases, labels = [], []
    for name, widget, record, row, _, setup in RESOURCES:
        run(setup, 0, 0, 0, 0, end=0x70A0B4)
        copied = vm.mem_read(reg("sp") + 0x18, 20)
        require(
            bytes(copied),
            data[record : record + 20],
            "original resource lookup and copy",
        )
        label = reg("r1")
        labels.append(label)
        require(read(label), BASE + RENDERER_VTABLE, "original renderer constructed")
        require(read(label + 0x84, "H"), 4, "original text style")
        require(read(label + 0x90), BASE + row, "original locale row binding")
        for active, forced in ((0, 0), (9, 0), (10, 0), (10, 1)):
            write(renderer_global + 8, active, "B")
            write(label + 0xAC, forced, "B")
            locale = 0 if forced else active
            glyph, width, payload = glyph_record(data, row, locale)
            expected = pack(f"<{len(payload)}H", *payload) if width == 1 else payload
            run(0x873A1C, 0, label, end=0x873A58)
            text = reg("sp") + 0xC
            size = read(text + 4, "H")
            require(size * 2, len(expected), "renderer units include terminator")
            require(
                glyph_sizes[-1], size * 2, "renderer requested exact glyph allocation"
            )
            output = bytes(vm.mem_read(read(text), size * 2))
            require(output, expected, "original glyph preparation")
            text_cases.append(
                {
                    "label": name,
                    "active_locale_index": active,
                    "force_index_zero": bool(forced),
                    "used_locale_index": locale,
                    "source": glyph,
                    "source_unit_bytes": width,
                    "output_units_including_terminator": size,
                    "output_sha256": sha256(output),
                }
            )

    # Independently replay the text wrapper's two source fields and null setter guard.
    wrapper = 0x10022000
    write(wrapper + 4, labels[0])
    write(wrapper + 0x64, 7, "H")
    run(0x82DE20, wrapper, BASE + RESOURCES[1][3])
    run(0x82DE2C, wrapper, BASE + RESOURCES[2][3])
    run(0x82DE2C, wrapper, 0)
    for state, row in ((0, RESOURCES[1][3]), (1, RESOURCES[2][3])):
        run(0x82DE38, wrapper, state, 0, 0, end=0x82DE7C)
        require(read(labels[0] + 0x90), BASE + row, "wrapper text source by state")
        require(read(labels[0] + 0x84, "H"), 7, "wrapper passes style halfword")
    write(stack + 0x5C, wrapper)
    run(0x3E4630, end=0x3E463C)
    require(
        read(wrapper + 0x60), BASE + RESOURCES[0][3], "screen title's second source"
    )

    screen, core, cfg, mirror, callbacks, lookups, widget, notifier = (
        0x10030000 + 0x4000 * i for i in range(8)
    )
    vm.mem_write(screen, b"\xA5" * 0x100)
    run(0x3E2C44, screen, end=0x3E2C84)
    require(read(screen), BASE + VTABLE, "screen constructor vtable")
    require(
        [read(screen + i, "B") for i in (0xF4, 0xF9)], [0, 0], "screen initial bytes"
    )
    for address, value in (
        (screen + 0xB4, core),
        (core + 0xC, cfg),
        (cfg + 0xC, mirror),
        (screen + 0x24, lookups),
        (screen + 0xC4, notifier),
    ):
        write(address, value)
    write(callbacks, 0xE12FFF1E)
    for obj, slot, method in (
        (lookups, 8, callbacks + 4),
        (widget, 0x48, callbacks),
        (notifier, 0x18, callbacks),
    ):
        write(obj, obj + 0x100)
        write(obj + 0x100 + slot, method)

    def side_effect(_vm, address, _size, _user):
        if address == callbacks + 4:
            require(
                reg("r1") in (ITEM, PEF, DNG, 0x01500040, 0x01500007),
                True,
                "fixture widget lookup",
            )
            reg("r0", widget)
        reg("pc", reg("lr"))

    hook(callbacks + 4, side_effect)
    for offset in REFRESH_STUBS:
        hook(BASE + offset, side_effect)
    stores = []

    def record_store(_vm, _address, _size, _user):
        stores.append(tuple(reg(f"r{i}") for i in range(4)))

    hook(BASE + 0x6FE52C, record_store)
    require(
        tuple(run(0x4B14C4, 0, SETTING, index) for index in range(8)),
        BANKS,
        "original bank lookup",
    )

    def config_bytes():
        offset = 0x588 + SETTING
        return [
            list(read(base + offset + STRIDE * i, "B") for i in range(8))
            for base in (cfg + 0x14, mirror)
        ]

    def check_bank(index, initial):
        values = [0xA5] * 8
        values[BANKS[index]] = initial
        write(cfg + 0x23C8, index, "B")
        for base in (cfg + 0x14, mirror):
            for i, value in enumerate(values):
                write(base + 0x588 + SETTING + STRIDE * i, value, "B")
        run(0x3E35F0, end=0x3E3620, r4=screen)
        require(
            [read(screen + i, "B") for i in (0xF4, 0xF9)],
            [initial, initial],
            "screen initialization",
        )
        return values

    event_cases = []
    cases = [(1, 0, DNG, ITEM, event) for event in COMMIT]
    cases += [
        (0, 1, PEF, ITEM, 6),
        (2, 1, PEF, ITEM, 0x20),
        (2, 1, PEF, ITEM, 3),
        (1, 0, DNG, ITEM, 0xF),
        (1, 0, DNG, ITEM + 1, 6),
    ]
    for index, initial, chosen, apply_item, event in cases:
        expected = check_bank(index, initial)
        stores.clear()
        run(0x6D5ED0, screen, chosen)
        require(read(screen + 0xD4), chosen, "screen records selection widget")
        pending = int(chosen == DNG)
        require(read(screen + 0xF9, "B"), pending, "selection sets pending byte")
        require(
            config_bytes(), [expected, expected], "selection does not write profile"
        )
        departed = PEF if chosen == DNG else DNG
        run(0x6D5EDC, screen, departed)
        require(
            read(screen + 0xF9, "B"),
            pending,
            "leaving opposite widget retains pending byte",
        )
        run(0x6D5F00, screen, apply_item, event)
        committed = apply_item == ITEM and event in COMMIT
        final = pending if committed else initial
        final_pending = final if apply_item == ITEM else pending
        require(
            [read(screen + i, "B") for i in (0xF4, 0xF9)],
            [final, final_pending],
            "apply or restore screen values",
        )
        expected[BANKS[index]] = final
        require(config_bytes(), [expected, expected], "live and mirror bank contents")
        require(
            stores,
            (
                [(base, SETTING, final, BANKS[index]) for base in (cfg + 0x14, mirror)]
                if committed
                else []
            ),
            "setting store calls",
        )
        require(
            run(0x6D5EC4, screen, ITEM),
            DNG if final else PEF,
            "reverse widget selection",
        )
        event_cases.append(
            {
                "active_index": index,
                "storage_bank": BANKS[index],
                "initial": initial,
                "selected_widget": chosen,
                "departed_widget": departed,
                "apply_item": apply_item,
                "apply_event": event,
                "profile_committed": committed,
                "stored_value": final,
                "pending_after": final_pending,
            }
        )
    check_bank(2, 2)
    require(run(0x6D5EC4, screen, ITEM), 0, "invalid value has no matching widget")
    return {
        "unicorn_version": uc.__version__,
        "text_cases": text_cases,
        "event_cases": event_cases,
        "invalid_reverse_value": 2,
        "invalid_reverse_widget": 0,
        "wrapper_state_replays": 2,
        "allocators": [0x712828, 0x712860],
        "ui_refresh_stubs": list(REFRESH_STUBS),
    }


def analyze(data):
    return {
        "decoded_sha256": DECODED_SHA256,
        "candidate_load_base": BASE,
        "location_units": "Decoded file offsets unless an object offset, widget ID or address.",
        "screen": {
            "widget_table": TABLE,
            "vtable": VTABLE,
            "item_id": ITEM,
            "dispatch_entry_vslot_target": [list(row) for row in DISPATCHES],
            "cached_choice_offset": 0xF4,
            "pending_choice_offset": 0xF9,
            "commit_events": list(COMMIT),
            "pef_value": 0,
            "dng_value": 1,
        },
        "configuration": {
            "id": SETTING,
            "bank_table_row": BANK_ROW,
            "banks_by_active_index": list(BANKS),
            "bank_stride": STRIDE,
            "byte_offset_in_bank": 0x588 + SETTING,
            "active_index_offset": 0x23C8,
            "live_bank_base_offset": 0x14,
            "mirror_pointer_offset": 0xC,
        },
        "renderer": {
            "vtable": RENDERER_VTABLE,
            "text_method_vslot": 0xC,
            "text_prepare": 0x873964,
            "style_u16_offset": 0x84,
            "locale_row_pointer_offset": 0x90,
            "force_locale_zero_byte_offset": 0xAC,
            "locale_width_table": LOCALE_KIND,
            "wrapper_locale_sources": [0x5C, 0x60],
            "wrapper_style_u16_offset": 0x64,
            "prepared_descriptor_pointer_offset": 0,
            "prepared_descriptor_count_u16_offset": 4,
        },
        "resources": verify_static(data),
        "original_a32": emulate(data),
        "range_hashes": {
            f"{start:#x}..{end:#x}": sha256(data[start:end]) for start, end in RANGES
        },
        "limits": [
            "Original resource lookup executes through construction of the text object. The "
            "execution stops at widget wrapper allocation. The separate wrapper-state fixtures "
            "supply two locale rows to exercise the setter and source selection.",
            "Glyph payloads are opaque firmware codes. The tested English labels use codes plus "
            "0x1e. Prepared glyph hashes include the terminating u16; no font atlas or bitmap "
            "output was extracted.",
            "Event input, widget lookup and callbacks, refresh boundaries, active index and RAM "
            "banks are fixtures. The original configuration getter, setter and bank mapping execute.",
            "Physical controls, LCD output, persistent save, encoding, and K-3 III internal IDs "
            "are outside these checks.",
        ],
    }


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
            "UI resource snapshot",
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
