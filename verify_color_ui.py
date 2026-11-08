"""Verify the K-3 II C3 Color Space menu with bounded original ARM execution.

SPDX-License-Identifier: GPL-2.0-only
"""

import argparse
import json
from pathlib import Path
from struct import pack, unpack, unpack_from

from verify_findings import DECODED_SHA256, literal_offset, require, sha256, u32
from verify_tone_path import BASE, check_edge, check_words, load_image
from verify_ui_resources import RENDERER_VTABLE, glyph_record

TABLE, DETAIL_VTABLE, PARENT_VTABLE = 0x9A2BE4, 0xA61868, 0xA5E1D4
GROUP, GROUP_ROW, DETAIL_ID = 13, 0x9B5EF4, 0xB4
PARENT_WIDGET = 0x0140B043
ROOT = 0x01913000
CHOICES = (ROOT + 0xA, ROOT + 0xE)
CAPTIONS = (ROOT + 0xC, ROOT + 0x10)
HELP = (ROOT + 0x12, ROOT + 0x13)
SETTING, STRIDE = 0x15C, 1048
BANKS = (0, 0, 2, 3, 4, 5, 6, 7)
BANK_ROW = 0xA52680 + SETTING * 16
BANK_BYTE = 0x588 + SETTING
WRAPPER_VTABLE = {2: 0xA773F8, 3: 0xA5C948, 4: 0xA5B540}
CONSTRUCTOR_STOP = {2: (0x70A118, 8), 3: (0x708FCC, 0x18), 4: (0x70A0B4, 0x18)}
RESOURCES = (
    ("Color Space", ROOT + 9, 3, 0xE482C4, 0x437D04),
    ("sRGB choice", CHOICES[0], 2, 0x34B, 0x437D1C),
    ("sRGB", CAPTIONS[0], 4, 0xE4836C, 0x437D4C),
    ("AdobeRGB choice", CHOICES[1], 2, 0x34F, 0x437D7C),
    ("AdobeRGB", CAPTIONS[1], 4, 0xE483C0, 0x437DAC),
    ("Sets color space to sRGB", HELP[0], 3, 0xE48414, 0x437DDC),
    ("Sets color space to AdobeRGB", HELP[1], 3, 0xE48468, 0x437DF4),
)
CALLS = (
    (0x4A5B48, 0x6DA5AC),
    (0x4A5C28, 0x6D5FF0),
    (0x6D9E84, 0x4377A0),
    (0x4377A4, 0x6D5A38),
    (0x437C20, 0x70916C),
    (0x437994, 0x6F1A50),
    (0x4380EC, 0x6F1A50),
    (0x438198, 0x4B15BC),
    (0x438240, 0x708774),
    (0x438374, 0x4382F4),
    (0x43839C, 0x4382F4),
    (0x4383C8, 0x4382F4),
    (0x438424, 0x4382F4),
    (0x438460, 0x4382F4),
    (0x438418, 0x6D5FF0),
    (0x707A60, 0x70ACB8),
    (0x709058, 0x873B08),
    (0x873A54, 0x873964),
)
TAILS = (
    (0x4A5950, 0x4A5B50),
    (0x6D9220, 0x6D9E7C),
    (0x43824C, 0x43810C),
    (0x43830C, 0x6F1A38),
)
WORDS = {
    0x4A5B40: 0xE3A02006,
    0x6D8F48: 0x308FF105,
    0x6D9E88: 0xE58402D0,
    0x4377AC: 0xE5801000,
    0x437990: 0xE3A01F57,
    0x437998: 0xE5C400E7,
    0x4380E8: 0xE3A01F57,
    0x4381BC: 0xE5C400E7,
    0x4381E8: 0xE5C400E7,
    0x438300: 0xE5D420E7,
    0x438304: 0xE3A01F57,
    0x438364: 0x0A000022,
    0x6D5EC8: 0xE59220BC,
    0x6D5ED4: 0xE59220C0,
    0x6D5EE0: 0xE59220C4,
    0x6D5F7C: 0xE59030D4,
    0x70ACD4: 0xE5C4500E,
    0x70AA78: 0xE5C0100C,
    0x8C1B00: 0xE5C01051,
    0x84EA10: 0xE1C016B0,
}
RANGES = (
    (0x4A5888, 0x4A5C30),
    (0x6D9E7C, 0x6D9E90),
    (0x4377A0, 0x4377C0),
    (0x43795C, 0x43799C),
    (0x437C14, 0x437E00),
    (0x4380DC, 0x43831C),
    (0x438310, 0x438480),
    (0x70ACB8, 0x70AD10),
    (0x8C1B00, 0x8C1B20),
    (0x873964, 0x873A58),
)


def record_offset(widget):
    return TABLE + (widget - ROOT) * 20


def verify_static(data):
    check_words(data, WORDS)
    for site, dest in CALLS:
        check_edge(data, site, dest)
    for site, dest in TAILS:
        check_edge(data, site, dest, link=False)
    for site, value in (
        (0x4377A8, BASE + DETAIL_VTABLE),
        (0x437C18, BASE + TABLE),
        (0x4A58C4, PARENT_WIDGET - 0xE),
    ):
        require(u32(data, literal_offset(data, site)), value, "original literal")
    for table, slot, target in (
        (PARENT_VTABLE, 0xD4, 0x4A5888),
        (DETAIL_VTABLE, 0x98, 0x43795C),
        (DETAIL_VTABLE, 0xBC, 0x4380DC),
        (DETAIL_VTABLE, 0xC0, 0x43816C),
        (DETAIL_VTABLE, 0xC4, 0x438250),
        (DETAIL_VTABLE, 0xD4, 0x438310),
        (WRAPPER_VTABLE[2], 0x48, 0x707A54),
        (WRAPPER_VTABLE[3], 0xC, 0x70AA6C),
        (WRAPPER_VTABLE[4], 0x48, 0x707A54),
        (RENDERER_VTABLE, 0xC, 0x873A1C),
    ):
        require(u32(data, table + slot), BASE + target, "original vtable")
    require(u32(data, 0x9B48DC), PARENT_WIDGET, "parent row widget")
    require(
        tuple(data[GROUP_ROW : GROUP_ROW + 8]),
        (0x43, 0xB0, 0xB1, 0xB2, 0xB3, 0xAF, 0xB4, 0xB5),
        "C3 routing row",
    )
    require(unpack_from("<8H", data, BANK_ROW), BANKS, "setting bank mapping")
    result = []
    for name, widget, kind, resource, setup in RESOURCES:
        record = record_offset(widget)
        source = resource if kind == 2 else BASE + resource
        require(
            unpack_from("<5I", data, record),
            (widget, kind, source, 3, 0),
            "resource record",
        )
        require(u32(data, literal_offset(data, setup)), widget, "screen setup widget")
        check_edge(data, setup + 8, 0x70A1B8)
        evidence = {
            "label": name,
            "widget": widget,
            "record": record,
            "type": kind,
            "setup": setup,
        }
        if kind == 2:
            evidence["sprite_resource_id"] = resource
        else:
            glyph, width, payload = glyph_record(data, resource, 0)
            require(width, 1, "English byte glyphs")
            require(
                "".join(chr(code + 0x1E) for code in payload[:-1]), name, "English text"
            )
            evidence.update(
                locale_row=resource, english_source=glyph, glyph_sha256=sha256(payload)
            )
        result.append(evidence)
    return result


def emulate(data):
    import unicorn as uc
    from unicorn import arm_const as arm

    vm = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    vm.mem_map(0x40400000, 0x100000)
    vm.mem_map(0x10000000, 0x100000)
    stack, ret = 0x100F0000, 0x100F1000

    def read(address, fmt="I"):
        size = {"B": 1, "H": 2, "I": 4}[fmt]
        return unpack("<" + fmt, vm.mem_read(address, size))[0]

    def write(address, value, fmt="I"):
        vm.mem_write(address, pack("<" + fmt, value))

    def reg(name, value=None):
        register = getattr(arm, "UC_ARM_REG_" + name.upper())
        if value is None:
            return vm.reg_read(register)
        vm.reg_write(register, value)

    def run(entry, *args, end=None, **registers):
        stop = ret if end is None else BASE + end
        for name, value in dict(sp=stack, lr=ret, **registers).items():
            reg(name, value)
        for i, value in enumerate(args):
            reg(f"r{i}", value)
        vm.emu_start(BASE + entry, stop, count=200_000)
        require(reg("pc"), stop, f"A32 stop from {entry:#x}")
        return reg("r0")

    def hook(address, callback):
        vm.hook_add(uc.UC_HOOK_CODE, callback, begin=address, end=address)

    allocated = 0x10010000
    glyph_allocation_sizes = []

    def allocation(_vm, address, _size, _user):
        nonlocal allocated
        size = reg("r0")
        require(
            0 < size <= 0x1000 and allocated + size <= 0x10020000, True, "fixture heap"
        )
        if reg("lr") == BASE + 0x8739E0:
            require(address, BASE + 0x712860, "glyph allocation entry")
            glyph_allocation_sizes.append(size)
        reg("r0", allocated)
        allocated += (size + 15) & ~15
        reg("pc", reg("lr"))

    for offset in (0x712828, 0x712860):
        hook(BASE + offset, allocation)
    reg("fpexc", 0x40000000)
    for flag in (0x4040B120, 0x4041DE9C, 0x40409514):
        write(flag, 1)
    manager = 0x4047CC04
    run(0x832184, manager, 0)
    run(0x437C14, end=0x437C24)

    leaves, rendered = {}, []
    for name, widget, kind, resource, setup in RESOURCES:
        stop, stack_row = CONSTRUCTOR_STOP[kind]
        write(stack + 0x10, manager)
        run(setup, 0, 0, 0, 0, end=stop)
        record = record_offset(widget)
        require(
            bytes(vm.mem_read(reg("sp") + stack_row, 20)),
            data[record : record + 20],
            "original widget record lookup",
        )
        leaf = reg("r1")
        leaves[widget] = leaf
        if kind == 2:
            require(
                read(leaf + 0x60, "H"),
                resource,
                "sprite resource passed to original leaf",
            )
            continue
        require(read(leaf), BASE + RENDERER_VTABLE, "original text leaf")
        require(read(leaf + 0x84, "H"), 4, "text style")
        require(read(leaf + 0x90), BASE + resource, "locale pointer")
        run(0x873A1C, 0, leaf, end=0x873A58)
        descriptor = reg("sp") + 0xC
        units = read(descriptor + 4, "H")
        _, width, source = glyph_record(data, resource, 0)
        require(width, 1, "fixture uses English byte glyphs")
        expected = pack(f"<{len(source)}H", *source)
        require(units * 2, len(expected), "text length including terminator")
        require(glyph_allocation_sizes[-1], len(expected), "text allocation size")
        output = bytes(vm.mem_read(read(descriptor), units * 2))
        require(output, expected, "original prepared glyphs")
        rendered.append(
            {
                "label": name,
                "widget": widget,
                "units_including_terminator": units,
                "prepared_sha256": sha256(output),
            }
        )

    core, profile, mirror, callbacks, lookups, notifier, parent, panel = (
        0x10030000 + 0x4000 * i for i in range(8)
    )
    widgets = {ROOT: 0x10060000, ROOT + 1: 0x10060400}
    write(widgets[ROOT + 1], BASE + WRAPPER_VTABLE[3])
    for i, (_, widget, kind, _, _) in enumerate(RESOURCES):
        obj = 0x10061000 + 0x400 * i
        widgets[widget] = obj
        write(obj, BASE + WRAPPER_VTABLE[kind])
        write(obj + 4, leaves[widget])
        write(obj + 8, widget)
    for obj, slot, target in (
        (lookups, 8, callbacks + 4),
        (notifier, 0x18, callbacks),
        (notifier, 8, callbacks + 8),
    ):
        write(obj, obj + 0x100)
        write(obj + 0x100 + slot, target)
    write(callbacks, 0xE12FFF1E)
    notifications, root_requests = [], []

    def side_effect(_vm, address, _size, _user):
        if address == callbacks + 4:
            reg("r0", widgets[reg("r1")])
        elif address == callbacks + 8:
            notifications.append([reg("r1"), reg("r3")])
        elif address == BASE + 0x708774:
            require(reg("r0"), widgets[ROOT], "root focus request widget")
            root_requests.append([reg("r1"), reg("r2")])
        reg("pc", reg("lr"))

    for address in (callbacks + 4, callbacks + 8, BASE + 0x708774, BASE + 0x6D5A38):
        hook(address, side_effect)
    write(parent, BASE + PARENT_VTABLE)
    write(parent + 4, panel)
    write(parent + 0xC4, notifier)
    write(parent + 0xD4, PARENT_WIDGET)
    write(panel + 0x26, GROUP, "B")
    run(0x6D5F38, parent, 0x1D, 0)
    require(notifications, [[DETAIL_ID, 0x1D]], "parent menu routes to detail screen")

    registry = 0x10000000
    run(0x6D8F3C, end=0x6DA178, r4=registry, r5=DETAIL_ID)
    screen = read(registry + 4 * DETAIL_ID)
    require(read(screen), BASE + DETAIL_VTABLE, "actual registry created detail screen")
    require(read(screen + 0xE7, "B"), 0, "screen constructor clears pending value")
    for address, value in (
        (screen + 0xB4, core),
        (core + 0xC, profile),
        (profile + 0xC, mirror),
        (screen + 0x24, lookups),
        (screen + 0xC4, notifier),
        (screen + 4, panel),
    ):
        write(address, value)
    require(
        tuple(run(0x4B14C4, 0, SETTING, i) for i in range(8)),
        BANKS,
        "active index lookup",
    )
    memory_writes = []

    def written(_vm, _access, address, size, value, _user):
        memory_writes.append((address, size, value))

    vm.hook_add(uc.UC_HOOK_MEM_WRITE, written, begin=profile, end=profile + 0x23FF)
    vm.hook_add(uc.UC_HOOK_MEM_WRITE, written, begin=mirror, end=mirror + 0x23FF)
    cases = (
        ("sRGB to AdobeRGB", 1, 0, 1, 6, True, 0xC2),
        ("AdobeRGB to sRGB", 2, 1, 0, 6, True, 0xC2),
        ("cancel AdobeRGB", 1, 0, 1, 3, False, 0xC1),
        ("cancel sRGB", 2, 1, 0, 3, False, 0xC1),
        ("reconfirm sRGB", 0, 0, 0, 6, True, 0xC2),
        ("reconfirm AdobeRGB", 2, 1, 1, 6, True, 0xC2),
        ("confirm without choice event", 1, 1, None, 6, True, 0xC2),
        ("confirm route 0x11", 2, 0, 1, 0x11, True, 0xC1),
    )
    results = []
    for name, index, initial, chosen, action, commit, notice in cases:
        bank = BANKS[index]
        addresses = [
            profile + 0x14 + BANK_BYTE + STRIDE * bank,
            mirror + BANK_BYTE + STRIDE * bank,
        ]
        write(profile + 0x23C8, index, "B")
        for slot in range(8):
            for base in (profile + 0x14, mirror):
                write(
                    base + BANK_BYTE + STRIDE * slot,
                    initial if slot == bank else 0xA5,
                    "B",
                )
        for widget in (*CHOICES, *CAPTIONS, *HELP, ROOT + 1):
            write(widgets[widget] + 0xC, 0, "B")
            write(widgets[widget] + 0xE, 0, "B")
            if widget in leaves:
                write(leaves[widget] + 0x51, 0, "B")
        write(widgets[ROOT + 1] + 0xC, 1, "B")
        write(screen + 0xE7, 0xA5, "B")
        memory_writes.clear()
        notifications.clear()
        root_requests.clear()
        run(0x43795C, screen, end=0x43799C)
        require(read(screen + 0xE6, "B"), 1, "enabled focus fixture")
        require(read(screen + 0xE7, "B"), initial, "open reloads saved value")
        require(run(0x6D5EC4, screen, 0), CHOICES[initial], "saved selection on open")
        focus = None
        if chosen is not None:
            selected = CHOICES[chosen]
            run(0x6D5ED0, screen, selected)
            require(read(screen + 0xD4), selected, "last logical widget")
            require(read(screen + 0xE7, "B"), chosen, "selected pending value")
            require(
                run(0x6D5EC4, screen, 0),
                CHOICES[initial],
                "reverse still reads saved value",
            )
            selected_pair = (selected, CAPTIONS[chosen])
            for widget in selected_pair:
                require(read(widgets[widget] + 0xE, "B"), 1, "selected wrapper state")
                require(read(leaves[widget] + 0x51, "B"), 1, "selected leaf state")
                require(
                    [read(leaves[widget] + k, "H") for k in (0x54, 0x56)],
                    [100, 150],
                    "selected leaf parameter pair",
                )
            require(
                [read(widgets[k] + 0xC, "B") for k in (ROOT + 1, HELP[chosen])],
                [0, 1],
                "selection switches generic and option help flags",
            )
            run(0x6D5EDC, screen, selected)
            require(
                read(screen + 0xE7, "B"), chosen, "depart does not clear pending choice"
            )
            for widget in selected_pair:
                require(
                    read(widgets[widget] + 0xE, "B"), 0, "depart clears wrapper state"
                )
                require(read(leaves[widget] + 0x51, "B"), 0, "depart clears leaf state")
                require(
                    [read(leaves[widget] + k, "H") for k in (0x54, 0x56)],
                    [100, 100],
                    "depart resets leaf parameter pair",
                )
            require(root_requests, [[1, selected], [0, 0]], "root focus requests")
            focus = {
                "choice": selected,
                "caption": CAPTIONS[chosen],
                "help": HELP[chosen],
                "selected_pair": [100, 150],
                "departed_pair": [100, 100],
            }
        require(memory_writes, [], "open and selection perform no profile writes")
        pending = initial if chosen is None else chosen
        run(0x6D5F38, screen, action, 0)
        require(notifications, [[notice, action]], "screen navigation notification")
        final = pending if commit else initial
        require(
            memory_writes,
            [(address, 1, final) for address in addresses] if commit else [],
            "exact live and mirror byte stores",
        )
        require(
            read(screen + 0xE7, "B"),
            pending,
            "apply or cancel leaves pending byte in place",
        )
        require(
            [read(address, "B") for address in addresses], [final, final], "saved bytes"
        )
        require(
            run(0x6D5EC4, screen, 0),
            CHOICES[final],
            "reverse lookup follows saved value",
        )
        write(screen + 0xE7, 0xA5, "B")
        run(0x43795C, screen, end=0x43799C)
        require(read(screen + 0xE7, "B"), final, "reopen reloads saved value")
        require(
            memory_writes,
            [(address, 1, final) for address in addresses] if commit else [],
            "reopen performs no profile stores",
        )
        results.append(
            {
                "case": name,
                "active_index": index,
                "storage_bank": bank,
                "initial": initial,
                "chosen": chosen,
                "action": action,
                "notify": notice,
                "saved": final,
                "pending_after_action": pending,
                "pending_after_reopen": final,
                "live_byte_writes": int(commit),
                "mirror_byte_writes": int(commit),
                "focus": focus,
            }
        )
    return {
        "unicorn_version": uc.__version__,
        "text_cases": rendered,
        "lifecycle_cases": results,
        "parent_route": {
            "logical_action": 0x1D,
            "widget": PARENT_WIDGET,
            "notified_detail_id": DETAIL_ID,
            "registry_slot": 4 * DETAIL_ID,
        },
    }


def analyze(data):
    return {
        "decoded_sha256": DECODED_SHA256,
        "candidate_load_base": BASE,
        "location_units": "Decoded file offsets unless an object offset, widget ID or address.",
        "screen": {
            "parent_vtable": PARENT_VTABLE,
            "detail_vtable": DETAIL_VTABLE,
            "detail_id": DETAIL_ID,
            "category_index": GROUP,
            "category_row": GROUP_ROW,
            "category_row_index": 6,
            "widget_table": TABLE,
            "open": 0x43795C,
            "reverse": 0x4380DC,
            "choose": 0x43816C,
            "depart": 0x438250,
            "action": 0x438310,
            "apply": 0x4382F4,
            "pending_byte": 0xE7,
            "last_logical_widget": 0xD4,
        },
        "configuration": {
            "id": SETTING,
            "bank_lookup_row": BANK_ROW,
            "banks": list(BANKS),
            "bank_stride": STRIDE,
            "setting_offset_within_bank": BANK_BYTE,
            "active_index_offset": 0x23C8,
            "live_bank_base_offset": 0x14,
            "mirror_pointer_offset": 0xC,
            "value_by_choice": {"sRGB": 0, "AdobeRGB": 1},
        },
        "focus": {
            "choice_widgets": list(CHOICES),
            "caption_widgets": list(CAPTIONS),
            "help_widgets": list(HELP),
            "choice_and_caption_slot": 0x48,
            "choice_and_caption_method": 0x707A54,
            "wrapper_state_offset": 0xE,
            "leaf_state_offset": 0x51,
            "leaf_parameter_u16_offsets": [0x54, 0x56],
            "help_visibility_slot": 0xC,
            "help_visibility_field": 0xC,
        },
        "resources": verify_static(data),
        "original_a32": emulate(data),
        "range_hashes": {f"{a:#x}..{b:#x}": sha256(data[a:b]) for a, b in RANGES},
        "limits": [
            "Parent notification and detail registry dispatch are separate original segments. "
            "The notification consumer and parent input mapping were outside the replay.",
            "Original resource lookup runs to leaf construction. Fixture wrappers use original "
            "vtables and the constructed leaves. Text preparation stops before rendering. "
            "Help checks show the selected help widget being enabled, without assuming exclusive visibility.",
            "Allocator stubs are 0x712828 and 0x712860. Base screen construction 0x6d5a38 and "
            "root focus-list service 0x708774 are boundary stubs. Widget lookup, notifier and "
            "initialized singleton flags use fixtures.",
            "Open and reopen run through the original setting read at 0x437998. Logical UI "
            "actions use original dispatchers. The fixtures observe writes to RAM live and mirror "
            "bank bytes. They do not establish physical controls, LCD output, persistent writes "
            "or behavior of another model.",
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
            "Color Space snapshot",
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
