"""Check K-3 II masked scaler gate writers and conditional JPEG plane aliases.

SPDX-License-Identifier: GPL-2.0-only
Instruction locations are decoded file offsets.
"""

import argparse
import json
from pathlib import Path
from struct import iter_unpack, pack, unpack

from verify_findings import DECODED_SHA256, literal_offset, require, sha256, u32
from verify_raw_path import branch_target
from verify_tone_path import BASE, check_words, load_image


EDGES = {
    "scaler_producers_and_gate": (
        (0x653B74, 0x71B0B0),
        (0x659EF0, 0x71B020),
        (0x659F18, 0x71B078),
        (0x659F28, 0x71B088),
        (0x659FAC, 0x71B090),
        (0x580A08, 0x580034),
        (0x580074, 0x71B018),
        (0x580080, 0x71B070),
        (0x58008C, 0x71B080),
        (0x5804A4, 0x71C440),
        (0x5804AC, 0x5808A8),
        (0x5804D4, 0x57F904),
        (0x580878, 0x57F904),
    ),
    "layout_and_jpeg": (
        (0x660B00, 0x660D5C),
        (0x660C70, 0x81CFB0),
        (0x660C7C, 0x81CFB8),
        (0x660C88, 0x81CFC0),
        (0x660CF0, 0x81CFB0),
        (0x660CFC, 0x81CFB8),
        (0x660D08, 0x81CFC0),
        (0x660D78, 0x81CFB0),
        (0x660D84, 0x81CFB8),
        (0x660D90, 0x81CFC0),
        (0x660E78, 0x81CFB0),
        (0x660E84, 0x81CFB8),
        (0x660E90, 0x81CFC0),
        (0x660EF8, 0x81CFB0),
        (0x660F08, 0x81CFB8),
        (0x660F14, 0x81CFC0),
        (0x65A098, 0x81CFB0),
        (0x65A0A4, 0x81CFB8),
        (0x65A0B0, 0x81CFC0),
        (0x65A150, 0x81CFB0),
        (0x65A15C, 0x81CFB8),
        (0x65A168, 0x81CFC0),
        (0x65D504, 0x78596C),
        (0x65D510, 0x78597C),
        (0x576D7C, 0x71B680),
        (0x576D88, 0x71B698),
        (0x576FBC, 0x71C558),
        (0x57701C, 0x71C570),
        (0x576FE8, 0x576AC4),
        (0x577044, 0x576AC4),
    ),
    "scaler_notifications": (
        (0x6DBB50, 0x6DBC20),
        (0x6DBB8C, 0x6DBEE0),
        (0x6DBC24, 0x65DC34),
        (0x65DC80, 0x65DD1C),
        (0x65DD2C, 0x70BF20),
        (0x65DD38, 0x70BF28),
        (0x65DD64, 0x70BF20),
        (0x65DD70, 0x70BF28),
    ),
    "module20_field_handoff": (
        (0x659524, 0x65A948),
        (0x65427C, 0x6546D0),
        (0x654280, 0x654724),
        (0x65A964, 0x719EF4),
        (0x65A9BC, 0x71BF10),
        (0x65A9F8, 0x7B2130),
        (0x65AA70, 0x71AD04),
        (0x65AABC, 0x71ACE4),
        (0x65AAC8, 0x71ACDC),
        (0x65AAD4, 0x71ACEC),
        (0x65DCC8, 0x65DD90),
        (0x65964C, 0x659678),
    ),
}

WORDS = {
    0x653B6C: 0xE30A17B4,
    0x653B70: 0xE0800001,
    0x71B0B0: 0xE3A01000,
    0x71B100: 0xE5C01038,
    0x71B090: 0xE5C01038,
    0x659F74: 0xE3A08000,
    0x659FA4: 0xE1A01008,
    0x659FA8: 0xE1A00007,
    0x71B020: 0xE5801018,
    0x71B078: 0xE580101C,
    0x71B088: 0xE5801020,
    0x71B018: 0xE5900018,
    0x71B070: 0xE590001C,
    0x71B080: 0xE5900020,
    0x71C440: 0xE5D00038,
    0x5804CC: 0xE59D101C,
    0x5804D0: 0xE59D2018,
    0x580868: 0xE59D1018,
    0x58086C: 0xE59D2014,
    0x5808A4: 0xE12FFF33,
    0x6609B4: 0xE59010D8,
    0x660AF4: 0xE1D60BB2,
    0x660AF8: 0xE3500001,
    0x660B0C: 0xE5840160,
    0x660B14: 0xE5840164,
    0x660B1C: 0xE5840168,
    0x660B34: 0xE59D000C,
    0x660B3C: 0xE59D0014,
    0x660B44: 0xE59D0018,
    0x660B48: 0xE8810201,
    0x660B50: 0xE5840188,
    0x660B58: 0xE584018C,
    0x660D60: 0xE3020354,
    0x660E60: 0xE302038C,
    0x660E70: 0xE59D100C,
    0x660E7C: 0xE59D1014,
    0x660E88: 0xE59D1018,
    0x660EE0: 0xE30203A8,
    0x660EF0: 0xE1A01009,
    0x660EFC: 0xE0895008,
    0x660F0C: 0xE085100A,
    0x65A090: 0xE5941178,
    0x65A09C: 0xE594117C,
    0x65A0A8: 0xE5941180,
    0x65A148: 0xE5941184,
    0x65A154: 0xE5941188,
    0x65A160: 0xE594118C,
    0x65D4A0: 0xE5D40065,
    0x65D4AC: 0x03A01001,
    0x65D4B0: 0x13A01000,
    0x78596C: 0xE5801008,
    0x78597C: 0xE580100C,
    0x785984: 0xE5C0102A,
    0x785994: 0xE5C0102B,
    0x71B680: 0xE5900008,
    0x71B698: 0xE590000C,
    0x71C558: 0xE5D0002A,
    0x71C570: 0xE5D0002B,
    0x576FDC: 0xE59D1014,
    0x577028: 0xE59D100C,
    0x6DBB4C: 0x03A01002,
    0x65DD20: 0xE3020204,
    0x65DD58: 0xE30201E8,
    0x65A94C: 0xE3100044,
    0x65A9EC: 0xE3100040,
    0x71BF10: 0xE5900204,
    0x7B2130: 0xE590013C,
    0x65AAB4: 0xE59411FC,
    0x65AAC0: 0xE5941200,
    0x65AACC: 0xE59411F8,
    0x65DD98: 0xE3500004,
    0x65DDA0: 0xE3500040,
    0x65DDA8: 0x05C500B4,
    0x65DDB0: 0xE5C510B4,
    0x65963C: 0xE3100088,
    0x659648: 0x18970C80,
}

RANGES = {
    "scaler_constructor_call": (0x653B6C, 0x653B80),
    "scaler_constructor": (0x71B0B0, 0x71B108),
    "scaler_parameter_setup": (0x659E78, 0x65A480),
    "auxiliary_scaler_worker": (0x5804A0, 0x5808A8),
    "plane_layout_builder": (0x6609AC, 0x660F60),
    "jpeg_payload_setup": (0x65D450, 0x65D564),
    "jpeg_auxiliary_input_dispatch": (0x576FB8, 0x577048),
    "scaler_completion_fields": (0x65DD1C, 0x65DD90),
    "module20_setup": (0x65A948, 0x65AAD8),
    "module20_mask_transition": (0x65DD90, 0x65DDB8),
    "cpp_masked_input_selection": (0x65962C, 0x659678),
}


def gate_search(data):
    """Search the aligned main image. Shared immediates alone cannot identify a payload."""
    direct_branches, literal_words, layout_immediates, byte_stores = [], [], [], []
    main = data[:0x1000000]
    for index, (word,) in enumerate(iter_unpack("<I", main)):
        site = 4 * index
        if word == BASE + 0x71B090:
            literal_words.append(site)
        if word >> 28 == 15:
            continue
        if word & 0x0E000000 == 0x0A000000:
            delta = word & 0xFFFFFF
            if delta & 0x800000:
                delta -= 0x1000000
            if site + 8 + 4 * delta == 0x71B090:
                direct_branches.append(site)
        if word & 0x0FF00000 == 0x03000000:
            immediate = ((word >> 4) & 0xF000) | (word & 0xFFF)
            if immediate in (0xA7B4, 0xA7EC):
                layout_immediates.append((site, immediate))
        if word & 0x0FF00FFF == 0x05C00038:
            byte_stores.append(site)
    require(direct_branches, [0x659FAC], "aligned A32 direct branches to gate setter")
    require(literal_words, [], "aligned words matching setter address")
    require(
        layout_immediates,
        [(i, 0xA7B4) for i in (0x653B6C, 0x653B78, 0x656990, 0x659ED0)],
        "MOVW scaler payload and absolute gate-offset candidates",
    )
    regions = ((0x653B6C, 0x653B80), (0x659E78, 0x65A480), (0x71B000, 0x71B108))
    owned = [
        site
        for site in byte_stores
        if any(start <= site < end for start, end in regions)
    ]
    require(
        owned,
        [0x71B090, 0x71B100],
        "positive immediate byte stores in scaler setup windows",
    )
    return {
        "scan_range": [0, len(main)],
        "setter_direct_branches": direct_branches,
        "setter_address_words": literal_words,
        "layout_movw_immediates": layout_immediates,
        "generic_byte_store_candidates": len(byte_stores),
        "scaler_setup_scan_windows": regions,
        "scaler_setup_byte_stores": owned,
    }


def verify_static(data):
    for edges in EDGES.values():
        for site, target in edges:
            require(branch_target(data, site), target, f"branch at {site:#x}")
    check_words(data, WORDS)
    literals = {0x580898: 0x020C0001, 0x580A44: 0x020C0002}
    for site, value in literals.items():
        require(u32(data, literal_offset(data, site)), value, f"literal at {site:#x}")
    require(u32(data, 0xA6856C), BASE + 0x6609AC, "job plane-layout vtable slot")
    return {
        "edges": EDGES,
        "instruction_offsets": list(WORDS),
        "literal_reads": literals,
        "gate_search": gate_search(data),
        "ranges": {
            name: {
                "start": start,
                "end_exclusive": end,
                "sha256": sha256(data[start:end]),
            }
            for name, (start, end) in RANGES.items()
        },
    }


def emulate(data):
    from unicorn import Uc, UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, __version__
    from unicorn import arm_const as arm

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(BASE, 0x1000000)
    uc.mem_write(BASE, data[:0x1000000])
    job, device, message, callback = 0x10000000, 0x10020000, 0x10022000, 0x10023000
    sp, ret = 0x10038000, 0x1003E000
    uc.mem_map(job, 0x40000)

    def write(address, *values, fmt="I"):
        uc.mem_write(address, pack(f"<{len(values)}{fmt}", *values))

    def read(address, count=1):
        return list(unpack(f"<{count}I", uc.mem_read(address, 4 * count)))

    def reg(name):
        return uc.reg_read(getattr(arm, f"UC_ARM_REG_{name.upper()}"))

    def set_reg(name, value):
        uc.reg_write(getattr(arm, f"UC_ARM_REG_{name.upper()}"), value)

    def run(start, end=None, **registers):
        stop = ret if end is None else BASE + end
        for name, value in dict(sp=sp, lr=ret, **registers).items():
            set_reg(name, value)
        uc.ctl_flush_tb()
        uc.emu_start(BASE + start, stop, count=100_000)
        require(reg("pc"), stop, f"probe stop from {start:#x}")
        return reg("r0")

    def planes(descriptor):
        return read(descriptor + 4, 3)

    scale_calls, encode_calls, notices = [], [], []

    def boundary(_uc, address, _size, _data):
        if address == BASE + 0x57F904:
            scale_calls.append([reg("r1") - job, reg("r2") - job])
        elif address == BASE + 0x576AC4:
            src = reg("r1")
            encode_calls.append({"descriptor": src - job, "planes": planes(src)})
            set_reg("r0", 0)
        else:
            notices.append(reg("r1"))
        set_reg("pc", reg("lr"))

    for address in (BASE + 0x57F904, BASE + 0x576AC4, callback + 0x20):
        uc.hook_add(UC_HOOK_CODE, boundary, begin=address, end=address)

    write(callback, callback + 4)
    write(callback + 12, callback + 0x20)
    write(message + 4, callback, 0, 0, job)

    scaler, jpeg = job + 0xA7B4, job + 0xA81C
    ordinary_offsets = (0x2140, 0x21E8, 0x2204)
    auxiliary_offsets = (0x2354, 0x238C, 0x23A8)
    cases = []
    for label, old_base, reservation in (
        ("fresh_mode1", None, 0),
        ("mode0_then_mode1_same_base", 0x11000013, 0),
        ("mode0_then_mode1_shifted_base", 0x11010013, 1),
    ):
        uc.mem_write(job, bytes(0x17000))
        write(job + 0x224, 32, 16, fmt="H")
        write(job + 0x22C, 16, 8, fmt="H")
        write(job + 0x20D6, 16, 8, 8, 4, fmt="H")
        write(job + 0x130, 8, 12)
        if old_base is not None:
            write(job + 0xD8, old_base)
            run(0x6609AC, r0=job)
        before = [planes(job + i) for i in ordinary_offsets]
        write(job + 0x20B2, 1, fmt="H")
        write(job + 0xD8, 0x11000013)
        run(0x6609AC, r0=job)
        require(
            [planes(job + i) for i in ordinary_offsets],
            before,
            "mode 1 preserves ordinary planes",
        )
        auxiliary = [planes(job + i) for i in auxiliary_offsets]
        aliased = [a == b for a, b in zip(auxiliary, before)]
        require(
            aliased,
            [old_base == 0x11000013] * 3,
            "mode 0/mode 1 physical plane equality",
        )

        write(scaler + 0x38, 0xA5, fmt="B")
        run(0x653B6C, 0x653B78, r0=job)
        require(uc.mem_read(scaler + 0x38, 1)[0], 0, "constructor clears poisoned gate")
        write(scaler + 0x38, 0xA5, fmt="B")
        for stack_offset, descriptor in (
            (0x10, 0x2178),
            (0x1C, 0x21E8),
            (0x18, 0x2204),
        ):
            write(sp + stack_offset, job + descriptor)
        write(job + 0x42, reservation, fmt="B")
        run(0x659EC8, 0x659FB0, r4=job, r8=job + 0x2354, sb=reservation)
        require(uc.mem_read(scaler + 0x38, 1)[0], 0, "setup clears poisoned gate")
        require(
            read(scaler + 0x18, 3),
            [job + i for i in auxiliary_offsets],
            "auxiliary bindings",
        )
        run(0x65A090, 0x65A0B4, r4=job)
        run(0x65A148, 0x65A16C, r4=job)
        require(
            [planes(job + i) for i in ordinary_offsets[1:]],
            before[1:],
            "ordinary setup repopulates JPEG ancillary planes from ordinary fields",
        )

        scale_calls.clear()
        notices.clear()
        write(sp + 0x2C, scaler)
        write(sp + 0x30, message)
        run(0x580040, 0x580094)
        run(0x5804A0, 0x5808A8, r5=device)
        require(scale_calls, [], "producer-disabled auxiliary scaler")
        write(scaler + 0x38, 1, fmt="B")
        run(0x5804A0, 0x5808A8, r5=device)
        require(
            scale_calls,
            [[0x2354, 0x238C], [0x238C, 0x23A8]],
            "injected auxiliary stage pairs",
        )
        require(notices, [0x020C0001], "auxiliary progress event")
        run(0x6DBA14, 0x6DBEE0, r6=notices[0])
        run(0x6DBA14, 0x6DBC20, r6=0x020C0002)
        require(reg("r1"), 2, "ordinary scaler completion module")
        run(0x65DC34, r0=job, r1=2)
        require(
            [planes(job + i) for i in ordinary_offsets],
            before,
            "module 2 completion plane pointers",
        )
        dimensions = [
            list(unpack("<2H", uc.mem_read(job + descriptor + 0x10, 4)))
            for descriptor in ordinary_offsets[1:]
        ]
        require(
            dimensions,
            [[16, 8], [8, 4]],
            "module 2 completion writes ancillary geometry",
        )

        write(job + 0x65, reservation, fmt="B")
        run(0x6593B0, r0=job, r1=16)
        require(
            read(jpeg + 8, 2), [job + 0x21E8, job + 0x2204], "ancillary JPEG bindings"
        )
        write(message + 8, jpeg)
        run(0x576D64, 0x576DF0, r7=message)
        encode_calls.clear()
        notices.clear()
        run(0x576FB8, 0x577048, r5=device, r7=message)
        expected = [
            {"descriptor": offset, "planes": plane}
            for offset, plane in zip(ordinary_offsets[1:], before[1:])
        ]
        if reservation:
            expected.pop()
        require(encode_calls, expected, "JPEG ancillary encode inputs")
        require(notices, [0x03000004], "ancillary JPEG notification")
        cases.append(
            {
                "layout_history": label,
                "reservation_flag": reservation,
                "ordinary_plane_triplets": before,
                "auxiliary_plane_triplets": auxiliary,
                "same_plane_addresses_by_pair": aliased,
                "initialized_gate_launches": [],
                "injected_gate_scaler_pairs": list(scale_calls),
                "ordinary_completion_geometry": dimensions,
                "jpeg_ancillary_inputs": list(encode_calls),
            }
        )

    module20 = job + 0x16324
    linked = [job + 0x2000 * (i + 1) for i in range(4)]
    for i, obj in enumerate(linked):
        write(obj + 0x20C4, linked[min(i + 1, 3)])
        run(0x654218, r0=obj, r1=16, r2=0x11FFFFE1 + 0x1000 * i)
        write(obj + 0x13C, 0x13000000 + 0x1000 * i)
    write(job + 0x20D0, linked[0])
    write(job + 0x2080, 1, fmt="B")
    downstream = [0x14000000, 0x14001000, 0x14002000]
    write(job + 0x218, 0xFC0)
    run(0x654218, r0=job, r1=15, r2=0x13FFFFE1)
    require(
        read(job + 0x1F8, 3),
        downstream,
        "slot 15 allocates module 20 destination bases",
    )
    transitions = []
    for mask, source_base, after in ((4, 0x12000000, 8), (0x40, 0x13000000, 0x80)):
        write(job + 0x20B4, mask, fmt="B")
        run(0x65A948, 0x65AAD8, r4=job, r5=job + 0x2000, r6=job + 0x200)
        source_bases = [read(module20 + i)[0] for i in (0x44, 0x48, 0x50, 0x4C)]
        require(
            source_bases,
            [source_base + 0x1000 * i for i in range(4)],
            "module 20 source bases",
        )
        require(
            [read(module20 + i)[0] for i in (0x2C, 0x24, 0x28)],
            downstream,
            "module 20 destination fields",
        )
        run(0x65DC34, r0=job, r1=20)
        require(uc.mem_read(job + 0x20B4, 1)[0], after, "module 20 completion mask")
        run(0x65962C, 0x659678, r4=job, r5=job + 0x2000)
        require(
            [reg(i) for i in ("r7", "sl", "fp")],
            downstream,
            "subsequent CPP input bases",
        )
        transitions.append(
            {
                "mask": mask,
                "updated_mask": after,
                "source_bases": source_bases,
                "module20_destinations_and_cpp_bases": downstream,
            }
        )
    return {
        "engine": f"Unicorn {__version__}",
        "layout_cases": cases,
        "module20_cases": transitions,
        "hooked_code_offsets": [0x57F904, 0x576AC4],
        "synthetic_callback": callback + 0x20,
    }


def analyze(data):
    return {
        "decoded_sha256": DECODED_SHA256,
        "candidate_load_base": BASE,
        "location_units": "decoded file offsets except synthetic addresses",
        "static": verify_static(data),
        "synthetic_a32": emulate(data),
        "limits": [
            "The aligned A32 search and resolved setter/constructor show zero producers in the "
            "inspected paths. Computed pointer stores, copies, indirect code and other instruction "
            "sets are outside the search. A nonzero producer is unresolved.",
            "Mode 1 and mode 0 construct separate descriptors with the same corresponding plane "
            "layout for the same input parameters. Fresh mode 1 leaves ordinary plane pointers "
            "unchanged. The mode 0 to mode 1 transition is a synthetic replay, not a camera-job trace.",
            "The auxiliary scaler calls were reached by forcing payload+0x38. The two stage "
            "pairs and JPEG encode inputs were intercepted. Plane equality in a paired fixture "
            "does not establish reachability, pixel contents or actual JPEG compression.",
            "Module 20 probes cover its pointer fields and two exact completion masks. "
            "The linked objects are synthetic. No module 20 pixel operation was executed.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = json.dumps(analyze(load_image(args.decoded)), indent=2)
    if args.compare:
        require(
            json.loads(result),
            json.loads(args.compare.read_text(encoding="utf-8")),
            "published masked scaler evidence",
        )
    print(result)


if __name__ == "__main__":
    main()
