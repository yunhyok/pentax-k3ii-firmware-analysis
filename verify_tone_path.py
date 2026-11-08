"""Verify a bounded static trace of the K-3 II tone and gamma path.

SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import json
from pathlib import Path

from inspect_firmware import FIRMWARE_SIZE
from verify_findings import (
    DECODED_SHA256,
    literal_offset,
    require,
    require_snapshot,
    sha256,
    u32,
)


BASE = 0x02000000
BANKS = (
    # Address getter, source object offset, 0xa00-copy call, 0x1000-copy call.
    (0x5B6C00, 0x1420C, 0x4DE0FC, 0x4DE154),
    (0x5B6C08, 0x1520C, 0x4DE110, 0x4DE168),
    (0x5B6C10, 0x1620C, 0x4DE124, 0x4DE17C),
    (0x5B6C18, 0x1720C, 0x4DE138, 0x4DE190),
)
EDGES = (
    ("dump to tone dump", 0x5B3A3C, 0x5B1160),
    ("dump to color matrix dump", 0x5B3A44, 0x5B0EFC),
    ("tone dump banner to formatter", 0x5B1168, 0x7073EC),
    ("TGCTL dump to formatter", 0x5B117C, 0x7073EC),
    ("wrapper to prepare", 0x4BCCC4, 0x4DDDC4),
    ("wrapper to apply", 0x4BCDE8, 0x4DDE3C),
    ("prepare to base curve selector", 0x4DDE1C, 0x4DDAB8),
    ("prepare to three-curve adjustment", 0x4DDE24, 0x4DD6D4),
    ("prepare tail branch to composer", 0x4DDE30, 0x4DD42C),
    ("selector to regular producer", 0x4DDC08, 0x4DC980),
    ("selector to mode-6 producer", 0x4DDC74, 0x4DD924),
    ("composer to interpolator, first curve", 0x4DD510, 0x4DD3EC),
    ("composer to interpolator, second curve", 0x4DD52C, 0x4DD3EC),
    ("composer to interpolator, third curve", 0x4DD54C, 0x4DD3EC),
    ("composer to table expander, first curve", 0x4DD5B4, 0x4DC910),
    ("composer to table expander, second curve", 0x4DD5C4, 0x4DC910),
    ("composer to table expander, third curve", 0x4DD5D4, 0x4DC910),
    ("composer to table expander, weighted curve", 0x4DD5E4, 0x4DC910),
    ("apply to TCYC setter", 0x4DDE84, 0x5B667C),
    ("apply to additional table count getter", 0x4DE080, 0x4F962C),
    ("apply to additional table getter", 0x4DE08C, 0x5B6BF0),
    ("apply to additional table copy", 0x4DE098, 0x712898),
)
# Each row identifies a call, the RMW helper and the descriptor's field offset.
TGCTL = (
    (0x4DDE64, 0x5B64A0, 0x00, 0, 1),
    (0x4DDE74, 0x5B64D0, 0x01, 1, 1),
    (0x4DDE94, 0x5B6500, 0x10, 16, 1),
    (0x4DDEC0, 0x5B6530, 0x14, 17, 1),
    (0x4DDEA4, 0x5B6560, 0x11, 24, 1),
    (0x4DDEDC, 0x5B6590, 0x18, 25, 1),
)
TCTBLCTL = (
    (0x4DDEEC, 0x5B65C0, 0x1C, 0, 2),
    (0x4DDEFC, 0x5B65E4, 0x1E, 4, 2),
    (0x4DDF0C, 0x5B6608, 0x20, 8, 2),
    (0x4DDF1C, 0x5B662C, 0x21, 16, 1),
    (0x4DDF2C, 0x5B6658, 0x22, 24, 6),
)


def load_image(path):
    with path.open("rb") as stream:
        data = stream.read(FIRMWARE_SIZE + 1)
    require(len(data), FIRMWARE_SIZE, "decoded length")
    require(sha256(data), DECODED_SHA256, "decoded identity")
    return data


def branch_target(data, offset, link=True):
    word = u32(data, offset)
    opcode = 0xEB if link else 0xEA
    if offset % 4 or word >> 24 != opcode:
        raise ValueError(f"invalid A32 branch at {offset:#x}")
    displacement = word & 0xFFFFFF
    if displacement & 0x800000:
        displacement -= 0x1000000
    target = offset + 8 + 4 * displacement
    u32(data, target)
    return target


def a32_immediate(word):
    value = word & 0xFF
    rotation = 2 * ((word >> 8) & 15)
    return ((value >> rotation) | (value << (32 - rotation))) & 0xFFFFFFFF


def adr_r0_target(data, offset):
    word = u32(data, offset)
    require(word & 0xFFFFF000, 0xE28F0000, f"ADD r0, PC immediate at {offset:#x}")
    target = offset + 8 + a32_immediate(word)
    u32(data, target)
    return target


def check_edge(data, offset, target, link=True):
    require(branch_target(data, offset, link), target, f"call target at {offset:#x}")


def literal_r0(data, offset):
    require(u32(data, offset) & 0xF000, 0, f"literal LDR destination at {offset:#x}")
    return u32(data, literal_offset(data, offset))


def check_words(data, expected):
    for offset, word in expected.items():
        require(u32(data, offset), word, f"A32 anchor at {offset:#x}")


def verify(data):
    for _, call, target in EDGES:
        check_edge(data, call, target, link=call != 0x4DDE30)
    for call, target, *_ in TGCTL + TCTBLCTL:
        check_edge(data, call, target)

    diagnostics = []
    for offset, target, label in (
        (0x5B1164, 0x5B1290, b"\n#### CColorInterpolationDriver::DumpToneGamma() ####\n\0"),
        (0x5B1178, 0x5B12C8, b"IO_B2Y.F_B2Y.TGCTL"),
        (0x5B1184, 0x5B12F0, b"IO_B2Y.F_B2Y.TCTBLCTL"),
        (0x5B0F00, 0x5B0F8C, b"#### CColorInterpolationDriver::DumpColorMatrixUnit1() ####\n\0"),
    ):
        require(adr_r0_target(data, offset), target, f"diagnostic ADR at {offset:#x}")
        require(data[target:target + len(label)], label, "diagnostic string")
        diagnostics.append({"adr": offset, "string_offset": target, "text": label.strip(b"\0\n").decode()})

    b2y_base = literal_r0(data, 0x5B116C)
    require(b2y_base, 0x20020000, "B2Y diagnostic base")
    require(literal_r0(data, 0x5B64A0), b2y_base, "TGCTL writer base")
    require(literal_r0(data, 0x5B65C0), b2y_base + 0x804, "TCTBLCTL writer address")
    require(literal_r0(data, 0x5B6684), b2y_base + 0x808, "TCYC writer address")
    check_words(data, {
        0x5B1174: 0xE5901800, 0x5B1180: 0xE5941004, 0x5B0F10: 0xE5901880,
        0x5B64B8: 0xE5810800, 0x5B65C8: 0xE7C12011, 0x5B65CC: 0xE5802000,
        0x4BCC64: 0xE3000454, 0x4BCC6C: 0xE0800004, 0x4BCD18: 0xE5C4000B,
        0x4BCDD4: 0xE5D4000B, 0x4BCDE0: 0xE3000454, 0x4BCDE4: 0xE0800004,
        0x4DC7E8: 0xE5801000, 0x4DDDF0: 0xE5850208, 0x4DDE0C: 0xE5D00010,
        0x4DDB08: 0xE3500006, 0x4DDB28: 0x0A00003F,
        0x4DCFAC: 0xE3500901, 0x4DCFB8: 0xE3540C01, 0x4DCFBC: 0xE0CA00B2,
        0x4DDA98: 0xE3500901, 0x4DDAA4: 0xE3540C01, 0x4DDAA8: 0xE0C700B2,
        0x4DD3EC: 0xE1A00322, 0x4DD3F0: 0xE202203F, 0x4DD3F4: 0xE35000FF,
        0x4DD41C: 0xE0811D22, 0x4DD420: 0xE0800341,
        0x4DD554: 0xE3A0204D, 0x4DD59C: 0xE3530C01, 0x4DD5A0: 0xE1C100B0,
        0x4DC968: 0xF400074D, 0x4DC978: 0xE3A02C01,
        0x4DE078: 0xE2840B62, 0x4DE07C: 0xE2800F87, 0x4DE084: 0xE1A06100,
        0x4DE094: 0xE2841F83, 0x4F962C: 0xE1D000B6,
    })
    vtable = u32(data, literal_offset(data, 0x4DC7E4))
    require(vtable, BASE + 0xA60DCC, "constructor vtable")
    require(u32(data, vtable - BASE + 0x18), BASE + 0x4DDDC4, "prepare slot")
    require(u32(data, vtable - BASE + 0x1C), BASE + 0x4DDE3C, "apply slot")
    banks = []
    for i, (getter, source, short_call, full_call) in enumerate(BANKS):
        address = literal_r0(data, getter)
        require(address, 0x20A21000 + i * 0x1000, "curve bank address")
        # Apply constructs r6/r7/r9/r10 = object + bank source offset.
        register = (6, 7, 9, 10)[i]
        add_start = 0x4DE0B0 + 4 * i
        add_end = (0x4DE0C0, 0x4DE0C4, 0x4DE0CC, 0x4DE0D0)[i]
        page = u32(data, add_start)
        delta = u32(data, add_end)
        require(page & 0xFFFFF000, 0xE2840000 | register << 12, "curve buffer page ADD")
        require(delta & 0xFFFFF000, 0xE2800000 | register << 16 | register << 12, "curve buffer offset ADD")
        require(a32_immediate(page) + a32_immediate(delta), source, "curve buffer object offset")
        for call, count_word in ((short_call, 0xE3A02C0A), (full_call, 0xE3A02A01)):
            check_edge(data, call, getter)
            check_edge(data, call + 12, 0x7129D0)
            require(u32(data, call + 4), count_word, "curve copy size")
            require(u32(data, call + 8), 0xE1A01000 + register, "curve copy source")
        banks.append({"address": address, "getter": getter, "source_object_offset": source,
                      "copy_calls": {"2560_bytes": short_call + 12, "4096_bytes": full_call + 12}})

    require(literal_r0(data, 0x5B6BF0), 0x20A00000, "additional table destination")
    return {
        "schema_version": 1,
        "decoded_sha256": DECODED_SHA256,
        "offset_space": "Decoded file offsets. Addresses and object offsets are named separately.",
        "candidate_code_base": BASE,
        "diagnostics": diagnostics,
        "direct_edges": [{"purpose": name, "instruction": call, "target": target} for name, call, target in EDGES],
        "code_range_sha256": {
            f"{start:#x}..{end:#x}": sha256(data[start:end]) for start, end in (
                (0x4DC910, 0x4DC980), (0x4DC980, 0x4DCFCC), (0x4DD3EC, 0x4DD42C),
                (0x4DD42C, 0x4DD60C), (0x4DD924, 0x4DDAB8), (0x4DDE3C, 0x4DE1A8),
                (0x5B1160, 0x5B1290),
            )
        },
        "prepare_apply": {"constructed_vtable_address": vtable, "subobject_offset": 0x454,
                          "wrapper_pending_byte_offset": 0xB, "descriptor_pointer_offset": 0x208},
        "registers": {
            "b2y_base_address": b2y_base,
            "TGCTL": {"address": b2y_base + 0x800, "setters": register_rows(TGCTL)},
            "TCTBLCTL": {"address": b2y_base + 0x804, "setters": register_rows(TCTBLCTL)},
            "TCYC": {"address": b2y_base + 0x808, "setter": 0x5B667C,
                     "descriptor_offsets": [4, 8, 12], "field_width": 12},
            "CC1CTL_diagnostic_read_address": b2y_base + 0x880,
        },
        "curve_generation": {
            "regular_entry": 0x4DC980, "selector_6_entry": 0x4DD924,
            "output_halfwords": 256, "output_cap": 0x4000,
            "composed_curve_count": 4, "companion_weights": [77, 150, 29],
            "interpolation_input_step": 64, "packed_halfwords": 1280,
        },
        "additional_table": {"address": 0x20A00000, "source_object_offset": 0x20C,
                             "count_object_offset": 0x18A22, "copy_length": "four times a u16 count"},
        "curve_banks": banks,
        "limits": ["Static trace for this decoded image.",
                   "Selector and descriptor field names are descriptive. Camera menu mapping is unverified.",
                   "Device memory behavior, physical addresses and pixel stage timing are unmeasured.",
                   "Table 0x20a00000 contents and exact per-pixel hardware transfer function remain open."],
    }


def register_rows(rows):
    return [{"call": call, "setter": target, "descriptor_offset": source, "bit": bit, "width": width}
            for call, target, source, bit, width in rows]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    try:
        result = verify(load_image(args.decoded))
        if args.compare:
            require_snapshot(result, args.compare, "tone path snapshot")
    except (OSError, ValueError) as error:
        parser.exit(1, f"tone verification failed: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
