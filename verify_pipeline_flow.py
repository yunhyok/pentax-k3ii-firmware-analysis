"""Verify the K-3 II RAW-job dispatch, tone handoff and output boundaries.

SPDX-License-Identifier: GPL-2.0-only
All instruction locations are decoded file offsets.
"""
import argparse
import json
from pathlib import Path
from struct import unpack

from verify_findings import (
    DECODED_SHA256,
    literal_offset,
    require,
    require_snapshot,
    sha256,
    u32,
)
from verify_raw_path import branch_target
from verify_tone_path import BASE, adr_r0_target, load_image


# Each entry is (instruction offset, target file offset).
EDGES = {
    "job_registration": (
        (0x720040, 0x5A1078), (0x720050, 0x6DB304),
        (0x72005C, 0x597774), (0x72006C, 0x597960), (0x720078, 0x597924),
        (0x5296D4, 0x5A1618), (0x5A1630, 0x5A14B4), (0x5A1640, 0x56B2E0),
        (0x5A1658, 0x5A13E0), (0x5A13EC, 0x5A1354), (0x52AF48, 0x6DB894),
        (0x6DB8C4, 0x5A11F8), (0x6DB8D0, 0x6DB888), (0x6DB890, 0x70C3CC),
    ),
    "worker": (
        (0x6DD2D4, 0x6DCB14), (0x6DCB74, 0x70C408), (0x6DCB84, 0x70C3E8),
        (0x6DCBC4, 0x5A12A4), (0x5A12E8, 0x719E7C), (0x5A12FC, 0x56B2E0),
        (0x6DCF34, 0x81C768), (0x6DCF48, 0x6DCF90),
        (0x6DCF4C, 0x6DCF98), (0x6DCFA4, 0x6DC2D0), (0x6DD118, 0x81C778),
    ),
    "recipe": (
        (0x52AC2C, 0x7774E4), (0x52AC58, 0x7774E4), (0x52AC84, 0x7774E4),
        (0x52ACD8, 0x7774E4), (0x52AD04, 0x7774E4), (0x52AD30, 0x7774E4),
        (0x52AD54, 0x7774E4), (0x52AD6C, 0x7774E4), (0x7774FC, 0x76E7AC),
        (0x52AC38, 0x6540BC), (0x52AC64, 0x6540BC), (0x52ACE4, 0x6540BC),
        (0x52AD10, 0x6540BC), (0x52AD3C, 0x6540BC), (0x52AD78, 0x6540BC),
        (0x81C76C, 0x7B32C8), (0x81C774, 0x834824), (0x81C79C, 0x834814),
    ),
    "message_dispatch": (
        (0x6DC2E4, 0x81C770), (0x6DC31C, 0x7DB908), (0x6DC328, 0x7DB920),
        (0x6DC334, 0x656984), (0x6DC340, 0x7DB910), (0x6DC34C, 0x7DB918),
        (0x6DC360, 0x6FEA38), (0x6FEA3C, 0x718AE8),
        (0x718B38, 0x526304), (0x6FEA70, 0x718B60),
    ),
    "tone_dispatch": (
        (0x6DB5BC, 0x7DD148), (0x565D58, 0x57B5DC), (0x57C4DC, 0x57BAC4),
        (0x565CD0, 0x4D5F54), (0x4D5FAC, 0x4BA63C),
        (0x565D78, 0x5450D4), (0x565D84, 0x59786C),
        (0x6569B4, 0x656A08), (0x656A0C, 0x656A94),
        (0x57BB30, 0x72D8CC), (0x57BBB4, 0x754CA4),
        (0x57BBBC, 0x57BCB8), (0x57BC50, 0x754B14),
        (0x4BAC28, 0x4E31A4), (0x4BAC6C, 0x4E3154), (0x4BAC84, 0x4BAC40),
        (0x4BCCC4, 0x4DDDC4), (0x4BCDE8, 0x4DDE3C),
    ),
    "tone_completion": (
        (0x6DBF0C, 0x6DB9EC), (0x6DBA88, 0x6DBCE0),
        (0x6DBCE8, 0x65DC34), (0x6DBCF8, 0x6DBE0C),
        (0x6DBE14, 0x6DBD0C), (0x6DBD10, 0x6DB894),
    ),
    "raw_pipe": (
        (0x6DB6C8, 0x85A2A8), (0x565CE8, 0x578120),
        (0x578DFC, 0x578BB8), (0x578CDC, 0x57867C), (0x578800, 0x53DE04),
        (0x6DBA74, 0x6DBC20), (0x6DBC24, 0x65DC34), (0x6DBC28, 0x6DBE0C),
    ),
    "scaler_dispatch": (
        (0x6DB5F4, 0x81D364), (0x565EA0, 0x57ECE8), (0x580C04, 0x58099C),
        (0x580A08, 0x580034), (0x5800CC, 0x57F904),
    ),
    "jpeg_codec": (
        (0x6DB690, 0x87BC84), (0x566004, 0x574628), (0x575CF8, 0x5755BC),
        (0x575708, 0x575384), (0x5754E4, 0x53C42C), (0x57551C, 0x53D16C),
        (0x53C828, 0x53C104), (0x53C11C, 0x4B6CF8), (0x53C21C, 0x4B6CF8),
        (0x53C844, 0x4B6BFC), (0x53C950, 0x6E3954),
    ),
    "store_dispatch": (
        (0x6DB6AC, 0x7DD140), (0x5662C8, 0x5A573C), (0x5A9CB0, 0x5A9704),
        (0x5A97E8, 0x5A8790), (0x5A9840, 0x5A6BE8),
        (0x6DBA4C, 0x6DBD4C), (0x6DBDA4, 0x6DBD0C),
        (0x5662F4, 0x5977C0), (0x74353C, 0x82AD28), (0x82B3D4, 0x82ADC8),
    ),
    "exif_writer": (
        (0x7C6B90, 0x7CD064), (0x7CD5F0, 0x7CD504),
    ),
}

# Literal reads establish constructed vtables and matching message IDs.
LITERALS = {
    0x6DB334: 0x02A6A428, 0x6DB5CC: 0x00600002, 0x6DB6BC: 0x00800001,
    0x57B604: 0x02A6E31C, 0x4BA644: 0x02A64CC4, 0x57C060: 0x00600003,
    0x5A5754: 0x02A6B89C, 0x5A97A8: 0x00800001, 0x5A9888: 0x00800001,
    0x578138: 0x02A678A8, 0x57ED00: 0x02A6A4CC, 0x5809CC: 0x00708001,
    0x6DB6A0: 0x00C00003, 0x574648: 0x02A69010, 0x5755F8: 0x00C00003,
    0x53C15C: 0x02A47BFC, 0x53C220: 0x02A47CCC, 0x53C2E0: 0x02A47B7C,
    0x4B6CF8: 0x200F0000, 0x4B6BFC: 0x200F0000, 0x82AD30: 0x02A74A14,
    0x7CD06C: 0x02A5C274, 0x7CD184: 0x029E56EB,
}
VTABLE_SLOTS = {
    0xA6A44C: 0x6DCB14, 0xA6A464: 0x6DBF08, 0xA6A4AC: 0x6DD2D0,
    0xA6E384: 0x6FEA50, 0xA6E388: 0x57C4D8, 0xA64CD8: 0x4BABBC,
    0xA64CDC: 0x4BABF4, 0xA64CE0: 0x4BCD24, 0xA64CF4: 0x4BCB70,
    0xA6B8DC: 0x6FEA50, 0xA6B8E0: 0x5A9CAC,
    0xA678EC: 0x578DF8, 0xA6A510: 0x580C00, 0xA69058: 0x575CF4,
    0xA74A80: 0x82B3C0, 0xA5C280: 0x7CD15C, 0xA5C28C: 0x7CD5C8, 0xA5C294: 0x7EB150,
}
ANCHORS = {
    # Job manager, pending state and shared event.
    0x597774: 0xE5801034,
    0x597960: 0xE580100C,
    0x597924: 0xE5801008,
    0x5A163C: 0xE3A01001,
    0x6DB8BC: 0xE5940034,
    0x6DB888: 0xE3A01001,
    0x6DB88C: 0xE2800D0D,
    0x6DCB68: 0xE3A01003,
    0x6DCB70: 0xE2840D0D,
    0x6DCBB8: 0xE5940034,
    # Recipe cursor and op5/op6 dispatch.
    0x6540BC: 0xE5801034,
    0x81C768: 0xE1C003D4,
    0x81C770: 0xE1C003D4,
    0x81C780: 0xE5801038,
    0x6DCF38: 0xE2400005,
    0x6DCF40: 0x308FF100,
    0x6DCF90: 0xE3A02000,
    0x6DCF98: 0xE3A02001,
    # Module command and job/payload fields in the message.
    0x6DC310: 0xE0857106,
    0x6DC318: 0xE597108C,
    0x6DC350: 0xE5970038,
    0x7DB908: 0xE580100C,
    0x7DB910: 0xE5801008,
    0x7DB918: 0xE5801010,
    0x7DB920: 0xE5801004,
    0x72D8CC: 0xE5900008,
    0x6FEA88: 0xE1A00004,
    0x6FEA8C: 0xE12FFF32,
    # Tone module registry, receiver thunk and wrapper dispatch.
    0x7DD148: 0xE5900004,
    0x6DB5C8: 0xE5840038,
    0x6DB5D0: 0xE584008C,
    0x565D5C: 0xE5840004,
    0x57B624: 0xE5801010,
    0x57C4D8: 0xE2400010,
    0x57BB00: 0xE2401606,
    0x57BB08: 0xE2511002,
    0x656A08: 0xE30A041C,
    0x656A94: 0xE0800002,
    0x4D5FB0: 0xE5840004,
    0x5450D4: 0xE5900004,
    0x59786C: 0xE5801034,
    0x57BC24: 0xE5945034,
    0x754B14: 0xE5900088,
    0x57BC54: 0xE1A01000,
    0x57BC64: 0xE590C014,
    0x57BC6C: 0xE12FFF3C,
    0x4BABD0: 0xE590C018,
    0x4BABD8: 0xE12FFF3C,
    0x4BABE0: 0xE590101C,
    0x4BABF0: 0xE12FFF11,
    0x4BAC50: 0xE12FFF3C,
    0x4BAC7C: 0x1590C030,
    # Tone callback and store receiver.
    0x57C064: 0xE5903008,
    0x57C06C: 0xE12FFF33,
    0x6DBF08: 0xE2400004,
    0x6DBCE0: 0xE3A01000,
    0x7DD140: 0xE5900058,
    0x5662CC: 0xE5840058,
    0x6DB6B8: 0xE584005C,
    0x6DB6C0: 0xE58400B0,
    0x5A5770: 0xE4801018,
    0x5A9CAC: 0xE2400008,
    0x5A6C4C: 0xE590C06C,
    0x5A6C54: 0xE12FFF3C,
    # JPEG SOI, APP1, EXIF identifier and output calls.
    0x7CD15C: 0xE3A010FF,
    0x7CD160: 0xE3A020D8,
    0x7CD164: 0xE5C0106C,
    0x7CD168: 0xE5C0206D,
    0x7CD16C: 0xE5C0106E,
    0x7CD170: 0xE3A010E1,
    0x7CD174: 0xE5C0106F,
    0x7CD18C: 0xE5802072,
    0x7CD194: 0xE1C017B6,
    0x7CD600: 0xE5901020,
    0x7CD608: 0xE12FFF31,
    0x7EB1B8: 0xE5907018,
    0x7EB1C0: 0xE12FFF37,
    0x7EB1F8: 0xE590C014,
    0x7EB200: 0xE12FFF3C,
    # Recipe selector sites and state bytes.
    0x52AB88: 0xE3A0700B,
    0x52AB90: 0xE3A0700C,
    0x52AC24: 0x13A01013,
    0x52AC28: 0x03A0100F,
    0x52AC50: 0x13A01012,
    0x52AC54: 0x03A0100E,
    0x52ACAC: 0xE3A0100D,
    0x52ACD0: 0x13A01015,
    0x52ACD4: 0x03A01011,
    0x52ACFC: 0x13A01014,
    0x52AD00: 0x03A01010,
    0x5A1218: 0xE3A01002,
    0x56B2E0: 0xE5C01030,
    0x5A12F4: 0xE3A01003,
    0x6FEA84: 0xE590200C,
    # Raw-pipe and scaler bindings.
    0x565CEC: 0xE5840008,
    0x57814C: 0xE5801008,
    0x578DF8: 0xE2400008,
    0x6DB6D4: 0xE5840060,
    0x6DB6D8: 0xE3A00002,
    0x6DB6DC: 0xE58400B4,
    0x578D94: 0xE1A00005,
    0x578D98: 0xE12FFF33,
    0x565EA4: 0xE5840014,
    0x6DB600: 0xE5840040,
    0x6DB608: 0xE5846094,
    0x580C00: 0xE2400008,
    # JPEG codec hardware configuration.
    0x87BC84: 0xE590002C,
    0x566008: 0xE584002C,
    0x574664: 0xE5801008,
    0x575CF4: 0xE2400008,
    0x5755FC: 0xE1500009,
    0x6DB69C: 0xE5840058,
    0x6DB6A4: 0xE58400AC,
    0x53C170: 0xE7843100,
    0x53C1C4: 0xE7823100,
    0x53C318: 0xE7880104,
    0x53C33C: 0xE7870104,
    0x4B6C04: 0xE5802014,
    0x4B6C0C: 0xE5801018,
    # StoreImage sink router.
    0x5977C4: 0xE7801002,
    0x743544: 0xE5840004,
    0x513F48: 0xE5840004,
    0x7849A0: 0xE5900004,
    0x82AD38: 0xE5801000,
    0x82B3E4: 0xE591C06C,
    0x82B3F0: 0xE12FFF1C,
}
MARKERS = {
    0x5A5D54: b"(StoreImage)\x00",
    0x7CD664: b"CExifJpegWriter::%s",
    0x9E56EB: b"Exif\x00\x00",
}
RANGES = {
    "raw_recipe_selection": (0x52AB88, 0x52AD80),
    "controller_submit_and_signal": (0x6DB888, 0x6DB8D4),
    "pending_job_selection": (0x5A12A4, 0x5A1328),
    "controller_module_message": (0x6DC2D0, 0x6DC364),
    "tone_receiver": (0x57BAC4, 0x57C074),
    "tone_prepare_dispatch": (0x4BABBC, 0x4BAC88),
    "jpeg_table_loader": (0x53C104, 0x53C34C),
    "jpeg_codec_config": (0x53C42C, 0x53C998),
    "jpeg_mmio_table_select": (0x4B6CF8, 0x4B6D9C),
    "jpeg_quantization_reference": (0xA47B7C, 0xA47BFC),
    "store_image_command": (0x5A97A4, 0x5A9898),
    "exif_jpeg_header_writer": (0x7CD15C, 0x7CD1AC),
    "exif_jpeg_output": (0x7EB150, 0x7EB208),
}
STAGES = {
    "raw_pipe": (5, 10), "tone_dispatch": (5, 0), "alternate_tone_dispatch": (6, 0),
    "scaler_dispatch": (5, 2), "store_dispatch": (5, 9), "direct_jpeg_dispatch": (5, 8),
}


def verify_static(data):
    for edges in EDGES.values():
        for offset, target in edges:
            require(branch_target(data, offset), target, f"A32 branch at {offset:#x}")
    for offset, expected in LITERALS.items():
        require(u32(data, literal_offset(data, offset)), expected, f"literal at {offset:#x}")
    for offset, target in VTABLE_SLOTS.items():
        require(u32(data, offset), BASE + target, f"vtable entry at {offset:#x}")
    for offset, expected in ANCHORS.items():
        require(u32(data, offset), expected, f"A32 anchor at {offset:#x}")
    for offset, marker in MARKERS.items():
        require(data[offset:offset + len(marker)], marker, f"marker at {offset:#x}")
    require(adr_r0_target(data, 0x7CD624), 0x7CD664, "EXIF writer diagnostic")
    tables = []
    for start, first_id, second_id in ((0xA47BFC, 0, 0x10), (0xA47CCC, 1, 0x11)):
        end = start
        for table_id, symbols in ((first_id, 12), (second_id, 162)):
            require(data[end], table_id, "Huffman table class and ID")
            require(sum(data[end + 1:end + 17]), symbols, "Huffman symbol count")
            end += 17 + symbols
        tables.append({
            "start": start, "end_exclusive": end, "symbol_counts": [12, 162],
            "sha256": sha256(data[start:end]),
        })
    return {
        "edges": EDGES,
        "jpeg_huffman_tables": tables,
        "ranges": {
            label: {"start": start, "end_exclusive": end, "sha256": sha256(data[start:end])}
            for label, (start, end) in RANGES.items()
        },
        "literal_reads": LITERALS,
        "vtable_slots": VTABLE_SLOTS,
        "a32_anchor_offsets": list(ANCHORS),
        "marker_offsets": list(MARKERS),
    }


def emulate_recipes(data):
    from unicorn import Uc, UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, __version__
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP,
    )

    scratch = 0x10000000
    stop = scratch + 0x2000
    factory = BASE + 0x76E7AC
    allocator = BASE + 0x712828
    step_limit = 100_000
    emulator = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    emulator.mem_map(BASE, 0x1000000)
    emulator.mem_write(BASE, data[:0x1000000])
    emulator.mem_map(scratch, 0x4000)
    allocations = []

    def allocate(uc, _address, _size, _user_data):
        allocations.append(uc.reg_read(UC_ARM_REG_R0))
        uc.reg_write(UC_ARM_REG_R0, scratch)
        uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

    emulator.hook_add(UC_HOOK_CODE, allocate, begin=allocator, end=allocator)
    results = {}
    for selector in range(0x0B, 0x16):
        allocations.clear()
        emulator.mem_write(scratch, bytes(0x4000))
        emulator.reg_write(UC_ARM_REG_SP, scratch + 0x3C00)
        emulator.reg_write(UC_ARM_REG_LR, stop)
        emulator.reg_write(UC_ARM_REG_R1, selector)
        emulator.emu_start(factory, stop, count=step_limit)
        require(emulator.reg_read(UC_ARM_REG_PC), stop, "factory return")
        require(emulator.reg_read(UC_ARM_REG_R0), scratch, "recipe buffer")
        require(allocations, [0x302], "recipe allocation")
        values = unpack("<385H", emulator.mem_read(scratch, 0x302))
        rows = list(zip(values[:128], values[128:256], values[256:384]))
        last = max(index for index, row in enumerate(rows) if any(row))
        require(rows[last], (8, 0, 0), "final populated recipe row")
        require(values[384], 1, "recipe trailer")
        results[hex(selector)] = {
            "populated_prefix_length": last + 1,
            "stage_indices": {
                stage: [index for index, row in enumerate(rows) if row[:2] == pair]
                for stage, pair in STAGES.items()
            },
        }
    return {
        "engine": f"Unicorn {__version__}", "factory": factory - BASE,
        "heap_stub": allocator - BASE, "step_limit_per_selector": step_limit,
        "array_offsets": [0, 0x100, 0x200], "array_entries": 128,
        "trailer_offset": 0x300, "trailer_value": 1, "selectors": results,
    }


def analyze(data):
    return {
        "decoded_sha256": DECODED_SHA256,
        "base": BASE,
        "offset_convention": "File offsets, with zero-based recipe indices",
        "static": verify_static(data),
        "recipe_emulation": emulate_recipes(data),
        "limits": [
            "Recipe factory alone ran under bounded emulation with the heap allocator stubbed.",
            "Tone prepare variant and RAW job resubmission are conditional firmware branches.",
            "The JPEG encoder receives command 0x00c00003, but none of the generated RAW recipes directly dispatches operation 5 to module 8.",
            "StoreImage dispatch, the JPEG encoder and EXIF JPEG packaging are independently verified boundaries.",
            "The path from processed pixels to JPEG compression and from compression to the EXIF writer remains unresolved.",
            "No live event scheduling, hardware image processing or physical file output was observed.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = json.dumps(analyze(load_image(args.decoded)), indent=2)
    if args.compare:
        require_snapshot(
            json.loads(result), args.compare, "published pipeline evidence"
        )
    print(result)


if __name__ == "__main__":
    main()
