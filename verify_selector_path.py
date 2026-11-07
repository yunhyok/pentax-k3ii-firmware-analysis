"""Verify the recipe selector namespace and execute its original default initializers.

SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import json
from pathlib import Path
import struct

from verify_findings import DECODED_SHA256, require
from verify_tone_path import BASE, check_edge, check_words, load_image


DEFAULT_SELECTORS = (0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 1, 2, 3, 0, 1, 2,
                     1, 1, 1, 1, 1, 2, 1, 1, 0, 2, 1, 1, 1, 0, 0, 1, 2, 3,
                     1, 4, 3, 4, 0, 6)
IMAGE_TONE = (0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 5)
EDGES = (
    (0x4BCC8C, 0x4DE1E0), (0x4DDAEC, 0x52671C),
    (0x4DDC74, 0x4DD924), (0x658BF0, 0x6EF3B8),
    (0x658C04, 0x73DC74), (0x66A8A0, 0x70145C),
    (0x66A8AC, 0x73DC74), (0x7014A0, 0x6FE180),
    (0x76D674, 0x4DB21C), (0x76D684, 0x6EF39C),
    (0x78E314, 0x7DD7E8), (0x78E70C, 0x78CEB4),
    (0x78CEC8, 0x6EF3B8),
)


def verify(data):
    for source, target in EDGES:
        check_edge(data, source, target)
    for offset, words in (
        (0x52671C, [0xE5900044, 0xE12FFF1E]),
        (0x73DC74, [0xE5801044, 0xE12FFF1E]),
        (0x4DE1E0, [0xE2800B62, 0xE2800F86, 0xE5801000, 0xE12FFF1E]),
        (0x4DDACC, [0xE5950000]), (0x4DDAE8, [0xE5950000]),
        (0x4DDB08, [0xE3500006]),
        (0x4DDB28, [0x0A00003F]),
        (0x6EF3B8, [0xE0800001, 0xE5D0009C, 0xE12FFF1E]),
        (0x6EF39C, [0xE0800001, 0xE5C0209C, 0xE12FFF1E]),
        (0x4C491C, [0xE5D00009, 0xE12FFF1E]),
        (0x4DB21C, [0xE3510029, 0xC3A01029, 0xE7900101, 0xEAFF8786]),
        (0x4BD048, [0xE5900004, 0xEA001E32]),
        (0x658BEC, [0xE3A01000]), (0x76D67C, [0xE3A01000]),
        (0x7DD7E8, [0xE1D000B4, 0xE12FFF1E]),
        (0x78E410, [0xE350004F, 0x1A00004B, 0xEA0000B9]),
        (0x78CEBC, [0xE590001C, 0xE3A04000, 0xE1A01004]),
        (0x78CEF0, [0xEA00000F]), (0x78CF34, [0xE3A04007]),
        (0x6C6114, [0xE5903010, 0xE3530000, 0x0280300C,
                    0xE0830081, 0xE1C020B0, 0xE12FFF1E]),
    ):
        check_words(data, {offset + 4 * i: word for i, word in enumerate(words)})
    return {
        "decoded_sha256": DECODED_SHA256,
        "address_convention": "file offsets; add 0x02000000 for main-image VA",
        "selector": {"recipe_offset": "0x44", "getter": "0x52671c", "setter": "0x73dc74",
                     "tone_recipe_pointer_offset": "0x18a18", "special_value": 6,
                     "special_producer": "0x4dd924"},
        "edges": [{"call": hex(a), "target": hex(b)} for a, b in EDGES],
        "source_paths": [
            "stored recipe byte +0x9c (parameter 0) -> 0x658bdc -> recipe word +0x44",
            "0x70145c input object +0x14 -> block +0x328 + 10*profile + parameter + 1048*bank",
            "0x76d648 family -> default profile getter 0x4db21c -> stored recipe byte +0x9c",
        ],
        "metadata_bridge": {"dispatcher": "0x78e300", "tag": "0x004f",
                            "handler": "0x78ceb4", "source_byte": "+0x9c",
                            "selector_to_tag_value": list(IMAGE_TONE),
                            "selector_6_tag_value": 7,
                            "label_inference": "Reversal Film, by Pentax ImageTone metadata mapping",
                            "label_source": "https://github.com/exiftool/exiftool/blob/9b8664dfcf2c609d3cc8925d380e98ad2a379f9b/lib/Image/ExifTool/Pentax.pm"},
        "limits": ["Selector, menu order and EXIF ImageTone are distinct numeric namespaces.",
                   "Default profile initialization does not prove the camera's active saved settings.",
                   "Reversal Film is identified through the metadata bridge, not a decoded on-screen resource.",
                   "The label of common profile ID 41 is not resolved even though its default selector is 6."],
    }


def emulate(data):
    import unicorn
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP,
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_C1_C0_2, UC_ARM_REG_FPEXC,
        UC_CPU_ARM_CORTEX_A9)
    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    vm.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    vm.mem_map(0x40400000, 0x100000)
    obj, stop = 0x10000000, 0x1000F000
    vm.mem_map(obj, 0x10000)
    vm.reg_write(UC_ARM_REG_SP, stop)
    vm.reg_write(UC_ARM_REG_C1_C0_2, 0xF00000)
    vm.reg_write(UC_ARM_REG_FPEXC, 0x40000000)

    def run(offset, r0=0, r1=0):
        vm.reg_write(UC_ARM_REG_R0, r0)
        vm.reg_write(UC_ARM_REG_R1, r1)
        vm.reg_write(UC_ARM_REG_LR, stop)
        vm.emu_start(BASE + offset, stop, count=100000)
        require(vm.reg_read(UC_ARM_REG_PC), stop, f"bounded return {offset:#x}")
        return vm.reg_read(UC_ARM_REG_R0)

    run(0x4DBC14)
    run(0x4DABD8, obj)
    rows = []
    for profile, expected in enumerate(DEFAULT_SELECTORS):
        actual = run(0x4DB21C, obj, profile)
        require(actual, expected, f"default profile {profile}")
        node = struct.unpack("<I", vm.mem_read(obj + 4 * profile, 4))[0]
        record = struct.unpack("<I", vm.mem_read(node + 4, 4))[0]
        rows.append({"profile_id": profile, "selector": actual, "record_address": hex(record)})
    # Exercise the exact store/read pair, including values outside the menu range.
    for value in (0, 5, 6, 7, 10, 41, 0xFFFFFFFF):
        run(0x73DC74, obj + 0x1000, value)
        require(run(0x52671C, obj + 0x1000), value, "selector setter/getter preserve word")
    parent, source, output = obj + 0x2000, obj + 0x3000, obj + 0x4000
    vm.mem_write(parent + 0x1C, struct.pack("<I", source))
    conversions = []
    for selector, expected in enumerate(IMAGE_TONE):
        vm.mem_write(source + 0x9C, bytes((selector,)))
        vm.mem_write(output, bytes(0x20))
        vm.mem_write(output + 4, struct.pack("<H", 0x004F))
        vm.mem_write(output + 0xC, b"\xCC\xCC")
        require(run(0x78E300, parent, output), 1, "metadata dispatcher success")
        actual = struct.unpack("<H", vm.mem_read(output + 0xC, 2))[0]
        require(actual, expected, f"ImageTone conversion for selector {selector}")
        conversions.append({"selector": selector, "tag_0x004f": actual})
    return {"engine": "Unicorn " + unicorn.__version__, "default_profiles": rows,
            "profiles_compared": len(rows), "setter_getter_cases": 7,
            "metadata_dispatcher_cases": conversions,
            "scope": "Original A32 initializers and getters; RAM-backed globals, no camera execution."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path)
    parser.add_argument("--emulate", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    data = load_image(args.image)
    result = verify(data)
    if args.emulate:
        result["numeric"] = emulate(data)
    if args.compare:
        require(result, json.loads(args.compare.read_text(encoding="utf-8")), "saved selector evidence")
    text = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
