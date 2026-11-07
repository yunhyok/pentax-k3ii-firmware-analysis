"""Run the original K-3 II WB and matrix instructions with synthetic records.

SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import json
from pathlib import Path
import random
import struct

from verify_findings import DECODED_SHA256, require, sha256
from verify_isp_paths import B2Y, WB_REGISTER_ORDER
from verify_tone_path import BASE, load_image


SCRATCH = 0x10000000
STOP = SCRATCH + 0xF000
SP = STOP - 0x1000
OBJ = SCRATCH + 0x1000
DESCRIPTOR = SCRATCH + 0x2000
RECORD = SCRATCH + 0x3000
H9 = struct.Struct("<9h")


def s16(value):
    return (value + 0x8000) % 0x10000 - 0x8000


def compose(left, right):
    return tuple(s16((sum(left[3*i+k] * right[3*k+j] for k in range(3)) + 4096) // 8192)
                 for i in range(3) for j in range(3))


def clamp_coefficient(value):
    return max(-2048, min(2047, s16(value)))


def prepare_cc0(first, second, gain, selector):
    multipliers = (64, 91, 128, 181, 256)
    factor = gain * (multipliers[selector] if selector < len(multipliers) else 128) // 256
    scaled = [s16((abs(value) * factor // 4096) * (-1 if value < 0 else 1))
              for value in compose(first, second)]
    for i in (0, 4, 8):
        row = i // 3
        scaled[i] = 2 * factor - sum(scaled[j] for j in range(3*row, 3*row+3) if j != i)
    return tuple(map(clamp_coefficient, scaled))


def field(buf, offset, shift, width, value):
    old = struct.unpack_from("<I", buf, offset)[0]
    mask = (1 << width) - 1
    struct.pack_into("<I", buf, offset, (old & ~(mask << shift)) | ((value & mask) << shift))


def verify_numeric(data):
    import unicorn
    from unicorn.arm_const import (
        UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
        UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R8, UC_CPU_ARM_CORTEX_A9,
    )

    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    vm.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    vm.mem_map(SCRATCH, 0x30000)
    vm.mem_map(B2Y, 0x1000)
    rng = random.Random(0x0312)
    seed = bytes(rng.randrange(256) for _ in range(0x1000))

    def write(addr, fmt, *values):
        vm.mem_write(addr, struct.pack("<" + fmt, *values))

    def read(addr, fmt):
        return struct.unpack("<" + fmt, vm.mem_read(addr, struct.calcsize("<" + fmt)))

    def run(entry, *args, end=None, registers=()):
        vm.reg_write(UC_ARM_REG_SP, SP)
        vm.reg_write(UC_ARM_REG_LR, STOP)
        for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            vm.reg_write(reg, value)
        for reg, value in registers:
            vm.reg_write(reg, value)
        until = STOP if end is None else BASE + end
        vm.emu_start(BASE + entry, until, count=20000)
        require(vm.reg_read(UC_ARM_REG_PC), until, f"bounded execution from {entry:#x}")

    def check_mmio(expected, label):
        actual = bytes(vm.mem_read(B2Y, len(seed)))
        if actual != expected:
            delta = [(hex(i), actual[i:i+4].hex(), expected[i:i+4].hex()) for i in range(0, len(seed), 4)
                     if actual[i:i+4] != expected[i:i+4]]
            raise ValueError(f"{label} MMIO differences (offset, actual LE, expected LE): {delta[:12]}")
        return sha256(actual)

    wb_cases = []
    for label, gains, offsets in (
        ("zero and edge", (0, 1, 0x7FF, 0x800), (0, 1, 0x3FFF, 0x4000)),
        ("out of field", (0xFFFF, 0x100, 0x1234, 0x0101), (0xFFFF, 0x7FFF, 0x8000, 0x3FFE)),
        ("quantizer boundaries", (0x1F, 0x20, 0x7FFF, 0xFFE0), (0x8001, 0x2000, 0x2001, 0x1FFF)),
        ("distinct channels", (0xB31D, 0x817, 0x260D, 0x707), (1, 5, 11, 23)),
    ):
        write(OBJ+0x30, "I", OBJ)
        write(OBJ+0xBF4, "I", OBJ)
        write(DESCRIPTOR+0x94, "I", RECORD)
        write(RECORD, "8H", *gains, *offsets)
        write(SP+4, "I", DESCRIPTOR)
        write(OBJ+0x36C+0x3A, "4H", *gains)

        vm.mem_write(B2Y, seed)
        run(0x57BD28, end=0x57BE78, registers=((UC_ARM_REG_R4, OBJ), (UC_ARM_REG_R8, 0)))
        expected = bytearray(seed)
        for i, channel in enumerate(WB_REGISTER_ORDER):
            gain, offset = gains[channel], offsets[channel]
            field(expected, 0x80 + 4*(i//2), 16*(i%2), 14, -offset)
            field(expected, 0x8C + 4*(i//2), 16*(i%2), 11, gain)
        wb_cases.append({"case": label, "path": "descriptor offset and gain", "mmio_sha256": check_mmio(expected, label)})

        vm.mem_write(B2Y, seed)
        run(0x626468, end=0x6264E0, registers=((UC_ARM_REG_R4, OBJ),))
        expected = bytearray(seed)
        for i, channel in enumerate(WB_REGISTER_ORDER):
            field(expected, 0x8C + 4*(i//2), 16*(i%2), 11, gains[channel] // 32)
        wb_cases.append({"case": label, "path": "right-shift gain", "mmio_sha256": check_mmio(expected, label)})

    boundary = (-32768, -2049, -2048, -2047, -1, 0, 2047, 2048, 32767)
    write(RECORD, "9h", *boundary)
    run(0x4C2720, end=0x4C2760, registers=((UC_ARM_REG_R3, RECORD), (UC_ARM_REG_R4, OBJ),
                                          (UC_ARM_REG_R5, 0x7FF), (UC_ARM_REG_R6, 0xF800)))
    boundary_expected = (-2048, -2048, -2048, -2047, -1, 0, 2047, 2047, 2047)
    require(read(OBJ+0xC, "9h"), boundary_expected, "signed coefficient clipping boundaries")

    products = (
        ("rounding", (1, 0, 0, -1, 0, 0, 0, 0, 0), (4095, 4096, 4097) + (0,) * 6),
        ("32-bit accumulator wrap", (32767,) * 9, (32767,) * 9),
        ("negative accumulator wrap", (-32768,) * 9, (32767,) * 9),
    )
    product_cases = []
    for label, left, right in products:
        write(RECORD, "9h", *left)
        write(RECORD+0x20, "9h", *right)
        run(0x4C24D4, OBJ, RECORD+0x40, RECORD, RECORD+0x20)
        actual = read(RECORD+0x40, "9h")
        require(actual, compose(left, right), f"original matrix product: {label}")
        product_cases.append({"case": label, "outputs": list(actual)})

    cc0_extra = H9.unpack_from(data, 0xA2C6AE)
    yc_right = H9.unpack_from(data, 0xA2C6C0)
    eye = (8192, 0, 0, 0, 8192, 0, 0, 0, 8192)
    matrix_cases = []
    for i, (gain, selector) in enumerate(((256, 0), (256, 1), (256, 2), (256, 3), (256, 4), (256, 5),
                                          (0, 2), (4096, 4), (65535, 4), (65535, 0xFFFF))):
        vm.mem_write(OBJ, b"\0" * 0x400)
        left = eye if i < 6 else tuple(rng.randrange(-32768, 32768) for _ in range(9))
        right = tuple(rng.randrange(-32768, 32768) for _ in range(9))
        third = eye if i < 6 else tuple(rng.randrange(-32768, 32768) for _ in range(9))
        cc1 = tuple(rng.randrange(-32768, 32768) for _ in range(9))
        clip = (0, 0xFFFF, 0x7FFF, 0x8000, 0x8001, 0x1)
        write(RECORD, "9h", *left)
        write(RECORD+0x20, "9h", *right)
        write(RECORD+0x40, "9h", *third)
        write(RECORD+0x60, "9h", *cc1)
        write(RECORD+0x80+4*i, "I", RECORD)
        write(RECORD+0xC0+4*i, "I", RECORD+0x20)
        write(DESCRIPTOR+0x04, "3I", RECORD+0x40, RECORD+0x20, RECORD+0x80)
        write(DESCRIPTOR+0x1C, "I", RECORD+0xC0)
        write(DESCRIPTOR+0x8C, "I", RECORD+0x60)
        write(DESCRIPTOR+0x88, "2B", i % 2, 0x81+i)
        for offset in (0x20, 0x7C, 0x90):
            write(DESCRIPTOR+offset, "6H", *clip)
        write(DESCRIPTOR+0x10, "5H", 0x1234, 0x2345, 0xABCD, clip[4], clip[1])
        write(OBJ+0x1E0, "I", DESCRIPTOR+0x7C)
        write(OBJ+0x1FC, "B", i % 2)
        write(OBJ+0x210, "2H", gain, selector)

        run(0x4C2598, OBJ, DESCRIPTOR, i)
        temp = compose(left, right)
        require(read(OBJ+0x1FE, "9h"), temp, "original 3x3 signed product")
        if i % 2:
            temp = compose(cc0_extra, temp)
        cc0 = prepare_cc0(temp, third, gain, selector)
        require(read(OBJ+0xC, "9h"), cc0, "original CC0 coefficients")
        require(read(OBJ+0x20, "I"), (DESCRIPTOR+0x10,), "CCYC record pointer")

        run(0x4C255C, OBJ, DESCRIPTOR, i)
        yc = compose(right, yc_right)
        require(read(OBJ+0x24, "9h"), yc, "original YC coefficients")
        require(read(OBJ+0x38, "I"), (DESCRIPTOR+0x20,), "YC_CLP record pointer")

        run(0x4C2158, OBJ, DESCRIPTOR)
        cc1_disabled = i % 2
        if not cc1_disabled:
            require(read(OBJ+0x1E6, "9h"), cc1, "original CC1 coefficient copy")
            require(read(OBJ+0x1F8, "I"), (DESCRIPTOR+0x90,), "CC1_CLP record pointer")

        vm.mem_write(B2Y, seed)
        run(0x4C2C18, OBJ)
        expected = bytearray(seed)
        field(expected, 0x100, 0, 1, 0)
        field(expected, 0x100, 4, 2, 1)
        field(expected, 0x880, 0, 1, cc1_disabled)
        if not cc1_disabled:
            field(expected, 0x880, 4, 2, 0x81+i)
        field(expected, 0x400, 0, 1, 0)
        for j, value in enumerate((0x1234, 0x2345, 0xABCD)):
            field(expected, 0x140, j*8, 8, value)
        field(expected, 0x144, 0, 15, clip[4])
        field(expected, 0x144, 16, 16, clip[1])
        matrix_registers = [(0x120, 12, cc0), (0x900, 13, yc)]
        clip_registers = [0x920, 0x78C]
        if not cc1_disabled:
            matrix_registers.append((0x8A0, 12, cc1))
            clip_registers.append(0x8C0)
        for first, width, coefficients in matrix_registers:
            for j, value in enumerate(coefficients):
                field(expected, first + 4*(j//2), 16*(j%2), width, value)
        for first in clip_registers:
            for j, value in enumerate(clip):
                field(expected, first + 4*(j//2), 16*(j%2), 15 if j % 2 == 0 else 16, value)

        matrix_cases.append({
            "factor_selector": selector, "gain_input": gain, "cc1_bypass_bit": cc1_disabled,
            "CC0_coefficients": list(cc0), "mmio_sha256": check_mmio(expected, f"matrix apply {i}"),
        })

    tone_obj = SCRATCH+0x10000
    clip_pairs = (
        (0xFFFF8000, 0x12345678), (0x10007FFF, 0x10000),
        (0x00018001, 0x7FFF8000), (0xFFFFFFFF, 0xFFFFFFFF),
    )
    write(tone_obj+0x208, "I", DESCRIPTOR)
    controls = bytearray(0x94)
    struct.pack_into("<3I", controls, 4, 0x1234, 0x5678, 0x9ABC)
    for i, pair in enumerate(clip_pairs):
        struct.pack_into("<2I", controls, 0x74+8*i, *pair)
    vm.mem_write(DESCRIPTOR, bytes(controls))
    vm.mem_write(B2Y, seed)
    run(0x4DDE3C, tone_obj)
    expected = bytearray(seed)
    # This fixture disables the optional bank uploads. The rest of apply still runs.
    for bit in (0, 1, 16, 17, 24, 25):
        field(expected, 0x800, bit, 1, 0)
    for shift, width in ((0, 2), (4, 2), (8, 2), (16, 1), (24, 6)):
        field(expected, 0x804, shift, width, 0)
    field(expected, 0x808, 0, 12, 0x1234)
    field(expected, 0x808, 16, 12, 0x5678)
    field(expected, 0x80C, 0, 12, 0x9ABC)
    for first in (0x810, 0x828, 0x840, 0x858):
        field(expected, first, 0, 18, 0)
        field(expected, first+4, 0, 18, 0)
        field(expected, first+8, 0, 26, 0)
        field(expected, first+12, 0, 26, 0)
        field(expected, first+16, 0, 16, 0x1000 if first in (0x810, 0x840) else 0)
    for i, (low, high) in enumerate(clip_pairs):
        field(expected, 0x86C+4*i, 0, 15, low)
        field(expected, 0x86C+4*i, 16, 16, high)
    tone_clip_case = {
        "entry": 0x4DDE3C, "descriptor_u32_pairs": [list(pair) for pair in clip_pairs],
        "TC_CLP_words": list(read(B2Y+0x86C, "4I")),
        "mmio_sha256": check_mmio(expected, "tone clip apply"),
    }

    return {
        "schema_version": 1, "decoded_sha256": DECODED_SHA256, "unicorn_version": unicorn.__version__,
        "cpu": "Cortex-A9 emulator model", "wb_cases": wb_cases, "matrix_cases": matrix_cases,
        "clamp_boundary": {"input": list(boundary), "output": list(boundary_expected)},
        "matrix_product_cases": product_cases, "tone_clip_case": tone_clip_case,
        "scope": {
            "mmio_bytes_compared_per_case": len(seed),
            "wb_instruction_spans": ["0x57bd28..0x57be78", "0x626468..0x6264e0"],
            "matrix_entries": ["0x4c2598 CC0 prepare", "0x4c255c YC prepare", "0x4c2158 CC1 prepare", "0x4c2c18 apply"],
            "clamp_instruction_span": "0x4c2720..0x4c2760",
        },
        "limits": [
            "Synthetic records and RAM-backed registers. No physical ISP, frame or camera execution.",
            "Tone clipping runs through full apply with upload flags clear; separate tone verification covers the uploads.",
            "WB caller fragments are seeded at valid internal entry points; upstream estimation is untested.",
            "CC1 bypass and active paths are covered; the MC apply branch after its clip setters is disabled.",
            "The signed coefficient clamp is CPU behavior. The pixel comparison and transfer function remain unknown.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded_image", type=Path)
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--output", type=Path)
    output.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = verify_numeric(load_image(args.decoded_image))
    serialized = json.dumps(result, indent=2) + "\n"
    if args.compare:
        require(result, json.loads(args.compare.read_text(encoding="utf-8")), "ISP numeric evidence")
        print(f"ISP numeric evidence matches {args.compare}")
    elif args.output:
        args.output.write_text(serialized, encoding="utf-8", newline="\n")
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()
