"""Run bounded original A32/Thumb tone kernels with synthetic data in Unicorn.

SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import json
from pathlib import Path
import struct

from verify_findings import DECODED_SHA256, require, sha256
from verify_tone_path import BASE, load_image


SCRATCH = 0x10000000
STOP = SCRATCH + 0x2F000
U16 = struct.Struct("<256H")
PACKED = struct.Struct("<1280H")


def interpolate(curve, value):
    index, fraction = divmod(value, 64)
    if index >= 255:
        return curve[255]
    product = (curve[index + 1] - curve[index]) * fraction
    increment = (abs(product) // 64) * (-1 if product < 0 else 1)
    return (curve[index] + increment) & 0xFFFF


def s16(value):
    return (value + 0x8000) % 0x10000 - 0x8000


def expand(curve):
    result = []
    for index, first in enumerate(curve):
        second = curve[min(index + 1, 255)]
        for lane in range(4):
            step = s16((s16(second) - s16(first)) * lane) >> 2
            result.append(max(0, min(0x4000, s16(first + step))))
    return tuple(result) + (curve[255],) * 256


def synthetic_curves():
    return {
        "mixed ascending": tuple((i * 61 + i % 9) for i in range(256)),
        "descending": tuple(0x3FFF - i * 63 for i in range(256)),
        "alternating endpoints": tuple(0x4000 if i % 2 else 0 for i in range(256)),
        "unsigned stress": tuple((i * 3511 + i * i) & 0xFFFF for i in range(256)),
    }


def verify_apply(vm, run, object_reg, stack_reg):
    """Emulate the complete apply routine with device addresses backed by RAM."""
    register_base = 0x20020000
    first_bank = 0x20A21000
    vm.mem_map(register_base, 0x1000)
    vm.mem_map(0x20A00000, 0x25000)
    obj = SCRATCH + 0x4000
    descriptor = SCRATCH + 0x1000
    vm.mem_write(obj + 0x208, struct.pack("<I", descriptor))
    controls = bytearray(0x94)
    controls[0] = 1
    controls[0x10] = 1
    controls[0x14] = 1
    controls[0x1C] = 3
    controls[0x1E] = 2
    controls[0x20] = 5
    controls[0x21] = 1
    controls[0x22] = 0x3F
    struct.pack_into("<3I", controls, 4, 0x1234, 0x5678, 0x9ABC)
    vm.mem_write(descriptor, bytes(controls))
    additional = bytes(range(32))
    vm.mem_write(obj + 0x20C, additional)
    vm.mem_write(obj + 0x18A22, struct.pack("<H", len(additional) // 4))
    curves = [bytes((j * (3 + i * 2) + i * 53) % 256 for j in range(0x1000)) for i in range(4)]
    for i, curve in enumerate(curves):
        vm.mem_write(obj + 0x1420C + i * 0x1000, curve)

    sentinel = b"\xCC" * 0x1000
    initial_word = 0xA5A5A5A5
    expected_words = (
        (initial_word & ~0x03030003) | 0x00030001,
        (initial_word & ~0x3F010333) | 0x3F010123,
        (initial_word & ~0x0FFF0FFF) | 0x06780234,
        (initial_word & ~0x00000FFF) | 0x00000ABC,
    )
    results = []
    for size in (0xA00, 0x1000):
        vm.mem_write(register_base + 0x800, struct.pack("<4I", *(initial_word,) * 4))
        vm.mem_write(0x20A00000, sentinel)
        vm.mem_write(first_bank, sentinel * 4)
        vm.mem_write(obj + 0x18A2C, b"\x01")
        vm.mem_write(obj + 0x18A64, b"\x01" + bytes((size == 0x1000,)))
        vm.reg_write(object_reg, obj)
        vm.reg_write(stack_reg, STOP)
        run(0x4DDE3C)

        words = struct.unpack("<4I", vm.mem_read(register_base + 0x800, 16))
        require(words, expected_words, "applied TGCTL/TCTBLCTL/TCYC words")
        data = bytes(vm.mem_read(0x20A00000, len(sentinel)))
        require(data == additional + sentinel[len(additional):], True, "additional table copy and extent")
        for i, curve in enumerate(curves):
            data = bytes(vm.mem_read(first_bank + i * 0x1000, len(sentinel)))
            require(data == curve[:size] + sentinel[size:], True, f"curve bank {i} copy and extent")
        require(bytes(vm.mem_read(obj + 0x18A64, 2)), b"\x00\x00", "cleared curve flags")
        require(bytes(vm.mem_read(obj + 0x18A2C, 1)), b"\x00", "cleared additional table flag")
        results.append({"curve_banks": 4, "bytes_per_curve_bank": size,
                        "additional_copy_bytes": len(additional), "register_words_compared": len(words)})
    return results

def verify_numeric(data):
    import unicorn
    from unicorn.arm_const import (
        UC_ARM_REG_C1_C0_2, UC_ARM_REG_FPEXC, UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_SP,
        UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R4, UC_CPU_ARM_CORTEX_A9,
    )

    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    vm.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    vm.mem_map(SCRATCH, 0x30000)
    vm.mem_map(0x4040B000, 0x1000)
    vm.reg_write(UC_ARM_REG_SP, STOP)
    vm.reg_write(UC_ARM_REG_C1_C0_2, 0xF00000)
    vm.reg_write(UC_ARM_REG_FPEXC, 0x40000000)

    def run(entry, until=STOP, count=100000):
        vm.reg_write(UC_ARM_REG_LR, STOP)
        vm.emu_start(BASE + entry, until, count=count)
        require(vm.reg_read(UC_ARM_REG_PC), until, f"bounded kernel stop from {entry:#x}")

    # Execute the firmware initializer for SIMD interpolation weights/clamps.
    run(0x4DE1F4)
    checks = []
    for label, curve in synthetic_curves().items():
        vm.mem_write(SCRATCH, U16.pack(*curve))
        values = []
        for sample in range(0x10000):
            vm.reg_write(UC_ARM_REG_R1, SCRATCH)
            vm.reg_write(UC_ARM_REG_R2, sample)
            run(0x4DD3EC, count=32)
            actual = vm.reg_read(UC_ARM_REG_R0)
            require(actual, interpolate(curve, sample), f"{label} interpolation at {sample:#x}")
            values.append(actual)
        checks.append({"case": label, "kernel": "interpolation", "outputs_compared": len(values),
                       "sha256": sha256(struct.pack("<65536H", *values))})

        vm.reg_write(UC_ARM_REG_R1, SCRATCH)
        vm.reg_write(UC_ARM_REG_R2, SCRATCH + 0x1000)
        run(0x4DC910)
        actual = bytes(vm.mem_read(SCRATCH + 0x1000, PACKED.size))
        require(actual == PACKED.pack(*expand(curve)), True, f"{label} NEON expansion")
        checks.append({"case": label, "kernel": "NEON expansion including Thumb fill",
                       "outputs_compared": 1280, "sha256": sha256(actual)})

    # Compose three independent curves and their weighted companion in one original loop.
    curves = tuple(synthetic_curves().values())[:3]
    samples = (
        tuple(i * 64 + i % 64 for i in range(256)),
        tuple((255 - i) * 64 + i % 64 for i in range(256)),
        tuple((i * 563) & 0xFFFF for i in range(256)),
    )
    stack = SCRATCH + 0x2E000
    obj = SCRATCH + 0x4000
    for i, (curve, source, offset) in enumerate(zip(curves, samples, (0x1820C, 0x1840C, 0x1860C))):
        pointer = SCRATCH + i * U16.size
        vm.mem_write(pointer, U16.pack(*curve))
        vm.mem_write(stack + 0x814 + 4 * i, struct.pack("<I", pointer))
        vm.mem_write(obj + offset, U16.pack(*source))
    vm.reg_write(UC_ARM_REG_R0, SCRATCH + 2 * U16.size)
    vm.reg_write(UC_ARM_REG_R4, obj)
    vm.reg_write(UC_ARM_REG_SP, stack)
    run(0x4DD4F0, until=BASE + 0x4DD5A8)
    expected = [[interpolate(curve, x) for x in source] for curve, source in zip(curves, samples)]
    expected.append([(77*r + 150*g + 29*b) >> 8 for r, g, b in zip(*expected)])
    actual = b"".join(bytes(vm.mem_read(stack + offset, U16.size)) for offset in (0x600, 0, 0x200, 0x400))
    require(actual == b"".join(U16.pack(*curve) for curve in expected), True, "four-curve composition")
    checks.append({"case": "distinct source curves and samples", "kernel": "four-curve composition",
                   "outputs_compared": 1024, "sha256": sha256(actual)})
    return {
        "schema_version": 1, "decoded_sha256": DECODED_SHA256, "engine": f"Unicorn {unicorn.__version__}",
        "emulated_cpu": "Cortex-A9", "checks": checks,
        "outputs_compared": sum(row["outputs_compared"] for row in checks),
        "apply_checks": verify_apply(vm, run, UC_ARM_REG_R0, UC_ARM_REG_SP),
        "limits": ["Synthetic data, original instructions, no camera execution.",
                   "Base curve producers are outside numeric replay. Device addresses are backed by synthetic RAM.",
                   "The NEON expansion check includes the original Thumb fill helper."],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    try:
        result = verify_numeric(load_image(args.decoded))
        if args.compare:
            require(result, json.loads(args.compare.read_text(encoding="utf-8")), "tone numeric snapshot")
    except (ImportError, OSError, ValueError) as error:
        parser.exit(1, f"tone numeric verification failed: {error}\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
