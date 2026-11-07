"""Run the isolated original A32 sample loop with synthetic memory (Unicorn 2.1.4).

SPDX-License-Identifier: GPL-2.0-only
No camera, peripherals, or surrounding RAW workflow are emulated.
"""
import argparse
import json
from pathlib import Path
import random
import struct
from verify_findings import DECODED_SHA256, require, sha256


def verify(data):
    import unicorn
    from unicorn import arm_const as arm
    require(sha256(data), DECODED_SHA256, "decoded identity")
    cpu = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    cpu.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    cpu.mem_map(0x0252A000, 0x1000, unicorn.UC_PROT_READ | unicorn.UC_PROT_EXEC)
    cpu.mem_write(0x0252A000, data[0x52A000:0x52B000])
    for page in [0x60000000, 0x61000000, 0x70000000]:
        cpu.mem_map(page, 0x1000)
    rng = random.Random(230)
    cases = [[], [0], [1, 0x3FFF, 0x4000, 0x7FFF, 0xFFFF],
             [rng.randrange(65536) for _ in range(257)]]
    results = []
    for values in cases:
        raw = struct.pack(f"<{len(values)}H", *values)
        cpu.mem_write(0x60000000, raw + b"\xa5" * 16)
        cpu.mem_write(0x61000000, b"\xa5" * (len(raw) + 16))
        cpu.mem_write(0x70000018, struct.pack("<I", 0x61000000))
        for reg, value in [(arm.UC_ARM_REG_SP, 0x70000000), (arm.UC_ARM_REG_R11, 0x60000000),
                           (arm.UC_ARM_REG_R3, len(values))]:
            cpu.reg_write(reg, value)
        cpu.emu_start(0x0252AE94, 0x0252AEC0, timeout=1_000_000, count=10000)
        require(cpu.reg_read(arm.UC_ARM_REG_PC), 0x0252AEC0, "bounded loop completion")
        output = bytes(cpu.mem_read(0x61000000, len(raw)))
        expected = struct.pack(f"<{len(values)}H", *[(v << 2) & 65535 for v in values])
        require(output, expected, "original A32 output")
        require(bytes(cpu.mem_read(0x61000000 + len(raw), 16)), b"\xa5" * 16, "destination sentinel")
        require(bytes(cpu.mem_read(0x60000000, len(raw) + 16)), raw + b"\xa5" * 16, "source unchanged")
        results.append({"samples": len(values), "input_sha256": sha256(raw), "output_sha256": sha256(output)})
    return {"decoded_sha256": sha256(data), "engine": f"Unicorn {unicorn.__version__}",
            "cpu_model": "Cortex-A9 selected for isolated A32 execution; not hardware identification",
            "range": [0x0252AE94, 0x0252AEC0], "cases_passed": len(cases),
            "samples_checked": sum(map(len, cases)), "results": results,
            "scope": "Synthetic loop only; camera pipeline and MMIO not executed"}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    with args.decoded.open("rb") as stream:
        result = verify(stream.read(16_838_657))
    if args.compare:
        require(result, json.loads(args.compare.read_text(encoding="utf-8")), "published numeric evidence")
    print(json.dumps(result, indent=2))
