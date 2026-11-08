"""Reproduce bounded static K-3 II v1.12 observations; never execute firmware.

SPDX-License-Identifier: GPL-2.0-only
Offsets in this report are decoded-file offsets unless explicitly named addresses.
The decoder preserves file size and offsets. CPU/OS identification remains static.
"""

import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import re
import struct

DECODED_SHA256 = "1b87bf35b290e4b4e8910beb4055c34f97504b65e249ad65e5ccc0402bd14cfc"
INPUT_SHA256 = "a33485f351019960192891ef69ddc5d4904ef9e298671d9d9955679e4c901a9a"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def u32(data, offset):
    if not 0 <= offset <= len(data) - 4:
        raise ValueError("word outside input")
    return struct.unpack_from("<I", data, offset)[0]


def literal_offset(data, offset):
    """Resolve one unconditional ARM LDR register,[PC,+/-imm12] file location."""
    word = u32(data, offset)
    if word & 0xFF7F0000 != 0xE51F0000:
        raise ValueError("not an unconditional ARM PC-relative word load")
    target = offset + 8 + ((word & 0xFFF) if word & 0x800000 else -(word & 0xFFF))
    u32(data, target)
    return target


def entropy(data):
    if not data:
        return 0.0
    return -sum((n / len(data)) * math.log2(n / len(data)) for n in Counter(data).values())


def require(actual, expected, context):
    if actual != expected:
        raise ValueError(f"{context}: expected {expected!r}, got {actual!r}")


def require_snapshot(actual, snapshot, context):
    """Compare a report to its JSON snapshot without coercing scalar types."""
    expected = json.loads(snapshot.read_text(encoding="utf-8"))
    # Normalize tuples and object keys as they appear in the exported JSON.
    actual = json.loads(json.dumps(actual))
    if json.dumps(actual, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise ValueError(f"{context}: snapshot differs from {snapshot}")


def analyze(data):
    require(sha256(data), DECODED_SHA256, "decoded firmware identity")
    require(len(data), 16_838_656, "decoded length")
    reset_pointer_offset = literal_offset(data, 0)
    reset_address = u32(data, reset_pointer_offset)
    base = reset_address - 0x200
    require(base, 0x02000000, "candidate image base")
    # Fixed-word checks bind the interpretation to the actual CP15/AND/CMP path.
    for offset, word in [(0x20C, 0xEE100F10), (0x210, 0xE59F1240), (0x214, 0xE5911000),
                         (0x218, 0xE0001001), (0x21C, 0xE59F0238), (0x220, 0xE5900000),
                         (0x224, 0xE1510000), (0x228, 0x1A00007C)]:
        require(u32(data, offset), word, f"startup instruction {offset:#x}")
    mask_ptr = literal_offset(data, 0x210)
    part_ptr = literal_offset(data, 0x21C)
    mask_offset = u32(data, mask_ptr) - base
    part_offset = u32(data, part_ptr) - base
    mask, expected = u32(data, mask_offset), u32(data, part_offset)
    require((mask_offset, part_offset, mask, expected), (0x448, 0x44C, 0xFFF0, 0xC090), "MIDR comparison")
    vectors = []
    for offset, label in [(0, "reset"), (4, "undefined"), (8, "SVC"),
                          (12, "prefetch abort"), (16, "data abort"), (28, "FIQ")]:
        require(u32(data, offset), 0xE59FF018, f"LDR PC vector {offset:#x}")
        pointer_offset = literal_offset(data, offset)
        address = u32(data, pointer_offset)
        target = address - base
        if not 0 <= target < 0x1000000:
            raise ValueError("vector outside candidate main-image mapping")
        vectors.append({"name": label, "vector_offset": offset, "pointer_offset": pointer_offset,
                        "target_address": address, "target_file_offset": target,
                        "target_first_16_sha256": sha256(data[target:target + 16])})
    require(u32(data, 0x18), 0xEA000009, "IRQ relative branch to file offset 0x44")
    require(u32(data, 0x2EC154), 0xE92D5008, "undefined exception handler prologue")
    seeds = []
    for name, marker in [("T-Kernel name", b"T-Kernel\0"),
                         ("T-Kernel diagnostic", b"T-Kernel/OS SVC in execution\0"),
                         ("RAW development diagnostic", b"Allocate ERR! in DevelopmentRawImage()\n\0"),
                         ("tone/gamma diagnostic", b"#### CColorInterpolationDriver::DumpToneGamma() ####\n\0"),
                         ("AF diagnostic", b"/////CalcMoveObjectDriveDefocusError/////\n\0"),
                         ("HDMI resource name", b"HdmiOutputSet\0"),
                         ("secondary header", b"PENTAX K-3MC   \0")]:
        offsets = [m.start() for m in re.finditer(re.escape(marker), data)]
        if not offsets:
            raise ValueError(f"missing seed: {name}")
        seeds.append({"name": name, "text": marker.rstrip(b"\0\n").decode(), "offsets": offsets,
                      "length_with_nul": len(marker), "sha256_with_nul": sha256(marker),
                      "interpretation": "literal/diagnostic evidence only; no runtime behavior established"})
    hdmi = next(row["offsets"][0] for row in seeds if row["name"] == "HDMI resource name")
    refs = [m.start() for m in re.finditer(re.escape(struct.pack("<I", base + hdmi)), data) if m.start() % 4 == 0]
    require(refs, [0x9B56F4, 0x9B5708, 0x9B5834, 0x9B5960], "HDMI string pointer corroboration")
    absent = {m.decode(): len(list(re.finditer(re.escape(m), data)))
              for m in [b"Linux version", b"SC2000", b"milbeaut", b"SHELLCMD", b"Cortex"]}
    return {"schema_version": 1, "analysis_date": "2026-11-07", "decoded_size": len(data),
            "decoded_sha256": sha256(data), "offset_space": "decoded file, same offsets as input",
            "candidate_main_image_base": base, "reset_target_address": reset_address,
            "vectors": vectors, "irq_branch_target_offset": 0x44,
            "midr_check": {"instruction_range": [0x20C, 0x22C], "range_sha256": sha256(data[0x20C:0x22C]),
                           "mask_pointer_literal_offset": mask_ptr, "expected_pointer_literal_offset": part_ptr,
                           "mask_offset": mask_offset, "expected_offset": part_offset,
                           "mask": mask, "expected_masked_value": expected, "part_number": expected >> 4,
                           "inference": "Startup distinguishes a Cortex-A9 part-number path (0xC09); live MIDR and exact SoC unobserved."},
            "ascii_runs_min_length_6": sum(1 for _ in re.finditer(rb"[ -~]{6,}", data)),
            "seeds": seeds, "hdmi_pointer_offsets": refs, "bounded_exact_marker_counts": absent,
            "main_region_sha256": sha256(data[:0x1000000]),
            "secondary_region_size": len(data) - 0x1000000,
            "secondary_region_sha256": sha256(data[0x1000000:]),
            "entropy_bits_per_byte": round(entropy(data), 6),
            "entropy_windows_64k": [{"offset": o, "length": len(data[o:o + 65536]),
                                     "bits_per_byte": round(entropy(data[o:o + 65536]), 6)}
                                    for o in range(0, len(data), 65536)],
            "limitations": ["Static analysis only; no camera execution or flashing.",
                            "A pointer-consistent candidate base is not a complete physical/runtime memory map.",
                            "Cortex-A9 part comparison does not identify silicon package, core count or clock.",
                            "T-Kernel strings support a software-family lead, not a verified OS version.",
                            "No named-record/LZ layout is transferred from K-3 Mark III.",
                            "Zero marker counts mean absence of these exact byte strings only.",
                            "Secondary region ISA and role remain unclassified."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path, help="compare with a published JSON observation snapshot")
    args = parser.parse_args()
    try:
        with args.decoded.open("rb") as stream:
            result = analyze(stream.read(16_838_657))
        if args.compare:
            require_snapshot(result, args.compare, "published evidence")
    except (OSError, ValueError) as error:
        parser.exit(1, f"verification failed: {error}\n")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
