"""Verify bounded static RAW-development observations in K-3 II v1.12.

SPDX-License-Identifier: GPL-2.0-only
Names not present as symbols are analyst labels. All ranges are file offsets.
"""
import argparse
import json
from pathlib import Path
from verify_findings import DECODED_SHA256, require, sha256, u32

BASE = 0x02000000


def branch_target(data, offset):
    word = u32(data, offset)
    if word & 0x0E000000 != 0x0A000000 or word >> 28 == 15:
        raise ValueError("not an A32 B/BL instruction")
    displacement = word & 0xFFFFFF
    if displacement & 0x800000:
        displacement -= 0x1000000
    return offset + 8 + displacement * 4


def analyze(data):
    require(sha256(data), DECODED_SHA256, "decoded identity")
    require(u32(data, 0x529664), 0xE92D4FF7, "RAW entry prologue")
    require(u32(data, 0x52ADF4), 0xE28F0E36, "diagnostic ADR")
    marker = b"Allocate ERR! in DevelopmentRawImage()\n\0"
    require(data[0x52B15C:0x52B15C + len(marker)], marker, "RAW diagnostic")
    links = [
        (0x68F928, 0x529664, "caller 1"), (0x690554, 0x529664, "caller 2"),
        (0x691040, 0x529664, "caller 3"), (0x692098, 0x529664, "caller 4"),
        (0x52ADB8, 0x70C56C, "allocation candidate"),
        (0x52ADC0, 0x52ADF4, "zero result to error diagnostic"),
        (0x52ADF8, 0x7073EC, "diagnostic formatter"),
        (0x52AE44, 0x52B51C, "failure to common epilogue"),
        (0x52AE64, 0x52AEC0, "nonzero flags bypass sample conversion"),
        (0x52AF48, 0x6DB894, "invoke controller wrapper"), (0x52B104, 0x6DB894, "invoke controller wrapper"),
        (0x52B114, 0x6DB894, "invoke controller wrapper"), (0x52B124, 0x6DB894, "invoke controller wrapper"),
        (0x52B134, 0x6DB894, "invoke controller wrapper"),
        (0x6DB8C4, 0x5A11F8, "set pending state"),
        (0x6DB8D0, 0x6DB888, "signal wrapper"),
        (0x6DB890, 0x70C3CC, "signal object at controller+0x340"),
    ]
    edges = []
    for source, target, meaning in links:
        require(branch_target(data, source), target, meaning)
        edges.append({"instruction_address": BASE + source, "target_address": BASE + target,
                      "instruction_word": f"0x{u32(data, source):08x}", "label": meaning})
    for offset, word in [(0x52AE60, 0xE19A0009), (0x52AEA4, 0xE1D220B0),
                         (0x52AEB0, 0xE1A02102), (0x52AEB4, 0xE1C720B0),
                         (0x72D324, 0xE58010C8), (0x72D338, 0xE58010D0),
                         (0x72D344, 0xE58010C4), (0x72D350, 0xE1C01ABE)]:
        require(u32(data, offset), word, f"instruction {offset:#x}")
    ranges = [("development orchestrator", 0x529664, 0x52B540),
              ("conditional sample loop", 0x52AE94, 0x52AEC0),
              ("controller handoff", 0x6DB894, 0x6DB8D4),
              ("pending state", 0x5A11F8, 0x5A1234),
              ("job link setters", 0x72D320, 0x72D358)]
    return {"analysis_date": "2026-11-08", "decoded_sha256": sha256(data), "base": BASE,
            "entry_address": BASE + 0x529664, "name_evidence": "inline DevelopmentRawImage diagnostic",
            "edges": edges, "ranges": [{"label": label, "file_start": a, "file_end_exclusive": z,
                                          "sha256": sha256(data[a:z])} for label, a, z in ranges],
            "conditional_sample_loop": {"start_address": BASE + 0x52AE94, "stop_address": BASE + 0x52AEC0,
                                        "formula": "dst[i] = (src_u16[i] << 2) & 0xffff",
                                        "guard": "r10 | r9 == 0 at 0x0252ae60; both values originate earlier",
                                        "input_bit_depth": "not established by this loop alone"},
            "job_fields": {"0x20c8": "link set by 0x0272d320", "0x20d0": "link set by 0x0272d334",
                           "0x20c4": "link set by 0x0272d340", "0x20ae": "u16 field set by 0x0272d34c"},
            "limits": ["Four direct callers are checked; this is not a complete caller inventory.",
                       "Controller handoff is traced; queue semantics, asynchronous consumer and connection to the tone wrapper are unverified.",
                       "No complete RAW-to-JPEG pixel transform or ISP stage order is established.",
                       "angr 10.0.5 found 710 blocks but emitted truncated pseudocode; that output was rejected as a whole-function explanation."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    with args.decoded.open("rb") as stream:
        result = analyze(stream.read(16_838_657))
    if args.compare:
        require(result, json.loads(args.compare.read_text(encoding="utf-8")), "published RAW evidence")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
