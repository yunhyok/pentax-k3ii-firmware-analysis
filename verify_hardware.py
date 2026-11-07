"""Reproduce hardware-identification evidence, without identifying a package by guess.

SPDX-License-Identifier: GPL-2.0-only
The secondary prefix is decoded against Fujitsu CM25-10142-3E Appendix B.
This is a checked prefix, not a general F2MC disassembler.
"""
import argparse
import json
from pathlib import Path
from verify_findings import DECODED_SHA256, literal_offset, require, sha256, u32

MANUAL = "https://www.infineon.com/assets/row/public/documents/10/57/infineon-f2mc-8l-mb89580b-bw-series-hardware-manual-additionaltechnicalinformation-en.pdf"
SECONDARY = 0x1000000
ROM_BASE = 0x1000


def rom_offset(address):
    if not ROM_BASE <= address <= 0xFFFF:
        raise ValueError("address outside secondary ROM mapping")
    return SECONDARY + address - ROM_BASE


def analyze(data):
    require(sha256(data), DECODED_SHA256, "decoded identity")
    prefix = [
        ("e4024e", "MOVW A,#0x024e"), ("e1", "MOVW SP,A"),
        ("70", "MOVW A,PS"), ("e407ff", "MOVW A,#0x07ff"),
        ("63", "ANDW A"), ("71", "MOVW PS,A"),
        ("70", "MOVW A,PS"), ("e40030", "MOVW A,#0x0030"),
        ("73", "ORW A"), ("71", "MOVW PS,A"),
        ("e77553", "MOVW EP,#0x7553"), ("e40875", "MOVW A,#0x0875"),
        ("e4000c", "MOVW A,#0x000c"), ("3172c1", "CALL 0x72c1"),
    ]
    pos = 0x1080
    instructions = []
    for code, meaning in prefix:
        offset = rom_offset(pos)
        expected = bytes.fromhex(code)
        require(data[offset:offset + len(expected)], expected, f"secondary prefix {pos:#x}")
        instructions.append({"rom_address": pos, "file_offset": offset, "bytes": code, "instruction": meaning})
        pos += len(expected)
    require(data[rom_offset(0xFFFC):], bytes.fromhex("ff001080"), "mode and reset vector")
    vectors = [{"rom_address": a, "target": int.from_bytes(data[rom_offset(a):rom_offset(a) + 2], "big")}
               for a in range(0xFFDC, 0xFFFC, 2)]
    for vector in vectors:
        rom_offset(vector["target"])
    # This shared interrupt handler terminates with RETI at ROM 0x23cf.
    require(data[rom_offset(0x23B8):rom_offset(0x23D0)],
            bytes.fromhex("404340f3400810094080002123c25049104850e350435030"),
            "shared interrupt handler prefix")
    require(literal_offset(data, 0x753C6C), 0x753C84, "chip version literal")
    require(u32(data, 0x753C84), 0xD0001000, "chip version MMIO address")
    require(u32(data, 0x753C70), 0xE5900000, "chip version read")
    require(u32(data, 0x753C74), 0xE200020F, "chip version mask")
    for offset, word in [(0x420, 0xE59F0028), (0x424, 0xE5901000),
                         (0x428, 0xE59F20C8), (0x42C, 0xE1510002),
                         (0x430, 0x1AFFFFFB), (0x434, 0xE59F00C0),
                         (0x438, 0xE12FFF10), (0x450, 0xC0001FFC),
                         (0x4F8, 0xA55A5AA5), (0x4FC, 0x02020100),
                         (0x20100, 0xEE110F10), (0x20104, 0xE3C00080),
                         (0x20108, 0xEE010F10)]:
        require(u32(data, offset), word, f"alternate ARM startup {offset:#x}")
    require(data[0x20000:0x2000F], b"HOKKTKIYHTNTMU ", "embedded header")
    library = b"M7 for Fujitsu"
    library_offset = data.find(library)
    require(data.count(library), 1, "M7 library marker occurrence")
    return {
        "analysis_date": "2026-11-08", "decoded_sha256": sha256(data),
        "main_cpu": {"finding": "Cortex-A9 part-number startup path; exact SoC unknown",
                     "part_number": 0xC09, "evidence": "findings.json:midr_check",
                     "nonmatching_path": {"start_address": 0x02000420,
                                          "mailbox_address": 0xC0001FFC, "expected_word": 0xA55A5AA5,
                                          "target_address": 0x02020100, "embedded_header_offset": 0x20000,
                                          "description": "Additional CP15 ARM bootstrap, core and role not identified"}},
        "chip_version_reader": {"function_address": 0x02753C6C, "mmio_address": 0xD0001000,
                                "mask": 0xF0000000, "diagnostic_call_address": 0x025C990C,
                                "diagnostic_format_offset": 0x5C9A68, "live_value": None},
        "library_marker": {"text": library.decode(), "file_offset": library_offset,
                           "sha256": sha256(library), "meaning": "library attribution, not SoC identity"},
        "secondary": {"isa": "F2MC-8L-compatible", "exact_part": None,
                      "interpretation": "Strong static ISA match, not a package marking or hardware observation",
                      "file_range": [SECONDARY, len(data)], "rom_range": [ROM_BASE, 0x10000],
                      "reset_vector": 0x1080, "mode_data": 0, "instructions": instructions,
                      "interrupt_vectors": vectors, "shared_handler_address": 0x23B8,
                      "prefix_sha256": sha256(data[SECONDARY + 0x80:rom_offset(pos)]),
                      "manual": MANUAL, "manual_printed_pages": "323-329; CPU vector table"},
        "limitations": ["No live MIDR, chip-version register, or board marking was read.",
                        "F2MC-8L-compatible encoding does not distinguish compatible derivatives or MCU part numbers.",
                        "Neither MB86S22A nor an MB89-series part is attributed to this camera."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    with args.decoded.open("rb") as stream:
        result = analyze(stream.read(16_838_657))
    if args.compare:
        require(result, json.loads(args.compare.read_text(encoding="utf-8")), "published hardware evidence")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
