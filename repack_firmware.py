#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Repack same-size K-3 II v1.12 edits for offline inspection, never flash them."""

import argparse
from contextlib import ExitStack
import json
from pathlib import Path
import struct

from inspect_firmware import FIRMWARE_SIZE, SECONDARY_BASE, decode
from verify_findings import INPUT_SHA256, require, sha256

SECTIONS = (
    (0, SECONDARY_BASE, 0x1F0, "<I"),
    (SECONDARY_BASE, FIRMWARE_SIZE, SECONDARY_BASE + 0x7C, ">I"),
)
CLEAR_HEADERS = ((0x100, 0x200), (SECONDARY_BASE, SECONDARY_BASE + 0x80))
MARKER_OFFSETS = (
    (0x1F8, 0x19FFF8, 0xFFFFF8),
    (SECONDARY_BASE + 0x70, SECONDARY_BASE + 0x70, SECONDARY_BASE + 0xEF00),
)


def checksum(data, start, end, fmt):
    return (
        sum(v[0] for v in struct.iter_unpack(fmt, memoryview(data)[start:end]))
        & 0xFFFFFFFF
    )


def repair_checksums(decoded):
    result = bytearray(decoded)
    if len(result) != FIRMWARE_SIZE:
        raise ValueError("same-size decoded image required; relocation is unsupported")
    for start, end, field, fmt in SECTIONS:
        struct.pack_into(fmt, result, field, 0)
        value = -checksum(result, start, end, fmt) & 0xFFFFFFFF
        if value == 0xFFFFFFFF:
            raise ValueError(
                f"checksum at {field:#x} would select the firmware bypass sentinel"
            )
        struct.pack_into(fmt, result, field, value)
    return result


def repack(original, edited):
    require(sha256(original), INPUT_SHA256, "original K-3 II v1.12 package identity")
    source = decode(original)
    require(len(edited), FIRMWARE_SIZE, "edited image length")
    for start, end in CLEAR_HEADERS:
        # Checksum fields are tool-owned; all other clear bytes and XOR keys stay fixed.
        left, right = bytearray(source[start:end]), bytearray(edited[start:end])
        for _, _, field, _ in SECTIONS:
            if start <= field < end:
                left[field - start : field - start + 4] = right[
                    field - start : field - start + 4
                ] = bytes(4)
        require(right, left, f"preserved clear header {start:#x}")
    for offsets in MARKER_OFFSETS:
        for offset in offsets:
            require(
                edited[offset : offset + 8],
                source[offset : offset + 8],
                f"model marker {offset:#x}",
            )
    repaired = repair_checksums(edited)
    package = decode(repaired)  # Same fixed-key XOR transform is its own inverse.
    require(decode(package) == repaired, True, "encoded candidate decodes exactly")
    unchanged = source == edited
    if unchanged:
        require(package == original, True, "lossless unchanged round-trip")
    report = {
        "original_sha256": sha256(original),
        "source_decoded_sha256": sha256(source),
        "edited_decoded_sha256": sha256(edited),
        "repaired_decoded_sha256": sha256(repaired),
        "package_sha256": sha256(package),
        "size": len(package),
        "unchanged_input": unchanged,
        "unchanged_round_trip_exact": unchanged and package == original,
        "edited_bytes": sum(a != b for a, b in zip(source, edited)),
        "package_changed_bytes": sum(a != b for a, b in zip(original, package)),
        "checksums": [
            {
                "start": a,
                "end_exclusive": z,
                "field": f,
                "byte_order": "little" if fmt == "<I" else "big",
                "stored": struct.unpack_from(fmt, repaired, f)[0],
                "sum_mod_2_32": checksum(repaired, a, z, fmt),
            }
            for a, z, f, fmt in SECTIONS
        ],
        "status": "offline_candidate_only",
        "limits": [
            "Fixed-size replacement only; no insertion, deletion or relocation.",
            "Checksums and structure do not prove updater acceptance, boot or camera operation.",
            "The command-7 validation boundary and physical update are not executed by this tool.",
        ],
    }
    return bytes(package), report


def write_outputs(directory, package, report):
    directory.mkdir(parents=True)
    with ExitStack() as rollback:
        rollback.callback(directory.rmdir)
        for name, data in (
            ("candidate.bin", package),
            ("repack.json", (json.dumps(report, indent=2) + "\n").encode()),
        ):
            path = directory / name
            with path.open("xb") as stream:
                rollback.callback(path.unlink)
                stream.write(data)
        rollback.pop_all()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("edited_decoded", type=Path)
    parser.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="new directory for offline candidate and manifest",
    )
    args = parser.parse_args()
    try:
        original = args.original.read_bytes()
        edited = args.edited_decoded.read_bytes()
        package, report = repack(original, edited)
        write_outputs(args.output_dir, package, report)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
