#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# XOR decoding adapted from Tao Wang's pentax-firmware-tool (GPL-2.0).
"""Inspect the Pentax K-3 II firmware package and optionally save decoded bytes."""

import argparse
from contextlib import ExitStack
import hashlib
import json
from pathlib import Path
from struct import Struct


UPSTREAM = (
    "https://github.com/twang2218/pentax-firmware-tool/blob/"
    "3e2597b5d4cfa9ce242b6d3aeef32c28e64b6f73/index.js"
)
FIRMWARE_SIZE = 0x100F000
SECONDARY_BASE = 0x1000000
WORD_MASK = 0xFFFFFFFF
BLOCK = Struct("<32I")
IV = Struct("<4I")

# Each tuple contains a base, an IV offset, a start offset and a byte count.
REGIONS = (
    (0, 0x100, 0, 0x100),
    (0, 0x100, 0x200, SECONDARY_BASE - 0x200),
    (SECONDARY_BASE, 0, 0x80, FIRMWARE_SIZE - SECONDARY_BASE - 0x80),
)
HEADER_FIELDS = (
    ("primary_id", 0x100, 16),
    ("copyright", 0x124, 42),
    ("model", 0x14E, 14),
    ("version", 0x15C, 20),
    ("vendor_id", 0x194, 9),
    ("internal_model", 0x1AB, 11),
    ("secondary_id", SECONDARY_BASE, 16),
    ("secondary_model", SECONDARY_BASE + 0x40, 16),
)


def decode_region(data, base, iv_offset, start, length):
    if (
        min(base, iv_offset, start, length) < 0
        or base + iv_offset + IV.size > len(data)
        or base + start + length > len(data)
    ):
        raise ValueError("decode region or IV extends beyond the input")
    if base % BLOCK.size or start % BLOCK.size or length % BLOCK.size:
        raise ValueError("decode region must align to 0x80 bytes")

    iv = IV.unpack_from(data, base + iv_offset)
    a = iv[0] + ~iv[2]
    b = iv[1] + ~iv[3]
    terms = (a, b, ~a, ~b)
    key = tuple(term + delta - 1 for word in iv for delta in (word, -word) for term in terms)
    for relative_offset in range(start, start + length, BLOCK.size):
        offset = base + relative_offset
        words = BLOCK.unpack_from(data, offset)
        BLOCK.pack_into(
            data, offset,
            *(word ^ ((mask - relative_offset) & WORD_MASK) for word, mask in zip(words, key)),
        )


def decode(data):
    # shortcut: accepts the observed package size, expand after verifying other K-3 II builds.
    if len(data) % BLOCK.size:
        raise ValueError("input size must align to 0x80 bytes")
    if len(data) != FIRMWARE_SIZE:
        raise ValueError(f"expected {FIRMWARE_SIZE:,} bytes, received {len(data):,}")
    if not data.startswith(b"Copyright", 0x124):
        raise ValueError("missing little-endian branch marker at 0x124")
    if not data.startswith(b"PENTAX K-3 II\0", 0x14E):
        raise ValueError("missing PENTAX K-3 II model marker at 0x14e")
    if not data.startswith(b"PENTAX K-3MC   \0", SECONDARY_BASE + 0x40):
        raise ValueError("missing secondary PENTAX K-3MC model marker at 0x1000040")

    decoded = bytearray(data)
    for region in REGIONS:
        decode_region(decoded, *region)
    return decoded


def build_inventory(filename, data, decoded):
    return {
        "input": {
            "filename": filename,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        "decoded": {
            "size": len(decoded),
            "sha256": hashlib.sha256(decoded).hexdigest(),
            "first_eight_words_le": [f"0x{word:08x}" for word in Struct("<8I").unpack_from(decoded)],
        },
        "algorithm": {
            "name": "32-bit little-endian XOR in 0x80-byte blocks",
            "source": UPSTREAM,
            "regions": [
                {
                    "start": f"0x{base + start:08x}",
                    "end_exclusive": f"0x{base + start + length:08x}",
                    "base": f"0x{base:08x}",
                    "iv_offset": f"0x{base + iv_offset:08x}",
                }
                for base, iv_offset, start, length in REGIONS
            ],
        },
        "headers": {
            name: {
                "offset": f"0x{offset:08x}",
                "text": data[offset:offset + length].split(b"\0", 1)[0].decode("ascii").rstrip(),
            }
            for name, offset, length in HEADER_FIELDS
        },
    }


def write_outputs(output_dir, decoded, inventory):
    output_dir.mkdir(parents=True)
    with ExitStack() as rollback:
        rollback.callback(output_dir.rmdir)
        for name, contents in (("decoded.bin", decoded), ("inventory.json", inventory.encode("utf-8"))):
            path = output_dir / name
            with path.open("xb") as stream:
                rollback.callback(path.unlink)
                stream.write(contents)
        rollback.pop_all()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output-dir", type=Path, help="save decoded.bin and inventory.json in a new directory")
    args = parser.parse_args()

    try:
        with args.input.open("rb") as stream:
            data = stream.read(FIRMWARE_SIZE + 1)
        decoded = decode(data)
        inventory = json.dumps(build_inventory(args.input.name, data, decoded), indent=2) + "\n"
        if args.output_dir:
            write_outputs(args.output_dir, decoded, inventory)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    print(inventory, end="")


if __name__ == "__main__":
    main()
