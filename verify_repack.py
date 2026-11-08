"""Verify offline K-3 II repacking against original XOR, checksum and header code.

SPDX-License-Identifier: GPL-2.0-only
No physical update, camera execution or device result is measured.
"""

import argparse
import json
from pathlib import Path
import struct
import tempfile

from inspect_firmware import decode
from repack_firmware import checksum, repack, write_outputs, SECTIONS, MARKER_OFFSETS
from verify_findings import (
    INPUT_SHA256,
    DECODED_SHA256,
    require,
    require_snapshot,
    sha256,
    u32,
)
from verify_tone_path import BASE, check_words
from verify_raw_path import branch_target

WORDS = {
    0x5D64E0: 0xE2511A0F,
    0x5D47DC: 0xE3540001,
    0x5D480C: 0xE1520001,
    0x5D4834: 0xE15E0003,
    0x5D483C: 0x01520006,
    0x5D484C: 0xE3510003,
    0x84766C: 0xE3700001,
    0x847694: 0xE5924000,
    0x8476A4: 0x06BF4F34,
    0x8476A8: 0x00800004,
    0x8476AC: 0x10800004,
    0x8476B8: 0xE3500000,
    0x847828: 0xE02CC00E,
    0x847870: 0xE02CC00E,
    0x599FBC: 0xE3A00007,
    0x59A038: 0xC0001FEC,
    0x5D4C2C: 0xA55A5AA5,
    0x5D4C70: 0x100F000,
    0xDA188: 0xE3500007,
    0xDA18C: 0x05970000,
    0xDA250: 0xE0822003,
    0xDA254: 0xE5993000,
    0xDA25C: 0x95862000,
    0xDA264: 0x8AFFFFF7,
}
EDGES = (
    (0x5D655C, 0x5D6388),
    (0x5D6568, 0x5D6388),
    (0x5D6394, 0x8476CC),
    (0x5D657C, 0x5D47D0),
    (0x5D6590, 0x5D47D0),
    (0x5D4864, 0x5D4788),
    (0x5D487C, 0x5D4778),
    (0x5D47B8, 0x599FB8),
    (0x5D4784, 0x84765C),
)
RANGES = {
    "header_guards": (0x5D4778, 0x5D4880),
    "file_size_decode_check": (0x5D64C0, 0x5D659C),
    "additive_checksum": (0x84765C, 0x8476CC),
    "xor_decoder": (0x8476CC, 0x847888),
    "validation_command7": (0x599FB8, 0x59A01C),
    "mailbox_receiver": (0xDA078, 0xDA30C),
    "marker_tables": (0x9E6088, 0x9E6100),
    "decoder_checksum_tables": (0x9E617C, 0x9E61D8),
}


def original_checks(data, packages):
    import unicorn
    from unicorn import arm_const as arm

    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    image, obj, sp, ret = 0x10000000, 0x12000000, 0x12002000, 0x12003000
    vm.mem_map(image, 0x1010000)
    vm.mem_map(obj, 0x4000)
    vm.mem_map(0x40307000, 0x1000)
    vm.mem_map(0xC0001000, 0x1000)

    def put(address, value):
        vm.mem_write(address, struct.pack("<I", value))

    def run(start, stop=ret, **registers):
        for name, value in {"sp": sp, "lr": ret, **registers}.items():
            vm.reg_write(getattr(arm, "UC_ARM_REG_" + name.upper()), value)
        vm.emu_start(BASE + start, stop, count=150_000_000)
        require(vm.reg_read(arm.UC_ARM_REG_PC), stop, f"original stop {start:#x}")
        return vm.reg_read(arm.UC_ARM_REG_R0)

    def with_receiver(start, **registers):
        # Sequential contexts share mapped bytes; physical cache/coherency is not modeled.
        vm.mem_write(0xC0001FD0, bytes(0x30))
        run(0xDA078, BASE + 0xDA0DC, sp=obj + 0x1000)
        receiver = vm.context_save()
        run(start, BASE + 0x599FF4, **registers)
        sender = vm.context_save()
        request = [u32(vm.mem_read(0xC0001FD0 + i * 4, 4), 0) for i in range(5)]
        vm.context_restore(receiver)
        vm.emu_start(BASE + 0xDA0DC, BASE + 0xDA2F4, count=150_000_000)
        require(
            vm.reg_read(arm.UC_ARM_REG_PC), BASE + 0xDA2F4, "receiver completed command"
        )
        reply = [
            u32(vm.mem_read(a, 4), 0) for a in (0xC0001FE8, 0xC0001FEC, 0xC0001FF0)
        ]
        require([reply[0], reply[2]], [7, 7], "receiver ack slots")
        vm.context_restore(sender)
        vm.emu_start(BASE + 0x599FF4, ret, count=150_000_000)
        require(vm.reg_read(arm.UC_ARM_REG_PC), ret, "sender completed after receiver")
        require(
            [u32(vm.mem_read(a, 4), 0) for a in (0xC0001FD0, 0xC0001FE0)],
            [0, 0],
            "sender clears command slots",
        )
        return {
            "return": vm.reg_read(arm.UC_ARM_REG_R0),
            "request": request,
            "reply": reply,
        }

    put(0x40307E14, image)
    put(obj + 0x48, u32(data, 0x110))
    results = []
    for label, package, decoded in packages:
        vm.mem_write(image, package)
        run(0x8476CC, r1=0, r2=image)
        run(0x8476CC, r1=1, r2=image)
        require(
            bytes(vm.mem_read(image, len(decoded))) == decoded,
            True,
            "native full decoder",
        )
        sums = [run(0x84765C, r1=i, r2=image) for i in (0, 1)]
        require(sums, [1, 1], "both original additive checks accept")
        mailbox = with_receiver(0x5D47D0, r0=obj, r1=0)
        require(mailbox["request"], [7, image, 0x400000, 0, 7], "command7 request")
        require(mailbox["reply"], [7, 0, 7], "original receiver computes zero sum")
        guards = [mailbox["return"], run(0x5D47D0, r0=obj, r1=1)]
        require(guards, [1, 1], "original guards accept both sections")
        bad_sums = []
        for i, (start, end, field, fmt) in enumerate(SECTIONS):
            address = image + start + (0x200 if i == 0 else 0x80)
            saved = bytes(vm.mem_read(address, 1))
            vm.mem_write(address, bytes([saved[0] ^ 1]))
            bad_sums.append(run(0x84765C, r1=i, r2=image))
            if i == 0:
                corrupt_mailbox = with_receiver(0x5D47D0, r0=obj, r1=0)
                require(
                    corrupt_mailbox["return"],
                    0,
                    "original command7 rejects corrupt primary",
                )
                require(
                    corrupt_mailbox["reply"][1] != 0, True, "nonzero sum from receiver"
                )
            vm.mem_write(address, saved)
        require(bad_sums, [0, 0], "single-byte corruption rejects both additive checks")
        results.append(
            {
                "label": label,
                "full_native_decoder_matches": True,
                "checksum_accept": sums,
                "header_guard_accept": guards,
                "command7": mailbox,
                "corrupt_primary_command7": corrupt_mailbox,
                "corrupted_checksum_accept": bad_sums,
            }
        )
    # Check each model/marker field independently; checks stop before hardware execution.
    vm.mem_write(image, data)
    marker_cases = []
    for kind, positions in enumerate(MARKER_OFFSETS):
        for offset in sorted(set(positions)):
            saved = bytes(vm.mem_read(image + offset + 4, 4))
            put(image + offset + 4, 0)
            result = run(0x5D47D0, r0=obj, r1=kind)
            require(result, 0, "marker corruption rejected")
            marker_cases.append({"kind": kind, "offset": offset + 4, "result": result})
            vm.mem_write(image + offset + 4, saved)
    sentinel_cases = []
    for kind, (start, end, field, fmt) in enumerate(SECTIONS):
        for stored in (0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFE, 0xFFFFFFFF):
            candidate = bytearray(data)
            candidate[start + (0x204 if kind == 0 else 0x84)] ^= 1
            struct.pack_into(fmt, candidate, field, stored)
            total = checksum(candidate, start, end, fmt)
            require(total != 0, True, "sentinel fixture has invalid actual checksum")
            vm.mem_write(image, bytes(candidate))
            accepted = run(0x84765C, r1=kind, r2=image)
            require(
                accepted,
                int(stored == 0xFFFFFFFF),
                "only FFFFFFFF sentinel bypasses this checksum function",
            )
            sentinel_cases.append(
                {"kind": kind, "stored": stored, "sum": total, "accepted": accepted}
            )
    return {
        "engine": unicorn.__version__,
        "cases": results,
        "marker_cases": marker_cases,
        "sentinel_cases": sentinel_cases,
        "instruction_hooks": [],
        "mailbox_model": "Original sender and receiver execute in sequential saved CPU contexts over shared mapped bytes. No supplied result or ready-status hooks.",
        "receiver_core_identity": "not established by this replay",
    }


def verify(original):
    require(sha256(original), INPUT_SHA256, "input identity")
    data = bytes(decode(original))
    require(sha256(data), DECODED_SHA256, "decoded identity")
    check_words(data, WORDS)
    for site, target in EDGES:
        require(branch_target(data, site), target, f"branch at {site:#x}")
    for kind, positions in enumerate(MARKER_OFFSETS):
        require(
            [u32(data, 0x9E609C + (3 * kind + i) * 4) * 2 for i in range(3)],
            list(positions),
            "marker table",
        )
    packages, reports = [], []
    for label, offsets in [
        ("unchanged", []),
        ("primary_menu_letter", [0xE4C6D8]),
        ("secondary_corruption_fixture", [0x1000080]),
    ]:
        edited = bytearray(data)
        for offset in offsets:
            edited[offset] = (
                edited[offset] + 0x20
                if label == "primary_menu_letter"
                else edited[offset] ^ 1
            )
        package, report = repack(original, edited)
        require(
            report["unchanged_round_trip_exact"], not offsets, "roundtrip case status"
        )
        reports.append({"label": label, **report})
        packages.append((label, package, bytes(decode(package))))
    rejected = []
    for kind, (start, end, field, fmt) in enumerate(SECTIONS):
        edited = bytearray(data)
        offset = start + (0x200 if kind == 0 else 0x80)
        old_word = struct.unpack_from(fmt, edited, offset)[0]
        old_checksum = struct.unpack_from(fmt, edited, field)[0]
        struct.pack_into(
            fmt, edited, offset, (old_word + old_checksum + 1) & 0xFFFFFFFF
        )
        try:
            repack(original, edited)
        except ValueError as exc:
            require(
                "bypass sentinel" in str(exc),
                True,
                "same-size sentinel rejection reason",
            )
            rejected.append(f"computed_sentinel_kind_{kind}")
        else:
            raise ValueError("computed checksum sentinel was exported")
    for label, offset in [
        ("primary_iv", 0x100),
        ("model", 0x110),
        ("secondary_iv", 0x1000000),
        ("middle_marker", 0x19FFFC),
    ]:
        edited = bytearray(data)
        edited[offset] ^= 1
        try:
            repack(original, edited)
        except ValueError:
            rejected.append(label)
        else:
            raise ValueError(f"{label} was not rejected")
    try:
        repack(original, data[:-128])
    except ValueError:
        rejected.append("resize")
    else:
        raise ValueError("resize accepted")
    with tempfile.TemporaryDirectory() as temporary:
        output = Path(temporary) / "candidate"
        write_outputs(output, b"fixture", {"fixture": True})
        try:
            write_outputs(output, b"replacement", {})
        except FileExistsError:
            require(
                (output / "candidate.bin").read_bytes(),
                b"fixture",
                "existing output preserved",
            )
            rejected.append("existing_output")
        else:
            raise ValueError("existing output overwritten")
    return {
        "decoded_sha256": DECODED_SHA256,
        "input_sha256": INPUT_SHA256,
        "locations": "decoded file offsets except explicit object/MMIO addresses",
        "branches": [list(e) for e in EDGES],
        "range_hashes": {
            name: {"start": a, "end_exclusive": z, "sha256": sha256(data[a:z])}
            for name, (a, z) in RANGES.items()
        },
        "repack_cases": reports,
        "rejected_edits": rejected,
        "original_a32": original_checks(data, packages),
        "limits": [
            "No camera update or physical command7 result was observed.",
            "The identified additive checks and fixed markers are not a cryptographic-signature proof.",
            "Whole updater, ROM installation, boot, image capture and data preservation remain untested.",
            "A repaired checksum can accept intentionally corrupted executable data; validity is not correctness.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = verify(args.original.read_bytes())
    if args.compare:
        require_snapshot(result, args.compare, "repack evidence")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
