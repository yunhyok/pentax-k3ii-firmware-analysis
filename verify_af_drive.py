"""Verify K-3 II v1.12 autofocus capability storage and drive selection.

SPDX-License-Identifier: GPL-2.0-only
"""

import argparse
import json
from pathlib import Path

from verify_findings import DECODED_SHA256, require, sha256, u32
from verify_raw_path import branch_target
from verify_tone_path import BASE, check_words, load_image


COPY_ROWS = {
    0xD524C: (0xD541C, 0, 0x3DC0),
    0xD525C: (0xD91DC, 0x00102800, 0x894),
    0xD526C: (0xD9A70, 0x00103094, 0xF4),
    0xD529C: (0xDAC60, 0x01002400, 0xD898),
}
TYPES = {
    "7CAfLens": (0xD25D7, 0xD0F50, 0xD4EE8),
    "8CAfMotor": (0xD2610, 0xD0F90, 0xD4F9C),
    "8CLensSdm": (0xD2624, 0xD0FBC, 0xD4FF4),
    "9CLensKaf2": (0xD2678, 0xD1024, 0xD50F8),
    "20CAfLensCommunication": (0xD1B38, 0xD0A64, 0xD4014),
}
WORDS = {
    0x21524: 0xE8BA000F,
    0x21534: 0xE1A0F003,
    0x21544: 0x28B00078,
    0x21548: 0x28A10078,
    0x4C504: 0xE590001C,
    0x4C50C: 0xE2000040,
    0x4C510: 0xE1A00320,
    0xB9B48: 0xE5D00006,
    0xB9B5C: 0xE5C01006,
    0x94DF4: 0xE1A00005,
    0x955C4: 0x8205,
    0x948C8: 0x8022,
    0x948D0: 0x1E1,
    0x94560: 0xE3510002,
    0x9485C: 0xE1B05000,
    0x94860: 0x05D41004,
    0x94864: 0x0597012C,
    0x52E80: 0xE594000C,
    0x52E8C: 0xE3500000,
    0x52370: 0xE5940008,
    0x4E0F0: 0xE3A01C89,
    0x4E0FC: 0xE1C404BC,
    0x4B9F8: 0xE5900024,
    0x4B9FC: 0xE3A01013,
    0x90260: 0xE5D000E4,
    0x4D468: 0xE35000F1,
    0x4D498: 0xE35000F2,
    0x4DD74: 0xE5900018,
    0x85B080: 0xE3A01001,
    0x5CA864: 0x13A01002,
    0x5D7070: 0xE3081601,
    0xB90D0: 0xE5801000,
    0xB90B4: 0xE5801000,
}
# Each branch's source is a file offset and its destination is an execution address.
EDGES = (
    (0x900A4, BASE + 0x94DC4),
    (0x91DA8, BASE + 0x94DC4),
    (0x94DE4, BASE + 0xB9B48),
    (0x94DF8, BASE + 0x94204),
    (0x94564, BASE + 0x94844),
    (0x94858, BASE + 0x93F94),
    (0x94868, BASE + 0xB9B5C),
    (0x4C508, BASE + 0xB9B48),
    (0xE7E00, BASE + 0x4C500),
    (0x52E84, BASE + 0x4C500),
    (0x52E94, BASE + 0x52ED4),
    (0x52ED8, BASE + 0x52F24),
    (0x52F58, 0x0100F408),
    (0xE7C68, 0x294C),
    (0x52EA4, BASE + 0x59B14),
    (0x5322C, BASE + 0x4DD6C),
    (0x4DD80, BASE + 0x4C500),
    (0x4DD88, BASE + 0x4E034),
    (0x4E0F4, BASE + 0x94204),
    (0x94A9C, BASE + 0x93D24),
    (0x53124, BASE + 0x52D18),
    (0x52E20, BASE + 0x5234C),
    (0x52378, BASE + 0x47D80),
    (0x47D98, BASE + 0x47CD0),
    (0x47D64, BASE + 0x332E8),
    (0x332F8, BASE + 0x33250),
    (0x3328C, BASE + 0xB90B0),
    (0x4BA00, BASE + 0x9025C),
    (0x4D404, BASE + 0x4B9F8),
    (0x4D46C, BASE + 0x4D4E8),
    (0x4D49C, BASE + 0x4D4DC),
    (0x4D4E4, BASE + 0x4D2BC),
    (0x4D4F0, BASE + 0x4D1BC),
    (0x85B088, BASE + 0x5CA85C),
    (0x5CA868, BASE + 0x5D7034),
    (0x5D7078, BASE + 0x5D6E4C),
)
RANGES = {
    "startup_copy": (0x21524, 0x21568),
    "startup_copy_rows": (0xD524C, 0xD52AC),
    "capability_query": (0x94DC4, 0x94E0C),
    "lens_command_dispatch": (0x94204, 0x94AAC),
    "capability_predicate": (0x4C500, 0x4C518),
    "drive_preparation": (0x52D18, 0x5342C),
    "lens_af_transaction_preparation": (0x4DD6C, 0x4E104),
    "body_drive_entry_and_direction": (0x47C30, 0x47E18),
    "body_register_preparation": (0x33250, 0x3332C),
    "native_model_profile_selection": (0x4D3F8, 0x4D5B0),
    "service_control": (0x85AFBC, 0x85B1B0),
}


def code_va(file_offset):
    for row in (0xD524C, 0xD529C):
        start, address, length = COPY_ROWS[row]
        if start <= file_offset < start + length:
            return address + file_offset - start
    return BASE + file_offset


def verify(data):
    check_words(data, WORDS)
    for site, target in EDGES:
        destination = code_va(site) + branch_target(data, site) - site
        require(destination, target, f"A32 branch at {site:#x}")
    for row, (source, dest, length) in COPY_ROWS.items():
        require(
            [u32(data, row + i) for i in range(0, 16, 4)],
            [BASE + source, dest, length, BASE + 0x21540],
            f"copy row {row:#x}",
        )
    for name, (offset, info, table) in TYPES.items():
        marker = name.encode("ascii") + b"\0"
        require(data[offset : offset + len(marker)], marker, f"RTTI name {name}")
        require(u32(data, info + 4), BASE + offset, f"RTTI pointer {name}")
        require(u32(data, table - 4), BASE + info, f"vtable RTTI {name}")
    require(data[0x85B26C:0x85B275], b"SDM On  \0", "service label")
    require(data[0x57210:0x57229], b"MOVABLE_SDM_DRIVE_ERROR\n\0", "AF diagnostic")

    return {
        "decoded_sha256": DECODED_SHA256,
        "firmware_version": "1.12",
        "image_base": BASE,
        "offset_units": "Decoded file offsets except execution addresses and object fields.",
        "word_check_count": len(WORDS),
        "branch_checks": [
            {"file_offset": site, "target_va": target} for site, target in EDGES
        ],
        "copy_rows": [
            {
                "file_offset": row,
                "source_file_offset": source,
                "destination_va": dest,
                "length": length,
            }
            for row, (source, dest, length) in COPY_ROWS.items()
        ],
        "class_records": {
            name: {"rtti": info, "name_offset": offset, "vtable": table}
            for name, (offset, info, table) in TYPES.items()
        },
        "capability": {
            "query_caller": 0x94DF8,
            "dispatch": 0x94204,
            "command": 0x8205,
            "response_bytes": 1,
            "accepted_transport_status": 0,
            "write": 0xB9B5C,
            "lens_object_offset": 6,
            "predicate": 0x4C500,
            "relocated_veneer_va": 0x0100F5A0,
            "mask": 0x40,
        },
        "drive": {
            "prepare": 0x52E38,
            "predicate_call": 0x52E84,
            "lens_start": 0x4DD6C,
            "lens_transaction": 0x8900,
            "body_target": 0x52D18,
            "body_dispatch": 0x47D80,
            "body_register_preparation": 0x33250,
        },
        "model_and_service": {
            "raw_model_getter": 0x4B9F8,
            "raw_model_index": 0x13,
            "native_profile_dispatch": 0x4D3F8,
            "native_profile_targets": {"0xf1": 0x4D1BC, "0xf2": 0x4D2BC},
            "service_label": 0x85B26C,
            "service_command": 0x8601,
            "service_on_payload_byte": 2,
        },
        "range_sha256": {
            label: sha256(data[start:end]) for label, (start, end) in RANGES.items()
        },
        "references": {
            "Ricoh K-3 II FAQ": "https://www.ricoh-imaging.co.jp/english/support/qa/k-3-2/index.html",
            "Ricoh original smc DA* 16-50 SDM": "https://www.ricoh-imaging.co.jp/english/products/lens/k/standard/smcpentax-das16-50/",
            "Ricoh original smc DA* 50-135 SDM": "https://www.ricoh-imaging.co.jp/english/products/lens/k/telephoto/smcpentax-das50-135/",
            "ExifTool MakerNote lens labels": "https://github.com/exiftool/exiftool/blob/9b8664dfcf2c609d3cc8925d380e98ad2a379f9b/lib/Image/ExifTool/Pentax.pm#L344-L360",
        },
    }


def emulate(data):
    import unicorn
    from unicorn import arm_const as arm

    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    for address, length in (
        (0, 0x4000),
        (0x00102000, 0x2000),
        (0x01002000, 0xE000),
        (0x10000000, 0x20000),
        (0x30011000, 0x1000),
    ):
        vm.mem_map(address, length)
    for source, dest, length in COPY_ROWS.values():
        vm.mem_write(dest, data[source : source + length])

    motor, lens, kaf, accessor, transport, sdm = (
        0x10000000 + 0x1000 * i for i in range(1, 7)
    )
    comm, pulse, position, sensor, flags = (
        0x10000000 + 0x1000 * i for i in range(0xB, 0x10)
    )
    ret = 0x1001F000

    def write(address, value, width=4):
        vm.mem_write(address, value.to_bytes(width, "little"))

    def read(address, width=1):
        return int.from_bytes(vm.mem_read(address, width), "little")

    def reg(name, value=None):
        register = getattr(arm, f"UC_ARM_REG_{name.upper()}")
        if value is None:
            return vm.reg_read(register)
        vm.reg_write(register, value)

    def run(entry, end=None, **registers):
        stop = ret if end is None else BASE + end
        for name, value in dict(sp=ret - 0x1000, lr=ret, **registers).items():
            reg(name, value)
        vm.emu_start(BASE + entry, stop, count=20000)
        require(reg("pc"), stop, f"original execution from {entry:#x}")
        return reg("r0")

    for obj, fields in (
        (
            motor,
            {
                4: accessor,
                8: pulse,
                0xC: lens,
                0x10: comm,
                0x14: position,
                0x18: position,
                0x34: sensor,
            },
        ),
        (lens, {0x1C: kaf, 0x24: transport}),
        (
            comm,
            {
                4: accessor,
                0xC: flags,
                0x18: lens,
                0x1C: position,
                0x20: position,
                0x24: position,
                0x2C: kaf,
                0x30: sdm,
            },
        ),
        (sdm, {0x4128: transport, 0x412C: kaf, 0x4134: accessor}),
        (sensor, {4: accessor, 0x9C: flags}),
        (accessor, {0x10: flags, 0x234: flags}),
    ):
        for offset, pointer in fields.items():
            write(obj + offset, pointer)

    trace, calls, staged = [], [], []
    response, status = 0, 0

    def boundary(_vm, address, _size, _user):
        offset = address - BASE
        if offset == 0x93F94:
            require(reg("r0"), sdm, "capability transport object")
            require(reg("r3"), sdm + 4, "capability destination")
            trace.append([reg("r1") << 8 | reg("r2"), read(reg("sp"), 4)])
            write(reg("r3"), response, 1)
            reg("r0", status)
        elif offset == 0x93D24:
            require(reg("r0"), sdm, "lens transaction object")
            require(reg("r3"), sdm + 4, "lens transaction payload source")
            count = read(reg("sp"), 4)
            trace.append([reg("r1") << 8 | reg("r2"), count])
            staged.append(list(vm.mem_read(reg("r3"), count)))
            reg("r0", 0)
        else:
            calls.append(offset)
            reg("r0", 0)
        reg("pc", reg("lr"))

    stubs = (0x93F94, 0x93D24, 0x47E38, 0x47E58, 0x41E08)
    for offset in stubs:
        vm.hook_add(
            unicorn.UC_HOOK_CODE, boundary, begin=BASE + offset, end=BASE + offset
        )

    results = []
    for response, status, previous, stored, use_lens in (
        (0x00, 0, 0x00, 0x00, False),
        (0x40, 0, 0x00, 0x40, True),
        (0xC0, 0, 0x00, 0xC0, True),
        (0x80, 0, 0x00, 0x80, False),
        (0x40, 7, 0x00, 0x00, False),
        (0x00, 7, 0x40, 0x40, True),
    ):
        write(kaf + 6, previous, 1)
        write(0x001030A4, 1, 1)  # Bypass unrelated AF sensor reconfiguration.
        write(0x001030AB, 0, 1)
        write(0x001030AF, 0, 1)
        write(0x0010314A, 0x12, 2)
        write(position + 0x9E, 0x345, 2)
        trace.clear()
        calls.clear()
        staged.clear()
        require(
            run(0x94204, r0=sdm, r1=0x8205), status, "capability transaction status"
        )
        require(trace, [[0x8205, 1]], "one-byte capability request")
        require(read(kaf + 6), stored, "capability store depends on success")
        require(run(0x4C500, r0=lens), int(use_lens), "lens AF bit-6 predicate")

        trace.clear()
        if use_lens:
            run(0x52E38, 0x4E0F8, r0=motor, r1=5)
            require(trace, [[0x8920, 1], [0x8900, 2]], "lens AF transaction sequence")
            require(staged, [[0], [3, 0x45]], "lens AF outbound bytes")
            require(calls, [], "lens branch skips body fixture helpers")
        else:
            run(0x52E38, 0x47D80, r0=motor, r1=5)
            require(
                [reg(name) for name in ("r0", "r1", "r2")],
                [pulse, 0, 0x12],
                "body target",
            )
            require(trace, [], "body branch has no lens transactions")
            require(
                calls, [0x47E38, 0x47E38, 0x47E58, 0x47E58, 0x41E08], "body setup calls"
            )
        require(
            read(kaf + 6),
            stored,
            "drive preparation retains the reported capability byte",
        )
        results.append(
            {
                "reply": response,
                "transport_status": status,
                "prior_capability": previous,
                "stored_capability": stored,
                "lens_af_predicate": int(use_lens),
                "route": "lens_transaction" if use_lens else "body_driver",
                "lens_transactions": trace.copy(),
                "outbound_payloads": staged.copy(),
                "body_target": None if use_lens else 0x12,
            }
        )

    native_profiles = []
    for key, target in ((0xF1, 0x4D1BC), (0xF2, 0x4D2BC), (0x00, 0x4D054)):
        write(transport + 0xF7, key, 1)
        require(run(0x4B9F8, r0=lens), key, "native lens-model byte")
        write(comm + 4, lens)
        run(0x4D3F8, target, r0=comm)
        native_profiles.append({"raw_key": key, "target_file_offset": target})

    return {
        "unicorn_version": unicorn.__version__,
        "drive_cases": results,
        "native_profile_cases": native_profiles,
        "stubbed_file_offsets": list(stubs),
        "limits": [
            "The capability transaction starts at the dispatcher with synthetic lens replies.",
            "Motion starts at 0x52e38 with prepared objects and argument 5. The lens leg ends after dispatch of 0x8900. The body leg ends at the driver entry 0x47d80.",
            "Hooks replace the two lens transfer helpers, body reset/prepare helpers 0x47e38 and 0x47e58, and focus position bookkeeping 0x41e08.",
            "The reconstructed A32 ranges use firmware copy-row addresses. The full boot and the external lens/body controllers were outside the probes.",
            "The KAF2 response bit identifies the traced branch. The fixture does not distinguish SDM from DC or PLM at the motor protocol level.",
            "The raw model byte reaches distinct native profiles. The mapping from a physical lens to an allowlisted native key and safe behavior across all AF stages remain unverified.",
            "No patch, lens ROM write, physical drive or firmware update was applied.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded_image", type=Path)
    parser.add_argument("--emulate", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    data = load_image(args.decoded_image)
    result = verify(data)
    if args.emulate:
        result["numeric"] = emulate(data)
    if args.compare:
        require(
            result,
            json.loads(args.compare.read_text(encoding="utf-8")),
            "AF drive evidence",
        )
        print(f"AF drive evidence matches {args.compare}")
    if args.output:
        args.output.write_text(
            json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n"
        )
    if not args.compare and not args.output:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
