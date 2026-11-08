"""Verify the K-3 II sector 14 record, diagnostic argument and save request.

SPDX-License-Identifier: GPL-2.0-only
"""

import argparse
import json
from hashlib import shake_256
from pathlib import Path
from struct import pack, unpack

from verify_findings import literal_offset, require, require_snapshot, sha256, u32
from verify_tone_path import BASE, a32_immediate, check_edge, check_words, load_image


SECTOR = 14
SECTOR_BYTES = 0x20000
SOURCE = BASE + SECTOR * SECTOR_BYTES
PROVIDER, MIRROR, STAGING = 0x4040AE68, 0x4042C4F0, 0x40459204
VTABLE = 0xA5ECEC
RECORD_BYTES, COPY_OFFSET = 0x20, 0x1528
DEFAULT, MARKER = 0x157488, 0xA55A5AA5
CSV_PATH, CSV_HEADER = 0x63643C, 0xA4918C
CSV_FORMATS = {0: 0x636490, 1: 0x636454}

CALLS = (
    (0x76C244, 0x71C908),
    (0x76B51C, 0x6E9494),
    (0x6E7ED0, 0x6E7E9C),
    (0x82E3EC, 0x6E7E9C),
    (0x82E408, 0x71C980),
    (0x82E41C, 0x712898),
    (0x74A9DC, 0x7B2004),
    (0x74A9EC, 0x6C61F0),
    (0x74AA04, 0x6C61F0),
    (0x74AA1C, 0x6C61F0),
    (0x74AA34, 0x6C61F0),
    (0x74AA4C, 0x6C61F0),
    (0x636040, 0x6E7E9C),
    (0x6362BC, 0x71C980),
    (0x6362C0, 0x71C870),
    (0x6E8534, 0x599F20),
    (0x6E8540, 0x6E8178),
    (0x6E854C, 0x599D18),
    (0x6E855C, 0x6E7E9C),
    (0x6E85B0, 0x599E88),
    (0x6E861C, 0x599E88),
    (0x6E867C, 0x599E88),
    (0x6E86DC, 0x599E88),
    (0x6E8740, 0x599E88),
    (0x6E8758, 0x599D6C),
    (0x599D5C, 0x5999C0),
    (0x599DB0, 0x599914),
    (0x6E8BEC, 0x6E8178),
    (0x6E8BF4, 0x599F6C),
)
TAILS = (
    (0x71C934, 0x71C7E4),
    (0x71C954, 0x712898),
    (0x71C964, 0x712898),
    (0x71C99C, 0x71C878),
    (0x71C9A4, 0x71C8C0),
    (0x74AA5C, 0x71C848),
    (0x636578, 0x6362AC),
    (0x6E8178, 0x72C988),
)
WORDS = {
    0x76B514: 0xE3A01000,  # register ID 0
    0x6E94BC: 0x05812014,
    0x6E80E4: 0xE5C022CA,  # constructor clears the later-group gate
    0x6E7EE0: 0xE590100C,
    0x6E7EF4: 0x05901018,
    0x6E7EF8: 0x1590101C,
    0x71C94C: 0xE3A02020,
    0x71C95C: 0xE3A02020,
    0x71C978: 0xE3A00010,
    0x82E410: 0xE3010528,
    0x82E414: 0xE3A02020,
    0x7B2004: 0xE3011528,
    0x636044: 0xE58D0004,
    0x71C870: 0xE5900014,
    0x6362C4: 0xE58D0220,
    0x6362F0: 0xE59D2220,
    0x636300: 0xFA0356EE,  # formatter BLX
    0x63655C: 0xFA035657,  # same formatter BLX
    0x6362A8: 0x0A0000A3,  # branch to header path
    0x6362B4: 0xE12FFF36,
    0x63631C: 0xE5906020,
    0x636324: 0xE12FFF36,
    0x636574: 0xE5906020,
    0x636290: 0xE12FFF36,
    0x636550: 0xE12FFF36,
    0x6E8548: 0xE3A01787,
    0x6E856C: 0xE5901028,
    0x6E8580: 0xE5901020,
    0x6E8594: 0xE5901024,
    0x6E8754: 0xE3A01787,
    0x6E8764: 0xE5D402CA,
    0x6E876C: 0x0A00011C,
    0x6E8BF8: 0xE1570005,
    0x6E8BFC: 0xC1A00007,
    0x6E8C00: 0xD1A00005,
}
LITERALS = (
    (0x76C240, 0x76BF44, PROVIDER),
    (0x76B510, 0x76BF44, PROVIDER),
    (0x71C7E8, 0x71C9A8, MARKER),
    (0x71C910, 0x71C9AC, BASE + VTABLE),
    (0x71C930, 0x71C9B0, SOURCE),
    (0x71C948, 0x71C9B8, BASE + DEFAULT),
    (0x71C950, 0x71C9B4, MIRROR),
    (0x71C958, 0x71C9B0, SOURCE),
    (0x71C960, 0x71C9B4, MIRROR),
    (0x71C968, 0x71C9B4, MIRROR),
    (0x71C970, 0x71C9B0, SOURCE),
    (0x71C980, 0x71C9B4, MIRROR),
    (0x71C998, 0x71C9B4, MIRROR),
    (0x71C9A0, 0x71C9B4, MIRROR),
    (0x636554, 0x637398, BASE + CSV_HEADER),
    (0x5999C0, 0x59A028, STAGING),
    (0x599ECC, 0x59A028, STAGING),
)
SLOTS = {
    0x0C: 0x71C930,
    0x18: 0x71C948,
    0x1C: 0x71C958,
    0x20: 0x71C968,
    0x24: 0x71C970,
    0x28: 0x71C978,
    0x2C: 0x71C998,
    0x30: 0x71C9A0,
}
RANGES = (
    (0x76C240, 0x76C248),
    (0x76B510, 0x76B520),
    (0x6E80BC, 0x6E8144),
    (0x6E9494, 0x6E94C4),
    (0x6E7E9C, 0x6E7F60),
    (0x71C7E4, 0x71C9BC),
    (0x82E3E4, 0x82E420),
    (0x74A9D0, 0x74AA60),
    (0x636038, 0x636048),
    (0x636270, 0x636328),
    (0x63653C, 0x63657C),
    (0x6E8528, 0x6E8770),
    (0x6E8BE4, 0x6E8C08),
    (0x5999C0, 0x5999F0),
    (0x599D18, 0x599DC0),
    (0x599E88, 0x599F0C),
)


def verify_static(data):
    for site, destination in CALLS:
        check_edge(data, site, destination)
    for site, destination in TAILS:
        check_edge(data, site, destination, link=False)
    check_words(data, WORDS)
    for site, address, value in LITERALS:
        require(literal_offset(data, site), address, f"literal location at {site:#x}")
        require(u32(data, address), value, f"literal value at {address:#x}")
    for slot, entry in SLOTS.items():
        require(u32(data, VTABLE + slot), BASE + entry, f"provider slot {slot:#x}")
    require(
        data[DEFAULT : DEFAULT + RECORD_BYTES],
        pack("<I", 0xFFFFFFFF) + bytes(28),
        "default record",
    )
    for site, opcode, sign in ((0x636284, 0xE28F1000, 1), (0x636548, 0xE24F1000, -1)):
        word = u32(data, site)
        require(word & 0xFFFFF000, opcode, "diagnostic path ADR")
        require(site + 8 + sign * a32_immediate(word), CSV_PATH, "common CSV name")

    path = data[CSV_PATH : data.index(0, CSV_PATH)].decode("ascii")
    require(path, r"C:\DacLog.csv", "diagnostic CSV")
    first_column = data[CSV_HEADER : data.index(b",", CSV_HEADER)].decode("ascii")
    require(first_column, '"SerialNo(UID)"', "diagnostic CSV header")
    for offset in CSV_FORMATS.values():
        require(data[offset : offset + 7], b'\n"%ld",', "row first field")
    return {
        "calls": [list(edge) for edge in CALLS],
        "tail_branches": [list(edge) for edge in TAILS],
        "word_checks": len(WORDS),
        "literal_checks": [list(row) for row in LITERALS],
        "provider_slots": [
            {"slot": slot, "entry_file_offset": entry} for slot, entry in SLOTS.items()
        ],
        "range_sha256": [
            {"start": lo, "end_exclusive": hi, "sha256": sha256(data[lo:hi])}
            for lo, hi in RANGES
        ],
        "diagnostic": {
            "path": path,
            "path_file_offset": CSV_PATH,
            "first_column": first_column[1:-1],
            "header_file_offset": CSV_HEADER,
            "first_row_conversion": "%ld",
            "formatter_call_sites": [0x636300, 0x63655C],
            "header_to_common_writer": [0x636578, 0x6362AC],
        },
    }


def emulate(data):
    import unicorn as uc
    from unicorn import arm_const as arm

    vm = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    for address, size in (
        (BASE, 0x1000000),
        (0x40400000, 0x100000),
        (0x10000000, 0x100000),
    ):
        vm.mem_map(address, size)
    vm.mem_write(BASE, data[:0x1000000])
    manager, owner = 0x10010000, 0x10018000
    bulk_input, bulk_output = 0x10020000, 0x10020100
    app, message, controller, args = 0x10030000, 0x10060000, 0x10061000, 0x10062000
    stack, stop = 0x100F0000, 0x100F1000

    def read(address, size):
        return bytes(vm.mem_read(address, size))

    def word(address):
        return int.from_bytes(read(address, 4), "little")

    def write_word(address, value):
        vm.mem_write(address, pack("<I", value))

    def reg(name, value=None):
        index = getattr(arm, f"UC_ARM_REG_{name.upper()}")
        if value is None:
            return vm.reg_read(index)
        vm.reg_write(index, value)

    def run(entry, *argv, end=None, **registers):
        for name, value in dict(sp=stack, lr=stop, **registers).items():
            reg(name, value)
        for index, value in enumerate(argv):
            reg(f"r{index}", value)
        finish = stop if end is None else BASE + end
        vm.ctl_flush_tb()
        vm.emu_start(BASE + entry, finish, count=1000000)
        require(reg("pc"), finish, f"native boundary from {entry:#x}")
        return reg("r0")

    # The native manager and provider constructors execute. Only their owning
    # object locations and the manager pointer used by the registration slice are supplied.
    vm.mem_write(manager, bytes([0xA5]) * 0x2D0)
    run(0x6E80BC, manager)
    constructed_provider = run(0x76C240, end=0x76C248)
    require(constructed_provider, PROVIDER, "startup provider constructor result")
    write_word(owner + 4, manager)
    registered = run(0x76B510, end=0x76B520, r4=owner)
    require(registered, 1, "native registration result")
    require(word(PROVIDER), BASE + VTABLE, "constructed provider vtable")
    require(
        unpack("<103I", read(manager + 0x14, 103 * 4)),
        (PROVIDER,) + (0,) * 102,
        "only ID 0 registered",
    )
    require(run(0x6E7E9C, manager, 0), PROVIDER, "native manager lookup")
    require(read(manager + 0x2CA, 1), b"\0", "native constructor later-group gate")

    loads = []
    for marker in (0xFFFFFFFF, 0, MARKER):
        source_record = pack("<I", marker) + bytes([0x93]) * 28
        vm.mem_write(SOURCE, source_record)
        vm.mem_write(MIRROR - 1, bytes([0xCC]) * (RECORD_BYTES + 2))
        run(0x6E7EB0, manager)
        from_sector = marker == MARKER
        expected = (
            source_record if from_sector else data[DEFAULT : DEFAULT + RECORD_BYTES]
        )
        observed = read(MIRROR, RECORD_BYTES)
        require(observed, expected, "native marker branch copy")
        require(read(MIRROR - 1, 1), b"\xcc", "load pre-record canary")
        require(read(MIRROR + RECORD_BYTES, 1), b"\xcc", "load post-record canary")
        loads.append(
            {
                "injected_marker": marker,
                "selected_file_offset": SOURCE - BASE if from_sector else DEFAULT,
                "mirror_sha256": sha256(observed),
            }
        )

    values = (0x10203040, 0x21324354, 0x32435465, 0x43546576, 12345678)
    packed_values = pack("<5I", *values)
    vm.mem_write(bulk_input, packed_values)
    vm.mem_write(bulk_output - 1, bytes([0xA7]) * (len(packed_values) + 2))
    before = read(MIRROR, RECORD_BYTES)
    run(word(word(PROVIDER) + 0x2C) - BASE, PROVIDER, bulk_input)
    count = run(word(word(PROVIDER) + 0x30) - BASE, PROVIDER, bulk_output)
    require(count, 5, "native bulk result count")
    output = read(bulk_output, len(packed_values))
    require(output, packed_values, "native bulk words")
    require(read(bulk_output - 1, 1), b"\xa7", "bulk output pre-canary")
    require(read(bulk_output + len(output), 1), b"\xa7", "bulk output post-canary")
    provider_record = read(MIRROR, RECORD_BYTES)
    require(
        provider_record,
        before[:4] + packed_values + before[24:],
        "native bulk word window",
    )

    copy = app + COPY_OFFSET
    vm.mem_write(copy - 1, bytes([0x5A]) * (RECORD_BYTES + 2))
    run(0x82E3E4, manager, end=0x82E420, r4=app)
    copied_record = read(copy, RECORD_BYTES)
    require(copied_record, provider_record, "native application copy")
    write_word(controller + 8, app)
    write_word(message + 0x10, args)
    new_values = pack("<5I", *(value ^ 0x55AA55AA for value in values))
    vm.mem_write(args, new_values)
    run(0x74A9D0, controller, message)
    app_record = read(copy, RECORD_BYTES)
    require(
        app_record, before[:4] + new_values + before[24:], "native copy-only setter"
    )
    require(read(copy - 1, 1), b"\x5a", "copy pre-record canary")
    require(read(copy + RECORD_BYTES, 1), b"\x5a", "copy post-record canary")
    require(
        read(MIRROR, RECORD_BYTES), provider_record, "setter preserves provider mirror"
    )

    # Reuse the same manager and provider, with separate diagnostic slices
    # around unrelated timestamp and file I/O code.
    run(0x636038, manager, end=0x636048)
    require(word(stack + 4), PROVIDER, "native diagnostic ID 0 lookup")
    run(0x6362B8, end=0x6362C8)
    require(word(stack + 0x220), values[-1], "diagnostic fifth word")
    diagnostic = []
    for mode, format_offset in CSV_FORMATS.items():
        run(0x6362D0, 0x12, end=0x636300, r5=mode, r8=0, r9=0, r10=0, r11=0)
        require(reg("r1"), BASE + format_offset, "native row format pointer")
        require(reg("r2"), values[-1], "native row first vararg")
        diagnostic.append(
            {
                "injected_r5": mode,
                "format_file_offset": reg("r1") - BASE,
                "first_vararg_r2": reg("r2"),
            }
        )

    save = replay_save(vm, uc, manager, read, reg, run, provider_record)
    return {
        "unicorn_version": uc.__version__,
        "startup": {
            "constructed_provider_va": constructed_provider,
            "vtable_va": word(PROVIDER),
            "registration_result": registered,
            "manager_id_0_provider_va": word(manager + 0x14),
            "later_group_gate": read(manager + 0x2CA, 1)[0],
        },
        "loads": loads,
        "bulk": {"read_count": count, "words": list(unpack("<5I", output))},
        "application": {
            "record_offset": COPY_OFFSET,
            "after_copy_sha256": sha256(copied_record),
            "after_message_sha256": sha256(app_record),
            "words_after_message": list(unpack("<5I", app_record[4:24])),
            "provider_mirror_preserved": True,
        },
        "diagnostic_formatter_entry_arguments": diagnostic,
        "save": save,
    }


def replay_save(vm, uc, manager, read, reg, run, provider_record):
    expected_events = [0x599F20, 0x72C988, 0x599E88, 0x599914, 0x72C988, 0x599F6C]
    order = list(range(0x2F)) + [0x56, 0x57, 0x62] + list(range(0x39, 0x56))
    lookups, events, requests = [], [], []
    replacements = {
        0x599F20: "Return zero at the leading mailbox helper.",
        0x599F6C: "Return zero at the trailing mailbox helper.",
        0x72C988: "Return zero without executing the privileged CPU helper.",
        0x599914: "Capture sector arguments and staging bytes, then return the injected status without performing the write.",
    }

    def hook(_vm, address, _size, _user):
        offset = address - BASE
        if offset == 0x6E7E9C:
            require(reg("r0"), manager, "save uses the same manager")
            lookups.append(reg("r1"))
            return
        events.append(offset)
        if offset == 0x599E88:
            require(
                [reg("r1"), reg("r2"), reg("r3")],
                [SOURCE, MIRROR, RECORD_BYTES // 2],
                "ID 0 overlay call arguments",
            )
            return
        if offset == 0x72C988:
            require(reg("r0"), manager, "manager CPU helper argument")
            require(
                reg("r1"), 0 if events.count(offset) == 1 else 1, "CPU helper phase"
            )
        if offset == 0x599914:
            require(reg("r1"), SOURCE, "native save destination")
            require(reg("r2"), SECTOR_BYTES // 2, "native save halfword count")
            sector = read(SOURCE, SECTOR_BYTES)
            staged = read(STAGING, SECTOR_BYTES)
            require(
                staged,
                provider_record + sector[RECORD_BYTES:],
                "complete sector overlay",
            )
            requests.append(
                {
                    "destination_va": reg("r1"),
                    "halfword_count": reg("r2"),
                    "same_content": staged == sector,
                    "staging_sha256": sha256(staged),
                }
            )
            reg("r0", injected_status)
        else:
            reg("r0", 0)
        reg("pc", reg("lr"))

    for offset in (*replacements, 0x6E7E9C, 0x599E88):
        vm.hook_add(uc.UC_HOOK_CODE, hook, begin=BASE + offset, end=BASE + offset)

    # A patterned source and differently poisoned staging region detect
    # skipped copies, zeros substituted for reads, and off-by-one writes.
    original_prefix = read(SOURCE, RECORD_BYTES)
    tail = shake_256(b"K-3 II sector 14 staging canary").digest(SECTOR_BYTES)[
        RECORD_BYTES:
    ]
    for injected_status, same in (
        (0, False),
        (1, False),
        (2, False),
        (3, False),
        (0, True),
    ):
        prefix = provider_record if same else original_prefix
        sector = prefix + tail
        vm.mem_write(SOURCE, sector)
        vm.mem_write(STAGING - 1, bytes([0xA6]) * (SECTOR_BYTES + 2))
        lookups.clear()
        events.clear()
        count_before = len(requests)
        returned_status = run(0x6E8528, manager)
        require(returned_status, injected_status, "native save returns backend status")
        require(len(requests), count_before + 1, "one sector request")
        require(
            requests[-1]["same_content"], same, "prepared equal or differing sector"
        )
        require(lookups, order, "complete first-sector provider lookup order")
        require(
            events,
            expected_events,
            "native overlay and substituted boundary order",
        )
        require(read(STAGING - 1, 1), b"\xa6", "sector staging pre-canary")
        require(read(STAGING + SECTOR_BYTES, 1), b"\xa6", "sector staging post-canary")
        require(
            read(SOURCE, SECTOR_BYTES),
            sector,
            "stubbed backend leaves source image unchanged",
        )
        require(
            read(MIRROR, RECORD_BYTES),
            provider_record,
            "save preserves provider mirror",
        )
        requests[-1].update(
            injected_backend_status=injected_status,
            manager_return=returned_status,
        )
    return {
        "entry_file_offset": 0x6E8528,
        "request_entry_file_offset": 0x599914,
        "staging_va": STAGING,
        "registered_provider_ids": [0],
        "provider_lookup_order": lookups.copy(),
        "overlay_call_count": events.count(0x599E88),
        "overlay_bytes": RECORD_BYTES,
        "boundary_order": events,
        "execution_replacements": {
            f"0x{offset:x}": role for offset, role in replacements.items()
        },
        "requests": requests,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    data = load_image(args.decoded)
    result = {
        "firmware_version": "1.12",
        "decoded_sha256": sha256(data),
        "image_base": BASE,
        "sector_index": SECTOR,
        "sector_bytes": SECTOR_BYTES,
        "sector_file_offset": SOURCE - BASE,
        "sector_va": SOURCE,
        "record_bytes": RECORD_BYTES,
        "mirror_va": MIRROR,
        "static": verify_static(data),
        "replay": emulate(data),
        "scope": [
            "Runs bounded original A32 slices in synthetic RAM with a prepared owner, manager, application and message.",
            "Replaces the mapped sector bytes with synthetic marker records and save canaries. Outputs hashes and scalars only.",
            "Stops before formatting the CSV row. Filename, header and path back to the common writer are static evidence.",
            "The CSV column label identifies the field's firmware export role. Physical UID identity, live diagnostic reachability, media writes and retention are outside the replay.",
            "Exercises the first sector group with only ID 0 registered and the original constructor's later-group gate clear.",
        ],
    }
    output = json.dumps(result, indent=2)
    if args.compare:
        require_snapshot(result, args.compare, "snapshot replay")
    print(output)


if __name__ == "__main__":
    main()
