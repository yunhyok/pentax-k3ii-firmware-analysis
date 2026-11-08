"""Replay preserved sectors 20/21, their pixel-policy input and ID63 block methods.

SPDX-License-Identifier: GPL-2.0-only
"""

from hashlib import shake_256
from pathlib import Path
from struct import pack
import json
import argparse
import hashlib
import unicorn as uc
from unicorn import arm_const as arm

from verify_findings import require, require_snapshot, sha256
from verify_tone_path import BASE, check_edge, check_words, load_image


STAGING = 0x40459204
SECTORS = (0x02280000, 0x022A0000)
SECTOR_BYTES = 0x20000
RAM = 0x80000000
MARKER = 0xA55A5AA5
PROVIDERS = (
    # ID, object VA, table offset, range offset in sector, bytes, startup slice
    (0x63, 0x4040AF5C, 0xA71C84, 0, 0x10000, 0x76C704),
    (0x64, 0x4040AF60, 0xA731FC, 0x10000, 0xE000, 0x76C718),
    (0x65, 0x4040AF64, 0xA73828, 0x1E000, 0x2000, 0x76C72C),
)
VTABLE_SLOTS = (
    (0x72E190, 0x72E198, 0x72E1A0, 0x72E1A8, 0x72E1B8, 0x72E1C8, 0x72E1D0, 0x72E1D8),
    (0x72DF78, 0x72DF80, 0x72DF88, 0x72DF90, 0x72DFA0, 0x72DFB0, 0x72DFB8, 0x72DFC0),
    (0x599730, 0x599738, 0x599740, 0x599748, 0x599758, 0x599768, 0x599770, 0x599778),
)


def check_source(data):
    calls = {
        0x76C708: 0x72E168,
        0x76C71C: 0x72DF50,
        0x76C730: 0x599708,
        0x76B8EC: 0x6E9494,
        0x76B8FC: 0x6E9494,
        0x76B90C: 0x6E9494,
        0x6E7F1C: 0x6E7E9C,
        0x6E8C2C: 0x599D18,
        0x6E8DA4: 0x599D18,
        0x6E8C38: 0x6E7E9C,
        0x6E8C98: 0x6E7E9C,
        0x6E8CF8: 0x6E7E9C,
        0x6E8DB0: 0x6E7E9C,
        0x6E8E10: 0x6E7E9C,
        0x6E8E70: 0x6E7E9C,
        0x6E8C8C: 0x599E88,
        0x6E8CEC: 0x599E88,
        0x6E8D4C: 0x599E88,
        0x6E8E04: 0x599E88,
        0x6E8E64: 0x599E88,
        0x6E8EC4: 0x599E88,
        0x6E8D58: 0x599D6C,
        0x6E8ED0: 0x599D6C,
        0x599D5C: 0x5999C0,
        0x599DB0: 0x599914,
        0x599EA0: 0x599A90,
        0x599EB4: 0x599AE8,
        0x599EC4: 0x599B20,
        0x65EA94: 0x74F9BC,
        0x74F9C8: 0x72E1E0,
        0x74F9CC: 0x72E004,
        0x74F9E8: 0x72DFC8,
        0x74F9EC: 0x72DDEC,
    }
    tails = (0x72E1B4, 0x72E1C4, 0x72DF9C, 0x72DFAC, 0x599754, 0x599764)
    for site, target in calls.items():
        check_edge(data, site, target)
    for site in tails:
        check_edge(data, site, 0x712898, link=False)
    words = {
        0x76C038: 0x4040AF5C,
        0x76C03C: 0x4040AF60,
        0x76C040: 0x4040AF64,
        0x72E208: MARKER,
        0x72E210: 0x022A0000,
        0x72E214: RAM,
        0x72E218: 0x02280000,
        0x72DFF0: MARKER,
        0x72DFF8: 0x022B0000,
        0x72DFFC: RAM + 0x10000,
        0x72E000: 0x02290000,
        0x5997A8: MARKER,
        0x5997B0: 0x022BE000,
        0x5997B4: RAM + 0x1E000,
        0x5997B8: 0x0229E000,
        0x72E1AC: 0xE3A02801,
        0x72E1BC: 0xE3A02801,
        0x72E1D8: 0xE3A00902,
        0x72DF94: 0xE3A02A0E,
        0x72DFA4: 0xE3A02A0E,
        0x72DFC0: 0xE3A00A07,
        0x59974C: 0xE3A02A02,
        0x59975C: 0xE3A02A02,
        0x599778: 0xE3A00A01,
        0x5999E0: 0xE1C540B0,
        0x599EF4: 0xE1C620B0,
        0x59A020: BASE + 0x9D4BE4,
        0x59A024: BASE + 0x9D49E0,
        0x59A028: STAGING,
        0x9D49E0 + 4 * 20: SECTORS[0],
        0x9D49E0 + 4 * 21: SECTORS[1],
        0x9D49E0 + 4 * 22: 0x022C0000,
        0x9D4BE4 + 4 * 20: SECTOR_BYTES // 2,
        0x9D4BE4 + 4 * 21: SECTOR_BYTES // 2,
        0x6E8F08: SECTORS[1],
        0x65EAA0: 0xE5C4004A,
        0x6E7F40: 0x1590101C,
        0x6E7F44: 0x05901018,
        0x6E7F4C: 0xE12FFF31,
    }
    for provider, slots in zip(PROVIDERS, VTABLE_SLOTS):
        table = provider[2]
        words.update(
            {table + 0xC + 4 * i: BASE + entry for i, entry in enumerate(slots)}
        )
    check_words(data, words)
    return {"branches": len(calls) + len(tails), "words": len(words)}


def emulate_storage(data):
    checks = check_source(data)
    vm = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    for address, size in (
        (BASE, 0x1000000),
        (0x40400000, 0x100000),
        (0x10000000, 0x100000),
        (RAM - 0x1000, SECTOR_BYTES + 0x2000),
    ):
        vm.mem_map(address, size)
    vm.mem_write(BASE, data[:0x1000000])
    manager, owner, storage, capture, cfg = range(0x10010000, 0x10060000, 0x10000)
    stack, sentinel = 0x100F0000, 0x100F1000

    def read(address, size):
        return bytes(vm.mem_read(address, size))

    def word(address):
        return int.from_bytes(read(address, 4), "little")

    def put(address, value, size=4):
        vm.mem_write(address, value.to_bytes(size, "little"))

    def reg(name, value=None):
        index = getattr(arm, "UC_ARM_REG_" + name.upper())
        if value is None:
            return vm.reg_read(index)
        vm.reg_write(index, value)

    def run(entry, *args, end=None, **regs):
        for name, value in dict(sp=stack, lr=sentinel, **regs).items():
            reg(name, value)
        for index, value in enumerate(args):
            reg(f"r{index}", value)
        stop = sentinel if end is None else BASE + end
        vm.ctl_flush_tb()
        vm.emu_start(BASE + entry, stop, count=3000000)
        require(reg("pc"), stop, f"native stop from {entry:#x}")
        return reg("r0")

    def make_manager(address, ids):
        vm.mem_write(address, bytes([0xA5]) * 0x2D0)
        run(0x6E80BC, address)
        put(address + 4, storage)
        put(owner + 4, address)
        if ids == (0x63, 0x64, 0x65):
            run(0x76B8E0, end=0x76B910, r4=owner)
        else:
            for idx, provider in enumerate(PROVIDERS):
                if provider[0] in ids:
                    entry = 0x76B8E0 + 0x10 * idx
                    run(entry, end=entry + 0x10, r4=owner)
        expected = {key: obj for key, obj, *_ in PROVIDERS if key in ids}
        require(
            [word(address + 0x14 + 4 * key) for key in range(0x67)],
            [expected.get(key, 0) for key in range(0x67)],
            "exact native registration table",
        )

    for key, obj, table, offset, size, startup in PROVIDERS:
        require(run(startup, end=startup + 8), obj, f"startup constructor ID {key:#x}")
        require(word(obj), BASE + table, f"original vtable ID {key:#x}")
        for slot, expected in (
            (0x20, RAM + offset),
            (0x24, SECTORS[1] + offset),
            (0x28, size // 2),
        ):
            require(
                run(word(word(obj) + slot) - BASE, obj),
                expected,
                f"native vtable slot {key:#x}/{slot:#x}",
            )

    all_ids = (0x63, 0x64, 0x65)
    make_manager(manager, all_ids)
    make_manager(manager + 0x400, (0x63, 0x65))
    make_manager(manager + 0x800, (0x63, 0x64))

    calls, staging_writes, base_copies = [], [], []
    ram_marker_reads = []

    def observe_call(_vm, pc, _size, _user):
        calls.append((pc - BASE, *(reg(f"r{i}") for i in range(4))))
        if pc - BASE == 0x599E88 and not base_copies:
            base_copies.append(read(STAGING, SECTOR_BYTES))

    def observe_staging(_vm, _kind, address, size, _value, _user):
        pc = reg("pc") - BASE
        if (
            not staging_writes
            or (staging_writes[-1][0] == 0x5999E0 and pc == 0x599EF4)
            or (pc == 0x599EF4 and address - STAGING in (0x10000, 0x1E000))
        ):
            staging_writes.append([pc, address - STAGING, 0])
        span = staging_writes[-1]
        require(
            (pc, address - STAGING, size),
            (span[0], span[1] + 2 * span[2], 2),
            "contiguous native staging halfword store",
        )
        span[2] += 1

    def observe_marker(_vm, _kind, address, size, _value, _user):
        ram_marker_reads.append((reg("pc") - BASE, address, size, word(address)))

    for off in (0x712898, 0x6E7E9C, 0x599D18, 0x599E88, 0x599D6C):
        vm.hook_add(uc.UC_HOOK_CODE, observe_call, begin=BASE + off, end=BASE + off)
    vm.hook_add(
        uc.UC_HOOK_MEM_WRITE,
        observe_staging,
        begin=STAGING - 1,
        end=STAGING + SECTOR_BYTES,
    )
    for address in (RAM, RAM + 0x10000):
        vm.hook_add(uc.UC_HOOK_MEM_READ, observe_marker, begin=address, end=address + 3)

    def prepare_flash(label, markers):
        banks = []
        for bank, start in enumerate(SECTORS):
            raw = bytearray(
                shake_256(f"sector{bank}:{label}".encode()).digest(SECTOR_BYTES)
            )
            for provider, valid in zip(PROVIDERS, markers[bank]):
                offset = provider[3]
                raw[offset : offset + 4] = pack(
                    "<I", MARKER if valid else (0xFFFFFFFF if bank else 0)
                )
            banks.append(bytes(raw))
            vm.mem_write(start, banks[-1])
        return banks

    load_cases = []
    for label, markers in (
        ("all_primary", ((1, 1, 1), (0, 0, 0))),
        ("all_backup", ((0, 0, 0), (1, 1, 1))),
        ("mixed_first_and_third_backup", ((0, 0, 0), (1, 0, 1))),
        ("mixed_only_second_backup", ((0, 0, 1), (0, 1, 0))),
        ("all_both_valid", ((1, 1, 1), (1, 1, 1))),
        ("all_invalid", ((0, 0, 0), (0, 0, 0))),
    ):
        banks = prepare_flash(label, markers)
        vm.mem_write(RAM - 1, bytes([0xD3]) * (SECTOR_BYTES + 2))
        calls.clear()
        run(0x6E7EB0, manager)
        copy_calls = [
            (pc, dst, src, size) for pc, dst, src, size, _ in calls if pc == 0x712898
        ]
        expected_copies, chunks, loaded_markers = [], [], []
        for idx, (_, _, _, offset, size, _) in enumerate(PROVIDERS):
            bank = markers[1][idx]
            expected_copies.append(
                (0x712898, RAM + offset, SECTORS[bank] + offset, size)
            )
            chunks.append(banks[bank][offset : offset + size])
            loaded_markers.append(
                MARKER if markers[bank][idx] else (0xFFFFFFFF if bank else 0)
            )
        require(
            copy_calls, expected_copies, "ordered original primary/backup copy calls"
        )
        mirror = read(RAM, SECTOR_BYTES)
        require(mirror, b"".join(chunks), "complete native RAM provider span")
        require(
            read(RAM - 1, 1) + read(RAM + SECTOR_BYTES, 1),
            b"\xd3\xd3",
            "mirror canaries",
        )
        for start, bank in zip(SECTORS, banks):
            require(
                read(start, SECTOR_BYTES),
                bank,
                "loader leaves flash fixtures unchanged",
            )

        put(stack, cfg)
        # Valid prepared fields; the marker helpers obtain fixed RAM addresses.
        put(cfg + 4, 0x10040000)
        put(cfg + 8, 0x10040040)
        policy_cases = []
        for config_byte in (0, 7):
            put(cfg + 0xC, config_byte, 1)
            put(capture + 0x4A, 0xA5, 1)
            ram_marker_reads.clear()
            run(0x65EA90, end=0x65EAA4, r4=capture)
            observed = read(capture + 0x4A, 1)[0]
            expected = int(bool(config_byte) and loaded_markers[:2] == [MARKER, MARKER])
            require(
                observed, expected, "capture policy reads same native-loaded mirrors"
            )
            require(
                ram_marker_reads,
                [
                    (0x72E004, RAM, 4, loaded_markers[0]),
                    (0x72DDEC, RAM + 0x10000, 4, loaded_markers[1]),
                ],
                "exact native policy marker loads",
            )
            policy_cases.append(
                {
                    "configuration_byte": config_byte,
                    "flag_4a": observed,
                    "marker_reads": list(ram_marker_reads),
                }
            )
        load_cases.append(
            {
                "case": label,
                "injected_marker_valid": markers,
                "flash_sha256": [sha256(bank) for bank in banks],
                "copy_calls": copy_calls,
                "mirror_sha256": sha256(mirror),
                "policy_cases": policy_cases,
            }
        )

    # Leave the native-loaded all-invalid mirrors intact. Reseed different flash
    # data for each sector; save staging must now copy and selectively overlay.
    banks = prepare_flash("staging source", ((1, 1, 1), (1, 1, 1)))
    staging_cases = []
    packet_update = None
    for name, active_manager, ids in (
        ("all_providers", manager, all_ids),
        ("no_id_64", manager + 0x400, (0x63, 0x65)),
        ("no_id_65", manager + 0x800, (0x63, 0x64)),
        ("native_id63_packet0_update", manager, all_ids),
    ):
        if name == "native_id63_packet0_update":
            packet_va = 0x10090000
            body = shake_256(b"ID63 packet linked to both save sectors").digest(2048)
            packet = pack("<II", 0, 0x12345678) + body
            vm.mem_write(packet_va - 4, b"\xa5" * 4 + packet + b"\xa5" * 4)
            require(
                run(0x72E0EC, RAM, packet_va),
                RAM,
                "native packet setter returns mirror pointer",
            )
            expected_mirror = bytearray(mirror)
            expected_mirror[4:6] = pack("<H", 0x5678)
            expected_mirror[0x10:0x810] = body
            require(
                read(RAM, SECTOR_BYTES),
                bytes(expected_mirror),
                "native packet updates exact fields in loaded mirror",
            )
            require(
                read(packet_va - 4, len(packet) + 8),
                b"\xa5" * 4 + packet + b"\xa5" * 4,
                "native setter preserves packet and canaries",
            )
            packet_update = {
                "entry": 0x72E0EC,
                "packet_index": 0,
                "input_header_word": 0x12345678,
                "stored_halfword": 0x5678,
                "payload_words": 512,
                "before_mirror_sha256": sha256(mirror),
                "after_mirror_sha256": sha256(expected_mirror),
                "execution_replacements": [],
            }
            mirror = bytes(expected_mirror)
        for bank, entry in enumerate((0x6E8C24, 0x6E8D98)):
            start = SECTORS[bank]
            vm.mem_write(
                STAGING - 1,
                shake_256(f"poison:{name}:{bank}".encode()).digest(SECTOR_BYTES + 2),
            )
            canaries = read(STAGING - 1, 1) + read(STAGING + SECTOR_BYTES, 1)
            calls.clear()
            staging_writes.clear()
            base_copies.clear()
            run(entry, end=0x599914, r4=active_manager)
            require(
                (reg("r0"), reg("r1"), reg("r2")),
                (storage, start, SECTOR_BYTES // 2),
                "native lower request entry",
            )
            require(
                [
                    (pc, r0, r1)
                    for pc, r0, r1, _, _ in calls
                    if pc in (0x599D18, 0x599D6C)
                ],
                [
                    (0x599D18, storage, start),
                    (0x599D6C, storage, start),
                ],
                "native staging and upper request use same sector",
            )
            require(
                [(r0, r1) for pc, r0, r1, _, _ in calls if pc == 0x6E7E9C],
                [(active_manager, key) for key in all_ids],
                "native overlay lookup order",
            )
            require(
                base_copies,
                [banks[bank]],
                "full original sector copy before any overlay",
            )
            expected = bytearray(banks[bank])
            overlay_args = []
            expected_writes = [[0x5999E0, 0, SECTOR_BYTES // 2]]
            for key, _, _, offset, size, _ in PROVIDERS:
                if key in ids:
                    expected[offset : offset + size] = mirror[offset : offset + size]
                    overlay_args.append(
                        (storage, SECTORS[1] + offset, RAM + offset, size // 2)
                    )
                    expected_writes.append([0x599EF4, offset, size // 2])
            require(
                [(r0, r1, r2, r3) for pc, r0, r1, r2, r3 in calls if pc == 0x599E88],
                overlay_args,
                "native overlay always uses provider backup-address getter",
            )
            require(staging_writes, expected_writes, "exact native staging write spans")
            staged = read(STAGING, SECTOR_BYTES)
            require(staged, bytes(expected), "whole native staging sector")
            require(
                read(STAGING - 1, 1) + read(STAGING + SECTOR_BYTES, 1),
                canaries,
                "staging canaries",
            )
            require(
                read(RAM, SECTOR_BYTES),
                mirror,
                "save does not mutate native-loaded mirrors",
            )
            for src, image in zip(SECTORS, banks):
                require(
                    read(src, SECTOR_BYTES),
                    image,
                    "stop before write preserves both source banks",
                )
            staging_cases.append(
                {
                    "case": name,
                    "entry": entry,
                    "sector_index": 20 + bank,
                    "destination": start,
                    "request_halfwords": reg("r2"),
                    "overlay_args": overlay_args,
                    "write_spans_pc_offset_halfwords": [
                        span.copy() for span in staging_writes
                    ],
                    "base_copy_sha256": sha256(base_copies[0]),
                    "staged_sha256": sha256(staged),
                }
            )

    return {
        "decoded_sha256": sha256(data),
        "code_va_base": BASE,
        "unicorn_version": uc.__version__,
        "static_checks": checks,
        "execution_replacements": [],
        "providers": [
            {
                "id": key,
                "object_va": obj,
                "vtable_offset": table,
                "ram_va": RAM + offset,
                "primary_flash_va": SECTORS[0] + offset,
                "backup_flash_va": SECTORS[1] + offset,
                "bytes": size,
                "constructor_slice": [startup, startup + 8],
            }
            for key, obj, table, offset, size, startup in PROVIDERS
        ],
        "boundaries": {
            "native_registry": [0x76B8E0, 0x76B910],
            "manager_load_entry": 0x6E7EB0,
            "policy_marker_slice": [0x65EA90, 0x65EAA4],
            "staging_end_exclusive": 0x599914,
            "synthetic_leaf_return_va": sentinel,
        },
        "load_cases": load_cases,
        "staging_cases": staging_cases,
        "native_packet_update_before_last_two_stages": packet_update,
    }


def emulate_chunks(data):
    vm = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    for start, size in (
        (BASE, 0x1000000),
        (0x10000000, 0x100000),
        (0x80000000, 0x20000),
    ):
        vm.mem_map(start, size)
    vm.mem_write(BASE, data[:0x1000000])
    record, source, output = 0x80000000, 0x10010000, 0x10020000
    stack, stop = 0x100F0000, 0x100F1000

    def reg(name, value=None):
        key = getattr(arm, "UC_ARM_REG_" + name.upper())
        if value is None:
            return vm.reg_read(key)
        vm.reg_write(key, value)

    def run(entry, *args, end=None):
        reg("sp", stack)
        reg("lr", stop)
        for i, value in enumerate(args):
            reg(f"r{i}", value)
        finish = stop if end is None else BASE + end
        vm.ctl_flush_tb()
        vm.emu_start(BASE + entry, finish, count=100000)
        require(reg("pc"), finish, f"original chunk boundary {entry:x}")
        return reg("r0")

    def read(address, size):
        return bytes(vm.mem_read(address, size))

    check_words(
        data,
        {
            0x72E064: 0xE3032FFC,
            0x72E08C: 0xE5854010,
            0x72E0CC: 0xE5955010,
            0x72E114: 0xE6FF1070,
        },
    )
    for site, target, link in (
        (0x72E10C, 0x72E058, False),
        (0x72E11C, 0x72E048, True),
        (0x72E148, 0x72E09C, False),
        (0x72E14C, 0x72E050, True),
        (0x72E15C, 0x72E09C, True),
    ):
        check_edge(data, site, target, link=link)
    baseline = hashlib.shake_256(b"ID63 complete record before chunks").digest(0x20000)
    vm.mem_write(record, baseline)
    expected = bytearray(baseline)
    rows = []
    for index in range(32):
        payload = hashlib.shake_256(f"ID63 chunk {index}".encode()).digest(2048)
        vm.mem_write(source - 4, b"\xA5" * 4 + payload + b"\xA5" * 4)
        require(
            run(0x72E058, record, source, index),
            record,
            "chunk writer returns record pointer",
        )
        count = min(512, 0x3FFC - index * 512)
        off = 16 + index * 2048
        expected[off : off + count * 4] = payload[: count * 4]
        require(
            read(record, 0x20000),
            bytes(expected),
            "complete record and adjacent RAM after write",
        )
        require(
            read(source - 4, 2056),
            b"\xA5" * 4 + payload + b"\xA5" * 4,
            "chunk input unchanged",
        )
        vm.mem_write(output - 4, b"\xB6" * 2056)
        returned = run(0x72E09C, record, output, index)
        require(returned, count, "chunk read returns word count")
        require(
            read(record, 0x20000),
            bytes(expected),
            "reader preserves record and adjacent RAM",
        )
        require(
            read(output - 4, 2056),
            b"\xB6" * 4 + payload[: count * 4] + b"\xB6" * (2052 - count * 4),
            "readback and complete output canary",
        )
        rows.append(
            {
                "index": index,
                "words": count,
                "record_offset": off,
                "payload_sha256": sha256(payload[: count * 4]),
            }
        )

    packet_rows = []
    for index in (0, 1, 31):
        payload = hashlib.shake_256(f"ID63 packet {index}".encode()).digest(2048)
        packet = (
            index.to_bytes(4, "little")
            + (b"\x78\x56\x34\x12" if index == 0 else b"")
            + payload
        )
        vm.mem_write(source, packet)
        before = read(record, 0x20000)
        require(
            run(0x72E0EC, record, source),
            record,
            "packet writer returns record pointer",
        )
        wanted = bytearray(before)
        count = min(512, 0x3FFC - index * 512)
        if index == 0:
            wanted[4:6] = b"\x78\x56"
        off = 16 + index * 2048
        wanted[off : off + count * 4] = payload[: count * 4]
        require(
            read(record, 0x20000), bytes(wanted), "packet setter exact complete record"
        )
        vm.mem_write(output - 4, b"\xC7" * 2060)
        vm.mem_write(output + 4, index.to_bytes(4, "little"))
        out_before = read(output - 4, 2060)
        returned = run(0x72E130, record, output)
        result = (b"\x78\x56\0\0" if index == 0 else b"") + payload[: count * 4]
        require(returned, count + (index == 0), "packet returned word count")
        require(
            read(record, 0x20000),
            bytes(wanted),
            "packet reader preserves record and adjacent RAM",
        )
        require(
            read(output - 4, 2060),
            out_before[:4] + result + out_before[4 + len(result) :],
            "packet reader exact fields and untouched tail",
        )
        packet_rows.append(
            {
                "index": index,
                "count_words": returned,
                "header_halfword": 0x5678 if index == 0 else None,
                "readback_sha256": sha256(result),
            }
        )

    before = read(record, 0x20000)
    run(0x72E058, record, source, 32, end=0x72E08C)
    require(
        reg("r5") + 0x10,
        record + 0x10010,
        "index32 calculated first store outside ID63 span",
    )
    require(reg("ip"), 0xFFFFFFFC, "index32 unsigned loop limit underflow")
    require(read(record, 0x20000), before, "stop before first out-of-span store")
    return {
        "decoded_sha256": sha256(data),
        "direct_chunk_cases": rows,
        "packet_cases": packet_rows,
        "execution_replacements": [],
        "index32_prefix": {
            "start": 0x72E058,
            "stop_before": 0x72E08C,
            "first_store_va": record + 0x10010,
            "loop_limit_words": 0xFFFFFFFC,
            "store_executed": False,
        },
        "limits": [
            "Synthetic RAM only; no physical calibration or provider save.",
            "Index32 stops before its first store, not a complete function run. Upstream packet validation is outside this probe.",
            "Only ID63 64KiB methods are tested; no claim that ID64 uses these same size constants.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    data = load_image(args.decoded)
    result = {
        "schema_version": 1,
        "firmware_version": "1.12",
        "decoded_sha256": sha256(data),
        "storage": emulate_storage(data),
        "id63_chunks": emulate_chunks(data),
        "limits": [
            "Flash sectors, RAM, owner/manager storage links, capture and config are synthetic. Native constructor and registry slices omit startup/destructor/synchronization work.",
            "Policy slice65EA90..65EAA4 checks the original initial4A store on loaded mirrors, not later policy overrides or live capture.",
            "Save slices start after mailbox/CPU prelude and stop before599914; backend write, save return and physical flash are not executed.",
            "The packet0 update modifies the same native-loaded mirror before two staging replays. It does not validate packet provenance or mark a record valid.",
            "ID63 chunk and packet boundary controls use a separate synthetic object. Index32 stops before its first out-of-span store; upstream validation/reachability remains unverified.",
            "No physical units or calibration interpretation are assigned to the record contents.",
        ],
    }
    if args.compare:
        require_snapshot(result, args.compare, "preserved sector20/21 replay")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
