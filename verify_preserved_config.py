"""Replay native preserved-provider validation and its initial capture-policy consumer.

SPDX-License-Identifier: GPL-2.0-only
"""

from pathlib import Path
from struct import pack
import json
import argparse
import unicorn as uc
from unicorn import arm_const as arm

from verify_findings import require, require_snapshot, sha256
from verify_tone_path import BASE, check_edge, check_words, load_image


SERVICE_OWNER = 0x4047D108
MANAGER_OWNER = 0x4040B0EC
MARKER = 0xA55A5AA5
RAM = (0x80000000, 0x80010000)
PRIMARY = (0x02280000, 0x02290000)
BACKUP = (0x022A0000, 0x022B0000)
PROVIDERS = (0x4040AF58, 0x4040AF5C, 0x4040AF60)
# The ctor assigns these groups, capacities and data index lists.
CAPACITY = (
    0x4C0,
    0x4C0,
    0x2590,
    0x2590,
    0x5490,
    0x5490,
    0x13C0,
    0x13C0,
    0x13C0,
    0x13C0,
    0x9E0,
    0x9E0,
    0x9E0,
    0x9E0,
    0x9E0,
    0x9E0,
    0x9E0,
    0x9E0,
    0x6DF0,
    0x6DF0,
    0x14E0,
    0x14E0,
    0x21E0,
    0x21E0,
    0x13C0,
    0x13C0,
)
GROUPS = (tuple(range(6)), (*range(6, 18), 24, 25))


def check_source(data):
    calls = {
        0x76C6F4: 0x73EEA8,
        0x76C708: 0x72E168,
        0x76C71C: 0x72DF50,
        0x76B8DC: 0x6E9494,
        0x76B8EC: 0x6E9494,
        0x76B8FC: 0x6E9494,
        0x565C90: 0x565BC8,
        0x5660AC: 0x712828,
        0x5660B0: 0x74E598,
        0x74ED5C: 0x76B478,
        0x74ED60: 0x785804,
        0x74ED6C: 0x6E7E9C,
        0x74ED7C: 0x6E7E9C,
        0x74ED88: 0x74EBF0,
        0x74EBFC: 0x72E1E0,
        0x74EC00: 0x72E0E4,
        0x74EC60: 0x72DFC8,
        0x74EC64: 0x72DECC,
        0x74ECC4: 0x72E004,
        0x74ECD4: 0x72DDEC,
        0x74EA18: 0x74E8D0,
        0x74EA68: 0x74E8D0,
        0x74EBD8: 0x74EA34,
        0x74EBE4: 0x74E9E4,
        0x74EE38: 0x74EA34,
        0x74EE44: 0x74E9E4,
        0x635568: 0x74F974,
        0x635F80: 0x74ED98,
        0x7B5130: 0x74ED98,
        0x65EA70: 0x565C68,
        0x65EA74: 0x78595C,
        0x65EA94: 0x74F9BC,
        0x593740: 0x565C68,
        0x593744: 0x78595C,
        0x593748: 0x74F9F8,
    }
    tails = {0x74ECEC: 0x74EA84, 0x74F988: 0x754B64}
    for table, link in ((calls, True), (tails, False)):
        for site, target in table.items():
            check_edge(data, site, target, link=link)
    words = {
        0x5668AC: 0x4040B7A4,
        0x5668B0: SERVICE_OWNER,
        0x76BF30: MANAGER_OWNER,
        0x76BF2C: 0x4040AE64,
        0x76C034: PROVIDERS[0],
        0x76C038: PROVIDERS[1],
        0x76C03C: PROVIDERS[2],
        0x5660A8: 0xE3A00F89,
        0x5660B4: 0xE584003C,
        0x5660C4: 0xE12FFF32,
        0x5666FC: 0xE594003C,
        0x566704: 0xE591200C,
        0x56670C: 0xE12FFF32,
        0x74ECF0: BASE + 0xA76A04,
        0xA76A0C: BASE + 0x74E8C8,
        0xA76A10: BASE + 0x74ED54,
        0x74E5B8: 0xE5C0600C,
        0x74E5BC: 0xE5C0600D,
        0x74ED70: 0xE5840004,
        0x74ED80: 0xE5840008,
        0x74EC08: 0xE5840010,
        0x74EC6C: 0xE5840014,
        0x74ECDC: 0x08BD81F0,
        0x74EBDC: 0xE5C4000C,
        0x74EBE8: 0xE5C4000D,
        0x74EE3C: 0xE5C4000C,
        0x74EE48: 0xE5C4000D,
        0x74E8F4: 0x8A000013,
        0x74E9AC: 0xE1500004,
        0x78595C: 0xE590003C,
        0x74F9D4: 0x15D4000C,
        0x74FA10: 0x15D4000D,
        0x65EAA0: 0xE5C4004A,
    }
    check_words(data, words)
    return {"branches": len(calls) + len(tails), "words": len(words)}


def probe(data):
    static = check_source(data)
    vm = uc.Uc(uc.UC_ARCH_ARM, uc.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    for address, size in (
        (BASE, 0x1000000),
        (0x40400000, 0x100000),
        (0x10000000, 0x100000),
        (0x40106000, 0x1000),
        (RAM[0], 0x20000),
    ):
        vm.mem_map(address, size)
    vm.mem_write(BASE, data[:0x1000000])
    manager, config, capture = 0x10010000, 0x10020000, 0x10030000
    stack, sentinel = 0x100F0000, 0x100F1000

    def read(address, size=4):
        return bytes(vm.mem_read(address, size))

    def word(address):
        return int.from_bytes(read(address), "little")

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
        try:
            vm.emu_start(BASE + entry, stop, count=1_000_000)
        except uc.UcError as e:
            raise ValueError(f"{entry:#x} stopped at VA {reg('pc'):#x}") from e
        require(reg("pc"), stop, f"native stop from {entry:#x}")
        return reg("r0")

    run(0x565BC8, SERVICE_OWNER)
    require(word(SERVICE_OWNER + 0x3C), 0, "native singleton ctor null pointer")
    run(0x6E80BC, manager)
    put(MANAGER_OWNER + 4, manager)
    for guard in (0x4040B7A4, 0x4040AE64, 0x4041D97C):
        put(guard, 1)
    for entry, obj in zip((0x76C6F0, 0x76C704, 0x76C718), PROVIDERS):
        require(run(entry, end=entry + 8), obj, "native provider startup slice")
    run(0x76B8D0, end=0x76B900, r4=MANAGER_OWNER)
    require(
        [word(manager + 0x14 + 4 * key) for key in (0x62, 0x63, 0x64)],
        list(PROVIDERS),
        "native provider table",
    )

    config_writes, flag_writes, consumers, validates = [], [], [], []

    def observe_write(_vm, _kind, address, size, value, _user):
        pc = reg("pc") - BASE
        if address == capture + 0x4A:
            flag_writes.append((pc, size, value))
        else:
            config_writes.append((pc, address - config, size, value))

    def observe_consumer(_vm, pc, _size, _user):
        consumers.append((pc - BASE, reg("r0")))

    def observe_validation(_vm, _pc, _size, _user):
        validates.append((reg("r1") - config - 0x18) // 0x10)

    vm.hook_add(
        uc.UC_HOOK_MEM_WRITE, observe_write, begin=config + 0xC, end=config + 0xD
    )
    vm.hook_add(
        uc.UC_HOOK_MEM_WRITE, observe_write, begin=capture + 0x4A, end=capture + 0x4A
    )
    for pc in (0x78595C, 0x74F9BC, 0x74F9F8):
        vm.hook_add(uc.UC_HOOK_CODE, observe_consumer, begin=BASE + pc, end=BASE + pc)
    vm.hook_add(
        uc.UC_HOOK_CODE, observe_validation, begin=BASE + 0x74E8D0, end=BASE + 0x74E8D0
    )

    def consume(expected):
        flag_writes.clear()
        consumers.clear()
        put(capture + 0x4A, 0xA5, 1)
        run(0x65EA68, capture, end=0x65EAA4)
        require(
            read(capture + 0x4A, 1),
            bytes([expected[0]]),
            "original capture policy flag",
        )
        require(flag_writes, [(0x65EAA0, 1, expected[0])], "native capture flag store")
        d = run(0x593740, end=0x59374C)
        require(d, expected[1], "neighbor consumer uses native +0xD")
        require(
            consumers,
            [
                (0x78595C, SERVICE_OWNER),
                (0x74F9BC, config),
                (0x78595C, SERVICE_OWNER),
                (0x74F9F8, config),
            ],
            "each native consumer gets same config from singleton",
        )
        return {
            "capture_flag_4a": expected[0],
            "neighbor_result": d,
            "consumer_entries": list(consumers),
            "capture_store": flag_writes[0],
        }

    def seed_provider(bank, marker, bad_idx):
        size = (0x10000, 0xE000)[bank]
        raw = bytearray(size)
        raw[:4] = pack("<I", marker)
        start = 0x90
        for position, idx in enumerate(GROUPS[bank]):
            # Nonempty stream: one word with high flag bits clear, then a B000 word.
            count = 2 if idx == bad_idx else 1
            raw[0x10 + 8 * position : 0x18 + 8 * position] = pack("<II", 4, count)
            raw[start : start + 4] = pack("<HH", 0x100 + idx, 0xB000)
            start += CAPACITY[idx]
        return bytes(raw)

    def check_descriptors(buffers, validate):
        for bank, group in enumerate(GROUPS):
            start = RAM[bank] + 0x90
            for position, idx in enumerate(group):
                desc = config + 0x18 + 0x10 * idx
                header = (
                    buffers[bank][0x10 + 8 * position : 0x18 + 8 * position]
                    if validate
                    else bytes(8)
                )
                require(
                    read(desc, 16),
                    pack("<II", start, CAPACITY[idx]) + header,
                    "native buffer-backed descriptor",
                )
                start += CAPACITY[idx]

    init_cases, update_cases = [], []
    for label, marker_valid, bad_idx, expected in (
        ("first_group_bad_count", (1, 1), 0, (0, 1)),
        ("second_group_bad_count", (1, 1), 7, (1, 0)),
        ("first_ram_marker_invalid", (0, 1), None, (0, 0)),
        ("second_ram_marker_invalid", (1, 0), None, (0, 0)),
        ("both_groups_valid", (1, 1), None, (1, 1)),
    ):
        buffers = []
        for bank, valid in enumerate(marker_valid):
            source = seed_provider(bank, MARKER if valid else 0, bad_idx)
            vm.mem_write(PRIMARY[bank], seed_provider(bank, 0, None))
            vm.mem_write(BACKUP[bank], source if valid else bytes(len(source)))
            if not valid:
                vm.mem_write(PRIMARY[bank], source)
            buffers.append(source)
        run(0x6E7EB0, manager)
        for address, image in zip(RAM, buffers):
            require(read(address, len(image)), image, "native sector provider load")
        require(
            read(0x40106980, 0x40), data[0x1578C8:0x157908], "native ID62 default load"
        )
        require(read(0x40106984, 2), b"\0\0", "native ID62 version branch")

        config_writes.clear()
        validates.clear()
        vm.mem_write(config, bytes([0xA5]) * 0x224)
        # Supplied allocation result enters the original constructor/caller binding.
        run(0x5660B0, config, end=0x5660C8, r4=SERVICE_OWNER)
        require(word(SERVICE_OWNER + 0x3C), config, "native service object binding")
        require(word(config), BASE + 0xA76A04, "native configuration vtable")
        require(
            config_writes,
            [(0x74E5B8, 0xC, 1, 0), (0x74E5BC, 0xD, 1, 0)],
            "native config defaults",
        )
        config_writes.clear()
        run(0x5666FC, end=0x566710, r4=SERVICE_OWNER)
        require(
            [word(config + off) for off in (4, 8)],
            list(PROVIDERS[1:]),
            "native virtual init binds real provider objects",
        )
        require(
            [word(config + off) for off in (0x10, 0x14)],
            [base + 0x10 for base in RAM],
            "native provider header pointers",
        )
        check_descriptors(buffers, all(marker_valid))
        require(read(config + 0xC, 2), bytes(expected), "native validator output bytes")
        expected_writes = (
            [(0x74EBDC, 0xC, 1, expected[0]), (0x74EBE8, 0xD, 1, expected[1])]
            if all(marker_valid)
            else []
        )
        require(
            config_writes, expected_writes, "native initialization validation stores"
        )
        if bad_idx == 0:
            expected_visits = (0, *GROUPS[1])
        elif bad_idx == 7:
            expected_visits = (*GROUPS[0], 6, 7)
        else:
            expected_visits = (*GROUPS[0], *GROUPS[1]) if all(marker_valid) else ()
        require(validates, list(expected_visits), "native independent validation order")
        init_cases.append(
            {
                "case": label,
                "backup_marker_valid": marker_valid,
                "bad_descriptor_index": bad_idx,
                "validated_indices": list(validates),
                "config_bytes": list(read(config + 0xC, 2)),
                "native_config_writes": list(config_writes),
                **consume(expected),
            }
        )

    # Continue from the valid native initialization. The original indexed
    # count setter changes one descriptor, then the original writer syncs it
    # into the already-loaded header table and recomputes the two bytes.
    for changes, expected in (
        (((0, 2),), (0, 1)),
        (((0, 1), (7, 2)), (1, 0)),
        (((7, 1),), (1, 1)),
    ):
        for idx, count in changes:
            run(0x74F974, config, idx, count)
            bank = int(idx >= 6)
            offset = 0x14 + 8 * GROUPS[bank].index(idx)
            updated = bytearray(buffers[bank])
            updated[offset : offset + 4] = pack("<I", count)
            buffers[bank] = bytes(updated)
        config_writes.clear()
        validates.clear()
        run(0x74ED98, config)
        for address, image in zip(RAM, buffers):
            require(
                read(address, len(image)),
                image,
                "native alternate writer only changes specified provider counts",
            )
        require(
            read(config + 0xC, 2),
            bytes(expected),
            "native alternate writer validator outputs",
        )
        require(
            config_writes,
            [(0x74EE3C, 0xC, 1, expected[0]), (0x74EE48, 0xD, 1, expected[1])],
            "native alternate writer byte stores",
        )
        update_cases.append(
            {
                "prepared_setter_arguments": changes,
                "config_bytes": list(read(config + 0xC, 2)),
                "native_config_writes": list(config_writes),
                **consume(expected),
            }
        )

    return {
        "decoded_sha256": sha256(data),
        "code_va_base": BASE,
        "unicorn_version": uc.__version__,
        "static_checks": static,
        "execution_replacements": [],
        "native_owners": {"service": SERVICE_OWNER, "provider_manager": MANAGER_OWNER},
        "prepared_initialization_guards": [0x4040B7A4, 0x4040AE64, 0x4041D97C],
        "validated_groups": [list(group) for group in GROUPS],
        "synthetic_descriptor": {
            "used_bytes": 4,
            "terminator": 0xB000,
            "matching_count": 1,
        },
        "boundaries": {
            "service_ctor": 0x565BC8,
            "allocation_result_to_bind": [0x5660B0, 0x5660C8],
            "provider_registration": [0x76B8D0, 0x76B900],
            "manager_load_entry": 0x6E7EB0,
            "config_virtual_init": [0x5666FC, 0x566710],
            "config_indexed_count_setter": 0x74F974,
            "config_alternate_writer": 0x74ED98,
            "capture_policy_prefix": [0x65EA68, 0x65EAA4],
            "neighbor_caller": [0x593740, 0x59374C],
            "leaf_return_va": sentinel,
        },
        "init_cases": init_cases,
        "update_cases": update_cases,
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
        "replay": probe(data),
        "limits": [
            "Synthetic Flash records, allocator result, manager link and singleton guards; no full boot, allocator or synchronization execution.",
            "Original constructor, native owner binding, provider load and virtual initialization execute in separately prepared call frames without instruction replacement.",
            "Only the original ID62 default version-zero route and a four-byte synthetic descriptor representation are tested.",
            "Capture prefix stops after the initial CAP+4A store; later policy overrides and the neighbor caller continuation are not executed.",
            "Count setter arguments are prepared. Its upstream event/transport reachability and physical record meaning remain unresolved.",
            "No camera, physical Flash, DMA, image capture or menu activation is exercised.",
        ],
    }
    if args.compare:
        require_snapshot(
            result, args.compare, "preserved configuration producer replay"
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
