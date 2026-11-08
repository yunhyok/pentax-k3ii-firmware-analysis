"""Verify the K-3 II SD block-command and ADMA2 programming path.

SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import json
from pathlib import Path
import struct

from verify_findings import DECODED_SHA256, require, require_snapshot, sha256
from verify_tone_path import BASE, branch_target, check_words, load_image


PORTS = (0xC6000000, 0xC7000000)
DEFAULT_MAX_BLOCKS = 0x8000
CARD_VTABLE, HOST_VTABLE = 0xA5D20C, 0xA656D0
EDGES = (
    (0x7620C4, 0x7413D8), (0x7620E4, 0x736A4C),
    (0x740FD8, 0x56F51C), (0x740FF0, 0x56D828), (0x741008, 0x5976B0),
    (0x741054, 0x56BD74), (0x741078, 0x56BD8C),
    (0x7410A8, 0x757890), (0x7410C0, 0x5975E4), (0x7410CC, 0x5975EC),
    (0x757B54, 0x719080), (0x757B60, 0x719078), (0x56BD98, 0x719760),
    (0x56D9EC, 0x719758), (0x757E2C, 0x757D14), (0x56DC58, 0x56F87C),
    (0x56D8EC, 0x7195B8), (0x758810, 0x7587E8), (0x758820, 0x785F28),
    (0x7582D0, 0x7582A8), (0x7582E0, 0x785F28),
    (0x758D04, 0x56C0E8), (0x758D18, 0x5D2C48), (0x758D24, 0x719768),
    (0x758A48, 0x758914), (0x7589C4, 0x758890), (0x758974, 0x7587FC),
    (0x758854, 0x758744), (0x75886C, 0x758658),
    (0x7588D0, 0x758138), (0x7588E0, 0x56C608),
    (0x7587A0, 0x56C6B8), (0x758698, 0x56C554), (0x7586C8, 0x56C6B8),
    (0x7583D0, 0x56C330), (0x758260, 0x56C408),
    (0x56EC74, 0x56EBA4), (0x56ECF8, 0x56EBA4),
    (0x56EBF8, 0x56EB68), (0x56EC14, 0x56EB58),
    (0x56E5A4, 0x56F578), (0x56E5B8, 0x56F5B8), (0x56E5CC, 0x56F5DC),
    (0x56E5DC, 0x56E374), (0x56E5F0, 0x56E454), (0x56E600, 0x56F674),
    (0x56E614, 0x56DF90), (0x56E640, 0x56E280),
    (0x56DFC8, 0x70C408), (0x56DFE0, 0x70C3E8),
    (0x56F2B8, 0x56FCA8), (0x56F2C4, 0x56FCDC),
    (0x56F2FC, 0x70C3CC), (0x56F3B0, 0x56FCBC),
    (0x56F3EC, 0x70C3CC), (0x56F3F8, 0x56FCF0),
)
TAIL_EDGES = ((0x56EC28, 0x5702E8), (0x56ECAC, 0x56DF90), (0x56ED30, 0x56DF90))
WORDS = {
    0x7415BC: 0x40479948, 0x7415C4: 0x029DCFD4,
    0x9DCFD4: PORTS[0], 0x9DCFEC: PORTS[1],
    0x740FD4: 0xE79A1188, 0x740FE0: 0xE584001C,
    0x741044: 0xE5845014, 0x741080: 0xE584500C,
    0x7410F0: 0xE5902008, 0x7410F8: 0xE12FFF32,
    0x741140: 0xE5845004, 0x7413D8: 0xE0800101, 0x7413DC: 0xE5900004,
    0x56F520: 0xE5801000, 0x5976B0: 0xE5801000, 0x56D9FC: 0xE5840000,
    0x56E68C: BASE + HOST_VTABLE, 0x758710: BASE + CARD_VTABLE,
    0x757B58: 0xE5840020, 0x757B64: 0xE5840024, 0x56BD9C: 0xE5840000,
    CARD_VTABLE + 8: BASE + 0x757B40,
    CARD_VTABLE + 0x18: BASE + 0x7589E8, CARD_VTABLE + 0x1C: BASE + 0x7585C4,
    HOST_VTABLE + 8: BASE + 0x56F298, HOST_VTABLE + 0x14: BASE + 0x56D9DC,
    HOST_VTABLE + 0x20: BASE + 0x56DC14, HOST_VTABLE + 0x30: BASE + 0x56E544,
    0x757D24: 0xE5911020, 0x757D28: 0xE12FFF31,
    0x56DC54: 0xE3A01010, 0x56F884: 0xE2011018,
    0x56F888: 0xE3C22018, 0x56F890: 0xE5801028,
    HOST_VTABLE + 0x48: BASE + 0x56EC2C, HOST_VTABLE + 0x4C: BASE + 0x56EC8C,
    HOST_VTABLE + 0x50: BASE + 0x56ECB0, HOST_VTABLE + 0x54: BASE + 0x56ED10,
    0x5728E4: 0xE12FFF3C, 0x572948: 0xE12FFF3C,
    0x758138: 0xE5D00037, 0x75813C: 0xE3500002,
    0x758140: 0x01A00001, 0x758144: 0x11A00481,
    0x7588B4: 0xE591C050, 0x7588FC: 0xE5914054,
    0x758768: 0xE591C050, 0x7587BC: 0xE5917054,
    0x7583A4: 0xE591C048, 0x7583EC: 0xE591404C,
    0x56C360: 0xE3A01011, 0x56C440: 0xE3A01012, 0x56C580: 0xE3A01017,
    0x56C638: 0xE3A01018, 0x56C6F0: 0xE3A01019,
    0x56C674: 0xE5915030, 0x56C738: 0xE5915030,
    0x59A568: 0xE5C01000, 0x59A570: 0xE9801008,
    0x59A584: 0xE5801000, 0x59A58C: 0xE1C020B4, 0x59A590: 0xE1C030B6,
    0x59A594: 0xE5C04008, 0x7195C8: 0xE5C01009,
    0x56DA30: 0xE3A01E82, 0x56DA40: 0xE280001F,
    0x56DA48: 0xE3C0001F, 0x56DA4C: 0xE7850001,
    0x56EB5C: 0xE3800002, 0x56EB6C: 0xE5C10000, 0x56EB74: 0xE5C10001,
    0x56EB7C: 0xE5C13002, 0x56EB80: 0xE5C10003,
    0x56EB88: 0xE5C12004, 0x56EB9C: 0xE5C10007,
    0x56EBBC: 0xE3A01B02, 0x56EBCC: 0xE1A04484,
    0x56EBD0: 0xE3A09021, 0x56EBD4: 0xE3A01801,
    0x56EC00: 0xE086600C, 0x56EC04: 0xE2855008,
    0x5702EC: 0xE5801058, 0x56F58C: 0xE5801004, 0x56F5C4: 0xE5802004,
    0x56F5E0: 0xE5801008, 0x56F69C: 0xE580100C,
    0x56E3E8: 0xE3A04011, 0x56E3F0: 0xE3A04033, 0x56E400: 0x13A04037,
    0x56E408: 0xE3A04001, 0x56E410: 0xE3A04023, 0x56E420: 0x13A04027,
    0x56E468: 0xE1A04400, 0x56E484: 0x13844020, 0x56E4D0: 0xE384401A,
    0x56E698: 0x77FF9F3F, 0x57047C: 0xC000FFC0,
    0x56FCAC: 0xE5900030, 0x56FCC4: 0xE5801030, 0x56FCE0: 0xE5900030,
    0x56FCE4: 0xE3C00322, 0x56FCFC: 0xE5801030, 0x56F3E4: 0xE1A01809,
    0x56E60C: 0xE1A01002, 0x56E64C: 0xE3590000, 0x56E654: 0xE3A05001,
    0x56DFB0: 0xE3814080, 0x56DFD8: 0xE0051000, 0x56DFE8: 0xE1100004,
    0x56E690: 0x77FF0000, 0x56ED2C: 0xE3A01002, 0x56ECA8: 0xE3A01002,
    0x5D28B4: 0xE31100FD, 0x5D28BC: 0x031100F9, 0x5D28C4: 0x02100008,
    0x56D8B4: 0xE3A01902, 0x56D8DC: 0xE3000404, 0x7195B8: 0xE5801000,
    0x59A54C: 0xE3001404, 0x71BAF0: 0xE5900000,
    0x758878: 0x10866004, 0x75887C: 0x10877484,
    0x75833C: 0xE0866004, 0x758340: 0xE0877484,
    0x56C100: 0xE3A01009, 0x758D20: 0xE2840014, 0x719768: 0xE5801000,
    0x5D2C9C: 0xE1A014A3, 0x5D2CB8: 0xE1A01500,
    0x758A18: 0xE0871008, 0x758A1C: 0xE1500001, 0x758A5C: 0xE3540003,
}
RANGES = {
    "registry_slot_construction": (0x740FA0, 0x741190),
    "two_port_configuration_rows": (0x9DCFD4, 0x9DD004),
    "card_write_dispatch": (0x758658, 0x758A7C),
    "card_read_dispatch": (0x758138, 0x758468),
    "command_wrappers": (0x56C330, 0x56C77C),
    "command_transfer_mode": (0x56E374, 0x56E454),
    "controller_command_issue": (0x56E454, 0x56E68C),
    "irq_flag_wait": (0x56DF90, 0x56DFF8),
    "contiguous_adma_table": (0x56EB58, 0x56EC2C),
    "controller_irq": (0x56F298, 0x56F460),
    "card_capacity_producer": (0x758CE4, 0x758D44),
    "csd_capacity_math": (0x5D2C48, 0x5D2CC4),
}


def verify(data):
    for link, edges in ((True, EDGES), (False, TAIL_EDGES)):
        for source, target in edges:
            require(branch_target(data, source, link), target, f"A32 branch {source:#x}")
    check_words(data, WORDS)
    return {
        "decoded_sha256": DECODED_SHA256,
        "offset_convention": "file offsets unless labeled MMIO address or VA",
        "edges": [{"source": hex(a), "target": hex(b)} for a, b in EDGES + TAIL_EDGES],
        "words": {hex(offset): hex(word) for offset, word in WORDS.items()},
        "ranges": {name: {"start": hex(start), "end_exclusive": hex(end),
                          "sha256": sha256(data[start:end])}
                   for name, (start, end) in RANGES.items()},
        "registry": {
            "constructor": "0x740fa0",
            "getter": "0x7413d8",
            "card_slot": "registry+4+port*4",
            "card_vtable_va": hex(BASE + CARD_VTABLE),
            "card_write": {"slot": "0x18", "target": "0x7589e8"},
            "card_read": {"slot": "0x1c", "target": "0x7585c4"},
            "host_vtable_va": hex(BASE + HOST_VTABLE),
            "host_controller_wrapper": "host+0x418",
        },
        "card_capacity": {
            "field": "card+0x14",
            "unit": "512-byte logical sectors",
            "producer": "CMD9 in 0x56c0e8 supplies CSD bytes to 0x758ce4; 0x5d2c48 computes the count",
            "csd_structure_0": "(C_SIZE+1) * (1<<(C_SIZE_MULT+2)) * ((1<<READ_BL_LEN)>>9)",
            "csd_structure_1": "(C_SIZE+1)<<10",
        },
        "controller": {
            "port_mmio_bases": list(map(hex, PORTS)),
            "block_size_count": "32-bit RMW at +0x04, block length low 12 bits and count upper 16 bits",
            "argument": "+0x08, LBA when card+0x37 is 2, otherwise LBA shifted left by 9",
            "command_transfer": "+0x0c, command index in bits 29:24, transfer mode in bits 5:0",
            "transfer_modes": {"CMD17": ["0x11"], "CMD18": ["0x33", "0x37"],
                               "CMD24": ["0x01"], "CMD25": ["0x23", "0x27"]},
            "interrupt_status": "+0x30, normal flags and shifted error flags delivered to host+0x41c event object",
            "transfer_wait": "bit 1 expected, mask 0x77ff0000 or bit 7 forces failure",
        },
        "adma2": {
            "builder": "0x56eba4",
            "descriptor_table": "host+0x43c points to 32-byte-aligned table, written to port+0x58",
            "descriptor_layout": ["uint16_le attributes", "uint16_le encoded length", "uint32_le buffer address"],
            "attributes": {"transfer": "0x21", "final_transfer": "0x23"},
            "host_control": "0x56dc14 sets +0x28 bits [4:3] to 0b10 through 0x56f87c",
            "segment_bytes_max": 65536,
            "default_max_command_sectors": DEFAULT_MAX_BLOCKS,
            "chunking": "Read 0x7582bc and write 0x7587fc clamp each chunk by host+0x404; advance LBA by count and buffer by count*512",
            "zero_length_encoding_bytes": 65536,
            "address": "original buffer pointer plus bytes already covered, passed directly to the table",
        },
        "sources_for_protocol_names": [
            "https://github.com/torvalds/linux/blob/v6.18/drivers/mmc/host/sdhci.h",
            "https://github.com/torvalds/linux/blob/v6.18/drivers/mmc/host/sdhci.c#L4465-L4475",
            "https://github.com/torvalds/linux/blob/v6.18/include/linux/mmc/mmc.h#L47-L58",
            "https://www.sdcard.org/downloads/pls/archives/",
        ],
        "limits": [
            "MMIO bases and offset use are firmware findings. SDHCI and ADMA2 names describe the matching register and descriptor layouts.",
            "Tests inject RAM, command responses, status and RTOS events. Physical card I/O, DMA data movement, CPU-to-bus address translation, and timing are outside the probes.",
            "The static card write entry has bounds, retry and recovery branches. Numeric probes enter the lower command helpers after those checks.",
            "The rechunk fixture only maps a source prefix. It verifies the firmware pointer arithmetic and programmed tables without modeling a DMA engine.",
        ],
    }


def emulate(data):
    import unicorn
    from unicorn.arm_const import (UC_ARM_REG_C1_C0_2, UC_ARM_REG_FPEXC,
                                   UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0,
                                   UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_SP,
                                   UC_CPU_ARM_CORTEX_A9)

    ram = 0x10000000
    card, host, adapter, wrapper, table, stop = [ram + n for n in range(0, 0x6000, 0x1000)]
    buffer = ram + 0x10000
    lba = 0x1234
    cases = (
        # Name, entry, port, card addressing mode, blocks, final command, transfer mode, fault.
        ("write-single", 0x758890, 0, 2, 1, 24, 0x01, None),
        ("write-multi-autostop", 0x758744, 1, 1, 129, 25, 0x27, None),
        ("write-multi-precount", 0x758658, 0, 2, 128, 25, 0x23, None),
        ("read-single", 0x75834C, 1, 1, 1, 17, 0x11, None),
        ("read-multi-autostop", 0x758204, 0, 2, 129, 18, 0x37, None),
        ("write-rechunk-65535", 0x7587FC, 1, 2, 65535, 25, 0x27, None),
        ("capacity-csd-v1", 0x758CE4, 0, 0, 0, 9, 0, None),
        ("capacity-csd-v2", 0x758CE4, 1, 1, 0, 9, 0, None),
        ("write-command-timeout", 0x758890, 0, 2, 1, 24, 0x01, "command_timeout"),
        ("write-card-response-error", 0x758890, 1, 2, 1, 24, 0x01, "card_response"),
        ("write-adma-error", 0x758890, 0, 2, 1, 24, 0x01, "adma"),
        ("write-transfer-timeout", 0x758890, 1, 2, 1, 24, 0x01, "transfer_timeout"),
        ("write-command-inhibited", 0x758890, 0, 2, 1, 24, 0x01, "inhibited"),
        ("irq-normal-and-error", 0x56F298, 1, 0, 0, 0, 0, None),
    )
    stubs = {
        0x70C3CC: "RTOS event post", 0x70C3E8: "RTOS event clear",
        0x70C390: "RTOS event snapshot", 0x70C408: "RTOS event wait",
        0x6FEB30: "global cache-management object lookup",
        0x6FEBAC: "CPU cache maintenance",
        0x757EF8: "post-transfer card state polling in the multi-block card helper",
    }
    results = []
    for name, entry, index, card_mode, blocks, cmd, mode, fault in cases:
        port = PORTS[index]
        irq = entry == 0x56F298
        capacity = entry == 0x758CE4
        machine = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
        machine.ctl_set_cpu_model(UC_CPU_ARM_CORTEX_A9)
        machine.reg_write(UC_ARM_REG_C1_C0_2, 0xF00000)
        machine.reg_write(UC_ARM_REG_FPEXC, 0x40000000)
        machine.mem_map(BASE, 0x1000000)
        machine.mem_write(BASE, data[:0x1000000])
        machine.mem_map(ram, 0x40000)
        machine.mem_map(port, 0x1000)

        def put(addr, value):
            machine.mem_write(addr, struct.pack("<I", value))

        for addr, value in (
            (card, BASE + CARD_VTABLE), (host, BASE + HOST_VTABLE),
            (card + 0x20, host), (card + 0x24, adapter), (adapter, host),
            (host + 0x404, DEFAULT_MAX_BLOCKS), (host + 0x418, wrapper), (host + 0x43C, table), (wrapper, port),
            (port + 0x24, int(fault == "inhibited")),
            (port + 0x30, 0x02008003 if irq else 0),
        ):
            put(addr, value)
        machine.mem_write(card + 0x36, bytes((1, card_mode)))
        machine.mem_write(table, b"\xA5" * 0x820)
        if capacity:
            put(card + 0x14, 0xBAD0BAD0)
            machine.mem_write(card + 0x34, struct.pack("<H", 0x2468))
            if card_mode == 0:
                csd = ((10 << 80) | (2047 << 62) | (6 << 47)).to_bytes(16, "big")
                expected_capacity = 0x100000
            else:
                csd = ((1 << 126) | (0x100FF << 48)).to_bytes(16, "big")
                expected_capacity = 0x04040000
            for register, field in zip((0x10, 0x14, 0x18, 0x1C),
                                       (csd[11:15], csd[7:11], csd[3:7], csd[:3])):
                put(port + register, int.from_bytes(field, "big"))
        payload = bytes(range(256)) * (min(blocks, 129) * 2)
        if payload:
            machine.mem_write(buffer, payload)
        mmio, waits, posts, tables = [], [], [], []
        flags = 0

        def mmio_write(_vm, _access, address, size, value, _user):
            require(size, 4, f"{name} MMIO store width")
            mmio.append((address - port, value & 0xFFFFFFFF))
            if address == port + 0x58:
                tables.append(bytes(machine.mem_read(table, 0x820)))

        def service(vm, address, _size, _user):
            nonlocal flags
            offset = address - BASE
            r0, r1, r2 = (vm.reg_read(reg) for reg in (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2))
            if offset in (0x70C3CC, 0x70C3E8, 0x70C390, 0x70C408):
                require(r0, host + 0x41C, f"{name} event object")
            result = 1
            if offset == 0x70C3CC:
                posts.append(r1)
                flags |= r1
            elif offset == 0x70C3E8:
                flags &= ~r1
            elif offset == 0x70C390:
                put(r1, flags)
            elif offset == 0x70C408:
                waits.append(r1)
                if r1 == 0x81:
                    result = int(fault != "command_timeout")
                    flags = result
                    if not capacity:
                        put(port + 0x10, 0x80000000 if fault == "card_response" else 0)
                else:
                    require(r1, 0x77FF0082, f"{name} data wait mask")
                    result = int(fault != "transfer_timeout")
                    flags = 0x02000002 if fault == "adma" else 2 * result
                put(r2, flags)
            vm.reg_write(UC_ARM_REG_R0, result)
            vm.reg_write(UC_ARM_REG_PC, vm.reg_read(UC_ARM_REG_LR))

        machine.hook_add(unicorn.UC_HOOK_MEM_WRITE, mmio_write, begin=port, end=port + 0xFFF)
        for offset in stubs:
            machine.hook_add(unicorn.UC_HOOK_CODE, service, begin=BASE + offset, end=BASE + offset)
        args = ((host,) if irq else (card,) if capacity else (card, lba, buffer) if blocks == 1
                else (card, lba, blocks, buffer))
        for reg, value in zip((UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3), args):
            machine.reg_write(reg, value)
        machine.reg_write(UC_ARM_REG_SP, ram + 0x3F000)
        machine.reg_write(UC_ARM_REG_LR, stop)
        try:
            machine.emu_start(BASE + entry, stop, count=100000)
        except unicorn.UcError as exc:
            raise RuntimeError(f"{name} stopped at {machine.reg_read(UC_ARM_REG_PC):#x}") from exc
        require(machine.reg_read(UC_ARM_REG_PC), stop, f"{name} bounded return")
        expected_writes = []
        expected_waits, table_summaries = [], []
        expected_return = int(fault is None and not irq)
        if irq:
            require(posts, [0x8003, 0x02000000], f"{name} posts")
            expected_writes = [(0x30, 0x8003), (0x30, 0x02000000)]
        elif capacity:
            expected_writes = [(8, 0x24680000), (0xC, 0x09090000)]
            expected_waits = [0x81]
            require(bytes(machine.mem_read(card + 0x54, 15)), csd[:15], f"{name} CSD bytes")
            actual_capacity, = struct.unpack("<I", machine.mem_read(card + 0x14, 4))
            require(actual_capacity, expected_capacity, f"{name} capacity in sectors")
        else:
            block_count = 0
            expected_tables = []
            previous_size_count = 0
            while block_count < blocks:
                count = min(blocks - block_count, DEFAULT_MAX_BLOCKS)
                expected_writes += [(0x30, 0x77FF0000), (0x58, table)]
                argument = (lba + block_count) * (1 if card_mode == 2 else 512)
                if entry == 0x758658:
                    expected_writes += [(8, count), (0xC, 0x171A0000)]
                    expected_waits.append(0x81)
                if fault != "inhibited":
                    size_count = (count << 16) | 512
                    expected_writes += [(4, previous_size_count | 512), (4, size_count),
                                        (8, argument), (0xC, (cmd << 24) | 0x003A0000 | mode)]
                    previous_size_count = count << 16
                    expected_waits.append(0x81)
                if fault not in ("inhibited", "command_timeout", "card_response"):
                    expected_waits.append(0x77FF0082)
                descriptors = []
                byte_count = count * 512
                for start in range(0, byte_count, 0x10000):
                    size = min(0x10000, byte_count - start)
                    attributes = 0x23 if start + size == byte_count else 0x21
                    descriptors.append((attributes, size & 0xFFFF, buffer + block_count * 512 + start))
                encoded = b"".join(struct.pack("<HHI", *row) for row in descriptors)
                expected_tables.append(encoded + bytes(0x800 - len(encoded)) + b"\xA5" * 0x20)
                table_summaries.append({
                    "count": len(descriptors),
                    "sha256": sha256(encoded),
                    "first": list(descriptors[0]),
                    "last": list(descriptors[-1]),
                })
                block_count += count
            require(tables, expected_tables, f"{name} complete ADMA tables")
            require(bytes(machine.mem_read(buffer, len(payload))), payload, f"{name} untouched synthetic buffer")
            require(posts, [], f"{name} direct event injection")
        require(mmio, expected_writes, f"{name} complete MMIO write trace")
        require(waits, expected_waits, f"{name} wait sequence")
        require(machine.reg_read(UC_ARM_REG_R0), expected_return, f"{name} return")
        results.append({
            "name": name, "entry": hex(entry), "port": hex(port),
            "card_address_mode": card_mode, "blocks": blocks,
            "fault": fault, "return": expected_return,
            "mmio_writes": [[hex(offset), hex(value)] for offset, value in mmio],
            "wait_masks": list(map(hex, waits)),
            "event_posts": list(map(hex, posts)),
            "descriptor_tables": table_summaries,
            **({"capacity_sectors": expected_capacity, "csd": csd.hex()} if capacity else {}),
        })
    return {"engine": f"Unicorn {unicorn.__version__}", "mode": "A32 entry, ARM/Thumb helper execution",
            "stubs": {hex(offset): desc for offset, desc in stubs.items()},
            "cases": results}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--emulate", action="store_true")
    parser.add_argument("--json", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    data = load_image(args.decoded)
    result = verify(data)
    if args.emulate:
        result["original_code"] = emulate(data)
    if args.compare:
        require_snapshot(result, args.compare, "SD evidence snapshot")
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    count = len(result.get("original_code", {}).get("cases", []))
    print(f"Verified {len(EDGES) + len(TAIL_EDGES)} branches, {len(WORDS)} words and {count} A32 probes.")


if __name__ == "__main__":
    main()
