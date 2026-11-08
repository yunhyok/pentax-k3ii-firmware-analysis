"""Verify backend B file writes through the actual card/SD/ADMA programming code.

SPDX-License-Identifier: GPL-2.0-only
Synthetic metadata, services and read data are explicitly intercepted.
"""

import argparse, json, struct
from pathlib import Path
from verify_tone_path import BASE, load_image
from verify_findings import require, sha256, DECODED_SHA256, u32
from verify_raw_path import branch_target
import unicorn as u
from unicorn import arm_const as a


def probe(data, entry=0x5CB860, offset=0, count=1024, fail=False):
    vm = u.Uc(u.UC_ARCH_ARM, u.UC_MODE_ARM)
    vm.ctl_set_cpu_model(a.UC_CPU_ARM_CORTEX_A9)
    vm.reg_write(a.UC_ARM_REG_C1_C0_2, 0xF00000)
    vm.reg_write(a.UC_ARM_REG_FPEXC, 0x40000000)
    for addr, size in [
        (BASE, 0x1000000),
        (0x10000000, 0x40000),
        (0x40400000, 0xC0000),
        (0xC6000000, 0x1000),
    ]:
        vm.mem_map(addr, size)
    vm.mem_write(BASE, data[:0x1000000])
    card, host, adapter, wrapper, table, stop, manager, volnames, err, backend = [
        0x10000000 + n for n in range(0, 0xA000, 0x1000)
    ]
    source, cache, stack = 0x10010000, 0x10020000, 0x1003E000
    drive, file = 0x404A7B08, 0x404ABDC0

    def put(addr, *vals):
        vm.mem_write(addr, struct.pack("<" + "I" * len(vals), *vals))

    def read(addr):
        return struct.unpack("<I", vm.mem_read(addr, 4))[0]

    for addr, val in [
        (card, BASE + 0xA5D20C),
        (card + 0x14, 0x100000),
        (card + 0x20, host),
        (card + 0x24, adapter),
        (host, BASE + 0xA656D0),
        (host + 0x404, 0x8000),
        (host + 0x418, wrapper),
        (host + 0x43C, table),
        (adapter, host),
        (wrapper, 0xC6000000),
        (0x4040AC34, manager),
        (manager + 0xC, volnames),
        (file + 0x1C, 1),
        (file + 0x28, 2),
        (file + 0x2C, offset),
        (file + 8, offset),
        (drive + 0x18, 0x100),
        (drive + 0x30, 0x20),
        (drive + 0x34, 8),
    ]:
        put(addr, val)
    vm.mem_write(card + 0x36, b"\1\2")
    vm.mem_write(drive + 0x28, struct.pack("<h", 512))
    vm.mem_write(file + 0x442, b"\1")
    vm.mem_write(volnames + 4, b"C:\0")
    payload = bytes((i * 7 + 3) & 255 for i in range(count))
    vm.mem_write(source, payload)
    vm.mem_write(cache, bytes([0xA5]) * 512)
    writes, reads, mmio, stubs, entered = [], [], [], set(), []
    flags = 0

    def service(uc, addr, size, user):
        nonlocal flags
        off = addr - BASE
        r = [
            uc.reg_read(x)
            for x in (
                a.UC_ARM_REG_R0,
                a.UC_ARM_REG_R1,
                a.UC_ARM_REG_R2,
                a.UC_ARM_REG_R3,
            )
        ]
        sp = uc.reg_read(a.UC_ARM_REG_SP)
        result = 0
        if off in (
            0xE86818,
            0xEAFFAC,
            0xEB1A94,
            0xEADE54,
            0xEAE0F4,
            0xE8623C,
            0x5CB380,
            0x5CB30C,
        ):
            entered.append(hex(off))
            return
        if off == 0x7589E8:
            require(r[0], card, "same card object at write entry")
            writes.append(
                {
                    "lba": r[1],
                    "blocks": r[2],
                    "source": r[3],
                    "data": bytes(vm.mem_read(r[3], r[2] * 512)).hex(),
                }
            )
            if not fail:
                return
        elif off == 0x7585C4:
            require(r[0], card, "same card object at read entry")
            reads.append({"lba": r[1], "blocks": r[2], "source": r[3]})
            vm.mem_write(r[3], bytes([0xCC]) * r[2] * 512)
            result = 1
        elif off == 0xEA5344:
            put(r[0], err)
        elif off == 0xEA6E74:
            put(read(sp + 4), 4096, 0)
        elif off == 0xEAB1A0:
            put(r[3], 2)
            put(read(sp), offset + count)
        elif off == 0x5CB204:
            result = cache
        elif off == 0x736B78:
            require(bytes(vm.mem_read(r[1], 3)), b"C:\0", "volume name")
            result = card
        elif off in (0x757DD8, 0x757EF8):
            result = 1
        elif off == 0x70C3E8:
            flags &= ~r[1]
            result = 1
        elif off == 0x70C390:
            put(r[1], flags)
            result = 1
        elif off == 0x70C408:
            flags = 1 if r[1] == 0x81 else 2
            put(r[2], flags)
            put(0xC6000010, 0)
            result = 1
        stubs.add(hex(off))
        uc.reg_write(a.UC_ARM_REG_R0, result)
        uc.reg_write(a.UC_ARM_REG_PC, uc.reg_read(a.UC_ARM_REG_LR))

    hooked = (
        0xEA5344,
        0xEA6E74,
        0xEAB1A0,
        0xEBDA20,
        0xEA870C,
        0xEAAF78,
        0xEA7D3C,
        0xEA7FDC,
        0x5CB148,
        0x5CB204,
        0x5CB220,
        0xEACB14,
        0x5CB748,
        0x736B78,
        0x78607C,
        0x78609C,
        0x6EF268,
        0x6EF248,
        0x757DD8,
        0x758468,
        0x757EF8,
        0x6FEB30,
        0x6FEBAC,
        0x70C3E8,
        0x70C390,
        0x70C408,
        0x7585C4,
        0x7589E8,
        0xE86818,
        0xEAFFAC,
        0xEB1A94,
        0xEADE54,
        0xEAE0F4,
        0xE8623C,
        0x5CB380,
        0x5CB30C,
    )
    for off in hooked:
        vm.hook_add(u.UC_HOOK_CODE, service, begin=BASE + off, end=BASE + off)

    def mm(uc, access, addr, size, val, user):
        if addr == 0xC6000058:
            mmio.append({"adma": bytes(vm.mem_read(val, 0x800)).hex()})
        if addr in (0xC6000004, 0xC6000008, 0xC600000C):
            mmio.append([hex(addr), hex(val)])

    vm.hook_add(u.UC_HOOK_MEM_WRITE, mm, begin=0xC6000000, end=0xC6000FFF)
    args = (
        (backend + 4, 0, source, count) if entry == 0x5CB860 else (0, 2, offset, source)
    )
    put(stack, count)
    vm.reg_write(a.UC_ARM_REG_SP, stack)
    vm.reg_write(a.UC_ARM_REG_LR, stop)
    for reg, value in zip(
        (a.UC_ARM_REG_R0, a.UC_ARM_REG_R1, a.UC_ARM_REG_R2, a.UC_ARM_REG_R3), args
    ):
        vm.reg_write(reg, value)
    try:
        vm.emu_start(BASE + entry, stop, count=300000)
    except u.UcError as e:
        raise RuntimeError(
            f"PC {vm.reg_read(a.UC_ARM_REG_PC):x}, entered={entered}, stubs={stubs}"
        ) from e
    require(vm.reg_read(a.UC_ARM_REG_PC), stop, "return")
    result = {
        "entry": hex(entry),
        "offset": offset,
        "count": count,
        "result": vm.reg_read(a.UC_ARM_REG_R0),
        "errno": read(err),
        "entered": entered,
        "writes": writes,
        "reads": reads,
        "mmio": mmio,
        "stubs": sorted(stubs),
    }

    require(
        result["result"],
        (0 if fail or count == 0 else 1) if entry == 0x5CB860 else count,
        "API return",
    )
    require(
        result["errno"],
        (
            ((0xFFFFD8E7 if fail else count) if count else 0xFFFFFFF5)
            if entry == 0x5CB860
            else 0
        ),
        "dispatcher result",
    )
    expected_writes, expected_reads = [], []
    cursor, remaining, pos = source, count, offset
    lba = 0x120
    while remaining:
        if pos or remaining < 512:
            size = min(512 - pos, remaining)
            fill = 0xCC if pos or entry != 0xEAE0F4 else 0
            block = (
                bytes([fill]) * pos
                + payload[cursor - source : cursor - source + size]
                + bytes([fill]) * (512 - pos - size)
            )
            expected_writes.append(
                {"lba": lba, "blocks": 1, "source": cache, "data": block.hex()}
            )
            if fill == 0xCC:
                expected_reads.append({"lba": lba, "blocks": 1, "source": cache})
            used, blocks = size, 1
        else:
            blocks = remaining // 512
            used = blocks * 512
            expected_writes.append(
                {
                    "lba": lba,
                    "blocks": blocks,
                    "source": cursor,
                    "data": payload[cursor - source : cursor - source + used].hex(),
                }
            )
        if fail:
            break
        cursor += used
        remaining -= used
        lba += blocks
        pos = 0
    require(
        writes,
        expected_writes,
        "same pointers, sector content and counts at real card entry",
    )
    require(reads, expected_reads, "partial-sector preserved-data reads")
    expected_mmio, previous_count = [], 0
    if not fail:
        for request in expected_writes:
            blocks = request["blocks"]
            record = struct.pack("<HHI", 0x23, blocks * 512, request["source"]) + bytes(
                0x800 - 8
            )
            expected_mmio += [
                {"adma": record.hex()},
                ["0xc6000004", hex((previous_count << 16) | 512)],
                ["0xc6000004", hex((blocks << 16) | 512)],
                ["0xc6000008", hex(request["lba"])],
                ["0xc600000c", hex(0x183A0001 if blocks == 1 else 0x193A0027)],
            ]
            previous_count = blocks
    require(mmio, expected_mmio, "ADMA table and selected MMIO writes")
    if count:
        require(
            entered[:4],
            (
                ["0xe86818", "0xeaffac", "0xeb1a94", "0xeade54"]
                if entry == 0x5CB860
                else [hex(entry), "0xe8623c", "0x5cb380", "0x5cb30c"]
            ),
            "original call chain",
        )
    for request in writes:
        request["buffer_sha256"] = sha256(bytes.fromhex(request.pop("data")))
    for row in mmio:
        if isinstance(row, dict):
            encoded = bytes.fromhex(row.pop("adma"))
            row["adma_table_sha256"] = sha256(encoded)
            row["first_descriptor"] = list(struct.unpack("<HHI", encoded[:8]))
    return result


EDGES = (
    (6076516, 6076436),
    (6076460, 15231000),
    (15400940, 15407764),
    (15410124, 15392340),
    (15410180, 15393012),
    (15410020, 15393012),
    (15392596, 15229500),
    (15392732, 15229500),
    (15392912, 15229500),
    (15393260, 15229500),
    (15393392, 15229500),
    (15393556, 15229500),
    (15229624, 6075264),
    (6075276, 6075148),
    (6075180, 7455392),
    (6075192, 7564152),
    (7703112, 7702804),
    (7702900, 7702524),
    (7702980, 7702672),
    (15392544, 15229312),
    (15392860, 15229312),
    (15393208, 15229312),
    (15392392, 15454800),
    (15393064, 15454800),
)
WORDS = {
    15808876: 48955308,
    15809008: 0,
    15231060: 3884974340,
    15231108: 3851419680,
    15231112: 3766485632,
    15231116: 3766550784,
    15231124: 3851431968,
    15231132: 3778019123,
    15229620: 3855613954,
    6075224: 3851468824,
    6075232: 3778019132,
    10867236: 41257448,
    15410164: 3888648223,
    6075244: 329269248,
    6078312: 4294957287,
}
RANGES = {
    "backend_write": (6076436, 6076520),
    "table_dispatch": (15231000, 15231148),
    "library_write_wrapper": (15400876, 15401032),
    "file_write": (15407764, 15410744),
    "preserve_tail": (15392340, 15393012),
    "zero_tail": (15393012, 15393656),
    "device_write": (15229500, 15229688),
    "card_bridge": (6075148, 6075284),
    "cluster_lba": (15454800, 15454888),
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    data = load_image(args.decoded)
    for site, target in EDGES:
        require(branch_target(data, site), target, f"branch {site:#x}")
    for site, word in WORDS.items():
        require(u32(data, site), word, f"word {site:#x}")
    cases = [
        probe(data, entry, offset, count, fail)
        for entry, offset, count, fail in (
            (0x5CB860, 0, 1024, False),
            (0x5CB860, 7, 12, False),
            (0x5CB860, 7, 1030, False),
            (0xEADE54, 0, 12, False),
            (0xEAE0F4, 0, 12, False),
            (0x5CB860, 0, 1024, True),
            (0x5CB860, 0, 0, False),
        )
    ]
    result = {
        "decoded_sha256": DECODED_SHA256,
        "engine": "Unicorn " + u.__version__,
        "static": {
            "edges": [[hex(x), hex(y)] for x, y in EDGES],
            "words": {hex(x): hex(y) for x, y in WORDS.items()},
            "ranges": {
                k: {
                    "start": hex(x),
                    "end_exclusive": hex(y),
                    "sha256": sha256(data[x:y]),
                }
                for k, (x, y) in RANGES.items()
            },
        },
        "cases": cases,
        "limits": [
            "The write-table index is seeded to zero and an existing file/extent is supplied. Mount, allocation, cluster-chain lookup, timestamps, locks, card preflight and CPU cache operations are not emulated.",
            "The EA6E74 metadata lookup returns a 4096-byte file size; EAB1A0 supplies one prepared extent. The wrapper, library file-write body, sector routines, block bridge, card write and SD/ADMA programming execute original code.",
            "Partial-sector reads are intercepted at the card read entry and filled with 0xCC. Write data is inspected at the actual card write entry and remains connected to original ADMA programming. There is no physical DMA or media execution.",
            "Failure is injected at the card write boundary; the original lower SD path is executed only in success cases. Zero-length file write is separately rejected before I/O.",
            "The tail-zeroing helper is tested directly. Its original file-write caller can round the byte count before calling it; these fixtures do not establish padding validity for all append modes.",
            "Mixed writes forward an unaligned middle pointer unchanged. This proves address arithmetic, not hardware acceptance of every address or CPU-to-bus coherence.",
        ],
    }
    if args.compare:
        require(
            result,
            json.loads(args.compare.read_text(encoding="utf-8")),
            "backend B evidence",
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
