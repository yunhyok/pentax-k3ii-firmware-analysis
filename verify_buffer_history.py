"""Verify K-3 II recipe ordering and job buffer lifetime with original A32 code.

SPDX-License-Identifier: GPL-2.0-only
"""

import argparse
import json
from pathlib import Path
from struct import pack, unpack

from verify_findings import DECODED_SHA256, require, sha256
from verify_tone_path import BASE, check_edge, check_words, load_image

ORDINARY = (0x2140, 0x21E8, 0x2204)
MASKED = (0x2354, 0x238C, 0x23A8)
WORDS = {
    0x5A133C: 0x16470,
    0x654330: 0x02A684E0,
    0xA684E8: 0x02654218,
    0xA68564: 0x026603AC,
    0xA6856C: 0x026609AC,
    0x6535B0: 0xE5805160,
    0x6535DC: 0xE580518C,
    0x653830: 0xE1C05BB2,
    0x653D10: 0xE5815094,
    0x654340: 0xE58410A4,
    0x654740: 0xE58410D8,
    0x654758: 0xE58410DC,
    0x6DC414: 0xE2870F5D,
    0x6DC438: 0xE12FFF34,
    0x6DC4B4: 0xE12FFF37,
    0x6DC6A0: 0xE12FFF1C,
    0x72D370: 0xE1C01BB2,
    0x659794: 0xE3100044,
    0x6597E0: 0xE5941160,
    0x65980C: 0xE5C4007F,
    0x659AC8: 0xE5941160,
    0x659AD4: 0xE5941164,
    0x659AE0: 0xE5941168,
    0x52ACD0: 0x13A01015,
    0x52ACD4: 0x03A01011,
    0x52ACFC: 0x13A01014,
    0x52AD00: 0x03A01010,
    0x7B56E8: 0xE3A01009,
    0x5A1424: 0x05C01058,
    0x5A1498: 0xE5C01058,
    0x5A1564: 0xE3A01006,
    0x5A1570: 0xE12FFF35,
    0x6DCF90: 0xE3A02000,
    0x6DCF98: 0xE3A02001,
    0x7DC0AC: 0xE2800008,
    0x81C7BC: 0xE280001C,
}
CALLS = {
    0x5A110C: 0x653444,
    0x5A152C: 0x712828,
    0x5A1534: 0x653444,
    0x52A05C: 0x72D36C,
    0x52A068: 0x72D36C,
    0x52A074: 0x72D36C,
    0x52A080: 0x72D36C,
    0x638D90: 0x72D36C,
    0x52ACE4: 0x6540BC,
    0x52AD10: 0x6540BC,
    0x7B56F8: 0x6540BC,
    0x6DC418: 0x6DC384,
    0x6DC3C0: 0x81D878,
    0x6DC47C: 0x7544A4,
    0x6DC494: 0x70C4EC,
    0x6DC67C: 0x70C570,
    0x6DC6DC: 0x6DC5F0,
    0x6DCFA4: 0x6DC2D0,
    0x70C55C: 0x6EFC64,
    0x6EFCA0: 0x72CED8,
    0x6EFD3C: 0x72CF00,
    0x76E7B8: 0x712828,
    0x659AD0: 0x81CFB0,
    0x659ADC: 0x81CFB8,
    0x659AE8: 0x81CFC0,
    0x6DC2F4: 0x6593B0,
    0x6DC304: 0x81C7BC,
    0x6DC30C: 0x7DC0AC,
    0x6DD018: 0x6DC054,
    0x6DC068: 0x81C7DC,
}
RANGES = {
    "attached_pool_and_job_allocation": (0x5A1400, 0x5A1618),
    "job_constructor": (0x653444, 0x653D20),
    "indexed_buffer_setter": (0x654218, 0x65476C),
    "ordinary_layout": (0x6603AC, 0x660718),
    "slot17_layout": (0x6609AC, 0x660F60),
    "pool_and_allocate": (0x6DC364, 0x6DC4D0),
    "release": (0x6DC5E4, 0x6DC6FC),
    "raw_kind_assignments": (0x52A048, 0x52A084),
    "capture_kind_assignment": (0x638D84, 0x638D94),
    "cpp_plane_select": (0x659790, 0x659810),
    "cpp_ordinary_descriptor": (0x659AC8, 0x659AEC),
    "module20_mask_update": (0x65DD90, 0x65DDB8),
}
RECIPE_ROWS = {
    8: {0: (2, 4, 0), 1: (5, 0, 0), 8: (5, 2, 0), 10: (5, 16, 0), 12: (1, 4, 0)},
    9: {
        0: (2, 18, 2),
        1: (2, 15, 2),
        2: (5, 20, 0),
        4: (2, 4, 0),
        5: (5, 0, 0),
        7: (1, 18, 0),
        8: (1, 15, 0),
        11: (5, 2, 0),
        13: (5, 16, 0),
        15: (1, 4, 0),
    },
    0x10: {
        14: (2, 17, 2),
        15: (5, 0, 0),
        36: (5, 2, 0),
        38: (5, 16, 0),
        48: (1, 17, 0),
    },
    0x11: {
        6: (2, 4, 0),
        12: (2, 17, 2),
        14: (2, 18, 2),
        16: (6, 0, 0),
        17: (5, 20, 0),
        40: (5, 0, 0),
        43: (21, 0, 0),
        68: (1, 17, 0),
        69: (1, 18, 0),
        72: (5, 2, 0),
        76: (1, 4, 0),
    },
    0x14: {25: (1, 17, 0)},
    0x15: {
        6: (2, 4, 0),
        12: (2, 17, 2),
        14: (2, 18, 2),
        16: (6, 0, 0),
        17: (5, 20, 0),
        41: (5, 0, 0),
        44: (21, 0, 0),
        69: (1, 17, 0),
        70: (1, 18, 0),
        72: (5, 2, 0),
        74: (5, 16, 0),
        76: (1, 4, 0),
    },
}
ALLOCATION_ROWS = {
    8: [(0, 4)],
    9: [(0, 18), (4, 4)],
    0x10: [(14, 17)],
    0x11: [(6, 4), (12, 17), (14, 18)],
    0x14: [],
    0x15: [(6, 4), (12, 17), (14, 18)],
}


def emulate(data):
    from unicorn import Uc, UcError, UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, __version__
    from unicorn import arm_const as arm

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(BASE, 0x1000000)
    uc.mem_write(BASE, data[:0x1000000])
    jobs = [0x10000000 + i * 0x18000 for i in range(4)]
    controller, scratch, sp, ret = 0x10060000, 0x10061000, 0x10064000, 0x10065000
    pool = controller + 0x174
    uc.mem_map(jobs[0], 0x66000)
    uc.mem_map(0x40400000, 0x100000)

    def write(address, *values, fmt="I"):
        uc.mem_write(address, pack(f"<{len(values)}{fmt}", *values))

    def read(address, count=1, fmt="I"):
        size = {"I": 4, "H": 2, "B": 1}[fmt]
        return list(unpack(f"<{count}{fmt}", uc.mem_read(address, size * count)))

    def reg(name, value=None):
        register = getattr(arm, f"UC_ARM_REG_{name.upper()}")
        if value is None:
            return uc.reg_read(register)
        uc.reg_write(register, value)

    def run(start, end=None, **registers):
        stop = ret if end is None else BASE + end
        for name, value in dict(sp=sp, lr=ret, **registers).items():
            reg(name, value)
        try:
            uc.emu_start(BASE + start, stop, count=300_000)
        except UcError as exc:
            raise ValueError(
                f'A32 probe from {start:#x} stopped at VA {reg("pc"):#x}'
            ) from exc
        require(reg("pc"), stop, f"probe stop from {start:#x}")
        return reg("r0")

    recipe_allocations, allocations, releases = [], [], []
    returned_bases = []

    def boundary(_uc, address, _size, _data):
        if address == BASE + 0x712828:
            recipe_allocations.append(reg("r0"))
            reg("r0", scratch)
        elif address == BASE + 0x72CED8:
            allocations.append([reg("r0"), reg("r1")])
            write(reg("r2"), returned_bases.pop(0))
            reg("r0", 0)
        else:
            releases.append([reg("r0"), reg("r1")])
            reg("r0", 0)
        reg("pc", reg("lr"))

    def hook(offset):
        address = BASE + offset
        return uc.hook_add(UC_HOOK_CODE, boundary, begin=address, end=address)

    recipe_hook = hook(0x712828)
    recipes = {}
    for selector, expected in RECIPE_ROWS.items():
        uc.mem_write(scratch, bytes(0x302))
        require(run(0x76E7AC, r1=selector), scratch, "recipe buffer")
        values = unpack("<385H", uc.mem_read(scratch, 0x302))
        rows = list(zip(values[:128], values[128:256], values[256:384]))
        require({i: rows[i] for i in expected}, expected, f"recipe {selector:#x} rows")
        allocations_in_recipe = [
            (i, index)
            for i, (op, index, _) in enumerate(rows)
            if op == 2 and index in (4, 17, 18)
        ]
        require(
            allocations_in_recipe, ALLOCATION_ROWS[selector], "tracked allocation rows"
        )
        recipes[hex(selector)] = {
            "sha256": sha256(uc.mem_read(scratch, 0x302)),
            "selected_rows": {str(i): list(rows[i]) for i in expected},
            "tracked_allocation_rows": [list(row) for row in allocations_in_recipe],
        }
    require(recipe_allocations, [0x302] * len(RECIPE_ROWS), "recipe allocation sizes")
    uc.hook_del(recipe_hook)

    # Pre-initialized globals avoid running unrelated singleton startup.
    reg("fpexc", 0x40000000)
    write(0x4041D880, 1)
    write(0x4041E834, 1)
    arena4 = 0x404A45AC + 20 * 4
    heap4 = 0x10062000

    def planes(job, descriptors):
        return [read(job + desc + 4, 3) for desc in descriptors]

    def construct(job):
        uc.mem_write(job, b"\xa5" * 0x16470)
        run(0x653444, 0x653A44, r0=job, r1=0)
        run(0x653D00, 0x653D20, r0=0, r4=job, r5=0)
        require(read(job), [0x02A684E0], "constructor installs the original vtable")
        require(read(job + 0x20B2, fmt="H"), [0], "constructor clears kind")
        require(
            read(job + 0x160, 12), [0] * 12, "constructor clears ordinary addresses"
        )
        require(read(job + 0x94, 19), [0] * 19, "constructor clears buffer slots")
        require(planes(job, ORDINARY + MASKED), [[0, 0, 0]] * 6, "fresh descriptors")
        write(job + 0x224, 32, 16, fmt="H")
        write(job + 0x22C, 16, 8, fmt="H")
        write(job + 0x20D6, 16, 8, 8, 4, fmt="H")
        write(job + 0x130, 8, 12)
        write(job + 0x124, 0x4000, 0x2000)

    for job in jobs:
        construct(job)
    write(sp, *jobs)
    write(sp + 0x28, 1)
    run(0x52A048, 0x52A084)
    require([read(job + 0x20B2, fmt="H")[0] for job in jobs], [1, 2, 3, 4], "RAW kinds")
    recipe9_job = jobs[3]
    construct(recipe9_job)

    write(arena4, 1, 0xFFFFFFFF, 0, heap4)
    hook(0x72CED8)
    hook(0x72CF00)
    job, secondary = jobs[:2]
    primary_base, masked_base, next_base = 0x81000013, 0x82000013, 0x83000013
    write(pool, primary_base, 0x4000, 0)
    write(pool + 0x7C, 1)
    secondary_base, slot18_base = 0x84000013, 0x85000013
    returned_bases.extend([masked_base, next_base, secondary_base, slot18_base])

    def allocate(slot, allocation_class, owner=job):
        require(
            run(0x6DC3D0, r0=controller, r1=owner, r2=slot, r3=allocation_class),
            1,
            f"allocate slot {slot}",
        )

    def release(slot, owner=job):
        run(0x6DC634, r0=controller, r1=owner, r2=slot)

    allocate(4, 0)
    ordinary = planes(job, ORDINARY)
    require(read(pool + 8, fmt="B"), [1], "slot 4 pool reservation")
    require(read(job + 0xA4), [primary_base], "slot 4 backing base")
    require(read(job + 0x160, 3), ordinary[0], "ordinary backing words")
    require(
        all(primary_base <= p < primary_base + 0x4000 for row in ordinary for p in row),
        True,
        "ordinary planes inside supplied pool buffer",
    )
    allocate(17, 2)
    alternate = planes(job, MASKED)
    delta = masked_base - primary_base
    require(
        alternate,
        [[p + delta for p in row] for row in ordinary],
        "distinct slot 17 planes",
    )
    require(planes(job, ORDINARY), ordinary, "kind 1 slot 17 preserves ordinary layout")
    require(read(job + 0xD8), [masked_base], "slot 17 backing base")

    write(job + ORDINARY[0] + 4, 0x12345678)
    write(job + MASKED[0] + 4, 0x23456789)
    allocate(4, 0)
    allocate(17, 2)
    require(read(job + ORDINARY[0] + 4), [0x12345678], "slot 4 present skips rebuild")
    require(read(job + MASKED[0] + 4), [0x23456789], "slot 17 present skips rebuild")
    write(job + ORDINARY[0] + 4, ordinary[0][0])
    write(job + MASKED[0] + 4, alternate[0][0])

    payload = job + 0xA41C
    write(sp + 4, payload)
    mask_routes = []
    for before, after in ((4, 8), (0x40, 0x80)):
        write(job + 0x20B4, before, fmt="B")
        run(0x659790, 0x659810, r4=job, r5=job + 0x2000, r8=job + MASKED[0])
        require(read(payload + 0x2C, 3), alternate[0], "masked CPP address setup")
        require(read(job + 0x7F, fmt="B"), [1], "masked CPP flag")
        run(0x65DD90, 0x65DD14, r5=job + 0x2000)
        require(read(job + 0x20B4, fmt="B"), [after], "module 20 completion mask")
        run(0x659790, 0x659810, r4=job, r5=job + 0x2000, r8=job + MASKED[0])
        require(read(payload + 0x2C, 3), ordinary[0], "ordinary CPP address setup")
        require(read(job + 0x7F, fmt="B"), [0], "ordinary CPP clears flag")
        mask_routes.append(
            {
                "initial_mask": before,
                "completion_mask": after,
                "masked_planes": alternate[0],
                "ordinary_planes": ordinary[0],
            }
        )

    release(17)
    require(
        releases, [[heap4, masked_base]], "slot 17 passes backing pointer to allocator"
    )
    require(read(job + 0xD8), [0], "release clears slot 17")
    require(
        planes(job, MASKED), alternate, "release leaves stale masked descriptor words"
    )
    require(read(job + 0xA4), [primary_base], "slot 4 backing survives slot 17 release")
    require(planes(job, ORDINARY), ordinary, "ordinary layout survives slot 17 release")
    write(job + ORDINARY[0] + 4, 0)
    run(0x659AC8, 0x659AEC, r4=job)
    require(
        planes(job, ORDINARY), ordinary, "CPP rebuilds ordinary descriptor from backing"
    )

    scaler, jpeg = job + 0xA7B4, job + 0xA81C
    write(sp + 4, job + 0x21CC)
    run(0x65A16C, 0x65A190, r4=job, r7=scaler, fp=job + 0x21B0)
    require(
        read(scaler, 3), [job + 0x2140, job + 0x21B0, job + 0x21CC], "scaler bindings"
    )
    run(0x6593B0, r0=job, r1=16)
    require(
        read(jpeg, 2), [job + 0x21B0, job + 0x21CC], "JPEG shares scaler output objects"
    )

    allocate(17, 2)
    rebuilt = planes(job, MASKED)
    require(
        rebuilt,
        [[p + next_base - masked_base for p in row] for row in alternate],
        "fresh slot 17 rebuilds stale addresses",
    )
    require(planes(job, ORDINARY), ordinary, "reallocation preserves ordinary")
    release(17)
    release(4)
    require(read(job + 0xA4), [0], "slot 4 release clears job binding")
    require(read(pool + 8, fmt="B"), [0], "slot 4 returns entry to pool")
    require(
        planes(job, ORDINARY), ordinary, "slot 4 release leaves stale ordinary words"
    )
    allocate(4, 0)
    require(
        read(job + 0xA4), [primary_base], "pool can issue the released slot 4 again"
    )

    allocate(17, 2, secondary)
    secondary_planes = planes(secondary, ORDINARY)
    require(
        secondary_planes,
        [[p + secondary_base - primary_base for p in row] for row in ordinary],
        "kind 2 slot 17 builds ordinary descriptors without slot 4",
    )
    require(read(secondary + 0xA4), [0], "secondary job has no slot 4")
    require(
        planes(secondary, MASKED), [[0, 0, 0]] * 3, "kind 2 leaves masked descriptors"
    )
    capture_owner = controller + 0x900
    write(capture_owner + 0x21C, secondary)
    write(capture_owner + 0x288, 3)
    run(0x638D84, 0x638D94, r4=capture_owner)
    require(
        read(secondary + 0x20B2, fmt="H"), [3], "capture setter reads owner counter"
    )
    require(
        planes(secondary, ORDINARY), secondary_planes, "kind setter does not rebuild"
    )
    # Replay the independent recipe-9 buffer legs after returning the fixture pool entry.
    release(4)
    allocate(18, 2, recipe9_job)
    require(
        read(recipe9_job + 0xDC), [slot18_base], "slot 18 stores its backing pointer"
    )
    require(
        read(recipe9_job + 0x208), [(slot18_base + 31) & ~31], "slot 18 aligns its base"
    )
    require(
        planes(recipe9_job, ORDINARY + MASKED),
        [[0, 0, 0]] * 6,
        "slot 18 does not construct the tracked plane descriptors",
    )
    write(recipe9_job + 0x20B4, 0x40, fmt="B")
    run(0x65DD90, 0x65DD14, r5=recipe9_job + 0x2000)
    allocate(4, 0, recipe9_job)
    write(sp + 4, recipe9_job + 0xA41C)
    run(
        0x659790,
        0x659810,
        r4=recipe9_job,
        r5=recipe9_job + 0x2000,
        r8=recipe9_job + MASKED[0],
    )
    require(
        read(recipe9_job + 0x20B4, fmt="B"), [0x80], "recipe 9 fixture completion mask"
    )
    require(
        read(recipe9_job + 0xA41C + 0x2C, 3),
        ordinary[0],
        "recipe 9 ordinary CPP planes",
    )
    require(read(recipe9_job + 0xD8), [0], "recipe 9 fixture has no slot 17")
    require(read(recipe9_job + 0x7F, fmt="B"), [0], "recipe 9 ordinary CPP flag")

    # This attached-buffer pool is distinct from the backend controller's slot-4 pool.
    attached_pool, attached_out = controller + 0x500, scratch
    attached = [0x86000000, 0x86001000, 0x86002000, 0x86003000]
    write(attached_pool + 0x58, 1, fmt="B")
    for i, value in enumerate(attached):
        write(attached_pool + 0x98 + 0x100 * i, value)
    write(sp, attached_out + 12)
    arguments = dict(
        r0=attached_pool, r1=attached_out, r2=attached_out + 4, r3=attached_out + 8
    )
    require(run(0x5A1448, **arguments), 1, "attached pool acquire")
    require(read(attached_out, 4), attached, "attached buffer pointers")
    require(
        run(0x5A1448, **arguments), 0, "attached pool cannot issue a live entry again"
    )
    run(0x5A1400, r0=attached_pool, r1=attached[0])
    require(run(0x5A1448, **arguments), 1, "attached pool reacquire after release")
    require(read(attached_out, 4), attached, "attached buffer pointers reused")

    require(
        allocations,
        [[heap4, 0x4000]] * 3 + [[heap4, 0x2000]],
        "existing slots make no new allocation call",
    )
    require(
        releases,
        [[heap4, masked_base], [heap4, next_base]],
        "allocator release sequence",
    )
    require(returned_bases, [], "all supplied allocation results were consumed")
    return {
        "unicorn_version": __version__,
        "hooks": {
            "recipe_allocation": 0x712828,
            "arena_allocate": 0x72CED8,
            "arena_free": 0x72CF00,
        },
        "recipes": recipes,
        "raw_kinds": [1, 2, 3, 4],
        "capture_kind_from_counter": 3,
        "attached_pool_acquire_results": [1, 0, 1],
        "attached_pool_reissued_pointers": attached,
        "ordinary_slot4_planes": ordinary,
        "masked_slot17_planes": alternate,
        "masked_slot17_reallocated_planes": rebuilt,
        "secondary_slot17_ordinary_planes": secondary_planes,
        "mask_routes": mask_routes,
        "recipe9_fixture": {
            "completion_mask": 0x80,
            "slot18_aligned_base": (slot18_base + 31) & ~31,
            "slot17_base": 0,
            "cpp_planes": ordinary[0],
        },
        "slot4_pool_single_entry_reacquired": primary_base,
        "scaler_descriptors": [0x2140, 0x21B0, 0x21CC],
        "jpeg_input_descriptors": [0x21B0, 0x21CC],
        "arena_allocation_calls": allocations,
        "arena_free_calls": releases,
    }


def analyze(data):
    check_words(data, WORDS)
    for call, target in CALLS.items():
        check_edge(data, call, target)
    return {
        "decoded_sha256": DECODED_SHA256,
        "candidate_load_base": BASE,
        "location_units": "decoded file offsets except code pointers and synthetic addresses",
        "words": {hex(offset): word for offset, word in WORDS.items()},
        "calls": {hex(call): target for call, target in CALLS.items()},
        "range_hashes": {
            name: {
                "start": start,
                "end_exclusive": end,
                "sha256": sha256(data[start:end]),
            }
            for name, (start, end) in RANGES.items()
        },
        "synthetic_a32": emulate(data),
        "limits": [
            "Recipe tables are built by original code. Selected rows are zero based. "
            "Recipe order and the segmented probes do not establish asynchronous completion order.",
            "Constructor coverage is the prefix through plane descriptor initialization and the "
            "separate buffer-slot clear loop. Fixture globals model initialized services.",
            "Pool entries, arena metadata, dimensions and allocator results are synthetic. "
            "The firmware pool and heap wrappers execute, but the lowest arena calls are hooked.",
            "The two live backings differ in these fixtures. Their real camera addresses and "
            "pixel contents are outside the probe. Descriptor words alone outlive slot release.",
            "CPP and module 20 probes execute address selection and completion-mask updates only. "
            "Scaler and JPEG probes check descriptor bindings without executing pixel operations.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = analyze(load_image(args.decoded))
    if args.compare:
        require(
            result,
            json.loads(args.compare.read_text(encoding="utf-8")),
            "buffer history",
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
