"""Trace the ordinary scaler gate through full module setup and controller submission.

SPDX-License-Identifier: GPL-2.0-only
Locations are decoded file offsets. No camera or pixel operation is executed.
"""

import argparse
import itertools
import json
from pathlib import Path
from struct import pack, unpack

from verify_findings import DECODED_SHA256, require, sha256
from verify_masked_scaler import gate_search
from verify_raw_path import branch_target
from verify_tone_path import BASE, check_words, load_image


EDGES = (
    (0x6DC2E4, 0x81C770),
    (0x81C774, 0x834824),
    (0x6DC2F4, 0x6593B0),
    (0x6594DC, 0x659E78),
    (0x659FAC, 0x71B090),
    (0x6DC334, 0x656984),
    (0x6569BC, 0x656A38),
    (0x6DC304, 0x81C7BC),
    (0x6DC30C, 0x7DC0AC),
    (0x6DC31C, 0x7DB908),
    (0x6DC328, 0x7DB920),
    (0x6DC340, 0x7DB910),
    (0x6DC34C, 0x7DB918),
    (0x6DC360, 0x6FEA38),
    (0x5804A4, 0x71C440),
    (0x5804AC, 0x5808A8),
    (0x528BC8, 0x656984),
    (0x528C0C, 0x656984),
    (0x528BD4, 0x754AE0),
    (0x528BE0, 0x754AE8),
)
WORDS = {
    0x659F74: 0xE3A08000,
    0x659FA4: 0xE1A01008,
    0x71B090: 0xE5C01038,
    0x71C440: 0xE5D00038,
    0x656A38: 0xE1A00003,
    0x656990: 0xE30A37B4,
    0x6DC2E8: 0xE20060FF,
    0x6DC338: 0xE1A01000,
    0x7DB910: 0xE5801008,
    0x7DB908: 0xE580100C,
    0x7DB918: 0xE5801010,
    0x7DB920: 0xE5801004,
    0x754AE0: 0xE5C0102A,
    0x754AE8: 0xE5C0102B,
    0x5804A8: 0xE3500000,
}
RANGES = {
    "controller_submit": (0x6DC2D0, 0x6DC364),
    "module_dispatch": (0x6593B0, 0x659528),
    "complete_module2_setup": (0x659E78, 0x65A480),
    "payload_selector": (0x656984, 0x656AB4),
    "packet_setters": (0x7DB908, 0x7DB928),
    "special_preview_disable": (0x528BB4, 0x528C34),
    "gate_consumer": (0x5804A0, 0x5804B0),
}


def emulate(data):
    import unicorn
    from unicorn import arm_const as arm

    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])
    job, controller, recipe = 0x10000000, 0x10020000, 0x10021000
    sp, stop = 0x10040000, 0x1004FF00
    vm.mem_map(job, 0x50000)
    vm.reg_write(arm.UC_ARM_REG_FPEXC, 0x40000000)
    payload = job + 0xA7B4
    writes, submissions = [], []

    def write(address, *values, fmt="I"):
        vm.mem_write(address, pack(f"<{len(values)}{fmt}", *values))

    def reg(name):
        return vm.reg_read(getattr(arm, "UC_ARM_REG_" + name.upper()))

    def trace_write(_vm, _access, address, size, value, _data):
        writes.append(
            {
                "pc": reg("pc") - BASE,
                "offset": address - payload,
                "width": size,
                "value": value,
            }
        )

    def enqueue(_vm, _address, _size, _data):
        request = reg("r1")
        fields = list(unpack("<4I", vm.mem_read(request + 4, 16)))
        submissions.append(
            {
                "queue": reg("r0"),
                "priority": reg("r2"),
                "request_offset": request - job,
                "fields": fields,
            }
        )
        vm.reg_write(arm.UC_ARM_REG_PC, reg("lr"))

    vm.hook_add(
        unicorn.UC_HOOK_MEM_WRITE, trace_write, begin=payload + 0x38, end=payload + 0x38
    )
    vm.hook_add(
        unicorn.UC_HOOK_CODE, enqueue, begin=BASE + 0x6FEA38, end=BASE + 0x6FEA38
    )

    def run(entry, end=None, **registers):
        end = stop if end is None else BASE + end
        for name, value in dict(sp=sp, lr=stop, **registers).items():
            vm.reg_write(getattr(arm, "UC_ARM_REG_" + name.upper()), value)
        vm.ctl_flush_tb()
        vm.emu_start(BASE + entry, end, count=100000)
        require(reg("pc"), end, f"complete original execution {entry:#x}")

    cases = []
    for outputs, flags, state5e, packet_variant in itertools.product(
        range(4), range(4), range(2), range(2)
    ):
        vm.mem_write(job, bytes(0x18000))
        write(job + 0x34, recipe, 0)
        write(recipe + 0x100, 2, fmt="H")
        write(controller + 0x8C + 2 * 4, 0x00708001)
        write(controller + 0x38 + 2 * 4, 0x13572468)
        for offset, value in (
            (0x3E, outputs & 1),
            (0x3F, outputs >> 1),
            (0x45, outputs & 1),
            (0x46, outputs >> 1),
            (0x40, flags & 1),
            (0x42, flags >> 1),
            (0x5E, state5e),
        ):
            write(job + offset, value, fmt="B")
        write(payload + 0x38, 0xA5, fmt="B")
        writes.clear()
        submissions.clear()
        run(0x6DC2D0, r0=controller, r1=job, r2=packet_variant)
        require(
            writes,
            [{"pc": 0x71B090, "offset": 0x38, "width": 1, "value": 0}],
            "full setup and submission write only zero to gate",
        )
        require(
            submissions,
            [
                {
                    "queue": 0x13572468,
                    "priority": 2,
                    "request_offset": 0x1C if packet_variant else 8,
                    "fields": [controller + 4, payload, 0x00708001, job],
                }
            ],
            "packet retains the initialized scaler payload pointer",
        )
        require(vm.mem_read(payload + 0x38, 1)[0], 0, "gate after submission")
        write(sp + 0x2C, payload)
        run(0x5804A0, 0x5808A8)
        require(reg("r0"), 0, "consumer read disables the auxiliary branch")
        cases.append(
            {
                "output_flags": outputs,
                "flags40_42": flags,
                "initial_state5e": state5e,
                "packet_variant": packet_variant,
                "gate_writes": list(writes),
                "submission": submissions[0],
                "consumer_gate": 0,
            }
        )
    return {
        "engine": f"Unicorn {unicorn.__version__}",
        "case_count": len(cases),
        "cases": cases,
        "hooked_code_offsets": [0x6FEA38],
        "write_observer_does_not_replace_instructions": True,
    }


def analyze(data):
    for source, target in EDGES:
        require(branch_target(data, source), target, f"edge {source:#x}")
    check_words(data, WORDS)
    return {
        "decoded_sha256": DECODED_SHA256,
        "location_units": "decoded file offsets",
        "static": {
            "edges": EDGES,
            "words": WORDS,
            "search": gate_search(data),
            "ranges": {
                name: {"start": a, "end_exclusive": z, "sha256": sha256(data[a:z])}
                for name, (a, z) in RANGES.items()
            },
        },
        "original_a32": emulate(data),
        "limits": [
            "All 64 cases run the full module-2 setup inside controller submission. "
            "The only replaced code call is queue insertion. The auxiliary consumer is then "
            "executed as a separate short segment on the same payload.",
            "Output flags, controller queue and command table, recipe row, geometry and other "
            "job state are synthetic. Cases are not a camera-mode availability test.",
            "The result excludes a nonzero gate producer within these complete module-2 paths, "
            "not throughout all firmware execution. Other queued work, concurrent writes, copies, "
            "indirect stores and untested state remain outside this execution.",
            "The special preview caller changes payload+0x2a/+0x2b; those are distinct from "
            "the auxiliary gate at +0x38. Its complete surrounding operation is not replayed.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = json.dumps(analyze(load_image(args.decoded)), indent=2)
    if args.compare:
        require(
            json.loads(result),
            json.loads(args.compare.read_text(encoding="utf-8")),
            "scaler gate snapshot",
        )
    print(result)


if __name__ == "__main__":
    main()
