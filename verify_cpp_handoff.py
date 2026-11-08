"""Verify the K-3 II second CPP pass, module 17 blend and scaler handoff.

SPDX-License-Identifier: GPL-2.0-only
Instruction locations are decoded file offsets.
"""

import argparse
import json
from pathlib import Path
from struct import pack, unpack

from verify_findings import (
    DECODED_SHA256,
    literal_offset,
    require,
    require_snapshot,
    sha256,
    u32,
)
from verify_raw_path import branch_target
from verify_tone_path import BASE, check_words, load_image


EDGES = {
    "second_cpp_pass": (
        (0x65955C, 0x71B580),
        (0x659798, 0x6597E0),
        (0x57BDFC, 0x57BE60),
        (0x57BE04, 0x71B578),
        (0x57BE1C, 0x7543D4),
        (0x57BE3C, 0x7543DC),
        (0x57BE5C, 0x7543E4),
        (0x57BF40, 0x58C078),
        (0x58C094, 0x58B500),
        (0x58BDAC, 0x5506E8),
        (0x58BDB8, 0x55073C),
        (0x58BDC4, 0x550790),
    ),
    "module_17": (
        (0x6DC2F4, 0x6593B0),
        (0x6DC334, 0x656984),
        (0x6DB780, 0x81D38C),
        (0x659518, 0x65D564),
        (0x6569F8, 0x656A84),
        (0x65D580, 0x71A72C),
        (0x65D58C, 0x71A734),
        (0x65D598, 0x71A73C),
        (0x65D5A4, 0x71A724),
        (0x65D5F8, 0x65D614),
        (0x65D604, 0x71A734),
        (0x65D610, 0x71A724),
        (0x589908, 0x589888),
        (0x5898B8, 0x71A71C),
        (0x5898C0, 0x5898D4),
        (0x5898D0, 0x58980C),
        (0x58987C, 0x5AB310),
        (0x5AB758, 0x72D54C),
        (0x5AB764, 0x72D554),
        (0x5AB770, 0x72D544),
        (0x5AF6A0, 0x7B3298),
        (0x5AF6AC, 0x7B3290),
        (0x5AF70C, 0x5AA800),
        (0x5AF720, 0x5AF79C),
        (0x5AF744, 0x702B8C),
        (0x5AF798, 0x5AA7AC),
        (0x5AA830, 0x5AA7AC),
        (0x5AA848, 0x5AA7AC),
        (0x5AA7F4, 0x5AA4E0),
        (0x5AA644, 0x753DA4),
        (0x5AA668, 0x753DAC),
        (0x5AA698, 0x753DB4),
        (0x5AA774, 0x6FEA38),
        (0x5AA78C, 0x70C408),
        (0x586B34, 0x586A88),
        (0x586AB0, 0x5403AC),
        (0x54040C, 0x53FEAC),
        (0x54041C, 0x53FC08),
        (0x540128, 0x6E0CB8),
        (0x53FE68, 0x6E0CB8),
        (0x53FBB4, 0x6E0CB8),
        (0x6DBC0C, 0x6DBEFC),
        (0x6DBF04, 0x6DBD0C),
    ),
    "scaler_and_jpeg": (
        (0x659AD0, 0x81CFB0),
        (0x659ADC, 0x81CFB8),
        (0x659AE8, 0x81CFC0),
        (0x659EF0, 0x71B020),
        (0x659FA0, 0x71AFF0),
        (0x659FAC, 0x71B090),
        (0x65A174, 0x71B010),
        (0x65A180, 0x71B050),
        (0x65A18C, 0x71B058),
        (0x65A1A4, 0x65A24C),
        (0x65A24C, 0x754AE0),
        (0x65A1C8, 0x754AE8),
        (0x580044, 0x71B008),
        (0x580074, 0x71B018),
        (0x5804A4, 0x71C440),
        (0x5804AC, 0x5808A8),
        (0x5804D4, 0x57F904),
        (0x58096C, 0x57FC04),
        (0x580994, 0x57FC04),
        (0x57FD14, 0x57F904),
        (0x57FD48, 0x57F904),
        (0x65D4EC, 0x71B6A0),
        (0x65D4F8, 0x71B6A8),
        (0x576D70, 0x71B688),
    ),
}
WORDS = {
    0x6593BC: 0xE3020194,
    0x6594AC: 0xE3020354,
    0x659548: 0xE5D41059,
    0x659794: 0xE3100044,
    0x65980C: 0xE5C4007F,
    0x71B578: 0xE59000AC,
    0x71B580: 0xE58010AC,
    0x65D564: 0xE5D40059,
    0x65D56C: 0xE2840A16,
    0x65D570: 0xE2800F9A,
    0x65D574: 0x03A01001,
    0x65D578: 0x13A01000,
    0x65D584: 0xE2841D85,
    0x65D590: 0xE59D1034,
    0x65D59C: 0xE2841D85,
    0x65D5F0: 0xE5D4007F,
    0x65D5F4: 0xE3500001,
    0x65D624: 0x05C4005E,
    0x71A72C: 0xE5C01000,
    0x71A734: 0xE5801018,
    0x71A73C: 0xE580101C,
    0x71A724: 0xE5801020,
    0x6DB614: 0xE3A06001,
    0x6DB78C: 0xE584007C,
    0x6DB794: 0xE58460D0,
    0x5898A0: 0xE3500001,
    0x5898BC: 0xE3500000,
    0x589900: 0xE12FFF13,
    0x72D544: 0xE5900020,
    0x72D54C: 0xE5900018,
    0x72D554: 0xE590001C,
    0x5AB75C: 0xE58D025C,
    0x5AB768: 0xE58D0380,
    0x5AB774: 0xE58D0368,
    0x5AF710: 0xE59D0260,
    0x5AF714: 0xE3500004,
    0x5AF718: 0x13500002,
    0x5AF71C: 0x13500001,
    0x5AA7E0: 0xE88C0018,
    0x5AA7EC: 0xE88D0014,
    0x753DA4: 0xE580101C,
    0x753DAC: 0xE5801028,
    0x753DB4: 0xE5801038,
    0x4E26A4: 0xE590001C,
    0x4E26AC: 0xE5900028,
    0x4E26EC: 0xE5900038,
    0x6E0CBC: 0xE3C11007,
    0x6E0CC4: 0xE5801024,
    0x659AC8: 0xE5941160,
    0x659AD4: 0xE5941164,
    0x659AE0: 0xE5941168,
    0x659F74: 0xE3A08000,
    0x659FA4: 0xE1A01008,
    0x71B090: 0xE5C01038,
    0x71C440: 0xE5D00038,
    0x5804CC: 0xE59D101C,
    0x5804D0: 0xE59D2018,
    0x580960: 0xE59D1020,
    0x580988: 0xE59D1020,
    0x65A190: 0xE5D41045,
    0x754AE0: 0xE5C0102A,
    0x754AE8: 0xE5C0102B,
    0x71AFF0: 0xE5C01030,
    0x71B010: 0xE5801000,
    0x71B050: 0xE5801004,
    0x71B058: 0xE5801008,
    0x71B6A0: 0xE5801000,
    0x71B6A8: 0xE5801004,
}
RANGES = {
    "module17_setup": (0x65D564, 0x65D62C),
    "module17_gate_and_completion": (0x589888, 0x58990C),
    "blend_descriptor_reads": (0x5AB754, 0x5AB778),
    "blend_plane_submission": (0x5AF684, 0x5AF79C),
    "blend_request_build_and_wait": (0x5AA4E0, 0x5AA858),
    "ordinary_scaler_bindings": (0x65A16C, 0x65A1CC),
    "ordinary_scaler_gate_setup": (0x65A24C, 0x65A258),
    "alternate_scaler_bindings": (0x659EC8, 0x659FB0),
    "scaler_alternate_gate": (0x5804A0, 0x5804D8),
    "scaler_main_gate": (0x58091C, 0x58099C),
}
EXPECTED_RECIPE_ROWS = {
    "0xc": [6, 8, 30, 32],
    "0x10": [15, 17, 36, 38],
    "0x13": [10, 12, 38, 40],
    "0x15": [41, 48, 72, 74],
}


def verify_static(data):
    for edges in EDGES.values():
        for source, target in edges:
            require(branch_target(data, source), target, f"branch at {source:#x}")
    check_words(data, WORDS)
    literals = {
        0x5896BC: BASE + 0xA700E0,
        0x5898F0: 0x05022001,
        0x5AA728: 0x010E0001,
        0x586B18: 0x010E0001,
    }
    for site, value in literals.items():
        require(u32(data, literal_offset(data, site)), value, f"literal at {site:#x}")
    receive_slots = {0xA700F8: 0x589888, 0xA70124: 0x589904}
    for slot, handler in receive_slots.items():
        require(u32(data, slot), BASE + handler, f"module 17 receive slot {slot:#x}")
    return {
        "edges": EDGES,
        "instruction_offsets": list(WORDS),
        "literal_reads": literals,
        "module17_receive_slots": receive_slots,
        "ranges": {
            name: {
                "start": start,
                "end_exclusive": end,
                "sha256": sha256(data[start:end]),
            }
            for name, (start, end) in RANGES.items()
        },
    }


def emulate(data):
    from unicorn import Uc, UC_ARCH_ARM, UC_HOOK_CODE, UC_MODE_ARM, __version__
    from unicorn import arm_const as arm

    uc = Uc(UC_ARCH_ARM, UC_MODE_ARM)
    uc.mem_map(BASE, 0x1000000)
    uc.mem_write(BASE, data[:0x1000000])
    job, device, message, callback = 0x10000000, 0x10020000, 0x10022000, 0x10023000
    sp, ret = 0x10038000, 0x1003E000
    uc.mem_map(job, 0x40000)
    uc.mem_map(0x20022000, 0x1000)
    uc.reg_write(arm.UC_ARM_REG_FPEXC, 0x40000000)
    stop = ret

    def write(address, *values, fmt="I"):
        uc.mem_write(address, pack(f"<{len(values)}{fmt}", *values))

    def read(address, count=1):
        return list(unpack(f"<{count}I", uc.mem_read(address, 4 * count)))

    def reg(name):
        return uc.reg_read(getattr(arm, f"UC_ARM_REG_{name.upper()}"))

    def set_reg(name, value):
        uc.reg_write(getattr(arm, f"UC_ARM_REG_{name.upper()}"), value)

    def run(start, end=None, **registers):
        nonlocal stop
        stop = ret if end is None else BASE + end
        for name, value in dict(sp=sp, lr=ret, **registers).items():
            set_reg(name, value)
        uc.ctl_flush_tb()
        uc.emu_start(BASE + start, stop, count=100_000)
        require(reg("pc"), stop, f"bounded probe stop at {start:#x}")
        return reg("r0")

    requests, callbacks, worker_inputs, scales = [], [], [], []
    recipe_ptr = 0x10030000
    allocations = []

    def boundary(_uc, addr, _size, _data):
        offset = addr - BASE
        if offset == 0x712828:
            allocations.append(reg("r0"))
            set_reg("r0", recipe_ptr)
        elif offset == 0x6FEA38:
            request = reg("r1")
            descriptor, command = read(request + 8, 2)
            require(command, 0x010E0001, "blend service request")
            requests.append([read(descriptor + i)[0] for i in (0x1C, 0x28, 0x38)])
        elif offset == 0x5AB310:
            worker_inputs.append(reg("r1"))
        elif offset == 0x57F904:
            scales.append([reg("r1"), reg("r2")])
        elif addr == callback + 0x20:
            callbacks.append([reg("r1"), reg("r2")])
        set_reg("pc", reg("lr"))

    boundary_offsets = (0x712828, 0x5AB310, 0x6FEA38, 0x70C3E8, 0x70C408, 0x57F904)
    for addr in [BASE + i for i in boundary_offsets] + [callback + 0x20]:
        uc.hook_add(UC_HOOK_CODE, boundary, begin=addr, end=addr)

    recipes = {}
    for selector, expected in EXPECTED_RECIPE_ROWS.items():
        require(run(0x76E7AC, r1=int(selector, 16)), recipe_ptr, "recipe pointer")
        values = unpack("<385H", uc.mem_read(recipe_ptr, 0x302))
        rows = list(zip(values[:128], values[128:256]))
        tone, scaler, jpeg = (rows.index(pair) for pair in ((5, 0), (5, 2), (5, 16)))
        blend = next(i for i in range(tone + 1, scaler) if rows[i] == (5, 17))
        order = [tone, blend, scaler, jpeg]
        require(order, expected, f"recipe {selector} CPP/blend/scaler/JPEG rows")
        recipes[selector] = order
    require(allocations, [0x302] * len(recipes), "recipe heap requests")

    results = []
    for mask, second, blend_mode in ((0, 0, 0), (0, 1, 0), (0, 1, 2), (0x44, 1, 4)):
        uc.mem_write(job, bytes(0x17000))
        requests.clear()
        callbacks.clear()
        worker_inputs.clear()
        scales.clear()
        cpp, scaler, blend = job + 0xA41C, job + 0xA7B4, job + 0x16268
        normal, masked, alternate = (job + i for i in (0x2140, 0x2354, 0x2194))
        direct_planes = [0x11000100, 0x11000200, 0x11000300]
        masked_planes = [0x12000100, 0x12000200, 0x12000300]
        second_planes = [0x13000100, 0x13000200, 0x13000300]
        write(job + 0x160, *direct_planes)
        write(masked + 4, *masked_planes)
        write(alternate + 4, *second_planes)
        write(job + 0x20B4, mask, fmt="B")
        write(job + 0x59, second, fmt="B")
        write(sp + 0x34, alternate)
        write(sp + 0x40, job + 0x2680)
        run(0x659528, 0x659588, r4=job)
        run(0x659790, 0x659810, r4=job, r5=job + 0x2000, r8=masked)
        run(0x659AC8, 0x659AEC, r4=job)
        primary, primary_planes = (
            (masked, masked_planes) if mask else (normal, direct_planes)
        )
        require(read(cpp + 0x2C, 3), primary_planes, "CPP first-pass output planes")
        if second:
            write(sp + 4, cpp)
            run(0x57BDF8, 0x57BE60, r8=1)
            require(read(cpp + 0x2C, 3), second_planes, "CPP second-pass output planes")
            run(0x58BC84, 0x58BDC8, r4=device, fp=cpp)
            require(
                [read(i)[0] for i in (0x20022440, 0x20022450, 0x20022460)],
                second_planes,
                "second-pass B2Y output writes",
            )

        run(0x6593B0, r0=job, r1=17)
        require(run(0x656984, r0=job, r1=17), blend, "module 17 payload getter")
        require(
            read(blend + 0x18, 3),
            [primary, alternate, primary],
            "blend payload bindings",
        )
        require(uc.mem_read(job + 0x5E, 1)[0], second, "module 17 job state")
        write(callback, callback + 4)
        write(callback + 12, callback + 0x20)
        write(message + 4, callback, blend, 1, job)
        run(0x589888, r0=device, r1=message)
        require(
            worker_inputs, [blend] if second else [], "module 17 original work gate"
        )
        require(callbacks, [[0x05022001, job]], "module 17 completion message")
        run(0x6DBA14, 0x6DBEFC, r6=callbacks[0][0])

        if second:
            # Enter after the worker's upstream feature, allocation and mode checks.
            write(sp + 0x3DC, blend)
            run(0x5AB754, 0x5AB778)
            require(
                [read(sp + i)[0] for i in (0x25C, 0x380, 0x368)],
                [primary, alternate, primary],
                "worker image descriptors",
            )
            write(sp + 0x3D8, device)
            write(sp + 0x260, blend_mode)
            for i, value in ((0x348, 32), (0x378, 16), (0x350, 16), (0x264, 16)):
                write(sp + i, value)
            run(0x5AF684, 0x5AF79C, r4=16, r5=32, r6=16, sb=32)
        active_planes = (
            [1, 2] + ([0] if blend_mode in (1, 2, 4) else []) if second else []
        )
        expected = [
            [second_planes[i], primary_planes[i], primary_planes[i]]
            for i in active_planes
        ]
        require(requests, expected, "blend input/primary/destination address roles")

        # Run the address-writing slices for the two source fields and destination field.
        lane, registers = device + 0x100, device + 0x200
        write(lane + 0x10, registers)
        for request in requests:
            descriptor = device + 0x300
            for (field, start, end), address in zip(
                (
                    (0x1C, 0x540118, 0x54012C),
                    (0x28, 0x53FE58, 0x53FE6C),
                    (0x38, 0x53FBA4, 0x53FBB8),
                ),
                request,
            ):
                write(descriptor + field, address)
                run(start, end, r5=lane, sb=descriptor)
                require(
                    read(registers + 0x24), [address], "blend address-programming slice"
                )

        # Reproduce the ordinary scaler binding, then follow its real output choice to the device boundary.
        first_jpeg, second_jpeg = job + 0x21B0, job + 0x21CC
        scaled_planes = [0x14000100, 0x14000200, 0x14000300]
        write(first_jpeg + 4, *scaled_planes)
        write(sp + 4, second_jpeg)
        run(0x65A16C, 0x65A190, r4=job, r7=scaler, fp=first_jpeg)
        require(
            read(scaler, 3),
            [normal, first_jpeg, second_jpeg],
            "ordinary scaler bindings",
        )
        write(job + 0x45, 1, fmt="B")
        run(0x65A190, 0x65A1CC, r4=job, r7=scaler)
        require(
            list(uc.mem_read(scaler + 0x2A, 2)), [1, 0], "ordinary scaler output gates"
        )
        write(sp + 0x2C, scaler)
        run(0x580040, 0x580094)
        require(read(sp + 0x20), [normal], "ordinary scaler source getter")
        run(0x58091C, 0x580944, r5=device)
        require(scales, [[normal, first_jpeg]], "normal scaler launch pair")
        run(0x6593B0, r0=job, r1=16)
        jpeg = job + 0xA81C
        write(message + 8, jpeg)
        run(0x576D64, 0x576DB0, r7=message)
        require(reg("r8"), scales[0][1], "JPEG first input shares scaler destination")
        write(device + 0x400, 0x15000000)
        run(0x576AF8, 0x576B50, r8=first_jpeg, sb=device + 0x400)
        require(read(sp + 8, 3), scaled_planes, "JPEG codec input plane fields")
        results.append(
            {
                "mask_byte": mask,
                "second_cpp_pass": second,
                "injected_blend_mode": blend_mode,
                "module17_completion": callbacks[0][0],
                "blend_requests_source1_source2_destination": list(requests),
                "blend_destination_is_ordinary_scaler_source": (
                    primary == normal if second else None
                ),
                "ordinary_scaler_source_planes": read(normal + 4, 3),
                "jpeg_input_planes": scaled_planes,
            }
        )

    # The alternate scaler entry reads the masked layout only when its own gate is set.
    scales.clear()
    write(sp + 0x10, job + 0x2178)
    write(sp + 0x1C, job + 0x21E8)
    write(sp + 0x18, job + 0x2204)
    run(0x659EC8, 0x659FB0, r4=job, r8=masked, sb=0)
    require(
        read(scaler + 0x18, 3),
        [masked, job + 0x238C, job + 0x23A8],
        "alternate scaler image descriptor bindings",
    )
    require(uc.mem_read(scaler + 0x38, 1)[0], 0, "alternate scaler producer gate")
    write(sp + 0x2C, scaler)
    write(sp + 0x1C, masked)
    write(sp + 0x18, job + 0x238C)
    run(0x5804A0, 0x5808A8, r5=device)
    require(scales, [], "initialized alternate scaler branch is skipped")
    write(scaler + 0x38, 1, fmt="B")
    run(0x5804A0, 0x5804D8, r5=device)
    require(
        scales,
        [[masked, job + 0x238C]],
        "alternate scaler launch pair with injected gate",
    )
    return {
        "engine": f"Unicorn {__version__}",
        "recipe_order": ["CPP", "module 17", "scaler", "module 16 JPEG"],
        "zero_based_recipe_rows": recipes,
        "handoff_cases": results,
        "injected_alternate_scaler_gate_launch_job_offsets": [0x2354, 0x238C],
        "hooked_code_offsets": list(boundary_offsets),
        "synthetic_completion_callback": callback + 0x20,
    }


def analyze(data):
    return {
        "decoded_sha256": DECODED_SHA256,
        "candidate_load_base": BASE,
        "location_units": "decoded file offsets except absolute MMIO and synthetic addresses",
        "static": verify_static(data),
        "synthetic_a32": emulate(data),
        "limits": [
            "Module 17 receives the CPP second-pass planes as a separate blend input. "
            "With job+0x7f clear, its blend destination descriptor aliases the ordinary scaler source. "
            "With job+0x7f equal to one, it instead aliases job+0x2354.",
            "The receiver's gate is replayed separately from the blend builder. The builder probes "
            "enter after feature and allocation checks and inject the blend mode. The zero mode "
            "issues two chroma requests. The tested modes 2 and 4 also issue a luma request.",
            "The scaler payload binds job+0x2354 as an auxiliary source and initializes its enable "
            "byte to zero. The verifier sets the byte to one only in a counterfactual probe. "
            "The auxiliary scaler destination job+0x238c is distinct from the tested JPEG input.",
            "The probes execute A32 address selection, dispatch and request assembly on aligned "
            "synthetic planes. Service calls and scaler launches are intercepted. The recipe rows "
            "establish relative order. Intervening stages and the resulting pixel contents, "
            "physical camera mode eligibility and JPEG bytes are untested.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = json.dumps(analyze(load_image(args.decoded)), indent=2)
    if args.compare:
        require_snapshot(
            json.loads(result), args.compare, "published CPP handoff evidence"
        )
    print(result)


if __name__ == "__main__":
    main()
