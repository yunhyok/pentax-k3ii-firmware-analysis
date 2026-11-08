"""Compile and replay a C reconstruction of the K-3 II v1.12 tone leaf.

SPDX-License-Identifier: GPL-2.0-only
"""

import argparse
from collections import Counter
import json
import os
from pathlib import Path
import re
import struct
import subprocess
from tempfile import TemporaryDirectory

from verify_findings import require, require_snapshot, sha256, u32
from verify_raw_path import branch_target
from verify_tone_numeric import U16, interpolate, synthetic_curves, verify_numeric
from verify_tone_path import BASE, load_image


ENTRY = 0x4DD3EC
END = 0x4DD42C
SIZE = END - ENTRY
ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "rebuild/tone_interpolate.c"
NUMERIC_BASELINE = ROOT / "analysis/tone-numeric.json"
TARGET_FLAGS = ("-target", "arm-freestanding-eabi", "-mcpu=cortex_a9", "-marm")
BUILD_FLAGS = TARGET_FLAGS + (
    "-Os",
    "-ffreestanding",
    "-fno-stack-protector",
    "-fno-unwind-tables",
    "-fno-asynchronous-unwind-tables",
)
ORIGINAL_LEAF_SHA256 = (
    "48d5fa13e54e9ee871b49fb1ec22c5e110ca2f5b6fef7715f70487b40023006f"
)
# Each original loop supplies its own condition flags before its first
# conditional instruction after the tone calls.
CALLER_CONDITIONS = (
    (0x4DD514, 0x4DD59C, 0x4DD5A4, 0x4DD4FC, 0xE3530C01),
    (0x4DD794, 0x4DD7D4, 0x4DD7F0, 0x4DD780, 0xE3530C01),
    (0x4DD860, 0x4DD898, 0x4DD8A0, 0x4DD84C, 0xE3570C01),
)
CALL_SLICES = (
    ("composer_four_outputs", 0x4DD4F0, 0x4DD5A8, (0x4DD510, 0x4DD52C, 0x4DD54C)),
    ("composer_weighted_only", 0x4DD768, 0x4DD7F4, (0x4DD790, 0x4DD7A8, 0x4DD7C4)),
    ("composer_three_outputs", 0x4DD848, 0x4DD8A4, (0x4DD85C, 0x4DD874, 0x4DD88C)),
)


def replay(data, *, invert_return_flags=False):
    import unicorn
    from unicorn import arm_const as arm

    preserved = tuple(getattr(arm, f"UC_ARM_REG_R{i}") for i in range(3, 13)) + (
        arm.UC_ARM_REG_SP,
    )
    vm = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
    vm.ctl_set_cpu_model(arm.UC_CPU_ARM_CORTEX_A9)
    vm.mem_map(BASE, 0x1000000)
    vm.mem_write(BASE, data[:0x1000000])

    obj, stack = 0x10000000, 0x10020000
    tables = (0x10030E00, 0x10032E00, 0x10034E00)
    vm.mem_map(obj, 0x22000)
    for table in tables:
        vm.mem_map(table & ~0xFFF, 0x1000)
    reg = vm.reg_read
    set_reg = vm.reg_write

    curves = tuple(synthetic_curves().values())[:3]
    for table, curve in zip(tables, curves):
        vm.mem_write(table, U16.pack(*curve))

    sample_pattern = (0, 1, 31, 63, 64, 65, 0x3FBE, 0x3FBF, 0x3FC0, 0x3FC1, 0xFFFF)
    samples = tuple(
        tuple(sample_pattern[(i + lane * 3) % len(sample_pattern)] for i in range(256))
        for lane in range(3)
    )
    counts = Counter()
    inflight = None
    calls = {BASE + site: site for _, _, _, sites in CALL_SLICES for site in sites}
    returns = {addr + 4: site for addr, site in calls.items()}

    def observe(_vm, addr, _size, _user):
        nonlocal inflight
        if addr in calls:
            require(inflight, None, "no nested call")
            site = calls[addr]
            table = reg(arm.UC_ARM_REG_R1)
            sample = reg(arm.UC_ARM_REG_R2)
            require(table in tables, True, f"curve pointer {table:#x} at {site:#x}")
            expected = interpolate(curves[tables.index(table)], sample)
            state = tuple(reg(register) for register in preserved)
            inflight = site, expected, state
        else:
            site, expected, state = inflight
            require(returns[addr], site, "return to originating caller")
            require(reg(arm.UC_ARM_REG_R0), expected, "interpolator result")
            require(reg(arm.UC_ARM_REG_LR), addr, "link register")
            require(
                tuple(reg(register) for register in preserved), state, "r3-r12 and SP"
            )
            require(reg(arm.UC_ARM_REG_CPSR) & 0x20, 0, "return in A32 state")
            counts[site] += 1
            inflight = None
            if invert_return_flags:
                set_reg(arm.UC_ARM_REG_CPSR, reg(arm.UC_ARM_REG_CPSR) ^ 0xF0000000)

    observations = [
        vm.hook_add(unicorn.UC_HOOK_CODE, observe, begin=address, end=address)
        for address in calls.keys() | returns.keys()
    ]

    results = {}
    for index, (label, begin, end, sites) in enumerate(CALL_SLICES):
        for site in sites:
            require(branch_target(data, site), ENTRY, "interpolator call target")
        vm.mem_write(obj, b"\xA5" * 0x20000)
        vm.mem_write(stack, b"\xA5" * 0x1000)
        set_reg(arm.UC_ARM_REG_R0, tables[2])
        set_reg(arm.UC_ARM_REG_R4, obj)
        set_reg(arm.UC_ARM_REG_R8, tables[0])
        set_reg(arm.UC_ARM_REG_SP, stack)
        if index == 0:
            for lane, offset in enumerate((0x1820C, 0x1840C, 0x1860C)):
                vm.mem_write(obj + offset, U16.pack(*samples[lane]))
            vm.mem_write(stack + 0x814, struct.pack("<II", *tables[:2]))
            inputs = samples
            outputs = tuple(stack + offset for offset in (0x600, 0, 0x200, 0x400))
        else:
            vm.mem_write(obj + 8, U16.pack(*samples[0]))
            if index == 1:
                vm.mem_write(stack, struct.pack("<III", *tables))
            else:
                vm.mem_write(stack + 0x10, struct.pack("<II", *tables[1:]))
            inputs = (samples[0],) * 3
            outputs = (
                (obj + 0x1880C,)
                if index == 1
                else tuple(obj + offset for offset in (0x1820C, 0x1840C, 0x1860C))
            )
        vm.emu_start(BASE + begin, BASE + end, count=40000)
        require(reg(arm.UC_ARM_REG_PC), BASE + end, label)
        require(inflight, None, "all calls returned")
        values = [
            [interpolate(curve, sample) for sample in src]
            for curve, src in zip(curves, inputs)
        ]
        weighted = [(77 * r + 150 * g + 29 * b) >> 8 for r, g, b in zip(*values)]
        expected = {0: values + [weighted], 1: [weighted], 2: values}[index]
        got = b"".join(bytes(vm.mem_read(address, U16.size)) for address in outputs)
        require(got, b"".join(U16.pack(*out) for out in expected), label)
        require([counts[site] for site in sites], [256] * 3, label + " call counts")
        results[label] = {
            "slice_file_offsets": [hex(begin), hex(end)],
            "calls": {hex(site): counts[site] for site in sites},
            "outputs": 256 * len(outputs),
            "output_sha256": sha256(got),
        }

    sentinel = 0x10022000
    direct_samples = (
        0,
        1,
        63,
        64,
        0x3FBF,
        0x3FC0,
        0xFFFF,
        0x10000,
        0x80000000,
        0xFFFFFFFF,
    )

    def check_pc(_vm, address, size, _user):
        require(
            BASE + ENTRY <= address < BASE + END and size == 4,
            True,
            "direct leaf instruction range and size",
        )

    accesses = []

    def record_access(_vm, access, address, size, _value, _user):
        accesses.append((access, address, size))

    direct_hooks = [
        vm.hook_add(unicorn.UC_HOOK_CODE, check_pc),
        vm.hook_add(
            unicorn.UC_HOOK_MEM_READ | unicorn.UC_HOOK_MEM_WRITE, record_access
        ),
    ]
    vm.ctl_flush_tb()  # Instrument the leaf even if callers already translated it.
    direct_reads = 0
    z_flags = []
    for table, curve in zip(tables, curves):
        for sample in direct_samples + (0x3FC1,):
            # Unique nonzero values expose accidental register clobbers.
            for index, register in enumerate(preserved[:-1]):
                set_reg(register, 0x5A005000 + index)
            set_reg(arm.UC_ARM_REG_SP, stack + 0x100)
            state = tuple(reg(register) for register in preserved)
            set_reg(arm.UC_ARM_REG_R0, 0xDEAD0000)  # Context is deliberately unmapped.
            set_reg(arm.UC_ARM_REG_R1, table)
            set_reg(arm.UC_ARM_REG_R2, sample)
            set_reg(arm.UC_ARM_REG_LR, sentinel)
            accesses.clear()
            vm.emu_start(BASE + ENTRY, sentinel, count=32)
            require(reg(arm.UC_ARM_REG_PC), sentinel, "direct leaf return")
            require(reg(arm.UC_ARM_REG_LR), sentinel, "direct link register")
            require(
                tuple(reg(register) for register in preserved),
                state,
                "direct r3-r12 and SP",
            )
            cpsr = reg(arm.UC_ARM_REG_CPSR)
            require(cpsr & 0x20, 0, "direct return in A32 state")
            if sample == 0x3FC1:
                z_flags.append((cpsr >> 30) & 1)
            require(
                reg(arm.UC_ARM_REG_R0), interpolate(curve, sample), "direct u32 input"
            )
            index = sample >> 6
            indices = (255,) if index >= 255 else (index, index + 1)
            expected = [(unicorn.UC_MEM_READ, table + 2 * i, 2) for i in indices]
            require(sorted(accesses), expected, "direct table accesses and no spills")
            direct_reads += len(accesses)
    for hook in direct_hooks:
        vm.hook_del(hook)

    for hook in observations:
        vm.hook_del(hook)
    negative_controls = []
    for (
        name,
        register,
        poison,
        site,
        end,
        expected_error,
        expected_pc,
        expected_address,
    ) in (
        (
            "r3",
            arm.UC_ARM_REG_R3,
            0x40000000,
            0x4DD510,
            0x4DD51C,
            unicorn.UC_ERR_WRITE_UNMAPPED,
            0x4DD518,
            stack + 0x600 + 0x80000000,
        ),
        (
            "r12",
            arm.UC_ARM_REG_R12,
            0xDEAD0000,
            0x4DD790,
            0x4DD79C,
            unicorn.UC_ERR_READ_UNMAPPED,
            0x4DD798,
            0xDEAD0008,
        ),
    ):
        set_reg(arm.UC_ARM_REG_R1, tables[0])
        set_reg(arm.UC_ARM_REG_R2, 1)
        set_reg(arm.UC_ARM_REG_R3, 0)
        set_reg(arm.UC_ARM_REG_R11, stack + 0x600)
        set_reg(arm.UC_ARM_REG_R12, obj)
        fault = []

        def clobber(_vm, _addr, _size, _user):
            set_reg(register, poison)

        def record_fault(_vm, _access, address, size, _value, _user):
            fault.append((reg(arm.UC_ARM_REG_PC), address, size))
            return False

        poison_hook = vm.hook_add(
            unicorn.UC_HOOK_CODE,
            clobber,
            begin=BASE + site + 4,
            end=BASE + site + 4,
        )
        fault_hook = vm.hook_add(unicorn.UC_HOOK_MEM_UNMAPPED, record_fault)
        vm.ctl_flush_tb()
        try:
            vm.emu_start(BASE + site, BASE + end, count=32)
        except unicorn.UcError as error:
            require(error.errno, expected_error, f"{name} expected caller fault")
        else:
            raise ValueError(f"{name} clobber unexpectedly continued")
        finally:
            vm.hook_del(fault_hook)
            vm.hook_del(poison_hook)
        require(
            fault, [(BASE + expected_pc, expected_address, 2)], f"{name} caller fault"
        )
        negative_controls.append(
            {
                "register_clobbered_at_caller_return": name,
                "caller_fault_file_offset": hex(expected_pc),
                "fault_address": hex(expected_address),
            }
        )

    return {
        "engine": f"Unicorn {unicorn.__version__}",
        "caller_slices": results,
        "caller_calls": sum(counts.values()),
        "caller_outputs": sum(row["outputs"] for row in results.values()),
        "direct_leaf_cases": len(tables) * (len(direct_samples) + 1),
        "direct_table_halfword_reads": direct_reads,
        "register_clobber_negative_controls": negative_controls,
    }, z_flags


def inspect_elf(path):
    from elftools.elf.elffile import ELFFile
    from elftools.elf.relocation import RelocationSection

    with path.open("rb") as stream:
        elf = ELFFile(stream)
        require(
            (elf.elfclass, elf.little_endian, elf["e_machine"], elf["e_type"]),
            (32, True, "EM_ARM", "ET_REL"),
            "compiled object format",
        )
        require(elf["e_flags"] >> 24, 5, "ARM EABI version")

        text = elf.get_section_by_name(".text")
        text_index = elf.get_section_index(".text")
        require(text is not None, True, "compiled text section")
        require(
            (text["sh_type"], text["sh_flags"], text["sh_addralign"], text["sh_size"]),
            ("SHT_PROGBITS", 6, 4, SIZE),
            "compiled text extent and alignment",
        )
        sections = list(elf.iter_sections())
        require(
            [section.name for section in sections if section["sh_flags"] & 4],
            [".text"],
            "executable sections",
        )
        require(
            [section.name for section in sections if section["sh_flags"] & 2],
            [".text", ".ARM.exidx"],
            "allocated sections",
        )
        relocations = [
            section for section in sections if isinstance(section, RelocationSection)
        ]
        require(
            sum(
                section.num_relocations()
                for section in relocations
                if section["sh_info"] == text_index
            ),
            0,
            "text relocations",
        )

        symtab = elf.get_section_by_name(".symtab")
        require(symtab is not None, True, "compiled symbol table")
        symbols = list(symtab.iter_symbols())
        require(
            [
                (sym.name, sym["st_value"], sym["st_size"], sym["st_info"]["bind"])
                for sym in symbols
                if sym["st_shndx"] == text_index
                and sym["st_info"]["type"] == "STT_FUNC"
            ],
            [("tone_interpolate", 0, SIZE, "STB_GLOBAL")],
            "complete function symbol extent",
        )
        require(
            [
                (sym.name, sym["st_value"])
                for sym in symbols
                if sym["st_shndx"] == text_index and sym.name.startswith("$")
            ],
            [("$a", 0)],
            "A32 text mapping symbol",
        )
        require(
            [
                sym.name
                for sym in symbols
                if sym.name and sym["st_shndx"] == "SHN_UNDEF"
            ],
            [],
            "undefined symbols",
        )

        attributes = elf.get_section_by_name(".ARM.attributes")
        require(attributes is not None, True, "compiled ARM attributes")
        tags = {
            attr.tag: attr.value
            for subsection in attributes.iter_subsections()
            if subsection.header["vendor_name"] == "aeabi"
            for scope in subsection.iter_subsubsections()
            for attr in scope.iter_attributes()
        }
        require(
            tuple(
                tags.get(tag)
                for tag in ("TAG_CPU_NAME", "TAG_CPU_ARCH", "TAG_ARM_ISA_USE")
            ),
            ("cortex-a9", 10, 1),
            "ARM target attributes",
        )
        return text.data(), {
            "format": "ELF32 little-endian ARM relocatable",
            "arm_eabi_version": 5,
            "arm_cpu": tags["TAG_CPU_NAME"],
            "arm_arch_tag": tags["TAG_CPU_ARCH"],
            "execution_mode": "A32",
            "text_size": text["sh_size"],
            "text_alignment": text["sh_addralign"],
            "symbol_size": SIZE,
            "text_relocations": 0,
            "other_relocation_sections": [section.name for section in relocations],
        }


def compile_tone(zig, source):
    zig = zig.resolve(strict=True)

    with TemporaryDirectory(prefix="k3ii-tone-rebuild-") as temporary:
        folder = Path(temporary)
        env = {
            **os.environ,
            "ZIG_GLOBAL_CACHE_DIR": str(folder / "global-cache"),
            "ZIG_LOCAL_CACHE_DIR": str(folder / "local-cache"),
        }

        def run(*args):
            return subprocess.run(
                [str(zig), *args],
                cwd=folder,
                env=env,
                check=True,
                capture_output=True,
                text=True,
                timeout=180,
            ).stdout

        zig_version = run("version").strip()
        require(zig_version, "0.17.1", "Zig version")
        version = run("cc", *TARGET_FLAGS, "--version")
        clang = re.search(r"^clang version (\S+)", version, re.MULTILINE)
        triple = re.search(r"^Target: (\S+)", version, re.MULTILINE)
        require(clang.group(1) if clang else None, "22.1.8", "Clang version")
        require(
            triple.group(1) if triple else None,
            "armv7a-unknown-unknown-eabi",
            "Clang target",
        )

        temp_source = folder / SOURCE.name
        temp_source.write_bytes(source)
        obj = folder / "tone_interpolate.o"
        run("cc", *BUILD_FLAGS, "-c", temp_source.name, "-o", obj.name)
        text, metadata = inspect_elf(obj)
        return text, {
            "zig_version": zig_version,
            "clang_version": clang.group(1),
            "clang_target": triple.group(1),
            "flags": list(BUILD_FLAGS),
            "object": metadata,
        }


def verify_rebuild(decoded, zig):
    # Check the user-supplied original image before invoking the compiler.
    data = load_image(decoded)
    source_hash = sha256(data)
    require(sha256(data[ENTRY:END]), ORIGINAL_LEAF_SHA256, "original leaf")
    source = SOURCE.read_text(encoding="utf-8").encode("utf-8")
    code, compiler = compile_tone(zig, source)
    require(len(code), SIZE, "replacement footprint")
    require(code != data[ENTRY:END], True, "new instructions differ from original")

    for start, cmp_site, branch_site, loop, expected_word in CALLER_CONDITIONS:
        require(u32(data, cmp_site), expected_word, "caller-local comparison")
        require(
            all(u32(data, site) >> 28 == 0xE for site in range(start, branch_site, 4)),
            True,
            "no predication before the caller's loop branch",
        )
        require(u32(data, branch_site) >> 24, 0xBA, "caller loop BLT condition")
        require(branch_target(data, branch_site), loop, "caller loop branch target")

    # A temporary in-memory input to Unicorn. Only the requested leaf changes.
    replacement = data[:ENTRY] + code + data[END:]
    require(len(replacement), len(data), "unchanged image size")
    require(
        replacement[:ENTRY] == data[:ENTRY] and replacement[END:] == data[END:],
        True,
        "bytes outside the leaf",
    )
    require(replacement[:64] == data[:64], True, "original image first 64 bytes")
    original, original_z = replay(data)
    rebuilt, rebuilt_z = replay(replacement)
    require(rebuilt, original, "original versus rebuilt caller and direct replay")
    require((original_z, rebuilt_z), ([1, 1, 1], [0, 0, 0]), "direct Z-flag difference")
    for label, image in (("original", data), ("rebuilt", replacement)):
        perturbed, _ = replay(image, invert_return_flags=True)
        require(perturbed, original, f"{label} caller return NZCV inversion")

    baseline = json.loads(NUMERIC_BASELINE.read_text(encoding="utf-8"))
    require(baseline["decoded_sha256"], source_hash, "published original numeric image")
    computed = verify_numeric(replacement)
    numeric = {
        key: computed[key]
        for key in (
            "engine",
            "emulated_cpu",
            "checks",
            "outputs_compared",
            "apply_checks",
        )
    }
    require(
        numeric,
        {key: baseline[key] for key in numeric},
        "published original numeric results",
    )

    return {
        "schema_version": 1,
        "firmware_version": "1.12",
        "source_image_sha256": source_hash,
        "leaf_file_start": ENTRY,
        "leaf_file_end_exclusive": END,
        "leaf_execution_va": BASE + ENTRY,
        "original_leaf_sha256": ORIGINAL_LEAF_SHA256,
        "c_source": SOURCE.relative_to(ROOT).as_posix(),
        "c_source_sha256": sha256(source),
        "c_source_hash_input": "UTF-8 with LF line endings",
        "compiled_leaf_sha256": sha256(code),
        "compiler": compiler,
        "emulator_overlay": {
            "bytes": SIZE,
            "unchanged_image_size": True,
            "unchanged_outside_leaf": True,
            "unchanged_image_first_64_bytes": True,
        },
        "matching_original_and_rebuilt_replay": rebuilt,
        "caller_return_flags_perturbation": {
            "changed_bits": "N,Z,C,V",
            "method": "XOR 0xf0000000 at every observed caller return",
            "returns_per_image": rebuilt["caller_calls"],
            "images": ["original", "rebuilt"],
            "same_caller_outputs": True,
        },
        "flags_difference_case": {
            "input_r2": 0x3FC1,
            "original_z": original_z[0],
            "rebuilt_z": rebuilt_z[0],
            "caller_local_cmp_file_offsets": [row[1] for row in CALLER_CONDITIONS],
            "caller_conditional_branch_file_offsets": [
                row[2] for row in CALLER_CONDITIONS
            ],
        },
        "published_original_numeric_baseline": NUMERIC_BASELINE.relative_to(
            ROOT
        ).as_posix(),
        "matching_numeric_results": numeric,
        "limits": [
            "Only the bounded scalar tone leaf is reconstructed. The input image is read-only and the replacement exists only in emulator memory.",
            "The temporary ELF has unwind metadata outside .text. Only the validated 64-byte A32 text is used.",
            "The original caller slices receive prepared stack, tables and objects. Direct fixtures check r3-r12, SP, LR, A32 state, and exact table reads without stores.",
            "APSR flags and the scratch values of r1/r2 may differ. The nine observed calls are in three loops that set their own condition flags before the conditional backedges.",
            "The complete numeric replay uses synthetic inputs and RAM-backed device addresses. Hardware, timing, installation and firmware packaging are outside the checks.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded", type=Path)
    parser.add_argument("--zig", required=True, type=Path)
    parser.add_argument("--compare", type=Path)
    args = parser.parse_args()
    try:
        result = verify_rebuild(args.decoded, args.zig)
        if args.compare:
            require_snapshot(result, args.compare, "tone rebuild evidence")
    except subprocess.CalledProcessError as error:
        parser.exit(1, f"Zig failed with exit {error.returncode}\n{error.stderr}")
    except (ImportError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"Tone rebuild verification failed\n{error}\n")
    if args.compare:
        print(f"Tone rebuild evidence matches {args.compare}")
    else:
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
