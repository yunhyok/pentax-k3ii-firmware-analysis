"""Verify selected K-3 II white balance, matrix and clipping paths.

SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import json
from pathlib import Path

from verify_findings import (
    DECODED_SHA256,
    literal_offset,
    require,
    require_snapshot,
    sha256,
    u32,
)
from verify_tone_path import BASE, adr_r0_target, check_edge, check_words, load_image


B2Y = 0x20020000
WB_REGISTER_ORDER = (0, 3, 1, 2)
# Hardware slots in register order: name, dump ADR, diagnostic read offset,
# register offset, field shift, field width, write helper and BFI instruction.
WB = (
    ("OFSTRR", 0x5B3448, 0x5B3444, 0x80, 0, 14, 0x5B3F04, 0x5B3F1C),
    ("OFSTBB", 0x5B345C, 0x5B3458, 0x80, 16, 14, 0x5B3F2C, 0x5B3F44),
    ("OFSTGR", 0x5B346C, 0x5B3470, 0x84, 0, 14, 0x5B3F54, 0x5B3F6C),
    ("OFSTGB", 0x5B3480, 0x5B3484, 0x84, 16, 14, 0x5B3F7C, 0x5B3F94),
    ("WBGARR", 0x5B34A0, 0x5B3498, 0x8C, 0, 11, 0x5B4044, 0x5B404C),
    ("WBGABB", 0x5B34B0, 0x5B34A8, 0x8C, 16, 11, 0x5B4058, 0x5B4060),
    ("WBGAGR", 0x5B34C0, 0x5B34B8, 0x90, 0, 11, 0x5B406C, 0x5B4074),
    ("WBGAGB", 0x5B34D0, 0x5B34C8, 0x90, 16, 11, 0x5B4080, 0x5B4088),
)

# Name, apply function, setter, first register, width, source, BFI sites.
MATRICES = (
    ("CC0K", 0x4C2BA0, 0x5B42D4, 0x120, 12, 0xC,
     (0x5B42E0, 0x5B42F0, 0x5B4300, 0x5B4310, 0x5B4320, 0x5B4330, 0x5B4340, 0x5B4350, 0x5B4360)),
    ("CC1K", 0x4C27D4, 0x5B6CC8, 0x8A0, 12, 0x1E6,
     (0x5B6CD8, 0x5B6CE8, 0x5B6CFC, 0x5B6D0C, 0x5B6D20, 0x5B6D30, 0x5B6D44, 0x5B6D54, 0x5B6D6C)),
    ("YC", 0x4C2B44, 0x5B6EC8, 0x900, 13, 0x24,
     (0x5B6ED8, 0x5B6EE8, 0x5B6EFC, 0x5B6F0C, 0x5B6F20, 0x5B6F30, 0x5B6F44, 0x5B6F54, 0x5B6F6C)),
)

# Name, apply, first register, clip source pointer offset, setter/first BFI offset.
CLIPS = (
    ("CCYC_CLP", 0x4C2BA0, 0x144, 0x20, ((0x5B4444, 0x5B444C), (0x5B4468, 0x5B4470))),
    ("CC1_CLP", 0x4C27D4, 0x8C0, 0x1F8, ((0x5B6E00, 0x5B6E0C), (0x5B6E48, 0x5B6E50), (0x5B6E88, 0x5B6E90))),
    ("YC_CLP", 0x4C2B44, 0x920, 0x38, ((0x5B7000, 0x5B700C), (0x5B7048, 0x5B7050), (0x5B7088, 0x5B7090))),
    ("MC_CLP", 0x4C2868, 0x78C, 0x1E0, ((0x5B63D8, 0x5B63E0), (0x5B6418, 0x5B6424), (0x5B6460, 0x5B6468))),
)

# Tone clips consume pairs of u32s, unlike the matrix clip records above.
# Descriptor offset, apply call, setter, BFI, diagnostic ADR.
TONE_CLIPS = (
    (0x74, 0x4DE020, 0x5B6AD8, 0x5B6AE4, 0x5B1254),
    (0x7C, 0x4DE034, 0x5B6B1C, 0x5B6B2C, 0x5B1264),
    (0x84, 0x4DE048, 0x5B6B68, 0x5B6B74, 0x5B1274),
    (0x8C, 0x4DE05C, 0x5B6BAC, 0x5B6BB8, 0x5B1284),
)

EDGES = (
    *((call, setter) for _, call, setter, _, _ in TONE_CLIPS),
    (0x57BE68, 0x58B3A0), (0x57BE74, 0x58B420), (0x57C34C, 0x58B3A0), (0x57C3C0, 0x58B420),
    (0x58B3B0, 0x4E2F34), (0x58B3CC, 0x4E2F44), (0x58B3E8, 0x4E2F3C), (0x58B404, 0x4E2F2C),
    (0x58B3C4, 0x5B3F04), (0x58B41C, 0x5B3F2C), (0x58B3E0, 0x5B3F54), (0x58B3FC, 0x5B3F7C),
    (0x58B430, 0x4E1974), (0x58B44C, 0x4E1984), (0x58B468, 0x4E197C), (0x58B484, 0x4E196C),
    (0x58B444, 0x5B4044), (0x58B49C, 0x5B4058), (0x58B460, 0x5B406C), (0x58B47C, 0x5B4080),
    (0x57BD2C, 0x7543BC), (0x57BD34, 0x784A58),
    (0x57BD9C, 0x71B550), (0x57BDB4, 0x71B550), (0x57BDCC, 0x71B550), (0x57BDE4, 0x71B550),
    (0x57BDA0, 0x73E1D8), (0x57BDB8, 0x73E1E8), (0x57BDD0, 0x73E1E0), (0x57BDE8, 0x73E1D0),
    (0x57BDAC, 0x784A40), (0x57BDC4, 0x784A50), (0x57BDDC, 0x784A48), (0x57BDF4, 0x784A38),
    (0x62646C, 0x7DCB78), (0x626478, 0x7DCB98), (0x626484, 0x7DCB90), (0x626490, 0x7DCB70),
    (0x62649C, 0x784A58), (0x6264A8, 0x784A40), (0x6264B4, 0x784A50),
    (0x6264C0, 0x784A48), (0x6264CC, 0x784A38), (0x6264DC, 0x58B420),
    (0x4BCBD4, 0x4C2774), (0x4BCD80, 0x4C2C18), (0x4BCDE8, 0x4DDE3C),
    (0x4C279C, 0x4C2598), (0x4C27AC, 0x4C255C), (0x4C27B8, 0x4C21B0), (0x4C27C8, 0x4C2158),
    (0x4C25D4, 0x4C48E0), (0x4C25C4, 0x538158), (0x4C25F0, 0x4C24D4),
    (0x4C2610, 0x4C24D4), (0x4C2640, 0x4C24D4), (0x4C2764, 0x4FA65C), (0x4C2584, 0x4C24D4),
    (0x4C2188, 0x4FA67C), (0x4C219C, 0x7129D0), (0x4C21A4, 0x4FA674),
    (0x4C258C, 0x4FA6A4), (0x4C21C4, 0x4FA654),
    (0x4C2C20, 0x4C2BA0), (0x4C2C28, 0x4C2B44), (0x4C2C30, 0x4C2868), (0x4C2C3C, 0x4C27D4),
    (0x4C2BC8, 0x5B4284), (0x4C2BD8, 0x5B42B0), (0x4C2BE4, 0x5B42D4), (0x4C2BF0, 0x5B43E0),
    (0x4C2C00, 0x5B4444), (0x4C2C14, 0x5B4468),
    (0x4C27FC, 0x5B6C70), (0x4C2814, 0x5B6CA0), (0x4C2824, 0x5B6CC8),
    (0x4C2838, 0x5B6E00), (0x4C284C, 0x5B6E48), (0x4C2864, 0x5B6E88),
    (0x4C2B5C, 0x5B6EC8), (0x4C2B70, 0x5B7000), (0x4C2B84, 0x5B7048), (0x4C2B9C, 0x5B7088),
    (0x4C288C, 0x5B63D8), (0x4C28A0, 0x5B6418), (0x4C28B4, 0x5B6460),
)
TAILS = {0x58B41C, 0x58B49C, 0x4C27C8, 0x4C2C3C, 0x4C2C14, 0x4C2864, 0x4C2B9C}


def diagnostic(data, adr, label):
    string = adr_r0_target(data, adr)
    prefix = ("IO_B2Y.F_B2Y." + label).encode()
    require(data[string:string + len(prefix)], prefix, f"diagnostic text at {string:#x}")
    # Two dump sites extract a field after ADR; several end with pop and a tail call.
    call = adr + (8 if adr in (0x5B346C, 0x5B3480) or u32(data, adr + 4) == 0xE8BD4010 else 4)
    check_edge(data, call, 0x7073EC, link=(u32(data, call) >> 24 == 0xEB))
    return {"adr": adr, "string_offset": string, "label": label}


def check_bfi(data, offset, shift, width):
    word = u32(data, offset)
    require(word & 0xFFE00070, 0xE7C00010, f"BFI at {offset:#x}")
    lsb = word >> 7 & 31
    require((lsb, (word >> 16 & 31) - lsb + 1), (shift, width), f"BFI field at {offset:#x}")


def verify(data):
    for site, target in EDGES:
        check_edge(data, site, target, link=site not in TAILS)
    for site, value in {
        0x5B124C: B2Y+0x86C, 0x5B125C: B2Y, 0x5B126C: B2Y+0x874, 0x5B127C: B2Y+0x878,
        0x5B6AD8: B2Y+0x86C, 0x5B6B1C: B2Y, 0x5B6B68: B2Y+0x874, 0x5B6BAC: B2Y+0x878,
        0x5B3438: B2Y, 0x5B3200: B2Y, 0x5B0F08: B2Y, 0x5B0F58: B2Y, 0x5B0F68: B2Y+0x8C4,
        0x5B0F78: B2Y+0x8C8, 0x5B0C38: B2Y, 0x5B0C7C: B2Y, 0x5B0C8C: B2Y+0x924, 0x5B0C9C: B2Y+0x928,
        0x5B2F74: B2Y+0x78C, 0x5B2F84: B2Y, 0x5B2F94: B2Y+0x794, 0x5B6CF0: B2Y+0x8A4,
        0x5B6EF0: B2Y+0x904, 0x5B6E48: B2Y+0x8C4, 0x5B6E88: B2Y+0x8C8, 0x5B7048: B2Y+0x924,
        0x5B7088: B2Y+0x928, 0x5B63D8: B2Y+0x78C, 0x5B6460: B2Y+0x794,
        0x5B42D4: B2Y, 0x5B6CC8: B2Y, 0x5B6EC8: B2Y, 0x5B4444: B2Y, 0x5B4468: B2Y,
        0x5B6E00: B2Y, 0x5B7000: B2Y, 0x5B6418: B2Y, 0x5B4284: B2Y, 0x5B6C70: B2Y,
        0x5B42B0: B2Y, 0x5B6CA0: B2Y, 0x4C2604: BASE+0xA2C6AE, 0x4C2574: BASE+0xA2C6C0,
        **{setter: B2Y for _, _, _, _, _, _, setter, _ in WB},
    }.items():
        require(u32(data, literal_offset(data, site)), value, f"register base literal at {site:#x}")

    check_words(data, {
        0x5B1250: 0xE5901000, 0x5B1260: 0xE5901870, 0x5B1270: 0xE5901000, 0x5B1280: 0xE5901000,
        0x5B6B24: 0xE2830E87, 0x5B6B28: 0xE5933870,
        0x5B3204: 0xE5941100, 0x5B3210: 0xE5941120, 0x5B321C: 0xE5941124,
        0x5B3228: 0xE5941128, 0x5B3234: 0xE594112C, 0x5B3240: 0xE5941130,
        0x5B324C: 0xE5941140, 0x5B3258: 0xE5941144, 0x5B0F0C: 0xE2804B02,
        0x5B0F10: 0xE5901880, 0x5B0F1C: 0xE59410A0, 0x5B0F28: 0xE59410A4,
        0x5B0F34: 0xE59410A8, 0x5B0F40: 0xE59410AC, 0x5B0F4C: 0xE59410B0,
        0x5B0F5C: 0xE59018C0, 0x5B0F6C: 0xE5901000, 0x5B0F7C: 0xE5901000,
        0x5B343C: 0xE2840080, 0x5B3440: 0xE1C000D0, 0x5B3444: 0xE7ED1050,
        0x5B3458: 0xE7ED1850, 0x5B3470: 0xE7ED1051, 0x5B3484: 0xE7ED1851,
        0x5B3498: 0xE594008C, 0x5B349C: 0xE7EA1050, 0x5B34A8: 0xE594008C,
        0x5B34AC: 0xE7EA1850, 0x5B34B8: 0xE5940090, 0x5B34BC: 0xE7EA1050,
        0x5B34C8: 0xE5940090, 0x5B34CC: 0xE7EA1850, 0x5B0C3C: 0xE2804B02,
        0x5B0C40: 0xE5901900, 0x5B0C4C: 0xE5941104, 0x5B0C58: 0xE5941108,
        0x5B0C64: 0xE594110C, 0x5B0C70: 0xE5941110, 0x5B0C80: 0xE5901920,
        0x5B0C90: 0xE5901000, 0x5B0CA0: 0xE5901000, 0x5B2F78: 0xE5901000,
        0x5B2F88: 0xE5901790, 0x5B2F98: 0xE5901000,
        0x71B550: 0xE5900094, 0x73E1D8: 0xE1D000B0, 0x73E1E8: 0xE1D000B2,
        0x73E1E0: 0xE1D000B4, 0x73E1D0: 0xE1D000B6, 0x784A58: 0xE3A01C01,
        0x4E1974: 0xE1D000B0, 0x4E1984: 0xE1D000B2, 0x4E197C: 0xE1D000B4, 0x4E196C: 0xE1D000B6,
        0x4E2F34: 0xE1D000B0, 0x4E2F44: 0xE1D000B2, 0x4E2F3C: 0xE1D000B4, 0x4E2F2C: 0xE1D000B6,
        0x626468: 0xE2840FDB, 0x626470: 0xE1A062A0, 0x62647C: 0xE1A052A0,
        0x626488: 0xE1A082A0, 0x626494: 0xE1A072A0, 0x7DCB78: 0xE1D003BA,
        0x7DCB98: 0xE1D003BC, 0x7DCB90: 0xE1D003BE, 0x7DCB70: 0xE1D004B0,
        0x4BCBD0: 0xE2840F59, 0x4BCD70: 0xE5D40006, 0x4BCD7C: 0xE2840F59,
        0x4BCDD4: 0xE5D4000B, 0x4BCDE0: 0xE3000454, 0x4BCDE4: 0xE0800004,
        0x4C2780: 0xE20140FF, 0x4C2784: 0xE1A05421, 0x4C21A8: 0xE58401F8,
        0x4FA674: 0xE2800090, 0x4FA67C: 0xE590008C, 0x4C2590: 0xE5840038,
        0x4FA6A4: 0xE2800020, 0x4C2768: 0xE5840020, 0x4FA65C: 0xE2800010,
        0x4C21C8: 0xE58401E0, 0x4FA654: 0xE280007C, 0x4C257C: 0xE2841024,
        0x4C2808: 0x18BD8070, 0x4C2810: 0xE5D411E5, 0x4C2818: 0xE30001E6,
        0x4C281C: 0xE0841000, 0x4C2828: 0xE59401F8, 0x4C283C: 0xE59401F8,
        0x4C2850: 0xE59401F8, 0x4C2BB4: 0xE5D40008, 0x4C2BCC: 0xE1D400BA,
        0x4C2BDC: 0xE284100C, 0x4C2BE8: 0xE5941020, 0x4C2BF8: 0xE1D010B6,
        0x4C2C08: 0xE1D010B8, 0x4C2B58: 0xE2841024, 0x4C2B60: 0xE5940038,
        0x4C287C: 0xE59401E0, 0x4C48E0: 0xE590000C, 0x4C48E4: 0xE7900101,
        0x4C2518: 0xE105588E, 0x4C2520: 0xE2850A01, 0x4C2528: 0xE1A006A0,
        0x4C252C: 0xE1C500B0, 0x4C264C: 0xE1D121B2, 0x4C2690: 0xE1D111B0,
        0x4C26B0: 0xE1D110F0, 0x4C26B4: 0xE0010291, 0x4C26C8: 0xE1A01641,
        0x4C26D0: 0xE1C610B0, 0x4C26DC: 0xE1A00082, 0x4C26F4: 0xE1CD10B0,
        0x4C2708: 0xE1CD10B8, 0x4C271C: 0xE1CD01B0, 0x4C26E4: 0xE30057FF,
        0x4C26E8: 0xE3A06B3E, 0x4C2728: 0xE1D210F0, 0x4C272C: 0xE3510B02,
        0x4C2734: 0xA1C150BC, 0x4C273C: 0xE3710B02, 0x4C2744: 0xB1C160BC,
        0x4C2750: 0xA1C210BC, 0x4C2758: 0xE3500009,
        0x5B4050: 0xE580208C, 0x5B4064: 0xE580208C, 0x5B4078: 0xE5802090,
        0x5B408C: 0xE5802090, 0x5B4364: 0xE5802130, 0x5B6D70: 0xE5810000,
        0x5B6F70: 0xE5810000, 0x5B4288: 0xE2212001, 0x5B6C74: 0xE2212001,
        0x5B4294: 0xE5801100, 0x5B6C84: 0xE5810000,
    })

    for site, shift, width in ((0x5B4290, 0, 1), (0x5B6C80, 0, 1),
                               (0x5B42B8, 4, 2), (0x5B6CAC, 4, 2)):
        check_bfi(data, site, shift, width)

    wb = []
    for i, (name, adr, read, register, shift, width, setter, bfi) in enumerate(WB):
        check_bfi(data, bfi, shift, width)
        if i < 4:
            check_words(data, {setter+4: 0xE1E00001, setter+8: 0xE2802001, setter+16: 0xE7DF271F,
                               setter+32: 0xE1C200F0})
        wb.append({**diagnostic(data, adr, name), "read_anchor": read, "setter": setter, "write_field": bfi,
                   "address": B2Y + register, "bit_offset": shift, "width": width, "input_offset": 2 * WB_REGISTER_ORDER[i % 4]})

    matrices = {}
    for (name, apply, setter, start, width, source, sites), first_adr in zip(MATRICES, (0x5B3214, 0x5B0F20, 0x5B0C44)):
        for i, site in enumerate(sites):
            check_bfi(data, site, 16 * (i % 2), width)
        matrices[name] = {
            "apply": apply, "setter": setter, "object_source_offset": source, "coefficient_count": 9,
            "first_address": B2Y + start, "last_address": B2Y + start + 16,
            "coefficient_field_width": width, "alternating_bit_offsets": [0, 16], "write_fields": list(sites),
            "diagnostics": [diagnostic(data, first_adr + 12 * i,
                                       f"{name[:-1]}K.{name}{i+1}" if name != "YC" else f"YC.YC{i+1}") for i in range(5)],
        }

    clips = {}
    for (name, apply, start, source, sites), first_adr in zip(CLIPS, (0x5B325C, 0x5B0F60, 0x5B0C84, 0x5B2F7C)):
        if name != "CCYC_CLP":
            for _, first_bfi in sites:
                check_bfi(data, first_bfi, 0, 15)
                check_bfi(data, first_bfi + 12, 16, 16)
                check_words(data, {first_bfi+4: 0xE5803000, first_bfi+16: 0xE5801000})
        if name == "CCYC_CLP":
            check_bfi(data, sites[0][1], 0, 15)
            check_bfi(data, sites[1][1], 16, 16)
            check_words(data, {0x5B4450: 0xE5802144, 0x5B4474: 0xE5802144})
        count = 1 if name == "CCYC_CLP" else 3
        clips[name] = {
            "apply": apply, "addresses": [B2Y + start + 4 * i for i in range(count)],
            "setter_entries": [setter for setter, _ in sites], "object_pointer_offset": source,
            "record_halfword_offsets": [6, 8] if count == 1 else list(range(0, 12, 2)),
            "field_widths": [15, 16], "field_bit_offsets": [0, 16], "preserved_bit": 15,
            "diagnostics": [diagnostic(data, first_adr + 16 * i,
                                       name if count == 1 else f"{name}.word[{i}]") for i in range(count)],
        }

    tone_clips = []
    for i, (source, call, setter, bfi, adr) in enumerate(TONE_CLIPS):
        check_words(data, {call-16: 0xE5940208, call-12: 0xE2800000 | source, call-8: 0xE8900006,
                           setter+4: 0xE7DF179F, bfi+4: 0xE5803000, bfi+16: 0xE5801000})
        check_bfi(data, bfi, 0, 15)
        check_bfi(data, bfi+12, 16, 16)
        tone_clips.append({**diagnostic(data, adr, f"TC_CLP.word[{i}]"), "address": B2Y+0x86C+4*i,
                           "descriptor_u32_offsets": [source, source+4], "setter": setter, "call": call})

    return {
        "schema_version": 1, "decoded_sha256": DECODED_SHA256, "candidate_code_base": BASE,
        "offset_space": "Decoded file offsets except addresses and explicitly named object/record offsets.",
        "direct_edges": [{"site": site, "target": target, "link": site not in TAILS} for site, target in EDGES],
        "white_balance": {
            "offset_apply": 0x58B3A0, "gain_apply": 0x58B420, "fields": wb,
            "record_channel_order": ["RR", "GR", "GB", "BB"],
            "offset_encoding": "(-u16) & 0x3fff", "gain_encoding": "u16 & 0x7ff",
            "direct_gain": {"context_pointer_offset": 0x94, "gain_record_offsets": [0, 2, 4, 6],
                            "offset_record_offsets": [8, 10, 12, 14], "caller_fragment": 0x57BD28},
            "shifted_gain": {"caller_fragment": 0x626468, "object_record_offset": 0x36C,
                             "gain_record_offsets": [0x3A, 0x3C, 0x3E, 0x40], "logical_right_shift": 5},
        },
        "matrix_prepare_apply": {
            "parent_subobject_offset": 0x164, "parent_pending_byte_offset": 6,
            "prepare_entry": 0x4C2774, "apply_entry": 0x4C2C18,
            "CC0CTL": {**diagnostic(data, 0x5B3208, "CC0CTL"), "address": B2Y + 0x100,
                       "control_write_helper": 0x5B4284, "mode_write_helper": 0x5B42B0,
                       "object_control_byte": 8, "object_mode_halfword": 0xA},
            "CC1CTL": {**diagnostic(data, 0x5B0F14, "CC1CTL"), "address": B2Y + 0x880,
                       "control_write_helper": 0x5B6C70, "mode_write_helper": 0x5B6CA0,
                       "object_control_byte": 0x1E4, "object_mode_byte": 0x1E5},
            "control_fields": {"bit0": "object control byte != 0", "bits5_4": "low two bits of mode"},
            "CC1_nonzero_control": "Write control bit 0, then return before mode, coefficients or clips.",
            "CC0_selector": "Low byte of prepare argument indexes descriptor+0xc pointer array.",
            "YC_selector": "Prepare argument shifted right 8 indexes descriptor+0x1c pointer array.",
            "CC1_source": "Nine halfwords copied from *(descriptor+0x8c); clip pointer is descriptor+0x90.",
        },
        "matrix_registers": matrices,
        "clip_registers": clips,
        "tone_clip_registers": {
            "apply": 0x4DDE3C, "descriptor_pointer_offset": 0x208, "field_widths": [15, 16],
            "field_bit_offsets": [0, 16], "preserved_bit": 15, "words": tone_clips,
        },
        "CC0_coefficient_math": {
            "prepare_entry": 0x4C2598, "multiply_entry": 0x4C24D4,
            "multiply": "Three signed halfword products in a wrapping 32-bit accumulator; add 0x1000, shift right 13, retain low 16 bits.",
            "scale": "Multiply signed halfwords by a derived u16 factor and divide by 4096 toward zero; retain low 16 bits.",
            "factor": {"gain_object_offset": 0x210, "selector_object_offset": 0x212,
                       "multipliers": [64, 91, 128, 181, 256], "fallback_multiplier": 128, "divisor": 256},
            "diagonal": "Replace each diagonal with twice the factor minus the sum of its two off-diagonals, retaining low 16 bits.",
            "clamp_loop": 0x4C2720, "clamp_input": "s16", "clamp_bounds": [-2048, 2047],
        },
        "code_range_sha256": {f"{a:#x}..{b:#x}": sha256(data[a:b]) for a, b in (
            (0x57BD28, 0x57BE78), (0x58B3A0, 0x58B4A0), (0x626468, 0x6264E0),
            (0x4C2158, 0x4C21B0), (0x4C24D4, 0x4C2868), (0x4C2868, 0x4C2C40),
            (0x5B3F04, 0x5B40D4), (0x5B4284, 0x5B448C), (0x5B63D8, 0x5B64A0),
            (0x5B6C70, 0x5B70C8), (0x4DE010, 0x4DE060), (0x5B6AD8, 0x5B6BF0),
        )},
        "limits": [
            "CPU programming order does not establish the hardware pixel pipeline order.",
            "BFI/UBFX establish field encoding, not the hardware clip comparison signedness, endpoint role or physical transfer function.",
            "The signed CPU clamp applies to CC0 coefficients, not to sensor or output pixels.",
            "Descriptor contents, camera menu labels, WB estimation and real-camera rendering are not identified by this trace.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decoded_image", type=Path)
    output = parser.add_mutually_exclusive_group()
    output.add_argument("--output", type=Path)
    output.add_argument("--compare", type=Path)
    args = parser.parse_args()
    result = verify(load_image(args.decoded_image))
    serialized = json.dumps(result, indent=2) + "\n"
    if args.compare:
        require_snapshot(result, args.compare, "ISP path evidence")
        print(f"ISP path evidence matches {args.compare}")
    elif args.output:
        args.output.write_text(serialized, encoding="utf-8", newline="\n")
    else:
        print(serialized, end="")


if __name__ == "__main__":
    main()
