import struct
import unittest

from verify_tone_numeric import expand, interpolate
from verify_tone_path import adr_r0_target, branch_target


class TonePathTests(unittest.TestCase):
    def test_forward_call_backward_branch_and_bounds(self):
        data = struct.pack("<4I", 0xEB000001, 0xEAFFFFFD, 0, 0)
        self.assertEqual(branch_target(data, 0), 12)
        self.assertEqual(branch_target(data, 4, link=False), 0)
        with self.assertRaisesRegex(ValueError, "invalid A32 branch"):
            branch_target(data, 4)
        with self.assertRaisesRegex(ValueError, "outside input"):
            branch_target(data[:8], 0)

    def test_adr_resolves_rotated_immediate(self):
        data = struct.pack("<I", 0xE28F0F49) + bytes(0x12C)
        self.assertEqual(adr_r0_target(data, 0), 0x12C)

    def test_interpolation_truncates_toward_zero_and_clamps_endpoint(self):
        curve = (100, 91) + (60,) * 253 + (7,)
        self.assertEqual(interpolate(curve, 1), 100)
        self.assertEqual(interpolate(curve, 32), 96)
        self.assertEqual(interpolate(curve, 0x3FC0), 7)
        self.assertEqual(interpolate(curve, 0xFFFF), 7)

    def test_simd_expansion_retains_halfword_wrap_and_raw_tail(self):
        curve = (0, 0x4000) + (0,) * 253 + (0xFFFF,)
        output = expand(curve)
        self.assertEqual(output[:4], (0, 0x1000, 0, 0))
        self.assertEqual(output[1020:1024], (0, 0, 0, 0))
        self.assertEqual(output[1024:], (0xFFFF,) * 256)
