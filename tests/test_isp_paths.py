import struct
import unittest

from verify_isp_numeric import clamp_coefficient, compose
from verify_isp_paths import check_bfi


class IspPathTests(unittest.TestCase):
    def test_field_verifier_rejects_wrong_width_or_non_bfi(self):
        bfi = struct.pack("<I", 0xE7DA2811)
        check_bfi(bfi, 0, 16, 11)
        with self.assertRaisesRegex(ValueError, "BFI field"):
            check_bfi(bfi, 0, 16, 12)
        with self.assertRaisesRegex(ValueError, "BFI at"):
            check_bfi(struct.pack("<I", 0xE580208C), 0, 16, 11)

    def test_signed_clip_treats_high_halfwords_as_negative(self):
        inputs = (0x07FF, 0x0800, 0x7FFF, 0x8000, 0xF7FF, 0xF800, 0xFFFF)
        self.assertEqual(tuple(map(clamp_coefficient, inputs)),
                         (2047, 2047, 2047, -2048, -2048, -2048, -1))

    def test_compose_rounds_signed_products_at_half_step(self):
        left = (1, 0, 0, -1, 0, 0, 0, 0, 0)
        right = (4095, 4096, 4097) + (0,) * 6
        self.assertEqual(compose(left, right), (0, 1, 1, 0, 0, -1, 0, 0, 0))
