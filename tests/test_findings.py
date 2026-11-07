import math
import struct
import unittest

from verify_findings import analyze, entropy, literal_offset, u32


class FindingsTests(unittest.TestCase):
    def test_word_and_literal_bounds(self):
        data = struct.pack('<5I', 0xE59F0008, 0xE51F100C, 0, 0, 0x1234)
        self.assertEqual(literal_offset(data, 0), 16)
        self.assertEqual(literal_offset(data, 4), 0)
        self.assertEqual(u32(data, 16), 0x1234)
        for offset in [-1, 17]:
            with self.assertRaises(ValueError):
                u32(data, offset)
        with self.assertRaises(ValueError):
            literal_offset(data, 8)
        with self.assertRaises(ValueError):
            literal_offset(struct.pack('<I', 0xE59F0008), 0)

    def test_entropy_known_distributions(self):
        self.assertEqual(entropy(b''), 0)
        self.assertEqual(entropy(b'A' * 100), 0)
        self.assertEqual(entropy(bytes(range(256))), 8)
        self.assertAlmostEqual(entropy(b'ABAB'), 1)

    def test_wrong_firmware_rejected(self):
        with self.assertRaisesRegex(ValueError, 'identity'):
            analyze(b'not a camera image')


if __name__ == '__main__':
    unittest.main()
