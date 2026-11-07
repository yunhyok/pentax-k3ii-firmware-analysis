import struct
import unittest
from verify_hardware import rom_offset
from verify_raw_path import branch_target


class DeepHelpers(unittest.TestCase):
    def test_secondary_boundaries(self):
        self.assertEqual(rom_offset(0x1080), 0x1000080)
        self.assertEqual(rom_offset(0xFFFF), 0x100EFFF)
        for bad in (0xFFF, 0x10000):
            with self.assertRaises(ValueError):
                rom_offset(bad)

    def test_arm_relative_branches(self):
        self.assertEqual(branch_target(struct.pack('<I', 0xEB000003), 0), 20)
        self.assertEqual(branch_target(struct.pack('<I', 0x1AFFFFFE), 0), 0)
        for word in (0xE1A00000, 0xFA000000):
            with self.assertRaises(ValueError):
                branch_target(struct.pack('<I', word), 0)


if __name__ == '__main__':
    unittest.main()
