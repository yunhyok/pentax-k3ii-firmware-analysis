import hashlib
from pathlib import Path
import tempfile
import unittest

from inspect_firmware import FIRMWARE_SIZE, IV, decode, decode_region, write_outputs


class DecodeTests(unittest.TestCase):
    def test_upstream_vector_uses_relative_block_offsets(self):
        data = bytearray(0x100) + bytearray(range(0x100))
        IV.pack_into(data, 0x90, 0x12345678, 0x90ABCDEF, 0xFEDCBA98, 0x76543210)
        untouched = data[:0x100]

        decode_region(data, base=0x80, iv_offset=0x10, start=0x80, length=0x100)

        self.assertEqual(data[:0x100], untouched)
        self.assertEqual(
            hashlib.sha256(data[0x100:]).hexdigest(),
            "f223434947438039d6f8b053c0a6ab4032cb3d66eb15d548b9f0deed9260a901",
        )

    def test_malformed_regions_are_rejected_before_mutation(self):
        data = bytearray(0x100)
        cases = (
            ((0, 0, 0, 0x7F), "align"),
            ((0, 0, 0x01, 0x80), "align"),
            ((0, 0, 0x80, 0x100), "extends beyond"),
            ((0, 0xF8, 0, 0x80), "extends beyond"),
            ((0, 0, 0, -0x80), "extends beyond"),
        )
        for region, message in cases:
            with self.subTest(region=region):
                with self.assertRaisesRegex(ValueError, message):
                    decode_region(data, *region)
                self.assertEqual(data, bytes(0x100))

    def test_rejects_wrong_size_and_model(self):
        with self.assertRaisesRegex(ValueError, "align"):
            decode(b"invalid")
        with self.assertRaisesRegex(ValueError, "expected 16,838,656"):
            decode(bytes(0x200))

        data = bytearray(FIRMWARE_SIZE)
        with self.assertRaisesRegex(ValueError, "branch marker"):
            decode(data)
        data[0x124:0x12D] = b"Copyright"
        with self.assertRaisesRegex(ValueError, "K-3 II model marker"):
            decode(data)
        data[0x14E:0x15C] = b"PENTAX K-3 II\0"
        with self.assertRaisesRegex(ValueError, "K-3MC model marker"):
            decode(data)

    def test_existing_output_directory_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "decoded"
            write_outputs(output, b"decoded", "{}\n")

            with self.assertRaises(FileExistsError):
                write_outputs(output, b"changed", '{"changed": true}\n')

            self.assertEqual((output / "decoded.bin").read_bytes(), b"decoded")
            self.assertEqual((output / "inventory.json").read_bytes(), b"{}\n")


if __name__ == "__main__":
    unittest.main()
