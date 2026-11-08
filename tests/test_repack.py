import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from inspect_firmware import FIRMWARE_SIZE
from repack_firmware import SECTIONS, repair_checksums, repack, write_outputs


class RepackTests(unittest.TestCase):
    def test_separate_little_and_big_endian_sums(self):
        data = bytearray(FIRMWARE_SIZE)
        data[0x200:0x204] = bytes.fromhex("12345678")
        data[0x1000080:0x1000084] = bytes.fromhex("12345678")
        result = repair_checksums(data)
        self.assertEqual(result[0x1F0:0x1F4], bytes.fromhex("eecba987"))
        self.assertEqual(result[0x100007C:0x1000080], bytes.fromhex("edcba988"))
        for a, z, fmt in ((0, 0x1000000, "<I"), (0x1000000, FIRMWARE_SIZE, ">I")):
            self.assertEqual(
                sum(x[0] for x in struct.iter_unpack(fmt, result[a:z])) & 0xFFFFFFFF, 0
            )
        self.assertEqual(data[0x1F0:0x1F4], bytes(4))
        self.assertEqual(result[0x200:0x204], data[0x200:0x204])

    def test_wrong_original_and_size_rejected(self):
        with self.assertRaises(ValueError):
            repack(b"wrong model", b"")
        with self.assertRaises(ValueError):
            repair_checksums(bytes(128))

    def test_computed_bypass_sentinel_is_rejected_in_both_byte_orders(self):
        for start, _, field, fmt in SECTIONS:
            with self.subTest(checksum_field=hex(field)):
                data = bytearray(FIRMWARE_SIZE)
                offset = start + (0x200 if start == 0 else 0x80)
                struct.pack_into(fmt, data, offset, 1)
                before = bytes(data)
                with self.assertRaisesRegex(ValueError, "bypass sentinel"):
                    repair_checksums(data)
                self.assertEqual(data, before)

    def test_existing_output_and_partial_write_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "candidate"
            write_outputs(target, b"package", {"status": "fixture"})
            with self.assertRaises(FileExistsError):
                write_outputs(target, b"replacement", {})
            self.assertEqual((target / "candidate.bin").read_bytes(), b"package")
            self.assertEqual(
                json.loads((target / "repack.json").read_text()), {"status": "fixture"}
            )
            original_open = Path.open

            def failing_open(path, *args, **kwargs):
                if path.name == "repack.json":
                    raise OSError("simulated full disk")
                return original_open(path, *args, **kwargs)

            failed = Path(directory) / "failed"
            with patch.object(Path, "open", failing_open), self.assertRaises(OSError):
                write_outputs(failed, b"package", {})
            self.assertFalse(failed.exists())


if __name__ == "__main__":
    unittest.main()
