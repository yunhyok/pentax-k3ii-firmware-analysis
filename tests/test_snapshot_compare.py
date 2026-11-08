import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from verify_findings import require_snapshot
import verify_pixel_records as pixel_records


class SnapshotCompareTests(unittest.TestCase):
    def test_accepts_json_order_whitespace_and_exported_container_types(self):
        report = {"second": (True, 1, 1.0), "first": {2: False, "label": "yes"}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            path.write_text(
                '{\n "first": {"label": "yes", "2": false}, "second": [true, 1, 1.0]\n}',
                encoding="utf-8",
            )
            require_snapshot(report, path, "test report")

    def test_rejects_different_json_scalar_types(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "snapshot.json"
            for actual, changed in ((False, 0), (True, 1), (1, 1.0)):
                with self.subTest(actual=actual, changed=changed):
                    path.write_text(json.dumps({"nested": [changed]}), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "test report: snapshot differs"):
                        require_snapshot({"nested": [actual]}, path, "test report")

    def test_pixel_records_cli_rejects_replacing_false_with_zero(self):
        replay = {"save": {"sector_14_provider_overlay": False}}
        with (
            tempfile.TemporaryDirectory() as directory,
            patch.object(pixel_records, "load_image", return_value=b"synthetic input"),
            patch.object(pixel_records, "verify_static", return_value={"providers": []}),
            patch.object(pixel_records, "emulate", return_value=replay),
        ):
            output = io.StringIO()
            with (
                patch("sys.argv", ["verify_pixel_records.py", "unused"]),
                contextlib.redirect_stdout(output),
            ):
                pixel_records.main()

            snapshot = json.loads(output.getvalue())
            path = Path(directory) / "snapshot.json"
            path.write_text(json.dumps(snapshot), encoding="utf-8")
            args = ["verify_pixel_records.py", "unused", "--compare", str(path)]
            with patch("sys.argv", args), contextlib.redirect_stdout(io.StringIO()):
                pixel_records.main()
                snapshot["replay"]["save"]["sector_14_provider_overlay"] = 0
                path.write_text(json.dumps(snapshot), encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "snapshot replay"):
                    pixel_records.main()


if __name__ == "__main__":
    unittest.main()
