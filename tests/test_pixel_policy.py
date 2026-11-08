import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_pixel_policy as policy


class PixelPolicySnapshotTests(unittest.TestCase):
    def test_cli_rejects_boolean_replaced_by_equal_integer(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(
            policy, "load_image", return_value=b"synthetic comparator input"
        ), patch.object(policy, "verify_static", return_value={}), patch.object(
            policy, "emulate", return_value={"policy_block_skipped": False}
        ):
            output = io.StringIO()
            with patch(
                "sys.argv", ["verify_pixel_policy.py", "unused"]
            ), contextlib.redirect_stdout(output):
                policy.main()
            snapshot = json.loads(output.getvalue())
            path = Path(tmp) / "snapshot.json"
            path.write_text(json.dumps(snapshot), encoding="utf-8")
            with patch(
                "sys.argv", ["verify_pixel_policy.py", "unused", "--compare", str(path)]
            ), contextlib.redirect_stdout(io.StringIO()):
                policy.main()
                snapshot["replay"]["policy_block_skipped"] = 0
                path.write_text(json.dumps(snapshot), encoding="utf-8")
                with self.assertRaises(ValueError):
                    policy.main()


if __name__ == "__main__":
    unittest.main()
