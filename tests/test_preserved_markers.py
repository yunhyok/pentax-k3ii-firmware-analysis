"""CLI and file safety checks using synthetic input, without firmware emulation."""

from contextlib import contextmanager, redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import verify_preserved_markers as markers
from inspect_firmware import FIRMWARE_SIZE


class PreservedMarkersTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        self.input = self.directory / "decoded.bin"
        self.output = self.directory / "evidence.json"

    def assert_cli_error(self, arguments, message):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as error:
                markers.main([str(self.input), *arguments])
        self.assertEqual(error.exception.code, 2)
        self.assertIn(message, stderr.getvalue())
        self.assertEqual(stdout.getvalue(), "")

    def test_invalid_length_and_full_size_wrong_digest_stop_before_replay(self):
        for data, message in (
            (b"short", "decoded length"),
            (bytes(FIRMWARE_SIZE), "decoded identity"),
        ):
            with self.subTest(message=message):
                self.input.write_bytes(data)
                with patch.dict("sys.modules", {"unicorn": None}):
                    with self.assertRaisesRegex(ValueError, message):
                        markers.probe(data)
                with patch.object(markers, "probe") as probe:
                    self.assert_cli_error(["--output", str(self.output)], message)
                    probe.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_preflight_rejects_input_and_hardlink_output_aliases(self):
        original = b"must remain intact"
        self.input.write_bytes(original)
        alias = self.directory / "hardlink.bin"
        alias.hardlink_to(self.input)
        with patch.object(markers, "load_image") as load_image:
            for output in (self.input, alias):
                with self.subTest(output=output.name):
                    self.assert_cli_error(
                        ["--output", str(output)], "refusing to replace existing output"
                    )
            load_image.assert_not_called()
        self.assertEqual(self.input.read_bytes(), original)
        self.assertEqual(alias.read_bytes(), original)

    def test_exclusive_output_preserves_file_created_at_publication(self):
        real_link = os.link

        def publish(staged, output):
            self.assertEqual(output, self.output)
            self.assertEqual(json.loads(staged.read_bytes()), {"input_file_rechecked": True})
            output.write_bytes(b"created by another writer")
            real_link(staged, output)

        with (
            patch.object(markers, "load_image", return_value=b"synthetic"),
            patch.object(markers, "probe", return_value={}),
            patch.object(os, "link", side_effect=publish),
        ):
            self.assert_cli_error(["--output", str(self.output)], self.output.name)
        self.assertEqual(self.output.read_bytes(), b"created by another writer")
        self.assertEqual(list(self.directory.iterdir()), [self.output])

    def test_output_write_failure_removes_partial_file(self):
        real_open = Path.open

        @contextmanager
        def failing_open(path, *args, **kwargs):
            with real_open(path, *args, **kwargs) as stream:
                write = stream.write

                def partial_write(payload):
                    write(payload[:2])
                    raise OSError("simulated partial write")

                with patch.object(stream, "write", side_effect=partial_write):
                    yield stream

        with patch.object(Path, "open", failing_open):
            with self.assertRaisesRegex(OSError, "simulated partial write"):
                markers.write_output(self.output, "payload")
        self.assertEqual(list(self.directory.iterdir()), [])

    def test_compare_rejects_int_in_place_of_bool_before_writing(self):
        snapshot = self.directory / "snapshot.json"
        snapshot.write_text('{"input_file_rechecked":true,"flag":1}', encoding="utf-8")
        args = ["--compare", str(snapshot), "--output", str(self.output)]
        with (
            patch.object(markers, "load_image", return_value=b"synthetic"),
            patch.object(markers, "probe", side_effect=lambda _data: {"flag": True}),
        ):
            self.assert_cli_error(args, "snapshot differs")
            self.assertFalse(self.output.exists())

            snapshot.write_text(
                '{"input_file_rechecked":true,"flag":true}', encoding="utf-8"
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                markers.main([str(self.input), *args])
        self.assertEqual(self.output.read_bytes(), stdout.getvalue().encode("utf-8"))
        self.assertEqual(
            json.loads(stdout.getvalue()), {"flag": True, "input_file_rechecked": True}
        )

    def test_changed_input_after_replay_prevents_output(self):
        with (
            patch.object(markers, "load_image", side_effect=[b"before", b"after"]),
            patch.object(markers, "probe", return_value={}),
        ):
            self.assert_cli_error(["--output", str(self.output)], "input bytes unchanged")
        self.assertFalse(self.output.exists())

