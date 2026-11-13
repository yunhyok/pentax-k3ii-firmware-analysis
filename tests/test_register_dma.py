"""Firmware-independent guards for the PixelDetect register and DMA verifier.

SPDX-License-Identifier: GPL-2.0-only
"""
import errno
from hashlib import sha256
import importlib.util
import os
from pathlib import Path
import py_compile
import runpy
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest


TOOL = Path(__file__).resolve().parents[1] / "verify_register_dma.py"
VERIFIER = runpy.run_path(str(TOOL))
DEPENDENCY_NAMES = ("inspect_firmware.py", "verify_findings.py", "verify_tone_path.py")
DEPENDENCY_CHECK = textwrap.dedent("""
    import runpy
    import sys

    tool, mode, *names = sys.argv[1:]
    verifier = runpy.run_path(tool)
    def trace(frame, event, arg):
        if event == "call" and frame.f_code.co_name == "<module>":
            filename = frame.f_code.co_filename.replace(chr(92), "/").rsplit("/", 1)[-1]
            if filename in names:
                print(f"executed {filename}")
    if mode == "trace":
        sys.settrace(trace)
    tone = verifier["load_dependencies"]()
    assert tone.__name__ == "verify_tone_path"
    assert tone.FIRMWARE_SIZE == verifier["DECODED_SIZE"]
    print("loaded")
""")


class RegisterDmaGuards(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory(
            dir=os.environ.get("REGISTER_DMA_TEST_TMP"),
        )))
        self.source = self.directory / "decoded.bin"
        self.output = self.directory / "report.json"
        self.source.write_bytes(b"input sentinel")

    def cli(self, output=None, flags=()):
        return subprocess.run(
            [sys.executable, "-B", "-I", "-S", *flags, str(TOOL), str(self.source),
             "--output", str(output if output is not None else self.output)],
            capture_output=True, text=True, timeout=30,
        )

    def assert_rejected(self, result, message):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)
        self.assertNotIn("No module named 'unicorn'", result.stderr)

    def test_wrong_size_and_correct_size_wrong_hash(self):
        self.assert_rejected(self.cli(), "Original decoded carrier")
        self.assertFalse(os.path.lexists(self.output))
        with self.source.open("r+b") as stream:
            stream.truncate(VERIFIER["DECODED_SIZE"])
        self.assert_rejected(self.cli(), "Decoded input SHA-256")
        self.assertFalse(os.path.lexists(self.output))
        self.assertEqual(self.source.stat().st_size, VERIFIER["DECODED_SIZE"])
        with self.source.open("rb") as stream:
            self.assertEqual(stream.read(14), b"input sentinel")

    def test_existing_output_and_source_aliases_are_preserved(self):
        self.output.write_bytes(b"report sentinel")
        alias = self.directory / "alias.bin"
        os.link(self.source, alias)
        for path in (self.output, self.source, alias, self.directory):
            with self.subTest(output=path.name):
                self.assert_rejected(self.cli(path), "FileExistsError")
        self.assertEqual(self.output.read_bytes(), b"report sentinel")
        self.assertEqual(self.source.read_bytes(), b"input sentinel")
        self.assertEqual(alias.read_bytes(), b"input sentinel")
        self.assertTrue(self.directory.is_dir())

    def test_dangling_output_link_is_preserved(self):
        missing = self.directory / "missing.json"
        try:
            self.output.symlink_to(missing.name)
        except NotImplementedError as exc:
            self.skipTest(str(exc))
        except OSError as exc:
            unavailable = exc.errno in {errno.EPERM, errno.EACCES, errno.ENOSYS, errno.ENOTSUP}
            if not unavailable and getattr(exc, "winerror", None) != 1314:
                raise
            self.skipTest(f"File symlinks are unavailable: {exc}")
        self.assert_rejected(self.cli(), "FileExistsError")
        self.assertEqual(self.output.readlink(), Path(missing.name))
        self.assertFalse(missing.exists())

    def test_optimized_mode_is_rejected_before_imports(self):
        self.assert_rejected(self.cli(flags=("-O",)), "Assertions required")
        self.assertFalse(os.path.lexists(self.output))

    def fixture_dependencies(self):
        self.assertEqual(set(VERIFIER["DEPENDENCIES"]), set(DEPENDENCY_NAMES))
        shutil.copyfile(TOOL, self.directory / TOOL.name)
        sources = {}
        for name in DEPENDENCY_NAMES:
            sources[name] = (TOOL.parent / name).read_bytes().replace(b"\r\n", b"\n")
            (self.directory / name).write_bytes(sources[name])
        return sources

    def dependency_script(self, trace=False):
        mode = "trace" if trace else "plain"
        return subprocess.run(
            [sys.executable, "-B", "-I", "-S", "-c", DEPENDENCY_CHECK,
             str(self.directory / TOOL.name), mode, *DEPENDENCY_NAMES],
            capture_output=True, text=True, timeout=30,
        )

    def test_lf_and_crlf_pins(self):
        sources = self.fixture_dependencies()
        for ending in (b"\n", b"\r\n"):
            with self.subTest(ending=ending):
                for name, source in sources.items():
                    (self.directory / name).write_bytes(source.replace(b"\n", ending))
                result = self.dependency_script(trace=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertCountEqual(
                    result.stdout.splitlines(),
                    ["loaded", *(f"executed {name}" for name in DEPENDENCY_NAMES)],
                )

    def test_each_dependency_drift_rejected_before_any_source_executes(self):
        sources = self.fixture_dependencies()
        for name, source in sources.items():
            with self.subTest(dependency=name):
                path = self.directory / name
                path.write_bytes(b"raise RuntimeError('unverified source executed')\n" + source)
                try:
                    result = self.dependency_script(trace=True)
                    self.assert_rejected(result, f"Dependency SHA-256 mismatch: {name}")
                    self.assertEqual(result.stdout, "", result.stdout)
                    self.assertNotIn("unverified source executed", result.stderr)
                finally:
                    path.write_bytes(source)

    def test_unchecked_bytecode_is_ignored(self):
        sources = self.fixture_dependencies()
        for name, source in sources.items():
            path = self.directory / name
            path.write_bytes(b"raise RuntimeError('unchecked cache executed')\n")
            py_compile.compile(
                str(path), cfile=importlib.util.cache_from_source(str(path)), doraise=True,
                invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
            )
            path.write_bytes(source)
        result = self.dependency_script()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "loaded")

    def test_projection_digest_rejects_any_field_drift(self):
        payload = {"count": 1, "trace": "a"}
        expected = sha256(b'{"count":1,"trace":"a"}').hexdigest()
        self.assertEqual(VERIFIER["canonical_sha256"](payload), expected)
        check = VERIFIER["verify_projection"]
        check({"trace": "a", "count": 1}, expected, "projection")
        for change in ({"count": 2}, {"count": True}, {"trace": "b"}, {"extra": 0}):
            with self.subTest(change=change):
                with self.assertRaisesRegex(ValueError, "projection"):
                    check({**payload, **change}, expected, "projection")


if __name__ == "__main__":
    unittest.main()
