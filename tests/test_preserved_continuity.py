"""Identity and non-clobber guards without firmware or Unicorn.

SPDX-License-Identifier: GPL-2.0-only
"""
import errno
import importlib.util
import os
from pathlib import Path
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest


TOOL = Path(__file__).resolve().parents[1] / "verify_preserved_continuity.py"
SPEC = importlib.util.spec_from_file_location("continuity", TOOL)
continuity = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(continuity)


class PreservedContinuityGuards(unittest.TestCase):
    def setUp(self):
        self.directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
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

    def test_wrong_size_and_correct_size_wrong_hash(self):
        self.assert_rejected(self.cli(), "Original decoded carrier")
        with self.source.open("r+b") as stream:
            stream.truncate(continuity.DECODED_SIZE)
        self.assert_rejected(self.cli(), "Decoded input SHA-256")
        self.assertFalse(os.path.lexists(self.output))
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

    def dependency_script(self, source):
        tool = self.directory / TOOL.name
        shutil.copyfile(TOOL, tool)
        code = ("import runpy, sys; sys.path.insert(0, sys.argv[1]); "
                "m=runpy.run_path(sys.argv[2]); m['load_dependencies'](); print('loaded')")
        return subprocess.run(
            [sys.executable, "-B", "-I", "-S", "-c", code, str(source), str(tool)],
            capture_output=True, text=True, timeout=30,
        )

    def fixture_dependencies(self):
        (self.directory / "analysis").mkdir()
        for name in continuity.DEPENDENCIES:
            text = (TOOL.parent / name).read_bytes().replace(b"\r\n", b"\n")
            (self.directory / name).write_bytes(text.replace(b"\n", b"\r\n"))
        stub = self.directory / "unicorn"
        stub.mkdir()
        (stub / "__init__.py").write_text("arm_const = None\n", encoding="utf-8")
        return self.directory

    def test_lf_crlf_pins_and_transitive_drift_before_execution(self):
        fixture = self.fixture_dependencies()
        result = self.dependency_script(fixture)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "loaded")
        for name in ("verify_findings.py", "analysis/preserved-config.json"):
            with self.subTest(dependency=name):
                path = fixture / name
                original = path.read_bytes()
                path.write_bytes(b"raise RuntimeError('unverified dependency executed')\r\n" + original)
                result = self.dependency_script(fixture)
                self.assert_rejected(result, f"Dependency SHA-256 mismatch: {name}")
                self.assertNotIn("unverified dependency executed", result.stderr)
                path.write_bytes(original)

    def test_unchecked_bytecode_is_ignored(self):
        fixture = self.fixture_dependencies()
        source = fixture / "verify_tone_path.py"
        original = source.read_bytes()
        source.write_bytes(b"raise RuntimeError('unverified cache')\n")
        py_compile.compile(str(source), cfile=importlib.util.cache_from_source(str(source)),
                           invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
        source.write_bytes(original)
        result = self.dependency_script(fixture)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "loaded")


if __name__ == "__main__":
    unittest.main()
