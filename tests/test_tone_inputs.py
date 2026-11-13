"""Integration guards for the tone-input CLI. No firmware or Unicorn needed."""

import json
import os
from pathlib import Path
import py_compile
import runpy
import shutil
import subprocess
import sys
import tempfile
from types import ModuleType
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
CLI_ROOT = Path(os.environ.get("TONE_INPUT_CANDIDATE", ROOT))
REPOSITORY = Path(os.environ.get("TONE_REPOSITORY", ROOT))
CLI = CLI_ROOT / "verify_tone_inputs.py"
API = runpy.run_path(str(CLI))


class ToneInputBoundaries(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(dir=os.environ.get("TONE_TEST_TMP"))
        self.addCleanup(tmp.cleanup)
        self.work = Path(tmp.name)

    def invoke(self, image, output):
        return subprocess.run(
            [sys.executable, "-B", "-I", "-S", str(CLI), str(image),
             "--repository", str(REPOSITORY), "--output", str(output)],
            capture_output=True,
            text=True,
            timeout=30,
        )

    def stage_sources(self):
        stage = self.work / "checkout"
        target = stage / "tools/tone_provenance"
        target.mkdir(parents=True)
        paths = ("inputs-sources.json", "input-ranges.json", "inputs.py")
        for name in paths:
            shutil.copyfile(CLI_ROOT / "tools/tone_provenance" / name, target / name)
        manifest = json.loads((target / "inputs-sources.json").read_bytes())
        for e in [manifest["loader"], *manifest["modules"].values()]:
            if e.get("location") != "candidate":
                shutil.copyfile(REPOSITORY / e["path"], stage / e["path"])
        return stage, manifest

    def test_wrong_size_and_full_size_wrong_identity(self):
        image = self.work / "bad.bin"
        output = self.work / "new.json"
        for size, expected in ((3, "decoded length"), (API["IMAGE_SIZE"], "decoded identity")):
            with self.subTest(size=size):
                content = bytes(size)
                image.write_bytes(content)
                proc = self.invoke(image, output)
                self.assertEqual(proc.returncode, 1)
                self.assertIn(expected, proc.stderr)
                self.assertNotIn("unicorn", proc.stderr.lower())
                self.assertEqual(image.read_bytes(), content)
                self.assertFalse(output.exists())

    def test_existing_output_aliases(self):
        image = self.work / "input.bin"
        image.write_bytes(b"original input")
        source = self.work / "helper.py"
        source.write_bytes(b"original helper")
        alias = self.work / "alias.json"
        alias.hardlink_to(image)
        for target in (image, source, alias, self.work):
            with self.subTest(target=target.name):
                proc = self.invoke(image, target)
                self.assertEqual(proc.returncode, 1)
                self.assertIn("output already exists", proc.stderr)
        self.assertEqual(image.read_bytes(), b"original input")
        self.assertEqual(source.read_bytes(), b"original helper")
        self.assertEqual(alias.read_bytes(), b"original input")

    def test_dangling_output_symlink(self):
        image = self.work / "input.bin"
        image.write_bytes(b"original input")
        target = self.work / "dangling.json"
        referent = self.work / "referent.json"
        try:
            target.symlink_to(referent)
        except OSError as error:
            self.skipTest(str(error))
        proc = self.invoke(image, target)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("output already exists", proc.stderr)
        self.assertTrue(target.is_symlink())
        self.assertFalse(referent.exists())

    def test_each_source_or_manifest_drift_precedes_execution(self):
        stage, manifest = self.stage_sources()
        paths = [
            ("tools/tone_provenance/inputs-sources.json", "input source manifest"),
            (manifest["ranges"]["path"], "range manifest"),
            (manifest["loader"]["path"], "shared loader identity"),
            *((e["path"], f"captured source {name}") for name, e in manifest["modules"].items()),
        ]
        staged_cli = stage / CLI.name
        shutil.copyfile(CLI, staged_cli)
        main = runpy.run_path(str(staged_cli))["main"]
        target = self.work / "untouched.json"
        args = ["unused.bin", "--repository", str(stage), "--output", str(target)]

        def unexpected_load(_):
            self.fail("CLI attempted project code execution before checking all source pins")

        with patch.dict(main.__globals__, {"load_captured": unexpected_load}):
            for relative, expected in paths:
                path = stage / relative
                before = path.read_bytes()
                with self.subTest(source=relative):
                    path.write_bytes(before + b"\n# drift")
                    try:
                        with self.assertRaisesRegex(ValueError, expected):
                            main(args)
                        self.assertFalse(target.exists())
                    finally:
                        path.write_bytes(before)

    def test_captured_loader_and_module_ignore_postcapture_disk_and_cache(self):
        stage, _ = self.stage_sources()
        local_helper = stage / "verify_findings.py"
        original = local_helper.read_bytes().replace(b"\r\n", b"\n")
        local_helper.write_bytes(b"raise RuntimeError('unchecked pyc executed')\n")
        py_compile.compile(
            str(local_helper),
            doraise=True,
            invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
        )
        local_helper.write_bytes(original.replace(b"\n", b"\r\n"))
        captured = API["capture_sources"](stage, stage)
        local_helper.write_bytes(b"raise RuntimeError('source reopened')\n")
        (stage / "verify_tone_provenance.py").write_bytes(b"raise RuntimeError('loader reopened')\n")
        poison = ModuleType("verify_findings")
        paths = [str(stage), *sys.path]
        with patch.dict(sys.modules, {"verify_findings": poison}), patch.object(sys, "path", paths):
            _, load = API["load_captured"](captured)
            tone = load("verify_tone_path")
            self.assertIs(tone.require, load("verify_findings").require)
            self.assertIs(sys.modules["verify_findings"], poison)

    def test_full_case_gate_runs_before_projection(self):
        shared, _ = API["load_captured"](API["capture_sources"](REPOSITORY, CLI_ROOT))
        original = [{"invalid": [], "word": 1, "unprojected": [15]}]
        valid_pin = API["sha256"](shared["canonical"](original)).hexdigest()
        with patch.dict(API["project_checked"].__globals__, {"CASES_SHA256": valid_pin}):
            for mutation in (
                {"invalid": [], "word": True, "unprojected": [15]},
                {"invalid": [], "word": 1, "unprojected": [16]},
                {"invalid": [], "word": 1, "unprojected": [15], "extra": 0},
            ):
                with self.subTest(mutation=mutation):
                    with self.assertRaisesRegex(ValueError, "identity before projection"):
                        API["project_checked"]([mutation], shared["canonical"])

    def test_compare_typed_drift_refuses_publication(self):
        captured = API["capture_sources"](REPOSITORY, CLI_ROOT)
        shared, _ = API["load_captured"](captured)
        output = self.work / "new.json"
        baseline = self.work / "baseline.json"
        fixture = {"cases": [{"enabled": 1}]}

        class FixtureImageLoader:
            def load_image(self, _):
                return b""

        with patch.dict(API["main"].__globals__, {
            "capture_sources": lambda _: captured,
            "load_captured": lambda _: (shared, lambda _: FixtureImageLoader()),
            "run": lambda *_: fixture,
        }):
            baseline.write_text('{"cases":[{"enabled":true}]}', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "complete typed public JSON"):
                API["main"](["unused.bin", "--compare", str(baseline), "--output", str(output)])
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
