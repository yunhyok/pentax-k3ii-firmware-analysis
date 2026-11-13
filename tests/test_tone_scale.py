"""Integration guards for the tone-scale CLI. No firmware or Unicorn needed."""

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
CLI_ROOT = Path(os.environ.get("TONE_SCALE_CANDIDATE", ROOT))
REPOSITORY = Path(os.environ.get("TONE_REPOSITORY", ROOT))
CLI = CLI_ROOT / "verify_tone_scale.py"
API = runpy.run_path(str(CLI))


class ToneScaleBoundaries(unittest.TestCase):
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
        paths = ("scale-sources.json", "scale-ranges.json", "scale.py", "ownership.py")
        for name in paths:
            shutil.copyfile(CLI_ROOT / "tools/tone_provenance" / name, target / name)
        manifest = json.loads((target / "scale-sources.json").read_bytes())
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
            ("tools/tone_provenance/scale-sources.json", "source manifest"),
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

    def test_full_typed_gates_cover_scale_and_ownership(self):
        shared, _ = API["load_captured"](API["capture_sources"](REPOSITORY, CLI_ROOT))
        canonical = shared["canonical"]
        cases = [
            [{"name": "scale", "word": 1, "trace": [15]}],
            [{"case": "owner", "word": 1, "trace": [15]}],
        ]
        names = ("SCALE_CASES_SHA256", "OWNERSHIP_CASES_SHA256")
        pins = {
            name: API["sha256"](canonical(record)).hexdigest()
            for name, record in zip(names, cases)
        }
        with patch.dict(API["project_checked"].__globals__, pins):
            API["project_checked"](*cases, canonical)
            for index, name in enumerate(names):
                for mutation in ({"word": True}, {"trace": [16]}, {"extra": 0}):
                    with self.subTest(gate=name, mutation=mutation):
                        changed = cases.copy()
                        changed[index] = [{**cases[index][0], **mutation}]
                        with self.assertRaises(ValueError):
                            API["project_checked"](*changed, canonical)

    def test_compare_typed_drift_refuses_publication(self):
        captured = API["capture_sources"](REPOSITORY, CLI_ROOT)
        shared, _ = API["load_captured"](captured)
        output = self.work / "new.json"
        baseline = self.work / "baseline.json"
        fixture = {
            "scale_cases": [{"completed": True, "word": 1}],
            "ownership_cases": [{"word": 1}],
        }

        class FixtureImageLoader:
            def load_image(self, _):
                return b""

        args = ["unused.bin", "--compare", str(baseline), "--output", str(output)]
        with patch.dict(API["main"].__globals__, {
            "capture_sources": lambda _: captured,
            "load_captured": lambda _: (shared, lambda _: FixtureImageLoader()),
            "run": lambda *_: fixture,
        }):
            for key, mutation in (
                ("scale_cases", {"completed": 1}),
                ("ownership_cases", {"word": True}),
            ):
                with self.subTest(key=key, mutation=mutation):
                    changed = {**fixture, key: [{**fixture[key][0], **mutation}]}
                    baseline.write_text(json.dumps(changed), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "typed"):
                        API["main"](args)
                    self.assertFalse(output.exists())



if __name__ == "__main__":
    unittest.main(verbosity=2)
