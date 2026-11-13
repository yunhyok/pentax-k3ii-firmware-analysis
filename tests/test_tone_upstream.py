"""Integration guards for the tone-upstream CLI. No firmware or Unicorn needed."""

import json
import os
from pathlib import Path
import py_compile
import runpy
import shutil
import subprocess
import sys
import tempfile
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
CLI_ROOT = Path(os.environ.get("TONE_UPSTREAM_CANDIDATE", ROOT))
REPOSITORY = Path(os.environ.get("TONE_REPOSITORY", ROOT))
CLI = CLI_ROOT / "verify_tone_upstream.py"
API = runpy.run_path(str(CLI))


class ToneUpstreamBoundaries(unittest.TestCase):
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

    def test_compare_file_is_regular_and_bounded(self):
        target = self.work / "compare.json"
        target.write_bytes(b'{"value": 1}')
        self.assertEqual(API["capture_compare"](target, 12), {"value": 1})
        target.write_bytes(b'{"value": 1}' + b' ' * 32)
        with self.assertRaisesRegex(ValueError, "compare exceeds"):
            API["capture_compare"](target, 12)
        inputs = [self.work]
        if hasattr(os, "mkfifo"):
            fifo = self.work / "compare.fifo"
            os.mkfifo(fifo)
            inputs.append(fifo)
        for path in inputs:
            with self.assertRaisesRegex(ValueError, "compare regular file"):
                API["capture_compare"](path, 12)

    def stage_sources(self):
        stage = self.work / "checkout"
        target = stage / "tools/tone_provenance"
        target.mkdir(parents=True)
        paths = ("upstream-sources.json", "upstream-ranges.json", "upstream.py")
        for name in paths:
            shutil.copyfile(CLI_ROOT / "tools/tone_provenance" / name, target / name)
        manifest = json.loads((target / "upstream-sources.json").read_bytes())
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

    def test_nonregular_input_precedes_emulator_import(self):
        output = self.work / "new.json"
        inputs = [self.work]
        if hasattr(os, "mkfifo"):
            fifo = self.work / "input.fifo"
            os.mkfifo(fifo)
            inputs.append(fifo)
        for image in inputs:
            with self.subTest(image=image.name):
                proc = self.invoke(image, output)
                self.assertEqual(proc.returncode, 1)
                self.assertIn("decoded regular file", proc.stderr)
                self.assertNotIn("unicorn", proc.stderr.lower())
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
            ("tools/tone_provenance/upstream-sources.json", "source manifest"),
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

    def test_complete_typed_gate_covers_research_metadata_and_cases(self):
        shared, _ = API["load_captured"](API["capture_sources"](REPOSITORY, CLI_ROOT))
        canonical = shared["canonical"]
        # Small synthetic observation exercises the gate without firmware or
        # claiming that replay values were reproduced by the unit test.
        snapshot = {
            "schema": "II-TONE-UPSTREAM-31-native-v1",
            "input_sha256": API["IMAGE_SHA256"],
            "probe_sha256": "a" * 64,
            "engine": "2.1.4",
            "allowed_ranges": [{"start": 1, "end_exclusive": 2, "sha256": "b" * 64}],
            "upstream": [{"index": 1, "reads": [{"address": 1}]}],
            "zero_consumers": [{"supplied_r5": 0, "observed_result": None}],
            "limits": ["fixture"],
        }
        pins = {
            "RESEARCH_CANONICAL_SHA256": API["sha256"](canonical(snapshot)).hexdigest(),
            "RESEARCH_SNAPSHOT_SHA256": API["sha256"](
                (json.dumps(snapshot, indent=2) + "\n").encode("utf-8")
            ).hexdigest(),
        }
        with patch.dict(API["project_checked"].__globals__, pins):
            API["project_checked"](snapshot, canonical)
            for name in snapshot:
                with self.subTest(missing=name):
                    changed = {key: value for key, value in snapshot.items() if key != name}
                    with self.assertRaises(ValueError):
                        API["project_checked"](changed, canonical)
            for mutation in (
                {"probe_sha256": "c" * 64},
                {"engine": "unknown"},
                {"allowed_ranges": [{**snapshot["allowed_ranges"][0], "start": True}]},
                {"upstream": [{"index": 1, "reads": [{"address": 2}]}]},
                {"upstream": [{"index": 1}]},
                {"zero_consumers": [{"supplied_r5": False, "observed_result": None}]},
                {"zero_consumers": [{"supplied_r5": 0, "observed_result": 0}]},
                {"limits": ["changed fixture"]},
                {"extra": 0},
            ):
                with self.subTest(mutation=mutation):
                    with self.assertRaises(ValueError):
                        API["project_checked"]({**snapshot, **mutation}, canonical)

            reordered = dict(reversed(tuple(snapshot.items())))
            self.assertEqual(canonical(reordered), canonical(snapshot))
            with self.assertRaisesRegex(ValueError, "serialized snapshot"):
                API["project_checked"](reordered, canonical)

    def test_run_requires_accepted_snapshot_before_adding_public_metadata(self):
        shared, _ = API["load_captured"](API["capture_sources"](REPOSITORY, CLI_ROOT))
        data = b"fixture"
        ranges = {"allowed": [], "static": [], "config_static": []}
        upstream = SimpleNamespace(
            uc=SimpleNamespace(__version__="2.1.4"),
            run_snapshot=lambda *_: {"probe_sha256": "unaccepted"},
        )
        with patch.dict(API["run"].__globals__, {
            "IMAGE_SIZE": len(data),
            "IMAGE_SHA256": API["sha256"](data).hexdigest(),
            "RANGES_SHA256": API["sha256"](shared["canonical"](ranges)).hexdigest(),
        }):
            # Source metadata is deliberately unavailable. A replay gate
            # reached first raises the precise error before reading it.
            with self.assertRaisesRegex(ValueError, "complete II31 typed observation"):
                API["run"](data, {"ranges": ranges}, shared, lambda _: upstream)

    def test_compare_typed_drift_refuses_publication(self):
        captured = API["capture_sources"](REPOSITORY, CLI_ROOT)
        shared, _ = API["load_captured"](captured)
        output = self.work / "new.json"
        baseline = self.work / "baseline.json"
        fixture = {
            "observations": {
                "upstream": [{"index": 1}],
                "zero_consumers": [{"actual_capture_proven": False}],
            },
        }

        args = ["unused.bin", "--compare", str(baseline), "--output", str(output)]
        with patch.dict(API["main"].__globals__, {
            "capture_sources": lambda _: captured,
            "load_captured": lambda _: (shared, None),
            "capture_image": lambda _: b"",
            "run": lambda *_: fixture,
        }):
            for key, mutation in (
                ("upstream", {"index": True}),
                ("zero_consumers", {"actual_capture_proven": 0}),
            ):
                with self.subTest(key=key, mutation=mutation):
                    observations = fixture["observations"]
                    changed = {
                        "observations": {
                            **observations,
                            key: [{**observations[key][0], **mutation}],
                        },
                    }
                    baseline.write_text(json.dumps(changed), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "typed"):
                        API["main"](args)
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
