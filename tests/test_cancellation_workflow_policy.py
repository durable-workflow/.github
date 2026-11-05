import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

import yaml


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/cancellation-competitors.yml"


class CancellationWorkflowPolicyTest(unittest.TestCase):
    def test_fixture_execution_requires_explicit_manual_selection(self):
        workflow = yaml.safe_load(WORKFLOW.read_text())
        expected = "github.event_name == 'workflow_dispatch' && inputs.run_fixtures == true"
        self.assertEqual({"restate", "temporal", "dbos"}, set(workflow["jobs"]))
        for name, job in workflow["jobs"].items():
            with self.subTest(job=name):
                self.assertEqual(expected, job.get("if"))

    def test_manual_fixture_selection_defaults_to_refusal(self):
        workflow = yaml.safe_load(WORKFLOW.read_text())
        # PyYAML's YAML 1.1 loader treats the Actions key `on` as True.
        events = workflow.get("on", workflow.get(True))
        selection = events["workflow_dispatch"]["inputs"]["run_fixtures"]
        self.assertEqual("boolean", selection["type"])
        self.assertIs(True, selection["required"])
        self.assertIs(False, selection["default"])

    def test_evidence_preparation_is_private_and_refuses_existing_paths(self):
        workflow = yaml.safe_load(WORKFLOW.read_text())
        for name, job in workflow["jobs"].items():
            step = next(s for s in job["steps"] if s.get("id") == "evidence")
            for kind in ("absent", "directory", "file", "symlink", "dangling"):
                with self.subTest(job=name, kind=kind), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    working = root / "conformance" / "cancellation" / name
                    working.mkdir(parents=True)
                    outside = root / "outside"
                    outside.mkdir(mode=0o700)
                    evidence = working / "evidence"
                    self.place_candidate_path(evidence, kind, outside)
                    result = subprocess.run(["bash", "-c", step["run"]], cwd=working,
                                            env={"PATH": os.defpath, "GITHUB_WORKSPACE": str(root)},
                                            capture_output=True, text=True)
                    if kind == "absent":
                        self.assertEqual(0, result.returncode, result.stderr)
                        self.assertEqual(0o700, stat.S_IMODE(evidence.stat().st_mode))
                        self.assertEqual(os.getuid(), evidence.stat().st_uid)
                    else:
                        self.assertNotEqual(0, result.returncode)
                    self.assertEqual(0o700, stat.S_IMODE(outside.stat().st_mode))
                    self.assertEqual([], list(outside.iterdir()))

    def place_candidate_path(self, evidence, kind, outside):
        if kind == "directory":
            evidence.mkdir()
        elif kind == "file":
            evidence.write_text("candidate data")
        elif kind == "symlink":
            evidence.symlink_to(outside)
        elif kind == "dangling":
            evidence.symlink_to(outside.parent / "missing")

    def test_evidence_preparation_refuses_a_symlinked_fixture_parent(self):
        workflow = yaml.safe_load(WORKFLOW.read_text())
        for name, job in workflow["jobs"].items():
            step = next(s for s in job["steps"] if s.get("id") == "evidence")
            with self.subTest(job=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                parent = root / "conformance" / "cancellation"
                parent.mkdir(parents=True)
                outside = root / "outside"
                outside.mkdir()
                (parent / name).symlink_to(outside, target_is_directory=True)
                result = subprocess.run(["bash", "-c", step["run"]], cwd=parent / name,
                                        env={"PATH": os.defpath, "GITHUB_WORKSPACE": str(root)},
                                        capture_output=True, text=True)
                self.assertNotEqual(0, result.returncode)
                self.assertEqual([], list(outside.iterdir()))

    def test_fixture_writes_use_the_host_identity_and_skip_unprepared_artifacts(self):
        workflow = yaml.safe_load(WORKFLOW.read_text())
        for name, job in workflow["jobs"].items():
            run = next(s["run"] for s in job["steps"] if s.get("name", "").startswith("Run "))
            with self.subTest(job=name):
                self.assertIn('exec --user "$(id -u):$(id -g)" -T sdk', run)
                self.assertNotIn("chmod", run)
                for line in run.splitlines():
                    if "sha256sum" in line:
                        self.assertIn("sha256sum -- ", line)
                for step in job["steps"]:
                    if step.get("if", "").startswith("always()"):
                        self.assertEqual("always() && steps.evidence.outcome == 'success'", step["if"])
