import json
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

    def cleanup_case(self, name, mode):
        workflow = yaml.safe_load(WORKFLOW.read_text())
        step = next(s for s in workflow['jobs'][name]['steps'] if s.get('name') in
                    ('Collect observations and remove the fixture', 'Remove the fixture'))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'evidence').mkdir()
            outside = root / 'outside.log'
            outside.write_text('unchanged')
            if mode == 'symlink':
                (root / 'evidence/runtime.log').symlink_to(outside)
            executable = root / 'docker'
            executable.write_text('''#!/usr/bin/python3
import json, os, sys
args = sys.argv[1:]
with open(os.environ['CALLS'], 'a') as output:
    output.write(json.dumps(args) + '\\n')
mode = os.environ['CASE']
if 'logs' in args and mode == 'log-failure':
    sys.exit(23)
if 'down' in args and mode == 'down-failure':
    sys.exit(37)
if args[:2] == ['ps', '-aq'] and mode == 'survivor':
    print('remaining-container')
if args[:2] == ['network', 'ls'] and mode == 'unavailable':
    sys.exit(19)
''')
            executable.chmod(0o700)
            calls = root / 'calls.jsonl'
            result = subprocess.run(['bash', '-e', '-c', step['run']], cwd=root,
                                    env={'PATH': str(root) + os.pathsep + os.defpath,
                                         'CALLS': str(calls), 'CASE': mode},
                                    capture_output=True, text=True)
            observed = [json.loads(line) for line in calls.read_text().splitlines()]
            self.assertEqual('unchanged', outside.read_text())
            self.assertIn(['compose', '-p', 'cancellation-' + name, 'down', '-v', '--remove-orphans'], observed)
            return result, observed

    def test_log_failure_still_tears_down_and_preserves_the_failed_status(self):
        for name in ('restate', 'temporal'):
            with self.subTest(job=name):
                result, _ = self.cleanup_case(name, 'log-failure')
                self.assertNotEqual(0, result.returncode)
                self.assertIn('log_status=23 down_status=0 absence_status=0', result.stdout)

    def test_log_symlink_is_not_followed_and_does_not_skip_teardown(self):
        for name in ('restate', 'temporal'):
            with self.subTest(job=name):
                result, _ = self.cleanup_case(name, 'symlink')
                self.assertNotEqual(0, result.returncode)

    def test_success_requires_available_empty_container_network_and_volume_queries(self):
        for name in ('restate', 'temporal', 'dbos'):
            for mode in ('success', 'survivor', 'unavailable', 'down-failure'):
                with self.subTest(job=name, mode=mode):
                    result, calls = self.cleanup_case(name, mode)
                    self.assertEqual(mode == 'success', result.returncode == 0)
                    for query in (['ps', '-aq'], ['network', 'ls'], ['volume', 'ls']):
                        self.assertTrue(any(row[:2] == query for row in calls))
