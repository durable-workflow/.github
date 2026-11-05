from pathlib import Path
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
