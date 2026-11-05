import json
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


class NativePolicyWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.safe_load((ROOT / ".github/workflows/native-policy.yml").read_text())
        self.rule = json.loads((ROOT / "qualification/native-policy-pilot.json").read_text())

    def test_required_workflow_has_both_events_and_no_path_filters(self):
        events = self.workflow.get("on", self.workflow.get(True))
        self.assertEqual({"pull_request": None, "merge_group": None}, events)
        self.assertEqual("${{ always() }}", self.workflow["jobs"]["policy"]["if"])

    def test_only_central_pinned_code_is_checked_out_without_persisted_credentials(self):
        steps = self.workflow["jobs"]["policy"]["steps"]
        checkouts = [step for step in steps if step.get("uses", "").startswith("actions/checkout@")]
        self.assertEqual(1, len(checkouts))
        settings = checkouts[0]["with"]
        self.assertEqual("durable-workflow/.github", settings["repository"])
        self.assertRegex(settings["ref"], r"^[0-9a-f]{40}$")
        self.assertIs(False, settings["persist-credentials"])
        self.assertEqual(".native-policy-control", settings["path"])

    def test_no_issuer_key_or_write_permission_is_introduced(self):
        self.assertEqual({"contents": "read", "pull-requests": "read"}, self.workflow["permissions"])
        raw = (ROOT / ".github/workflows/native-policy.yml").read_text()
        for prohibited in ("secrets.", "create-github-app-token", "checks: write", "POLICY_GATE_APP"):
            self.assertNotIn(prohibited, raw)

    def test_disabled_rule_binds_one_repository_and_exact_central_workflow(self):
        self.assertEqual("disabled", self.rule["enforcement"])
        self.assertEqual([], self.rule["bypass_actors"])
        self.assertEqual({"repository_ids": [575230056]}, self.rule["conditions"]["repository_id"])
        self.assertEqual({"include": ["~DEFAULT_BRANCH"], "exclude": []}, self.rule["conditions"]["ref_name"])
        self.assertEqual([{"type": "workflows", "parameters": {
            "do_not_enforce_on_create": True, "workflows": [{"repository_id": 575230056,
            "path": ".github/workflows/native-policy.yml", "ref": "refs/heads/main"}]}}], self.rule["rules"])

    def test_verified_bootstrap_precedes_hash_locked_dependency_install(self):
        steps = self.workflow["jobs"]["policy"]["steps"]
        bootstrap = next(i for i, step in enumerate(steps) if "bootstrap-patched-pip@" in step.get("uses", ""))
        install = next(i for i, step in enumerate(steps) if "pip --isolated install" in step.get("run", ""))
        self.assertLess(bootstrap, install)
        for flag in ("--require-hashes", "--only-binary=:all:", "--no-deps"):
            self.assertIn(flag, steps[install]["run"])


if __name__ == "__main__":
    unittest.main()
