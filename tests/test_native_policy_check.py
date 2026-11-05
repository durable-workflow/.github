from copy import deepcopy
from unittest import TestCase
from unittest.mock import patch

from scripts import native_policy_check as native
from scripts.protected_policy_inputs import InputRefused
from tests import test_protected_policy_inputs as inputs
from tests.test_protected_policy_check import SAFE_WORKFLOW


class NativePolicyCheckTest(TestCase):
    def setUp(self):
        self.fixture = inputs.ProtectedPolicyInputTest()
        self.fixture.setUp()
        self.fixture.pull()["base"]["repo"]["id"] = native.PILOT_ID
        self.fixture.records[f"/repos/{native.PILOT}/branches/main"] = {
            "name": "main", "protected": True, "commit": {"sha": inputs.BASE},
        }
        blob = self.fixture.blob()
        import base64
        blob["content"] = base64.encodebytes(SAFE_WORKFLOW).decode()
        blob["size"] = self.fixture.entries[0]["size"] = len(SAFE_WORKFLOW)
        self.environment = {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": native.PILOT,
                            "GITHUB_REPOSITORY_ID": str(native.PILOT_ID), "GITHUB_EVENT_NAME": "pull_request"}
        self.event = {"repository": {"id": native.PILOT_ID, "full_name": native.PILOT, "private": False},
                      "action": "opened", "number": 7, "pull_request": deepcopy(self.fixture.pull())}

    def run_gate(self, validator=None):
        return native.validate_native(self.fixture.read, self.environment["GITHUB_EVENT_NAME"],
                                      self.event, self.environment, validator=validator or (lambda *_: []))

    def group(self, head=inputs.HEAD):
        for path, value in list(self.fixture.records.items()):
            if path.startswith(f"/repos/{inputs.FORK}/git/"):
                self.fixture.records[path.replace(inputs.FORK, native.PILOT)] = deepcopy(value)
        if head != inputs.HEAD:
            commit = deepcopy(self.fixture.records[f"/repos/{native.PILOT}/git/commits/{inputs.HEAD}"])
            commit["sha"] = head
            self.fixture.records[f"/repos/{native.PILOT}/git/commits/{head}"] = commit
        ref = "refs/heads/gh-readonly-queue/main/pr-7-control"
        self.event.update(action="checks_requested", merge_group={"base_ref": "refs/heads/main",
                          "base_sha": inputs.BASE, "head_ref": ref, "head_sha": head})
        self.environment.update(GITHUB_EVENT_NAME="merge_group", GITHUB_REF=ref, GITHUB_SHA=head)
        self.fixture.requests.clear()

    def test_public_fork_uses_the_existing_inert_reader_without_an_issuer(self):
        result = self.run_gate()
        self.assertEqual(inputs.HEAD, result["head_sha"])
        self.assertEqual(inputs.FORK, result["head_repository"])
        self.assertEqual("github-required-workflow", result["enforcement"])
        self.assertFalse(any("check-runs" in path for path in self.fixture.requests))

    def test_old_event_cannot_qualify_a_newer_api_head(self):
        self.fixture.pull()["head"]["sha"] = "d" * 40
        self.fixture.requests.clear()
        with self.assertRaisesRegex(InputRefused, "stale"):
            self.run_gate()
        self.assertFalse(any("/git/" in path for path in self.fixture.requests))

    def test_head_movement_during_the_check_cannot_pass(self):
        def move(*_):
            self.fixture.pull()["head"]["sha"] = "d" * 40
            return []
        with self.assertRaises(InputRefused):
            self.run_gate(move)

    def test_wrong_repository_id_or_visibility_refuses(self):
        for key, value in (("id", True), ("id", 12), ("full_name", "other/repository"), ("private", True)):
            event = deepcopy(self.event)
            event["repository"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(InputRefused):
                native.validate_native(self.fixture.read, "pull_request", event, self.environment)

    def test_unsupported_event_and_activity_refuse(self):
        for action in ("edited", "closed", "ready_for_review"):
            self.event["action"] = action
            with self.subTest(action=action), self.assertRaises(InputRefused):
                self.run_gate()
        self.environment["GITHUB_EVENT_NAME"] = "workflow_dispatch"
        with self.assertRaises(InputRefused):
            self.run_gate()

    def test_merge_group_validates_combined_commit_without_a_pr_lookup(self):
        combined = "d" * 40
        self.group(combined)
        result = self.run_gate()
        self.assertEqual(combined, result["head_sha"])
        self.assertEqual("merge_group", result["subject"])
        self.assertIn(f"/repos/{native.PILOT}/git/commits/{combined}", self.fixture.requests)
        self.assertFalse(any("/pulls/" in path for path in self.fixture.requests))

    def test_merge_group_environment_and_base_ref_must_match(self):
        self.group()
        for key, value in (("GITHUB_SHA", "d" * 40), ("GITHUB_REF", "refs/heads/main")):
            environment = dict(self.environment, **{key: value})
            with self.subTest(key=key), self.assertRaises(InputRefused):
                native.validate_native(self.fixture.read, "merge_group", self.event, environment)
        self.event["merge_group"]["base_ref"] = "refs/heads/other"
        with self.assertRaises(InputRefused):
            self.run_gate()

    def test_merge_group_base_movement_during_validation_refuses(self):
        self.group()
        def move(*_):
            self.fixture.records[f"/repos/{native.PILOT}/branches/main"]["commit"]["sha"] = "d" * 40
            return []
        with self.assertRaises(InputRefused):
            self.run_gate(move)

    def test_merge_group_cannot_use_a_truncated_tree(self):
        self.group()
        self.fixture.records[f"/repos/{native.PILOT}/git/trees/{inputs.TREE}?recursive=1"]["truncated"] = True
        with self.assertRaises(InputRefused):
            self.run_gate()

    def test_runtime_preparation_does_not_run_outside_the_hosted_job(self):
        with patch.object(native.subprocess, "run") as run, self.assertRaises(InputRefused):
            native.prepare_runtime({"RUNNER_ENVIRONMENT": "self-hosted"})
        run.assert_not_called()
