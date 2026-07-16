from __future__ import annotations

import copy
import json
import re
import unittest
import urllib.parse
from pathlib import Path
from typing import Any

from scripts.qualification_policy import (
    EXPECTED_TARGETS,
    PolicyError,
    _latest_check_runs,
    audit_policy,
    validate_policy,
    verify_workflow_source,
)

ROOT = Path(__file__).resolve().parents[1]


def policy_fixture() -> dict[str, Any]:
    return json.loads((ROOT / "qualification" / "policy.json").read_text(encoding="utf-8"))


class FakeGitHubClient:
    def __init__(self, policy: dict[str, Any]) -> None:
        self.policy = policy
        self.targets_by_repository = {
            target["repository"]: target for target in policy["targets"].values()
        }

    @staticmethod
    def _repository(path: str) -> str:
        match = re.match(r"/repos/durable-workflow/([^/]+)", path)
        if not match:
            raise AssertionError(f"unexpected API path: {path}")
        return urllib.parse.unquote(match.group(1))

    def json(self, path: str) -> Any:
        repository = self._repository(path)
        target = self.targets_by_repository[repository]
        if path == f"/repos/durable-workflow/{repository}":
            return {"default_branch": target["branch"]}
        if "/actions/workflows/" in path:
            workflow = urllib.parse.unquote(path.rsplit("/", 1)[1])
            return {"id": len(workflow), "path": f".github/workflows/{workflow}", "state": "active"}
        if "/rules/branches/" in path:
            return [
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "required_status_checks": [
                            {"context": workflow["required_check"]} for workflow in target["workflows"]
                        ],
                        "strict_required_status_checks_policy": True,
                    },
                }
            ]
        if "/branches/" in path:
            return {"commit": {"sha": "a" * 40}}
        raise AssertionError(f"unexpected API path: {path}")

    def bytes(self, path: str) -> bytes:
        repository = self._repository(path)
        branch = self.targets_by_repository[repository]["branch"]
        return f"""name: qualification
on:
  push:
    branches: [{branch}]
  pull_request:
    branches: [{branch}]
  workflow_dispatch:
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    strategy:
      fail-fast: false
""".encode()

    def collection(self, path: str, key: str) -> list[dict[str, Any]]:
        self._repository(path)
        if key != "check_runs":
            raise AssertionError(f"unexpected collection: {key}")
        repository = self._repository(path)
        return [
            {
                "conclusion": "success",
                "id": index + 1,
                "name": workflow["required_check"],
                "status": "completed",
            }
            for index, workflow in enumerate(self.targets_by_repository[repository]["workflows"])
        ]

    def list_collection(self, path: str) -> list[dict[str, Any]]:
        result = self.json(path)
        if not isinstance(result, list):
            raise AssertionError(f"unexpected non-list collection: {path}")
        return result


class QualificationPolicyTest(unittest.TestCase):
    def test_public_target_inventory_and_branches_are_complete(self) -> None:
        policy = policy_fixture()
        validate_policy(policy)
        actual = {
            name: (target["repository"], target["branch"])
            for name, target in policy["targets"].items()
        }
        self.assertEqual(EXPECTED_TARGETS, actual)

    def test_policy_rejects_a_missing_public_target(self) -> None:
        policy = policy_fixture()
        del policy["targets"]["sdk-rust"]
        with self.assertRaisesRegex(PolicyError, "target inventory mismatch"):
            validate_policy(policy)

    def test_policy_rejects_duplicate_check_contexts(self) -> None:
        policy = policy_fixture()
        duplicate = copy.deepcopy(policy["targets"]["sample-app"]["workflows"][0])
        duplicate["path"] = "duplicate.yml"
        policy["targets"]["sample-app"]["workflows"].append(duplicate)
        with self.assertRaisesRegex(PolicyError, "duplicate workflow paths or check contexts"):
            validate_policy(policy)

    def test_workflow_contract_requires_dispatch_timeout_and_independent_matrix(self) -> None:
        workflow = {
            "path": "ci.yml",
            "required_check": "qualification",
            "matrix_independent": True,
        }
        with self.assertRaisesRegex(PolicyError, "manual recovery"):
            verify_workflow_source(
                "sdk-python",
                "main",
                workflow,
                "on:\n  push:\n    branches: [main]\n  pull_request:\n    branches: [main]\n"
                "jobs:\n  test:\n    timeout-minutes: 5\n    fail-fast: false\n",
            )

    def test_latest_check_run_uses_the_latest_attempt(self) -> None:
        latest = _latest_check_runs(
            [
                {"id": 1, "name": "qualification", "conclusion": "failure"},
                {"id": 3, "name": "qualification", "conclusion": "success"},
                {"id": 2, "name": "other", "conclusion": "success"},
            ]
        )
        self.assertEqual(3, latest["qualification"]["id"])

    def test_audit_binds_successful_checks_and_protection_to_exact_heads(self) -> None:
        policy = policy_fixture()
        evidence = audit_policy(policy, FakeGitHubClient(policy))
        self.assertEqual(set(EXPECTED_TARGETS), set(evidence["targets"]))
        for target in evidence["targets"].values():
            self.assertEqual("a" * 40, target["commit"])
            self.assertEqual(
                set(target["protected_checks"]),
                set(target["successful_check_runs"]),
            )

    def test_audit_rejects_a_failed_required_check(self) -> None:
        policy = policy_fixture()

        class FailedCheckClient(FakeGitHubClient):
            def collection(self, path: str, key: str) -> list[dict[str, Any]]:
                records = super().collection(path, key)
                records[0]["conclusion"] = "failure"
                return records

        with self.assertRaisesRegex(PolicyError, "completed/failure"):
            audit_policy(policy, FailedCheckClient(policy))

    def test_audit_rejects_unprotected_required_checks(self) -> None:
        policy = policy_fixture()

        class UnprotectedClient(FakeGitHubClient):
            def json(self, path: str) -> Any:
                if "/rules/branches/" in path:
                    return []
                return super().json(path)

        with self.assertRaisesRegex(PolicyError, "does not protect checks"):
            audit_policy(policy, UnprotectedClient(policy))

    def test_self_check_can_be_skipped_during_the_same_push(self) -> None:
        policy = policy_fixture()

        class NoSelfCheckClient(FakeGitHubClient):
            def collection(self, path: str, key: str) -> list[dict[str, Any]]:
                if "/durable-workflow/.github/" in path:
                    return []
                return super().collection(path, key)

        evidence = audit_policy(
            policy,
            NoSelfCheckClient(policy),
            skip_check_runs_for={"github-control-plane"},
        )
        self.assertEqual({}, evidence["targets"]["github-control-plane"]["successful_check_runs"])


if __name__ == "__main__":
    unittest.main()
