from __future__ import annotations

import copy
import io
import json
import re
import unittest
import urllib.error
import urllib.parse
import urllib.request
from contextlib import redirect_stderr
from pathlib import Path
from typing import Any
from unittest.mock import patch

from scripts.qualification_policy import (
    EXPECTED_TARGETS,
    INFRASTRUCTURE_EXIT_CODE,
    GitHubClient,
    GitHubInfrastructureError,
    PolicyError,
    _latest_check_runs,
    audit_policy,
    main,
    validate_policy,
    verify_workflow_source,
)

ROOT = Path(__file__).resolve().parents[1]


class FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.payload


def http_error(status: int, body: bytes = b"error", **headers: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://api.github.com/repos/durable-workflow/cli",
        status,
        "request failed",
        headers,
        io.BytesIO(body),
    )


def policy_fixture() -> dict[str, Any]:
    return json.loads((ROOT / "qualification" / "policy.json").read_text(encoding="utf-8"))


class FakeGitHubClient:
    def __init__(self, policy: dict[str, Any]) -> None:
        self.policy = policy
        self.targets_by_repository = {target["repository"]: target for target in policy["targets"].values()}

    @staticmethod
    def _repository(path: str) -> str:
        match = re.match(r"/repos/durable-workflow/([^/]+)", path)
        if not match:
            raise AssertionError(f"unexpected API path: {path}")
        return urllib.parse.unquote(match.group(1))

    def json(self, path: str) -> Any:
        if path.startswith("/repos/actions/checkout/commits/"):
            return {"sha": "b" * 40}
        repository = self._repository(path)
        target = self.targets_by_repository[repository]
        if path == f"/repos/durable-workflow/{repository}":
            return {"default_branch": target["branch"]}
        if "/contents/.github/workflows?" in path:
            paths = {f".github/workflows/{workflow['path']}" for workflow in target["workflows"]}
            paths.add(".github/workflows/release.yml")
            return [{"path": workflow_path, "type": "file"} for workflow_path in sorted(paths)]
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
        if path.startswith("/repos/actions/checkout/contents/action.yml?"):
            return b"name: checkout\nruns:\n  using: node24\n  main: dist/index.js\n"
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
    steps:
      - uses: actions/checkout@v6
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
    def test_github_client_recovers_from_service_and_connection_interruptions(self) -> None:
        sleeps: list[float] = []
        client = GitHubClient(max_attempts=3, retry_base_seconds=1, sleep=sleeps.append)
        responses = [
            http_error(503, b"service unavailable"),
            urllib.error.URLError(ConnectionResetError("connection reset by peer")),
            FakeResponse(b'{"default_branch":"main"}'),
        ]

        with patch.object(urllib.request, "urlopen", side_effect=responses) as urlopen:
            result = client.json("/repos/durable-workflow/cli")

        self.assertEqual({"default_branch": "main"}, result)
        self.assertEqual([1, 2], sleeps)
        self.assertEqual(3, urlopen.call_count)

    def test_github_client_honors_rate_limit_retry_timing(self) -> None:
        sleeps: list[float] = []
        client = GitHubClient(
            max_attempts=3,
            retry_base_seconds=1,
            retry_max_seconds=30,
            sleep=sleeps.append,
            now=lambda: 100,
        )
        responses = [
            http_error(403, b"API rate limit exceeded", **{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "112"}),
            http_error(429, **{"Retry-After": "7"}),
            FakeResponse(b"[]"),
        ]

        with patch.object(urllib.request, "urlopen", side_effect=responses):
            self.assertEqual([], client.json("/repos/durable-workflow/cli/rules/branches/main"))

        self.assertEqual([12, 7], sleeps)

    def test_github_client_bounds_transient_exhaustion_with_endpoint_evidence(self) -> None:
        client = GitHubClient(max_attempts=3, retry_base_seconds=1, sleep=lambda _delay: None)

        with (
            patch.object(
                urllib.request,
                "urlopen",
                side_effect=[http_error(503), http_error(503), http_error(503)],
            ),
            self.assertRaisesRegex(
                GitHubInfrastructureError,
                r"classification=github-api-transient, endpoint=GET /repos/durable-workflow/cli, "
                r"attempts=3, status=503",
            ),
        ):
            client.json("/repos/durable-workflow/cli")

    def test_github_client_does_not_retry_authorization_failures(self) -> None:
        client = GitHubClient(max_attempts=3, sleep=lambda _delay: self.fail("authorization failure was retried"))

        with (
            patch.object(urllib.request, "urlopen", side_effect=http_error(403, b"Resource not accessible")) as urlopen,
            self.assertRaisesRegex(PolicyError, r"GitHub API 403"),
        ):
            client.json("/repos/durable-workflow/cli")

        self.assertEqual(1, urlopen.call_count)

    def test_exhaustion_uses_a_distinct_temporary_failure_exit(self) -> None:
        error = GitHubInfrastructureError("/repos/durable-workflow/cli", 5, status=503)
        stderr = io.StringIO()

        with (
            patch("scripts.qualification_policy.audit_policy", side_effect=error),
            redirect_stderr(stderr),
        ):
            exit_code = main(["audit", "--policy", str(ROOT / "qualification" / "policy.json")])

        self.assertEqual(INFRASTRUCTURE_EXIT_CODE, exit_code)
        self.assertIn("qualification infrastructure failed", stderr.getvalue())
        self.assertIn("endpoint=GET /repos/durable-workflow/cli", stderr.getvalue())

    def test_github_client_rejects_malformed_json_without_retry(self) -> None:
        client = GitHubClient(max_attempts=3, sleep=lambda _delay: self.fail("malformed data was retried"))

        with (
            patch.object(urllib.request, "urlopen", return_value=FakeResponse(b"<html>not JSON</html>")) as urlopen,
            self.assertRaisesRegex(PolicyError, r"is not valid JSON"),
        ):
            client.json("/repos/durable-workflow/cli")

        self.assertEqual(1, urlopen.call_count)

    def test_public_target_inventory_and_branches_are_complete(self) -> None:
        policy = policy_fixture()
        validate_policy(policy)
        actual = {name: (target["repository"], target["branch"]) for name, target in policy["targets"].items()}
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

    def test_policy_rejects_retired_runtime_as_supported(self) -> None:
        policy = policy_fixture()
        policy["action_runtime"]["supported_javascript_runtimes"] = ["node20"]
        with self.assertRaisesRegex(PolicyError, "supported JavaScript action runtimes"):
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
            self.assertEqual("node24", target["action_releases"][0]["runtime"])
            self.assertIn(".github/workflows/release.yml", target["action_releases"][0]["workflows"])

    def test_audit_rejects_an_unapproved_action_release(self) -> None:
        policy = policy_fixture()

        class RetiredReleaseClient(FakeGitHubClient):
            def bytes(self, path: str) -> bytes:
                source = super().bytes(path)
                if "/repos/durable-workflow/" in path and "/contents/.github/workflows/" in path:
                    return source.replace(b"actions/checkout@v6", b"actions/checkout@v4")
                return source

        with self.assertRaisesRegex(PolicyError, "actions/checkout@v4 is not centrally approved"):
            audit_policy(policy, RetiredReleaseClient(policy))

    def test_audit_rejects_a_flow_style_unapproved_action_release(self) -> None:
        policy = policy_fixture()

        class FlowStyleReleaseClient(FakeGitHubClient):
            def bytes(self, path: str) -> bytes:
                source = super().bytes(path)
                if "/repos/durable-workflow/" in path and "/contents/.github/workflows/" in path:
                    return source.replace(
                        b"- uses: actions/checkout@v6",
                        b"- { uses: actions/checkout@v4 }",
                    )
                return source

        with self.assertRaisesRegex(PolicyError, "actions/checkout@v4 is not centrally approved"):
            audit_policy(policy, FlowStyleReleaseClient(policy))

    def test_audit_rejects_a_retired_action_javascript_runtime(self) -> None:
        policy = policy_fixture()

        class RetiredRuntimeClient(FakeGitHubClient):
            def bytes(self, path: str) -> bytes:
                if path.startswith("/repos/actions/checkout/contents/action.yml?"):
                    return b"name: checkout\nruns:\n  using: node20\n  main: dist/index.js\n"
                return super().bytes(path)

        with self.assertRaisesRegex(PolicyError, "uses retired JavaScript runtime node20"):
            audit_policy(policy, RetiredRuntimeClient(policy))

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
