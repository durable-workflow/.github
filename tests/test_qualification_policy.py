from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.qualification_policy import (
    PolicyError,
    scan_workflow_sources,
    validate_local_action_references,
    validate_policy,
)

ROOT = Path(__file__).resolve().parents[1]


def policy_fixture() -> dict[str, object]:
    return json.loads((ROOT / "qualification/policy.json").read_text(encoding="utf-8"))


def workflow(*steps: str, trigger: str = "pull_request", permissions: str = "contents: read") -> str:
    rendered_steps = "\n".join(f"      {line}" for step in steps for line in step.splitlines())
    return f"""name: test
on:
  {trigger}:
permissions:
  {permissions}
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
{rendered_steps}
"""


class QualificationPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = policy_fixture()

    def scan(self, source: str) -> dict[str, dict[str, object]]:
        return scan_workflow_sources(
            self.policy,
            "github-control-plane",
            {".github/workflows/test.yml": source},
        )

    def approved_action(self, repository: str) -> tuple[str, str]:
        releases = self.policy["action_runtime"]["allowed_releases"][repository]
        commit, version = next(iter(releases.items()))
        return commit, version

    def test_checked_in_policy_is_valid_and_has_no_retired_consumers(self) -> None:
        validate_policy(self.policy)
        self.assertEqual(
            {},
            self.policy["workflow_trust"]["privileged_workflow_run_consumers"],
        )
        self.assertEqual(
            [{
                "matrix_independent": False,
                "path": "ci.yml",
                "required_check": "Shared contract tests",
            }],
            self.policy["targets"]["github-control-plane"]["workflows"],
        )

    def test_current_control_repository_workflows_satisfy_policy(self) -> None:
        actions = validate_local_action_references(
            self.policy,
            ROOT / ".github/workflows",
            "github-control-plane",
        )
        self.assertTrue(actions)
        self.assertTrue(all("@" in action for action in actions))

    def test_approved_immutable_action_with_version_comment_is_accepted(self) -> None:
        commit, version = self.approved_action("actions/checkout")
        evidence = self.scan(workflow(f"- uses: actions/checkout@{commit} # {version}"))
        self.assertEqual(
            [f"actions/checkout@{commit}"],
            evidence[".github/workflows/test.yml"]["external_actions"],
        )

    def test_mutable_and_unknown_action_references_are_rejected(self) -> None:
        for reference in ("main", "a" * 40):
            with self.subTest(reference=reference), self.assertRaises(PolicyError):
                self.scan(workflow(f"- uses: actions/checkout@{reference} # unknown"))

    def test_action_pin_requires_its_reviewed_version_comment(self) -> None:
        commit, _version = self.approved_action("actions/checkout")
        with self.assertRaisesRegex(PolicyError, "readable version comment"):
            self.scan(workflow(f"- uses: actions/checkout@{commit}"))

    def test_pull_request_workflows_cannot_request_write_access(self) -> None:
        with self.assertRaisesRegex(PolicyError, "top-level write permissions"):
            self.scan(workflow("- run: true", permissions="contents: write"))

    def test_pull_request_target_is_rejected(self) -> None:
        with self.assertRaisesRegex(PolicyError, "pull_request_target"):
            self.scan(workflow("- run: true", trigger="pull_request_target"))

    def test_pull_request_jobs_cannot_use_environments_or_secrets(self) -> None:
        source = workflow("- run: echo ${{ secrets.TOKEN }}")
        source = source.replace("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    environment: production")
        with self.assertRaises(PolicyError):
            self.scan(source)

    def sonar_workflow(self) -> str:
        checkout, checkout_version = self.approved_action("actions/checkout")
        scanner, scanner_version = self.approved_action("sonarsource/sonarqube-scan-action")
        source = workflow(
            f"""- uses: actions/checkout@{checkout} # {checkout_version}
  with:
    fetch-depth: 0
    persist-credentials: false""",
            f"""- uses: SonarSource/sonarqube-scan-action@{scanner} # {scanner_version}
  env:
    SONAR_TOKEN: ${{{{ secrets.SONAR_TOKEN }}}}
  with:
    args: -Dsonar.qualitygate.wait=true -Dsonar.qualitygate.timeout=300""",
        )
        return source.replace(
            "    runs-on: ubuntu-latest\n    timeout-minutes: 5",
            "    if: github.event_name != 'pull_request' || "
            "github.event.pull_request.head.repo.full_name == github.repository\n"
            "    runs-on: ubuntu-latest\n    timeout-minutes: 15",
        )

    def test_isolated_same_repository_sonar_analysis_is_accepted(self) -> None:
        self.scan(self.sonar_workflow())

    def test_sonar_coverage_preparation_does_not_receive_analysis_credential(self) -> None:
        source = self.sonar_workflow().replace(
            "      - uses: SonarSource/",
            "      - run: python -m unittest\n      - uses: SonarSource/",
        )
        self.scan(source)
        leaked = source.replace("python -m unittest", "echo ${{ secrets.SONAR_TOKEN }}")
        with self.assertRaises(PolicyError):
            self.scan(leaked)

    def test_sonar_credential_exception_rejects_forks_and_unsafe_jobs(self) -> None:
        source = self.sonar_workflow()
        mutations = [
            source.replace("github.event.pull_request.head.repo.full_name == github.repository", "true"),
            source + "      - run: ./untrusted-script\n",
            source.replace("persist-credentials: false", "persist-credentials: true"),
            source.replace("fetch-depth: 0", "ref: ${{ github.event.pull_request.head.sha }}"),
            source.replace("secrets.SONAR_TOKEN", "secrets.PRODUCTION_TOKEN"),
            source.replace("qualitygate.timeout=300", "qualitygate.timeout=300 -Dsonar.host.url=https://example.com"),
            source.replace("    runs-on:", "    env:\n      TOKEN: ${{ secrets.TOKEN }}\n    runs-on:"),
            source.replace("    runs-on: ubuntu-latest", "    runs-on: self-hosted"),
            source.replace("timeout-minutes: 15", "timeout-minutes: 30"),
            source.replace("      - uses: actions/checkout@", "      - uses: actions/checkout/subdirectory@"),
            source.replace("      - uses: SonarSource/", "      - id: extra-state\n        uses: SonarSource/"),
            source.replace("      - uses: actions/checkout@", "      - id: extra-state\n        uses: actions/checkout@"),
            source.replace("    steps:\n", "    strategy: {}\n    steps:\n"),
        ]
        for changed in mutations:
            with self.subTest(source=changed), self.assertRaises(PolicyError):
                self.scan(changed)

    def test_pull_request_cache_rejects_broad_paths(self) -> None:
        commit, version = self.approved_action("actions/cache")
        source = workflow(
            f"""- uses: actions/cache@{commit} # {version}
  with:
    path: .
    key: test-${{{{ github.event_name }}}}"""
        )
        with self.assertRaisesRegex(PolicyError, "unsafe cache path"):
            self.scan(source)

    def test_policy_rejects_a_retired_javascript_runtime(self) -> None:
        candidate = copy.deepcopy(self.policy)
        candidate["action_runtime"]["supported_javascript_runtimes"] = ["node20"]
        with self.assertRaisesRegex(PolicyError, "supported JavaScript action runtimes"):
            validate_policy(candidate)

    def test_cli_validate_writes_no_repository_state(self) -> None:
        commit, version = self.approved_action("actions/checkout")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "ci.yml").write_text(
                workflow(f"- uses: actions/checkout@{commit} # {version}"),
                encoding="utf-8",
            )
            before = sorted(path.name for path in directory.iterdir())
            validate_local_action_references(self.policy, directory, "github-control-plane")
            self.assertEqual(before, sorted(path.name for path in directory.iterdir()))


if __name__ == "__main__":
    unittest.main()
