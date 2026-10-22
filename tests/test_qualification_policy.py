from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path

from scripts.qualification_policy import (
    PolicyError,
    LOCKED_POLICY_BOOTSTRAP_REVISION,
    LOCKED_POLICY_INSTALL_COMMAND,
    _verify_action_policy_preflight,
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

    def preflight_jobs(self, target: str = "ai") -> dict:
        checkout, _ = self.approved_action("actions/checkout")
        setup_python, _ = self.approved_action("actions/setup-python")
        jobs = {
            "action-policy": {
                "name": "Central action policy preflight",
                "runs-on": "ubuntu-latest",
                "timeout-minutes": "5",
                "steps": [
                    {"uses": f"actions/checkout@{checkout}", "with": {"persist-credentials": "false"}},
                    {
                        "uses": f"actions/checkout@{checkout}",
                        "with": {
                            "repository": "durable-workflow/.github",
                            "ref": "main",
                            "path": ".central-action-policy",
                            "persist-credentials": "false",
                        },
                    },
                    {"uses": f"actions/setup-python@{setup_python}", "with": {"python-version": "3.13"}},
                    {"run": "python -m pip install PyYAML==6.0.2"},
                    {"run": "python .central-action-policy/scripts/qualification_policy.py validate "
                     f"--policy .central-action-policy/qualification/policy.json --target {target} "
                     "--workflow-directory .github/workflows"},
                ],
            },
            "gate": {
                "needs": ["action-policy"],
                "if": "${{ always() }}",
                "steps": [{
                    "env": {"ACTION_POLICY_RESULT": "${{ needs.action-policy.result }}"},
                    "run": 'test "$ACTION_POLICY_RESULT" = success',
                }],
            },
        }
        return jobs

    def test_policy_preflight_accepts_binary_only_without_relaxing_dependency_command(self) -> None:
        jobs = self.preflight_jobs()
        for command in (
            "python -m pip install PyYAML==6.0.2",
            "python -m pip install --only-binary :all: PyYAML==6.0.2",
            "python -I -m pip install PyYAML==6.0.2",
            "python -I -m pip install --only-binary :all: PyYAML==6.0.2",
        ):
            with self.subTest(command=command):
                jobs["action-policy"]["steps"][3]["run"] = command
                _verify_action_policy_preflight("ai", "fixture", jobs, "gate")
        for suffix in ("==6.0.3", "==6.0.2 --extra-index-url https://example.com", "==6.0.2; echo unsafe"):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(PolicyError, "reviewed policy dependency"):
                jobs["action-policy"]["steps"][3]["run"] = "python -m pip install --only-binary :all: PyYAML" + suffix
                _verify_action_policy_preflight("ai", "fixture", jobs, "gate")

        steps = jobs["action-policy"]["steps"]
        steps[3]["run"] = "python -m pip install PyYAML==6.0.2"
        bootstrap = {
            "name": "Bootstrap patched pip trust",
            "uses": "durable-workflow/.github/.github/actions/bootstrap-patched-pip@ff93e15dd3d3aa0b5ba8991fe5101a9e1be49c10",
        }
        steps.insert(3, bootstrap)
        _verify_action_policy_preflight("ai", "fixture", jobs, "gate")
        for revision, label in self.policy["action_runtime"]["allowed_releases"]["durable-workflow/.github"].items():
            if label == "clean-trust":
                steps[3] = {**bootstrap, "uses": bootstrap["uses"].rsplit("@", 1)[0] + "@" + revision}
                _verify_action_policy_preflight("ai", "fixture", jobs, "gate", {revision})
        for change in (
            {**bootstrap, "uses": bootstrap["uses"].replace("ff93e15", "0000000")},
            {**bootstrap, "if": "false"},
            {"run": "python -m pip install --upgrade pip"},
        ):
            with self.subTest(bootstrap=change), self.assertRaisesRegex(PolicyError, "unreviewed pip bootstrap"):
                steps[3] = change
                _verify_action_policy_preflight("ai", "fixture", jobs, "gate")
        steps[3] = bootstrap
        steps[3], steps[4] = steps[4], steps[3]
        with self.assertRaisesRegex(PolicyError, "unreviewed pip bootstrap"):
            _verify_action_policy_preflight("ai", "fixture", jobs, "gate")

    def test_server_requires_the_isolated_hash_locked_policy_install(self) -> None:
        jobs = self.preflight_jobs("server")
        steps = jobs["action-policy"]["steps"]
        steps.insert(3, {"uses": "durable-workflow/.github/.github/actions/bootstrap-patched-pip@" + LOCKED_POLICY_BOOTSTRAP_REVISION})
        steps[4]["run"] = LOCKED_POLICY_INSTALL_COMMAND
        revisions = {LOCKED_POLICY_BOOTSTRAP_REVISION}
        _verify_action_policy_preflight("server", "fixture", jobs, "gate", revisions, True)
        for flag in ("-I ", "--require-hashes ", "--only-binary=:all: ", "--no-deps "):
            changed = copy.deepcopy(jobs)
            changed["action-policy"]["steps"][4]["run"] = LOCKED_POLICY_INSTALL_COMMAND.replace(flag, "")
            with self.subTest(removed=flag), self.assertRaisesRegex(PolicyError, "reviewed policy dependency"):
                _verify_action_policy_preflight("server", "fixture", changed, "gate", revisions, True)
        for command in (
            LOCKED_POLICY_INSTALL_COMMAND.replace("qualification/requirements.lock", "requirements.lock"),
            LOCKED_POLICY_INSTALL_COMMAND.replace(".central-action-policy/", ""),
            LOCKED_POLICY_INSTALL_COMMAND + " --extra-index-url https://example.com",
            LOCKED_POLICY_INSTALL_COMMAND + " --trusted-host example.com",
            "python -m pip install PyYAML==6.0.2",
        ):
            changed = copy.deepcopy(jobs)
            changed["action-policy"]["steps"][4]["run"] = command
            with self.subTest(command=command), self.assertRaisesRegex(PolicyError, "reviewed policy dependency"):
                _verify_action_policy_preflight("server", "fixture", changed, "gate", revisions, True)
        changed = copy.deepcopy(jobs)
        changed["action-policy"]["steps"].pop(3)
        with self.assertRaisesRegex(PolicyError, "locked-policy pip bootstrap"):
            _verify_action_policy_preflight("server", "fixture", changed, "gate", revisions, True)
        changed = copy.deepcopy(jobs)
        changed["action-policy"]["steps"][3]["uses"] = steps[3]["uses"].replace(LOCKED_POLICY_BOOTSTRAP_REVISION, "75587fc33ff40c34f32ef777293dad56bb6f48c7")
        with self.assertRaisesRegex(PolicyError, "locked-policy pip bootstrap"):
            _verify_action_policy_preflight("server", "fixture", changed, "gate", revisions | {"75587fc33ff40c34f32ef777293dad56bb6f48c7"}, True)
        self.assertTrue(self.policy["targets"]["server"]["workflows"][0]["locked_policy_dependency_required"])

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
            source.replace("    runs-on:", "    name: ${{ secrets.DEPLOY_TOKEN }}\n    runs-on:"),
            source.replace("      - uses: SonarSource/", "      - name: ${{ secrets.DEPLOY_TOKEN }}\n        uses: SonarSource/"),
            source.replace("      - uses: actions/checkout@", "      - name: ${{ secrets.DEPLOY_TOKEN }}\n        uses: actions/checkout@"),
            source.replace("args: -Dsonar.qualitygate.wait=true -Dsonar.qualitygate.timeout=300", "args: []"),
        ]
        for changed in mutations:
            with self.subTest(source=changed), self.assertRaises(PolicyError):
                self.scan(changed)

    def coverage_sonar_workflow(self) -> str:
        upload, upload_version = self.approved_action("actions/upload-artifact")
        download, download_version = self.approved_action("actions/download-artifact")
        source = self.sonar_workflow().replace(
            "  pull_request:\n",
            "  pull_request:\n  workflow_dispatch:\n",
        ).replace(
            "github.event_name != 'pull_request' || "
            "github.event.pull_request.head.repo.full_name == github.repository",
            "github.event_name != 'pull_request' && github.ref == 'refs/heads/main'",
        ).replace(
            "    runs-on: ubuntu-latest",
            "    needs: [coverage]\n    runs-on: ubuntu-latest",
        ).replace(
            "      - uses: SonarSource/",
            f"""      - uses: actions/download-artifact@{download} # {download_version}
        with:
          artifact-ids: ${{{{ needs.coverage.outputs.sonar_artifact_id }}}}
          path: .sonar-coverage
          digest-mismatch: error
      - uses: SonarSource/""",
        )
        return source.replace("jobs:\n", f"""jobs:
  coverage:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    outputs:
      sonar_artifact_id: ${{{{ steps.sonar_coverage.outputs.artifact-id }}}}
    steps:
      - uses: actions/upload-artifact@{upload} # {upload_version}
        id: sonar_coverage
        with:
          name: sonar-coverage
          path: |
            coverage.xml
            build/feature-coverage/mysql-shard-0-coverage.xml
          if-no-files-found: error
          retention-days: 1
""", 1)

    def test_main_sonar_import_accepts_the_same_run_report_producer(self) -> None:
        evidence = self.scan(self.coverage_sonar_workflow())
        self.assertEqual(["test"], evidence[".github/workflows/test.yml"]["privileged_jobs"])

    def test_standalone_scan_can_leave_missing_coverage_unmeasured(self) -> None:
        source = self.sonar_workflow().replace(
            "-Dsonar.qualitygate.timeout=300",
            "-Dsonar.qualitygate.timeout=300 -Dsonar.coverage.exclusions=**/*",
        )
        self.scan(source)
        measured = self.coverage_sonar_workflow().replace(
            "-Dsonar.qualitygate.timeout=300",
            "-Dsonar.qualitygate.timeout=300 -Dsonar.coverage.exclusions=**/*",
        )
        with self.assertRaises(PolicyError):
            self.scan(measured)

    def test_sonar_report_import_requires_bound_artifacts_and_isolated_data(self) -> None:
        source = self.coverage_sonar_workflow()
        mutations = [
            source.replace("needs: [coverage]", "needs: [other]"),
            source.replace("steps.sonar_coverage.outputs.artifact-id", "steps.other.outputs.artifact-id"),
            source.replace("id: sonar_coverage", "id: other"),
            source.replace("path: .sonar-coverage", "path: ."),
            source.replace("path: .sonar-coverage", "path: ../outside"),
            source.replace("digest-mismatch: error", "digest-mismatch: warn"),
            source.replace("retention-days: 1", "retention-days: 90"),
            source.replace("if-no-files-found: error", "if-no-files-found: ignore"),
            source.replace("name: sonar-coverage", "name: unrelated"),
            source.replace("build/feature-coverage/mysql-shard-0-coverage.xml", "build/../other-coverage.xml"),
            source.replace("build/feature-coverage/mysql-shard-0-coverage.xml", "build/script.php"),
            source.replace("          path: .sonar-coverage", "          run-id: 123\n          path: .sonar-coverage"),
            source.replace("      - uses: SonarSource/", "      - run: ./report-script\n      - uses: SonarSource/"),
        ]
        for changed in mutations:
            with self.subTest(source=changed), self.assertRaises(PolicyError):
                self.scan(changed)

    def test_sonar_report_import_preserves_the_main_branch_credential_boundary(self) -> None:
        source = self.coverage_sonar_workflow()
        for changed in (
            source.replace("refs/heads/main", "refs/heads/other"),
            source.replace("github.event_name != 'pull_request'", "true"),
            source.replace(" && github.ref == 'refs/heads/main'", ""),
            source.replace("secrets.SONAR_TOKEN", "secrets.OTHER_TOKEN"),
        ):
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
