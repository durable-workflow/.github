from __future__ import annotations

import base64
import copy
import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock

import yaml

from scripts import beta_candidate, component_release_recovery
from scripts.beta_candidate import CLI_ASSETS, CandidateError, canonical_cli_embedded_identity
from scripts.component_release_recovery import RecoveryError
from scripts.release_plan import (
    require_distribution_identity,
    revalidate_conflict_public_evidence,
)

VERIFIERS = (
    (beta_candidate, CandidateError),
    (component_release_recovery, RecoveryError),
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def inspected_build_info(version: str, commit: str) -> str:
    source = (
        "<?php declare(strict_types=1); namespace DurableWorkflow\\Cli; "
        "final class GeneratedBuildInfo { "
        f"public const VERSION = '{version}'; public const COMMIT = '{commit}'; "
        "public const BUILD_DATE = '2026-07-21T00:00:00Z'; }"
    )
    return base64.b64encode(source.encode()).decode()


class CliReleaseFixtureClient:
    def __init__(self, version: str) -> None:
        self.version = version
        self.contents = {name: f"fixture {name}\n".encode() for name in CLI_ASSETS - {"SHA256SUMS"}}
        self.checksums = "".join(
            f"{hashlib.sha256(content).hexdigest()}  {name}\n" for name, content in sorted(self.contents.items())
        ).encode()

    def json(self, _url: str) -> dict[str, object]:
        return {
            "id": 123,
            "tag_name": self.version,
            "draft": False,
            "html_url": f"https://github.com/durable-workflow/cli/releases/tag/{self.version}",
            "assets": [
                {
                    "id": index,
                    "name": name,
                    "browser_download_url": f"https://example.invalid/{name}",
                }
                for index, name in enumerate(sorted(CLI_ASSETS), start=1)
            ],
        }

    def bytes(self, _url: str) -> bytes:
        return self.checksums

    def download(self, url: str, path: Path, *, expected_sha256: str) -> dict[str, object]:
        content = self.contents[url.rsplit("/", 1)[-1]]
        if expected_sha256 != hashlib.sha256(content).hexdigest():
            raise AssertionError("fixture download checksum mismatch")
        path.write_bytes(content)
        return {"url": url, "size": len(content), "sha256": expected_sha256}


def verify_cli_release(
    module: ModuleType,
    client: CliReleaseFixtureClient,
    version: str,
    commit: str,
) -> dict[str, object]:
    if module is beta_candidate:
        with tempfile.TemporaryDirectory() as temporary:
            return module.verify_github_release(
                client,
                module.COMPONENTS["cli"],
                version,
                commit,
                Path(temporary),
            )
    return module.verify_cli(client, module.COMPONENTS["cli"], version, commit)


class CliReleaseAuthorityTest(unittest.TestCase):
    def test_verifiers_accept_qualified_main_authority_and_isolate_phar_execution(self) -> None:
        version = "0.1.94"
        commit = "36bde75882980e834854a145c9ad0f61ceec4659"
        allowed_path = "/opt/php/bin:/usr/bin"

        for module, _error_type in VERIFIERS:
            with self.subTest(module=module.__name__):
                calls: list[tuple[list[str], dict[str, object]]] = []

                def run(
                    command: list[str],
                    calls: list[tuple[list[str], dict[str, object]]] = calls,
                    current_module: ModuleType = module,
                    **kwargs: object,
                ) -> subprocess.CompletedProcess[str]:
                    calls.append((command, kwargs))
                    if command[0] == "php":
                        return subprocess.CompletedProcess(
                            command,
                            0,
                            stdout=(
                                inspected_build_info(version, commit)
                                if current_module is beta_candidate
                                else f"dw {version} (commit {commit[:12]}, built 2026-07-20)"
                            ),
                            stderr="",
                        )
                    if "--source-digest" in command:
                        return subprocess.CompletedProcess(command, 1, stdout="", stderr="not exact-tag authority")
                    return subprocess.CompletedProcess(command, 0, stdout="verified", stderr="")

                with (
                    mock.patch.dict(
                        os.environ,
                        {"PATH": allowed_path, "GH_TOKEN": "secret", "DATABASE_URL": "secret"},
                        clear=False,
                    ),
                    mock.patch.object(module.shutil, "which", return_value="/usr/bin/tool"),
                    mock.patch.object(module.subprocess, "run", side_effect=run),
                ):
                    evidence = verify_cli_release(module, CliReleaseFixtureClient(version), version, commit)

                attestations = [command for command, _kwargs in calls if command[0] == "gh"]
                main_attestations = [command for command in attestations if "--signer-workflow" in command]
                self.assertEqual(len(CLI_ASSETS) + 1, len(attestations))
                self.assertEqual(len(CLI_ASSETS), len(main_attestations))
                for command in main_attestations:
                    self.assertEqual("refs/heads/main", command[command.index("--source-ref") + 1])
                    self.assertEqual(
                        "durable-workflow/cli/.github/workflows/release.yml",
                        command[command.index("--signer-workflow") + 1],
                    )
                    self.assertNotIn("--source-digest", command)
                self.assertEqual(
                    {
                        "mode": "qualified-main-workflow",
                        "ref": "refs/heads/main",
                        "workflow": "durable-workflow/cli/.github/workflows/release.yml",
                    },
                    evidence["build_attestation_authority"],
                )
                self.assertEqual(commit, evidence["package_source"]["commit"])
                if module is beta_candidate:
                    self.assertEqual(
                        canonical_cli_embedded_identity(version, commit),
                        evidence["package_source"]["embedded_phar_identity"],
                    )
                self.assertEqual({"PATH": allowed_path}, calls[-1][1]["env"])
                phar_argument = calls[-1][0][-1] if module is beta_candidate else calls[-1][0][1]
                self.assertEqual(Path(phar_argument).parent, calls[-1][1]["cwd"])

    def test_control_plane_cli_verifiers_are_isolated_from_write_authority(self) -> None:
        workflows = {
            "beta-candidate.yml": {
                "verification": "python scripts/beta_candidate.py verify",
                "mutation": "python scripts/beta_candidate.py record",
                "handoff": {
                    "candidate.json",
                    "verification.json",
                },
            },
            "release-plan-observer.yml": {
                "verification": "python scripts/release_plan.py observe",
                "mutation": "python scripts/release_plan.py complete",
                "handoff": {
                    "release-plan.json",
                    "release-preparation.json",
                    "candidate-verifier-input.json",
                    "release-state.json",
                    "verification.json",
                },
            },
            "release-plan-supersession.yml": {
                "verification": "python scripts/release_plan.py prepare-supersession",
                "mutation": "python scripts/release_plan.py record-supersession",
                "handoff": {
                    "release-plan-failure.json",
                    "authoritative-successor-release-plan.json",
                },
            },
        }

        self.assertEqual(
            {
                "beta-candidate.yml",
                "release-plan-observer.yml",
                "release-plan-supersession.yml",
            },
            set(workflows),
        )
        for filename, contract in workflows.items():
            with self.subTest(workflow=filename):
                source = (REPOSITORY_ROOT / ".github" / "workflows" / filename).read_text(encoding="utf-8")
                workflow = yaml.safe_load(source)
                self.assertEqual({}, workflow["permissions"])
                jobs = workflow["jobs"]
                verification_name, verification_job = next(
                    (name, job)
                    for name, job in jobs.items()
                    if any(contract["verification"] in step.get("run", "") for step in job["steps"])
                )
                mutation_name, mutation_job = next(
                    (name, job)
                    for name, job in jobs.items()
                    if any(contract["mutation"] in step.get("run", "") for step in job["steps"])
                )
                self.assertNotEqual(verification_name, mutation_name)
                self.assertEqual("read", verification_job["permissions"]["contents"])
                self.assertNotIn("write", verification_job["permissions"].values())
                self.assertEqual("write", mutation_job["permissions"]["contents"])
                mutation_needs = (
                    {mutation_job["needs"]} if isinstance(mutation_job["needs"], str) else set(mutation_job["needs"])
                )
                self.assertIn(verification_name, mutation_needs)

                for job in (verification_job, mutation_job):
                    checkouts = [
                        step for step in job["steps"] if str(step.get("uses", "")).startswith("actions/checkout@")
                    ]
                    self.assertGreaterEqual(len(checkouts), 1)
                    for checkout in checkouts:
                        self.assertEqual("actions/checkout@v6", checkout["uses"])
                        self.assertIs(checkout["with"]["persist-credentials"], False)
                        self.assertEqual("${{ github.sha }}", checkout["with"]["ref"])

                verification = next(
                    step for step in verification_job["steps"] if contract["verification"] in step.get("run", "")
                )
                mutation = next(step for step in mutation_job["steps"] if contract["mutation"] in step.get("run", ""))
                upload = next(
                    step
                    for step in verification_job["steps"]
                    if step.get("uses") == "actions/upload-artifact@v7"
                    and contract["handoff"].issubset(set(step["with"].get("path", "").splitlines()))
                )
                download = next(
                    step for step in mutation_job["steps"] if step.get("uses") == "actions/download-artifact@v8"
                )

                self.assertEqual(upload["with"]["name"], download["with"]["name"])
                self.assertEqual(
                    contract["handoff"],
                    set(upload["with"]["path"].splitlines()),
                )
                self.assertIn(
                    "GIT_CONFIG_KEY_0=http.https://github.com/.extraheader",
                    mutation["run"],
                )
                self.assertIn(
                    'GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $git_authorization"',
                    mutation["run"],
                )
                self.assertEqual("${{ github.token }}", mutation["env"]["GITHUB_TOKEN"])
                for token_name in ("GITHUB_TOKEN", "GH_TOKEN"):
                    if token_name in verification.get("env", {}):
                        self.assertEqual("${{ github.token }}", verification["env"][token_name])

    def test_observer_writer_binds_mutation_to_trusted_plan_discovery(self) -> None:
        workflow = yaml.safe_load(
            (REPOSITORY_ROOT / ".github/workflows/release-plan-observer.yml").read_text(encoding="utf-8")
        )
        observe = workflow["jobs"]["observe"]
        record = workflow["jobs"]["record"]
        trusted_plan_tag = "${{ needs.observe.outputs.plan-tag }}"
        trusted_plan_sha256 = "${{ needs.observe.outputs.plan-sha256 }}"
        trusted_preparation_sha256 = "${{ needs.observe.outputs.preparation-sha256 }}"
        trusted_verification_outcome = "${{ needs.observe.outputs.verification-outcome }}"
        self.assertEqual("${{ steps.plan.outputs.tag }}", observe["outputs"]["plan-tag"])
        self.assertEqual("read", observe["permissions"]["attestations"])
        self.assertNotIn("write", observe["permissions"].values())
        self.assertEqual("${{ steps.plan.outputs.plan_sha256 }}", observe["outputs"]["plan-sha256"])
        self.assertEqual(
            "${{ steps.plan.outputs.preparation_sha256 }}",
            observe["outputs"]["preparation-sha256"],
        )

        rediscovery = next(step for step in record["steps"] if "release_plan.py discover" in step.get("run", ""))
        handoff = next(
            step for step in record["steps"] if "release_plan.py validate-observation-handoff" in step.get("run", "")
        )
        upload = next(step for step in record["steps"] if "gh release upload" in step.get("run", ""))
        self.assertEqual(trusted_plan_tag, rediscovery["env"]["EXPECTED_PLAN_TAG"])
        self.assertIn('--tag "$EXPECTED_PLAN_TAG"', rediscovery["run"])
        self.assertEqual(trusted_plan_tag, handoff["env"]["EXPECTED_PLAN_TAG"])
        self.assertEqual(trusted_plan_sha256, handoff["env"]["EXPECTED_PLAN_SHA256"])
        self.assertEqual(
            trusted_preparation_sha256,
            handoff["env"]["EXPECTED_PREPARATION_SHA256"],
        )
        self.assertEqual(
            trusted_verification_outcome,
            handoff["env"]["EXPECTED_VERIFICATION_OUTCOME"],
        )
        self.assertEqual("${{ github.token }}", handoff["env"]["GH_TOKEN"])
        self.assertEqual("${{ github.token }}", handoff["env"]["GITHUB_TOKEN"])
        self.assertEqual("read", record["permissions"]["attestations"])
        for argument in (
            "--authoritative-plan",
            "--authoritative-preparation",
            "--expected-plan-tag",
            "--expected-plan-sha256",
            "--expected-preparation-sha256",
            "--expected-verification-outcome",
        ):
            self.assertIn(argument, handoff["run"])
        self.assertEqual(trusted_plan_tag, upload["env"]["PLAN_TAG"])
        self.assertNotIn("steps.handoff.outputs", upload["env"]["PLAN_TAG"])
        self.assertLess(record["steps"].index(rediscovery), record["steps"].index(handoff))
        self.assertLess(record["steps"].index(handoff), record["steps"].index(upload))

    def test_supersession_writer_binds_mutation_to_dispatch_authority(self) -> None:
        workflow = yaml.safe_load(
            (REPOSITORY_ROOT / ".github/workflows/release-plan-supersession.yml").read_text(encoding="utf-8")
        )
        steps = workflow["jobs"]["record"]["steps"]
        handoff = next(step for step in steps if "release_plan.py validate-supersession-handoff" in step.get("run", ""))
        mutation = next(step for step in steps if "release_plan.py record-supersession" in step.get("run", ""))

        self.assertEqual("${{ inputs.failed_plan_tag }}", handoff["env"]["FAILED_PLAN_TAG"])
        self.assertEqual(
            "${{ inputs.conflicting_components }}",
            handoff["env"]["CONFLICTING_COMPONENTS"],
        )
        self.assertNotIn("GITHUB_TOKEN", handoff.get("env", {}))
        self.assertNotIn("GH_TOKEN", handoff.get("env", {}))
        self.assertIn('--expected-failed-plan-tag "$FAILED_PLAN_TAG"', handoff["run"])
        self.assertIn(
            '--expected-conflict-components "$CONFLICTING_COMPONENTS"',
            handoff["run"],
        )
        self.assertIn("authorized-release-plan-failure.json", handoff["run"])
        self.assertIn(
            "record-supersession \\\n    authorized-release-plan-failure.json",
            mutation["run"],
        )
        self.assertNotIn("isolated-supersession/release-plan-failure.json", mutation["run"])
        self.assertEqual("${{ github.token }}", mutation["env"]["GITHUB_TOKEN"])
        self.assertLess(steps.index(handoff), steps.index(mutation))

    def test_supersession_write_revalidation_does_not_execute_the_downloaded_phar(self) -> None:
        version = "0.1.95"
        observed_commit = "e" * 40
        embedded_identity = canonical_cli_embedded_identity(version, observed_commit)
        release = {
            "id": 123,
            "url": "https://github.com/durable-workflow/cli/releases/1",
        }
        distribution = {
            "kind": "github-release",
            "build_attestations_verified": True,
            "build_attestation_authority": {
                "mode": "exact-tag",
                "ref": f"refs/tags/{version}",
                "commit": observed_commit,
            },
            "package_source": {
                "commit": observed_commit,
                "embedded_phar_identity": embedded_identity,
            },
            "assets": [],
        }
        conflict = {
            "component": "cli",
            "version": version,
            "observed_commit": observed_commit,
            "reason": "published-version-source-conflict",
            "github_release": release,
            "distribution": distribution,
        }
        failed_plan = {
            "components": {
                "cli": {"version": version, "commit": "a" * 40},
            }
        }
        verifier = mock.Mock(return_value=distribution)
        with (
            mock.patch("scripts.release_plan.resolve_tag", return_value=observed_commit),
            mock.patch("scripts.release_plan.github_release_conflict_evidence", return_value=release),
            mock.patch("scripts.release_plan.verify_github_release", verifier),
        ):
            revalidate_conflict_public_evidence(conflict, failed_plan, {}, mock.Mock())

        self.assertEqual(1, verifier.call_count)
        self.assertEqual({}, verifier.call_args.kwargs)

    def test_verifiers_accept_exact_tag_authority_for_the_planned_package_source(self) -> None:
        version = "0.1.95"
        commit = "4" * 40

        for module, _error_type in VERIFIERS:
            with self.subTest(module=module.__name__):
                calls: list[list[str]] = []

                def run(
                    command: list[str],
                    calls: list[list[str]] = calls,
                    current_module: ModuleType = module,
                    **_kwargs: object,
                ) -> subprocess.CompletedProcess[str]:
                    calls.append(command)
                    if command[0] == "php":
                        return subprocess.CompletedProcess(
                            command,
                            0,
                            stdout=(
                                inspected_build_info(version, commit)
                                if current_module is beta_candidate
                                else f"dw {version} (commit {commit[:12]}, built 2026-07-21)"
                            ),
                            stderr="",
                        )
                    return subprocess.CompletedProcess(command, 0, stdout="verified", stderr="")

                with (
                    mock.patch.object(module.shutil, "which", return_value="/usr/bin/tool"),
                    mock.patch.object(module.subprocess, "run", side_effect=run),
                ):
                    evidence = verify_cli_release(module, CliReleaseFixtureClient(version), version, commit)

                attestations = [command for command in calls if command[0] == "gh"]
                self.assertEqual(len(CLI_ASSETS), len(attestations))
                for command in attestations:
                    self.assertEqual(commit, command[command.index("--source-digest") + 1])
                    self.assertEqual(f"refs/tags/{version}", command[command.index("--source-ref") + 1])
                    self.assertNotIn("--signer-workflow", command)
                self.assertEqual(
                    {
                        "mode": "exact-tag",
                        "ref": f"refs/tags/{version}",
                        "commit": commit,
                    },
                    evidence["build_attestation_authority"],
                )
                self.assertEqual(commit, evidence["package_source"]["commit"])

    def test_verifiers_reject_untrusted_main_workflow_or_ref(self) -> None:
        version = "0.1.94"
        commit = "3" * 40
        untrusted_authorities = (
            ("refs/heads/release", "durable-workflow/cli/.github/workflows/release.yml"),
            ("refs/heads/main", "durable-workflow/cli/.github/workflows/untrusted.yml"),
        )

        for module, error_type in VERIFIERS:
            for accepted_ref, accepted_workflow in untrusted_authorities:
                with self.subTest(module=module.__name__, ref=accepted_ref, workflow=accepted_workflow):

                    def run(
                        command: list[str],
                        accepted_ref: str = accepted_ref,
                        accepted_workflow: str = accepted_workflow,
                        **_kwargs: object,
                    ) -> subprocess.CompletedProcess[str]:
                        valid = (
                            "--signer-workflow" in command
                            and command[command.index("--source-ref") + 1] == accepted_ref
                            and command[command.index("--signer-workflow") + 1] == accepted_workflow
                        )
                        return subprocess.CompletedProcess(
                            command, 0 if valid else 1, stdout="", stderr="untrusted authority"
                        )

                    with (
                        mock.patch.object(module.shutil, "which", return_value="/usr/bin/tool"),
                        mock.patch.object(module.subprocess, "run", side_effect=run),
                        self.assertRaisesRegex(error_type, "untrusted authority"),
                    ):
                        verify_cli_release(module, CliReleaseFixtureClient(version), version, commit)

    def test_verifiers_pin_one_attestation_mode_across_every_asset(self) -> None:
        version = "0.1.94"
        commit = "3" * 40

        for module, error_type in VERIFIERS:
            with self.subTest(module=module.__name__):
                exact_tag_attempts = 0
                calls: list[list[str]] = []

                def run(
                    command: list[str],
                    calls: list[list[str]] = calls,
                    **_kwargs: object,
                ) -> subprocess.CompletedProcess[str]:
                    nonlocal exact_tag_attempts
                    calls.append(command)
                    if command[0] == "php":
                        self.fail("PHAR executed before every asset shared one authority")
                    if "--source-digest" in command:
                        exact_tag_attempts += 1
                        return subprocess.CompletedProcess(
                            command,
                            0 if exact_tag_attempts == 1 else 1,
                            stdout="",
                            stderr="authority differs",
                        )
                    return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

                with (
                    mock.patch.object(module.shutil, "which", return_value="/usr/bin/tool"),
                    mock.patch.object(module.subprocess, "run", side_effect=run),
                    self.assertRaisesRegex(error_type, "exact-tag: authority differs"),
                ):
                    verify_cli_release(module, CliReleaseFixtureClient(version), version, commit)

                self.assertEqual(2, exact_tag_attempts)
                self.assertFalse(any("--signer-workflow" in command for command in calls))

    def test_verifiers_reject_embedded_package_source_mismatch(self) -> None:
        version = "0.1.94"
        commit = "3" * 40

        for module, error_type in VERIFIERS:
            with self.subTest(module=module.__name__):

                def run(
                    command: list[str],
                    current_module: ModuleType = module,
                    **_kwargs: object,
                ) -> subprocess.CompletedProcess[str]:
                    if command[0] == "php":
                        wrong_commit = "f" * 40
                        return subprocess.CompletedProcess(
                            command,
                            0,
                            stdout=(
                                inspected_build_info(version, wrong_commit)
                                if current_module is beta_candidate
                                else f"dw {version} (commit {wrong_commit[:12]}, built 2026-07-20)"
                            ),
                            stderr="",
                        )
                    return subprocess.CompletedProcess(command, 0, stdout="verified", stderr="")

                with (
                    mock.patch.object(module.shutil, "which", return_value="/usr/bin/tool"),
                    mock.patch.object(module.subprocess, "run", side_effect=run),
                    self.assertRaisesRegex(error_type, "does not embed planned source commit"),
                ):
                    verify_cli_release(module, CliReleaseFixtureClient(version), version, commit)

    def test_release_plan_binds_package_source_and_attestation_authority_separately(self) -> None:
        version = "0.1.94"
        package_commit = "36bde75882980e834854a145c9ad0f61ceec4659"
        distribution = {
            "kind": "github-release",
            "build_attestations_verified": True,
            "build_attestation_authority": {
                "mode": "qualified-main-workflow",
                "ref": "refs/heads/main",
                "workflow": "durable-workflow/cli/.github/workflows/release.yml",
            },
            "package_source": {
                "commit": package_commit,
                "embedded_phar_identity": canonical_cli_embedded_identity(version, package_commit),
            },
        }

        require_distribution_identity(distribution, "cli", version, package_commit)

        wrong_package_source = copy.deepcopy(distribution)
        wrong_package_source["package_source"]["commit"] = "b" * 40
        with self.assertRaisesRegex(CandidateError, "bind the observed source commit"):
            require_distribution_identity(wrong_package_source, "cli", version, package_commit)

        for field, value in (
            ("ref", "refs/heads/release"),
            ("workflow", "durable-workflow/cli/.github/workflows/untrusted.yml"),
        ):
            with self.subTest(field=field):
                untrusted_authority = copy.deepcopy(distribution)
                untrusted_authority["build_attestation_authority"][field] = value
                with self.assertRaisesRegex(CandidateError, "untrusted build attestation authority"):
                    require_distribution_identity(untrusted_authority, "cli", version, package_commit)


if __name__ == "__main__":
    unittest.main()
