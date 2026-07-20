from __future__ import annotations

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
from scripts.beta_candidate import CLI_ASSETS, CandidateError
from scripts.component_release_recovery import RecoveryError
from scripts.release_plan import require_distribution_identity

VERIFIERS = (
    (beta_candidate, CandidateError),
    (component_release_recovery, RecoveryError),
)
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class CliReleaseFixtureClient:
    def __init__(self, version: str) -> None:
        self.version = version
        self.contents = {
            name: f"fixture {name}\n".encode() for name in CLI_ASSETS - {"SHA256SUMS"}
        }
        self.checksums = "".join(
            f"{hashlib.sha256(content).hexdigest()}  {name}\n"
            for name, content in sorted(self.contents.items())
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
                    **kwargs: object,
                ) -> subprocess.CompletedProcess[str]:
                    calls.append((command, kwargs))
                    if command[0] == "php":
                        return subprocess.CompletedProcess(
                            command,
                            0,
                            stdout=f"dw {version} (commit {commit[:12]}, built 2026-07-20)",
                            stderr="",
                        )
                    if "--source-digest" in command:
                        return subprocess.CompletedProcess(
                            command, 1, stdout="", stderr="not exact-tag authority"
                        )
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
                    evidence = verify_cli_release(
                        module, CliReleaseFixtureClient(version), version, commit
                    )

                attestations = [command for command, _kwargs in calls if command[0] == "gh"]
                main_attestations = [
                    command for command in attestations if "--signer-workflow" in command
                ]
                self.assertEqual(len(CLI_ASSETS) + 1, len(attestations))
                self.assertEqual(len(CLI_ASSETS), len(main_attestations))
                for command in main_attestations:
                    self.assertEqual(
                        "refs/heads/main", command[command.index("--source-ref") + 1]
                    )
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
                self.assertEqual({"PATH": allowed_path}, calls[-1][1]["env"])
                self.assertEqual(Path(calls[-1][0][1]).parent, calls[-1][1]["cwd"])

    def test_control_plane_artifact_jobs_do_not_persist_checkout_credentials(self) -> None:
        workflows = (
            (
                "beta-candidate.yml",
                "python scripts/beta_candidate.py verify",
                "python scripts/beta_candidate.py record",
                False,
            ),
            (
                "release-plan-observer.yml",
                "python scripts/release_plan.py observe",
                "python scripts/release_plan.py complete",
                False,
            ),
            (
                "release-plan-supersession.yml",
                "python scripts/release_plan.py prepare-supersession",
                "python scripts/release_plan.py record-supersession",
                True,
            ),
        )

        for filename, verification_command, mutation_command, token_free_verifier in workflows:
            with self.subTest(workflow=filename):
                source = (REPOSITORY_ROOT / ".github" / "workflows" / filename).read_text(
                    encoding="utf-8"
                )
                workflow = yaml.safe_load(source)
                steps = next(iter(workflow["jobs"].values()))["steps"]
                checkout = next(
                    step for step in steps if step.get("uses") == "actions/checkout@v6"
                )
                verification = next(
                    step for step in steps if verification_command in step.get("run", "")
                )
                mutation = next(
                    step for step in steps if mutation_command in step.get("run", "")
                )

                self.assertIs(checkout["with"]["persist-credentials"], False)
                self.assertIn(
                    "GIT_CONFIG_KEY_0=http.https://github.com/.extraheader",
                    mutation["run"],
                )
                self.assertIn(
                    'GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $git_authorization"',
                    mutation["run"],
                )
                self.assertEqual("${{ github.token }}", mutation["env"]["GITHUB_TOKEN"])
                if token_free_verifier:
                    self.assertNotIn("GITHUB_TOKEN", verification.get("env", {}))
                    self.assertNotIn("GH_TOKEN", verification.get("env", {}))

    def test_verifiers_accept_exact_tag_authority_for_the_planned_package_source(self) -> None:
        version = "0.1.95"
        commit = "4" * 40

        for module, _error_type in VERIFIERS:
            with self.subTest(module=module.__name__):
                calls: list[list[str]] = []

                def run(
                    command: list[str],
                    calls: list[list[str]] = calls,
                    **_kwargs: object,
                ) -> subprocess.CompletedProcess[str]:
                    calls.append(command)
                    if command[0] == "php":
                        return subprocess.CompletedProcess(
                            command,
                            0,
                            stdout=f"dw {version} (commit {commit[:12]}, built 2026-07-21)",
                            stderr="",
                        )
                    return subprocess.CompletedProcess(command, 0, stdout="verified", stderr="")

                with (
                    mock.patch.object(module.shutil, "which", return_value="/usr/bin/tool"),
                    mock.patch.object(module.subprocess, "run", side_effect=run),
                ):
                    evidence = verify_cli_release(
                        module, CliReleaseFixtureClient(version), version, commit
                    )

                attestations = [command for command in calls if command[0] == "gh"]
                self.assertEqual(len(CLI_ASSETS), len(attestations))
                for command in attestations:
                    self.assertEqual(commit, command[command.index("--source-digest") + 1])
                    self.assertEqual(
                        f"refs/tags/{version}", command[command.index("--source-ref") + 1]
                    )
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
                with self.subTest(
                    module=module.__name__, ref=accepted_ref, workflow=accepted_workflow
                ):
                    def run(
                        command: list[str],
                        accepted_ref: str = accepted_ref,
                        accepted_workflow: str = accepted_workflow,
                        **_kwargs: object,
                    ) -> subprocess.CompletedProcess[str]:
                        valid = (
                            "--signer-workflow" in command
                            and command[command.index("--source-ref") + 1] == accepted_ref
                            and command[command.index("--signer-workflow") + 1]
                            == accepted_workflow
                        )
                        return subprocess.CompletedProcess(
                            command, 0 if valid else 1, stdout="", stderr="untrusted authority"
                        )

                    with (
                        mock.patch.object(module.shutil, "which", return_value="/usr/bin/tool"),
                        mock.patch.object(module.subprocess, "run", side_effect=run),
                        self.assertRaisesRegex(error_type, "untrusted authority"),
                    ):
                        verify_cli_release(
                            module, CliReleaseFixtureClient(version), version, commit
                        )

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
                    verify_cli_release(
                        module, CliReleaseFixtureClient(version), version, commit
                    )

                self.assertEqual(2, exact_tag_attempts)
                self.assertFalse(any("--signer-workflow" in command for command in calls))

    def test_verifiers_reject_embedded_package_source_mismatch(self) -> None:
        version = "0.1.94"
        commit = "3" * 40

        for module, error_type in VERIFIERS:
            with self.subTest(module=module.__name__):
                def run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
                    if command[0] == "php":
                        return subprocess.CompletedProcess(
                            command,
                            0,
                            stdout=f"dw {version} (commit {'f' * 12}, built 2026-07-20)",
                            stderr="",
                        )
                    return subprocess.CompletedProcess(command, 0, stdout="verified", stderr="")

                with (
                    mock.patch.object(module.shutil, "which", return_value="/usr/bin/tool"),
                    mock.patch.object(module.subprocess, "run", side_effect=run),
                    self.assertRaisesRegex(error_type, "does not embed planned source commit"),
                ):
                    verify_cli_release(
                        module, CliReleaseFixtureClient(version), version, commit
                    )

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
                "embedded_phar_identity": (
                    f"dw {version} (commit {package_commit[:12]}, built 2026-07-20)"
                ),
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
                with self.assertRaisesRegex(
                    CandidateError, "untrusted build attestation authority"
                ):
                    require_distribution_identity(
                        untrusted_authority, "cli", version, package_commit
                    )


if __name__ == "__main__":
    unittest.main()
