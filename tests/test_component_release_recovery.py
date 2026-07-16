from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.component_release_recovery import (
    CLI_ASSETS,
    COMPONENTS,
    FOUNDATION_COMMIT,
    FOUNDATION_TAG,
    SCHEMA,
    RecoveryError,
    canonical_json,
    main,
    select_publication_run,
    validate_plan,
    verify_cli,
    verify_recovery_workflow_source,
)


def plan(channel: str = "alpha") -> dict[str, object]:
    prerelease = "alpha" if channel == "alpha" else "beta"
    return {
        "schema": SCHEMA,
        "plan": "component-recovery",
        "channel": channel,
        "foundation": {"tag": FOUNDATION_TAG, "commit": FOUNDATION_COMMIT},
        "components": {
            name: {
                "version": f"2.0.0-{prerelease}.{index + 1}" if name in {"workflow", "waterline"} else f"1.0.{index}",
                "commit": f"{index + 1:040x}",
            }
            for index, name in enumerate(COMPONENTS)
        },
        "beta_authorization": (
            {"tag": "beta-authorization/component-recovery", "commit": "f" * 40} if channel == "beta" else None
        ),
    }


class ComponentRecoveryContractTest(unittest.TestCase):
    def test_dependency_progression_is_public_and_acyclic(self) -> None:
        self.assertEqual((), COMPONENTS["workflow"].dependencies)
        self.assertEqual((), COMPONENTS["sdk-php"].dependencies)
        self.assertEqual(("workflow", "sdk-php"), COMPONENTS["waterline"].dependencies)
        self.assertEqual(("workflow",), COMPONENTS["server"].dependencies)
        self.assertEqual(("server",), COMPONENTS["cli"].dependencies)
        self.assertEqual(("server",), COMPONENTS["sdk-python"].dependencies)
        self.assertEqual(("server",), COMPONENTS["sdk-rust"].dependencies)

    def test_expected_default_branches_are_explicit(self) -> None:
        self.assertEqual("v2", COMPONENTS["workflow"].default_branch)
        self.assertEqual("v2", COMPONENTS["waterline"].default_branch)
        for name in {"server", "cli", "sdk-php", "sdk-python", "sdk-rust"}:
            self.assertEqual("main", COMPONENTS[name].default_branch)

    def test_alpha_and_beta_plans_validate_independently(self) -> None:
        validate_plan(plan("alpha"))
        validate_plan(plan("beta"))

    def test_beta_plan_rejects_alpha_workflow_version(self) -> None:
        candidate = plan("beta")
        candidate["components"]["workflow"]["version"] = "2.0.0-alpha.8"
        with self.assertRaisesRegex(RecoveryError, "2.0.0-beta.N"):
            validate_plan(candidate)

    def test_publication_workflows_dispatch_in_the_declared_tag_context(self) -> None:
        dispatching = {
            "server": ("release.yml", "tag"),
            "cli": ("release.yml", "tag"),
            "sdk-python": ("publish.yml", "release_tag"),
            "sdk-rust": ("release.yml", "release_tag"),
        }
        self.assertEqual(dispatching, {
            name: (component.release_workflow, component.release_tag_input)
            for name, component in COMPONENTS.items()
            if component.release_workflow is not None
        })
        for name, (workflow, tag_input) in dispatching.items():
            with self.subTest(component=name):
                source = f'''on:
  schedule:
  workflow_dispatch:
jobs:
  recover:
    steps:
      - name: Create the exact source tag
        run: |
          gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs" \\
            -f ref="refs/tags/$RELEASE_TAG" -f sha="$RELEASE_COMMIT"
      - name: Start repository-owned publication
        run: |
          gh run list --workflow {workflow} \\
            --json databaseId,displayTitle,headBranch,headSha,status,conclusion
          python scripts/ci/component-release-recovery.py select-publication-run \\
            --release-tag "$RELEASE_TAG" --release-commit "$RELEASE_COMMIT"
          gh workflow run {workflow} --ref "$RELEASE_TAG" \\
            -f {tag_input}="$RELEASE_TAG" -f release_plan="$PLAN_TAG"
'''
                verify_recovery_workflow_source(name, source)
                with self.assertRaisesRegex(RecoveryError, "exact tag context"):
                    verify_recovery_workflow_source(
                        name,
                        source.replace('"$RELEASE_TAG" \\\n', '"$DEFAULT_BRANCH" \\\n', 1),
                    )
                with self.assertRaisesRegex(RecoveryError, "release tag input"):
                    verify_recovery_workflow_source(
                        name,
                        source.replace(f'-f {tag_input}="$RELEASE_TAG"', f'-f {tag_input}="$DEFAULT_BRANCH"'),
                    )

    def test_publication_run_selection_adopts_tag_triggered_runs(self) -> None:
        release_tag = "1.2.3"
        release_commit = "a" * 40

        def run(status: str, conclusion: str | None, run_id: int = 17) -> dict[str, object]:
            return {
                "databaseId": run_id,
                "displayTitle": f"Release {release_tag} for direct",
                "headBranch": release_tag,
                "headSha": release_commit,
                "status": status,
                "conclusion": conclusion,
            }

        cases = (
            ("queued", None, "wait"),
            ("in_progress", None, "wait"),
            ("completed", "failure", "rerun"),
            ("completed", "success", "complete"),
        )
        for status, conclusion, action in cases:
            with self.subTest(status=status, conclusion=conclusion):
                self.assertEqual(
                    {"action": action, "run_id": 17, "status": status, "conclusion": conclusion},
                    select_publication_run(release_tag, release_commit, [run(status, conclusion)]),
                )
        self.assertEqual(
            {"action": "dispatch", "run_id": None, "status": None, "conclusion": None},
            select_publication_run(release_tag, release_commit, []),
        )
        with self.assertRaisesRegex(RecoveryError, "different source commit"):
            select_publication_run(
                release_tag,
                release_commit,
                [{**run("queued", None), "headSha": "b" * 40}],
            )

    def test_cli_release_rejects_assets_attested_for_the_wrong_source(self) -> None:
        attested_commit = "a" * 40
        declared_commit = "b" * 40
        version = "1.2.3"
        attested_ref = "refs/tags/1.2.2"

        class FixtureClient:
            contents = {name: f"fixture {name}\n".encode() for name in CLI_ASSETS - {"SHA256SUMS"}}
            checksums = "".join(
                f"{hashlib.sha256(content).hexdigest()}  {name}\n" for name, content in sorted(contents.items())
            ).encode()

            def __init__(self) -> None:
                self.downloaded: set[str] = set()

            def json(self, _url: str) -> dict[str, object]:
                return {
                    "id": 123,
                    "tag_name": version,
                    "draft": False,
                    "html_url": f"https://github.com/durable-workflow/cli/releases/tag/{version}",
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
                name = url.rsplit("/", 1)[-1]
                content = self.contents[name]
                if expected_sha256 != hashlib.sha256(content).hexdigest():
                    raise AssertionError("fixture download checksum mismatch")
                path.write_bytes(content)
                self.downloaded.add(name)
                return {"url": url, "size": len(content), "sha256": expected_sha256}

        def verify_attestation(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            self.assertEqual("durable-workflow/cli", command[command.index("--repo") + 1])
            source_digest = command[command.index("--source-digest") + 1]
            source_ref = command[command.index("--source-ref") + 1]
            valid = source_digest == attested_commit and source_ref == attested_ref
            return subprocess.CompletedProcess(
                command,
                0 if valid else 1,
                stdout="",
                stderr="attestation source does not match the declared release",
            )

        client = FixtureClient()
        shutil_module = mock.Mock()
        shutil_module.which.return_value = "/usr/bin/gh"
        subprocess_module = mock.Mock()
        subprocess_module.run.side_effect = verify_attestation
        with (
            mock.patch("scripts.component_release_recovery.shutil", shutil_module, create=True),
            mock.patch("scripts.component_release_recovery.subprocess", subprocess_module, create=True),
            self.assertRaisesRegex(RecoveryError, "build attestation failed"),
        ):
            verify_cli(client, COMPONENTS["cli"], version, declared_commit)
        self.assertEqual(CLI_ASSETS - {"SHA256SUMS"}, client.downloaded)

    def test_post_discovery_failures_retain_explicit_and_scheduled_plan_identity(self) -> None:
        candidate = plan()
        plan_tag = "release-plan/plan-a"
        record_commit = "d" * 40

        for requested_tag in (plan_tag, None):
            with self.subTest(requested_tag=requested_tag), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                plan_output = root / "release-plan.json"
                evidence_output = root / "release-recovery-evidence.json"
                arguments = [
                    "component_release_recovery.py",
                    "resolve",
                    "--component",
                    "server",
                    "--plan-output",
                    str(plan_output),
                    "--evidence",
                    str(evidence_output),
                ]
                if requested_tag is not None:
                    arguments.extend(("--plan-tag", requested_tag))
                else:
                    arguments.append("--allow-empty")

                with (
                    mock.patch.object(sys, "argv", arguments),
                    mock.patch(
                        "scripts.component_release_recovery.discover_plan",
                        return_value=(plan_tag, record_commit, candidate),
                    ) as discover,
                    mock.patch(
                        "scripts.component_release_recovery.resolve_component",
                        side_effect=RecoveryError("post-discovery failure", "tag-preflight"),
                    ),
                ):
                    self.assertEqual(1, main())

                discover.assert_called_once_with(mock.ANY, requested_tag)
                self.assertEqual(canonical_json(candidate), plan_output.read_bytes())
                evidence = json.loads(evidence_output.read_bytes())
                self.assertEqual(plan_tag, evidence["release_plan_tag"])
                self.assertEqual(candidate["plan"], evidence["plan"])
                self.assertEqual(candidate["channel"], evidence["channel"])
                self.assertEqual(record_commit, evidence["plan_record_commit"])
                self.assertEqual(plan_tag, evidence["durable_evidence"]["release_plan"])
                self.assertTrue(evidence["resume_action"].endswith(f" for {plan_tag}"))


if __name__ == "__main__":
    unittest.main()
