from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from scripts.component_release_recovery import (
    CLI_ASSETS,
    COMPONENTS,
    FOUNDATION_COMMIT,
    FOUNDATION_TAG,
    PREPARATION_SCHEMA,
    SCHEMA,
    NotFound,
    PublicClient,
    PublicInfrastructureError,
    RecoveryError,
    canonical_json,
    discover_plan,
    main,
    manifest_digest,
    resolve_component,
    select_publication_run,
    validate_plan,
    validate_release_preparation,
    verify_cli,
    verify_recovery_workflow_source,
)


def github_http_error(status: int, body: bytes = b"error", **headers: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://api.github.com/repos/durable-workflow/.github/releases",
        status,
        "request failed",
        headers,
        io.BytesIO(body),
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


def preparation(candidate: dict[str, object]) -> dict[str, object]:
    release_date = "2026-07-19"
    components: dict[str, object] = {}
    for name, identity in candidate["components"].items():
        heading = f"## [{identity['version']}] - {release_date}"
        markdown = f"{heading}\n\nPrepared source changes.\n"
        repository = COMPONENTS[name].repository
        changelog = name in {"workflow", "waterline", "sdk-php", "sdk-python"}
        components[name] = {
            "version": identity["version"],
            "source_commit": identity["commit"],
            "release_notes": {
                "format": "text/markdown",
                "heading": heading,
                "markdown": markdown,
                "release_date": release_date,
                "sha256": hashlib.sha256(markdown.encode()).hexdigest(),
                "source": {
                    "kind": "changelog-unreleased" if changelog else "source-commit-message",
                    "sha256": "a" * 64,
                    "url": (
                        f"https://github.com/{repository}/blob/{identity['commit']}/CHANGELOG.md"
                        if changelog
                        else f"https://github.com/{repository}/commit/{identity['commit']}"
                    ),
                },
            },
        }
    return {
        "schema": PREPARATION_SCHEMA,
        "release_plan": {
            "tag": f"release-plan/{candidate['plan']}",
            "sha256": manifest_digest(candidate),
        },
        "components": components,
    }


class ComponentRecoveryContractTest(unittest.TestCase):
    def test_recovery_public_client_retries_transient_github_reads(self) -> None:
        sleeps: list[float] = []
        client = PublicClient(max_attempts=3, retry_base_seconds=1, sleep=sleeps.append)
        responses = [
            github_http_error(503, **{"Retry-After": "4"}),
            urllib.error.URLError(ConnectionResetError("connection reset")),
            io.BytesIO(b"[]"),
        ]

        with mock.patch(
            "scripts.component_release_recovery.urllib.request.urlopen",
            side_effect=responses,
        ) as open_url:
            result = client.json("https://api.github.com/repos/durable-workflow/.github/releases?per_page=100")

        self.assertEqual([], result)
        self.assertEqual([4, 2], sleeps)
        self.assertEqual(3, open_url.call_count)

    def test_recovery_public_client_never_retries_authentication_with_rate_limit_guidance(self) -> None:
        sleeps: list[float] = []
        client = PublicClient(max_attempts=3, retry_base_seconds=1, sleep=sleeps.append)
        error = github_http_error(
            401,
            b"Bad credentials: API rate limit exceeded",
            **{"Retry-After": "20", "X-RateLimit-Remaining": "0"},
        )

        with (
            mock.patch(
                "scripts.component_release_recovery.urllib.request.urlopen",
                side_effect=error,
            ) as open_url,
            self.assertRaisesRegex(RecoveryError, r"public request failed \(401\)"),
        ):
            client.json("https://api.github.com/repos/durable-workflow/.github/releases?per_page=100")

        self.assertEqual([], sleeps)
        self.assertEqual(1, open_url.call_count)

    def test_recovery_public_client_separates_exhausted_infrastructure_from_missing_resources(self) -> None:
        client = PublicClient(max_attempts=2, retry_base_seconds=1, sleep=lambda _delay: None)
        with (
            mock.patch(
                "scripts.component_release_recovery.urllib.request.urlopen",
                side_effect=[github_http_error(503), github_http_error(502)],
            ) as open_url,
            self.assertRaisesRegex(
                PublicInfrastructureError,
                r"endpoint_class=releases-api, attempts=2, reason=retry-exhausted, status=502",
            ),
        ):
            client.json("https://api.github.com/repos/durable-workflow/.github/releases?per_page=100")
        self.assertEqual(2, open_url.call_count)

        with (
            mock.patch(
                "scripts.component_release_recovery.urllib.request.urlopen",
                side_effect=github_http_error(404),
            ) as open_url,
            self.assertRaisesRegex(NotFound, "public resource is absent"),
        ):
            client.json("https://api.github.com/repos/durable-workflow/.github/releases/tags/missing")
        self.assertEqual(1, open_url.call_count)

    def test_discovery_rejects_missing_preparation_for_an_incomplete_release(self) -> None:
        candidate = plan()
        tag = f"release-plan/{candidate['plan']}"
        record_commit = "a" * 40
        client = mock.Mock()
        client.json.return_value = {
            "tag_name": tag,
            "draft": False,
            "assets": [
                {
                    "name": "release-plan.json",
                    "browser_download_url": "https://example.invalid/release-plan.json",
                }
            ],
        }
        client.bytes.return_value = canonical_json(candidate)

        with (
            mock.patch("scripts.component_release_recovery.resolve_tag", return_value=record_commit),
            mock.patch(
                "scripts.component_release_recovery.read_record",
                side_effect=[candidate, NotFound("missing preparation", "plan-discovery")],
            ),
            mock.patch(
                "scripts.component_release_recovery.verify_component",
                side_effect=NotFound("release is incomplete"),
            ),
            self.assertRaisesRegex(RecoveryError, "only completed legacy releases"),
        ):
            discover_plan(client, tag, "workflow")

    def test_resolution_rejects_missing_preparation_before_publish(self) -> None:
        candidate = plan()
        with (
            mock.patch("scripts.component_release_recovery.verify_plan_authority", return_value=({}, {})),
            mock.patch("scripts.component_release_recovery.resolve_tag", return_value=None),
            self.assertRaisesRegex(RecoveryError, "release preparation required before publishing workflow"),
        ):
            resolve_component(
                mock.Mock(),
                "workflow",
                f"release-plan/{candidate['plan']}",
                "a" * 40,
                candidate,
                None,
            )

    def test_completed_legacy_release_is_the_only_missing_preparation_exception(self) -> None:
        candidate = plan()
        identity = candidate["components"]["workflow"]
        public_evidence = {"version": identity["version"], "commit": identity["commit"]}
        with (
            mock.patch("scripts.component_release_recovery.verify_plan_authority", return_value=({}, {})),
            mock.patch("scripts.component_release_recovery.resolve_tag", return_value=identity["commit"]),
            mock.patch("scripts.component_release_recovery.verify_component", return_value=public_evidence),
        ):
            state, outputs = resolve_component(
                mock.Mock(),
                "workflow",
                f"release-plan/{candidate['plan']}",
                "a" * 40,
                candidate,
                None,
            )

        self.assertEqual("skip", outputs["action"])
        self.assertEqual("complete", state["phase"])
        self.assertEqual(public_evidence, state["public_evidence"])
        self.assertNotIn("release_preparation", state)

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
        for channel in ("alpha", "beta"):
            candidate = plan(channel)
            validate_plan(candidate)
            validate_release_preparation(preparation(candidate), candidate)

    def test_preparation_rejects_notes_for_another_version(self) -> None:
        candidate = plan()
        prepared = preparation(candidate)
        prepared["components"]["server"]["version"] = "9.9.9"
        with self.assertRaisesRegex(RecoveryError, "different planned identity"):
            validate_release_preparation(prepared, candidate)

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
      - run: python recovery.py resolve --preparation-output release-preparation.json
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
                preparation_output = root / "release-preparation.json"
                evidence_output = root / "release-recovery-evidence.json"
                arguments = [
                    "component_release_recovery.py",
                    "resolve",
                    "--component",
                    "server",
                    "--plan-output",
                    str(plan_output),
                    "--preparation-output",
                    str(preparation_output),
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
                        return_value=(plan_tag, record_commit, candidate, preparation(candidate)),
                    ) as discover,
                    mock.patch(
                        "scripts.component_release_recovery.resolve_component",
                        side_effect=RecoveryError("post-discovery failure", "tag-preflight"),
                    ),
                ):
                    self.assertEqual(1, main())

                discover.assert_called_once_with(mock.ANY, requested_tag, "server")
                self.assertEqual(canonical_json(candidate), plan_output.read_bytes())
                self.assertEqual(
                    canonical_json(preparation(candidate)),
                    preparation_output.read_bytes(),
                )
                evidence = json.loads(evidence_output.read_bytes())
                self.assertEqual(plan_tag, evidence["release_plan_tag"])
                self.assertEqual(candidate["plan"], evidence["plan"])
                self.assertEqual(candidate["channel"], evidence["channel"])
                self.assertEqual(record_commit, evidence["plan_record_commit"])
                self.assertEqual(plan_tag, evidence["durable_evidence"]["release_plan"])
                self.assertTrue(evidence["resume_action"].endswith(f" for {plan_tag}"))


if __name__ == "__main__":
    unittest.main()
