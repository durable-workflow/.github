from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import re
import subprocess
import tempfile
import textwrap
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
    scan_workflow_sources,
    validate_policy,
    verify_workflow_source,
)

ROOT = Path(__file__).resolve().parents[1]
CHECKOUT_PIN = "d23441a48e516b6c34aea4fa41551a30e30af803"


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
        if re.match(r"/repos/[^/]+/[^/]+/commits/[0-9a-f]{40}$", path):
            return {"sha": path.rsplit("/", 1)[1]}
        repository = self._repository(path)
        target = self.targets_by_repository[repository]
        if path == f"/repos/durable-workflow/{repository}":
            return {"default_branch": target["branch"]}
        if "/contents/.github/workflows?" in path:
            paths = {f".github/workflows/{workflow['path']}" for workflow in target["workflows"]}
            paths.add(".github/workflows/release.yml")
            if repository == ".github":
                paths.add(".github/workflows/beta-conformance-retention.yml")
                paths.add(".github/workflows/beta-continuity-resolution.yml")
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
        if re.match(r"/repos/[^/]+/[^/]+/contents/action\.ya?ml\?", path):
            return b"name: checkout\nruns:\n  using: node24\n  main: dist/index.js\n"
        if "/contents/.github/workflows/beta-continuity-resolution.yml?" in path:
            return (
                ROOT / ".github" / "workflows" / "beta-continuity-resolution.yml"
            ).read_bytes()
        if "/contents/.github/workflows/beta-conformance-retention.yml?" in path:
            return f"""name: Beta conformance retention
on:
  workflow_run:
    workflows: [Beta conformance]
    types: [completed]
permissions:
  contents: read
jobs:
  bind:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
    outputs:
      source_run_id: ${{{{ github.event.workflow_run.id }}}}
      source_run_attempt: ${{{{ github.event.workflow_run.run_attempt }}}}
    steps:
      - uses: actions/checkout@{CHECKOUT_PIN} # v6
        with:
          persist-credentials: false
      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6
        with:
          python-version: "3.13"
      - env:
          GH_TOKEN: ${{{{ github.token }}}}
          REQUESTED_RUN_ID: ${{{{ inputs.source_run_id || github.event.workflow_run.id }}}}
          REQUESTED_RUN_ATTEMPT: ${{{{ inputs.source_run_attempt || github.event.workflow_run.run_attempt }}}}
        run: |
          python scripts/beta_conformance.py retention-source \\
            --expected-run-id "$REQUESTED_RUN_ID" \\
            --expected-run-attempt "$REQUESTED_RUN_ATTEMPT" \\
            --github-output "$GITHUB_OUTPUT"
  retain:
    needs: bind
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    environment: beta-conformance
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@{CHECKOUT_PIN} # v6
        with:
          persist-credentials: false
      - uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6
        with:
          python-version: "3.13"
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8
        with:
          name: beta-conformance-plan-${{{{ needs.bind.outputs.source_run_id }}}}
          path: aggregate-input
          github-token: ${{{{ github.token }}}}
          run-id: ${{{{ needs.bind.outputs.source_run_id }}}}
          digest-mismatch: error
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8
        with:
          pattern: >-
            beta-conformance-*-${{{{ needs.bind.outputs.source_run_id }}}}-${{{{
            needs.bind.outputs.source_run_attempt }}}}
          path: evidence
          github-token: ${{{{ github.token }}}}
          run-id: ${{{{ needs.bind.outputs.source_run_id }}}}
          digest-mismatch: error
      - run: |
          python scripts/beta_conformance.py aggregate \\
            aggregate-input/execution-plan.json \\
            evidence \\
            suite-result.json \\
            release-assets \\
            --contract beta-conformance/contract.json \\
            --run-id "${{{{ needs.bind.outputs.source_run_id }}}}" \\
            --run-attempt "${{{{ needs.bind.outputs.source_run_attempt }}}}" \\
            --generated-at "${{{{ needs.bind.outputs.source_completed_at }}}}" \\
            --source-candidate "${{{{ needs.bind.outputs.source_candidate }}}}" \\
            --source-head-sha "${{{{ needs.bind.outputs.source_head_sha }}}}" \\
            --github-output "$GITHUB_OUTPUT"
""".encode()
        repository = self._repository(path)
        branch = self.targets_by_repository[repository]["branch"]
        return f"""name: qualification
on:
  push:
    branches: [{branch}]
  pull_request:
    branches: [{branch}]
  workflow_dispatch:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 10
    strategy:
      fail-fast: false
    steps:
      - uses: actions/checkout@{CHECKOUT_PIN} # v6
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
    @staticmethod
    def trusted_pull_request_source() -> str:
        return f"""name: trust fixture
on:
  pull_request:
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{CHECKOUT_PIN} # v6
      - uses: actions/cache@caa296126883cff596d87d8935842f9db880ef25 # v5
        with:
          path: vendor
          key: ${{{{ github.event_name }}}}-dependencies
          restore-keys: ${{{{ github.event_name }}}}-
"""

    @staticmethod
    def trusted_privileged_artifact_source() -> str:
        validator = textwrap.indent(
            policy_fixture()["workflow_trust"]["privileged_artifact_handoffs"]["validator_command"].rstrip(),
            "          ",
        )
        return f"""name: trusted publication
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  package:
    runs-on: ubuntu-latest
    outputs:
      artifact_id: ${{{{ steps.release.outputs.artifact-id }}}}
      artifact_digest: ${{{{ steps.release.outputs.artifact-digest }}}}
      source_run_id: ${{{{ github.run_id }}}}
      source_run_attempt: ${{{{ github.run_attempt }}}}
    steps:
      - id: release
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7
        with:
          archive: false
          if-no-files-found: error
          path: release.tar
  publish:
    needs: package
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@{CHECKOUT_PIN} # v6
        with:
          fetch-depth: 0
          persist-credentials: false
          ref: ${{{{ github.sha }}}}
      - uses: actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8
        with:
          artifact-ids: ${{{{ needs.package.outputs.artifact_id }}}}
          digest-mismatch: error
          github-token: ${{{{ github.token }}}}
          path: isolated-release
          repository: ${{{{ github.repository }}}}
          run-id: ${{{{ needs.package.outputs.source_run_id }}}}
      - name: Validate the exact producer artifact before use
        env:
          ARTIFACT_DIRECTORY: isolated-release
          EXPECTED_ARTIFACT_DIGEST: ${{{{ needs.package.outputs.artifact_digest }}}}
          EXPECTED_ARTIFACT_ID: ${{{{ needs.package.outputs.artifact_id }}}}
          EXPECTED_SOURCE_RUN_ATTEMPT: ${{{{ needs.package.outputs.source_run_attempt }}}}
          EXPECTED_SOURCE_RUN_ID: ${{{{ needs.package.outputs.source_run_id }}}}
        run: |
{validator}
"""

    def test_workflow_trust_accepts_partitioned_unprivileged_pull_requests(self) -> None:
        evidence = scan_workflow_sources(
            policy_fixture(),
            "cli",
            {".github/workflows/fixture.yml": self.trusted_pull_request_source()},
        )
        self.assertEqual([], evidence[".github/workflows/fixture.yml"]["privileged_jobs"])

    def test_workflow_trust_rejects_mutable_actions_and_missing_version_comments(self) -> None:
        source = self.trusted_pull_request_source()
        cases = {
            "mutable": (
                source.replace(f"@{CHECKOUT_PIN} # v6", "@v6 # v6"),
                "not pinned to a full commit SHA",
            ),
            "unlabeled": (source.replace(" # v6", "", 1), "readable version comment"),
        }
        for name, (candidate, message) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(PolicyError, message):
                scan_workflow_sources(policy_fixture(), "cli", {"fixture.yml": candidate})

    def test_workflow_trust_distinguishes_local_actions_and_pins_container_actions(self) -> None:
        source = self.trusted_pull_request_source().replace(
            f"- uses: actions/checkout@{CHECKOUT_PIN} # v6",
            "- uses: ./actions/verify # local",
        )
        evidence = scan_workflow_sources(policy_fixture(), "cli", {"fixture.yml": source})
        self.assertEqual(["./actions/verify"], evidence["fixture.yml"]["local_actions"])

        with self.assertRaisesRegex(PolicyError, "readable version comment"):
            scan_workflow_sources(
                policy_fixture(),
                "cli",
                {"fixture.yml": source.replace(" # local", "")},
            )

        mutable_container = source.replace(
            "- uses: ./actions/verify # local",
            "- uses: docker://lycheeverse/lychee:0.24.2 # 0.24.2",
        )
        with self.assertRaisesRegex(PolicyError, "immutable sha256 digest"):
            scan_workflow_sources(policy_fixture(), "cli", {"fixture.yml": mutable_container})

    def test_workflow_trust_rejects_top_level_write_and_pull_request_target(self) -> None:
        source = self.trusted_pull_request_source()
        cases = {
            "top-write": (source.replace("contents: read", "contents: write", 1), "top-level write"),
            "target-event": (
                source.replace("pull_request:", "pull_request_target:"),
                "forbidden pull_request_target",
            ),
        }
        for name, (candidate, message) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(PolicyError, message):
                scan_workflow_sources(policy_fixture(), "cli", {"fixture.yml": candidate})

    def test_workflow_trust_rejects_pull_request_credentials_and_shared_caches(self) -> None:
        source = self.trusted_pull_request_source()
        cases = {
            "environment": (
                source.replace("runs-on: ubuntu-latest", "runs-on: ubuntu-latest\n    environment: release\n"),
                "requests an environment",
            ),
            "secret": (
                source.replace(
                    "runs-on: ubuntu-latest",
                    "runs-on: ubuntu-latest\n    env:\n      TOKEN: ${{ secrets['RELEASE_TOKEN'] }}",
                ),
                "references a secret",
            ),
            "shared-cache": (
                source.replace("${{ github.event_name }}-dependencies", "shared-dependencies"),
                "must partition trusted and untrusted events",
            ),
            "constant-boolean-cache-key": (
                source.replace(
                    "${{ github.event_name }}-dependencies",
                    "shared-${{ github.event_name != '' }}",
                ),
                "must partition trusted and untrusted events",
            ),
            "constant-boolean-cache-restore": (
                source.replace(
                    "${{ github.event_name }}-",
                    "shared-${{ github.event_name != '' }}",
                ),
                "must partition trusted and untrusted events",
            ),
            "partially-shared-cache-restore": (
                source.replace(
                    "restore-keys: ${{ github.event_name }}-",
                    "restore-keys: |\n            ${{ github.event_name }}-\n            shared-",
                ),
                "must partition trusted and untrusted events",
            ),
            "workspace-root-cache": (
                source.replace("path: vendor", "path: /"),
                "unsafe cache path",
            ),
        }
        for name, (candidate, message) in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(PolicyError, message):
                scan_workflow_sources(policy_fixture(), "cli", {"fixture.yml": candidate})

    def test_workflow_trust_rejects_whole_workspace_and_home_cache_aliases(self) -> None:
        source = self.trusted_pull_request_source()
        unsafe_paths = (
            "${{ github.workspace }}",
            "${{ github.workspace }}/**",
            "${{ env.GITHUB_WORKSPACE }}",
            "$GITHUB_WORKSPACE",
            "${GITHUB_WORKSPACE}",
            "${{ env.HOME }}",
            "$HOME",
            "${HOME}",
            "**",
            "~/**",
            "$HOME/**",
        )
        for path in unsafe_paths:
            with self.subTest(path=path), self.assertRaisesRegex(PolicyError, "unsafe cache path"):
                scan_workflow_sources(
                    policy_fixture(),
                    "cli",
                    {"fixture.yml": source.replace("path: vendor", f"path: '{path}'")},
                )

        narrow = source.replace(
            "path: vendor",
            "path: |\n            vendor\n            $HOME/.cache/composer\n            ~/.cache/pip",
        )
        scan_workflow_sources(policy_fixture(), "cli", {"fixture.yml": narrow})

    def test_privileged_manual_dispatch_requires_a_protected_ref(self) -> None:
        source = self.trusted_privileged_artifact_source()
        cases = {
            "missing": source.replace("    if: github.ref == 'refs/heads/main'\n", ""),
            "wrong ref": source.replace("refs/heads/main", "refs/heads/topic"),
            "bypass": source.replace(
                "github.ref == 'refs/heads/main'",
                "github.ref == 'refs/heads/main' || inputs.force",
            ),
        }
        for name, candidate in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(PolicyError, "outside refs/heads/main"):
                scan_workflow_sources(policy_fixture(), "cli", {"unsafe.yml": candidate})

        tag_or_dispatch = source.replace(
            "github.ref == 'refs/heads/main'",
            "(github.event_name == 'push' && startsWith(github.ref, 'refs/tags/')) || "
            "(github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main')",
        )
        scan_workflow_sources(policy_fixture(), "cli", {"trusted.yml": tag_or_dispatch})

    def test_reusable_workflow_credentials_require_a_protected_dispatch_ref(self) -> None:
        local_call = "uses: ./.github/workflows/release.yml # local"
        external_call = (
            "uses: actions/checkout/.github/workflows/release.yml@"
            f"{CHECKOUT_PIN} # v6"
        )

        def reusable_call(uses: str, secrets: str = "", condition: str = "") -> str:
            return f"""name: reusable workflow caller
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  release:
    {uses}
{condition}{secrets}"""

        unguarded = {
            "local inherit": reusable_call(local_call, "    secrets: inherit\n"),
            "external inherit": reusable_call(external_call, "    secrets: inherit\n"),
            "explicit map": reusable_call(
                external_call,
                "    secrets:\n      package-token: ${{ github.token }}\n",
            ),
            "empty map": reusable_call(local_call, "    secrets: {}\n"),
        }
        for name, source in unguarded.items():
            with self.subTest(name=name), self.assertRaisesRegex(PolicyError, "outside refs/heads/main"):
                scan_workflow_sources(policy_fixture(), "cli", {"unsafe.yml": source})

        protected = reusable_call(
            local_call,
            "    secrets: inherit\n",
            "    if: github.ref == 'refs/heads/main'\n",
        )
        protected_evidence = scan_workflow_sources(policy_fixture(), "cli", {"protected.yml": protected})
        self.assertEqual(["release"], protected_evidence["protected.yml"]["privileged_jobs"])

        credential_free = reusable_call(local_call)
        credential_free_evidence = scan_workflow_sources(
            policy_fixture(),
            "cli",
            {"credential-free.yml": credential_free},
        )
        self.assertEqual([], credential_free_evidence["credential-free.yml"]["privileged_jobs"])

    def test_pull_request_reusable_workflows_cannot_receive_credentials(self) -> None:
        source = """name: untrusted reusable workflow caller
on:
  pull_request:
permissions:
  contents: read
jobs:
  release:
    uses: ./.github/workflows/release.yml # local
"""
        declarations = {
            "inherit": "    secrets: inherit\n",
            "explicit map": "    secrets:\n      package-token: ${{ github.token }}\n",
        }
        for name, declaration in declarations.items():
            with self.subTest(name=name), self.assertRaisesRegex(PolicyError, "references a secret"):
                scan_workflow_sources(policy_fixture(), "cli", {"unsafe.yml": source + declaration})

    def test_protected_ref_guard_covers_recovery_and_docs_deployment_shapes(self) -> None:
        fixtures = {
            "server": f"""name: server recovery
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  recover:
    runs-on: ubuntu-latest
    permissions:
      actions: write
      contents: write
    steps:
      - uses: actions/checkout@{CHECKOUT_PIN} # v6
""",
            "documentation": """name: docs deployment
on:
  workflow_dispatch:
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: github-pages
    permissions:
      contents: read
      id-token: write
      pages: write
    steps: []
""",
        }
        for target, source in fixtures.items():
            with self.subTest(target=target), self.assertRaisesRegex(PolicyError, "outside refs/heads/main"):
                scan_workflow_sources(policy_fixture(), target, {"fixture.yml": source})
            guarded = source.replace("    runs-on:", "    if: github.ref == 'refs/heads/main'\n    runs-on:")
            scan_workflow_sources(policy_fixture(), target, {"fixture.yml": guarded})

    def test_workflow_trust_rejects_unreviewed_workflow_run_consumers(self) -> None:
        source = f"""name: unsafe retention
on:
  workflow_run:
    workflows: [Build]
    types: [completed]
permissions:
  contents: read
jobs:
  retain:
    runs-on: ubuntu-latest
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@{CHECKOUT_PIN} # v6
"""
        with self.assertRaisesRegex(PolicyError, "no reviewed privileged workflow_run trust binding"):
            scan_workflow_sources(policy_fixture(), "cli", {"unsafe.yml": source})

    def test_workflow_trust_binds_privileged_artifacts_to_their_upload_producer(self) -> None:
        source = self.trusted_privileged_artifact_source()
        evidence = scan_workflow_sources(policy_fixture(), "cli", {"trusted.yml": source})
        self.assertEqual(["publish"], evidence["trusted.yml"]["privileged_jobs"])

        cases = {
            "unrelated dependency": source.replace("needs: package", "needs: unrelated"),
            "matching name without digest": source.replace(
                "          artifact-ids: ${{ needs.package.outputs.artifact_id }}\n",
                "          name: release.tar\n",
            ),
            "wrong digest": source.replace(
                "artifact_digest: ${{ steps.release.outputs.artifact-digest }}",
                "artifact_digest: ${{ steps.release.outputs.artifact-id }}",
            ),
            "digest check after first consumer": source.replace(
                "      - name: Validate the exact producer artifact before use\n",
                "      - run: tar -xf isolated-release/release.tar\n"
                "      - name: Validate the exact producer artifact before use\n",
            ),
        }
        for name, candidate in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                PolicyError,
                "exact producer, immutable artifact identity, and pre-use digest validation",
            ):
                scan_workflow_sources(policy_fixture(), "cli", {"unsafe.yml": candidate})

    def test_privileged_artifact_validation_rejects_execution_overrides(self) -> None:
        source = self.trusted_privileged_artifact_source()
        cases = {
            "download can ignore digest mismatch": source.replace("digest-mismatch: error", "digest-mismatch: warn"),
            "download changes repository": source.replace(
                "repository: ${{ github.repository }}", "repository: attacker/fork"
            ),
            "validator can be skipped": source.replace(
                "      - name: Validate the exact producer artifact before use\n",
                "      - name: Validate the exact producer artifact before use\n        if: ${{ false }}\n",
            ),
            "validator custom shell": source.replace(
                "        run: |\n          set -euo pipefail",
                "        shell: true {0}\n        run: |\n          set -euo pipefail",
            ),
            "job container": source.replace(
                "  publish:\n", "  publish:\n    container: python:3.13\n"
            ),
            "job service": source.replace(
                "  publish:\n", "  publish:\n    services:\n      writer:\n        image: alpine:3.20\n"
            ),
            "download path override": source.replace("path: isolated-release", "path: scripts"),
            "checkout persists credentials": source.replace("persist-credentials: false", "persist-credentials: true"),
            "checkout selects a different ref": source.replace(
                "ref: ${{ github.sha }}", "ref: ${{ inputs.unreviewed_ref }}"
            ),
            "predecessor run shadows tools": source.replace(
                "      - uses: actions/download-artifact@",
                "      - run: echo '/tmp/shadow' >> \"$GITHUB_PATH\"\n"
                "      - uses: actions/download-artifact@",
            ),
            "extra predecessor action": source.replace(
                "      - uses: actions/download-artifact@",
                f"      - uses: actions/checkout@{CHECKOUT_PIN} # v6\n"
                "        with:\n"
                "          fetch-depth: 0\n"
                "          persist-credentials: false\n"
                "          ref: ${{ github.sha }}\n"
                "      - uses: actions/download-artifact@",
            ),
            "download can be skipped": source.replace(
                "      - uses: actions/download-artifact@",
                "      - if: ${{ false }}\n        uses: actions/download-artifact@",
            ),
        }
        for name, candidate in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                PolicyError,
                "exact producer, immutable artifact identity, and pre-use digest validation",
            ):
                scan_workflow_sources(policy_fixture(), "cli", {"unsafe.yml": candidate})

    def test_privileged_artifact_validator_compares_the_downloaded_bytes(self) -> None:
        command = policy_fixture()["workflow_trust"]["privileged_artifact_handoffs"]["validator_command"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact_directory = root / "isolated-release"
            artifact_directory.mkdir()
            payload = b"exact artifact bytes"
            (artifact_directory / "release.tar").write_bytes(payload)
            environment = {
                **os.environ,
                "ARTIFACT_DIRECTORY": artifact_directory.name,
                "EXPECTED_ARTIFACT_DIGEST": hashlib.sha256(payload).hexdigest(),
                "EXPECTED_ARTIFACT_ID": "101",
                "EXPECTED_SOURCE_RUN_ATTEMPT": "2",
                "EXPECTED_SOURCE_RUN_ID": "303",
            }
            exact = subprocess.run(
                ["bash", "-c", command],
                cwd=root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(0, exact.returncode, exact.stderr)

            environment["EXPECTED_ARTIFACT_DIGEST"] = "0" * 64
            wrong = subprocess.run(
                ["bash", "-c", command],
                cwd=root,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(0, wrong.returncode)
            self.assertIn("artifact digest mismatch", wrong.stderr)

    def test_workflow_run_validators_must_be_executable_steps(self) -> None:
        policy = policy_fixture()
        source = (ROOT / ".github/workflows/beta-conformance-retention.yml").read_text(encoding="utf-8")
        resolution_source = (
            ROOT / ".github/workflows/beta-continuity-resolution.yml"
        ).read_text(encoding="utf-8")
        scan_workflow_sources(
            policy,
            "github-control-plane",
            {
                ".github/workflows/beta-conformance-retention.yml": source,
                ".github/workflows/beta-continuity-resolution.yml": resolution_source,
            },
        )

        cases = {
            "identity in comment": source.replace(
                "          python scripts/beta_conformance.py retention-source \\",
                "          # python scripts/beta_conformance.py retention-source \\",
            ),
            "digest in comment": source.replace(
                "          python scripts/beta_conformance.py aggregate \\",
                "          # python scripts/beta_conformance.py aggregate \\",
            ),
            "identity in output": source.replace(
                "          python scripts/beta_conformance.py retention-source \\",
                "          echo python scripts/beta_conformance.py retention-source \\",
            ),
            "identity from unreviewed path": source.replace(
                "          python scripts/beta_conformance.py retention-source \\",
                "          python shadow/scripts/beta_conformance.py retention-source \\",
            ),
            "identity short-circuited": source.replace(
                "          python scripts/beta_conformance.py retention-source \\",
                "          true || python scripts/beta_conformance.py retention-source \\",
            ),
            "identity multiline short-circuited": source.replace(
                "          python scripts/beta_conformance.py retention-source \\",
                "          true ||\n"
                "          python scripts/beta_conformance.py retention-source \\",
            ),
            "identity in unreachable shell branch": source.replace(
                "          python scripts/beta_conformance.py retention-source \\",
                "          if false; then\n"
                "            python scripts/beta_conformance.py retention-source \\",
            ).replace(
                '            --github-output "$GITHUB_OUTPUT"',
                '            --github-output "$GITHUB_OUTPUT"\n          fi',
                1,
            ),
            "digest short-circuited": source.replace(
                "          python scripts/beta_conformance.py aggregate \\",
                "          true || python scripts/beta_conformance.py aggregate \\",
            ),
            "identity conditionally skipped": source.replace(
                "      - name: Resolve and validate the completed source run\n",
                "      - name: Resolve and validate the completed source run\n        if: ${{ false }}\n",
            ),
            "digest failure ignored": source.replace(
                "      - name: Aggregate exact-tuple evidence\n",
                "      - name: Aggregate exact-tuple evidence\n        continue-on-error: true\n",
            ),
            "identity custom shell": source.replace(
                "      - name: Resolve and validate the completed source run\n",
                "      - name: Resolve and validate the completed source run\n"
                "        shell: true {0}\n",
            ),
            "digest working directory": source.replace(
                "      - name: Aggregate exact-tuple evidence\n",
                "      - name: Aggregate exact-tuple evidence\n"
                "        working-directory: shadow\n",
            ),
            "identity inherited job shell": source.replace(
                "  bind:\n",
                "  bind:\n    defaults:\n      run:\n        shell: true {0}\n",
            ),
            "digest inherited job working directory": source.replace(
                "  retain:\n",
                "  retain:\n    defaults:\n      run:\n        working-directory: shadow\n",
            ),
            "validators inherited workflow shell": source.replace(
                "jobs:\n",
                "defaults:\n  run:\n    shell: true {0}\n\njobs:\n",
            ),
            "validators inherited workflow working directory": source.replace(
                "jobs:\n",
                "defaults:\n  run:\n    working-directory: shadow\n\njobs:\n",
            ),
        }
        for name, candidate in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(PolicyError, "does not invoke its reviewed"):
                scan_workflow_sources(
                    policy,
                    "github-control-plane",
                    {".github/workflows/beta-conformance-retention.yml": candidate},
                )

    def test_workflow_run_validators_reject_preceding_injection_and_containers(self) -> None:
        policy = policy_fixture()
        source = (ROOT / ".github/workflows/beta-conformance-retention.yml").read_text(encoding="utf-8")
        cases = {
            "prior run writes shell startup": source.replace(
                "      - name: Resolve and validate the completed source run\n",
                "      - name: Inject shell startup\n"
                "        run: echo 'BASH_ENV=/tmp/injected' >> \"$GITHUB_ENV\"\n\n"
                "      - name: Resolve and validate the completed source run\n",
            ),
            "prior run shadows Python": source.replace(
                "      - name: Aggregate exact-tuple evidence\n",
                "      - name: Shadow Python\n"
                "        run: echo '/tmp/shadow' >> \"$GITHUB_PATH\"\n\n"
                "      - name: Aggregate exact-tuple evidence\n",
            ),
            "unreviewed preceding action": source.replace(
                "      - name: Resolve and validate the completed source run\n",
                "      - name: Extra setup action\n"
                "        uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1  # v6\n"
                "        with:\n"
                "          python-version: \"3.13\"\n\n"
                "      - name: Resolve and validate the completed source run\n",
            ),
            "checkout selects a shadow path": source.replace(
                "          persist-credentials: false\n",
                "          persist-credentials: false\n"
                "          path: shadow\n",
                1,
            ),
            "checkout selects a contributor fork": source.replace(
                "          persist-credentials: false\n",
                "          persist-credentials: false\n"
                "          repository: attacker/controller-fork\n",
                1,
            ),
            "setup action receives environment": source.replace(
                "      - name: Set up Python\n",
                "      - name: Set up Python\n"
                "        env:\n"
                "          BASH_ENV: /tmp/injected\n",
                1,
            ),
            "artifact overwrites the controller checkout": source.replace(
                "          path: aggregate-input\n",
                "          path: .\n",
            ),
            "artifact overwrites reviewed validators": source.replace(
                "          path: aggregate-input\n",
                "          path: scripts\n",
            ),
            "validator selects a different run": source.replace(
                "          REQUESTED_RUN_ID: ${{ inputs.source_run_id || github.event.workflow_run.id }}\n",
                "          REQUESTED_RUN_ID: 1\n",
            ).replace(
                '            --github-output "$GITHUB_OUTPUT"',
                '            --github-output "$GITHUB_OUTPUT"\n'
                "          # github.event.workflow_run.id",
                1,
            ),
            "validator selects a different attempt": source.replace(
                "          REQUESTED_RUN_ATTEMPT: >-\n"
                "            ${{ inputs.source_run_attempt || github.event.workflow_run.run_attempt }}\n",
                "          REQUESTED_RUN_ATTEMPT: 1\n",
            ).replace(
                '            --github-output "$GITHUB_OUTPUT"',
                '            --github-output "$GITHUB_OUTPUT"\n'
                "          # github.event.workflow_run.run_attempt",
                1,
            ),
            "binder container environment": source.replace(
                "  bind:\n",
                "  bind:\n"
                "    container:\n"
                "      image: python:3.13\n"
                "      env:\n"
                "        BASH_ENV: /tmp/injected\n",
            ),
            "publisher container environment": source.replace(
                "  retain:\n",
                "  retain:\n"
                "    container:\n"
                "      image: python:3.13\n"
                "      env:\n"
                "        PYTHONPATH: /tmp/injected\n",
            ),
        }

        for name, candidate in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(PolicyError, "does not invoke its reviewed"):
                scan_workflow_sources(
                    policy,
                    "github-control-plane",
                    {".github/workflows/beta-conformance-retention.yml": candidate},
                )

    def test_workflow_run_validator_commands_bind_exact_run_selectors(self) -> None:
        policy = policy_fixture()
        source = (ROOT / ".github/workflows/beta-conformance-retention.yml").read_text(encoding="utf-8")
        cases = {
            "identity run ID replaced with a constant": source.replace(
                '--expected-run-id "$REQUESTED_RUN_ID"',
                '--expected-run-id "1"',
            ),
            "identity run attempt replaced with a constant": source.replace(
                '--expected-run-attempt "$REQUESTED_RUN_ATTEMPT"',
                '--expected-run-attempt "1"',
            ),
            "identity run ID replaced with shell expansion": source.replace(
                '--expected-run-id "$REQUESTED_RUN_ID"',
                '--expected-run-id "$(printf \'%s\' "$REQUESTED_RUN_ID")"',
            ),
            "artifact run ID replaced with a constant": source.replace(
                '--run-id "${{ needs.bind.outputs.source_run_id }}"',
                '--run-id "1"',
            ),
        }

        for name, candidate in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(PolicyError, "does not invoke its reviewed"):
                scan_workflow_sources(
                    policy,
                    "github-control-plane",
                    {".github/workflows/beta-conformance-retention.yml": candidate},
                )

    def test_resolution_publisher_requires_exact_qualified_controller_revision(self) -> None:
        policy = policy_fixture()
        source = (
            ROOT / ".github/workflows/beta-continuity-resolution.yml"
        ).read_text(encoding="utf-8")
        retention_source = (
            ROOT / ".github/workflows/beta-conformance-retention.yml"
        ).read_text(encoding="utf-8")
        scan_workflow_sources(
            policy,
            "github-control-plane",
            {
                ".github/workflows/beta-conformance-retention.yml": retention_source,
                ".github/workflows/beta-continuity-resolution.yml": source,
            },
        )

        cases = {
            "controller binding absent": source.replace(
                "      github.ref == 'refs/heads/main' &&\n"
                "      github.sha == needs.bind.outputs.source_head_sha",
                "      github.ref == 'refs/heads/main'",
            ),
            "controller binding uses event source": source.replace(
                "github.sha == needs.bind.outputs.source_head_sha",
                "github.event.workflow_run.head_sha == needs.bind.outputs.source_head_sha",
            ),
            "controller binding uses another output": source.replace(
                "github.sha == needs.bind.outputs.source_head_sha",
                "github.sha == needs.bind.outputs.source_run_id",
            ),
        }
        for name, candidate in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                PolicyError,
                "does not enforce its reviewed privilege condition",
            ):
                scan_workflow_sources(
                    policy,
                    "github-control-plane",
                    {
                        ".github/workflows/beta-conformance-retention.yml": retention_source,
                        ".github/workflows/beta-continuity-resolution.yml": candidate,
                    },
                )

    def test_workflow_run_validator_jobs_reject_services_and_unreviewed_runners(self) -> None:
        policy = policy_fixture()
        source = (ROOT / ".github/workflows/beta-conformance-retention.yml").read_text(encoding="utf-8")
        cases = {
            "binder service workspace bind": source.replace(
                "  bind:\n",
                "  bind:\n"
                "    services:\n"
                "      workspace-writer:\n"
                "        image: alpine:3.20\n"
                "        volumes:\n"
                '          - "${{ github.workspace }}:/workspace"\n',
            ),
            "publisher service workspace bind": source.replace(
                "  retain:\n",
                "  retain:\n"
                "    services:\n"
                "      workspace-writer:\n"
                "        image: alpine:3.20\n"
                "        volumes:\n"
                '          - "${{ github.workspace }}:/workspace"\n',
            ),
            "binder self-hosted runner": source.replace(
                "    runs-on: ubuntu-latest\n",
                "    runs-on: self-hosted\n",
                1,
            ),
            "publisher self-hosted runner": source.replace(
                "    runs-on: ubuntu-latest\n    timeout-minutes: 15\n",
                "    runs-on: self-hosted\n    timeout-minutes: 15\n",
            ),
        }

        for name, candidate in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(PolicyError, "does not invoke its reviewed"):
                scan_workflow_sources(
                    policy,
                    "github-control-plane",
                    {".github/workflows/beta-conformance-retention.yml": candidate},
                )

    def test_workflow_run_validators_reject_unreviewed_effective_environment(self) -> None:
        policy = policy_fixture()
        source = (ROOT / ".github/workflows/beta-conformance-retention.yml").read_text(encoding="utf-8")
        environment_names = (
            "BASH_ENV",
            "ENV",
            "PATH",
            "PYTHONPATH",
            "PYTHONHOME",
            "LD_PRELOAD",
            "LD_LIBRARY_PATH",
        )

        def at_workflow_scope(name: str) -> str:
            return source.replace("jobs:\n", f"env:\n  {name}: /tmp/injected\n\njobs:\n")

        def at_job_scope(name: str) -> str:
            return source.replace("  bind:\n", f"  bind:\n    env:\n      {name}: /tmp/injected\n")

        def at_step_scope(name: str) -> str:
            return source.replace(
                "        id: source\n        env:\n",
                f"        id: source\n        env:\n          {name}: /tmp/injected\n",
            )

        for scope, inject in (
            ("workflow", at_workflow_scope),
            ("job", at_job_scope),
            ("step", at_step_scope),
        ):
            for environment_name in environment_names:
                with self.subTest(scope=scope, environment_name=environment_name), self.assertRaisesRegex(
                    PolicyError,
                    "does not invoke its reviewed source identity validator",
                ):
                    scan_workflow_sources(
                        policy,
                        "github-control-plane",
                        {".github/workflows/beta-conformance-retention.yml": inject(environment_name)},
                    )

    def test_policy_rejects_execution_affecting_validator_environment_allowlist(self) -> None:
        policy = policy_fixture()
        consumer = policy["workflow_trust"]["privileged_workflow_run_consumers"][
            "github-control-plane/beta-conformance-retention.yml"
        ]
        consumer["identity_validator_environment"].append("PYTHONPATH")

        with self.assertRaisesRegex(PolicyError, "reviewed safe environment names"):
            validate_policy(policy)

    def test_policy_rejects_unreviewed_validator_runner(self) -> None:
        policy = policy_fixture()
        consumer = policy["workflow_trust"]["privileged_workflow_run_consumers"][
            "github-control-plane/beta-conformance-retention.yml"
        ]
        consumer["validator_runner"] = "self-hosted"

        with self.assertRaisesRegex(PolicyError, "reviewed GitHub-hosted runner"):
            validate_policy(policy)

    def test_policy_rejects_unreviewed_validator_setup_actions(self) -> None:
        policy = policy_fixture()
        consumer = policy["workflow_trust"]["privileged_workflow_run_consumers"][
            "github-control-plane/beta-conformance-retention.yml"
        ]
        consumer["identity_validator_preceding_steps"].append(
            "docker/login-action@af1e73f918a031802d376d3c8bbc3fe56130a9b0"
        )

        with self.assertRaisesRegex(PolicyError, "reviewed immutable action steps"):
            validate_policy(policy)

    def test_artifact_digest_validator_rejects_unreviewed_effective_environment(self) -> None:
        policy = policy_fixture()
        source = (ROOT / ".github/workflows/beta-conformance-retention.yml").read_text(encoding="utf-8")
        cases = {
            "job shell startup": source.replace(
                "  retain:\n",
                "  retain:\n    env:\n      BASH_ENV: /tmp/injected\n",
            ),
            "step Python import path": source.replace(
                "      - name: Aggregate exact-tuple evidence\n",
                "      - name: Aggregate exact-tuple evidence\n"
                "        env:\n"
                "          PYTHONPATH: /tmp/injected\n",
            ),
        }

        for name, candidate in cases.items():
            with self.subTest(name=name), self.assertRaisesRegex(
                PolicyError,
                "does not invoke its reviewed artifact digest validator",
            ):
                scan_workflow_sources(
                    policy,
                    "github-control-plane",
                    {".github/workflows/beta-conformance-retention.yml": candidate},
                )

    def test_github_client_falls_back_without_forwarding_authorization(self) -> None:
        sleeps: list[float] = []
        client = GitHubClient("secret", max_attempts=3, retry_base_seconds=1, sleep=sleeps.append)
        responses = [
            http_error(503, b"service unavailable", **{"Retry-After": "120"}),
            FakeResponse(b'{"default_branch":"main"}'),
        ]

        with patch.object(urllib.request, "urlopen", side_effect=responses) as urlopen:
            result = client.json("/repos/durable-workflow/cli")

        self.assertEqual({"default_branch": "main"}, result)
        self.assertEqual([], sleeps)
        self.assertEqual(2, urlopen.call_count)
        authenticated_request = urlopen.call_args_list[0].args[0]
        credential_free_request = urlopen.call_args_list[1].args[0]
        self.assertEqual("Bearer secret", authenticated_request.get_header("Authorization"))
        self.assertIsNone(credential_free_request.get_header("Authorization"))

    def test_github_client_recovers_after_both_clients_have_connection_interruptions(self) -> None:
        sleeps: list[float] = []
        client = GitHubClient("secret", max_attempts=3, retry_base_seconds=1, sleep=sleeps.append)
        responses = [
            urllib.error.URLError(ConnectionResetError("authenticated connection reset")),
            urllib.error.URLError(ConnectionResetError("credential-free connection reset")),
            FakeResponse(b'{"default_branch":"main"}'),
        ]

        with patch.object(urllib.request, "urlopen", side_effect=responses) as urlopen:
            result = client.json("/repos/durable-workflow/cli")

        self.assertEqual({"default_branch": "main"}, result)
        self.assertEqual([1], sleeps)
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
            http_error(429, **{"Retry-After": "120"}),
            FakeResponse(b"[]"),
        ]

        with patch.object(urllib.request, "urlopen", side_effect=responses):
            self.assertEqual([], client.json("/repos/durable-workflow/cli/rules/branches/main"))

        self.assertEqual([12, 120], sleeps)

    def test_github_client_bounds_transient_exhaustion_with_endpoint_evidence(self) -> None:
        client = GitHubClient("secret", max_attempts=3, retry_base_seconds=1, sleep=lambda _delay: None)

        with (
            patch.object(
                urllib.request,
                "urlopen",
                side_effect=[http_error(503), http_error(502)] * 3,
            ),
            self.assertRaisesRegex(
                GitHubInfrastructureError,
                r"classification=github-api-transient, endpoint=GET /repos/durable-workflow/cli, "
                r"reason=retry-exhausted, authenticated_attempts=3, authenticated_status=503, "
                r"credential_free_attempts=3, credential_free_status=502",
            ),
        ):
            client.json("/repos/durable-workflow/cli")

    def test_github_client_bounds_all_endpoint_retries_by_the_audit_deadline(self) -> None:
        clock = [0.0]
        sleeps: list[float] = []

        def sleep(delay: float) -> None:
            sleeps.append(delay)
            clock[0] += delay

        client = GitHubClient(
            "secret",
            max_attempts=5,
            retry_base_seconds=2,
            audit_timeout_seconds=3,
            sleep=sleep,
            monotonic=lambda: clock[0],
        )

        responses = [
            http_error(503),
            http_error(503),
            FakeResponse(b'{"default_branch":"main"}'),
            http_error(503),
            http_error(503),
        ]
        with patch.object(urllib.request, "urlopen", side_effect=responses) as urlopen:
            self.assertEqual(
                {"default_branch": "main"},
                client.json("/repos/durable-workflow/cli"),
            )
            with self.assertRaisesRegex(
                GitHubInfrastructureError,
                r"endpoint=GET /repos/durable-workflow/server, reason=audit-deadline, "
                r"authenticated_attempts=1, authenticated_status=503, credential_free_attempts=1, "
                r"credential_free_status=503",
            ):
                client.json("/repos/durable-workflow/server")

        self.assertEqual([2], sleeps)
        self.assertEqual(5, urlopen.call_count)

    def test_github_client_does_not_retry_authorization_failures(self) -> None:
        for status in (401, 403):
            with self.subTest(status=status):
                client = GitHubClient(
                    "secret",
                    max_attempts=3,
                    sleep=lambda _delay: self.fail("authorization failure was retried"),
                )

                with (
                    patch.object(
                        urllib.request,
                        "urlopen",
                        side_effect=http_error(status, b"Resource not accessible"),
                    ) as urlopen,
                    self.assertRaisesRegex(PolicyError, rf"GitHub API {status}"),
                ):
                    client.json("/repos/durable-workflow/cli")

                self.assertEqual(1, urlopen.call_count)

    def test_exhaustion_uses_a_distinct_temporary_failure_exit(self) -> None:
        error = GitHubInfrastructureError(
            "/repos/durable-workflow/cli",
            {"authenticated": 5, "credential_free": 5},
            {"authenticated": "status=503", "credential_free": "status=503"},
            reason="retry-exhausted",
        )
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

    def test_private_cloud_is_rejected_from_the_public_target_inventory(self) -> None:
        policy = policy_fixture()
        self.assertEqual(10, len(EXPECTED_TARGETS))
        self.assertNotIn("cloud", EXPECTED_TARGETS)
        self.assertNotIn("cloud", policy["targets"])

        policy["targets"]["cloud"] = {
            "branch": "main",
            "repository": "cloud",
            "workflows": [
                {
                    "matrix_independent": False,
                    "path": "ci.yml",
                    "required_check": "Route Drift Guard",
                }
            ],
        }
        with self.assertRaisesRegex(PolicyError, "target inventory mismatch"):
            validate_policy(policy)

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

    def test_audit_rejects_a_plan_commit_after_its_target_branch_advances(self) -> None:
        policy = policy_fixture()

        with self.assertRaisesRegex(PolicyError, "requested release plan pins"):
            audit_policy(
                policy,
                FakeGitHubClient(policy),
                expected_commits={"workflow": "b" * 40},
            )

        evidence = audit_policy(
            policy,
            FakeGitHubClient(policy),
            expected_commits={name: "a" * 40 for name in EXPECTED_TARGETS},
        )
        self.assertEqual("a" * 40, evidence["targets"]["workflow"]["commit"])

    def test_audit_rejects_an_unapproved_action_release(self) -> None:
        policy = policy_fixture()

        class RetiredReleaseClient(FakeGitHubClient):
            def bytes(self, path: str) -> bytes:
                source = super().bytes(path)
                if "/repos/durable-workflow/" in path and "/contents/.github/workflows/" in path:
                    return source.replace(
                        f"actions/checkout@{CHECKOUT_PIN} # v6".encode(),
                        b"actions/checkout@v4 # v4",
                    )
                return source

        with self.assertRaisesRegex(PolicyError, "is not pinned to a full commit SHA"):
            audit_policy(policy, RetiredReleaseClient(policy))

    def test_audit_rejects_a_flow_style_unapproved_action_release(self) -> None:
        policy = policy_fixture()

        class FlowStyleReleaseClient(FakeGitHubClient):
            def bytes(self, path: str) -> bytes:
                source = super().bytes(path)
                if "/repos/durable-workflow/" in path and "/contents/.github/workflows/" in path:
                    return source.replace(
                        f"- uses: actions/checkout@{CHECKOUT_PIN} # v6".encode(),
                        b"- { uses: actions/checkout@v4 } # v4",
                    )
                return source

        with self.assertRaisesRegex(PolicyError, "is not pinned to a full commit SHA"):
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

    def test_audit_waits_for_a_concurrent_target_qualification(self) -> None:
        policy = policy_fixture()

        class DelayedCheckClient(FakeGitHubClient):
            def __init__(self, delayed_policy: dict[str, Any]) -> None:
                super().__init__(delayed_policy)
                self.waterline_attempts = 0

            def collection(self, path: str, key: str) -> list[dict[str, Any]]:
                records = super().collection(path, key)
                if "/durable-workflow/waterline/" not in path:
                    return records
                self.waterline_attempts += 1
                if self.waterline_attempts == 1:
                    return []
                if self.waterline_attempts == 2:
                    records[0]["conclusion"] = None
                    records[0]["status"] = "in_progress"
                return records

        client = DelayedCheckClient(policy)
        sleeps: list[float] = []

        evidence = audit_policy(
            policy,
            client,
            check_run_max_attempts=3,
            check_run_poll_seconds=5,
            check_run_sleep=sleeps.append,
        )

        self.assertEqual([5, 5], sleeps)
        self.assertEqual(3, client.waterline_attempts)
        self.assertEqual(
            {"Target branch qualification"},
            set(evidence["targets"]["waterline"]["successful_check_runs"]),
        )

    def test_audit_fails_after_bounded_check_convergence(self) -> None:
        policy = policy_fixture()

        class MissingCheckClient(FakeGitHubClient):
            def collection(self, path: str, key: str) -> list[dict[str, Any]]:
                if "/durable-workflow/waterline/" in path:
                    return []
                return super().collection(path, key)

        sleeps: list[float] = []
        with self.assertRaisesRegex(
            PolicyError,
            "required checks did not converge after 3 attempts: 'Target branch qualification' has not been created",
        ):
            audit_policy(
                policy,
                MissingCheckClient(policy),
                check_run_max_attempts=3,
                check_run_poll_seconds=5,
                check_run_sleep=sleeps.append,
            )

        self.assertEqual([5, 5], sleeps)

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
