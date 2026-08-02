from __future__ import annotations

import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

from scripts.current_plan_publication import (
    AUTHORITY_REF,
    CONTROL_REPOSITORY,
    CURRENT_PLAN_WORKFLOW,
    CURRENT_PLAN_WORKFLOW_REF,
    CurrentPlanPublicationError,
    approved_writer_handoff,
    validate_approved_writer_handoff,
    validate_runtime_identity,
)

ROOT = Path(__file__).resolve().parents[1]
OBSERVER_WORKFLOW = ROOT / ".github/workflows/release-plan-observer.yml"
CURRENT_WORKFLOW = ROOT / ".github/workflows/current-release-plan.yml"
PLAN_REGISTRY_GROUP = "release-plan-registry"


def publication_step() -> dict[str, object]:
    workflow = yaml.safe_load(OBSERVER_WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["publish-current"]["steps"]
    return next(
        step
        for step in steps
        if step.get("name") == "Publish the matching aggregate current authority"
    )


class CurrentPlanPublicationTest(unittest.TestCase):
    def test_waiting_approval_does_not_hold_the_writer_registry(self) -> None:
        current = yaml.safe_load(CURRENT_WORKFLOW.read_text(encoding="utf-8"))
        observer = yaml.safe_load(OBSERVER_WORKFLOW.read_text(encoding="utf-8"))
        approval = current["jobs"]["authorize"]
        writer = current["jobs"]["record"]

        self.assertNotIn("concurrency", current)
        self.assertEqual("beta-authorization", approval["environment"])
        self.assertNotIn("concurrency", approval)
        self.assertEqual({"contents": "read"}, approval["permissions"])
        approval_checkout = next(step for step in approval["steps"] if "actions/checkout" in step.get("uses", ""))
        self.assertIs(approval_checkout["with"]["persist-credentials"], False)
        self.assertEqual("${{ github.sha }}", approval_checkout["with"]["ref"])
        self.assertEqual("authorize", writer["needs"])
        self.assertIn("needs.authorize.result == 'success'", writer["if"])
        self.assertEqual(
            {"group": PLAN_REGISTRY_GROUP, "cancel-in-progress": False},
            writer["concurrency"],
        )
        self.assertEqual(
            {"group": PLAN_REGISTRY_GROUP, "cancel-in-progress": False},
            observer["concurrency"],
        )
        self.assertNotIn("write", observer["jobs"]["observe"]["permissions"].values())
        self.assertEqual("record", observer["jobs"]["publish-current"]["needs"])
        self.assertIn(
            "needs.record.outputs.current-plan == 'true'",
            observer["jobs"]["publish-current"]["if"],
        )

        running: str | None = None
        pending: str | None = None
        superseded: list[str] = []

        def schedule(name: str) -> None:
            nonlocal running, pending
            if running is None:
                running = name
                return
            if pending is not None:
                superseded.append(pending)
            pending = name

        # The protected approval is waiting but owns no concurrency group.
        for observer_run in ("scheduled-observer-1", "scheduled-observer-2", "scheduled-observer-3"):
            schedule(observer_run)

        self.assertEqual("scheduled-observer-1", running)
        self.assertEqual("scheduled-observer-3", pending)
        self.assertEqual(["scheduled-observer-2"], superseded)
        self.assertEqual(2, len({running, pending} - {None}))

        running, pending = pending, None
        self.assertEqual("scheduled-observer-3", running)
        running = None
        self.assertIsNone(running)
        self.assertIsNone(pending)

    def test_approved_writer_handoff_is_exact_and_retry_safe(self) -> None:
        identity = {
            "repository": CONTROL_REPOSITORY,
            "ref": f"refs/heads/{AUTHORITY_REF}",
            "workflow_ref": CURRENT_PLAN_WORKFLOW_REF,
            "source_sha": "a" * 40,
            "run_id": 123456789,
            "producer_attempt": 1,
        }
        handoff = approved_writer_handoff(**identity)
        self.assertRegex(handoff, r"^[0-9a-f]{64}$")
        self.assertEqual(handoff, approved_writer_handoff(**identity))
        validate_approved_writer_handoff(
            handoff,
            **identity,
            current_attempt=2,
        )

        mismatches = (
            ({"handoff": "0" * 64}, "does not match"),
            ({"source_sha": "b" * 40}, "does not match"),
            ({"run_id": identity["run_id"] + 1}, "does not match"),
            ({"producer_attempt": 2, "current_attempt": 1}, "newer than"),
        )
        for changes, diagnostic in mismatches:
            arguments = {**identity, "handoff": handoff, "current_attempt": 2, **changes}
            with (
                self.subTest(changes=changes),
                self.assertRaisesRegex(
                    CurrentPlanPublicationError,
                    diagnostic,
                ),
            ):
                validate_approved_writer_handoff(**arguments)

    def test_protected_runtime_identity_is_exact(self) -> None:
        validate_runtime_identity(
            CONTROL_REPOSITORY,
            f"refs/heads/{AUTHORITY_REF}",
            CURRENT_PLAN_WORKFLOW_REF,
        )
        current = yaml.safe_load(CURRENT_WORKFLOW.read_text(encoding="utf-8"))
        validation = next(
            step
            for step in current["jobs"]["record"]["steps"]
            if step.get("name") == "Validate aggregate current-plan publication authority"
        )
        self.assertIn("scripts/current_plan_publication.py validate-runtime", validation["run"])
        self.assertIn('--repository "$GITHUB_REPOSITORY"', validation["run"])
        self.assertIn('--ref "$GITHUB_REF"', validation["run"])
        self.assertIn('--workflow-ref "$GITHUB_WORKFLOW_REF"', validation["run"])
        self.assertIn("validate-approved-writer-handoff", validation["run"])
        self.assertEqual(
            {
                "APPROVED_WRITER_HANDOFF": "${{ needs.authorize.outputs.handoff }}",
                "APPROVAL_PRODUCER_ATTEMPT": "${{ needs.authorize.outputs.producer-attempt }}",
            },
            validation["env"],
        )

        mismatches = (
            (None, f"refs/heads/{AUTHORITY_REF}", CURRENT_PLAN_WORKFLOW_REF),
            ("outside/fork", f"refs/heads/{AUTHORITY_REF}", CURRENT_PLAN_WORKFLOW_REF),
            (CONTROL_REPOSITORY, "refs/heads/feature", CURRENT_PLAN_WORKFLOW_REF),
            (
                CONTROL_REPOSITORY,
                f"refs/heads/{AUTHORITY_REF}",
                f"{CONTROL_REPOSITORY}/.github/workflows/other.yml@refs/heads/{AUTHORITY_REF}",
            ),
        )
        for repository, ref, workflow_ref in mismatches:
            with (
                self.subTest(repository=repository, ref=ref, workflow_ref=workflow_ref),
                self.assertRaises(CurrentPlanPublicationError),
            ):
                validate_runtime_identity(repository, ref, workflow_ref)

    def test_checkout_free_dispatch_targets_one_explicit_workflow(self) -> None:
        step = publication_step()
        self.assertEqual(
            {
                "GH_TOKEN": "${{ github.token }}",
                "TARGET_REF": AUTHORITY_REF,
                "TARGET_REPOSITORY": CONTROL_REPOSITORY,
                "TARGET_WORKFLOW": CURRENT_PLAN_WORKFLOW,
            },
            step["env"],
        )
        workflow = yaml.safe_load(OBSERVER_WORKFLOW.read_text(encoding="utf-8"))
        publish_job = workflow["jobs"]["publish-current"]
        self.assertFalse(any("actions/checkout" in str(item.get("uses", "")) for item in publish_job["steps"]))

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            command_log = root / "gh-commands"
            fake_bin = root / "bin"
            fake_bin.mkdir()
            gh = fake_bin / "gh"
            gh.write_text(
                '#!/usr/bin/env bash\nprintf \'%s\\n\' "$*" >> "$COMMAND_LOG"\n',
                encoding="utf-8",
            )
            gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
            environment = {
                **os.environ,
                **step["env"],
                "COMMAND_LOG": str(command_log),
                "GITHUB_REF": f"refs/heads/{AUTHORITY_REF}",
                "GITHUB_REPOSITORY": CONTROL_REPOSITORY,
                "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
            }

            for _observation in range(2):
                process = subprocess.run(
                    ["bash", "-c", str(step["run"])],
                    cwd=root,
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(0, process.returncode, process.stderr)
                self.assertFalse((root / ".git").exists())

            self.assertEqual(
                [
                    (
                        f"workflow run {CURRENT_PLAN_WORKFLOW} --repo "
                        f"{CONTROL_REPOSITORY} --ref {AUTHORITY_REF}"
                    ),
                    (
                        f"workflow run {CURRENT_PLAN_WORKFLOW} --repo "
                        f"{CONTROL_REPOSITORY} --ref {AUTHORITY_REF}"
                    ),
                ],
                command_log.read_text(encoding="utf-8").splitlines(),
            )

        current = CURRENT_WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("current-completion", current)
        self.assertIn("steps.existing.outputs.status != 'existing'", current)

    def test_missing_or_mismatched_runner_identity_never_invokes_gh(self) -> None:
        step = publication_step()
        cases = (
            ({"GITHUB_REF": f"refs/heads/{AUTHORITY_REF}"}, "repository=<absent>"),
            (
                {
                    "GITHUB_REPOSITORY": "outside/fork",
                    "GITHUB_REF": f"refs/heads/{AUTHORITY_REF}",
                },
                "repository=outside/fork",
            ),
            (
                {"GITHUB_REPOSITORY": CONTROL_REPOSITORY, "GITHUB_REF": "refs/heads/feature"},
                "ref=refs/heads/feature",
            ),
        )
        for identity, diagnostic in cases:
            with self.subTest(identity=identity), tempfile.TemporaryDirectory() as directory:
                environment = {**os.environ, **step["env"], **identity, "PATH": directory}
                if "GITHUB_REPOSITORY" not in identity:
                    environment.pop("GITHUB_REPOSITORY", None)
                process = subprocess.run(
                    ["/bin/bash", "-c", str(step["run"])],
                    cwd=directory,
                    env=environment,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(1, process.returncode)
                self.assertIn(diagnostic, process.stderr)
                self.assertIn(f"expected repository={CONTROL_REPOSITORY}", process.stderr)
                self.assertIn(f"workflow={CURRENT_PLAN_WORKFLOW}", process.stderr)
                self.assertIn(f"ref={AUTHORITY_REF}", process.stderr)

    def test_dispatch_failure_is_bounded_actionable_and_redacts_tokens(self) -> None:
        step = publication_step()
        secret = "github_pat_sensitive_value"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"
            fake_bin.mkdir()
            gh = fake_bin / "gh"
            gh.write_text(
                '#!/usr/bin/env bash\nprintf \'dispatch rejected for token %s\n\' "$GH_TOKEN" >&2\nexit 7\n',
                encoding="utf-8",
            )
            gh.chmod(gh.stat().st_mode | stat.S_IXUSR)
            environment = {
                **os.environ,
                **step["env"],
                "GH_TOKEN": secret,
                "GITHUB_REF": f"refs/heads/{AUTHORITY_REF}",
                "GITHUB_REPOSITORY": CONTROL_REPOSITORY,
                "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
            }
            process = subprocess.run(
                ["bash", "-c", str(step["run"])],
                cwd=root,
                env=environment,
                text=True,
                capture_output=True,
                check=False,
            )

        self.assertEqual(1, process.returncode)
        self.assertIn(f"repository={CONTROL_REPOSITORY}", process.stderr)
        self.assertIn(f"workflow={CURRENT_PLAN_WORKFLOW}", process.stderr)
        self.assertIn(f"ref={AUTHORITY_REF}", process.stderr)
        self.assertIn("dispatch rejected", process.stderr)
        self.assertIn("<redacted>", process.stderr)
        self.assertNotIn(secret, process.stderr)
        self.assertLess(len(process.stderr), 2300)


if __name__ == "__main__":
    unittest.main()
