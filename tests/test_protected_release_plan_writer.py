from __future__ import annotations

import unittest
from pathlib import Path
from typing import Any

import yaml

from scripts.protected_release_plan_writer import (
    AUTHORITY_REF,
    CONTROL_REPOSITORY,
    PROTECTED_WORKFLOWS,
    ProtectedWriterError,
    approved_writer_handoff,
    expected_workflow_ref,
    validate_approved_writer_handoff,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = ROOT / ".github" / "workflows"
PLAN_REGISTRY_GROUP = "release-plan-registry"
WRITER_CONCURRENCY = {
    "group": PLAN_REGISTRY_GROUP,
    "cancel-in-progress": False,
}
WORKFLOW_CONTRACTS = {
    "release-plan.yml": {
        "approval": "authorize",
        "environment": "beta-authorization",
        "permissions": {"contents": "read"},
        "writer": "validate-and-record",
    },
    "release-plan-supersession.yml": {
        "approval": "qualify",
        "environment": "release-plan-supersession",
        "permissions": {
            "actions": "read",
            "attestations": "read",
            "contents": "read",
        },
        "writer": "record",
    },
}


def load_workflow(name: str) -> dict[str, Any]:
    return yaml.safe_load((WORKFLOW_ROOT / name).read_text(encoding="utf-8"))


def handoff_identity(workflow: str) -> dict[str, Any]:
    return {
        "workflow": workflow,
        "repository": CONTROL_REPOSITORY,
        "ref": f"refs/heads/{AUTHORITY_REF}",
        "workflow_ref": expected_workflow_ref(workflow),
        "source_sha": "a" * 40,
        "run_id": 123456789,
        "producer_attempt": 1,
    }


def schedule_observer(
    name: str,
    running: str | None,
    pending: str | None,
    superseded: list[str],
) -> tuple[str, str | None]:
    if running is None:
        return name, pending
    if pending is not None:
        superseded.append(pending)
    return running, name


class ProtectedReleasePlanWriterTest(unittest.TestCase):
    def test_handoff_is_exact_and_safe_for_failed_writer_retries(self) -> None:
        for workflow in sorted(PROTECTED_WORKFLOWS):
            with self.subTest(workflow=workflow):
                identity = handoff_identity(workflow)
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
                    (
                        {
                            "workflow_ref": expected_workflow_ref(
                                next(name for name in PROTECTED_WORKFLOWS if name != workflow)
                            )
                        },
                        "workflow mismatch",
                    ),
                    ({"producer_attempt": 2}, "does not match"),
                    (
                        {"producer_attempt": 3, "current_attempt": 2},
                        "newer than",
                    ),
                )
                for changes, diagnostic in mismatches:
                    arguments = {
                        **identity,
                        "handoff": handoff,
                        "current_attempt": 2,
                        **changes,
                    }
                    with (
                        self.subTest(changes=changes),
                        self.assertRaisesRegex(ProtectedWriterError, diagnostic),
                    ):
                        validate_approved_writer_handoff(**arguments)

    def test_handoff_rejects_non_authoritative_runtime_identity(self) -> None:
        identity = handoff_identity("release-plan.yml")
        mismatches = (
            ({"workflow": "outside.yml"}, "not allowlisted"),
            ({"repository": "outside/fork"}, "repository mismatch"),
            ({"ref": "refs/heads/feature"}, "ref mismatch"),
            ({"source_sha": "A" * 40}, "full lowercase commit"),
            ({"run_id": 0}, "positive integer"),
        )
        for changes, diagnostic in mismatches:
            with (
                self.subTest(changes=changes),
                self.assertRaisesRegex(ProtectedWriterError, diagnostic),
            ):
                approved_writer_handoff(**{**identity, **changes})

    def test_protected_waits_are_read_only_and_outside_the_writer_lock(self) -> None:
        for workflow_name, contract in WORKFLOW_CONTRACTS.items():
            with self.subTest(workflow=workflow_name):
                workflow = load_workflow(workflow_name)
                approval = workflow["jobs"][contract["approval"]]
                writer = workflow["jobs"][contract["writer"]]

                self.assertNotIn("concurrency", workflow)
                self.assertEqual(contract["environment"], approval["environment"])
                self.assertEqual(contract["permissions"], approval["permissions"])
                self.assertNotIn("write", approval["permissions"].values())
                self.assertNotIn("concurrency", approval)
                approval_checkout = next(
                    step for step in approval["steps"] if "actions/checkout" in step.get("uses", "")
                )
                self.assertIs(approval_checkout["with"]["persist-credentials"], False)
                self.assertEqual("${{ github.sha }}", approval_checkout["with"]["ref"])

                self.assertEqual(contract["approval"], writer["needs"])
                self.assertIn(
                    f"needs.{contract['approval']}.result == 'success'",
                    writer["if"],
                )
                self.assertNotIn("environment", writer)
                self.assertEqual(WRITER_CONCURRENCY, writer["concurrency"])
                self.assertEqual("write", writer["permissions"]["contents"])
                for job_name, job in workflow["jobs"].items():
                    if job_name != contract["writer"]:
                        self.assertNotIn("concurrency", job)

    def test_writers_validate_the_exact_approved_job_before_mutation(self) -> None:
        mutation_steps = {
            "release-plan.yml": "Create or compare the immutable Git record",
            "release-plan-supersession.yml": "Create or compare immutable terminal record",
        }
        for workflow_name, contract in WORKFLOW_CONTRACTS.items():
            with self.subTest(workflow=workflow_name):
                workflow = load_workflow(workflow_name)
                approval = workflow["jobs"][contract["approval"]]
                writer = workflow["jobs"][contract["writer"]]
                approval_step = next(step for step in approval["steps"] if step.get("id") == "approval")
                validation = next(
                    step
                    for step in writer["steps"]
                    if "protected_release_plan_writer.py validate" in step.get("run", "")
                )
                mutation = next(step for step in writer["steps"] if step.get("name") == mutation_steps[workflow_name])

                self.assertIn("protected_release_plan_writer.py create", approval_step["run"])
                self.assertIn(f"--workflow {workflow_name}", approval_step["run"])
                for option, value in (
                    ("--repository", '"$GITHUB_REPOSITORY"'),
                    ("--ref", '"$GITHUB_REF"'),
                    ("--workflow-ref", '"$GITHUB_WORKFLOW_REF"'),
                    ("--source-sha", '"$GITHUB_SHA"'),
                    ("--run-id", '"$GITHUB_RUN_ID"'),
                    ("--run-attempt", '"$GITHUB_RUN_ATTEMPT"'),
                ):
                    self.assertIn(f"{option} {value}", approval_step["run"])
                self.assertIn(f"--workflow {workflow_name}", validation["run"])
                for option in (
                    "--repository",
                    "--ref",
                    "--workflow-ref",
                    "--source-sha",
                    "--run-id",
                    "--current-attempt",
                    "--producer-attempt",
                    "--handoff",
                ):
                    self.assertIn(option, validation["run"])
                self.assertLess(writer["steps"].index(validation), writer["steps"].index(mutation))

    def test_pending_reviews_do_not_expand_the_scheduled_observer_queue(self) -> None:
        observer = load_workflow("release-plan-observer.yml")
        self.assertEqual(WRITER_CONCURRENCY, observer["concurrency"])

        for workflow_name in WORKFLOW_CONTRACTS:
            with self.subTest(pending_workflow=workflow_name):
                # The protected job is pending and owns no concurrency group.
                running: str | None = None
                pending: str | None = None
                superseded: list[str] = []

                for observer_run in (
                    "scheduled-observer-1",
                    "scheduled-observer-2",
                    "scheduled-observer-3",
                ):
                    running, pending = schedule_observer(
                        observer_run,
                        running,
                        pending,
                        superseded,
                    )

                self.assertEqual("scheduled-observer-1", running)
                self.assertEqual("scheduled-observer-3", pending)
                self.assertEqual(["scheduled-observer-2"], superseded)
                self.assertEqual(2, len({running, pending} - {None}))

                running, pending = pending, None
                self.assertEqual("scheduled-observer-3", running)
                running = None
                self.assertIsNone(running)
                self.assertIsNone(pending)

    def test_continuity_dispatch_consumes_only_the_successful_writer(self) -> None:
        workflow = load_workflow("release-plan.yml")
        dispatch = workflow["jobs"]["dispatch-accepted-continuity"]

        self.assertEqual("validate-and-record", dispatch["needs"])
        self.assertIn(
            "needs.validate-and-record.outputs.channel != 'rc'",
            dispatch["if"],
        )
        self.assertEqual(
            {"actions": "write", "contents": "read"},
            dispatch["permissions"],
        )
        self.assertNotIn("environment", dispatch)
        self.assertNotIn("concurrency", dispatch)
        self.assertNotIn("needs.authorize", str(dispatch))


if __name__ == "__main__":
    unittest.main()
