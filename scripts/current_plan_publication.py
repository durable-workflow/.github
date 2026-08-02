#!/usr/bin/env python3
"""Validate protected current-plan publication and its approved writer handoff."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import re
import sys
from pathlib import Path
from typing import Any

CONTROL_REPOSITORY = "durable-workflow/.github"
AUTHORITY_REF = "main"
CURRENT_PLAN_WORKFLOW = "current-release-plan.yml"
CURRENT_PLAN_WORKFLOW_PATH = f".github/workflows/{CURRENT_PLAN_WORKFLOW}"
CURRENT_PLAN_WORKFLOW_REF = (
    f"{CONTROL_REPOSITORY}/{CURRENT_PLAN_WORKFLOW_PATH}@refs/heads/{AUTHORITY_REF}"
)
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
HANDOFF_DOMAIN = b"durable-workflow.current-plan-writer-approval/v1\0"


class CurrentPlanPublicationError(ValueError):
    """The current-plan publication runtime is absent or mismatched."""


def _identity(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise CurrentPlanPublicationError(f"current-plan publication {label} is absent")
    return value


def validate_runtime_identity(repository: Any, ref: Any, workflow_ref: Any) -> None:
    repository = _identity(repository, "repository")
    ref = _identity(ref, "ref")
    workflow_ref = _identity(workflow_ref, "workflow identity")

    if repository != CONTROL_REPOSITORY:
        raise CurrentPlanPublicationError(
            "current-plan publication repository mismatch: "
            f"expected {CONTROL_REPOSITORY}, got {repository}"
        )
    expected_ref = f"refs/heads/{AUTHORITY_REF}"
    if ref != expected_ref:
        raise CurrentPlanPublicationError(
            f"current-plan publication ref mismatch: expected {expected_ref}, got {ref}"
        )
    if workflow_ref != CURRENT_PLAN_WORKFLOW_REF:
        raise CurrentPlanPublicationError(
            "current-plan publication workflow mismatch: "
            f"expected {CURRENT_PLAN_WORKFLOW_REF}, got {workflow_ref}"
        )


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise CurrentPlanPublicationError(f"current-plan publication {label} must be a positive integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise CurrentPlanPublicationError(f"current-plan publication {label} must be a positive integer") from error
    if parsed < 1:
        raise CurrentPlanPublicationError(f"current-plan publication {label} must be a positive integer")
    return parsed


def approved_writer_handoff(
    repository: Any,
    ref: Any,
    workflow_ref: Any,
    source_sha: Any,
    run_id: Any,
    producer_attempt: Any,
) -> str:
    """Bind environment-gated job success to one protected workflow run."""

    validate_runtime_identity(repository, ref, workflow_ref)
    source_sha = _identity(source_sha, "source SHA")
    if COMMIT_PATTERN.fullmatch(source_sha) is None:
        raise CurrentPlanPublicationError("current-plan publication source SHA must be a full lowercase commit")
    run_id = _positive_integer(run_id, "run ID")
    producer_attempt = _positive_integer(producer_attempt, "approval attempt")
    identity = "\0".join(
        (
            repository,
            ref,
            workflow_ref,
            source_sha,
            str(run_id),
            str(producer_attempt),
        )
    ).encode()
    return hashlib.sha256(HANDOFF_DOMAIN + identity).hexdigest()


def validate_approved_writer_handoff(
    handoff: Any,
    repository: Any,
    ref: Any,
    workflow_ref: Any,
    source_sha: Any,
    run_id: Any,
    current_attempt: Any,
    producer_attempt: Any,
) -> None:
    handoff = _identity(handoff, "approved writer handoff")
    current_attempt = _positive_integer(current_attempt, "current attempt")
    producer_attempt_value = _positive_integer(producer_attempt, "approval attempt")
    if producer_attempt_value > current_attempt:
        raise CurrentPlanPublicationError("current-plan publication approval attempt is newer than the writer attempt")
    expected = approved_writer_handoff(
        repository,
        ref,
        workflow_ref,
        source_sha,
        run_id,
        producer_attempt_value,
    )
    if not hmac.compare_digest(handoff, expected):
        raise CurrentPlanPublicationError(
            "current-plan publication approved writer handoff does not match this workflow run"
        )


def write_github_output(path: Path, values: dict[str, str | int]) -> None:
    with path.open("a", encoding="utf-8") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")


def add_runtime_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--workflow-ref", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser(
        "validate-runtime",
        help="fail unless the protected current-plan workflow is running on its exact authority",
    )
    add_runtime_arguments(validate)
    create_handoff = subparsers.add_parser(
        "create-approved-writer-handoff",
        help="bind a completed protected-environment job to its exact workflow run",
    )
    add_runtime_arguments(create_handoff)
    create_handoff.add_argument("--source-sha", required=True)
    create_handoff.add_argument("--run-id", required=True)
    create_handoff.add_argument("--run-attempt", required=True)
    create_handoff.add_argument("--github-output", required=True, type=Path)
    validate_handoff = subparsers.add_parser(
        "validate-approved-writer-handoff",
        help="fail unless the privileged writer follows an exact approved job",
    )
    add_runtime_arguments(validate_handoff)
    validate_handoff.add_argument("--source-sha", required=True)
    validate_handoff.add_argument("--run-id", required=True)
    validate_handoff.add_argument("--current-attempt", required=True)
    validate_handoff.add_argument("--producer-attempt", required=True)
    validate_handoff.add_argument("--handoff", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "validate-runtime":
            validate_runtime_identity(
                arguments.repository,
                arguments.ref,
                arguments.workflow_ref,
            )
        elif arguments.command == "create-approved-writer-handoff":
            handoff = approved_writer_handoff(
                arguments.repository,
                arguments.ref,
                arguments.workflow_ref,
                arguments.source_sha,
                arguments.run_id,
                arguments.run_attempt,
            )
            write_github_output(
                arguments.github_output,
                {
                    "handoff": handoff,
                    "producer-attempt": _positive_integer(arguments.run_attempt, "approval attempt"),
                },
            )
        elif arguments.command == "validate-approved-writer-handoff":
            validate_approved_writer_handoff(
                arguments.handoff,
                arguments.repository,
                arguments.ref,
                arguments.workflow_ref,
                arguments.source_sha,
                arguments.run_id,
                arguments.current_attempt,
                arguments.producer_attempt,
            )
    except CurrentPlanPublicationError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
