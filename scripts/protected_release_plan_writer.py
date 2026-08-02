#!/usr/bin/env python3
"""Bind protected release-plan jobs to their serialized writers."""

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
PROTECTED_WORKFLOWS = frozenset(
    {
        "release-plan.yml",
        "release-plan-supersession.yml",
    }
)
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
HANDOFF_DOMAIN = b"durable-workflow.protected-release-plan-writer/v1\0"


class ProtectedWriterError(ValueError):
    """A protected release-plan writer identity is absent or mismatched."""


def _identity(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ProtectedWriterError(f"protected release-plan {label} is absent")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise ProtectedWriterError(f"protected release-plan {label} must be a positive integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise ProtectedWriterError(f"protected release-plan {label} must be a positive integer") from error
    if parsed < 1:
        raise ProtectedWriterError(f"protected release-plan {label} must be a positive integer")
    return parsed


def expected_workflow_ref(workflow: Any) -> str:
    workflow = _identity(workflow, "workflow")
    if workflow not in PROTECTED_WORKFLOWS:
        raise ProtectedWriterError(f"protected release-plan workflow is not allowlisted: {workflow}")
    return f"{CONTROL_REPOSITORY}/.github/workflows/{workflow}@refs/heads/{AUTHORITY_REF}"


def validate_runtime_identity(
    workflow: Any,
    repository: Any,
    ref: Any,
    workflow_ref: Any,
) -> tuple[str, str, str, str]:
    workflow = _identity(workflow, "workflow")
    repository = _identity(repository, "repository")
    ref = _identity(ref, "ref")
    workflow_ref = _identity(workflow_ref, "workflow ref")

    if repository != CONTROL_REPOSITORY:
        raise ProtectedWriterError(
            f"protected release-plan repository mismatch: expected {CONTROL_REPOSITORY}, got {repository}"
        )
    expected_ref = f"refs/heads/{AUTHORITY_REF}"
    if ref != expected_ref:
        raise ProtectedWriterError(f"protected release-plan ref mismatch: expected {expected_ref}, got {ref}")
    expected = expected_workflow_ref(workflow)
    if workflow_ref != expected:
        raise ProtectedWriterError(f"protected release-plan workflow mismatch: expected {expected}, got {workflow_ref}")
    return workflow, repository, ref, workflow_ref


def approved_writer_handoff(
    workflow: Any,
    repository: Any,
    ref: Any,
    workflow_ref: Any,
    source_sha: Any,
    run_id: Any,
    producer_attempt: Any,
) -> str:
    """Bind one successful protected job to its exact workflow run."""

    workflow, repository, ref, workflow_ref = validate_runtime_identity(
        workflow,
        repository,
        ref,
        workflow_ref,
    )
    source_sha = _identity(source_sha, "source SHA")
    if COMMIT_PATTERN.fullmatch(source_sha) is None:
        raise ProtectedWriterError("protected release-plan source SHA must be a full lowercase commit")
    run_id = _positive_integer(run_id, "run ID")
    producer_attempt = _positive_integer(producer_attempt, "approval attempt")
    identity = "\0".join(
        (
            workflow,
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
    workflow: Any,
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
        raise ProtectedWriterError("protected release-plan approval attempt is newer than the writer attempt")
    expected = approved_writer_handoff(
        workflow,
        repository,
        ref,
        workflow_ref,
        source_sha,
        run_id,
        producer_attempt_value,
    )
    if not hmac.compare_digest(handoff, expected):
        raise ProtectedWriterError("protected release-plan approved writer handoff does not match this workflow run")


def write_github_output(path: Path, values: dict[str, str | int]) -> None:
    with path.open("a", encoding="utf-8") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")


def add_identity_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workflow", required=True, choices=sorted(PROTECTED_WORKFLOWS))
    parser.add_argument("--repository", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--workflow-ref", required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--run-id", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    create = subparsers.add_parser(
        "create",
        help="bind a successful protected job to its exact workflow run",
    )
    add_identity_arguments(create)
    create.add_argument("--run-attempt", required=True)
    create.add_argument("--github-output", required=True, type=Path)
    validate = subparsers.add_parser(
        "validate",
        help="fail unless a writer follows the exact successful protected job",
    )
    add_identity_arguments(validate)
    validate.add_argument("--current-attempt", required=True)
    validate.add_argument("--producer-attempt", required=True)
    validate.add_argument("--handoff", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "create":
            handoff = approved_writer_handoff(
                arguments.workflow,
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
                    "producer-attempt": _positive_integer(
                        arguments.run_attempt,
                        "approval attempt",
                    ),
                },
            )
        elif arguments.command == "validate":
            validate_approved_writer_handoff(
                arguments.handoff,
                arguments.workflow,
                arguments.repository,
                arguments.ref,
                arguments.workflow_ref,
                arguments.source_sha,
                arguments.run_id,
                arguments.current_attempt,
                arguments.producer_attempt,
            )
    except ProtectedWriterError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
