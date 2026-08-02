#!/usr/bin/env python3
"""Validate the protected runtime identity for current-plan publication."""

from __future__ import annotations

import argparse
import sys
from typing import Any

CONTROL_REPOSITORY = "durable-workflow/.github"
AUTHORITY_REF = "main"
CURRENT_PLAN_WORKFLOW = "current-release-plan.yml"
CURRENT_PLAN_WORKFLOW_PATH = f".github/workflows/{CURRENT_PLAN_WORKFLOW}"
CURRENT_PLAN_WORKFLOW_REF = (
    f"{CONTROL_REPOSITORY}/{CURRENT_PLAN_WORKFLOW_PATH}@refs/heads/{AUTHORITY_REF}"
)


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser(
        "validate-runtime",
        help="fail unless the protected current-plan workflow is running on its exact authority",
    )
    validate.add_argument("--repository", required=True)
    validate.add_argument("--ref", required=True)
    validate.add_argument("--workflow-ref", required=True)
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
    except CurrentPlanPublicationError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
