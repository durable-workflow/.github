#!/usr/bin/env python3
"""Propose one qualified reconciliation for protected recovery workflow drift."""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.beta_candidate import COMPONENTS, CandidateError, PublicClient, canonical_json, write_github_output
from scripts.recovery_workflow_authority import (
    AUTHORITY_PATH,
    CHECK_RUN_APP,
    SOURCE_IDENTITIES_PATH,
    RecoveryWorkflowAuthorityError,
    branch_url,
    compare_url,
    exact_source_sha256,
    qualification_requirements,
    validate_authority,
    validate_source_identities,
    verify_authority_source_identities,
    workflow_metadata_url,
    workflow_run_url,
    workflow_source_url,
)

OBSERVATION_SCHEMA = "durable-workflow.component-release-recovery-authority-observation/v1"
DEFAULT_BRANCHES = {
    "workflow": "v2",
    "waterline": "v2",
    "server": "main",
    "cli": "main",
    "sdk-php": "main",
    "sdk-python": "main",
    "sdk-rust": "main",
}


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RecoveryWorkflowAuthorityError(f"cannot read {label}: {error}") from error
    if not isinstance(value, dict):
        raise RecoveryWorkflowAuthorityError(f"{label} must contain a JSON object")
    return value


def component_identities() -> dict[str, tuple[str, str]]:
    return {name: (component.repository, DEFAULT_BRANCHES[name]) for name, component in COMPONENTS.items()}


def check_runs_url(repository: str, commit: str) -> str:
    return f"https://api.github.com/repos/{repository}/commits/{commit}/check-runs?filter=latest&per_page=100"


def _qualified_identity(
    client: Any,
    name: str,
    repository: str,
    branch: str,
    commit: str,
    requirement: Mapping[str, str],
) -> dict[str, Any]:
    response = client.json(check_runs_url(repository, commit))
    check_runs = response.get("check_runs") if isinstance(response, dict) else None
    if not isinstance(check_runs, list):
        raise RecoveryWorkflowAuthorityError(f"{name} recovery qualification checks have an invalid response")
    matching = [
        check for check in check_runs if isinstance(check, dict) and check.get("name") == requirement["required_check"]
    ]
    if not matching:
        raise RecoveryWorkflowAuthorityError(f"{name} recovery workflow source has no protected qualification check")
    check = max(matching, key=lambda value: value.get("id") if isinstance(value.get("id"), int) else 0)
    check_run_id = check.get("id")
    app = check.get("app")
    if (
        not isinstance(check_run_id, int)
        or isinstance(check_run_id, bool)
        or check_run_id < 1
        or check.get("head_sha") != commit
        or check.get("status") != "completed"
        or check.get("conclusion") != "success"
        or not isinstance(app, dict)
        or app.get("slug") != CHECK_RUN_APP
    ):
        raise RecoveryWorkflowAuthorityError(
            f"{name} recovery workflow source is not protected by a successful GitHub Actions check"
        )
    check_url = check.get("html_url")
    match = (
        re.fullmatch(
            rf"https://github\.com/{re.escape(repository)}/actions/runs/([1-9][0-9]*)/job/{check_run_id}",
            check_url,
        )
        if isinstance(check_url, str)
        else None
    )
    if match is None:
        raise RecoveryWorkflowAuthorityError(
            f"{name} recovery qualification check has an invalid workflow-run identity"
        )
    run_id = int(match.group(1))
    run = client.json(workflow_run_url(repository, run_id))
    run_attempt = run.get("run_attempt") if isinstance(run, dict) else None
    expected_run = {
        "id": run_id,
        "path": requirement["workflow"],
        "event": "push",
        "head_branch": branch,
        "head_sha": commit,
        "status": "completed",
        "conclusion": "success",
        "html_url": f"https://github.com/{repository}/actions/runs/{run_id}",
    }
    if (
        not isinstance(run, dict)
        or not isinstance(run_attempt, int)
        or isinstance(run_attempt, bool)
        or run_attempt < 1
        or any(run.get(field) != expected for field, expected in expected_run.items())
    ):
        raise RecoveryWorkflowAuthorityError(
            f"{name} recovery qualification is not an exact successful protected-branch run"
        )
    return {
        "check_run_id": check_run_id,
        "check_url": check_url,
        "conclusion": "success",
        "event": "push",
        "head_branch": branch,
        "head_sha": commit,
        "required_check": requirement["required_check"],
        "run_attempt": run_attempt,
        "run_id": run_id,
        "status": "completed",
        "url": expected_run["html_url"],
        "workflow": requirement["workflow"],
    }


def _protected_branch_observation(
    client: Any,
    name: str,
    workflow: Mapping[str, str],
    requirement: Mapping[str, str],
) -> dict[str, Any]:
    repository = workflow["repository"]
    branch = workflow["ref"].removeprefix("refs/heads/")
    branch_data = client.json(branch_url(repository, branch))
    commit = branch_data.get("commit", {}).get("sha") if isinstance(branch_data, dict) else None
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise RecoveryWorkflowAuthorityError(f"{name} recovery protected branch did not resolve to an exact commit")
    metadata = client.json(workflow_metadata_url(repository, workflow["path"]))
    if (
        not isinstance(metadata, dict)
        or metadata.get("path") != workflow["path"]
        or metadata.get("state") != workflow["state"]
    ):
        raise RecoveryWorkflowAuthorityError(f"{name} recovery workflow does not expose the protected path and state")
    raw = client.bytes(
        workflow_source_url(repository, workflow["path"], commit),
        accept="application/vnd.github.raw+json",
    )
    return {
        "source_commit": commit,
        "sha256": exact_source_sha256(raw),
        "qualification": _qualified_identity(
            client,
            name,
            repository,
            branch,
            commit,
            requirement,
        ),
    }


def reconcile_authority(
    authority: dict[str, Any],
    source_document: dict[str, Any],
    policy: dict[str, Any],
    client: Any,
    components: Mapping[str, tuple[str, str]],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    workflows = validate_authority(authority, components)
    requirements = qualification_requirements(policy, components)
    source_identities = validate_source_identities(
        source_document,
        workflows,
        components,
        requirements,
    )
    verify_authority_source_identities(
        client,
        workflows,
        source_identities,
        requirements,
        require_current=False,
    )

    proposed_authority = copy.deepcopy(authority)
    proposed_sources = copy.deepcopy(source_document)
    changes: list[dict[str, Any]] = []
    for name, workflow in workflows.items():
        observation = _protected_branch_observation(
            client,
            name,
            workflow,
            requirements[name],
        )
        current = source_identities[name]["identities"][-1]
        if observation["sha256"] == current["sha256"]:
            continue

        repository = workflow["repository"]
        comparison = client.json(compare_url(repository, current["source_commit"], observation["source_commit"]))
        if (
            not isinstance(comparison, dict)
            or comparison.get("status") != "ahead"
            or comparison.get("base_commit", {}).get("sha") != current["source_commit"]
            or comparison.get("merge_base_commit", {}).get("sha") != current["source_commit"]
        ):
            raise RecoveryWorkflowAuthorityError(
                f"{name} recovery workflow successor does not descend from the accepted identity"
            )
        successor = {
            **observation,
            "supersedes": {
                "source_commit": current["source_commit"],
                "sha256": current["sha256"],
            },
        }
        proposed_authority["workflows"][name]["sha256"] = successor["sha256"]
        proposed_sources["workflows"][name]["identities"].append(successor)
        changes.append(
            {
                "component": name,
                "previous": successor["supersedes"],
                "successor": {
                    "source_commit": successor["source_commit"],
                    "sha256": successor["sha256"],
                    "qualification": successor["qualification"],
                },
            }
        )

    proposed_workflows = validate_authority(proposed_authority, components)
    validate_source_identities(
        proposed_sources,
        proposed_workflows,
        components,
        requirements,
    )
    observation = {
        "schema": OBSERVATION_SCHEMA,
        "outcome": "change-required" if changes else "current",
        "changes": changes,
    }
    return proposed_authority, proposed_sources, observation


def _write_reconciliation(
    authority_path: Path,
    source_path: Path,
    policy_path: Path,
    proposed_authority_path: Path,
    proposed_source_path: Path,
    observation_path: Path,
    client: Any,
    github_output: Path | None,
) -> dict[str, Any]:
    proposed_authority, proposed_sources, observation = reconcile_authority(
        _load_json(authority_path, "recovery workflow authority"),
        _load_json(source_path, "recovery protected source identities"),
        _load_json(policy_path, "qualification policy"),
        client,
        component_identities(),
    )
    proposed_authority_path.write_bytes(canonical_json(proposed_authority))
    proposed_source_path.write_bytes(canonical_json(proposed_sources))
    observation_path.write_bytes(canonical_json(observation))
    write_github_output(
        github_output,
        {
            "changed": "true" if observation["changes"] else "false",
            "components": ",".join(change["component"] for change in observation["changes"]),
        },
    )
    return observation


def _verify_proposal(
    authority_path: Path,
    source_path: Path,
    policy_path: Path,
    proposed_authority_path: Path,
    proposed_source_path: Path,
    observation_path: Path,
    client: Any,
) -> dict[str, Any]:
    expected_authority, expected_sources, expected_observation = reconcile_authority(
        _load_json(authority_path, "recovery workflow authority"),
        _load_json(source_path, "recovery protected source identities"),
        _load_json(policy_path, "qualification policy"),
        client,
        component_identities(),
    )
    supplied_authority = _load_json(proposed_authority_path, "proposed recovery workflow authority")
    supplied_sources = _load_json(proposed_source_path, "proposed recovery protected source identities")
    supplied_observation = _load_json(observation_path, "recovery authority observation")
    if (
        canonical_json(supplied_authority) != canonical_json(expected_authority)
        or canonical_json(supplied_sources) != canonical_json(expected_sources)
        or canonical_json(supplied_observation) != canonical_json(expected_observation)
    ):
        raise RecoveryWorkflowAuthorityError(
            "recovery authority proposal differs from the current qualified observation"
        )
    if not expected_observation["changes"]:
        raise RecoveryWorkflowAuthorityError("recovery authority proposal contains no reconciliation")
    return expected_observation


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("reconcile", "verify-proposal"))
    parser.add_argument("--authority", type=Path, default=Path(AUTHORITY_PATH))
    parser.add_argument("--source-identities", type=Path, default=Path(SOURCE_IDENTITIES_PATH))
    parser.add_argument("--policy", type=Path, default=Path("qualification/policy.json"))
    parser.add_argument("--proposed-authority", type=Path, required=True)
    parser.add_argument("--proposed-source-identities", type=Path, required=True)
    parser.add_argument("--observation", type=Path, required=True)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN"))
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        client = PublicClient(args.github_token)
        if args.command == "reconcile":
            result = _write_reconciliation(
                args.authority,
                args.source_identities,
                args.policy,
                args.proposed_authority,
                args.proposed_source_identities,
                args.observation,
                client,
                args.github_output,
            )
        else:
            result = _verify_proposal(
                args.authority,
                args.source_identities,
                args.policy,
                args.proposed_authority,
                args.proposed_source_identities,
                args.observation,
                client,
            )
        print(json.dumps(result, sort_keys=True))
        return 0
    except (CandidateError, RecoveryWorkflowAuthorityError) as error:
        print(f"recovery authority reconciliation error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
