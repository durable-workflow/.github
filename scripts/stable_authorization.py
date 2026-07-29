#!/usr/bin/env python3
"""Evaluate and record the protected stable 2.0 authorization decision."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.beta_authorization import user_identity
from scripts.beta_candidate import (
    COMPONENTS,
    VERSION_PATTERN,
    CandidateError,
    PublicClient,
    canonical_json,
    fetch_existing_record,
    manifest_digest,
    read_record_file,
    run_git,
    write_github_output,
)
from scripts.release_plan import read_public_record, resolve_tag

CONTRACT_SCHEMA = "durable-workflow.stable-authorization.contract/v1"
REQUEST_SCHEMA = "durable-workflow.stable-authorization-request/v1"
EXPERIMENT_EVIDENCE_SCHEMA = "durable-workflow.release-critical-experiment-evidence/v1"
READOUT_SCHEMA = "durable-workflow.stable-authorization-readout/v1"
AUTHORIZATION_SCHEMA = "durable-workflow.stable-authorization/v1"
CONTROL_REPOSITORY = "durable-workflow/.github"
STABLE_VERSION = "2.0.0"
AUTHORIZATION_ENVIRONMENT = "stable-authorization"
AUTHORIZATION_WORKFLOW = ".github/workflows/stable-authorization.yml"
AUTHORIZATION_WORKFLOW_REF = "durable-workflow/.github/.github/workflows/stable-authorization.yml@refs/heads/main"
CONTRACT_URL = "https://raw.githubusercontent.com/durable-workflow/.github/main/stable-authorization/contract.json"
AUTHORIZATION_TAG_PREFIX = f"stable-authorization/{STABLE_VERSION}/"
PRODUCT_OWNER_REVIEWER_ID = 1130888
API_VERSION = "2022-11-28"
COMPONENT_NAMES = tuple(COMPONENTS)
RELEASE_CRITICAL_EXPERIMENTS = (
    "activities",
    "cloud",
    "heartbeats",
    "namespaces",
    "polyglot",
    "replay",
    "signals-queries",
    "timers",
    "worker-versioning",
    "workflow-lifecycle",
    "workflow-updates",
    "python",
)
POLYGLOT_CELLS = ("php", "python", "rust")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
LOGIN_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,39}$")
CANDIDATE_TAG_PATTERN = re.compile(r"^release-candidate/rc/(?P<candidate>[a-z0-9][a-z0-9._-]{0,55})$")
MAX_REQUEST_BYTES = 1024 * 1024
MAX_EVIDENCE_BYTES = 2 * 1024 * 1024


def require_exact_keys(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise CandidateError(f"{context} keys must be exactly {sorted(expected)}")
    return value


def parse_json_file(path: Path, context: str, *, maximum_bytes: int) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CandidateError(f"cannot read {context} {path}: {error}") from error
    if len(raw) > maximum_bytes:
        raise CandidateError(f"{context} exceeds the {maximum_bytes}-byte limit")
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise CandidateError(f"{context} is not valid JSON: {error}") from error


def validate_contract(value: Any) -> dict[str, Any]:
    contract = require_exact_keys(
        value,
        {
            "$schema",
            "schema",
            "stable_version",
            "artifact_components",
            "release_critical_experiments",
            "required_sdk_cells",
            "evidence_policy",
            "human_decision",
        },
        "stable authorization contract",
    )
    expected = {
        "$schema": "./contract-schema.json",
        "schema": CONTRACT_SCHEMA,
        "stable_version": STABLE_VERSION,
        "artifact_components": list(COMPONENT_NAMES),
        "release_critical_experiments": list(RELEASE_CRITICAL_EXPERIMENTS),
        "required_sdk_cells": {"polyglot": list(POLYGLOT_CELLS)},
        "evidence_policy": {
            "artifact_tuple_binding": "exact",
            "missing": "deny",
            "stale": "deny",
            "non_passing": "deny",
            "runner_blocked": "deny",
            "aggregate_historical_pass_rate": "never_authoritative",
        },
        "human_decision": {
            "required": True,
            "occurs_after_evidence_gate": True,
        },
    }
    if contract != expected:
        raise CandidateError("stable authorization contract differs from the fixed release-critical tier")
    return contract


def load_contract(path: Path) -> dict[str, Any]:
    return validate_contract(parse_json_file(path, "stable authorization contract", maximum_bytes=256 * 1024))


def validate_binding(value: Any, context: str) -> dict[str, Any]:
    binding = require_exact_keys(value, {"tag", "commit", "sha256"}, context)
    if (
        not isinstance(binding["tag"], str)
        or CANDIDATE_TAG_PATTERN.fullmatch(binding["tag"]) is None
        or not isinstance(binding["commit"], str)
        or COMMIT_PATTERN.fullmatch(binding["commit"]) is None
        or not isinstance(binding["sha256"], str)
        or SHA256_PATTERN.fullmatch(binding["sha256"]) is None
    ):
        raise CandidateError(f"{context} must identify one immutable RC artifact tuple")
    return binding


def validate_artifact_tuple(value: Any) -> dict[str, Any]:
    artifact_tuple = require_exact_keys(value, {"tag", "commit", "components"}, "artifact tuple")
    if (
        not isinstance(artifact_tuple["tag"], str)
        or CANDIDATE_TAG_PATTERN.fullmatch(artifact_tuple["tag"]) is None
        or not isinstance(artifact_tuple["commit"], str)
        or COMMIT_PATTERN.fullmatch(artifact_tuple["commit"]) is None
    ):
        raise CandidateError("artifact tuple must cite one immutable RC candidate tag and commit")
    components = artifact_tuple["components"]
    if not isinstance(components, dict) or set(components) != set(COMPONENT_NAMES):
        raise CandidateError(f"artifact tuple components must be exactly {list(COMPONENT_NAMES)}")
    for name in COMPONENT_NAMES:
        component = require_exact_keys(
            components[name],
            {"version", "commit"},
            f"artifact tuple component {name}",
        )
        if (
            not isinstance(component["version"], str)
            or VERSION_PATTERN.fullmatch(component["version"]) is None
            or not isinstance(component["commit"], str)
            or COMMIT_PATTERN.fullmatch(component["commit"]) is None
        ):
            raise CandidateError(f"artifact tuple component {name} has an invalid immutable identity")
    return artifact_tuple


def validate_generated_at(value: Any, context: str) -> None:
    if not isinstance(value, str):
        raise CandidateError(f"{context} generated_at must be a date-time")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise CandidateError(f"{context} generated_at must be a date-time") from error
    if parsed.tzinfo is None:
        raise CandidateError(f"{context} generated_at must include a timezone")


def validate_cell(value: Any, context: str) -> dict[str, Any]:
    cell = require_exact_keys(value, {"outcome", "runner_blocked", "artifact_tuple"}, context)
    if cell["outcome"] not in {"pass", "fail", "error"} or not isinstance(cell["runner_blocked"], bool):
        raise CandidateError(f"{context} has an invalid outcome")
    validate_binding(cell["artifact_tuple"], f"{context} artifact tuple")
    return cell


def validate_experiment_evidence(
    value: Any,
    experiment: str,
) -> dict[str, Any]:
    expected_keys = {
        "schema",
        "experiment",
        "outcome",
        "runner_blocked",
        "artifact_tuple",
        "source",
    }
    if experiment == "polyglot":
        expected_keys.add("cells")
    evidence = require_exact_keys(value, expected_keys, f"{experiment} evidence")
    if (
        evidence["schema"] != EXPERIMENT_EVIDENCE_SCHEMA
        or evidence["experiment"] != experiment
        or evidence["outcome"] not in {"pass", "fail", "error"}
        or not isinstance(evidence["runner_blocked"], bool)
    ):
        raise CandidateError(f"{experiment} evidence has an invalid outcome contract")
    validate_binding(evidence["artifact_tuple"], f"{experiment} evidence artifact tuple")
    source = require_exact_keys(
        evidence["source"],
        {"url", "sha256", "generated_at"},
        f"{experiment} evidence source",
    )
    public_source_prefixes = (
        "https://github.com/durable-workflow/",
        "https://raw.githubusercontent.com/durable-workflow/",
    )
    if (
        not isinstance(source["url"], str)
        or not source["url"].startswith(public_source_prefixes)
        or not isinstance(source["sha256"], str)
        or SHA256_PATTERN.fullmatch(source["sha256"]) is None
    ):
        raise CandidateError(f"{experiment} evidence source must be public and digest-bound")
    validate_generated_at(source["generated_at"], f"{experiment} evidence source")
    if experiment == "polyglot":
        cells = evidence["cells"]
        if not isinstance(cells, dict) or not set(cells) <= set(POLYGLOT_CELLS):
            raise CandidateError("polyglot evidence contains an unknown SDK cell")
        for cell in POLYGLOT_CELLS:
            if cell in cells:
                validate_cell(cells[cell], f"polyglot {cell} cell")
    return evidence


def validate_request(value: Any) -> dict[str, Any]:
    request = require_exact_keys(
        value,
        {"$schema", "schema", "stable_version", "artifact_tuple", "evidence"},
        "stable authorization request",
    )
    if (
        request["$schema"] != "./request-schema.json"
        or request["schema"] != REQUEST_SCHEMA
        or request["stable_version"] != STABLE_VERSION
    ):
        raise CandidateError("stable authorization request must select only stable 2.0.0")
    validate_artifact_tuple(request["artifact_tuple"])
    evidence = require_exact_keys(
        request["evidence"],
        {"experiments"},
        "stable authorization request evidence",
    )
    experiments = evidence["experiments"]
    if not isinstance(experiments, dict) or not set(experiments) <= set(RELEASE_CRITICAL_EXPERIMENTS):
        raise CandidateError("stable authorization request contains an unknown experiment")
    for experiment, record in experiments.items():
        validate_experiment_evidence(record, experiment)
    return request


def load_request(path: Path) -> dict[str, Any]:
    return validate_request(parse_json_file(path, "stable authorization request", maximum_bytes=MAX_REQUEST_BYTES))


def tuple_binding(artifact_tuple: dict[str, Any]) -> dict[str, str]:
    return {
        "tag": artifact_tuple["tag"],
        "commit": artifact_tuple["commit"],
        "sha256": manifest_digest(artifact_tuple),
    }


def status_for_record(
    record: dict[str, Any] | None,
    expected_binding: dict[str, str],
) -> dict[str, Any]:
    if record is None:
        return {
            "freshness": "missing",
            "outcome": "missing",
            "status": "missing",
            "ready": False,
        }
    freshness = "current" if record["artifact_tuple"] == expected_binding else "stale"
    if record["runner_blocked"]:
        outcome = "runner-blocked"
    elif record["outcome"] == "pass":
        outcome = "pass"
    else:
        outcome = "fail"
    ready = freshness == "current" and outcome == "pass"
    return {
        "freshness": freshness,
        "outcome": outcome,
        "status": outcome if freshness == "current" else "stale",
        "ready": ready,
    }


def evaluate(
    contract: dict[str, Any],
    request: dict[str, Any],
) -> dict[str, Any]:
    validate_contract(contract)
    validate_request(request)
    artifact_tuple = request["artifact_tuple"]
    expected_binding = tuple_binding(artifact_tuple)
    evidence = request["evidence"]["experiments"]
    experiments: dict[str, dict[str, Any]] = {}
    for experiment in RELEASE_CRITICAL_EXPERIMENTS:
        record = evidence.get(experiment)
        status = status_for_record(record, expected_binding)
        cells: dict[str, dict[str, Any]] = {}
        if experiment == "polyglot":
            recorded_cells = record.get("cells", {}) if record is not None else {}
            for cell in POLYGLOT_CELLS:
                cells[cell] = status_for_record(recorded_cells.get(cell), expected_binding)
            status["ready"] = status["ready"] and all(cell["ready"] for cell in cells.values())
            if status["status"] == "pass" and not status["ready"]:
                status["status"] = "fail"
        status["source"] = record["source"] if record is not None else None
        status["cells"] = cells
        experiments[experiment] = status
    gate = "pass" if all(status["ready"] for status in experiments.values()) else "fail"
    return {
        "schema": READOUT_SCHEMA,
        "stable_version": STABLE_VERSION,
        "artifact_tuple": {
            "tag": artifact_tuple["tag"],
            "commit": artifact_tuple["commit"],
            "sha256": expected_binding["sha256"],
            "components": artifact_tuple["components"],
        },
        "contract": {
            "schema": CONTRACT_SCHEMA,
            "url": CONTRACT_URL,
            "sha256": manifest_digest(contract),
        },
        "evidence_gate": gate,
        "stable_authorization": ("awaiting-human-decision" if gate == "pass" else "blocked"),
        "prerelease_iteration": "allowed",
        "experiments": experiments,
        "historical_aggregate": {
            "release_authority": "never-authoritative",
        },
    }


def render_summary(readout: dict[str, Any]) -> str:
    lines = [
        "# Stable 2.0 release-critical evidence",
        "",
        f"Evidence gate: **{readout['evidence_gate']}**",
        "",
        "| Experiment or SDK cell | Freshness | Outcome | Ready |",
        "| --- | --- | --- | --- |",
    ]
    for experiment, status in readout["experiments"].items():
        lines.append(
            f"| {experiment} | {status['freshness']} | {status['outcome']} | {'yes' if status['ready'] else 'no'} |"
        )
        for cell, cell_status in status["cells"].items():
            lines.append(
                f"| {experiment}/{cell} | {cell_status['freshness']} | "
                f"{cell_status['outcome']} | {'yes' if cell_status['ready'] else 'no'} |"
            )
    lines.extend(
        [
            "",
            "Historical aggregate pass percentages are not release authority.",
            f"Prerelease iteration: {readout['prerelease_iteration']}.",
            "",
        ]
    )
    return "\n".join(lines)


def verified_readout(
    contract: dict[str, Any],
    request: dict[str, Any],
    path: Path,
) -> dict[str, Any]:
    value = parse_json_file(path, "stable authorization readout", maximum_bytes=MAX_EVIDENCE_BYTES)
    expected = evaluate(contract, request)
    if value != expected or path.read_bytes() != canonical_json(expected):
        raise CandidateError("stable authorization readout differs from the request and fixed contract")
    return expected


def require_ready(readout: dict[str, Any]) -> None:
    if readout["evidence_gate"] != "pass":
        failures = [name for name, status in readout["experiments"].items() if not status["ready"]]
        raise CandidateError("stable authorization is blocked by release-critical evidence: " + ", ".join(failures))
    if readout["stable_authorization"] != "awaiting-human-decision":
        raise CandidateError("passing evidence must still await an explicit human decision")


def verify_artifact_tuple_candidate(
    client: PublicClient,
    request: dict[str, Any],
) -> None:
    artifact_tuple = request["artifact_tuple"]
    resolved = resolve_tag(client, CONTROL_REPOSITORY, artifact_tuple["tag"])
    if resolved != artifact_tuple["commit"]:
        raise CandidateError("artifact tuple tag does not resolve to its requested immutable commit")
    candidate = read_public_record(
        client,
        artifact_tuple["tag"],
        artifact_tuple["commit"],
        "release-candidate.json",
    )
    if (
        not isinstance(candidate, dict)
        or candidate.get("schema") != "durable-workflow.release-candidate/v1"
        or candidate.get("channel") != "rc"
        or candidate.get("components") != artifact_tuple["components"]
    ):
        raise CandidateError("artifact tuple differs from its immutable RC candidate record")


def verify_evidence_sources(
    client: PublicClient,
    request: dict[str, Any],
) -> None:
    for experiment, record in request["evidence"]["experiments"].items():
        source = record["source"]
        raw = client.bytes(source["url"])
        if len(raw) > MAX_EVIDENCE_BYTES:
            raise CandidateError(f"{experiment} public evidence exceeds the 2 MiB limit")
        if hashlib.sha256(raw).hexdigest() != source["sha256"]:
            raise CandidateError(f"{experiment} public evidence digest differs")
        expected = {key: value for key, value in record.items() if key != "source"}
        if raw != canonical_json(expected):
            raise CandidateError(f"{experiment} public evidence differs from the authorization request")


def environment_urls() -> tuple[str, str]:
    activity = (
        f"https://github.com/{CONTROL_REPOSITORY}/deployments/activity_log"
        f"?environments_filter={AUTHORIZATION_ENVIRONMENT}"
    )
    api = f"https://api.github.com/repos/{CONTROL_REPOSITORY}/environments/{AUTHORIZATION_ENVIRONMENT}"
    return activity, api


def protected_environment_evidence(client: PublicClient) -> dict[str, Any]:
    activity_url, _api_url = environment_urls()
    encoded = urllib.parse.quote(AUTHORIZATION_ENVIRONMENT, safe="")
    headers = {"X-GitHub-Api-Version": API_VERSION}
    environment = client.json(
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/environments/{encoded}",
        headers=headers,
        accept="application/vnd.github+json",
    )
    rules = environment.get("protection_rules") if isinstance(environment, dict) else None
    reviewer_rules = [
        rule
        for rule in rules or []
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers" and rule.get("reviewers")
    ]
    rule_ids = sorted(rule["id"] for rule in reviewer_rules if type(rule.get("id")) is int and rule["id"] > 0)
    reviewer_user_ids = sorted(
        identity["id"]
        for rule in reviewer_rules
        for reviewer in rule.get("reviewers", [])
        if isinstance(reviewer, dict)
        and reviewer.get("type") == "User"
        and isinstance((identity := reviewer.get("reviewer")), dict)
        and type(identity.get("id")) is int
        and identity["id"] > 0
    )
    branch_policy = environment.get("deployment_branch_policy") if isinstance(environment, dict) else None
    if (
        not rule_ids
        or reviewer_user_ids != [PRODUCT_OWNER_REVIEWER_ID]
        or [rule.get("prevent_self_review") for rule in reviewer_rules] != [True]
        or type(environment.get("id") if isinstance(environment, dict) else None) is not int
        or environment["id"] < 1
        or environment.get("html_url") != activity_url
        or branch_policy != {"custom_branch_policies": True, "protected_branches": False}
    ):
        raise CandidateError("stable authorization environment must require independent product-owner review")
    policies = client.json(
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/environments/{encoded}/"
        "deployment-branch-policies?per_page=100",
        headers=headers,
        accept="application/vnd.github+json",
    )
    custom = policies.get("branch_policies") if isinstance(policies, dict) else None
    if (
        not isinstance(custom, list)
        or policies.get("total_count") != 1
        or len(custom) != 1
        or not isinstance(custom[0], dict)
        or type(custom[0].get("id")) is not int
        or custom[0]["id"] < 1
        or custom[0].get("name") != "main"
        or custom[0].get("type", "branch") != "branch"
    ):
        raise CandidateError("stable authorization environment must allow only main")
    return {
        "custom_branch_policies": [{"id": custom[0]["id"], "name": "main"}],
        "deployment_branch_policy": branch_policy,
        "environment_id": environment["id"],
        "environment_url": activity_url,
        "prevent_self_review": True,
        "required_reviewer_rule_ids": rule_ids,
        "required_reviewer_user_ids": reviewer_user_ids,
    }


def protected_run_evidence(
    client: PublicClient,
    *,
    actor: str,
    run_id: int,
    run_attempt: int,
    workflow_commit: str,
    environment_protection: dict[str, Any],
) -> dict[str, Any]:
    headers = {"X-GitHub-Api-Version": API_VERSION}
    run = client.json(
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/actions/runs/{run_id}",
        headers=headers,
        accept="application/vnd.github+json",
    )
    accepted_paths = {AUTHORIZATION_WORKFLOW, f"{AUTHORIZATION_WORKFLOW}@main"}
    if (
        not isinstance(run, dict)
        or run.get("actor", {}).get("login") != actor
        or run.get("repository", {}).get("full_name") != CONTROL_REPOSITORY
        or run.get("id") != run_id
        or run.get("run_attempt") != run_attempt
        or run.get("event") != "workflow_dispatch"
        or run.get("path") not in accepted_paths
        or run.get("head_branch") != "main"
        or run.get("head_sha") != workflow_commit
        or run.get("html_url") != f"https://github.com/{CONTROL_REPOSITORY}/actions/runs/{run_id}"
    ):
        raise CandidateError("stable authorization workflow run evidence does not match GitHub")
    history = client.json(
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/actions/runs/{run_id}/approvals",
        headers=headers,
        accept="application/vnd.github+json",
    )
    if (
        not isinstance(history, list)
        or len(history) != 1
        or not isinstance(history[0], dict)
        or history[0].get("state") != "approved"
    ):
        raise CandidateError("stable authorization requires exactly one approved environment review")
    review = history[0]
    environments = review.get("environments")
    if (
        not isinstance(review.get("comment"), str)
        or not isinstance(environments, list)
        or len(environments) != 1
        or not isinstance(environments[0], dict)
    ):
        raise CandidateError("stable authorization approval history is malformed")
    activity_url, api_url = environment_urls()
    environment = environments[0]
    if (
        environment.get("id") != environment_protection["environment_id"]
        or environment.get("name") != AUTHORIZATION_ENVIRONMENT
        or environment.get("html_url") != activity_url
        or environment.get("url") != api_url
        or not isinstance(environment.get("node_id"), str)
        or not environment["node_id"]
    ):
        raise CandidateError("stable authorization review names the wrong environment")
    reviewer = user_identity(review.get("user"), "stable authorization approving reviewer")
    if reviewer["id"] != PRODUCT_OWNER_REVIEWER_ID:
        raise CandidateError("stable authorization review was not submitted by the product owner")
    return {
        "comment": review["comment"],
        "environments": [
            {
                "html_url": activity_url,
                "id": environment["id"],
                "name": AUTHORIZATION_ENVIRONMENT,
                "node_id": environment["node_id"],
                "url": api_url,
            }
        ],
        "run_attempt": run_attempt,
        "run_id": run_id,
        "state": "approved",
        "user": reviewer,
    }


def authorization_tag(request: dict[str, Any]) -> str:
    match = CANDIDATE_TAG_PATTERN.fullmatch(request["artifact_tuple"]["tag"])
    if match is None:
        raise CandidateError("artifact tuple has no stable authorization identity")
    return f"{AUTHORIZATION_TAG_PREFIX}{match.group('candidate')}"


def validate_existing_authorization(
    value: Any,
    request: dict[str, Any],
    readout: dict[str, Any],
    contract: dict[str, Any],
) -> dict[str, Any]:
    authorization = require_exact_keys(
        value,
        {
            "schema",
            "channel",
            "stable_version",
            "artifact_tuple",
            "contract",
            "request_sha256",
            "readout_sha256",
            "evidence_gate",
            "decision",
        },
        "stable authorization",
    )
    if (
        authorization["schema"] != AUTHORIZATION_SCHEMA
        or authorization["channel"] != "stable"
        or authorization["stable_version"] != STABLE_VERSION
        or authorization["artifact_tuple"] != request["artifact_tuple"]
        or authorization["contract"] != {"url": CONTRACT_URL, "sha256": manifest_digest(contract)}
        or authorization["request_sha256"] != manifest_digest(request)
        or authorization["readout_sha256"] != manifest_digest(readout)
        or authorization["evidence_gate"] != "pass"
    ):
        raise CandidateError("existing stable authorization differs from this exact evidence decision")
    decision = require_exact_keys(
        authorization["decision"],
        {
            "status",
            "type",
            "actor",
            "repository",
            "workflow_ref",
            "workflow_commit",
            "run_id",
            "run_attempt",
            "run_url",
            "environment",
            "environment_protection",
            "environment_approval",
        },
        "stable authorization human decision",
    )
    if (
        decision["status"] != "authorized"
        or decision["type"] != "protected-human-review"
        or decision["repository"] != CONTROL_REPOSITORY
        or decision["environment"] != AUTHORIZATION_ENVIRONMENT
        or decision["workflow_ref"] != AUTHORIZATION_WORKFLOW_REF
        or not isinstance(decision["actor"], str)
        or LOGIN_PATTERN.fullmatch(decision["actor"]) is None
        or not isinstance(decision["workflow_commit"], str)
        or COMMIT_PATTERN.fullmatch(decision["workflow_commit"]) is None
        or type(decision["run_id"]) is not int
        or decision["run_id"] < 1
        or type(decision["run_attempt"]) is not int
        or decision["run_attempt"] < 1
        or decision["run_url"] != f"https://github.com/{CONTROL_REPOSITORY}/actions/runs/{decision['run_id']}"
    ):
        raise CandidateError("existing stable authorization lacks an explicit human decision")
    protection = decision["environment_protection"]
    approval = decision["environment_approval"]
    if (
        not isinstance(protection, dict)
        or protection.get("prevent_self_review") is not True
        or protection.get("required_reviewer_user_ids") != [PRODUCT_OWNER_REVIEWER_ID]
        or not isinstance(approval, dict)
        or approval.get("state") != "approved"
        or approval.get("run_id") != decision["run_id"]
        or approval.get("run_attempt") != decision["run_attempt"]
        or user_identity(approval.get("user"), "stable authorization approving reviewer")["id"]
        != PRODUCT_OWNER_REVIEWER_ID
    ):
        raise CandidateError("existing stable authorization lacks an approved product-owner review")
    return authorization


def existing_authorization(
    repository: Path,
    request: dict[str, Any],
    readout: dict[str, Any],
    contract: dict[str, Any],
    *,
    remote: str,
    authoritative_authorization: Path | None = None,
    authoritative_request: Path | None = None,
    authoritative_readout: Path | None = None,
    authoritative_contract: Path | None = None,
) -> dict[str, str] | None:
    tag = authorization_tag(request)
    reference = fetch_existing_record(repository, remote, tag)
    if reference is None:
        return None
    files = {
        "authorization": read_record_file(repository, reference, "stable-authorization.json"),
        "request": read_record_file(repository, reference, "stable-authorization-request.json"),
        "readout": read_record_file(repository, reference, "release-critical-readout.json"),
        "contract": read_record_file(repository, reference, "release-critical-contract.json"),
    }
    if files["request"] != canonical_json(request):
        raise CandidateError("existing stable authorization has a different request")
    if files["readout"] != canonical_json(readout):
        raise CandidateError("existing stable authorization has a different readout")
    if files["contract"] != canonical_json(contract):
        raise CandidateError("existing stable authorization has a different tier contract")
    try:
        authorization = json.loads(files["authorization"])
    except json.JSONDecodeError as error:
        raise CandidateError("existing stable authorization is not valid JSON") from error
    validate_existing_authorization(authorization, request, readout, contract)
    outputs = (
        (authoritative_authorization, files["authorization"]),
        (authoritative_request, files["request"]),
        (authoritative_readout, files["readout"]),
        (authoritative_contract, files["contract"]),
    )
    for path, content in outputs:
        if path is not None:
            path.write_bytes(content)
    return {
        "status": "existing",
        "tag": tag,
        "commit": run_git(["rev-parse", f"{reference}^{{commit}}"], cwd=repository),
    }


def check_authorization(
    repository: Path,
    contract_path: Path,
    request_path: Path,
    readout_path: Path,
    *,
    remote: str,
) -> dict[str, str]:
    contract = load_contract(contract_path)
    request = load_request(request_path)
    readout = verified_readout(contract, request, readout_path)
    require_ready(readout)
    existing = existing_authorization(
        repository,
        request,
        readout,
        contract,
        remote=remote,
    )
    return existing or {
        "status": "new",
        "tag": authorization_tag(request),
    }


def record_authorization(
    repository: Path,
    contract_path: Path,
    request_path: Path,
    readout_path: Path,
    *,
    remote: str,
    authoritative_authorization: Path,
    authoritative_request: Path,
    authoritative_readout: Path,
    authoritative_contract: Path,
    client: PublicClient,
    actor: str,
    run_id: int,
    run_attempt: int,
    workflow_ref: str,
    workflow_commit: str,
) -> dict[str, str]:
    contract = load_contract(contract_path)
    request = load_request(request_path)
    readout = verified_readout(contract, request, readout_path)
    require_ready(readout)
    existing = existing_authorization(
        repository,
        request,
        readout,
        contract,
        remote=remote,
        authoritative_authorization=authoritative_authorization,
        authoritative_request=authoritative_request,
        authoritative_readout=authoritative_readout,
        authoritative_contract=authoritative_contract,
    )
    if existing is not None:
        return existing
    if (
        not isinstance(actor, str)
        or LOGIN_PATTERN.fullmatch(actor) is None
        or run_id < 1
        or run_attempt < 1
        or workflow_ref != AUTHORIZATION_WORKFLOW_REF
        or COMMIT_PATTERN.fullmatch(workflow_commit) is None
    ):
        raise CandidateError("stable authorization workflow identity is invalid")
    verify_artifact_tuple_candidate(client, request)
    verify_evidence_sources(client, request)
    protection = protected_environment_evidence(client)
    approval = protected_run_evidence(
        client,
        actor=actor,
        run_id=run_id,
        run_attempt=run_attempt,
        workflow_commit=workflow_commit,
        environment_protection=protection,
    )
    authorization = {
        "schema": AUTHORIZATION_SCHEMA,
        "channel": "stable",
        "stable_version": STABLE_VERSION,
        "artifact_tuple": request["artifact_tuple"],
        "contract": {
            "url": CONTRACT_URL,
            "sha256": manifest_digest(contract),
        },
        "request_sha256": manifest_digest(request),
        "readout_sha256": manifest_digest(readout),
        "evidence_gate": "pass",
        "decision": {
            "status": "authorized",
            "type": "protected-human-review",
            "actor": actor,
            "repository": CONTROL_REPOSITORY,
            "workflow_ref": workflow_ref,
            "workflow_commit": workflow_commit,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "run_url": f"https://github.com/{CONTROL_REPOSITORY}/actions/runs/{run_id}",
            "environment": AUTHORIZATION_ENVIRONMENT,
            "environment_protection": protection,
            "environment_approval": approval,
        },
    }
    validate_existing_authorization(authorization, request, readout, contract)
    canonical_files = {
        "stable-authorization.json": canonical_json(authorization),
        "stable-authorization-request.json": canonical_json(request),
        "release-critical-readout.json": canonical_json(readout),
        "release-critical-contract.json": canonical_json(contract),
    }
    tag = authorization_tag(request)
    with tempfile.NamedTemporaryFile(prefix="stable-authorization-index-", delete=False) as index:
        index_path = Path(index.name)
    try:
        environment = os.environ.copy()
        environment["GIT_INDEX_FILE"] = str(index_path)
        index_path.unlink(missing_ok=True)
        run_git(["read-tree", "--empty"], cwd=repository, env=environment)
        for filename, content in canonical_files.items():
            blob = (
                subprocess.run(
                    ["git", "hash-object", "-w", "--stdin"],
                    cwd=repository,
                    env=environment,
                    input=content,
                    check=True,
                    stdout=subprocess.PIPE,
                )
                .stdout.decode()
                .strip()
            )
            run_git(
                ["update-index", "--add", "--cacheinfo", f"100644,{blob},{filename}"],
                cwd=repository,
                env=environment,
            )
        tree = run_git(["write-tree"], cwd=repository, env=environment)
        commit_environment = environment | {
            "GIT_AUTHOR_NAME": "Durable Workflow Stable Authorizer",
            "GIT_AUTHOR_EMAIL": "support@durable-workflow.com",
            "GIT_COMMITTER_NAME": "Durable Workflow Stable Authorizer",
            "GIT_COMMITTER_EMAIL": "support@durable-workflow.com",
        }
        commit = subprocess.run(
            ["git", "commit-tree", tree],
            cwd=repository,
            env=commit_environment,
            input=f"Record stable authorization for {request['artifact_tuple']['tag']}\n",
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        push = subprocess.run(
            ["git", "push", remote, f"{commit}:refs/tags/{tag}"],
            cwd=repository,
            check=False,
            text=True,
            capture_output=True,
        )
        if push.returncode:
            recovered = existing_authorization(
                repository,
                request,
                readout,
                contract,
                remote=remote,
                authoritative_authorization=authoritative_authorization,
                authoritative_request=authoritative_request,
                authoritative_readout=authoritative_readout,
                authoritative_contract=authoritative_contract,
            )
            if recovered is None:
                raise CandidateError(f"cannot publish immutable stable authorization: {push.stderr.strip()}")
            return recovered
    finally:
        index_path.unlink(missing_ok=True)
    authoritative_authorization.write_bytes(canonical_files["stable-authorization.json"])
    authoritative_request.write_bytes(canonical_files["stable-authorization-request.json"])
    authoritative_readout.write_bytes(canonical_files["release-critical-readout.json"])
    authoritative_contract.write_bytes(canonical_files["release-critical-contract.json"])
    return {
        "status": "created",
        "tag": tag,
        "commit": commit,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    readout = commands.add_parser("readout")
    readout.add_argument("contract", type=Path)
    readout.add_argument("request", type=Path)
    readout.add_argument("destination", type=Path)
    readout.add_argument("--verify-public-sources", action="store_true")
    readout.add_argument("--github-summary", type=Path)

    ready = commands.add_parser("require-ready")
    ready.add_argument("contract", type=Path)
    ready.add_argument("request", type=Path)
    ready.add_argument("readout", type=Path)

    check = commands.add_parser("check")
    check.add_argument("contract", type=Path)
    check.add_argument("request", type=Path)
    check.add_argument("readout", type=Path)
    check.add_argument("--repository", type=Path, default=Path.cwd())
    check.add_argument("--remote", default="origin")
    check.add_argument("--github-output", type=Path)

    record = commands.add_parser("record")
    record.add_argument("contract", type=Path)
    record.add_argument("request", type=Path)
    record.add_argument("readout", type=Path)
    record.add_argument("--repository", type=Path, default=Path.cwd())
    record.add_argument("--remote", default="origin")
    record.add_argument("--authoritative-authorization", required=True, type=Path)
    record.add_argument("--authoritative-request", required=True, type=Path)
    record.add_argument("--authoritative-readout", required=True, type=Path)
    record.add_argument("--authoritative-contract", required=True, type=Path)
    record.add_argument("--actor", required=True)
    record.add_argument("--run-id", required=True, type=int)
    record.add_argument("--run-attempt", required=True, type=int)
    record.add_argument("--workflow-ref", required=True)
    record.add_argument("--workflow-commit", required=True)
    record.add_argument("--github-output", type=Path)

    arguments = parser.parse_args()
    try:
        if arguments.command == "readout":
            contract = load_contract(arguments.contract)
            request = load_request(arguments.request)
            if arguments.verify_public_sources:
                client = PublicClient(os.environ.get("GITHUB_TOKEN"))
                verify_artifact_tuple_candidate(client, request)
                verify_evidence_sources(client, request)
            result = evaluate(contract, request)
            arguments.destination.write_bytes(canonical_json(result))
            if arguments.github_summary is not None:
                with arguments.github_summary.open("a", encoding="utf-8") as summary:
                    summary.write(render_summary(result))
        elif arguments.command == "require-ready":
            contract = load_contract(arguments.contract)
            request = load_request(arguments.request)
            require_ready(verified_readout(contract, request, arguments.readout))
        elif arguments.command == "check":
            result = check_authorization(
                arguments.repository,
                arguments.contract,
                arguments.request,
                arguments.readout,
                remote=arguments.remote,
            )
            write_github_output(arguments.github_output, result)
            print(json.dumps(result, sort_keys=True))
        else:
            result = record_authorization(
                arguments.repository,
                arguments.contract,
                arguments.request,
                arguments.readout,
                remote=arguments.remote,
                authoritative_authorization=arguments.authoritative_authorization,
                authoritative_request=arguments.authoritative_request,
                authoritative_readout=arguments.authoritative_readout,
                authoritative_contract=arguments.authoritative_contract,
                client=PublicClient(os.environ.get("GITHUB_TOKEN")),
                actor=arguments.actor,
                run_id=arguments.run_id,
                run_attempt=arguments.run_attempt,
                workflow_ref=arguments.workflow_ref,
                workflow_commit=arguments.workflow_commit,
            )
            write_github_output(arguments.github_output, result)
            print(json.dumps(result, sort_keys=True))
    except CandidateError as error:
        print(f"stable authorization failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
