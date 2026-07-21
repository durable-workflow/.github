#!/usr/bin/env python3
"""Validate and record the protected GitHub beta authorization decision."""

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
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

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
    validate_manifest,
    validate_verification,
    write_github_output,
)
from scripts.beta_conformance import ConformanceError
from scripts.beta_continuity import (
    ContinuityError,
    exact_completion_authority,
    load_config,
)
from scripts.beta_continuity import (
    validated_conformance_release as validate_conformance_release,
)
from scripts.release_plan import (
    EXPECTED_DEFAULT_BRANCHES,
    read_public_record,
    resolve_tag,
    validate_plan,
)

REQUEST_SCHEMA = "durable-workflow.beta-authorization-request/v1"
AUTHORIZATION_SCHEMA = "durable-workflow.beta-authorization/v1"
EVIDENCE_SCHEMA = "durable-workflow.beta-authorization-evidence/v1"
QUALIFICATION_SCHEMA = "durable-workflow.github-target-qualification/v1"
CONTROL_REPOSITORY = "durable-workflow/.github"
AUTHORIZATION_TAG_PREFIX = "beta-authorization/"
AUTHORIZATION_ENVIRONMENT = "beta-authorization"
AUTHORIZATION_WORKFLOW = ".github/workflows/beta-authorization.yml"
AUTHORIZATION_WORKFLOW_REF = (
    "durable-workflow/.github/.github/workflows/beta-authorization.yml@refs/heads/main"
)
AUTHORITY_ISSUE = 3
AUTHORITY_ISSUE_URL = f"https://github.com/{CONTROL_REPOSITORY}/issues/{AUTHORITY_ISSUE}"
AUTHORITY_WORK_ID = "authorize-2-0-beta"
PRODUCT_OWNER_REVIEWER_ID = 1130888
API_VERSION = "2022-11-28"
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
IDENTITY_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,55}$")
BETA_VERSION_PATTERN = re.compile(r"^2\.0\.0-beta\.[1-9][0-9]*$")
LOGIN_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,39}$")
DECISION_MARKER = re.compile(
    r"<!-- durable-workflow-beta-decision: authorize sha256:(?P<digest>[0-9a-f]{64}) -->"
)
REQUIRED_AUTHORITY_LABELS = {
    "authority:github",
    "beta:blocker",
    "completion:evidence-required",
    "kind:release-blocker",
    "priority:P0",
}
MAX_REQUEST_BYTES = 256 * 1024
MAX_EVIDENCE_BYTES = 1024 * 1024
MAX_QUALIFICATION_BYTES = 2 * 1024 * 1024
MAX_ISSUE_PAGES = 100


def require_exact_keys(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise CandidateError(f"{context} keys must be exactly {sorted(expected)}")
    return value


def require_git_record(value: Any, context: str, *, digest: bool = False) -> dict[str, Any]:
    keys = {"tag", "commit", "sha256"} if digest else {"tag", "commit"}
    record = require_exact_keys(value, keys, context)
    if (
        not isinstance(record["tag"], str)
        or not record["tag"]
        or len(record["tag"]) > 180
        or not COMMIT_PATTERN.fullmatch(str(record["commit"]))
        or (digest and not SHA256_PATTERN.fullmatch(str(record["sha256"])))
    ):
        raise CandidateError(f"{context} has an invalid immutable Git identity")
    return record


def validate_authorization(value: Any) -> dict[str, Any]:
    authorization = require_exact_keys(
        value,
        {"schema", "channel", "candidate", "components"},
        "beta authorization",
    )
    if authorization["schema"] != AUTHORIZATION_SCHEMA or authorization["channel"] != "beta":
        raise CandidateError("authorization must explicitly select only the beta channel")
    if not isinstance(authorization["candidate"], str) or not IDENTITY_PATTERN.fullmatch(
        authorization["candidate"]
    ):
        raise CandidateError("authorization candidate must be a valid release-plan identity")
    components = authorization["components"]
    if not isinstance(components, dict) or set(components) != set(COMPONENTS):
        raise CandidateError(f"authorization components must be exactly {sorted(COMPONENTS)}")
    for name, value in components.items():
        identity = require_exact_keys(value, {"version", "commit"}, f"authorization components.{name}")
        if not isinstance(identity["version"], str) or not VERSION_PATTERN.fullmatch(identity["version"]):
            raise CandidateError(f"authorization components.{name}.version must be exact SemVer")
        if not COMMIT_PATTERN.fullmatch(str(identity["commit"])):
            raise CandidateError(f"authorization components.{name}.commit must be a full lowercase commit")
    for name in ("workflow", "waterline"):
        if not BETA_VERSION_PATTERN.fullmatch(components[name]["version"]):
            raise CandidateError(f"authorization {name} version must be an exact 2.0.0-beta.N identity")
    return authorization


def validate_request(value: Any) -> dict[str, Any]:
    request = require_exact_keys(value, {"schema", "authorization", "evidence"}, "authorization request")
    if request["schema"] != REQUEST_SCHEMA:
        raise CandidateError(f"authorization request schema must be {REQUEST_SCHEMA}")
    validate_authorization(request["authorization"])
    evidence = require_exact_keys(
        request["evidence"],
        {"candidate", "conformance", "continuity", "decision"},
        "authorization request evidence",
    )
    candidate = require_git_record(evidence["candidate"], "candidate evidence")
    if not re.fullmatch(r"beta-candidate/[a-z0-9][a-z0-9._-]{0,62}", candidate["tag"]):
        raise CandidateError("candidate evidence must cite an immutable beta-candidate tag")
    conformance = require_git_record(evidence["conformance"], "conformance evidence")
    if not re.fullmatch(
        r"beta-conformance/[a-z0-9][a-z0-9._-]{0,62}/[1-9][0-9]*\.[1-9][0-9]*",
        conformance["tag"],
    ):
        raise CandidateError("conformance evidence must cite a retained run and attempt")
    continuity = require_exact_keys(evidence["continuity"], {"complete", "no_op"}, "continuity evidence")
    complete = require_git_record(continuity["complete"], "continuity complete evidence")
    no_op = require_git_record(continuity["no_op"], "continuity no-op evidence")
    complete_match = re.fullmatch(
        r"beta-continuity/(?P<plan>[a-z0-9][a-z0-9._-]{0,55})/complete",
        complete["tag"],
    )
    if complete_match is None or no_op["tag"] != f"beta-continuity/{complete_match.group('plan')}/no-op-confirmed":
        raise CandidateError("continuity evidence must cite matching complete and no-op phase tags")
    decision = require_exact_keys(evidence["decision"], {"issue", "comment"}, "decision evidence")
    if decision["issue"] != AUTHORITY_ISSUE or type(decision["comment"]) is not int or decision["comment"] < 1:
        raise CandidateError(f"decision evidence must cite a comment on {CONTROL_REPOSITORY}#{AUTHORITY_ISSUE}")
    return request


def load_request(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CandidateError(f"cannot read authorization request {path}: {error}") from error
    if len(raw) > MAX_REQUEST_BYTES:
        raise CandidateError("authorization request exceeds the 256 KiB limit")
    try:
        request = json.loads(raw)
    except json.JSONDecodeError as error:
        raise CandidateError(f"authorization request is not valid JSON: {error}") from error
    return validate_request(request)


def user_identity(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CandidateError(f"{context} has no GitHub user identity")
    identity = {
        "login": value.get("login"),
        "id": value.get("id"),
        "node_id": value.get("node_id"),
        "url": value.get("url"),
        "html_url": value.get("html_url"),
    }
    login = identity["login"]
    if (
        not isinstance(login, str)
        or not LOGIN_PATTERN.fullmatch(login)
        or type(identity["id"]) is not int
        or identity["id"] < 1
        or not isinstance(identity["node_id"], str)
        or not identity["node_id"]
        or identity["url"] != f"https://api.github.com/users/{login}"
        or identity["html_url"] != f"https://github.com/{login}"
    ):
        raise CandidateError(f"{context} has an invalid durable GitHub user identity")
    return identity


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
    rule_ids = sorted(
        rule["id"] for rule in reviewer_rules if type(rule.get("id")) is int and rule["id"] > 0
    )
    reviewer_user_ids: list[int] = []
    for rule in reviewer_rules:
        for reviewer in rule.get("reviewers", []):
            identity = reviewer.get("reviewer") if isinstance(reviewer, dict) else None
            if (
                isinstance(identity, dict)
                and reviewer.get("type") == "User"
                and type(identity.get("id")) is int
                and identity["id"] > 0
            ):
                reviewer_user_ids.append(identity["id"])
    reviewer_user_ids.sort()
    prevent_self_review = [rule.get("prevent_self_review") for rule in reviewer_rules]
    branch_policy = environment.get("deployment_branch_policy") if isinstance(environment, dict) else None
    if (
        not rule_ids
        or reviewer_user_ids != [PRODUCT_OWNER_REVIEWER_ID]
        or prevent_self_review != [False]
        or type(environment.get("id") if isinstance(environment, dict) else None) is not int
        or environment["id"] < 1
        or environment.get("html_url") != activity_url
        or branch_policy != {"custom_branch_policies": True, "protected_branches": False}
    ):
        raise CandidateError("beta authorization environment must require reviewers and custom branch policies")
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
        raise CandidateError("beta authorization environment must allow only the main branch")
    return {
        "custom_branch_policies": [{"id": custom[0]["id"], "name": "main"}],
        "deployment_branch_policy": branch_policy,
        "environment_id": environment["id"],
        "environment_url": activity_url,
        "prevent_self_review": False,
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
        raise CandidateError("beta authorization workflow run evidence does not match GitHub")
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
        raise CandidateError("beta authorization run must contain exactly one approved environment review")
    review = history[0]
    environments = review.get("environments")
    if (
        not isinstance(review.get("comment"), str)
        or not isinstance(environments, list)
        or len(environments) != 1
        or not isinstance(environments[0], dict)
    ):
        raise CandidateError("beta authorization approval history is malformed")
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
        raise CandidateError("beta authorization review names the wrong protected environment")
    reviewer = user_identity(review.get("user"), "beta authorization approving reviewer")
    if reviewer["id"] != PRODUCT_OWNER_REVIEWER_ID:
        raise CandidateError("beta authorization review was not submitted by the required product owner")
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


def verify_candidate_evidence(client: PublicClient, request: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    reference = request["evidence"]["candidate"]
    resolved = resolve_tag(client, CONTROL_REPOSITORY, reference["tag"])
    if resolved != reference["commit"]:
        raise CandidateError("cited beta candidate tag does not resolve to its requested immutable commit")
    manifest = read_public_record(client, reference["tag"], reference["commit"], "candidate.json")
    verification = read_public_record(client, reference["tag"], reference["commit"], "verification.json")
    validate_manifest(manifest)
    validate_verification(verification, manifest)
    intended = request["authorization"]["components"]
    mismatches = [
        name for name in COMPONENTS if manifest["components"][name]["commit"] != intended[name]["commit"]
    ]
    if mismatches:
        raise CandidateError(f"beta candidate source commits differ from the intended release plan: {mismatches}")

    release = client.json(
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/releases/tags/"
        f"{urllib.parse.quote(reference['tag'], safe='')}"
    )
    assets = {
        asset.get("name"): asset
        for asset in release.get("assets", [])
        if isinstance(asset, dict) and isinstance(asset.get("name"), str)
    } if isinstance(release, dict) else {}
    for filename, value in (("candidate.json", manifest), ("verification.json", verification)):
        asset = assets.get(filename)
        if not isinstance(asset, dict) or not isinstance(asset.get("browser_download_url"), str):
            raise CandidateError(f"cited beta candidate lacks its durable {filename} Release mirror")
        if client.bytes(asset["browser_download_url"]) != canonical_json(value):
            raise CandidateError(f"cited beta candidate {filename} Release mirror differs from Git authority")
    return manifest, {
        "tag": reference["tag"],
        "commit": reference["commit"],
        "manifest_sha256": manifest_digest(manifest),
        "verification_sha256": manifest_digest(verification),
    }


def validate_qualification_evidence(
    qualification: Any,
    request: dict[str, Any],
    *,
    current_policy: bool = True,
) -> dict[str, Any]:
    targets = qualification.get("targets") if isinstance(qualification, dict) else None
    policy = (
        json.loads(
            (Path(__file__).resolve().parents[1] / "qualification" / "policy.json").read_bytes()
        )
        if current_policy
        else None
    )
    if (
        not isinstance(qualification, dict)
        or set(qualification) != {"schema", "targets"}
        or qualification.get("schema") != QUALIFICATION_SCHEMA
        or not isinstance(targets, dict)
        or (current_policy and set(targets) != set(policy["targets"]))
        or (not current_policy and not set(targets) >= set(COMPONENTS))
    ):
        raise CandidateError("cited qualification evidence has an invalid authority shape")
    target_contracts = (
        policy["targets"]
        if current_policy
        else {
            name: {"branch": EXPECTED_DEFAULT_BRANCHES[name], "workflows": None}
            for name in COMPONENTS
        }
    )
    for name, target_policy in target_contracts.items():
        target = targets.get(name)
        protected = target.get("protected_checks") if isinstance(target, dict) else None
        successful = target.get("successful_check_runs") if isinstance(target, dict) else None
        expected_commit = request["authorization"]["components"].get(name, {}).get("commit")
        expected_checks = (
            {workflow["required_check"] for workflow in target_policy["workflows"]}
            if target_policy["workflows"] is not None
            else None
        )
        workflows = target.get("workflows") if isinstance(target, dict) else None
        workflows_are_valid = (
            isinstance(workflows, list)
            and bool(workflows)
            and all(
                isinstance(workflow, dict)
                and set(workflow) == {"path", "required_check", "workflow_id"}
                and isinstance(workflow["path"], str)
                and re.fullmatch(
                    r"\.github/workflows/[a-z0-9][a-z0-9.-]*\.yml",
                    workflow["path"],
                )
                and isinstance(workflow["required_check"], str)
                and bool(workflow["required_check"].strip())
                and type(workflow["workflow_id"]) is int
                and workflow["workflow_id"] > 0
                for workflow in workflows
            )
        )
        recorded_workflows = (
            {(workflow["path"], workflow["required_check"]) for workflow in workflows}
            if workflows_are_valid
            else set()
        )
        recorded_paths = (
            {workflow["path"] for workflow in workflows}
            if workflows_are_valid
            else set()
        )
        recorded_checks = (
            {workflow["required_check"] for workflow in workflows}
            if workflows_are_valid
            else set()
        )
        expected_workflows = (
            {
                (f".github/workflows/{workflow['path']}", workflow["required_check"])
                for workflow in target_policy["workflows"]
            }
            if target_policy["workflows"] is not None
            else None
        )
        if (
            not isinstance(target, dict)
            or set(target)
            != {
                "action_releases",
                "branch",
                "commit",
                "protected_checks",
                "successful_check_runs",
                "workflows",
            }
            or target.get("branch") != target_policy["branch"]
            or not COMMIT_PATTERN.fullmatch(str(target.get("commit", "")))
            or (expected_commit is not None and target.get("commit") != expected_commit)
            or not isinstance(protected, list)
            or not protected
            or any(not isinstance(check, str) or not check for check in protected)
            or (expected_checks is not None and set(protected) != expected_checks)
            or not isinstance(successful, dict)
            or set(successful) != set(protected)
            or any(type(run_id) is not int or run_id < 1 for run_id in successful.values())
            or not isinstance(target.get("action_releases"), list)
            or not workflows_are_valid
            or set(protected) != recorded_checks
            or len(protected) != len(recorded_checks)
            or len(recorded_paths) != len(workflows)
            or len(recorded_checks) != len(workflows)
            or (target_policy["workflows"] is not None and len(workflows) != len(target_policy["workflows"]))
            or (expected_workflows is not None and recorded_workflows != expected_workflows)
        ):
            if name in request["authorization"]["components"]:
                raise CandidateError(f"qualification evidence does not prove intended {name} source commit")
            raise CandidateError(f"qualification evidence for {name} has an invalid protected target record")
    return qualification


def load_qualification_evidence(path: Path | None, request: dict[str, Any]) -> dict[str, Any]:
    if path is None:
        raise CandidateError("a new beta authorization requires fresh target qualification evidence")
    try:
        raw = path.read_bytes()
    except FileNotFoundError as error:
        raise CandidateError("a new beta authorization requires fresh target qualification evidence") from error
    except OSError as error:
        raise CandidateError(f"cannot read target qualification evidence {path}: {error}") from error
    if len(raw) > MAX_QUALIFICATION_BYTES:
        raise CandidateError("target qualification evidence exceeds the 2 MiB limit")
    try:
        qualification = json.loads(raw)
    except json.JSONDecodeError as error:
        raise CandidateError("target qualification evidence is not valid JSON") from error
    return validate_qualification_evidence(qualification, request)


def expected_qualification_commits(request: dict[str, Any]) -> dict[str, str]:
    return {
        name: identity["commit"]
        for name, identity in request["authorization"]["components"].items()
    }


def verify_qualified_heads_stable(
    client: PublicClient,
    request: dict[str, Any],
    qualification: dict[str, Any],
) -> None:
    for name, identity in request["authorization"]["components"].items():
        component = COMPONENTS[name]
        branch = EXPECTED_DEFAULT_BRANCHES[name]
        encoded_branch = urllib.parse.quote(branch, safe="")
        current = client.json(f"https://api.github.com/repos/{component.repository}/branches/{encoded_branch}")
        current_commit = current.get("commit") if isinstance(current, dict) else None
        if (
            not isinstance(current, dict)
            or not isinstance(current_commit, dict)
            or current_commit.get("sha") != identity["commit"]
            or qualification["targets"][name]["commit"] != identity["commit"]
        ):
            raise CandidateError(f"qualified {name} source changed before beta authorization publication")


def conformance_rank(tag: str) -> tuple[int, int]:
    match = re.fullmatch(r"beta-conformance/.+/(?P<run>[1-9][0-9]*)\.(?P<attempt>[1-9][0-9]*)", tag)
    if match is None:
        raise CandidateError("conformance evidence tag has an invalid run identity")
    return int(match.group("run")), int(match.group("attempt"))


def verify_conformance_evidence(
    client: PublicClient,
    request: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    reference = request["evidence"]["conformance"]
    if resolve_tag(client, CONTROL_REPOSITORY, reference["tag"]) != reference["commit"]:
        raise CandidateError("cited conformance tag does not resolve to its requested immutable commit")
    release = client.json(
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/releases/tags/"
        f"{urllib.parse.quote(reference['tag'], safe='')}"
    )
    pseudo_plan = {"components": manifest["components"]}
    try:
        evidence = validate_conformance_release(
            client,
            pseudo_plan,
            manifest,
            release,
            conformance_rank(reference["tag"]),
        )
    except ConformanceError as error:
        raise CandidateError(f"cited conformance Release is invalid: {error}") from error
    if evidence is None or evidence["tag"] != reference["tag"]:
        raise CandidateError("cited conformance Release is not retained passing exact-candidate evidence")
    return {"commit": reference["commit"], **evidence}


def verify_continuity_evidence(client: PublicClient, request: dict[str, Any]) -> dict[str, Any]:
    reference = request["evidence"]["continuity"]
    complete = reference["complete"]
    no_op = reference["no_op"]
    if resolve_tag(client, CONTROL_REPOSITORY, complete["tag"]) != complete["commit"]:
        raise CandidateError("cited continuity completion tag moved or is missing")
    if resolve_tag(client, CONTROL_REPOSITORY, no_op["tag"]) != no_op["commit"]:
        raise CandidateError("cited continuity no-op tag moved or is missing")
    plan = read_public_record(client, complete["tag"], complete["commit"], "release-plan.json")
    validate_plan(plan)
    expected_complete = f"beta-continuity/{plan['plan']}/complete"
    expected_no_op = f"beta-continuity/{plan['plan']}/no-op-confirmed"
    if complete["tag"] != expected_complete or no_op["tag"] != expected_no_op:
        raise CandidateError("cited continuity phase tags differ from their exact release plan")
    try:
        completion = exact_completion_authority(
            client,
            load_config(Path(__file__).resolve().parents[1] / "beta-continuity" / "config.json"),
            plan,
            complete["commit"],
            no_op["commit"],
        )
    except (ContinuityError, ConformanceError) as error:
        raise CandidateError(f"cited continuity completion is invalid: {error}") from error
    return {
        "complete": complete,
        "no_op": no_op,
        "plan": completion["plan_record"],
    }


def authority_issue_and_decision(
    client: PublicClient,
    request: dict[str, Any],
    *,
    actor: str,
) -> dict[str, Any]:
    issue = client.json(f"https://api.github.com/repos/{CONTROL_REPOSITORY}/issues/{AUTHORITY_ISSUE}")
    labels = {
        label.get("name") for label in issue.get("labels", []) if isinstance(label, dict)
    } if isinstance(issue, dict) else set()
    body = issue.get("body") if isinstance(issue, dict) else None
    milestone = issue.get("milestone") if isinstance(issue, dict) else None
    if (
        not isinstance(issue, dict)
        or issue.get("number") != AUTHORITY_ISSUE
        or issue.get("state") != "open"
        or issue.get("html_url") != AUTHORITY_ISSUE_URL
        or "pull_request" in issue
        or not labels >= REQUIRED_AUTHORITY_LABELS
        or not isinstance(body, str)
        or f"<!-- beta-work-id: {AUTHORITY_WORK_ID} -->" not in body
        or not isinstance(milestone, dict)
        or milestone.get("title") != "2.0 beta"
    ):
        raise CandidateError("the public beta authority issue is not an open, classified authorization gate")

    comment_id = request["evidence"]["decision"]["comment"]
    comment = client.json(f"https://api.github.com/repos/{CONTROL_REPOSITORY}/issues/comments/{comment_id}")
    comment_body = comment.get("body") if isinstance(comment, dict) else None
    marker_matches = list(DECISION_MARKER.finditer(comment_body or ""))
    expected_digest = manifest_digest(request["authorization"])
    author = user_identity(comment.get("user") if isinstance(comment, dict) else None, "beta decision comment")
    if (
        not isinstance(comment, dict)
        or comment.get("id") != comment_id
        or comment.get("issue_url") != f"https://api.github.com/repos/{CONTROL_REPOSITORY}/issues/{AUTHORITY_ISSUE}"
        or comment.get("html_url") != f"{AUTHORITY_ISSUE_URL}#issuecomment-{comment_id}"
        or author["login"] != actor
        or comment.get("author_association") not in {"OWNER", "MEMBER", "COLLABORATOR"}
        or len(marker_matches) != 1
        or marker_matches[0].group("digest") != expected_digest
    ):
        raise CandidateError("the cited product-owner comment does not authorize this exact beta release plan")
    return {
        "repository": CONTROL_REPOSITORY,
        "issue": AUTHORITY_ISSUE,
        "issue_url": AUTHORITY_ISSUE_URL,
        "comment": comment_id,
        "comment_url": comment["html_url"],
        "author": author,
        "body_sha256": hashlib.sha256(comment_body.encode()).hexdigest(),
    }


def public_backlog_evidence(client: PublicClient) -> dict[str, Any]:
    policy = json.loads(
        (Path(__file__).resolve().parents[1] / "issue-authority" / "policy.json").read_bytes()
    )
    repositories = [f"durable-workflow/{name}" for name in policy["repositories"]]
    unresolved: list[dict[str, Any]] = []
    seen: set[tuple[str, int]] = set()
    for repository in repositories:
        for priority in ("priority:P0", "priority:P1"):
            for page in range(1, MAX_ISSUE_PAGES + 1):
                query = urllib.parse.urlencode(
                    {"state": "open", "labels": priority, "per_page": 100, "page": page}
                )
                payload = client.json(f"https://api.github.com/repos/{repository}/issues?{query}")
                if not isinstance(payload, list):
                    raise CandidateError(f"public backlog query for {repository} returned invalid evidence")
                for issue in payload:
                    if not isinstance(issue, dict):
                        raise CandidateError(f"public backlog query for {repository} contains an invalid issue")
                    if "pull_request" in issue:
                        continue
                    number = issue.get("number")
                    if type(number) is not int or number < 1:
                        raise CandidateError(f"public backlog query for {repository} contains an invalid issue")
                    key = (repository, number)
                    if key in seen:
                        continue
                    seen.add(key)
                    if key == (CONTROL_REPOSITORY, AUTHORITY_ISSUE):
                        continue
                    unresolved.append(
                        {
                            "repository": repository,
                            "number": number,
                            "url": issue.get("html_url"),
                            "priority": priority,
                        }
                    )
                if len(payload) < 100:
                    break
            else:
                raise CandidateError(f"public backlog query for {repository} exceeded its page limit")
    if unresolved:
        identities = [f"{item['repository']}#{item['number']}" for item in unresolved]
        raise CandidateError(f"unresolved public P0/P1 work blocks beta authorization: {identities}")
    return {
        "repositories": repositories,
        "allowed_authorization_gate": {
            "repository": CONTROL_REPOSITORY,
            "number": AUTHORITY_ISSUE,
            "url": AUTHORITY_ISSUE_URL,
        },
        "unresolved_p0_p1": [],
    }


def verify_requested_refs_stable(client: PublicClient, request: dict[str, Any]) -> None:
    references = [
        request["evidence"]["candidate"],
        request["evidence"]["conformance"],
        request["evidence"]["continuity"]["complete"],
        request["evidence"]["continuity"]["no_op"],
    ]
    for reference in references:
        if resolve_tag(client, CONTROL_REPOSITORY, reference["tag"]) != reference["commit"]:
            raise CandidateError(f"public evidence tag {reference['tag']} changed before authorization publication")


def build_evidence(
    client: PublicClient,
    request: dict[str, Any],
    qualification: dict[str, Any],
    *,
    actor: str,
    run_id: int,
    run_attempt: int,
    workflow_ref: str,
    workflow_commit: str,
) -> dict[str, Any]:
    if (
        not LOGIN_PATTERN.fullmatch(actor)
        or run_id < 1
        or run_attempt < 1
        or workflow_ref != AUTHORIZATION_WORKFLOW_REF
        or not COMMIT_PATTERN.fullmatch(workflow_commit)
    ):
        raise CandidateError("beta authorization workflow dispatch identity is invalid")
    protection = protected_environment_evidence(client)
    approval = protected_run_evidence(
        client,
        actor=actor,
        run_id=run_id,
        run_attempt=run_attempt,
        workflow_commit=workflow_commit,
        environment_protection=protection,
    )
    decision = authority_issue_and_decision(client, request, actor=actor)
    candidate_manifest, candidate = verify_candidate_evidence(client, request)
    validate_qualification_evidence(qualification, request, current_policy=False)
    conformance = verify_conformance_evidence(client, request, candidate_manifest)
    continuity = verify_continuity_evidence(client, request)
    backlog = public_backlog_evidence(client)
    verify_requested_refs_stable(client, request)
    verify_qualified_heads_stable(client, request, qualification)
    return {
        "schema": EVIDENCE_SCHEMA,
        "authorization_sha256": manifest_digest(request["authorization"]),
        "request_sha256": manifest_digest(request),
        "decision": decision,
        "candidate": candidate,
        "qualification": {
            "path": "target-qualification-evidence.json",
            "sha256": manifest_digest(qualification),
        },
        "conformance": conformance,
        "continuity": continuity,
        "backlog": backlog,
        "github_authority": {
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


def validate_recorded_evidence(
    value: Any,
    request: dict[str, Any],
    qualification: dict[str, Any],
) -> dict[str, Any]:
    evidence = require_exact_keys(
        value,
        {
            "schema",
            "authorization_sha256",
            "request_sha256",
            "decision",
            "candidate",
            "qualification",
            "conformance",
            "continuity",
            "backlog",
            "github_authority",
        },
        "recorded beta authorization evidence",
    )
    if (
        evidence["schema"] != EVIDENCE_SCHEMA
        or evidence["authorization_sha256"] != manifest_digest(request["authorization"])
        or evidence["request_sha256"] != manifest_digest(request)
    ):
        raise CandidateError("existing beta authorization was created from a different request")
    decision = require_exact_keys(
        evidence["decision"],
        {"repository", "issue", "issue_url", "comment", "comment_url", "author", "body_sha256"},
        "recorded decision evidence",
    )
    authority = require_exact_keys(
        evidence["github_authority"],
        {
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
        "recorded GitHub authority",
    )
    actor = authority["actor"]
    if (
        authority["repository"] != CONTROL_REPOSITORY
        or authority["workflow_ref"] != AUTHORIZATION_WORKFLOW_REF
        or authority["environment"] != AUTHORIZATION_ENVIRONMENT
        or not isinstance(actor, str)
        or not LOGIN_PATTERN.fullmatch(actor)
        or not COMMIT_PATTERN.fullmatch(str(authority["workflow_commit"]))
        or type(authority["run_id"]) is not int
        or authority["run_id"] < 1
        or type(authority["run_attempt"]) is not int
        or authority["run_attempt"] < 1
        or authority["run_url"]
        != f"https://github.com/{CONTROL_REPOSITORY}/actions/runs/{authority['run_id']}"
    ):
        raise CandidateError("existing beta authorization has invalid GitHub workflow authority")
    if (
        decision["repository"] != CONTROL_REPOSITORY
        or decision["issue"] != AUTHORITY_ISSUE
        or decision["issue_url"] != AUTHORITY_ISSUE_URL
        or decision["comment"] != request["evidence"]["decision"]["comment"]
        or decision["comment_url"] != f"{AUTHORITY_ISSUE_URL}#issuecomment-{decision['comment']}"
        or not SHA256_PATTERN.fullmatch(str(decision["body_sha256"]))
        or user_identity(decision["author"], "recorded decision author")["login"] != actor
    ):
        raise CandidateError("existing beta authorization has invalid product-owner decision evidence")

    candidate = require_exact_keys(
        evidence["candidate"],
        {"tag", "commit", "manifest_sha256", "verification_sha256"},
        "recorded candidate evidence",
    )
    if (
        {key: candidate[key] for key in ("tag", "commit")} != request["evidence"]["candidate"]
        or not SHA256_PATTERN.fullmatch(str(candidate["manifest_sha256"]))
        or not SHA256_PATTERN.fullmatch(str(candidate["verification_sha256"]))
    ):
        raise CandidateError("existing beta authorization has invalid candidate evidence")
    if evidence["qualification"] != {
        "path": "target-qualification-evidence.json",
        "sha256": manifest_digest(qualification),
    }:
        raise CandidateError("existing beta authorization has different qualification evidence")
    validate_qualification_evidence(qualification, request, current_policy=False)
    conformance = require_exact_keys(
        evidence["conformance"],
        {"tag", "commit", "release", "run"},
        "recorded conformance evidence",
    )
    expected_conformance = request["evidence"]["conformance"]
    run_id, run_attempt = conformance_rank(conformance["tag"])
    if (
        {key: conformance[key] for key in ("tag", "commit")} != expected_conformance
        or not isinstance(conformance["release"], str)
        or not conformance["release"].startswith(
            f"https://github.com/{CONTROL_REPOSITORY}/releases/tag/"
        )
        or conformance["run"]
        != {
            "repository": CONTROL_REPOSITORY,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "evidence_tag": conformance["tag"],
        }
    ):
        raise CandidateError("existing beta authorization has invalid retained conformance evidence")
    continuity = require_exact_keys(
        evidence["continuity"], {"complete", "no_op", "plan"}, "recorded continuity evidence"
    )
    if (
        continuity["complete"] != request["evidence"]["continuity"]["complete"]
        or continuity["no_op"] != request["evidence"]["continuity"]["no_op"]
    ):
        raise CandidateError("existing beta authorization has different continuity evidence")
    require_git_record(continuity["plan"], "recorded continuity plan", digest=True)

    backlog = require_exact_keys(
        evidence["backlog"],
        {"repositories", "allowed_authorization_gate", "unresolved_p0_p1"},
        "recorded backlog evidence",
    )
    recorded_repositories = backlog["repositories"]
    minimum_repositories = {CONTROL_REPOSITORY} | {
        component.repository for component in COMPONENTS.values()
    }
    if (
        not isinstance(recorded_repositories, list)
        or len(recorded_repositories) != len(set(recorded_repositories))
        or any(
            not isinstance(repository, str)
            or not repository.startswith("durable-workflow/")
            for repository in recorded_repositories
        )
        or not set(recorded_repositories) >= minimum_repositories
        or backlog["unresolved_p0_p1"] != []
        or backlog["allowed_authorization_gate"]
        != {"repository": CONTROL_REPOSITORY, "number": AUTHORITY_ISSUE, "url": AUTHORITY_ISSUE_URL}
    ):
        raise CandidateError("existing beta authorization has invalid final backlog evidence")
    protection = require_exact_keys(
        authority["environment_protection"],
        {
            "custom_branch_policies",
            "deployment_branch_policy",
            "environment_id",
            "environment_url",
            "prevent_self_review",
            "required_reviewer_rule_ids",
            "required_reviewer_user_ids",
        },
        "recorded environment protection",
    )
    activity_url, api_url = environment_urls()
    custom_policies = protection["custom_branch_policies"]
    reviewer_rule_ids = protection["required_reviewer_rule_ids"]
    reviewer_user_ids = protection["required_reviewer_user_ids"]
    if (
        protection["deployment_branch_policy"]
        != {"custom_branch_policies": True, "protected_branches": False}
        or type(protection["environment_id"]) is not int
        or protection["environment_id"] < 1
        or not isinstance(reviewer_rule_ids, list)
        or not reviewer_rule_ids
        or any(type(rule_id) is not int or rule_id < 1 for rule_id in reviewer_rule_ids)
        or reviewer_rule_ids != sorted(set(reviewer_rule_ids))
        or reviewer_user_ids != [PRODUCT_OWNER_REVIEWER_ID]
        or protection["prevent_self_review"] is not False
        or not isinstance(custom_policies, list)
        or len(custom_policies) != 1
        or not isinstance(custom_policies[0], dict)
        or set(custom_policies[0]) != {"id", "name"}
        or type(custom_policies[0]["id"]) is not int
        or custom_policies[0]["id"] < 1
        or custom_policies[0]["name"] != "main"
        or protection["environment_url"] != activity_url
    ):
        raise CandidateError("existing beta authorization lacks protected environment evidence")
    approval = require_exact_keys(
        authority["environment_approval"],
        {"comment", "environments", "run_attempt", "run_id", "state", "user"},
        "recorded environment approval",
    )
    approved_environments = approval["environments"]
    approved_environment = (
        approved_environments[0]
        if isinstance(approved_environments, list)
        and len(approved_environments) == 1
        and isinstance(approved_environments[0], dict)
        else {}
    )
    expected_environment = {
        "html_url": activity_url,
        "id": protection["environment_id"],
        "name": AUTHORIZATION_ENVIRONMENT,
        "node_id": approved_environment.get("node_id"),
        "url": api_url,
    }
    if (
        approval["state"] != "approved"
        or approval["run_id"] != authority["run_id"]
        or approval["run_attempt"] != authority["run_attempt"]
        or not isinstance(approval["comment"], str)
        or approved_environment != expected_environment
        or not isinstance(expected_environment["node_id"], str)
        or not expected_environment["node_id"]
    ):
        raise CandidateError("existing beta authorization lacks an approved environment review")
    approving_reviewer = user_identity(approval["user"], "recorded approving reviewer")
    if approving_reviewer["id"] not in reviewer_user_ids:
        raise CandidateError("existing beta authorization has an unrecognized approving reviewer")
    return evidence


def load_recorded_evidence(
    raw: bytes,
    request: dict[str, Any],
    qualification: dict[str, Any],
) -> dict[str, Any]:
    if len(raw) > MAX_EVIDENCE_BYTES:
        raise CandidateError("recorded beta authorization evidence exceeds the 1 MiB limit")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise CandidateError("existing beta authorization evidence is not valid JSON") from error
    return validate_recorded_evidence(value, request, qualification)


def existing_authorization(
    repository: Path,
    request: dict[str, Any],
    *,
    remote: str,
    authoritative_authorization: Path | None,
    authoritative_evidence: Path | None,
    authoritative_qualification: Path | None,
) -> dict[str, str] | None:
    authorization = request["authorization"]
    tag = f"{AUTHORIZATION_TAG_PREFIX}{authorization['candidate']}"
    existing_ref = fetch_existing_record(repository, remote, tag)
    if existing_ref is None:
        return None
    existing_authorization = read_record_file(repository, existing_ref, "beta-authorization.json")
    if existing_authorization != canonical_json(authorization):
        raise CandidateError(f"beta authorization {authorization['candidate']} is immutable and differs")
    existing_evidence = read_record_file(repository, existing_ref, "beta-authorization-evidence.json")
    existing_qualification = read_record_file(repository, existing_ref, "target-qualification-evidence.json")
    if len(existing_qualification) > MAX_QUALIFICATION_BYTES:
        raise CandidateError("existing target qualification evidence exceeds the 2 MiB limit")
    try:
        qualification = json.loads(existing_qualification)
    except json.JSONDecodeError as error:
        raise CandidateError("existing target qualification evidence is not valid JSON") from error
    load_recorded_evidence(existing_evidence, request, qualification)
    if authoritative_authorization is not None:
        authoritative_authorization.write_bytes(existing_authorization)
    if authoritative_evidence is not None:
        authoritative_evidence.write_bytes(existing_evidence)
    if authoritative_qualification is not None:
        authoritative_qualification.write_bytes(existing_qualification)
    return {
        "status": "existing",
        "candidate": authorization["candidate"],
        "tag": tag,
        "commit": run_git(["rev-parse", f"{existing_ref}^{{commit}}"], cwd=repository),
    }


def check_authorization(repository: Path, request_path: Path, *, remote: str) -> dict[str, str]:
    request = load_request(request_path)
    existing = existing_authorization(
        repository,
        request,
        remote=remote,
        authoritative_authorization=None,
        authoritative_evidence=None,
        authoritative_qualification=None,
    )
    if existing is not None:
        return existing
    authorization = request["authorization"]
    return {
        "status": "new",
        "candidate": authorization["candidate"],
        "tag": f"{AUTHORIZATION_TAG_PREFIX}{authorization['candidate']}",
    }


def record_authorization(
    repository: Path,
    request_path: Path,
    *,
    qualification_path: Path | None,
    remote: str,
    authoritative_authorization: Path,
    authoritative_evidence: Path,
    authoritative_qualification: Path,
    client: PublicClient,
    actor: str,
    run_id: int,
    run_attempt: int,
    workflow_ref: str,
    workflow_commit: str,
) -> dict[str, str]:
    request = load_request(request_path)
    existing = existing_authorization(
        repository,
        request,
        remote=remote,
        authoritative_authorization=authoritative_authorization,
        authoritative_evidence=authoritative_evidence,
        authoritative_qualification=authoritative_qualification,
    )
    if existing is not None:
        return existing

    authorization = request["authorization"]
    qualification = load_qualification_evidence(qualification_path, request)
    evidence = build_evidence(
        client,
        request,
        qualification,
        actor=actor,
        run_id=run_id,
        run_attempt=run_attempt,
        workflow_ref=workflow_ref,
        workflow_commit=workflow_commit,
    )
    validate_recorded_evidence(evidence, request, qualification)
    canonical_authorization = canonical_json(authorization)
    canonical_evidence = canonical_json(evidence)
    canonical_qualification = canonical_json(qualification)
    tag = f"{AUTHORIZATION_TAG_PREFIX}{authorization['candidate']}"
    with tempfile.NamedTemporaryFile(prefix="beta-authorization-index-", delete=False) as index:
        index_path = Path(index.name)
    try:
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(index_path)
        index_path.unlink(missing_ok=True)
        run_git(["read-tree", "--empty"], cwd=repository, env=env)
        for filename, content in (
            ("beta-authorization.json", canonical_authorization),
            ("beta-authorization-evidence.json", canonical_evidence),
            ("target-qualification-evidence.json", canonical_qualification),
        ):
            blob = subprocess.run(
                ["git", "hash-object", "-w", "--stdin"],
                cwd=repository,
                env=env,
                input=content,
                check=True,
                stdout=subprocess.PIPE,
            ).stdout.decode().strip()
            run_git(
                ["update-index", "--add", "--cacheinfo", f"100644,{blob},{filename}"],
                cwd=repository,
                env=env,
            )
        tree = run_git(["write-tree"], cwd=repository, env=env)
        commit_env = env | {
            "GIT_AUTHOR_NAME": "Durable Workflow Beta Authorizer",
            "GIT_AUTHOR_EMAIL": "support@durable-workflow.com",
            "GIT_COMMITTER_NAME": "Durable Workflow Beta Authorizer",
            "GIT_COMMITTER_EMAIL": "support@durable-workflow.com",
        }
        commit = subprocess.run(
            ["git", "commit-tree", tree],
            cwd=repository,
            env=commit_env,
            input=f"Record beta authorization {authorization['candidate']}\n",
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
                remote=remote,
                authoritative_authorization=authoritative_authorization,
                authoritative_evidence=authoritative_evidence,
                authoritative_qualification=authoritative_qualification,
            )
            if recovered is None:
                raise CandidateError(f"cannot publish immutable beta authorization: {push.stderr.strip()}")
            return recovered
    finally:
        index_path.unlink(missing_ok=True)
    authoritative_authorization.write_bytes(canonical_authorization)
    authoritative_evidence.write_bytes(canonical_evidence)
    authoritative_qualification.write_bytes(canonical_qualification)
    return {
        "status": "created",
        "candidate": authorization["candidate"],
        "tag": tag,
        "commit": commit,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate")
    validate.add_argument("request", type=Path)
    validate.add_argument("destination", type=Path)

    expected = commands.add_parser("expected-commits")
    expected.add_argument("request", type=Path)
    expected.add_argument("destination", type=Path)

    check = commands.add_parser("check")
    check.add_argument("request", type=Path)
    check.add_argument("--repository", type=Path, default=Path.cwd())
    check.add_argument("--remote", default="origin")
    check.add_argument("--github-output", type=Path)

    record = commands.add_parser("record")
    record.add_argument("request", type=Path)
    record.add_argument("--qualification", type=Path)
    record.add_argument("--repository", type=Path, default=Path.cwd())
    record.add_argument("--remote", default="origin")
    record.add_argument("--authoritative-authorization", required=True, type=Path)
    record.add_argument("--authoritative-evidence", required=True, type=Path)
    record.add_argument("--authoritative-qualification", required=True, type=Path)
    record.add_argument("--actor", required=True)
    record.add_argument("--run-id", required=True, type=int)
    record.add_argument("--run-attempt", required=True, type=int)
    record.add_argument("--workflow-ref", required=True)
    record.add_argument("--workflow-commit", required=True)
    record.add_argument("--github-output", type=Path)

    arguments = parser.parse_args()
    try:
        if arguments.command == "validate":
            request = load_request(arguments.request)
            arguments.destination.write_bytes(canonical_json(request))
        elif arguments.command == "expected-commits":
            request = load_request(arguments.request)
            arguments.destination.write_bytes(canonical_json(expected_qualification_commits(request)))
        elif arguments.command == "check":
            result = check_authorization(
                arguments.repository,
                arguments.request,
                remote=arguments.remote,
            )
            write_github_output(arguments.github_output, result)
            print(json.dumps(result, sort_keys=True))
        else:
            result = record_authorization(
                arguments.repository,
                arguments.request,
                qualification_path=arguments.qualification,
                remote=arguments.remote,
                authoritative_authorization=arguments.authoritative_authorization,
                authoritative_evidence=arguments.authoritative_evidence,
                authoritative_qualification=arguments.authoritative_qualification,
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
        print(f"beta authorization failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
