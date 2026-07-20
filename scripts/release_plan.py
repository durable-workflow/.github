#!/usr/bin/env python3
"""Validate, record, discover, and observe immutable public release plans."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any

# GitHub Actions invokes this file directly from the repository root. In that
# mode Python adds scripts/, rather than the repository root, to sys.path.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.beta_candidate import (
    COMPONENTS,
    INFRASTRUCTURE_EXIT_CODE,
    VERIFIERS,
    CandidateError,
    PublicClient,
    PublicInfrastructureError,
    canonical_json,
    fetch_existing_record,
    manifest_digest,
    read_record_file,
    resolve_github_tag,
    run_git,
    validate_verification,
    verify_candidate,
    write_github_output,
)

SCHEMA = "durable-workflow.release-plan/v1"
PREPARATION_SCHEMA = "durable-workflow.release-preparation/v1"
PLAN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,55}$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
ALPHA_VERSION_PATTERN = re.compile(r"^2\.0\.0-alpha\.[1-9][0-9]*$")
BETA_VERSION_PATTERN = re.compile(r"^2\.0\.0-beta\.[1-9][0-9]*$")
PLAN_TAG_PREFIX = "release-plan/"
COMPLETION_TAG_PREFIX = "release-candidate/"
FAILURE_TAG_PREFIX = "release-plan-failure/"
FOUNDATION_TAG = "beta-candidate/beta-continuity-foundation"
FOUNDATION_COMMIT = "4995052410bd4301c5796ffba54e0b6d2f490ed1"
CONTROL_REPOSITORY = "durable-workflow/.github"
SUPERSESSION_ENVIRONMENT = "release-plan-supersession"
SUPERSESSION_WORKFLOW = ".github/workflows/release-plan-supersession.yml"
SUPERSESSION_REASON = "published-version-source-conflict"
SOURCE_MANIFEST_REASON = "source-manifest-version-conflict"
OCCUPIED_SOURCE_MANIFEST_REASON = "occupied-source-manifest-version-conflict"
SUPERSESSION_API_VERSION = "2026-03-10"
SUPERSESSION_ENVIRONMENT_URL = (
    f"https://github.com/{CONTROL_REPOSITORY}/deployments/activity_log"
    f"?environments_filter={SUPERSESSION_ENVIRONMENT}"
)
SUPERSESSION_ENVIRONMENT_API_URL = (
    f"https://api.github.com/repos/{CONTROL_REPOSITORY}/environments/{SUPERSESSION_ENVIRONMENT}"
)

EXPECTED_DEFAULT_BRANCHES = {
    "workflow": "v2",
    "waterline": "v2",
    "server": "main",
    "cli": "main",
    "sdk-php": "main",
    "sdk-python": "main",
    "sdk-rust": "main",
}

SOURCE_MANIFESTS = {
    "sdk-python": {
        "path": "pyproject.toml",
        "package": "durable-workflow",
        "table": "project",
    },
    "sdk-rust": {
        "path": "Cargo.toml",
        "package": "durable-workflow",
        "table": "package",
    },
}

SOURCE_CHANGELOGS = {
    "workflow": "CHANGELOG.md",
    "waterline": "CHANGELOG.md",
    "sdk-php": "CHANGELOG.md",
    "sdk-python": "CHANGELOG.md",
}

MARKDOWN_MEDIA_TYPE = "text/markdown"


def load_plan(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CandidateError(f"cannot read release plan {path}: {error}") from error
    if len(raw) > 64 * 1024:
        raise CandidateError("release plan exceeds the 64 KiB limit")
    try:
        plan = json.loads(raw)
    except json.JSONDecodeError as error:
        raise CandidateError(f"release plan is not valid JSON: {error}") from error
    validate_plan(plan)
    return plan


def validate_plan(plan: Any) -> None:
    if not isinstance(plan, dict):
        raise CandidateError("release plan must be a JSON object")
    expected = {"schema", "plan", "channel", "foundation", "components", "beta_authorization"}
    if set(plan) != expected:
        raise CandidateError(f"release plan keys must be exactly {sorted(expected)}")
    if plan["schema"] != SCHEMA:
        raise CandidateError(f"release plan schema must be {SCHEMA}")
    if not isinstance(plan["plan"], str) or not PLAN_PATTERN.fullmatch(plan["plan"]):
        raise CandidateError("plan must be 1-56 lowercase letters, digits, dots, underscores, or hyphens")
    if plan["channel"] not in {"alpha", "beta"}:
        raise CandidateError("release channel must be alpha or beta")
    if plan["foundation"] != {"tag": FOUNDATION_TAG, "commit": FOUNDATION_COMMIT}:
        raise CandidateError("release plan must name the proven immutable candidate foundation")

    components = plan["components"]
    if not isinstance(components, dict) or set(components) != set(COMPONENTS):
        raise CandidateError(f"components must be exactly {sorted(COMPONENTS)}")
    for name, identity in components.items():
        if not isinstance(identity, dict) or set(identity) != {"version", "commit"}:
            raise CandidateError(f"components.{name} must contain only version and commit")
        if not isinstance(identity["version"], str) or not VERSION_PATTERN.fullmatch(identity["version"]):
            raise CandidateError(f"components.{name}.version must be an exact SemVer release")
        if not isinstance(identity["commit"], str) or not COMMIT_PATTERN.fullmatch(identity["commit"]):
            raise CandidateError(f"components.{name}.commit must be a full lowercase Git commit identity")

    prerelease_pattern = ALPHA_VERSION_PATTERN if plan["channel"] == "alpha" else BETA_VERSION_PATTERN
    for component in ("workflow", "waterline"):
        version = components[component]["version"]
        if not prerelease_pattern.fullmatch(version):
            raise CandidateError(f"{component} version {version} is not an exact 2.0.0-{plan['channel']}.N identity")

    authorization = plan["beta_authorization"]
    if plan["channel"] == "alpha":
        if authorization is not None:
            raise CandidateError("alpha release plans must not claim beta authorization")
    elif (
        not isinstance(authorization, dict)
        or set(authorization) != {"tag", "commit"}
        or not re.fullmatch(r"beta-authorization/[a-z0-9][a-z0-9._-]{0,55}", str(authorization.get("tag", "")))
        or not COMMIT_PATTERN.fullmatch(str(authorization.get("commit", "")))
    ):
        raise CandidateError("beta release plans require an immutable beta authorization tag and commit")


def resolve_tag(client: PublicClient, repository: str, tag: str) -> str | None:
    encoded = urllib.parse.quote(tag, safe="")
    url = f"https://api.github.com/repos/{repository}/git/ref/tags/{encoded}"
    try:
        ref = client.json(url)
    except CandidateError as error:
        if "(404)" in str(error):
            return None
        raise
    target = ref.get("object", {})
    seen: set[str] = set()
    while target.get("type") == "tag":
        sha = target.get("sha")
        if not isinstance(sha, str) or sha in seen:
            raise CandidateError(f"invalid annotated tag chain for {repository}@{tag}")
        seen.add(sha)
        target = client.json(f"https://api.github.com/repos/{repository}/git/tags/{sha}").get("object", {})
    if target.get("type") != "commit" or not COMMIT_PATTERN.fullmatch(str(target.get("sha", ""))):
        raise CandidateError(f"tag {repository}@{tag} does not resolve to a commit")
    return str(target["sha"])


def read_public_record(client: PublicClient, tag: str, commit: str, filename: str) -> Any:
    resolved = resolve_tag(client, CONTROL_REPOSITORY, tag)
    if resolved != commit:
        raise CandidateError(f"public record {tag} resolves to {resolved or 'no commit'}, not {commit}")
    encoded_name = urllib.parse.quote(filename, safe="/")
    raw = client.bytes(
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/contents/{encoded_name}?ref={commit}",
        accept="application/vnd.github.raw+json",
    )
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise CandidateError(f"public record {tag}:{filename} is not valid JSON") from error


def verify_beta_authorization(client: PublicClient, plan: dict[str, Any]) -> None:
    authorization = plan["beta_authorization"]
    if authorization is None:
        return
    record = read_public_record(client, authorization["tag"], authorization["commit"], "beta-authorization.json")
    expected = {
        "schema": "durable-workflow.beta-authorization/v1",
        "channel": "beta",
        "candidate": plan["plan"],
        "components": plan["components"],
    }
    if record != expected:
        raise CandidateError("beta authorization does not name the same candidate and seven-component tuple")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def parse_release_date(value: str) -> str:
    try:
        parsed = dt.date.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise CandidateError("release preparation date must be an exact YYYY-MM-DD date") from error
    if parsed.isoformat() != value:
        raise CandidateError("release preparation date must be an exact YYYY-MM-DD date")
    return value


def unreleased_changelog_body(raw: bytes, component_name: str) -> str:
    if len(raw) > 1024 * 1024:
        raise CandidateError(f"{component_name} CHANGELOG.md exceeds the 1 MiB preparation limit")
    try:
        source = raw.decode("utf-8").replace("\r\n", "\n")
    except UnicodeDecodeError as error:
        raise CandidateError(f"{component_name} CHANGELOG.md is not valid UTF-8") from error
    heading = re.search(r"(?m)^## \[?Unreleased\]?\s*$", source)
    if heading is None:
        raise CandidateError(f"{component_name} CHANGELOG.md has no unique Unreleased section")
    if re.search(r"(?m)^## \[?Unreleased\]?\s*$", source[heading.end() :]):
        raise CandidateError(f"{component_name} CHANGELOG.md has no unique Unreleased section")
    following = re.search(r"(?m)^##\s+", source[heading.end() :])
    end = heading.end() + following.start() if following else len(source)
    body = source[heading.end() : end].strip()
    if not body:
        raise CandidateError(f"{component_name} CHANGELOG.md Unreleased section is empty")
    return body


def component_release_notes(
    plan: dict[str, Any],
    component_name: str,
    client: PublicClient,
    release_date: str,
) -> dict[str, Any]:
    component = COMPONENTS[component_name]
    identity = plan["components"][component_name]
    if component_name in SOURCE_CHANGELOGS:
        path = SOURCE_CHANGELOGS[component_name]
        encoded_path = urllib.parse.quote(path, safe="/")
        raw = client.bytes(
            f"https://api.github.com/repos/{component.repository}/contents/{encoded_path}"
            f"?ref={identity['commit']}",
            accept="application/vnd.github.raw+json",
        )
        body = unreleased_changelog_body(raw, component_name)
        source = {
            "kind": "changelog-unreleased",
            "sha256": sha256_bytes(raw),
            "url": f"https://github.com/{component.repository}/blob/{identity['commit']}/{path}",
        }
    else:
        commit = client.json(
            f"https://api.github.com/repos/{component.repository}/commits/{identity['commit']}"
        )
        message = commit.get("commit", {}).get("message") if isinstance(commit, dict) else None
        if not isinstance(message, str) or not message.strip():
            raise CandidateError(f"{component_name} source commit has no public release-note summary")
        body = message.strip().replace("\r\n", "\n")
        source = {
            "kind": "source-commit-message",
            "sha256": sha256_bytes(body.encode()),
            "url": f"https://github.com/{component.repository}/commit/{identity['commit']}",
        }
    heading = f"## [{identity['version']}] - {release_date}"
    markdown = f"{heading}\n\n{body}\n"
    return {
        "format": MARKDOWN_MEDIA_TYPE,
        "heading": heading,
        "markdown": markdown,
        "release_date": release_date,
        "sha256": sha256_bytes(markdown.encode()),
        "source": source,
    }


def prepare_release(
    plan: dict[str, Any], client: PublicClient, release_date: str
) -> dict[str, Any]:
    validate_plan(plan)
    release_date = parse_release_date(release_date)
    preparation = {
        "schema": PREPARATION_SCHEMA,
        "release_plan": {
            "tag": f"{PLAN_TAG_PREFIX}{plan['plan']}",
            "sha256": manifest_digest(plan),
        },
        "components": {
            name: {
                "version": plan["components"][name]["version"],
                "source_commit": plan["components"][name]["commit"],
                "release_notes": component_release_notes(plan, name, client, release_date),
            }
            for name in COMPONENTS
        },
    }
    validate_release_preparation(preparation, plan)
    return preparation


def validate_release_preparation(preparation: Any, plan: dict[str, Any]) -> None:
    validate_plan(plan)
    if not isinstance(preparation, dict) or set(preparation) != {
        "schema",
        "release_plan",
        "components",
    }:
        raise CandidateError("release preparation has an invalid top-level shape")
    if preparation["schema"] != PREPARATION_SCHEMA:
        raise CandidateError(f"release preparation schema must be {PREPARATION_SCHEMA}")
    expected_plan = {
        "tag": f"{PLAN_TAG_PREFIX}{plan['plan']}",
        "sha256": manifest_digest(plan),
    }
    if preparation["release_plan"] != expected_plan:
        raise CandidateError("release preparation names a different immutable release plan")
    components = preparation["components"]
    if not isinstance(components, dict) or set(components) != set(COMPONENTS):
        raise CandidateError(f"release preparation components must be exactly {sorted(COMPONENTS)}")
    for name, entry in components.items():
        identity = plan["components"][name]
        if not isinstance(entry, dict) or set(entry) != {
            "version",
            "source_commit",
            "release_notes",
        }:
            raise CandidateError(f"release preparation component {name} has an invalid shape")
        if entry["version"] != identity["version"] or entry["source_commit"] != identity["commit"]:
            raise CandidateError(f"release preparation component {name} names a different planned identity")
        notes = entry["release_notes"]
        if not isinstance(notes, dict) or set(notes) != {
            "format",
            "heading",
            "markdown",
            "release_date",
            "sha256",
            "source",
        }:
            raise CandidateError(f"release preparation component {name} has invalid release notes")
        release_date = parse_release_date(notes["release_date"])
        expected_heading = f"## [{identity['version']}] - {release_date}"
        if notes["format"] != MARKDOWN_MEDIA_TYPE or notes["heading"] != expected_heading:
            raise CandidateError(f"release preparation component {name} has a mismatched versioned heading")
        markdown = notes["markdown"]
        if (
            not isinstance(markdown, str)
            or not markdown.startswith(f"{expected_heading}\n\n")
            or not markdown.endswith("\n")
            or notes["sha256"] != sha256_bytes(markdown.encode())
        ):
            raise CandidateError(f"release preparation component {name} has mismatched note content")
        source = notes["source"]
        expected_kind = (
            "changelog-unreleased" if name in SOURCE_CHANGELOGS else "source-commit-message"
        )
        expected_source_url = (
            f"https://github.com/{COMPONENTS[name].repository}/blob/{identity['commit']}/"
            f"{SOURCE_CHANGELOGS[name]}"
            if name in SOURCE_CHANGELOGS
            else f"https://github.com/{COMPONENTS[name].repository}/commit/{identity['commit']}"
        )
        if (
            not isinstance(source, dict)
            or set(source) != {"kind", "sha256", "url"}
            or source["kind"] != expected_kind
            or not re.fullmatch(r"[0-9a-f]{64}", str(source["sha256"]))
            or source["url"] != expected_source_url
        ):
            raise CandidateError(f"release preparation component {name} has invalid note-source evidence")


def revalidate_release_preparation(
    preparation: dict[str, Any], plan: dict[str, Any], client: PublicClient
) -> None:
    validate_release_preparation(preparation, plan)
    dates = {
        entry["release_notes"]["release_date"]
        for entry in preparation["components"].values()
    }
    if len(dates) != 1:
        raise CandidateError("release preparation components do not share one release date")
    expected = prepare_release(plan, client, dates.pop())
    if canonical_json(preparation) != canonical_json(expected):
        raise CandidateError("release preparation no longer matches its immutable source evidence")


def is_immediate_version_successor(previous: str, successor: str) -> bool:
    previous_match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?", previous)
    successor_match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?", successor)
    if previous_match is None or successor_match is None:
        return False
    previous_core = tuple(int(value) for value in previous_match.groups()[:3])
    successor_core = tuple(int(value) for value in successor_match.groups()[:3])
    previous_prerelease = previous_match.group(4)
    successor_prerelease = successor_match.group(4)
    if previous_prerelease is None:
        return successor_prerelease is None and successor_core == (
            previous_core[0],
            previous_core[1],
            previous_core[2] + 1,
        )
    previous_parts = previous_prerelease.rsplit(".", 1)
    successor_parts = (successor_prerelease or "").rsplit(".", 1)
    return (
        successor_core == previous_core
        and len(previous_parts) == 2
        and len(successor_parts) == 2
        and previous_parts[0] == successor_parts[0]
        and previous_parts[1].isdigit()
        and successor_parts[1].isdigit()
        and int(successor_parts[1]) == int(previous_parts[1]) + 1
    )


def conflict_component_names(conflicts: Any) -> list[str]:
    if isinstance(conflicts, str):
        names = [conflicts]
    elif isinstance(conflicts, list):
        names = [
            conflict.get("component") if isinstance(conflict, dict) else conflict
            for conflict in conflicts
        ]
    else:
        raise CandidateError("release plan failure conflicts must be a non-empty list")
    if (
        not names
        or any(not isinstance(name, str) or name not in COMPONENTS for name in names)
        or len(names) != len(set(names))
    ):
        raise CandidateError(f"conflicting components must be unique names from {sorted(COMPONENTS)}")
    expected_order = [name for name in COMPONENTS if name in names]
    if names != expected_order:
        raise CandidateError("conflicting components must follow release-plan component order")
    return names


def parse_conflict_components(value: str) -> list[str]:
    names = [name.strip() for name in value.split(",") if name.strip()]
    return conflict_component_names(names)


def validate_successor_transition(
    failed_plan: dict[str, Any], successor_plan: dict[str, Any], conflicts: str | list[Any]
) -> None:
    validate_plan(failed_plan)
    validate_plan(successor_plan)
    conflict_names = conflict_component_names(conflicts)
    if successor_plan["plan"] == failed_plan["plan"]:
        raise CandidateError("a superseding release plan must use a new plan identity")
    if successor_plan["channel"] != failed_plan["channel"]:
        raise CandidateError("a superseding release plan cannot change the release channel")
    if successor_plan["foundation"] != failed_plan["foundation"]:
        raise CandidateError("a superseding release plan cannot change the candidate foundation")
    for name, identity in failed_plan["components"].items():
        successor_identity = successor_plan["components"][name]
        if name not in conflict_names and successor_identity != identity:
            raise CandidateError(f"superseding release plan changes unaffected component {name}")
    for name in conflict_names:
        failed_identity = failed_plan["components"][name]
        successor_identity = successor_plan["components"][name]
        if successor_identity == failed_identity:
            raise CandidateError(f"superseding release plan leaves conflict unresolved for {name}")

    if isinstance(conflicts, str):
        conflict_records: list[Any] = [{"component": conflicts, "reason": SUPERSESSION_REASON}]
    else:
        conflict_records = conflicts
    if not all(isinstance(conflict, dict) for conflict in conflict_records):
        return
    for conflict in conflict_records:
        name = conflict["component"]
        failed_identity = failed_plan["components"][name]
        successor_identity = successor_plan["components"][name]
        if conflict.get("reason") == SUPERSESSION_REASON:
            if successor_identity["commit"] != failed_identity["commit"]:
                raise CandidateError(
                    f"superseding release plan must retain {name}'s conflicting planned commit"
                )
            if not is_immediate_version_successor(
                failed_identity["version"], successor_identity["version"]
            ):
                raise CandidateError(
                    f"superseding release plan must allocate {name}'s immediate next version"
                )
        elif conflict.get("reason") == SOURCE_MANIFEST_REASON:
            if successor_identity["version"] != failed_identity["version"]:
                raise CandidateError(
                    f"superseding release plan must retain {name}'s intended version"
                )
            if successor_identity["commit"] == failed_identity["commit"]:
                raise CandidateError(
                    f"superseding release plan must replace {name}'s incompatible source commit"
                )
        elif conflict.get("reason") == OCCUPIED_SOURCE_MANIFEST_REASON:
            if not is_immediate_version_successor(
                failed_identity["version"], successor_identity["version"]
            ):
                raise CandidateError(
                    f"superseding release plan must allocate {name}'s immediate next version"
                )
            if successor_identity["commit"] == failed_identity["commit"]:
                raise CandidateError(
                    f"superseding release plan must replace {name}'s incompatible tagged source commit"
                )
        else:
            raise CandidateError(f"release plan failure has an unsupported conflict reason for {name}")


def validate_environment_protection_evidence(protection: Any) -> None:
    expected_keys = {
        "custom_branch_policies",
        "deployment_branch_policy",
        "environment_id",
        "environment_url",
        "required_reviewer_rule_ids",
    }
    if not isinstance(protection, dict) or set(protection) != expected_keys:
        raise CandidateError("release plan failure environment protection evidence has an invalid shape")
    reviewer_rule_ids = protection["required_reviewer_rule_ids"]
    branch_policy = protection["deployment_branch_policy"]
    custom_policies = protection["custom_branch_policies"]
    if (
        type(protection["environment_id"]) is not int
        or protection["environment_id"] < 1
        or protection["environment_url"] != SUPERSESSION_ENVIRONMENT_URL
        or not isinstance(reviewer_rule_ids, list)
        or not reviewer_rule_ids
        or any(type(rule_id) is not int or rule_id < 1 for rule_id in reviewer_rule_ids)
        or reviewer_rule_ids != sorted(set(reviewer_rule_ids))
    ):
        raise CandidateError("release plan failure lacks protected-environment reviewer evidence")
    if branch_policy != {"custom_branch_policies": True, "protected_branches": False}:
        raise CandidateError("release plan failure lacks the protected environment custom-branch policy")
    if (
        not isinstance(custom_policies, list)
        or len(custom_policies) != 1
        or not isinstance(custom_policies[0], dict)
        or set(custom_policies[0]) != {"id", "name"}
        or type(custom_policies[0]["id"]) is not int
        or custom_policies[0]["id"] < 1
        or custom_policies[0]["name"] != "main"
    ):
        raise CandidateError("release plan failure lacks the protected environment custom main-branch policy")


def validate_environment_approval_evidence(approval: Any, authorization: dict[str, Any]) -> None:
    expected_keys = {"comment", "environments", "run_attempt", "run_id", "state", "user"}
    if not isinstance(approval, dict) or set(approval) != expected_keys:
        raise CandidateError("release plan failure environment approval evidence has an invalid shape")
    environments = approval["environments"]
    user = approval["user"]
    protection = authorization["environment_protection"]
    if (
        approval["state"] != "approved"
        or not isinstance(approval["comment"], str)
        or approval["run_id"] != authorization["run_id"]
        or approval["run_attempt"] != authorization["run_attempt"]
        or not isinstance(environments, list)
        or len(environments) != 1
        or not isinstance(environments[0], dict)
        or set(environments[0]) != {"html_url", "id", "name", "node_id", "url"}
    ):
        raise CandidateError("release plan failure lacks an approved deployment bound to its workflow run")
    environment = environments[0]
    if (
        environment["id"] != protection["environment_id"]
        or type(environment["id"]) is not int
        or environment["name"] != SUPERSESSION_ENVIRONMENT
        or environment["url"] != SUPERSESSION_ENVIRONMENT_API_URL
        or environment["html_url"] != SUPERSESSION_ENVIRONMENT_URL
        or not isinstance(environment["node_id"], str)
        or not environment["node_id"]
    ):
        raise CandidateError("release plan failure approval names the wrong protected environment")
    if not isinstance(user, dict) or set(user) != {"html_url", "id", "login", "node_id", "url"}:
        raise CandidateError("release plan failure approving user evidence has an invalid shape")
    login = user["login"]
    if (
        type(user["id"]) is not int
        or user["id"] < 1
        or not isinstance(user["node_id"], str)
        or not user["node_id"]
        or not isinstance(login, str)
        or not re.fullmatch(r"[A-Za-z0-9-]{1,39}", login)
        or user["url"] != f"https://api.github.com/users/{login}"
        or user["html_url"] != f"https://github.com/{login}"
    ):
        raise CandidateError("release plan failure lacks a durable approving user identity")


def validate_source_manifest_evidence(
    evidence: Any,
    component_name: str,
    identity: dict[str, str],
    *,
    must_match_version: bool,
) -> None:
    expected_keys = {"declared_version", "package", "path", "sha256", "source_commit", "url"}
    specification = SOURCE_MANIFESTS.get(component_name)
    if (
        specification is None
        or not isinstance(evidence, dict)
        or set(evidence) != expected_keys
        or evidence["path"] != specification["path"]
        or evidence["package"] != specification["package"]
        or evidence["source_commit"] != identity["commit"]
        or not re.fullmatch(r"[0-9a-f]{64}", str(evidence["sha256"]))
        or not isinstance(evidence["declared_version"], str)
        or not VERSION_PATTERN.fullmatch(evidence["declared_version"])
        or evidence["url"]
        != (
            f"https://github.com/{COMPONENTS[component_name].repository}/blob/"
            f"{identity['commit']}/{specification['path']}"
        )
    ):
        raise CandidateError(f"release plan failure has invalid source-manifest evidence for {component_name}")
    version_matches = evidence["declared_version"] == identity["version"]
    if version_matches is not must_match_version:
        state = "match" if must_match_version else "conflict with"
        raise CandidateError(
            f"release plan failure source manifest does not {state} {component_name} version allocation"
        )


def publication_absence_locations(
    component_name: str, version: str
) -> tuple[dict[str, str], dict[str, str]]:
    component = COMPONENTS[component_name]
    encoded_version = urllib.parse.quote(version, safe="")
    release = {
        "api_url": (
            f"https://api.github.com/repos/{component.repository}/releases/tags/{encoded_version}"
        ),
        "status": "absent",
        "url": f"https://github.com/{component.repository}/releases/tag/{encoded_version}",
    }
    encoded_package = urllib.parse.quote(component.package, safe="")
    if component.distribution == "pypi":
        distribution = {
            "api_url": f"https://pypi.org/pypi/{encoded_package}/{encoded_version}/json",
            "kind": "pypi",
            "status": "absent",
            "url": f"https://pypi.org/project/{encoded_package}/{encoded_version}/",
        }
    elif component.distribution == "crates.io":
        distribution = {
            "api_url": f"https://crates.io/api/v1/crates/{encoded_package}/{encoded_version}",
            "kind": "crates.io",
            "status": "absent",
            "url": f"https://crates.io/crates/{encoded_package}/{encoded_version}",
        }
    else:
        raise CandidateError(
            f"{component_name} has no supported source-manifest distribution absence proof"
        )
    return release, distribution


def validate_occupied_source_manifest_evidence(
    conflict: dict[str, Any], component_name: str, identity: dict[str, str]
) -> None:
    component = COMPONENTS[component_name]
    source_tag = conflict["source_tag"]
    if (
        not isinstance(source_tag, dict)
        or set(source_tag) != {"commit", "repository", "tag", "tag_object", "url"}
        or source_tag["repository"] != component.repository
        or source_tag["tag"] != identity["version"]
        or source_tag["commit"] != identity["commit"]
        or not COMMIT_PATTERN.fullmatch(str(source_tag["tag_object"]))
        or source_tag["url"]
        != f"https://github.com/{component.repository}/tree/{identity['version']}"
    ):
        raise CandidateError(
            f"release plan failure does not prove {component_name}'s occupied planned source tag"
        )
    expected_release, expected_distribution = publication_absence_locations(
        component_name, identity["version"]
    )
    if conflict["github_release"] != expected_release:
        raise CandidateError(
            f"release plan failure lacks {component_name} GitHub Release absence evidence"
        )
    if conflict["distribution"] != expected_distribution:
        raise CandidateError(
            f"release plan failure lacks {component_name} distribution absence evidence"
        )


def validate_conflict_record(
    conflict: Any,
    failed_plan: dict[str, Any],
    successor_plan: dict[str, Any],
) -> None:
    if not isinstance(conflict, dict):
        raise CandidateError("release plan failure conflict evidence has an invalid shape")
    component_name = conflict.get("component")
    if component_name not in COMPONENTS:
        raise CandidateError("release plan failure names an unknown conflicting component")
    identity = failed_plan["components"][component_name]
    successor_identity = successor_plan["components"][component_name]
    common_identity_matches = (
        conflict.get("version") == identity["version"]
        and conflict.get("planned_commit") == identity["commit"]
    )
    reason = conflict.get("reason")
    if reason == SUPERSESSION_REASON:
        expected_keys = {
            "component",
            "version",
            "planned_commit",
            "observed_commit",
            "reason",
            "github_release",
            "distribution",
        }
        if (
            set(conflict) != expected_keys
            or not common_identity_matches
            or not COMMIT_PATTERN.fullmatch(str(conflict.get("observed_commit", "")))
            or conflict["observed_commit"] == identity["commit"]
        ):
            raise CandidateError(
                "release plan failure conflict does not prove a different public source identity"
            )
        release = conflict["github_release"]
        if (
            not isinstance(release, dict)
            or set(release) != {"id", "url"}
            or type(release["id"]) is not int
            or release["id"] < 1
            or not isinstance(release["url"], str)
            or not release["url"].startswith(
                f"https://github.com/{COMPONENTS[component_name].repository}/releases/"
            )
        ):
            raise CandidateError("release plan failure lacks durable GitHub Release evidence")
        distribution = conflict["distribution"]
        if (
            not isinstance(distribution, dict)
            or distribution.get("kind") != COMPONENTS[component_name].distribution
        ):
            raise CandidateError("release plan failure lacks matching distribution evidence")
        require_distribution_identity(distribution, component_name, conflict["observed_commit"])
    elif reason == SOURCE_MANIFEST_REASON:
        expected_keys = {
            "component",
            "version",
            "planned_commit",
            "reason",
            "source_manifest",
            "successor_source_manifest",
        }
        if set(conflict) != expected_keys or not common_identity_matches:
            raise CandidateError("release plan failure manifest conflict evidence has an invalid shape")
        validate_source_manifest_evidence(
            conflict["source_manifest"], component_name, identity, must_match_version=False
        )
        validate_source_manifest_evidence(
            conflict["successor_source_manifest"],
            component_name,
            successor_identity,
            must_match_version=True,
        )
    elif reason == OCCUPIED_SOURCE_MANIFEST_REASON:
        expected_keys = {
            "component",
            "version",
            "planned_commit",
            "reason",
            "source_manifest",
            "source_tag",
            "github_release",
            "distribution",
            "successor_source_manifest",
        }
        if set(conflict) != expected_keys or not common_identity_matches:
            raise CandidateError(
                "release plan failure occupied manifest conflict evidence has an invalid shape"
            )
        validate_source_manifest_evidence(
            conflict["source_manifest"], component_name, identity, must_match_version=False
        )
        validate_source_manifest_evidence(
            conflict["successor_source_manifest"],
            component_name,
            successor_identity,
            must_match_version=True,
        )
        validate_occupied_source_manifest_evidence(conflict, component_name, identity)
    else:
        raise CandidateError(f"release plan failure has an unsupported conflict reason for {component_name}")


def validate_supersession_record(
    record: Any,
    failed_plan: dict[str, Any],
    failed_plan_commit: str,
    successor_plan: dict[str, Any],
) -> None:
    if not isinstance(record, dict):
        raise CandidateError("release plan failure record must be a JSON object")
    expected = {
        "schema",
        "outcome",
        "failed_plan",
        "conflicts",
        "successor_plan",
        "authorization",
    }
    if set(record) != expected:
        raise CandidateError(f"release plan failure record keys must be exactly {sorted(expected)}")
    expected_failed = {
        "tag": f"{PLAN_TAG_PREFIX}{failed_plan['plan']}",
        "commit": failed_plan_commit,
        "sha256": manifest_digest(failed_plan),
    }
    if record["schema"] != "durable-workflow.release-plan-failure/v1":
        raise CandidateError("release plan failure record has an unsupported schema")
    if record["outcome"] != "terminal-failure" or record["failed_plan"] != expected_failed:
        raise CandidateError("release plan failure record does not terminate this exact immutable plan")

    expected_successor = {
        "tag": f"{PLAN_TAG_PREFIX}{successor_plan['plan']}",
        "sha256": manifest_digest(successor_plan),
    }
    if record["successor_plan"] != expected_successor:
        raise CandidateError("release plan failure record names a different successor plan")
    conflicts = record["conflicts"]
    conflict_component_names(conflicts)
    for conflict in conflicts:
        validate_conflict_record(conflict, failed_plan, successor_plan)
    validate_successor_transition(failed_plan, successor_plan, conflicts)

    authorization = record["authorization"]
    authorization_keys = {
        "actor",
        "environment",
        "environment_approval",
        "environment_protection",
        "repository",
        "run_attempt",
        "run_id",
        "run_url",
        "workflow_commit",
        "workflow_ref",
    }
    if not isinstance(authorization, dict) or set(authorization) != authorization_keys:
        raise CandidateError("release plan failure authorization evidence has an invalid shape")
    protection = authorization["environment_protection"]
    validate_environment_protection_evidence(protection)
    workflow_ref = f"{CONTROL_REPOSITORY}/{SUPERSESSION_WORKFLOW}@refs/heads/main"
    if (
        authorization.get("repository") != CONTROL_REPOSITORY
        or authorization.get("environment") != SUPERSESSION_ENVIRONMENT
        or authorization.get("workflow_ref") != workflow_ref
        or not COMMIT_PATTERN.fullmatch(str(authorization.get("workflow_commit", "")))
        or not re.fullmatch(r"[A-Za-z0-9-]{1,39}", str(authorization.get("actor", "")))
        or type(authorization.get("run_id")) is not int
        or authorization["run_id"] < 1
        or type(authorization.get("run_attempt")) is not int
        or authorization["run_attempt"] < 1
        or authorization.get("run_url")
        != f"https://github.com/{CONTROL_REPOSITORY}/actions/runs/{authorization.get('run_id')}"
    ):
        raise CandidateError("release plan failure was not authorized by the protected supersession workflow")
    validate_environment_approval_evidence(authorization["environment_approval"], authorization)


def require_distribution_identity(distribution: dict[str, Any], component_name: str, observed_commit: str) -> None:
    component = COMPONENTS[component_name]
    if distribution.get("kind") != component.distribution:
        raise CandidateError("public distribution evidence has the wrong kind")
    if component.distribution == "composer":
        matches = (
            distribution.get("source_reference") == observed_commit
            and distribution.get("dist_reference") == observed_commit
        )
    elif component.distribution == "github-release":
        source = distribution.get("build_attestation_source")
        matches = isinstance(source, dict) and source.get("commit") == observed_commit
    elif component.distribution == "pypi":
        source = distribution.get("source_identity")
        matches = isinstance(source, dict) and source.get("source_commit") == observed_commit
    elif component.distribution == "crates.io":
        matches = distribution.get("archive_vcs_commit") == observed_commit
    else:
        configs = distribution.get("configs")
        matches = (
            isinstance(configs, list)
            and bool(configs)
            and all(
                isinstance(config, dict)
                and isinstance(config.get("labels"), dict)
                and config["labels"].get("org.opencontainers.image.revision") == observed_commit
                for config in configs
            )
        )
    if not matches:
        raise CandidateError("public distribution evidence does not bind the observed source commit")


def github_release_conflict_evidence(
    client: PublicClient,
    component_name: str,
    version: str,
) -> dict[str, Any]:
    component = COMPONENTS[component_name]
    encoded_version = urllib.parse.quote(version, safe="")
    release = client.json(
        f"https://api.github.com/repos/{component.repository}/releases/tags/{encoded_version}"
    )
    if (
        not isinstance(release, dict)
        or release.get("draft")
        or release.get("tag_name") != version
    ):
        raise CandidateError(
            f"{component_name} version {version} has no public GitHub Release conflict"
        )
    return {
        "id": release.get("id"),
        "url": release.get("html_url"),
    }


def source_manifest_evidence(
    client: PublicClient,
    component_name: str,
    identity: dict[str, str],
) -> dict[str, Any]:
    specification = SOURCE_MANIFESTS.get(component_name)
    if specification is None:
        raise CandidateError(f"{component_name} has no supported source-manifest conflict proof")
    encoded_path = urllib.parse.quote(specification["path"], safe="/")
    raw = client.bytes(
        f"https://api.github.com/repos/{COMPONENTS[component_name].repository}/contents/"
        f"{encoded_path}?ref={identity['commit']}",
        accept="application/vnd.github.raw+json",
    )
    if len(raw) > 1024 * 1024:
        raise CandidateError(f"{component_name} source manifest exceeds the 1 MiB evidence limit")
    try:
        manifest = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise CandidateError(f"{component_name} source manifest is not valid UTF-8 TOML") from error
    package = manifest.get(specification["table"])
    declared_version = package.get("version") if isinstance(package, dict) else None
    declared_package = package.get("name") if isinstance(package, dict) else None
    if declared_package != specification["package"] or not isinstance(declared_version, str):
        raise CandidateError(f"{component_name} source manifest has no exact package identity")
    evidence = {
        "declared_version": declared_version,
        "package": declared_package,
        "path": specification["path"],
        "sha256": hashlib.sha256(raw).hexdigest(),
        "source_commit": identity["commit"],
        "url": (
            f"https://github.com/{COMPONENTS[component_name].repository}/blob/"
            f"{identity['commit']}/{specification['path']}"
        ),
    }
    return evidence


def conflict_components_from_public_evidence(
    failed_plan: dict[str, Any], client: PublicClient
) -> list[str]:
    conflicts = []
    for name in COMPONENTS:
        identity = failed_plan["components"][name]
        if name in SOURCE_MANIFESTS:
            manifest = source_manifest_evidence(client, name, identity)
            if manifest["declared_version"] != identity["version"]:
                conflicts.append(name)
                continue
        observed_commit = resolve_tag(client, COMPONENTS[name].repository, identity["version"])
        if observed_commit not in {None, identity["commit"]}:
            conflicts.append(name)
    return conflicts


def revalidate_conflict_public_evidence(
    conflict: dict[str, Any],
    failed_plan: dict[str, Any],
    successor_plan: dict[str, Any],
    client: PublicClient,
) -> None:
    component_name = conflict["component"]
    component = COMPONENTS[component_name]
    if conflict["reason"] == SUPERSESSION_REASON:
        observed_commit = resolve_tag(client, component.repository, conflict["version"])
        if observed_commit != conflict["observed_commit"]:
            raise CandidateError(
                f"terminal conflict source tag {component.repository}@{conflict['version']} moved from "
                f"{conflict['observed_commit']} to {observed_commit or 'no commit'}"
            )
        try:
            live_release = github_release_conflict_evidence(
                client,
                component_name,
                conflict["version"],
            )
        except CandidateError as error:
            raise CandidateError(
                f"terminal conflict GitHub Release evidence for {component_name} no longer matches GitHub: "
                f"{error}"
            ) from error
        if live_release != conflict["github_release"]:
            raise CandidateError(
                f"terminal conflict GitHub Release evidence for {component_name} no longer matches GitHub"
            )
        try:
            with tempfile.TemporaryDirectory(prefix="release-plan-failure-revalidation-") as temporary:
                live_distribution = VERIFIERS[component.distribution](
                    client,
                    component,
                    conflict["version"],
                    conflict["observed_commit"],
                    Path(temporary),
                )
            require_distribution_identity(
                live_distribution,
                component_name,
                conflict["observed_commit"],
            )
        except CandidateError as error:
            raise CandidateError(
                f"terminal conflict distribution evidence for {component_name} no longer matches its registry: "
                f"{error}"
            ) from error
        if live_distribution != conflict["distribution"]:
            raise CandidateError(
                f"terminal conflict distribution evidence for {component_name} no longer matches its registry"
            )
        return
    failed_identity = failed_plan["components"][component_name]
    successor_identity = successor_plan["components"][component_name]
    if conflict["reason"] == SOURCE_MANIFEST_REASON:
        source_tag_commit = resolve_tag(
            client,
            component.repository,
            failed_identity["version"],
        )
        if source_tag_commit is not None:
            raise CandidateError(
                f"terminal conflict source tag {component.repository}@{failed_identity['version']} "
                f"appeared at {source_tag_commit}"
            )
    elif conflict["reason"] == OCCUPIED_SOURCE_MANIFEST_REASON:
        source_tag = resolve_github_tag(client, component.repository, failed_identity["version"])
        if source_tag != conflict["source_tag"]:
            raise CandidateError(
                f"terminal conflict source tag {component.repository}@{failed_identity['version']} moved"
            )
        try:
            live_release, live_distribution = prove_publication_absence(
                client,
                component_name,
                failed_identity["version"],
            )
        except CandidateError as error:
            raise CandidateError(
                f"terminal conflict publication absence evidence for {component_name} no longer matches "
                f"GitHub and its registry: {error}"
            ) from error
        if (
            live_release != conflict["github_release"]
            or live_distribution != conflict["distribution"]
        ):
            raise CandidateError(
                f"terminal conflict publication absence evidence for {component_name} no longer matches "
                "GitHub and its registry"
            )
    if source_manifest_evidence(client, component_name, failed_identity) != conflict["source_manifest"]:
        raise CandidateError(f"terminal conflict source manifest for {component_name} no longer matches GitHub")
    if (
        source_manifest_evidence(client, component_name, successor_identity)
        != conflict["successor_source_manifest"]
    ):
        raise CandidateError(f"terminal successor source manifest for {component_name} no longer matches GitHub")


def revalidate_supersession_public_evidence(
    record: dict[str, Any],
    failed_plan: dict[str, Any],
    successor_plan: dict[str, Any],
    client: PublicClient,
) -> None:
    for conflict in record["conflicts"]:
        revalidate_conflict_public_evidence(conflict, failed_plan, successor_plan, client)
        component_name = conflict["component"]
        component = COMPONENTS[component_name]
        successor_identity = successor_plan["components"][component_name]
        existing_successor_version = resolve_tag(
            client,
            component.repository,
            successor_identity["version"],
        )
        if existing_successor_version not in {None, successor_identity["commit"]}:
            raise CandidateError(
                f"successor version {component.repository}@{successor_identity['version']} already points to "
                f"{existing_successor_version}"
            )

    authorization = record["authorization"]
    live_protection = protected_environment_evidence(client)
    if live_protection != authorization["environment_protection"]:
        raise CandidateError("release plan failure protected environment policy no longer matches GitHub")
    live_approval = protected_run_approval_evidence(
        client,
        actor=authorization["actor"],
        run_id=authorization["run_id"],
        run_attempt=authorization["run_attempt"],
        workflow_commit=authorization["workflow_commit"],
        environment_protection=live_protection,
    )
    if live_approval != authorization["environment_approval"]:
        raise CandidateError("release plan failure approved deployment evidence no longer matches GitHub")


def load_public_supersession(
    failed_plan: dict[str, Any], failed_plan_commit: str, client: PublicClient
) -> tuple[str, str, dict[str, Any], dict[str, Any]] | None:
    tag = f"{FAILURE_TAG_PREFIX}{failed_plan['plan']}"
    commit = resolve_tag(client, CONTROL_REPOSITORY, tag)
    if commit is None:
        return None
    record = read_public_record(client, tag, commit, "release-plan-failure.json")
    successor = read_public_record(client, tag, commit, "successor-release-plan.json")
    validate_plan(successor)
    validate_supersession_record(record, failed_plan, failed_plan_commit, successor)
    return tag, commit, record, successor


def require_prior_plans_completed(plan: dict[str, Any], client: PublicClient) -> dict[str, dict[str, str]]:
    refs = client.json(f"https://api.github.com/repos/{CONTROL_REPOSITORY}/git/matching-refs/tags/{PLAN_TAG_PREFIX}")
    if not isinstance(refs, list):
        raise CandidateError("GitHub did not return the immutable release-plan tag registry")
    requested_tag = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    completed: dict[str, dict[str, str]] = {}
    for ref in refs:
        name = str(ref.get("ref", ""))
        if not name.startswith("refs/tags/"):
            continue
        tag = name.removeprefix("refs/tags/")
        if not tag.startswith(PLAN_TAG_PREFIX) or tag == requested_tag:
            continue
        record_commit = resolve_tag(client, CONTROL_REPOSITORY, tag)
        if record_commit is None:
            raise CandidateError(f"prior release plan {tag} has no immutable Git record")
        prior = read_public_record(client, tag, record_commit, "release-plan.json")
        validate_plan(prior)
        if tag != f"{PLAN_TAG_PREFIX}{prior['plan']}":
            raise CandidateError(f"prior release plan {tag} has a different document identity")
        completion_tag = f"{COMPLETION_TAG_PREFIX}{prior['channel']}/{prior['plan']}"
        completion_commit = resolve_tag(client, CONTROL_REPOSITORY, completion_tag)
        if completion_commit is None:
            supersession = load_public_supersession(prior, record_commit, client)
            if supersession is None:
                raise CandidateError(
                    f"cannot record {requested_tag} while prior plan {tag} is incomplete; "
                    f"resume its repository Release plan recovery actions"
                )
            failure_tag, failure_commit, failure, successor = supersession
            successor_tag = failure["successor_plan"]["tag"]
            successor_commit = resolve_tag(client, CONTROL_REPOSITORY, successor_tag)
            if successor_commit is None:
                if requested_tag != successor_tag or canonical_json(plan) != canonical_json(successor):
                    raise CandidateError(
                        f"terminal plan {tag} admits only exact successor {successor_tag} at "
                        f"sha256 {failure['successor_plan']['sha256']}"
                    )
            else:
                public_successor = read_public_record(
                    client,
                    successor_tag,
                    successor_commit,
                    "release-plan.json",
                )
                validate_plan(public_successor)
                if canonical_json(public_successor) != canonical_json(successor):
                    raise CandidateError(f"recorded successor {successor_tag} differs from {failure_tag}")
            completed[tag] = {
                "failure_tag": failure_tag,
                "failure_commit": failure_commit,
                "outcome": "terminal-failure",
                "successor_tag": successor_tag,
            }
            continue
        completion = read_public_record(
            client,
            completion_tag,
            completion_commit,
            "release-candidate.json",
        )
        try:
            preparation = read_public_record(
                client,
                tag,
                record_commit,
                "release-preparation.json",
            )
        except CandidateError as error:
            if "(404)" not in str(error):
                raise
            preparation = None
        if preparation is not None:
            validate_release_preparation(preparation, prior)
        if completion != completion_manifest(prior, record_commit, preparation):
            raise CandidateError(f"prior completion record {completion_tag} does not prove {tag}")
        if load_public_supersession(prior, record_commit, client) is not None:
            raise CandidateError(f"prior release plan {tag} has conflicting completion and terminal-failure records")
        completed[tag] = {
            "completion_tag": completion_tag,
            "completion_commit": completion_commit,
            "outcome": "completed",
        }
    return completed


def preflight_plan(
    plan: dict[str, Any], client: PublicClient, *, release_date: str | None = None
) -> dict[str, Any]:
    foundation = read_public_record(client, FOUNDATION_TAG, FOUNDATION_COMMIT, "candidate.json")
    if foundation.get("candidate") != "beta-continuity-foundation":
        raise CandidateError("immutable candidate foundation has an unexpected identity")

    plan_tag = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    plan_commit = resolve_tag(client, CONTROL_REPOSITORY, plan_tag)
    if plan_commit is not None:
        supersession = load_public_supersession(plan, plan_commit, client)
        if supersession is not None:
            _failure_tag, _failure_commit, failure, _successor = supersession
            raise CandidateError(
                f"release plan {plan_tag} has terminally failed; dispatch exact successor "
                f"{failure['successor_plan']['tag']} at sha256 {failure['successor_plan']['sha256']}"
            )

    prior_plans = require_prior_plans_completed(plan, client)
    branches: dict[str, str] = {}
    recovery_workflows: dict[str, dict[str, Any]] = {}
    source_manifests: dict[str, dict[str, Any]] = {}
    tags: dict[str, str] = {}
    for name, component in COMPONENTS.items():
        repository = client.json(f"https://api.github.com/repos/{component.repository}")
        default_branch = repository.get("default_branch")
        expected_branch = EXPECTED_DEFAULT_BRANCHES[name]
        if default_branch != expected_branch:
            raise CandidateError(
                f"{component.repository} default branch is {default_branch!r}; "
                f"release plans require {expected_branch!r}"
            )
        branches[name] = default_branch

        workflow = client.json(
            f"https://api.github.com/repos/{component.repository}/actions/workflows/release-plan-recovery.yml"
        )
        expected_path = ".github/workflows/release-plan-recovery.yml"
        if workflow.get("path") != expected_path or workflow.get("state") != "active":
            raise CandidateError(
                f"{component.repository} does not expose an active {expected_path} on its default branch"
            )
        contents_url = (
            f"https://api.github.com/repos/{component.repository}/contents/{expected_path}?ref={expected_branch}"
        )
        workflow_source = client.bytes(contents_url, accept="application/vnd.github.raw+json").decode("utf-8")
        if (
            not re.search(r"(?m)^  schedule:\s*$", workflow_source)
            or not re.search(r"(?m)^  workflow_dispatch:\s*$", workflow_source)
            or "--preparation-output" not in workflow_source
        ):
            raise CandidateError(
                f"{component.repository} recovery workflow lacks prepared-plan schedule/manual dispatch "
                f"on {expected_branch}"
            )
        recovery_workflows[name] = {
            "default_branch": expected_branch,
            "path": expected_path,
            "state": workflow["state"],
            "workflow_id": workflow.get("id"),
            "url": workflow.get("html_url"),
        }

        identity = plan["components"][name]
        client.json(f"https://api.github.com/repos/{component.repository}/commits/{identity['commit']}")
        if name in SOURCE_MANIFESTS:
            manifest = source_manifest_evidence(client, name, identity)
            if manifest["declared_version"] != identity["version"]:
                raise CandidateError(
                    f"{name} source manifest declares {manifest['declared_version']}, "
                    f"not planned version {identity['version']}"
                )
            source_manifests[name] = manifest
        existing = resolve_tag(client, component.repository, identity["version"])
        if existing is not None and existing != identity["commit"]:
            raise CandidateError(
                f"existing version tag {component.repository}@{identity['version']} points to {existing}, "
                f"not {identity['commit']}"
            )
        tags[name] = existing or "absent"

    verify_beta_authorization(client, plan)
    preparation = prepare_release(
        plan,
        client,
        release_date or dt.datetime.now(dt.UTC).date().isoformat(),
    )
    return {
        "default_branches": branches,
        "prior_plans": prior_plans,
        "recovery_workflows": recovery_workflows,
        "release_preparation": preparation,
        "source_manifests": source_manifests,
        "version_tags": tags,
    }


def check_plan_compatibility(repository: Path, plan_path: Path, *, remote: str) -> dict[str, str]:
    plan = load_plan(plan_path)
    canonical = canonical_json(plan)
    tag = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    existing_ref = fetch_existing_record(repository, remote, tag)
    if not existing_ref:
        return {"status": "new", "plan": plan["plan"], "tag": tag}
    existing = read_record_file(repository, existing_ref, "release-plan.json")
    if existing != canonical:
        raise CandidateError(f"release plan {plan['plan']} is immutable and the requested tuple is different")
    try:
        preparation = json.loads(
            read_record_file(repository, existing_ref, "release-preparation.json")
        )
    except json.JSONDecodeError as error:
        raise CandidateError(f"release plan {plan['plan']} has invalid preparation authority") from error
    validate_release_preparation(preparation, plan)
    return {
        "status": "existing",
        "plan": plan["plan"],
        "tag": tag,
        "commit": run_git(["rev-parse", f"{existing_ref}^{{commit}}"], cwd=repository),
        "preparation_sha256": manifest_digest(preparation),
    }


def load_release_preparation(path: Path, plan: dict[str, Any]) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CandidateError(f"cannot read release preparation {path}: {error}") from error
    if len(raw) > 2 * 1024 * 1024:
        raise CandidateError("release preparation exceeds the 2 MiB limit")
    try:
        preparation = json.loads(raw)
    except json.JSONDecodeError as error:
        raise CandidateError(f"release preparation is not valid JSON: {error}") from error
    validate_release_preparation(preparation, plan)
    return preparation


def record_plan(
    repository: Path,
    plan_path: Path,
    preparation_path: Path,
    *,
    remote: str,
    authoritative_plan: Path,
    authoritative_preparation: Path,
) -> dict[str, str]:
    plan = load_plan(plan_path)
    canonical = canonical_json(plan)
    preparation = load_release_preparation(preparation_path, plan)
    canonical_preparation = canonical_json(preparation)
    tag = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    existing_ref = fetch_existing_record(repository, remote, tag)
    if existing_ref:
        existing = read_record_file(repository, existing_ref, "release-plan.json")
        if existing != canonical:
            raise CandidateError(f"release plan {plan['plan']} is immutable and the requested tuple is different")
        existing_preparation = read_record_file(repository, existing_ref, "release-preparation.json")
        try:
            validate_release_preparation(json.loads(existing_preparation), plan)
        except json.JSONDecodeError as error:
            raise CandidateError(
                f"release plan {plan['plan']} has invalid immutable preparation authority"
            ) from error
        authoritative_plan.write_bytes(existing)
        authoritative_preparation.write_bytes(existing_preparation)
        return {
            "status": "existing",
            "plan": plan["plan"],
            "tag": tag,
            "commit": run_git(["rev-parse", f"{existing_ref}^{{commit}}"], cwd=repository),
            "preparation_sha256": manifest_digest(json.loads(existing_preparation)),
        }

    with tempfile.NamedTemporaryFile(prefix="release-plan-index-", delete=False) as index:
        index_path = Path(index.name)
    try:
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(index_path)
        index_path.unlink(missing_ok=True)
        run_git(["read-tree", "--empty"], cwd=repository, env=env)
        for filename, content in (
            ("release-plan.json", canonical),
            ("release-preparation.json", canonical_preparation),
        ):
            blob = (
                subprocess.run(
                    ["git", "hash-object", "-w", "--stdin"],
                    cwd=repository,
                    env=env,
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
                env=env,
            )
        tree = run_git(["write-tree"], cwd=repository, env=env)
        commit_env = env | {
            "GIT_AUTHOR_NAME": "Durable Workflow Release Planner",
            "GIT_AUTHOR_EMAIL": "support@durable-workflow.com",
            "GIT_COMMITTER_NAME": "Durable Workflow Release Planner",
            "GIT_COMMITTER_EMAIL": "support@durable-workflow.com",
        }
        commit = subprocess.run(
            ["git", "commit-tree", tree],
            cwd=repository,
            env=commit_env,
            input=f"Record release plan {plan['plan']}\n",
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        process = subprocess.run(
            ["git", "push", remote, f"{commit}:refs/tags/{tag}"],
            cwd=repository,
            check=False,
            text=True,
            capture_output=True,
        )
        if process.returncode:
            recovered = check_plan_compatibility(repository, plan_path, remote=remote)
            if recovered["status"] != "existing":
                raise CandidateError(f"cannot publish immutable release plan: {process.stderr.strip()}")
            authoritative_plan.write_bytes(canonical)
            recovered_ref = fetch_existing_record(repository, remote, tag)
            if not recovered_ref:
                raise CandidateError("immutable release preparation disappeared during recovery")
            authoritative_preparation.write_bytes(
                read_record_file(repository, recovered_ref, "release-preparation.json")
            )
            return recovered
        authoritative_plan.write_bytes(canonical)
        authoritative_preparation.write_bytes(canonical_preparation)
        return {
            "status": "created",
            "plan": plan["plan"],
            "tag": tag,
            "commit": commit,
            "preparation_sha256": manifest_digest(preparation),
        }
    finally:
        index_path.unlink(missing_ok=True)


def protected_environment_evidence(client: PublicClient) -> dict[str, Any]:
    encoded = urllib.parse.quote(SUPERSESSION_ENVIRONMENT, safe="")
    environment = client.json(
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/environments/{encoded}",
        headers={"X-GitHub-Api-Version": SUPERSESSION_API_VERSION},
        accept="application/vnd.github+json",
    )
    if not isinstance(environment, dict):
        raise CandidateError(f"GitHub environment {SUPERSESSION_ENVIRONMENT} has invalid public evidence")
    rules = environment.get("protection_rules")
    if not isinstance(rules, list):
        raise CandidateError(f"GitHub environment {SUPERSESSION_ENVIRONMENT} has no protection rules")
    reviewer_rules = [
        rule
        for rule in rules or []
        if isinstance(rule, dict) and rule.get("type") == "required_reviewers" and rule.get("reviewers")
    ]
    rule_ids = sorted(
        rule["id"] for rule in reviewer_rules if type(rule.get("id")) is int and rule["id"] > 0
    )
    if not rule_ids:
        raise CandidateError(
            f"GitHub environment {SUPERSESSION_ENVIRONMENT} must require a reviewer before supersession"
        )
    environment_id = environment.get("id")
    environment_url = environment.get("html_url")
    deployment_branch_policy = environment.get("deployment_branch_policy")
    if (
        type(environment_id) is not int
        or environment_id < 1
        or not isinstance(environment_url, str)
        or environment_url != SUPERSESSION_ENVIRONMENT_URL
    ):
        raise CandidateError(f"GitHub environment {SUPERSESSION_ENVIRONMENT} has invalid public evidence")
    if (
        not isinstance(deployment_branch_policy, dict)
        or deployment_branch_policy.get("custom_branch_policies") is not True
        or deployment_branch_policy.get("protected_branches") is not False
    ):
        raise CandidateError(
            f"GitHub environment {SUPERSESSION_ENVIRONMENT} must enable custom branch policies"
        )
    policies = client.json(
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/environments/{encoded}/"
        "deployment-branch-policies?per_page=100",
        headers={"X-GitHub-Api-Version": SUPERSESSION_API_VERSION},
        accept="application/vnd.github+json",
    )
    branch_policies = policies.get("branch_policies") if isinstance(policies, dict) else None
    if (
        not isinstance(branch_policies, list)
        or type(policies.get("total_count")) is not int
        or policies["total_count"] != 1
        or len(branch_policies) != 1
        or not isinstance(branch_policies[0], dict)
        or type(branch_policies[0].get("id")) is not int
        or branch_policies[0]["id"] < 1
        or branch_policies[0].get("name") != "main"
        or branch_policies[0].get("type", "branch") != "branch"
    ):
        raise CandidateError(
            f"GitHub environment {SUPERSESSION_ENVIRONMENT} must allow only the main branch"
        )
    evidence = {
        "custom_branch_policies": [
            {
                "id": branch_policies[0]["id"],
                "name": branch_policies[0]["name"],
            }
        ],
        "deployment_branch_policy": {
            "custom_branch_policies": True,
            "protected_branches": False,
        },
        "environment_id": environment_id,
        "environment_url": environment_url,
        "required_reviewer_rule_ids": rule_ids,
    }
    validate_environment_protection_evidence(evidence)
    return evidence


def protected_run_approval_evidence(
    client: PublicClient,
    *,
    actor: str,
    run_id: int,
    run_attempt: int,
    workflow_commit: str,
    environment_protection: dict[str, Any],
) -> dict[str, Any]:
    run = client.json(
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/actions/runs/{run_id}",
        headers={"X-GitHub-Api-Version": SUPERSESSION_API_VERSION},
        accept="application/vnd.github+json",
    )
    run_actor = run.get("actor") if isinstance(run, dict) else None
    run_repository = run.get("repository") if isinstance(run, dict) else None
    run_path = run.get("path") if isinstance(run, dict) else None
    accepted_run_paths = {SUPERSESSION_WORKFLOW, f"{SUPERSESSION_WORKFLOW}@main"}
    if (
        not isinstance(run, dict)
        or not isinstance(run_actor, dict)
        or run_actor.get("login") != actor
        or not isinstance(run_repository, dict)
        or run_repository.get("full_name") != CONTROL_REPOSITORY
        or type(run.get("id")) is not int
        or run["id"] != run_id
        or type(run.get("run_attempt")) is not int
        or run["run_attempt"] != run_attempt
        or run.get("event") != "workflow_dispatch"
        or run_path not in accepted_run_paths
        or run.get("head_branch") != "main"
        or run.get("head_sha") != workflow_commit
        or run.get("html_url") != f"https://github.com/{CONTROL_REPOSITORY}/actions/runs/{run_id}"
    ):
        raise CandidateError("protected supersession workflow run evidence does not match GitHub")

    history = client.json(
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/actions/runs/{run_id}/approvals",
        headers={"X-GitHub-Api-Version": SUPERSESSION_API_VERSION},
        accept="application/vnd.github+json",
    )
    if (
        not isinstance(history, list)
        or len(history) != 1
        or not isinstance(history[0], dict)
        or history[0].get("state") != "approved"
    ):
        raise CandidateError("protected supersession run must contain exactly one approved review")
    review = history[0]
    environments = review.get("environments")
    user = review.get("user")
    if (
        not isinstance(review.get("comment"), str)
        or not isinstance(environments, list)
        or len(environments) != 1
        or not isinstance(environments[0], dict)
        or not isinstance(user, dict)
    ):
        raise CandidateError("protected supersession approval history is malformed")
    environment = environments[0]
    evidence = {
        "comment": review["comment"],
        "environments": [
            {
                "html_url": environment.get("html_url"),
                "id": environment.get("id"),
                "name": environment.get("name"),
                "node_id": environment.get("node_id"),
                "url": environment.get("url"),
            }
        ],
        "run_attempt": run_attempt,
        "run_id": run_id,
        "state": review["state"],
        "user": {
            "html_url": user.get("html_url"),
            "id": user.get("id"),
            "login": user.get("login"),
            "node_id": user.get("node_id"),
            "url": user.get("url"),
        },
    }
    validate_environment_approval_evidence(
        evidence,
        {
            "environment_approval": evidence,
            "environment_protection": environment_protection,
            "run_attempt": run_attempt,
            "run_id": run_id,
        },
    )
    return evidence


def prove_publication_absence(
    client: PublicClient, component_name: str, version: str
) -> tuple[dict[str, str], dict[str, str]]:
    release, distribution = publication_absence_locations(component_name, version)
    for surface, evidence in (
        ("GitHub Release", release),
        ("public distribution", distribution),
    ):
        try:
            client.json(evidence["api_url"])
        except CandidateError as error:
            if "(404)" in str(error):
                continue
            raise CandidateError(
                f"cannot prove {component_name} {surface} absence for {version}: {error}"
            ) from error
        raise CandidateError(
            f"{component_name} version {version} already has a {surface}; "
            "an occupied source-manifest conflict requires it to be absent"
        )
    return release, distribution


def prepare_conflict_evidence(
    failed_plan: dict[str, Any],
    successor_plan: dict[str, Any],
    conflict_component: str,
    client: PublicClient,
) -> dict[str, Any]:
    identity = failed_plan["components"][conflict_component]
    successor_identity = successor_plan["components"][conflict_component]
    component = COMPONENTS[conflict_component]
    failed_manifest = (
        source_manifest_evidence(client, conflict_component, identity)
        if conflict_component in SOURCE_MANIFESTS
        else None
    )
    observed_commit = resolve_tag(client, component.repository, identity["version"])
    if failed_manifest is not None and failed_manifest["declared_version"] != identity["version"]:
        successor_manifest = source_manifest_evidence(
            client,
            conflict_component,
            successor_identity,
        )
        if observed_commit is None:
            conflict = {
                "component": conflict_component,
                "version": identity["version"],
                "planned_commit": identity["commit"],
                "reason": SOURCE_MANIFEST_REASON,
                "source_manifest": failed_manifest,
                "successor_source_manifest": successor_manifest,
            }
        elif observed_commit == identity["commit"]:
            source_tag = resolve_github_tag(client, component.repository, identity["version"])
            if source_tag["commit"] != observed_commit:
                raise CandidateError(
                    f"{conflict_component} version {identity['version']} changed while proving its source"
                )
            release_absence, distribution_absence = prove_publication_absence(
                client, conflict_component, identity["version"]
            )
            conflict = {
                "component": conflict_component,
                "version": identity["version"],
                "planned_commit": identity["commit"],
                "reason": OCCUPIED_SOURCE_MANIFEST_REASON,
                "source_manifest": failed_manifest,
                "source_tag": source_tag,
                "github_release": release_absence,
                "distribution": distribution_absence,
                "successor_source_manifest": successor_manifest,
            }
        else:
            raise CandidateError(
                f"{conflict_component} version {identity['version']} has both a source-manifest conflict "
                f"and a version tag at different commit {observed_commit}"
            )
    else:
        if observed_commit is None:
            raise CandidateError(
                f"{conflict_component} version {identity['version']} has no terminal public conflict"
            )
        source = resolve_github_tag(client, component.repository, identity["version"])
        if source["commit"] != observed_commit:
            raise CandidateError(
                f"{conflict_component} version {identity['version']} changed while proving its source"
            )
        if observed_commit == identity["commit"]:
            raise CandidateError(
                f"{conflict_component} version {identity['version']} still resolves to the planned source commit"
            )
        release = github_release_conflict_evidence(
            client,
            conflict_component,
            identity["version"],
        )
        with tempfile.TemporaryDirectory(prefix="release-plan-failure-") as temporary:
            distribution = VERIFIERS[component.distribution](
                client,
                component,
                identity["version"],
                observed_commit,
                Path(temporary),
            )
        require_distribution_identity(distribution, conflict_component, observed_commit)
        conflict = {
            "component": conflict_component,
            "version": identity["version"],
            "planned_commit": identity["commit"],
            "observed_commit": observed_commit,
            "reason": SUPERSESSION_REASON,
            "github_release": release,
            "distribution": distribution,
        }
    existing_successor_version = resolve_tag(
        client,
        component.repository,
        successor_identity["version"],
    )
    if existing_successor_version not in {None, successor_identity["commit"]}:
        raise CandidateError(
            f"successor version {component.repository}@{successor_identity['version']} already points to "
            f"{existing_successor_version}"
        )
    return conflict


def prepare_supersession(
    failed_plan_tag: str,
    conflict_components: str | list[str],
    successor_plan: dict[str, Any],
    client: PublicClient,
    *,
    actor: str,
    run_id: str,
    run_attempt: str,
    workflow_ref: str,
    workflow_commit: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    if not failed_plan_tag.startswith(PLAN_TAG_PREFIX):
        raise CandidateError(f"failed release plan tag must start with {PLAN_TAG_PREFIX}")
    failed_plan_commit = resolve_tag(client, CONTROL_REPOSITORY, failed_plan_tag)
    if failed_plan_commit is None:
        raise CandidateError(f"failed release plan tag {failed_plan_tag} does not exist")
    failed_plan = read_public_record(
        client,
        failed_plan_tag,
        failed_plan_commit,
        "release-plan.json",
    )
    validate_plan(failed_plan)
    if failed_plan_tag != f"{PLAN_TAG_PREFIX}{failed_plan['plan']}":
        raise CandidateError("failed release plan tag and document identity differ")
    component_names = conflict_component_names(conflict_components)
    validate_successor_transition(failed_plan, successor_plan, component_names)
    required_conflicts = conflict_components_from_public_evidence(failed_plan, client)
    missing_conflicts = [name for name in required_conflicts if name not in component_names]
    if missing_conflicts:
        raise CandidateError(
            "conflicting components omit independently proven public conflicts: "
            + ", ".join(missing_conflicts)
        )

    existing = load_public_supersession(failed_plan, failed_plan_commit, client)
    if existing is not None:
        _tag, _commit, record, authoritative_successor = existing
        if canonical_json(successor_plan) != canonical_json(authoritative_successor):
            raise CandidateError("release plan failure is immutable and names a different successor")
        if conflict_component_names(record["conflicts"]) != component_names:
            raise CandidateError("release plan failure is immutable and names different conflicts")
        return record, authoritative_successor

    completion_tag = f"{COMPLETION_TAG_PREFIX}{failed_plan['channel']}/{failed_plan['plan']}"
    if resolve_tag(client, CONTROL_REPOSITORY, completion_tag) is not None:
        raise CandidateError(f"completed release plan {failed_plan_tag} cannot be terminally failed")

    conflicts = [
        prepare_conflict_evidence(failed_plan, successor_plan, name, client)
        for name in component_names
    ]

    try:
        run_id_value = int(run_id)
        run_attempt_value = int(run_attempt)
    except ValueError as error:
        raise CandidateError("protected workflow run identity must be numeric") from error
    protection = protected_environment_evidence(client)
    approval = protected_run_approval_evidence(
        client,
        actor=actor,
        run_id=run_id_value,
        run_attempt=run_attempt_value,
        workflow_commit=workflow_commit,
        environment_protection=protection,
    )
    record = {
        "schema": "durable-workflow.release-plan-failure/v1",
        "outcome": "terminal-failure",
        "failed_plan": {
            "tag": failed_plan_tag,
            "commit": failed_plan_commit,
            "sha256": manifest_digest(failed_plan),
        },
        "conflicts": conflicts,
        "successor_plan": {
            "tag": f"{PLAN_TAG_PREFIX}{successor_plan['plan']}",
            "sha256": manifest_digest(successor_plan),
        },
        "authorization": {
            "actor": actor,
            "environment": SUPERSESSION_ENVIRONMENT,
            "environment_approval": approval,
            "environment_protection": protection,
            "repository": CONTROL_REPOSITORY,
            "run_attempt": run_attempt_value,
            "run_id": run_id_value,
            "run_url": f"https://github.com/{CONTROL_REPOSITORY}/actions/runs/{run_id_value}",
            "workflow_commit": workflow_commit,
            "workflow_ref": workflow_ref,
        },
    }
    validate_supersession_record(record, failed_plan, failed_plan_commit, successor_plan)
    return record, successor_plan


def load_supersession_file(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise CandidateError(f"cannot read release plan failure record {path}: {error}") from error
    if not isinstance(value, dict):
        raise CandidateError("release plan failure record must be a JSON object")
    return value


def record_supersession(
    repository: Path,
    record_path: Path,
    successor_plan_path: Path,
    *,
    remote: str,
    authoritative_record: Path,
    authoritative_successor: Path,
    client: PublicClient,
) -> dict[str, str]:
    record = load_supersession_file(record_path)
    successor = load_plan(successor_plan_path)
    failed = record.get("failed_plan")
    if not isinstance(failed, dict) or not str(failed.get("tag", "")).startswith(PLAN_TAG_PREFIX):
        raise CandidateError("release plan failure record has no failed plan identity")
    failed_plan_name = str(failed["tag"]).removeprefix(PLAN_TAG_PREFIX)
    if not PLAN_PATTERN.fullmatch(failed_plan_name):
        raise CandidateError("release plan failure record has an invalid failed plan identity")
    if record.get("successor_plan") != {
        "tag": f"{PLAN_TAG_PREFIX}{successor['plan']}",
        "sha256": manifest_digest(successor),
    }:
        raise CandidateError("release plan failure record does not bind the supplied successor document")
    failed_plan_commit = resolve_tag(client, CONTROL_REPOSITORY, failed["tag"])
    if failed_plan_commit is None:
        raise CandidateError(f"failed release plan tag {failed['tag']} does not exist")
    failed_plan = read_public_record(
        client,
        failed["tag"],
        failed_plan_commit,
        "release-plan.json",
    )
    validate_plan(failed_plan)
    validate_supersession_record(record, failed_plan, failed_plan_commit, successor)
    canonical_record = canonical_json(record)
    canonical_successor = canonical_json(successor)
    tag = f"{FAILURE_TAG_PREFIX}{failed_plan_name}"
    existing_ref = fetch_existing_record(repository, remote, tag)
    if existing_ref:
        existing_record = read_record_file(repository, existing_ref, "release-plan-failure.json")
        existing_successor = read_record_file(repository, existing_ref, "successor-release-plan.json")
        if existing_record != canonical_record or existing_successor != canonical_successor:
            raise CandidateError(f"release plan failure {failed_plan_name} is immutable and differs")
        authoritative_record.write_bytes(existing_record)
        authoritative_successor.write_bytes(existing_successor)
        return {
            "status": "existing",
            "failed_plan": failed_plan_name,
            "tag": tag,
            "commit": run_git(["rev-parse", f"{existing_ref}^{{commit}}"], cwd=repository),
        }

    completion_tag = f"{COMPLETION_TAG_PREFIX}{failed_plan['channel']}/{failed_plan['plan']}"
    if resolve_tag(client, CONTROL_REPOSITORY, completion_tag) is not None:
        raise CandidateError(f"completed release plan {failed['tag']} cannot be terminally failed")
    revalidate_supersession_public_evidence(record, failed_plan, successor, client)

    with tempfile.NamedTemporaryFile(prefix="release-plan-failure-index-", delete=False) as index:
        index_path = Path(index.name)
    try:
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(index_path)
        index_path.unlink(missing_ok=True)
        run_git(["read-tree", "--empty"], cwd=repository, env=env)
        for filename, content in (
            ("release-plan-failure.json", canonical_record),
            ("successor-release-plan.json", canonical_successor),
        ):
            blob = (
                subprocess.run(
                    ["git", "hash-object", "-w", "--stdin"],
                    cwd=repository,
                    env=env,
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
                env=env,
            )
        tree = run_git(["write-tree"], cwd=repository, env=env)
        commit_env = env | {
            "GIT_AUTHOR_NAME": "Durable Workflow Release Planner",
            "GIT_AUTHOR_EMAIL": "support@durable-workflow.com",
            "GIT_COMMITTER_NAME": "Durable Workflow Release Planner",
            "GIT_COMMITTER_EMAIL": "support@durable-workflow.com",
        }
        commit = subprocess.run(
            ["git", "commit-tree", tree],
            cwd=repository,
            env=commit_env,
            input=f"Record terminal failure for release plan {failed_plan_name}\n",
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        process = subprocess.run(
            ["git", "push", remote, f"{commit}:refs/tags/{tag}"],
            cwd=repository,
            check=False,
            text=True,
            capture_output=True,
        )
        if process.returncode:
            existing_ref = fetch_existing_record(repository, remote, tag)
            if (
                not existing_ref
                or read_record_file(repository, existing_ref, "release-plan-failure.json") != canonical_record
                or read_record_file(repository, existing_ref, "successor-release-plan.json") != canonical_successor
            ):
                raise CandidateError(f"cannot publish immutable release plan failure: {process.stderr.strip()}")
            authoritative_record.write_bytes(canonical_record)
            authoritative_successor.write_bytes(canonical_successor)
            return {
                "status": "existing",
                "failed_plan": failed_plan_name,
                "tag": tag,
                "commit": run_git(["rev-parse", f"{existing_ref}^{{commit}}"], cwd=repository),
            }
        authoritative_record.write_bytes(canonical_record)
        authoritative_successor.write_bytes(canonical_successor)
        return {"status": "created", "failed_plan": failed_plan_name, "tag": tag, "commit": commit}
    finally:
        index_path.unlink(missing_ok=True)


def candidate_manifest(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "durable-workflow.beta-candidate/v1",
        "candidate": f"{plan['channel']}-{plan['plan']}",
        "components": plan["components"],
    }


def completion_manifest(
    plan: dict[str, Any],
    plan_record_commit: str,
    preparation: dict[str, Any] | None = None,
) -> dict[str, Any]:
    completion = {
        "schema": "durable-workflow.release-candidate/v1",
        "candidate": plan["plan"],
        "channel": plan["channel"],
        "release_plan": {
            "tag": f"{PLAN_TAG_PREFIX}{plan['plan']}",
            "commit": plan_record_commit,
            "sha256": manifest_digest(plan),
        },
        "components": plan["components"],
    }
    if preparation is not None:
        validate_release_preparation(preparation, plan)
        completion["release_preparation_sha256"] = manifest_digest(preparation)
    return completion


def record_completion(
    repository: Path,
    plan_path: Path,
    verification_path: Path,
    *,
    remote: str,
    authoritative_completion: Path,
    authoritative_verification: Path,
    client: PublicClient,
) -> dict[str, str]:
    plan = load_plan(plan_path)
    plan_tag = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    plan_record_commit = resolve_tag(client, CONTROL_REPOSITORY, plan_tag)
    if plan_record_commit is None:
        raise CandidateError(f"release plan tag {plan_tag} is absent")
    if load_public_supersession(plan, plan_record_commit, client) is not None:
        raise CandidateError(f"terminally failed release plan {plan_tag} cannot be completed")
    try:
        preparation = read_public_record(
            client,
            plan_tag,
            plan_record_commit,
            "release-preparation.json",
        )
    except CandidateError as error:
        if "(404)" not in str(error):
            raise
        preparation = None
    if preparation is not None:
        validate_release_preparation(preparation, plan)
    completion = completion_manifest(plan, plan_record_commit, preparation)
    canonical_completion = canonical_json(completion)
    try:
        verification = json.loads(verification_path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise CandidateError(f"cannot read public verification: {error}") from error
    validate_verification(verification, candidate_manifest(plan))
    completion_verification = {
        "schema": "durable-workflow.release-candidate-verification/v1",
        "candidate": plan["plan"],
        "channel": plan["channel"],
        "release_plan_sha256": manifest_digest(plan),
        "public_verification": verification,
    }
    if preparation is not None:
        completion_verification["release_preparation_sha256"] = manifest_digest(preparation)
    canonical_verification = canonical_json(completion_verification)
    tag = f"{COMPLETION_TAG_PREFIX}{plan['channel']}/{plan['plan']}"
    existing_ref = fetch_existing_record(repository, remote, tag)
    if existing_ref:
        existing = read_record_file(repository, existing_ref, "release-candidate.json")
        if existing != canonical_completion:
            raise CandidateError(f"completed release candidate {plan['plan']} is immutable and differs")
        existing_verification = read_record_file(repository, existing_ref, "verification.json")
        authoritative_completion.write_bytes(existing)
        authoritative_verification.write_bytes(existing_verification)
        return {
            "status": "existing",
            "candidate": plan["plan"],
            "channel": plan["channel"],
            "tag": tag,
            "commit": run_git(["rev-parse", f"{existing_ref}^{{commit}}"], cwd=repository),
        }

    with tempfile.NamedTemporaryFile(prefix="release-candidate-index-", delete=False) as index:
        index_path = Path(index.name)
    try:
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(index_path)
        index_path.unlink(missing_ok=True)
        run_git(["read-tree", "--empty"], cwd=repository, env=env)
        for filename, content in (
            ("release-candidate.json", canonical_completion),
            ("verification.json", canonical_verification),
        ):
            blob = (
                subprocess.run(
                    ["git", "hash-object", "-w", "--stdin"],
                    cwd=repository,
                    env=env,
                    input=content,
                    check=True,
                    stdout=subprocess.PIPE,
                )
                .stdout.decode()
                .strip()
            )
            run_git(["update-index", "--add", "--cacheinfo", f"100644,{blob},{filename}"], cwd=repository, env=env)
        tree = run_git(["write-tree"], cwd=repository, env=env)
        commit_env = env | {
            "GIT_AUTHOR_NAME": "Durable Workflow Release Observer",
            "GIT_AUTHOR_EMAIL": "support@durable-workflow.com",
            "GIT_COMMITTER_NAME": "Durable Workflow Release Observer",
            "GIT_COMMITTER_EMAIL": "support@durable-workflow.com",
        }
        commit = subprocess.run(
            ["git", "commit-tree", tree],
            cwd=repository,
            env=commit_env,
            input=f"Record completed {plan['channel']} release candidate {plan['plan']}\n",
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        process = subprocess.run(
            ["git", "push", remote, f"{commit}:refs/tags/{tag}"],
            cwd=repository,
            check=False,
            text=True,
            capture_output=True,
        )
        if process.returncode:
            existing_ref = fetch_existing_record(repository, remote, tag)
            if (
                not existing_ref
                or read_record_file(repository, existing_ref, "release-candidate.json") != canonical_completion
            ):
                raise CandidateError(f"cannot publish completed release candidate: {process.stderr.strip()}")
            authoritative_completion.write_bytes(read_record_file(repository, existing_ref, "release-candidate.json"))
            authoritative_verification.write_bytes(read_record_file(repository, existing_ref, "verification.json"))
            return {
                "status": "existing",
                "candidate": plan["plan"],
                "channel": plan["channel"],
                "tag": tag,
                "commit": run_git(["rev-parse", f"{existing_ref}^{{commit}}"], cwd=repository),
            }
        authoritative_completion.write_bytes(canonical_completion)
        authoritative_verification.write_bytes(canonical_verification)
        return {
            "status": "created",
            "candidate": plan["plan"],
            "channel": plan["channel"],
            "tag": tag,
            "commit": commit,
        }
    finally:
        index_path.unlink(missing_ok=True)


def terminal_failure_state(plan: dict[str, Any], client: PublicClient) -> dict[str, Any] | None:
    plan_tag = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    plan_commit = resolve_tag(client, CONTROL_REPOSITORY, plan_tag)
    if plan_commit is None:
        raise CandidateError(f"release plan tag {plan_tag} is absent")
    supersession = load_public_supersession(plan, plan_commit, client)
    if supersession is None:
        return None
    failure_tag, failure_commit, failure, _successor = supersession
    conflicts = failure["conflicts"]
    successor = failure["successor_plan"]
    reasons = []
    for conflict in conflicts:
        if conflict["reason"] == SUPERSESSION_REASON:
            detail = f"public source {conflict['observed_commit']}"
        elif conflict["reason"] == OCCUPIED_SOURCE_MANIFEST_REASON:
            detail = (
                f"occupied planned source tag {conflict['source_tag']['commit']} has manifest version "
                f"{conflict['source_manifest']['declared_version']}; successor "
                f"{conflict['successor_source_manifest']['source_commit']} declares the next allocation"
            )
        else:
            detail = (
                f"source manifest declares {conflict['source_manifest']['declared_version']} and "
                f"successor source {conflict['successor_source_manifest']['source_commit']} is compatible"
            )
        reasons.append(
            f"{conflict['component']}: {conflict['version']} is terminally conflicted; "
            f"planned source {conflict['planned_commit']}, {detail}"
        )
    reason = "; ".join(reasons)
    return {
        "schema": "durable-workflow.release-state/v1",
        "plan": plan["plan"],
        "channel": plan["channel"],
        "plan_sha256": manifest_digest(plan),
        "observed_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "phase": "terminal-failure",
        "outcome": "superseded",
        "failed_components": [conflict["component"] for conflict in conflicts],
        "reason": reason,
        "conflicts": conflicts,
        "durable_evidence": {
            "release_plan": failure["failed_plan"],
            "terminal_failure": {"tag": failure_tag, "commit": failure_commit},
            "protected_action": failure["authorization"],
        },
        "resume_action": (
            f"Download successor-release-plan.json from {failure_tag}, dispatch the Release plan action for exact "
            f"successor {successor['tag']} at sha256 {successor['sha256']}, run its repository Release plan "
            "recovery actions, then rerun Release plan observer"
        ),
    }


def observe_plan(
    plan: dict[str, Any], preparation: dict[str, Any] | None, client: PublicClient
) -> tuple[dict[str, Any], dict[str, Any]]:
    if preparation is not None:
        revalidate_release_preparation(preparation, plan, client)
    candidate = candidate_manifest(plan)
    state: dict[str, Any] = {
        "schema": "durable-workflow.release-state/v1",
        "plan": plan["plan"],
        "channel": plan["channel"],
        "plan_sha256": manifest_digest(plan),
        "observed_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "phase": "public-artifact-verification",
        "outcome": "failed",
        "durable_evidence": {
            "release_plan_tag": f"{PLAN_TAG_PREFIX}{plan['plan']}",
            "component_actions": "repository Actions runs and public version tags",
        },
        "resume_action": "Run the component's Release plan recovery action, then rerun Release plan observer",
    }
    if preparation is not None:
        state["durable_evidence"]["release_preparation_sha256"] = manifest_digest(preparation)
    try:
        for name, component in COMPONENTS.items():
            version = plan["components"][name]["version"]
            encoded = urllib.parse.quote(version, safe="")
            try:
                release = client.json(f"https://api.github.com/repos/{component.repository}/releases/tags/{encoded}")
            except CandidateError as error:
                raise CandidateError(f"{name}: GitHub Release lookup failed: {error}") from error
            if release.get("draft") or release.get("tag_name") != version:
                raise CandidateError(f"{name}: GitHub Release {component.repository}@{version} is not public")
        verification = verify_candidate(candidate, client)
    except CandidateError as error:
        state["reason"] = str(error)
        raise CandidateError(str(error)) from error
    state.update(
        {
            "phase": "complete",
            "outcome": "verified",
            "components": verification["components"],
            "resume_action": "No recovery action is required",
        }
    )
    return verification, state


def discover_plan(
    client: PublicClient, requested_tag: str | None
) -> tuple[str, dict[str, Any], dict[str, Any] | None]:
    if requested_tag:
        tag = requested_tag
        if not tag.startswith(PLAN_TAG_PREFIX):
            raise CandidateError(f"release plan tag must start with {PLAN_TAG_PREFIX}")
    else:
        releases = client.json(f"https://api.github.com/repos/{CONTROL_REPOSITORY}/releases?per_page=100")
        tag = next(
            (
                str(release.get("tag_name"))
                for release in releases
                if not release.get("draft") and str(release.get("tag_name", "")).startswith(PLAN_TAG_PREFIX)
            ),
            "",
        )
        if not tag:
            raise CandidateError("no public release plan is available")
    commit = resolve_tag(client, CONTROL_REPOSITORY, tag)
    if commit is None:
        raise CandidateError(f"release plan tag {tag} does not exist")
    plan = read_public_record(client, tag, commit, "release-plan.json")
    validate_plan(plan)
    if tag != f"{PLAN_TAG_PREFIX}{plan['plan']}":
        raise CandidateError("release plan tag and document identity differ")
    try:
        preparation = read_public_record(client, tag, commit, "release-preparation.json")
    except CandidateError as error:
        if "(404)" not in str(error):
            raise
        preparation = None
    if preparation is not None:
        validate_release_preparation(preparation, plan)
    release = client.json(
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/releases/tags/"
        f"{urllib.parse.quote(tag, safe='')}"
    )
    assets = {asset.get("name"): asset for asset in release.get("assets", [])}
    records = [("release-plan.json", plan)]
    if preparation is not None:
        records.append(("release-preparation.json", preparation))
    for filename, value in records:
        asset = assets.get(filename)
        if not isinstance(asset, dict) or not isinstance(asset.get("browser_download_url"), str):
            raise CandidateError(f"release plan {tag} lacks durable {filename} mirror")
        if client.bytes(asset["browser_download_url"]) != canonical_json(value):
            raise CandidateError(f"release plan {tag} {filename} mirror differs from Git authority")
    return tag, plan, preparation


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("source", type=Path)
    validate.add_argument("destination", type=Path)

    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("plan", type=Path)
    preflight.add_argument("evidence", type=Path)
    preflight.add_argument("--preparation", required=True, type=Path)
    preflight.add_argument("--release-date", required=True)

    check = subparsers.add_parser("check")
    check.add_argument("plan", type=Path)
    check.add_argument("--remote", default="origin")

    record = subparsers.add_parser("record")
    record.add_argument("plan", type=Path)
    record.add_argument("preparation", type=Path)
    record.add_argument("--remote", default="origin")
    record.add_argument("--authoritative-plan", required=True, type=Path)
    record.add_argument("--authoritative-preparation", required=True, type=Path)
    record.add_argument("--github-output", type=Path)

    supersede = subparsers.add_parser("prepare-supersession")
    supersede.add_argument("failed_plan_tag")
    supersede.add_argument("conflict_components")
    supersede.add_argument("successor_plan", type=Path)
    supersede.add_argument("record", type=Path)
    supersede.add_argument("authoritative_successor", type=Path)
    supersede.add_argument("--actor", required=True)
    supersede.add_argument("--run-id", required=True)
    supersede.add_argument("--run-attempt", required=True)
    supersede.add_argument("--workflow-ref", required=True)
    supersede.add_argument("--workflow-commit", required=True)

    record_supersession_parser = subparsers.add_parser("record-supersession")
    record_supersession_parser.add_argument("record", type=Path)
    record_supersession_parser.add_argument("successor_plan", type=Path)
    record_supersession_parser.add_argument("--remote", default="origin")
    record_supersession_parser.add_argument("--authoritative-record", required=True, type=Path)
    record_supersession_parser.add_argument("--authoritative-successor", required=True, type=Path)
    record_supersession_parser.add_argument("--github-output", type=Path)

    discover = subparsers.add_parser("discover")
    discover.add_argument("destination", type=Path)
    discover.add_argument("--preparation", required=True, type=Path)
    discover.add_argument("--tag")
    discover.add_argument("--github-output", type=Path)

    observe = subparsers.add_parser("observe")
    observe.add_argument("plan", type=Path)
    observe.add_argument("preparation", type=Path)
    observe.add_argument("candidate", type=Path)
    observe.add_argument("verification", type=Path)
    observe.add_argument("state", type=Path)

    complete = subparsers.add_parser("complete")
    complete.add_argument("plan", type=Path)
    complete.add_argument("verification", type=Path)
    complete.add_argument("--remote", default="origin")
    complete.add_argument("--authoritative-completion", required=True, type=Path)
    complete.add_argument("--authoritative-verification", required=True, type=Path)
    complete.add_argument("--github-output", type=Path)

    args = parser.parse_args()
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    try:
        if args.command == "validate":
            plan = load_plan(args.source)
            args.destination.write_bytes(canonical_json(plan))
        elif args.command == "preflight":
            plan = load_plan(args.plan)
            evidence = preflight_plan(
                plan,
                PublicClient(token),
                release_date=args.release_date,
            )
            preparation = evidence.pop("release_preparation")
            args.preparation.write_bytes(canonical_json(preparation))
            evidence["release_preparation_sha256"] = manifest_digest(preparation)
            args.evidence.write_bytes(
                canonical_json(
                    {
                        "schema": "durable-workflow.release-plan-preflight/v1",
                        "plan": plan["plan"],
                        "channel": plan["channel"],
                        "outcome": "verified",
                        **evidence,
                    }
                )
            )
        elif args.command == "check":
            print(json.dumps(check_plan_compatibility(Path.cwd(), args.plan, remote=args.remote), sort_keys=True))
        elif args.command == "record":
            result = record_plan(
                Path.cwd(),
                args.plan,
                args.preparation,
                remote=args.remote,
                authoritative_plan=args.authoritative_plan,
                authoritative_preparation=args.authoritative_preparation,
            )
            write_github_output(args.github_output, result)
            print(json.dumps(result, sort_keys=True))
        elif args.command == "prepare-supersession":
            successor = load_plan(args.successor_plan)
            record_value, authoritative_successor = prepare_supersession(
                args.failed_plan_tag,
                parse_conflict_components(args.conflict_components),
                successor,
                PublicClient(token),
                actor=args.actor,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                workflow_ref=args.workflow_ref,
                workflow_commit=args.workflow_commit,
            )
            args.record.write_bytes(canonical_json(record_value))
            args.authoritative_successor.write_bytes(canonical_json(authoritative_successor))
        elif args.command == "record-supersession":
            result = record_supersession(
                Path.cwd(),
                args.record,
                args.successor_plan,
                remote=args.remote,
                authoritative_record=args.authoritative_record,
                authoritative_successor=args.authoritative_successor,
                client=PublicClient(token),
            )
            write_github_output(args.github_output, result)
            print(json.dumps(result, sort_keys=True))
        elif args.command == "discover":
            tag, plan, preparation = discover_plan(PublicClient(token), args.tag)
            args.destination.write_bytes(canonical_json(plan))
            if preparation is not None:
                args.preparation.write_bytes(canonical_json(preparation))
            values = {"tag": tag, "plan": plan["plan"], "channel": plan["channel"]}
            write_github_output(args.github_output, values)
            print(json.dumps(values, sort_keys=True))
        elif args.command == "observe":
            plan = load_plan(args.plan)
            preparation = (
                load_release_preparation(args.preparation, plan)
                if args.preparation.exists()
                else None
            )
            candidate = candidate_manifest(plan)
            args.candidate.write_bytes(canonical_json(candidate))
            client = PublicClient(token)
            terminal_state = terminal_failure_state(plan, client)
            if terminal_state is not None:
                args.state.write_bytes(canonical_json(terminal_state))
                raise CandidateError(terminal_state["reason"])
            try:
                verification, state = observe_plan(plan, preparation, client)
            except CandidateError as error:
                reason = str(error)
                failed_component = next(
                    (name for name in COMPONENTS if reason.startswith(f"{name}:")),
                    None,
                )
                failed_state = {
                    "schema": "durable-workflow.release-state/v1",
                    "plan": plan["plan"],
                    "channel": plan["channel"],
                    "plan_sha256": manifest_digest(plan),
                    "observed_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                    "phase": "public-artifact-verification",
                    "outcome": "failed",
                    "failed_component": failed_component,
                    "reason": reason,
                    "durable_evidence": {
                        "release_plan_tag": f"{PLAN_TAG_PREFIX}{plan['plan']}",
                        "component_actions": "repository Actions runs and public version tags",
                    },
                    "resume_action": (
                        "Run the component's Release plan recovery action, then rerun Release plan observer"
                    ),
                }
                if preparation is not None:
                    failed_state["durable_evidence"]["release_preparation_sha256"] = manifest_digest(
                        preparation
                    )
                args.state.write_bytes(canonical_json(failed_state))
                raise
            args.verification.write_bytes(canonical_json(verification))
            args.state.write_bytes(canonical_json(state))
        elif args.command == "complete":
            result = record_completion(
                Path.cwd(),
                args.plan,
                args.verification,
                remote=args.remote,
                authoritative_completion=args.authoritative_completion,
                authoritative_verification=args.authoritative_verification,
                client=PublicClient(token),
            )
            write_github_output(args.github_output, result)
            print(json.dumps(result, sort_keys=True))
    except PublicInfrastructureError as error:
        print(f"release plan infrastructure failed: {error}", file=sys.stderr)
        return INFRASTRUCTURE_EXIT_CODE
    except CandidateError as error:
        print(f"release plan error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
