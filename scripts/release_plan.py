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

from scripts import component_release_recovery as recovery_discovery
from scripts.beta_candidate import (
    COMPONENTS,
    INFRASTRUCTURE_EXIT_CODE,
    VERIFIERS,
    CandidateError,
    PublicClient,
    PublicInfrastructureError,
    canonical_cli_embedded_identity,
    canonical_json,
    fetch_existing_record,
    load_manifest,
    load_verification,
    manifest_digest,
    read_record_file,
    resolve_github_tag,
    revalidate_verification,
    run_git,
    verify_candidate,
    verify_github_release,
    write_github_output,
)
from scripts.beta_candidate import (
    LEGACY_SCHEMA as LEGACY_CANDIDATE_SCHEMA,
)
from scripts.beta_candidate import (
    SCHEMA as CANDIDATE_SCHEMA,
)
from scripts.product_train import require_current_product_train
from scripts.recovery_workflow_authority import (
    RecoveryWorkflowAuthorityError,
    load_qualified_authority,
    verify_workflow_source,
)

SCHEMA = "durable-workflow.release-plan/v2"
LEGACY_SCHEMA = "durable-workflow.release-plan/v1"
LEGACY_PLAN_DIGESTS = recovery_discovery.LEGACY_PLAN_DIGESTS
PREPARATION_SCHEMA = "durable-workflow.release-preparation/v1"
SOURCE_PREPARATION_SCHEMA = "durable-workflow.release-source-preparation/v1"
PLAN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,55}$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
ALPHA_VERSION_PATTERN = re.compile(r"^2\.0\.0-alpha\.[1-9][0-9]*$")
BETA_VERSION_PATTERN = re.compile(r"^2\.0\.0-beta\.[1-9][0-9]*$")
PLAN_TAG_PREFIX = "release-plan/"
COMPLETION_TAG_PREFIX = "release-candidate/"
FAILURE_TAG_PREFIX = "release-plan-failure/"
CONTINUITY_TAG_PREFIX = "beta-continuity/"
CONTINUITY_EVIDENCE_SCHEMA = "durable-workflow.beta-continuity.evidence/v1"
CONTINUITY_SUPERSESSION_REASON = "missing-post-acceptance-publication-trigger"
CONTINUITY_RESOLUTION_TAG_PREFIX = "release-plan-continuity-resolution/"
CONTINUITY_RESOLUTION_SCHEMA = recovery_discovery.CONTINUITY_RESOLUTION_SCHEMA
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
    f"https://github.com/{CONTROL_REPOSITORY}/deployments/activity_log?environments_filter={SUPERSESSION_ENVIRONMENT}"
)
SUPERSESSION_ENVIRONMENT_API_URL = (
    f"https://api.github.com/repos/{CONTROL_REPOSITORY}/environments/{SUPERSESSION_ENVIRONMENT}"
)
OBSERVATION_MAX_BYTES = 256 * 1024
OBSERVATION_MAX_TEXT = 4096
OBSERVATION_MAX_ITEMS = 64
OBSERVATION_MAX_DEPTH = 12
OBSERVATION_FAILURE_REASON = (
    "Public artifact verification failed; inspect the read-only observer run for component diagnostics"
)
OBSERVATION_RECOVERY_ACTION = (
    "Run the affected component's Release plan recovery action, then rerun Release plan observer"
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

SOURCE_PREPARATION_PATH = Path(__file__).resolve().parent.parent / "release-plans" / "current-source-preparation.json"

MARKDOWN_MEDIA_TYPE = "text/markdown"


def load_recovery_workflow_authority(
    client: PublicClient,
) -> tuple[dict[str, dict[str, str]], dict[str, Any]]:
    identities = {
        name: (component.repository, EXPECTED_DEFAULT_BRANCHES[name])
        for name, component in COMPONENTS.items()
    }
    try:
        return load_qualified_authority(client, identities)
    except RecoveryWorkflowAuthorityError as error:
        raise CandidateError(f"invalid component release recovery authority: {error}") from error


def load_plan(path: Path, *, require_current: bool = False) -> dict[str, Any]:
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
    if require_current and plan["channel"] == "beta":
        require_current_product_train(plan["components"])
    return plan


def validate_plan(plan: Any) -> None:
    _validate_plan(plan, {SCHEMA})


def validate_recorded_plan(plan: Any) -> None:
    """Validate a current plan or an exact plan recorded under the v1 contract."""
    _validate_plan(plan, {LEGACY_SCHEMA, SCHEMA})
    if plan["schema"] == LEGACY_SCHEMA and manifest_digest(plan) not in LEGACY_PLAN_DIGESTS:
        raise CandidateError("legacy release plan is not an exact recorded historical contract")


def _validate_plan(plan: Any, schemas: set[str]) -> None:
    if not isinstance(plan, dict):
        raise CandidateError("release plan must be a JSON object")
    expected = {"schema", "plan", "channel", "foundation", "components", "beta_authorization"}
    if set(plan) != expected:
        raise CandidateError(f"release plan keys must be exactly {sorted(expected)}")
    if plan["schema"] not in schemas:
        raise CandidateError(f"release plan schema must be one of {sorted(schemas)}")
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


def load_source_preparation(path: Path = SOURCE_PREPARATION_PATH) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CandidateError(f"cannot read release source preparation {path}: {error}") from error
    if len(raw) > 64 * 1024:
        raise CandidateError("release source preparation exceeds the 64 KiB limit")
    try:
        preparation = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CandidateError(f"release source preparation is not valid JSON: {error}") from error
    validate_source_preparation(preparation)
    return preparation


def validate_source_preparation(preparation: Any) -> None:
    expected = {
        "$schema",
        "schema",
        "plan",
        "channel",
        "train",
        "status",
        "components",
        "authorization",
    }
    if not isinstance(preparation, dict) or set(preparation) != expected:
        raise CandidateError("release source preparation has an invalid top-level shape")
    if (
        preparation["$schema"] != "./source-preparation-schema.json"
        or preparation["schema"] != SOURCE_PREPARATION_SCHEMA
        or preparation["channel"] != "beta"
        or preparation["status"] != "source-prepared"
        or not isinstance(preparation["plan"], str)
        or not PLAN_PATTERN.fullmatch(preparation["plan"])
    ):
        raise CandidateError("release source preparation has an invalid identity")
    if preparation["authorization"] != {
        "state": "required-after-source-landing",
        "producer": "protected-beta-authorization",
    }:
        raise CandidateError("release source preparation must retain the protected authorization boundary")

    components = preparation["components"]
    if not isinstance(components, dict) or set(components) != set(COMPONENTS):
        raise CandidateError(f"release source preparation components must be exactly {sorted(COMPONENTS)}")
    product_components: dict[str, dict[str, str]] = {}
    for name, identity in components.items():
        if not isinstance(identity, dict) or set(identity) != {"version", "commit", "release_notes"}:
            raise CandidateError(f"release source preparation component {name} has an invalid shape")
        version = identity["version"]
        commit = identity["commit"]
        if (
            not isinstance(version, str)
            or not BETA_VERSION_PATTERN.fullmatch(version)
            or not isinstance(commit, str)
            or not COMMIT_PATTERN.fullmatch(commit)
        ):
            raise CandidateError(f"release source preparation component {name} has an invalid identity")
        notes = identity["release_notes"]
        expected_kind = "changelog-unreleased" if name in SOURCE_CHANGELOGS else "source-commit-message"
        expected_note_keys = {"kind", "sha256", "path"} if name in SOURCE_CHANGELOGS else {"kind", "sha256"}
        if (
            not isinstance(notes, dict)
            or set(notes) != expected_note_keys
            or notes.get("kind") != expected_kind
            or not re.fullmatch(r"[0-9a-f]{64}", str(notes.get("sha256", "")))
            or (name in SOURCE_CHANGELOGS and notes.get("path") != SOURCE_CHANGELOGS[name])
        ):
            raise CandidateError(f"release source preparation component {name} has invalid note authority")
        product_components[name] = {"version": version, "commit": commit}

    current = require_current_product_train(product_components)
    if preparation["train"] != current:
        raise CandidateError("release source preparation does not identify the supported product train")


def require_current_source_preparation(plan: dict[str, Any]) -> dict[str, Any] | None:
    if plan["channel"] != "beta":
        return None
    preparation = load_source_preparation()
    if plan["plan"] != preparation["plan"]:
        raise CandidateError(
            f"beta release plan {plan['plan']} does not match prepared source plan {preparation['plan']}"
        )
    expected_components = {
        name: {"version": identity["version"], "commit": identity["commit"]}
        for name, identity in preparation["components"].items()
    }
    if plan["components"] != expected_components:
        raise CandidateError("beta release plan does not match the exact prepared seven-component source tuple")
    authorization = plan["beta_authorization"]
    if authorization["tag"] != f"beta-authorization/{preparation['plan']}":
        raise CandidateError("beta release plan authorization does not match the prepared source plan")
    return preparation


def require_prepared_note_sources(
    source_preparation: dict[str, Any],
    release_preparation: dict[str, Any],
) -> None:
    for name, prepared_identity in source_preparation["components"].items():
        expected = prepared_identity["release_notes"]
        actual = release_preparation["components"][name]["release_notes"]["source"]
        if actual["kind"] != expected["kind"] or actual["sha256"] != expected["sha256"]:
            raise CandidateError(f"{name} release notes differ from the prepared source authority")


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
            f"https://api.github.com/repos/{component.repository}/contents/{encoded_path}?ref={identity['commit']}",
            accept="application/vnd.github.raw+json",
        )
        body = unreleased_changelog_body(raw, component_name)
        source = {
            "kind": "changelog-unreleased",
            "sha256": sha256_bytes(raw),
            "url": f"https://github.com/{component.repository}/blob/{identity['commit']}/{path}",
        }
    else:
        commit = client.json(f"https://api.github.com/repos/{component.repository}/commits/{identity['commit']}")
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


def prepare_release(plan: dict[str, Any], client: PublicClient, release_date: str) -> dict[str, Any]:
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
    validate_recorded_plan(plan)
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
        expected_kind = "changelog-unreleased" if name in SOURCE_CHANGELOGS else "source-commit-message"
        expected_source_url = (
            f"https://github.com/{COMPONENTS[name].repository}/blob/{identity['commit']}/{SOURCE_CHANGELOGS[name]}"
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


def revalidate_release_preparation(preparation: dict[str, Any], plan: dict[str, Any], client: PublicClient) -> None:
    validate_release_preparation(preparation, plan)
    dates = {entry["release_notes"]["release_date"] for entry in preparation["components"].values()}
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
        names = [conflict.get("component") if isinstance(conflict, dict) else conflict for conflict in conflicts]
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
    validate_recorded_plan(failed_plan)
    validate_recorded_plan(successor_plan)
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
                raise CandidateError(f"superseding release plan must retain {name}'s conflicting planned commit")
            if not is_immediate_version_successor(failed_identity["version"], successor_identity["version"]):
                raise CandidateError(f"superseding release plan must allocate {name}'s immediate next version")
        elif conflict.get("reason") == SOURCE_MANIFEST_REASON:
            if successor_identity["version"] != failed_identity["version"]:
                raise CandidateError(f"superseding release plan must retain {name}'s intended version")
            if successor_identity["commit"] == failed_identity["commit"]:
                raise CandidateError(f"superseding release plan must replace {name}'s incompatible source commit")
        elif conflict.get("reason") == OCCUPIED_SOURCE_MANIFEST_REASON:
            if not is_immediate_version_successor(failed_identity["version"], successor_identity["version"]):
                raise CandidateError(f"superseding release plan must allocate {name}'s immediate next version")
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


def publication_absence_locations(component_name: str, version: str) -> tuple[dict[str, str], dict[str, str]]:
    component = COMPONENTS[component_name]
    encoded_version = urllib.parse.quote(version, safe="")
    release = {
        "api_url": (f"https://api.github.com/repos/{component.repository}/releases/tags/{encoded_version}"),
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
        raise CandidateError(f"{component_name} has no supported source-manifest distribution absence proof")
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
        or source_tag["url"] != f"https://github.com/{component.repository}/tree/{identity['version']}"
    ):
        raise CandidateError(f"release plan failure does not prove {component_name}'s occupied planned source tag")
    expected_release, expected_distribution = publication_absence_locations(component_name, identity["version"])
    if conflict["github_release"] != expected_release:
        raise CandidateError(f"release plan failure lacks {component_name} GitHub Release absence evidence")
    if conflict["distribution"] != expected_distribution:
        raise CandidateError(f"release plan failure lacks {component_name} distribution absence evidence")


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
        conflict.get("version") == identity["version"] and conflict.get("planned_commit") == identity["commit"]
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
            raise CandidateError("release plan failure conflict does not prove a different public source identity")
        release = conflict["github_release"]
        if (
            not isinstance(release, dict)
            or set(release) != {"id", "url"}
            or type(release["id"]) is not int
            or release["id"] < 1
            or not isinstance(release["url"], str)
            or not release["url"].startswith(f"https://github.com/{COMPONENTS[component_name].repository}/releases/")
        ):
            raise CandidateError("release plan failure lacks durable GitHub Release evidence")
        distribution = conflict["distribution"]
        if not isinstance(distribution, dict) or distribution.get("kind") != COMPONENTS[component_name].distribution:
            raise CandidateError("release plan failure lacks matching distribution evidence")
        require_distribution_identity(
            distribution,
            component_name,
            conflict["version"],
            conflict["observed_commit"],
        )
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
            raise CandidateError("release plan failure occupied manifest conflict evidence has an invalid shape")
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
        or authorization["run_attempt"] != 1
        or authorization.get("run_url")
        != f"https://github.com/{CONTROL_REPOSITORY}/actions/runs/{authorization.get('run_id')}"
    ):
        raise CandidateError("release plan failure was not authorized by the protected supersession workflow")
    validate_environment_approval_evidence(authorization["environment_approval"], authorization)


def require_distribution_identity(
    distribution: dict[str, Any], component_name: str, version: str, observed_commit: str
) -> None:
    component = COMPONENTS[component_name]
    if distribution.get("kind") != component.distribution:
        raise CandidateError("public distribution evidence has the wrong kind")
    if component.distribution == "composer":
        matches = (
            distribution.get("source_reference") == observed_commit
            and distribution.get("dist_reference") == observed_commit
        )
    elif component.distribution == "github-release":
        package_source = distribution.get("package_source")
        matches = (
            isinstance(package_source, dict)
            and set(package_source) == {"commit", "embedded_phar_identity"}
            and package_source.get("commit") == observed_commit
            and package_source.get("embedded_phar_identity")
            == canonical_cli_embedded_identity(version, observed_commit)
        )
        authority = distribution.get("build_attestation_authority")
        exact_tag_authority = {
            "mode": "exact-tag",
            "ref": f"refs/tags/{version}",
            "commit": observed_commit,
        }
        qualified_main_authority = {
            "mode": "qualified-main-workflow",
            "ref": "refs/heads/main",
            "workflow": f"{component.repository}/.github/workflows/release.yml",
        }
        if distribution.get("build_attestations_verified") is not True or authority not in (
            exact_tag_authority,
            qualified_main_authority,
        ):
            raise CandidateError("public distribution evidence has an untrusted build attestation authority")
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
    release = client.json(f"https://api.github.com/repos/{component.repository}/releases/tags/{encoded_version}")
    if not isinstance(release, dict) or release.get("draft") or release.get("tag_name") != version:
        raise CandidateError(f"{component_name} version {version} has no public GitHub Release conflict")
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


def conflict_components_from_public_evidence(failed_plan: dict[str, Any], client: PublicClient) -> list[str]:
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
                f"terminal conflict GitHub Release evidence for {component_name} no longer matches GitHub: {error}"
            ) from error
        if live_release != conflict["github_release"]:
            raise CandidateError(
                f"terminal conflict GitHub Release evidence for {component_name} no longer matches GitHub"
            )
        try:
            with tempfile.TemporaryDirectory(prefix="release-plan-failure-revalidation-") as temporary:
                if component.distribution == "github-release":
                    live_distribution = verify_github_release(
                        client,
                        component,
                        conflict["version"],
                        conflict["observed_commit"],
                        Path(temporary),
                    )
                else:
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
                conflict["version"],
                conflict["observed_commit"],
            )
        except CandidateError as error:
            raise CandidateError(
                f"terminal conflict distribution evidence for {component_name} no longer matches its registry: {error}"
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
        if live_release != conflict["github_release"] or live_distribution != conflict["distribution"]:
            raise CandidateError(
                f"terminal conflict publication absence evidence for {component_name} no longer matches "
                "GitHub and its registry"
            )
    if source_manifest_evidence(client, component_name, failed_identity) != conflict["source_manifest"]:
        raise CandidateError(f"terminal conflict source manifest for {component_name} no longer matches GitHub")
    if source_manifest_evidence(client, component_name, successor_identity) != conflict["successor_source_manifest"]:
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

    revalidate_supersession_authority(record, client, require_success=False)


def load_public_supersession(
    failed_plan: dict[str, Any], failed_plan_commit: str, client: PublicClient
) -> tuple[str, str, dict[str, Any], dict[str, Any]] | None:
    tag = f"{FAILURE_TAG_PREFIX}{failed_plan['plan']}"
    commit = resolve_tag(client, CONTROL_REPOSITORY, tag)
    if commit is None:
        return None
    record = read_public_record(client, tag, commit, "release-plan-failure.json")
    successor = read_public_record(client, tag, commit, "successor-release-plan.json")
    validate_recorded_plan(successor)
    validate_supersession_record(record, failed_plan, failed_plan_commit, successor)
    revalidate_supersession_authority(record, client, require_success=True)
    return tag, commit, record, successor


def validate_continuity_supersession(
    successor_plan: dict[str, Any],
    prior_plan: dict[str, Any],
    prior_plan_commit: str,
    client: PublicClient,
    *,
    accepted_tag: str,
    accepted_commit: str,
    accepted_evidence: Any,
    accepted_plan: Any,
) -> dict[str, str]:
    validate_recorded_plan(accepted_plan)
    successor_tag = f"{PLAN_TAG_PREFIX}{successor_plan['plan']}"
    successor_digest = manifest_digest(successor_plan)
    if (
        not isinstance(accepted_evidence, dict)
        or accepted_tag != f"{CONTINUITY_TAG_PREFIX}{successor_plan['plan']}/accepted"
        or canonical_json(accepted_plan) != canonical_json(successor_plan)
        or accepted_evidence.get("schema") != CONTINUITY_EVIDENCE_SCHEMA
        or accepted_evidence.get("phase") != "accepted"
        or accepted_evidence.get("outcome") != "accepted"
        or accepted_evidence.get("release_plan") != {"tag": successor_tag, "sha256": successor_digest}
        or accepted_evidence.get("candidate_identity")
        != {"components": successor_plan["components"], "plan_sha256": successor_digest}
    ):
        raise CandidateError(
            f"accepted continuity record {accepted_tag} does not prove exact requested plan {successor_tag}"
        )

    prior_tag = f"{PLAN_TAG_PREFIX}{prior_plan['plan']}"
    prior_digest = manifest_digest(prior_plan)
    interruption_tag = f"{CONTINUITY_TAG_PREFIX}{prior_plan['plan']}/interrupted"
    superseded = accepted_evidence.get("superseded_interruption")
    if (
        not isinstance(superseded, dict)
        or set(superseded) != {"commit", "evidence_sha256", "plan_sha256", "reason", "tag"}
        or superseded.get("tag") != interruption_tag
        or superseded.get("reason") != CONTINUITY_SUPERSESSION_REASON
        or not COMMIT_PATTERN.fullmatch(str(superseded.get("commit", "")))
        or not re.fullmatch(r"[0-9a-f]{64}", str(superseded.get("evidence_sha256", "")))
        or superseded.get("plan_sha256") != prior_digest
    ):
        raise CandidateError(f"accepted continuity record {accepted_tag} has invalid superseded interruption identity")

    interruption_commit = resolve_tag(client, CONTROL_REPOSITORY, interruption_tag)
    if interruption_commit != superseded["commit"]:
        raise CandidateError(
            f"superseded interruption {interruption_tag} resolves to "
            f"{interruption_commit or 'no commit'}, not {superseded['commit']}"
        )
    interruption_evidence = read_public_record(
        client,
        interruption_tag,
        interruption_commit,
        "continuity-evidence.json",
    )
    interruption_plan = read_public_record(
        client,
        interruption_tag,
        interruption_commit,
        "release-plan.json",
    )
    validate_recorded_plan(interruption_plan)
    if (
        not isinstance(interruption_evidence, dict)
        or canonical_json(interruption_plan) != canonical_json(prior_plan)
        or manifest_digest(interruption_plan) != superseded["plan_sha256"]
        or manifest_digest(interruption_evidence) != superseded["evidence_sha256"]
        or interruption_evidence.get("schema") != CONTINUITY_EVIDENCE_SCHEMA
        or interruption_evidence.get("phase") != "interrupted"
        or interruption_evidence.get("outcome") != "intentionally-interrupted"
        or interruption_evidence.get("release_plan") != {"tag": prior_tag, "sha256": prior_digest}
        or interruption_evidence.get("plan_record")
        != {"tag": prior_tag, "commit": prior_plan_commit, "sha256": prior_digest}
    ):
        raise CandidateError(f"superseded interruption {interruption_tag} does not prove prior plan {prior_tag}")
    return {
        "accepted_tag": accepted_tag,
        "accepted_commit": accepted_commit,
        "interruption_tag": interruption_tag,
        "interruption_commit": interruption_commit,
        "outcome": "superseded-diagnostic-interruption",
    }


def load_continuity_supersession(
    requested_plan: dict[str, Any],
    prior_plan: dict[str, Any],
    prior_plan_commit: str,
    client: PublicClient,
) -> dict[str, str] | None:
    accepted_tag = f"{CONTINUITY_TAG_PREFIX}{requested_plan['plan']}/accepted"
    accepted_commit = resolve_tag(client, CONTROL_REPOSITORY, accepted_tag)
    if accepted_commit is None:
        return None

    accepted_evidence = read_public_record(
        client,
        accepted_tag,
        accepted_commit,
        "continuity-evidence.json",
    )
    accepted_plan = read_public_record(
        client,
        accepted_tag,
        accepted_commit,
        "release-plan.json",
    )
    return validate_continuity_supersession(
        requested_plan,
        prior_plan,
        prior_plan_commit,
        client,
        accepted_tag=accepted_tag,
        accepted_commit=accepted_commit,
        accepted_evidence=accepted_evidence,
        accepted_plan=accepted_plan,
    )


def validate_continuity_resolution_authority(
    resolution: Any,
    client: PublicClient,
) -> dict[str, Any]:
    if (
        not isinstance(resolution, dict)
        or set(resolution)
        != {
            "interruption",
            "qualification",
            "schema",
            "selected_successor",
            "successor_claims",
        }
        or resolution.get("schema") != CONTINUITY_RESOLUTION_SCHEMA
    ):
        raise CandidateError("continuity successor resolution has an invalid document shape")
    interruption = resolution.get("interruption")
    claims = resolution.get("successor_claims")
    selected = resolution.get("selected_successor")
    if (
        not isinstance(interruption, dict)
        or set(interruption) != {"evidence", "plan"}
        or not isinstance(claims, list)
        or len(claims) < 2
    ):
        raise CandidateError("continuity successor resolution does not describe an interrupted fork")

    def require_identity(value: Any, label: str) -> dict[str, str]:
        if (
            not isinstance(value, dict)
            or set(value) != {"commit", "sha256", "tag"}
            or not isinstance(value.get("tag"), str)
            or not isinstance(value.get("commit"), str)
            or not COMMIT_PATTERN.fullmatch(value["commit"])
            or not isinstance(value.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["sha256"])
        ):
            raise CandidateError(f"continuity successor resolution has an invalid {label} identity")
        return value

    interrupted_plan_identity = require_identity(interruption.get("plan"), "interrupted plan")
    interruption_identity = require_identity(interruption.get("evidence"), "interruption evidence")
    interrupted_name = interrupted_plan_identity["tag"].removeprefix(PLAN_TAG_PREFIX)
    if (
        interrupted_plan_identity["tag"] != f"{PLAN_TAG_PREFIX}{interrupted_name}"
        or not PLAN_PATTERN.fullmatch(interrupted_name)
        or interruption_identity["tag"] != f"{CONTINUITY_TAG_PREFIX}{interrupted_name}/interrupted"
    ):
        raise CandidateError("continuity successor resolution has conflicting interruption tags")
    interrupted_commit = resolve_tag(client, CONTROL_REPOSITORY, interrupted_plan_identity["tag"])
    if interrupted_commit != interrupted_plan_identity["commit"]:
        raise CandidateError("continuity successor resolution names a moved interrupted plan")
    interrupted_plan = read_public_record(
        client,
        interrupted_plan_identity["tag"],
        interrupted_commit,
        "release-plan.json",
    )
    validate_recorded_plan(interrupted_plan)
    if (
        interrupted_plan["plan"] != interrupted_name
        or manifest_digest(interrupted_plan) != interrupted_plan_identity["sha256"]
    ):
        raise CandidateError("continuity successor resolution has a mismatched interrupted plan")
    interruption_commit = resolve_tag(client, CONTROL_REPOSITORY, interruption_identity["tag"])
    if interruption_commit != interruption_identity["commit"]:
        raise CandidateError("continuity successor resolution names moved interruption evidence")
    interruption_evidence = read_public_record(
        client,
        interruption_identity["tag"],
        interruption_commit,
        "continuity-evidence.json",
    )
    if manifest_digest(interruption_evidence) != interruption_identity["sha256"]:
        raise CandidateError("continuity successor resolution has mismatched interruption evidence")

    validated_claims: list[dict[str, dict[str, str]]] = []
    for claim in claims:
        if not isinstance(claim, dict) or set(claim) != {"acceptance", "plan"}:
            raise CandidateError("continuity successor resolution has an invalid successor claim")
        plan_identity = require_identity(claim.get("plan"), "successor plan")
        acceptance_identity = require_identity(claim.get("acceptance"), "successor acceptance")
        successor_name = plan_identity["tag"].removeprefix(PLAN_TAG_PREFIX)
        if (
            plan_identity["tag"] != f"{PLAN_TAG_PREFIX}{successor_name}"
            or not PLAN_PATTERN.fullmatch(successor_name)
            or acceptance_identity["tag"] != f"{CONTINUITY_TAG_PREFIX}{successor_name}/accepted"
        ):
            raise CandidateError("continuity successor resolution has conflicting successor tags")
        successor_commit = resolve_tag(client, CONTROL_REPOSITORY, plan_identity["tag"])
        if successor_commit != plan_identity["commit"]:
            raise CandidateError("continuity successor resolution names a moved successor plan")
        successor_plan = read_public_record(
            client,
            plan_identity["tag"],
            successor_commit,
            "release-plan.json",
        )
        validate_recorded_plan(successor_plan)
        if successor_plan["plan"] != successor_name or manifest_digest(successor_plan) != plan_identity["sha256"]:
            raise CandidateError("continuity successor resolution has a mismatched successor plan")
        accepted_commit = resolve_tag(client, CONTROL_REPOSITORY, acceptance_identity["tag"])
        if accepted_commit != acceptance_identity["commit"]:
            raise CandidateError("continuity successor resolution names moved acceptance evidence")
        accepted_evidence = read_public_record(
            client,
            acceptance_identity["tag"],
            accepted_commit,
            "continuity-evidence.json",
        )
        accepted_plan = read_public_record(
            client,
            acceptance_identity["tag"],
            accepted_commit,
            "release-plan.json",
        )
        if manifest_digest(accepted_evidence) != acceptance_identity["sha256"]:
            raise CandidateError("continuity successor resolution has mismatched acceptance evidence")
        validate_continuity_supersession(
            successor_plan,
            interrupted_plan,
            interrupted_plan_identity["commit"],
            client,
            accepted_tag=acceptance_identity["tag"],
            accepted_commit=accepted_commit,
            accepted_evidence=accepted_evidence,
            accepted_plan=accepted_plan,
        )
        validated_claims.append({"plan": plan_identity, "acceptance": acceptance_identity})

    if (
        validated_claims != sorted(validated_claims, key=lambda claim: claim["plan"]["tag"])
        or len({claim["plan"]["tag"] for claim in validated_claims}) != len(validated_claims)
        or selected not in [claim["plan"] for claim in validated_claims]
    ):
        raise CandidateError("continuity successor resolution does not select one exact sorted successor claim")
    try:
        recovery_discovery.validate_continuity_resolution_qualification(
            resolution["qualification"],
            client,
        )
    except recovery_discovery.RecoveryError as error:
        raise CandidateError(str(error)) from error
    return resolution


def continuity_resolution_tag(resolution: dict[str, Any]) -> str:
    interrupted_plan = resolution["interruption"]["plan"]["tag"].removeprefix(PLAN_TAG_PREFIX)
    return f"{CONTINUITY_RESOLUTION_TAG_PREFIX}{interrupted_plan}/{manifest_digest(resolution)}"


def select_completed_continuity_resolution(
    prior_plan: dict[str, Any],
    prior_plan_commit: str,
    matches: list[dict[str, str]],
    client: PublicClient,
) -> dict[str, str]:
    prefix = f"{CONTINUITY_RESOLUTION_TAG_PREFIX}{prior_plan['plan']}/"
    refs = client.json(f"https://api.github.com/repos/{CONTROL_REPOSITORY}/git/matching-refs/tags/{prefix}")
    if not isinstance(refs, list):
        raise CandidateError("GitHub did not return the immutable continuity-resolution tag registry")
    resolution_tags: list[str] = []
    for ref in refs:
        value = ref.get("ref") if isinstance(ref, dict) else None
        tag = value.removeprefix("refs/tags/") if isinstance(value, str) else ""
        if (
            value != f"refs/tags/{tag}"
            or not tag.startswith(prefix)
            or not re.fullmatch(r"[0-9a-f]{64}", tag.removeprefix(prefix))
        ):
            raise CandidateError("GitHub returned a malformed immutable continuity-resolution tag registry entry")
        resolution_tags.append(tag)
    if not resolution_tags:
        raise CandidateError(f"release plan {PLAN_TAG_PREFIX}{prior_plan['plan']} has multiple continuity successors")
    if len(resolution_tags) != 1 or len(set(resolution_tags)) != 1:
        raise CandidateError(
            f"release plan {PLAN_TAG_PREFIX}{prior_plan['plan']} has multiple continuity successor resolutions"
        )
    resolution_tag = resolution_tags[0]
    resolution_commit = resolve_tag(client, CONTROL_REPOSITORY, resolution_tag)
    if resolution_commit is None:
        raise CandidateError(f"continuity successor resolution {resolution_tag} is absent")
    resolution = read_public_record(
        client,
        resolution_tag,
        resolution_commit,
        "continuity-successor-resolution.json",
    )
    expected_claims = sorted(
        (
            {
                "plan": {
                    "tag": match["successor_plan_tag"],
                    "commit": match["successor_plan_commit"],
                    "sha256": match["successor_plan_sha256"],
                },
                "acceptance": {
                    "tag": match["accepted_tag"],
                    "commit": match["accepted_commit"],
                    "sha256": match["acceptance_sha256"],
                },
            }
            for match in matches
        ),
        key=lambda claim: claim["plan"]["tag"],
    )
    expected_interruption = {
        "plan": {
            "tag": f"{PLAN_TAG_PREFIX}{prior_plan['plan']}",
            "commit": prior_plan_commit,
            "sha256": manifest_digest(prior_plan),
        },
        "evidence": {
            "tag": matches[0]["interruption_tag"],
            "commit": matches[0]["interruption_commit"],
            "sha256": matches[0]["interruption_evidence_sha256"],
        },
    }
    selected = resolution.get("selected_successor") if isinstance(resolution, dict) else None
    if (
        not isinstance(resolution, dict)
        or set(resolution)
        != {
            "interruption",
            "qualification",
            "schema",
            "selected_successor",
            "successor_claims",
        }
        or resolution.get("schema") != CONTINUITY_RESOLUTION_SCHEMA
        or resolution.get("interruption") != expected_interruption
        or resolution.get("successor_claims") != expected_claims
        or selected not in [claim["plan"] for claim in expected_claims]
        or resolution_tag != continuity_resolution_tag(resolution)
    ):
        raise CandidateError(
            f"release plan {PLAN_TAG_PREFIX}{prior_plan['plan']} has an invalid immutable "
            "continuity successor resolution"
        )
    try:
        recovery_discovery.validate_continuity_resolution_qualification(
            resolution["qualification"],
            client,
        )
    except recovery_discovery.RecoveryError as error:
        raise CandidateError(str(error)) from error
    return next(match for match in matches if match["successor_plan_tag"] == selected["tag"])


def load_plan_completion(
    plan: dict[str, Any],
    plan_record_commit: str,
    client: PublicClient,
    *,
    record_label: str,
) -> dict[str, str] | None:
    plan_tag = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    completion_tag = f"{COMPLETION_TAG_PREFIX}{plan['channel']}/{plan['plan']}"
    completion_commit = resolve_tag(client, CONTROL_REPOSITORY, completion_tag)
    if completion_commit is None:
        return None
    completion = read_public_record(
        client,
        completion_tag,
        completion_commit,
        "release-candidate.json",
    )
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
    if completion != completion_manifest(plan, plan_record_commit, preparation):
        raise CandidateError(f"{record_label} completion record {completion_tag} does not prove {plan_tag}")
    if load_public_supersession(plan, plan_record_commit, client) is not None:
        raise CandidateError(
            f"{record_label} release plan {plan_tag} has conflicting completion and terminal-failure records"
        )
    return {
        "completion_tag": completion_tag,
        "completion_commit": completion_commit,
        "outcome": "completed",
    }


def discover_completed_continuity_supersession(
    prior_plan: dict[str, Any],
    prior_plan_commit: str,
    release_plan_tags: list[str],
    client: PublicClient,
) -> dict[str, str] | None:
    interruption_tag = f"{CONTINUITY_TAG_PREFIX}{prior_plan['plan']}/interrupted"
    matches: list[dict[str, str]] = []
    for successor_tag in release_plan_tags:
        successor_name = successor_tag.removeprefix(PLAN_TAG_PREFIX)
        accepted_tag = f"{CONTINUITY_TAG_PREFIX}{successor_name}/accepted"
        accepted_commit = resolve_tag(client, CONTROL_REPOSITORY, accepted_tag)
        if accepted_commit is None:
            continue
        accepted_evidence = read_public_record(
            client,
            accepted_tag,
            accepted_commit,
            "continuity-evidence.json",
        )
        superseded = accepted_evidence.get("superseded_interruption") if isinstance(accepted_evidence, dict) else None
        if not isinstance(superseded, dict) or superseded.get("tag") != interruption_tag:
            continue

        accepted_plan = read_public_record(
            client,
            accepted_tag,
            accepted_commit,
            "release-plan.json",
        )
        validate_recorded_plan(accepted_plan)
        supersession = validate_continuity_supersession(
            accepted_plan,
            prior_plan,
            prior_plan_commit,
            client,
            accepted_tag=accepted_tag,
            accepted_commit=accepted_commit,
            accepted_evidence=accepted_evidence,
            accepted_plan=accepted_plan,
        )

        if successor_tag != f"{PLAN_TAG_PREFIX}{accepted_plan['plan']}":
            raise CandidateError(f"accepted continuity successor {accepted_tag} has a different plan identity")
        successor_commit = resolve_tag(client, CONTROL_REPOSITORY, successor_tag)
        if successor_commit is None:
            raise CandidateError(f"accepted continuity successor {successor_tag} has no immutable release plan record")
        public_successor = read_public_record(
            client,
            successor_tag,
            successor_commit,
            "release-plan.json",
        )
        validate_recorded_plan(public_successor)
        if canonical_json(public_successor) != canonical_json(accepted_plan):
            raise CandidateError(f"recorded continuity successor {successor_tag} differs from {accepted_tag}")
        completion = load_plan_completion(
            accepted_plan,
            successor_commit,
            client,
            record_label=f"continuity successor {successor_tag}",
        )
        if completion is None:
            raise CandidateError(f"accepted continuity successor {successor_tag} has no immutable completion record")
        matches.append(
            {
                **supersession,
                "interruption_evidence_sha256": str(accepted_evidence["superseded_interruption"]["evidence_sha256"]),
                "successor_plan_tag": successor_tag,
                "successor_plan_commit": successor_commit,
                "successor_plan_sha256": manifest_digest(accepted_plan),
                "acceptance_sha256": manifest_digest(accepted_evidence),
                "completion_tag": completion["completion_tag"],
                "completion_commit": completion["completion_commit"],
            }
        )

    if not matches:
        return None
    if len(matches) == 1:
        return matches[0]
    return select_completed_continuity_resolution(prior_plan, prior_plan_commit, matches, client)


def require_prior_plans_completed(plan: dict[str, Any], client: PublicClient) -> dict[str, dict[str, str]]:
    refs = client.json(f"https://api.github.com/repos/{CONTROL_REPOSITORY}/git/matching-refs/tags/{PLAN_TAG_PREFIX}")
    if not isinstance(refs, list):
        raise CandidateError("GitHub did not return the immutable release-plan tag registry")
    requested_tag = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    release_plan_tags: list[str] = []
    for ref in refs:
        if not isinstance(ref, dict) or not isinstance(ref.get("ref"), str):
            raise CandidateError("GitHub returned a malformed immutable release-plan tag registry entry")
        tag = ref["ref"].removeprefix("refs/tags/")
        plan_name = tag.removeprefix(PLAN_TAG_PREFIX)
        if (
            ref["ref"] != f"refs/tags/{tag}"
            or not tag.startswith(PLAN_TAG_PREFIX)
            or not PLAN_PATTERN.fullmatch(plan_name)
        ):
            raise CandidateError("GitHub returned a malformed immutable release-plan tag registry entry")
        release_plan_tags.append(tag)
    if len(set(release_plan_tags)) != len(release_plan_tags):
        raise CandidateError("immutable release-plan tag registry contains duplicate authorities")

    completed: dict[str, dict[str, str]] = {}
    release_plan_tags.sort()
    for tag in release_plan_tags:
        if tag == requested_tag:
            continue
        record_commit = resolve_tag(client, CONTROL_REPOSITORY, tag)
        if record_commit is None:
            raise CandidateError(f"prior release plan {tag} has no immutable Git record")
        prior = read_public_record(client, tag, record_commit, "release-plan.json")
        validate_recorded_plan(prior)
        if tag != f"{PLAN_TAG_PREFIX}{prior['plan']}":
            raise CandidateError(f"prior release plan {tag} has a different document identity")
        completion = load_plan_completion(
            prior,
            record_commit,
            client,
            record_label="prior",
        )
        if completion is None:
            supersession = load_public_supersession(prior, record_commit, client)
            if supersession is None:
                continuity_supersession = load_continuity_supersession(
                    plan,
                    prior,
                    record_commit,
                    client,
                )
                if continuity_supersession is None:
                    continuity_supersession = discover_completed_continuity_supersession(
                        prior,
                        record_commit,
                        release_plan_tags,
                        client,
                    )
                if continuity_supersession is None:
                    raise CandidateError(
                        f"cannot record {requested_tag} while prior plan {tag} is incomplete; "
                        f"resume its repository Release plan recovery actions"
                    )
                completed[tag] = continuity_supersession
                continue
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
                validate_recorded_plan(public_successor)
                if canonical_json(public_successor) != canonical_json(successor):
                    raise CandidateError(f"recorded successor {successor_tag} differs from {failure_tag}")
            completed[tag] = {
                "failure_tag": failure_tag,
                "failure_commit": failure_commit,
                "outcome": "terminal-failure",
                "successor_tag": successor_tag,
            }
            continue
        completed[tag] = completion
    return completed


def preflight_plan(plan: dict[str, Any], client: PublicClient, *, release_date: str | None = None) -> dict[str, Any]:
    source_preparation = require_current_source_preparation(plan)
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
    recovery_authority, recovery_authority_source = load_recovery_workflow_authority(client)
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

        expected_workflow = recovery_authority[name]
        workflow = client.json(
            f"https://api.github.com/repos/{component.repository}/actions/workflows/release-plan-recovery.yml"
        )
        expected_path = expected_workflow["path"]
        if workflow.get("path") != expected_path or workflow.get("state") != expected_workflow["state"]:
            raise CandidateError(
                f"{component.repository} does not expose an active {expected_path} on its default branch"
            )
        contents_url = (
            f"https://api.github.com/repos/{component.repository}/contents/{expected_path}?ref={expected_branch}"
        )
        workflow_source = client.bytes(contents_url, accept="application/vnd.github.raw+json").decode("utf-8")
        try:
            workflow_sha256 = verify_workflow_source(name, workflow_source, expected_workflow["sha256"])
        except RecoveryWorkflowAuthorityError as error:
            raise CandidateError(str(error)) from error
        helper_path = "scripts/ci/component-release-recovery.py"
        helper_source = client.bytes(
            f"https://api.github.com/repos/{component.repository}/contents/{helper_path}?ref={expected_branch}",
            accept="application/vnd.github.raw+json",
        ).decode("utf-8")
        if (
            'CONTINUITY_TAG_PREFIX = "beta-continuity/"' not in helper_source
            or "def scheduled_continuity_pause(" not in helper_source
            or "if args.plan_tag is None" not in helper_source
            or '"phase": "continuity-gate"' not in helper_source
        ):
            raise CandidateError(
                f"{component.repository} recovery helper lacks deterministic scheduled continuity gating "
                "with exact-plan manual recovery"
            )
        recovery_workflows[name] = {
            "authority": recovery_authority_source,
            "continuity_gate": "scheduled-pause-with-exact-plan-recovery",
            "default_branch": expected_branch,
            "path": expected_path,
            "sha256": workflow_sha256,
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
    if source_preparation is not None:
        require_prepared_note_sources(source_preparation, preparation)
    evidence = {
        "default_branches": branches,
        "prior_plans": prior_plans,
        "recovery_workflows": recovery_workflows,
        "release_preparation": preparation,
        "source_manifests": source_manifests,
        "version_tags": tags,
    }
    if source_preparation is not None:
        evidence["source_preparation"] = {
            "path": "release-plans/current-source-preparation.json",
            "plan": source_preparation["plan"],
            "sha256": manifest_digest(source_preparation),
        }
    return evidence


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
        preparation = json.loads(read_record_file(repository, existing_ref, "release-preparation.json"))
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
            raise CandidateError(f"release plan {plan['plan']} has invalid immutable preparation authority") from error
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


def protected_environment_evidence(
    client: PublicClient,
) -> tuple[dict[str, Any], set[tuple[int, str]]]:
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
    rule_ids = sorted(rule["id"] for rule in reviewer_rules if type(rule.get("id")) is int and rule["id"] > 0)
    if len(reviewer_rules) != 1 or len(rule_ids) != 1:
        raise CandidateError(
            f"GitHub environment {SUPERSESSION_ENVIRONMENT} must contain one explicit reviewer policy"
        )
    reviewer_user_ids: list[int] = []
    required_reviewers: set[tuple[int, str]] = set()
    for reviewer in reviewer_rules[0]["reviewers"]:
        identity = reviewer.get("reviewer") if isinstance(reviewer, dict) else None
        if (
            not isinstance(identity, dict)
            or reviewer.get("type") != "User"
            or type(identity.get("id")) is not int
            or identity["id"] < 1
            or not isinstance(identity.get("login"), str)
            or not re.fullmatch(r"[A-Za-z0-9-]{1,39}", identity["login"])
        ):
            raise CandidateError(
                f"GitHub environment {SUPERSESSION_ENVIRONMENT} has an unverifiable required reviewer"
            )
        reviewer_user_ids.append(identity["id"])
        required_reviewers.add((identity["id"], identity["login"]))
    reviewer_user_ids = sorted(set(reviewer_user_ids))
    prevent_self_review = reviewer_rules[0].get("prevent_self_review")
    if not reviewer_user_ids or type(prevent_self_review) is not bool:
        raise CandidateError(
            f"GitHub environment {SUPERSESSION_ENVIRONMENT} has an invalid required reviewer policy"
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
        raise CandidateError(f"GitHub environment {SUPERSESSION_ENVIRONMENT} must enable custom branch policies")
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
        raise CandidateError(f"GitHub environment {SUPERSESSION_ENVIRONMENT} must allow only the main branch")
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
    return evidence, required_reviewers


def protected_run_approval_evidence(
    client: PublicClient,
    *,
    actor: str,
    run_id: int,
    run_attempt: int,
    workflow_commit: str,
    environment_protection: dict[str, Any],
    required_reviewers: set[tuple[int, str]],
    require_success: bool = False,
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
        or (
            require_success
            and (run.get("status") != "completed" or run.get("conclusion") != "success")
        )
    ):
        raise CandidateError("protected supersession workflow run evidence does not match GitHub")
    if run_attempt != 1:
        raise CandidateError(
            "GitHub approval history cannot prove protected approval for a rerun attempt"
        )

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
    if (evidence["user"]["id"], evidence["user"]["login"]) not in required_reviewers:
        raise CandidateError(
            "protected supersession approving user is not authorized by the current reviewer policy"
        )
    return evidence


def revalidate_supersession_authority(
    record: dict[str, Any],
    client: PublicClient,
    *,
    require_success: bool,
) -> None:
    authorization = record["authorization"]
    live_protection, required_reviewers = protected_environment_evidence(client)
    if live_protection != authorization["environment_protection"]:
        raise CandidateError("release plan failure protected environment policy no longer matches GitHub")
    live_approval = protected_run_approval_evidence(
        client,
        actor=authorization["actor"],
        run_id=authorization["run_id"],
        run_attempt=authorization["run_attempt"],
        workflow_commit=authorization["workflow_commit"],
        environment_protection=live_protection,
        required_reviewers=required_reviewers,
        require_success=require_success,
    )
    if live_approval != authorization["environment_approval"]:
        raise CandidateError("release plan failure approved deployment evidence no longer matches GitHub")


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
            raise CandidateError(f"cannot prove {component_name} {surface} absence for {version}: {error}") from error
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
            raise CandidateError(f"{conflict_component} version {identity['version']} has no terminal public conflict")
        source = resolve_github_tag(client, component.repository, identity["version"])
        if source["commit"] != observed_commit:
            raise CandidateError(f"{conflict_component} version {identity['version']} changed while proving its source")
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
        require_distribution_identity(
            distribution,
            conflict_component,
            identity["version"],
            observed_commit,
        )
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
    validate_recorded_plan(failed_plan)
    if failed_plan_tag != f"{PLAN_TAG_PREFIX}{failed_plan['plan']}":
        raise CandidateError("failed release plan tag and document identity differ")
    component_names = conflict_component_names(conflict_components)
    validate_successor_transition(failed_plan, successor_plan, component_names)
    required_conflicts = conflict_components_from_public_evidence(failed_plan, client)
    missing_conflicts = [name for name in required_conflicts if name not in component_names]
    if missing_conflicts:
        raise CandidateError(
            "conflicting components omit independently proven public conflicts: " + ", ".join(missing_conflicts)
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

    conflicts = [prepare_conflict_evidence(failed_plan, successor_plan, name, client) for name in component_names]

    try:
        run_id_value = int(run_id)
        run_attempt_value = int(run_attempt)
    except ValueError as error:
        raise CandidateError("protected workflow run identity must be numeric") from error
    protection, required_reviewers = protected_environment_evidence(client)
    approval = protected_run_approval_evidence(
        client,
        actor=actor,
        run_id=run_id_value,
        run_attempt=run_attempt_value,
        workflow_commit=workflow_commit,
        environment_protection=protection,
        required_reviewers=required_reviewers,
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


def validate_supersession_handoff(
    record_path: Path,
    successor_plan_path: Path,
    destination: Path,
    *,
    expected_failed_plan_tag: str,
    expected_conflict_components: str | list[str],
) -> dict[str, Any]:
    record = load_supersession_file(record_path)
    successor = load_plan(successor_plan_path)
    failed = record.get("failed_plan")
    if not isinstance(failed, dict) or failed.get("tag") != expected_failed_plan_tag:
        raise CandidateError("release plan failure record does not match the trusted failed plan dispatch input")
    expected_components = (
        parse_conflict_components(expected_conflict_components)
        if isinstance(expected_conflict_components, str)
        else conflict_component_names(expected_conflict_components)
    )
    if conflict_component_names(record.get("conflicts")) != expected_components:
        raise CandidateError("release plan failure record does not match the trusted conflict component dispatch input")
    if record.get("successor_plan") != {
        "tag": f"{PLAN_TAG_PREFIX}{successor['plan']}",
        "sha256": manifest_digest(successor),
    }:
        raise CandidateError("release plan failure record does not bind the supplied successor document")
    destination.write_bytes(canonical_json(record))
    return record


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
    validate_recorded_plan(failed_plan)
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
    validate_recorded_plan(plan)
    return {
        "schema": LEGACY_CANDIDATE_SCHEMA if plan["schema"] == LEGACY_SCHEMA else CANDIDATE_SCHEMA,
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
    public_plan = read_public_record(
        client,
        plan_tag,
        plan_record_commit,
        "release-plan.json",
    )
    validate_recorded_plan(public_plan)
    if canonical_json(public_plan) != canonical_json(plan):
        raise CandidateError("observed release plan differs from immutable Git authority")
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
    candidate = candidate_manifest(plan)
    verification = load_verification(verification_path, candidate)
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

    verification = revalidate_verification(verification, candidate, client)
    completion_verification["public_verification"] = verification
    canonical_verification = canonical_json(completion_verification)

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
        "resume_action": OBSERVATION_RECOVERY_ACTION,
    }
    if preparation is not None:
        state["durable_evidence"]["release_preparation_sha256"] = manifest_digest(preparation)
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
    state.update(
        {
            "phase": "complete",
            "outcome": "verified",
            "components": verification["components"],
            "resume_action": "No recovery action is required",
        }
    )
    return verification, state


def failed_observation_state(
    plan: dict[str, Any], preparation: dict[str, Any] | None, observed_at: str
) -> dict[str, Any]:
    durable_evidence = {
        "release_plan_tag": f"{PLAN_TAG_PREFIX}{plan['plan']}",
        "component_actions": "repository Actions runs and public version tags",
    }
    if preparation is not None:
        durable_evidence["release_preparation_sha256"] = manifest_digest(preparation)
    return {
        "schema": "durable-workflow.release-state/v1",
        "plan": plan["plan"],
        "channel": plan["channel"],
        "plan_sha256": manifest_digest(plan),
        "observed_at": observed_at,
        "phase": "public-artifact-verification",
        "outcome": "failed",
        "reason": OBSERVATION_FAILURE_REASON,
        "durable_evidence": durable_evidence,
        "resume_action": OBSERVATION_RECOVERY_ACTION,
    }


def validate_observation_handoff(
    plan_path: Path,
    preparation_path: Path,
    candidate_path: Path,
    verification_path: Path,
    state_path: Path,
    output_directory: Path,
    *,
    authoritative_plan_path: Path,
    authoritative_preparation_path: Path,
    expected_plan_tag: str,
    expected_plan_sha256: str,
    expected_preparation_sha256: str,
    expected_verification_outcome: str,
    client: PublicClient,
) -> dict[str, str]:
    plan = load_plan(plan_path)
    plan_tag = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    if expected_plan_tag != plan_tag:
        raise CandidateError("observation handoff does not match the originally selected plan tag")
    if expected_plan_sha256 != manifest_digest(plan):
        raise CandidateError("observation handoff does not match the originally selected release plan")
    preparation = load_release_preparation(preparation_path, plan) if preparation_path.exists() else None
    authoritative_plan = load_plan(authoritative_plan_path)
    authoritative_preparation = (
        load_release_preparation(authoritative_preparation_path, authoritative_plan)
        if authoritative_preparation_path.exists()
        else None
    )
    if canonical_json(plan) != canonical_json(authoritative_plan):
        raise CandidateError("observation release plan differs from current public authority")
    preparation_sha256 = manifest_digest(preparation) if preparation is not None else "absent"
    authoritative_preparation_sha256 = (
        manifest_digest(authoritative_preparation) if authoritative_preparation is not None else "absent"
    )
    if (
        expected_preparation_sha256 != preparation_sha256
        or expected_preparation_sha256 != authoritative_preparation_sha256
    ):
        raise CandidateError("observation handoff does not match the originally selected preparation")
    candidate = load_manifest(candidate_path)
    if canonical_json(candidate) != canonical_json(candidate_manifest(plan)):
        raise CandidateError("observation candidate does not match its release plan")
    try:
        state_raw = state_path.read_bytes()
    except OSError as error:
        raise CandidateError(f"cannot read release observation state: {error}") from error
    if len(state_raw) > OBSERVATION_MAX_BYTES:
        raise CandidateError(f"release observation state exceeds the {OBSERVATION_MAX_BYTES // 1024} KiB limit")
    try:
        state = json.loads(state_raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise CandidateError(f"cannot read release observation state: {error}") from error
    validate_observation_bounds(state)
    if not isinstance(state, dict):
        raise CandidateError("release observation state must be a JSON object")
    observed_at = state.get("observed_at")
    if not isinstance(observed_at, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", observed_at
    ):
        raise CandidateError("release observation state has an invalid observed_at timestamp")
    try:
        dt.datetime.strptime(observed_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise CandidateError("release observation state has an invalid observed_at timestamp") from error
    if expected_verification_outcome not in {"success", "failure"}:
        raise CandidateError("trusted verification-step outcome must be success or failure")

    outcome = state.get("outcome")
    verification: dict[str, Any] | None = None
    durable_evidence = {
        "release_plan_tag": plan_tag,
        "component_actions": "repository Actions runs and public version tags",
    }
    if preparation is not None:
        durable_evidence["release_preparation_sha256"] = preparation_sha256
    if outcome == "verified":
        if expected_verification_outcome != "success":
            raise CandidateError("verified release observation contradicts the trusted verification-step outcome")
        submitted_verification = load_verification(verification_path, candidate)
        verification = revalidate_verification(submitted_verification, candidate, client)
        expected_state = {
            "schema": "durable-workflow.release-state/v1",
            "plan": plan["plan"],
            "channel": plan["channel"],
            "plan_sha256": manifest_digest(plan),
            "observed_at": observed_at,
            "phase": "complete",
            "outcome": "verified",
            "components": verification["components"],
            "durable_evidence": durable_evidence,
            "resume_action": "No recovery action is required",
        }
    elif outcome == "failed":
        if expected_verification_outcome != "failure":
            raise CandidateError("failed release observation contradicts the trusted verification-step outcome")
        expected_state = failed_observation_state(plan, preparation, observed_at)
        if verification_path.exists():
            raise CandidateError("failed release observation unexpectedly contains verification evidence")
    elif outcome == "superseded":
        if expected_verification_outcome != "failure":
            raise CandidateError("superseded release observation contradicts the trusted verification-step outcome")
        if verification_path.exists():
            raise CandidateError("superseded release observation unexpectedly contains verification evidence")
        expected_state = terminal_failure_state(plan, client)
        if expected_state is None:
            raise CandidateError("superseded release observation has no current public terminal authority")
        expected_state["observed_at"] = observed_at
    else:
        raise CandidateError("release observation state has an invalid outcome")
    if state != expected_state:
        raise CandidateError("release observation state differs from the writer's trusted reconstruction")

    trusted_state = expected_state
    trusted_state["observed_at"] = dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    output_directory.mkdir(parents=True, exist_ok=True)
    (output_directory / "release-plan.json").write_bytes(canonical_json(plan))
    if preparation is not None:
        (output_directory / "release-preparation.json").write_bytes(canonical_json(preparation))
    (output_directory / "candidate-verifier-input.json").write_bytes(canonical_json(candidate))
    (output_directory / "release-state.json").write_bytes(canonical_json(trusted_state))
    if verification is not None:
        (output_directory / "verification.json").write_bytes(canonical_json(verification))
    return {
        "channel": plan["channel"],
        "outcome": str(outcome),
        "plan": plan["plan"],
        "tag": plan_tag,
    }


def validate_observation_bounds(value: Any, context: str = "release observation state", depth: int = 0) -> None:
    if depth > OBSERVATION_MAX_DEPTH:
        raise CandidateError(f"{context} exceeds the maximum nesting depth")
    if isinstance(value, dict):
        if len(value) > OBSERVATION_MAX_ITEMS:
            raise CandidateError(f"{context} contains too many object fields")
        for key, nested in value.items():
            if not isinstance(key, str) or not key or len(key) > 128:
                raise CandidateError(f"{context} contains an invalid object key")
            validate_observation_bounds(nested, f"{context}.{key}", depth + 1)
    elif isinstance(value, list):
        if len(value) > OBSERVATION_MAX_ITEMS:
            raise CandidateError(f"{context} contains too many array items")
        for index, nested in enumerate(value):
            validate_observation_bounds(nested, f"{context}[{index}]", depth + 1)
    elif isinstance(value, str):
        if len(value) > OBSERVATION_MAX_TEXT or "\x00" in value:
            raise CandidateError(f"{context} contains oversized or invalid text")
    elif value is not None and type(value) not in {bool, int}:
        raise CandidateError(f"{context} contains an unsupported JSON value")
    elif type(value) is int and not -(2**63) <= value <= 2**63 - 1:
        raise CandidateError(f"{context} contains an oversized integer")


def discover_plan(client: PublicClient, requested_tag: str | None) -> tuple[str, dict[str, Any], dict[str, Any] | None]:
    if requested_tag:
        tag = requested_tag
        if not tag.startswith(PLAN_TAG_PREFIX):
            raise CandidateError(f"release plan tag must start with {PLAN_TAG_PREFIX}")
    else:

        class DiscoveryClient:
            def json(self, url: str, **options: Any) -> Any:
                try:
                    return client.json(url, **options)
                except CandidateError as error:
                    if "(404)" in str(error):
                        raise recovery_discovery.NotFound(str(error), "plan-discovery") from error
                    raise

            def bytes(self, url: str, **options: Any) -> bytes:
                try:
                    return client.bytes(url, **options)
                except CandidateError as error:
                    if "(404)" in str(error):
                        raise recovery_discovery.NotFound(str(error), "plan-discovery") from error
                    raise

        try:
            tag = recovery_discovery.select_implicit_plan_authority(DiscoveryClient())["tag"]
        except recovery_discovery.RecoveryError as error:
            raise CandidateError(str(error)) from error
    commit = resolve_tag(client, CONTROL_REPOSITORY, tag)
    if commit is None:
        raise CandidateError(f"release plan tag {tag} does not exist")
    plan = read_public_record(client, tag, commit, "release-plan.json")
    validate_recorded_plan(plan)
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
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/releases/tags/{urllib.parse.quote(tag, safe='')}"
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

    validate_supersession = subparsers.add_parser("validate-supersession-handoff")
    validate_supersession.add_argument("record", type=Path)
    validate_supersession.add_argument("successor_plan", type=Path)
    validate_supersession.add_argument("destination", type=Path)
    validate_supersession.add_argument("--expected-failed-plan-tag", required=True)
    validate_supersession.add_argument("--expected-conflict-components", required=True)

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

    validate_observation = subparsers.add_parser("validate-observation-handoff")
    validate_observation.add_argument("plan", type=Path)
    validate_observation.add_argument("preparation", type=Path)
    validate_observation.add_argument("candidate", type=Path)
    validate_observation.add_argument("verification", type=Path)
    validate_observation.add_argument("state", type=Path)
    validate_observation.add_argument("output_directory", type=Path)
    validate_observation.add_argument("--authoritative-plan", required=True, type=Path)
    validate_observation.add_argument("--authoritative-preparation", required=True, type=Path)
    validate_observation.add_argument("--expected-plan-tag", required=True)
    validate_observation.add_argument("--expected-plan-sha256", required=True)
    validate_observation.add_argument("--expected-preparation-sha256", required=True)
    validate_observation.add_argument("--expected-verification-outcome", required=True)
    validate_observation.add_argument("--github-output", type=Path)

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
            plan = load_plan(args.source, require_current=True)
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
        elif args.command == "validate-supersession-handoff":
            validate_supersession_handoff(
                args.record,
                args.successor_plan,
                args.destination,
                expected_failed_plan_tag=args.expected_failed_plan_tag,
                expected_conflict_components=args.expected_conflict_components,
            )
        elif args.command == "discover":
            tag, plan, preparation = discover_plan(PublicClient(token), args.tag)
            args.destination.write_bytes(canonical_json(plan))
            if preparation is not None:
                args.preparation.write_bytes(canonical_json(preparation))
            values = {
                "tag": tag,
                "plan": plan["plan"],
                "channel": plan["channel"],
                "plan_sha256": manifest_digest(plan),
                "preparation_sha256": manifest_digest(preparation) if preparation is not None else "absent",
            }
            write_github_output(args.github_output, values)
            print(json.dumps(values, sort_keys=True))
        elif args.command == "observe":
            plan = load_plan(args.plan)
            preparation = load_release_preparation(args.preparation, plan) if args.preparation.exists() else None
            candidate = candidate_manifest(plan)
            args.candidate.write_bytes(canonical_json(candidate))
            client = PublicClient(token)
            terminal_state = terminal_failure_state(plan, client)
            if terminal_state is not None:
                args.state.write_bytes(canonical_json(terminal_state))
                raise CandidateError(terminal_state["reason"])
            try:
                verification, state = observe_plan(plan, preparation, client)
            except CandidateError:
                failed_state = failed_observation_state(
                    plan,
                    preparation,
                    dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                )
                args.state.write_bytes(canonical_json(failed_state))
                raise
            args.verification.write_bytes(canonical_json(verification))
            args.state.write_bytes(canonical_json(state))
        elif args.command == "validate-observation-handoff":
            result = validate_observation_handoff(
                args.plan,
                args.preparation,
                args.candidate,
                args.verification,
                args.state,
                args.output_directory,
                authoritative_plan_path=args.authoritative_plan,
                authoritative_preparation_path=args.authoritative_preparation,
                expected_plan_tag=args.expected_plan_tag,
                expected_plan_sha256=args.expected_plan_sha256,
                expected_preparation_sha256=args.expected_preparation_sha256,
                expected_verification_outcome=args.expected_verification_outcome,
                client=PublicClient(token),
            )
            write_github_output(args.github_output, result)
            print(json.dumps(result, sort_keys=True))
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
