#!/usr/bin/env python3
"""Validate and operate the GitHub-authoritative public product backlog."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Collection, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

# GitHub Actions invokes this file directly from the repository root. In that
# mode Python adds scripts/, rather than the repository root, to sys.path.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts import cross_repository_lifecycle
from scripts.beta_candidate import COMPONENTS

POLICY_SCHEMA = "durable-workflow.github-issue-authority/v1"
BACKLOG_SCHEMA = "durable-workflow.github-beta-backlog/v1"
INTAKE_SCHEMA = "durable-workflow.github-issue-intake/v11"
LEGACY_TARGET_SCHEMA = "durable-workflow.legacy-cross-repository-targets/v5"
MARKER_PATTERN = re.compile(r"<!-- beta-work-id: ([a-z0-9][a-z0-9-]{2,79}) -->")
WORK_MARKER_PATTERN = re.compile(r"<!-- durable-workflow-work-id: ([a-z0-9][a-z0-9-]{2,79}) -->")
CONSOLIDATED_FINDING_PATTERN = re.compile(
    r"<!-- durable-workflow-consolidated-finding: ([a-z0-9][a-z0-9-]{2,79}) -->"
)
LEGACY_TARGET_HEADING = "### Affected public repositories"
UNBLOCK_CONTEXT_START = "<!-- beta-unblock-condition:start -->"
UNBLOCK_CONTEXT_END = "<!-- beta-unblock-condition:end -->"
UNBLOCK_CONTEXT_MARKERS = (UNBLOCK_CONTEXT_START, UNBLOCK_CONTEXT_END)
NON_PUBLIC_CONTEXT_PATTERNS = (
    re.compile(r"(?<![:/A-Za-z0-9_.-])/(?!/)[^\s)>\]]+"),
    re.compile(r"\b(?:localhost|127\.0\.0\.1)(?::[0-9]+)?\b", re.I),
)
SUPERSESSION_EVIDENCE_MARKER = "<!-- durable-workflow-prerelease-supersession -->"
FROZEN_LIFECYCLE_EVIDENCE_MARKER = "<!-- durable-workflow-frozen-lifecycle:v1 -->"
PUBLIC_LIFECYCLE_MARKER = "<!-- durable-workflow-public-lifecycle:v1 -->"
PUBLIC_RETIREMENT_RECORD_MARKER = "<!-- durable-workflow-public-lifecycle-state:superseded;condition:none -->"
PUBLIC_LIFECYCLE_PROJECTION_SCHEMA = "durable-workflow.public-lifecycle-projection/v1"
SUPERSESSION_ACTIVATION_CONTEXT_PREFIX = "issue-authority/prerelease-supersession"
SUPERSESSION_ACTIVATION_DESCRIPTION_PREFIX = "sha256:"
GITHUB_ACTIONS_BOT_ID = 41_898_282
GITHUB_ACTIONS_BOT_LOGIN = "github-actions[bot]"
SUPERSEDED_STATUS_LABEL = "status:superseded"
STATUS_LABELS = {
    "status:triage",
    "status:ready",
    "status:in-progress",
    "status:blocked",
    "status:done",
    SUPERSEDED_STATUS_LABEL,
}
OPEN_STATUS_LABELS = STATUS_LABELS - {"status:done", SUPERSEDED_STATUS_LABEL}
COMPLETION_REQUIRED_LABEL = "completion:evidence-required"
COMPLETION_VERIFIED_LABEL = "completion:evidence-verified"
COMPLETION_LABELS = {COMPLETION_REQUIRED_LABEL, COMPLETION_VERIFIED_LABEL}
KIND_LABELS = {"kind:defect", "kind:feature", "kind:release-blocker", "kind:cross-repository"}
PUBLIC_EXECUTION_STATES = {
    "blocked",
    "built",
    "claimed",
    "completed",
    "failed",
    "integrated",
    "integrating",
    "pending",
    "superseded",
}
PUBLIC_CONDITIONS = {
    "dependency-pending": "A required public dependency or decision is still pending.",
    "qualification-failed": "Required public qualification has not completed successfully.",
    "release-evidence-pending": "Changes have landed; release or completion evidence is still pending.",
}
PRIORITY_LABELS = {"priority:P0", "priority:P1", "priority:P2", "priority:P3", "priority:untriaged"}
CLASSIFICATION_LABELS = {"beta:blocker", "beta:compatible", "post-2.0"}
OWNER_LABELS = {
    ".github": "repo:github-control-plane",
    "workflow": "repo:workflow",
    "waterline": "repo:waterline",
    "server": "repo:server",
    "cli": "repo:cli",
    "ai": "repo:ai",
    "sample-app": "repo:sample-app",
    "sdk-php": "repo:sdk-php",
    "sdk-python": "repo:sdk-python",
    "sdk-rust": "repo:sdk-rust",
    "durable-workflow.github.io": "repo:documentation",
}
GITHUB_API_ATTEMPTS = 4
GITHUB_API_RETRY_SECONDS = 2.0
PRODUCT_TRAIN_IDENTIFIER_PATTERN = re.compile(
    r"^(?P<base>[0-9]+\.[0-9]+\.[0-9]+)-(?P<channel>alpha|beta|rc)\.(?P<number>[0-9]+)$"
)

ISSUE_INTAKE_QUERY = """
query IssueIntake($owner: String!, $repository: String!, $cursor: String) {
  repository(owner: $owner, name: $repository) {
    issues(
      first: 100
      after: $cursor
      orderBy: {field: CREATED_AT, direction: ASC}
      states: [OPEN, CLOSED]
    ) {
      nodes {
        number
        createdAt
        closedAt
        lastEditedAt
        updatedAt
        url
        state
        stateReason
        author { login }
        milestone { title }
        labels(first: 100) {
          nodes { name }
          pageInfo { hasNextPage }
        }
        timelineItems(
          last: 100
          itemTypes: [CLOSED_EVENT, LABELED_EVENT, RENAMED_TITLE_EVENT, REOPENED_EVENT, UNLABELED_EVENT]
        ) {
          nodes {
            __typename
            ... on ClosedEvent { createdAt }
            ... on LabeledEvent {
              createdAt
              actor { login }
              label { name }
            }
            ... on UnlabeledEvent {
              createdAt
              actor { login }
              label { name }
            }
            ... on RenamedTitleEvent {
              createdAt
            }
            ... on ReopenedEvent { createdAt }
          }
        }
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
}
"""

ISSUE_REVISION_QUERY = """
query IssueRevision($owner: String!, $repository: String!, $number: Int!) {
  repository(owner: $owner, name: $repository) {
    issue(number: $number) {
      number
      title
      body
      createdAt
      closedAt
      lastEditedAt
      updatedAt
      url
      state
      stateReason
      author { login }
      milestone { title }
      labels(first: 100) {
        nodes { name }
        pageInfo { hasNextPage }
      }
      timelineItems(
        last: 100
        itemTypes: [CLOSED_EVENT, LABELED_EVENT, RENAMED_TITLE_EVENT, REOPENED_EVENT, UNLABELED_EVENT]
      ) {
        nodes {
          __typename
          ... on ClosedEvent { createdAt }
          ... on LabeledEvent {
            createdAt
            actor { login }
            label { name }
          }
          ... on UnlabeledEvent {
            createdAt
            actor { login }
            label { name }
          }
          ... on RenamedTitleEvent {
            createdAt
          }
          ... on ReopenedEvent { createdAt }
        }
      }
    }
  }
}
"""

PULL_REQUEST_METADATA_QUERY = """
query PullRequestMetadata($owner: String!, $repository: String!, $cursor: String) {
  repository(owner: $owner, name: $repository) {
    pullRequests(
      first: 100
      after: $cursor
      orderBy: {field: CREATED_AT, direction: ASC}
      states: [OPEN, CLOSED, MERGED]
    ) {
      nodes {
        number
        createdAt
        closedAt
        mergedAt
        updatedAt
        url
        state
      }
      pageInfo {
        hasNextPage
        endCursor
      }
    }
  }
}
"""

CLOSING_REFERENCE_QUERY = """
query ClosingReferences($owner: String!, $repository: String!, $number: Int!, $cursor: String) {
  repository(owner: $owner, name: $repository) {
    issue(number: $number) {
      timelineItems(first: 100, after: $cursor, itemTypes: [CROSS_REFERENCED_EVENT]) {
        nodes {
          __typename
          ... on CrossReferencedEvent {
            actor { login }
            id
            referencedAt
            source {
              __typename
              ... on PullRequest {
                number
                repository { nameWithOwner }
                url
              }
            }
            willCloseTarget
          }
        }
        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }
  }
}
"""


class AuthorityError(RuntimeError):
    """The public issue-authority contract cannot be satisfied."""


class LifecycleAuditError(AuthorityError):
    """Lifecycle reconciliation applied safe changes but retained isolated failures."""

    def __init__(self, message: str, evidence: Mapping[str, Any]) -> None:
        super().__init__(message)
        self.evidence = dict(evidence)


def _load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AuthorityError(f"cannot read {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise AuthorityError(f"{label} {path} must contain a JSON object")
    return value


def _validate_schema(instance: dict[str, Any], schema: dict[str, Any], label: str) -> None:
    validator = Draft202012Validator(schema, format_checker=FormatChecker())
    errors = sorted(validator.iter_errors(instance), key=lambda error: list(error.absolute_path))
    if not errors:
        return
    error = errors[0]
    location = ".".join(str(part) for part in error.absolute_path) or "<root>"
    raise AuthorityError(f"{label} schema validation failed at {location}: {error.message}")


def _public_safe(values: Sequence[str]) -> None:
    for value in values:
        if any(marker in value for marker in UNBLOCK_CONTEXT_MARKERS):
            raise AuthorityError("selective backlog contains a reserved unblock condition marker")
        for pattern in NON_PUBLIC_CONTEXT_PATTERNS:
            match = pattern.search(value)
            if match:
                raise AuthorityError(f"selective backlog contains non-public context matching {match.group(0)!r}")


def load_public_lifecycle_projection(
    path: Path,
    policy: Mapping[str, Any],
    actor: str | None,
) -> tuple[dict[tuple[str, int], dict[str, Any]], list[str]]:
    """Validate an authenticated, public-safe execution-state projection issue by issue."""

    projection_actors = {str(value).casefold() for value in policy["lifecycle"]["projection_actors"]}
    if not isinstance(actor, str) or actor.casefold() not in projection_actors:
        raise AuthorityError("public lifecycle projection actor is not allowlisted")
    payload = _load_json(path, "public lifecycle projection")
    if set(payload) != {"generated_at", "issues", "schema"}:
        raise AuthorityError("public lifecycle projection envelope has unexpected fields")
    if payload.get("schema") != PUBLIC_LIFECYCLE_PROJECTION_SCHEMA:
        raise AuthorityError("public lifecycle projection uses an unsupported schema")
    generated_at = _parse_timestamp(payload.get("generated_at"), "projection generation timestamp")
    raw_issues = payload.get("issues")
    if not isinstance(raw_issues, list) or len(raw_issues) > 1000:
        raise AuthorityError("public lifecycle projection has an invalid issue bound")

    admitted_repositories = set(policy["repositories"])
    projections: dict[tuple[str, int], dict[str, Any]] = {}
    failures: list[str] = []
    quarantined: set[tuple[str, int]] = set()
    for index, raw in enumerate(raw_issues):
        if not isinstance(raw, Mapping):
            failures.append(f"projection entry {index} is not an object")
            continue
        repository = raw.get("repository")
        number = raw.get("number")
        identity = (
            (repository, number)
            if isinstance(repository, str) and type(number) is int and number > 0
            else None
        )
        location = (
            f"{repository}#{number}"
            if identity is not None and repository in admitted_repositories
            else f"projection entry {index}"
        )
        allowed_fields = {
            "completion_evidence",
            "implementation_source",
            "number",
            "public_condition",
            "repository",
            "state",
            "transition_at",
            "verified_release",
        }
        try:
            if identity is None or repository not in admitted_repositories:
                raise AuthorityError("has an invalid public issue identity")
            if set(raw) - allowed_fields:
                raise AuthorityError("has unexpected fields")
            state = raw.get("state")
            if state not in PUBLIC_EXECUTION_STATES:
                raise AuthorityError("has an unsupported execution state")
            transition_at = _parse_timestamp(raw.get("transition_at"), "projection transition timestamp")
            if transition_at > generated_at:
                raise AuthorityError("has a transition after the projection generation time")
            condition = raw.get("public_condition")
            if state in {"blocked", "failed"}:
                if condition not in {"dependency-pending", "qualification-failed"}:
                    raise AuthorityError("must select a bounded public blocker condition")
            elif state == "integrated":
                if condition not in {None, "release-evidence-pending"}:
                    raise AuthorityError("has an incompatible public condition")
                condition = "release-evidence-pending"
            elif condition is not None:
                raise AuthorityError("has a public condition outside a conditional state")
            completion_evidence = raw.get("completion_evidence")
            if state == "completed":
                if completion_evidence != "verified":
                    raise AuthorityError("cannot complete without verified public evidence")
            elif completion_evidence is not None:
                raise AuthorityError("has completion evidence outside the completed state")
            implementation_source = raw.get("implementation_source")
            verified_release = raw.get("verified_release")
            if implementation_source is not None or verified_release is not None:
                if state != "completed" or completion_evidence != "verified":
                    raise AuthorityError("has release completion evidence outside the completed state")
                if (
                    not isinstance(implementation_source, str)
                    or re.fullmatch(r"[0-9a-f]{40}", implementation_source) is None
                ):
                    raise AuthorityError("has an invalid implementation source")
                if not isinstance(verified_release, Mapping) or set(verified_release) != {
                    "repository",
                    "source_shas",
                    "version",
                }:
                    raise AuthorityError("has malformed verified release evidence")
                release_repository = verified_release.get("repository")
                release_version = verified_release.get("version")
                source_shas = verified_release.get("source_shas")
                if (
                    not isinstance(release_repository, str)
                    or release_repository not in admitted_repositories
                    or not isinstance(release_version, str)
                    or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,99}", release_version) is None
                    or not isinstance(source_shas, list)
                    or not 1 <= len(source_shas) <= 1000
                    or any(
                        not isinstance(source_sha, str)
                        or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None
                        for source_sha in source_shas
                    )
                    or len(source_shas) != len(set(source_shas))
                ):
                    raise AuthorityError("has invalid verified release identity")
                if implementation_source not in source_shas:
                    raise AuthorityError("verified release does not contain the bound implementation source")
            if identity in projections or identity in quarantined:
                projections.pop(identity, None)
                quarantined.add(identity)
                raise AuthorityError("is duplicated and was quarantined")
            projections[identity] = {
                "completion_evidence": completion_evidence,
                "implementation_source": implementation_source,
                "public_condition": condition,
                "state": state,
                "transition_at": transition_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
                "verified_release": dict(verified_release) if verified_release is not None else None,
            }
        except AuthorityError as error:
            failures.append(f"{location} {error}")
    return projections, failures


def validate_contract(
    policy: dict[str, Any],
    backlog: dict[str, Any],
    policy_schema: dict[str, Any],
    backlog_schema: dict[str, Any],
) -> None:
    _validate_schema(policy, policy_schema, "issue-authority policy")
    _validate_schema(backlog, backlog_schema, "selective backlog")
    if policy.get("schema") != POLICY_SCHEMA or backlog.get("schema") != BACKLOG_SCHEMA:
        raise AuthorityError("issue-authority documents use an unsupported schema")
    if policy.get("state_direction") != "github-to-mirrors":
        raise AuthorityError("issue state must flow from GitHub to consumers only")

    intake = policy["intake"]
    trusted_actors = intake["trusted_actors"]
    if trusted_actors != list(dict.fromkeys(trusted_actors)) or set(trusted_actors) != {
        "durable-workflow-ops",
        "rmcdaniel",
    }:
        raise AuthorityError("issue-intake trusted actors must be the reviewed maintainer identities")

    repositories = policy["repositories"]
    if repositories != list(dict.fromkeys(repositories)) or set(repositories) != set(OWNER_LABELS):
        raise AuthorityError("issue-authority repository inventory is incomplete or duplicated")
    if "cloud" in repositories:
        raise AuthorityError("private Cloud implementation work cannot enter the public issue-authority inventory")

    labels = policy["labels"]
    label_names = [label["name"] for label in labels]
    if len(label_names) != len(set(label_names)):
        raise AuthorityError("issue-authority labels must be unique")
    required_labels = {
        "authority:github",
        "authority:conflict",
        *STATUS_LABELS,
        *COMPLETION_LABELS,
        *KIND_LABELS,
        *PRIORITY_LABELS,
        *CLASSIFICATION_LABELS,
        *OWNER_LABELS.values(),
        intake["approval_label"],
    }
    missing_labels = required_labels - set(label_names)
    if missing_labels:
        raise AuthorityError(f"issue-authority policy is missing labels {sorted(missing_labels)}")

    milestones = policy["milestones"]
    milestone_titles = [milestone["title"] for milestone in milestones]
    if len(milestone_titles) != len(set(milestone_titles)):
        raise AuthorityError("issue-authority milestones must be unique")
    for milestone in milestones:
        unknown = set(milestone["repositories"]) - set(repositories)
        if unknown:
            raise AuthorityError(f"milestone {milestone['title']!r} names unknown repositories {sorted(unknown)}")
    if backlog["milestone"] not in milestone_titles:
        raise AuthorityError("selective backlog milestone is not declared by issue-authority policy")

    retired_identities: set[tuple[str, int]] = set()
    for supersession in policy["prerelease_supersessions"]:
        retired = supersession["retired"]
        successor = supersession["successor"]
        retired_identity = (retired["repository"], retired["number"])
        if retired["repository"] not in repositories or successor["repository"] not in repositories:
            raise AuthorityError("prerelease supersession names an unknown public repository")
        if retired_identity in retired_identities:
            raise AuthorityError(
                f"prerelease supersession repeats retired issue {retired['repository']}#{retired['number']}"
            )
        retired_identities.add(retired_identity)
        successor_number = successor.get("number")
        if type(successor_number) is int:
            successor_identity = (successor["repository"], successor_number)
            if retired_identity == successor_identity:
                raise AuthorityError("prerelease supersession must name a distinct successor")
        elif (
            successor["repository"] != policy["authority_repository"]
            or successor["commit"] != supersession["activation_commit"]
        ):
            raise AuthorityError(
                "immutable prerelease successor must be an exact authority-repository activation commit"
            )

    successor_by_retired = {
        (record["retired"]["repository"], record["retired"]["number"]): record["successor"]
        for record in policy["prerelease_supersessions"]
    }
    for start in retired_identities:
        seen: set[tuple[str, int]] = set()
        current = start
        while current in successor_by_retired:
            if current in seen:
                raise AuthorityError("prerelease supersession issue chain contains a cycle")
            seen.add(current)
            successor = successor_by_retired[current]
            successor_number = successor.get("number")
            if type(successor_number) is not int:
                break
            current = (successor["repository"], successor_number)

    items = backlog["items"]
    item_ids = [item["id"] for item in items]
    if len(item_ids) != len(set(item_ids)):
        raise AuthorityError("selective backlog item ids must be unique")
    known_ids: set[str] = set()
    for item in items:
        if item["repository"] not in repositories:
            raise AuthorityError(f"backlog item {item['id']} names an unknown public repository")
        unblock_condition = item.get("unblock_condition")
        if (
            item["status"] == "blocked"
            and not item["depends_on"]
            and (not unblock_condition or not unblock_condition.strip())
        ):
            raise AuthorityError(
                f"blocked backlog item {item['id']} must name a dependency or explicit unblock condition"
            )
        future_dependencies = set(item["depends_on"]) - known_ids
        if future_dependencies:
            raise AuthorityError(
                f"backlog item {item['id']} dependencies must precede it: {sorted(future_dependencies)}"
            )
        known_ids.add(item["id"])
        if MARKER_PATTERN.search(item["body"]):
            raise AuthorityError(f"backlog item {item['id']} body must not supply its own authority marker")

    review = backlog["review"]
    review_ids = [record["review_id"] for record in review]
    if len(review_ids) != len(set(review_ids)):
        raise AuthorityError("selective backlog review ids must be unique")
    migrated = {record["review_id"] for record in review if record["disposition"] == "migrate"}
    if migrated != set(item_ids):
        raise AuthorityError(
            f"reviewed migration set differs from backlog items; reviewed={sorted(migrated)}, items={sorted(item_ids)}"
        )

    public_values = [backlog["milestone"]]
    for record in review:
        public_values.extend((record["title"], record["reason"]))
    for item in items:
        public_values.extend((item["title"], item["body"]))
        if unblock_condition := item.get("unblock_condition"):
            public_values.append(unblock_condition)
    public_values.extend(supersession["reason"] for supersession in policy["prerelease_supersessions"])
    _public_safe(public_values)


def load_contract(
    policy_path: Path,
    backlog_path: Path,
    policy_schema_path: Path | None = None,
    backlog_schema_path: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    policy = _load_json(policy_path, "issue-authority policy")
    backlog = _load_json(backlog_path, "selective backlog")
    policy_schema = _load_json(
        policy_schema_path or policy_path.with_name("policy-schema.json"),
        "issue-authority policy schema",
    )
    backlog_schema = _load_json(
        backlog_schema_path or backlog_path.with_name("backlog-schema.json"),
        "selective backlog schema",
    )
    validate_contract(policy, backlog, policy_schema, backlog_schema)
    return policy, backlog


def load_legacy_cross_repository_targets(
    path: Path,
    target_qualification: Mapping[str, Any],
    schema_path: Path | None = None,
) -> dict[str, Any]:
    migration = _load_json(path, "legacy cross-repository target migration")
    schema = _load_json(
        schema_path or path.with_name("legacy-cross-repository-targets-schema.json"),
        "legacy cross-repository target migration schema",
    )
    _validate_schema(migration, schema, "legacy cross-repository target migration")
    if migration.get("schema") != LEGACY_TARGET_SCHEMA:
        raise AuthorityError("legacy cross-repository target migration uses an unsupported schema")
    _parse_timestamp(migration.get("created_before"), "legacy target migration cutoff")

    target_map = cross_repository_lifecycle.qualification_targets(target_qualification)
    landing_map: dict[str, Mapping[str, Any]] = {}
    for landing in migration["protected_branch_landings"]:
        repository = landing["repository"]
        target = target_map.get(repository)
        if target is None or target["branch"] != landing["branch"]:
            raise AuthorityError(
                f"legacy protected-branch landing names unqualified target {repository}@{landing['branch']}"
            )
        if repository in landing_map:
            raise AuthorityError(f"legacy protected-branch landing repeats repository {repository}")
        landing_map[repository] = landing

    identities: set[tuple[str, str]] = set()
    for authority in migration["authorities"]:
        identity = (authority["marker"], authority["id"])
        if identity in identities:
            raise AuthorityError(f"legacy cross-repository target migration repeats {authority['id']}")
        identities.add(identity)
        try:
            cross_repository_lifecycle.declared_targets(
                f"{cross_repository_lifecycle.TARGET_HEADING}\n\n" + "\n".join(authority["targets"]),
                target_map,
                organization="durable-workflow",
                required=True,
            )
        except cross_repository_lifecycle.LifecycleError as error:
            raise AuthorityError(str(error)) from error

    immutable_identities: set[tuple[str, int]] = set()
    for binding in migration["immutable_issue_targets"]:
        repository = binding["repository"]
        identity = (repository, binding["number"])
        if repository not in target_map:
            raise AuthorityError(
                f"immutable issue target binding names unqualified source repository {repository}"
            )
        if identity in immutable_identities:
            raise AuthorityError(
                f"immutable issue target binding repeats {repository}#{binding['number']}"
            )
        immutable_identities.add(identity)
        try:
            bound_targets = cross_repository_lifecycle.declared_targets(
                f"{cross_repository_lifecycle.TARGET_HEADING}\n\n" + "\n".join(binding["targets"]),
                target_map,
                organization="durable-workflow",
                required=True,
            )
        except cross_repository_lifecycle.LifecycleError as error:
            raise AuthorityError(str(error)) from error
        if repository not in {target["repository"] for target in bound_targets}:
            raise AuthorityError(
                f"immutable issue target binding for {repository}#{binding['number']} omits its source repository"
            )

    completed_identities: set[tuple[str, int]] = set()
    for completion in migration["historical_completions"]:
        if completion["repository"] not in target_map:
            raise AuthorityError(
                f"legacy historical completion names unqualified source repository {completion['repository']}"
            )
        identity = (completion["repository"], completion["number"])
        if identity in completed_identities:
            raise AuthorityError(
                f"legacy historical completion repeats {completion['repository']}#{completion['number']}"
            )
        completed_identities.add(identity)
        try:
            completed_targets = cross_repository_lifecycle.declared_targets(
                f"{cross_repository_lifecycle.TARGET_HEADING}\n\n" + "\n".join(completion["targets"]),
                target_map,
                organization="durable-workflow",
                required=True,
            )
        except cross_repository_lifecycle.LifecycleError as error:
            raise AuthorityError(str(error)) from error
        missing_landings = sorted(
            target["repository"] for target in completed_targets if target["repository"] not in landing_map
        )
        if missing_landings:
            raise AuthorityError(
                f"legacy historical completion has no protected-branch landings for {missing_landings}"
            )

    frozen_identities: set[tuple[str, int]] = set()
    frozen_snapshots: set[str] = set()
    for frozen in migration["frozen_lifecycle_migrations"]:
        repository = frozen["repository"]
        identity = (repository, frozen["number"])
        if repository not in target_map:
            raise AuthorityError(
                f"frozen lifecycle migration names unqualified source repository {repository}"
            )
        if identity in frozen_identities or identity in completed_identities:
            raise AuthorityError(
                f"frozen lifecycle migration repeats {repository}#{frozen['number']}"
            )
        frozen_identities.add(identity)
        snapshot = frozen["authority_snapshot_sha256"]
        if snapshot in frozen_snapshots:
            raise AuthorityError("frozen lifecycle migrations repeat an approved authority snapshot")
        frozen_snapshots.add(snapshot)
        _parse_timestamp(frozen["approval_at"], "frozen lifecycle approval timestamp")
        try:
            declared = cross_repository_lifecycle.declared_targets(
                f"{cross_repository_lifecycle.TARGET_HEADING}\n\n"
                + "\n".join(frozen["declared_targets"]),
                target_map,
                organization="durable-workflow",
                required=True,
            )
        except cross_repository_lifecycle.LifecycleError as error:
            raise AuthorityError(str(error)) from error
        declared_contract = {
            (str(target["repository"]), str(target["branch"])) for target in declared
        }
        if not any(target["repository"] == repository for target in declared):
            raise AuthorityError(
                f"frozen lifecycle migration for {repository}#{frozen['number']} omits its source repository"
            )
        if frozen["outcome"] == "missing-evidence":
            if (
                frozen["completion_source"] is not None
                or frozen["landings"]
                or not isinstance(frozen["missing_evidence"], str)
                or not frozen["missing_evidence"].strip()
            ):
                raise AuthorityError(
                    f"frozen missing-evidence migration for {repository}#{frozen['number']} "
                    "must contain only its bounded reason"
                )
            continue
        if frozen["missing_evidence"] is not None or not frozen["landings"]:
            raise AuthorityError(
                f"frozen completed migration for {repository}#{frozen['number']} has no exact landings"
            )
        landing_contract: set[tuple[str, str]] = set()
        source_commits: list[str] = []
        for landing in frozen["landings"]:
            landing_identity = (landing["repository"], landing["branch"])
            if landing_identity not in declared_contract or landing_identity in landing_contract:
                raise AuthorityError(
                    f"frozen lifecycle migration for {repository}#{frozen['number']} "
                    "has duplicated or undeclared landing evidence"
                )
            landing_contract.add(landing_identity)
            if landing["repository"] == repository:
                source_commits.append(landing["commit"])
            qualification = landing["qualification"]
            checks = qualification["checks"]
            check_names = [check["name"] for check in checks]
            check_jobs = [check["job"] for check in checks]
            if (
                len(check_names) != len(set(check_names))
                or len(check_jobs) != len(set(check_jobs))
                or any(check["run"] != qualification["run"] for check in checks)
            ):
                raise AuthorityError(
                    f"frozen lifecycle migration for {repository}#{frozen['number']} "
                    "has ambiguous qualification check identity"
                )
        if landing_contract != declared_contract:
            raise AuthorityError(
                f"frozen lifecycle migration for {repository}#{frozen['number']} "
                "does not cover its exact declared target set"
            )
        if source_commits != [frozen["completion_source"]]:
            raise AuthorityError(
                f"frozen lifecycle migration for {repository}#{frozen['number']} "
                "does not bind its source completion commit"
            )
    return migration


def validate_backlog_cross_repository_targets(
    backlog: Mapping[str, Any],
    target_qualification: Mapping[str, Any],
    *,
    organization: str,
) -> None:
    target_map = cross_repository_lifecycle.qualification_targets(target_qualification)
    for item in backlog["items"]:
        selections = item.get("required_source_targets")
        if item["kind"] != "cross-repository":
            if selections is not None:
                raise AuthorityError(f"non-cross-repository backlog item {item['id']} declares multiple source targets")
            continue
        if not isinstance(selections, list):
            raise AuthorityError(f"cross-repository backlog item {item['id']} has no required source targets")
        try:
            cross_repository_lifecycle.declared_targets(
                f"{cross_repository_lifecycle.TARGET_HEADING}\n\n" + "\n".join(selections),
                target_map,
                organization=organization,
                required=True,
            )
        except cross_repository_lifecycle.LifecycleError as error:
            raise AuthorityError(f"cross-repository backlog item {item['id']}: {error}") from error


def _object_digest(value: Any) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def issue_revision_digest(title: str, body: str) -> str:
    """Bind the complete instruction-bearing issue revision to one stable digest."""

    return _object_digest({"body": body, "title": title})


def _parse_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise AuthorityError(f"GitHub issue intake has no valid {label}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AuthorityError(f"GitHub issue intake has invalid {label}") from error
    if parsed.tzinfo is None:
        raise AuthorityError(f"GitHub issue intake {label} must include a timezone")
    return parsed


def _intake_label_names(issue: Mapping[str, Any]) -> set[str]:
    names: set[str] = set()
    labels = issue.get("labels")
    if not isinstance(labels, Sequence) or isinstance(labels, str | bytes):
        return names
    for label in labels:
        if isinstance(label, str):
            names.add(label)
        elif isinstance(label, Mapping) and isinstance(label.get("name"), str):
            names.add(str(label["name"]))
    return names


def assess_issue_intake(
    issue: Mapping[str, Any],
    timeline: Sequence[Mapping[str, Any]],
    *,
    approval_label: str,
    trusted_actors: Sequence[str],
    bind_revision: bool = True,
) -> dict[str, Any]:
    """Reconstruct whether the current title/body revision has trusted authority."""

    number = issue.get("number")
    author = issue.get("author")
    author_login = author.get("login") if isinstance(author, Mapping) else None
    if not isinstance(number, int):
        raise AuthorityError("GitHub issue intake returned an issue without a numeric identity")

    def approved_record(actor: str, approved_at: Any, mode: str) -> dict[str, Any]:
        record = {
            "approved": True,
            "approval_actor": actor,
            "approval_at": approved_at,
            "approval_mode": mode,
            "reason": mode,
        }
        if bind_revision:
            title = issue.get("title")
            body = issue.get("body")
            if not isinstance(title, str) or not isinstance(body, str):
                raise AuthorityError(f"GitHub issue {number} has no complete title/body revision")
            record["revision"] = issue_revision_digest(title, body)
        return record

    trusted = {actor.casefold() for actor in trusted_actors}
    last_edited_value = issue.get("last_edited_at")
    edit_times: list[datetime] = []
    if last_edited_value is not None:
        edit_times.append(_parse_timestamp(last_edited_value, "last body edit timestamp"))
    edit_times.extend(
        _parse_timestamp(event.get("created_at"), "title edit timestamp")
        for event in timeline
        if event.get("event") == "renamed"
    )
    last_edit = max(edit_times) if edit_times else None
    if isinstance(author_login, str) and author_login.casefold() in trusted and last_edit is None:
        created_at = issue.get("created_at")
        _parse_timestamp(created_at, "creation timestamp")
        return approved_record(author_login, created_at, "trusted-creation")

    if approval_label not in _intake_label_names(issue):
        return {"approved": False, "reason": "approval-label-absent"}

    transitions: list[tuple[datetime, int, Mapping[str, Any]]] = []
    for index, event in enumerate(timeline):
        if event.get("label") != approval_label or event.get("event") not in {"labeled", "unlabeled"}:
            continue
        transitions.append((_parse_timestamp(event.get("created_at"), "label event timestamp"), index, event))
    if not transitions:
        return {"approved": False, "reason": "approval-event-absent"}

    approval_time, _index, latest = max(transitions, key=lambda record: (record[0], record[1]))
    if latest.get("event") != "labeled":
        return {"approved": False, "reason": "approval-label-removed"}
    actor = latest.get("actor")
    if not isinstance(actor, str) or actor.casefold() not in trusted:
        return {"approved": False, "reason": "approval-actor-untrusted"}
    if last_edit is not None and approval_time <= last_edit:
        return {"approved": False, "reason": "approval-predates-revision"}

    return approved_record(actor, latest["created_at"], "trusted-label")


def _normalize_intake_issue(node: Mapping[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    labels_connection = node.get("labels")
    if not isinstance(labels_connection, Mapping):
        raise AuthorityError("GitHub issue intake returned malformed labels")
    page_info = labels_connection.get("pageInfo")
    if isinstance(page_info, Mapping) and page_info.get("hasNextPage"):
        raise AuthorityError(f"GitHub issue {node.get('number')} exceeds the intake label bound")
    labels = labels_connection.get("nodes")
    if not isinstance(labels, list):
        raise AuthorityError("GitHub issue intake returned malformed label nodes")

    timeline_connection = node.get("timelineItems")
    timeline_nodes = timeline_connection.get("nodes") if isinstance(timeline_connection, Mapping) else None
    if not isinstance(timeline_nodes, list):
        raise AuthorityError("GitHub issue intake returned malformed approval history")
    timeline: list[dict[str, Any]] = []
    for event in timeline_nodes:
        if not isinstance(event, Mapping):
            continue
        event_type = {
            "ClosedEvent": "closed",
            "LabeledEvent": "labeled",
            "RenamedTitleEvent": "renamed",
            "ReopenedEvent": "reopened",
            "UnlabeledEvent": "unlabeled",
        }.get(event.get("__typename"))
        if event_type in {"closed", "renamed", "reopened"}:
            timeline.append({"created_at": event.get("createdAt"), "event": event_type})
            continue
        label = event.get("label")
        actor = event.get("actor")
        if event_type is None or not isinstance(label, Mapping):
            continue
        timeline.append(
            {
                "actor": actor.get("login") if isinstance(actor, Mapping) else None,
                "created_at": event.get("createdAt"),
                "event": event_type,
                "label": label.get("name"),
            }
        )

    milestone = node.get("milestone")
    issue = {
        "author": node.get("author"),
        "body": node.get("body"),
        "closed_at": node.get("closedAt"),
        "created_at": node.get("createdAt"),
        "html_url": node.get("url"),
        "labels": [label for label in labels if isinstance(label, Mapping)],
        "last_edited_at": node.get("lastEditedAt"),
        "milestone": {"title": milestone.get("title")} if isinstance(milestone, Mapping) else None,
        "number": node.get("number"),
        "state": str(node.get("state", "")).lower(),
        "state_reason": (str(node["stateReason"]).lower() if isinstance(node.get("stateReason"), str) else None),
        "title": node.get("title"),
        "updated_at": node.get("updatedAt"),
    }
    return issue, timeline


class GitHubDiscovery:
    """Read-only GraphQL client that reconstructs issue revision authority."""

    def __init__(
        self,
        token: str,
        graphql_url: str = "https://api.github.com/graphql",
        *,
        api_url: str = "https://api.github.com",
    ) -> None:
        if not token:
            raise AuthorityError("GITHUB_TOKEN is required for read-only issue discovery")
        self.api_url = api_url.rstrip("/")
        self.graphql_url = graphql_url
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
            "User-Agent": "durable-workflow-issue-intake/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def graphql(self, query: str, variables: Mapping[str, Any]) -> dict[str, Any]:
        body = json.dumps({"query": query, "variables": variables}, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(self.graphql_url, data=body, headers=self.headers, method="POST")
        for attempt in range(1, GITHUB_API_ATTEMPTS + 1):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    payload = json.loads(response.read())
                if not isinstance(payload, dict) or payload.get("errors") or not isinstance(payload.get("data"), dict):
                    raise AuthorityError("GitHub GraphQL issue discovery returned errors")
                return payload["data"]
            except urllib.error.HTTPError as error:
                retryable = error.code == 429 or 500 <= error.code <= 599
                if not retryable or attempt == GITHUB_API_ATTEMPTS:
                    raise AuthorityError(f"GitHub GraphQL issue discovery returned {error.code}") from error
            except (urllib.error.URLError, ConnectionError, TimeoutError, json.JSONDecodeError) as error:
                if attempt == GITHUB_API_ATTEMPTS:
                    raise AuthorityError("GitHub GraphQL issue discovery failed after bounded retries") from error
            time.sleep(GITHUB_API_RETRY_SECONDS * (2 ** (attempt - 1)))
        raise AssertionError("GitHub GraphQL retry loop ended unexpectedly")

    def _rest(self, path: str) -> Any:
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            headers=self.headers,
            method="GET",
        )
        for attempt in range(1, GITHUB_API_ATTEMPTS + 1):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    response_body = response.read()
                return json.loads(response_body) if response_body else None
            except urllib.error.HTTPError as error:
                retryable = error.code == 429 or 500 <= error.code <= 599
                if not retryable or attempt == GITHUB_API_ATTEMPTS:
                    raise AuthorityError(f"GitHub REST issue discovery returned {error.code}") from error
            except (urllib.error.URLError, ConnectionError, TimeoutError, json.JSONDecodeError) as error:
                if attempt == GITHUB_API_ATTEMPTS:
                    raise AuthorityError("GitHub REST issue discovery failed after bounded retries") from error
            time.sleep(GITHUB_API_RETRY_SECONDS * (2 ** (attempt - 1)))
        raise AssertionError("GitHub REST issue discovery retry loop ended unexpectedly")

    def _bytes(self, path: str) -> bytes:
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            headers={**self.headers, "Accept": "application/vnd.github.raw+json"},
            method="GET",
        )
        for attempt in range(1, GITHUB_API_ATTEMPTS + 1):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    return response.read()
            except urllib.error.HTTPError as error:
                retryable = error.code == 429 or 500 <= error.code <= 599
                if not retryable or attempt == GITHUB_API_ATTEMPTS:
                    raise AuthorityError(f"GitHub REST content discovery returned {error.code}") from error
            except (urllib.error.URLError, ConnectionError, TimeoutError) as error:
                if attempt == GITHUB_API_ATTEMPTS:
                    raise AuthorityError("GitHub REST content discovery failed after bounded retries") from error
            time.sleep(GITHUB_API_RETRY_SECONDS * (2 ** (attempt - 1)))
        raise AssertionError("GitHub REST content discovery retry loop ended unexpectedly")

    def read_file(
        self,
        organization: str,
        repository: str,
        commit: str,
        path: str,
    ) -> bytes:
        encoded_path = urllib.parse.quote(path, safe="/")
        encoded_commit = urllib.parse.quote(commit, safe="")
        return self._bytes(f"/repos/{organization}/{repository}/contents/{encoded_path}?ref={encoded_commit}")

    def list_commit_statuses(
        self,
        organization: str,
        repository: str,
        commit: str,
    ) -> list[dict[str, Any]]:
        encoded_commit = urllib.parse.quote(commit, safe="")
        statuses: list[dict[str, Any]] = []
        for page in range(1, 11):
            payload = self._rest(
                f"/repos/{organization}/{repository}/commits/{encoded_commit}/statuses?per_page=100&page={page}"
            )
            if not isinstance(payload, list):
                raise AuthorityError("GitHub REST issue discovery returned malformed commit statuses")
            statuses.extend(dict(status) for status in payload if isinstance(status, Mapping))
            if len(payload) < 100:
                return statuses
        raise AuthorityError("GitHub REST issue discovery commit statuses exceeded the pagination bound")

    def list_issues(self, organization: str, repository: str) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
        issues: list[tuple[dict[str, Any], list[dict[str, Any]]]] = []
        cursor: str | None = None
        for _page in range(10):
            data = self.graphql(
                ISSUE_INTAKE_QUERY,
                {"cursor": cursor, "owner": organization, "repository": repository},
            )
            repository_node = data.get("repository")
            connection = repository_node.get("issues") if isinstance(repository_node, Mapping) else None
            if not isinstance(connection, Mapping) or not isinstance(connection.get("nodes"), list):
                raise AuthorityError(f"GitHub issue discovery cannot read {organization}/{repository}")
            for node in connection["nodes"]:
                if isinstance(node, Mapping):
                    issues.append(_normalize_intake_issue(node))
            page_info = connection.get("pageInfo")
            if not isinstance(page_info, Mapping):
                raise AuthorityError("GitHub issue discovery returned malformed pagination")
            if not page_info.get("hasNextPage"):
                return issues
            cursor = page_info.get("endCursor")
            if not isinstance(cursor, str) or not cursor:
                raise AuthorityError("GitHub issue discovery omitted its next cursor")
        raise AuthorityError(f"GitHub issue discovery for {repository} exceeded the pagination bound")

    def list_pull_requests(self, organization: str, repository: str) -> list[dict[str, Any]]:
        """Read bounded pull-request metadata without fetching titles, bodies, or comments."""

        pulls: list[dict[str, Any]] = []
        cursor: str | None = None
        for _page in range(10):
            data = self.graphql(
                PULL_REQUEST_METADATA_QUERY,
                {"cursor": cursor, "owner": organization, "repository": repository},
            )
            repository_node = data.get("repository")
            connection = repository_node.get("pullRequests") if isinstance(repository_node, Mapping) else None
            if not isinstance(connection, Mapping) or not isinstance(connection.get("nodes"), list):
                raise AuthorityError(f"GitHub pull-request metadata discovery cannot read {organization}/{repository}")
            for node in connection["nodes"]:
                if not isinstance(node, Mapping):
                    continue
                pulls.append(
                    {
                        "closed_at": node.get("closedAt"),
                        "created_at": node.get("createdAt"),
                        "merged_at": node.get("mergedAt"),
                        "number": node.get("number"),
                        "repository": repository,
                        "state": str(node.get("state", "")).lower(),
                        "type": "pull_request",
                        "updated_at": node.get("updatedAt"),
                        "url": node.get("url"),
                    }
                )
            page_info = connection.get("pageInfo")
            if not isinstance(page_info, Mapping):
                raise AuthorityError("GitHub pull-request metadata discovery returned malformed pagination")
            if not page_info.get("hasNextPage"):
                return pulls
            cursor = page_info.get("endCursor")
            if not isinstance(cursor, str) or not cursor:
                raise AuthorityError("GitHub pull-request metadata discovery omitted its next cursor")
        raise AuthorityError(f"GitHub pull-request metadata for {repository} exceeded the pagination bound")

    def get_issue(
        self,
        organization: str,
        repository: str,
        number: int,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        data = self.graphql(
            ISSUE_REVISION_QUERY,
            {"number": number, "owner": organization, "repository": repository},
        )
        repository_node = data.get("repository")
        node = repository_node.get("issue") if isinstance(repository_node, Mapping) else None
        if not isinstance(node, Mapping):
            raise AuthorityError(f"GitHub issue discovery cannot read {repository}/{number}")
        return _normalize_intake_issue(node)


def _manifest_core(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: manifest.get(key)
        for key in (
            "schema",
            "organization",
            "policy_digest",
            "legacy_target_migration_digest",
            "issues",
            "public_metadata",
            "rejected_issues",
        )
    }


def _manifest_public_metadata(manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    records = manifest.get("public_metadata")
    if not isinstance(records, list):
        raise AuthorityError("issue-intake manifest has no metadata-only public inventory")
    identities: set[tuple[str, str, int]] = set()
    normalized: list[dict[str, Any]] = []
    issue_keys = {
        "approved",
        "approval_reason",
        "closed_at",
        "created_at",
        "label_transition_at",
        "labels",
        "last_transition_at",
        "number",
        "repository",
        "specialized_lifecycle",
        "state",
        "type",
        "updated_at",
        "url",
    }
    pull_request_keys = {
        "closed_at",
        "created_at",
        "merged_at",
        "number",
        "repository",
        "state",
        "type",
        "updated_at",
        "url",
    }
    quarantine_keys = {"quarantined", "reconciliation_failure"}
    for record in records:
        if not isinstance(record, Mapping):
            raise AuthorityError("issue-intake manifest contains malformed public metadata")
        record_type = record.get("type")
        repository = record.get("repository")
        number = record.get("number")
        if (
            record_type not in {"issue", "pull_request"}
            or not isinstance(repository, str)
            or type(number) is not int
            or number < 1
        ):
            raise AuthorityError("issue-intake manifest contains invalid public metadata identity")
        keys = set(record)
        expected_keys = issue_keys if record_type == "issue" else pull_request_keys
        if not expected_keys <= keys or keys - expected_keys - quarantine_keys:
            raise AuthorityError("issue-intake manifest public metadata exceeds its metadata-only field set")
        expected_url = (
            f"https://github.com/{manifest.get('organization')}/{repository}/"
            f"{'issues' if record_type == 'issue' else 'pull'}/{number}"
        )
        if record.get("url") != expected_url:
            raise AuthorityError("issue-intake manifest contains a non-public metadata URL")
        labels = record.get("labels") if record_type == "issue" else []
        if not isinstance(labels, list) or not all(isinstance(label, str) and label for label in labels):
            raise AuthorityError("issue-intake manifest contains invalid public label metadata")
        identity = (repository, str(record_type), number)
        if identity in identities:
            raise AuthorityError("issue-intake manifest repeats a public metadata identity")
        identities.add(identity)
        normalized.append(dict(record))
    return normalized


def _manifest_completion_holds(manifest: Mapping[str, Any]) -> set[tuple[str, int]]:
    return {
        (record["repository"], record["number"])
        for record in manifest["issues"]
        if record["completion_evidence_required"] is True
    }


def _manifest_cross_repository_targets(
    manifest: Mapping[str, Any],
) -> dict[tuple[str, int], list[dict[str, Any]]]:
    return {
        (record["repository"], record["number"]): list(record["cross_repository_targets"])
        for record in manifest["issues"]
        if record["cross_repository_targets"]
    }


def _manifest_historical_cross_repository_completions(
    manifest: Mapping[str, Any],
) -> dict[tuple[str, int], list[dict[str, Any]]]:
    return {
        (record["repository"], record["number"]): list(record["historical_cross_repository_completion"])
        for record in manifest["issues"]
        if record["historical_cross_repository_completion"]
    }


def _manifest_frozen_cross_repository_lifecycles(
    manifest: Mapping[str, Any],
) -> dict[tuple[str, int], dict[str, Any]]:
    return {
        (record["repository"], record["number"]): dict(record["frozen_cross_repository_lifecycle"])
        for record in manifest["issues"]
        if record["frozen_cross_repository_lifecycle"] is not None
    }


def _manifest_prerelease_supersessions(
    manifest: Mapping[str, Any],
) -> dict[tuple[str, int], dict[str, Any]]:
    return {
        (record["repository"], record["number"]): dict(record["superseded_by"])
        for record in manifest["issues"]
        if record["superseded_by"] is not None
    }


def _is_issue_successor(successor: Mapping[str, Any]) -> bool:
    return type(successor.get("number")) is int


def _validate_immutable_product_train_successor(
    successor: Mapping[str, Any],
    raw: bytes,
) -> None:
    if hashlib.sha256(raw).hexdigest() != successor["sha256"]:
        raise AuthorityError("immutable prerelease successor product-train digest changed")
    try:
        product_train = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuthorityError("immutable prerelease successor product train is not valid UTF-8 JSON") from error

    train = successor["train"]
    train_match = PRODUCT_TRAIN_IDENTIFIER_PATTERN.fullmatch(train)
    trains = product_train.get("trains") if isinstance(product_train, Mapping) else None
    selected = trains.get(train) if isinstance(trains, Mapping) else None
    components = product_train.get("components") if isinstance(product_train, Mapping) else None
    versions = selected.get("versions") if isinstance(selected, Mapping) else None
    progression = product_train.get("progression") if isinstance(product_train, Mapping) else None
    prerelease_progression = progression.get("prerelease") if isinstance(progression, Mapping) else None
    component_version_pattern = (
        re.compile(rf"^{re.escape(train_match['base'])}-{train_match['channel']}\.[0-9]+$")
        if train_match is not None
        else None
    )
    synchronized = isinstance(versions, Mapping) and all(
        isinstance(version, str) and version == train for version in versions.values()
    )
    if (
        not isinstance(product_train, Mapping)
        or product_train.get("schema") != "durable-workflow.product-train/v2"
        or train_match is None
        or product_train.get("current") != train
        or components != list(COMPONENTS)
        or not isinstance(versions, Mapping)
        or set(versions) != set(COMPONENTS)
        or component_version_pattern is None
        or any(
            not isinstance(version, str) or component_version_pattern.fullmatch(version) is None
            for version in versions.values()
        )
        or selected.get("channel") != train_match["channel"]
        or selected.get("status") != "supported"
        or selected.get("release_plan") != successor["release_plan"]
        or not isinstance(progression, Mapping)
        or progression.get("stable") != "semantic_versioning"
        or progression.get("compatibility_shims") != "forbidden_between_2_0_prereleases"
        or prerelease_progression
        not in {
            "synchronized_beta_increment",
            "synchronized_prerelease_increment",
            "independent_prerelease_components",
        }
        or (prerelease_progression == "synchronized_beta_increment" and train_match["channel"] != "beta")
        or (prerelease_progression != "independent_prerelease_components" and not synchronized)
    ):
        raise AuthorityError("immutable prerelease successor is not one coherent supported public product train")


def _supersession_activation(
    supersession: Mapping[str, Any],
    retired_record: Mapping[str, Any],
    successor_record: Mapping[str, Any] | None,
) -> dict[str, str]:
    retired = supersession["retired"]
    successor = supersession["successor"]
    context = f"{SUPERSESSION_ACTIVATION_CONTEXT_PREFIX}/{retired['repository']}/{retired['number']}"
    if len(context) > 100:
        raise AuthorityError("prerelease supersession activation context exceeds the GitHub status bound")
    if _is_issue_successor(successor):
        assert successor_record is not None
        successor_authority = {
            **successor,
            "revision": successor_record["revision"],
        }
    else:
        successor_authority = dict(successor)
    activation = {
        "commit": supersession["activation_commit"],
        "context": context,
        "digest": _object_digest(
            {
                "activation_commit": supersession["activation_commit"],
                "reason": supersession["reason"],
                "retired": {
                    **retired,
                    "revision": retired_record["revision"],
                },
                "successor": successor_authority,
            }
        ),
    }
    return activation


def _activation_status_is_trusted(status: Mapping[str, Any]) -> bool:
    creator = status.get("creator")
    return (
        isinstance(creator, Mapping)
        and creator.get("id") == GITHUB_ACTIONS_BOT_ID
        and isinstance(creator.get("login"), str)
        and creator["login"].casefold() == GITHUB_ACTIONS_BOT_LOGIN
        and creator.get("type") == "Bot"
    )


def _supersession_activation_is_recorded(
    statuses: Sequence[Mapping[str, Any]],
    activation: Mapping[str, str],
) -> bool:
    trusted_authorities = [
        status
        for status in statuses
        if (
            status.get("context") == activation["context"]
            and _activation_status_is_trusted(status)
        )
    ]
    expected_description = SUPERSESSION_ACTIVATION_DESCRIPTION_PREFIX + activation["digest"]
    authorities = {
        (status.get("state"), status.get("description"))
        for status in trusted_authorities
    }
    if authorities and authorities != {("success", expected_description)}:
        raise AuthorityError("prerelease supersession has conflicting immutable activation authority")
    return authorities == {("success", expected_description)}


def _require_supersession_activation(
    policy: Mapping[str, Any],
    client: Any,
    activation: Mapping[str, str],
) -> None:
    statuses = client.list_commit_statuses(
        policy["organization"],
        ".github",
        activation["commit"],
    )
    if not _supersession_activation_is_recorded(statuses, activation):
        raise AuthorityError("completed prerelease successor has no immutable active-successor activation")


def _bind_prerelease_supersessions(
    policy: Mapping[str, Any],
    records: Sequence[dict[str, Any]],
    inventory: Mapping[str, Sequence[Mapping[str, Any]]],
    client: Any,
    *,
    require_activations: bool = True,
) -> None:
    record_by_identity = {(record["repository"], record["number"]): record for record in records}
    issue_by_identity = {
        (repository, int(issue["number"])): issue for repository, issues in inventory.items() for issue in issues
    }
    retired_identities = {
        (record["retired"]["repository"], record["retired"]["number"]) for record in policy["prerelease_supersessions"]
    }
    product_train_files: dict[tuple[str, str, str, str], bytes] = {}
    milestone_titles = {milestone["title"] for milestone in policy["milestones"]}
    blocker_labels = {
        "authority:github",
        "beta:blocker",
    }
    active_labels = {
        *blocker_labels,
        COMPLETION_REQUIRED_LABEL,
    }

    for supersession in policy["prerelease_supersessions"]:
        retired = supersession["retired"]
        successor = supersession["successor"]
        retired_identity = (retired["repository"], retired["number"])
        retired_record = record_by_identity.get(retired_identity)
        retired_issue = issue_by_identity.get(retired_identity)
        if retired_record is None or retired_issue is None:
            raise AuthorityError(
                f"retired prerelease issue {retired['repository']}#{retired['number']} "
                "does not have trusted current-revision intake"
            )

        retired_labels = _intake_label_names(retired_issue)
        retired_statuses = retired_labels & STATUS_LABELS
        retired_milestone = retired_issue.get("milestone")
        retired_milestone_title = retired_milestone.get("title") if isinstance(retired_milestone, Mapping) else None
        if (
            not blocker_labels <= retired_labels
            or len(retired_labels & KIND_LABELS) != 1
            or not retired_statuses
            or retired_issue.get("state") not in {"open", "closed"}
            or retired_milestone_title not in milestone_titles
        ):
            raise AuthorityError(
                f"retired prerelease issue {retired['repository']}#{retired['number']} "
                "does not retain evidence-required blocker authority"
            )

        if _is_issue_successor(successor):
            successor_identity = (successor["repository"], successor["number"])
            successor_record = record_by_identity.get(successor_identity)
            successor_issue = issue_by_identity.get(successor_identity)
            if successor_record is None or successor_issue is None:
                raise AuthorityError(
                    f"prerelease successor {successor['repository']}#{successor['number']} "
                    "does not have trusted current-revision intake"
                )

            successor_labels = _intake_label_names(successor_issue)
            successor_statuses = successor_labels & STATUS_LABELS
            successor_milestone = successor_issue.get("milestone")
            successor_milestone_title = (
                successor_milestone.get("title") if isinstance(successor_milestone, Mapping) else None
            )
            successor_is_active = (
                active_labels <= successor_labels
                and COMPLETION_VERIFIED_LABEL not in successor_labels
                and len(successor_labels & KIND_LABELS) == 1
                and len(successor_statuses) == 1
                and successor_statuses <= OPEN_STATUS_LABELS
                and successor_issue.get("state") == "open"
                and successor_milestone_title == retired_milestone_title
            )
            successor_is_completed = (
                {"authority:github", "beta:blocker", COMPLETION_VERIFIED_LABEL} <= successor_labels
                and len(successor_labels & KIND_LABELS) == 1
                and successor_statuses == {"status:done"}
                and successor_issue.get("state") == "closed"
                and successor_milestone_title == retired_milestone_title
            )
            successor_is_retiring = (
                successor_identity in retired_identities
                and blocker_labels <= successor_labels
                and len(successor_labels & KIND_LABELS) == 1
                and bool(successor_statuses)
                and successor_issue.get("state") in {"open", "closed"}
                and successor_milestone_title == retired_milestone_title
            )
            if not successor_is_active and not successor_is_completed and not successor_is_retiring:
                raise AuthorityError(
                    f"prerelease successor {successor['repository']}#{successor['number']} "
                    "is neither active, verified completed, nor bound to a later retirement "
                    "in the same release milestone"
                )

            activation = _supersession_activation(
                supersession,
                retired_record,
                successor_record,
            )
            if (
                retired_issue.get("state") == "closed"
                or SUPERSEDED_STATUS_LABEL in retired_statuses
                or successor_is_completed
                or successor_is_retiring
            ) and require_activations:
                _require_supersession_activation(policy, client, activation)
            retired_record["superseded_by"] = {
                "activation": activation,
                "number": successor["number"],
                "reason": supersession["reason"],
                "repository": successor["repository"],
                "revision": successor_record["revision"],
            }
            continue

        product_train_identity = (
            successor["repository"],
            successor["commit"],
            successor["path"],
            successor["sha256"],
        )
        raw = product_train_files.get(product_train_identity)
        if raw is None:
            raw = client.read_file(
                policy["organization"],
                successor["repository"],
                successor["commit"],
                successor["path"],
            )
            product_train_files[product_train_identity] = raw
        _validate_immutable_product_train_successor(successor, raw)
        activation = _supersession_activation(
            supersession,
            retired_record,
            None,
        )
        if (
            retired_issue.get("state") == "closed"
            or SUPERSEDED_STATUS_LABEL in retired_statuses
        ) and require_activations:
            _require_supersession_activation(policy, client, activation)
        retired_record["superseded_by"] = {
            "activation": activation,
            "commit": successor["commit"],
            "path": successor["path"],
            "reason": supersession["reason"],
            "release_plan": dict(successor["release_plan"]),
            "repository": successor["repository"],
            "sha256": successor["sha256"],
            "train": successor["train"],
        }


def _legacy_form_targets(
    body: str,
    targets: Mapping[str, Mapping[str, Any]],
    *,
    organization: str,
) -> list[dict[str, Any]]:
    heading_count = body.count(LEGACY_TARGET_HEADING)
    if heading_count == 0:
        return []
    if heading_count != 1:
        raise AuthorityError("legacy cross-repository issue repeats its affected public repositories section")
    section = body.split(LEGACY_TARGET_HEADING, 1)[1]
    section = re.split(r"(?m)^### ", section, maxsplit=1)[0]
    mentioned = set(re.findall(rf"\b{re.escape(organization)}/([a-z0-9_.-]+)\b", section))
    unknown = mentioned - set(targets)
    if unknown:
        raise AuthorityError(f"legacy cross-repository issue names unqualified targets {sorted(unknown)}")
    if len(mentioned) < 2:
        raise AuthorityError("legacy cross-repository issue does not bind at least two public targets")
    return [dict(targets[repository]) for repository in sorted(mentioned)]


def _legacy_migrated_targets(
    issue: Mapping[str, Any],
    timeline: Sequence[Mapping[str, Any]],
    assessment: Mapping[str, Any],
    migration: Mapping[str, Any] | None,
    targets: Mapping[str, Mapping[str, Any]],
    *,
    organization: str,
) -> list[dict[str, Any]]:
    if not _legacy_revision_is_eligible(issue, timeline, assessment, migration):
        return []
    assert migration is not None
    body = str(issue.get("body", ""))
    matches: list[Mapping[str, Any]] = []
    patterns = {
        "beta-work-id": MARKER_PATTERN,
        "durable-workflow-work-id": WORK_MARKER_PATTERN,
    }
    for authority in migration["authorities"]:
        pattern = patterns[authority["marker"]]
        if authority["id"] in pattern.findall(body):
            matches.append(authority)
    if len(matches) > 1:
        raise AuthorityError("legacy cross-repository revision matches multiple target migrations")
    if matches:
        authority = matches[0]
        try:
            return cross_repository_lifecycle.declared_targets(
                f"{cross_repository_lifecycle.TARGET_HEADING}\n\n" + "\n".join(authority["targets"]),
                targets,
                organization=organization,
                required=True,
            )
        except cross_repository_lifecycle.LifecycleError as error:
            raise AuthorityError(str(error)) from error
    return _legacy_form_targets(body, targets, organization=organization)


def _immutable_issue_targets(
    source_repository: str,
    issue: Mapping[str, Any],
    migration: Mapping[str, Any] | None,
    targets: Mapping[str, Mapping[str, Any]],
    *,
    organization: str,
) -> list[dict[str, Any]]:
    if migration is None:
        return []
    matches = [
        binding
        for binding in migration["immutable_issue_targets"]
        if binding["repository"] == source_repository and binding["number"] == issue.get("number")
    ]
    if not matches:
        return []
    if len(matches) != 1:
        raise AuthorityError("cross-repository issue matches multiple immutable target bindings")
    try:
        return cross_repository_lifecycle.declared_targets(
            f"{cross_repository_lifecycle.TARGET_HEADING}\n\n" + "\n".join(matches[0]["targets"]),
            targets,
            organization=organization,
            required=True,
        )
    except cross_repository_lifecycle.LifecycleError as error:
        raise AuthorityError(str(error)) from error


def _legacy_revision_is_eligible(
    issue: Mapping[str, Any],
    timeline: Sequence[Mapping[str, Any]],
    assessment: Mapping[str, Any],
    migration: Mapping[str, Any] | None,
) -> bool:
    if migration is None or assessment.get("approval_mode") != "trusted-creation":
        return False
    cutoff = _parse_timestamp(migration.get("created_before"), "legacy target migration cutoff")
    created_at = _parse_timestamp(issue.get("created_at"), "creation timestamp")
    if created_at >= cutoff or issue.get("last_edited_at") is not None:
        return False
    for event in timeline:
        if event.get("label") != "kind:cross-repository":
            continue
        if _parse_timestamp(event.get("created_at"), "cross-repository label timestamp") >= cutoff:
            return False
    return True


def _legacy_historical_completion(
    source_repository: str,
    issue: Mapping[str, Any],
    timeline: Sequence[Mapping[str, Any]],
    assessment: Mapping[str, Any],
    declared: Sequence[Mapping[str, Any]],
    migration: Mapping[str, Any] | None,
) -> list[dict[str, Any]]:
    if not _legacy_revision_is_eligible(issue, timeline, assessment, migration):
        return []
    assert migration is not None
    matches = [
        completion
        for completion in migration["historical_completions"]
        if completion["repository"] == source_repository
        and completion["number"] == issue.get("number")
        and completion["revision"] == assessment.get("revision")
    ]
    if not matches:
        return []
    if len(matches) != 1:
        raise AuthorityError("legacy cross-repository revision matches multiple historical completions")
    completion = matches[0]
    expected_targets = sorted(f"durable-workflow/{target['repository']}@{target['branch']}" for target in declared)
    if sorted(completion["targets"]) != expected_targets:
        raise AuthorityError(
            f"GitHub issue {issue['number']}: historical completion targets differ from its migrated target set"
        )
    landing_map = {
        (landing["repository"], landing["branch"]): landing for landing in migration["protected_branch_landings"]
    }
    return [dict(landing_map[(str(target["repository"]), str(target["branch"]))]) for target in declared]


def _frozen_lifecycle_migration(
    source_repository: str,
    issue: Mapping[str, Any],
    assessment: Mapping[str, Any],
    declared: Sequence[Mapping[str, Any]],
    migration: Mapping[str, Any] | None,
) -> dict[str, Any] | None:
    """Bind one reviewed migration to the exact trusted issue revision."""

    if migration is None:
        return None
    matches = [
        record
        for record in migration["frozen_lifecycle_migrations"]
        if record["repository"] == source_repository and record["number"] == issue.get("number")
    ]
    if not matches:
        return None
    if len(matches) != 1:
        raise AuthorityError("cross-repository issue matches multiple frozen lifecycle migrations")
    frozen = matches[0]
    approval_actor = assessment.get("approval_actor")
    approval_actor_sha256 = (
        hashlib.sha256(approval_actor.casefold().encode("utf-8")).hexdigest()
        if isinstance(approval_actor, str)
        else None
    )
    if (
        approval_actor_sha256 != frozen["approval_actor_sha256"]
        or assessment.get("approval_at") != frozen["approval_at"]
        or assessment.get("approval_mode") != frozen["approval_mode"]
    ):
        raise AuthorityError(
            f"GitHub issue {issue['number']}: frozen lifecycle authority differs from its trusted intake"
        )
    if assessment.get("revision") != frozen["approved_issue_revision_sha256"]:
        raise AuthorityError(
            f"GitHub issue {issue['number']}: current revision differs from reviewed frozen authority"
        )
    expected_targets = sorted(
        f"durable-workflow/{target['repository']}@{target['branch']}" for target in declared
    )
    if sorted(frozen["declared_targets"]) != expected_targets:
        raise AuthorityError(
            f"GitHub issue {issue['number']}: frozen lifecycle targets differ from its declared target set"
        )
    return json.loads(json.dumps(frozen))


def _issue_cross_repository_targets(
    source_repository: str,
    issue: Mapping[str, Any],
    timeline: Sequence[Mapping[str, Any]],
    assessment: Mapping[str, Any],
    targets: Mapping[str, Mapping[str, Any]],
    migration: Mapping[str, Any] | None,
    *,
    organization: str,
) -> list[dict[str, Any]]:
    labels = _intake_label_names(issue)
    is_cross_repository = "kind:cross-repository" in labels
    immutable_targets = _immutable_issue_targets(
        source_repository,
        issue,
        migration,
        targets,
        organization=organization,
    )
    try:
        declared = cross_repository_lifecycle.declared_targets(
            str(issue["body"]),
            targets,
            organization=organization,
        )
    except cross_repository_lifecycle.LifecycleError as error:
        raise AuthorityError(f"GitHub issue {issue['number']}: {error}") from error
    if declared:
        if immutable_targets:
            if declared != immutable_targets:
                raise AuthorityError(
                    f"GitHub issue {issue['number']}: declared source targets differ from its immutable target binding"
                )
            return declared
        if not is_cross_repository:
            raise AuthorityError(
                f"GitHub issue {issue['number']} declares multiple source targets without cross-repository authority"
            )
        return declared
    if immutable_targets:
        return immutable_targets
    if not is_cross_repository:
        return []
    migrated = _legacy_migrated_targets(
        issue,
        timeline,
        assessment,
        migration,
        targets,
        organization=organization,
    )
    if migrated:
        return migrated
    raise AuthorityError(
        f"GitHub issue {issue['number']}: cross-repository authority must declare its required source targets"
    )


def _target_rejection(
    repository: str,
    number: int,
    assessment: Mapping[str, Any],
    error: AuthorityError,
) -> dict[str, Any]:
    return {
        "approval_actor": assessment["approval_actor"],
        "approval_at": assessment["approval_at"],
        "approval_mode": assessment["approval_mode"],
        "number": number,
        "reason": str(error),
        "repository": repository,
        "revision": assessment["revision"],
    }


def _latest_lifecycle_transition(
    issue: Mapping[str, Any],
    timeline: Sequence[Mapping[str, Any]],
    *,
    approval_label: str,
) -> str:
    """Return the latest metadata-only timestamp that can change public lifecycle meaning."""

    candidates = [issue.get("created_at")]
    if issue.get("closed_at") is not None:
        candidates.append(issue.get("closed_at"))
    for event in timeline:
        if event.get("event") in {"closed", "reopened"} or (
            event.get("event") in {"labeled", "unlabeled"}
            and event.get("label") in {*STATUS_LABELS, *COMPLETION_LABELS, approval_label}
        ):
            candidates.append(event.get("created_at"))
    parsed = [
        (_parse_timestamp(value, "public lifecycle transition timestamp"), str(value))
        for value in candidates
        if value is not None
    ]
    if not parsed:
        raise AuthorityError(f"GitHub issue {issue.get('number')} has no lifecycle timestamp")
    return max(parsed, key=lambda record: record[0])[1]


def _issue_metadata_record(
    repository: str,
    issue: Mapping[str, Any],
    timeline: Sequence[Mapping[str, Any]],
    assessment: Mapping[str, Any],
    *,
    approval_label: str,
) -> dict[str, Any]:
    labels = sorted(_intake_label_names(issue))
    label_transition_at: dict[str, str] = {}
    for label in (*STATUS_LABELS, *COMPLETION_LABELS, approval_label):
        transitions = [
            (event.get("created_at"), event.get("event"))
            for event in timeline
            if event.get("label") == label and event.get("event") in {"labeled", "unlabeled"}
        ]
        if transitions:
            latest_at, latest_event = max(
                transitions,
                key=lambda record: _parse_timestamp(record[0], "label transition timestamp"),
            )
            if latest_event == "labeled" and label in labels:
                label_transition_at[label] = str(latest_at)
    return {
        "approved": assessment.get("approved") is True,
        "approval_reason": str(assessment.get("reason", "unknown")),
        "closed_at": issue.get("closed_at"),
        "created_at": issue.get("created_at"),
        "label_transition_at": label_transition_at,
        "labels": labels,
        "last_transition_at": _latest_lifecycle_transition(
            issue,
            timeline,
            approval_label=approval_label,
        ),
        "number": issue.get("number"),
        "repository": repository,
        "specialized_lifecycle": False,
        "state": issue.get("state"),
        "type": "issue",
        "updated_at": issue.get("updated_at"),
        "url": issue.get("html_url"),
    }


def discover_public_issue_metadata(policy: Mapping[str, Any], client: Any) -> list[dict[str, Any]]:
    """Collect only public issue metadata; never request instruction-bearing prose."""

    intake_policy = policy["intake"]
    metadata: list[dict[str, Any]] = []
    for repository in policy["repositories"]:
        for issue, timeline in client.list_issues(policy["organization"], repository):
            assessment = assess_issue_intake(
                issue,
                timeline,
                approval_label=intake_policy["approval_label"],
                trusted_actors=intake_policy["trusted_actors"],
                bind_revision=False,
            )
            metadata.append(
                _issue_metadata_record(
                    repository,
                    issue,
                    timeline,
                    assessment,
                    approval_label=intake_policy["approval_label"],
                )
            )
    return sorted(
        metadata,
        key=lambda record: (str(record["repository"]), int(record["number"])),
    )


def discover_public_metadata(policy: Mapping[str, Any], client: Any) -> list[dict[str, Any]]:
    """Collect only public issue/PR metadata; never request instruction-bearing prose."""

    metadata = discover_public_issue_metadata(policy, client)
    for repository in policy["repositories"]:
        metadata.extend(client.list_pull_requests(policy["organization"], repository))
    return sorted(
        metadata,
        key=lambda record: (str(record["repository"]), str(record["type"]), int(record["number"])),
    )


def reconstruct_intake(
    policy: dict[str, Any],
    client: Any,
    *,
    pre_intake_release_completions: Collection[tuple[str, int]] = (),
    target_qualification: Mapping[str, Any] | None = None,
    legacy_cross_repository_targets: Mapping[str, Any] | None = None,
    trigger_repository: str | None = None,
    trigger_number: int | None = None,
    trigger_action: str | None = None,
    trigger_actor: str | None = None,
    trigger_label: str | None = None,
    require_supersession_activations: bool = True,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    """Build a deterministic manifest and an inventory containing only vetted revisions."""

    intake_policy = policy["intake"]
    lifecycle_targets = (
        cross_repository_lifecycle.qualification_targets(target_qualification)
        if target_qualification is not None
        else {}
    )
    records: list[dict[str, Any]] = []
    rejected_records: list[dict[str, Any]] = []
    public_metadata: list[dict[str, Any]] = []
    metadata_by_identity: dict[tuple[str, int], dict[str, Any]] = {}
    inventory: dict[str, list[dict[str, Any]]] = {repository: [] for repository in policy["repositories"]}
    trigger_assessment: dict[str, Any] | None = None
    terminal_release_completions = set(pre_intake_release_completions)
    for repository in policy["repositories"]:
        for issue, timeline in client.list_issues(policy["organization"], repository):
            number = issue["number"]
            is_trigger = repository == trigger_repository and number == trigger_number
            if is_trigger and trigger_action == "edited":
                trigger_assessment = {"approved": False, "reason": "revision-edited"}
                continue
            if (
                is_trigger
                and trigger_action == "unlabeled"
                and trigger_label == intake_policy["approval_label"]
            ):
                trigger_assessment = {"approved": False, "reason": "approval-label-removed"}
                continue
            if (
                is_trigger
                and trigger_action == "labeled"
                and trigger_label == intake_policy["approval_label"]
                and (
                    not isinstance(trigger_actor, str)
                    or trigger_actor.casefold()
                    not in {actor.casefold() for actor in intake_policy["trusted_actors"]}
                )
            ):
                trigger_assessment = {"approved": False, "reason": "approval-actor-untrusted"}
                continue
            preliminary = assess_issue_intake(
                issue,
                timeline,
                approval_label=intake_policy["approval_label"],
                trusted_actors=intake_policy["trusted_actors"],
                bind_revision=False,
            )
            metadata = _issue_metadata_record(
                repository,
                issue,
                timeline,
                preliminary,
                approval_label=intake_policy["approval_label"],
            )
            public_metadata.append(metadata)
            metadata_by_identity[(repository, number)] = metadata
            if (repository, number) in terminal_release_completions:
                labels = _intake_label_names(issue)
                terminal = (
                    preliminary["approved"]
                    and issue.get("state") == "closed"
                    and labels & STATUS_LABELS == {"status:done"}
                    and COMPLETION_VERIFIED_LABEL in labels
                )
                if not terminal:
                    metadata["quarantined"] = True
                    metadata["reconciliation_failure"] = "release-completion-not-terminal"
                else:
                    metadata["approved"] = True
                    metadata["approval_reason"] = str(preliminary["reason"])
                    metadata["specialized_lifecycle"] = True
                if is_trigger:
                    trigger_assessment = (
                        dict(preliminary)
                        if terminal
                        else {"approved": False, "reason": "release-completion-not-terminal"}
                    )
                # A verified release completion is terminal before any approved
                # revision is fetched or prerelease supersession is bound. This
                # keeps the completed issue out of successor reservation.
                continue
            if not preliminary["approved"]:
                if is_trigger:
                    trigger_assessment = dict(preliminary)
                continue
            issue, timeline = client.get_issue(policy["organization"], repository, number)
            assessment = assess_issue_intake(
                issue,
                timeline,
                approval_label=intake_policy["approval_label"],
                trusted_actors=intake_policy["trusted_actors"],
            )
            if is_trigger:
                trigger_assessment = dict(assessment)
            if not assessment["approved"]:
                continue
            try:
                cross_repository_targets = _issue_cross_repository_targets(
                    repository,
                    issue,
                    timeline,
                    assessment,
                    lifecycle_targets,
                    legacy_cross_repository_targets,
                    organization=policy["organization"],
                )
                historical_completion = _legacy_historical_completion(
                    repository,
                    issue,
                    timeline,
                    assessment,
                    cross_repository_targets,
                    legacy_cross_repository_targets,
                )
                frozen_lifecycle = _frozen_lifecycle_migration(
                    repository,
                    issue,
                    assessment,
                    cross_repository_targets,
                    legacy_cross_repository_targets,
                )
            except AuthorityError as error:
                rejected_records.append(_target_rejection(repository, number, assessment, error))
                metadata["quarantined"] = True
                metadata["reconciliation_failure"] = "approved-intake-invalid"
                if is_trigger:
                    trigger_assessment = {"approved": False, "reason": "source-targets-invalid"}
                continue
            inventory[repository].append(issue)
            metadata["approved"] = True
            metadata["approval_reason"] = str(assessment["reason"])
            metadata["labels"] = sorted(_intake_label_names(issue))
            metadata["specialized_lifecycle"] = bool(
                cross_repository_targets or frozen_lifecycle
            )
            records.append(
                {
                    "approval_actor": assessment["approval_actor"],
                    "approval_at": assessment["approval_at"],
                    "approval_mode": assessment["approval_mode"],
                    "completion_evidence_required": COMPLETION_REQUIRED_LABEL in _intake_label_names(issue),
                    "cross_repository_targets": cross_repository_targets,
                    "frozen_cross_repository_lifecycle": frozen_lifecycle,
                    "historical_cross_repository_completion": historical_completion,
                    "number": number,
                    "repository": repository,
                    "revision": assessment["revision"],
                    "superseded_by": None,
                }
            )

        list_pull_requests = getattr(client, "list_pull_requests", None)
        if callable(list_pull_requests):
            public_metadata.extend(list_pull_requests(policy["organization"], repository))

    _bind_prerelease_supersessions(
        policy,
        records,
        inventory,
        client,
        require_activations=require_supersession_activations,
    )
    for record in records:
        if record["superseded_by"] is not None:
            metadata_by_identity[(record["repository"], record["number"])]["specialized_lifecycle"] = True
    manifest: dict[str, Any] = {
        "schema": INTAKE_SCHEMA,
        "organization": policy["organization"],
        "policy_digest": _object_digest(policy),
        "legacy_target_migration_digest": _object_digest(legacy_cross_repository_targets or {}),
        "issues": records,
        "public_metadata": sorted(
            public_metadata,
            key=lambda record: (str(record["repository"]), str(record["type"]), int(record["number"])),
        ),
        "rejected_issues": rejected_records,
    }
    if trigger_repository is not None or trigger_number is not None:
        approved = bool(trigger_assessment and trigger_assessment["approved"])
        reason = trigger_assessment["reason"] if trigger_assessment else "trigger-issue-not-found"
        manifest["trigger"] = {
            "action": trigger_action,
            "approved": approved,
            "number": trigger_number,
            "reason": reason,
            "repository": trigger_repository,
        }
    return manifest, inventory


def activate_prerelease_supersessions(
    policy: dict[str, Any],
    discovery: Any,
    client: Any,
    *,
    target_qualification: Mapping[str, Any] | None = None,
    legacy_cross_repository_targets: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Create only missing status authority derived from the current trusted intake."""

    manifest, _inventory = reconstruct_intake(
        policy,
        discovery,
        target_qualification=target_qualification,
        legacy_cross_repository_targets=legacy_cross_repository_targets,
        require_supersession_activations=False,
    )
    supersessions = _manifest_prerelease_supersessions(manifest)
    activations: list[dict[str, str]] = []
    for supersession in policy["prerelease_supersessions"]:
        retired = supersession["retired"]
        identity = (retired["repository"], retired["number"])
        bound = supersessions.get(identity)
        if bound is None:
            raise AuthorityError(
                f"prerelease supersession {retired['repository']}#{retired['number']} "
                "did not bind to trusted current-revision intake"
            )
        activations.append(dict(bound["activation"]))

    authority_repository = policy["authority_repository"]
    statuses_by_commit: dict[str, list[dict[str, Any]]] = {}
    recorded: list[bool] = []
    for activation in activations:
        commit = activation["commit"]
        if commit not in statuses_by_commit:
            statuses_by_commit[commit] = client.list_commit_statuses(
                policy["organization"],
                authority_repository,
                commit,
            )
        recorded.append(
            _supersession_activation_is_recorded(
                statuses_by_commit[commit],
                activation,
            )
        )

    evidence_activations: list[dict[str, Any]] = []
    for activation, already_recorded in zip(activations, recorded, strict=True):
        created = False
        if not already_recorded:
            created = client.ensure_supersession_activation(
                policy["organization"],
                authority_repository,
                activation,
            )
        evidence_activations.append(
            {
                **activation,
                "creator": {
                    "id": GITHUB_ACTIONS_BOT_ID,
                    "login": GITHUB_ACTIONS_BOT_LOGIN,
                    "type": "Bot",
                },
                "result": "created" if created else "existing",
            }
        )

    return {
        "schema": "durable-workflow.github-issue-authority-evidence/v1",
        "mode": "activate",
        "outcome": "pass",
        "activations": evidence_activations,
        "intake": _manifest_core(manifest),
    }


def _valid_superseded_by(
    value: Any,
    repositories: Collection[str],
) -> bool:
    if not isinstance(value, Mapping):
        return False
    activation = value.get("activation")
    if (
        not isinstance(activation, Mapping)
        or set(activation) != {"commit", "context", "digest"}
        or not re.fullmatch(r"[0-9a-f]{40}", str(activation.get("commit", "")))
        or not isinstance(activation.get("context"), str)
        or not activation["context"].startswith(SUPERSESSION_ACTIVATION_CONTEXT_PREFIX + "/")
        or not re.fullmatch(r"[0-9a-f]{64}", str(activation.get("digest", "")))
        or not isinstance(value.get("reason"), str)
        or not value["reason"]
        or not isinstance(value.get("repository"), str)
        or value["repository"] not in repositories
    ):
        return False

    if "number" in value:
        return (
            set(value) == {"activation", "number", "reason", "repository", "revision"}
            and type(value.get("number")) is int
            and value["number"] > 0
            and isinstance(value.get("revision"), str)
            and re.fullmatch(r"[0-9a-f]{64}", value["revision"]) is not None
        )

    release_plan = value.get("release_plan")
    return (
        set(value)
        == {
            "activation",
            "commit",
            "path",
            "reason",
            "release_plan",
            "repository",
            "sha256",
            "train",
        }
        and re.fullmatch(r"[0-9a-f]{40}", str(value.get("commit", ""))) is not None
        and value.get("path") == "product-train/current.json"
        and re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256", ""))) is not None
        and PRODUCT_TRAIN_IDENTIFIER_PATTERN.fullmatch(str(value.get("train", ""))) is not None
        and isinstance(release_plan, Mapping)
        and set(release_plan) == {"sha256", "tag"}
        and re.fullmatch(r"[0-9a-f]{64}", str(release_plan.get("sha256", ""))) is not None
        and re.fullmatch(r"release-plan/[a-z0-9][a-z0-9-]{2,79}", str(release_plan.get("tag", ""))) is not None
    )


def verify_intake_manifest(
    policy: dict[str, Any],
    manifest: Mapping[str, Any],
    client: Any,
    *,
    target_qualification: Mapping[str, Any] | None = None,
    legacy_cross_repository_targets: Mapping[str, Any] | None = None,
) -> dict[str, list[dict[str, Any]]]:
    if manifest.get("schema") != INTAKE_SCHEMA:
        raise AuthorityError("issue-intake manifest uses an unsupported schema")
    if (
        manifest.get("organization") != policy["organization"]
        or manifest.get("policy_digest") != _object_digest(policy)
        or manifest.get("legacy_target_migration_digest") != _object_digest(legacy_cross_repository_targets or {})
    ):
        raise AuthorityError("vetted issue revisions changed after read-only discovery")

    records = manifest.get("issues")
    rejected_records = manifest.get("rejected_issues")
    if not isinstance(records, list) or not isinstance(rejected_records, list):
        raise AuthorityError("issue-intake manifest has no complete issue record lists")

    record_keys = {
        "approval_actor",
        "approval_at",
        "approval_mode",
        "completion_evidence_required",
        "cross_repository_targets",
        "frozen_cross_repository_lifecycle",
        "historical_cross_repository_completion",
        "number",
        "repository",
        "revision",
        "superseded_by",
    }
    inventory: dict[str, list[dict[str, Any]]] = {repository: [] for repository in policy["repositories"]}
    identities: set[tuple[str, int]] = set()
    intake_policy = policy["intake"]
    lifecycle_targets = (
        cross_repository_lifecycle.qualification_targets(target_qualification)
        if target_qualification is not None
        else {}
    )
    current_records: list[dict[str, Any]] = []
    for record in records:
        if not isinstance(record, Mapping) or set(record) != record_keys:
            raise AuthorityError("issue-intake manifest contains a malformed issue record")
        repository = record.get("repository")
        number = record.get("number")
        superseded_by = record.get("superseded_by")
        if (
            not isinstance(repository, str)
            or repository not in inventory
            or not isinstance(number, int)
            or isinstance(number, bool)
            or number < 1
            or not isinstance(record.get("completion_evidence_required"), bool)
            or not isinstance(record.get("cross_repository_targets"), list)
            or (
                record.get("frozen_cross_repository_lifecycle") is not None
                and not isinstance(record.get("frozen_cross_repository_lifecycle"), Mapping)
            )
            or not isinstance(record.get("historical_cross_repository_completion"), list)
            or (superseded_by is not None and not _valid_superseded_by(superseded_by, inventory))
        ):
            raise AuthorityError("issue-intake manifest contains invalid issue authority")
        identity = (repository, number)
        if identity in identities:
            raise AuthorityError("issue-intake manifest contains a duplicate issue identity")
        identities.add(identity)

        issue, timeline = client.get_issue(policy["organization"], repository, number)
        assessment = assess_issue_intake(
            issue,
            timeline,
            approval_label=intake_policy["approval_label"],
            trusted_actors=intake_policy["trusted_actors"],
        )
        if not assessment["approved"]:
            raise AuthorityError("vetted issue revisions changed after read-only discovery")
        expected_targets = _issue_cross_repository_targets(
            repository,
            issue,
            timeline,
            assessment,
            lifecycle_targets,
            legacy_cross_repository_targets,
            organization=policy["organization"],
        )
        expected_historical_completion = _legacy_historical_completion(
            repository,
            issue,
            timeline,
            assessment,
            expected_targets,
            legacy_cross_repository_targets,
        )
        expected_frozen_lifecycle = _frozen_lifecycle_migration(
            repository,
            issue,
            assessment,
            expected_targets,
            legacy_cross_repository_targets,
        )
        current = {
            "approval_actor": assessment.get("approval_actor"),
            "approval_at": assessment.get("approval_at"),
            "approval_mode": assessment.get("approval_mode"),
            "completion_evidence_required": record["completion_evidence_required"],
            "cross_repository_targets": expected_targets,
            "frozen_cross_repository_lifecycle": expected_frozen_lifecycle,
            "historical_cross_repository_completion": expected_historical_completion,
            "number": issue.get("number"),
            "repository": repository,
            "revision": assessment.get("revision"),
            "superseded_by": None,
        }
        current_records.append(current)
        inventory[repository].append(issue)

    rejection_keys = {
        "approval_actor",
        "approval_at",
        "approval_mode",
        "number",
        "reason",
        "repository",
        "revision",
    }
    current_rejections: list[dict[str, Any]] = []
    for rejection in rejected_records:
        if not isinstance(rejection, Mapping) or set(rejection) != rejection_keys:
            raise AuthorityError("issue-intake manifest contains a malformed rejected issue record")
        repository = rejection.get("repository")
        number = rejection.get("number")
        if (
            not isinstance(repository, str)
            or repository not in inventory
            or type(number) is not int
            or number < 1
            or not isinstance(rejection.get("reason"), str)
            or not rejection["reason"]
        ):
            raise AuthorityError("issue-intake manifest contains invalid rejected issue authority")
        identity = (repository, number)
        if identity in identities:
            raise AuthorityError("issue-intake manifest contains a duplicate issue identity")
        identities.add(identity)

        issue, timeline = client.get_issue(policy["organization"], repository, number)
        assessment = assess_issue_intake(
            issue,
            timeline,
            approval_label=intake_policy["approval_label"],
            trusted_actors=intake_policy["trusted_actors"],
        )
        if not assessment["approved"]:
            raise AuthorityError("vetted issue revisions changed after read-only discovery")
        try:
            expected_targets = _issue_cross_repository_targets(
                repository,
                issue,
                timeline,
                assessment,
                lifecycle_targets,
                legacy_cross_repository_targets,
                organization=policy["organization"],
            )
            _legacy_historical_completion(
                repository,
                issue,
                timeline,
                assessment,
                expected_targets,
                legacy_cross_repository_targets,
            )
            _frozen_lifecycle_migration(
                repository,
                issue,
                assessment,
                expected_targets,
                legacy_cross_repository_targets,
            )
        except AuthorityError as error:
            current_rejections.append(_target_rejection(repository, number, assessment, error))
        else:
            raise AuthorityError("vetted issue revisions changed after read-only discovery")

    if [dict(rejection) for rejection in rejected_records] != current_rejections:
        raise AuthorityError("vetted issue revisions changed after read-only discovery")

    _bind_prerelease_supersessions(policy, current_records, inventory, client)
    if [dict(record) for record in records] != current_records:
        raise AuthorityError("vetted issue revisions changed after read-only discovery")
    return inventory


class GitHubApi:
    """Bounded GitHub client for public issue metadata and lifecycle labels."""

    def __init__(
        self,
        token: str,
        api_url: str = "https://api.github.com",
        *,
        activation_token: str | None = None,
        read_token: str | None = None,
        graphql_url: str = "https://api.github.com/graphql",
    ) -> None:
        if not token:
            raise AuthorityError("BETA_PRODUCT_WORK_TOKEN is required for cross-repository issue authority")
        self.api_url = api_url.rstrip("/")
        self.graphql_url = graphql_url
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "durable-workflow-issue-authority/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        self.read_headers = {
            **self.headers,
            "Authorization": f"Bearer {read_token if read_token is not None else token}",
        }
        self.activation_headers = {
            **self.headers,
            "Authorization": f"Bearer {activation_token if activation_token is not None else token}",
        }
        self._writer_identity: tuple[int, str] | None = None

    @staticmethod
    def _error_detail(error: urllib.error.HTTPError) -> str:
        try:
            return error.read().decode("utf-8", errors="replace")[:600]
        except OSError:
            return "response body unavailable"

    def _request(
        self,
        method: str,
        path: str,
        payload: Mapping[str, Any] | None = None,
        *,
        writer_authenticated_read: bool = False,
    ) -> Any:
        if (
            payload is not None
            and isinstance(payload.get("labels"), Sequence)
            and not isinstance(payload.get("labels"), str | bytes)
            and re.fullmatch(r"/repos/[^/]+/[^/]+/issues(?:/[1-9][0-9]*)?(?:/labels)?", path)
        ):
            raw_labels = payload["labels"]
            if not all(isinstance(label, str) for label in raw_labels):
                raise AuthorityError(f"GitHub issue writer {path} received invalid labels")
            _require_exact_kind_label(raw_labels, f"GitHub issue writer {path}")
        body = None
        headers = dict(self.read_headers if method == "GET" and not writer_authenticated_read else self.headers)
        if payload is not None:
            body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(f"{self.api_url}{path}", data=body, headers=headers, method=method)
        # A lost response to POST may mean GitHub accepted the mutation. Never
        # repeat a create request: the next workflow run rediscovers it by its
        # stable marker or unique metadata name before trying again.
        attempts = 1 if method == "POST" else GITHUB_API_ATTEMPTS
        for attempt in range(1, attempts + 1):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    response_body = response.read()
                return json.loads(response_body) if response_body else None
            except urllib.error.HTTPError as error:
                detail = self._error_detail(error)
                retryable = error.code == 429 or 500 <= error.code <= 599
                if not retryable or attempt == attempts:
                    raise AuthorityError(f"GitHub API {method} {path} returned {error.code}: {detail}") from error
            except (urllib.error.URLError, ConnectionError, TimeoutError) as error:
                if attempt == attempts:
                    raise AuthorityError(f"GitHub API {method} {path} failed after bounded retries: {error}") from error
            time.sleep(GITHUB_API_RETRY_SECONDS * (2 ** (attempt - 1)))
        raise AssertionError("GitHub API retry loop ended unexpectedly")

    def request(self, method: str, path: str, payload: Mapping[str, Any] | None = None) -> Any:
        return self._request(method, path, payload)

    def _graphql(self, query: str, variables: Mapping[str, Any]) -> dict[str, Any]:
        body = json.dumps({"query": query, "variables": variables}, separators=(",", ":")).encode("utf-8")
        headers = {**self.read_headers, "Content-Type": "application/json"}
        request = urllib.request.Request(self.graphql_url, data=body, headers=headers, method="POST")
        for attempt in range(1, GITHUB_API_ATTEMPTS + 1):
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    payload = json.loads(response.read())
                if not isinstance(payload, dict) or payload.get("errors") or not isinstance(payload.get("data"), dict):
                    raise AuthorityError("GitHub GraphQL lifecycle authority returned errors")
                return payload["data"]
            except urllib.error.HTTPError as error:
                retryable = error.code == 429 or 500 <= error.code <= 599
                if not retryable or attempt == GITHUB_API_ATTEMPTS:
                    raise AuthorityError(f"GitHub GraphQL lifecycle authority returned {error.code}") from error
            except (urllib.error.URLError, ConnectionError, TimeoutError, json.JSONDecodeError) as error:
                if attempt == GITHUB_API_ATTEMPTS:
                    raise AuthorityError("GitHub GraphQL lifecycle authority failed after bounded retries") from error
            time.sleep(GITHUB_API_RETRY_SECONDS * (2 ** (attempt - 1)))
        raise AssertionError("GitHub GraphQL retry loop ended unexpectedly")

    def _authenticated_writer(self) -> tuple[int, str]:
        if self._writer_identity is not None:
            return self._writer_identity
        user = self._request("GET", "/user", writer_authenticated_read=True)
        identifier = user.get("id") if isinstance(user, Mapping) else None
        login = user.get("login") if isinstance(user, Mapping) else None
        if type(identifier) is not int or identifier < 1 or not isinstance(login, str) or not login:
            raise AuthorityError("BETA_PRODUCT_WORK_TOKEN did not identify an authenticated GitHub writer")
        self._writer_identity = (identifier, login)
        return self._writer_identity

    def list_collection(self, path: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        separator = "&" if "?" in path else "?"
        for page in range(1, 11):
            payload = self.request("GET", f"{path}{separator}per_page=100&page={page}")
            if not isinstance(payload, list):
                raise AuthorityError(f"GitHub API collection {path} did not return a list")
            records.extend(record for record in payload if isinstance(record, dict))
            if len(payload) < 100:
                return records
        raise AuthorityError(f"GitHub API collection {path} exceeded the pagination bound")

    def list_commit_statuses(
        self,
        organization: str,
        repository: str,
        commit: str,
    ) -> list[dict[str, Any]]:
        encoded_commit = urllib.parse.quote(commit, safe="")
        return self.list_collection(f"/repos/{organization}/{repository}/commits/{encoded_commit}/statuses")

    def ensure_supersession_activation(
        self,
        organization: str,
        repository: str,
        activation: Mapping[str, str],
    ) -> bool:
        statuses = self.list_commit_statuses(
            organization,
            repository,
            activation["commit"],
        )
        if _supersession_activation_is_recorded(statuses, activation):
            return False

        encoded_commit = urllib.parse.quote(activation["commit"], safe="")
        payload = {
            "context": activation["context"],
            "description": SUPERSESSION_ACTIVATION_DESCRIPTION_PREFIX + activation["digest"],
            "state": "success",
        }
        request = urllib.request.Request(
            f"{self.api_url}/repos/{organization}/{repository}/statuses/{encoded_commit}",
            data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
            headers={**self.activation_headers, "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                result = json.loads(response.read())
        except (
            urllib.error.HTTPError,
            urllib.error.URLError,
            ConnectionError,
            TimeoutError,
            json.JSONDecodeError,
        ) as error:
            raise AuthorityError("GitHub could not persist immutable prerelease supersession activation") from error
        if not isinstance(result, Mapping) or not _supersession_activation_is_recorded([result], activation):
            raise AuthorityError("GitHub returned untrusted prerelease supersession activation")
        return True

    def ensure_labels(
        self,
        organization: str,
        repository: str,
        desired: Sequence[dict[str, str]],
    ) -> list[str]:
        base = f"/repos/{organization}/{repository}/labels"
        existing = {record.get("name"): record for record in self.list_collection(base)}
        changes: list[str] = []
        for label in desired:
            current = existing.get(label["name"])
            if current is None:
                self.request("POST", base, label)
                changes.append(f"created:{label['name']}")
                continue
            current_matches = (
                current.get("color", "").lower() == label["color"]
                and current.get("description") == label["description"]
            )
            if current_matches:
                continue
            encoded_name = urllib.parse.quote(label["name"], safe="")
            update = {
                "new_name": label["name"],
                "color": label["color"],
                "description": label["description"],
            }
            self.request("PATCH", f"{base}/{encoded_name}", update)
            changes.append(f"updated:{label['name']}")
        return changes

    def ensure_milestone(
        self,
        organization: str,
        repository: str,
        desired: dict[str, Any],
    ) -> tuple[int, str | None]:
        base = f"/repos/{organization}/{repository}/milestones"
        existing = {record.get("title"): record for record in self.list_collection(f"{base}?state=all")}
        current = existing.get(desired["title"])
        payload = {
            "title": desired["title"],
            "description": desired["description"],
            "state": desired["state"],
        }
        if current is None:
            created = self.request("POST", base, payload)
            return int(created["number"]), "created"
        number = int(current["number"])
        if current.get("description") == desired["description"] and current.get("state") == desired["state"]:
            return number, None
        self.request("PATCH", f"{base}/{number}", payload)
        return number, "updated"

    def list_issues(self, organization: str, repository: str) -> list[dict[str, Any]]:
        records = self.list_collection(f"/repos/{organization}/{repository}/issues?state=all&direction=asc")
        return [record for record in records if "pull_request" not in record]

    def create_issue(
        self,
        organization: str,
        repository: str,
        *,
        title: str,
        body: str,
        labels: Sequence[str],
        milestone: int,
    ) -> dict[str, Any]:
        _require_exact_kind_label(labels, f"new GitHub issue {repository}/{title}")
        result = self.request(
            "POST",
            f"/repos/{organization}/{repository}/issues",
            {"title": title, "body": body, "labels": list(labels), "milestone": milestone},
        )
        if not isinstance(result, dict):
            raise AuthorityError(f"GitHub did not return the created issue for {repository}/{title}")
        return result

    def replace_issue_labels(
        self,
        organization: str,
        repository: str,
        number: int,
        labels: Sequence[str],
    ) -> None:
        _require_exact_kind_label(labels, f"GitHub issue {repository}#{number}")
        self.request(
            "PUT",
            f"/repos/{organization}/{repository}/issues/{number}/labels",
            {"labels": sorted(set(labels))},
        )

    def update_issue_body(
        self,
        organization: str,
        repository: str,
        number: int,
        body: str,
    ) -> None:
        self.request("PATCH", f"/repos/{organization}/{repository}/issues/{number}", {"body": body})

    def update_issue_state(
        self,
        organization: str,
        repository: str,
        number: int,
        state: str,
        *,
        state_reason: str,
    ) -> None:
        valid_state_reasons = {
            "closed": {"completed", "not_planned"},
            "open": {"reopened"},
        }
        if state_reason not in valid_state_reasons.get(state, set()):
            raise AuthorityError(f"invalid GitHub issue state reason {state_reason!r} for {state!r} state")
        self.request(
            "PATCH",
            f"/repos/{organization}/{repository}/issues/{number}",
            {"state": state, "state_reason": state_reason},
        )

    def list_issue_closing_references(
        self,
        organization: str,
        repository: str,
        number: int,
    ) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        cursor: str | None = None
        for _page in range(10):
            data = self._graphql(
                CLOSING_REFERENCE_QUERY,
                {
                    "cursor": cursor,
                    "number": number,
                    "owner": organization,
                    "repository": repository,
                },
            )
            repository_node = data.get("repository")
            issue = repository_node.get("issue") if isinstance(repository_node, Mapping) else None
            connection = issue.get("timelineItems") if isinstance(issue, Mapping) else None
            if not isinstance(connection, Mapping) or not isinstance(connection.get("nodes"), list):
                raise AuthorityError(f"GitHub GraphQL lifecycle authority cannot read {repository}/{number}")
            records.extend(dict(node) for node in connection["nodes"] if isinstance(node, Mapping))
            page_info = connection.get("pageInfo")
            if not isinstance(page_info, Mapping):
                raise AuthorityError("GitHub GraphQL lifecycle authority returned malformed pagination")
            if not page_info.get("hasNextPage"):
                return records
            cursor = page_info.get("endCursor")
            if not isinstance(cursor, str) or not cursor:
                raise AuthorityError("GitHub GraphQL lifecycle authority omitted its next cursor")
        raise AuthorityError(
            f"GitHub GraphQL lifecycle authority for {repository}/{number} exceeded the pagination bound"
        )

    def get_pull_request(self, organization: str, repository: str, number: int) -> dict[str, Any]:
        result = self.request("GET", f"/repos/{organization}/{repository}/pulls/{number}")
        if not isinstance(result, dict):
            raise AuthorityError(f"GitHub did not return linked pull request {repository}#{number}")
        return result

    def list_pull_request_reviews(
        self,
        organization: str,
        repository: str,
        number: int,
    ) -> list[dict[str, Any]]:
        return self.list_collection(f"/repos/{organization}/{repository}/pulls/{number}/reviews")

    def commit_reaches_branch(
        self,
        organization: str,
        repository: str,
        commit: str,
        branch: str,
    ) -> bool:
        encoded_commit = urllib.parse.quote(commit, safe="")
        encoded_branch = urllib.parse.quote(branch, safe="")
        comparison = self.request(
            "GET",
            f"/repos/{organization}/{repository}/compare/{encoded_commit}...{encoded_branch}",
        )
        return isinstance(comparison, dict) and comparison.get("status") in {"ahead", "identical"}

    def commit_contains(
        self,
        organization: str,
        repository: str,
        descendant: str,
        ancestor: str,
    ) -> bool:
        encoded_ancestor = urllib.parse.quote(ancestor, safe="")
        encoded_descendant = urllib.parse.quote(descendant, safe="")
        comparison = self.request(
            "GET",
            f"/repos/{organization}/{repository}/compare/{encoded_ancestor}...{encoded_descendant}",
        )
        return isinstance(comparison, dict) and comparison.get("status") in {"ahead", "identical"}

    def _latest_check_runs(self, organization: str, repository: str, commit: str) -> dict[str, dict[str, Any]]:
        encoded_commit = urllib.parse.quote(commit, safe="")
        runs: list[dict[str, Any]] = []
        for page in range(1, 11):
            payload = self.request(
                "GET",
                f"/repos/{organization}/{repository}/commits/{encoded_commit}/check-runs?per_page=100&page={page}",
            )
            page_runs = payload.get("check_runs") if isinstance(payload, dict) else None
            if not isinstance(page_runs, list):
                raise AuthorityError(f"GitHub did not return check runs for {repository}@{commit}")
            runs.extend(run for run in page_runs if isinstance(run, dict))
            if len(page_runs) < 100:
                break
        else:
            raise AuthorityError(f"GitHub check runs for {repository}@{commit} exceeded the pagination bound")
        latest: dict[str, tuple[tuple[str, int], dict[str, Any]]] = {}
        for run in runs:
            name = run.get("name")
            identifier = run.get("id")
            if not isinstance(name, str) or not isinstance(identifier, int):
                continue
            timestamp = run.get("completed_at") or run.get("started_at") or ""
            ordering = (timestamp if isinstance(timestamp, str) else "", identifier)
            if name not in latest or ordering > latest[name][0]:
                latest[name] = (ordering, run)
        return {name: run for name, (_ordering, run) in latest.items()}

    def successful_check_names(self, organization: str, repository: str, commit: str) -> set[str]:
        return {
            name
            for name, run in self._latest_check_runs(organization, repository, commit).items()
            if run.get("status") == "completed" and run.get("conclusion") == "success"
        }

    def successful_check_run_ids(self, organization: str, repository: str, commit: str) -> dict[str, int]:
        """Bind each latest green check name to its immutable GitHub Actions run identity."""

        pattern = re.compile(
            rf"https://github\.com/{re.escape(organization)}/{re.escape(repository)}/actions/runs/"
            r"([1-9][0-9]*)(?:/job/[1-9][0-9]*)?(?:\?[^#\s]*)?"
        )
        identities: dict[str, int] = {}
        for name, run in self._latest_check_runs(organization, repository, commit).items():
            details_url = run.get("details_url")
            match = pattern.fullmatch(details_url) if isinstance(details_url, str) else None
            if run.get("status") == "completed" and run.get("conclusion") == "success" and match is not None:
                identities[name] = int(match.group(1))
        return identities

    def successful_workflow_run(
        self,
        organization: str,
        repository: str,
        run_id: int,
        commit: str,
        workflow_path: str | None,
        workflow_name: str | None,
    ) -> bool:
        """Verify one cited run's repository, workflow, commit, and successful conclusion."""

        run = self.request("GET", f"/repos/{organization}/{repository}/actions/runs/{run_id}")
        run_repository = run.get("repository") if isinstance(run, Mapping) else None
        run_workflow_name = run.get("name") if isinstance(run, Mapping) else None
        run_workflow_path = run.get("path") if isinstance(run, Mapping) else None
        run_workflow_id = run.get("workflow_id") if isinstance(run, Mapping) else None
        actual_workflow_is_identified = (
            isinstance(run_workflow_name, str)
            and bool(run_workflow_name.strip())
            and isinstance(run_workflow_path, str)
            and re.fullmatch(r"\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml", run_workflow_path) is not None
            and type(run_workflow_id) is int
            and run_workflow_id > 0
        )
        expected_workflow_path = f".github/workflows/{workflow_path}" if workflow_path is not None else None
        run_matches = (
            isinstance(run, Mapping)
            and type(run.get("id")) is int
            and run["id"] == run_id
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and run.get("head_sha") == commit
            and actual_workflow_is_identified
            and (expected_workflow_path is None or run_workflow_path == expected_workflow_path)
            and run.get("html_url") == f"https://github.com/{organization}/{repository}/actions/runs/{run_id}"
            and isinstance(run_repository, Mapping)
            and run_repository.get("full_name") == f"{organization}/{repository}"
        )
        if not run_matches:
            return False

        workflow = self.request(
            "GET",
            f"/repos/{organization}/{repository}/actions/workflows/{run_workflow_id}",
        )
        definition_name = workflow.get("name") if isinstance(workflow, Mapping) else None
        return (
            isinstance(workflow, Mapping)
            and type(workflow.get("id")) is int
            and workflow["id"] == run_workflow_id
            and isinstance(definition_name, str)
            and bool(definition_name.strip())
            and workflow.get("path") == run_workflow_path
            and (workflow_name is None or definition_name == workflow_name)
        )

    def successful_historical_workflow_run(
        self,
        organization: str,
        repository: str,
        run_id: int,
        commit: str,
        branch: str,
        workflow_path: str,
        workflow_name: str,
    ) -> bool:
        """Verify immutable run metadata without consulting a renamed current workflow."""

        run = self.request("GET", f"/repos/{organization}/{repository}/actions/runs/{run_id}")
        run_repository = run.get("repository") if isinstance(run, Mapping) else None
        return (
            isinstance(run, Mapping)
            and type(run.get("id")) is int
            and run["id"] == run_id
            and run.get("status") == "completed"
            and run.get("conclusion") == "success"
            and run.get("head_sha") == commit
            and run.get("event") == "push"
            and run.get("head_branch") == branch
            and run.get("name") == workflow_name
            and run.get("path") == f".github/workflows/{workflow_path}"
            and run.get("html_url")
            == f"https://github.com/{organization}/{repository}/actions/runs/{run_id}"
            and isinstance(run_repository, Mapping)
            and run_repository.get("full_name") == f"{organization}/{repository}"
        )

    def successful_historical_workflow_jobs(
        self,
        organization: str,
        repository: str,
        run_id: int,
    ) -> dict[str, int]:
        """Return successful latest-attempt jobs bound to one immutable workflow run."""

        jobs: list[dict[str, Any]] = []
        for page in range(1, 11):
            payload = self.request(
                "GET",
                f"/repos/{organization}/{repository}/actions/runs/{run_id}/jobs"
                f"?filter=latest&per_page=100&page={page}",
            )
            page_jobs = payload.get("jobs") if isinstance(payload, Mapping) else None
            if not isinstance(page_jobs, list) or not all(isinstance(job, dict) for job in page_jobs):
                raise AuthorityError("GitHub Actions run jobs did not return a complete collection")
            jobs.extend(page_jobs)
            if len(page_jobs) < 100:
                successful: dict[str, int] = {}
                for job in jobs:
                    if (
                        isinstance(job.get("name"), str)
                        and type(job.get("id")) is int
                        and job["id"] > 0
                        and job.get("status") == "completed"
                        and job.get("conclusion") == "success"
                        and isinstance(job.get("html_url"), str)
                        and re.fullmatch(
                            rf"https://github\.com/{re.escape(organization)}/"
                            rf"{re.escape(repository)}/actions/runs/{run_id}/job/[1-9][0-9]*",
                            job["html_url"],
                        )
                        is not None
                    ):
                        name = str(job["name"])
                        if name in successful:
                            raise AuthorityError(
                                "GitHub Actions run contains duplicate successful job names"
                            )
                        successful[name] = int(job["id"])
                return successful
        raise AuthorityError("GitHub Actions run jobs exceeded the pagination bound")

    def list_trusted_issue_comments(
        self,
        organization: str,
        repository: str,
        number: int,
    ) -> list[dict[str, Any]]:
        """Return comments owned by the exact authenticated lifecycle writer identity."""

        comments = self.list_collection(f"/repos/{organization}/{repository}/issues/{number}/comments")
        writer_id, writer_login = self._authenticated_writer()
        return [
            comment
            for comment in comments
            if (
                isinstance(comment.get("body"), str)
                and type(comment.get("id")) is int
                and isinstance(comment.get("user"), Mapping)
                and type(comment["user"].get("id")) is int
                and comment["user"]["id"] == writer_id
                and isinstance(comment["user"].get("login"), str)
                and comment["user"]["login"].casefold() == writer_login.casefold()
            )
        ]

    def upsert_lifecycle_comment(
        self,
        organization: str,
        repository: str,
        number: int,
        marker: str,
        body: str,
    ) -> bool:
        comment = self._managed_lifecycle_comment(organization, repository, number, marker)
        if comment is not None:
            if comment["body"] == body:
                return False
            comment_id = comment.get("id")
            if not isinstance(comment_id, int):
                raise AuthorityError(f"GitHub issue {repository}#{number} has lifecycle evidence without an identity")
            self.request("PATCH", f"/repos/{organization}/{repository}/issues/comments/{comment_id}", {"body": body})
            return True
        self.request("POST", f"/repos/{organization}/{repository}/issues/{number}/comments", {"body": body})
        return True

    def _managed_lifecycle_comment(
        self,
        organization: str,
        repository: str,
        number: int,
        marker: str,
    ) -> dict[str, Any] | None:
        comments = self.list_trusted_issue_comments(organization, repository, number)
        matches = [comment for comment in comments if marker in comment["body"]]
        if len(matches) > 1:
            raise AuthorityError(
                f"GitHub issue {repository}#{number} has duplicate cross-repository lifecycle evidence"
            )
        return matches[0] if matches else None

    def managed_lifecycle_comment_body(
        self,
        organization: str,
        repository: str,
        number: int,
        marker: str,
    ) -> str | None:
        comment = self._managed_lifecycle_comment(organization, repository, number, marker)
        return str(comment["body"]) if comment is not None else None

    def has_managed_lifecycle_comment(
        self,
        organization: str,
        repository: str,
        number: int,
        marker: str | None = None,
    ) -> bool:
        markers = (
            {marker}
            if marker is not None
            else {
                FROZEN_LIFECYCLE_EVIDENCE_MARKER,
                PUBLIC_LIFECYCLE_MARKER,
                SUPERSESSION_EVIDENCE_MARKER,
                cross_repository_lifecycle.EVIDENCE_MARKER,
            }
        )
        return any(
            any(marker in comment["body"] for marker in markers)
            for comment in self.list_trusted_issue_comments(organization, repository, number)
        )


def _label_names(issue: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for label in issue.get("labels") or []:
        if isinstance(label, str):
            names.add(label)
        elif isinstance(label, dict) and isinstance(label.get("name"), str):
            names.add(label["name"])
    return names


def _kind_label_names(labels: Collection[str]) -> set[str]:
    return {label for label in labels if label.startswith("kind:")}


def _has_trusted_public_retirement(
    client: Any,
    organization: str,
    repository: str,
    number: int,
) -> bool:
    """Recognize only the authenticated lifecycle writer's retirement record."""

    records = []
    for comment in client.list_trusted_issue_comments(organization, repository, number):
        lines = comment["body"].splitlines()
        if PUBLIC_LIFECYCLE_MARKER in lines:
            records.append(lines)
    if len(records) > 1:
        raise AuthorityError(f"GitHub issue {repository}#{number} has duplicate public lifecycle records")
    if not records:
        return False
    marker_count = records[0].count(PUBLIC_RETIREMENT_RECORD_MARKER)
    if marker_count > 1:
        raise AuthorityError(f"GitHub issue {repository}#{number} has duplicate public retirement markers")
    return marker_count == 1


def _require_exact_kind_label(labels: Collection[str], location: str) -> str:
    kinds = _kind_label_names(labels)
    if len(kinds) != 1:
        raise AuthorityError(f"{location} label write must contain exactly one kind:* label, got {sorted(kinds)}")
    kind = next(iter(kinds))
    if kind not in KIND_LABELS:
        raise AuthorityError(f"{location} label write contains unsupported lifecycle kind {kind!r}")
    return kind


def _replace_kind_label(labels: Collection[str], kind: str) -> set[str]:
    """Replace, rather than append, the kind at completion and release writer boundaries."""

    if kind not in KIND_LABELS:
        raise AuthorityError(f"unsupported lifecycle kind transition {kind!r}")
    replacement = {label for label in labels if not label.startswith("kind:")}
    replacement.add(kind)
    _require_exact_kind_label(replacement, "lifecycle kind transition")
    return replacement


def _issue_url(issue: dict[str, Any], organization: str, repository: str) -> str:
    url = issue.get("html_url")
    if isinstance(url, str) and url.startswith("https://github.com/"):
        return url
    number = issue.get("number")
    if not isinstance(number, int):
        raise AuthorityError(f"GitHub issue in {repository} has no numeric identity")
    return f"https://github.com/{organization}/{repository}/issues/{number}"


def _render_supersession_evidence(
    organization: str,
    retired_repository: str,
    retired_number: int,
    successor: Mapping[str, Any],
) -> str:
    successor_repository = str(successor["repository"])
    if "number" in successor:
        successor_number = int(successor["number"])
        successor_url = f"https://github.com/{organization}/{successor_repository}/issues/{successor_number}"
        successor_line = f"[{organization}/{successor_repository}#{successor_number}]({successor_url})"
    else:
        successor_commit = str(successor["commit"])
        successor_path = str(successor["path"])
        successor_url = (
            f"https://github.com/{organization}/{successor_repository}/blob/{successor_commit}/{successor_path}"
        )
        successor_line = (
            f"[{successor['train']} immutable product train]({successor_url}) (`{successor['release_plan']['tag']}`)"
        )
    return (
        f"{SUPERSESSION_EVIDENCE_MARKER}\n"
        "This prerelease authority is retired without recording completion of its original acceptance criteria.\n\n"
        f"- Successor: {successor_line}\n"
        f"- Reason: {successor['reason']}\n"
        f"- Retired authority: `{organization}/{retired_repository}#{retired_number}`\n"
    )


def _item_labels(item: dict[str, Any]) -> list[str]:
    classification = {
        "blocker": "beta:blocker",
        "compatible": "beta:compatible",
        "post-2.0": "post-2.0",
    }[item["classification"]]
    return sorted(
        {
            "authority:github",
            f"kind:{item['kind']}",
            f"priority:{item['priority']}",
            f"status:{item['status']}",
            classification,
            OWNER_LABELS[item["repository"]],
        }
    )


def _render_unblock_context(item: dict[str, Any]) -> str:
    unblock_condition = item.get("unblock_condition")
    if not unblock_condition:
        return ""
    return f"{UNBLOCK_CONTEXT_START}\n## Unblock condition\n\n{unblock_condition.rstrip()}\n{UNBLOCK_CONTEXT_END}"


def _render_body(
    item: dict[str, Any],
    dependency_urls: Mapping[str, str],
    dependency_titles: Mapping[str, str],
) -> str:
    dependencies = item["depends_on"]
    if dependencies:
        dependency_lines = "\n".join(
            f"- [{dependency_titles[dependency]}]({dependency_urls[dependency]})" for dependency in dependencies
        )
    else:
        dependency_lines = "None."
    required_targets = item.get("required_source_targets")
    target_section = (
        f"\n\n{cross_repository_lifecycle.TARGET_HEADING}\n\n" + "\n".join(required_targets)
        if isinstance(required_targets, list)
        else ""
    )
    unblock_context = _render_unblock_context(item)
    rendered_unblock_context = f"\n\n{unblock_context}" if unblock_context else ""
    return (
        f"{item['body'].rstrip()}"
        f"{target_section}\n\n"
        f"## Dependencies\n\n{dependency_lines}"
        f"{rendered_unblock_context}\n\n"
        f"<!-- beta-work-id: {item['id']} -->\n"
    )


def _marker_is_line_bounded(body: str, marker: str, index: int) -> bool:
    starts_line = index == 0 or body[index - 1] == "\n"
    after = index + len(marker)
    ends_line = after == len(body) or body.startswith(("\n", "\r\n"), after)
    return starts_line and ends_line


def _unblock_context_span(item: dict[str, Any], body: str) -> tuple[int, int] | None:
    start_count = body.count(UNBLOCK_CONTEXT_START)
    end_count = body.count(UNBLOCK_CONTEXT_END)
    if start_count == 0 and end_count == 0:
        return None
    if start_count != 1 or end_count != 1:
        raise AuthorityError(f"GitHub issue for {item['id']} has malformed unblock condition context")

    start = body.index(UNBLOCK_CONTEXT_START)
    end = body.index(UNBLOCK_CONTEXT_END)
    if (
        start >= end
        or not _marker_is_line_bounded(body, UNBLOCK_CONTEXT_START, start)
        or not _marker_is_line_bounded(body, UNBLOCK_CONTEXT_END, end)
    ):
        raise AuthorityError(f"GitHub issue for {item['id']} has malformed unblock condition context")
    return start, end + len(UNBLOCK_CONTEXT_END)


def _reconcile_unblock_context(item: dict[str, Any], issue: dict[str, Any]) -> str | None:
    body = issue.get("body")
    if not isinstance(body, str):
        raise AuthorityError(f"GitHub issue for {item['id']} has no text body")
    context_span = _unblock_context_span(item, body)
    desired = _render_unblock_context(item)
    if context_span is None and not desired:
        return None
    if context_span is not None:
        start, end = context_span
        if desired:
            updated = body[:start] + desired + body[end:]
        else:
            if body[max(0, start - 4) : start] == "\r\n\r\n":
                start -= 4
            elif body[max(0, start - 2) : start] == "\n\n":
                start -= 2
            updated = body[:start] + body[end:]
    else:
        marker = f"<!-- beta-work-id: {item['id']} -->"
        updated = body.replace(marker, f"{desired}\n\n{marker}", 1)
    return updated if updated != body else None


def _plan_unblock_context_updates(
    backlog: dict[str, Any],
    resolved: Mapping[str, tuple[str, dict[str, Any]]],
) -> dict[str, str | None]:
    return {
        item["id"]: _reconcile_unblock_context(item, resolved[item["id"]][1])
        for item in backlog["items"]
        if item["id"] in resolved
    }


def _plan_ready_transition_updates(
    backlog: dict[str, Any],
    resolved: Mapping[str, tuple[str, dict[str, Any]]],
) -> dict[str, list[str] | None]:
    updates: dict[str, list[str] | None] = {}
    for item in backlog["items"]:
        match = resolved.get(item["id"])
        if match is None:
            continue
        issue = match[1]
        body = issue.get("body")
        labels = _label_names(issue)
        is_reviewed_ready_transition = (
            item["status"] == "ready"
            and not item["depends_on"]
            and not item.get("unblock_condition")
            and isinstance(body, str)
            and _unblock_context_span(item, body) is not None
        )
        if (
            is_reviewed_ready_transition
            and issue.get("state") == "open"
            and labels & STATUS_LABELS == {"status:blocked"}
        ):
            replacement = labels - STATUS_LABELS | {"status:ready"}
            updates[item["id"]] = sorted(replacement)
        else:
            updates[item["id"]] = None
    return updates


def _preflight_unblock_context_layouts(
    backlog: dict[str, Any],
    inventory: Mapping[str, Sequence[dict[str, Any]]],
) -> None:
    items = {item["id"]: item for item in backlog["items"]}
    for issues in inventory.values():
        for issue in issues:
            body = issue.get("body")
            if not isinstance(body, str):
                continue
            for work_id in set(MARKER_PATTERN.findall(body)) & items.keys():
                _unblock_context_span(items[work_id], body)


def _inventory(policy: dict[str, Any], client: Any) -> dict[str, list[dict[str, Any]]]:
    organization = policy["organization"]
    return {repository: client.list_issues(organization, repository) for repository in policy["repositories"]}


def sync_metadata(policy: dict[str, Any], client: Any) -> tuple[dict[tuple[str, str], int], dict[str, Any]]:
    organization = policy["organization"]
    evidence: dict[str, Any] = {"labels": {}, "milestones": {}}
    for repository in policy["repositories"]:
        evidence["labels"][repository] = client.ensure_labels(organization, repository, policy["labels"])

    milestone_numbers: dict[tuple[str, str], int] = {}
    for milestone in policy["milestones"]:
        for repository in milestone["repositories"]:
            number, change = client.ensure_milestone(organization, repository, milestone)
            milestone_numbers[(repository, milestone["title"])] = number
            if change:
                evidence["milestones"][f"{repository}/{milestone['title']}"] = change
    return milestone_numbers, evidence


def _marker_index(
    inventory: Mapping[str, Sequence[dict[str, Any]]],
) -> tuple[
    dict[str, list[tuple[str, dict[str, Any]]]],
    list[tuple[str, dict[str, Any], list[str]]],
]:
    markers: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    aliases: list[tuple[str, dict[str, Any], list[str]]] = []
    for repository, issues in inventory.items():
        for issue in issues:
            body = issue.get("body") or ""
            if not isinstance(body, str):
                continue
            ids = MARKER_PATTERN.findall(body)
            consolidated_ids = CONSOLIDATED_FINDING_PATTERN.findall(body)
            if len(ids) != len(set(ids)):
                raise AuthorityError(f"issue {repository}/{issue.get('number')} repeats its beta work marker")
            if len(consolidated_ids) != len(set(consolidated_ids)):
                raise AuthorityError(
                    f"issue {repository}/{issue.get('number')} repeats a consolidated finding marker"
                )
            if set(ids) & set(consolidated_ids):
                raise AuthorityError(
                    f"issue {repository}/{issue.get('number')} repeats one work identity across marker kinds"
                )
            distinct_ids = sorted(set(ids))
            if len(distinct_ids) > 1:
                aliases.append((repository, issue, distinct_ids))
            for work_id in [*ids, *consolidated_ids]:
                markers.setdefault(work_id, []).append((repository, issue))
    return markers, aliases


def _mark_conflicts(policy: dict[str, Any], client: Any, matches: Sequence[tuple[str, dict[str, Any]]]) -> None:
    organization = policy["organization"]
    for repository, issue in matches:
        labels = _label_names(issue) | {"authority:github", "authority:conflict"}
        client.replace_issue_labels(organization, repository, int(issue["number"]), sorted(labels))


def _preflight_markers(
    policy: dict[str, Any],
    backlog: dict[str, Any],
    client: Any,
    inventory: Mapping[str, Sequence[dict[str, Any]]],
    *,
    allow_missing: bool,
) -> dict[str, tuple[str, dict[str, Any]]]:
    selected_ids = {item["id"] for item in backlog["items"]}
    markers, aliases = _marker_index(inventory)
    if aliases:
        failures = [
            f"{repository}#{issue.get('number')} contains multiple distinct beta work ids {work_ids}"
            for repository, issue, work_ids in aliases
        ]
        raise AuthorityError("issue authority marker audit failed: " + "; ".join(failures))
    unknown = set(markers) - selected_ids
    if unknown:
        for work_id in sorted(unknown):
            _mark_conflicts(policy, client, markers[work_id])
        raise AuthorityError(f"GitHub contains beta work ids absent from the reviewed backlog: {sorted(unknown)}")

    resolved: dict[str, tuple[str, dict[str, Any]]] = {}
    failures: list[str] = []
    for work_id in sorted(selected_ids):
        matches = markers.get(work_id, [])
        if len(matches) > 1:
            _mark_conflicts(policy, client, matches)
            failures.append(f"{work_id} appears on {len(matches)} GitHub issues")
        elif matches:
            repository, issue = matches[0]
            expected_repository = next(item["repository"] for item in backlog["items"] if item["id"] == work_id)
            if repository != expected_repository:
                _mark_conflicts(policy, client, matches)
                failures.append(f"{work_id} is in {repository}, expected {expected_repository}")
            else:
                resolved[work_id] = matches[0]
        elif not allow_missing:
            failures.append(f"{work_id} has no GitHub issue")
    if failures:
        raise AuthorityError("issue authority marker audit failed: " + "; ".join(failures))
    return resolved


def _evaluate_frozen_lifecycle(
    client: Any,
    organization: str,
    migration: Mapping[str, Any],
) -> dict[str, Any]:
    """Revalidate exact frozen landing, workflow-run, and check identities."""

    if migration["outcome"] == "missing-evidence":
        return {
            "missing_evidence": migration["missing_evidence"],
            "outcome": "missing-evidence",
            "targets": [],
        }
    targets: list[dict[str, Any]] = []
    for landing in migration["landings"]:
        repository = landing["repository"]
        branch = landing["branch"]
        commit = landing["commit"]
        qualification = landing["qualification"]
        result = {
            "branch": branch,
            "commit": commit,
            "qualification": json.loads(json.dumps(qualification)),
            "repository": repository,
            "state": "pending:landing-not-on-target",
        }
        if not client.commit_reaches_branch(organization, repository, commit, branch):
            targets.append(result)
            continue
        if not client.successful_historical_workflow_run(
            organization,
            repository,
            qualification["run"],
            commit,
            branch,
            qualification["workflow_path"],
            qualification["workflow_name"],
        ):
            result["state"] = "pending:qualification-run"
            targets.append(result)
            continue
        successful_checks = client.successful_historical_workflow_jobs(
            organization,
            repository,
            qualification["run"],
        )
        if any(
            successful_checks.get(check["name"]) != check["job"]
            for check in qualification["checks"]
        ):
            result["state"] = "pending:qualification-check"
            targets.append(result)
            continue
        result["state"] = "complete"
        targets.append(result)
    incomplete = [
        f"{target['repository']}@{target['branch']}={target['state']}"
        for target in targets
        if target["state"] != "complete"
    ]
    return {
        "missing_evidence": (
            "Exact frozen aggregate revalidation failed: " + ", ".join(incomplete)
            if incomplete
            else None
        ),
        "outcome": "missing-evidence" if incomplete else "complete",
        "targets": targets,
    }


def _render_frozen_lifecycle_evidence(
    migration: Mapping[str, Any],
    result: Mapping[str, Any],
) -> str:
    record = {
        "approval": {
            "actor_sha256": migration["approval_actor_sha256"],
            "at": migration["approval_at"],
            "mode": migration["approval_mode"],
        },
        "authority_snapshot_sha256": migration["authority_snapshot_sha256"],
        "completion_source": migration["completion_source"],
        "declared_targets": list(migration["declared_targets"]),
        "missing_evidence": result["missing_evidence"],
        "outcome": result["outcome"],
        "approved_issue_revision_sha256": migration["approved_issue_revision_sha256"],
        "schema": "durable-workflow.frozen-cross-repository-lifecycle/v1",
        "targets": list(result["targets"]),
    }
    return (
        f"{FROZEN_LIFECYCLE_EVIDENCE_MARKER}\n"
        "Historical cross-repository lifecycle result generated by protected Issue Authority.\n\n"
        "```json\n"
        + json.dumps(record, indent=2, sort_keys=True)
        + "\n```\n"
    )


def _audit_state_labels(
    policy: dict[str, Any],
    client: Any,
    inventory: Mapping[str, list[dict[str, Any]]],
    approved_completion_holds: set[tuple[str, int]],
    cross_repository_targets: Mapping[tuple[str, int], Sequence[Mapping[str, Any]]] | None,
    historical_cross_repository_completions: (Mapping[tuple[str, int], Sequence[Mapping[str, Any]]] | None),
    frozen_cross_repository_lifecycles: Mapping[tuple[str, int], Mapping[str, Any]] | None,
    prerelease_supersessions: Mapping[tuple[str, int], Mapping[str, Any]] | None,
) -> list[str]:
    organization = policy["organization"]
    failures: list[str] = []
    trusted_retirements: set[tuple[str, int]] = set()
    retirement_quarantines: set[tuple[str, int]] = set()
    for repository, issues in inventory.items():
        for issue in issues:
            number = issue.get("number")
            if type(number) is not int:
                continue
            identity = (repository, number)
            try:
                if _has_trusted_public_retirement(
                    client,
                    organization,
                    repository,
                    number,
                ):
                    trusted_retirements.add(identity)
            except AuthorityError as error:
                failures.append(f"{repository}#{number} retirement record is malformed: {error}")
                retirement_quarantines.add(identity)

    historical_completion_identities = set(historical_cross_repository_completions or {})
    frozen_results: dict[tuple[str, int], dict[str, Any]] = {}
    for identity, migration in sorted((frozen_cross_repository_lifecycles or {}).items()):
        if identity in trusted_retirements or identity in retirement_quarantines:
            continue
        declared = (cross_repository_targets or {}).get(identity, ())
        declared_contract = sorted(
            f"durable-workflow/{target.get('repository')}@{target.get('branch')}" for target in declared
        )
        if declared_contract != sorted(migration["declared_targets"]):
            raise AuthorityError(
                f"{identity[0]}#{identity[1]} frozen lifecycle evidence differs from its declared target set"
            )
        frozen_results[identity] = _evaluate_frozen_lifecycle(client, organization, migration)
    recorded_landing_results: dict[tuple[str, str, str, tuple[str, ...]], Mapping[str, Any]] = {}
    for identity, landings in sorted((historical_cross_repository_completions or {}).items()):
        if identity in trusted_retirements or identity in retirement_quarantines:
            continue
        declared = (cross_repository_targets or {}).get(identity, ())
        if not declared:
            raise AuthorityError(
                f"{identity[0]}#{identity[1]} has historical completion evidence without a declared target set"
            )
        declared_contract = sorted(
            (
                str(target.get("repository")),
                str(target.get("branch")),
            )
            for target in declared
        )
        landing_contract = sorted(
            (
                str(landing.get("repository")),
                str(landing.get("branch")),
            )
            for landing in landings
        )
        if declared_contract != landing_contract:
            raise AuthorityError(
                f"{identity[0]}#{identity[1]} historical completion evidence differs from its declared target set"
            )
        pending_landings = [
            landing
            for landing in landings
            if (
                str(landing.get("repository")),
                str(landing.get("branch")),
                str(landing.get("commit")),
                tuple(sorted(str(check) for check in landing.get("required_checks", ()))),
            )
            not in recorded_landing_results
        ]
        try:
            if pending_landings:
                assessment = cross_repository_lifecycle.evaluate_recorded_landings(
                    client,
                    organization,
                    pending_landings,
                )
                for landing, result in zip(pending_landings, assessment["targets"], strict=True):
                    key = (
                        str(landing["repository"]),
                        str(landing["branch"]),
                        str(landing["commit"]),
                        tuple(sorted(str(check) for check in landing["required_checks"])),
                    )
                    recorded_landing_results[key] = result
        except cross_repository_lifecycle.LifecycleError as error:
            raise AuthorityError(str(error)) from error
        results = [
            recorded_landing_results[
                (
                    str(landing["repository"]),
                    str(landing["branch"]),
                    str(landing["commit"]),
                    tuple(sorted(str(check) for check in landing["required_checks"])),
                )
            ]
            for landing in landings
        ]
        if any(result["state"] != "complete" for result in results):
            landing_failures = [
                f"{target['repository']}@{target['branch']}={target['state']}"
                for target in results
                if target["state"] != "complete"
            ]
            raise AuthorityError(
                f"{identity[0]}#{identity[1]} historical completion evidence failed revalidation: "
                + ", ".join(landing_failures)
            )

    for repository, issues in inventory.items():
        for issue in issues:
            labels = _label_names(issue)
            number = int(issue["number"])
            location = f"{repository}#{number}"
            identity = (repository, number)
            if identity in retirement_quarantines:
                continue
            trusted_retirement = identity in trusted_retirements
            if "authority:github" not in labels and not trusted_retirement:
                continue
            state = issue.get("state")
            if (
                state == "closed"
                and not trusted_retirement
                and not client.has_managed_lifecycle_comment(
                    organization,
                    repository,
                    number,
                )
            ):
                # Closed history is metadata-only unless this authority already
                # owns a managed lifecycle record for an explicit transition.
                continue
            kinds = _kind_label_names(labels)
            if len(kinds) != 1 or not kinds <= KIND_LABELS:
                failures.append(f"{location} must have exactly one supported kind:* label, got {sorted(kinds)}")
                # A classification choice is maintainer authority. Quarantine
                # this identity without guessing while unrelated issues keep
                # reconciling in the same aggregate run.
                continue
            if trusted_retirement:
                replacement = labels - STATUS_LABELS - COMPLETION_LABELS
                replacement.discard("authority:conflict")
                replacement.update({"authority:github", SUPERSEDED_STATUS_LABEL})
                if replacement != labels:
                    client.replace_issue_labels(
                        organization,
                        repository,
                        number,
                        sorted(replacement),
                    )
                    issue["labels"] = [{"name": label} for label in sorted(replacement)]
                    labels = replacement
                if state != "closed" or issue.get("state_reason") != "not_planned":
                    client.update_issue_state(
                        organization,
                        repository,
                        number,
                        "closed",
                        state_reason="not_planned",
                    )
                    issue["state"] = "closed"
                    issue["state_reason"] = "not_planned"
                if len(labels & PRIORITY_LABELS) != 1:
                    failures.append(f"{location} must have exactly one priority label")
                continue
            statuses = labels & STATUS_LABELS
            open_statuses_before_lifecycle = statuses & OPEN_STATUS_LABELS
            replacement = set(labels)
            aggregated_close = False
            assessment: dict[str, Any] | None = None
            approved_completion_hold = identity in approved_completion_holds
            frozen_migration = (frozen_cross_repository_lifecycles or {}).get(identity)
            frozen_result = frozen_results.get(identity)
            supersession = (prerelease_supersessions or {}).get((repository, number))
            if (
                supersession is None
                and frozen_migration is None
                and approved_completion_hold
                and COMPLETION_REQUIRED_LABEL not in labels
                and COMPLETION_VERIFIED_LABEL not in labels
            ):
                replacement.add(COMPLETION_REQUIRED_LABEL)
                client.replace_issue_labels(organization, repository, number, sorted(replacement))
                issue["labels"] = [{"name": label} for label in sorted(replacement)]
                labels = replacement
                statuses = labels & STATUS_LABELS

            if supersession is not None:
                client.ensure_supersession_activation(
                    organization,
                    ".github",
                    supersession["activation"],
                )
                client.upsert_lifecycle_comment(
                    organization,
                    repository,
                    number,
                    SUPERSESSION_EVIDENCE_MARKER,
                    _render_supersession_evidence(
                        organization,
                        repository,
                        number,
                        supersession,
                    ),
                )
                if state != "closed" or issue.get("state_reason") != "not_planned":
                    client.update_issue_state(
                        organization,
                        repository,
                        number,
                        "closed",
                        state_reason="not_planned",
                    )
                    issue["state"] = "closed"
                    issue["state_reason"] = "not_planned"
                replacement = set(labels) - STATUS_LABELS
                replacement -= COMPLETION_LABELS
                replacement.add(SUPERSEDED_STATUS_LABEL)
                if replacement != labels:
                    client.replace_issue_labels(
                        organization,
                        repository,
                        number,
                        sorted(replacement),
                    )
                    issue["labels"] = [{"name": label} for label in sorted(replacement)]
                    labels = replacement
                if len(labels & KIND_LABELS) != 1:
                    failures.append(f"{location} must have exactly one kind label")
                if len(labels & PRIORITY_LABELS) != 1:
                    failures.append(f"{location} must have exactly one priority label")
                continue

            if frozen_migration is not None:
                if frozen_result is None:
                    raise AuthorityError(f"{location} has no evaluated frozen lifecycle result")
                client.upsert_lifecycle_comment(
                    organization,
                    repository,
                    number,
                    FROZEN_LIFECYCLE_EVIDENCE_MARKER,
                    _render_frozen_lifecycle_evidence(frozen_migration, frozen_result),
                )
                replacement = set(labels) - COMPLETION_LABELS
                replacement.add(
                    COMPLETION_VERIFIED_LABEL
                    if frozen_result["outcome"] == "complete"
                    else COMPLETION_REQUIRED_LABEL
                )
                if replacement != labels:
                    client.replace_issue_labels(organization, repository, number, sorted(replacement))
                    issue["labels"] = [{"name": label} for label in sorted(replacement)]
                    labels = set(replacement)
                    statuses = labels & STATUS_LABELS

            completion_is_pending = COMPLETION_REQUIRED_LABEL in labels and COMPLETION_VERIFIED_LABEL not in labels
            declared_targets = (
                cross_repository_targets.get((repository, number), ()) if cross_repository_targets is not None else ()
            )
            target_contract_is_missing = (
                cross_repository_targets is not None and "kind:cross-repository" in labels and not declared_targets
            )
            target_completion_is_pending = False
            target_contract_failure_reported = False
            if frozen_result is not None:
                target_completion_is_pending = frozen_result["outcome"] != "complete"
            elif (repository, number) in historical_completion_identities:
                target_completion_is_pending = False
            elif declared_targets:
                try:
                    assessment = cross_repository_lifecycle.evaluate_lifecycle(
                        client,
                        organization,
                        repository,
                        issue,
                        declared_targets,
                        trusted_actors=policy["intake"]["trusted_actors"],
                    )
                    client.upsert_lifecycle_comment(
                        organization,
                        repository,
                        number,
                        cross_repository_lifecycle.EVIDENCE_MARKER,
                        cross_repository_lifecycle.render_evidence(assessment),
                    )
                    if assessment["complete"] and not cross_repository_lifecycle.lifecycle_authority_is_current(
                        client,
                        organization,
                        repository,
                        issue,
                        assessment,
                    ):
                        assessment = cross_repository_lifecycle.pending_reference_change(assessment)
                        client.upsert_lifecycle_comment(
                            organization,
                            repository,
                            number,
                            cross_repository_lifecycle.EVIDENCE_MARKER,
                            cross_repository_lifecycle.render_evidence(assessment),
                        )
                except cross_repository_lifecycle.LifecycleError as error:
                    raise AuthorityError(str(error)) from error
                target_completion_is_pending = not assessment["complete"]
            elif target_contract_is_missing:
                target_completion_is_pending = True

            must_remain_open = completion_is_pending or target_completion_is_pending
            if state == "closed" and must_remain_open:
                client.update_issue_state(
                    organization,
                    repository,
                    number,
                    "open",
                    state_reason="reopened",
                )
                issue["state"] = "open"
                issue["state_reason"] = "reopened"
                replacement -= STATUS_LABELS
                previous_open_statuses = statuses & OPEN_STATUS_LABELS
                replacement.update(previous_open_statuses if len(previous_open_statuses) == 1 else {"status:triage"})
                if replacement != labels:
                    client.replace_issue_labels(organization, repository, number, sorted(replacement))
                    issue["labels"] = [{"name": label} for label in sorted(replacement)]
                labels = replacement
                statuses = labels & STATUS_LABELS
                state = "open"
                reason = (
                    "closed without a valid declared target set"
                    if target_contract_is_missing
                    else "closed before every declared target landing and repository qualification completed"
                    if target_completion_is_pending
                    else "closed before its required public completion evidence was verified"
                )
                if frozen_result is None:
                    failures.append(f"{location} {reason}")
                target_contract_failure_reported = target_contract_is_missing
            elif state == "open" and (
                (declared_targets and not must_remain_open)
                or (COMPLETION_VERIFIED_LABEL in labels and not must_remain_open)
            ):
                client.update_issue_state(
                    organization,
                    repository,
                    number,
                    "closed",
                    state_reason="completed",
                )
                issue["state"] = "closed"
                issue["state_reason"] = "completed"
                state = "closed"
                aggregated_close = True
            if target_contract_is_missing and not target_contract_failure_reported:
                failures.append(f"{location} has cross-repository authority without a valid declared target set")

            if state == "closed" and statuses != {"status:done"}:
                replacement -= STATUS_LABELS
                replacement.add("status:done")
                client.replace_issue_labels(organization, repository, number, sorted(replacement))
                issue["labels"] = [{"name": label} for label in sorted(replacement)]
                labels = replacement
                if not aggregated_close and frozen_result is None:
                    failures.append(f"{location} closed state overrode stale lifecycle labels {sorted(statuses)}")
            elif state == "open" and "status:done" in statuses:
                replacement.remove("status:done")
                if not replacement & OPEN_STATUS_LABELS:
                    replacement.add("status:triage")
                client.replace_issue_labels(organization, repository, number, sorted(replacement))
                issue["labels"] = [{"name": label} for label in sorted(replacement)]
                labels = replacement
                if frozen_result is None:
                    failures.append(f"{location} open state overrode stale status:done")
            elif state == "open" and len(statuses & OPEN_STATUS_LABELS) != 1:
                replacement.add("authority:conflict")
                client.replace_issue_labels(organization, repository, number, sorted(replacement))
                issue["labels"] = [{"name": label} for label in sorted(replacement)]
                labels = replacement
                failures.append(f"{location} has ambiguous open lifecycle labels {sorted(statuses)}")

            if (
                assessment is not None
                and assessment["complete"]
                and not cross_repository_lifecycle.lifecycle_authority_is_current(
                    client,
                    organization,
                    repository,
                    issue,
                    assessment,
                )
            ):
                assessment = cross_repository_lifecycle.pending_reference_change(assessment)
                client.upsert_lifecycle_comment(
                    organization,
                    repository,
                    number,
                    cross_repository_lifecycle.EVIDENCE_MARKER,
                    cross_repository_lifecycle.render_evidence(assessment),
                )
                if state == "closed":
                    client.update_issue_state(
                        organization,
                        repository,
                        number,
                        "open",
                        state_reason="reopened",
                    )
                    issue["state"] = "open"
                    issue["state_reason"] = "reopened"
                    state = "open"
                replacement = set(labels) - STATUS_LABELS
                replacement.update(open_statuses_before_lifecycle or {"status:triage"})
                if replacement != labels:
                    client.replace_issue_labels(organization, repository, number, sorted(replacement))
                    issue["labels"] = [{"name": label} for label in sorted(replacement)]
                    labels = replacement
                failures.append(f"{location} closing-reference authority changed during lifecycle mutation")

            if state == "closed" and "state_reason" in issue and issue.get("state_reason") != "completed":
                client.update_issue_state(
                    organization,
                    repository,
                    number,
                    "closed",
                    state_reason="completed",
                )
                issue["state_reason"] = "completed"

            if len(_kind_label_names(labels)) != 1:
                failures.append(f"{location} must have exactly one kind label")
            if len(labels & PRIORITY_LABELS) != 1:
                failures.append(f"{location} must have exactly one priority label")
    return failures


def _audit_migrated_classification(
    backlog: dict[str, Any],
    resolved: Mapping[str, tuple[str, dict[str, Any]]],
) -> list[str]:
    failures: list[str] = []
    for item in backlog["items"]:
        match = resolved.get(item["id"])
        if match is None:
            continue
        repository, issue = match
        labels = _label_names(issue)
        required = {"authority:github", OWNER_LABELS[repository]}
        if not required <= labels:
            failures.append(f"{repository}#{issue['number']} is missing authoritative ownership labels")
        if len(labels & CLASSIFICATION_LABELS) != 1:
            failures.append(f"{repository}#{issue['number']} must have exactly one beta classification")
        milestone = issue.get("milestone")
        if not isinstance(milestone, dict) or milestone.get("title") != backlog["milestone"]:
            failures.append(f"{repository}#{issue['number']} is not assigned to {backlog['milestone']!r}")
    return failures


def _public_blocker_condition(issue: Mapping[str, Any] | None) -> str:
    if issue is None or not isinstance(issue.get("body"), str):
        return "See the public issue for the condition that must change before work can resume."
    body = str(issue["body"])
    if body.count(UNBLOCK_CONTEXT_START) != 1 or body.count(UNBLOCK_CONTEXT_END) != 1:
        return "See the public issue for the condition that must change before work can resume."
    start = body.index(UNBLOCK_CONTEXT_START) + len(UNBLOCK_CONTEXT_START)
    end = body.index(UNBLOCK_CONTEXT_END)
    if start >= end:
        return "See the public issue for the condition that must change before work can resume."
    condition = body[start:end].strip()
    condition = re.sub(r"^##[ \t]+Unblock condition[ \t]*\r?\n+", "", condition).strip()
    if not condition:
        return "See the public issue for the condition that must change before work can resume."
    try:
        _public_safe([condition])
    except AuthorityError:
        return "See the public issue for the condition that must change before work can resume."
    return condition


def _public_lifecycle_state(
    metadata: Mapping[str, Any],
    labels: Collection[str],
) -> str:
    if SUPERSEDED_STATUS_LABEL in labels:
        return "superseded"
    if metadata.get("state") == "closed" or "status:done" in labels:
        return "completed"
    if metadata.get("approved") is not True:
        return "awaiting-maintainer-vetting"
    if "status:blocked" in labels:
        return "blocked"
    if "status:in-progress" in labels:
        return "in-progress"
    return "approved-queued"


def _render_public_lifecycle_comment(
    state: str,
    condition: str | None = None,
    *,
    condition_key: str | None = None,
) -> str:
    headings = {
        "approved-queued": "Approved and queued",
        "awaiting-maintainer-vetting": "Awaiting maintainer vetting",
        "blocked": "Blocked",
        "completed": "Completed",
        "in-progress": "In progress",
        "superseded": "Superseded",
    }
    explanations = {
        "approved-queued": "A maintainer approved the current issue revision and it is queued for product work.",
        "awaiting-maintainer-vetting": "A maintainer has not yet approved the current issue revision.",
        "blocked": "Work cannot advance until the public condition below changes.",
        "completed": "The approved work and its required public completion evidence are complete.",
        "in-progress": "Implementation is actively in progress.",
        "superseded": "A reviewed successor or disposition replaced this work.",
    }
    if state not in headings:
        raise AuthorityError(f"unsupported public lifecycle state {state!r}")
    condition_heading = "Public unblock condition" if state == "blocked" else "Public condition"
    condition_section = f"\n\n**{condition_heading}**\n\n{condition}" if condition else ""
    rendered_condition_key = condition_key or "none"
    return (
        f"{PUBLIC_LIFECYCLE_MARKER}\n"
        f"<!-- durable-workflow-public-lifecycle-state:{state};condition:{rendered_condition_key} -->\n"
        "### Public lifecycle\n\n"
        f"**State:** {headings[state]}\n\n"
        f"{explanations[state]}"
        f"{condition_section}\n"
    )


def reconcile_public_lifecycle(
    policy: Mapping[str, Any],
    client: Any,
    public_metadata: Sequence[dict[str, Any]],
    inventory: Mapping[str, Sequence[dict[str, Any]]],
    *,
    lifecycle_projection: Mapping[tuple[str, int], Mapping[str, Any]] | None = None,
    now: datetime | None = None,
    projection_failures: Sequence[str] = (),
) -> list[str]:
    """Converge labels/comments per issue while quarantining malformed identities."""

    organization = str(policy["organization"])
    lifecycle_policy = policy["lifecycle"]
    state_labels = lifecycle_policy["state_labels"]
    transition_at = (now or datetime.now(UTC)).astimezone(UTC).isoformat().replace("+00:00", "Z")
    projection = lifecycle_projection or {}
    approved_issues = {
        (repository, int(issue["number"])): issue
        for repository, issues in inventory.items()
        for issue in issues
        if type(issue.get("number")) is int
    }
    failures: list[str] = list(projection_failures)
    seen_projection_identities: set[tuple[str, int]] = set()
    for metadata in public_metadata:
        if metadata.get("type") != "issue":
            continue
        repository = metadata.get("repository")
        number = metadata.get("number")
        if not isinstance(repository, str) or type(number) is not int:
            failures.append("public issue metadata has an invalid identity")
            continue
        location = f"{repository}#{number}"
        if metadata.get("quarantined") is True:
            failures.append(f"{location} has quarantined approved intake")
            continue
        issue = approved_issues.get((repository, number))
        if issue is not None:
            metadata["approved"] = True
            metadata["labels"] = sorted(_label_names(issue))
            metadata["state"] = issue.get("state")
            metadata["closed_at"] = issue.get("closed_at")
        labels = set(metadata.get("labels", ()))
        identity = (repository, number)
        projected = projection.get(identity)
        if projected is not None:
            seen_projection_identities.add(identity)
            if metadata.get("approved") is not True:
                failures.append(f"{location} projection does not match approved public intake")
                metadata["reconciliation_failure"] = "projection-not-approved"
                continue

        try:
            trusted_retirement = _has_trusted_public_retirement(
                client,
                organization,
                repository,
                number,
            )
        except AuthorityError as error:
            failures.append(f"{location} retirement record is malformed: {error}")
            metadata["reconciliation_failure"] = "retirement-record"
            continue
        if trusted_retirement:
            kinds = _kind_label_names(labels)
            if len(kinds) != 1 or not kinds <= KIND_LABELS:
                failures.append(f"{location} has malformed kind labels {sorted(kinds)}")
                metadata["reconciliation_failure"] = "malformed-kind-labels"
                continue
            if projected is not None and projected.get("state") != "superseded":
                failures.append(f"{location} projection conflicts with trusted retirement")
                metadata["reconciliation_failure"] = "projection-conflicts-with-retirement"
            replacement = labels - STATUS_LABELS - COMPLETION_LABELS
            replacement.discard("authority:conflict")
            replacement.update({"authority:github", SUPERSEDED_STATUS_LABEL})
            if replacement != labels:
                client.replace_issue_labels(
                    organization,
                    repository,
                    number,
                    sorted(replacement),
                )
                labels = replacement
                metadata["labels"] = sorted(labels)
                if issue is not None:
                    issue["labels"] = [{"name": label} for label in sorted(labels)]
            if metadata.get("state") != "closed" or (issue is not None and issue.get("state_reason") != "not_planned"):
                client.update_issue_state(
                    organization,
                    repository,
                    number,
                    "closed",
                    state_reason="not_planned",
                )
                metadata["state"] = "closed"
                metadata["closed_at"] = transition_at
                if issue is not None:
                    issue["state"] = "closed"
                    issue["state_reason"] = "not_planned"
            metadata["public_state"] = "superseded"
            continue

        if metadata.get("state") == "closed":
            metadata["public_state"] = _public_lifecycle_state(metadata, labels)
            if metadata.get("specialized_lifecycle") is True or projected is None:
                continue
            projected_state = projected.get("state")
            if projected_state not in {"completed", "superseded"}:
                continue
            if not client.has_managed_lifecycle_comment(
                organization,
                repository,
                number,
                PUBLIC_LIFECYCLE_MARKER,
            ):
                continue
            public_state = "completed" if projected_state == "completed" else "superseded"
            metadata["public_state"] = public_state
            try:
                client.upsert_lifecycle_comment(
                    organization,
                    repository,
                    number,
                    PUBLIC_LIFECYCLE_MARKER,
                    _render_public_lifecycle_comment(public_state),
                )
            except AuthorityError as error:
                failures.append(f"{location} lifecycle comment reconciliation failed: {error}")
                metadata["reconciliation_failure"] = "lifecycle-comment"
            continue

        kinds = _kind_label_names(labels)
        if len(kinds) != 1 or not kinds <= KIND_LABELS:
            failures.append(f"{location} has malformed kind labels {sorted(kinds)}")
            metadata["reconciliation_failure"] = "malformed-kind-labels"
            continue
        statuses = labels & STATUS_LABELS
        if len(statuses) > 1:
            failures.append(f"{location} has ambiguous lifecycle labels {sorted(statuses)}")
            metadata["reconciliation_failure"] = "ambiguous-lifecycle-labels"
            continue

        projected_state = projected.get("state") if projected is not None else None
        completion_target_pending = (
            COMPLETION_REQUIRED_LABEL in labels and COMPLETION_VERIFIED_LABEL not in labels
        )
        if projected_state == "completed" and completion_target_pending:
            failures.append(f"{location} verified release completion is waiting on required target evidence")
            metadata["reconciliation_failure"] = "required-target-evidence"
            projected_state = "integrated"
        desired_state = None
        if projected_state == "completed" or (
            projected is None
            and metadata.get("approved") is True
            and COMPLETION_VERIFIED_LABEL in labels
        ):
            desired_state = "completed"
        elif projected_state == "superseded":
            desired_state = "superseded"

        effective_transition_at = str(projected.get("transition_at")) if projected is not None else transition_at
        if desired_state in {"completed", "superseded"}:
            state_reason = "completed" if desired_state == "completed" else "not_planned"
            client.update_issue_state(
                organization,
                repository,
                number,
                "closed",
                state_reason=state_reason,
            )
            metadata["state"] = "closed"
            metadata["closed_at"] = transition_at
            metadata["last_transition_at"] = effective_transition_at

        if desired_state == "completed":
            desired_status = state_labels["completed"]
        elif desired_state == "superseded":
            desired_status = SUPERSEDED_STATUS_LABEL
        elif metadata.get("approved") is not True:
            desired_status = state_labels["awaiting-maintainer-vetting"]
        elif projected_state in {"blocked", "failed"} or (
            projected is None and "status:blocked" in statuses
        ):
            desired_status = state_labels["blocked"]
        elif projected_state in {"built", "claimed", "integrated", "integrating"} or (
            projected is None and "status:in-progress" in statuses
        ):
            desired_status = state_labels["in-progress"]
        else:
            desired_status = state_labels["approved-queued"]

        replacement = labels - STATUS_LABELS | {desired_status}
        if projected is not None:
            # A unique authenticated projection, a non-duplicated managed
            # lifecycle record, and unambiguous kind/status labels prove that
            # an older authority conflict has been resolved.
            replacement.discard("authority:conflict")
        if desired_state == "completed":
            replacement -= COMPLETION_LABELS
            replacement.add(COMPLETION_VERIFIED_LABEL)
        elif desired_state == "superseded":
            replacement -= COMPLETION_LABELS
        status_changed = statuses != {desired_status}
        if metadata.get("approved") is True:
            replacement.add("authority:github")
        if replacement != labels:
            client.replace_issue_labels(organization, repository, number, sorted(replacement))
            labels = replacement
            metadata["labels"] = sorted(labels)
            if status_changed:
                metadata["last_transition_at"] = effective_transition_at
                metadata.setdefault("label_transition_at", {})[desired_status] = effective_transition_at
            if issue is not None:
                issue["labels"] = [{"name": label} for label in sorted(labels)]

        public_state = _public_lifecycle_state(metadata, labels)
        metadata["public_state"] = public_state
        if metadata.get("specialized_lifecycle") is True:
            continue
        if projected is not None and projected.get("public_condition") is not None:
            public_condition = str(projected["public_condition"])
            condition = PUBLIC_CONDITIONS[public_condition]
            condition_key = f"projection:{public_condition}"
        else:
            condition = _public_blocker_condition(issue) if public_state == "blocked" else None
            condition_key = (
                f"public-text:{hashlib.sha256(condition.encode('utf-8')).hexdigest()[:16]}"
                if condition is not None
                else None
            )
        try:
            existing_comment = client.managed_lifecycle_comment_body(
                organization,
                repository,
                number,
                PUBLIC_LIFECYCLE_MARKER,
            )
            if (
                projected is None
                and existing_comment is not None
                and f"lifecycle-state:{public_state};condition:projection:" in existing_comment
            ):
                continue
            client.upsert_lifecycle_comment(
                organization,
                repository,
                number,
                PUBLIC_LIFECYCLE_MARKER,
                _render_public_lifecycle_comment(
                    public_state,
                    condition,
                    condition_key=condition_key,
                ),
            )
        except AuthorityError as error:
            failures.append(f"{location} lifecycle comment reconciliation failed: {error}")
            metadata["reconciliation_failure"] = "lifecycle-comment"
    for repository, number in sorted(set(projection) - seen_projection_identities):
        failures.append(f"{repository}#{number} projection does not match admitted public issue metadata")
    return failures


def _verified_release_completions(
    projection: Mapping[tuple[str, int], Mapping[str, Any]],
) -> dict[tuple[str, int], Mapping[str, Any]]:
    """Select only source-bound release completions for the pre-intake writer."""

    return {
        identity: record
        for identity, record in projection.items()
        if (
            record.get("state") == "completed"
            and record.get("completion_evidence") == "verified"
            and isinstance(record.get("implementation_source"), str)
            and isinstance(record.get("verified_release"), Mapping)
        )
    }


def reconcile_verified_releases_before_intake(
    policy: Mapping[str, Any],
    client: Any,
    public_metadata: Sequence[dict[str, Any]],
    lifecycle_projection: Mapping[tuple[str, int], Mapping[str, Any]],
    *,
    now: datetime | None = None,
    projection_failures: Sequence[str] = (),
) -> dict[str, Any]:
    """Close verified release completions before intake can bind or reserve them."""

    release_completions = _verified_release_completions(lifecycle_projection)
    selected_metadata = [
        metadata
        for metadata in public_metadata
        if (
            metadata.get("type") == "issue"
            and (metadata.get("repository"), metadata.get("number")) in release_completions
        )
    ]
    inventory: dict[str, list[dict[str, Any]]] = {
        str(repository): [] for repository in policy["repositories"]
    }
    for metadata in selected_metadata:
        if metadata.get("approved") is not True:
            continue
        repository = str(metadata["repository"])
        inventory[repository].append(
            {
                "closed_at": metadata.get("closed_at"),
                "labels": [{"name": label} for label in metadata.get("labels", [])],
                "number": int(metadata["number"]),
                "state": metadata.get("state"),
                "state_reason": None,
            }
        )
    failures = reconcile_public_lifecycle(
        policy,
        client,
        selected_metadata,
        inventory,
        lifecycle_projection=release_completions,
        now=now,
        projection_failures=projection_failures,
    )
    terminal_identities = sorted(
        f"{metadata['repository']}#{metadata['number']}"
        for metadata in selected_metadata
        if (
            metadata.get("state") == "closed"
            and set(metadata.get("labels", ())) & STATUS_LABELS == {"status:done"}
            and COMPLETION_VERIFIED_LABEL in set(metadata.get("labels", ()))
        )
    )
    return {
        "failures": list(failures),
        "mode": "pre-intake-release-completion",
        "outcome": "fail" if failures else "pass",
        "release_completion_count": len(release_completions),
        "schema": "durable-workflow.github-issue-authority-evidence/v1",
        "terminal_identities": terminal_identities,
    }


def build_public_age_audit(
    policy: Mapping[str, Any],
    public_metadata: Sequence[Mapping[str, Any]],
    reconciliation_failures: Sequence[str],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build a metadata-only, public-safe age artifact with issues and PRs separate."""

    audited_at = (now or datetime.now(UTC)).astimezone(UTC)
    lifecycle_policy = policy["lifecycle"]
    approved_state_seconds = int(lifecycle_policy["approved_state_seconds"])
    audit_interval_seconds = int(lifecycle_policy["audit_interval_seconds"])
    closure_seconds = int(lifecycle_policy["completed_issue_closure_seconds"])
    creation_stale_seconds = int(lifecycle_policy["creation_stale_age_seconds"])
    maximum_open_actionable = int(lifecycle_policy["max_open_actionable_per_repository"])
    priority_escalation_seconds = int(lifecycle_policy["priority_escalation_seconds"])
    product_owner_alert_seconds = int(lifecycle_policy["product_owner_alert_seconds"])
    triage_seconds = int(lifecycle_policy["maintainer_vetting_seconds"])
    stale_transition_seconds = int(lifecycle_policy["stale_approved_transition_seconds"])
    unattended_seconds = int(lifecycle_policy["unattended_placeholder_seconds"])
    repositories: dict[str, dict[str, Any]] = {}
    age_bucket_template = {"under-24h": 0, "24h-to-72h": 0, "72h-to-7d": 0, "over-7d": 0}

    def empty_bucket() -> dict[str, Any]:
        return {
            "age_buckets": dict(age_bucket_template),
            "actionable_open_count": 0,
            "closed_count": 0,
            "counts_by_state": {},
            "creation_suppressed": False,
            "oldest_age_seconds": 0,
            "oldest_open_created_age_seconds": 0,
            "open_count": 0,
            "over_budget": False,
            "stale_identities": [],
            "total_count": 0,
        }

    totals = {
        "issues": empty_bucket(),
        "pull_requests": empty_bucket(),
    }
    for repository in policy["repositories"]:
        repositories[str(repository)] = {
            "issues": empty_bucket(),
            "pull_requests": empty_bucket(),
        }

    metadata_failures: list[str] = []
    actionable_records: dict[str, list[dict[str, Any]]] = {
        str(repository): [] for repository in policy["repositories"]
    }
    open_issue_created_ages: dict[str, list[int]] = {
        str(repository): [] for repository in policy["repositories"]
    }
    external_intake: list[dict[str, Any]] = []
    notification_crossings: list[dict[str, Any]] = []
    for record in public_metadata:
        repository = record.get("repository")
        number = record.get("number")
        record_type = record.get("type")
        if repository not in repositories or type(number) is not int or record_type not in {"issue", "pull_request"}:
            metadata_failures.append("public age audit encountered an invalid metadata identity")
            continue
        bucket_name = "issues" if record_type == "issue" else "pull_requests"
        bucket = repositories[str(repository)][bucket_name]
        total_bucket = totals[bucket_name]
        if record_type == "issue":
            labels = set(record.get("labels", ()))
            state = str(record.get("public_state") or _public_lifecycle_state(record, labels))
            transition_value = record.get("last_transition_at") or record.get("created_at")
        else:
            state = "merged" if record.get("merged_at") else str(record.get("state", "unknown"))
            transition_value = (
                record.get("merged_at")
                or record.get("closed_at")
                or record.get("updated_at")
                or record.get("created_at")
            )
        try:
            transition = _parse_timestamp(transition_value, f"{record_type} age timestamp").astimezone(UTC)
        except AuthorityError as error:
            metadata_failures.append(f"{repository}#{number} has invalid age metadata: {error}")
            continue
        age_seconds = max(0, int((audited_at - transition).total_seconds()))
        created_age_seconds = age_seconds
        if record_type == "issue":
            try:
                created_at = _parse_timestamp(record.get("created_at"), "issue creation timestamp").astimezone(UTC)
                created_age_seconds = max(0, int((audited_at - created_at).total_seconds()))
            except AuthorityError:
                created_age_seconds = age_seconds
        age_bucket = (
            "under-24h"
            if age_seconds < 24 * 3600
            else "24h-to-72h"
            if age_seconds < 72 * 3600
            else "72h-to-7d"
            if age_seconds < 7 * 24 * 3600
            else "over-7d"
        )
        for current in (bucket, total_bucket):
            counts = current["counts_by_state"]
            counts[state] = counts.get(state, 0) + 1
            current["oldest_age_seconds"] = max(current["oldest_age_seconds"], age_seconds)
            current["age_buckets"][age_bucket] += 1
            current["total_count"] += 1
            if record.get("state") == "open":
                current["open_count"] += 1
                current["oldest_open_created_age_seconds"] = max(
                    current["oldest_open_created_age_seconds"],
                    created_age_seconds,
                )
            else:
                current["closed_count"] += 1

        stale: list[dict[str, Any]] = []
        identity = f"{repository}#{number}"
        if record_type == "issue":
            labels = set(record.get("labels", ()))
            if record.get("state") == "open":
                open_issue_created_ages[str(repository)].append(created_age_seconds)
            if record.get("state") == "open" and record.get("approved") is True:
                priority = next((label for label in PRIORITY_LABELS if label in labels), "priority:untriaged")
                actionable_record = {
                    "age_seconds": created_age_seconds,
                    "identity": identity,
                    "kind": next((label for label in KIND_LABELS if label in labels), None),
                    "priority": priority,
                    "repository": str(repository),
                    "state": state,
                }
                actionable_records[str(repository)].append(actionable_record)
                bucket["actionable_open_count"] += 1
                total_bucket["actionable_open_count"] += 1
            elif record.get("state") == "open" and record.get("approved") is not True:
                external_intake.append(
                    {
                        "age_seconds": created_age_seconds,
                        "identity": identity,
                        "kind": next((label for label in KIND_LABELS if label in labels), None),
                        "repository": str(repository),
                    }
                )
            if (
                record.get("state") == "open"
                and record.get("approved") is True
                and age_seconds >= stale_transition_seconds
            ):
                stale.append(
                    {
                        "age_seconds": age_seconds,
                        "identity": identity,
                        "target": (
                            "stale-blocker-72h"
                            if state == "blocked"
                            else "approved-transition-72h"
                        ),
                    }
                )
            if (
                record.get("state") == "open"
                and record.get("approved") is True
                and created_age_seconds >= product_owner_alert_seconds
            ):
                stale.append(
                    {
                        "age_seconds": created_age_seconds,
                        "identity": identity,
                        "target": "product-owner-alert-7d",
                    }
                )
                if created_age_seconds < product_owner_alert_seconds + audit_interval_seconds:
                    notification_crossings.append(
                        {"identity": identity, "target": "product-owner-alert-7d"}
                    )
            if (
                record.get("state") == "open"
                and record.get("approved") is True
                and created_age_seconds >= unattended_seconds
            ):
                unattended_target = "blocker-review-14d" if state == "blocked" else "unattended-placeholder-14d"
                stale.append(
                    {
                        "age_seconds": created_age_seconds,
                        "identity": identity,
                        "target": unattended_target,
                    }
                )
                if created_age_seconds < unattended_seconds + audit_interval_seconds:
                    notification_crossings.append({"identity": identity, "target": unattended_target})
            if (
                record.get("state") == "open"
                and record.get("approved") is True
                and (
                    len(labels & STATUS_LABELS) != 1
                    or record.get("reconciliation_failure") is not None
                )
                and age_seconds >= approved_state_seconds
            ):
                stale.append({"age_seconds": age_seconds, "identity": identity, "target": "approved-state-24h"})
            if (
                record.get("state") == "open"
                and record.get("approved") is not True
                and "status:triage" not in labels
                and age_seconds >= triage_seconds
            ):
                stale.append({"age_seconds": age_seconds, "identity": identity, "target": "triage-visibility-24h"})
            if record.get("state") == "open" and COMPLETION_VERIFIED_LABEL in labels:
                verified_at = record.get("label_transition_at", {}).get(COMPLETION_VERIFIED_LABEL)
                try:
                    verified_timestamp = _parse_timestamp(verified_at, "completion verification timestamp")
                    verified_age = int(
                        (audited_at - verified_timestamp).total_seconds()
                    )
                except AuthorityError:
                    verified_age = age_seconds
                if verified_age >= closure_seconds:
                    stale.append(
                        {"age_seconds": verified_age, "identity": identity, "target": "verified-closure-15m"}
                    )
        bucket["stale_identities"].extend(stale)
        total_bucket["stale_identities"].extend(stale)

    priority_order = ["priority:P0", "priority:P1", "priority:P2", "priority:P3", "priority:untriaged"]
    claim_order: list[dict[str, Any]] = []
    over_budget_repositories: list[str] = []
    for repository, records in actionable_records.items():
        issue_bucket = repositories[repository]["issues"]
        oldest_created_age = max(open_issue_created_ages[repository], default=0)
        creation_suppressed = (
            len(records) >= maximum_open_actionable or oldest_created_age >= creation_stale_seconds
        )
        over_budget = len(records) > maximum_open_actionable or oldest_created_age >= creation_stale_seconds
        issue_bucket["creation_suppressed"] = creation_suppressed
        issue_bucket["over_budget"] = over_budget
        if over_budget:
            over_budget_repositories.append(repository)
        if (
            len(records) == maximum_open_actionable
            and records
            and min(int(record["age_seconds"]) for record in records) < audit_interval_seconds
        ):
            notification_crossings.append(
                {"identity": repository, "target": "open-actionable-budget"}
            )
        for record in records:
            if record["state"] != "approved-queued":
                continue
            priority_index = priority_order.index(str(record["priority"]))
            escalated = int(record["age_seconds"]) >= priority_escalation_seconds
            effective_index = max(0, priority_index - 1) if escalated else priority_index
            claim_order.append(
                {
                    "age_escalated": escalated,
                    "age_seconds": int(record["age_seconds"]),
                    "effective_priority": priority_order[effective_index],
                    "identity": record["identity"],
                    "priority": record["priority"],
                }
            )
    claim_order.sort(
        key=lambda record: (
            priority_order.index(str(record["effective_priority"])),
            -int(record["age_seconds"]),
            str(record["identity"]),
        )
    )
    totals["issues"]["creation_suppressed"] = any(
        repositories[repository]["issues"]["creation_suppressed"] for repository in repositories
    )
    totals["issues"]["over_budget"] = bool(over_budget_repositories)

    deduplication_candidates: list[dict[str, Any]] = []
    for intake in external_intake:
        roots = [
            record
            for record in actionable_records[intake["repository"]]
            if intake["kind"] is not None and record["kind"] == intake["kind"]
        ]
        deduplication_candidates.append(
            {
                "identity": intake["identity"],
                "root": max(roots, key=lambda record: int(record["age_seconds"]))["identity"] if roots else None,
                "triage_exempt_from_creation_budget": True,
            }
        )

    notification_crossings = sorted(
        {json.dumps(record, sort_keys=True) for record in notification_crossings}
    )
    notification_records = [json.loads(record) for record in notification_crossings]
    notification_digest = hashlib.sha256(
        json.dumps(notification_records, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    pipeline_health = {
        "claim_order": claim_order,
        "deduplication_candidates": deduplication_candidates,
        "dm_notification": {
            "dedupe_key": f"public-issue-lifecycle:{notification_digest}",
            "required": bool(notification_records),
            "threshold_crossings": notification_records,
        },
        "open_count_by_repository": {
            repository: repositories[repository]["issues"]["open_count"]
            for repository in repositories
        },
        "oldest_open_created_age_seconds": totals["issues"]["oldest_open_created_age_seconds"],
        "over_budget_repositories": sorted(over_budget_repositories),
        "schema": "durable-workflow.public-issue-lifecycle-health/v1",
        "status_distribution": dict(totals["issues"]["counts_by_state"]),
    }

    failures = [*reconciliation_failures, *metadata_failures]
    stale_count = sum(len(totals[bucket]["stale_identities"]) for bucket in ("issues", "pull_requests"))
    return {
        "schema": "durable-workflow.public-issue-age-audit/v1",
        "audited_at": audited_at.isoformat().replace("+00:00", "Z"),
        "outcome": "fail" if failures else "attention-required" if stale_count else "pass",
        "operational_targets_seconds": {
            "audit_interval": audit_interval_seconds,
            "approved_state": approved_state_seconds,
            "completed_issue_closure": closure_seconds,
            "creation_stale_age": creation_stale_seconds,
            "maintainer_vetting": triage_seconds,
            "priority_escalation": priority_escalation_seconds,
            "product_owner_alert": product_owner_alert_seconds,
            "stale_approved_transition": stale_transition_seconds,
            "unattended_placeholder": unattended_seconds,
        },
        "pipeline_health": pipeline_health,
        "repositories": repositories,
        "reconciliation_failures": list(failures),
        "stale_identity_count": stale_count,
        "summary": totals,
    }


def _issue_sweep_evidence(
    policy: Mapping[str, Any],
    before: Mapping[str, Any],
    after: Mapping[str, Any],
    reconciliation_failures: Sequence[str],
) -> dict[str, Any]:
    return {
        "schema": "durable-workflow.public-issue-lifecycle-sweep/v1",
        "before": dict(before["summary"]["issues"]),
        "after": dict(after["summary"]["issues"]),
        "repositories": {
            repository: {
                "before": dict(before["repositories"][repository]["issues"]),
                "after": dict(after["repositories"][repository]["issues"]),
            }
            for repository in policy["repositories"]
        },
        "reconciliation_failures": list(reconciliation_failures),
    }


def _issue_created_at(issue: Mapping[str, Any]) -> datetime | None:
    value = issue.get("created_at") or issue.get("createdAt")
    if value is None:
        return None
    try:
        return _parse_timestamp(value, "public issue creation timestamp").astimezone(UTC)
    except AuthorityError:
        return None


def _is_open_actionable_issue(issue: Mapping[str, Any]) -> bool:
    labels = _label_names(dict(issue))
    return (
        issue.get("state") == "open"
        and "pull_request" not in issue
        and "authority:github" in labels
        and not labels & {"status:done", SUPERSEDED_STATUS_LABEL}
    )


def _creation_budget(
    policy: Mapping[str, Any],
    issues: Sequence[dict[str, Any]],
    item: Mapping[str, Any],
    *,
    now: datetime,
    public_metadata: Sequence[Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    lifecycle = policy["lifecycle"]
    maximum = int(lifecycle["max_open_actionable_per_repository"])
    stale_seconds = int(lifecycle["creation_stale_age_seconds"])
    open_issues = [
        issue
        for issue in issues
        if issue.get("state") == "open" and "pull_request" not in issue
    ]
    actionable = [issue for issue in open_issues if _is_open_actionable_issue(issue)]

    def oldest_key(issue: Mapping[str, Any]) -> tuple[datetime, int]:
        return (
            _issue_created_at(issue) or datetime.max.replace(tzinfo=UTC),
            int(issue.get("number")) if type(issue.get("number")) is int else 2**63 - 1,
        )

    creation_times = [
        created_at
        for issue in open_issues
        if (created_at := _issue_created_at(issue)) is not None
    ]
    for record in public_metadata or ():
        if (
            record.get("repository") != item["repository"]
            or record.get("type") != "issue"
            or record.get("state") != "open"
        ):
            continue
        try:
            creation_times.append(
                _parse_timestamp(record.get("created_at"), "public issue creation timestamp").astimezone(UTC)
            )
        except AuthorityError:
            continue
    oldest_created_at = min(creation_times) if creation_times else None
    oldest_age_seconds = max(0, int((now - oldest_created_at).total_seconds())) if oldest_created_at else 0
    reasons: list[str] = []
    if len(actionable) >= maximum:
        reasons.append("open-actionable-budget")
    if oldest_age_seconds >= stale_seconds:
        reasons.append("open-issue-older-than-7d")

    required_labels = set(_item_labels(dict(item)))
    required_kind = next(label for label in required_labels if label.startswith("kind:"))
    required_classification = next(label for label in required_labels if label in CLASSIFICATION_LABELS)
    applicable = [
        issue
        for issue in actionable
        if {required_kind, required_classification} <= _label_names(issue)
        and isinstance(issue.get("body"), str)
        and type(issue.get("number")) is int
    ]
    root = min(applicable, key=oldest_key) if applicable else None
    return {
        "blocked": bool(reasons),
        "oldest_age_seconds": oldest_age_seconds,
        "open_actionable_count": len(actionable),
        "reasons": reasons,
        "root": root,
    }


def _consolidate_backlog_finding(item: Mapping[str, Any], root: Mapping[str, Any]) -> str | None:
    body = root.get("body")
    if not isinstance(body, str):
        raise AuthorityError(f"consolidation root for {item['id']} has no public body")
    marker = f"<!-- durable-workflow-consolidated-finding: {item['id']} -->"
    if marker in body:
        return None
    finding = (
        f"## Consolidated finding: {item['title']}\n\n"
        f"{str(item['body']).strip()}\n\n"
        f"{marker}\n"
    )
    return f"{body.rstrip()}\n\n{finding}"


def apply_backlog(
    policy: dict[str, Any],
    backlog: dict[str, Any],
    client: Any,
    *,
    inventory: dict[str, list[dict[str, Any]]] | None = None,
    approved_completion_holds: set[tuple[str, int]] | None = None,
    cross_repository_targets: Mapping[tuple[str, int], Sequence[Mapping[str, Any]]] | None = None,
    historical_cross_repository_completions: (Mapping[tuple[str, int], Sequence[Mapping[str, Any]]] | None) = None,
    frozen_cross_repository_lifecycles: Mapping[tuple[str, int], Mapping[str, Any]] | None = None,
    lifecycle_projection: Mapping[tuple[str, int], Mapping[str, Any]] | None = None,
    lifecycle_projection_failures: Sequence[str] = (),
    prerelease_supersessions: Mapping[tuple[str, int], Mapping[str, Any]] | None = None,
    public_metadata: list[dict[str, Any]] | None = None,
    audit_time: datetime | None = None,
) -> dict[str, Any]:
    organization = policy["organization"]
    inventory = inventory if inventory is not None else _inventory(policy, client)
    effective_audit_time = audit_time or datetime.now(UTC)
    before_age_audit = (
        build_public_age_audit(policy, public_metadata, [], now=effective_audit_time)
        if public_metadata is not None
        else None
    )
    resolved = _preflight_markers(policy, backlog, client, inventory, allow_missing=True)
    _preflight_unblock_context_layouts(backlog, inventory)
    planned_body_updates = _plan_unblock_context_updates(backlog, resolved)
    planned_ready_transitions = _plan_ready_transition_updates(backlog, resolved)
    milestone_numbers, metadata_evidence = sync_metadata(policy, client)
    dependency_urls = {
        work_id: _issue_url(issue, organization, repository) for work_id, (repository, issue) in resolved.items()
    }
    dependency_titles = {item["id"]: item["title"] for item in backlog["items"]}
    issue_evidence: dict[str, Any] = {}

    for item in backlog["items"]:
        if item["id"] in resolved:
            repository, issue = resolved[item["id"]]
            updated_body = planned_body_updates[item["id"]]
            updated_labels = planned_ready_transitions[item["id"]]
            if updated_labels is not None:
                client.replace_issue_labels(
                    organization,
                    repository,
                    int(issue["number"]),
                    updated_labels,
                )
                issue["labels"] = [{"name": label} for label in updated_labels]
            if updated_body is not None:
                client.update_issue_body(
                    organization,
                    repository,
                    int(issue["number"]),
                    updated_body,
                )
                issue["body"] = updated_body
            issue_evidence[item["id"]] = {
                "action": (
                    "transitioned-to-ready"
                    if updated_labels is not None
                    else "updated-blocker-context"
                    if updated_body is not None
                    else "preserved"
                ),
                "state": issue.get("state"),
                "url": _issue_url(issue, organization, repository),
            }
            continue
        budget = _creation_budget(
            policy,
            inventory[item["repository"]],
            item,
            now=effective_audit_time,
            public_metadata=public_metadata,
        )
        if budget["blocked"]:
            root = budget["root"]
            if isinstance(root, Mapping):
                updated_body = _consolidate_backlog_finding(item, root)
                if updated_body is not None:
                    client.update_issue_body(
                        organization,
                        item["repository"],
                        int(root["number"]),
                        updated_body,
                    )
                    root["body"] = updated_body
                resolved[item["id"]] = (item["repository"], root)
                dependency_urls[item["id"]] = _issue_url(root, organization, item["repository"])
                issue_evidence[item["id"]] = {
                    "action": "consolidated" if updated_body is not None else "preserved-consolidation",
                    "budget_reasons": list(budget["reasons"]),
                    "state": root.get("state"),
                    "url": dependency_urls[item["id"]],
                }
            else:
                issue_evidence[item["id"]] = {
                    "action": "retained-private-audit",
                    "budget_reasons": list(budget["reasons"]),
                    "open_actionable_count": int(budget["open_actionable_count"]),
                }
            continue
        unresolved_dependencies = [dependency for dependency in item["depends_on"] if dependency not in dependency_urls]
        if unresolved_dependencies:
            issue_evidence[item["id"]] = {
                "action": "retained-private-audit",
                "budget_reasons": ["dependency-was-not-publicly-routed"],
            }
            continue
        dependency_urls_for_item = {dependency: dependency_urls[dependency] for dependency in item["depends_on"]}
        issue = client.create_issue(
            organization,
            item["repository"],
            title=item["title"],
            body=_render_body(item, dependency_urls_for_item, dependency_titles),
            labels=_item_labels(item),
            milestone=milestone_numbers[(item["repository"], backlog["milestone"])],
        )
        inventory[item["repository"]].append(issue)
        dependency_urls[item["id"]] = _issue_url(issue, organization, item["repository"])
        resolved[item["id"]] = (item["repository"], issue)
        issue_evidence[item["id"]] = {
            "action": "created",
            "state": issue.get("state"),
            "url": dependency_urls[item["id"]],
        }

    failures = _audit_state_labels(
        policy,
        client,
        inventory,
        approved_completion_holds or set(),
        cross_repository_targets,
        historical_cross_repository_completions,
        frozen_cross_repository_lifecycles,
        prerelease_supersessions,
    )
    failures.extend(_audit_migrated_classification(backlog, resolved))
    if public_metadata is not None:
        failures.extend(
            reconcile_public_lifecycle(
                policy,
                client,
                public_metadata,
                inventory,
                lifecycle_projection=lifecycle_projection,
                now=effective_audit_time,
                projection_failures=lifecycle_projection_failures,
            )
        )
    evidence = {
        "schema": "durable-workflow.github-issue-authority-evidence/v1",
        "mode": "apply",
        "outcome": "fail" if failures else "pass",
        "metadata": metadata_evidence,
        "issues": issue_evidence,
        "prerelease_supersessions": _supersession_evidence(
            policy["organization"],
            prerelease_supersessions,
        ),
    }
    if public_metadata is not None:
        after_age_audit = build_public_age_audit(
            policy,
            public_metadata,
            failures,
            now=effective_audit_time,
        )
        evidence["age_audit"] = after_age_audit
        assert before_age_audit is not None
        evidence["issue_sweep"] = _issue_sweep_evidence(
            policy,
            before_age_audit,
            after_age_audit,
            failures,
        )
    if failures:
        raise LifecycleAuditError(
            "GitHub issue state drift was corrected or flagged: " + "; ".join(failures),
            evidence,
        )
    return evidence


def audit_backlog(
    policy: dict[str, Any],
    backlog: dict[str, Any],
    client: Any,
    *,
    inventory: dict[str, list[dict[str, Any]]] | None = None,
    approved_completion_holds: set[tuple[str, int]] | None = None,
    cross_repository_targets: Mapping[tuple[str, int], Sequence[Mapping[str, Any]]] | None = None,
    historical_cross_repository_completions: (Mapping[tuple[str, int], Sequence[Mapping[str, Any]]] | None) = None,
    frozen_cross_repository_lifecycles: Mapping[tuple[str, int], Mapping[str, Any]] | None = None,
    lifecycle_projection: Mapping[tuple[str, int], Mapping[str, Any]] | None = None,
    lifecycle_projection_failures: Sequence[str] = (),
    prerelease_supersessions: Mapping[tuple[str, int], Mapping[str, Any]] | None = None,
    public_metadata: list[dict[str, Any]] | None = None,
    audit_time: datetime | None = None,
) -> dict[str, Any]:
    inventory = inventory if inventory is not None else _inventory(policy, client)
    effective_audit_time = audit_time or datetime.now(UTC)
    before_age_audit = (
        build_public_age_audit(policy, public_metadata, [], now=effective_audit_time)
        if public_metadata is not None
        else None
    )
    resolved = _preflight_markers(policy, backlog, client, inventory, allow_missing=True)
    budget_deferrals: dict[str, dict[str, Any]] = {}
    missing_failures: list[str] = []
    for item in backlog["items"]:
        if item["id"] in resolved:
            continue
        budget = _creation_budget(
            policy,
            inventory[item["repository"]],
            item,
            now=effective_audit_time,
            public_metadata=public_metadata,
        )
        if not budget["blocked"]:
            missing_failures.append(f"{item['id']} has no GitHub issue")
            continue
        root = budget["root"]
        budget_deferrals[item["id"]] = {
            "action": "awaiting-consolidation" if isinstance(root, Mapping) else "retained-private-audit",
            "budget_reasons": list(budget["reasons"]),
            "open_actionable_count": int(budget["open_actionable_count"]),
            **(
                {"url": _issue_url(root, policy["organization"], item["repository"])}
                if isinstance(root, Mapping)
                else {}
            ),
        }
    if missing_failures:
        raise AuthorityError("issue authority marker audit failed: " + "; ".join(missing_failures))
    _preflight_unblock_context_layouts(backlog, inventory)
    _plan_unblock_context_updates(backlog, resolved)
    _milestones, metadata_evidence = sync_metadata(policy, client)
    failures = _audit_state_labels(
        policy,
        client,
        inventory,
        approved_completion_holds or set(),
        cross_repository_targets,
        historical_cross_repository_completions,
        frozen_cross_repository_lifecycles,
        prerelease_supersessions,
    )
    failures.extend(_audit_migrated_classification(backlog, resolved))
    if public_metadata is not None:
        failures.extend(
            reconcile_public_lifecycle(
                policy,
                client,
                public_metadata,
                inventory,
                lifecycle_projection=lifecycle_projection,
                now=effective_audit_time,
                projection_failures=lifecycle_projection_failures,
            )
        )
    organization = policy["organization"]
    evidence = {
        "schema": "durable-workflow.github-issue-authority-evidence/v1",
        "mode": "audit",
        "outcome": "fail" if failures else "pass",
        "metadata": metadata_evidence,
        "prerelease_supersessions": _supersession_evidence(
            organization,
            prerelease_supersessions,
        ),
        "issues": {
            work_id: {
                "state": issue.get("state"),
                "url": _issue_url(issue, organization, repository),
            }
            for work_id, (repository, issue) in sorted(resolved.items())
        }
        | budget_deferrals,
    }
    if public_metadata is not None:
        after_age_audit = build_public_age_audit(
            policy,
            public_metadata,
            failures,
            now=effective_audit_time,
        )
        evidence["age_audit"] = after_age_audit
        assert before_age_audit is not None
        evidence["issue_sweep"] = _issue_sweep_evidence(
            policy,
            before_age_audit,
            after_age_audit,
            failures,
        )
    if failures:
        raise LifecycleAuditError(
            "GitHub issue state drift was corrected or flagged: " + "; ".join(failures),
            evidence,
        )
    return evidence


def _supersession_evidence(
    organization: str,
    supersessions: Mapping[tuple[str, int], Mapping[str, Any]] | None,
) -> list[dict[str, Any]]:
    def successor_evidence(successor: Mapping[str, Any]) -> dict[str, Any]:
        repository = str(successor["repository"])
        if "number" in successor:
            number = int(successor["number"])
            return {
                "number": number,
                "repository": repository,
                "revision": successor["revision"],
                "url": f"https://github.com/{organization}/{repository}/issues/{number}",
            }
        commit = str(successor["commit"])
        path = str(successor["path"])
        return {
            "commit": commit,
            "path": path,
            "release_plan": dict(successor["release_plan"]),
            "repository": repository,
            "sha256": successor["sha256"],
            "train": successor["train"],
            "url": f"https://github.com/{organization}/{repository}/blob/{commit}/{path}",
        }

    return [
        {
            "retired": {
                "number": number,
                "repository": repository,
                "url": f"https://github.com/{organization}/{repository}/issues/{number}",
            },
            "state": "superseded",
            "activation": dict(successor["activation"]),
            "successor": successor_evidence(successor),
        }
        for (repository, number), successor in sorted((supersessions or {}).items())
    ]


def _write_evidence(path: Path | None, evidence: dict[str, Any]) -> None:
    if path is not None:
        path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_discovery_outputs(path: Path | None, manifest: dict[str, Any]) -> None:
    if path is None:
        return
    trigger = manifest.get("trigger")
    trigger_approved = not isinstance(trigger, Mapping) or trigger.get("approved") is True
    with path.open("a", encoding="utf-8") as output:
        output.write("intake_ready=true\n")
        output.write(f"trigger_approved={'true' if trigger_approved else 'false'}\n")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in (
        "validate",
        "discover",
        "metadata-audit",
        "complete-before-intake",
        "activate",
        "apply",
        "audit",
    ):
        command = subparsers.add_parser(name)
        command.add_argument("policy", type=Path)
        command.add_argument("backlog", type=Path)
        command.add_argument(
            "--qualification-policy",
            type=Path,
            default=Path("qualification/policy.json"),
        )
        command.add_argument(
            "--legacy-cross-repository-targets",
            type=Path,
            default=Path("issue-authority/legacy-cross-repository-targets.json"),
        )
        command.add_argument("--policy-schema", type=Path)
        command.add_argument("--backlog-schema", type=Path)
        if name == "discover":
            command.add_argument("--output", type=Path, required=True)
            command.add_argument("--github-output", type=Path)
            command.add_argument("--lifecycle-projection", type=Path)
            command.add_argument("--projection-actor")
            command.add_argument("--trigger-repository")
            command.add_argument("--trigger-number", type=int)
            command.add_argument("--trigger-action")
            command.add_argument("--trigger-actor")
            command.add_argument("--trigger-label")
        elif name == "metadata-audit":
            command.add_argument("--evidence", type=Path, required=True)
        elif name == "complete-before-intake":
            command.add_argument("--evidence", type=Path, required=True)
            command.add_argument("--lifecycle-projection", type=Path, required=True)
            command.add_argument("--projection-actor", required=True)
        elif name == "activate":
            command.add_argument("--evidence", type=Path)
        elif name in {"apply", "audit"}:
            command.add_argument("--evidence", type=Path)
            command.add_argument("--intake-manifest", type=Path, required=True)
            command.add_argument("--lifecycle-projection", type=Path)
            command.add_argument("--projection-actor")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(argv or sys.argv[1:])
    evidence_path = getattr(arguments, "evidence", None)
    try:
        policy, backlog = load_contract(
            arguments.policy,
            arguments.backlog,
            arguments.policy_schema,
            arguments.backlog_schema,
        )
        target_qualification = _load_json(arguments.qualification_policy, "target qualification policy")
        try:
            cross_repository_lifecycle.qualification_targets(target_qualification)
        except cross_repository_lifecycle.LifecycleError as error:
            raise AuthorityError(str(error)) from error
        legacy_cross_repository_targets = load_legacy_cross_repository_targets(
            arguments.legacy_cross_repository_targets,
            target_qualification,
        )
        validate_backlog_cross_repository_targets(
            backlog,
            target_qualification,
            organization=policy["organization"],
        )
        if arguments.command == "validate":
            return 0
        discovery_token = os.environ.get("GITHUB_TOKEN") or ""
        discovery = GitHubDiscovery(
            discovery_token,
            os.environ.get("GITHUB_GRAPHQL_URL", "https://api.github.com/graphql"),
            api_url=os.environ.get("GITHUB_API_URL", "https://api.github.com"),
        )
        if arguments.command == "metadata-audit":
            public_metadata = discover_public_metadata(policy, discovery)
            evidence = build_public_age_audit(policy, public_metadata, [])
            _write_evidence(evidence_path, evidence)
            notification = evidence["pipeline_health"]["dm_notification"]
            if notification["required"]:
                print(
                    f"::warning title=Public lifecycle age audit::"
                    f"Lifecycle thresholds crossed for {len(notification['threshold_crossings'])} "
                    "public identities; use the retained dedupe key for one product-owner notification.",
                    file=sys.stderr,
                )
            return 0
        if arguments.command == "complete-before-intake":
            lifecycle_projection, lifecycle_projection_failures = load_public_lifecycle_projection(
                arguments.lifecycle_projection,
                policy,
                arguments.projection_actor,
            )
            public_metadata = discover_public_issue_metadata(policy, discovery)
            token = os.environ.get("BETA_PRODUCT_WORK_TOKEN") or ""
            client = GitHubApi(
                token,
                os.environ.get("GITHUB_API_URL", "https://api.github.com"),
                activation_token=discovery_token,
                read_token=discovery_token,
                graphql_url=os.environ.get("GITHUB_GRAPHQL_URL", "https://api.github.com/graphql"),
            )
            evidence = reconcile_verified_releases_before_intake(
                policy,
                client,
                public_metadata,
                lifecycle_projection,
                projection_failures=lifecycle_projection_failures,
            )
            _write_evidence(evidence_path, evidence)
            for failure in evidence["failures"]:
                print(f"issue authority isolated {failure}", file=sys.stderr)
            return 0
        if arguments.command == "discover":
            has_repository = arguments.trigger_repository is not None
            has_number = arguments.trigger_number is not None
            if has_repository != has_number:
                raise AuthorityError("trigger repository and issue number must be provided together")
            lifecycle_projection: dict[tuple[str, int], dict[str, Any]] = {}
            if arguments.lifecycle_projection is not None:
                lifecycle_projection, lifecycle_projection_failures = load_public_lifecycle_projection(
                    arguments.lifecycle_projection,
                    policy,
                    arguments.projection_actor,
                )
                for failure in lifecycle_projection_failures:
                    print(f"issue authority isolated {failure}", file=sys.stderr)
            elif arguments.projection_actor is not None:
                raise AuthorityError("public lifecycle projection actor was supplied without a projection")
            manifest, _inventory = reconstruct_intake(
                policy,
                discovery,
                pre_intake_release_completions=_verified_release_completions(lifecycle_projection),
                target_qualification=target_qualification,
                legacy_cross_repository_targets=legacy_cross_repository_targets,
                trigger_repository=arguments.trigger_repository,
                trigger_number=arguments.trigger_number,
                trigger_action=arguments.trigger_action,
                trigger_actor=arguments.trigger_actor,
                trigger_label=arguments.trigger_label,
            )
            for rejection in manifest["rejected_issues"]:
                print(
                    f"issue authority isolated {rejection['repository']}#{rejection['number']}: "
                    f"{rejection['reason']}",
                    file=sys.stderr,
                )
            _write_evidence(arguments.output, manifest)
            _write_discovery_outputs(arguments.github_output, manifest)
            return 0

        if arguments.command == "activate":
            client = GitHubApi(
                discovery_token,
                os.environ.get("GITHUB_API_URL", "https://api.github.com"),
                activation_token=discovery_token,
                read_token=discovery_token,
                graphql_url=os.environ.get("GITHUB_GRAPHQL_URL", "https://api.github.com/graphql"),
            )
            evidence = activate_prerelease_supersessions(
                policy,
                discovery,
                client,
                target_qualification=target_qualification,
                legacy_cross_repository_targets=legacy_cross_repository_targets,
            )
            _write_evidence(evidence_path, evidence)
            return 0

        manifest = _load_json(arguments.intake_manifest, "issue-intake manifest")
        inventory = verify_intake_manifest(
            policy,
            manifest,
            discovery,
            target_qualification=target_qualification,
            legacy_cross_repository_targets=legacy_cross_repository_targets,
        )
        approved_completion_holds = _manifest_completion_holds(manifest)
        cross_repository_targets = _manifest_cross_repository_targets(manifest)
        historical_cross_repository_completions = _manifest_historical_cross_repository_completions(manifest)
        frozen_cross_repository_lifecycles = _manifest_frozen_cross_repository_lifecycles(manifest)
        prerelease_supersessions = _manifest_prerelease_supersessions(manifest)
        public_metadata = _manifest_public_metadata(manifest)
        lifecycle_projection: dict[tuple[str, int], dict[str, Any]] = {}
        lifecycle_projection_failures: list[str] = []
        if arguments.lifecycle_projection is not None:
            lifecycle_projection, lifecycle_projection_failures = load_public_lifecycle_projection(
                arguments.lifecycle_projection,
                policy,
                arguments.projection_actor,
            )
        elif arguments.projection_actor is not None:
            raise AuthorityError("public lifecycle projection actor was supplied without a projection")
        token = os.environ.get("BETA_PRODUCT_WORK_TOKEN") or ""
        client = GitHubApi(
            token,
            os.environ.get("GITHUB_API_URL", "https://api.github.com"),
            activation_token=discovery_token,
            read_token=discovery_token,
            graphql_url=os.environ.get("GITHUB_GRAPHQL_URL", "https://api.github.com/graphql"),
        )
        if arguments.command == "apply":
            evidence = apply_backlog(
                policy,
                backlog,
                client,
                inventory=inventory,
                approved_completion_holds=approved_completion_holds,
                cross_repository_targets=cross_repository_targets,
                historical_cross_repository_completions=historical_cross_repository_completions,
                frozen_cross_repository_lifecycles=frozen_cross_repository_lifecycles,
                lifecycle_projection=lifecycle_projection,
                lifecycle_projection_failures=lifecycle_projection_failures,
                prerelease_supersessions=prerelease_supersessions,
                public_metadata=public_metadata,
            )
        else:
            evidence = audit_backlog(
                policy,
                backlog,
                client,
                inventory=inventory,
                approved_completion_holds=approved_completion_holds,
                cross_repository_targets=cross_repository_targets,
                historical_cross_repository_completions=historical_cross_repository_completions,
                frozen_cross_repository_lifecycles=frozen_cross_repository_lifecycles,
                lifecycle_projection=lifecycle_projection,
                lifecycle_projection_failures=lifecycle_projection_failures,
                prerelease_supersessions=prerelease_supersessions,
                public_metadata=public_metadata,
            )
        evidence["intake"] = _manifest_core(manifest)
        _write_evidence(evidence_path, evidence)
        return 0
    except AuthorityError as error:
        failure_evidence = getattr(error, "evidence", None)
        if arguments.command == "metadata-audit" and "policy" in locals():
            failure_evidence = build_public_age_audit(policy, [], [str(error)])
        if not isinstance(failure_evidence, dict):
            failure_evidence = {
                "schema": "durable-workflow.github-issue-authority-evidence/v1",
                "mode": arguments.command,
                "outcome": "fail",
            }
        failure_evidence["error"] = str(error)
        _write_evidence(
            evidence_path,
            failure_evidence,
        )
        print(f"issue authority failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
