#!/usr/bin/env python3
"""Validate and operate the GitHub-authoritative public product backlog."""

from __future__ import annotations

import argparse
import base64
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
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

# GitHub Actions invokes this file directly from the repository root. In that
# mode Python adds scripts/, rather than the repository root, to sys.path.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts import cross_repository_lifecycle

POLICY_SCHEMA = "durable-workflow.github-issue-authority/v1"
BACKLOG_SCHEMA = "durable-workflow.github-beta-backlog/v1"
INTAKE_SCHEMA = "durable-workflow.github-issue-intake/v8"
LEGACY_TARGET_SCHEMA = "durable-workflow.legacy-cross-repository-targets/v3"
MARKER_PATTERN = re.compile(r"<!-- beta-work-id: ([a-z0-9][a-z0-9-]{2,79}) -->")
WORK_MARKER_PATTERN = re.compile(r"<!-- durable-workflow-work-id: ([a-z0-9][a-z0-9-]{2,79}) -->")
LEGACY_TARGET_HEADING = "### Affected public repositories"
UNBLOCK_CONTEXT_START = "<!-- beta-unblock-condition:start -->"
UNBLOCK_CONTEXT_END = "<!-- beta-unblock-condition:end -->"
UNBLOCK_CONTEXT_MARKERS = (UNBLOCK_CONTEXT_START, UNBLOCK_CONTEXT_END)
NON_PUBLIC_CONTEXT_PATTERNS = (
    re.compile(r"(?<![:/A-Za-z0-9_.-])/(?!/)[^\s)>\]]+"),
    re.compile(r"\b(?:localhost|127\.0\.0\.1)(?::[0-9]+)?\b", re.I),
)
SUPERSESSION_EVIDENCE_MARKER = "<!-- durable-workflow-prerelease-supersession -->"
SUPERSESSION_ACTIVATION_CONTEXT_PREFIX = "issue-authority/prerelease-supersession"
SUPERSESSION_ACTIVATION_DESCRIPTION_PREFIX = "sha256:"
GITHUB_ACTIONS_BOT_ID = 41_898_282
GITHUB_ACTIONS_BOT_LOGIN = "github-actions[bot]"
SUPERSEDED_STATUS_LABEL = "status:superseded"
STATUS_LABELS = {
    "status:triage",
    "status:ready",
    "status:blocked",
    "status:done",
    SUPERSEDED_STATUS_LABEL,
}
OPEN_STATUS_LABELS = STATUS_LABELS - {"status:done", SUPERSEDED_STATUS_LABEL}
COMPLETION_REQUIRED_LABEL = "completion:evidence-required"
COMPLETION_VERIFIED_LABEL = "completion:evidence-verified"
COMPLETION_LABELS = {COMPLETION_REQUIRED_LABEL, COMPLETION_VERIFIED_LABEL}
KIND_LABELS = {"kind:defect", "kind:feature", "kind:release-blocker", "kind:cross-repository"}
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
        lastEditedAt
        url
        state
        stateReason
        author { login }
        milestone { title }
        labels(first: 100) {
          nodes { name }
          pageInfo { hasNextPage }
        }
        timelineItems(last: 100, itemTypes: [LABELED_EVENT, RENAMED_TITLE_EVENT, UNLABELED_EVENT]) {
          nodes {
            __typename
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
      lastEditedAt
      url
      state
      stateReason
      author { login }
      milestone { title }
      labels(first: 100) {
        nodes { name }
        pageInfo { hasNextPage }
      }
      timelineItems(last: 100, itemTypes: [LABELED_EVENT, RENAMED_TITLE_EVENT, UNLABELED_EVENT]) {
        nodes {
          __typename
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
        }
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
            "LabeledEvent": "labeled",
            "RenamedTitleEvent": "renamed",
            "UnlabeledEvent": "unlabeled",
        }.get(event.get("__typename"))
        if event_type == "renamed":
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
        "created_at": node.get("createdAt"),
        "html_url": node.get("url"),
        "labels": [label for label in labels if isinstance(label, Mapping)],
        "last_edited_at": node.get("lastEditedAt"),
        "milestone": {"title": milestone.get("title")} if isinstance(milestone, Mapping) else None,
        "number": node.get("number"),
        "state": str(node.get("state", "")).lower(),
        "state_reason": (str(node["stateReason"]).lower() if isinstance(node.get("stateReason"), str) else None),
        "title": node.get("title"),
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
        )
    }


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
    trains = product_train.get("trains") if isinstance(product_train, Mapping) else None
    selected = trains.get(train) if isinstance(trains, Mapping) else None
    components = product_train.get("components") if isinstance(product_train, Mapping) else None
    versions = selected.get("versions") if isinstance(selected, Mapping) else None
    if (
        not isinstance(product_train, Mapping)
        or product_train.get("schema") != "durable-workflow.product-train/v2"
        or product_train.get("current") != train
        or not isinstance(components, list)
        or not components
        or len(components) != len(set(components))
        or not isinstance(versions, Mapping)
        or set(versions) != set(components)
        or set(versions.values()) != {train}
        or selected.get("status") != "supported"
        or selected.get("release_plan") != successor["release_plan"]
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
    validated_product_trains: set[tuple[str, str, str, str]] = set()
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
        if product_train_identity not in validated_product_trains:
            raw = client.read_file(
                policy["organization"],
                successor["repository"],
                successor["commit"],
                successor["path"],
            )
            _validate_immutable_product_train_successor(successor, raw)
            validated_product_trains.add(product_train_identity)
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


def _issue_cross_repository_targets(
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
    try:
        declared = cross_repository_lifecycle.declared_targets(
            str(issue["body"]),
            targets,
            organization=organization,
        )
    except cross_repository_lifecycle.LifecycleError as error:
        raise AuthorityError(f"GitHub issue {issue['number']}: {error}") from error
    if declared:
        if not is_cross_repository:
            raise AuthorityError(
                f"GitHub issue {issue['number']} declares multiple source targets without cross-repository authority"
            )
        return declared
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


def reconstruct_intake(
    policy: dict[str, Any],
    client: Any,
    *,
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
    inventory: dict[str, list[dict[str, Any]]] = {repository: [] for repository in policy["repositories"]}
    trigger_assessment: dict[str, Any] | None = None
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
            inventory[repository].append(issue)
            cross_repository_targets = _issue_cross_repository_targets(
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
            records.append(
                {
                    "approval_actor": assessment["approval_actor"],
                    "approval_at": assessment["approval_at"],
                    "approval_mode": assessment["approval_mode"],
                    "completion_evidence_required": COMPLETION_REQUIRED_LABEL in _intake_label_names(issue),
                    "cross_repository_targets": cross_repository_targets,
                    "historical_cross_repository_completion": historical_completion,
                    "number": number,
                    "repository": repository,
                    "revision": assessment["revision"],
                    "superseded_by": None,
                }
            )

    _bind_prerelease_supersessions(
        policy,
        records,
        inventory,
        client,
        require_activations=require_supersession_activations,
    )
    manifest: dict[str, Any] = {
        "schema": INTAKE_SCHEMA,
        "organization": policy["organization"],
        "policy_digest": _object_digest(policy),
        "legacy_target_migration_digest": _object_digest(legacy_cross_repository_targets or {}),
        "issues": records,
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
        and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-(?:alpha|beta)\.[0-9]+", str(value.get("train", ""))) is not None
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
    if not isinstance(records, list):
        raise AuthorityError("issue-intake manifest has no issue record list")

    record_keys = {
        "approval_actor",
        "approval_at",
        "approval_mode",
        "completion_evidence_required",
        "cross_repository_targets",
        "historical_cross_repository_completion",
        "number",
        "repository",
        "revision",
        "superseded_by",
    }
    inventory: dict[str, list[dict[str, Any]]] = {repository: [] for repository in policy["repositories"]}
    identities: set[tuple[str, int]] = set()
    intake_policy = policy["intake"]
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
            issue,
            timeline,
            assessment,
            (
                cross_repository_lifecycle.qualification_targets(target_qualification)
                if target_qualification is not None
                else {}
            ),
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
        current = {
            "approval_actor": assessment.get("approval_actor"),
            "approval_at": assessment.get("approval_at"),
            "approval_mode": assessment.get("approval_mode"),
            "completion_evidence_required": record["completion_evidence_required"],
            "cross_repository_targets": expected_targets,
            "historical_cross_repository_completion": expected_historical_completion,
            "number": issue.get("number"),
            "repository": repository,
            "revision": assessment.get("revision"),
            "superseded_by": None,
        }
        current_records.append(current)
        inventory[repository].append(issue)

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

    def successful_check_names(self, organization: str, repository: str, commit: str) -> set[str]:
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
        return {
            name
            for name, (_ordering, run) in latest.items()
            if run.get("status") == "completed" and run.get("conclusion") == "success"
        }

    def upsert_lifecycle_comment(
        self,
        organization: str,
        repository: str,
        number: int,
        marker: str,
        body: str,
    ) -> None:
        comments = self.list_collection(f"/repos/{organization}/{repository}/issues/{number}/comments")
        writer_id, writer_login = self._authenticated_writer()
        matches = [
            comment
            for comment in comments
            if (
                isinstance(comment.get("body"), str)
                and marker in comment["body"]
                and isinstance(comment.get("user"), Mapping)
                and type(comment["user"].get("id")) is int
                and comment["user"]["id"] == writer_id
                and isinstance(comment["user"].get("login"), str)
                and comment["user"]["login"].casefold() == writer_login.casefold()
            )
        ]
        if len(matches) > 1:
            raise AuthorityError(
                f"GitHub issue {repository}#{number} has duplicate cross-repository lifecycle evidence"
            )
        if matches:
            comment = matches[0]
            if comment["body"] == body:
                return
            comment_id = comment.get("id")
            if not isinstance(comment_id, int):
                raise AuthorityError(f"GitHub issue {repository}#{number} has lifecycle evidence without an identity")
            self.request("PATCH", f"/repos/{organization}/{repository}/issues/comments/{comment_id}", {"body": body})
            return
        self.request("POST", f"/repos/{organization}/{repository}/issues/{number}/comments", {"body": body})


def _label_names(issue: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for label in issue.get("labels") or []:
        if isinstance(label, str):
            names.add(label)
        elif isinstance(label, dict) and isinstance(label.get("name"), str):
            names.add(label["name"])
    return names


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
            if len(ids) != len(set(ids)):
                raise AuthorityError(f"issue {repository}/{issue.get('number')} repeats its beta work marker")
            distinct_ids = sorted(set(ids))
            if len(distinct_ids) > 1:
                aliases.append((repository, issue, distinct_ids))
            for work_id in ids:
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


def _audit_state_labels(
    policy: dict[str, Any],
    client: Any,
    inventory: Mapping[str, list[dict[str, Any]]],
    approved_completion_holds: set[tuple[str, int]],
    cross_repository_targets: Mapping[tuple[str, int], Sequence[Mapping[str, Any]]] | None,
    historical_cross_repository_completions: (Mapping[tuple[str, int], Sequence[Mapping[str, Any]]] | None),
    prerelease_supersessions: Mapping[tuple[str, int], Mapping[str, Any]] | None,
) -> list[str]:
    organization = policy["organization"]
    historical_completion_identities = set(historical_cross_repository_completions or {})
    recorded_landing_results: dict[tuple[str, str, str, tuple[str, ...]], Mapping[str, Any]] = {}
    for identity, landings in sorted((historical_cross_repository_completions or {}).items()):
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
            failures = [
                f"{target['repository']}@{target['branch']}={target['state']}"
                for target in results
                if target["state"] != "complete"
            ]
            raise AuthorityError(
                f"{identity[0]}#{identity[1]} historical completion evidence failed revalidation: "
                + ", ".join(failures)
            )

    failures: list[str] = []
    for repository, issues in inventory.items():
        for issue in issues:
            labels = _label_names(issue)
            if "authority:github" not in labels:
                continue
            number = int(issue["number"])
            location = f"{repository}#{number}"
            statuses = labels & STATUS_LABELS
            open_statuses_before_lifecycle = statuses & OPEN_STATUS_LABELS
            state = issue.get("state")
            replacement = set(labels)
            aggregated_close = False
            assessment: dict[str, Any] | None = None
            approved_completion_hold = (repository, number) in approved_completion_holds
            supersession = (prerelease_supersessions or {}).get((repository, number))
            if (
                supersession is None
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

            completion_is_pending = COMPLETION_REQUIRED_LABEL in labels and COMPLETION_VERIFIED_LABEL not in labels
            declared_targets = (
                cross_repository_targets.get((repository, number), ()) if cross_repository_targets is not None else ()
            )
            target_contract_is_missing = (
                cross_repository_targets is not None and "kind:cross-repository" in labels and not declared_targets
            )
            target_completion_is_pending = False
            target_contract_failure_reported = False
            if (repository, number) in historical_completion_identities:
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
                    if assessment["complete"] and not cross_repository_lifecycle.closing_references_are_current(
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
                failures.append(f"{location} {reason}")
                target_contract_failure_reported = target_contract_is_missing
            elif state == "open" and declared_targets and not must_remain_open:
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
                if not aggregated_close:
                    failures.append(f"{location} closed state overrode stale lifecycle labels {sorted(statuses)}")
            elif state == "open" and "status:done" in statuses:
                replacement.remove("status:done")
                if not replacement & OPEN_STATUS_LABELS:
                    replacement.add("status:triage")
                client.replace_issue_labels(organization, repository, number, sorted(replacement))
                issue["labels"] = [{"name": label} for label in sorted(replacement)]
                labels = replacement
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
                and not cross_repository_lifecycle.closing_references_are_current(
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

            if len(labels & KIND_LABELS) != 1:
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


def apply_backlog(
    policy: dict[str, Any],
    backlog: dict[str, Any],
    client: Any,
    *,
    inventory: dict[str, list[dict[str, Any]]] | None = None,
    approved_completion_holds: set[tuple[str, int]] | None = None,
    cross_repository_targets: Mapping[tuple[str, int], Sequence[Mapping[str, Any]]] | None = None,
    historical_cross_repository_completions: (Mapping[tuple[str, int], Sequence[Mapping[str, Any]]] | None) = None,
    prerelease_supersessions: Mapping[tuple[str, int], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    organization = policy["organization"]
    inventory = inventory if inventory is not None else _inventory(policy, client)
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
        prerelease_supersessions,
    )
    failures.extend(_audit_migrated_classification(backlog, resolved))
    if failures:
        raise AuthorityError("GitHub issue state drift was corrected or flagged: " + "; ".join(failures))
    return {
        "schema": "durable-workflow.github-issue-authority-evidence/v1",
        "mode": "apply",
        "outcome": "pass",
        "metadata": metadata_evidence,
        "issues": issue_evidence,
        "prerelease_supersessions": _supersession_evidence(
            policy["organization"],
            prerelease_supersessions,
        ),
    }


def audit_backlog(
    policy: dict[str, Any],
    backlog: dict[str, Any],
    client: Any,
    *,
    inventory: dict[str, list[dict[str, Any]]] | None = None,
    approved_completion_holds: set[tuple[str, int]] | None = None,
    cross_repository_targets: Mapping[tuple[str, int], Sequence[Mapping[str, Any]]] | None = None,
    historical_cross_repository_completions: (Mapping[tuple[str, int], Sequence[Mapping[str, Any]]] | None) = None,
    prerelease_supersessions: Mapping[tuple[str, int], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    inventory = inventory if inventory is not None else _inventory(policy, client)
    resolved = _preflight_markers(policy, backlog, client, inventory, allow_missing=False)
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
        prerelease_supersessions,
    )
    failures.extend(_audit_migrated_classification(backlog, resolved))
    if failures:
        raise AuthorityError("GitHub issue state drift was corrected or flagged: " + "; ".join(failures))
    organization = policy["organization"]
    return {
        "schema": "durable-workflow.github-issue-authority-evidence/v1",
        "mode": "audit",
        "outcome": "pass",
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
        },
    }


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
    encoded = base64.b64encode(
        json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).decode("ascii")
    trigger = manifest.get("trigger")
    trigger_approved = not isinstance(trigger, Mapping) or trigger.get("approved") is True
    with path.open("a", encoding="utf-8") as output:
        output.write("intake_ready=true\n")
        output.write(f"trigger_approved={'true' if trigger_approved else 'false'}\n")
        output.write(f"manifest={encoded}\n")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "discover", "activate", "apply", "audit"):
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
            command.add_argument("--trigger-repository")
            command.add_argument("--trigger-number", type=int)
            command.add_argument("--trigger-action")
            command.add_argument("--trigger-actor")
            command.add_argument("--trigger-label")
        elif name == "activate":
            command.add_argument("--evidence", type=Path)
        elif name in {"apply", "audit"}:
            command.add_argument("--evidence", type=Path)
            command.add_argument("--intake-manifest", type=Path, required=True)
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
        if arguments.command == "discover":
            has_repository = arguments.trigger_repository is not None
            has_number = arguments.trigger_number is not None
            if has_repository != has_number:
                raise AuthorityError("trigger repository and issue number must be provided together")
            manifest, _inventory = reconstruct_intake(
                policy,
                discovery,
                target_qualification=target_qualification,
                legacy_cross_repository_targets=legacy_cross_repository_targets,
                trigger_repository=arguments.trigger_repository,
                trigger_number=arguments.trigger_number,
                trigger_action=arguments.trigger_action,
                trigger_actor=arguments.trigger_actor,
                trigger_label=arguments.trigger_label,
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
        prerelease_supersessions = _manifest_prerelease_supersessions(manifest)
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
                prerelease_supersessions=prerelease_supersessions,
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
                prerelease_supersessions=prerelease_supersessions,
            )
        evidence["intake"] = _manifest_core(manifest)
        _write_evidence(evidence_path, evidence)
        return 0
    except AuthorityError as error:
        _write_evidence(
            evidence_path,
            {
                "schema": "durable-workflow.github-issue-authority-evidence/v1",
                "mode": arguments.command,
                "outcome": "fail",
                "error": str(error),
            },
        )
        print(f"issue authority failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
