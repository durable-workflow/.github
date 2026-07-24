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
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

POLICY_SCHEMA = "durable-workflow.github-issue-authority/v1"
BACKLOG_SCHEMA = "durable-workflow.github-beta-backlog/v1"
INTAKE_SCHEMA = "durable-workflow.github-issue-intake/v2"
MARKER_PATTERN = re.compile(r"<!-- beta-work-id: ([a-z0-9][a-z0-9-]{2,79}) -->")
UNBLOCK_CONTEXT_START = "<!-- beta-unblock-condition:start -->"
UNBLOCK_CONTEXT_END = "<!-- beta-unblock-condition:end -->"
UNBLOCK_CONTEXT_MARKERS = (UNBLOCK_CONTEXT_START, UNBLOCK_CONTEXT_END)
NON_PUBLIC_CONTEXT_PATTERNS = (
    re.compile(r"(?<![:/A-Za-z0-9_.-])/(?!/)[^\s)>\]]+"),
    re.compile(r"\b(?:localhost|127\.0\.0\.1)(?::[0-9]+)?\b", re.I),
)
STATUS_LABELS = {"status:triage", "status:ready", "status:blocked", "status:done"}
OPEN_STATUS_LABELS = STATUS_LABELS - {"status:done"}
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
        "title": node.get("title"),
    }
    return issue, timeline


class GitHubDiscovery:
    """Read-only GraphQL client that reconstructs issue revision authority."""

    def __init__(self, token: str, graphql_url: str = "https://api.github.com/graphql") -> None:
        if not token:
            raise AuthorityError("GITHUB_TOKEN is required for read-only issue discovery")
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
    return {key: manifest.get(key) for key in ("schema", "organization", "policy_digest", "issues")}


def _manifest_completion_holds(manifest: Mapping[str, Any]) -> set[tuple[str, int]]:
    return {
        (record["repository"], record["number"])
        for record in manifest["issues"]
        if record["completion_evidence_required"] is True
    }


def reconstruct_intake(
    policy: dict[str, Any],
    client: Any,
    *,
    trigger_repository: str | None = None,
    trigger_number: int | None = None,
    trigger_action: str | None = None,
    trigger_actor: str | None = None,
    trigger_label: str | None = None,
) -> tuple[dict[str, Any], dict[str, list[dict[str, Any]]]]:
    """Build a deterministic manifest and an inventory containing only vetted revisions."""

    intake_policy = policy["intake"]
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
            records.append(
                {
                    "approval_actor": assessment["approval_actor"],
                    "approval_at": assessment["approval_at"],
                    "approval_mode": assessment["approval_mode"],
                    "completion_evidence_required": COMPLETION_REQUIRED_LABEL in _intake_label_names(issue),
                    "number": number,
                    "repository": repository,
                    "revision": assessment["revision"],
                }
            )

    manifest: dict[str, Any] = {
        "schema": INTAKE_SCHEMA,
        "organization": policy["organization"],
        "policy_digest": _object_digest(policy),
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


def verify_intake_manifest(
    policy: dict[str, Any],
    manifest: Mapping[str, Any],
    client: Any,
) -> dict[str, list[dict[str, Any]]]:
    if manifest.get("schema") != INTAKE_SCHEMA:
        raise AuthorityError("issue-intake manifest uses an unsupported schema")
    if (
        manifest.get("organization") != policy["organization"]
        or manifest.get("policy_digest") != _object_digest(policy)
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
        "number",
        "repository",
        "revision",
    }
    inventory: dict[str, list[dict[str, Any]]] = {repository: [] for repository in policy["repositories"]}
    identities: set[tuple[str, int]] = set()
    intake_policy = policy["intake"]
    for record in records:
        if not isinstance(record, Mapping) or set(record) != record_keys:
            raise AuthorityError("issue-intake manifest contains a malformed issue record")
        repository = record.get("repository")
        number = record.get("number")
        if (
            not isinstance(repository, str)
            or repository not in inventory
            or not isinstance(number, int)
            or isinstance(number, bool)
            or number < 1
            or not isinstance(record.get("completion_evidence_required"), bool)
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
        current = {
            "approval_actor": assessment.get("approval_actor"),
            "approval_at": assessment.get("approval_at"),
            "approval_mode": assessment.get("approval_mode"),
            "completion_evidence_required": record["completion_evidence_required"],
            "number": issue.get("number"),
            "repository": repository,
            "revision": assessment.get("revision"),
        }
        if not assessment["approved"] or dict(record) != current:
            raise AuthorityError("vetted issue revisions changed after read-only discovery")
        inventory[repository].append(issue)
    return inventory


class GitHubApi:
    """Bounded GitHub REST client for public issue metadata and lifecycle labels."""

    def __init__(self, token: str, api_url: str = "https://api.github.com") -> None:
        if not token:
            raise AuthorityError("BETA_PRODUCT_WORK_TOKEN is required for cross-repository issue authority")
        self.api_url = api_url.rstrip("/")
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "durable-workflow-issue-authority/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    @staticmethod
    def _error_detail(error: urllib.error.HTTPError) -> str:
        try:
            return error.read().decode("utf-8", errors="replace")[:600]
        except OSError:
            return "response body unavailable"

    def request(self, method: str, path: str, payload: Mapping[str, Any] | None = None) -> Any:
        body = None
        headers = dict(self.headers)
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
    ) -> None:
        self.request("PATCH", f"/repos/{organization}/{repository}/issues/{number}", {"state": state})


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
    unblock_context = _render_unblock_context(item)
    rendered_unblock_context = f"\n\n{unblock_context}" if unblock_context else ""
    return (
        f"{item['body'].rstrip()}\n\n"
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
) -> list[str]:
    organization = policy["organization"]
    failures: list[str] = []
    for repository, issues in inventory.items():
        for issue in issues:
            labels = _label_names(issue)
            if "authority:github" not in labels:
                continue
            number = int(issue["number"])
            location = f"{repository}#{number}"
            statuses = labels & STATUS_LABELS
            state = issue.get("state")
            replacement = set(labels)
            approved_completion_hold = (repository, number) in approved_completion_holds
            if (
                approved_completion_hold
                and COMPLETION_REQUIRED_LABEL not in labels
                and COMPLETION_VERIFIED_LABEL not in labels
            ):
                replacement.add(COMPLETION_REQUIRED_LABEL)
                client.replace_issue_labels(organization, repository, number, sorted(replacement))
                issue["labels"] = [{"name": label} for label in sorted(replacement)]
                labels = replacement
                statuses = labels & STATUS_LABELS

            completion_is_pending = COMPLETION_REQUIRED_LABEL in labels and COMPLETION_VERIFIED_LABEL not in labels
            if state == "closed" and completion_is_pending:
                client.update_issue_state(organization, repository, number, "open")
                issue["state"] = "open"
                replacement -= STATUS_LABELS
                previous_open_statuses = statuses & OPEN_STATUS_LABELS
                replacement.update(previous_open_statuses if len(previous_open_statuses) == 1 else {"status:triage"})
                if replacement != labels:
                    client.replace_issue_labels(organization, repository, number, sorted(replacement))
                    issue["labels"] = [{"name": label} for label in sorted(replacement)]
                labels = replacement
                statuses = labels & STATUS_LABELS
                state = "open"
                failures.append(f"{location} closed before its required public completion evidence was verified")

            if state == "closed" and statuses != {"status:done"}:
                replacement -= STATUS_LABELS
                replacement.add("status:done")
                client.replace_issue_labels(organization, repository, number, sorted(replacement))
                failures.append(f"{location} closed state overrode stale lifecycle labels {sorted(statuses)}")
            elif state == "open" and "status:done" in statuses:
                replacement.remove("status:done")
                if not replacement & OPEN_STATUS_LABELS:
                    replacement.add("status:triage")
                client.replace_issue_labels(organization, repository, number, sorted(replacement))
                failures.append(f"{location} open state overrode stale status:done")
            elif state == "open" and len(statuses & OPEN_STATUS_LABELS) != 1:
                replacement.add("authority:conflict")
                client.replace_issue_labels(organization, repository, number, sorted(replacement))
                failures.append(f"{location} has ambiguous open lifecycle labels {sorted(statuses)}")

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

    failures = _audit_state_labels(policy, client, inventory, approved_completion_holds or set())
    failures.extend(_audit_migrated_classification(backlog, resolved))
    if failures:
        raise AuthorityError("GitHub issue state drift was corrected or flagged: " + "; ".join(failures))
    return {
        "schema": "durable-workflow.github-issue-authority-evidence/v1",
        "mode": "apply",
        "outcome": "pass",
        "metadata": metadata_evidence,
        "issues": issue_evidence,
    }


def audit_backlog(
    policy: dict[str, Any],
    backlog: dict[str, Any],
    client: Any,
    *,
    inventory: dict[str, list[dict[str, Any]]] | None = None,
    approved_completion_holds: set[tuple[str, int]] | None = None,
) -> dict[str, Any]:
    inventory = inventory if inventory is not None else _inventory(policy, client)
    resolved = _preflight_markers(policy, backlog, client, inventory, allow_missing=False)
    _preflight_unblock_context_layouts(backlog, inventory)
    _plan_unblock_context_updates(backlog, resolved)
    _milestones, metadata_evidence = sync_metadata(policy, client)
    failures = _audit_state_labels(policy, client, inventory, approved_completion_holds or set())
    failures.extend(_audit_migrated_classification(backlog, resolved))
    if failures:
        raise AuthorityError("GitHub issue state drift was corrected or flagged: " + "; ".join(failures))
    organization = policy["organization"]
    return {
        "schema": "durable-workflow.github-issue-authority-evidence/v1",
        "mode": "audit",
        "outcome": "pass",
        "metadata": metadata_evidence,
        "issues": {
            work_id: {
                "state": issue.get("state"),
                "url": _issue_url(issue, organization, repository),
            }
            for work_id, (repository, issue) in sorted(resolved.items())
        },
    }


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
    for name in ("validate", "discover", "apply", "audit"):
        command = subparsers.add_parser(name)
        command.add_argument("policy", type=Path)
        command.add_argument("backlog", type=Path)
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
        elif name != "validate":
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
        if arguments.command == "validate":
            return 0
        discovery_token = os.environ.get("GITHUB_TOKEN") or ""
        discovery = GitHubDiscovery(
            discovery_token,
            os.environ.get("GITHUB_GRAPHQL_URL", "https://api.github.com/graphql"),
        )
        if arguments.command == "discover":
            has_repository = arguments.trigger_repository is not None
            has_number = arguments.trigger_number is not None
            if has_repository != has_number:
                raise AuthorityError("trigger repository and issue number must be provided together")
            manifest, _inventory = reconstruct_intake(
                policy,
                discovery,
                trigger_repository=arguments.trigger_repository,
                trigger_number=arguments.trigger_number,
                trigger_action=arguments.trigger_action,
                trigger_actor=arguments.trigger_actor,
                trigger_label=arguments.trigger_label,
            )
            _write_evidence(arguments.output, manifest)
            _write_discovery_outputs(arguments.github_output, manifest)
            return 0

        manifest = _load_json(arguments.intake_manifest, "issue-intake manifest")
        inventory = verify_intake_manifest(policy, manifest, discovery)
        approved_completion_holds = _manifest_completion_holds(manifest)
        token = os.environ.get("BETA_PRODUCT_WORK_TOKEN") or ""
        client = GitHubApi(token, os.environ.get("GITHUB_API_URL", "https://api.github.com"))
        if arguments.command == "apply":
            evidence = apply_backlog(
                policy,
                backlog,
                client,
                inventory=inventory,
                approved_completion_holds=approved_completion_holds,
            )
        else:
            evidence = audit_backlog(
                policy,
                backlog,
                client,
                inventory=inventory,
                approved_completion_holds=approved_completion_holds,
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
