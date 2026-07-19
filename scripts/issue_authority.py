#!/usr/bin/env python3
"""Validate and operate the GitHub-authoritative public product backlog."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator, FormatChecker

POLICY_SCHEMA = "durable-workflow.github-issue-authority/v1"
BACKLOG_SCHEMA = "durable-workflow.github-beta-backlog/v1"
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
KIND_LABELS = {"kind:defect", "kind:feature", "kind:release-blocker", "kind:cross-repository"}
PRIORITY_LABELS = {"priority:P0", "priority:P1", "priority:P2", "priority:P3", "priority:untriaged"}
CLASSIFICATION_LABELS = {"beta:blocker", "beta:compatible", "post-2.0"}
OWNER_LABELS = {
    ".github": "repo:github-control-plane",
    "workflow": "repo:workflow",
    "waterline": "repo:waterline",
    "server": "repo:server",
    "cli": "repo:cli",
    "sample-app": "repo:sample-app",
    "sdk-php": "repo:sdk-php",
    "sdk-python": "repo:sdk-python",
    "sdk-rust": "repo:sdk-rust",
    "durable-workflow.github.io": "repo:documentation",
}
GITHUB_API_ATTEMPTS = 4
GITHUB_API_RETRY_SECONDS = 2.0


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
        *KIND_LABELS,
        *PRIORITY_LABELS,
        *CLASSIFICATION_LABELS,
        *OWNER_LABELS.values(),
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
    if not desired:
        return None
    if context_span is not None:
        start, end = context_span
        updated = body[:start] + desired + body[end:]
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
) -> dict[str, list[tuple[str, dict[str, Any]]]]:
    markers: dict[str, list[tuple[str, dict[str, Any]]]] = {}
    for repository, issues in inventory.items():
        for issue in issues:
            body = issue.get("body") or ""
            if not isinstance(body, str):
                continue
            ids = MARKER_PATTERN.findall(body)
            if len(ids) != len(set(ids)):
                raise AuthorityError(f"issue {repository}/{issue.get('number')} repeats its beta work marker")
            for work_id in ids:
                markers.setdefault(work_id, []).append((repository, issue))
    return markers


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
    markers = _marker_index(inventory)
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


def apply_backlog(policy: dict[str, Any], backlog: dict[str, Any], client: Any) -> dict[str, Any]:
    organization = policy["organization"]
    inventory = _inventory(policy, client)
    _preflight_unblock_context_layouts(backlog, inventory)
    milestone_numbers, metadata_evidence = sync_metadata(policy, client)
    resolved = _preflight_markers(policy, backlog, client, inventory, allow_missing=True)
    planned_body_updates = _plan_unblock_context_updates(backlog, resolved)
    dependency_urls = {
        work_id: _issue_url(issue, organization, repository) for work_id, (repository, issue) in resolved.items()
    }
    dependency_titles = {item["id"]: item["title"] for item in backlog["items"]}
    issue_evidence: dict[str, Any] = {}

    for item in backlog["items"]:
        if item["id"] in resolved:
            repository, issue = resolved[item["id"]]
            updated_body = planned_body_updates[item["id"]]
            if updated_body is not None:
                client.update_issue_body(
                    organization,
                    repository,
                    int(issue["number"]),
                    updated_body,
                )
                issue["body"] = updated_body
            issue_evidence[item["id"]] = {
                "action": "updated-blocker-context" if updated_body is not None else "preserved",
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

    failures = _audit_state_labels(policy, client, inventory)
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


def audit_backlog(policy: dict[str, Any], backlog: dict[str, Any], client: Any) -> dict[str, Any]:
    inventory = _inventory(policy, client)
    _preflight_unblock_context_layouts(backlog, inventory)
    _milestones, metadata_evidence = sync_metadata(policy, client)
    resolved = _preflight_markers(policy, backlog, client, inventory, allow_missing=False)
    _plan_unblock_context_updates(backlog, resolved)
    failures = _audit_state_labels(policy, client, inventory)
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


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "apply", "audit"):
        command = subparsers.add_parser(name)
        command.add_argument("policy", type=Path)
        command.add_argument("backlog", type=Path)
        command.add_argument("--policy-schema", type=Path)
        command.add_argument("--backlog-schema", type=Path)
        if name != "validate":
            command.add_argument("--evidence", type=Path)
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
        token = os.environ.get("BETA_PRODUCT_WORK_TOKEN") or os.environ.get("GH_TOKEN") or ""
        client = GitHubApi(token, os.environ.get("GITHUB_API_URL", "https://api.github.com"))
        if arguments.command == "apply":
            evidence = apply_backlog(policy, backlog, client)
        else:
            evidence = audit_backlog(policy, backlog, client)
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
