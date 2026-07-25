"""Aggregate public landing evidence for one authoritative cross-repository issue."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from typing import Any

TARGET_HEADING = "### Required source targets"
EVIDENCE_MARKER = "<!-- durable-workflow-cross-repository-lifecycle:v1 -->"
API_PULL_PATTERN = re.compile(r"/repos/([^/]+)/([^/]+)/pulls/([1-9][0-9]*)$")
HTML_PULL_PATTERN = re.compile(r"https://github\.com/([^/]+)/([^/]+)/pull/([1-9][0-9]*)$")


class LifecycleError(RuntimeError):
    """Cross-repository lifecycle evidence is malformed or unavailable."""


def qualification_targets(policy: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    """Reduce the qualification policy to the target identity used by issue intake."""

    targets = policy.get("targets")
    if not isinstance(targets, Mapping):
        raise LifecycleError("target qualification policy has no target map")
    reduced: dict[str, dict[str, Any]] = {}
    for value in targets.values():
        if not isinstance(value, Mapping):
            raise LifecycleError("target qualification policy contains a malformed target")
        repository = value.get("repository")
        branch = value.get("branch")
        workflows = value.get("workflows")
        if (
            not isinstance(repository, str)
            or not repository
            or not isinstance(branch, str)
            or not branch
            or not isinstance(workflows, Sequence)
            or isinstance(workflows, str | bytes)
        ):
            raise LifecycleError("target qualification policy contains an invalid target identity")
        checks: list[str] = []
        for workflow in workflows:
            check = workflow.get("required_check") if isinstance(workflow, Mapping) else None
            if not isinstance(check, str) or not check:
                raise LifecycleError(f"target qualification policy has no required check for {repository}@{branch}")
            checks.append(check)
        if repository in reduced:
            raise LifecycleError(f"target qualification policy repeats repository {repository}")
        reduced[repository] = {
            "branch": branch,
            "repository": repository,
            "required_checks": sorted(set(checks)),
        }
    return reduced


def declared_targets(
    body: str,
    targets: Mapping[str, Mapping[str, Any]],
    *,
    organization: str,
) -> list[dict[str, Any]]:
    """Read exact form selections from the bounded affected-repositories section."""

    heading_count = body.count(TARGET_HEADING)
    if heading_count == 0:
        return []
    if heading_count != 1:
        raise LifecycleError("cross-repository issue repeats its affected public repositories section")
    section = body.split(TARGET_HEADING, 1)[1]
    section = re.split(r"(?m)^### ", section, maxsplit=1)[0]
    selected: list[str] = []
    candidate_pattern = re.compile(rf"^(?:-\s*)?{re.escape(organization)}/([a-z0-9_.-]+)@(main|v2)\s*$")
    for raw_line in section.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("- "):
            line = line[2:].strip()
        for selection in line.split(","):
            match = candidate_pattern.fullmatch(selection.strip())
            if match is None:
                raise LifecycleError(
                    "affected public repositories must contain only exact organization/repository@branch selections"
                )
            repository, branch = match.groups()
            target = targets.get(repository)
            if target is None or target["branch"] != branch:
                raise LifecycleError(f"affected public repository {repository}@{branch} is not a qualified target")
            selected.append(repository)
    if len(selected) != len(set(selected)):
        raise LifecycleError("affected public repositories contain a duplicate target")
    if len(selected) < 2:
        raise LifecycleError("cross-repository lifecycle aggregation requires at least two public targets")
    return [dict(targets[repository]) for repository in sorted(selected)]


def _pull_identity(event: Mapping[str, Any], organization: str) -> tuple[str, int] | None:
    if event.get("event") != "cross-referenced" or event.get("will_close_target") is not True:
        return None
    source = event.get("source")
    source_issue = source.get("issue") if isinstance(source, Mapping) else None
    pull = source_issue.get("pull_request") if isinstance(source_issue, Mapping) else None
    if not isinstance(pull, Mapping):
        return None
    for field, pattern in (("url", API_PULL_PATTERN), ("html_url", HTML_PULL_PATTERN)):
        value = pull.get(field)
        match = pattern.search(value) if isinstance(value, str) else None
        if match is not None and match.group(1).casefold() == organization.casefold():
            return match.group(2), int(match.group(3))
    return None


def _latest_attempts(
    client: Any,
    organization: str,
    events: Sequence[Mapping[str, Any]],
    target_repositories: set[str],
) -> dict[str, dict[str, Any]]:
    attempts: dict[str, dict[str, Any]] = {}
    seen: set[tuple[str, int]] = set()
    for event in events:
        identity = _pull_identity(event, organization)
        if identity is None or identity in seen:
            continue
        seen.add(identity)
        repository, number = identity
        if repository not in target_repositories:
            continue
        pull = client.get_pull_request(organization, repository, number)
        created_at = pull.get("created_at")
        if not isinstance(created_at, str) or not created_at:
            raise LifecycleError(f"linked pull request {repository}#{number} has no creation time")
        current = attempts.get(repository)
        ordering = (created_at, number)
        if current is None or ordering > current["_ordering"]:
            attempts[repository] = {**pull, "_ordering": ordering}
    return attempts


def _evaluate_target(
    client: Any,
    organization: str,
    target: Mapping[str, Any],
    pull: Mapping[str, Any] | None,
) -> dict[str, Any]:
    repository = str(target["repository"])
    branch = str(target["branch"])
    required_checks = list(target["required_checks"])
    result: dict[str, Any] = {
        "branch": branch,
        "commit": None,
        "missing_checks": required_checks,
        "pull_request": None,
        "repository": repository,
        "state": "pending:no-linked-pull-request",
    }
    if pull is None:
        return result
    number = pull.get("number")
    html_url = pull.get("html_url")
    base = pull.get("base")
    base_repo = base.get("repo") if isinstance(base, Mapping) else None
    result["pull_request"] = html_url
    if (
        not isinstance(number, int)
        or not isinstance(html_url, str)
        or not isinstance(base, Mapping)
        or base.get("ref") != branch
        or not isinstance(base_repo, Mapping)
        or base_repo.get("full_name") != f"{organization}/{repository}"
    ):
        result["state"] = "pending:wrong-target"
        return result
    if pull.get("merged_at") is None:
        result["state"] = "pending:rejected" if pull.get("state") == "closed" else "pending:open"
        return result
    commit = pull.get("merge_commit_sha")
    if not isinstance(commit, str) or re.fullmatch(r"[0-9a-f]{40}", commit) is None:
        result["state"] = "pending:invalid-merge-commit"
        return result
    result["commit"] = commit
    if not client.commit_reaches_branch(organization, repository, commit, branch):
        result["state"] = "pending:landing-not-on-target"
        return result
    successful_checks = client.successful_check_names(organization, repository, commit)
    missing_checks = sorted(set(required_checks) - successful_checks)
    result["missing_checks"] = missing_checks
    if missing_checks:
        result["state"] = "pending:qualification"
        return result
    result["state"] = "complete"
    return result


def evaluate_lifecycle(
    client: Any,
    organization: str,
    source_repository: str,
    issue: Mapping[str, Any],
    targets: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Evaluate the latest linked implementation attempt for every declared target."""

    number = issue.get("number")
    if not isinstance(number, int):
        raise LifecycleError("cross-repository issue has no numeric identity")
    repositories = {str(target["repository"]) for target in targets}
    if len(repositories) != len(targets):
        raise LifecycleError("cross-repository lifecycle target set is duplicated")
    events = client.list_issue_timeline(organization, source_repository, number)
    attempts = _latest_attempts(client, organization, events, repositories)
    results = [
        _evaluate_target(client, organization, target, attempts.get(str(target["repository"]))) for target in targets
    ]
    return {
        "complete": bool(results) and all(result["state"] == "complete" for result in results),
        "targets": results,
    }


def render_evidence(assessment: Mapping[str, Any]) -> str:
    """Render one replaceable, public lifecycle evidence record."""

    rows = [
        f"{EVIDENCE_MARKER}",
        "Cross-repository landing evidence (generated from linked implementation pull requests):",
        "",
        "| Target | Latest attempt | Landing | Required qualification | State |",
        "| --- | --- | --- | --- | --- |",
    ]
    for target in assessment["targets"]:
        repository = target["repository"]
        branch = target["branch"]
        pull_url = target["pull_request"]
        attempt = f"[pull request]({pull_url})" if pull_url else "Not linked"
        commit = target["commit"]
        landing = (
            f"[`{commit[:12]}`](https://github.com/durable-workflow/{repository}/commit/{commit})"
            if commit
            else "Pending"
        )
        missing = target["missing_checks"]
        qualification = "Passed" if not missing else "Pending: " + ", ".join(f"`{name}`" for name in missing)
        rows.append(
            f"| `durable-workflow/{repository}@{branch}` | {attempt} | {landing} | "
            f"{qualification} | `{target['state']}` |"
        )
    rows.extend(
        [
            "",
            (
                "Every declared target landing and required repository qualification is complete."
                if assessment["complete"]
                else "The parent remains open until every declared target is complete."
            ),
        ]
    )
    return "\n".join(rows) + "\n"
