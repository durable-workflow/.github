"""Aggregate public landing evidence for one authoritative cross-repository issue."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

TARGET_HEADING = "### Required source targets"
TARGET_HEADING_PATTERN = re.compile(r"(?m)^#{2,3}[ \t]+Required source targets[ \t]*\r?$")
EVIDENCE_MARKER = "<!-- durable-workflow-cross-repository-lifecycle:v1 -->"
API_PULL_PATTERN = re.compile(r"/repos/([^/]+)/([^/]+)/pulls/([1-9][0-9]*)$")
HTML_PULL_PATTERN = re.compile(r"https://github\.com/([^/]+)/([^/]+)/pull/([1-9][0-9]*)$")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
TRUSTED_REPOSITORY_ASSOCIATIONS = {"COLLABORATOR", "MEMBER", "OWNER"}


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
    required: bool = False,
) -> list[dict[str, Any]]:
    """Read exact form selections from the bounded affected-repositories section."""

    headings = list(TARGET_HEADING_PATTERN.finditer(body))
    if not headings:
        if required:
            raise LifecycleError("cross-repository authority must declare its required source targets")
        return []
    if len(headings) != 1:
        raise LifecycleError("cross-repository issue repeats its affected public repositories section")
    section = body[headings[0].end() :]
    section = re.split(r"(?m)^#{1,6}[ \t]+", section, maxsplit=1)[0]
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


def _utc_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if timestamp.tzinfo is None:
        return None
    return timestamp.astimezone(UTC)


def _approved_head_reviewer(
    client: Any,
    organization: str,
    repository: str,
    number: int,
    head_sha: str,
    reference_at: datetime,
    trusted_actors: set[str],
) -> tuple[str, str, int] | None:
    """Return an authorized exact-head approval recorded after the closing reference."""

    latest_by_reviewer: dict[tuple[int, str], tuple[tuple[datetime, int], Mapping[str, Any]]] = {}
    for review in client.list_pull_request_reviews(organization, repository, number):
        if not isinstance(review, Mapping) or review.get("commit_id") != head_sha:
            continue
        user = review.get("user")
        identifier = user.get("id") if isinstance(user, Mapping) else None
        login = user.get("login") if isinstance(user, Mapping) else None
        review_id = review.get("id")
        submitted_at = review.get("submitted_at")
        submitted_timestamp = _utc_timestamp(submitted_at)
        if (
            type(identifier) is not int
            or identifier < 1
            or not isinstance(login, str)
            or not login
            or type(review_id) is not int
            or review_id < 1
            or submitted_timestamp is None
        ):
            continue
        reviewer = (identifier, login.casefold())
        ordering = (submitted_timestamp, review_id)
        if reviewer not in latest_by_reviewer or ordering > latest_by_reviewer[reviewer][0]:
            latest_by_reviewer[reviewer] = (ordering, review)
    for reviewer in sorted(latest_by_reviewer):
        ordering, review = latest_by_reviewer[reviewer]
        user = review["user"]
        login = str(user["login"])
        if (
            ordering[0] > reference_at
            and review.get("state") == "APPROVED"
            and (
                login.casefold() in trusted_actors
                or review.get("author_association") in TRUSTED_REPOSITORY_ASSOCIATIONS
            )
        ):
            return login, str(review["submitted_at"]), int(review["id"])
    return None


def _trusted_pull_request(
    client: Any,
    organization: str,
    repository: str,
    number: int,
    event: Mapping[str, Any],
    reference_at: datetime,
    pull: Mapping[str, Any],
    trusted_actors: set[str],
) -> dict[str, Any] | None:
    """Bind exact pull metadata and admit only trusted or explicitly approved work."""

    target_repository = f"{organization}/{repository}"
    expected_api_url = f"https://api.github.com/repos/{target_repository}/pulls/{number}"
    expected_html_url = f"https://github.com/{target_repository}/pull/{number}"
    actor = event.get("actor")
    actor_login = actor.get("login") if isinstance(actor, Mapping) else None
    user = pull.get("user")
    author_login = user.get("login") if isinstance(user, Mapping) else None
    base = pull.get("base")
    base_repo = base.get("repo") if isinstance(base, Mapping) else None
    head = pull.get("head")
    head_repo = head.get("repo") if isinstance(head, Mapping) else None
    base_ref = base.get("ref") if isinstance(base, Mapping) else None
    base_sha = base.get("sha") if isinstance(base, Mapping) else None
    head_ref = head.get("ref") if isinstance(head, Mapping) else None
    head_sha = head.get("sha") if isinstance(head, Mapping) else None
    head_repository = head_repo.get("full_name") if isinstance(head_repo, Mapping) else None
    author_association = pull.get("author_association")
    if (
        pull.get("number") != number
        or pull.get("url") != expected_api_url
        or pull.get("html_url") != expected_html_url
        or not isinstance(actor_login, str)
        or not actor_login
        or not isinstance(author_login, str)
        or not author_login
        or not isinstance(author_association, str)
        or not isinstance(base, Mapping)
        or not isinstance(base_repo, Mapping)
        or base_repo.get("full_name") != target_repository
        or not isinstance(base_ref, str)
        or not base_ref
        or not isinstance(base_sha, str)
        or COMMIT_PATTERN.fullmatch(base_sha) is None
        or not isinstance(head, Mapping)
        or not isinstance(head_repo, Mapping)
        or not isinstance(head_repository, str)
        or REPOSITORY_PATTERN.fullmatch(head_repository) is None
        or not isinstance(head_ref, str)
        or not head_ref
        or not isinstance(head_sha, str)
        or COMMIT_PATTERN.fullmatch(head_sha) is None
    ):
        return None
    trusted_author = author_login.casefold() in trusted_actors or author_association in TRUSTED_REPOSITORY_ASSOCIATIONS
    trusted_reference_actor = actor_login.casefold() in trusted_actors or (
        actor_login.casefold() == author_login.casefold()
    )
    trusted_execution = head_repository == target_repository and trusted_author and trusted_reference_actor
    approval = None
    if not trusted_execution:
        approval = _approved_head_reviewer(
            client,
            organization,
            repository,
            number,
            head_sha,
            reference_at,
            trusted_actors,
        )
    if not trusted_execution and approval is None:
        return None
    approved_by = approval[0] if approval is not None else None
    provenance = f"trusted-author:{author_login}" if trusted_execution else f"approved:{approved_by}"
    return {
        **pull,
        "_provenance": {
            "actor": actor_login,
            "approval_at": approval[1] if approval is not None else None,
            "approval_review": approval[2] if approval is not None else None,
            "author": author_login,
            "base_ref": base_ref,
            "base_repository": target_repository,
            "base_sha": base_sha,
            "head_ref": head_ref,
            "head_repository": head_repository,
            "head_sha": head_sha,
            "kind": provenance,
            "reference_at": event["created_at"],
            "reference_event": event["id"],
        },
    }


def _latest_attempts(
    client: Any,
    organization: str,
    events: Sequence[Mapping[str, Any]],
    target_repositories: set[str],
    trusted_actors: set[str],
) -> dict[str, dict[str, Any]]:
    attempts: dict[str, dict[str, Any]] = {}
    references: dict[tuple[str, int], tuple[tuple[datetime, int], Mapping[str, Any]]] = {}
    invalid_references: set[tuple[str, int]] = set()
    for event in events:
        identity = _pull_identity(event, organization)
        if identity is None:
            continue
        reference_at = _utc_timestamp(event.get("created_at"))
        reference_id = event.get("id")
        if reference_at is None or type(reference_id) is not int or reference_id < 1:
            invalid_references.add(identity)
            references.pop(identity, None)
            continue
        if identity in invalid_references:
            continue
        ordering = (reference_at, reference_id)
        if identity not in references or ordering > references[identity][0]:
            references[identity] = (ordering, event)
    for (repository, number), (reference_ordering, event) in sorted(references.items()):
        if repository not in target_repositories:
            continue
        pull = client.get_pull_request(organization, repository, number)
        trusted_pull = _trusted_pull_request(
            client,
            organization,
            repository,
            number,
            event,
            reference_ordering[0],
            pull,
            trusted_actors,
        )
        if trusted_pull is None:
            continue
        created_at = trusted_pull.get("created_at")
        if not isinstance(created_at, str) or not created_at:
            raise LifecycleError(f"linked pull request {repository}#{number} has no creation time")
        current = attempts.get(repository)
        ordering = (created_at, number)
        if current is None or ordering > current["_ordering"]:
            attempts[repository] = {**trusted_pull, "_ordering": ordering}
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
        "approval_at": None,
        "approval_review": None,
        "base_commit": None,
        "base_ref": None,
        "base_repository": None,
        "branch": branch,
        "commit": None,
        "head_commit": None,
        "head_ref": None,
        "head_repository": None,
        "missing_checks": required_checks,
        "pull_author": None,
        "provenance": None,
        "pull_request": None,
        "reference_actor": None,
        "reference_at": None,
        "reference_event": None,
        "repository": repository,
        "state": "pending:no-linked-pull-request",
    }
    if pull is None:
        return result
    number = pull.get("number")
    html_url = pull.get("html_url")
    base = pull.get("base")
    base_repo = base.get("repo") if isinstance(base, Mapping) else None
    provenance = pull.get("_provenance")
    result["pull_request"] = html_url
    if not isinstance(provenance, Mapping):
        raise LifecycleError(f"linked pull request {repository}#{number} has no trusted provenance")
    result["approval_at"] = provenance["approval_at"]
    result["approval_review"] = provenance["approval_review"]
    result["base_commit"] = provenance["base_sha"]
    result["base_ref"] = provenance["base_ref"]
    result["base_repository"] = provenance["base_repository"]
    result["head_commit"] = provenance["head_sha"]
    result["head_ref"] = provenance["head_ref"]
    result["head_repository"] = provenance["head_repository"]
    result["pull_author"] = provenance["author"]
    result["provenance"] = provenance["kind"]
    result["reference_actor"] = provenance["actor"]
    result["reference_at"] = provenance["reference_at"]
    result["reference_event"] = provenance["reference_event"]
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
    if not isinstance(commit, str) or COMMIT_PATTERN.fullmatch(commit) is None:
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
    *,
    trusted_actors: Sequence[str],
) -> dict[str, Any]:
    """Evaluate the latest linked implementation attempt for every declared target."""

    number = issue.get("number")
    if not isinstance(number, int):
        raise LifecycleError("cross-repository issue has no numeric identity")
    repositories = {str(target["repository"]) for target in targets}
    if len(repositories) != len(targets):
        raise LifecycleError("cross-repository lifecycle target set is duplicated")
    trusted = {actor.casefold() for actor in trusted_actors if isinstance(actor, str) and actor}
    if not trusted:
        raise LifecycleError("cross-repository lifecycle has no trusted execution actors")
    events = client.list_issue_timeline(organization, source_repository, number)
    attempts = _latest_attempts(client, organization, events, repositories, trusted)
    results = [
        _evaluate_target(client, organization, target, attempts.get(str(target["repository"]))) for target in targets
    ]
    return {
        "complete": bool(results) and all(result["state"] == "complete" for result in results),
        "targets": results,
    }


def evaluate_recorded_landings(
    client: Any,
    organization: str,
    landings: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Revalidate immutable protected-branch evidence for an archived aggregate."""

    repositories = {str(landing.get("repository")) for landing in landings}
    if not landings or len(repositories) != len(landings):
        raise LifecycleError("historical cross-repository landing evidence is empty or duplicated")
    results: list[dict[str, Any]] = []
    for landing in landings:
        repository = landing.get("repository")
        branch = landing.get("branch")
        commit = landing.get("commit")
        required_checks = landing.get("required_checks")
        if (
            not isinstance(repository, str)
            or not repository
            or not isinstance(branch, str)
            or not branch
            or not isinstance(commit, str)
            or COMMIT_PATTERN.fullmatch(commit) is None
            or not isinstance(required_checks, Sequence)
            or isinstance(required_checks, str | bytes)
            or any(not isinstance(check, str) or not check for check in required_checks)
        ):
            raise LifecycleError("historical cross-repository landing evidence is malformed")
        result = {
            "branch": branch,
            "commit": commit,
            "missing_checks": list(required_checks),
            "repository": repository,
            "state": "pending:landing-not-on-target",
        }
        if client.commit_reaches_branch(organization, repository, commit, branch):
            missing_checks = sorted(
                set(required_checks) - client.successful_check_names(organization, repository, commit)
            )
            result["missing_checks"] = missing_checks
            result["state"] = "pending:qualification" if missing_checks else "complete"
        results.append(result)
    return {
        "complete": all(result["state"] == "complete" for result in results),
        "targets": results,
    }


def render_evidence(assessment: Mapping[str, Any]) -> str:
    """Render one replaceable, public lifecycle evidence record."""

    rows = [
        f"{EVIDENCE_MARKER}",
        "Cross-repository landing evidence (generated from trusted implementation pull requests):",
        "",
        "| Target | Latest attempt | Bound provenance | Landing | Required qualification | State |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for target in assessment["targets"]:
        repository = target["repository"]
        branch = target["branch"]
        pull_url = target["pull_request"]
        attempt = f"[pull request]({pull_url})" if pull_url else "Not linked"
        head_commit = target["head_commit"]
        head_repository = target["head_repository"]
        head_ref = target["head_ref"]
        base_commit = target["base_commit"]
        base_repository = target["base_repository"]
        base_ref = target["base_ref"]
        pull_author = target["pull_author"]
        provenance = target["provenance"]
        reference_actor = target["reference_actor"]
        reference_at = target["reference_at"]
        reference_event = target["reference_event"]
        approval_at = target["approval_at"]
        approval_review = target["approval_review"]
        authority_binding = f"; reference event `{reference_event}` at `{reference_at}`"
        if approval_at and approval_review:
            authority_binding += f"; approval review `{approval_review}` at `{approval_at}`"
        bound_provenance = (
            f"head [`{head_repository}@{head_ref}`]"
            f"(https://github.com/{head_repository}/commit/{head_commit}) "
            f"`{head_commit[:12]}` → base "
            f"[`{base_repository}@{base_ref}`]"
            f"(https://github.com/{base_repository}/commit/{base_commit}) "
            f"`{base_commit[:12]}`; `{provenance}`; "
            f"author `{pull_author}`; reference actor `{reference_actor}`"
            f"{authority_binding}"
            if (
                head_commit
                and head_repository
                and head_ref
                and base_commit
                and base_repository
                and base_ref
                and pull_author
                and provenance
                and reference_actor
                and reference_at
                and reference_event
            )
            else "Pending"
        )
        commit = target["commit"]
        landing = (
            f"[`{commit[:12]}`](https://github.com/durable-workflow/{repository}/commit/{commit})"
            if commit
            else "Pending"
        )
        missing = target["missing_checks"]
        qualification = "Passed" if not missing else "Pending: " + ", ".join(f"`{name}`" for name in missing)
        rows.append(
            f"| `durable-workflow/{repository}@{branch}` | {attempt} | {bound_provenance} | {landing} | "
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
