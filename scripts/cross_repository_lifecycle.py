"""Aggregate public landing evidence for one authoritative cross-repository issue."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from typing import Any

TARGET_HEADING = "### Required source targets"
TARGET_HEADING_PATTERN = re.compile(r"(?m)^#{2,3}[ \t]+Required source targets[ \t]*\r?$")
EVIDENCE_MARKER = "<!-- durable-workflow-cross-repository-lifecycle:v1 -->"
HTML_PULL_PATTERN = re.compile(r"https://github\.com/([^/]+)/([^/]+)/pull/([1-9][0-9]*)$")
COMMIT_PATTERN = re.compile(r"[0-9a-f]{40}")
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
WORKFLOW_PATH_PATTERN = re.compile(r"[A-Za-z0-9_.-]+\.ya?ml")
TRUSTED_REPOSITORY_ASSOCIATIONS = {"COLLABORATOR", "MEMBER", "OWNER"}
REFERENCE_SNAPSHOT_ATTEMPTS = 2
QualificationClaim = tuple[str | None, str | None, int]
RecordedTarget = tuple[str, str, str, tuple[str, ...], tuple[QualificationClaim, ...], str | None]
RecordedCompletion = tuple[str, tuple[RecordedTarget, ...]]


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
        required_workflows: list[dict[str, str]] = []
        for workflow in workflows:
            check = workflow.get("required_check") if isinstance(workflow, Mapping) else None
            path = workflow.get("path") if isinstance(workflow, Mapping) else None
            if (
                not isinstance(check, str)
                or not check
                or not isinstance(path, str)
                or WORKFLOW_PATH_PATTERN.fullmatch(path) is None
            ):
                raise LifecycleError(f"target qualification policy has no required check for {repository}@{branch}")
            checks.append(check)
            required_workflows.append({"path": path, "required_check": check})
        workflow_paths = [workflow["path"] for workflow in required_workflows]
        if len(workflow_paths) != len(set(workflow_paths)) or len(checks) != len(set(checks)):
            raise LifecycleError(f"target qualification policy repeats workflow identity for {repository}@{branch}")
        if repository in reduced:
            raise LifecycleError(f"target qualification policy repeats repository {repository}")
        reduced[repository] = {
            "branch": branch,
            "repository": repository,
            "required_checks": sorted(set(checks)),
            "required_workflows": sorted(required_workflows, key=lambda workflow: workflow["path"]),
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
    if event.get("__typename") != "CrossReferencedEvent" or event.get("willCloseTarget") is not True:
        return None
    source = event.get("source")
    repository = source.get("repository") if isinstance(source, Mapping) else None
    name_with_owner = repository.get("nameWithOwner") if isinstance(repository, Mapping) else None
    number = source.get("number") if isinstance(source, Mapping) else None
    url = source.get("url") if isinstance(source, Mapping) else None
    match = HTML_PULL_PATTERN.fullmatch(url) if isinstance(url, str) else None
    if (
        not isinstance(source, Mapping)
        or source.get("__typename") != "PullRequest"
        or not isinstance(name_with_owner, str)
        or REPOSITORY_PATTERN.fullmatch(name_with_owner) is None
        or type(number) is not int
        or number < 1
        or match is None
    ):
        return None
    owner, repository_name = name_with_owner.split("/", 1)
    if (
        owner.casefold() != organization.casefold()
        or match.group(1).casefold() != organization.casefold()
        or match.group(2) != repository_name
        or int(match.group(3)) != number
    ):
        return None
    return repository_name, number


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


def _closing_reference_snapshot(
    events: Sequence[Mapping[str, Any]],
    organization: str,
    target_repositories: set[str],
) -> tuple[tuple[str, int, str, str, str, bool], ...]:
    """Bind every target-relevant positive closing reference to its exact authority fields."""

    snapshot: list[tuple[str, int, str, str, str, bool]] = []
    for event in events:
        identity = _pull_identity(event, organization)
        if identity is None or identity[0] not in target_repositories:
            continue
        reference_id = event.get("id")
        referenced_at = event.get("referencedAt")
        actor = event.get("actor")
        actor_login = actor.get("login") if isinstance(actor, Mapping) else None
        if (
            not isinstance(reference_id, str)
            or not reference_id
            or _utc_timestamp(referenced_at) is None
            or not isinstance(referenced_at, str)
            or not isinstance(actor_login, str)
            or not actor_login
        ):
            continue
        snapshot.append((identity[0], identity[1], reference_id, referenced_at, actor_login, True))
    return tuple(sorted(snapshot))


def pending_reference_change(assessment: Mapping[str, Any]) -> dict[str, Any]:
    """Fail a stale assessment closed without carrying completed landing evidence forward."""

    targets = []
    for value in assessment["targets"]:
        target = dict(value)
        target["commit"] = None
        target["state"] = "pending:closing-reference-changed"
        targets.append(target)
    return {
        "_authority_kind": assessment.get("_authority_kind"),
        "_closing_reference_snapshot": assessment.get("_closing_reference_snapshot", ()),
        "_completion_record_identity": assessment.get("_completion_record_identity"),
        "complete": False,
        "targets": targets,
    }


def closing_references_are_current(
    client: Any,
    organization: str,
    source_repository: str,
    issue: Mapping[str, Any],
    assessment: Mapping[str, Any],
) -> bool:
    """Re-read GraphQL authority and compare it with the snapshot that produced an assessment."""

    number = issue.get("number")
    if not isinstance(number, int):
        raise LifecycleError("cross-repository issue has no numeric identity")
    repositories = {str(target["repository"]) for target in assessment["targets"]}
    events = client.list_issue_closing_references(organization, source_repository, number)
    return _closing_reference_snapshot(events, organization, repositories) == assessment.get(
        "_closing_reference_snapshot"
    )


def _pipeline_completion_record(
    body: str,
    organization: str,
    source_repository: str,
    targets: Sequence[Mapping[str, Any]],
) -> RecordedCompletion | None:
    """Read the exact immutable landing and run identities emitted by the protected merge gate."""

    expected: dict[tuple[str, str], tuple[tuple[str, ...], tuple[str, ...]]] = {}
    for target in targets:
        required_workflows = target.get("required_workflows")
        if not isinstance(required_workflows, Sequence) or isinstance(required_workflows, str | bytes):
            return None
        workflow_paths = tuple(
            sorted(
                str(workflow.get("path"))
                for workflow in required_workflows
                if isinstance(workflow, Mapping)
                and isinstance(workflow.get("path"), str)
                and WORKFLOW_PATH_PATTERN.fullmatch(str(workflow["path"])) is not None
            )
        )
        if not workflow_paths or len(workflow_paths) != len(required_workflows):
            return None
        expected[(str(target["repository"]), str(target["branch"]))] = (
            tuple(sorted(set(target["required_checks"]))),
            workflow_paths,
        )
    source_targets = [identity for identity in expected if identity[0] == source_repository]
    if len(source_targets) != 1:
        return None
    source_branch = source_targets[0][1]
    lines = body.splitlines()
    source_commit_url = rf"https://github\.com/{re.escape(organization)}/{re.escape(source_repository)}/commit/"
    linked_commit = rf"\[`([0-9a-f]{{7,40}})`\]\({source_commit_url}({COMMIT_PATTERN.pattern})\)"
    primary_pattern = re.compile(rf"Completed in {linked_commit} on `({re.escape(source_branch)})`\.")
    primary_matches = [match for line in lines if (match := primary_pattern.fullmatch(line.strip())) is not None]
    implementation_pattern = re.compile(
        rf"Implemented in {linked_commit}(?: on `{re.escape(source_branch)}`)?\."
    )
    completion_pattern = re.compile(
        rf"Included by completion source {linked_commit}(?: on `{re.escape(source_branch)}`)?\."
    )
    implementation_matches = [
        match for line in lines if (match := implementation_pattern.fullmatch(line.strip())) is not None
    ]
    completion_matches = [
        match for line in lines if (match := completion_pattern.fullmatch(line.strip())) is not None
    ]
    implementation_commit: str | None = None
    if (
        len(primary_matches) == 1
        and not implementation_matches
        and not completion_matches
        and primary_matches[0].group(2).startswith(primary_matches[0].group(1))
    ):
        source_commit = primary_matches[0].group(2)
    elif (
        not primary_matches
        and len(implementation_matches) == 1
        and len(completion_matches) == 1
        and implementation_matches[0].group(2).startswith(implementation_matches[0].group(1))
        and completion_matches[0].group(2).startswith(completion_matches[0].group(1))
    ):
        implementation_commit = implementation_matches[0].group(2)
        source_commit = completion_matches[0].group(2)
        if implementation_commit == source_commit:
            return None
    else:
        return None

    source_run_url = (
        rf"https://github\.com/{re.escape(organization)}/{re.escape(source_repository)}/actions/runs/"
    )
    legacy_source_qualification_pattern = re.compile(
        r"Required public qualification passed: " + source_run_url + r"([1-9][0-9]*)"
    )
    named_source_qualification_patterns = (
        re.compile(
            r"Required public qualification (?P<name>[A-Za-z0-9][A-Za-z0-9 ._+:/-]*?) "
            r"\(`?(?P<path>[A-Za-z0-9_.-]+\.ya?ml)`?\) passed in run "
            r"\[(?P<run>[1-9][0-9]*)\]\(" + source_run_url + r"(?P<url_run>[1-9][0-9]*)\)\.?"
        ),
        re.compile(
            r"Required public qualification (?P<name>[A-Za-z0-9][A-Za-z0-9 ._+:/-]*?) "
            r"\(`?(?P<path>[A-Za-z0-9_.-]+\.ya?ml)`?\) passed in run "
            r"(?P<run>[1-9][0-9]*) \(" + source_run_url + r"(?P<url_run>[1-9][0-9]*)\)\.?"
        ),
        re.compile(
            r"Required public qualification (?P<name>[A-Za-z0-9][A-Za-z0-9 ._+:/-]*?) "
            r"\(`?(?P<path>[A-Za-z0-9_.-]+\.ya?ml)`?\) passed in run "
            r"(?P<run>[1-9][0-9]*): " + source_run_url + r"(?P<url_run>[1-9][0-9]*)\.?"
        ),
        re.compile(
            r"Required public qualification `(?P<name>[A-Za-z0-9][A-Za-z0-9 ._+:/-]*?)` "
            r"\(`?(?P<path>[A-Za-z0-9_.-]+\.ya?ml)`?\) passed in "
            r"\[run (?P<run>[1-9][0-9]*)\]\(" + source_run_url + r"(?P<url_run>[1-9][0-9]*)\)\.?"
        ),
    )
    legacy_source_runs = [
        match
        for line in lines
        if (match := legacy_source_qualification_pattern.fullmatch(line.strip())) is not None
    ]
    named_source_runs = [
        match
        for line in lines
        for pattern in named_source_qualification_patterns
        if (match := pattern.fullmatch(line.strip())) is not None
    ]
    source_workflow_paths = expected[(source_repository, source_branch)][1]
    source_qualifications: tuple[QualificationClaim, ...]
    if len(legacy_source_runs) == 1 and not named_source_runs:
        source_qualifications = ((None, None, int(legacy_source_runs[0].group(1))),)
    elif not legacy_source_runs and named_source_runs:
        claims = [
            (match.group("name"), match.group("path"), int(match.group("run")))
            for match in named_source_runs
            if match.group("run") == match.group("url_run") and match.group("path") in source_workflow_paths
        ]
        if len(claims) != len(named_source_runs) or len(claims) != len(set(claims)):
            return None
        source_qualifications = tuple(sorted(claims, key=lambda claim: (claim[1], claim[2], claim[0] or "")))
    else:
        return None

    peer_heading = "Required cross-repository target qualification passed:"
    headings = [index for index, line in enumerate(lines) if line.strip() == peer_heading]
    if len(headings) != 1:
        return None
    peer_pattern = re.compile(
        rf"- `([a-z0-9_.-]+):(main|v2)` at \[`([0-9a-f]{{7,40}})`\]\("
        rf"https://github\.com/{re.escape(organization)}/([a-z0-9_.-]+)/commit/"
        rf"({COMMIT_PATTERN.pattern})\) (?P<qualification>.+)"
    )
    peer_records: list[RecordedTarget] = []
    peer_lines_started = False
    for line in lines[headings[0] + 1 :]:
        stripped = line.strip()
        if not stripped:
            if peer_lines_started:
                break
            continue
        if not stripped.startswith("- "):
            if peer_lines_started:
                break
            return None
        peer_lines_started = True
        match = peer_pattern.fullmatch(stripped)
        if match is None:
            return None
        repository, branch, short_commit, url_repository, commit = match.groups()[:5]
        identity = (repository, branch)
        if (
            repository != url_repository
            or identity not in expected
            or repository == source_repository
            or not commit.startswith(short_commit)
        ):
            return None
        required_checks, workflow_paths = expected[identity]
        peer_run_url = rf"https://github\.com/{re.escape(organization)}/{re.escape(repository)}/actions/runs/"
        legacy_peer_pattern = re.compile(
            r"\(\[qualification\]\(" + peer_run_url + r"(?P<run>[1-9][0-9]*)\)\)"
        )
        named_peer_patterns = (
            re.compile(
                r"(?:; |\()Required (?:public|target) qualification "
                r"(?P<name>[A-Za-z0-9][A-Za-z0-9 ._+:/-]*?) "
                r"\(`?(?P<path>[A-Za-z0-9_.-]+\.ya?ml)`?\) passed in run "
                r"\[(?P<run>[1-9][0-9]*)\]\(" + peer_run_url + r"(?P<url_run>[1-9][0-9]*)\)\.?\)?"
            ),
            re.compile(
                r"\(\[(?P<name>[A-Za-z0-9][A-Za-z0-9 ._+:/-]*?) "
                r"\(`?(?P<path>[A-Za-z0-9_.-]+\.ya?ml)`?\)(?: passed in)? run "
                r"(?P<run>[1-9][0-9]*)\]\(" + peer_run_url + r"(?P<url_run>[1-9][0-9]*)\)\)"
            ),
        )
        qualification_text = match.group("qualification")
        legacy_peer = legacy_peer_pattern.fullmatch(qualification_text)
        named_peer = next(
            (candidate for pattern in named_peer_patterns if (candidate := pattern.fullmatch(qualification_text))),
            None,
        )
        if legacy_peer is not None and named_peer is None:
            qualifications = ((None, None, int(legacy_peer.group("run"))),)
        elif legacy_peer is None and named_peer is not None:
            if named_peer.group("run") != named_peer.group("url_run") or named_peer.group("path") not in workflow_paths:
                return None
            qualifications = (
                (named_peer.group("name"), named_peer.group("path"), int(named_peer.group("run"))),
            )
        else:
            return None
        peer_records.append((repository, branch, commit, required_checks, qualifications, None))

    expected_peers = set(expected) - set(source_targets)
    observed_peers = [
        (repository, branch)
        for repository, branch, _commit, _checks, _qualifications, _implementation_commit in peer_records
    ]
    if (
        not peer_lines_started
        or len(observed_peers) != len(set(observed_peers))
        or set(observed_peers) != expected_peers
    ):
        return None

    marker_pattern = re.compile(rf"<!--\s*durable-workflow-completion-source:\s*({COMMIT_PATTERN.pattern})\s*-->")
    marker_matches = marker_pattern.findall(body)
    if (
        len(marker_matches) != 1
        or body.count("durable-workflow-completion-source:") != 1
        or marker_matches[0] != source_commit
    ):
        return None
    if implementation_commit is not None:
        implementation_marker_pattern = re.compile(
            rf"<!--\s*durable-workflow-implementation-source:\s*({COMMIT_PATTERN.pattern})\s*-->"
        )
        implementation_marker_matches = implementation_marker_pattern.findall(body)
        if (
            len(implementation_marker_matches) != 1
            or body.count("durable-workflow-implementation-source:") != 1
            or implementation_marker_matches[0] != implementation_commit
        ):
            return None
    records = [
        (
            source_repository,
            source_branch,
            source_commit,
            expected[(source_repository, source_branch)][0],
            source_qualifications,
            implementation_commit,
        )
    ]
    records.extend(peer_records)
    return marker_matches[0], tuple(sorted(records))


def _recorded_completion(
    client: Any,
    organization: str,
    source_repository: str,
    issue: Mapping[str, Any],
    targets: Sequence[Mapping[str, Any]],
) -> RecordedCompletion | None:
    """Select one semantically exact aggregate record from the authenticated lifecycle writer."""

    number = issue.get("number")
    if not isinstance(number, int):
        raise LifecycleError("cross-repository issue has no numeric identity")
    candidates = {
        record
        for comment in client.list_trusted_issue_comments(organization, source_repository, number)
        if isinstance(comment, Mapping)
        and isinstance(comment.get("body"), str)
        and (
            record := _pipeline_completion_record(
                comment["body"],
                organization,
                source_repository,
                targets,
            )
        )
        is not None
    }
    if len(candidates) > 1:
        raise LifecycleError("trusted cross-repository completion records disagree")
    return next(iter(candidates)) if candidates else None


def lifecycle_authority_is_current(
    client: Any,
    organization: str,
    source_repository: str,
    issue: Mapping[str, Any],
    assessment: Mapping[str, Any],
) -> bool:
    """Re-read the authority source that produced a complete lifecycle assessment."""

    if not closing_references_are_current(client, organization, source_repository, issue, assessment):
        return False
    if assessment.get("_authority_kind") not in {"mixed-landing-record", "protected-branch-record"}:
        return True
    targets = [
        {
            "branch": target["branch"],
            "repository": target["repository"],
            "required_checks": target["required_checks"],
            "required_workflows": target["required_workflows"],
        }
        for target in assessment["targets"]
    ]
    return _recorded_completion(client, organization, source_repository, issue, targets) == assessment.get(
        "_completion_record_identity"
    )


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
            "reference_at": event["referencedAt"],
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
    for index, event in enumerate(events):
        identity = _pull_identity(event, organization)
        if identity is None:
            continue
        reference_at = _utc_timestamp(event.get("referencedAt"))
        reference_id = event.get("id")
        if reference_at is None or not isinstance(reference_id, str) or not reference_id:
            invalid_references.add(identity)
            references.pop(identity, None)
            continue
        if identity in invalid_references:
            continue
        ordering = (reference_at, index)
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
    required_workflows = [dict(workflow) for workflow in target.get("required_workflows", ())]
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
        "required_checks": required_checks,
        "required_workflows": required_workflows,
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


def _evaluate_recorded_target(
    client: Any,
    organization: str,
    target: Mapping[str, Any],
    completion: RecordedTarget,
    completion_source: str,
) -> dict[str, Any]:
    """Independently revalidate one exact commit from a trusted aggregate completion record."""

    repository, branch, commit, required_checks, qualifications, implementation_commit = completion
    required_workflows = [dict(workflow) for workflow in target.get("required_workflows", ())]
    result: dict[str, Any] = {
        "approval_at": None,
        "approval_review": None,
        "base_commit": None,
        "base_ref": None,
        "base_repository": None,
        "branch": branch,
        "commit": commit,
        "completion_source": completion_source,
        "head_commit": None,
        "head_ref": None,
        "head_repository": None,
        "implementation_commit": implementation_commit,
        "missing_checks": list(required_checks),
        "provenance": "authenticated-completion-record",
        "pull_author": None,
        "pull_request": None,
        "qualification_runs": [
            {"name": name, "path": path, "run": run_id} for name, path, run_id in qualifications
        ],
        "reference_actor": None,
        "reference_at": None,
        "reference_event": None,
        "repository": repository,
        "required_check_runs": {},
        "required_checks": list(required_checks),
        "required_workflows": required_workflows,
        "state": "pending:landing-not-on-target",
    }
    if repository != target["repository"] or branch != target["branch"]:
        result["state"] = "pending:wrong-target"
        return result
    if tuple(sorted(set(target["required_checks"]))) != required_checks:
        result["state"] = "pending:qualification-identity"
        return result
    if not client.commit_reaches_branch(organization, repository, commit, branch):
        return result
    if implementation_commit is not None and not client.commit_reaches_branch(
        organization, repository, implementation_commit, branch
    ):
        return result
    expected_workflow_paths = {
        str(workflow.get("path")) for workflow in required_workflows if isinstance(workflow.get("path"), str)
    }
    if (
        not qualifications
        or any(
            path is not None and path not in expected_workflow_paths
            for _name, path, _run_id in qualifications
        )
        or any(
            not client.successful_workflow_run(
                organization,
                repository,
                run_id,
                commit,
                path,
                name,
            )
            for name, path, run_id in qualifications
        )
    ):
        result["state"] = "pending:qualification-identity"
        return result
    successful_checks = client.successful_check_run_ids(organization, repository, commit)
    result["required_check_runs"] = {
        check: successful_checks[check] for check in required_checks if check in successful_checks
    }
    missing_checks = sorted(set(required_checks) - set(successful_checks))
    result["missing_checks"] = missing_checks
    if missing_checks:
        result["state"] = "pending:qualification"
    else:
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
    """Evaluate attempts only from a bounded, convergent closing-reference snapshot."""

    number = issue.get("number")
    if not isinstance(number, int):
        raise LifecycleError("cross-repository issue has no numeric identity")
    repositories = {str(target["repository"]) for target in targets}
    if len(repositories) != len(targets):
        raise LifecycleError("cross-repository lifecycle target set is duplicated")
    trusted = {actor.casefold() for actor in trusted_actors if isinstance(actor, str) and actor}
    if not trusted:
        raise LifecycleError("cross-repository lifecycle has no trusted execution actors")
    assessment: dict[str, Any] | None = None
    for _attempt in range(REFERENCE_SNAPSHOT_ATTEMPTS):
        events = client.list_issue_closing_references(organization, source_repository, number)
        snapshot = _closing_reference_snapshot(events, organization, repositories)
        attempts = _latest_attempts(client, organization, events, repositories, trusted)
        results = [
            _evaluate_target(client, organization, target, attempts.get(str(target["repository"])))
            for target in targets
        ]
        authority_kind = "closing-references"
        completion_record = None
        if results and any(result["state"] == "pending:no-linked-pull-request" for result in results):
            completion_record = _recorded_completion(
                client,
                organization,
                source_repository,
                issue,
                targets,
            )
            if completion_record is not None:
                completion_source, recorded_targets = completion_record
                by_repository = {record[0]: record for record in recorded_targets}
                recorded_results = [
                    _evaluate_recorded_target(
                        client,
                        organization,
                        target,
                        by_repository[str(target["repository"])],
                        completion_source,
                    )
                    for target in targets
                ]
                results = [
                    recorded
                    if current["state"] == "pending:no-linked-pull-request" or recorded["state"] != "complete"
                    else current
                    for current, recorded in zip(results, recorded_results, strict=True)
                ]
                authority_kind = (
                    "protected-branch-record"
                    if all(result["provenance"] == "authenticated-completion-record" for result in results)
                    else "mixed-landing-record"
                )
        assessment = {
            "_authority_kind": authority_kind,
            "_closing_reference_snapshot": snapshot,
            "_completion_record_identity": completion_record,
            "complete": bool(results) and all(result["state"] == "complete" for result in results),
            "targets": results,
        }
        final_events = client.list_issue_closing_references(organization, source_repository, number)
        if _closing_reference_snapshot(final_events, organization, repositories) == snapshot:
            return assessment
    if assessment is None:
        raise LifecycleError("cross-repository lifecycle did not evaluate a closing-reference snapshot")
    return pending_reference_change(assessment)


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
        "Cross-repository landing evidence (generated from trusted implementation pull requests or authenticated "
        "protected-branch completion records):",
    ]
    completion_record = assessment.get("_completion_record_identity")
    if (
        assessment.get("_authority_kind") in {"mixed-landing-record", "protected-branch-record"}
        and isinstance(completion_record, tuple)
        and completion_record
    ):
        rows.append(f"Completion source: `{completion_record[0]}`")
    rows.extend(
        [
            "",
            "| Target | Latest attempt | Bound provenance | Landing | Required qualification | State |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for target in assessment["targets"]:
        repository = target["repository"]
        branch = target["branch"]
        pull_url = target["pull_request"]
        attempt = (
            f"[pull request]({pull_url})"
            if pull_url
            else "Authenticated protected-branch completion record"
            if target.get("provenance") == "authenticated-completion-record"
            else "Not linked"
        )
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
        if provenance == "authenticated-completion-record":
            bound_provenance = "Authenticated lifecycle-writer record; exact commit revalidated on protected branch"
        elif (
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
        ):
            bound_provenance = (
                f"head [`{head_repository}@{head_ref}`]"
                f"(https://github.com/{head_repository}/commit/{head_commit}) "
                f"`{head_commit[:12]}` → base "
                f"[`{base_repository}@{base_ref}`]"
                f"(https://github.com/{base_repository}/commit/{base_commit}) "
                f"`{base_commit[:12]}`; `{provenance}`; "
                f"author `{pull_author}`; reference actor `{reference_actor}`"
                f"{authority_binding}"
            )
        else:
            bound_provenance = "Pending"
        commit = target["commit"]
        implementation_commit = target.get("implementation_commit")
        if commit and isinstance(implementation_commit, str):
            landing = (
                f"completion [`{commit[:12]}`](https://github.com/durable-workflow/{repository}/commit/{commit}); "
                f"implementation [`{implementation_commit[:12]}`]"
                f"(https://github.com/durable-workflow/{repository}/commit/{implementation_commit})"
            )
        elif commit:
            landing = f"[`{commit[:12]}`](https://github.com/durable-workflow/{repository}/commit/{commit})"
        else:
            landing = "Pending"
        missing = target["missing_checks"]
        required_checks = target["required_checks"]
        required_check_runs = target.get("required_check_runs", {})
        check_identity = ", ".join(
            (
                f"`{name}` ([check run `{required_check_runs[name]}`]"
                f"(https://github.com/durable-workflow/{repository}/actions/runs/{required_check_runs[name]}))"
                if name in required_check_runs
                else f"`{name}`"
            )
            for name in required_checks
        )
        qualification_runs = target.get("qualification_runs", [])
        cited_runs = []
        for qualification_run in qualification_runs:
            if not isinstance(qualification_run, Mapping) or not isinstance(qualification_run.get("run"), int):
                continue
            run_id = qualification_run["run"]
            workflow_name = qualification_run.get("name")
            workflow_path = qualification_run.get("path")
            workflow_identity = (
                f"`{workflow_name}` (`{workflow_path}`)"
                if isinstance(workflow_name, str) and isinstance(workflow_path, str)
                else f"`{workflow_path}`"
                if isinstance(workflow_path, str)
                else "legacy generic qualification"
            )
            cited_runs.append(
                f"{workflow_identity} [cited run `{run_id}`]"
                f"(https://github.com/durable-workflow/{repository}/actions/runs/{run_id})"
            )
        run_identity = f"; cited qualification: {', '.join(cited_runs)}" if cited_runs else ""
        qualification = (
            "Pending: closing-reference authority changed"
            if target["state"] == "pending:closing-reference-changed"
            else f"Passed: {check_identity}{run_identity}"
            if target["state"] == "complete"
            else "Pending: "
            + ", ".join(f"`{name}`" for name in missing)
            + f"; required: {check_identity}{run_identity}"
            if missing
            else f"Required: {check_identity}{run_identity}"
        )
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
