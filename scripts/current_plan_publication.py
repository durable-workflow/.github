#!/usr/bin/env python3
"""Protect current-plan publication dispatch and its approved writer handoff."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

CONTROL_REPOSITORY = "durable-workflow/.github"
AUTHORITY_REF = "main"
OBSERVER_WORKFLOW = "release-plan-observer.yml"
OBSERVER_WORKFLOW_PATH = f".github/workflows/{OBSERVER_WORKFLOW}"
OBSERVER_WORKFLOW_REF = f"{CONTROL_REPOSITORY}/{OBSERVER_WORKFLOW_PATH}@refs/heads/{AUTHORITY_REF}"
CURRENT_PLAN_WORKFLOW = "current-release-plan.yml"
CURRENT_PLAN_WORKFLOW_PATH = f".github/workflows/{CURRENT_PLAN_WORKFLOW}"
CURRENT_PLAN_WORKFLOW_REF = (
    f"{CONTROL_REPOSITORY}/{CURRENT_PLAN_WORKFLOW_PATH}@refs/heads/{AUTHORITY_REF}"
)
CURRENT_PLAN_PATH = "release-plans/current.json"
CURRENT_PLAN_SCHEMA = "durable-workflow.release-plan/v2"
PLAN_TAG_PREFIX = "release-plan/"
BETA_AUTHORIZATION_ENVIRONMENT = "beta-authorization"
GITHUB_API_VERSION = "2022-11-28"
ACTIVE_RUN_STATUSES = ("waiting", "queued", "in_progress", "pending", "requested")
CURRENT_PLAN_RUN_EVENTS = frozenset(("push", "workflow_dispatch"))
RUN_PAGE_SIZE = 100
RUN_PAGE_LIMIT = 10
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
PLAN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,55}$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?$")
RFC3339_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
HANDOFF_DOMAIN = b"durable-workflow.current-plan-writer-approval/v1\0"


class CurrentPlanPublicationError(ValueError):
    """The current-plan publication authority is absent, mismatched, or ambiguous."""


class ActionsClient(Protocol):
    def get(self, path: str) -> Any: ...

    def post(self, path: str, payload: Any | None = None) -> Any: ...


@dataclass(frozen=True)
class PlanIdentity:
    tag: str
    sha256: str


@dataclass(frozen=True)
class CandidateIdentity:
    repository: str
    workflow: str
    ref: str
    source_sha: str
    plan: PlanIdentity


@dataclass(frozen=True)
class ActiveRun:
    run_id: int
    status: str
    source_sha: str
    created_at: dt.datetime
    url: str


@dataclass(frozen=True)
class ReconciliationResult:
    outcome: str
    retained_run_url: str | None
    cancelled_run_urls: tuple[str, ...]


class GitHubActionsClient:
    """A bounded client for exact Actions discovery, cancellation, and dispatch."""

    def __init__(self, token: str, api_url: str = "https://api.github.com") -> None:
        if not token:
            raise CurrentPlanPublicationError("current-plan publication GitHub token is absent")
        if api_url.rstrip("/") != "https://api.github.com":
            raise CurrentPlanPublicationError("current-plan publication GitHub API authority is mismatched")
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "durable-workflow-current-plan-publication/1",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }

    def request(self, method: str, path: str, payload: Any | None = None) -> Any:
        data = None if payload is None else json.dumps(payload).encode()
        request = urllib.request.Request(
            f"{self.api_url}{path}",
            data=data,
            headers=self.headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read()
        except urllib.error.HTTPError as error:
            detail = error.read(2048).decode(errors="replace").replace(self.token, "<redacted>")
            raise CurrentPlanPublicationError(
                f"GitHub {method} {path} failed ({error.code}): {detail}"
            ) from error
        except urllib.error.URLError as error:
            detail = str(error.reason).replace(self.token, "<redacted>")
            raise CurrentPlanPublicationError(f"GitHub {method} {path} failed: {detail}") from error
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise CurrentPlanPublicationError(f"GitHub {method} {path} returned invalid JSON") from error

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def post(self, path: str, payload: Any | None = None) -> Any:
        return self.request("POST", path, payload)


def _identity(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise CurrentPlanPublicationError(f"current-plan publication {label} is absent")
    return value


def validate_runtime_identity(repository: Any, ref: Any, workflow_ref: Any) -> None:
    repository = _identity(repository, "repository")
    ref = _identity(ref, "ref")
    workflow_ref = _identity(workflow_ref, "workflow identity")

    if repository != CONTROL_REPOSITORY:
        raise CurrentPlanPublicationError(
            "current-plan publication repository mismatch: "
            f"expected {CONTROL_REPOSITORY}, got {repository}"
        )
    expected_ref = f"refs/heads/{AUTHORITY_REF}"
    if ref != expected_ref:
        raise CurrentPlanPublicationError(
            f"current-plan publication ref mismatch: expected {expected_ref}, got {ref}"
        )
    if workflow_ref != CURRENT_PLAN_WORKFLOW_REF:
        raise CurrentPlanPublicationError(
            "current-plan publication workflow mismatch: "
            f"expected {CURRENT_PLAN_WORKFLOW_REF}, got {workflow_ref}"
        )


def validate_observer_runtime_identity(repository: Any, ref: Any, workflow_ref: Any) -> None:
    repository = _identity(repository, "observer repository")
    ref = _identity(ref, "observer ref")
    workflow_ref = _identity(workflow_ref, "observer workflow identity")
    expected_ref = f"refs/heads/{AUTHORITY_REF}"
    if repository != CONTROL_REPOSITORY or ref != expected_ref or workflow_ref != OBSERVER_WORKFLOW_REF:
        raise CurrentPlanPublicationError(
            "current-plan observer authority mismatch: "
            f"expected repository={CONTROL_REPOSITORY} workflow={OBSERVER_WORKFLOW_REF} ref={expected_ref}"
        )


def _positive_integer(value: Any, label: str) -> int:
    if isinstance(value, bool):
        raise CurrentPlanPublicationError(f"current-plan publication {label} must be a positive integer")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise CurrentPlanPublicationError(
            f"current-plan publication {label} must be a positive integer"
        ) from error
    if parsed < 1:
        raise CurrentPlanPublicationError(f"current-plan publication {label} must be a positive integer")
    return parsed


def approved_writer_handoff(
    repository: Any,
    ref: Any,
    workflow_ref: Any,
    source_sha: Any,
    run_id: Any,
    producer_attempt: Any,
) -> str:
    """Bind environment-gated job success to one protected workflow run."""

    validate_runtime_identity(repository, ref, workflow_ref)
    source_sha = _identity(source_sha, "source SHA")
    if COMMIT_PATTERN.fullmatch(source_sha) is None:
        raise CurrentPlanPublicationError("current-plan publication source SHA must be a full lowercase commit")
    run_id = _positive_integer(run_id, "run ID")
    producer_attempt = _positive_integer(producer_attempt, "approval attempt")
    identity = "\0".join(
        (
            repository,
            ref,
            workflow_ref,
            source_sha,
            str(run_id),
            str(producer_attempt),
        )
    ).encode()
    return hashlib.sha256(HANDOFF_DOMAIN + identity).hexdigest()


def validate_approved_writer_handoff(
    handoff: Any,
    repository: Any,
    ref: Any,
    workflow_ref: Any,
    source_sha: Any,
    run_id: Any,
    current_attempt: Any,
    producer_attempt: Any,
) -> None:
    handoff = _identity(handoff, "approved writer handoff")
    current_attempt = _positive_integer(current_attempt, "current attempt")
    producer_attempt_value = _positive_integer(producer_attempt, "approval attempt")
    if producer_attempt_value > current_attempt:
        raise CurrentPlanPublicationError("current-plan publication approval attempt is newer than the writer attempt")
    expected = approved_writer_handoff(
        repository,
        ref,
        workflow_ref,
        source_sha,
        run_id,
        producer_attempt_value,
    )
    if not hmac.compare_digest(handoff, expected):
        raise CurrentPlanPublicationError(
            "current-plan publication approved writer handoff does not match this workflow run"
        )


def _canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _plan_identity(value: Any, label: str) -> PlanIdentity:
    expected_keys = {"schema", "plan", "channel", "foundation", "components", "beta_authorization"}
    if not isinstance(value, dict) or set(value) != expected_keys:
        raise CurrentPlanPublicationError(f"{label} has an invalid current-plan shape")
    plan = value.get("plan")
    if value.get("schema") != CURRENT_PLAN_SCHEMA or not isinstance(plan, str) or not PLAN_PATTERN.fullmatch(plan):
        raise CurrentPlanPublicationError(f"{label} has an invalid current-plan identity")
    if value.get("channel") not in {"alpha", "beta", "rc"}:
        raise CurrentPlanPublicationError(f"{label} has an invalid current-plan channel")
    foundation = value.get("foundation")
    if (
        not isinstance(foundation, dict)
        or set(foundation) != {"tag", "commit"}
        or not isinstance(foundation.get("tag"), str)
        or COMMIT_PATTERN.fullmatch(str(foundation.get("commit", ""))) is None
    ):
        raise CurrentPlanPublicationError(f"{label} has an invalid current-plan foundation")
    components = value.get("components")
    if not isinstance(components, dict) or not components:
        raise CurrentPlanPublicationError(f"{label} has no current-plan components")
    for name, component in components.items():
        if (
            not isinstance(name, str)
            or not isinstance(component, dict)
            or set(component) != {"version", "commit"}
            or not isinstance(component.get("version"), str)
            or VERSION_PATTERN.fullmatch(component["version"]) is None
            or COMMIT_PATTERN.fullmatch(str(component.get("commit", ""))) is None
        ):
            raise CurrentPlanPublicationError(f"{label} has an invalid current-plan component")
    return PlanIdentity(
        tag=f"{PLAN_TAG_PREFIX}{plan}",
        sha256=hashlib.sha256(_canonical_json(value)).hexdigest(),
    )


def _load_local_candidate(
    path: Path,
    repository: Any,
    ref: Any,
    workflow: Any,
    source_sha: Any,
    plan_tag: Any,
    plan_sha256: Any,
) -> CandidateIdentity:
    repository = _identity(repository, "target repository")
    ref = _identity(ref, "target ref")
    workflow = _identity(workflow, "target workflow")
    source_sha = _identity(source_sha, "source SHA")
    plan_tag = _identity(plan_tag, "current-plan tag")
    plan_sha256 = _identity(plan_sha256, "current-plan digest")
    if repository != CONTROL_REPOSITORY:
        raise CurrentPlanPublicationError("current-plan dispatch target repository is mismatched")
    if ref != AUTHORITY_REF:
        raise CurrentPlanPublicationError("current-plan dispatch target ref is mismatched")
    if workflow != CURRENT_PLAN_WORKFLOW:
        raise CurrentPlanPublicationError("current-plan dispatch target workflow is mismatched")
    if COMMIT_PATTERN.fullmatch(source_sha) is None:
        raise CurrentPlanPublicationError("current-plan dispatch source SHA must be a full lowercase commit")
    if (
        not plan_tag.startswith(PLAN_TAG_PREFIX)
        or PLAN_PATTERN.fullmatch(plan_tag.removeprefix(PLAN_TAG_PREFIX)) is None
    ):
        raise CurrentPlanPublicationError("current-plan dispatch plan tag is invalid")
    if DIGEST_PATTERN.fullmatch(plan_sha256) is None:
        raise CurrentPlanPublicationError("current-plan dispatch plan digest is invalid")
    try:
        raw = path.read_bytes()
        if len(raw) > 64 * 1024:
            raise CurrentPlanPublicationError("local current plan exceeds the 64 KiB limit")
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CurrentPlanPublicationError(f"cannot read local current plan {path}: {error}") from error
    local_identity = _plan_identity(value, "local source revision")
    if local_identity != PlanIdentity(plan_tag, plan_sha256):
        raise CurrentPlanPublicationError(
            "observed current-plan identity does not match the protected source revision"
        )
    return CandidateIdentity(
        repository=repository,
        workflow=workflow,
        ref=ref,
        source_sha=source_sha,
        plan=local_identity,
    )


def _workflow_metadata(client: ActionsClient, candidate: CandidateIdentity) -> int:
    encoded = urllib.parse.quote(candidate.workflow, safe="")
    value = client.get(f"/repos/{candidate.repository}/actions/workflows/{encoded}")
    workflow_id = value.get("id") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or isinstance(workflow_id, bool)
        or not isinstance(workflow_id, int)
        or workflow_id < 1
        or value.get("path") != CURRENT_PLAN_WORKFLOW_PATH
        or value.get("state") != "active"
        or value.get("name") != "Current release plan"
        or value.get("html_url")
        != f"https://github.com/{candidate.repository}/actions/workflows/{candidate.workflow}"
    ):
        raise CurrentPlanPublicationError("current-plan workflow API authority is malformed or mismatched")
    return workflow_id


def _require_authority_ref(client: ActionsClient, candidate: CandidateIdentity) -> None:
    value = client.get(f"/repos/{candidate.repository}/git/ref/heads/{candidate.ref}")
    target = value.get("object") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("ref") != f"refs/heads/{candidate.ref}"
        or not isinstance(target, dict)
        or target.get("type") != "commit"
        or target.get("sha") != candidate.source_sha
    ):
        raise CurrentPlanPublicationError(
            "current-plan authority ref no longer resolves to the observed source revision"
        )


def _active_runs(client: ActionsClient, candidate: CandidateIdentity, workflow_id: int) -> list[ActiveRun]:
    runs: list[ActiveRun] = []
    seen: set[int] = set()
    for requested_status in ACTIVE_RUN_STATUSES:
        encoded_status = urllib.parse.quote(requested_status, safe="")
        status_count = 0
        for page in range(1, RUN_PAGE_LIMIT + 1):
            path = (
                f"/repos/{candidate.repository}/actions/workflows/{workflow_id}/runs"
                f"?branch={candidate.ref}&status={encoded_status}"
                f"&per_page={RUN_PAGE_SIZE}&page={page}"
            )
            payload = client.get(path)
            page_runs = payload.get("workflow_runs") if isinstance(payload, dict) else None
            total_count = payload.get("total_count") if isinstance(payload, dict) else None
            if (
                not isinstance(page_runs, list)
                or isinstance(total_count, bool)
                or not isinstance(total_count, int)
                or total_count < len(page_runs)
            ):
                raise CurrentPlanPublicationError("current-plan workflow-runs API response is malformed")
            for value in page_runs:
                run = _active_run(value, candidate, workflow_id, requested_status)
                if run.run_id in seen:
                    raise CurrentPlanPublicationError("current-plan workflow-runs API contains a duplicate run")
                seen.add(run.run_id)
                runs.append(run)
                status_count += 1
            if len(page_runs) < RUN_PAGE_SIZE or status_count >= total_count:
                break
        else:
            raise CurrentPlanPublicationError(
                f"current-plan {requested_status} workflow runs exceed the pagination bound"
            )
    return runs


def _active_run(value: Any, candidate: CandidateIdentity, workflow_id: int, requested_status: str) -> ActiveRun:
    repository = value.get("repository") if isinstance(value, dict) else None
    head_repository = value.get("head_repository") if isinstance(value, dict) else None
    run_id = value.get("id") if isinstance(value, dict) else None
    run_attempt = value.get("run_attempt") if isinstance(value, dict) else None
    created_at = value.get("created_at") if isinstance(value, dict) else None
    expected_paths = {CURRENT_PLAN_WORKFLOW_PATH, f"{CURRENT_PLAN_WORKFLOW_PATH}@{candidate.ref}"}
    expected_url = f"https://github.com/{candidate.repository}/actions/runs/{run_id}"
    expected_api_url = f"https://api.github.com/repos/{candidate.repository}/actions/runs/{run_id}"
    if (
        not isinstance(value, dict)
        or isinstance(run_id, bool)
        or not isinstance(run_id, int)
        or run_id < 1
        or isinstance(run_attempt, bool)
        or not isinstance(run_attempt, int)
        or run_attempt < 1
        or value.get("workflow_id") != workflow_id
        or value.get("event") not in CURRENT_PLAN_RUN_EVENTS
        or value.get("path") not in expected_paths
        or value.get("head_branch") != candidate.ref
        or not isinstance(repository, dict)
        or repository.get("full_name") != candidate.repository
        or not isinstance(head_repository, dict)
        or head_repository.get("full_name") != candidate.repository
        or value.get("html_url") != expected_url
        or value.get("url") != expected_api_url
        or value.get("status") != requested_status
        or value.get("conclusion") is not None
        or not isinstance(created_at, str)
        or RFC3339_PATTERN.fullmatch(created_at) is None
        or COMMIT_PATTERN.fullmatch(str(value.get("head_sha", ""))) is None
    ):
        raise CurrentPlanPublicationError("active current-plan workflow run is malformed or mismatched")
    try:
        created_at_value = dt.datetime.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=dt.UTC)
    except ValueError as error:
        raise CurrentPlanPublicationError("active current-plan workflow run has an invalid timestamp") from error
    return ActiveRun(
        run_id=run_id,
        status=requested_status,
        source_sha=value["head_sha"],
        created_at=created_at_value,
        url=expected_url,
    )


def _source_plan_identity(client: ActionsClient, candidate: CandidateIdentity, source_sha: str) -> PlanIdentity:
    encoded_path = "/".join(urllib.parse.quote(part, safe="") for part in CURRENT_PLAN_PATH.split("/"))
    value = client.get(
        f"/repos/{candidate.repository}/contents/{encoded_path}?ref={source_sha}"
    )
    encoded = value.get("content") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("type") != "file"
        or value.get("path") != CURRENT_PLAN_PATH
        or value.get("encoding") != "base64"
        or not isinstance(encoded, str)
        or len(encoded) > 96 * 1024
    ):
        raise CurrentPlanPublicationError("historical current-plan source response is malformed")
    try:
        raw = base64.b64decode("".join(encoded.split()), validate=True)
        if len(raw) > 64 * 1024:
            raise CurrentPlanPublicationError("historical current plan exceeds the 64 KiB limit")
        plan = json.loads(raw)
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CurrentPlanPublicationError("historical current-plan source is malformed") from error
    return _plan_identity(plan, f"source revision {source_sha}")


def _require_older_revision(client: ActionsClient, candidate: CandidateIdentity, source_sha: str) -> None:
    value = client.get(f"/repos/{candidate.repository}/compare/{source_sha}...{candidate.source_sha}")
    base = value.get("base_commit") if isinstance(value, dict) else None
    merge_base = value.get("merge_base_commit") if isinstance(value, dict) else None
    ahead_by = value.get("ahead_by") if isinstance(value, dict) else None
    behind_by = value.get("behind_by") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("status") != "ahead"
        or not isinstance(base, dict)
        or base.get("sha") != source_sha
        or not isinstance(merge_base, dict)
        or merge_base.get("sha") != source_sha
        or isinstance(ahead_by, bool)
        or not isinstance(ahead_by, int)
        or ahead_by < 1
        or behind_by != 0
    ):
        raise CurrentPlanPublicationError(
            f"active run {source_sha} is not a verified ancestor of {candidate.source_sha}"
        )


def _is_unapproved_wait(client: ActionsClient, candidate: CandidateIdentity, run: ActiveRun) -> bool:
    if run.status != "waiting":
        return False
    value = client.get(
        f"/repos/{candidate.repository}/actions/runs/{run.run_id}/pending_deployments"
    )
    if not isinstance(value, list):
        raise CurrentPlanPublicationError(
            f"pending deployments for current-plan run {run.run_id} are malformed"
        )
    if not value:
        return False
    if len(value) != 1 or not isinstance(value[0], dict):
        raise CurrentPlanPublicationError(
            f"current-plan run {run.run_id} has ambiguous pending authorization"
        )
    environment = value[0].get("environment")
    environment_id = environment.get("id") if isinstance(environment, dict) else None
    expected_url = (
        f"https://api.github.com/repos/{candidate.repository}/environments/"
        f"{BETA_AUTHORIZATION_ENVIRONMENT}"
    )
    if (
        not isinstance(environment, dict)
        or isinstance(environment_id, bool)
        or not isinstance(environment_id, int)
        or environment_id < 1
        or environment.get("name") != BETA_AUTHORIZATION_ENVIRONMENT
        or environment.get("url") != expected_url
    ):
        raise CurrentPlanPublicationError(
            f"current-plan run {run.run_id} pending authorization is mismatched"
        )
    return True


def reconcile_current_plan_dispatch(
    client: ActionsClient,
    *,
    plan_path: Path,
    repository: Any,
    ref: Any,
    workflow: Any,
    source_sha: Any,
    plan_tag: Any,
    plan_sha256: Any,
    observer_workflow_ref: Any,
) -> ReconciliationResult:
    """Coalesce exact current-plan approval waits without crossing authorization."""

    validate_observer_runtime_identity(repository, f"refs/heads/{ref}", observer_workflow_ref)
    candidate = _load_local_candidate(
        plan_path,
        repository,
        ref,
        workflow,
        source_sha,
        plan_tag,
        plan_sha256,
    )
    workflow_id = _workflow_metadata(client, candidate)
    _require_authority_ref(client, candidate)
    runs = _active_runs(client, candidate, workflow_id)

    current_runs = [run for run in runs if run.source_sha == candidate.source_sha]
    stale_runs = [run for run in runs if run.source_sha != candidate.source_sha]
    source_identities = {candidate.source_sha: candidate.plan}
    for run in stale_runs:
        if run.source_sha not in source_identities:
            source_identities[run.source_sha] = _source_plan_identity(client, candidate, run.source_sha)
            _require_older_revision(client, candidate, run.source_sha)

    unapproved: dict[int, bool] = {}
    for run in runs:
        unapproved[run.run_id] = _is_unapproved_wait(client, candidate, run)

    protected_current = [run for run in current_runs if not unapproved[run.run_id]]
    if len(protected_current) > 1:
        raise CurrentPlanPublicationError(
            "multiple exact-candidate runs may have passed protected authorization; refusing mutation"
        )
    if any(not unapproved[run.run_id] for run in stale_runs):
        raise CurrentPlanPublicationError(
            "an older current-plan run may have passed protected authorization; refusing supersession"
        )

    retained: ActiveRun | None
    if protected_current:
        retained = protected_current[0]
    elif current_runs:
        retained = min(current_runs, key=lambda run: (run.created_at, run.run_id))
    else:
        retained = None

    cancellations = [
        run
        for run in runs
        if unapproved[run.run_id] and run is not retained
    ]
    _require_authority_ref(client, candidate)
    cancelled_urls: list[str] = []
    for run in sorted(cancellations, key=lambda item: (item.created_at, item.run_id)):
        if not _is_unapproved_wait(client, candidate, run):
            raise CurrentPlanPublicationError(
                f"current-plan run {run.run_id} is no longer awaiting protected authorization"
            )
        client.post(f"/repos/{candidate.repository}/actions/runs/{run.run_id}/cancel")
        cancelled_urls.append(run.url)
        plan = source_identities[run.source_sha]
        print(
            "Cancelled verified unapproved current-plan wait "
            f"{run.url} (source={run.source_sha} plan={plan.tag} plan_sha256={plan.sha256})."
        )

    if retained is not None:
        print(
            "Current-plan publication is an idempotent no-op; retained "
            f"{retained.url} for repository={candidate.repository} workflow={candidate.workflow} "
            f"ref={candidate.ref} source={candidate.source_sha} plan={candidate.plan.tag} "
            f"plan_sha256={candidate.plan.sha256}."
        )
        return ReconciliationResult("retained", retained.url, tuple(cancelled_urls))

    client.post(
        f"/repos/{candidate.repository}/actions/workflows/{workflow_id}/dispatches",
        {"ref": candidate.ref},
    )
    print(
        "Dispatched exact current-plan candidate "
        f"repository={candidate.repository} workflow={candidate.workflow} ref={candidate.ref} "
        f"source={candidate.source_sha} plan={candidate.plan.tag} "
        f"plan_sha256={candidate.plan.sha256}."
    )
    return ReconciliationResult("dispatched", None, tuple(cancelled_urls))


def write_github_output(path: Path, values: dict[str, str | int]) -> None:
    with path.open("a", encoding="utf-8") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")


def add_runtime_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repository", required=True)
    parser.add_argument("--ref", required=True)
    parser.add_argument("--workflow-ref", required=True)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    validate = subparsers.add_parser(
        "validate-runtime",
        help="fail unless the protected current-plan workflow is running on its exact authority",
    )
    add_runtime_arguments(validate)
    create_handoff = subparsers.add_parser(
        "create-approved-writer-handoff",
        help="bind a completed protected-environment job to its exact workflow run",
    )
    add_runtime_arguments(create_handoff)
    create_handoff.add_argument("--source-sha", required=True)
    create_handoff.add_argument("--run-id", required=True)
    create_handoff.add_argument("--run-attempt", required=True)
    create_handoff.add_argument("--github-output", required=True, type=Path)
    validate_handoff = subparsers.add_parser(
        "validate-approved-writer-handoff",
        help="fail unless the privileged writer follows an exact approved job",
    )
    add_runtime_arguments(validate_handoff)
    validate_handoff.add_argument("--source-sha", required=True)
    validate_handoff.add_argument("--run-id", required=True)
    validate_handoff.add_argument("--current-attempt", required=True)
    validate_handoff.add_argument("--producer-attempt", required=True)
    validate_handoff.add_argument("--handoff", required=True)
    reconcile = subparsers.add_parser(
        "reconcile-dispatch",
        help="coalesce unapproved exact-candidate waits before dispatch",
    )
    reconcile.add_argument("--plan", required=True, type=Path)
    reconcile.add_argument("--repository", required=True)
    reconcile.add_argument("--ref", required=True)
    reconcile.add_argument("--workflow", required=True)
    reconcile.add_argument("--observer-workflow-ref", required=True)
    reconcile.add_argument("--source-sha", required=True)
    reconcile.add_argument("--plan-tag", required=True)
    reconcile.add_argument("--plan-sha256", required=True)
    reconcile.add_argument("--github-output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "validate-runtime":
            validate_runtime_identity(
                arguments.repository,
                arguments.ref,
                arguments.workflow_ref,
            )
        elif arguments.command == "create-approved-writer-handoff":
            handoff = approved_writer_handoff(
                arguments.repository,
                arguments.ref,
                arguments.workflow_ref,
                arguments.source_sha,
                arguments.run_id,
                arguments.run_attempt,
            )
            write_github_output(
                arguments.github_output,
                {
                    "handoff": handoff,
                    "producer-attempt": _positive_integer(arguments.run_attempt, "approval attempt"),
                },
            )
        elif arguments.command == "validate-approved-writer-handoff":
            validate_approved_writer_handoff(
                arguments.handoff,
                arguments.repository,
                arguments.ref,
                arguments.workflow_ref,
                arguments.source_sha,
                arguments.run_id,
                arguments.current_attempt,
                arguments.producer_attempt,
            )
        elif arguments.command == "reconcile-dispatch":
            token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or ""
            result = reconcile_current_plan_dispatch(
                GitHubActionsClient(token, os.environ.get("GITHUB_API_URL", "https://api.github.com")),
                plan_path=arguments.plan,
                repository=arguments.repository,
                ref=arguments.ref,
                workflow=arguments.workflow,
                source_sha=arguments.source_sha,
                plan_tag=arguments.plan_tag,
                plan_sha256=arguments.plan_sha256,
                observer_workflow_ref=arguments.observer_workflow_ref,
            )
            if arguments.github_output is not None:
                write_github_output(
                    arguments.github_output,
                    {
                        "outcome": result.outcome,
                        "retained-run-url": result.retained_run_url or "",
                        "cancelled-run-count": len(result.cancelled_run_urls),
                    },
                )
    except CurrentPlanPublicationError as error:
        print(error, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
