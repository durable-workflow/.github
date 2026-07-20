#!/usr/bin/env python3
"""Validate and audit GitHub-owned public target qualification."""

from __future__ import annotations

import argparse
import contextlib
import email.utils
import errno
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Mapping
from datetime import UTC
from pathlib import Path
from typing import Any

import yaml

SCHEMA = "durable-workflow.github-target-qualification/v1"
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
SUPPORTED_JAVASCRIPT_ACTION_RUNTIMES = ["node24"]
EXPECTED_TARGETS = {
    "cli": ("cli", "main"),
    "documentation": ("durable-workflow.github.io", "main"),
    "github-control-plane": (".github", "main"),
    "sample-app": ("sample-app", "main"),
    "sdk-php": ("sdk-php", "main"),
    "sdk-python": ("sdk-python", "main"),
    "sdk-rust": ("sdk-rust", "main"),
    "server": ("server", "main"),
    "waterline": ("waterline", "v2"),
    "workflow": ("workflow", "v2"),
}
GITHUB_API_MAX_ATTEMPTS = 5
GITHUB_API_RETRY_BASE_SECONDS = 2.0
GITHUB_API_RETRY_MAX_SECONDS = 120.0
GITHUB_API_REQUEST_TIMEOUT_SECONDS = 30.0
GITHUB_API_AUDIT_TIMEOUT_SECONDS = 600.0
CHECK_RUN_MAX_ATTEMPTS = 20
CHECK_RUN_POLL_SECONDS = 30.0
INFRASTRUCTURE_EXIT_CODE = 75


class PolicyError(RuntimeError):
    """A qualification or protection contract is not satisfied."""


class ResourceNotFound(PolicyError):
    """A required GitHub resource does not exist."""


class GitHubInfrastructureError(RuntimeError):
    """A bounded set of transient GitHub API attempts was exhausted."""

    def __init__(
        self,
        path: str,
        attempts: Mapping[str, int],
        failures: Mapping[str, str],
        *,
        reason: str,
    ) -> None:
        evidence = ["classification=github-api-transient", f"endpoint=GET {path}", f"reason={reason}"]
        for client in ("authenticated", "credential_free"):
            if client in attempts:
                evidence.append(f"{client}_attempts={attempts[client]}")
            if client in failures:
                evidence.append(f"{client}_{failures[client]}")
        super().__init__(f"GitHub API transient failure exhausted ({', '.join(evidence)})")


class _TransientGitHubFailure(RuntimeError):
    """One GitHub API client attempt encountered retryable infrastructure."""

    def __init__(
        self,
        *,
        status: int | None = None,
        transport: str | None = None,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        self.status = status
        self.transport = transport
        self.headers = headers or {}
        super().__init__(self.evidence)

    @property
    def evidence(self) -> str:
        if self.status is not None:
            return f"status={self.status}"
        return f"transport={self.transport}"


class _AuditDeadlineExceeded(RuntimeError):
    """The shared qualification API deadline elapsed during one request."""


class GitHubClient:
    def __init__(
        self,
        token: str | None = None,
        api_url: str = "https://api.github.com",
        *,
        max_attempts: int = GITHUB_API_MAX_ATTEMPTS,
        retry_base_seconds: float = GITHUB_API_RETRY_BASE_SECONDS,
        retry_max_seconds: float = GITHUB_API_RETRY_MAX_SECONDS,
        request_timeout_seconds: float = GITHUB_API_REQUEST_TIMEOUT_SECONDS,
        audit_timeout_seconds: float = GITHUB_API_AUDIT_TIMEOUT_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            max_attempts < 1
            or retry_base_seconds < 0
            or retry_max_seconds < retry_base_seconds
            or request_timeout_seconds <= 0
            or audit_timeout_seconds <= 0
        ):
            raise ValueError("invalid GitHub API retry configuration")
        self.api_url = api_url.rstrip("/")
        self.max_attempts = max_attempts
        self.retry_base_seconds = retry_base_seconds
        self.retry_max_seconds = retry_max_seconds
        self.request_timeout_seconds = request_timeout_seconds
        self.sleep = sleep
        self.now = now
        self.monotonic = monotonic
        self.deadline = monotonic() + audit_timeout_seconds
        self.headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "durable-workflow-target-qualification/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    @staticmethod
    def _error_detail(error: urllib.error.HTTPError) -> str:
        try:
            return error.read().decode("utf-8", errors="replace")[:500]
        except OSError:
            return "response body unavailable"

    @staticmethod
    def _is_rate_limited(
        error: urllib.error.HTTPError,
        detail: str,
    ) -> bool:
        headers = error.headers or {}
        return error.code == 429 or (
            error.code in {401, 403}
            and (
                headers.get("Retry-After") is not None
                or headers.get("X-RateLimit-Remaining") == "0"
                or "rate limit" in detail.lower()
            )
        )

    @staticmethod
    def _transport_name(error: BaseException) -> str | None:
        reason = error.reason if isinstance(error, urllib.error.URLError) else error
        if isinstance(
            reason,
            ConnectionError | TimeoutError | http.client.IncompleteRead | http.client.RemoteDisconnected,
        ):
            return type(reason).__name__
        if isinstance(reason, OSError) and reason.errno in {
            errno.ECONNABORTED,
            errno.ECONNRESET,
            errno.EPIPE,
            errno.ETIMEDOUT,
        }:
            return type(reason).__name__
        return None

    def _server_retry_delay(self, headers: Mapping[str, str]) -> float | None:
        delays: list[float] = []
        retry_after = headers.get("Retry-After")
        if retry_after:
            try:
                delays.append(float(retry_after))
            except ValueError:
                try:
                    retry_at = email.utils.parsedate_to_datetime(retry_after)
                except (TypeError, ValueError):
                    pass
                else:
                    if retry_at.tzinfo is None:
                        retry_at = retry_at.replace(tzinfo=UTC)
                    delays.append(retry_at.timestamp() - self.now())
        rate_limit_reset = headers.get("X-RateLimit-Reset")
        if rate_limit_reset:
            with contextlib.suppress(ValueError):
                delays.append(float(rate_limit_reset) - self.now())
        return max((delay for delay in delays if delay > 0), default=None)

    def _retry_delay(self, attempt: int, failures: Mapping[str, _TransientGitHubFailure]) -> float:
        backoff = min(self.retry_base_seconds * (2 ** (attempt - 1)), self.retry_max_seconds)
        server_delays = [self._server_retry_delay(failure.headers) for failure in failures.values()]
        return max(backoff, *(server_delay or 0 for server_delay in server_delays))

    @staticmethod
    def _failure_evidence(failures: Mapping[str, _TransientGitHubFailure]) -> dict[str, str]:
        return {client: failure.evidence for client, failure in failures.items()}

    def _infrastructure_error(
        self,
        path: str,
        attempts: Mapping[str, int],
        failures: Mapping[str, _TransientGitHubFailure],
        *,
        reason: str,
    ) -> GitHubInfrastructureError:
        return GitHubInfrastructureError(
            path,
            attempts,
            self._failure_evidence(failures),
            reason=reason,
        )

    def _remaining_time(self) -> float:
        return self.deadline - self.monotonic()

    def _retry(
        self,
        path: str,
        attempt: int,
        attempts: Mapping[str, int],
        failures: Mapping[str, _TransientGitHubFailure],
    ) -> None:
        delay = self._retry_delay(attempt, failures)
        if delay >= self._remaining_time():
            raise self._infrastructure_error(
                path,
                attempts,
                failures,
                reason="audit-deadline",
            )
        failure_summary = " ".join(
            f"{client.replace('_', '-')}={failure.evidence}" for client, failure in failures.items()
        )
        print(
            f"qualification GitHub API retry: endpoint=GET {path} {failure_summary} "
            f"attempt={attempt}/{self.max_attempts} delay={delay:g}s",
            file=sys.stderr,
        )
        self.sleep(delay)

    def _request_once(self, path: str, *, accept: str | None, authenticated: bool) -> bytes:
        headers = dict(self.headers)
        if not authenticated:
            headers.pop("Authorization", None)
        if accept:
            headers["Accept"] = accept
        request = urllib.request.Request(f"{self.api_url}{path}", headers=headers)
        remaining = self._remaining_time()
        if remaining <= 0:
            raise _AuditDeadlineExceeded
        timeout = min(self.request_timeout_seconds, remaining)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read()
            if self._remaining_time() <= 0:
                raise _AuditDeadlineExceeded
            return payload
        except urllib.error.HTTPError as error:
            detail = self._error_detail(error)
            if error.code == 404:
                raise ResourceNotFound(f"GitHub API 404 for {path}: {detail}") from error
            if 500 <= error.code <= 599 or self._is_rate_limited(error, detail):
                raise _TransientGitHubFailure(status=error.code, headers=error.headers) from error
            raise PolicyError(f"GitHub API {error.code} for {path}: {detail}") from error
        except (urllib.error.URLError, ConnectionError, TimeoutError, http.client.IncompleteRead) as error:
            transport = self._transport_name(error)
            if transport is None:
                reason = error.reason if isinstance(error, urllib.error.URLError) else error
                raise PolicyError(f"GitHub API request failed for {path}: {reason}") from error
            raise _TransientGitHubFailure(transport=transport) from error

    def _request(self, path: str, *, accept: str | None = None) -> bytes:
        authenticated = "Authorization" in self.headers
        clients = ("authenticated", "credential_free") if authenticated else ("credential_free",)
        attempts = dict.fromkeys(clients, 0)
        for attempt in range(1, self.max_attempts + 1):
            failures: dict[str, _TransientGitHubFailure] = {}
            for client in clients:
                if self._remaining_time() <= 0:
                    raise self._infrastructure_error(path, attempts, failures, reason="audit-deadline")
                attempts[client] += 1
                try:
                    return self._request_once(path, accept=accept, authenticated=client == "authenticated")
                except _AuditDeadlineExceeded:
                    raise self._infrastructure_error(path, attempts, failures, reason="audit-deadline") from None
                except _TransientGitHubFailure as error:
                    failures[client] = error
                    if client == "authenticated":
                        print(
                            f"qualification GitHub API fallback: endpoint=GET {path} "
                            f"authenticated={error.evidence} attempt={attempt}/{self.max_attempts} "
                            "client=credential-free",
                            file=sys.stderr,
                        )
            if attempt == self.max_attempts:
                raise self._infrastructure_error(
                    path,
                    attempts,
                    failures,
                    reason="retry-exhausted",
                )
            self._retry(path, attempt, attempts, failures)
        raise AssertionError("GitHub API retry loop ended unexpectedly")

    def json(self, path: str) -> Any:
        try:
            return json.loads(self._request(path))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise PolicyError(f"GitHub API response for {path} is not valid JSON") from error

    def bytes(self, path: str) -> bytes:
        return self._request(path, accept="application/vnd.github.raw+json")

    def collection(self, path: str, key: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        separator = "&" if "?" in path else "?"
        for page in range(1, 11):
            payload = self.json(f"{path}{separator}per_page=100&page={page}")
            page_records = payload.get(key)
            if not isinstance(page_records, list):
                raise PolicyError(f"GitHub API response for {path} has no {key!r} collection")
            records.extend(page_records)
            if len(page_records) < 100:
                return records
        raise PolicyError(f"GitHub API pagination exceeded the audit bound for {path}")

    def list_collection(self, path: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        separator = "&" if "?" in path else "?"
        for page in range(1, 11):
            page_records = self.json(f"{path}{separator}per_page=100&page={page}")
            if not isinstance(page_records, list):
                raise PolicyError(f"GitHub API response for {path} is not a collection")
            records.extend(page_records)
            if len(page_records) < 100:
                return records
        raise PolicyError(f"GitHub API pagination exceeded the audit bound for {path}")


def load_policy(path: Path) -> dict[str, Any]:
    try:
        policy = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PolicyError(f"Cannot read qualification policy {path}: {error}") from error
    validate_policy(policy)
    return policy


def validate_policy(policy: dict[str, Any]) -> None:
    if policy.get("schema") != SCHEMA:
        raise PolicyError(f"qualification policy schema must be {SCHEMA}")
    if policy.get("organization") != "durable-workflow":
        raise PolicyError("qualification policy organization must be durable-workflow")
    if policy.get("required_status_checks_strict") is not True:
        raise PolicyError("qualification policy must require strict status checks")

    action_runtime = policy.get("action_runtime")
    if not isinstance(action_runtime, dict) or set(action_runtime) != {
        "allowed_releases",
        "supported_javascript_runtimes",
    }:
        raise PolicyError("qualification policy must declare the complete action runtime contract")
    if action_runtime["supported_javascript_runtimes"] != SUPPORTED_JAVASCRIPT_ACTION_RUNTIMES:
        raise PolicyError(
            f"qualification policy supported JavaScript action runtimes must be {SUPPORTED_JAVASCRIPT_ACTION_RUNTIMES}"
        )
    allowed_releases = action_runtime["allowed_releases"]
    if not isinstance(allowed_releases, dict) or not allowed_releases:
        raise PolicyError("qualification policy must declare allowed action releases")
    for repository, references in allowed_releases.items():
        if not isinstance(repository, str) or not re.fullmatch(r"[a-z0-9_.-]+/[a-z0-9_.-]+", repository):
            raise PolicyError(f"invalid action repository {repository!r}")
        if (
            not isinstance(references, list)
            or not references
            or len(references) != len(set(references))
            or not all(
                isinstance(reference, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", reference)
                for reference in references
            )
        ):
            raise PolicyError(f"{repository} must declare unique static action release references")

    targets = policy.get("targets")
    if not isinstance(targets, dict) or set(targets) != set(EXPECTED_TARGETS):
        missing = sorted(set(EXPECTED_TARGETS) - set(targets or {}))
        extra = sorted(set(targets or {}) - set(EXPECTED_TARGETS))
        raise PolicyError(f"qualification target inventory mismatch; missing={missing}, extra={extra}")

    for name, (expected_repository, expected_branch) in EXPECTED_TARGETS.items():
        target = targets[name]
        if target.get("repository") != expected_repository or target.get("branch") != expected_branch:
            raise PolicyError(
                f"{name} must target {expected_repository}@{expected_branch}, got "
                f"{target.get('repository')}@{target.get('branch')}"
            )
        workflows = target.get("workflows")
        if not isinstance(workflows, list) or not workflows:
            raise PolicyError(f"{name} must declare at least one qualification workflow")
        checks: set[str] = set()
        paths: set[str] = set()
        for workflow in workflows:
            path = workflow.get("path")
            check = workflow.get("required_check")
            if not isinstance(path, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.yml", path):
                raise PolicyError(f"{name} has invalid workflow path {path!r}")
            if not isinstance(check, str) or not check.strip():
                raise PolicyError(f"{name}/{path} has no required check context")
            if not isinstance(workflow.get("matrix_independent"), bool):
                raise PolicyError(f"{name}/{path} must declare matrix_independent")
            if path in paths or check in checks:
                raise PolicyError(f"{name} has duplicate workflow paths or check contexts")
            paths.add(path)
            checks.add(check)


def verify_workflow_source(name: str, branch: str, workflow: dict[str, Any], source: str) -> None:
    label = f"{name}/.github/workflows/{workflow['path']}"
    if not re.search(r"(?m)^  push:\s*$", source):
        raise PolicyError(f"{label} does not run automatically on target pushes")
    if branch not in source:
        raise PolicyError(f"{label} does not name target branch {branch!r}")
    if not re.search(r"(?m)^  pull_request:\s*$", source):
        raise PolicyError(f"{label} does not qualify changes before target-branch updates")
    if not re.search(r"(?m)^  workflow_dispatch:\s*$", source):
        raise PolicyError(f"{label} has no GitHub-owned manual recovery trigger")
    if "timeout-minutes:" not in source:
        raise PolicyError(f"{label} has no bounded job timeout")
    if workflow["matrix_independent"] and not re.search(r"(?m)^\s+fail-fast:\s*false\s*$", source):
        raise PolicyError(f"{label} does not keep matrix cells independent")


def _parse_yaml(source: str, label: str) -> Any:
    try:
        return yaml.load(source, Loader=yaml.BaseLoader)
    except yaml.YAMLError as error:
        raise PolicyError(f"cannot parse {label} as YAML: {error}") from error


def _workflow_action_references(source: str, label: str) -> list[str]:
    document = _parse_yaml(source, label)
    references: list[str] = []

    def visit(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if key == "uses":
                    if not isinstance(value, str):
                        raise PolicyError(f"{label} has a non-string action reference")
                    references.append(value)
                visit(value)
        elif isinstance(node, list):
            for value in node:
                visit(value)

    visit(document)
    return references


def _split_action_reference(specification: str) -> tuple[str, str, str] | None:
    if specification.startswith(("./", "docker://")) or "/.github/workflows/" in specification:
        return None
    action, separator, reference = specification.rpartition("@")
    if not separator or not reference or "${{" in specification:
        raise PolicyError(f"action reference must be static and versioned: {specification!r}")
    parts = action.split("/")
    if len(parts) < 2 or not all(parts[:2]):
        raise PolicyError(f"invalid action reference {specification!r}")
    repository = "/".join(parts[:2]).lower()
    manifest_directory = "/".join(parts[2:])
    return repository, manifest_directory, reference


def _action_runtime(source: str, specification: str) -> str:
    manifest = _parse_yaml(source, f"action manifest for {specification}")
    if isinstance(manifest, dict):
        runs = manifest.get("runs")
        if isinstance(runs, dict):
            runtime = runs.get("using")
            if isinstance(runtime, str) and re.fullmatch(r"[A-Za-z0-9._-]+", runtime):
                return runtime.lower()
    raise PolicyError(f"action {specification} has no runs.using declaration")


def _load_workflow_sources(client: GitHubClient, slug: str, commit: str) -> dict[str, str]:
    directory = ".github/workflows"
    encoded_directory = urllib.parse.quote(directory, safe="/")
    records = client.json(f"/repos/{slug}/contents/{encoded_directory}?ref={commit}")
    if not isinstance(records, list):
        raise PolicyError(f"{slug}@{commit} has no workflow directory listing")

    sources: dict[str, str] = {}
    for record in records:
        path = record.get("path")
        if record.get("type") != "file" or not isinstance(path, str) or not path.endswith((".yml", ".yaml")):
            continue
        if not path.startswith(f"{directory}/"):
            raise PolicyError(f"{slug}@{commit} returned workflow outside {directory}: {path!r}")
        encoded_path = urllib.parse.quote(path, safe="/")
        sources[path] = client.bytes(f"/repos/{slug}/contents/{encoded_path}?ref={commit}").decode("utf-8")
    if not sources:
        raise PolicyError(f"{slug}@{commit} has no public workflow sources")
    return sources


def _inspect_action_release(
    client: GitHubClient,
    specification: str,
    repository: str,
    manifest_directory: str,
    reference: str,
) -> dict[str, Any]:
    encoded_reference = urllib.parse.quote(reference, safe="")
    commit_data = client.json(f"/repos/{repository}/commits/{encoded_reference}")
    commit = commit_data.get("sha")
    if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise PolicyError(f"action {specification} did not resolve to an exact commit")

    prefix = f"{manifest_directory}/" if manifest_directory else ""
    source = None
    for filename in ("action.yml", "action.yaml"):
        path = urllib.parse.quote(f"{prefix}{filename}", safe="/")
        try:
            source = client.bytes(f"/repos/{repository}/contents/{path}?ref={commit}").decode("utf-8")
            break
        except ResourceNotFound:
            continue
    if source is None:
        raise PolicyError(f"action {specification}@{commit} has no action manifest")
    return {
        "action": f"{repository}/{manifest_directory}".rstrip("/"),
        "commit": commit,
        "reference": reference,
        "repository": repository,
        "runtime": _action_runtime(source, specification),
    }


def audit_action_releases(
    policy: dict[str, Any],
    client: GitHubClient,
    workflow_sources: dict[str, str],
    cache: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    usages: dict[str, set[str]] = {}
    for path, source in workflow_sources.items():
        for specification in _workflow_action_references(source, path):
            if _split_action_reference(specification) is not None:
                usages.setdefault(specification, set()).add(path)

    runtime_policy = policy["action_runtime"]
    allowed_releases = runtime_policy["allowed_releases"]
    supported_runtimes = set(runtime_policy["supported_javascript_runtimes"])
    evidence: list[dict[str, Any]] = []
    for specification, workflows in sorted(usages.items()):
        parsed = _split_action_reference(specification)
        if parsed is None:
            continue
        repository, manifest_directory, reference = parsed
        if repository not in allowed_releases:
            raise PolicyError(f"action {repository} has no centrally approved release")
        if reference not in allowed_releases[repository]:
            raise PolicyError(
                f"action {specification} is not centrally approved; allowed references are "
                f"{allowed_releases[repository]}"
            )
        if specification not in cache:
            cache[specification] = _inspect_action_release(
                client,
                specification,
                repository,
                manifest_directory,
                reference,
            )
        release = cache[specification]
        runtime = release["runtime"]
        if runtime.startswith("node") and runtime not in supported_runtimes:
            raise PolicyError(
                f"action {specification}@{release['commit']} uses retired JavaScript runtime {runtime}; "
                f"supported runtimes are {sorted(supported_runtimes)}"
            )
        evidence.append({**release, "workflows": sorted(workflows)})
    return evidence


def validate_local_action_references(policy: dict[str, Any], directory: Path) -> list[str]:
    sources = {
        path.as_posix(): path.read_text(encoding="utf-8") for path in sorted(directory.glob("*.y*ml")) if path.is_file()
    }
    allowed_releases = policy["action_runtime"]["allowed_releases"]
    specifications: set[str] = set()
    for path, source in sources.items():
        for specification in _workflow_action_references(source, path):
            parsed = _split_action_reference(specification)
            if parsed is None:
                continue
            repository, _manifest_directory, reference = parsed
            if repository not in allowed_releases or reference not in allowed_releases[repository]:
                raise PolicyError(f"local workflow action {specification} is not centrally approved")
            specifications.add(specification)
    return sorted(specifications)


def _latest_check_runs(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for record in records:
        name = record.get("name")
        if not isinstance(name, str):
            continue
        if name not in latest or int(record.get("id", 0)) > int(latest[name].get("id", 0)):
            latest[name] = record
    return latest


def _successful_check_runs(
    client: GitHubClient,
    slug: str,
    head_sha: str,
    required_checks: set[str],
    *,
    max_attempts: int,
    poll_seconds: float,
    sleep: Callable[[float], None],
) -> dict[str, int]:
    if max_attempts < 1 or poll_seconds < 0:
        raise ValueError("invalid check-run convergence configuration")

    path = f"/repos/{slug}/commits/{head_sha}/check-runs?filter=latest"
    for attempt in range(1, max_attempts + 1):
        latest = _latest_check_runs(client.collection(path, "check_runs"))
        pending: list[str] = []
        successful: dict[str, int] = {}
        for check in sorted(required_checks):
            record = latest.get(check)
            if record is None:
                pending.append(f"{check!r} has not been created")
                continue
            status = record.get("status")
            conclusion = record.get("conclusion")
            if status != "completed":
                pending.append(f"{check!r} is {status}/{conclusion}")
                continue
            if conclusion != "success":
                raise PolicyError(f"{slug}@{head_sha} check {check!r} is {status}/{conclusion}")
            successful[check] = int(record.get("id", 0))

        if not pending:
            return successful
        if attempt == max_attempts:
            raise PolicyError(
                f"{slug}@{head_sha} required checks did not converge after {max_attempts} attempts: "
                + "; ".join(pending)
            )
        print(
            f"qualification check wait: target={slug}@{head_sha} attempt={attempt}/{max_attempts} "
            f"delay={poll_seconds:g}s pending={'; '.join(pending)}",
            file=sys.stderr,
        )
        sleep(poll_seconds)

    raise AssertionError("check-run convergence loop ended unexpectedly")


def audit_policy(
    policy: dict[str, Any],
    client: GitHubClient,
    *,
    expected_commits: dict[str, str] | None = None,
    skip_check_runs_for: set[str] | None = None,
    check_run_max_attempts: int = CHECK_RUN_MAX_ATTEMPTS,
    check_run_poll_seconds: float = CHECK_RUN_POLL_SECONDS,
    check_run_sleep: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    validate_policy(policy)
    organization = policy["organization"]
    skipped = skip_check_runs_for or set()
    pinned = expected_commits or {}
    unknown_skips = skipped - set(policy["targets"])
    if unknown_skips:
        raise PolicyError(f"unknown skipped qualification targets: {sorted(unknown_skips)}")
    unknown_pins = set(pinned) - set(policy["targets"])
    if unknown_pins:
        raise PolicyError(f"unknown pinned qualification targets: {sorted(unknown_pins)}")
    invalid_pins = {name: commit for name, commit in pinned.items() if not COMMIT_PATTERN.fullmatch(commit)}
    if invalid_pins:
        raise PolicyError(f"invalid pinned qualification commits: {invalid_pins}")

    evidence: dict[str, Any] = {"schema": SCHEMA, "targets": {}}
    action_cache: dict[str, dict[str, Any]] = {}
    for name, target in policy["targets"].items():
        repository = target["repository"]
        branch = target["branch"]
        slug = f"{organization}/{repository}"
        encoded_branch = urllib.parse.quote(branch, safe="")

        repository_data = client.json(f"/repos/{slug}")
        if repository_data.get("default_branch") != branch:
            raise PolicyError(
                f"{slug} default branch is {repository_data.get('default_branch')!r}; expected {branch!r}"
            )
        branch_data = client.json(f"/repos/{slug}/branches/{encoded_branch}")
        head_sha = branch_data.get("commit", {}).get("sha")
        if not isinstance(head_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", head_sha):
            raise PolicyError(f"{slug}@{branch} did not resolve to an exact commit")
        if name in pinned and head_sha != pinned[name]:
            raise PolicyError(
                f"{slug}@{branch} advanced to {head_sha}; the requested release plan pins {pinned[name]}"
            )

        workflow_sources = _load_workflow_sources(client, slug, head_sha)
        action_releases = audit_action_releases(policy, client, workflow_sources, action_cache)
        workflow_evidence = []
        for workflow in target["workflows"]:
            workflow_path = workflow["path"]
            encoded_workflow = urllib.parse.quote(workflow_path, safe="")
            metadata = client.json(f"/repos/{slug}/actions/workflows/{encoded_workflow}")
            expected_path = f".github/workflows/{workflow_path}"
            if metadata.get("state") != "active" or metadata.get("path") != expected_path:
                raise PolicyError(f"{slug} does not expose active workflow {expected_path}")
            source = workflow_sources.get(expected_path)
            if source is None:
                raise PolicyError(f"{slug}@{head_sha} does not contain {expected_path}")
            verify_workflow_source(name, branch, workflow, source)
            workflow_evidence.append(
                {
                    "path": expected_path,
                    "required_check": workflow["required_check"],
                    "workflow_id": metadata.get("id"),
                }
            )

        required_checks = {workflow["required_check"] for workflow in target["workflows"]}
        successful_checks: dict[str, int] = {}
        if name not in skipped:
            successful_checks = _successful_check_runs(
                client,
                slug,
                head_sha,
                required_checks,
                max_attempts=check_run_max_attempts,
                poll_seconds=check_run_poll_seconds,
                sleep=check_run_sleep,
            )

        rules = client.list_collection(f"/repos/{slug}/rules/branches/{encoded_branch}")
        protected_checks: set[str] = set()
        strict = False
        for rule in rules:
            if rule.get("type") != "required_status_checks":
                continue
            parameters = rule.get("parameters") or {}
            strict = strict or parameters.get("strict_required_status_checks_policy") is True
            for check in parameters.get("required_status_checks") or []:
                context = check.get("context")
                if isinstance(context, str):
                    protected_checks.add(context)
        missing_protection = required_checks - protected_checks
        if missing_protection:
            raise PolicyError(f"{slug}@{branch} does not protect checks {sorted(missing_protection)}")
        if policy["required_status_checks_strict"] and not strict:
            raise PolicyError(f"{slug}@{branch} does not enforce strict required status checks")

        evidence["targets"][name] = {
            "action_releases": action_releases,
            "branch": branch,
            "commit": head_sha,
            "protected_checks": sorted(required_checks),
            "successful_check_runs": successful_checks,
            "workflows": workflow_evidence,
        }
    return evidence


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("validate", "audit"))
    parser.add_argument("--policy", type=Path, default=Path("qualification/policy.json"))
    parser.add_argument("--github-token", default=os.environ.get("GITHUB_TOKEN"))
    parser.add_argument("--evidence", type=Path)
    parser.add_argument(
        "--expected-commits",
        type=Path,
        help="JSON object mapping qualification target names to exact expected target-branch commits",
    )
    parser.add_argument("--skip-check-runs-for", action="append", default=[])
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        policy = load_policy(args.policy)
        if args.command == "validate":
            actions = validate_local_action_references(policy, Path(".github/workflows"))
            result: dict[str, Any] = {
                "actions": actions,
                "schema": policy["schema"],
                "targets": sorted(policy["targets"]),
            }
        else:
            expected_commits = None
            if args.expected_commits:
                try:
                    expected_commits = json.loads(args.expected_commits.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as error:
                    raise PolicyError(f"cannot read expected qualification commits: {error}") from error
                if not isinstance(expected_commits, dict) or not all(
                    isinstance(name, str) and isinstance(commit, str)
                    for name, commit in expected_commits.items()
                ):
                    raise PolicyError("expected qualification commits must be a JSON string-to-string object")
            result = audit_policy(
                policy,
                GitHubClient(args.github_token),
                expected_commits=expected_commits,
                skip_check_runs_for=set(args.skip_check_runs_for),
            )
        output = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.evidence:
            args.evidence.write_text(output, encoding="utf-8")
        print(output, end="")
        return 0
    except GitHubInfrastructureError as error:
        print(f"qualification infrastructure failed: {error}", file=sys.stderr)
        return INFRASTRUCTURE_EXIT_CODE
    except PolicyError as error:
        print(f"qualification policy failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
