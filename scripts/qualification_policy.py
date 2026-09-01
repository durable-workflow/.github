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
    "ai": ("ai", "main"),
    "cli": ("cli", "main"),
    "cloud": ("cloud", "main"),
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
EXPECTED_PUBLIC_AUDIT_TARGETS = set(EXPECTED_TARGETS) - {"cloud"}
GITHUB_API_MAX_ATTEMPTS = 5
GITHUB_API_RETRY_BASE_SECONDS = 2.0
GITHUB_API_RETRY_MAX_SECONDS = 120.0
GITHUB_API_REQUEST_TIMEOUT_SECONDS = 30.0
GITHUB_API_AUDIT_TIMEOUT_SECONDS = 600.0
CHECK_RUN_MAX_ATTEMPTS = 20
CHECK_RUN_POLL_SECONDS = 30.0
INFRASTRUCTURE_EXIT_CODE = 75
SAFE_VALIDATOR_ENVIRONMENT_NAMES = {
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "REQUESTED_RUN_ATTEMPT",
    "REQUESTED_RUN_ID",
}
SAFE_VALIDATOR_ACTION_REPOSITORIES = {
    "actions/checkout",
    "actions/download-artifact",
    "actions/setup-python",
}
SAFE_VALIDATOR_RUNNERS = {"ubuntu-latest"}


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
        "allowed_container_images",
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
    for repository, releases in allowed_releases.items():
        if not isinstance(repository, str) or not re.fullmatch(r"[a-z0-9_.-]+/[a-z0-9_.-]+", repository):
            raise PolicyError(f"invalid action repository {repository!r}")
        if (
            not isinstance(releases, dict)
            or not releases
            or not all(
                isinstance(commit, str)
                and COMMIT_PATTERN.fullmatch(commit)
                and isinstance(version, str)
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", version)
                for commit, version in releases.items()
            )
        ):
            raise PolicyError(f"{repository} must map immutable action commits to readable versions")

    allowed_containers = action_runtime["allowed_container_images"]
    if not isinstance(allowed_containers, dict) or not allowed_containers:
        raise PolicyError("qualification policy must declare allowed container image digests")
    for image, releases in allowed_containers.items():
        if not isinstance(image, str) or not re.fullmatch(r"[a-z0-9._/-]+", image):
            raise PolicyError(f"invalid container image {image!r}")
        if (
            not isinstance(releases, dict)
            or not releases
            or not all(
                isinstance(digest, str)
                and re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
                and isinstance(version, str)
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", version)
                for digest, version in releases.items()
            )
        ):
            raise PolicyError(f"{image} must map immutable image digests to readable versions")

    workflow_trust = policy.get("workflow_trust")
    if not isinstance(workflow_trust, dict) or set(workflow_trust) != {
        "privileged_artifact_handoffs",
        "privileged_workflow_run_consumers",
        "pull_request_target_exceptions",
    }:
        raise PolicyError("qualification policy must declare the complete workflow trust contract")
    if workflow_trust["pull_request_target_exceptions"] != []:
        raise PolicyError("pull_request_target exceptions require a separately reviewed policy revision")
    artifact_handoffs = workflow_trust["privileged_artifact_handoffs"]
    if not isinstance(artifact_handoffs, dict) or set(artifact_handoffs) != {
        "validator_command",
        "validator_environment",
        "validator_preceding_steps",
        "validator_runner",
    }:
        raise PolicyError("qualification policy must declare the complete privileged artifact handoff contract")
    if (
        not isinstance(artifact_handoffs["validator_command"], str)
        or not artifact_handoffs["validator_command"].strip()
        or artifact_handoffs["validator_environment"]
        != [
            "ARTIFACT_DIRECTORY",
            "EXPECTED_ARTIFACT_DIGEST",
            "EXPECTED_ARTIFACT_ID",
            "EXPECTED_SOURCE_RUN_ATTEMPT",
            "EXPECTED_SOURCE_RUN_ID",
        ]
        or artifact_handoffs["validator_runner"] not in SAFE_VALIDATOR_RUNNERS
    ):
        raise PolicyError("qualification policy has an invalid privileged artifact handoff contract")
    preceding_steps = artifact_handoffs["validator_preceding_steps"]
    if not isinstance(preceding_steps, list) or len(preceding_steps) != 1:
        raise PolicyError("privileged artifact validation must have one reviewed predecessor")
    checkout = preceding_steps[0]
    if (
        not isinstance(checkout, dict)
        or set(checkout) != {"uses", "with"}
        or not isinstance(checkout["uses"], str)
        or _split_action_reference(checkout["uses"]) is None
        or _split_action_reference(checkout["uses"])[0] != "actions/checkout"
        or checkout["with"]
        != {
            "fetch-depth": "0",
            "persist-credentials": "false",
            "ref": "${{ github.sha }}",
        }
    ):
        raise PolicyError("privileged artifact validation predecessor must be the reviewed safe checkout")
    _checkout_repository, _checkout_directory, checkout_commit = _split_action_reference(checkout["uses"])
    checkout_releases = action_runtime["allowed_releases"].get("actions/checkout")
    if (
        not COMMIT_PATTERN.fullmatch(checkout_commit)
        or not isinstance(checkout_releases, dict)
        or checkout_commit not in checkout_releases
    ):
        raise PolicyError("privileged artifact validation predecessor must use an approved checkout release")
    consumers = workflow_trust["privileged_workflow_run_consumers"]
    if not isinstance(consumers, dict):
        raise PolicyError("privileged workflow_run consumers must be an object")
    required_consumer_fields = {
        "artifact_digest_validator_command",
        "artifact_digest_validator_environment",
        "artifact_digest_validator_preceding_steps",
        "event",
        "identity_validator_command",
        "identity_validator_environment",
        "identity_validator_preceding_steps",
        "privileged_job_condition",
        "protected_ref",
        "repository",
        "validator_runner",
        "workflow",
    }
    for path, consumer in consumers.items():
        if not isinstance(path, str) or not re.fullmatch(r"[a-z0-9-]+/[a-z0-9][a-z0-9.-]*\.yml", path):
            raise PolicyError(f"invalid privileged workflow_run consumer path {path!r}")
        if not isinstance(consumer, dict) or set(consumer) != required_consumer_fields:
            raise PolicyError(f"{path} must declare the complete workflow_run trust binding")
        if consumer["event"] not in {"push", "workflow_dispatch"}:
            raise PolicyError(f"{path} source event is not a reviewed trusted event")
        if (
            not isinstance(consumer["validator_runner"], str)
            or consumer["validator_runner"] not in SAFE_VALIDATOR_RUNNERS
        ):
            raise PolicyError(f"{path} validator runner must be a reviewed GitHub-hosted runner")
        string_fields = required_consumer_fields - {
            "artifact_digest_validator_environment",
            "artifact_digest_validator_preceding_steps",
            "identity_validator_environment",
            "identity_validator_preceding_steps",
        }
        if not all(isinstance(consumer[field], str) and consumer[field].strip() for field in string_fields):
            raise PolicyError(f"{path} workflow_run trust binding values must be non-empty strings")
        for field in ("artifact_digest_validator_environment", "identity_validator_environment"):
            environment = consumer[field]
            if (
                not isinstance(environment, list)
                or not all(
                    isinstance(name, str) and name in SAFE_VALIDATOR_ENVIRONMENT_NAMES for name in environment
                )
                or len(environment) != len(set(environment))
            ):
                raise PolicyError(f"{path} {field} must contain only reviewed safe environment names")
        for field in (
            "artifact_digest_validator_preceding_steps",
            "identity_validator_preceding_steps",
        ):
            steps = consumer[field]
            if not isinstance(steps, list) or not 1 <= len(steps) <= 4:
                raise PolicyError(f"{path} {field} must declare one to four reviewed immutable action steps")
            for step in steps:
                if (
                    not isinstance(step, dict)
                    or set(step) != {"uses", "with"}
                    or not isinstance(step["uses"], str)
                    or not isinstance(step["with"], dict)
                    or not step["with"]
                    or not all(
                        isinstance(name, str)
                        and isinstance(value, str)
                        and value
                        for name, value in step["with"].items()
                    )
                ):
                    raise PolicyError(f"{path} {field} must contain only reviewed immutable action steps")
                parsed = _split_action_reference(step["uses"])
                if parsed is None:
                    raise PolicyError(f"{path} {field} must contain only reviewed immutable action steps")
                repository, _manifest_directory, commit = parsed
                releases = action_runtime["allowed_releases"].get(repository)
                if (
                    repository not in SAFE_VALIDATOR_ACTION_REPOSITORIES
                    or not COMMIT_PATTERN.fullmatch(commit)
                    or not isinstance(releases, dict)
                    or commit not in releases
                ):
                    raise PolicyError(f"{path} {field} must contain only reviewed immutable action steps")
                settings = step["with"]
                if repository == "actions/checkout":
                    trusted_controller = settings == {"persist-credentials": "false"}
                    qualified_source = (
                        consumer["event"] == "push"
                        and field == "artifact_digest_validator_preceding_steps"
                        and settings
                        == {
                            "fetch-depth": "0",
                            "ref": "${{ needs.bind.outputs.source_head_sha }}",
                        }
                    )
                    if not trusted_controller and not qualified_source:
                        raise PolicyError(
                            f"{path} {field} checkout must select only the trusted controller"
                        )
                if repository == "actions/setup-python" and (
                    set(settings) != {"python-version"}
                    or re.fullmatch(r"3\.\d+", settings["python-version"]) is None
                ):
                    raise PolicyError(f"{path} {field} Python setup must select one reviewed runtime")
                if repository == "actions/download-artifact":
                    selectors = {"artifact-ids", "name", "pattern"}.intersection(settings)
                    if (
                        len(selectors) != 1
                        or set(settings)
                        != selectors | {"digest-mismatch", "github-token", "path", "run-id"}
                        or settings["digest-mismatch"] != "error"
                        or settings["github-token"] != "${{ github.token }}"
                        or re.fullmatch(r"[a-z0-9][a-z0-9_-]*", settings["path"]) is None
                        or re.fullmatch(
                            r"\$\{\{ needs\.[A-Za-z0-9_-]+\.outputs\.[A-Za-z0-9_-]+ }}",
                            settings["run-id"],
                        )
                        is None
                    ):
                        raise PolicyError(f"{path} {field} artifact download must bind one exact source run")
        if any(
            _split_action_reference(step["uses"])[0] == "actions/download-artifact"
            for step in consumer["identity_validator_preceding_steps"]
        ):
            raise PolicyError(f"{path} identity validation must precede artifact downloads")
        has_artifact_download = any(
            _split_action_reference(step["uses"])[0] == "actions/download-artifact"
            for step in consumer["artifact_digest_validator_preceding_steps"]
        )
        if consumer["event"] == "workflow_dispatch" and not has_artifact_download:
            raise PolicyError(f"{path} artifact validation must follow a reviewed artifact download")

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
        expected_public_audit = name in EXPECTED_PUBLIC_AUDIT_TARGETS
        if target.get("public_audit", True) is not expected_public_audit:
            raise PolicyError(f"{name} public_audit must be {expected_public_audit}")
        workflows = target.get("workflows")
        if not isinstance(workflows, list) or not workflows:
            raise PolicyError(f"{name} must declare at least one qualification workflow")
        checks: set[str] = set()
        paths: set[str] = set()
        preflight_workflows: list[str] = []
        for workflow in workflows:
            path = workflow.get("path")
            check = workflow.get("required_check")
            if not isinstance(path, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]*\.yml", path):
                raise PolicyError(f"{name} has invalid workflow path {path!r}")
            if not isinstance(check, str) or not check.strip():
                raise PolicyError(f"{name}/{path} has no required check context")
            if not isinstance(workflow.get("matrix_independent"), bool):
                raise PolicyError(f"{name}/{path} must declare matrix_independent")
            action_policy_preflight = workflow.get("action_policy_preflight", False)
            if not isinstance(action_policy_preflight, bool):
                raise PolicyError(f"{name}/{path} action_policy_preflight must be a boolean")
            if action_policy_preflight:
                preflight_workflows.append(path)
            if path in paths or check in checks:
                raise PolicyError(f"{name} has duplicate workflow paths or check contexts")
            paths.add(path)
            checks.add(check)

        expected_preflight_count = 0 if name == "github-control-plane" else 1
        if len(preflight_workflows) != expected_preflight_count:
            raise PolicyError(
                f"{name} must declare exactly {expected_preflight_count} central action policy "
                f"preflight workflow(s), got {sorted(preflight_workflows)}"
            )


def _normalized_shell(value: object) -> str:
    return re.sub(r"\s+", " ", value.strip()) if isinstance(value, str) else ""


def _is_action_step(step: object, repository: str) -> bool:
    if not isinstance(step, dict) or not isinstance(step.get("uses"), str):
        return False
    parsed = _split_action_reference(step["uses"])
    return (
        parsed is not None
        and parsed[0] == repository
        and parsed[1] == ""
        and COMMIT_PATTERN.fullmatch(parsed[2]) is not None
    )


def _verify_action_policy_preflight(
    target_name: str,
    label: str,
    jobs: dict[str, Any],
    gate_job_name: str,
) -> None:
    preflight = jobs.get("action-policy")
    if not isinstance(preflight, dict):
        raise PolicyError(f"{label} has no central action policy preflight job")
    accepted_conditions = {"", "github.server_url == 'https://github.com'"}
    if (
        preflight.get("name") != "Central action policy preflight"
        or _condition_without_expression_wrapper(preflight.get("if", "")) not in accepted_conditions
        or preflight.get("runs-on") != "ubuntu-latest"
        or preflight.get("timeout-minutes") != "5"
        or preflight.get("needs") is not None
        or preflight.get("permissions") is not None
        or preflight.get("env") is not None
    ):
        raise PolicyError(f"{label} central action policy preflight job is not the reviewed read-only shape")

    steps = preflight.get("steps")
    if not isinstance(steps, list) or len(steps) != 5 or not all(isinstance(step, dict) for step in steps):
        raise PolicyError(f"{label} central action policy preflight must contain the five reviewed steps")
    candidate, central, setup_python, install, validate = steps
    if (
        not _is_action_step(candidate, "actions/checkout")
        or candidate.get("with") != {"persist-credentials": "false"}
    ):
        raise PolicyError(f"{label} central action policy preflight must check out credential-free candidate source")
    if (
        not _is_action_step(central, "actions/checkout")
        or central.get("with")
        != {
            "repository": "durable-workflow/.github",
            "ref": "main",
            "path": ".central-action-policy",
            "persist-credentials": "false",
        }
    ):
        raise PolicyError(f"{label} central action policy preflight must use protected central policy source")
    if (
        not _is_action_step(setup_python, "actions/setup-python")
        or setup_python.get("with") != {"python-version": "3.13"}
    ):
        raise PolicyError(f"{label} central action policy preflight must use the reviewed Python runtime")
    if set(install) - {"name", "run"} or _normalized_shell(install.get("run")) != (
        "python -m pip install PyYAML==6.0.2"
    ):
        raise PolicyError(f"{label} central action policy preflight must install the reviewed policy dependency")
    expected_validation = (
        "python .central-action-policy/scripts/qualification_policy.py validate "
        f"--policy .central-action-policy/qualification/policy.json --target {target_name} "
        "--workflow-directory .github/workflows"
    )
    if set(validate) - {"name", "run"} or _normalized_shell(validate.get("run")) != expected_validation:
        raise PolicyError(f"{label} central action policy preflight does not invoke the reviewed validator")

    gate = jobs[gate_job_name]
    if "action-policy" not in _job_needs(gate, f"{label} required check gate"):
        raise PolicyError(f"{label} required check does not depend on the central action policy preflight")
    condition = gate.get("if")
    if not isinstance(condition, str) or "always()" not in _condition_without_expression_wrapper(condition):
        raise PolicyError(f"{label} required check must run after a failed central action policy preflight")
    reviewed_gate = {
        "env": {"ACTION_POLICY_RESULT": "${{ needs.action-policy.result }}"},
        "run": 'test "$ACTION_POLICY_RESULT" = success',
    }
    if not any(
        isinstance(step, dict)
        and _condition_without_expression_wrapper(step.get("if", "")) in accepted_conditions
        and step.get("env") == reviewed_gate["env"]
        and _normalized_shell(step.get("run")) == reviewed_gate["run"]
        for step in gate.get("steps") or []
    ):
        raise PolicyError(f"{label} required check does not fail closed on the central action policy result")


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

    document = _parse_yaml(source, label)
    jobs = document.get("jobs") if isinstance(document, dict) else None
    if not isinstance(jobs, dict) or not jobs:
        raise PolicyError(f"{label} must declare jobs")
    required_check = workflow["required_check"]
    stable_jobs: list[str] = []
    for job_id, job in jobs.items():
        if not isinstance(job_id, str) or not isinstance(job, dict):
            continue
        job_name = job.get("name", job_id)
        strategy = job.get("strategy")
        has_matrix = isinstance(strategy, dict) and "matrix" in strategy
        if isinstance(job_name, str) and job_name == required_check and "${{" not in job_name and not has_matrix:
            stable_jobs.append(job_id)
    if len(stable_jobs) != 1:
        raise PolicyError(
            f"{label} does not emit required check {required_check!r} as exactly one stable non-matrix job; "
            f"matching jobs={stable_jobs}"
        )
    if workflow.get("action_policy_preflight") is True:
        _verify_action_policy_preflight(name, label, jobs, stable_jobs[0])


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
    if specification.startswith(("./", "docker://")):
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


def _split_container_reference(specification: str) -> tuple[str, str] | None:
    if not specification.startswith("docker://"):
        return None
    image, separator, digest = specification.removeprefix("docker://").rpartition("@")
    if not separator or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise PolicyError(f"container action must use an immutable sha256 digest: {specification!r}")
    if not re.fullmatch(r"[a-z0-9._/-]+", image):
        raise PolicyError(f"invalid container action image {image!r}")
    return image, digest


def _permissions_with_write(permissions: Any, label: str) -> set[str]:
    if not isinstance(permissions, dict):
        raise PolicyError(f"{label} permissions must be an explicit mapping")
    writes: set[str] = set()
    for scope, access in permissions.items():
        if not isinstance(scope, str) or access not in {"read", "write", "none"}:
            raise PolicyError(f"{label} has invalid permission {scope!r}: {access!r}")
        if access == "write":
            writes.add(scope)
    return writes


def _reference_source_lines(source: str, specification: str) -> list[str]:
    pattern = re.compile(rf"(?:^|[{{,\s-])uses\s*:\s*['\"]?{re.escape(specification)}(?:['\"]|[\s,}}#]|$)")
    return [line for line in source.splitlines() if pattern.search(line)]


def _require_reference_comment(source: str, specification: str, version: str, label: str) -> None:
    lines = _reference_source_lines(source, specification)
    if not lines:
        raise PolicyError(f"{label} cannot locate source for action reference {specification!r}")
    comment = re.compile(rf"#\s*{re.escape(version)}(?:\s|$)")
    if any(not comment.search(line) for line in lines):
        raise PolicyError(f"{label} action {specification} must carry readable version comment '# {version}'")


def _job_action_steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    steps = job.get("steps") or []
    if not isinstance(steps, list):
        return []
    return [step for step in steps if isinstance(step, dict) and isinstance(step.get("uses"), str)]


def _job_needs(job: dict[str, Any], label: str) -> set[str]:
    needs = job.get("needs")
    if needs is None:
        return set()
    if isinstance(needs, str) and needs:
        return {needs}
    if isinstance(needs, list) and all(isinstance(name, str) and name for name in needs):
        return set(needs)
    raise PolicyError(f"{label} has an invalid needs dependency")


def _string_values(value: Any) -> list[str]:
    values: list[str] = []
    if isinstance(value, dict):
        for nested in value.values():
            values.extend(_string_values(nested))
    elif isinstance(value, list):
        for nested in value:
            values.extend(_string_values(nested))
    elif isinstance(value, str):
        values.append(value)
    return values


def _references_secret_context(value: Any) -> bool:
    for scalar in _string_values(value):
        for expression in re.findall(r"\$\{\{(.*?)}}", scalar, flags=re.DOTALL):
            if re.search(r"(?i)\bsecrets\b", expression):
                return True
    return False


def _unsafe_cache_path(path: str) -> bool:
    paths = [candidate.strip() for candidate in path.splitlines() if candidate.strip()]
    if not paths:
        return True
    for candidate in paths:
        candidate = candidate.removeprefix("!").strip().replace("\\", "/")
        compact = re.sub(r"\s+", "", candidate)
        if compact in {
            ".",
            "./",
            "..",
            "/",
            "/*",
            "/**",
            "**",
            "./**",
            "~",
            "~/",
            "$HOME",
            "${HOME}",
            "$GITHUB_WORKSPACE",
            "${GITHUB_WORKSPACE}",
            "${{github.workspace}}",
            "${{env.HOME}}",
            "${{env.GITHUB_WORKSPACE}}",
        }:
            return True
        broad_roots = (
            "~",
            "$HOME",
            "${HOME}",
            "$GITHUB_WORKSPACE",
            "${GITHUB_WORKSPACE}",
            "${{github.workspace}}",
            "${{env.HOME}}",
            "${{env.GITHUB_WORKSPACE}}",
        )
        if any(
            compact.startswith(f"{root}/")
            and compact.removeprefix(f"{root}/") in {"*", "**", "**/*"}
            for root in broad_roots
        ):
            return True
        if re.match(r"(?i)^[a-z]:/?$", candidate):
            return True
        if re.search(r"(?i)(secret|credential|\.ssh|\.npmrc|\.pypirc|\.docker)", candidate):
            return True
    return False


def _cache_keys_partition_events(value: str) -> bool:
    event_partition = re.compile(r"\$\{\{\s*github\.event_name\s*}}")
    keys = [key.strip() for key in value.splitlines() if key.strip()]
    return bool(keys) and all(event_partition.search(key) for key in keys)


def _condition_without_expression_wrapper(condition: str) -> str:
    condition = condition.strip()
    if condition.startswith("${{") and condition.endswith("}}"):
        return condition[3:-2].strip()
    return condition


def _strip_balanced_parentheses(expression: str) -> str:
    expression = expression.strip()
    while expression.startswith("(") and expression.endswith(")"):
        depth = 0
        quote: str | None = None
        encloses_all = True
        for index, character in enumerate(expression):
            if quote is not None:
                if character == quote:
                    quote = None
                continue
            if character in {"'", '"'}:
                quote = character
            elif character == "(":
                depth += 1
            elif character == ")":
                depth -= 1
                if depth == 0 and index != len(expression) - 1:
                    encloses_all = False
                    break
        if not encloses_all or depth != 0 or quote is not None:
            break
        expression = expression[1:-1].strip()
    return expression


def _split_condition(expression: str, operator: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    quote: str | None = None
    index = 0
    while index < len(expression):
        character = expression[index]
        if quote is not None:
            if character == quote:
                quote = None
            index += 1
            continue
        if character in {"'", '"'}:
            quote = character
            index += 1
            continue
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
        elif depth == 0 and expression.startswith(operator, index):
            parts.append(expression[start:index].strip())
            start = index + len(operator)
            index = start
            continue
        index += 1
    if parts:
        parts.append(expression[start:].strip())
    return parts


def _condition_truth_for_unprotected_dispatch(expression: str, protected_ref: str) -> tuple[bool, bool]:
    """Return whether an expression can be true/false for a dispatch from another ref."""

    expression = _strip_balanced_parentheses(expression)
    disjunction = _split_condition(expression, "||")
    if disjunction:
        values = [_condition_truth_for_unprotected_dispatch(part, protected_ref) for part in disjunction]
        return any(value[0] for value in values), all(value[1] for value in values)
    conjunction = _split_condition(expression, "&&")
    if conjunction:
        values = [_condition_truth_for_unprotected_dispatch(part, protected_ref) for part in conjunction]
        return all(value[0] for value in values), any(value[1] for value in values)
    if expression.startswith("!") and not expression.startswith("!="):
        can_be_true, can_be_false = _condition_truth_for_unprotected_dispatch(expression[1:], protected_ref)
        return can_be_false, can_be_true

    comparison = re.fullmatch(
        r"github\.(event_name|ref)\s*(==|!=)\s*(['\"])(.*?)\3",
        expression,
        flags=re.DOTALL,
    )
    if comparison is None:
        return True, True
    field, operator, _quote, expected = comparison.groups()
    if field == "event_name":
        equality = expected == "workflow_dispatch"
        value = equality if operator == "==" else not equality
        return value, not value
    if expected != protected_ref:
        return True, True
    equality = False
    value = equality if operator == "==" else not equality
    return value, not value


def _protects_manual_dispatch(job: dict[str, Any], protected_ref: str) -> bool:
    condition = job.get("if")
    if not isinstance(condition, str) or not condition.strip():
        return False
    expression = _condition_without_expression_wrapper(condition)
    can_run_unprotected, _can_skip_unprotected = _condition_truth_for_unprotected_dispatch(
        expression,
        protected_ref,
    )
    return not can_run_unprotected


def _run_defaults(scope: Mapping[str, Any]) -> Mapping[str, Any]:
    defaults = scope.get("defaults")
    if not isinstance(defaults, dict):
        return {}
    run = defaults.get("run")
    return run if isinstance(run, dict) else {}


def _uses_only_allowed_environment(
    scopes: tuple[Mapping[str, Any], ...], allowed_environment: object
) -> bool:
    if not isinstance(allowed_environment, list) or not all(isinstance(name, str) for name in allowed_environment):
        return False
    allowed_names = set(allowed_environment)
    for scope in scopes:
        environment = scope.get("env")
        if environment is None:
            continue
        if not isinstance(environment, dict) or not set(environment).issubset(allowed_names):
            return False
    return True


def _trusted_validator_action_step(step: object, expected_step: object) -> bool:
    if (
        not isinstance(step, dict)
        or not isinstance(expected_step, dict)
        or set(expected_step) != {"uses", "with"}
        or not set(step).issubset({"name", "uses", "with"})
    ):
        return False
    return step.get("uses") == expected_step["uses"] and step.get("with") == expected_step["with"]


def _step_invokes(
    workflow: Mapping[str, Any],
    job: Mapping[str, Any],
    step: dict[str, Any],
    expected_command: str,
    allowed_environment: object,
) -> bool:
    """Accept a reviewed validator only as the step's sole, unconditional command."""

    command = step.get("run")
    return (
        isinstance(command, str)
        and command == expected_command
        and "if" not in step
        and step.get("continue-on-error") in (None, False, "false")
        and not any(
            key in execution_scope
            for key in ("shell", "working-directory")
            for execution_scope in (step, _run_defaults(job), _run_defaults(workflow))
        )
        and _uses_only_allowed_environment((workflow, job, step), allowed_environment)
    )


def _reviewed_validator_step(
    workflow: Mapping[str, Any],
    job: dict[str, Any],
    expected_command: str,
    allowed_environment: object,
    preceding_steps: object,
    runner: object,
) -> dict[str, Any] | None:
    if job.get("runs-on") != runner or "container" in job or "services" in job:
        return None
    steps = job.get("steps") or []
    if (
        not isinstance(steps, list)
        or not isinstance(preceding_steps, list)
        or not all(isinstance(step, dict) for step in preceding_steps)
        or len(steps) <= len(preceding_steps)
    ):
        return None
    if not all(
        _trusted_validator_action_step(step, expected_step)
        for step, expected_step in zip(steps[: len(preceding_steps)], preceding_steps, strict=True)
    ):
        return None
    validator = steps[len(preceding_steps)]
    if not isinstance(validator, dict) or not _step_invokes(
        workflow,
        job,
        validator,
        expected_command,
        allowed_environment,
    ):
        return None
    return validator


def _job_invokes_after_trusted_actions(
    workflow: Mapping[str, Any],
    job: dict[str, Any],
    expected_command: str,
    allowed_environment: object,
    preceding_steps: object,
    runner: object,
) -> bool:
    return _reviewed_validator_step(
        workflow,
        job,
        expected_command,
        allowed_environment,
        preceding_steps,
        runner,
    ) is not None


def _identity_validator_binds_requested_run(step: Mapping[str, Any]) -> bool:
    environment = step.get("env")
    if not isinstance(environment, dict):
        return False

    def normalized(value: object) -> str:
        return re.sub(r"\s+", " ", value.strip()) if isinstance(value, str) else ""

    return (
        normalized(environment.get("GH_TOKEN")) == "${{ github.token }}"
        and normalized(environment.get("REQUESTED_RUN_ID"))
        == "${{ inputs.source_run_id || github.event.workflow_run.id }}"
        and normalized(environment.get("REQUESTED_RUN_ATTEMPT"))
        == "${{ inputs.source_run_attempt || github.event.workflow_run.run_attempt }}"
    )


def _exact_expression(value: object, pattern: str) -> re.Match[str] | None:
    if not isinstance(value, str):
        return None
    expression = re.fullmatch(r"\$\{\{\s*(.*?)\s*}}", value, flags=re.DOTALL)
    if expression is None:
        return None
    return re.fullmatch(pattern, expression.group(1).strip())


def _direct_artifact_handoff(
    workflow: dict[str, Any],
    jobs: dict[str, Any],
    job: dict[str, Any],
    download_index: int,
    settings: dict[str, Any],
    handoff_policy: dict[str, Any],
    label: str,
) -> bool:
    """Prove one direct, digest-bound artifact handoff before privileged use."""

    if job.get("runs-on") != handoff_policy["validator_runner"] or "container" in job or "services" in job:
        return False
    if workflow.get("env") is not None or job.get("env") is not None:
        return False
    if set(settings) != {
        "artifact-ids",
        "digest-mismatch",
        "github-token",
        "path",
        "repository",
        "run-id",
    }:
        return False
    download_directory = settings.get("path")
    if (
        settings.get("digest-mismatch") != "error"
        or settings.get("github-token") != "${{ github.token }}"
        or settings.get("repository") != "${{ github.repository }}"
        or not isinstance(download_directory, str)
        or re.fullmatch(r"isolated-[a-z0-9][a-z0-9._-]*", download_directory) is None
    ):
        return False

    artifact_id = _exact_expression(
        settings.get("artifact-ids"),
        r"needs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)",
    )
    if artifact_id is None:
        return False
    producer_name, artifact_id_output = artifact_id.groups()
    needs = _job_needs(job, label)
    producer = jobs.get(producer_name)
    if producer_name not in needs or not isinstance(producer, dict):
        return False
    outputs = producer.get("outputs")
    if not isinstance(outputs, dict):
        return False
    upload_reference = _exact_expression(
        outputs.get(artifact_id_output),
        r"steps\.([A-Za-z0-9_-]+)\.outputs\.artifact-id",
    )
    if upload_reference is None:
        return False
    upload_id = upload_reference.group(1)
    upload_step = None
    for step in producer.get("steps") or []:
        if not isinstance(step, dict) or step.get("id") != upload_id:
            continue
        parsed = _split_action_reference(step.get("uses")) if isinstance(step.get("uses"), str) else None
        if parsed is not None and parsed[0] == "actions/upload-artifact":
            upload_step = step
            break
    if upload_step is None or not set(upload_step).issubset({"id", "name", "uses", "with"}):
        return False
    upload_settings = upload_step.get("with")
    if (
        not isinstance(upload_settings, dict)
        or set(upload_settings) != {"archive", "if-no-files-found", "path"}
        or upload_settings.get("archive") != "false"
        or upload_settings.get("if-no-files-found") != "error"
        or not isinstance(upload_settings.get("path"), str)
        or re.fullmatch(r"[a-z0-9][a-z0-9._-]*", upload_settings["path"]) is None
    ):
        return False

    def output_name_for(expected: str) -> str | None:
        names = [
            name
            for name, value in outputs.items()
            if isinstance(name, str)
            and _exact_expression(value, re.escape(expected)) is not None
        ]
        return names[0] if len(names) == 1 else None

    digest_output = output_name_for(f"steps.{upload_id}.outputs.artifact-digest")
    run_id_output = output_name_for("github.run_id")
    run_attempt_output = output_name_for("github.run_attempt")
    if None in {digest_output, run_id_output, run_attempt_output}:
        return False
    expected_run_id = f"${{{{ needs.{producer_name}.outputs.{run_id_output} }}}}"
    if settings.get("run-id") != expected_run_id:
        return False

    steps = job.get("steps") or []
    preceding_steps = handoff_policy["validator_preceding_steps"]
    if (
        not isinstance(steps, list)
        or not isinstance(preceding_steps, list)
        or download_index != len(preceding_steps)
        or download_index + 1 >= len(steps)
        or not all(
            _trusted_validator_action_step(step, expected_step)
            for step, expected_step in zip(steps[:download_index], preceding_steps, strict=True)
        )
    ):
        return False
    download_step = steps[download_index]
    if not isinstance(download_step, dict) or not set(download_step).issubset({"name", "uses", "with"}):
        return False
    validator = steps[download_index + 1]
    if not isinstance(validator, dict) or not set(validator).issubset({"env", "name", "run"}):
        return False
    expected_environment = {
        "ARTIFACT_DIRECTORY": download_directory,
        "EXPECTED_ARTIFACT_DIGEST": f"${{{{ needs.{producer_name}.outputs.{digest_output} }}}}",
        "EXPECTED_ARTIFACT_ID": settings["artifact-ids"],
        "EXPECTED_SOURCE_RUN_ATTEMPT": f"${{{{ needs.{producer_name}.outputs.{run_attempt_output} }}}}",
        "EXPECTED_SOURCE_RUN_ID": expected_run_id,
    }
    if validator.get("env") != expected_environment:
        return False
    return _step_invokes(
        workflow,
        job,
        validator,
        handoff_policy["validator_command"],
        handoff_policy["validator_environment"],
    )


def _scan_workflow_trust(
    policy: dict[str, Any],
    target_name: str,
    workflow_path: str,
    source: str,
) -> dict[str, Any]:
    label = f"{target_name}/{workflow_path}"
    document = _parse_yaml(source, label)
    if not isinstance(document, dict):
        raise PolicyError(f"{label} must contain a workflow mapping")
    triggers = document.get("on")
    if not isinstance(triggers, dict):
        raise PolicyError(f"{label} must declare explicit workflow triggers")
    if "pull_request_target" in triggers:
        raise PolicyError(f"{label} uses forbidden pull_request_target execution")

    top_writes = _permissions_with_write(document.get("permissions"), f"{label} top-level")
    if top_writes:
        raise PolicyError(f"{label} grants top-level write permissions {sorted(top_writes)}")

    action_runtime = policy["action_runtime"]
    references = _workflow_action_references(source, label)
    external_actions: set[str] = set()
    container_actions: set[str] = set()
    local_actions: set[str] = set()
    for specification in references:
        if specification.startswith("./"):
            local_actions.add(specification)
            _require_reference_comment(source, specification, "local", label)
            continue
        container = _split_container_reference(specification)
        if container is not None:
            image, digest = container
            releases = action_runtime["allowed_container_images"].get(image)
            if not isinstance(releases, dict) or digest not in releases:
                raise PolicyError(f"{label} container action {specification} is not centrally approved")
            _require_reference_comment(source, specification, releases[digest], label)
            container_actions.add(specification)
            continue
        parsed = _split_action_reference(specification)
        if parsed is None:
            raise PolicyError(f"{label} has unsupported action reference {specification!r}")
        repository, _manifest_directory, commit = parsed
        releases = action_runtime["allowed_releases"].get(repository)
        if not COMMIT_PATTERN.fullmatch(commit):
            raise PolicyError(f"{label} action {specification} is not pinned to a full commit SHA")
        if not isinstance(releases, dict) or commit not in releases:
            raise PolicyError(f"{label} action {specification} is not centrally approved")
        _require_reference_comment(source, specification, releases[commit], label)
        external_actions.add(specification)

    pull_request = "pull_request" in triggers
    manual_dispatch = "workflow_dispatch" in triggers
    protected_ref = f"refs/heads/{policy['targets'][target_name]['branch']}"
    workflow_run = triggers.get("workflow_run")
    consumer_key = f"{target_name}/{Path(workflow_path).name}"
    consumer_policy = policy["workflow_trust"]["privileged_workflow_run_consumers"].get(consumer_key)
    reviewed_workflow_run = workflow_run is not None and consumer_policy is not None
    workflow_values = {key: value for key, value in document.items() if key != "jobs"}
    if pull_request and _references_secret_context(workflow_values):
        raise PolicyError(f"{label} pull-request workflow references a secret")
    jobs = document.get("jobs")
    if not isinstance(jobs, dict) or not jobs:
        raise PolicyError(f"{label} must declare jobs")
    privileged_jobs: list[str] = []
    for job_name, job in jobs.items():
        if not isinstance(job_name, str) or not isinstance(job, dict):
            raise PolicyError(f"{label} has an invalid job declaration")
        job_permissions = job.get("permissions")
        job_writes = (
            _permissions_with_write(job_permissions, f"{label} job {job_name!r}")
            if job_permissions is not None
            else set()
        )
        job_privileged = bool(
            job_writes or "environment" in job or "secrets" in job or _references_secret_context(job)
        )
        if job_privileged:
            privileged_jobs.append(job_name)
        if manual_dispatch and job_privileged and not _protects_manual_dispatch(job, protected_ref):
            raise PolicyError(
                f"{label} privileged workflow_dispatch job {job_name!r} can run outside {protected_ref}"
            )
        if pull_request and job_writes:
            raise PolicyError(f"{label} pull-request job {job_name!r} grants write permissions")
        if pull_request and "environment" in job:
            raise PolicyError(f"{label} pull-request job {job_name!r} requests an environment")
        if pull_request and ("secrets" in job or _references_secret_context(job)):
            raise PolicyError(f"{label} pull-request job {job_name!r} references a secret")

        action_steps_by_identity = {id(step): index for index, step in enumerate(job.get("steps") or [])}
        for step in _job_action_steps(job):
            specification = step["uses"]
            parsed = _split_action_reference(specification)
            repository = parsed[0] if parsed is not None else None
            if repository == "actions/cache":
                settings = step.get("with")
                if not isinstance(settings, dict):
                    raise PolicyError(f"{label} cache step in job {job_name!r} must declare settings")
                path = settings.get("path")
                if not isinstance(path, str) or _unsafe_cache_path(path):
                    raise PolicyError(f"{label} cache step in job {job_name!r} has an unsafe cache path")
                if pull_request:
                    for key_name in ("key", "restore-keys"):
                        value = settings.get(key_name)
                        if value is not None and (
                            not isinstance(value, str) or not _cache_keys_partition_events(value)
                        ):
                            raise PolicyError(
                                f"{label} pull-request cache {key_name} in job {job_name!r} "
                                "must partition trusted and untrusted events"
                            )
                    if "key" not in settings:
                        raise PolicyError(f"{label} pull-request cache in job {job_name!r} has no explicit key")
            if repository == "actions/download-artifact" and job_privileged:
                settings = step.get("with")
                if not isinstance(settings, dict) or not ({"artifact-ids", "name", "pattern"} & set(settings)):
                    raise PolicyError(
                        f"{label} privileged artifact consumer {job_name!r} has no exact artifact selector"
                    )
                if not reviewed_workflow_run and not _direct_artifact_handoff(
                    document,
                    jobs,
                    job,
                    action_steps_by_identity[id(step)],
                    settings,
                    policy["workflow_trust"]["privileged_artifact_handoffs"],
                    f"{label} privileged artifact consumer {job_name!r}",
                ):
                    raise PolicyError(
                        f"{label} privileged artifact consumer {job_name!r} has no exact producer, "
                        "immutable artifact identity, and pre-use digest validation"
                    )

    if workflow_run is not None:
        if not isinstance(workflow_run, dict) or consumer_policy is None:
            raise PolicyError(f"{label} has no reviewed privileged workflow_run trust binding")
        if workflow_run.get("workflows") != [consumer_policy["workflow"]]:
            raise PolicyError(f"{label} workflow_run source identity differs from policy")
        if workflow_run.get("types") != ["completed"]:
            raise PolicyError(f"{label} workflow_run must accept only completed runs")
        binders: set[str] = set()
        for job_name, job in jobs.items():
            if not isinstance(job_name, str) or not isinstance(job, dict):
                continue
            validator_step = _reviewed_validator_step(
                document,
                job,
                consumer_policy["identity_validator_command"],
                consumer_policy["identity_validator_environment"],
                consumer_policy["identity_validator_preceding_steps"],
                consumer_policy["validator_runner"],
            )
            if validator_step is not None and _identity_validator_binds_requested_run(validator_step):
                binders.add(job_name)
        if not binders:
            raise PolicyError(f"{label} does not invoke its reviewed source identity validator")
        for job_name in privileged_jobs:
            job = jobs[job_name]
            needs = _job_needs(job, f"{label} privileged workflow_run job {job_name!r}")
            if not needs.intersection(binders) or "environment" not in job:
                raise PolicyError(f"{label} privileged workflow_run job {job_name!r} is not isolated behind a binder")
            condition = job.get("if")
            if (
                not isinstance(condition, str)
                or _condition_without_expression_wrapper(condition)
                != consumer_policy["privileged_job_condition"]
            ):
                raise PolicyError(
                    f"{label} privileged workflow_run job {job_name!r} "
                    "does not enforce its reviewed privilege condition"
                )
            if not _job_invokes_after_trusted_actions(
                document,
                job,
                consumer_policy["artifact_digest_validator_command"],
                consumer_policy["artifact_digest_validator_environment"],
                consumer_policy["artifact_digest_validator_preceding_steps"],
                consumer_policy["validator_runner"],
            ):
                raise PolicyError(f"{label} does not invoke its reviewed artifact digest validator")
            for step in _job_action_steps(job):
                parsed = _split_action_reference(step["uses"])
                if parsed is not None and parsed[0] == "actions/download-artifact":
                    settings = step.get("with") or {}
                    run_id = settings.get("run-id") if isinstance(settings, dict) else None
                    source_binders = (
                        set(re.findall(r"\bneeds\.([A-Za-z0-9_-]+)\.outputs\.", run_id))
                        if isinstance(run_id, str)
                        else set()
                    )
                    if not source_binders.intersection(binders):
                        raise PolicyError(
                            f"{label} privileged workflow_run job {job_name!r} does not select an exact run"
                        )
    elif consumer_policy is not None:
        raise PolicyError(f"{label} is policy-bound as a workflow_run consumer but has no workflow_run trigger")

    return {
        "containers": sorted(container_actions),
        "external_actions": sorted(external_actions),
        "local_actions": sorted(local_actions),
        "privileged_jobs": sorted(privileged_jobs),
    }


def scan_workflow_sources(
    policy: dict[str, Any], target_name: str, workflow_sources: Mapping[str, str]
) -> dict[str, dict[str, Any]]:
    if target_name not in policy["targets"]:
        raise PolicyError(f"unknown workflow trust target {target_name!r}")
    evidence: dict[str, dict[str, Any]] = {}
    for path, source in sorted(workflow_sources.items()):
        evidence[path] = _scan_workflow_trust(policy, target_name, path, source)
    expected_consumers = {
        key.rsplit("/", 1)[1]
        for key in policy["workflow_trust"]["privileged_workflow_run_consumers"]
        if key.startswith(f"{target_name}/")
    }
    present = {Path(path).name for path in workflow_sources}
    missing = expected_consumers - present
    if missing:
        raise PolicyError(f"{target_name} is missing policy-bound workflow_run consumers {sorted(missing)}")
    return evidence


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
    if reference != commit:
        raise PolicyError(f"action {specification} resolved to unexpected commit {commit}")

    if manifest_directory.startswith(".github/workflows/"):
        return {
            "action": f"{repository}/{manifest_directory}",
            "commit": commit,
            "reference": reference,
            "repository": repository,
            "runtime": "reusable-workflow",
        }

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
                f"{sorted(allowed_releases[repository])}"
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
        evidence.append(
            {
                **release,
                "version": allowed_releases[repository][reference],
                "workflows": sorted(workflows),
            }
        )
    return evidence


def validate_local_action_references(
    policy: dict[str, Any], directory: Path, target_name: str = "github-control-plane"
) -> list[str]:
    sources = {
        path.as_posix(): path.read_text(encoding="utf-8") for path in sorted(directory.glob("*.y*ml")) if path.is_file()
    }
    evidence = scan_workflow_sources(policy, target_name, sources)
    target = policy["targets"][target_name]
    for workflow in target["workflows"]:
        if workflow.get("action_policy_preflight") is not True:
            continue
        workflow_path = (directory / workflow["path"]).as_posix()
        source = sources.get(workflow_path)
        if source is None:
            raise PolicyError(f"{target_name} is missing action policy preflight workflow {workflow['path']}")
        verify_workflow_source(target_name, target["branch"], workflow, source)
    return sorted(
        {
            specification
            for workflow in evidence.values()
            for specification in workflow["external_actions"] + workflow["containers"]
        }
    )


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
        if target.get("public_audit", True) is False:
            continue
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
        workflow_trust = scan_workflow_sources(policy, name, workflow_sources)
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
            "workflow_trust": workflow_trust,
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
        "--target",
        default="github-control-plane",
        help="public target name when validating a local workflow directory",
    )
    parser.add_argument(
        "--workflow-directory",
        type=Path,
        default=Path(".github/workflows"),
        help="portable local workflow inventory to validate",
    )
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
            actions = validate_local_action_references(policy, args.workflow_directory, args.target)
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
