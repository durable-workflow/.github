#!/usr/bin/env python3
"""Run beta conformance from immutable public artifacts and retain bounded evidence."""

from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from pathlib import Path
from typing import Any

# Direct workflow invocation adds scripts/, rather than the repository root, to
# sys.path. Keep module and command-line execution equivalent.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.beta_candidate import (
    CANDIDATE_PATTERN,
    CLI_ASSETS,
    COMPONENTS,
    VERSION_PATTERN,
    WATERLINE_SERVICE,
    CandidateError,
    Component,
    canonical_json,
    load_manifest,
    manifest_digest,
    validate_verification,
)

CONTRACT_SCHEMA = "durable-workflow.beta-conformance.contract/v2"
PLAN_SCHEMA = "durable-workflow.beta-conformance.plan/v2"
EXPERIMENT_RESULT_SCHEMA = "durable-workflow.beta-conformance.experiment-result/v2"
SUITE_RESULT_SCHEMA = "durable-workflow.beta-conformance.suite-result/v2"
LEGACY_PLAN_SCHEMA = "durable-workflow.beta-conformance.plan/v1"
LEGACY_EXPERIMENT_RESULT_SCHEMA = "durable-workflow.beta-conformance.experiment-result/v1"
LEGACY_SUITE_RESULT_SCHEMA = "durable-workflow.beta-conformance.suite-result/v1"
CONTROL_REPOSITORY = "durable-workflow/.github"
CONFORMANCE_WORKFLOW_NAME = "Beta conformance"
CONFORMANCE_WORKFLOW_PATH = ".github/workflows/beta-conformance.yml"
CONFORMANCE_WORKFLOW_PATHS = {CONFORMANCE_WORKFLOW_PATH, f"{CONFORMANCE_WORKFLOW_PATH}@main"}
EXPERIMENTS = ("heartbeats", "polyglot", "replay", "signals-queries")
WATERLINE_SERVICE_DISTRIBUTION = "waterline-service"
DISTRIBUTIONS: dict[str, tuple[str, Component]] = {
    **{name: (name, component) for name, component in COMPONENTS.items()},
    WATERLINE_SERVICE_DISTRIBUTION: ("waterline", WATERLINE_SERVICE),
}
PASS_OUTCOMES = {"pass", "passed", "success", "successful", "completed", "verified"}
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
PYPI_SEMVER_PRERELEASE_PATTERN = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-(alpha|beta|rc)\.(0|[1-9][0-9]*)$"
)
PYPI_NATIVE_PRERELEASE_PATTERN = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(a|b|rc)(0|[1-9][0-9]*)$"
)
DIAGNOSTIC_LIMIT = 8192
NATIVE_RESULT_LIMIT = 4 * 1024 * 1024
NATIVE_RESULT_PREFIX_LIMIT = 64 * 1024
NATIVE_FAILURE_PROJECTION_LIMIT = 24 * 1024
NATIVE_FAILURE_COMPONENT_LIMIT = 6 * 1024
FINDING_LIMIT = 20
FINDING_TEXT_LIMIT = 2048
MAX_INFRASTRUCTURE_ATTEMPTS = 2
GITHUB_API_URL = "https://api.github.com"
GITHUB_API_RESPONSE_LIMIT = 4 * 1024 * 1024
RUNTIME_DEPENDENCY_SELECTORS = {
    "mysql": "docker.io/library/mysql:8.0",
    "redis": "docker.io/library/redis:7-alpine",
}
NATIVE_SCENARIO_STATUSES = {"pass", "fail", "unsupported", "not_covered", "runner_blocked"}
TRANSIENT_PATTERNS = (
    re.compile(
        r"\b(?:registry|pypi|packagist|crates\.io|docker hub|package download|artifact download)\b"
        r".{0,160}\b(?:429|50[234])\b",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(r"\b(?:registry|package download|artifact download)\b.{0,160}too many requests", re.IGNORECASE),
    re.compile(r"tls handshake timeout", re.IGNORECASE),
    re.compile(r"connection (?:reset|timed out)", re.IGNORECASE),
    re.compile(r"temporary failure in name resolution", re.IGNORECASE),
    re.compile(r"registry.*service unavailable", re.IGNORECASE),
)
SENSITIVE_EVIDENCE_KEY = re.compile(
    r"(?:authorization|credential|password|passwd|secret|api[_-]?(?:key|token)|token)",
    re.IGNORECASE,
)
EVIDENCE_OPTIONAL_QUOTE = r"(?:\\?[\"'])?"
EVIDENCE_QUOTED_TERMINATORS = frozenset(" \t\r\n,;:)}]")
EVIDENCE_ASSIGNMENT_PREFIX = re.compile(
    r"(?P<prefix>(?<![\w-])"
    + EVIDENCE_OPTIONAL_QUOTE
    + r"(?P<key>[a-z0-9_-]+)"
    + EVIDENCE_OPTIONAL_QUOTE
    + r"\s*[:=]\s*)",
    re.IGNORECASE,
)
BETA_TOKEN_EVIDENCE = re.compile(r"\bbeta-[0-9a-f]{32}\b", re.IGNORECASE)
CREDENTIAL_URL_EVIDENCE = re.compile(
    r"https?://[^\s/@:]+:[^\s/@]+@",
    re.IGNORECASE,
)
SYNTHETIC_CREDENTIAL_CANARY = "beta-00000000000000000000000000000000"


class ConformanceError(RuntimeError):
    """The portable beta conformance contract is invalid or cannot run."""


def github_api_json(path: str, token: str) -> Any:
    """Retrieve one bounded GitHub API document with the workflow token."""

    if not token:
        raise ConformanceError("GitHub API authentication is required for conformance retention")
    request = urllib.request.Request(
        f"{GITHUB_API_URL}{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read(GITHUB_API_RESPONSE_LIMIT + 1)
    except urllib.error.HTTPError as error:
        raise ConformanceError(f"GitHub API metadata request failed with HTTP {error.code}") from error
    except urllib.error.URLError as error:
        raise ConformanceError("GitHub API metadata request failed") from error
    if len(payload) > GITHUB_API_RESPONSE_LIMIT:
        raise ConformanceError("GitHub API metadata response exceeds the retention limit")
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConformanceError("GitHub API metadata response is not valid JSON") from error


def fetch_retention_source_metadata(
    expected_run_id: int,
    expected_run_attempt: int,
    token: str,
) -> tuple[Any, Any]:
    """Retrieve the exact source attempt and reviewed workflow identity."""

    if expected_run_id < 1 or expected_run_attempt < 1:
        raise ConformanceError("conformance retention source identity must be positive")
    run = github_api_json(
        f"/repos/{CONTROL_REPOSITORY}/actions/runs/{expected_run_id}/attempts/{expected_run_attempt}",
        token,
    )
    workflow = github_api_json(
        f"/repos/{CONTROL_REPOSITORY}/actions/workflows/beta-conformance.yml",
        token,
    )
    return run, workflow


def now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def github_timestamp(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ConformanceError(f"{label} is not a UTC GitHub timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ConformanceError(f"{label} is not a UTC GitHub timestamp") from error
    if parsed.tzinfo != dt.UTC:
        raise ConformanceError(f"{label} is not a UTC GitHub timestamp")
    return value


def validate_retention_source(
    run: Any,
    workflow: Any,
    *,
    expected_run_id: int,
    expected_run_attempt: int | None = None,
) -> dict[str, int | str]:
    """Bind retention to a completed default-branch conformance execution."""
    if not isinstance(run, dict):
        raise ConformanceError("conformance retention source must be a GitHub workflow run")
    run_id = run.get("id")
    run_attempt = run.get("run_attempt")
    repository = run.get("repository")
    head_repository = run.get("head_repository")
    if (
        not isinstance(workflow, dict)
        or type(workflow.get("id")) is not int
        or workflow["id"] < 1
        or workflow.get("name") != CONFORMANCE_WORKFLOW_NAME
        or workflow.get("path") != CONFORMANCE_WORKFLOW_PATH
        or workflow.get("state") != "active"
    ):
        raise ConformanceError("trusted conformance workflow metadata is invalid")
    if type(run_id) is not int or run_id < 1 or run_id != expected_run_id:
        raise ConformanceError("conformance retention source has a mismatched run identity")
    if type(run_attempt) is not int or run_attempt < 1:
        raise ConformanceError("conformance retention source has an invalid run attempt")
    if expected_run_attempt is not None and run_attempt != expected_run_attempt:
        raise ConformanceError("conformance retention source has a mismatched run attempt")
    if (
        not isinstance(repository, dict)
        or repository.get("full_name") != CONTROL_REPOSITORY
        or not isinstance(head_repository, dict)
        or head_repository.get("full_name") != CONTROL_REPOSITORY
    ):
        raise ConformanceError("conformance retention source is not owned by the control repository")
    if (
        run.get("workflow_id") != workflow["id"]
        or run.get("path") not in CONFORMANCE_WORKFLOW_PATHS
        or run.get("event") != "workflow_dispatch"
    ):
        raise ConformanceError("conformance retention source is not the dispatched conformance workflow")
    if run.get("head_branch") != "main" or not COMMIT_PATTERN.fullmatch(str(run.get("head_sha", ""))):
        raise ConformanceError("conformance retention source is not bound to the default branch")
    if run.get("status") != "completed" or not isinstance(run.get("conclusion"), str):
        raise ConformanceError("conformance retention source is not completed")
    display_title = run.get("display_title")
    candidate = display_title.removeprefix("Conformance ") if isinstance(display_title, str) else ""
    if not CANDIDATE_PATTERN.fullmatch(candidate):
        raise ConformanceError("conformance retention source has no candidate identity")
    return {
        "source_candidate": candidate,
        "source_completed_at": github_timestamp(run.get("updated_at"), "conformance completion"),
        "source_head_sha": run["head_sha"],
        "source_run_id": run_id,
        "source_run_attempt": run_attempt,
    }


def validate_retention_ref(
    ref: Any,
    comparison: Any,
    *,
    expected_tag: str,
    source_sha: str,
    controller_sha: str,
) -> dict[str, str]:
    """Bind an immutable evidence tag to protected retention-controller history."""
    expected_ref = f"refs/tags/{expected_tag}"
    target = ref.get("object") if isinstance(ref, dict) else None
    if not isinstance(ref, dict) or ref.get("ref") != expected_ref:
        raise ConformanceError("conformance evidence ref has a mismatched tag identity")
    if not COMMIT_PATTERN.fullmatch(source_sha) or not COMMIT_PATTERN.fullmatch(controller_sha):
        raise ConformanceError("conformance evidence ref has an invalid source or controller commit")
    if (
        not isinstance(target, dict)
        or target.get("type") != "commit"
        or not COMMIT_PATTERN.fullmatch(str(target.get("sha", "")))
    ):
        raise ConformanceError("conformance evidence ref does not resolve to a commit")
    target_sha = target["sha"]
    base = comparison.get("base_commit") if isinstance(comparison, dict) else None
    merge_base = comparison.get("merge_base_commit") if isinstance(comparison, dict) else None
    status = comparison.get("status") if isinstance(comparison, dict) else None
    ahead_by = comparison.get("ahead_by") if isinstance(comparison, dict) else None
    behind_by = comparison.get("behind_by") if isinstance(comparison, dict) else None
    if (
        not isinstance(base, dict)
        or base.get("sha") != target_sha
        or not isinstance(merge_base, dict)
        or merge_base.get("sha") != target_sha
        or status not in {"ahead", "identical"}
        or type(ahead_by) is not int
        or ahead_by < 0
        or behind_by != 0
        or (status == "identical" and (target_sha != controller_sha or ahead_by != 0))
        or (status == "ahead" and (target_sha == controller_sha or ahead_by < 1))
    ):
        raise ConformanceError("conformance evidence ref is outside protected controller history")
    return {
        "controller_sha": controller_sha,
        "evidence_ref": expected_ref,
        "evidence_sha": target_sha,
        "source_sha": source_sha,
    }


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json(value))


def load_json(path: Path, *, limit: int = 4 * 1024 * 1024) -> Any:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise ConformanceError(f"cannot read JSON document {path}: {error}") from error
    if len(raw) > limit:
        raise ConformanceError(f"JSON document exceeds the {limit}-byte limit: {path}")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ConformanceError(f"invalid JSON document {path}: {error}") from error


def load_native_result(
    path: Path,
) -> tuple[Any, int | None, str | None, str | None, int | None, str | None]:
    """Read native evidence with bounded work and distinguish complete from prefix identities."""
    observed_size: int | None = None
    try:
        with path.open("rb") as handle:
            observed_size = os.fstat(handle.fileno()).st_size
            if observed_size > NATIVE_RESULT_LIMIT:
                prefix = handle.read(NATIVE_RESULT_PREFIX_LIMIT)
                return (
                    None,
                    observed_size,
                    None,
                    sha256_bytes(prefix),
                    len(prefix),
                    "oversized",
                )
            raw = handle.read(NATIVE_RESULT_LIMIT + 1)
            observed_size = max(observed_size, os.fstat(handle.fileno()).st_size, len(raw))
    except OSError:
        return None, observed_size, None, None, None, "unreadable"

    if observed_size > NATIVE_RESULT_LIMIT or len(raw) > NATIVE_RESULT_LIMIT:
        prefix = raw[:NATIVE_RESULT_PREFIX_LIMIT]
        return None, observed_size, None, sha256_bytes(prefix), len(prefix), "oversized"

    digest = sha256_bytes(raw)
    try:
        native = json.loads(raw)
    except (json.JSONDecodeError, RecursionError, UnicodeDecodeError, ValueError):
        return None, observed_size, digest, None, None, "invalid_json"
    return native, observed_size, digest, None, None, None


def safe_relative_path(value: Any, *, suffix: str | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise ConformanceError("runner paths must be non-empty strings")
    path = Path(value)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != value:
        raise ConformanceError(f"runner path must be portable and relative: {value}")
    if suffix and not value.endswith(suffix):
        raise ConformanceError(f"runner path must end in {suffix}: {value}")
    return value


def validate_contract(contract: Any) -> None:
    if not isinstance(contract, dict) or set(contract) != {
        "$schema",
        "schema",
        "runtime_dependencies",
        "experiments",
    }:
        raise ConformanceError("beta conformance contract has an invalid top-level shape")
    if contract["$schema"] != "./contract-schema.json":
        raise ConformanceError("beta conformance contract must reference its repository schema")
    if contract["schema"] != CONTRACT_SCHEMA:
        raise ConformanceError(f"beta conformance contract schema must be {CONTRACT_SCHEMA}")
    if contract["runtime_dependencies"] != RUNTIME_DEPENDENCY_SELECTORS:
        raise ConformanceError("beta conformance contract has invalid runtime dependency selectors")
    experiments = contract["experiments"]
    if not isinstance(experiments, dict) or set(experiments) != set(EXPERIMENTS):
        raise ConformanceError(f"beta conformance experiments must be exactly {list(EXPERIMENTS)}")
    for name, specification in experiments.items():
        if not isinstance(specification, dict) or set(specification) != {
            "owning_contract",
            "required_clients",
            "required_distributions",
            "runners",
            "timeout_seconds",
        }:
            raise ConformanceError(f"experiment {name} has an invalid shape")
        owner = specification["owning_contract"]
        if not isinstance(owner, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", owner):
            raise ConformanceError(f"experiment {name} has an invalid owning contract")
        clients = specification["required_clients"]
        if (
            not isinstance(clients, list)
            or not clients
            or len(clients) != len(set(clients))
            or not set(clients).issubset({"sdk-php", "sdk-python", "sdk-rust"})
        ):
            raise ConformanceError(f"experiment {name} has invalid required clients")
        required_distributions = specification["required_distributions"]
        if (
            not isinstance(required_distributions, list)
            or not required_distributions
            or len(required_distributions) != len(set(required_distributions))
            or not set(required_distributions).issubset(DISTRIBUTIONS)
            or not {"server", *clients}.issubset(required_distributions)
        ):
            raise ConformanceError(f"experiment {name} has invalid required distributions")
        timeout = specification["timeout_seconds"]
        if not isinstance(timeout, int) or not 60 <= timeout <= 5400:
            raise ConformanceError(f"experiment {name} timeout must be between 60 and 5400 seconds")
        runners = specification["runners"]
        if not isinstance(runners, list) or not 1 <= len(runners) <= 3:
            raise ConformanceError(f"experiment {name} must have between one and three runners")
        runner_ids: set[str] = set()
        for runner in runners:
            if (
                not isinstance(runner, dict)
                or not {"id", "path", "result"}.issubset(runner)
                or not set(runner).issubset(
                    {
                        "id",
                        "path",
                        "result",
                        "required_distributions",
                        "result_schema",
                        "required_result_fields",
                        "required_scenarios",
                        "runtime",
                        "source",
                    }
                )
            ):
                raise ConformanceError(f"experiment {name} runner has an invalid shape")
            runner_id = runner["id"]
            if (
                not isinstance(runner_id, str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", runner_id)
                or runner_id in runner_ids
            ):
                raise ConformanceError(f"experiment {name} has an invalid or duplicate runner id")
            runner_ids.add(runner_id)
            runner_required_distributions = runner.get("required_distributions")
            if (
                not isinstance(runner_required_distributions, list)
                or not runner_required_distributions
                or len(runner_required_distributions) != len(set(runner_required_distributions))
                or not set(runner_required_distributions).issubset(required_distributions)
            ):
                raise ConformanceError(f"experiment {name} runner has invalid required distributions")
            source = runner.get("source")
            if source not in {"server-image", "control-plane"}:
                raise ConformanceError(f"experiment {name} runner has an invalid source")
            path = safe_relative_path(runner["path"])
            expected_prefix = "scripts/conformance/" if source == "server-image" else "scripts/"
            if not path.startswith(expected_prefix) or not path.endswith((".sh", ".mjs", ".py")):
                raise ConformanceError(f"experiment {name} runner is outside the published conformance surface")
            if source == "control-plane" and path != "scripts/waterline_service_conformance.py":
                raise ConformanceError(f"experiment {name} names an unsupported control-plane runner")
            safe_relative_path(runner["result"], suffix=".json")
            if "/" in runner["result"]:
                raise ConformanceError(f"experiment {name} native result must be a file name")
            result_schema = runner.get("result_schema")
            required_result_fields = runner.get("required_result_fields")
            required_scenarios = runner.get("required_scenarios")
            if (result_schema is None) != (required_result_fields is None):
                raise ConformanceError(
                    f"experiment {name} runner must declare its result schema and required fields together"
                )
            if result_schema is not None:
                if not isinstance(result_schema, str) or not re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,126}", result_schema):
                    raise ConformanceError(f"experiment {name} runner has an invalid result schema")
                if (
                    not isinstance(required_result_fields, list)
                    or not required_result_fields
                    or len(required_result_fields) != len(set(required_result_fields))
                    or any(
                        not isinstance(field, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,126}", field)
                        for field in required_result_fields
                    )
                ):
                    raise ConformanceError(f"experiment {name} runner has invalid required result fields")
            if required_scenarios is not None:
                if required_result_fields is None or "scenario_results" not in required_result_fields:
                    raise ConformanceError(
                        f"experiment {name} runner scenarios require a declared scenario_results field"
                    )
                if (
                    not isinstance(required_scenarios, list)
                    or not required_scenarios
                    or len(required_scenarios) != len(set(required_scenarios))
                    or any(
                        not isinstance(scenario, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,126}", scenario)
                        for scenario in required_scenarios
                    )
                ):
                    raise ConformanceError(f"experiment {name} runner has invalid required scenarios")
            runtime = runner.get("runtime")
            if runtime is not None:
                if not isinstance(runtime, dict) or set(runtime) != {
                    "cache_backend",
                    "database_backend",
                    "kind",
                    "namespace_environment",
                    "network_scope",
                    "queue_backend",
                    "server_url_environment",
                    "token_environment",
                }:
                    raise ConformanceError(f"experiment {name} runner has an invalid runtime dependency")
                if runtime["kind"] != "standalone-server":
                    raise ConformanceError(f"experiment {name} runner has an unsupported runtime dependency")
                if (
                    runtime["database_backend"] != "mysql"
                    or runtime["cache_backend"] != "redis"
                    or runtime["queue_backend"] != "redis"
                    or runtime["network_scope"] != "private"
                ):
                    raise ConformanceError(f"experiment {name} runner has an unsupported runtime topology")
                environment_names = [
                    runtime["namespace_environment"],
                    runtime["server_url_environment"],
                    runtime["token_environment"],
                ]
                if len(set(environment_names)) != len(environment_names) or any(
                    not isinstance(value, str) or not re.fullmatch(r"DW_[A-Z0-9_]{1,95}", value)
                    for value in environment_names
                ):
                    raise ConformanceError(f"experiment {name} runner has invalid runtime environment bindings")
        runner_distributions = {distribution for runner in runners for distribution in runner["required_distributions"]}
        if runner_distributions != set(required_distributions):
            raise ConformanceError(f"experiment {name} runners do not cover its required distributions")
    covered_distributions = {
        distribution
        for specification in experiments.values()
        for distribution in specification["required_distributions"]
    }
    if covered_distributions != set(DISTRIBUTIONS):
        raise ConformanceError("beta conformance contract does not execute every required distribution")


def load_contract(path: Path) -> dict[str, Any]:
    contract = load_json(path, limit=256 * 1024)
    validate_contract(contract)
    return contract


def artifact_version_components(required_distributions: list[str]) -> list[str]:
    """Return the candidate components represented by distribution assignments."""
    return list(dict.fromkeys(DISTRIBUTIONS[distribution][0] for distribution in required_distributions))


def runner_required_artifact_versions(
    runner: dict[str, Any], required_distributions: list[str] | None = None
) -> list[str]:
    """Return candidate components versioned by an executed distribution assignment."""
    required = artifact_version_components(required_distributions or runner["required_distributions"])
    runtime = runner.get("runtime")
    if isinstance(runtime, dict) and runtime.get("kind") == "standalone-server" and "server" not in required:
        required.append("server")
    return required


def git(repository: Path, *arguments: str) -> bytes:
    process = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=False,
        capture_output=True,
    )
    if process.returncode:
        detail = process.stderr.decode(errors="replace").strip()
        raise ConformanceError(f"git {' '.join(arguments)} failed: {detail}")
    return process.stdout


def read_candidate_record(repository: Path, manifest: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    record_ref = f"beta-candidate/{manifest['candidate']}"
    record_commit = git(repository, "rev-parse", f"{record_ref}^{{commit}}").decode().strip()
    if not COMMIT_PATTERN.fullmatch(record_commit):
        raise ConformanceError(f"candidate record {record_ref} does not resolve to a full Git commit")
    try:
        recorded_manifest = json.loads(git(repository, "show", f"{record_ref}:candidate.json"))
        verification = json.loads(git(repository, "show", f"{record_ref}:verification.json"))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ConformanceError(f"candidate record {record_ref} contains invalid JSON") from error
    if canonical_json(recorded_manifest) != canonical_json(manifest):
        raise ConformanceError(f"candidate record {record_ref} does not contain the requested immutable tuple")
    try:
        validate_verification(verification, manifest)
    except CandidateError as error:
        raise ConformanceError(f"candidate record {record_ref} has invalid verification: {error}") from error
    return record_commit, verification


def distribution_locator(name: str, version: str) -> str:
    _component_name, component = DISTRIBUTIONS[name]
    return f"{component.distribution}:{component.package}@{version}"


def distribution_version(components: dict[str, Any], name: str) -> str:
    component_name, _component = DISTRIBUTIONS[name]
    return components[component_name]["version"]


def pypi_release_identity(version: str) -> tuple[str, str, str, str | None, str | None] | None:
    stable = re.fullmatch(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", version)
    if stable:
        major, minor, patch = stable.groups()
        return major, minor, patch, None, None
    semver = PYPI_SEMVER_PRERELEASE_PATTERN.fullmatch(version)
    if semver:
        major, minor, patch, prerelease, ordinal = semver.groups()
        phase = {"alpha": "a", "beta": "b", "rc": "rc"}[prerelease]
        return major, minor, patch, phase, ordinal
    native = PYPI_NATIVE_PRERELEASE_PATTERN.fullmatch(version)
    if native:
        major, minor, patch, phase, ordinal = native.groups()
        return major, minor, patch, phase, ordinal
    return None


def registry_versions_equivalent(name: str, observed: str, expected: str) -> bool:
    """Compare exact candidate versions with the canonical spelling of their registry."""
    if observed == expected:
        return True
    if name != "sdk-python":
        return False
    observed_identity = pypi_release_identity(observed)
    return observed_identity is not None and observed_identity == pypi_release_identity(expected)


def distribution_artifact(name: Any, sha256: Any) -> dict[str, str]:
    if not isinstance(name, str) or not name or len(name) > 256:
        raise ConformanceError("candidate verification has an invalid distribution artifact name")
    if not isinstance(sha256, str) or not DIGEST_PATTERN.fullmatch(sha256):
        raise ConformanceError(f"candidate verification distribution artifact {name} has no SHA-256 identity")
    return {"name": name, "sha256": sha256}


def normalized_distribution_identity(name: str, version: str, artifacts: list[dict[str, str]]) -> dict[str, Any]:
    ordered = sorted(artifacts, key=lambda artifact: artifact["name"])
    if not ordered or len(ordered) != len({artifact["name"] for artifact in ordered}):
        raise ConformanceError(f"candidate verification has invalid {name} distribution artifacts")
    return {
        "kind": DISTRIBUTIONS[name][1].distribution,
        "locator": distribution_locator(name, version),
        "artifacts": ordered,
    }


def normalize_distribution_identities(
    verification: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    identities: dict[str, dict[str, Any]] = {}
    for name, (component_name, component) in DISTRIBUTIONS.items():
        version = manifest["components"][component_name]["version"]
        component_verification = verification["components"][component_name]
        if name == "waterline":
            distributions = component_verification.get("distributions")
            distribution = distributions.get("embedded") if isinstance(distributions, dict) else None
        elif name == WATERLINE_SERVICE_DISTRIBUTION:
            distributions = component_verification.get("distributions")
            distribution = distributions.get("service") if isinstance(distributions, dict) else None
        else:
            distribution = component_verification.get("distribution")
        if not isinstance(distribution, dict) or distribution.get("kind") != component.distribution:
            raise ConformanceError(f"candidate verification has no exact {name} distribution identity")
        if component.distribution == "composer":
            dist = distribution.get("dist")
            artifacts = [
                distribution_artifact(component.package, dist.get("sha256") if isinstance(dist, dict) else None)
            ]
        elif component.distribution == "github-release":
            raw_assets = distribution.get("assets")
            if not isinstance(raw_assets, list):
                raise ConformanceError("candidate verification has no CLI release-asset identities")
            artifacts = [
                distribution_artifact(asset.get("name"), asset.get("sha256"))
                for asset in raw_assets
                if isinstance(asset, dict)
            ]
            if {artifact["name"] for artifact in artifacts} != CLI_ASSETS:
                raise ConformanceError("candidate verification does not identify every required CLI release asset")
        elif component.distribution == "pypi":
            raw_files = distribution.get("files")
            if not isinstance(raw_files, list):
                raise ConformanceError("candidate verification has no PyPI file identities")
            artifacts = [
                distribution_artifact(item.get("filename"), item.get("sha256"))
                for item in raw_files
                if isinstance(item, dict)
            ]
        elif component.distribution == "crates.io":
            archive = distribution.get("archive")
            artifacts = [
                distribution_artifact(
                    f"{component.package}-{version}.crate",
                    archive.get("sha256") if isinstance(archive, dict) else None,
                )
            ]
        elif component.distribution == "oci":
            digest = distribution.get("manifest_digest")
            artifacts = [
                distribution_artifact("manifest", digest.removeprefix("sha256:") if isinstance(digest, str) else None)
            ]
        else:
            raise AssertionError(f"unsupported distribution kind: {component.distribution}")
        identities[name] = normalized_distribution_identity(name, version, artifacts)
    return identities


def validate_distribution_identity(name: str, identity: Any, components: dict[str, Any]) -> None:
    expected_locator = distribution_locator(name, distribution_version(components, name))
    if (
        not isinstance(identity, dict)
        or set(identity) != {"kind", "locator", "artifacts"}
        or identity["kind"] != DISTRIBUTIONS[name][1].distribution
        or identity["locator"] != expected_locator
    ):
        raise ConformanceError(f"distribution identity for {name} has an invalid locator")
    artifacts = identity["artifacts"]
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 128:
        raise ConformanceError(f"distribution identity for {name} has invalid artifacts")
    names = []
    for artifact in artifacts:
        if (
            not isinstance(artifact, dict)
            or set(artifact) != {"name", "sha256"}
            or not isinstance(artifact["name"], str)
            or not artifact["name"]
            or len(artifact["name"]) > 256
            or not DIGEST_PATTERN.fullmatch(str(artifact["sha256"]))
        ):
            raise ConformanceError(f"distribution identity for {name} has an invalid artifact digest")
        names.append(artifact["name"])
    if names != sorted(names) or len(names) != len(set(names)):
        raise ConformanceError(f"distribution identity for {name} artifacts are not uniquely normalized")


def validate_partial_distribution_identities(identities: Any, components: dict[str, Any]) -> None:
    if not isinstance(identities, dict) or not set(identities).issubset(DISTRIBUTIONS):
        raise ConformanceError("executed distribution identities name an unknown component")
    for name, identity in identities.items():
        validate_distribution_identity(name, identity, components)


def validate_distribution_identities(identities: Any, components: dict[str, Any]) -> None:
    if not isinstance(identities, dict) or set(identities) != set(DISTRIBUTIONS):
        raise ConformanceError("distribution identities do not bind every required distribution")
    validate_partial_distribution_identities(identities, components)


def validate_runtime_dependencies(dependencies: Any) -> None:
    if not isinstance(dependencies, dict) or set(dependencies) != set(RUNTIME_DEPENDENCY_SELECTORS):
        raise ConformanceError("runtime dependencies do not bind the declared MySQL and Redis images")
    for name, selector in RUNTIME_DEPENDENCY_SELECTORS.items():
        dependency = dependencies[name]
        repository = selector.rsplit(":", 1)[0]
        digest = dependency.get("manifest_digest") if isinstance(dependency, dict) else None
        if (
            not isinstance(dependency, dict)
            or set(dependency) != {"selector", "image", "manifest_digest"}
            or dependency["selector"] != selector
            or not isinstance(digest, str)
            or not OCI_DIGEST_PATTERN.fullmatch(digest)
            or dependency["image"] != f"{repository}@{digest}"
        ):
            raise ConformanceError(f"runtime dependency {name} has no exact OCI manifest binding")


def normalized_oci_repository(value: str) -> str:
    repository = value.removeprefix("docker.io/")
    if "/" not in repository:
        repository = f"library/{repository}"
    return repository


def resolve_runtime_dependencies(contract: dict[str, Any], *, docker: str = "docker") -> dict[str, dict[str, str]]:
    """Resolve declared selectors once so isolated jobs consume immutable references."""
    validate_contract(contract)
    dependencies: dict[str, dict[str, str]] = {}
    for name, selector in contract["runtime_dependencies"].items():
        docker_runtime_command([docker, "pull", selector])
        inspection = docker_runtime_command([docker, "image", "inspect", "--format", "{{json .RepoDigests}}", selector])
        try:
            references = json.loads(inspection.stdout)
        except (json.JSONDecodeError, TypeError) as error:
            raise ConformanceError(f"runtime dependency {name} has invalid Docker digest evidence") from error
        if not isinstance(references, list):
            raise ConformanceError(f"runtime dependency {name} has invalid Docker digest evidence")
        expected_repository = normalized_oci_repository(selector.rsplit(":", 1)[0])
        digests = {
            digest
            for reference in references
            if isinstance(reference, str)
            for repository, separator, digest in [reference.rpartition("@")]
            if separator
            and normalized_oci_repository(repository) == expected_repository
            and OCI_DIGEST_PATTERN.fullmatch(digest)
        }
        if len(digests) != 1:
            raise ConformanceError(f"runtime dependency {name} did not resolve to one immutable OCI manifest digest")
        digest = digests.pop()
        repository = selector.rsplit(":", 1)[0]
        dependencies[name] = {
            "selector": selector,
            "image": f"{repository}@{digest}",
            "manifest_digest": digest,
        }
    validate_runtime_dependencies(dependencies)
    return dependencies


def prepare_plan(
    repository: Path,
    manifest: dict[str, Any],
    contract: dict[str, Any],
    runner_revision: str,
    runtime_dependencies: dict[str, Any],
) -> dict[str, Any]:
    validate_contract(contract)
    validate_runtime_dependencies(runtime_dependencies)
    if not COMMIT_PATTERN.fullmatch(runner_revision):
        raise ConformanceError("runner revision must be a full lowercase Git commit")
    git(repository, "cat-file", "-e", f"{runner_revision}^{{commit}}")
    record_commit, verification = read_candidate_record(repository, manifest)
    distribution_identities = normalize_distribution_identities(verification, manifest)
    server_distribution = verification["components"]["server"].get("distribution")
    if not isinstance(server_distribution, dict):
        raise ConformanceError("candidate verification has no server distribution identity")
    image = server_distribution.get("image")
    image_digest = server_distribution.get("manifest_digest")
    expected_tag = f"docker.io/durableworkflow/server:{manifest['components']['server']['version']}"
    if image != expected_tag or not isinstance(image_digest, str) or not OCI_DIGEST_PATTERN.fullmatch(image_digest):
        raise ConformanceError("candidate verification has no exact matching server image digest")
    waterline_distributions = verification["components"]["waterline"].get("distributions")
    waterline_service = waterline_distributions.get("service") if isinstance(waterline_distributions, dict) else None
    waterline_image = waterline_service.get("image") if isinstance(waterline_service, dict) else None
    waterline_digest = waterline_service.get("manifest_digest") if isinstance(waterline_service, dict) else None
    expected_waterline_tag = f"docker.io/durableworkflow/waterline:{manifest['components']['waterline']['version']}"
    if (
        waterline_image != expected_waterline_tag
        or not isinstance(waterline_digest, str)
        or not OCI_DIGEST_PATTERN.fullmatch(waterline_digest)
    ):
        raise ConformanceError("candidate verification has no exact matching Waterline service image digest")
    components = manifest["components"]
    plan = {
        "schema": PLAN_SCHEMA,
        "candidate": {
            "name": manifest["candidate"],
            "manifest_sha256": manifest_digest(manifest),
            "verification_sha256": sha256_bytes(canonical_json(verification)),
            "record_ref": f"beta-candidate/{manifest['candidate']}",
            "record_commit": record_commit,
        },
        "artifact_tuple": components,
        "source_identities": {name: identity["commit"] for name, identity in components.items()},
        "distribution_identities": distribution_identities,
        "runtime_dependencies": runtime_dependencies,
        "runner": {
            "repository": "durable-workflow/.github",
            "revision": runner_revision,
            "contract_sha256": sha256_bytes(canonical_json(contract)),
        },
        "server_runner": {
            "image": f"docker.io/durableworkflow/server@{image_digest}",
            "manifest_digest": image_digest,
            "source_commit": components["server"]["commit"],
        },
        "waterline_service_runner": {
            "image": f"docker.io/durableworkflow/waterline@{waterline_digest}",
            "manifest_digest": waterline_digest,
            "source_commit": components["waterline"]["commit"],
        },
        "experiments": list(EXPERIMENTS),
    }
    validate_plan(plan)
    return plan


def validate_plan(plan: Any) -> None:
    _validate_plan(plan, PLAN_SCHEMA, set(DISTRIBUTIONS), require_waterline_service=True)


def validate_recorded_plan(plan: Any) -> None:
    schema = plan.get("schema") if isinstance(plan, dict) else None
    if schema == PLAN_SCHEMA:
        validate_plan(plan)
        return
    if schema == LEGACY_PLAN_SCHEMA:
        _validate_plan(plan, LEGACY_PLAN_SCHEMA, set(COMPONENTS), require_waterline_service=False)
        return
    raise ConformanceError("recorded beta conformance plan uses an unsupported schema")


def _validate_plan(
    plan: Any,
    schema: str,
    required_distributions: set[str],
    *,
    require_waterline_service: bool,
) -> None:
    required = {
        "schema",
        "candidate",
        "artifact_tuple",
        "source_identities",
        "distribution_identities",
        "runtime_dependencies",
        "runner",
        "server_runner",
        "experiments",
    }
    if require_waterline_service:
        required.add("waterline_service_runner")
    if not isinstance(plan, dict) or set(plan) != required or plan.get("schema") != schema:
        raise ConformanceError("beta conformance plan has an invalid top-level shape")
    components = plan["artifact_tuple"]
    if not isinstance(components, dict) or set(components) != set(COMPONENTS):
        raise ConformanceError("beta conformance plan does not bind the exact seven-artifact tuple")
    for name, identity in components.items():
        if not isinstance(identity, dict) or set(identity) != {"version", "commit"}:
            raise ConformanceError(f"beta conformance plan has an invalid {name} identity")
        if (
            not isinstance(identity["version"], str)
            or not VERSION_PATTERN.fullmatch(identity["version"])
            or not COMMIT_PATTERN.fullmatch(str(identity["commit"]))
        ):
            raise ConformanceError(f"beta conformance plan has an invalid {name} version or commit")
    sources = plan["source_identities"]
    if not isinstance(sources, dict) or sources != {name: item["commit"] for name, item in components.items()}:
        raise ConformanceError("beta conformance plan source identities do not match the artifact tuple")
    if (
        not isinstance(plan["distribution_identities"], dict)
        or set(plan["distribution_identities"]) != required_distributions
    ):
        raise ConformanceError("distribution identities do not bind every required distribution")
    validate_partial_distribution_identities(plan["distribution_identities"], components)
    validate_runtime_dependencies(plan["runtime_dependencies"])
    candidate = plan["candidate"]
    if (
        not isinstance(candidate, dict)
        or set(candidate) != {"name", "manifest_sha256", "verification_sha256", "record_ref", "record_commit"}
        or not isinstance(candidate["name"], str)
        or not CANDIDATE_PATTERN.fullmatch(candidate["name"])
        or not DIGEST_PATTERN.fullmatch(str(candidate["manifest_sha256"]))
        or not DIGEST_PATTERN.fullmatch(str(candidate["verification_sha256"]))
        or not COMMIT_PATTERN.fullmatch(str(candidate["record_commit"]))
        or candidate["record_ref"] != f"beta-candidate/{candidate['name']}"
    ):
        raise ConformanceError("beta conformance plan has an invalid candidate binding")
    runner = plan["runner"]
    if (
        not isinstance(runner, dict)
        or set(runner) != {"repository", "revision", "contract_sha256"}
        or runner["repository"] != "durable-workflow/.github"
        or not COMMIT_PATTERN.fullmatch(str(runner["revision"]))
        or not DIGEST_PATTERN.fullmatch(str(runner["contract_sha256"]))
    ):
        raise ConformanceError("beta conformance plan has an invalid runner binding")
    server_runner = plan["server_runner"]
    digest = server_runner.get("manifest_digest") if isinstance(server_runner, dict) else None
    if (
        not isinstance(server_runner, dict)
        or set(server_runner) != {"image", "manifest_digest", "source_commit"}
        or not isinstance(digest, str)
        or not OCI_DIGEST_PATTERN.fullmatch(digest)
        or server_runner["image"] != f"docker.io/durableworkflow/server@{digest}"
        or server_runner["source_commit"] != components["server"]["commit"]
    ):
        raise ConformanceError("beta conformance plan has an invalid published server runner binding")
    if require_waterline_service:
        waterline_runner = plan["waterline_service_runner"]
        waterline_digest = waterline_runner.get("manifest_digest") if isinstance(waterline_runner, dict) else None
        if (
            not isinstance(waterline_runner, dict)
            or set(waterline_runner) != {"image", "manifest_digest", "source_commit"}
            or not isinstance(waterline_digest, str)
            or not OCI_DIGEST_PATTERN.fullmatch(waterline_digest)
            or waterline_runner["image"] != f"docker.io/durableworkflow/waterline@{waterline_digest}"
            or waterline_runner["source_commit"] != components["waterline"]["commit"]
        ):
            raise ConformanceError(
                "beta conformance plan has an invalid published Waterline service runner binding"
            )
    if plan["experiments"] != list(EXPERIMENTS):
        raise ConformanceError("beta conformance plan does not select the complete experiment set")


def restore_plan(
    plan: dict[str, Any],
    manifest: dict[str, Any],
    contract: dict[str, Any],
    runner_revision: str,
) -> dict[str, Any]:
    """Restore a first-attempt plan without resolving mutable inputs again."""
    validate_plan(plan)
    validate_contract(contract)
    if not COMMIT_PATTERN.fullmatch(runner_revision) or plan["runner"]["revision"] != runner_revision:
        raise ConformanceError("restored beta conformance plan does not bind this workflow revision")
    if plan["runner"]["contract_sha256"] != sha256_bytes(canonical_json(contract)):
        raise ConformanceError("restored beta conformance plan does not bind this contract")
    if (
        plan["candidate"]["name"] != manifest["candidate"]
        or plan["candidate"]["manifest_sha256"] != manifest_digest(manifest)
        or plan["artifact_tuple"] != manifest["components"]
    ):
        raise ConformanceError("restored beta conformance plan does not bind the requested candidate")
    return plan


def plan_github_outputs(plan: dict[str, Any]) -> dict[str, str]:
    validate_plan(plan)
    return {
        "candidate": plan["candidate"]["name"],
        "experiments": json.dumps(plan["experiments"], separators=(",", ":")),
        "manifest_sha256": plan["candidate"]["manifest_sha256"],
    }


def load_plan(path: Path) -> dict[str, Any]:
    plan = load_json(path, limit=256 * 1024)
    validate_plan(plan)
    return plan


def run_checked(command: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    process = subprocess.run(command, check=False, text=True, capture_output=capture)
    if process.returncode:
        detail = (process.stderr or process.stdout or "").strip() if capture else ""
        raise ConformanceError(f"command failed ({process.returncode}): {' '.join(command)}: {detail}")
    return process


def extract_runner(plan: dict[str, Any], output: Path, extraction_record: Path, docker: str = "docker") -> None:
    validate_plan(plan)
    if output.exists() and any(output.iterdir()):
        raise ConformanceError(f"published runner output directory is not empty: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix="beta-conformance-image-", dir=output.parent))
    container_id = ""
    image = plan["server_runner"]["image"]
    try:
        run_checked([docker, "pull", image], capture=True)
        inspection = run_checked(
            [docker, "image", "inspect", "--format", "{{json .RepoDigests}}", image], capture=True
        ).stdout
        if plan["server_runner"]["manifest_digest"] not in inspection:
            raise ConformanceError("pulled server image inspection does not contain the candidate manifest digest")
        container_id = run_checked([docker, "create", image], capture=True).stdout.strip()
        if not container_id:
            raise ConformanceError("docker create returned no container identity")
        extracted = temporary / "app"
        extracted.mkdir()
        run_checked([docker, "cp", f"{container_id}:/app/.", str(extracted)], capture=True)
        if output.exists():
            output.rmdir()
        extracted.rename(output)
        write_json(
            extraction_record,
            {
                "schema": "durable-workflow.beta-conformance.server-runner-extraction/v1",
                "image": image,
                "manifest_digest": plan["server_runner"]["manifest_digest"],
                "source_commit": plan["server_runner"]["source_commit"],
                "local_product_source_checkout_used": False,
            },
        )
    finally:
        if container_id:
            subprocess.run([docker, "rm", "-f", container_id], check=False, capture_output=True)
        shutil.rmtree(temporary, ignore_errors=True)


def tail_and_digest(path: Path) -> tuple[str, str]:
    digest = sha256_file(path)
    with path.open("rb") as handle:
        size = path.stat().st_size
        if size > DIAGNOSTIC_LIMIT:
            handle.seek(-DIAGNOSTIC_LIMIT, os.SEEK_END)
        value = handle.read(DIAGNOSTIC_LIMIT).decode(errors="replace")
    return sanitized_evidence_text(value, DIAGNOSTIC_LIMIT), digest


def bounded_text(value: Any, limit: int = FINDING_TEXT_LIMIT) -> str:
    text = str(value).replace("\x00", "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


def evidence_value_parts(value: str) -> tuple[str, str, str]:
    for quote in (r"\"", r"\'", '"', "'"):
        if value.startswith(quote) and value.endswith(quote) and len(value) >= len(quote) * 2:
            return quote, value[len(quote) : -len(quote)], quote
    return "", value, ""


def quoted_evidence_value_end(text: str, start: int) -> int | None:
    escaped_wrapper = text.startswith((r"\"", r"\'"), start)
    if escaped_wrapper:
        quote = text[start + 1]
        cursor = start + 2
    elif start < len(text) and text[start] in {'"', "'"}:
        quote = text[start]
        cursor = start + 1
    else:
        return None

    while cursor < len(text) and text[cursor] not in "\r\n":
        if text[cursor] == quote:
            slash_start = cursor
            while slash_start > start and text[slash_start - 1] == "\\":
                slash_start -= 1
            slash_count = cursor - slash_start
            if (escaped_wrapper and slash_count == 1) or (not escaped_wrapper and slash_count % 2 == 0):
                end = cursor + 1
                return end if end == len(text) or text[end] in EVIDENCE_QUOTED_TERMINATORS else len(text)
        cursor += 1
    return len(text)


def evidence_value_end(text: str, start: int) -> int:
    if "\n" in text[start:] or "\r" in text[start:]:
        return len(text)
    quoted_end = quoted_evidence_value_end(text, start)
    if quoted_end is not None:
        return quoted_end

    # Whitespace and punctuation are valid secret characters in arbitrary log
    # scalars, so an unquoted value has no trustworthy boundary. Consume its
    # bounded remainder, including any text after a pre-redacted prefix.
    return len(text)


def evidence_value_spans(text: str) -> Iterator[tuple[int, int, bool]]:
    search_from = 0
    while match := EVIDENCE_ASSIGNMENT_PREFIX.search(text, search_from):
        if SENSITIVE_EVIDENCE_KEY.search(match.group("key")) is None:
            search_from = match.end()
            continue
        start = match.end()
        end = evidence_value_end(text, start)
        if end > start:
            authorization = "authorization" in match.group("key").lower()
            yield start, end, authorization
            search_from = end
        else:
            search_from = start + 1


def redacted_evidence_value(value: str, preserve_bearer: bool = False) -> str:
    opening, inner, closing = evidence_value_parts(value)
    stripped = inner.strip()
    if re.fullmatch(r"(?:bearer\s+)?\[REDACTED\]", stripped, flags=re.IGNORECASE):
        return value
    bearer = re.match(r"\s*(bearer\s+)", inner, flags=re.IGNORECASE) if preserve_bearer else None
    replacement = f"{bearer.group(1)}[REDACTED]" if bearer else "[REDACTED]"
    return f"{opening}{replacement}{closing}"


def redact_evidence_assignments(text: str) -> str:
    fragments: list[str] = []
    cursor = 0
    for start, end, authorization in evidence_value_spans(text):
        fragments.append(text[cursor:start])
        fragments.append(redacted_evidence_value(text[start:end], preserve_bearer=authorization))
        cursor = end
    fragments.append(text[cursor:])
    return "".join(fragments)


def contains_sensitive_evidence_text(value: str) -> bool:
    if BETA_TOKEN_EVIDENCE.search(value) or CREDENTIAL_URL_EVIDENCE.search(value):
        return True
    return any(
        not re.fullmatch(
            r"(?:bearer\s+)?\[REDACTED\]" if authorization else r"\[REDACTED\]",
            evidence_value_parts(value[start:end])[1].strip(),
            flags=re.IGNORECASE,
        )
        for start, end, authorization in evidence_value_spans(value)
    )


def sanitized_evidence_text(value: Any, limit: int = 512) -> str:
    text = str(value).replace("\x00", "")
    text = redact_evidence_assignments(text)
    text = BETA_TOKEN_EVIDENCE.sub("[REDACTED]", text)
    text = CREDENTIAL_URL_EVIDENCE.sub(
        lambda match: f"{match.group(0).split('://', 1)[0]}://[REDACTED]@",
        text,
    )
    return bounded_text(text, limit)


def validate_public_evidence_strings(value: Any) -> None:
    """Reject credential-shaped text anywhere in a public JSON asset."""

    def has_sensitive_string(entry: Any) -> bool:
        if isinstance(entry, str):
            return contains_sensitive_evidence_text(entry)
        if isinstance(entry, list):
            return any(has_sensitive_string(item) for item in entry)
        if isinstance(entry, dict):
            return any(
                contains_sensitive_evidence_text(str(key))
                or (
                    SENSITIVE_EVIDENCE_KEY.search(str(key)) is not None
                    and nested not in ("[REDACTED]", "Bearer [REDACTED]", "bearer [REDACTED]")
                )
                or has_sensitive_string(nested)
                for key, nested in entry.items()
            )
        return False

    if has_sensitive_string(value):
        raise ConformanceError("public conformance evidence contains unsanitized sensitive text")


def bounded_sanitized_evidence(value: Any, limit: int = NATIVE_FAILURE_COMPONENT_LIMIT) -> Any:
    def sanitize(entry: Any, depth: int = 0) -> Any:
        if entry is None or isinstance(entry, bool | int | float):
            return entry
        if isinstance(entry, str):
            return sanitized_evidence_text(entry)
        if depth >= 7:
            return "[depth limit reached]"
        if isinstance(entry, list):
            return [sanitize(item, depth + 1) for item in entry[:16]]
        if isinstance(entry, dict):
            result: dict[str, Any] = {}
            for key, nested in list(entry.items())[:32]:
                safe_key = sanitized_evidence_text(key, 128)
                result[safe_key] = (
                    "[REDACTED]" if SENSITIVE_EVIDENCE_KEY.search(safe_key) else sanitize(nested, depth + 1)
                )
            return result
        return sanitized_evidence_text(entry)

    sanitized = sanitize(value)
    if len(canonical_json(sanitized)) <= limit:
        return sanitized

    serialized = json.dumps(sanitized, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    low = 0
    high = len(serialized)
    bounded: dict[str, Any] = {"_truncated": True, "bounded_json_excerpt": ""}
    while low <= high:
        middle = (low + high) // 2
        candidate = {
            "_truncated": True,
            "bounded_json_excerpt": sanitized_evidence_text(serialized[:middle], middle),
        }
        if len(canonical_json(candidate)) <= limit:
            bounded = candidate
            low = middle + 1
        else:
            high = middle - 1
    return bounded


def summarize_native_failure_projection(native: dict[str, Any]) -> dict[str, Any]:
    projection: dict[str, Any] = {
        "max_bytes": NATIVE_FAILURE_PROJECTION_LIMIT,
        "component_max_bytes": NATIVE_FAILURE_COMPONENT_LIMIT,
        "truncated": False,
        "scenarios": [],
    }
    raw_scenarios = native.get("scenario_results", native.get("scenarioResults", {}))
    if isinstance(raw_scenarios, dict):
        items = list(raw_scenarios.items())[:128]
    elif isinstance(raw_scenarios, list):
        items = [(str(index), value) for index, value in enumerate(raw_scenarios[:128])]
    else:
        return projection

    for raw_id, value in items:
        if isinstance(value, dict):
            scenario_id = value.get("scenario_id", value.get("id", raw_id))
            status = value.get("status", value.get("outcome", "unknown"))
            observed = value.get("observed_outputs", value.get("observedOutputs", {}))
            linked_findings = value.get("linked_findings", value.get("linkedFindings"))
        else:
            scenario_id = raw_id
            status = value
            observed = {}
            linked_findings = None
        normalized_status = sanitized_evidence_text(status, 64)
        if normalized_status in PASS_OUTCOMES:
            continue
        if not isinstance(observed, dict):
            observed = {}
        scenario = {
            "id": sanitized_evidence_text(scenario_id, 128),
            "status": normalized_status,
            "failure_stage": (
                sanitized_evidence_text(observed["failure_stage"], 128)
                if isinstance(observed.get("failure_stage"), str)
                else None
            ),
            "failure_classification": (
                sanitized_evidence_text(observed["failure_classification"], 128)
                if isinstance(observed.get("failure_classification"), str)
                else None
            ),
            "failure_owner": (
                sanitized_evidence_text(observed["failure_owner"], 128)
                if isinstance(observed.get("failure_owner"), str)
                else None
            ),
            "worker_evidence": bounded_sanitized_evidence(observed.get("worker_evidence")),
            "server_evidence": bounded_sanitized_evidence(observed.get("server_evidence")),
            "linked_findings": bounded_sanitized_evidence(linked_findings),
        }
        candidate = {**projection, "scenarios": [*projection["scenarios"], scenario]}
        if len(canonical_json(candidate)) > NATIVE_FAILURE_PROJECTION_LIMIT:
            projection["truncated"] = True
            break
        projection["scenarios"].append(scenario)
    return projection


def native_failure_projection_error(projection: Any) -> str:
    if not isinstance(projection, dict) or set(projection) != {
        "max_bytes",
        "component_max_bytes",
        "truncated",
        "scenarios",
    }:
        return "experiment result has an invalid native failure projection"
    if (
        projection["max_bytes"] != NATIVE_FAILURE_PROJECTION_LIMIT
        or projection["component_max_bytes"] != NATIVE_FAILURE_COMPONENT_LIMIT
        or not isinstance(projection["truncated"], bool)
        or not isinstance(projection["scenarios"], list)
        or len(projection["scenarios"]) > 128
        or len(canonical_json(projection)) > NATIVE_FAILURE_PROJECTION_LIMIT
    ):
        return "experiment result has an unbounded native failure projection"

    def has_secret(value: Any) -> bool:
        if isinstance(value, str):
            return contains_sensitive_evidence_text(value)
        if isinstance(value, list):
            return any(has_secret(entry) for entry in value)
        if isinstance(value, dict):
            return any(
                contains_sensitive_evidence_text(str(key))
                or (SENSITIVE_EVIDENCE_KEY.search(str(key)) is not None and nested != "[REDACTED]")
                or has_secret(nested)
                for key, nested in value.items()
            )
        return False

    for scenario in projection["scenarios"]:
        if not isinstance(scenario, dict) or set(scenario) != {
            "id",
            "status",
            "failure_stage",
            "failure_classification",
            "failure_owner",
            "worker_evidence",
            "server_evidence",
            "linked_findings",
        }:
            return "experiment result has a malformed native failure scenario"
        if (
            not isinstance(scenario["id"], str)
            or not scenario["id"]
            or len(scenario["id"]) > 128
            or not isinstance(scenario["status"], str)
            or not scenario["status"]
            or len(scenario["status"]) > 64
            or scenario["status"] in PASS_OUTCOMES
            or any(
                value is not None and (not isinstance(value, str) or len(value) > 128)
                for value in (
                    scenario["failure_stage"],
                    scenario["failure_classification"],
                    scenario["failure_owner"],
                )
            )
        ):
            return "experiment result has invalid native failure attribution"
        if any(
            has_secret(value)
            for value in (
                scenario["id"],
                scenario["status"],
                scenario["failure_stage"],
                scenario["failure_classification"],
                scenario["failure_owner"],
            )
        ):
            return "experiment result has unsanitized native failure attribution"
        for field in ("worker_evidence", "server_evidence", "linked_findings"):
            if len(canonical_json(scenario[field])) > NATIVE_FAILURE_COMPONENT_LIMIT:
                return "experiment result has an unbounded native failure evidence component"
            if has_secret(scenario[field]):
                return "experiment result has unsanitized native failure evidence"
    return ""


def summarize_findings(native: Any) -> list[dict[str, str]]:
    if not isinstance(native, dict):
        return []
    candidates = native.get("findings")
    if not isinstance(candidates, list):
        candidates = []
    summaries: list[dict[str, str]] = []
    for finding in candidates[:FINDING_LIMIT]:
        if isinstance(finding, dict):
            owner = next(
                (
                    finding.get(key)
                    for key in ("owning_contract", "owning_surface", "owner", "surface")
                    if finding.get(key)
                ),
                "unspecified",
            )
            summary = next(
                (finding.get(key) for key in ("summary", "title", "reason", "message", "type") if finding.get(key)),
                "native conformance finding",
            )
            kind = finding.get("type") or finding.get("id") or "finding"
        else:
            owner = "unspecified"
            summary = finding
            kind = "finding"
        summaries.append(
            {
                "type": sanitized_evidence_text(kind, 128),
                "owning_contract": sanitized_evidence_text(owner, 128),
                "summary": sanitized_evidence_text(summary, FINDING_TEXT_LIMIT),
            }
        )
    return summaries


def native_state(native: Any) -> tuple[str | None, bool, list[dict[str, str]]]:
    if not isinstance(native, dict):
        return None, False, []
    raw_outcome = native.get("outcome", native.get("status"))
    outcome = sanitized_evidence_text(str(raw_outcome).lower(), 128) if raw_outcome is not None else None
    runner_blocked = native.get("runner_blocked") is True or native.get("runnerBlocked") is True
    return outcome, runner_blocked, summarize_findings(native)


def native_distribution_identity_structure_error(name: str, identity: Any) -> str:
    if not isinstance(identity, dict) or set(identity) != {"kind", "locator", "artifacts"}:
        return f"published runner result has a malformed {name} distribution identity body"
    _component_name, component = DISTRIBUTIONS[name]
    locator_prefix = f"{component.distribution}:{component.package}@"
    locator_version = (
        identity["locator"][len(locator_prefix) :]
        if isinstance(identity.get("locator"), str) and identity["locator"].startswith(locator_prefix)
        else ""
    )
    if (
        not isinstance(identity["kind"], str)
        or not identity["kind"]
        or len(identity["kind"]) > 64
        or identity["kind"] != component.distribution
        or not isinstance(identity["locator"], str)
        or not identity["locator"]
        or len(identity["locator"]) > 256
        or not identity["locator"].startswith(locator_prefix)
        or (
            VERSION_PATTERN.fullmatch(locator_version) is None
            and (name != "sdk-python" or PYPI_NATIVE_PRERELEASE_PATTERN.fullmatch(locator_version) is None)
        )
    ):
        return f"published runner result has a malformed {name} distribution identity locator"
    artifacts = identity["artifacts"]
    if not isinstance(artifacts, list) or not 1 <= len(artifacts) <= 128:
        return f"published runner result has malformed {name} distribution identity artifacts"
    artifact_names: list[str] = []
    for artifact in artifacts:
        if (
            not isinstance(artifact, dict)
            or set(artifact) != {"name", "sha256"}
            or not isinstance(artifact["name"], str)
            or not artifact["name"]
            or len(artifact["name"]) > 256
            or not isinstance(artifact["sha256"], str)
            or not DIGEST_PATTERN.fullmatch(artifact["sha256"])
        ):
            return f"published runner result has a malformed {name} distribution artifact identity"
        artifact_names.append(artifact["name"])
    if artifact_names != sorted(artifact_names) or len(artifact_names) != len(set(artifact_names)):
        return f"published runner result has non-normalized {name} distribution artifact identities"
    return ""


def native_result_completeness_error(
    native: Any,
    required_distributions: list[str],
    runner: dict[str, Any],
) -> str:
    if not isinstance(native, dict):
        return "published runner result must be a JSON object"
    required_fields = runner.get("required_result_fields", [])
    missing_fields = [field for field in required_fields if field not in native]
    if missing_fields:
        return f"published runner result is missing required fields: {', '.join(missing_fields)}"
    result_schema = runner.get("result_schema")
    if result_schema is not None and native.get("schema") != result_schema:
        return "published runner result does not use its declared schema"
    for field in ("started_at", "finished_at"):
        if field in required_fields and (not isinstance(native[field], str) or not native[field].strip()):
            return f"published runner result has an invalid {field} value"
    outcome = native.get("outcome", native.get("status"))
    if not isinstance(outcome, str) or not outcome.strip():
        return "published runner result does not declare an outcome"
    if "runner_blocked" in required_fields and not isinstance(native["runner_blocked"], bool):
        return "published runner result does not declare a boolean runner_blocked value"
    required_artifact_versions = set(runner_required_artifact_versions(runner, required_distributions))
    versions = native.get("artifact_versions", native.get("artifactVersions"))
    if not isinstance(versions, dict) or any(
        name not in versions or not isinstance(versions[name], str) or not versions[name]
        for name in required_artifact_versions
    ):
        return "published runner result does not retain every required artifact version"
    extra_versions = set(versions) - required_artifact_versions
    if extra_versions:
        return (
            "published runner result retains artifact versions outside its required distributions: "
            f"{', '.join(sorted(extra_versions))}"
        )
    identities = native.get(
        "executed_distribution_identities",
        native.get("executedDistributionIdentities"),
    )
    if not isinstance(identities, dict) or any(name not in identities for name in required_distributions):
        return "published runner result does not retain every required distribution identity"
    extra_identities = set(identities) - set(required_distributions)
    if extra_identities:
        return (
            "published runner result retains distribution identities outside its required distributions: "
            f"{', '.join(sorted(extra_identities))}"
        )
    for name, identity in identities.items():
        identity_error = native_distribution_identity_structure_error(name, identity)
        if identity_error:
            return identity_error
    if "runtime_matrix" in required_fields and not isinstance(native["runtime_matrix"], dict):
        return "published runner result does not retain a runtime matrix"
    scenarios = native.get("scenario_results", native.get("scenarioResults"))
    if not isinstance(scenarios, dict | list) or not scenarios:
        return "published runner result does not retain scenario statuses"
    required_scenarios = runner.get("required_scenarios", [])
    if required_scenarios:
        if not isinstance(scenarios, dict):
            return "published runner result does not retain keyed required scenario statuses"
        missing_scenarios = [scenario for scenario in required_scenarios if scenario not in scenarios]
        if missing_scenarios:
            return f"published runner result is missing required scenarios: {', '.join(missing_scenarios)}"
        for scenario in required_scenarios:
            cell = scenarios[scenario]
            if (
                not isinstance(cell, dict)
                or cell.get("scenario_id") != scenario
                or not isinstance(cell.get("status"), str)
                or cell["status"] not in NATIVE_SCENARIO_STATUSES
            ):
                return f"published runner result has a malformed {scenario} scenario status"
        if outcome.lower() in PASS_OUTCOMES and any(
            scenarios[scenario]["status"] != "pass" for scenario in required_scenarios
        ):
            return "published runner result declares a passing outcome with non-passing required scenarios"
    if not isinstance(native.get("findings"), list):
        return "published runner result does not retain a findings list"
    if "finding_links" in required_fields and not isinstance(native["finding_links"], dict):
        return "published runner result does not retain finding links"
    return ""


def summarize_executed_distribution_identities(native: dict[str, Any]) -> dict[str, Any]:
    raw = native.get("executed_distribution_identities", native.get("executedDistributionIdentities", {}))
    if not isinstance(raw, dict):
        return {}
    identities: dict[str, Any] = {}
    for name, identity in raw.items():
        if name not in DISTRIBUTIONS or not isinstance(identity, dict):
            continue
        kind = identity.get("kind")
        locator = identity.get("locator")
        artifacts = identity.get("artifacts")
        if (
            kind != DISTRIBUTIONS[name][1].distribution
            or not isinstance(locator, str)
            or not locator
            or len(locator) > 256
            or not isinstance(artifacts, list)
        ):
            continue
        normalized_artifacts = []
        for artifact in artifacts:
            if (
                not isinstance(artifact, dict)
                or set(artifact) != {"name", "sha256"}
                or not isinstance(artifact["name"], str)
                or not artifact["name"]
                or len(artifact["name"]) > 256
                or not isinstance(artifact["sha256"], str)
                or not DIGEST_PATTERN.fullmatch(artifact["sha256"])
            ):
                normalized_artifacts = []
                break
            normalized_artifacts.append(
                {"name": sanitized_evidence_text(artifact["name"], 256), "sha256": artifact["sha256"]}
            )
        normalized_artifacts.sort(key=lambda artifact: artifact["name"])
        if normalized_artifacts and len(normalized_artifacts) == len(
            {artifact["name"] for artifact in normalized_artifacts}
        ):
            normalized = {"kind": kind, "locator": locator, "artifacts": normalized_artifacts}
            if native_distribution_identity_structure_error(name, normalized):
                continue
            identities[name] = normalized
    return identities


def summarize_native_result(native: Any) -> dict[str, Any] | None:
    if not isinstance(native, dict):
        return None
    versions = native.get("artifact_versions", native.get("artifactVersions", {}))
    if not isinstance(versions, dict):
        versions = {}
    bounded_versions = {
        name: sanitized_evidence_text(version, 128)
        for name, version in versions.items()
        if name in DISTRIBUTIONS and isinstance(version, str)
    }
    raw_scenarios = native.get("scenario_results", {})
    scenarios: list[dict[str, str]] = []
    if isinstance(raw_scenarios, dict):
        items = raw_scenarios.items()
    elif isinstance(raw_scenarios, list):
        items = ((str(index), item) for index, item in enumerate(raw_scenarios))
    else:
        items = iter(())
    for scenario_id, value in list(items)[:128]:
        if isinstance(value, dict):
            scenario_id = value.get("scenario_id", value.get("id", scenario_id))
            status = value.get("status", value.get("outcome", "unknown"))
        else:
            status = value
        scenarios.append(
            {
                "id": sanitized_evidence_text(scenario_id, 128),
                "status": sanitized_evidence_text(status, 64),
            }
        )
    schema = native.get("schema")
    source_values = [
        native.get("local_product_source_checkouts_used"),
        native.get("local_product_source_checkout_used"),
        native.get("local_product_sources_used"),
    ]
    source_policy = native.get("source_policy")
    if isinstance(source_policy, dict):
        source_values.append(source_policy.get("local_product_sources_used"))
    local_source_used = True if True in source_values else (False if False in source_values else None)
    return {
        "schema": sanitized_evidence_text(schema, 256) if isinstance(schema, str) else None,
        "artifact_versions": bounded_versions,
        "executed_distribution_identities": summarize_executed_distribution_identities(native),
        "scenario_statuses": scenarios,
        "failure_projection": summarize_native_failure_projection(native),
        "local_product_source_checkout_used": local_source_used,
    }


def inject_distribution_identity_mismatch(
    native: Any, plan: dict[str, Any], required_distributions: list[str]
) -> tuple[str, str]:
    if not isinstance(native, dict):
        raise ConformanceError("distribution identity failure injection requires a native result object")
    raw = native.get("executed_distribution_identities", native.get("executedDistributionIdentities"))
    if not isinstance(raw, dict):
        raise ConformanceError("distribution identity failure injection requires executed distribution evidence")
    for name in sorted(required_distributions):
        identity = raw.get(name)
        expected_identity = plan["distribution_identities"][name]
        if not isinstance(identity, dict) or not isinstance(identity.get("artifacts"), list):
            continue
        expected_artifacts = {artifact["name"]: artifact["sha256"] for artifact in expected_identity["artifacts"]}
        artifacts = sorted(
            (artifact for artifact in identity["artifacts"] if isinstance(artifact, dict)),
            key=lambda artifact: str(artifact.get("name", "")),
        )
        for artifact in artifacts:
            artifact_name = artifact.get("name")
            if artifact_name not in expected_artifacts:
                continue
            expected_digest = expected_artifacts[artifact_name]
            artifact["sha256"] = "0" * 64 if expected_digest != "0" * 64 else "f" * 64
            return name, artifact_name
    raise ConformanceError("distribution identity failure injection found no required executed artifact identity")


def is_classified_transient(text: str) -> bool:
    return any(pattern.search(text) for pattern in TRANSIENT_PATTERNS)


def classify_attempt(
    *,
    returncode: int,
    timed_out: bool,
    native_outcome: str | None,
    runner_blocked: bool,
    native_result_rejected: bool,
    diagnostic_text: str,
) -> tuple[str, bool]:
    if native_result_rejected:
        return "infrastructure_failure", False
    if native_outcome is not None and native_outcome not in PASS_OUTCOMES and not runner_blocked:
        return "product_failure", False
    if timed_out:
        return "product_failure", False
    transient = is_classified_transient(diagnostic_text)
    if runner_blocked:
        return "infrastructure_failure", transient
    if returncode == 0 and native_outcome in PASS_OUTCOMES:
        return "passed", False
    if returncode == 75 or transient:
        return "infrastructure_failure", True
    return "product_failure", False


def execute_command(
    command: list[str],
    *,
    cwd: Path,
    environment: dict[str, str],
    timeout_seconds: int,
    stdout_path: Path,
    stderr_path: Path,
) -> tuple[int, bool]:
    timed_out = False
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        process = subprocess.Popen(
            command,
            cwd=cwd,
            env=environment,
            stdout=stdout,
            stderr=stderr,
            start_new_session=True,
        )
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                returncode = process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                returncode = process.wait()
    return returncode, timed_out


def runner_command(path: Path, result_dir: Path) -> list[str]:
    interpreters = {
        ".sh": "bash",
        ".mjs": "node",
        ".py": sys.executable,
    }
    try:
        interpreter = interpreters[path.suffix]
    except KeyError as error:
        raise ConformanceError(f"unsupported conformance runner type: {path.suffix}") from error
    return [interpreter, str(path), "--result-dir", str(result_dir)]


def artifact_environment(plan: dict[str, Any], scratch: Path) -> dict[str, str]:
    versions = {name: identity["version"] for name, identity in plan["artifact_tuple"].items()}
    return {
        **os.environ,
        "DW_CANDIDATE_VERIFICATION_SHA256": plan["candidate"]["verification_sha256"],
        "DW_SERVER_IMAGE": plan["server_runner"]["image"],
        "DW_SERVER_VERSION": versions["server"],
        "DW_CLI_VERSION": versions["cli"],
        "DW_PHP_SDK_VERSION": versions["sdk-php"],
        "DW_PYTHON_SDK_VERSION": versions["sdk-python"],
        "DW_RUST_SDK_VERSION": versions["sdk-rust"],
        "DW_WORKFLOW_PHP_VERSION": versions["workflow"],
        "DW_WATERLINE_VERSION": versions["waterline"],
        "DW_WATERLINE_SERVICE_IMAGE": plan["waterline_service_runner"]["image"],
        "DW_CONFORMANCE_TMPDIR": str(scratch),
    }


def docker_runtime_command(
    command: list[str], *, timeout_seconds: int = 180, check: bool = True
) -> subprocess.CompletedProcess[str]:
    try:
        process = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
        )
    except FileNotFoundError as error:
        raise ConformanceError("Docker is required by the declared standalone-server runtime") from error
    except subprocess.TimeoutExpired as error:
        raise ConformanceError("standalone-server Docker command exceeded its bounded deadline") from error
    if check and process.returncode:
        detail = bounded_text((process.stderr or process.stdout).strip(), DIAGNOSTIC_LIMIT)
        action = command[1] if len(command) > 1 else "command"
        raise ConformanceError(f"standalone-server Docker {action} failed: {detail}")
    return process


def wait_for_server_ready(server_url: str, container_name: str, *, docker: str = "docker") -> None:
    deadline = time.monotonic() + 120
    last_error = "server did not answer its readiness endpoint"
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{server_url}/api/ready", timeout=3) as response:
                if response.status < 500:
                    return
                last_error = f"readiness endpoint returned HTTP {response.status}"
        except Exception as error:  # Network error details are retained only after the bounded wait.
            last_error = f"{type(error).__name__}: {error}"
        time.sleep(2)
    logs = docker_runtime_command(
        [docker, "logs", "--tail", "80", container_name],
        timeout_seconds=30,
        check=False,
    )
    detail = bounded_text(f"{last_error}\n{logs.stdout}\n{logs.stderr}".strip(), DIAGNOSTIC_LIMIT)
    raise ConformanceError(f"exact candidate standalone server did not become ready: {detail}")


def require_running_container(container_name: str, *, docker: str = "docker") -> None:
    state = docker_runtime_command(
        [docker, "inspect", "--format", "{{.State.Running}}", container_name],
        timeout_seconds=30,
    )
    if state.stdout.strip() == "true":
        return
    logs = docker_runtime_command(
        [docker, "logs", "--tail", "80", container_name],
        timeout_seconds=30,
        check=False,
    )
    detail = bounded_text(f"{logs.stdout}\n{logs.stderr}".strip(), DIAGNOSTIC_LIMIT)
    raise ConformanceError(f"exact candidate standalone server process {container_name} exited: {detail}")


def wait_for_healthy_container(container_name: str, *, docker: str = "docker") -> None:
    deadline = time.monotonic() + 120
    last_status = "starting"
    while time.monotonic() < deadline:
        state = docker_runtime_command(
            [docker, "inspect", "--format", "{{.State.Health.Status}}", container_name],
            timeout_seconds=30,
            check=False,
        )
        if state.returncode == 0:
            last_status = state.stdout.strip()
            if last_status == "healthy":
                return
            if last_status == "unhealthy":
                break
        else:
            last_status = bounded_text((state.stderr or state.stdout).strip(), 512)
        time.sleep(2)
    logs = docker_runtime_command(
        [docker, "logs", "--tail", "80", container_name],
        timeout_seconds=30,
        check=False,
    )
    detail = bounded_text(f"health={last_status}\n{logs.stdout}\n{logs.stderr}".strip(), DIAGNOSTIC_LIMIT)
    raise ConformanceError(f"standalone-server dependency {container_name} did not become healthy: {detail}")


def cleanup_docker_runtime(command: list[str]) -> None:
    with contextlib.suppress(ConformanceError):
        docker_runtime_command(command, timeout_seconds=30, check=False)


@contextlib.contextmanager
def standalone_server_runtime(
    plan: dict[str, Any], runner: dict[str, Any], scratch: Path, *, docker: str = "docker"
) -> Iterator[dict[str, str]]:
    runtime = runner["runtime"]
    identity_seed = f"{scratch.resolve()}:{os.getpid()}:{time.time_ns()}".encode()
    suffix = sha256_bytes(identity_seed)[:12]
    prefix = f"dw-beta-{runner['id']}-{suffix}"
    network = f"{prefix}-network"
    container_names = [
        f"{prefix}-bootstrap",
        f"{prefix}-http",
        f"{prefix}-queue",
        f"{prefix}-scheduler",
        f"{prefix}-mysql",
        f"{prefix}-redis",
    ]
    bootstrap_name, http_name, queue_name, scheduler_name, mysql_name, redis_name = container_names
    image = plan["server_runner"]["image"]
    mysql_image = plan["runtime_dependencies"]["mysql"]["image"]
    redis_image = plan["runtime_dependencies"]["redis"]["image"]
    server_version = plan["artifact_tuple"]["server"]["version"]
    manifest_digest = plan["candidate"]["manifest_sha256"]
    runtime_token = f"beta-{manifest_digest[:32]}"
    runtime_key = (
        "base64:" + base64.b64encode(hashlib.sha256(f"{manifest_digest}:{runner['id']}".encode()).digest()).decode()
    )
    labels = ["--label", f"dev.durable-workflow.beta-conformance={manifest_digest}"]
    database_name = "durable_workflow"
    database_user = "durable_workflow"
    database_password = sha256_bytes(f"{manifest_digest}:{runner['id']}:mysql".encode())[:32]
    database_root_password = sha256_bytes(f"{manifest_digest}:{runner['id']}:mysql-root".encode())[:32]
    shared_environment = [
        "-e",
        f"APP_VERSION={server_version}",
        "-e",
        f"DW_SERVER_KEY={runtime_key}",
        "-e",
        "DW_AUTH_DRIVER=token",
        "-e",
        f"DW_AUTH_TOKEN={runtime_token}",
        "-e",
        "DW_WORKER_POLL_TIMEOUT=1",
        "-e",
        "DW_WORKER_POLL_INTERVAL_MS=100",
        "-e",
        "DW_QUERY_TASK_TIMEOUT=3",
        "-e",
        "DB_CONNECTION=mysql",
        "-e",
        f"DB_HOST={mysql_name}",
        "-e",
        "DB_PORT=3306",
        "-e",
        f"DB_DATABASE={database_name}",
        "-e",
        f"DB_USERNAME={database_user}",
        "-e",
        f"DB_PASSWORD={database_password}",
        "-e",
        "QUEUE_CONNECTION=redis",
        "-e",
        "CACHE_STORE=redis",
        "-e",
        f"REDIS_HOST={redis_name}",
        "-e",
        "REDIS_PORT=6379",
    ]

    try:
        docker_runtime_command([docker, "network", "create", *labels, network])
        docker_runtime_command(
            [
                docker,
                "run",
                "-d",
                "--rm",
                "--name",
                mysql_name,
                *labels,
                "--network",
                network,
                "-e",
                f"MYSQL_DATABASE={database_name}",
                "-e",
                f"MYSQL_USER={database_user}",
                "-e",
                f"MYSQL_PASSWORD={database_password}",
                "-e",
                f"MYSQL_ROOT_PASSWORD={database_root_password}",
                "--health-cmd",
                'mysqladmin ping -h 127.0.0.1 -uroot --password="$MYSQL_ROOT_PASSWORD"',
                "--health-interval",
                "2s",
                "--health-timeout",
                "2s",
                "--health-retries",
                "60",
                mysql_image,
            ]
        )
        docker_runtime_command(
            [
                docker,
                "run",
                "-d",
                "--rm",
                "--name",
                redis_name,
                *labels,
                "--network",
                network,
                "--health-cmd",
                "redis-cli ping",
                "--health-interval",
                "2s",
                "--health-timeout",
                "2s",
                "--health-retries",
                "60",
                redis_image,
            ]
        )
        wait_for_healthy_container(mysql_name, docker=docker)
        wait_for_healthy_container(redis_name, docker=docker)
        docker_runtime_command(
            [
                docker,
                "run",
                "--rm",
                "--name",
                bootstrap_name,
                *labels,
                "--network",
                network,
                *shared_environment,
                image,
                "server-bootstrap",
            ]
        )
        docker_runtime_command(
            [
                docker,
                "run",
                "-d",
                "--rm",
                "--name",
                http_name,
                *labels,
                "-p",
                "127.0.0.1::8080",
                "--network",
                network,
                *shared_environment,
                "-e",
                "DW_SERVER_TOPOLOGY_SHAPE=standalone_server",
                "-e",
                "DW_SERVER_PROCESS_CLASS=server_http_node",
                image,
            ]
        )
        docker_runtime_command(
            [
                docker,
                "run",
                "-d",
                "--rm",
                "--name",
                queue_name,
                *labels,
                "--network",
                network,
                *shared_environment,
                "-e",
                "DW_SERVER_TOPOLOGY_SHAPE=standalone_server",
                "-e",
                "DW_SERVER_PROCESS_CLASS=worker_node",
                image,
                "php",
                "artisan",
                "queue:work",
                "--sleep=1",
                "--tries=3",
                "--max-time=5400",
            ]
        )
        docker_runtime_command(
            [
                docker,
                "run",
                "-d",
                "--rm",
                "--init",
                "--name",
                scheduler_name,
                *labels,
                "--network",
                network,
                *shared_environment,
                "-e",
                "DW_SERVER_TOPOLOGY_SHAPE=standalone_server",
                "-e",
                "DW_SERVER_PROCESS_CLASS=scheduler_node",
                image,
                "sh",
                "-c",
                "while true; do php artisan schedule:evaluate --limit=100 --json; "
                "php artisan activity:timeout-enforce --limit=100; sleep 1; done",
            ]
        )
        port_result = docker_runtime_command([docker, "port", http_name, "8080/tcp"], timeout_seconds=30)
        port_match = re.search(r"127\.0\.0\.1:(\d+)\s*$", port_result.stdout)
        if port_match is None:
            raise ConformanceError("standalone-server Docker runtime did not publish a loopback HTTP port")
        server_url = f"http://127.0.0.1:{port_match.group(1)}"
        wait_for_server_ready(server_url, http_name, docker=docker)
        for container_name in (mysql_name, redis_name, http_name, queue_name, scheduler_name):
            require_running_container(container_name, docker=docker)
        runner_server_url = f"http://{http_name}:8080" if runner["id"] == "waterline-service" else server_url
        environment = {
            runtime["server_url_environment"]: runner_server_url,
            runtime["namespace_environment"]: "default",
            runtime["token_environment"]: runtime_token,
        }
        if runner["id"] == "waterline-service":
            environment["DW_WATERLINE_SERVICE_DOCKER_NETWORK"] = network
        yield environment
        for container_name in (mysql_name, redis_name, http_name, queue_name, scheduler_name):
            require_running_container(container_name, docker=docker)
    finally:
        for container_name in reversed(container_names):
            cleanup_docker_runtime([docker, "rm", "--force", container_name])
        cleanup_docker_runtime([docker, "network", "rm", network])


@contextlib.contextmanager
def runner_runtime_environment(plan: dict[str, Any], runner: dict[str, Any], scratch: Path) -> Iterator[dict[str, str]]:
    runtime = runner.get("runtime")
    if runtime is None:
        yield {}
        return
    if runtime["kind"] != "standalone-server":
        raise ConformanceError(f"unsupported runner runtime: {runtime['kind']}")
    with standalone_server_runtime(plan, runner, scratch) as environment:
        yield environment


def failure_fingerprint(
    plan: dict[str, Any], experiment: str, classification: str, owner: str, diagnostics: list[dict[str, Any]]
) -> str | None:
    if classification == "passed":
        return None
    stable = {
        "candidate_manifest_sha256": plan["candidate"]["manifest_sha256"],
        "candidate_verification_sha256": plan["candidate"]["verification_sha256"],
        "contract_sha256": plan["runner"]["contract_sha256"],
        "runtime_dependencies": plan["runtime_dependencies"],
        "experiment": experiment,
        "classification": classification,
        "owning_contract": owner,
        "findings": [diagnostic.get("findings", []) for diagnostic in diagnostics],
        "timed_out": [diagnostic.get("timed_out", False) for diagnostic in diagnostics],
        "native_outcomes": [diagnostic.get("native_outcome") for diagnostic in diagnostics],
    }
    return sha256_bytes(canonical_json(stable))


def injected_failure_result(
    plan: dict[str, Any],
    experiment: str,
    owner: str,
    required_clients: list[str],
    required_distributions: list[str],
    started_at: str,
) -> dict[str, Any]:
    raw_stderr = f"deterministic synthetic sanitizer canary: Authorization: Bearer {SYNTHETIC_CREDENTIAL_CANARY}"
    diagnostic = {
        "runner": "injected-product-failure",
        "attempt": 1,
        "exit_code": 1,
        "timed_out": False,
        "native_outcome": "fail",
        "runner_blocked": False,
        "stdout_tail": "",
        "stdout_sha256": sha256_bytes(b""),
        "stderr_tail": sanitized_evidence_text(raw_stderr, DIAGNOSTIC_LIMIT),
        "stderr_sha256": sha256_bytes(raw_stderr.encode()),
        "native_result_size_bytes": None,
        "native_result_sha256": None,
        "native_result_prefix_sha256": None,
        "native_result_prefix_bytes": None,
        "native_summary": None,
        "findings": [
            {
                "type": "injected_product_failure",
                "owning_contract": owner,
                "summary": "Deterministic product failure injected before experiment execution.",
            }
        ],
    }
    return experiment_result(
        plan,
        experiment,
        owner,
        required_clients,
        required_distributions,
        started_at,
        "product_failure",
        1,
        [diagnostic],
    )


def experiment_result(
    plan: dict[str, Any],
    experiment: str,
    owner: str,
    required_clients: list[str],
    required_distributions: list[str],
    started_at: str,
    classification: str,
    attempts: int,
    diagnostics: list[dict[str, Any]],
) -> dict[str, Any]:
    result = {
        "schema": EXPERIMENT_RESULT_SCHEMA,
        "experiment": experiment,
        "candidate": plan["candidate"],
        "artifact_tuple": plan["artifact_tuple"],
        "source_identities": plan["source_identities"],
        "distribution_identities": plan["distribution_identities"],
        "runtime_dependencies": plan["runtime_dependencies"],
        "runner": plan["runner"],
        "server_runner": plan["server_runner"],
        "waterline_service_runner": plan["waterline_service_runner"],
        "owning_contract": owner,
        "required_clients": required_clients,
        "required_distributions": required_distributions,
        "source_policy": {
            "product_artifacts": "published_only",
            "orchestration_source": "bound_control_plane_and_exact_candidate_images",
            "local_product_source_checkout_used": False,
        },
        "started_at": started_at,
        "finished_at": now(),
        "outcome": "pass" if classification == "passed" else "fail",
        "classification": classification,
        "failure_fingerprint": failure_fingerprint(plan, experiment, classification, owner, diagnostics),
        "retry": {
            "attempts": attempts,
            "maximum_infrastructure_attempts": MAX_INFRASTRUCTURE_ATTEMPTS,
            "semantic_failures_retryable": False,
        },
        "diagnostics": diagnostics,
    }
    validate_experiment_result(result, plan)
    return result


def artifact_binding_failures(
    plan: dict[str, Any], required_distributions: list[str], diagnostics: list[dict[str, Any]]
) -> list[str]:
    observed_versions: dict[str, set[str]] = {}
    observed_identities: dict[str, list[dict[str, Any]]] = {}
    failures: list[str] = []
    for diagnostic in diagnostics:
        summary = diagnostic.get("native_summary")
        if not isinstance(summary, dict):
            continue
        if summary.get("local_product_source_checkout_used") is True:
            failures.append("native evidence reports a local product source checkout")
        versions = summary.get("artifact_versions")
        if isinstance(versions, dict):
            for name, version in versions.items():
                observed_versions.setdefault(name, set()).add(str(version))
        identities = summary.get("executed_distribution_identities")
        if isinstance(identities, dict):
            for name, identity in identities.items():
                observed_identities.setdefault(name, []).append(identity)
    for name, versions in observed_versions.items():
        expected = distribution_version(plan["artifact_tuple"], name)
        if any(not registry_versions_equivalent(name, version, expected) for version in versions):
            failures.append(f"{name} native evidence reports {sorted(versions)}, expected exact version {expected}")
    for name, identities in observed_identities.items():
        expected = plan["distribution_identities"][name]
        expected_artifacts = {artifact["name"]: artifact["sha256"] for artifact in expected["artifacts"]}
        for identity in identities:
            if native_distribution_identity_structure_error(name, identity):
                failures.append(f"{name} native evidence has an invalid executed distribution identity")
                continue
            locator_prefix = f"{identity['kind']}:{DISTRIBUTIONS[name][1].package}@"
            observed_version = identity["locator"].removeprefix(locator_prefix)
            expected_version = distribution_version(plan["artifact_tuple"], name)
            if identity["kind"] != expected["kind"] or not registry_versions_equivalent(
                name,
                observed_version,
                expected_version,
            ):
                failures.append(f"{name} native evidence reports a different distribution locator")
                continue
            for artifact in identity["artifacts"]:
                expected_sha256 = expected_artifacts.get(artifact["name"])
                if expected_sha256 is None:
                    failures.append(
                        f"{name} native evidence reports unknown executed distribution artifact {artifact['name']}"
                    )
                elif artifact["sha256"] != expected_sha256:
                    failures.append(
                        f"{name} executed distribution artifact {artifact['name']} does not match the candidate digest"
                    )
    for name in artifact_version_components(required_distributions):
        if name not in observed_versions:
            failures.append(f"native evidence does not report the exact {name} artifact version")
    for name in required_distributions:
        if name not in observed_identities:
            failures.append(f"native evidence does not report the executed {name} distribution identity")
    return list(dict.fromkeys(failures))


def run_experiment(
    plan: dict[str, Any],
    contract: dict[str, Any],
    experiment: str,
    artifact_root: Path,
    result_dir: Path,
    *,
    inject_product_failure: bool = False,
    inject_identity_failure: bool = False,
) -> dict[str, Any]:
    validate_plan(plan)
    validate_contract(contract)
    if sha256_bytes(canonical_json(contract)) != plan["runner"]["contract_sha256"]:
        raise ConformanceError("execution contract does not match the runner revision bound into the plan")
    if experiment not in EXPERIMENTS:
        raise ConformanceError(f"unknown beta conformance experiment: {experiment}")
    if inject_product_failure and inject_identity_failure:
        raise ConformanceError("product and distribution identity failures cannot both be injected")
    specification = contract["experiments"][experiment]
    owner = specification["owning_contract"]
    started_at = now()
    result_dir.mkdir(parents=True, exist_ok=True)
    if inject_product_failure:
        result = injected_failure_result(
            plan,
            experiment,
            owner,
            specification["required_clients"],
            specification["required_distributions"],
            started_at,
        )
        write_json(result_dir / "experiment-result.json", result)
        return result

    diagnostics: list[dict[str, Any]] = []
    final_classification = "passed"
    maximum_attempts_used = 1
    identity_failure_injected = False
    for runner in specification["runners"]:
        runner_root = artifact_root if runner["source"] == "server-image" else Path(__file__).resolve().parent.parent
        runner_path = runner_root / safe_relative_path(runner["path"])
        if not runner_path.is_file():
            diagnostic = {
                "runner": runner["id"],
                "attempt": 1,
                "exit_code": 127,
                "timed_out": False,
                "native_outcome": None,
                "runner_blocked": False,
                "stdout_tail": "",
                "stdout_sha256": sha256_bytes(b""),
                "stderr_tail": bounded_text(f"published server image is missing {runner['path']}", DIAGNOSTIC_LIMIT),
                "stderr_sha256": sha256_bytes(f"published server image is missing {runner['path']}".encode()),
                "native_result_size_bytes": None,
                "native_result_sha256": None,
                "native_result_prefix_sha256": None,
                "native_result_prefix_bytes": None,
                "native_summary": None,
                "findings": [
                    {
                        "type": "published_runner_missing",
                        "owning_contract": owner,
                        "summary": bounded_text(f"Published server image is missing {runner['path']}"),
                    }
                ],
            }
            diagnostics.append(diagnostic)
            final_classification = "product_failure"
            break

        native_dir = result_dir / "native" / runner["id"]
        native_dir.mkdir(parents=True, exist_ok=True)
        scratch = result_dir / "scratch" / runner["id"]
        scratch.mkdir(parents=True, exist_ok=True)
        runner_classification = "passed"
        for attempt in range(1, MAX_INFRASTRUCTURE_ATTEMPTS + 1):
            maximum_attempts_used = max(maximum_attempts_used, attempt)
            stdout_path = result_dir / f"{runner['id']}-attempt-{attempt}.stdout.log"
            stderr_path = result_dir / f"{runner['id']}-attempt-{attempt}.stderr.log"
            runtime_blocked = False
            runtime_error = ""
            try:
                with runner_runtime_environment(plan, runner, scratch) as runtime_environment:
                    environment = {**artifact_environment(plan, scratch), **runtime_environment}
                    returncode, timed_out = execute_command(
                        runner_command(runner_path, native_dir),
                        cwd=artifact_root,
                        environment=environment,
                        timeout_seconds=specification["timeout_seconds"],
                        stdout_path=stdout_path,
                        stderr_path=stderr_path,
                    )
            except ConformanceError as error:
                runtime_blocked = True
                runtime_error = sanitized_evidence_text(error, DIAGNOSTIC_LIMIT)
                stdout_path.write_text("", encoding="utf-8")
                stderr_path.write_text(runtime_error, encoding="utf-8")
                returncode = 1
                timed_out = False
            stdout_tail, stdout_digest = tail_and_digest(stdout_path)
            stderr_tail, stderr_digest = tail_and_digest(stderr_path)
            native_path = native_dir / runner["result"]
            native: Any = None
            native_size = None
            native_digest = None
            native_prefix_digest = None
            native_prefix_bytes = None
            native_result_error = ""
            native_result_rejected = False
            injected_identity: tuple[str, str] | None = None
            if native_path.is_file():
                (
                    native,
                    native_size,
                    native_digest,
                    native_prefix_digest,
                    native_prefix_bytes,
                    native_result_status,
                ) = load_native_result(native_path)
                if native_result_status == "oversized":
                    native_result_error = (
                        f"published runner result size {native_size} exceeds the "
                        f"{NATIVE_RESULT_LIMIT}-byte portable evidence limit"
                    )
                    native_result_rejected = True
                elif native_result_status == "invalid_json":
                    native_result_error = "published runner result is not valid JSON"
                    native_result_rejected = True
                elif native_result_status == "unreadable":
                    native_result_error = "published runner result could not be read"
                if native_result_error:
                    stderr_tail = sanitized_evidence_text(
                        f"{stderr_tail}\n{native_result_error}",
                        DIAGNOSTIC_LIMIT,
                    )
                else:
                    native_outcome, _, _ = native_state(native)
                    native_result_error = native_result_completeness_error(
                        native,
                        runner["required_distributions"],
                        runner,
                    )
                    native_result_rejected = bool(native_result_error)
                    if native_result_error:
                        stderr_tail = sanitized_evidence_text(
                            f"{stderr_tail}\n{native_result_error}",
                            DIAGNOSTIC_LIMIT,
                        )
                    elif (
                        inject_identity_failure
                        and not identity_failure_injected
                        and returncode == 0
                        and not timed_out
                        and native_outcome in PASS_OUTCOMES
                    ):
                        injected_identity = inject_distribution_identity_mismatch(
                            native, plan, runner["required_distributions"]
                        )
                        write_json(native_path, native)
                        identity_failure_injected = True
                        (
                            native,
                            native_size,
                            native_digest,
                            native_prefix_digest,
                            native_prefix_bytes,
                            rewritten_native_status,
                        ) = load_native_result(native_path)
                        if rewritten_native_status == "oversized":
                            native_result_error = (
                                f"published runner result size {native_size} exceeds the "
                                f"{NATIVE_RESULT_LIMIT}-byte portable evidence limit"
                            )
                            native_result_rejected = True
                        elif rewritten_native_status == "invalid_json":
                            native_result_error = "published runner result is not valid JSON"
                            native_result_rejected = True
                        elif rewritten_native_status == "unreadable":
                            native_result_error = "published runner result could not be read"
                        if native_result_error:
                            stderr_tail = sanitized_evidence_text(
                                f"{stderr_tail}\n{native_result_error}",
                                DIAGNOSTIC_LIMIT,
                            )
            else:
                if not runtime_blocked:
                    native_result_error = "published runner did not emit its declared native result"
                    stderr_tail = sanitized_evidence_text(
                        f"{stderr_tail}\n{native_result_error}",
                        DIAGNOSTIC_LIMIT,
                    )
            native_outcome, runner_blocked, findings = native_state(native)
            runner_blocked = runner_blocked or runtime_blocked or bool(native_result_error)
            if runtime_blocked:
                findings.insert(
                    0,
                    {
                        "type": "declared_runtime_unavailable",
                        "owning_contract": owner,
                        "summary": sanitized_evidence_text(
                            f"Published runner {runner['id']} could not start its declared runtime: {runtime_error}",
                            FINDING_TEXT_LIMIT,
                        ),
                    },
                )
                findings = findings[:FINDING_LIMIT]
            if native_result_error:
                findings.insert(
                    0,
                    {
                        "type": "native_result_unreadable",
                        "owning_contract": owner,
                        "summary": sanitized_evidence_text(
                            f"Published runner {runner['id']} emitted evidence the portable wrapper could not read: "
                            f"{native_result_error}.",
                            FINDING_TEXT_LIMIT,
                        ),
                    },
                )
                findings = findings[:FINDING_LIMIT]
            if injected_identity is not None:
                component, artifact_name = injected_identity
                findings.insert(
                    0,
                    {
                        "type": "injected_distribution_identity_mismatch",
                        "owning_contract": owner,
                        "summary": sanitized_evidence_text(
                            f"Injected a same-version digest mismatch for {component} artifact {artifact_name}.",
                            FINDING_TEXT_LIMIT,
                        ),
                    },
                )
                findings = findings[:FINDING_LIMIT]
            classification, retryable = classify_attempt(
                returncode=returncode,
                timed_out=timed_out,
                native_outcome=native_outcome,
                runner_blocked=runner_blocked,
                native_result_rejected=native_result_rejected,
                diagnostic_text=f"{stdout_tail}\n{stderr_tail}",
            )
            if classification != "passed" and not findings:
                findings = [
                    {
                        "type": "experiment_execution_failure",
                        "owning_contract": owner,
                        "summary": sanitized_evidence_text(
                            "Experiment timed out."
                            if timed_out
                            else f"Published runner {runner['id']} exited with status {returncode}.",
                            FINDING_TEXT_LIMIT,
                        ),
                    }
                ]
            diagnostics.append(
                {
                    "runner": runner["id"],
                    "attempt": attempt,
                    "exit_code": returncode,
                    "timed_out": timed_out,
                    "native_outcome": native_outcome,
                    "runner_blocked": runner_blocked,
                    "stdout_tail": stdout_tail,
                    "stdout_sha256": stdout_digest,
                    "stderr_tail": stderr_tail,
                    "stderr_sha256": stderr_digest,
                    "native_result_size_bytes": native_size,
                    "native_result_sha256": native_digest,
                    "native_result_prefix_sha256": native_prefix_digest,
                    "native_result_prefix_bytes": native_prefix_bytes,
                    "native_summary": summarize_native_result(native),
                    "findings": findings,
                }
            )
            runner_classification = classification
            if classification == "passed":
                break
            if not retryable or attempt == MAX_INFRASTRUCTURE_ATTEMPTS:
                break
            time.sleep(attempt)
        final_classification = runner_classification
        if final_classification != "passed":
            break

    if final_classification == "passed":
        binding_failures = artifact_binding_failures(plan, specification["required_distributions"], diagnostics)
        if binding_failures:
            message = "\n".join(binding_failures)
            diagnostics.append(
                {
                    "runner": "artifact-binding",
                    "attempt": 1,
                    "exit_code": 1,
                    "timed_out": False,
                    "native_outcome": "fail",
                    "runner_blocked": False,
                    "stdout_tail": "",
                    "stdout_sha256": sha256_bytes(b""),
                    "stderr_tail": sanitized_evidence_text(message, DIAGNOSTIC_LIMIT),
                    "stderr_sha256": sha256_bytes(message.encode()),
                    "native_result_size_bytes": None,
                    "native_result_sha256": None,
                    "native_result_prefix_sha256": None,
                    "native_result_prefix_bytes": None,
                    "native_summary": None,
                    "findings": [
                        {
                            "type": "exact_artifact_binding_failure",
                            "owning_contract": owner,
                            "summary": sanitized_evidence_text(failure, FINDING_TEXT_LIMIT),
                        }
                        for failure in binding_failures[:FINDING_LIMIT]
                    ],
                }
            )
            final_classification = "product_failure"

    result = experiment_result(
        plan,
        experiment,
        owner,
        specification["required_clients"],
        specification["required_distributions"],
        started_at,
        final_classification,
        maximum_attempts_used,
        diagnostics,
    )
    write_json(result_dir / "experiment-result.json", result)
    return result


def retained_attempt_classification(diagnostic: dict[str, Any]) -> tuple[str, bool]:
    native_size = diagnostic["native_result_size_bytes"]
    native_digest = diagnostic["native_result_sha256"]
    native_summary = diagnostic["native_summary"]
    native_result_rejected = (isinstance(native_size, int) and native_size > NATIVE_RESULT_LIMIT) or (
        native_digest is not None and native_summary is None
    )
    return classify_attempt(
        returncode=diagnostic["exit_code"],
        timed_out=diagnostic["timed_out"],
        native_outcome=diagnostic["native_outcome"],
        runner_blocked=diagnostic["runner_blocked"],
        native_result_rejected=native_result_rejected,
        diagnostic_text=f"{diagnostic['stdout_tail']}\n{diagnostic['stderr_tail']}",
    )


def validate_retained_runner_summary(
    diagnostic: dict[str, Any],
    runner: dict[str, Any],
    plan: dict[str, Any],
    *,
    terminal_pass: bool,
    require_contract_summary: bool,
    require_binding: bool,
) -> None:
    summary = diagnostic["native_summary"]
    if summary is None:
        if terminal_pass:
            raise ConformanceError(f"passing runner {runner['id']} does not retain a native summary")
        return
    required_distributions = set(runner["required_distributions"])
    required_artifact_versions = set(runner_required_artifact_versions(runner))
    reported_versions = set(summary["artifact_versions"])
    if reported_versions - required_artifact_versions:
        raise ConformanceError(f"runner {runner['id']} retains artifact versions outside its exact assignment")
    reported_identities = set(summary["executed_distribution_identities"])
    if reported_identities - required_distributions:
        raise ConformanceError(f"runner {runner['id']} retains distribution identities outside its exact assignment")
    if require_contract_summary and (
        reported_versions != required_artifact_versions or reported_identities != required_distributions
    ):
        raise ConformanceError(f"runner {runner['id']} does not retain its exact distribution assignment")
    if not require_contract_summary:
        return
    result_schema = runner.get("result_schema")
    if result_schema is not None and summary["schema"] != result_schema:
        raise ConformanceError(f"runner {runner['id']} does not retain its declared schema")
    required_scenarios = runner.get("required_scenarios", [])
    if required_scenarios:
        scenario_ids = [cell["id"] for cell in summary["scenario_statuses"]]
        if len(scenario_ids) != len(set(scenario_ids)) or set(scenario_ids) != set(required_scenarios):
            raise ConformanceError(f"runner {runner['id']} does not retain exactly its declared scenario cells")
        if terminal_pass and any(cell["status"] != "pass" for cell in summary["scenario_statuses"]):
            raise ConformanceError(f"passing runner {runner['id']} retains a non-passing declared scenario cell")
    if require_binding and artifact_binding_failures(plan, runner["required_distributions"], [diagnostic]):
        raise ConformanceError(f"passing runner {runner['id']} has incomplete or mismatched native artifact evidence")


def validate_retained_attempt_lifecycle(result: dict[str, Any], plan: dict[str, Any], contract: dict[str, Any]) -> None:
    experiment = result["experiment"]
    specification = contract["experiments"][experiment]
    if result["owning_contract"] != specification["owning_contract"]:
        raise ConformanceError(f"experiment result {experiment} names a different owning contract")
    if result["required_clients"] != specification["required_clients"]:
        raise ConformanceError(f"experiment result {experiment} names different required clients")
    if result["required_distributions"] != specification["required_distributions"]:
        raise ConformanceError(f"experiment result {experiment} names different required distributions")

    diagnostics = result["diagnostics"]
    if diagnostics[0]["runner"] == "injected-product-failure":
        if (
            len(diagnostics) != 1
            or result["classification"] != "product_failure"
            or result["retry"]["attempts"] != 1
            or diagnostics[0]["native_summary"] is not None
        ):
            raise ConformanceError("injected product-failure evidence has an invalid lifecycle")
        return
    if any(diagnostic["runner"] == "injected-product-failure" for diagnostic in diagnostics):
        raise ConformanceError("injected product-failure evidence must be the only diagnostic")

    binding_positions = [
        index for index, diagnostic in enumerate(diagnostics) if diagnostic["runner"] == "artifact-binding"
    ]
    if len(binding_positions) > 1 or (binding_positions and binding_positions[0] != len(diagnostics) - 1):
        raise ConformanceError("artifact-binding evidence has a duplicate or non-terminal lifecycle")
    binding_diagnostic = diagnostics[-1] if binding_positions else None
    runner_diagnostics = diagnostics[:-1] if binding_diagnostic is not None else diagnostics
    if binding_diagnostic is not None:
        binding_classification, _ = retained_attempt_classification(binding_diagnostic)
        if (
            result["classification"] != "product_failure"
            or binding_classification != "product_failure"
            or binding_diagnostic["attempt"] != 1
            or binding_diagnostic["native_summary"] is not None
        ):
            raise ConformanceError("artifact-binding evidence has an invalid terminal lifecycle")

    expected_runners = specification["runners"]
    expected_ids = {runner["id"] for runner in expected_runners}
    cursor = 0
    completed_runners = 0
    maximum_attempt = 1
    terminal_failure: str | None = None
    for runner in expected_runners:
        attempts: list[dict[str, Any]] = []
        while cursor < len(runner_diagnostics) and runner_diagnostics[cursor]["runner"] == runner["id"]:
            attempts.append(runner_diagnostics[cursor])
            cursor += 1
        if not attempts:
            break
        classified = [retained_attempt_classification(diagnostic) for diagnostic in attempts]
        passing_attempts = [index for index, (classification, _) in enumerate(classified) if classification == "passed"]
        if len(passing_attempts) > 1 or (passing_attempts and passing_attempts[0] != len(attempts) - 1):
            raise ConformanceError(f"runner {runner['id']} retains duplicate passing terminal attempts")
        observed_attempts = [diagnostic["attempt"] for diagnostic in attempts]
        if observed_attempts != list(range(1, len(attempts) + 1)):
            raise ConformanceError(f"runner {runner['id']} does not retain a bounded, ordered attempt lifecycle")
        maximum_attempt = max(maximum_attempt, observed_attempts[-1])
        for diagnostic, (classification, _retryable) in zip(attempts, classified, strict=True):
            validate_retained_runner_summary(
                diagnostic,
                runner,
                plan,
                terminal_pass=classification == "passed",
                require_contract_summary=classification in {"passed", "product_failure"},
                require_binding=result["classification"] == "passed",
            )
        for classification, retryable in classified[:-1]:
            if classification != "infrastructure_failure" or not retryable:
                raise ConformanceError(
                    f"runner {runner['id']} retains a non-transient attempt before its terminal attempt"
                )
        terminal_classification, _ = classified[-1]
        if terminal_classification == "passed":
            completed_runners += 1
            continue
        terminal_failure = terminal_classification
        break

    if cursor < len(runner_diagnostics):
        runner_id = runner_diagnostics[cursor]["runner"]
        if runner_id in expected_ids:
            raise ConformanceError(f"experiment {experiment} retains a duplicate or out-of-order runner {runner_id}")
        raise ConformanceError(f"experiment {experiment} retains unknown runner {runner_id}")
    if result["retry"]["attempts"] != maximum_attempt:
        raise ConformanceError("experiment result retry count disagrees with its runner attempts")
    if binding_diagnostic is not None:
        if completed_runners != len(expected_runners) or terminal_failure is not None:
            raise ConformanceError("artifact-binding evidence requires every declared runner to pass")
        return
    if result["classification"] == "passed":
        if completed_runners != len(expected_runners) or terminal_failure is not None:
            raise ConformanceError(
                f"passing experiment {experiment} does not end in one terminal pass for every declared runner"
            )
        return
    if terminal_failure is None or terminal_failure != result["classification"]:
        raise ConformanceError("failed experiment result disagrees with its terminal runner attempt")


def validate_experiment_result(result: Any, plan: dict[str, Any], contract: dict[str, Any] | None = None) -> None:
    _validate_experiment_result(
        result,
        plan,
        contract,
        schema=EXPERIMENT_RESULT_SCHEMA,
        allowed_distributions=set(DISTRIBUTIONS),
        require_waterline_service=True,
    )


def validate_recorded_experiment_result(result: Any, plan: dict[str, Any]) -> None:
    schema = result.get("schema") if isinstance(result, dict) else None
    if schema == EXPERIMENT_RESULT_SCHEMA:
        if plan.get("schema") != PLAN_SCHEMA:
            raise ConformanceError("recorded experiment result does not match its plan schema")
        validate_experiment_result(result, plan)
        return
    if schema == LEGACY_EXPERIMENT_RESULT_SCHEMA:
        if plan.get("schema") != LEGACY_PLAN_SCHEMA:
            raise ConformanceError("recorded experiment result does not match its plan schema")
        _validate_experiment_result(
            result,
            plan,
            None,
            schema=LEGACY_EXPERIMENT_RESULT_SCHEMA,
            allowed_distributions=set(COMPONENTS),
            require_waterline_service=False,
        )
        return
    raise ConformanceError("recorded experiment result uses an unsupported schema")


def _validate_experiment_result(
    result: Any,
    plan: dict[str, Any],
    contract: dict[str, Any] | None,
    *,
    schema: str,
    allowed_distributions: set[str],
    require_waterline_service: bool,
) -> None:
    required = {
        "schema",
        "experiment",
        "candidate",
        "artifact_tuple",
        "source_identities",
        "distribution_identities",
        "runtime_dependencies",
        "runner",
        "server_runner",
        "owning_contract",
        "required_clients",
        "required_distributions",
        "source_policy",
        "started_at",
        "finished_at",
        "outcome",
        "classification",
        "failure_fingerprint",
        "retry",
        "diagnostics",
    }
    if require_waterline_service:
        required.add("waterline_service_runner")
    if not isinstance(result, dict) or set(result) != required or result.get("schema") != schema:
        raise ConformanceError("experiment result has an invalid top-level shape")
    if result["experiment"] not in EXPERIMENTS:
        raise ConformanceError("experiment result has an unknown experiment")
    binding_fields = [
        "candidate",
        "artifact_tuple",
        "source_identities",
        "distribution_identities",
        "runtime_dependencies",
        "runner",
        "server_runner",
    ]
    if require_waterline_service:
        binding_fields.append("waterline_service_runner")
    for field in binding_fields:
        if result[field] != plan[field]:
            raise ConformanceError(f"experiment result {result['experiment']} has a mismatched {field} binding")
    classification = result["classification"]
    clients = result["required_clients"]
    if (
        not isinstance(clients, list)
        or not clients
        or len(clients) != len(set(clients))
        or not set(clients).issubset({"sdk-php", "sdk-python", "sdk-rust"})
    ):
        raise ConformanceError("experiment result has invalid required clients")
    required_distributions = result["required_distributions"]
    if (
        not isinstance(required_distributions, list)
        or not required_distributions
        or len(required_distributions) != len(set(required_distributions))
        or not set(required_distributions).issubset(allowed_distributions)
        or not {"server", *clients}.issubset(required_distributions)
    ):
        raise ConformanceError("experiment result has invalid required distributions")
    orchestration_source = (
        "bound_control_plane_and_exact_candidate_images"
        if require_waterline_service
        else "exact_server_container"
    )
    if result["source_policy"] != {
        "product_artifacts": "published_only",
        "orchestration_source": orchestration_source,
        "local_product_source_checkout_used": False,
    }:
        raise ConformanceError("experiment result does not prove the published-only source policy")
    if classification not in {"passed", "product_failure", "infrastructure_failure"}:
        raise ConformanceError("experiment result has an invalid classification")
    if result["outcome"] != ("pass" if classification == "passed" else "fail"):
        raise ConformanceError("experiment result outcome disagrees with its classification")
    fingerprint = result["failure_fingerprint"]
    if (classification == "passed" and fingerprint is not None) or (
        classification != "passed" and (not isinstance(fingerprint, str) or not DIGEST_PATTERN.fullmatch(fingerprint))
    ):
        raise ConformanceError("experiment result has an invalid failure fingerprint")
    retry = result["retry"]
    if (
        not isinstance(retry, dict)
        or set(retry) != {"attempts", "maximum_infrastructure_attempts", "semantic_failures_retryable"}
        or not isinstance(retry["attempts"], int)
        or not 1 <= retry["attempts"] <= MAX_INFRASTRUCTURE_ATTEMPTS
        or retry["maximum_infrastructure_attempts"] != MAX_INFRASTRUCTURE_ATTEMPTS
        or retry["semantic_failures_retryable"] is not False
    ):
        raise ConformanceError("experiment result has an invalid retry record")
    diagnostics = result["diagnostics"]
    if not isinstance(diagnostics, list) or not 1 <= len(diagnostics) <= 7:
        raise ConformanceError("experiment result diagnostics must contain one to seven bounded entries")
    for diagnostic in diagnostics:
        if not isinstance(diagnostic, dict):
            raise ConformanceError("experiment result diagnostic must be an object")
        if (
            not isinstance(diagnostic.get("runner"), str)
            or not diagnostic["runner"]
            or len(diagnostic["runner"]) > 63
            or type(diagnostic.get("attempt")) is not int
            or not 1 <= diagnostic["attempt"] <= MAX_INFRASTRUCTURE_ATTEMPTS
            or type(diagnostic.get("exit_code")) is not int
            or not isinstance(diagnostic.get("timed_out"), bool)
            or (
                diagnostic.get("native_outcome") is not None
                and (not isinstance(diagnostic["native_outcome"], str) or len(diagnostic["native_outcome"]) > 128)
            )
            or not isinstance(diagnostic.get("runner_blocked"), bool)
        ):
            raise ConformanceError("experiment result diagnostic has an invalid attempt shape")
        native_identity_fields = {
            "native_result_size_bytes",
            "native_result_sha256",
            "native_result_prefix_sha256",
            "native_result_prefix_bytes",
        }
        if not native_identity_fields.issubset(diagnostic):
            raise ConformanceError("experiment result diagnostic must retain the native result identity shape")
        if (
            len(str(diagnostic.get("stdout_tail", ""))) > DIAGNOSTIC_LIMIT
            or len(str(diagnostic.get("stderr_tail", ""))) > DIAGNOSTIC_LIMIT
        ):
            raise ConformanceError("experiment result contains unbounded diagnostic output")
        findings = diagnostic.get("findings")
        if not isinstance(findings, list) or len(findings) > FINDING_LIMIT:
            raise ConformanceError("experiment result contains unbounded findings")
        native_size = diagnostic.get("native_result_size_bytes")
        native_digest = diagnostic.get("native_result_sha256")
        native_prefix_digest = diagnostic.get("native_result_prefix_sha256")
        native_prefix_bytes = diagnostic.get("native_result_prefix_bytes")
        native_summary = diagnostic.get("native_summary")
        if native_size is not None and (type(native_size) is not int or native_size < 0):
            raise ConformanceError("experiment result has an invalid native result size")
        if native_digest is not None and (
            not isinstance(native_digest, str) or not DIGEST_PATTERN.fullmatch(native_digest)
        ):
            raise ConformanceError("experiment result has an invalid complete native result identity")
        if (native_prefix_digest is None) != (native_prefix_bytes is None) or (
            native_prefix_digest is not None
            and (
                not isinstance(native_prefix_digest, str)
                or not DIGEST_PATTERN.fullmatch(native_prefix_digest)
                or type(native_prefix_bytes) is not int
                or not 1 <= native_prefix_bytes <= NATIVE_RESULT_PREFIX_LIMIT
            )
        ):
            raise ConformanceError("experiment result has an invalid bounded native result identity")
        if native_digest is not None and (
            native_size is None
            or native_size > NATIVE_RESULT_LIMIT
            or native_prefix_digest is not None
            or native_prefix_bytes is not None
        ):
            raise ConformanceError("complete native identities are only valid for bounded evidence")
        if native_prefix_digest is not None and (
            native_size is None or native_size <= NATIVE_RESULT_LIMIT or native_digest is not None
        ):
            raise ConformanceError("bounded native identities are only valid for oversized evidence")
        known_size_without_identity = (
            native_size is not None
            and native_digest is None
            and native_prefix_digest is None
            and native_prefix_bytes is None
        )
        if (
            native_size is not None
            and native_size > NATIVE_RESULT_LIMIT
            and (native_digest is not None or (native_prefix_digest is None and not known_size_without_identity))
        ):
            raise ConformanceError("oversized native evidence must retain only a bounded identity")
        if native_summary is not None and (
            native_size is None
            or native_size > NATIVE_RESULT_LIMIT
            or native_digest is None
            or native_prefix_digest is not None
            or native_prefix_bytes is not None
        ):
            raise ConformanceError("parsed native results must retain their complete bounded identity")
        if known_size_without_identity and diagnostic.get("runner_blocked") is not True:
            raise ConformanceError(
                "native result sizes without an identity are only valid for unreadable infrastructure evidence"
            )
        if native_summary is not None:
            if not isinstance(native_summary, dict) or set(native_summary) != {
                "schema",
                "artifact_versions",
                "executed_distribution_identities",
                "scenario_statuses",
                "failure_projection",
                "local_product_source_checkout_used",
            }:
                raise ConformanceError("experiment result has an invalid native summary")
            if (
                len(native_summary["artifact_versions"]) > len(allowed_distributions)
                or len(native_summary["executed_distribution_identities"]) > len(allowed_distributions)
                or len(native_summary["scenario_statuses"]) > 128
            ):
                raise ConformanceError("experiment result has an unbounded native summary")
            summary_versions = native_summary["artifact_versions"]
            if (
                not isinstance(summary_versions, dict)
                or not set(summary_versions).issubset(allowed_distributions)
                or any(not isinstance(version, str) or len(version) > 128 for version in summary_versions.values())
            ):
                raise ConformanceError("experiment result has invalid native artifact versions")
            summary_identities = native_summary["executed_distribution_identities"]
            if not isinstance(summary_identities, dict) or not set(summary_identities).issubset(
                allowed_distributions
            ):
                raise ConformanceError("experiment result retains an unknown native distribution identity")
            for name, identity in summary_identities.items():
                identity_error = native_distribution_identity_structure_error(name, identity)
                if identity_error:
                    raise ConformanceError(identity_error)
            scenario_statuses = native_summary["scenario_statuses"]
            if not isinstance(scenario_statuses, list) or any(
                not isinstance(cell, dict)
                or set(cell) != {"id", "status"}
                or not isinstance(cell["id"], str)
                or not cell["id"]
                or len(cell["id"]) > 128
                or not isinstance(cell["status"], str)
                or len(cell["status"]) > 64
                for cell in scenario_statuses
            ):
                raise ConformanceError("experiment result has invalid native scenario statuses")
            if any(
                contains_sensitive_evidence_text(cell["id"]) or contains_sensitive_evidence_text(cell["status"])
                for cell in scenario_statuses
            ):
                raise ConformanceError("experiment result has unsanitized native scenario statuses")
            projection_error = native_failure_projection_error(native_summary["failure_projection"])
            if projection_error:
                raise ConformanceError(projection_error)
    validate_public_evidence_strings(result)
    if classification == "passed" and artifact_binding_failures(plan, required_distributions, diagnostics):
        raise ConformanceError("passing experiment result has incomplete or mismatched native artifact evidence")
    if contract is not None:
        validate_contract(contract)
        if sha256_bytes(canonical_json(contract)) != plan["runner"]["contract_sha256"]:
            raise ConformanceError("retained experiment contract does not match the plan binding")
        validate_retained_attempt_lifecycle(result, plan, contract)


def missing_experiment_summary(
    plan: dict[str, Any],
    experiment: str,
    owner: str,
    required_clients: list[str],
    required_distributions: list[str],
) -> dict[str, Any]:
    fingerprint = sha256_bytes(
        canonical_json(
            {
                "candidate_manifest_sha256": plan["candidate"]["manifest_sha256"],
                "candidate_verification_sha256": plan["candidate"]["verification_sha256"],
                "contract_sha256": plan["runner"]["contract_sha256"],
                "runtime_dependencies": plan["runtime_dependencies"],
                "experiment": experiment,
                "classification": "infrastructure_failure",
                "reason": "experiment result was not retained",
            }
        )
    )
    return {
        "outcome": "fail",
        "classification": "infrastructure_failure",
        "owning_contract": owner,
        "required_clients": required_clients,
        "required_distributions": required_distributions,
        "result_sha256": None,
        "failure_fingerprint": fingerprint,
    }


def aggregate_results(
    plan: dict[str, Any],
    contract: dict[str, Any],
    result_root: Path,
    *,
    run_id: int,
    run_attempt: int,
    source_candidate: str,
    source_head_sha: str,
    generated_at: str | None = None,
) -> tuple[dict[str, Any], dict[str, Path]]:
    validate_plan(plan)
    validate_contract(contract)
    if plan["candidate"]["name"] != source_candidate:
        raise ConformanceError("execution plan does not bind the source workflow candidate")
    if plan["runner"]["revision"] != source_head_sha:
        raise ConformanceError("execution plan does not bind the source workflow commit")
    if run_id < 1 or run_attempt < 1:
        raise ConformanceError("GitHub run identity must be positive")
    discovered: dict[str, tuple[dict[str, Any], Path]] = {}
    for path in result_root.rglob("experiment-result.json"):
        result = load_json(path)
        validate_experiment_result(result, plan, contract)
        experiment = result["experiment"]
        if experiment in discovered:
            raise ConformanceError(f"multiple retained results exist for experiment {experiment}")
        discovered[experiment] = (result, path)
    summaries: dict[str, Any] = {}
    retained_paths: dict[str, Path] = {}
    executed_distribution_identities: dict[str, dict[str, Any]] = {}
    for experiment in EXPERIMENTS:
        if experiment not in discovered:
            summaries[experiment] = missing_experiment_summary(
                plan,
                experiment,
                contract["experiments"][experiment]["owning_contract"],
                contract["experiments"][experiment]["required_clients"],
                contract["experiments"][experiment]["required_distributions"],
            )
            continue
        result, path = discovered[experiment]
        for diagnostic in result["diagnostics"]:
            native_summary = diagnostic.get("native_summary")
            if not isinstance(native_summary, dict):
                continue
            for name, identity in native_summary["executed_distribution_identities"].items():
                merged = executed_distribution_identities.setdefault(
                    name,
                    {"kind": identity["kind"], "locator": identity["locator"], "artifacts": []},
                )
                artifacts = {
                    artifact["name"]: artifact["sha256"] for artifact in [*merged["artifacts"], *identity["artifacts"]]
                }
                merged["artifacts"] = [
                    {"name": artifact_name, "sha256": artifacts[artifact_name]} for artifact_name in sorted(artifacts)
                ]
        summaries[experiment] = {
            "outcome": result["outcome"],
            "classification": result["classification"],
            "owning_contract": result["owning_contract"],
            "required_clients": result["required_clients"],
            "required_distributions": result["required_distributions"],
            "result_sha256": sha256_file(path),
            "failure_fingerprint": result["failure_fingerprint"],
        }
        retained_paths[experiment] = path
    outcome = "pass" if all(item["outcome"] == "pass" for item in summaries.values()) else "fail"
    if outcome == "pass" and set(executed_distribution_identities) != set(DISTRIBUTIONS):
        raise ConformanceError("passing suite does not retain every required executed distribution identity")
    evidence_tag = f"beta-conformance/{plan['candidate']['name']}/{run_id}.{run_attempt}"
    suite = {
        "schema": SUITE_RESULT_SCHEMA,
        "candidate": plan["candidate"],
        "artifact_tuple": plan["artifact_tuple"],
        "source_identities": plan["source_identities"],
        "distribution_identities": plan["distribution_identities"],
        "executed_distribution_identities": executed_distribution_identities,
        "runtime_dependencies": plan["runtime_dependencies"],
        "runner": plan["runner"],
        "server_runner": plan["server_runner"],
        "waterline_service_runner": plan["waterline_service_runner"],
        "source_policy": {
            "product_artifacts": "published_only",
            "orchestration_source": "bound_control_plane_and_exact_candidate_images",
            "local_product_source_checkout_used": False,
        },
        "github_run": {
            "repository": "durable-workflow/.github",
            "run_id": run_id,
            "run_attempt": run_attempt,
            "evidence_tag": evidence_tag,
        },
        "generated_at": github_timestamp(generated_at, "suite generation") if generated_at is not None else now(),
        "outcome": outcome,
        "experiments": summaries,
    }
    return suite, retained_paths


def write_github_output(path: Path | None, values: dict[str, str]) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as handle:
        for key, value in values.items():
            if "\n" in value or "\r" in value:
                raise ConformanceError(f"GitHub output {key} must be a single line")
            handle.write(f"{key}={value}\n")


def parser() -> argparse.ArgumentParser:
    arguments = argparse.ArgumentParser(description=__doc__)
    commands = arguments.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="validate the portable contract and JSON schemas")
    validate.add_argument("contract", type=Path)
    validate.add_argument("schemas", nargs="*", type=Path)

    prepare = commands.add_parser("prepare", help="bind an immutable candidate to this runner revision")
    prepare.add_argument("manifest", type=Path)
    prepare.add_argument("output", type=Path)
    prepare.add_argument("--contract", type=Path, required=True)
    prepare.add_argument("--repository", type=Path, default=Path("."))
    prepare.add_argument("--runner-revision", required=True)
    prepare.add_argument("--docker", default="docker")
    prepare.add_argument("--github-output", type=Path)

    restore = commands.add_parser("restore-plan", help="validate and reuse a retained first-attempt plan")
    restore.add_argument("plan", type=Path)
    restore.add_argument("manifest", type=Path)
    restore.add_argument("--contract", type=Path, required=True)
    restore.add_argument("--runner-revision", required=True)
    restore.add_argument("--github-output", type=Path)

    extract = commands.add_parser("extract", help="extract conformance orchestration from the exact server image")
    extract.add_argument("plan", type=Path)
    extract.add_argument("output", type=Path)
    extract.add_argument("extraction_record", type=Path)
    extract.add_argument("--docker", default="docker")

    run = commands.add_parser("run", help="run one isolated experiment")
    run.add_argument("plan", type=Path)
    run.add_argument("experiment", choices=EXPERIMENTS)
    run.add_argument("artifact_root", type=Path)
    run.add_argument("result_dir", type=Path)
    run.add_argument("--contract", type=Path, required=True)
    run.add_argument("--inject-product-failure", action="store_true")
    run.add_argument("--inject-identity-failure", action="store_true")

    aggregate = commands.add_parser("aggregate", help="aggregate retained matrix evidence")
    aggregate.add_argument("plan", type=Path)
    aggregate.add_argument("result_root", type=Path)
    aggregate.add_argument("output", type=Path)
    aggregate.add_argument("asset_dir", type=Path)
    aggregate.add_argument("--contract", type=Path, required=True)
    aggregate.add_argument("--run-id", type=int, required=True)
    aggregate.add_argument("--run-attempt", type=int, required=True)
    aggregate.add_argument("--source-candidate", required=True)
    aggregate.add_argument("--source-head-sha", required=True)
    aggregate.add_argument("--generated-at")
    aggregate.add_argument("--github-output", type=Path)

    retention = commands.add_parser("retention-source", help="validate a completed conformance run")
    retention.add_argument("--expected-run-id", type=int, required=True)
    retention.add_argument("--expected-run-attempt", type=int, required=True)
    retention.add_argument("--github-output", type=Path)

    retention_ref = commands.add_parser("retention-ref", help="validate the durable conformance evidence ref")
    retention_ref.add_argument("ref", type=Path)
    retention_ref.add_argument("comparison", type=Path)
    retention_ref.add_argument("--expected-tag", required=True)
    retention_ref.add_argument("--source-sha", required=True)
    retention_ref.add_argument("--controller-sha", required=True)
    return arguments


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "validate":
            load_contract(arguments.contract)
            for schema in arguments.schemas:
                value = load_json(schema, limit=512 * 1024)
                if (
                    not isinstance(value, dict)
                    or value.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
                ):
                    raise ConformanceError(f"schema is not JSON Schema draft 2020-12: {schema}")
            return 0
        if arguments.command == "prepare":
            manifest = load_manifest(arguments.manifest)
            contract = load_contract(arguments.contract)
            runtime_dependencies = resolve_runtime_dependencies(contract, docker=arguments.docker)
            plan = prepare_plan(
                arguments.repository,
                manifest,
                contract,
                arguments.runner_revision,
                runtime_dependencies,
            )
            write_json(arguments.output, plan)
            write_github_output(arguments.github_output, plan_github_outputs(plan))
            return 0
        if arguments.command == "restore-plan":
            plan = restore_plan(
                load_plan(arguments.plan),
                load_manifest(arguments.manifest),
                load_contract(arguments.contract),
                arguments.runner_revision,
            )
            write_github_output(arguments.github_output, plan_github_outputs(plan))
            return 0
        if arguments.command == "extract":
            extract_runner(load_plan(arguments.plan), arguments.output, arguments.extraction_record, arguments.docker)
            return 0
        if arguments.command == "run":
            plan = load_plan(arguments.plan)
            result = run_experiment(
                plan,
                load_contract(arguments.contract),
                arguments.experiment,
                arguments.artifact_root,
                arguments.result_dir,
                inject_product_failure=arguments.inject_product_failure,
                inject_identity_failure=arguments.inject_identity_failure,
            )
            print(json.dumps({"experiment": arguments.experiment, "outcome": result["outcome"]}, sort_keys=True))
            return 0 if result["outcome"] == "pass" else 1
        if arguments.command == "aggregate":
            plan = load_plan(arguments.plan)
            suite, retained = aggregate_results(
                plan,
                load_contract(arguments.contract),
                arguments.result_root,
                run_id=arguments.run_id,
                run_attempt=arguments.run_attempt,
                source_candidate=arguments.source_candidate,
                source_head_sha=arguments.source_head_sha,
                generated_at=arguments.generated_at,
            )
            write_json(arguments.output, suite)
            arguments.asset_dir.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(arguments.output, arguments.asset_dir / "suite-result.json")
            for experiment, path in retained.items():
                shutil.copyfile(path, arguments.asset_dir / f"{experiment}.json")
            write_github_output(
                arguments.github_output,
                {
                    "candidate": plan["candidate"]["name"],
                    "evidence_tag": suite["github_run"]["evidence_tag"],
                    "outcome": suite["outcome"],
                },
            )
            print(json.dumps({"evidence_tag": suite["github_run"]["evidence_tag"], "outcome": suite["outcome"]}))
            return 0
        if arguments.command == "retention-source":
            run, workflow = fetch_retention_source_metadata(
                arguments.expected_run_id,
                arguments.expected_run_attempt,
                os.environ.get("GH_TOKEN", ""),
            )
            source = validate_retention_source(
                run,
                workflow,
                expected_run_id=arguments.expected_run_id,
                expected_run_attempt=arguments.expected_run_attempt,
            )
            write_github_output(
                arguments.github_output,
                {name: str(value) for name, value in source.items()},
            )
            print(json.dumps(source, sort_keys=True))
            return 0
        if arguments.command == "retention-ref":
            ref = validate_retention_ref(
                load_json(arguments.ref),
                load_json(arguments.comparison),
                expected_tag=arguments.expected_tag,
                source_sha=arguments.source_sha,
                controller_sha=arguments.controller_sha,
            )
            print(json.dumps(ref, sort_keys=True))
            return 0
    except (CandidateError, ConformanceError, OSError) as error:
        print(f"beta conformance error: {error}", file=sys.stderr)
        return 2
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
