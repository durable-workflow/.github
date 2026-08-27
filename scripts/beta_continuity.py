#!/usr/bin/env python3
"""Drive the workspace-unavailable beta continuity drill from GitHub authority."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.beta_candidate import (
    COMPONENTS,
    VERSION_PATTERN,
    CandidateError,
    PublicClient,
    canonical_json,
    fetch_existing_record,
    manifest_digest,
    read_record_file,
    resolve_github_tag,
    run_git,
    validate_recorded_verification,
    write_github_output,
)
from scripts.beta_conformance import (
    EXPERIMENTS as CONFORMANCE_EXPERIMENTS,
)
from scripts.beta_conformance import (
    LEGACY_PLAN_SCHEMA,
    LEGACY_SUITE_RESULT_SCHEMA,
    ConformanceError,
    validate_public_evidence_strings,
    validate_recorded_experiment_result,
    validate_recorded_plan,
)
from scripts.beta_conformance import (
    PLAN_SCHEMA as CONFORMANCE_PLAN_SCHEMA,
)
from scripts.beta_conformance import (
    SUITE_RESULT_SCHEMA as CONFORMANCE_SUITE_RESULT_SCHEMA,
)
from scripts.release_plan import (
    CONTINUITY_RESOLUTION_SCHEMA,
    EXPECTED_DEFAULT_BRANCHES,
    FOUNDATION_COMMIT,
    FOUNDATION_TAG,
    PLAN_TAG_PREFIX,
    candidate_manifest,
    continuity_resolution_tag,
    discover_plan,
    read_public_record,
    resolve_tag,
    validate_continuity_resolution_authority,
    validate_plan,
)
from scripts.release_plan import (
    LEGACY_SCHEMA as LEGACY_RELEASE_PLAN_SCHEMA,
)
from scripts.release_plan import (
    SCHEMA as RELEASE_PLAN_SCHEMA,
)
from scripts.release_plan import (
    validate_recorded_plan as validate_recorded_release_plan,
)

SCHEMA = "durable-workflow.beta-continuity.config/v1"
EVIDENCE_SCHEMA = "durable-workflow.beta-continuity.evidence/v1"
SELECTION_SCHEMA = "durable-workflow.beta-continuity.selection/v1"
CONTROL_REPOSITORY = "durable-workflow/.github"
PHASE_TAG_PREFIX = "beta-continuity/"
SELECTION_TAG_PREFIX = "beta-continuity-selection/"
RELEASE_WORKFLOW = "release-plan.yml"
CONTINUITY_WORKFLOW = "beta-continuity.yml"
OBSERVER_WORKFLOW = "release-plan-observer.yml"
CANDIDATE_WORKFLOW = "beta-candidate.yml"
BETA_CANDIDATE_WORKFLOW_NAME = "Beta candidate"
BETA_CANDIDATE_WORKFLOW_PATH = f".github/workflows/{CANDIDATE_WORKFLOW}"
CONFORMANCE_WORKFLOW = "beta-conformance.yml"
CONFORMANCE_RETENTION_WORKFLOW = "beta-conformance-retention.yml"
CONTINUITY_RESOLUTION_SELECTION_SCHEMA = (
    "durable-workflow.release-plan-continuity-resolution-selection/v1"
)
WORK_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")
BETA_WORK_ID_MARKER_PREFIX = "<!-- beta-work-id: "
BETA_WORK_ID_MARKER = re.compile(r"<!-- beta-work-id: (?P<work_id>[a-z0-9][a-z0-9._-]{0,79}) -->")
DURABLE_WORK_ID_MARKER_PREFIX = "<!-- durable-workflow-work-id: "
DURABLE_WORK_ID_MARKER = re.compile(r"<!-- durable-workflow-work-id: (?P<work_id>[a-z0-9][a-z0-9._-]{0,79}) -->")
PLAN_PREFIX_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,35}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
PUBLIC_REPOSITORY_PATTERN = re.compile(r"^durable-workflow/[A-Za-z0-9._-]+$")
STABLE_VERSION_PATTERN = re.compile(r"^(0\.[0-9]+\.)([0-9]+)$")
ALPHA_VERSION_PATTERN = re.compile(r"^(2\.0\.0-alpha\.)([1-9][0-9]*)$")
SOURCE_MANIFESTS = {
    "sdk-python": ("pyproject.toml", "project", "durable-workflow"),
    "sdk-rust": ("Cargo.toml", "package", "durable-workflow"),
}
PHASES = (
    "accepted",
    "interrupted",
    "resumed",
    "conformance-requested",
    "complete",
    "no-op-confirmed",
)
ROUTED_BLOCKER_AUTHORITY_LABELS = (
    "authority:github",
    "beta:blocker",
    "kind:release-blocker",
    "priority:P1",
)
ROUTED_BLOCKER_LIFECYCLE_LABELS = {"status:ready", "status:done"}
ROUTED_BLOCKER_LABELS = (
    *ROUTED_BLOCKER_AUTHORITY_LABELS,
    "status:ready",
)
ISSUE_KIND_LABELS = {"kind:defect", "kind:feature", "kind:release-blocker", "kind:cross-repository"}
ROUTED_BLOCKER_MARKER = re.compile(
    r"<!-- beta-continuity-blocker: "
    r"(?P<component>[a-z0-9][a-z0-9-]*)-(?P<reason>source-version|occupied-version)-"
    r"(?P<version>[^ ]+) -->"
)
ROUTED_BLOCKER_MARKER_PREFIX = "<!-- beta-continuity-blocker: "
QUALIFICATION_EVIDENCE_SCHEMA = "durable-workflow.github-target-qualification/v1"
GITHUB_RELEASE_PAGE_SIZE = 100
GITHUB_RELEASE_PAGE_LIMIT = 100


class ContinuityError(RuntimeError):
    """The public continuity drill cannot safely advance."""


class PlanBlocked(ContinuityError):
    """The next public release plan has focused component blockers."""

    def __init__(self, blockers: list[dict[str, str]]) -> None:
        self.blockers = blockers
        super().__init__("; ".join(blocker["reason"] for blocker in blockers))


def replace_issue_kind(labels: set[str], kind: str, location: str) -> set[str]:
    """Replace an incompatible kind at an issue writer boundary."""

    if kind not in ISSUE_KIND_LABELS:
        raise ContinuityError(f"{location} requested an unsupported issue kind {kind!r}")
    replacement = {label for label in labels if not label.startswith("kind:")}
    replacement.add(kind)
    return replacement


def require_exact_issue_kind(labels: set[str], location: str) -> str:
    kinds = {label for label in labels if label.startswith("kind:")}
    if len(kinds) != 1 or not kinds <= ISSUE_KIND_LABELS:
        raise ContinuityError(f"{location} must write exactly one supported kind:* label, got {sorted(kinds)}")
    return next(iter(kinds))


class GitHubWriter:
    """Small bounded client for authenticated GitHub mutations and run discovery."""

    def __init__(self, token: str, api_url: str = "https://api.github.com") -> None:
        if not token:
            raise ContinuityError("GitHub continuity authority token is unavailable")
        self.api_url = api_url.rstrip("/")
        self.headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "durable-workflow-beta-continuity/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def request(self, method: str, path: str, payload: Any | None = None) -> Any:
        if (
            method in {"PATCH", "POST"}
            and re.fullmatch(r"/repos/.+/issues(?:/[1-9][0-9]*)?", path)
            and isinstance(payload, dict)
            and isinstance(payload.get("labels"), list)
        ):
            require_exact_issue_kind(set(payload["labels"]), f"GitHub issue writer {path}")
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
            detail = error.read(4096).decode(errors="replace")
            raise ContinuityError(f"GitHub {method} {path} failed ({error.code}): {detail}") from error
        except urllib.error.URLError as error:
            raise ContinuityError(f"GitHub {method} {path} failed: {error.reason}") from error
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as error:
            raise ContinuityError(f"GitHub {method} {path} returned invalid JSON") from error

    def get(self, path: str) -> Any:
        return self.request("GET", path)

    def list(self, path: str) -> list[dict[str, Any]]:
        records: list[dict[str, Any]] = []
        separator = "&" if "?" in path else "?"
        for page in range(1, 11):
            payload = self.get(f"{path}{separator}per_page=100&page={page}")
            if not isinstance(payload, list):
                raise ContinuityError(f"GitHub collection {path} has an invalid shape")
            records.extend(payload)
            if len(payload) < 100:
                return records
        raise ContinuityError(f"GitHub collection {path} exceeded the pagination bound")

    def dispatch(self, repository: str, workflow: str, ref: str, inputs: dict[str, str]) -> None:
        encoded = urllib.parse.quote(workflow, safe="")
        self.request(
            "POST",
            f"/repos/{repository}/actions/workflows/{encoded}/dispatches",
            {"ref": ref, "inputs": inputs},
        )


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def load_json(path: Path, label: str) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContinuityError(f"cannot read {label} {path}: {error}") from error


def validate_resolution_source(
    run: Any,
    workflow: Any,
    *,
    expected_run_id: int,
    expected_run_attempt: int,
) -> dict[str, Any]:
    if (
        not isinstance(workflow, dict)
        or type(workflow.get("id")) is not int
        or workflow["id"] < 1
        or workflow.get("name") != BETA_CANDIDATE_WORKFLOW_NAME
        or workflow.get("path") != BETA_CANDIDATE_WORKFLOW_PATH
        or workflow.get("state") != "active"
    ):
        raise ContinuityError("trusted Beta candidate workflow metadata is invalid")
    if not isinstance(run, dict):
        raise ContinuityError("continuity resolution qualification is absent")
    repository = run.get("repository")
    head_repository = run.get("head_repository")
    if (
        type(run.get("id")) is not int
        or run.get("id") != expected_run_id
        or type(run.get("run_attempt")) is not int
        or run.get("run_attempt") != expected_run_attempt
        or not isinstance(repository, dict)
        or repository.get("full_name") != CONTROL_REPOSITORY
        or not isinstance(head_repository, dict)
        or head_repository.get("full_name") != CONTROL_REPOSITORY
        or run.get("workflow_id") != workflow["id"]
        or run.get("path")
        not in {
            BETA_CANDIDATE_WORKFLOW_PATH,
            f"{BETA_CANDIDATE_WORKFLOW_PATH}@main",
            f"{BETA_CANDIDATE_WORKFLOW_PATH}@refs/heads/main",
        }
        or run.get("event") != "push"
        or run.get("head_branch") != "main"
    ):
        raise ContinuityError("continuity resolution qualification is from an untrusted workflow")
    head_sha = run.get("head_sha")
    if not isinstance(head_sha, str) or not COMMIT_PATTERN.fullmatch(head_sha):
        raise ContinuityError("continuity resolution qualification has an invalid source revision")
    if run.get("status") != "completed":
        raise ContinuityError("continuity resolution qualification is pending")
    if run.get("conclusion") == "cancelled":
        raise ContinuityError("continuity resolution qualification was cancelled")
    if run.get("conclusion") != "success":
        raise ContinuityError("continuity resolution qualification failed")
    return {
        "repository": CONTROL_REPOSITORY,
        "workflow": BETA_CANDIDATE_WORKFLOW_PATH,
        "event": "push",
        "head_branch": "main",
        "head_sha": head_sha,
        "run_id": expected_run_id,
        "run_attempt": expected_run_attempt,
        "status": "completed",
        "conclusion": "success",
    }


def qualified_resolution_source(
    expected_run_id: int,
    expected_run_attempt: int,
    token: str,
) -> dict[str, Any]:
    if expected_run_id < 1 or expected_run_attempt < 1:
        raise ContinuityError("continuity resolution qualification identity must be positive")
    writer = GitHubWriter(token, os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    run = writer.get(
        f"/repos/{CONTROL_REPOSITORY}/actions/runs/{expected_run_id}/"
        f"attempts/{expected_run_attempt}"
    )
    workflow = writer.get(
        f"/repos/{CONTROL_REPOSITORY}/actions/workflows/{CANDIDATE_WORKFLOW}"
    )
    return validate_resolution_source(
        run,
        workflow,
        expected_run_id=expected_run_id,
        expected_run_attempt=expected_run_attempt,
    )


def resolution_source_command(
    expected_run_id: int,
    expected_run_attempt: int,
    output: Path | None,
) -> dict[str, Any]:
    source = qualified_resolution_source(
        expected_run_id,
        expected_run_attempt,
        os.environ.get("GH_TOKEN", ""),
    )
    write_github_output(
        output,
        {
            "source_head_sha": source["head_sha"],
            "source_run_attempt": str(source["run_attempt"]),
            "source_run_id": str(source["run_id"]),
        },
    )
    return source


def load_config(path: Path) -> dict[str, Any]:
    value = load_json(path, "continuity config")
    if not isinstance(value, dict) or set(value) != {
        "$schema",
        "authority_issue",
        "channel",
        "drill",
        "evidence_work_items",
        "first_component",
        "plan_prefix",
        "public_issue_budget",
        "required_issue_labels",
        "superseded_interruption",
    }:
        raise ContinuityError("continuity config has an invalid top-level shape")
    if value.get("$schema") != "./schema.json" or value.get("channel") != "alpha":
        raise ContinuityError("continuity config must select the alpha prerelease channel and local schema")
    if not isinstance(value.get("drill"), str) or not WORK_ID_PATTERN.fullmatch(value["drill"]):
        raise ContinuityError("continuity drill has an invalid identity")
    issue = value.get("authority_issue")
    if not isinstance(issue, dict) or set(issue) != {"number", "repository", "work_id"}:
        raise ContinuityError("continuity authority issue has an invalid shape")
    if (
        issue.get("repository") != CONTROL_REPOSITORY
        or type(issue.get("number")) is not int
        or issue["number"] < 1
        or not isinstance(issue.get("work_id"), str)
        or not WORK_ID_PATTERN.fullmatch(issue["work_id"])
    ):
        raise ContinuityError("continuity authority issue is invalid")
    work_items = value.get("evidence_work_items")
    if not isinstance(work_items, list) or not work_items:
        raise ContinuityError("continuity evidence work items are invalid")
    work_item_locations: set[tuple[str, int]] = set()
    for work_item in work_items:
        if (
            not isinstance(work_item, dict)
            or set(work_item) != {"number", "repository", "required_labels", "work_id"}
            or not isinstance(work_item.get("repository"), str)
            or not PUBLIC_REPOSITORY_PATTERN.fullmatch(work_item["repository"])
            or type(work_item.get("number")) is not int
            or work_item["number"] < 1
            or not isinstance(work_item.get("work_id"), str)
            or not WORK_ID_PATTERN.fullmatch(work_item["work_id"])
            or not isinstance(work_item.get("required_labels"), list)
            or not all(isinstance(label, str) and label for label in work_item["required_labels"])
            or len(set(work_item["required_labels"])) != len(work_item["required_labels"])
            or not {
                "authority:github",
                "beta:blocker",
                "completion:evidence-required",
                "status:ready",
            }
            <= set(work_item["required_labels"])
        ):
            raise ContinuityError("continuity evidence work item authority is invalid")
        require_exact_issue_kind(
            set(work_item["required_labels"]),
            f"continuity evidence work item {work_item['repository']}#{work_item['number']}",
        )
        location = (work_item["repository"], work_item["number"])
        if location in work_item_locations or location == (issue["repository"], issue["number"]):
            raise ContinuityError("continuity evidence work item inventory contains a duplicate authority")
        work_item_locations.add(location)
    if not isinstance(value.get("plan_prefix"), str) or not PLAN_PREFIX_PATTERN.fullmatch(value["plan_prefix"]):
        raise ContinuityError("continuity plan prefix has an invalid identity")
    budget = value.get("public_issue_budget")
    if budget != {"max_open_actionable": 1, "stale_age_seconds": 604800}:
        raise ContinuityError("continuity public issue budget is invalid")
    if value.get("first_component") not in COMPONENTS:
        raise ContinuityError("continuity first component is unknown")
    labels = value.get("required_issue_labels")
    if not isinstance(labels, list) or not labels or not all(isinstance(label, str) and label for label in labels):
        raise ContinuityError("continuity required issue labels are invalid")
    require_exact_issue_kind(set(labels), "continuity parent authority")
    superseded = value.get("superseded_interruption")
    if (
        not isinstance(superseded, dict)
        or set(superseded) != {"reason", "tag"}
        or not isinstance(superseded.get("reason"), str)
        or not WORK_ID_PATTERN.fullmatch(superseded["reason"])
        or not isinstance(superseded.get("tag"), str)
        or not superseded["tag"].startswith(PHASE_TAG_PREFIX)
        or not superseded["tag"].endswith("/interrupted")
    ):
        raise ContinuityError("superseded continuity interruption is invalid")
    return value


def optional_public_json(client: PublicClient, url: str) -> Any | None:
    try:
        return client.json(url)
    except CandidateError as error:
        if "(404)" in str(error):
            return None
        raise


def has_exact_work_id(issue: dict[str, Any], work_id: str) -> bool:
    body = str(issue.get("body", ""))
    return body.count(BETA_WORK_ID_MARKER_PREFIX) == 1 and BETA_WORK_ID_MARKER.findall(body) == [work_id]


def has_exact_durable_work_id(issue: dict[str, Any], work_id: str) -> bool:
    body = str(issue.get("body", ""))
    return body.count(DURABLE_WORK_ID_MARKER_PREFIX) == 1 and DURABLE_WORK_ID_MARKER.findall(body) == [work_id]


def authority_issue(config: dict[str, Any], client: PublicClient, *, allow_completed: bool = False) -> dict[str, Any]:
    specification = config["authority_issue"]
    issue = client.json(f"https://api.github.com/repos/{specification['repository']}/issues/{specification['number']}")
    labels = {label.get("name") for label in issue.get("labels", []) if isinstance(label, dict) and label.get("name")}
    missing = set(config["required_issue_labels"]) - labels
    exact_work_id = has_exact_work_id(issue, specification["work_id"])
    required_authority = {
        label
        for label in config["required_issue_labels"]
        if not label.startswith("status:") and not label.startswith("completion:")
    }
    completed = (
        allow_completed
        and issue.get("state") == "closed"
        and required_authority <= labels
        and {"status:done", "completion:evidence-verified"} <= labels
    )
    if (issue.get("state") != "open" and not completed) or (missing and not completed) or not exact_work_id:
        raise ContinuityError(
            f"authority issue is not ready: state={issue.get('state')}, missing_labels={sorted(missing)}, "
            f"work_id_marker={exact_work_id}"
        )
    return {
        "number": specification["number"],
        "repository": specification["repository"],
        "url": issue.get("html_url"),
        "labels": sorted(labels),
        "state": issue["state"],
        "updated_at": issue.get("updated_at"),
        "work_id": specification["work_id"],
    }


def parse_manifest_version(component: str, raw: bytes) -> str:
    path, table, package = SOURCE_MANIFESTS[component]
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ContinuityError(f"{component} {path} is not valid TOML: {error}") from error
    section = document.get(table)
    if not isinstance(section, dict) or section.get("name") != package:
        raise ContinuityError(f"{component} {path} does not declare {package} in [{table}]")
    version = section.get("version")
    if not isinstance(version, str):
        raise ContinuityError(f"{component} {path} has no exact package version")
    return version


def next_version(component: str, tags: list[str]) -> str:
    pattern = ALPHA_VERSION_PATTERN if component in {"workflow", "waterline"} else STABLE_VERSION_PATTERN
    matches = [match for tag in tags if (match := pattern.fullmatch(tag))]
    if not matches:
        raise ContinuityError(f"{component} has no public version baseline")
    latest = max(matches, key=lambda match: int(match.group(2)))
    return f"{latest.group(1)}{int(latest.group(2)) + 1}"


def public_releases(client: PublicClient, repository: str) -> list[dict[str, Any]]:
    endpoint = f"https://api.github.com/repos/{repository}/releases"
    releases: list[dict[str, Any]] = []
    full_page_digests: set[str] = set()
    seen_tags: set[str] = set()
    for page in range(1, GITHUB_RELEASE_PAGE_LIMIT + 1):
        page_releases = client.json(f"{endpoint}?per_page={GITHUB_RELEASE_PAGE_SIZE}&page={page}")
        if (
            not isinstance(page_releases, list)
            or len(page_releases) > GITHUB_RELEASE_PAGE_SIZE
            or any(
                not isinstance(release, dict)
                or not isinstance(release.get("tag_name"), str)
                or not release["tag_name"]
                or type(release.get("draft")) is not bool
                for release in page_releases
            )
        ):
            raise ContinuityError(f"{repository} releases response page {page} is invalid")
        page_tags = {release["tag_name"] for release in page_releases}
        if len(page_tags) != len(page_releases) or seen_tags & page_tags:
            raise ContinuityError(f"{repository} release pagination did not advance")
        seen_tags.update(page_tags)
        releases.extend(page_releases)
        if len(page_releases) < GITHUB_RELEASE_PAGE_SIZE:
            return releases
        page_digest = hashlib.sha256(canonical_json(page_releases)).hexdigest()
        if page_digest in full_page_digests:
            raise ContinuityError(f"{repository} release pagination did not advance")
        full_page_digests.add(page_digest)
    raise ContinuityError(f"{repository} release history exceeded the pagination bound")


def public_release_tags(client: PublicClient, repository: str) -> list[str]:
    return [release["tag_name"] for release in public_releases(client, repository) if not release["draft"]]


def require_unoccupied_fresh_versions(client: PublicClient, versions: dict[str, str]) -> None:
    for name, component in COMPONENTS.items():
        version = versions[name]
        encoded = urllib.parse.quote(version, safe="")
        tag = optional_public_json(
            client,
            f"https://api.github.com/repos/{component.repository}/git/ref/tags/{encoded}",
        )
        release = optional_public_json(
            client,
            f"https://api.github.com/repos/{component.repository}/releases/tags/{encoded}",
        )
        occupied_by = [label for label, record in (("tag", tag), ("release", release)) if record is not None]
        if occupied_by:
            raise ContinuityError(
                f"fresh continuity version {component.repository}@{version} is already occupied by public "
                f"{' and '.join(occupied_by)} authority"
            )


def has_routed_blocker_authority(issue: dict[str, Any]) -> bool:
    labels = issue.get("labels")
    if not isinstance(labels, list):
        return False
    names: set[str] = set()
    for label in labels:
        if not isinstance(label, dict) or not isinstance(label.get("name"), str) or not label["name"]:
            return False
        names.add(label["name"])
    lifecycle = {name for name in names if name.startswith("status:")}
    return (
        set(ROUTED_BLOCKER_AUTHORITY_LABELS) <= names
        and len(lifecycle) == 1
        and lifecycle <= ROUTED_BLOCKER_LIFECYCLE_LABELS
    )


def is_exact_routed_blocker(
    config: dict[str, Any],
    issue: dict[str, Any],
    component_name: str,
    version: str,
) -> bool:
    body = issue.get("body")
    if not isinstance(body, str) or not has_routed_blocker_dependency(config, issue):
        return False
    markers = list(ROUTED_BLOCKER_MARKER.finditer(body))
    return (
        body.count(ROUTED_BLOCKER_MARKER_PREFIX) == 1
        and len(markers) == 1
        and markers[0].group("component") == component_name
        and markers[0].group("version") == version
        and VERSION_PATTERN.fullmatch(version) is not None
    )


def has_routed_blocker_dependency(config: dict[str, Any], issue: dict[str, Any]) -> bool:
    authority = config["authority_issue"]
    dependency = f"Blocks https://github.com/{authority['repository']}/issues/{authority['number']}."
    return dependency in str(issue.get("body", ""))


def selection_plan_name(config: dict[str, Any], versions: dict[str, str]) -> str:
    digest = hashlib.sha256(canonical_json(versions)).hexdigest()[:12]
    return f"{config['plan_prefix']}-{digest}"


def validate_selection(config: dict[str, Any], selection: Any) -> None:
    expected_keys = {"schema", "drill", "plan", "channel", "versions"}
    if not isinstance(selection, dict) or set(selection) != expected_keys:
        raise ContinuityError("continuity selection has an invalid top-level shape")
    if (
        selection.get("schema") != SELECTION_SCHEMA
        or selection.get("drill") != config["drill"]
        or selection.get("channel") != config["channel"]
    ):
        raise ContinuityError("continuity selection does not match this drill")
    versions = selection.get("versions")
    if not isinstance(versions, dict) or set(versions) != set(COMPONENTS):
        raise ContinuityError(f"continuity selection versions must be exactly {sorted(COMPONENTS)}")
    for name, version in versions.items():
        pattern = ALPHA_VERSION_PATTERN if name in {"workflow", "waterline"} else STABLE_VERSION_PATTERN
        if not isinstance(version, str) or not pattern.fullmatch(version):
            raise ContinuityError(f"continuity selection version for {name} is invalid")
    if selection.get("plan") != selection_plan_name(config, versions):
        raise ContinuityError("continuity selection plan identity does not match its version tuple")


def select_versions(config: dict[str, Any], client: PublicClient) -> dict[str, Any]:
    versions = {
        name: next_version(name, public_release_tags(client, component.repository))
        for name, component in COMPONENTS.items()
    }
    selection = {
        "schema": SELECTION_SCHEMA,
        "drill": config["drill"],
        "plan": selection_plan_name(config, versions),
        "channel": config["channel"],
        "versions": versions,
    }
    validate_selection(config, selection)
    require_unoccupied_fresh_versions(client, versions)
    return selection


def selection_tag(config: dict[str, Any]) -> str:
    return f"{SELECTION_TAG_PREFIX}{config['drill']}"


def public_selection(config: dict[str, Any], client: PublicClient) -> tuple[dict[str, Any], dict[str, str]] | None:
    tag = selection_tag(config)
    commit = resolve_tag(client, CONTROL_REPOSITORY, tag)
    if commit is None:
        return None
    selection = read_public_json_file(client, commit, "continuity-selection.json")
    validate_selection(config, selection)
    return selection, {"tag": tag, "commit": commit, "sha256": manifest_digest(selection)}


def build_plan(
    config: dict[str, Any],
    client: PublicClient,
    selection: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, str]]:
    selection = selection or select_versions(config, client)
    validate_selection(config, selection)
    components: dict[str, dict[str, str]] = {}
    expected_commits: dict[str, str] = {}
    blockers: list[dict[str, str]] = []
    for name, component in COMPONENTS.items():
        version = selection["versions"][name]
        commit = resolve_tag(client, component.repository, version)
        if commit is None:
            branch = EXPECTED_DEFAULT_BRANCHES[name]
            branch_record = client.json(
                f"https://api.github.com/repos/{component.repository}/branches/{urllib.parse.quote(branch, safe='')}"
            )
            commit = branch_record.get("commit", {}).get("sha")
        if not isinstance(commit, str) or not COMMIT_PATTERN.fullmatch(commit):
            raise ContinuityError(f"{component.repository}@{version} did not resolve to an exact source commit")
        if name in SOURCE_MANIFESTS:
            path, _table, _package = SOURCE_MANIFESTS[name]
            encoded_path = urllib.parse.quote(path, safe="/")
            raw = client.bytes(
                f"https://api.github.com/repos/{component.repository}/contents/{encoded_path}?ref={commit}",
                accept="application/vnd.github.raw+json",
            )
            declared = parse_manifest_version(name, raw)
            if declared != version:
                blockers.append(
                    {
                        "component": name,
                        "reason": (
                            f"{component.repository}@{commit} declares {declared} in {path}; "
                            f"the retained continuity version is {version}"
                        ),
                        "repository": component.repository,
                        "slug": f"{name}-source-version-{version}",
                        "version": version,
                    }
                )
        components[name] = {"commit": commit, "version": version}
        expected_commits[name] = commit
    if blockers:
        raise PlanBlocked(blockers)
    plan = {
        "schema": RELEASE_PLAN_SCHEMA,
        "plan": selection["plan"],
        "channel": config["channel"],
        "foundation": {"tag": FOUNDATION_TAG, "commit": FOUNDATION_COMMIT},
        "components": components,
        "beta_authorization": None,
    }
    validate_plan(plan)
    return plan, expected_commits


def phase_tag(plan: dict[str, Any], phase: str) -> str:
    if phase not in PHASES:
        raise ContinuityError(f"unknown continuity phase {phase}")
    return f"{PHASE_TAG_PREFIX}{plan['plan']}/{phase}"


def read_public_json_file(client: PublicClient, commit: str, filename: str) -> Any:
    encoded = urllib.parse.quote(filename, safe="/")
    raw = client.bytes(
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/contents/{encoded}?ref={commit}",
        accept="application/vnd.github.raw+json",
    )
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise ContinuityError(f"{CONTROL_REPOSITORY}@{commit}:{filename} is not valid JSON") from error


def superseded_interruption(config: dict[str, Any], client: PublicClient) -> dict[str, str]:
    specification = config["superseded_interruption"]
    tag = specification["tag"]
    commit = resolve_tag(client, CONTROL_REPOSITORY, tag)
    if commit is None:
        raise ContinuityError(f"superseded interruption {tag} is not retained")
    evidence = read_public_json_file(client, commit, "continuity-evidence.json")
    plan = read_public_json_file(client, commit, "release-plan.json")
    validate_recorded_release_plan(plan)
    if evidence.get("phase") != "interrupted" or phase_tag(plan, "interrupted") != tag:
        raise ContinuityError(f"superseded interruption {tag} has invalid diagnostic evidence")
    return {
        "commit": commit,
        "evidence_sha256": manifest_digest(evidence),
        "plan_sha256": manifest_digest(plan),
        "reason": specification["reason"],
        "tag": tag,
    }


def accepted_plan(config: dict[str, Any], client: PublicClient) -> dict[str, Any] | None:
    prefix = f"{PHASE_TAG_PREFIX}{config['plan_prefix']}-"
    encoded = urllib.parse.quote(prefix, safe="/")
    refs = client.json(f"https://api.github.com/repos/{CONTROL_REPOSITORY}/git/matching-refs/tags/{encoded}")
    accepted = [ref for ref in refs if str(ref.get("ref", "")).endswith("/accepted")]
    if len(accepted) > 1:
        raise ContinuityError("multiple accepted continuity plans exist for this drill")
    if not accepted:
        return None
    commit = accepted[0].get("object", {}).get("sha")
    if not isinstance(commit, str) or not COMMIT_PATTERN.fullmatch(commit):
        raise ContinuityError("accepted continuity phase does not resolve to a commit")
    plan = read_public_json_file(client, commit, "release-plan.json")
    validate_recorded_release_plan(plan)
    return plan


def plan_command(
    config_path: Path,
    plan_path: Path,
    expected_path: Path,
    state_path: Path,
    output: Path | None,
    expected_plan_tag: str | None = None,
) -> None:
    config = load_config(config_path)
    client = PublicClient(os.environ.get("GITHUB_TOKEN"))
    issue = authority_issue(config, client, allow_completed=True)
    accepted = accepted_plan(config, client)
    if expected_plan_tag:
        actual_plan_tag = f"{PLAN_TAG_PREFIX}{accepted['plan']}" if accepted is not None else None
        if actual_plan_tag != expected_plan_tag:
            raise ContinuityError(
                f"continuity callback requested {expected_plan_tag}, but exact accepted plan is "
                f"{actual_plan_tag or 'unavailable'}"
            )
    selected = public_selection(config, client)
    state: dict[str, Any] = {
        "schema": EVIDENCE_SCHEMA,
        "drill": config["drill"],
        "phase": "planning",
        "observed_at": utc_now(),
        "authority_issue": issue,
    }
    try:
        if accepted is None:
            if selected is None:
                selection = select_versions(config, client)
                selection_record = record_selection(Path.cwd(), config, selection)
            else:
                selection, selection_record = selected
            state["selection"] = {
                **selection_record,
                "plan": selection["plan"],
                "sha256": manifest_digest(selection),
                "versions": selection["versions"],
            }
            plan, expected = build_plan(config, client, selection)
            controller_commit = os.environ.get("GITHUB_SHA")
            if controller_commit:
                if not COMMIT_PATTERN.fullmatch(controller_commit):
                    raise ContinuityError("GitHub controller revision is not an exact commit")
                expected["github-control-plane"] = controller_commit
            needs_qualification = "true"
        else:
            plan = accepted
            if selected is not None:
                selection, selection_record = selected
                if (
                    plan["plan"] != selection["plan"]
                    or {name: identity["version"] for name, identity in plan["components"].items()}
                    != selection["versions"]
                ):
                    raise ContinuityError("accepted continuity plan differs from its immutable version selection")
                state["selection"] = {**selection_record, "plan": selection["plan"]}
            expected = {name: identity["commit"] for name, identity in plan["components"].items()}
            needs_qualification = "false"
        state.update(
            {
                "outcome": "ready",
                "plan": {"tag": f"{PLAN_TAG_PREFIX}{plan['plan']}", "sha256": manifest_digest(plan)},
            }
        )
    except PlanBlocked as error:
        state.update({"outcome": "blocked", "blockers": error.blockers})
        state_path.write_bytes(canonical_json(state))
        raise
    plan_path.write_bytes(canonical_json(plan))
    expected_path.write_bytes(canonical_json(expected))
    state_path.write_bytes(canonical_json(state))
    write_github_output(
        output,
        {
            "needs_qualification": needs_qualification,
            "plan": plan["plan"],
            "plan_tag": f"{PLAN_TAG_PREFIX}{plan['plan']}",
        },
    )


def record_immutable_tag(
    repository: Path,
    tag: str,
    files: list[tuple[str, bytes]],
    message: str,
    label: str,
    *,
    remote: str,
) -> dict[str, str]:
    existing_ref = fetch_existing_record(repository, remote, tag)
    if existing_ref:
        for filename, content in files:
            if read_record_file(repository, existing_ref, filename) != content:
                raise ContinuityError(f"immutable {label} {tag} differs from the requested record")
        return {"status": "existing", "tag": tag, "commit": run_git(["rev-parse", existing_ref], cwd=repository)}

    with tempfile.NamedTemporaryFile(prefix="beta-continuity-index-", delete=False) as index:
        index_path = Path(index.name)
    try:
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(index_path)
        index_path.unlink(missing_ok=True)
        run_git(["read-tree", "--empty"], cwd=repository, env=env)
        for filename, content in files:
            blob = (
                subprocess.run(
                    ["git", "hash-object", "-w", "--stdin"],
                    cwd=repository,
                    env=env,
                    input=content,
                    check=True,
                    stdout=subprocess.PIPE,
                )
                .stdout.decode()
                .strip()
            )
            run_git(
                ["update-index", "--add", "--cacheinfo", f"100644,{blob},{filename}"],
                cwd=repository,
                env=env,
            )
        tree = run_git(["write-tree"], cwd=repository, env=env)
        commit_env = env | {
            "GIT_AUTHOR_NAME": "Durable Workflow Continuity",
            "GIT_AUTHOR_EMAIL": "support@durable-workflow.com",
            "GIT_COMMITTER_NAME": "Durable Workflow Continuity",
            "GIT_COMMITTER_EMAIL": "support@durable-workflow.com",
        }
        commit = subprocess.run(
            ["git", "commit-tree", tree],
            cwd=repository,
            env=commit_env,
            input=f"{message}\n",
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        pushed = subprocess.run(
            ["git", "push", remote, f"{commit}:refs/tags/{tag}"],
            cwd=repository,
            check=False,
            text=True,
            capture_output=True,
        )
        if pushed.returncode:
            recovered = fetch_existing_record(repository, remote, tag)
            if not recovered:
                raise ContinuityError(f"cannot publish immutable {label}: {pushed.stderr.strip()}")
            for filename, content in files:
                if read_record_file(repository, recovered, filename) != content:
                    raise ContinuityError(f"concurrent {label} {tag} has different evidence")
            commit = run_git(["rev-parse", recovered], cwd=repository)
            return {"status": "existing", "tag": tag, "commit": commit}
        return {"status": "created", "tag": tag, "commit": commit}
    finally:
        index_path.unlink(missing_ok=True)


def record_selection(
    repository: Path,
    config: dict[str, Any],
    selection: dict[str, Any],
    *,
    remote: str = "origin",
) -> dict[str, str]:
    validate_selection(config, selection)
    tag = selection_tag(config)
    return record_immutable_tag(
        repository,
        tag,
        [("continuity-selection.json", canonical_json(selection))],
        f"Select versions for continuity drill {config['drill']}",
        "continuity selection",
        remote=remote,
    )


def record_phase(
    repository: Path,
    plan: dict[str, Any],
    phase: str,
    evidence: dict[str, Any],
    *,
    qualification_path: Path | None = None,
    remote: str = "origin",
) -> dict[str, str]:
    tag = phase_tag(plan, phase)
    files: list[tuple[str, bytes]] = [
        ("continuity-evidence.json", canonical_json(evidence)),
        ("release-plan.json", canonical_json(plan)),
    ]
    if qualification_path is not None and qualification_path.exists():
        qualification = load_json(qualification_path, "target qualification evidence")
        files.append(("target-qualification-evidence.json", canonical_json(qualification)))
    return record_immutable_tag(
        repository,
        tag,
        files,
        f"Record {phase} continuity phase for {plan['plan']}",
        "continuity phase",
        remote=remote,
    )


def record_continuity_resolution(
    repository: Path,
    selection_path: Path,
    *,
    source_sha: str,
    run_id: int,
    run_attempt: int,
    remote: str = "origin",
) -> dict[str, str]:
    selection = load_json(selection_path, "continuity successor selection")
    if (
        not isinstance(selection, dict)
        or set(selection)
        != {"interruption", "schema", "selected_successor", "successor_claims"}
        or selection.get("schema") != CONTINUITY_RESOLUTION_SELECTION_SCHEMA
    ):
        raise ContinuityError("continuity successor selection has an invalid document shape")
    qualification = qualified_resolution_source(
        run_id,
        run_attempt,
        os.environ.get("GITHUB_TOKEN", ""),
    )
    if qualification["head_sha"] != source_sha:
        raise ContinuityError(
            "continuity resolution qualification is bound to another source revision"
        )
    resolution = {
        **selection,
        "schema": CONTINUITY_RESOLUTION_SCHEMA,
        "qualification": qualification,
    }
    client = PublicClient(os.environ.get("GITHUB_TOKEN"))
    validate_continuity_resolution_authority(
        resolution,
        client,
    )
    interrupted_plan = resolution["interruption"]["plan"]["tag"].removeprefix(PLAN_TAG_PREFIX)
    prefix = f"release-plan-continuity-resolution/{interrupted_plan}/"
    refs = client.json(
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/git/matching-refs/tags/{prefix}"
    )
    if not isinstance(refs, list):
        raise ContinuityError(
            "GitHub did not return the immutable continuity-resolution tag registry"
        )
    tags: list[str] = []
    for ref in refs:
        value = ref.get("ref") if isinstance(ref, dict) else None
        tag = value.removeprefix("refs/tags/") if isinstance(value, str) else ""
        if (
            value != f"refs/tags/{tag}"
            or not tag.startswith(prefix)
            or not re.fullmatch(r"[0-9a-f]{64}", tag.removeprefix(prefix))
        ):
            raise ContinuityError(
                "immutable continuity-resolution registry is malformed or ambiguous"
            )
        tags.append(tag)
    if len(tags) != len(refs) or len(tags) > 1:
        raise ContinuityError(
            "immutable continuity-resolution registry is malformed or ambiguous"
        )
    if tags:
        commit = resolve_tag(client, CONTROL_REPOSITORY, tags[0])
        if commit is None:
            raise ContinuityError("existing continuity successor resolution is absent")
        existing = read_public_record(
            client,
            tags[0],
            commit,
            "continuity-successor-resolution.json",
        )
        validate_continuity_resolution_authority(existing, client)
        comparable = {
            field: existing.get(field)
            for field in ("interruption", "selected_successor", "successor_claims")
        }
        if comparable != {
            field: selection[field]
            for field in ("interruption", "selected_successor", "successor_claims")
        }:
            raise ContinuityError(
                "existing continuity successor resolution selects different authority"
            )
        return {"status": "existing", "tag": tags[0], "commit": commit}
    return record_immutable_tag(
        repository,
        continuity_resolution_tag(resolution),
        [("continuity-successor-resolution.json", canonical_json(resolution))],
        f"Resolve continuity successor fork for {interrupted_plan}",
        "continuity successor resolution",
        remote=remote,
    )


def public_phase_commit(client: PublicClient, plan: dict[str, Any], phase: str) -> str | None:
    return resolve_tag(client, CONTROL_REPOSITORY, phase_tag(plan, phase))


def plan_record(client: PublicClient, plan: dict[str, Any]) -> dict[str, str] | None:
    tag = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    commit = resolve_tag(client, CONTROL_REPOSITORY, tag)
    if commit is None:
        return None
    public, _preparation = discover_plan(client, tag)[1:]
    if canonical_json(public) != canonical_json(plan):
        raise ContinuityError(f"public release plan {tag} differs from accepted continuity authority")
    return {"tag": tag, "commit": commit, "sha256": manifest_digest(plan)}


def component_publications(client: PublicClient, plan: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    published: dict[str, Any] = {}
    pending: list[str] = []
    for name, component in COMPONENTS.items():
        identity = plan["components"][name]
        encoded = urllib.parse.quote(identity["version"], safe="")
        release = optional_public_json(
            client,
            f"https://api.github.com/repos/{component.repository}/releases/tags/{encoded}",
        )
        if not isinstance(release, dict) or release.get("draft") or release.get("tag_name") != identity["version"]:
            pending.append(name)
            continue
        try:
            source = resolve_github_tag(client, component.repository, identity["version"])
        except CandidateError:
            pending.append(name)
            continue
        if source["commit"] != identity["commit"]:
            raise ContinuityError(
                f"{component.repository}@{identity['version']} resolves to {source['commit']}, "
                f"not planned commit {identity['commit']}"
            )
        published[name] = {
            "commit": identity["commit"],
            "published_at": release.get("published_at"),
            "release_id": release.get("id"),
            "url": release.get("html_url"),
            "version": identity["version"],
        }
    return published, pending


def accepted_publication_state(
    client: PublicClient,
    plan: dict[str, Any],
    accepted_commit: str,
) -> dict[str, Any]:
    evidence = read_public_json_file(client, accepted_commit, "continuity-evidence.json")
    published = evidence.get("public_components_at_acceptance")
    pending = evidence.get("pending_components_at_acceptance")
    expected_plan = {
        "tag": f"{PLAN_TAG_PREFIX}{plan['plan']}",
        "sha256": manifest_digest(plan),
    }
    if (
        evidence.get("schema") != EVIDENCE_SCHEMA
        or evidence.get("phase") != "accepted"
        or evidence.get("outcome") != "accepted"
        or evidence.get("release_plan") != expected_plan
        or evidence.get("candidate_identity")
        != {"components": plan["components"], "plan_sha256": expected_plan["sha256"]}
        or not isinstance(evidence.get("observed_at"), str)
        or not isinstance(published, dict)
        or not isinstance(pending, list)
        or not all(isinstance(name, str) for name in pending)
        or set(published) & set(pending)
        or set(published) | set(pending) != set(COMPONENTS)
    ):
        raise ContinuityError("accepted continuity evidence lacks a complete publication baseline")
    for name, publication in published.items():
        identity = plan["components"].get(name)
        if (
            not isinstance(publication, dict)
            or not isinstance(identity, dict)
            or publication.get("commit") != identity.get("commit")
            or publication.get("version") != identity.get("version")
        ):
            raise ContinuityError(f"accepted publication baseline for {name} differs from the exact plan")
    return {
        "observed_at": evidence["observed_at"],
        "pending_components": pending,
        "public_components": published,
        "tag": phase_tag(plan, "accepted"),
        "commit": accepted_commit,
    }


def accepted_plan_authority(client: PublicClient, plan: dict[str, Any]) -> dict[str, Any] | None:
    tag = phase_tag(plan, "accepted")
    commit = resolve_tag(client, CONTROL_REPOSITORY, tag)
    if commit is None:
        return None
    recorded_plan = read_public_json_file(client, commit, "release-plan.json")
    validate_recorded_release_plan(recorded_plan)
    if canonical_json(recorded_plan) != canonical_json(plan):
        raise ContinuityError(f"accepted continuity record {tag} differs from the recorded release plan")
    acceptance = accepted_publication_state(client, plan, commit)
    if resolve_tag(client, CONTROL_REPOSITORY, tag) != commit:
        raise ContinuityError(f"accepted continuity record {tag} moved while the callback was validated")
    return acceptance


def parse_github_timestamp(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str):
        raise ContinuityError(f"{label} has no public timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ContinuityError(f"{label} has an invalid public timestamp") from error
    if parsed.tzinfo is None:
        raise ContinuityError(f"{label} has no timezone")
    return parsed


def recovery_publication_triggers(
    writer: GitHubWriter,
    plan_tag_value: str,
    acceptance: dict[str, Any],
    published: dict[str, Any],
) -> dict[str, Any]:
    accepted_at = parse_github_timestamp(acceptance["observed_at"], "continuity acceptance")
    triggers: dict[str, Any] = {}
    for name in acceptance["pending_components"]:
        publication = published.get(name)
        if not isinstance(publication, dict):
            continue
        component = COMPONENTS[name]
        encoded = urllib.parse.quote("release-plan-recovery.yml", safe="")
        payload = writer.get(
            f"/repos/{component.repository}/actions/workflows/{encoded}/runs?event=workflow_dispatch&per_page=100"
        )
        runs = payload.get("workflow_runs", []) if isinstance(payload, dict) else []
        published_at = parse_github_timestamp(publication.get("published_at"), f"{name} publication")
        qualifying = []
        for run in runs:
            if (
                run.get("event") != "workflow_dispatch"
                or run.get("status") != "completed"
                or run.get("conclusion") != "success"
                or plan_tag_value not in str(run.get("display_title", ""))
            ):
                continue
            created_at = parse_github_timestamp(run.get("created_at"), f"{name} recovery run")
            if accepted_at <= created_at <= published_at:
                qualifying.append((created_at, run))
        if not qualifying:
            continue
        _created_at, recovery = max(qualifying, key=lambda item: (item[0], int(item[1].get("id", 0))))
        triggers[name] = {
            "publication": publication,
            "repository_recovery_run": {
                "conclusion": recovery.get("conclusion"),
                "created_at": recovery.get("created_at"),
                "display_title": recovery.get("display_title"),
                "event": recovery.get("event"),
                "id": recovery.get("id"),
                "status": recovery.get("status"),
                "url": recovery.get("html_url"),
                "workflow": f"https://github.com/{component.repository}/actions/workflows/release-plan-recovery.yml",
            },
        }
    return triggers


def validate_interrupted_evidence(
    client: PublicClient,
    plan: dict[str, Any],
    interrupted_commit: str,
    acceptance: dict[str, Any],
) -> dict[str, Any]:
    evidence = read_public_json_file(client, interrupted_commit, "continuity-evidence.json")
    recorded_plan = read_public_json_file(client, interrupted_commit, "release-plan.json")
    validate_recorded_release_plan(recorded_plan)
    triggers = evidence.get("interruption_triggers")
    accepted_phase = evidence.get("accepted_phase")
    if (
        evidence.get("phase") != "interrupted"
        or canonical_json(recorded_plan) != canonical_json(plan)
        or not isinstance(triggers, dict)
        or not triggers
        or not set(triggers) <= set(acceptance["pending_components"])
        or accepted_phase != {"tag": acceptance["tag"], "commit": acceptance["commit"]}
    ):
        raise ContinuityError(
            "immutable interrupted continuity evidence has no valid post-acceptance recovery trigger; "
            "a new continuity identity must supersede it"
        )
    accepted_at = parse_github_timestamp(acceptance["observed_at"], "continuity acceptance")
    plan_tag_value = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    for name, trigger in triggers.items():
        publication = trigger.get("publication") if isinstance(trigger, dict) else None
        recovery = trigger.get("repository_recovery_run") if isinstance(trigger, dict) else None
        component = COMPONENTS[name]
        identity = plan["components"][name]
        if (
            not isinstance(publication, dict)
            or publication.get("commit") != identity["commit"]
            or publication.get("version") != identity["version"]
            or not isinstance(recovery, dict)
            or recovery.get("event") != "workflow_dispatch"
            or recovery.get("status") != "completed"
            or recovery.get("conclusion") != "success"
            or plan_tag_value not in str(recovery.get("display_title", ""))
            or recovery.get("workflow")
            != f"https://github.com/{component.repository}/actions/workflows/release-plan-recovery.yml"
        ):
            raise ContinuityError("immutable interrupted continuity evidence has an invalid recovery trigger")
        created_at = parse_github_timestamp(recovery.get("created_at"), f"{name} recovery run")
        published_at = parse_github_timestamp(publication.get("published_at"), f"{name} publication")
        if not accepted_at <= created_at <= published_at:
            raise ContinuityError("immutable interrupted continuity evidence has an invalid recovery chronology")
    return triggers


def require_partial_publication(published: dict[str, Any], pending: list[str]) -> None:
    if not published or not pending:
        raise ContinuityError(
            "the interruption phase requires at least one published and at least one pending component"
        )


def recovery_run_exists(writer: GitHubWriter, repository: str, workflow: str, plan_tag_value: str) -> bool:
    existing = workflow_run(writer, repository, workflow, plan_tag_value)
    return existing is not None and run_prevents_redispatch(existing)


def dispatch_recovery(writer: GitHubWriter, component_name: str, plan_tag_value: str) -> str:
    component = COMPONENTS[component_name]
    workflow = "release-plan-recovery.yml"
    if not recovery_run_exists(writer, component.repository, workflow, plan_tag_value):
        writer.dispatch(
            component.repository,
            workflow,
            EXPECTED_DEFAULT_BRANCHES[component_name],
            {"plan_tag": plan_tag_value},
        )
    return f"https://github.com/{component.repository}/actions/workflows/{workflow}"


def workflow_run(writer: GitHubWriter, repository: str, workflow: str, title_fragment: str) -> dict[str, Any] | None:
    encoded = urllib.parse.quote(workflow, safe="")
    payload = writer.get(f"/repos/{repository}/actions/workflows/{encoded}/runs?event=workflow_dispatch&per_page=100")
    runs = payload.get("workflow_runs", []) if isinstance(payload, dict) else []
    matching = [run for run in runs if title_fragment in str(run.get("display_title", ""))]
    return max(matching, key=lambda run: int(run.get("id", 0)), default=None)


def run_prevents_redispatch(run: dict[str, Any]) -> bool:
    return run.get("status") != "completed" or run.get("conclusion") == "success"


def ensure_dispatch(
    writer: GitHubWriter,
    repository: str,
    workflow: str,
    ref: str,
    inputs: dict[str, str],
    title_fragment: str,
) -> dict[str, Any] | None:
    existing = workflow_run(writer, repository, workflow, title_fragment)
    if existing is None or not run_prevents_redispatch(existing):
        writer.dispatch(repository, workflow, ref, inputs)
    return existing


def conformance_run_reference(run: dict[str, Any] | None) -> dict[str, Any] | None:
    if run is None:
        return None
    return {
        "conclusion": run.get("conclusion"),
        "id": run.get("id"),
        "run_attempt": run.get("run_attempt"),
        "status": run.get("status"),
        "url": run.get("html_url"),
    }


def retention_workflow_runs(
    writer: GitHubWriter,
    source_run_id: int,
    source_run_attempt: int,
) -> list[dict[str, Any]]:
    encoded = urllib.parse.quote(CONFORMANCE_RETENTION_WORKFLOW, safe="")
    payload = writer.get(f"/repos/{CONTROL_REPOSITORY}/actions/workflows/{encoded}/runs?per_page=100")
    runs = payload.get("workflow_runs", []) if isinstance(payload, dict) else []
    display_title = f"Retain conformance {source_run_id}.{source_run_attempt}"
    matching = [
        run
        for run in runs
        if isinstance(run, dict)
        and run.get("display_title") == display_title
        and type(run.get("id")) is int
        and run["id"] > 0
    ]
    return sorted(matching, key=lambda run: run["id"])


def ensure_conformance_execution_or_retention(
    writer: GitHubWriter,
    candidate: dict[str, Any],
) -> dict[str, Any]:
    """Run conformance once, then recover only its retained artifacts."""
    candidate_name = candidate.get("candidate")
    if not isinstance(candidate_name, str) or not candidate_name:
        raise ContinuityError("immutable candidate has no conformance identity")
    source_run = workflow_run(writer, CONTROL_REPOSITORY, CONFORMANCE_WORKFLOW, candidate_name)
    if source_run is None:
        writer.dispatch(
            CONTROL_REPOSITORY,
            CONFORMANCE_WORKFLOW,
            "main",
            {
                "candidate_manifest": canonical_json(candidate).decode().strip(),
                "injected_canary_failure_experiment": "none",
                "injected_failure_experiment": "none",
            },
        )
        return {
            "outcome": "conformance-execution-requested",
            "retention_runs": [],
            "source_run": None,
        }
    if source_run.get("status") != "completed":
        return {
            "outcome": "waiting-for-conformance-execution",
            "retention_runs": [],
            "source_run": conformance_run_reference(source_run),
        }
    run_id = source_run.get("id")
    run_attempt = source_run.get("run_attempt")
    if type(run_id) is not int or run_id < 1 or type(run_attempt) is not int or run_attempt < 1:
        raise ContinuityError("completed conformance run has no recoverable run identity")
    retention_runs = retention_workflow_runs(writer, run_id, run_attempt)
    retained_references = [conformance_run_reference(run) for run in retention_runs[-2:]]
    if any(run_prevents_redispatch(run) for run in retention_runs):
        return {
            "outcome": "waiting-for-conformance-retention",
            "retention_runs": retained_references,
            "source_run": conformance_run_reference(source_run),
        }
    if len(retention_runs) >= 2:
        return {
            "outcome": "conformance-retention-terminal-failure",
            "retention_runs": retained_references,
            "source_run": conformance_run_reference(source_run),
        }
    writer.dispatch(
        CONTROL_REPOSITORY,
        CONFORMANCE_RETENTION_WORKFLOW,
        "main",
        {"source_run_id": str(run_id), "source_run_attempt": str(run_attempt)},
    )
    return {
        "outcome": "conformance-retention-requested",
        "retention_runs": retained_references,
        "source_run": conformance_run_reference(source_run),
    }


def dispatch_accepted_continuity(plan_path: Path, output: Path | None) -> None:
    plan = load_json(plan_path, "release plan")
    validate_recorded_release_plan(plan)
    token = os.environ.get("GITHUB_TOKEN")
    client = PublicClient(token)
    acceptance = accepted_plan_authority(client, plan)
    if acceptance is None:
        write_github_output(output, {"dispatched": "false", "plan_tag": f"{PLAN_TAG_PREFIX}{plan['plan']}"})
        return

    writer = GitHubWriter(token or "", os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    plan_tag_value = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    existing = ensure_dispatch(
        writer,
        CONTROL_REPOSITORY,
        CONTINUITY_WORKFLOW,
        "main",
        {"plan_tag": plan_tag_value},
        plan_tag_value,
    )
    should_dispatch = existing is None or not run_prevents_redispatch(existing)
    write_github_output(
        output,
        {
            "accepted_commit": acceptance["commit"],
            "accepted_tag": acceptance["tag"],
            "dispatched": str(should_dispatch).lower(),
            "plan_tag": plan_tag_value,
        },
    )


def successful_scheduled_noop_run(
    writer: GitHubWriter,
    completion: dict[str, Any],
    current_run: dict[str, str],
) -> dict[str, Any] | None:
    completed_at = parse_github_timestamp(completion.get("observed_at"), "continuity completion")
    complete_run = completion.get("github_run")
    complete_run_id = complete_run.get("id") if isinstance(complete_run, dict) else None
    encoded = urllib.parse.quote("beta-continuity.yml", safe="")
    payload = writer.get(f"/repos/{CONTROL_REPOSITORY}/actions/workflows/{encoded}/runs?event=schedule&per_page=100")
    runs = payload.get("workflow_runs", []) if isinstance(payload, dict) else []
    qualifying = []
    for run in runs:
        run_id = str(run.get("id"))
        if (
            run.get("event") != "schedule"
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
            or run_id in {str(complete_run_id), current_run["id"]}
        ):
            continue
        created_at = parse_github_timestamp(run.get("created_at"), "scheduled continuity run")
        if created_at >= completed_at:
            qualifying.append((created_at, run))
    if not qualifying:
        return None
    _created_at, successful = max(qualifying, key=lambda item: (item[0], int(item[1].get("id", 0))))
    return {
        "conclusion": successful.get("conclusion"),
        "created_at": successful.get("created_at"),
        "id": successful.get("id"),
        "url": successful.get("html_url"),
    }


def issue_phase_marker(config: dict[str, Any], phase: str) -> str:
    return f"<!-- beta-continuity-phase: {config['drill']}:{phase} -->"


def ensure_issue_comment(
    writer: GitHubWriter,
    config: dict[str, Any],
    plan: dict[str, Any],
    phase: str,
    record: dict[str, str],
    summary: str,
) -> None:
    issue = config["authority_issue"]
    path = f"/repos/{issue['repository']}/issues/{issue['number']}/comments"
    marker = issue_phase_marker(config, phase)
    comments = writer.list(path)
    if any(marker in str(comment.get("body", "")) for comment in comments):
        return
    url = f"https://github.com/{CONTROL_REPOSITORY}/tree/{urllib.parse.quote(record['tag'], safe='/')}"
    body = (
        f"{marker}\n"
        f"GitHub continuity phase `{phase}` is retained at [`{record['tag']}`]({url}) "
        f"for immutable plan `release-plan/{plan['plan']}`. {summary}"
    )
    writer.request("POST", path, {"body": body})


def base_evidence(
    config: dict[str, Any],
    issue: dict[str, Any],
    plan: dict[str, Any],
    phase: str,
    run: dict[str, str],
) -> dict[str, Any]:
    return {
        "schema": EVIDENCE_SCHEMA,
        "drill": config["drill"],
        "phase": phase,
        "observed_at": utc_now(),
        "authority_issue": issue,
        "release_plan": {"tag": f"{PLAN_TAG_PREFIX}{plan['plan']}", "sha256": manifest_digest(plan)},
        "github_run": run,
    }


def conformance_release_rank(prefix: str, tag: Any) -> tuple[int, int] | None:
    if not isinstance(tag, str) or not tag.startswith(prefix):
        return None
    match = re.fullmatch(r"([1-9][0-9]*)\.([1-9][0-9]*)", tag.removeprefix(prefix))
    if match is None:
        return None
    return int(match.group(1)), int(match.group(2))


def exact_conformance_reference(plan: dict[str, Any], reference: Any) -> bool:
    candidate = candidate_manifest(plan)
    prefix = f"beta-conformance/{candidate['candidate']}/"
    if not isinstance(reference, dict) or set(reference) != {"release", "run", "tag"}:
        return False
    rank = conformance_release_rank(prefix, reference.get("tag"))
    run = reference.get("run")
    return (
        rank is not None
        and isinstance(reference.get("release"), str)
        and reference["release"].startswith(f"https://github.com/{CONTROL_REPOSITORY}/releases/tag/")
        and run
        == {
            "repository": CONTROL_REPOSITORY,
            "run_id": rank[0],
            "run_attempt": rank[1],
            "evidence_tag": reference["tag"],
        }
    )


def validated_conformance_release(
    client: PublicClient,
    plan: dict[str, Any],
    candidate: dict[str, Any],
    release: dict[str, Any],
    rank: tuple[int, int],
    *,
    allow_legacy: bool = False,
) -> dict[str, Any] | None:
    tag = release.get("tag_name")
    release_url = release.get("html_url")
    release_assets = release.get("assets")
    if (
        not isinstance(tag, str)
        or not isinstance(release_url, str)
        or not release_url.startswith(f"https://github.com/{CONTROL_REPOSITORY}/releases/tag/")
        or not isinstance(release_assets, list)
    ):
        return None
    assets = {
        item.get("name"): item
        for item in release_assets
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    suite_asset = assets.get("suite-result.json")
    if not isinstance(suite_asset, dict):
        return None
    try:
        suite, _suite_payload = validated_conformance_asset(client, suite_asset)
    except ConformanceError:
        return None
    expected_run = {
        "repository": CONTROL_REPOSITORY,
        "run_id": rank[0],
        "run_attempt": rank[1],
        "evidence_tag": tag,
    }
    suite_schema = suite.get("schema") if isinstance(suite, dict) else None
    if suite_schema == LEGACY_SUITE_RESULT_SCHEMA and not allow_legacy:
        return None
    if suite_schema not in {LEGACY_SUITE_RESULT_SCHEMA, CONFORMANCE_SUITE_RESULT_SCHEMA}:
        return None
    if suite.get("github_run") != expected_run:
        return None
    if (
        suite.get("outcome") != "pass"
        or not isinstance(suite.get("candidate"), dict)
        or suite["candidate"].get("name") != candidate["candidate"]
        or suite.get("artifact_tuple") != plan["components"]
    ):
        return None
    legacy = suite_schema == LEGACY_SUITE_RESULT_SCHEMA
    conformance_plan = {
        "schema": LEGACY_PLAN_SCHEMA if legacy else CONFORMANCE_PLAN_SCHEMA,
        "candidate": suite.get("candidate"),
        "artifact_tuple": suite.get("artifact_tuple"),
        "source_identities": suite.get("source_identities"),
        "distribution_identities": suite.get("distribution_identities"),
        "runtime_dependencies": suite.get("runtime_dependencies"),
        "runner": suite.get("runner"),
        "server_runner": suite.get("server_runner"),
        "experiments": list(CONFORMANCE_EXPERIMENTS),
    }
    if not legacy:
        conformance_plan["waterline_service_runner"] = suite.get("waterline_service_runner")
    try:
        validate_recorded_plan(conformance_plan)
        summaries = suite.get("experiments")
        if not isinstance(summaries, dict) or set(summaries) != set(CONFORMANCE_EXPERIMENTS):
            return None
        for experiment in CONFORMANCE_EXPERIMENTS:
            experiment_asset = assets.get(f"{experiment}.json")
            if not isinstance(experiment_asset, dict):
                raise ConformanceError("durable conformance release is missing an experiment asset")
            result, payload = validated_conformance_asset(client, experiment_asset)
            validate_recorded_experiment_result(result, conformance_plan)
            summary = summaries[experiment]
            if (
                not isinstance(result, dict)
                or result.get("experiment") != experiment
                or not isinstance(summary, dict)
                or summary.get("result_sha256") != hashlib.sha256(payload).hexdigest()
                or summary.get("outcome") != result.get("outcome")
                or summary.get("classification") != result.get("classification")
            ):
                raise ConformanceError("durable conformance release has mismatched experiment evidence")
    except ConformanceError:
        return None
    return {"release": release_url, "run": expected_run, "tag": tag}


def public_conformance_releases(client: PublicClient) -> list[dict[str, Any]]:
    return public_releases(client, CONTROL_REPOSITORY)


def conformance_evidence(
    client: PublicClient,
    plan: dict[str, Any],
    *,
    preferred: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    candidate = candidate_manifest(plan)
    releases = public_conformance_releases(client)
    prefix = f"beta-conformance/{candidate['candidate']}/"
    ranked_releases = sorted(
        (
            (rank, release)
            for release in releases
            if isinstance(release, dict)
            and not release.get("draft")
            and (rank := conformance_release_rank(prefix, release.get("tag_name"))) is not None
        ),
        key=lambda item: item[0],
    )
    if preferred is not None:
        preferred_rank = conformance_release_rank(prefix, preferred.get("tag"))
        if preferred_rank is None:
            return None
        preferred_release = next(
            (release for _rank, release in ranked_releases if release.get("tag_name") == preferred["tag"]),
            None,
        )
        if preferred_release is not None:
            evidence = validated_conformance_release(
                client,
                plan,
                candidate,
                preferred_release,
                preferred_rank,
                allow_legacy=plan.get("schema") == LEGACY_RELEASE_PLAN_SCHEMA,
            )
            if evidence == preferred:
                return evidence
        ranked_releases = [(rank, release) for rank, release in ranked_releases if rank > preferred_rank]

    for rank, release in ranked_releases:
        evidence = validated_conformance_release(client, plan, candidate, release, rank)
        if evidence is not None:
            return evidence
    return None


def validated_conformance_asset(client: PublicClient, asset: dict[str, Any]) -> tuple[Any, bytes]:
    url = asset.get("browser_download_url")
    if not isinstance(url, str):
        raise ConformanceError("durable conformance release asset has no download URL")
    payload = client.bytes(url)
    try:
        value = json.loads(payload.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ConformanceError("durable conformance release asset is not valid JSON") from error
    validate_public_evidence_strings(value)
    return value, payload


def accepted_qualification_evidence(
    client: PublicClient,
    plan: dict[str, Any],
    accepted_commit: str,
) -> dict[str, Any]:
    acceptance = read_public_json_file(client, accepted_commit, "continuity-evidence.json")
    qualification = read_public_json_file(client, accepted_commit, "target-qualification-evidence.json")
    targets = qualification.get("targets") if isinstance(qualification, dict) else None
    controller_run = acceptance.get("github_run") if isinstance(acceptance, dict) else None
    controller_commit = controller_run.get("sha") if isinstance(controller_run, dict) else None
    required_targets = set(COMPONENTS) | {"github-control-plane"}
    if (
        not isinstance(qualification, dict)
        or set(qualification) != {"schema", "targets"}
        or qualification.get("schema") != QUALIFICATION_EVIDENCE_SCHEMA
        or not isinstance(targets, dict)
        or not required_targets <= set(targets)
        or not isinstance(controller_commit, str)
        or not COMMIT_PATTERN.fullmatch(controller_commit)
    ):
        raise ContinuityError("accepted continuity record lacks exact target qualification evidence")

    expected_commits = {name: identity["commit"] for name, identity in plan["components"].items()}
    expected_commits["github-control-plane"] = controller_commit
    for name, expected_commit in expected_commits.items():
        target = targets.get(name)
        protected = target.get("protected_checks") if isinstance(target, dict) else None
        successful = target.get("successful_check_runs") if isinstance(target, dict) else None
        expected_branch = "main" if name == "github-control-plane" else EXPECTED_DEFAULT_BRANCHES[name]
        if (
            not isinstance(target, dict)
            or target.get("branch") != expected_branch
            or target.get("commit") != expected_commit
            or not isinstance(protected, list)
            or not protected
            or not all(isinstance(check, str) and check for check in protected)
            or not isinstance(successful, dict)
            or set(successful) != set(protected)
            or not all(type(run_id) is int and run_id > 0 for run_id in successful.values())
        ):
            raise ContinuityError(f"target qualification evidence for {name} does not prove the exact plan source")
    return {
        "commit": accepted_commit,
        "sha256": manifest_digest(qualification),
        "tag": phase_tag(plan, "accepted"),
    }


def exact_completion_authority(
    client: PublicClient,
    config: dict[str, Any],
    plan: dict[str, Any],
    complete_commit: str,
    noop_commit: str,
) -> dict[str, Any]:
    plan_digest = manifest_digest(plan)
    plan_tag_value = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    public_plan_record = plan_record(client, plan)
    if public_plan_record is None:
        raise ContinuityError("completed continuity plan has no immutable plan artifact")
    plan_commit = public_plan_record["commit"]
    recorded_plan = read_public_json_file(client, plan_commit, "release-plan.json")
    validate_recorded_release_plan(recorded_plan)
    if canonical_json(recorded_plan) != canonical_json(plan):
        raise ContinuityError("completed continuity plan artifact differs from the exact accepted plan")
    plan_record_value = {"tag": plan_tag_value, "commit": plan_commit, "sha256": plan_digest}
    if public_plan_record != plan_record_value:
        raise ContinuityError("completed continuity plan record has an invalid public identity")

    accepted_commit = public_phase_commit(client, plan, "accepted")
    if accepted_commit is None:
        raise ContinuityError("completed continuity plan has no immutable acceptance artifact")
    acceptance = accepted_plan_authority(client, plan)
    if acceptance is None or acceptance["commit"] != accepted_commit:
        raise ContinuityError("completed continuity acceptance does not match the exact plan")
    qualification = accepted_qualification_evidence(client, plan, accepted_commit)

    completion_tag = f"release-candidate/{plan['channel']}/{plan['plan']}"
    completion_commit = resolve_tag(client, CONTROL_REPOSITORY, completion_tag)
    if completion_commit is None:
        raise ContinuityError("completed continuity plan has no public verification artifact")
    completion_artifact = read_public_json_file(client, completion_commit, "release-candidate.json")
    completion_verification = read_public_json_file(client, completion_commit, "verification.json")
    expected_release_plan = {"tag": plan_tag_value, "commit": plan_commit, "sha256": plan_digest}
    completion_keys = {"schema", "candidate", "channel", "release_plan", "components"}
    if not isinstance(completion_artifact, dict) or (
        frozenset(completion_artifact)
        not in {frozenset(completion_keys), frozenset(completion_keys | {"release_preparation_sha256"})}
        or completion_artifact.get("schema") != "durable-workflow.release-candidate/v1"
        or completion_artifact.get("candidate") != plan["plan"]
        or completion_artifact.get("channel") != plan["channel"]
        or completion_artifact.get("release_plan") != expected_release_plan
        or completion_artifact.get("components") != plan["components"]
    ):
        raise ContinuityError("public completion artifact differs from the exact plan")
    public_verification = (
        completion_verification.get("public_verification") if isinstance(completion_verification, dict) else None
    )
    completion_verification_keys = {
        "schema",
        "candidate",
        "channel",
        "release_plan_sha256",
        "public_verification",
    }
    if (
        not isinstance(completion_verification, dict)
        or frozenset(completion_verification)
        not in {
            frozenset(completion_verification_keys),
            frozenset(completion_verification_keys | {"release_preparation_sha256"}),
        }
        or completion_verification.get("schema") != "durable-workflow.release-candidate-verification/v1"
        or completion_verification.get("candidate") != plan["plan"]
        or completion_verification.get("channel") != plan["channel"]
        or completion_verification.get("release_plan_sha256") != plan_digest
        or completion_verification.get("release_preparation_sha256")
        != completion_artifact.get("release_preparation_sha256")
        or not isinstance(public_verification, dict)
    ):
        raise ContinuityError("public completion verification differs from the exact plan")
    try:
        validate_recorded_verification(public_verification, candidate_manifest(plan))
    except CandidateError as error:
        raise ContinuityError(f"public completion verification does not prove exact sources: {error}") from error

    published, pending = component_publications(client, plan)
    if pending or set(published) != set(COMPONENTS):
        raise ContinuityError(f"completed continuity sources are not all public: pending={sorted(pending)}")

    complete_evidence = read_public_json_file(client, complete_commit, "continuity-evidence.json")
    complete_plan = read_public_json_file(client, complete_commit, "release-plan.json")
    expected_phase_record = {"tag": completion_tag, "commit": completion_commit}
    recorded_conformance = complete_evidence.get("conformance") if isinstance(complete_evidence, dict) else None
    if (
        canonical_json(complete_plan) != canonical_json(plan)
        or not isinstance(complete_evidence, dict)
        or complete_evidence.get("schema") != EVIDENCE_SCHEMA
        or complete_evidence.get("drill") != config["drill"]
        or complete_evidence.get("phase") != "complete"
        or complete_evidence.get("outcome") != "passed"
        or complete_evidence.get("release_plan") != {"tag": plan_tag_value, "sha256": plan_digest}
        or complete_evidence.get("accepted_phase") != phase_tag(plan, "accepted")
        or complete_evidence.get("interrupted_phase") != phase_tag(plan, "interrupted")
        or complete_evidence.get("resumed_phase") != phase_tag(plan, "resumed")
        or complete_evidence.get("plan_record") != plan_record_value
        or complete_evidence.get("public_verification") != expected_phase_record
        or not exact_conformance_reference(plan, recorded_conformance)
        or complete_evidence.get("published_components") != published
    ):
        raise ContinuityError("immutable completion phase does not prove exact plan artifacts and sources")
    live_conformance = conformance_evidence(client, plan, preferred=recorded_conformance)
    if live_conformance is None:
        raise ContinuityError("completed continuity plan has no live exact-tuple conformance evidence")

    noop_evidence = read_public_json_file(client, noop_commit, "continuity-evidence.json")
    noop_plan = read_public_json_file(client, noop_commit, "release-plan.json")
    successful_noop = noop_evidence.get("successful_no_op_run") if isinstance(noop_evidence, dict) else None
    if (
        canonical_json(noop_plan) != canonical_json(plan)
        or noop_evidence.get("schema") != EVIDENCE_SCHEMA
        or noop_evidence.get("drill") != config["drill"]
        or noop_evidence.get("phase") != "no-op-confirmed"
        or noop_evidence.get("outcome") != "successful-scheduled-no-op-confirmed"
        or noop_evidence.get("release_plan") != {"tag": plan_tag_value, "sha256": plan_digest}
        or noop_evidence.get("complete_phase") != {"tag": phase_tag(plan, "complete"), "commit": complete_commit}
        or not isinstance(successful_noop, dict)
        or successful_noop.get("conclusion") != "success"
        or type(successful_noop.get("id")) is not int
        or not isinstance(successful_noop.get("url"), str)
    ):
        raise ContinuityError("scheduled no-op evidence does not prove the exact completed continuity plan")

    stable_tags = {
        plan_tag_value: plan_commit,
        phase_tag(plan, "accepted"): accepted_commit,
        phase_tag(plan, "complete"): complete_commit,
        phase_tag(plan, "no-op-confirmed"): noop_commit,
        completion_tag: completion_commit,
    }
    for tag, expected_commit in stable_tags.items():
        if resolve_tag(client, CONTROL_REPOSITORY, tag) != expected_commit:
            raise ContinuityError(f"public evidence tag {tag} moved during completion validation")
    return {
        "complete_phase": {"tag": phase_tag(plan, "complete"), "commit": complete_commit},
        "no_op_phase": {"tag": phase_tag(plan, "no-op-confirmed"), "commit": noop_commit},
        "plan": plan,
        "plan_record": plan_record_value,
        "public_verification": expected_phase_record,
        "qualification": qualification,
        "conformance": live_conformance,
        "sources": published,
    }


def completion_evidence_report(marker: str, completion: dict[str, Any], closing_lines: list[str]) -> str:
    plan = completion["plan"]
    plan_record_value = completion["plan_record"]
    verification = completion["public_verification"]
    qualification = completion["qualification"]
    conformance = completion["conformance"]
    versions = ", ".join(f"{name} `{identity['version']}`" for name, identity in sorted(plan["components"].items()))
    lines = [
        marker,
        "Exact GitHub continuity evidence is verified and live.",
        "",
        (
            f"- Plan: [`{plan_record_value['tag']}`](https://github.com/{CONTROL_REPOSITORY}/tree/"
            f"{urllib.parse.quote(plan_record_value['tag'], safe='/')}) at `{plan_record_value['commit']}`."
        ),
        (
            f"- Public verification: [`{verification['tag']}`](https://github.com/{CONTROL_REPOSITORY}/tree/"
            f"{urllib.parse.quote(verification['tag'], safe='/')}) at `{verification['commit']}`."
        ),
        (
            f"- Qualification: [`{qualification['tag']}`](https://github.com/{CONTROL_REPOSITORY}/tree/"
            f"{urllib.parse.quote(qualification['tag'], safe='/')}) at `{qualification['commit']}` with SHA-256 "
            f"`{qualification['sha256']}`."
        ),
        f"- Conformance: [`{conformance['tag']}`]({conformance['release']}).",
        f"- Published versions: {versions}.",
        *closing_lines,
    ]
    return "\n".join(lines) + "\n"


def blocker_completion_report_body(
    config: dict[str, Any],
    completion: dict[str, Any],
    component_name: str,
    repository: str,
    number: int,
) -> str:
    plan = completion["plan"]
    identity = plan["components"][component_name]
    marker = (
        f"<!-- beta-continuity-blocker-closure: {config['drill']}:{repository}:{number}:"
        f"{plan['plan']}:{manifest_digest(plan)} -->"
    )
    return completion_evidence_report(
        marker,
        completion,
        [
            (
                f"- This routed blocker proves {component_name} `{identity['version']}` from exact source "
                f"`{identity['commit']}`."
            )
        ],
    )


def work_item_completion_report_body(
    config: dict[str, Any],
    completion: dict[str, Any],
    specification: dict[str, Any],
) -> str:
    plan = completion["plan"]
    marker = (
        f"<!-- beta-continuity-work-item-closure: {specification['work_id']}:{plan['plan']}:{manifest_digest(plan)} -->"
    )
    return completion_evidence_report(
        marker,
        completion,
        [f"- Trusted work item `{specification['work_id']}` is complete from this exact evidence."],
    )


def completion_report_body(
    config: dict[str, Any],
    completion: dict[str, Any],
    blockers: list[dict[str, Any]],
    work_items: list[dict[str, Any]],
) -> str:
    plan = completion["plan"]
    marker = f"<!-- beta-continuity-closure: {config['drill']}:{plan['plan']}:{manifest_digest(plan)} -->"
    blocker_summary = (
        ", ".join(f"[{item['repository']}#{item['number']}]({item['url']})" for item in blockers)
        if blockers
        else "No exact routed blocker issues were present."
    )
    work_item_summary = ", ".join(f"[{item['repository']}#{item['number']}]({item['url']})" for item in work_items)
    return completion_evidence_report(
        marker,
        completion,
        [
            f"- Routed blockers completed before this parent: {blocker_summary}",
            f"- Evidence work items completed before this parent: {work_item_summary}",
        ],
    )


def ensure_exact_completion_comment(writer: GitHubWriter, path: str, body: str) -> None:
    comments = writer.list(path)
    if not any(comment.get("body") == body for comment in comments if isinstance(comment, dict)):
        writer.request("POST", path, {"body": body})


def require_exact_completion_comment(writer: GitHubWriter, path: str, body: str) -> None:
    comments = writer.list(path)
    if not any(comment.get("body") == body for comment in comments if isinstance(comment, dict)):
        raise ContinuityError(f"GitHub issue evidence comment did not persist at {path}")


def converge_routed_blockers(
    writer: GitHubWriter,
    config: dict[str, Any],
    completion: dict[str, Any],
) -> list[dict[str, Any]]:
    plan = completion.get("plan")
    if not isinstance(plan, dict) or plan.get("components") is None:
        raise ContinuityError("verified completion evidence has no exact plan")
    routed: list[tuple[str, str, dict[str, Any]]] = []
    for component_name, identity in plan["components"].items():
        repository = COMPONENTS[component_name].repository
        issues = writer.list(f"/repos/{repository}/issues?state=all")
        for issue in issues:
            if (
                not isinstance(issue, dict)
                or "pull_request" in issue
                or not isinstance(issue.get("number"), int)
                or not has_routed_blocker_authority(issue)
                or not has_routed_blocker_dependency(config, issue)
            ):
                continue
            if is_exact_routed_blocker(config, issue, component_name, identity["version"]):
                routed.append((component_name, repository, issue))
                continue
            labels = {label["name"] for label in issue["labels"]}
            if issue.get("state") != "closed" or "status:ready" in labels:
                raise ContinuityError(
                    f"active routed blocker {repository}#{issue['number']} differs from the exact completed plan"
                )

    result: list[dict[str, Any]] = []
    for component_name, repository, issue in sorted(routed, key=lambda item: (item[1], item[2]["number"])):
        number = issue["number"]
        path = f"/repos/{repository}/issues/{number}"
        comment_path = f"{path}/comments"
        current = writer.get(path)
        if (
            not isinstance(current, dict)
            or not has_routed_blocker_authority(current)
            or not is_exact_routed_blocker(
                config,
                current,
                component_name,
                plan["components"][component_name]["version"],
            )
        ):
            raise ContinuityError(f"routed blocker {repository}#{number} lost its trusted exact authority")
        report = blocker_completion_report_body(config, completion, component_name, repository, number)
        ensure_exact_completion_comment(writer, comment_path, report)
        labels = {label["name"] for label in current["labels"]}
        desired_labels = {label for label in labels if not label.startswith("status:")}
        desired_labels.discard("completion:evidence-required")
        desired_labels.update({"completion:evidence-verified", "status:done"})
        desired_labels = replace_issue_kind(
            desired_labels,
            "kind:release-blocker",
            f"routed blocker {repository}#{number}",
        )
        if current.get("state") != "closed" or labels != desired_labels:
            writer.request(
                "PATCH",
                path,
                {"labels": sorted(desired_labels), "state": "closed"},
            )
        live = writer.get(path)
        live_labels = {
            label.get("name") for label in live.get("labels", []) if isinstance(label, dict) and label.get("name")
        }
        if (
            live.get("state") != "closed"
            or not {"completion:evidence-verified", "status:done"} <= live_labels
            or not has_routed_blocker_authority(live)
            or not is_exact_routed_blocker(config, live, component_name, plan["components"][component_name]["version"])
        ):
            raise ContinuityError(f"routed blocker {repository}#{number} did not converge to verified completion")
        require_exact_completion_comment(writer, comment_path, report)
        result.append(
            {
                "component": component_name,
                "labels": sorted(live_labels),
                "number": number,
                "repository": repository,
                "state": "closed",
                "url": live.get("html_url") or f"https://github.com/{repository}/issues/{number}",
                "version": plan["components"][component_name]["version"],
            }
        )
    return result


def validate_evidence_work_item(
    specification: dict[str, Any],
    issue: dict[str, Any],
    *,
    require_completed: bool = False,
) -> set[str]:
    labels = {label.get("name") for label in issue.get("labels", []) if isinstance(label, dict) and label.get("name")}
    required = set(specification["required_labels"])
    required_kind = require_exact_issue_kind(
        required,
        f"trusted evidence work item {specification['repository']}#{specification['number']}",
    )
    authority = {label for label in required if not label.startswith("status:") and not label.startswith("completion:")}
    statuses = {label for label in labels if label.startswith("status:")}
    completions = {label for label in labels if label.startswith("completion:")}
    ready = (
        issue.get("state") == "open"
        and required <= labels
        and statuses == {"status:ready"}
        and completions == {"completion:evidence-required"}
    )
    completed = (
        issue.get("state") == "closed"
        and authority <= labels
        and statuses == {"status:done"}
        and completions == {"completion:evidence-verified"}
    )
    if not has_exact_durable_work_id(issue, specification["work_id"]) or (
        not completed if require_completed else not (ready or completed)
    ):
        raise ContinuityError(
            f"trusted evidence work item {specification['repository']}#{specification['number']} "
            "does not match its configured work-id, labels, and lifecycle"
        )
    location = f"trusted evidence work item {specification['repository']}#{specification['number']}"
    if require_exact_issue_kind(labels, location) != required_kind:
        raise ContinuityError(
            f"{location} has an incompatible kind"
        )
    return labels


def load_evidence_work_items(
    writer: GitHubWriter,
    config: dict[str, Any],
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    work_items: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for specification in config["evidence_work_items"]:
        path = f"/repos/{specification['repository']}/issues/{specification['number']}"
        issue = writer.get(path)
        if not isinstance(issue, dict):
            raise ContinuityError(f"trusted evidence work item {path} has an invalid GitHub response")
        validate_evidence_work_item(specification, issue)
        work_items.append((specification, issue))
    return work_items


def converge_evidence_work_items(
    writer: GitHubWriter,
    config: dict[str, Any],
    completion: dict[str, Any],
    work_items: list[tuple[dict[str, Any], dict[str, Any]]],
) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for specification, _issue in work_items:
        repository = specification["repository"]
        number = specification["number"]
        path = f"/repos/{repository}/issues/{number}"
        comment_path = f"{path}/comments"
        current = writer.get(path)
        if not isinstance(current, dict):
            raise ContinuityError(f"trusted evidence work item {path} has an invalid GitHub response")
        labels = validate_evidence_work_item(specification, current)
        report = work_item_completion_report_body(config, completion, specification)
        ensure_exact_completion_comment(writer, comment_path, report)
        desired_labels = {
            label for label in labels if not label.startswith("status:") and not label.startswith("completion:")
        }
        desired_labels.update({"completion:evidence-verified", "status:done"})
        required_kind = require_exact_issue_kind(
            set(specification["required_labels"]),
            f"trusted evidence work item {repository}#{number}",
        )
        desired_labels = replace_issue_kind(
            desired_labels,
            required_kind,
            f"trusted evidence work item {repository}#{number}",
        )
        if current.get("state") != "closed" or labels != desired_labels:
            writer.request("PATCH", path, {"labels": sorted(desired_labels), "state": "closed"})
        live = writer.get(path)
        live_labels = validate_evidence_work_item(specification, live, require_completed=True)
        require_exact_completion_comment(writer, comment_path, report)
        result.append(
            {
                "labels": sorted(live_labels),
                "number": number,
                "repository": repository,
                "state": "closed",
                "url": live.get("html_url") or f"https://github.com/{repository}/issues/{number}",
                "work_id": specification["work_id"],
            }
        )
    return result


def close_authority_issue(
    writer: GitHubWriter,
    config: dict[str, Any],
    completion: dict[str, Any],
) -> dict[str, Any]:
    issue = config["authority_issue"]
    path = f"/repos/{issue['repository']}/issues/{issue['number']}"
    current = writer.get(path)
    if not isinstance(current, dict):
        raise ContinuityError("parent continuity issue has an invalid GitHub response")
    current_labels = {
        label.get("name") for label in current.get("labels", []) if isinstance(label, dict) and label.get("name")
    }
    required_parent_labels = set(config["required_issue_labels"])
    authority_labels = {
        label
        for label in required_parent_labels
        if not label.startswith("status:") and not label.startswith("completion:")
    }
    parent_statuses = {label for label in current_labels if label.startswith("status:")}
    parent_completions = {label for label in current_labels if label.startswith("completion:")}
    parent_ready = (
        current.get("state") == "open"
        and required_parent_labels <= current_labels
        and parent_statuses == {"status:ready"}
        and parent_completions == {"completion:evidence-required"}
    )
    parent_completed = (
        current.get("state") == "closed"
        and authority_labels <= current_labels
        and parent_statuses == {"status:done"}
        and parent_completions == {"completion:evidence-verified"}
    )
    if not has_exact_work_id(current, issue["work_id"]) or not (parent_ready or parent_completed):
        raise ContinuityError("parent continuity issue lost its protected authority before completion")

    evidence_work_items = load_evidence_work_items(writer, config)
    blockers = converge_routed_blockers(writer, config, completion)
    completed_work_items = converge_evidence_work_items(writer, config, completion, evidence_work_items)
    current = writer.get(path)
    if not isinstance(current, dict):
        raise ContinuityError("parent continuity issue has an invalid GitHub response")
    current_labels = {
        label.get("name") for label in current.get("labels", []) if isinstance(label, dict) and label.get("name")
    }
    parent_statuses = {label for label in current_labels if label.startswith("status:")}
    parent_completions = {label for label in current_labels if label.startswith("completion:")}
    parent_ready = (
        current.get("state") == "open"
        and required_parent_labels <= current_labels
        and parent_statuses == {"status:ready"}
        and parent_completions == {"completion:evidence-required"}
    )
    parent_completed = (
        current.get("state") == "closed"
        and authority_labels <= current_labels
        and parent_statuses == {"status:done"}
        and parent_completions == {"completion:evidence-verified"}
    )
    if not has_exact_work_id(current, issue["work_id"]) or not (parent_ready or parent_completed):
        raise ContinuityError("parent continuity issue lost its protected authority before completion")
    comment_path = f"{path}/comments"
    report = completion_report_body(config, completion, blockers, completed_work_items)
    ensure_exact_completion_comment(writer, comment_path, report)

    labels = {label.get("name") for label in current.get("labels", []) if isinstance(label, dict) and label.get("name")}
    labels.discard("status:ready")
    labels.discard("status:blocked")
    labels.discard("completion:evidence-required")
    labels.update({"status:done", "completion:evidence-verified"})
    parent_kind = require_exact_issue_kind(required_parent_labels, "parent continuity issue")
    labels = replace_issue_kind(labels, parent_kind, "parent continuity issue completion")
    if current.get("state") != "closed" or labels != current_labels:
        writer.request("PATCH", path, {"labels": sorted(labels), "state": "closed"})
    live_parent = writer.get(path)
    live_labels = {
        label.get("name") for label in live_parent.get("labels", []) if isinstance(label, dict) and label.get("name")
    }
    if (
        live_parent.get("state") != "closed"
        or authority_labels - live_labels
        or {label for label in live_labels if label.startswith("status:")} != {"status:done"}
        or {label for label in live_labels if label.startswith("completion:")} != {"completion:evidence-verified"}
        or not has_exact_work_id(live_parent, issue["work_id"])
    ):
        raise ContinuityError("parent continuity issue did not converge to verified completion")
    require_exact_completion_comment(writer, comment_path, report)
    return {
        "blockers": blockers,
        "evidence_work_items": completed_work_items,
        "parent": {
            "labels": sorted(live_labels),
            "number": issue["number"],
            "repository": issue["repository"],
            "state": "closed",
            "url": live_parent.get("html_url") or f"https://github.com/{issue['repository']}/issues/{issue['number']}",
        },
    }


def advance_command(
    config_path: Path,
    plan_path: Path,
    state_path: Path,
    qualification_path: Path | None,
    output: Path | None,
) -> None:
    config = load_config(config_path)
    plan = load_json(plan_path, "release plan")
    validate_recorded_release_plan(plan)
    github_token = os.environ.get("GITHUB_TOKEN")
    authority_token = os.environ.get("BETA_PRODUCT_WORK_TOKEN")
    client = PublicClient(github_token)
    writer = GitHubWriter(authority_token or "", os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    dispatcher = GitHubWriter(github_token or "", os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    issue = authority_issue(config, client, allow_completed=True)
    run = {
        "id": os.environ.get("GITHUB_RUN_ID", "local"),
        "attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
        "repository": os.environ.get("GITHUB_REPOSITORY", CONTROL_REPOSITORY),
        "sha": os.environ.get("GITHUB_SHA", "0" * 40),
    }

    if issue["state"] == "closed":
        complete_commit = public_phase_commit(client, plan, "complete")
        noop_commit = public_phase_commit(client, plan, "no-op-confirmed")
        if complete_commit is None or noop_commit is None:
            raise ContinuityError(
                "authority issue closed without immutable complete and scheduled no-op continuity phases"
            )
        evidence = read_public_json_file(client, noop_commit, "continuity-evidence.json")
        completion_authority = exact_completion_authority(client, config, plan, complete_commit, noop_commit)
        close_authority_issue(writer, config, completion_authority)
        state_path.write_bytes(canonical_json(evidence))
        write_github_output(
            output,
            {"phase": "no-op-confirmed", "plan_tag": f"{PLAN_TAG_PREFIX}{plan['plan']}"},
        )
        return

    accepted_commit = public_phase_commit(client, plan, "accepted")
    if accepted_commit is None:
        if qualification_path is None or not qualification_path.exists():
            raise ContinuityError("first continuity acceptance requires exact target qualification evidence")
        public_at_acceptance, pending_at_acceptance = component_publications(client, plan)
        if not pending_at_acceptance:
            raise ContinuityError("continuity acceptance requires at least one component pending publication")
        evidence = base_evidence(config, issue, plan, "accepted", run)
        evidence.update(
            {
                "outcome": "accepted",
                "candidate_identity": {"components": plan["components"], "plan_sha256": manifest_digest(plan)},
                "credential_boundary": "GitHub protected beta product work environment",
                "pending_components_at_acceptance": pending_at_acceptance,
                "public_components_at_acceptance": public_at_acceptance,
                "superseded_interruption": superseded_interruption(config, client),
            }
        )
        record = record_phase(Path.cwd(), plan, "accepted", evidence, qualification_path=qualification_path)
        ensure_issue_comment(
            writer,
            config,
            plan,
            "accepted",
            record,
            "The public issue, exact target commits, protected checks, and candidate tuple are now remote authority.",
        )
        writer.dispatch(
            CONTROL_REPOSITORY,
            RELEASE_WORKFLOW,
            "main",
            {"release_plan": canonical_json(plan).decode().strip()},
        )
        state_path.write_bytes(canonical_json(evidence))
        write_github_output(output, {"phase": "accepted", "plan_tag": f"{PLAN_TAG_PREFIX}{plan['plan']}"})
        return

    complete_commit = public_phase_commit(client, plan, "complete")
    if complete_commit is not None:
        completion = read_public_json_file(client, complete_commit, "continuity-evidence.json")
        event = os.environ.get("GITHUB_EVENT_NAME", "local")
        noop_commit = public_phase_commit(client, plan, "no-op-confirmed")
        successful_noop = (
            successful_scheduled_noop_run(writer, completion, run)
            if event == "schedule" and noop_commit is None
            else None
        )
        if noop_commit is None and successful_noop is None:
            state = base_evidence(config, issue, plan, "complete", run)
            state.update(
                {
                    "outcome": "waiting-for-subsequent-scheduled-no-op",
                    "complete_phase": {"tag": phase_tag(plan, "complete"), "commit": complete_commit},
                }
            )
            state_path.write_bytes(canonical_json(state))
            write_github_output(output, {"phase": "complete", "plan_tag": f"{PLAN_TAG_PREFIX}{plan['plan']}"})
            return
        if noop_commit is None:
            evidence = base_evidence(config, issue, plan, "no-op-confirmed", run)
            evidence.update(
                {
                    "outcome": "successful-scheduled-no-op-confirmed",
                    "complete_phase": {"tag": phase_tag(plan, "complete"), "commit": complete_commit},
                    "successful_no_op_run": successful_noop,
                }
            )
            noop_record = record_phase(Path.cwd(), plan, "no-op-confirmed", evidence)
            ensure_issue_comment(
                writer,
                config,
                plan,
                "no-op-confirmed",
                noop_record,
                "A later scheduled controller run found the completed exact plan and performed no release work.",
            )
            noop_commit = noop_record["commit"]
        else:
            evidence = read_public_json_file(client, noop_commit, "continuity-evidence.json")
        completion_authority = exact_completion_authority(client, config, plan, complete_commit, noop_commit)
        close_authority_issue(writer, config, completion_authority)
        state_path.write_bytes(canonical_json(evidence))
        write_github_output(
            output,
            {"phase": "no-op-confirmed", "plan_tag": f"{PLAN_TAG_PREFIX}{plan['plan']}"},
        )
        return

    record = plan_record(client, plan)
    if record is None:
        ensure_dispatch(
            writer,
            CONTROL_REPOSITORY,
            RELEASE_WORKFLOW,
            "main",
            {"release_plan": canonical_json(plan).decode().strip()},
            plan["plan"],
        )
        state = base_evidence(config, issue, plan, "accepted", run)
        state.update({"outcome": "waiting-for-immutable-plan"})
        state_path.write_bytes(canonical_json(state))
        write_github_output(output, {"phase": "accepted", "plan_tag": f"{PLAN_TAG_PREFIX}{plan['plan']}"})
        return

    acceptance = accepted_publication_state(client, plan, accepted_commit)
    published, pending = component_publications(client, plan)
    interrupted_commit = public_phase_commit(client, plan, "interrupted")
    if interrupted_commit is None:
        interruption_triggers = recovery_publication_triggers(writer, record["tag"], acceptance, published)
    else:
        interruption_triggers = validate_interrupted_evidence(
            client,
            plan,
            interrupted_commit,
            acceptance,
        )

    if interrupted_commit is None and not interruption_triggers:
        recovery_candidates = [name for name in acceptance["pending_components"] if name in pending]
        if not recovery_candidates:
            raise ContinuityError(
                "all acceptance-pending components became public without a qualifying exact-plan recovery; "
                "a new continuity identity must supersede this plan"
            )
        first_component = config["first_component"]
        recovery_component = first_component if first_component in recovery_candidates else recovery_candidates[0]
        dispatch_recovery(writer, recovery_component, record["tag"])
        state = base_evidence(config, issue, plan, "publication-started", run)
        state.update(
            {
                "outcome": "waiting-for-post-acceptance-recovery-publication",
                "acceptance_publication_state": acceptance,
                "plan_record": record,
                "published_components": published,
                "pending_components": pending,
                "recovery_component": recovery_component,
            }
        )
        state_path.write_bytes(canonical_json(state))
        write_github_output(output, {"phase": "publication-started", "plan_tag": record["tag"]})
        return

    if interrupted_commit is None:
        require_partial_publication(published, pending)
        evidence = base_evidence(config, issue, plan, "interrupted", run)
        evidence.update(
            {
                "outcome": "intentionally-interrupted",
                "accepted_phase": {"tag": acceptance["tag"], "commit": acceptance["commit"]},
                "interruption_triggers": interruption_triggers,
                "plan_record": record,
                "published_components": published,
                "pending_components": pending,
                "resume_contract": "A later GitHub run must dispatch this exact immutable plan tag.",
            }
        )
        phase_record = record_phase(Path.cwd(), plan, "interrupted", evidence)
        ensure_issue_comment(
            writer,
            config,
            plan,
            "interrupted",
            phase_record,
            (
                f"The controller yielded after {len(interruption_triggers)} acceptance-pending component(s) "
                f"became public through exact-plan repository recovery; {len(pending)} remain."
            ),
        )
        state_path.write_bytes(canonical_json(evidence))
        write_github_output(output, {"phase": "interrupted", "plan_tag": record["tag"]})
        return

    resumed_commit = public_phase_commit(client, plan, "resumed")
    if resumed_commit is None:
        workflows = {name: dispatch_recovery(writer, name, record["tag"]) for name in COMPONENTS}
        evidence = base_evidence(config, issue, plan, "resumed", run)
        evidence.update(
            {
                "outcome": "resumed-identical-plan",
                "interrupted_phase": {"tag": phase_tag(plan, "interrupted"), "commit": interrupted_commit},
                "plan_record": record,
                "published_components_at_resume": published,
                "pending_components_at_resume": pending,
                "repository_recovery_workflows": workflows,
            }
        )
        phase_record = record_phase(Path.cwd(), plan, "resumed", evidence)
        ensure_issue_comment(
            writer,
            config,
            plan,
            "resumed",
            phase_record,
            "All seven repository-owned recovery workflows received the identical immutable plan tag.",
        )
        state_path.write_bytes(canonical_json(evidence))
        write_github_output(output, {"phase": "resumed", "plan_tag": record["tag"]})
        return

    if pending:
        for name in pending:
            dispatch_recovery(writer, name, record["tag"])
        state = base_evidence(config, issue, plan, "resumed", run)
        state.update(
            {
                "outcome": "recovering",
                "plan_record": record,
                "published_components": published,
                "pending_components": pending,
            }
        )
        state_path.write_bytes(canonical_json(state))
        write_github_output(output, {"phase": "resumed", "plan_tag": record["tag"]})
        return

    completion_tag = f"release-candidate/{plan['channel']}/{plan['plan']}"
    completion_commit = resolve_tag(client, CONTROL_REPOSITORY, completion_tag)
    if completion_commit is None:
        ensure_dispatch(
            writer,
            CONTROL_REPOSITORY,
            OBSERVER_WORKFLOW,
            "main",
            {"plan_tag": record["tag"]},
            record["tag"],
        )
        state = base_evidence(config, issue, plan, "public-verification", run)
        state.update({"outcome": "waiting-for-verification", "published_components": published})
        state_path.write_bytes(canonical_json(state))
        write_github_output(output, {"phase": "public-verification", "plan_tag": record["tag"]})
        return

    conformance = conformance_evidence(client, plan)
    requested_commit = public_phase_commit(client, plan, "conformance-requested")
    if conformance is None:
        candidate = candidate_manifest(plan)
        candidate_tag = f"beta-candidate/{candidate['candidate']}"
        candidate_commit = resolve_tag(client, CONTROL_REPOSITORY, candidate_tag)
        if candidate_commit is None:
            ensure_dispatch(
                dispatcher,
                CONTROL_REPOSITORY,
                CANDIDATE_WORKFLOW,
                "main",
                {"candidate_manifest": canonical_json(candidate).decode().strip()},
                candidate["candidate"],
            )
            state = base_evidence(config, issue, plan, "candidate-verification", run)
            state.update(
                {
                    "outcome": "waiting-for-immutable-candidate",
                    "candidate": candidate,
                    "public_verification": {"tag": completion_tag, "commit": completion_commit},
                }
            )
            state_path.write_bytes(canonical_json(state))
            write_github_output(output, {"phase": "candidate-verification", "plan_tag": record["tag"]})
            return
        progress = ensure_conformance_execution_or_retention(dispatcher, candidate)
        if requested_commit is None:
            evidence = base_evidence(config, issue, plan, "conformance-requested", run)
            evidence.update(
                {
                    "outcome": "requested-clean-github-runner-conformance",
                    "candidate": {"manifest": candidate, "tag": candidate_tag, "commit": candidate_commit},
                    "public_verification": {"tag": completion_tag, "commit": completion_commit},
                    "conformance_progress": progress,
                }
            )
            phase_record = record_phase(Path.cwd(), plan, "conformance-requested", evidence)
            ensure_issue_comment(
                writer,
                config,
                plan,
                "conformance-requested",
                phase_record,
                "Public verification passed and exact-tuple conformance execution or retention was requested.",
            )
            state_path.write_bytes(canonical_json(evidence))
        else:
            state = base_evidence(config, issue, plan, "conformance-requested", run)
            state.update(
                {
                    "outcome": progress["outcome"],
                    "conformance_progress": progress,
                }
            )
            state_path.write_bytes(canonical_json(state))
        write_github_output(output, {"phase": "conformance-requested", "plan_tag": record["tag"]})
        return

    complete_commit = public_phase_commit(client, plan, "complete")
    if complete_commit is None:
        evidence = base_evidence(config, issue, plan, "complete", run)
        evidence.update(
            {
                "outcome": "passed",
                "accepted_phase": phase_tag(plan, "accepted"),
                "interrupted_phase": phase_tag(plan, "interrupted"),
                "resumed_phase": phase_tag(plan, "resumed"),
                "plan_record": record,
                "public_verification": {"tag": completion_tag, "commit": completion_commit},
                "conformance": conformance,
                "published_components": published,
            }
        )
        phase_record = record_phase(Path.cwd(), plan, "complete", evidence)
        ensure_issue_comment(
            writer,
            config,
            plan,
            "complete",
            phase_record,
            (
                "The interrupted seven-artifact release, public verification, and exact-tuple conformance all "
                "passed. The authority remains open for a later scheduled no-op confirmation."
            ),
        )
        state_path.write_bytes(canonical_json(evidence))
    else:
        evidence = read_public_json_file(client, complete_commit, "continuity-evidence.json")
        state_path.write_bytes(canonical_json(evidence))
    write_github_output(output, {"phase": "complete", "plan_tag": record["tag"]})


def blocker_body(config: dict[str, Any], blocker: dict[str, str], selection: dict[str, Any]) -> str:
    issue = config["authority_issue"]
    selection_url = f"https://github.com/{CONTROL_REPOSITORY}/tree/{selection['tag']}"
    return (
        "## Classification\n\n"
        "Beta continuity release blocker owned by this repository.\n\n"
        "## Evidence\n\n"
        f"The GitHub-only continuity planner retained its version selection at {selection_url}, then paused: "
        f"{blocker['reason']}.\n\n"
        "## Acceptance criteria\n\n"
        f"- Version `{blocker['version']}` is prepared from the default branch and published without rewriting "
        "history.\n"
        "- The repository-owned Release plan recovery workflow accepts that exact source and prepared plan.\n"
        "- Protected target qualification is green before the continuity planner retries.\n\n"
        "## Dependency\n\n"
        f"Blocks https://github.com/{issue['repository']}/issues/{issue['number']}.\n\n"
        f"<!-- beta-continuity-blocker: {blocker['slug']} -->\n"
    )


def consolidated_blocker_finding(blocker: dict[str, str], selection: dict[str, Any]) -> str:
    selection_url = f"https://github.com/{CONTROL_REPOSITORY}/tree/{selection['tag']}"
    return (
        f"## Consolidated continuity finding: {blocker['component']}\n\n"
        f"The retained [continuity selection]({selection_url}) cannot advance because "
        f"{blocker['reason']}.\n\n"
        "### Additional acceptance criteria\n\n"
        f"- Prepare and qualify version `{blocker['version']}` from the repository default branch.\n"
        "- Resume the same retained release selection after this condition clears.\n\n"
        f"<!-- beta-continuity-consolidated-finding: {blocker['slug']} -->\n"
    )


def _continuity_creation_budget(
    config: dict[str, Any],
    issues: list[dict[str, Any]],
) -> tuple[list[str], dict[str, Any] | None]:
    budget = config["public_issue_budget"]
    now = dt.datetime.now(dt.UTC)

    def labels(issue: dict[str, Any]) -> set[str]:
        return {
            str(label["name"])
            for label in issue.get("labels", [])
            if isinstance(label, dict) and isinstance(label.get("name"), str)
        }

    open_issues = [
        issue
        for issue in issues
        if (
            isinstance(issue, dict)
            and "pull_request" not in issue
            and issue.get("state") == "open"
        )
    ]
    actionable = [
        issue
        for issue in open_issues
        if "authority:github" in labels(issue)
        and not labels(issue) & {"status:done", "status:superseded"}
    ]

    def created_at(issue: dict[str, Any]) -> dt.datetime | None:
        value = issue.get("created_at")
        if value is None:
            return None
        try:
            return parse_github_timestamp(value, "routed blocker creation timestamp")
        except ContinuityError:
            return None

    reasons: list[str] = []
    if len(actionable) >= int(budget["max_open_actionable"]):
        reasons.append("open-actionable-budget")
    if any(
        created is not None and int((now - created).total_seconds()) >= int(budget["stale_age_seconds"])
        for issue in open_issues
        if (created := created_at(issue)) is not None
    ):
        reasons.append("open-issue-older-than-7d")
    roots = [
        issue
        for issue in actionable
        if {"authority:github", "kind:release-blocker"} <= labels(issue)
        and isinstance(issue.get("body"), str)
        and type(issue.get("number")) is int
    ]
    root = min(
        roots,
        key=lambda issue: (
            created_at(issue) or dt.datetime.max.replace(tzinfo=dt.UTC),
            int(issue["number"]),
        ),
        default=None,
    )
    return reasons, root


def route_blockers(config_path: Path, state_path: Path) -> None:
    config = load_config(config_path)
    state = load_json(state_path, "continuity planning state")
    blockers = state.get("blockers")
    selection = state.get("selection")
    if state.get("outcome") != "blocked" or not isinstance(blockers, list) or not blockers:
        raise ContinuityError("continuity planning state contains no routable blockers")
    if not isinstance(selection, dict) or not isinstance(selection.get("tag"), str):
        raise ContinuityError("continuity planning state has no immutable version selection")
    writer = GitHubWriter(
        os.environ.get("BETA_PRODUCT_WORK_TOKEN", ""),
        os.environ.get("GITHUB_API_URL", "https://api.github.com"),
    )
    routing: list[dict[str, Any]] = []
    for blocker in blockers:
        repository = blocker["repository"]
        issues = writer.list(f"/repos/{repository}/issues?state=all")
        routed = [
            (issue["number"], issue)
            for issue in issues
            if isinstance(issue, dict)
            and "pull_request" not in issue
            and is_exact_routed_blocker(
                config,
                issue,
                blocker["component"],
                blocker["version"],
            )
            and has_routed_blocker_authority(issue)
            and isinstance(issue.get("number"), int)
        ]
        if routed:
            number, issue = min(routed, key=lambda item: item[0])
            labels = {label["name"] for label in issue["labels"]}
            desired_labels = {
                label for label in labels if not label.startswith("status:") and not label.startswith("completion:")
            }
            desired_labels.add("status:ready")
            desired_labels = replace_issue_kind(
                desired_labels,
                "kind:release-blocker",
                f"routed blocker {repository}#{number}",
            )
            if issue.get("state") != "open" or labels != desired_labels:
                writer.request(
                    "PATCH",
                    f"/repos/{repository}/issues/{number}",
                    {"state": "open", "labels": sorted(desired_labels)},
                )
            routing.append({"action": "reused", "number": number, "repository": repository})
            continue
        budget_reasons, root = _continuity_creation_budget(config, issues)
        if budget_reasons:
            if root is not None:
                marker = f"<!-- beta-continuity-consolidated-finding: {blocker['slug']} -->"
                body = str(root["body"])
                if marker not in body:
                    body = f"{body.rstrip()}\n\n{consolidated_blocker_finding(blocker, selection)}"
                    writer.request(
                        "PATCH",
                        f"/repos/{repository}/issues/{root['number']}",
                        {"body": body},
                    )
                    root["body"] = body
                routing.append(
                    {
                        "action": "consolidated",
                        "budget_reasons": budget_reasons,
                        "number": int(root["number"]),
                        "repository": repository,
                    }
                )
            else:
                routing.append(
                    {
                        "action": "retained-private-audit",
                        "budget_reasons": budget_reasons,
                        "repository": repository,
                    }
                )
            continue
        component = blocker["component"]
        writer.request(
            "POST",
            f"/repos/{repository}/issues",
            {
                "title": f"Release blocker: prepare {component} source for GitHub continuity",
                "body": blocker_body(config, blocker, selection),
                "labels": list(ROUTED_BLOCKER_LABELS),
            },
        )
        routing.append({"action": "created", "repository": repository})
    state["routing"] = sorted(routing, key=lambda record: (record["repository"], record["action"]))
    state_path.write_bytes(canonical_json(state))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    plan = commands.add_parser("plan")
    plan.add_argument("config", type=Path)
    plan.add_argument("release_plan", type=Path)
    plan.add_argument("expected_commits", type=Path)
    plan.add_argument("state", type=Path)
    plan.add_argument("--github-output", type=Path)
    plan.add_argument("--expected-plan-tag")

    callback = commands.add_parser("dispatch-accepted")
    callback.add_argument("release_plan", type=Path)
    callback.add_argument("--github-output", type=Path)

    advance = commands.add_parser("advance")
    advance.add_argument("config", type=Path)
    advance.add_argument("release_plan", type=Path)
    advance.add_argument("state", type=Path)
    advance.add_argument("--qualification", type=Path)
    advance.add_argument("--github-output", type=Path)

    blockers = commands.add_parser("route-blockers")
    blockers.add_argument("config", type=Path)
    blockers.add_argument("state", type=Path)

    source = commands.add_parser("resolution-source")
    source.add_argument("--expected-run-id", type=int, required=True)
    source.add_argument("--expected-run-attempt", type=int, required=True)
    source.add_argument("--github-output", type=Path)

    resolution = commands.add_parser("record-resolution")
    resolution.add_argument("selection", type=Path)
    resolution.add_argument("--source-sha", required=True)
    resolution.add_argument("--run-id", type=int, required=True)
    resolution.add_argument("--run-attempt", type=int, required=True)
    resolution.add_argument("--remote", default="origin")

    args = parser.parse_args()
    try:
        if args.command == "plan":
            plan_command(
                args.config,
                args.release_plan,
                args.expected_commits,
                args.state,
                args.github_output,
                args.expected_plan_tag,
            )
        elif args.command == "dispatch-accepted":
            dispatch_accepted_continuity(args.release_plan, args.github_output)
        elif args.command == "advance":
            advance_command(
                args.config,
                args.release_plan,
                args.state,
                args.qualification,
                args.github_output,
            )
        elif args.command == "route-blockers":
            route_blockers(args.config, args.state)
        elif args.command == "resolution-source":
            result = resolution_source_command(
                args.expected_run_id,
                args.expected_run_attempt,
                args.github_output,
            )
            print(json.dumps(result, sort_keys=True))
        else:
            result = record_continuity_resolution(
                Path.cwd(),
                args.selection,
                source_sha=args.source_sha,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                remote=args.remote,
            )
            print(json.dumps(result, sort_keys=True))
    except PlanBlocked as error:
        print(f"beta continuity planning blocked: {error}", file=sys.stderr)
        return 2
    except (CandidateError, ContinuityError) as error:
        print(f"beta continuity error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
