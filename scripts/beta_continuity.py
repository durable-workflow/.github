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
    write_github_output,
)
from scripts.release_plan import (
    EXPECTED_DEFAULT_BRANCHES,
    FOUNDATION_COMMIT,
    FOUNDATION_TAG,
    PLAN_TAG_PREFIX,
    candidate_manifest,
    discover_plan,
    resolve_tag,
    validate_plan,
)

SCHEMA = "durable-workflow.beta-continuity.config/v1"
EVIDENCE_SCHEMA = "durable-workflow.beta-continuity.evidence/v1"
SELECTION_SCHEMA = "durable-workflow.beta-continuity.selection/v1"
CONTROL_REPOSITORY = "durable-workflow/.github"
PHASE_TAG_PREFIX = "beta-continuity/"
SELECTION_TAG_PREFIX = "beta-continuity-selection/"
RELEASE_WORKFLOW = "release-plan.yml"
OBSERVER_WORKFLOW = "release-plan-observer.yml"
CANDIDATE_WORKFLOW = "beta-candidate.yml"
CONFORMANCE_WORKFLOW = "beta-conformance.yml"
WORK_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,79}$")
PLAN_PREFIX_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{0,35}$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
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
ROUTED_BLOCKER_LABELS = (
    "authority:github",
    "beta:blocker",
    "kind:release-blocker",
    "priority:P1",
    "status:ready",
)


class ContinuityError(RuntimeError):
    """The public continuity drill cannot safely advance."""


class PlanBlocked(ContinuityError):
    """The next public release plan has focused component blockers."""

    def __init__(self, blockers: list[dict[str, str]]) -> None:
        self.blockers = blockers
        super().__init__("; ".join(blocker["reason"] for blocker in blockers))


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


def load_config(path: Path) -> dict[str, Any]:
    value = load_json(path, "continuity config")
    if not isinstance(value, dict) or set(value) != {
        "$schema",
        "authority_issue",
        "channel",
        "drill",
        "first_component",
        "plan_prefix",
        "required_issue_labels",
        "superseded_interruption",
    }:
        raise ContinuityError("continuity config has an invalid top-level shape")
    if value.get("$schema") != "./schema.json" or value.get("channel") != "alpha":
        raise ContinuityError("continuity config must select the alpha prerelease channel and local schema")
    if not isinstance(value.get("drill"), str) or not WORK_ID_PATTERN.fullmatch(value["drill"]):
        raise ContinuityError("continuity drill has an invalid identity")
    if not isinstance(value.get("plan_prefix"), str) or not PLAN_PREFIX_PATTERN.fullmatch(value["plan_prefix"]):
        raise ContinuityError("continuity plan prefix has an invalid identity")
    if value.get("first_component") not in COMPONENTS:
        raise ContinuityError("continuity first component is unknown")
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
    labels = value.get("required_issue_labels")
    if not isinstance(labels, list) or not labels or not all(isinstance(label, str) and label for label in labels):
        raise ContinuityError("continuity required issue labels are invalid")
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


def authority_issue(config: dict[str, Any], client: PublicClient, *, allow_completed: bool = False) -> dict[str, Any]:
    specification = config["authority_issue"]
    issue = client.json(f"https://api.github.com/repos/{specification['repository']}/issues/{specification['number']}")
    labels = {label.get("name") for label in issue.get("labels", []) if isinstance(label, dict) and label.get("name")}
    missing = set(config["required_issue_labels"]) - labels
    marker = f"<!-- beta-work-id: {specification['work_id']} -->"
    completed = (
        allow_completed and issue.get("state") == "closed" and {"status:done", "completion:evidence-verified"} <= labels
    )
    if (
        (issue.get("state") != "open" and not completed)
        or (missing and not completed)
        or marker not in str(issue.get("body", ""))
    ):
        raise ContinuityError(
            f"authority issue is not ready: state={issue.get('state')}, missing_labels={sorted(missing)}, "
            f"work_id_marker={marker in str(issue.get('body', ''))}"
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


def public_release_tags(client: PublicClient, repository: str) -> list[str]:
    releases = client.json(f"https://api.github.com/repos/{repository}/releases?per_page=100")
    if not isinstance(releases, list):
        raise ContinuityError(f"{repository} releases response is invalid")
    return [str(release["tag_name"]) for release in releases if not release.get("draft") and release.get("tag_name")]


def has_routed_blocker_authority(issue: dict[str, Any]) -> bool:
    labels = issue.get("labels")
    if not isinstance(labels, list):
        return False
    names: set[str] = set()
    for label in labels:
        if not isinstance(label, dict) or not isinstance(label.get("name"), str) or not label["name"]:
            return False
        names.add(label["name"])
    return set(ROUTED_BLOCKER_LABELS) <= names


def routed_blocker_version(config: dict[str, Any], client: PublicClient, component_name: str) -> str | None:
    repository = COMPONENTS[component_name].repository
    issues = client.json(f"https://api.github.com/repos/{repository}/issues?state=all&per_page=100")
    if not isinstance(issues, list):
        raise ContinuityError(f"{repository} issues response is invalid")
    authority = config["authority_issue"]
    dependency = f"Blocks https://github.com/{authority['repository']}/issues/{authority['number']}."
    marker = re.compile(
        rf"<!-- beta-continuity-blocker: {re.escape(component_name)}-"
        r"(?:source-version|occupied-version)-(?P<version>[^ ]+) -->"
    )
    candidates: list[tuple[int, str]] = []
    for issue in issues:
        if not isinstance(issue, dict) or "pull_request" in issue:
            continue
        body = str(issue.get("body", ""))
        match = marker.search(body)
        version = match.group("version") if match else None
        number = issue.get("number")
        if (
            dependency in body
            and has_routed_blocker_authority(issue)
            and isinstance(number, int)
            and isinstance(version, str)
            and VERSION_PATTERN.fullmatch(version)
        ):
            candidates.append((number, version))
    return min(candidates)[1] if candidates else None


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
    versions: dict[str, str] = {}
    for name, component in COMPONENTS.items():
        previously_routed = routed_blocker_version(config, client, name)
        versions[name] = previously_routed or next_version(name, public_release_tags(client, component.repository))
    selection = {
        "schema": SELECTION_SCHEMA,
        "drill": config["drill"],
        "plan": selection_plan_name(config, versions),
        "channel": config["channel"],
        "versions": versions,
    }
    validate_selection(config, selection)
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
        "schema": "durable-workflow.release-plan/v1",
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
    validate_plan(plan)
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
    validate_plan(plan)
    return plan


def plan_command(
    config_path: Path,
    plan_path: Path,
    expected_path: Path,
    state_path: Path,
    output: Path | None,
) -> None:
    config = load_config(config_path)
    client = PublicClient(os.environ.get("GITHUB_TOKEN"))
    issue = authority_issue(config, client, allow_completed=True)
    accepted = accepted_plan(config, client)
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
    if (
        evidence.get("phase") != "accepted"
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
    validate_plan(recorded_plan)
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


def conformance_evidence(client: PublicClient, plan: dict[str, Any]) -> dict[str, Any] | None:
    candidate = candidate_manifest(plan)
    releases = client.json(f"https://api.github.com/repos/{CONTROL_REPOSITORY}/releases?per_page=100")
    prefix = f"beta-conformance/{candidate['candidate']}/"
    for release in releases:
        if release.get("draft") or not str(release.get("tag_name", "")).startswith(prefix):
            continue
        asset = next((item for item in release.get("assets", []) if item.get("name") == "suite-result.json"), None)
        if not isinstance(asset, dict) or not isinstance(asset.get("browser_download_url"), str):
            continue
        suite = client.json(asset["browser_download_url"])
        if (
            suite.get("schema") == "durable-workflow.beta-conformance.suite-result/v1"
            and suite.get("outcome") == "pass"
            and suite.get("candidate", {}).get("name") == candidate["candidate"]
            and suite.get("artifact_tuple") == plan["components"]
        ):
            return {
                "release": release.get("html_url"),
                "run": suite.get("github_run"),
                "tag": release.get("tag_name"),
            }
    return None


def close_authority_issue(writer: GitHubWriter, config: dict[str, Any], completion: dict[str, Any]) -> None:
    issue = config["authority_issue"]
    path = f"/repos/{issue['repository']}/issues/{issue['number']}"
    current = writer.get(path)
    labels = {label.get("name") for label in current.get("labels", []) if isinstance(label, dict) and label.get("name")}
    labels.discard("status:ready")
    labels.discard("status:blocked")
    labels.discard("completion:evidence-required")
    labels.update({"status:done", "completion:evidence-verified"})
    writer.request("PATCH", path, {"labels": sorted(labels), "state": "closed"})


def advance_command(
    config_path: Path,
    plan_path: Path,
    state_path: Path,
    qualification_path: Path | None,
    output: Path | None,
) -> None:
    config = load_config(config_path)
    plan = load_json(plan_path, "release plan")
    validate_plan(plan)
    github_token = os.environ.get("GITHUB_TOKEN")
    authority_token = os.environ.get("BETA_PRODUCT_WORK_TOKEN")
    client = PublicClient(github_token)
    writer = GitHubWriter(authority_token or "", os.environ.get("GITHUB_API_URL", "https://api.github.com"))
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
        else:
            evidence = read_public_json_file(client, noop_commit, "continuity-evidence.json")
        close_authority_issue(writer, config, evidence)
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
                writer,
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
        existing_run = ensure_dispatch(
            writer,
            CONTROL_REPOSITORY,
            CONFORMANCE_WORKFLOW,
            "main",
            {
                "candidate_manifest": canonical_json(candidate).decode().strip(),
                "injected_failure_experiment": "none",
            },
            candidate["candidate"],
        )
        if requested_commit is None:
            evidence = base_evidence(config, issue, plan, "conformance-requested", run)
            evidence.update(
                {
                    "outcome": "requested-clean-github-runner-conformance",
                    "candidate": {"manifest": candidate, "tag": candidate_tag, "commit": candidate_commit},
                    "public_verification": {"tag": completion_tag, "commit": completion_commit},
                    "existing_run": (
                        {"id": existing_run.get("id"), "url": existing_run.get("html_url")} if existing_run else None
                    ),
                }
            )
            phase_record = record_phase(Path.cwd(), plan, "conformance-requested", evidence)
            ensure_issue_comment(
                writer,
                config,
                plan,
                "conformance-requested",
                phase_record,
                "Public verification passed and exact-tuple conformance was requested on clean GitHub runners.",
            )
            state_path.write_bytes(canonical_json(evidence))
        else:
            state = base_evidence(config, issue, plan, "conformance-requested", run)
            state.update({"outcome": "waiting-for-conformance"})
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
    for blocker in blockers:
        repository = blocker["repository"]
        marker = f"<!-- beta-continuity-blocker: {blocker['slug']} -->"
        issues = writer.list(f"/repos/{repository}/issues?state=all")
        if any(marker in str(issue.get("body", "")) for issue in issues if "pull_request" not in issue):
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    plan = commands.add_parser("plan")
    plan.add_argument("config", type=Path)
    plan.add_argument("release_plan", type=Path)
    plan.add_argument("expected_commits", type=Path)
    plan.add_argument("state", type=Path)
    plan.add_argument("--github-output", type=Path)

    advance = commands.add_parser("advance")
    advance.add_argument("config", type=Path)
    advance.add_argument("release_plan", type=Path)
    advance.add_argument("state", type=Path)
    advance.add_argument("--qualification", type=Path)
    advance.add_argument("--github-output", type=Path)

    blockers = commands.add_parser("route-blockers")
    blockers.add_argument("config", type=Path)
    blockers.add_argument("state", type=Path)

    args = parser.parse_args()
    try:
        if args.command == "plan":
            plan_command(
                args.config,
                args.release_plan,
                args.expected_commits,
                args.state,
                args.github_output,
            )
        elif args.command == "advance":
            advance_command(
                args.config,
                args.release_plan,
                args.state,
                args.qualification,
                args.github_output,
            )
        else:
            route_blockers(args.config, args.state)
    except PlanBlocked as error:
        print(f"beta continuity planning blocked: {error}", file=sys.stderr)
        return 2
    except (CandidateError, ContinuityError) as error:
        print(f"beta continuity error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
