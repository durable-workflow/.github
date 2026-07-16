#!/usr/bin/env python3
"""Validate, record, discover, and observe immutable public release plans."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
from pathlib import Path
from typing import Any

from scripts.beta_candidate import (
    COMPONENTS,
    CandidateError,
    PublicClient,
    canonical_json,
    fetch_existing_record,
    manifest_digest,
    read_record_file,
    run_git,
    validate_verification,
    verify_candidate,
    write_github_output,
)

SCHEMA = "durable-workflow.release-plan/v1"
PLAN_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,55}$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
ALPHA_VERSION_PATTERN = re.compile(r"^2\.0\.0-alpha\.[1-9][0-9]*$")
BETA_VERSION_PATTERN = re.compile(r"^2\.0\.0-beta\.[1-9][0-9]*$")
PLAN_TAG_PREFIX = "release-plan/"
COMPLETION_TAG_PREFIX = "release-candidate/"
FOUNDATION_TAG = "beta-candidate/beta-continuity-foundation"
FOUNDATION_COMMIT = "4995052410bd4301c5796ffba54e0b6d2f490ed1"
CONTROL_REPOSITORY = "durable-workflow/.github"

EXPECTED_DEFAULT_BRANCHES = {
    "workflow": "v2",
    "waterline": "v2",
    "server": "main",
    "cli": "main",
    "sdk-php": "main",
    "sdk-python": "main",
    "sdk-rust": "main",
}


def load_plan(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CandidateError(f"cannot read release plan {path}: {error}") from error
    if len(raw) > 64 * 1024:
        raise CandidateError("release plan exceeds the 64 KiB limit")
    try:
        plan = json.loads(raw)
    except json.JSONDecodeError as error:
        raise CandidateError(f"release plan is not valid JSON: {error}") from error
    validate_plan(plan)
    return plan


def validate_plan(plan: Any) -> None:
    if not isinstance(plan, dict):
        raise CandidateError("release plan must be a JSON object")
    expected = {"schema", "plan", "channel", "foundation", "components", "beta_authorization"}
    if set(plan) != expected:
        raise CandidateError(f"release plan keys must be exactly {sorted(expected)}")
    if plan["schema"] != SCHEMA:
        raise CandidateError(f"release plan schema must be {SCHEMA}")
    if not isinstance(plan["plan"], str) or not PLAN_PATTERN.fullmatch(plan["plan"]):
        raise CandidateError("plan must be 1-56 lowercase letters, digits, dots, underscores, or hyphens")
    if plan["channel"] not in {"alpha", "beta"}:
        raise CandidateError("release channel must be alpha or beta")
    if plan["foundation"] != {"tag": FOUNDATION_TAG, "commit": FOUNDATION_COMMIT}:
        raise CandidateError("release plan must name the proven immutable candidate foundation")

    components = plan["components"]
    if not isinstance(components, dict) or set(components) != set(COMPONENTS):
        raise CandidateError(f"components must be exactly {sorted(COMPONENTS)}")
    for name, identity in components.items():
        if not isinstance(identity, dict) or set(identity) != {"version", "commit"}:
            raise CandidateError(f"components.{name} must contain only version and commit")
        if not isinstance(identity["version"], str) or not VERSION_PATTERN.fullmatch(identity["version"]):
            raise CandidateError(f"components.{name}.version must be an exact SemVer release")
        if not isinstance(identity["commit"], str) or not COMMIT_PATTERN.fullmatch(identity["commit"]):
            raise CandidateError(f"components.{name}.commit must be a full lowercase Git commit identity")

    prerelease_pattern = ALPHA_VERSION_PATTERN if plan["channel"] == "alpha" else BETA_VERSION_PATTERN
    for component in ("workflow", "waterline"):
        version = components[component]["version"]
        if not prerelease_pattern.fullmatch(version):
            raise CandidateError(f"{component} version {version} is not an exact 2.0.0-{plan['channel']}.N identity")

    authorization = plan["beta_authorization"]
    if plan["channel"] == "alpha":
        if authorization is not None:
            raise CandidateError("alpha release plans must not claim beta authorization")
    elif (
        not isinstance(authorization, dict)
        or set(authorization) != {"tag", "commit"}
        or not re.fullmatch(r"beta-authorization/[a-z0-9][a-z0-9._-]{0,55}", str(authorization.get("tag", "")))
        or not COMMIT_PATTERN.fullmatch(str(authorization.get("commit", "")))
    ):
        raise CandidateError("beta release plans require an immutable beta authorization tag and commit")


def resolve_tag(client: PublicClient, repository: str, tag: str) -> str | None:
    encoded = urllib.parse.quote(tag, safe="")
    url = f"https://api.github.com/repos/{repository}/git/ref/tags/{encoded}"
    try:
        ref = client.json(url)
    except CandidateError as error:
        if "(404)" in str(error):
            return None
        raise
    target = ref.get("object", {})
    seen: set[str] = set()
    while target.get("type") == "tag":
        sha = target.get("sha")
        if not isinstance(sha, str) or sha in seen:
            raise CandidateError(f"invalid annotated tag chain for {repository}@{tag}")
        seen.add(sha)
        target = client.json(f"https://api.github.com/repos/{repository}/git/tags/{sha}").get("object", {})
    if target.get("type") != "commit" or not COMMIT_PATTERN.fullmatch(str(target.get("sha", ""))):
        raise CandidateError(f"tag {repository}@{tag} does not resolve to a commit")
    return str(target["sha"])


def read_public_record(client: PublicClient, tag: str, commit: str, filename: str) -> Any:
    resolved = resolve_tag(client, CONTROL_REPOSITORY, tag)
    if resolved != commit:
        raise CandidateError(f"public record {tag} resolves to {resolved or 'no commit'}, not {commit}")
    encoded_name = urllib.parse.quote(filename, safe="/")
    raw = client.bytes(
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/contents/{encoded_name}?ref={commit}",
        accept="application/vnd.github.raw+json",
    )
    try:
        return json.loads(raw)
    except json.JSONDecodeError as error:
        raise CandidateError(f"public record {tag}:{filename} is not valid JSON") from error


def verify_beta_authorization(client: PublicClient, plan: dict[str, Any]) -> None:
    authorization = plan["beta_authorization"]
    if authorization is None:
        return
    record = read_public_record(client, authorization["tag"], authorization["commit"], "beta-authorization.json")
    expected = {
        "schema": "durable-workflow.beta-authorization/v1",
        "channel": "beta",
        "candidate": plan["plan"],
        "components": plan["components"],
    }
    if record != expected:
        raise CandidateError("beta authorization does not name the same candidate and seven-component tuple")


def require_prior_plans_completed(plan: dict[str, Any], client: PublicClient) -> dict[str, dict[str, str]]:
    refs = client.json(f"https://api.github.com/repos/{CONTROL_REPOSITORY}/git/matching-refs/tags/{PLAN_TAG_PREFIX}")
    if not isinstance(refs, list):
        raise CandidateError("GitHub did not return the immutable release-plan tag registry")
    requested_tag = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    completed: dict[str, dict[str, str]] = {}
    for ref in refs:
        name = str(ref.get("ref", ""))
        if not name.startswith("refs/tags/"):
            continue
        tag = name.removeprefix("refs/tags/")
        if not tag.startswith(PLAN_TAG_PREFIX) or tag == requested_tag:
            continue
        record_commit = resolve_tag(client, CONTROL_REPOSITORY, tag)
        if record_commit is None:
            raise CandidateError(f"prior release plan {tag} has no immutable Git record")
        prior = read_public_record(client, tag, record_commit, "release-plan.json")
        validate_plan(prior)
        if tag != f"{PLAN_TAG_PREFIX}{prior['plan']}":
            raise CandidateError(f"prior release plan {tag} has a different document identity")
        completion_tag = f"{COMPLETION_TAG_PREFIX}{prior['channel']}/{prior['plan']}"
        completion_commit = resolve_tag(client, CONTROL_REPOSITORY, completion_tag)
        if completion_commit is None:
            raise CandidateError(
                f"cannot record {requested_tag} while prior plan {tag} is incomplete; "
                f"resume its repository Release plan recovery actions"
            )
        completion = read_public_record(
            client,
            completion_tag,
            completion_commit,
            "release-candidate.json",
        )
        if completion != completion_manifest(prior, record_commit):
            raise CandidateError(f"prior completion record {completion_tag} does not prove {tag}")
        completed[tag] = {"completion_tag": completion_tag, "completion_commit": completion_commit}
    return completed


def preflight_plan(plan: dict[str, Any], client: PublicClient) -> dict[str, Any]:
    foundation = read_public_record(client, FOUNDATION_TAG, FOUNDATION_COMMIT, "candidate.json")
    if foundation.get("candidate") != "beta-continuity-foundation":
        raise CandidateError("immutable candidate foundation has an unexpected identity")

    prior_plans = require_prior_plans_completed(plan, client)
    branches: dict[str, str] = {}
    recovery_workflows: dict[str, dict[str, Any]] = {}
    tags: dict[str, str] = {}
    for name, component in COMPONENTS.items():
        repository = client.json(f"https://api.github.com/repos/{component.repository}")
        default_branch = repository.get("default_branch")
        expected_branch = EXPECTED_DEFAULT_BRANCHES[name]
        if default_branch != expected_branch:
            raise CandidateError(
                f"{component.repository} default branch is {default_branch!r}; "
                f"release plans require {expected_branch!r}"
            )
        branches[name] = default_branch

        workflow = client.json(
            f"https://api.github.com/repos/{component.repository}/actions/workflows/release-plan-recovery.yml"
        )
        expected_path = ".github/workflows/release-plan-recovery.yml"
        if workflow.get("path") != expected_path or workflow.get("state") != "active":
            raise CandidateError(
                f"{component.repository} does not expose an active {expected_path} on its default branch"
            )
        contents_url = (
            f"https://api.github.com/repos/{component.repository}/contents/{expected_path}?ref={expected_branch}"
        )
        workflow_source = client.bytes(contents_url, accept="application/vnd.github.raw+json").decode("utf-8")
        if not re.search(r"(?m)^  schedule:\s*$", workflow_source) or not re.search(
            r"(?m)^  workflow_dispatch:\s*$", workflow_source
        ):
            raise CandidateError(
                f"{component.repository} recovery workflow lacks schedule or manual dispatch on {expected_branch}"
            )
        recovery_workflows[name] = {
            "default_branch": expected_branch,
            "path": expected_path,
            "state": workflow["state"],
            "workflow_id": workflow.get("id"),
            "url": workflow.get("html_url"),
        }

        identity = plan["components"][name]
        client.json(f"https://api.github.com/repos/{component.repository}/commits/{identity['commit']}")
        existing = resolve_tag(client, component.repository, identity["version"])
        if existing is not None and existing != identity["commit"]:
            raise CandidateError(
                f"existing version tag {component.repository}@{identity['version']} points to {existing}, "
                f"not {identity['commit']}"
            )
        tags[name] = existing or "absent"

    verify_beta_authorization(client, plan)
    return {
        "default_branches": branches,
        "prior_plans": prior_plans,
        "recovery_workflows": recovery_workflows,
        "version_tags": tags,
    }


def check_plan_compatibility(repository: Path, plan_path: Path, *, remote: str) -> dict[str, str]:
    plan = load_plan(plan_path)
    canonical = canonical_json(plan)
    tag = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    existing_ref = fetch_existing_record(repository, remote, tag)
    if not existing_ref:
        return {"status": "new", "plan": plan["plan"], "tag": tag}
    existing = read_record_file(repository, existing_ref, "release-plan.json")
    if existing != canonical:
        raise CandidateError(f"release plan {plan['plan']} is immutable and the requested tuple is different")
    return {
        "status": "existing",
        "plan": plan["plan"],
        "tag": tag,
        "commit": run_git(["rev-parse", f"{existing_ref}^{{commit}}"], cwd=repository),
    }


def record_plan(repository: Path, plan_path: Path, *, remote: str, authoritative_plan: Path) -> dict[str, str]:
    plan = load_plan(plan_path)
    canonical = canonical_json(plan)
    tag = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    existing_ref = fetch_existing_record(repository, remote, tag)
    if existing_ref:
        existing = read_record_file(repository, existing_ref, "release-plan.json")
        if existing != canonical:
            raise CandidateError(f"release plan {plan['plan']} is immutable and the requested tuple is different")
        authoritative_plan.write_bytes(existing)
        return {
            "status": "existing",
            "plan": plan["plan"],
            "tag": tag,
            "commit": run_git(["rev-parse", f"{existing_ref}^{{commit}}"], cwd=repository),
        }

    with tempfile.NamedTemporaryFile(prefix="release-plan-index-", delete=False) as index:
        index_path = Path(index.name)
    try:
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(index_path)
        index_path.unlink(missing_ok=True)
        run_git(["read-tree", "--empty"], cwd=repository, env=env)
        blob = (
            subprocess.run(
                ["git", "hash-object", "-w", "--stdin"],
                cwd=repository,
                env=env,
                input=canonical,
                check=True,
                stdout=subprocess.PIPE,
            )
            .stdout.decode()
            .strip()
        )
        run_git(["update-index", "--add", "--cacheinfo", f"100644,{blob},release-plan.json"], cwd=repository, env=env)
        tree = run_git(["write-tree"], cwd=repository, env=env)
        commit_env = env | {
            "GIT_AUTHOR_NAME": "Durable Workflow Release Planner",
            "GIT_AUTHOR_EMAIL": "support@durable-workflow.com",
            "GIT_COMMITTER_NAME": "Durable Workflow Release Planner",
            "GIT_COMMITTER_EMAIL": "support@durable-workflow.com",
        }
        commit = subprocess.run(
            ["git", "commit-tree", tree],
            cwd=repository,
            env=commit_env,
            input=f"Record release plan {plan['plan']}\n",
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        process = subprocess.run(
            ["git", "push", remote, f"{commit}:refs/tags/{tag}"],
            cwd=repository,
            check=False,
            text=True,
            capture_output=True,
        )
        if process.returncode:
            recovered = check_plan_compatibility(repository, plan_path, remote=remote)
            if recovered["status"] != "existing":
                raise CandidateError(f"cannot publish immutable release plan: {process.stderr.strip()}")
            authoritative_plan.write_bytes(canonical)
            return recovered
        authoritative_plan.write_bytes(canonical)
        return {"status": "created", "plan": plan["plan"], "tag": tag, "commit": commit}
    finally:
        index_path.unlink(missing_ok=True)


def candidate_manifest(plan: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": "durable-workflow.beta-candidate/v1",
        "candidate": f"{plan['channel']}-{plan['plan']}",
        "components": plan["components"],
    }


def completion_manifest(plan: dict[str, Any], plan_record_commit: str) -> dict[str, Any]:
    return {
        "schema": "durable-workflow.release-candidate/v1",
        "candidate": plan["plan"],
        "channel": plan["channel"],
        "release_plan": {
            "tag": f"{PLAN_TAG_PREFIX}{plan['plan']}",
            "commit": plan_record_commit,
            "sha256": manifest_digest(plan),
        },
        "components": plan["components"],
    }


def record_completion(
    repository: Path,
    plan_path: Path,
    verification_path: Path,
    *,
    remote: str,
    authoritative_completion: Path,
    authoritative_verification: Path,
    client: PublicClient,
) -> dict[str, str]:
    plan = load_plan(plan_path)
    plan_tag = f"{PLAN_TAG_PREFIX}{plan['plan']}"
    plan_record_commit = resolve_tag(client, CONTROL_REPOSITORY, plan_tag)
    if plan_record_commit is None:
        raise CandidateError(f"release plan tag {plan_tag} is absent")
    completion = completion_manifest(plan, plan_record_commit)
    canonical_completion = canonical_json(completion)
    try:
        verification = json.loads(verification_path.read_bytes())
    except (OSError, json.JSONDecodeError) as error:
        raise CandidateError(f"cannot read public verification: {error}") from error
    validate_verification(verification, candidate_manifest(plan))
    completion_verification = {
        "schema": "durable-workflow.release-candidate-verification/v1",
        "candidate": plan["plan"],
        "channel": plan["channel"],
        "release_plan_sha256": manifest_digest(plan),
        "public_verification": verification,
    }
    canonical_verification = canonical_json(completion_verification)
    tag = f"{COMPLETION_TAG_PREFIX}{plan['channel']}/{plan['plan']}"
    existing_ref = fetch_existing_record(repository, remote, tag)
    if existing_ref:
        existing = read_record_file(repository, existing_ref, "release-candidate.json")
        if existing != canonical_completion:
            raise CandidateError(f"completed release candidate {plan['plan']} is immutable and differs")
        existing_verification = read_record_file(repository, existing_ref, "verification.json")
        authoritative_completion.write_bytes(existing)
        authoritative_verification.write_bytes(existing_verification)
        return {
            "status": "existing",
            "candidate": plan["plan"],
            "channel": plan["channel"],
            "tag": tag,
            "commit": run_git(["rev-parse", f"{existing_ref}^{{commit}}"], cwd=repository),
        }

    with tempfile.NamedTemporaryFile(prefix="release-candidate-index-", delete=False) as index:
        index_path = Path(index.name)
    try:
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(index_path)
        index_path.unlink(missing_ok=True)
        run_git(["read-tree", "--empty"], cwd=repository, env=env)
        for filename, content in (
            ("release-candidate.json", canonical_completion),
            ("verification.json", canonical_verification),
        ):
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
            run_git(["update-index", "--add", "--cacheinfo", f"100644,{blob},{filename}"], cwd=repository, env=env)
        tree = run_git(["write-tree"], cwd=repository, env=env)
        commit_env = env | {
            "GIT_AUTHOR_NAME": "Durable Workflow Release Observer",
            "GIT_AUTHOR_EMAIL": "support@durable-workflow.com",
            "GIT_COMMITTER_NAME": "Durable Workflow Release Observer",
            "GIT_COMMITTER_EMAIL": "support@durable-workflow.com",
        }
        commit = subprocess.run(
            ["git", "commit-tree", tree],
            cwd=repository,
            env=commit_env,
            input=f"Record completed {plan['channel']} release candidate {plan['plan']}\n",
            check=True,
            text=True,
            capture_output=True,
        ).stdout.strip()
        process = subprocess.run(
            ["git", "push", remote, f"{commit}:refs/tags/{tag}"],
            cwd=repository,
            check=False,
            text=True,
            capture_output=True,
        )
        if process.returncode:
            existing_ref = fetch_existing_record(repository, remote, tag)
            if (
                not existing_ref
                or read_record_file(repository, existing_ref, "release-candidate.json") != canonical_completion
            ):
                raise CandidateError(f"cannot publish completed release candidate: {process.stderr.strip()}")
            authoritative_completion.write_bytes(read_record_file(repository, existing_ref, "release-candidate.json"))
            authoritative_verification.write_bytes(read_record_file(repository, existing_ref, "verification.json"))
            return {
                "status": "existing",
                "candidate": plan["plan"],
                "channel": plan["channel"],
                "tag": tag,
                "commit": run_git(["rev-parse", f"{existing_ref}^{{commit}}"], cwd=repository),
            }
        authoritative_completion.write_bytes(canonical_completion)
        authoritative_verification.write_bytes(canonical_verification)
        return {
            "status": "created",
            "candidate": plan["plan"],
            "channel": plan["channel"],
            "tag": tag,
            "commit": commit,
        }
    finally:
        index_path.unlink(missing_ok=True)


def observe_plan(plan: dict[str, Any], client: PublicClient) -> tuple[dict[str, Any], dict[str, Any]]:
    candidate = candidate_manifest(plan)
    state: dict[str, Any] = {
        "schema": "durable-workflow.release-state/v1",
        "plan": plan["plan"],
        "channel": plan["channel"],
        "plan_sha256": manifest_digest(plan),
        "observed_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "phase": "public-artifact-verification",
        "outcome": "failed",
        "durable_evidence": {
            "release_plan_tag": f"{PLAN_TAG_PREFIX}{plan['plan']}",
            "component_actions": "repository Actions runs and public version tags",
        },
        "resume_action": "Run the component's Release plan recovery action, then rerun Release plan observer",
    }
    try:
        for name, component in COMPONENTS.items():
            version = plan["components"][name]["version"]
            encoded = urllib.parse.quote(version, safe="")
            try:
                release = client.json(f"https://api.github.com/repos/{component.repository}/releases/tags/{encoded}")
            except CandidateError as error:
                raise CandidateError(f"{name}: GitHub Release lookup failed: {error}") from error
            if release.get("draft") or release.get("tag_name") != version:
                raise CandidateError(f"{name}: GitHub Release {component.repository}@{version} is not public")
        verification = verify_candidate(candidate, client)
    except CandidateError as error:
        state["reason"] = str(error)
        raise CandidateError(str(error)) from error
    state.update(
        {
            "phase": "complete",
            "outcome": "verified",
            "components": verification["components"],
            "resume_action": "No recovery action is required",
        }
    )
    return verification, state


def discover_plan(client: PublicClient, requested_tag: str | None) -> tuple[str, dict[str, Any]]:
    if requested_tag:
        tag = requested_tag
        if not tag.startswith(PLAN_TAG_PREFIX):
            raise CandidateError(f"release plan tag must start with {PLAN_TAG_PREFIX}")
    else:
        releases = client.json(f"https://api.github.com/repos/{CONTROL_REPOSITORY}/releases?per_page=100")
        tag = next(
            (
                str(release.get("tag_name"))
                for release in releases
                if not release.get("draft") and str(release.get("tag_name", "")).startswith(PLAN_TAG_PREFIX)
            ),
            "",
        )
        if not tag:
            raise CandidateError("no public release plan is available")
    commit = resolve_tag(client, CONTROL_REPOSITORY, tag)
    if commit is None:
        raise CandidateError(f"release plan tag {tag} does not exist")
    plan = read_public_record(client, tag, commit, "release-plan.json")
    validate_plan(plan)
    if tag != f"{PLAN_TAG_PREFIX}{plan['plan']}":
        raise CandidateError("release plan tag and document identity differ")
    return tag, plan


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("source", type=Path)
    validate.add_argument("destination", type=Path)

    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("plan", type=Path)
    preflight.add_argument("evidence", type=Path)

    check = subparsers.add_parser("check")
    check.add_argument("plan", type=Path)
    check.add_argument("--remote", default="origin")

    record = subparsers.add_parser("record")
    record.add_argument("plan", type=Path)
    record.add_argument("--remote", default="origin")
    record.add_argument("--authoritative-plan", required=True, type=Path)
    record.add_argument("--github-output", type=Path)

    discover = subparsers.add_parser("discover")
    discover.add_argument("destination", type=Path)
    discover.add_argument("--tag")
    discover.add_argument("--github-output", type=Path)

    observe = subparsers.add_parser("observe")
    observe.add_argument("plan", type=Path)
    observe.add_argument("candidate", type=Path)
    observe.add_argument("verification", type=Path)
    observe.add_argument("state", type=Path)

    complete = subparsers.add_parser("complete")
    complete.add_argument("plan", type=Path)
    complete.add_argument("verification", type=Path)
    complete.add_argument("--remote", default="origin")
    complete.add_argument("--authoritative-completion", required=True, type=Path)
    complete.add_argument("--authoritative-verification", required=True, type=Path)
    complete.add_argument("--github-output", type=Path)

    args = parser.parse_args()
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    try:
        if args.command == "validate":
            plan = load_plan(args.source)
            args.destination.write_bytes(canonical_json(plan))
        elif args.command == "preflight":
            plan = load_plan(args.plan)
            evidence = preflight_plan(plan, PublicClient(token))
            args.evidence.write_bytes(
                canonical_json(
                    {
                        "schema": "durable-workflow.release-plan-preflight/v1",
                        "plan": plan["plan"],
                        "channel": plan["channel"],
                        "outcome": "verified",
                        **evidence,
                    }
                )
            )
        elif args.command == "check":
            print(json.dumps(check_plan_compatibility(Path.cwd(), args.plan, remote=args.remote), sort_keys=True))
        elif args.command == "record":
            result = record_plan(Path.cwd(), args.plan, remote=args.remote, authoritative_plan=args.authoritative_plan)
            write_github_output(args.github_output, result)
            print(json.dumps(result, sort_keys=True))
        elif args.command == "discover":
            tag, plan = discover_plan(PublicClient(token), args.tag)
            args.destination.write_bytes(canonical_json(plan))
            values = {"tag": tag, "plan": plan["plan"], "channel": plan["channel"]}
            write_github_output(args.github_output, values)
            print(json.dumps(values, sort_keys=True))
        elif args.command == "observe":
            plan = load_plan(args.plan)
            candidate = candidate_manifest(plan)
            args.candidate.write_bytes(canonical_json(candidate))
            try:
                verification, state = observe_plan(plan, PublicClient(token))
            except CandidateError as error:
                reason = str(error)
                failed_component = next(
                    (name for name in COMPONENTS if reason.startswith(f"{name}:")),
                    None,
                )
                failed_state = {
                    "schema": "durable-workflow.release-state/v1",
                    "plan": plan["plan"],
                    "channel": plan["channel"],
                    "plan_sha256": manifest_digest(plan),
                    "observed_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                    "phase": "public-artifact-verification",
                    "outcome": "failed",
                    "failed_component": failed_component,
                    "reason": reason,
                    "durable_evidence": {
                        "release_plan_tag": f"{PLAN_TAG_PREFIX}{plan['plan']}",
                        "component_actions": "repository Actions runs and public version tags",
                    },
                    "resume_action": (
                        "Run the component's Release plan recovery action, then rerun Release plan observer"
                    ),
                }
                args.state.write_bytes(canonical_json(failed_state))
                raise
            args.verification.write_bytes(canonical_json(verification))
            args.state.write_bytes(canonical_json(state))
        else:
            result = record_completion(
                Path.cwd(),
                args.plan,
                args.verification,
                remote=args.remote,
                authoritative_completion=args.authoritative_completion,
                authoritative_verification=args.authoritative_verification,
                client=PublicClient(token),
            )
            write_github_output(args.github_output, result)
            print(json.dumps(result, sort_keys=True))
    except CandidateError as error:
        print(f"release plan error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
