#!/usr/bin/env python3
"""Validate and audit GitHub-owned public target qualification."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

SCHEMA = "durable-workflow.github-target-qualification/v1"
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


class PolicyError(RuntimeError):
    """A qualification or protection contract is not satisfied."""


class GitHubClient:
    def __init__(self, token: str | None = None, api_url: str = "https://api.github.com") -> None:
        self.api_url = api_url.rstrip("/")
        self.headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "durable-workflow-target-qualification/1",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    def _request(self, path: str, *, accept: str | None = None) -> bytes:
        headers = dict(self.headers)
        if accept:
            headers["Accept"] = accept
        request = urllib.request.Request(f"{self.api_url}{path}", headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")[:500]
            raise PolicyError(f"GitHub API {error.code} for {path}: {detail}") from error
        except urllib.error.URLError as error:
            raise PolicyError(f"GitHub API request failed for {path}: {error.reason}") from error

    def json(self, path: str) -> Any:
        return json.loads(self._request(path))

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


def _latest_check_runs(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    latest: dict[str, dict[str, Any]] = {}
    for record in records:
        name = record.get("name")
        if not isinstance(name, str):
            continue
        if name not in latest or int(record.get("id", 0)) > int(latest[name].get("id", 0)):
            latest[name] = record
    return latest


def audit_policy(
    policy: dict[str, Any],
    client: GitHubClient,
    *,
    skip_check_runs_for: set[str] | None = None,
) -> dict[str, Any]:
    validate_policy(policy)
    organization = policy["organization"]
    skipped = skip_check_runs_for or set()
    unknown_skips = skipped - set(policy["targets"])
    if unknown_skips:
        raise PolicyError(f"unknown skipped qualification targets: {sorted(unknown_skips)}")

    evidence: dict[str, Any] = {"schema": SCHEMA, "targets": {}}
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

        workflow_evidence = []
        for workflow in target["workflows"]:
            workflow_path = workflow["path"]
            encoded_workflow = urllib.parse.quote(workflow_path, safe="")
            metadata = client.json(f"/repos/{slug}/actions/workflows/{encoded_workflow}")
            expected_path = f".github/workflows/{workflow_path}"
            if metadata.get("state") != "active" or metadata.get("path") != expected_path:
                raise PolicyError(f"{slug} does not expose active workflow {expected_path}")
            contents_path = urllib.parse.quote(expected_path, safe="/")
            source = client.bytes(f"/repos/{slug}/contents/{contents_path}?ref={head_sha}").decode("utf-8")
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
            records = client.collection(
                f"/repos/{slug}/commits/{head_sha}/check-runs?filter=latest",
                "check_runs",
            )
            latest = _latest_check_runs(records)
            for check in sorted(required_checks):
                record = latest.get(check)
                if record is None:
                    raise PolicyError(f"{slug}@{head_sha} has no {check!r} check run")
                if record.get("status") != "completed" or record.get("conclusion") != "success":
                    raise PolicyError(
                        f"{slug}@{head_sha} check {check!r} is "
                        f"{record.get('status')}/{record.get('conclusion')}"
                    )
                successful_checks[check] = int(record.get("id", 0))

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
    parser.add_argument("--skip-check-runs-for", action="append", default=[])
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        policy = load_policy(args.policy)
        if args.command == "validate":
            result: dict[str, Any] = {"schema": policy["schema"], "targets": sorted(policy["targets"])}
        else:
            result = audit_policy(
                policy,
                GitHubClient(args.github_token),
                skip_check_runs_for=set(args.skip_check_runs_for),
            )
        output = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.evidence:
            args.evidence.write_text(output, encoding="utf-8")
        print(output, end="")
        return 0
    except PolicyError as error:
        print(f"qualification policy failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
