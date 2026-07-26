#!/usr/bin/env python3
"""Qualify the shared release-recovery contract across every public target."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

# GitHub Actions invokes this file directly from the repository root. In that
# mode Python adds scripts/, rather than the repository root, to sys.path.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts import release_recovery_consumer_conformance as conformance

EVIDENCE_SCHEMA = "durable-workflow.release-recovery-target-qualification-evidence/v1"
CONTRACT_PATH = "scripts/ci/release-recovery-consumer-contract.json"
ADAPTER_PATH = "scripts/ci/release-recovery-consumer-adapter.json"
SUITE_PATH = "scripts/ci/release_recovery_consumer_conformance.py"


def fetch_public(url: str) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "release-recovery-target-qualification"},
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            return response.read()
    except (OSError, urllib.error.HTTPError) as error:
        raise conformance.ConformanceError(f"cannot read public conformance target: {url}") from error


def json_object(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise conformance.ConformanceError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise conformance.ConformanceError(f"{label} is not a JSON object")
    return value


def resolve_target_commit(repository: str, branch: str) -> tuple[str, str]:
    target_ref = f"refs/heads/{branch}"
    try:
        result = subprocess.run(
            [
                "git",
                "ls-remote",
                "--exit-code",
                "--refs",
                f"https://github.com/{repository}.git",
                target_ref,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise conformance.ConformanceError(f"cannot resolve public target {repository}@{branch}") from error
    lines = result.stdout.splitlines()
    fields = lines[0].split() if len(lines) == 1 else []
    if (
        result.returncode != 0
        or len(fields) != 2
        or fields[1] != target_ref
        or conformance.COMMIT_PATTERN.fullmatch(fields[0]) is None
    ):
        raise conformance.ConformanceError(f"{repository}@{branch} did not resolve to an exact commit")
    return target_ref, fields[0]


def validate_adapter(
    raw: bytes,
    consumer: dict[str, str],
    contract: dict[str, Any],
    contract_sha256: str,
) -> dict[str, str]:
    adapter = json_object(raw, f"{consumer['component']} adapter")
    if raw != conformance.canonical_json(adapter):
        raise conformance.ConformanceError(f"{consumer['component']} adapter is not canonical JSON")
    expected_keys = {
        "component",
        "consumer",
        "contract",
        "distribution_verification",
        "repository",
        "schema",
        "suite",
        "target_branch",
    }
    if set(adapter) != expected_keys or adapter.get("schema") != conformance.ADAPTER_SCHEMA:
        raise conformance.ConformanceError(f"{consumer['component']} adapter does not satisfy the shared adapter shape")
    expected_identity = {
        "component": consumer["component"],
        "repository": consumer["repository"],
        "target_branch": consumer["target_branch"],
    }
    if any(adapter.get(field) != value for field, value in expected_identity.items()):
        raise conformance.ConformanceError(f"{consumer['component']} adapter has the wrong target identity")
    if adapter.get("contract") != {
        "path": CONTRACT_PATH,
        "sha256": contract_sha256,
        "version": contract["version"],
    }:
        raise conformance.ConformanceError(f"{consumer['component']} adapter does not pin the current contract")
    if adapter.get("suite") != {
        "path": SUITE_PATH,
        "sha256": contract["suite"]["sha256"],
    }:
        raise conformance.ConformanceError(f"{consumer['component']} adapter does not pin the current suite")
    return {
        **expected_identity,
        "sha256": conformance.sha256_bytes(raw),
    }


def audit_public_targets(contract: dict[str, Any], contract_raw: bytes) -> list[dict[str, Any]]:
    contract_sha256 = conformance.sha256_bytes(contract_raw)
    results: list[dict[str, Any]] = []
    for consumer in contract["consumers"]:
        repository = consumer["repository"]
        branch = consumer["target_branch"]
        target_ref, commit = resolve_target_commit(repository, branch)
        base = f"https://raw.githubusercontent.com/{repository}/{commit}"
        remote_contract = fetch_public(f"{base}/{CONTRACT_PATH}")
        remote_adapter = fetch_public(f"{base}/{ADAPTER_PATH}")
        remote_suite = fetch_public(f"{base}/{SUITE_PATH}")
        if remote_contract != contract_raw:
            raise conformance.ConformanceError(f"{consumer['component']} does not carry the current shared contract")
        adapter_identity = validate_adapter(
            remote_adapter,
            consumer,
            contract,
            contract_sha256,
        )
        suite_sha256 = conformance.sha256_bytes(remote_suite)
        if suite_sha256 != contract["suite"]["sha256"]:
            raise conformance.ConformanceError(f"{consumer['component']} does not carry the current shared suite")
        results.append(
            {
                "adapter": adapter_identity,
                "contract": {
                    "sha256": contract_sha256,
                    "version": contract["version"],
                },
                "source_commit": commit,
                "status": "pass",
                "suite_sha256": suite_sha256,
                "target_ref": target_ref,
            }
        )
    return results


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    contract_path = args.contract.resolve()
    contract, contract_raw = conformance.load_json_object(contract_path, "shared contract")
    suite_path = Path(conformance.__file__).resolve()
    contract_sha256 = conformance.validate_contract(contract, contract_raw, suite_path)
    targets = audit_public_targets(contract, contract_raw)
    evidence = {
        "schema": EVIDENCE_SCHEMA,
        "contract": {
            "sha256": contract_sha256,
            "suite_sha256": contract["suite"]["sha256"],
            "version": contract["version"],
        },
        "generated_at": dt.datetime.now(dt.UTC).isoformat(),
        "outcome": "pass",
        "source_commit": conformance.source_commit(Path.cwd().resolve()),
        "targets": targets,
    }
    conformance.write_evidence(args.evidence, evidence)
    print(f"release-recovery contract {contract['version']} passed for {len(targets)} exact public target commits")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
