#!/usr/bin/env python3
"""Create, select, and validate attempt-bound verifier handoffs."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.beta_candidate import CandidateError, PublicClient, PublicInfrastructureError, canonical_json

HANDOFF_SCHEMA = "durable-workflow.verifier-handoff/v1"
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_HANDOFF_BYTES = 64 * 1024
MAX_ARTIFACTS = 1_000


class HandoffError(RuntimeError):
    """A verifier handoff cannot be recovered without changing its identity."""


@dataclass(frozen=True)
class HandoffKind:
    artifact_prefix: str
    filenames: tuple[str, ...]


KINDS = {
    "candidate": HandoffKind(
        "beta-candidate-verification",
        ("candidate.json", "verification.json"),
    ),
    "release-plan-observation": HandoffKind(
        "release-plan-observation",
        (
            "release-plan.json",
            "release-preparation.json",
            "candidate-verifier-input.json",
            "release-state.json",
            "verification.json",
        ),
    ),
}


@dataclass(frozen=True)
class SelectedArtifact:
    artifact_id: int
    name: str
    producer_attempt: int


def positive_integer(value: str | int, label: str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as error:
        raise HandoffError(f"{label} must be a positive integer") from error
    if parsed < 1 or isinstance(value, bool):
        raise HandoffError(f"{label} must be a positive integer")
    return parsed


def validate_runtime_identity(repository: str, workflow_ref: str, source_sha: str) -> None:
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise HandoffError("handoff repository has an invalid identity")
    if not workflow_ref.startswith(f"{repository}/.github/workflows/") or "@" not in workflow_ref:
        raise HandoffError("handoff workflow ref has an invalid identity")
    if len(workflow_ref) > 512 or any(character in workflow_ref for character in "\r\n"):
        raise HandoffError("handoff workflow ref has an invalid identity")
    if not COMMIT_PATTERN.fullmatch(source_sha):
        raise HandoffError("handoff source SHA must be a full lowercase commit")


def artifact_name(kind: str, run_id: int, run_attempt: int) -> str:
    contract = KINDS[kind]
    return f"{contract.artifact_prefix}-{run_id}-{run_attempt}"


def hash_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise HandoffError(f"handoff file is missing or is not a regular file: {path.name}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def create_handoff(
    kind: str,
    directory: Path,
    output: Path,
    *,
    repository: str,
    workflow_ref: str,
    source_sha: str,
    run_id: int,
    run_attempt: int,
) -> dict[str, Any]:
    validate_runtime_identity(repository, workflow_ref, source_sha)
    run_id = positive_integer(run_id, "handoff run ID")
    run_attempt = positive_integer(run_attempt, "handoff run attempt")
    contract = KINDS[kind]
    files = {filename: hash_file(directory / filename) for filename in contract.filenames}
    handoff = {
        "schema": HANDOFF_SCHEMA,
        "kind": kind,
        "artifact_name": artifact_name(kind, run_id, run_attempt),
        "producer": {
            "repository": repository,
            "workflow_ref": workflow_ref,
            "source_sha": source_sha,
            "run_id": run_id,
            "run_attempt": run_attempt,
        },
        "files": files,
    }
    output.write_bytes(canonical_json(handoff))
    return handoff


def _load_handoff(path: Path) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise HandoffError(f"cannot read verifier handoff: {error}") from error
    if len(raw) > MAX_HANDOFF_BYTES:
        raise HandoffError("verifier handoff exceeds the 64 KiB limit")
    try:
        handoff = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise HandoffError("verifier handoff is not valid JSON") from error
    if not isinstance(handoff, dict):
        raise HandoffError("verifier handoff must be a JSON object")
    return handoff, raw


def validate_handoff(
    kind: str,
    directory: Path,
    manifest: Path,
    *,
    repository: str,
    workflow_ref: str,
    source_sha: str,
    run_id: int,
    current_attempt: int,
    producer_attempt: int,
) -> dict[str, Any]:
    validate_runtime_identity(repository, workflow_ref, source_sha)
    run_id = positive_integer(run_id, "handoff run ID")
    current_attempt = positive_integer(current_attempt, "current run attempt")
    producer_attempt = positive_integer(producer_attempt, "handoff producer attempt")
    if producer_attempt > current_attempt:
        raise HandoffError("handoff producer attempt is newer than the recorder attempt")

    handoff, raw = _load_handoff(manifest)
    if raw != canonical_json(handoff):
        raise HandoffError("verifier handoff is not canonical JSON")
    if set(handoff) != {"schema", "kind", "artifact_name", "producer", "files"}:
        raise HandoffError("verifier handoff has unexpected or missing fields")
    if handoff["schema"] != HANDOFF_SCHEMA or handoff["kind"] != kind:
        raise HandoffError("verifier handoff has a mismatched contract identity")
    expected_name = artifact_name(kind, run_id, producer_attempt)
    if handoff["artifact_name"] != expected_name:
        raise HandoffError("verifier handoff artifact name does not bind the selected producing attempt")

    producer = handoff["producer"]
    if not isinstance(producer, dict) or set(producer) != {
        "repository",
        "workflow_ref",
        "source_sha",
        "run_id",
        "run_attempt",
    }:
        raise HandoffError("verifier handoff has an invalid producer identity")
    expected_producer = {
        "repository": repository,
        "workflow_ref": workflow_ref,
        "source_sha": source_sha,
        "run_id": run_id,
        "run_attempt": producer_attempt,
    }
    if producer != expected_producer:
        raise HandoffError("verifier handoff producer identity does not match the recorder selection")

    contract = KINDS[kind]
    files = handoff["files"]
    if not isinstance(files, dict) or set(files) != set(contract.filenames):
        raise HandoffError("verifier handoff file set does not match its contract")
    expected_entries = {*contract.filenames, manifest.name}
    try:
        actual_entries = {path.name for path in directory.iterdir()}
    except OSError as error:
        raise HandoffError(f"cannot inspect verifier handoff directory: {error}") from error
    if actual_entries != expected_entries:
        raise HandoffError("verifier handoff artifact contains unexpected or missing files")
    for filename in contract.filenames:
        digest = files[filename]
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise HandoffError(f"verifier handoff has an invalid digest for {filename}")
        if hash_file(directory / filename) != digest:
            raise HandoffError(f"verifier handoff digest does not match {filename}")
    return handoff


def list_run_artifacts(client: PublicClient, repository: str, run_id: int) -> list[dict[str, Any]]:
    run_id = positive_integer(run_id, "handoff run ID")
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise HandoffError("handoff repository has an invalid identity")
    artifacts: list[dict[str, Any]] = []
    expected_total: int | None = None
    page = 1
    while True:
        url = f"https://api.github.com/repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100&page={page}"
        payload = client.json(url)
        if not isinstance(payload, dict):
            raise HandoffError("GitHub Actions artifact listing is not a JSON object")
        total = payload.get("total_count")
        page_artifacts = payload.get("artifacts")
        if type(total) is not int or total < 0 or not isinstance(page_artifacts, list):
            raise HandoffError("GitHub Actions artifact listing has an invalid shape")
        if expected_total is None:
            expected_total = total
            if expected_total > MAX_ARTIFACTS:
                raise HandoffError("GitHub Actions artifact listing exceeds the recovery bound")
        elif total != expected_total:
            raise HandoffError("GitHub Actions artifact listing changed during recovery")
        if not all(isinstance(artifact, dict) for artifact in page_artifacts):
            raise HandoffError("GitHub Actions artifact listing contains an invalid artifact")
        artifacts.extend(page_artifacts)
        if len(artifacts) > expected_total:
            raise HandoffError("GitHub Actions artifact listing contains duplicate pagination evidence")
        if len(artifacts) == expected_total:
            break
        if not page_artifacts:
            raise HandoffError("GitHub Actions artifact listing ended before its declared total")
        page += 1
    return artifacts


def select_handoff_artifact(
    kind: str,
    artifacts: list[dict[str, Any]],
    *,
    run_id: int,
    current_attempt: int,
    producer_attempt: int,
    source_sha: str,
) -> SelectedArtifact:
    run_id = positive_integer(run_id, "handoff run ID")
    current_attempt = positive_integer(current_attempt, "current run attempt")
    producer_attempt = positive_integer(producer_attempt, "handoff producer attempt")
    if producer_attempt > current_attempt:
        raise HandoffError("handoff producer attempt is newer than the recorder attempt")
    if not COMMIT_PATTERN.fullmatch(source_sha):
        raise HandoffError("handoff source SHA must be a full lowercase commit")
    prefix = KINDS[kind].artifact_prefix
    pattern = re.compile(rf"^{re.escape(prefix)}-{run_id}-([1-9][0-9]*)$")
    by_attempt: dict[int, list[dict[str, Any]]] = {}
    for artifact in artifacts:
        name = artifact.get("name")
        match = pattern.fullmatch(name) if isinstance(name, str) else None
        if match is None:
            continue
        attempt = int(match.group(1))
        if attempt > current_attempt:
            raise HandoffError("verifier handoff artifact names a future producing attempt")
        workflow_run = artifact.get("workflow_run")
        if (
            not isinstance(workflow_run, dict)
            or workflow_run.get("id") != run_id
            or workflow_run.get("head_sha") != source_sha
        ):
            raise HandoffError("verifier handoff artifact has a mismatched workflow-run identity")
        by_attempt.setdefault(attempt, []).append(artifact)

    if not by_attempt:
        raise HandoffError("no verifier handoff artifact exists for this workflow run")
    if producer_attempt not in by_attempt:
        raise HandoffError(f"no verifier handoff artifact exists for producing attempt {producer_attempt}")
    if producer_attempt != max(by_attempt):
        raise HandoffError("retained producer attempt does not identify the newest verifier handoff")
    selected = by_attempt[producer_attempt]
    if len(selected) != 1:
        raise HandoffError(f"verifier handoff attempt {producer_attempt} is ambiguous")
    artifact = selected[0]
    if artifact.get("expired") is not False:
        raise HandoffError(f"verifier handoff attempt {producer_attempt} is expired or has unknown retention state")
    artifact_id = artifact.get("id")
    if type(artifact_id) is not int or artifact_id < 1:
        raise HandoffError("verifier handoff artifact has an invalid ID")
    return SelectedArtifact(artifact_id, artifact_name(kind, run_id, producer_attempt), producer_attempt)


def write_github_output(path: Path, values: dict[str, str | int]) -> None:
    with path.open("a", encoding="utf-8") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create", help="create an attempt-bound handoff manifest")
    create.add_argument("kind", choices=KINDS)
    create.add_argument("output", type=Path)
    create.add_argument("--directory", type=Path, required=True)
    create.add_argument("--repository", required=True)
    create.add_argument("--workflow-ref", required=True)
    create.add_argument("--source-sha", required=True)
    create.add_argument("--run-id", required=True)
    create.add_argument("--run-attempt", required=True)
    create.add_argument("--github-output", type=Path)

    select = subparsers.add_parser("select", help="select the newest exact handoff from this workflow run")
    select.add_argument("kind", choices=KINDS)
    select.add_argument("--repository", required=True)
    select.add_argument("--source-sha", required=True)
    select.add_argument("--run-id", required=True)
    select.add_argument("--run-attempt", required=True)
    select.add_argument("--producer-attempt", required=True)
    select.add_argument("--github-output", type=Path, required=True)

    validate = subparsers.add_parser("validate", help="validate downloaded handoff identity and bytes")
    validate.add_argument("kind", choices=KINDS)
    validate.add_argument("manifest", type=Path)
    validate.add_argument("--directory", type=Path, required=True)
    validate.add_argument("--repository", required=True)
    validate.add_argument("--workflow-ref", required=True)
    validate.add_argument("--source-sha", required=True)
    validate.add_argument("--run-id", required=True)
    validate.add_argument("--current-attempt", required=True)
    validate.add_argument("--producer-attempt", required=True)
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    try:
        if arguments.command == "create":
            result = create_handoff(
                arguments.kind,
                arguments.directory,
                arguments.output,
                repository=arguments.repository,
                workflow_ref=arguments.workflow_ref,
                source_sha=arguments.source_sha,
                run_id=arguments.run_id,
                run_attempt=arguments.run_attempt,
            )
            if arguments.github_output is not None:
                write_github_output(
                    arguments.github_output,
                    {
                        "artifact_name": result["artifact_name"],
                        "producer_attempt": result["producer"]["run_attempt"],
                    },
                )
            print(json.dumps(result, sort_keys=True))
        elif arguments.command == "select":
            token = os.environ.get("GITHUB_TOKEN")
            if not token:
                raise HandoffError("GITHUB_TOKEN is required to select a verifier handoff")
            artifacts = list_run_artifacts(PublicClient(token), arguments.repository, arguments.run_id)
            selected = select_handoff_artifact(
                arguments.kind,
                artifacts,
                run_id=arguments.run_id,
                current_attempt=arguments.run_attempt,
                producer_attempt=arguments.producer_attempt,
                source_sha=arguments.source_sha,
            )
            values = {
                "artifact_id": selected.artifact_id,
                "artifact_name": selected.name,
                "producer_attempt": selected.producer_attempt,
            }
            write_github_output(arguments.github_output, values)
            print(json.dumps(values, sort_keys=True))
        else:
            result = validate_handoff(
                arguments.kind,
                arguments.directory,
                arguments.manifest,
                repository=arguments.repository,
                workflow_ref=arguments.workflow_ref,
                source_sha=arguments.source_sha,
                run_id=arguments.run_id,
                current_attempt=arguments.current_attempt,
                producer_attempt=arguments.producer_attempt,
            )
            print(json.dumps(result, sort_keys=True))
    except PublicInfrastructureError as error:
        print(f"verifier handoff infrastructure failed: {error}", file=sys.stderr)
        return 75
    except CandidateError as error:
        print(f"verifier handoff API failed: {error}", file=sys.stderr)
        return 1
    except HandoffError as error:
        print(f"verifier handoff error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
