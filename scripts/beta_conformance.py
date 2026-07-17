#!/usr/bin/env python3
"""Run beta conformance from immutable public artifacts and retain bounded evidence."""

from __future__ import annotations

import argparse
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
    CandidateError,
    canonical_json,
    load_manifest,
    manifest_digest,
    validate_verification,
)

CONTRACT_SCHEMA = "durable-workflow.beta-conformance.contract/v1"
PLAN_SCHEMA = "durable-workflow.beta-conformance.plan/v1"
EXPERIMENT_RESULT_SCHEMA = "durable-workflow.beta-conformance.experiment-result/v1"
SUITE_RESULT_SCHEMA = "durable-workflow.beta-conformance.suite-result/v1"
EXPERIMENTS = ("heartbeats", "polyglot", "replay", "signals-queries")
PASS_OUTCOMES = {"pass", "passed", "success", "successful", "completed", "verified"}
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
DIGEST_PATTERN = re.compile(r"^[0-9a-f]{64}$")
OCI_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")
DIAGNOSTIC_LIMIT = 8192
FINDING_LIMIT = 20
FINDING_TEXT_LIMIT = 2048
MAX_INFRASTRUCTURE_ATTEMPTS = 2
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


class ConformanceError(RuntimeError):
    """The portable beta conformance contract is invalid or cannot run."""


def now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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
    if not isinstance(contract, dict) or set(contract) != {"$schema", "schema", "experiments"}:
        raise ConformanceError("beta conformance contract has an invalid top-level shape")
    if contract["$schema"] != "./contract-schema.json":
        raise ConformanceError("beta conformance contract must reference its repository schema")
    if contract["schema"] != CONTRACT_SCHEMA:
        raise ConformanceError(f"beta conformance contract schema must be {CONTRACT_SCHEMA}")
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
            or not set(required_distributions).issubset(COMPONENTS)
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
            if not isinstance(runner, dict) or set(runner) != {"id", "path", "result"}:
                raise ConformanceError(f"experiment {name} runner has an invalid shape")
            runner_id = runner["id"]
            if (
                not isinstance(runner_id, str)
                or not re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", runner_id)
                or runner_id in runner_ids
            ):
                raise ConformanceError(f"experiment {name} has an invalid or duplicate runner id")
            runner_ids.add(runner_id)
            path = safe_relative_path(runner["path"])
            if not path.startswith("scripts/conformance/") or not path.endswith((".sh", ".mjs", ".py")):
                raise ConformanceError(f"experiment {name} runner is outside the published conformance surface")
            safe_relative_path(runner["result"], suffix=".json")
            if "/" in runner["result"]:
                raise ConformanceError(f"experiment {name} native result must be a file name")
    covered_distributions = {
        distribution
        for specification in experiments.values()
        for distribution in specification["required_distributions"]
    }
    if covered_distributions != set(COMPONENTS):
        raise ConformanceError("beta conformance contract does not execute all seven distributions")


def load_contract(path: Path) -> dict[str, Any]:
    contract = load_json(path, limit=256 * 1024)
    validate_contract(contract)
    return contract


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
    component = COMPONENTS[name]
    return f"{component.distribution}:{component.package}@{version}"


def distribution_artifact(name: Any, sha256: Any) -> dict[str, str]:
    if not isinstance(name, str) or not name or len(name) > 256:
        raise ConformanceError("candidate verification has an invalid distribution artifact name")
    if not isinstance(sha256, str) or not DIGEST_PATTERN.fullmatch(sha256):
        raise ConformanceError(f"candidate verification distribution artifact {name} has no SHA-256 identity")
    return {"name": name, "sha256": sha256}


def normalized_distribution_identity(
    name: str, version: str, artifacts: list[dict[str, str]]
) -> dict[str, Any]:
    ordered = sorted(artifacts, key=lambda artifact: artifact["name"])
    if not ordered or len(ordered) != len({artifact["name"] for artifact in ordered}):
        raise ConformanceError(f"candidate verification has invalid {name} distribution artifacts")
    return {
        "kind": COMPONENTS[name].distribution,
        "locator": distribution_locator(name, version),
        "artifacts": ordered,
    }


def normalize_distribution_identities(
    verification: dict[str, Any], manifest: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    identities: dict[str, dict[str, Any]] = {}
    for name, component in COMPONENTS.items():
        version = manifest["components"][name]["version"]
        distribution = verification["components"][name].get("distribution")
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
    expected_locator = distribution_locator(name, components[name]["version"])
    if (
        not isinstance(identity, dict)
        or set(identity) != {"kind", "locator", "artifacts"}
        or identity["kind"] != COMPONENTS[name].distribution
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
    if not isinstance(identities, dict) or not set(identities).issubset(COMPONENTS):
        raise ConformanceError("executed distribution identities name an unknown component")
    for name, identity in identities.items():
        validate_distribution_identity(name, identity, components)


def validate_distribution_identities(identities: Any, components: dict[str, Any]) -> None:
    if not isinstance(identities, dict) or set(identities) != set(COMPONENTS):
        raise ConformanceError("distribution identities do not bind the exact seven-artifact tuple")
    validate_partial_distribution_identities(identities, components)


def prepare_plan(
    repository: Path,
    manifest: dict[str, Any],
    contract: dict[str, Any],
    runner_revision: str,
) -> dict[str, Any]:
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
        "experiments": list(EXPERIMENTS),
    }
    validate_plan(plan)
    return plan


def validate_plan(plan: Any) -> None:
    required = {
        "schema",
        "candidate",
        "artifact_tuple",
        "source_identities",
        "distribution_identities",
        "runner",
        "server_runner",
        "experiments",
    }
    if not isinstance(plan, dict) or set(plan) != required or plan.get("schema") != PLAN_SCHEMA:
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
    validate_distribution_identities(plan["distribution_identities"], components)
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
    if plan["experiments"] != list(EXPERIMENTS):
        raise ConformanceError("beta conformance plan does not select the complete experiment set")


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
    return value, digest


def bounded_text(value: Any, limit: int = FINDING_TEXT_LIMIT) -> str:
    text = str(value).replace("\x00", "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


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
                "type": bounded_text(kind, 128),
                "owning_contract": bounded_text(owner, 128),
                "summary": bounded_text(summary),
            }
        )
    return summaries


def native_state(native: Any) -> tuple[str | None, bool, list[dict[str, str]]]:
    if not isinstance(native, dict):
        return None, False, []
    raw_outcome = native.get("outcome", native.get("status"))
    outcome = str(raw_outcome).lower() if raw_outcome is not None else None
    runner_blocked = native.get("runner_blocked") is True or native.get("runnerBlocked") is True
    return outcome, runner_blocked, summarize_findings(native)


def summarize_executed_distribution_identities(
    native: dict[str, Any], plan: dict[str, Any]
) -> dict[str, Any]:
    raw = native.get("executed_distribution_identities", native.get("executedDistributionIdentities", {}))
    if not isinstance(raw, dict):
        return {}
    identities: dict[str, Any] = {}
    for name, identity in raw.items():
        if name not in COMPONENTS or not isinstance(identity, dict):
            continue
        kind = identity.get("kind")
        locator = identity.get("locator")
        artifacts = identity.get("artifacts")
        if (
            kind != COMPONENTS[name].distribution
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
            normalized_artifacts.append({"name": artifact["name"], "sha256": artifact["sha256"]})
        normalized_artifacts.sort(key=lambda artifact: artifact["name"])
        if (
            normalized_artifacts
            and len(normalized_artifacts) == len({artifact["name"] for artifact in normalized_artifacts})
        ):
            normalized = {"kind": kind, "locator": locator, "artifacts": normalized_artifacts}
            try:
                validate_distribution_identity(name, normalized, plan["artifact_tuple"])
            except ConformanceError:
                continue
            identities[name] = normalized
    return identities


def summarize_native_result(native: Any, plan: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(native, dict):
        return None
    versions = native.get("artifact_versions", native.get("artifactVersions", {}))
    if not isinstance(versions, dict):
        versions = {}
    bounded_versions = {
        name: bounded_text(version, 128)
        for name, version in versions.items()
        if name in COMPONENTS and isinstance(version, str)
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
        scenarios.append({"id": bounded_text(scenario_id, 128), "status": bounded_text(status, 64)})
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
        "schema": bounded_text(schema, 256) if isinstance(schema, str) else None,
        "artifact_versions": bounded_versions,
        "executed_distribution_identities": summarize_executed_distribution_identities(native, plan),
        "scenario_statuses": scenarios,
        "local_product_source_checkout_used": local_source_used,
    }


def is_classified_transient(text: str) -> bool:
    return any(pattern.search(text) for pattern in TRANSIENT_PATTERNS)


def classify_attempt(
    *,
    returncode: int,
    timed_out: bool,
    native_outcome: str | None,
    runner_blocked: bool,
    diagnostic_text: str,
) -> tuple[str, bool]:
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
        "DW_CONFORMANCE_TMPDIR": str(scratch),
    }


def failure_fingerprint(
    plan: dict[str, Any], experiment: str, classification: str, owner: str, diagnostics: list[dict[str, Any]]
) -> str | None:
    if classification == "passed":
        return None
    stable = {
        "candidate_manifest_sha256": plan["candidate"]["manifest_sha256"],
        "candidate_verification_sha256": plan["candidate"]["verification_sha256"],
        "contract_sha256": plan["runner"]["contract_sha256"],
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
    diagnostic = {
        "runner": "injected-product-failure",
        "attempt": 1,
        "exit_code": 1,
        "timed_out": False,
        "native_outcome": "fail",
        "runner_blocked": False,
        "stdout_tail": "",
        "stdout_sha256": sha256_bytes(b""),
        "stderr_tail": "deterministic product-failure injection requested by workflow input",
        "stderr_sha256": sha256_bytes(b"deterministic product-failure injection requested by workflow input"),
        "native_result_sha256": None,
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
        "runner": plan["runner"],
        "server_runner": plan["server_runner"],
        "owning_contract": owner,
        "required_clients": required_clients,
        "required_distributions": required_distributions,
        "source_policy": {
            "product_artifacts": "published_only",
            "orchestration_source": "exact_server_container",
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
        expected = plan["artifact_tuple"][name]["version"]
        if versions != {expected}:
            failures.append(f"{name} native evidence reports {sorted(versions)}, expected exact version {expected}")
    for name, identities in observed_identities.items():
        expected = plan["distribution_identities"][name]
        expected_artifacts = {artifact["name"]: artifact["sha256"] for artifact in expected["artifacts"]}
        for identity in identities:
            try:
                validate_distribution_identity(name, identity, plan["artifact_tuple"])
            except ConformanceError:
                failures.append(f"{name} native evidence has an invalid executed distribution identity")
                continue
            if identity["kind"] != expected["kind"] or identity["locator"] != expected["locator"]:
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
    for name in required_distributions:
        if name not in observed_versions:
            failures.append(f"native evidence does not report the exact {name} artifact version")
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
) -> dict[str, Any]:
    validate_plan(plan)
    validate_contract(contract)
    if sha256_bytes(canonical_json(contract)) != plan["runner"]["contract_sha256"]:
        raise ConformanceError("execution contract does not match the runner revision bound into the plan")
    if experiment not in EXPERIMENTS:
        raise ConformanceError(f"unknown beta conformance experiment: {experiment}")
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
    for runner in specification["runners"]:
        runner_path = artifact_root / safe_relative_path(runner["path"])
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
                "native_result_sha256": None,
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
            environment = artifact_environment(plan, scratch)
            returncode, timed_out = execute_command(
                ["bash", str(runner_path), "--result-dir", str(native_dir)],
                cwd=artifact_root,
                environment=environment,
                timeout_seconds=specification["timeout_seconds"],
                stdout_path=stdout_path,
                stderr_path=stderr_path,
            )
            stdout_tail, stdout_digest = tail_and_digest(stdout_path)
            stderr_tail, stderr_digest = tail_and_digest(stderr_path)
            native_path = native_dir / runner["result"]
            native: Any = None
            native_digest = None
            if native_path.is_file():
                try:
                    native = load_json(native_path)
                    native_digest = sha256_file(native_path)
                except ConformanceError as error:
                    stderr_tail = bounded_text(f"{stderr_tail}\n{error}", DIAGNOSTIC_LIMIT)
            native_outcome, runner_blocked, findings = native_state(native)
            classification, retryable = classify_attempt(
                returncode=returncode,
                timed_out=timed_out,
                native_outcome=native_outcome,
                runner_blocked=runner_blocked,
                diagnostic_text=f"{stdout_tail}\n{stderr_tail}",
            )
            if classification != "passed" and not findings:
                findings = [
                    {
                        "type": "experiment_execution_failure",
                        "owning_contract": owner,
                        "summary": bounded_text(
                            "Experiment timed out."
                            if timed_out
                            else f"Published runner {runner['id']} exited with status {returncode}."
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
                    "native_result_sha256": native_digest,
                    "native_summary": summarize_native_result(native, plan),
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
                    "stderr_tail": bounded_text(message, DIAGNOSTIC_LIMIT),
                    "stderr_sha256": sha256_bytes(message.encode()),
                    "native_result_sha256": None,
                    "native_summary": None,
                    "findings": [
                        {
                            "type": "exact_artifact_binding_failure",
                            "owning_contract": owner,
                            "summary": bounded_text(failure),
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


def validate_experiment_result(result: Any, plan: dict[str, Any]) -> None:
    required = {
        "schema",
        "experiment",
        "candidate",
        "artifact_tuple",
        "source_identities",
        "distribution_identities",
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
    if not isinstance(result, dict) or set(result) != required or result.get("schema") != EXPERIMENT_RESULT_SCHEMA:
        raise ConformanceError("experiment result has an invalid top-level shape")
    if result["experiment"] not in EXPERIMENTS:
        raise ConformanceError("experiment result has an unknown experiment")
    for field in (
        "candidate",
        "artifact_tuple",
        "source_identities",
        "distribution_identities",
        "runner",
        "server_runner",
    ):
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
        or not set(required_distributions).issubset(COMPONENTS)
        or not {"server", *clients}.issubset(required_distributions)
    ):
        raise ConformanceError("experiment result has invalid required distributions")
    if result["source_policy"] != {
        "product_artifacts": "published_only",
        "orchestration_source": "exact_server_container",
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
            len(str(diagnostic.get("stdout_tail", ""))) > DIAGNOSTIC_LIMIT
            or len(str(diagnostic.get("stderr_tail", ""))) > DIAGNOSTIC_LIMIT
        ):
            raise ConformanceError("experiment result contains unbounded diagnostic output")
        findings = diagnostic.get("findings")
        if not isinstance(findings, list) or len(findings) > FINDING_LIMIT:
            raise ConformanceError("experiment result contains unbounded findings")
        native_summary = diagnostic.get("native_summary")
        if native_summary is not None:
            if not isinstance(native_summary, dict) or set(native_summary) != {
                "schema",
                "artifact_versions",
                "executed_distribution_identities",
                "scenario_statuses",
                "local_product_source_checkout_used",
            }:
                raise ConformanceError("experiment result has an invalid native summary")
            if (
                len(native_summary["artifact_versions"]) > len(COMPONENTS)
                or len(native_summary["executed_distribution_identities"]) > len(COMPONENTS)
                or len(native_summary["scenario_statuses"]) > 128
            ):
                raise ConformanceError("experiment result has an unbounded native summary")
            validate_partial_distribution_identities(
                native_summary["executed_distribution_identities"], plan["artifact_tuple"]
            )
    if classification == "passed" and artifact_binding_failures(plan, required_distributions, diagnostics):
        raise ConformanceError("passing experiment result has incomplete or mismatched native artifact evidence")


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
) -> tuple[dict[str, Any], dict[str, Path]]:
    validate_plan(plan)
    validate_contract(contract)
    if run_id < 1 or run_attempt < 1:
        raise ConformanceError("GitHub run identity must be positive")
    discovered: dict[str, tuple[dict[str, Any], Path]] = {}
    for path in result_root.rglob("experiment-result.json"):
        result = load_json(path)
        validate_experiment_result(result, plan)
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
        expected_owner = contract["experiments"][experiment]["owning_contract"]
        if result["owning_contract"] != expected_owner:
            raise ConformanceError(f"experiment result {experiment} names a different owning contract")
        expected_clients = contract["experiments"][experiment]["required_clients"]
        if result["required_clients"] != expected_clients:
            raise ConformanceError(f"experiment result {experiment} names different required clients")
        expected_distributions = contract["experiments"][experiment]["required_distributions"]
        if result["required_distributions"] != expected_distributions:
            raise ConformanceError(f"experiment result {experiment} names different required distributions")
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
                    artifact["name"]: artifact["sha256"]
                    for artifact in [*merged["artifacts"], *identity["artifacts"]]
                }
                merged["artifacts"] = [
                    {"name": artifact_name, "sha256": artifacts[artifact_name]}
                    for artifact_name in sorted(artifacts)
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
    if outcome == "pass" and set(executed_distribution_identities) != set(COMPONENTS):
        raise ConformanceError("passing suite does not retain executed identities for all seven distributions")
    evidence_tag = f"beta-conformance/{plan['candidate']['name']}/{run_id}.{run_attempt}"
    suite = {
        "schema": SUITE_RESULT_SCHEMA,
        "candidate": plan["candidate"],
        "artifact_tuple": plan["artifact_tuple"],
        "source_identities": plan["source_identities"],
        "distribution_identities": plan["distribution_identities"],
        "executed_distribution_identities": executed_distribution_identities,
        "runner": plan["runner"],
        "server_runner": plan["server_runner"],
        "source_policy": {
            "product_artifacts": "published_only",
            "orchestration_source": "exact_server_container",
            "local_product_source_checkout_used": False,
        },
        "github_run": {
            "repository": "durable-workflow/.github",
            "run_id": run_id,
            "run_attempt": run_attempt,
            "evidence_tag": evidence_tag,
        },
        "generated_at": now(),
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
    prepare.add_argument("--github-output", type=Path)

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

    aggregate = commands.add_parser("aggregate", help="aggregate retained matrix evidence")
    aggregate.add_argument("plan", type=Path)
    aggregate.add_argument("result_root", type=Path)
    aggregate.add_argument("output", type=Path)
    aggregate.add_argument("asset_dir", type=Path)
    aggregate.add_argument("--contract", type=Path, required=True)
    aggregate.add_argument("--run-id", type=int, required=True)
    aggregate.add_argument("--run-attempt", type=int, required=True)
    aggregate.add_argument("--github-output", type=Path)
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
            plan = prepare_plan(arguments.repository, manifest, contract, arguments.runner_revision)
            write_json(arguments.output, plan)
            write_github_output(
                arguments.github_output,
                {
                    "candidate": plan["candidate"]["name"],
                    "experiments": json.dumps(plan["experiments"], separators=(",", ":")),
                    "manifest_sha256": plan["candidate"]["manifest_sha256"],
                },
            )
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
    except (CandidateError, ConformanceError, OSError) as error:
        print(f"beta conformance error: {error}", file=sys.stderr)
        return 2
    raise AssertionError("unreachable")


if __name__ == "__main__":
    raise SystemExit(main())
