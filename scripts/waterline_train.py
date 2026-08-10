#!/usr/bin/env python3
"""Qualify a sequential Waterline successor from immutable public evidence."""

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
import urllib.parse
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.beta_candidate import (
    COMPONENTS,
    WATERLINE_SERVICE,
    CandidateError,
    PublicClient,
    require_tag_commit,
    resolve_github_tag,
    verify_composer,
    verify_oci,
)
from scripts.release_plan import validate_recorded_plan

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "waterline-train" / "contract.json"
CONTRACT_SCHEMA = "durable-workflow.waterline-release-train/v1"
COMPLETION_SCHEMA = "durable-workflow.waterline-release-completion/v3"
CONTROL_REPOSITORY = "durable-workflow/.github"
DOCS_REPOSITORY = "durable-workflow/durable-workflow.github.io"
DOCS_AUDIT_URL = "https://durable-workflow.com/docs-page-release-audit.json"
SUPPORTED_DOCS_AUDIT_SCHEMA_VERSIONS = frozenset((6, 7, 8))
QUICKSTART_CONTRACT_URL = "https://durable-workflow.com/quickstart-execution-contract.json"
QUICKSTART_EVIDENCE_URL = re.compile(
    r"^https://durable-workflow\.com/platform-conformance/evidence/"
    r"[a-z0-9][a-z0-9._-]+\.json$"
)
PLAN_TAG = re.compile(r"^release-plan/[a-z0-9][a-z0-9._-]{0,55}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
PRERELEASE = re.compile(r"^2\.0\.0-(?P<channel>beta|rc)\.(?P<number>[1-9][0-9]*)$")
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$")
QUICKSTART_SCENARIOS = (
    "php_user_local_server_completion",
    "python_user_local_server_completion",
    "rust_user_local_server_completion",
    "operator_local_server_observation",
    "laravel_user_embedded_completion",
)
COMPLETION_REQUIRES = (
    "immutable_successor_plan_identity",
    "source_bound_github_release",
    "packagist_package",
    "container_image",
    "deployed_docs_artifact_tuple",
    "exact_current_composer_laravel_boot",
    "retained_five_scenario_quickstart",
)


class TrainError(RuntimeError):
    """The Waterline/PHP release train is incomplete or inconsistent."""


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise TrainError(f"cannot read JSON from {path}: {error}") from error
    if not isinstance(value, dict):
        raise TrainError(f"{path} must contain a JSON object")
    return value


def decode_json(raw: bytes, label: str, *, maximum: int = 1024 * 1024) -> dict[str, Any]:
    if len(raw) > maximum:
        raise TrainError(f"{label} exceeds the {maximum}-byte limit")
    try:
        value = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise TrainError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise TrainError(f"{label} must contain a JSON object")
    return value


def validate_contract(contract: Mapping[str, Any]) -> None:
    expected = {
        "$schema",
        "schema",
        "composer_tuple",
        "dependency_policy",
        "completion_requires",
        "quickstart_scenarios",
    }
    if set(contract) != expected or contract.get("schema") != CONTRACT_SCHEMA:
        raise TrainError("Waterline release-train contract has an invalid shape")
    if contract.get("composer_tuple") != {
        "waterline": "durable-workflow/waterline",
        "workflow": "durable-workflow/workflow",
        "sdk-php": "durable-workflow/sdk",
    }:
        raise TrainError("release train must qualify the exact three-package Composer tuple")
    if contract.get("dependency_policy") != {
        "waterline_to_sdk": "exact",
        "conflicting_sdk_prerelease": "sequential_waterline_successor_required",
        "historical_prereleases": "immutable",
        "cross_prerelease_compatibility_shim": "forbidden",
    }:
        raise TrainError("release train must preserve exact immutable prerelease dependencies")
    if tuple(contract.get("completion_requires", ())) != COMPLETION_REQUIRES:
        raise TrainError("release train must require immutable fresh public completion evidence")
    if tuple(contract.get("quickstart_scenarios", ())) != QUICKSTART_SCENARIOS:
        raise TrainError("release train must require the five public quickstart scenarios")


def exact_sdk_requirement(waterline_manifest: Mapping[str, Any]) -> str:
    require = waterline_manifest.get("require")
    requirement = require.get("durable-workflow/sdk") if isinstance(require, dict) else None
    if not isinstance(requirement, str) or PRERELEASE.fullmatch(requirement) is None:
        raise TrainError("Waterline must declare one exact PHP SDK prerelease")
    return requirement


def exact_workflow_requirement(waterline_manifest: Mapping[str, Any]) -> str:
    require = waterline_manifest.get("require-dev")
    requirement = require.get("durable-workflow/workflow") if isinstance(require, dict) else None
    if not isinstance(requirement, str) or PRERELEASE.fullmatch(requirement) is None:
        raise TrainError("Waterline must declare one exact Workflow prerelease")
    return requirement


def next_prerelease(version: str) -> str:
    match = PRERELEASE.fullmatch(version)
    if match is None:
        raise TrainError(f"Waterline version is not a supported prerelease: {version}")
    return f"2.0.0-{match['channel']}.{int(match['number']) + 1}"


def previous_prerelease(version: str) -> str:
    match = PRERELEASE.fullmatch(version)
    if match is None or int(match["number"]) <= 1:
        raise TrainError(f"Waterline version has no supported sequential predecessor: {version}")
    return f"2.0.0-{match['channel']}.{int(match['number']) - 1}"


def advances(previous: str, successor: str) -> bool:
    before = PRERELEASE.fullmatch(previous)
    after = PRERELEASE.fullmatch(successor)
    return bool(
        before
        and after
        and before.group("channel") == after.group("channel")
        and int(after.group("number")) > int(before.group("number"))
    )


def compatibility_decision(
    sdk_version: str,
    waterline_version: str,
    waterline_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    if PRERELEASE.fullmatch(sdk_version) is None:
        raise TrainError(f"PHP SDK version is not a supported prerelease: {sdk_version}")
    required_sdk = exact_sdk_requirement(waterline_manifest)
    if required_sdk == sdk_version:
        return {
            "action": "qualify_exact_current_tuple",
            "sdk_version": sdk_version,
            "waterline_version": waterline_version,
        }
    return {
        "action": "route_sequential_waterline_successor",
        "sdk_version": sdk_version,
        "waterline_version": waterline_version,
        "waterline_required_sdk": required_sdk,
        "required_successor_version": next_prerelease(waterline_version),
    }


def _parse_time(value: object, label: str) -> dt.datetime:
    if not isinstance(value, str):
        raise TrainError(f"{label} must be an RFC 3339 timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise TrainError(f"{label} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None:
        raise TrainError(f"{label} must include a timezone")
    return parsed


def release_identity(release: Mapping[str, Any], *, label: str) -> tuple[int, str]:
    release_id = release.get("id")
    url = release.get("html_url")
    if not isinstance(release_id, int) or isinstance(release_id, bool) or release_id < 1:
        raise TrainError(f"{label} has no immutable release id")
    if not isinstance(url, str) or not url.startswith("https://github.com/"):
        raise TrainError(f"{label} has no canonical public URL")
    return release_id, url


def plan_artifact_tuple(plan: Mapping[str, Any]) -> dict[str, str]:
    components = plan.get("components")
    if not isinstance(components, dict) or set(components) != set(COMPONENTS):
        raise TrainError("successor plan must bind the complete release artifact tuple")
    result: dict[str, str] = {}
    for name, identity in components.items():
        version = identity.get("version") if isinstance(identity, dict) else None
        commit = identity.get("commit") if isinstance(identity, dict) else None
        if not isinstance(version, str) or not isinstance(commit, str) or COMMIT.fullmatch(commit) is None:
            raise TrainError(f"successor plan has an invalid {name} identity")
        result[name] = version
    for name in ("waterline", "workflow", "sdk-php"):
        if PRERELEASE.fullmatch(result[name]) is None:
            raise TrainError(f"successor plan must bind an exact prerelease {name} version")
    return result


def quickstart_contract_tuple(contract: Mapping[str, Any]) -> dict[str, str]:
    artifacts = contract.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != set(COMPONENTS):
        raise TrainError("deployed quickstart contract does not bind the complete artifact tuple")

    result: dict[str, str] = {}
    for name in COMPONENTS:
        artifact = artifacts[name]
        version = artifact.get("version") if isinstance(artifact, dict) else None
        if not isinstance(version, str) or VERSION.fullmatch(version) is None:
            raise TrainError(f"deployed quickstart contract has an invalid {name} version")
        result[name] = version
    return result


def validate_successor_source(
    plan: Mapping[str, Any],
    manifest: Mapping[str, Any],
    predecessor_manifest: Mapping[str, Any],
) -> dict[str, Any]:
    versions = plan_artifact_tuple(plan)
    if plan.get("channel") != "rc":
        raise TrainError("current Waterline train completion requires an immutable release-candidate plan")
    if manifest.get("name") != "durable-workflow/waterline":
        raise TrainError("planned Waterline source has the wrong Composer package identity")
    if exact_sdk_requirement(manifest) != versions["sdk-php"]:
        raise TrainError("planned Waterline source does not pin the exact planned PHP SDK")
    if exact_workflow_requirement(manifest) != versions["workflow"]:
        raise TrainError("planned Waterline source does not pin the exact planned Workflow package")
    declared_waterline = manifest.get("extra", {}).get("durable-workflow", {}).get("product-train")
    if declared_waterline != versions["waterline"]:
        raise TrainError("planned Waterline source does not declare the successor version")

    predecessor = previous_prerelease(versions["waterline"])
    predecessor_sdk = exact_sdk_requirement(predecessor_manifest)
    if predecessor_manifest.get("name") != "durable-workflow/waterline":
        raise TrainError("predecessor Waterline source has the wrong Composer package identity")
    if not advances(predecessor_sdk, versions["sdk-php"]):
        raise TrainError("successor does not repair an independently advanced PHP SDK prerelease")
    return {
        "outcome": "verified",
        "kind": "sdk-advance-with-sequential-waterline-successor",
        "predecessor_waterline": predecessor,
        "predecessor_sdk_requirement": predecessor_sdk,
        "successor_waterline": versions["waterline"],
        "successor_sdk_requirement": versions["sdk-php"],
    }


def github_release(client: PublicClient, repository: str, tag: str, expected_commit: str) -> dict[str, Any]:
    source = resolve_github_tag(client, repository, tag)
    require_tag_commit(source, expected_commit)
    encoded = urllib.parse.quote(tag, safe="")
    release = client.json(f"https://api.github.com/repos/{repository}/releases/tags/{encoded}")
    if release.get("draft") or release.get("tag_name") != tag:
        raise TrainError(f"GitHub release {repository}@{tag} is absent or still a draft")
    published_at = release.get("published_at")
    _parse_time(published_at, f"GitHub release {repository}@{tag}")
    release_id, release_url = release_identity(release, label=f"GitHub release {repository}@{tag}")
    return {
        "outcome": "verified",
        "repository": repository,
        "version": tag,
        "source": source,
        "release_id": release_id,
        "url": release_url,
        "published_at": published_at,
    }


def source_json(
    client: PublicClient,
    repository: str,
    commit: str,
    path: str,
    label: str,
) -> tuple[dict[str, Any], str]:
    if COMMIT.fullmatch(commit) is None:
        raise TrainError(f"{label} source commit is invalid")
    url = f"https://raw.githubusercontent.com/{repository}/{commit}/{path}"
    raw = client.bytes(url)
    return decode_json(raw, label), hashlib.sha256(raw).hexdigest()


def immutable_plan(client: PublicClient, plan_tag: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if PLAN_TAG.fullmatch(plan_tag) is None:
        raise TrainError("plan tag must be an exact release-plan identity")
    source = resolve_github_tag(client, CONTROL_REPOSITORY, plan_tag)
    plan, raw_sha256 = source_json(
        client,
        CONTROL_REPOSITORY,
        source["commit"],
        "release-plan.json",
        "immutable successor plan",
    )
    try:
        validate_recorded_plan(plan)
    except CandidateError as error:
        raise TrainError(f"immutable successor plan is invalid: {error}") from error
    if plan_tag != f"release-plan/{plan['plan']}":
        raise TrainError("plan tag does not match the immutable successor plan identity")

    encoded = urllib.parse.quote(plan_tag, safe="")
    release = client.json(f"https://api.github.com/repos/{CONTROL_REPOSITORY}/releases/tags/{encoded}")
    assets = [asset for asset in release.get("assets", []) if asset.get("name") == "release-plan.json"]
    if release.get("draft") or release.get("tag_name") != plan_tag or len(assets) != 1:
        raise TrainError("immutable successor plan has no exact GitHub release mirror")
    release_id, _release_url = release_identity(release, label="immutable successor plan release")
    asset_id = assets[0].get("id")
    asset_url = assets[0].get("browser_download_url")
    if not isinstance(asset_id, int) or isinstance(asset_id, bool) or asset_id < 1:
        raise TrainError("immutable successor plan mirror has no release asset id")
    if not isinstance(asset_url, str) or not asset_url.startswith("https://github.com/"):
        raise TrainError("immutable successor plan mirror has no canonical public URL")
    mirror_raw = client.bytes(asset_url)
    if hashlib.sha256(mirror_raw).hexdigest() != raw_sha256 or decode_json(mirror_raw, "release plan mirror") != plan:
        raise TrainError("release plan mirror differs from immutable Git authority")
    return plan, {
        "outcome": "verified",
        "tag": plan_tag,
        "record_commit": source["commit"],
        "sha256": raw_sha256,
        "release_id": release_id,
        "release_asset_id": asset_id,
        "release_asset_url": asset_url,
    }


def verify_public_artifacts(
    client: PublicClient,
    plan: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    versions = plan_artifact_tuple(plan)
    components = plan["components"]
    releases = {
        name: github_release(
            client,
            COMPONENTS[name].repository,
            versions[name],
            components[name]["commit"],
        )
        for name in ("waterline", "workflow", "sdk-php")
    }
    if _parse_time(releases["waterline"]["published_at"], "Waterline publication") <= _parse_time(
        releases["sdk-php"]["published_at"], "PHP SDK publication"
    ):
        raise TrainError("Waterline successor publication must follow the PHP SDK prerelease")

    with tempfile.TemporaryDirectory(prefix="waterline-train-artifacts-") as temporary:
        directory = Path(temporary)
        distributions = {
            name: verify_composer(
                client,
                COMPONENTS[name],
                versions[name],
                components[name]["commit"],
                directory,
            )
            for name in ("waterline", "workflow", "sdk-php")
        }
        waterline_image = verify_oci(
            client,
            WATERLINE_SERVICE,
            versions["waterline"],
            components["waterline"]["commit"],
            directory,
        )
    return releases, distributions, waterline_image


def install_laravel_boot_probe(root: Path) -> None:
    provider = root / "app" / "Providers" / "ExactCurrentQualificationServiceProvider.php"
    provider.write_text(
        """<?php

namespace App\\Providers;

use DurableWorkflow\\WorkflowClientInterface;
use Illuminate\\Support\\ServiceProvider;
use RuntimeException;

final class ExactCurrentQualificationServiceProvider extends ServiceProvider
{
    public function boot(): void
    {
        if (! interface_exists(WorkflowClientInterface::class)
            || ! $this->app->bound(WorkflowClientInterface::class)) {
            throw new RuntimeException(
                'The exact-current PHP SDK Laravel client contract is unavailable.'
            );
        }
    }
}
""",
        encoding="utf-8",
    )

    providers = root / "bootstrap" / "providers.php"
    try:
        source = providers.read_text(encoding="utf-8")
    except OSError as error:
        raise TrainError("clean Laravel application has no provider manifest") from error
    short_marker = "    AppServiceProvider::class,\n"
    qualified_marker = "    App\\Providers\\AppServiceProvider::class,\n"
    if short_marker in source:
        source = source.replace(
            "use App\\Providers\\AppServiceProvider;\n",
            "use App\\Providers\\AppServiceProvider;\n"
            "use App\\Providers\\ExactCurrentQualificationServiceProvider;\n",
            1,
        ).replace(
            short_marker,
            short_marker + "    ExactCurrentQualificationServiceProvider::class,\n",
            1,
        )
    elif qualified_marker in source:
        source = source.replace(
            qualified_marker,
            qualified_marker
            + "    App\\Providers\\ExactCurrentQualificationServiceProvider::class,\n",
            1,
        )
    else:
        raise TrainError("clean Laravel provider manifest has an unsupported shape")
    providers.write_text(source, encoding="utf-8")


def solve_composer_tuple(
    versions: Mapping[str, str],
    *,
    runner: Any = subprocess.run,
    probe_installer: Any = install_laravel_boot_probe,
) -> dict[str, Any]:
    composer_tuple = {name: versions[name] for name in ("waterline", "workflow", "sdk-php")}
    manifest = {
        "name": "durable-workflow/exact-current-qualification",
        "minimum-stability": "RC",
        "prefer-stable": True,
        "require": {
            "durable-workflow/waterline": composer_tuple["waterline"],
            "durable-workflow/workflow": composer_tuple["workflow"],
            "durable-workflow/sdk": composer_tuple["sdk-php"],
        },
    }
    with tempfile.TemporaryDirectory(prefix="waterline-train-composer-") as temporary:
        root = Path(temporary) / "laravel"
        try:
            create = runner(
                [
                    "composer",
                    "create-project",
                    "laravel/laravel",
                    str(root),
                    "^13.0",
                    "--no-install",
                    "--no-scripts",
                    "--no-interaction",
                    "--no-progress",
                    "--prefer-dist",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            raise TrainError("Composer is unavailable for clean Laravel qualification") from error
        if create.returncode != 0:
            raise TrainError("clean Laravel application could not be created for exact-current qualification")

        try:
            install = runner(
                [
                    "composer",
                    "require",
                    "--working-dir",
                    str(root),
                    "--with-all-dependencies",
                    "--no-interaction",
                    "--no-progress",
                    "--prefer-dist",
                    f"durable-workflow/waterline:{composer_tuple['waterline']}@RC",
                    f"durable-workflow/workflow:{composer_tuple['workflow']}@RC",
                    f"durable-workflow/sdk:{composer_tuple['sdk-php']}@RC",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=600,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            raise TrainError("Composer is unavailable for exact-current Laravel installation") from error
        install_output = f"{install.stdout}\n{install.stderr}"[-64 * 1024 :]
        if install.returncode != 0:
            raise TrainError(
                "exact-current Waterline, Workflow, and PHP SDK packages are not installable in Laravel"
            )

        probe_installer(root)
        try:
            discovery = runner(
                ["php", "artisan", "package:discover", "--ansi", "--no-interaction"],
                cwd=root,
                check=False,
                capture_output=True,
                text=True,
                timeout=300,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as error:
            raise TrainError("Laravel is unavailable for exact-current package discovery") from error
        discovery_output = f"{discovery.stdout}\n{discovery.stderr}"[-64 * 1024 :]
        if discovery.returncode != 0:
            raise TrainError("exact-current Composer graph does not boot through Laravel package discovery")

    return {
        "outcome": "pass",
        "artifact_tuple": composer_tuple,
        "manifest_sha256": hashlib.sha256(canonical_json(manifest)).hexdigest(),
        "install_output_sha256": hashlib.sha256(install_output.encode()).hexdigest(),
        "package_discovery_output_sha256": hashlib.sha256(discovery_output.encode()).hexdigest(),
        "laravel_boot": "pass",
    }


def verify_docs_documents(
    audit: Mapping[str, Any],
    published_versions: Mapping[str, Any],
    contract: Mapping[str, Any],
    quickstart_evidence: Mapping[str, Any],
    expected_versions: Mapping[str, str],
) -> dict[str, str]:
    if (
        audit.get("schema") != "durable-workflow.docs.page-release-audit"
        or audit.get("schema_version") not in SUPPORTED_DOCS_AUDIT_SCHEMA_VERSIONS
    ):
        raise TrainError("deployed docs release audit has an unsupported schema")
    if audit.get("artifact_versions") != expected_versions:
        raise TrainError("deployed docs do not name the exact immutable successor tuple")
    compatibility = audit.get("artifact_compatibility_evidence")
    if (
        not isinstance(compatibility, dict)
        or compatibility.get("outcome") != "pass"
        or compatibility.get("qualified_artifact_versions") != expected_versions
    ):
        raise TrainError("deployed docs install pins do not name the exact qualified successor tuple")
    if published_versions.get("artifacts") != expected_versions:
        raise TrainError("deployed docs revision does not bind the exact published artifact tuple")
    if contract.get("schema") != "durable-workflow.docs.v2.quickstart-execution-contract":
        raise TrainError("deployed quickstart contract has an unsupported schema")
    contract_tuple = quickstart_contract_tuple(contract)
    if contract_tuple != expected_versions:
        raise TrainError("deployed quickstart contract does not name the exact execution tuple")
    scenarios = contract.get("scenarios")
    observed_scenarios = (
        tuple(item.get("id") for item in scenarios if isinstance(item, dict))
        if isinstance(scenarios, list)
        else ()
    )
    if observed_scenarios != QUICKSTART_SCENARIOS:
        raise TrainError("deployed quickstart contract does not require all five scenarios in order")

    qualification = audit.get("quickstart_qualification")
    if not isinstance(qualification, dict) or qualification.get("outcome") != "pass":
        raise TrainError("deployed docs lack passing five-scenario exact-current quickstart evidence")
    if (
        qualification.get("role") != "five_scenario_exact_current"
        or qualification.get("artifact_versions") != expected_versions
        or tuple(qualification.get("required_scenarios", ())) != QUICKSTART_SCENARIOS
    ):
        raise TrainError("deployed quickstart qualification is stale or incomplete")
    if audit.get("schema_version") >= 8 and (
        qualification.get("contract_artifact_versions") != contract_tuple
        or qualification.get("execution_artifact_versions") != contract_tuple
    ):
        raise TrainError("deployed quickstart qualification does not bind contract and execution tuples")
    evidence_identity = qualification.get("evidence")
    if not isinstance(evidence_identity, dict):
        raise TrainError("deployed quickstart qualification lacks retained evidence identity")
    if (
        quickstart_evidence.get("schema") != "durable-workflow.v2.platform-conformance.run-evidence"
        or quickstart_evidence.get("schema_version") != 1
        or quickstart_evidence.get("id") != evidence_identity.get("id")
        or quickstart_evidence.get("experiment") != "quickstart"
        or quickstart_evidence.get("evidence_kind") != "executed_run"
        or quickstart_evidence.get("artifact_tuple") != contract_tuple
        or quickstart_evidence.get("outcome") != "pass"
        or quickstart_evidence.get("runner_blocked") is not False
    ):
        raise TrainError("retained quickstart evidence does not prove the exact current five-scenario run")

    evidence_qualification = quickstart_evidence.get("qualification")
    scenario_results = (
        evidence_qualification.get("scenario_results")
        if isinstance(evidence_qualification, dict)
        else None
    )
    expected_scenario_results = [
        {"id": scenario, "outcome": "pass"} for scenario in QUICKSTART_SCENARIOS
    ]
    if scenario_results != expected_scenario_results:
        raise TrainError("retained quickstart evidence does not prove all five scenarios passed")

    exact_composer_graph = evidence_qualification.get("exact_composer_graph")
    expected_composer_tuple = {
        name: contract_tuple[name] for name in ("sdk-php", "waterline", "workflow")
    }
    expected_composer_fields = {
        "outcome",
        "artifact_tuple",
        "manifest_sha256",
        "install_output_sha256",
        "package_discovery",
        "package_discovery_output_sha256",
        "laravel_boot",
    }
    if (
        not isinstance(exact_composer_graph, dict)
        or set(exact_composer_graph) != expected_composer_fields
        or exact_composer_graph.get("outcome") != "pass"
        or exact_composer_graph.get("artifact_tuple") != expected_composer_tuple
        or exact_composer_graph.get("package_discovery") != "pass"
        or exact_composer_graph.get("laravel_boot") != "pass"
        or any(
            not isinstance(exact_composer_graph.get(field), str)
            or SHA256.fullmatch(exact_composer_graph[field]) is None
            for field in (
                "manifest_sha256",
                "install_output_sha256",
                "package_discovery_output_sha256",
            )
        )
    ):
        raise TrainError(
            "retained quickstart evidence does not prove the exact Composer install, "
            "package discovery, and Laravel boot"
        )
    return contract_tuple


def verify_deployed_docs(client: PublicClient, expected_versions: Mapping[str, str]) -> dict[str, Any]:
    audit_raw = client.bytes(DOCS_AUDIT_URL)
    audit = decode_json(audit_raw, "deployed docs release audit")
    revision = audit.get("docs_revision")
    if not isinstance(revision, str) or COMMIT.fullmatch(revision) is None:
        raise TrainError("deployed docs release audit has no immutable source revision")
    versions_url = (
        f"https://raw.githubusercontent.com/{DOCS_REPOSITORY}/{revision}/"
        "scripts/published-artifact-versions.json"
    )
    versions_raw = client.bytes(versions_url)
    published_versions = decode_json(versions_raw, "deployed docs artifact tuple source")
    contract_raw = client.bytes(QUICKSTART_CONTRACT_URL)
    contract = decode_json(contract_raw, "deployed quickstart contract")

    qualification = audit.get("quickstart_qualification")
    evidence_identity = qualification.get("evidence") if isinstance(qualification, dict) else None
    evidence_url = evidence_identity.get("url") if isinstance(evidence_identity, dict) else None
    if not isinstance(evidence_url, str) or QUICKSTART_EVIDENCE_URL.fullmatch(evidence_url) is None:
        raise TrainError("deployed quickstart qualification has no retained public evidence URL")
    evidence_raw = client.bytes(evidence_url)
    evidence = decode_json(evidence_raw, "retained quickstart evidence")
    contract_tuple = verify_docs_documents(
        audit,
        published_versions,
        contract,
        evidence,
        expected_versions,
    )
    return {
        "outcome": "pass",
        "docs_revision": revision,
        "audit_url": DOCS_AUDIT_URL,
        "audit_sha256": hashlib.sha256(audit_raw).hexdigest(),
        "artifact_tuple_source_url": versions_url,
        "artifact_tuple_source_sha256": hashlib.sha256(versions_raw).hexdigest(),
        "quickstart_contract_url": QUICKSTART_CONTRACT_URL,
        "quickstart_contract_sha256": hashlib.sha256(contract_raw).hexdigest(),
        "quickstart_evidence_url": evidence_url,
        "quickstart_evidence_sha256": hashlib.sha256(evidence_raw).hexdigest(),
        "quickstart_evidence_id": evidence["id"],
        "quickstart_contract_artifact_tuple": contract_tuple,
        "quickstart_execution_artifact_tuple": evidence["artifact_tuple"],
        "artifact_tuple": dict(expected_versions),
    }


def qualify_public_completion(client: PublicClient, plan_tag: str) -> dict[str, Any]:
    plan, plan_authority = immutable_plan(client, plan_tag)
    versions = plan_artifact_tuple(plan)
    waterline_identity = plan["components"]["waterline"]
    manifest, manifest_sha256 = source_json(
        client,
        COMPONENTS["waterline"].repository,
        waterline_identity["commit"],
        "composer.json",
        "planned Waterline composer manifest",
    )
    predecessor_version = previous_prerelease(versions["waterline"])
    predecessor_source = resolve_github_tag(client, COMPONENTS["waterline"].repository, predecessor_version)
    predecessor_manifest, predecessor_manifest_sha256 = source_json(
        client,
        COMPONENTS["waterline"].repository,
        predecessor_source["commit"],
        "composer.json",
        "predecessor Waterline composer manifest",
    )
    transition = validate_successor_source(plan, manifest, predecessor_manifest)
    transition.update(
        {
            "successor_composer_sha256": manifest_sha256,
            "predecessor_source_commit": predecessor_source["commit"],
            "predecessor_composer_sha256": predecessor_manifest_sha256,
        }
    )

    try:
        releases, distributions, waterline_image = verify_public_artifacts(client, plan)
    except CandidateError as error:
        raise TrainError(f"public successor artifacts are incomplete: {error}") from error
    composer_resolution = solve_composer_tuple(versions)
    docs = verify_deployed_docs(client, versions)
    return {
        "schema": COMPLETION_SCHEMA,
        "outcome": "pass",
        "plan_authority": plan_authority,
        "artifact_tuple": versions,
        "transition": transition,
        "composer_resolution": composer_resolution,
        "public_artifacts": {
            "waterline": {
                "github_release": releases["waterline"],
                "packagist": distributions["waterline"],
                "container_image": waterline_image,
            },
            "workflow": {
                "github_release": releases["workflow"],
                "packagist": distributions["workflow"],
            },
            "sdk-php": {
                "github_release": releases["sdk-php"],
                "packagist": distributions["sdk-php"],
            },
        },
        "deployed_docs": docs,
        "quickstart": {
            "outcome": "pass",
            "evidence_id": docs["quickstart_evidence_id"],
            "evidence_url": docs["quickstart_evidence_url"],
            "evidence_sha256": docs["quickstart_evidence_sha256"],
            "artifact_tuple": versions,
            "contract_artifact_tuple": docs["quickstart_contract_artifact_tuple"],
            "execution_artifact_tuple": docs["quickstart_execution_artifact_tuple"],
            "scenarios": list(QUICKSTART_SCENARIOS),
        },
    }


def main(arguments: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate-contract")
    qualify = subparsers.add_parser("qualify-public")
    qualify.add_argument("--plan-tag", required=True)
    qualify.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args(arguments)

    validate_contract(read_json(CONTRACT_PATH))
    if args.command == "qualify-public":
        client = PublicClient(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN"))
        evidence = qualify_public_completion(client, args.plan_tag)
        args.evidence.write_bytes(canonical_json(evidence))
        print(
            "Verified immutable public Waterline successor "
            f"{evidence['artifact_tuple']['waterline']} with PHP SDK {evidence['artifact_tuple']['sdk-php']}"
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (CandidateError, TrainError) as error:
        print(f"Waterline release train incomplete: {error}")
        raise SystemExit(1) from error
