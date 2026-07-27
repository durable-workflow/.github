"""Load and enforce the supported seven-component product train."""

from __future__ import annotations

import hashlib
import json
import re
import urllib.error
import urllib.request
from functools import lru_cache
from pathlib import Path
from typing import Any

from scripts.beta_candidate import COMPONENTS, CandidateError

CONTRACT_PATH = Path(__file__).resolve().parents[1] / "product-train" / "current.json"
CURRENT_PLAN_PATH = Path(__file__).resolve().parents[1] / "release-plans" / "current.json"
SDK_SERVER_QUALIFICATION_PATH = Path(__file__).resolve().parents[1] / "product-train" / "sdk-server-qualification.json"
SCHEMA = "durable-workflow.product-train/v2"
SDK_SERVER_QUALIFICATION_SCHEMA = "durable-workflow.sdk-server-qualification/v1"
SDK_SERVER_QUALIFICATION_URL = (
    "https://raw.githubusercontent.com/durable-workflow/.github/main/product-train/sdk-server-qualification.json"
)
SDK_ARTIFACTS = ("sdk-php", "sdk-python", "sdk-rust")
SDK_SERVER_EXPERIMENTS = ("heartbeats", "replay", "signals-queries")
CONFORMANCE_SUITE_SCHEMA = "durable-workflow.beta-conformance.suite-result/v2"
CONFORMANCE_SUITE_MAX_BYTES = 256 * 1024


def load_sdk_server_qualification(
    path: Path = SDK_SERVER_QUALIFICATION_PATH,
) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        qualification = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise CandidateError(f"cannot load SDK-to-Server qualification authority {path}: {error}") from error
    if len(raw) > 64 * 1024:
        raise CandidateError("SDK-to-Server qualification authority exceeds the 64 KiB limit")
    return qualification, raw


@lru_cache(maxsize=8)
def download_conformance_suite(source_url: str) -> bytes:
    request = urllib.request.Request(
        source_url,
        headers={
            "Accept": "application/octet-stream",
            "User-Agent": "durable-workflow-product-train/1",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(CONFORMANCE_SUITE_MAX_BYTES + 1)
    except (OSError, urllib.error.URLError) as error:
        raise CandidateError("cannot download immutable SDK-to-Server conformance suite") from error
    if len(raw) > CONFORMANCE_SUITE_MAX_BYTES:
        raise CandidateError("SDK-to-Server conformance suite exceeds the 256 KiB limit")
    return raw


def load_conformance_suite(raw: bytes, expected_sha256: str) -> dict[str, Any]:
    if not isinstance(raw, bytes):
        raise CandidateError("SDK-to-Server conformance suite must be downloaded as bytes")
    if len(raw) > CONFORMANCE_SUITE_MAX_BYTES:
        raise CandidateError("SDK-to-Server conformance suite exceeds the 256 KiB limit")
    if hashlib.sha256(raw).hexdigest() != expected_sha256:
        raise CandidateError("SDK-to-Server conformance suite does not match its pinned SHA-256")
    try:
        suite = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise CandidateError("SDK-to-Server conformance suite is not valid JSON") from error
    if not isinstance(suite, dict):
        raise CandidateError("SDK-to-Server conformance suite must be a JSON object")
    return suite


def validate_conformance_suite(
    suite: dict[str, Any],
    evidence: dict[str, Any],
    release_plan: dict[str, Any],
) -> None:
    expected_keys = {
        "schema",
        "candidate",
        "artifact_tuple",
        "source_identities",
        "distribution_identities",
        "executed_distribution_identities",
        "runtime_dependencies",
        "runner",
        "server_runner",
        "waterline_service_runner",
        "source_policy",
        "github_run",
        "generated_at",
        "outcome",
        "experiments",
    }
    if (
        set(suite) != expected_keys
        or suite.get("schema") != CONFORMANCE_SUITE_SCHEMA
        or suite.get("outcome") != "pass"
        or suite.get("github_run") != evidence["github_run"]
        or suite.get("source_policy")
        != {
            "product_artifacts": "published_only",
            "orchestration_source": "bound_control_plane_and_exact_candidate_images",
            "local_product_source_checkout_used": False,
        }
    ):
        raise CandidateError("SDK-to-Server conformance suite has an invalid or non-passing shape")

    components = release_plan["components"]
    candidate = suite["candidate"]
    expected_candidate = evidence["tag"].split("/")[-2]
    if (
        not isinstance(candidate, dict)
        or candidate.get("name") != expected_candidate
        or suite.get("artifact_tuple") != components
        or suite.get("source_identities") != {name: identity["commit"] for name, identity in components.items()}
    ):
        raise CandidateError("SDK-to-Server conformance suite does not bind the exact release-plan source tuple")

    declared_distributions = suite["distribution_identities"]
    executed_distributions = suite["executed_distribution_identities"]
    if not isinstance(declared_distributions, dict) or not isinstance(executed_distributions, dict):
        raise CandidateError("SDK-to-Server conformance suite lacks distribution identities")
    for artifact in (*SDK_ARTIFACTS, "server"):
        if not valid_distribution_identity(declared_distributions.get(artifact)):
            raise CandidateError(f"SDK-to-Server conformance suite lacks declared {artifact} distribution identity")
        if not valid_distribution_identity(executed_distributions.get(artifact)):
            raise CandidateError(f"SDK-to-Server conformance suite lacks executed {artifact} distribution identity")

    experiments = suite["experiments"]
    if not isinstance(experiments, dict):
        raise CandidateError("SDK-to-Server conformance suite lacks experiment results")
    for name in SDK_SERVER_EXPERIMENTS:
        experiment = experiments.get(name)
        if (
            not isinstance(experiment, dict)
            or set(experiment)
            != {
                "outcome",
                "classification",
                "owning_contract",
                "required_clients",
                "required_distributions",
                "result_sha256",
                "failure_fingerprint",
            }
            or experiment.get("outcome") != "pass"
            or experiment.get("classification") != "passed"
            or experiment.get("failure_fingerprint") is not None
            or not isinstance(experiment.get("required_clients"), list)
            or not all(artifact in experiment["required_clients"] for artifact in SDK_ARTIFACTS)
            or not isinstance(experiment.get("required_distributions"), list)
            or not all(artifact in experiment["required_distributions"] for artifact in ("server", *SDK_ARTIFACTS))
            or re.fullmatch(r"[0-9a-f]{64}", str(experiment.get("result_sha256", ""))) is None
        ):
            raise CandidateError(
                f"SDK-to-Server conformance suite experiment {name} must pass for PHP, Python, Rust, and Server"
            )


def validate_sdk_server_qualification(
    qualification: Any,
    release_plan: dict[str, Any],
    release_plan_reference: dict[str, str],
    *,
    suite_result_raw: bytes | None = None,
) -> dict[str, Any]:
    expected_keys = {
        "$schema",
        "schema",
        "release_plan",
        "outcome",
        "evidence",
        "bindings",
    }
    if (
        not isinstance(qualification, dict)
        or set(qualification) != expected_keys
        or qualification.get("$schema") != "./sdk-server-qualification-schema.json"
        or qualification.get("schema") != SDK_SERVER_QUALIFICATION_SCHEMA
        or qualification.get("release_plan") != release_plan_reference
        or qualification.get("outcome") != "pass"
    ):
        raise CandidateError("SDK-to-Server qualification authority has an invalid or non-passing shape")

    evidence = qualification["evidence"]
    github_run = evidence.get("github_run") if isinstance(evidence, dict) else None
    expected_evidence_url = (
        f"https://github.com/durable-workflow/.github/releases/download/{evidence.get('tag')}/suite-result.json"
        if isinstance(evidence, dict)
        else ""
    )
    if (
        not isinstance(evidence, dict)
        or set(evidence)
        != {
            "schema",
            "tag",
            "source_url",
            "sha256",
            "outcome",
            "github_run",
        }
        or evidence.get("schema") != CONFORMANCE_SUITE_SCHEMA
        or re.fullmatch(
            r"beta-conformance/beta-[a-z0-9._-]+/[1-9][0-9]*\.[1-9][0-9]*",
            str(evidence.get("tag", "")),
        )
        is None
        or evidence.get("source_url") != expected_evidence_url
        or re.fullmatch(r"[0-9a-f]{64}", str(evidence.get("sha256", ""))) is None
        or evidence.get("outcome") != "pass"
        or not isinstance(github_run, dict)
        or set(github_run) != {"repository", "run_id", "run_attempt", "evidence_tag"}
        or github_run.get("repository") != "durable-workflow/.github"
        or type(github_run.get("run_id")) is not int
        or github_run["run_id"] < 1
        or type(github_run.get("run_attempt")) is not int
        or github_run["run_attempt"] < 1
        or github_run.get("evidence_tag") != evidence.get("tag")
        or not evidence["tag"].endswith(f"/{github_run['run_id']}.{github_run['run_attempt']}")
    ):
        raise CandidateError("SDK-to-Server qualification has invalid conformance evidence")

    if suite_result_raw is None:
        suite_result_raw = download_conformance_suite(evidence["source_url"])
    suite = load_conformance_suite(suite_result_raw, evidence["sha256"])
    validate_conformance_suite(suite, evidence, release_plan)

    bindings = qualification["bindings"]
    if not isinstance(bindings, dict) or set(bindings) != set(SDK_ARTIFACTS):
        raise CandidateError("SDK-to-Server qualification must define PHP, Python, and Rust bindings")
    server = release_plan["components"]["server"]
    executed_distributions = suite["executed_distribution_identities"]
    for artifact in SDK_ARTIFACTS:
        binding = bindings[artifact]
        if (
            not isinstance(binding, dict)
            or set(binding)
            != {
                "sdk",
                "server",
                "supported_server_versions",
                "outcome",
                "experiments",
            }
            or not isinstance(binding.get("sdk"), dict)
            or set(binding["sdk"]) != {"source", "distribution"}
            or binding["sdk"].get("source") != release_plan["components"][artifact]
            or binding["sdk"].get("distribution") != executed_distributions[artifact]
            or not isinstance(binding.get("server"), dict)
            or set(binding["server"]) != {"source", "distribution"}
            or binding["server"].get("source") != server
            or binding["server"].get("distribution") != executed_distributions["server"]
            or binding.get("supported_server_versions") != server["version"]
            or binding.get("outcome") != "pass"
            or binding.get("experiments") != list(SDK_SERVER_EXPERIMENTS)
        ):
            raise CandidateError(f"SDK-to-Server qualification does not contain a passing exact {artifact} binding")
    return qualification


def valid_distribution_identity(value: Any) -> bool:
    if (
        not isinstance(value, dict)
        or set(value) != {"kind", "locator", "artifacts"}
        or value.get("kind") not in {"composer", "pypi", "crates.io", "oci"}
        or not isinstance(value.get("locator"), str)
        or not value["locator"]
        or not isinstance(value.get("artifacts"), list)
        or not value["artifacts"]
    ):
        return False
    names: set[str] = set()
    for artifact in value["artifacts"]:
        if (
            not isinstance(artifact, dict)
            or set(artifact) != {"name", "sha256"}
            or not isinstance(artifact.get("name"), str)
            or not artifact["name"]
            or artifact["name"] in names
            or re.fullmatch(r"[0-9a-f]{64}", str(artifact.get("sha256", ""))) is None
        ):
            return False
        names.add(artifact["name"])
    return True


def load_product_train(
    path: Path = CONTRACT_PATH,
    *,
    current_plan_path: Path = CURRENT_PLAN_PATH,
    qualification_path: Path = SDK_SERVER_QUALIFICATION_PATH,
) -> dict[str, Any]:
    try:
        contract = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CandidateError(f"cannot load product-train authority {path}: {error}") from error

    expected_keys = {
        "$schema",
        "schema",
        "current",
        "components",
        "trains",
        "progression",
        "historical_prereleases",
    }
    if not isinstance(contract, dict) or set(contract) != expected_keys or contract.get("schema") != SCHEMA:
        raise CandidateError("product-train authority has an invalid top-level shape")
    if contract["components"] != list(COMPONENTS):
        raise CandidateError("product-train authority components must follow release order")
    trains = contract.get("trains")
    current = contract.get("current")
    if not isinstance(trains, dict) or current not in trains:
        raise CandidateError("product-train authority does not define its current train")
    current_train = trains[current]
    if (
        not isinstance(current_train, dict)
        or current_train.get("status") != "supported"
        or set(current_train.get("versions", {})) != set(COMPONENTS)
    ):
        raise CandidateError("current product train does not define the supported seven-component tuple")
    if re.fullmatch(r"2\.0\.0-beta\.[1-9][0-9]*", str(current)) is None:
        raise CandidateError("current product train must use a 2.0.0-beta.N identifier")
    if any(not isinstance(train, dict) for train in trains.values()):
        raise CandidateError("product-train authority contains an invalid train record")
    supported = [name for name, train in trains.items() if train.get("status") == "supported"]
    if supported != [current]:
        raise CandidateError("product-train authority must define exactly one supported train")
    if any(version != current for version in current_train["versions"].values()):
        raise CandidateError("current component versions must match the synchronized train identifier")
    expected_registry_versions = dict.fromkeys(COMPONENTS, current)
    expected_registry_versions["sdk-python"] = current.replace("-beta.", "b")
    if current_train.get("registry_versions") != expected_registry_versions:
        raise CandidateError("current registry versions must identify the synchronized train")
    install = current_train.get("install")
    waterline_install = install.get("waterline") if isinstance(install, dict) else None
    if (
        not isinstance(waterline_install, dict)
        or set(waterline_install) != {"embedded", "service"}
        or any(not isinstance(command, str) or not command for command in waterline_install.values())
    ):
        raise CandidateError("current product train must publish both Waterline install modes")
    plan_reference = current_train.get("release_plan")
    try:
        plan_raw = current_plan_path.read_bytes()
        plan = json.loads(plan_raw)
    except (OSError, json.JSONDecodeError) as error:
        raise CandidateError(f"cannot load current release-plan authority {current_plan_path}: {error}") from error
    if not isinstance(plan, dict):
        raise CandidateError("current release-plan authority must be a JSON object")
    canonical_plan = (json.dumps(plan, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
    expected_plan_reference = {
        "tag": f"release-plan/{plan.get('plan')}",
        "sha256": hashlib.sha256(canonical_plan).hexdigest(),
    }
    plan_components = plan.get("components") if isinstance(plan, dict) else None
    if (
        plan_reference != expected_plan_reference
        or plan.get("channel") != "beta"
        or not isinstance(plan_components, dict)
        or {
            name: identity.get("version") if isinstance(identity, dict) else None
            for name, identity in plan_components.items()
        }
        != current_train["versions"]
    ):
        raise CandidateError("current product train does not bind its exact public release plan")

    qualification_reference = current_train.get("sdk_server_qualification")
    qualification, qualification_raw = load_sdk_server_qualification(qualification_path)
    expected_qualification_reference = {
        "schema": SDK_SERVER_QUALIFICATION_SCHEMA,
        "source_url": SDK_SERVER_QUALIFICATION_URL,
        "sha256": hashlib.sha256(qualification_raw).hexdigest(),
    }
    if qualification_reference != expected_qualification_reference:
        raise CandidateError("current product train does not bind its exact SDK-to-Server qualification")
    validate_sdk_server_qualification(qualification, plan, expected_plan_reference)
    return contract


def require_current_product_train(components: Any) -> str:
    contract = load_product_train()
    current = str(contract["current"])
    expected_versions = contract["trains"][current]["versions"]
    if not isinstance(components, dict):
        raise CandidateError("current product train requires a seven-component tuple")

    mismatches = [
        f"{name}={components.get(name, {}).get('version', '<missing>')}"
        for name, expected in expected_versions.items()
        if not isinstance(components.get(name), dict) or components[name].get("version") != expected
    ]
    if mismatches:
        raise CandidateError(
            f"new beta records must use supported product train {current}; mismatched " + ", ".join(mismatches)
        )
    return current
