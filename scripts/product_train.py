"""Load and enforce the supported seven-component product train."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from scripts.beta_candidate import COMPONENTS, CandidateError

CONTRACT_PATH = Path(__file__).resolve().parents[1] / "product-train" / "current.json"
CURRENT_PLAN_PATH = Path(__file__).resolve().parents[1] / "release-plans" / "current.json"
SCHEMA = "durable-workflow.product-train/v2"


def load_product_train(path: Path = CONTRACT_PATH) -> dict[str, Any]:
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
        plan_raw = CURRENT_PLAN_PATH.read_bytes()
        plan = json.loads(plan_raw)
    except (OSError, json.JSONDecodeError) as error:
        raise CandidateError(f"cannot load current release-plan authority {CURRENT_PLAN_PATH}: {error}") from error
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
