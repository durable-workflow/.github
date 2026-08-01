from __future__ import annotations

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from scripts.beta_candidate import COMPONENTS, CandidateError
from scripts.product_train import (
    SDK_ARTIFACTS,
    SDK_SERVER_EXPERIMENTS,
    download_conformance_suite,
    load_product_train,
    load_sdk_server_qualification,
    require_current_product_train,
    validate_sdk_server_qualification,
)

ROOT = Path(__file__).resolve().parents[1]


class ProductTrainTest(unittest.TestCase):
    def test_current_authority_matches_schema_and_one_supported_tuple(self) -> None:
        schema = json.loads((ROOT / "product-train" / "schema.json").read_text(encoding="utf-8"))
        contract = load_product_train()
        Draft202012Validator(schema).validate(contract)

        current = contract["current"]
        self.assertEqual("2.0.0-rc.5", current)
        supported = [name for name, train in contract["trains"].items() if train["status"] == "supported"]
        self.assertEqual([current], supported)
        self.assertEqual({name: current for name in COMPONENTS}, contract["trains"][current]["versions"])
        self.assertEqual("2.0.0rc5", contract["trains"][current]["registry_versions"]["sdk-python"])

        qualification, qualification_raw = load_sdk_server_qualification()
        qualification_schema = json.loads(
            (ROOT / "product-train" / "sdk-server-qualification-schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator(qualification_schema).validate(qualification)
        self.assertEqual("pass", qualification["outcome"])
        self.assertEqual(set(SDK_ARTIFACTS), set(qualification["bindings"]))
        self.assertTrue(
            all(
                binding["experiments"] == list(SDK_SERVER_EXPERIMENTS) for binding in qualification["bindings"].values()
            )
        )
        self.assertEqual(
            hashlib.sha256(qualification_raw).hexdigest(),
            contract["trains"][current]["sdk_server_qualification"]["sha256"],
        )

        install = contract["trains"][current]["install"]
        self.assertEqual(
            {
                "workflow": "composer require durable-workflow/workflow:2.0.0-rc.5@RC",
                "sdk-php": "composer require durable-workflow/sdk:2.0.0-rc.5@RC",
                "waterline": {
                    "embedded": (
                        "composer require "
                        "durable-workflow/waterline:2.0.0-rc.5@RC "
                        "durable-workflow/workflow:2.0.0-rc.5@RC "
                        "durable-workflow/sdk:2.0.0-rc.5@RC"
                    ),
                    "service": "docker pull durableworkflow/waterline:2.0.0-rc.5",
                },
                "server": "docker pull durableworkflow/server:2.0.0-rc.5",
                "cli": "curl -fsSL https://durable-workflow.com/install.sh | VERSION=2.0.0-rc.5 sh",
                "sdk-python": "pip install durable-workflow==2.0.0rc5",
                "sdk-rust": "cargo add durable-workflow@=2.0.0-rc.5",
            },
            install,
        )

        incomplete = json.loads(json.dumps(contract))
        del incomplete["trains"][current]["install"]["waterline"]["service"]
        with self.assertRaises(ValidationError):
            Draft202012Validator(schema).validate(incomplete)

        missing_qualification = copy.deepcopy(contract)
        del missing_qualification["trains"][current]["sdk_server_qualification"]
        with self.assertRaises(ValidationError):
            Draft202012Validator(schema).validate(missing_qualification)

    def test_mixed_component_sequences_form_one_exact_train(self) -> None:
        contract = json.loads((ROOT / "product-train" / "current.json").read_text(encoding="utf-8"))
        plan = json.loads((ROOT / "release-plans" / "current.json").read_text(encoding="utf-8"))
        current = "2.0.0-rc.13"
        plan_name = "current-2-0-20260801"
        versions = {
            "workflow": "2.0.0-rc.12",
            "waterline": "2.0.0-rc.9",
            "server": "2.0.0-rc.13",
            "cli": "2.0.0-rc.12",
            "sdk-php": "2.0.0-rc.6",
            "sdk-python": "2.0.0-rc.8",
            "sdk-rust": "2.0.0-rc.7",
        }
        plan["plan"] = plan_name
        for name, version in versions.items():
            plan["components"][name]["version"] = version
        plan_raw = (json.dumps(plan, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
        qualification_raw = b"{}\n"
        train = copy.deepcopy(contract["trains"][contract["current"]])
        train["versions"] = versions
        train["registry_versions"] = {**versions, "sdk-python": "2.0.0rc8"}
        train["install"] = {
            "workflow": "composer require durable-workflow/workflow:2.0.0-rc.12@RC",
            "sdk-php": "composer require durable-workflow/sdk:2.0.0-rc.6@RC",
            "waterline": {
                "embedded": (
                    "composer require durable-workflow/waterline:2.0.0-rc.9@RC "
                    "durable-workflow/workflow:2.0.0-rc.12@RC "
                    "durable-workflow/sdk:2.0.0-rc.6@RC"
                ),
                "service": "docker pull durableworkflow/waterline:2.0.0-rc.9",
            },
            "server": "docker pull durableworkflow/server:2.0.0-rc.13",
            "cli": "curl -fsSL https://durable-workflow.com/install.sh | VERSION=2.0.0-rc.12 sh",
            "sdk-python": "pip install durable-workflow==2.0.0rc8",
            "sdk-rust": "cargo add durable-workflow@=2.0.0-rc.7",
        }
        train["release_plan"] = {
            "tag": f"release-plan/{plan_name}",
            "sha256": hashlib.sha256(plan_raw).hexdigest(),
        }
        train["sdk_server_qualification"]["sha256"] = hashlib.sha256(qualification_raw).hexdigest()
        contract["current"] = current
        contract["trains"] = {current: train}
        contract["progression"]["prerelease"] = "independent_prerelease_components"

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            contract_path = directory / "current.json"
            plan_path = directory / "plan.json"
            qualification_path = directory / "qualification.json"
            contract_path.write_text(json.dumps(contract), encoding="utf-8")
            plan_path.write_bytes(plan_raw)
            qualification_path.write_bytes(qualification_raw)

            with mock.patch("scripts.product_train.validate_sdk_server_qualification"):
                self.assertEqual(
                    contract,
                    load_product_train(
                        contract_path,
                        current_plan_path=plan_path,
                        qualification_path=qualification_path,
                    ),
                )

                contract["trains"][current]["versions"]["sdk-rust"] = "2.0.0-beta.7"
                contract_path.write_text(json.dumps(contract), encoding="utf-8")
                with self.assertRaisesRegex(CandidateError, "selected channel"):
                    load_product_train(
                        contract_path,
                        current_plan_path=plan_path,
                        qualification_path=qualification_path,
                    )

    def test_sdk_server_qualification_fails_closed(self) -> None:
        contract = load_product_train()
        current = contract["current"]
        release_plan = json.loads((ROOT / "release-plans" / "current.json").read_text(encoding="utf-8"))
        plan_reference = contract["trains"][current]["release_plan"]
        qualification, _raw = load_sdk_server_qualification()
        suite_raw = download_conformance_suite(qualification["evidence"]["source_url"])

        failed = copy.deepcopy(qualification)
        failed["outcome"] = "fail"
        failed["bindings"]["sdk-python"]["outcome"] = "fail"
        with self.assertRaisesRegex(CandidateError, "invalid or non-passing"):
            validate_sdk_server_qualification(failed, release_plan, plan_reference)

        failed_evidence = copy.deepcopy(qualification)
        failed_evidence["evidence"]["outcome"] = "fail"
        with self.assertRaisesRegex(CandidateError, "invalid conformance evidence"):
            validate_sdk_server_qualification(
                failed_evidence,
                release_plan,
                plan_reference,
            )

        mutable_evidence = copy.deepcopy(qualification)
        mutable_evidence["evidence"]["source_url"] = (
            "https://raw.githubusercontent.com/durable-workflow/.github/main/"
            "product-train/sdk-server-qualification.json"
        )
        with self.assertRaisesRegex(CandidateError, "invalid conformance evidence"):
            validate_sdk_server_qualification(
                mutable_evidence,
                release_plan,
                plan_reference,
            )

        failed_binding = copy.deepcopy(qualification)
        failed_binding["bindings"]["sdk-python"]["outcome"] = "fail"
        with self.assertRaisesRegex(CandidateError, "passing exact sdk-python binding"):
            validate_sdk_server_qualification(
                failed_binding,
                release_plan,
                plan_reference,
            )

        mismatched = copy.deepcopy(qualification)
        mismatched["bindings"]["sdk-rust"]["server"]["source"]["version"] = "2.0.0-beta.18"
        with self.assertRaisesRegex(CandidateError, "exact sdk-rust binding"):
            validate_sdk_server_qualification(mismatched, release_plan, plan_reference)

        forged_sdk_distribution = copy.deepcopy(qualification)
        forged_sdk_distribution["bindings"]["sdk-rust"]["sdk"]["distribution"]["locator"] = (
            "crates.io:durable-workflow@9.9.9"
        )
        forged_sdk_distribution["bindings"]["sdk-rust"]["sdk"]["distribution"]["artifacts"][0]["sha256"] = "f" * 64
        with self.assertRaisesRegex(CandidateError, "exact sdk-rust binding"):
            validate_sdk_server_qualification(
                forged_sdk_distribution,
                release_plan,
                plan_reference,
                suite_result_raw=suite_raw,
            )

        forged_server_distribution = copy.deepcopy(qualification)
        forged_server_distribution["bindings"]["sdk-php"]["server"]["distribution"]["locator"] = (
            "oci:docker.io/durableworkflow/server@9.9.9"
        )
        forged_server_distribution["bindings"]["sdk-php"]["server"]["distribution"]["artifacts"][0]["sha256"] = "e" * 64
        with self.assertRaisesRegex(CandidateError, "exact sdk-php binding"):
            validate_sdk_server_qualification(
                forged_server_distribution,
                release_plan,
                plan_reference,
                suite_result_raw=suite_raw,
            )

        missing_experiment_binding = copy.deepcopy(qualification)
        missing_experiment_binding["bindings"]["sdk-python"]["experiments"].remove("signals-queries")
        with self.assertRaisesRegex(CandidateError, "exact sdk-python binding"):
            validate_sdk_server_qualification(
                missing_experiment_binding,
                release_plan,
                plan_reference,
                suite_result_raw=suite_raw,
            )

        with self.assertRaisesRegex(CandidateError, "pinned SHA-256"):
            validate_sdk_server_qualification(
                qualification,
                release_plan,
                plan_reference,
                suite_result_raw=suite_raw + b"\n",
            )

        suite_without_rust = json.loads(suite_raw)
        suite_without_rust["experiments"]["replay"]["required_clients"].remove("sdk-rust")
        suite_without_rust_raw = (
            json.dumps(suite_without_rust, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        ).encode()
        weak_qualification = copy.deepcopy(qualification)
        weak_qualification["evidence"]["sha256"] = hashlib.sha256(suite_without_rust_raw).hexdigest()
        with self.assertRaisesRegex(CandidateError, "experiment replay"):
            validate_sdk_server_qualification(
                weak_qualification,
                release_plan,
                plan_reference,
                suite_result_raw=suite_without_rust_raw,
            )

        stale_suite = json.loads(suite_raw)
        stale_suite["artifact_tuple"]["sdk-python"]["version"] = "2.0.0-beta.18"
        stale_suite_raw = (json.dumps(stale_suite, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()
        stale_qualification = copy.deepcopy(qualification)
        stale_qualification["evidence"]["sha256"] = hashlib.sha256(stale_suite_raw).hexdigest()
        with self.assertRaisesRegex(CandidateError, "exact release-plan source tuple"):
            validate_sdk_server_qualification(
                stale_qualification,
                release_plan,
                plan_reference,
                suite_result_raw=stale_suite_raw,
            )

    def test_new_prerelease_tuple_must_match_current_train(self) -> None:
        components = {name: {"version": "2.0.0-rc.5", "commit": "a" * 40} for name in COMPONENTS}
        self.assertEqual("2.0.0-rc.5", require_current_product_train(components))

        components["cli"]["version"] = "0.1.95"
        with self.assertRaisesRegex(CandidateError, "supported product train 2.0.0-rc.5"):
            require_current_product_train(components)
