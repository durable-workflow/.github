from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

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
        self.assertEqual("2.0.0-beta.21", current)
        supported = [
            name for name, train in contract["trains"].items() if train["status"] == "supported"
        ]
        self.assertEqual([current], supported)
        self.assertEqual({name: current for name in COMPONENTS}, contract["trains"][current]["versions"])
        self.assertEqual("2.0.0b21", contract["trains"][current]["registry_versions"]["sdk-python"])

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
                "workflow": "composer require durable-workflow/workflow:2.0.0-beta.21@beta",
                "sdk-php": "composer require durable-workflow/sdk:2.0.0-beta.21@beta",
                "waterline": {
                    "embedded": (
                        "composer require "
                        "durable-workflow/waterline:2.0.0-beta.21@beta "
                        "durable-workflow/workflow:2.0.0-beta.21@beta "
                        "durable-workflow/sdk:2.0.0-beta.21@beta"
                    ),
                    "service": "docker pull durableworkflow/waterline:2.0.0-beta.21",
                },
                "server": "docker pull durableworkflow/server:2.0.0-beta.21",
                "cli": "curl -fsSL https://durable-workflow.com/install.sh | VERSION=2.0.0-beta.21 sh",
                "sdk-python": "pip install durable-workflow==2.0.0-beta.21",
                "sdk-rust": "cargo add durable-workflow@=2.0.0-beta.21",
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

    def test_new_beta_tuple_must_match_current_train(self) -> None:
        components = {name: {"version": "2.0.0-beta.21", "commit": "a" * 40} for name in COMPONENTS}
        self.assertEqual("2.0.0-beta.21", require_current_product_train(components))

        components["cli"]["version"] = "0.1.95"
        with self.assertRaisesRegex(CandidateError, "supported product train 2.0.0-beta.21"):
            require_current_product_train(components)
