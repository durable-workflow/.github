from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts.waterline_train import (
    QUICKSTART_SCENARIOS,
    TrainError,
    compatibility_decision,
    read_json,
    release_identity,
    solve_composer_tuple,
    validate_contract,
    validate_successor_source,
    verify_docs_documents,
)

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "waterline-release-train.yml"
VERSIONS = {
    "cli": "2.0.0-rc.12",
    "sdk-php": "2.0.0-rc.11",
    "sdk-python": "2.0.0-rc.19",
    "sdk-rust": "2.0.0-rc.8",
    "server": "2.0.0-rc.19",
    "waterline": "2.0.0-rc.12",
    "workflow": "2.0.0-rc.13",
}


def successor_plan() -> dict:
    return {
        "schema": "durable-workflow.release-plan/v2",
        "plan": "waterline-current-successor",
        "channel": "rc",
        "foundation": {
            "tag": "beta-candidate/rc-waterline-current-successor",
            "commit": "f" * 40,
        },
        "components": {
            name: {"version": version, "commit": str(index + 1) * 40}
            for index, (name, version) in enumerate(VERSIONS.items())
        },
        "beta_authorization": None,
    }


def waterline_manifest(*, version: str, sdk: str, workflow: str) -> dict:
    return {
        "name": "durable-workflow/waterline",
        "require": {"durable-workflow/sdk": sdk},
        "require-dev": {"durable-workflow/workflow": workflow},
        "extra": {"durable-workflow": {"product-train": version}},
    }


def docs_documents(*, schema_version: int = 7) -> tuple[dict, dict, dict, dict]:
    evidence_id = "quickstart-20260809t120000z"
    evidence_url = f"https://durable-workflow.com/platform-conformance/evidence/{evidence_id}.json"
    audit = {
        "schema": "durable-workflow.docs.page-release-audit",
        "schema_version": schema_version,
        "artifact_versions": VERSIONS,
        "quickstart_qualification": {
            "role": "five_scenario_exact_current",
            "outcome": "pass",
            "artifact_versions": VERSIONS,
            "required_scenarios": list(QUICKSTART_SCENARIOS),
            "evidence": {"id": evidence_id, "url": evidence_url},
        },
    }
    published = {"artifacts": VERSIONS}
    contract = {
        "schema": "durable-workflow.docs.v2.quickstart-execution-contract",
        "scenarios": [{"id": scenario} for scenario in QUICKSTART_SCENARIOS],
    }
    evidence = {
        "schema": "durable-workflow.v2.platform-conformance.run-evidence",
        "schema_version": 1,
        "id": evidence_id,
        "experiment": "quickstart",
        "evidence_kind": "executed_run",
        "artifact_tuple": VERSIONS,
        "outcome": "pass",
        "runner_blocked": False,
    }
    return audit, published, contract, evidence


class WaterlineTrainTest(unittest.TestCase):
    def test_contract_preserves_exact_sequential_release_policy(self) -> None:
        validate_contract(read_json(ROOT / "waterline-train" / "contract.json"))

    def test_completion_schema_requires_immutable_public_identities(self) -> None:
        schema = read_json(ROOT / "waterline-train" / "completion-evidence-schema.json")

        Draft202012Validator.check_schema(schema)
        plan_authority = schema["properties"]["plan_authority"]
        self.assertIn("record_commit", plan_authority["required"])
        self.assertIn("release_asset_id", plan_authority["required"])
        self.assertIn("quickstart_evidence_sha256", schema["properties"]["deployed_docs"]["required"])

    def test_github_release_identity_must_be_public_and_immutable(self) -> None:
        with self.assertRaisesRegex(TrainError, "immutable release id"):
            release_identity({"id": True, "html_url": "https://github.com/example/release"}, label="release")
        with self.assertRaisesRegex(TrainError, "canonical public URL"):
            release_identity({"id": 42, "html_url": "https://example.test/release"}, label="release")

    def test_sdk_only_advance_routes_immediate_waterline_successor(self) -> None:
        decision = compatibility_decision(
            "2.0.0-rc.11",
            "2.0.0-rc.11",
            {"require": {"durable-workflow/sdk": "2.0.0-rc.7"}},
        )

        self.assertEqual("route_sequential_waterline_successor", decision["action"])
        self.assertEqual("2.0.0-rc.12", decision["required_successor_version"])

    def test_matching_exact_dependency_can_enter_public_qualification(self) -> None:
        decision = compatibility_decision(
            "2.0.0-rc.11",
            "2.0.0-rc.12",
            {"require": {"durable-workflow/sdk": "2.0.0-rc.11"}},
        )

        self.assertEqual("qualify_exact_current_tuple", decision["action"])

    def test_successor_source_binds_sequential_version_and_exact_packages(self) -> None:
        result = validate_successor_source(
            successor_plan(),
            waterline_manifest(
                version=VERSIONS["waterline"],
                sdk=VERSIONS["sdk-php"],
                workflow=VERSIONS["workflow"],
            ),
            waterline_manifest(
                version="2.0.0-rc.11",
                sdk="2.0.0-rc.7",
                workflow="2.0.0-rc.12",
            ),
        )

        self.assertEqual("sdk-advance-with-sequential-waterline-successor", result["kind"])
        self.assertEqual("2.0.0-rc.11", result["predecessor_waterline"])

    def test_cross_prerelease_shim_cannot_replace_the_exact_successor_pin(self) -> None:
        manifest = waterline_manifest(
            version=VERSIONS["waterline"],
            sdk=VERSIONS["sdk-php"],
            workflow=VERSIONS["workflow"],
        )
        manifest["require"]["durable-workflow/sdk"] = "^2.0.0-rc.7"

        with self.assertRaisesRegex(TrainError, "exact PHP SDK"):
            validate_successor_source(successor_plan(), manifest, manifest)

    def test_current_v7_docs_audit_can_complete_exact_public_qualification(self) -> None:
        verify_docs_documents(*docs_documents(), VERSIONS)

    def test_previous_v6_docs_audit_remains_supported(self) -> None:
        verify_docs_documents(*docs_documents(schema_version=6), VERSIONS)

    def test_unknown_docs_audit_schema_remains_fail_closed(self) -> None:
        audit, published, contract, evidence = docs_documents(schema_version=8)

        with self.assertRaisesRegex(TrainError, "unsupported schema"):
            verify_docs_documents(audit, published, contract, evidence, VERSIONS)

    def test_source_only_state_cannot_complete_without_retained_quickstart(self) -> None:
        audit, published, contract, evidence = docs_documents()
        audit["quickstart_qualification"] = {
            **audit["quickstart_qualification"],
            "outcome": "incomplete",
            "evidence": None,
        }

        with self.assertRaisesRegex(TrainError, "lack passing five-scenario"):
            verify_docs_documents(audit, published, contract, evidence, VERSIONS)

    def test_fabricated_or_stale_docs_tuple_cannot_complete(self) -> None:
        audit, published, contract, evidence = docs_documents()
        audit["artifact_versions"] = {**VERSIONS, "waterline": "2.0.0-rc.99"}

        with self.assertRaisesRegex(TrainError, "exact immutable successor tuple"):
            verify_docs_documents(audit, published, contract, evidence, VERSIONS)

    def test_tuple_mismatched_retained_run_cannot_complete(self) -> None:
        audit, published, contract, evidence = docs_documents()
        evidence["artifact_tuple"] = {**VERSIONS, "sdk-php": "2.0.0-rc.10"}

        with self.assertRaisesRegex(TrainError, "does not prove the exact current"):
            verify_docs_documents(audit, published, contract, evidence, VERSIONS)

    def test_unresolvable_composer_tuple_cannot_complete(self) -> None:
        def fail_solver(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 2, "", "dependency conflict")

        with self.assertRaisesRegex(TrainError, "not Composer-satisfiable"):
            solve_composer_tuple(VERSIONS, runner=fail_solver)

    def test_solver_evidence_is_generated_from_the_exact_tuple(self) -> None:
        def pass_solver(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess([], 0, "lock operations", "")

        evidence = solve_composer_tuple(VERSIONS, runner=pass_solver)

        self.assertEqual("pass", evidence["outcome"])
        self.assertEqual(
            {name: VERSIONS[name] for name in ("waterline", "workflow", "sdk-php")},
            evidence["artifact_tuple"],
        )

    def test_workflow_accepts_only_an_immutable_plan_identity(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("plan_tag:", source)
        self.assertIn("qualify-public", source)
        self.assertNotIn("completion_evidence", source)


if __name__ == "__main__":
    unittest.main()
