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


def docs_documents(*, schema_version: int = 8) -> tuple[dict, dict, dict, dict]:
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
            "contract_artifact_versions": VERSIONS,
            "execution_artifact_versions": VERSIONS,
            "required_scenarios": list(QUICKSTART_SCENARIOS),
            "evidence": {"id": evidence_id, "url": evidence_url},
        },
    }
    published = {"artifacts": VERSIONS}
    contract = {
        "schema": "durable-workflow.docs.v2.quickstart-execution-contract",
        "artifacts": {name: {"version": version} for name, version in VERSIONS.items()},
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
        self.assertIn("laravel_boot", schema["properties"]["composer_resolution"]["required"])
        self.assertIn("contract_artifact_tuple", schema["properties"]["quickstart"]["required"])
        self.assertIn("execution_artifact_tuple", schema["properties"]["quickstart"]["required"])

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

    def test_current_v8_docs_audit_can_complete_exact_public_qualification(self) -> None:
        self.assertEqual(VERSIONS, verify_docs_documents(*docs_documents(), VERSIONS))

    def test_previous_v7_docs_audit_remains_supported(self) -> None:
        audit, published, contract, evidence = docs_documents(schema_version=7)
        audit["quickstart_qualification"].pop("contract_artifact_versions")
        audit["quickstart_qualification"].pop("execution_artifact_versions")

        verify_docs_documents(audit, published, contract, evidence, VERSIONS)

    def test_previous_v6_docs_audit_remains_supported(self) -> None:
        audit, published, contract, evidence = docs_documents(schema_version=6)
        audit["quickstart_qualification"].pop("contract_artifact_versions")
        audit["quickstart_qualification"].pop("execution_artifact_versions")

        verify_docs_documents(audit, published, contract, evidence, VERSIONS)

    def test_unknown_docs_audit_schema_remains_fail_closed(self) -> None:
        audit, published, contract, evidence = docs_documents(schema_version=9)

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

    def test_contract_tuple_must_equal_the_executed_tuple(self) -> None:
        audit, published, contract, evidence = docs_documents()
        contract["artifacts"]["sdk-php"]["version"] = "2.0.0-rc.6"

        with self.assertRaisesRegex(TrainError, "contract does not name the exact execution tuple"):
            verify_docs_documents(audit, published, contract, evidence, VERSIONS)

    def test_unresolvable_composer_tuple_cannot_complete(self) -> None:
        def fail_solver(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            returncode = 0 if args[1] == "create-project" else 2
            return subprocess.CompletedProcess(args, returncode, "", "dependency conflict")

        with self.assertRaisesRegex(TrainError, "not installable in Laravel"):
            solve_composer_tuple(VERSIONS, runner=fail_solver, probe_installer=lambda _root: None)

    def test_laravel_boot_evidence_is_generated_from_the_exact_tuple(self) -> None:
        commands: list[list[str]] = []

        def pass_solver(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            commands.append(args)
            return subprocess.CompletedProcess(args, 0, "lock operations", "")

        evidence = solve_composer_tuple(
            VERSIONS,
            runner=pass_solver,
            probe_installer=lambda _root: None,
        )

        self.assertEqual("pass", evidence["outcome"])
        self.assertEqual("pass", evidence["laravel_boot"])
        self.assertEqual(
            {name: VERSIONS[name] for name in ("waterline", "workflow", "sdk-php")},
            evidence["artifact_tuple"],
        )
        self.assertEqual("create-project", commands[0][1])
        self.assertEqual("require", commands[1][1])
        self.assertEqual(["php", "artisan", "package:discover"], commands[2][:3])
        self.assertNotIn("--dry-run", commands[1])

    def test_laravel_package_discovery_failure_cannot_complete(self) -> None:
        def discover_fail(args: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            returncode = 1 if args[0] == "php" else 0
            return subprocess.CompletedProcess(args, returncode, "", "missing interface")

        with self.assertRaisesRegex(TrainError, "does not boot through Laravel package discovery"):
            solve_composer_tuple(
                VERSIONS,
                runner=discover_fail,
                probe_installer=lambda _root: None,
            )

    def test_workflow_accepts_only_an_immutable_plan_identity(self) -> None:
        source = WORKFLOW.read_text(encoding="utf-8")

        self.assertIn("plan_tag:", source)
        self.assertIn("qualify-public", source)
        self.assertNotIn("completion_evidence", source)


if __name__ == "__main__":
    unittest.main()
