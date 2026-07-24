from __future__ import annotations

import contextlib
import json
import re
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any
from unittest import mock

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

from scripts.beta_candidate import COMPONENTS, SCHEMA, canonical_json
from scripts.beta_conformance import (
    DISTRIBUTIONS,
    EXPERIMENTS,
    MAX_INFRASTRUCTURE_ATTEMPTS,
    NATIVE_FAILURE_COMPONENT_LIMIT,
    NATIVE_FAILURE_PROJECTION_LIMIT,
    NATIVE_RESULT_LIMIT,
    NATIVE_RESULT_PREFIX_LIMIT,
    RUNTIME_DEPENDENCY_SELECTORS,
    SYNTHETIC_CREDENTIAL_CANARY,
    ConformanceError,
    aggregate_results,
    artifact_binding_failures,
    bounded_text,
    classify_attempt,
    distribution_version,
    experiment_result,
    fetch_retention_source_metadata,
    inject_distribution_identity_mismatch,
    injected_failure_result,
    load_contract,
    native_failure_projection_error,
    native_result_completeness_error,
    prepare_plan,
    resolve_runtime_dependencies,
    restore_plan,
    run_experiment,
    runner_command,
    runner_required_artifact_versions,
    runner_runtime_environment,
    sha256_bytes,
    sha256_file,
    summarize_native_result,
    validate_contract,
    validate_experiment_result,
    validate_plan,
    validate_retention_ref,
    validate_retention_source,
    write_json,
)
from tests.verification_fixture import candidate_verification as complete_candidate_verification

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "beta-conformance" / "contract.json"


def beta_schema_validator(name: str) -> Draft202012Validator:
    schemas = {
        path.name: json.loads(path.read_bytes()) for path in sorted((ROOT / "beta-conformance").glob("*schema.json"))
    }
    registry = Registry().with_resources((schema["$id"], Resource.from_contents(schema)) for schema in schemas.values())
    return Draft202012Validator(schemas[name], registry=registry)


def candidate_manifest() -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "candidate": "portable-beta-test",
        "components": {
            name: {"version": f"1.2.{index}", "commit": f"{index + 1:040x}"} for index, name in enumerate(COMPONENTS)
        },
    }


def candidate_verification(candidate: dict[str, object]) -> dict[str, object]:
    return complete_candidate_verification(candidate, verified_at="2026-07-17T00:00:00Z")


class RunnerCommandTest(unittest.TestCase):
    def test_python_runner_uses_the_current_python_interpreter(self) -> None:
        self.assertEqual(
            [sys.executable, "scripts/runner.py", "--result-dir", "result"],
            runner_command(Path("scripts/runner.py"), Path("result")),
        )


def runtime_dependencies() -> dict[str, dict[str, str]]:
    dependencies = {}
    for index, (name, selector) in enumerate(RUNTIME_DEPENDENCY_SELECTORS.items(), start=1):
        digest = f"sha256:{index:064x}"
        dependencies[name] = {
            "selector": selector,
            "image": f"{selector.rsplit(':', 1)[0]}@{digest}",
            "manifest_digest": digest,
        }
    return dependencies


def successful_diagnostic(
    plan: dict[str, object],
    required_distributions: list[str] | None = None,
    *,
    required_artifact_versions: list[str] | None = None,
    runner_id: str = "fixture",
    schema: str = "fixture.result/v1",
    scenario_ids: list[str] | None = None,
) -> dict[str, object]:
    selected = required_distributions or list(DISTRIBUTIONS)
    selected_versions = required_artifact_versions or selected
    selected_scenarios = scenario_ids or ["fixture"]
    artifact_tuple = plan["artifact_tuple"]
    distribution_identities = plan["distribution_identities"]
    assert isinstance(artifact_tuple, dict)
    assert isinstance(distribution_identities, dict)
    empty_digest = sha256_bytes(b"")
    return {
        "runner": runner_id,
        "attempt": 1,
        "exit_code": 0,
        "timed_out": False,
        "native_outcome": "pass",
        "runner_blocked": False,
        "stdout_tail": "",
        "stdout_sha256": empty_digest,
        "stderr_tail": "",
        "stderr_sha256": empty_digest,
        "native_result_size_bytes": 128,
        "native_result_sha256": "b" * 64,
        "native_result_prefix_sha256": None,
        "native_result_prefix_bytes": None,
        "native_summary": {
            "schema": schema,
            "artifact_versions": {name: distribution_version(artifact_tuple, name) for name in selected_versions},
            "executed_distribution_identities": {
                name: json.loads(canonical_json(distribution_identities[name])) for name in selected
            },
            "scenario_statuses": [{"id": scenario_id, "status": "pass"} for scenario_id in selected_scenarios],
            "failure_projection": {
                "max_bytes": NATIVE_FAILURE_PROJECTION_LIMIT,
                "component_max_bytes": NATIVE_FAILURE_COMPONENT_LIMIT,
                "truncated": False,
                "scenarios": [],
            },
            "local_product_source_checkout_used": False,
        },
        "findings": [],
    }


def successful_runner_diagnostics(plan: dict[str, object], specification: dict[str, Any]) -> list[dict[str, object]]:
    return [
        successful_diagnostic(
            plan,
            runner["required_distributions"],
            required_artifact_versions=runner_required_artifact_versions(runner),
            runner_id=runner["id"],
            schema=runner.get("result_schema", "fixture.result/v1"),
            scenario_ids=runner.get("required_scenarios", ["fixture"]),
        )
        for runner in specification["runners"]
    ]


def successful_native_result(
    plan: dict[str, object],
    required_distributions: list[str],
    *,
    required_artifact_versions: list[str] | None = None,
) -> dict[str, object]:
    artifact_tuple = plan["artifact_tuple"]
    distribution_identities = plan["distribution_identities"]
    assert isinstance(artifact_tuple, dict)
    assert isinstance(distribution_identities, dict)
    selected_versions = required_artifact_versions or required_distributions
    return {
        "schema": "fixture.result/v1",
        "outcome": "pass",
        "artifact_versions": {name: distribution_version(artifact_tuple, name) for name in selected_versions},
        "executed_distribution_identities": {
            name: json.loads(canonical_json(distribution_identities[name])) for name in required_distributions
        },
        "local_product_source_checkout_used": False,
        "scenario_results": {"fixture": "pass"},
        "findings": [],
    }


class RetentionSourceTest(unittest.TestCase):
    @staticmethod
    def workflow() -> dict[str, object]:
        return {
            "id": 314998157,
            "name": "Beta conformance",
            "path": ".github/workflows/beta-conformance.yml",
            "state": "active",
        }

    @staticmethod
    def completed_run() -> dict[str, object]:
        return {
            "conclusion": "failure",
            "display_title": "Conformance alpha-workspace-unavailable-recovery-f46818553161",
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_repository": {"full_name": "durable-workflow/.github"},
            "head_sha": "1fd9296396bb8fc57f50362323e40ab9008bbc9f",
            "id": 29775218461,
            "name": "Conformance alpha-workspace-unavailable-recovery-f46818553161",
            "path": ".github/workflows/beta-conformance.yml",
            "repository": {"full_name": "durable-workflow/.github"},
            "run_attempt": 1,
            "status": "completed",
            "updated_at": "2026-07-20T20:20:06Z",
            "workflow_id": 314998157,
        }

    def test_completed_default_branch_run_is_bound_for_retention(self) -> None:
        source = validate_retention_source(
            self.completed_run(),
            self.workflow(),
            expected_run_id=29775218461,
            expected_run_attempt=1,
        )

        self.assertEqual(
            {
                "source_candidate": "alpha-workspace-unavailable-recovery-f46818553161",
                "source_completed_at": "2026-07-20T20:20:06Z",
                "source_head_sha": "1fd9296396bb8fc57f50362323e40ab9008bbc9f",
                "source_run_attempt": 1,
                "source_run_id": 29775218461,
            },
            source,
        )

    def test_retention_entrypoint_fetches_the_exact_attempt_and_workflow(self) -> None:
        responses = []
        for document in (self.completed_run(), self.workflow()):
            response = mock.MagicMock()
            response.__enter__.return_value = response
            response.read.return_value = json.dumps(document).encode()
            responses.append(response)

        with mock.patch("scripts.beta_conformance.urllib.request.urlopen", side_effect=responses) as urlopen:
            run, workflow = fetch_retention_source_metadata(29775218461, 1, "retention-token")

        self.assertEqual(self.completed_run(), run)
        self.assertEqual(self.workflow(), workflow)
        requests = [call.args[0] for call in urlopen.call_args_list]
        self.assertEqual(
            [
                "https://api.github.com/repos/durable-workflow/.github/actions/runs/29775218461/attempts/1",
                "https://api.github.com/repos/durable-workflow/.github/actions/workflows/beta-conformance.yml",
            ],
            [request.full_url for request in requests],
        )
        self.assertTrue(all(request.get_header("Authorization") == "Bearer retention-token" for request in requests))

    def test_retention_rejects_a_different_execution_authority(self) -> None:
        mutations = {
            "display_title": "Unbound retention source",
            "event": "pull_request",
            "head_branch": "feature",
            "head_repository": {"full_name": "someone/fork"},
            "head_sha": "short",
            "path": ".github/workflows/another.yml",
            "repository": {"full_name": "someone/fork"},
            "status": "in_progress",
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                run = self.completed_run()
                run[field] = value
                with self.assertRaises(ConformanceError):
                    validate_retention_source(run, self.workflow(), expected_run_id=29775218461)

        with self.assertRaisesRegex(ConformanceError, "mismatched run identity"):
            validate_retention_source(self.completed_run(), self.workflow(), expected_run_id=1)
        with self.assertRaisesRegex(ConformanceError, "mismatched run attempt"):
            validate_retention_source(
                self.completed_run(),
                self.workflow(),
                expected_run_id=29775218461,
                expected_run_attempt=2,
            )
        feature_run = self.completed_run()
        feature_run["path"] = ".github/workflows/beta-conformance.yml@feature"
        with self.assertRaisesRegex(ConformanceError, "dispatched conformance workflow"):
            validate_retention_source(feature_run, self.workflow(), expected_run_id=29775218461)

        mismatched_workflow = self.workflow()
        mismatched_workflow["id"] = 1
        with self.assertRaisesRegex(ConformanceError, "dispatched conformance workflow"):
            validate_retention_source(
                self.completed_run(),
                mismatched_workflow,
                expected_run_id=29775218461,
            )
        untrusted_workflow = self.workflow()
        untrusted_workflow["name"] = "Another workflow"
        with self.assertRaisesRegex(ConformanceError, "workflow metadata is invalid"):
            validate_retention_source(
                self.completed_run(),
                untrusted_workflow,
                expected_run_id=29775218461,
            )

    def test_workflows_separate_execution_and_retention_permissions(self) -> None:
        workflows = ROOT / ".github" / "workflows"
        execution = yaml.load((workflows / "beta-conformance.yml").read_text(), Loader=yaml.BaseLoader)
        retention = yaml.load(
            (workflows / "beta-conformance-retention.yml").read_text(),
            Loader=yaml.BaseLoader,
        )

        self.assertEqual({"contents": "read"}, execution["permissions"])
        self.assertEqual({"prepare", "conformance"}, set(execution["jobs"]))
        canary_input = execution["on"]["workflow_dispatch"]["inputs"]["injected_canary_failure_experiment"]
        self.assertEqual("none", canary_input["default"])
        self.assertEqual("none", canary_input["options"][0])
        self.assertEqual({"none", *EXPERIMENTS}, set(canary_input["options"]))
        execute_step = next(step for step in execution["jobs"]["conformance"]["steps"] if step.get("id") == "execute")
        self.assertEqual(
            "${{ inputs.injected_canary_failure_experiment }}",
            execute_step["env"]["INJECTED_CANARY_FAILURE_EXPERIMENT"],
        )
        execution_scripts = "\n".join(step.get("run", "") for step in execution["jobs"]["conformance"]["steps"])
        self.assertIn('INJECTED_CANARY_FAILURE_EXPERIMENT" = "$EXPERIMENT', execution_scripts)
        self.assertIn("injection+=(--inject-product-failure)", execution_scripts)
        self.assertEqual(["Beta conformance"], retention["on"]["workflow_run"]["workflows"])
        self.assertIn("workflow_dispatch", retention["on"])
        self.assertEqual(
            {"actions": "read", "contents": "read"},
            retention["jobs"]["bind"]["permissions"],
        )
        self.assertEqual(
            {"actions": "read", "contents": "write"},
            retention["jobs"]["retain"]["permissions"],
        )
        self.assertEqual("beta-conformance", retention["jobs"]["retain"]["environment"])
        retention_scripts = "\n".join(step.get("run", "") for step in retention["jobs"]["retain"]["steps"])
        self.assertIn("--source-head-sha", retention_scripts)
        self.assertIn("--source-candidate", retention_scripts)
        self.assertIn("evidence-ref.json evidence-ref-comparison.json", retention_scripts)
        self.assertIn("for attempt in 1 2 3", retention_scripts)

    def test_workflow_reuses_the_first_attempt_plan_or_fails_before_experiments(self) -> None:
        workflows = ROOT / ".github" / "workflows"
        execution = yaml.load((workflows / "beta-conformance.yml").read_text(), Loader=yaml.BaseLoader)
        retention = yaml.load(
            (workflows / "beta-conformance-retention.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        prepare_steps = execution["jobs"]["prepare"]["steps"]
        create = next(step for step in prepare_steps if " prepare " in f" {step.get('run', '')} ")
        restore = next(
            step
            for step in prepare_steps
            if step.get("uses") == "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
        )
        expose = next(step for step in prepare_steps if step.get("id") == "plan")
        retain = next(
            step
            for step in prepare_steps
            if step.get("uses") == "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"
        )
        plan_name = "beta-conformance-plan-${{ github.run_id }}"

        self.assertEqual("${{ github.run_attempt == 1 }}", create["if"])
        self.assertEqual("${{ github.run_attempt > 1 }}", restore["if"])
        self.assertEqual(plan_name, restore["with"]["name"])
        self.assertIn("restore-plan execution-plan.json requested-candidate.json", expose["run"])
        self.assertEqual("${{ github.run_attempt == 1 }}", retain["if"])
        self.assertEqual(plan_name, retain["with"]["name"])
        self.assertNotIn("run_attempt", restore["with"]["name"])

        conformance_restore = next(
            step
            for step in execution["jobs"]["conformance"]["steps"]
            if step.get("uses") == "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
        )
        retention_restore = next(
            step
            for step in retention["jobs"]["retain"]["steps"]
            if step.get("uses") == "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c"
            and "name" in step.get("with", {})
        )
        self.assertEqual(plan_name, conformance_restore["with"]["name"])
        self.assertEqual(
            "beta-conformance-plan-${{ needs.bind.outputs.source_run_id }}",
            retention_restore["with"]["name"],
        )

    def test_absent_evidence_tag_targets_the_protected_controller(self) -> None:
        retention = yaml.load(
            (ROOT / ".github" / "workflows" / "beta-conformance-retention.yml").read_text(),
            Loader=yaml.BaseLoader,
        )
        retention_scripts = "\n".join(step.get("run", "") for step in retention["jobs"]["retain"]["steps"])

        self.assertIn('create_target=(--target "$GITHUB_SHA")', retention_scripts)
        self.assertIn("create_target=(--verify-tag)", retention_scripts)
        self.assertNotIn('gh release create "$EVIDENCE_TAG" --target', retention_scripts)
        self.assertNotIn('--target "$SOURCE_HEAD_SHA"', retention_scripts)
        self.assertNotIn('--method POST "/repos/$GITHUB_REPOSITORY/git/refs"', retention_scripts)

    def test_historical_source_and_controller_release_target_are_distinct(self) -> None:
        tag = "beta-conformance/alpha-workspace-unavailable-recovery-f46818553161/29775218461.1"
        source_sha = "1fd9296396bb8fc57f50362323e40ab9008bbc9f"
        controller_sha = "c36b24c2a7ecca24900e4938239d3e789eaae9fd"
        ref = {"ref": f"refs/tags/{tag}", "object": {"type": "commit", "sha": controller_sha}}
        comparison = {
            "ahead_by": 0,
            "base_commit": {"sha": controller_sha},
            "behind_by": 0,
            "merge_base_commit": {"sha": controller_sha},
            "status": "identical",
        }

        self.assertEqual(
            {
                "controller_sha": controller_sha,
                "evidence_ref": f"refs/tags/{tag}",
                "evidence_sha": controller_sha,
                "source_sha": source_sha,
            },
            validate_retention_ref(
                ref,
                comparison,
                expected_tag=tag,
                source_sha=source_sha,
                controller_sha=controller_sha,
            ),
        )
        self.assertNotEqual(source_sha, controller_sha)

    def test_existing_source_ref_is_accepted_without_moving_it(self) -> None:
        tag = "beta-conformance/alpha-workspace-unavailable-recovery-f46818553161/29775218461.1"
        source_sha = "1fd9296396bb8fc57f50362323e40ab9008bbc9f"
        controller_sha = "c36b24c2a7ecca24900e4938239d3e789eaae9fd"
        ref = {"ref": f"refs/tags/{tag}", "object": {"type": "commit", "sha": source_sha}}
        comparison = {
            "ahead_by": 1,
            "base_commit": {"sha": source_sha},
            "behind_by": 0,
            "merge_base_commit": {"sha": source_sha},
            "status": "ahead",
        }

        validated = validate_retention_ref(
            ref,
            comparison,
            expected_tag=tag,
            source_sha=source_sha,
            controller_sha=controller_sha,
        )

        self.assertEqual(source_sha, validated["evidence_sha"])

    def test_release_creation_rejects_a_mismatched_or_annotated_ref(self) -> None:
        tag = "beta-conformance/alpha-workspace-unavailable-recovery-f46818553161/29775218461.1"
        source_sha = "1fd9296396bb8fc57f50362323e40ab9008bbc9f"
        controller_sha = "c36b24c2a7ecca24900e4938239d3e789eaae9fd"
        comparison = {
            "ahead_by": 1,
            "base_commit": {"sha": source_sha},
            "behind_by": 0,
            "merge_base_commit": {"sha": source_sha},
            "status": "ahead",
        }
        mutations = (
            {"ref": "refs/tags/unrelated", "object": {"type": "commit", "sha": source_sha}},
            {"ref": f"refs/tags/{tag}", "object": {"type": "tag", "sha": source_sha}},
            {"ref": f"refs/tags/{tag}", "object": {"type": "commit", "sha": "a" * 40}},
        )
        for ref in mutations:
            with self.subTest(ref=ref), self.assertRaises(ConformanceError):
                validate_retention_ref(
                    ref,
                    comparison,
                    expected_tag=tag,
                    source_sha=source_sha,
                    controller_sha=controller_sha,
                )

        diverged = dict(comparison, status="diverged", behind_by=1)
        ref = {"ref": f"refs/tags/{tag}", "object": {"type": "commit", "sha": source_sha}}
        with self.assertRaisesRegex(ConformanceError, "outside protected controller history"):
            validate_retention_ref(
                ref,
                diverged,
                expected_tag=tag,
                source_sha=source_sha,
                controller_sha=controller_sha,
            )


class CandidateRecordFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name)
        subprocess.run(["git", "init", str(self.repository)], check=True, capture_output=True)
        subprocess.run(
            ["git", "-C", str(self.repository), "config", "user.name", "Conformance Fixture"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.repository), "config", "user.email", "fixture@example.invalid"],
            check=True,
        )
        self.manifest = candidate_manifest()
        (self.repository / "candidate.json").write_bytes(canonical_json(self.manifest))
        (self.repository / "verification.json").write_bytes(canonical_json(candidate_verification(self.manifest)))
        subprocess.run(["git", "-C", str(self.repository), "add", "."], check=True)
        subprocess.run(
            ["git", "-C", str(self.repository), "commit", "-m", "Record candidate"],
            check=True,
            capture_output=True,
        )
        self.commit = subprocess.run(
            ["git", "-C", str(self.repository), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        subprocess.run(
            [
                "git",
                "-C",
                str(self.repository),
                "tag",
                f"beta-candidate/{self.manifest['candidate']}",
            ],
            check=True,
        )

    def close(self) -> None:
        self.temporary.cleanup()


class ContractTest(unittest.TestCase):
    def test_contract_is_portable_and_covers_the_required_beta_set(self) -> None:
        contract = load_contract(CONTRACT_PATH)
        self.assertEqual(set(EXPERIMENTS), set(contract["experiments"]))
        self.assertEqual(RUNTIME_DEPENDENCY_SELECTORS, contract["runtime_dependencies"])
        self.assertEqual(
            {"sdk-php", "sdk-python", "sdk-rust"},
            {
                client
                for specification in contract["experiments"].values()
                for client in specification["required_clients"]
            },
        )
        self.assertEqual(
            set(DISTRIBUTIONS),
            {
                distribution
                for specification in contract["experiments"].values()
                for distribution in specification["required_distributions"]
            },
        )
        encoded = canonical_json(contract).decode()
        self.assertIsNone(re.search(r'"/(?:[^"\\]|\\.)*"', encoded))
        self.assertNotIn("../", encoded)
        self.assertNotIn(":latest", encoded)

        for experiment, specification in contract["experiments"].items():
            with self.subTest(experiment=experiment):
                self.assertEqual(
                    set(specification["required_distributions"]),
                    {
                        distribution
                        for runner in specification["runners"]
                        for distribution in runner["required_distributions"]
                    },
                )

        php_runner = next(
            runner for runner in contract["experiments"]["polyglot"]["runners"] if runner["id"] == "php-sdk"
        )
        self.assertEqual(
            {
                "cache_backend": "redis",
                "database_backend": "mysql",
                "kind": "standalone-server",
                "namespace_environment": "DW_PHP_SDK_CONFORMANCE_NAMESPACE",
                "network_scope": "private",
                "queue_backend": "redis",
                "server_url_environment": "DW_PHP_SDK_CONFORMANCE_SERVER_URL",
                "token_environment": "DW_PHP_SDK_CONFORMANCE_TOKEN",
            },
            php_runner["runtime"],
        )
        self.assertEqual(
            ["sdk-php"],
            php_runner["required_distributions"],
        )
        self.assertEqual(
            ["sdk-php", "server"],
            runner_required_artifact_versions(php_runner),
        )
        signals_runner = contract["experiments"]["signals-queries"]["runners"][0]
        self.assertEqual("durable-workflow.v2.signal-query-runtime.result", signals_runner["result_schema"])
        self.assertEqual(
            {
                "schema",
                "started_at",
                "finished_at",
                "outcome",
                "runner_blocked",
                "artifactVersions",
                "executed_distribution_identities",
                "runtime_matrix",
                "scenario_results",
                "findings",
                "finding_links",
            },
            set(signals_runner["required_result_fields"]),
        )
        self.assertEqual(19, len(signals_runner["required_scenarios"]))
        self.assertIn("published_artifact_install_only", signals_runner["required_scenarios"])
        self.assertIn("waterline_operator_visibility", signals_runner["required_scenarios"])
        self.assertIn("waterline_service_operator_visibility", signals_runner["required_scenarios"])

    def test_contract_rejects_a_multi_runner_distribution_gap(self) -> None:
        contract = load_contract(CONTRACT_PATH)
        contract["experiments"]["heartbeats"]["runners"][2]["required_distributions"].remove("sdk-rust")

        with self.assertRaisesRegex(ConformanceError, "do not cover"):
            validate_contract(contract)

    def test_every_schema_is_parseable_draft_2020_12(self) -> None:
        for path in sorted((ROOT / "beta-conformance").glob("*schema.json")):
            schema = json.loads(path.read_bytes())
            self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])

        result_schema = json.loads((ROOT / "beta-conformance" / "result-schema.json").read_bytes())
        diagnostic = result_schema["properties"]["diagnostics"]["items"]
        self.assertTrue(
            {
                "native_result_size_bytes",
                "native_result_sha256",
                "native_result_prefix_sha256",
                "native_result_prefix_bytes",
            }.issubset(diagnostic["required"])
        )
        self.assertEqual(4, len(diagnostic["oneOf"]))
        beta_schema_validator("contract-schema.json").validate(load_contract(CONTRACT_PATH))


class PlanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = CandidateRecordFixture()
        self.contract = load_contract(CONTRACT_PATH)

    def tearDown(self) -> None:
        self.fixture.close()

    def test_plan_binds_record_tuple_sources_runner_and_oci_digest(self) -> None:
        plan = prepare_plan(
            self.fixture.repository,
            self.fixture.manifest,
            self.contract,
            self.fixture.commit,
            runtime_dependencies(),
        )
        validate_plan(plan)
        beta_schema_validator("plan-schema.json").validate(plan)
        self.assertEqual(self.fixture.commit, plan["candidate"]["record_commit"])
        self.assertEqual(self.fixture.commit, plan["runner"]["revision"])
        self.assertEqual(
            {name: identity["commit"] for name, identity in self.fixture.manifest["components"].items()},
            plan["source_identities"],
        )
        self.assertEqual(
            f"docker.io/durableworkflow/server@sha256:{'a' * 64}",
            plan["server_runner"]["image"],
        )
        self.assertEqual(
            f"docker.io/durableworkflow/waterline@sha256:{'b' * 64}",
            plan["waterline_service_runner"]["image"],
        )
        self.assertEqual(
            sha256_bytes(canonical_json(candidate_verification(self.fixture.manifest))),
            plan["candidate"]["verification_sha256"],
        )
        self.assertEqual(set(DISTRIBUTIONS), set(plan["distribution_identities"]))
        self.assertEqual(runtime_dependencies(), plan["runtime_dependencies"])

    def test_plan_rejects_missing_or_mismatched_waterline_service_evidence(self) -> None:
        plan = prepare_plan(
            self.fixture.repository,
            self.fixture.manifest,
            self.contract,
            self.fixture.commit,
            runtime_dependencies(),
        )

        missing = json.loads(canonical_json(plan))
        del missing["distribution_identities"]["waterline-service"]
        with self.assertRaisesRegex(ConformanceError, "every required distribution"):
            validate_plan(missing)
        with self.assertRaises(ValidationError):
            beta_schema_validator("plan-schema.json").validate(missing)

        mismatched = json.loads(canonical_json(plan))
        mismatched["waterline_service_runner"]["source_commit"] = "f" * 40
        with self.assertRaisesRegex(ConformanceError, "Waterline service runner"):
            validate_plan(mismatched)

    def test_prepare_resolves_declared_runtime_selectors_to_one_manifest_digest(self) -> None:
        digests = {"mysql": f"sha256:{'c' * 64}", "redis": f"sha256:{'d' * 64}"}
        commands: list[list[str]] = []

        def docker(command: list[str], **arguments: object) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            selector = command[-1]
            name = next(name for name, value in RUNTIME_DEPENDENCY_SELECTORS.items() if value == selector)
            if command[1] == "image":
                repository = name if name == "mysql" else f"docker.io/library/{name}"
                stdout = json.dumps([f"{repository}@{digests[name]}"])
            else:
                stdout = "pulled\n"
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        with mock.patch("scripts.beta_conformance.docker_runtime_command", side_effect=docker):
            resolved = resolve_runtime_dependencies(self.contract)

        self.assertEqual(4, len(commands))
        for name, selector in RUNTIME_DEPENDENCY_SELECTORS.items():
            self.assertEqual(selector, resolved[name]["selector"])
            self.assertEqual(digests[name], resolved[name]["manifest_digest"])
            self.assertEqual(
                f"{selector.rsplit(':', 1)[0]}@{digests[name]}",
                resolved[name]["image"],
            )

    def test_restore_reuses_the_plan_without_resolving_runtime_selectors(self) -> None:
        plan = prepare_plan(
            self.fixture.repository,
            self.fixture.manifest,
            self.contract,
            self.fixture.commit,
            runtime_dependencies(),
        )

        with mock.patch("scripts.beta_conformance.resolve_runtime_dependencies") as resolve:
            restored = restore_plan(plan, self.fixture.manifest, self.contract, self.fixture.commit)

        self.assertIs(plan, restored)
        resolve.assert_not_called()

    def test_restore_rejects_a_plan_from_another_run_identity(self) -> None:
        plan = prepare_plan(
            self.fixture.repository,
            self.fixture.manifest,
            self.contract,
            self.fixture.commit,
            runtime_dependencies(),
        )

        with self.subTest("runner revision"), self.assertRaisesRegex(ConformanceError, "workflow revision"):
            restore_plan(plan, self.fixture.manifest, self.contract, "f" * 40)

        with self.subTest("candidate"):
            changed_manifest = json.loads(canonical_json(self.fixture.manifest))
            changed_manifest["candidate"] = "another-candidate"
            with self.assertRaisesRegex(ConformanceError, "requested candidate"):
                restore_plan(plan, changed_manifest, self.contract, self.fixture.commit)

        with self.subTest("contract"):
            changed_contract = json.loads(canonical_json(self.contract))
            changed_contract["experiments"]["replay"]["timeout_seconds"] += 1
            with self.assertRaisesRegex(ConformanceError, "this contract"):
                restore_plan(plan, self.fixture.manifest, changed_contract, self.fixture.commit)

    def test_plan_rejects_a_mutable_runtime_dependency_reference(self) -> None:
        dependencies = runtime_dependencies()
        dependencies["mysql"]["image"] = dependencies["mysql"]["selector"]

        with self.assertRaisesRegex(ConformanceError, "exact OCI manifest binding"):
            prepare_plan(
                self.fixture.repository,
                self.fixture.manifest,
                self.contract,
                self.fixture.commit,
                dependencies,
            )

    def test_plan_rejects_tuple_mutation_after_immutable_record(self) -> None:
        changed = json.loads(canonical_json(self.fixture.manifest))
        changed["components"]["sdk-python"]["version"] = "9.9.9"
        with self.assertRaisesRegex(RuntimeError, "does not contain the requested immutable tuple"):
            prepare_plan(
                self.fixture.repository,
                changed,
                self.contract,
                self.fixture.commit,
                runtime_dependencies(),
            )


class StandaloneServerRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = CandidateRecordFixture()
        self.contract = load_contract(CONTRACT_PATH)
        self.plan = prepare_plan(
            self.fixture.repository,
            self.fixture.manifest,
            self.contract,
            self.fixture.commit,
            runtime_dependencies(),
        )
        self.temporary = tempfile.TemporaryDirectory()
        self.scratch = Path(self.temporary.name)
        self.runner = next(
            runner for runner in self.contract["experiments"]["polyglot"]["runners"] if runner["id"] == "php-sdk"
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.fixture.close()

    def test_declared_runtime_uses_exact_candidate_image_and_cleans_isolated_state(self) -> None:
        commands: list[list[str]] = []

        def docker(command: list[str], **arguments: object) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            if command[1] == "port":
                stdout = "127.0.0.1:49152\n"
            elif command[1] == "inspect":
                stdout = "healthy\n" if "Health.Status" in command[3] else "true\n"
            else:
                stdout = "runtime-id\n"
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        with (
            mock.patch("scripts.beta_conformance.docker_runtime_command", side_effect=docker),
            mock.patch("scripts.beta_conformance.wait_for_server_ready") as wait_for_server,
            runner_runtime_environment(self.plan, self.runner, self.scratch) as environment,
        ):
            self.assertEqual("http://127.0.0.1:49152", environment["DW_PHP_SDK_CONFORMANCE_SERVER_URL"])
            self.assertEqual("default", environment["DW_PHP_SDK_CONFORMANCE_NAMESPACE"])
            self.assertRegex(environment["DW_PHP_SDK_CONFORMANCE_TOKEN"], r"^beta-[0-9a-f]{32}$")

        wait_for_server.assert_called_once()
        run_commands = [command for command in commands if command[1] == "run"]
        self.assertEqual(6, len(run_commands))
        server_commands = [command for command in run_commands if self.plan["server_runner"]["image"] in command]
        self.assertEqual(4, len(server_commands))
        for dependency in self.plan["runtime_dependencies"].values():
            self.assertTrue(any(dependency["image"] in command for command in run_commands))
            self.assertFalse(any(dependency["selector"] in command for command in run_commands))
        expected_version = self.plan["artifact_tuple"]["server"]["version"]
        self.assertTrue(all(f"APP_VERSION={expected_version}" in command for command in server_commands))
        self.assertTrue(all("DB_CONNECTION=mysql" in command for command in server_commands))
        self.assertTrue(all("QUEUE_CONNECTION=redis" in command for command in server_commands))
        self.assertTrue(all("CACHE_STORE=redis" in command for command in server_commands))
        self.assertTrue(all("DB_CONNECTION=sqlite" not in command for command in run_commands))
        network_commands = [command for command in commands if command[1:3] == ["network", "create"]]
        self.assertEqual(1, len(network_commands))
        network_name = network_commands[0][-1]
        self.assertTrue(all(network_name in command for command in run_commands))
        self.assertTrue(any("127.0.0.1::8080" in command for command in run_commands))
        self.assertTrue(any(command[-1] == "server-bootstrap" for command in run_commands))
        self.assertTrue(any("queue:work" in command for command in run_commands))
        scheduler_commands = [command for command in run_commands if "schedule:evaluate" in command[-1]]
        self.assertEqual(1, len(scheduler_commands))
        self.assertIn("--init", scheduler_commands[0])
        self.assertEqual(12, len([command for command in commands if command[1] == "inspect"]))
        self.assertEqual(6, len([command for command in commands if command[1:3] == ["rm", "--force"]]))
        self.assertEqual(1, len([command for command in commands if command[1:3] == ["network", "rm"]]))
        self.assertFalse(any(command[1] == "volume" for command in commands))

    def test_declared_runtime_rejects_a_companion_that_exits_during_the_matrix(self) -> None:
        running_inspect_count = 0

        def docker(command: list[str], **arguments: object) -> subprocess.CompletedProcess[str]:
            nonlocal running_inspect_count
            if command[1] == "port":
                stdout = "127.0.0.1:49152\n"
            elif command[1] == "inspect":
                if "Health.Status" in command[3]:
                    stdout = "healthy\n"
                else:
                    running_inspect_count += 1
                    stdout = "false\n" if running_inspect_count == 4 else "true\n"
            elif command[1] == "logs":
                stdout = "queue worker stopped\n"
            else:
                stdout = "runtime-id\n"
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        with (
            mock.patch("scripts.beta_conformance.docker_runtime_command", side_effect=docker),
            mock.patch("scripts.beta_conformance.wait_for_server_ready"),
            self.assertRaisesRegex(ConformanceError, r"standalone server process .*queue.* exited"),
            runner_runtime_environment(self.plan, self.runner, self.scratch),
        ):
            pass

    def test_waterline_service_runtime_joins_the_private_server_network(self) -> None:
        service_runner = next(
            runner
            for runner in self.contract["experiments"]["signals-queries"]["runners"]
            if runner["id"] == "waterline-service"
        )
        commands: list[list[str]] = []

        def docker(command: list[str], **arguments: object) -> subprocess.CompletedProcess[str]:
            commands.append(command)
            if command[1] == "port":
                stdout = "127.0.0.1:49152\n"
            elif command[1] == "inspect":
                stdout = "healthy\n" if "Health.Status" in command[3] else "true\n"
            else:
                stdout = "runtime-id\n"
            return subprocess.CompletedProcess(command, 0, stdout=stdout, stderr="")

        with (
            mock.patch("scripts.beta_conformance.docker_runtime_command", side_effect=docker),
            mock.patch("scripts.beta_conformance.wait_for_server_ready"),
            runner_runtime_environment(self.plan, service_runner, self.scratch) as environment,
        ):
            network = environment["DW_WATERLINE_SERVICE_DOCKER_NETWORK"]
            server_container = network.removesuffix("-network") + "-http"
            self.assertEqual(
                f"http://{server_container}:8080",
                environment["DW_WATERLINE_SERVICE_SERVER_URL"],
            )
            self.assertNotIn("127.0.0.1", environment["DW_WATERLINE_SERVICE_SERVER_URL"])

        self.assertTrue(any(command[1:3] == ["network", "create"] and network in command for command in commands))


class FailureClassificationTest(unittest.TestCase):
    def test_semantic_failure_is_never_retried_even_when_log_mentions_503(self) -> None:
        classification, retryable = classify_attempt(
            returncode=1,
            timed_out=False,
            native_outcome="fail",
            runner_blocked=False,
            native_result_rejected=False,
            diagnostic_text="HTTP 503 appeared in a product assertion",
        )
        self.assertEqual("product_failure", classification)
        self.assertFalse(retryable)

    def test_only_classified_infrastructure_transient_is_retryable(self) -> None:
        classification, retryable = classify_attempt(
            returncode=1,
            timed_out=False,
            native_outcome=None,
            runner_blocked=False,
            native_result_rejected=False,
            diagnostic_text="registry returned 503 Service Unavailable during pull",
        )
        self.assertEqual("infrastructure_failure", classification)
        self.assertTrue(retryable)

    def test_timeout_is_a_red_owning_contract_failure_not_a_retry(self) -> None:
        classification, retryable = classify_attempt(
            returncode=-15,
            timed_out=True,
            native_outcome=None,
            runner_blocked=False,
            native_result_rejected=False,
            diagnostic_text="",
        )
        self.assertEqual("product_failure", classification)
        self.assertFalse(retryable)

    def test_rejected_native_result_is_never_retried_as_a_transient(self) -> None:
        classification, retryable = classify_attempt(
            returncode=75,
            timed_out=False,
            native_outcome=None,
            runner_blocked=True,
            native_result_rejected=True,
            diagnostic_text="tls handshake timeout",
        )
        self.assertEqual("infrastructure_failure", classification)
        self.assertFalse(retryable)

    def test_native_artifact_version_drift_stays_red(self) -> None:
        fixture = CandidateRecordFixture()
        try:
            contract = load_contract(CONTRACT_PATH)
            plan = prepare_plan(
                fixture.repository,
                fixture.manifest,
                contract,
                fixture.commit,
                runtime_dependencies(),
            )
            diagnostic = successful_diagnostic(plan, ["sdk-python"])
            diagnostic["native_summary"]["artifact_versions"] = {
                "sdk-python": "9.9.9",
            }
            failures = artifact_binding_failures(plan, ["sdk-python"], [diagnostic])
            self.assertEqual(1, len(failures))
            self.assertIn("expected exact version", failures[0])
        finally:
            fixture.close()

    def test_same_version_with_a_different_distribution_digest_stays_red(self) -> None:
        fixture = CandidateRecordFixture()
        try:
            contract = load_contract(CONTRACT_PATH)
            plan = prepare_plan(
                fixture.repository,
                fixture.manifest,
                contract,
                fixture.commit,
                runtime_dependencies(),
            )
            diagnostic = successful_diagnostic(plan, ["sdk-python"])
            diagnostic["native_summary"]["executed_distribution_identities"]["sdk-python"]["artifacts"][0]["sha256"] = (
                "f" * 64
            )
            failures = artifact_binding_failures(plan, ["sdk-python"], [diagnostic])
            self.assertEqual(1, len(failures))
            self.assertIn("sdk-python executed distribution artifact", failures[0])
        finally:
            fixture.close()

    def test_identity_failure_injection_changes_a_required_digest_not_the_version(self) -> None:
        fixture = CandidateRecordFixture()
        try:
            contract = load_contract(CONTRACT_PATH)
            plan = prepare_plan(
                fixture.repository,
                fixture.manifest,
                contract,
                fixture.commit,
                runtime_dependencies(),
            )
            diagnostic = successful_diagnostic(plan, ["sdk-python"])
            native = {
                "executed_distribution_identities": diagnostic["native_summary"]["executed_distribution_identities"]
            }
            component, artifact_name = inject_distribution_identity_mismatch(native, plan, ["sdk-python"])
            self.assertEqual("sdk-python", component)
            self.assertEqual("durable_workflow.tar.gz", artifact_name)
            self.assertEqual(
                plan["artifact_tuple"]["sdk-python"]["version"],
                diagnostic["native_summary"]["artifact_versions"]["sdk-python"],
            )
            failures = artifact_binding_failures(plan, ["sdk-python"], [diagnostic])
            self.assertEqual(1, len(failures))
            self.assertIn("does not match the candidate digest", failures[0])
        finally:
            fixture.close()

    def test_missing_distribution_evidence_stays_red(self) -> None:
        fixture = CandidateRecordFixture()
        try:
            contract = load_contract(CONTRACT_PATH)
            plan = prepare_plan(
                fixture.repository,
                fixture.manifest,
                contract,
                fixture.commit,
                runtime_dependencies(),
            )
            diagnostic = successful_diagnostic(plan, ["cli"])
            del diagnostic["native_summary"]["executed_distribution_identities"]["cli"]
            failures = artifact_binding_failures(plan, ["cli"], [diagnostic])
            self.assertEqual(1, len(failures))
            self.assertIn("executed cli distribution identity", failures[0])
        finally:
            fixture.close()

    def test_injected_product_failure_has_stable_fingerprint_and_one_attempt(self) -> None:
        fixture = CandidateRecordFixture()
        try:
            contract = load_contract(CONTRACT_PATH)
            plan = prepare_plan(
                fixture.repository,
                fixture.manifest,
                contract,
                fixture.commit,
                runtime_dependencies(),
            )
            specification = contract["experiments"]["replay"]
            first = injected_failure_result(
                plan,
                "replay",
                "deterministic-replay",
                specification["required_clients"],
                specification["required_distributions"],
                "2026-07-17T00:00:00Z",
            )
            second = injected_failure_result(
                plan,
                "replay",
                "deterministic-replay",
                specification["required_clients"],
                specification["required_distributions"],
                "2026-07-18T00:00:00Z",
            )
            self.assertEqual(first["failure_fingerprint"], second["failure_fingerprint"])
            self.assertEqual(1, first["retry"]["attempts"])
            self.assertEqual(MAX_INFRASTRUCTURE_ATTEMPTS, first["retry"]["maximum_infrastructure_attempts"])
            self.assertFalse(first["retry"]["semantic_failures_retryable"])
            validate_experiment_result(first, plan, contract)
        finally:
            fixture.close()


class ExperimentRetryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = CandidateRecordFixture()
        self.contract = load_contract(CONTRACT_PATH)
        self.plan = prepare_plan(
            self.fixture.repository,
            self.fixture.manifest,
            self.contract,
            self.fixture.commit,
            runtime_dependencies(),
        )
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifact_root = self.root / "published-server"
        self.result_dir = self.root / "result"
        self.specification = self.contract["experiments"]["replay"]
        self.runner = self.specification["runners"][0]
        runner_path = self.artifact_root / self.runner["path"]
        runner_path.parent.mkdir(parents=True)
        runner_path.write_text("#!/usr/bin/env bash\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.fixture.close()

    def native_result(self, outcome: str) -> dict[str, object]:
        return {
            "schema": "fixture.result/v1",
            "outcome": outcome,
            "artifact_versions": {
                name: self.plan["artifact_tuple"][name]["version"]
                for name in self.specification["required_distributions"]
            },
            "executed_distribution_identities": {
                name: json.loads(canonical_json(self.plan["distribution_identities"][name]))
                for name in self.specification["required_distributions"]
            },
            "local_product_source_checkout_used": False,
            "scenario_results": {"fixture": outcome},
            "findings": (
                []
                if outcome == "pass"
                else [
                    {
                        "type": "fixture_product_failure",
                        "owning_contract": self.specification["owning_contract"],
                        "summary": "The fixture detected a semantic failure.",
                    }
                ]
            ),
        }

    def test_injected_canary_failure_asset_is_redacted_and_preserves_the_raw_digest(self) -> None:
        result = run_experiment(
            self.plan,
            self.contract,
            "replay",
            self.artifact_root,
            self.result_dir,
            inject_product_failure=True,
        )

        raw_stderr = f"deterministic synthetic sanitizer canary: Authorization: Bearer {SYNTHETIC_CREDENTIAL_CANARY}"
        diagnostic = result["diagnostics"][0]
        asset = (self.result_dir / "experiment-result.json").read_bytes()
        self.assertEqual(canonical_json(result), asset)
        self.assertIn(b"[REDACTED]", asset)
        self.assertEqual(sha256_bytes(raw_stderr.encode()), diagnostic["stderr_sha256"])
        self.assertNotIn(SYNTHETIC_CREDENTIAL_CANARY.encode(), asset)
        validate_experiment_result(result, self.plan, self.contract)

    def test_failed_runner_asset_sanitizes_every_public_diagnostic_and_preserves_raw_identities(self) -> None:
        stdout = "runner password=stdout-secret"
        stderr = "Authorization: Bearer stderr-secret"
        beta_token = "beta-0123456789abcdef0123456789abcdef"
        credential_url = "https://runner:summary-secret@example.test/failure"
        native = self.native_result("fail api_token=outcome-secret")
        native["schema"] = f"fixture.{beta_token}"
        first_distribution = self.specification["required_distributions"][0]
        native["artifact_versions"][first_distribution] = (
            f"{native['artifact_versions'][first_distribution]} db_password=version-secret"
        )
        native["findings"] = [
            {
                "type": "password=type-secret",
                "owning_contract": "Authorization: Bearer owner-secret",
                "summary": credential_url,
            }
        ]
        native_payload = canonical_json(native)

        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            stdout_path.write_text(stdout, encoding="utf-8")
            stderr_path.write_text(stderr, encoding="utf-8")
            native_dir = Path(command[-1])
            (native_dir / self.runner["result"]).write_bytes(native_payload)
            return 1, False

        with mock.patch("scripts.beta_conformance.execute_command", side_effect=execute):
            result = run_experiment(
                self.plan,
                self.contract,
                "replay",
                self.artifact_root,
                self.result_dir,
            )

        diagnostic = result["diagnostics"][0]
        rendered = canonical_json(result).decode()
        self.assertEqual(sha256_bytes(stdout.encode()), diagnostic["stdout_sha256"])
        self.assertEqual(sha256_bytes(stderr.encode()), diagnostic["stderr_sha256"])
        self.assertEqual(sha256_bytes(native_payload), diagnostic["native_result_sha256"])
        self.assertIn("[REDACTED]", rendered)
        for fragment in (
            "stdout-secret",
            "stderr-secret",
            "outcome-secret",
            beta_token,
            "version-secret",
            "type-secret",
            "owner-secret",
            "summary-secret",
        ):
            self.assertNotIn(fragment, rendered)
        validate_experiment_result(result, self.plan, self.contract)

    def test_retention_rejects_sensitive_text_in_every_public_diagnostic_surface(self) -> None:
        result = experiment_result(
            self.plan,
            "replay",
            self.specification["owning_contract"],
            self.specification["required_clients"],
            self.specification["required_distributions"],
            "2026-07-19T00:00:00Z",
            "passed",
            1,
            successful_runner_diagnostics(self.plan, self.specification),
        )
        leaks = {
            "stdout": ("stdout_tail", "password=stdout-secret"),
            "stderr": ("stderr_tail", "Authorization: Bearer stderr-secret"),
            "native outcome": ("native_outcome", "fail beta-0123456789abcdef0123456789abcdef"),
        }
        for label, (field, value) in leaks.items():
            with self.subTest(surface=label):
                leaking = json.loads(canonical_json(result))
                leaking["diagnostics"][0][field] = value
                with self.assertRaisesRegex(ConformanceError, "unsanitized sensitive text"):
                    validate_experiment_result(leaking, self.plan)

        finding_leak = json.loads(canonical_json(result))
        finding_leak["diagnostics"][0]["findings"] = [
            {
                "type": "password=type-secret",
                "owning_contract": "Authorization: Bearer owner-secret",
                "summary": "https://runner:summary-secret@example.test/failure",
            }
        ]
        with self.assertRaisesRegex(ConformanceError, "unsanitized sensitive text"):
            validate_experiment_result(finding_leak, self.plan)

        summary_leak = json.loads(canonical_json(result))
        summary_leak["diagnostics"][0]["native_summary"]["schema"] = "password=schema-secret"
        with self.assertRaisesRegex(ConformanceError, "unsanitized sensitive text"):
            validate_experiment_result(summary_leak, self.plan)

    def test_native_failure_projection_retains_attribution_and_sanitized_companion_evidence(self) -> None:
        private_token = "beta-0123456789abcdef0123456789abcdef"
        quoted_password = r"two \"quoted-password-fragment\" password-tail"
        quoted_api_token = "left,right;tail"
        escaped_password = r"escaped \\\"escaped-password-fragment\\\" escaped-tail"
        escaped_api_token = "escaped,left;tail"
        quoted_bearer = "bearer token, with; delimiters"
        multiline_password = 'line-one\nmultiline-password-secret" multiline-password-tail'
        multiline_authorization = "line-one\nmultiline-authorization-secret multiline-authorization-tail"
        native = self.native_result("fail")
        native["scenario_results"] = {
            "php_sdk_lifecycle_surface": {
                "scenario_id": "php_sdk_lifecycle_surface",
                "status": "fail",
                "observed_outputs": {
                    "failure_stage": "baseline_client",
                    "failure_classification": "server",
                    "failure_owner": "server",
                    "worker_evidence": {
                        "process_state": {"state": "exited", "alive": False, "exit_code": 1},
                        "companion": {"access_token": private_token},
                    },
                    "server_evidence": {
                        "runtime_failure": {
                            "operation": "worker.run",
                            "status_code": 500,
                            "public_error_envelope": {
                                "message": f"Authorization: Bearer {private_token}",
                                "diagnostic": (f'{{"password":"{quoted_password}","api_token":"{quoted_api_token}"}}'),
                                "quoted_header": f'{{"Authorization":"Bearer {quoted_bearer}"}}',
                                "multiline_diagnostic": f'password="{multiline_password}',
                                "multiline_header": f"Authorization: Bearer {multiline_authorization}",
                                "escaped_diagnostics": [
                                    rf"{{\"password\":\"{escaped_password}\"}}",
                                    rf"{{\"api_token\":\"{escaped_api_token}\"}}",
                                ],
                            },
                        },
                    },
                },
                "linked_findings": [
                    {
                        "classification": "server",
                        "owning_surface": "server",
                        "summary": "The companion worker exited after a worker-protocol response.",
                    }
                ],
            }
        }

        summary = summarize_native_result(native)

        self.assertIsNotNone(summary)
        assert summary is not None
        projection = summary["failure_projection"]
        self.assertLessEqual(len(canonical_json(projection)), NATIVE_FAILURE_PROJECTION_LIMIT)
        self.assertFalse(projection["truncated"])
        self.assertEqual(1, len(projection["scenarios"]))
        scenario = projection["scenarios"][0]
        self.assertEqual("baseline_client", scenario["failure_stage"])
        self.assertEqual("server", scenario["failure_classification"])
        self.assertEqual("server", scenario["failure_owner"])
        self.assertEqual("exited", scenario["worker_evidence"]["process_state"]["state"])
        self.assertEqual(500, scenario["server_evidence"]["runtime_failure"]["status_code"])
        rendered = canonical_json(projection).decode()
        self.assertNotIn(private_token, rendered)
        self.assertNotIn(quoted_password, rendered)
        self.assertNotIn(quoted_api_token, rendered)
        self.assertNotIn(escaped_password, rendered)
        self.assertNotIn(escaped_api_token, rendered)
        self.assertNotIn(quoted_bearer, rendered)
        self.assertNotIn("quoted-password-fragment", rendered)
        self.assertNotIn("password-tail", rendered)
        self.assertNotIn("escaped-password-fragment", rendered)
        self.assertNotIn("escaped-tail", rendered)
        self.assertNotIn("multiline-password-secret", rendered)
        self.assertNotIn("multiline-password-tail", rendered)
        self.assertNotIn("multiline-authorization-secret", rendered)
        self.assertNotIn("multiline-authorization-tail", rendered)
        self.assertIn("[REDACTED]", rendered)
        public_error_envelope = scenario["server_evidence"]["runtime_failure"]["public_error_envelope"]
        self.assertEqual(
            '{"password":"[REDACTED]","api_token":"[REDACTED]"}',
            public_error_envelope["diagnostic"],
        )
        self.assertEqual(
            '{"Authorization":"Bearer [REDACTED]"}',
            public_error_envelope["quoted_header"],
        )
        self.assertEqual("password=[REDACTED]", public_error_envelope["multiline_diagnostic"])
        self.assertEqual("Authorization: Bearer [REDACTED]", public_error_envelope["multiline_header"])
        escaped_diagnostics = public_error_envelope["escaped_diagnostics"]
        self.assertEqual(
            [r"{\"password\":\"[REDACTED]\"}", r"{\"api_token\":\"[REDACTED]\"}"],
            escaped_diagnostics,
        )
        self.assertEqual("", native_failure_projection_error(projection))
        escaped_diagnostics[0] = rf"{{\"password\":\"{escaped_password}\"}}"
        self.assertEqual(
            "experiment result has unsanitized native failure evidence",
            native_failure_projection_error(projection),
        )
        escaped_diagnostics[1] = r"{\"api_token\":\"[REDACTED]\"}"
        public_error_envelope["multiline_diagnostic"] = f'password="{multiline_password}'
        self.assertEqual(
            "experiment result has unsanitized native failure evidence",
            native_failure_projection_error(projection),
        )
        public_error_envelope["multiline_diagnostic"] = "password=[REDACTED]"
        public_error_envelope["multiline_header"] = f"Authorization: Bearer {multiline_authorization}"
        self.assertEqual(
            "experiment result has unsanitized native failure evidence",
            native_failure_projection_error(projection),
        )
        escaped_diagnostics[0] = r"{\"password\":\"[REDACTED]\"}"
        escaped_diagnostics[1] = rf"{{\"api_token\":\"{escaped_api_token}\"}}"
        self.assertEqual(
            "experiment result has unsanitized native failure evidence",
            native_failure_projection_error(projection),
        )

    def test_native_failure_projection_sanitizes_and_validates_attribution_strings(self) -> None:
        sensitive_values = {
            "id": r'password="scenario \"id-secret\" id-tail"',
            "status": 'fail api_token="status \\"status-secret\\"\nstatus-tail',
            "failure_stage": r'client password="stage \"stage-secret\" stage-tail"',
            "failure_classification": r'server api_token="class \"class-secret\" class-tail"',
            "failure_owner": 'server password="owner\nnewline-owner-secret" newline-owner-tail',
        }
        sensitive_fragments = {
            field: re.findall(r"[a-z]+-(?:secret|tail)", value) for field, value in sensitive_values.items()
        }
        native = self.native_result("fail")
        native["scenario_results"] = {
            "fixture": {
                "scenario_id": sensitive_values["id"],
                "status": sensitive_values["status"],
                "observed_outputs": {
                    field: sensitive_values[field]
                    for field in ("failure_stage", "failure_classification", "failure_owner")
                },
            }
        }

        summary = summarize_native_result(native)

        self.assertIsNotNone(summary)
        assert summary is not None
        projection = summary["failure_projection"]
        scenario = projection["scenarios"][0]
        retained_status = summary["scenario_statuses"][0]
        rendered_summary = canonical_json(summary).decode()
        self.assertEqual("", native_failure_projection_error(projection))
        for field, sensitive_value in sensitive_values.items():
            with self.subTest(field=field):
                self.assertNotIn(sensitive_value, scenario[field])
                self.assertIn("[REDACTED]", scenario[field])
                for fragment in sensitive_fragments[field]:
                    self.assertNotIn(fragment, scenario[field])
                    self.assertNotIn(fragment, rendered_summary)
                leaking_projection = json.loads(canonical_json(projection))
                leaking_projection["scenarios"][0][field] = sensitive_value
                self.assertEqual(
                    "experiment result has unsanitized native failure attribution",
                    native_failure_projection_error(leaking_projection),
                )
        self.assertEqual(scenario["id"], retained_status["id"])
        self.assertEqual(scenario["status"], retained_status["status"])

    def test_native_summary_validation_rejects_unsanitized_scenario_statuses(self) -> None:
        specification = self.contract["experiments"]["replay"]
        result = experiment_result(
            self.plan,
            "replay",
            specification["owning_contract"],
            specification["required_clients"],
            specification["required_distributions"],
            "2026-07-19T00:00:00Z",
            "passed",
            1,
            [successful_diagnostic(self.plan, specification["required_distributions"])],
        )
        sensitive_values = {
            "id": r'password="scenario \"id-secret\" id-tail"',
            "status": "pass api_token=status-secret\nstatus-tail",
        }

        for field, sensitive_value in sensitive_values.items():
            with self.subTest(field=field):
                leaking_result = json.loads(canonical_json(result))
                leaking_result["diagnostics"][0]["native_summary"]["scenario_statuses"][0][field] = sensitive_value
                with self.assertRaisesRegex(ConformanceError, "unsanitized native scenario statuses"):
                    validate_experiment_result(leaking_result, self.plan)

    def test_native_failure_projection_redacts_ambiguous_unquoted_scalar_suffixes(self) -> None:
        sensitive_values = {
            "failure_stage": "client password=two words tail",
            "worker_evidence": "api_token=left,right;tail",
            "server_evidence": "Authorization: Bearer [REDACTED] suffix",
        }
        native = self.native_result("fail")
        native["scenario_results"] = {
            "fixture": {
                "scenario_id": "fixture",
                "status": "fail",
                "observed_outputs": {
                    "failure_stage": sensitive_values["failure_stage"],
                    "worker_evidence": sensitive_values["worker_evidence"],
                    "server_evidence": sensitive_values["server_evidence"],
                },
            }
        }

        summary = summarize_native_result(native)

        self.assertIsNotNone(summary)
        assert summary is not None
        projection = summary["failure_projection"]
        scenario = projection["scenarios"][0]
        self.assertEqual("client password=[REDACTED]", scenario["failure_stage"])
        self.assertEqual("api_token=[REDACTED]", scenario["worker_evidence"])
        self.assertEqual("Authorization: Bearer [REDACTED]", scenario["server_evidence"])
        self.assertEqual("", native_failure_projection_error(projection))

        for field, sensitive_value in sensitive_values.items():
            with self.subTest(field=field):
                leaking_projection = json.loads(canonical_json(projection))
                leaking_projection["scenarios"][0][field] = sensitive_value
                expected_error = (
                    "experiment result has unsanitized native failure attribution"
                    if field == "failure_stage"
                    else "experiment result has unsanitized native failure evidence"
                )
                self.assertEqual(
                    expected_error,
                    native_failure_projection_error(leaking_projection),
                )

    def test_native_failure_projection_redacts_compound_sensitive_keys(self) -> None:
        sensitive_attribution = {
            "id": "case access_token=access token tail",
            "status": "fail db_password=database password tail",
            "failure_stage": "client x-api-token=x api token tail",
            "failure_owner": "server Proxy-Authorization: Bearer proxy authorization tail",
        }
        sensitive_evidence = {
            "snake": [
                "access_token=snake access tail",
                "db_password=snake database tail",
                "x_api_token=snake x api tail",
                "proxy_authorization: Bearer snake proxy tail",
            ],
            "kebab": [
                "access-token=kebab access tail",
                "db-password=kebab database tail",
                "x-api-token=kebab x api tail",
                "Proxy-Authorization: Bearer kebab proxy tail",
            ],
            "camel": [
                "accessToken=camel access tail",
                "dbPassword=camel database tail",
                "xApiToken=camel x api tail",
                "proxyAuthorization: Bearer camel proxy tail",
            ],
        }
        native = self.native_result("fail")
        native["scenario_results"] = {
            "fixture": {
                "scenario_id": sensitive_attribution["id"],
                "status": sensitive_attribution["status"],
                "observed_outputs": {
                    "failure_stage": sensitive_attribution["failure_stage"],
                    "failure_owner": sensitive_attribution["failure_owner"],
                    "worker_evidence": sensitive_evidence,
                },
            }
        }

        summary = summarize_native_result(native)

        self.assertIsNotNone(summary)
        assert summary is not None
        projection = summary["failure_projection"]
        scenario = projection["scenarios"][0]
        self.assertEqual("case access_token=[REDACTED]", scenario["id"])
        self.assertEqual("fail db_password=[REDACTED]", scenario["status"])
        self.assertEqual("client x-api-token=[REDACTED]", scenario["failure_stage"])
        self.assertEqual(
            "server Proxy-Authorization: Bearer [REDACTED]",
            scenario["failure_owner"],
        )
        for style, values in sensitive_evidence.items():
            with self.subTest(style=style):
                self.assertEqual(
                    [
                        values[0].split("=", 1)[0] + "=[REDACTED]",
                        values[1].split("=", 1)[0] + "=[REDACTED]",
                        values[2].split("=", 1)[0] + "=[REDACTED]",
                        values[3].split(":", 1)[0] + ": Bearer [REDACTED]",
                    ],
                    scenario["worker_evidence"][style],
                )
        self.assertEqual("", native_failure_projection_error(projection))

        for field, sensitive_value in sensitive_attribution.items():
            with self.subTest(field=field):
                leaking_projection = json.loads(canonical_json(projection))
                leaking_projection["scenarios"][0][field] = sensitive_value
                self.assertEqual(
                    "experiment result has unsanitized native failure attribution",
                    native_failure_projection_error(leaking_projection),
                )
        for style, values in sensitive_evidence.items():
            for index, sensitive_value in enumerate(values):
                with self.subTest(style=style, index=index):
                    leaking_projection = json.loads(canonical_json(projection))
                    leaking_projection["scenarios"][0]["worker_evidence"][style][index] = sensitive_value
                    self.assertEqual(
                        "experiment result has unsanitized native failure evidence",
                        native_failure_projection_error(leaking_projection),
                    )

    def portable_signals_query_result(self) -> tuple[dict[str, object], dict[str, object]]:
        runner = self.contract["experiments"]["signals-queries"]["runners"][0]
        native = self.native_result("pass")
        native.update(
            {
                "schema": runner["result_schema"],
                "started_at": "2026-07-19T00:00:00Z",
                "finished_at": "2026-07-19T00:01:00Z",
                "runner_blocked": False,
                "artifactVersions": native.pop("artifact_versions"),
                "runtime_matrix": {},
                "scenario_results": {
                    scenario: {"scenario_id": scenario, "status": "pass"} for scenario in runner["required_scenarios"]
                },
                "finding_links": {},
            }
        )
        return native, runner

    def test_every_declared_portable_field_is_required(self) -> None:
        native, runner = self.portable_signals_query_result()
        required_distributions = runner["required_distributions"]
        self.assertEqual("", native_result_completeness_error(native, required_distributions, runner))

        for field in runner["required_result_fields"]:
            with self.subTest(field=field):
                incomplete = dict(native)
                incomplete.pop(field)
                self.assertIn(
                    field,
                    native_result_completeness_error(incomplete, required_distributions, runner),
                )

    def test_malformed_portable_identity_bodies_are_incomplete_evidence(self) -> None:
        native, runner = self.portable_signals_query_result()
        required_distributions = runner["required_distributions"]
        malformed_identities = (
            None,
            {"kind": "pypi", "locator": "pypi:durable-workflow@1.2.0"},
            {"kind": "pypi", "locator": "pypi:durable-workflow@1.2.0", "artifacts": []},
            {
                "kind": "pypi",
                "locator": "not-a-distribution-locator",
                "artifacts": [{"name": "package.whl", "sha256": "a" * 64}],
            },
            {
                "kind": "pypi",
                "locator": "pypi:durable-workflow/sdk-python@1.2.0",
                "artifacts": [{"name": "package.whl", "sha256": "a" * 64}],
            },
            {
                "kind": "pypi",
                "locator": "pypi:durable-workflow@not-a-version",
                "artifacts": [{"name": "package.whl", "sha256": "a" * 64}],
            },
            {
                "kind": "composer",
                "locator": "composer:durable-workflow/sdk-python@1.2.0",
                "artifacts": [{"name": "package.whl", "sha256": "a" * 64}],
            },
            {
                "kind": "pypi",
                "locator": "pypi:durable-workflow@1.2.0",
                "artifacts": [{"name": "package.whl", "sha256": "not-a-digest"}],
            },
        )

        for identity in malformed_identities:
            with self.subTest(identity=identity):
                malformed = json.loads(canonical_json(native))
                malformed["executed_distribution_identities"]["sdk-python"] = identity
                self.assertIn(
                    "malformed sdk-python distribution",
                    native_result_completeness_error(malformed, required_distributions, runner),
                )

    def test_passing_outcome_cannot_hide_a_non_passing_required_scenario(self) -> None:
        native, runner = self.portable_signals_query_result()
        required_distributions = runner["required_distributions"]
        native["scenario_results"][runner["required_scenarios"][0]]["status"] = "fail"

        self.assertIn(
            "passing outcome with non-passing required scenarios",
            native_result_completeness_error(native, required_distributions, runner),
        )

    def test_classified_infrastructure_retry_can_recover_the_experiment(self) -> None:
        attempts = 0

        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            nonlocal attempts
            attempts += 1
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            stdout_path.write_text("", encoding="utf-8")
            if attempts == 1:
                stderr_path.write_text(
                    "registry returned 503 Service Unavailable during pull",
                    encoding="utf-8",
                )
                return 75, False
            stderr_path.write_text("", encoding="utf-8")
            native_dir = Path(command[-1])
            (native_dir / self.runner["result"]).write_bytes(canonical_json(self.native_result("pass")))
            return 0, False

        with (
            mock.patch("scripts.beta_conformance.execute_command", side_effect=execute),
            mock.patch("scripts.beta_conformance.time.sleep"),
        ):
            result = run_experiment(
                self.plan,
                self.contract,
                "replay",
                self.artifact_root,
                self.result_dir,
            )

        self.assertEqual(2, attempts)
        self.assertEqual("pass", result["outcome"])
        self.assertEqual("passed", result["classification"])
        self.assertIsNone(result["failure_fingerprint"])
        self.assertEqual(2, result["retry"]["attempts"])
        self.assertEqual([1, 2], [diagnostic["attempt"] for diagnostic in result["diagnostics"]])

    def test_declared_runtime_environment_reaches_the_published_runner(self) -> None:
        self.runner["runtime"] = {
            "cache_backend": "redis",
            "database_backend": "mysql",
            "kind": "standalone-server",
            "namespace_environment": "DW_PHP_SDK_CONFORMANCE_NAMESPACE",
            "network_scope": "private",
            "queue_backend": "redis",
            "server_url_environment": "DW_PHP_SDK_CONFORMANCE_SERVER_URL",
            "token_environment": "DW_PHP_SDK_CONFORMANCE_TOKEN",
        }
        self.plan = prepare_plan(
            self.fixture.repository,
            self.fixture.manifest,
            self.contract,
            self.fixture.commit,
            runtime_dependencies(),
        )

        @contextlib.contextmanager
        def runtime(*arguments: object, **options: object):
            yield {
                "DW_PHP_SDK_CONFORMANCE_NAMESPACE": "default",
                "DW_PHP_SDK_CONFORMANCE_SERVER_URL": "http://127.0.0.1:49152",
                "DW_PHP_SDK_CONFORMANCE_TOKEN": "beta-token",
            }

        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            environment = arguments["environment"]
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(environment, dict)
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            self.assertEqual("http://127.0.0.1:49152", environment["DW_PHP_SDK_CONFORMANCE_SERVER_URL"])
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            native_dir = Path(command[-1])
            (native_dir / self.runner["result"]).write_bytes(canonical_json(self.native_result("pass")))
            return 0, False

        with (
            mock.patch("scripts.beta_conformance.runner_runtime_environment", side_effect=runtime),
            mock.patch("scripts.beta_conformance.execute_command", side_effect=execute) as execute_command,
        ):
            result = run_experiment(
                self.plan,
                self.contract,
                "replay",
                self.artifact_root,
                self.result_dir,
            )

        execute_command.assert_called_once()
        self.assertEqual("pass", result["outcome"])

    def test_unavailable_declared_runtime_is_retained_without_unclassified_retry(self) -> None:
        self.runner["runtime"] = {
            "cache_backend": "redis",
            "database_backend": "mysql",
            "kind": "standalone-server",
            "namespace_environment": "DW_PHP_SDK_CONFORMANCE_NAMESPACE",
            "network_scope": "private",
            "queue_backend": "redis",
            "server_url_environment": "DW_PHP_SDK_CONFORMANCE_SERVER_URL",
            "token_environment": "DW_PHP_SDK_CONFORMANCE_TOKEN",
        }
        self.plan = prepare_plan(
            self.fixture.repository,
            self.fixture.manifest,
            self.contract,
            self.fixture.commit,
            runtime_dependencies(),
        )

        with (
            mock.patch(
                "scripts.beta_conformance.runner_runtime_environment",
                side_effect=ConformanceError("exact candidate standalone server did not become ready"),
            ),
            mock.patch("scripts.beta_conformance.execute_command") as execute_command,
        ):
            result = run_experiment(
                self.plan,
                self.contract,
                "replay",
                self.artifact_root,
                self.result_dir,
            )

        execute_command.assert_not_called()
        self.assertEqual("fail", result["outcome"])
        self.assertEqual("infrastructure_failure", result["classification"])
        self.assertEqual(1, result["retry"]["attempts"])
        self.assertTrue(result["diagnostics"][0]["runner_blocked"])
        self.assertEqual("declared_runtime_unavailable", result["diagnostics"][0]["findings"][0]["type"])

    def test_oversized_native_result_is_not_retried_with_transient_diagnostics(self) -> None:
        oversized_size = 1 << 40
        native_path = self.result_dir / "native" / self.runner["id"] / self.runner["result"]

        def bounded_digest(path: Path) -> str:
            if path == native_path:
                raise AssertionError("oversized native result must not be hashed in full")
            return sha256_file(path)

        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("tls handshake timeout", encoding="utf-8")
            native_dir = Path(command[-1])
            with (native_dir / self.runner["result"]).open("wb") as handle:
                handle.write(b"{" + b"x" * (NATIVE_RESULT_PREFIX_LIMIT - 1))
                handle.truncate(oversized_size)
            return 0, False

        with (
            mock.patch("scripts.beta_conformance.execute_command", side_effect=execute) as execute_command,
            mock.patch(
                "scripts.beta_conformance.sha256_file",
                side_effect=bounded_digest,
            ),
        ):
            result = run_experiment(
                self.plan,
                self.contract,
                "replay",
                self.artifact_root,
                self.result_dir,
            )

        execute_command.assert_called_once()
        self.assertEqual("fail", result["outcome"])
        self.assertEqual("infrastructure_failure", result["classification"])
        self.assertEqual(1, result["retry"]["attempts"])
        diagnostic = result["diagnostics"][0]
        self.assertTrue(diagnostic["runner_blocked"])
        self.assertEqual(oversized_size, diagnostic["native_result_size_bytes"])
        self.assertIsNone(diagnostic["native_result_sha256"])
        self.assertEqual(NATIVE_RESULT_PREFIX_LIMIT, diagnostic["native_result_prefix_bytes"])
        self.assertEqual(
            sha256_bytes(b"{" + b"x" * (NATIVE_RESULT_PREFIX_LIMIT - 1)),
            diagnostic["native_result_prefix_sha256"],
        )
        self.assertEqual("native_result_unreadable", diagnostic["findings"][0]["type"])
        validate_experiment_result(result, self.plan, self.contract)
        self.assertNotIn(str(self.result_dir), diagnostic["stderr_tail"])

    def test_oversized_native_prefix_read_failure_retains_unreadable_evidence(self) -> None:
        oversized_size = 1 << 40
        native_path = self.result_dir / "native" / self.runner["id"] / self.runner["result"]
        original_open = Path.open

        class PrefixReadFailure:
            def __enter__(self) -> PrefixReadFailure:
                self.handle = original_open(native_path, "rb")
                return self

            def __exit__(self, *arguments: object) -> None:
                self.handle.close()

            def fileno(self) -> int:
                return self.handle.fileno()

            def read(self, size: int = -1) -> bytes:
                raise OSError("simulated native evidence read failure")

        def open_with_prefix_failure(path: Path, *arguments: object, **options: object):
            if path == native_path and arguments == ("rb",):
                return PrefixReadFailure()
            return original_open(path, *arguments, **options)

        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            native_dir = Path(command[-1])
            with (native_dir / self.runner["result"]).open("wb") as handle:
                handle.truncate(oversized_size)
            return 0, False

        with (
            mock.patch("scripts.beta_conformance.execute_command", side_effect=execute) as execute_command,
            mock.patch.object(Path, "open", open_with_prefix_failure),
        ):
            result = run_experiment(
                self.plan,
                self.contract,
                "replay",
                self.artifact_root,
                self.result_dir,
            )

        execute_command.assert_called_once()
        retained = json.loads((self.result_dir / "experiment-result.json").read_bytes())
        self.assertEqual(result, retained)
        self.assertEqual("infrastructure_failure", result["classification"])
        self.assertEqual(1, result["retry"]["attempts"])
        self.assertEqual(1, len(result["diagnostics"]))
        diagnostic = result["diagnostics"][0]
        self.assertTrue(diagnostic["runner_blocked"])
        self.assertEqual(oversized_size, diagnostic["native_result_size_bytes"])
        self.assertIsNone(diagnostic["native_result_sha256"])
        self.assertIsNone(diagnostic["native_result_prefix_sha256"])
        self.assertIsNone(diagnostic["native_result_prefix_bytes"])
        self.assertIsNone(diagnostic["native_summary"])

    def test_malformed_native_result_is_not_retried_with_transient_diagnostics(self) -> None:
        malformed = b'{"outcome":'

        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text(
                "registry returned 503 Service Unavailable during pull",
                encoding="utf-8",
            )
            native_dir = Path(command[-1])
            (native_dir / self.runner["result"]).write_bytes(malformed)
            return 0, False

        with mock.patch("scripts.beta_conformance.execute_command", side_effect=execute) as execute_command:
            result = run_experiment(
                self.plan,
                self.contract,
                "replay",
                self.artifact_root,
                self.result_dir,
            )

        execute_command.assert_called_once()
        self.assertEqual("infrastructure_failure", result["classification"])
        self.assertEqual(1, result["retry"]["attempts"])
        diagnostic = result["diagnostics"][0]
        self.assertEqual(len(malformed), diagnostic["native_result_size_bytes"])
        self.assertEqual(sha256_bytes(malformed), diagnostic["native_result_sha256"])
        self.assertIsNone(diagnostic["native_result_prefix_sha256"])

    def test_incomplete_native_result_is_not_retried_with_transient_diagnostics(self) -> None:
        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("tls handshake timeout", encoding="utf-8")
            native_dir = Path(command[-1])
            (native_dir / self.runner["result"]).write_bytes(
                canonical_json({"schema": "fixture.result/v1", "outcome": "pass"})
            )
            return 0, False

        with mock.patch("scripts.beta_conformance.execute_command", side_effect=execute) as execute_command:
            result = run_experiment(
                self.plan,
                self.contract,
                "replay",
                self.artifact_root,
                self.result_dir,
            )

        execute_command.assert_called_once()
        self.assertEqual("fail", result["outcome"])
        self.assertEqual("infrastructure_failure", result["classification"])
        self.assertEqual(1, result["retry"]["attempts"])
        diagnostic = result["diagnostics"][0]
        self.assertEqual("pass", diagnostic["native_outcome"])
        self.assertTrue(diagnostic["runner_blocked"])
        self.assertEqual("native_result_unreadable", diagnostic["findings"][0]["type"])

    def test_malformed_identity_is_runner_infrastructure_not_product_failure(self) -> None:
        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            native = self.native_result("pass")
            native["executed_distribution_identities"]["sdk-python"] = {
                "kind": "pypi",
                "locator": "pypi:durable-workflow@1.2.0",
            }
            native_dir = Path(command[-1])
            (native_dir / self.runner["result"]).write_bytes(canonical_json(native))
            return 0, False

        with mock.patch("scripts.beta_conformance.execute_command", side_effect=execute):
            result = run_experiment(
                self.plan,
                self.contract,
                "replay",
                self.artifact_root,
                self.result_dir,
            )

        self.assertEqual("fail", result["outcome"])
        self.assertEqual("infrastructure_failure", result["classification"])
        diagnostic = result["diagnostics"][0]
        self.assertEqual("pass", diagnostic["native_outcome"])
        self.assertTrue(diagnostic["runner_blocked"])
        self.assertEqual("native_result_unreadable", diagnostic["findings"][0]["type"])
        self.assertNotIn("artifact-binding", [item["runner"] for item in result["diagnostics"]])

    def test_malformed_identity_locator_is_runner_infrastructure_not_product_failure(self) -> None:
        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            native = self.native_result("pass")
            native["executed_distribution_identities"]["sdk-python"]["locator"] = "not-a-distribution-locator"
            native_dir = Path(command[-1])
            (native_dir / self.runner["result"]).write_bytes(canonical_json(native))
            return 0, False

        with mock.patch("scripts.beta_conformance.execute_command", side_effect=execute) as execute_command:
            result = run_experiment(
                self.plan,
                self.contract,
                "replay",
                self.artifact_root,
                self.result_dir,
            )

        execute_command.assert_called_once()
        self.assertEqual("fail", result["outcome"])
        self.assertEqual("infrastructure_failure", result["classification"])
        diagnostic = result["diagnostics"][0]
        self.assertEqual("pass", diagnostic["native_outcome"])
        self.assertTrue(diagnostic["runner_blocked"])
        self.assertIn("malformed sdk-python distribution identity locator", diagnostic["stderr_tail"])
        self.assertEqual("native_result_unreadable", diagnostic["findings"][0]["type"])
        self.assertNotIn("artifact-binding", [item["runner"] for item in result["diagnostics"]])

    def test_accepted_native_result_retains_exact_full_identity(self) -> None:
        native_bytes = json.dumps(self.native_result("pass"), indent=2).encode() + b"\n"

        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            native_dir = Path(command[-1])
            (native_dir / self.runner["result"]).write_bytes(native_bytes)
            return 0, False

        with mock.patch("scripts.beta_conformance.execute_command", side_effect=execute):
            result = run_experiment(
                self.plan,
                self.contract,
                "replay",
                self.artifact_root,
                self.result_dir,
            )

        self.assertEqual("passed", result["classification"])
        diagnostic = result["diagnostics"][0]
        self.assertEqual(len(native_bytes), diagnostic["native_result_size_bytes"])
        self.assertEqual(sha256_bytes(native_bytes), diagnostic["native_result_sha256"])
        self.assertIsNone(diagnostic["native_result_prefix_sha256"])

    def test_missing_waterline_service_visibility_is_one_attempt_runner_infrastructure_failure(self) -> None:
        native, runner = self.portable_signals_query_result()
        missing_scenario = "waterline_service_operator_visibility"
        native["scenario_results"].pop(missing_scenario)
        runner_path = self.artifact_root / runner["path"]
        runner_path.parent.mkdir(parents=True, exist_ok=True)
        runner_path.write_text("#!/usr/bin/env bash\n", encoding="utf-8")

        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            native_dir = Path(command[-1])
            (native_dir / runner["result"]).write_bytes(canonical_json(native))
            return 0, False

        with mock.patch("scripts.beta_conformance.execute_command", side_effect=execute) as execute_command:
            result = run_experiment(
                self.plan,
                self.contract,
                "signals-queries",
                self.artifact_root,
                self.result_dir,
            )

        execute_command.assert_called_once()
        self.assertEqual("fail", result["outcome"])
        self.assertEqual("infrastructure_failure", result["classification"])
        self.assertEqual(1, result["retry"]["attempts"])
        diagnostic = result["diagnostics"][0]
        self.assertTrue(diagnostic["runner_blocked"])
        self.assertIn(missing_scenario, diagnostic["stderr_tail"])
        self.assertEqual("native_result_unreadable", diagnostic["findings"][0]["type"])
        validate_experiment_result(result, self.plan, self.contract)

    def test_missing_native_result_is_runner_infrastructure_not_product_failure(self) -> None:
        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            return 0, False

        with mock.patch("scripts.beta_conformance.execute_command", side_effect=execute) as execute_command:
            result = run_experiment(
                self.plan,
                self.contract,
                "replay",
                self.artifact_root,
                self.result_dir,
            )

        execute_command.assert_called_once()
        self.assertEqual("fail", result["outcome"])
        self.assertEqual("infrastructure_failure", result["classification"])
        self.assertEqual(1, result["retry"]["attempts"])
        self.assertTrue(result["diagnostics"][0]["runner_blocked"])
        self.assertEqual("native_result_unreadable", result["diagnostics"][0]["findings"][0]["type"])

    def test_semantic_failure_is_not_retried_by_the_experiment_runner(self) -> None:
        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("HTTP 503 appeared in a product assertion", encoding="utf-8")
            native_dir = Path(command[-1])
            (native_dir / self.runner["result"]).write_bytes(canonical_json(self.native_result("fail")))
            return 1, False

        with mock.patch("scripts.beta_conformance.execute_command", side_effect=execute) as execute_command:
            result = run_experiment(
                self.plan,
                self.contract,
                "replay",
                self.artifact_root,
                self.result_dir,
            )

        self.assertEqual(1, execute_command.call_count)
        self.assertEqual("fail", result["outcome"])
        self.assertEqual("product_failure", result["classification"])
        self.assertEqual(1, result["retry"]["attempts"])
        validate_experiment_result(result, self.plan, self.contract)

    def test_passing_native_result_with_same_version_and_different_digest_stays_red(self) -> None:
        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            native = self.native_result("pass")
            native["executed_distribution_identities"]["sdk-python"]["artifacts"][0]["sha256"] = "f" * 64
            native_dir = Path(command[-1])
            (native_dir / self.runner["result"]).write_bytes(canonical_json(native))
            return 0, False

        with mock.patch("scripts.beta_conformance.execute_command", side_effect=execute) as execute_command:
            result = run_experiment(
                self.plan,
                self.contract,
                "replay",
                self.artifact_root,
                self.result_dir,
            )

        execute_command.assert_called_once()
        self.assertEqual("product_failure", result["classification"])
        binding = result["diagnostics"][-1]
        self.assertEqual("artifact-binding", binding["runner"])
        self.assertEqual("deterministic-replay", binding["findings"][0]["owning_contract"])
        self.assertIn("sdk-python executed distribution artifact", binding["findings"][0]["summary"])

    def test_passing_native_result_with_different_valid_locator_stays_red(self) -> None:
        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            native = self.native_result("pass")
            native["executed_distribution_identities"]["sdk-python"]["locator"] = "pypi:durable-workflow@9.9.9"
            native_dir = Path(command[-1])
            (native_dir / self.runner["result"]).write_bytes(canonical_json(native))
            return 0, False

        with mock.patch("scripts.beta_conformance.execute_command", side_effect=execute) as execute_command:
            result = run_experiment(
                self.plan,
                self.contract,
                "replay",
                self.artifact_root,
                self.result_dir,
            )

        execute_command.assert_called_once()
        self.assertEqual("product_failure", result["classification"])
        binding = result["diagnostics"][-1]
        self.assertEqual("artifact-binding", binding["runner"])
        self.assertEqual(
            "pypi:durable-workflow@9.9.9",
            result["diagnostics"][0]["native_summary"]["executed_distribution_identities"]["sdk-python"]["locator"],
        )
        self.assertIn("different distribution locator", binding["findings"][0]["summary"])

    def test_injected_identity_failure_exercises_binding_and_is_not_retried(self) -> None:
        native_path = self.result_dir / "native" / self.runner["id"] / self.runner["result"]

        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            native_dir = Path(command[-1])
            (native_dir / self.runner["result"]).write_bytes(canonical_json(self.native_result("pass")))
            return 0, False

        def write_distinct_native(path: Path, value: object) -> None:
            if path == native_path:
                path.write_bytes(json.dumps(value, separators=(",", ":")).encode() + b"\n")
            else:
                write_json(path, value)

        with (
            mock.patch("scripts.beta_conformance.execute_command", side_effect=execute) as execute_command,
            mock.patch("scripts.beta_conformance.write_json", side_effect=write_distinct_native),
        ):
            result = run_experiment(
                self.plan,
                self.contract,
                "replay",
                self.artifact_root,
                self.result_dir,
                inject_identity_failure=True,
            )

        execute_command.assert_called_once()
        self.assertEqual("product_failure", result["classification"])
        self.assertEqual(1, result["retry"]["attempts"])
        self.assertFalse(result["retry"]["semantic_failures_retryable"])
        native = result["diagnostics"][0]
        self.assertEqual(
            "injected_distribution_identity_mismatch",
            native["findings"][0]["type"],
        )
        self.assertEqual(
            self.plan["artifact_tuple"]["cli"]["version"],
            native["native_summary"]["artifact_versions"]["cli"],
        )
        literal_native = native_path.read_bytes()
        self.assertEqual(len(literal_native), native["native_result_size_bytes"])
        self.assertEqual(sha256_bytes(literal_native), native["native_result_sha256"])
        binding = result["diagnostics"][-1]
        self.assertEqual("artifact-binding", binding["runner"])
        self.assertIn("does not match the candidate digest", binding["findings"][0]["summary"])


class MultiRunnerExperimentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = CandidateRecordFixture()
        self.contract = load_contract(CONTRACT_PATH)
        self.plan = prepare_plan(
            self.fixture.repository,
            self.fixture.manifest,
            self.contract,
            self.fixture.commit,
            runtime_dependencies(),
        )
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.artifact_root = self.root / "published-server"
        self.result_dir = self.root / "result"
        self.specification = self.contract["experiments"]["heartbeats"]
        for runner in self.specification["runners"]:
            runner_path = self.artifact_root / runner["path"]
            runner_path.parent.mkdir(parents=True, exist_ok=True)
            runner_path.write_text("#!/usr/bin/env bash\n", encoding="utf-8")

    def tearDown(self) -> None:
        self.temporary.cleanup()
        self.fixture.close()

    def execute_shards(
        self,
        mutate: Callable[[str, dict[str, object]], None] | None = None,
    ) -> tuple[list[str], dict[str, Any]]:
        executed: list[str] = []
        runners = {runner["id"]: runner for runner in self.specification["runners"]}

        def execute(command: list[str], **arguments: object) -> tuple[int, bool]:
            stdout_path = arguments["stdout_path"]
            stderr_path = arguments["stderr_path"]
            assert isinstance(stdout_path, Path)
            assert isinstance(stderr_path, Path)
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text("", encoding="utf-8")
            native_dir = Path(command[-1])
            runner_id = native_dir.name
            runner = runners[runner_id]
            native = successful_native_result(self.plan, runner["required_distributions"])
            if callable(mutate):
                mutate(runner_id, native)
            (native_dir / runner["result"]).write_bytes(canonical_json(native))
            executed.append(runner_id)
            return 0, False

        with mock.patch("scripts.beta_conformance.execute_command", side_effect=execute):
            result = run_experiment(
                self.plan,
                self.contract,
                "heartbeats",
                self.artifact_root,
                self.result_dir,
            )
        return executed, result

    def test_polyglot_python_shard_is_complete_without_the_peer_php_identity(self) -> None:
        specification = self.contract["experiments"]["polyglot"]
        runner = specification["runners"][0]
        native = successful_native_result(self.plan, runner["required_distributions"])

        self.assertEqual(
            "",
            native_result_completeness_error(
                native,
                runner["required_distributions"],
                runner,
            ),
        )
        self.assertIn(
            "every required artifact version",
            native_result_completeness_error(
                native,
                specification["required_distributions"],
                runner,
            ),
        )

    def test_declared_runtime_version_is_separate_from_executed_identity_assignment(self) -> None:
        specification = self.contract["experiments"]["polyglot"]
        runner = next(item for item in specification["runners"] if item["id"] == "php-sdk")
        native = successful_native_result(
            self.plan,
            runner["required_distributions"],
            required_artifact_versions=runner_required_artifact_versions(runner),
        )

        self.assertEqual({"sdk-php", "server"}, set(native["artifact_versions"]))
        self.assertEqual({"sdk-php"}, set(native["executed_distribution_identities"]))
        self.assertEqual(
            "",
            native_result_completeness_error(
                native,
                runner["required_distributions"],
                runner,
            ),
        )

        missing_runtime_version = json.loads(canonical_json(native))
        missing_runtime_version["artifact_versions"].pop("server")
        self.assertIn(
            "every required artifact version",
            native_result_completeness_error(
                missing_runtime_version,
                runner["required_distributions"],
                runner,
            ),
        )

        peer_version = json.loads(canonical_json(native))
        peer_version["artifact_versions"]["sdk-python"] = self.plan["artifact_tuple"]["sdk-python"]["version"]
        self.assertIn(
            "outside its required distributions: sdk-python",
            native_result_completeness_error(
                peer_version,
                runner["required_distributions"],
                runner,
            ),
        )

        runtime_identity = json.loads(canonical_json(native))
        runtime_identity["executed_distribution_identities"]["server"] = json.loads(
            canonical_json(self.plan["distribution_identities"]["server"])
        )
        self.assertIn(
            "distribution identities outside its required distributions: server",
            native_result_completeness_error(
                runtime_identity,
                runner["required_distributions"],
                runner,
            ),
        )

    def test_valid_partial_php_python_and_rust_shards_form_a_passing_aggregate(self) -> None:
        executed, result = self.execute_shards()

        self.assertEqual(["php", "python", "rust"], executed)
        self.assertEqual("pass", result["outcome"])
        self.assertEqual("passed", result["classification"])
        self.assertEqual(1, result["retry"]["attempts"])
        self.assertEqual(
            [set(runner["required_distributions"]) for runner in self.specification["runners"]],
            [
                set(diagnostic["native_summary"]["executed_distribution_identities"])
                for diagnostic in result["diagnostics"]
            ],
        )

    def test_exact_peer_only_claim_fails_closed_at_the_reporting_shard(self) -> None:
        def add_python_claim(runner_id: str, native: dict[str, object]) -> None:
            if runner_id == "php":
                versions = native["artifact_versions"]
                identities = native["executed_distribution_identities"]
                artifact_tuple = self.plan["artifact_tuple"]
                distribution_identities = self.plan["distribution_identities"]
                assert isinstance(versions, dict)
                assert isinstance(identities, dict)
                assert isinstance(artifact_tuple, dict)
                assert isinstance(distribution_identities, dict)
                versions["sdk-python"] = artifact_tuple["sdk-python"]["version"]
                identities["sdk-python"] = json.loads(canonical_json(distribution_identities["sdk-python"]))

        executed, result = self.execute_shards(add_python_claim)

        self.assertEqual(["php"], executed)
        self.assertEqual("fail", result["outcome"])
        self.assertEqual("infrastructure_failure", result["classification"])
        self.assertEqual(1, result["retry"]["attempts"])
        self.assertTrue(result["diagnostics"][0]["runner_blocked"])
        self.assertIn(
            "artifact versions outside its required distributions: sdk-python",
            result["diagnostics"][0]["stderr_tail"],
        )
        with self.assertRaisesRegex(ConformanceError, "outside its exact assignment"):
            validate_experiment_result(result, self.plan, self.contract)

    def test_exact_peer_only_identity_is_rejected_without_an_extra_version(self) -> None:
        runner = self.specification["runners"][0]
        native = successful_native_result(self.plan, runner["required_distributions"])
        distribution_identities = self.plan["distribution_identities"]
        assert isinstance(distribution_identities, dict)
        identities = native["executed_distribution_identities"]
        assert isinstance(identities, dict)
        identities["sdk-python"] = json.loads(canonical_json(distribution_identities["sdk-python"]))

        self.assertIn(
            "distribution identities outside its required distributions: sdk-python",
            native_result_completeness_error(
                native,
                runner["required_distributions"],
                runner,
            ),
        )

    def test_missing_consumed_identity_fails_closed_after_one_attempt(self) -> None:
        def remove_php_identity(runner_id: str, native: dict[str, object]) -> None:
            if runner_id == "php":
                identities = native["executed_distribution_identities"]
                assert isinstance(identities, dict)
                identities.pop("sdk-php")

        executed, result = self.execute_shards(remove_php_identity)

        self.assertEqual(["php"], executed)
        self.assertEqual("fail", result["outcome"])
        self.assertEqual("infrastructure_failure", result["classification"])
        self.assertEqual(1, result["retry"]["attempts"])
        self.assertTrue(result["diagnostics"][0]["runner_blocked"])
        self.assertIn("every required distribution identity", result["diagnostics"][0]["stderr_tail"])
        validate_experiment_result(result, self.plan, self.contract)

    def test_mismatched_consumed_identity_runs_all_shards_then_fails_the_aggregate(self) -> None:
        def mismatch_php_identity(runner_id: str, native: dict[str, object]) -> None:
            if runner_id == "php":
                identities = native["executed_distribution_identities"]
                assert isinstance(identities, dict)
                artifacts = identities["sdk-php"]["artifacts"]
                artifacts[0]["sha256"] = "f" * 64

        executed, result = self.execute_shards(mismatch_php_identity)

        self.assertEqual(["php", "python", "rust"], executed)
        self.assertEqual("fail", result["outcome"])
        self.assertEqual("product_failure", result["classification"])
        self.assertEqual(1, result["retry"]["attempts"])
        self.assertEqual("artifact-binding", result["diagnostics"][-1]["runner"])
        self.assertIn("does not match the candidate digest", result["diagnostics"][-1]["stderr_tail"])
        validate_experiment_result(result, self.plan, self.contract)


class EvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = CandidateRecordFixture()
        self.contract = load_contract(CONTRACT_PATH)
        self.plan = prepare_plan(
            self.fixture.repository,
            self.fixture.manifest,
            self.contract,
            self.fixture.commit,
            runtime_dependencies(),
        )

    def tearDown(self) -> None:
        self.fixture.close()

    def test_diagnostic_text_is_bounded(self) -> None:
        value = bounded_text("x" * 9000, 8192)
        self.assertEqual(8192, len(value))
        self.assertTrue(value.endswith("…"))

    def native_identity_results(self) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        specification = self.contract["experiments"]["replay"]
        complete = experiment_result(
            self.plan,
            "replay",
            specification["owning_contract"],
            specification["required_clients"],
            specification["required_distributions"],
            "2026-07-19T00:00:00Z",
            "passed",
            1,
            [successful_diagnostic(self.plan, specification["required_distributions"])],
        )
        unreadable_diagnostic = successful_diagnostic(self.plan, specification["required_distributions"])
        unreadable_diagnostic.update(
            {
                "exit_code": 1,
                "native_outcome": None,
                "runner_blocked": True,
                "native_result_size_bytes": 512,
                "native_result_sha256": None,
                "native_summary": None,
            }
        )
        unreadable = experiment_result(
            self.plan,
            "replay",
            specification["owning_contract"],
            specification["required_clients"],
            specification["required_distributions"],
            "2026-07-19T00:00:00Z",
            "infrastructure_failure",
            1,
            [unreadable_diagnostic],
        )
        oversized_unreadable = json.loads(canonical_json(unreadable))
        oversized_unreadable["diagnostics"][0]["native_result_size_bytes"] = NATIVE_RESULT_LIMIT + 1
        return complete, unreadable, oversized_unreadable

    def test_result_validator_accepts_complete_and_unreadable_native_identity_shapes(self) -> None:
        complete, unreadable, oversized_unreadable = self.native_identity_results()

        validate_experiment_result(complete, self.plan)
        validate_experiment_result(unreadable, self.plan)
        validate_experiment_result(oversized_unreadable, self.plan)

    def test_result_schema_accepts_complete_and_unreadable_native_identity_shapes(self) -> None:
        validator = beta_schema_validator("result-schema.json")
        complete, unreadable, oversized_unreadable = self.native_identity_results()

        validator.validate(complete)
        validator.validate(unreadable)
        validator.validate(oversized_unreadable)

    def test_parsed_native_summary_requires_a_complete_identity(self) -> None:
        validator = beta_schema_validator("result-schema.json")
        complete, unreadable, oversized_unreadable = self.native_identity_results()
        complete["diagnostics"][0]["native_result_sha256"] = None

        with self.assertRaisesRegex(ConformanceError, "parsed native results"):
            validate_experiment_result(complete, self.plan)
        with self.assertRaises(ValidationError):
            validator.validate(complete)

        for invalid_unreadable in (unreadable, oversized_unreadable):
            with self.subTest(size=invalid_unreadable["diagnostics"][0]["native_result_size_bytes"]):
                invalid_unreadable["diagnostics"][0]["runner_blocked"] = False
                with self.assertRaisesRegex(ConformanceError, "unreadable infrastructure evidence"):
                    validate_experiment_result(invalid_unreadable, self.plan)
                with self.assertRaises(ValidationError):
                    validator.validate(invalid_unreadable)

    def test_result_validator_requires_exclusive_native_identity_fields(self) -> None:
        specification = self.contract["experiments"]["replay"]
        result = injected_failure_result(
            self.plan,
            "replay",
            specification["owning_contract"],
            specification["required_clients"],
            specification["required_distributions"],
            "2026-07-19T00:00:00Z",
        )
        del result["diagnostics"][0]["native_result_size_bytes"]
        with self.assertRaisesRegex(ConformanceError, "native result identity shape"):
            validate_experiment_result(result, self.plan)

        result = injected_failure_result(
            self.plan,
            "replay",
            specification["owning_contract"],
            specification["required_clients"],
            specification["required_distributions"],
            "2026-07-19T00:00:00Z",
        )
        diagnostic = result["diagnostics"][0]
        diagnostic["native_result_size_bytes"] = NATIVE_RESULT_LIMIT + 1
        diagnostic["native_result_sha256"] = "a" * 64
        diagnostic["native_result_prefix_sha256"] = "b" * 64
        diagnostic["native_result_prefix_bytes"] = NATIVE_RESULT_PREFIX_LIMIT
        with self.assertRaisesRegex(ConformanceError, "complete native identities"):
            validate_experiment_result(result, self.plan)

    def test_aggregate_binds_each_result_and_preserves_red_product_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for experiment in EXPERIMENTS:
                owner = self.contract["experiments"][experiment]["owning_contract"]
                clients = self.contract["experiments"][experiment]["required_clients"]
                distributions = self.contract["experiments"][experiment]["required_distributions"]
                if experiment == "signals-queries":
                    result = injected_failure_result(
                        self.plan,
                        experiment,
                        owner,
                        clients,
                        distributions,
                        "2026-07-17T00:00:00Z",
                    )
                else:
                    specification = self.contract["experiments"][experiment]
                    result = experiment_result(
                        self.plan,
                        experiment,
                        owner,
                        clients,
                        distributions,
                        "2026-07-17T00:00:00Z",
                        "passed",
                        1,
                        successful_runner_diagnostics(self.plan, specification),
                    )
                path = root / experiment / "experiment-result.json"
                path.parent.mkdir()
                path.write_bytes(canonical_json(result))

            suite, retained = aggregate_results(
                self.plan,
                self.contract,
                root,
                run_id=12345,
                run_attempt=2,
                source_candidate=self.plan["candidate"]["name"],
                source_head_sha=self.plan["runner"]["revision"],
                generated_at="2026-07-20T20:20:06Z",
            )

        self.assertEqual("fail", suite["outcome"])
        self.assertEqual(set(EXPERIMENTS), set(retained))
        self.assertEqual("product_failure", suite["experiments"]["signals-queries"]["classification"])
        self.assertEqual("2026-07-20T20:20:06Z", suite["generated_at"])
        self.assertEqual(
            "beta-conformance/portable-beta-test/12345.2",
            suite["github_run"]["evidence_tag"],
        )

    def test_aggregate_records_a_missing_matrix_result_as_infrastructure_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            suite, retained = aggregate_results(
                self.plan,
                self.contract,
                Path(temporary),
                run_id=12345,
                run_attempt=1,
                source_candidate=self.plan["candidate"]["name"],
                source_head_sha=self.plan["runner"]["revision"],
            )
        self.assertEqual({}, retained)
        self.assertEqual("fail", suite["outcome"])
        for experiment in EXPERIMENTS:
            self.assertEqual("infrastructure_failure", suite["experiments"][experiment]["classification"])
            self.assertRegex(suite["experiments"][experiment]["failure_fingerprint"], r"^[0-9a-f]{64}$")

    def test_aggregate_rejects_a_plan_from_another_source_run(self) -> None:
        cases = {
            "candidate": {
                "source_candidate": "another-candidate",
                "source_head_sha": self.plan["runner"]["revision"],
            },
            "commit": {
                "source_candidate": self.plan["candidate"]["name"],
                "source_head_sha": "f" * 40,
            },
        }
        for name, source in cases.items():
            with (
                self.subTest(name=name),
                tempfile.TemporaryDirectory() as temporary,
                self.assertRaisesRegex(
                    ConformanceError,
                    "execution plan does not bind the source workflow",
                ),
            ):
                aggregate_results(
                    self.plan,
                    self.contract,
                    Path(temporary),
                    run_id=12345,
                    run_attempt=1,
                    **source,
                )

    def test_green_suite_retains_executed_identities_for_all_required_distributions(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for experiment in EXPERIMENTS:
                specification = self.contract["experiments"][experiment]
                result = experiment_result(
                    self.plan,
                    experiment,
                    specification["owning_contract"],
                    specification["required_clients"],
                    specification["required_distributions"],
                    "2026-07-17T00:00:00Z",
                    "passed",
                    1,
                    successful_runner_diagnostics(self.plan, specification),
                )
                path = root / experiment / "experiment-result.json"
                path.parent.mkdir()
                path.write_bytes(canonical_json(result))

            suite, _ = aggregate_results(
                self.plan,
                self.contract,
                root,
                run_id=12345,
                run_attempt=1,
                source_candidate=self.plan["candidate"]["name"],
                source_head_sha=self.plan["runner"]["revision"],
            )

        self.assertEqual("pass", suite["outcome"])
        self.assertEqual(set(DISTRIBUTIONS), set(suite["executed_distribution_identities"]))
        self.assertEqual(self.plan["runtime_dependencies"], suite["runtime_dependencies"])
        beta_schema_validator("suite-result-schema.json").validate(suite)

    def test_aggregate_rejects_a_passing_result_missing_a_declared_runner(self) -> None:
        specification = self.contract["experiments"]["polyglot"]
        result = experiment_result(
            self.plan,
            "polyglot",
            specification["owning_contract"],
            specification["required_clients"],
            specification["required_distributions"],
            "2026-07-17T00:00:00Z",
            "passed",
            1,
            successful_runner_diagnostics(self.plan, specification),
        )
        result["diagnostics"].pop()

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "polyglot" / "experiment-result.json"
            path.parent.mkdir()
            path.write_bytes(canonical_json(result))
            with self.assertRaisesRegex(ConformanceError, "every declared runner"):
                aggregate_results(
                    self.plan,
                    self.contract,
                    Path(temporary),
                    run_id=12345,
                    run_attempt=1,
                    source_candidate=self.plan["candidate"]["name"],
                    source_head_sha=self.plan["runner"]["revision"],
                )

    def test_retained_runtime_version_is_bound_without_a_runtime_execution_identity(self) -> None:
        specification = self.contract["experiments"]["polyglot"]
        result = experiment_result(
            self.plan,
            "polyglot",
            specification["owning_contract"],
            specification["required_clients"],
            specification["required_distributions"],
            "2026-07-17T00:00:00Z",
            "passed",
            1,
            successful_runner_diagnostics(self.plan, specification),
        )
        php_summary = next(
            diagnostic["native_summary"] for diagnostic in result["diagnostics"] if diagnostic["runner"] == "php-sdk"
        )

        self.assertEqual({"sdk-php", "server"}, set(php_summary["artifact_versions"]))
        self.assertEqual({"sdk-php"}, set(php_summary["executed_distribution_identities"]))
        validate_experiment_result(result, self.plan, self.contract)

        missing_runtime_version = json.loads(canonical_json(result))
        next(
            diagnostic["native_summary"]
            for diagnostic in missing_runtime_version["diagnostics"]
            if diagnostic["runner"] == "php-sdk"
        )["artifact_versions"].pop("server")
        with self.assertRaisesRegex(ConformanceError, "exact distribution assignment"):
            validate_experiment_result(missing_runtime_version, self.plan, self.contract)

        mismatched_runtime_version = json.loads(canonical_json(result))
        next(
            diagnostic["native_summary"]
            for diagnostic in mismatched_runtime_version["diagnostics"]
            if diagnostic["runner"] == "php-sdk"
        )["artifact_versions"]["server"] = "0.0.0-wrong"
        with self.assertRaisesRegex(ConformanceError, "mismatched native artifact evidence"):
            validate_experiment_result(mismatched_runtime_version, self.plan, self.contract)

        runtime_identity = json.loads(canonical_json(result))
        next(
            diagnostic["native_summary"]
            for diagnostic in runtime_identity["diagnostics"]
            if diagnostic["runner"] == "php-sdk"
        )["executed_distribution_identities"]["server"] = json.loads(
            canonical_json(self.plan["distribution_identities"]["server"])
        )
        with self.assertRaisesRegex(ConformanceError, "identities outside its exact assignment"):
            validate_experiment_result(runtime_identity, self.plan, self.contract)

        peer_version = json.loads(canonical_json(result))
        next(
            diagnostic["native_summary"]
            for diagnostic in peer_version["diagnostics"]
            if diagnostic["runner"] == "php-sdk"
        )["artifact_versions"]["sdk-python"] = self.plan["artifact_tuple"]["sdk-python"]["version"]
        with self.assertRaisesRegex(ConformanceError, "versions outside its exact assignment"):
            validate_experiment_result(peer_version, self.plan, self.contract)

    def test_aggregate_rejects_an_exact_peer_only_runner_claim(self) -> None:
        specification = self.contract["experiments"]["heartbeats"]
        result = experiment_result(
            self.plan,
            "heartbeats",
            specification["owning_contract"],
            specification["required_clients"],
            specification["required_distributions"],
            "2026-07-17T00:00:00Z",
            "passed",
            1,
            successful_runner_diagnostics(self.plan, specification),
        )
        php_summary = result["diagnostics"][0]["native_summary"]
        php_summary["artifact_versions"]["sdk-python"] = self.plan["artifact_tuple"]["sdk-python"]["version"]
        php_summary["executed_distribution_identities"]["sdk-python"] = json.loads(
            canonical_json(self.plan["distribution_identities"]["sdk-python"])
        )

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "heartbeats" / "experiment-result.json"
            path.parent.mkdir()
            path.write_bytes(canonical_json(result))
            with self.assertRaisesRegex(ConformanceError, "outside its exact assignment"):
                aggregate_results(
                    self.plan,
                    self.contract,
                    Path(temporary),
                    run_id=12345,
                    run_attempt=1,
                    source_candidate=self.plan["candidate"]["name"],
                    source_head_sha=self.plan["runner"]["revision"],
                )

    def test_aggregate_rejects_a_peer_only_identity_without_an_extra_version(self) -> None:
        specification = self.contract["experiments"]["heartbeats"]
        result = experiment_result(
            self.plan,
            "heartbeats",
            specification["owning_contract"],
            specification["required_clients"],
            specification["required_distributions"],
            "2026-07-17T00:00:00Z",
            "passed",
            1,
            successful_runner_diagnostics(self.plan, specification),
        )
        php_summary = result["diagnostics"][0]["native_summary"]
        php_summary["executed_distribution_identities"]["sdk-python"] = json.loads(
            canonical_json(self.plan["distribution_identities"]["sdk-python"])
        )

        with self.assertRaisesRegex(ConformanceError, "identities outside its exact assignment"):
            validate_experiment_result(result, self.plan, self.contract)

    def test_aggregate_rejects_a_duplicate_runner_terminal(self) -> None:
        specification = self.contract["experiments"]["heartbeats"]
        result = experiment_result(
            self.plan,
            "heartbeats",
            specification["owning_contract"],
            specification["required_clients"],
            specification["required_distributions"],
            "2026-07-17T00:00:00Z",
            "passed",
            1,
            successful_runner_diagnostics(self.plan, specification),
        )
        result["diagnostics"].insert(
            1,
            json.loads(canonical_json(result["diagnostics"][0])),
        )

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "heartbeats" / "experiment-result.json"
            path.parent.mkdir()
            path.write_bytes(canonical_json(result))
            with self.assertRaisesRegex(ConformanceError, "duplicate passing terminal"):
                aggregate_results(
                    self.plan,
                    self.contract,
                    Path(temporary),
                    run_id=12345,
                    run_attempt=1,
                    source_candidate=self.plan["candidate"]["name"],
                    source_head_sha=self.plan["runner"]["revision"],
                )

    def test_aggregate_rejects_an_unknown_runner(self) -> None:
        specification = self.contract["experiments"]["heartbeats"]
        result = experiment_result(
            self.plan,
            "heartbeats",
            specification["owning_contract"],
            specification["required_clients"],
            specification["required_distributions"],
            "2026-07-17T00:00:00Z",
            "passed",
            1,
            successful_runner_diagnostics(self.plan, specification),
        )
        result["diagnostics"][1]["runner"] = "undeclared-python"

        with self.assertRaisesRegex(ConformanceError, "unknown runner"):
            validate_experiment_result(result, self.plan, self.contract)

    def test_contract_validator_requires_every_declared_scenario_cell(self) -> None:
        specification = self.contract["experiments"]["signals-queries"]
        result = experiment_result(
            self.plan,
            "signals-queries",
            specification["owning_contract"],
            specification["required_clients"],
            specification["required_distributions"],
            "2026-07-17T00:00:00Z",
            "passed",
            1,
            successful_runner_diagnostics(self.plan, specification),
        )
        result["diagnostics"][0]["native_summary"]["scenario_statuses"].pop()

        with self.assertRaisesRegex(ConformanceError, "declared scenario cells"):
            validate_experiment_result(result, self.plan, self.contract)

    def test_aggregate_rejects_incomplete_product_failure_runner_summaries(self) -> None:
        specification = self.contract["experiments"]["signals-queries"]
        diagnostic = successful_runner_diagnostics(self.plan, specification)[0]
        diagnostic.update({"exit_code": 1, "native_outcome": "fail"})
        retained = experiment_result(
            self.plan,
            "signals-queries",
            specification["owning_contract"],
            specification["required_clients"],
            specification["required_distributions"],
            "2026-07-17T00:00:00Z",
            "product_failure",
            1,
            [diagnostic],
        )
        adversarial_summaries = (
            (
                "missing-assignment-with-wrong-schema-and-no-scenarios",
                {
                    "artifact_versions": {},
                    "executed_distribution_identities": {},
                    "schema": "adversarial.result/v1",
                    "scenario_statuses": [],
                },
                "exact distribution assignment",
            ),
            ("wrong-schema", {"schema": "adversarial.result/v1"}, "declared schema"),
            ("missing-scenario-cells", {"scenario_statuses": []}, "declared scenario cells"),
        )

        for label, summary_changes, expected_error in adversarial_summaries:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as temporary:
                result = json.loads(canonical_json(retained))
                result["diagnostics"][0]["native_summary"].update(summary_changes)
                path = Path(temporary) / "signals-queries" / "experiment-result.json"
                path.parent.mkdir()
                path.write_bytes(canonical_json(result))

                with self.assertRaisesRegex(ConformanceError, expected_error):
                    aggregate_results(
                        self.plan,
                        self.contract,
                        Path(temporary),
                        run_id=12345,
                        run_attempt=1,
                        source_candidate=self.plan["candidate"]["name"],
                        source_head_sha=self.plan["runner"]["revision"],
                    )

    def test_contract_validator_accepts_a_transient_then_pass_runner_lifecycle(self) -> None:
        specification = self.contract["experiments"]["heartbeats"]
        result = experiment_result(
            self.plan,
            "heartbeats",
            specification["owning_contract"],
            specification["required_clients"],
            specification["required_distributions"],
            "2026-07-17T00:00:00Z",
            "passed",
            1,
            successful_runner_diagnostics(self.plan, specification),
        )
        transient = json.loads(canonical_json(result["diagnostics"][0]))
        transient.update(
            {
                "exit_code": 75,
                "native_outcome": None,
                "runner_blocked": True,
                "stderr_tail": "package download returned 503",
                "stderr_sha256": sha256_bytes(b"package download returned 503"),
                "native_result_size_bytes": None,
                "native_result_sha256": None,
                "native_summary": None,
            }
        )
        result["diagnostics"][0]["attempt"] = 2
        result["diagnostics"].insert(0, transient)
        result["retry"]["attempts"] = 2

        validate_experiment_result(result, self.plan, self.contract)

    def test_result_validator_rejects_a_different_source_tuple(self) -> None:
        result = experiment_result(
            self.plan,
            "replay",
            "deterministic-replay",
            self.contract["experiments"]["replay"]["required_clients"],
            self.contract["experiments"]["replay"]["required_distributions"],
            "2026-07-17T00:00:00Z",
            "passed",
            1,
            [successful_diagnostic(self.plan)],
        )
        result["source_identities"] = dict(result["source_identities"])
        result["source_identities"]["sdk-rust"] = "f" * 40
        with self.assertRaisesRegex(RuntimeError, "mismatched source_identities binding"):
            validate_experiment_result(result, self.plan)


if __name__ == "__main__":
    unittest.main()
