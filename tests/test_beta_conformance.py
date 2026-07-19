from __future__ import annotations

import contextlib
import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError
from referencing import Registry, Resource

from scripts.beta_candidate import CLI_ASSETS, COMPONENTS, SCHEMA, VERIFICATION_SCHEMA, canonical_json, manifest_digest
from scripts.beta_conformance import (
    EXPERIMENTS,
    MAX_INFRASTRUCTURE_ATTEMPTS,
    NATIVE_RESULT_LIMIT,
    NATIVE_RESULT_PREFIX_LIMIT,
    ConformanceError,
    aggregate_results,
    artifact_binding_failures,
    bounded_text,
    classify_attempt,
    experiment_result,
    inject_distribution_identity_mismatch,
    injected_failure_result,
    load_contract,
    native_result_completeness_error,
    prepare_plan,
    run_experiment,
    runner_runtime_environment,
    sha256_bytes,
    sha256_file,
    validate_experiment_result,
    validate_plan,
    write_json,
)

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
    components = candidate["components"]
    assert isinstance(components, dict)
    results = {}
    for name, identity in components.items():
        assert isinstance(identity, dict)
        digest = f"{list(COMPONENTS).index(name) + 1:064x}"
        component = COMPONENTS[name]
        if component.distribution == "composer":
            distribution = {
                "kind": "composer",
                "dist": {"sha256": digest},
            }
        elif component.distribution == "github-release":
            distribution = {
                "kind": "github-release",
                "assets": [
                    {"name": asset_name, "sha256": f"{index + 20:064x}"}
                    for index, asset_name in enumerate(sorted(CLI_ASSETS))
                ],
            }
        elif component.distribution == "pypi":
            distribution = {
                "kind": "pypi",
                "files": [
                    {"filename": "durable_workflow.whl", "sha256": digest},
                    {"filename": "durable_workflow.tar.gz", "sha256": f"{100:064x}"},
                ],
            }
        elif component.distribution == "crates.io":
            distribution = {
                "kind": "crates.io",
                "archive": {"sha256": digest},
            }
        elif component.distribution == "oci":
            distribution = {
                "kind": "oci",
                "image": f"docker.io/durableworkflow/server:{identity['version']}",
                "manifest_digest": f"sha256:{'a' * 64}",
            }
        else:
            raise AssertionError(component.distribution)
        results[name] = {
            "version": identity["version"],
            "commit": identity["commit"],
            "source": {},
            "distribution": distribution,
            "outcome": "verified",
        }
    return {
        "schema": VERIFICATION_SCHEMA,
        "candidate": candidate["candidate"],
        "manifest_sha256": manifest_digest(candidate),
        "verified_at": "2026-07-17T00:00:00Z",
        "outcome": "verified",
        "components": results,
    }


def successful_diagnostic(
    plan: dict[str, object], required_distributions: list[str] | None = None
) -> dict[str, object]:
    selected = required_distributions or list(COMPONENTS)
    artifact_tuple = plan["artifact_tuple"]
    distribution_identities = plan["distribution_identities"]
    assert isinstance(artifact_tuple, dict)
    assert isinstance(distribution_identities, dict)
    empty_digest = sha256_bytes(b"")
    return {
        "runner": "fixture",
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
            "schema": "fixture.result/v1",
            "artifact_versions": {name: artifact_tuple[name]["version"] for name in selected},
            "executed_distribution_identities": {
                name: json.loads(canonical_json(distribution_identities[name])) for name in selected
            },
            "scenario_statuses": [{"id": "fixture", "status": "pass"}],
            "local_product_source_checkout_used": False,
        },
        "findings": [],
    }


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
        self.assertEqual(
            {"sdk-php", "sdk-python", "sdk-rust"},
            {
                client
                for specification in contract["experiments"].values()
                for client in specification["required_clients"]
            },
        )
        self.assertEqual(
            set(COMPONENTS),
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

        php_runner = next(
            runner for runner in contract["experiments"]["polyglot"]["runners"] if runner["id"] == "php-sdk"
        )
        self.assertEqual(
            {
                "kind": "standalone-server",
                "namespace_environment": "DW_PHP_SDK_CONFORMANCE_NAMESPACE",
                "server_url_environment": "DW_PHP_SDK_CONFORMANCE_SERVER_URL",
                "token_environment": "DW_PHP_SDK_CONFORMANCE_TOKEN",
            },
            php_runner["runtime"],
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
        self.assertEqual(18, len(signals_runner["required_scenarios"]))
        self.assertIn("published_artifact_install_only", signals_runner["required_scenarios"])
        self.assertIn("waterline_operator_visibility", signals_runner["required_scenarios"])

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
        )
        validate_plan(plan)
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
            sha256_bytes(canonical_json(candidate_verification(self.fixture.manifest))),
            plan["candidate"]["verification_sha256"],
        )
        self.assertEqual(set(COMPONENTS), set(plan["distribution_identities"]))

    def test_plan_rejects_tuple_mutation_after_immutable_record(self) -> None:
        changed = json.loads(canonical_json(self.fixture.manifest))
        changed["components"]["sdk-python"]["version"] = "9.9.9"
        with self.assertRaisesRegex(RuntimeError, "does not contain the requested immutable tuple"):
            prepare_plan(self.fixture.repository, changed, self.contract, self.fixture.commit)


class StandaloneServerRuntimeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = CandidateRecordFixture()
        self.contract = load_contract(CONTRACT_PATH)
        self.plan = prepare_plan(
            self.fixture.repository,
            self.fixture.manifest,
            self.contract,
            self.fixture.commit,
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
                stdout = "true\n"
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
        self.assertEqual(4, len(run_commands))
        self.assertTrue(all(self.plan["server_runner"]["image"] in command for command in run_commands))
        self.assertTrue(any("127.0.0.1::8080" in command for command in run_commands))
        self.assertTrue(any(command[-1] == "server-bootstrap" for command in run_commands))
        self.assertTrue(any("queue:work" in command for command in run_commands))
        self.assertTrue(any("schedule:evaluate" in command[-1] for command in run_commands))
        self.assertEqual(4, len([command for command in commands if command[1:3] == ["rm", "--force"]]))
        self.assertEqual(1, len([command for command in commands if command[1:4] == ["volume", "rm", "--force"]]))


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
            plan = prepare_plan(fixture.repository, fixture.manifest, contract, fixture.commit)
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
            plan = prepare_plan(fixture.repository, fixture.manifest, contract, fixture.commit)
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
            plan = prepare_plan(fixture.repository, fixture.manifest, contract, fixture.commit)
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
            plan = prepare_plan(fixture.repository, fixture.manifest, contract, fixture.commit)
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
            plan = prepare_plan(fixture.repository, fixture.manifest, contract, fixture.commit)
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
                    scenario: {"scenario_id": scenario, "status": "pass"}
                    for scenario in runner["required_scenarios"]
                },
                "finding_links": {},
            }
        )
        return native, runner

    def test_every_declared_portable_field_is_required(self) -> None:
        native, runner = self.portable_signals_query_result()
        required_distributions = self.contract["experiments"]["signals-queries"]["required_distributions"]
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
        required_distributions = self.contract["experiments"]["signals-queries"]["required_distributions"]
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
        required_distributions = self.contract["experiments"]["signals-queries"]["required_distributions"]
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
            "kind": "standalone-server",
            "namespace_environment": "DW_PHP_SDK_CONFORMANCE_NAMESPACE",
            "server_url_environment": "DW_PHP_SDK_CONFORMANCE_SERVER_URL",
            "token_environment": "DW_PHP_SDK_CONFORMANCE_TOKEN",
        }
        self.plan = prepare_plan(
            self.fixture.repository,
            self.fixture.manifest,
            self.contract,
            self.fixture.commit,
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
            "kind": "standalone-server",
            "namespace_environment": "DW_PHP_SDK_CONFORMANCE_NAMESPACE",
            "server_url_environment": "DW_PHP_SDK_CONFORMANCE_SERVER_URL",
            "token_environment": "DW_PHP_SDK_CONFORMANCE_TOKEN",
        }
        self.plan = prepare_plan(
            self.fixture.repository,
            self.fixture.manifest,
            self.contract,
            self.fixture.commit,
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
            native["executed_distribution_identities"]["sdk-python"]["locator"] = (
                "not-a-distribution-locator"
            )
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

    def test_missing_required_scenario_is_one_attempt_runner_infrastructure_failure(self) -> None:
        native, runner = self.portable_signals_query_result()
        missing_scenario = runner["required_scenarios"][0]
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
            native["executed_distribution_identities"]["sdk-python"]["locator"] = (
                "pypi:durable-workflow@9.9.9"
            )
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
            result["diagnostics"][0]["native_summary"]["executed_distribution_identities"]["sdk-python"][
                "locator"
            ],
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


class EvidenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = CandidateRecordFixture()
        self.contract = load_contract(CONTRACT_PATH)
        self.plan = prepare_plan(
            self.fixture.repository,
            self.fixture.manifest,
            self.contract,
            self.fixture.commit,
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
                    result = experiment_result(
                        self.plan,
                        experiment,
                        owner,
                        clients,
                        distributions,
                        "2026-07-17T00:00:00Z",
                        "passed",
                        1,
                        [successful_diagnostic(self.plan, distributions)],
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
            )

        self.assertEqual("fail", suite["outcome"])
        self.assertEqual(set(EXPERIMENTS), set(retained))
        self.assertEqual("product_failure", suite["experiments"]["signals-queries"]["classification"])
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
            )
        self.assertEqual({}, retained)
        self.assertEqual("fail", suite["outcome"])
        for experiment in EXPERIMENTS:
            self.assertEqual("infrastructure_failure", suite["experiments"][experiment]["classification"])
            self.assertRegex(suite["experiments"][experiment]["failure_fingerprint"], r"^[0-9a-f]{64}$")

    def test_green_suite_retains_executed_identities_for_all_seven_distributions(self) -> None:
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
                    [successful_diagnostic(self.plan, specification["required_distributions"])],
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
            )

        self.assertEqual("pass", suite["outcome"])
        self.assertEqual(set(COMPONENTS), set(suite["executed_distribution_identities"]))

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
