from __future__ import annotations

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.beta_candidate import CLI_ASSETS, COMPONENTS, SCHEMA, VERIFICATION_SCHEMA, canonical_json, manifest_digest
from scripts.beta_conformance import (
    EXPERIMENTS,
    MAX_INFRASTRUCTURE_ATTEMPTS,
    aggregate_results,
    artifact_binding_failures,
    bounded_text,
    classify_attempt,
    experiment_result,
    inject_distribution_identity_mismatch,
    injected_failure_result,
    load_contract,
    prepare_plan,
    run_experiment,
    sha256_bytes,
    validate_experiment_result,
    validate_plan,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "beta-conformance" / "contract.json"


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
        "native_result_sha256": "b" * 64,
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

    def test_every_schema_is_parseable_draft_2020_12(self) -> None:
        for path in sorted((ROOT / "beta-conformance").glob("*schema.json")):
            schema = json.loads(path.read_bytes())
            self.assertEqual("https://json-schema.org/draft/2020-12/schema", schema["$schema"])


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


class FailureClassificationTest(unittest.TestCase):
    def test_semantic_failure_is_never_retried_even_when_log_mentions_503(self) -> None:
        classification, retryable = classify_attempt(
            returncode=1,
            timed_out=False,
            native_outcome="fail",
            runner_blocked=False,
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
            diagnostic_text="",
        )
        self.assertEqual("product_failure", classification)
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
            diagnostic["native_summary"]["executed_distribution_identities"]["sdk-python"]["artifacts"][0][
                "sha256"
            ] = "f" * 64
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
                "executed_distribution_identities": diagnostic["native_summary"][
                    "executed_distribution_identities"
                ]
            }
            component, artifact_name = inject_distribution_identity_mismatch(
                native, plan, ["sdk-python"]
            )
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

    def test_injected_identity_failure_exercises_binding_and_is_not_retried(self) -> None:
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

        with mock.patch("scripts.beta_conformance.execute_command", side_effect=execute) as execute_command:
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
