from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock

from jsonschema import Draft202012Validator

from scripts import release_recovery_consumer_conformance as conformance

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "release-recovery" / "consumer-conformance" / "contract.json"
CONTRACT_SCHEMA_PATH = ROOT / "release-recovery" / "consumer-conformance" / "contract-schema.json"
SUITE_PATH = ROOT / "scripts" / "release_recovery_consumer_conformance.py"


class ReleaseRecoveryConsumerConformanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract_raw = CONTRACT_PATH.read_bytes()
        cls.contract = json.loads(cls.contract_raw)
        cls.contract_schema = json.loads(CONTRACT_SCHEMA_PATH.read_bytes())

    def test_contract_binds_the_exact_suite_and_required_target_set(self) -> None:
        digest = conformance.validate_contract(
            self.contract,
            self.contract_raw,
            SUITE_PATH,
        )

        self.assertEqual(conformance.sha256_bytes(self.contract_raw), digest)
        self.assertEqual(
            list(conformance.REQUIRED_CASES),
            [case["id"] for case in self.contract["cases"]],
        )
        self.assertEqual(list(conformance.CONSUMERS), self.contract["consumers"])

    def changed_contract(self, previous_version: str, current_version: str) -> tuple[dict, dict]:
        previous = copy.deepcopy(self.contract)
        previous["version"] = previous_version
        current = copy.deepcopy(previous)
        current["cases"][0]["requirement"] += " Changed."
        current["version"] = current_version
        return previous, current

    def test_changed_contract_requires_strictly_greater_semver_precedence(self) -> None:
        accepted = (
            ("1.2.0", "1.2.1"),
            ("1.2.0", "1.3.0"),
            ("1.2.0", "2.0.0"),
            ("1.3.0-rc.1", "1.3.0-rc.2"),
            ("1.3.0-rc.2", "1.3.0"),
        )
        for previous_version, current_version in accepted:
            with self.subTest(previous=previous_version, current=current_version):
                previous, current = self.changed_contract(previous_version, current_version)
                conformance.require_versioned_contract_change(previous, current)

        rejected = (
            ("1.2.0", "1.2.0"),
            ("2.0.0", "1.9.9"),
            ("1.3.0", "1.3.0+rebuilt"),
            ("1.3.0+first", "1.3.0+second"),
            ("1.3.0-rc.2", "1.3.0-rc.1"),
        )
        for previous_version, current_version in rejected:
            with (
                self.subTest(previous=previous_version, current=current_version),
                self.assertRaisesRegex(conformance.ConformanceError, "strictly advancing"),
            ):
                previous, current = self.changed_contract(previous_version, current_version)
                conformance.require_versioned_contract_change(previous, current)

    def test_suite_digest_change_requires_strictly_advancing_version(self) -> None:
        current = copy.deepcopy(self.contract)
        current["version"] = "1.4.2"
        previous = copy.deepcopy(current)
        previous["suite"]["sha256"] = "0" * 64

        with self.assertRaisesRegex(conformance.ConformanceError, "strictly advancing"):
            conformance.require_versioned_contract_change(previous, current)

        current["version"] = "1.5.0"
        conformance.require_versioned_contract_change(previous, current)

    def test_contract_version_uses_exact_semver(self) -> None:
        validator = Draft202012Validator(self.contract_schema)
        valid = ("0.0.0", "1.0.0-rc.1", "1.0.0-0A.0", "1.0.0+build.01")
        for version in valid:
            with self.subTest(version=version):
                contract = copy.deepcopy(self.contract)
                contract["version"] = version
                validator.validate(contract)
                conformance.validate_contract(
                    contract,
                    conformance.canonical_json(contract),
                    SUITE_PATH,
                )

        malformed = ("1.0.0-rc.01", "1.0.0-01", "01.0.0", "1.0.0-alpha..1")
        for version in malformed:
            with (
                self.subTest(version=version),
                self.assertRaisesRegex(conformance.ConformanceError, "exact SemVer"),
            ):
                contract = copy.deepcopy(self.contract)
                contract["version"] = version
                self.assertTrue(list(validator.iter_errors(contract)))
                conformance.validate_contract(
                    contract,
                    conformance.canonical_json(contract),
                    SUITE_PATH,
                )

    def adapter_fixture(
        self,
        root: Path,
    ) -> tuple[dict, dict, str, Path, Path]:
        suite_path = root / "scripts" / "ci" / "release_recovery_consumer_conformance.py"
        contract_path = root / "scripts" / "ci" / "release-recovery-consumer-contract.json"
        consumer_path = root / "scripts" / "ci" / "component-release-recovery.py"
        verifier_path = root / "scripts" / "ci" / "test-component-release-recovery.py"
        suite_path.parent.mkdir(parents=True)
        suite_path.write_bytes(SUITE_PATH.read_bytes())
        contract = copy.deepcopy(self.contract)
        contract_raw = conformance.canonical_json(contract)
        contract_path.write_bytes(contract_raw)
        consumer_path.write_text("# consumer fixture\n")
        verifier_path.write_text("# verifier fixture\n")
        adapter = {
            "component": "workflow",
            "consumer": consumer_path.relative_to(root).as_posix(),
            "contract": {
                "path": contract_path.relative_to(root).as_posix(),
                "sha256": conformance.sha256_bytes(contract_raw),
                "version": contract["version"],
            },
            "distribution_verification": {"command": ["{python}", verifier_path.relative_to(root).as_posix()]},
            "repository": "durable-workflow/workflow",
            "schema": conformance.ADAPTER_SCHEMA,
            "suite": {
                "path": suite_path.relative_to(root).as_posix(),
                "sha256": contract["suite"]["sha256"],
            },
            "target_branch": "v2",
        }
        return adapter, contract, conformance.sha256_bytes(contract_raw), suite_path, contract_path

    def validate_adapter_fixture(
        self,
        adapter: dict,
        contract: dict,
        contract_sha256: str,
        root: Path,
        suite_path: Path,
        contract_path: Path,
    ) -> tuple[Path, list[str]]:
        return conformance.validate_adapter(
            adapter,
            contract,
            contract_sha256,
            root,
            suite_path,
            contract_path,
        )

    def test_adapter_declared_and_invoked_contract_identity_matches(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter, contract, digest, suite_path, contract_path = self.adapter_fixture(root)

            consumer, command = self.validate_adapter_fixture(
                adapter,
                contract,
                digest,
                root,
                suite_path,
                contract_path,
            )

        self.assertEqual("component-release-recovery.py", consumer.name)
        self.assertEqual(["{python}", "scripts/ci/test-component-release-recovery.py"], command)

    def test_alternate_invoked_contract_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter, contract, digest, suite_path, contract_path = self.adapter_fixture(root)
            alternate_path = contract_path.with_name("alternate-contract.json")
            alternate_path.write_bytes(contract_path.read_bytes())

            with self.assertRaisesRegex(
                conformance.ConformanceError,
                "invoked contract is not the adapter's declared contract",
            ):
                self.validate_adapter_fixture(
                    adapter,
                    contract,
                    digest,
                    root,
                    suite_path,
                    alternate_path,
                )

    def test_stale_declared_contract_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter, contract, _, suite_path, contract_path = self.adapter_fixture(root)
            stale_contract = copy.deepcopy(contract)
            stale_contract["version"] = "1.4.0"
            stale_raw = conformance.canonical_json(stale_contract)
            contract_path.write_bytes(stale_raw)

            with self.assertRaisesRegex(
                conformance.ConformanceError,
                "declared contract does not match its version and digest pins",
            ):
                self.validate_adapter_fixture(
                    adapter,
                    stale_contract,
                    conformance.sha256_bytes(stale_raw),
                    root,
                    suite_path,
                    contract_path,
                )

    def test_mismatched_declared_contract_bytes_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            adapter, contract, digest, suite_path, contract_path = self.adapter_fixture(root)
            mismatched = copy.deepcopy(contract)
            mismatched["cases"][0]["requirement"] += " (mismatched declared bytes)"
            contract_path.write_bytes(conformance.canonical_json(mismatched))

            with self.assertRaisesRegex(
                conformance.ConformanceError,
                "declared contract does not match its version and digest pins",
            ):
                self.validate_adapter_fixture(
                    adapter,
                    contract,
                    digest,
                    root,
                    suite_path,
                    contract_path,
                )

    def test_previous_contract_distinguishes_first_adoption_from_unavailable_commit(self) -> None:
        contract_path = ROOT / "scripts" / "ci" / "release-recovery-consumer-contract.json"
        commit = "a" * 40
        commit_exists = mock.Mock(returncode=0, stdout=b"")
        contract_absent = mock.Mock(returncode=0, stdout=b"")
        with mock.patch.object(
            conformance.subprocess,
            "run",
            side_effect=(commit_exists, contract_absent),
        ):
            self.assertIsNone(conformance.previous_contract(ROOT, contract_path, commit))

        commit_unavailable = mock.Mock(returncode=128, stdout=b"")
        with (
            mock.patch.object(conformance.subprocess, "run", return_value=commit_unavailable),
            self.assertRaisesRegex(conformance.ConformanceError, "commit is unavailable"),
        ):
            conformance.previous_contract(ROOT, contract_path, commit)

    def test_blanket_two_successor_rejection_fails_the_shared_continuity_case(self) -> None:
        mutant = ModuleType("blanket_continuity_rejection")

        class RecoveryError(RuntimeError):
            pass

        mutant.RecoveryError = RecoveryError
        mutant.CONTROL_REPOSITORY = "durable-workflow/.github"
        mutant.CONTINUITY_RESOLUTION_SCHEMA = "durable-workflow.release-plan-continuity-resolution/v2"
        mutant.CONTINUITY_RESOLUTION_TAG_PREFIX = "release-plan-continuity-resolution/"
        mutant.CONTINUITY_RESOLUTION_QUALIFICATION_WORKFLOW = ".github/workflows/beta-candidate.yml"
        mutant.CONTINUITY_RESOLUTION_QUALIFICATION_EVENT = "push"
        mutant.CONTINUITY_RESOLUTION_QUALIFICATION_BRANCH = "main"
        mutant.manifest_digest = lambda value: conformance.sha256_bytes(conformance.canonical_json(value))
        mutant.list_continuity_resolution_tags = lambda *_args: []
        mutant.resolve_tag = lambda *_args: None
        mutant.read_record = lambda *_args: {}

        def reject_every_fork(*_args):
            raise RecoveryError("blanket two-successor rejection")

        mutant.resolve_continuity_successor_fork = reject_every_fork

        with self.assertRaisesRegex(RecoveryError, "blanket two-successor rejection"):
            conformance.case_continuity_ambiguity_rejection(mutant)

    def test_continuity_case_exercises_exact_transport_authorities(self) -> None:
        consumer = conformance.load_consumer(ROOT / "scripts" / "component_release_recovery.py")

        conformance.case_continuity_ambiguity_rejection(consumer)

    def test_public_audit_requires_every_target_to_pin_identical_bytes(self) -> None:
        suite_raw = SUITE_PATH.read_bytes()
        consumers = {
            consumer["repository"].removeprefix("durable-workflow/"): consumer
            for consumer in self.contract["consumers"]
        }

        def public_file(url: str) -> bytes:
            relative = url.removeprefix("https://raw.githubusercontent.com/durable-workflow/")
            repository, branch, path = relative.split("/", 2)
            consumer = consumers[repository]
            self.assertEqual(consumer["target_branch"], branch)
            if path.endswith("release-recovery-consumer-contract.json"):
                return self.contract_raw
            if path.endswith("release_recovery_consumer_conformance.py"):
                return suite_raw
            if path.endswith("release-recovery-consumer-adapter.json"):
                return conformance.canonical_json(
                    {
                        "component": consumer["component"],
                        "contract": {
                            "path": ("scripts/ci/release-recovery-consumer-contract.json"),
                            "sha256": conformance.sha256_bytes(self.contract_raw),
                            "version": self.contract["version"],
                        },
                        "repository": consumer["repository"],
                        "target_branch": consumer["target_branch"],
                    }
                )
            self.fail(f"unexpected audit path: {path}")

        with mock.patch.object(
            conformance,
            "fetch_public",
            side_effect=public_file,
        ):
            results = conformance.audit_public_targets(
                self.contract,
                self.contract_raw,
            )

        self.assertEqual(
            [consumer["component"] for consumer in self.contract["consumers"]],
            [result["component"] for result in results],
        )
        self.assertTrue(all(result["status"] == "pass" for result in results))


if __name__ == "__main__":
    unittest.main()
