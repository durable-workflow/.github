from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
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
