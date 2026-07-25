from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from unittest import mock

from scripts import release_recovery_consumer_conformance as conformance

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "release-recovery" / "consumer-conformance" / "contract.json"
SUITE_PATH = ROOT / "scripts" / "release_recovery_consumer_conformance.py"


class ReleaseRecoveryConsumerConformanceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract_raw = CONTRACT_PATH.read_bytes()
        cls.contract = json.loads(cls.contract_raw)

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

    def test_contract_behavior_cannot_change_at_the_same_version(self) -> None:
        changed = copy.deepcopy(self.contract)
        changed["cases"][0]["requirement"] += " Changed."

        with self.assertRaisesRegex(
            conformance.ConformanceError,
            "without advancing",
        ):
            conformance.require_versioned_contract_change(self.contract, changed)

        changed["version"] = "1.1.0"
        conformance.require_versioned_contract_change(self.contract, changed)

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
