from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

import yaml

from scripts import release_recovery_consumer_conformance as conformance
from scripts import release_recovery_target_qualification as qualification

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "release-recovery" / "consumer-conformance" / "contract.json"
SUITE_PATH = ROOT / "scripts" / "release_recovery_consumer_conformance.py"
SOURCE_QUALIFICATION = ROOT / ".github" / "workflows" / "source-qualification.yml"


class ReleaseRecoveryTargetQualificationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract_raw = CONTRACT_PATH.read_bytes()
        cls.contract = json.loads(cls.contract_raw)
        cls.suite_raw = SUITE_PATH.read_bytes()

    def adapter(self, consumer: dict[str, str], contract: dict, contract_raw: bytes) -> bytes:
        return conformance.canonical_json(
            {
                "component": consumer["component"],
                "consumer": "scripts/ci/component-release-recovery.py",
                "contract": {
                    "path": qualification.CONTRACT_PATH,
                    "sha256": conformance.sha256_bytes(contract_raw),
                    "version": contract["version"],
                },
                "distribution_verification": {
                    "command": ["{python}", "scripts/ci/verify-release-recovery-distribution.py"]
                },
                "repository": consumer["repository"],
                "schema": conformance.ADAPTER_SCHEMA,
                "suite": {
                    "path": qualification.SUITE_PATH,
                    "sha256": contract["suite"]["sha256"],
                },
                "target_branch": consumer["target_branch"],
            }
        )

    def public_state(
        self,
        expected_contract: dict,
        expected_raw: bytes,
        advanced_components: set[str],
    ):
        consumers = {consumer["repository"]: consumer for consumer in expected_contract["consumers"]}
        baseline_contract = self.contract
        baseline_raw = self.contract_raw

        def public_file(url: str) -> bytes:
            relative = url.removeprefix("https://raw.githubusercontent.com/")
            organization, repository, commit, path = relative.split("/", 3)
            self.assertEqual("durable-workflow", organization)
            consumer = consumers[f"{organization}/{repository}"]
            self.assertEqual(conformance.sha256_bytes(consumer["component"].encode())[:40], commit)
            advanced = consumer["component"] in advanced_components
            remote_contract = expected_contract if advanced else baseline_contract
            remote_raw = expected_raw if advanced else baseline_raw
            if path == qualification.CONTRACT_PATH:
                return remote_raw
            if path == qualification.ADAPTER_PATH:
                return self.adapter(consumer, remote_contract, remote_raw)
            if path == qualification.SUITE_PATH:
                return self.suite_raw
            self.fail(f"unexpected public target path: {path}")

        return public_file

    def resolved_target(self, repository: str, branch: str) -> tuple[str, str]:
        consumer = next(consumer for consumer in self.contract["consumers"] if consumer["repository"] == repository)
        self.assertEqual(consumer["target_branch"], branch)
        return f"refs/heads/{branch}", conformance.sha256_bytes(consumer["component"].encode())[:40]

    def test_required_target_branch_workflow_runs_aggregate_qualification(self) -> None:
        workflow = yaml.safe_load(SOURCE_QUALIFICATION.read_text())
        source_job = workflow["jobs"]["source"]
        steps = source_job["steps"]
        audit = next(step for step in steps if step.get("name") == "Audit synchronized release-recovery consumers")
        policy = json.loads((ROOT / "qualification" / "policy.json").read_bytes())
        required_check = policy["targets"]["github-control-plane"]["workflows"][0]["required_check"]
        self.assertEqual(required_check, source_job["name"])
        self.assertIn("schedule", workflow[True])
        self.assertIn("scripts/release_recovery_target_qualification.py", audit["run"])
        self.assertIn("github.ref == 'refs/heads/main'", audit["if"])

    def test_cli_is_directly_executable(self) -> None:
        result = subprocess.run(
            [sys.executable, "scripts/release_recovery_target_qualification.py", "--help"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr)

    def test_target_ref_resolves_to_one_exact_commit(self) -> None:
        commit = "a" * 40
        result = mock.Mock(
            returncode=0,
            stdout=f"{commit}\trefs/heads/v2\n",
        )
        with mock.patch.object(qualification.subprocess, "run", return_value=result) as run:
            self.assertEqual(
                ("refs/heads/v2", commit),
                qualification.resolve_target_commit("durable-workflow/workflow", "v2"),
            )

        run.assert_called_once_with(
            [
                "git",
                "ls-remote",
                "--exit-code",
                "--refs",
                "https://github.com/durable-workflow/workflow.git",
                "refs/heads/v2",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )

        result.stdout = f"{commit}\trefs/heads/main\n"
        with (
            mock.patch.object(qualification.subprocess, "run", return_value=result),
            self.assertRaisesRegex(conformance.ConformanceError, "did not resolve to an exact commit"),
        ):
            qualification.resolve_target_commit("durable-workflow/workflow", "v2")

    def test_one_consumer_advance_fails_and_a_synchronized_advance_passes(self) -> None:
        advanced = copy.deepcopy(self.contract)
        advanced["version"] = "1.5.0"
        advanced_raw = conformance.canonical_json(advanced)
        conformance.validate_contract(advanced, advanced_raw, SUITE_PATH)

        with (
            mock.patch.object(
                qualification,
                "resolve_target_commit",
                side_effect=self.resolved_target,
            ),
            mock.patch.object(
                qualification,
                "fetch_public",
                side_effect=self.public_state(
                    advanced,
                    advanced_raw,
                    {"workflow"},
                ),
            ),
            self.assertRaisesRegex(
                conformance.ConformanceError,
                "waterline does not carry the current shared contract",
            ),
        ):
            qualification.audit_public_targets(advanced, advanced_raw)

        with (
            mock.patch.object(
                qualification,
                "resolve_target_commit",
                side_effect=self.resolved_target,
            ),
            mock.patch.object(
                qualification,
                "fetch_public",
                side_effect=self.public_state(
                    advanced,
                    advanced_raw,
                    {consumer["component"] for consumer in advanced["consumers"]},
                ),
            ),
        ):
            evidence = qualification.audit_public_targets(advanced, advanced_raw)

        self.assertEqual(7, len(evidence))
        self.assertTrue(all(target["status"] == "pass" for target in evidence))
        self.assertEqual(
            {f"refs/heads/{consumer['target_branch']}" for consumer in advanced["consumers"]},
            {target["target_ref"] for target in evidence},
        )
        self.assertTrue(all(conformance.COMMIT_PATTERN.fullmatch(target["source_commit"]) for target in evidence))

    def test_missing_or_mismatched_identity_and_digest_fail_closed(self) -> None:
        consumer = self.contract["consumers"][0]
        adapter_raw = self.adapter(consumer, self.contract, self.contract_raw)
        adapter = json.loads(adapter_raw)
        adapter["target_branch"] = "main"
        with self.assertRaisesRegex(conformance.ConformanceError, "wrong target identity"):
            qualification.validate_adapter(
                conformance.canonical_json(adapter),
                consumer,
                self.contract,
                conformance.sha256_bytes(self.contract_raw),
            )

        adapter = json.loads(adapter_raw)
        adapter["suite"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(conformance.ConformanceError, "does not pin the current suite"):
            qualification.validate_adapter(
                conformance.canonical_json(adapter),
                consumer,
                self.contract,
                conformance.sha256_bytes(self.contract_raw),
            )

        with (
            mock.patch.object(
                qualification,
                "resolve_target_commit",
                side_effect=self.resolved_target,
            ),
            mock.patch.object(
                qualification,
                "fetch_public",
                side_effect=conformance.ConformanceError("artifact absent"),
            ),
            self.assertRaisesRegex(conformance.ConformanceError, "artifact absent"),
        ):
            qualification.audit_public_targets(self.contract, self.contract_raw)


if __name__ == "__main__":
    unittest.main()
