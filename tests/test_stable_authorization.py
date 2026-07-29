from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml
from jsonschema import Draft202012Validator

from scripts.beta_candidate import CandidateError, canonical_json, manifest_digest
from scripts.stable_authorization import (
    AUTHORIZATION_SCHEMA,
    AUTHORIZATION_WORKFLOW_REF,
    COMPONENT_NAMES,
    CONTRACT_SCHEMA,
    CONTRACT_URL,
    EXPERIMENT_EVIDENCE_SCHEMA,
    POLYGLOT_CELLS,
    READOUT_SCHEMA,
    RELEASE_CRITICAL_EXPERIMENTS,
    REQUEST_SCHEMA,
    evaluate,
    load_contract,
    load_request,
    protected_environment_evidence,
    protected_run_evidence,
    require_ready,
    tuple_binding,
    validate_existing_authorization,
    validate_request,
    verified_readout,
    verify_artifact_tuple_candidate,
    verify_evidence_sources,
)

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "stable-authorization" / "contract.json"


class RouteClient:
    def __init__(self, routes: dict[str, object]) -> None:
        self.routes = routes

    def json(self, url: str, **_kwargs: object) -> object:
        if url not in self.routes:
            raise AssertionError(f"unexpected route: {url}")
        return copy.deepcopy(self.routes[url])


def github_user(login: str, identifier: int) -> dict[str, object]:
    return {
        "login": login,
        "id": identifier,
        "node_id": f"U_{identifier}",
        "url": f"https://api.github.com/users/{login}",
        "html_url": f"https://github.com/{login}",
    }


def artifact_tuple() -> dict[str, object]:
    return {
        "tag": "release-candidate/rc/coherent-2-0-rc-9",
        "commit": "f" * 40,
        "components": {
            name: {
                "version": f"2.0.0-rc.{index + 1}",
                "commit": f"{index + 1:040x}",
            }
            for index, name in enumerate(COMPONENT_NAMES)
        },
    }


def source_payload(record: dict[str, object]) -> bytes:
    return canonical_json({key: value for key, value in record.items() if key != "source"})


def experiment_evidence(
    experiment: str,
    binding: dict[str, str],
) -> dict[str, object]:
    record: dict[str, object] = {
        "schema": EXPERIMENT_EVIDENCE_SCHEMA,
        "experiment": experiment,
        "outcome": "pass",
        "runner_blocked": False,
        "artifact_tuple": copy.deepcopy(binding),
    }
    if experiment == "polyglot":
        record["cells"] = {
            cell: {
                "outcome": "pass",
                "runner_blocked": False,
                "artifact_tuple": copy.deepcopy(binding),
            }
            for cell in POLYGLOT_CELLS
        }
    payload = canonical_json(record)
    record["source"] = {
        "url": f"https://github.com/durable-workflow/.github/releases/download/evidence/{experiment}.json",
        "sha256": hashlib.sha256(payload).hexdigest(),
        "generated_at": "2026-07-29T13:00:00Z",
    }
    return record


def request() -> dict[str, object]:
    selected_tuple = artifact_tuple()
    binding = tuple_binding(selected_tuple)
    return {
        "$schema": "./request-schema.json",
        "schema": REQUEST_SCHEMA,
        "stable_version": "2.0.0",
        "artifact_tuple": selected_tuple,
        "evidence": {
            "experiments": {
                experiment: experiment_evidence(experiment, binding) for experiment in RELEASE_CRITICAL_EXPERIMENTS
            }
        },
    }


def authorization_record(
    value: dict[str, object],
    readout: dict[str, object],
    contract: dict[str, object],
) -> dict[str, object]:
    return {
        "schema": AUTHORIZATION_SCHEMA,
        "channel": "stable",
        "stable_version": "2.0.0",
        "artifact_tuple": value["artifact_tuple"],
        "contract": {
            "url": CONTRACT_URL,
            "sha256": manifest_digest(contract),
        },
        "request_sha256": manifest_digest(value),
        "readout_sha256": manifest_digest(readout),
        "evidence_gate": "pass",
        "decision": {
            "status": "authorized",
            "type": "protected-human-review",
            "actor": "release-operator",
            "repository": "durable-workflow/.github",
            "workflow_ref": AUTHORIZATION_WORKFLOW_REF,
            "workflow_commit": "e" * 40,
            "run_id": 100,
            "run_attempt": 1,
            "run_url": "https://github.com/durable-workflow/.github/actions/runs/100",
            "environment": "stable-authorization",
            "environment_protection": {
                "prevent_self_review": True,
                "required_reviewer_user_ids": [1130888],
            },
            "environment_approval": {
                "state": "approved",
                "run_id": 100,
                "run_attempt": 1,
                "user": github_user("release-owner", 1130888),
            },
        },
    }


class StableAuthorizationContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_contract(CONTRACT_PATH)

    def test_contract_declares_the_exact_fixed_tier_and_sdk_cells(self) -> None:
        self.assertEqual(CONTRACT_SCHEMA, self.contract["schema"])
        self.assertEqual(list(COMPONENT_NAMES), self.contract["artifact_components"])
        self.assertEqual(
            list(RELEASE_CRITICAL_EXPERIMENTS),
            self.contract["release_critical_experiments"],
        )
        self.assertEqual(
            {"polyglot": list(POLYGLOT_CELLS)},
            self.contract["required_sdk_cells"],
        )
        self.assertEqual(
            "never_authoritative",
            self.contract["evidence_policy"]["aggregate_historical_pass_rate"],
        )
        self.assertEqual(
            {"required": True, "occurs_after_evidence_gate": True},
            self.contract["human_decision"],
        )

    def test_machine_readable_schemas_accept_a_passing_decision(self) -> None:
        value = request()
        readout = evaluate(self.contract, value)
        for filename, document in (
            ("contract-schema.json", self.contract),
            ("request-schema.json", value),
            ("readout-schema.json", readout),
            (
                "authorization-schema.json",
                authorization_record(value, readout, self.contract),
            ),
        ):
            schema = json.loads((ROOT / "stable-authorization" / filename).read_bytes())
            Draft202012Validator(schema).validate(document)

    def test_passing_tier_still_awaits_a_human_decision(self) -> None:
        readout = evaluate(self.contract, request())

        self.assertEqual(READOUT_SCHEMA, readout["schema"])
        self.assertEqual("pass", readout["evidence_gate"])
        self.assertEqual("awaiting-human-decision", readout["stable_authorization"])
        self.assertEqual("allowed", readout["prerelease_iteration"])
        self.assertNotIn("pass_rate", json.dumps(readout))
        for status in readout["experiments"].values():
            self.assertEqual("current", status["freshness"])
            self.assertEqual("pass", status["outcome"])
            self.assertTrue(status["ready"])
        for status in readout["experiments"]["polyglot"]["cells"].values():
            self.assertEqual("current", status["freshness"])
            self.assertEqual("pass", status["outcome"])
            self.assertTrue(status["ready"])
        require_ready(readout)
        validate_existing_authorization(
            authorization_record(request(), readout, self.contract),
            request(),
            readout,
            self.contract,
        )

    def test_missing_evidence_is_visible_without_blocking_prerelease_iteration(self) -> None:
        value = request()
        value["evidence"]["experiments"].pop("cloud")

        readout = evaluate(self.contract, value)

        self.assertEqual("fail", readout["evidence_gate"])
        self.assertEqual("blocked", readout["stable_authorization"])
        self.assertEqual("allowed", readout["prerelease_iteration"])
        self.assertEqual("missing", readout["experiments"]["cloud"]["freshness"])
        self.assertEqual("missing", readout["experiments"]["cloud"]["outcome"])
        with self.assertRaisesRegex(CandidateError, "cloud"):
            require_ready(readout)

    def test_stale_pass_blocks_a_superficially_favorable_aggregate(self) -> None:
        value = request()
        stale = value["evidence"]["experiments"]["timers"]
        stale["artifact_tuple"]["sha256"] = "0" * 64

        readout = evaluate(self.contract, value)
        passing_outcomes = sum(status["outcome"] == "pass" for status in readout["experiments"].values())
        apparent_rate = 100 * passing_outcomes / len(RELEASE_CRITICAL_EXPERIMENTS)

        self.assertGreater(apparent_rate, 90)
        self.assertEqual("stale", readout["experiments"]["timers"]["freshness"])
        self.assertEqual("pass", readout["experiments"]["timers"]["outcome"])
        self.assertFalse(readout["experiments"]["timers"]["ready"])
        self.assertEqual("fail", readout["evidence_gate"])
        self.assertEqual(
            {"release_authority": "never-authoritative"},
            readout["historical_aggregate"],
        )

    def test_fail_and_runner_blocked_are_independent_fail_closed_states(self) -> None:
        failed = request()
        failed["evidence"]["experiments"]["activities"]["outcome"] = "fail"
        blocked = request()
        blocked["evidence"]["experiments"]["heartbeats"]["runner_blocked"] = True

        failed_readout = evaluate(self.contract, failed)
        blocked_readout = evaluate(self.contract, blocked)

        self.assertEqual("fail", failed_readout["experiments"]["activities"]["outcome"])
        self.assertEqual(
            "runner-blocked",
            blocked_readout["experiments"]["heartbeats"]["outcome"],
        )
        self.assertEqual("fail", failed_readout["evidence_gate"])
        self.assertEqual("fail", blocked_readout["evidence_gate"])

    def test_every_polyglot_sdk_cell_must_be_current_and_passing(self) -> None:
        missing = request()
        missing["evidence"]["experiments"]["polyglot"]["cells"].pop("rust")
        stale = request()
        stale["evidence"]["experiments"]["polyglot"]["cells"]["php"]["artifact_tuple"]["commit"] = "0" * 40
        blocked = request()
        blocked["evidence"]["experiments"]["polyglot"]["cells"]["python"]["runner_blocked"] = True

        missing_readout = evaluate(self.contract, missing)
        stale_readout = evaluate(self.contract, stale)
        blocked_readout = evaluate(self.contract, blocked)

        self.assertEqual(
            "missing",
            missing_readout["experiments"]["polyglot"]["cells"]["rust"]["status"],
        )
        self.assertEqual(
            "stale",
            stale_readout["experiments"]["polyglot"]["cells"]["php"]["status"],
        )
        self.assertEqual(
            "runner-blocked",
            blocked_readout["experiments"]["polyglot"]["cells"]["python"]["status"],
        )
        for readout in (missing_readout, stale_readout, blocked_readout):
            self.assertFalse(readout["experiments"]["polyglot"]["ready"])
            self.assertEqual("fail", readout["evidence_gate"])

    def test_aggregate_claims_and_non_polyglot_cells_are_rejected(self) -> None:
        aggregate = request()
        aggregate["historical_pass_rate"] = 99.9
        with self.assertRaisesRegex(CandidateError, "keys must be exactly"):
            validate_request(aggregate)

        cells = request()
        cells["evidence"]["experiments"]["replay"]["cells"] = {}
        with self.assertRaisesRegex(CandidateError, "keys must be exactly"):
            validate_request(cells)

    def test_readout_must_be_canonical_and_recomputed_before_use(self) -> None:
        value = request()
        expected = evaluate(self.contract, value)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "readout.json"
            path.write_bytes(canonical_json(expected))
            self.assertEqual(expected, verified_readout(self.contract, value, path))

            changed = copy.deepcopy(expected)
            changed["experiments"]["timers"]["ready"] = False
            path.write_bytes(canonical_json(changed))
            with self.assertRaisesRegex(CandidateError, "differs"):
                verified_readout(self.contract, value, path)

    def test_request_loader_rejects_a_noncanonical_tier_name(self) -> None:
        value = request()
        value["evidence"]["experiments"]["python-sdk"] = value["evidence"]["experiments"].pop("python")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "request.json"
            path.write_bytes(canonical_json(value))
            with self.assertRaisesRegex(CandidateError, "unknown experiment"):
                load_request(path)

    def test_cli_entry_points_are_directly_executable(self) -> None:
        for command in ("readout", "require-ready", "check", "record"):
            process = subprocess.run(
                [sys.executable, "scripts/stable_authorization.py", command, "--help"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, process.returncode, process.stderr)


class PublicEvidenceTest(unittest.TestCase):
    def test_public_evidence_bytes_must_match_every_inline_record(self) -> None:
        value = request()
        routes = {
            record["source"]["url"]: source_payload(record) for record in value["evidence"]["experiments"].values()
        }
        client = mock.Mock()
        client.bytes.side_effect = lambda url: routes[url]

        verify_evidence_sources(client, value)
        self.assertEqual(len(RELEASE_CRITICAL_EXPERIMENTS), client.bytes.call_count)

        routes[value["evidence"]["experiments"]["cloud"]["source"]["url"]] = b"{}\n"
        with self.assertRaisesRegex(CandidateError, "cloud public evidence digest"):
            verify_evidence_sources(client, value)

    @mock.patch("scripts.stable_authorization.read_public_record")
    @mock.patch("scripts.stable_authorization.resolve_tag")
    def test_candidate_tag_must_publish_the_same_seven_component_tuple(
        self,
        resolve: mock.Mock,
        read: mock.Mock,
    ) -> None:
        value = request()
        resolve.return_value = value["artifact_tuple"]["commit"]
        read.return_value = {
            "schema": "durable-workflow.release-candidate/v1",
            "channel": "rc",
            "components": value["artifact_tuple"]["components"],
        }

        verify_artifact_tuple_candidate(mock.Mock(), value)

        read.return_value = copy.deepcopy(read.return_value)
        read.return_value["components"]["server"]["version"] = "2.0.0-rc.99"
        with self.assertRaisesRegex(CandidateError, "differs"):
            verify_artifact_tuple_candidate(mock.Mock(), value)


class ProtectedHumanDecisionTest(unittest.TestCase):
    def test_environment_and_approval_require_an_independent_product_owner(self) -> None:
        api = "https://api.github.com/repos/durable-workflow/.github/environments/stable-authorization"
        activity = (
            "https://github.com/durable-workflow/.github/deployments/activity_log"
            "?environments_filter=stable-authorization"
        )
        run_url = "https://api.github.com/repos/durable-workflow/.github/actions/runs/100"
        routes = {
            api: {
                "id": 17,
                "html_url": activity,
                "deployment_branch_policy": {
                    "custom_branch_policies": True,
                    "protected_branches": False,
                },
                "protection_rules": [
                    {
                        "id": 19,
                        "type": "required_reviewers",
                        "prevent_self_review": True,
                        "reviewers": [
                            {
                                "type": "User",
                                "reviewer": github_user("release-owner", 1130888),
                            }
                        ],
                    }
                ],
            },
            f"{api}/deployment-branch-policies?per_page=100": {
                "total_count": 1,
                "branch_policies": [{"id": 23, "name": "main", "type": "branch"}],
            },
            run_url: {
                "actor": {"login": "release-operator"},
                "repository": {"full_name": "durable-workflow/.github"},
                "id": 100,
                "run_attempt": 1,
                "event": "workflow_dispatch",
                "path": ".github/workflows/stable-authorization.yml",
                "head_branch": "main",
                "head_sha": "e" * 40,
                "html_url": "https://github.com/durable-workflow/.github/actions/runs/100",
            },
            f"{run_url}/approvals": [
                {
                    "comment": "Authorize stable 2.0",
                    "state": "approved",
                    "environments": [
                        {
                            "id": 17,
                            "name": "stable-authorization",
                            "node_id": "ENV_17",
                            "html_url": activity,
                            "url": api,
                        }
                    ],
                    "user": github_user("release-owner", 1130888),
                }
            ],
        }
        client = RouteClient(routes)

        protection = protected_environment_evidence(client)
        approval = protected_run_evidence(
            client,
            actor="release-operator",
            run_id=100,
            run_attempt=1,
            workflow_commit="e" * 40,
            environment_protection=protection,
        )

        self.assertTrue(protection["prevent_self_review"])
        self.assertEqual([1130888], protection["required_reviewer_user_ids"])
        self.assertEqual("approved", approval["state"])
        self.assertEqual(1130888, approval["user"]["id"])

    def test_self_review_enabled_environment_fails_closed(self) -> None:
        api = "https://api.github.com/repos/durable-workflow/.github/environments/stable-authorization"
        activity = (
            "https://github.com/durable-workflow/.github/deployments/activity_log"
            "?environments_filter=stable-authorization"
        )
        routes = {
            api: {
                "id": 17,
                "html_url": activity,
                "deployment_branch_policy": {
                    "custom_branch_policies": True,
                    "protected_branches": False,
                },
                "protection_rules": [
                    {
                        "id": 19,
                        "type": "required_reviewers",
                        "prevent_self_review": False,
                        "reviewers": [
                            {
                                "type": "User",
                                "reviewer": github_user("release-owner", 1130888),
                            }
                        ],
                    }
                ],
            }
        }

        with self.assertRaisesRegex(CandidateError, "independent product-owner"):
            protected_environment_evidence(RouteClient(routes))


class StableAuthorizationWorkflowTest(unittest.TestCase):
    def test_human_environment_is_reached_only_after_the_evidence_job(self) -> None:
        path = ROOT / ".github" / "workflows" / "stable-authorization.yml"
        source = path.read_text(encoding="utf-8")
        workflow = yaml.safe_load(source)
        evidence = workflow["jobs"]["evidence"]
        authorize = workflow["jobs"]["authorize"]

        self.assertEqual("evidence", authorize["needs"])
        self.assertIn("github.ref == 'refs/heads/main'", authorize["if"])
        self.assertEqual("stable-authorization", authorize["environment"])
        self.assertEqual("read", evidence["permissions"]["contents"])
        self.assertEqual("write", authorize["permissions"]["contents"])
        evidence_commands = "\n".join(step.get("run", "") for step in evidence["steps"])
        authorize_commands = "\n".join(step.get("run", "") for step in authorize["steps"])
        self.assertIn("--verify-public-sources", evidence_commands)
        self.assertIn("require-ready", evidence_commands)
        self.assertIn("stable_authorization.py record", authorize_commands)
        self.assertLess(
            evidence_commands.index("--verify-public-sources"),
            evidence_commands.index("require-ready"),
        )
        self.assertNotIn("pass_rate", source)


if __name__ == "__main__":
    unittest.main()
