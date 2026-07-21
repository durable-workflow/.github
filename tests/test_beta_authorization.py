from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from scripts.beta_authorization import (
    AUTHORIZATION_SCHEMA,
    AUTHORIZATION_WORKFLOW_REF,
    EVIDENCE_SCHEMA,
    REQUEST_SCHEMA,
    CandidateError,
    authority_issue_and_decision,
    build_evidence,
    check_authorization,
    expected_qualification_commits,
    protected_environment_evidence,
    protected_run_evidence,
    public_backlog_evidence,
    record_authorization,
    validate_qualification_evidence,
    validate_request,
    verify_candidate_evidence,
    verify_conformance_evidence,
    verify_continuity_evidence,
    verify_qualified_heads_stable,
)
from scripts.beta_candidate import COMPONENTS, canonical_json, manifest_digest
from scripts.release_plan import verify_beta_authorization
from tests.verification_fixture import candidate_verification

ROOT = Path(__file__).resolve().parents[1]


def authorization() -> dict[str, object]:
    return {
        "schema": AUTHORIZATION_SCHEMA,
        "channel": "beta",
        "candidate": "first-beta",
        "components": {
            name: {
                "version": f"2.0.0-beta.{index + 1}" if name in {"workflow", "waterline"} else f"1.4.{index}",
                "commit": f"{index + 1:040x}",
            }
            for index, name in enumerate(COMPONENTS)
        },
    }


def request() -> dict[str, object]:
    return {
        "schema": REQUEST_SCHEMA,
        "authorization": authorization(),
        "evidence": {
            "candidate": {
                "tag": "beta-candidate/qualified-alpha",
                "commit": "a" * 40,
            },
            "conformance": {
                "tag": "beta-conformance/qualified-alpha/123.1",
                "commit": "d" * 40,
            },
            "continuity": {
                "complete": {
                    "tag": "beta-continuity/continuity-alpha/complete",
                    "commit": "e" * 40,
                },
                "no_op": {
                    "tag": "beta-continuity/continuity-alpha/no-op-confirmed",
                    "commit": "f" * 40,
                },
            },
            "decision": {"issue": 3, "comment": 91},
        },
    }


def candidate_manifest() -> dict[str, object]:
    intended = authorization()["components"]
    return {
        "schema": "durable-workflow.beta-candidate/v1",
        "candidate": "qualified-alpha",
        "components": {
            name: {
                "version": f"2.0.0-alpha.{index + 1}" if name in {"workflow", "waterline"} else f"1.3.{index}",
                "commit": intended[name]["commit"],
            }
            for index, name in enumerate(COMPONENTS)
        },
    }


def qualification() -> dict[str, object]:
    intended = authorization()["components"]
    policy = json.loads((ROOT / "qualification" / "policy.json").read_bytes())
    return {
        "schema": "durable-workflow.github-target-qualification/v1",
        "targets": {
            name: {
                "action_releases": [],
                "branch": target["branch"],
                "commit": intended[name]["commit"] if name in intended else f"{index + 20:040x}",
                "protected_checks": [workflow["required_check"] for workflow in target["workflows"]],
                "successful_check_runs": {
                    workflow["required_check"]: index + 10 for workflow in target["workflows"]
                },
                "workflows": [
                    {
                        "path": f".github/workflows/{workflow['path']}",
                        "required_check": workflow["required_check"],
                        "workflow_id": index + 100,
                    }
                    for workflow in target["workflows"]
                ],
            }
            for index, (name, target) in enumerate(policy["targets"].items())
        },
    }


def github_user(login: str, identifier: int) -> dict[str, object]:
    return {
        "login": login,
        "id": identifier,
        "node_id": f"U_{identifier}",
        "url": f"https://api.github.com/users/{login}",
        "html_url": f"https://github.com/{login}",
    }


def environment_protection() -> dict[str, object]:
    return {
        "custom_branch_policies": [{"id": 23, "name": "main"}],
        "deployment_branch_policy": {"custom_branch_policies": True, "protected_branches": False},
        "environment_id": 17,
        "environment_url": (
            "https://github.com/durable-workflow/.github/deployments/activity_log"
            "?environments_filter=beta-authorization"
        ),
        "prevent_self_review": False,
        "required_reviewer_rule_ids": [19],
        "required_reviewer_user_ids": [1130888],
    }


def environment_approval() -> dict[str, object]:
    return {
        "comment": "Approved for beta",
        "environments": [
            {
                "html_url": (
                    "https://github.com/durable-workflow/.github/deployments/activity_log"
                    "?environments_filter=beta-authorization"
                ),
                "id": 17,
                "name": "beta-authorization",
                "node_id": "ENV_17",
                "url": "https://api.github.com/repos/durable-workflow/.github/environments/beta-authorization",
            }
        ],
        "run_attempt": 1,
        "run_id": 456,
        "state": "approved",
        "user": github_user("release-reviewer", 1130888),
    }


def recorded_evidence(value: dict[str, object]) -> dict[str, object]:
    return {
        "schema": EVIDENCE_SCHEMA,
        "authorization_sha256": manifest_digest(value["authorization"]),
        "request_sha256": manifest_digest(value),
        "decision": {
            "repository": "durable-workflow/.github",
            "issue": 3,
            "issue_url": "https://github.com/durable-workflow/.github/issues/3",
            "comment": 91,
            "comment_url": "https://github.com/durable-workflow/.github/issues/3#issuecomment-91",
            "author": github_user("release-operator", 7),
            "body_sha256": "1" * 64,
        },
        "candidate": {
            "tag": "beta-candidate/qualified-alpha",
            "commit": "a" * 40,
            "manifest_sha256": "2" * 64,
            "verification_sha256": "3" * 64,
        },
        "qualification": {
            "path": "target-qualification-evidence.json",
            "sha256": manifest_digest(qualification()),
        },
        "conformance": {
            "tag": "beta-conformance/qualified-alpha/123.1",
            "commit": "d" * 40,
            "release": "https://github.com/durable-workflow/.github/releases/tag/conformance",
            "run": {
                "repository": "durable-workflow/.github",
                "run_id": 123,
                "run_attempt": 1,
                "evidence_tag": "beta-conformance/qualified-alpha/123.1",
            },
        },
        "continuity": {
            "complete": value["evidence"]["continuity"]["complete"],
            "no_op": value["evidence"]["continuity"]["no_op"],
            "plan": {"tag": "release-plan/continuity-alpha", "commit": "4" * 40, "sha256": "5" * 64},
        },
        "backlog": {
            "repositories": [
                f"durable-workflow/{name}"
                for name in json.loads((ROOT / "issue-authority" / "policy.json").read_bytes())["repositories"]
            ],
            "allowed_authorization_gate": {
                "repository": "durable-workflow/.github",
                "number": 3,
                "url": "https://github.com/durable-workflow/.github/issues/3",
            },
            "unresolved_p0_p1": [],
        },
        "github_authority": {
            "actor": "release-operator",
            "repository": "durable-workflow/.github",
            "workflow_ref": AUTHORIZATION_WORKFLOW_REF,
            "workflow_commit": "6" * 40,
            "run_id": 456,
            "run_attempt": 1,
            "run_url": "https://github.com/durable-workflow/.github/actions/runs/456",
            "environment": "beta-authorization",
            "environment_protection": environment_protection(),
            "environment_approval": environment_approval(),
        },
    }


class RouteClient:
    def __init__(self, json_routes: dict[str, object], byte_routes: dict[str, bytes] | None = None) -> None:
        self.json_routes = json_routes
        self.byte_routes = byte_routes or {}
        self.requested: list[str] = []

    def json(self, url: str, **_kwargs: object) -> object:
        self.requested.append(url)
        if url not in self.json_routes:
            raise AssertionError(f"unexpected JSON URL: {url}")
        return copy.deepcopy(self.json_routes[url])

    def bytes(self, url: str, **_kwargs: object) -> bytes:
        self.requested.append(url)
        if url not in self.byte_routes:
            raise AssertionError(f"unexpected bytes URL: {url}")
        return self.byte_routes[url]


class BetaAuthorizationContractTest(unittest.TestCase):
    def test_request_and_record_schemas_accept_the_canonical_contract(self) -> None:
        record_schema = json.loads((ROOT / "beta-authorization" / "record-schema.json").read_bytes())
        request_schema = json.loads((ROOT / "beta-authorization" / "request-schema.json").read_bytes())
        record_resource = Resource.from_contents(record_schema)
        registry = Registry().with_resource(record_schema["$id"], record_resource)

        Draft202012Validator(record_schema).validate(authorization())
        Draft202012Validator(request_schema, registry=registry).validate(request())
        Draft202012Validator(
            json.loads((ROOT / "beta-authorization" / "evidence-schema.json").read_bytes())
        ).validate(recorded_evidence(request()))

    def test_validation_rejects_stable_channel_and_incomplete_evidence(self) -> None:
        stable = request()
        stable["authorization"]["channel"] = "stable"
        with self.assertRaisesRegex(CandidateError, "only the beta channel"):
            validate_request(stable)

        incomplete = request()
        incomplete["evidence"].pop("conformance")
        with self.assertRaisesRegex(CandidateError, "keys must be exactly"):
            validate_request(incomplete)

    def test_fresh_qualification_pins_exactly_the_seven_intended_sources(self) -> None:
        value = request()
        self.assertEqual(
            {
                name: identity["commit"]
                for name, identity in value["authorization"]["components"].items()
            },
            expected_qualification_commits(value),
        )

    def test_workflow_is_protected_and_mirrors_both_git_records(self) -> None:
        source = (ROOT / ".github" / "workflows" / "beta-authorization.yml").read_text(encoding="utf-8")
        self.assertIn("environment: beta-authorization", source)
        self.assertIn("contents: write", source)
        self.assertIn("checks: read", source)
        self.assertIn("issues: read", source)
        self.assertIn("python scripts/beta_authorization.py record", source)
        self.assertIn("--verify-tag --prerelease", source)
        self.assertIn("beta-authorization-evidence.json", source)
        self.assertIn("qualification_policy.py audit", source)
        self.assertIn("target-qualification-evidence.json", source)
        self.assertNotIn("stable-authorization", source)

    @mock.patch("scripts.release_plan.read_public_record")
    def test_record_is_consumed_by_the_existing_beta_release_plan_contract(self, read_record: mock.Mock) -> None:
        value = authorization()
        plan = {
            "plan": value["candidate"],
            "components": value["components"],
            "beta_authorization": {"tag": "beta-authorization/first-beta", "commit": "7" * 40},
        }
        read_record.return_value = value
        verify_beta_authorization(mock.Mock(), plan)

        changed = copy.deepcopy(value)
        changed["components"]["server"]["version"] = "9.9.9"
        read_record.return_value = changed
        with self.assertRaisesRegex(CandidateError, "same candidate and seven-component tuple"):
            verify_beta_authorization(mock.Mock(), plan)

    def test_cli_entry_points_are_directly_executable(self) -> None:
        for command in ("validate", "expected-commits", "check", "record"):
            process = subprocess.run(
                [sys.executable, "scripts/beta_authorization.py", command, "--help"],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, process.returncode, process.stderr)


class ProtectedGitHubAuthorityTest(unittest.TestCase):
    def test_environment_and_approval_bind_main_dispatch_and_both_identities(self) -> None:
        activity = (
            "https://github.com/durable-workflow/.github/deployments/activity_log"
            "?environments_filter=beta-authorization"
        )
        environment_url = "https://api.github.com/repos/durable-workflow/.github/environments/beta-authorization"
        routes = {
            environment_url: {
                "id": 17,
                "html_url": activity,
                "protection_rules": [
                    {
                        "id": 19,
                        "type": "required_reviewers",
                        "prevent_self_review": False,
                        "reviewers": [
                            {"type": "User", "reviewer": {"id": 1130888}}
                        ],
                    }
                ],
                "deployment_branch_policy": {"custom_branch_policies": True, "protected_branches": False},
            },
            f"{environment_url}/deployment-branch-policies?per_page=100": {
                "total_count": 1,
                "branch_policies": [{"id": 23, "name": "main", "type": "branch"}],
            },
            "https://api.github.com/repos/durable-workflow/.github/actions/runs/456": {
                "actor": {"login": "release-operator"},
                "event": "workflow_dispatch",
                "head_branch": "main",
                "head_sha": "6" * 40,
                "html_url": "https://github.com/durable-workflow/.github/actions/runs/456",
                "id": 456,
                "path": ".github/workflows/beta-authorization.yml@main",
                "repository": {"full_name": "durable-workflow/.github"},
                "run_attempt": 1,
            },
            "https://api.github.com/repos/durable-workflow/.github/actions/runs/456/approvals": [
                {
                    "comment": "Approved for beta",
                    "environments": environment_approval()["environments"],
                    "state": "approved",
                    "user": github_user("release-reviewer", 1130888),
                }
            ],
        }
        client = RouteClient(routes)
        protection = protected_environment_evidence(client)
        approval = protected_run_evidence(
            client,
            actor="release-operator",
            run_id=456,
            run_attempt=1,
            workflow_commit="6" * 40,
            environment_protection=protection,
        )
        self.assertEqual("release-reviewer", approval["user"]["login"])
        self.assertEqual([19], protection["required_reviewer_rule_ids"])
        self.assertEqual([1130888], protection["required_reviewer_user_ids"])

    def test_decision_comment_must_be_by_dispatcher_and_bind_exact_authorization(self) -> None:
        value = request()
        digest = manifest_digest(value["authorization"])
        routes = {
            "https://api.github.com/repos/durable-workflow/.github/issues/3": {
                "number": 3,
                "state": "open",
                "html_url": "https://github.com/durable-workflow/.github/issues/3",
                "labels": [{"name": name} for name in (
                    "authority:github",
                    "beta:blocker",
                    "completion:evidence-required",
                    "kind:release-blocker",
                    "priority:P0",
                )],
                "body": "<!-- beta-work-id: authorize-2-0-beta -->",
                "milestone": {"title": "2.0 beta"},
            },
            "https://api.github.com/repos/durable-workflow/.github/issues/comments/91": {
                "id": 91,
                "issue_url": "https://api.github.com/repos/durable-workflow/.github/issues/3",
                "html_url": "https://github.com/durable-workflow/.github/issues/3#issuecomment-91",
                "author_association": "MEMBER",
                "user": github_user("release-operator", 7),
                "body": (
                    "I authorize the beta release.\n\n"
                    f"<!-- durable-workflow-beta-decision: authorize sha256:{digest} -->"
                ),
            },
        }
        evidence = authority_issue_and_decision(RouteClient(routes), value, actor="release-operator")
        self.assertEqual("release-operator", evidence["author"]["login"])

        changed = copy.deepcopy(value)
        changed["authorization"]["components"]["server"]["commit"] = "9" * 40
        with self.assertRaisesRegex(CandidateError, "does not authorize this exact"):
            authority_issue_and_decision(RouteClient(routes), changed, actor="release-operator")

    def test_backlog_allows_only_the_authorization_gate(self) -> None:
        repositories = json.loads((ROOT / "issue-authority" / "policy.json").read_bytes())["repositories"]
        routes: dict[str, object] = {}
        for name in repositories:
            repository = f"durable-workflow/{name}"
            for priority in ("priority:P0", "priority:P1"):
                query = urllib.parse.urlencode({"state": "open", "labels": priority, "per_page": 100, "page": 1})
                routes[f"https://api.github.com/repos/{repository}/issues?{query}"] = []
        p0_query = urllib.parse.urlencode(
            {"state": "open", "labels": "priority:P0", "per_page": 100, "page": 1}
        )
        routes[f"https://api.github.com/repos/durable-workflow/.github/issues?{p0_query}"] = [
            {"number": 3, "html_url": "https://github.com/durable-workflow/.github/issues/3"}
        ]
        evidence = public_backlog_evidence(RouteClient(routes))
        self.assertEqual([], evidence["unresolved_p0_p1"])

        routes[f"https://api.github.com/repos/durable-workflow/server/issues?{p0_query}"] = [
            {"number": 27, "html_url": "https://github.com/durable-workflow/server/issues/27"}
        ]
        with self.assertRaisesRegex(CandidateError, "server#27"):
            public_backlog_evidence(RouteClient(routes))


class PublicEvidenceBindingTest(unittest.TestCase):
    @mock.patch("scripts.beta_authorization.resolve_tag")
    @mock.patch("scripts.beta_authorization.read_public_record")
    def test_candidate_artifacts_must_bind_intended_source_commits(
        self,
        read_record: mock.Mock,
        resolve: mock.Mock,
    ) -> None:
        value = request()
        manifest = candidate_manifest()
        verification = candidate_verification(manifest)
        resolve.return_value = value["evidence"]["candidate"]["commit"]
        read_record.side_effect = [manifest, verification]
        release_url = "https://api.github.com/repos/durable-workflow/.github/releases/tags/beta-candidate%2Fqualified-alpha"
        client = RouteClient(
            {
                release_url: {
                    "assets": [
                        {"name": "candidate.json", "browser_download_url": "https://assets/candidate"},
                        {"name": "verification.json", "browser_download_url": "https://assets/verification"},
                    ]
                }
            },
            {
                "https://assets/candidate": canonical_json(manifest),
                "https://assets/verification": canonical_json(verification),
            },
        )
        _manifest, evidence = verify_candidate_evidence(client, value)
        self.assertEqual(value["evidence"]["candidate"]["commit"], evidence["commit"])

        changed = copy.deepcopy(value)
        changed["authorization"]["components"]["server"]["commit"] = "9" * 40
        read_record.side_effect = [manifest, verification]
        with self.assertRaisesRegex(CandidateError, "source commits differ"):
            verify_candidate_evidence(client, changed)

    def test_qualification_must_prove_every_intended_commit(
        self,
    ) -> None:
        value = request()
        proof = qualification()
        self.assertEqual(proof, validate_qualification_evidence(proof, value))

        proof["targets"]["server"]["successful_check_runs"] = {}
        with self.assertRaisesRegex(CandidateError, "server source commit"):
            validate_qualification_evidence(proof, value)

    def test_qualified_branch_heads_are_rechecked_before_publication(self) -> None:
        value = request()
        routes = {
            (
                f"https://api.github.com/repos/{COMPONENTS[name].repository}/branches/"
                f"{'v2' if name in {'workflow', 'waterline'} else 'main'}"
            ): {"commit": {"sha": identity["commit"]}}
            for name, identity in value["authorization"]["components"].items()
        }
        verify_qualified_heads_stable(RouteClient(routes), value, qualification())

        routes["https://api.github.com/repos/durable-workflow/server/branches/main"] = {
            "commit": {"sha": "9" * 40}
        }
        with self.assertRaisesRegex(CandidateError, "server source changed"):
            verify_qualified_heads_stable(RouteClient(routes), value, qualification())

    @mock.patch("scripts.beta_authorization.validate_conformance_release")
    @mock.patch("scripts.beta_authorization.resolve_tag")
    def test_conformance_must_be_the_cited_retained_passing_release(
        self,
        resolve: mock.Mock,
        validate_release: mock.Mock,
    ) -> None:
        value = request()
        reference = value["evidence"]["conformance"]
        resolve.return_value = reference["commit"]
        release_url = (
            "https://api.github.com/repos/durable-workflow/.github/releases/tags/"
            "beta-conformance%2Fqualified-alpha%2F123.1"
        )
        release = {"tag_name": reference["tag"]}
        validate_release.return_value = {
            "tag": reference["tag"],
            "release": "https://github.com/durable-workflow/.github/releases/tag/conformance",
            "run": {
                "repository": "durable-workflow/.github",
                "run_id": 123,
                "run_attempt": 1,
                "evidence_tag": reference["tag"],
            },
        }
        evidence = verify_conformance_evidence(RouteClient({release_url: release}), value, candidate_manifest())
        self.assertEqual(reference["commit"], evidence["commit"])

        validate_release.return_value = None
        with self.assertRaisesRegex(CandidateError, "not retained passing"):
            verify_conformance_evidence(RouteClient({release_url: release}), value, candidate_manifest())

    @mock.patch("scripts.beta_authorization.exact_completion_authority")
    @mock.patch("scripts.beta_authorization.load_config", return_value={"drill": "continuity"})
    @mock.patch("scripts.beta_authorization.validate_plan")
    @mock.patch("scripts.beta_authorization.read_public_record")
    @mock.patch("scripts.beta_authorization.resolve_tag")
    def test_continuity_requires_exact_complete_and_no_op_refs(
        self,
        resolve: mock.Mock,
        read_record: mock.Mock,
        _validate: mock.Mock,
        _config: mock.Mock,
        completion: mock.Mock,
    ) -> None:
        value = request()
        plan = {"plan": "continuity-alpha"}
        resolve.side_effect = [
            value["evidence"]["continuity"]["complete"]["commit"],
            value["evidence"]["continuity"]["no_op"]["commit"],
        ]
        read_record.return_value = plan
        completion.return_value = {
            "plan_record": {"tag": "release-plan/continuity-alpha", "commit": "1" * 40, "sha256": "2" * 64}
        }
        result = verify_continuity_evidence(mock.Mock(), value)
        self.assertEqual("release-plan/continuity-alpha", result["plan"]["tag"])
        completion.assert_called_once()

    @mock.patch("scripts.beta_authorization.verify_qualified_heads_stable")
    @mock.patch("scripts.beta_authorization.verify_requested_refs_stable")
    @mock.patch("scripts.beta_authorization.public_backlog_evidence")
    @mock.patch("scripts.beta_authorization.verify_continuity_evidence")
    @mock.patch("scripts.beta_authorization.verify_conformance_evidence")
    @mock.patch("scripts.beta_authorization.verify_candidate_evidence")
    @mock.patch("scripts.beta_authorization.authority_issue_and_decision")
    @mock.patch("scripts.beta_authorization.protected_run_evidence")
    @mock.patch("scripts.beta_authorization.protected_environment_evidence")
    def test_first_publication_checks_every_authority_before_returning_evidence(
        self,
        protection: mock.Mock,
        approval: mock.Mock,
        decision: mock.Mock,
        candidate: mock.Mock,
        conformance: mock.Mock,
        continuity: mock.Mock,
        backlog: mock.Mock,
        stable: mock.Mock,
        qualified_heads: mock.Mock,
    ) -> None:
        value = request()
        protection.return_value = environment_protection()
        approval.return_value = environment_approval()
        decision.return_value = recorded_evidence(value)["decision"]
        candidate.return_value = (candidate_manifest(), recorded_evidence(value)["candidate"])
        conformance.return_value = recorded_evidence(value)["conformance"]
        continuity.return_value = recorded_evidence(value)["continuity"]
        backlog.return_value = recorded_evidence(value)["backlog"]
        evidence = build_evidence(
            mock.Mock(),
            value,
            qualification(),
            actor="release-operator",
            run_id=456,
            run_attempt=1,
            workflow_ref=AUTHORIZATION_WORKFLOW_REF,
            workflow_commit="6" * 40,
        )
        self.assertEqual(EVIDENCE_SCHEMA, evidence["schema"])
        stable.assert_called_once()
        qualified_heads.assert_called_once()
        self.assertEqual("release-reviewer", evidence["github_authority"]["environment_approval"]["user"]["login"])


class ImmutableAuthorizationRecordTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repository = self.root / "repository"
        self.remote = self.root / "remote.git"
        subprocess.run(["git", "init", "--bare", str(self.remote)], check=True, capture_output=True)
        subprocess.run(["git", "init", "-b", "main", str(self.repository)], check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=self.repository, check=True)
        subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=self.repository, check=True)
        (self.repository / "README.md").write_text("test\n", encoding="utf-8")
        subprocess.run(["git", "add", "README.md"], cwd=self.repository, check=True)
        subprocess.run(["git", "commit", "-m", "Initial"], cwd=self.repository, check=True, capture_output=True)
        subprocess.run(["git", "remote", "add", "origin", str(self.remote)], cwd=self.repository, check=True)
        subprocess.run(["git", "push", "origin", "main"], cwd=self.repository, check=True, capture_output=True)
        self.request = request()
        self.request_path = self.root / "request.json"
        self.request_path.write_bytes(canonical_json(self.request))
        self.authoritative = self.root / "authorization.json"
        self.evidence = self.root / "evidence.json"
        self.qualification_path = self.root / "qualification.json"
        self.qualification_path.write_bytes(canonical_json(qualification()))
        self.authoritative_qualification = self.root / "authoritative-qualification.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def record(self) -> dict[str, str]:
        return record_authorization(
            self.repository,
            self.request_path,
            qualification_path=self.qualification_path,
            remote="origin",
            authoritative_authorization=self.authoritative,
            authoritative_evidence=self.evidence,
            authoritative_qualification=self.authoritative_qualification,
            client=mock.Mock(),
            actor="release-operator",
            run_id=456,
            run_attempt=1,
            workflow_ref=AUTHORIZATION_WORKFLOW_REF,
            workflow_commit="6" * 40,
        )

    def replace_remote_record(
        self,
        evidence: dict[str, object],
        qualification_evidence: dict[str, object],
    ) -> None:
        for filename, value in (
            ("beta-authorization.json", self.request["authorization"]),
            ("beta-authorization-evidence.json", evidence),
            ("target-qualification-evidence.json", qualification_evidence),
        ):
            (self.repository / filename).write_bytes(canonical_json(value))
        subprocess.run(
            [
                "git",
                "add",
                "beta-authorization.json",
                "beta-authorization-evidence.json",
                "target-qualification-evidence.json",
            ],
            cwd=self.repository,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "Replace retained record"],
            cwd=self.repository,
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["git", "push", "--force", "origin", "HEAD:refs/tags/beta-authorization/first-beta"],
            cwd=self.repository,
            check=True,
            capture_output=True,
        )

    @mock.patch("scripts.beta_authorization.build_evidence")
    def test_identical_rerun_compares_without_revalidating_or_changing_record(self, build: mock.Mock) -> None:
        self.assertEqual(
            "new",
            check_authorization(self.repository, self.request_path, remote="origin")["status"],
        )
        build.return_value = recorded_evidence(self.request)
        created = self.record()
        self.assertEqual("created", created["status"])
        commit = created["commit"]

        build.side_effect = AssertionError("existing immutable authorization must not be rebuilt")
        self.qualification_path.unlink()
        existing = self.record()
        self.assertEqual("existing", existing["status"])
        self.assertEqual(commit, existing["commit"])
        self.assertEqual(canonical_json(self.request["authorization"]), self.authoritative.read_bytes())
        self.assertEqual(
            "existing",
            check_authorization(self.repository, self.request_path, remote="origin")["status"],
        )

    @mock.patch("scripts.beta_authorization.build_evidence")
    def test_identical_rerun_recovers_record_after_current_qualification_policy_changes(
        self,
        build: mock.Mock,
    ) -> None:
        original_qualification = qualification()
        original_evidence = recorded_evidence(self.request)
        build.return_value = original_evidence
        created = self.record()
        self.assertEqual("created", created["status"])

        self.authoritative.unlink()
        self.evidence.unlink()
        self.authoritative_qualification.unlink()
        self.qualification_path.unlink()
        build.side_effect = AssertionError("existing immutable authorization must not be rebuilt")

        policy_path = ROOT / "qualification" / "policy.json"
        changed_policy = json.loads(policy_path.read_bytes())
        changed_policy["targets"]["server"]["workflows"][0]["required_check"] = (
            "Future server qualification"
        )
        changed_policy_bytes = canonical_json(changed_policy)
        read_bytes = Path.read_bytes

        def read_with_changed_policy(path: Path) -> bytes:
            if path == policy_path:
                return changed_policy_bytes
            return read_bytes(path)

        with mock.patch.object(Path, "read_bytes", read_with_changed_policy):
            self.assertEqual(
                "existing",
                check_authorization(self.repository, self.request_path, remote="origin")["status"],
            )
            existing = self.record()

        self.assertEqual("existing", existing["status"])
        self.assertEqual(created["commit"], existing["commit"])
        self.assertEqual(canonical_json(self.request["authorization"]), self.authoritative.read_bytes())
        self.assertEqual(canonical_json(original_evidence), self.evidence.read_bytes())
        self.assertEqual(canonical_json(original_qualification), self.authoritative_qualification.read_bytes())

    @mock.patch("scripts.beta_authorization.build_evidence")
    def test_recovery_rejects_retained_checks_that_disagree_with_recorded_workflow(
        self,
        build: mock.Mock,
    ) -> None:
        retained_qualification = qualification()
        retained_evidence = recorded_evidence(self.request)
        build.return_value = retained_evidence
        self.record()

        retained_qualification["targets"]["server"]["protected_checks"] = ["Unrelated check"]
        retained_qualification["targets"]["server"]["successful_check_runs"] = {
            "Unrelated check": 999
        }
        retained_evidence["qualification"]["sha256"] = manifest_digest(retained_qualification)
        self.replace_remote_record(retained_evidence, retained_qualification)

        self.authoritative.unlink()
        self.evidence.unlink()
        self.authoritative_qualification.unlink()
        self.qualification_path.unlink()
        build.side_effect = AssertionError("existing immutable authorization must not be rebuilt")

        with self.assertRaisesRegex(CandidateError, "does not prove intended server source commit"):
            self.record()

        build.assert_called_once()
        self.assertFalse(self.authoritative.exists())
        self.assertFalse(self.evidence.exists())
        self.assertFalse(self.authoritative_qualification.exists())

    @mock.patch("scripts.beta_authorization.build_evidence")
    def test_new_authorization_remains_bound_to_current_qualification_policy(
        self,
        build: mock.Mock,
    ) -> None:
        policy_path = ROOT / "qualification" / "policy.json"
        changed_policy = json.loads(policy_path.read_bytes())
        changed_policy["targets"]["server"]["workflows"][0]["required_check"] = (
            "Future server qualification"
        )
        changed_policy_bytes = canonical_json(changed_policy)
        read_bytes = Path.read_bytes

        def read_with_changed_policy(path: Path) -> bytes:
            if path == policy_path:
                return changed_policy_bytes
            return read_bytes(path)

        with (
            mock.patch.object(Path, "read_bytes", read_with_changed_policy),
            self.assertRaisesRegex(CandidateError, "does not prove intended server source commit"),
        ):
            self.record()

        build.assert_not_called()
        refs = subprocess.run(
            ["git", "ls-remote", "--tags", str(self.remote)],
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        self.assertNotIn("beta-authorization/", refs)

    @mock.patch("scripts.beta_authorization.build_evidence")
    def test_changed_identity_is_rejected_and_first_validation_failure_does_not_publish(self, build: mock.Mock) -> None:
        build.side_effect = CandidateError("missing conformance evidence")
        with self.assertRaisesRegex(CandidateError, "missing conformance"):
            self.record()
        refs = subprocess.run(
            ["git", "ls-remote", "--tags", str(self.remote)],
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        self.assertNotIn("beta-authorization/", refs)

        build.side_effect = None
        build.return_value = recorded_evidence(self.request)
        self.record()
        changed = copy.deepcopy(self.request)
        changed["authorization"]["components"]["server"]["commit"] = "9" * 40
        self.request_path.write_bytes(canonical_json(changed))
        with self.assertRaisesRegex(CandidateError, "immutable and differs"):
            self.record()

    def test_occupied_conflicting_tag_fails_closed(self) -> None:
        subprocess.run(
            ["git", "push", "origin", "HEAD:refs/tags/beta-authorization/first-beta"],
            cwd=self.repository,
            check=True,
            capture_output=True,
        )
        with self.assertRaisesRegex(CandidateError, "missing beta-authorization.json"):
            self.record()

    def test_new_authorization_rejects_missing_fresh_qualification_before_publication(self) -> None:
        self.qualification_path.unlink()
        with self.assertRaisesRegex(CandidateError, "requires fresh target qualification"):
            self.record()
        refs = subprocess.run(
            ["git", "ls-remote", "--tags", str(self.remote)],
            text=True,
            capture_output=True,
            check=True,
        ).stdout
        self.assertNotIn("beta-authorization/", refs)


if __name__ == "__main__":
    unittest.main()
