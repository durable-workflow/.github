from __future__ import annotations

import copy
import hashlib
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.beta_candidate import CandidateError, canonical_json
from scripts.release_plan import (
    COMPONENTS,
    FOUNDATION_COMMIT,
    FOUNDATION_TAG,
    PLAN_TAG_PREFIX,
    SCHEMA,
    candidate_manifest,
    check_plan_compatibility,
    completion_manifest,
    is_immediate_version_successor,
    load_public_supersession,
    manifest_digest,
    parse_conflict_components,
    prepare_supersession,
    protected_environment_evidence,
    protected_run_approval_evidence,
    record_plan,
    record_supersession,
    require_prior_plans_completed,
    terminal_failure_state,
    validate_plan,
    validate_successor_transition,
    validate_supersession_record,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def cargo_manifest(version: str) -> bytes:
    return f'[package]\nname = "durable-workflow"\nversion = "{version}"\n'.encode()


def source_manifest_record(commit: str, version: str) -> dict[str, object]:
    raw = cargo_manifest(version)
    return {
        "declared_version": version,
        "package": "durable-workflow",
        "path": "Cargo.toml",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "source_commit": commit,
        "url": f"https://github.com/durable-workflow/sdk-rust/blob/{commit}/Cargo.toml",
    }


def release_plan(channel: str = "alpha") -> dict[str, object]:
    prerelease = "alpha" if channel == "alpha" else "beta"
    return {
        "schema": SCHEMA,
        "plan": "recovery-proof-1",
        "channel": channel,
        "foundation": {"tag": FOUNDATION_TAG, "commit": FOUNDATION_COMMIT},
        "components": {
            name: {
                "version": f"2.0.0-{prerelease}.{index + 1}" if name in {"workflow", "waterline"} else f"1.2.{index}",
                "commit": f"{index + 1:040x}",
            }
            for index, name in enumerate(COMPONENTS)
        },
        "beta_authorization": (
            {"tag": "beta-authorization/recovery-proof-1", "commit": "f" * 40} if channel == "beta" else None
        ),
    }


def successor_plan(
    failed: dict[str, object],
    *,
    component: str = "waterline",
    components: tuple[str, ...] | None = None,
) -> dict[str, object]:
    successor = copy.deepcopy(failed)
    successor["plan"] = "recovery-proof-2"
    for name in components or (component,):
        if name == "sdk-rust":
            successor["components"][name]["commit"] = "d" * 40
        else:
            version = successor["components"][name]["version"]
            prefix, number = version.rsplit(".", 1)
            successor["components"][name]["version"] = f"{prefix}.{int(number) + 1}"
    return successor


def environment_protection_evidence() -> dict[str, object]:
    return {
        "custom_branch_policies": [{"id": 23, "name": "main"}],
        "deployment_branch_policy": {
            "custom_branch_policies": True,
            "protected_branches": False,
        },
        "environment_id": 17,
        "environment_url": (
            "https://github.com/durable-workflow/.github/deployments/activity_log"
            "?environments_filter=release-plan-supersession"
        ),
        "required_reviewer_rule_ids": [19],
    }


def environment_approval_evidence() -> dict[str, object]:
    return {
        "comment": "Supersession reviewed",
        "environments": [
            {
                "html_url": (
                    "https://github.com/durable-workflow/.github/deployments/activity_log"
                    "?environments_filter=release-plan-supersession"
                ),
                "id": 17,
                "name": "release-plan-supersession",
                "node_id": "ENV_kwDOApproval",
                "url": (
                    "https://api.github.com/repos/durable-workflow/.github/environments/"
                    "release-plan-supersession"
                ),
            }
        ],
        "run_attempt": 1,
        "run_id": 456,
        "state": "approved",
        "user": {
            "html_url": "https://github.com/release-reviewer",
            "id": 29,
            "login": "release-reviewer",
            "node_id": "U_kgDOReviewer",
            "url": "https://api.github.com/users/release-reviewer",
        },
    }


def github_environment() -> dict[str, object]:
    return {
        "id": 17,
        "html_url": (
            "https://github.com/durable-workflow/.github/deployments/activity_log"
            "?environments_filter=release-plan-supersession"
        ),
        "protection_rules": [
            {"id": 19, "type": "required_reviewers", "reviewers": [{"type": "User"}]}
        ],
        "deployment_branch_policy": {
            "custom_branch_policies": True,
            "protected_branches": False,
        },
    }


def workflow_run() -> dict[str, object]:
    return {
        "actor": {"login": "release-operator"},
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": "f" * 40,
        "html_url": "https://github.com/durable-workflow/.github/actions/runs/456",
        "id": 456,
        "path": ".github/workflows/release-plan-supersession.yml@main",
        "repository": {"full_name": "durable-workflow/.github"},
        "run_attempt": 1,
    }


def approval_history() -> list[dict[str, object]]:
    approval = environment_approval_evidence()
    return [
        {
            "comment": approval["comment"],
            "environments": approval["environments"],
            "state": approval["state"],
            "user": approval["user"],
        }
    ]


def supersession_record(
    failed: dict[str, object],
    successor: dict[str, object],
    *,
    component: str = "waterline",
    failed_commit: str = "a" * 40,
) -> dict[str, object]:
    identity = failed["components"][component]
    observed_commit = "e" * 40
    return {
        "schema": "durable-workflow.release-plan-failure/v1",
        "outcome": "terminal-failure",
        "failed_plan": {
            "tag": f"{PLAN_TAG_PREFIX}{failed['plan']}",
            "commit": failed_commit,
            "sha256": manifest_digest(failed),
        },
        "conflicts": [
            {
                "component": component,
                "version": identity["version"],
                "planned_commit": identity["commit"],
                "observed_commit": observed_commit,
                "reason": "published-version-source-conflict",
                "github_release": {
                    "id": 123,
                    "url": "https://github.com/durable-workflow/waterline/releases/1",
                },
                "distribution": {
                    "kind": "composer",
                    "source_reference": observed_commit,
                    "dist_reference": observed_commit,
                },
            }
        ],
        "successor_plan": {
            "tag": f"{PLAN_TAG_PREFIX}{successor['plan']}",
            "sha256": manifest_digest(successor),
        },
        "authorization": {
            "actor": "release-operator",
            "environment": "release-plan-supersession",
            "environment_approval": environment_approval_evidence(),
            "environment_protection": environment_protection_evidence(),
            "repository": "durable-workflow/.github",
            "run_attempt": 1,
            "run_id": 456,
            "run_url": "https://github.com/durable-workflow/.github/actions/runs/456",
            "workflow_commit": "f" * 40,
            "workflow_ref": (
                "durable-workflow/.github/.github/workflows/"
                "release-plan-supersession.yml@refs/heads/main"
            ),
        },
    }


class ReleasePlanEntryPointTest(unittest.TestCase):
    def test_supersession_components_are_canonicalized_in_release_order(self) -> None:
        self.assertEqual(
            ["waterline", "sdk-rust"],
            parse_conflict_components("waterline, sdk-rust"),
        )
        with self.assertRaisesRegex(CandidateError, "release-plan component order"):
            parse_conflict_components("sdk-rust,waterline")

    def test_workflow_commands_are_directly_executable(self) -> None:
        for command in (
            "validate",
            "check",
            "preflight",
            "record",
            "prepare-supersession",
            "record-supersession",
            "discover",
            "observe",
            "complete",
        ):
            with self.subTest(command=command):
                process = subprocess.run(
                    [sys.executable, "scripts/release_plan.py", command, "--help"],
                    cwd=REPOSITORY_ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(0, process.returncode, process.stderr)

    def test_terminal_and_completion_writers_share_the_plan_registry_lock(self) -> None:
        for workflow in (
            "release-plan.yml",
            "release-plan-observer.yml",
            "release-plan-supersession.yml",
        ):
            source = (REPOSITORY_ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
            self.assertIn("concurrency:\n  group: release-plan-registry\n", source)
            self.assertIn("  actions: read\n", source)


class ReleasePlanValidationTest(unittest.TestCase):
    def test_alpha_plan_is_channel_bound(self) -> None:
        plan = release_plan()
        validate_plan(plan)
        candidate = candidate_manifest(plan)
        self.assertEqual("alpha-recovery-proof-1", candidate["candidate"])
        self.assertEqual(plan["components"], candidate["components"])
        completion = completion_manifest(plan, "a" * 40)
        self.assertEqual("alpha", completion["channel"])
        self.assertEqual("durable-workflow.release-candidate/v1", completion["schema"])

    def test_alpha_plan_rejects_beta_authorization(self) -> None:
        plan = release_plan()
        plan["beta_authorization"] = {"tag": "beta-authorization/recovery-proof-1", "commit": "f" * 40}
        with self.assertRaisesRegex(CandidateError, "must not claim beta authorization"):
            validate_plan(plan)

    def test_beta_plan_requires_exact_beta_versions_and_authorization(self) -> None:
        plan = release_plan("beta")
        validate_plan(plan)
        plan["components"]["workflow"]["version"] = "2.0.0-alpha.99"
        with self.assertRaisesRegex(CandidateError, "not an exact 2.0.0-beta.N identity"):
            validate_plan(plan)

    def test_plan_rejects_a_different_foundation(self) -> None:
        plan = release_plan()
        plan["foundation"]["commit"] = "0" * 40
        with self.assertRaisesRegex(CandidateError, "proven immutable candidate foundation"):
            validate_plan(plan)

    def test_new_plan_cannot_strand_an_interrupted_prior_plan(self) -> None:
        prior = release_plan()
        prior["plan"] = "plan-a"
        requested = release_plan()
        requested["plan"] = "plan-b"

        class FixtureClient:
            def json(self, _url: str) -> list[dict[str, str]]:
                return [{"ref": "refs/tags/release-plan/plan-a"}]

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=["a" * 40, None]),
            mock.patch("scripts.release_plan.read_public_record", return_value=prior),
            mock.patch("scripts.release_plan.load_public_supersession", return_value=None),
            self.assertRaisesRegex(CandidateError, "prior plan release-plan/plan-a is incomplete"),
        ):
            require_prior_plans_completed(requested, FixtureClient())

    def test_new_plan_checks_all_matching_refs_when_registry_exceeds_one_hundred(self) -> None:
        requested = release_plan()
        requested["plan"] = "plan-b"
        requested_urls: list[str] = []

        class FixtureClient:
            def json(self, url: str) -> list[dict[str, str]]:
                requested_urls.append(url)
                return [
                    *[
                        {"ref": f"refs/tags/release-plan/completed-{index:03d}"}
                        for index in range(125)
                    ],
                    {"ref": "refs/tags/release-plan/plan-a"},
                ]

        def plan_for_tag(tag: str) -> dict[str, object]:
            prior = release_plan()
            prior["plan"] = tag.removeprefix("release-plan/")
            return prior

        def resolve(_client: object, _repository: str, tag: str) -> str | None:
            if tag == "release-candidate/alpha/plan-a":
                return None
            return "b" * 40 if tag.startswith("release-candidate/") else "a" * 40

        def read_record(_client: object, tag: str, commit: str, _filename: str) -> dict[str, object]:
            if tag.startswith("release-plan/"):
                return plan_for_tag(tag)
            plan_tag = tag.removeprefix("release-candidate/alpha/")
            return completion_manifest(plan_for_tag(f"release-plan/{plan_tag}"), "a" * 40)

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", side_effect=read_record),
            mock.patch("scripts.release_plan.load_public_supersession", return_value=None),
            self.assertRaisesRegex(CandidateError, "prior plan release-plan/plan-a is incomplete"),
        ):
            require_prior_plans_completed(requested, FixtureClient())

        self.assertEqual(
            [
                "https://api.github.com/repos/durable-workflow/.github/"
                "git/matching-refs/tags/release-plan/"
            ],
            requested_urls,
        )

    def test_completed_prior_plan_allows_the_next_plan(self) -> None:
        prior = release_plan()
        prior["plan"] = "plan-a"
        requested = release_plan()
        requested["plan"] = "plan-b"
        record_commit = "a" * 40
        completed_commit = "b" * 40
        completion = completion_manifest(prior, record_commit)

        class FixtureClient:
            def json(self, _url: str) -> list[dict[str, str]]:
                return [{"ref": "refs/tags/release-plan/plan-a"}]

        with (
            mock.patch(
                "scripts.release_plan.resolve_tag",
                side_effect=[record_commit, completed_commit],
            ),
            mock.patch(
                "scripts.release_plan.read_public_record",
                side_effect=[prior, completion],
            ),
            mock.patch("scripts.release_plan.load_public_supersession", return_value=None),
        ):
            evidence = require_prior_plans_completed(requested, FixtureClient())
        self.assertEqual(completed_commit, evidence["release-plan/plan-a"]["completion_commit"])

    def test_terminal_failure_admits_only_the_exact_immediate_successor(self) -> None:
        failed = release_plan()
        failed["plan"] = "plan-a"
        successor = successor_plan(failed)
        successor["plan"] = "plan-b"
        record_commit = "a" * 40
        failure = supersession_record(failed, successor, failed_commit=record_commit)

        class FixtureClient:
            def json(self, _url: str) -> list[dict[str, str]]:
                return [{"ref": "refs/tags/release-plan/plan-a"}]

        terminal = ("release-plan-failure/plan-a", "b" * 40, failure, successor)
        with (
            mock.patch(
                "scripts.release_plan.resolve_tag",
                side_effect=[record_commit, None, None],
            ),
            mock.patch("scripts.release_plan.read_public_record", return_value=failed),
            mock.patch("scripts.release_plan.load_public_supersession", return_value=terminal),
        ):
            evidence = require_prior_plans_completed(successor, FixtureClient())
        self.assertEqual("terminal-failure", evidence["release-plan/plan-a"]["outcome"])

        different = copy.deepcopy(successor)
        different["components"]["server"]["commit"] = "d" * 40
        with (
            mock.patch(
                "scripts.release_plan.resolve_tag",
                side_effect=[record_commit, None, None],
            ),
            mock.patch("scripts.release_plan.read_public_record", return_value=failed),
            mock.patch("scripts.release_plan.load_public_supersession", return_value=terminal),
            self.assertRaisesRegex(CandidateError, "admits only exact successor"),
        ):
            require_prior_plans_completed(different, FixtureClient())

    def test_successor_rejects_skipped_versions_and_unaffected_changes(self) -> None:
        failed = release_plan()
        successor = successor_plan(failed)
        validate_successor_transition(failed, successor, "waterline")
        self.assertTrue(is_immediate_version_successor("2.0.0-alpha.135", "2.0.0-alpha.136"))

        skipped = copy.deepcopy(successor)
        skipped["components"]["waterline"]["version"] = "2.0.0-alpha.4"
        with self.assertRaisesRegex(CandidateError, "immediate next"):
            validate_successor_transition(failed, skipped, "waterline")

        changed = copy.deepcopy(successor)
        changed["components"]["server"]["commit"] = "d" * 40
        with self.assertRaisesRegex(CandidateError, "unaffected component server"):
            validate_successor_transition(failed, changed, "waterline")

    def test_terminal_record_rejects_mutated_evidence(self) -> None:
        failed = release_plan()
        successor = successor_plan(failed)
        record = supersession_record(failed, successor)
        validate_supersession_record(record, failed, "a" * 40, successor)

        record["conflicts"][0]["observed_commit"] = "d" * 40
        with self.assertRaisesRegex(CandidateError, "distribution evidence"):
            validate_supersession_record(record, failed, "a" * 40, successor)

    def test_terminal_record_accepts_github_environment_activity_url(self) -> None:
        failed = release_plan()
        successor = successor_plan(failed)
        record = supersession_record(failed, successor)

        self.assertEqual(
            "https://github.com/durable-workflow/.github/deployments/activity_log"
            "?environments_filter=release-plan-supersession",
            record["authorization"]["environment_protection"]["environment_url"],
        )
        validate_supersession_record(record, failed, "a" * 40, successor)

        record["authorization"]["environment_protection"]["environment_url"] = (
            "https://github.com/durable-workflow/.github/settings/environments/1"
        )
        with self.assertRaisesRegex(CandidateError, "protected-environment reviewer evidence"):
            validate_supersession_record(record, failed, "a" * 40, successor)

    def test_terminal_record_rejects_unbound_or_malformed_approval_evidence(self) -> None:
        failed = release_plan()
        successor = successor_plan(failed)

        mutations = (
            (
                "wrong run",
                lambda record: record["authorization"]["environment_approval"].update({"run_id": 999}),
                "approved deployment bound",
            ),
            (
                "wrong environment",
                lambda record: record["authorization"]["environment_approval"]["environments"][0].update(
                    {"name": "staging"}
                ),
                "wrong protected environment",
            ),
            (
                "malformed user",
                lambda record: record["authorization"]["environment_approval"]["user"].pop("node_id"),
                "approving user evidence",
            ),
        )
        for name, mutate, error in mutations:
            with self.subTest(name=name):
                record = supersession_record(failed, successor)
                mutate(record)
                with self.assertRaisesRegex(CandidateError, error):
                    validate_supersession_record(record, failed, "a" * 40, successor)

    def test_loading_terminal_record_revalidates_live_policy_and_approval(self) -> None:
        failed = release_plan()
        successor = successor_plan(failed)
        record = supersession_record(failed, successor)
        resolved = ["b" * 40, "e" * 40]

        changed_policy = environment_protection_evidence()
        changed_policy["custom_branch_policies"] = [{"id": 24, "name": "main"}]
        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolved),
            mock.patch("scripts.release_plan.read_public_record", side_effect=[record, successor]),
            mock.patch("scripts.release_plan.protected_environment_evidence", return_value=changed_policy),
            self.assertRaisesRegex(CandidateError, "policy no longer matches"),
        ):
            load_public_supersession(failed, "a" * 40, object())

        changed_approval = environment_approval_evidence()
        changed_approval["user"] = {
            "html_url": "https://github.com/other-reviewer",
            "id": 30,
            "login": "other-reviewer",
            "node_id": "U_kgDOOtherReviewer",
            "url": "https://api.github.com/users/other-reviewer",
        }
        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=["b" * 40, "e" * 40]),
            mock.patch("scripts.release_plan.read_public_record", side_effect=[record, successor]),
            mock.patch(
                "scripts.release_plan.protected_environment_evidence",
                return_value=environment_protection_evidence(),
            ),
            mock.patch("scripts.release_plan.protected_run_approval_evidence", return_value=changed_approval),
            self.assertRaisesRegex(CandidateError, "approved deployment evidence no longer matches"),
        ):
            load_public_supersession(failed, "a" * 40, object())

    def test_terminal_record_rejects_a_moved_public_source_tag(self) -> None:
        failed = release_plan()
        successor = successor_plan(failed)
        record = supersession_record(failed, successor)
        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=["b" * 40, "d" * 40]),
            mock.patch(
                "scripts.release_plan.read_public_record",
                side_effect=[record, successor],
            ),
            self.assertRaisesRegex(CandidateError, "source tag .* moved"),
        ):
            load_public_supersession(failed, "a" * 40, object())

    def test_terminal_record_rejects_fabricated_protected_run_evidence(self) -> None:
        failed = release_plan()
        successor = successor_plan(failed)
        record = supersession_record(failed, successor)

        class FixtureClient:
            def json(self, url: str, **_kwargs: object) -> object:
                if url.endswith("deployment-branch-policies?per_page=100"):
                    return {
                        "total_count": 1,
                        "branch_policies": [{"id": 23, "name": "main", "type": "branch"}],
                    }
                if "/environments/" in url:
                    return github_environment()
                if url.endswith("/approvals"):
                    return approval_history()
                run = workflow_run()
                run["actor"] = {"login": "different-actor"}
                return run

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=["b" * 40, "e" * 40]),
            mock.patch(
                "scripts.release_plan.read_public_record",
                side_effect=[record, successor],
            ),
            self.assertRaisesRegex(CandidateError, "workflow run evidence does not match"),
        ):
            load_public_supersession(failed, "a" * 40, FixtureClient())


class ReleasePlanSupersessionTest(unittest.TestCase):
    def test_environment_requires_custom_main_branch_policy(self) -> None:
        def evidence(environment: object, policies: object) -> dict[str, object]:
            class FixtureClient:
                def json(_client, url: str, **kwargs: object) -> object:
                    self.assertEqual(
                        {"X-GitHub-Api-Version": "2026-03-10"},
                        kwargs.get("headers"),
                    )
                    if url.endswith("deployment-branch-policies?per_page=100"):
                        return policies
                    return environment

            return protected_environment_evidence(FixtureClient())

        environment = github_environment()
        policies = {
            "total_count": 1,
            "branch_policies": [{"id": 23, "name": "main", "type": "branch"}],
        }
        self.assertEqual(environment_protection_evidence(), evidence(environment, policies))

        disabled = copy.deepcopy(environment)
        disabled["deployment_branch_policy"] = {
            "custom_branch_policies": False,
            "protected_branches": True,
        }
        with self.assertRaisesRegex(CandidateError, "enable custom branch policies"):
            evidence(disabled, policies)

        wrong_policy = {
            "total_count": 1,
            "branch_policies": [{"id": 23, "name": "release/*", "type": "branch"}],
        }
        with self.assertRaisesRegex(CandidateError, "allow only the main branch"):
            evidence(environment, wrong_policy)

        extra_policy = {
            "total_count": 2,
            "branch_policies": [
                {"id": 23, "name": "main", "type": "branch"},
                {"id": 24, "name": "release/*", "type": "branch"},
            ],
        }
        with self.assertRaisesRegex(CandidateError, "allow only the main branch"):
            evidence(environment, extra_policy)

    def test_approval_history_rejects_absent_rejected_wrong_environment_wrong_run_and_malformed(self) -> None:
        def evidence(run: object, history: object) -> dict[str, object]:
            class FixtureClient:
                def json(_client, url: str, **kwargs: object) -> object:
                    self.assertEqual(
                        {"X-GitHub-Api-Version": "2026-03-10"},
                        kwargs.get("headers"),
                    )
                    return history if url.endswith("/approvals") else run

            return protected_run_approval_evidence(
                FixtureClient(),
                actor="release-operator",
                run_id=456,
                run_attempt=1,
                workflow_commit="f" * 40,
                environment_protection=environment_protection_evidence(),
            )

        self.assertEqual(environment_approval_evidence(), evidence(workflow_run(), approval_history()))

        rejected = approval_history()
        rejected[0]["state"] = "rejected"
        wrong_environment = approval_history()
        wrong_environment[0]["environments"][0]["name"] = "staging"
        wrong_run = workflow_run()
        wrong_run["id"] = 999
        malformed = approval_history()
        malformed[0]["environments"] = "release-plan-supersession"

        failures = (
            ("absent", workflow_run(), [], "exactly one approved review"),
            ("rejected", workflow_run(), rejected, "exactly one approved review"),
            ("wrong environment", workflow_run(), wrong_environment, "wrong protected environment"),
            ("wrong run", wrong_run, approval_history(), "workflow run evidence does not match"),
            ("malformed", workflow_run(), malformed, "approval history is malformed"),
        )
        for name, run, history, error in failures:
            with self.subTest(name=name), self.assertRaisesRegex(CandidateError, error):
                evidence(run, history)

        self.assertEqual(
            ".github/workflows/release-plan-supersession.yml@main",
            workflow_run()["path"],
        )
        for path in (
            ".github/workflows/release-plan-supersession.yml@v2",
            ".github/workflows/release-plan.yml@main",
        ):
            run = workflow_run()
            run["path"] = path
            with self.subTest(path=path), self.assertRaisesRegex(
                CandidateError, "workflow run evidence does not match"
            ):
                evidence(run, approval_history())

    def test_prepare_proves_real_public_conflict_and_protected_run(self) -> None:
        failed = release_plan()
        failed["plan"] = "plan-a"
        successor = successor_plan(failed)
        successor["plan"] = "plan-b"
        failed_commit = "a" * 40
        observed_commit = "e" * 40

        class FixtureClient:
            def bytes(self, _url: str, **_kwargs: object) -> bytes:
                return cargo_manifest(failed["components"]["sdk-rust"]["version"])

            def json(self, url: str, **_kwargs: object) -> object:
                if url.endswith("deployment-branch-policies?per_page=100"):
                    return {
                        "total_count": 1,
                        "branch_policies": [{"id": 23, "name": "main", "type": "branch"}],
                    }
                if "/environments/" in url:
                    return github_environment()
                if url.endswith("/approvals"):
                    return approval_history()
                if "/actions/runs/" in url:
                    return workflow_run()
                return {
                    "id": 123,
                    "tag_name": failed["components"]["waterline"]["version"],
                    "draft": False,
                    "html_url": "https://github.com/durable-workflow/waterline/releases/1",
                }

        def resolve(_client: object, repository: str, tag: str) -> str | None:
            if repository == "durable-workflow/.github" and tag == "release-plan/plan-a":
                return failed_commit
            if (
                repository == "durable-workflow/waterline"
                and tag == failed["components"]["waterline"]["version"]
            ):
                return observed_commit
            return None

        distribution = {
            "kind": "composer",
            "source_reference": observed_commit,
            "dist_reference": observed_commit,
        }
        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", return_value=failed),
            mock.patch(
                "scripts.release_plan.resolve_github_tag",
                return_value={"commit": observed_commit},
            ),
            mock.patch.dict(
                "scripts.release_plan.VERIFIERS",
                {"composer": mock.Mock(return_value=distribution)},
            ),
        ):
            record, durable_successor = prepare_supersession(
                "release-plan/plan-a",
                "waterline",
                successor,
                FixtureClient(),
                actor="release-operator",
                run_id="456",
                run_attempt="1",
                workflow_ref=(
                    "durable-workflow/.github/.github/workflows/"
                    "release-plan-supersession.yml@refs/heads/main"
                ),
                workflow_commit="f" * 40,
            )

        self.assertEqual(observed_commit, record["conflicts"][0]["observed_commit"])
        self.assertEqual(manifest_digest(successor), record["successor_plan"]["sha256"])
        self.assertEqual([19], record["authorization"]["environment_protection"]["required_reviewer_rule_ids"])
        self.assertEqual(
            [{"id": 23, "name": "main"}],
            record["authorization"]["environment_protection"]["custom_branch_policies"],
        )
        self.assertEqual(
            "release-reviewer",
            record["authorization"]["environment_approval"]["user"]["login"],
        )
        self.assertEqual(
            "https://github.com/durable-workflow/.github/deployments/activity_log"
            "?environments_filter=release-plan-supersession",
            record["authorization"]["environment_protection"]["environment_url"],
        )
        self.assertEqual(successor, durable_successor)

    def test_prepare_retains_public_tag_and_source_manifest_conflicts(self) -> None:
        failed = release_plan()
        failed["plan"] = "plan-a"
        failed["components"]["sdk-rust"] = {
            "version": "0.1.16",
            "commit": "dde751dc45366beaf8a829ed42c7ab92d0aad775",
        }
        successor = successor_plan(failed, components=("waterline", "sdk-rust"))
        successor["plan"] = "plan-b"
        successor["components"]["sdk-rust"]["commit"] = (
            "2e09d42d8380bd0a2c8145dfeabd9d6294a8e8e1"
        )
        failed_commit = "a" * 40
        observed_commit = "e" * 40

        class FixtureClient:
            def bytes(self, url: str, **_kwargs: object) -> bytes:
                if failed["components"]["sdk-rust"]["commit"] in url:
                    return cargo_manifest("0.1.15")
                if successor["components"]["sdk-rust"]["commit"] in url:
                    return cargo_manifest("0.1.16")
                raise AssertionError(f"unexpected source manifest request: {url}")

            def json(self, url: str, **_kwargs: object) -> object:
                if url.endswith("deployment-branch-policies?per_page=100"):
                    return {
                        "total_count": 1,
                        "branch_policies": [{"id": 23, "name": "main", "type": "branch"}],
                    }
                if "/environments/" in url:
                    return github_environment()
                if url.endswith("/approvals"):
                    return approval_history()
                if "/actions/runs/" in url:
                    return workflow_run()
                return {
                    "id": 123,
                    "tag_name": failed["components"]["waterline"]["version"],
                    "draft": False,
                    "html_url": "https://github.com/durable-workflow/waterline/releases/1",
                }

        def resolve(_client: object, repository: str, tag: str) -> str | None:
            if repository == "durable-workflow/.github" and tag == "release-plan/plan-a":
                return failed_commit
            if (
                repository == "durable-workflow/waterline"
                and tag == failed["components"]["waterline"]["version"]
            ):
                return observed_commit
            return None

        distribution = {
            "kind": "composer",
            "source_reference": observed_commit,
            "dist_reference": observed_commit,
        }
        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", return_value=failed),
            mock.patch(
                "scripts.release_plan.resolve_github_tag",
                return_value={"commit": observed_commit},
            ),
            mock.patch.dict(
                "scripts.release_plan.VERIFIERS",
                {"composer": mock.Mock(return_value=distribution)},
            ),
        ):
            record, durable_successor = prepare_supersession(
                "release-plan/plan-a",
                ["waterline", "sdk-rust"],
                successor,
                FixtureClient(),
                actor="release-operator",
                run_id="456",
                run_attempt="1",
                workflow_ref=(
                    "durable-workflow/.github/.github/workflows/"
                    "release-plan-supersession.yml@refs/heads/main"
                ),
                workflow_commit="f" * 40,
            )

        self.assertEqual(
            ["waterline", "sdk-rust"],
            [conflict["component"] for conflict in record["conflicts"]],
        )
        self.assertEqual(
            ["published-version-source-conflict", "source-manifest-version-conflict"],
            [conflict["reason"] for conflict in record["conflicts"]],
        )
        rust_conflict = record["conflicts"][1]
        self.assertEqual("0.1.15", rust_conflict["source_manifest"]["declared_version"])
        self.assertEqual(
            "0.1.16",
            rust_conflict["successor_source_manifest"]["declared_version"],
        )
        self.assertEqual(successor, durable_successor)
        validate_supersession_record(record, failed, failed_commit, successor)

        unresolved = copy.deepcopy(successor)
        unresolved["components"]["sdk-rust"] = copy.deepcopy(failed["components"]["sdk-rust"])
        with self.assertRaisesRegex(CandidateError, "leaves conflict unresolved for sdk-rust"):
            validate_successor_transition(failed, unresolved, record["conflicts"])

        changed_unaffected = copy.deepcopy(successor)
        changed_unaffected["components"]["server"]["commit"] = "9" * 40
        with self.assertRaisesRegex(CandidateError, "unaffected component server"):
            validate_successor_transition(failed, changed_unaffected, record["conflicts"])

        mismatched_successor = copy.deepcopy(record)
        mismatched_successor["conflicts"][1]["successor_source_manifest"] = source_manifest_record(
            successor["components"]["sdk-rust"]["commit"], "0.1.15"
        )
        with self.assertRaisesRegex(CandidateError, "does not match sdk-rust version allocation"):
            validate_supersession_record(
                mismatched_successor,
                failed,
                failed_commit,
                successor,
            )

        terminal = ("release-plan-failure/plan-a", "b" * 40, record, successor)
        with (
            mock.patch("scripts.release_plan.resolve_tag", return_value=failed_commit),
            mock.patch("scripts.release_plan.load_public_supersession", return_value=terminal),
        ):
            state = terminal_failure_state(failed, object())
        self.assertEqual(["waterline", "sdk-rust"], state["failed_components"])
        self.assertEqual(record["conflicts"], state["conflicts"])
        self.assertIn("source manifest declares 0.1.15", state["reason"])

    def test_prepare_rejects_omitted_source_manifest_conflict(self) -> None:
        failed = release_plan()
        failed["plan"] = "plan-a"
        failed["components"]["sdk-rust"] = {
            "version": "0.1.16",
            "commit": "dde751dc45366beaf8a829ed42c7ab92d0aad775",
        }
        successor = successor_plan(failed)

        class FixtureClient:
            def bytes(self, _url: str, **_kwargs: object) -> bytes:
                return cargo_manifest("0.1.15")

        def resolve(_client: object, repository: str, tag: str) -> str | None:
            if repository == "durable-workflow/.github" and tag == "release-plan/plan-a":
                return "a" * 40
            return None

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", return_value=failed),
            self.assertRaisesRegex(CandidateError, "omit independently proven.*sdk-rust"),
        ):
            prepare_supersession(
                "release-plan/plan-a",
                ["waterline"],
                successor,
                FixtureClient(),
                actor="release-operator",
                run_id="456",
                run_attempt="1",
                workflow_ref=(
                    "durable-workflow/.github/.github/workflows/"
                    "release-plan-supersession.yml@refs/heads/main"
                ),
                workflow_commit="f" * 40,
            )

    def test_prepare_rejects_omitted_public_tag_conflict(self) -> None:
        failed = release_plan()
        failed["plan"] = "plan-a"
        failed["components"]["sdk-rust"] = {
            "version": "0.1.16",
            "commit": "dde751dc45366beaf8a829ed42c7ab92d0aad775",
        }
        successor = successor_plan(failed, component="sdk-rust")
        successor["components"]["sdk-rust"]["commit"] = (
            "2e09d42d8380bd0a2c8145dfeabd9d6294a8e8e1"
        )
        failed_commit = "a" * 40
        observed_waterline_commit = "e" * 40

        class FixtureClient:
            def bytes(self, _url: str, **_kwargs: object) -> bytes:
                return cargo_manifest("0.1.15")

        def resolve(_client: object, repository: str, tag: str) -> str | None:
            if repository == "durable-workflow/.github" and tag == "release-plan/plan-a":
                return failed_commit
            if (
                repository == "durable-workflow/waterline"
                and tag == failed["components"]["waterline"]["version"]
            ):
                return observed_waterline_commit
            return None

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", return_value=failed),
            self.assertRaisesRegex(CandidateError, "omit independently proven.*waterline"),
        ):
            prepare_supersession(
                "release-plan/plan-a",
                ["sdk-rust"],
                successor,
                FixtureClient(),
                actor="release-operator",
                run_id="456",
                run_attempt="1",
                workflow_ref=(
                    "durable-workflow/.github/.github/workflows/"
                    "release-plan-supersession.yml@refs/heads/main"
                ),
                workflow_commit="f" * 40,
            )

    def test_observer_classifies_terminal_conflict_and_exact_recovery(self) -> None:
        failed = release_plan()
        failed["plan"] = "plan-a"
        successor = successor_plan(failed)
        successor["plan"] = "plan-b"
        failure = supersession_record(failed, successor)
        terminal = ("release-plan-failure/plan-a", "b" * 40, failure, successor)
        with (
            mock.patch("scripts.release_plan.resolve_tag", return_value="a" * 40),
            mock.patch("scripts.release_plan.load_public_supersession", return_value=terminal),
        ):
            state = terminal_failure_state(failed, object())

        self.assertEqual("terminal-failure", state["phase"])
        self.assertEqual("superseded", state["outcome"])
        self.assertEqual(["waterline"], state["failed_components"])
        self.assertIn("release-plan/plan-b", state["resume_action"])
        self.assertIn(manifest_digest(successor), state["resume_action"])


class ReleasePlanRecordTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.repository = root / "work"
        self.remote = root / "remote.git"
        subprocess.run(["git", "init", "--bare", str(self.remote)], check=True, capture_output=True)
        subprocess.run(["git", "init", str(self.repository)], check=True, capture_output=True)
        self.plan_path = root / "release-plan.json"
        self.authoritative_path = root / "authoritative-release-plan.json"
        self.failure_path = root / "release-plan-failure.json"
        self.successor_path = root / "successor-release-plan.json"
        self.authoritative_failure_path = root / "authoritative-release-plan-failure.json"
        self.authoritative_successor_path = root / "authoritative-successor-release-plan.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_plan(self, plan: dict[str, object]) -> None:
        self.plan_path.write_bytes(canonical_json(plan))

    def test_first_record_and_identical_recovery_keep_one_commit(self) -> None:
        plan = release_plan()
        self.write_plan(plan)
        created = record_plan(
            self.repository,
            self.plan_path,
            remote=str(self.remote),
            authoritative_plan=self.authoritative_path,
        )
        repeated = record_plan(
            self.repository,
            self.plan_path,
            remote=str(self.remote),
            authoritative_plan=self.authoritative_path,
        )
        self.assertEqual("created", created["status"])
        self.assertEqual("existing", repeated["status"])
        self.assertEqual(created["commit"], repeated["commit"])
        files = subprocess.run(
            ["git", "--git-dir", str(self.remote), "ls-tree", "-r", "--name-only", created["commit"]],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.splitlines()
        self.assertEqual(["release-plan.json"], files)
        self.assertEqual(canonical_json(plan), self.authoritative_path.read_bytes())

    def test_existing_plan_rejects_tuple_mutation(self) -> None:
        plan = release_plan()
        self.write_plan(plan)
        record_plan(
            self.repository,
            self.plan_path,
            remote=str(self.remote),
            authoritative_plan=self.authoritative_path,
        )
        changed = copy.deepcopy(plan)
        changed["components"]["server"]["commit"] = "e" * 40
        self.write_plan(changed)
        with self.assertRaisesRegex(CandidateError, "immutable"):
            check_plan_compatibility(self.repository, self.plan_path, remote=str(self.remote))

    def test_terminal_record_and_successor_are_idempotently_immutable(self) -> None:
        failed = release_plan()
        successor = successor_plan(failed)
        record = supersession_record(failed, successor)
        self.failure_path.write_bytes(canonical_json(record))
        self.successor_path.write_bytes(canonical_json(successor))

        def resolve(_client: object, _repository: str, tag: str) -> str | None:
            return "a" * 40 if tag == record["failed_plan"]["tag"] else None

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", return_value=failed),
        ):
            created = record_supersession(
                self.repository,
                self.failure_path,
                self.successor_path,
                remote=str(self.remote),
                authoritative_record=self.authoritative_failure_path,
                authoritative_successor=self.authoritative_successor_path,
                client=object(),
            )
            repeated = record_supersession(
                self.repository,
                self.failure_path,
                self.successor_path,
                remote=str(self.remote),
                authoritative_record=self.authoritative_failure_path,
                authoritative_successor=self.authoritative_successor_path,
                client=object(),
            )

        self.assertEqual("created", created["status"])
        self.assertEqual("existing", repeated["status"])
        self.assertEqual(created["commit"], repeated["commit"])
        files = subprocess.run(
            ["git", "--git-dir", str(self.remote), "ls-tree", "-r", "--name-only", created["commit"]],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.splitlines()
        self.assertEqual(["release-plan-failure.json", "successor-release-plan.json"], files)


if __name__ == "__main__":
    unittest.main()
