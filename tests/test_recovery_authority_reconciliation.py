from __future__ import annotations

import copy
import unittest
from collections.abc import Mapping

from scripts.beta_candidate import canonical_json
from scripts.recovery_authority_reconciliation import reconcile_authority
from scripts.recovery_workflow_authority import (
    AUTHORITY_PATH,
    CONTROL_REPOSITORY,
    SOURCE_IDENTITIES_PATH,
    SOURCE_IDENTITIES_SCHEMA,
    RecoveryWorkflowAuthorityError,
    authority_ref_url,
    branch_url,
    check_run_url,
    compare_url,
    exact_source_sha256,
    qualification_policy_binding,
    qualification_policy_url,
    workflow_metadata_url,
    workflow_run_url,
    workflow_source_url,
)

REPOSITORY = "durable-workflow/waterline"
BRANCH = "v2"
PATH = ".github/workflows/release-plan-recovery.yml"
POLICY_A_WORKFLOW = ".github/workflows/php.yml"
POLICY_A_CHECK = "Target branch qualification"
POLICY_B_WORKFLOW = ".github/workflows/source-qualification.yml"
POLICY_B_CHECK = "Source qualification"
OLD_COMMIT = "1" * 40
NEW_COMMIT = "2" * 40
POLICY_A_COMMIT = "a" * 40
POLICY_B_COMMIT = "b" * 40
CONTROL_HEAD = "f" * 40
OLD_SOURCE = b"name: Recovery\non:\n  workflow_dispatch:\n"
NEW_SOURCE = OLD_SOURCE + b"# successor\n"


def requirement(workflow: str, required_check: str) -> dict[str, str]:
    return {"workflow": workflow, "required_check": required_check}


POLICY_A_REQUIREMENT = requirement(POLICY_A_WORKFLOW, POLICY_A_CHECK)
POLICY_B_REQUIREMENT = requirement(POLICY_B_WORKFLOW, POLICY_B_CHECK)


def qualification(
    commit: str,
    run_id: int,
    check_run_id: int,
    protected_requirement: Mapping[str, str] = POLICY_A_REQUIREMENT,
) -> dict[str, object]:
    return {
        "check_run_id": check_run_id,
        "check_url": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/job/{check_run_id}",
        "conclusion": "success",
        "event": "push",
        "head_branch": BRANCH,
        "head_sha": commit,
        "required_check": protected_requirement["required_check"],
        "run_attempt": 1,
        "run_id": run_id,
        "status": "completed",
        "url": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
        "workflow": protected_requirement["workflow"],
    }


def authority() -> dict[str, object]:
    return {
        "schema": "durable-workflow.component-release-recovery-authority/v2",
        "source": {
            "repository": CONTROL_REPOSITORY,
            "ref": "refs/heads/main",
            "path": AUTHORITY_PATH,
            "qualification": {
                "workflow": ".github/workflows/beta-candidate.yml",
                "event": "push",
            },
        },
        "workflows": {
            "waterline": {
                "repository": REPOSITORY,
                "ref": f"refs/heads/{BRANCH}",
                "path": PATH,
                "state": "active",
                "sha256": exact_source_sha256(OLD_SOURCE),
            }
        },
    }


def policy(protected_requirement: Mapping[str, str] = POLICY_A_REQUIREMENT) -> dict[str, object]:
    return {
        "organization": "durable-workflow",
        "targets": {
            "waterline": {
                "repository": "waterline",
                "branch": BRANCH,
                "workflows": [
                    {
                        "path": protected_requirement["workflow"].removeprefix(".github/workflows/"),
                        "required_check": protected_requirement["required_check"],
                    }
                ],
            }
        },
    }


def policy_binding(
    value: dict[str, object],
    commit: str,
) -> dict[str, str]:
    return qualification_policy_binding(canonical_json(value), commit)


def source_identities() -> dict[str, object]:
    policy_a = policy()
    return {
        "schema": SOURCE_IDENTITIES_SCHEMA,
        "source": {
            "repository": CONTROL_REPOSITORY,
            "ref": "refs/heads/main",
            "authority_path": AUTHORITY_PATH,
            "path": SOURCE_IDENTITIES_PATH,
        },
        "workflows": {
            "waterline": {
                "repository": REPOSITORY,
                "ref": f"refs/heads/{BRANCH}",
                "path": PATH,
                "state": "active",
                "identities": [
                    {
                        "source_commit": OLD_COMMIT,
                        "sha256": exact_source_sha256(OLD_SOURCE),
                        "qualification": qualification(OLD_COMMIT, 101, 201),
                        "qualification_policy": policy_binding(policy_a, POLICY_A_COMMIT),
                    }
                ],
            }
        },
    }


class FixtureClient:
    def __init__(
        self,
        *,
        head: str,
        current_policy: dict[str, object] | None = None,
        current_policy_commit: str = POLICY_A_COMMIT,
        successor_requirement: Mapping[str, str] | None = None,
        qualified: bool = True,
        run_branch: str = BRANCH,
    ) -> None:
        self.head = head
        self.qualified = qualified
        self.run_branch = run_branch
        self.current_policy = current_policy or policy()
        self.current_policy_commit = current_policy_commit
        self.sources = {OLD_COMMIT: OLD_SOURCE, NEW_COMMIT: NEW_SOURCE}
        self.identities = {
            OLD_COMMIT: (101, 201, POLICY_A_REQUIREMENT),
            NEW_COMMIT: (
                102,
                202,
                successor_requirement
                or next(iter(self.current_policy["targets"]["waterline"]["workflows"])),
            ),
        }
        self.policies = {
            POLICY_A_COMMIT: canonical_json(policy()),
            current_policy_commit: canonical_json(self.current_policy),
        }

    @staticmethod
    def _normalized_requirement(value: Mapping[str, object]) -> dict[str, str]:
        workflow = str(value["path"]) if "path" in value else str(value["workflow"])
        return {
            "workflow": (
                workflow if workflow.startswith(".github/workflows/") else f".github/workflows/{workflow}"
            ),
            "required_check": str(value["required_check"]),
        }

    def json(self, url: str) -> dict[str, object]:
        if url == authority_ref_url():
            return {"sha": CONTROL_HEAD}
        if url == branch_url(REPOSITORY, BRANCH):
            return {"commit": {"sha": self.head}}
        if url == workflow_metadata_url(REPOSITORY, PATH):
            return {"id": 71, "path": PATH, "state": "active"}
        for policy_commit in self.policies:
            if url == compare_url(CONTROL_REPOSITORY, policy_commit, CONTROL_HEAD):
                return {
                    "status": "ahead",
                    "base_commit": {"sha": policy_commit},
                    "merge_base_commit": {"sha": policy_commit},
                }
        unresolved_policy_commit = "c" * 40
        if url == compare_url(CONTROL_REPOSITORY, unresolved_policy_commit, CONTROL_HEAD):
            return {
                "status": "ahead",
                "base_commit": {"sha": unresolved_policy_commit},
                "merge_base_commit": {"sha": unresolved_policy_commit},
            }
        for commit, (run_id, check_run_id, raw_requirement) in self.identities.items():
            protected_requirement = self._normalized_requirement(raw_requirement)
            if url == workflow_run_url(REPOSITORY, run_id):
                return {
                    "id": run_id,
                    "run_attempt": 1,
                    "path": protected_requirement["workflow"],
                    "event": "push",
                    "head_branch": self.run_branch if commit == self.head else BRANCH,
                    "head_sha": commit,
                    "status": "completed",
                    "conclusion": "success",
                    "html_url": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
                }
            if url == check_run_url(REPOSITORY, check_run_id):
                return self._check(
                    commit,
                    run_id,
                    check_run_id,
                    protected_requirement,
                    successful=True,
                )
            if url.endswith(f"/commits/{commit}/check-runs?filter=latest&per_page=100"):
                return {
                    "check_runs": [
                        self._check(
                            commit,
                            run_id,
                            check_run_id,
                            protected_requirement,
                            successful=self.qualified or commit != self.head,
                        )
                    ]
                }
        for base in self.identities:
            if url == compare_url(REPOSITORY, base, self.head):
                return {
                    "status": "identical" if base == self.head else "ahead",
                    "base_commit": {"sha": base},
                    "merge_base_commit": {"sha": base},
                }
        raise AssertionError(f"unexpected fixture URL: {url}")

    @staticmethod
    def _check(
        commit: str,
        run_id: int,
        check_run_id: int,
        protected_requirement: Mapping[str, str],
        *,
        successful: bool,
    ) -> dict[str, object]:
        return {
            "id": check_run_id,
            "name": protected_requirement["required_check"],
            "head_sha": commit,
            "status": "completed",
            "conclusion": "success" if successful else "failure",
            "html_url": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/job/{check_run_id}",
            "app": {"slug": "github-actions"},
        }

    def bytes(self, url: str, *, accept: str | None = None) -> bytes:
        self.assert_media_type(accept)
        for commit, raw in self.policies.items():
            if url == qualification_policy_url(commit):
                return raw
        for commit, source in self.sources.items():
            if url == workflow_source_url(REPOSITORY, PATH, commit):
                return source
        raise RecoveryWorkflowAuthorityError(f"protected policy or source could not be resolved: {url}")

    @staticmethod
    def assert_media_type(accept: str | None) -> None:
        if accept != "application/vnd.github.raw+json":
            raise AssertionError(f"unexpected media type: {accept}")


class RecoveryAuthorityReconciliationTest(unittest.TestCase):
    components = {"waterline": (REPOSITORY, BRANCH)}

    def reconcile(
        self,
        client: FixtureClient,
        *,
        source_document: dict[str, object] | None = None,
        current_policy: dict[str, object] | None = None,
        current_policy_commit: str = POLICY_A_COMMIT,
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        selected_policy = current_policy or policy()
        return reconcile_authority(
            authority(),
            source_document or source_identities(),
            selected_policy,
            policy_binding(selected_policy, current_policy_commit),
            client,
            self.components,
        )

    def test_identical_observation_is_idempotent(self) -> None:
        current_sources = source_identities()

        proposed_authority, proposed_sources, observation = self.reconcile(
            FixtureClient(head=OLD_COMMIT),
            source_document=current_sources,
        )

        self.assertEqual(authority(), proposed_authority)
        self.assertEqual(current_sources, proposed_sources)
        self.assertEqual("current", observation["outcome"])
        self.assertEqual([], observation["changes"])

    def test_policy_b_successor_does_not_reinterpret_policy_a_history(self) -> None:
        policy_b = policy(POLICY_B_REQUIREMENT)
        client = FixtureClient(
            head=NEW_COMMIT,
            current_policy=policy_b,
            current_policy_commit=POLICY_B_COMMIT,
        )

        proposed_authority, proposed_sources, observation = self.reconcile(
            client,
            current_policy=policy_b,
            current_policy_commit=POLICY_B_COMMIT,
        )

        self.assertEqual("change-required", observation["outcome"])
        identities = proposed_sources["workflows"]["waterline"]["identities"]
        self.assertEqual(2, len(identities))
        self.assertEqual(POLICY_A_WORKFLOW, identities[0]["qualification"]["workflow"])
        self.assertEqual(POLICY_A_COMMIT, identities[0]["qualification_policy"]["commit"])
        self.assertEqual(POLICY_B_WORKFLOW, identities[1]["qualification"]["workflow"])
        self.assertEqual(POLICY_B_COMMIT, identities[1]["qualification_policy"]["commit"])
        self.assertEqual(
            identities[1]["qualification_policy"],
            observation["changes"][0]["successor"]["qualification_policy"],
        )
        self.assertEqual(
            {
                "source_commit": OLD_COMMIT,
                "sha256": exact_source_sha256(OLD_SOURCE),
            },
            identities[-1]["supersedes"],
        )
        self.assertEqual(
            exact_source_sha256(NEW_SOURCE),
            proposed_authority["workflows"]["waterline"]["sha256"],
        )

    def test_missing_or_altered_historical_policy_binding_fails_closed(self) -> None:
        cases: list[tuple[str, dict[str, object], str]] = []
        missing = source_identities()
        del missing["workflows"]["waterline"]["identities"][0]["qualification_policy"]
        cases.append(("missing", missing, "invalid shape"))
        altered = source_identities()
        altered["workflows"]["waterline"]["identities"][0]["qualification_policy"]["sha256"] = "0" * 64
        cases.append(("altered", altered, "does not match its protected binding"))

        for label, source_document, message in cases:
            with self.subTest(binding=label), self.assertRaisesRegex(
                RecoveryWorkflowAuthorityError,
                message,
            ):
                self.reconcile(
                    FixtureClient(head=OLD_COMMIT),
                    source_document=source_document,
                )

    def test_unresolvable_or_ambiguous_policy_binding_fails_closed(self) -> None:
        unresolvable = source_identities()
        binding = unresolvable["workflows"]["waterline"]["identities"][0]["qualification_policy"]
        binding["commit"] = "c" * 40
        client = FixtureClient(head=OLD_COMMIT)
        with self.assertRaisesRegex(RecoveryWorkflowAuthorityError, "could not be resolved"):
            self.reconcile(client, source_document=unresolvable)

        ambiguous_policy = policy()
        ambiguous_policy["targets"]["waterline"]["workflows"].append(
            {"path": "other.yml", "required_check": "Other qualification"}
        )
        ambiguous_client = FixtureClient(
            head=NEW_COMMIT,
            current_policy=ambiguous_policy,
            current_policy_commit=POLICY_B_COMMIT,
        )
        with self.assertRaisesRegex(RecoveryWorkflowAuthorityError, "mismatched protected target"):
            self.reconcile(
                ambiguous_client,
                current_policy=ambiguous_policy,
                current_policy_commit=POLICY_B_COMMIT,
            )

    def test_successor_qualified_only_by_obsolete_policy_is_rejected(self) -> None:
        policy_b = policy(POLICY_B_REQUIREMENT)
        client = FixtureClient(
            head=NEW_COMMIT,
            current_policy=policy_b,
            current_policy_commit=POLICY_B_COMMIT,
            successor_requirement=POLICY_A_REQUIREMENT,
        )

        with self.assertRaisesRegex(RecoveryWorkflowAuthorityError, "no protected qualification check"):
            self.reconcile(
                client,
                current_policy=policy_b,
                current_policy_commit=POLICY_B_COMMIT,
            )

    def test_mismatched_accepted_bytes_fail_before_observation(self) -> None:
        client = FixtureClient(head=OLD_COMMIT)
        client.sources[OLD_COMMIT] += b"# tampered\n"

        with self.assertRaisesRegex(RecoveryWorkflowAuthorityError, "protected source bytes"):
            self.reconcile(client)

    def test_unqualified_or_cross_branch_successor_is_rejected(self) -> None:
        cases = (
            (FixtureClient(head=NEW_COMMIT, qualified=False), "successful GitHub Actions check"),
            (FixtureClient(head=NEW_COMMIT, run_branch="contributor"), "protected-branch run"),
        )
        for client, message in cases:
            with self.subTest(message=message), self.assertRaisesRegex(
                RecoveryWorkflowAuthorityError,
                message,
            ):
                self.reconcile(client, source_document=copy.deepcopy(source_identities()))


if __name__ == "__main__":
    unittest.main()
