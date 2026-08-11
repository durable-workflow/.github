from __future__ import annotations

import copy
import unittest

from scripts.recovery_authority_reconciliation import reconcile_authority
from scripts.recovery_workflow_authority import (
    AUTHORITY_PATH,
    SOURCE_IDENTITIES_PATH,
    SOURCE_IDENTITIES_SCHEMA,
    RecoveryWorkflowAuthorityError,
    branch_url,
    check_run_url,
    compare_url,
    exact_source_sha256,
    workflow_metadata_url,
    workflow_run_url,
    workflow_source_url,
)

REPOSITORY = "durable-workflow/waterline"
BRANCH = "v2"
PATH = ".github/workflows/release-plan-recovery.yml"
QUALIFICATION_WORKFLOW = ".github/workflows/php.yml"
REQUIRED_CHECK = "Target branch qualification"
OLD_COMMIT = "1" * 40
NEW_COMMIT = "2" * 40
OLD_SOURCE = b"name: Recovery\non:\n  workflow_dispatch:\n"
NEW_SOURCE = OLD_SOURCE + b"# successor\n"


def qualification(commit: str, run_id: int, check_run_id: int) -> dict[str, object]:
    return {
        "check_run_id": check_run_id,
        "check_url": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/job/{check_run_id}",
        "conclusion": "success",
        "event": "push",
        "head_branch": BRANCH,
        "head_sha": commit,
        "required_check": REQUIRED_CHECK,
        "run_attempt": 1,
        "run_id": run_id,
        "status": "completed",
        "url": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
        "workflow": QUALIFICATION_WORKFLOW,
    }


def authority() -> dict[str, object]:
    return {
        "schema": "durable-workflow.component-release-recovery-authority/v2",
        "source": {
            "repository": "durable-workflow/.github",
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


def source_identities() -> dict[str, object]:
    return {
        "schema": SOURCE_IDENTITIES_SCHEMA,
        "source": {
            "repository": "durable-workflow/.github",
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
                    }
                ],
            }
        },
    }


def policy() -> dict[str, object]:
    return {
        "organization": "durable-workflow",
        "targets": {
            "waterline": {
                "repository": "waterline",
                "branch": BRANCH,
                "workflows": [
                    {
                        "path": "php.yml",
                        "required_check": REQUIRED_CHECK,
                    }
                ],
            }
        },
    }


class FixtureClient:
    def __init__(self, *, head: str, qualified: bool = True, run_branch: str = BRANCH) -> None:
        self.head = head
        self.qualified = qualified
        self.run_branch = run_branch
        self.sources = {OLD_COMMIT: OLD_SOURCE, NEW_COMMIT: NEW_SOURCE}
        self.identities = {
            OLD_COMMIT: (101, 201),
            NEW_COMMIT: (102, 202),
        }

    def json(self, url: str) -> dict[str, object]:
        if url == branch_url(REPOSITORY, BRANCH):
            return {"commit": {"sha": self.head}}
        if url == workflow_metadata_url(REPOSITORY, PATH):
            return {"id": 71, "path": PATH, "state": "active"}
        for commit, (run_id, check_run_id) in self.identities.items():
            if url == workflow_run_url(REPOSITORY, run_id):
                return {
                    "id": run_id,
                    "run_attempt": 1,
                    "path": QUALIFICATION_WORKFLOW,
                    "event": "push",
                    "head_branch": self.run_branch if commit == self.head else BRANCH,
                    "head_sha": commit,
                    "status": "completed",
                    "conclusion": "success",
                    "html_url": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}",
                }
            if url == check_run_url(REPOSITORY, check_run_id):
                return self._check(commit, run_id, check_run_id, successful=True)
            if url.endswith(f"/commits/{commit}/check-runs?filter=latest&per_page=100"):
                return {
                    "check_runs": [
                        self._check(
                            commit,
                            run_id,
                            check_run_id,
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
        *,
        successful: bool,
    ) -> dict[str, object]:
        return {
            "id": check_run_id,
            "name": REQUIRED_CHECK,
            "head_sha": commit,
            "status": "completed",
            "conclusion": "success" if successful else "failure",
            "html_url": f"https://github.com/{REPOSITORY}/actions/runs/{run_id}/job/{check_run_id}",
            "app": {"slug": "github-actions"},
        }

    def bytes(self, url: str, *, accept: str | None = None) -> bytes:
        self.assert_media_type(accept)
        for commit, source in self.sources.items():
            if url == workflow_source_url(REPOSITORY, PATH, commit):
                return source
        raise AssertionError(f"unexpected fixture URL: {url}")

    @staticmethod
    def assert_media_type(accept: str | None) -> None:
        if accept != "application/vnd.github.raw+json":
            raise AssertionError(f"unexpected media type: {accept}")


class RecoveryAuthorityReconciliationTest(unittest.TestCase):
    components = {"waterline": (REPOSITORY, BRANCH)}

    def test_identical_observation_is_idempotent(self) -> None:
        current_authority = authority()
        current_sources = source_identities()

        proposed_authority, proposed_sources, observation = reconcile_authority(
            current_authority,
            current_sources,
            policy(),
            FixtureClient(head=OLD_COMMIT),
            self.components,
        )

        self.assertEqual(current_authority, proposed_authority)
        self.assertEqual(current_sources, proposed_sources)
        self.assertEqual("current", observation["outcome"])
        self.assertEqual([], observation["changes"])

    def test_qualified_successor_explicitly_supersedes_the_current_identity(self) -> None:
        proposed_authority, proposed_sources, observation = reconcile_authority(
            authority(),
            source_identities(),
            policy(),
            FixtureClient(head=NEW_COMMIT),
            self.components,
        )

        self.assertEqual("change-required", observation["outcome"])
        self.assertEqual(["waterline"], [change["component"] for change in observation["changes"]])
        identities = proposed_sources["workflows"]["waterline"]["identities"]
        self.assertEqual(2, len(identities))
        self.assertEqual(
            {
                "source_commit": OLD_COMMIT,
                "sha256": exact_source_sha256(OLD_SOURCE),
            },
            identities[-1]["supersedes"],
        )
        self.assertEqual(NEW_COMMIT, identities[-1]["source_commit"])
        self.assertEqual(
            exact_source_sha256(NEW_SOURCE),
            proposed_authority["workflows"]["waterline"]["sha256"],
        )

    def test_mismatched_accepted_bytes_fail_before_observation(self) -> None:
        client = FixtureClient(head=OLD_COMMIT)
        client.sources[OLD_COMMIT] += b"# tampered\n"

        with self.assertRaisesRegex(
            RecoveryWorkflowAuthorityError,
            "protected source bytes",
        ):
            reconcile_authority(
                authority(),
                source_identities(),
                policy(),
                client,
                self.components,
            )

    def test_unqualified_or_cross_branch_successor_is_rejected(self) -> None:
        cases = (
            (FixtureClient(head=NEW_COMMIT, qualified=False), "successful GitHub Actions check"),
            (FixtureClient(head=NEW_COMMIT, run_branch="contributor"), "protected-branch run"),
        )
        for client, message in cases:
            with (
                self.subTest(message=message),
                self.assertRaisesRegex(
                    RecoveryWorkflowAuthorityError,
                    message,
                ),
            ):
                reconcile_authority(
                    copy.deepcopy(authority()),
                    copy.deepcopy(source_identities()),
                    policy(),
                    client,
                    self.components,
                )


if __name__ == "__main__":
    unittest.main()
