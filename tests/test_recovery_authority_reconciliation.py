from __future__ import annotations

import copy
import json
import unittest
from collections.abc import Mapping
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts.beta_candidate import canonical_json
from scripts.recovery_authority_reconciliation import reconcile_authority
from scripts.recovery_workflow_authority import (
    AUTHORITY_PATH,
    CONTROL_REPOSITORY,
    SOURCE_IDENTITIES_PATH,
    SOURCE_IDENTITIES_SCHEMA,
    SOURCE_IDENTITY_HISTORY_LIMIT,
    RecoveryWorkflowAuthorityError,
    authority_ref_url,
    authority_url,
    branch_url,
    check_run_url,
    compare_url,
    exact_source_sha256,
    qualification_policy_binding,
    qualification_policy_url,
    source_history_binding,
    source_identities_url,
    validate_authority,
    validate_source_identities,
    verify_authority_source_identities,
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
ROOT = Path(__file__).resolve().parents[1]
SOURCE_IDENTITIES_JSON_SCHEMA = json.loads(
    (ROOT / "release-recovery" / "protected-source-identities-schema.json").read_bytes()
)
PUBLIC_SOURCE_IDENTITIES = json.loads(
    (ROOT / "release-recovery" / "protected-source-identities.json").read_bytes()
)


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
        self.requests: list[tuple[str, str]] = []
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
        self.historical_sources: dict[str, bytes] = {}
        self.historical_authorities: dict[str, bytes] = {}
        self.ancestor_commits: set[str] = set()

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
        self.requests.append(("json", url))
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
        for base in {*self.identities, *self.ancestor_commits}:
            for head in {*self.identities, self.head}:
                if url == compare_url(REPOSITORY, base, head):
                    return {
                        "status": "identical" if base == head else "ahead",
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
        self.requests.append(("bytes", url))
        self.assert_media_type(accept)
        for commit, raw in self.historical_sources.items():
            if url == source_identities_url(commit):
                return raw
        for commit, raw in self.historical_authorities.items():
            if url == authority_url(commit):
                return raw
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
        authority_document: dict[str, object] | None = None,
        source_document: dict[str, object] | None = None,
        source_raw: bytes | None = None,
        current_policy: dict[str, object] | None = None,
        current_policy_commit: str = POLICY_A_COMMIT,
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
        selected_policy = current_policy or policy()
        selected_sources = source_document or source_identities()
        return reconcile_authority(
            authority_document or authority(),
            selected_sources,
            selected_policy,
            policy_binding(selected_policy, current_policy_commit),
            client,
            self.components,
            source_raw=source_raw or canonical_json(selected_sources),
        )

    def full_history(
        self,
        *,
        prior_checkpoint_count: int = 0,
        segment: int = 0,
    ) -> tuple[dict[str, object], dict[str, object], FixtureClient]:
        current_authority = authority()
        current_sources = source_identities()
        client = FixtureClient(head=NEW_COMMIT)
        identities: list[dict[str, object]] = []
        previous: dict[str, str] | None = None
        if prior_checkpoint_count:
            previous = {
                "source_commit": "e" * 40,
                "sha256": exact_source_sha256(b"prior checkpoint terminal\n"),
            }
            current_sources["workflows"]["waterline"]["checkpoint"] = {
                "accepted_identities": prior_checkpoint_count,
                "predecessor": previous,
                "source": source_history_binding(b"{}\n", "d" * 40),
            }

        for index in range(SOURCE_IDENTITY_HISTORY_LIMIT):
            commit = OLD_COMMIT if index == 0 and segment == 0 else f"{segment * 10000 + index + 1000:040x}"
            source = (
                OLD_SOURCE
                if index == 0 and segment == 0
                else OLD_SOURCE + f"# segment {segment} accepted {index}\n".encode()
            )
            run_id = 1000 + index
            check_run_id = 2000 + index
            identity: dict[str, object] = {
                "source_commit": commit,
                "sha256": exact_source_sha256(source),
                "qualification": qualification(commit, run_id, check_run_id),
                "qualification_policy": policy_binding(policy(), POLICY_A_COMMIT),
            }
            if previous is not None:
                identity["supersedes"] = dict(previous)
            identities.append(identity)
            previous = {"source_commit": commit, "sha256": identity["sha256"]}
            client.sources[commit] = source
            client.identities[commit] = (run_id, check_run_id, POLICY_A_REQUIREMENT)

        current_sources["workflows"]["waterline"]["identities"] = identities
        current_authority["workflows"]["waterline"]["sha256"] = identities[-1]["sha256"]
        return current_authority, current_sources, client

    def rolled_history(
        self,
    ) -> tuple[
        dict[str, object],
        dict[str, object],
        dict[str, object],
        dict[str, object],
        dict[str, object],
        FixtureClient,
    ]:
        current_authority, current_sources, client = self.full_history()
        source_raw = canonical_json(current_sources)
        proposed_authority, proposed_sources, observation = self.reconcile(
            client,
            authority_document=current_authority,
            source_document=current_sources,
            source_raw=source_raw,
        )
        client.historical_sources[POLICY_A_COMMIT] = source_raw
        client.historical_authorities[POLICY_A_COMMIT] = canonical_json(current_authority)
        return current_authority, current_sources, proposed_authority, proposed_sources, observation, client

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

    def test_successor_at_the_retention_boundary_rolls_over_and_remains_verifiable(self) -> None:
        (
            current_authority,
            current_sources,
            proposed_authority,
            proposed_sources,
            observation,
            client,
        ) = self.rolled_history()
        record = proposed_sources["workflows"]["waterline"]
        checkpoint = record["checkpoint"]

        self.assertEqual(SOURCE_IDENTITY_HISTORY_LIMIT, len(current_sources["workflows"]["waterline"]["identities"]))
        self.assertEqual(1, len(record["identities"]))
        self.assertEqual(SOURCE_IDENTITY_HISTORY_LIMIT, checkpoint["accepted_identities"])
        self.assertEqual(checkpoint["predecessor"], record["identities"][0]["supersedes"])
        self.assertEqual(
            current_sources["workflows"]["waterline"]["identities"][-1]["source_commit"],
            checkpoint["predecessor"]["source_commit"],
        )
        self.assertEqual(
            source_history_binding(canonical_json(current_sources), POLICY_A_COMMIT),
            checkpoint["source"],
        )
        self.assertEqual(checkpoint, observation["changes"][0]["checkpoint"])

        workflows = validate_authority(proposed_authority, self.components)
        validated = validate_source_identities(proposed_sources, workflows, self.components)
        evidence = verify_authority_source_identities(client, workflows, validated)
        self.assertEqual(checkpoint, evidence["waterline"]["checkpoint"])
        self.assertEqual(NEW_COMMIT, evidence["waterline"]["identities"][0]["source_commit"])
        schema_proposal = copy.deepcopy(PUBLIC_SOURCE_IDENTITIES)
        schema_proposal["workflows"]["waterline"] = copy.deepcopy(record)
        Draft202012Validator(SOURCE_IDENTITIES_JSON_SCHEMA).validate(schema_proposal)

        oversized = copy.deepcopy(current_sources)
        oversized["workflows"]["waterline"]["identities"].append(record["identities"][0])
        with self.assertRaisesRegex(RecoveryWorkflowAuthorityError, "100-identity limit"):
            validate_source_identities(oversized, workflows, self.components)
        schema_oversized = copy.deepcopy(schema_proposal)
        schema_oversized["workflows"]["waterline"]["identities"] = copy.deepcopy(
            oversized["workflows"]["waterline"]["identities"]
        )
        self.assertTrue(list(Draft202012Validator(SOURCE_IDENTITIES_JSON_SCHEMA).iter_errors(schema_oversized)))
        self.assertNotEqual(current_authority, proposed_authority)

    def test_rollover_checkpoint_rejects_drop_reorder_fork_and_forgery(self) -> None:
        (
            _current_authority,
            current_sources,
            proposed_authority,
            proposed_sources,
            _observation,
            client,
        ) = self.rolled_history()
        workflows = validate_authority(proposed_authority, self.components)

        mutations: list[tuple[str, dict[str, object], FixtureClient, str]] = []
        wrong_count = copy.deepcopy(proposed_sources)
        wrong_count["workflows"]["waterline"]["checkpoint"]["accepted_identities"] = 200
        mutations.append(("drop", wrong_count, client, "discontinuous accepted identity count"))

        forged_predecessor = copy.deepcopy(proposed_sources)
        forged = {"source_commit": "9" * 40, "sha256": "8" * 64}
        forged_predecessor["workflows"]["waterline"]["checkpoint"]["predecessor"] = forged
        forged_predecessor["workflows"]["waterline"]["identities"][0]["supersedes"] = forged
        mutations.append(("fork", forged_predecessor, client, "exact current predecessor"))

        forged_source = copy.deepcopy(proposed_sources)
        forged_source["workflows"]["waterline"]["checkpoint"]["source"]["sha256"] = "0" * 64
        mutations.append(("forge", forged_source, client, "protected binding"))

        reordered_history = copy.deepcopy(current_sources)
        historical_identities = reordered_history["workflows"]["waterline"]["identities"]
        historical_identities[-2], historical_identities[-1] = historical_identities[-1], historical_identities[-2]
        reordered_raw = canonical_json(reordered_history)
        reordered_sources = copy.deepcopy(proposed_sources)
        reordered_sources["workflows"]["waterline"]["checkpoint"]["source"] = source_history_binding(
            reordered_raw,
            POLICY_A_COMMIT,
        )
        reordered_client = copy.deepcopy(client)
        reordered_client.historical_sources[POLICY_A_COMMIT] = reordered_raw
        mutations.append(("reorder", reordered_sources, reordered_client, "mismatched predecessor"))

        for label, source_document, selected_client, message in mutations:
            with self.subTest(mutation=label), self.assertRaisesRegex(
                RecoveryWorkflowAuthorityError,
                message,
            ):
                validated = validate_source_identities(source_document, workflows, self.components)
                verify_authority_source_identities(selected_client, workflows, validated)

    def test_a_later_full_segment_rolls_forward_without_replaying_older_checkpoints(self) -> None:
        root_authority, root_sources, _root_client = self.full_history()
        root_raw = canonical_json(root_sources)
        current_authority, current_sources, client = self.full_history(
            prior_checkpoint_count=SOURCE_IDENTITY_HISTORY_LIMIT,
            segment=1,
        )
        root_terminal = {
            field: root_sources["workflows"]["waterline"]["identities"][-1][field]
            for field in ("source_commit", "sha256")
        }
        current_record = current_sources["workflows"]["waterline"]
        current_record["checkpoint"] = {
            "accepted_identities": SOURCE_IDENTITY_HISTORY_LIMIT,
            "predecessor": root_terminal,
            "source": source_history_binding(root_raw, POLICY_A_COMMIT),
        }
        current_record["identities"][0]["supersedes"] = root_terminal
        client.ancestor_commits.add(root_terminal["source_commit"])
        current_raw = canonical_json(current_sources)
        client.historical_sources[POLICY_A_COMMIT] = root_raw
        client.historical_authorities[POLICY_A_COMMIT] = canonical_json(root_authority)
        client.policies[POLICY_B_COMMIT] = canonical_json(policy())

        proposed_authority, proposed_sources, observation = self.reconcile(
            client,
            authority_document=current_authority,
            source_document=current_sources,
            source_raw=current_raw,
            current_policy_commit=POLICY_B_COMMIT,
        )
        checkpoint = proposed_sources["workflows"]["waterline"]["checkpoint"]
        self.assertEqual(2 * SOURCE_IDENTITY_HISTORY_LIMIT, checkpoint["accepted_identities"])
        self.assertEqual(source_history_binding(current_raw, POLICY_B_COMMIT), checkpoint["source"])
        self.assertEqual(checkpoint, observation["changes"][0]["checkpoint"])

        client.historical_sources[POLICY_B_COMMIT] = current_raw
        client.historical_authorities[POLICY_B_COMMIT] = canonical_json(current_authority)
        client.requests.clear()
        workflows = validate_authority(proposed_authority, self.components)
        validated = validate_source_identities(proposed_sources, workflows, self.components)
        evidence = verify_authority_source_identities(client, workflows, validated)

        self.assertEqual(2 * SOURCE_IDENTITY_HISTORY_LIMIT, evidence["waterline"]["checkpoint"]["accepted_identities"])
        self.assertFalse(any(url == source_identities_url(POLICY_A_COMMIT) for _method, url in client.requests))

    def test_checkpoint_live_reads_do_not_grow_with_total_accepted_history(self) -> None:
        (
            current_authority,
            current_sources,
            proposed_authority,
            proposed_sources,
            _observation,
            client,
        ) = self.rolled_history()
        historical_record = current_sources["workflows"]["waterline"]
        prior = {"source_commit": "e" * 40, "sha256": exact_source_sha256(b"older terminal\n")}
        historical_record["checkpoint"] = {
            "accepted_identities": 9900,
            "predecessor": prior,
            "source": source_history_binding(b"{}\n", "d" * 40),
        }
        historical_record["identities"][0]["supersedes"] = prior
        historical_raw = canonical_json(current_sources)
        checkpoint = proposed_sources["workflows"]["waterline"]["checkpoint"]
        checkpoint["accepted_identities"] = 10000
        checkpoint["source"] = source_history_binding(historical_raw, POLICY_A_COMMIT)
        client.historical_sources[POLICY_A_COMMIT] = historical_raw
        client.historical_authorities[POLICY_A_COMMIT] = canonical_json(current_authority)
        client.requests.clear()

        workflows = validate_authority(proposed_authority, self.components)
        validated = validate_source_identities(proposed_sources, workflows, self.components)
        evidence = verify_authority_source_identities(client, workflows, validated)

        self.assertEqual(10000, evidence["waterline"]["checkpoint"]["accepted_identities"])
        self.assertLessEqual(len(client.requests), 12)
        self.assertFalse(any("d" * 40 in url for _method, url in client.requests))

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
