from __future__ import annotations

import copy
import json
import re
import unittest
import urllib.error
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml

from scripts.cross_repository_lifecycle import (
    EVIDENCE_MARKER,
    declared_targets,
    evaluate_lifecycle,
    qualification_targets,
    render_evidence,
)
from scripts.issue_authority import (
    COMPLETION_REQUIRED_LABEL,
    COMPLETION_VERIFIED_LABEL,
    INTAKE_SCHEMA,
    OWNER_LABELS,
    STATUS_LABELS,
    SUPERSEDED_STATUS_LABEL,
    SUPERSESSION_EVIDENCE_MARKER,
    UNBLOCK_CONTEXT_END,
    UNBLOCK_CONTEXT_START,
    AuthorityError,
    GitHubApi,
    GitHubDiscovery,
    apply_backlog,
    assess_issue_intake,
    audit_backlog,
    issue_revision_digest,
    load_contract,
    load_legacy_cross_repository_targets,
    reconstruct_intake,
    validate_backlog_cross_repository_targets,
    validate_contract,
    verify_intake_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
REVIEWED_BLOCK_CONDITION = "A separately owned public release gate must complete."


def mark_release_item_blocked(backlog: dict[str, Any]) -> dict[str, Any]:
    item = next(item for item in backlog["items"] if item["id"] == "release-plan-versioned-changelogs")
    item["status"] = "blocked"
    item["unblock_condition"] = REVIEWED_BLOCK_CONDITION
    return item


class FakeResponse:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self.payload


def contract_fixture(
    *,
    include_supersessions: bool = False,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    directory = ROOT / "issue-authority"
    documents = tuple(
        json.loads((directory / name).read_text(encoding="utf-8"))
        for name in ("policy.json", "backlog.json", "policy-schema.json", "backlog-schema.json")
    )
    if not include_supersessions:
        documents[0]["prerelease_supersessions"] = []
    return documents


def qualification_fixture() -> dict[str, Any]:
    return json.loads((ROOT / "qualification" / "policy.json").read_text(encoding="utf-8"))


def legacy_target_fixture() -> dict[str, Any]:
    return json.loads((ROOT / "issue-authority" / "legacy-cross-repository-targets.json").read_text(encoding="utf-8"))


def historical_landing_fixture(*repositories: str) -> list[dict[str, Any]]:
    landings = {landing["repository"]: landing for landing in legacy_target_fixture()["protected_branch_landings"]}
    return [copy.deepcopy(landings[repository]) for repository in repositories]


class FakeGitHubApi:
    def __init__(self, policy: dict[str, Any]) -> None:
        self.labels: dict[str, dict[str, dict[str, str]]] = {repository: {} for repository in policy["repositories"]}
        self.milestones: dict[str, dict[str, dict[str, Any]]] = {
            repository: {} for repository in policy["repositories"]
        }
        self.issues: dict[str, list[dict[str, Any]]] = {repository: [] for repository in policy["repositories"]}
        self.label_updates: list[tuple[str, str, str]] = []
        self.milestone_updates: list[tuple[str, str, str]] = []
        self.created_issues: list[tuple[str, int]] = []
        self.replacements: list[tuple[str, int, list[str]]] = []
        self.body_updates: list[tuple[str, int, str]] = []
        self.state_updates: list[tuple[str, int, str]] = []
        self.timelines: dict[tuple[str, int], list[dict[str, Any]]] = {}
        self.timeline_sequences: dict[tuple[str, int], list[list[dict[str, Any]]]] = {}
        self.timeline_reads: list[tuple[str, int]] = []
        self.pulls: dict[tuple[str, int], dict[str, Any]] = {}
        self.reviews: dict[tuple[str, int], list[dict[str, Any]]] = {}
        self.reachable: set[tuple[str, str, str]] = set()
        self.successful_checks: dict[tuple[str, str], set[str]] = {}
        self.reachability_requests: list[tuple[str, str, str]] = []
        self.check_requests: list[tuple[str, str]] = []
        self.comments: dict[tuple[str, int], str] = {}
        self.comment_updates: list[tuple[str, int, str]] = []

    def ensure_labels(
        self,
        _organization: str,
        repository: str,
        desired: list[dict[str, str]],
    ) -> list[str]:
        changes: list[str] = []
        for label in desired:
            action = "created" if label["name"] not in self.labels[repository] else "updated"
            if self.labels[repository].get(label["name"]) == label:
                continue
            self.labels[repository][label["name"]] = copy.deepcopy(label)
            changes.append(f"{action}:{label['name']}")
            self.label_updates.append((repository, action, label["name"]))
        return changes

    def ensure_milestone(
        self,
        _organization: str,
        repository: str,
        desired: dict[str, Any],
    ) -> tuple[int, str | None]:
        current = self.milestones[repository].get(desired["title"])
        if current == desired:
            return 1, None
        self.milestones[repository][desired["title"]] = copy.deepcopy(desired)
        action = "created" if current is None else "updated"
        self.milestone_updates.append((repository, action, desired["title"]))
        return 1, action

    def list_issues(self, _organization: str, repository: str) -> list[dict[str, Any]]:
        return list(self.issues[repository])

    def create_issue(
        self,
        organization: str,
        repository: str,
        *,
        title: str,
        body: str,
        labels: list[str],
        milestone: int,
    ) -> dict[str, Any]:
        number = len(self.issues[repository]) + 1
        issue = {
            "body": body,
            "html_url": f"https://github.com/{organization}/{repository}/issues/{number}",
            "labels": [{"name": label} for label in labels],
            "milestone": {"number": milestone, "title": "2.0 beta"},
            "number": number,
            "state": "open",
            "title": title,
        }
        self.issues[repository].append(issue)
        self.created_issues.append((repository, number))
        return issue

    def replace_issue_labels(
        self,
        _organization: str,
        repository: str,
        number: int,
        labels: list[str],
    ) -> None:
        issue = next(issue for issue in self.issues[repository] if issue["number"] == number)
        issue["labels"] = [{"name": label} for label in labels]
        self.replacements.append((repository, number, labels))

    def update_issue_body(
        self,
        _organization: str,
        repository: str,
        number: int,
        body: str,
    ) -> None:
        issue = next(issue for issue in self.issues[repository] if issue["number"] == number)
        issue["body"] = body
        self.body_updates.append((repository, number, body))

    def update_issue_state(
        self,
        _organization: str,
        repository: str,
        number: int,
        state: str,
    ) -> None:
        issue = next(issue for issue in self.issues[repository] if issue["number"] == number)
        issue["state"] = state
        self.state_updates.append((repository, number, state))

    def list_issue_closing_references(
        self,
        _organization: str,
        repository: str,
        number: int,
    ) -> list[dict[str, Any]]:
        self.timeline_reads.append((repository, number))
        sequence = self.timeline_sequences.get((repository, number))
        if sequence:
            value = sequence.pop(0) if len(sequence) > 1 else sequence[0]
            return copy.deepcopy(value)
        return copy.deepcopy(self.timelines.get((repository, number), []))

    def get_pull_request(self, _organization: str, repository: str, number: int) -> dict[str, Any]:
        return copy.deepcopy(self.pulls[(repository, number)])

    def list_pull_request_reviews(
        self,
        _organization: str,
        repository: str,
        number: int,
    ) -> list[dict[str, Any]]:
        return copy.deepcopy(self.reviews.get((repository, number), []))

    def commit_reaches_branch(
        self,
        _organization: str,
        repository: str,
        commit: str,
        branch: str,
    ) -> bool:
        self.reachability_requests.append((repository, commit, branch))
        return (repository, commit, branch) in self.reachable

    def successful_check_names(
        self,
        _organization: str,
        repository: str,
        commit: str,
    ) -> set[str]:
        self.check_requests.append((repository, commit))
        return set(self.successful_checks.get((repository, commit), set()))

    def upsert_lifecycle_comment(
        self,
        _organization: str,
        repository: str,
        number: int,
        marker: str,
        body: str,
    ) -> None:
        self.assert_lifecycle_marker(marker, body)
        key = (repository, number)
        if self.comments.get(key) == body:
            return
        self.comments[key] = body
        self.comment_updates.append((repository, number, body))

    @staticmethod
    def assert_lifecycle_marker(marker: str, body: str) -> None:
        if marker not in body:
            raise AssertionError("lifecycle comment omitted its stable marker")


def label_names(issue: dict[str, Any]) -> set[str]:
    return {label["name"] for label in issue["labels"]}


def find_work_item(client: FakeGitHubApi, work_id: str) -> tuple[str, dict[str, Any]]:
    marker = f"<!-- beta-work-id: {work_id} -->"
    for repository, issues in client.issues.items():
        for issue in issues:
            if marker in issue["body"]:
                return repository, issue
    raise AssertionError(f"missing work item {work_id}")


def replace_unblock_context(issue: dict[str, Any], replacement: str) -> None:
    start = issue["body"].index(UNBLOCK_CONTEXT_START)
    end = issue["body"].index(UNBLOCK_CONTEXT_END) + len(UNBLOCK_CONTEXT_END)
    issue["body"] = issue["body"][:start] + replacement + issue["body"][end:]


def intake_issue(
    *,
    author: str = "external-contributor",
    body: str = "Current body",
    edited_at: str | None = None,
    labels: list[str] | None = None,
    number: int = 1,
) -> dict[str, Any]:
    return {
        "author": {"login": author},
        "body": body,
        "created_at": "2026-07-21T10:00:00Z",
        "html_url": f"https://github.com/durable-workflow/.github/issues/{number}",
        "labels": [{"name": label} for label in labels or []],
        "last_edited_at": edited_at,
        "milestone": None,
        "number": number,
        "state": "open",
        "title": "Current title",
    }


def prerelease_authority_issue(
    number: int,
    *,
    author: str = "rmcdaniel",
    body: str | None = None,
    state: str = "open",
    status: str = "status:ready",
) -> dict[str, Any]:
    issue = intake_issue(
        author=author,
        body=body or f"Prerelease authority {number}",
        labels=[
            "authority:github",
            "beta:blocker",
            COMPLETION_REQUIRED_LABEL,
            "kind:release-blocker",
            "priority:P0",
            status,
        ],
        number=number,
    )
    issue["milestone"] = {"title": "2.0 beta"}
    issue["state"] = state
    return issue


def label_event(
    actor: str,
    created_at: str,
    *,
    event: str = "labeled",
    label: str = "intake:approved",
) -> dict[str, Any]:
    return {
        "actor": actor,
        "created_at": created_at,
        "event": event,
        "label": label,
    }


def closing_reference(
    repository: str,
    number: int,
    *,
    actor: str = "durable-workflow-ops",
    created_at: str = "2026-07-24T09:00:00Z",
    identifier: str | None = None,
    will_close_target: bool = True,
) -> dict[str, Any]:
    return {
        "__typename": "CrossReferencedEvent",
        "actor": {"login": actor},
        "id": identifier if identifier is not None else f"CRE_kwDOA1b2c84A{number:04d}",
        "referencedAt": created_at,
        "source": {
            "__typename": "PullRequest",
            "number": number,
            "repository": {"nameWithOwner": f"durable-workflow/{repository}"},
            "url": f"https://github.com/durable-workflow/{repository}/pull/{number}",
        },
        "willCloseTarget": will_close_target,
    }


def pull_request(
    repository: str,
    number: int,
    branch: str,
    *,
    author: str = "durable-workflow-ops",
    author_association: str = "MEMBER",
    created_at: str,
    commit: str | None = None,
    head_repository: str | None = None,
    head_sha: str | None = None,
    state: str = "open",
) -> dict[str, Any]:
    resolved_head_repository = head_repository or f"durable-workflow/{repository}"
    resolved_head_sha = head_sha or f"{number:040x}"
    return {
        "author_association": author_association,
        "base": {
            "ref": branch,
            "repo": {"full_name": f"durable-workflow/{repository}"},
            "sha": f"{number + 1000:040x}",
        },
        "created_at": created_at,
        "head": {
            "ref": f"seed/implementation-{number}",
            "repo": {"full_name": resolved_head_repository},
            "sha": resolved_head_sha,
        },
        "html_url": f"https://github.com/durable-workflow/{repository}/pull/{number}",
        "merge_commit_sha": commit,
        "merged_at": "2026-07-24T12:00:00Z" if commit else None,
        "number": number,
        "state": "closed" if commit else state,
        "url": f"https://api.github.com/repos/durable-workflow/{repository}/pulls/{number}",
        "user": {"login": author},
    }


def approving_review(
    head_sha: str,
    *,
    association: str = "MEMBER",
    identifier: int = 1,
    reviewer: str = "repository-maintainer",
    state: str = "APPROVED",
    submitted_at: str = "2026-07-24T09:30:00Z",
) -> dict[str, Any]:
    return {
        "author_association": association,
        "commit_id": head_sha,
        "id": identifier,
        "state": state,
        "submitted_at": submitted_at,
        "user": {"id": identifier + 100, "login": reviewer},
    }


def closing_reference_race_fixture() -> tuple[Any, ...]:
    policy, backlog, _policy_schema, _backlog_schema = contract_fixture()
    for item in backlog["items"]:
        if item["kind"] == "cross-repository":
            item["kind"] = "feature"
    client = FakeGitHubApi(policy)
    apply_backlog(policy, backlog, client)
    parent = {
        "body": "Vetted cross-repository work.",
        "html_url": "https://github.com/durable-workflow/.github/issues/99",
        "labels": [
            {"name": "authority:github"},
            {"name": "kind:cross-repository"},
            {"name": "priority:P1"},
            {"name": "status:ready"},
        ],
        "milestone": None,
        "number": 99,
        "state": "open",
        "title": "Coordinate source landings",
    }
    client.issues[".github"].append(parent)
    targets = qualification_targets(qualification_fixture())
    selected_targets = [targets[".github"], targets["workflow"]]
    source_commit = "a" * 40
    workflow_commit = "b" * 40
    external_head = "c" * 40
    source_reference = closing_reference(".github", 51, created_at="2026-07-24T08:00:00Z")
    external_reference = closing_reference(
        "workflow",
        70,
        actor="external-contributor",
        created_at="2026-07-24T09:00:00Z",
    )
    client.pulls[(".github", 51)] = pull_request(
        ".github",
        51,
        "main",
        commit=source_commit,
        created_at="2026-07-24T07:30:00Z",
    )
    client.pulls[("workflow", 70)] = pull_request(
        "workflow",
        70,
        "v2",
        author="external-contributor",
        author_association="NONE",
        commit=workflow_commit,
        created_at="2026-07-24T08:30:00Z",
        head_repository="external-contributor/workflow",
        head_sha=external_head,
    )
    client.reviews[("workflow", 70)] = [
        approving_review(
            external_head,
            submitted_at="2026-07-24T09:30:00Z",
        )
    ]
    for target, commit in ((targets[".github"], source_commit), (targets["workflow"], workflow_commit)):
        repository = target["repository"]
        client.reachable.add((repository, commit, target["branch"]))
        client.successful_checks[(repository, commit)] = set(target["required_checks"])
    return (
        policy,
        backlog,
        client,
        parent,
        {(".github", 99): selected_targets},
        source_reference,
        external_reference,
    )


class FakeDiscovery:
    def __init__(
        self,
        policy: dict[str, Any],
        issues: dict[str, list[tuple[dict[str, Any], list[dict[str, Any]]]]],
    ) -> None:
        self.policy = policy
        self.issues = issues
        self.list_requests: list[str] = []
        self.get_requests: list[tuple[str, int]] = []

    def list_issues(
        self,
        _organization: str,
        repository: str,
    ) -> list[tuple[dict[str, Any], list[dict[str, Any]]]]:
        self.list_requests.append(repository)
        return copy.deepcopy(self.issues.get(repository, []))

    def get_issue(
        self,
        _organization: str,
        repository: str,
        number: int,
    ) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        self.get_requests.append((repository, number))
        issue, timeline = next(record for record in self.issues.get(repository, []) if record[0]["number"] == number)
        return copy.deepcopy(issue), copy.deepcopy(timeline)


class ContractValidationTest(unittest.TestCase):
    def test_checked_in_contract_is_valid(self) -> None:
        policy, backlog = load_contract(
            ROOT / "issue-authority" / "policy.json",
            ROOT / "issue-authority" / "backlog.json",
        )

        self.assertEqual("github-to-mirrors", policy["state_direction"])
        self.assertEqual(["rmcdaniel", "durable-workflow-ops"], policy["intake"]["trusted_actors"])
        self.assertEqual("intake:approved", policy["intake"]["approval_label"])
        self.assertEqual(
            [
                {
                    "number": 59,
                    "repository": ".github",
                }
            ],
            [record["retired"] for record in policy["prerelease_supersessions"]],
        )
        self.assertEqual(
            [
                {
                    "number": 61,
                    "repository": ".github",
                }
            ],
            [record["successor"] for record in policy["prerelease_supersessions"]],
        )
        self.assertIn(
            SUPERSEDED_STATUS_LABEL,
            {label["name"] for label in policy["labels"]},
        )
        self.assertEqual(4, len(backlog["items"]))
        blocked = [item for item in backlog["items"] if item["status"] == "blocked"]
        self.assertTrue(all(item["depends_on"] or item.get("unblock_condition") for item in blocked))
        validate_backlog_cross_repository_targets(
            backlog,
            qualification_fixture(),
            organization=policy["organization"],
        )

    def test_checked_in_legacy_target_migration_is_qualified(self) -> None:
        migration = load_legacy_cross_repository_targets(
            ROOT / "issue-authority" / "legacy-cross-repository-targets.json",
            qualification_fixture(),
        )

        self.assertEqual("durable-workflow.legacy-cross-repository-targets/v3", migration["schema"])
        self.assertTrue(migration["authorities"])
        self.assertEqual(
            {2, 26, 32, 33, 35, 36, 37, 38, 39, 41, 46, 48},
            {completion["number"] for completion in migration["historical_completions"]},
        )
        self.assertEqual(
            set(qualification_targets(qualification_fixture())),
            {landing["repository"] for landing in migration["protected_branch_landings"]},
        )
        migrated_beta = {
            authority["id"]: authority["targets"]
            for authority in migration["authorities"]
            if authority["marker"] == "beta-work-id"
        }
        _policy, backlog, _policy_schema, _backlog_schema = contract_fixture()
        current_beta = {
            item["id"]: item["required_source_targets"]
            for item in backlog["items"]
            if item["kind"] == "cross-repository"
        }
        self.assertEqual(current_beta, migrated_beta)

    def test_cross_repository_backlog_items_must_declare_qualified_targets(self) -> None:
        policy, backlog, policy_schema, backlog_schema = contract_fixture()
        backlog["items"][0].pop("required_source_targets")

        with self.assertRaisesRegex(AuthorityError, "required_source_targets"):
            validate_contract(policy, backlog, policy_schema, backlog_schema)

    def test_public_repository_inventory_is_exact(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        expected_repositories = [
            ".github",
            "workflow",
            "waterline",
            "server",
            "cli",
            "ai",
            "sample-app",
            "sdk-php",
            "sdk-python",
            "sdk-rust",
            "durable-workflow.github.io",
        ]
        self.assertEqual(expected_repositories, policy["repositories"])
        self.assertEqual(expected_repositories, list(OWNER_LABELS))
        self.assertEqual(expected_repositories, policy["milestones"][0]["repositories"])

    def test_prerelease_supersession_requires_a_distinct_active_successor(self) -> None:
        policy, backlog, policy_schema, backlog_schema = contract_fixture(include_supersessions=True)
        policy["prerelease_supersessions"][0]["successor"] = copy.deepcopy(
            policy["prerelease_supersessions"][0]["retired"]
        )

        with self.assertRaisesRegex(AuthorityError, "distinct active successor"):
            validate_contract(policy, backlog, policy_schema, backlog_schema)

    def test_prerelease_supersession_cannot_chain_through_a_retired_issue(self) -> None:
        policy, backlog, policy_schema, backlog_schema = contract_fixture(include_supersessions=True)
        policy["prerelease_supersessions"].append(
            {
                "reason": "A later immutable artifact mismatch requires another train.",
                "retired": {"repository": ".github", "number": 61},
                "successor": {"repository": ".github", "number": 62},
            }
        )

        with self.assertRaisesRegex(AuthorityError, "must remain active"):
            validate_contract(policy, backlog, policy_schema, backlog_schema)

    def test_review_and_migration_sets_must_match_exactly(self) -> None:
        policy, backlog, policy_schema, backlog_schema = contract_fixture()
        backlog["review"][3]["disposition"] = "evidence-only"

        with self.assertRaisesRegex(AuthorityError, "reviewed migration set differs"):
            validate_contract(policy, backlog, policy_schema, backlog_schema)

    def test_dependencies_must_be_topologically_ordered(self) -> None:
        policy, backlog, policy_schema, backlog_schema = contract_fixture()
        backlog["items"][0]["depends_on"] = ["authorize-2-0-beta"]

        with self.assertRaisesRegex(AuthorityError, "dependencies must precede"):
            validate_contract(policy, backlog, policy_schema, backlog_schema)

    def test_blocked_item_must_name_dependency_or_unblock_condition(self) -> None:
        policy, backlog, policy_schema, backlog_schema = contract_fixture()
        mark_release_item_blocked(backlog)
        backlog["items"][0].pop("unblock_condition")

        with self.assertRaisesRegex(AuthorityError, "must name a dependency or explicit unblock condition"):
            validate_contract(policy, backlog, policy_schema, backlog_schema)

    def test_unblock_condition_must_be_public_safe(self) -> None:
        policy, backlog, policy_schema, backlog_schema = contract_fixture()
        mark_release_item_blocked(backlog)
        backlog["items"][0]["unblock_condition"] = "Wait for /var/private-state."

        with self.assertRaisesRegex(AuthorityError, "non-public context"):
            validate_contract(policy, backlog, policy_schema, backlog_schema)

    def test_reviewed_source_fields_reject_reserved_unblock_context_markers(self) -> None:
        for marker in (UNBLOCK_CONTEXT_START, UNBLOCK_CONTEXT_END):
            with self.subTest(marker=marker):
                policy, backlog, policy_schema, backlog_schema = contract_fixture()
                backlog["review"][0]["reason"] += f" {marker}"

                with self.assertRaisesRegex(AuthorityError, "reserved unblock condition marker"):
                    validate_contract(policy, backlog, policy_schema, backlog_schema)

    def test_private_operational_context_is_rejected(self) -> None:
        policy, backlog, policy_schema, backlog_schema = contract_fixture()
        backlog["items"][0]["body"] += "\nDetails are in /var/private-state."

        with self.assertRaisesRegex(AuthorityError, "non-public context"):
            validate_contract(policy, backlog, policy_schema, backlog_schema)

    def test_private_cloud_is_not_a_public_authority_target(self) -> None:
        policy, backlog, policy_schema, backlog_schema = contract_fixture()
        policy["repositories"].append("cloud")

        with self.assertRaisesRegex(AuthorityError, "repository inventory"):
            validate_contract(policy, backlog, policy_schema, backlog_schema)

    def test_issue_forms_use_only_policy_labels(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        policy_labels = {label["name"] for label in policy["labels"]}
        form_directory = ROOT / ".github" / "ISSUE_TEMPLATE"
        expected = {
            "cross_repository.yml",
            "feature_request.yml",
            "product_defect.yml",
            "release_blocker.yml",
        }
        forms = {path.name: yaml.safe_load(path.read_text(encoding="utf-8")) for path in form_directory.glob("*.yml")}

        self.assertTrue(expected <= set(forms))
        self.assertFalse(forms["config.yml"]["blank_issues_enabled"])
        for name, form in forms.items():
            if name != "config.yml":
                self.assertTrue(set(form["labels"]) <= policy_labels)
                self.assertIn("authority:github", form["labels"])
                self.assertNotIn(COMPLETION_REQUIRED_LABEL, form["labels"])
                self.assertIn("priority:untriaged", form["labels"])

    def test_cross_repository_form_exposes_every_qualified_target(self) -> None:
        form = yaml.safe_load(
            (ROOT / ".github" / "ISSUE_TEMPLATE" / "cross_repository.yml").read_text(encoding="utf-8")
        )
        qualification = qualification_fixture()
        affected = next(field for field in form["body"] if field.get("id") == "affected")
        expected = {
            f"durable-workflow/{target['repository']}@{target['branch']}"
            for target in qualification["targets"].values()
        }

        self.assertEqual("dropdown", affected["type"])
        self.assertTrue(affected["attributes"]["multiple"])
        self.assertEqual(expected, set(affected["attributes"]["options"]))

    def test_authority_jobs_are_limited_to_the_canonical_github_host(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "issue-authority.yml").read_text(encoding="utf-8"))
        conditions = {
            job: " ".join(workflow["jobs"][job]["if"].split())
            for job in ("validate", "intake", "apply", "audit")
        }

        self.assertEqual(
            "${{ github.event_name != 'issues' || github.server_url == 'https://github.com' }}",
            conditions["validate"],
        )
        self.assertEqual(
            "${{ github.server_url == 'https://github.com' && "
            "(github.event_name == 'push' || github.event_name == 'schedule' || "
            "github.event_name == 'issues' || github.event_name == 'workflow_dispatch') }}",
            conditions["intake"],
        )
        self.assertEqual(
            "${{ github.ref == 'refs/heads/main' && github.server_url == 'https://github.com' && "
            "needs.intake.outputs.intake_ready == 'true' && (github.event_name == 'push' || "
            "(github.event_name == 'workflow_dispatch' && inputs.mode == 'apply')) }}",
            conditions["apply"],
        )
        self.assertEqual(
            "${{ github.ref == 'refs/heads/main' && github.server_url == 'https://github.com' && "
            "needs.intake.outputs.intake_ready == 'true' && (github.event_name == 'schedule' || "
            "(github.event_name == 'issues' && needs.intake.outputs.trigger_approved == 'true') || "
            "(github.event_name == 'workflow_dispatch' && inputs.mode == 'audit')) }}",
            conditions["audit"],
        )

    def test_public_and_local_issue_events_have_isolated_concurrency(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "issue-authority.yml").read_text(encoding="utf-8"))
        concurrency = workflow["concurrency"]

        self.assertEqual(
            "${{ github.server_url == 'https://github.com' && "
            "'github-issue-authority-public' || "
            "format('github-issue-authority-local-{0}-{1}', "
            "github.repository, github.event.issue.number) }}",
            " ".join(concurrency["group"].split()),
        )
        self.assertEqual(
            "${{ github.server_url != 'https://github.com' && github.event_name == 'issues' }}",
            concurrency["cancel-in-progress"],
        )

    def test_unapproved_events_cannot_reach_a_privileged_environment(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "issue-authority.yml").read_text(encoding="utf-8"))
        intake = workflow["jobs"]["intake"]

        self.assertNotIn("environment", intake)
        self.assertEqual({"contents": "read", "issues": "read"}, intake["permissions"])
        self.assertNotIn("BETA_PRODUCT_WORK_TOKEN", json.dumps(intake))
        self.assertEqual("${{ github.token }}", intake["steps"][-1]["env"]["GITHUB_TOKEN"])
        for name in ("apply", "audit"):
            job = workflow["jobs"][name]
            self.assertEqual("beta-product-work", job["environment"])
            self.assertEqual(
                {
                    "checks": "read",
                    "contents": "read",
                    "issues": "read",
                    "pull-requests": "read",
                },
                job["permissions"],
            )
            self.assertIn("intake", job["needs"])
            self.assertNotIn("PUBLIC_ISSUE_DISCOVERY_TOKEN", json.dumps(job))
            self.assertIn("GITHUB_TOKEN", json.dumps(job))
            self.assertIn("BETA_PRODUCT_WORK_TOKEN", json.dumps(job))

    def test_comments_and_pull_request_content_are_not_event_inputs(self) -> None:
        source = (ROOT / ".github" / "workflows" / "issue-authority.yml").read_text(encoding="utf-8")

        self.assertNotIn("issue_comment:", source)
        self.assertNotIn("pull_request:", source)
        self.assertNotIn("pull_request_target:", source)
        self.assertIn("types: [opened, edited, closed, reopened, labeled, unlabeled, milestoned, demilestoned]", source)

    def test_every_external_action_is_immutably_pinned(self) -> None:
        source = (ROOT / ".github" / "workflows" / "issue-authority.yml").read_text(encoding="utf-8")
        invocations = re.findall(r"^\s+uses:\s+(actions/[^\s@]+)@([^\s]+)(?:\s+#\s+(.+))?$", source, re.MULTILINE)

        self.assertTrue(invocations)
        for action, revision, version in invocations:
            with self.subTest(action=action):
                self.assertRegex(revision, r"^[0-9a-f]{40}$")
                self.assertRegex(version or "", r"^v[0-9]+$")


class IssueIntakeTest(unittest.TestCase):
    trusted = ["rmcdaniel", "durable-workflow-ops"]

    def assess(self, issue: dict[str, Any], timeline: list[dict[str, Any]]) -> dict[str, Any]:
        return assess_issue_intake(
            issue,
            timeline,
            approval_label="intake:approved",
            trusted_actors=self.trusted,
        )

    def test_trusted_creation_is_vetted_without_a_label(self) -> None:
        issue = intake_issue(author="rmcdaniel")

        assessment = self.assess(issue, [])

        self.assertTrue(assessment["approved"])
        self.assertEqual("trusted-creation", assessment["approval_mode"])
        self.assertEqual(issue_revision_digest(issue["title"], issue["body"]), assessment["revision"])

    def test_external_creation_is_inert(self) -> None:
        assessment = self.assess(intake_issue(), [])

        self.assertFalse(assessment["approved"])
        self.assertEqual("approval-label-absent", assessment["reason"])

    def test_unapproved_body_is_never_fetched_for_revision_binding(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        discovery = FakeDiscovery(policy, {".github": [(intake_issue(), [])]})

        manifest, inventory = reconstruct_intake(policy, discovery)

        self.assertEqual([], manifest["issues"])
        self.assertEqual([], inventory[".github"])
        self.assertEqual([], discovery.get_requests)

    def test_only_a_trusted_latest_label_actor_can_approve(self) -> None:
        issue = intake_issue(labels=["intake:approved"])
        trusted = self.assess(issue, [label_event("durable-workflow-ops", "2026-07-21T10:01:00Z")])
        untrusted = self.assess(issue, [label_event("external-contributor", "2026-07-21T10:01:00Z")])

        self.assertTrue(trusted["approved"])
        self.assertEqual("durable-workflow-ops", trusted["approval_actor"])
        self.assertFalse(untrusted["approved"])
        self.assertEqual("approval-actor-untrusted", untrusted["reason"])

    def test_post_approval_edit_invalidates_the_revision(self) -> None:
        issue = intake_issue(
            body="Edited body",
            edited_at="2026-07-21T10:02:00Z",
            labels=["intake:approved"],
        )

        assessment = self.assess(issue, [label_event("rmcdaniel", "2026-07-21T10:01:00Z")])

        self.assertFalse(assessment["approved"])
        self.assertEqual("approval-predates-revision", assessment["reason"])

    def test_title_rename_after_approval_invalidates_the_revision(self) -> None:
        issue = intake_issue(labels=["intake:approved"])
        timeline = [
            label_event("rmcdaniel", "2026-07-21T10:01:00Z"),
            {"created_at": "2026-07-21T10:02:00Z", "event": "renamed"},
        ]

        assessment = self.assess(issue, timeline)

        self.assertFalse(assessment["approved"])
        self.assertEqual("approval-predates-revision", assessment["reason"])

    def test_label_removal_invalidates_approval(self) -> None:
        issue = intake_issue()
        timeline = [
            label_event("rmcdaniel", "2026-07-21T10:01:00Z"),
            label_event("rmcdaniel", "2026-07-21T10:02:00Z", event="unlabeled"),
        ]

        assessment = self.assess(issue, timeline)

        self.assertFalse(assessment["approved"])
        self.assertEqual("approval-label-absent", assessment["reason"])

    def test_reapproval_binds_the_new_revision_digest(self) -> None:
        original = intake_issue(labels=["intake:approved"])
        original_assessment = self.assess(original, [label_event("rmcdaniel", "2026-07-21T10:01:00Z")])
        edited = intake_issue(
            body="A newly reviewed body",
            edited_at="2026-07-21T10:02:00Z",
            labels=["intake:approved"],
        )
        timeline = [
            label_event("rmcdaniel", "2026-07-21T10:01:00Z"),
            label_event("rmcdaniel", "2026-07-21T10:02:30Z", event="unlabeled"),
            label_event("rmcdaniel", "2026-07-21T10:03:00Z"),
        ]

        edited_assessment = self.assess(edited, timeline)

        self.assertTrue(edited_assessment["approved"])
        self.assertNotEqual(original_assessment["revision"], edited_assessment["revision"])

    def test_clean_machine_reconstruction_is_deterministic_and_reverified(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        issue = intake_issue(author="rmcdaniel")
        issues = {".github": [(issue, [])]}

        first, first_inventory = reconstruct_intake(policy, FakeDiscovery(policy, issues))
        second, _second_inventory = reconstruct_intake(policy, FakeDiscovery(policy, issues))

        self.assertEqual(INTAKE_SCHEMA, first["schema"])
        self.assertEqual(first, second)
        self.assertEqual([issue], first_inventory[".github"])
        verified = verify_intake_manifest(policy, first, FakeDiscovery(policy, issues))
        self.assertEqual(first_inventory, verified)

    def test_completion_hold_is_bound_as_structured_intake_authority(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        issue = intake_issue(author="rmcdaniel", labels=[COMPLETION_REQUIRED_LABEL])
        manifest, _inventory = reconstruct_intake(
            policy,
            FakeDiscovery(policy, {".github": [(issue, [])]}),
        )

        self.assertTrue(manifest["issues"][0]["completion_evidence_required"])

        current = copy.deepcopy(issue)
        current["labels"] = []
        verified = verify_intake_manifest(
            policy,
            manifest,
            FakeDiscovery(policy, {".github": [(current, [])]}),
        )

        self.assertNotIn(COMPLETION_REQUIRED_LABEL, label_names(verified[".github"][0]))

    def test_prerelease_supersession_binds_both_trusted_issue_revisions(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture(include_supersessions=True)
        retired = prerelease_authority_issue(59)
        successor = prerelease_authority_issue(61, body="Coherent replacement train")
        issues = {".github": [(retired, []), (successor, [])]}
        manifest, inventory = reconstruct_intake(
            policy,
            FakeDiscovery(policy, issues),
        )

        records = {(record["repository"], record["number"]): record for record in manifest["issues"]}
        superseded_by = records[(".github", 59)]["superseded_by"]
        self.assertEqual(".github", superseded_by["repository"])
        self.assertEqual(61, superseded_by["number"])
        self.assertEqual(
            records[(".github", 61)]["revision"],
            superseded_by["revision"],
        )
        self.assertIsNone(records[(".github", 61)]["superseded_by"])
        self.assertEqual(
            inventory,
            verify_intake_manifest(
                policy,
                manifest,
                FakeDiscovery(policy, issues),
            ),
        )

    def test_untrusted_retired_issue_cannot_activate_prerelease_supersession(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture(include_supersessions=True)
        retired = prerelease_authority_issue(59, author="external-contributor")
        successor = prerelease_authority_issue(61)

        with self.assertRaisesRegex(AuthorityError, "does not have trusted current-revision intake"):
            reconstruct_intake(
                policy,
                FakeDiscovery(policy, {".github": [(retired, []), (successor, [])]}),
            )

    def test_manifest_cannot_redirect_a_bound_prerelease_successor(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture(include_supersessions=True)
        retired = prerelease_authority_issue(59)
        successor = prerelease_authority_issue(61)
        issues = {".github": [(retired, []), (successor, [])]}
        manifest, _inventory = reconstruct_intake(
            policy,
            FakeDiscovery(policy, issues),
        )
        retired_record = next(record for record in manifest["issues"] if record["number"] == 59)
        retired_record["superseded_by"]["number"] = 62

        with self.assertRaisesRegex(AuthorityError, "changed after read-only discovery"):
            verify_intake_manifest(
                policy,
                manifest,
                FakeDiscovery(policy, issues),
            )

    def test_closed_successor_cannot_receive_active_prerelease_authority(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture(include_supersessions=True)
        retired = prerelease_authority_issue(59)
        successor = prerelease_authority_issue(
            61,
            state="closed",
            status="status:done",
        )

        with self.assertRaisesRegex(AuthorityError, "is not an active evidence-required blocker"):
            reconstruct_intake(
                policy,
                FakeDiscovery(policy, {".github": [(retired, []), (successor, [])]}),
            )

    def test_cross_repository_targets_are_bound_from_the_vetted_form_section(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        qualification = qualification_fixture()
        issue = intake_issue(
            author="rmcdaniel",
            body=(
                "### Required source targets\n\n"
                "durable-workflow/.github@main\n"
                "durable-workflow/workflow@v2\n\n"
                "### Repository roles\n\nShared authority and consumer.\n"
            ),
            labels=["kind:cross-repository"],
        )
        discovery = FakeDiscovery(policy, {".github": [(issue, [])]})

        manifest, inventory = reconstruct_intake(
            policy,
            discovery,
            target_qualification=qualification,
        )
        targets = manifest["issues"][0]["cross_repository_targets"]

        self.assertEqual([".github", "workflow"], [target["repository"] for target in targets])
        self.assertEqual(["main", "v2"], [target["branch"] for target in targets])
        self.assertTrue(all(target["required_checks"] for target in targets))
        self.assertEqual(
            inventory,
            verify_intake_manifest(
                policy,
                manifest,
                FakeDiscovery(policy, {".github": [(issue, [])]}),
                target_qualification=qualification,
            ),
        )

    def test_api_and_issue_form_target_headings_use_the_same_contract(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        qualification = qualification_fixture()

        for heading in ("## Required source targets", "### Required source targets"):
            with self.subTest(heading=heading):
                issue = intake_issue(
                    author="rmcdaniel",
                    body=(
                        f"{heading}\n\n"
                        "durable-workflow/.github@main\n"
                        "durable-workflow/workflow@v2\n\n"
                        "## Repository roles\n\nShared authority and consumer.\n"
                    ),
                    labels=["kind:cross-repository"],
                )
                manifest, _inventory = reconstruct_intake(
                    policy,
                    FakeDiscovery(policy, {".github": [(issue, [])]}),
                    target_qualification=qualification,
                )

                self.assertEqual(
                    [".github", "workflow"],
                    [target["repository"] for target in manifest["issues"][0]["cross_repository_targets"]],
                )

    def test_cross_repository_intake_rejects_invalid_target_sets(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        qualification = qualification_fixture()
        invalid_bodies = {
            "missing": ("Current body", "must declare its required source targets"),
            "empty": (
                "### Required source targets\n\n### Repository roles\n\nShared authority.",
                "at least two public targets",
            ),
            "single": (
                "### Required source targets\n\ndurable-workflow/.github@main",
                "at least two public targets",
            ),
            "duplicate": (
                "### Required source targets\n\ndurable-workflow/.github@main\ndurable-workflow/.github@main",
                "duplicate target",
            ),
            "unqualified": (
                "### Required source targets\n\ndurable-workflow/.github@main\ndurable-workflow/workflow@main",
                "not a qualified target",
            ),
            "repeated-section": (
                "## Required source targets\n\n"
                "durable-workflow/.github@main\n"
                "durable-workflow/workflow@v2\n\n"
                "### Required source targets\n\n"
                "durable-workflow/.github@main\n"
                "durable-workflow/server@main",
                "repeats its affected public repositories section",
            ),
        }

        for name, (body, message) in invalid_bodies.items():
            with self.subTest(name=name):
                issue = intake_issue(
                    author="rmcdaniel",
                    body=body,
                    labels=["kind:cross-repository"],
                )
                discovery = FakeDiscovery(policy, {".github": [(issue, [])]})

                with self.assertRaisesRegex(AuthorityError, message):
                    reconstruct_intake(
                        policy,
                        discovery,
                        target_qualification=qualification,
                    )

    def test_non_cross_repository_intake_rejects_multiple_targets(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        issue = intake_issue(
            author="rmcdaniel",
            body=("### Required source targets\n\ndurable-workflow/.github@main\ndurable-workflow/workflow@v2"),
        )

        with self.assertRaisesRegex(AuthorityError, "without cross-repository authority"):
            reconstruct_intake(
                policy,
                FakeDiscovery(policy, {".github": [(issue, [])]}),
                target_qualification=qualification_fixture(),
            )

    def test_legacy_cross_repository_authority_requires_edit_and_reapproval(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        legacy = intake_issue(
            author="rmcdaniel",
            labels=["kind:cross-repository"],
        )

        with self.assertRaisesRegex(AuthorityError, "must declare its required source targets"):
            reconstruct_intake(
                policy,
                FakeDiscovery(policy, {".github": [(legacy, [])]}),
                target_qualification=qualification_fixture(),
            )

        migrated = intake_issue(
            author="rmcdaniel",
            body=("### Required source targets\n\ndurable-workflow/.github@main\ndurable-workflow/workflow@v2"),
            edited_at="2026-07-21T10:02:00Z",
            labels=["intake:approved", "kind:cross-repository"],
        )
        manifest, _inventory = reconstruct_intake(
            policy,
            FakeDiscovery(
                policy,
                {
                    ".github": [
                        (
                            migrated,
                            [
                                label_event(
                                    "durable-workflow-ops",
                                    "2026-07-21T10:02:30Z",
                                    event="unlabeled",
                                ),
                                label_event("durable-workflow-ops", "2026-07-21T10:03:00Z"),
                            ],
                        )
                    ]
                },
            ),
            target_qualification=qualification_fixture(),
        )

        self.assertEqual(2, len(manifest["issues"][0]["cross_repository_targets"]))

    def test_captured_legacy_active_and_closed_revisions_use_exact_migrated_targets(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        active = intake_issue(
            author="rmcdaniel",
            body=(
                "Approved API-created authority.\n\n"
                "<!-- durable-workflow-work-id: version-component-release-recovery-consumer-conformance -->"
            ),
            labels=["authority:github", "kind:cross-repository", "priority:P1", "status:ready"],
            number=40,
        )
        active_hygiene = intake_issue(
            author="durable-workflow-ops",
            body=(
                "## Required source targets\n\n"
                "durable-workflow/.github@main\n"
                "durable-workflow/cli@main\n"
                "durable-workflow/durable-workflow.github.io@main\n"
                "durable-workflow/sample-app@main\n"
                "durable-workflow/sdk-php@main\n"
                "durable-workflow/sdk-python@main\n"
                "durable-workflow/sdk-rust@main\n"
                "durable-workflow/server@main\n"
                "durable-workflow/waterline@v2\n"
                "durable-workflow/workflow@v2\n\n"
                "### Repository roles\n\nActive public source hygiene."
            ),
            edited_at="2026-07-25T02:05:00Z",
            labels=[
                "authority:github",
                "intake:approved",
                "kind:cross-repository",
                "priority:P2",
                "status:ready",
            ],
            number=42,
        )
        closed = intake_issue(
            author="rmcdaniel",
            body=(
                "Completed trusted-created authority.\n\n"
                "<!-- durable-workflow-work-id: github-actions-trust-boundary -->"
            ),
            labels=["authority:github", "kind:cross-repository", "priority:P1", "status:done"],
            number=39,
        )
        closed["state"] = "closed"
        migration = legacy_target_fixture()
        closed_targets = next(
            authority["targets"]
            for authority in migration["authorities"]
            if authority["id"] == "github-actions-trust-boundary"
        )
        migration["historical_completions"] = [
            {
                "number": 39,
                "repository": ".github",
                "revision": issue_revision_digest(closed["title"], closed["body"]),
                "targets": closed_targets,
            }
        ]
        evolved_qualification = qualification_fixture()
        control_plane = next(
            target for target in evolved_qualification["targets"].values() if target["repository"] == ".github"
        )
        control_plane["workflows"][0]["required_check"] = "Renamed control-plane qualification"
        control_plane["workflows"].append(
            {
                "matrix_independent": True,
                "path": "future-qualification.yml",
                "required_check": "Additional control-plane qualification",
            }
        )
        issues = {
            ".github": [
                (closed, []),
                (active, []),
                (active_hygiene, [label_event("durable-workflow-ops", "2026-07-25T02:06:00Z")]),
            ]
        }

        manifest, inventory = reconstruct_intake(
            policy,
            FakeDiscovery(policy, issues),
            target_qualification=evolved_qualification,
            legacy_cross_repository_targets=migration,
        )

        records = {record["number"]: record for record in manifest["issues"]}
        self.assertEqual(8, len(records[40]["cross_repository_targets"]))
        self.assertEqual(10, len(records[42]["cross_repository_targets"]))
        self.assertEqual(10, len(records[39]["cross_repository_targets"]))
        self.assertEqual(10, len(records[39]["historical_cross_repository_completion"]))
        self.assertEqual([], records[40]["historical_cross_repository_completion"])
        self.assertEqual([], records[42]["historical_cross_repository_completion"])
        self.assertEqual("trusted-creation", records[40]["approval_mode"])
        self.assertEqual("trusted-label", records[42]["approval_mode"])
        current_control_plane = next(
            target for target in records[40]["cross_repository_targets"] if target["repository"] == ".github"
        )
        archived_control_plane = next(
            target
            for target in records[39]["historical_cross_repository_completion"]
            if target["repository"] == ".github"
        )
        self.assertEqual(
            ["Additional control-plane qualification", "Renamed control-plane qualification"],
            current_control_plane["required_checks"],
        )
        self.assertEqual(["Control-plane source qualification"], archived_control_plane["required_checks"])
        self.assertEqual(
            inventory,
            verify_intake_manifest(
                policy,
                manifest,
                FakeDiscovery(policy, issues),
                target_qualification=evolved_qualification,
                legacy_cross_repository_targets=migration,
            ),
        )

    def test_edited_api_created_revision_uses_its_declared_targets_not_legacy_migration(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        issue = intake_issue(
            author="rmcdaniel",
            body=(
                "## Required source targets\n\n"
                "durable-workflow/.github@main\n"
                "durable-workflow/workflow@v2\n"
                "durable-workflow/waterline@v2\n"
                "durable-workflow/server@main\n"
                "durable-workflow/cli@main\n"
                "durable-workflow/sdk-php@main\n"
                "durable-workflow/sdk-python@main\n"
                "durable-workflow/sdk-rust@main\n\n"
                "### Repository roles\n\nActive source and consumers."
            ),
            edited_at="2026-07-25T01:59:00Z",
            labels=["intake:approved", "kind:cross-repository"],
            number=52,
        )
        timeline = [label_event("rmcdaniel", "2026-07-25T02:00:00Z")]

        manifest, _inventory = reconstruct_intake(
            policy,
            FakeDiscovery(policy, {".github": [(issue, timeline)]}),
            target_qualification=qualification_fixture(),
            legacy_cross_repository_targets=legacy_target_fixture(),
        )

        record = manifest["issues"][0]
        self.assertEqual("trusted-label", record["approval_mode"])
        self.assertEqual(8, len(record["cross_repository_targets"]))
        self.assertEqual([], record["historical_cross_repository_completion"])

    def test_legacy_issue_form_revision_migrates_its_bounded_repository_set(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        issue = intake_issue(
            author="rmcdaniel",
            body=(
                "### Affected public repositories\n\n"
                "- `durable-workflow/.github` owns the decision.\n"
                "- `durable-workflow/workflow` consumes it.\n\n"
                "### Shared public contract\n\nLegacy form revision."
            ),
            labels=["kind:cross-repository"],
        )

        manifest, _inventory = reconstruct_intake(
            policy,
            FakeDiscovery(policy, {".github": [(issue, [])]}),
            target_qualification=qualification_fixture(),
            legacy_cross_repository_targets=legacy_target_fixture(),
        )

        self.assertEqual(
            [".github", "workflow"],
            [target["repository"] for target in manifest["issues"][0]["cross_repository_targets"]],
        )

    def test_legacy_target_migration_cannot_authorize_later_revisions_or_relabels(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        body = (
            "Legacy authority.\n\n"
            "<!-- durable-workflow-work-id: version-component-release-recovery-consumer-conformance -->"
        )
        cases: dict[str, tuple[dict[str, Any], list[dict[str, Any]]]] = {}

        created_late = intake_issue(
            author="rmcdaniel",
            body=body,
            labels=["kind:cross-repository"],
        )
        created_late["created_at"] = "2026-07-25T00:02:00Z"
        cases["created-after-cutoff"] = (created_late, [])

        edited = intake_issue(
            author="rmcdaniel",
            body=body,
            edited_at="2026-07-25T00:02:00Z",
            labels=["intake:approved", "kind:cross-repository"],
        )
        cases["edited-and-reapproved"] = (
            edited,
            [label_event("rmcdaniel", "2026-07-25T00:03:00Z")],
        )

        relabeled = intake_issue(
            author="rmcdaniel",
            body=body,
            labels=["kind:cross-repository"],
        )
        cases["relabeled-after-cutoff"] = (
            relabeled,
            [
                label_event(
                    "rmcdaniel",
                    "2026-07-25T00:03:00Z",
                    label="kind:cross-repository",
                )
            ],
        )

        for name, (issue, timeline) in cases.items():
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(AuthorityError, "must declare its required source targets"),
            ):
                reconstruct_intake(
                    policy,
                    FakeDiscovery(policy, {".github": [(issue, timeline)]}),
                    target_qualification=qualification_fixture(),
                    legacy_cross_repository_targets=legacy_target_fixture(),
                )

    def test_manifest_revalidation_rejects_cross_repository_label_without_targets(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        issue = intake_issue(author="rmcdaniel")
        manifest, _inventory = reconstruct_intake(
            policy,
            FakeDiscovery(policy, {".github": [(issue, [])]}),
            target_qualification=qualification_fixture(),
        )
        relabeled = copy.deepcopy(issue)
        relabeled["labels"] = [{"name": "kind:cross-repository"}]

        with self.assertRaisesRegex(AuthorityError, "must declare its required source targets"):
            verify_intake_manifest(
                policy,
                manifest,
                FakeDiscovery(policy, {".github": [(relabeled, [])]}),
                target_qualification=qualification_fixture(),
            )

    def test_completion_hold_manifest_field_must_be_boolean(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        issue = intake_issue(author="rmcdaniel")
        discovery = FakeDiscovery(policy, {".github": [(issue, [])]})
        manifest, _inventory = reconstruct_intake(policy, discovery)
        manifest["issues"][0]["completion_evidence_required"] = "false"

        with self.assertRaisesRegex(AuthorityError, "invalid issue authority"):
            verify_intake_manifest(policy, manifest, discovery)

    def test_historical_completion_manifest_field_must_be_a_list(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        issue = intake_issue(author="rmcdaniel")
        discovery = FakeDiscovery(policy, {".github": [(issue, [])]})
        manifest, _inventory = reconstruct_intake(policy, discovery)
        manifest["issues"][0]["historical_cross_repository_completion"] = "complete"

        with self.assertRaisesRegex(AuthorityError, "invalid issue authority"):
            verify_intake_manifest(policy, manifest, discovery)

    def test_concurrent_unselected_trusted_issue_remains_inert_during_revalidation(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        selected = intake_issue(author="rmcdaniel")
        manifest, _inventory = reconstruct_intake(
            policy,
            FakeDiscovery(policy, {".github": [(selected, [])]}),
        )
        concurrent = intake_issue(author="durable-workflow-ops", body="Later issue", number=2)
        discovery = FakeDiscovery(policy, {".github": [(selected, []), (concurrent, [])]})

        verified = verify_intake_manifest(policy, manifest, discovery)

        self.assertEqual([selected], verified[".github"])
        self.assertEqual([], discovery.list_requests)
        self.assertEqual([(".github", 1)], discovery.get_requests)

    def test_selected_issue_revision_change_fails_manifest_revalidation(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        selected = intake_issue(author="rmcdaniel")
        manifest, _inventory = reconstruct_intake(
            policy,
            FakeDiscovery(policy, {".github": [(selected, [])]}),
        )
        changed = {".github": [(copy.deepcopy(selected), [])]}
        changed[".github"][0][0]["body"] = "Changed after discovery"
        changed[".github"][0][0]["last_edited_at"] = "2026-07-21T10:05:00Z"
        with self.assertRaisesRegex(AuthorityError, "changed after read-only discovery"):
            verify_intake_manifest(policy, manifest, FakeDiscovery(policy, changed))

    def test_edited_trigger_fails_closed_during_api_convergence(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        issue = intake_issue(author="rmcdaniel")
        issues = {".github": [(issue, [])]}
        discovery = FakeDiscovery(policy, issues)

        manifest, _inventory = reconstruct_intake(
            policy,
            discovery,
            trigger_repository=".github",
            trigger_number=1,
            trigger_action="edited",
        )

        self.assertFalse(manifest["trigger"]["approved"])
        self.assertEqual("revision-edited", manifest["trigger"]["reason"])
        self.assertEqual([], discovery.get_requests)

    def test_approval_label_removal_fails_closed_during_api_convergence(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        issue = intake_issue(labels=["intake:approved"])
        issues = {".github": [(issue, [label_event("rmcdaniel", "2026-07-21T10:01:00Z")])]}
        discovery = FakeDiscovery(policy, issues)

        manifest, _inventory = reconstruct_intake(
            policy,
            discovery,
            trigger_repository=".github",
            trigger_number=1,
            trigger_action="unlabeled",
            trigger_actor="external-contributor",
            trigger_label="intake:approved",
        )

        self.assertFalse(manifest["trigger"]["approved"])
        self.assertEqual("approval-label-removed", manifest["trigger"]["reason"])
        self.assertEqual([], discovery.get_requests)

    def test_untrusted_approval_actor_fails_closed_during_api_convergence(self) -> None:
        policy, _backlog, _policy_schema, _backlog_schema = contract_fixture()
        issue = intake_issue(labels=["intake:approved"])
        issues = {".github": [(issue, [label_event("rmcdaniel", "2026-07-21T10:01:00Z")])]}
        discovery = FakeDiscovery(policy, issues)

        manifest, _inventory = reconstruct_intake(
            policy,
            discovery,
            trigger_repository=".github",
            trigger_number=1,
            trigger_action="labeled",
            trigger_actor="external-contributor",
            trigger_label="intake:approved",
        )

        self.assertFalse(manifest["trigger"]["approved"])
        self.assertEqual("approval-actor-untrusted", manifest["trigger"]["reason"])
        self.assertEqual([], discovery.get_requests)


class GitHubApiTest(unittest.TestCase):
    def test_discovery_uses_the_read_only_job_token(self) -> None:
        client = GitHubDiscovery("job-token")
        response = FakeResponse(b'{"data":{"repository":{"issues":{"nodes":[],"pageInfo":{"hasNextPage":false}}}}}')

        with patch("urllib.request.urlopen", return_value=response) as urlopen:
            self.assertEqual([], client.list_issues("durable-workflow", "workflow"))

        request = urlopen.call_args.args[0]
        self.assertEqual("Bearer job-token", request.get_header("Authorization"))
        self.assertEqual("POST", request.method)

    def test_lifecycle_reads_captured_graphql_closing_reference_shape(self) -> None:
        client = GitHubApi(
            "writer-token",
            read_token="job-token",
            graphql_url="https://api.github.test/graphql",
        )
        payload = (ROOT / "tests/fixtures/github/cross-referenced-events.json").read_bytes()

        with patch("urllib.request.urlopen", return_value=FakeResponse(payload)) as urlopen:
            references = client.list_issue_closing_references("durable-workflow", ".github", 99)

        self.assertEqual(["CRE_kwDOA1b2c84AAZ9x", "CRE_kwDOA1b2c84AAaB7"], [event["id"] for event in references])
        request = urlopen.call_args.args[0]
        body = json.loads(request.data)
        self.assertEqual("https://api.github.test/graphql", request.full_url)
        self.assertEqual("Bearer job-token", request.get_header("Authorization"))
        self.assertEqual(
            {"cursor": None, "number": 99, "owner": "durable-workflow", "repository": ".github"},
            body["variables"],
        )
        self.assertIn("... on CrossReferencedEvent", body["query"])
        self.assertIn("willCloseTarget", body["query"])

    def test_create_request_is_not_repeated_after_an_ambiguous_failure(self) -> None:
        client = GitHubApi("secret")
        responses = [
            urllib.error.URLError(ConnectionResetError("response lost")),
            FakeResponse(b'{"number":1}'),
        ]

        with (
            patch("urllib.request.urlopen", side_effect=responses) as urlopen,
            self.assertRaisesRegex(AuthorityError, "failed after bounded retries"),
        ):
            client.request("POST", "/repos/durable-workflow/.github/issues", {"title": "work"})

        self.assertEqual(1, urlopen.call_count)

    def test_lifecycle_reads_use_the_job_token_while_mutations_use_the_writer(self) -> None:
        client = GitHubApi("writer-token", read_token="job-token")
        responses = [FakeResponse(b'{"state":"open"}'), FakeResponse(b"")]

        with patch("urllib.request.urlopen", side_effect=responses) as urlopen:
            client.request("GET", "/repos/durable-workflow/workflow")
            client.request("PATCH", "/repos/durable-workflow/.github/issues/1", {"state": "open"})

        read_request = urlopen.call_args_list[0].args[0]
        write_request = urlopen.call_args_list[1].args[0]
        self.assertEqual("Bearer job-token", read_request.get_header("Authorization"))
        self.assertEqual("Bearer writer-token", write_request.get_header("Authorization"))

    def test_lifecycle_upsert_ignores_external_marker_copies_before_and_after_generated_comment(self) -> None:
        client = GitHubApi("writer-token", read_token="job-token")
        generated_body = f"{EVIDENCE_MARKER}\nCurrent lifecycle evidence.\n"
        comments = [
            {
                "body": f"{EVIDENCE_MARKER}\nExternal copy before.\n",
                "id": 10,
                "user": {"id": 100, "login": "external-before"},
            },
            {
                "body": f"{EVIDENCE_MARKER}\nOutdated lifecycle evidence.\n",
                "id": 11,
                "user": {"id": 7, "login": "durable-workflow-ops"},
            },
            {
                "body": f"{EVIDENCE_MARKER}\nExternal copy after.\n",
                "id": 12,
                "user": {"id": 101, "login": "external-after"},
            },
        ]
        responses = [
            FakeResponse(json.dumps(comments).encode()),
            FakeResponse(b'{"id":7,"login":"durable-workflow-ops"}'),
            FakeResponse(b""),
        ]

        with patch("urllib.request.urlopen", side_effect=responses) as urlopen:
            client.upsert_lifecycle_comment(
                "durable-workflow",
                ".github",
                47,
                EVIDENCE_MARKER,
                generated_body,
            )

        comment_read, identity_read, update = [call.args[0] for call in urlopen.call_args_list]
        self.assertEqual("Bearer job-token", comment_read.get_header("Authorization"))
        self.assertEqual("Bearer writer-token", identity_read.get_header("Authorization"))
        self.assertEqual("https://api.github.com/user", identity_read.full_url)
        self.assertEqual("PATCH", update.method)
        self.assertEqual("https://api.github.com/repos/durable-workflow/.github/issues/comments/11", update.full_url)
        self.assertEqual("Bearer writer-token", update.get_header("Authorization"))

    def test_lifecycle_upsert_does_not_trust_matching_login_with_wrong_writer_id(self) -> None:
        client = GitHubApi("writer-token", read_token="job-token")
        generated_body = f"{EVIDENCE_MARKER}\nCurrent lifecycle evidence.\n"
        comments = [
            {
                "body": generated_body,
                "id": 10,
                "user": {"id": 8, "login": "durable-workflow-ops"},
            }
        ]
        responses = [
            FakeResponse(json.dumps(comments).encode()),
            FakeResponse(b'{"id":7,"login":"durable-workflow-ops"}'),
            FakeResponse(b'{"id":11}'),
        ]

        with patch("urllib.request.urlopen", side_effect=responses) as urlopen:
            client.upsert_lifecycle_comment(
                "durable-workflow",
                ".github",
                47,
                EVIDENCE_MARKER,
                generated_body,
            )

        create = urlopen.call_args_list[2].args[0]
        self.assertEqual("POST", create.method)
        self.assertEqual("https://api.github.com/repos/durable-workflow/.github/issues/47/comments", create.full_url)

    def test_lifecycle_upsert_rejects_multiple_generated_comments_from_authenticated_writer(self) -> None:
        client = GitHubApi("writer-token", read_token="job-token")
        comments = [
            {
                "body": f"{EVIDENCE_MARKER}\nFirst generated comment.\n",
                "id": 10,
                "user": {"id": 7, "login": "durable-workflow-ops"},
            },
            {
                "body": f"{EVIDENCE_MARKER}\nSecond generated comment.\n",
                "id": 11,
                "user": {"id": 7, "login": "durable-workflow-ops"},
            },
        ]
        responses = [
            FakeResponse(json.dumps(comments).encode()),
            FakeResponse(b'{"id":7,"login":"durable-workflow-ops"}'),
        ]

        with (
            patch("urllib.request.urlopen", side_effect=responses) as urlopen,
            self.assertRaisesRegex(AuthorityError, "duplicate cross-repository lifecycle evidence"),
        ):
            client.upsert_lifecycle_comment(
                "durable-workflow",
                ".github",
                47,
                EVIDENCE_MARKER,
                f"{EVIDENCE_MARKER}\nCurrent lifecycle evidence.\n",
            )

        self.assertEqual(2, urlopen.call_count)

    def test_read_request_retries_transient_transport_failure(self) -> None:
        client = GitHubApi("secret")
        responses = [
            urllib.error.URLError(ConnectionResetError("connection reset")),
            FakeResponse(b'{"state":"open"}'),
        ]

        with (
            patch("urllib.request.urlopen", side_effect=responses) as urlopen,
            patch("scripts.issue_authority.time.sleep") as sleep,
        ):
            result = client.request("GET", "/repos/durable-workflow/.github")

        self.assertEqual({"state": "open"}, result)
        self.assertEqual(2, urlopen.call_count)
        sleep.assert_called_once_with(2.0)


class MigrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy, self.backlog, _policy_schema, _backlog_schema = contract_fixture()
        self.client = FakeGitHubApi(self.policy)

    def clear_mutation_spies(self) -> None:
        self.client.label_updates.clear()
        self.client.milestone_updates.clear()
        self.client.created_issues.clear()
        self.client.replacements.clear()
        self.client.body_updates.clear()
        self.client.state_updates.clear()
        self.client.comment_updates.clear()

    def assert_no_github_mutations(self) -> None:
        self.assertEqual([], self.client.label_updates)
        self.assertEqual([], self.client.milestone_updates)
        self.assertEqual([], self.client.created_issues)
        self.assertEqual([], self.client.replacements)
        self.assertEqual([], self.client.body_updates)
        self.assertEqual([], self.client.state_updates)
        self.assertEqual([], self.client.comment_updates)

    def test_apply_creates_only_reviewed_items_with_dependencies(self) -> None:
        evidence = apply_backlog(self.policy, self.backlog, self.client)

        self.assertEqual("pass", evidence["outcome"])
        self.assertEqual(4, sum(len(issues) for issues in self.client.issues.values()))
        expected_labels = {label["name"] for label in self.policy["labels"]}
        for repository in self.policy["repositories"]:
            self.assertEqual(expected_labels, set(self.client.labels[repository]))
        for item in self.backlog["items"]:
            repository, issue = find_work_item(self.client, item["id"])
            self.assertEqual(item["repository"], repository)
            self.assertEqual("open", issue["state"])
            self.assertEqual("2.0 beta", issue["milestone"]["title"])
            self.assertIn(OWNER_LABELS[repository], label_names(issue))
            self.assertNotIn(COMPLETION_REQUIRED_LABEL, label_names(issue))
            if item["kind"] == "cross-repository":
                targets = declared_targets(
                    issue["body"],
                    qualification_targets(qualification_fixture()),
                    organization=self.policy["organization"],
                    required=True,
                )
                self.assertEqual(
                    sorted(item["required_source_targets"]),
                    sorted(
                        f"{self.policy['organization']}/{target['repository']}@{target['branch']}" for target in targets
                    ),
                )

        _repository, authorization = find_work_item(self.client, "authorize-2-0-beta")
        _drill_repository, drill = find_work_item(self.client, "github-only-beta-continuity-drill")
        _release_repository, release = find_work_item(self.client, "release-plan-versioned-changelogs")
        self.assertIn(drill["html_url"], authorization["body"])
        self.assertNotIn(UNBLOCK_CONTEXT_START, release["body"])
        self.assertNotIn("## Unblock condition", release["body"])
        self.assertEqual({"status:ready"}, label_names(release) & STATUS_LABELS)

    def test_apply_advances_the_existing_dependency_free_issue_without_duplication(self) -> None:
        blocked_backlog = copy.deepcopy(self.backlog)
        blocked_item = mark_release_item_blocked(blocked_backlog)
        apply_backlog(self.policy, blocked_backlog, self.client)
        repository, issue = find_work_item(self.client, blocked_item["id"])
        issue["body"] = issue["body"].replace("## Problem", "Maintainer context.\n\n## Problem")
        blocker_context = (
            f"{UNBLOCK_CONTEXT_START}\n## Unblock condition\n\n{REVIEWED_BLOCK_CONDITION}\n{UNBLOCK_CONTEXT_END}"
        )
        expected_body = issue["body"].replace(f"\n\n{blocker_context}", "")
        issue_number = issue["number"]

        evidence = apply_backlog(self.policy, self.backlog, self.client)

        self.assertEqual("transitioned-to-ready", evidence["issues"][blocked_item["id"]]["action"])
        self.assertEqual(issue_number, issue["number"])
        self.assertEqual(4, sum(len(issues) for issues in self.client.issues.values()))
        self.assertEqual({"status:ready"}, label_names(issue) & STATUS_LABELS)
        self.assertEqual(expected_body, issue["body"])
        self.assertNotIn(UNBLOCK_CONTEXT_START, issue["body"])
        self.assertIn("## Dependencies\n\nNone.", issue["body"])
        self.assertIn((repository, issue_number, sorted(label_names(issue))), self.client.replacements)

        replacement_count = len(self.client.replacements)
        body_update_count = len(self.client.body_updates)
        replay_evidence = apply_backlog(self.policy, self.backlog, self.client)

        self.assertEqual("preserved", replay_evidence["issues"][blocked_item["id"]]["action"])
        self.assertEqual(replacement_count, len(self.client.replacements))
        self.assertEqual(body_update_count, len(self.client.body_updates))
        self.assertEqual(4, sum(len(issues) for issues in self.client.issues.values()))

    def test_replay_restores_machine_owned_unblock_context_without_losing_edits(self) -> None:
        mark_release_item_blocked(self.backlog)
        apply_backlog(self.policy, self.backlog, self.client)
        repository, issue = find_work_item(self.client, "release-plan-versioned-changelogs")
        replace_unblock_context(issue, "")
        issue["body"] = issue["body"].replace("## Problem", "Maintainer context.\n\n## Problem")
        issue["state"] = "closed"
        issue["labels"] = [
            {"name": "status:done" if label["name"] in STATUS_LABELS else label["name"]} for label in issue["labels"]
        ]
        issue["labels"].append({"name": COMPLETION_VERIFIED_LABEL})
        expected_labels = copy.deepcopy(issue["labels"])

        evidence = apply_backlog(self.policy, self.backlog, self.client)

        self.assertEqual("updated-blocker-context", evidence["issues"]["release-plan-versioned-changelogs"]["action"])
        self.assertIn("Maintainer context.", issue["body"])
        self.assertIn(self.backlog["items"][0]["unblock_condition"], issue["body"])
        self.assertEqual("closed", issue["state"])
        self.assertEqual(expected_labels, issue["labels"])
        self.assertEqual(1, len(self.client.body_updates))

        replay_evidence = apply_backlog(self.policy, self.backlog, self.client)

        self.assertEqual("preserved", replay_evidence["issues"]["release-plan-versioned-changelogs"]["action"])
        self.assertEqual(1, len(self.client.body_updates))

    def test_replay_replaces_one_valid_unblock_context_without_losing_edits(self) -> None:
        mark_release_item_blocked(self.backlog)
        apply_backlog(self.policy, self.backlog, self.client)
        _repository, issue = find_work_item(self.client, "release-plan-versioned-changelogs")
        stale_context = (
            f"{UNBLOCK_CONTEXT_START}\n## Unblock condition\n\nStale reviewed condition.\n{UNBLOCK_CONTEXT_END}"
        )
        replace_unblock_context(issue, stale_context)
        issue["body"] = issue["body"].replace("## Problem", "Maintainer context.\n\n## Problem")
        issue["state"] = "closed"
        issue["labels"] = [
            {"name": "status:done" if label["name"] in STATUS_LABELS else label["name"]} for label in issue["labels"]
        ]
        issue["labels"].append({"name": COMPLETION_VERIFIED_LABEL})
        expected_labels = copy.deepcopy(issue["labels"])

        evidence = apply_backlog(self.policy, self.backlog, self.client)

        self.assertEqual("updated-blocker-context", evidence["issues"]["release-plan-versioned-changelogs"]["action"])
        self.assertIn("Maintainer context.", issue["body"])
        self.assertNotIn("Stale reviewed condition.", issue["body"])
        self.assertIn(self.backlog["items"][0]["unblock_condition"], issue["body"])
        self.assertEqual("closed", issue["state"])
        self.assertEqual(expected_labels, issue["labels"])
        self.assertEqual(1, len(self.client.body_updates))

        replay_evidence = apply_backlog(self.policy, self.backlog, self.client)

        self.assertEqual("preserved", replay_evidence["issues"]["release-plan-versioned-changelogs"]["action"])
        self.assertEqual(1, len(self.client.body_updates))

    def test_apply_rejects_malformed_unblock_context_before_issue_mutation(self) -> None:
        mark_release_item_blocked(self.backlog)
        valid_context = f"{UNBLOCK_CONTEXT_START}\n## Unblock condition\n\nReviewed condition.\n{UNBLOCK_CONTEXT_END}"
        malformed_contexts = {
            "reversed": f"{UNBLOCK_CONTEXT_END}\nReviewed condition.\n{UNBLOCK_CONTEXT_START}",
            "repeated": f"{valid_context}\n\n{valid_context}",
            "nested": (
                f"{UNBLOCK_CONTEXT_START}\n{UNBLOCK_CONTEXT_START}\nReviewed condition.\n"
                f"{UNBLOCK_CONTEXT_END}\n{UNBLOCK_CONTEXT_END}"
            ),
            "start-only": f"{UNBLOCK_CONTEXT_START}\nReviewed condition.",
            "end-only": f"Reviewed condition.\n{UNBLOCK_CONTEXT_END}",
            "inline-start": f"prefix {UNBLOCK_CONTEXT_START}\nReviewed condition.\n{UNBLOCK_CONTEXT_END}",
            "inline-end": f"{UNBLOCK_CONTEXT_START}\nReviewed condition.\n{UNBLOCK_CONTEXT_END} suffix",
            "same-line": f"{UNBLOCK_CONTEXT_START} Reviewed condition. {UNBLOCK_CONTEXT_END}",
        }

        for name, malformed_context in malformed_contexts.items():
            with self.subTest(name=name):
                client = FakeGitHubApi(self.policy)
                apply_backlog(self.policy, self.backlog, client)
                _repository, issue = find_work_item(client, "release-plan-versioned-changelogs")
                replace_unblock_context(issue, malformed_context)
                client.body_updates.clear()
                client.replacements.clear()
                issues_before = copy.deepcopy(client.issues)

                with self.assertRaisesRegex(AuthorityError, "malformed unblock condition context"):
                    apply_backlog(self.policy, self.backlog, client)

                self.assertEqual(issues_before, client.issues)
                self.assertEqual([], client.body_updates)
                self.assertEqual([], client.replacements)

    def test_audit_rejects_malformed_unblock_context_before_issue_mutation(self) -> None:
        mark_release_item_blocked(self.backlog)
        apply_backlog(self.policy, self.backlog, self.client)
        _repository, issue = find_work_item(self.client, "release-plan-versioned-changelogs")
        replace_unblock_context(
            issue,
            f"{UNBLOCK_CONTEXT_END}\nReviewed condition.\n{UNBLOCK_CONTEXT_START}",
        )
        self.client.body_updates.clear()
        self.client.replacements.clear()
        issues_before = copy.deepcopy(self.client.issues)

        with self.assertRaisesRegex(AuthorityError, "malformed unblock condition context"):
            audit_backlog(self.policy, self.backlog, self.client)

        self.assertEqual(issues_before, self.client.issues)
        self.assertEqual([], self.client.body_updates)
        self.assertEqual([], self.client.replacements)

    def test_replay_preserves_github_edits_and_closed_state(self) -> None:
        apply_backlog(self.policy, self.backlog, self.client)
        repository, issue = find_work_item(self.client, "github-only-beta-continuity-drill")
        issue["title"] = "Maintainer refined title"
        issue["body"] = issue["body"].replace("## Scope", "## Maintainer rationale\n\nDurable decision.\n\n## Scope")
        issue["state"] = "closed"
        issue["labels"] = [
            {"name": "status:done" if label["name"] in STATUS_LABELS else label["name"]}
            for label in issue["labels"]
            if label["name"] not in STATUS_LABELS or label["name"] == "status:ready"
        ]
        issue["labels"].append({"name": COMPLETION_VERIFIED_LABEL})

        evidence = apply_backlog(self.policy, self.backlog, self.client)

        self.assertEqual("preserved", evidence["issues"]["github-only-beta-continuity-drill"]["action"])
        self.assertEqual("closed", evidence["issues"]["github-only-beta-continuity-drill"]["state"])
        self.assertEqual("Maintainer refined title", issue["title"])
        self.assertIn("Durable decision.", issue["body"])
        self.assertEqual(4, sum(len(issues) for issues in self.client.issues.values()))
        self.assertEqual(repository, ".github")

    def test_duplicate_marker_is_labeled_and_fails_before_creation(self) -> None:
        apply_backlog(self.policy, self.backlog, self.client)
        repository, issue = find_work_item(self.client, "release-plan-versioned-changelogs")
        duplicate = copy.deepcopy(issue)
        duplicate["number"] = 99
        duplicate["html_url"] = f"https://github.com/durable-workflow/{repository}/issues/99"
        self.client.issues[repository].append(duplicate)

        with self.assertRaisesRegex(AuthorityError, "appears on 2 GitHub issues"):
            apply_backlog(self.policy, self.backlog, self.client)

        self.assertIn("authority:conflict", label_names(issue))
        self.assertIn("authority:conflict", label_names(duplicate))
        self.assertEqual(5, sum(len(issues) for issues in self.client.issues.values()))

    def test_apply_rejects_distinct_markers_before_any_github_mutation(self) -> None:
        apply_backlog(self.policy, self.backlog, self.client)
        repository, issue = find_work_item(self.client, "release-plan-versioned-changelogs")
        alias_repository, alias = find_work_item(self.client, "authorize-2-0-beta")
        self.assertEqual(repository, alias_repository)
        self.client.issues[alias_repository].remove(alias)
        issue["body"] += "\n<!-- beta-work-id: authorize-2-0-beta -->\n"
        self.backlog["items"][3]["unblock_condition"] = "A separate reviewed condition must remain independent."
        self.client.labels[repository]["authority:github"]["description"] = "Stale label definition"
        self.client.milestones[repository]["2.0 beta"]["description"] = "Stale milestone definition"
        self.clear_mutation_spies()
        issues_before = copy.deepcopy(self.client.issues)
        labels_before = copy.deepcopy(self.client.labels)
        milestones_before = copy.deepcopy(self.client.milestones)

        with self.assertRaises(AuthorityError) as raised:
            apply_backlog(self.policy, self.backlog, self.client)

        message = str(raised.exception)
        self.assertIn(f"{repository}#{issue['number']}", message)
        self.assertIn("release-plan-versioned-changelogs", message)
        self.assertIn("authorize-2-0-beta", message)
        self.assertEqual(issues_before, self.client.issues)
        self.assertEqual(labels_before, self.client.labels)
        self.assertEqual(milestones_before, self.client.milestones)
        self.assert_no_github_mutations()

    def test_audit_rejects_distinct_markers_before_any_github_mutation(self) -> None:
        apply_backlog(self.policy, self.backlog, self.client)
        repository, issue = find_work_item(self.client, "release-plan-versioned-changelogs")
        alias_repository, alias = find_work_item(self.client, "github-only-beta-continuity-drill")
        self.assertEqual(repository, alias_repository)
        self.client.issues[alias_repository].remove(alias)
        issue["body"] += "\n<!-- beta-work-id: github-only-beta-continuity-drill -->\n"
        self.client.labels[repository]["authority:github"]["description"] = "Stale label definition"
        self.client.milestones[repository]["2.0 beta"]["description"] = "Stale milestone definition"
        self.clear_mutation_spies()
        issues_before = copy.deepcopy(self.client.issues)
        labels_before = copy.deepcopy(self.client.labels)
        milestones_before = copy.deepcopy(self.client.milestones)

        with self.assertRaises(AuthorityError) as raised:
            audit_backlog(self.policy, self.backlog, self.client)

        message = str(raised.exception)
        self.assertIn(f"{repository}#{issue['number']}", message)
        self.assertIn("release-plan-versioned-changelogs", message)
        self.assertIn("github-only-beta-continuity-drill", message)
        self.assertEqual(issues_before, self.client.issues)
        self.assertEqual(labels_before, self.client.labels)
        self.assertEqual(milestones_before, self.client.milestones)
        self.assert_no_github_mutations()

    def test_audit_fails_when_a_selected_issue_is_missing(self) -> None:
        apply_backlog(self.policy, self.backlog, self.client)
        repository, issue = find_work_item(self.client, "docs-php-conformance-public-authority")
        self.client.issues[repository].remove(issue)

        with self.assertRaisesRegex(AuthorityError, "has no GitHub issue"):
            audit_backlog(self.policy, self.backlog, self.client)

    def test_explicit_unverified_completion_hold_is_reopened_and_fails_visibly(self) -> None:
        apply_backlog(self.policy, self.backlog, self.client)
        repository, issue = find_work_item(self.client, "github-only-beta-continuity-drill")
        issue["labels"].append({"name": COMPLETION_REQUIRED_LABEL})
        issue["state"] = "closed"

        with self.assertRaisesRegex(
            AuthorityError,
            "closed before its required public completion evidence was verified",
        ):
            audit_backlog(self.policy, self.backlog, self.client)

        self.assertEqual({"status:ready"}, label_names(issue) & STATUS_LABELS)
        self.assertEqual("open", issue["state"])
        self.assertIn((repository, issue["number"], "open"), self.client.state_updates)

    def test_valid_prerelease_supersession_is_terminal_without_false_completion(self) -> None:
        for item in self.backlog["items"]:
            if item["kind"] == "cross-repository":
                item["kind"] = "feature"
        apply_backlog(self.policy, self.backlog, self.client)
        retired = prerelease_authority_issue(59)
        retired["labels"] = [
            {"name": "kind:cross-repository" if label["name"] == "kind:release-blocker" else label["name"]}
            for label in retired["labels"]
        ]
        successor = prerelease_authority_issue(61, body="Coherent synchronized replacement train")
        self.client.issues[".github"].extend((retired, successor))
        targets = qualification_targets(qualification_fixture())
        successor_revision = issue_revision_digest(successor["title"], successor["body"])
        supersessions = {
            (".github", 59): {
                "number": 61,
                "reason": "An immutable artifact mismatch requires the replacement train.",
                "repository": ".github",
                "revision": successor_revision,
            }
        }
        self.clear_mutation_spies()

        evidence = audit_backlog(
            self.policy,
            self.backlog,
            self.client,
            approved_completion_holds={(".github", 59), (".github", 61)},
            cross_repository_targets={
                (".github", 59): [targets[".github"], targets["workflow"]],
            },
            prerelease_supersessions=supersessions,
        )

        self.assertEqual("pass", evidence["outcome"])
        self.assertEqual("closed", retired["state"])
        self.assertEqual({SUPERSEDED_STATUS_LABEL}, label_names(retired) & STATUS_LABELS)
        self.assertIn(COMPLETION_REQUIRED_LABEL, label_names(retired))
        self.assertNotIn(COMPLETION_VERIFIED_LABEL, label_names(retired))
        self.assertNotIn("status:done", label_names(retired))
        self.assertEqual("open", successor["state"])
        self.assertEqual({"status:ready"}, label_names(successor) & STATUS_LABELS)
        self.assertEqual([], self.client.timeline_reads)
        self.assertIn((".github", 59, "closed"), self.client.state_updates)
        comment = self.client.comments[(".github", 59)]
        self.assertIn(SUPERSESSION_EVIDENCE_MARKER, comment)
        self.assertIn("https://github.com/durable-workflow/.github/issues/61", comment)
        self.assertEqual("superseded", evidence["prerelease_supersessions"][0]["state"])
        self.assertEqual(successor_revision, evidence["prerelease_supersessions"][0]["successor"]["revision"])

        self.clear_mutation_spies()
        repeated = audit_backlog(
            self.policy,
            self.backlog,
            self.client,
            approved_completion_holds={(".github", 59), (".github", 61)},
            cross_repository_targets={
                (".github", 59): [targets[".github"], targets["workflow"]],
            },
            prerelease_supersessions=supersessions,
        )

        self.assertEqual("pass", repeated["outcome"])
        self.assertEqual("closed", retired["state"])
        self.assertEqual({SUPERSEDED_STATUS_LABEL}, label_names(retired) & STATUS_LABELS)
        self.assertEqual([], self.client.timeline_reads)
        self.assert_no_github_mutations()

    def test_verified_public_completion_evidence_allows_closed_state_to_win(self) -> None:
        apply_backlog(self.policy, self.backlog, self.client)
        _repository, issue = find_work_item(self.client, "github-only-beta-continuity-drill")
        issue["state"] = "closed"
        issue["labels"] = [
            {"name": "status:done" if label["name"] in STATUS_LABELS else label["name"]} for label in issue["labels"]
        ]
        issue["labels"].append({"name": COMPLETION_VERIFIED_LABEL})
        self.clear_mutation_spies()

        evidence = audit_backlog(self.policy, self.backlog, self.client)

        self.assertEqual("pass", evidence["outcome"])
        self.assertEqual("closed", evidence["issues"]["github-only-beta-continuity-drill"]["state"])
        self.assert_no_github_mutations()

    def test_completion_shaped_prose_does_not_create_an_evidence_hold(self) -> None:
        apply_backlog(self.policy, self.backlog, self.client)
        _repository, issue = find_work_item(self.client, "github-only-beta-continuity-drill")
        issue["body"] = "## Completion\n\n## Delete when\n\n## Acceptance\n\n" + issue["body"]
        issue["state"] = "closed"
        issue["labels"] = [
            {"name": "status:done" if label["name"] in STATUS_LABELS else label["name"]} for label in issue["labels"]
        ]
        self.clear_mutation_spies()

        evidence = audit_backlog(self.policy, self.backlog, self.client)

        self.assertEqual("pass", evidence["outcome"])
        self.assertEqual("closed", evidence["issues"]["github-only-beta-continuity-drill"]["state"])
        self.assertNotIn(COMPLETION_REQUIRED_LABEL, label_names(issue))
        self.assert_no_github_mutations()

    def test_removed_completion_hold_is_not_readded_by_default(self) -> None:
        apply_backlog(self.policy, self.backlog, self.client)
        _repository, issue = find_work_item(self.client, "github-only-beta-continuity-drill")
        issue["labels"].append({"name": COMPLETION_REQUIRED_LABEL})
        issue["labels"] = [label for label in issue["labels"] if label["name"] != COMPLETION_REQUIRED_LABEL]
        self.clear_mutation_spies()

        evidence = audit_backlog(self.policy, self.backlog, self.client)

        self.assertEqual("pass", evidence["outcome"])
        self.assertNotIn(COMPLETION_REQUIRED_LABEL, label_names(issue))
        self.assert_no_github_mutations()

    def test_approved_intake_completion_hold_is_restored(self) -> None:
        apply_backlog(self.policy, self.backlog, self.client)
        repository, issue = find_work_item(self.client, "github-only-beta-continuity-drill")
        self.clear_mutation_spies()

        evidence = audit_backlog(
            self.policy,
            self.backlog,
            self.client,
            approved_completion_holds={(repository, issue["number"])},
        )

        self.assertEqual("pass", evidence["outcome"])
        self.assertIn(COMPLETION_REQUIRED_LABEL, label_names(issue))
        self.assertIn((repository, issue["number"], sorted(label_names(issue))), self.client.replacements)
        self.assertEqual([], self.client.state_updates)

    def test_corrected_apply_converges_all_mutated_archived_states(self) -> None:
        for item in self.backlog["items"]:
            if item["kind"] == "cross-repository":
                item["kind"] = "feature"
        self.client.issues[".github"] = [
            {
                "body": "Unrelated public issue.",
                "html_url": f"https://github.com/durable-workflow/.github/issues/{number}",
                "labels": [],
                "milestone": None,
                "number": number,
                "state": "open",
                "title": "Unrelated public issue",
            }
            for number in range(1, 61)
        ]
        apply_backlog(self.policy, self.backlog, self.client)
        migration = legacy_target_fixture()
        qualified = qualification_targets(qualification_fixture())
        target_sets: dict[tuple[str, int], list[dict[str, Any]]] = {}
        completion_sets: dict[tuple[str, int], list[dict[str, Any]]] = {}
        parents: list[dict[str, Any]] = []
        for completion in migration["historical_completions"]:
            identity = (completion["repository"], completion["number"])
            repositories = [target.split("/", 1)[1].rsplit("@", 1)[0] for target in completion["targets"]]
            landings = historical_landing_fixture(*repositories)
            target_sets[identity] = [dict(qualified[repository]) for repository in repositories]
            completion_sets[identity] = landings
            parent = {
                "body": "Archived cross-repository authority.",
                "html_url": (
                    f"https://github.com/durable-workflow/{completion['repository']}/issues/{completion['number']}"
                ),
                "labels": [
                    {"name": "authority:github"},
                    {"name": "kind:cross-repository"},
                    {"name": "priority:P1"},
                    {"name": "status:triage"},
                ],
                "milestone": None,
                "number": completion["number"],
                "state": "open",
                "title": "Archived public work",
            }
            placeholder = next(
                issue
                for issue in self.client.issues[completion["repository"]]
                if issue["number"] == completion["number"]
            )
            placeholder.clear()
            placeholder.update(parent)
            parents.append(placeholder)
            self.client.comments[identity] = (
                f"{EVIDENCE_MARKER}\n"
                "Cross-repository landing evidence:\n\n"
                "The parent remains open until every declared target is complete.\n"
            )
            for landing in landings:
                self.client.reachable.add((landing["repository"], landing["commit"], landing["branch"]))
                self.client.successful_checks[(landing["repository"], landing["commit"])] = set(
                    landing["required_checks"]
                )
        self.clear_mutation_spies()

        evidence = apply_backlog(
            self.policy,
            self.backlog,
            self.client,
            cross_repository_targets=target_sets,
            historical_cross_repository_completions=completion_sets,
        )

        self.assertEqual("pass", evidence["outcome"])
        self.assertTrue(all(parent["state"] == "closed" for parent in parents))
        self.assertTrue(all(label_names(parent) & STATUS_LABELS == {"status:done"} for parent in parents))
        self.assertEqual(
            {(repository, number, "closed") for repository, number in completion_sets},
            set(self.client.state_updates),
        )
        self.assertEqual(
            set(completion_sets),
            {(repository, number) for repository, number, _labels in self.client.replacements},
        )
        self.assertEqual([], self.client.comment_updates)
        self.assertEqual([], self.client.created_issues)
        self.assertEqual([], self.client.body_updates)
        self.assertEqual(10, len(self.client.reachability_requests))
        self.assertEqual(10, len(self.client.check_requests))

    def test_corrected_apply_preserves_already_restored_archived_state(self) -> None:
        for item in self.backlog["items"]:
            if item["kind"] == "cross-repository":
                item["kind"] = "feature"
        apply_backlog(self.policy, self.backlog, self.client)
        parent = {
            "body": "Archived cross-repository authority.",
            "html_url": "https://github.com/durable-workflow/.github/issues/99",
            "labels": [
                {"name": "authority:github"},
                {"name": "kind:cross-repository"},
                {"name": "priority:P1"},
                {"name": "status:done"},
            ],
            "milestone": None,
            "number": 99,
            "state": "closed",
            "title": "Archived public work",
        }
        self.client.issues[".github"].append(parent)
        landings = historical_landing_fixture(".github", "workflow")
        for landing in landings:
            self.client.reachable.add((landing["repository"], landing["commit"], landing["branch"]))
            self.client.successful_checks[(landing["repository"], landing["commit"])] = set(landing["required_checks"])
        targets = [{key: value for key, value in landing.items() if key != "commit"} for landing in landings]
        self.clear_mutation_spies()

        evidence = apply_backlog(
            self.policy,
            self.backlog,
            self.client,
            cross_repository_targets={(".github", 99): targets},
            historical_cross_repository_completions={(".github", 99): landings},
        )

        self.assertEqual("pass", evidence["outcome"])
        self.assertEqual("closed", parent["state"])
        self.assertEqual({"status:done"}, label_names(parent) & STATUS_LABELS)
        self.assert_no_github_mutations()

    def test_archived_completion_ignores_later_required_check_rename_and_addition(self) -> None:
        for item in self.backlog["items"]:
            if item["kind"] == "cross-repository":
                item["kind"] = "feature"
        apply_backlog(self.policy, self.backlog, self.client)
        parent = {
            "body": "Archived cross-repository authority.",
            "html_url": "https://github.com/durable-workflow/.github/issues/99",
            "labels": [
                {"name": "authority:github"},
                {"name": "kind:cross-repository"},
                {"name": "priority:P1"},
                {"name": "status:done"},
            ],
            "milestone": None,
            "number": 99,
            "state": "closed",
            "title": "Archived public work",
        }
        self.client.issues[".github"].append(parent)
        landings = historical_landing_fixture(".github", "workflow")
        for landing in landings:
            self.client.reachable.add((landing["repository"], landing["commit"], landing["branch"]))
            self.client.successful_checks[(landing["repository"], landing["commit"])] = set(landing["required_checks"])
        targets = [{key: value for key, value in landing.items() if key != "commit"} for landing in landings]
        targets[0]["required_checks"] = [
            "Additional control-plane qualification",
            "Renamed control-plane qualification",
        ]
        self.clear_mutation_spies()

        evidence = audit_backlog(
            self.policy,
            self.backlog,
            self.client,
            cross_repository_targets={(".github", 99): targets},
            historical_cross_repository_completions={(".github", 99): landings},
        )

        self.assertEqual("pass", evidence["outcome"])
        self.assertEqual("closed", parent["state"])
        self.assertEqual({"status:done"}, label_names(parent) & STATUS_LABELS)
        self.assert_no_github_mutations()

    def test_missing_frozen_historical_check_fails_without_reopening_archived_work(self) -> None:
        for item in self.backlog["items"]:
            if item["kind"] == "cross-repository":
                item["kind"] = "feature"
        apply_backlog(self.policy, self.backlog, self.client)
        parent = {
            "body": "Archived cross-repository authority.",
            "html_url": "https://github.com/durable-workflow/.github/issues/39",
            "labels": [
                {"name": "authority:github"},
                {"name": "kind:cross-repository"},
                {"name": "priority:P1"},
                {"name": "status:done"},
            ],
            "milestone": None,
            "number": 39,
            "state": "closed",
            "title": "Archived public work",
        }
        self.client.issues[".github"].append(parent)
        landings = historical_landing_fixture(".github", "workflow")
        for landing in landings:
            self.client.reachable.add((landing["repository"], landing["commit"], landing["branch"]))
        self.client.successful_checks[(landings[0]["repository"], landings[0]["commit"])] = set(
            landings[0]["required_checks"]
        )
        targets = [{key: value for key, value in landing.items() if key != "commit"} for landing in landings]
        self.clear_mutation_spies()

        with self.assertRaisesRegex(AuthorityError, "historical completion evidence failed revalidation"):
            audit_backlog(
                self.policy,
                self.backlog,
                self.client,
                cross_repository_targets={(".github", 39): targets},
                historical_cross_repository_completions={(".github", 39): landings},
            )

        self.assertEqual("closed", parent["state"])
        self.assertEqual({"status:done"}, label_names(parent) & STATUS_LABELS)
        self.assert_no_github_mutations()

    def test_cross_repository_parent_ignores_untrusted_noise_and_accepts_a_trusted_rebuild(self) -> None:
        for item in self.backlog["items"]:
            if item["kind"] == "cross-repository":
                item["kind"] = "feature"
        apply_backlog(self.policy, self.backlog, self.client)
        qualification = qualification_fixture()

        def target(repository: str) -> dict[str, Any]:
            value = next(value for value in qualification["targets"].values() if value["repository"] == repository)
            return {
                "branch": value["branch"],
                "repository": repository,
                "required_checks": sorted({workflow["required_check"] for workflow in value["workflows"]}),
            }

        parent = {
            "body": "Vetted cross-repository work.",
            "html_url": "https://github.com/durable-workflow/.github/issues/99",
            "labels": [
                {"name": "authority:github"},
                {"name": "kind:cross-repository"},
                {"name": "priority:P1"},
                {"name": "status:ready"},
            ],
            "milestone": None,
            "number": 99,
            "state": "closed",
            "title": "Coordinate source landings",
        }
        self.client.issues[".github"].append(parent)
        source_commit = "a" * 40
        peer_commit = "b" * 40
        self.client.timelines[(".github", 99)] = [
            closing_reference("workflow", 50, actor="external-contributor"),
            closing_reference(".github", 51),
            closing_reference("workflow", 52),
        ]
        self.client.pulls[("workflow", 50)] = pull_request(
            "workflow",
            50,
            "v2",
            author="external-contributor",
            author_association="NONE",
            created_at="2026-07-24T11:00:00Z",
            head_repository="external-contributor/workflow",
            state="closed",
        )
        self.client.pulls[(".github", 51)] = pull_request(
            ".github",
            51,
            "main",
            created_at="2026-07-24T10:00:00Z",
            commit=source_commit,
        )
        self.client.pulls[("workflow", 52)] = pull_request(
            "workflow",
            52,
            "v2",
            created_at="2026-07-24T10:01:00Z",
        )
        self.client.reachable.add((".github", source_commit, "main"))
        self.client.successful_checks[(".github", source_commit)] = set(target(".github")["required_checks"])
        declared = {(".github", 99): [target(".github"), target("workflow")]}

        with self.assertRaisesRegex(AuthorityError, "before every declared target landing"):
            audit_backlog(
                self.policy,
                self.backlog,
                self.client,
                cross_repository_targets=declared,
            )

        self.assertEqual("open", parent["state"])
        self.assertEqual({"status:ready"}, label_names(parent) & STATUS_LABELS)
        self.assertIn(EVIDENCE_MARKER, self.client.comments[(".github", 99)])
        self.assertIn("pending:open", self.client.comments[(".github", 99)])
        self.assertNotIn("/pull/50", self.client.comments[(".github", 99)])
        self.assertIn("trusted-author:durable-workflow-ops", self.client.comments[(".github", 99)])
        self.assertIn("reference actor `durable-workflow-ops`", self.client.comments[(".github", 99)])

        self.client.pulls[("workflow", 52)] = pull_request(
            "workflow",
            52,
            "v2",
            created_at="2026-07-24T10:01:00Z",
            commit=peer_commit,
        )
        self.client.reachable.add(("workflow", peer_commit, "v2"))

        qualification_pending = audit_backlog(
            self.policy,
            self.backlog,
            self.client,
            cross_repository_targets=declared,
        )

        self.assertEqual("pass", qualification_pending["outcome"])
        self.assertEqual("open", parent["state"])
        self.assertIn("pending:qualification", self.client.comments[(".github", 99)])

        self.client.successful_checks[("workflow", peer_commit)] = set(target("workflow")["required_checks"])

        evidence = audit_backlog(
            self.policy,
            self.backlog,
            self.client,
            cross_repository_targets=declared,
        )

        self.assertEqual("pass", evidence["outcome"])
        self.assertEqual("closed", parent["state"])
        self.assertEqual({"status:done"}, label_names(parent) & STATUS_LABELS)
        self.assertIn("Every declared target landing", self.client.comments[(".github", 99)])

        self.client.timelines[(".github", 99)].append(closing_reference("workflow", 53, actor="public-noise"))
        self.client.pulls[("workflow", 53)] = pull_request(
            "workflow",
            53,
            "v2",
            author="public-noise",
            author_association="NONE",
            created_at="2026-07-24T11:00:00Z",
            head_repository="public-noise/workflow",
            state="closed",
        )

        untrusted_evidence = audit_backlog(
            self.policy,
            self.backlog,
            self.client,
            cross_repository_targets=declared,
        )
        self.assertEqual("pass", untrusted_evidence["outcome"])
        self.assertEqual("closed", parent["state"])
        self.assertIn("/pull/52", self.client.comments[(".github", 99)])
        self.assertNotIn("/pull/53", self.client.comments[(".github", 99)])

        self.client.timelines[(".github", 99)].append(closing_reference("workflow", 54, will_close_target=False))
        self.client.pulls[("workflow", 54)] = pull_request(
            "workflow",
            54,
            "v2",
            created_at="2026-07-24T12:00:00Z",
            state="closed",
        )

        unrelated_evidence = audit_backlog(
            self.policy,
            self.backlog,
            self.client,
            cross_repository_targets=declared,
        )
        self.assertEqual("pass", unrelated_evidence["outcome"])
        self.assertEqual("closed", parent["state"])

        self.client.timelines[(".github", 99)].append(closing_reference("workflow", 55))
        self.client.pulls[("workflow", 55)] = pull_request(
            "workflow",
            55,
            "v2",
            created_at="2026-07-24T13:00:00Z",
            state="closed",
        )

        with self.assertRaisesRegex(AuthorityError, "before every declared target landing"):
            audit_backlog(
                self.policy,
                self.backlog,
                self.client,
                cross_repository_targets=declared,
            )
        self.assertEqual("open", parent["state"])
        self.assertIn("pending:rejected", self.client.comments[(".github", 99)])
        self.assertIn("/pull/55", self.client.comments[(".github", 99)])

        rejected_evidence = audit_backlog(
            self.policy,
            self.backlog,
            self.client,
            cross_repository_targets=declared,
        )
        self.assertEqual("pass", rejected_evidence["outcome"])
        self.assertEqual("open", parent["state"])

        rebuilt_commit = "c" * 40
        self.client.timelines[(".github", 99)].append(closing_reference("workflow", 56))
        self.client.pulls[("workflow", 56)] = pull_request(
            "workflow",
            56,
            "v2",
            created_at="2026-07-24T14:00:00Z",
            commit=rebuilt_commit,
        )
        self.client.reachable.add(("workflow", rebuilt_commit, "v2"))
        self.client.successful_checks[("workflow", rebuilt_commit)] = set(target("workflow")["required_checks"])

        rebuilt_evidence = audit_backlog(
            self.policy,
            self.backlog,
            self.client,
            cross_repository_targets=declared,
        )
        self.assertEqual("pass", rebuilt_evidence["outcome"])
        self.assertEqual("closed", parent["state"])
        self.assertEqual({"status:done"}, label_names(parent) & STATUS_LABELS)
        self.assertNotIn(COMPLETION_REQUIRED_LABEL, label_names(parent))

    def test_closing_reference_changes_during_assessment_remain_pending(self) -> None:
        cases = {
            "removed": lambda source, _external: [source],
            "reintroduced": lambda source, _external: [
                source,
                closing_reference(
                    "workflow",
                    70,
                    actor="external-contributor",
                    created_at="2026-07-24T10:00:00Z",
                    identifier="CRE_kwDOA1b2c84A0071",
                ),
            ],
            "retargeted": lambda source, _external: [
                source,
                closing_reference(
                    "server",
                    71,
                    actor="external-contributor",
                    created_at="2026-07-24T10:00:00Z",
                    identifier="CRE_kwDOA1b2c84A0072",
                ),
            ],
        }
        for name, changed_references in cases.items():
            with self.subTest(name=name):
                policy, backlog, client, parent, declared, source_reference, external_reference = (
                    closing_reference_race_fixture()
                )
                initial = [source_reference, external_reference]
                changed = changed_references(source_reference, external_reference)
                client.timeline_sequences[(".github", 99)] = [initial, changed, changed]

                evidence = audit_backlog(
                    policy,
                    backlog,
                    client,
                    cross_repository_targets=declared,
                )

                self.assertEqual("pass", evidence["outcome"])
                self.assertEqual("open", parent["state"])
                self.assertNotIn("status:done", label_names(parent))
                self.assertIn("The parent remains open", client.comments[(".github", 99)])
                self.assertNotIn("Every declared target landing", client.comments[(".github", 99)])
                self.assertEqual(4, client.timeline_reads.count((".github", 99)))

    def test_unchanged_external_reference_with_fresh_exact_head_approval_completes(self) -> None:
        policy, backlog, client, parent, declared, source_reference, external_reference = (
            closing_reference_race_fixture()
        )
        client.timelines[(".github", 99)] = [source_reference, external_reference]

        evidence = audit_backlog(
            policy,
            backlog,
            client,
            cross_repository_targets=declared,
        )

        self.assertEqual("pass", evidence["outcome"])
        self.assertEqual("closed", parent["state"])
        self.assertEqual({"status:done"}, label_names(parent) & STATUS_LABELS)
        self.assertIn("Every declared target landing", client.comments[(".github", 99)])
        self.assertIn("approval review `1` at `2026-07-24T09:30:00Z`", client.comments[(".github", 99)])
        self.assertEqual(4, client.timeline_reads.count((".github", 99)))

    def test_nonconvergent_reference_snapshot_stops_at_the_retry_bound(self) -> None:
        policy, backlog, client, parent, declared, source_reference, external_reference = (
            closing_reference_race_fixture()
        )
        unchanged = [source_reference, external_reference]
        removed = [source_reference]
        client.timeline_sequences[(".github", 99)] = [unchanged, removed, unchanged, removed]

        evidence = audit_backlog(
            policy,
            backlog,
            client,
            cross_repository_targets=declared,
        )

        self.assertEqual("pass", evidence["outcome"])
        self.assertEqual("open", parent["state"])
        self.assertNotIn("status:done", label_names(parent))
        self.assertIn("pending:closing-reference-changed", client.comments[(".github", 99)])
        self.assertNotIn("Every declared target landing", client.comments[(".github", 99)])
        self.assertEqual(4, client.timeline_reads.count((".github", 99)))

    def test_closing_reference_change_racing_final_write_is_immediately_reconciled(self) -> None:
        policy, backlog, client, parent, declared, source_reference, external_reference = (
            closing_reference_race_fixture()
        )
        unchanged = [source_reference, external_reference]
        removed = [source_reference]
        client.timeline_sequences[(".github", 99)] = [unchanged, unchanged, unchanged, removed]

        with self.assertRaisesRegex(AuthorityError, "closing-reference authority changed during lifecycle mutation"):
            audit_backlog(
                policy,
                backlog,
                client,
                cross_repository_targets=declared,
            )

        self.assertEqual("open", parent["state"])
        self.assertEqual({"status:ready"}, label_names(parent) & STATUS_LABELS)
        self.assertIn("pending:closing-reference-changed", client.comments[(".github", 99)])
        self.assertIn("The parent remains open", client.comments[(".github", 99)])
        self.assertNotIn("Every declared target landing", client.comments[(".github", 99)])
        self.assertEqual(4, client.timeline_reads.count((".github", 99)))

    def test_external_attempt_requires_approval_of_its_exact_head(self) -> None:
        target = qualification_targets(qualification_fixture())["workflow"]
        trusted_actors = self.policy["intake"]["trusted_actors"]
        issue = {"number": 99}
        landed_commit = "d" * 40
        approved_head = "e" * 40
        newer_head = "f" * 40
        self.client.timelines[(".github", 99)] = [
            closing_reference("workflow", 70, actor="external-contributor"),
            closing_reference("workflow", 71, actor="another-contributor"),
        ]
        self.client.pulls[("workflow", 70)] = pull_request(
            "workflow",
            70,
            "v2",
            author="external-contributor",
            author_association="NONE",
            commit=landed_commit,
            created_at="2026-07-24T10:00:00Z",
            head_repository="external-contributor/workflow",
            head_sha=approved_head,
        )
        self.client.reviews[("workflow", 70)] = [approving_review(approved_head)]
        self.client.pulls[("workflow", 71)] = pull_request(
            "workflow",
            71,
            "v2",
            author="another-contributor",
            author_association="NONE",
            created_at="2026-07-24T11:00:00Z",
            head_repository="another-contributor/workflow",
            head_sha=newer_head,
            state="closed",
        )
        self.client.reviews[("workflow", 71)] = [approving_review("0" * 40)]
        self.client.reachable.add(("workflow", landed_commit, "v2"))
        self.client.successful_checks[("workflow", landed_commit)] = set(target["required_checks"])

        approved = evaluate_lifecycle(
            self.client,
            "durable-workflow",
            ".github",
            issue,
            [target],
            trusted_actors=trusted_actors,
        )

        self.assertTrue(approved["complete"])
        self.assertEqual(
            "https://github.com/durable-workflow/workflow/pull/70",
            approved["targets"][0]["pull_request"],
        )
        self.assertEqual(approved_head, approved["targets"][0]["head_commit"])
        self.assertEqual("durable-workflow/workflow", approved["targets"][0]["base_repository"])
        self.assertEqual("v2", approved["targets"][0]["base_ref"])
        self.assertEqual("approved:repository-maintainer", approved["targets"][0]["provenance"])
        rendered = render_evidence(approved)
        self.assertIn("reference event `CRE_kwDOA1b2c84A0070` at `2026-07-24T09:00:00Z`", rendered)
        self.assertIn("approval review `1` at `2026-07-24T09:30:00Z`", rendered)

        self.client.reviews[("workflow", 71)] = [approving_review(newer_head)]

        superseded = evaluate_lifecycle(
            self.client,
            "durable-workflow",
            ".github",
            issue,
            [target],
            trusted_actors=trusted_actors,
        )

        self.assertFalse(superseded["complete"])
        self.assertEqual("pending:rejected", superseded["targets"][0]["state"])
        self.assertEqual(
            "https://github.com/durable-workflow/workflow/pull/71",
            superseded["targets"][0]["pull_request"],
        )

    def test_external_attempt_requires_fresh_approval_after_latest_closing_reference(self) -> None:
        target = qualification_targets(qualification_fixture())["workflow"]
        trusted_actors = self.policy["intake"]["trusted_actors"]
        issue = {"number": 99}
        landed_commit = "a" * 40
        external_head = "b" * 40
        late_reference = closing_reference(
            "workflow",
            91,
            actor="external-contributor",
            created_at="2026-07-24T10:00:00Z",
            identifier="CRE_kwDOA1b2c84AA910",
        )
        self.client.timelines[(".github", 99)] = [late_reference]
        self.client.pulls[("workflow", 91)] = pull_request(
            "workflow",
            91,
            "v2",
            author="external-contributor",
            author_association="NONE",
            created_at="2026-07-24T09:00:00Z",
            head_repository="external-contributor/workflow",
            head_sha=external_head,
            state="closed",
        )
        self.client.reviews[("workflow", 91)] = [
            approving_review(
                external_head,
                submitted_at="2026-07-24T09:30:00Z",
            )
        ]

        before_landing = evaluate_lifecycle(
            self.client,
            "durable-workflow",
            ".github",
            issue,
            [target],
            trusted_actors=trusted_actors,
        )

        self.assertFalse(before_landing["complete"])
        self.assertEqual("pending:no-linked-pull-request", before_landing["targets"][0]["state"])

        self.client.timelines[(".github", 99)].insert(
            0,
            closing_reference(
                "workflow",
                90,
                created_at="2026-07-24T08:30:00Z",
                identifier="CRE_kwDOA1b2c84AA900",
            ),
        )
        self.client.pulls[("workflow", 90)] = pull_request(
            "workflow",
            90,
            "v2",
            commit=landed_commit,
            created_at="2026-07-24T08:00:00Z",
        )
        self.client.reachable.add(("workflow", landed_commit, "v2"))
        self.client.successful_checks[("workflow", landed_commit)] = set(target["required_checks"])

        completed = evaluate_lifecycle(
            self.client,
            "durable-workflow",
            ".github",
            issue,
            [target],
            trusted_actors=trusted_actors,
        )

        self.assertTrue(completed["complete"])
        self.assertIn("/pull/90", completed["targets"][0]["pull_request"])

        self.client.reviews[("workflow", 91)].append(
            approving_review(
                external_head,
                identifier=2,
                submitted_at="2026-07-24T10:30:00Z",
            )
        )

        admitted = evaluate_lifecycle(
            self.client,
            "durable-workflow",
            ".github",
            issue,
            [target],
            trusted_actors=trusted_actors,
        )

        self.assertFalse(admitted["complete"])
        self.assertEqual("pending:rejected", admitted["targets"][0]["state"])
        self.assertIn("/pull/91", admitted["targets"][0]["pull_request"])

        self.client.timelines[(".github", 99)].append(
            closing_reference(
                "workflow",
                91,
                actor="external-contributor",
                created_at="2026-07-24T11:00:00Z",
                identifier="CRE_kwDOA1b2c84AA911",
            )
        )

        reintroduced = evaluate_lifecycle(
            self.client,
            "durable-workflow",
            ".github",
            issue,
            [target],
            trusted_actors=trusted_actors,
        )

        self.assertTrue(reintroduced["complete"])
        self.assertIn("/pull/90", reintroduced["targets"][0]["pull_request"])

        self.client.reviews[("workflow", 91)].append(
            approving_review(
                external_head,
                identifier=3,
                submitted_at="2026-07-24T11:30:00Z",
            )
        )

        readmitted = evaluate_lifecycle(
            self.client,
            "durable-workflow",
            ".github",
            issue,
            [target],
            trusted_actors=trusted_actors,
        )

        self.assertFalse(readmitted["complete"])
        self.assertEqual("pending:rejected", readmitted["targets"][0]["state"])
        self.assertIn("/pull/91", readmitted["targets"][0]["pull_request"])
        self.assertEqual("CRE_kwDOA1b2c84AA911", readmitted["targets"][0]["reference_event"])
        self.assertEqual(3, readmitted["targets"][0]["approval_review"])

    def test_captured_graphql_references_admit_trusted_and_freshly_approved_external_attempts(self) -> None:
        targets = qualification_targets(qualification_fixture())
        selected_targets = [targets["workflow"], targets["server"]]
        trusted_actors = self.policy["intake"]["trusted_actors"]
        payload = json.loads((ROOT / "tests/fixtures/github/cross-referenced-events.json").read_text(encoding="utf-8"))
        self.client.timelines[(".github", 99)] = payload["data"]["repository"]["issue"]["timelineItems"]["nodes"]
        workflow_landing = "c" * 40
        server_landing = "d" * 40
        external_head = "e" * 40
        self.client.pulls[("workflow", 70)] = pull_request(
            "workflow",
            70,
            "v2",
            commit=workflow_landing,
            created_at="2026-07-24T08:45:00Z",
        )
        self.client.pulls[("server", 71)] = pull_request(
            "server",
            71,
            "main",
            author="external-contributor",
            author_association="NONE",
            commit=server_landing,
            created_at="2026-07-24T08:50:00Z",
            head_repository="external-contributor/server",
            head_sha=external_head,
        )
        self.client.reviews[("server", 71)] = [
            approving_review(
                external_head,
                submitted_at="2026-07-24T09:30:00Z",
            )
        ]
        for target, commit in ((targets["workflow"], workflow_landing), (targets["server"], server_landing)):
            repository = target["repository"]
            self.client.reachable.add((repository, commit, target["branch"]))
            self.client.successful_checks[(repository, commit)] = set(target["required_checks"])

        assessment = evaluate_lifecycle(
            self.client,
            "durable-workflow",
            ".github",
            {"number": 99},
            selected_targets,
            trusted_actors=trusted_actors,
        )

        self.assertTrue(assessment["complete"])
        by_repository = {target["repository"]: target for target in assessment["targets"]}
        self.assertEqual("CRE_kwDOA1b2c84AAZ9x", by_repository["workflow"]["reference_event"])
        self.assertEqual("trusted-author:durable-workflow-ops", by_repository["workflow"]["provenance"])
        self.assertEqual("CRE_kwDOA1b2c84AAaB7", by_repository["server"]["reference_event"])
        self.assertEqual("approved:repository-maintainer", by_repository["server"]["provenance"])
        self.assertEqual("2026-07-24T09:30:00Z", by_repository["server"]["approval_at"])

    def test_trusted_attempt_requires_exact_pull_head_base_and_reference_metadata(self) -> None:
        target = qualification_targets(qualification_fixture())["workflow"]
        trusted_actors = self.policy["intake"]["trusted_actors"]
        issue = {"number": 99}
        mutations = [
            ("pull API identity", "pull", ("url",), "https://api.github.com/repos/durable-workflow/workflow/pulls/99"),
            ("pull HTML identity", "pull", ("html_url",), "https://github.com/durable-workflow/workflow/pull/99"),
            ("head repository", "pull", ("head", "repo", "full_name"), "public-noise/workflow"),
            ("head commit", "pull", ("head", "sha"), "invalid"),
            ("base repository", "pull", ("base", "repo", "full_name"), "durable-workflow/server"),
            ("base commit", "pull", ("base", "sha"), "invalid"),
            ("reference actor", "event", ("actor", "login"), "public-noise"),
            ("reference source type", "event", ("source", "__typename"), "Issue"),
            ("reference source repository", "event", ("source", "repository", "nameWithOwner"), "other/workflow"),
            ("reference event identity", "event", ("id",), 80),
            ("reference event timestamp", "event", ("referencedAt",), "invalid"),
        ]
        for label, location, path, replacement in mutations:
            with self.subTest(label=label):
                event = closing_reference("workflow", 80)
                pull = pull_request(
                    "workflow",
                    80,
                    "v2",
                    created_at="2026-07-24T10:00:00Z",
                    state="closed",
                )
                record = event if location == "event" else pull
                cursor = record
                for field in path[:-1]:
                    cursor = cursor[field]
                cursor[path[-1]] = replacement
                self.client.timelines[(".github", 99)] = [event]
                self.client.pulls[("workflow", 80)] = pull

                assessment = evaluate_lifecycle(
                    self.client,
                    "durable-workflow",
                    ".github",
                    issue,
                    [target],
                    trusted_actors=trusted_actors,
                )

                self.assertFalse(assessment["complete"])
                self.assertEqual("pending:no-linked-pull-request", assessment["targets"][0]["state"])

        wrong_branch = pull_request(
            "workflow",
            81,
            "main",
            created_at="2026-07-24T11:00:00Z",
            state="closed",
        )
        self.client.timelines[(".github", 99)] = [closing_reference("workflow", 81)]
        self.client.pulls[("workflow", 81)] = wrong_branch

        fail_closed = evaluate_lifecycle(
            self.client,
            "durable-workflow",
            ".github",
            issue,
            [target],
            trusted_actors=trusted_actors,
        )

        self.assertFalse(fail_closed["complete"])
        self.assertEqual("pending:wrong-target", fail_closed["targets"][0]["state"])

    def test_cross_repository_parent_without_manifest_targets_cannot_remain_done(self) -> None:
        for item in self.backlog["items"]:
            if item["kind"] == "cross-repository":
                item["kind"] = "feature"
        apply_backlog(self.policy, self.backlog, self.client)
        parent = {
            "body": "Legacy cross-repository authority.",
            "html_url": "https://github.com/durable-workflow/.github/issues/99",
            "labels": [
                {"name": "authority:github"},
                {"name": "kind:cross-repository"},
                {"name": "priority:P1"},
                {"name": "status:done"},
            ],
            "milestone": None,
            "number": 99,
            "state": "closed",
            "title": "Coordinate source landings",
        }
        self.client.issues[".github"].append(parent)

        with self.assertRaisesRegex(AuthorityError, "without a valid declared target set"):
            audit_backlog(
                self.policy,
                self.backlog,
                self.client,
                cross_repository_targets={},
            )

        self.assertEqual("open", parent["state"])
        self.assertEqual({"status:triage"}, label_names(parent) & STATUS_LABELS)

    def test_ambiguous_open_status_is_labeled_and_fails(self) -> None:
        apply_backlog(self.policy, self.backlog, self.client)
        _repository, issue = find_work_item(self.client, "docs-php-conformance-public-authority")
        issue["labels"].append({"name": "status:blocked"})

        with self.assertRaisesRegex(AuthorityError, "ambiguous open lifecycle labels"):
            audit_backlog(self.policy, self.backlog, self.client)

        self.assertIn("authority:conflict", label_names(issue))


if __name__ == "__main__":
    unittest.main()
