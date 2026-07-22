from __future__ import annotations

import copy
import json
import unittest
import urllib.error
from pathlib import Path
from typing import Any
from unittest.mock import patch

import yaml

from scripts.issue_authority import (
    COMPLETION_REQUIRED_LABEL,
    COMPLETION_VERIFIED_LABEL,
    OWNER_LABELS,
    STATUS_LABELS,
    UNBLOCK_CONTEXT_END,
    UNBLOCK_CONTEXT_START,
    AuthorityError,
    GitHubApi,
    apply_backlog,
    audit_backlog,
    load_contract,
    validate_contract,
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


def contract_fixture() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[str, Any]]:
    directory = ROOT / "issue-authority"
    return tuple(
        json.loads((directory / name).read_text(encoding="utf-8"))
        for name in ("policy.json", "backlog.json", "policy-schema.json", "backlog-schema.json")
    )


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


class ContractValidationTest(unittest.TestCase):
    def test_checked_in_contract_is_valid(self) -> None:
        policy, backlog = load_contract(
            ROOT / "issue-authority" / "policy.json",
            ROOT / "issue-authority" / "backlog.json",
        )

        self.assertEqual("github-to-mirrors", policy["state_direction"])
        self.assertEqual(4, len(backlog["items"]))
        blocked = [item for item in backlog["items"] if item["status"] == "blocked"]
        self.assertTrue(all(item["depends_on"] or item.get("unblock_condition") for item in blocked))

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
        for name in expected:
            form = forms[name]
            self.assertTrue(set(form["labels"]) <= policy_labels)
            self.assertIn("authority:github", form["labels"])
            self.assertIn(COMPLETION_REQUIRED_LABEL, form["labels"])
            self.assertIn("priority:untriaged", form["labels"])

    def test_authority_jobs_are_limited_to_the_canonical_github_host(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "issue-authority.yml").read_text(encoding="utf-8"))
        conditions = {job: " ".join(workflow["jobs"][job]["if"].split()) for job in ("validate", "apply", "audit")}

        self.assertEqual(
            "${{ github.event_name != 'issues' || github.server_url == 'https://github.com' }}",
            conditions["validate"],
        )
        self.assertEqual(
            "${{ github.ref == 'refs/heads/main' && github.server_url == 'https://github.com' && "
            "(github.event_name == 'push' || "
            "(github.event_name == 'workflow_dispatch' && inputs.mode == 'apply')) }}",
            conditions["apply"],
        )
        self.assertEqual(
            "${{ github.ref == 'refs/heads/main' && github.server_url == 'https://github.com' && "
            "(github.event_name == 'schedule' || "
            "github.event_name == 'issues' || "
            "(github.event_name == 'workflow_dispatch' && inputs.mode == 'audit')) }}",
            conditions["audit"],
        )


class GitHubApiTest(unittest.TestCase):
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

    def assert_no_github_mutations(self) -> None:
        self.assertEqual([], self.client.label_updates)
        self.assertEqual([], self.client.milestone_updates)
        self.assertEqual([], self.client.created_issues)
        self.assertEqual([], self.client.replacements)
        self.assertEqual([], self.client.body_updates)
        self.assertEqual([], self.client.state_updates)

    def test_apply_creates_only_reviewed_items_with_dependencies(self) -> None:
        evidence = apply_backlog(self.policy, self.backlog, self.client)

        self.assertEqual("pass", evidence["outcome"])
        self.assertEqual(4, sum(len(issues) for issues in self.client.issues.values()))
        for item in self.backlog["items"]:
            repository, issue = find_work_item(self.client, item["id"])
            self.assertEqual(item["repository"], repository)
            self.assertEqual("open", issue["state"])
            self.assertEqual("2.0 beta", issue["milestone"]["title"])
            self.assertIn(OWNER_LABELS[repository], label_names(issue))

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

    def test_unverified_close_is_reopened_and_fails_visibly(self) -> None:
        apply_backlog(self.policy, self.backlog, self.client)
        repository, issue = find_work_item(self.client, "github-only-beta-continuity-drill")
        issue["state"] = "closed"

        with self.assertRaisesRegex(
            AuthorityError,
            "closed before its required public completion evidence was verified",
        ):
            audit_backlog(self.policy, self.backlog, self.client)

        self.assertEqual({"status:ready"}, label_names(issue) & STATUS_LABELS)
        self.assertEqual("open", issue["state"])
        self.assertIn((repository, issue["number"], "open"), self.client.state_updates)

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

    def test_open_authoritative_issue_is_enrolled_in_the_completion_gate(self) -> None:
        apply_backlog(self.policy, self.backlog, self.client)
        repository, issue = find_work_item(self.client, "github-only-beta-continuity-drill")
        issue["labels"] = [label for label in issue["labels"] if label["name"] != COMPLETION_REQUIRED_LABEL]
        self.clear_mutation_spies()

        evidence = audit_backlog(self.policy, self.backlog, self.client)

        self.assertEqual("pass", evidence["outcome"])
        self.assertIn(COMPLETION_REQUIRED_LABEL, label_names(issue))
        self.assertIn((repository, issue["number"], sorted(label_names(issue))), self.client.replacements)
        self.assertEqual([], self.client.state_updates)

    def test_ambiguous_open_status_is_labeled_and_fails(self) -> None:
        apply_backlog(self.policy, self.backlog, self.client)
        _repository, issue = find_work_item(self.client, "docs-php-conformance-public-authority")
        issue["labels"].append({"name": "status:blocked"})

        with self.assertRaisesRegex(AuthorityError, "ambiguous open lifecycle labels"):
            audit_backlog(self.policy, self.backlog, self.client)

        self.assertIn("authority:conflict", label_names(issue))


if __name__ == "__main__":
    unittest.main()
