from __future__ import annotations

import base64
import contextlib
import copy
import hashlib
import io
import json
import unittest
import urllib.parse
from pathlib import Path
from typing import Any

import yaml

from scripts.current_plan_publication import (
    AUTHORITY_REF,
    BETA_AUTHORIZATION_ENVIRONMENT,
    CONTROL_REPOSITORY,
    CURRENT_PLAN_RUN_EVENTS,
    CURRENT_PLAN_WORKFLOW,
    CURRENT_PLAN_WORKFLOW_PATH,
    CURRENT_PLAN_WORKFLOW_REF,
    OBSERVER_WORKFLOW_REF,
    CurrentPlanPublicationError,
    approved_writer_handoff,
    reconcile_current_plan_dispatch,
    validate_approved_writer_handoff,
    validate_runtime_identity,
)

ROOT = Path(__file__).resolve().parents[1]
OBSERVER_WORKFLOW = ROOT / ".github/workflows/release-plan-observer.yml"
CURRENT_WORKFLOW = ROOT / ".github/workflows/current-release-plan.yml"
CONTINUITY_WORKFLOW = ROOT / ".github/workflows/beta-continuity.yml"
CURRENT_PLAN = ROOT / "release-plans/current.json"
PLAN_REGISTRY_GROUP = "release-plan-registry"
WORKFLOW_ID = 7321
CURRENT_SHA = "b" * 40
OLDER_SHA = "a" * 40


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def current_plan() -> dict[str, Any]:
    return json.loads(CURRENT_PLAN.read_bytes())


def plan_identity(plan: dict[str, Any]) -> tuple[str, str]:
    return f"release-plan/{plan['plan']}", hashlib.sha256(canonical_json(plan)).hexdigest()


def workflow_run(
    run_id: int,
    *,
    source_sha: str = CURRENT_SHA,
    status: str = "waiting",
    created_at: str = "2026-08-11T01:00:00Z",
    event: str = "workflow_dispatch",
) -> dict[str, Any]:
    return {
        "conclusion": None,
        "created_at": created_at,
        "event": event,
        "head_branch": AUTHORITY_REF,
        "head_repository": {"full_name": CONTROL_REPOSITORY},
        "head_sha": source_sha,
        "html_url": f"https://github.com/{CONTROL_REPOSITORY}/actions/runs/{run_id}",
        "id": run_id,
        "path": f"{CURRENT_PLAN_WORKFLOW_PATH}@{AUTHORITY_REF}",
        "repository": {"full_name": CONTROL_REPOSITORY},
        "run_attempt": 1,
        "status": status,
        "url": f"https://api.github.com/repos/{CONTROL_REPOSITORY}/actions/runs/{run_id}",
        "workflow_id": WORKFLOW_ID,
    }


def pending_authorization() -> list[dict[str, Any]]:
    return [
        {
            "current_user_can_approve": False,
            "environment": {
                "id": 19,
                "name": BETA_AUTHORIZATION_ENVIRONMENT,
                "url": (
                    f"https://api.github.com/repos/{CONTROL_REPOSITORY}/environments/"
                    f"{BETA_AUTHORIZATION_ENVIRONMENT}"
                ),
            },
            "reviewers": [{"type": "Team", "reviewer": {"id": 71}}],
        }
    ]


class FakeActionsClient:
    def __init__(
        self,
        runs: list[dict[str, Any]],
        *,
        current_sha: str = CURRENT_SHA,
        pending: dict[int, Any] | None = None,
        historical_plans: dict[str, dict[str, Any]] | None = None,
        comparisons: dict[str, Any] | None = None,
        workflow_metadata: dict[str, Any] | None = None,
    ) -> None:
        self.runs = runs
        self.current_sha = current_sha
        self.pending = pending or {}
        self.historical_plans = historical_plans or {}
        self.comparisons = comparisons or {}
        self.workflow_metadata = (
            workflow_metadata
            if workflow_metadata is not None
            else {
                "html_url": (
                    f"https://github.com/{CONTROL_REPOSITORY}/blob/{AUTHORITY_REF}/"
                    f"{CURRENT_PLAN_WORKFLOW_PATH}"
                ),
                "id": WORKFLOW_ID,
                "name": "Current release plan",
                "path": CURRENT_PLAN_WORKFLOW_PATH,
                "state": "active",
                "url": (
                    f"https://api.github.com/repos/{CONTROL_REPOSITORY}/actions/workflows/"
                    f"{WORKFLOW_ID}"
                ),
            }
        )
        self.posts: list[tuple[str, Any | None]] = []
        self.gets: list[str] = []

    def get(self, path: str) -> Any:
        self.gets.append(path)
        if path == f"/repos/{CONTROL_REPOSITORY}/actions/workflows/{CURRENT_PLAN_WORKFLOW}":
            return self.workflow_metadata
        if path == f"/repos/{CONTROL_REPOSITORY}/git/ref/heads/{AUTHORITY_REF}":
            return {
                "object": {"sha": self.current_sha, "type": "commit"},
                "ref": f"refs/heads/{AUTHORITY_REF}",
            }
        if path.startswith(f"/repos/{CONTROL_REPOSITORY}/actions/workflows/{WORKFLOW_ID}/runs?"):
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(path).query)
            status = query["status"][0]
            event = query.get("event", [None])[0]
            page = int(query["page"][0])
            matching = [
                run
                for run in self.runs
                if run.get("status") == status and (event is None or run.get("event") == event)
            ]
            start = (page - 1) * 100
            return {"total_count": len(matching), "workflow_runs": matching[start : start + 100]}
        suffix = "/pending_deployments"
        if path.endswith(suffix) and "/actions/runs/" in path:
            run_id = int(path.removesuffix(suffix).rsplit("/", 1)[-1])
            return self.pending.get(run_id, [])
        contents_prefix = f"/repos/{CONTROL_REPOSITORY}/contents/release-plans/current.json?ref="
        if path.startswith(contents_prefix):
            revision = path.removeprefix(contents_prefix)
            plan = self.historical_plans[revision]
            return {
                "content": base64.encodebytes(canonical_json(plan)).decode(),
                "encoding": "base64",
                "path": "release-plans/current.json",
                "type": "file",
            }
        compare_prefix = f"/repos/{CONTROL_REPOSITORY}/compare/"
        if path.startswith(compare_prefix):
            comparison = path.removeprefix(compare_prefix)
            return self.comparisons[comparison]
        raise AssertionError(f"unexpected GET {path}")

    def post(self, path: str, payload: Any | None = None) -> None:
        self.posts.append((path, payload))


def reconcile(client: FakeActionsClient, source_sha: str = CURRENT_SHA):
    tag, digest = plan_identity(current_plan())
    return reconcile_current_plan_dispatch(
        client,
        plan_path=CURRENT_PLAN,
        repository=CONTROL_REPOSITORY,
        ref=AUTHORITY_REF,
        workflow=CURRENT_PLAN_WORKFLOW,
        source_sha=source_sha,
        plan_tag=tag,
        plan_sha256=digest,
        observer_workflow_ref=OBSERVER_WORKFLOW_REF,
    )


def publication_step() -> dict[str, object]:
    workflow = yaml.safe_load(OBSERVER_WORKFLOW.read_text(encoding="utf-8"))
    steps = workflow["jobs"]["publish-current"]["steps"]
    return next(
        step
        for step in steps
        if step.get("name") == "Publish the matching aggregate current authority"
    )


class CurrentPlanPublicationTest(unittest.TestCase):
    def test_deduper_classifies_every_current_plan_trigger_mode(self) -> None:
        workflow = yaml.load(CURRENT_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)

        self.assertEqual(set(workflow["on"]), set(CURRENT_PLAN_RUN_EVENTS))

    def test_active_push_wait_for_exact_candidate_is_retained(self) -> None:
        push_wait = workflow_run(100, event="push")
        client = FakeActionsClient(
            [push_wait],
            pending={100: pending_authorization()},
        )

        result = reconcile(client)

        self.assertEqual("retained", result.outcome)
        self.assertEqual(push_wait["html_url"], result.retained_run_url)
        self.assertEqual((), result.cancelled_run_urls)
        self.assertEqual([], client.posts)
        run_queries = [path for path in client.gets if "/actions/workflows/7321/runs?" in path]
        self.assertTrue(run_queries)
        self.assertTrue(all("event=" not in path for path in run_queries))

    def test_active_run_from_unconfigured_trigger_fails_closed(self) -> None:
        unexpected = workflow_run(99, event="pull_request")
        client = FakeActionsClient([unexpected])

        with self.assertRaisesRegex(CurrentPlanPublicationError, "malformed or mismatched"):
            reconcile(client)

        self.assertEqual([], client.posts)

    def test_workflow_metadata_requires_exact_api_and_ref_identity(self) -> None:
        metadata = FakeActionsClient([]).workflow_metadata
        cases = (
            (
                "mismatched workflow ref",
                {
                    **metadata,
                    "html_url": metadata["html_url"].replace("/blob/main/", "/blob/feature/"),
                },
            ),
            (
                "mismatched API workflow",
                {
                    **metadata,
                    "url": metadata["url"].replace(str(WORKFLOW_ID), str(WORKFLOW_ID + 1)),
                },
            ),
        )

        for label, mismatched in cases:
            client = FakeActionsClient([], workflow_metadata=mismatched)
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(CurrentPlanPublicationError, "workflow API authority"),
            ):
                reconcile(client)
            self.assertEqual([], client.posts)

    def test_duplicate_same_candidate_waits_are_coalesced_and_later_observations_are_noops(self) -> None:
        first = workflow_run(101, created_at="2026-08-11T01:00:00Z", event="push")
        duplicate = workflow_run(102, created_at="2026-08-11T02:00:00Z")
        client = FakeActionsClient(
            [first, duplicate],
            pending={101: pending_authorization(), 102: pending_authorization()},
        )
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            initial = reconcile(client)
        self.assertEqual("retained", initial.outcome)
        self.assertEqual(first["html_url"], initial.retained_run_url)
        self.assertEqual((duplicate["html_url"],), initial.cancelled_run_urls)
        self.assertEqual(
            [(f"/repos/{CONTROL_REPOSITORY}/actions/runs/102/cancel", None)],
            client.posts,
        )

        client.runs = [first]
        with contextlib.redirect_stdout(output):
            repeated = reconcile(client)
        self.assertEqual("retained", repeated.outcome)
        self.assertEqual(first["html_url"], repeated.retained_run_url)
        self.assertEqual((), repeated.cancelled_run_urls)
        self.assertEqual(1, len(client.posts))
        self.assertEqual(2, output.getvalue().count("idempotent no-op"))
        self.assertIn(str(first["html_url"]), output.getvalue())

    def test_newer_candidate_supersedes_only_verified_unapproved_ancestor(self) -> None:
        prior_plan = copy.deepcopy(current_plan())
        prior_plan["plan"] = "prior-current-plan"
        old = workflow_run(201, source_sha=OLDER_SHA)
        comparison = {
            "ahead_by": 3,
            "base_commit": {"sha": OLDER_SHA},
            "behind_by": 0,
            "merge_base_commit": {"sha": OLDER_SHA},
            "status": "ahead",
        }
        client = FakeActionsClient(
            [old],
            pending={201: pending_authorization()},
            historical_plans={OLDER_SHA: prior_plan},
            comparisons={f"{OLDER_SHA}...{CURRENT_SHA}": comparison},
        )

        result = reconcile(client)

        self.assertEqual("dispatched", result.outcome)
        self.assertIsNone(result.retained_run_url)
        self.assertEqual((old["html_url"],), result.cancelled_run_urls)
        self.assertEqual(
            [
                (f"/repos/{CONTROL_REPOSITORY}/actions/runs/201/cancel", None),
                (
                    f"/repos/{CONTROL_REPOSITORY}/actions/workflows/{WORKFLOW_ID}/dispatches",
                    {"ref": AUTHORITY_REF},
                ),
            ],
            client.posts,
        )

    def test_ambiguous_or_malformed_api_state_fails_before_mutation(self) -> None:
        cases: list[tuple[str, FakeActionsClient, str]] = []

        mismatched_run = workflow_run(301)
        mismatched_run["head_repository"] = {"full_name": "outside/fork"}
        cases.append(
            (
                "mismatched repository",
                FakeActionsClient([mismatched_run], pending={301: pending_authorization()}),
                "malformed or mismatched",
            )
        )

        malformed_timestamp = workflow_run(304, created_at="2026-99-11T01:00:00Z")
        cases.append(
            (
                "malformed timestamp",
                FakeActionsClient([malformed_timestamp], pending={304: pending_authorization()}),
                "invalid timestamp",
            )
        )

        malformed_pending = pending_authorization()
        malformed_pending[0]["environment"]["name"] = "stable-authorization"
        cases.append(
            (
                "mismatched pending environment",
                FakeActionsClient([workflow_run(302)], pending={302: malformed_pending}),
                "pending authorization is mismatched",
            )
        )

        prior_plan = copy.deepcopy(current_plan())
        prior_plan["plan"] = "diverged-plan"
        diverged = {
            "ahead_by": 1,
            "base_commit": {"sha": OLDER_SHA},
            "behind_by": 1,
            "merge_base_commit": {"sha": "c" * 40},
            "status": "diverged",
        }
        cases.append(
            (
                "diverged source",
                FakeActionsClient(
                    [workflow_run(303, source_sha=OLDER_SHA)],
                    pending={303: pending_authorization()},
                    historical_plans={OLDER_SHA: prior_plan},
                    comparisons={f"{OLDER_SHA}...{CURRENT_SHA}": diverged},
                ),
                "not a verified ancestor",
            )
        )

        for label, client, diagnostic in cases:
            with (
                self.subTest(label=label),
                self.assertRaisesRegex(CurrentPlanPublicationError, diagnostic),
            ):
                reconcile(client)
            self.assertEqual([], client.posts)

    def test_already_approved_writer_is_retained_and_never_cancelled(self) -> None:
        writer = workflow_run(401, status="in_progress")
        duplicate_wait = workflow_run(402, created_at="2026-08-11T02:00:00Z")
        client = FakeActionsClient(
            [writer, duplicate_wait],
            pending={402: pending_authorization()},
        )

        result = reconcile(client)

        self.assertEqual("retained", result.outcome)
        self.assertEqual(writer["html_url"], result.retained_run_url)
        self.assertEqual((duplicate_wait["html_url"],), result.cancelled_run_urls)
        self.assertEqual(
            [(f"/repos/{CONTROL_REPOSITORY}/actions/runs/402/cancel", None)],
            client.posts,
        )
        self.assertNotIn(
            f"/repos/{CONTROL_REPOSITORY}/actions/runs/401/pending_deployments",
            client.gets,
        )

    def test_older_writer_that_may_be_approved_fails_closed(self) -> None:
        prior_plan = copy.deepcopy(current_plan())
        prior_plan["plan"] = "older-approved-plan"
        comparison = {
            "ahead_by": 2,
            "base_commit": {"sha": OLDER_SHA},
            "behind_by": 0,
            "merge_base_commit": {"sha": OLDER_SHA},
            "status": "ahead",
        }
        writer = workflow_run(451, source_sha=OLDER_SHA, status="queued")
        client = FakeActionsClient(
            [writer],
            historical_plans={OLDER_SHA: prior_plan},
            comparisons={f"{OLDER_SHA}...{CURRENT_SHA}": comparison},
        )

        with self.assertRaisesRegex(CurrentPlanPublicationError, "may have passed protected authorization"):
            reconcile(client)
        self.assertEqual([], client.posts)

    def test_exact_repository_workflow_ref_source_and_plan_are_required(self) -> None:
        tag, digest = plan_identity(current_plan())
        valid = {
            "plan_path": CURRENT_PLAN,
            "repository": CONTROL_REPOSITORY,
            "ref": AUTHORITY_REF,
            "workflow": CURRENT_PLAN_WORKFLOW,
            "source_sha": CURRENT_SHA,
            "plan_tag": tag,
            "plan_sha256": digest,
            "observer_workflow_ref": OBSERVER_WORKFLOW_REF,
        }
        cases = (
            ("repository", "outside/fork"),
            ("ref", "feature"),
            ("workflow", "other.yml"),
            ("source_sha", "short"),
            ("plan_tag", "release-plan/other"),
            ("plan_sha256", "0" * 64),
            ("observer_workflow_ref", OBSERVER_WORKFLOW_REF.replace("observer", "other")),
        )
        for field, value in cases:
            client = FakeActionsClient([])
            with (
                self.subTest(field=field),
                self.assertRaises(CurrentPlanPublicationError),
            ):
                reconcile_current_plan_dispatch(client, **{**valid, field: value})
            self.assertEqual([], client.gets)
            self.assertEqual([], client.posts)

    def test_authority_ref_is_rechecked_before_any_mutation(self) -> None:
        class MovingRefClient(FakeActionsClient):
            def __init__(self) -> None:
                super().__init__([workflow_run(501)], pending={501: pending_authorization()})
                self.ref_reads = 0

            def get(self, path: str) -> Any:
                value = super().get(path)
                if path.endswith(f"/git/ref/heads/{AUTHORITY_REF}"):
                    self.ref_reads += 1
                    if self.ref_reads == 2:
                        value["object"]["sha"] = "c" * 40
                return value

        client = MovingRefClient()
        with self.assertRaisesRegex(CurrentPlanPublicationError, "no longer resolves"):
            reconcile(client)
        self.assertEqual([], client.posts)

    def test_authorization_is_rechecked_immediately_before_cancellation(self) -> None:
        class ApprovalRaceClient(FakeActionsClient):
            def __init__(self) -> None:
                super().__init__([workflow_run(551)], pending={551: pending_authorization()})
                self.pending_reads = 0

            def get(self, path: str) -> Any:
                if path.endswith("/actions/runs/551/pending_deployments"):
                    self.pending_reads += 1
                    if self.pending_reads == 2:
                        self.gets.append(path)
                        return []
                return super().get(path)

        current = workflow_run(550, created_at="2026-08-11T00:30:00Z")
        client = ApprovalRaceClient()
        client.runs.insert(0, current)
        client.pending[550] = pending_authorization()

        with self.assertRaisesRegex(CurrentPlanPublicationError, "no longer awaiting"):
            reconcile(client)
        self.assertEqual([], client.posts)

    def test_observer_and_continuity_schedules_do_not_wait_on_protected_approval(self) -> None:
        current = yaml.safe_load(CURRENT_WORKFLOW.read_text(encoding="utf-8"))
        observer = yaml.safe_load(OBSERVER_WORKFLOW.read_text(encoding="utf-8"))
        continuity = yaml.safe_load(CONTINUITY_WORKFLOW.read_text(encoding="utf-8"))
        approval = current["jobs"]["authorize"]
        writer = current["jobs"]["record"]

        self.assertNotIn("concurrency", current)
        self.assertEqual(BETA_AUTHORIZATION_ENVIRONMENT, approval["environment"])
        self.assertNotIn("concurrency", approval)
        self.assertEqual({"contents": "read"}, approval["permissions"])
        self.assertEqual("authorize", writer["needs"])
        self.assertIn("needs.authorize.result == 'success'", writer["if"])
        self.assertEqual(
            {"group": PLAN_REGISTRY_GROUP, "cancel-in-progress": False},
            writer["concurrency"],
        )
        self.assertEqual(
            {"group": PLAN_REGISTRY_GROUP, "cancel-in-progress": False},
            observer["concurrency"],
        )
        self.assertNotEqual(PLAN_REGISTRY_GROUP, continuity["concurrency"]["group"])
        self.assertNotIn("write", observer["jobs"]["observe"]["permissions"].values())

    def test_observer_wires_exact_candidate_outputs_to_bounded_reconciliation(self) -> None:
        workflow = yaml.safe_load(OBSERVER_WORKFLOW.read_text(encoding="utf-8"))
        record = workflow["jobs"]["record"]
        publish = workflow["jobs"]["publish-current"]
        step = publication_step()
        checkout = next(item for item in publish["steps"] if "actions/checkout" in item.get("uses", ""))

        self.assertEqual("${{ steps.aggregate.outputs.current-plan-tag }}", record["outputs"]["current-plan-tag"])
        self.assertEqual(
            "${{ steps.aggregate.outputs.current-plan-sha256 }}",
            record["outputs"]["current-plan-sha256"],
        )
        self.assertEqual({"actions": "write", "contents": "read"}, publish["permissions"])
        self.assertIs(checkout["with"]["persist-credentials"], False)
        self.assertEqual("${{ github.sha }}", checkout["with"]["ref"])
        self.assertEqual(
            "release-plans/current.json\nscripts/current_plan_publication.py\n",
            checkout["with"]["sparse-checkout"],
        )
        self.assertEqual(
            {
                "GH_TOKEN": "${{ github.token }}",
                "CURRENT_PLAN_SHA256": "${{ needs.record.outputs.current-plan-sha256 }}",
                "CURRENT_PLAN_TAG": "${{ needs.record.outputs.current-plan-tag }}",
                "TARGET_REF": AUTHORITY_REF,
                "TARGET_REPOSITORY": CONTROL_REPOSITORY,
                "TARGET_WORKFLOW": CURRENT_PLAN_WORKFLOW,
            },
            step["env"],
        )
        self.assertIn("current_plan_publication.py reconcile-dispatch", step["run"])
        self.assertIn('--observer-workflow-ref "$GITHUB_WORKFLOW_REF"', step["run"])
        self.assertIn('--source-sha "$GITHUB_SHA"', step["run"])
        self.assertIn('--plan-tag "$CURRENT_PLAN_TAG"', step["run"])
        self.assertIn('--plan-sha256 "$CURRENT_PLAN_SHA256"', step["run"])
        self.assertNotIn("gh workflow run", step["run"])

    def test_approved_writer_handoff_is_exact_and_retry_safe(self) -> None:
        identity = {
            "repository": CONTROL_REPOSITORY,
            "ref": f"refs/heads/{AUTHORITY_REF}",
            "workflow_ref": CURRENT_PLAN_WORKFLOW_REF,
            "source_sha": "d" * 40,
            "run_id": 123456789,
            "producer_attempt": 1,
        }
        handoff = approved_writer_handoff(**identity)
        self.assertRegex(handoff, r"^[0-9a-f]{64}$")
        validate_approved_writer_handoff(handoff, **identity, current_attempt=2)

        mismatches = (
            ({"handoff": "0" * 64}, "does not match"),
            ({"source_sha": "e" * 40}, "does not match"),
            ({"run_id": identity["run_id"] + 1}, "does not match"),
            ({"producer_attempt": 2, "current_attempt": 1}, "newer than"),
        )
        for changes, diagnostic in mismatches:
            arguments = {**identity, "handoff": handoff, "current_attempt": 2, **changes}
            with (
                self.subTest(changes=changes),
                self.assertRaisesRegex(CurrentPlanPublicationError, diagnostic),
            ):
                validate_approved_writer_handoff(**arguments)

    def test_protected_writer_runtime_identity_remains_exact(self) -> None:
        validate_runtime_identity(
            CONTROL_REPOSITORY,
            f"refs/heads/{AUTHORITY_REF}",
            CURRENT_PLAN_WORKFLOW_REF,
        )
        mismatches = (
            (None, f"refs/heads/{AUTHORITY_REF}", CURRENT_PLAN_WORKFLOW_REF),
            ("outside/fork", f"refs/heads/{AUTHORITY_REF}", CURRENT_PLAN_WORKFLOW_REF),
            (CONTROL_REPOSITORY, "refs/heads/feature", CURRENT_PLAN_WORKFLOW_REF),
            (
                CONTROL_REPOSITORY,
                f"refs/heads/{AUTHORITY_REF}",
                f"{CONTROL_REPOSITORY}/.github/workflows/other.yml@refs/heads/{AUTHORITY_REF}",
            ),
        )
        for repository, ref, workflow_ref in mismatches:
            with (
                self.subTest(repository=repository, ref=ref, workflow_ref=workflow_ref),
                self.assertRaises(CurrentPlanPublicationError),
            ):
                validate_runtime_identity(repository, ref, workflow_ref)


if __name__ == "__main__":
    unittest.main()
