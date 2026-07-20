from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.beta_candidate import COMPONENTS
from scripts.beta_continuity import (
    EVIDENCE_SCHEMA,
    ContinuityError,
    PlanBlocked,
    authority_issue,
    build_plan,
    dispatch_recovery,
    load_config,
    next_version,
    phase_tag,
    plan_command,
    record_phase,
    require_partial_publication,
    select_versions,
)

ROOT = Path(__file__).resolve().parents[1]


class PlanningClient:
    def __init__(
        self,
        *,
        stale_manifests: bool = False,
        blocker_versions: dict[str, list[str]] | None = None,
    ) -> None:
        self.stale_manifests = stale_manifests
        self.blocker_versions = blocker_versions or {}
        self.commits = {name: f"{index + 1:040x}" for index, name in enumerate(COMPONENTS)}
        self.latest = {
            "workflow": "2.0.0-alpha.291",
            "waterline": "2.0.0-alpha.137",
            "server": "0.2.693",
            "cli": "0.1.93",
            "sdk-php": "0.1.13",
            "sdk-python": "0.4.102",
            "sdk-rust": "0.1.17",
        }

    def json(self, url: str) -> object:
        for name, component in COMPONENTS.items():
            if url == f"https://api.github.com/repos/{component.repository}/issues?state=all&per_page=100":
                return [
                    {
                        "body": (
                            "Blocks https://github.com/durable-workflow/.github/issues/2.\n\n"
                            f"<!-- beta-continuity-blocker: {name}-source-version-{version} -->"
                        ),
                        "number": index + 1,
                    }
                    for index, version in enumerate(self.blocker_versions.get(name, []))
                ]
            if f"repos/{component.repository}/branches/" in url:
                return {"commit": {"sha": self.commits[name]}}
            if url == f"https://api.github.com/repos/{component.repository}/releases?per_page=100":
                return [{"draft": False, "tag_name": self.latest[name]}]
        raise AssertionError(f"unexpected JSON URL: {url}")

    def bytes(self, url: str, *, accept: str | None = None) -> bytes:
        self.assert_raw(accept)
        if "sdk-python" in url:
            version = "0.4.102" if self.stale_manifests else "0.4.103"
            return f'[project]\nname = "durable-workflow"\nversion = "{version}"\n'.encode()
        if "sdk-rust" in url:
            version = "0.1.17" if self.stale_manifests else "0.1.18"
            return f'[package]\nname = "durable-workflow"\nversion = "{version}"\n'.encode()
        raise AssertionError(f"unexpected bytes URL: {url}")

    @staticmethod
    def assert_raw(accept: str | None) -> None:
        if accept != "application/vnd.github.raw+json":
            raise AssertionError(f"unexpected Accept: {accept}")


def run(command: list[str], directory: Path) -> str:
    return subprocess.run(command, cwd=directory, check=True, text=True, capture_output=True).stdout.strip()


class BetaContinuityTest(unittest.TestCase):
    def test_completed_authority_is_a_valid_scheduled_no_op_boundary(self) -> None:
        config = load_config(ROOT / "beta-continuity" / "config.json")

        class CompletedIssueClient:
            @staticmethod
            def json(_url: str) -> dict[str, object]:
                return {
                    "body": "<!-- beta-work-id: github-only-beta-continuity-drill -->",
                    "html_url": "https://github.com/durable-workflow/.github/issues/2",
                    "labels": [
                        {"name": "authority:github"},
                        {"name": "beta:blocker"},
                        {"name": "completion:evidence-verified"},
                        {"name": "status:done"},
                    ],
                    "state": "closed",
                    "updated_at": "2026-07-20T00:00:00Z",
                }

        with self.assertRaises(ContinuityError):
            authority_issue(config, CompletedIssueClient())  # type: ignore[arg-type]
        issue = authority_issue(config, CompletedIssueClient(), allow_completed=True)  # type: ignore[arg-type]
        self.assertEqual("closed", issue["state"])

    def test_config_is_machine_validated(self) -> None:
        config = load_config(ROOT / "beta-continuity" / "config.json")

        self.assertEqual("workspace-unavailable-beta-continuity", config["drill"])
        self.assertEqual("durable-workflow/.github", config["authority_issue"]["repository"])
        self.assertEqual("workflow", config["first_component"])

    def test_version_allocation_uses_the_next_numeric_public_identity(self) -> None:
        self.assertEqual(
            "2.0.0-alpha.292",
            next_version("workflow", ["2.0.0-alpha.9", "2.0.0-alpha.291", "not-a-release"]),
        )
        self.assertEqual("0.4.103", next_version("sdk-python", ["0.4.99", "0.4.102", "1.0.0-beta.1"]))

    def test_plan_binds_seven_heads_and_requires_unoccupied_manifest_versions(self) -> None:
        config = load_config(ROOT / "beta-continuity" / "config.json")
        client = PlanningClient()

        with patch("scripts.beta_continuity.resolve_tag", return_value=None):
            plan, expected = build_plan(config, client)  # type: ignore[arg-type]

        self.assertEqual(set(COMPONENTS), set(plan["components"]))
        self.assertEqual("2.0.0-alpha.292", plan["components"]["workflow"]["version"])
        self.assertEqual("0.4.103", plan["components"]["sdk-python"]["version"])
        self.assertEqual("0.1.18", plan["components"]["sdk-rust"]["version"])
        self.assertEqual(expected, {name: identity["commit"] for name, identity in plan["components"].items()})
        self.assertTrue(plan["plan"].startswith("workspace-unavailable-"))

    def test_plan_routes_stale_source_versions_as_component_blockers(self) -> None:
        config = load_config(ROOT / "beta-continuity" / "config.json")

        with (
            patch("scripts.beta_continuity.resolve_tag", return_value=None),
            self.assertRaises(PlanBlocked) as raised,
        ):
            build_plan(config, PlanningClient(stale_manifests=True))  # type: ignore[arg-type]

        blockers = raised.exception.blockers
        self.assertEqual({"sdk-python", "sdk-rust"}, {blocker["component"] for blocker in blockers})
        self.assertTrue(all(blocker["repository"].startswith("durable-workflow/") for blocker in blockers))

    def test_planning_records_the_selection_before_routing_source_blockers(self) -> None:
        client = PlanningClient(stale_manifests=True)
        issue = {
            "number": 2,
            "repository": "durable-workflow/.github",
            "state": "open",
            "work_id": "github-only-beta-continuity-drill",
        }
        selection_record = {
            "status": "created",
            "tag": "beta-continuity-selection/workspace-unavailable-beta-continuity",
            "commit": "f" * 40,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch("scripts.beta_continuity.PublicClient", return_value=client),
                patch("scripts.beta_continuity.authority_issue", return_value=issue),
                patch("scripts.beta_continuity.accepted_plan", return_value=None),
                patch("scripts.beta_continuity.public_selection", return_value=None),
                patch("scripts.beta_continuity.record_selection", return_value=selection_record) as record,
                patch("scripts.beta_continuity.resolve_tag", return_value=None),
                patch.dict(os.environ, {"GITHUB_SHA": "c" * 40}),
                self.assertRaises(PlanBlocked),
            ):
                plan_command(
                    ROOT / "beta-continuity" / "config.json",
                    root / "release-plan.json",
                    root / "expected.json",
                    root / "state.json",
                    None,
                )

            record.assert_called_once()
            state = json.loads((root / "state.json").read_text(encoding="utf-8"))
            self.assertEqual("blocked", state["outcome"])
            self.assertEqual(selection_record["tag"], state["selection"]["tag"])
            self.assertEqual("0.4.103", state["selection"]["versions"]["sdk-python"])

    def test_retained_selection_reuses_published_versions_without_successor_loop(self) -> None:
        config = load_config(ROOT / "beta-continuity" / "config.json")
        client = PlanningClient(
            blocker_versions={
                "sdk-python": ["0.4.103", "0.4.104"],
                "sdk-rust": ["0.1.18", "0.1.19"],
            }
        )
        client.latest.update({"sdk-python": "0.4.104", "sdk-rust": "0.1.19"})
        selection = select_versions(config, client)  # type: ignore[arg-type]
        published_commits = {
            (COMPONENTS["sdk-python"].repository, "0.4.103"): "a" * 40,
            (COMPONENTS["sdk-rust"].repository, "0.1.18"): "b" * 40,
        }

        def resolve_selected_tag(_client: object, repository: str, version: str) -> str | None:
            return published_commits.get((repository, version))

        with patch("scripts.beta_continuity.resolve_tag", side_effect=resolve_selected_tag):
            plan, expected = build_plan(config, client, selection)  # type: ignore[arg-type]

        self.assertEqual("0.4.103", selection["versions"]["sdk-python"])
        self.assertEqual("0.1.18", selection["versions"]["sdk-rust"])
        self.assertEqual("0.4.103", plan["components"]["sdk-python"]["version"])
        self.assertEqual("a" * 40, expected["sdk-python"])
        self.assertEqual("0.1.18", plan["components"]["sdk-rust"]["version"])
        self.assertEqual("b" * 40, expected["sdk-rust"])

    def test_interruption_requires_a_provably_partial_publication(self) -> None:
        require_partial_publication({"workflow": {"version": "2.0.0-alpha.292"}}, ["waterline"])
        with self.assertRaises(ContinuityError):
            require_partial_publication({name: {} for name in COMPONENTS}, [])
        with self.assertRaises(ContinuityError):
            require_partial_publication({}, list(COMPONENTS))

    def test_failed_first_recovery_is_retried_once_without_duplicate_active_or_successful_runs(self) -> None:
        plan_tag = "release-plan/workspace-unavailable-20260720"

        class RecoveryWriter:
            def __init__(self) -> None:
                self.runs = [
                    {
                        "id": 101,
                        "display_title": f"Recover {plan_tag}",
                        "status": "completed",
                        "conclusion": "failure",
                    }
                ]
                self.dispatches: list[tuple[str, str, str, dict[str, str]]] = []

            def get(self, _path: str) -> dict[str, object]:
                return {"workflow_runs": self.runs}

            def dispatch(self, repository: str, workflow: str, ref: str, inputs: dict[str, str]) -> None:
                self.dispatches.append((repository, workflow, ref, inputs))

        writer = RecoveryWriter()

        dispatch_recovery(writer, "workflow", plan_tag)  # type: ignore[arg-type]
        self.assertEqual(1, len(writer.dispatches))

        writer.runs.append(
            {
                "id": 102,
                "display_title": f"Recover {plan_tag}",
                "status": "queued",
                "conclusion": None,
            }
        )
        dispatch_recovery(writer, "workflow", plan_tag)  # type: ignore[arg-type]
        self.assertEqual(1, len(writer.dispatches))

        writer.runs[-1]["status"] = "in_progress"
        dispatch_recovery(writer, "workflow", plan_tag)  # type: ignore[arg-type]
        self.assertEqual(1, len(writer.dispatches))

        writer.runs[-1].update({"status": "completed", "conclusion": "success"})
        dispatch_recovery(writer, "workflow", plan_tag)  # type: ignore[arg-type]
        self.assertEqual(1, len(writer.dispatches))

        require_partial_publication(
            {"workflow": {"version": "2.0.0-alpha.292"}},
            [name for name in COMPONENTS if name != "workflow"],
        )

    def test_phase_records_are_append_only_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            remote = root / "remote.git"
            checkout = root / "checkout"
            run(["git", "init", "--bare", str(remote)], root)
            run(["git", "clone", str(remote), str(checkout)], root)
            plan = {
                "schema": "durable-workflow.release-plan/v1",
                "plan": "continuity-test",
                "channel": "alpha",
                "foundation": {
                    "tag": "beta-candidate/beta-continuity-foundation",
                    "commit": "4995052410bd4301c5796ffba54e0b6d2f490ed1",
                },
                "components": {
                    name: {
                        "commit": f"{index + 1:040x}",
                        "version": (
                            f"2.0.0-alpha.{index + 1}" if name in {"workflow", "waterline"} else f"0.1.{index + 1}"
                        ),
                    }
                    for index, name in enumerate(COMPONENTS)
                },
                "beta_authorization": None,
            }
            evidence = {
                "schema": EVIDENCE_SCHEMA,
                "drill": "continuity-test",
                "phase": "interrupted",
                "observed_at": "2026-07-20T00:00:00Z",
            }

            first = record_phase(checkout, plan, "interrupted", evidence)
            second = record_phase(checkout, plan, "interrupted", evidence)

            self.assertEqual("created", first["status"])
            self.assertEqual("existing", second["status"])
            self.assertEqual(first["commit"], second["commit"])
            self.assertEqual(
                first["commit"],
                run(
                    ["git", "ls-remote", "--refs", "origin", f"refs/tags/{phase_tag(plan, 'interrupted')}"],
                    checkout,
                ).split()[0],
            )
            recorded = json.loads(
                run(
                    [
                        "git",
                        "show",
                        "refs/beta-candidate-check/"
                        + hashlib.sha256(phase_tag(plan, "interrupted").encode()).hexdigest()
                        + ":continuity-evidence.json",
                    ],
                    checkout,
                )
            )
            self.assertEqual(evidence, recorded)

    def test_workflow_is_scheduled_and_uses_protected_github_authority(self) -> None:
        source = (ROOT / ".github" / "workflows" / "beta-continuity.yml").read_text(encoding="utf-8")

        self.assertIn("schedule:", source)
        self.assertIn("environment: beta-product-work", source)
        self.assertIn("scripts/beta_continuity.py advance", source)
        self.assertIn("scripts/beta_continuity.py route-blockers", source)
        self.assertIn("if: ${{ steps.plan.outcome == 'success' }}", source)
        self.assertNotIn("run: exit 1", source)
        self.assertNotIn("/workspace", source)


if __name__ == "__main__":
    unittest.main()
