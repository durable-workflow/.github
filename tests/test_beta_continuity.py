from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from scripts.beta_candidate import COMPONENTS, manifest_digest
from scripts.beta_continuity import (
    EVIDENCE_SCHEMA,
    ContinuityError,
    PlanBlocked,
    accepted_plan_authority,
    accepted_publication_state,
    advance_command,
    authority_issue,
    build_plan,
    close_authority_issue,
    conformance_evidence,
    dispatch_accepted_continuity,
    dispatch_recovery,
    ensure_conformance_execution_or_retention,
    exact_completion_authority,
    load_config,
    next_version,
    phase_tag,
    plan_command,
    record_phase,
    recovery_publication_triggers,
    require_partial_publication,
    route_blockers,
    select_versions,
    validate_interrupted_evidence,
)
from scripts.release_plan import candidate_manifest

ROOT = Path(__file__).resolve().parents[1]
ROUTED_BLOCKER_LABELS = (
    "authority:github",
    "beta:blocker",
    "kind:release-blocker",
    "priority:P1",
    "status:ready",
)


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
                        "labels": [{"name": label} for label in ROUTED_BLOCKER_LABELS],
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


def continuity_plan(name: str = "continuity-test") -> dict[str, object]:
    return {
        "schema": "durable-workflow.release-plan/v1",
        "plan": name,
        "channel": "alpha",
        "foundation": {
            "tag": "beta-candidate/beta-continuity-foundation",
            "commit": "4995052410bd4301c5796ffba54e0b6d2f490ed1",
        },
        "components": {
            component: {
                "commit": f"{index + 1:040x}",
                "version": (
                    f"2.0.0-alpha.{index + 1}" if component in {"workflow", "waterline"} else f"0.1.{index + 1}"
                ),
            }
            for index, component in enumerate(COMPONENTS)
        },
        "beta_authorization": None,
    }


def conformance_release_fixture(
    plan: dict[str, Any],
    run_id: int,
    *,
    sensitive: bool = False,
) -> tuple[dict[str, Any], dict[str, bytes], dict[str, Any]]:
    candidate = candidate_manifest(plan)
    tag = f"beta-conformance/{candidate['candidate']}/{run_id}.1"
    experiments = ("heartbeats", "polyglot", "replay", "signals-queries")
    payloads = {
        f"https://downloads.example/{run_id}/{name}.json": json.dumps(
            {
                "classification": "passed",
                "experiment": name,
                "outcome": "pass",
                "stdout_tail": "password=published-secret" if sensitive and name == "replay" else "",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        for name in experiments
    }
    run = {
        "repository": "durable-workflow/.github",
        "run_id": run_id,
        "run_attempt": 1,
        "evidence_tag": tag,
    }
    suite = {
        "schema": "durable-workflow.beta-conformance.suite-result/v1",
        "candidate": {"name": candidate["candidate"]},
        "artifact_tuple": plan["components"],
        "source_identities": {},
        "distribution_identities": {},
        "runner": {},
        "server_runner": {},
        "github_run": run,
        "outcome": "pass",
        "experiments": {
            name: {
                "classification": "passed",
                "outcome": "pass",
                "result_sha256": hashlib.sha256(payloads[f"https://downloads.example/{run_id}/{name}.json"]).hexdigest(),
            }
            for name in experiments
        },
    }
    suite_url = f"https://downloads.example/{run_id}/suite-result.json"
    payloads[suite_url] = json.dumps(suite, sort_keys=True, separators=(",", ":")).encode()
    release_url = f"https://github.com/durable-workflow/.github/releases/tag/{tag}"
    release = {
        "assets": [
            {"browser_download_url": url, "name": url.rsplit("/", 1)[-1]} for url in payloads
        ],
        "draft": False,
        "html_url": release_url,
        "tag_name": tag,
    }
    return release, payloads, {"release": release_url, "run": run, "tag": tag}


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

        self.assertEqual("workspace-unavailable-beta-continuity-recovery", config["drill"])
        self.assertEqual("durable-workflow/.github", config["authority_issue"]["repository"])
        self.assertEqual(
            {
                10: "beta-continuity-post-acceptance-publication",
                11: "continuity-converges-routed-release-blockers",
            },
            {item["number"]: item["work_id"] for item in config["evidence_work_items"]},
        )
        self.assertEqual("workflow", config["first_component"])
        self.assertEqual("workspace-unavailable-recovery", config["plan_prefix"])
        self.assertEqual(
            "beta-continuity/workspace-unavailable-0b191da0d140/interrupted",
            config["superseded_interruption"]["tag"],
        )

    def test_evidence_work_item_inventory_is_declarative_and_unique(self) -> None:
        config = load_config(ROOT / "beta-continuity" / "config.json")
        future = {
            "number": 12,
            "repository": "durable-workflow/.github",
            "required_labels": [
                "authority:github",
                "beta:blocker",
                "completion:evidence-required",
                "status:ready",
            ],
            "work_id": "future-evidence-required-correction",
        }
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "config.json"
            config["evidence_work_items"].append(future)
            path.write_text(json.dumps(config), encoding="utf-8")
            self.assertEqual(3, len(load_config(path)["evidence_work_items"]))

            config["evidence_work_items"].append({**future, "work_id": "duplicate-location"})
            path.write_text(json.dumps(config), encoding="utf-8")
            with self.assertRaisesRegex(ContinuityError, "duplicate authority"):
                load_config(path)

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
            "tag": "beta-continuity-selection/workspace-unavailable-beta-continuity-recovery",
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

    def test_untrusted_lower_number_blocker_markers_cannot_steer_version_selection(self) -> None:
        config = load_config(ROOT / "beta-continuity" / "config.json")
        component = COMPONENTS["sdk-python"]
        dependency = "Blocks https://github.com/durable-workflow/.github/issues/2."

        def issue(
            number: int,
            version: str,
            *,
            labels: object,
            parent: str = dependency,
            marker_component: str = "sdk-python",
            pull_request: bool = False,
        ) -> dict[str, object]:
            value: dict[str, object] = {
                "body": (f"{parent}\n\n<!-- beta-continuity-blocker: {marker_component}-source-version-{version} -->"),
                "labels": labels,
                "number": number,
            }
            if pull_request:
                value["pull_request"] = {"url": "https://api.github.com/repos/example/pulls/1"}
            return value

        valid_labels = [{"name": label} for label in ROUTED_BLOCKER_LABELS]
        completed_labels = [{"name": label} for label in (*ROUTED_BLOCKER_LABELS[:-1], "status:done")]
        blocked_labels = [{"name": label} for label in (*ROUTED_BLOCKER_LABELS[:-1], "status:blocked")]
        adversarial_issues = [
            issue(1, "0.4.900", labels=[]),
            issue(2, "0.4.901", labels=valid_labels, pull_request=True),
            issue(3, "0.4.902", labels=[*valid_labels, {"color": "b60205"}]),
            issue(4, "0.4.903", labels=valid_labels, marker_component="sdk-rust"),
            issue(
                5,
                "0.4.904",
                labels=valid_labels,
                parent="Blocks https://github.com/durable-workflow/.github/issues/999.",
            ),
            issue(6, "0.4.905", labels=blocked_labels),
            issue(50, "0.4.104", labels=completed_labels),
        ]

        class AdversarialPlanningClient(PlanningClient):
            def json(self, url: str) -> object:
                if url == f"https://api.github.com/repos/{component.repository}/issues?state=all&per_page=100":
                    return adversarial_issues
                return super().json(url)

        client = AdversarialPlanningClient()
        client.latest["sdk-python"] = "0.4.104"
        first = select_versions(config, client)  # type: ignore[arg-type]
        second = select_versions(config, client)  # type: ignore[arg-type]

        self.assertEqual("0.4.104", first["versions"]["sdk-python"])
        self.assertEqual(first, second)

    def test_untrusted_marker_cannot_suppress_protected_blocker_routing(self) -> None:
        marker = "<!-- beta-continuity-blocker: sdk-python-source-version-0.4.103 -->"

        class RoutingWriter:
            def __init__(self) -> None:
                self.issues: list[dict[str, object]] = [
                    {
                        "body": marker,
                        "labels": [],
                        "number": 1,
                    },
                    {
                        "body": marker,
                        "labels": [{"name": label} for label in (*ROUTED_BLOCKER_LABELS[:-1], "status:blocked")],
                        "number": 2,
                    },
                    {
                        "body": marker,
                        "labels": [{"name": label} for label in ROUTED_BLOCKER_LABELS],
                        "number": 3,
                        "pull_request": {"url": "https://api.github.com/repos/example/pulls/3"},
                    },
                ]
                self.created: list[dict[str, object]] = []

            def list(self, _path: str) -> list[dict[str, object]]:
                return self.issues

            def request(self, method: str, _path: str, payload: dict[str, object]) -> None:
                self.assert_post(method)
                self.created.append(payload)
                self.issues.append(
                    {
                        **payload,
                        "labels": [{"name": label} for label in payload["labels"]],
                        "number": len(self.issues) + 1,
                        "state": "open",
                    }
                )

            @staticmethod
            def assert_post(method: str) -> None:
                if method != "POST":
                    raise AssertionError(f"unexpected method: {method}")

        state = {
            "outcome": "blocked",
            "selection": {"tag": "beta-continuity-selection/workspace-unavailable-beta-continuity-recovery"},
            "blockers": [
                {
                    "component": "sdk-python",
                    "reason": "source manifest has not reached the retained version",
                    "repository": COMPONENTS["sdk-python"].repository,
                    "slug": "sdk-python-source-version-0.4.103",
                    "version": "0.4.103",
                }
            ],
        }
        writer = RoutingWriter()
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            with patch("scripts.beta_continuity.GitHubWriter", return_value=writer):
                route_blockers(ROOT / "beta-continuity" / "config.json", state_path)
                route_blockers(ROOT / "beta-continuity" / "config.json", state_path)

        self.assertEqual(1, len(writer.created))
        self.assertEqual(list(ROUTED_BLOCKER_LABELS), writer.created[0]["labels"])

    def test_completed_protected_blocker_is_reopened_and_reactivated(self) -> None:
        marker = (
            "Blocks https://github.com/durable-workflow/.github/issues/2.\n\n"
            "<!-- beta-continuity-blocker: sdk-python-source-version-0.4.103 -->"
        )

        class RoutingWriter:
            def __init__(self) -> None:
                self.requests: list[tuple[str, str, dict[str, object]]] = []
                self.issues = [
                    {
                        "body": marker,
                        "labels": [
                            {"name": label}
                            for label in (
                                *ROUTED_BLOCKER_LABELS[:-1],
                                "status:done",
                                "component:sdk-python",
                            )
                        ],
                        "number": 5,
                        "state": "closed",
                    }
                ]

            def list(self, _path: str) -> list[dict[str, object]]:
                return self.issues

            def request(self, method: str, path: str, payload: dict[str, object]) -> None:
                self.requests.append((method, path, payload))
                issue = self.issues[0]
                issue["state"] = payload["state"]
                issue["labels"] = [{"name": label} for label in payload["labels"]]

        state = {
            "outcome": "blocked",
            "selection": {"tag": "beta-continuity-selection/workspace-unavailable-beta-continuity-recovery"},
            "blockers": [
                {
                    "component": "sdk-python",
                    "reason": "source manifest has not reached the retained version",
                    "repository": COMPONENTS["sdk-python"].repository,
                    "slug": "sdk-python-source-version-0.4.103",
                    "version": "0.4.103",
                }
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            state_path = Path(temporary) / "state.json"
            state_path.write_text(json.dumps(state), encoding="utf-8")
            writer = RoutingWriter()
            with patch("scripts.beta_continuity.GitHubWriter", return_value=writer):
                route_blockers(ROOT / "beta-continuity" / "config.json", state_path)
                route_blockers(ROOT / "beta-continuity" / "config.json", state_path)

        self.assertEqual(
            [
                (
                    "PATCH",
                    f"/repos/{COMPONENTS['sdk-python'].repository}/issues/5",
                    {
                        "state": "open",
                        "labels": [
                            "authority:github",
                            "beta:blocker",
                            "component:sdk-python",
                            "kind:release-blocker",
                            "priority:P1",
                            "status:ready",
                        ],
                    },
                )
            ],
            writer.requests,
        )

    def test_interruption_requires_a_provably_partial_publication(self) -> None:
        require_partial_publication({"workflow": {"version": "2.0.0-alpha.292"}}, ["waterline"])
        with self.assertRaises(ContinuityError):
            require_partial_publication({name: {} for name in COMPONENTS}, [])
        with self.assertRaises(ContinuityError):
            require_partial_publication({}, list(COMPONENTS))

    def test_acceptance_baseline_partitions_the_exact_plan(self) -> None:
        plan = continuity_plan()
        python_identity = plan["components"]["sdk-python"]
        evidence = {
            "schema": EVIDENCE_SCHEMA,
            "phase": "accepted",
            "outcome": "accepted",
            "observed_at": "2026-07-20T10:00:00Z",
            "release_plan": {
                "tag": f"release-plan/{plan['plan']}",
                "sha256": manifest_digest(plan),
            },
            "candidate_identity": {
                "components": plan["components"],
                "plan_sha256": manifest_digest(plan),
            },
            "public_components_at_acceptance": {"sdk-python": python_identity},
            "pending_components_at_acceptance": [name for name in COMPONENTS if name != "sdk-python"],
        }
        with patch("scripts.beta_continuity.read_public_json_file", return_value=evidence):
            baseline = accepted_publication_state(object(), plan, "a" * 40)  # type: ignore[arg-type]

        self.assertEqual({"sdk-python"}, set(baseline["public_components"]))
        self.assertNotIn("sdk-python", baseline["pending_components"])

        evidence.pop("pending_components_at_acceptance")
        with (
            patch("scripts.beta_continuity.read_public_json_file", return_value=evidence),
            self.assertRaisesRegex(ContinuityError, "complete publication baseline"),
        ):
            accepted_publication_state(object(), plan, "a" * 40)  # type: ignore[arg-type]

    def test_terminal_authority_binds_plan_source_and_qualification_artifacts(self) -> None:
        config = load_config(ROOT / "beta-continuity" / "config.json")
        plan = continuity_plan("workspace-unavailable-recovery-test")
        plan_commit = "1" * 40
        accepted_commit = "2" * 40
        completion_commit = "3" * 40
        complete_commit = "4" * 40
        noop_commit = "5" * 40
        controller_commit = "6" * 40
        plan_tag = f"release-plan/{plan['plan']}"
        completion_tag = f"release-candidate/{plan['channel']}/{plan['plan']}"
        published = {
            name: {
                "commit": identity["commit"],
                "published_at": "2026-07-20T10:10:00Z",
                "release_id": index + 1,
                "url": f"https://github.com/{COMPONENTS[name].repository}/releases/tag/{identity['version']}",
                "version": identity["version"],
            }
            for index, (name, identity) in enumerate(plan["components"].items())
        }
        candidate = candidate_manifest(plan)
        public_verification = {
            "schema": "durable-workflow.beta-candidate-verification/v1",
            "candidate": candidate["candidate"],
            "manifest_sha256": manifest_digest(candidate),
            "verified_at": "2026-07-20T10:20:00Z",
            "outcome": "verified",
            "components": {
                name: {"commit": identity["commit"], "outcome": "verified", "version": identity["version"]}
                for name, identity in plan["components"].items()
            },
        }
        qualification_targets = {
            name: {
                "branch": "v2" if name in {"workflow", "waterline"} else "main",
                "commit": identity["commit"],
                "protected_checks": ["qualification"],
                "successful_check_runs": {"qualification": index + 10},
            }
            for index, (name, identity) in enumerate(plan["components"].items())
        }
        qualification_targets["github-control-plane"] = {
            "branch": "main",
            "commit": controller_commit,
            "protected_checks": ["qualification"],
            "successful_check_runs": {"qualification": 99},
        }
        qualification = {
            "schema": "durable-workflow.github-target-qualification/v1",
            "targets": qualification_targets,
        }
        recorded_conformance_tag = f"beta-conformance/{candidate['candidate']}/300.1"
        recorded_conformance = {
            "release": f"https://github.com/durable-workflow/.github/releases/tag/{recorded_conformance_tag}",
            "run": {
                "repository": "durable-workflow/.github",
                "run_id": 300,
                "run_attempt": 1,
                "evidence_tag": recorded_conformance_tag,
            },
            "tag": recorded_conformance_tag,
        }
        replacement_conformance_tag = f"beta-conformance/{candidate['candidate']}/301.1"
        replacement_conformance = {
            "release": f"https://github.com/durable-workflow/.github/releases/tag/{replacement_conformance_tag}",
            "run": {
                "repository": "durable-workflow/.github",
                "run_id": 301,
                "run_attempt": 1,
                "evidence_tag": replacement_conformance_tag,
            },
            "tag": replacement_conformance_tag,
        }
        plan_record = {"tag": plan_tag, "commit": plan_commit, "sha256": manifest_digest(plan)}
        acceptance = {
            "schema": EVIDENCE_SCHEMA,
            "github_run": {"sha": controller_commit},
        }
        completion_artifact = {
            "schema": "durable-workflow.release-candidate/v1",
            "candidate": plan["plan"],
            "channel": plan["channel"],
            "release_plan": {"tag": plan_tag, "commit": plan_commit, "sha256": manifest_digest(plan)},
            "components": plan["components"],
        }
        completion_verification = {
            "schema": "durable-workflow.release-candidate-verification/v1",
            "candidate": plan["plan"],
            "channel": plan["channel"],
            "release_plan_sha256": manifest_digest(plan),
            "public_verification": public_verification,
        }
        complete_evidence = {
            "schema": EVIDENCE_SCHEMA,
            "drill": config["drill"],
            "phase": "complete",
            "outcome": "passed",
            "release_plan": {"tag": plan_tag, "sha256": manifest_digest(plan)},
            "accepted_phase": f"beta-continuity/{plan['plan']}/accepted",
            "interrupted_phase": f"beta-continuity/{plan['plan']}/interrupted",
            "resumed_phase": f"beta-continuity/{plan['plan']}/resumed",
            "plan_record": plan_record,
            "public_verification": {"tag": completion_tag, "commit": completion_commit},
            "conformance": recorded_conformance,
            "published_components": published,
        }
        noop_evidence = {
            "schema": EVIDENCE_SCHEMA,
            "drill": config["drill"],
            "phase": "no-op-confirmed",
            "outcome": "successful-scheduled-no-op-confirmed",
            "release_plan": {"tag": plan_tag, "sha256": manifest_digest(plan)},
            "complete_phase": {
                "tag": f"beta-continuity/{plan['plan']}/complete",
                "commit": complete_commit,
            },
            "successful_no_op_run": {
                "conclusion": "success",
                "created_at": "2026-07-20T10:30:00Z",
                "id": 301,
                "url": "https://github.com/durable-workflow/.github/actions/runs/301",
            },
        }
        records = {
            (plan_commit, "release-plan.json"): plan,
            (accepted_commit, "continuity-evidence.json"): acceptance,
            (accepted_commit, "target-qualification-evidence.json"): qualification,
            (completion_commit, "release-candidate.json"): completion_artifact,
            (completion_commit, "verification.json"): completion_verification,
            (complete_commit, "continuity-evidence.json"): complete_evidence,
            (complete_commit, "release-plan.json"): plan,
            (noop_commit, "continuity-evidence.json"): noop_evidence,
            (noop_commit, "release-plan.json"): plan,
        }
        tags = {
            plan_tag: plan_commit,
            f"beta-continuity/{plan['plan']}/accepted": accepted_commit,
            f"beta-continuity/{plan['plan']}/complete": complete_commit,
            f"beta-continuity/{plan['plan']}/no-op-confirmed": noop_commit,
            completion_tag: completion_commit,
        }

        def read_record(_client: object, commit: str, filename: str) -> object:
            return records[(commit, filename)]

        client = object()
        with (
            patch("scripts.beta_continuity.resolve_tag", side_effect=lambda _client, _repo, tag: tags.get(tag)),
            patch("scripts.beta_continuity.plan_record", return_value=plan_record),
            patch(
                "scripts.beta_continuity.public_phase_commit",
                side_effect=lambda _client, _plan, phase: tags.get(f"beta-continuity/{plan['plan']}/{phase}"),
            ),
            patch(
                "scripts.beta_continuity.accepted_plan_authority",
                return_value={"commit": accepted_commit},
            ),
            patch("scripts.beta_continuity.read_public_json_file", side_effect=read_record),
            patch("scripts.beta_continuity.component_publications", return_value=(published, [])),
            patch(
                "scripts.beta_continuity.conformance_evidence",
                return_value=replacement_conformance,
            ) as conformance_selection,
        ):
            authority = exact_completion_authority(
                client,  # type: ignore[arg-type]
                config,
                plan,
                complete_commit,
                noop_commit,
            )
            self.assertEqual(plan_record, authority["plan_record"])
            self.assertEqual(manifest_digest(qualification), authority["qualification"]["sha256"])
            self.assertEqual(replacement_conformance, authority["conformance"])
            self.assertEqual(recorded_conformance, complete_evidence["conformance"])
            conformance_selection.assert_called_once_with(
                client,
                plan,
                preferred=recorded_conformance,
            )

            qualification_targets["sdk-python"]["commit"] = "f" * 40
            with self.assertRaisesRegex(ContinuityError, "sdk-python.*exact plan source"):
                exact_completion_authority(
                    client,  # type: ignore[arg-type]
                    config,
                    plan,
                    complete_commit,
                    noop_commit,
                )

    def test_terminal_authority_fails_closed_without_public_artifact_evidence(self) -> None:
        config = load_config(ROOT / "beta-continuity" / "config.json")
        plan = continuity_plan("workspace-unavailable-recovery-test")
        plan_record = {
            "tag": f"release-plan/{plan['plan']}",
            "commit": "1" * 40,
            "sha256": manifest_digest(plan),
        }

        with (
            patch("scripts.beta_continuity.plan_record", return_value=plan_record),
            patch("scripts.beta_continuity.read_public_json_file", side_effect=[plan, None, {}]),
            patch("scripts.beta_continuity.public_phase_commit", return_value="2" * 40),
            patch("scripts.beta_continuity.accepted_plan_authority", return_value={"commit": "2" * 40}),
            patch("scripts.beta_continuity.accepted_qualification_evidence", return_value={}),
            patch("scripts.beta_continuity.resolve_tag", return_value="3" * 40),
            self.assertRaisesRegex(ContinuityError, "public completion artifact differs from the exact plan"),
        ):
            exact_completion_authority(
                object(),  # type: ignore[arg-type]
                config,
                plan,
                "4" * 40,
                "5" * 40,
            )

    def test_completion_fails_closed_when_a_configured_evidence_work_item_is_missing(self) -> None:
        config = load_config(ROOT / "beta-continuity" / "config.json")
        parent_specification = config["authority_issue"]
        parent = {
            "body": f"<!-- beta-work-id: {parent_specification['work_id']} -->",
            "labels": [{"name": label} for label in config["required_issue_labels"]],
            "number": parent_specification["number"],
            "state": "open",
        }
        present_specification = config["evidence_work_items"][0]
        present = {
            "body": "<!-- durable-workflow-work-id: beta-continuity-post-acceptance-publication -->",
            "labels": [{"name": label} for label in present_specification["required_labels"]],
            "number": present_specification["number"],
            "state": "open",
        }
        missing_specification = config["evidence_work_items"][1]
        parent_path = (
            f"/repos/{parent_specification['repository']}/issues/{parent_specification['number']}"
        )
        present_path = (
            f"/repos/{present_specification['repository']}/issues/{present_specification['number']}"
        )
        missing_path = (
            f"/repos/{missing_specification['repository']}/issues/{missing_specification['number']}"
        )

        class MissingWorkItemWriter:
            def __init__(self) -> None:
                self.requests: list[tuple[str, str]] = []

            @staticmethod
            def get(path: str) -> dict[str, object] | None:
                if path == parent_path:
                    return parent
                if path == present_path:
                    return present
                if path == missing_path:
                    return None
                raise AssertionError(f"unexpected GET path: {path}")

            def request(self, method: str, path: str, _payload: dict[str, object]) -> None:
                self.requests.append((method, path))

        writer = MissingWorkItemWriter()
        with self.assertRaises(ContinuityError) as raised:
            close_authority_issue(writer, config, {})  # type: ignore[arg-type]

        self.assertIn(
            f"trusted evidence work item {missing_path} has an invalid GitHub response",
            str(raised.exception),
        )
        self.assertEqual([], writer.requests)
        self.assertEqual("open", parent["state"])

    def test_routed_blockers_close_before_parent_and_ignore_untrusted_markers(self) -> None:
        config = load_config(ROOT / "beta-continuity" / "config.json")
        plan = continuity_plan("workspace-unavailable-recovery-test")
        component = "sdk-python"
        repository = COMPONENTS[component].repository
        version = plan["components"][component]["version"]
        dependency = "Blocks https://github.com/durable-workflow/.github/issues/2."
        marker = f"<!-- beta-continuity-blocker: {component}-source-version-{version} -->"
        trusted = {
            "body": f"{dependency}\n\n{marker}",
            "html_url": f"https://github.com/{repository}/issues/5",
            "labels": [{"name": label} for label in (*ROUTED_BLOCKER_LABELS, f"component:{component}")],
            "number": 5,
            "state": "open",
        }
        untrusted = {
            "body": f"{dependency}\n\n{marker}",
            "html_url": f"https://github.com/{repository}/issues/1",
            "labels": [],
            "number": 1,
            "state": "open",
        }
        mismatched = {
            "body": (f"{dependency}\n\n<!-- beta-continuity-blocker: {component}-source-version-9.9.9 -->"),
            "labels": [{"name": label} for label in ROUTED_BLOCKER_LABELS],
            "number": 2,
            "state": "open",
        }
        parent = {
            "body": "<!-- beta-work-id: github-only-beta-continuity-drill -->",
            "html_url": "https://github.com/durable-workflow/.github/issues/2",
            "labels": [{"name": label} for label in config["required_issue_labels"]],
            "number": 2,
            "state": "open",
        }
        live_work_item_bodies = {
            10: ("<!-- durable-workflow-work-id: beta-continuity-post-acceptance-publication -->"),
            11: ("<!-- durable-workflow-work-id: continuity-converges-routed-release-blockers -->"),
        }
        evidence_work_items = {
            specification["number"]: {
                "body": live_work_item_bodies[specification["number"]],
                "html_url": (f"https://github.com/{specification['repository']}/issues/{specification['number']}"),
                "labels": [{"name": label} for label in specification["required_labels"]],
                "number": specification["number"],
                "state": "open",
            }
            for specification in config["evidence_work_items"]
        }

        class ClosureWriter:
            def __init__(self) -> None:
                self.issues = {repository: [untrusted, mismatched, trusted]}
                self.parent = parent
                self.evidence_work_items = evidence_work_items
                self.comments: dict[str, list[dict[str, object]]] = {}
                self.requests: list[tuple[str, str]] = []
                self.fail_blocker_patch_once = False

            def list(self, path: str) -> list[dict[str, object]]:
                if path.endswith("/comments"):
                    return self.comments.setdefault(path, [])
                for slug, issues in self.issues.items():
                    if path.startswith(f"/repos/{slug}/issues?"):
                        return issues
                return []

            def get(self, path: str) -> dict[str, object]:
                if path == "/repos/durable-workflow/.github/issues/2":
                    return self.parent
                for number, work_item in self.evidence_work_items.items():
                    if path == f"/repos/durable-workflow/.github/issues/{number}":
                        return work_item
                for slug, issues in self.issues.items():
                    prefix = f"/repos/{slug}/issues/"
                    if path.startswith(prefix):
                        number = int(path.removeprefix(prefix))
                        return next(issue for issue in issues if issue["number"] == number)
                raise AssertionError(f"unexpected GET path: {path}")

            def request(self, method: str, path: str, payload: dict[str, object]) -> None:
                self.requests.append((method, path))
                if method == "POST":
                    self.comments.setdefault(path, []).append(payload)
                    return
                if path == f"/repos/{repository}/issues/5" and self.fail_blocker_patch_once:
                    self.fail_blocker_patch_once = False
                    raise ContinuityError("injected blocker close interruption")
                issue = self.get(path)
                issue["state"] = payload["state"]
                issue["labels"] = [{"name": label} for label in payload["labels"]]

        completion = {
            "plan": plan,
            "plan_record": {
                "tag": f"release-plan/{plan['plan']}",
                "commit": "a" * 40,
                "sha256": manifest_digest(plan),
            },
            "public_verification": {
                "tag": f"release-candidate/{plan['channel']}/{plan['plan']}",
                "commit": "b" * 40,
            },
            "qualification": {
                "tag": f"beta-continuity/{plan['plan']}/accepted",
                "commit": "c" * 40,
                "sha256": "d" * 64,
            },
            "conformance": {
                "release": "https://github.com/durable-workflow/.github/releases/tag/example",
                "tag": "beta-conformance/example/1.1",
            },
        }
        writer = ClosureWriter()
        with self.assertRaisesRegex(ContinuityError, "active routed blocker.*differs"):
            close_authority_issue(writer, config, completion)  # type: ignore[arg-type]
        self.assertEqual([], writer.requests)
        mismatched["state"] = "closed"
        mismatched["labels"] = [{"name": label} for label in (*ROUTED_BLOCKER_LABELS[:-1], "status:done")]
        expected_work_item_body = evidence_work_items[11]["body"]
        evidence_work_items[11]["body"] = (
            f"{expected_work_item_body}\n<!-- durable-workflow-work-id: UNTRUSTED-ALIAS -->"
        )
        with self.assertRaisesRegex(ContinuityError, "does not match its configured work-id"):
            close_authority_issue(writer, config, completion)  # type: ignore[arg-type]
        evidence_work_items[11]["body"] = expected_work_item_body
        expected_work_item_labels = evidence_work_items[11]["labels"]
        evidence_work_items[11]["labels"] = [
            label for label in expected_work_item_labels if label["name"] != "beta:blocker"
        ]
        with self.assertRaisesRegex(ContinuityError, "does not match its configured work-id"):
            close_authority_issue(writer, config, completion)  # type: ignore[arg-type]
        evidence_work_items[11]["labels"] = expected_work_item_labels
        self.assertEqual([], writer.requests)
        writer.fail_blocker_patch_once = True
        with self.assertRaisesRegex(ContinuityError, "injected blocker close interruption"):
            close_authority_issue(writer, config, completion)  # type: ignore[arg-type]
        first = close_authority_issue(writer, config, completion)  # type: ignore[arg-type]
        first_requests = list(writer.requests)
        second = close_authority_issue(writer, config, completion)  # type: ignore[arg-type]

        self.assertEqual(first, second)
        self.assertEqual(
            [
                ("POST", f"/repos/{repository}/issues/5/comments"),
                ("PATCH", f"/repos/{repository}/issues/5"),
                ("PATCH", f"/repos/{repository}/issues/5"),
                ("POST", "/repos/durable-workflow/.github/issues/10/comments"),
                ("PATCH", "/repos/durable-workflow/.github/issues/10"),
                ("POST", "/repos/durable-workflow/.github/issues/11/comments"),
                ("PATCH", "/repos/durable-workflow/.github/issues/11"),
                ("POST", "/repos/durable-workflow/.github/issues/2/comments"),
                ("PATCH", "/repos/durable-workflow/.github/issues/2"),
            ],
            first_requests,
        )
        self.assertEqual(first_requests, writer.requests)
        self.assertEqual("open", untrusted["state"])
        self.assertEqual("closed", mismatched["state"])
        self.assertEqual("closed", trusted["state"])
        self.assertTrue(all(item["state"] == "closed" for item in evidence_work_items.values()))
        self.assertEqual("closed", parent["state"])
        self.assertEqual([5], [item["number"] for item in first["blockers"]])
        self.assertEqual([10, 11], [item["number"] for item in first["evidence_work_items"]])

    def test_release_plan_callback_requires_and_dispatches_the_exact_public_acceptance(self) -> None:
        plan = continuity_plan("workspace-unavailable-recovery-test")
        acceptance = {
            "commit": "a" * 40,
            "pending_components": ["workflow"],
            "public_components": {name: {} for name in COMPONENTS if name != "workflow"},
            "tag": f"beta-continuity/{plan['plan']}/accepted",
        }

        class CallbackWriter:
            def __init__(self) -> None:
                self.runs: list[dict[str, object]] = []
                self.dispatches: list[tuple[str, str, str, dict[str, str]]] = []
                self.dispatch_error: ContinuityError | None = None

            def get(self, _path: str) -> dict[str, object]:
                return {"workflow_runs": self.runs}

            def dispatch(self, repository: str, workflow: str, ref: str, inputs: dict[str, str]) -> None:
                if self.dispatch_error is not None:
                    raise self.dispatch_error
                self.dispatches.append((repository, workflow, ref, inputs))

        writer = CallbackWriter()
        with tempfile.TemporaryDirectory() as temporary:
            plan_path = Path(temporary) / "release-plan.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            with (
                patch("scripts.beta_continuity.PublicClient"),
                patch("scripts.beta_continuity.accepted_plan_authority", return_value=acceptance),
                patch("scripts.beta_continuity.GitHubWriter", return_value=writer),
                patch.dict(os.environ, {"GITHUB_TOKEN": "token"}),
            ):
                dispatch_accepted_continuity(plan_path, None)

            expected_tag = f"release-plan/{plan['plan']}"
            self.assertEqual(
                [("durable-workflow/.github", "beta-continuity.yml", "main", {"plan_tag": expected_tag})],
                writer.dispatches,
            )

            writer.runs.append(
                {
                    "conclusion": None,
                    "display_title": f"Continue {expected_tag}",
                    "id": 101,
                    "status": "in_progress",
                }
            )
            with (
                patch("scripts.beta_continuity.PublicClient"),
                patch("scripts.beta_continuity.accepted_plan_authority", return_value=acceptance),
                patch("scripts.beta_continuity.GitHubWriter", return_value=writer),
                patch.dict(os.environ, {"GITHUB_TOKEN": "token"}),
            ):
                dispatch_accepted_continuity(plan_path, None)
            self.assertEqual(1, len(writer.dispatches))

            writer.runs[-1].update({"conclusion": "success", "status": "completed"})
            with (
                patch("scripts.beta_continuity.PublicClient"),
                patch("scripts.beta_continuity.accepted_plan_authority", return_value=acceptance),
                patch("scripts.beta_continuity.GitHubWriter", return_value=writer),
                patch.dict(os.environ, {"GITHUB_TOKEN": "token"}),
            ):
                dispatch_accepted_continuity(plan_path, None)
            self.assertEqual(1, len(writer.dispatches))

            writer.runs[-1].update({"conclusion": "failure", "status": "completed"})
            writer.dispatch_error = ContinuityError("GitHub dispatch failed (500)")
            with (
                patch("scripts.beta_continuity.PublicClient"),
                patch("scripts.beta_continuity.accepted_plan_authority", return_value=acceptance),
                patch("scripts.beta_continuity.GitHubWriter", return_value=writer),
                patch.dict(os.environ, {"GITHUB_TOKEN": "token"}),
                self.assertRaisesRegex(ContinuityError, "dispatch failed"),
            ):
                dispatch_accepted_continuity(plan_path, None)

            with (
                patch("scripts.beta_continuity.PublicClient"),
                patch("scripts.beta_continuity.accepted_plan_authority", return_value=None),
                patch("scripts.beta_continuity.GitHubWriter") as writer_factory,
                patch.dict(os.environ, {"GITHUB_TOKEN": "token"}),
            ):
                dispatch_accepted_continuity(plan_path, None)
            writer_factory.assert_not_called()

    def test_public_acceptance_binds_the_callback_to_the_recorded_plan(self) -> None:
        plan = continuity_plan("workspace-unavailable-recovery-test")
        mutated = continuity_plan("workspace-unavailable-recovery-test")
        mutated["components"]["workflow"]["commit"] = "f" * 40
        with (
            patch("scripts.beta_continuity.resolve_tag", return_value="a" * 40),
            patch("scripts.beta_continuity.read_public_json_file", return_value=mutated),
            self.assertRaisesRegex(ContinuityError, "differs from the recorded release plan"),
        ):
            accepted_plan_authority(object(), plan)  # type: ignore[arg-type]

    def test_public_acceptance_rejects_a_tag_that_moves_during_callback_validation(self) -> None:
        plan = continuity_plan("workspace-unavailable-recovery-test")
        evidence = {
            "schema": EVIDENCE_SCHEMA,
            "phase": "accepted",
            "outcome": "accepted",
            "observed_at": "2026-07-20T10:00:00Z",
            "release_plan": {
                "tag": f"release-plan/{plan['plan']}",
                "sha256": manifest_digest(plan),
            },
            "candidate_identity": {
                "components": plan["components"],
                "plan_sha256": manifest_digest(plan),
            },
            "public_components_at_acceptance": {},
            "pending_components_at_acceptance": list(COMPONENTS),
        }
        with (
            patch("scripts.beta_continuity.resolve_tag", side_effect=["a" * 40, "b" * 40]) as resolve,
            patch("scripts.beta_continuity.read_public_json_file", side_effect=[plan, evidence]),
            self.assertRaisesRegex(ContinuityError, "moved while the callback was validated"),
        ):
            accepted_plan_authority(object(), plan)  # type: ignore[arg-type]

        self.assertEqual(2, resolve.call_count)

    def test_callback_plan_input_must_match_the_exact_accepted_identity(self) -> None:
        plan = continuity_plan("workspace-unavailable-recovery-test")
        issue = {
            "number": 2,
            "repository": "durable-workflow/.github",
            "state": "open",
            "work_id": "github-only-beta-continuity-drill",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with (
                patch("scripts.beta_continuity.PublicClient"),
                patch("scripts.beta_continuity.authority_issue", return_value=issue),
                patch("scripts.beta_continuity.accepted_plan", return_value=plan),
                self.assertRaisesRegex(ContinuityError, "but exact accepted plan is"),
            ):
                plan_command(
                    ROOT / "beta-continuity" / "config.json",
                    root / "release-plan.json",
                    root / "expected.json",
                    root / "state.json",
                    None,
                    "release-plan/unrelated",
                )

    def test_only_post_acceptance_exact_plan_recovery_can_trigger_interruption(self) -> None:
        plan_tag = "release-plan/workspace-unavailable-recovery-test"
        acceptance = {
            "observed_at": "2026-07-20T10:00:00Z",
            "pending_components": [name for name in COMPONENTS if name != "sdk-python"],
            "public_components": {"sdk-python": {"version": "0.4.103"}},
        }
        published = {
            "sdk-python": {
                "published_at": "2026-07-20T09:00:00Z",
                "version": "0.4.103",
            },
            "workflow": {
                "published_at": "2026-07-20T10:05:00Z",
                "version": "2.0.0-alpha.292",
            },
        }

        class RecoveryWriter:
            created_at = "2026-07-20T10:01:00Z"

            def get(self, _path: str) -> dict[str, object]:
                return {
                    "workflow_runs": [
                        {
                            "conclusion": "success",
                            "created_at": self.created_at,
                            "display_title": f"Recover {plan_tag}",
                            "event": "workflow_dispatch",
                            "html_url": "https://github.com/durable-workflow/workflow/actions/runs/123",
                            "id": 123,
                            "status": "completed",
                        }
                    ]
                }

        writer = RecoveryWriter()
        triggers = recovery_publication_triggers(writer, plan_tag, acceptance, published)  # type: ignore[arg-type]
        self.assertEqual({"workflow"}, set(triggers))
        self.assertNotIn("sdk-python", triggers)

        writer.created_at = "2026-07-20T10:06:00Z"
        self.assertEqual(
            {},
            recovery_publication_triggers(writer, plan_tag, acceptance, published),  # type: ignore[arg-type]
        )

    def test_invalid_immutable_interruption_requires_a_new_identity(self) -> None:
        plan = continuity_plan()
        acceptance = {
            "commit": "a" * 40,
            "observed_at": "2026-07-20T10:00:00Z",
            "pending_components": ["workflow"],
            "tag": "beta-continuity/continuity-test/accepted",
        }
        invalid = {
            "accepted_phase": {"tag": acceptance["tag"], "commit": acceptance["commit"]},
            "phase": "interrupted",
        }
        with (
            patch(
                "scripts.beta_continuity.read_public_json_file",
                side_effect=[invalid, plan],
            ),
            self.assertRaisesRegex(ContinuityError, "new continuity identity"),
        ):
            validate_interrupted_evidence(
                object(),  # type: ignore[arg-type]
                plan,
                "b" * 40,
                acceptance,
            )

    def test_completion_waits_for_a_later_scheduled_no_op_before_closing(self) -> None:
        plan = continuity_plan("workspace-unavailable-recovery-test")
        issue = {
            "number": 2,
            "repository": "durable-workflow/.github",
            "state": "open",
            "work_id": "github-only-beta-continuity-drill",
        }
        completion = {
            "phase": "complete",
            "observed_at": "2026-07-20T10:00:00Z",
            "github_run": {"id": "100"},
        }

        def phase_commit(_client: object, _plan: object, phase: str) -> str | None:
            return {"accepted": "a" * 40, "complete": "c" * 40}.get(phase)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan_path = root / "release-plan.json"
            state_path = root / "state.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")

            class NoopWriter:
                @staticmethod
                def get(_path: str) -> dict[str, object]:
                    return {
                        "workflow_runs": [
                            {
                                "conclusion": "success",
                                "created_at": "2026-07-20T10:10:00Z",
                                "event": "schedule",
                                "html_url": "https://github.com/durable-workflow/.github/actions/runs/102",
                                "id": 102,
                                "status": "completed",
                            }
                        ]
                    }

            with (
                patch("scripts.beta_continuity.PublicClient"),
                patch("scripts.beta_continuity.GitHubWriter", return_value=NoopWriter()),
                patch("scripts.beta_continuity.authority_issue", return_value=issue),
                patch("scripts.beta_continuity.public_phase_commit", side_effect=phase_commit),
                patch("scripts.beta_continuity.read_public_json_file", return_value=completion),
                patch("scripts.beta_continuity.close_authority_issue") as close,
                patch.dict(
                    os.environ,
                    {"GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ID": "101"},
                    clear=False,
                ),
            ):
                advance_command(ROOT / "beta-continuity" / "config.json", plan_path, state_path, None, None)

            self.assertEqual("waiting-for-subsequent-scheduled-no-op", json.loads(state_path.read_bytes())["outcome"])
            close.assert_not_called()

            with (
                patch("scripts.beta_continuity.PublicClient"),
                patch("scripts.beta_continuity.GitHubWriter", return_value=NoopWriter()),
                patch("scripts.beta_continuity.authority_issue", return_value=issue),
                patch("scripts.beta_continuity.public_phase_commit", side_effect=phase_commit),
                patch("scripts.beta_continuity.read_public_json_file", return_value=completion),
                patch(
                    "scripts.beta_continuity.record_phase",
                    return_value={"tag": "beta-continuity/test/no-op-confirmed", "commit": "d" * 40},
                ) as record,
                patch("scripts.beta_continuity.ensure_issue_comment"),
                patch("scripts.beta_continuity.exact_completion_authority", return_value={}),
                patch("scripts.beta_continuity.close_authority_issue") as close,
                patch.dict(
                    os.environ,
                    {"GITHUB_EVENT_NAME": "schedule", "GITHUB_RUN_ID": "103"},
                    clear=False,
                ),
            ):
                advance_command(ROOT / "beta-continuity" / "config.json", plan_path, state_path, None, None)

            self.assertEqual("no-op-confirmed", record.call_args.args[2])
            close.assert_called_once()

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

    def test_completed_conformance_recovers_artifacts_without_rerunning_the_matrix(self) -> None:
        candidate = candidate_manifest(continuity_plan("workspace-unavailable-recovery-test"))

        class ConformanceWriter:
            def __init__(self) -> None:
                self.source_runs: list[dict[str, object]] = []
                self.retention_runs: list[dict[str, object]] = []
                self.dispatches: list[tuple[str, str, str, dict[str, str]]] = []

            def get(self, path: str) -> dict[str, object]:
                if "beta-conformance-retention.yml" in path:
                    return {"workflow_runs": self.retention_runs}
                if "beta-conformance.yml" in path:
                    return {"workflow_runs": self.source_runs}
                raise AssertionError(path)

            def dispatch(self, repository: str, workflow: str, ref: str, inputs: dict[str, str]) -> None:
                self.dispatches.append((repository, workflow, ref, inputs))

        writer = ConformanceWriter()
        progress = ensure_conformance_execution_or_retention(writer, candidate)  # type: ignore[arg-type]
        self.assertEqual("conformance-execution-requested", progress["outcome"])
        self.assertEqual("beta-conformance.yml", writer.dispatches[-1][1])
        self.assertEqual("none", writer.dispatches[-1][3]["injected_canary_failure_experiment"])

        writer.dispatches.clear()
        writer.source_runs.append(
            {
                "conclusion": "failure",
                "display_title": f"Conformance {candidate['candidate']}",
                "html_url": "https://github.com/durable-workflow/.github/actions/runs/29775218461",
                "id": 29775218461,
                "run_attempt": 1,
                "status": "completed",
            }
        )
        progress = ensure_conformance_execution_or_retention(writer, candidate)  # type: ignore[arg-type]

        self.assertEqual("conformance-retention-requested", progress["outcome"])
        self.assertEqual(
            [
                (
                    "durable-workflow/.github",
                    "beta-conformance-retention.yml",
                    "main",
                    {"source_run_attempt": "1", "source_run_id": "29775218461"},
                )
            ],
            writer.dispatches,
        )

        writer.retention_runs.append(
            {
                "conclusion": "success",
                "display_title": "Retain conformance 29775218461.1",
                "event": "workflow_run",
                "id": 29780000000,
                "run_attempt": 1,
                "status": "completed",
            }
        )
        ensure_conformance_execution_or_retention(writer, candidate)  # type: ignore[arg-type]
        self.assertEqual(1, len(writer.dispatches))

        writer.dispatches.clear()
        writer.retention_runs = [
            {
                "conclusion": "failure",
                "display_title": "Retain conformance 29775218461.1",
                "event": "workflow_run",
                "id": 29780000001,
                "run_attempt": 1,
                "status": "completed",
            }
        ]
        progress = ensure_conformance_execution_or_retention(writer, candidate)  # type: ignore[arg-type]
        self.assertEqual("conformance-retention-requested", progress["outcome"])
        self.assertEqual(1, len(writer.dispatches))
        self.assertEqual("beta-conformance-retention.yml", writer.dispatches[0][1])

        writer.retention_runs.append(
            {
                "conclusion": "failure",
                "display_title": "Retain conformance 29775218461.1",
                "event": "workflow_dispatch",
                "id": 29780000002,
                "run_attempt": 1,
                "status": "completed",
            }
        )
        writer.dispatches.clear()
        progress = ensure_conformance_execution_or_retention(writer, candidate)  # type: ignore[arg-type]
        self.assertEqual("conformance-retention-terminal-failure", progress["outcome"])
        self.assertEqual([], writer.dispatches)

    def test_unsafe_recorded_conformance_release_is_replaced_by_the_earliest_newer_valid_release(self) -> None:
        plan = continuity_plan("existing-release-safety-test")
        unsafe_release, unsafe_payloads, unsafe_reference = conformance_release_fixture(
            plan,
            12345,
            sensitive=True,
        )
        replacement_release, replacement_payloads, replacement_reference = conformance_release_fixture(plan, 12346)

        class ExistingReleaseClient:
            @staticmethod
            def json(_url: str) -> list[dict[str, object]]:
                return [replacement_release, unsafe_release]

            @staticmethod
            def bytes(url: str) -> bytes:
                return (unsafe_payloads | replacement_payloads)[url]

        with (
            patch("scripts.beta_continuity.validate_conformance_plan"),
            patch("scripts.beta_continuity.validate_experiment_result"),
        ):
            self.assertEqual(
                replacement_reference,
                conformance_evidence(
                    ExistingReleaseClient(),  # type: ignore[arg-type]
                    plan,
                    preferred=unsafe_reference,
                ),
            )

    def test_multiple_valid_conformance_releases_preserve_recorded_authority(self) -> None:
        plan = continuity_plan("stable-conformance-authority-test")
        first_release, first_payloads, first_reference = conformance_release_fixture(plan, 12346)
        later_release, later_payloads, _later_reference = conformance_release_fixture(plan, 12347)

        class MultipleReleaseClient:
            def __init__(self, releases: list[dict[str, Any]]) -> None:
                self.releases = releases

            def json(self, _url: str) -> list[dict[str, Any]]:
                return self.releases

            @staticmethod
            def bytes(url: str) -> bytes:
                return (first_payloads | later_payloads)[url]

        with (
            patch("scripts.beta_continuity.validate_conformance_plan"),
            patch("scripts.beta_continuity.validate_experiment_result"),
        ):
            for releases in ([later_release, first_release], [first_release, later_release]):
                with self.subTest(releases=[release["tag_name"] for release in releases]):
                    client = MultipleReleaseClient(releases)
                    self.assertEqual(first_reference, conformance_evidence(client, plan))  # type: ignore[arg-type]
                    self.assertEqual(
                        first_reference,
                        conformance_evidence(client, plan, preferred=first_reference),  # type: ignore[arg-type]
                    )

    def test_phase_records_are_append_only_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            remote = root / "remote.git"
            checkout = root / "checkout"
            run(["git", "init", "--bare", str(remote)], root)
            run(["git", "clone", str(remote), str(checkout)], root)
            plan = continuity_plan()
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
        self.assertIn("plan_tag:", source)
        self.assertIn("environment: beta-product-work", source)
        self.assertIn("--expected-plan-tag", source)
        self.assertIn("scripts/beta_continuity.py advance", source)
        self.assertIn("scripts/beta_continuity.py route-blockers", source)
        self.assertIn("if: ${{ steps.plan.outcome == 'success' }}", source)
        self.assertNotIn("run: exit 1", source)
        self.assertNotIn("/workspace", source)


if __name__ == "__main__":
    unittest.main()
