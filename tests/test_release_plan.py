from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator, ValidationError

from scripts.beta_candidate import CandidateError, canonical_json
from scripts.release_plan import (
    COMPONENTS,
    CONTINUITY_RESOLUTION_SCHEMA,
    CONTINUITY_RESOLUTION_TAG_PREFIX,
    FOUNDATION_COMMIT,
    FOUNDATION_TAG,
    LEGACY_SCHEMA,
    OBSERVATION_FAILURE_REASON,
    OCCUPIED_SOURCE_MANIFEST_REASON,
    PLAN_TAG_PREFIX,
    PREPARATION_SCHEMA,
    SCHEMA,
    SOURCE_CHANGELOGS,
    SOURCE_MANIFEST_REASON,
    SUPERSESSION_REASON,
    candidate_manifest,
    check_plan_compatibility,
    completion_manifest,
    conflict_component_names,
    discover_plan,
    failed_observation_state,
    is_immediate_version_successor,
    load_continuity_supersession,
    load_plan,
    load_public_supersession,
    manifest_digest,
    parse_conflict_components,
    preflight_plan,
    prepare_release,
    prepare_supersession,
    protected_environment_evidence,
    protected_run_approval_evidence,
    record_completion,
    record_current_plan_authorization,
    record_plan,
    record_supersession,
    require_prior_plans_completed,
    terminal_failure_state,
    validate_observation_handoff,
    validate_plan,
    validate_recorded_plan,
    validate_release_preparation,
    validate_successor_transition,
    validate_supersession_handoff,
    validate_supersession_record,
)
from scripts.release_plan import (
    main as release_plan_main,
)
from tests.verification_fixture import (
    candidate_verification,
    legacy_beta_one_candidate_manifest,
    legacy_beta_one_release_plan,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def cargo_manifest(version: str) -> bytes:
    return f'[package]\nname = "durable-workflow"\nversion = "{version}"\n'.encode()


def continuity_resolution_qualification() -> dict[str, object]:
    return {
        "repository": "durable-workflow/.github",
        "workflow": ".github/workflows/beta-candidate.yml",
        "event": "push",
        "head_branch": "main",
        "head_sha": "9" * 40,
        "run_id": 987,
        "run_attempt": 2,
        "status": "completed",
        "conclusion": "success",
    }


def continuity_resolution_qualification_run() -> dict[str, object]:
    qualification = continuity_resolution_qualification()
    return {
        "id": qualification["run_id"],
        "run_attempt": qualification["run_attempt"],
        "repository": {"full_name": "durable-workflow/.github"},
        "head_repository": {"full_name": "durable-workflow/.github"},
        "path": ".github/workflows/beta-candidate.yml@main",
        "event": qualification["event"],
        "head_branch": qualification["head_branch"],
        "head_sha": qualification["head_sha"],
        "status": qualification["status"],
        "conclusion": qualification["conclusion"],
    }


def python_manifest(version: str) -> bytes:
    return f'[project]\nname = "durable-workflow"\nversion = "{version}"\n'.encode()


def planned_source_manifest(url: str, plan: dict[str, object]) -> bytes:
    if url.endswith("/pyproject.toml?ref=" + plan["components"]["sdk-python"]["commit"]):
        return python_manifest(plan["components"]["sdk-python"]["version"])
    if url.endswith("/Cargo.toml?ref=" + plan["components"]["sdk-rust"]["commit"]):
        return cargo_manifest(plan["components"]["sdk-rust"]["version"])
    raise AssertionError(f"unexpected source manifest request: {url}")


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


def python_source_manifest_record(commit: str, version: str) -> dict[str, object]:
    raw = python_manifest(version)
    return {
        "declared_version": version,
        "package": "durable-workflow",
        "path": "pyproject.toml",
        "sha256": hashlib.sha256(raw).hexdigest(),
        "source_commit": commit,
        "url": f"https://github.com/durable-workflow/sdk-python/blob/{commit}/pyproject.toml",
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


def release_preparation(plan: dict[str, object], release_date: str = "2026-07-19") -> dict[str, object]:
    components: dict[str, object] = {}
    for name, identity in plan["components"].items():
        body = f"Prepared source changes for {name}."
        heading = f"## [{identity['version']}] - {release_date}"
        markdown = f"{heading}\n\n{body}\n"
        repository = COMPONENTS[name].repository
        if name in SOURCE_CHANGELOGS:
            kind = "changelog-unreleased"
            url = f"https://github.com/{repository}/blob/{identity['commit']}/CHANGELOG.md"
        else:
            kind = "source-commit-message"
            url = f"https://github.com/{repository}/commit/{identity['commit']}"
        components[name] = {
            "version": identity["version"],
            "source_commit": identity["commit"],
            "release_notes": {
                "format": "text/markdown",
                "heading": heading,
                "markdown": markdown,
                "release_date": release_date,
                "sha256": hashlib.sha256(markdown.encode()).hexdigest(),
                "source": {
                    "kind": kind,
                    "sha256": hashlib.sha256(body.encode()).hexdigest(),
                    "url": url,
                },
            },
        }
    preparation = {
        "schema": PREPARATION_SCHEMA,
        "release_plan": {
            "tag": f"{PLAN_TAG_PREFIX}{plan['plan']}",
            "sha256": manifest_digest(plan),
        },
        "components": components,
    }
    validate_release_preparation(preparation, plan)
    return preparation


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


def continuity_supersession_records(
    prior: dict[str, object],
    requested: dict[str, object],
    prior_commit: str,
    *,
    accepted_commit: str = "c" * 40,
    interruption_commit: str = "d" * 40,
) -> dict[str, object]:
    accepted_tag = f"beta-continuity/{requested['plan']}/accepted"
    interruption_tag = f"beta-continuity/{prior['plan']}/interrupted"
    prior_tag = f"release-plan/{prior['plan']}"
    prior_digest = manifest_digest(prior)
    requested_digest = manifest_digest(requested)
    interruption_evidence = {
        "schema": "durable-workflow.beta-continuity.evidence/v1",
        "phase": "interrupted",
        "outcome": "intentionally-interrupted",
        "release_plan": {"tag": prior_tag, "sha256": prior_digest},
        "plan_record": {
            "tag": prior_tag,
            "commit": prior_commit,
            "sha256": prior_digest,
        },
    }
    accepted_evidence = {
        "schema": "durable-workflow.beta-continuity.evidence/v1",
        "phase": "accepted",
        "outcome": "accepted",
        "release_plan": {
            "tag": f"release-plan/{requested['plan']}",
            "sha256": requested_digest,
        },
        "candidate_identity": {
            "components": requested["components"],
            "plan_sha256": requested_digest,
        },
        "superseded_interruption": {
            "commit": interruption_commit,
            "evidence_sha256": manifest_digest(interruption_evidence),
            "plan_sha256": prior_digest,
            "reason": "missing-post-acceptance-publication-trigger",
            "tag": interruption_tag,
        },
    }
    return {
        "accepted_commit": accepted_commit,
        "accepted_evidence": accepted_evidence,
        "accepted_plan": copy.deepcopy(requested),
        "accepted_tag": accepted_tag,
        "interruption_commit": interruption_commit,
        "interruption_evidence": interruption_evidence,
        "interruption_plan": copy.deepcopy(prior),
        "interruption_tag": interruption_tag,
    }


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


def environment_protection_authority() -> tuple[dict[str, object], set[tuple[int, str]]]:
    return environment_protection_evidence(), {(29, "release-reviewer")}


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
                "url": ("https://api.github.com/repos/durable-workflow/.github/environments/release-plan-supersession"),
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
            {
                "id": 19,
                "prevent_self_review": False,
                "type": "required_reviewers",
                "reviewers": [
                    {
                        "type": "User",
                        "reviewer": {
                            "avatar_url": "https://avatars.githubusercontent.com/u/29?v=4",
                            "html_url": "https://github.com/release-reviewer",
                            "id": 29,
                            "login": "release-reviewer",
                            "node_id": "U_kgDOReviewer",
                            "site_admin": False,
                            "type": "User",
                            "url": "https://api.github.com/users/release-reviewer",
                        },
                    }
                ],
            }
        ],
        "deployment_branch_policy": {
            "custom_branch_policies": True,
            "protected_branches": False,
        },
    }


def workflow_run() -> dict[str, object]:
    return {
        "actor": {"login": "release-operator"},
        "conclusion": "success",
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": "f" * 40,
        "html_url": "https://github.com/durable-workflow/.github/actions/runs/456",
        "id": 456,
        "path": ".github/workflows/release-plan-supersession.yml@main",
        "repository": {"full_name": "durable-workflow/.github"},
        "run_attempt": 1,
        "status": "completed",
    }


def approval_history() -> list[dict[str, object]]:
    approval = environment_approval_evidence()
    return [
        {
            "comment": approval["comment"],
            "environments": [
                {
                    **approval["environments"][0],
                    "can_admins_bypass": True,
                    "created_at": "2026-07-23T00:00:00Z",
                    "updated_at": "2026-07-23T00:00:00Z",
                }
            ],
            "state": approval["state"],
            "user": {
                **approval["user"],
                "avatar_url": "https://avatars.githubusercontent.com/u/29?v=4",
                "site_admin": False,
                "type": "User",
            },
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
                "durable-workflow/.github/.github/workflows/release-plan-supersession.yml@refs/heads/main"
            ),
        },
    }


class ReleasePlanEntryPointTest(unittest.TestCase):
    def test_observer_uses_the_shared_immutable_discovery_contract(self) -> None:
        candidate = release_plan("beta")
        tag = f"{PLAN_TAG_PREFIX}{candidate['plan']}"
        commit = "a" * 40
        prepared = release_preparation(candidate)
        release = {
            "tag_name": tag,
            "assets": [
                {"name": "release-plan.json", "browser_download_url": "https://example.test/plan"},
                {
                    "name": "release-preparation.json",
                    "browser_download_url": "https://example.test/preparation",
                },
            ],
        }
        client = mock.Mock()
        client.json.return_value = release
        client.bytes.side_effect = [canonical_json(candidate), canonical_json(prepared)]

        with (
            mock.patch(
                "scripts.release_plan.recovery_discovery.select_implicit_plan_authority",
                return_value={"tag": tag},
            ) as select,
            mock.patch("scripts.release_plan.resolve_tag", return_value=commit),
            mock.patch(
                "scripts.release_plan.read_public_record",
                side_effect=[candidate, prepared],
            ),
        ):
            selected_tag, selected_plan, selected_preparation = discover_plan(client, None)

        self.assertEqual(tag, selected_tag)
        self.assertEqual(candidate, selected_plan)
        self.assertEqual(prepared, selected_preparation)
        select.assert_called_once()
        self.assertNotIn("/releases?per_page=", client.json.call_args.args[0])

    def test_scheduled_discovery_fails_closed_without_plan_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "release-plan.json"
            preparation = root / "release-preparation.json"
            github_output = root / "github-output"
            arguments = [
                "release_plan.py",
                "discover",
                str(destination),
                "--preparation",
                str(preparation),
                "--allow-empty",
                "--github-output",
                str(github_output),
            ]
            with (
                mock.patch.object(sys, "argv", arguments),
                mock.patch(
                    "scripts.release_plan.discover_plan",
                    side_effect=CandidateError("no public release plan is available"),
                ),
            ):
                self.assertEqual(1, release_plan_main())

            self.assertFalse(github_output.exists())
            self.assertFalse(destination.exists())
            self.assertFalse(preparation.exists())

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
            "validate-current",
            "check",
            "preflight",
            "record",
            "record-current-authorization",
            "prepare-supersession",
            "record-supersession",
            "validate-supersession-handoff",
            "discover",
            "observe",
            "validate-observation-handoff",
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
            "current-release-plan.yml",
            "release-plan.yml",
            "release-plan-observer.yml",
            "release-plan-supersession.yml",
        ):
            source = (REPOSITORY_ROOT / ".github" / "workflows" / workflow).read_text(encoding="utf-8")
            self.assertIn("concurrency:\n  group: release-plan-registry\n", source)

    def test_recorded_accepted_plan_dispatches_continuity_with_scoped_permission(self) -> None:
        source = (REPOSITORY_ROOT / ".github" / "workflows" / "release-plan.yml").read_text(encoding="utf-8")

        self.assertIn("needs: validate-and-record", source)
        self.assertIn("python scripts/beta_continuity.py dispatch-accepted", source)
        self.assertIn("permissions:\n      actions: write\n      contents: read", source)


class ReleasePlanValidationTest(unittest.TestCase):
    def test_new_beta_plan_requires_current_product_train(self) -> None:
        plan = release_plan("beta")
        plan["components"] = {
            name: {"version": "2.0.0-beta.17", "commit": identity["commit"]}
            for name, identity in plan["components"].items()
        }

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "release-plan.json"
            path.write_bytes(canonical_json(plan))
            self.assertEqual(plan, load_plan(path, require_current=True))

            plan["components"]["server"]["version"] = "0.2.701"
            path.write_bytes(canonical_json(plan))
            with self.assertRaisesRegex(CandidateError, "supported product train 2.0.0-beta.17"):
                load_plan(path, require_current=True)

    def test_supersession_handoff_binds_dispatch_identities(self) -> None:
        failed = release_plan()
        successor = successor_plan(failed)
        record = supersession_record(failed, successor)
        failed_tag = record["failed_plan"]["tag"]
        conflict_components = conflict_component_names(record["conflicts"])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record_path = root / "release-plan-failure.json"
            successor_path = root / "successor-release-plan.json"
            authorized_path = root / "authorized-release-plan-failure.json"
            record_path.write_bytes(canonical_json(record))
            successor_path.write_bytes(canonical_json(successor))

            validated = validate_supersession_handoff(
                record_path,
                successor_path,
                authorized_path,
                expected_failed_plan_tag=failed_tag,
                expected_conflict_components=",".join(conflict_components),
            )

            self.assertEqual(record, validated)
            self.assertEqual(canonical_json(record), authorized_path.read_bytes())

            with self.assertRaisesRegex(CandidateError, "trusted failed plan dispatch input"):
                validate_supersession_handoff(
                    record_path,
                    successor_path,
                    authorized_path,
                    expected_failed_plan_tag=f"{PLAN_TAG_PREFIX}different-plan",
                    expected_conflict_components=conflict_components,
                )
            with self.assertRaisesRegex(CandidateError, "trusted conflict component dispatch input"):
                validate_supersession_handoff(
                    record_path,
                    successor_path,
                    authorized_path,
                    expected_failed_plan_tag=failed_tag,
                    expected_conflict_components="server",
                )

    def test_observation_handoff_canonicalizes_only_plan_bound_evidence(self) -> None:
        plan = release_plan()
        preparation = release_preparation(plan)
        candidate = candidate_manifest(plan)
        verification = candidate_verification(candidate)
        state = {
            "schema": "durable-workflow.release-state/v1",
            "plan": plan["plan"],
            "channel": plan["channel"],
            "plan_sha256": manifest_digest(plan),
            "observed_at": "2026-07-20T21:00:00Z",
            "phase": "complete",
            "outcome": "verified",
            "components": verification["components"],
            "durable_evidence": {
                "release_plan_tag": f"{PLAN_TAG_PREFIX}{plan['plan']}",
                "component_actions": "repository Actions runs and public version tags",
                "release_preparation_sha256": manifest_digest(preparation),
            },
            "resume_action": "No recovery action is required",
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = root / "inputs"
            authority = root / "authority"
            outputs = root / "outputs"
            inputs.mkdir()
            authority.mkdir()
            paths = {
                "plan": inputs / "release-plan.json",
                "preparation": inputs / "release-preparation.json",
                "candidate": inputs / "candidate-verifier-input.json",
                "verification": inputs / "verification.json",
                "state": inputs / "release-state.json",
            }
            for name, value in (
                ("plan", plan),
                ("preparation", preparation),
                ("candidate", candidate),
                ("verification", verification),
                ("state", state),
            ):
                paths[name].write_bytes(canonical_json(value))
            authoritative_plan = authority / "release-plan.json"
            authoritative_preparation = authority / "release-preparation.json"
            authoritative_plan.write_bytes(canonical_json(plan))
            authoritative_preparation.write_bytes(canonical_json(preparation))
            authority_arguments = {
                "authoritative_plan_path": authoritative_plan,
                "authoritative_preparation_path": authoritative_preparation,
                "expected_plan_tag": f"{PLAN_TAG_PREFIX}{plan['plan']}",
                "expected_plan_sha256": manifest_digest(plan),
                "expected_preparation_sha256": manifest_digest(preparation),
                "expected_verification_outcome": "success",
                "client": mock.Mock(),
            }

            with mock.patch("scripts.release_plan.revalidate_verification", return_value=verification):
                result = validate_observation_handoff(
                    paths["plan"],
                    paths["preparation"],
                    paths["candidate"],
                    paths["verification"],
                    paths["state"],
                    outputs,
                    **authority_arguments,
                )

            self.assertEqual(f"{PLAN_TAG_PREFIX}{plan['plan']}", result["tag"])
            self.assertEqual(canonical_json(plan), (outputs / "release-plan.json").read_bytes())
            changed_state = copy.deepcopy(state)
            changed_state["plan_sha256"] = "f" * 64
            paths["state"].write_bytes(canonical_json(changed_state))
            with (
                mock.patch("scripts.release_plan.revalidate_verification", return_value=verification),
                self.assertRaisesRegex(CandidateError, "trusted reconstruction"),
            ):
                validate_observation_handoff(
                    paths["plan"],
                    paths["preparation"],
                    paths["candidate"],
                    paths["verification"],
                    paths["state"],
                    outputs,
                    **authority_arguments,
                )

            paths["state"].write_bytes(canonical_json(state))
            mismatched_outcome_arguments = {**authority_arguments, "expected_verification_outcome": "failure"}
            with self.assertRaisesRegex(CandidateError, "contradicts the trusted verification-step outcome"):
                validate_observation_handoff(
                    paths["plan"],
                    paths["preparation"],
                    paths["candidate"],
                    paths["verification"],
                    paths["state"],
                    outputs,
                    **mismatched_outcome_arguments,
                )

            injected_state = copy.deepcopy(state)
            injected_state["durable_evidence"]["same_user_process"] = "fabricated"
            paths["state"].write_bytes(canonical_json(injected_state))
            with (
                mock.patch("scripts.release_plan.revalidate_verification", return_value=verification),
                self.assertRaisesRegex(CandidateError, "trusted reconstruction"),
            ):
                validate_observation_handoff(
                    paths["plan"],
                    paths["preparation"],
                    paths["candidate"],
                    paths["verification"],
                    paths["state"],
                    outputs,
                    **authority_arguments,
                )

            oversized_state = copy.deepcopy(state)
            oversized_state["resume_action"] = "x" * 4097
            paths["state"].write_bytes(canonical_json(oversized_state))
            with self.assertRaisesRegex(CandidateError, "oversized or invalid text"):
                validate_observation_handoff(
                    paths["plan"],
                    paths["preparation"],
                    paths["candidate"],
                    paths["verification"],
                    paths["state"],
                    outputs,
                    **authority_arguments,
                )

            paths["state"].write_bytes(canonical_json(state))
            steered_plan = copy.deepcopy(plan)
            steered_plan["plan"] = "credential-steered-plan"
            paths["plan"].write_bytes(canonical_json(steered_plan))
            with self.assertRaisesRegex(CandidateError, "originally selected plan tag"):
                validate_observation_handoff(
                    paths["plan"],
                    paths["preparation"],
                    paths["candidate"],
                    paths["verification"],
                    paths["state"],
                    outputs,
                    **authority_arguments,
                )

    def test_failed_observer_reason_tampering_fails_before_first_writer_output(self) -> None:
        plan = release_plan()
        preparation = release_preparation(plan)
        candidate = candidate_manifest(plan)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = root / "inputs"
            authority = root / "authority"
            outputs = root / "outputs"
            inputs.mkdir()
            authority.mkdir()
            paths = {
                "plan": inputs / "release-plan.json",
                "preparation": inputs / "release-preparation.json",
                "candidate": inputs / "candidate-verifier-input.json",
                "verification": inputs / "verification.json",
                "state": inputs / "release-state.json",
            }
            paths["plan"].write_bytes(canonical_json(plan))
            paths["preparation"].write_bytes(canonical_json(preparation))
            paths["candidate"].write_bytes(canonical_json(candidate))
            authoritative_plan = authority / "release-plan.json"
            authoritative_preparation = authority / "release-preparation.json"
            authoritative_plan.write_bytes(canonical_json(plan))
            authoritative_preparation.write_bytes(canonical_json(preparation))
            state = failed_observation_state(plan, preparation, "2026-07-20T21:00:00Z")
            state["reason"] = "cli: verifier-controlled failure detail"
            paths["state"].write_bytes(canonical_json(state))

            with self.assertRaisesRegex(CandidateError, "writer's trusted reconstruction"):
                validate_observation_handoff(
                    paths["plan"],
                    paths["preparation"],
                    paths["candidate"],
                    paths["verification"],
                    paths["state"],
                    outputs,
                    authoritative_plan_path=authoritative_plan,
                    authoritative_preparation_path=authoritative_preparation,
                    expected_plan_tag=f"{PLAN_TAG_PREFIX}{plan['plan']}",
                    expected_plan_sha256=manifest_digest(plan),
                    expected_preparation_sha256=manifest_digest(preparation),
                    expected_verification_outcome="failure",
                    client=mock.Mock(),
                )

            self.assertFalse(outputs.exists())
            state["reason"] = OBSERVATION_FAILURE_REASON
            paths["state"].write_bytes(canonical_json(state))
            validate_observation_handoff(
                paths["plan"],
                paths["preparation"],
                paths["candidate"],
                paths["verification"],
                paths["state"],
                outputs,
                authoritative_plan_path=authoritative_plan,
                authoritative_preparation_path=authoritative_preparation,
                expected_plan_tag=f"{PLAN_TAG_PREFIX}{plan['plan']}",
                expected_plan_sha256=manifest_digest(plan),
                expected_preparation_sha256=manifest_digest(preparation),
                expected_verification_outcome="failure",
                client=mock.Mock(),
            )
            durable_state = json.loads((outputs / "release-state.json").read_bytes())
            self.assertEqual(OBSERVATION_FAILURE_REASON, durable_state["reason"])

    def test_completion_rejects_a_handoff_for_a_different_public_plan(self) -> None:
        plan = release_plan()
        different = copy.deepcopy(plan)
        different["components"]["server"]["commit"] = "e" * 40
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plan_path = root / "release-plan.json"
            verification_path = root / "verification.json"
            plan_path.write_bytes(canonical_json(plan))
            verification_path.write_text("{}", encoding="utf-8")
            with (
                mock.patch("scripts.release_plan.resolve_tag", return_value="a" * 40),
                mock.patch("scripts.release_plan.read_public_record", return_value=different),
                self.assertRaisesRegex(CandidateError, "immutable Git authority"),
            ):
                record_completion(
                    root,
                    plan_path,
                    verification_path,
                    remote="origin",
                    authoritative_completion=root / "authoritative-completion.json",
                    authoritative_verification=root / "authoritative-verification.json",
                    client=mock.Mock(),
                )

    def test_preparation_derives_exact_notes_from_immutable_sources(self) -> None:
        plan = release_plan()

        class FixtureClient:
            def bytes(self, url: str, **_kwargs: object) -> bytes:
                component = next(name for name in SOURCE_CHANGELOGS if f"/{name}/" in url)
                return (
                    f"# Changelog\n\n## [Unreleased]\n\nSource changes for {component}.\n\n"
                    "## [0.0.1] - 2026-07-18\n\nEarlier changes.\n"
                ).encode()

            def json(self, url: str, **_kwargs: object) -> dict[str, object]:
                component = next(name for name in COMPONENTS if f"/{name}/" in url)
                return {"commit": {"message": f"Source changes for {component}."}}

        preparation = prepare_release(plan, FixtureClient(), "2026-07-19")

        self.assertEqual(set(COMPONENTS), set(preparation["components"]))
        for name, identity in plan["components"].items():
            entry = preparation["components"][name]
            self.assertEqual(identity["version"], entry["version"])
            self.assertEqual(identity["commit"], entry["source_commit"])
            self.assertEqual(
                f"## [{identity['version']}] - 2026-07-19",
                entry["release_notes"]["heading"],
            )
            self.assertEqual(
                hashlib.sha256(entry["release_notes"]["markdown"].encode()).hexdigest(),
                entry["release_notes"]["sha256"],
            )

        preparation["components"]["sdk-php"]["version"] = "9.9.9"
        with self.assertRaisesRegex(CandidateError, "different planned identity"):
            validate_release_preparation(preparation, plan)

        preparation = release_preparation(plan)
        preparation["components"]["sdk-php"]["release_notes"]["source"]["url"] = (
            f"https://github.com/durable-workflow/sdk-php/blob/{'f' * 40}/CHANGELOG.md"
        )
        with self.assertRaisesRegex(CandidateError, "invalid note-source evidence"):
            validate_release_preparation(preparation, plan)

    def test_preparation_schema_accepts_the_machine_record(self) -> None:
        schema = json.loads((REPOSITORY_ROOT / "release-plans" / "preparation-schema.json").read_bytes())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(release_preparation(release_plan()))

    def test_continuity_resolution_schema_requires_qualified_producer_identity(self) -> None:
        schema = json.loads(
            (REPOSITORY_ROOT / "release-plans" / "continuity-resolution-schema.json").read_bytes()
        )
        selection = json.loads(
            (REPOSITORY_ROOT / "release-plans" / "continuity-successor-selection.json").read_bytes()
        )
        resolution = {
            **selection,
            "schema": CONTINUITY_RESOLUTION_SCHEMA,
            "qualification": continuity_resolution_qualification(),
        }
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(resolution)
        for field in ("workflow", "head_sha", "run_id", "run_attempt", "status", "conclusion"):
            invalid = copy.deepcopy(resolution)
            del invalid["qualification"][field]
            with self.subTest(field=field), self.assertRaises(ValidationError):
                Draft202012Validator(schema).validate(invalid)

    def test_alpha_plan_is_channel_bound(self) -> None:
        plan = release_plan()
        validate_plan(plan)
        schema = json.loads((REPOSITORY_ROOT / "release-plans" / "schema.json").read_bytes())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(plan)
        candidate = candidate_manifest(plan)
        self.assertEqual("alpha-recovery-proof-1", candidate["candidate"])
        self.assertEqual(plan["components"], candidate["components"])
        preparation = release_preparation(plan)
        completion = completion_manifest(plan, "a" * 40, preparation)
        self.assertEqual("alpha", completion["channel"])
        self.assertEqual("durable-workflow.release-candidate/v1", completion["schema"])

        legacy = copy.deepcopy(plan)
        legacy["schema"] = LEGACY_SCHEMA
        with self.assertRaisesRegex(CandidateError, "release plan schema"):
            validate_plan(legacy)
        with self.assertRaisesRegex(CandidateError, "not an exact recorded historical contract"):
            validate_recorded_plan(legacy)

    def test_exact_historical_beta_one_plan_and_candidate_remain_paired(self) -> None:
        plan = legacy_beta_one_release_plan()
        candidate = legacy_beta_one_candidate_manifest()

        self.assertEqual(
            "e1fc6e20c9d2ded0b5e7ac4d6be75ba861d31fc4b2db651dc0272dca623f2c7f",
            manifest_digest(plan),
        )
        validate_recorded_plan(plan)
        self.assertEqual(candidate, candidate_manifest(plan))

        unrecorded = copy.deepcopy(plan)
        unrecorded["plan"] = "beta-1-replacement"
        with self.assertRaisesRegex(CandidateError, "not an exact recorded historical contract"):
            validate_recorded_plan(unrecorded)

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

    def test_plan_component_versions_require_strict_semver(self) -> None:
        schema = json.loads((REPOSITORY_ROOT / "release-plans" / "schema.json").read_bytes())
        validator = Draft202012Validator(schema)
        for malformed in ("01.0.0", "1.0.0-alpha.01", "1.0.0-alpha..1", "1.0.0\n"):
            plan = release_plan("beta")
            plan["components"]["server"]["version"] = malformed

            with self.subTest(version=malformed), self.assertRaisesRegex(
                CandidateError,
                "components.server.version must be an exact SemVer release",
            ):
                validate_plan(plan)
            with self.subTest(version=malformed), self.assertRaises(ValidationError):
                validator.validate(plan)

    def test_plan_accepts_valid_prerelease_and_build_metadata(self) -> None:
        schema = json.loads((REPOSITORY_ROOT / "release-plans" / "schema.json").read_bytes())
        validator = Draft202012Validator(schema)
        for valid in (
            "1.0.0-alpha.1",
            "1.0.0-alpha.1+build.01",
            "1.0.0+build.01",
        ):
            plan = release_plan("beta")
            plan["components"]["server"]["version"] = valid

            with self.subTest(version=valid):
                validate_plan(plan)
                validator.validate(plan)

    def test_derived_release_plan_schemas_share_strict_semver_validation(self) -> None:
        version_schemas = {
            "candidate-schema.json": ("$defs", "component", "properties", "version"),
            "failure-schema.json": ("$defs", "version"),
            "preparation-schema.json": ("$defs", "component", "properties", "version"),
        }
        malformed_versions = ("01.0.0", "1.0.0-alpha.01", "1.0.0-alpha..1", "1.0.0\n")
        valid_versions = ("1.0.0-alpha.1", "1.0.0-alpha.1+build.01", "1.0.0+build.01")

        for filename, path in version_schemas.items():
            schema = json.loads((REPOSITORY_ROOT / "release-plans" / filename).read_bytes())
            Draft202012Validator.check_schema(schema)
            version_schema = schema
            for segment in path:
                version_schema = version_schema[segment]
            validator = Draft202012Validator(version_schema)
            for malformed in malformed_versions:
                with self.subTest(schema=filename, version=malformed), self.assertRaises(
                    ValidationError
                ):
                    validator.validate(malformed)
            for valid in valid_versions:
                with self.subTest(schema=filename, version=valid):
                    validator.validate(valid)

    def test_plan_rejects_a_different_foundation(self) -> None:
        plan = release_plan()
        plan["foundation"]["commit"] = "0" * 40
        with self.assertRaisesRegex(CandidateError, "proven immutable candidate foundation"):
            validate_plan(plan)

    def test_preflight_rejects_python_source_manifest_version_mismatch(self) -> None:
        plan = release_plan()
        plan["components"]["sdk-python"]["version"] = "0.4.100"
        workflow_source = (
            b"on:\n  schedule:\n  workflow_dispatch:\n"
            b"steps:\n  - run: recovery resolve --preparation-output release-preparation.json\n"
        )
        workflow_digest = hashlib.sha256(workflow_source).hexdigest()
        recovery_authority = {
            name: {
                "repository": component.repository,
                "ref": f"refs/heads/{'v2' if name in {'workflow', 'waterline'} else 'main'}",
                "path": ".github/workflows/release-plan-recovery.yml",
                "state": "active",
                "sha256": workflow_digest,
            }
            for name, component in COMPONENTS.items()
        }

        class FixtureClient:
            def bytes(self, url: str, **_kwargs: object) -> bytes:
                if url.endswith("pyproject.toml?ref=" + plan["components"]["sdk-python"]["commit"]):
                    return python_manifest("0.4.99")
                if url.endswith("Cargo.toml?ref=" + plan["components"]["sdk-rust"]["commit"]):
                    return cargo_manifest(plan["components"]["sdk-rust"]["version"])
                if url.endswith("release-plan-recovery.yml?ref=v2") or url.endswith(
                    "release-plan-recovery.yml?ref=main"
                ):
                    return workflow_source
                if url.endswith("scripts/ci/component-release-recovery.py?ref=v2") or url.endswith(
                    "scripts/ci/component-release-recovery.py?ref=main"
                ):
                    return (
                        b'CONTINUITY_TAG_PREFIX = "beta-continuity/"\n'
                        b"def scheduled_continuity_pause():\n  pass\n"
                        b'if args.plan_tag is None:\n  state = {"phase": "continuity-gate"}\n'
                    )
                raise AssertionError(f"unexpected bytes request: {url}")

            def json(self, url: str, **_kwargs: object) -> object:
                if "/actions/workflows/" in url:
                    return {
                        "html_url": url,
                        "id": 1,
                        "path": ".github/workflows/release-plan-recovery.yml",
                        "state": "active",
                    }
                if "/commits/" in url:
                    return {}
                repository = url.removeprefix("https://api.github.com/repos/durable-workflow/")
                return {"default_branch": "v2" if repository in {"workflow", "waterline"} else "main"}

        with (
            mock.patch(
                "scripts.release_plan.read_public_record",
                return_value={"candidate": "beta-continuity-foundation"},
            ),
            mock.patch("scripts.release_plan.resolve_tag", return_value=None),
            mock.patch("scripts.release_plan.require_prior_plans_completed", return_value={}),
            mock.patch(
                "scripts.release_plan.load_recovery_workflow_authority",
                return_value=(
                    recovery_authority,
                    {
                        "repository": "durable-workflow/.github",
                        "ref": "refs/heads/main",
                        "commit": "a" * 40,
                        "path": "release-recovery/authority.json",
                        "sha256": "b" * 64,
                        "qualification": {"conclusion": "success"},
                    },
                ),
            ),
            self.assertRaisesRegex(CandidateError, "sdk-python source manifest declares 0.4.99"),
        ):
            preflight_plan(plan, FixtureClient())

    def test_new_plan_cannot_strand_an_interrupted_prior_plan(self) -> None:
        prior = release_plan()
        prior["plan"] = "plan-a"
        requested = release_plan()
        requested["plan"] = "plan-b"

        class FixtureClient:
            def json(self, url: str) -> list[dict[str, str]]:
                if url.endswith("matching-refs/tags/beta-continuity/"):
                    return []
                return [{"ref": "refs/tags/release-plan/plan-a"}]

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=["a" * 40, None, None, None]),
            mock.patch("scripts.release_plan.read_public_record", return_value=prior),
            mock.patch("scripts.release_plan.load_public_supersession", return_value=None),
            self.assertRaisesRegex(CandidateError, "prior plan release-plan/plan-a is incomplete"),
        ):
            require_prior_plans_completed(requested, FixtureClient())

    def test_exact_continuity_successor_can_retain_a_diagnostic_interruption(self) -> None:
        prior = release_plan()
        prior["plan"] = "plan-a"
        requested = release_plan()
        requested["plan"] = "plan-b"
        prior_commit = "a" * 40
        records = continuity_supersession_records(prior, requested, prior_commit)

        class FixtureClient:
            def json(self, _url: str) -> list[dict[str, str]]:
                return [{"ref": "refs/tags/release-plan/plan-a"}]

        def resolve(_client: object, _repository: str, tag: str) -> str | None:
            return {
                "release-plan/plan-a": prior_commit,
                "release-candidate/alpha/plan-a": None,
                records["accepted_tag"]: records["accepted_commit"],
                records["interruption_tag"]: records["interruption_commit"],
            }.get(tag)

        def read_record(_client: object, tag: str, _commit: str, filename: str) -> dict[str, object]:
            if tag == "release-plan/plan-a":
                return prior
            if tag == records["accepted_tag"]:
                return records["accepted_evidence"] if filename == "continuity-evidence.json" else requested
            if tag == records["interruption_tag"]:
                return records["interruption_evidence"] if filename == "continuity-evidence.json" else prior
            raise AssertionError(f"unexpected public record {tag}:{filename}")

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", side_effect=read_record),
            mock.patch("scripts.release_plan.load_public_supersession", return_value=None),
        ):
            evidence = require_prior_plans_completed(requested, FixtureClient())

        self.assertEqual(
            "superseded-diagnostic-interruption",
            evidence["release-plan/plan-a"]["outcome"],
        )
        self.assertEqual(records["accepted_commit"], evidence["release-plan/plan-a"]["accepted_commit"])

    def test_completed_continuity_successors_terminalize_the_interruption_for_a_future_plan(self) -> None:
        interrupted = release_plan()
        interrupted["plan"] = "plan-a"
        first_successor = release_plan()
        first_successor["plan"] = "plan-b"
        second_successor = release_plan()
        second_successor["plan"] = "plan-c"
        ordinary = release_plan()
        ordinary["plan"] = "plan-x"
        future = release_plan("beta")
        future["plan"] = "plan-d"
        plan_commits = {
            "release-plan/plan-a": "a" * 40,
            "release-plan/plan-b": "b" * 40,
            "release-plan/plan-c": "c" * 40,
            "release-plan/plan-x": "3" * 40,
        }
        first_records = continuity_supersession_records(
            interrupted,
            first_successor,
            plan_commits["release-plan/plan-a"],
            accepted_commit="d" * 40,
            interruption_commit="e" * 40,
        )
        second_records = continuity_supersession_records(
            interrupted,
            second_successor,
            plan_commits["release-plan/plan-a"],
            accepted_commit="f" * 40,
            interruption_commit="e" * 40,
        )
        completion_commits = {
            "release-candidate/alpha/plan-b": "1" * 40,
            "release-candidate/alpha/plan-c": "2" * 40,
            "release-candidate/alpha/plan-x": "4" * 40,
        }
        ordinary_records = continuity_supersession_records(
            interrupted,
            ordinary,
            plan_commits["release-plan/plan-a"],
            accepted_commit="5" * 40,
            interruption_commit="e" * 40,
        )
        ordinary_records["accepted_evidence"].pop("superseded_interruption")

        resolution = {
            "schema": CONTINUITY_RESOLUTION_SCHEMA,
            "qualification": continuity_resolution_qualification(),
            "interruption": {
                "plan": {
                    "tag": "release-plan/plan-a",
                    "commit": plan_commits["release-plan/plan-a"],
                    "sha256": manifest_digest(interrupted),
                },
                "evidence": {
                    "tag": first_records["interruption_tag"],
                    "commit": first_records["interruption_commit"],
                    "sha256": manifest_digest(first_records["interruption_evidence"]),
                },
            },
            "successor_claims": [
                {
                    "plan": {
                        "tag": "release-plan/plan-b",
                        "commit": plan_commits["release-plan/plan-b"],
                        "sha256": manifest_digest(first_successor),
                    },
                    "acceptance": {
                        "tag": first_records["accepted_tag"],
                        "commit": first_records["accepted_commit"],
                        "sha256": manifest_digest(first_records["accepted_evidence"]),
                    },
                },
                {
                    "plan": {
                        "tag": "release-plan/plan-c",
                        "commit": plan_commits["release-plan/plan-c"],
                        "sha256": manifest_digest(second_successor),
                    },
                    "acceptance": {
                        "tag": second_records["accepted_tag"],
                        "commit": second_records["accepted_commit"],
                        "sha256": manifest_digest(second_records["accepted_evidence"]),
                    },
                },
            ],
        }
        resolution["selected_successor"] = resolution["successor_claims"][1]["plan"]
        resolution_tag = f"{CONTINUITY_RESOLUTION_TAG_PREFIX}plan-a/{manifest_digest(resolution)}"
        resolution_commit = "6" * 40

        class FixtureClient:
            def __init__(
                self,
                resolution_tags: list[str],
                qualification_run: object | None = None,
            ) -> None:
                self.resolution_tags = resolution_tags
                self.qualification_run = (
                    continuity_resolution_qualification_run()
                    if qualification_run is None
                    else qualification_run
                )

            def json(self, url: str) -> object:
                if url.endswith("matching-refs/tags/release-plan/"):
                    return [{"ref": f"refs/tags/{tag}"} for tag in plan_commits]
                if url.endswith("matching-refs/tags/release-plan-continuity-resolution/plan-a/"):
                    return [{"ref": f"refs/tags/{tag}"} for tag in self.resolution_tags]
                if "/actions/runs/987/attempts/2" in url:
                    return self.qualification_run
                raise AssertionError(f"unexpected registry request {url}")

        def resolve(_client: object, _repository: str, tag: str) -> str | None:
            return {
                **plan_commits,
                **completion_commits,
                first_records["accepted_tag"]: first_records["accepted_commit"],
                second_records["accepted_tag"]: second_records["accepted_commit"],
                ordinary_records["accepted_tag"]: ordinary_records["accepted_commit"],
                first_records["interruption_tag"]: first_records["interruption_commit"],
                resolution_tag: resolution_commit,
            }.get(tag)

        plans = {
            "release-plan/plan-a": interrupted,
            "release-plan/plan-b": first_successor,
            "release-plan/plan-c": second_successor,
            "release-plan/plan-x": ordinary,
        }
        accepted = {
            first_records["accepted_tag"]: first_records,
            second_records["accepted_tag"]: second_records,
            ordinary_records["accepted_tag"]: ordinary_records,
        }

        def read_record(_client: object, tag: str, _commit: str, filename: str) -> dict[str, object]:
            if tag in plans:
                if filename == "release-preparation.json":
                    raise CandidateError("public request failed (404)")
                return plans[tag]
            if tag in accepted:
                records = accepted[tag]
                return (
                    records["accepted_evidence"] if filename == "continuity-evidence.json" else records["accepted_plan"]
                )
            if tag == first_records["interruption_tag"]:
                return (
                    first_records["interruption_evidence"]
                    if filename == "continuity-evidence.json"
                    else first_records["interruption_plan"]
                )
            if tag == resolution_tag:
                return resolution
            if tag == "release-candidate/alpha/plan-b":
                return completion_manifest(first_successor, plan_commits["release-plan/plan-b"])
            if tag == "release-candidate/alpha/plan-c":
                return completion_manifest(second_successor, plan_commits["release-plan/plan-c"])
            if tag == "release-candidate/alpha/plan-x":
                return completion_manifest(ordinary, plan_commits["release-plan/plan-x"])
            raise AssertionError(f"unexpected public record {tag}:{filename}")

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", side_effect=read_record),
            mock.patch("scripts.release_plan.load_public_supersession", return_value=None),
        ):
            with self.assertRaisesRegex(CandidateError, "multiple continuity successors"):
                require_prior_plans_completed(future, FixtureClient([]))
            evidence = require_prior_plans_completed(future, FixtureClient([resolution_tag]))

        terminal = evidence["release-plan/plan-a"]
        self.assertEqual("superseded-diagnostic-interruption", terminal["outcome"])
        self.assertEqual(second_records["accepted_tag"], terminal["accepted_tag"])
        self.assertEqual("release-plan/plan-c", terminal["successor_plan_tag"])
        self.assertEqual("completed", evidence["release-plan/plan-b"]["outcome"])
        self.assertEqual("completed", evidence["release-plan/plan-c"]["outcome"])
        self.assertEqual("completed", evidence["release-plan/plan-x"]["outcome"])
        invalid_qualifications = (
            ([], "qualification is absent"),
            (
                {**continuity_resolution_qualification_run(), "status": "queued", "conclusion": None},
                "qualification is pending",
            ),
            (
                {**continuity_resolution_qualification_run(), "conclusion": "failure"},
                "qualification failed",
            ),
            (
                {**continuity_resolution_qualification_run(), "conclusion": "cancelled"},
                "qualification was cancelled",
            ),
            (
                {**continuity_resolution_qualification_run(), "head_sha": "8" * 40},
                "another source revision",
            ),
            (
                {
                    **continuity_resolution_qualification_run(),
                    "path": ".github/workflows/untrusted.yml@main",
                },
                "untrusted workflow",
            ),
        )
        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", side_effect=read_record),
            mock.patch("scripts.release_plan.load_public_supersession", return_value=None),
        ):
            for run, message in invalid_qualifications:
                with self.subTest(qualification=message), self.assertRaisesRegex(
                    CandidateError,
                    message,
                ):
                    require_prior_plans_completed(
                        future,
                        FixtureClient([resolution_tag], run),
                    )

    def test_accepted_but_incomplete_continuity_successor_does_not_terminalize_the_interruption(self) -> None:
        interrupted = release_plan()
        interrupted["plan"] = "plan-a"
        successor = release_plan()
        successor["plan"] = "plan-b"
        future = release_plan("beta")
        future["plan"] = "plan-c"
        prior_commit = "a" * 40
        successor_commit = "b" * 40
        records = continuity_supersession_records(interrupted, successor, prior_commit)

        class FixtureClient:
            def json(self, url: str) -> list[dict[str, str]]:
                if url.endswith("matching-refs/tags/release-plan/"):
                    return [
                        {"ref": "refs/tags/release-plan/plan-a"},
                        {"ref": "refs/tags/release-plan/plan-b"},
                    ]
                raise AssertionError(f"unexpected registry request {url}")

        def resolve(_client: object, _repository: str, tag: str) -> str | None:
            return {
                "release-plan/plan-a": prior_commit,
                "release-plan/plan-b": successor_commit,
                records["accepted_tag"]: records["accepted_commit"],
                records["interruption_tag"]: records["interruption_commit"],
            }.get(tag)

        def read_record(_client: object, tag: str, _commit: str, filename: str) -> dict[str, object]:
            if tag == "release-plan/plan-a":
                return interrupted
            if tag == "release-plan/plan-b":
                return successor
            if tag == records["accepted_tag"]:
                return records["accepted_evidence"] if filename == "continuity-evidence.json" else successor
            if tag == records["interruption_tag"]:
                return records["interruption_evidence"] if filename == "continuity-evidence.json" else interrupted
            raise AssertionError(f"unexpected public record {tag}:{filename}")

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", side_effect=read_record),
            mock.patch("scripts.release_plan.load_public_supersession", return_value=None),
            self.assertRaisesRegex(CandidateError, "successor release-plan/plan-b has no immutable completion"),
        ):
            require_prior_plans_completed(future, FixtureClient())

    def test_identity_mismatched_continuity_successor_does_not_terminalize_the_interruption(self) -> None:
        interrupted = release_plan()
        interrupted["plan"] = "plan-a"
        successor = release_plan()
        successor["plan"] = "plan-b"
        future = release_plan("beta")
        future["plan"] = "plan-c"
        prior_commit = "a" * 40
        records = continuity_supersession_records(interrupted, successor, prior_commit)
        records["accepted_evidence"]["superseded_interruption"]["commit"] = "f" * 40

        class FixtureClient:
            def json(self, url: str) -> list[dict[str, str]]:
                if url.endswith("matching-refs/tags/release-plan/"):
                    return [
                        {"ref": "refs/tags/release-plan/plan-a"},
                        {"ref": "refs/tags/release-plan/plan-b"},
                    ]
                raise AssertionError(f"unexpected registry request {url}")

        def resolve(_client: object, _repository: str, tag: str) -> str | None:
            return {
                "release-plan/plan-a": prior_commit,
                records["accepted_tag"]: records["accepted_commit"],
                records["interruption_tag"]: records["interruption_commit"],
            }.get(tag)

        def read_record(_client: object, tag: str, _commit: str, filename: str) -> dict[str, object]:
            if tag == "release-plan/plan-a":
                return interrupted
            if tag == records["accepted_tag"]:
                return records["accepted_evidence"] if filename == "continuity-evidence.json" else successor
            raise AssertionError(f"unexpected public record {tag}:{filename}")

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", side_effect=read_record),
            mock.patch("scripts.release_plan.load_public_supersession", return_value=None),
            self.assertRaisesRegex(CandidateError, "superseded interruption .* resolves to"),
        ):
            require_prior_plans_completed(future, FixtureClient())

    def test_one_continuity_acceptance_cannot_clear_an_unrelated_incomplete_plan(self) -> None:
        prior = release_plan()
        prior["plan"] = "plan-a"
        unrelated = release_plan()
        unrelated["plan"] = "plan-x"
        requested = release_plan()
        requested["plan"] = "plan-b"
        prior_commit = "a" * 40
        unrelated_commit = "b" * 40
        records = continuity_supersession_records(prior, requested, prior_commit)

        class FixtureClient:
            def json(self, _url: str) -> list[dict[str, str]]:
                return [
                    {"ref": "refs/tags/release-plan/plan-a"},
                    {"ref": "refs/tags/release-plan/plan-x"},
                ]

        def resolve(_client: object, _repository: str, tag: str) -> str | None:
            return {
                "release-plan/plan-a": prior_commit,
                "release-plan/plan-x": unrelated_commit,
                "release-candidate/alpha/plan-a": None,
                "release-candidate/alpha/plan-x": None,
                records["accepted_tag"]: records["accepted_commit"],
                records["interruption_tag"]: records["interruption_commit"],
            }.get(tag)

        def read_record(_client: object, tag: str, _commit: str, filename: str) -> dict[str, object]:
            if tag == "release-plan/plan-a":
                return prior
            if tag == "release-plan/plan-x":
                return unrelated
            if tag == records["accepted_tag"]:
                return records["accepted_evidence"] if filename == "continuity-evidence.json" else requested
            if tag == records["interruption_tag"]:
                return records["interruption_evidence"] if filename == "continuity-evidence.json" else prior
            raise AssertionError(f"unexpected public record {tag}:{filename}")

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", side_effect=read_record),
            mock.patch("scripts.release_plan.load_public_supersession", return_value=None),
            self.assertRaisesRegex(CandidateError, "invalid superseded interruption identity"),
        ):
            require_prior_plans_completed(requested, FixtureClient())

    def test_continuity_supersession_rejects_forged_or_stale_evidence(self) -> None:
        prior = release_plan()
        prior["plan"] = "plan-a"
        requested = release_plan()
        requested["plan"] = "plan-b"
        prior_commit = "a" * 40

        def accepted_plan_mismatch(records: dict[str, object]) -> None:
            records["accepted_plan"]["components"]["server"]["commit"] = "e" * 40

        def accepted_outcome_mismatch(records: dict[str, object]) -> None:
            records["accepted_evidence"]["outcome"] = "waiting"

        def missing_identity(records: dict[str, object]) -> None:
            records["accepted_evidence"].pop("superseded_interruption")

        def forged_interruption_tag(records: dict[str, object]) -> None:
            records["accepted_evidence"]["superseded_interruption"]["tag"] = "beta-continuity/unrelated/interrupted"

        def mismatched_interruption_commit(records: dict[str, object]) -> None:
            records["accepted_evidence"]["superseded_interruption"]["commit"] = "e" * 40

        def mismatched_evidence_digest(records: dict[str, object]) -> None:
            records["accepted_evidence"]["superseded_interruption"]["evidence_sha256"] = "e" * 64

        def stale_plan_record(records: dict[str, object]) -> None:
            records["interruption_evidence"]["plan_record"]["commit"] = "e" * 40
            records["accepted_evidence"]["superseded_interruption"]["evidence_sha256"] = manifest_digest(
                records["interruption_evidence"]
            )

        def interruption_outcome_mismatch(records: dict[str, object]) -> None:
            records["interruption_evidence"]["outcome"] = "complete"
            records["accepted_evidence"]["superseded_interruption"]["evidence_sha256"] = manifest_digest(
                records["interruption_evidence"]
            )

        cases = (
            ("accepted plan mismatch", accepted_plan_mismatch, "does not prove exact requested plan"),
            ("accepted outcome mismatch", accepted_outcome_mismatch, "does not prove exact requested plan"),
            ("missing supersession identity", missing_identity, "invalid superseded interruption identity"),
            ("forged interruption tag", forged_interruption_tag, "invalid superseded interruption identity"),
            ("mismatched interruption commit", mismatched_interruption_commit, "resolves to"),
            ("mismatched evidence digest", mismatched_evidence_digest, "does not prove prior plan"),
            ("stale plan record", stale_plan_record, "does not prove prior plan"),
            ("interruption outcome mismatch", interruption_outcome_mismatch, "does not prove prior plan"),
        )
        for name, mutate, message in cases:
            with self.subTest(name=name):
                records = continuity_supersession_records(prior, requested, prior_commit)
                mutate(records)

                def resolve(
                    _client: object,
                    _repository: str,
                    tag: str,
                    current_records: dict[str, object] = records,
                ) -> str | None:
                    return {
                        current_records["accepted_tag"]: current_records["accepted_commit"],
                        current_records["interruption_tag"]: current_records["interruption_commit"],
                    }.get(tag)

                def read_record(
                    _client: object,
                    tag: str,
                    _commit: str,
                    filename: str,
                    current_records: dict[str, object] = records,
                ) -> dict[str, object]:
                    if tag == current_records["accepted_tag"]:
                        return (
                            current_records["accepted_evidence"]
                            if filename == "continuity-evidence.json"
                            else current_records["accepted_plan"]
                        )
                    if tag == current_records["interruption_tag"]:
                        return (
                            current_records["interruption_evidence"]
                            if filename == "continuity-evidence.json"
                            else current_records["interruption_plan"]
                        )
                    raise AssertionError(f"unexpected public record {tag}:{filename}")

                with (
                    mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
                    mock.patch("scripts.release_plan.read_public_record", side_effect=read_record),
                    self.assertRaisesRegex(CandidateError, message),
                ):
                    load_continuity_supersession(requested, prior, prior_commit, object())

    def test_continuity_supersession_rejects_a_moved_accepted_tag(self) -> None:
        prior = release_plan()
        prior["plan"] = "plan-a"
        requested = release_plan()
        requested["plan"] = "plan-b"

        with (
            mock.patch("scripts.release_plan.resolve_tag", return_value="c" * 40),
            mock.patch(
                "scripts.release_plan.read_public_record",
                side_effect=CandidateError("public record beta-continuity/plan-b/accepted resolves to a moved commit"),
            ),
            self.assertRaisesRegex(CandidateError, "moved commit"),
        ):
            load_continuity_supersession(requested, prior, "a" * 40, object())

    def test_new_plan_checks_all_matching_refs_when_registry_exceeds_one_hundred(self) -> None:
        requested = release_plan()
        requested["plan"] = "plan-b"
        requested_urls: list[str] = []

        class FixtureClient:
            def json(self, url: str) -> list[dict[str, str]]:
                requested_urls.append(url)
                return [
                    *[{"ref": f"refs/tags/release-plan/completed-{index:03d}"} for index in range(125)],
                    {"ref": "refs/tags/release-plan/plan-a"},
                ]

        def plan_for_tag(tag: str) -> dict[str, object]:
            prior = release_plan()
            prior["plan"] = tag.removeprefix("release-plan/")
            return prior

        def resolve(_client: object, _repository: str, tag: str) -> str | None:
            if tag.startswith("beta-continuity/"):
                return None
            if tag == "release-candidate/alpha/plan-a":
                return None
            return "b" * 40 if tag.startswith("release-candidate/") else "a" * 40

        def read_record(_client: object, tag: str, commit: str, filename: str) -> dict[str, object]:
            if tag.startswith("release-plan/"):
                plan = plan_for_tag(tag)
                return release_preparation(plan) if filename == "release-preparation.json" else plan
            plan_tag = tag.removeprefix("release-candidate/alpha/")
            plan = plan_for_tag(f"release-plan/{plan_tag}")
            return completion_manifest(plan, "a" * 40, release_preparation(plan))

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", side_effect=read_record),
            mock.patch("scripts.release_plan.load_public_supersession", return_value=None),
            mock.patch("scripts.release_plan.load_continuity_supersession", return_value=None),
            self.assertRaisesRegex(CandidateError, "prior plan release-plan/plan-a is incomplete"),
        ):
            require_prior_plans_completed(requested, FixtureClient())

        self.assertEqual(
            ["https://api.github.com/repos/durable-workflow/.github/git/matching-refs/tags/release-plan/"],
            requested_urls,
        )

    def test_completed_prior_plan_allows_the_next_plan(self) -> None:
        prior = release_plan()
        prior["plan"] = "plan-a"
        requested = release_plan()
        requested["plan"] = "plan-b"
        record_commit = "a" * 40
        completed_commit = "b" * 40
        preparation = release_preparation(prior)
        completion = completion_manifest(prior, record_commit, preparation)

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
                side_effect=[prior, completion, preparation],
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

        with (
            mock.patch(
                "scripts.release_plan.resolve_tag",
                side_effect=[record_commit, None, "b" * 40, None],
            ),
            mock.patch(
                "scripts.release_plan.read_public_record",
                side_effect=[failed, failure, successor],
            ),
            mock.patch(
                "scripts.release_plan.protected_environment_evidence",
                return_value=environment_protection_authority(),
            ),
            mock.patch(
                "scripts.release_plan.protected_run_approval_evidence",
                return_value=environment_approval_evidence(),
            ),
        ):
            evidence = require_prior_plans_completed(successor, FixtureClient())
        self.assertEqual("terminal-failure", evidence["release-plan/plan-a"]["outcome"])

        different = copy.deepcopy(successor)
        different["components"]["server"]["commit"] = "d" * 40
        with (
            mock.patch(
                "scripts.release_plan.resolve_tag",
                side_effect=[record_commit, None, "b" * 40, None],
            ),
            mock.patch(
                "scripts.release_plan.read_public_record",
                side_effect=[failed, failure, successor],
            ),
            mock.patch(
                "scripts.release_plan.protected_environment_evidence",
                return_value=environment_protection_authority(),
            ),
            mock.patch(
                "scripts.release_plan.protected_run_approval_evidence",
                return_value=environment_approval_evidence(),
            ),
            self.assertRaisesRegex(CandidateError, "admits only exact successor"),
        ):
            require_prior_plans_completed(different, FixtureClient())

        later = copy.deepcopy(successor)
        later["plan"] = "plan-c"
        with (
            mock.patch(
                "scripts.release_plan.resolve_tag",
                side_effect=[record_commit, None, "b" * 40, "c" * 40],
            ),
            mock.patch(
                "scripts.release_plan.read_public_record",
                side_effect=[failed, failure, successor, successor],
            ),
            mock.patch(
                "scripts.release_plan.protected_environment_evidence",
                return_value=environment_protection_authority(),
            ),
            mock.patch(
                "scripts.release_plan.protected_run_approval_evidence",
                return_value=environment_approval_evidence(),
            ),
        ):
            evidence = require_prior_plans_completed(later, FixtureClient())
        self.assertEqual("terminal-failure", evidence["release-plan/plan-a"]["outcome"])

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

    def test_exact_semver_successors_cover_both_conflict_paths(self) -> None:
        long_numeric = "9" * 4301
        cases = (
            ("release", "1.2.3", "1.2.4"),
            ("prerelease", "1.2.3-alpha.9", "1.2.3-alpha.10"),
            ("release-build", "1.2.3+build.1", "1.2.4+build.2"),
            (
                "prerelease-build",
                "1.2.3-alpha.9+build.1",
                "1.2.3-alpha.10+build.2",
            ),
            ("single-numeric-prerelease", "1.2.3-9", "1.2.3-10"),
            (
                "single-numeric-prerelease-build",
                "1.2.3-9+build.1",
                "1.2.3-10+build.2",
            ),
            ("nonnumeric-prerelease", "1.2.3-rc", "1.2.3-rc.1"),
            (
                "nonnumeric-prerelease-build",
                "1.2.3-rc+build.1",
                "1.2.3-rc.1+build.2",
            ),
            (
                "long-core",
                f"1.2.{long_numeric}",
                f"1.2.1{'0' * 4301}",
            ),
            (
                "long-prerelease",
                f"1.2.3-alpha.{long_numeric}",
                f"1.2.3-alpha.1{'0' * 4301}",
            ),
        )

        for reason in (SUPERSESSION_REASON, OCCUPIED_SOURCE_MANIFEST_REASON):
            for label, previous_version, successor_version in cases:
                failed = release_plan("beta")
                failed["plan"] = f"semver-{label}-failed"
                failed["components"]["server"]["version"] = previous_version
                successor = copy.deepcopy(failed)
                successor["plan"] = f"semver-{label}-successor"
                successor["components"]["server"]["version"] = successor_version
                if reason == OCCUPIED_SOURCE_MANIFEST_REASON:
                    successor["components"]["server"]["commit"] = "e" * 40

                with self.subTest(reason=reason, kind=label):
                    validate_successor_transition(
                        failed,
                        successor,
                        [{"component": "server", "reason": reason}],
                    )

            failed = release_plan("beta")
            failed["plan"] = "semver-long-skipped-failed"
            failed["components"]["server"]["version"] = f"1.2.{long_numeric}"
            successor = copy.deepcopy(failed)
            successor["plan"] = "semver-long-skipped-successor"
            successor["components"]["server"]["version"] = f"1.2.2{'0' * 4301}"
            if reason == OCCUPIED_SOURCE_MANIFEST_REASON:
                successor["components"]["server"]["commit"] = "e" * 40

            with (
                self.subTest(reason=reason, kind="invalid"),
                self.assertRaisesRegex(
                    CandidateError,
                    "immediate next version",
                ),
            ):
                validate_successor_transition(
                    failed,
                    successor,
                    [{"component": "server", "reason": reason}],
                )

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

    def test_loading_terminal_record_requires_live_github_authority(self) -> None:
        failed = release_plan()
        successor = successor_plan(failed)
        record = supersession_record(failed, successor)
        with (
            mock.patch("scripts.release_plan.resolve_tag", return_value="b" * 40),
            mock.patch("scripts.release_plan.read_public_record", side_effect=[record, successor]),
            mock.patch(
                "scripts.release_plan.revalidate_conflict_public_evidence",
                side_effect=AssertionError("historical records must not revalidate conflict evidence"),
            ),
            mock.patch(
                "scripts.release_plan.protected_environment_evidence",
                return_value=environment_protection_authority(),
            ),
            mock.patch(
                "scripts.release_plan.protected_run_approval_evidence",
                return_value=environment_approval_evidence(),
            ),
        ):
            loaded = load_public_supersession(failed, "a" * 40, object())
        self.assertEqual(record, loaded[2])
        self.assertEqual(successor, loaded[3])

    def test_terminal_record_rejects_unverifiable_github_authority(self) -> None:
        failed = release_plan()
        successor = successor_plan(failed)
        record = supersession_record(failed, successor)
        with (
            mock.patch("scripts.release_plan.resolve_tag", return_value="b" * 40),
            mock.patch(
                "scripts.release_plan.read_public_record",
                side_effect=[record, successor],
            ),
            mock.patch(
                "scripts.release_plan.protected_environment_evidence",
                side_effect=CandidateError("environment policy unavailable"),
            ),
            self.assertRaisesRegex(CandidateError, "environment policy unavailable"),
        ):
            load_public_supersession(failed, "a" * 40, object())

    def test_terminal_record_rejects_fabricated_authorization_identity(self) -> None:
        failed = release_plan()
        successor = successor_plan(failed)
        record = supersession_record(failed, successor)
        record["authorization"]["workflow_ref"] = (
            "durable-workflow/.github/.github/workflows/release-plan.yml@refs/heads/main"
        )
        with (
            mock.patch("scripts.release_plan.resolve_tag", return_value="b" * 40),
            mock.patch(
                "scripts.release_plan.read_public_record",
                side_effect=[record, successor],
            ),
            self.assertRaisesRegex(CandidateError, "not authorized by the protected supersession workflow"),
        ):
            load_public_supersession(failed, "a" * 40, object())


class ReleasePlanSupersessionTest(unittest.TestCase):
    def prepare_occupied_python_conflict(
        self,
    ) -> tuple[dict[str, object], dict[str, object], dict[str, object], str]:
        failed = release_plan()
        failed["plan"] = "plan-a"
        failed["components"]["sdk-python"] = {
            "version": "0.4.100",
            "commit": "2018400368cf4251c58b24b3d53a99f0ca3512e3",
        }
        successor = copy.deepcopy(failed)
        successor["plan"] = "plan-b"
        successor["components"]["sdk-python"] = {
            "version": "0.4.101",
            "commit": "d" * 40,
        }
        failed_commit = "a" * 40
        source_tag = {
            "repository": "durable-workflow/sdk-python",
            "tag": "0.4.100",
            "tag_object": failed["components"]["sdk-python"]["commit"],
            "commit": failed["components"]["sdk-python"]["commit"],
            "url": "https://github.com/durable-workflow/sdk-python/tree/0.4.100",
        }

        class FixtureClient:
            def bytes(self, url: str, **_kwargs: object) -> bytes:
                if failed["components"]["sdk-python"]["commit"] in url:
                    return python_manifest("0.4.99")
                if successor["components"]["sdk-python"]["commit"] in url:
                    return python_manifest("0.4.101")
                return planned_source_manifest(url, failed)

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
                if url.endswith("/releases/tags/0.4.100") or url.endswith("/pypi/durable-workflow/0.4.100/json"):
                    raise CandidateError(f"public request failed (404) for {url}")
                raise AssertionError(f"unexpected JSON request: {url}")

        def resolve(_client: object, repository: str, tag: str) -> str | None:
            if repository == "durable-workflow/.github" and tag == "release-plan/plan-a":
                return failed_commit
            if repository == "durable-workflow/sdk-python" and tag == "0.4.100":
                return failed["components"]["sdk-python"]["commit"]
            return None

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", return_value=failed),
            mock.patch("scripts.release_plan.resolve_github_tag", return_value=source_tag),
        ):
            record, durable_successor = prepare_supersession(
                "release-plan/plan-a",
                ["sdk-python"],
                successor,
                FixtureClient(),
                actor="release-operator",
                run_id="456",
                run_attempt="1",
                workflow_ref=(
                    "durable-workflow/.github/.github/workflows/release-plan-supersession.yml@refs/heads/main"
                ),
                workflow_commit="f" * 40,
            )
        self.assertEqual(successor, durable_successor)
        return failed, successor, record, failed_commit

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

            return protected_environment_evidence(FixtureClient())[0]

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

        unsupported_reviewer = copy.deepcopy(environment)
        unsupported_reviewer["protection_rules"][0]["reviewers"][0] = {
            "type": "Team",
            "reviewer": {"id": 29},
        }
        with self.assertRaisesRegex(CandidateError, "unverifiable required reviewer"):
            evidence(unsupported_reviewer, policies)

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
                required_reviewers={(29, "release-reviewer")},
                require_success=True,
            )

        self.assertEqual(environment_approval_evidence(), evidence(workflow_run(), approval_history()))

        rejected = approval_history()
        rejected[0]["state"] = "rejected"
        wrong_environment = approval_history()
        wrong_environment[0]["environments"][0]["name"] = "staging"
        wrong_run = workflow_run()
        wrong_run["id"] = 999
        wrong_attempt = workflow_run()
        wrong_attempt["run_attempt"] = 2
        wrong_revision = workflow_run()
        wrong_revision["head_sha"] = "0" * 40
        failed_run = workflow_run()
        failed_run["conclusion"] = "failure"
        malformed = approval_history()
        malformed[0]["environments"] = "release-plan-supersession"
        outside_policy = approval_history()
        outside_policy[0]["user"]["id"] = 999

        failures = (
            ("absent", workflow_run(), [], "exactly one approved review"),
            ("rejected", workflow_run(), rejected, "exactly one approved review"),
            ("wrong environment", workflow_run(), wrong_environment, "wrong protected environment"),
            ("wrong run", wrong_run, approval_history(), "workflow run evidence does not match"),
            ("wrong attempt", wrong_attempt, approval_history(), "workflow run evidence does not match"),
            ("wrong revision", wrong_revision, approval_history(), "workflow run evidence does not match"),
            ("failed run", failed_run, approval_history(), "workflow run evidence does not match"),
            ("malformed", workflow_run(), malformed, "approval history is malformed"),
            (
                "outside reviewer policy",
                workflow_run(),
                outside_policy,
                "not authorized by the current reviewer policy",
            ),
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
            with (
                self.subTest(path=path),
                self.assertRaisesRegex(CandidateError, "workflow run evidence does not match"),
            ):
                evidence(run, approval_history())

    def test_run_scoped_approval_history_cannot_authorize_a_rerun_attempt(self) -> None:
        client = mock.Mock()
        rerun = workflow_run()
        rerun["run_attempt"] = 2
        client.json.side_effect = [rerun]

        with self.assertRaisesRegex(CandidateError, "cannot prove protected approval for a rerun"):
            protected_run_approval_evidence(
                client,
                actor="release-operator",
                run_id=456,
                run_attempt=2,
                workflow_commit="f" * 40,
                environment_protection=environment_protection_evidence(),
                required_reviewers={(29, "release-reviewer")},
                require_success=True,
            )
        self.assertEqual(1, client.json.call_count)

    def test_prepare_proves_real_public_conflict_and_protected_run(self) -> None:
        failed = release_plan()
        failed["plan"] = "plan-a"
        successor = successor_plan(failed)
        successor["plan"] = "plan-b"
        failed_commit = "a" * 40
        observed_commit = "e" * 40

        class FixtureClient:
            def bytes(self, url: str, **_kwargs: object) -> bytes:
                return planned_source_manifest(url, failed)

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
            if repository == "durable-workflow/waterline" and tag == failed["components"]["waterline"]["version"]:
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
                    "durable-workflow/.github/.github/workflows/release-plan-supersession.yml@refs/heads/main"
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
        successor["components"]["sdk-rust"]["commit"] = "2e09d42d8380bd0a2c8145dfeabd9d6294a8e8e1"
        failed_commit = "a" * 40
        observed_commit = "e" * 40

        class FixtureClient:
            def bytes(self, url: str, **_kwargs: object) -> bytes:
                if "/sdk-python/" in url:
                    return planned_source_manifest(url, failed)
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
            if repository == "durable-workflow/waterline" and tag == failed["components"]["waterline"]["version"]:
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
                    "durable-workflow/.github/.github/workflows/release-plan-supersession.yml@refs/heads/main"
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

    def test_prepare_occupied_python_manifest_conflict_admits_exact_successor(self) -> None:
        failed, successor, record, failed_commit = self.prepare_occupied_python_conflict()
        conflict = record["conflicts"][0]

        self.assertEqual(OCCUPIED_SOURCE_MANIFEST_REASON, conflict["reason"])
        self.assertEqual("0.4.99", conflict["source_manifest"]["declared_version"])
        self.assertEqual("absent", conflict["github_release"]["status"])
        self.assertEqual("absent", conflict["distribution"]["status"])
        self.assertEqual("0.4.101", conflict["successor_source_manifest"]["declared_version"])
        for name in COMPONENTS:
            if name != "sdk-python":
                self.assertEqual(failed["components"][name], successor["components"][name])
        validate_supersession_record(record, failed, failed_commit, successor)

        class FixtureClient:
            def json(self, _url: str) -> list[dict[str, str]]:
                return [{"ref": "refs/tags/release-plan/plan-a"}]

        terminal = ("release-plan-failure/plan-a", "b" * 40, record, successor)
        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=[failed_commit, None, None]),
            mock.patch("scripts.release_plan.read_public_record", return_value=failed),
            mock.patch("scripts.release_plan.load_public_supersession", return_value=terminal),
        ):
            evidence = require_prior_plans_completed(successor, FixtureClient())
        self.assertEqual("terminal-failure", evidence["release-plan/plan-a"]["outcome"])

    def test_occupied_python_manifest_conflict_rejects_alternate_successors(self) -> None:
        failed, successor, record, _failed_commit = self.prepare_occupied_python_conflict()

        skipped = copy.deepcopy(successor)
        skipped["components"]["sdk-python"]["version"] = "0.4.102"
        with self.assertRaisesRegex(CandidateError, "immediate next version"):
            validate_successor_transition(failed, skipped, record["conflicts"])

        unchanged_source = copy.deepcopy(successor)
        unchanged_source["components"]["sdk-python"]["commit"] = failed["components"]["sdk-python"]["commit"]
        with self.assertRaisesRegex(CandidateError, "replace sdk-python's incompatible tagged source commit"):
            validate_successor_transition(failed, unchanged_source, record["conflicts"])

        changed_unaffected = copy.deepcopy(successor)
        changed_unaffected["components"]["server"]["commit"] = "9" * 40
        with self.assertRaisesRegex(CandidateError, "unaffected component server"):
            validate_successor_transition(failed, changed_unaffected, record["conflicts"])

    def test_occupied_python_manifest_conflict_rejects_mismatched_successor_manifest(self) -> None:
        failed, successor, record, failed_commit = self.prepare_occupied_python_conflict()
        record["conflicts"][0]["successor_source_manifest"] = python_source_manifest_record(
            successor["components"]["sdk-python"]["commit"], "0.4.100"
        )
        with self.assertRaisesRegex(CandidateError, "does not match sdk-python version allocation"):
            validate_supersession_record(record, failed, failed_commit, successor)

    def test_occupied_python_manifest_conflict_remains_durable_after_source_tag_moves(self) -> None:
        failed, successor, record, failed_commit = self.prepare_occupied_python_conflict()
        with (
            mock.patch("scripts.release_plan.resolve_tag", return_value="b" * 40),
            mock.patch("scripts.release_plan.read_public_record", side_effect=[record, successor]),
            mock.patch(
                "scripts.release_plan.resolve_github_tag",
                side_effect=AssertionError("historical records must not reload source tags"),
            ),
            mock.patch(
                "scripts.release_plan.protected_environment_evidence",
                return_value=environment_protection_authority(),
            ),
            mock.patch(
                "scripts.release_plan.protected_run_approval_evidence",
                return_value=environment_approval_evidence(),
            ),
        ):
            loaded = load_public_supersession(failed, failed_commit, object())
        self.assertEqual(record, loaded[2])
        self.assertEqual(successor, loaded[3])

    def test_prepare_rejects_omitted_python_manifest_conflict(self) -> None:
        failed = release_plan()
        failed["plan"] = "plan-a"
        failed["components"]["sdk-python"] = {
            "version": "0.4.100",
            "commit": "2018400368cf4251c58b24b3d53a99f0ca3512e3",
        }
        successor = successor_plan(failed)

        class FixtureClient:
            def bytes(self, url: str, **_kwargs: object) -> bytes:
                if "/sdk-python/" in url:
                    return python_manifest("0.4.99")
                return planned_source_manifest(url, failed)

        def resolve(_client: object, repository: str, tag: str) -> str | None:
            if repository == "durable-workflow/.github" and tag == "release-plan/plan-a":
                return "a" * 40
            if repository == "durable-workflow/sdk-python" and tag == "0.4.100":
                return failed["components"]["sdk-python"]["commit"]
            return None

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", return_value=failed),
            self.assertRaisesRegex(CandidateError, "omit independently proven.*sdk-python"),
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
                    "durable-workflow/.github/.github/workflows/release-plan-supersession.yml@refs/heads/main"
                ),
                workflow_commit="f" * 40,
            )

    def test_prepare_rejects_omitted_source_manifest_conflict(self) -> None:
        failed = release_plan()
        failed["plan"] = "plan-a"
        failed["components"]["sdk-rust"] = {
            "version": "0.1.16",
            "commit": "dde751dc45366beaf8a829ed42c7ab92d0aad775",
        }
        successor = successor_plan(failed)

        class FixtureClient:
            def bytes(self, url: str, **_kwargs: object) -> bytes:
                if "/sdk-python/" in url:
                    return planned_source_manifest(url, failed)
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
                    "durable-workflow/.github/.github/workflows/release-plan-supersession.yml@refs/heads/main"
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
        successor["components"]["sdk-rust"]["commit"] = "2e09d42d8380bd0a2c8145dfeabd9d6294a8e8e1"
        failed_commit = "a" * 40
        observed_waterline_commit = "e" * 40

        class FixtureClient:
            def bytes(self, url: str, **_kwargs: object) -> bytes:
                if "/sdk-python/" in url:
                    return planned_source_manifest(url, failed)
                return cargo_manifest("0.1.15")

        def resolve(_client: object, repository: str, tag: str) -> str | None:
            if repository == "durable-workflow/.github" and tag == "release-plan/plan-a":
                return failed_commit
            if repository == "durable-workflow/waterline" and tag == failed["components"]["waterline"]["version"]:
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
                    "durable-workflow/.github/.github/workflows/release-plan-supersession.yml@refs/heads/main"
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
        self.preparation_path = root / "release-preparation.json"
        self.authoritative_path = root / "authoritative-release-plan.json"
        self.authoritative_authorization_path = root / "authoritative-beta-authorization.json"
        self.authoritative_preparation_path = root / "authoritative-release-preparation.json"
        self.failure_path = root / "release-plan-failure.json"
        self.successor_path = root / "successor-release-plan.json"
        self.authoritative_failure_path = root / "authoritative-release-plan-failure.json"
        self.authoritative_successor_path = root / "authoritative-successor-release-plan.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_plan(self, plan: dict[str, object]) -> None:
        self.plan_path.write_bytes(canonical_json(plan))
        self.preparation_path.write_bytes(canonical_json(release_preparation(plan)))

    def test_first_record_and_identical_recovery_keep_one_commit(self) -> None:
        plan = release_plan()
        self.write_plan(plan)
        first_preparation = release_preparation(plan)
        created = record_plan(
            self.repository,
            self.plan_path,
            self.preparation_path,
            remote=str(self.remote),
            authoritative_plan=self.authoritative_path,
            authoritative_preparation=self.authoritative_preparation_path,
        )
        self.preparation_path.write_bytes(canonical_json(release_preparation(plan, "2026-07-20")))
        repeated = record_plan(
            self.repository,
            self.plan_path,
            self.preparation_path,
            remote=str(self.remote),
            authoritative_plan=self.authoritative_path,
            authoritative_preparation=self.authoritative_preparation_path,
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
        self.assertEqual(["release-plan.json", "release-preparation.json"], files)
        self.assertEqual(canonical_json(plan), self.authoritative_path.read_bytes())
        self.assertEqual(
            canonical_json(first_preparation),
            self.authoritative_preparation_path.read_bytes(),
        )

    def test_current_completed_train_authorization_is_deterministic_and_idempotent(self) -> None:
        current_plan = REPOSITORY_ROOT / "release-plans" / "current.json"
        created = record_current_plan_authorization(
            self.repository,
            current_plan,
            remote=str(self.remote),
            authoritative_authorization=self.authoritative_authorization_path,
        )
        repeated = record_current_plan_authorization(
            self.repository,
            current_plan,
            remote=str(self.remote),
            authoritative_authorization=self.authoritative_authorization_path,
        )

        self.assertEqual("created", created["status"])
        self.assertEqual("existing", repeated["status"])
        self.assertEqual("b024309e2fef13f0b2ed063f194ea4c4f3c126e7", created["commit"])
        self.assertEqual(created["commit"], repeated["commit"])
        files = subprocess.run(
            ["git", "--git-dir", str(self.remote), "ls-tree", "-r", "--name-only", created["commit"]],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.splitlines()
        self.assertEqual(["beta-authorization.json"], files)

    def test_existing_plan_rejects_tuple_mutation(self) -> None:
        plan = release_plan()
        self.write_plan(plan)
        record_plan(
            self.repository,
            self.plan_path,
            self.preparation_path,
            remote=str(self.remote),
            authoritative_plan=self.authoritative_path,
            authoritative_preparation=self.authoritative_preparation_path,
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

        def resolve(_client: object, repository: str, tag: str) -> str | None:
            if repository == "durable-workflow/.github" and tag == record["failed_plan"]["tag"]:
                return "a" * 40
            if repository == "durable-workflow/waterline" and tag == failed["components"]["waterline"]["version"]:
                return "e" * 40
            return None

        client = mock.Mock()
        client.json.return_value = {
            "draft": False,
            "html_url": record["conflicts"][0]["github_release"]["url"],
            "id": record["conflicts"][0]["github_release"]["id"],
            "tag_name": failed["components"]["waterline"]["version"],
        }
        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", return_value=failed),
            mock.patch.dict(
                "scripts.release_plan.VERIFIERS",
                {"composer": mock.Mock(return_value=record["conflicts"][0]["distribution"])},
            ),
            mock.patch(
                "scripts.release_plan.protected_environment_evidence",
                return_value=environment_protection_authority(),
            ) as protection,
            mock.patch(
                "scripts.release_plan.protected_run_approval_evidence",
                return_value=environment_approval_evidence(),
            ) as approval,
        ):
            created = record_supersession(
                self.repository,
                self.failure_path,
                self.successor_path,
                remote=str(self.remote),
                authoritative_record=self.authoritative_failure_path,
                authoritative_successor=self.authoritative_successor_path,
                client=client,
            )
            protection.side_effect = CandidateError("environment policy changed after publication")
            approval.side_effect = CandidateError("approval history unavailable after publication")
            repeated = record_supersession(
                self.repository,
                self.failure_path,
                self.successor_path,
                remote=str(self.remote),
                authoritative_record=self.authoritative_failure_path,
                authoritative_successor=self.authoritative_successor_path,
                client=client,
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

    def test_terminal_record_rechecks_mutable_evidence_before_publication(self) -> None:
        failed = release_plan()
        successor = successor_plan(failed)
        record = supersession_record(failed, successor)
        self.failure_path.write_bytes(canonical_json(record))
        self.successor_path.write_bytes(canonical_json(successor))
        failed_version = failed["components"]["waterline"]["version"]
        successor_version = successor["components"]["waterline"]["version"]

        errors = {
            "conflict": "terminal conflict source tag .* moved",
            "release": "GitHub Release evidence .* no longer matches GitHub",
            "release-absent": "GitHub Release evidence .* no longer matches GitHub",
            "distribution": "distribution evidence .* no longer matches its registry",
            "successor": "successor version .* already points to",
            "policy": "protected environment policy no longer matches",
            "approval": "approval history unavailable",
        }
        for drift, error in errors.items():
            with self.subTest(drift=drift):

                def resolve(
                    _client: object,
                    repository: str,
                    tag: str,
                    drift: str = drift,
                ) -> str | None:
                    if repository == "durable-workflow/.github" and tag == record["failed_plan"]["tag"]:
                        return "a" * 40
                    if repository == "durable-workflow/waterline" and tag == failed_version:
                        return "d" * 40 if drift == "conflict" else "e" * 40
                    if repository == "durable-workflow/waterline" and tag == successor_version:
                        return "d" * 40 if drift == "successor" else None
                    return None

                protection = environment_protection_evidence()
                if drift == "policy":
                    protection["custom_branch_policies"] = [{"id": 24, "name": "main"}]

                def approval(
                    _client: object,
                    drift: str = drift,
                    **_kwargs: object,
                ) -> dict[str, object]:
                    if drift == "approval":
                        raise CandidateError("approval history unavailable")
                    return environment_approval_evidence()

                client = mock.Mock()
                if drift == "release-absent":
                    client.json.side_effect = CandidateError("GitHub Release was removed")
                else:
                    client.json.return_value = {
                        "draft": False,
                        "html_url": record["conflicts"][0]["github_release"]["url"],
                        "id": (124 if drift == "release" else record["conflicts"][0]["github_release"]["id"]),
                        "tag_name": failed_version,
                    }
                live_distribution = copy.deepcopy(record["conflicts"][0]["distribution"])
                if drift == "distribution":
                    live_distribution["dist"] = {
                        "sha256": "f" * 64,
                        "url": "https://example.com/repacked.zip",
                    }

                with (
                    mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
                    mock.patch("scripts.release_plan.read_public_record", return_value=failed),
                    mock.patch.dict(
                        "scripts.release_plan.VERIFIERS",
                        {"composer": mock.Mock(return_value=live_distribution)},
                    ),
                    mock.patch(
                        "scripts.release_plan.protected_environment_evidence",
                        return_value=(protection, {(29, "release-reviewer")}),
                    ),
                    mock.patch(
                        "scripts.release_plan.protected_run_approval_evidence",
                        side_effect=approval,
                    ),
                    self.assertRaisesRegex(CandidateError, error),
                ):
                    record_supersession(
                        self.repository,
                        self.failure_path,
                        self.successor_path,
                        remote=str(self.remote),
                        authoritative_record=self.authoritative_failure_path,
                        authoritative_successor=self.authoritative_successor_path,
                        client=client,
                    )

                published = subprocess.run(
                    [
                        "git",
                        "--git-dir",
                        str(self.remote),
                        "for-each-ref",
                        "--format=%(refname)",
                        "refs/tags/release-plan-failure/recovery-proof-1",
                    ],
                    check=True,
                    capture_output=True,
                )
                self.assertEqual(b"", published.stdout)

    def test_terminal_record_rejects_manifest_tag_appearing_after_prepare(self) -> None:
        failed = release_plan()
        failed["components"]["sdk-rust"] = {
            "version": "0.1.16",
            "commit": "dde751dc45366beaf8a829ed42c7ab92d0aad775",
        }
        successor = successor_plan(failed, component="sdk-rust")
        failed_identity = failed["components"]["sdk-rust"]
        successor_identity = successor["components"]["sdk-rust"]
        source_tag_commit = None

        class FixtureClient:
            def bytes(self, url: str, **_kwargs: object) -> bytes:
                if "/sdk-python/" in url:
                    return planned_source_manifest(url, failed)
                if failed_identity["commit"] in url:
                    return cargo_manifest("0.1.15")
                if successor_identity["commit"] in url:
                    return cargo_manifest(successor_identity["version"])
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
                raise AssertionError(f"unexpected public evidence request: {url}")

        client = FixtureClient()

        def resolve(_client: object, repository: str, tag: str) -> str | None:
            if repository == "durable-workflow/.github" and tag == f"{PLAN_TAG_PREFIX}{failed['plan']}":
                return "a" * 40
            if repository == "durable-workflow/sdk-rust" and tag == failed_identity["version"]:
                return source_tag_commit
            return None

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", return_value=failed),
        ):
            record, durable_successor = prepare_supersession(
                f"{PLAN_TAG_PREFIX}{failed['plan']}",
                ["sdk-rust"],
                successor,
                client,
                actor="release-operator",
                run_id="456",
                run_attempt="1",
                workflow_ref=(
                    "durable-workflow/.github/.github/workflows/release-plan-supersession.yml@refs/heads/main"
                ),
                workflow_commit="f" * 40,
            )
            self.assertEqual(SOURCE_MANIFEST_REASON, record["conflicts"][0]["reason"])
            self.failure_path.write_bytes(canonical_json(record))
            self.successor_path.write_bytes(canonical_json(durable_successor))

            for appeared_commit in (failed_identity["commit"], successor_identity["commit"]):
                with self.subTest(appeared_commit=appeared_commit):
                    source_tag_commit = appeared_commit
                    with self.assertRaisesRegex(
                        CandidateError,
                        "terminal conflict source tag .* appeared",
                    ):
                        record_supersession(
                            self.repository,
                            self.failure_path,
                            self.successor_path,
                            remote=str(self.remote),
                            authoritative_record=self.authoritative_failure_path,
                            authoritative_successor=self.authoritative_successor_path,
                            client=client,
                        )

                    published = subprocess.run(
                        [
                            "git",
                            "--git-dir",
                            str(self.remote),
                            "for-each-ref",
                            "--format=%(refname)",
                            "refs/tags/release-plan-failure/recovery-proof-1",
                        ],
                        check=True,
                        capture_output=True,
                    )
                    self.assertEqual(b"", published.stdout)

    def test_terminal_record_revalidates_occupied_manifest_publication_evidence(self) -> None:
        failed = release_plan()
        failed["components"]["sdk-python"] = {
            "version": "0.4.100",
            "commit": "2018400368cf4251c58b24b3d53a99f0ca3512e3",
        }
        successor = copy.deepcopy(failed)
        successor["plan"] = "recovery-proof-2"
        successor["components"]["sdk-python"] = {
            "version": "0.4.101",
            "commit": "d" * 40,
        }
        record = supersession_record(failed, successor, component="sdk-python")
        failed_identity = failed["components"]["sdk-python"]
        successor_identity = successor["components"]["sdk-python"]
        release_api = "https://api.github.com/repos/durable-workflow/sdk-python/releases/tags/0.4.100"
        distribution_api = "https://pypi.org/pypi/durable-workflow/0.4.100/json"
        record["conflicts"][0] = {
            "component": "sdk-python",
            "version": failed_identity["version"],
            "planned_commit": failed_identity["commit"],
            "reason": OCCUPIED_SOURCE_MANIFEST_REASON,
            "source_manifest": python_source_manifest_record(
                failed_identity["commit"],
                "0.4.99",
            ),
            "source_tag": {
                "commit": failed_identity["commit"],
                "repository": "durable-workflow/sdk-python",
                "tag": failed_identity["version"],
                "tag_object": failed_identity["commit"],
                "url": "https://github.com/durable-workflow/sdk-python/tree/0.4.100",
            },
            "github_release": {
                "api_url": release_api,
                "status": "absent",
                "url": "https://github.com/durable-workflow/sdk-python/releases/tag/0.4.100",
            },
            "distribution": {
                "api_url": distribution_api,
                "kind": "pypi",
                "status": "absent",
                "url": "https://pypi.org/project/durable-workflow/0.4.100/",
            },
            "successor_source_manifest": python_source_manifest_record(
                successor_identity["commit"],
                successor_identity["version"],
            ),
        }
        self.failure_path.write_bytes(canonical_json(record))
        self.successor_path.write_bytes(canonical_json(successor))

        def resolve(_client: object, repository: str, tag: str) -> str | None:
            if repository == "durable-workflow/.github" and tag == record["failed_plan"]["tag"]:
                return "a" * 40
            return None

        def source_manifest(url: str, **_kwargs: object) -> bytes:
            if failed_identity["commit"] in url:
                return python_manifest("0.4.99")
            if successor_identity["commit"] in url:
                return python_manifest(successor_identity["version"])
            raise AssertionError(f"unexpected source manifest request: {url}")

        for appeared_surface, error in (
            ("source-tag", "source tag .* moved"),
            ("github-release", "already has a GitHub Release"),
            ("distribution", "already has a public distribution"),
        ):
            with self.subTest(appeared_surface=appeared_surface):
                client = mock.Mock()
                client.bytes.side_effect = source_manifest

                def json(url: str, surface: str = appeared_surface) -> object:
                    if url == release_api and surface == "github-release":
                        return {"id": 123}
                    if url == distribution_api and surface == "distribution":
                        return {"info": {"version": failed_identity["version"]}}
                    raise CandidateError(f"public request failed (404) for {url}")

                client.json.side_effect = json
                live_source_tag = copy.deepcopy(record["conflicts"][0]["source_tag"])
                if appeared_surface == "source-tag":
                    live_source_tag["commit"] = "e" * 40
                with (
                    mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
                    mock.patch("scripts.release_plan.read_public_record", return_value=failed),
                    mock.patch(
                        "scripts.release_plan.resolve_github_tag",
                        return_value=live_source_tag,
                    ),
                    self.assertRaisesRegex(CandidateError, error),
                ):
                    record_supersession(
                        self.repository,
                        self.failure_path,
                        self.successor_path,
                        remote=str(self.remote),
                        authoritative_record=self.authoritative_failure_path,
                        authoritative_successor=self.authoritative_successor_path,
                        client=client,
                    )

                published = subprocess.run(
                    [
                        "git",
                        "--git-dir",
                        str(self.remote),
                        "for-each-ref",
                        "--format=%(refname)",
                        "refs/tags/release-plan-failure/recovery-proof-1",
                    ],
                    check=True,
                    capture_output=True,
                )
                self.assertEqual(b"", published.stdout)


if __name__ == "__main__":
    unittest.main()
