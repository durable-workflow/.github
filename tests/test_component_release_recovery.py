from __future__ import annotations

import datetime as dt
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

from scripts.component_release_recovery import (
    CLI_ASSETS,
    COMPONENTS,
    FOUNDATION_COMMIT,
    FOUNDATION_TAG,
    PREPARATION_SCHEMA,
    SCHEMA,
    SUPERSESSION_API_VERSION,
    NotFound,
    PublicClient,
    PublicInfrastructureError,
    RecoveryError,
    canonical_json,
    direct_plan_lifecycle,
    discover_plan,
    list_release_plan_tags,
    main,
    manifest_digest,
    resolve_component,
    revalidate_supersession_authority,
    scheduled_continuity_pause,
    select_implicit_plan_authority,
    select_publication_run,
    validate_plan,
    validate_release_preparation,
    verify_cli,
    verify_composer,
    verify_recovery_workflow_source,
)
from scripts.recovery_workflow_authority import normalized_source_sha256


def github_http_error(status: int, body: bytes = b"error", **headers: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://api.github.com/repos/durable-workflow/.github/releases",
        status,
        "request failed",
        headers,
        io.BytesIO(body),
    )


def plan(channel: str = "alpha") -> dict[str, object]:
    prerelease = "alpha" if channel == "alpha" else "beta"
    return {
        "schema": SCHEMA,
        "plan": "component-recovery",
        "channel": channel,
        "foundation": {"tag": FOUNDATION_TAG, "commit": FOUNDATION_COMMIT},
        "components": {
            name: {
                "version": f"2.0.0-{prerelease}.{index + 1}" if name in {"workflow", "waterline"} else f"1.0.{index}",
                "commit": f"{index + 1:040x}",
            }
            for index, name in enumerate(COMPONENTS)
        },
        "beta_authorization": (
            {"tag": "beta-authorization/component-recovery", "commit": "f" * 40} if channel == "beta" else None
        ),
    }


def preparation(candidate: dict[str, object]) -> dict[str, object]:
    release_date = "2026-07-19"
    components: dict[str, object] = {}
    for name, identity in candidate["components"].items():
        heading = f"## [{identity['version']}] - {release_date}"
        markdown = f"{heading}\n\nPrepared source changes.\n"
        repository = COMPONENTS[name].repository
        changelog = name in {"workflow", "waterline", "sdk-php", "sdk-python"}
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
                    "kind": "changelog-unreleased" if changelog else "source-commit-message",
                    "sha256": "a" * 64,
                    "url": (
                        f"https://github.com/{repository}/blob/{identity['commit']}/CHANGELOG.md"
                        if changelog
                        else f"https://github.com/{repository}/commit/{identity['commit']}"
                    ),
                },
            },
        }
    return {
        "schema": PREPARATION_SCHEMA,
        "release_plan": {
            "tag": f"release-plan/{candidate['plan']}",
            "sha256": manifest_digest(candidate),
        },
        "components": components,
    }


def supersession_record(
    failed: dict[str, object],
    successor: dict[str, object],
    failed_commit: str,
) -> dict[str, object]:
    identity = failed["components"]["workflow"]
    observed_commit = "e" * 40
    environment_url = (
        "https://github.com/durable-workflow/.github/deployments/activity_log?"
        "environments_filter=release-plan-supersession"
    )
    protection = {
        "custom_branch_policies": [{"id": 22, "name": "main"}],
        "deployment_branch_policy": {
            "custom_branch_policies": True,
            "protected_branches": False,
        },
        "environment_id": 11,
        "environment_url": environment_url,
        "required_reviewer_rule_ids": [33],
    }
    return {
        "schema": "durable-workflow.release-plan-failure/v1",
        "outcome": "terminal-failure",
        "failed_plan": {
            "tag": f"release-plan/{failed['plan']}",
            "commit": failed_commit,
            "sha256": manifest_digest(failed),
        },
        "conflicts": [
            {
                "component": "workflow",
                "version": identity["version"],
                "planned_commit": identity["commit"],
                "observed_commit": observed_commit,
                "reason": "published-version-source-conflict",
                "github_release": {
                    "id": 44,
                    "url": "https://github.com/durable-workflow/workflow/releases/44",
                },
                "distribution": {
                    "kind": "composer",
                    "source_reference": observed_commit,
                    "dist_reference": observed_commit,
                },
            }
        ],
        "successor_plan": {
            "tag": f"release-plan/{successor['plan']}",
            "sha256": manifest_digest(successor),
        },
        "authorization": {
            "actor": "release-operator",
            "environment": "release-plan-supersession",
            "environment_approval": {
                "comment": "approved",
                "environments": [
                    {
                        "html_url": environment_url,
                        "id": 11,
                        "name": "release-plan-supersession",
                        "node_id": "environment-node",
                        "url": (
                            "https://api.github.com/repos/durable-workflow/.github/"
                            "environments/release-plan-supersession"
                        ),
                    }
                ],
                "run_attempt": 1,
                "run_id": 456,
                "state": "approved",
                "user": {
                    "html_url": "https://github.com/release-reviewer",
                    "id": 55,
                    "login": "release-reviewer",
                    "node_id": "reviewer-node",
                    "url": "https://api.github.com/users/release-reviewer",
                },
            },
            "environment_protection": protection,
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


def captured_github_authority(
    record: dict[str, object],
) -> tuple[mock.Mock, dict[str, object]]:
    authorization = record["authorization"]
    protection = authorization["environment_protection"]
    approval = authorization["environment_approval"]
    environment = {
        "id": protection["environment_id"],
        "html_url": protection["environment_url"],
        "protection_rules": [
            {
                "id": protection["required_reviewer_rule_ids"][0],
                "type": "required_reviewers",
                "reviewers": [{"type": "User"}],
            }
        ],
        "deployment_branch_policy": protection["deployment_branch_policy"],
    }
    policies = {
        "total_count": 1,
        "branch_policies": [
            {
                **protection["custom_branch_policies"][0],
                "type": "branch",
            }
        ],
    }
    run = {
        "actor": {"login": authorization["actor"]},
        "conclusion": "success",
        "event": "workflow_dispatch",
        "head_branch": "main",
        "head_sha": authorization["workflow_commit"],
        "html_url": authorization["run_url"],
        "id": authorization["run_id"],
        "path": ".github/workflows/release-plan-supersession.yml@main",
        "repository": {"full_name": "durable-workflow/.github"},
        "run_attempt": authorization["run_attempt"],
        "status": "completed",
    }
    history = json.loads(
        json.dumps(
            [
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
                        "avatar_url": "https://avatars.githubusercontent.com/u/55?v=4",
                        "site_admin": False,
                        "type": "User",
                    },
                }
            ]
        )
    )
    responses = {
        "environment": environment,
        "policies": policies,
        "run": run,
        "history": history,
    }
    client = mock.Mock()

    def respond(url: str, **_kwargs: object) -> object:
        if url.endswith("deployment-branch-policies?per_page=100"):
            return responses["policies"]
        if url.endswith("/approvals"):
            return responses["history"]
        if "/actions/runs/" in url:
            return responses["run"]
        if "/environments/" in url:
            return responses["environment"]
        raise AssertionError(f"unexpected GitHub authority request: {url}")

    client.json.side_effect = respond
    return client, responses


class ComponentRecoveryContractTest(unittest.TestCase):
    def test_immutable_plan_registry_is_consumed_as_one_complete_authority_set(self) -> None:
        client = mock.Mock()
        client.json.return_value = [
            {"ref": f"refs/tags/release-plan/completed-{index:03d}"}
            for index in range(125)
        ]

        tags = list_release_plan_tags(client)

        self.assertEqual(125, len(tags))
        client.json.assert_called_once_with(
            "https://api.github.com/repos/durable-workflow/.github/"
            "git/matching-refs/tags/release-plan/"
        )

    def test_scheduled_discovery_uses_immutable_plan_time_not_updated_release_order(self) -> None:
        older = plan()
        older["plan"] = "older-alpha"
        newer = plan("beta")
        newer["plan"] = "newer-beta"
        tags = [f"release-plan/{older['plan']}", f"release-plan/{newer['plan']}"]
        commits = {tags[0]: "a" * 40, tags[1]: "b" * 40}
        recorded = {
            "a" * 40: dt.datetime(2026, 7, 20, tzinfo=dt.UTC),
            "b" * 40: dt.datetime(2026, 7, 22, tzinfo=dt.UTC),
        }

        with (
            mock.patch(
                "scripts.component_release_recovery.list_release_plan_tags",
                # Mutable Releases API order after the older Release was edited.
                return_value=[tags[0], tags[1]],
            ),
            mock.patch(
                "scripts.component_release_recovery.resolve_tag",
                side_effect=lambda _client, _repository, tag: commits[tag],
            ),
            mock.patch(
                "scripts.component_release_recovery.read_plan_authority",
                side_effect=[(older, preparation(older)), (newer, preparation(newer))],
            ),
            mock.patch(
                "scripts.component_release_recovery.direct_plan_lifecycle",
                side_effect=[("completed", None), ("completed", None)],
            ),
            mock.patch(
                "scripts.component_release_recovery.immutable_plan_recorded_at",
                side_effect=lambda _client, commit: recorded[commit],
            ),
            mock.patch(
                "scripts.component_release_recovery.accepted_continuity_supersession",
                return_value=None,
            ),
        ):
            selected = select_implicit_plan_authority(mock.Mock())

        self.assertEqual(tags[1], selected["tag"])
        self.assertEqual("completed", selected["lifecycle"])

    def test_terminal_failure_successor_requires_exact_authorized_plan_identity(self) -> None:
        failed = plan()
        failed["plan"] = "failed-plan"
        authorized_successor = json.loads(json.dumps(failed))
        authorized_successor["plan"] = "successor-plan"
        authorized_successor["components"]["workflow"]["version"] = "2.0.0-alpha.2"
        recorded_successor = json.loads(json.dumps(authorized_successor))
        recorded_successor["components"]["workflow"]["commit"] = "e" * 40
        failed_tag = f"release-plan/{failed['plan']}"
        successor_tag = f"release-plan/{authorized_successor['plan']}"
        failed_commit = "a" * 40
        successor_commit = "b" * 40
        failure_commit = "c" * 40
        failure = supersession_record(failed, authorized_successor, failed_commit)

        with (
            mock.patch(
                "scripts.component_release_recovery.resolve_tag",
                side_effect=[None, failure_commit],
            ),
            mock.patch(
                "scripts.component_release_recovery.read_record",
                side_effect=[failure, authorized_successor],
            ),
            mock.patch(
                "scripts.component_release_recovery.revalidate_supersession_authority",
            ),
        ):
            lifecycle, successor_identity = direct_plan_lifecycle(
                mock.Mock(),
                failed_tag,
                failed_commit,
                failed,
                None,
            )

        self.assertEqual("superseded", lifecycle)
        self.assertEqual(
            {
                "tag": successor_tag,
                "sha256": manifest_digest(authorized_successor),
                "plan": authorized_successor,
            },
            successor_identity,
        )

        commits = {failed_tag: failed_commit, successor_tag: successor_commit}
        recorded = {
            failed_commit: dt.datetime(2026, 7, 20, tzinfo=dt.UTC),
            successor_commit: dt.datetime(2026, 7, 21, tzinfo=dt.UTC),
        }
        with (
            mock.patch(
                "scripts.component_release_recovery.list_release_plan_tags",
                return_value=[failed_tag, successor_tag],
            ),
            mock.patch(
                "scripts.component_release_recovery.resolve_tag",
                side_effect=lambda _client, _repository, tag: commits[tag],
            ),
            mock.patch(
                "scripts.component_release_recovery.read_plan_authority",
                side_effect=[(failed, None), (recorded_successor, None)],
            ),
            mock.patch(
                "scripts.component_release_recovery.direct_plan_lifecycle",
                side_effect=[
                    (lifecycle, successor_identity),
                    ("completed", None),
                ],
            ),
            mock.patch(
                "scripts.component_release_recovery.immutable_plan_recorded_at",
                side_effect=lambda _client, commit: recorded[commit],
            ),
            mock.patch(
                "scripts.component_release_recovery.accepted_continuity_supersession",
                return_value=None,
            ),
            self.assertRaisesRegex(RecoveryError, "conflicting successor identity"),
        ):
            select_implicit_plan_authority(mock.Mock())

    def test_terminal_failure_rejects_incomplete_lifecycle_authority(self) -> None:
        failed = plan()
        failed["plan"] = "failed-plan"
        successor = json.loads(json.dumps(failed))
        successor["plan"] = "successor-plan"
        successor["components"]["workflow"]["version"] = "2.0.0-alpha.2"
        failed_tag = f"release-plan/{failed['plan']}"
        failed_commit = "a" * 40
        incomplete = {
            "schema": "durable-workflow.release-plan-failure/v1",
            "outcome": "terminal-failure",
            "failed_plan": {
                "tag": failed_tag,
                "commit": failed_commit,
                "sha256": manifest_digest(failed),
            },
            "successor_plan": {
                "tag": f"release-plan/{successor['plan']}",
                "sha256": manifest_digest(successor),
            },
        }

        with (
            mock.patch(
                "scripts.component_release_recovery.resolve_tag",
                side_effect=[None, "c" * 40],
            ),
            mock.patch(
                "scripts.component_release_recovery.read_record",
                side_effect=[incomplete, successor],
            ),
            self.assertRaisesRegex(RecoveryError, "record keys must be exactly"),
        ):
            direct_plan_lifecycle(
                mock.Mock(),
                failed_tag,
                failed_commit,
                failed,
                None,
            )

    def test_terminal_failure_resolves_and_normalizes_captured_github_authority(self) -> None:
        failed = plan()
        successor = json.loads(json.dumps(failed))
        successor["plan"] = "successor-plan"
        successor["components"]["workflow"]["version"] = "2.0.0-alpha.2"
        record = supersession_record(failed, successor, "a" * 40)
        client, _responses = captured_github_authority(record)

        revalidate_supersession_authority(record, client)

        mutations = (
            ("run", "id", 999),
            ("run", "run_attempt", 2),
            ("run", "path", ".github/workflows/release-plan-observer.yml@main"),
            ("run", "head_sha", "0" * 40),
            ("run", "conclusion", "failure"),
            ("environment", "id", 999),
            ("history", "state", "rejected"),
            ("reviewer", "id", 999),
        )
        for target, field, value in mutations:
            with self.subTest(target=target, field=field):
                changed = json.loads(json.dumps(record))
                client, responses = captured_github_authority(changed)
                if target == "history":
                    responses["history"][0][field] = value
                elif target == "reviewer":
                    responses["history"][0]["user"][field] = value
                else:
                    responses[target][field] = value
                with self.assertRaises(RecoveryError):
                    revalidate_supersession_authority(changed, client)

    def test_scheduled_discovery_fails_closed_on_ambiguous_or_incomplete_history(self) -> None:
        first = plan()
        first["plan"] = "first"
        second = plan("beta")
        second["plan"] = "second"
        tags = [f"release-plan/{first['plan']}", f"release-plan/{second['plan']}"]
        commits = {tags[0]: "a" * 40, tags[1]: "b" * 40}

        cases = (
            (
                "ambiguous immutable Git recorded-at",
                [("completed", None), ("completed", None)],
                {
                    "a" * 40: dt.datetime(2026, 7, 20, tzinfo=dt.UTC),
                    "b" * 40: dt.datetime(2026, 7, 20, tzinfo=dt.UTC),
                },
            ),
            (
                "remains actionable",
                [("actionable", None), ("completed", None)],
                {
                    "a" * 40: dt.datetime(2026, 7, 20, tzinfo=dt.UTC),
                    "b" * 40: dt.datetime(2026, 7, 21, tzinfo=dt.UTC),
                },
            ),
        )
        for message, lifecycles, recorded in cases:
            with (
                self.subTest(message=message),
                mock.patch(
                    "scripts.component_release_recovery.list_release_plan_tags",
                    return_value=tags,
                ),
                mock.patch(
                    "scripts.component_release_recovery.resolve_tag",
                    side_effect=lambda _client, _repository, tag: commits[tag],
                ),
                mock.patch(
                    "scripts.component_release_recovery.read_plan_authority",
                    side_effect=[(first, preparation(first)), (second, preparation(second))],
                ),
                mock.patch(
                    "scripts.component_release_recovery.direct_plan_lifecycle",
                    side_effect=lifecycles,
                ),
                mock.patch(
                    "scripts.component_release_recovery.immutable_plan_recorded_at",
                    side_effect=lambda _client, commit, recorded=recorded: recorded[commit],
                ),
                mock.patch(
                    "scripts.component_release_recovery.accepted_continuity_supersession",
                    return_value=None,
                ),
                self.assertRaisesRegex(RecoveryError, message),
            ):
                select_implicit_plan_authority(mock.Mock())

    def test_completed_continuity_successors_deterministically_supersede_one_interruption(self) -> None:
        interrupted = plan()
        interrupted["plan"] = "interrupted"
        first_successor = plan()
        first_successor["plan"] = "first-successor"
        latest = plan("beta")
        latest["plan"] = "latest"
        plans = [interrupted, first_successor, latest]
        tags = [f"release-plan/{candidate['plan']}" for candidate in plans]
        interruption_tag = "beta-continuity/interrupted/interrupted"
        interruption_commit = "d" * 40
        interruption_evidence = {"outcome": "intentionally-interrupted"}
        superseded = {
            "tag": interruption_tag,
            "commit": interruption_commit,
            "evidence_sha256": manifest_digest(interruption_evidence),
            "plan_sha256": manifest_digest(interrupted),
            "reason": "missing-post-acceptance-publication-trigger",
        }
        commits = {
            tags[0]: "a" * 40,
            tags[1]: "b" * 40,
            tags[2]: "c" * 40,
            interruption_tag: interruption_commit,
        }
        recorded = {
            "a" * 40: dt.datetime(2026, 7, 20, tzinfo=dt.UTC),
            "b" * 40: dt.datetime(2026, 7, 21, tzinfo=dt.UTC),
            "c" * 40: dt.datetime(2026, 7, 22, tzinfo=dt.UTC),
        }

        with (
            mock.patch(
                "scripts.component_release_recovery.list_release_plan_tags",
                return_value=tags,
            ),
            mock.patch(
                "scripts.component_release_recovery.resolve_tag",
                side_effect=lambda _client, _repository, tag: commits[tag],
            ),
            mock.patch(
                "scripts.component_release_recovery.read_plan_authority",
                side_effect=[(candidate, preparation(candidate)) for candidate in plans],
            ),
            mock.patch(
                "scripts.component_release_recovery.direct_plan_lifecycle",
                side_effect=[
                    ("interrupted", interruption_tag),
                    ("completed", None),
                    ("completed", None),
                ],
            ),
            mock.patch(
                "scripts.component_release_recovery.immutable_plan_recorded_at",
                side_effect=lambda _client, commit: recorded[commit],
            ),
            mock.patch(
                "scripts.component_release_recovery.accepted_continuity_supersession",
                side_effect=[None, superseded, superseded],
            ),
            mock.patch(
                "scripts.component_release_recovery.read_record",
                return_value=interruption_evidence,
            ),
        ):
            selected = select_implicit_plan_authority(mock.Mock())

        self.assertEqual(tags[2], selected["tag"])
        self.assertEqual("completed", selected["lifecycle"])

    def test_recovery_composer_verification_expands_minified_exact_version_strictly(self) -> None:
        component = COMPONENTS["sdk-php"]
        commit = "a" * 40
        client = mock.Mock()
        client.json.return_value = {
            "minified": "composer/2.0",
            "packages": {
                component.package: [
                    {
                        "version": "0.1.2",
                        "source": {"reference": commit},
                        "dist": {"reference": commit},
                    },
                    {"version": "0.1.1"},
                ]
            },
        }

        result = verify_composer(client, component, "0.1.1", commit)
        self.assertEqual(commit, result["source_reference"])
        self.assertEqual(commit, result["dist_reference"])

        client.json.return_value["packages"][component.package][1]["dist"] = {"reference": "b" * 40}
        with self.assertRaisesRegex(RecoveryError, "Packagist identity.*not"):
            verify_composer(client, component, "0.1.1", commit)

    def test_recovery_composer_verification_rejects_invalid_compact_identity_and_order(self) -> None:
        component = COMPONENTS["sdk-php"]
        commit = "a" * 40
        first = {
            "version": "0.1.1",
            "source": {"reference": commit},
            "dist": {"reference": commit},
        }
        client = mock.Mock()

        cases = (
            ([first, {"version": "0.1.2"}], "strictly descending"),
            ([first, {"version": "0.1.0"}, {"dist": {"reference": commit}}], "declare a version"),
        )
        for versions, error in cases:
            with self.subTest(error=error):
                client.json.return_value = {
                    "minified": "composer/2.0",
                    "packages": {component.package: versions},
                }
                with self.assertRaisesRegex(RecoveryError, error):
                    verify_composer(client, component, "0.1.1", commit)

    def test_recovery_composer_verification_rejects_ambiguous_exact_version_before_provenance(self) -> None:
        component = COMPONENTS["sdk-php"]
        commit = "a" * 40
        client = mock.Mock()
        client.json.return_value = {
            "packages": {
                component.package: [
                    {
                        "version": "0.1.1",
                        "source": {"reference": commit},
                        "dist": {"reference": commit},
                    },
                    {
                        "version": "v0.1.1",
                        "source": {"reference": "b" * 40},
                        "dist": {"reference": "b" * 40},
                    },
                ]
            }
        }

        with self.assertRaisesRegex(RecoveryError, "multiple records"):
            verify_composer(client, component, "0.1.1", commit)

    def test_scheduled_continuity_recovery_waits_for_remote_resume(self) -> None:
        candidate = plan()
        with (
            mock.patch(
                "scripts.component_release_recovery.resolve_tag",
                side_effect=["a" * 40, None],
            ),
            mock.patch("scripts.component_release_recovery.read_record", return_value=candidate),
        ):
            paused = scheduled_continuity_pause(mock.Mock(), candidate)

        self.assertEqual(
            f"beta-continuity/{candidate['plan']}/resumed",
            paused["resumed_tag"],
        )
        with (
            mock.patch(
                "scripts.component_release_recovery.resolve_tag",
                side_effect=["a" * 40, "b" * 40],
            ),
            mock.patch("scripts.component_release_recovery.read_record", return_value=candidate),
        ):
            self.assertIsNone(scheduled_continuity_pause(mock.Mock(), candidate))

    def test_recovery_public_client_retries_transient_github_reads(self) -> None:
        sleeps: list[float] = []
        client = PublicClient(max_attempts=3, retry_base_seconds=1, sleep=sleeps.append)
        responses = [
            github_http_error(503, **{"Retry-After": "4"}),
            urllib.error.URLError(ConnectionResetError("connection reset")),
            io.BytesIO(b"[]"),
        ]

        with mock.patch(
            "scripts.component_release_recovery.urllib.request.urlopen",
            side_effect=responses,
        ) as open_url:
            result = client.json("https://api.github.com/repos/durable-workflow/.github/releases?per_page=100")

        self.assertEqual([], result)
        self.assertEqual([4, 2], sleeps)
        self.assertEqual(3, open_url.call_count)

    def test_authenticated_requests_preserve_endpoint_api_versions(self) -> None:
        cases = (
            ({"X-GitHub-Api-Version": SUPERSESSION_API_VERSION}, SUPERSESSION_API_VERSION),
            ({}, "2022-11-28"),
        )
        for headers, expected_version in cases:
            with self.subTest(expected_version=expected_version):
                client = PublicClient(token="test-token")
                response = mock.Mock()
                with mock.patch(
                    "scripts.component_release_recovery.urllib.request.urlopen",
                    return_value=response,
                ) as open_url:
                    self.assertIs(
                        response,
                        client.request(
                            "https://api.github.com/repos/durable-workflow/.github/actions/runs/456",
                            headers=headers,
                        ),
                    )

                request = open_url.call_args.args[0]
                request_headers = {key.lower(): value for key, value in request.header_items()}
                self.assertEqual("Bearer test-token", request_headers["authorization"])
                self.assertEqual(expected_version, request_headers["x-github-api-version"])

    def test_recovery_public_client_never_retries_authentication_with_rate_limit_guidance(self) -> None:
        sleeps: list[float] = []
        client = PublicClient(max_attempts=3, retry_base_seconds=1, sleep=sleeps.append)
        error = github_http_error(
            401,
            b"Bad credentials: API rate limit exceeded",
            **{"Retry-After": "20", "X-RateLimit-Remaining": "0"},
        )

        with (
            mock.patch(
                "scripts.component_release_recovery.urllib.request.urlopen",
                side_effect=error,
            ) as open_url,
            self.assertRaisesRegex(RecoveryError, r"public request failed \(401\)"),
        ):
            client.json("https://api.github.com/repos/durable-workflow/.github/releases?per_page=100")

        self.assertEqual([], sleeps)
        self.assertEqual(1, open_url.call_count)

    def test_recovery_public_client_separates_exhausted_infrastructure_from_missing_resources(self) -> None:
        client = PublicClient(max_attempts=2, retry_base_seconds=1, sleep=lambda _delay: None)
        with (
            mock.patch(
                "scripts.component_release_recovery.urllib.request.urlopen",
                side_effect=[github_http_error(503), github_http_error(502)],
            ) as open_url,
            self.assertRaisesRegex(
                PublicInfrastructureError,
                r"endpoint_class=releases-api, attempts=2, reason=retry-exhausted, status=502",
            ),
        ):
            client.json("https://api.github.com/repos/durable-workflow/.github/releases?per_page=100")
        self.assertEqual(2, open_url.call_count)

        with (
            mock.patch(
                "scripts.component_release_recovery.urllib.request.urlopen",
                side_effect=github_http_error(404),
            ) as open_url,
            self.assertRaisesRegex(NotFound, "public resource is absent"),
        ):
            client.json("https://api.github.com/repos/durable-workflow/.github/releases/tags/missing")
        self.assertEqual(1, open_url.call_count)

    def test_discovery_rejects_missing_preparation_for_an_incomplete_release(self) -> None:
        candidate = plan()
        tag = f"release-plan/{candidate['plan']}"
        record_commit = "a" * 40
        client = mock.Mock()
        client.json.return_value = {
            "tag_name": tag,
            "draft": False,
            "assets": [
                {
                    "name": "release-plan.json",
                    "browser_download_url": "https://example.invalid/release-plan.json",
                }
            ],
        }
        client.bytes.return_value = canonical_json(candidate)

        with (
            mock.patch("scripts.component_release_recovery.resolve_tag", return_value=record_commit),
            mock.patch(
                "scripts.component_release_recovery.read_record",
                side_effect=[candidate, NotFound("missing preparation", "plan-discovery")],
            ),
            mock.patch(
                "scripts.component_release_recovery.verify_component",
                side_effect=NotFound("release is incomplete"),
            ),
            self.assertRaisesRegex(RecoveryError, "only completed legacy releases"),
        ):
            discover_plan(client, tag, "workflow")

    def test_resolution_rejects_missing_preparation_before_publish(self) -> None:
        candidate = plan()
        with (
            mock.patch("scripts.component_release_recovery.verify_plan_authority", return_value=({}, {})),
            mock.patch("scripts.component_release_recovery.resolve_tag", return_value=None),
            self.assertRaisesRegex(RecoveryError, "release preparation required before publishing workflow"),
        ):
            resolve_component(
                mock.Mock(),
                "workflow",
                f"release-plan/{candidate['plan']}",
                "a" * 40,
                candidate,
                None,
            )

    def test_completed_legacy_release_is_the_only_missing_preparation_exception(self) -> None:
        candidate = plan()
        identity = candidate["components"]["workflow"]
        public_evidence = {"version": identity["version"], "commit": identity["commit"]}
        with (
            mock.patch("scripts.component_release_recovery.verify_plan_authority", return_value=({}, {})),
            mock.patch("scripts.component_release_recovery.resolve_tag", return_value=identity["commit"]),
            mock.patch("scripts.component_release_recovery.verify_component", return_value=public_evidence),
        ):
            state, outputs = resolve_component(
                mock.Mock(),
                "workflow",
                f"release-plan/{candidate['plan']}",
                "a" * 40,
                candidate,
                None,
            )

        self.assertEqual("skip", outputs["action"])
        self.assertEqual("complete", state["phase"])
        self.assertEqual(public_evidence, state["public_evidence"])
        self.assertNotIn("release_preparation", state)

    def test_dependency_progression_is_public_and_acyclic(self) -> None:
        self.assertEqual((), COMPONENTS["workflow"].dependencies)
        self.assertEqual((), COMPONENTS["sdk-php"].dependencies)
        self.assertEqual(("workflow", "sdk-php"), COMPONENTS["waterline"].dependencies)
        self.assertEqual(("workflow",), COMPONENTS["server"].dependencies)
        self.assertEqual(("server",), COMPONENTS["cli"].dependencies)
        self.assertEqual(("server",), COMPONENTS["sdk-python"].dependencies)
        self.assertEqual(("server",), COMPONENTS["sdk-rust"].dependencies)

    def test_expected_default_branches_are_explicit(self) -> None:
        self.assertEqual("v2", COMPONENTS["workflow"].default_branch)
        self.assertEqual("v2", COMPONENTS["waterline"].default_branch)
        for name in {"server", "cli", "sdk-php", "sdk-python", "sdk-rust"}:
            self.assertEqual("main", COMPONENTS[name].default_branch)

    def test_alpha_and_beta_plans_validate_independently(self) -> None:
        for channel in ("alpha", "beta"):
            candidate = plan(channel)
            validate_plan(candidate)
            validate_release_preparation(preparation(candidate), candidate)

    def test_preparation_rejects_notes_for_another_version(self) -> None:
        candidate = plan()
        prepared = preparation(candidate)
        prepared["components"]["server"]["version"] = "9.9.9"
        with self.assertRaisesRegex(RecoveryError, "different planned identity"):
            validate_release_preparation(prepared, candidate)

    def test_beta_plan_rejects_alpha_workflow_version(self) -> None:
        candidate = plan("beta")
        candidate["components"]["workflow"]["version"] = "2.0.0-alpha.8"
        with self.assertRaisesRegex(RecoveryError, "2.0.0-beta.N"):
            validate_plan(candidate)

    def test_publication_workflows_dispatch_in_the_declared_tag_context(self) -> None:
        dispatching = {
            "server": ("release.yml", "tag"),
            "cli": ("release.yml", "tag"),
            "sdk-python": ("publish.yml", "release_tag"),
            "sdk-rust": ("release.yml", "release_tag"),
        }
        self.assertEqual(dispatching, {
            name: (component.release_workflow, component.release_tag_input)
            for name, component in COMPONENTS.items()
            if component.release_workflow is not None
        })
        for name, (workflow, tag_input) in dispatching.items():
            with self.subTest(component=name):
                source = f'''on:
  schedule:
  workflow_dispatch:
jobs:
  recover:
    steps:
      - run: python recovery.py resolve --preparation-output release-preparation.json
      - name: Create the exact source tag
        run: |
          gh api --method POST "repos/$GITHUB_REPOSITORY/git/refs" \\
            -f ref="refs/tags/$RELEASE_TAG" -f sha="$RELEASE_COMMIT"
      - name: Start repository-owned publication
        run: |
          gh run list --workflow {workflow} \\
            --json databaseId,displayTitle,headBranch,headSha,status,conclusion
          python scripts/ci/component-release-recovery.py select-publication-run \\
            --release-tag "$RELEASE_TAG" --release-commit "$RELEASE_COMMIT"
          gh workflow run {workflow} --ref "$RELEASE_TAG" \\
            -f {tag_input}="$RELEASE_TAG" -f release_plan="$PLAN_TAG"
'''
                expected_sha256 = normalized_source_sha256(source)
                verify_recovery_workflow_source(name, source, expected_sha256)
                with self.assertRaisesRegex(RecoveryError, "protected source identity"):
                    verify_recovery_workflow_source(
                        name,
                        source.replace('"$RELEASE_TAG" \\\n', '"$DEFAULT_BRANCH" \\\n', 1),
                        expected_sha256,
                    )
                with self.assertRaisesRegex(RecoveryError, "protected source identity"):
                    verify_recovery_workflow_source(
                        name,
                        source.replace(f'-f {tag_input}="$RELEASE_TAG"', f'-f {tag_input}="$DEFAULT_BRANCH"'),
                        expected_sha256,
                    )

    def test_publication_run_selection_adopts_tag_triggered_runs(self) -> None:
        release_tag = "1.2.3"
        release_commit = "a" * 40

        def run(status: str, conclusion: str | None, run_id: int = 17) -> dict[str, object]:
            return {
                "databaseId": run_id,
                "displayTitle": f"Release {release_tag} for direct",
                "headBranch": release_tag,
                "headSha": release_commit,
                "status": status,
                "conclusion": conclusion,
            }

        cases = (
            ("queued", None, "wait"),
            ("in_progress", None, "wait"),
            ("completed", "failure", "rerun"),
            ("completed", "success", "complete"),
        )
        for status, conclusion, action in cases:
            with self.subTest(status=status, conclusion=conclusion):
                self.assertEqual(
                    {"action": action, "run_id": 17, "status": status, "conclusion": conclusion},
                    select_publication_run(release_tag, release_commit, [run(status, conclusion)]),
                )
        self.assertEqual(
            {"action": "dispatch", "run_id": None, "status": None, "conclusion": None},
            select_publication_run(release_tag, release_commit, []),
        )
        with self.assertRaisesRegex(RecoveryError, "different source commit"):
            select_publication_run(
                release_tag,
                release_commit,
                [{**run("queued", None), "headSha": "b" * 40}],
            )

    def test_cli_release_rejects_assets_attested_for_the_wrong_source(self) -> None:
        attested_commit = "a" * 40
        declared_commit = "b" * 40
        version = "1.2.3"
        attested_ref = "refs/tags/1.2.2"

        class FixtureClient:
            contents = {name: f"fixture {name}\n".encode() for name in CLI_ASSETS - {"SHA256SUMS"}}
            checksums = "".join(
                f"{hashlib.sha256(content).hexdigest()}  {name}\n" for name, content in sorted(contents.items())
            ).encode()

            def __init__(self) -> None:
                self.downloaded: set[str] = set()

            def json(self, _url: str) -> dict[str, object]:
                return {
                    "id": 123,
                    "tag_name": version,
                    "draft": False,
                    "html_url": f"https://github.com/durable-workflow/cli/releases/tag/{version}",
                    "assets": [
                        {
                            "id": index,
                            "name": name,
                            "browser_download_url": f"https://example.invalid/{name}",
                        }
                        for index, name in enumerate(sorted(CLI_ASSETS), start=1)
                    ],
                }

            def bytes(self, _url: str) -> bytes:
                return self.checksums

            def download(self, url: str, path: Path, *, expected_sha256: str) -> dict[str, object]:
                name = url.rsplit("/", 1)[-1]
                content = self.contents[name]
                if expected_sha256 != hashlib.sha256(content).hexdigest():
                    raise AssertionError("fixture download checksum mismatch")
                path.write_bytes(content)
                self.downloaded.add(name)
                return {"url": url, "size": len(content), "sha256": expected_sha256}

        def verify_attestation(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            self.assertEqual("durable-workflow/cli", command[command.index("--repo") + 1])
            if "--source-digest" not in command:
                return subprocess.CompletedProcess(
                    command,
                    1,
                    stdout="",
                    stderr="workflow authority does not match the declared release",
                )
            source_digest = command[command.index("--source-digest") + 1]
            source_ref = command[command.index("--source-ref") + 1]
            valid = source_digest == attested_commit and source_ref == attested_ref
            return subprocess.CompletedProcess(
                command,
                0 if valid else 1,
                stdout="",
                stderr="attestation source does not match the declared release",
            )

        client = FixtureClient()
        shutil_module = mock.Mock()
        shutil_module.which.return_value = "/usr/bin/gh"
        subprocess_module = mock.Mock()
        subprocess_module.run.side_effect = verify_attestation
        with (
            mock.patch("scripts.component_release_recovery.shutil", shutil_module, create=True),
            mock.patch("scripts.component_release_recovery.subprocess", subprocess_module, create=True),
            self.assertRaisesRegex(RecoveryError, "build attestation failed"),
        ):
            verify_cli(client, COMPONENTS["cli"], version, declared_commit)
        self.assertEqual(CLI_ASSETS - {"SHA256SUMS"}, client.downloaded)

    def test_post_discovery_failures_retain_explicit_and_scheduled_plan_identity(self) -> None:
        candidate = plan()
        plan_tag = "release-plan/plan-a"
        record_commit = "d" * 40

        for requested_tag in (plan_tag, None):
            with self.subTest(requested_tag=requested_tag), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                plan_output = root / "release-plan.json"
                preparation_output = root / "release-preparation.json"
                evidence_output = root / "release-recovery-evidence.json"
                arguments = [
                    "component_release_recovery.py",
                    "resolve",
                    "--component",
                    "server",
                    "--plan-output",
                    str(plan_output),
                    "--preparation-output",
                    str(preparation_output),
                    "--evidence",
                    str(evidence_output),
                ]
                if requested_tag is not None:
                    arguments.extend(("--plan-tag", requested_tag))
                else:
                    arguments.append("--allow-empty")

                with (
                    mock.patch.object(sys, "argv", arguments),
                    mock.patch(
                        "scripts.component_release_recovery.discover_plan",
                        return_value=(plan_tag, record_commit, candidate, preparation(candidate)),
                    ) as discover,
                    mock.patch(
                        "scripts.component_release_recovery.resolve_component",
                        side_effect=RecoveryError("post-discovery failure", "tag-preflight"),
                    ),
                    mock.patch(
                        "scripts.component_release_recovery.scheduled_continuity_pause",
                        return_value=None,
                    ) as continuity_pause,
                ):
                    self.assertEqual(1, main())

                discover.assert_called_once_with(mock.ANY, requested_tag, "server")
                if requested_tag is None:
                    continuity_pause.assert_called_once_with(mock.ANY, candidate)
                else:
                    continuity_pause.assert_not_called()
                self.assertEqual(canonical_json(candidate), plan_output.read_bytes())
                self.assertEqual(
                    canonical_json(preparation(candidate)),
                    preparation_output.read_bytes(),
                )
                evidence = json.loads(evidence_output.read_bytes())
                self.assertEqual(plan_tag, evidence["release_plan_tag"])
                self.assertEqual(candidate["plan"], evidence["plan"])
                self.assertEqual(candidate["channel"], evidence["channel"])
                self.assertEqual(record_commit, evidence["plan_record_commit"])
                self.assertEqual(plan_tag, evidence["durable_evidence"]["release_plan"])
                self.assertTrue(evidence["resume_action"].endswith(f" for {plan_tag}"))

    def test_scheduled_discovery_without_a_pending_plan_is_a_truthful_no_op(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            evidence_output = root / "release-recovery-evidence.json"
            github_output = root / "github-output"
            arguments = [
                "component_release_recovery.py",
                "resolve",
                "--component",
                "server",
                "--plan-output",
                str(root / "release-plan.json"),
                "--preparation-output",
                str(root / "release-preparation.json"),
                "--evidence",
                str(evidence_output),
                "--github-output",
                str(github_output),
                "--allow-empty",
            ]

            with (
                mock.patch.object(sys, "argv", arguments),
                mock.patch(
                    "scripts.component_release_recovery.discover_plan",
                    side_effect=RecoveryError("no public release plan is available", "plan-discovery"),
                ),
            ):
                self.assertEqual(0, main())

            evidence = json.loads(evidence_output.read_bytes())
            self.assertEqual("plan-discovery", evidence["phase"])
            self.assertEqual("idle", evidence["outcome"])
            self.assertEqual("action=none\n", github_output.read_text())


if __name__ == "__main__":
    unittest.main()
