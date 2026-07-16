from __future__ import annotations

import copy
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.beta_candidate import CandidateError, canonical_json
from scripts.release_plan import (
    COMPONENTS,
    FOUNDATION_COMMIT,
    FOUNDATION_TAG,
    SCHEMA,
    candidate_manifest,
    check_plan_compatibility,
    completion_manifest,
    record_plan,
    require_prior_plans_completed,
    validate_plan,
)


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


class ReleasePlanValidationTest(unittest.TestCase):
    def test_alpha_plan_is_channel_bound(self) -> None:
        plan = release_plan()
        validate_plan(plan)
        candidate = candidate_manifest(plan)
        self.assertEqual("alpha-recovery-proof-1", candidate["candidate"])
        self.assertEqual(plan["components"], candidate["components"])
        completion = completion_manifest(plan, "a" * 40)
        self.assertEqual("alpha", completion["channel"])
        self.assertEqual("durable-workflow.release-candidate/v1", completion["schema"])

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

    def test_plan_rejects_a_different_foundation(self) -> None:
        plan = release_plan()
        plan["foundation"]["commit"] = "0" * 40
        with self.assertRaisesRegex(CandidateError, "proven immutable candidate foundation"):
            validate_plan(plan)

    def test_new_plan_cannot_strand_an_interrupted_prior_plan(self) -> None:
        prior = release_plan()
        prior["plan"] = "plan-a"
        requested = release_plan()
        requested["plan"] = "plan-b"

        class FixtureClient:
            def json(self, _url: str) -> list[dict[str, str]]:
                return [{"ref": "refs/tags/release-plan/plan-a"}]

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=["a" * 40, None]),
            mock.patch("scripts.release_plan.read_public_record", return_value=prior),
            self.assertRaisesRegex(CandidateError, "prior plan release-plan/plan-a is incomplete"),
        ):
            require_prior_plans_completed(requested, FixtureClient())

    def test_new_plan_checks_all_matching_refs_when_registry_exceeds_one_hundred(self) -> None:
        requested = release_plan()
        requested["plan"] = "plan-b"
        requested_urls: list[str] = []

        class FixtureClient:
            def json(self, url: str) -> list[dict[str, str]]:
                requested_urls.append(url)
                return [
                    *[
                        {"ref": f"refs/tags/release-plan/completed-{index:03d}"}
                        for index in range(125)
                    ],
                    {"ref": "refs/tags/release-plan/plan-a"},
                ]

        def plan_for_tag(tag: str) -> dict[str, object]:
            prior = release_plan()
            prior["plan"] = tag.removeprefix("release-plan/")
            return prior

        def resolve(_client: object, _repository: str, tag: str) -> str | None:
            if tag == "release-candidate/alpha/plan-a":
                return None
            return "b" * 40 if tag.startswith("release-candidate/") else "a" * 40

        def read_record(_client: object, tag: str, commit: str, _filename: str) -> dict[str, object]:
            if tag.startswith("release-plan/"):
                return plan_for_tag(tag)
            plan_tag = tag.removeprefix("release-candidate/alpha/")
            return completion_manifest(plan_for_tag(f"release-plan/{plan_tag}"), "a" * 40)

        with (
            mock.patch("scripts.release_plan.resolve_tag", side_effect=resolve),
            mock.patch("scripts.release_plan.read_public_record", side_effect=read_record),
            self.assertRaisesRegex(CandidateError, "prior plan release-plan/plan-a is incomplete"),
        ):
            require_prior_plans_completed(requested, FixtureClient())

        self.assertEqual(
            [
                "https://api.github.com/repos/durable-workflow/.github/"
                "git/matching-refs/tags/release-plan/"
            ],
            requested_urls,
        )

    def test_completed_prior_plan_allows_the_next_plan(self) -> None:
        prior = release_plan()
        prior["plan"] = "plan-a"
        requested = release_plan()
        requested["plan"] = "plan-b"
        record_commit = "a" * 40
        completed_commit = "b" * 40
        completion = completion_manifest(prior, record_commit)

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
                side_effect=[prior, completion],
            ),
        ):
            evidence = require_prior_plans_completed(requested, FixtureClient())
        self.assertEqual(completed_commit, evidence["release-plan/plan-a"]["completion_commit"])


class ReleasePlanRecordTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.repository = root / "work"
        self.remote = root / "remote.git"
        subprocess.run(["git", "init", "--bare", str(self.remote)], check=True, capture_output=True)
        subprocess.run(["git", "init", str(self.repository)], check=True, capture_output=True)
        self.plan_path = root / "release-plan.json"
        self.authoritative_path = root / "authoritative-release-plan.json"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_plan(self, plan: dict[str, object]) -> None:
        self.plan_path.write_bytes(canonical_json(plan))

    def test_first_record_and_identical_recovery_keep_one_commit(self) -> None:
        plan = release_plan()
        self.write_plan(plan)
        created = record_plan(
            self.repository,
            self.plan_path,
            remote=str(self.remote),
            authoritative_plan=self.authoritative_path,
        )
        repeated = record_plan(
            self.repository,
            self.plan_path,
            remote=str(self.remote),
            authoritative_plan=self.authoritative_path,
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
        self.assertEqual(["release-plan.json"], files)
        self.assertEqual(canonical_json(plan), self.authoritative_path.read_bytes())

    def test_existing_plan_rejects_tuple_mutation(self) -> None:
        plan = release_plan()
        self.write_plan(plan)
        record_plan(
            self.repository,
            self.plan_path,
            remote=str(self.remote),
            authoritative_plan=self.authoritative_path,
        )
        changed = copy.deepcopy(plan)
        changed["components"]["server"]["commit"] = "e" * 40
        self.write_plan(changed)
        with self.assertRaisesRegex(CandidateError, "immutable"):
            check_plan_compatibility(self.repository, self.plan_path, remote=str(self.remote))


if __name__ == "__main__":
    unittest.main()
