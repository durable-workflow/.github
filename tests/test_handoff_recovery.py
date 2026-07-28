from __future__ import annotations

import json
import tempfile
import unittest
import urllib.parse
from pathlib import Path

from scripts.beta_candidate import canonical_json
from scripts.handoff_recovery import (
    KINDS,
    HandoffError,
    artifact_name,
    create_handoff,
    list_run_artifacts,
    select_handoff_artifact,
    validate_handoff,
)

REPOSITORY = "durable-workflow/.github"
RUN_ID = 123456
SOURCE_SHA = "a" * 40
WORKFLOW_REFS = {
    "candidate": "durable-workflow/.github/.github/workflows/beta-candidate.yml@refs/heads/main",
    "release-plan-observation": (
        "durable-workflow/.github/.github/workflows/release-plan-observer.yml@refs/heads/main"
    ),
}


def artifact(kind: str, attempt: int, artifact_id: int, *, expired: bool = False) -> dict[str, object]:
    return {
        "id": artifact_id,
        "name": artifact_name(kind, RUN_ID, attempt),
        "expired": expired,
        "workflow_run": {"id": RUN_ID, "head_sha": SOURCE_SHA},
    }


class HandoffSelectionTest(unittest.TestCase):
    def test_recorder_only_rerun_recovers_the_latest_prior_producing_attempt(self) -> None:
        for kind in KINDS:
            with self.subTest(kind=kind):
                selected = select_handoff_artifact(
                    kind,
                    [artifact(kind, 1, 101)],
                    run_id=RUN_ID,
                    current_attempt=2,
                    producer_attempt=1,
                    source_sha=SOURCE_SHA,
                )
                self.assertEqual(101, selected.artifact_id)
                self.assertEqual(1, selected.producer_attempt)
                self.assertEqual(artifact_name(kind, RUN_ID, 1), selected.name)

    def test_full_rerun_prefers_the_new_same_attempt_handoff(self) -> None:
        for kind in KINDS:
            with self.subTest(kind=kind):
                selected = select_handoff_artifact(
                    kind,
                    [artifact(kind, 1, 101), artifact(kind, 2, 202)],
                    run_id=RUN_ID,
                    current_attempt=2,
                    producer_attempt=2,
                    source_sha=SOURCE_SHA,
                )
                self.assertEqual(202, selected.artifact_id)
                self.assertEqual(2, selected.producer_attempt)

    def test_missing_expired_ambiguous_and_mismatched_handoffs_fail_closed(self) -> None:
        kind = "candidate"
        cases = {
            "missing": ([], "no verifier handoff"),
            "expired": (
                [artifact(kind, 1, 101), artifact(kind, 2, 202, expired=True)],
                "expired or has unknown retention state",
            ),
            "ambiguous": (
                [artifact(kind, 1, 101), artifact(kind, 1, 102)],
                "ambiguous",
            ),
            "future": ([artifact(kind, 3, 303)], "future producing attempt"),
        }
        for label, (artifacts, message) in cases.items():
            with self.subTest(case=label), self.assertRaisesRegex(HandoffError, message):
                select_handoff_artifact(
                    kind,
                    artifacts,
                    run_id=RUN_ID,
                    current_attempt=2,
                    producer_attempt=2 if label == "expired" else 1,
                    source_sha=SOURCE_SHA,
                )

        wrong_run = artifact(kind, 1, 101)
        wrong_run["workflow_run"] = {"id": RUN_ID + 1, "head_sha": SOURCE_SHA}
        with self.assertRaisesRegex(HandoffError, "mismatched workflow-run identity"):
            select_handoff_artifact(
                kind,
                [wrong_run],
                run_id=RUN_ID,
                current_attempt=2,
                producer_attempt=1,
                source_sha=SOURCE_SHA,
            )

    def test_retained_attempt_must_exist_and_name_the_newest_producer(self) -> None:
        kind = "release-plan-observation"
        artifacts = [artifact(kind, 1, 101), artifact(kind, 2, 202)]
        with self.assertRaisesRegex(HandoffError, "does not identify the newest"):
            select_handoff_artifact(
                kind,
                artifacts,
                run_id=RUN_ID,
                current_attempt=3,
                producer_attempt=1,
                source_sha=SOURCE_SHA,
            )
        with self.assertRaisesRegex(HandoffError, "producing attempt 3"):
            select_handoff_artifact(
                kind,
                artifacts,
                run_id=RUN_ID,
                current_attempt=3,
                producer_attempt=3,
                source_sha=SOURCE_SHA,
            )

    def test_artifact_listing_is_complete_and_bounded(self) -> None:
        class Client:
            def json(self, url: str) -> dict[str, object]:
                page = int(urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["page"][0])
                page_artifacts = [artifact("candidate", 1, index) for index in range(1, 101)]
                if page == 2:
                    page_artifacts = [artifact("candidate", 2, 101)]
                return {"total_count": 101, "artifacts": page_artifacts}

        artifacts = list_run_artifacts(Client(), REPOSITORY, RUN_ID)  # type: ignore[arg-type]
        self.assertEqual(101, len(artifacts))


class HandoffManifestTest(unittest.TestCase):
    def _create_fixture(self, root: Path, kind: str, attempt: int = 1) -> Path:
        for filename in KINDS[kind].filenames:
            (root / filename).write_text(f"{kind}:{filename}\n", encoding="utf-8")
        manifest = root / "handoff.json"
        create_handoff(
            kind,
            root,
            manifest,
            repository=REPOSITORY,
            workflow_ref=WORKFLOW_REFS[kind],
            source_sha=SOURCE_SHA,
            run_id=RUN_ID,
            run_attempt=attempt,
        )
        return manifest

    def test_candidate_and_observer_handoffs_bind_identity_attempt_and_file_bytes(self) -> None:
        for kind in KINDS:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                manifest = self._create_fixture(root, kind)
                result = validate_handoff(
                    kind,
                    root,
                    manifest,
                    repository=REPOSITORY,
                    workflow_ref=WORKFLOW_REFS[kind],
                    source_sha=SOURCE_SHA,
                    run_id=RUN_ID,
                    current_attempt=2,
                    producer_attempt=1,
                )
                self.assertEqual(1, result["producer"]["run_attempt"])
                self.assertEqual(artifact_name(kind, RUN_ID, 1), result["artifact_name"])

                first_file = root / KINDS[kind].filenames[0]
                first_file.write_bytes(b"different evidence")
                with self.assertRaisesRegex(HandoffError, "digest does not match"):
                    validate_handoff(
                        kind,
                        root,
                        manifest,
                        repository=REPOSITORY,
                        workflow_ref=WORKFLOW_REFS[kind],
                        source_sha=SOURCE_SHA,
                        run_id=RUN_ID,
                        current_attempt=2,
                        producer_attempt=1,
                    )

    def test_failed_observation_handoff_omits_only_verification_evidence(self) -> None:
        kind = "release-plan-observation"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self._create_fixture(root, kind)
            failed = validate_handoff(
                kind,
                root,
                manifest,
                repository=REPOSITORY,
                workflow_ref=WORKFLOW_REFS[kind],
                source_sha=SOURCE_SHA,
                run_id=RUN_ID,
                current_attempt=1,
                producer_attempt=1,
            )
            self.assertNotIn("verification.json", failed["files"])

            (root / "verification.json").write_text("verified\n", encoding="utf-8")
            create_handoff(
                kind,
                root,
                manifest,
                repository=REPOSITORY,
                workflow_ref=WORKFLOW_REFS[kind],
                source_sha=SOURCE_SHA,
                run_id=RUN_ID,
                run_attempt=1,
            )
            verified = validate_handoff(
                kind,
                root,
                manifest,
                repository=REPOSITORY,
                workflow_ref=WORKFLOW_REFS[kind],
                source_sha=SOURCE_SHA,
                run_id=RUN_ID,
                current_attempt=1,
                producer_attempt=1,
            )
            self.assertIn("verification.json", verified["files"])

    def test_identity_mismatch_and_unexpected_files_fail_before_use(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self._create_fixture(root, "candidate")
            handoff = json.loads(manifest.read_bytes())
            handoff["producer"]["run_attempt"] = 2
            manifest.write_bytes(canonical_json(handoff))
            with self.assertRaisesRegex(HandoffError, "producer identity"):
                validate_handoff(
                    "candidate",
                    root,
                    manifest,
                    repository=REPOSITORY,
                    workflow_ref=WORKFLOW_REFS["candidate"],
                    source_sha=SOURCE_SHA,
                    run_id=RUN_ID,
                    current_attempt=2,
                    producer_attempt=1,
                )

            manifest = self._create_fixture(root, "candidate")
            (root / "unrelated.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(HandoffError, "unexpected or missing files"):
                validate_handoff(
                    "candidate",
                    root,
                    manifest,
                    repository=REPOSITORY,
                    workflow_ref=WORKFLOW_REFS["candidate"],
                    source_sha=SOURCE_SHA,
                    run_id=RUN_ID,
                    current_attempt=2,
                    producer_attempt=1,
                )


if __name__ == "__main__":
    unittest.main()
