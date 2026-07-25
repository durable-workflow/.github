from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import TypeAlias

import yaml

from scripts.release_asset_mirror import MirrorError, repair_asset

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "durable-workflow/.github"
TAG = "beta-candidate/2.0.0-beta.10"
ASSET = "candidate.json"
AUTHORITY = b'{"candidate":"2.0.0-beta.10"}\n'

Outcome: TypeAlias = list[str] | bytes | RuntimeError | None


class FakeGitHub:
    def __init__(
        self,
        *,
        views: list[Outcome],
        downloads: list[Outcome] | None = None,
        upload: Outcome = None,
    ) -> None:
        self.views = views
        self.downloads = downloads or []
        self.upload = upload
        self.calls: list[list[str]] = []

    def __call__(self, command: list[str]) -> subprocess.CompletedProcess[str]:
        self.calls.append(command)
        operation = tuple(command[1:3])
        if operation == ("release", "view"):
            outcome = self.views.pop(0)
            if isinstance(outcome, RuntimeError):
                return subprocess.CompletedProcess(command, 1, stdout="", stderr=str(outcome))
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=json.dumps({"assets": [{"name": name} for name in outcome]}),
                stderr="",
            )
        if operation == ("release", "download"):
            outcome = self.downloads.pop(0)
            if isinstance(outcome, RuntimeError):
                return subprocess.CompletedProcess(command, 1, stdout="", stderr=str(outcome))
            destination = Path(command[command.index("--dir") + 1])
            asset_name = command[command.index("--pattern") + 1]
            (destination / asset_name).write_bytes(outcome)
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        if operation == ("release", "upload"):
            if isinstance(self.upload, RuntimeError):
                return subprocess.CompletedProcess(command, 1, stdout="", stderr=str(self.upload))
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
        raise AssertionError(f"unexpected gh command: {command}")

    def call_count(self, operation: tuple[str, str]) -> int:
        return sum(tuple(command[1:3]) == operation for command in self.calls)


class ReleaseAssetMirrorTest(unittest.TestCase):
    def authority_file(self, root: Path) -> Path:
        authority = root / ASSET
        authority.write_bytes(AUTHORITY)
        return authority

    def test_delayed_visibility_after_already_exists_refetches_and_compares(self) -> None:
        github = FakeGitHub(
            views=[
                [],
                RuntimeError("release metadata is temporarily unavailable"),
                [],
                [ASSET],
            ],
            downloads=[
                RuntimeError("asset download is not visible yet"),
                AUTHORITY,
            ],
            upload=RuntimeError("asset under the same name already exists"),
        )
        sleeps: list[float] = []
        with tempfile.TemporaryDirectory() as temporary:
            result = repair_asset(
                REPOSITORY,
                TAG,
                self.authority_file(Path(temporary)),
                ASSET,
                runner=github,
                retry_delays=(0, 0, 0),
                sleep=sleeps.append,
            )

        self.assertEqual("matched", result)
        self.assertEqual(4, github.call_count(("release", "view")))
        self.assertEqual(1, github.call_count(("release", "upload")))
        self.assertEqual(2, github.call_count(("release", "download")))
        self.assertEqual(3, len(sleeps))

    def test_already_existing_equal_content_is_accepted_without_upload(self) -> None:
        github = FakeGitHub(views=[[ASSET]], downloads=[AUTHORITY])
        with tempfile.TemporaryDirectory() as temporary:
            result = repair_asset(
                REPOSITORY,
                TAG,
                self.authority_file(Path(temporary)),
                ASSET,
                runner=github,
                retry_delays=(0, 0),
                sleep=lambda _delay: None,
            )

        self.assertEqual("matched", result)
        self.assertEqual(1, github.call_count(("release", "view")))
        self.assertEqual(1, github.call_count(("release", "download")))
        self.assertEqual(0, github.call_count(("release", "upload")))

    def test_conflicting_content_fails_immediately(self) -> None:
        github = FakeGitHub(
            views=[[], [ASSET]],
            downloads=[b'{"candidate":"different"}\n'],
            upload=RuntimeError("asset under the same name already exists"),
        )
        sleeps: list[float] = []
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(MirrorError, "differs from immutable Git authority"),
        ):
            repair_asset(
                REPOSITORY,
                TAG,
                self.authority_file(Path(temporary)),
                ASSET,
                runner=github,
                retry_delays=(0, 0, 0),
                sleep=sleeps.append,
            )

        self.assertEqual(1, github.call_count(("release", "download")))
        self.assertEqual(1, github.call_count(("release", "upload")))
        self.assertEqual([], sleeps)

    def test_transient_metadata_reads_stop_at_the_retry_bound(self) -> None:
        github = FakeGitHub(
            views=[
                RuntimeError("temporary read failure"),
                RuntimeError("temporary read failure"),
                RuntimeError("temporary read failure"),
            ]
        )
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(MirrorError, "cannot inspect release assets after 3 attempts"),
        ):
            repair_asset(
                REPOSITORY,
                TAG,
                self.authority_file(Path(temporary)),
                ASSET,
                runner=github,
                retry_delays=(0, 0),
                sleep=lambda _delay: None,
            )

        self.assertEqual(3, github.call_count(("release", "view")))
        self.assertEqual(0, github.call_count(("release", "upload")))

    def test_beta_candidate_recorder_uses_the_bounded_mirror_helper(self) -> None:
        workflow = yaml.safe_load(
            (REPOSITORY_ROOT / ".github" / "workflows" / "beta-candidate.yml").read_text(encoding="utf-8")
        )
        qualify = workflow["jobs"]["qualify"]
        record = workflow["jobs"]["record"]
        mirror = next(
            step for step in record["steps"] if step.get("name") == "Create or repair the durable GitHub Release mirror"
        )
        probe = next(
            step
            for step in record["steps"]
            if step.get("name") == "Exercise recorder-only recovery before any mutation"
        )

        self.assertEqual("qualify", record["needs"])
        self.assertLess(record["steps"].index(probe), record["steps"].index(mirror))
        self.assertNotIn(
            "release_asset_mirror.py",
            "\n".join(step.get("run", "") for step in qualify["steps"]),
        )
        self.assertEqual(2, mirror["run"].count("python scripts/release_asset_mirror.py repair"))
        self.assertIn('--repository "$GITHUB_REPOSITORY"', mirror["run"])
        self.assertNotIn("gh release download", mirror["run"])
        self.assertNotIn("gh release upload", mirror["run"])


if __name__ == "__main__":
    unittest.main()
