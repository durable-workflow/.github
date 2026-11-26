from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

from scripts.regression_corpus import CorpusError, _worker_replay_clock

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "conformance/replay-clock"
_SPEC = importlib.util.spec_from_file_location("replay_clock_run", CASE / "run.py")
assert _SPEC is not None
assert _SPEC.loader is not None
run = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(run)


def _micros(text: str) -> int:
    delta = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ") - datetime(1970, 1, 1)
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


class ReplayClockConformanceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.vectors = run.load_vectors()

    def observations(self, binding: str) -> dict[str, dict[str, object]]:
        return {case["id"]: run.expected_for(self.vectors, binding, case["id"]) for case in self.vectors["cases"]}

    def test_vectors_are_internally_consistent(self) -> None:
        ids = [case["id"] for case in self.vectors["cases"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(run.BINDINGS), set(self.vectors["requires_newer_than"]))
        run_id = self.vectors["workflow"]["run_id"]
        for case in self.vectors["cases"]:
            expected = case["expected"]
            self.assertTrue(expected["repeated_reads_equal"])
            self.assertEqual(
                _micros(expected["after_timer"]) - _micros(expected["after_activity"]),
                expected["elapsed_microseconds"],
            )
            carrier = case.get("replay_clock")
            if case["id"] == "carrier":
                # Only a carrier for this run whose source matches ordinary history is adopted.
                self.assertEqual(_worker_replay_clock(carrier, case["id"])["workflow_run_id"], run_id)
                self.assertEqual(carrier["started_at"].replace("Z", ""), expected["entry"].replace("Z", ""))
            else:
                self.assertIsNone(expected["entry"])
        for binding, overrides in self.vectors["binding_overrides"].items():
            self.assertIn(binding, run.BINDINGS)
            self.assertLessEqual(set(overrides) - {"_note"}, set(ids))

    def test_unproved_carriers_are_exactly_the_documented_refusals(self) -> None:
        cases = {case["id"]: case.get("replay_clock") for case in self.vectors["cases"]}
        with self.assertRaises(CorpusError):
            _worker_replay_clock(cases["carrier-low-precision"], "low-precision")
        self.assertNotEqual(self.vectors["workflow"]["run_id"], cases["carrier-for-another-run"]["workflow_run_id"])
        self.assertEqual(cases["redrive-source-on-ordinary-history"]["source"], "redrive_replayed_started_at")
        self.assertNotIn("no-carrier", {key for key, value in cases.items() if value is not None})

    def test_matching_observations_pass_and_every_drift_is_reported(self) -> None:
        for binding in run.BINDINGS:
            self.assertEqual([], run.compare(self.vectors, binding, self.observations(binding)))
        drifted = self.observations("python")
        drifted["carrier"]["entry"] = "2026-11-01T00:00:00.123456Z"
        mismatches = run.compare(self.vectors, "python", drifted)
        self.assertEqual(1, len(mismatches))
        self.assertIn("python/carrier/entry", mismatches[0])
        missing = self.observations("rust")
        del missing["no-carrier"]
        self.assertTrue(run.compare(self.vectors, "rust", missing))

    def test_embedded_keeps_the_started_event_time_only_where_documented(self) -> None:
        embedded = self.observations("embedded-worker-protocol")
        self.assertEqual("2026-11-01T00:00:00.000000Z", embedded["carrier"]["entry"])
        self.assertEqual(self.vectors["history"][0]["recorded_at"], embedded["no-carrier"]["entry"])
        self.assertTrue(run.compare(self.vectors, "python", embedded))

    def test_releases_without_the_carrier_are_not_yet_released(self) -> None:
        for binding, last in self.vectors["requires_newer_than"].items():
            self.assertFalse(run.released(self.vectors, binding, last))
            major, minor, patch = run.version_tuple(last)
            self.assertTrue(run.released(self.vectors, binding, f"{major}.{minor}.{patch + 1}"))
        for invalid in ("2.24", "v2.24.0", "2.24.0-rc1", "latest"):
            with self.assertRaises(ValueError):
                run.version_tuple(invalid)

    def test_vectors_file_is_canonical_json(self) -> None:
        text = (CASE / "vectors-v1.json").read_text(encoding="utf-8")
        self.assertEqual(json.dumps(json.loads(text), indent=2) + "\n", text)
        self.assertEqual(copy.deepcopy(self.vectors), json.loads(text))


class ReplayClockRunnerTest(unittest.TestCase):
    def setUp(self) -> None:
        self.vectors = run.load_vectors()
        self.work = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def test_containers_use_a_private_scratch_mount_not_a_shared_temporary_directory(self) -> None:
        completed = subprocess.CompletedProcess([], 0, stdout='{"observations": {}}\n', stderr="")
        with mock.patch.object(run.subprocess, "run", return_value=completed) as docker:
            run._run_binding("python", "9.9.9", None, self.work, prefix="test-prefix")
        command = docker.call_args.args[0]
        self.assertEqual(["docker", "run", "--rm", "--init"], command[:4])
        self.assertTrue(command[command.index("--name") + 1].startswith("test-prefix-python-"))
        scratch = command[command.index("--tmpfs") + 1]
        self.assertTrue(scratch.startswith("/scratch:"))
        self.assertIn("mode=0700", scratch)
        self.assertIn("HOME=/scratch", command)
        self.assertNotIn("/tmp", command[-1])

    def test_a_crashed_binding_is_recorded_as_an_error_and_the_run_continues(self) -> None:
        failed = subprocess.CompletedProcess([], 125, stdout="", stderr="no such image")
        garbage = subprocess.CompletedProcess([], 0, stdout="not json\n", stderr="")
        with mock.patch.object(run.subprocess, "run", side_effect=[failed, garbage]):
            crashed = run.evaluate(self.vectors, "python", "9.9.9", None, self.work)
            unparsable = run.evaluate(self.vectors, "python", "9.9.9", None, self.work)
        self.assertEqual("error", crashed["status"])
        self.assertIn("no such image", crashed["error"])
        self.assertEqual("error", unparsable["status"])

    def test_a_matching_report_passes_and_an_old_release_is_not_run(self) -> None:
        observations = {case["id"]: run.expected_for(self.vectors, "python", case["id"])
                        for case in self.vectors["cases"]}
        report = {"observations": observations, "sdk_version": "9.9.9"}
        with mock.patch.object(run, "_run_binding", return_value=report):
            self.assertEqual("pass", run.evaluate(self.vectors, "python", "9.9.9", None, self.work)["status"])
        with mock.patch.object(run, "_run_binding") as never:
            last = self.vectors["requires_newer_than"]["python"]
            result = run.evaluate(self.vectors, "python", last, None, self.work)
        never.assert_not_called()
        self.assertEqual("not_yet_released", result["status"])

    def test_selection_refuses_unknown_bindings_and_inexact_versions(self) -> None:
        with mock.patch.dict(run.os.environ, {"DW_PYTHON_SDK_VERSION": "latest"}), self.assertRaises(SystemExit):
            run._selected("python", {})
        with self.assertRaises(SystemExit):
            run._selected("go", {})
        with mock.patch.dict(run.os.environ, {"DW_PYTHON_SDK_VERSION": "9.9.9"}):
            self.assertEqual([("python", "9.9.9", None)], run._selected("python", {}))


if __name__ == "__main__":
    unittest.main()
