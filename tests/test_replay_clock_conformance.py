from __future__ import annotations

import copy
import importlib.util
import json
import unittest
from datetime import datetime
from pathlib import Path

from scripts.regression_corpus import CorpusError, _worker_replay_clock

ROOT = Path(__file__).resolve().parents[1]
CASE = ROOT / "conformance/replay-clock"
_SPEC = importlib.util.spec_from_file_location("replay_clock_run", CASE / "run.py")
assert _SPEC is not None and _SPEC.loader is not None
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
            self.assertTrue(set(overrides) - {"_note"} <= set(ids))

    def test_unproved_carriers_are_exactly_the_documented_refusals(self) -> None:
        cases = {case["id"]: case.get("replay_clock") for case in self.vectors["cases"]}
        with self.assertRaises(CorpusError):
            _worker_replay_clock(cases["carrier-low-precision"], "low-precision")
        self.assertNotEqual(cases["carrier-for-another-run"]["workflow_run_id"], self.vectors["workflow"]["run_id"])
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


if __name__ == "__main__":
    unittest.main()
