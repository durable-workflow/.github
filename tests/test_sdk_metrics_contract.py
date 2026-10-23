"""Keep the shared recorder API machine-readable and compatible for SDK tests."""

from __future__ import annotations

import json
import re
import unittest
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SdkMetricsContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = json.loads((ROOT / "sdk-metrics/contract.json").read_text(encoding="utf-8"))
        cls.metrics = cls.contract["metrics"]

    def test_contract_identity_and_reference_are_explicit(self) -> None:
        self.assertEqual("durable-workflow.sdk-metrics/v1", self.contract["schema"])
        self.assertIs(int, type(self.contract["revision"]))
        self.assertGreaterEqual(self.contract["revision"], 1)
        reference = self.contract["reference"]
        self.assertEqual("durable-workflow/sdk-python", reference["repository"])
        self.assertRegex(reference["commit"], r"^[a-f0-9]{40}$")
        self.assertEqual(
            {"src/durable_workflow/metrics.py", "src/durable_workflow/client.py", "src/durable_workflow/worker.py"},
            set(reference["paths"]),
        )

    def test_stable_names_remain_present_and_unique(self) -> None:
        names = [metric["name"] for metric in self.metrics]
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue({
            "durable_workflow_client_requests",
            "durable_workflow_client_request_duration_seconds",
            "durable_workflow_worker_polls",
            "durable_workflow_worker_poll_duration_seconds",
            "durable_workflow_worker_tasks",
            "durable_workflow_worker_task_duration_seconds",
        }.issubset(names))
        for name in names:
            with self.subTest(name=name):
                self.assertIsNotNone(re.fullmatch(r"durable_workflow_[a-z_]+", name))

    def test_instruments_keep_recorder_operation_and_units(self) -> None:
        expected_instruments = {"counter": ("increment", "1"), "histogram": ("record", "s")}
        for metric in self.metrics:
            with self.subTest(name=metric["name"]):
                expected_method, expected_unit = expected_instruments[metric["type"]]
                self.assertEqual(expected_method, metric["recorder_method"])
                self.assertEqual(expected_unit, metric["unit"])
                self.assertEqual(metric["type"] == "histogram", metric["name"].endswith("_seconds"))

    def test_counts_and_durations_share_exact_tag_keys(self) -> None:
        scopes = defaultdict(list)
        for metric in self.metrics:
            scopes[metric["scope"]].append(metric)
            self.assertEqual(len(metric["tags"]), len(set(metric["tags"])))
            self.assertTrue(all(isinstance(tag, str) and tag for tag in metric["tags"]))
        expected_tags = {
            "client_request": {"method", "route", "plane", "status_code", "outcome"},
            "worker_poll": {"task_kind", "task_queue", "outcome"},
            "worker_task": {"task_kind", "task_queue", "outcome"},
        }
        for scope, tags in expected_tags.items():
            with self.subTest(scope=scope):
                self.assertEqual(2, len(scopes[scope]))
                self.assertEqual({"counter", "histogram"}, {metric["type"] for metric in scopes[scope]})
                for metric in scopes[scope]:
                    self.assertEqual(tags, set(metric["tags"]))


if __name__ == "__main__":
    unittest.main()
