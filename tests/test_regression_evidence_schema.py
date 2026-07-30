from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = ROOT / "tests/fixtures/regression-corpus"


def successful_replay_fixture() -> dict[str, object]:
    return {
        "$schema": "https://raw.githubusercontent.com/durable-workflow/.github/main/"
        "regression-corpus/evidence-schema.json",
        "fixture_schema": "durable-workflow.replay-regression/v1",
        "id": "representative-successful-replay",
        "protocol_version": "1.0",
        "bindings": ["php"],
        "workflow": {
            "type": "Tests\\Fixtures\\V2\\TestGoldenReplayWorkflow",
            "arguments": ["single-activity"],
            "payload_codec": "json",
        },
        "history": [
            {
                "sequence": 1,
                "event_type": "WorkflowStarted",
                "payload": {},
            }
        ],
        "expected": {
            "completed": True,
            "result": None,
            "commands": [{"type": "complete_workflow"}],
        },
    }


def checked_in_fixture(name: str) -> dict[str, object]:
    return json.loads((FIXTURE_ROOT / name).read_text(encoding="utf-8"))


class ReplayEvidenceSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(
            (ROOT / "regression-corpus/evidence-schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def assertValid(self, instance: object) -> None:
        errors = sorted(self.validator.iter_errors(instance), key=lambda error: list(error.path))
        self.assertEqual([], errors, "\n".join(error.message for error in errors))

    def assertInvalid(self, instance: object) -> None:
        self.assertFalse(self.validator.is_valid(instance))

    def test_success_failure_and_embedded_consumer_fixtures_validate(self) -> None:
        fixtures = {
            "successful replay": successful_replay_fixture(),
            "Workflow failure replay": checked_in_fixture(
                "workflow-fiber-malformed-service-response.json"
            ),
            "embedded consumer replay": checked_in_fixture(
                "embedded-malformed-service-response.json"
            ),
        }

        for name, fixture in fixtures.items():
            with self.subTest(name=name):
                self.assertValid(fixture)

    def test_replay_requires_exactly_one_outcome_form(self) -> None:
        failure = checked_in_fixture("workflow-fiber-malformed-service-response.json")
        both = copy.deepcopy(failure)
        both["expected"] = {"completed": False}
        neither = copy.deepcopy(failure)
        del neither["expected_failure"]
        both_with_command_only = copy.deepcopy(both)
        both_with_command_only["command_sequence"] = [{"completed": False}]
        del both_with_command_only["history"]
        failure_without_history = copy.deepcopy(failure)
        failure_without_history["command_sequence"] = [{"completed": False}]
        del failure_without_history["history"]
        failure_with_both_inputs = copy.deepcopy(failure)
        failure_with_both_inputs["command_sequence"] = [{"completed": False}]

        invalid_outcomes = {
            "both": both,
            "both with command input only": both_with_command_only,
            "neither": neither,
            "failure without history": failure_without_history,
            "failure with history and command inputs": failure_with_both_inputs,
        }
        for name, fixture in invalid_outcomes.items():
            with self.subTest(name=name):
                self.assertInvalid(fixture)

    def test_expected_failure_has_the_supported_machine_shape(self) -> None:
        fixture = checked_in_fixture("workflow-fiber-malformed-service-response.json")
        invalid_failures = {
            "missing exception": {"type": "malformed_service_response_envelope"},
            "unknown failure type": {
                "type": "unknown_failure",
                "exception": "Workflow\\Serializers\\CodecDecodeException",
            },
            "empty exception": {
                "type": "malformed_service_response_envelope",
                "exception": "",
            },
            "unknown field": {
                "type": "malformed_service_response_envelope",
                "exception": "Workflow\\Serializers\\CodecDecodeException",
                "message": "diagnostic-only",
            },
        }

        for name, expected_failure in invalid_failures.items():
            with self.subTest(name=name):
                invalid = copy.deepcopy(fixture)
                invalid["expected_failure"] = expected_failure
                self.assertInvalid(invalid)

    def test_consumer_declarations_are_nonempty_unique_and_supported(self) -> None:
        fixture = checked_in_fixture("embedded-malformed-service-response.json")
        invalid_consumers = {
            "empty": [],
            "duplicate": ["workflow-fiber-runner", "workflow-fiber-runner"],
            "unknown": ["workflow-fiber-runner", "mutable-remote-validator"],
            "not an array": "workflow-fiber-runner",
        }

        for name, consumers in invalid_consumers.items():
            with self.subTest(name=name):
                invalid = copy.deepcopy(fixture)
                invalid["consumers"] = consumers
                self.assertInvalid(invalid)

    def test_unknown_top_level_replay_fields_are_rejected(self) -> None:
        fixture = successful_replay_fixture()
        fixture["consumer_options"] = {}

        self.assertInvalid(fixture)


if __name__ == "__main__":
    unittest.main()
