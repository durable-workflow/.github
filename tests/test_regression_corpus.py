from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts.regression_corpus import CorpusError, validate

ROOT = Path(__file__).resolve().parents[1]


def run(root: Path, *command: str) -> str:
    result = subprocess.run(
        command,
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout.strip()


def write_json(root: Path, path: str, value: object) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


def codec_fixture(identity: str, wire: object, version: str = "1") -> dict[str, object]:
    return {
        "$schema": "https://raw.githubusercontent.com/durable-workflow/.github/main/"
        "regression-corpus/evidence-schema.json",
        "fixture_schema": "durable-workflow.codec-regression/v1",
        "id": identity,
        "protocol": {
            "codec": "avro",
            "schema": "durable_workflow.protocol.Value",
            "version": version,
            "fingerprint": "e2a33dff55802237",
        },
        "bindings": ["php", "python", "rust"],
        "value": {"type": "long", "value": "0"},
        "framing": {
            "encoding": "avro-single-object",
            "wire_base64": wire,
        },
        "failure_policy": {
            "operation": "round_trip",
            "error": None,
        },
    }


def replay_fixture(identity: str) -> dict[str, object]:
    return {
        "$schema": "https://raw.githubusercontent.com/durable-workflow/.github/main/"
        "regression-corpus/evidence-schema.json",
        "fixture_schema": "durable-workflow.replay-regression/v1",
        "id": identity,
        "protocol_version": "1.13",
        "bindings": ["php"],
        "workflow": {"type": "fixture.workflow", "input": []},
        "history": [{"event_type": "ActivityCompleted", "payload": {"sequence": 1}}],
        "expected": {"command_sequence": [{"type": "complete_workflow"}]},
    }


def golden_history_fixture() -> dict[str, object]:
    replay = replay_fixture("golden-source")
    return {
        "fixture_schema": "durable-workflow.golden-history.v1",
        "source": {
            "runtime": "fixture-runtime",
            "version": "1.0.0",
            "worker_protocol_version": "1.0",
        },
        "cases": [
            {
                "name": "activity",
                "workflow_type": replay["workflow"]["type"],
                "start_input": replay["workflow"]["input"],
                "history": replay["history"],
                "expected": replay["expected"],
            }
        ],
    }


def avro_golden_fixture(
    malformed_wire: str = "AQ==",
    malformed_name: str = "bad_frame",
) -> dict[str, object]:
    return {
        "schema": "durable_workflow.protocol.Value",
        "fingerprint": "e2a33dff55802237",
        "cases": [
            {
                "name": "long_zero",
                "kind": "long",
                "value": "0",
                "wire_base64": "AA==",
            }
        ],
        "malformed_frames": [
            {
                "name": malformed_name,
                "error": "invalid_payload_framing",
                "wire_base64": malformed_wire,
            }
        ],
        "alternate_map_orders": [
            {
                "name": "map_order",
                "wire_base64": ["Ag==", "Aw=="],
            }
        ],
    }


def policy() -> dict[str, object]:
    return {
        "$schema": "https://raw.githubusercontent.com/durable-workflow/.github/main/"
        "regression-corpus/policy-schema.json",
        "schema": "durable-workflow.regression-corpus-policy/v1",
        "repository": "fixture",
        "binding": "php",
        "categories": {
            "codec": {
                "fixtures": [
                    {
                        "glob": "tests/fixtures/codec/*.json",
                        "format": "codec-regression-v1",
                    }
                ],
                "guards": [{"glob": "src/codec.py"}],
            },
            "replay": {
                "fixtures": [
                    {
                        "glob": "tests/fixtures/replay/*.json",
                        "format": "replay-regression-v1",
                    }
                ],
                "guards": [
                    {
                        "glob": "src/runtime.py",
                        "content_patterns": ["[Rr]eplay"],
                    }
                ],
            },
        },
    }


class RegressionCorpusTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        run(self.root, "git", "init", "-q")
        run(self.root, "git", "config", "user.email", "fixtures@example.com")
        run(self.root, "git", "config", "user.name", "Fixture Author")
        write_json(self.root, "regression-corpus-policy.json", policy())
        write_json(
            self.root,
            "tests/fixtures/codec/long-zero.json",
            codec_fixture("avro-value-v1-long-zero", "wwHioz3/VYAiNwQA"),
        )
        write_json(
            self.root,
            "tests/fixtures/replay/activity.json",
            replay_fixture("worker-v1-activity-completion"),
        )
        (self.root / "src").mkdir()
        (self.root / "src/codec.py").write_text("def encode(value):\n    return value\n", encoding="utf-8")
        (self.root / "src/runtime.py").write_text(
            "def replay(history):\n    return history\n",
            encoding="utf-8",
        )
        run(self.root, "git", "add", ".")
        run(self.root, "git", "commit", "-qm", "baseline")
        self.base = run(self.root, "git", "rev-parse", "HEAD")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_unrelated_change_may_keep_corpus_counts_equal(self) -> None:
        (self.root / "README.md").write_text("Editable prose.\n", encoding="utf-8")

        result = validate(self.root, Path("regression-corpus-policy.json"), self.base)

        self.assertFalse(result["counts"]["codec"]["related_change"])
        self.assertEqual(1, result["counts"]["codec"]["current"])
        self.assertEqual(1, result["counts"]["codec"]["base"])

    def test_codec_change_requires_real_corpus_growth_not_only_a_test(self) -> None:
        (self.root / "src/codec.py").write_text(
            "def encode(value):\n    return bytes(str(value), 'utf-8')\n",
            encoding="utf-8",
        )
        (self.root / "tests/test_codec.py").write_text(
            "def test_implementation_detail():\n    assert True\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(CorpusError, "codec implementation changed but its corpus did not grow"):
            validate(self.root, Path("regression-corpus-policy.json"), self.base)

    def test_related_change_passes_after_one_minimal_fixture_is_added(self) -> None:
        (self.root / "src/codec.py").write_text(
            "def encode(value):\n    return bytes(str(value), 'utf-8')\n",
            encoding="utf-8",
        )
        write_json(
            self.root,
            "tests/fixtures/codec/long-one.json",
            codec_fixture("avro-value-v1-long-one", "wwHioz3/VYAiNwQC"),
        )

        result = validate(self.root, Path("regression-corpus-policy.json"), self.base)

        self.assertTrue(result["counts"]["codec"]["related_change"])
        self.assertEqual(2, result["counts"]["codec"]["current"])

    def test_existing_fixture_is_immutable(self) -> None:
        fixture = codec_fixture("avro-value-v1-long-zero", "wwHioz3/VYAiNwQC")
        write_json(self.root, "tests/fixtures/codec/long-zero.json", fixture)

        with self.assertRaisesRegex(CorpusError, "immutable fixture .* was changed"):
            validate(self.root, Path("regression-corpus-policy.json"), self.base)

    def test_semantic_duplicate_is_rejected_even_with_another_id(self) -> None:
        write_json(
            self.root,
            "tests/fixtures/codec/copied.json",
            codec_fixture("renamed-copy", "wwHioz3/VYAiNwQA"),
        )

        with self.assertRaisesRegex(CorpusError, "duplicate semantic fixtures"):
            validate(self.root, Path("regression-corpus-policy.json"), self.base)

    def test_noncanonical_base64_wire_is_rejected(self) -> None:
        write_json(
            self.root,
            "tests/fixtures/codec/noncanonical.json",
            codec_fixture("noncanonical-wire", "AB=="),
        )

        with self.assertRaisesRegex(CorpusError, "is not canonical base64"):
            validate(self.root, Path("regression-corpus-policy.json"), self.base)

    def test_empty_base64_wire_is_accepted_by_schema_and_parser(self) -> None:
        fixture = codec_fixture("empty-wire", "")
        evidence_schema = json.loads((ROOT / "regression-corpus/evidence-schema.json").read_text())
        Draft202012Validator(evidence_schema).validate(fixture)
        write_json(
            self.root,
            "tests/fixtures/codec/empty-wire.json",
            fixture,
        )

        result = validate(self.root, Path("regression-corpus-policy.json"), self.base)

        self.assertEqual(2, result["counts"]["codec"]["current"])

    def test_required_null_wire_remains_rejected(self) -> None:
        write_json(
            self.root,
            "tests/fixtures/codec/null-wire.json",
            codec_fixture("null-wire", None),
        )

        with self.assertRaisesRegex(CorpusError, "must include wire_base64 for round_trip"):
            validate(self.root, Path("regression-corpus-policy.json"), self.base)

    def test_optional_null_wire_remains_accepted(self) -> None:
        fixture = codec_fixture("null-encode-rejection", None)
        fixture["failure_policy"] = {
            "operation": "encode_reject",
            "error": "unsupported_value",
        }
        write_json(
            self.root,
            "tests/fixtures/codec/null-encode-rejection.json",
            fixture,
        )

        result = validate(self.root, Path("regression-corpus-policy.json"), self.base)

        self.assertEqual(2, result["counts"]["codec"]["current"])

    def test_non_string_wire_remains_rejected(self) -> None:
        write_json(
            self.root,
            "tests/fixtures/codec/non-string-wire.json",
            codec_fixture("non-string-wire", []),
        )

        with self.assertRaisesRegex(CorpusError, "wire_base64 must be a string"):
            validate(self.root, Path("regression-corpus-policy.json"), self.base)

    def test_empty_avro_golden_rewrap_is_a_semantic_duplicate(self) -> None:
        expanded = policy()
        expanded["categories"]["codec"]["fixtures"].append(
            {
                "glob": "tests/fixtures/avro-golden.json",
                "format": "avro-value-golden-v1",
            }
        )
        write_json(self.root, "regression-corpus-policy.json", expanded)
        write_json(
            self.root,
            "tests/fixtures/avro-golden.json",
            avro_golden_fixture("", malformed_name="empty_blob"),
        )
        rewrapped = codec_fixture("empty-blob-rewrap", "")
        rewrapped["failure_policy"] = {
            "operation": "decode_reject",
            "error": "invalid_payload_framing",
        }
        write_json(
            self.root,
            "tests/fixtures/codec/empty-blob-rewrap.json",
            rewrapped,
        )

        with self.assertRaisesRegex(CorpusError, "duplicate semantic fixtures"):
            validate(self.root, Path("regression-corpus-policy.json"), self.base)

    def test_noncanonical_malformed_golden_wire_is_rejected(self) -> None:
        expanded = policy()
        expanded["categories"]["codec"]["fixtures"].append(
            {
                "glob": "tests/fixtures/avro-golden.json",
                "format": "avro-value-golden-v1",
            }
        )
        write_json(self.root, "regression-corpus-policy.json", expanded)
        write_json(
            self.root,
            "tests/fixtures/avro-golden.json",
            avro_golden_fixture("AR=="),
        )

        with self.assertRaisesRegex(CorpusError, "is not canonical base64"):
            validate(self.root, Path("regression-corpus-policy.json"), self.base)

    def test_malformed_wire_migration_rejects_different_decoded_bytes(self) -> None:
        expanded = policy()
        expanded["categories"]["codec"]["fixtures"].append(
            {
                "glob": "tests/fixtures/avro-golden.json",
                "format": "avro-value-golden-v1",
            }
        )
        write_json(self.root, "regression-corpus-policy.json", expanded)
        write_json(
            self.root,
            "tests/fixtures/avro-golden.json",
            avro_golden_fixture("AR=="),
        )
        run(self.root, "git", "add", ".")
        run(self.root, "git", "commit", "-qm", "legacy malformed wire")
        self.base = run(self.root, "git", "rev-parse", "HEAD")
        write_json(
            self.root,
            "tests/fixtures/avro-golden.json",
            avro_golden_fixture("Ag=="),
        )

        with self.assertRaisesRegex(CorpusError, "immutable fixture file"):
            validate(self.root, Path("regression-corpus-policy.json"), self.base)

    def test_malformed_wire_migration_accepts_same_decoded_bytes(self) -> None:
        expanded = policy()
        expanded["categories"]["codec"]["fixtures"].append(
            {
                "glob": "tests/fixtures/avro-golden.json",
                "format": "avro-value-golden-v1",
            }
        )
        write_json(self.root, "regression-corpus-policy.json", expanded)
        write_json(
            self.root,
            "tests/fixtures/avro-golden.json",
            avro_golden_fixture("AR=="),
        )
        run(self.root, "git", "add", ".")
        run(self.root, "git", "commit", "-qm", "legacy malformed wire")
        self.base = run(self.root, "git", "rev-parse", "HEAD")
        write_json(
            self.root,
            "tests/fixtures/avro-golden.json",
            avro_golden_fixture("AQ=="),
        )

        result = validate(self.root, Path("regression-corpus-policy.json"), self.base)

        self.assertEqual(
            result["counts"]["codec"]["base"],
            result["counts"]["codec"]["current"],
        )

    def test_malformed_wire_migration_accepts_explicit_legacy_repair(self) -> None:
        expanded = policy()
        expanded["categories"]["codec"]["fixtures"].append(
            {
                "glob": "tests/fixtures/avro-golden.json",
                "format": "avro-value-golden-v1",
            }
        )
        write_json(self.root, "regression-corpus-policy.json", expanded)
        write_json(
            self.root,
            "tests/fixtures/avro-golden.json",
            avro_golden_fixture("%%%"),
        )
        run(self.root, "git", "add", ".")
        run(self.root, "git", "commit", "-qm", "legacy malformed wire")
        self.base = run(self.root, "git", "rev-parse", "HEAD")
        write_json(
            self.root,
            "tests/fixtures/avro-golden.json",
            avro_golden_fixture("JSUl"),
        )

        result = validate(self.root, Path("regression-corpus-policy.json"), self.base)

        self.assertEqual(
            result["counts"]["codec"]["base"],
            result["counts"]["codec"]["current"],
        )

    def test_golden_history_rewrap_is_a_semantic_duplicate(self) -> None:
        expanded = policy()
        expanded["categories"]["replay"]["fixtures"].append(
            {
                "glob": "tests/fixtures/golden/*.json",
                "format": "golden-history-v1",
            }
        )
        write_json(self.root, "regression-corpus-policy.json", expanded)
        write_json(
            self.root,
            "tests/fixtures/golden/activity.json",
            golden_history_fixture(),
        )

        with self.assertRaisesRegex(CorpusError, "duplicate semantic fixtures"):
            validate(self.root, Path("regression-corpus-policy.json"), self.base)

    def test_golden_rewrap_cannot_repeat_nested_commands_as_new_evidence(self) -> None:
        expanded = policy()
        expanded["categories"]["replay"]["fixtures"].append(
            {
                "glob": "tests/fixtures/golden/*.json",
                "format": "golden-history-v1",
            }
        )
        write_json(self.root, "regression-corpus-policy.json", expanded)
        other_replay = replay_fixture("different-replay")
        other_replay["workflow"]["type"] = "fixture.other-workflow"
        write_json(
            self.root,
            "tests/fixtures/replay/activity.json",
            other_replay,
        )
        write_json(
            self.root,
            "tests/fixtures/golden/activity.json",
            golden_history_fixture(),
        )
        run(self.root, "git", "add", ".")
        run(self.root, "git", "commit", "-qm", "cross-format baseline")
        self.base = run(self.root, "git", "rev-parse", "HEAD")

        rewrapped = replay_fixture("redundant-command-rewrap")
        rewrapped["command_sequence"] = rewrapped["expected"]["command_sequence"]
        write_json(
            self.root,
            "tests/fixtures/replay/rewrapped.json",
            rewrapped,
        )

        with self.assertRaisesRegex(CorpusError, "duplicate semantic fixtures"):
            validate(self.root, Path("regression-corpus-policy.json"), self.base)

    def test_replay_change_passes_after_genuinely_new_behavior_is_added(self) -> None:
        (self.root / "src/runtime.py").write_text(
            "def replay_events(history):\n    return list(history)\n",
            encoding="utf-8",
        )
        fixture = replay_fixture("worker-v1-timer-completion")
        fixture["workflow"]["type"] = "fixture.timer-workflow"
        fixture["history"] = [{"event_type": "TimerFired", "payload": {"sequence": 1}}]
        fixture["expected"] = {"command_sequence": [{"type": "complete_workflow", "result": "timer-fired"}]}
        write_json(
            self.root,
            "tests/fixtures/replay/timer.json",
            fixture,
        )

        result = validate(self.root, Path("regression-corpus-policy.json"), self.base)

        self.assertTrue(result["counts"]["replay"]["related_change"])
        self.assertEqual(2, result["counts"]["replay"]["current"])

    def test_codec_schema_label_cannot_disguise_duplicate_behavior(self) -> None:
        (self.root / "src/codec.py").write_text(
            "def encode(value):\n    return bytes(str(value), 'utf-8')\n",
            encoding="utf-8",
        )
        fixture = codec_fixture("renamed-schema-copy", "wwHioz3/VYAiNwQA")
        fixture["protocol"]["schema"] = "metadata.only.Value"
        write_json(self.root, "tests/fixtures/codec/renamed-schema.json", fixture)

        with self.assertRaisesRegex(CorpusError, "duplicate semantic fixtures"):
            validate(self.root, Path("regression-corpus-policy.json"), self.base)

    def test_guard_selector_cannot_be_replaced_to_hide_codec_change(self) -> None:
        (self.root / "src/codec.py").write_text(
            "def encode(value):\n    return bytes(str(value), 'utf-8')\n",
            encoding="utf-8",
        )
        weakened = policy()
        weakened["categories"]["codec"]["guards"] = [{"glob": "src/not-codec.py"}]
        write_json(self.root, "regression-corpus-policy.json", weakened)

        with self.assertRaisesRegex(
            CorpusError,
            "categories.codec.guards cannot remove or change a base selector",
        ):
            validate(self.root, Path("regression-corpus-policy.json"), self.base)

    def test_protocol_supersession_appends_and_preserves_the_old_fixture(self) -> None:
        replacement = codec_fixture("avro-value-v2-long-zero", "wwHioz3/VYAiNwQE", version="2")
        replacement["supersedes"] = ["avro-value-v1-long-zero"]
        write_json(
            self.root,
            "tests/fixtures/codec/long-zero-v2.json",
            replacement,
        )

        result = validate(self.root, Path("regression-corpus-policy.json"), self.base)

        self.assertEqual(2, result["counts"]["codec"]["current"])
        self.assertTrue((self.root / "tests/fixtures/codec/long-zero.json").exists())

    def test_content_guard_ignores_unrelated_lines_in_a_shared_source_file(self) -> None:
        (self.root / "src/runtime.py").write_text(
            "def replay(history):\n    return history\n\nVERSION = '1.0'\n",
            encoding="utf-8",
        )

        result = validate(self.root, Path("regression-corpus-policy.json"), self.base)

        self.assertFalse(result["counts"]["replay"]["related_change"])

    def test_content_guard_requires_replay_growth_for_replay_lines(self) -> None:
        (self.root / "src/runtime.py").write_text(
            "def replay(replay_history):\n    return list(replay_history)\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(CorpusError, "replay implementation changed but its corpus did not grow"):
            validate(self.root, Path("regression-corpus-policy.json"), self.base)

    def test_published_schemas_accept_the_machine_owned_examples(self) -> None:
        policy_schema = json.loads((ROOT / "regression-corpus/policy-schema.json").read_text())
        evidence_schema = json.loads((ROOT / "regression-corpus/evidence-schema.json").read_text())
        Draft202012Validator.check_schema(policy_schema)
        Draft202012Validator.check_schema(evidence_schema)
        Draft202012Validator(policy_schema).validate(policy())
        Draft202012Validator(evidence_schema).validate(
            codec_fixture("avro-value-v1-long-zero", "wwHioz3/VYAiNwQA")
        )
        Draft202012Validator(evidence_schema).validate(replay_fixture("worker-v1-activity-completion"))
