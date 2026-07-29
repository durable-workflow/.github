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


def codec_fixture(identity: str, wire: str, version: str = "1") -> dict[str, object]:
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
