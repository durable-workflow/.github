from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def proof() -> dict[str, object]:
    return {
        "$schema": "https://raw.githubusercontent.com/durable-workflow/.github/main/"
        "regression-corpus/server-codec-counterfactual-schema.json",
        "proof_schema": "durable-workflow.server-codec-counterfactual/v1",
        "fixture": "tests/Fixtures/CodecRegression/json-tagged-payload-codec-rejected.json",
        "test": "tests/Feature/CodecRegression/JsonTaggedPayloadCodecRejectedTest.php",
        "boundaries": [
            "app/Http/Controllers/Api/WorkflowController.php",
            "app/Support/WorkflowStartService.php",
        ],
    }


class ServerCodecCounterfactualSchemaTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = json.loads(
            (
                ROOT / "regression-corpus/server-codec-counterfactual-schema.json"
            ).read_text(encoding="utf-8")
        )
        Draft202012Validator.check_schema(cls.schema)
        cls.validator = Draft202012Validator(cls.schema)

    def test_one_proof_can_name_multiple_boundaries(self) -> None:
        self.assertTrue(self.validator.is_valid(proof()))

    def test_boundaries_are_required_unique_guarded_source_paths(self) -> None:
        invalid_documents: list[dict[str, object]] = []

        empty = copy.deepcopy(proof())
        empty["boundaries"] = []
        invalid_documents.append(empty)

        duplicate = copy.deepcopy(proof())
        duplicate["boundaries"] = [
            "app/Support/WorkflowStartService.php",
            "app/Support/WorkflowStartService.php",
        ]
        invalid_documents.append(duplicate)

        unguarded = copy.deepcopy(proof())
        unguarded["boundaries"] = ["routes/api.php"]
        invalid_documents.append(unguarded)

        for document in invalid_documents:
            with self.subTest(document=document):
                self.assertFalse(self.validator.is_valid(document))


if __name__ == "__main__":
    unittest.main()
