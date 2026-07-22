from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts.beta_candidate import COMPONENTS, CandidateError
from scripts.product_train import load_product_train, require_current_product_train

ROOT = Path(__file__).resolve().parents[1]


class ProductTrainTest(unittest.TestCase):
    def test_current_authority_matches_schema_and_one_supported_tuple(self) -> None:
        schema = json.loads((ROOT / "product-train" / "schema.json").read_text(encoding="utf-8"))
        contract = load_product_train()
        Draft202012Validator(schema).validate(contract)

        current = contract["current"]
        self.assertEqual("2.0.0-beta.3", current)
        supported = [
            name for name, train in contract["trains"].items() if train["status"] == "supported"
        ]
        self.assertEqual([current], supported)
        self.assertEqual({name: current for name in COMPONENTS}, contract["trains"][current]["versions"])
        self.assertEqual("2.0.0b3", contract["trains"][current]["registry_versions"]["sdk-python"])

    def test_new_beta_tuple_must_match_current_train(self) -> None:
        components = {name: {"version": "2.0.0-beta.3", "commit": "a" * 40} for name in COMPONENTS}
        self.assertEqual("2.0.0-beta.3", require_current_product_train(components))

        components["cli"]["version"] = "0.1.95"
        with self.assertRaisesRegex(CandidateError, "supported product train 2.0.0-beta.3"):
            require_current_product_train(components)
