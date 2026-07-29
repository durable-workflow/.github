from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

from scripts.beta_candidate import COMPONENTS, CandidateError
from scripts.product_train import load_product_train
from scripts.release_plan import (
    RELEASE_CANDIDATE_SOURCE_PREPARATION_PATH,
    load_plan,
    load_source_preparation,
    require_current_source_preparation,
    require_prepared_note_sources,
    validate_source_preparation,
)

ROOT = Path(__file__).resolve().parents[1]


class ReleaseSourcePreparationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.preparation = load_source_preparation()

    def test_current_source_preparation_matches_schema_and_product_train(self) -> None:
        schema = json.loads((ROOT / "release-plans" / "source-preparation-schema.json").read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self.preparation)

        product_train = load_product_train()
        self.assertEqual(product_train["current"], self.preparation["train"])
        self.assertEqual(list(COMPONENTS), list(self.preparation["components"]))
        self.assertEqual(
            product_train["trains"][product_train["current"]]["versions"],
            {name: identity["version"] for name, identity in self.preparation["components"].items()},
        )

    def test_current_plan_must_match_the_exact_prepared_sources(self) -> None:
        plan = load_plan(ROOT / "release-plans" / "current.json")
        self.assertEqual(self.preparation, require_current_source_preparation(plan))

        plan["components"]["server"]["commit"] = "e" * 40
        with self.assertRaisesRegex(CandidateError, "exact prepared seven-component source tuple"):
            require_current_source_preparation(plan)

    def test_first_release_candidate_matches_its_prepared_sources_and_schema(self) -> None:
        preparation = load_source_preparation(RELEASE_CANDIDATE_SOURCE_PREPARATION_PATH)
        plan = load_plan(ROOT / "release-plans" / "first-release-candidate.json")
        schema = json.loads((ROOT / "release-plans" / "source-preparation-schema.json").read_text(encoding="utf-8"))

        Draft202012Validator(schema).validate(preparation)
        self.assertEqual("rc", preparation["channel"])
        self.assertEqual("2.0.0-rc.1", preparation["train"])
        self.assertEqual(
            {
                "cli": "2.0.0-rc.1",
                "sdk-php": "2.0.0-rc.1",
                "sdk-python": "2.0.0-rc.1",
                "sdk-rust": "2.0.0-rc.1",
                "server": "2.0.0-rc.2",
                "waterline": "2.0.0-rc.1",
                "workflow": "2.0.0-rc.1",
            },
            {name: identity["version"] for name, identity in preparation["components"].items()},
        )
        self.assertEqual(preparation, require_current_source_preparation(plan))
        self.assertEqual(
            plan["components"],
            {
                name: {"version": identity["version"], "commit": identity["commit"]}
                for name, identity in preparation["components"].items()
            },
        )

        changed = copy.deepcopy(preparation)
        changed["components"]["cli"]["version"] = "2.0.0-beta.21"
        with self.assertRaisesRegex(CandidateError, "component cli has an invalid identity"):
            validate_source_preparation(changed)

    def test_prepared_note_digests_are_release_preflight_authority(self) -> None:
        release_preparation = {
            "components": {
                name: {
                    "release_notes": {
                        "source": {
                            "kind": identity["release_notes"]["kind"],
                            "sha256": identity["release_notes"]["sha256"],
                        }
                    }
                }
                for name, identity in self.preparation["components"].items()
            }
        }
        require_prepared_note_sources(self.preparation, release_preparation)

        changed = copy.deepcopy(release_preparation)
        changed["components"]["sdk-python"]["release_notes"]["source"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(CandidateError, "sdk-python release notes differ"):
            require_prepared_note_sources(self.preparation, changed)

    def test_source_preparation_rejects_an_unprotected_authorization_state(self) -> None:
        changed = copy.deepcopy(self.preparation)
        changed["authorization"]["state"] = "authorized"
        with self.assertRaisesRegex(CandidateError, "protected authorization boundary"):
            validate_source_preparation(changed)


if __name__ == "__main__":
    unittest.main()
