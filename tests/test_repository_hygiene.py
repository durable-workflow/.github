from __future__ import annotations

import json
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
INVENTORY_PATH = ROOT / "repository-hygiene" / "inventory.json"
SCHEMA_PATH = ROOT / "repository-hygiene" / "inventory-schema.json"


class RepositoryHygieneInventoryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.inventory = json.loads(INVENTORY_PATH.read_bytes())
        self.schema = json.loads(SCHEMA_PATH.read_bytes())

    def test_inventory_matches_its_published_schema(self) -> None:
        Draft202012Validator.check_schema(self.schema)
        Draft202012Validator(self.schema).validate(self.inventory)

    def test_inventory_covers_the_public_repository_authority(self) -> None:
        policy = json.loads((ROOT / "issue-authority" / "policy.json").read_bytes())
        repositories = self.inventory["repositories"]

        self.assertEqual(policy["repositories"], [entry["repository"] for entry in repositories])
        self.assertEqual(
            {
                ".github": "main",
                "workflow": "v2",
                "waterline": "v2",
                "server": "main",
                "cli": "main",
                "ai": "main",
                "sample-app": "main",
                "sdk-php": "main",
                "sdk-python": "main",
                "sdk-rust": "main",
                "durable-workflow.github.io": "main",
            },
            {entry["repository"]: entry["branch"] for entry in repositories},
        )

    def test_inventory_uses_the_published_schema_identity(self) -> None:
        self.assertEqual("./inventory-schema.json", self.inventory["$schema"])
        self.assertEqual(
            self.schema["properties"]["schema"]["const"],
            self.inventory["schema"],
        )
        self.assertEqual(
            self.schema["properties"]["organization"]["const"],
            self.inventory["organization"],
        )
        self.assertEqual("2.0.0-beta.17", self.inventory["cleanup_release_train"])

    def test_cleaned_and_retired_repositories_record_removals(self) -> None:
        for entry in self.inventory["repositories"]:
            if entry["disposition"] in {"cleaned", "retired-bootstrap"}:
                self.assertTrue(entry["removals"], entry["repository"])
            self.assertEqual(len(entry["removals"]), len(set(entry["removals"])))
            self.assertEqual(len(entry["retained_surfaces"]), len(set(entry["retained_surfaces"])))


if __name__ == "__main__":
    unittest.main()
