from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from scripts.visual_evidence import changed_paths, classify_changes, load_json, validate_manifest

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "visual-evidence" / "policy.json"
SCHEMA_PATH = ROOT / "visual-evidence" / "schema.json"


class VisualEvidencePolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = load_json(POLICY_PATH, "visual evidence policy")

    def test_policy_matches_its_schema(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_bytes())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(self.policy)

    def test_search_and_navigation_selectors_require_open_states(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stylesheet = root / "docs" / "layout.css"
            stylesheet.parent.mkdir()
            stylesheet.write_text(".md-search__overlay { width: 100vw; }\n", encoding="utf-8")
            template = root / "templates" / "shell.html"
            template.parent.mkdir()
            template.write_text('<button data-md-toggle="drawer">Menu</button>\n', encoding="utf-8")

            self.assertEqual(
                {
                    "navigation": ["templates/shell.html"],
                    "search": ["docs/layout.css"],
                },
                classify_changes(
                    root,
                    ["docs/layout.css", "templates/shell.html"],
                    self.policy,
                ),
            )

    def test_markdown_and_unrelated_styles_do_not_require_interaction_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "guide.md").write_text("Search the documentation.\n", encoding="utf-8")
            (root / "branding.css").write_text(".logo { color: blue; }\n", encoding="utf-8")
            self.assertEqual({}, classify_changes(root, ["guide.md", "branding.css"], self.policy))

    def test_removing_or_renaming_final_selectors_uses_base_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            stylesheet = root / "docs" / "layout.css"
            stylesheet.parent.mkdir()
            stylesheet.write_text(
                ".md-search__overlay { width: 100vw; }\n.md-nav__drawer { width: 20rem; }\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "docs/layout.css"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Visual Evidence Test",
                    "-c",
                    "user.email=visual-evidence@example.invalid",
                    "commit",
                    "-qm",
                    "baseline",
                ],
                cwd=root,
                check=True,
            )
            base_ref = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            stylesheet.write_text(
                ".docs-panel { width: 20rem; }\n",
                encoding="utf-8",
            )
            subprocess.run(["git", "add", "docs/layout.css"], cwd=root, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Visual Evidence Test",
                    "-c",
                    "user.email=visual-evidence@example.invalid",
                    "commit",
                    "-qm",
                    "rename selectors",
                ],
                cwd=root,
                check=True,
            )

            self.assertEqual(
                {
                    "navigation": ["docs/layout.css"],
                    "search": ["docs/layout.css"],
                },
                classify_changes(
                    root,
                    changed_paths(root, base_ref),
                    self.policy,
                    base_ref,
                ),
            )

    def capture(self, root: Path, interaction: str, state: str, width: int, selector: str) -> dict[str, Any]:
        name = f"{interaction}-{width}"
        screenshot = root / f"{name}.png"
        report = root / f"{name}.json"
        screenshot.write_bytes(b"png")
        viewport = {"width": width, "height": 900}
        interactions = [{"type": "click", "selector": selector}]
        report.write_text(
            json.dumps(
                {
                    "schema": "durable-workflow.pipeline.visual-capture/v1",
                    "surface": "docs",
                    "state": state,
                    "viewport": viewport,
                    "interactions": interactions,
                    "page_status": 200,
                    "geometry": {"horizontal_overflow": False},
                }
            ),
            encoding="utf-8",
        )
        return {
            "surface": "docs",
            "state": state,
            "viewport": viewport,
            "interactions": interactions,
            "page_status": 200,
            "screenshot": screenshot.name,
            "report": report.name,
        }

    def write_manifest(self, root: Path, captures: list[dict[str, Any]]) -> Path:
        manifest = root / "manifest.json"
        manifest.write_text(
            json.dumps({"schema": "durable-workflow.pipeline.visual-review/v1", "captures": captures}),
            encoding="utf-8",
        )
        return manifest

    def test_default_captures_do_not_satisfy_search_open_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = self.write_manifest(
                root,
                [self.capture(root, "search", "default", 390, ".md-header__button")],
            )
            failures = validate_manifest(manifest, {"search": ["docs/layout.css"]}, self.policy)
            self.assertEqual(3, len(failures))
            self.assertTrue(all("search-open" in failure for failure in failures))

    def test_every_viewport_requires_a_meaningful_open_interaction(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            captures = [
                self.capture(root, "search", "search-open", width, ".md-header__button[for='__search']")
                for width in (1440, 768, 390)
            ]
            captures.extend(
                self.capture(root, "navigation", "navigation-open", width, ".md-header__button[for='__drawer']")
                for width in (1440, 768, 390)
            )
            manifest = self.write_manifest(root, captures)
            self.assertEqual(
                [],
                validate_manifest(
                    manifest,
                    {
                        "navigation": ["templates/shell.html"],
                        "search": ["docs/layout.css"],
                    },
                    self.policy,
                ),
            )

            captures[2] = self.capture(root, "search", "search-open", 390, ".unrelated-control")
            manifest = self.write_manifest(root, captures)
            failures = validate_manifest(manifest, {"search": ["docs/layout.css"]}, self.policy)
            self.assertEqual(1, len(failures))
            self.assertIn("mobile viewport", failures[0])


if __name__ == "__main__":
    unittest.main()
