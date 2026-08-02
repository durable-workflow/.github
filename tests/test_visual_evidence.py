from __future__ import annotations

import json
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from typing import Any

import yaml
from jsonschema import Draft202012Validator

from scripts.visual_evidence import (
    VisualEvidenceError,
    changed_paths,
    classify_changes,
    load_json,
    validate_manifest,
    validate_report,
)

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

    def test_source_qualification_pins_an_isolated_browser_runtime(self) -> None:
        package = json.loads((ROOT / "package.json").read_bytes())
        lock = json.loads((ROOT / "package-lock.json").read_bytes())
        self.assertEqual("140.0.0", package["dependencies"]["@sparticuz/chromium"])
        self.assertEqual("1.55.0", package["dependencies"]["playwright-core"])
        for dependency, expected_version in (
            ("@sparticuz/chromium", "140.0.0"),
            ("playwright-core", "1.55.0"),
        ):
            locked = lock["packages"][f"node_modules/{dependency}"]
            self.assertEqual(expected_version, locked["version"])
            self.assertTrue(locked["integrity"].startswith("sha512-"))

        workflow = yaml.safe_load((ROOT / ".github/workflows/source-qualification.yml").read_bytes())
        self.assertEqual({"contents": "read"}, workflow["permissions"])
        steps = workflow["jobs"]["source"]["steps"]
        setup_node = next(step for step in steps if str(step.get("uses", "")).startswith("actions/setup-node@"))
        self.assertNotIn("cache", setup_node.get("with", {}))
        visual_capture = next(step for step in steps if step.get("name") == "Validate visual capture")
        self.assertEqual(
            "${{ runner.temp }}/visual-chromium-${{ github.run_id }}-${{ github.run_attempt }}",
            visual_capture["env"]["TMPDIR"],
        )
        self.assertIn("npm run test:visual-capture", visual_capture["run"])
        for step in steps:
            if "actions/upload-artifact@" not in str(step.get("uses", "")):
                continue
            self.assertIn("github.event_name != 'pull_request'", step["if"])

    def test_rust_reusable_workflow_captures_and_retains_the_exact_candidate_matrix(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github/workflows/rust-docs-visual.yml").read_bytes())
        self.assertEqual({"contents": "read"}, workflow["permissions"])
        job = workflow["jobs"]["visual-evidence"]
        steps = job["steps"]
        candidate_checkout = next(step for step in steps if step.get("name") == "Check out candidate source")
        self.assertEqual("${{ github.sha }}", candidate_checkout["with"]["ref"])
        self.assertEqual("${{ github.repository }}", candidate_checkout["with"]["repository"])

        classify = next(step for step in steps if step.get("name") == "Classify candidate changes")
        self.assertIn("--profile rust-sdk-reference", classify["run"])
        capture = next(step for step in steps if step.get("name") == "Capture candidate state matrix")
        for viewport in ("1440x900", "800x900", "390x844"):
            self.assertIn(viewport, capture["run"])
        for state in ("initial", "granted", "denied", "preferences-open"):
            self.assertIn(f"capture {state}", capture["run"])
        self.assertIn("--source-revision \"$SOURCE_REVISION\"", capture["run"])

        validate = next(step for step in steps if step.get("name") == "Validate source-bound candidate evidence")
        self.assertIn("--expected-revision \"$SOURCE_REVISION\"", validate["run"])
        retention = next(step for step in steps if step.get("name") == "Retain candidate visual evidence")
        self.assertIn("steps.classify.outputs.required == 'true'", retention["if"])

    def test_rust_capture_loads_the_classified_root_entry_route(self) -> None:
        workflow = yaml.safe_load((ROOT / ".github/workflows/rust-docs-visual.yml").read_bytes())
        steps = workflow["jobs"]["visual-evidence"]["steps"]
        build = next(step for step in steps if step.get("name") == "Build candidate API reference")
        capture = next(step for step in steps if step.get("name") == "Capture candidate state matrix")

        self.assertIn("cp docs/index.html target/doc/index.html", build["run"])
        self.assertEqual(
            ["candidate/target/doc"],
            re.findall(
                r"(?m)^\s*python3 -m http\.server\b[^\n]*"
                r"--directory\s+([^\s\\]+)",
                capture["run"],
            ),
        )
        self.assertEqual(
            ["http://127.0.0.1:4173/", "http://127.0.0.1:4173/"],
            re.findall(r'http://127\.0\.0\.1:4173/[^\s"\\]*', capture["run"]),
        )

    def test_merge_gate_and_audit_review_screenshots_with_unreachable_control_geometry(self) -> None:
        for reviewer in ("merge_gate", "audit"):
            contract = self.policy["review_contract"][reviewer]
            self.assertTrue(contract["correlate_with_screenshot"])
            self.assertIn("geometry.unreachable_controls", contract["inspect_report_fields"])

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

    def test_rust_reference_profile_classifies_only_browser_rendering_inputs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [
                "docs/analytics/analytics.css",
                "docs/analytics/analytics.js",
                "docs/analytics-head.html",
                "docs/index.html",
                "src/lib.rs",
                "README.md",
            ]
            for path in paths:
                candidate = root / path
                candidate.parent.mkdir(parents=True, exist_ok=True)
                candidate.write_text("candidate\n", encoding="utf-8")

            self.assertEqual(
                {
                    "rust-sdk-analytics": [
                        "docs/analytics-head.html",
                        "docs/analytics/analytics.css",
                        "docs/analytics/analytics.js",
                    ],
                    "rust-sdk-reference": [
                        "docs/analytics-head.html",
                        "docs/analytics/analytics.css",
                        "docs/analytics/analytics.js",
                        "docs/index.html",
                    ],
                },
                classify_changes(root, paths, self.policy, profile_name="rust-sdk-reference"),
            )

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
                    "geometry": {
                        "horizontal_overflow": False,
                        "clipped_text": [],
                        "clipped_control_text": [],
                        "oversized_choice_controls": [],
                        "unreachable_controls": [],
                    },
                    "console_errors": [],
                    "http_errors": [],
                    "page_errors": [],
                    "request_failures": [],
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

    def test_admission_rejects_unreachable_controls(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = self.capture(root, "search", "search-open", 390, ".search")
            report_path = root / capture["report"]
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["geometry"]["unreachable_controls"] = [
                {
                    "tag": "input",
                    "name": "organization_website",
                    "reachable_area_ratio": 0.2,
                }
            ]
            report_path.write_text(json.dumps(report), encoding="utf-8")

            failures = validate_report(root / "manifest.json", capture, self.policy)
            self.assertEqual(1, len(failures))
            self.assertIn("non-empty unreachable_controls", failures[0])

    def test_admission_requires_all_capture_health_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = self.capture(root, "search", "search-open", 390, ".search")
            report_path = root / capture["report"]
            report = json.loads(report_path.read_text(encoding="utf-8"))
            del report["geometry"]["unreachable_controls"]
            report_path.write_text(json.dumps(report), encoding="utf-8")

            failures = validate_report(root / "manifest.json", capture, self.policy)
            self.assertEqual(1, len(failures))
            self.assertIn("missing the unreachable_controls findings list", failures[0])

    def test_admission_preserves_clipping_console_and_control_size_checks(self) -> None:
        cases = (
            ("geometry", "clipped_text"),
            ("geometry", "clipped_control_text"),
            ("geometry", "oversized_choice_controls"),
            ("report", "console_errors"),
            ("report", "http_errors"),
            ("report", "page_errors"),
            ("report", "request_failures"),
        )
        for location, field in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                capture = self.capture(root, "search", "search-open", 390, ".search")
                report_path = root / capture["report"]
                report = json.loads(report_path.read_text(encoding="utf-8"))
                target = report["geometry"] if location == "geometry" else report
                target[field] = [{"finding": field}]
                report_path.write_text(json.dumps(report), encoding="utf-8")

                failures = validate_report(root / "manifest.json", capture, self.policy)
                self.assertEqual(1, len(failures))
                self.assertIn(f"non-empty {field}", failures[0])

    def test_admission_preserves_horizontal_overflow_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = self.capture(root, "search", "search-open", 390, ".search")
            report_path = root / capture["report"]
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["geometry"]["horizontal_overflow"] = True
            report_path.write_text(json.dumps(report), encoding="utf-8")

            failures = validate_report(root / "manifest.json", capture, self.policy)
            self.assertEqual(1, len(failures))
            self.assertIn("horizontal_overflow", failures[0])

    def test_admission_checks_a_supplied_manifest_without_interaction_classification(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            capture = self.capture(root, "default", "default", 1440, "#action")
            report_path = root / capture["report"]
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["geometry"]["unreachable_controls"] = [{"tag": "button"}]
            report_path.write_text(json.dumps(report), encoding="utf-8")
            manifest = self.write_manifest(root, [capture])

            failures = validate_manifest(manifest, {}, self.policy)
            self.assertEqual(1, len(failures))
            self.assertIn("non-empty unreachable_controls", failures[0])

    def write_manifest(self, root: Path, captures: list[dict[str, Any]]) -> Path:
        manifest = root / "manifest.json"
        manifest.write_text(
            json.dumps({"schema": "durable-workflow.pipeline.visual-review/v1", "captures": captures}),
            encoding="utf-8",
        )
        return manifest

    def rust_capture(
        self,
        root: Path,
        state: str,
        width: int,
        height: int,
        source: dict[str, str],
        selectors: list[str] | None = None,
    ) -> dict[str, Any]:
        name = f"rust-{state}-{width}x{height}"
        screenshot = root / f"{name}.png"
        report_path = root / f"{name}.json"
        screenshot.write_bytes(b"png")
        viewport = {"width": width, "height": height}
        interactions = [{"type": "click", "selector": selector} for selector in selectors or []]
        report = {
            "schema": "durable-workflow.pipeline.visual-capture/v1",
            "surface": "rust-sdk-reference",
            "state": state,
            "viewport": viewport,
            "interactions": interactions,
            "source": source,
            "page_status": 200,
            "geometry": {
                "horizontal_overflow": False,
                "clipped_text": [],
                "clipped_control_text": [],
                "oversized_choice_controls": [],
                "unreachable_controls": [],
            },
            "console_errors": [],
            "http_errors": [],
            "page_errors": [],
            "request_failures": [],
        }
        report_path.write_text(json.dumps(report), encoding="utf-8")
        return {
            "surface": report["surface"],
            "state": state,
            "viewport": viewport,
            "interactions": interactions,
            "source": source,
            "page_status": 200,
            "screenshot": screenshot.name,
            "report": report_path.name,
        }

    def rust_matrix(self, root: Path, source: dict[str, str]) -> list[dict[str, Any]]:
        captures = []
        selectors = {
            "initial": [],
            "granted": ['[data-consent="granted"]'],
            "denied": ['[data-consent="denied"]'],
            "preferences-open": [
                '[data-consent="denied"]',
                "#durable-workflow-analytics-preferences",
            ],
        }
        for width, height in ((1440, 900), (800, 900), (390, 844)):
            for state, clicks in selectors.items():
                captures.append(self.rust_capture(root, state, width, height, source, clicks))
        return captures

    def rust_manifest(
        self,
        root: Path,
        captures: list[dict[str, Any]],
        source: dict[str, str],
    ) -> Path:
        manifest = root / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "schema": "durable-workflow.pipeline.visual-review/v1",
                    "source": source,
                    "captures": captures,
                }
            ),
            encoding="utf-8",
        )
        return manifest

    def test_rust_fixed_control_regression_requires_clean_rendered_candidate_evidence(self) -> None:
        revision = "a" * 40
        source = {"repository": "durable-workflow/sdk-rust", "revision": revision}
        classification = {
            "rust-sdk-analytics": ["docs/analytics/analytics.css"],
            "rust-sdk-reference": ["docs/analytics/analytics.css"],
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaises(VisualEvidenceError):
                validate_manifest(
                    root / "missing.json",
                    classification,
                    self.policy,
                    "rust-sdk-reference",
                    revision,
                )

            captures = self.rust_matrix(root, source)
            obstructed = captures[0]
            report_path = root / obstructed["report"]
            report = json.loads(report_path.read_text(encoding="utf-8"))
            report["geometry"]["unreachable_controls"] = [
                {
                    "tag": "a",
                    "name": "Modules",
                    "blockers": [{"position": "fixed", "tag": "aside"}],
                }
            ]
            report_path.write_text(json.dumps(report), encoding="utf-8")
            manifest = self.rust_manifest(root, captures, source)
            failures = validate_manifest(
                manifest,
                classification,
                self.policy,
                "rust-sdk-reference",
                revision,
            )
            self.assertTrue(any("non-empty unreachable_controls" in failure for failure in failures))

            report["geometry"]["unreachable_controls"] = []
            report_path.write_text(json.dumps(report), encoding="utf-8")
            self.assertEqual(
                [],
                validate_manifest(
                    manifest,
                    classification,
                    self.policy,
                    "rust-sdk-reference",
                    revision,
                ),
            )

            incomplete = [
                capture
                for capture in captures
                if not (
                    capture["state"] == "preferences-open"
                    and capture["viewport"] == {"width": 800, "height": 900}
                )
            ]
            manifest = self.rust_manifest(root, incomplete, source)
            failures = validate_manifest(
                manifest,
                classification,
                self.policy,
                "rust-sdk-reference",
                revision,
            )
            self.assertTrue(
                any(
                    "preferences-open" in failure and "exact intermediate viewport" in failure
                    for failure in failures
                )
            )

    def test_rust_profile_rejects_stale_wrong_source_and_wrong_viewport_evidence(self) -> None:
        revision = "b" * 40
        source = {"repository": "durable-workflow/sdk-rust", "revision": revision}
        classification = {"rust-sdk-reference": ["docs/index.html"]}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            captures = self.rust_matrix(root, source)
            manifest = self.rust_manifest(root, captures, source)
            self.assertEqual(
                [],
                validate_manifest(
                    manifest,
                    classification,
                    self.policy,
                    "rust-sdk-reference",
                    revision,
                ),
            )

            failures = validate_manifest(
                manifest,
                classification,
                self.policy,
                "rust-sdk-reference",
                "c" * 40,
            )
            self.assertTrue(any("wrong source" in failure for failure in failures))

            captures[0]["viewport"] = {"width": 800, "height": 899}
            manifest = self.rust_manifest(root, captures, source)
            failures = validate_manifest(
                manifest,
                classification,
                self.policy,
                "rust-sdk-reference",
                revision,
            )
            self.assertTrue(any("exact desktop viewport" in failure for failure in failures))

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
