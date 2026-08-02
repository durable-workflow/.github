#!/usr/bin/env python3
"""Classify interaction-sensitive UI changes and validate rendered evidence."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_POLICY = ROOT / "visual-evidence" / "policy.json"
MANIFEST_SCHEMA = "durable-workflow.pipeline.visual-review/v1"
REPORT_SCHEMA = "durable-workflow.pipeline.visual-capture/v1"


class VisualEvidenceError(RuntimeError):
    pass


def load_json(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise VisualEvidenceError(f"{label} is not readable JSON: {path}") from exc
    if not isinstance(value, dict):
        raise VisualEvidenceError(f"{label} must be a JSON object: {path}")
    return value


def changed_paths(root: Path, base_ref: str) -> list[str]:
    result = subprocess.run(
        [
            "git",
            "diff",
            "--name-only",
            "--no-renames",
            "--diff-filter=ACDMRTUXB",
            "-z",
            f"{base_ref}...HEAD",
        ],
        cwd=root,
        check=True,
        capture_output=True,
    )
    return [entry.decode("utf-8") for entry in result.stdout.split(b"\0") if entry]


def file_content(root: Path, path: str, base_ref: str | None = None) -> str:
    contents: list[str] = []
    candidate = root / path
    if candidate.is_file():
        contents.append(candidate.read_text(encoding="utf-8", errors="replace"))
    if base_ref:
        result = subprocess.run(
            ["git", "show", f"{base_ref}:{path}"],
            cwd=root,
            check=False,
            capture_output=True,
        )
        if result.returncode == 0:
            contents.append(result.stdout.decode("utf-8", errors="replace"))
    return "\n".join(contents)


def classify_changes(
    root: Path,
    paths: list[str],
    policy: dict[str, Any],
    base_ref: str | None = None,
    profile_name: str | None = None,
) -> dict[str, list[str]]:
    extensions = tuple(policy["customer_facing_extensions"])
    matches: dict[str, set[str]] = {}
    for path in paths:
        normalized = path.replace("\\", "/")
        if not normalized.lower().endswith(extensions):
            continue
        searchable = f"{normalized}\n{file_content(root, normalized, base_ref)}"
        if profile_name is None:
            for interaction, rule in policy["interactions"].items():
                if any(re.search(pattern, searchable) for pattern in rule["content_patterns"]):
                    matches.setdefault(interaction, set()).add(normalized)
        else:
            profile = policy["visual_profiles"].get(profile_name)
            if profile is None:
                raise VisualEvidenceError(f"unknown visual evidence profile: {profile_name}")
            for rule in profile["change_rules"]:
                if any(re.search(pattern, normalized) for pattern in rule["path_patterns"]):
                    matches.setdefault(rule["classification"], set()).add(normalized)
    return {interaction: sorted(paths) for interaction, paths in sorted(matches.items())}


def viewport_class(width: int, policy: dict[str, Any]) -> str | None:
    for name, bounds in policy["viewport_classes"].items():
        if width < bounds["minimum_width"]:
            continue
        if "maximum_width" in bounds and width > bounds["maximum_width"]:
            continue
        return name
    return None


def validate_report(
    manifest_path: Path,
    capture: dict[str, Any],
    policy: dict[str, Any],
    expected_source: dict[str, str] | None = None,
) -> list[str]:
    failures: list[str] = []
    evidence_root = manifest_path.parent.resolve()
    report_path = (evidence_root / str(capture.get("report", ""))).resolve()
    screenshot_path = (evidence_root / str(capture.get("screenshot", ""))).resolve()
    if evidence_root not in report_path.parents or evidence_root not in screenshot_path.parents:
        return ["capture report and screenshot must remain inside the manifest directory"]
    if not screenshot_path.is_file():
        failures.append(f"capture screenshot is missing: {screenshot_path}")
    try:
        report = load_json(report_path, "visual capture report")
    except VisualEvidenceError as exc:
        return failures + [str(exc)]
    if report.get("schema") != REPORT_SCHEMA:
        failures.append(f"capture report has an unsupported schema: {report_path}")
    compared_fields = ["surface", "state", "viewport", "interactions"]
    if expected_source is not None:
        compared_fields.append("source")
    for field in compared_fields:
        if report.get(field) != capture.get(field):
            failures.append(f"capture report {field} does not match its manifest entry: {report_path}")
    if expected_source is not None and capture.get("source") != expected_source:
        failures.append(f"capture is not bound to the expected source: {report_path}")
    if report.get("page_status") != 200:
        failures.append(f"capture report did not render an HTTP 200 page: {report_path}")
    geometry = report.get("geometry")
    if not isinstance(geometry, dict):
        failures.append(f"capture report has horizontal overflow or missing geometry: {report_path}")
        return failures
    requirements = policy["report_requirements"]
    for field in requirements["false_geometry_flags"]:
        if geometry.get(field) is not False:
            failures.append(f"capture report has {field} or is missing the field: {report_path}")
    for field in requirements["empty_geometry_findings"]:
        findings = geometry.get(field)
        if not isinstance(findings, list):
            failures.append(f"capture report is missing the {field} findings list: {report_path}")
        elif findings:
            failures.append(f"capture report has non-empty {field} findings: {report_path}")
    for field in requirements["empty_report_findings"]:
        findings = report.get(field)
        if not isinstance(findings, list):
            failures.append(f"capture report is missing the {field} findings list: {report_path}")
        elif findings:
            failures.append(f"capture report has non-empty {field} findings: {report_path}")
    return failures


def validate_manifest(
    manifest_path: Path,
    classification: dict[str, list[str]],
    policy: dict[str, Any],
    profile_name: str | None = None,
    expected_revision: str | None = None,
) -> list[str]:
    if not classification and not manifest_path.is_file():
        return []
    manifest = load_json(manifest_path, "visual evidence manifest")
    if manifest.get("schema") != MANIFEST_SCHEMA or not isinstance(manifest.get("captures"), list):
        raise VisualEvidenceError("visual evidence manifest has an unsupported schema")

    failures: list[str] = []
    profile = None
    expected_source = None
    profile_classifications: dict[str, dict[str, Any]] = {}
    if profile_name:
        profile = policy["visual_profiles"].get(profile_name)
        if profile is None:
            raise VisualEvidenceError(f"unknown visual evidence profile: {profile_name}")
        profile_classifications = {
            rule["classification"]: rule for rule in profile["change_rules"]
        }
        if any(name in profile_classifications for name in classification):
            if not expected_revision or re.fullmatch(r"[0-9a-f]{40}", expected_revision) is None:
                failures.append("profile evidence requires the expected 40-character source revision")
            else:
                expected_source = {
                    "repository": profile["repository"],
                    "revision": expected_revision,
                }
                if manifest.get("source") != expected_source:
                    failures.append("visual evidence manifest is missing, stale, or bound to the wrong source")
    captures = [capture for capture in manifest["captures"] if isinstance(capture, dict)]
    for capture in captures:
        failures.extend(validate_report(manifest_path, capture, policy, expected_source))
    for interaction, paths in classification.items():
        if interaction not in policy["interactions"]:
            continue
        rule = policy["interactions"][interaction]
        required_state = rule["required_state"]
        state_captures = [capture for capture in captures if capture.get("state") == required_state]
        for viewport_name in policy["viewport_classes"]:
            qualifying = []
            for capture in state_captures:
                viewport = capture.get("viewport")
                if not isinstance(viewport, dict) or not isinstance(viewport.get("width"), int):
                    continue
                if viewport_class(viewport["width"], policy) != viewport_name:
                    continue
                interactions = capture.get("interactions")
                if not isinstance(interactions, list):
                    continue
                selectors = [
                    item.get("selector", "")
                    for item in interactions
                    if isinstance(item, dict) and item.get("type") == "click" and isinstance(item.get("selector"), str)
                ]
                if any(
                    re.search(pattern, selector)
                    for pattern in rule["interaction_selector_patterns"]
                    for selector in selectors
                ):
                    qualifying.append(capture)
            if not qualifying:
                failures.append(
                    f"{interaction} changes in {', '.join(paths)} require a {required_state} "
                    f"capture with a meaningful click at the {viewport_name} viewport"
                )
                continue
    if profile is not None:
        required_states: set[str] = set()
        affected_paths: set[str] = set()
        for name, paths in classification.items():
            rule = profile_classifications.get(name)
            if rule is None:
                continue
            required_states.update(rule["required_states"])
            affected_paths.update(paths)
        for state in sorted(required_states):
            state_rule = profile["states"][state]
            selector_patterns = state_rule["interaction_selector_patterns"]
            for viewport_name, expected_viewport in profile["viewports"].items():
                qualifying = []
                for capture in captures:
                    if capture.get("surface") != profile["surface"]:
                        continue
                    if capture.get("state") != state or capture.get("viewport") != expected_viewport:
                        continue
                    interactions = capture.get("interactions")
                    if not isinstance(interactions, list):
                        continue
                    selectors = [
                        item.get("selector", "")
                        for item in interactions
                        if isinstance(item, dict)
                        and item.get("type") == "click"
                        and isinstance(item.get("selector"), str)
                    ]
                    if selector_patterns and not all(
                        any(re.search(pattern, selector) for selector in selectors)
                        for pattern in selector_patterns
                    ):
                        continue
                    qualifying.append(capture)
                if not qualifying:
                    failures.append(
                        f"visual changes in {', '.join(sorted(affected_paths))} require a source-bound "
                        f"{state} capture at the exact {viewport_name} viewport"
                    )
    return failures


def parser() -> argparse.ArgumentParser:
    command_parser = argparse.ArgumentParser()
    command_parser.add_argument("--policy", type=Path, default=DEFAULT_POLICY)
    subparsers = command_parser.add_subparsers(dest="command", required=True)
    for name in ("classify", "validate"):
        subparser = subparsers.add_parser(name)
        subparser.add_argument("--root", type=Path, default=Path.cwd())
        subparser.add_argument("--base-ref")
        subparser.add_argument("--changed-file", action="append", default=[])
        subparser.add_argument("--profile")
        if name == "validate":
            subparser.add_argument("--manifest", type=Path, required=True)
            subparser.add_argument("--expected-revision")
    return command_parser


def main() -> None:
    args = parser().parse_args()
    root = args.root.resolve()
    policy = load_json(args.policy, "visual evidence policy")
    paths = list(args.changed_file)
    if args.base_ref:
        paths.extend(changed_paths(root, args.base_ref))
    if not paths:
        raise SystemExit("provide --base-ref or at least one --changed-file")
    classification = classify_changes(
        root,
        sorted(set(paths)),
        policy,
        args.base_ref,
        args.profile,
    )
    if args.command == "classify":
        print(json.dumps({"classification": classification}, sort_keys=True))
        return
    failures = validate_manifest(
        args.manifest.resolve(),
        classification,
        policy,
        args.profile,
        args.expected_revision,
    )
    if failures:
        raise SystemExit("\n".join(failures))
    print(json.dumps({"classification": classification, "valid": True}, sort_keys=True))


if __name__ == "__main__":
    main()
