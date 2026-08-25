from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import unittest
from pathlib import Path

from scripts.component_release_recovery import (
    COMPONENTS,
    RecoveryError,
    load_recovery_workflow_authority,
    verify_recovery_workflow_source,
)
from scripts.recovery_workflow_authority import (
    AUTHORITY_PATH,
    QUALIFICATION_EVENT,
    QUALIFICATION_WORKFLOW,
    SOURCE_IDENTITIES_PATH,
    RecoveryWorkflowAuthorityError,
    authority_ref_url,
    authority_url,
    normalized_source_sha256,
    qualification_requirements,
    qualification_runs_url,
    validate_authority,
    validate_source_identities,
    verify_authority_workflow_sources,
)

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = json.loads((ROOT / AUTHORITY_PATH).read_bytes())
SOURCE_IDENTITIES = json.loads((ROOT / SOURCE_IDENTITIES_PATH).read_bytes())
IDENTITIES = {
    name: (component.repository, component.default_branch)
    for name, component in COMPONENTS.items()
}


AUTHORITY_COMMIT = "a" * 40


def qualification_run(
    status: str = "completed",
    conclusion: str | None = "success",
    *,
    head_sha: str = AUTHORITY_COMMIT,
    head_branch: str = "main",
    path: str = ".github/workflows/beta-candidate.yml",
) -> dict[str, object]:
    return {
        "id": 71,
        "run_attempt": 2,
        "name": "Beta candidate",
        "workflow_id": 37,
        "path": path,
        "event": "push",
        "head_branch": head_branch,
        "head_sha": head_sha,
        "status": status,
        "conclusion": conclusion,
        "url": "https://api.github.com/repos/durable-workflow/.github/actions/runs/71",
        "html_url": "https://github.com/durable-workflow/.github/actions/runs/71",
    }


class FixtureClient:
    def __init__(self, value: object, runs: list[dict[str, object]] | None = None) -> None:
        self.raw = json.dumps(value).encode("utf-8")
        self.runs = [qualification_run()] if runs is None else runs
        self.requests: list[tuple[str, str, str | None]] = []

    def json(self, url: str) -> dict[str, object]:
        self.requests.append(("json", url, None))
        if url == authority_ref_url():
            return {"sha": AUTHORITY_COMMIT}
        if url == qualification_runs_url(AUTHORITY_COMMIT):
            return {"total_count": len(self.runs), "workflow_runs": self.runs}
        raise AssertionError(f"unexpected fixture URL: {url}")

    def bytes(self, url: str, *, accept: str | None = None) -> bytes:
        self.requests.append(("bytes", url, accept))
        if url != authority_url(AUTHORITY_COMMIT):
            raise AssertionError(f"unexpected fixture URL: {url}")
        return self.raw


class WorkflowSourceClient:
    def __init__(self) -> None:
        self.authority = copy.deepcopy(AUTHORITY)
        self.sources = {
            name: f"name: Recover {name}\non:\n  workflow_dispatch:\n"
            for name in COMPONENTS
        }
        for name, source in self.sources.items():
            self.authority["workflows"][name]["sha256"] = normalized_source_sha256(source)

    def _entry(self, url: str) -> tuple[str, dict[str, str]]:
        for name, entry in self.authority["workflows"].items():
            if f"/repos/{entry['repository']}/" in url:
                return name, entry
        raise AssertionError(f"unexpected workflow source URL: {url}")

    def json(self, url: str) -> dict[str, object]:
        name, entry = self._entry(url)
        return {
            "id": len(name),
            "path": entry["path"],
            "state": entry["state"],
            "html_url": f"https://github.com/{entry['repository']}/actions",
        }

    def bytes(self, url: str, *, accept: str | None = None) -> bytes:
        name, _entry = self._entry(url)
        if accept != "application/vnd.github.raw+json":
            raise AssertionError(f"unexpected workflow source media type: {accept}")
        return self.sources[name].encode("utf-8")


class RecoveryWorkflowAuthorityTest(unittest.TestCase):
    def test_public_authority_names_the_complete_protected_branch_tuple(self) -> None:
        workflows = validate_authority(AUTHORITY, IDENTITIES)

        self.assertEqual(set(COMPONENTS), set(workflows))
        for name, component in COMPONENTS.items():
            with self.subTest(component=name):
                self.assertEqual(component.repository, workflows[name]["repository"])
                self.assertEqual(f"refs/heads/{component.default_branch}", workflows[name]["ref"])
                self.assertEqual("active", workflows[name]["state"])
        self.assertEqual(
            {"workflow": QUALIFICATION_WORKFLOW, "event": QUALIFICATION_EVENT},
            AUTHORITY["source"]["qualification"],
        )

    def test_public_source_history_binds_the_current_waterline_reconciliation(self) -> None:
        workflows = validate_authority(AUTHORITY, IDENTITIES)
        histories = validate_source_identities(
            SOURCE_IDENTITIES,
            workflows,
            IDENTITIES,
        )

        waterline = histories["waterline"]["identities"]
        self.assertEqual(3, len(waterline))
        self.assertEqual(
            "367c0a1896ad2978b4b9e4f67e2b09558686962b",
            waterline[-1]["source_commit"],
        )
        self.assertEqual(AUTHORITY["workflows"]["waterline"]["sha256"], waterline[-1]["sha256"])
        self.assertEqual(
            {
                "source_commit": waterline[-2]["source_commit"],
                "sha256": waterline[-2]["sha256"],
            },
            waterline[-1]["supersedes"],
        )
        self.assertEqual("success", waterline[-1]["qualification"]["conclusion"])
        expected_binding = {
            "commit": "6c177285bd9224bad7a58da1e07c0d9f52850160",
            "path": "qualification/policy.json",
            "ref": "refs/heads/main",
            "repository": "durable-workflow/.github",
            "sha256": "c4383fe691fef8f571a9b58c6dbd7f0d41f9925b24df8ae651570204b394e724",
        }
        ancestry = subprocess.run(
            ["git", "merge-base", "--is-ancestor", expected_binding["commit"], "HEAD"],
            cwd=ROOT,
            check=False,
            capture_output=True,
        )
        self.assertEqual(0, ancestry.returncode)
        historical_policy = subprocess.run(
            ["git", "show", f"{expected_binding['commit']}:{expected_binding['path']}"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout
        self.assertEqual(expected_binding["sha256"], hashlib.sha256(historical_policy).hexdigest())
        historical_requirements = qualification_requirements(json.loads(historical_policy), IDENTITIES)
        for name, record in histories.items():
            for identity in record["identities"]:
                self.assertEqual(expected_binding, identity["qualification_policy"])
                self.assertEqual(
                    historical_requirements[name],
                    {
                        field: identity["qualification"][field]
                        for field in ("workflow", "required_check")
                    },
                )

    def test_component_loader_reads_only_the_successfully_qualified_exact_revision(self) -> None:
        client = FixtureClient(AUTHORITY)

        workflows, source = load_recovery_workflow_authority(client)
        self.assertEqual(AUTHORITY["workflows"], workflows)
        self.assertEqual(AUTHORITY_COMMIT, source["commit"])
        self.assertEqual(hashlib.sha256(client.raw).hexdigest(), source["sha256"])
        self.assertEqual(AUTHORITY_COMMIT, source["qualification"]["head_sha"])
        self.assertEqual(".github/workflows/beta-candidate.yml", source["qualification"]["path"])
        self.assertEqual("main", source["qualification"]["head_branch"])
        self.assertEqual("success", source["qualification"]["conclusion"])
        self.assertEqual(
            [
                ("json", authority_ref_url(), None),
                ("json", qualification_runs_url(AUTHORITY_COMMIT), None),
                (
                    "bytes",
                    authority_url(AUTHORITY_COMMIT),
                    "application/vnd.github.raw+json",
                ),
            ],
            client.requests,
        )

    def test_non_green_or_mismatched_qualification_fails_before_manifest_download(self) -> None:
        cases = (
            ("pending", [qualification_run("in_progress", None)], "pending"),
            ("failed", [qualification_run("completed", "failure")], "failed"),
            ("cancelled", [qualification_run("completed", "cancelled")], "cancelled"),
            ("absent", [], "absent"),
            ("revision-mismatch", [qualification_run(head_sha="b" * 40)], "another commit"),
        )
        for label, runs, message in cases:
            with self.subTest(state=label):
                client = FixtureClient(AUTHORITY, runs)
                with self.assertRaisesRegex(RecoveryError, message):
                    load_recovery_workflow_authority(client)
                self.assertFalse(any(method == "bytes" for method, _url, _accept in client.requests))

    def test_qualification_accepts_the_documented_protected_workflow_ref_suffix(self) -> None:
        client = FixtureClient(
            AUTHORITY,
            [qualification_run(path=".github/workflows/beta-candidate.yml@main")],
        )

        _workflows, source = load_recovery_workflow_authority(client)

        self.assertEqual(
            ".github/workflows/beta-candidate.yml@main",
            source["qualification"]["path"],
        )
        self.assertEqual("main", source["qualification"]["head_branch"])

    def test_qualification_rejects_wrong_workflow_or_ref_before_manifest_download(self) -> None:
        paths = (
            ".github/workflows/source-qualification.yml@main",
            ".github/workflows/source-qualification.yml",
            ".github/workflows/beta-candidate.yml@v2",
        )
        for path in paths:
            with self.subTest(path=path):
                client = FixtureClient(AUTHORITY, [qualification_run(path=path)])
                with self.assertRaisesRegex(RecoveryError, "absent"):
                    load_recovery_workflow_authority(client)
                self.assertFalse(any(method == "bytes" for method, _url, _accept in client.requests))

        client = FixtureClient(AUTHORITY, [qualification_run(head_branch="v2")])
        with self.assertRaisesRegex(RecoveryError, "absent"):
            load_recovery_workflow_authority(client)
        self.assertFalse(any(method == "bytes" for method, _url, _accept in client.requests))

    def test_mismatched_authority_and_workflow_source_fail_closed(self) -> None:
        wrong_branch = copy.deepcopy(AUTHORITY)
        wrong_branch["workflows"]["server"]["ref"] = "refs/heads/contributor"
        with self.assertRaisesRegex(RecoveryError, "mismatched identity"):
            load_recovery_workflow_authority(FixtureClient(wrong_branch))

        source = "on:\n  schedule:\n  workflow_dispatch:\n"
        digest = normalized_source_sha256(source)
        self.assertEqual(digest, verify_recovery_workflow_source("server", source, digest))
        with self.assertRaisesRegex(RecoveryError, "protected source identity"):
            verify_recovery_workflow_source("server", source + "# modified\n", digest)

    def test_source_qualification_verifies_every_protected_workflow_source(self) -> None:
        client = WorkflowSourceClient()
        workflows = validate_authority(client.authority, IDENTITIES)

        evidence = verify_authority_workflow_sources(client, workflows)

        self.assertEqual(set(COMPONENTS), set(evidence))
        for name, entry in evidence.items():
            with self.subTest(component=name):
                self.assertEqual(workflows[name]["sha256"], entry["sha256"])
                self.assertEqual(workflows[name]["ref"], entry["ref"])

    def test_source_qualification_rejects_protected_workflow_drift(self) -> None:
        client = WorkflowSourceClient()
        workflows = validate_authority(client.authority, IDENTITIES)
        client.sources["workflow"] += "# changed after authority qualification\n"

        with self.assertRaisesRegex(
            RecoveryWorkflowAuthorityError,
            "workflow recovery workflow does not match the protected source identity",
        ):
            verify_authority_workflow_sources(client, workflows)


if __name__ == "__main__":
    unittest.main()
