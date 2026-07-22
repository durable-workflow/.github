from __future__ import annotations

import copy
import json
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
    AUTHORITY_REF,
    CONTROL_REPOSITORY,
    normalized_source_sha256,
    validate_authority,
)

ROOT = Path(__file__).resolve().parents[1]
AUTHORITY = json.loads((ROOT / AUTHORITY_PATH).read_bytes())
IDENTITIES = {
    name: (component.repository, component.default_branch)
    for name, component in COMPONENTS.items()
}


class FixtureClient:
    def __init__(self, value: object) -> None:
        self.value = value
        self.requests: list[tuple[str, str | None]] = []

    def bytes(self, url: str, *, accept: str | None = None) -> bytes:
        self.requests.append((url, accept))
        return json.dumps(self.value).encode("utf-8")


class RecoveryWorkflowAuthorityTest(unittest.TestCase):
    def test_public_authority_names_the_complete_protected_branch_tuple(self) -> None:
        workflows = validate_authority(AUTHORITY, IDENTITIES)

        self.assertEqual(set(COMPONENTS), set(workflows))
        for name, component in COMPONENTS.items():
            with self.subTest(component=name):
                self.assertEqual(component.repository, workflows[name]["repository"])
                self.assertEqual(f"refs/heads/{component.default_branch}", workflows[name]["ref"])
                self.assertEqual("active", workflows[name]["state"])

    def test_component_loader_reads_only_the_protected_control_plane_source(self) -> None:
        client = FixtureClient(AUTHORITY)

        self.assertEqual(AUTHORITY["workflows"], load_recovery_workflow_authority(client))
        self.assertEqual(
            [
                (
                    f"https://api.github.com/repos/{CONTROL_REPOSITORY}/contents/{AUTHORITY_PATH}"
                    f"?ref={AUTHORITY_REF}",
                    "application/vnd.github.raw+json",
                )
            ],
            client.requests,
        )

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


if __name__ == "__main__":
    unittest.main()
