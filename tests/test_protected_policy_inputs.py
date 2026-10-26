import base64
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from unittest.mock import patch

from scripts.protected_policy_inputs import (
    MAX_FILE_BYTES,
    MAX_FILES,
    InputRefused,
    checked_path,
    checked_slug,
    collect_inputs,
    read_identity,
    require_current,
    write_inputs,
)


BASE = "a" * 40
HEAD = "b" * 40
TREE = "c" * 40
REPOSITORY = "durable-workflow/.github"
FORK = "contributor/policy-change"
WORKFLOW = ".github/workflows/ci.yml"


class ProtectedPolicyInputTest(unittest.TestCase):
    def setUp(self):
        self.entries = []
        self.records = {
            f"/repos/{REPOSITORY}/pulls/7": {
                "state": "open", "number": 7,
                "base": {"ref": "main", "sha": BASE, "repo": {
                    "id": 100, "full_name": REPOSITORY, "private": False,
                }},
                "head": {"sha": HEAD, "repo": {
                    "id": 200, "full_name": FORK, "private": False,
                }},
            },
            f"/repos/{FORK}/git/commits/{HEAD}": {"sha": HEAD, "tree": {"sha": TREE}},
            f"/repos/{FORK}/git/trees/{TREE}?recursive=1": {
                "sha": TREE, "truncated": False, "tree": self.entries,
            },
        }
        self.requests = []
        self.add_file(WORKFLOW, b"on: push\njobs: {}\n")
        self.identity = read_identity(self.read, REPOSITORY, 100, 7, BASE)

    def read(self, path):
        self.requests.append(path)
        return deepcopy(self.records[path])

    def add_file(self, path, contents, mode="100644"):
        sha = f"{len(self.entries) + 1:040x}"
        entry = {"path": path, "sha": sha, "mode": mode, "type": "blob", "size": len(contents)}
        self.entries.append(entry)
        self.records[f"/repos/{FORK}/git/blobs/{sha}"] = {
            "sha": sha, "size": len(contents), "encoding": "base64",
            "content": base64.encodebytes(contents).decode("ascii"),
        }
        return entry

    def blob(self, entry=None):
        entry = entry or self.entries[0]
        return self.records[f"/repos/{FORK}/git/blobs/{entry['sha']}"]

    def pull(self):
        return self.records[f"/repos/{REPOSITORY}/pulls/7"]

    def collect(self):
        return collect_inputs(self.read, self.identity)

    def test_only_workflows_and_referenced_helpers_are_fetched_from_the_exact_fork_commit(self):
        self.blob()["content"] = base64.encodebytes(b"run: scripts/one.sh\n").decode()
        self.entries[0]["size"] = self.blob()["size"] = len(b"run: scripts/one.sh\n")
        self.add_file("scripts/one.sh", b"#!/bin/sh\n./scripts/two.sh\n", "100755")
        self.add_file("scripts/two.sh", b"#!/bin/sh\nexit 0\n", "100755")
        unreferenced = self.add_file("pip.py", b"raise SystemExit('must never load')")
        files = self.collect()
        self.assertEqual({WORKFLOW, "scripts/one.sh", "scripts/two.sh"}, set(files))
        self.assertNotIn(f"/repos/{FORK}/git/blobs/{unreferenced['sha']}", self.requests)
        self.assertIn(f"/repos/{FORK}/git/commits/{HEAD}", self.requests)

    def test_head_movement_refuses_the_result(self):
        self.pull()["head"]["sha"] = "d" * 40
        with self.assertRaises(InputRefused):
            require_current(self.read, self.identity)

    def test_base_movement_refuses_the_result(self):
        self.pull()["base"]["sha"] = "d" * 40
        with self.assertRaises(InputRefused):
            self.collect()

    def test_wrong_repository_id_refuses_before_candidate_reads(self):
        self.pull()["base"]["repo"]["id"] = 101
        with self.assertRaises(InputRefused):
            read_identity(self.read, REPOSITORY, 100, 7, BASE)

    def test_closed_pull_request_cannot_issue_a_result(self):
        self.pull()["state"] = "closed"
        with self.assertRaises(InputRefused):
            require_current(self.read, self.identity)

    def test_private_repository_is_not_silently_onboarded(self):
        self.pull()["base"]["repo"]["private"] = True
        with self.assertRaises(InputRefused):
            require_current(self.read, self.identity)

    def test_private_fork_is_not_silently_onboarded(self):
        self.pull()["head"]["repo"]["private"] = True
        with self.assertRaises(InputRefused):
            require_current(self.read, self.identity)

    def test_external_base_repository_is_not_onboarded(self):
        with self.assertRaises(InputRefused):
            read_identity(self.read, "elsewhere/repository", 100, 7, BASE)

    def test_deleted_fork_refuses(self):
        self.pull()["head"]["repo"] = None
        with self.assertRaises(InputRefused):
            require_current(self.read, self.identity)

    def test_unsafe_paths_and_repository_names_refuse(self):
        for value in (".", "../escape", "/absolute", "a//b", "a/../b", "a\\b", "a\nb", "a\0b"):
            with self.subTest(path=value), self.assertRaises(InputRefused):
                checked_path(value)
        for value in ("../repo", "owner/..", "https://github.com/owner/repo", "owner/repo/more", "x\ny/repo"):
            with self.subTest(slug=value), self.assertRaises(InputRefused):
                checked_slug(value)

    def test_symlink_workflow_refuses_without_fetching_its_contents(self):
        self.entries[0]["mode"] = "120000"
        with self.assertRaises(InputRefused):
            self.collect()
        self.assertFalse(any("/git/blobs/" in path for path in self.requests))

    def test_referenced_symlink_helper_refuses(self):
        contents = b"run: scripts/link.sh\n"
        self.entries[0]["size"] = self.blob()["size"] = len(contents)
        self.blob()["content"] = base64.encodebytes(contents).decode()
        self.add_file("scripts/link.sh", b"../../outside", "120000")
        with self.assertRaises(InputRefused):
            self.collect()

    def test_submodule_cannot_supply_a_workflow(self):
        self.entries[0].update({"mode": "160000", "type": "commit"})
        with self.assertRaises(InputRefused):
            self.collect()

    def test_truncated_tree_refuses(self):
        self.records[f"/repos/{FORK}/git/trees/{TREE}?recursive=1"]["truncated"] = True
        with self.assertRaises(InputRefused):
            self.collect()

    def test_another_commit_or_tree_cannot_supply_candidate_inputs(self):
        commit = self.records[f"/repos/{FORK}/git/commits/{HEAD}"]
        commit["sha"] = "d" * 40
        with self.assertRaises(InputRefused):
            self.collect()
        commit["sha"] = HEAD
        self.records[f"/repos/{FORK}/git/trees/{TREE}?recursive=1"]["sha"] = "d" * 40
        with self.assertRaises(InputRefused):
            self.collect()

    def test_duplicate_path_refuses(self):
        self.entries.append(deepcopy(self.entries[0]))
        with self.assertRaises(InputRefused):
            self.collect()

    def test_oversized_file_refuses_before_blob_download(self):
        self.entries[0]["size"] = MAX_FILE_BYTES + 1
        with self.assertRaises(InputRefused):
            self.collect()
        self.assertFalse(any("/git/blobs/" in path for path in self.requests))

    def test_wrong_declared_blob_size_refuses(self):
        self.blob()["size"] += 1
        with self.assertRaises(InputRefused):
            self.collect()

    def test_wrong_blob_identity_refuses(self):
        self.blob()["sha"] = "d" * 40
        with self.assertRaises(InputRefused):
            self.collect()

    def test_invalid_base64_refuses(self):
        self.blob()["content"] = "$not-base64"
        with self.assertRaises(InputRefused):
            self.collect()

    def test_binary_workflow_refuses(self):
        self.entries[0]["size"] = self.blob()["size"] = 1
        self.blob()["content"] = "/w=="
        with self.assertRaises(InputRefused):
            self.collect()

    def test_total_byte_bound_applies_across_files(self):
        with patch("scripts.protected_policy_inputs.MAX_TOTAL_BYTES", 4):
            with self.assertRaises(InputRefused):
                self.collect()

    def test_file_count_bound_applies_to_workflow_fanout(self):
        for number in range(MAX_FILES):
            self.add_file(f".github/workflows/extra-{number}.yml", b"on: push\n")
        with self.assertRaises(InputRefused):
            self.collect()

    def test_materialization_is_inert_and_does_not_preserve_executable_bits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            marker = root / "executed"
            files = {"scripts/attack.sh": f"#!/bin/sh\ntouch '{marker}'\n".encode()}
            destination = root / "candidate"
            write_inputs(files, destination)
            self.assertFalse(marker.exists())
            self.assertEqual(0o600, (destination / "scripts/attack.sh").stat().st_mode & 0o777)
            self.assertEqual(files["scripts/attack.sh"], (destination / "scripts/attack.sh").read_bytes())

    def test_materialization_refuses_existing_destination_and_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaises(FileExistsError):
                write_inputs({WORKFLOW: b"on: push"}, root)
            with self.assertRaises(InputRefused):
                write_inputs({"../outside": b"must not write"}, root / "candidate")
            self.assertFalse((root / "outside").exists())

    def test_materialization_refuses_a_symlink_destination(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            outside = root / "outside"
            outside.mkdir()
            redirected = root / "candidate"
            redirected.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(FileExistsError):
                write_inputs({WORKFLOW: b"on: push"}, redirected)
            self.assertEqual([], list(outside.iterdir()))

    def test_materialization_refuses_non_bytes_and_oversized_files_before_creation(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "candidate"
            for contents in ("not bytes", b"x" * (MAX_FILE_BYTES + 1)):
                with self.subTest(kind=type(contents).__name__), self.assertRaises(InputRefused):
                    write_inputs({WORKFLOW: contents}, destination)
                self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
