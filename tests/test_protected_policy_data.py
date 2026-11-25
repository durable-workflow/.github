"""Approved policy inputs as protected-main data, and the data-change gate.

CI runs these through tests.test_protected_policy_check, which imports them.
"""

import base64
from copy import deepcopy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import unittest

from scripts import native_policy_check as native
from scripts import php_linux_bootstrap as bootstrap
from scripts import php_linux_profile_records as records
from scripts import protected_policy_check as checker
from scripts import protected_policy_context as context
from scripts import protected_policy_data as data
from scripts.protected_policy_inputs import InputRefused

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = data.DATA_REPOSITORY
REPOSITORY_ID = native.PILOT_ID
MIRROR = bootstrap.MIRROR_REPOSITORY
# The qualification workflows still check out cba1285d; ci.yml uses the mirrored setup pin.
CURRENT_PIN = "cba1285ddd43696ac9f445d7d04e8aff8fcad545"
CI_PIN = "636d0cda4ce1e9c94ac6bf649154ff57957558be"
CI = ".github/workflows/ci.yml"
QUALIFY = (".github/workflows/qualify-linux-php-initial.yml", ".github/workflows/qualify-linux-php-ubuntu24.yml")
CI_FIXTURE = "tests/fixtures/ci-php-archive-mirror-20261119-source.yml"
QUALIFY_FIXTURES = ("tests/fixtures/qualify-linux-php-initial-archive-repair-20261119.yml",
                    "tests/fixtures/qualify-linux-php-ubuntu24-archive-repair-20261119.yml")
# The registries hard-coded in runtime 90313f07 (the #411 head), as sorted
# "path sha256" lines. Moving them to data must not add or drop an identity.
PREVIOUS_REGISTRIES = {
    "github-control-plane": (30, "e1e0e64a9e1593f4d57183ae0b0053ac30d61d0de9d869eff3c55cdcbfd92aac"),
    "ai": (2, "4ac997256eef428482ccbc0274df755f8cf5687e6e7a04039ac51ea741b29cbd"),
}


def git_sha(seed: str) -> str:
    return hashlib.sha1(seed.encode()).hexdigest()


def repository_files() -> dict[str, bytes]:
    """The repository data a policy read can reach: workflows, helpers, data and fixtures."""
    files = {}
    for top in (".github", "scripts", "qualification", "tests/fixtures"):
        for path in sorted((ROOT / top).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                files[path.relative_to(ROOT).as_posix()] = path.read_bytes()
    return files


class FakeGitHub:
    """Exact commits, protected main, PRs and release-asset metadata; a missing record is a refusal."""

    def __init__(self):
        self.records, self.requests = {}, []
        self.trees = {}

    def read(self, path):
        self.requests.append(path)
        if path not in self.records:
            raise InputRefused("GitHub request refused: curl exit 22, HTTP 404")
        return deepcopy(self.records[path])

    def commit(self, sha, files, repository=REPOSITORY, modes=None):
        tree_sha = git_sha("tree" + sha)
        entries = []
        for path, raw in sorted(files.items()):
            blob = hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()
            self.records[f"/repos/{repository}/git/blobs/{blob}"] = {
                "sha": blob, "size": len(raw), "encoding": "base64", "content": base64.b64encode(raw).decode()}
            entries.append({"path": path, "sha": blob, "mode": (modes or {}).get(path, "100644"), "type": "blob",
                            "size": len(raw)})
        self.records[f"/repos/{repository}/git/commits/{sha}"] = {"sha": sha, "tree": {"sha": tree_sha}}
        self.records[f"/repos/{repository}/git/trees/{tree_sha}?recursive=1"] = {
            "sha": tree_sha, "truncated": False, "tree": entries}
        self.trees[sha] = dict(files)
        return sha

    def set_main(self, sha):
        self.records[f"/repos/{REPOSITORY}/branches/main"] = {"name": "main", "protected": True,
                                                               "commit": {"sha": sha}}

    def merged(self, ancestor, descendant):
        self.records[f"/repos/{REPOSITORY}/compare/{ancestor}...{descendant}"] = {
            "status": "identical" if ancestor == descendant else "ahead"}

    def asset(self, repository, identity):
        self.records[f"/repos/{repository}/releases/assets/{identity['id']}"] = {
            **{key: identity[key] for key in ("id", "name", "size", "digest")}, "state": "uploaded"}

    def pull(self, number, base, head):
        self.records[f"/repos/{REPOSITORY}/pulls/{number}"] = {
            "state": "open", "number": number,
            "base": {"ref": "main", "sha": base, "repo": {"id": REPOSITORY_ID, "full_name": REPOSITORY,
                                                           "private": False}},
            "head": {"sha": head, "repo": {"id": REPOSITORY_ID, "full_name": REPOSITORY, "private": False}}}
        event = {"repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY, "private": False},
                 "action": "synchronize", "number": number,
                 "pull_request": deepcopy(self.records[f"/repos/{REPOSITORY}/pulls/{number}"])}
        environment = {"GITHUB_SERVER_URL": "https://github.com", "GITHUB_REPOSITORY": REPOSITORY,
                       "GITHUB_REPOSITORY_ID": str(REPOSITORY_ID), "GITHUB_EVENT_NAME": "pull_request"}
        return event, environment


def fake_archive(label: str) -> bytes:
    """A small zstd tar whose headers the strict inspector reads like a real archive."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as output:
        for name in ("./", "./usr/", "./usr/bin/", "./usr/lib/"):
            info = tarfile.TarInfo(name)
            info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, 1
            output.addfile(info)
        payload = f"#!/bin/sh\necho fake {label}\n".encode()
        info = tarfile.TarInfo("./usr/bin/php8.3")
        info.size, info.mode, info.mtime = len(payload), 0o755, 1
        output.addfile(info, io.BytesIO(payload))
        info = tarfile.TarInfo("./usr/bin/php")
        info.type, info.linkname, info.mode, info.mtime = tarfile.SYMTYPE, "php8.3", 0o777, 1
        output.addfile(info)
    return subprocess.run(["/usr/bin/zstd", "--compress", "--stdout", "--quiet"], input=raw.getvalue(),
                          capture_output=True, check=True).stdout


def archive_update(files: dict[str, bytes], release: str, compressed: bytes, upstream_id: int,
                   mirror_id: int) -> tuple[dict[str, bytes], dict]:
    """What a maintainer commits for a new archive: catalog row and re-derived records only."""
    catalog = json.loads(files[data.CATALOG_PATH])
    row = next(row for row in catalog["archives"] if row["release"] == release)
    identity = {"id": upstream_id, "name": row["asset"]["name"], "size": len(compressed),
                "digest": "sha256:" + hashlib.sha256(compressed).hexdigest()}
    metadata_raw, plan_raw = records.records(compressed, identity)
    archive_path, plan_path, alternatives_path = data.profile_paths(row["profile"]["name"])
    alternatives = json.loads(files[alternatives_path])
    alternatives["archive_metadata_sha256"] = hashlib.sha256(metadata_raw).hexdigest()
    alternatives_raw = (json.dumps(alternatives, indent=2) + "\n").encode()
    plan = json.loads(plan_raw)
    row.update(asset=identity, profile=dict(
        row["profile"], metadata_sha256=hashlib.sha256(metadata_raw).hexdigest(),
        plan_sha256=hashlib.sha256(plan_raw).hexdigest(),
        inventory_sha256=hashlib.sha256(alternatives_raw).hexdigest(),
        counts=[plan["expected_members"], plan["expected_regular_files"], plan["expected_directories"]]),
        mirror={"repository": MIRROR, "release_tag": "php-sha256-" + identity["digest"][7:23], "id": mirror_id,
                "name": identity["name"], "size": identity["size"], "digest": identity["digest"]})
    updated = dict(files)
    updated.update({data.CATALOG_PATH: (json.dumps(bootstrap.validate_catalog(catalog), indent=2) + "\n").encode(),
                    archive_path: metadata_raw, plan_path: plan_raw, alternatives_path: alternatives_raw})
    return updated, row


def approve_pin(files: dict[str, bytes], pin: str, old_pin: str = CI_PIN) -> dict[str, bytes]:
    """The routine approval: one bound setup pin and pin-substituted reviewed workflow bytes."""
    updated = dict(files)
    policy = json.loads(files[data.POLICY_PATH])
    releases = policy["action_runtime"]["allowed_releases"][REPOSITORY]
    releases[pin] = data.BOUND_LABEL
    policy["action_runtime"]["allowed_releases"][REPOSITORY] = dict(sorted(releases.items()))
    updated[data.POLICY_PATH] = (json.dumps(policy, indent=2) + "\n").encode()
    document = json.loads(files[data.DATA_PATH])
    entries = document["reviewed_workflows"]["github-control-plane"]
    # Only the setup action `uses:` position is data-swappable; the qualification
    # workflows check out the repository at the pin and stay a runtime review.
    for path, fixture in ((CI, CI_FIXTURE),):
        old = files[fixture]
        new = old.replace(old_pin.encode(), pin.encode())
        name = f"tests/fixtures/{Path(path).stem}-setup-{pin[:12]}.yml"
        updated[name] = new
        entries.append({"registry": "routine_setup_pin", "path": path, "sha256": hashlib.sha256(new).hexdigest(),
                        "fixture": name, "derived_from": hashlib.sha256(old).hexdigest()})
    updated[data.DATA_PATH] = (json.dumps(document, indent=2) + "\n").encode()
    return updated


def adopt_workflows(files: dict[str, bytes], pin: str, old_pin: str = CI_PIN) -> dict[str, bytes]:
    updated = dict(files)
    updated[CI] = files[CI].replace(old_pin.encode(), pin.encode())
    return updated


def mirrored(files: dict[str, bytes], github: FakeGitHub) -> dict[str, bytes]:
    """Main after the held mirror upload and its adoption PR (mirror IDs are synthetic)."""
    catalog = json.loads(files[data.CATALOG_PATH])
    for offset, row in enumerate(catalog["archives"]):
        row["mirror"] = {"repository": MIRROR, "release_tag": "php-sha256-" + row["asset"]["digest"][7:23],
                         "id": 800000001 + offset, **{key: row["asset"][key] for key in ("name", "size", "digest")}}
        github.asset(MIRROR, row["mirror"])
    return {**files, data.CATALOG_PATH: (json.dumps(catalog, indent=2) + "\n").encode()}


def unmirrored(files: dict[str, bytes]) -> dict[str, bytes]:
    """A catalog whose setup rows have no mirror record (main before the mirror adoption)."""
    catalog = json.loads(files[data.CATALOG_PATH])
    for row in catalog["archives"]:
        row["mirror"] = None
    return {**files, data.CATALOG_PATH: (json.dumps(catalog, indent=2) + "\n").encode()}


def with_reviewed_setup_code(files: dict[str, bytes], github: FakeGitHub) -> dict[str, bytes]:
    """Main whose data reviews this checkout's setup code (as the seed entry does after merge)."""
    probe = git_sha("setup code probe")
    github.commit(probe, files)
    entries = {entry["path"]: entry for entry in github.records[
        f"/repos/{REPOSITORY}/git/trees/{git_sha('tree' + probe)}?recursive=1"]["tree"]}
    document = json.loads(files[data.DATA_PATH])
    digest = data.setup_code_identity(entries)
    if digest not in {item["sha256"] for item in document["reviewed_setup_code"]}:
        document["reviewed_setup_code"].append({"sha256": digest, "source": "this checkout"})
    return {**files, data.DATA_PATH: (json.dumps(document, indent=2) + "\n").encode()}


class Scenario(unittest.TestCase):
    def setUp(self):
        self.github = FakeGitHub()
        self.fetched = []
        self.archives = {}

    def fetch(self, row, catalog):
        self.fetched.append(row["mirror"]["id"] if row["mirror"] else None)
        # The real fetch is setup's exact-ID mirror download (verified separately).
        if row["mirror"] is None or row["mirror"]["id"] not in self.archives:
            raise InputRefused("The mirrored archive is absent or differs from its pinned bytes")
        return self.archives[row["mirror"]["id"]]

    def start(self, files, sha="1" * 40):
        self.github.commit(sha, files)
        self.github.set_main(sha)
        return sha

    def propose(self, base, files, head, number=9, validator=None):
        self.github.commit(head, files)
        event, environment = self.github.pull(number, base, head)
        options = {"fetch_archive": self.fetch}
        if validator is not None:
            options["validator"] = validator
        return native.validate_native(self.github.read, "pull_request", event, environment, **options)

    def merge(self, head, files):
        """A merge commit whose tree is the PR head's; main moves to it."""
        merge = git_sha("merge" + head)
        self.github.commit(merge, files)
        self.github.set_main(merge)
        self.github.merged(head, merge)
        self.github.merged(merge, merge)
        return merge


class OldBehaviourPreservedTest(unittest.TestCase):
    def test_data_carries_exactly_the_previous_hard_coded_registries(self):
        local = data.local_data()
        for target, (count, digest) in PREVIOUS_REGISTRIES.items():
            lines = sorted(f"{path} {sha}" for path, shas in local.reviewed(target).items() for sha in shas)
            self.assertEqual((count, digest), (len(lines), hashlib.sha256("\n".join(lines).encode()).hexdigest()))
            self.assertEqual(context.reviewed_context_hashes(target), local.reviewed(target))

    def test_effective_policy_from_unchanged_main_is_the_reviewed_policy(self):
        from scripts.qualification_policy import load_policy

        frozen = load_policy(ROOT / data.POLICY_PATH)
        self.assertEqual(frozen, data.effective_policy(frozen, data.local_data()))

    def test_setup_registries_derived_from_the_catalog_keep_their_reviewed_values(self):
        from scripts import php_linux_alternatives, php_linux_configuration, php_linux_normalize, setup_php_linux

        self.assertEqual({"26.04": 768113262, "24.04": 768105765}, setup_php_linux.HOST_ARCHIVES)
        self.assertEqual({768113262: ("initial", "929756ce06042afe9ae97737449b1f1a89eed92c5a30e5deaa0f2f26f75cfb5a",
                                      "38600c07fc8ec2be10da770e1d6512b9dc91470354e68a0d78ed1aa678e0c1a8",
                                      (3900, 3510, 390)),
                          768105765: ("ubuntu24", "3b66abc2d7479c783b7763867aa3a171af104c51ec9b4609f1a8748af8e0501a",
                                      "ce4287e3ae64109b7ea98b2ae5914af35f597e7f9018581e675b0e90a30ba4b0",
                                      (3564, 3194, 370))}, php_linux_normalize.SOURCE_PROFILES)
        self.assertEqual({768113262: ("initial", "6dac97b30a2cbd1a2b9d340f44df8ed3dd80b7ad0bc439526d2f39fb78f3af8e"),
                          768105765: ("ubuntu24", "240fba4596736ec5a5736a7d7ded31b575a85f8fb061565649a09205d36eb3ed")},
                         php_linux_alternatives.INVENTORIES)
        self.assertEqual({768113262: "ubuntu26.04-x64-php8.3-production-coverage-none",
                          768105765: "ubuntu24.04-x64-php8.3-production-coverage-none"},
                         php_linux_configuration.PROFILES)

    def test_live_workflows_get_the_same_verdict_from_main_data_as_before(self):
        files = repository_files()
        workflows = {path: raw for path, raw in files.items() if path.startswith(".github/workflows/")}
        helpers = {}
        from scripts.protected_policy_inputs import HELPERS
        pending = list(workflows)
        while pending:
            raw = files[pending.pop()]
            for helper in HELPERS.findall(raw.decode()):
                helper = helper.removeprefix("./")
                if helper in files and helper not in workflows and helper not in helpers:
                    helpers[helper] = files[helper]
                    pending.append(helper)
        inputs = {**workflows, **helpers}
        before = checker.validate_files(inputs)
        after = checker.validate_files(inputs, data=data.local_data())
        self.assertEqual(before, {key: after[key] for key in before})


class DataGateTest(Scenario):
    def setUp(self):
        super().setUp()
        self.files = repository_files()
        self.base = self.start(self.files)

    def gate(self, files, head="2" * 40, fetch=True):
        self.github.commit(head, files)
        base = data.main_data(self.github.read, expected_sha=self.base)
        return data.gate_data_change(self.github.read, REPOSITORY, head, base,
                                     fetch_archive=self.fetch if fetch else None)

    def test_runtime_reads_protected_main_never_the_candidate_head(self):
        self.github.requests.clear()
        loaded = checker.approved_data(self.github.read, self.base, checker.CONTROL_TARGET)
        self.assertEqual(self.base, loaded.commit)
        self.assertTrue(all(f"/repos/{REPOSITORY}/" in path for path in self.github.requests))
        self.github.set_main("3" * 40)
        with self.assertRaisesRegex(InputRefused, "protected base"):
            checker.approved_data(self.github.read, self.base, checker.CONTROL_TARGET)
        self.github.records[f"/repos/{REPOSITORY}/branches/main"]["protected"] = False
        with self.assertRaisesRegex(InputRefused, "protected main"):
            data.main_data(self.github.read)

    def test_main_without_approved_data_fails_closed(self):
        files = {path: raw for path, raw in self.files.items() if path != data.DATA_PATH}
        self.base = self.start(files, "4" * 40)
        with self.assertRaisesRegex(InputRefused, "lacks approved policy data"):
            data.main_data(self.github.read)

    def test_unchanged_data_and_consumer_only_policy_changes_are_not_runtime_data(self):
        self.assertEqual({"data_change": False}, self.gate(self.files))
        policy = json.loads(self.files[data.POLICY_PATH])
        policy["action_runtime"]["allowed_releases"]["actions/checkout"]["f" * 40] = "v9"
        changed = {**self.files, data.POLICY_PATH: (json.dumps(policy, indent=2) + "\n").encode()}
        self.assertEqual({"data_change": False}, self.gate(changed, "5" * 40))

    def test_a_pr_cannot_approve_its_own_workflow_bytes(self):
        new_pin = git_sha("unmerged setup")
        files = adopt_workflows(approve_pin(self.files, new_pin), new_pin)
        # Validation uses main's data, which lacks the PR's new hash and pin.
        with self.assertRaisesRegex(InputRefused, "closed literal"):
            self.propose(self.base, files, "6" * 40, validator=lambda *_: [])
        # The data gate also refuses mixing data with the workflows it would approve.
        with self.assertRaisesRegex(InputRefused, "data-only"):
            self.gate(files, "7" * 40)

    def test_tampered_data_is_refused(self):
        document = json.loads(self.files[data.DATA_PATH])
        cases = {
            "extra field": {**document, "bypass": True},
            "unknown schema": {**document, "schema": "durable-workflow.protected-policy-data/v0"},
            "short digest": {**document, "reviewed_workflows": {**document["reviewed_workflows"], "ai": [
                {"registry": "ai_workflows", "path": CI, "sha256": "ab"}]}},
        }
        for number, (label, value) in enumerate(cases.items()):
            with self.subTest(label), self.assertRaises(InputRefused):
                self.gate({**self.files, data.DATA_PATH: json.dumps(value).encode()}, git_sha(label))
        duplicate = b'{"schema": "x", "schema": "' + data.SCHEMA.encode() + b'", "reviewed_workflows": {}}'
        with self.assertRaisesRegex(InputRefused, "duplicate"):
            self.gate({**self.files, data.DATA_PATH: duplicate}, "8" * 40)

    def test_new_or_changed_workflow_approvals_need_a_routine_derivation(self):
        document = json.loads(self.files[data.DATA_PATH])
        entries = document["reviewed_workflows"]["github-control-plane"]
        entries.append({"registry": "anything", "path": CI, "sha256": "e" * 64, "fixture": CI_FIXTURE})
        with self.assertRaisesRegex(InputRefused, "runtime review"):
            self.gate({**self.files, data.DATA_PATH: json.dumps(document).encode()}, "9" * 40)
        document = json.loads(self.files[data.DATA_PATH])
        document["reviewed_workflows"]["github-control-plane"][0]["registry"] = "renamed"
        with self.assertRaisesRegex(InputRefused, "immutable"):
            self.gate({**self.files, data.DATA_PATH: json.dumps(document).encode()}, "a1" * 20)

    def test_derivation_admits_only_setup_action_pin_substitution(self):
        old = self.files[CI_FIXTURE]
        self.assertEqual(1, old.count(CI_PIN.encode()))
        pin, other = git_sha("pin"), git_sha("other")
        new = old.replace(CI_PIN.encode(), pin.encode())
        self.assertEqual(pin, data.routine_substitution(old, new, frozenset({CI_PIN}), frozenset({pin})))
        unapproved = old.replace(CI_PIN.encode(), git_sha("x").encode())
        for label, before, after, pins in (
                ("extra edit", old, new.replace(b"python -m unittest", b"python -m unittest ; curl evil", 1), {pin}),
                ("comment edit", old, new.replace(b"# bound-linux-php", b"# other"), {pin}),
                ("unapproved new pin", old, new, set()),
                ("unapproved old pin", unapproved, new, {pin}),
                ("new pin also checked out", old, new.replace(b"persist-credentials: false",
                                                              b"ref: " + pin.encode(), 1), {pin}),
                ("identical bytes", old, old, {pin})):
            with self.subTest(label), self.assertRaises(InputRefused):
                data.routine_substitution(before, after, frozenset({CI_PIN}), frozenset(pins))

    def test_a_pin_swap_in_a_checkout_position_needs_a_runtime_review(self):
        old = self.files[QUALIFY_FIXTURES[0]]
        self.assertEqual(6, old.count(CURRENT_PIN.encode()))
        self.assertIn(b"ref: " + CURRENT_PIN.encode(), old)
        new = old.replace(CURRENT_PIN.encode(), git_sha("pin").encode())
        with self.assertRaisesRegex(InputRefused, "setup action `uses:` pins"):
            data.routine_substitution(old, new, frozenset({CURRENT_PIN}), frozenset({git_sha("pin")}))
        pin = git_sha("pin")
        files = dict(self.files)
        document = json.loads(files[data.DATA_PATH])
        name = "tests/fixtures/qualify-initial-swapped.yml"
        files[name] = new
        document["reviewed_workflows"]["github-control-plane"].append({
            "registry": "routine_setup_pin", "path": QUALIFY[0], "sha256": hashlib.sha256(new).hexdigest(),
            "fixture": name, "derived_from": hashlib.sha256(old).hexdigest()})
        files[data.DATA_PATH] = json.dumps(document).encode()
        policy = json.loads(files[data.POLICY_PATH])
        policy["action_runtime"]["allowed_releases"][REPOSITORY][pin] = data.BOUND_LABEL
        files[data.POLICY_PATH] = json.dumps(policy).encode()
        with self.assertRaisesRegex(InputRefused, "uses:|already be a commit"):
            self.gate(files, "a2" * 20)

    def test_catalog_installer_and_upstream_sources_are_not_data(self):
        for field, value in (("installer", {"id": 1, "name": "install.sh", "size": 1,
                                            "digest": "sha256:" + "1" * 64}),
                             ("upstream_sources", {"unix.sh": "1" * 64, "linux.sh": "2" * 64})):
            catalog = json.loads(self.files[data.CATALOG_PATH])
            catalog[field] = value
            with self.subTest(field), self.assertRaisesRegex(InputRefused, "only catalog archive rows"):
                self.gate({**self.files, data.CATALOG_PATH: json.dumps(catalog).encode()}, git_sha(field))

    def test_new_bound_pin_must_already_be_on_main_and_bind_only_mirrored_archives(self):
        document = json.loads(self.files[data.DATA_PATH])
        document["reviewed_setup_code"] = []
        self.files = {**self.files, data.DATA_PATH: (json.dumps(document, indent=2) + "\n").encode()}
        self.base = self.start(self.files, "b0" * 20)
        unmerged = git_sha("unmerged")
        self.github.commit(unmerged, unmirrored(self.files))
        with self.assertRaisesRegex(InputRefused, "already be a commit on protected main"):
            self.gate(approve_pin(self.files, unmerged), "b1" * 20)
        self.github.merged(unmerged, self.base)
        with self.assertRaisesRegex(InputRefused, "exactly reviewed setup code"):
            self.gate(approve_pin(self.files, unmerged), "b2" * 20)
        self.files = with_reviewed_setup_code(self.files, self.github)
        self.base = self.start(self.files, "b3" * 20)
        self.github.merged(unmerged, self.base)
        with self.assertRaisesRegex(InputRefused, "only approved mirrored archives"):
            self.gate(approve_pin(self.files, unmerged), "b4" * 20)
        for label, planted in (("root module", {"hashlib.py": b"raise SystemExit('shadowed')\n"}),
                               ("planted bytecode", {"scripts/php_setup/__pycache__/php_linux_bootstrap.cpython-312.pyc":
                                                     b"\xcb\r\r\n\x03\x00\x00\x00planted"})):
            shadowed = self.github.commit(git_sha(label), mirrored({**self.files, **planted}, self.github))
            self.github.merged(shadowed, self.base)
            with self.subTest(label), self.assertRaisesRegex(InputRefused, "bytecode or root Python"):
                self.gate(approve_pin(self.files, shadowed), git_sha("gate " + label))
        changed_code = {**self.files, "scripts/php_setup/php_linux_normalize.py": b"# substituted setup code\n"}
        substituted = self.github.commit(git_sha("changed code"), mirrored(changed_code, self.github))
        self.github.merged(substituted, self.base)
        with self.assertRaisesRegex(InputRefused, "exactly reviewed setup code"):
            self.gate(approve_pin(self.files, substituted), "b5" * 20)

    def test_new_setup_code_identities_are_not_data_approvals(self):
        document = json.loads(self.files[data.DATA_PATH])
        document["reviewed_setup_code"].append({"sha256": "f" * 64, "source": "self-approved"})
        with self.assertRaisesRegex(InputRefused, "runtime review"):
            self.gate({**self.files, data.DATA_PATH: json.dumps(document).encode()}, "b6" * 20)

    def test_runtime_reviewed_setup_code_is_the_only_code_data_may_add_and_pin(self):
        from unittest import mock

        changed_code = {**self.files, "scripts/php_setup/php_linux_normalize.py": b"# runtime-reviewed setup code\n"}
        reviewed = self.github.commit(git_sha("runtime reviewed code"), changed_code)
        self.github.merged(reviewed, self.base)
        entries = {entry["path"]: entry for entry in self.github.records[
            f"/repos/{REPOSITORY}/git/trees/{git_sha('tree' + reviewed)}?recursive=1"]["tree"]}
        digest = data.setup_code_identity(entries)
        document = json.loads(self.files[data.DATA_PATH])
        document["reviewed_setup_code"].append({"sha256": digest, "source": "runtime reviewed"})
        admitted = {**self.files, data.DATA_PATH: (json.dumps(document, indent=2) + "\n").encode()}
        approval = approve_pin(admitted, reviewed)
        with self.assertRaisesRegex(InputRefused, "runtime review"):
            self.gate(approval, "b7" * 20)
        with mock.patch.object(data, "RUNTIME_REVIEWED_SETUP_CODE", frozenset((digest,))):
            self.assertEqual([reviewed], self.gate(approval, "b8" * 20)["pins"])
            # A pin whose code is not runtime-reviewed still refuses beside an admitted digest.
            other = self.github.commit(git_sha("other code"),
                                       {**self.files, "scripts/php_setup/php_linux_normalize.py": b"# other code\n"})
            self.github.merged(other, self.base)
            with self.assertRaisesRegex(InputRefused, "exactly reviewed setup code"):
                self.gate(approve_pin(admitted, other), "b9" * 20)

    def test_checkout_setup_code_is_admitted_by_this_runtime(self):
        """A setup-code change must list its new identity for runtime review in the same change."""
        try:
            listing = subprocess.run(["git", "-C", str(ROOT), "ls-tree", "-r", "-t", "-z", "HEAD"],
                                     capture_output=True, check=True).stdout.decode()
            dirty = subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--", *data.SETUP_TREES,
                                    *data.SETUP_INPUTS], capture_output=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("No git checkout")
        if dirty:
            self.skipTest("Uncommitted setup code has no tree identity yet")
        entries = {}
        for record in filter(None, listing.split("\0")):
            metadata, path = record.split("\t", 1)
            mode, kind, sha = metadata.split()
            entries[path] = {"type": kind, "mode": mode, "sha": sha}
        self.assertIn(data.setup_code_identity(entries),
                      data.RUNTIME_REVIEWED_SETUP_CODE | data.local_data().setup_code)

    def test_new_archive_needs_upstream_provenance_mirror_and_strict_inspection(self):
        compressed = fake_archive("8.3.99")
        files, row = archive_update(self.files, "26.04", compressed, 900000001, 900000101)
        with self.assertRaisesRegex(InputRefused, "published upstream"):
            self.gate(files, "c1" * 20)
        self.github.asset(data.UPSTREAM_REPOSITORY, row["asset"])
        with self.assertRaisesRegex(InputRefused, "mirror asset is absent"):
            self.gate(files, "c2" * 20)
        self.github.asset(MIRROR, row["mirror"])
        with self.assertRaisesRegex(InputRefused, "absent or differs"):
            self.gate(files, "c3" * 20)
        self.archives[900000101] = compressed
        report = self.gate(files, "c4" * 20)
        self.assertEqual([{"asset_id": 900000001, "profile": "initial",
                           "metadata_sha256": row["profile"]["metadata_sha256"]}], report["archives"])
        self.assertEqual([900000101], self.fetched[-1:])

    def test_tampered_records_or_mismatched_hashes_are_refused(self):
        compressed = fake_archive("8.3.99")
        files, row = archive_update(self.files, "26.04", compressed, 900000001, 900000101)
        self.github.asset(data.UPSTREAM_REPOSITORY, row["asset"])
        self.github.asset(MIRROR, row["mirror"])
        self.archives[900000101] = compressed
        archive_path = data.profile_paths("initial")[0]
        tampered = {**files, archive_path: files[archive_path].replace(b"php8.3", b"php8.4")}
        with self.assertRaisesRegex(InputRefused, "differ from the strict inspector"):
            self.gate(tampered, "d1" * 20)
        self.archives[900000101] = fake_archive("substituted bytes")
        with self.assertRaisesRegex(InputRefused, "strict archive inspector refused"):
            self.gate(files, "d2" * 20)
        self.archives[900000101] = compressed
        self.github.asset(MIRROR, dict(row["mirror"], digest="sha256:" + "0" * 64))
        with self.assertRaisesRegex(InputRefused, "mirror asset is absent or differs"):
            self.gate(files, "d3" * 20)
        self.github.asset(MIRROR, row["mirror"])
        self.github.asset(data.UPSTREAM_REPOSITORY, dict(row["asset"], size=row["asset"]["size"] + 1))
        with self.assertRaisesRegex(InputRefused, "published upstream"):
            self.gate(files, "d4" * 20)
        catalog = json.loads(files[data.CATALOG_PATH])
        catalog["archives"][1]["mirror"]["digest"] = "sha256:" + "0" * 64
        with self.assertRaises(InputRefused):
            self.gate({**files, data.CATALOG_PATH: json.dumps(catalog).encode()}, "d5" * 20)

    def test_missing_mirror_fails_closed_even_for_an_already_approved_archive(self):
        catalog = json.loads(self.files[data.CATALOG_PATH])
        row = catalog["archives"][0]
        row["mirror"] = {"repository": MIRROR, "release_tag": "php-sha256-" + row["asset"]["digest"][7:23],
                         "id": 800000001, **{key: row["asset"][key] for key in ("name", "size", "digest")}}
        files = {**self.files, data.CATALOG_PATH: (json.dumps(catalog, indent=2) + "\n").encode()}
        before = len([path for path in self.github.requests if "shivammathur" in path])
        with self.assertRaisesRegex(InputRefused, "mirror asset is absent"):
            self.gate(files, "e1" * 20)
        # Adopting a mirror for an unchanged upstream identity does not re-require upstream.
        self.assertEqual(before, len([path for path in self.github.requests if "shivammathur" in path]))
        self.github.asset(MIRROR, row["mirror"])
        with self.assertRaisesRegex(InputRefused, "absent or differs"):
            self.gate(files, "e2" * 20)
        with self.assertRaisesRegex(InputRefused, "bounded mirror fetch"):
            self.gate(files, "e3" * 20, fetch=False)

    def test_effective_policy_takes_only_bound_setup_pins_from_main(self):
        from scripts.qualification_policy import load_policy

        frozen = load_policy(ROOT / data.POLICY_PATH)
        policy = json.loads(self.files[data.POLICY_PATH])
        releases = policy["action_runtime"]["allowed_releases"]
        releases["evil/action"] = {"f" * 40: "v1"}
        releases[REPOSITORY]["d" * 40] = data.BOUND_LABEL
        del releases[REPOSITORY][CURRENT_PIN]
        main = data.approved_from_files("f" * 40, {**{p: self.files[p] for p in data.RUNTIME_DATA},
                                                   data.POLICY_PATH: json.dumps(policy).encode()})
        effective = data.effective_policy(frozen, main)["action_runtime"]["allowed_releases"]
        self.assertNotIn("evil/action", effective)
        self.assertEqual(data.BOUND_LABEL, effective[REPOSITORY]["d" * 40])
        self.assertNotIn(CURRENT_PIN, effective[REPOSITORY])
        self.assertEqual("clean-trust", effective[REPOSITORY]["75587fc33ff40c34f32ef777293dad56bb6f48c7"])


class RoutineUpdateSimulationTest(Scenario):
    """End to end: a fake PHP 8.3.99 archive replaces 26.04 with data PRs only.

    The runtime is this checkout's frozen code throughout: no runtime file,
    native-policy workflow or ruleset changes. Main starts after the held
    mirror adoption, so every current row is already mirrored.
    """

    def test_next_routine_update_is_data_prs_without_runtime_or_ruleset_change(self):
        start = with_reviewed_setup_code(mirrored(repository_files(), self.github), self.github)
        main = self.start(start)
        runtime = {path: raw for path, raw in start.items()
                   if path.startswith(("scripts/", ".github/workflows/native-policy.yml"))}

        # 1. Data PR: the new archive row, mirror record and re-derived records.
        compressed = fake_archive("8.3.99")
        update, row = archive_update(start, "26.04", compressed, 900000001, 900000101)
        self.github.asset(data.UPSTREAM_REPOSITORY, row["asset"])
        self.github.asset(MIRROR, row["mirror"])
        self.archives[900000101] = compressed
        self.assertTrue(all(path.startswith("qualification/")
                            for path in update if update[path] != start.get(path)))
        report = self.propose(main, update, "a" * 40)
        self.assertTrue(report["data_gate"]["data_change"])
        self.assertEqual([900000001], [item["asset_id"] for item in report["data_gate"]["archives"]])
        main = self.merge("a" * 40, update)
        setup_pin = main  # setup-php-linux at this commit binds the new mirrored archive

        # The adoption PR is refused until main approves the new pin and bytes.
        adopted = adopt_workflows(update, setup_pin)
        with self.assertRaisesRegex(InputRefused, "closed literal|not approved|not allowed"):
            self.propose(main, adopted, "b" * 40)

        # 2. Data PR: approve the merged pin and the pin-substituted workflow bytes.
        approval = approve_pin(update, setup_pin)
        report = self.propose(main, approval, "c" * 40)
        self.assertEqual([setup_pin], report["data_gate"]["pins"])
        self.assertEqual({CI}, {item["path"] for item in report["data_gate"]["workflows"]})
        main = self.merge("c" * 40, approval)

        # 3. Ordinary adoption PR: the workflows now pass against main's data.
        adopted = adopt_workflows(approval, setup_pin)
        report = self.propose(main, adopted, "d" * 40)
        self.assertFalse(report["data_gate"]["data_change"])
        self.assertEqual(main, report["data_commit"])

        # The runtime that judged every step is unchanged.
        self.assertEqual(runtime, {path: adopted[path] for path in runtime})


if __name__ == "__main__":
    unittest.main()


STARTUP_PROBE = r'''
import json, runpy, sys
entry, report = sys.argv[1], sys.argv[2]
opened = []
def audit(event, arguments):
    if event == "open" and isinstance(arguments[0], str):
        opened.append(arguments[0])
sys.addaudithook(audit)
sys.argv = [entry]
code = None
try:
    runpy.run_path(entry, run_name="__main__")
except SystemExit as stop:
    code = stop.code
modules = {name: getattr(module, "__file__", None) for name, module in list(sys.modules.items())}
import sysconfig
stdlib = [sysconfig.get_paths()[key] for key in ("stdlib", "platstdlib")]
with open(report, "w") as output:
    json.dump({"code": code, "opened": opened, "path": sys.path, "modules": modules, "stdlib": stdlib}, output)
'''
SHADOWS = ("hashlib", "ssl", "tarfile", "base64", "json", "tempfile")
# The interpreter the action starts (bootstrap.js execs /usr/bin/python3); images
# without it (python:3.13-slim) use this test's own interpreter instead.
PYTHON = "/usr/bin/python3" if os.access("/usr/bin/python3", os.X_OK) else sys.executable


class SetupStartupClosureTest(unittest.TestCase):
    """Everything setup loads is inside the reviewed setup-code digest.

    The tree is a copy of this checkout with a planted root `hashlib.py` (and
    other stdlib names) and a planted unchecked-hash `.pyc`. Each plant runs
    under a naive start-up (the negative controls) and never under the
    action's exact `python3 -I -S -B -X pycache_prefix=<fresh>` start-up.
    """

    def setUp(self):
        import shutil
        import tempfile

        self.directory = Path(tempfile.mkdtemp(prefix="setup-closure-"))
        self.addCleanup(shutil.rmtree, self.directory)
        self.root = self.directory / "repo"
        ignore = shutil.ignore_patterns("__pycache__", "*.pyc")
        for top in ("scripts", ".github/actions/setup-php-linux", "qualification"):
            shutil.copytree(ROOT / top, self.root / top, ignore=ignore)
        self.marker = self.directory / "planted-code-ran"
        payload = f"open({str(self.marker)!r}, 'a').write(__name__ + '\\n')\n"
        for name in SHADOWS:
            (self.root / f"{name}.py").write_text(payload)
        tag = subprocess.run([PYTHON, "-I", "-c", "import sys; print(sys.implementation.cache_tag)"],
                             capture_output=True, text=True, check=True).stdout.strip()
        planted = self.directory / "planted_source.py"
        planted.write_text(payload)
        self.pyc = self.root / f"scripts/php_setup/__pycache__/php_linux_bootstrap.{tag}.pyc"
        self.pyc.parent.mkdir()
        subprocess.run([PYTHON, "-I", "-c",
                        "import py_compile, sys; py_compile.compile(sys.argv[1], cfile=sys.argv[2], doraise=True, "
                        "invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)", str(planted), str(self.pyc)],
                       check=True)

    def ran(self):
        return self.marker.read_text().split() if self.marker.exists() else []

    def test_plants_execute_under_a_naive_start_up(self):
        for statement in ("import scripts.php_setup.php_linux_bootstrap", "import hashlib"):
            self.marker.unlink(missing_ok=True)
            subprocess.run([PYTHON, "-I", "-S", "-B", "-c",
                            f"import sys; sys.path.insert(0, {str(self.root)!r}); {statement}"],
                           capture_output=True, timeout=30, check=False)
            with self.subTest(statement):
                self.assertNotEqual([], self.ran())

    def test_action_start_up_loads_only_covered_setup_code(self):
        import tempfile

        probe = self.directory / "probe.py"
        probe.write_text(STARTUP_PROBE)
        report = self.directory / "report.json"
        cache = Path(tempfile.mkdtemp(prefix="fresh-cache-", dir=self.directory))
        cache.chmod(0o700)
        entry = self.root / "scripts/php_setup/setup_php_linux.py"
        result = subprocess.run([PYTHON, "-I", "-S", "-B", "-X", f"pycache_prefix={cache}",
                                 str(probe), str(entry), str(report)],
                                cwd=self.root, capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(0, result.returncode, result.stderr)
        observed = json.loads(report.read_text())
        self.assertEqual(1, observed["code"])  # imports done; main refuses the missing entry arguments
        self.assertEqual([], self.ran())
        self.assertNotIn(str(self.root), observed["path"])
        # The action interpreter's own standard library (it may differ from the test's).
        stdlib = {Path(path).resolve() for path in observed["stdlib"]}
        tree = self.root.resolve()
        loaded = set()
        for name, file in observed["modules"].items():
            if file is None or Path(file).resolve() == probe.resolve():
                continue
            path = Path(file).resolve()
            if any(path.is_relative_to(prefix) for prefix in stdlib) and not path.is_relative_to(tree):
                continue
            with self.subTest(module=name):
                self.assertTrue(path.is_relative_to(tree), file)
                relative = path.relative_to(tree).as_posix()
                self.assertTrue(data.setup_code_path(relative), relative)
                loaded.add(relative)
        self.assertTrue({"scripts/php_setup/__init__.py", "scripts/php_setup/php_linux_bootstrap.py",
                         "scripts/php_setup/php_linux_normalize.py"} <= loaded, loaded)
        self.assertTrue(loaded <= set(data.SETUP_MODULES), loaded)
        archive_data = data.gated_paths(data.local_data().catalog) - {data.DATA_PATH, data.POLICY_PATH}
        for file in observed["opened"]:
            path = Path(file).resolve()
            if not path.is_relative_to(tree):
                continue
            relative = path.relative_to(tree).as_posix()
            with self.subTest(opened=relative):
                self.assertNotIn("__pycache__", relative)
                self.assertTrue(data.setup_code_path(relative) or relative in archive_data, relative)
        refused = subprocess.run([PYTHON, "-I", "-S", "-B", str(entry)], cwd=self.root,
                                 capture_output=True, text=True, timeout=30, check=False)
        self.assertEqual(1, refused.returncode)
        self.assertIn("pycache_prefix", refused.stderr)
        self.assertEqual([], self.ran())
        opened = {Path(file).resolve() for file in observed["opened"]}
        self.assertIn(entry.resolve(), opened)
        self.assertNotIn(self.pyc.resolve(), opened)

    def test_every_import_in_reviewed_setup_code_stays_inside_the_import_root(self):
        import ast

        for module in data.SETUP_MODULES:
            tree = ast.parse((ROOT / module).read_text(), module)
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.ImportFrom) and node.level == 1 and node.module is None:
                    names = [data.SETUP_IMPORT_ROOT + alias.name + ".py" for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and (node.level or node.module == "scripts"
                                                           or (node.module or "").startswith(("scripts.", "php_setup"))):
                    names = ["other package import " + str(node.module)]
                elif isinstance(node, ast.Import):
                    names = ["absolute " + alias.name for alias in node.names
                             if alias.name.split(".")[0] in {"scripts", "php_setup"}]
                elif isinstance(node, ast.Name) and node.id in {"__import__", "exec", "eval", "runpy"}:
                    names = ["dynamic " + node.id]
                for name in names:
                    with self.subTest(module=module, imports=name):
                        self.assertIn(name, data.SETUP_MODULES)


class SetupImportRootManifestTest(unittest.TestCase):
    """Nothing can be added beside a reviewed module in the setup import root."""

    def setUp(self):
        self.github = FakeGitHub()
        self.files = repository_files()

    def identity(self, files, modes=None):
        sha = git_sha(json.dumps(sorted(files)) + json.dumps(modes or {}))
        self.github.commit(sha, files, modes=modes)
        tree = self.github.records[f"/repos/{REPOSITORY}/git/trees/{git_sha('tree' + sha)}?recursive=1"]["tree"]
        return data.setup_code_identity({entry["path"]: entry for entry in tree})

    def test_the_reviewed_manifest_is_exactly_the_import_root(self):
        on_disk = {path.relative_to(ROOT).as_posix() for path in (ROOT / data.SETUP_IMPORT_ROOT).iterdir()
                   if path.name != "__pycache__"}
        self.assertEqual(set(data.SETUP_MODULES), on_disk)
        self.identity(self.files)  # this checkout's tree is an admissible exact manifest

    def test_plants_beside_reviewed_modules_refuse(self):
        root = data.SETUP_IMPORT_ROOT
        plants = {
            "package directory": {root + "php_linux_archive/__init__.py": b"raise SystemExit('planted')\n"},
            "abi3 extension": {root + "php_linux_archive.abi3.so": b"\x7fELF planted"},
            "versioned extension": {root + "php_linux_archive.cpython-312-x86_64-linux-gnu.so": b"\x7fELF"},
            "plain extension": {root + "php_linux_recipe.so": b"\x7fELF planted"},
            "extra file": {root + "notes.txt": b"anything\n"},
            "bytecode": {root + "__pycache__/php_linux_bootstrap.cpython-312.pyc": b"planted"},
        }
        for label, planted in plants.items():
            with self.subTest(label), self.assertRaises(InputRefused):
                self.identity({**self.files, **planted})
        link = root + "php_linux_recipe"
        with self.assertRaisesRegex(InputRefused, "never links"):
            self.identity({**self.files, link: b"php_linux_tools.py"}, modes={link: "120000"})
        removed = {path: raw for path, raw in self.files.items() if path != root + "php_linux_tools.py"}
        with self.assertRaisesRegex(InputRefused, "exactly the reviewed modules"):
            self.identity(removed)

    def test_any_other_change_under_the_setup_trees_changes_the_digest(self):
        reviewed = self.identity(self.files)
        for path in (".github/actions/setup-php-linux/vendor/node_modules/x/index.js",
                     "qualification/vendor/extra.sh", "qualification/php-tools/extra.json"):
            with self.subTest(path):
                self.assertNotEqual(reviewed, self.identity({**self.files, path: b"planted\n"}))
        self.assertEqual(reviewed, self.identity({**self.files, "scripts/unrelated_tool.py": b"pass\n"}))

    def test_archive_attributes_are_refused_at_root_and_nested_paths(self):
        for path in (".gitattributes", ".github/actions/.gitattributes", "docs/.gitattributes"):
            with self.subTest(path), self.assertRaisesRegex(InputRefused, r"\.gitattributes"):
                self.identity({**self.files, path: b"# test metadata\n"})
