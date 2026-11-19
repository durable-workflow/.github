"""Approved policy inputs are data on protected main, never PR-head code.

The frozen policy runtime keeps every check. What it approves comes from data
committed to `refs/heads/main` of durable-workflow/.github:

* `qualification/protected-policy-data.json`: reviewed exact workflow bytes
  (SHA-256 per path, with the reviewed fixture bytes where they exist);
* `qualification/policy.json`: the `bound-linux-php` setup action pins;
* `qualification/php-linux-bootstrap.json` and the per-profile records: the
  approved PHP archives, their mirror location and normalization records.

The runtime reads that data from the protected main commit (for the control
repository: the PR or merge-group base, which must equal main). It never reads
it from the candidate head, so a PR cannot approve itself. A PR that changes
the data passes only through `gate_data_change`, which admits only objectively
verifiable routine additions: archives with live upstream provenance, a
byte-identical mirror and strict-inspector records; `bound-linux-php` pins at
commits in the PR's own ancestry whose catalog binds only those archives; and
workflow bytes that differ from already reviewed bytes only by substituting
one approved setup pin for another. Anything else stays a runtime review.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
from typing import Any, Callable

from scripts.protected_policy_inputs import (
    CONTROL_TARGET, CommitIdentity, InputRefused, _text_blob, _tree_entries, checked_path, checked_sha,
    checked_slug,
)

ROOT = Path(__file__).resolve().parents[1]
DATA_REPOSITORY = CONTROL_TARGET.repository
SCHEMA = "durable-workflow.protected-policy-data/v1"
DATA_PATH = "qualification/protected-policy-data.json"
POLICY_PATH = "qualification/policy.json"
CATALOG_PATH = "qualification/php-linux-bootstrap.json"
RUNTIME_DATA = (DATA_PATH, POLICY_PATH, CATALOG_PATH)
PROFILE_RECORDS = ("archive", "normalization", "alternatives")
BOUND_LABEL = "bound-linux-php"
UPSTREAM_REPOSITORY = "shivammathur/php-ubuntu"
TARGETS = ("github-control-plane", "ai")
REGISTRY = re.compile(r"[a-z0-9_]{1,80}")
DIGEST = re.compile(r"[0-9a-f]{64}")
COMMIT_TOKEN = re.compile(rb"[0-9a-f]{40}")
MAX_ENTRIES = 512
# Everything the bound setup action executes or reads, except the archive data
# (catalog and profile records). A new setup pin must have exactly the code of
# reviewed setup code: routine pins change data, never code.
SETUP_CODE = (".github/actions/setup-php-linux/", "scripts/__init__.py", "scripts/setup_php_linux.py",
              "scripts/php_linux_", "qualification/vendor/", "qualification/setup-php-source.json",
              "qualification/php-linux-tools.json")


def profile_paths(name: str) -> tuple[str, ...]:
    return tuple(f"qualification/php-linux-{name}-{kind}.json" for kind in PROFILE_RECORDS)


def gated_paths(*catalogs: dict) -> set[str]:
    paths = set(RUNTIME_DATA)
    for catalog in catalogs:
        for row in catalog.get("archives", []) if isinstance(catalog, dict) else ():
            if isinstance(row, dict) and isinstance(row.get("profile"), dict):
                name = row["profile"].get("name")
                if isinstance(name, str) and re.fullmatch(r"[a-z0-9]{1,32}", name):
                    paths.update(profile_paths(name))
    return paths


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputRefused("Protected data JSON contains a duplicate member")
        result[key] = value
    return result


def strict_json(raw: bytes, label: str) -> Any:
    def constant(_value):
        raise InputRefused(f"{label} contains a non-finite number")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique, parse_constant=constant)
    except InputRefused:
        raise
    except (UnicodeError, ValueError, RecursionError) as error:
        raise InputRefused(f"{label} is not strict UTF-8 JSON") from error


def validate_document(document: Any) -> dict:
    """Closed schema for the reviewed-workflow registry."""
    if not isinstance(document, dict) or set(document) != {"schema", "reviewed_setup_code", "reviewed_workflows"}:
        raise InputRefused("Protected policy data has unexpected fields")
    if document["schema"] != SCHEMA:
        raise InputRefused("Unknown protected policy data schema")
    code = document["reviewed_setup_code"]
    if (not isinstance(code, list) or len(code) > MAX_ENTRIES
            or any(not isinstance(item, dict) or set(item) != {"sha256", "source"}
                   or not isinstance(item["sha256"], str) or DIGEST.fullmatch(item["sha256"]) is None
                   or not isinstance(item["source"], str) or not 0 < len(item["source"]) <= 200
                   for item in code)
            or len({item["sha256"] for item in code}) != len(code)):
        raise InputRefused("Reviewed setup code identities must be unique exact digests")
    registries = document["reviewed_workflows"]
    if not isinstance(registries, dict) or set(registries) != set(TARGETS):
        raise InputRefused("Protected policy data must name exactly the supported targets")
    for target, entries in registries.items():
        if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
            raise InputRefused("Reviewed workflow entries must be a bounded list")
        seen = set()
        for entry in entries:
            if not isinstance(entry, dict) or not {"registry", "path", "sha256"} <= set(entry) \
                    or not set(entry) <= {"registry", "path", "sha256", "fixture", "derived_from"}:
                raise InputRefused("Reviewed workflow entry has unexpected fields")
            path = checked_path(entry["path"])
            if (PurePosixPath(path).parent.as_posix() != ".github/workflows"
                    or not path.endswith((".yml", ".yaml"))
                    or not isinstance(entry["registry"], str) or REGISTRY.fullmatch(entry["registry"]) is None
                    or not isinstance(entry["sha256"], str) or DIGEST.fullmatch(entry["sha256"]) is None):
                raise InputRefused("Reviewed workflow entry is not an exact workflow identity")
            if "fixture" in entry:
                fixture = checked_path(entry["fixture"])
                if not fixture.startswith("tests/fixtures/") or not fixture.endswith((".yml", ".yaml")):
                    raise InputRefused("Reviewed workflow bytes must be a tests/fixtures workflow")
            if "derived_from" in entry and (not isinstance(entry["derived_from"], str)
                                            or DIGEST.fullmatch(entry["derived_from"]) is None):
                raise InputRefused("A derived reviewed workflow must name its reviewed predecessor")
            identity = (path, entry["sha256"])
            if identity in seen:
                raise InputRefused("Duplicate reviewed workflow identity")
            seen.add(identity)
    return document


@dataclass(frozen=True)
class ApprovedData:
    commit: str
    document: dict
    policy: dict
    catalog: dict
    raw: dict

    def reviewed(self, target: str) -> dict[str, set[str]]:
        if target not in TARGETS:
            raise InputRefused("Unsupported protected policy context target")
        result: dict[str, set[str]] = {}
        for entry in self.document["reviewed_workflows"][target]:
            result.setdefault(entry["path"], set()).add(entry["sha256"])
        return result

    def entries(self, target: str) -> dict[tuple[str, str], dict]:
        return {(entry["path"], entry["sha256"]): entry for entry in self.document["reviewed_workflows"][target]}

    @property
    def setup_code(self) -> frozenset[str]:
        return frozenset(item["sha256"] for item in self.document["reviewed_setup_code"])

    @property
    def bound_setups(self) -> frozenset[str]:
        releases = self.policy["action_runtime"]["allowed_releases"].get(DATA_REPOSITORY, {})
        return frozenset(sha for sha, label in releases.items() if label == BOUND_LABEL)


def approved_from_files(commit: str, files: dict[str, bytes]) -> ApprovedData:
    from scripts import php_linux_bootstrap as bootstrap
    from scripts.qualification_policy import PolicyError, validate_policy

    missing = [path for path in RUNTIME_DATA if path not in files]
    if missing:
        raise InputRefused("Protected main lacks approved policy data: " + ", ".join(missing))
    document = validate_document(strict_json(files[DATA_PATH], DATA_PATH))
    policy = strict_json(files[POLICY_PATH], POLICY_PATH)
    try:
        validate_policy(policy)
    except (PolicyError, KeyError, TypeError) as error:
        raise InputRefused("Protected main has an invalid action policy") from error
    catalog = strict_json(files[CATALOG_PATH], CATALOG_PATH)
    try:
        bootstrap.validate_catalog(catalog)
    except (ValueError, KeyError, TypeError) as error:
        raise InputRefused("Protected main has an invalid PHP archive catalog") from error
    return ApprovedData(commit, document, policy, catalog, dict(files))


def local_data(root: Path = ROOT) -> ApprovedData:
    """This checkout's copy, for offline tools and source tests only."""
    return approved_from_files("0" * 40, {path: (root / path).read_bytes() for path in RUNTIME_DATA})


def read_commit_files(read, repository: str, sha: str, paths, *, entries=None) -> dict[str, bytes]:
    """Read named regular files of one exact commit as data; absent paths are omitted."""
    identity = CommitIdentity(checked_slug(repository), checked_sha(sha))
    entries = _tree_entries(read, identity) if entries is None else entries
    return {path: _text_blob(read, repository, entries[path]) for path in sorted(paths) if path in entries}


def main_data(read, *, expected_sha: str | None = None) -> ApprovedData:
    """Approved data from the current protected main commit of the control repository."""
    record = read(f"/repos/{DATA_REPOSITORY}/branches/main")
    try:
        if record["name"] != "main" or record["protected"] is not True:
            raise InputRefused("Approved policy data requires the protected main branch")
        sha = checked_sha(record["commit"]["sha"])
    except (KeyError, TypeError) as error:
        raise InputRefused("Incomplete protected-branch metadata for approved data") from error
    if expected_sha is not None and sha != expected_sha:
        raise InputRefused("Approved policy data must come from the protected base commit")
    return approved_from_files(sha, read_commit_files(read, DATA_REPOSITORY, sha, RUNTIME_DATA))


def effective_policy(frozen: dict, data: ApprovedData) -> dict:
    """The runtime's frozen policy with main's bound setup pins.

    Only `bound-linux-php` pins of this repository come from main; every
    other release, label, image and target rule stays the reviewed runtime's.
    Retiring a bound pin on main therefore also takes effect.
    """
    result = copy.deepcopy(frozen)
    releases = result["action_runtime"]["allowed_releases"].setdefault(DATA_REPOSITORY, {})
    for sha in [sha for sha, label in releases.items() if label == BOUND_LABEL]:
        del releases[sha]
    for sha in data.bound_setups:
        if releases.get(sha, BOUND_LABEL) != BOUND_LABEL:
            raise InputRefused("A bound setup pin cannot also carry another reviewed role")
        releases[sha] = BOUND_LABEL
    result["action_runtime"]["allowed_releases"][DATA_REPOSITORY] = dict(sorted(releases.items()))
    return result


# ---------------------------------------------------------------------------
# Data-change gate.


def setup_code_identity(entries: dict) -> str:
    """Digest of the setup action's code closure: exact paths, modes and git blob IDs."""
    rows = []
    for path, entry in sorted(entries.items()):
        if not path.startswith(SETUP_CODE):
            continue
        if (entry.get("type") != "blob" or entry.get("mode") not in {"100644", "100755"}
                or not isinstance(entry.get("sha"), str)):
            raise InputRefused("Setup code must be regular files")
        rows.append([path, entry["mode"], checked_sha(entry["sha"])])
    if not rows:
        raise InputRefused("No setup code at the selected commit")
    return hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest()


def routine_substitution(old: bytes, new: bytes, old_pins: frozenset[str], new_pins: frozenset[str]) -> str:
    """Return the one new pin if `new` is `old` with only approved pins replaced."""
    old_parts, new_parts = COMMIT_TOKEN.split(old), COMMIT_TOKEN.split(new)
    old_tokens, new_tokens = COMMIT_TOKEN.findall(old), COMMIT_TOKEN.findall(new)
    if old_parts != new_parts or len(old_tokens) != len(new_tokens):
        raise InputRefused("A data-approved workflow may change only commit pins of reviewed bytes")
    replaced = {(before.decode(), after.decode()) for before, after in zip(old_tokens, new_tokens) if before != after}
    targets = {after for _before, after in replaced}
    if (not replaced or len(targets) != 1 or any(before not in old_pins for before, _after in replaced)
            or not targets <= new_pins):
        raise InputRefused("A data-approved workflow may only replace approved bound setup pins with one new pin")
    return targets.pop()


def asset_matches(record: Any, identity: dict) -> bool:
    return (isinstance(record, dict) and record.get("id") == identity["id"]
            and record.get("name") == identity["name"] and record.get("size") == identity["size"]
            and record.get("digest") == identity["digest"] and record.get("state") == "uploaded")


def _optional(read, path: str):
    try:
        return read(path)
    except InputRefused:
        return None


def api_provenance(read, row: dict, *, upstream: bool) -> None:
    """Live release-asset metadata must bind the same bytes (fails closed on 404)."""
    if upstream and not asset_matches(
            _optional(read, f"/repos/{UPSTREAM_REPOSITORY}/releases/assets/{row['asset']['id']}"), row["asset"]):
        raise InputRefused("A newly approved archive must be published upstream with the same bytes")
    mirror = row["mirror"]
    if mirror is None:
        raise InputRefused("A newly approved archive must be mirrored to the reviewed immutable release")
    if not asset_matches(_optional(read, f"/repos/{mirror['repository']}/releases/assets/{mirror['id']}"), mirror):
        raise InputRefused("The archive mirror asset is absent or differs from the reviewed bytes")


def inspect_records(compressed: bytes, row: dict, files: dict[str, bytes]) -> dict:
    """Strict inspector: re-derive records from the exact bytes and compare byte-for-byte."""
    from scripts import php_linux_bootstrap as bootstrap
    from scripts import php_linux_profile_records as records

    identity, profile = row["asset"], row["profile"]
    archive, normalization, alternatives = profile_paths(profile["name"])
    try:
        metadata_raw, plan_raw = records.records(compressed, identity)
    except (ValueError, OSError) as error:
        raise InputRefused("The strict archive inspector refused the mirrored bytes") from error
    if files.get(archive) != metadata_raw or files.get(normalization) != plan_raw:
        raise InputRefused("Committed archive records differ from the strict inspector's derivation")
    plan = json.loads(plan_raw)
    inventory = files.get(alternatives)
    if (bootstrap.sha256(metadata_raw) != profile["metadata_sha256"]
            or bootstrap.sha256(plan_raw) != profile["plan_sha256"]
            or [plan["expected_members"], plan["expected_regular_files"], plan["expected_directories"]]
            != profile["counts"]
            or inventory is None or bootstrap.sha256(inventory) != profile["inventory_sha256"]
            or strict_json(inventory, alternatives).get("archive_metadata_sha256") != profile["metadata_sha256"]):
        raise InputRefused("The catalog profile does not bind the inspected records")
    return {"asset_id": identity["id"], "profile": profile["name"], "metadata_sha256": profile["metadata_sha256"]}


def _changed(base_entries: dict, head_entries: dict, paths) -> set[str]:
    return {path for path in paths
            if (base_entries.get(path) or {}).get("sha") != (head_entries.get(path) or {}).get("sha")}


def _workflow_paths(entries: dict) -> set[str]:
    return {path for path in entries if path.startswith(".github/")}


def gate_data_change(read, head_repository: str, head_sha: str, base: ApprovedData, *,
                     head_entries: dict | None = None,
                     fetch_archive: Callable[[dict, dict], bytes] | None = None) -> dict:
    """Refuse a PR's data change unless it is an objectively verified routine addition."""
    head_repository, head_sha = checked_slug(head_repository), checked_sha(head_sha)
    base_entries = _tree_entries(read, CommitIdentity(DATA_REPOSITORY, base.commit))
    if head_entries is None:
        head_entries = _tree_entries(read, CommitIdentity(head_repository, head_sha))
    from scripts import php_linux_bootstrap as bootstrap

    paths = gated_paths(base.catalog).union(*(profile_paths(name) for name in sorted(bootstrap.PROFILE_NAMES)))
    changed = _changed(base_entries, head_entries, paths)
    if not changed:
        return {"data_change": False}
    head_files = read_commit_files(read, head_repository, head_sha, RUNTIME_DATA, entries=head_entries)
    head = approved_from_files(head_sha, head_files)
    if head.setup_code - base.setup_code:
        raise InputRefused("Approving new setup code is a runtime review, not a data change")
    if changed == {POLICY_PATH} and head.bound_setups == base.bound_setups:
        # Consumer action policy outside the bound setup role is not runtime data.
        return {"data_change": False}
    if _changed(base_entries, head_entries, _workflow_paths(base_entries) | _workflow_paths(head_entries)):
        raise InputRefused("A protected data change must be a data-only PR without workflow or action changes")
    record_paths = gated_paths(head.catalog) - set(RUNTIME_DATA)
    head_files.update(read_commit_files(read, head_repository, head_sha, record_paths, entries=head_entries))
    report = {"data_change": True, "changed": sorted(changed), "workflows": [], "pins": [], "archives": []}

    # Reviewed workflow bytes: removals tighten; additions must be routine derivations.
    for target in TARGETS:
        before, after = base.entries(target), head.entries(target)
        for key, entry in after.items():
            if key in before:
                if before[key] != entry:
                    raise InputRefused("An existing reviewed workflow approval is immutable")
                continue
            predecessor = before.get((entry["path"], entry.get("derived_from")))
            if predecessor is None or "fixture" not in predecessor or "fixture" not in entry:
                raise InputRefused("A new reviewed workflow needs a runtime review unless it derives from reviewed bytes")
            old = read_commit_files(read, DATA_REPOSITORY, base.commit, [predecessor["fixture"]],
                                    entries=base_entries).get(predecessor["fixture"])
            new = read_commit_files(read, head_repository, head_sha, [entry["fixture"]],
                                    entries=head_entries).get(entry["fixture"])
            if (old is None or new is None or hashlib.sha256(old).hexdigest() != predecessor["sha256"]
                    or hashlib.sha256(new).hexdigest() != entry["sha256"]):
                raise InputRefused("Reviewed workflow fixtures do not hold the approved bytes")
            pin = routine_substitution(old, new, base.bound_setups, head.bound_setups)
            report["workflows"].append({"target": target, "path": entry["path"], "sha256": entry["sha256"],
                                        "derived_from": predecessor["sha256"], "pin": pin})

    # Approved archives: a new upstream identity needs live provenance; any new or
    # changed row needs its mirror and the strict inspector over the mirrored bytes.
    base_rows = {json.dumps(row, sort_keys=True) for row in base.catalog["archives"]}
    base_assets = {json.dumps(row["asset"], sort_keys=True) for row in base.catalog["archives"]}
    changed_profiles = {PurePosixPath(path).name.removeprefix("php-linux-").rsplit("-", 1)[0]
                        for path in changed if path in record_paths}
    for row in head.catalog["archives"]:
        changed_row = json.dumps(row, sort_keys=True) not in base_rows
        if row["profile"] is None:
            if changed_row:
                raise InputRefused("A data-approved archive must bind its normalization profile")
            continue
        if not changed_row and row["profile"]["name"] not in changed_profiles:
            continue
        api_provenance(read, row, upstream=json.dumps(row["asset"], sort_keys=True) not in base_assets)
        if fetch_archive is None:
            raise InputRefused("Archive inspection requires the bounded mirror fetch")
        compressed = fetch_archive(row, head.catalog)
        report["archives"].append(inspect_records(compressed, row, head_files))

    # Bound setup pins: only commits already on protected main (any merge method
    # keeps them reachable), whose catalog binds only approved mirrored rows.
    head_rows = {json.dumps(row, sort_keys=True) for row in head.catalog["archives"]}
    for pin in sorted(head.bound_setups - base.bound_setups):
        comparison = _optional(read, f"/repos/{DATA_REPOSITORY}/compare/{pin}...{base.commit}")
        if not isinstance(comparison, dict) or comparison.get("status") not in {"ahead", "identical"}:
            raise InputRefused("A new bound setup pin must already be a commit on protected main")
        pinned_entries = _tree_entries(read, CommitIdentity(DATA_REPOSITORY, pin))
        if setup_code_identity(pinned_entries) not in base.setup_code:
            raise InputRefused("A new bound setup pin must carry exactly reviewed setup code")
        pinned = read_commit_files(read, DATA_REPOSITORY, pin, [CATALOG_PATH],
                                   entries=pinned_entries).get(CATALOG_PATH)
        if pinned is None:
            raise InputRefused("A bound setup pin must carry the PHP archive catalog")
        catalog = strict_json(pinned, CATALOG_PATH)
        try:
            rows = bootstrap.setup_rows(catalog)
        except (ValueError, KeyError, TypeError) as error:
            raise InputRefused("A bound setup pin's catalog is not a reviewed setup catalog") from error
        if any(row["mirror"] is None or json.dumps(row, sort_keys=True) not in head_rows | base_rows
               for row in rows.values()):
            raise InputRefused("A bound setup pin may bind only approved mirrored archives")
        report["pins"].append(pin)
    return report


def mirror_fetcher(bundle: Path, expected_ca_sha256: str):
    """Download the mirror bytes through setup's exact-ID, sealed, bounded fetch."""
    import os

    from scripts import php_linux_bootstrap as bootstrap

    context = bootstrap.explicit_trust(bundle, expected_ca_sha256)

    def fetch(row: dict, catalog: dict) -> bytes:
        try:
            with bootstrap.download_held(row["asset"], context, catalog=catalog) as held:
                held.assert_sealed()
                chunks, offset = [], 0
                while chunk := os.pread(held.descriptor, 1 << 20, offset):
                    chunks.append(chunk)
                    offset += len(chunk)
                return b"".join(chunks)
        except (ValueError, OSError) as error:
            raise InputRefused("The mirrored archive is absent or differs from its pinned bytes") from error
    return fetch
