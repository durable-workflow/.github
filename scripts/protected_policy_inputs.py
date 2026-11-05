"""Read a PR's policy inputs as bounded data, without checking out candidate code."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


MAX_TREE_ENTRIES = 20_000
MAX_FILES = 256
MAX_FILE_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 8 * 1024 * 1024
SHA = re.compile(r"[0-9a-f]{40}")
SLUG = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}")
HELPERS = re.compile(r"(?:\./)?(?:scripts|\.github)/[A-Za-z0-9_./-]+")
ReadJson = Callable[[str], Any]


class InputRefused(ValueError):
    """Candidate identity or input data cannot be verified within the bounds."""


def checked_sha(value: object) -> str:
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise InputRefused("An exact GitHub commit or blob identity is required")
    return value


def checked_slug(value: object) -> str:
    if (
        not isinstance(value, str)
        or SLUG.fullmatch(value) is None
        or any(part in {".", ".."} for part in value.split("/"))
    ):
        raise InputRefused("A GitHub owner/repository identity is required")
    return value


def checked_path(value: object) -> str:
    if not isinstance(value, str) or len(value) > 1024 or not value:
        raise InputRefused("Invalid policy input path")
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or not path.parts
        or path.as_posix() != value
        or any(part in {".", ".."} for part in path.parts)
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise InputRefused("Policy input path must be canonical and repository-relative")
    return value


def positive_id(value: object) -> int:
    if type(value) is not int or value <= 0:
        raise InputRefused("A positive GitHub object ID is required")
    return value


@dataclass(frozen=True)
class PullIdentity:
    repository: str
    repository_id: int
    number: int
    base_sha: str
    head_sha: str
    head_repository: str
    head_repository_id: int


def read_identity(
    read: ReadJson, repository: str, repository_id: int, number: int, expected_base_sha: str,
) -> PullIdentity:
    checked_slug(repository)
    if not repository.startswith("durable-workflow/"):
        raise InputRefused("The protected gate is limited to Durable Workflow repositories")
    positive_id(repository_id)
    positive_id(number)
    checked_sha(expected_base_sha)
    record = read(f"/repos/{repository}/pulls/{number}")
    try:
        base, head = record["base"], record["head"]
        if (
            record["state"] != "open"
            or positive_id(record["number"]) != number
            or base["ref"] != "main"
            or base["sha"] != expected_base_sha
            or base["repo"]["full_name"] != repository
            or positive_id(base["repo"]["id"]) != repository_id
            or base["repo"]["private"] is not False
            or head["repo"]["private"] is not False
        ):
            raise InputRefused("The PR must remain open against the expected repository main branch")
        return PullIdentity(
            repository, repository_id, number, checked_sha(base["sha"]), checked_sha(head["sha"]),
            checked_slug(head["repo"]["full_name"]), positive_id(head["repo"]["id"]),
        )
    except (KeyError, TypeError) as error:
        raise InputRefused("Incomplete GitHub PR identity") from error


def require_current(read: ReadJson, identity: PullIdentity) -> None:
    if read_identity(
        read, identity.repository, identity.repository_id, identity.number, identity.base_sha,
    ) != identity:
        raise InputRefused("PR head, base or repository changed during policy validation")


def _tree_entries(read: ReadJson, identity: PullIdentity) -> dict[str, dict]:
    prefix = f"/repos/{identity.head_repository}/git"
    commit = read(f"{prefix}/commits/{identity.head_sha}")
    try:
        if checked_sha(commit["sha"]) != identity.head_sha:
            raise InputRefused("GitHub returned another candidate commit")
        tree_sha = checked_sha(commit["tree"]["sha"])
        tree = read(f"{prefix}/trees/{tree_sha}?recursive=1")
        entries = tree["tree"]
        if (
            tree.get("truncated") is not False
            or checked_sha(tree["sha"]) != tree_sha
            or not isinstance(entries, list)
            or len(entries) > MAX_TREE_ENTRIES
        ):
            raise InputRefused("Candidate tree is incomplete or exceeds the input bound")
        result = {}
        for entry in entries:
            path = checked_path(entry["path"])
            if path in result:
                raise InputRefused("Candidate tree contains a duplicate path")
            result[path] = entry
        return result
    except (KeyError, TypeError) as error:
        raise InputRefused("Malformed GitHub tree metadata") from error


def _text_blob(read: ReadJson, repository: str, entry: dict) -> bytes:
    if (
        entry.get("type") != "blob"
        or entry.get("mode") not in {"100644", "100755"}
        or type(entry.get("size")) is not int
        or not 0 <= entry["size"] <= MAX_FILE_BYTES
    ):
        raise InputRefused("Policy input must be a bounded regular file, never a symlink or submodule")
    sha = checked_sha(entry.get("sha"))
    blob = read(f"/repos/{repository}/git/blobs/{sha}")
    try:
        content = blob["content"]
        if (
            blob["sha"] != sha
            or blob["encoding"] != "base64"
            or type(blob["size"]) is not int
            or blob["size"] != entry["size"]
            or not isinstance(content, str)
            or len(content) > MAX_FILE_BYTES * 2
        ):
            raise InputRefused("GitHub blob identity, size or encoding does not match the candidate tree")
        raw = base64.b64decode(content.replace("\n", ""), validate=True)
        if len(raw) != entry["size"]:
            raise InputRefused("GitHub blob contents do not match the declared size")
        raw.decode("utf-8")
        return raw
    except (KeyError, TypeError, UnicodeError, binascii.Error) as error:
        raise InputRefused("Policy input must be valid UTF-8 in a verified GitHub blob") from error


def _referenced_inputs(raw: bytes, entries: dict[str, dict], collected: dict[str, bytes]) -> list[str]:
    result = []
    for helper in HELPERS.findall(raw.decode("utf-8")):
        helper = checked_path(helper.removeprefix("./"))
        if helper in entries and entries[helper].get("type") != "tree" and helper not in collected:
            result.append(helper)
    return result


def collect_inputs(read: ReadJson, identity: PullIdentity) -> dict[str, bytes]:
    entries = _tree_entries(read, identity)
    pending = sorted(
        path for path in entries
        if PurePosixPath(path).parent.as_posix() == ".github/workflows" and path.endswith((".yml", ".yaml"))
    )
    if not pending:
        raise InputRefused("Candidate has no workflow files")
    collected: dict[str, bytes] = {}
    total = 0
    while pending:
        path = pending.pop()
        if path in collected:
            continue
        if len(collected) >= MAX_FILES:
            raise InputRefused("Too many workflow or referenced helper inputs")
        raw = _text_blob(read, identity.head_repository, entries[path])
        total += len(raw)
        if total > MAX_TOTAL_BYTES:
            raise InputRefused("Workflow and helper inputs exceed the total byte bound")
        collected[path] = raw
        pending.extend(_referenced_inputs(raw, entries, collected))
    require_current(read, identity)
    return collected


def write_inputs(files: dict[str, bytes], destination: Path) -> None:
    """Materialize data in a new directory, without preserving executable modes."""
    if len(files) > MAX_FILES:
        raise InputRefused("Policy materialization exceeds the file bound")
    for name, contents in files.items():
        checked_path(name)
        if not isinstance(contents, bytes) or len(contents) > MAX_FILE_BYTES:
            raise InputRefused("Policy materialization requires bounded byte strings")
    if sum(len(value) for value in files.values()) > MAX_TOTAL_BYTES:
        raise InputRefused("Policy materialization exceeds the byte bound")
    destination.mkdir(mode=0o700)
    for name, contents in files.items():
        path = destination / checked_path(name)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open("xb") as handle:
            handle.write(contents)
        path.chmod(0o600)
