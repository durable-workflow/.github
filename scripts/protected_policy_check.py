"""Read-only pilot runner for the protected workflow-policy check.

An enforcement caller must use the reviewed central checkout. Candidate inputs
remain data in a separate temporary directory. Ordinary CI can exercise this
client, but does not issue a Check Run or establish its App identity. The
protected issuer must independently recheck the PR identity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from typing import Any

# Python -I excludes both the working directory and the script directory.
# Add only this reviewed checkout, never the candidate materialization root.
ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from scripts.protected_policy_inputs import (  # noqa: E402
    MAX_FILES, MAX_TREE_ENTRIES, InputRefused, collect_inputs, read_identity, require_current, write_inputs,
)

PILOT_REPOSITORY = "durable-workflow/.github"
PILOT_REPOSITORY_ID = 575230056
MAX_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_REQUESTS = MAX_FILES + 16
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = MAX_TREE_ENTRIES * 16
TOTAL_SECONDS = 120
REQUEST_SECONDS = 15
ENDPOINT = re.compile(
    r"/repos/[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}/(?:"
    r"pulls/[1-9][0-9]*|branches/main|git/commits/[0-9a-f]{40}|"
    r"git/trees/[0-9a-f]{40}\?recursive=1|git/blobs/[0-9a-f]{40})"
)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputRefused("GitHub JSON contains a duplicate member")
        result[key] = value
    return result


def reject_constant(_value: str) -> None:
    raise InputRefused("GitHub JSON contains a non-finite number")


def decode_metadata(raw: str) -> dict[str, Any]:
    try:
        value = json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    except (ValueError, RecursionError) as error:
        raise InputRefused("GitHub did not provide unambiguous bounded JSON") from error
    if not isinstance(value, dict):
        raise InputRefused("The selected GitHub endpoints must return JSON objects")
    # Validate the standard decoder's result without recursively walking an
    # attacker-controlled structure or relying on Python's parser stack limit.
    pending, count = [(value, 0)], 0
    while pending:
        item, depth = pending.pop()
        count += 1
        if depth > MAX_JSON_DEPTH or count > MAX_JSON_NODES:
            raise InputRefused("GitHub JSON exceeds the structure bound")
        if isinstance(item, dict):
            children = item.values()
        elif isinstance(item, list):
            children = item
        else:
            children = ()
        if len(children) > MAX_JSON_NODES:
            raise InputRefused("GitHub JSON exceeds the collection bound")
        pending.extend((child, depth + 1) for child in children)
    return value


class GitHubReadClient:
    """Use curl's byte and wall-clock limits, without redirects or decompression."""

    def __init__(self, bundle: Path, directory: Path, expected_digest: str, token: str = "", *,
                 run=subprocess.run, clock=time.monotonic):
        self.run, self.clock = run, clock
        self.deadline = clock() + TOTAL_SECONDS
        self.requests = 0
        if token and re.fullmatch(r"[A-Za-z0-9_.-]+", token) is None:
            raise InputRefused("The read credential has an invalid format")
        self.config = f'header = "Authorization: Bearer {token}"\n' if token else ""
        if (bundle.is_symlink() or not bundle.is_file() or bundle.stat().st_size > 2 * 1024 * 1024
                or directory.is_symlink() or not directory.is_dir() or any(directory.iterdir())):
            raise InputRefused("Explicit reviewed CA file and empty additional-root directory are required")
        if (re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
                or hashlib.sha256(bundle.read_bytes()).hexdigest() != expected_digest):
            raise InputRefused("The selected CA file does not match the reviewed bootstrap digest")
        self.bundle, self.directory = str(bundle.resolve()), str(directory.resolve())
        try:
            version = run(["/usr/bin/curl", "--disable", "--version"], stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=2, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise InputRefused("Cannot inspect the fixed curl executable") from error
        match = re.match(rb"curl (\d+)\.(\d+)\.(\d+)\b", version.stdout)
        if version.returncode or not match or tuple(map(int, match.groups())) < (8, 4, 0):
            raise InputRefused("curl 8.4 or newer is required for unknown-length response bounds")

    def __call__(self, path: str) -> Any:
        if ENDPOINT.fullmatch(path) is None or any(part in {".", ".."} for part in path.split("/")):
            raise InputRefused("The policy reader permits only exact GitHub metadata/blob endpoints")
        remaining = self.deadline - self.clock()
        if remaining <= 0 or self.requests >= MAX_REQUESTS:
            raise InputRefused("The policy API time or request bound is exhausted")
        self.requests += 1
        timeout = min(REQUEST_SECONDS, remaining)
        with tempfile.TemporaryDirectory(prefix="policy-response-") as temporary:
            response = Path(temporary) / "body.json"
            with (Path(temporary) / "curl-error").open("wb") as errors:
                command = [
                    "/usr/bin/curl", "--disable", "--silent", "--show-error", "--fail",
                    "--globoff", "--proto", "=https", "--max-redirs", "0",
                    "--max-time", str(timeout), "--connect-timeout", str(min(5, timeout)),
                    "--max-filesize", str(MAX_RESPONSE_BYTES), "--cacert", self.bundle,
                    "--capath", self.directory, "--header", "Accept: application/vnd.github+json",
                    "--header", "Accept-Encoding: identity", "--header", "X-GitHub-Api-Version: 2022-11-28",
                    "--config", "-", "--output", str(response), "--write-out", "%{http_code}",
                    "--url", "https://api.github.com" + path,
                ]
                try:
                    result = self.run(command, input=self.config.encode(), stdout=subprocess.PIPE,
                                      stderr=errors, timeout=timeout, check=False)
                except (OSError, subprocess.TimeoutExpired) as error:
                    raise InputRefused("The bounded GitHub read did not complete") from error
            if result.returncode or result.stdout != b"200":
                status = result.stdout.decode("ascii", errors="replace")[:3]
                raise InputRefused(f"GitHub read refused: curl exit {result.returncode}, HTTP {status}")
            if self.clock() >= self.deadline:
                raise InputRefused("The total policy API deadline expired")
            if not response.is_file() or response.stat().st_size > MAX_RESPONSE_BYTES:
                raise InputRefused("The GitHub response is absent or exceeds the byte bound")
            try:
                value = decode_metadata(response.read_text(encoding="utf-8"))
            except InputRefused:
                raise
            except UnicodeError as error:
                raise InputRefused("GitHub JSON must use UTF-8") from error
            if self.clock() >= self.deadline:
                raise InputRefused("The total policy API deadline expired during decoding")
            return value


def require_protected_base(read, base_sha: str) -> None:
    record = read(f"/repos/{PILOT_REPOSITORY}/branches/main")
    try:
        if record["name"] != "main" or record["protected"] is not True or record["commit"]["sha"] != base_sha:
            raise InputRefused("The pilot's protected main branch moved or cannot be verified")
    except (KeyError, TypeError) as error:
        raise InputRefused("Incomplete protected-branch metadata") from error


def validate_snapshot(read, number: int, base_sha: str, *, validator=None) -> dict[str, Any]:
    from scripts.qualification_policy import PolicyError, load_policy, validate_local_action_references

    require_protected_base(read, base_sha)
    identity = read_identity(read, PILOT_REPOSITORY, PILOT_REPOSITORY_ID, number, base_sha)
    files = collect_inputs(read, identity)
    policy_path = ROOT / "qualification/policy.json"
    try:
        policy = load_policy(policy_path)
    except PolicyError as error:
        raise InputRefused("The reviewed central policy is invalid") from error
    check = validator or validate_local_action_references
    with tempfile.TemporaryDirectory(prefix="policy-candidate-") as temporary:
        candidate = Path(temporary) / "data"
        write_inputs(files, candidate)
        try:
            actions = check(policy, candidate / ".github/workflows", "github-control-plane")
        except (PolicyError, RecursionError) as error:
            raise InputRefused(str(error)) from error
    require_protected_base(read, base_sha)
    require_current(read, identity)
    digests = {name: hashlib.sha256(raw).hexdigest() for name, raw in sorted(files.items())}
    return {
        "schema": "durable-workflow.protected-policy-read/v1", "repository": identity.repository,
        "repository_id": identity.repository_id, "pull_request": identity.number,
        "base_sha": identity.base_sha, "head_sha": identity.head_sha,
        "head_repository": identity.head_repository, "head_repository_id": identity.head_repository_id,
        "policy_sha256": hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        "inputs_sha256": hashlib.sha256(json.dumps(digests, sort_keys=True).encode()).hexdigest(),
        "input_count": len(files), "approved_action_count": len(actions),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pull-request", type=int, required=True)
    parser.add_argument("--base-sha", required=True)
    args = parser.parse_args()
    try:
        read = GitHubReadClient(
            Path(os.environ["CURL_CA_BUNDLE"]), Path(os.environ["SSL_CERT_DIR"]),
            os.environ["DW_CI_CA_SHA256"], os.environ.get("GITHUB_TOKEN", ""),
        )
        report = validate_snapshot(read, args.pull_request, args.base_sha)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (InputRefused, OSError, KeyError) as error:
        print(json.dumps({"policy_refused": str(error)[:1000]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
