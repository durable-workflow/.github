"""Read-only GitHub required-workflow pilot; no App or check-writing API."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from scripts.protected_policy_inputs import (  # noqa: E402
    InputRefused, checked_sha, collect_commit_inputs, positive_id, read_identity,
)

PILOT = "durable-workflow/.github"
PILOT_ID = 575230056
QUEUE_REF = re.compile(r"refs/heads/gh-readonly-queue/main/[A-Za-z0-9_/-]+")


def prepare_runtime(environment):
    """Prepare only the standard hosted Python's isolated environment."""
    if environment.get("RUNNER_ENVIRONMENT") != "github-hosted" or sys.version_info < (3, 13):
        raise InputRefused("The pilot needs the reviewed standard hosted Python runtime")
    parent = Path(environment["RUNNER_TEMP"])
    if not parent.is_absolute() or "\n" in str(parent):
        raise InputRefused("Invalid hosted temporary directory")
    runtime = parent / "native-policy-python"
    if runtime.exists():
        raise InputRefused("The isolated policy runtime already exists")
    subprocess.run([sys.executable, "-I", "-m", "venv", str(runtime)], check=True)
    with Path(environment["GITHUB_PATH"]).open("a", encoding="utf-8") as handle:
        handle.write(str(runtime / "bin") + "\n")


def _require_pilot(event_name, event, environment):
    repository = event.get("repository", {})
    if (not isinstance(repository, dict)
            or environment.get("GITHUB_SERVER_URL") != "https://github.com"
            or environment.get("GITHUB_REPOSITORY") != PILOT
            or environment.get("GITHUB_REPOSITORY_ID") != str(PILOT_ID)
            or environment.get("GITHUB_EVENT_NAME") != event_name
            or repository.get("full_name") != PILOT
            or positive_id(repository.get("id")) != PILOT_ID
            or repository.get("private") is not False):
        raise InputRefused("This source pilot admits only the selected public repository")


def _pull_request(read, event, validator):
    from scripts import protected_policy_check as checker

    if event.get("action") not in {"opened", "synchronize", "reopened"}:
        raise InputRefused("Unsupported required-workflow PR activity")
    number = positive_id(event.get("number"))
    pull = event["pull_request"]
    base, head = checked_sha(pull["base"]["sha"]), checked_sha(pull["head"]["sha"])
    identity = read_identity(read, PILOT, PILOT_ID, number, base)
    if identity.head_sha != head:
        raise InputRefused("The event's pull-request head is stale")
    report = checker.validate_snapshot(read, number, base, validator=validator)
    if report["head_sha"] != head:
        raise InputRefused("The event's pull-request head changed")
    return {**report, "enforcement": "github-required-workflow", "subject": "pull_request"}


def _merge_group(read, event, environment, validator):
    from scripts import protected_policy_check as checker

    if event.get("action") != "checks_requested":
        raise InputRefused("Unsupported required-workflow event")
    group = event["merge_group"]
    base, head = checked_sha(group["base_sha"]), checked_sha(group["head_sha"])
    ref = group["head_ref"]
    if (group["base_ref"] != "refs/heads/main" or not isinstance(ref, str)
            or QUEUE_REF.fullmatch(ref) is None or "//" in ref
            or environment.get("GITHUB_REF") != ref or environment.get("GITHUB_SHA") != head):
        raise InputRefused("The native merge-group event identity differs")
    checker.require_protected_base(read, base)
    files = collect_commit_inputs(read, PILOT, head)
    statistics = checker.validate_files(files, validator=validator)
    checker.require_protected_base(read, base)
    return {"schema": "durable-workflow.native-policy-read/v1", "repository": PILOT,
            "repository_id": PILOT_ID, "subject": "merge_group", "base_sha": base,
            "head_sha": head, "head_ref": ref, "enforcement": "github-required-workflow",
            **statistics}


def validate_native(read, event_name, event, environment, *, validator=None):
    _require_pilot(event_name, event, environment)
    if event_name == "pull_request":
        return _pull_request(read, event, validator)
    if event_name == "merge_group":
        return _merge_group(read, event, environment, validator)
    raise InputRefused("Unsupported required-workflow event")


def main():
    try:
        if sys.argv[1:] == ["--prepare-runtime"]:
            prepare_runtime(os.environ)
            return 0
        if sys.argv[1:]:
            raise InputRefused("No candidate-supplied arguments are accepted")
        from scripts.protected_policy_check import GitHubReadClient, decode_metadata

        event_path = Path(os.environ["GITHUB_EVENT_PATH"])
        with event_path.open("rb") as handle:
            raw = handle.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            raise InputRefused("The GitHub event exceeds its byte bound")
        event = decode_metadata(raw.decode("utf-8"))
        read = GitHubReadClient(Path(os.environ["CURL_CA_BUNDLE"]), Path(os.environ["SSL_CERT_DIR"]),
                                os.environ["DW_CI_CA_SHA256"], os.environ.get("GITHUB_TOKEN", ""))
        print(json.dumps(validate_native(read, os.environ["GITHUB_EVENT_NAME"], event, os.environ),
                         sort_keys=True))
        return 0
    except (InputRefused, KeyError, TypeError, OSError, UnicodeError, subprocess.SubprocessError) as error:
        print(json.dumps({"policy_refused": str(error)[:1000]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
