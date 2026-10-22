"""Prepared checks-only App issuer for the public central-policy pilot.

Run only from reviewed central code in the protected execution environment.
This component is not a workflow binding or proof of live enforcement.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from scripts.protected_policy_check import (  # noqa: E402
    PILOT_REPOSITORY, PILOT_REPOSITORY_ID, GitHubReadClient,
    require_protected_base, validate_snapshot,
)
from scripts.protected_policy_inputs import (  # noqa: E402
    InputRefused, checked_sha, positive_id, read_identity, require_current,
)

CHECK_NAME = "Protected workflow policy"
WORKFLOW_REF = f"{PILOT_REPOSITORY}/.github/workflows/protected-policy.yml@refs/heads/main"


def require_protected_execution(environment, base_sha: str) -> None:
    """Check caller context; actual credential denial still relies on GitHub."""
    expected = {
        "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": PILOT_REPOSITORY,
        "GITHUB_REPOSITORY_ID": str(PILOT_REPOSITORY_ID), "GITHUB_REF": "refs/heads/main",
        "GITHUB_SHA": checked_sha(base_sha), "GITHUB_EVENT_NAME": "pull_request_target",
        "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
    }
    if any(environment.get(name) != value for name, value in expected.items()):
        raise InputRefused("The issuer requires the reviewed protected-main workflow context")


class CheckRunIssuer(GitHubReadClient):
    """Write one Check Run, verifying its App before completing it successfully."""

    def __init__(self, *args, expected_app_id: int, **options):
        self.expected_app_id = positive_id(expected_app_id)
        self.check_id = None
        self.head_sha = None
        super().__init__(*args, **options)
        if not self.config:
            raise InputRefused("A separate checks-only installation token is required")

    def __call__(self, _path):
        raise InputRefused("The App credential is restricted to the check issuer")

    def _verify(self, record, *, status: str, conclusion) -> int:
        try:
            check_id = positive_id(record["id"])
            if (positive_id(record["app"]["id"]) != self.expected_app_id
                    or record["name"] != CHECK_NAME or record["head_sha"] != self.head_sha
                    or record["status"] != status or record["conclusion"] != conclusion
                    or (self.check_id is not None and check_id != self.check_id)):
                raise InputRefused("The Check Run identity or App issuer does not match")
            return check_id
        except (KeyError, TypeError) as error:
            raise InputRefused("GitHub returned incomplete Check Run metadata") from error

    def begin(self, head_sha: str) -> None:
        if self.head_sha is not None:
            raise InputRefused("The issuer permits only one Check Run")
        self.head_sha = checked_sha(head_sha)
        record = self._request_json(
            f"/repos/{PILOT_REPOSITORY}/check-runs", method="POST", expected_status=b"201",
            body={"name": CHECK_NAME, "head_sha": self.head_sha, "status": "in_progress"},
        )
        # A wrong installation may create an incomplete check, never a success.
        self.check_id = self._verify(record, status="in_progress", conclusion=None)

    def complete(self, report: dict) -> dict:
        if self.check_id is None or report.get("head_sha") != self.head_sha:
            raise InputRefused("No matching App-issued check is ready for completion")
        summary = "\n".join([
            "Reviewed central policy accepted bounded, data-only workflow inputs.",
            f"Policy SHA-256: {report['policy_sha256']}",
            f"Inputs SHA-256: {report['inputs_sha256']}",
        ])
        record = self._request_json(
            f"/repos/{PILOT_REPOSITORY}/check-runs/{self.check_id}",
            method="PATCH", expected_status=b"200",
            body={"status": "completed", "conclusion": "success", "output": {
                "title": "Workflow policy accepted", "summary": summary,
            }},
        )
        self._verify(record, status="completed", conclusion="success")
        # A completed issuer object cannot be reused to publish another result.
        self.check_id = None
        return {"check_name": CHECK_NAME, "app_id": self.expected_app_id, "head_sha": self.head_sha}


def qualify_and_issue(read, issuer, number: int, base_sha: str, expected_head: str) -> dict:
    checked_sha(expected_head)
    identity = read_identity(read, PILOT_REPOSITORY, PILOT_REPOSITORY_ID, number, base_sha)
    if identity.head_sha != expected_head:
        raise InputRefused("The event's expected head is no longer current")
    report = validate_snapshot(read, number, base_sha)
    if any(report.get(key) != value for key, value in {
        "repository": identity.repository, "repository_id": identity.repository_id,
        "pull_request": identity.number, "head_sha": identity.head_sha, "base_sha": identity.base_sha,
        "head_repository": identity.head_repository, "head_repository_id": identity.head_repository_id,
    }.items()):
        raise InputRefused("The validated snapshot does not match the original PR identity")
    issuer.begin(identity.head_sha)
    # Recheck after the App identity is known, immediately before success.
    require_protected_base(read, base_sha)
    require_current(read, identity)
    return {**report, **issuer.complete(report)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pull-request", type=int, required=True)
    parser.add_argument("--base-sha", required=True)
    parser.add_argument("--expected-head", required=True)
    args = parser.parse_args()
    try:
        require_protected_execution(os.environ, args.base_sha)
        bundle = Path(os.environ["CURL_CA_BUNDLE"])
        directory = Path(os.environ["SSL_CERT_DIR"])
        digest = os.environ["DW_CI_CA_SHA256"]
        read = GitHubReadClient(bundle, directory, digest, os.environ["GITHUB_TOKEN"])
        app_id = os.environ["POLICY_GATE_APP_ID"]
        if re.fullmatch(r"[1-9]\d{0,18}", app_id, flags=re.ASCII) is None:
            raise InputRefused("A canonical positive App ID is required")
        issuer = CheckRunIssuer(
            bundle, directory, digest, os.environ["POLICY_CHECKS_TOKEN"],
            expected_app_id=int(app_id),
        )
        issuer.deadline = min(issuer.deadline, read.deadline)
        print(json.dumps(qualify_and_issue(
            read, issuer, args.pull_request, args.base_sha, args.expected_head,
        ), sort_keys=True))
        return 0
    except (InputRefused, OSError, KeyError) as error:
        print(json.dumps({"policy_refused": str(error)[:1000]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
