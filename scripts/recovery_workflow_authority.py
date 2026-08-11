"""Resolve and validate the qualified component recovery-workflow authority."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import urllib.parse
from collections.abc import Mapping
from typing import Any

SCHEMA = "durable-workflow.component-release-recovery-authority/v2"
CONTROL_REPOSITORY = "durable-workflow/.github"
AUTHORITY_REF = "main"
AUTHORITY_PATH = "release-recovery/authority.json"
QUALIFICATION_WORKFLOW = ".github/workflows/beta-candidate.yml"
QUALIFICATION_EVENT = "push"
QUALIFICATION_REF_PATH = f"{QUALIFICATION_WORKFLOW}@{AUTHORITY_REF}"
WORKFLOW_PATH = ".github/workflows/release-plan-recovery.yml"
SOURCE_IDENTITIES_SCHEMA = "durable-workflow.component-release-recovery-source-identities/v1"
SOURCE_IDENTITIES_PATH = "release-recovery/protected-source-identities.json"
CHECK_RUN_APP = "github-actions"
SOURCE_IDENTITY = {
    "repository": CONTROL_REPOSITORY,
    "ref": f"refs/heads/{AUTHORITY_REF}",
    "path": AUTHORITY_PATH,
    "qualification": {
        "workflow": QUALIFICATION_WORKFLOW,
        "event": QUALIFICATION_EVENT,
    },
}


class RecoveryWorkflowAuthorityError(ValueError):
    """The protected recovery-workflow authority is malformed or mismatched."""


def normalized_source_sha256(source: str) -> str:
    return hashlib.sha256(source.replace("\r\n", "\n").encode("utf-8")).hexdigest()


def exact_source_sha256(raw: bytes) -> str:
    try:
        source = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise RecoveryWorkflowAuthorityError("recovery workflow is not valid UTF-8") from error
    if "\r" in source:
        raise RecoveryWorkflowAuthorityError("recovery workflow source must use canonical LF bytes")
    return hashlib.sha256(raw).hexdigest()


def _commit(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 40
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise RecoveryWorkflowAuthorityError(f"{label} has an invalid commit")
    return value


def _positive_integer(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise RecoveryWorkflowAuthorityError(f"{label} has an invalid identity")
    return value


def branch_url(repository: str, branch: str) -> str:
    encoded = urllib.parse.quote(branch, safe="")
    return f"https://api.github.com/repos/{repository}/branches/{encoded}"


def compare_url(repository: str, base: str, head: str) -> str:
    comparison = urllib.parse.quote(f"{base}...{head}", safe=".")
    return f"https://api.github.com/repos/{repository}/compare/{comparison}"


def workflow_metadata_url(repository: str, path: str) -> str:
    return (
        f"https://api.github.com/repos/{repository}/actions/workflows/"
        f"{urllib.parse.quote(path.rsplit('/', 1)[-1], safe='')}"
    )


def workflow_source_url(repository: str, path: str, commit: str) -> str:
    encoded_path = urllib.parse.quote(path, safe="/")
    encoded_commit = urllib.parse.quote(commit, safe="")
    return f"https://api.github.com/repos/{repository}/contents/{encoded_path}?ref={encoded_commit}"


def workflow_run_url(repository: str, run_id: int) -> str:
    return f"https://api.github.com/repos/{repository}/actions/runs/{run_id}"


def check_run_url(repository: str, check_run_id: int) -> str:
    return f"https://api.github.com/repos/{repository}/check-runs/{check_run_id}"


def authority_ref_url() -> str:
    return f"https://api.github.com/repos/{CONTROL_REPOSITORY}/commits/{AUTHORITY_REF}"


def authority_url(commit: str) -> str:
    return (
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/contents/{AUTHORITY_PATH}"
        f"?ref={commit}"
    )


def qualification_runs_url(commit: str) -> str:
    workflow = QUALIFICATION_WORKFLOW.rsplit("/", 1)[-1]
    return (
        f"https://api.github.com/repos/{CONTROL_REPOSITORY}/actions/workflows/{workflow}/runs"
        f"?branch={AUTHORITY_REF}&event={QUALIFICATION_EVENT}&head_sha={commit}&per_page=100"
    )


def validate_authority_commit(value: Any) -> str:
    commit = value.get("sha") if isinstance(value, dict) else None
    if (
        not isinstance(commit, str)
        or len(commit) != 40
        or any(character not in "0123456789abcdef" for character in commit)
    ):
        raise RecoveryWorkflowAuthorityError("recovery workflow authority ref has an invalid commit")
    return commit


def _qualification_evidence(run: dict[str, Any], commit: str) -> dict[str, Any]:
    run_id = run.get("id")
    run_attempt = run.get("run_attempt")
    if (
        not isinstance(run_id, int)
        or isinstance(run_id, bool)
        or run_id < 1
        or not isinstance(run_attempt, int)
        or isinstance(run_attempt, bool)
        or run_attempt < 1
    ):
        raise RecoveryWorkflowAuthorityError(
            "recovery workflow authority qualification has an invalid run identity"
        )
    return {
        "workflow": QUALIFICATION_WORKFLOW,
        "path": run["path"],
        "event": QUALIFICATION_EVENT,
        "head_branch": AUTHORITY_REF,
        "head_sha": commit,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "status": "completed",
        "conclusion": "success",
        "url": f"https://github.com/{CONTROL_REPOSITORY}/actions/runs/{run_id}",
    }


def validate_authority_qualification(value: Any, commit: str) -> dict[str, Any]:
    runs = value.get("workflow_runs") if isinstance(value, dict) else None
    if not isinstance(runs, list):
        raise RecoveryWorkflowAuthorityError(
            "recovery workflow authority qualification response has an invalid shape"
        )

    candidates = [
        run
        for run in runs
        if isinstance(run, dict)
        and run.get("path") in (QUALIFICATION_WORKFLOW, QUALIFICATION_REF_PATH)
        and run.get("event") == QUALIFICATION_EVENT
        and run.get("head_branch") == AUTHORITY_REF
    ]
    if not candidates:
        raise RecoveryWorkflowAuthorityError(
            "recovery workflow authority qualification is absent for the resolved commit"
        )
    if any(run.get("head_sha") != commit for run in candidates):
        raise RecoveryWorkflowAuthorityError(
            "recovery workflow authority qualification is bound to another commit"
        )

    successful = [
        run
        for run in candidates
        if run.get("status") == "completed" and run.get("conclusion") == "success"
    ]
    if successful:
        return _qualification_evidence(successful[0], commit)
    if any(run.get("status") != "completed" for run in candidates):
        raise RecoveryWorkflowAuthorityError(
            "recovery workflow authority qualification is pending for the resolved commit"
        )
    if any(run.get("conclusion") == "cancelled" for run in candidates):
        raise RecoveryWorkflowAuthorityError(
            "recovery workflow authority qualification was cancelled for the resolved commit"
        )
    raise RecoveryWorkflowAuthorityError(
        "recovery workflow authority qualification failed for the resolved commit"
    )


def qualified_source_identity(
    raw: bytes,
    commit: str,
    qualification: dict[str, Any],
) -> dict[str, Any]:
    return {
        "repository": CONTROL_REPOSITORY,
        "ref": f"refs/heads/{AUTHORITY_REF}",
        "commit": commit,
        "path": AUTHORITY_PATH,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "qualification": qualification,
    }


def validate_authority(
    value: Any,
    components: Mapping[str, tuple[str, str]],
) -> dict[str, dict[str, str]]:
    if not isinstance(value, dict) or set(value) != {"schema", "source", "workflows"}:
        raise RecoveryWorkflowAuthorityError("recovery workflow authority has an invalid document shape")
    if value.get("schema") != SCHEMA or value.get("source") != SOURCE_IDENTITY:
        raise RecoveryWorkflowAuthorityError("recovery workflow authority has an unexpected protected source")

    workflows = value.get("workflows")
    if not isinstance(workflows, dict) or set(workflows) != set(components):
        raise RecoveryWorkflowAuthorityError("recovery workflow authority does not name the complete component set")

    validated: dict[str, dict[str, str]] = {}
    for name, (repository, default_branch) in components.items():
        entry = workflows.get(name)
        expected_identity = {
            "repository": repository,
            "ref": f"refs/heads/{default_branch}",
            "path": WORKFLOW_PATH,
            "state": "active",
        }
        if not isinstance(entry, dict) or set(entry) != {*expected_identity, "sha256"}:
            raise RecoveryWorkflowAuthorityError(f"{name} recovery workflow authority has an invalid shape")
        if any(entry.get(field) != expected for field, expected in expected_identity.items()):
            raise RecoveryWorkflowAuthorityError(f"{name} recovery workflow authority has a mismatched identity")
        digest = entry.get("sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
        ):
            raise RecoveryWorkflowAuthorityError(f"{name} recovery workflow authority has an invalid SHA-256")
        validated[name] = dict(entry)
    return validated


def decode_authority(
    raw: bytes,
    components: Mapping[str, tuple[str, str]],
) -> dict[str, dict[str, str]]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RecoveryWorkflowAuthorityError("recovery workflow authority is not valid UTF-8 JSON") from error
    return validate_authority(value, components)


def qualification_requirements(
    policy: Any,
    components: Mapping[str, tuple[str, str]],
) -> dict[str, dict[str, str]]:
    if not isinstance(policy, dict) or policy.get("organization") != "durable-workflow":
        raise RecoveryWorkflowAuthorityError("recovery qualification policy has an invalid organization")
    targets = policy.get("targets")
    if not isinstance(targets, dict):
        raise RecoveryWorkflowAuthorityError("recovery qualification policy has an invalid target set")

    requirements: dict[str, dict[str, str]] = {}
    for name, (repository, branch) in components.items():
        target = targets.get(name)
        expected_repository = repository.removeprefix("durable-workflow/")
        workflows = target.get("workflows") if isinstance(target, dict) else None
        if (
            not isinstance(target, dict)
            or target.get("repository") != expected_repository
            or target.get("branch") != branch
            or not isinstance(workflows, list)
            or len(workflows) != 1
        ):
            raise RecoveryWorkflowAuthorityError(
                f"{name} recovery qualification policy has a mismatched protected target"
            )
        workflow = workflows[0]
        workflow_path = workflow.get("path") if isinstance(workflow, dict) else None
        required_check = workflow.get("required_check") if isinstance(workflow, dict) else None
        if (
            not isinstance(workflow_path, str)
            or not re.fullmatch(r"[A-Za-z0-9._-]+\.ya?ml", workflow_path)
            or not isinstance(required_check, str)
            or not required_check
        ):
            raise RecoveryWorkflowAuthorityError(
                f"{name} recovery qualification policy has an invalid workflow identity"
            )
        requirements[name] = {
            "workflow": f".github/workflows/{workflow_path}",
            "required_check": required_check,
        }
    return requirements


def _validate_qualification(
    name: str,
    value: Any,
    repository: str,
    branch: str,
    commit: str,
    requirement: Mapping[str, str],
) -> dict[str, Any]:
    fields = {
        "check_run_id",
        "check_url",
        "conclusion",
        "event",
        "head_branch",
        "head_sha",
        "required_check",
        "run_attempt",
        "run_id",
        "status",
        "url",
        "workflow",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise RecoveryWorkflowAuthorityError(f"{name} recovery source qualification has an invalid shape")
    run_id = _positive_integer(value.get("run_id"), f"{name} recovery qualification run")
    run_attempt = _positive_integer(
        value.get("run_attempt"),
        f"{name} recovery qualification attempt",
    )
    check_run_id = _positive_integer(
        value.get("check_run_id"),
        f"{name} recovery qualification check",
    )
    expected = {
        "check_run_id": check_run_id,
        "check_url": (f"https://github.com/{repository}/actions/runs/{run_id}/job/{check_run_id}"),
        "conclusion": "success",
        "event": "push",
        "head_branch": branch,
        "head_sha": commit,
        "required_check": requirement["required_check"],
        "run_attempt": run_attempt,
        "run_id": run_id,
        "status": "completed",
        "url": f"https://github.com/{repository}/actions/runs/{run_id}",
        "workflow": requirement["workflow"],
    }
    if value != expected:
        raise RecoveryWorkflowAuthorityError(
            f"{name} recovery source qualification has a mismatched protected identity"
        )
    return dict(value)


def validate_source_identities(
    value: Any,
    workflows: Mapping[str, Mapping[str, str]],
    components: Mapping[str, tuple[str, str]],
    requirements: Mapping[str, Mapping[str, str]],
) -> dict[str, dict[str, Any]]:
    expected_source = {
        "repository": CONTROL_REPOSITORY,
        "ref": f"refs/heads/{AUTHORITY_REF}",
        "authority_path": AUTHORITY_PATH,
        "path": SOURCE_IDENTITIES_PATH,
    }
    if not isinstance(value, dict) or set(value) != {"schema", "source", "workflows"}:
        raise RecoveryWorkflowAuthorityError("recovery protected source identities have an invalid document shape")
    if value.get("schema") != SOURCE_IDENTITIES_SCHEMA or value.get("source") != expected_source:
        raise RecoveryWorkflowAuthorityError("recovery protected source identities have an unexpected authority")
    records = value.get("workflows")
    if not isinstance(records, dict) or set(records) != set(components):
        raise RecoveryWorkflowAuthorityError(
            "recovery protected source identities do not name the complete component set"
        )
    if set(requirements) != set(components):
        raise RecoveryWorkflowAuthorityError(
            "recovery qualification requirements do not name the complete component set"
        )

    validated: dict[str, dict[str, Any]] = {}
    for name, (repository, branch) in components.items():
        record = records[name]
        expected_identity = {
            "repository": repository,
            "ref": f"refs/heads/{branch}",
            "path": WORKFLOW_PATH,
            "state": "active",
        }
        if not isinstance(record, dict) or set(record) != {*expected_identity, "identities"}:
            raise RecoveryWorkflowAuthorityError(f"{name} recovery protected source history has an invalid shape")
        if any(record.get(field) != expected for field, expected in expected_identity.items()):
            raise RecoveryWorkflowAuthorityError(f"{name} recovery protected source history has a mismatched identity")
        identities = record.get("identities")
        if not isinstance(identities, list) or not identities:
            raise RecoveryWorkflowAuthorityError(f"{name} recovery protected source history is empty")

        previous: dict[str, Any] | None = None
        accepted: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for index, identity in enumerate(identities):
            expected_fields = {"source_commit", "sha256", "qualification"}
            if index:
                expected_fields.add("supersedes")
            if not isinstance(identity, dict) or set(identity) != expected_fields:
                raise RecoveryWorkflowAuthorityError(f"{name} recovery protected source identity has an invalid shape")
            commit = _commit(
                identity.get("source_commit"),
                f"{name} recovery protected source identity",
            )
            digest = identity.get("sha256")
            if (
                not isinstance(digest, str)
                or len(digest) != 64
                or any(character not in "0123456789abcdef" for character in digest)
            ):
                raise RecoveryWorkflowAuthorityError(
                    f"{name} recovery protected source identity has an invalid SHA-256"
                )
            if (commit, digest) in seen:
                raise RecoveryWorkflowAuthorityError(
                    f"{name} recovery protected source history repeats an accepted identity"
                )
            if previous is not None and identity.get("supersedes") != {
                "source_commit": previous["source_commit"],
                "sha256": previous["sha256"],
            }:
                raise RecoveryWorkflowAuthorityError(
                    f"{name} recovery protected source successor has a mismatched predecessor"
                )
            accepted_identity = {
                "source_commit": commit,
                "sha256": digest,
                "qualification": _validate_qualification(
                    name,
                    identity["qualification"],
                    repository,
                    branch,
                    commit,
                    requirements[name],
                ),
            }
            if previous is not None:
                accepted_identity["supersedes"] = dict(identity["supersedes"])
            accepted.append(accepted_identity)
            seen.add((commit, digest))
            previous = accepted_identity

        if accepted[-1]["sha256"] != workflows[name]["sha256"]:
            raise RecoveryWorkflowAuthorityError(
                f"{name} recovery protected source history does not bind the current authority"
            )
        validated[name] = {**expected_identity, "identities": accepted}
    return validated


def decode_source_identities(
    raw: bytes,
    workflows: Mapping[str, Mapping[str, str]],
    components: Mapping[str, tuple[str, str]],
    requirements: Mapping[str, Mapping[str, str]],
) -> dict[str, dict[str, Any]]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RecoveryWorkflowAuthorityError("recovery protected source identities are not valid UTF-8 JSON") from error
    return validate_source_identities(value, workflows, components, requirements)


def load_qualified_authority(
    client: Any,
    components: Mapping[str, tuple[str, str]],
) -> tuple[dict[str, dict[str, str]], dict[str, Any]]:
    commit = validate_authority_commit(client.json(authority_ref_url()))
    qualification = validate_authority_qualification(
        client.json(qualification_runs_url(commit)),
        commit,
    )
    raw = client.bytes(authority_url(commit), accept="application/vnd.github.raw+json")
    workflows = decode_authority(raw, components)
    return workflows, qualified_source_identity(raw, commit, qualification)


def verify_workflow_source(name: str, source: str, expected_sha256: str) -> str:
    actual_sha256 = normalized_source_sha256(source)
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise RecoveryWorkflowAuthorityError(
            f"{name} recovery workflow does not match the protected source identity"
        )
    return actual_sha256


def validate_live_qualification(
    client: Any,
    name: str,
    repository: str,
    branch: str,
    identity: Mapping[str, Any],
    requirement: Mapping[str, str],
) -> dict[str, Any]:
    commit = identity["source_commit"]
    recorded = identity["qualification"]
    run = client.json(workflow_run_url(repository, recorded["run_id"]))
    expected_run = {
        "id": recorded["run_id"],
        "run_attempt": recorded["run_attempt"],
        "path": requirement["workflow"],
        "event": "push",
        "head_branch": branch,
        "head_sha": commit,
        "status": "completed",
        "conclusion": "success",
        "html_url": recorded["url"],
    }
    if not isinstance(run, dict) or any(run.get(field) != expected for field, expected in expected_run.items()):
        raise RecoveryWorkflowAuthorityError(
            f"{name} recovery qualification run is not exact successful protected-branch evidence"
        )

    check = client.json(check_run_url(repository, recorded["check_run_id"]))
    app = check.get("app") if isinstance(check, dict) else None
    expected_check = {
        "id": recorded["check_run_id"],
        "name": requirement["required_check"],
        "head_sha": commit,
        "status": "completed",
        "conclusion": "success",
        "html_url": recorded["check_url"],
    }
    if (
        not isinstance(check, dict)
        or any(check.get(field) != expected for field, expected in expected_check.items())
        or not isinstance(app, dict)
        or app.get("slug") != CHECK_RUN_APP
    ):
        raise RecoveryWorkflowAuthorityError(
            f"{name} recovery qualification check is not exact successful GitHub Actions evidence"
        )
    return dict(recorded)


def verify_authority_source_identities(
    client: Any,
    workflows: Mapping[str, Mapping[str, str]],
    source_identities: Mapping[str, Mapping[str, Any]],
    requirements: Mapping[str, Mapping[str, str]],
    *,
    require_current: bool = True,
) -> dict[str, dict[str, Any]]:
    evidence: dict[str, dict[str, Any]] = {}
    for name, expected in workflows.items():
        record = source_identities[name]
        repository = expected["repository"]
        branch = expected["ref"].removeprefix("refs/heads/")
        branch_data = client.json(branch_url(repository, branch))
        head_commit = branch_data.get("commit", {}).get("sha") if isinstance(branch_data, dict) else None
        head_commit = _commit(head_commit, f"{name} protected branch")

        metadata = client.json(workflow_metadata_url(repository, expected["path"]))
        if (
            not isinstance(metadata, dict)
            or metadata.get("path") != expected["path"]
            or metadata.get("state") != expected["state"]
        ):
            raise RecoveryWorkflowAuthorityError(
                f"{name} recovery workflow does not expose the protected path and state"
            )

        verified_history: list[dict[str, Any]] = []
        head_source: bytes | None = None
        for identity in record["identities"]:
            commit = identity["source_commit"]
            if commit != head_commit:
                comparison = client.json(compare_url(repository, commit, head_commit))
                if (
                    not isinstance(comparison, dict)
                    or comparison.get("status") != "ahead"
                    or comparison.get("base_commit", {}).get("sha") != commit
                    or comparison.get("merge_base_commit", {}).get("sha") != commit
                ):
                    raise RecoveryWorkflowAuthorityError(
                        f"{name} recovery protected source commit is not on the protected branch"
                    )
            raw = client.bytes(
                workflow_source_url(repository, expected["path"], commit),
                accept="application/vnd.github.raw+json",
            )
            if commit == head_commit:
                head_source = raw
            if not hmac.compare_digest(exact_source_sha256(raw), identity["sha256"]):
                raise RecoveryWorkflowAuthorityError(
                    f"{name} recovery protected source bytes do not match the accepted identity"
                )
            qualification = validate_live_qualification(
                client,
                name,
                repository,
                branch,
                identity,
                requirements[name],
            )
            verified_history.append(
                {
                    "source_commit": commit,
                    "sha256": identity["sha256"],
                    "qualification": qualification,
                }
            )
        if head_source is None:
            head_source = client.bytes(
                workflow_source_url(repository, expected["path"], head_commit),
                accept="application/vnd.github.raw+json",
            )
        head_sha256 = exact_source_sha256(head_source)
        if require_current and not hmac.compare_digest(head_sha256, expected["sha256"]):
            raise RecoveryWorkflowAuthorityError(
                f"{name} recovery workflow does not match the protected source identity"
            )
        evidence[name] = {
            "repository": repository,
            "ref": expected["ref"],
            "path": expected["path"],
            "state": expected["state"],
            "head_commit": head_commit,
            "sha256": head_sha256,
            "workflow_id": metadata.get("id"),
            "url": metadata.get("html_url"),
            "identities": verified_history,
        }
    return evidence


def verify_authority_workflow_sources(
    client: Any,
    workflows: Mapping[str, Mapping[str, str]],
) -> dict[str, dict[str, Any]]:
    evidence: dict[str, dict[str, Any]] = {}
    for name, expected in workflows.items():
        repository = expected["repository"]
        path = expected["path"]
        branch = expected["ref"].removeprefix("refs/heads/")
        workflow = client.json(workflow_metadata_url(repository, path))
        if workflow.get("path") != path or workflow.get("state") != expected["state"]:
            raise RecoveryWorkflowAuthorityError(
                f"{name} recovery workflow does not expose the protected path and state"
            )

        source_url = workflow_source_url(repository, path, branch)
        try:
            source = client.bytes(
                source_url,
                accept="application/vnd.github.raw+json",
            ).decode("utf-8")
        except UnicodeDecodeError as error:
            raise RecoveryWorkflowAuthorityError(
                f"{name} recovery workflow is not valid UTF-8"
            ) from error
        digest = verify_workflow_source(name, source, expected["sha256"])
        evidence[name] = {
            "repository": repository,
            "ref": expected["ref"],
            "path": path,
            "state": workflow["state"],
            "sha256": digest,
            "workflow_id": workflow.get("id"),
            "url": workflow.get("html_url"),
        }
    return evidence
