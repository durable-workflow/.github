#!/usr/bin/env python3
"""Validate, verify, and immutably record a public beta candidate tuple."""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import datetime as dt
import email.utils
import errno
import hashlib
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

# GitHub Actions invokes this file directly from the repository root. In that
# mode Python adds scripts/, rather than the repository root, to sys.path.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scripts.packagist_metadata import PackagistMetadataError, exact_package_version

SCHEMA = "durable-workflow.beta-candidate/v2"
LEGACY_SCHEMA = "durable-workflow.beta-candidate/v1"
VERIFICATION_SCHEMA = "durable-workflow.beta-candidate-verification/v2"
LEGACY_VERIFICATION_SCHEMA = "durable-workflow.beta-candidate-verification/v1"
LEGACY_MANIFEST_DIGESTS = frozenset(
    {
        "1104bbb8d40c1acd8062a15b7fd385966bdb4428a533ef5d947820944e85d294",
        "26084d2e8f12faeebb7b09bf3de41e1dd65f8afdaa5d38f786fcbcd1bf770f15",
        "2fbeda4e3368edf7cda7bcc749359d4bcdf7fcccca289e32316782613a84b4a6",
        "43243594ba34ff220365d9c514e6a54b93789788676ca8b1d678b679afa6c1c5",
        "43f535585fc225a2d2cfcf347ec45c78daae1ff2d244e422d8952347d1ef4a95",
        "47fdba440315d2f05b16c66b5ef37139db4b306fbf8e168c5e15a27a26592742",
        "561c4544a8b9305056f863f20f84791921952f1dbcff97929805a5dac01027fb",
        "5e083e07e6abecbb0547466812f866a3650039b210dbe1d486ca98528479cd29",
        "5fce05154eb66ee1551bad7eadda0911ed867ea3cedd8f37d091df0649bbc5db",
        "80282957f3a417af6025b4ad4abf461b03388d799ee570de128f25a676909f70",
        "81f3346f59f414b29fc88efc993dd3c3d5ee759a819d9f82720118981776f4f3",
        "a4b72535496346aa47bf0a8ebedd84308231776c9df015dd913095163eda3ce2",
        "c6821caad478ee255b9e8cb70638d96ec46a70bd5afc54636861fe71840a6cbe",
        "d70e45ce40c0959f38345abb1b6e53e2da8026832a918a640fe69d48b534f1e3",
        "dd5e8d3bb248c2b1b292b5badf29376cc5c5b6fa73dedfb343e33987a2b6d7a2",
        "ec5a4c032dfcaa73878b4126af4e2b2bb90c09fe46def19314d66be441b16174",
        "ffee151da2e3835bf32bc2ef05dc5d0f3261e45c13da0ef6e2d6e6f19c1ca50f",
    }
)
CANDIDATE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?$")
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")
TAG_PREFIX = "beta-candidate/"
GITHUB_READ_MAX_ATTEMPTS = 5
GITHUB_READ_RETRY_BASE_SECONDS = 2.0
GITHUB_READ_RETRY_MAX_SECONDS = 120.0
GITHUB_READ_REQUEST_TIMEOUT_SECONDS = 30.0
GITHUB_READ_DEADLINE_SECONDS = 600.0
INFRASTRUCTURE_EXIT_CODE = 75
VERIFICATION_MAX_BYTES = 256 * 1024
MAX_URL_LENGTH = 2048
MAX_TEXT_LENGTH = 4096
MAX_PYPI_FILES = 32
PHAR_BUILD_INFO_MAX_BYTES = 16 * 1024
RFC3339_SECONDS_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
PYPI_PRERELEASE_LABELS = {"alpha": "a", "beta": "b", "rc": "rc"}


@dataclass(frozen=True)
class Component:
    repository: str
    distribution: str
    package: str


COMPONENTS = {
    "workflow": Component("durable-workflow/workflow", "composer", "durable-workflow/workflow"),
    "waterline": Component("durable-workflow/waterline", "composer", "durable-workflow/waterline"),
    "server": Component("durable-workflow/server", "oci", "docker.io/durableworkflow/server"),
    "cli": Component("durable-workflow/cli", "github-release", "durable-workflow/cli"),
    "sdk-php": Component("durable-workflow/sdk-php", "composer", "durable-workflow/sdk"),
    "sdk-python": Component("durable-workflow/sdk-python", "pypi", "durable-workflow"),
    "sdk-rust": Component("durable-workflow/sdk-rust", "crates.io", "durable-workflow"),
}

WATERLINE_SERVICE = Component(
    "durable-workflow/waterline",
    "oci",
    "docker.io/durableworkflow/waterline",
)

CLI_ASSETS = {
    "dw.phar",
    "dw-linux-x86_64",
    "dw-linux-aarch64",
    "dw-macos-aarch64",
    "dw-windows-x86_64.exe",
    "dw.rb",
    "install.sh",
    "install.ps1",
    "verify-release.sh",
    "SHA256SUMS",
}


class CandidateError(RuntimeError):
    """A candidate does not satisfy the public identity contract."""


class PublicInfrastructureError(RuntimeError):
    """A bounded set of transient GitHub public-read attempts was exhausted."""

    def __init__(
        self,
        endpoint_class: str,
        attempts: int,
        *,
        reason: str,
        failure: str | None = None,
    ) -> None:
        evidence = [
            "classification=github-read-transient",
            f"endpoint_class={endpoint_class}",
            f"attempts={attempts}",
            f"reason={reason}",
        ]
        if failure is not None:
            evidence.append(failure)
        super().__init__(f"GitHub public read transient failure exhausted ({', '.join(evidence)})")


class _TransientGitHubRead(RuntimeError):
    """One GitHub public-read attempt encountered retryable infrastructure."""

    def __init__(self, evidence: str, headers: Mapping[str, str] | None = None) -> None:
        self.evidence = evidence
        self.headers = headers or {}
        super().__init__(evidence)


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def load_manifest(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CandidateError(f"cannot read candidate manifest {path}: {error}") from error
    if len(raw) > 64 * 1024:
        raise CandidateError("candidate manifest exceeds the 64 KiB limit")
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise CandidateError(f"candidate manifest is not valid JSON: {error}") from error
    validate_manifest(value)
    return value


def validate_manifest(value: Any) -> None:
    _validate_manifest(value, {SCHEMA})


def validate_recorded_manifest(value: Any) -> None:
    """Validate a current manifest or an exact pre-service manifest."""
    _validate_manifest(value, {LEGACY_SCHEMA, SCHEMA})
    if value["schema"] == LEGACY_SCHEMA and manifest_digest(value) not in LEGACY_MANIFEST_DIGESTS:
        raise CandidateError("legacy candidate manifest is not an exact recorded historical contract")


def _validate_manifest(value: Any, schemas: set[str]) -> None:
    if not isinstance(value, dict):
        raise CandidateError("candidate manifest must be a JSON object")
    expected_top = {"schema", "candidate", "components"}
    if set(value) != expected_top:
        raise CandidateError(f"candidate manifest keys must be exactly {sorted(expected_top)}")
    if value["schema"] not in schemas:
        raise CandidateError(f"candidate manifest schema must be one of {sorted(schemas)}")
    candidate = value["candidate"]
    if not isinstance(candidate, str) or not CANDIDATE_PATTERN.fullmatch(candidate):
        raise CandidateError("candidate must be 1-63 lowercase letters, digits, dots, underscores, or hyphens")
    components = value["components"]
    if not isinstance(components, dict) or set(components) != set(COMPONENTS):
        raise CandidateError(f"components must be exactly {sorted(COMPONENTS)}")
    for name, identity in components.items():
        if not isinstance(identity, dict) or set(identity) != {"version", "commit"}:
            raise CandidateError(f"components.{name} must contain only version and commit")
        version = identity["version"]
        commit = identity["commit"]
        if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
            raise CandidateError(f"components.{name}.version must be an exact SemVer release")
        if not isinstance(commit, str) or not COMMIT_PATTERN.fullmatch(commit):
            raise CandidateError(f"components.{name}.commit must be a full lowercase Git commit identity")


def manifest_digest(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(manifest)).hexdigest()


def canonical_cli_embedded_identity(version: str, commit: str) -> str:
    """Return the writer-reproducible portion of the verified PHAR identity."""
    return f"dw {version.lstrip('v')} (commit {commit[:12]})"


def canonical_pypi_version(version: str) -> str:
    """Translate the supported SemVer prerelease spelling to PEP 440."""
    match = re.fullmatch(
        r"([0-9]+\.[0-9]+\.[0-9]+)-(alpha|beta|rc)\.([1-9][0-9]*)",
        version,
    )
    if match is None:
        return version
    base, channel, sequence = match.groups()
    return f"{base}{PYPI_PRERELEASE_LABELS[channel]}{sequence}"


def _require_exact_keys(value: Any, keys: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise CandidateError(f"{context} keys must be exactly {sorted(keys)}")
    return value


def _require_bounded_string(value: Any, context: str, *, maximum: int = MAX_TEXT_LENGTH) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum or "\x00" in value:
        raise CandidateError(f"{context} must be a non-empty string of at most {maximum} characters")
    return value


def _require_https_url(value: Any, context: str) -> str:
    url = _require_bounded_string(value, context, maximum=MAX_URL_LENGTH)
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.netloc or parsed.username is not None or parsed.password is not None:
        raise CandidateError(f"{context} must be a bounded public HTTPS URL")
    return url


def _require_positive_integer(value: Any, context: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if type(value) is not int or value < minimum or value > 2**63 - 1:
        raise CandidateError(f"{context} must be an integer between {minimum} and {2**63 - 1}")
    return value


def _validate_download_evidence(value: Any, context: str) -> None:
    download = _require_exact_keys(value, {"url", "size", "sha256"}, context)
    _require_https_url(download["url"], f"{context}.url")
    _require_positive_integer(download["size"], f"{context}.size")
    if not re.fullmatch(r"[0-9a-f]{64}", str(download["sha256"])):
        raise CandidateError(f"{context}.sha256 must be a lowercase SHA-256 identity")


def _validate_source_evidence(value: Any, component: Component, version: str, commit: str, context: str) -> None:
    source = _require_exact_keys(value, {"repository", "tag", "tag_object", "commit", "url"}, context)
    if (
        source["repository"] != component.repository
        or source["tag"] != version
        or source["commit"] != commit
        or not COMMIT_PATTERN.fullmatch(str(source["tag_object"]))
        or source["url"] != f"https://github.com/{component.repository}/tree/{version}"
    ):
        raise CandidateError(f"{context} does not prove the planned source tag and commit")


def _validate_composer_evidence(value: Any, component: Component, _version: str, commit: str, context: str) -> None:
    distribution = _require_exact_keys(
        value,
        {"kind", "package", "registry", "source_reference", "dist_reference", "dist"},
        context,
    )
    encoded = "/".join(urllib.parse.quote(part, safe="") for part in component.package.split("/"))
    if (
        distribution["kind"] != "composer"
        or distribution["package"] != component.package
        or distribution["registry"] != f"https://repo.packagist.org/p2/{encoded}.json"
        or distribution["source_reference"] != commit
        or distribution["dist_reference"] != commit
    ):
        raise CandidateError(f"{context} does not prove the planned Composer package identity")
    _validate_download_evidence(distribution["dist"], f"{context}.dist")


def _validate_github_release_evidence(
    value: Any, component: Component, version: str, commit: str, context: str
) -> None:
    distribution = _require_exact_keys(
        value,
        {
            "kind",
            "repository",
            "release_id",
            "release_url",
            "build_attestations_verified",
            "build_attestation_authority",
            "package_source",
            "assets",
        },
        context,
    )
    release_url = _require_https_url(distribution["release_url"], f"{context}.release_url")
    if (
        distribution["kind"] != "github-release"
        or distribution["repository"] != component.repository
        or not release_url.startswith(f"https://github.com/{component.repository}/releases/")
        or distribution["build_attestations_verified"] is not True
    ):
        raise CandidateError(f"{context} does not prove the planned GitHub Release")
    _require_positive_integer(distribution["release_id"], f"{context}.release_id")

    authority = distribution["build_attestation_authority"]
    if isinstance(authority, dict) and authority.get("mode") == "exact-tag":
        expected_authority = {"mode": "exact-tag", "ref": f"refs/tags/{version}", "commit": commit}
    else:
        expected_authority = {
            "mode": "qualified-main-workflow",
            "ref": "refs/heads/main",
            "workflow": f"{component.repository}/.github/workflows/release.yml",
        }
    if authority != expected_authority:
        raise CandidateError(f"{context}.build_attestation_authority is not an accepted exact authority")

    package_source = _require_exact_keys(
        distribution["package_source"], {"commit", "embedded_phar_identity"}, f"{context}.package_source"
    )
    embedded_identity = package_source["embedded_phar_identity"]
    if package_source["commit"] != commit or embedded_identity != canonical_cli_embedded_identity(version, commit):
        raise CandidateError(f"{context}.package_source does not bind the planned CLI source")

    assets = distribution["assets"]
    if not isinstance(assets, list) or len(assets) != len(CLI_ASSETS):
        raise CandidateError(f"{context}.assets must contain exactly the required CLI release assets")
    names: set[str] = set()
    for index, raw_asset in enumerate(assets):
        asset = _require_exact_keys(
            raw_asset, {"name", "asset_id", "url", "size", "sha256"}, f"{context}.assets[{index}]"
        )
        if asset["name"] not in CLI_ASSETS or asset["name"] in names:
            raise CandidateError(f"{context}.assets contains an invalid or duplicate asset name")
        names.add(asset["name"])
        _require_positive_integer(asset["asset_id"], f"{context}.assets[{index}].asset_id")
        _validate_download_evidence(
            {key: asset[key] for key in ("url", "size", "sha256")},
            f"{context}.assets[{index}]",
        )
    if names != CLI_ASSETS:
        raise CandidateError(f"{context}.assets does not cover every required CLI release asset")


def _validate_pypi_evidence(value: Any, component: Component, version: str, commit: str, context: str) -> None:
    distribution = _require_exact_keys(value, {"kind", "package", "registry", "source_identity", "files"}, context)
    encoded_package = urllib.parse.quote(component.package, safe="")
    registry_urls = {
        f"https://pypi.org/pypi/{encoded_package}/{urllib.parse.quote(registry_version, safe='')}/json"
        for registry_version in {version, canonical_pypi_version(version)}
    }
    if (
        distribution["kind"] != "pypi"
        or distribution["package"] != component.package
        or distribution["registry"] not in registry_urls
    ):
        raise CandidateError(f"{context} does not prove the planned PyPI package identity")
    source_identity = _require_exact_keys(
        distribution["source_identity"],
        {"source_archive", "source_files_compared", "wheel_files_compared", "source_commit"},
        f"{context}.source_identity",
    )
    _validate_download_evidence(source_identity["source_archive"], f"{context}.source_identity.source_archive")
    _require_positive_integer(
        source_identity["source_files_compared"], f"{context}.source_identity.source_files_compared"
    )
    _require_positive_integer(
        source_identity["wheel_files_compared"], f"{context}.source_identity.wheel_files_compared"
    )
    if source_identity["source_commit"] != commit:
        raise CandidateError(f"{context}.source_identity does not bind the planned source commit")

    files = distribution["files"]
    if not isinstance(files, list) or not 2 <= len(files) <= MAX_PYPI_FILES:
        raise CandidateError(f"{context}.files must contain 2-{MAX_PYPI_FILES} bounded distribution files")
    names: set[str] = set()
    package_types: set[str] = set()
    for index, raw_file in enumerate(files):
        file = _require_exact_keys(
            raw_file,
            {"url", "size", "sha256", "filename", "package_type"},
            f"{context}.files[{index}]",
        )
        filename = _require_bounded_string(file["filename"], f"{context}.files[{index}].filename", maximum=255)
        if filename in names or "/" in filename or "\\" in filename:
            raise CandidateError(f"{context}.files contains an invalid or duplicate filename")
        names.add(filename)
        if file["package_type"] not in {"bdist_wheel", "sdist"}:
            raise CandidateError(f"{context}.files contains an unsupported package type")
        package_types.add(file["package_type"])
        _validate_download_evidence(
            {key: file[key] for key in ("url", "size", "sha256")},
            f"{context}.files[{index}]",
        )
    if package_types != {"bdist_wheel", "sdist"}:
        raise CandidateError(f"{context}.files must prove both wheel and source distributions")


def _validate_crate_evidence(value: Any, component: Component, version: str, commit: str, context: str) -> None:
    distribution = _require_exact_keys(
        value,
        {"kind", "package", "registry", "archive_vcs_commit", "archive_vcs_dirty", "archive"},
        context,
    )
    encoded_package = urllib.parse.quote(component.package, safe="")
    encoded_version = urllib.parse.quote(version, safe="")
    if (
        distribution["kind"] != "crates.io"
        or distribution["package"] != component.package
        or distribution["registry"] != f"https://crates.io/api/v1/crates/{encoded_package}/{encoded_version}"
        or distribution["archive_vcs_commit"] != commit
        or distribution["archive_vcs_dirty"] is not False
    ):
        raise CandidateError(f"{context} does not prove the planned crates.io package identity")
    _validate_download_evidence(distribution["archive"], f"{context}.archive")


def _validate_oci_evidence(value: Any, component: Component, version: str, commit: str, context: str) -> None:
    distribution = _require_exact_keys(value, {"kind", "image", "manifest_digest", "platforms", "configs"}, context)
    if (
        distribution["kind"] != "oci"
        or distribution["image"] != f"{component.package}:{version}"
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", str(distribution["manifest_digest"]))
    ):
        raise CandidateError(f"{context} does not prove the planned OCI image identity")
    platforms = distribution["platforms"]
    if not isinstance(platforms, list) or len(platforms) != 2 or set(platforms) != {"linux/amd64", "linux/arm64"}:
        raise CandidateError(f"{context}.platforms must prove exactly the required Linux platforms")
    configs = distribution["configs"]
    if not isinstance(configs, list) or len(configs) != 2:
        raise CandidateError(f"{context}.configs must prove exactly two platform configurations")
    digests: set[str] = set()
    expected_labels = {
        "org.opencontainers.image.revision": commit,
        "dev.durable-workflow.release.tag": version,
    }
    for index, raw_config in enumerate(configs):
        config = _require_exact_keys(raw_config, {"digest", "labels"}, f"{context}.configs[{index}]")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(config["digest"])) or config["digest"] in digests:
            raise CandidateError(f"{context}.configs contains an invalid or duplicate digest")
        digests.add(config["digest"])
        if config["labels"] != expected_labels:
            raise CandidateError(f"{context}.configs labels do not bind the planned source identity")


def load_verification(path: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise CandidateError(f"cannot read verification result: {error}") from error
    if len(raw) > VERIFICATION_MAX_BYTES:
        raise CandidateError(f"verification result exceeds the {VERIFICATION_MAX_BYTES // 1024} KiB limit")
    try:
        verification = json.loads(raw)
    except json.JSONDecodeError as error:
        raise CandidateError(f"cannot read verification result: {error}") from error
    validate_verification(verification, manifest)
    return verification


def validate_verification(verification: Any, manifest: dict[str, Any]) -> None:
    _validate_verification(verification, manifest, VERIFICATION_SCHEMA)


def validate_recorded_verification(verification: Any, manifest: dict[str, Any]) -> None:
    """Validate immutable evidence under the verification schema that produced it."""
    validate_recorded_manifest(manifest)
    expected_schema = LEGACY_VERIFICATION_SCHEMA if manifest["schema"] == LEGACY_SCHEMA else VERIFICATION_SCHEMA
    _validate_verification(verification, manifest, expected_schema)


def _validate_verification(verification: Any, manifest: dict[str, Any], schema: str) -> None:
    if not isinstance(verification, dict):
        raise CandidateError("verification result must be a JSON object")
    expected_top = {"schema", "candidate", "manifest_sha256", "verified_at", "outcome", "components"}
    if set(verification) != expected_top:
        raise CandidateError(f"verification result keys must be exactly {sorted(expected_top)}")
    if (
        verification["schema"] != schema
        or verification["candidate"] != manifest["candidate"]
        or verification["manifest_sha256"] != manifest_digest(manifest)
        or verification["outcome"] != "verified"
    ):
        raise CandidateError("verification result does not prove this exact candidate manifest")
    verified_at = verification["verified_at"]
    if not isinstance(verified_at, str) or not RFC3339_SECONDS_PATTERN.fullmatch(verified_at):
        raise CandidateError("verification result verified_at must be an RFC 3339 UTC timestamp")
    try:
        dt.datetime.strptime(verified_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise CandidateError("verification result verified_at must be a valid UTC timestamp") from error

    components = verification["components"]
    if not isinstance(components, dict) or set(components) != set(COMPONENTS):
        raise CandidateError("verification result does not cover every candidate component")
    for name, identity in manifest["components"].items():
        result = components[name]
        dual_waterline = name == "waterline" and schema == VERIFICATION_SCHEMA
        expected_result = (
            {"version", "commit", "source", "distributions", "outcome"}
            if dual_waterline
            else {"version", "commit", "source", "distribution", "outcome"}
        )
        if not isinstance(result, dict) or set(result) != expected_result or result["outcome"] != "verified":
            raise CandidateError(f"verification result for {name} is not successful")
        if result["version"] != identity["version"] or result["commit"] != identity["commit"]:
            raise CandidateError(f"verification result for {name} proves a different source release")
        component = COMPONENTS[name]
        context = f"verification result for {name}"
        _validate_source_evidence(result["source"], component, identity["version"], identity["commit"], context)
        distribution_validators = {
            "composer": _validate_composer_evidence,
            "github-release": _validate_github_release_evidence,
            "pypi": _validate_pypi_evidence,
            "crates.io": _validate_crate_evidence,
            "oci": _validate_oci_evidence,
        }
        if dual_waterline:
            distributions = _require_exact_keys(
                result["distributions"],
                {"embedded", "service"},
                f"{context}.distributions",
            )
            _validate_composer_evidence(
                distributions["embedded"],
                component,
                identity["version"],
                identity["commit"],
                f"{context}.distributions.embedded",
            )
            _validate_oci_evidence(
                distributions["service"],
                WATERLINE_SERVICE,
                identity["version"],
                identity["commit"],
                f"{context}.distributions.service",
            )
        else:
            distribution_validators[component.distribution](
                result["distribution"],
                component,
                identity["version"],
                identity["commit"],
                f"{context}.distribution",
            )


class PublicClient:
    def __init__(
        self,
        github_token: str | None = None,
        *,
        max_attempts: int = GITHUB_READ_MAX_ATTEMPTS,
        retry_base_seconds: float = GITHUB_READ_RETRY_BASE_SECONDS,
        retry_max_seconds: float = GITHUB_READ_RETRY_MAX_SECONDS,
        request_timeout_seconds: float = GITHUB_READ_REQUEST_TIMEOUT_SECONDS,
        deadline_seconds: float = GITHUB_READ_DEADLINE_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        if (
            max_attempts < 1
            or retry_base_seconds < 0
            or retry_max_seconds < retry_base_seconds
            or request_timeout_seconds <= 0
            or deadline_seconds <= 0
        ):
            raise ValueError("invalid GitHub public-read retry configuration")
        self.github_token = github_token
        self.max_attempts = max_attempts
        self.retry_base_seconds = retry_base_seconds
        self.retry_max_seconds = retry_max_seconds
        self.request_timeout_seconds = request_timeout_seconds
        self.sleep = sleep
        self.now = now
        self.monotonic = monotonic
        self.deadline = monotonic() + deadline_seconds

    @staticmethod
    def _github_endpoint_class(url: str) -> str | None:
        parsed = urllib.parse.urlsplit(url)
        host = (parsed.hostname or "").lower()
        if host == "api.github.com":
            path = parsed.path
            endpoint_classes = (
                ("/releases", "releases-api"),
                ("/git/", "git-api"),
                ("/contents/", "contents-api"),
                ("/commits/", "commits-api"),
                ("/actions/", "actions-api"),
                ("/environments/", "environments-api"),
            )
            for marker, endpoint_class in endpoint_classes:
                if marker in path:
                    return endpoint_class
            if path.startswith("/users/"):
                return "users-api"
            return "repositories-api"
        if host == "github.com" or host.endswith(".github.com") or host.endswith(".githubusercontent.com"):
            return "github-download"
        return None

    @staticmethod
    def _error_detail(error: urllib.error.HTTPError) -> str:
        try:
            return error.read(1024).decode(errors="replace")
        except OSError:
            return "response body unavailable"

    @staticmethod
    def _is_rate_limited(error: urllib.error.HTTPError, detail: str) -> bool:
        headers = error.headers or {}
        return error.code == 429 or (
            error.code == 403
            and (
                headers.get("Retry-After") is not None
                or headers.get("X-RateLimit-Remaining") == "0"
                or "rate limit" in detail.lower()
            )
        )

    @staticmethod
    def _transport_name(error: BaseException) -> str | None:
        reason = error.reason if isinstance(error, urllib.error.URLError) else error
        if isinstance(
            reason,
            ConnectionError | TimeoutError | http.client.IncompleteRead | http.client.RemoteDisconnected,
        ):
            return type(reason).__name__
        if isinstance(reason, OSError) and reason.errno in {
            errno.ECONNABORTED,
            errno.ECONNRESET,
            errno.EPIPE,
            errno.ETIMEDOUT,
        }:
            return type(reason).__name__
        return None

    def _server_retry_delay(self, headers: Mapping[str, str]) -> float | None:
        delays: list[float] = []
        retry_after = headers.get("Retry-After")
        if retry_after:
            try:
                delays.append(float(retry_after))
            except ValueError:
                try:
                    retry_at = email.utils.parsedate_to_datetime(retry_after)
                except (TypeError, ValueError):
                    pass
                else:
                    if retry_at.tzinfo is None:
                        retry_at = retry_at.replace(tzinfo=dt.UTC)
                    delays.append(retry_at.timestamp() - self.now())
        rate_limit_reset = headers.get("X-RateLimit-Reset")
        if rate_limit_reset:
            with contextlib.suppress(ValueError):
                delays.append(float(rate_limit_reset) - self.now())
        return max((delay for delay in delays if delay > 0), default=None)

    def _retry_delay(self, attempt: int, failure: _TransientGitHubRead) -> float:
        backoff = min(self.retry_base_seconds * (2 ** (attempt - 1)), self.retry_max_seconds)
        return max(backoff, self._server_retry_delay(failure.headers) or 0)

    def _remaining_time(self) -> float:
        return self.deadline - self.monotonic()

    def _run(
        self,
        url: str,
        operation: Callable[[urllib.response.addinfourl], Any],
        *,
        headers: dict[str, str] | None,
        accept: str | None,
    ) -> Any:
        endpoint_class = self._github_endpoint_class(url)
        attempt_limit = self.max_attempts if endpoint_class is not None else 1
        request_headers = {
            "User-Agent": "durable-workflow-beta-candidate-verifier/1",
            **(headers or {}),
        }
        if accept:
            request_headers["Accept"] = accept
        if self.github_token and urllib.parse.urlsplit(url).hostname == "api.github.com":
            request_headers["Authorization"] = f"Bearer {self.github_token}"
            request_headers.setdefault("X-GitHub-Api-Version", "2022-11-28")

        for attempt in range(1, attempt_limit + 1):
            if endpoint_class is not None and self._remaining_time() <= 0:
                raise PublicInfrastructureError(endpoint_class, attempt - 1, reason="workflow-deadline")
            timeout = min(self.request_timeout_seconds, self._remaining_time()) if endpoint_class is not None else 60
            request = urllib.request.Request(url, headers=request_headers)
            failure: _TransientGitHubRead | None = None
            try:
                response = urllib.request.urlopen(request, timeout=timeout)
                result = operation(response)
                if endpoint_class is not None and self._remaining_time() <= 0:
                    raise PublicInfrastructureError(endpoint_class, attempt, reason="workflow-deadline")
                return result
            except urllib.error.HTTPError as error:
                detail = self._error_detail(error)
                if endpoint_class is not None and (500 <= error.code <= 599 or self._is_rate_limited(error, detail)):
                    failure = _TransientGitHubRead(f"status={error.code}", error.headers)
                else:
                    raise CandidateError(f"public request failed ({error.code}) for {url}: {detail}") from error
            except (urllib.error.URLError, ConnectionError, TimeoutError, http.client.IncompleteRead) as error:
                transport = self._transport_name(error)
                if endpoint_class is not None and transport is not None:
                    failure = _TransientGitHubRead(f"transport={transport}")
                else:
                    reason = error.reason if isinstance(error, urllib.error.URLError) else error
                    raise CandidateError(f"public request failed for {url}: {reason}") from error

            assert endpoint_class is not None and failure is not None
            if attempt == attempt_limit:
                raise PublicInfrastructureError(
                    endpoint_class,
                    attempt,
                    reason="retry-exhausted",
                    failure=failure.evidence,
                )
            delay = self._retry_delay(attempt, failure)
            if delay >= self._remaining_time():
                raise PublicInfrastructureError(
                    endpoint_class,
                    attempt,
                    reason="workflow-deadline",
                    failure=failure.evidence,
                )
            print(
                f"GitHub public read retry: endpoint_class={endpoint_class} "
                f"attempt={attempt}/{attempt_limit} {failure.evidence} delay={delay:g}s",
                file=sys.stderr,
            )
            self.sleep(delay)
        raise AssertionError("GitHub public-read retry loop ended unexpectedly")

    def request(
        self,
        url: str,
        *,
        headers: dict[str, str] | None = None,
        accept: str | None = None,
    ) -> urllib.response.addinfourl:
        return self._run(url, lambda response: response, headers=headers, accept=accept)

    def json(self, url: str, *, headers: dict[str, str] | None = None, accept: str | None = None) -> Any:
        def read_json(response: urllib.response.addinfourl) -> Any:
            with response:
                try:
                    return json.load(response)
                except (json.JSONDecodeError, UnicodeDecodeError) as error:
                    raise CandidateError(f"public endpoint did not return valid JSON: {url}") from error

        return self._run(url, read_json, headers=headers, accept=accept)

    def bytes(self, url: str, *, headers: dict[str, str] | None = None, accept: str | None = None) -> bytes:
        def read_bytes(response: urllib.response.addinfourl) -> bytes:
            with response:
                return response.read()

        return self._run(url, read_bytes, headers=headers, accept=accept)

    def download(self, url: str, path: Path, *, expected_sha256: str | None = None) -> dict[str, Any]:
        def download_once(response: urllib.response.addinfourl) -> tuple[str, int]:
            digest = hashlib.sha256()
            size = 0
            with response, path.open("wb") as destination:
                while chunk := response.read(1024 * 1024):
                    digest.update(chunk)
                    destination.write(chunk)
                    size += len(chunk)
            return digest.hexdigest(), size

        actual, size = self._run(url, download_once, headers=None, accept=None)
        if expected_sha256 and actual != expected_sha256.lower():
            raise CandidateError(f"download digest mismatch for {url}: expected {expected_sha256}, got {actual}")
        return {"url": url, "size": size, "sha256": actual}


def resolve_github_tag(client: PublicClient, repository: str, version: str) -> dict[str, Any]:
    encoded = urllib.parse.quote(version, safe="")
    url = f"https://api.github.com/repos/{repository}/git/ref/tags/{encoded}"
    ref = client.json(url)
    target = ref.get("object", {})
    tag_object = target.get("sha")
    seen: set[str] = set()
    while target.get("type") == "tag":
        sha = target.get("sha")
        if not isinstance(sha, str) or sha in seen:
            raise CandidateError(f"invalid annotated tag chain for {repository}@{version}")
        seen.add(sha)
        annotated = client.json(f"https://api.github.com/repos/{repository}/git/tags/{sha}")
        target = annotated.get("object", {})
    if target.get("type") != "commit" or not COMMIT_PATTERN.fullmatch(str(target.get("sha", ""))):
        raise CandidateError(f"release tag {repository}@{version} does not resolve to a commit")
    return {
        "repository": repository,
        "tag": version,
        "tag_object": tag_object,
        "commit": target["sha"],
        "url": f"https://github.com/{repository}/tree/{version}",
    }


def require_tag_commit(source: dict[str, Any], expected_commit: str) -> None:
    if source["commit"] != expected_commit:
        raise CandidateError(
            f"release tag {source['repository']}@{source['tag']} points to {source['commit']}, not {expected_commit}"
        )


def verify_composer(
    client: PublicClient, component: Component, version: str, expected_commit: str, directory: Path
) -> dict[str, Any]:
    encoded = "/".join(urllib.parse.quote(part, safe="") for part in component.package.split("/"))
    metadata_url = f"https://repo.packagist.org/p2/{encoded}.json"
    payload = client.json(metadata_url)
    try:
        release = exact_package_version(payload, component.package, version)
    except PackagistMetadataError as error:
        raise CandidateError(f"Packagist metadata for {component.package} is invalid: {error}") from error
    if not release:
        raise CandidateError(f"Packagist does not expose {component.package}@{version}")
    source = release.get("source")
    source_reference = source.get("reference") if isinstance(source, dict) else None
    dist = release.get("dist", {})
    dist_reference = dist.get("reference") if isinstance(dist, dict) else None
    if source_reference != expected_commit or dist_reference != expected_commit:
        raise CandidateError(
            f"Packagist source identity for {component.package}@{version} does not match {expected_commit}"
        )
    dist_url = dist.get("url") if isinstance(dist, dict) else None
    if not isinstance(dist_url, str) or not dist_url.startswith("https://"):
        raise CandidateError(f"Packagist release {component.package}@{version} has no public dist URL")
    download = client.download(dist_url, directory / f"{component.package.replace('/', '-')}.zip")
    return {
        "kind": "composer",
        "package": component.package,
        "registry": metadata_url,
        "source_reference": source_reference,
        "dist_reference": dist_reference,
        "dist": download,
    }


def parse_checksums(raw: bytes) -> dict[str, str]:
    checksums: dict[str, str] = {}
    for line in raw.decode("utf-8").splitlines():
        match = re.fullmatch(r"([0-9a-fA-F]{64})\s+[*]?([^/\s]+)", line.strip())
        if match:
            checksums[match.group(2)] = match.group(1).lower()
    return checksums


def inspect_cli_phar_identity(phar_path: Path, version: str, expected_commit: str) -> str:
    """Read generated source identity from a PHAR archive without executing its stub."""
    if shutil.which("php") is None:
        raise CandidateError("PHP is required to inspect CLI release source metadata")
    inspection = r"""
try {
    $archive = new Phar($argv[1]);
    $path = 'src/GeneratedBuildInfo.php';
    if (!$archive->offsetExists($path)) {
        exit(41);
    }
    $contents = $archive[$path]->getContent();
    if (strlen($contents) > 16384) {
        exit(42);
    }
    fwrite(STDOUT, base64_encode($contents));
} catch (Throwable $error) {
    exit(43);
}
"""
    try:
        process = subprocess.run(
            [
                "php",
                "-d",
                "display_errors=0",
                "-d",
                "log_errors=0",
                "-r",
                inspection,
                "--",
                str(phar_path),
            ],
            cwd=phar_path.parent,
            check=False,
            text=True,
            capture_output=True,
            env={"PATH": os.environ.get("PATH", os.defpath)},
            timeout=30,
        )
    except subprocess.TimeoutExpired as error:
        raise CandidateError(f"CLI PHAR for {version} source metadata inspection timed out") from error
    if process.returncode:
        raise CandidateError(f"CLI PHAR for {version} has no inspectable generated source metadata")
    try:
        generated = base64.b64decode(process.stdout, validate=True)
    except (ValueError, binascii.Error) as error:
        raise CandidateError(f"CLI PHAR for {version} has invalid generated source metadata") from error
    if len(generated) > PHAR_BUILD_INFO_MAX_BYTES:
        raise CandidateError(f"CLI PHAR for {version} has oversized generated source metadata")
    try:
        source = generated.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CandidateError(f"CLI PHAR for {version} has non-UTF-8 generated source metadata") from error

    def generated_constant(name: str) -> str | None:
        matches = re.findall(rf"\bpublic\s+const\s+{name}\s*=\s*'([^'\\\r\n]*)'\s*;", source)
        return matches[0] if len(matches) == 1 else None

    if generated_constant("VERSION") != version.lstrip("v") or generated_constant("COMMIT") != expected_commit:
        raise CandidateError(f"CLI PHAR for {version} does not embed planned source commit {expected_commit}")
    return canonical_cli_embedded_identity(version, expected_commit)


def verify_github_release(
    client: PublicClient,
    component: Component,
    version: str,
    expected_commit: str,
    directory: Path,
) -> dict[str, Any]:
    encoded = urllib.parse.quote(version, safe="")
    api_url = f"https://api.github.com/repos/{component.repository}/releases/tags/{encoded}"
    release = client.json(api_url)
    if release.get("draft") or release.get("tag_name") != version:
        raise CandidateError(f"GitHub release {component.repository}@{version} is absent or still a draft")
    assets = {asset.get("name"): asset for asset in release.get("assets", [])}
    missing = CLI_ASSETS - set(assets)
    if missing:
        raise CandidateError(f"GitHub release {component.repository}@{version} lacks assets: {sorted(missing)}")

    checksum_asset = assets["SHA256SUMS"]
    checksum_raw = client.bytes(checksum_asset["browser_download_url"])
    checksum_path = directory / "SHA256SUMS"
    checksum_path.write_bytes(checksum_raw)
    checksums = parse_checksums(checksum_raw)
    downloadable = sorted(CLI_ASSETS - {"SHA256SUMS"})
    if set(downloadable) - set(checksums):
        raise CandidateError("CLI SHA256SUMS does not cover every public release asset")

    verified_assets: list[dict[str, Any]] = []
    downloaded_paths = []
    for name in downloadable:
        asset = assets[name]
        asset_path = directory / name
        result = client.download(asset["browser_download_url"], asset_path, expected_sha256=checksums[name])
        result.update({"name": name, "asset_id": asset.get("id")})
        verified_assets.append(result)
        downloaded_paths.append(asset_path)
    verified_assets.append(
        {
            "name": "SHA256SUMS",
            "asset_id": checksum_asset.get("id"),
            "url": checksum_asset["browser_download_url"],
            "size": len(checksum_raw),
            "sha256": hashlib.sha256(checksum_raw).hexdigest(),
        }
    )
    downloaded_paths.append(checksum_path)
    if shutil.which("gh") is None:
        raise CandidateError("GitHub CLI is required to verify CLI release attestations")
    signer_workflow = f"{component.repository}/.github/workflows/release.yml"
    attestation_modes = [
        (
            "exact-tag",
            ["--source-ref", f"refs/tags/{version}", "--source-digest", expected_commit],
            {"mode": "exact-tag", "ref": f"refs/tags/{version}", "commit": expected_commit},
        ),
        (
            "qualified-main-workflow",
            ["--source-ref", "refs/heads/main", "--signer-workflow", signer_workflow],
            {"mode": "qualified-main-workflow", "ref": "refs/heads/main", "workflow": signer_workflow},
        ),
    ]
    selected_attestation_mode: tuple[str, list[str], dict[str, str]] | None = None
    for asset_path in downloaded_paths:
        base_arguments = ["gh", "attestation", "verify", str(asset_path), "--repo", component.repository]
        candidates = attestation_modes if selected_attestation_mode is None else [selected_attestation_mode]
        failures: list[str] = []
        for mode in candidates:
            process = subprocess.run([*base_arguments, *mode[1]], check=False, text=True, capture_output=True)
            if process.returncode == 0:
                selected_attestation_mode = mode
                break
            failures.append(f"{mode[0]}: {process.stderr.strip()}")
        else:
            raise CandidateError(f"CLI build attestation failed for {asset_path.name}: {'; '.join(failures)}")

    assert selected_attestation_mode is not None
    embedded_identity = inspect_cli_phar_identity(directory / "dw.phar", version, expected_commit)
    return {
        "kind": "github-release",
        "repository": component.repository,
        "release_id": release.get("id"),
        "release_url": release.get("html_url"),
        "build_attestations_verified": True,
        "build_attestation_authority": selected_attestation_mode[2],
        "package_source": {
            "commit": expected_commit,
            "embedded_phar_identity": embedded_identity,
        },
        "assets": verified_assets,
    }


def archive_files(path: Path, *, zip_archive: bool = False) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    if zip_archive:
        with zipfile.ZipFile(path) as archive:
            for member in archive.infolist():
                if member.is_dir():
                    continue
                files[member.filename] = archive.read(member)
        return files
    with tarfile.open(path, "r:*") as archive:
        for member in archive.getmembers():
            if not member.isfile():
                continue
            extracted = archive.extractfile(member)
            if extracted is not None:
                files[member.name] = extracted.read()
    return files


def strip_archive_root(files: dict[str, bytes]) -> dict[str, bytes]:
    stripped = {}
    for name, content in files.items():
        _, separator, relative = name.partition("/")
        if separator and relative:
            stripped[relative] = content
    return stripped


def verify_python_archive_identity(
    client: PublicClient,
    component: Component,
    expected_commit: str,
    sdist_path: Path,
    wheel_paths: list[Path],
    directory: Path,
) -> dict[str, Any]:
    source_url = f"https://github.com/{component.repository}/archive/{expected_commit}.tar.gz"
    source_path = directory / "python-source.tar.gz"
    source_download = client.download(source_url, source_path)
    source_files = strip_archive_root(archive_files(source_path))
    sdist_files = strip_archive_root(archive_files(sdist_path))
    compared_source_files = []
    for name, content in sdist_files.items():
        if ".egg-info/" in name or name.endswith(("/PKG-INFO", "PKG-INFO")):
            continue
        if name == "setup.cfg" and name not in source_files:
            # setuptools may synthesize this legacy metadata file while
            # assembling an sdist from a pyproject-only source tree.
            continue
        if name not in source_files or source_files[name] != content:
            raise CandidateError(f"PyPI source archive file {name} does not match source commit {expected_commit}")
        compared_source_files.append(name)
    if "pyproject.toml" not in compared_source_files or not any(
        name.startswith("src/durable_workflow/") and name.endswith(".py") for name in compared_source_files
    ):
        raise CandidateError("PyPI source archive did not provide enough source files for identity verification")

    compared_wheel_files = []
    for wheel_path in wheel_paths:
        wheel_files = archive_files(wheel_path, zip_archive=True)
        for name, content in wheel_files.items():
            if ".dist-info/" in name:
                continue
            source_name = f"src/{name}"
            if source_name not in sdist_files or sdist_files[source_name] != content:
                raise CandidateError(f"PyPI wheel file {name} does not match the verified source archive")
            compared_wheel_files.append(name)
    if not any(name.startswith("durable_workflow/") and name.endswith(".py") for name in compared_wheel_files):
        raise CandidateError("PyPI wheel did not provide enough package files for identity verification")
    return {
        "source_archive": source_download,
        "source_files_compared": len(compared_source_files),
        "wheel_files_compared": len(compared_wheel_files),
        "source_commit": expected_commit,
    }


def verify_pypi(
    client: PublicClient, component: Component, version: str, expected_commit: str, directory: Path
) -> dict[str, Any]:
    encoded_package = urllib.parse.quote(component.package, safe="")
    registry_version = canonical_pypi_version(version)
    encoded_version = urllib.parse.quote(registry_version, safe="")
    api_url = f"https://pypi.org/pypi/{encoded_package}/{encoded_version}/json"
    payload = client.json(api_url)
    published_version = payload.get("info", {}).get("version")
    if published_version not in {version, registry_version}:
        raise CandidateError(f"PyPI does not expose {component.package}=={version}")
    project_urls = payload.get("info", {}).get("project_urls") or {}
    repository_urls = {str(value).rstrip("/") for value in project_urls.values()}
    expected_repository = f"https://github.com/{component.repository}"
    if expected_repository not in repository_urls:
        raise CandidateError(f"PyPI metadata for {component.package}=={version} does not name {expected_repository}")
    files = [
        item
        for item in payload.get("urls", [])
        if not item.get("yanked") and item.get("packagetype") in {"bdist_wheel", "sdist"}
    ]
    package_types = {item.get("packagetype") for item in files}
    if not {"bdist_wheel", "sdist"}.issubset(package_types):
        raise CandidateError(f"PyPI release {component.package}=={version} must provide a wheel and source archive")
    verified_files = []
    sdist_path = None
    wheel_paths = []
    for item in files:
        expected_digest = item.get("digests", {}).get("sha256")
        if not re.fullmatch(r"[0-9a-f]{64}", str(expected_digest or "")):
            raise CandidateError(f"PyPI file {item.get('filename')} has no SHA-256 identity")
        file_path = directory / item["filename"]
        result = client.download(item["url"], file_path, expected_sha256=expected_digest)
        result.update({"filename": item["filename"], "package_type": item.get("packagetype")})
        verified_files.append(result)
        if item.get("packagetype") == "sdist":
            sdist_path = file_path
        elif item.get("packagetype") == "bdist_wheel":
            wheel_paths.append(file_path)
    if sdist_path is None:
        raise CandidateError(f"PyPI release {component.package}=={version} has no source archive")
    source_identity = verify_python_archive_identity(
        client, component, expected_commit, sdist_path, wheel_paths, directory
    )
    return {
        "kind": "pypi",
        "package": component.package,
        "registry": api_url,
        "source_identity": source_identity,
        "files": verified_files,
    }


def verify_crate(
    client: PublicClient, component: Component, version: str, expected_commit: str, directory: Path
) -> dict[str, Any]:
    encoded_package = urllib.parse.quote(component.package, safe="")
    encoded_version = urllib.parse.quote(version, safe="")
    api_url = f"https://crates.io/api/v1/crates/{encoded_package}/{encoded_version}"
    payload = client.json(api_url)
    crate_version = payload.get("version", {})
    if crate_version.get("num") != version or crate_version.get("yanked"):
        raise CandidateError(f"crates.io does not expose an active {component.package}@{version}")
    crate_payload = client.json(f"https://crates.io/api/v1/crates/{encoded_package}")
    crate_metadata = crate_payload.get("crate", {})
    expected_repository = f"https://github.com/{component.repository}"
    if str(crate_metadata.get("repository", "")).rstrip("/") != expected_repository:
        raise CandidateError(
            f"crates.io metadata for {component.package}@{version} names a different source repository"
        )
    expected_digest = crate_version.get("checksum")
    if not re.fullmatch(r"[0-9a-f]{64}", str(expected_digest or "")):
        raise CandidateError(f"crates.io release {component.package}@{version} has no SHA-256 identity")
    download_url = f"https://crates.io/api/v1/crates/{encoded_package}/{encoded_version}/download"
    archive_path = directory / f"{component.package}-{version}.crate"
    download = client.download(download_url, archive_path, expected_sha256=expected_digest)
    with tarfile.open(archive_path, "r:gz") as archive:
        vcs_members = [member for member in archive.getmembers() if member.name.endswith("/.cargo_vcs_info.json")]
        if len(vcs_members) != 1:
            raise CandidateError("published crate must contain exactly one .cargo_vcs_info.json")
        extracted = archive.extractfile(vcs_members[0])
        if extracted is None:
            raise CandidateError("cannot read crate source identity")
        vcs_info = json.load(extracted)
    archive_commit = vcs_info.get("git", {}).get("sha1")
    if archive_commit != expected_commit or vcs_info.get("git", {}).get("dirty", False) is not False:
        raise CandidateError(f"published crate source identity does not match clean commit {expected_commit}")
    return {
        "kind": "crates.io",
        "package": component.package,
        "registry": api_url,
        "archive_vcs_commit": archive_commit,
        "archive_vcs_dirty": False,
        "archive": download,
    }


def oci_json(client: PublicClient, url: str, token: str, accept: str) -> tuple[Any, str | None]:
    response = client.request(url, headers={"Authorization": f"Bearer {token}"}, accept=accept)
    with response:
        digest = response.headers.get("Docker-Content-Digest")
        return json.load(response), digest


def verify_oci(
    client: PublicClient, component: Component, version: str, expected_commit: str, _directory: Path
) -> dict[str, Any]:
    registry, repository = component.package.split("/", 1)
    if registry == "docker.io":
        registry_api = "registry-1.docker.io"
        token_host = "auth.docker.io"
        token_service = "registry.docker.io"
    else:
        registry_api = registry
        token_host = registry
        token_service = registry
    token_url = (
        f"https://{token_host}/token?service={urllib.parse.quote(token_service)}"
        f"&scope={urllib.parse.quote(f'repository:{repository}:pull')}"
    )
    token = client.json(token_url).get("token")
    if not isinstance(token, str) or not token:
        raise CandidateError(f"public OCI registry did not grant pull access to {component.package}:{version}")
    manifest_accept = ", ".join(
        [
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ]
    )
    manifest_url = f"https://{registry_api}/v2/{repository}/manifests/{urllib.parse.quote(version, safe='')}"
    manifest, manifest_digest_header = oci_json(client, manifest_url, token, manifest_accept)
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(manifest_digest_header or "")):
        raise CandidateError(f"OCI image {component.package}:{version} has no immutable manifest digest")
    descriptors = manifest.get("manifests")
    if not isinstance(descriptors, list):
        raise CandidateError(f"OCI image {component.package}:{version} is not a multi-platform release")
    selected_platforms: list[str] = []
    candidates = []
    for descriptor in descriptors:
        platform = descriptor.get("platform", {})
        label = f"{platform.get('os')}/{platform.get('architecture')}"
        if platform.get("os") == "linux" and platform.get("architecture") in {"amd64", "arm64"}:
            candidates.append(descriptor)
            selected_platforms.append(label)
    if set(selected_platforms) != {"linux/amd64", "linux/arm64"}:
        raise CandidateError(f"OCI image {component.package}:{version} lacks required Linux platforms")

    configs = []
    for descriptor in candidates:
        child_url = f"https://{registry_api}/v2/{repository}/manifests/{descriptor['digest']}"
        child, child_digest = oci_json(client, child_url, token, manifest_accept)
        if child_digest != descriptor["digest"]:
            raise CandidateError(f"OCI image {component.package}:{version} platform digest changed during verification")
        config_digest = child.get("config", {}).get("digest")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", str(config_digest or "")):
            raise CandidateError(f"OCI image {component.package}:{version} has no immutable config digest")
        config_url = f"https://{registry_api}/v2/{repository}/blobs/{config_digest}"
        config = client.json(config_url, headers={"Authorization": f"Bearer {token}"})
        labels = config.get("config", {}).get("Labels") or {}
        expected_labels = {
            "org.opencontainers.image.revision": expected_commit,
            "dev.durable-workflow.release.tag": version,
        }
        if any(labels.get(key) != value for key, value in expected_labels.items()):
            raise CandidateError(f"OCI image {component.package}:{version} labels do not match its source release")
        configs.append({"digest": config_digest, "labels": expected_labels})
    return {
        "kind": "oci",
        "image": f"{component.package}:{version}",
        "manifest_digest": manifest_digest_header,
        "platforms": selected_platforms,
        "configs": configs,
    }


VERIFIERS = {
    "composer": verify_composer,
    "github-release": verify_github_release,
    "pypi": verify_pypi,
    "crates.io": verify_crate,
    "oci": verify_oci,
}


def verify_candidate(manifest: dict[str, Any], client: PublicClient) -> dict[str, Any]:
    components = {}
    with tempfile.TemporaryDirectory(prefix="beta-candidate-") as temporary:
        directory = Path(temporary)
        for name, component in COMPONENTS.items():
            identity = manifest["components"][name]
            try:
                source = resolve_github_tag(client, component.repository, identity["version"])
                require_tag_commit(source, identity["commit"])
                if name == "waterline":
                    distributions = {
                        "embedded": verify_composer(
                            client, component, identity["version"], identity["commit"], directory
                        ),
                        "service": verify_oci(
                            client, WATERLINE_SERVICE, identity["version"], identity["commit"], directory
                        ),
                    }
                else:
                    distribution = VERIFIERS[component.distribution](
                        client, component, identity["version"], identity["commit"], directory
                    )
            except CandidateError as error:
                raise CandidateError(f"{name}: {error}") from error
            components[name] = {
                "version": identity["version"],
                "commit": identity["commit"],
                "source": source,
                "outcome": "verified",
            }
            if name == "waterline":
                components[name]["distributions"] = distributions
            else:
                components[name]["distribution"] = distribution
    return {
        "schema": VERIFICATION_SCHEMA,
        "candidate": manifest["candidate"],
        "manifest_sha256": manifest_digest(manifest),
        "verified_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "outcome": "verified",
        "components": components,
    }


def revalidate_verification(
    verification: dict[str, Any], manifest: dict[str, Any], client: PublicClient
) -> dict[str, Any]:
    """Independently reproduce and canonicalize evidence before an authenticated write."""
    validate_verification(verification, manifest)
    components: dict[str, Any] = {}
    with tempfile.TemporaryDirectory(prefix="beta-candidate-writer-revalidation-") as temporary:
        directory = Path(temporary)
        for name, component in COMPONENTS.items():
            identity = manifest["components"][name]
            submitted = verification["components"][name]
            try:
                source = resolve_github_tag(client, component.repository, identity["version"])
                require_tag_commit(source, identity["commit"])
                if name == "waterline":
                    distributions = {
                        "embedded": verify_composer(
                            client,
                            component,
                            identity["version"],
                            identity["commit"],
                            directory,
                        ),
                        "service": verify_oci(
                            client,
                            WATERLINE_SERVICE,
                            identity["version"],
                            identity["commit"],
                            directory,
                        ),
                    }
                elif component.distribution == "github-release":
                    distribution = verify_github_release(
                        client,
                        component,
                        identity["version"],
                        identity["commit"],
                        directory,
                    )
                else:
                    distribution = VERIFIERS[component.distribution](
                        client, component, identity["version"], identity["commit"], directory
                    )
            except CandidateError as error:
                raise CandidateError(f"fresh writer revalidation failed for {name}: {error}") from error
            submitted_distributions = submitted.get("distributions") if name == "waterline" else None
            if source != submitted["source"] or (
                distributions != submitted_distributions
                if name == "waterline"
                else distribution != submitted["distribution"]
            ):
                raise CandidateError(
                    f"fresh writer revalidation for {name} differs from the isolated verification handoff"
                )
            components[name] = {
                "version": identity["version"],
                "commit": identity["commit"],
                "source": source,
                "outcome": "verified",
            }
            if name == "waterline":
                components[name]["distributions"] = distributions
            else:
                components[name]["distribution"] = distribution
    return {
        "schema": VERIFICATION_SCHEMA,
        "candidate": manifest["candidate"],
        "manifest_sha256": manifest_digest(manifest),
        "verified_at": dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "outcome": "verified",
        "components": components,
    }


def run_git(arguments: list[str], *, cwd: Path, env: dict[str, str] | None = None, check: bool = True) -> str:
    process = subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        env=env,
        check=False,
        text=True,
        capture_output=True,
    )
    if check and process.returncode:
        raise CandidateError(f"git {' '.join(arguments)} failed: {process.stderr.strip()}")
    return process.stdout.strip()


def read_record_file(repository: Path, ref: str, filename: str) -> bytes:
    process = subprocess.run(
        ["git", "show", f"{ref}:{filename}"],
        cwd=repository,
        check=False,
        capture_output=True,
    )
    if process.returncode:
        raise CandidateError(f"existing candidate record is incomplete: missing {filename}")
    return process.stdout


def fetch_existing_record(repository: Path, remote: str, tag: str) -> str | None:
    remote_ref = f"refs/tags/{tag}"
    query = subprocess.run(
        ["git", "ls-remote", "--exit-code", "--refs", remote, remote_ref],
        cwd=repository,
        check=False,
        text=True,
        capture_output=True,
    )
    if query.returncode == 2:
        return None
    if query.returncode:
        raise CandidateError(f"cannot inspect remote candidate record: {query.stderr.strip()}")
    local_ref = f"refs/beta-candidate-check/{hashlib.sha256(tag.encode()).hexdigest()}"
    run_git(["fetch", "--no-tags", "--force", remote, f"{remote_ref}:{local_ref}"], cwd=repository)
    return local_ref


def write_github_output(path: Path | None, values: dict[str, str]) -> None:
    if path is None:
        return
    with path.open("a", encoding="utf-8") as output:
        for key, value in values.items():
            output.write(f"{key}={value}\n")


def check_candidate_compatibility(repository: Path, manifest_path: Path, *, remote: str) -> dict[str, str]:
    manifest = load_manifest(manifest_path)
    canonical_manifest = canonical_json(manifest)
    tag = f"{TAG_PREFIX}{manifest['candidate']}"
    existing_ref = fetch_existing_record(repository, remote, tag)
    if not existing_ref:
        return {"status": "new", "candidate": manifest["candidate"], "tag": tag}
    existing_manifest = read_record_file(repository, existing_ref, "candidate.json")
    if existing_manifest != canonical_manifest:
        raise CandidateError(f"candidate {manifest['candidate']} is immutable and the requested tuple is different")
    read_record_file(repository, existing_ref, "verification.json")
    return {
        "status": "existing",
        "candidate": manifest["candidate"],
        "tag": tag,
        "commit": run_git(["rev-parse", f"{existing_ref}^{{commit}}"], cwd=repository),
    }


def record_candidate(
    repository: Path,
    manifest_path: Path,
    verification_path: Path,
    *,
    remote: str,
    authoritative_verification: Path,
    client: PublicClient,
) -> dict[str, str]:
    manifest = load_manifest(manifest_path)
    canonical_manifest = canonical_json(manifest)
    verification = load_verification(verification_path, manifest)
    tag = f"{TAG_PREFIX}{manifest['candidate']}"

    existing_ref = fetch_existing_record(repository, remote, tag)
    if existing_ref:
        existing_manifest = read_record_file(repository, existing_ref, "candidate.json")
        if existing_manifest != canonical_manifest:
            raise CandidateError(f"candidate {manifest['candidate']} is immutable and the requested tuple is different")
        existing_verification = read_record_file(repository, existing_ref, "verification.json")
        authoritative_verification.write_bytes(existing_verification)
        return {
            "status": "existing",
            "candidate": manifest["candidate"],
            "tag": tag,
            "commit": run_git(["rev-parse", f"{existing_ref}^{{commit}}"], cwd=repository),
        }

    verification = revalidate_verification(verification, manifest, client)
    canonical_verification = canonical_json(verification)

    with tempfile.NamedTemporaryFile(prefix="beta-candidate-index-", delete=False) as index:
        index_path = Path(index.name)
    try:
        env = os.environ.copy()
        env["GIT_INDEX_FILE"] = str(index_path)
        index_path.unlink(missing_ok=True)
        run_git(["read-tree", "--empty"], cwd=repository, env=env)
        record_files = (("candidate.json", canonical_manifest), ("verification.json", canonical_verification))
        for filename, content in record_files:
            blob = (
                subprocess.run(
                    ["git", "hash-object", "-w", "--stdin"],
                    cwd=repository,
                    env=env,
                    input=content,
                    check=True,
                    stdout=subprocess.PIPE,
                )
                .stdout.decode()
                .strip()
            )
            run_git(["update-index", "--add", "--cacheinfo", f"100644,{blob},{filename}"], cwd=repository, env=env)
        tree = run_git(["write-tree"], cwd=repository, env=env)
        commit_env = env.copy()
        commit_env.update(
            {
                "GIT_AUTHOR_NAME": "Durable Workflow Candidate Recorder",
                "GIT_AUTHOR_EMAIL": "support@durable-workflow.com",
                "GIT_COMMITTER_NAME": "Durable Workflow Candidate Recorder",
                "GIT_COMMITTER_EMAIL": "support@durable-workflow.com",
            }
        )
        commit = (
            subprocess.run(
                ["git", "commit-tree", tree],
                cwd=repository,
                env=commit_env,
                input=f"Record beta candidate {manifest['candidate']}\n".encode(),
                check=True,
                stdout=subprocess.PIPE,
            )
            .stdout.decode()
            .strip()
        )
    finally:
        index_path.unlink(missing_ok=True)

    push = subprocess.run(
        ["git", "push", remote, f"{commit}:refs/tags/{tag}"],
        cwd=repository,
        check=False,
        text=True,
        capture_output=True,
    )
    if push.returncode:
        # A concurrent first writer can win between inspection and push. Its
        # manifest is still authoritative, so apply the normal equality check.
        existing_ref = fetch_existing_record(repository, remote, tag)
        if not existing_ref:
            raise CandidateError(f"cannot publish candidate record: {push.stderr.strip()}")
        if read_record_file(repository, existing_ref, "candidate.json") != canonical_manifest:
            raise CandidateError(f"candidate {manifest['candidate']} was concurrently recorded with a different tuple")
        existing_verification = read_record_file(repository, existing_ref, "verification.json")
        authoritative_verification.write_bytes(existing_verification)
        return {
            "status": "existing",
            "candidate": manifest["candidate"],
            "tag": tag,
            "commit": run_git(["rev-parse", f"{existing_ref}^{{commit}}"], cwd=repository),
        }

    authoritative_verification.write_bytes(canonical_verification)
    return {"status": "created", "candidate": manifest["candidate"], "tag": tag, "commit": commit}


def command_validate(arguments: argparse.Namespace) -> None:
    manifest = load_manifest(arguments.manifest)
    if arguments.require_supported_train:
        from scripts.product_train import require_current_product_train

        require_current_product_train(manifest["components"])
    arguments.output.write_bytes(canonical_json(manifest))


def command_compare(arguments: argparse.Namespace) -> None:
    requested = canonical_json(load_manifest(arguments.requested))
    existing = canonical_json(load_manifest(arguments.existing))
    if requested != existing:
        raise CandidateError("candidate manifest mutation rejected")


def command_verify(arguments: argparse.Namespace) -> None:
    manifest = load_manifest(arguments.manifest)
    client = PublicClient(os.environ.get("GITHUB_TOKEN"))
    arguments.output.write_bytes(canonical_json(verify_candidate(manifest, client)))


def command_validate_verification(arguments: argparse.Namespace) -> None:
    manifest = load_manifest(arguments.manifest)
    load_verification(arguments.verification, manifest)


def command_check(arguments: argparse.Namespace) -> None:
    result = check_candidate_compatibility(arguments.repository, arguments.manifest, remote=arguments.remote)
    write_github_output(arguments.github_output, result)
    print(json.dumps(result, sort_keys=True))


def command_record(arguments: argparse.Namespace) -> None:
    result = record_candidate(
        arguments.repository,
        arguments.manifest,
        arguments.verification,
        remote=arguments.remote,
        authoritative_verification=arguments.authoritative_verification,
        client=PublicClient(os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")),
    )
    write_github_output(arguments.github_output, result)
    print(json.dumps(result, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate = subparsers.add_parser("validate", help="validate and canonicalize a candidate manifest")
    validate.add_argument("manifest", type=Path)
    validate.add_argument("output", type=Path)
    validate.add_argument("--require-supported-train", action="store_true")
    validate.set_defaults(handler=command_validate)

    compare = subparsers.add_parser("compare", help="prove two manifests have the same identity")
    compare.add_argument("requested", type=Path)
    compare.add_argument("existing", type=Path)
    compare.set_defaults(handler=command_compare)

    verify = subparsers.add_parser("verify", help="verify every public artifact and source release")
    verify.add_argument("manifest", type=Path)
    verify.add_argument("output", type=Path)
    verify.set_defaults(handler=command_verify)

    validate_verification_parser = subparsers.add_parser(
        "validate-verification",
        help="validate isolated verification evidence before granting mutation authority",
    )
    validate_verification_parser.add_argument("manifest", type=Path)
    validate_verification_parser.add_argument("verification", type=Path)
    validate_verification_parser.set_defaults(handler=command_validate_verification)

    check = subparsers.add_parser("check", help="reject mutation of an existing candidate before verification")
    check.add_argument("manifest", type=Path)
    check.add_argument("--repository", type=Path, default=Path.cwd())
    check.add_argument("--remote", default="origin")
    check.add_argument("--github-output", type=Path)
    check.set_defaults(handler=command_check)

    record = subparsers.add_parser("record", help="create or compare an immutable candidate Git tag")
    record.add_argument("manifest", type=Path)
    record.add_argument("verification", type=Path)
    record.add_argument("--repository", type=Path, default=Path.cwd())
    record.add_argument("--remote", default="origin")
    record.add_argument("--authoritative-verification", type=Path, required=True)
    record.add_argument("--github-output", type=Path)
    record.set_defaults(handler=command_record)
    return parser


def main() -> int:
    parser = build_parser()
    arguments = parser.parse_args()
    try:
        arguments.handler(arguments)
    except PublicInfrastructureError as error:
        print(f"beta candidate infrastructure failed: {error}", file=sys.stderr)
        return INFRASTRUCTURE_EXIT_CODE
    except CandidateError as error:
        print(f"beta candidate error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
