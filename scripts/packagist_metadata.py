"""Expand Packagist's Composer 2 metadata representation."""

from __future__ import annotations

import re
from typing import Any

COMPOSER_MINIFIED_FORMAT = "composer/2.0"
COMPOSER_RELEASE_PATTERN = re.compile(
    r"^v?(?P<release>\d+(?:\.\d+){0,3})"
    r"(?:[._-]?(?P<stability>stable|dev|alpha|a|beta|b|rc|patch|pl|p)(?P<number>(?:[._-]?\d+)*))?"
    r"(?:\+[0-9A-Za-z.-]+)?$",
    re.IGNORECASE,
)
STABILITY_ORDER = {
    "dev": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "rc": 3,
    "stable": 4,
    "patch": 5,
    "pl": 5,
    "p": 5,
}


class PackagistMetadataError(ValueError):
    """Packagist metadata does not satisfy the advertised wire format."""


def package_versions(payload: Any, package: str) -> list[dict[str, Any]]:
    """Return package versions after applying the advertised Composer diff format."""
    if not isinstance(payload, dict):
        raise PackagistMetadataError("response must be an object")
    packages = payload.get("packages")
    if packages is None:
        return []
    if not isinstance(packages, dict):
        raise PackagistMetadataError("packages must be an object")
    versions = packages.get(package)
    if versions is None:
        return []
    if not isinstance(versions, list):
        raise PackagistMetadataError(f"packages.{package} must be a list")

    if "minified" not in payload:
        return [_version_object(version, package) for version in versions]
    minified_format = payload["minified"]
    if minified_format != COMPOSER_MINIFIED_FORMAT:
        raise PackagistMetadataError(f"unsupported minified format: {minified_format!r}")

    expanded: list[dict[str, Any]] = []
    previous: dict[str, Any] | None = None
    previous_identity: tuple[tuple[int, ...], int, tuple[int, ...]] | None = None
    previous_version: str | None = None
    for index, version in enumerate(versions):
        diff = _version_object(version, package)
        compact_version = diff.get("version")
        if not isinstance(compact_version, str) or not compact_version or compact_version == "__unset":
            raise PackagistMetadataError(f"packages.{package} compact entry {index} must declare a version")
        identity = _composer_release_identity(compact_version, package, index)
        if previous_identity is not None and identity >= previous_identity:
            raise PackagistMetadataError(
                f"packages.{package} compact versions must be strictly descending; "
                f"{compact_version!r} follows {previous_version!r}"
            )
        if previous is None:
            current = diff.copy()
        else:
            current = previous.copy()
            for key, value in diff.items():
                if value == "__unset":
                    current.pop(key, None)
                else:
                    current[key] = value
        expanded.append(current)
        previous = current
        previous_identity = identity
        previous_version = compact_version
    return expanded


def exact_package_version(payload: Any, package: str, version: str) -> dict[str, Any] | None:
    """Return one exact package version, rejecting ambiguous registry metadata."""
    requested = version[1:] if version.startswith("v") else version
    matches: list[dict[str, Any]] = []
    for release in package_versions(payload, package):
        release_version = release.get("version")
        if not isinstance(release_version, str) or not release_version:
            raise PackagistMetadataError(f"packages.{package} entries must declare a version")
        comparable = release_version[1:] if release_version.startswith("v") else release_version
        if comparable == requested:
            matches.append(release)
    if len(matches) > 1:
        raise PackagistMetadataError(f"packages.{package} contains multiple records for exact version {version}")
    return matches[0] if matches else None


def _version_object(version: Any, package: str) -> dict[str, Any]:
    if not isinstance(version, dict):
        raise PackagistMetadataError(f"packages.{package} entries must be objects")
    return version


def _composer_release_identity(
    version: str, package: str, index: int
) -> tuple[tuple[int, ...], int, tuple[int, ...]]:
    match = COMPOSER_RELEASE_PATTERN.fullmatch(version)
    if match is None:
        raise PackagistMetadataError(
            f"packages.{package} compact entry {index} has an unsupported release version {version!r}"
        )
    release = tuple(int(part) for part in match.group("release").split("."))
    release += (0,) * (4 - len(release))
    stability = match.group("stability")
    stability_order = STABILITY_ORDER[stability.lower()] if stability else STABILITY_ORDER["stable"]
    number = tuple(int(part) for part in re.findall(r"\d+", match.group("number") or ""))
    return release, stability_order, number
