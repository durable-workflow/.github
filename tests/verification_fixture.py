from __future__ import annotations

import urllib.parse
from typing import Any

from scripts.beta_candidate import (
    CLI_ASSETS,
    COMPONENTS,
    VERIFICATION_SCHEMA,
    WATERLINE_SERVICE,
    manifest_digest,
)


def candidate_verification(candidate: dict[str, Any], *, verified_at: str = "2026-07-20T21:00:00Z") -> dict[str, Any]:
    results: dict[str, Any] = {}
    for index, (name, identity) in enumerate(candidate["components"].items(), start=1):
        component = COMPONENTS[name]
        version = identity["version"]
        commit = identity["commit"]
        source = {
            "repository": component.repository,
            "tag": version,
            "tag_object": commit,
            "commit": commit,
            "url": f"https://github.com/{component.repository}/tree/{version}",
        }

        def download(filename: str, seed: int = index, component_name: str = name) -> dict[str, Any]:
            return {
                "url": f"https://downloads.example.test/{component_name}/{urllib.parse.quote(filename)}",
                "size": 1000 + seed,
                "sha256": f"{seed:064x}",
            }

        if component.distribution == "composer":
            encoded = "/".join(urllib.parse.quote(part, safe="") for part in component.package.split("/"))
            distribution = {
                "kind": "composer",
                "package": component.package,
                "registry": f"https://repo.packagist.org/p2/{encoded}.json",
                "source_reference": commit,
                "dist_reference": commit,
                "dist": download("package.zip"),
            }
        elif component.distribution == "github-release":
            distribution = {
                "kind": "github-release",
                "repository": component.repository,
                "release_id": 100 + index,
                "release_url": f"https://github.com/{component.repository}/releases/tag/{version}",
                "build_attestations_verified": True,
                "build_attestation_authority": {
                    "mode": "exact-tag",
                    "ref": f"refs/tags/{version}",
                    "commit": commit,
                },
                "package_source": {
                    "commit": commit,
                    "embedded_phar_identity": f"dw {version} (commit {commit[:12]})",
                },
                "assets": [
                    {
                        "name": asset,
                        "asset_id": 1000 + asset_index,
                        **download(asset, 20 + asset_index),
                    }
                    for asset_index, asset in enumerate(sorted(CLI_ASSETS), start=1)
                ],
            }
        elif component.distribution == "pypi":
            encoded_package = urllib.parse.quote(component.package, safe="")
            encoded_version = urllib.parse.quote(version, safe="")
            distribution = {
                "kind": "pypi",
                "package": component.package,
                "registry": f"https://pypi.org/pypi/{encoded_package}/{encoded_version}/json",
                "source_identity": {
                    "source_archive": download("source.tar.gz", 40),
                    "source_files_compared": 12,
                    "wheel_files_compared": 8,
                    "source_commit": commit,
                },
                "files": [
                    {
                        **download("durable_workflow.whl", 41),
                        "filename": "durable_workflow.whl",
                        "package_type": "bdist_wheel",
                    },
                    {
                        **download("durable_workflow.tar.gz", 42),
                        "filename": "durable_workflow.tar.gz",
                        "package_type": "sdist",
                    },
                ],
            }
        elif component.distribution == "crates.io":
            encoded_package = urllib.parse.quote(component.package, safe="")
            encoded_version = urllib.parse.quote(version, safe="")
            distribution = {
                "kind": "crates.io",
                "package": component.package,
                "registry": f"https://crates.io/api/v1/crates/{encoded_package}/{encoded_version}",
                "archive_vcs_commit": commit,
                "archive_vcs_dirty": False,
                "archive": download("package.crate"),
            }
        elif component.distribution == "oci":
            labels = {
                "org.opencontainers.image.revision": commit,
                "dev.durable-workflow.release.tag": version,
            }
            distribution = {
                "kind": "oci",
                "image": f"{component.package}:{version}",
                "manifest_digest": f"sha256:{'a' * 64}",
                "platforms": ["linux/amd64", "linux/arm64"],
                "configs": [
                    {"digest": f"sha256:{index + 10:064x}", "labels": labels},
                    {"digest": f"sha256:{index + 20:064x}", "labels": labels},
                ],
            }
        else:
            raise AssertionError(component.distribution)
        results[name] = {
            "version": version,
            "commit": commit,
            "source": source,
            "outcome": "verified",
        }
        if name == "waterline":
            labels = {
                "org.opencontainers.image.revision": commit,
                "dev.durable-workflow.release.tag": version,
            }
            results[name]["distributions"] = {
                "embedded": distribution,
                "service": {
                    "kind": "oci",
                    "image": f"{WATERLINE_SERVICE.package}:{version}",
                    "manifest_digest": f"sha256:{'b' * 64}",
                    "platforms": ["linux/amd64", "linux/arm64"],
                    "configs": [
                        {"digest": f"sha256:{index + 30:064x}", "labels": labels},
                        {"digest": f"sha256:{index + 40:064x}", "labels": labels},
                    ],
                },
            }
        else:
            results[name]["distribution"] = distribution
    return {
        "schema": VERIFICATION_SCHEMA,
        "candidate": candidate["candidate"],
        "manifest_sha256": manifest_digest(candidate),
        "verified_at": verified_at,
        "outcome": "verified",
        "components": results,
    }
