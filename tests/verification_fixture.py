from __future__ import annotations

import urllib.parse
from typing import Any

from scripts.beta_candidate import (
    CLI_ASSETS,
    COMPONENTS,
    LEGACY_SCHEMA,
    LEGACY_VERIFICATION_SCHEMA,
    VERIFICATION_SCHEMA,
    WATERLINE_SERVICE,
    manifest_digest,
)


def legacy_candidate_manifest() -> dict[str, Any]:
    return {
        "schema": LEGACY_SCHEMA,
        "candidate": "beta-continuity-foundation",
        "components": {
            "workflow": {
                "version": "2.0.0-alpha.284",
                "commit": "80bef5d9bf01f3282c088b59c433e46b8b146617",
            },
            "waterline": {
                "version": "2.0.0-alpha.133",
                "commit": "5c311cef874601b23342aad1cdd02c9d20483a79",
            },
            "server": {
                "version": "0.2.663",
                "commit": "ce07bf90497a1bd0a0259b3c70c2e1a63302b6b6",
            },
            "cli": {
                "version": "0.1.91",
                "commit": "83b3d01d06ade2380c9e84dc722d485972380167",
            },
            "sdk-php": {
                "version": "0.1.7",
                "commit": "73a9482f431ae522fcb9b8b94158a9f7f9d4f589",
            },
            "sdk-python": {
                "version": "0.4.99",
                "commit": "46957ac89385902988598eb1d538c6f38da92ab3",
            },
            "sdk-rust": {
                "version": "0.1.15",
                "commit": "810f9b53ea418718a5b85804e139a416692713ea",
            },
        },
    }


def _historical_components(identities: dict[str, tuple[str, str]]) -> dict[str, dict[str, str]]:
    return {
        name: {
            "version": version,
            "commit": commit,
        }
        for name, (version, commit) in identities.items()
    }


def legacy_beta_one_candidate_manifest() -> dict[str, Any]:
    return {
        "schema": LEGACY_SCHEMA,
        "candidate": "beta-beta-1-e743e3760000",
        "components": _historical_components(
            {
                "workflow": ("2.0.0-beta.1", "22bbf2a1469f4a38b1a6e1006ca8e46835c2fea4"),
                "waterline": ("2.0.0-beta.1", "0fb3caaba1e8a77f9bfa63ba3dcb2bcbaa825c31"),
                "server": ("0.2.699", "d6e8fb6c76c1d71cc7d3a1d38bdebd324150acad"),
                "cli": ("0.1.95", "bc036e94604329612b65a2a9effe2e929f91f4e1"),
                "sdk-php": ("0.1.16", "3b79813b1bbcb811277cc30d8dcfc359ea53f65c"),
                "sdk-python": ("0.4.106", "13037ddcb1f55d72c24256591e346b991ad64273"),
                "sdk-rust": ("0.1.22", "6fa98425c8ec7690ef96f8296a21407aa8d03067"),
            }
        ),
    }


def legacy_beta_one_release_plan() -> dict[str, Any]:
    candidate = legacy_beta_one_candidate_manifest()
    return {
        "schema": "durable-workflow.release-plan/v1",
        "plan": "beta-1-e743e3760000",
        "channel": "beta",
        "foundation": {
            "tag": "beta-candidate/beta-continuity-foundation",
            "commit": "4995052410bd4301c5796ffba54e0b6d2f490ed1",
        },
        "components": candidate["components"],
        "beta_authorization": {
            "tag": "beta-authorization/beta-1-e743e3760000",
            "commit": "bef98bfd61b604d48459c15e968e3ace8e5124b0",
        },
    }


def legacy_completed_candidate_manifests() -> list[dict[str, Any]]:
    continuity_components = {
        "workflow": ("2.0.0-alpha.289", "54320e6687d7028dfb625152a864ba218e125afe"),
        "waterline": ("2.0.0-alpha.136", "60b2de727e27cc17fcb611b3650e0c100968547b"),
        "server": ("0.2.666", "ffa5bf5e0d68a032550451dc31073cc83c25fc52"),
        "cli": ("0.1.92", "9aafb87f2432cba0be9ed21e4e509cb9b6acda5d"),
        "sdk-php": ("0.1.9", "05fe99b44062b939e4c43acc00dae457eef87af2"),
        "sdk-python": ("0.4.101", "8aa0e86fe51edc1e7aba3d97ddf3dfda8009ee23"),
        "sdk-rust": ("0.1.16", "31e87f4aa13a7fd255fd277a62c43c96ee1532ab"),
    }
    continuity_successor_components = {
        **continuity_components,
        "server": ("0.2.667", "305f29b3b123bb8c805a9ce7b13dd6d8485f7bfa"),
    }
    release_preparation_components = {
        "workflow": ("2.0.0-alpha.291", "518a27492d38bd92bca3e2bb91b9ccf82da9589b"),
        "waterline": ("2.0.0-alpha.137", "4c90258f077724fd1267fd8a2d6e902162a835bf"),
        "server": ("0.2.689", "5772b22c81c20b2d3b49fe539fe1244f69b3e66d"),
        "cli": ("0.1.93", "3fcc580722d0e1e9f5d3da21472d811697f3d3e9"),
        "sdk-php": ("0.1.13", "4863f4d8ce4ac935f6187d87bfb435918cdf8653"),
        "sdk-python": ("0.4.102", "0c7ea1b18a754191a72d4c4884ea83b087f27ff9"),
        "sdk-rust": ("0.1.17", "68f1adf24939885bb6779918c1cc197f7f0565d7"),
    }
    return [
        {
            "schema": LEGACY_SCHEMA,
            "candidate": "alpha-alpha-continuity-drill-20260716c",
            "components": _historical_components(continuity_components),
        },
        {
            "schema": LEGACY_SCHEMA,
            "candidate": "alpha-alpha-continuity-drill-20260716d",
            "components": _historical_components(continuity_successor_components),
        },
        {
            "schema": LEGACY_SCHEMA,
            "candidate": "alpha-alpha-release-preparation-proof-20260719",
            "components": _historical_components(release_preparation_components),
        },
    ]


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


def legacy_candidate_verification(
    candidate: dict[str, Any], *, verified_at: str = "2026-07-20T21:00:00Z"
) -> dict[str, Any]:
    result = candidate_verification(candidate, verified_at=verified_at)
    result["schema"] = LEGACY_VERIFICATION_SCHEMA
    waterline = result["components"]["waterline"]
    waterline["distribution"] = waterline.pop("distributions")["embedded"]
    return result
