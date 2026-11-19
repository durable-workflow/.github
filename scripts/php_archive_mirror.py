#!/usr/bin/env python3
"""Plan and adopt the immutable mirror of the reviewed PHP setup archives.

Upstream `shivammathur/php-ubuntu` replaces its `builds` release assets in
place. Setup therefore fetches each reviewed archive from a byte-identical
copy in `durable-workflow/php-archives`: one immutable GitHub release per
archive, tagged by the archive's SHA-256. The catalog keeps the upstream row
as provenance and profile identity; the mirror row must carry the same name,
size and SHA-256, and setup verifies both before sealing the bytes.

    plan  --archive-dir DIR   verify local archives and print the upload plan
    adopt --release-json F    bind uploaded mirror assets into the catalog

`plan` never uploads. It reads `DIR/<asset name>` for each setup row,
refuses bytes that differ from the catalog, re-derives the committed records
with the strict inspector, and prints the exact `gh release create` commands
an authorized maintainer runs after review. `adopt` reads the release JSON
from `gh api repos/durable-workflow/php-archives/releases/tags/TAG`, requires
each named asset to have the cataloged size and `digest`, and rewrites only
the matching rows' `mirror` records. The required native policy gate then
re-checks live metadata and re-inspects the mirrored bytes before the data
PR can merge.

Run with `python3 -I -S -B scripts/php_archive_mirror.py ...`; pass paths to
downloaded archives as arguments, never run from their directory.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shlex
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import php_linux_bootstrap as bootstrap  # noqa: E402
from scripts import protected_policy_data as data  # noqa: E402


def release_tag(row: dict) -> str:
    return "php-sha256-" + row["asset"]["digest"].removeprefix(bootstrap.SHA256_PREFIX)[:16]


def local_archive(directory: Path, row: dict) -> bytes:
    path = directory / row["asset"]["name"]
    if path.is_symlink() or not path.is_file() or path.stat().st_size != row["asset"]["size"]:
        raise ValueError(f"{row['asset']['name']}: no regular local file with the cataloged size")
    raw = path.read_bytes()
    if bootstrap.SHA256_PREFIX + bootstrap.sha256(raw) != row["asset"]["digest"]:
        raise ValueError(f"{row['asset']['name']}: local bytes differ from the cataloged SHA-256")
    return raw


def plan(directory: Path, catalog: dict, root: Path = ROOT, releases=None) -> dict:
    """Dry run: verify, inspect and describe the upload without performing it."""
    rows = bootstrap.setup_rows(catalog)
    if releases is not None:
        if not set(releases) <= set(rows):
            raise ValueError("Unknown setup release")
        rows = {release: rows[release] for release in releases}
    files = {path: (root / path).read_bytes()
             for path in sorted(data.gated_paths(catalog) - set(data.RUNTIME_DATA))}
    result = []
    for release, row in sorted(rows.items()):
        compressed = local_archive(directory, row)
        inspected = data.inspect_records(compressed, row, files)
        tag = release_tag(row)
        command = ["gh", "release", "create", tag, "--repo", bootstrap.MIRROR_REPOSITORY,
                   "--title", f"{row['asset']['name']} {tag}",
                   "--notes", f"Byte-identical mirror of {bootstrap.REPOSITORY} asset {row['asset']['id']} "
                              f"({row['asset']['digest']}).",
                   str(directory / row["asset"]["name"])]
        result.append({
            "release": release, "profile": row["profile"]["name"], "upstream": row["asset"],
            "inspected": inspected, "current_mirror": row["mirror"],
            "planned_mirror": {"repository": bootstrap.MIRROR_REPOSITORY, "release_tag": tag, "id": None,
                               "name": row["asset"]["name"], "size": row["asset"]["size"],
                               "digest": row["asset"]["digest"]},
            "upload_command": shlex.join(command),
        })
    return {"schema": "durable-workflow.php-archive-mirror-plan/v1", "dry_run": True,
            "repository": bootstrap.MIRROR_REPOSITORY, "archives": result}


def adopt(catalog: dict, release: dict) -> dict:
    """Bind one uploaded release's assets to the rows with exactly those bytes."""
    if not isinstance(release, dict) or release.get("draft") is not False or release.get("immutable") is not True:
        raise ValueError("Adopt only a published immutable mirror release")
    tag = release.get("tag_name")
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ValueError("The mirror release has no asset list")
    adopted = 0
    updated = json.loads(json.dumps(catalog))
    for row in updated["archives"]:
        if row["profile"] is None or release_tag(row) != tag:
            continue
        matches = [asset for asset in assets if isinstance(asset, dict) and asset.get("name") == row["asset"]["name"]]
        if (len(matches) != 1 or matches[0].get("size") != row["asset"]["size"]
                or matches[0].get("digest") != row["asset"]["digest"] or matches[0].get("state") != "uploaded"
                or type(matches[0].get("id")) is not int):
            raise ValueError("The mirror release asset differs from the cataloged bytes")
        row["mirror"] = {"repository": bootstrap.MIRROR_REPOSITORY, "release_tag": tag, "id": matches[0]["id"],
                         "name": row["asset"]["name"], "size": row["asset"]["size"],
                         "digest": row["asset"]["digest"]}
        adopted += 1
    if adopted != 1:
        raise ValueError("The release must mirror exactly one cataloged setup archive")
    return bootstrap.validate_catalog(updated)


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    planned = commands.add_parser("plan")
    planned.add_argument("--archive-dir", type=Path, required=True)
    planned.add_argument("--release", action="append", choices=("24.04", "26.04"),
                         help="Plan only these setup releases (default: all)")
    adopted = commands.add_parser("adopt")
    adopted.add_argument("--release-json", type=Path, required=True)
    options = parser.parse_args(arguments)
    catalog = bootstrap.load_catalog()
    if options.command == "plan":
        print(json.dumps(plan(options.archive_dir, catalog, releases=options.release), indent=2))
        return 0
    release = json.loads(options.release_json.read_text(encoding="utf-8"))
    bootstrap.CATALOG.write_text(json.dumps(adopt(catalog, release), indent=2) + "\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (ValueError, OSError, data.InputRefused) as error:
        print(f"PHP archive mirror refused: {type(error).__name__}: {error}"[:600], file=sys.stderr)
        raise SystemExit(1)
