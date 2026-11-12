#!/usr/bin/env python3
"""Derive the reviewed archive metadata and link plan for one cataloged PHP tuple.

Upstream php-ubuntu replaces its release assets in place. Each replacement
needs new `php-linux-<profile>-archive.json` and `-normalization.json` records
before setup can admit the new bytes. This offline command rebuilds both from a
local copy of the exact cataloged archive.

It reads tar headers through the same stock zstd decoder and tarfile stream
parser that setup uses. It never extracts, installs or executes a member, makes
no network request and refuses bytes that differ from the catalog's pinned size
and SHA-256. Setup still revalidates every recorded header, link treatment and
count against the held archive, so a wrong record can only cause a refusal.

    python3 -I -S -B scripts/php_linux_profile_records.py 24.04 ARCHIVE OUTPUT_DIRECTORY
"""

from collections import Counter
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import php_linux_archive as archive  # noqa: E402
from scripts import php_linux_bootstrap as bootstrap  # noqa: E402
from scripts import php_linux_normalize as normalization  # noqa: E402

PROFILE_NAMES = {"26.04": "initial", "24.04": "ubuntu24"}
COLUMNS = ["name", "type", "linkname", "size", "offset", "offset_data"]
ALLOWED_PAX = frozenset(("path", "mtime", "atime", "ctime", "uid", "gid", "uname", "gname"))


def decoded(compressed: bytes) -> bytes:
    result = subprocess.run(["/usr/bin/zstd", "--decompress", "--stdout", "--quiet"], input=compressed,
                            capture_output=True, timeout=120, env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    if result.returncode != 0 or len(result.stdout) > archive.MAX_UNPACKED:
        raise ValueError("Cataloged archive does not decode within the inspection bound")
    return result.stdout


def refusal(member, number: int, error: ValueError) -> dict:
    return {"current_refusal": str(error), "linkname": member.linkname, "name": member.name,
            "number": number, "offset": member.offset, "offset_data": member.offset_data,
            "pax_headers": dict(member.pax_headers), "size": member.size, "sparse": member.issparse(),
            "type": member.type.decode("ascii"),
            "unsupported_pax_keys": sorted(set(member.pax_headers) - ALLOWED_PAX),
            "unsupported_type": member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)}


def raw_header(member, number: int) -> dict:
    info = {key: value.decode("ascii") if isinstance(value, bytes) else value
            for key, value in member.get_info().items()}
    return dict(info, number=number, offset=member.offset, offset_data=member.offset_data,
                pax_headers=dict(member.pax_headers), sparse=member.issparse())


def dump_metadata(metadata: dict) -> bytes:
    """Indented fields with one compact member row per line."""
    head = json.dumps({key: value for key, value in metadata.items() if key != "members"}, indent=2)
    rows = ",\n".join("    " + json.dumps(row, separators=(",", ":")) for row in metadata["members"])
    return (head[:-2] + ',\n  "members": [\n' + rows + "\n  ]\n}\n").encode()


def records(compressed: bytes, identity: dict) -> tuple[bytes, bytes]:
    """Return exact metadata and plan bytes for one independently bound archive."""
    bootstrap.asset_identity(identity, identity.get("name"), bootstrap.MAX_ARCHIVE)
    if len(compressed) != identity["size"] or bootstrap.SHA256_PREFIX + bootstrap.sha256(compressed) != identity["digest"]:
        raise ValueError("Local archive differs from its cataloged size/digest")
    rows, inventory, index, parents, seen, strict_parents = [], [], {}, set(), {}, set()
    first_refusal = None
    with tarfile.open(fileobj=io.BytesIO(decoded(compressed)), mode="r|") as source:
        for number, member in enumerate(source, 1):
            rows.append(normalization.header_row(member))
            inventory.append(raw_header(member, number))
            normalization.index_member(member, index, parents)
            if first_refusal is None:
                try:
                    archive.reserve_member(member, seen, strict_parents)
                except ValueError as error:
                    first_refusal = refusal(member, number, error)
    asset = {key: identity[key] for key in ("id", "name", "size")}
    asset["sha256"] = identity["digest"].removeprefix(bootstrap.SHA256_PREFIX)
    # The raw inventory is the canonical JSON of every complete header, in order.
    metadata = {"schema": "durable-workflow.php-linux-archive-metadata/v1", "asset": asset, "columns": COLUMNS,
                "member_count": len(rows),
                "type_counts": dict(sorted(Counter(row[1] for row in rows).items())),
                "pax_headers": sum(bool(row["pax_headers"]) for row in inventory),
                "sparse_members": sum(row["sparse"] for row in inventory),
                "raw_inventory_sha256": bootstrap.sha256(normalization.canonical_json(inventory)),
                "first_refusal": first_refusal, "members": rows}
    metadata_raw = dump_metadata(metadata)
    aliases, omitted = [], []
    for name, member in index.items():
        if member.type == tarfile.SYMTYPE:
            kind, target = normalization.resolve(index, name)
            if kind == "regular":
                aliases.append([name, target])
            else:
                omitted.append([name, kind, target])
    regular = sum(member.type == tarfile.REGTYPE for member in index.values())
    directories = sum(member.type == tarfile.DIRTYPE for member in index.values())
    plan = {"schema": "durable-workflow.php-linux-normalization-proposal/v1", "asset": asset,
            "metadata_sha256": bootstrap.sha256(metadata_raw),
            "materialize_regular_aliases": sorted(aliases), "omit_aliases": sorted(omitted),
            "expected_regular_files": regular + len(aliases), "expected_directories": directories,
            "expected_members": regular + len(aliases) + directories, "expected_links": 0}
    normalization.checked_plan(index, plan)
    for name, _target in aliases:
        if any(other.startswith(name + "/") for other in index):
            raise ValueError("A materialized alias would parent another archive member")
    return metadata_raw, (json.dumps(plan, indent=2) + "\n").encode()


def main(arguments: list[str]) -> dict:
    if len(arguments) != 3 or arguments[0] not in PROFILE_NAMES:
        raise ValueError("Usage: php_linux_profile_records.py 26.04|24.04 ARCHIVE OUTPUT_DIRECTORY")
    release, path, output = arguments
    catalog = json.loads(bootstrap.CATALOG.read_text())
    identity = bootstrap.select(catalog, operating_system="ubuntu", release=release,
                                architecture="x86_64", php="8.3")["asset"]
    with open(path, "rb") as source:
        compressed = source.read(bootstrap.MAX_ARCHIVE + 1)
    metadata_raw, plan_raw = records(compressed, identity)
    prefix = Path(output) / ("php-linux-" + PROFILE_NAMES[release])
    for suffix, raw in (("-archive.json", metadata_raw), ("-normalization.json", plan_raw)):
        descriptor = os.open(f"{prefix}{suffix}", os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        with os.fdopen(descriptor, "wb") as target:
            target.write(raw)
    plan = json.loads(plan_raw)
    return {"asset_id": identity["id"], "metadata_sha256": bootstrap.sha256(metadata_raw),
            "plan_sha256": bootstrap.sha256(plan_raw),
            "counts": [plan["expected_members"], plan["expected_regular_files"], plan["expected_directories"]]}


if __name__ == "__main__":
    print(json.dumps(main(sys.argv[1:]), indent=2))
