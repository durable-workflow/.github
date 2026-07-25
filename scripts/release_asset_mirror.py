#!/usr/bin/env python3
"""Create or compare a GitHub Release asset against immutable Git authority."""

from __future__ import annotations

import argparse
import filecmp
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from pathlib import Path

REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
DEFAULT_RETRY_DELAYS = (1.0, 2.0, 4.0, 8.0)

Runner = Callable[[list[str]], subprocess.CompletedProcess[str]]
Sleeper = Callable[[float], None]


class MirrorError(RuntimeError):
    """A Release mirror cannot be reconciled with its immutable authority."""


def run_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def command_problem(result: subprocess.CompletedProcess[str]) -> str:
    message = (result.stderr or result.stdout or "").strip()
    if not message:
        message = f"command exited with status {result.returncode}"
    return " ".join(message.split())[:500]


def validate_inputs(repository: str, tag: str, source_path: Path, asset_name: str) -> None:
    if not REPOSITORY_PATTERN.fullmatch(repository):
        raise MirrorError("release repository has an invalid identity")
    if not tag or len(tag) > 255 or tag.startswith("-") or any(character in tag for character in "\0\r\n"):
        raise MirrorError("release tag has an invalid identity")
    if (
        not asset_name
        or len(asset_name) > 255
        or Path(asset_name).name != asset_name
        or asset_name in {".", ".."}
        or any(character in asset_name for character in "\0\r\n#*?[]")
    ):
        raise MirrorError("release asset has an unsafe name")
    if source_path.is_symlink() or not source_path.is_file():
        raise MirrorError("immutable Git authority must be a regular file")


def parse_asset_names(payload: str) -> set[str]:
    try:
        release = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise MirrorError("release asset listing is not valid JSON") from error
    if not isinstance(release, dict) or not isinstance(release.get("assets"), list):
        raise MirrorError("release asset listing has an invalid shape")
    names: list[str] = []
    for asset in release["assets"]:
        if not isinstance(asset, dict) or not isinstance(asset.get("name"), str) or not asset["name"]:
            raise MirrorError("release asset listing contains an invalid asset")
        names.append(asset["name"])
    if len(names) != len(set(names)):
        raise MirrorError("release asset listing contains duplicate names")
    return set(names)


def inspect_assets(
    repository: str,
    tag: str,
    *,
    expected_asset: str | None,
    runner: Runner,
    retry_delays: Sequence[float],
    sleep: Sleeper,
) -> set[str]:
    attempts = len(retry_delays) + 1
    last_problem = "release metadata did not contain the expected asset"
    for attempt in range(attempts):
        result = runner(
            [
                "gh",
                "release",
                "view",
                tag,
                "--repo",
                repository,
                "--json",
                "assets",
            ]
        )
        if result.returncode == 0:
            try:
                names = parse_asset_names(result.stdout)
            except MirrorError as error:
                last_problem = str(error)
            else:
                if expected_asset is None or expected_asset in names:
                    return names
                last_problem = f"release asset {expected_asset} is not visible yet"
        else:
            last_problem = command_problem(result)
        if attempt < len(retry_delays):
            sleep(retry_delays[attempt])

    if expected_asset is not None:
        raise MirrorError(
            f"release asset {expected_asset} did not become visible after {attempts} attempts: {last_problem}"
        )
    raise MirrorError(f"cannot inspect release assets after {attempts} attempts: {last_problem}")


def download_and_compare(
    repository: str,
    tag: str,
    source_path: Path,
    asset_name: str,
    *,
    runner: Runner,
    retry_delays: Sequence[float],
    sleep: Sleeper,
) -> None:
    attempts = len(retry_delays) + 1
    last_problem = "release asset download did not produce a regular file"
    for attempt in range(attempts):
        with tempfile.TemporaryDirectory(prefix="release-asset-download-") as temporary:
            destination = Path(temporary)
            result = runner(
                [
                    "gh",
                    "release",
                    "download",
                    tag,
                    "--repo",
                    repository,
                    "--pattern",
                    asset_name,
                    "--dir",
                    str(destination),
                ]
            )
            downloaded = destination / asset_name
            if result.returncode == 0:
                if downloaded.is_symlink() or not downloaded.is_file():
                    last_problem = "release asset download did not produce a regular file"
                elif not filecmp.cmp(source_path, downloaded, shallow=False):
                    raise MirrorError(f"release asset {asset_name} differs from immutable Git authority")
                else:
                    return
            else:
                last_problem = command_problem(result)
        if attempt < len(retry_delays):
            sleep(retry_delays[attempt])

    raise MirrorError(f"cannot download release asset {asset_name} after {attempts} attempts: {last_problem}")


def upload_asset(
    repository: str,
    tag: str,
    source_path: Path,
    asset_name: str,
    *,
    runner: Runner,
) -> subprocess.CompletedProcess[str]:
    with tempfile.TemporaryDirectory(prefix="release-asset-upload-") as temporary:
        upload_path = Path(temporary) / asset_name
        shutil.copyfile(source_path, upload_path)
        return runner(
            [
                "gh",
                "release",
                "upload",
                tag,
                str(upload_path),
                "--repo",
                repository,
            ]
        )


def repair_asset(
    repository: str,
    tag: str,
    source_path: Path,
    asset_name: str,
    *,
    runner: Runner = run_command,
    retry_delays: Sequence[float] = DEFAULT_RETRY_DELAYS,
    sleep: Sleeper = time.sleep,
) -> str:
    validate_inputs(repository, tag, source_path, asset_name)
    assets = inspect_assets(
        repository,
        tag,
        expected_asset=None,
        runner=runner,
        retry_delays=retry_delays,
        sleep=sleep,
    )
    if asset_name in assets:
        download_and_compare(
            repository,
            tag,
            source_path,
            asset_name,
            runner=runner,
            retry_delays=retry_delays,
            sleep=sleep,
        )
        return "matched"

    upload = upload_asset(repository, tag, source_path, asset_name, runner=runner)
    if upload.returncode == 0:
        return "uploaded"

    upload_problem = command_problem(upload)
    try:
        inspect_assets(
            repository,
            tag,
            expected_asset=asset_name,
            runner=runner,
            retry_delays=retry_delays,
            sleep=sleep,
        )
    except MirrorError as visibility_error:
        raise MirrorError(f"cannot upload release asset {asset_name}: {upload_problem}; {visibility_error}") from None
    download_and_compare(
        repository,
        tag,
        source_path,
        asset_name,
        runner=runner,
        retry_delays=retry_delays,
        sleep=sleep,
    )
    return "matched"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    repair = commands.add_parser("repair", help="create or compare one immutable Release asset")
    repair.add_argument("tag")
    repair.add_argument("source_path", type=Path)
    repair.add_argument("asset_name")
    repair.add_argument("--repository", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        if not (os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")):
            raise MirrorError("GH_TOKEN or GITHUB_TOKEN is required to repair a Release asset")
        result = repair_asset(
            arguments.repository,
            arguments.tag,
            arguments.source_path,
            arguments.asset_name,
        )
    except MirrorError as error:
        print(f"release mirror error: {error}", file=sys.stderr)
        return 1
    print(f"release asset {arguments.asset_name}: {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
