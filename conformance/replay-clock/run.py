"""Run the replay-clock conformance case against exact published SDK releases.

Each binding replays the shared vectors-v1.json history with each case's
WorkerReplayClock v1 carrier and reports replay_now() at entry, after an
activity and after a timer. This script installs the selected releases in
throwaway containers, runs the thin per-binding runners and compares every
observation with the vectors. A release that predates the entry carrier is
reported as not yet released rather than failed.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
VECTORS = HERE / "vectors-v1.json"
BINDINGS = ("python", "rust", "php", "embedded-worker-protocol")
VERSION_ENV = {
    "python": "DW_PYTHON_SDK_VERSION",
    "rust": "DW_RUST_SDK_VERSION",
    "php": "DW_PHP_SDK_VERSION",
    "embedded-worker-protocol": "DW_WORKFLOW_PHP_VERSION",
}
_VERSION = re.compile(r"\d+\.\d+\.\d+")
# Same patched pip the published cancellation runners pin before installing.
_PIP = ("pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/"
        "pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70")


def load_vectors(path: Path = VECTORS) -> dict[str, Any]:
    vectors = json.loads(path.read_text(encoding="utf-8"))
    if vectors.get("schema") != "durable-workflow.replay-clock-conformance/v1":
        raise SystemExit(f"{path}: unexpected schema {vectors.get('schema')!r}")
    return vectors


def version_tuple(version: str) -> tuple[int, int, int]:
    if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
        raise ValueError(f"exact release version required, got {version!r}")
    major, minor, patch = (int(part) for part in version.split("."))
    return major, minor, patch


def released(vectors: dict[str, Any], binding: str, version: str) -> bool:
    """Whether this exact release is newer than the last one without the carrier."""
    return version_tuple(version) > version_tuple(vectors["requires_newer_than"][binding])


def expected_for(vectors: dict[str, Any], binding: str, case_id: str) -> dict[str, Any]:
    case = next(case for case in vectors["cases"] if case["id"] == case_id)
    override = vectors.get("binding_overrides", {}).get(binding, {}).get(case_id, {})
    return {**case["expected"], **override}


def compare(vectors: dict[str, Any], binding: str, observations: dict[str, Any]) -> list[str]:
    """Return every mismatch between a binding's observations and the vectors."""
    mismatches: list[str] = []
    case_ids = [case["id"] for case in vectors["cases"]]
    if sorted(observations) != sorted(case_ids):
        mismatches.append(f"{binding}: observed cases {sorted(observations)} != {sorted(case_ids)}")
    for case_id in case_ids:
        observed = observations.get(case_id)
        if not isinstance(observed, dict):
            continue
        for key, value in expected_for(vectors, binding, case_id).items():
            if observed.get(key, "<missing>") != value:
                actual = observed.get(key, "<missing>")
                mismatches.append(f"{binding}/{case_id}/{key}: expected {value!r}, observed {actual!r}")
    return mismatches


# Each container gets a private tmpfs owned by the invoking user. The venv, the
# source copy, HOME and the package caches live there, never in a shared,
# world-writable directory.
SCRATCH = "/scratch"
PROJECT = "/project"
CASE_VECTORS = "/case/vectors-v1.json"


def _docker(name: str, image: str, mounts: list[tuple[Path, str, str]], script: str, env: dict[str, str]) -> str:
    uid, gid = os.getuid(), os.getgid()
    command = ["docker", "run", "--rm", "--init", "--cpus", "2", "--memory", "4g", "--name", name,
               "-u", f"{uid}:{gid}",
               "--tmpfs", f"{SCRATCH}:rw,exec,nosuid,nodev,size=2g,mode=0700,uid={uid},gid={gid}",
               "-e", f"HOME={SCRATCH}"]
    for key, value in env.items():
        command += ["-e", f"{key}={value}"]
    for source, target, mode in mounts:
        command += ["-v", f"{source}:{target}:{mode}"]
    command += [image, "sh", "-ec", script]
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        # PHP CLI reports fatal errors on stdout, so keep the tail of both streams.
        raise RuntimeError(f"{name} failed ({result.returncode}):\n{result.stdout[-2000:]}\n{result.stderr[-4000:]}")
    lines = result.stdout.strip().splitlines()
    return lines[-1] if lines else ""


def _run_python(name: str, version: str | None, source: Path | None) -> str:
    case = (HERE, "/case", "ro")
    install = f"{SCRATCH}/sdk" if source else f"durable-workflow=={version}"
    mounts = [case] + ([(source, "/sdk", "ro")] if source else [])
    # A source build writes metadata, so it builds from a private copy.
    copy = (f"mkdir {SCRATCH}/sdk && tar -C /sdk --exclude=./.venv --exclude=./.git -cf - . | "
            f"tar -C {SCRATCH}/sdk -xf - && " if source else "")
    venv = f"{SCRATCH}/venv"
    script = (f"{copy}python -m venv {venv} && {venv}/bin/pip -q install --disable-pip-version-check "
              f"--no-deps --upgrade '{_PIP}' && {venv}/bin/pip -q install --no-cache-dir '{install}' && "
              f"{venv}/bin/python -I /case/python/runner.py {CASE_VECTORS}")
    return _docker(name, "python:3.12-slim", mounts, script, {})


def _run_rust(name: str, version: str | None, source: Path | None, work: Path) -> str:
    project = work / "rust"
    shutil.copytree(HERE / "rust", project)
    dependency = '{ path = "/sdk" }' if source else f'"={version}"'
    (project / "Cargo.toml").write_text(
        (project / "Cargo.toml.in").read_text(encoding="utf-8").replace("@DURABLE_WORKFLOW@", dependency),
        encoding="utf-8")
    mounts = [(HERE, "/case", "ro"), (project, PROJECT, "rw")] + ([(source, "/sdk", "ro")] if source else [])
    script = f"cd {PROJECT} && cargo run -q --release -- {CASE_VECTORS}"
    return _docker(name, "rust:1.86.0", mounts, script,
                   {"CARGO_HOME": f"{SCRATCH}/cargo", "DW_RUST_SDK_VERSION": version or "source"})


def _run_php(name: str, binding: str, version: str | None, source: Path | None, work: Path) -> str:
    package = "durable-workflow/sdk" if binding == "php" else "durable-workflow/workflow"
    project = work / binding
    shutil.copytree(HERE / "php", project)
    repositories = [{"type": "path", "url": "/sdk", "options": {"symlink": False}}] if source else []
    (project / "composer.json").write_text(
        (project / "composer.json.in").read_text(encoding="utf-8")
        .replace("@REQUIRE@", json.dumps({package: "*@dev" if source else version}))
        .replace("@REPOSITORIES@", json.dumps(repositories)), encoding="utf-8")
    mounts = [(project, PROJECT, "rw")] + ([(source, "/sdk", "ro")] if source else [])
    _docker(f"{name}-install", "composer:2.10.3", mounts,
            f"cd {PROJECT} && composer install -q --no-interaction --no-dev --ignore-platform-req=ext-*",
            {"COMPOSER_HOME": f"{SCRATCH}/composer"})
    runner = "sdk-runner.php" if binding == "php" else "embedded-runner.php"
    return _docker(name, "php:8.4-cli", [(HERE, "/case", "ro"), (project, PROJECT, "ro")],
                   f"cd {PROJECT} && php {runner} {CASE_VECTORS}", {})


def _run_binding(binding: str, version: str | None, source: Path | None, work: Path,
                 prefix: str = "dw-replay-clock") -> dict[str, Any]:
    name = f"{prefix}-{binding}-{os.getpid()}"
    if binding == "python":
        output = _run_python(name, version, source)
    elif binding == "rust":
        output = _run_rust(name, version, source, work)
    else:
        output = _run_php(name, binding, version, source, work)
    report = json.loads(output)
    if not isinstance(report, dict) or not isinstance(report.get("observations"), dict):
        raise ValueError(f"{binding}: runner printed no observations")
    return report


def evaluate(vectors: dict[str, Any], binding: str, version: str | None, source: Path | None, work: Path,
             prefix: str = "dw-replay-clock") -> dict[str, Any]:
    """Run one binding and record its outcome; a crashed binding is an error, not an abort."""
    label = "source" if source else version
    if source is None and not released(vectors, binding, version or ""):
        return {"status": "not_yet_released", "version": version,
                "requires_newer_than": vectors["requires_newer_than"][binding]}
    try:
        report = _run_binding(binding, version, source, work, prefix)
    except (OSError, RuntimeError, ValueError) as error:
        return {"status": "error", "version": label, "error": str(error)}
    mismatches = compare(vectors, binding, report["observations"])
    return {"status": "fail" if mismatches else "pass", "version": label,
            "reported_version": report.get("sdk_version"), "mismatches": mismatches,
            "observations": report["observations"]}


def _selected(only: str, sources: dict[str, str]) -> list[tuple[str, str | None, Path | None]]:
    selected = []
    for binding in [item for item in only.split(",") if item]:
        if binding not in BINDINGS:
            raise SystemExit(f"unknown binding {binding!r}")
        source = Path(sources[binding]).resolve() if binding in sources else None
        version = os.environ.get(VERSION_ENV[binding])
        if source is None and not version:
            raise SystemExit(f"set {VERSION_ENV[binding]} to the exact published release, or omit {binding}")
        if source is None:
            try:
                version_tuple(version)
            except ValueError as error:
                raise SystemExit(f"{VERSION_ENV[binding]}: {error}") from None
        selected.append((binding, version, source))
    return selected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", default=",".join(BINDINGS), help="comma-separated bindings to run")
    parser.add_argument("--source", action="append", default=[], metavar="BINDING=PATH",
                        help="development only: replay an unreleased checkout instead of a release")
    parser.add_argument("--result-dir", type=Path, help="write result.json here")
    parser.add_argument("--container-prefix", default="dw-replay-clock", help="name prefix for the containers")
    args = parser.parse_args(argv)
    vectors = load_vectors()
    sources = {binding: path for binding, path in (item.split("=", 1) for item in args.source)}
    selected = _selected(args.only, sources)
    with tempfile.TemporaryDirectory(prefix="dw-replay-clock-") as temporary:
        results = {binding: evaluate(vectors, binding, version, source, Path(temporary), args.container_prefix)
                   for binding, version, source in selected}
    document = json.dumps({"schema": vectors["schema"], "bindings": results}, indent=2, sort_keys=True)
    if args.result_dir:
        args.result_dir.mkdir(parents=True, exist_ok=True)
        (args.result_dir / "result.json").write_text(document + "\n", encoding="utf-8")
    print(document)
    return 1 if any(result["status"] in {"fail", "error"} for result in results.values()) else 0


if __name__ == "__main__":
    sys.exit(main())
