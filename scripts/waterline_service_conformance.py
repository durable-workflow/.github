#!/usr/bin/env python3
"""Exercise the exact Waterline service image against the exact standalone server."""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import os
import re
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

SCHEMA = "durable-workflow.beta-conformance.waterline-service.v1"
SCENARIO = "service_image_php_sdk_standalone"
IMAGE_PATTERN = re.compile(r"^docker\.io/durableworkflow/waterline@(?P<digest>sha256:[0-9a-f]{64})$")
VERSION_PATTERN = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z][0-9A-Za-z.-]*)?$")


class ServiceConformanceError(RuntimeError):
    """The published Waterline service artifact did not satisfy its runtime contract."""


def now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def docker(arguments: list[str], *, timeout: int = 180, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        process = subprocess.run(
            ["docker", *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        raise ServiceConformanceError("Docker is unavailable for the Waterline service runner") from error
    if check and process.returncode:
        raise ServiceConformanceError(f"Docker {arguments[0]} failed for the Waterline service runner")
    return process


def required_environment() -> dict[str, str]:
    names = (
        "DW_SERVER_VERSION",
        "DW_PHP_SDK_VERSION",
        "DW_WATERLINE_VERSION",
        "DW_WATERLINE_SERVICE_IMAGE",
        "DW_WATERLINE_SERVICE_DOCKER_NETWORK",
        "DW_WATERLINE_SERVICE_SERVER_URL",
        "DW_WATERLINE_SERVICE_NAMESPACE",
        "DW_WATERLINE_SERVICE_TOKEN",
    )
    values = {name: os.environ.get(name, "") for name in names}
    if any(not value for value in values.values()):
        raise ServiceConformanceError("Waterline service runner environment is incomplete")
    for name in ("DW_SERVER_VERSION", "DW_PHP_SDK_VERSION", "DW_WATERLINE_VERSION"):
        if VERSION_PATTERN.fullmatch(values[name]) is None:
            raise ServiceConformanceError(f"{name} is not an exact release version")
    if IMAGE_PATTERN.fullmatch(values["DW_WATERLINE_SERVICE_IMAGE"]) is None:
        raise ServiceConformanceError("DW_WATERLINE_SERVICE_IMAGE is not digest-pinned")
    return values


def wait_for_url(url: str, *, timeout: int = 120) -> bytes:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=3) as response:
                if response.status < 500:
                    return response.read(1024 * 1024)
        except Exception:
            time.sleep(2)
    raise ServiceConformanceError("Waterline service did not become ready before its deadline")


def installed_sdk_version(container: str) -> str:
    inspection = (
        "$installed=require '/app/vendor/composer/installed.php';"
        "$version=$installed['versions']['durable-workflow/sdk']['pretty_version']??'';"
        "fwrite(STDOUT,(string)$version);"
    )
    result = docker(["exec", container, "php", "-r", inspection], timeout=30)
    version = result.stdout.strip().removeprefix("v")
    if VERSION_PATTERN.fullmatch(version) is None:
        raise ServiceConformanceError("Waterline service image does not expose an exact installed PHP SDK version")
    return version


def distribution_identity(image: str, version: str) -> dict[str, Any]:
    match = IMAGE_PATTERN.fullmatch(image)
    if match is None:
        raise ServiceConformanceError("Waterline service image is not digest-pinned")
    return {
        "kind": "oci",
        "locator": f"oci:docker.io/durableworkflow/waterline@{version}",
        "artifacts": [{"name": "manifest", "sha256": match.group("digest").removeprefix("sha256:")}],
    }


def write_result(
    result_dir: Path,
    environment: dict[str, str],
    started_at: str,
    *,
    status: str,
    runner_blocked: bool,
    identity: dict[str, Any] | None,
    summary: str | None = None,
) -> None:
    findings = []
    if summary:
        findings.append(
            {
                "type": "waterline_service_execution_failure",
                "owning_contract": "signals-and-queries",
                "summary": summary[:2048],
            }
        )
    result = {
        "schema": SCHEMA,
        "started_at": started_at,
        "finished_at": now(),
        "outcome": "pass" if status == "pass" else "fail",
        "runner_blocked": runner_blocked,
        "artifact_versions": {
            "server": environment["DW_SERVER_VERSION"],
            "waterline-service": environment["DW_WATERLINE_VERSION"],
        },
        "executed_distribution_identities": ({"waterline-service": identity} if identity is not None else {}),
        "local_product_source_checkout_used": False,
        "scenario_results": {
            SCENARIO: {
                "scenario_id": SCENARIO,
                "status": status,
            }
        },
        "findings": findings,
    }
    result_dir.mkdir(parents=True, exist_ok=True)
    (result_dir / "waterline-service-conformance-result.json").write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def run(result_dir: Path) -> int:
    started_at = now()
    environment: dict[str, str] = {}
    identity = None
    container = f"dw-waterline-service-{os.getpid()}-{time.time_ns()}"
    try:
        environment = required_environment()
        image = environment["DW_WATERLINE_SERVICE_IMAGE"]
        docker(["pull", image], timeout=300)
        inspection = docker(["image", "inspect", "--format", "{{json .RepoDigests}}", image], timeout=30)
        digest = IMAGE_PATTERN.fullmatch(image).group("digest")  # type: ignore[union-attr]
        if digest not in inspection.stdout:
            raise ServiceConformanceError("pulled Waterline service image does not retain the candidate digest")
        identity = distribution_identity(image, environment["DW_WATERLINE_VERSION"])
        docker(
            [
                "run",
                "-d",
                "--rm",
                "--name",
                container,
                "--network",
                environment["DW_WATERLINE_SERVICE_DOCKER_NETWORK"],
                "-p",
                "127.0.0.1::8080",
                "-e",
                f"WATERLINE_SERVER_ENDPOINT={environment['DW_WATERLINE_SERVICE_SERVER_URL']}",
                "-e",
                f"WATERLINE_SERVER_TOKEN={environment['DW_WATERLINE_SERVICE_TOKEN']}",
                "-e",
                f"WATERLINE_NAMESPACE={environment['DW_WATERLINE_SERVICE_NAMESPACE']}",
                "-e",
                "WATERLINE_ACCESS_MODE=read_only",
                "-e",
                "WATERLINE_ALLOW_UNAUTHENTICATED=true",
                image,
            ],
            timeout=60,
        )
        port = docker(["port", container, "8080/tcp"], timeout=30).stdout.strip().rsplit(":", 1)[-1]
        if not port.isdigit():
            raise ServiceConformanceError("Waterline service image did not publish its HTTP port")
        base_url = f"http://127.0.0.1:{port}"
        wait_for_url(f"{base_url}/up")
        sdk_version = installed_sdk_version(container)
        if sdk_version != environment["DW_PHP_SDK_VERSION"]:
            raise ServiceConformanceError("Waterline service image contains a mismatched PHP SDK version")
        payload = json.loads(wait_for_url(f"{base_url}/waterline/api/flows/running"))
        if not isinstance(payload, dict) or not isinstance(payload.get("data"), list):
            raise ServiceConformanceError("Waterline service did not return the standalone workflow list shape")
        write_result(result_dir, environment, started_at, status="pass", runner_blocked=False, identity=identity)
        return 0
    except (ServiceConformanceError, json.JSONDecodeError) as error:
        if environment:
            write_result(
                result_dir,
                environment,
                started_at,
                status="runner_blocked" if identity is None else "fail",
                runner_blocked=identity is None,
                identity=identity,
                summary=str(error),
            )
        return 1
    finally:
        with contextlib.suppress(ServiceConformanceError):
            docker(["rm", "--force", container], timeout=30, check=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--result-dir", type=Path, required=True)
    arguments = parser.parse_args()
    return run(arguments.result_dir)


if __name__ == "__main__":
    raise SystemExit(main())
