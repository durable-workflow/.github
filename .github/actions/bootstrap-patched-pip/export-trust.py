#!/usr/bin/env python3
"""Export the authenticated pip wheel's clean trust bundle to later CI steps."""

from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

_SPEC = importlib.util.spec_from_file_location("private_pip_runtime", Path(__file__).with_name("pip_runtime.py"))
runtime = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(runtime)


FILE_VARIABLES = (
    "SSL_CERT_FILE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "COMPOSER_CAFILE",
    "REQUESTS_CA_BUNDLE", "PIP_CERT",
)
DIRECTORY_VARIABLES = ("SSL_CERT_DIR", "GIT_SSL_CAPATH", "COMPOSER_CAPATH")
BLOCKED_SUBJECTS = ("AAA Certificate Services", "emSign ECC Root CA - G3")
CLIENT_VARIABLES = {
    "pip": ("PIP_CERT",), "python": ("REQUESTS_CA_BUNDLE",),
    "composer": ("COMPOSER_CAFILE",), "curl": ("CURL_CA_BUNDLE",),
    "git": ("GIT_SSL_CAINFO",), "npm": ("NPM_CONFIG_CAFILE",),
    "cargo": ("CARGO_HTTP_CAINFO",),
}


def inspect_bundle(path: Path) -> tuple[bytes, int]:
    with runtime.held_file(path, maximum=1024 * 1024) as (contents, _identity):
        return _inspect_contents(contents)


def _inspect_contents(contents: bytes) -> tuple[bytes, int]:
    certificates = re.findall(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", contents, re.S,
    )
    if not certificates:
        raise ValueError("The CA bundle has no PEM certificates")
    with runtime.held_file("/usr/bin/openssl", executable=True) as (_binary, _identity):
        for certificate in certificates:
            result = subprocess.run(
                ["/usr/bin/openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253"],
                input=certificate, capture_output=True, check=False, timeout=5,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null", "OPENSSL_MODULES": "/dev/null"},
            )
            if result.returncode:
                raise ValueError("The CA bundle has a malformed certificate")
            subject = result.stdout.decode("utf-8").removeprefix("subject=").strip()
            for blocked in BLOCKED_SUBJECTS:
                if re.search(r"(?:^|[,+])CN=" + re.escape(blocked) + r"(?:$|[,+])", subject):
                    raise ValueError("Blocked certificate in CA bundle: " + blocked)
    return contents, len(certificates)


def write_bundle(bundle: Path, contents: bytes) -> None:
    if bundle.exists():
        with runtime.held_file(bundle, maximum=1024 * 1024, owned=True) as (existing, _identity):
            if existing != contents:
                raise ValueError("Existing CI trust bundle has unexpected contents")
        return
    with runtime.BoundDirectory(bundle.parent, private=True) as parent:
        parent.create(bundle.name, contents, 0o444)


def export_bundle(source: Path, runner_temp: Path, env_file: Path, output_file: Path, clients=("pip",), *, expected_identity=None, trust_root=None) -> dict:
    if not clients or set(clients) - CLIENT_VARIABLES.keys():
        raise ValueError("Select only supported CI trust clients")
    with runtime.github_file(env_file, runner_temp) as append_env, runtime.github_file(output_file, runner_temp) as append_output:
        with runtime.held_file(source, maximum=1024 * 1024) as (contents, identity):
            if expected_identity is not None and identity != expected_identity:
                raise ValueError("Private certifi CA object changed before export")
            return _export_bundle(contents, trust_root or runner_temp, clients, append_env, append_output)


def _export_bundle(contents, trust_root, clients, append_env, append_output):
    contents, count = _inspect_contents(contents)
    digest = hashlib.sha256(contents).hexdigest()
    directory = runtime.absolute_path(trust_root) / "durable-workflow-trust"
    bundle = directory / (digest + ".pem")
    empty_directory = directory / "no-additional-roots"
    for path in (bundle, empty_directory):
        if any(character in str(path) for character in "\r\n"):
            raise ValueError("CI trust paths must not contain line breaks")
    if directory.is_symlink() or empty_directory.is_symlink() or bundle.is_symlink():
        raise ValueError("CI trust output must not be redirected through a symlink")
    with runtime.BoundDirectory(trust_root, private=True) as parent:
        if not directory.exists():
            os.mkdir(directory.name, 0o700, dir_fd=parent.fd)
        with runtime.BoundDirectory(directory, private=True) as held:
            if not empty_directory.exists():
                os.mkdir(empty_directory.name, 0o700, dir_fd=held.fd)
            with runtime.BoundDirectory(empty_directory, private=True) as empty:
                if os.listdir(empty.fd):
                    raise ValueError("The additional-root directory must be empty")
                write_bundle(bundle, contents)
                held.check()
    variables = {"SSL_CERT_FILE": str(bundle), "SSL_CERT_DIR": str(empty_directory)}
    for client in clients:
        variables.update({name: str(bundle) for name in CLIENT_VARIABLES[client]})
    for client, name in (("git", "GIT_SSL_CAPATH"), ("composer", "COMPOSER_CAPATH")):
        if client in clients:
            variables[name] = str(empty_directory)
    variables["DW_CI_CA_SHA256"] = digest
    append_env("".join(f"{name}={value}\n" for name, value in variables.items()))
    append_output(f"ca-file={bundle}\nca-directory={empty_directory}\nca-sha256={digest}\n")
    print(f"Verified CI CA bundle: {bundle}; sha256={digest}; certificates={count}; blocked=0/0")
    return variables


def main() -> None:
    if len(sys.argv) != 3 or sys.argv[1] != "--runtime":
        raise ValueError("An explicit verified private runtime receipt is required")
    created = os.environ.get("TRUST_CREATED")
    if created not in {"true", "false"}:
        raise ValueError("An explicit producer-owned allocation marker is required")
    owned = runtime.runtime_root(sys.argv[2], os.environ["RUNNER_TEMP"]) if created == "true" else None
    try:
        report, subjects = runtime.verify_runtime(sys.argv[2], os.environ["RUNNER_TEMP"])
        runtime.verify_active_origin(report, shutil.which("python"))
        source = Path(report["purelib"]) / "pip/_vendor/certifi/cacert.pem"
        export_bundle(
            source, Path(os.environ["RUNNER_TEMP"]),
            Path(os.environ["GITHUB_ENV"]), Path(os.environ["GITHUB_OUTPUT"]),
            tuple(name.strip() for name in os.environ.get("TRUST_CLIENTS", "pip").split(",")),
            expected_identity=subjects[str(source)],
            trust_root=Path(report["root"]),
        )
    except BaseException:
        if owned is not None:
            runtime.cleanup_runtime(owned[0], os.environ["RUNNER_TEMP"], owned[1])
        raise


if __name__ == "__main__":
    main()
