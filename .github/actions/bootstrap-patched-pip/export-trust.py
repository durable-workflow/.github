#!/usr/bin/env python3
"""Export the authenticated pip wheel's clean trust bundle to later CI steps."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess


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
    if not path.is_file():
        raise ValueError("The CA bundle must be a regular file")
    contents = path.read_bytes()
    certificates = re.findall(
        rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", contents, re.S,
    )
    if not certificates:
        raise ValueError("The CA bundle has no PEM certificates")
    for certificate in certificates:
        result = subprocess.run(
            ["openssl", "x509", "-noout", "-subject", "-nameopt", "RFC2253"],
            input=certificate, capture_output=True, check=False,
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
        if bundle.read_bytes() != contents:
            raise ValueError("Existing CI trust bundle has unexpected contents")
        return
    with bundle.open("xb") as handle:
        handle.write(contents)
    bundle.chmod(0o444)


def export_bundle(source: Path, runner_temp: Path, env_file: Path, output_file: Path, clients=("pip",)) -> dict:
    if not clients or set(clients) - CLIENT_VARIABLES.keys():
        raise ValueError("Select only supported CI trust clients")
    contents, count = inspect_bundle(source)
    digest = hashlib.sha256(contents).hexdigest()
    directory = runner_temp.resolve() / "durable-workflow-trust"
    bundle = directory / (digest + ".pem")
    empty_directory = directory / "no-additional-roots"
    for path in (bundle, empty_directory):
        if any(character in str(path) for character in "\r\n"):
            raise ValueError("CI trust paths must not contain line breaks")
    if directory.is_symlink() or empty_directory.is_symlink() or bundle.is_symlink():
        raise ValueError("CI trust output must not be redirected through a symlink")
    directory.mkdir(parents=True, exist_ok=True)
    empty_directory.mkdir(exist_ok=True)
    if any(empty_directory.iterdir()):
        raise ValueError("The additional-root directory must be empty")
    write_bundle(bundle, contents)
    variables = {"SSL_CERT_FILE": str(bundle), "SSL_CERT_DIR": str(empty_directory)}
    for client in clients:
        variables.update({name: str(bundle) for name in CLIENT_VARIABLES[client]})
    for client, name in (("git", "GIT_SSL_CAPATH"), ("composer", "COMPOSER_CAPATH")):
        if client in clients:
            variables[name] = str(empty_directory)
    variables["DW_CI_CA_SHA256"] = digest
    with env_file.open("a", encoding="utf-8") as handle:
        handle.write("".join(f"{name}={value}\n" for name, value in variables.items()))
    with output_file.open("a", encoding="utf-8") as handle:
        handle.write(f"ca-file={bundle}\nca-directory={empty_directory}\nca-sha256={digest}\n")
    print(f"Verified CI CA bundle: {bundle}; sha256={digest}; certificates={count}; blocked=0/0")
    return variables


def main() -> None:
    import pip
    from pip._vendor import certifi

    if pip.__version__ != "26.2.2":
        raise ValueError("Authenticated pip 26.2.2 must be installed before exporting trust")
    export_bundle(
        Path(certifi.where()), Path(os.environ["RUNNER_TEMP"]),
        Path(os.environ["GITHUB_ENV"]), Path(os.environ["GITHUB_OUTPUT"]),
        tuple(name.strip() for name in os.environ.get("TRUST_CLIENTS", "pip").split(",")),
    )


if __name__ == "__main__":
    main()
