"""Exact PHAR inputs for the proposed Linux setup companion, with no CLI.

Publisher authority is captured during separately reviewed data preparation.
Runtime downloads consume literal reviewed bytes; they never discover a tool,
version, key, digest or replacement authority from a live service.
"""

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import time
import xml.etree.ElementTree as ET
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from scripts import php_linux_bootstrap as bootstrap


CATALOG = bootstrap.ROOT / "qualification/php-linux-tools.json"
PROFILES = {"composer": ("2.10.3", "https://getcomposer.org/download/2.10.3/composer.phar"),
            "phpunit": ("11.5.57", "https://phar.phpunit.de/phpunit-11.5.57.phar")}
SHA256_PATTERN = r"[a-f0-9]{64}"
MAX_TOOL = 10 * 1024 * 1024
PUBLISHER_STATES = frozenset(("verified", "reviewed-publisher-digest"))


def evidence_file(record: dict, root: Path) -> bytes:
    bootstrap.exact_keys(record, {"file", "sha256"})
    name = record["file"]
    if (not isinstance(name, str) or not name.startswith("qualification/php-tools/")
            or any(part in ("", ".", "..") for part in name.split("/"))
            or not re.fullmatch(SHA256_PATTERN, record["sha256"])):
        raise ValueError("Unbound publisher evidence path or digest")
    path = root / name
    if any(parent.is_symlink() for parent in (path, *path.parents) if parent != root.parent):
        raise ValueError("Publisher evidence must be a regular source file")
    contents = path.read_bytes()
    if len(contents) > 1024 * 1024 or bootstrap.sha256(contents) != record["sha256"]:
        raise ValueError("Publisher evidence differs from the reviewed source bytes")
    return contents


def validate_tool_tuple(row, names):
    bootstrap.exact_keys(row, {"name", "version", "url", "size", "sha256", "minimum_php",
                              "publisher_digest_url", "publisher_signature_url", "evidence",
                              "publisher_authority"})
    if (row["name"] not in PROFILES or row["name"] in names
            or (row["version"], row["url"]) != PROFILES[row["name"]]
            or type(row["size"]) is not int or not 0 < row["size"] <= MAX_TOOL
            or not re.fullmatch(SHA256_PATTERN, row["sha256"])
            or row["minimum_php"] != {"composer": "7.2.5", "phpunit": "8.2"}[row["name"]]):
        raise ValueError("Unsupported or replaced exact tool tuple")
    names.add(row["name"])


def prepared_receipt(row, root):
    authority = row["publisher_authority"]
    required = {"state", "receipt", "receipt_sha256", "decision"}
    if row["name"] == "composer":
        required |= {"public_key", "public_key_sha256"}
    bootstrap.exact_keys(authority, required)
    if authority["state"] not in PUBLISHER_STATES | {"missing-full-fingerprint-binding"}:
        raise ValueError("Unknown publisher authority state")
    receipt = json.loads(evidence_file({"file": authority["receipt"],
                                       "sha256": authority["receipt_sha256"]}, root))
    if (receipt.get("kind") != "source-data-two-phars"
            or receipt.get("authority_ca_sha256") != "50f79f98dac192b20dbf73f35c56f0b0c557ab267ff5199d1117cc1180b70785"
            or any(receipt.get(name) is not False for name in
                   ("php_executed", "phar_stub_executed", "setup_executed", "apt_executed"))):
        raise ValueError("Tool evidence lacks the selected data-only client/store provenance")
    obj = receipt["objects"][f"{row['name']}-{row['version']}.phar"]
    if obj != {"url": row["url"], "effective_url": row["url"],
               "size": row["size"], "sha256": row["sha256"]}:
        raise ValueError("Prepared PHAR differs from its exact catalog identity")
    return receipt


def verify_publisher_metadata(row, receipt):
    records = {"composer": ("composer.sha256sum", "composer.sig.json"),
               "phpunit": ("phpunit-phive.xml", "phpunit.asc")}[row["name"]]
    for role, name in zip(("digest", "signature"), records):
        if (receipt["objects"][name]["url"] != row[f"publisher_{role}_url"]
                or receipt["objects"][name]["sha256"] != row["evidence"][role]["sha256"]):
            raise ValueError("Publisher metadata is not bound to the captured exact authority")


def verify_composer_authority(row, evidence, signature, root):
    authority = row["publisher_authority"]
    public = evidence_file({"file": authority["public_key"],
                            "sha256": authority["public_key_sha256"]}, root)
    if (authority["state"] != "verified" or signature.get("verification") != "Verified OK"
            or signature.get("public_key_role") != "Tags Public Key"
            or signature.get("public_key_pem_sha256") != bootstrap.sha256(public)):
        raise ValueError("Composer publisher verification is incomplete")
    if evidence["digest"].decode().split()[0] != row["sha256"]:
        raise ValueError("Composer publisher digest differs from selected bytes")


def verify_phpunit_digest(row, evidence):
    if row["publisher_authority"]["decision"] != "https://github.com/durable-workflow/.github/issues/297#issuecomment-6664627349":
        raise ValueError("Publisher digest authority lacks its exact source decision")
    manifest = ET.fromstring(evidence["digest"])
    if manifest.tag != "{https://phar.io/repository}repository":
        raise ValueError("Unknown publisher manifest format")
    releases = [release for phar in manifest if phar.get("name") == "phpunit"
                for release in phar if release.get("version") == row["version"]]
    if len(releases) != 1 or releases[0].get("url") != row["url"]:
        raise ValueError("Canonical publisher tool/version record is missing or ambiguous")
    hashes = [item for item in releases[0] if item.tag.rsplit("}", 1)[-1] == "hash"
              and item.get("type") == "sha-256"]
    if len(hashes) != 1 or hashes[0].get("value") != row["sha256"]:
        raise ValueError("Canonical publisher digest differs from selected PHAR bytes")


def validate_catalog(catalog: dict, root: Path = bootstrap.ROOT) -> dict:
    bootstrap.exact_keys(catalog, {"schema", "tools"})
    if (catalog["schema"] != "durable-workflow.php-linux-tools/v1"
            or not isinstance(catalog["tools"], list) or len(catalog["tools"]) != len(PROFILES)):
        raise ValueError("Unknown exact Linux tool catalog")
    names = set()
    for row in catalog["tools"]:
        validate_tool_tuple(row, names)
        bootstrap.exact_keys(row["evidence"], {"digest", "signature", "requirements"})
        evidence = {name: evidence_file(record, root) for name, record in row["evidence"].items()}
        receipt = prepared_receipt(row, root)
        signature = receipt["signatures"][row["name"]]
        verify_publisher_metadata(row, receipt)
        authority = row["publisher_authority"]
        if row["name"] == "composer":
            verify_composer_authority(row, evidence, signature, root)
        elif authority["state"] == "reviewed-publisher-digest":
            verify_phpunit_digest(row, evidence)
        elif authority["state"] != "missing-full-fingerprint-binding":
            raise ValueError("PHPUnit signature authentication is outside the selected source authority")
    return catalog


def select_tools(catalog: dict, requested: str, php: str, root: Path = bootstrap.ROOT) -> list[dict]:
    validate_catalog(catalog, root)
    if not re.fullmatch(r"8\.[1-5]", php):
        raise ValueError("Tools require an exact supported PHP minor")
    if requested == "none":
        return []
    if not requested:
        raise ValueError("Omitted/default tool selection has no reviewed exact tuple")
    rows = {f"{row['name']}:{row['version']}": row for row in catalog["tools"]}
    selections = [value.strip() for value in requested.split(",")]
    if len(selections) != len(set(selections)) or any(value not in rows for value in selections):
        raise ValueError("Only the explicitly reviewed tool versions are supported")
    result = [rows[value] for value in selections]
    for row in result:
        if row["name"] == "phpunit" and php == "8.1":
            raise ValueError("PHPUnit 11 requires PHP 8.2 or later; PHP 8.1 remains unsupported")
        if row["publisher_authority"]["state"] not in PUBLISHER_STATES:
            raise ValueError("Selected tool publisher authority is incomplete; no download or fallback")
    return result


def identity(row: dict) -> dict:
    if (row.get("name") not in PROFILES
            or (row.get("version"), row.get("url")) != PROFILES[row["name"]]
            or type(row.get("size")) is not int or not 0 < row["size"] <= MAX_TOOL
            or not re.fullmatch(SHA256_PATTERN, row.get("sha256", ""))):
        raise ValueError("Tool identity has no exact reviewed name/version/URL")
    return {"name": row["name"], "version": row["version"], "url": row["url"],
            "size": row["size"], "digest": "sha256:" + row["sha256"]}


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, target):
        raise ValueError("Exact tool URL redirected; replacement/fallback authority refused")


@contextmanager
def download_held(row: dict, context, opener_factory=build_opener, clock=time.monotonic):
    expected = identity(row)
    if (row["publisher_authority"]["state"] not in PUBLISHER_STATES
            or context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname):
        raise ValueError("Qualified publisher and exclusive verified HTTPS trust are required")
    client = opener_factory(ProxyHandler({}), HTTPSHandler(context=context), NoRedirects())
    request = Request(row["url"], headers={"Accept-Encoding": "identity",
                                          "User-Agent": "durable-workflow-php-bootstrap"})
    deadline = clock() + 60
    with client.open(request, timeout=15) as response:
        if response.status != 200 or response.geturl() != row["url"]:
            raise ValueError("Exact tool URL/status differs; no discovery or fallback")
        with bootstrap.hold_bytes(bootstrap.DeadlineInput(response, deadline, clock), expected,
                                  {"url": row["url"]}) as held:
            yield held


def install_held(held: bootstrap.HeldAsset, row: dict, environment: dict,
                 execute=subprocess.run, inspect=None):
    """Proposed installation effect, tested only with an inert executor.

    The sealed file is standard input to a fixed install command. No mutable
    cache/path is reopened between byte verification and installation.
    This function does not execute the PHAR or PHP.
    """
    held.assert_sealed()
    if held.identity != identity(row) or row["publisher_authority"]["state"] not in PUBLISHER_STATES:
        raise ValueError("Held tool does not match the reviewed qualified tuple")
    if environment != bootstrap.clean_environment(environment, environment.get("HOME", "")) or dict(os.environ) != environment:
        raise ValueError("Tool installation requires an already closed parent environment")
    target = Path("/usr/local/bin") / row["name"]
    os.lseek(held.descriptor, 0, os.SEEK_SET)
    execute(["/usr/bin/sudo", "/usr/bin/install", "-m", "0755", "/dev/stdin", str(target)],
            stdin=held.descriptor, env=environment, timeout=30, check=True)
    if inspect is None:
        inspect = lambda path: (path.lstat(), path.read_bytes())
    metadata, contents = inspect(target)
    if (not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o755
            or len(contents) != row["size"] or bootstrap.sha256(contents) != row["sha256"]):
        raise ValueError("Installed tool differs from the held verified input")
    return {"target": str(target), **held.identity}
