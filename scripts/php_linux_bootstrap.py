#!/usr/bin/env python3
"""Source proposal for the exact php-ubuntu installer/archive trust boundary.

This module has no installer/download command-line entrypoint. Consumer wiring,
the surrounding setup-php tool/extension paths and any actual setup execution
remain separate review gates on central issue 297.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import time
from typing import BinaryIO
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener


ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "qualification/php-linux-bootstrap.json"
SOURCE_COMMIT = "f3e473d116dcccaddc5834248c87452386958240"
REPOSITORY = "shivammathur/php-ubuntu"
SHA256_PREFIX = "sha256:"
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_INSTALLER = 16 * 1024
SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
REDIRECT_HOSTS = frozenset(("api.github.com", "github.com", "release-assets.githubusercontent.com"))


def sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def exact_keys(value: dict, keys: set[str]) -> None:
    if not isinstance(value, dict) or set(value) != keys:
        raise ValueError("Unexpected bootstrap record fields")


def asset_identity(value: dict, expected_name: str, maximum: int) -> dict:
    exact_keys(value, {"id", "name", "size", "digest"})
    if (type(value["id"]) is not int or value["id"] < 1
            or value["name"] != expected_name
            or type(value["size"]) is not int or not 0 < value["size"] <= maximum
            or not isinstance(value["digest"], str)
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", value["digest"])):
        raise ValueError("Unbound installer/archive identity")
    return value


def archive_name(row: dict) -> str:
    suffix = "_arm64" if row["arch"] == "aarch64" else ""
    return f"php_{row['php']}-nts+ubuntu{row['release']}{suffix}.tar.zst"


def validate_catalog(catalog: dict) -> dict:
    exact_keys(catalog, {"schema", "repository", "release_id", "release_tag", "setup_php_commit",
                         "upstream_sources", "installer", "archives"})
    if (catalog["schema"] != "durable-workflow.php-linux-bootstrap/v1"
            or catalog["repository"] != REPOSITORY or catalog["release_id"] != 39619287
            or catalog["release_tag"] != "builds" or catalog["setup_php_commit"] != SOURCE_COMMIT):
        raise ValueError("Unknown bootstrap source authority")
    exact_keys(catalog["upstream_sources"], {"unix.sh", "linux.sh"})
    if any(not re.fullmatch(r"[a-f0-9]{64}", item) for item in catalog["upstream_sources"].values()):
        raise ValueError("Unbound setup-php source bytes")
    installer = asset_identity(catalog["installer"], "install.sh", MAX_INSTALLER)
    if not isinstance(catalog["archives"], list) or not catalog["archives"]:
        raise ValueError("No reviewed archive tuples")
    identities = {installer["id"]}
    tuples = set()
    for row in catalog["archives"]:
        exact_keys(row, {"os", "release", "arch", "php", "thread_safety", "build", "asset"})
        if (row["os"] != "ubuntu" or row["release"] not in ("22.04", "24.04", "26.04")
                or row["arch"] not in ("x86_64", "aarch64") or row["thread_safety"] != "nts"
                or row["build"] != "release" or not re.fullmatch(r"8\.[1-5]", row["php"])):
            raise ValueError("Unsupported bootstrap tuple")
        asset = asset_identity(row["asset"], archive_name(row), MAX_ARCHIVE)
        key = tuple(row[name] for name in ("os", "release", "arch", "php", "thread_safety", "build"))
        if key in tuples or asset["id"] in identities:
            raise ValueError("Duplicate/replaced bootstrap tuple or asset")
        identities.add(asset["id"])
        tuples.add(key)
    return catalog


def select(catalog: dict, *, operating_system: str, release: str, architecture: str,
           php: str, thread_safety: str = "nts", build: str = "release") -> dict:
    validate_catalog(catalog)
    architecture = {"amd64": "x86_64", "arm64": "aarch64"}.get(architecture, architecture)
    requested = (operating_system, release, architecture, php, thread_safety, build)
    rows = [row for row in catalog["archives"] if tuple(row[name] for name in
            ("os", "release", "arch", "php", "thread_safety", "build")) == requested]
    if len(rows) != 1:
        raise ValueError("No exact reviewed bootstrap tuple; runner labels and latest are not selectors")
    return rows[0]


def asset_url(asset: dict) -> str:
    # The mutable tag/name and current release metadata are never fetch selectors.
    return f"https://api.github.com/repos/{REPOSITORY}/releases/assets/{asset['id']}"


def effective_url(url: str) -> dict:
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in REDIRECT_HOSTS or parsed.username
            or parsed.password or parsed.port not in (None, 443) or parsed.fragment):
        raise ValueError("Bootstrap redirect/fallback authority refused")
    if parsed.hostname == "api.github.com" and not re.fullmatch(
        r"/repos/shivammathur/php-ubuntu/releases/assets/[1-9]\d*", parsed.path,
    ):
        raise ValueError("Foreign bootstrap asset endpoint")
    if parsed.hostname == "github.com" and not parsed.path.startswith("/shivammathur/php-ubuntu/"):
        raise ValueError("Foreign bootstrap repository redirect")
    # Preserve exact URL binding without disclosing a signed query string.
    return {"scheme": parsed.scheme, "host": parsed.hostname, "path": parsed.path,
            "url_sha256": sha256(url.encode("utf-8"))}


class ClosedRedirects(HTTPRedirectHandler):
    max_redirections = 4

    def redirect_request(self, request, response, code, message, headers, target):
        effective_url(target)
        if code not in (301, 302, 303, 307, 308):
            raise ValueError("Unsupported bootstrap redirect status")
        return super().redirect_request(request, response, code, message, headers, target)


def explicit_trust(bundle: Path, expected_sha256: str, context_factory=ssl.SSLContext):
    """Consume the existing authenticated-bootstrap trust output exclusively.

    The caller binds expected_sha256 to that predecessor's reviewed output;
    there is no host-store fallback, new trust root or native-store mutation.
    """
    if (not re.fullmatch(r"[a-f0-9]{64}", expected_sha256) or bundle.is_symlink()
            or not bundle.is_file() or not 0 < bundle.stat().st_size <= 1024 * 1024):
        raise ValueError("Authenticated bootstrap CA input is missing or invalid")
    contents = bundle.read_bytes()
    if sha256(contents) != expected_sha256:
        raise ValueError("Bootstrap CA differs from its authenticated predecessor")
    context = context_factory(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=contents.decode("ascii"))
    return context


class DeadlineInput:
    def __init__(self, response, deadline, clock=time.monotonic):
        self.response = response
        self.deadline = deadline
        self.clock = clock

    def read(self, size):
        if self.clock() >= self.deadline:
            raise ValueError("Bound bootstrap asset read deadline exhausted")
        return self.response.read(size)


@contextmanager
def download_held(identity: dict, context, opener_factory=build_opener, clock=time.monotonic):
    """Proposed anonymous exact-ID fetch; no live metadata or retry/fallback.

    This function is not wired into an action. Its source controls substitute
    an inert opener; no installer/archive acquisition runs in those controls.
    """
    asset_identity(identity, identity["name"], MAX_ARCHIVE)
    if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
        raise ValueError("Verified explicit HTTPS trust is required")
    client = opener_factory(ProxyHandler({}), HTTPSHandler(context=context), ClosedRedirects())
    request = Request(asset_url(identity), headers={"Accept": "application/octet-stream",
                                                 "User-Agent": "durable-workflow-php-bootstrap"})
    deadline = clock() + 60
    with client.open(request, timeout=15) as response:
        if response.status != 200:
            raise HTTPError(request.full_url, response.status, "Bootstrap asset response refused", None, None)
        final = response.geturl()
        effective_url(final)
        with hold_verified(DeadlineInput(response, deadline, clock), identity, final) as held:
            yield held


@dataclass
class HeldAsset:
    descriptor: int
    identity: dict
    effective: dict

    def assert_sealed(self) -> None:
        if (fcntl.fcntl(self.descriptor, fcntl.F_GET_SEALS) != SEALS
                or os.fstat(self.descriptor).st_size != self.identity["size"]):
            raise ValueError("Installer/archive stream is not the verified sealed input")
        digest = hashlib.sha256()
        offset = 0
        while chunk := os.pread(self.descriptor, 65536, offset):
            digest.update(chunk)
            offset += len(chunk)
        if SHA256_PREFIX + digest.hexdigest() != self.identity["digest"]:
            raise ValueError("Sealed installer/archive identity differs")

    def close(self) -> None:
        os.close(self.descriptor)


@contextmanager
def hold_bytes(source: BinaryIO, identity: dict, final: dict):
    """Shared sealed-byte primitive; callers bind provider/catalog authority."""
    if (type(identity.get("size")) is not int or not 0 < identity["size"] <= MAX_ARCHIVE
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", identity.get("digest", ""))):
        raise ValueError("Bound stream size/digest is invalid")
    descriptor = os.memfd_create("durable-php-input", os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    try:
        size = 0
        digest = hashlib.sha256()
        while chunk := source.read(min(65536, identity["size"] + 1 - size)):
            size += len(chunk)
            if size > identity["size"]:
                raise ValueError("Bootstrap input exceeds the independently pinned size")
            digest.update(chunk)
            view = memoryview(chunk)
            while view:
                view = view[os.write(descriptor, view):]
        if size != identity["size"] or SHA256_PREFIX + digest.hexdigest() != identity["digest"]:
            raise ValueError("Bootstrap input differs from the independently pinned bytes")
        fcntl.fcntl(descriptor, fcntl.F_ADD_SEALS, SEALS)
        os.lseek(descriptor, 0, os.SEEK_SET)
        held = HeldAsset(descriptor, dict(identity), final)
        held.assert_sealed()
        yield held
    finally:
        os.close(descriptor)



@contextmanager
def hold_verified(source: BinaryIO, identity: dict, final_url: str):
    """Bind a GitHub asset independently before sealing its exact descriptor."""
    asset_identity(identity, identity["name"], MAX_ARCHIVE)
    with hold_bytes(source, identity, effective_url(final_url)) as held:
        yield held


def installer_source_origin(identity: dict) -> dict:
    catalog = validate_catalog(json.loads(CATALOG.read_text()))
    if identity != catalog["installer"]:
        raise ValueError("Installer differs from the committed source authority")
    return {"kind": "repository", "path":
            f"qualification/vendor/php-ubuntu-{identity['id']}/install.sh",
            "digest": identity["digest"]}


@contextmanager
def hold_source_installer(identity: dict):
    """Seal the committed upstream snapshot without a rolling release request."""
    origin = installer_source_origin(identity)
    descriptor = os.open(ROOT / origin["path"], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size != identity["size"]:
            raise ValueError("Committed installer is not the bounded regular input")
        with hold_bytes(source, identity, origin) as held:
            after = os.fstat(source.fileno())
            fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(before, key) != getattr(after, key) for key in fields):
                raise ValueError("Committed installer changed while sealing")
            yield held


def replace_once(source: str, before: str, after: str) -> str:
    if source.count(before) != 1:
        raise ValueError("Pinned upstream patch location is absent or ambiguous")
    return source.replace(before, after, 1)


def installer_source(original: bytes, catalog: dict) -> bytes:
    """Keep the reviewed upstream effects, replace acquisition/extraction only.

    Conditional network APT repair is an explicit refusal until General's
    separate issue295 guard/offline contract is integrated and reviewed.
    """
    validate_catalog(catalog)
    if len(original) != catalog["installer"]["size"] or SHA256_PREFIX + sha256(original) != catalog["installer"]["digest"]:
        raise ValueError("Installer patch requires the exact independently pinned upstream bytes")
    source = original.decode("utf-8")
    start = source.index("get() {\n")
    finish = source.index("\ninstall() {", start)
    source = source[:start] + source[finish + 1:]
    acquisition = next(line for line in source.splitlines() if line.startswith('  get /tmp/"$tar_file"'))
    source = replace_once(source, acquisition, '  : "Archive is inherited as a verified sealed descriptor"')
    source = replace_once(source, '  sudo tar -I zstd -xf /tmp/"$tar_file" -C /',
                          '  /usr/bin/sudo /usr/bin/tar -I /usr/bin/zstd -xf - -C / <&"$DW_VERIFIED_ARCHIVE_FD"')
    repair = '    sudo apt --fix-broken install -y || (sudo apt-get update && sudo apt --fix-broken install -y)'
    refusal = '    printf "%s\\n" "Bound PHP setup refuses network APT repair pending issue295" >&2; exit 78'
    source = replace_once(source, repair, refusal)
    debug = '    [ -n "$list" ] && sudo apt-get update -o Dir::Etc::sourcelist="$list" -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup="0"'
    source = replace_once(source, debug, refusal)
    return source.encode("utf-8")


def no_apt_installer_source(original: bytes, catalog: dict) -> bytes:
    """Initial CLI profile: no APT, package-state merger or service start.

    The exact held upstream archive still supplies PHP. Package-manager state
    and the merge helper are excluded from root extraction, so no opaque
    archive helper is executed. Missing host libraries cause refusal; they
    never trigger a package-manager repair.
    """
    source = installer_source(original, catalog).decode()
    for line in ('  sudo cp /var/lib/dpkg/status /var/lib/dpkg/status-orig\n',
                 '  sudo rm -rf /var/lib/apt/lists/*ondrej*\n',
                 '  sudo LC_ALL=C.UTF-8 python3 /usr/sbin/merge_status && sudo rm -f /usr/sbin/merge_status\n',
                 '  sudo mv /var/lib/dpkg/status-orig /var/lib/dpkg/status\n'):
        source = replace_once(source, line, '')
    excludes = ' '.join('--exclude=' + prefix + name for name in
        ('var/lib/dpkg', 'var/lib/apt', 'etc/apt', 'usr/sbin/merge_status') for prefix in ('', './'))
    from scripts import php_linux_alternatives as alternatives
    excludes += ' ' + ' '.join('--exclude=' + prefix + name
        for name in alternatives.exclusions() for prefix in ('', './'))
    source = replace_once(source, '/usr/bin/tar -I /usr/bin/zstd -xf - -C /',
                          '/usr/bin/tar -I /usr/bin/zstd ' + excludes + ' -xf - -C /')
    for name in ('fix_service', 'fix_list', 'fix_packages'):
        pattern = r'^' + name + r'\(\) \{\n.*?^\}\n'
        matches = list(re.finditer(pattern, source, re.M | re.S))
        if len(matches) != 1:
            raise ValueError("Exact initial installer phase is absent or ambiguous")
        match = matches[0]
        source = source[:match.start()] + source[match.end():]
        source = replace_once(source, '\n' + name + '\n', '\n')
    source = replace_once(source, '  wait "${to_wait[@]}"\n}',
        '  wait "${to_wait[@]}"\n' + alternatives.selection_source() + '\n}')
    return source.encode()


def clean_environment(parent: dict[str, str], private_home: str) -> dict[str, str]:
    """Used before execve, so no credential-bearing wrapper parent remains."""
    home = Path(private_home)
    if not home.is_absolute() or any(character in private_home for character in "\r\n\0"):
        raise ValueError("A private absolute setup HOME is required")
    allowed = ("GITHUB_ENV", "GITHUB_PATH", "GITHUB_OUTPUT", "GITHUB_STEP_SUMMARY",
               "RUNNER_TEMP", "RUNNER_TOOL_CACHE", "RUNNER_OS", "RUNNER_ARCH", "RUNNER_ENVIRONMENT",
               "ImageOS", "ImageVersion", "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE",
               "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "COMPOSER_CAFILE", "COMPOSER_CAPATH", "DW_CI_CA_SHA256")
    environment = {name: parent[name] for name in allowed if parent.get(name)}
    environment.update({"PATH": "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "HOME": private_home,
                        "TMPDIR": str(home.parent / "tmp"), "TMP": str(home.parent / "tmp"),
                        "TEMP": str(home.parent / "tmp"),
                        "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "GITHUB_ACTIONS": "true"})
    return environment


def observed_host() -> dict:
    text = Path("/etc/os-release").read_text(encoding="utf-8")
    values = {}
    for name in ("ID", "VERSION_ID"):
        matches = re.findall(r"^" + name + r"=(?:\"([^\"]+)\"|([a-zA-Z0-9.]+))$", text, re.M)
        if len(matches) != 1:
            raise ValueError("Effective runner distribution/release is ambiguous")
        values[name] = matches[0][0] or matches[0][1]
    return {"operating_system": values["ID"], "release": values["VERSION_ID"],
            "architecture": os.uname().machine}


def run_held_installer(script: HeldAsset, archive: HeldAsset, arguments: tuple[str, str, str],
                       environment: dict[str, str], catalog: dict, execute=subprocess.run, host=None,
                       no_apt=False, normalized=None):
    """Effect primitive only; no shipped CLI/action currently invokes this.

    The proposed consumer must first execve into this closed environment and
    bind both original/derived installer identities to its reviewed recipe.
    Tests inject an inert executor and never run the installer or sudo/tar.
    """
    script.assert_sealed()
    archive.assert_sealed()
    if len(arguments) != 3:
        raise ValueError("Exact PHP/build/thread-safety arguments required")
    selected = select(catalog, **(observed_host() if host is None else host),
                      php=arguments[0], build=arguments[1], thread_safety=arguments[2])
    original = (ROOT / "qualification/vendor/php-ubuntu-713206915/install.sh").read_bytes()
    derived = no_apt_installer_source(original, catalog) if no_apt else installer_source(original, catalog)
    derived_identity = dict(catalog["installer"], name="bound-install.sh", size=len(derived),
                            digest=SHA256_PREFIX + sha256(derived))
    if archive.identity != selected["asset"] or script.identity != derived_identity:
        raise ValueError("Held inputs do not match the exact selected source/tuple")
    installation_archive = archive
    if normalized is not None:
        from scripts import php_linux_normalize as normalization
        if not isinstance(normalized, normalization.NormalizedInput) or normalized.original is not archive or not no_apt:
            raise ValueError("Only the exact no-APT normalization derivation is supported")
        normalized.assert_valid()
        installation_archive = normalized.held
    if environment != clean_environment(environment, environment.get("HOME", "")) or dict(os.environ) != environment:
        raise ValueError("Bound installer requires an already closed parent environment")
    os.lseek(script.descriptor, 0, os.SEEK_SET)
    os.lseek(installation_archive.descriptor, 0, os.SEEK_SET)
    child = dict(environment, DW_VERIFIED_ARCHIVE_FD=str(installation_archive.descriptor))
    result = execute(["/usr/bin/bash", f"/proc/self/fd/{script.descriptor}", *arguments], env=child,
                     pass_fds=(script.descriptor, installation_archive.descriptor), timeout=120, check=True)
    if normalized is not None:
        from scripts import php_linux_alternatives as alternatives
        alternatives.verify(normalized.files, original=normalized.original.identity)
    return result
