"""Closed CLI configuration derivation for the initial Linux PHP profile.

Expectations come from a held production template and the pinned setup source.
Observed configured files never supply their own expected digest.
"""

import base64
from contextlib import contextmanager
import io
import os
from pathlib import Path
import re
import stat
import subprocess

from scripts import php_linux_bootstrap as bootstrap
from scripts import php_linux_recipe as recipe
from scripts import php_linux_normalize as normalization


SCHEMA = "durable-workflow.php-linux-cli-configuration/v1"
PROFILE = "ubuntu26.04-x64-php8.3-production-coverage-none"
TEMPLATE = "usr/lib/php/8.3/php.ini-production.cli"
CLI = "etc/php/8.3/cli/php.ini"
PECL = "etc/php/8.3/cli/conf.d/99-pecl.ini"
CURRENT = "usr/lib/php/8.3/php.ini-current"
MANIFEST_NAME = "cli-configuration.json"
MAX_TEMPLATE = 128 * 1024
MAX_DOCUMENT = 256 * 1024
COMPONENTS = ("src/configs/ini/php.ini", "src/configs/ini/xdebug.ini", "src/configs/ini/jit.ini")


def identity(raw):
    return {"size": len(raw), "sha256": bootstrap.sha256(raw)}


def without_coverage(raw):
    # Preserve the exact pinned GNU sed expression, including its unescaped dot.
    expression = re.compile(rb'=(.*/)?"?(xdebug|pcov)(.so)?"?$')
    lines = raw.split(b"\n")
    return b"".join(line + (b"\n" if index < len(lines) - 1 else b"")
                    for index, line in enumerate(lines) if not expression.search(line))


def removed_members(files):
    prefix = "etc/php/8.3/cli/conf.d/"
    selected = []
    for member in files:
        if member.startswith(prefix) and re.fullmatch(r"[A-Za-z0-9_.-]+-(?:xdebug|pcov)\.ini", member[len(prefix):]):
            selected.append(member)
    if len(selected) > 16:
        raise ValueError("CLI coverage removal exceeds the closed initial profile")
    return sorted(selected)


def derive(template, files, source):
    if (not isinstance(template, bytes) or not 0 < len(template) <= MAX_TEMPLATE
            or files.get(TEMPLATE) != identity(template)):
        raise ValueError("CLI production template lacks held archive authority")
    components = {name: source[name] for name in COMPONENTS}
    if any(not isinstance(raw, bytes) or not 0 < len(raw) <= 4096 for raw in components.values()):
        raise ValueError("Pinned CLI configuration component exceeds its source bound")
    outputs = {
        CLI: without_coverage(template + components[COMPONENTS[0]] + components[COMPONENTS[1]]),
        PECL: without_coverage(b"\n" + components[COMPONENTS[2]]),
        CURRENT: b"production\n",
    }
    document = {
        "schema": SCHEMA, "profile": PROFILE, "setup_php_commit": bootstrap.SOURCE_COMMIT,
        "input": {"member": TEMPLATE, **identity(template),
                  "base64": base64.b64encode(template).decode("ascii")},
        "components": {name: identity(raw) for name, raw in components.items()},
        "outputs": {name: identity(raw) for name, raw in outputs.items()},
        "removed": removed_members(files),
    }
    return document, outputs


def validate(document, files, source=None):
    bootstrap.exact_keys(document, {"schema", "profile", "setup_php_commit", "input", "components", "outputs", "removed"})
    incoming = document["input"]
    bootstrap.exact_keys(incoming, {"member", "size", "sha256", "base64"})
    for mapping in (document["components"], document["outputs"]):
        if not isinstance(mapping, dict):
            raise ValueError("CLI configuration file identities require a closed mapping")
        for value in mapping.values():
            bootstrap.exact_keys(value, {"size", "sha256"})
            if type(value["size"]) is not int or not isinstance(value["sha256"], str):
                raise ValueError("CLI configuration file identity has invalid field types")
    if type(incoming["size"]) is not int or not isinstance(incoming["sha256"], str):
        raise ValueError("CLI configuration preimage identity has invalid field types")
    if not isinstance(incoming["base64"], str) or len(incoming["base64"]) > 4 * ((MAX_TEMPLATE + 2) // 3):
        raise ValueError("CLI configuration preimage exceeds its fixed bound")
    try:
        template = base64.b64decode(incoming["base64"], validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("CLI configuration preimage is not canonical base64") from error
    expected, outputs = derive(template, files, recipe.verified_source() if source is None else source)
    if document != expected:
        raise ValueError("CLI configuration differs from its independently derived source recipe")
    return outputs


def subject_plan(document, files):
    outputs = validate(document, files)
    prefix = "etc/php/8.3/cli/conf.d/"
    active = {name for name in files if name.startswith(prefix)
              and "/" not in name[len(prefix):] and name.endswith('.ini')}
    active.difference_update(document['removed'])
    active.update((CLI, PECL))
    return {'schema': SCHEMA, 'outputs': {name: identity(raw) for name, raw in outputs.items()},
            'active': sorted(active)}


def capture_template(files, root=Path("/")):
    return capture_member(files, TEMPLATE, root)


def capture_member(files, member, root):
    expected = files.get(member)
    if not isinstance(expected, dict) or type(expected.get("size")) is not int or not 0 < expected["size"] <= MAX_TEMPLATE:
        raise ValueError("Initial archive lacks its bounded CLI production template")
    descriptor = os.open(root / member, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size != expected["size"]:
            raise ValueError("CLI template is not the exact regular installed archive member")
        raw = os.pread(descriptor, MAX_TEMPLATE + 1, 0)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (any(getattr(before, key) != getattr(after, key) for key in fields)
                or identity(raw) != expected):
            raise ValueError("CLI template bytes changed during descriptor capture")
        return raw
    finally:
        os.close(descriptor)


def write_manifest(state, document, files):
    validate(document, files)
    return normalization.write_document(state, MANIFEST_NAME, document, MAX_DOCUMENT)


@contextmanager
def capture_manifest(state, record, files):
    with normalization.capture_document(state, record, MANIFEST_NAME, MAX_DOCUMENT) as (document, held, unchanged):
        outputs = validate(document, files)
        yield document, outputs, held, unchanged


def apply(document, files, environment, *, root=Path("/"), execute=subprocess.run, source=None):
    """Write only three literal outputs and remove exact held coverage entries."""
    outputs = validate(document, files, source)
    if environment != bootstrap.clean_environment(environment, environment.get("HOME", "")) or dict(os.environ) != environment:
        raise ValueError("CLI configuration requires the already closed parent environment")
    for member in outputs:
        path = root / member
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("CLI output cannot replace a symlink, alias or special file")
    for member in document['removed']:
        capture_member(files, member, root)
    for member, raw in outputs.items():
        bound = {"size": len(raw), "digest": bootstrap.SHA256_PREFIX + bootstrap.sha256(raw)}
        with bootstrap.hold_bytes(io.BytesIO(raw), bound, {"recipe": SCHEMA, "member": member}) as held:
            execute(["/usr/bin/sudo", "/usr/bin/tee", "--", str(root / member)],
                    stdin=held.descriptor, stdout=subprocess.DEVNULL,
                    env=environment, timeout=10, check=True)
            held.assert_sealed()
        execute(["/usr/bin/sudo", "/usr/bin/chmod", "0644", str(root / member)],
                env=environment, timeout=10, check=True)
        descriptor = os.open(root / member, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or stat.S_IMODE(metadata.st_mode) != 0o644
                    or identity(os.pread(descriptor, MAX_TEMPLATE + 16385, 0)) != identity(raw)):
                raise ValueError("Written CLI output differs from its sealed source derivation")
        finally:
            os.close(descriptor)
    for member in document["removed"]:
        path = root / member
        capture_member(files, member, root)
        execute(["/usr/bin/sudo", "/usr/bin/rm", "--", str(path)],
                env=environment, timeout=10, check=True)
    return outputs
