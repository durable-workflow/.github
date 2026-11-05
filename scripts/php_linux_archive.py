"""Read a held PHP archive and bind installed PHP/modules before execution."""

import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import select
import shutil
import stat
import subprocess
import tarfile
import time

from scripts import php_linux_bootstrap as bootstrap


MAX_UNPACKED = 2 * 1024 * 1024 * 1024
MAX_MEMBERS = 100000


class BoundedPipe(io.RawIOBase):
    def __init__(self, stream, maximum=MAX_UNPACKED, duration=60):
        self.stream, self.remaining = stream, maximum
        self.deadline = time.monotonic() + duration

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or not select.select([self.stream], [], [], remaining)[0]:
            raise ValueError("Bound archive inspection deadline exhausted")
        data = os.read(self.stream.fileno(), min(len(buffer), self.remaining + 1))
        self.remaining -= len(data)
        if self.remaining < 0:
            raise ValueError("Bound archive exceeds the inspection byte limit")
        buffer[:len(data)] = data
        return len(data)


def inventory(stream) -> dict:
    """Stream regular file hashes, never extract or execute archive members."""
    try:
        with tarfile.open(fileobj=stream, mode="r|") as archive:
            return inventory_members(archive)
    except tarfile.TarError as error:
        raise ValueError("Bound archive structure is invalid; no extraction authority") from error


def canonical_member(member) -> str:
    name = member.name
    if member.isdir() and name in (".", "./"):
        return ""
    if name.startswith("./"):
        name = name[2:]
    if len(name.encode('utf-8')) > 4096 or len(name.split('/')) > 128:
        raise ValueError("Bound archive member path exceeds the inspection scope")
    path = PurePosixPath(name)
    if (not name or name != path.as_posix() or path.is_absolute()
            or any(part in ("", ".", "..") for part in name.split("/"))
            or any(character in name for character in "\0\r\n\\")):
        raise ValueError("Bound archive member path is not canonical and scoped")
    return name


def inventory_members(archive) -> dict:
    files, seen, parents, total = {}, {}, set(), 0
    for count, member in enumerate(archive, 1):
        if count > MAX_MEMBERS:
            raise ValueError("Bound archive member limit exceeded")
        if (member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE, tarfile.DIRTYPE)
                or member.issparse() or set(member.pax_headers) -
                {"path", "mtime", "atime", "ctime", "uid", "gid", "uname", "gname"}):
            raise ValueError("Bound archive links/sparse/special members are unsupported")
        name = canonical_member(member)
        ancestors = {parent.as_posix() for parent in PurePosixPath(name).parents if parent.as_posix() != "."}
        kind = "directory" if member.isdir() else "file"
        if (name in seen or any(seen.get(parent) == "file" for parent in ancestors)
                or (kind == "file" and name in parents)):
            raise ValueError("Bound archive canonical member/parent/type collision")
        seen[name] = kind
        parents.update(ancestors)
        if len(seen) + len(parents) > MAX_MEMBERS:
            raise ValueError("Bound archive explicit/implicit member limit exceeded")
        if member.isdir():
            continue
        total += member.size
        if member.size < 0 or total > MAX_UNPACKED:
            raise ValueError("Bound archive file-size limit exceeded")
        digest, size = hashlib.sha256(), 0
        source = archive.extractfile(member)
        while chunk := source.read(65536):
            digest.update(chunk)
            size += len(chunk)
        if size != member.size:
            raise ValueError("Bound archive regular member is truncated")
        files[name] = {"size": size, "sha256": digest.hexdigest()}
    return files


def inspect_held(held: bootstrap.HeldAsset) -> dict:
    held.assert_sealed()
    os.lseek(held.descriptor, 0, os.SEEK_SET)
    process = subprocess.Popen(["/usr/bin/zstd", "--decompress", "--stdout", "--quiet"],
        stdin=held.descriptor, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
    try:
        with io.BufferedReader(BoundedPipe(process.stdout)) as stream:
            files = inventory(stream)
            while stream.read(65536):
                pass
        if process.wait(timeout=5) != 0:
            raise ValueError("Bound archive decompression failed")
        return files
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()


def verify_file(path: Path, expected: dict, read=None):
    if read is None:
        read = lambda item: (item.lstat(), item.read_bytes())
    metadata, contents = read(path)
    if (not stat.S_ISREG(metadata.st_mode) or len(contents) != expected["size"]
            or bootstrap.sha256(contents) != expected["sha256"]):
        raise ValueError("Installed PHP/module does not match its held archive member")


def verify_installed(files: dict, php: str, required: list[str], execute=subprocess.run,
                     root: Path = Path("/"), read=None, shared=None, command_path=None,
                     active_configs=None, resolve=None) -> dict:
    binary_name = f"usr/bin/php{php}"
    if binary_name not in files:
        raise ValueError("Bound archive does not contain its exact regular PHP binary")
    binary = root / binary_name
    verify_file(binary, files[binary_name], read)
    if command_path is None:
        command_path = lambda name: Path(shutil.which(name, path=os.environ["PATH"]) or "/missing-command").resolve()
    for command in ("php", "php-config"):
        member = f"usr/bin/{command}{php}"
        if member not in files or command_path(command) != (root / member).resolve():
            raise ValueError("Default PHP command does not resolve to its bound installed archive member")
        verify_file(root / member, files[member], read)
    # -n suppresses configuration/module loading until the requested module
    # identities are checked. The executable itself was bound above.
    probe = execute([str(binary), "-n", "-r",
        "echo json_encode(['builtins'=>get_loaded_extensions(),'extension_dir'=>PHP_EXTENSION_DIR,"
        "'version'=>PHP_VERSION,'zts'=>PHP_ZTS,'debug'=>PHP_DEBUG,"
        "'config_path'=>defined('PHP_CONFIG_FILE_PATH')?PHP_CONFIG_FILE_PATH:null,"
        "'scan_dir'=>defined('PHP_CONFIG_FILE_SCAN_DIR')?PHP_CONFIG_FILE_SCAN_DIR:null]);"],
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, capture_output=True,
        text=True, timeout=10, check=True)
    import json
    result = json.loads(probe.stdout)
    bootstrap.exact_keys(result, {"builtins", "extension_dir", "config_path", "scan_dir", "version", "zts", "debug"})
    if (not isinstance(result["version"], str) or not result["version"].startswith(php + ".")
            or result["zts"] != 0 or result["debug"] != 0):
        raise ValueError("Bound PHP does not implement the selected minor/NTS/release tuple")
    if (not isinstance(result["builtins"], list)
            or any(not isinstance(name, str) for name in result["builtins"])
            or not isinstance(result["extension_dir"], str)):
        raise ValueError("Bound PHP module probe is malformed")
    directory = PurePosixPath(result["extension_dir"])
    if (not directory.is_absolute() or ".." in directory.parts
            or not directory.as_posix().startswith("/usr/lib/php/")):
        raise ValueError("Bound PHP extension directory is outside the archive scope")
    prefix = directory.as_posix().lstrip("/")
    shared = list((root / prefix).glob("*.so")) if shared is None else shared
    for path in shared:
        name = path.relative_to(root).as_posix()
        if name not in files:
            raise ValueError("Ambient shared extension is absent from the bound archive")
        verify_file(path, files[name], read)
    # Default startup must not load an ambient .ini or a module from outside
    # the held archive before pinned upstream starts. Redis's one INI rewrite
    # is the deterministic effect in the bound upstream installer itself.
    if (result["config_path"] != f"/etc/php/{php}/cli"
            or result["scan_dir"] != f"/etc/php/{php}/cli/conf.d"):
        raise ValueError("PHP default configuration paths have no reviewed CLI profile")
    configs = dict(files)
    redis = b"; priority=25\nextension=redis.so\n"
    configs[f"etc/php/{php}/mods-available/redis.ini"] = {"size": len(redis), "sha256": bootstrap.sha256(redis)}
    if active_configs is None:
        active_configs = [root / result["config_path"].lstrip("/") / "php.ini",
                          *(root / result["scan_dir"].lstrip("/")).glob("*.ini")]
    resolve = (lambda path: path.resolve(strict=True)) if resolve is None else resolve
    for path in active_configs:
        target = resolve(path)
        name = target.relative_to(root).as_posix()
        if name not in configs:
            raise ValueError("Ambient PHP startup configuration is absent from the held source recipe")
        verify_file(target, configs[name], read)
        text = target.read_text() if read is None else read(target)[1].decode()
        if re.search(r"^\s*extension_dir\s*=", text, re.M | re.I):
            raise ValueError("An active extension_dir override has no reviewed initial profile")
        for match in re.finditer(r"^\s*(?:zend_)?extension\s*=\s*([^;\r\n]+)", text, re.M | re.I):
            value = match[1].strip().strip('"\'')
            module = PurePosixPath(value)
            if not module.is_absolute():
                module = directory / (value if value.endswith(".so") else value + ".so")
            member = module.as_posix().lstrip("/")
            if ".." in module.parts or member not in files:
                raise ValueError("Active startup module is absent from the bound archive")
            verify_file(root / member, files[member], read)
    builtins = {name.lower() for name in result["builtins"]}
    checked = {}
    for extension in required:
        name = "sqlite3" if extension == "sqlite" else extension
        if name in builtins:
            checked[extension] = {"source": binary_name, **files[binary_name]}
            continue
        member = f"{prefix}/{name}.so"
        if member not in files:
            raise ValueError("Requested extension is absent from the bound PHP archive; no acquisition")
        verify_file(root / member, files[member], read)
        checked[extension] = {"source": member, **files[member]}
    return {"binary": {"source": binary_name, **files[binary_name]}, "extensions": checked,
            "version": result["version"], "zts": result["zts"], "debug": result["debug"]}


def verify_enabled(files: dict, php: str, required: list[str], coverage: str,
                   execute=subprocess.run, command_path=None) -> dict:
    binary = Path(f"/usr/bin/php{php}")
    verify_file(binary, files[f"usr/bin/php{php}"])
    if command_path is None:
        command_path = lambda: Path(shutil.which("php", path=os.environ["PATH"]) or "/missing-php").resolve()
    if command_path() != binary.resolve():
        raise ValueError("Configured default PHP no longer resolves to the bound binary")
    probe = execute([str(binary), "-r", "echo json_encode(get_loaded_extensions());"],
        env=bootstrap.clean_environment(dict(os.environ), os.environ["HOME"]),
        capture_output=True, text=True, timeout=10, check=True)
    import json
    loaded = json.loads(probe.stdout)
    if not isinstance(loaded, list) or any(not isinstance(name, str) for name in loaded):
        raise ValueError("Configured PHP module observation is malformed")
    actual = {name.lower().replace("zend ", "") for name in loaded}
    if any(("sqlite3" if name == "sqlite" else name) not in actual for name in required):
        raise ValueError("An archive-contained requested extension was not enabled")
    if coverage == "none" and actual & {"pcov", "xdebug"}:
        raise ValueError("Explicit coverage none did not disable the coverage drivers")
    return {"loaded_extensions": sorted(actual), "coverage": coverage}
