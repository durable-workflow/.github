"""Read a held PHP archive and bind installed PHP/modules before execution."""

import hashlib
import io
import json
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
SUBJECT_SCHEMA = "durable-workflow.php-linux-subjects/v1"
NORMALIZED_SUBJECT_SCHEMA = "durable-workflow.php-linux-subjects/v2"
MAX_SUBJECT_BYTES = 48 * 1024


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


def reserve_member(member, seen, parents) -> str:
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
    return name


def member_identity(source, expected_size):
    digest, size = hashlib.sha256(), 0
    while chunk := source.read(65536):
        digest.update(chunk)
        size += len(chunk)
    if size != expected_size:
        raise ValueError("Bound archive regular member is truncated")
    return {"size": size, "sha256": digest.hexdigest()}


def inventory_members(archive) -> dict:
    files, seen, parents, total = {}, {}, set(), 0
    for count, member in enumerate(archive, 1):
        if count > MAX_MEMBERS:
            raise ValueError("Bound archive member limit exceeded")
        name = reserve_member(member, seen, parents)
        if member.isdir():
            continue
        total += member.size
        if member.size < 0 or total > MAX_UNPACKED:
            raise ValueError("Bound archive file-size limit exceeded")
        files[name] = member_identity(archive.extractfile(member), member.size)
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
                # Consume through decoder EOF so zstd verifies its checksum.
                continue
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
        member = path.name if re.fullmatch(r'[A-Za-z0-9_.-]{1,100}', path.name) else 'unknown-member'
        raise ValueError("Installed PHP/module does not match its held archive member: " + member)


def verify_commands(files, php, root, read, command_path):
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
    return binary_name, binary


def probe_binary(binary, php, execute):
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
    return result, directory


def verify_shared(files, directory, root, read, shared):
    prefix = directory.as_posix().lstrip("/")
    shared = list((root / prefix).glob("*.so")) if shared is None else shared
    for path in shared:
        name = path.relative_to(root).as_posix()
        if name not in files:
            raise ValueError("Ambient shared extension is absent from the bound archive")
        verify_file(path, files[name], read)


def verify_config_modules(text, directory, files, root, read):
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


def configuration_members(files, php):
    configs = dict(files)
    redis = b"; priority=25\nextension=redis.so\n"
    configs[f"etc/php/{php}/mods-available/redis.ini"] = {"size": len(redis), "sha256": bootstrap.sha256(redis)}
    return configs


def verify_configs(files, php, result, directory, root, read, active_configs, resolve, configuration=None):
    # Default startup must not load an ambient .ini or a module from outside
    # the held archive before pinned upstream starts. Redis's one INI rewrite
    # is the deterministic effect in the bound upstream installer itself.
    if (result["config_path"] != f"/etc/php/{php}/cli"
            or result["scan_dir"] != f"/etc/php/{php}/cli/conf.d"):
        raise ValueError("PHP default configuration paths have no reviewed CLI profile")
    configs = configuration_members(files, php)
    if configuration is not None:
        configs.update(configuration['outputs'])
    if active_configs is None:
        active_configs = [root / result["config_path"].lstrip("/") / "php.ini",
                          *(root / result["scan_dir"].lstrip("/")).glob("*.ini")]
    resolve = (lambda path: path.resolve(strict=True)) if resolve is None else resolve
    if configuration is not None and sorted(path.relative_to(root).as_posix() for path in active_configs) != configuration['active']:
        raise ValueError('Active CLI configuration differs from the complete held recipe')
    for path in active_configs:
        target = resolve(path)
        name = target.relative_to(root).as_posix()
        if name not in configs:
            raise ValueError("Ambient PHP startup configuration is absent from the held source recipe")
        verify_file(target, configs[name], read)
        text = target.read_text() if read is None else read(target)[1].decode()
        verify_config_modules(text, directory, files, root, read)


def verify_required(files, required, result, directory, binary_name, root, read):
    prefix = directory.as_posix().lstrip("/")
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
    return checked


def verify_installed(files: dict, php: str, required: list[str], execute=subprocess.run,
                     root: Path = Path("/"), read=None, shared=None, command_path=None,
                     active_configs=None, resolve=None, configuration=None) -> dict:
    binary_name, binary = verify_commands(files, php, root, read, command_path)
    result, directory = probe_binary(binary, php, execute)
    verify_shared(files, directory, root, read, shared)
    verify_configs(files, php, result, directory, root, read, active_configs, resolve, configuration)
    checked = verify_required(files, required, result, directory, binary_name, root, read)
    return {"binary": {"source": binary_name, **files[binary_name]}, "extensions": checked,
            "version": result["version"], "zts": result["zts"], "debug": result["debug"]}


def selected_subject_schema(normalization_targets, selected):
    schema = selected
    if schema is None:
        schema = NORMALIZED_SUBJECT_SCHEMA if normalization_targets is not None else SUBJECT_SCHEMA
    if schema not in (SUBJECT_SCHEMA, NORMALIZED_SUBJECT_SCHEMA):
        raise ValueError('Unknown installed subject representation')
    if schema == NORMALIZED_SUBJECT_SCHEMA and normalization_targets is None:
        raise ValueError('Subject references require the complete normalization authority')
    return schema


def subject_record(name, expected, php, configuration, normalization_targets, *, subject_schema=None):
    schema = selected_subject_schema(normalization_targets, subject_schema)
    authority = ({"kind": "derived-redis", "member": name}
                 if name == f"etc/php/{php}/mods-available/redis.ini"
                 else {"kind": "archive", "member": name})
    if configuration is not None and name in configuration['outputs']:
        authority = {'kind': 'derived-cli-configuration', 'member': name,
                     'recipe': configuration['schema']}
    elif normalization_targets is not None and name in normalization_targets:
        origin = normalization_targets[name]
        if expected != {key: origin[key] for key in ('size', 'sha256')}:
            raise ValueError('Normalized subject differs from its original contained target')
        authority = {'kind': 'normalized-archive', 'member': name,
            'source_member': origin['target'], 'target_size': origin['size'],
            'target_sha256': origin['sha256'],
            'target_metadata_sha256': bootstrap.sha256(json.dumps(origin['metadata'], sort_keys=True,
                separators=(',', ':')).encode())}
    # V2 indexes the complete sealed document by the canonical file key.
    # V1's historical representation retains its full duplicate target proof.
    if schema == NORMALIZED_SUBJECT_SCHEMA and authority['kind'] in ('archive', 'normalized-archive'):
        authority = {'kind': authority['kind']}
    return {"type": "regular", **expected, "authority": authority}


def capture_subjects(files, php, required, *, root=Path("/"), read=None, resolve=None,
                     command_path=None, normalization_targets=None, configuration=None,
                     subject_schema=None, **checks):
    """Producer manifest: each file identity comes from held archive/derived bytes."""
    schema = selected_subject_schema(normalization_targets, subject_schema)
    manifest = {"schema": schema, "files": {}, "commands": {}, "configs": {}}
    configs = configuration_members(files, php)
    if configuration is not None:
        configs.update(configuration['outputs'])
    native_read = read or (lambda path: (path.lstat(), path.read_bytes()))
    native_resolve = resolve or (lambda path: path.resolve(strict=True))
    native_command = command_path or (
        lambda name: Path(shutil.which(name, path=os.environ["PATH"]) or "/missing-command").resolve())

    def canonical(path):
        return "/" + path.relative_to(root).as_posix()

    def observed_read(path):
        name = path.relative_to(root).as_posix()
        expected = configs.get(name)
        if expected is None:
            raise ValueError("Subject lacks held-archive/derived authority")
        metadata, contents = native_read(path)
        verify_file(path, expected, lambda _: (metadata, contents))
        manifest["files"][canonical(path)] = subject_record(name, expected, php, configuration,
            normalization_targets, subject_schema=schema)
        return metadata, contents

    def observed_resolve(path):
        target = native_resolve(path)
        manifest["configs"][canonical(path)] = canonical(target)
        return target

    def observed_command(name):
        target = native_command(name)
        manifest["commands"][name] = canonical(target)
        return target

    installed = verify_installed(files, php, required, root=root, read=observed_read,
        resolve=observed_resolve, command_path=observed_command, configuration=configuration, **checks)
    if configuration is not None:
        for name in configuration['outputs']:
            if '/' + name not in manifest['files']:
                observed_read(root / name)
    require_subject_bound(manifest)
    return installed, manifest


def require_subject_bound(manifest):
    if len(manifest["files"]) > 256 or len(json.dumps(manifest, sort_keys=True).encode()) > MAX_SUBJECT_BYTES:
        raise ValueError("Installed subject manifest exceeds the bounded profile")


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
