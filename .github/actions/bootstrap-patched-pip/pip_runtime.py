"""Seed and verify a job-private pip runtime without changing the selected manager."""

from __future__ import annotations

import base64
import contextlib
import csv
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import subprocess
import sys
import zipfile


VERSION = "26.2.2"
WHEEL_NAME = "pip-26.2.2-py3-none-any.whl"
WHEEL_URL = "https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/" + WHEEL_NAME
WHEEL_SHA256 = "fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70"
WHEEL_SIZE = 1819850
CA_SHA256 = "50f79f98dac192b20dbf73f35c56f0b0c557ab267ff5199d1117cc1180b70785"
DIST_INFO = "pip-26.2.2.dist-info"
RUNTIME_RECEIPT = "runtime.json"
HASH_PREFIX = "sha256="
PIP_MODULE = "pip/__init__.py"
CERTIFI_CA = "pip/_vendor/certifi/cacert.pem"
VENV_CONFIG = "pyvenv.cfg"
SCM_IGNORE = ".gitignore"
MAX_FILE = 16 * 1024 * 1024
MAX_FILES = 8192
MAX_TREE = 64 * 1024 * 1024
CLEAN_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
             "PIP_CONFIG_FILE": "/dev/null", "PYTHONDONTWRITEBYTECODE": "1"}


def _identity(metadata):
    return {"device": metadata.st_dev, "inode": metadata.st_ino, "mode": stat.S_IMODE(metadata.st_mode),
            "owner": metadata.st_uid, "links": metadata.st_nlink, "size": metadata.st_size,
            "mtime_ns": metadata.st_mtime_ns, "ctime_ns": metadata.st_ctime_ns}


def directory_identity(metadata):
    return {"device": metadata.st_dev, "inode": metadata.st_ino,
            "owner": metadata.st_uid, "mode": stat.S_IMODE(metadata.st_mode)}


class RuntimeState:
    """Transfer the producer's exact allocation identity without another lookup."""

    def __init__(self, root, identity):
        self.root = root
        self.identity = identity

    @property
    def receipt(self):
        return self.root / RUNTIME_RECEIPT


def absolute_path(value):
    path = Path(value)
    if any(c in str(path) for c in "\r\n\x00"):
        raise ValueError("Runtime paths must not contain line breaks or NUL")
    if (not path.is_absolute() or str(path) != str(value) or str(value).startswith("//")
            or any(part in {".", ".."} for part in str(value).split("/"))):
        raise ValueError("Runtime path must be absolute and canonical")
    return path


class BoundDirectory:
    """Keep every parent descriptor open; writes use the held final directory."""

    def __init__(self, path, *, private=False):
        self.path = absolute_path(path)
        self.chain = []
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        self.chain.append((None, "/", descriptor))
        try:
            for part in self.path.parts[1:]:
                child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                self.chain.append((descriptor, part, child))
                metadata = os.fstat(child)
                sticky_root = metadata.st_uid == 0 and metadata.st_mode & stat.S_ISVTX
                if metadata.st_uid not in {0, os.getuid()} or (metadata.st_mode & 0o022 and not sticky_root):
                    raise ValueError(f"Runtime directory refused: path={self.path.anchor + '/'.join(self.path.parts[1:len(self.chain)])} "
                                     f"uid={metadata.st_uid} mode={stat.S_IMODE(metadata.st_mode):04o}")
                descriptor = child
            self.fd = descriptor
            metadata = os.fstat(self.fd)
            if private and (metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700):
                raise ValueError("Private runtime directory must be owned and mode0700")
            self.expected = {fd: (s.st_dev, s.st_ino, s.st_uid, stat.S_IMODE(s.st_mode))
                             for _parent, _name, fd in self.chain for s in [os.fstat(fd)]}
            self.check()
        except BaseException:
            self.close()
            raise

    def check(self):
        for parent, name, descriptor in self.chain:
            held = os.fstat(descriptor)
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(current.st_mode) or (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino):
                raise ValueError("Held runtime directory identity changed")
            if (current.st_dev, current.st_ino, current.st_uid, stat.S_IMODE(current.st_mode)) != self.expected[descriptor]:
                raise ValueError("Held runtime directory permissions changed")

    def close(self):
        for _parent, _name, descriptor in reversed(self.chain):
            os.close(descriptor)
        self.chain = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def create(self, name, data, mode=0o600):
        if name != Path(name).name or name in {".", ".."}:
            raise ValueError("Runtime file name must be one segment")
        self.check()
        descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=self.fd)
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            os.fchmod(output.fileno(), mode)
        self.check()
        return self.path / name


@contextlib.contextmanager
def held_file(path, *, maximum=MAX_FILE, owned=False, executable=False):
    path = absolute_path(path)
    with BoundDirectory(path.parent) as parent:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent.fd)
        try:
            before = os.fstat(descriptor)
            owners = {os.getuid()} if owned else {0, os.getuid()}
            if (not stat.S_ISREG(before.st_mode) or before.st_uid not in owners or before.st_nlink != 1
                    or before.st_mode & 0o022 or before.st_size > maximum
                    or executable and not before.st_mode & 0o111):
                raise ValueError("Runtime subject must be a regular file with valid owner/mode/link/size")
            data = b""
            while len(data) <= maximum:
                chunk = os.read(descriptor, min(65536, maximum + 1 - len(data)))
                if not chunk:
                    break
                data += chunk
            after = os.fstat(descriptor)
            current = os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)
            if (len(data) > maximum or _identity(before) != _identity(after)
                    or (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino)):
                raise ValueError("Runtime subject changed while held")
            parent.check()
            yield data, {**_identity(after), "sha256": hashlib.sha256(data).hexdigest()}
            parent.check()
            current = os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)
            if (_identity(os.fstat(descriptor)) != _identity(after)
                    or (current.st_dev, current.st_ino) != (after.st_dev, after.st_ino)):
                raise ValueError("Held runtime subject identity changed")
        finally:
            os.close(descriptor)


def append_github_file(path, contents, runner_temp):
    with github_file(path, runner_temp) as append:
        append(contents)


@contextlib.contextmanager
def github_file(path, runner_temp):
    path = absolute_path(path)
    path.relative_to(absolute_path(runner_temp))
    with BoundDirectory(path.parent) as parent:
        parent.check()
        descriptor = os.open(path.name, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent.fd)
        try:
            before = os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1
                    or before.st_mode & 0o022 or before.st_size > 1024 * 1024):
                raise ValueError("GitHub command file identity is invalid")
            def append(contents):
                nonlocal before
                parent.check()
                current = os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
                    raise ValueError("GitHub command file was redirected before writing")
                payload = contents.encode("utf-8")
                if len(payload) > 65536 or os.write(descriptor, payload) != len(payload):
                    raise ValueError("GitHub command output exceeded its bound")
                parent.check()
                current = os.stat(path.name, dir_fd=parent.fd, follow_symlinks=False)
                after = os.fstat(descriptor)
                if ((current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
                        or (after.st_uid, after.st_mode, after.st_nlink) != (before.st_uid, before.st_mode, before.st_nlink)
                        or after.st_size != before.st_size + len(payload)):
                    raise ValueError("GitHub command file was redirected")
                before = after
            yield append
        finally:
            os.close(descriptor)


def _wheel_files(contents):
    files = {}
    with zipfile.ZipFile(io.BytesIO(contents)) as archive:
        total = 0
        for member in archive.infolist():
            name = member.filename
            path = PurePosixPath(name)
            kind = stat.S_IFMT(member.external_attr >> 16)
            if (member.is_dir() or name in files or str(path) != name or path.is_absolute()
                    or any(part in {".", ".."} for part in path.parts)
                    or not name.startswith(("pip/", DIST_INFO + "/"))
                    or kind not in {0, stat.S_IFREG} or member.file_size > MAX_FILE):
                raise ValueError("Wheel has a foreign, aliased or special member")
            total += member.file_size
            if len(files) >= MAX_FILES or total > MAX_TREE:
                raise ValueError("Wheel inventory exceeds its bound")
            files[name] = archive.read(member)
    return files


def _wheel_inventory(contents):
    """Parse only data from an already authenticated wheel."""
    files = _wheel_files(contents)
    record_name = DIST_INFO + "/RECORD"
    if record_name not in files:
        raise ValueError("Wheel RECORD is missing")
    rows = {}
    for row in csv.reader(io.StringIO(files[record_name].decode("utf-8"))):
        if len(row) != 3 or row[0] in rows or row[0] not in files:
            raise ValueError("Wheel RECORD has an unexpected or duplicate entry")
        rows[row[0]] = row
    if set(rows) != set(files) or rows[record_name][1:] != ["", ""]:
        raise ValueError("Wheel RECORD is incomplete or self-hashed")
    for name, data in files.items():
        if name == record_name:
            continue
        expected = HASH_PREFIX + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip("=")
        if rows[name][1:] != [expected, str(len(data))]:
            raise ValueError("Wheel member does not match its RECORD")
    metadata = files.get(DIST_INFO + "/METADATA", b"").decode("utf-8")
    if (re.findall(r"^Name: (.+)$", metadata, re.M) != ["pip"]
            or re.findall(r"^Version: (.+)$", metadata, re.M) != [VERSION]):
        raise ValueError("Wheel distribution identity is not the authorized pip version")
    if CERTIFI_CA not in files or PIP_MODULE not in files:
        raise ValueError("Wheel module or vendored certifi origin is missing")
    return files


def authenticated_wheel(path):
    with held_file(path, maximum=WHEEL_SIZE, owned=True) as (contents, identity):
        if len(contents) != WHEEL_SIZE or identity["sha256"] != WHEEL_SHA256:
            raise ValueError("Private wheel does not match the authorized exact bytes")
        files = _wheel_inventory(contents)
        if hashlib.sha256(files[CERTIFI_CA]).hexdigest() != CA_SHA256:
            raise ValueError("Vendored CA does not match its reviewed authority")
        return files, identity


def _walk_error(error):
    raise error


def _tree_files(directory, *, owned=False):
    """Inventory files without following links or accepting special entries."""
    result = {}
    total = 0
    for current, directories, names in os.walk(directory, followlinks=False, onerror=_walk_error):
        with BoundDirectory(Path(current)) as held:
            if owned and os.fstat(held.fd).st_uid != os.getuid():
                raise ValueError("Private module directory is not job-owned")
            for name in directories:
                if (Path(current) / name).is_symlink():
                    raise ValueError("Runtime module directory redirects through a symlink")
            for name in names:
                path = Path(current) / name
                with held_file(path, owned=owned) as (_contents, identity):
                    total += identity["size"]
                    if len(result) >= MAX_FILES or total > MAX_TREE:
                        raise ValueError("Runtime module inventory exceeds its bound")
                    result[str(path.relative_to(directory))] = identity
    return result


def closed_directories(directory, expected_names):
    expected = {str(parent) for name in expected_names for parent in PurePosixPath(name).parents if str(parent) != "."}
    actual = set()
    for current, directories, _files in os.walk(directory, followlinks=False, onerror=_walk_error):
        for name in directories:
            path = Path(current) / name
            with BoundDirectory(path) as held:
                if os.fstat(held.fd).st_uid != os.getuid():
                    raise ValueError("Private module directory is not job-owned")
            actual.add(str(path.relative_to(directory)))
    if actual != expected:
        raise ValueError("Private pip directory inventory is not closed")


PYTHON_PROBE = r'''
import json,pathlib,site,sys,sysconfig
executable=pathlib.Path(sys.executable)
prefix=executable.parent.parent
roots=site.getsitepackages([str(prefix)]) if (prefix/'pyvenv.cfg').is_file() else site.getsitepackages()
print(json.dumps({'executable':str(executable),'version':list(sys.version_info[:3]),
 'base_executable':str(pathlib.Path(sys._base_executable).resolve()),'roots':roots}))
'''


def selected_interpreter(path, execute=subprocess.run):
    path = absolute_path(path)
    canonical = path.resolve(strict=True)
    location = os.environ.get("pythonLocation")
    if location:
        if re.fullmatch(r"/opt/hostedtoolcache/Python/\d+\.\d+\.\d+/(?:x64|arm64)", location) is None:
            raise ValueError("Selected setup-python location is not a reviewed hosted runtime")
        expected = absolute_path(location) / "bin/python"
        if canonical != expected.resolve(strict=True):
            raise ValueError("Selected Python does not match the existing setup-python selection")
    elif canonical.parent != Path("/usr/bin") or re.fullmatch(r"python3(?:\.\d+)?", canonical.name) is None:
        raise ValueError("Host-default Python is outside its reviewed system location")
    loader = selected_loader(location)
    environment = dict(CLEAN_ENV, **({"LD_LIBRARY_PATH": loader["path"]} if loader else {}))
    with BoundDirectory(path.parent) as alias_parent, \
            held_file(canonical, maximum=64 * 1024 * 1024, executable=True) as (_data, identity):
        alias = _identity(path.lstat())
        if alias["owner"] not in {0, os.getuid()}:
            raise ValueError("Selected Python alias has an untrusted owner")
        response = execute([str(path), "-I", "-S", "-B", "-c", PYTHON_PROBE],
                           env=environment, capture_output=True, text=True, timeout=10, check=True)
        alias_parent.check()
        if _identity(path.lstat()) != alias or path.resolve(strict=True) != canonical:
            raise ValueError("Selected Python alias changed while held")
    probe = json.loads(response.stdout)
    if (probe["executable"] != str(path) or probe["base_executable"] != str(canonical)
            or probe["version"][0] != 3 or tuple(probe["version"]) < (3, 10, 0)):
        raise ValueError("Selected Python runtime identity is unsupported")
    if location and ".".join(map(str, probe["version"])) != Path(location).parent.name:
        raise ValueError("Selected Python version differs from its exact setup-python location")
    return {**probe, "canonical": str(canonical), "identity": identity, "loader": loader}


def selected_loader(location):
    """Use only the selected hosted Python's held library directory, never an ambient chain."""
    if not location:
        return None
    directory = absolute_path(location) / "lib"
    files = {}
    with BoundDirectory(directory):
        for path in sorted(directory.glob("lib*.so*")):
            target = path.resolve(strict=True)
            if target.parent != directory:
                raise ValueError("Selected Python library link escapes its exact directory")
            with held_file(target, maximum=64 * 1024 * 1024) as (_data, identity):
                files[path.name] = {"target": str(target), "link": os.readlink(path) if path.is_symlink() else None,
                                    "identity": identity}
    if not files:
        raise ValueError("Selected hosted Python has no bound shared library")
    return {"path": str(directory), "files": files}


def manager_snapshot(interpreter):
    candidates = []
    for value in interpreter["roots"]:
        root = absolute_path(value)
        if not (root / PIP_MODULE).exists():
            continue
        with BoundDirectory(root):
            directory, version = manager_distribution(root)
            candidates.append({"root": str(root), "version": version, "distribution": str(directory),
                "module_files": _tree_files(root / "pip"), "metadata_files": _tree_files(directory)})
    if len(candidates) != 1:
        raise ValueError("Manager pip has no single bound module/distribution origin")
    return candidates[0]


def manager_distribution(root):
    metadata = []
    for entry in root.glob("pip-*.dist-info"):
        with held_file(entry / "METADATA") as (contents, _):
            text = contents.decode("utf-8")
        if re.findall(r"^Name: (.+)$", text, re.M) == ["pip"]:
            versions = re.findall(r"^Version: (.+)$", text, re.M)
            if len(versions) != 1 or not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", versions[0]):
                raise ValueError("Manager pip version is ambiguous")
            metadata.append((entry, versions[0]))
    if len(metadata) != 1:
        raise ValueError("Manager pip distribution is missing or ambiguous")
    directory, version = metadata[0]
    if tuple(map(int, version.split(".")[:2])) < (22, 3):
        raise ValueError("Manager pip does not support the reviewed --python primitive")
    return directory, version


MANAGER_MAIN = """import sys
sys.path.insert(0,sys.argv.pop(1))
from pip._internal.cli.main import main
raise SystemExit(main())
"""


def manager_command(interpreter, manager, arguments, environment, *, execute=subprocess.run):
    result = execute([interpreter["executable"], "-I", "-S", "-B", "-c", MANAGER_MAIN,
                      manager["root"], "--isolated", "--no-cache-dir", "--disable-pip-version-check", "--no-input",
                      *arguments], env=environment, cwd=environment["HOME"],
                     capture_output=True, text=True, timeout=90, check=True)
    if len(result.stdout.encode()) + len(result.stderr.encode()) > 65536:
        raise ValueError("Manager pip output exceeded its bound")
    return result


def private_environment(root, interpreter=None):
    environment = dict(CLEAN_ENV, HOME=str(root / "home"), TMPDIR=str(root / "tmp"))
    if interpreter and interpreter["loader"]:
        environment["LD_LIBRARY_PATH"] = interpreter["loader"]["path"]
    return environment


def _private_root(runner_temp):
    runner_temp = absolute_path(runner_temp)
    with BoundDirectory(runner_temp) as parent:
        if os.fstat(parent.fd).st_uid != os.getuid():
            raise ValueError("RUNNER_TEMP is not owned by the job user")
        name = "dw-pip-" + secrets.token_hex(16)
        parent.check()
        root = runner_temp / name
        created = False
        identity = None
        try:
            os.mkdir(name, 0o700, dir_fd=parent.fd)
            created = True
            identity = directory_identity(os.stat(name, dir_fd=parent.fd, follow_symlinks=False))
            with BoundDirectory(root, private=True) as directory:
                if os.listdir(directory.fd):
                    raise ValueError("New private runtime is not empty")
                for child in ("home", "tmp", "downloads"):
                    os.mkdir(child, 0o700, dir_fd=directory.fd)
                directory.check()
        except BaseException:
            if created:
                # The held parent plus successful no-replace mkdir owns this
                # fresh name even when the first metadata observation fails.
                if identity is None:
                    # No child contents have been created yet. Removal needs
                    # no second lookup of the metadata that just failed.
                    os.rmdir(name, dir_fd=parent.fd)
                    if name in os.listdir(parent.fd):
                        raise ValueError("Empty private allocation cleanup did not remove its exact name")
                    parent.check()
                else:
                    parent.check()
                    cleanup_runtime(root, runner_temp, identity)
            raise
        return RuntimeState(root, identity)


def venv_layout(root, interpreter):
    environment = root / "environment"
    private_python = environment / "bin/python"
    with held_file(environment / VENV_CONFIG, maximum=8192, owned=True) as (contents, _):
        values = {}
        for line in contents.decode("utf-8").splitlines():
            key, separator, value = line.partition(" = ")
            if not separator or key in values or key not in {"home", "include-system-site-packages", "version", "executable", "command"}:
                raise ValueError("Private pyvenv.cfg has an unexpected field")
            values[key] = value
    if (values.get("include-system-site-packages") != "false"
            or values.get("version") != ".".join(map(str, interpreter["version"]))
            or Path(values.get("home", "")).resolve() != Path(interpreter["canonical"]).parent
            or values.get("executable", interpreter["canonical"]) != interpreter["canonical"]):
        raise ValueError("Private interpreter configuration changed its bound origin")
    with BoundDirectory(environment), BoundDirectory(private_python.parent):
        if private_python.resolve(strict=True) != Path(interpreter["canonical"]):
            raise ValueError("Private Python link escaped its selected interpreter")
        for name in python_aliases(interpreter):
            path = private_python.parent / name
            if not path.is_symlink() or path.resolve(strict=True) != Path(interpreter["canonical"]):
                raise ValueError("Private interpreter has a foreign Python link")
    major, minor = interpreter["version"][:2]
    purelib = environment / f"lib/python{major}.{minor}/site-packages"
    with BoundDirectory(purelib):
        return private_python, purelib


def python_aliases(interpreter):
    aliases = {"python", "python3", f"python3.{interpreter['version'][1]}"}
    # CPython 3.14's stock venv adds this exact alias to the same interpreter.
    if tuple(interpreter["version"]) >= (3, 14, 0):
        aliases.add("𝜋thon")
    return aliases


def venv_baseline(root, interpreter):
    python, purelib = venv_layout(root, interpreter)
    environment = root / "environment"
    expected = {"bin", "include", "lib", "lib64", VENV_CONFIG}
    if tuple(interpreter["version"]) >= (3, 13, 0):
        expected.add(SCM_IGNORE)
    if set(os.listdir(environment)) != expected:
        raise ValueError("Private environment has an unexpected top-level entry")
    alias = environment / "lib64"
    if not alias.is_symlink() or os.readlink(alias) != "lib":
        raise ValueError("Private environment lib64 alias changed")
    result = {}
    generated = [environment / VENV_CONFIG, *(python.parent / name for name in
                 ("activate", "activate.csh", "activate.fish", "Activate.ps1"))]
    if SCM_IGNORE in expected:
        generated.append(environment / SCM_IGNORE)
    for path in generated:
        with held_file(path, owned=True) as (_contents, identity):
            result[str(path.relative_to(environment))] = identity
    result["links"] = {name: {"target": os.readlink(python.parent / name),
                              "identity": _identity((python.parent / name).lstat())}
                       for name in python_aliases(interpreter)}
    result["lib64"] = {"target": "lib", "identity": _identity(alias.lstat())}
    with BoundDirectory(environment / "include") as include:
        # Stock venv may create a single empty versioned include directory.
        for name in os.listdir(include.fd):
            if name != f"python{interpreter['version'][0]}.{interpreter['version'][1]}":
                raise ValueError("Private environment include directory has an unexpected entry")
            with BoundDirectory(environment / "include" / name) as child:
                if os.listdir(child.fd):
                    raise ValueError("Private environment include directory is not empty")
    if set(os.listdir(purelib.parent)) != {"site-packages"}:
        raise ValueError("Private environment has a foreign module search root")
    return result


def unique_pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Runtime JSON contains a duplicate key")
        value[key] = item
    return value


def _read_json(path):
    with held_file(path, maximum=MAX_FILE, owned=True) as (contents, _):
        return json.loads(contents, object_pairs_hook=unique_pairs)


def create_runtime(selected, runner_temp, *, execute=subprocess.run):
    interpreter = selected_interpreter(selected, execute)
    manager = manager_snapshot(interpreter)
    state = _private_root(runner_temp)
    try:
        _seed_runtime(state.root, interpreter, manager, expected_identity=state.identity, execute=execute)
        return state
    except BaseException:
        cleanup_runtime(state.root, runner_temp, state.identity)
        raise


def cleanup_runtime(root, runner_temp, expected_identity):
    root = absolute_path(root)
    if root.parent != absolute_path(runner_temp) or re.fullmatch(r"dw-pip-[0-9a-f]{32}", root.name) is None:
        raise ValueError("Cleanup is outside the exact private pip state")
    with BoundDirectory(root.parent) as parent, BoundDirectory(root, private=True) as held:
        if directory_identity(os.fstat(held.fd)) != expected_identity:
            raise ValueError("Cleanup private runtime identity changed")
        # Stock rmtree uses directory descriptors and never follows a link.
        if not shutil.rmtree.avoids_symlink_attacks:
            raise ValueError("This platform has no descriptor-safe private cleanup")
        for _directory, _children, _files, descriptor in os.fwalk(root, follow_symlinks=False):
            if os.fstat(descriptor).st_uid != os.getuid():
                raise ValueError("Cleanup encountered an unowned private directory")
            os.fchmod(descriptor, 0o700)
        held.check()
        shutil.rmtree(root.name, dir_fd=parent.fd)
        parent.check()
        if os.path.lexists(root):
            raise ValueError("Private pip cleanup did not remove its exact state")


def _seed_runtime(root, interpreter, manager, *, expected_identity, execute):
    environment = private_environment(root, interpreter)
    with BoundDirectory(root, private=True) as held:
        if directory_identity(os.fstat(held.fd)) != expected_identity:
            raise ValueError("New private runtime changed before seeding")
        execute([interpreter["executable"], "-I", "-S", "-B", "-m", "venv", "--without-pip",
                 "--symlinks", str(root / "environment")], env=environment,
                capture_output=True, text=True, timeout=30, check=True)
        private_python, purelib = venv_layout(root, interpreter)
        if os.listdir(purelib):
            raise ValueError("New private Python site-packages is not empty")
        baseline = venv_baseline(root, interpreter)
        manager_command(interpreter, manager, ["download", "--no-index", "--no-deps", "--only-binary=:all:",
            "--retries", "0", "--timeout", "15", "--progress-bar", "off", "--dest", str(root / "downloads"),
            "pip @ " + WHEEL_URL + "#sha256=" + WHEEL_SHA256], environment, execute=execute)
        wheel = root / "downloads" / WHEEL_NAME
        if sorted(path.name for path in wheel.parent.iterdir()) != [WHEEL_NAME]:
            raise ValueError("Private wheel acquisition has unexpected entries")
        _files, wheel_identity = authenticated_wheel(wheel)
        manager_command(interpreter, manager, ["--python", str(private_python), "install", "--no-index",
            "--no-deps", "--only-binary=:all:", "--no-compile", "--prefix", str(root / "environment"),
            "pip @ " + wheel.as_uri() + "#sha256=" + WHEEL_SHA256], environment, execute=execute)
        if manager_snapshot(interpreter) != manager:
            raise ValueError("Manager pip changed while seeding the private runtime")
        if venv_baseline(root, interpreter) != baseline:
            raise ValueError("Private environment baseline changed while seeding pip")
        validate_install(root, interpreter, _files, initial=True)
        freeze_pip(root, interpreter)
        os.chmod(wheel, 0o400)
        _files, wheel_identity = authenticated_wheel(wheel)
        held.check()
        report = {"schema": "durable-workflow.private-pip/v1", "root": str(root),
            "root_identity": directory_identity(os.fstat(held.fd)),
            "venv_baseline": baseline,
            "interpreter": interpreter, "manager": manager, "python": str(private_python),
            "purelib": str(purelib), "wheel": str(wheel), "wheel_identity": wheel_identity}
        held.create(RUNTIME_RECEIPT, (json.dumps(report, sort_keys=True) + "\n").encode())
    return root / RUNTIME_RECEIPT


SCRIPT_BODY_OLD = r'''# -*- coding: utf-8 -*-
import re
import sys
from pip._internal.cli.main import main
if __name__ == '__main__':
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
'''
SCRIPT_BODY_CURRENT = r'''# -*- coding: utf-8 -*-
import re
import sys
if __name__ == '__main__':
    from pip._internal.cli.main import main
    sys.argv[0] = re.sub(r'(-script\.pyw|\.exe)?$', '', sys.argv[0])
    sys.exit(main())
'''


def _entrypoint(path, private_python):
    with held_file(path, maximum=8192, owned=True, executable=True) as (contents, identity):
        header = ("#!" + str(private_python) + "\n").encode()
        expected = {header + source.encode() for source in (SCRIPT_BODY_OLD, SCRIPT_BODY_CURRENT)}
        if contents not in expected:
            raise ValueError("Private pip entrypoint is not the bound stock script/shebang")
    return contents, identity


def _record_path(purelib, value):
    if "\\" in value or "\x00" in value or PurePosixPath(value).is_absolute():
        raise ValueError("Installed RECORD path is not relative")
    result = Path(os.path.abspath(purelib / value))
    if os.path.relpath(result, purelib) != value:
        raise ValueError("Installed RECORD path is not canonical")
    return result


def validate_install(root, interpreter, wheel_files, *, initial=False):
    private_python, purelib = venv_layout(root, interpreter)
    if initial and set(os.listdir(purelib)) != {"pip", DIST_INFO}:
        raise ValueError("Private pip target has unexpected entries")
    if any(path.suffix == ".pth" or path.name.startswith(("sitecustomize", "usercustomize")) for path in purelib.iterdir()):
        raise ValueError("Private Python site contains an unbound startup hook")
    expected_files = {}
    record = DIST_INFO + "/RECORD"
    for name, expected in wheel_files.items():
        if name == record:
            continue
        path = purelib / name
        with held_file(path, owned=True) as (contents, identity):
            if contents != expected:
                raise ValueError("Installed pip module/data differs from its authenticated wheel")
            expected_files[path] = identity
    expected_files.update(installed_provenance(root, purelib, private_python, interpreter, initial=initial))
    validate_pip_inventory(purelib, expected_files)
    expected_files[purelib / record] = validate_installed_record(purelib, record, expected_files)
    return {str(path): identity for path, identity in expected_files.items()}


def installed_provenance(root, purelib, private_python, interpreter, *, initial):
    expected_files = {}
    extra = {DIST_INFO + "/INSTALLER": b"pip\n", DIST_INFO + "/REQUESTED": b""}
    for name, expected in extra.items():
        path = purelib / name
        with held_file(path, owned=True) as (contents, identity):
            if contents != expected:
                raise ValueError("Private pip installer metadata is not the stock value")
            expected_files[path] = identity
    direct = purelib / DIST_INFO / "direct_url.json"
    expected_direct = {"url": (root / "downloads" / WHEEL_NAME).as_uri(), "archive_info": {
        "hash": HASH_PREFIX + WHEEL_SHA256, "hashes": {"sha256": WHEEL_SHA256}}}
    if _read_json(direct) != expected_direct:
        raise ValueError("Private pip provenance does not bind the authorized held wheel")
    with held_file(direct, owned=True) as (_contents, identity):
        expected_files[direct] = identity
    minor = interpreter["version"][1]
    scripts = {"pip", "pip3", f"pip3.{minor}"}
    permitted_bin = scripts | python_aliases(interpreter) | {
        "activate", "activate.csh", "activate.fish", "Activate.ps1"}
    entries = set(os.listdir(private_python.parent))
    if (initial and entries != permitted_bin or not permitted_bin <= entries
            or any(name.startswith(("pip.", "sitecustomize", "usercustomize")) for name in entries)):
        raise ValueError("Private interpreter bin directory has unexpected entries")
    for name in scripts:
        path = private_python.parent / name
        _contents, identity = _entrypoint(path, private_python)
        expected_files[path] = identity
    return expected_files


def validate_pip_inventory(purelib, expected_files):
    for subdirectory in ("pip", DIST_INFO):
        actual = _tree_files(purelib / subdirectory, owned=True)
        expected_names = {str(path.relative_to(purelib / subdirectory))
                          for path in expected_files if path.is_relative_to(purelib / subdirectory)}
        if subdirectory == DIST_INFO:
            expected_names.add("RECORD")
        if set(actual) != expected_names:
            raise ValueError("Private pip module/dist-info inventory is not closed")
        closed_directories(purelib / subdirectory, expected_names)


def validate_installed_record(purelib, record, expected_files):
    with held_file(purelib / record, owned=True) as (contents, record_identity):
        rows = {}
        for row in csv.reader(io.StringIO(contents.decode("utf-8"))):
            if len(row) != 3:
                raise ValueError("Installed RECORD row is malformed")
            path = _record_path(purelib, row[0])
            if path in rows or path not in set(expected_files) | {purelib / record}:
                raise ValueError("Installed RECORD has a foreign or duplicate subject")
            rows[path] = row[1:]
        if set(rows) != set(expected_files) | {purelib / record} or rows[purelib / record] != ["", ""]:
            raise ValueError("Installed RECORD is incomplete or self-hashed")
        for path, identity in expected_files.items():
            digest = base64.urlsafe_b64encode(bytes.fromhex(identity["sha256"])).decode().rstrip("=")
            if rows[path] != [HASH_PREFIX + digest, str(identity["size"])]:
                raise ValueError("Installed RECORD does not bind its actual subject")
    return record_identity


def freeze_pip(root, interpreter):
    python, purelib = venv_layout(root, interpreter)
    for name in ("pip", DIST_INFO):
        for directory, _children, files in os.walk(purelib / name, topdown=False, onerror=_walk_error):
            for filename in files:
                os.chmod(Path(directory) / filename, 0o400)
            os.chmod(directory, 0o500)
    for name in ("pip", "pip3", f"pip3.{interpreter['version'][1]}"):
        os.chmod(python.parent / name, 0o500)


ORIGIN_PROBE = r'''
import json,pathlib,sys
root=pathlib.Path(sys.argv[1])
sys.path.insert(0,str(root))
import pip
from pip._vendor import certifi
print(json.dumps({'python':sys.executable,'version':pip.__version__,
 'module':str(pathlib.Path(pip.__file__).resolve()),'certifi':str(pathlib.Path(certifi.__file__).resolve()),
 'ca':str(pathlib.Path(certifi.where()).resolve())}))
'''


def verify_runtime(path, runner_temp, *, execute=subprocess.run, initial=False, require_trust=False):
    path = absolute_path(path)
    root, _identity = runtime_root(path, runner_temp)
    with BoundDirectory(root, private=True):
        report = _read_json(path)
        if (set(report) != {"schema", "root", "root_identity", "venv_baseline", "interpreter", "manager", "python", "purelib", "wheel", "wheel_identity"}
                or report["schema"] != "durable-workflow.private-pip/v1" or report["root"] != str(root)):
            raise ValueError("Runtime receipt is not the closed producer schema")
        if report["root_identity"] != directory_identity(root.stat(follow_symlinks=False)):
            raise ValueError("Private runtime directory differs from its producer identity")
        interpreter = selected_interpreter(report["interpreter"]["executable"], execute)
        if interpreter != report["interpreter"] or manager_snapshot(interpreter) != report["manager"]:
            raise ValueError("Selected manager interpreter/pip identity changed")
        python, purelib = venv_layout(root, interpreter)
        if venv_baseline(root, interpreter) != report["venv_baseline"]:
            raise ValueError("Private environment generated-file identity changed")
        if report["python"] != str(python) or report["purelib"] != str(purelib) or report["wheel"] != str(root / "downloads" / WHEEL_NAME):
            raise ValueError("Private runtime path bindings changed")
        files, wheel_identity = authenticated_wheel(report["wheel"])
        if wheel_identity != report["wheel_identity"]:
            raise ValueError("Held wheel object identity changed")
        subjects = validate_install(root, interpreter, files, initial=initial)
        result = execute([str(python), "-I", "-S", "-B", "-c", ORIGIN_PROBE, str(purelib)],
            env=private_environment(root, interpreter), capture_output=True, text=True, timeout=10, check=True)
        origin = json.loads(result.stdout)
        expected = {"python": str(python), "version": VERSION, "module": str(purelib / PIP_MODULE),
            "certifi": str(purelib / "pip/_vendor/certifi/__init__.py"),
            "ca": str(purelib / CERTIFI_CA)}
        if origin != expected or validate_install(root, interpreter, files) != subjects:
            raise ValueError("Private pip/certifi module origin changed at use")
        if require_trust:
            verify_exported_trust(root)
        return report, subjects


def verify_exported_trust(root):
    trust = root / "durable-workflow-trust"
    with BoundDirectory(trust, private=True), BoundDirectory(trust / "no-additional-roots", private=True) as empty:
        if os.listdir(empty.fd):
            raise ValueError("Private exported additional-root directory is not empty")
        with held_file(trust / (CA_SHA256 + ".pem"), maximum=1024 * 1024, owned=True) as (_data, identity):
            if identity["sha256"] != CA_SHA256:
                raise ValueError("Exported CA clone changed its exact wheel authority")


def runtime_root(path, runner_temp):
    root = receipt_root(path, runner_temp)
    with BoundDirectory(root, private=True) as held:
        return root, directory_identity(os.fstat(held.fd))


def receipt_root(path, runner_temp):
    path = absolute_path(path)
    root = path.parent
    if path.name != RUNTIME_RECEIPT or root.parent != absolute_path(runner_temp) or re.fullmatch(r"dw-pip-[0-9a-f]{32}", root.name) is None:
        raise ValueError("Runtime receipt is outside its exact owned state")
    return root


def producer_state(path, identity, runner_temp):
    root = receipt_root(path, runner_temp)
    value = json.loads(identity, object_pairs_hook=unique_pairs)
    if (not isinstance(value, dict) or set(value) != {"device", "inode", "owner", "mode"}
            or any(type(number) is not int or number < 0 for number in value.values())
            or value["inode"] == 0 or value["owner"] != os.getuid() or value["mode"] != 0o700):
        raise ValueError("Producer allocation identity is not the closed owned schema")
    return RuntimeState(root, value)


def verify_active_origin(report, selected):
    if str(absolute_path(selected)) != report["python"] or shutil.which("python") != report["python"]:
        raise ValueError("Later Python client fell back outside the private runtime")
    expected = str(Path(report["python"]).parent / "pip")
    if shutil.which("pip") != expected or os.environ.get("PYTHONPATH") != report["purelib"]:
        raise ValueError("Later pip client/module path fell back outside the private runtime")
    if os.environ.get("PYTHONHOME") or os.environ.get("PYTHONNOUSERSITE") != "1":
        raise ValueError("Later Python client has an ambient home/user-site override")
    loader = report["interpreter"]["loader"]
    expected_loader = loader["path"] if loader else ""
    actual_loader = os.environ.get("TRUST_CALLER_LD_LIBRARY_PATH", os.environ.get("LD_LIBRARY_PATH", ""))
    if actual_loader != expected_loader:
        raise ValueError("Later Python client has an unbound loader search path")
    if os.environ.get("LD_PRELOAD") or os.environ.get("LD_AUDIT"):
        raise ValueError("Later Python client has an ambient loader hook")


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in {"bootstrap", "verify"}:
        raise ValueError("Select only the bootstrap or read-only verification operation")
    os.umask(0o077)
    operation, selected = sys.argv[1:]
    runner_temp = absolute_path(os.environ["RUNNER_TEMP"])
    created = None
    try:
        with github_file(os.environ["GITHUB_ENV"], runner_temp) as append_env, \
                github_file(os.environ["GITHUB_OUTPUT"], runner_temp) as append_output, \
                github_file(os.environ["GITHUB_PATH"], runner_temp) as append_path:
            existing = os.environ.get("DW_CI_PIP_STATE")
            if operation == "verify" and not existing:
                raise ValueError("Private pip verification has no explicit producer receipt")
            if existing:
                path = absolute_path(existing)
                report, _subjects = verify_runtime(path, runner_temp, require_trust=True)
                verify_active_origin(report, selected)
            else:
                created = create_runtime(selected, runner_temp)
                path = created.receipt
                report, _subjects = verify_runtime(path, runner_temp, initial=True)
            if operation == "bootstrap":
                append_path(str(Path(report["python"]).parent) + "\n")
                append_env(f"DW_CI_PIP_STATE={path}\nDW_CI_PIP_PYTHON={report['python']}\n"
                           f"PYTHONPATH={report['purelib']}\nPYTHONHOME=\nPYTHONNOUSERSITE=1\nPYTHONDONTWRITEBYTECODE=1\n"
                           f"LD_LIBRARY_PATH={report['interpreter']['loader']['path'] if report['interpreter']['loader'] else ''}\n"
                           "LD_PRELOAD=\nLD_AUDIT=\nPIP_CONFIG_FILE=/dev/null\nPIP_KEYRING_PROVIDER=disabled\nPIP_NO_INPUT=1\n")
            append_output(f"pip-state={path}\npip-python={report['python']}\npip-purelib={report['purelib']}\n"
                          f"pip-created={'true' if created else 'false'}\n"
                          f"pip-identity={json.dumps(created.identity if created else report['root_identity'], separators=(',', ':'))}\n")
            print(json.dumps({"private_pip": VERSION, "python_version": report["interpreter"]["version"],
                              "manager_unchanged": True, "operation": operation}, sort_keys=True))
    except BaseException:
        if created is not None:
            cleanup_runtime(created.root, runner_temp, created.identity)
        raise


if __name__ == "__main__":
    main()
