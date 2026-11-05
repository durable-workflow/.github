"""Unwired offline APT bootstrap proposal for a disposable Resolute runner."""

import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))
from scripts.require_fixed_apt import CLEAN_ENV, require_fixed_apt  # noqa: E402

# Publisher-signed Release -> Packages -> DEB identities retained beside these
# inputs. These are reviewed constants, never caller-supplied expected hashes.
PACKAGES = (
    ("libapt-pkg7.0_3.2.1ubuntu0.1_amd64.deb", 1139022,
     "94e5d41303265b66af0f8c70ade18bfb77260ad286edee6c8045faddef82b94c"),
    ("apt_3.2.1ubuntu0.1_amd64.deb", 1506688,
     "0de729b8fe0e1c67c04e8e8d5bd6e0420dbd47f75b93f0b71c8e740edc2d5ffc"),
)


def capture_packages(directory):
    captured = []
    for name, size, digest in PACKAGES:
        descriptor = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size != size:
                raise ValueError("Fixed package file type/link/size differs")
            data = stream.read(size + 1)
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Fixed package captured bytes differ")
        captured.append((name, data, digest))
    return captured


def command(arguments, *, run, data=None, timeout=30):
    return run(arguments, input=data, env=CLEAN_ENV, check=True, timeout=timeout,
               stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def install(captured, *, run=subprocess.run):
    # Root receives only the already-captured immutable bytes through stdin.
    # The unprivileged checkout cannot replace files inside this /run directory.
    result = command(["/usr/bin/sudo", "-n", "/usr/bin/mktemp", "-d", "/run/dw-fixed-apt.XXXXXXXX"], run=run)
    private = result.stdout.decode("ascii").strip()
    if re.fullmatch(r"/run/dw-fixed-apt\.[A-Za-z0-9]{8}", private) is None:
        raise ValueError("Root package directory identity differs")
    paths = [private + "/" + name for name, _, _ in captured]
    try:
        for path, (_, data, _) in zip(paths, captured):
            command(["/usr/bin/sudo", "-n", "/usr/bin/tee", "--", path], run=run, data=data)
        hashes = command(["/usr/bin/sudo", "-n", "/usr/bin/sha256sum", "--", *paths], run=run)
        expected = "".join(digest + "  " + path + "\n" for path, (_, _, digest) in zip(paths, captured))
        if hashes.stdout.decode("ascii") != expected:
            raise ValueError("Root-owned package copy differs")
        prefix = ["/usr/bin/sudo", "-n", "/usr/bin/unshare", "--net", "--", "/usr/bin/dpkg"]
        command([*prefix, "--no-act", "--install", *paths], run=run, timeout=60)
        command([*prefix, "--install", *paths], run=run, timeout=120)
    finally:
        command(["/usr/bin/sudo", "-n", "/usr/bin/rm", "-f", "--", *paths], run=run)
        command(["/usr/bin/sudo", "-n", "/usr/bin/rmdir", "--", private], run=run)


def main():
    try:
        if sys.argv[1:] not in ([], ["--plan"], ["--install"]):
            raise ValueError("No bootstrap source/version/path overrides are accepted")
        captured = capture_packages(ROOT / "qualification/apt-resolute")
        if sys.argv[1:] != ["--install"]:
            print(json.dumps({"installed": False, "packages": [name for name, _, _ in captured]}))
            return 0
        release = platform.freedesktop_os_release()
        if (os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
                or os.environ.get("GITHUB_ACTIONS") != "true"
                or (release.get("ID"), release.get("VERSION_ID")) != ("ubuntu", "26.04")
                or platform.machine() != "x86_64"):
            raise ValueError("Installation is limited to the selected disposable hosted runner")
        try:
            report = require_fixed_apt(release)
        except ValueError:
            query = command(["/usr/bin/dpkg-query", "--showformat=${Package} ${db:Status-Status} ${Version}\\n",
                             "--show", "apt", "libapt-pkg7.0"], run=subprocess.run)
            if query.stdout != b"apt installed 3.2.0\nlibapt-pkg7.0 installed 3.2.0\n":
                raise ValueError("The affected installed package pair differs from the reviewed runner")
            install(captured)
            report = require_fixed_apt(release)
        print(json.dumps(report, sort_keys=True))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, UnicodeError) as error:
        print(json.dumps({"installed": False, "refusal": str(error)[:500]}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
