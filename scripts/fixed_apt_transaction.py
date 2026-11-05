"""Unwired, one-shot offline transaction for a disposable hosted runner."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "DPKG_FRONTEND_LOCKED": "1"}
SERVICES = ("apt-daily.service", "apt-daily-upgrade.service")
TIMERS = ("apt-daily.timer", "apt-daily-upgrade.timer")
PACKAGES = (
    ("libapt-pkg7.0_3.2.1ubuntu0.1_amd64.deb", 1139022,
     "94e5d41303265b66af0f8c70ade18bfb77260ad286edee6c8045faddef82b94c"),
    ("apt_3.2.1ubuntu0.1_amd64.deb", 1506688,
     "0de729b8fe0e1c67c04e8e8d5bd6e0420dbd47f75b93f0b71c8e740edc2d5ffc"),
)


def command(argv, *, run=subprocess.run, timeout=15):
    return run(argv, env=ENV, check=True, timeout=timeout, capture_output=True)


def unit_state(unit, *, run=subprocess.run):
    output = command(["/usr/bin/systemctl", "show", "--no-pager",
                      "--property=LoadState,ActiveState,UnitFileState", unit], run=run)
    fields = dict(line.split("=", 1) for line in output.stdout.decode("ascii").splitlines())
    if set(fields) != {"LoadState", "ActiveState", "UnitFileState"}:
        raise ValueError("Incomplete package timer/service state")
    return fields


def fence_units(*, run=subprocess.run, directory=Path("/run/systemd/system")):
    before = {unit: unit_state(unit, run=run) for unit in SERVICES + TIMERS}
    if any(value["LoadState"] != "loaded" or "masked" in value["UnitFileState"]
           for value in before.values()):
        raise ValueError("Unknown or already masked package unit")
    if any(before[unit]["ActiveState"] != "inactive" for unit in SERVICES):
        raise ValueError("A package service is active; it will not be stopped")
    identities = {}
    # No replacement: every created link remains until this disposable VM ends.
    # Fence both services before asking systemd to stop either timer.
    for unit in SERVICES + TIMERS:
        path = directory / unit
        path.symlink_to("/dev/null")
        info = path.lstat()
        identities[unit] = (info.st_dev, info.st_ino)
    command(["/usr/bin/systemctl", "daemon-reload"], run=run)
    command(["/usr/bin/systemctl", "stop", *TIMERS], run=run)
    check_fence(identities, run=run, directory=directory)
    return before, identities


def check_fence(identities, *, run=subprocess.run, directory=Path("/run/systemd/system")):
    if set(identities) != set(SERVICES + TIMERS):
        raise ValueError("Incomplete package-unit fence")
    for unit, identity in identities.items():
        path = directory / unit
        info = path.lstat()
        if (not stat.S_ISLNK(info.st_mode) or (info.st_dev, info.st_ino) != identity
                or os.readlink(path) != "/dev/null"):
            raise ValueError("Package-unit mask identity changed")
        state = unit_state(unit, run=run)
        if state != {"LoadState": "masked", "ActiveState": "inactive",
                     "UnitFileState": "masked-runtime"}:
            raise ValueError("Package timer/service fence is not effective")


def check_processes(proc=Path("/proc")):
    for entry in proc.iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            name = (entry / "comm").read_text().strip()
        except FileNotFoundError:
            continue  # A process that exited cannot hold a package lock.
        if name in {"apt", "apt-get", "aptitude", "dpkg", "unattended-upgr"}:
            raise ValueError("A package-manager process is active; it will not be killed")


def acquire_lock(path, *, owner=0):
    descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != owner or info.st_nlink != 1:
            raise ValueError("Package lock file identity differs")
        fcntl.lockf(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def check_database(*, run=subprocess.run):
    result = command(["/usr/bin/dpkg", "--audit"], run=run)
    if result.stdout or result.stderr:
        raise ValueError("The package database is not clean")


def check_pair(version, *, run=subprocess.run):
    result = command(["/usr/bin/dpkg-query", "--show",
                      "--showformat=${Package} ${Status} ${Version}\\n",
                      "apt", "libapt-pkg7.0"], run=run)
    expected = "".join(f"{name} install ok installed {version}\n"
                       for name in ("apt", "libapt-pkg7.0")).encode()
    if result.stdout != expected:
        raise ValueError("The exact clean-installed APT pair differs")


def verify_packages(directory):
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("Root package directory identity differs")
    for name, size, digest in PACKAGES:
        descriptor = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or info.st_nlink != 1 or info.st_size != size):
                raise ValueError("Root package copy identity differs")
            data = stream.read(size + 1)
        if len(data) != size or hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("Root package copy hash differs")


def transact(directory, *, run=subprocess.run):
    verify_packages(directory)
    frontend = acquire_lock("/var/lib/dpkg/lock-frontend")
    try:
        # Check direct-dpkg contention, then let stock dpkg take its own database
        # lock for each command. The frontend lock stays held across both calls.
        database = acquire_lock("/var/lib/dpkg/lock")
        os.close(database)
        check_processes()
        before, masks = fence_units(run=run)
        check_processes()
        check_database(run=run)
        check_pair("3.2.0", run=run)
        paths = [str(directory / name) for name, _, _ in PACKAGES]
        prefix = ["/usr/bin/unshare", "--net", "--", "/usr/bin/dpkg"]
        command([*prefix, "--no-act", "--install", *paths], run=run, timeout=45)
        check_fence(masks, run=run)
        check_processes()
        verify_packages(directory)
        command([*prefix, "--install", *paths], run=run, timeout=120)
        check_pair("3.2.1ubuntu0.1", run=run)
        check_database(run=run)
        verification = command(["/usr/bin/dpkg", "--verify", "apt", "libapt-pkg7.0"], run=run)
        if verification.stdout or verification.stderr:
            raise ValueError("Installed package file verification failed")
        client = command(["/usr/bin/apt-get", "--version"], run=run)
        if not client.stdout.startswith(b"apt 3.2.1ubuntu0.1 (amd64)\n"):
            raise ValueError("Installed APT client version differs")
        check_fence(masks, run=run)
        return {"installed": True, "apt": "3.2.1ubuntu0.1", "libapt": "3.2.1ubuntu0.1",
                "original_units": before, "runtime_masks_retained": sorted(masks)}
    finally:
        os.close(frontend)


def main():
    try:
        if (os.geteuid() != 0 or len(sys.argv) != 2
                or re.fullmatch(r"/run/dw-fixed-apt\.[A-Za-z0-9]{8}", sys.argv[1]) is None):
            raise ValueError("Only the selected root-owned staging directory is accepted")
        print(json.dumps(transact(Path(sys.argv[1])), sort_keys=True))
        return 0
    except (ValueError, OSError, subprocess.SubprocessError, UnicodeError) as error:
        print(json.dumps({"installed": False, "refusal": str(error)[:500],
                          "quarantine": "Runtime APT masks remain; discard the disposable VM"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
