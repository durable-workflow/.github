"""Protect the shared parent of the selected GitHub-hosted Python runtime."""

import os
import re
import stat
import sys


def protect_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        protect_parent(descriptor, 0)
    finally:
        os.close(descriptor)


def protect_parent(descriptor, runner_uid):
    before = os.fstat(descriptor)
    mode = stat.S_IMODE(before.st_mode)
    if before.st_uid not in {0, runner_uid} or mode & (stat.S_ISUID | stat.S_ISGID):
        raise ValueError("Hosted runtime parent must be root-owned or runner-owned without special modes")
    expected = ((mode | stat.S_ISVTX) if before.st_uid == 0 and mode & 0o022
                else mode & ~0o022)
    if mode != expected:
        os.fchmod(descriptor, expected)
    after = os.fstat(descriptor)
    if ((before.st_dev, before.st_ino, before.st_uid)
            != (after.st_dev, after.st_ino, after.st_uid)
            or stat.S_IMODE(after.st_mode) != expected):
        raise ValueError("Hosted runtime parent protection was not established")


def seal_tree(descriptor, runner_uid, budget=None, depth=0):
    """Remove other-user writes from only the selected runtime, without following links."""
    budget = [0] if budget is None else budget
    if depth > 64:
        raise ValueError("Selected runtime exceeds the metadata depth limit")
    metadata = os.fstat(descriptor)
    if metadata.st_uid not in {0, runner_uid} or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise ValueError("Selected runtime has an unsupported owner or special mode")
    os.fchmod(descriptor, stat.S_IMODE(metadata.st_mode) & ~0o022)
    for name in os.listdir(descriptor):
        budget[0] += 1
        if budget[0] > 200000:
            raise ValueError("Selected runtime exceeds the metadata walk limit")
        entry = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if entry.st_uid not in {0, runner_uid}:
            raise ValueError("Selected runtime entry has an unsupported owner")
        if stat.S_ISLNK(entry.st_mode):
            continue
        directory = stat.S_ISDIR(entry.st_mode)
        if not directory and (not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1):
            raise ValueError("Selected runtime entry is not a private regular file or directory")
        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                        | (os.O_DIRECTORY if directory else 0), dir_fd=descriptor)
        try:
            held = os.fstat(child)
            if ((held.st_dev, held.st_ino, held.st_uid, held.st_mode, held.st_nlink)
                    != (entry.st_dev, entry.st_ino, entry.st_uid, entry.st_mode, entry.st_nlink)):
                raise ValueError("Selected runtime entry changed during protection")
            if directory:
                seal_tree(child, runner_uid, budget, depth + 1)
            else:
                if held.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    raise ValueError("Selected runtime file has a special mode")
                expected = stat.S_IMODE(held.st_mode) & ~0o022
                os.fchmod(child, expected)
                after = os.fstat(child)
                if ((held.st_dev, held.st_ino, held.st_uid, held.st_nlink)
                        != (after.st_dev, after.st_ino, after.st_uid, after.st_nlink)
                        or stat.S_IMODE(after.st_mode) != expected):
                    raise ValueError("Selected runtime file protection was not established")
        finally:
            os.close(child)
    after = os.fstat(descriptor)
    if ((metadata.st_dev, metadata.st_ino, metadata.st_uid)
            != (after.st_dev, after.st_ino, after.st_uid)
            or stat.S_IMODE(after.st_mode) != stat.S_IMODE(metadata.st_mode) & ~0o022):
        raise ValueError("Selected runtime directory protection was not established")


def protect_hosted_python(location, runner_uid):
    if re.fullmatch(r"/opt/hostedtoolcache/Python/\d+\.\d+\.\d+/(?:x64|arm64)", location) is None:
        raise ValueError("Selected runtime is outside the fixed hosted Python location")
    # Hold each ancestor and never follow a directory symlink. Root-owned
    # shared parents get sticky ownership; runner-owned parents lose other-user
    # writes. Other versions and languages are never traversed.
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in location.split("/")[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            protect_parent(descriptor, runner_uid)
        seal_tree(descriptor, runner_uid)
    finally:
        os.close(descriptor)


if __name__ == "__main__":
    if (len(sys.argv) != 2 or os.geteuid() != 0
            or re.fullmatch(r"[1-9][0-9]*", os.environ.get("SUDO_UID", "")) is None):
        raise SystemExit("Hosted runtime parent protection requires its fixed privileged invocation")
    protect_hosted_python(sys.argv[1], int(os.environ["SUDO_UID"]))
    print("Hosted runtime parent protection verified.")
