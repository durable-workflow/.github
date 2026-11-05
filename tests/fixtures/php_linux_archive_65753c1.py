"""Exact inventory() predecessor from central commit 65753c129da90a5ff4b8c41f95e1e68067627de4.

Inert regression fixture only. No extraction, executable or network operation.
The function body below is retained verbatim to reproduce its admissions.
"""
import hashlib
from pathlib import PurePosixPath
import tarfile
MAX_UNPACKED = 2 * 1024 * 1024 * 1024
MAX_MEMBERS = 100000

def inventory(stream) -> dict:
    """Stream regular file hashes, never extract or execute archive members."""
    files, seen, total = {}, set(), 0
    with tarfile.open(fileobj=stream, mode="r|") as archive:
        for count, member in enumerate(archive, 1):
            if count > MAX_MEMBERS:
                raise ValueError("Bound archive member limit exceeded")
            name = member.name
            while name.startswith("./"):
                name = name[2:]
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("Bound archive contains an unscoped member path")
            if member.isdir():
                continue
            if not name or name in seen:
                raise ValueError("Bound archive member identity is ambiguous")
            seen.add(name)
            if not member.isfile():
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
            files[path.as_posix()] = {"size": size, "sha256": digest.hexdigest()}
    return files
