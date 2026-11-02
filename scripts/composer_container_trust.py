#!/usr/bin/env python3
"""Bind a reviewed container Composer recipe to its real checkout and CA bundle.

This prepares inputs for the in-container verifier; it does not authorize a
dependency request by running Composer on the host. Recipes remain unavailable
until their build instructions and actual-container controls have been reviewed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
from typing import Any
from urllib.parse import urlsplit


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "durable-workflow.composer-container-trust.v1"
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
COMPOSER_IMAGE = re.compile(
    r"(?:docker\.io/library/)?composer(?::2\.10\.3)?@sha256:[0-9a-f]{64}\Z"
)


class ContainerTrustRefused(RuntimeError):
    """The supplied context cannot establish the required build identity."""


def sha256(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def git(root: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    try:
        return subprocess.run(
            ["git", "-C", str(root), *arguments], check=True, capture_output=True, input=input_bytes,
        ).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise ContainerTrustRefused("Cannot verify the source checkout with Git.") from error


def repository_name(url: str) -> str:
    if url.startswith("git@github.com:"):
        name = url.removeprefix("git@github.com:")
    else:
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or parsed.netloc != "github.com"
                or parsed.query or parsed.fragment):
            raise ContainerTrustRefused("The source remote must identify its public GitHub repository.")
        name = parsed.path.removeprefix("/")
    name = name.removesuffix(".git")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", name):
        raise ContainerTrustRefused("The source remote repository is malformed.")
    return name


def checkout_file(root: Path, relative: str, commit: str) -> bytes:
    path = PurePosixPath(relative)
    if (path.is_absolute() or not path.parts or ".." in path.parts
            or any(character in relative for character in "\r\n\0")):
        raise ContainerTrustRefused("Recipe files must be relative to the source checkout.")
    candidate = root
    for part in path.parts:
        candidate /= part
        if candidate.is_symlink():
            raise ContainerTrustRefused("Recipe files must not use symbolic links.")
    if not candidate.is_file() or candidate.stat().st_size > 4 * 1024 * 1024:
        raise ContainerTrustRefused("A required recipe file is missing or too large.")
    if int(git(root, "cat-file", "-s", f"{commit}:{path.as_posix()}")) > 4 * 1024 * 1024:
        raise ContainerTrustRefused("A committed recipe file is too large.")
    contents = candidate.read_bytes()
    if contents != git(root, "show", f"{commit}:{path.as_posix()}"):
        raise ContainerTrustRefused("Recipe bytes differ from the selected source commit.")
    return contents


def approved_recipe(source: Path, commit: str, request: dict[str, Any]) -> dict[str, Any]:
    dockerfile = request.get("dockerfile")
    recipes = request.get("approved_recipes")
    if not isinstance(dockerfile, str) or not isinstance(recipes, list) or len(recipes) > 32:
        raise ContainerTrustRefused("The reviewed recipe catalog is malformed.")
    contents = checkout_file(source, dockerfile, commit)
    digest = sha256(contents)
    candidates = [recipe for recipe in recipes if isinstance(recipe, dict)
                  and isinstance(recipe.get("files"), dict)
                  and recipe["files"].get(dockerfile) == digest]
    if len(candidates) != 1:
        raise ContainerTrustRefused("This Dockerfile has no uniquely approved Composer trust recipe.")
    recipe = candidates[0]
    files = recipe.get("files")
    image = recipe.get("composer_image")
    stage = recipe.get("composer_stage")
    if (not isinstance(files, dict) or not 1 <= len(files) <= 32
            or not isinstance(image, str) or not COMPOSER_IMAGE.fullmatch(image)
            or not isinstance(stage, str)):
        raise ContainerTrustRefused("The approved recipe metadata is malformed.")
    for relative, expected in files.items():
        if (not isinstance(relative, str) or not isinstance(expected, str)
                or not SHA256.fullmatch(expected)
                or sha256(checkout_file(source, relative, commit)) != expected):
            raise ContainerTrustRefused("The selected source no longer matches its reviewed recipe files.")
    stages = {name.lower(): base for base, name in re.findall(
        r"^\s*FROM\s+(?:--platform=\S+\s+)?(\S+)\s+AS\s+(\S+)\s*$",
        contents.decode("utf-8"), flags=re.IGNORECASE | re.MULTILINE,
    )}
    if stages.get(stage.lower()) != image or str(request.get("stage", "")).lower() not in stages:
        raise ContainerTrustRefused("The declared Composer and request stages differ from the reviewed Dockerfile.")
    return recipe


def require_clean_context(source: Path, commit: str) -> None:
    if git(source, "status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching"):
        raise ContainerTrustRefused("The actual build context contains tracked, staged, untracked or ignored changes.")
    paths, expected = [], []
    for entry in git(source, "ls-tree", "-rz", commit).split(b"\0"):
        if not entry:
            continue
        metadata, relative = entry.split(b"\t", 1)
        mode, kind, object_id = metadata.split()
        path = source / relative.decode("utf-8")
        if kind != b"blob" or mode not in {b"100644", b"100755"}:
            raise ContainerTrustRefused("Container source contexts with links or submodules are not supported.")
        if not path.is_file() or path.is_symlink() or bool(path.stat().st_mode & 0o111) != (mode == b"100755"):
            raise ContainerTrustRefused("The actual build context has changed file types or executable modes.")
        paths.append(json.dumps(str(path), ensure_ascii=False))
        expected.append(object_id)
    # Hash the bytes independently of Git's index/stat cache, assume-unchanged
    # flags and checkout filters. Labels and a clean status alone are not proof.
    actual = git(source, "hash-object", "--no-filters", "--stdin-paths",
                 input_bytes=("\n".join(paths) + "\n").encode()).splitlines()
    if actual != expected:
        raise ContainerTrustRefused("The actual build context bytes differ from the selected tree.")


def authenticated_bundle(environment: dict[str, str]) -> tuple[Path, str]:
    expected = environment.get("DW_CI_CA_SHA256", "")
    if not SHA256.fullmatch(expected):
        raise ContainerTrustRefused("The clean bootstrap must supply its authenticated CA digest.")
    bundle_name = environment.get("COMPOSER_CAFILE", "")
    if not bundle_name or any(character in bundle_name for character in "\r\n\0"):
        raise ContainerTrustRefused("The clean bootstrap must select a CA file.")
    bundle = Path(bundle_name).resolve(strict=True)
    if (not bundle.is_file() or bundle.stat().st_size > 8 * 1024 * 1024
            or sha256(bundle.read_bytes()) != expected):
        raise ContainerTrustRefused("The selected CA file differs from the authenticated bootstrap.")
    return bundle, expected


def prepare(
    source: Path, commit: str, request_id: str, catalog: dict[str, Any],
    environment: dict[str, str], verifier_directory: Path,
) -> tuple[dict[str, str], dict[str, Any]]:
    if not COMMIT.fullmatch(commit):
        raise ContainerTrustRefused("An exact lower-case source commit is required.")
    requests = catalog.get("requests")
    if catalog.get("schema") != SCHEMA or not isinstance(requests, dict):
        raise ContainerTrustRefused("The container trust catalog is not supported.")
    request = requests.get(request_id)
    if not isinstance(request, dict):
        raise ContainerTrustRefused("The container Composer request is not registered.")
    source = source.resolve(strict=True)
    if (git(source, "rev-parse", "--show-toplevel").decode().strip() != str(source)
            or git(source, "rev-parse", "HEAD").decode().strip() != commit):
        raise ContainerTrustRefused("The checkout does not match the selected source commit.")
    remote = git(source, "remote", "get-url", "origin").decode().strip()
    if repository_name(remote) != request.get("repository"):
        raise ContainerTrustRefused("The checkout is from a different source repository.")
    require_clean_context(source, commit)
    recipe = approved_recipe(source, commit, request)
    bundle, expected = authenticated_bundle(environment)
    verifier = verifier_directory.resolve(strict=True) / "verify.php"
    if not verifier.is_file() or verifier.is_symlink():
        raise ContainerTrustRefused("The reviewed in-container verifier is missing.")
    outputs = {
        "context-directory": str(verifier.parent), "ca-file": str(bundle),
        "ca-sha256": expected, "source-commit": commit,
        "dockerfile-sha256": recipe["files"][request["dockerfile"]],
    }
    if any("\n" in value or "\r" in value for value in outputs.values()):
        raise ContainerTrustRefused("Build inputs must be single-line values.")
    evidence = {
        "schema": SCHEMA, "request": request_id,
        "source_repository": request["repository"], "source_commit": commit,
        "recipe_files": recipe["files"], "composer_image": recipe["composer_image"],
        "stage": request["stage"], "ca_sha256": expected,
        "verifier_sha256": sha256(verifier.read_bytes()),
    }
    return outputs, evidence


def provenance_destination(path: Path, environment: dict[str, str], source: Path) -> Path:
    workspace = Path(environment["GITHUB_WORKSPACE"]).resolve(strict=True)
    destination = path.resolve()
    if not destination.is_relative_to(workspace) or destination == workspace:
        raise ContainerTrustRefused("Provenance must be a new file inside the Actions workspace.")
    if destination.is_relative_to(source.resolve(strict=True)):
        raise ContainerTrustRefused("Provenance must not add bytes to the selected build context.")
    if path.is_symlink() or destination.exists():
        raise ContainerTrustRefused("Provenance must not replace an existing file or symbolic link.")
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-directory", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--request", required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    args = parser.parse_args()
    try:
        catalog = json.loads((ROOT / "qualification/composer-container-trust.json").read_text())
        outputs, evidence = prepare(
            args.source_directory, args.source_commit, args.request, catalog, dict(os.environ),
            ROOT / ".github/actions/verify-composer-trust",
        )
        provenance = provenance_destination(args.provenance, dict(os.environ), args.source_directory)
        output = Path(os.environ["GITHUB_OUTPUT"]).resolve()
        if output.is_relative_to(args.source_directory.resolve(strict=True)):
            raise ContainerTrustRefused("Actions outputs must not add bytes to the selected build context.")
        with provenance.open("x") as destination:
            destination.write(json.dumps(evidence, indent=2) + "\n")
        with output.open("a") as destination:
            destination.writelines(f"{key}={value}\n" for key, value in outputs.items())
        print(f"Verified container Composer recipe for {evidence['source_repository']} at {args.source_commit}.")
        return 0
    except (ContainerTrustRefused, OSError, ValueError, KeyError) as error:
        message = str(error) if isinstance(error, ContainerTrustRefused) else "Container trust input inspection failed."
        print(f"Container Composer trust refused: {message}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
