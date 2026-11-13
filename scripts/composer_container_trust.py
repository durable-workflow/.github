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
import stat
import subprocess
import sys
import tempfile
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
    context_policies = [name for name in (".dockerignore", dockerfile + ".dockerignore") if (source / name).is_file()]
    if not context_policies or any(name not in files for name in context_policies):
        raise ContainerTrustRefused("Every Docker context exclusion file must be part of the reviewed recipe.")
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
    candidate = Path(bundle_name)
    if candidate.is_symlink():
        raise ContainerTrustRefused("The selected CA file must not be a symbolic link.")
    bundle = candidate.resolve(strict=True)
    if (not bundle.is_file() or bundle.stat().st_size > 8 * 1024 * 1024
            or sha256(bundle.read_bytes()) != expected):
        raise ContainerTrustRefused("The selected CA file differs from the authenticated bootstrap.")
    return bundle, expected


def regular_ca_bytes(path: Path, expected: str) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= 8 * 1024 * 1024:
            raise ContainerTrustRefused("The selected CA must be a single regular bounded file.")
        contents = os.pread(descriptor, 8 * 1024 * 1024 + 1, 0)
        after = os.fstat(descriptor)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, key) != getattr(after, key) for key in fields) or sha256(contents) != expected:
            raise ContainerTrustRefused("The selected CA object or authenticated bytes changed.")
        return contents
    finally:
        os.close(descriptor)


def stage_compose_ca(outputs: dict[str, str], directory: Path, source: Path) -> dict[str, Any]:
    """Copy only the authenticated public bundle inside Bake's allowed tree."""
    if directory.is_symlink() or any(character in str(directory) for character in "\r\n\0"):
        raise ContainerTrustRefused("The Compose directory must not be a symbolic link.")
    directory = directory.resolve(strict=True)
    if not directory.is_dir() or directory.stat().st_uid != os.getuid():
        raise ContainerTrustRefused("The staged CA needs an owned Compose directory.")
    if directory.is_relative_to(source.resolve(strict=True)) or directory.is_relative_to(Path(outputs["context-directory"])):
        raise ContainerTrustRefused("The staged CA must stay outside all image build contexts.")
    contents = regular_ca_bytes(Path(outputs["ca-file"]), outputs["ca-sha256"])
    state = Path(tempfile.mkdtemp(prefix=".dw-composer-ca-", dir=directory))
    selected = state / "ca.pem"
    try:
        descriptor = os.open(selected, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(contents)
        if regular_ca_bytes(selected, outputs["ca-sha256"]) != contents:
            raise ContainerTrustRefused("The staged CA differs from its authenticated source.")
        info = selected.stat(follow_symlinks=False)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o400:
            raise ContainerTrustRefused("The staged CA must remain an owned read-only file.")
        outputs["ca-file"] = str(selected)
        return {"sha256": outputs["ca-sha256"], "size": len(contents), "mode": 0o400}
    except BaseException:
        selected.unlink(missing_ok=True)
        state.rmdir()
        raise


def cleanup_compose_ca(selected: Path, directory: Path, expected: str) -> None:
    directory = directory.resolve(strict=True)
    state = selected.parent
    if (not SHA256.fullmatch(expected) or not selected.is_absolute() or selected.name != "ca.pem"
            or state.parent != directory or not re.fullmatch(r"\.dw-composer-ca-[a-z0-9_]+", state.name)
            or state.is_symlink() or selected.is_symlink()):
        raise ContainerTrustRefused("Only the exact owned staged CA can be removed.")
    info = state.stat()
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700 or set(state.iterdir()) != {selected}:
        raise ContainerTrustRefused("The staged CA directory identity or contents changed.")
    regular_ca_bytes(selected, expected)
    selected.unlink()
    state.rmdir()


def cleanup_main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Remove only a verified staged public CA copy.")
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--compose-directory", type=Path, required=True)
    parser.add_argument("--ca-sha256", required=True)
    args = parser.parse_args(arguments)
    try:
        cleanup_compose_ca(args.ca_file, args.compose_directory, args.ca_sha256)
        return 0
    except (ContainerTrustRefused, OSError, ValueError) as error:
        print(f"Staged Composer CA cleanup refused: {type(error).__name__}.")
        return 1


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


def verify_compose_build(build: dict[str, Any], source: Path, request: dict[str, Any], outputs: dict[str, str]) -> None:
    if (not isinstance(build, dict) or Path(build.get("context", "")).resolve() != source.resolve()
            or build.get("dockerfile", "Dockerfile") != request["dockerfile"]
            or build.get("target", request["stage"]) != request["stage"]
            or "dockerfile_inline" in build):
        raise ContainerTrustRefused("Compose must build the verified source, Dockerfile and request stage.")
    if "cache_from" in build or "cache_to" in build:
        # Secret contents are absent from BuildKit cache keys. Registered
        # requests use a fresh hosted runner, without imported/exported layers.
        raise ContainerTrustRefused("Compose must not import or export BuildKit caches.")
    if build.get("additional_contexts") != {"dwf_composer_trust": outputs["context-directory"]}:
        raise ContainerTrustRefused("Compose must mount only the reviewed verifier context.")
    arguments = {"DW_CI_CA_SHA256": outputs["ca-sha256"], "DW_SERVER_SOURCE_COMMIT": outputs["source-commit"],
                 "DW_SERVER_DOCKERFILE_SHA256": outputs["dockerfile-sha256"]}
    if any(build.get("args", {}).get(name) != value for name, value in arguments.items()):
        raise ContainerTrustRefused("Compose must use the verified source and CA build arguments.")
    if build.get("secrets") not in ([{"source": "dwf_ci_ca"}], [{"source": "dwf_ci_ca", "target": "dwf_ci_ca"}]):
        raise ContainerTrustRefused("Compose must mount the authenticated CA build secret.")


def verify_compose_configuration(document: dict[str, Any], source: Path, request: dict[str, Any], outputs: dict[str, str]) -> list[str]:
    services = document.get("services", {})
    expected = request.get("services")
    if not isinstance(services, dict) or not isinstance(expected, list) or not expected:
        raise ContainerTrustRefused("The registered Compose build services are missing.")
    builds = {name: service["build"] for name, service in services.items() if "build" in service}
    if set(builds) != set(expected):
        raise ContainerTrustRefused("The actual Compose build services differ from the registered request.")
    for build in builds.values():
        verify_compose_build(build, source, request, outputs)
    secrets = document.get("secrets", {})
    selected = secrets.get("dwf_ci_ca", {})
    if selected.get("file") != outputs["ca-file"] or "environment" in selected or selected.get("external"):
        raise ContainerTrustRefused("The actual Compose CA secret differs from the authenticated file.")
    return sorted(builds)


def compose_environment(environment: dict[str, str], outputs: dict[str, str]) -> dict[str, str]:
    return environment | {
        "DWF_COMPOSER_TRUST_CONTEXT": outputs["context-directory"], "COMPOSER_CAFILE": outputs["ca-file"],
        "DW_CI_CA_SHA256": outputs["ca-sha256"], "DW_SERVER_SOURCE_COMMIT": outputs["source-commit"],
        "DW_SERVER_DOCKERFILE_SHA256": outputs["dockerfile-sha256"],
    }


def inspect_compose(directory: Path, source: Path, request: dict[str, Any], outputs: dict[str, str]) -> list[str]:
    files = os.environ.get("COMPOSE_FILE", "").split(os.pathsep)
    if files not in request.get("compose_files", []):
        raise ContainerTrustRefused("Compose must use the registered local file set.")
    for name in files:
        path = directory / name
        if path.is_symlink() or not path.is_file():
            raise ContainerTrustRefused("The registered Compose file must be a regular local file.")
    outputs["compose-file"] = os.pathsep.join(files)
    try:
        result = subprocess.run(["docker", "compose", "--env-file", "/dev/null", "config", "--format", "json"], cwd=directory,
                                env=compose_environment(dict(os.environ), outputs), check=True,
                                capture_output=True, text=True, timeout=30)
        document = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as error:
        # Compose's rendered configuration and errors can contain application
        # environment values. Keep both out of logs and the provenance record.
        raise ContainerTrustRefused("Cannot inspect the actual merged Compose build configuration.") from error
    return verify_compose_configuration(document, source, request, outputs)


def main() -> int:
    if sys.argv[1:2] == ["cleanup-ca"]:
        return cleanup_main(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-directory", type=Path, required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--request", required=True)
    parser.add_argument("--compose-directory", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    args = parser.parse_args()
    staged: Path | None = None
    outputs: dict[str, str] = {}
    try:
        catalog = json.loads((ROOT / "qualification/composer-container-trust.json").read_text())
        outputs, evidence = prepare(
            args.source_directory, args.source_commit, args.request, catalog, dict(os.environ),
            ROOT / ".github/actions/verify-composer-trust",
        )
        evidence["staged_ca"] = stage_compose_ca(outputs, args.compose_directory, args.source_directory)
        staged = Path(outputs["ca-file"])
        evidence["compose_services"] = inspect_compose(
            args.compose_directory, args.source_directory, catalog["requests"][args.request], outputs,
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
    except (ContainerTrustRefused, OSError, ValueError, KeyError, TypeError) as error:
        if staged is not None:
            try:
                cleanup_compose_ca(staged, args.compose_directory, outputs["ca-sha256"])
            except (ContainerTrustRefused, OSError, ValueError):
                print("Staged Composer CA changed; automatic cleanup refused.")
        message = str(error) if isinstance(error, ContainerTrustRefused) else "Container trust input inspection failed."
        print(f"Container Composer trust refused: {message}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
