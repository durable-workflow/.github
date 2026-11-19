"""Conservative input language for the protected pilot, not ordinary preflight.

Candidate text is data. Unsupported execution contexts refuse instead of
extending the shared validator into a shell interpreter.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shlex
from typing import Any

import yaml

from scripts.protected_policy_inputs import HELPERS, InputRefused, checked_path

MAX_YAML_NODES = 50_000
MAX_YAML_DEPTH = 64
ROOT_DIRECTORIES = {None, ".", "./", "${{ github.workspace }}"}
SHELLS = {None, "bash", "sh"}
STARTUP_ENVIRONMENT = {
    "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "LD_PRELOAD", "PATH", "CDPATH",
    "BASH_COMPAT", "BASH_LOADABLES_PATH", "GLOBIGNORE", "PROMPT_COMMAND", "PS4",
}
SHEBANGS = {"#!/bin/sh", "#!/bin/bash", "#!/usr/bin/sh", "#!/usr/bin/bash",
            "#!/usr/bin/env sh", "#!/usr/bin/env bash"}
# Literal words have no shell expansions, operators, escapes, globs or quote
# concatenation. Quoting may group data containing spaces, never shell syntax.
WORD = r'''(?:[A-Za-z0-9_./:@%+,=-]+|'[A-Za-z0-9_./:@%+,= -]*'|"[A-Za-z0-9_./:@%+,= -]*")'''
COMMAND = re.compile(rf"{WORD}(?:[ \t]+{WORD})*[ \t]*")
PYTHON_MODULES = {"unittest", "pip", "venv", "http.server"}
CI_WORKFLOW = ".github/workflows/ci.yml"
SONAR_WORKFLOW = ".github/workflows/sonar.yml"
INITIAL_PHP_WORKFLOW = ".github/workflows/qualify-linux-php-initial.yml"
# Reviewed workflow-byte identities are data, never derived from candidate
# text. The native runtime reads them from protected main (see
# scripts/protected_policy_data.py) and passes them to validate_context. These
# module registries are this checkout's copy of the same data, kept under their
# historical names for offline tools and source tests.
_LOCAL_DATA = json.loads((Path(__file__).resolve().parents[1] /
                          "qualification/protected-policy-data.json").read_text(encoding="utf-8"))


def _registry(target: str, name: str) -> dict[str, str]:
    return {entry["path"]: entry["sha256"] for entry in _LOCAL_DATA["reviewed_workflows"][target]
            if entry["registry"] == name}


_CONTROL_REGISTRIES = tuple(dict.fromkeys(
    entry["registry"] for entry in _LOCAL_DATA["reviewed_workflows"]["github-control-plane"]))
for _name in _CONTROL_REGISTRIES:
    globals()["REVIEWED_" + _name.upper()] = _registry("github-control-plane", _name)
REVIEWED_AI_WORKFLOWS = _registry("ai", "ai_workflows")


def reviewed_context_hashes(policy_target: str) -> dict[str, set[str]]:
    if policy_target == "github-control-plane":
        registries = tuple(globals()["REVIEWED_" + name.upper()] for name in _CONTROL_REGISTRIES)
    elif policy_target == "ai":
        registries = (REVIEWED_AI_WORKFLOWS,)
    else:
        raise InputRefused("Unsupported protected policy context target")
    result: dict[str, set[str]] = {}
    for registry in registries:
        for name, digest in registry.items():
            result.setdefault(name, set()).add(digest)
    return result


def literal_python(arguments: list[str]) -> bool:
    if arguments[:1] == ["-I"]:
        arguments = arguments[1:]
    if arguments[:1] == ["-m"]:
        return len(arguments) >= 2 and arguments[1] in PYTHON_MODULES
    return bool(arguments) and not arguments[0].startswith("-") and arguments[0].endswith(".py")


def literal_command(words: list[str]) -> bool:
    command, arguments = words[0], words[1:]
    if command in {"bash", "sh"}:
        return bool(arguments) and HELPERS.fullmatch(arguments[0]) is not None
    if command in {"python", "python3"}:
        return literal_python(arguments)
    if command == "node":
        return bool(arguments) and not arguments[0].startswith("-") and arguments[0].endswith((".js", ".mjs"))
    if command == "coverage":
        return bool(arguments) and arguments[0] in {"run", "xml"}
    if command == "composer":
        return bool(arguments) and arguments[0] in {"install", "update", "validate", "config"}
    return HELPERS.fullmatch(command) is not None and PurePosixPath(command).suffix in {"", ".sh", ".bash"}


def unsupported_shell(source: str) -> bool:
    if any(ord(character) < 32 and character not in "\n\t" for character in source):
        return True
    for line in source.splitlines():
        line = line.strip(" \t")
        if line.startswith("#!") and line not in SHEBANGS:
            return True
        if not line or line.startswith("#"):
            continue
        if COMMAND.fullmatch(line) is None or not literal_command(shlex.split(line)):
            return True
    return False


def node_children(node):
    if isinstance(node, yaml.SequenceNode):
        return node.value
    if not isinstance(node, yaml.MappingNode):
        return []
    names, children = set(), []
    for key, value in node.value:
        if not isinstance(key, yaml.ScalarNode) or key.value in names or key.value == "<<":
            raise InputRefused("Protected pilot YAML keys must be unique scalars without merges")
        names.add(key.value)
        children.extend((key, value))
    return children


def bounded_document(source: str) -> dict[str, Any]:
    loader = yaml.BaseLoader(source)
    try:
        root = loader.get_single_node()
        pending = [(root, 0, frozenset())]
        count = 0
        while pending:
            node, depth, ancestors = pending.pop()
            count += 1
            if count > MAX_YAML_NODES or depth > MAX_YAML_DEPTH:
                raise InputRefused("Protected pilot YAML exceeds its node or depth bound")
            if node is None or id(node) in ancestors:
                raise InputRefused("Protected pilot YAML is empty or recursive")
            lineage = ancestors | {id(node)}
            pending.extend((child, depth + 1, lineage) for child in node_children(node))
        document = loader.construct_document(root)
    except (yaml.YAMLError, RecursionError) as error:
        raise InputRefused("Protected pilot YAML cannot be read within its bounds") from error
    finally:
        loader.dispose()
    if not isinstance(document, dict):
        raise InputRefused("Protected pilot requires a workflow mapping")
    return document


def run_defaults(scope: dict[str, Any]) -> dict[str, Any]:
    defaults = scope.get("defaults", {})
    if not isinstance(defaults, dict) or not isinstance(defaults.get("run", {}), dict):
        raise InputRefused("Protected pilot requires explicit run defaults")
    return defaults.get("run", {})


def shell_targets(source: str) -> set[str]:
    forced_shell = set()
    for line in source.splitlines():
        if COMMAND.fullmatch(line.strip()) is not None:
            words = shlex.split(line)
            if words[0] in {"bash", "sh"} and len(words) > 1:
                forced_shell.add(words[1].removeprefix("./"))
    return forced_shell


def check_helpers(source: str, files: dict[str, bytes], visited: set[str]) -> None:
    forced_shell = shell_targets(source)
    for reference in HELPERS.findall(source):
        name = checked_path(reference.removeprefix("./"))
        if name not in files or name in visited:
            continue
        visited.add(name)
        text = files[name].decode("utf-8")
        suffix = PurePosixPath(name).suffix
        if (name in forced_shell or suffix in {"", ".sh", ".bash", ".ksh", ".zsh"}
                or re.match(r"^#![^\n]*\b(?:bash|sh|dash|ksh|zsh)\b", text)):
            if unsupported_shell(text):
                raise InputRefused("Protected pilot helper has an unsupported directory or dynamic shell context")
            check_helpers(text, files, visited)


def validate_helper_step(document, job, step, files, reviewed_complex=False):
    if not isinstance(step, dict):
        raise InputRefused("Protected pilot requires step mappings")
    source = step.get("run", "")
    if not isinstance(source, str):
        raise InputRefused("Protected pilot requires literal run text")
    if unsupported_shell(source) and not reviewed_complex:
        raise InputRefused("Protected pilot requires closed literal commands or exact reviewed workflow bytes")
    if not HELPERS.search(source):
        return
    contexts = [run_defaults(document), run_defaults(job), step]
    directory = next((scope["working-directory"] for scope in reversed(contexts)
                      if "working-directory" in scope), None)
    shell = next((scope["shell"] for scope in reversed(contexts) if "shell" in scope), None)
    if not isinstance(directory, (str, type(None))) or directory not in ROOT_DIRECTORIES:
        raise InputRefused("Protected pilot relative helpers require the workspace root")
    if not isinstance(shell, (str, type(None))) or shell not in SHELLS:
        raise InputRefused("Protected pilot relative helpers require a reviewed shell")
    for scope in (document, job, step):
        environment = scope.get("env", {})
        if (not isinstance(environment, dict) or STARTUP_ENVIRONMENT.intersection(environment)
                or any(str(name).startswith("BASH_FUNC_") for name in environment)):
            raise InputRefused("Protected pilot helper startup environment is unsupported")
    check_helpers(source, files, set())


def validate_context(files: dict[str, bytes], *, policy_target: str = "github-control-plane",
                     reviewed: dict[str, set[str]] | None = None) -> None:
    """`reviewed` is protected main's data; None selects this checkout's copy."""
    reviewed_hashes = reviewed_context_hashes(policy_target) if reviewed is None else reviewed
    for name, raw in sorted(files.items()):
        if PurePosixPath(name).parent.as_posix() != ".github/workflows" or not name.endswith((".yml", ".yaml")):
            continue
        document = bounded_document(raw.decode("utf-8"))
        digest = hashlib.sha256(raw).hexdigest()
        reviewed_complex = digest in reviewed_hashes.get(name, ())
        jobs = document.get("jobs", {})
        if not isinstance(jobs, dict):
            raise InputRefused("Protected pilot requires a jobs mapping")
        for job in jobs.values():
            if not isinstance(job, dict) or not isinstance(job.get("steps", []), list):
                raise InputRefused("Protected pilot requires explicit jobs and step lists")
            for step in job.get("steps", []):
                validate_helper_step(document, job, step, files, reviewed_complex)
