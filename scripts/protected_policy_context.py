"""Conservative input language for the protected pilot, not ordinary preflight.

Candidate text is data. Unsupported execution contexts refuse instead of
extending the shared validator into a shell interpreter.
"""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
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
# Filled with explicit reviewed workflow-byte identities, never derived from
# candidate text. A changed complex workflow needs a separate source review.
REVIEWED_COMPLEX_WORKFLOWS = {
    ".github/workflows/qualify-linux-php-initial.yml": "c94aa78f856940b71ce21476caf1f9f826375f11499d54759c81a79467acd1eb",
    CI_WORKFLOW: "d5b32d7b2868638e09b7deea1d3cab4bcbd3b4601fd9120da0be55319540eff7",
    SONAR_WORKFLOW: "0dd432a52b1dcb6ef10b6e25404163b285deaa651a92219456eabec18514067b",
    ".github/workflows/protected-policy.yml": "642d204ea939ca5eba7ef51be9e4ae56a35177413caabe849315086d3d9d2d31",
    ".github/workflows/rust-docs-visual.yml": "69bc0b89cdeacbabd35c345770de86fe9e20bb3f2a53fc1c7a157973c3db31a6",
    ".github/workflows/cancellation-competitors.yml": "9ce25bd480c899e52a7e805fd6e5e6d45fcaa687c8c25b092d1f2163baf0b0b5",
}
# Exact source-CI successors keep the approved immutable trust bootstrap while
# the new private-pip implementation is qualified separately. These are inert
# future workflow identities; candidate text never supplies an expected digest.
REVIEWED_SOURCE_CI_SUCCESSORS = {
    CI_WORKFLOW: "f0546eeeeec386042088cb5eb2ff36caedf9517726c06d030a0b1e275b94fb55",
    SONAR_WORKFLOW: "10af0ec0dcec58368a8261188e9e2fb1c3c91736d39502863e7aa57914e99fbe",
}
# The successor remains inert until its separate runtime pin and manual-only
# workflow integration. Keep the consumed predecessor's identity unchanged.
REVIEWED_INITIAL_PROFILE_SUCCESSORS = {
    ".github/workflows/qualify-linux-php-initial.yml": "d3eefa3cce62b0c92ae07d6e6a1617342b843e9b5fb0ddad6ad6be4c1c4a2f9f",
}
REVIEWED_NORMALIZED_PROFILE_SUCCESSORS = {
    ".github/workflows/qualify-linux-php-initial.yml": "52fa0e223464e06bd7e10f0b57076557f350353dcfedb1235b0829e0121134ac",
}

# AI's existing matrix commands are reviewed only for that repository. They do
# not enlarge the control repository's complex-workflow exceptions.
REVIEWED_AI_WORKFLOWS = {
    CI_WORKFLOW: "bb67cff8534c78269aa4a0025c3d28056b0ce6f81d8ec8e8b146e13fb9216aa3",
    SONAR_WORKFLOW: "350ab6c80ad7e83702d4afb4215652affa226bed2e33401ad6fab594ec37d9b6",
}


def reviewed_context_hashes(policy_target: str) -> dict[str, set[str]]:
    if policy_target == "github-control-plane":
        registries = (REVIEWED_COMPLEX_WORKFLOWS, REVIEWED_SOURCE_CI_SUCCESSORS,
                      REVIEWED_INITIAL_PROFILE_SUCCESSORS, REVIEWED_NORMALIZED_PROFILE_SUCCESSORS)
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


def validate_context(files: dict[str, bytes], *, policy_target: str = "github-control-plane") -> None:
    reviewed_hashes = reviewed_context_hashes(policy_target)
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
