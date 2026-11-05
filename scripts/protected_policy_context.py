"""Conservative input language for the protected pilot, not ordinary preflight.

Candidate text is data. Unsupported execution contexts refuse instead of
extending the shared validator into a shell interpreter.
"""

from __future__ import annotations

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
DIRECTORY_OR_EVALUATION_WORDS = {"cd", "pushd", "popd", "eval", "source", "."}
STARTUP_ENVIRONMENT = {"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "LD_PRELOAD"}


def unsupported_shell(source: str) -> bool:
    if "`" in source or "$(" in source:
        return True
    try:
        words = shlex.shlex(source.replace("\\\n", ""), posix=True, punctuation_chars=";&|()\n")
        words.whitespace = " \t\r"
        words.whitespace_split = True
        # This is a conservative word check, not command-position inference.
        # In particular, --source and --source-repository are ordinary flags.
        return any(word in DIRECTORY_OR_EVALUATION_WORDS for word in words)
    except ValueError:
        return True


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


def check_helpers(source: str, files: dict[str, bytes], visited: set[str]) -> None:
    for reference in HELPERS.findall(source):
        name = checked_path(reference.removeprefix("./"))
        if name not in files or name in visited:
            continue
        visited.add(name)
        text = files[name].decode("utf-8")
        suffix = PurePosixPath(name).suffix
        if suffix in {"", ".sh", ".bash", ".ksh", ".zsh"} or re.match(r"^#![^\n]*\b(?:bash|sh|dash|ksh|zsh)\b", text):
            if unsupported_shell(text):
                raise InputRefused("Protected pilot helper has an unsupported directory or dynamic shell context")
            check_helpers(text, files, visited)


def validate_helper_step(document, job, step, files):
    if not isinstance(step, dict):
        raise InputRefused("Protected pilot requires step mappings")
    source = step.get("run", "")
    if not isinstance(source, str):
        raise InputRefused("Protected pilot requires literal run text")
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
        if not isinstance(environment, dict) or STARTUP_ENVIRONMENT.intersection(environment):
            raise InputRefused("Protected pilot helper startup environment is unsupported")
    if unsupported_shell(source):
        raise InputRefused("Protected pilot relative helpers have an unsupported directory or dynamic shell context")
    check_helpers(source, files, set())


def validate_context(files: dict[str, bytes]) -> None:
    for name, raw in sorted(files.items()):
        if PurePosixPath(name).parent.as_posix() != ".github/workflows" or not name.endswith((".yml", ".yaml")):
            continue
        document = bounded_document(raw.decode("utf-8"))
        jobs = document.get("jobs", {})
        if not isinstance(jobs, dict):
            raise InputRefused("Protected pilot requires a jobs mapping")
        for job in jobs.values():
            if not isinstance(job, dict) or not isinstance(job.get("steps", []), list):
                raise InputRefused("Protected pilot requires explicit jobs and step lists")
            for step in job.get("steps", []):
                validate_helper_step(document, job, step, files)
