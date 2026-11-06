"""Unwired initial-profile terminal evidence; no acquisition or root operations."""

from contextlib import contextmanager, ExitStack
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess

from scripts import php_linux_archive as archive
from scripts import php_linux_bootstrap as bootstrap
from scripts import php_linux_recipe as recipe
from scripts import php_linux_tools as tools
from scripts import setup_php_linux as setup
from scripts import php_linux_normalize as normalization
from scripts import php_linux_alternatives


MAX_RECEIPT = setup.MAX_RECEIPT
TOOL_DIRECTORY = "/usr/local/bin/"
PASS_FIELDS = frozenset(("schema", "outcome", "stage", "host", "image", "apt", "ca_sha256",
    "request", "host_tool", "setup_php_commit", "source_hashes", "preinstalled_authority",
    "tools", "installer", "archive", "installed", "configured", "subjects"))
NORMALIZED_PASS_FIELDS = PASS_FIELDS | {'normalization', 'normalization_manifest'}
_PIP_SPEC = importlib.util.spec_from_file_location("qualification_private_pip",
    bootstrap.ROOT / ".github/actions/bootstrap-patched-pip/pip_runtime.py")
private_pip = importlib.util.module_from_spec(_PIP_SPEC)
_PIP_SPEC.loader.exec_module(private_pip)


def unique_mapping(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Terminal receipt contains duplicate fields")
        result[key] = value
    return result


def canonical_path(value):
    if (not isinstance(value, str) or len(value) > 4096 or not value.startswith("/")
            or PurePosixPath(value).as_posix() != value or ".." in value.split("/")
            or any(character in value for character in "\0\r\n\\")):
        raise ValueError("Subject path is not canonical")
    return value


def file_identity(value):
    bootstrap.exact_keys(value, {"type", "size", "sha256", "authority"})
    if (value["type"] != "regular" or type(value["size"]) is not int
            or not 0 <= value["size"] <= archive.MAX_UNPACKED
            or not isinstance(value["sha256"], str)
            or not re.fullmatch(tools.SHA256_PATTERN, value["sha256"])):
        raise ValueError("Terminal subject has an invalid regular-file identity")


def validate_manifest(report, plan):
    manifest = report["subjects"]
    bootstrap.exact_keys(manifest, {"schema", "files", "commands", "configs"})
    if (manifest["schema"] != archive.SUBJECT_SCHEMA or not isinstance(manifest["files"], dict)
            or not manifest["files"] or not isinstance(manifest["configs"], dict)):
        raise ValueError("Producer subject manifest is incomplete")
    archive.require_subject_bound(manifest)
    php = plan["request"]["inputs"]["php-version"]
    if manifest["commands"] != {"php": f"/usr/bin/php{php}", "php-config": f"/usr/bin/php-config{php}"}:
        raise ValueError("Producer default commands are not bound to the selected archive")
    selected = {row["name"]: row for row in plan["tools"]}
    validate_manifest_files(manifest, selected, php,
        normalized=report['schema'] == setup.NORMALIZED_RECEIPT_SCHEMA)
    validate_manifest_binary(report, manifest, php)
    validate_manifest_tools(manifest, plan["tools"])


def validate_manifest_files(manifest, selected, php, *, normalized=False):
    for path, identity in manifest["files"].items():
        canonical_path(path)
        file_identity(identity)
        validate_subject_authority(path, identity, selected, php, normalized=normalized)
    for path, target in manifest["configs"].items():
        canonical_path(path)
        canonical_path(target)
        if not path.startswith(f"/etc/php/{php}/cli/") or target not in manifest["files"]:
            raise ValueError("Active configuration lacks a producer-bound subject")


def validate_manifest_binary(report, manifest, php):
    binary = report["installed"]["binary"]
    if binary != {"source": f"usr/bin/php{php}", **{
            key: manifest["files"].get(f"/usr/bin/php{php}", {}).get(key) for key in ("size", "sha256")}}:
        raise ValueError("Installed PHP receipt differs from its producer manifest")


def validate_manifest_tools(manifest, selected):
    for row in selected:
        expected = {"type": "regular", "size": row["size"], "sha256": row["sha256"],
                    "authority": {"kind": "tool", "name": row["name"]}}
        if manifest["files"].get(TOOL_DIRECTORY + row["name"]) != expected:
            raise ValueError("Both literal PHAR subjects are mandatory")


def validate_subject_authority(path, identity, selected, php, *, normalized=False):
    authority = identity["authority"]
    if not isinstance(authority, dict):
        raise ValueError("Subject authority is missing")
    kind = authority.get("kind")
    if kind == "tool":
        bootstrap.exact_keys(authority, {"kind", "name"})
        row = selected.get(authority["name"])
        if (row is None or path != TOOL_DIRECTORY + row["name"]
                or identity["size"] != row["size"] or identity["sha256"] != row["sha256"]):
            raise ValueError("PHAR subject lacks literal tool-catalog authority")
        return
    if kind == 'normalized-archive':
        bootstrap.exact_keys(authority, {'kind', 'member', 'source_member', 'target_size',
            'target_sha256', 'target_metadata_sha256'})
        if (not normalized or authority['member'] != path.lstrip('/')
                or authority['target_size'] != identity['size'] or authority['target_sha256'] != identity['sha256']
                or not isinstance(authority['source_member'], str)
                or not re.fullmatch(tools.SHA256_PATTERN, authority['target_metadata_sha256'])):
            raise ValueError('Normalized subject lacks its exact source-target authority')
        return
    bootstrap.exact_keys(authority, {"kind", "member"})
    if authority["member"] != path.lstrip("/") or kind not in ("archive", "derived-redis"):
        raise ValueError("Subject lacks canonical held-archive member authority")
    if kind == "derived-redis":
        name = f"etc/php/{php}/mods-available/redis.ini"
        expected = archive.configuration_members({}, php)[name]
        if authority["member"] != name or any(identity[key] != expected[key] for key in expected):
            raise ValueError("Derived configuration lacks its exact source recipe")


def validate_success(report, state):
    normalized = isinstance(report, dict) and report.get('schema') == setup.NORMALIZED_RECEIPT_SCHEMA
    expected_fields = NORMALIZED_PASS_FIELDS if normalized else PASS_FIELDS
    if not isinstance(report, dict) or set(report) != expected_fields:
        raise ValueError("Complete successful setup receipt is required")
    if (report["schema"] not in (setup.RECEIPT_SCHEMA, setup.NORMALIZED_RECEIPT_SCHEMA) or report["outcome"] != "pass"
            or report["stage"] != "complete" or report["preinstalled_authority"] is not False
            or report["apt"] != {"invoked": False, "profile": "no-apt"}
            or report["ca_sha256"] != setup.CA_SHA256
            or report["setup_php_commit"] != bootstrap.SOURCE_COMMIT):
        raise ValueError("Setup receipt does not establish a completed bound profile")
    catalog = json.loads(bootstrap.CATALOG.read_text())
    tool_catalog = json.loads(tools.CATALOG.read_text())
    plan = recipe.validate_request(report["request"], catalog, tool_catalog, report["host"])
    setup.initial_profile(plan, report["host"])
    validate_runtime_receipt(report, plan)
    validate_source_receipts(report, state, plan, catalog)
    validate_manifest(report, plan)
    return plan


def validate_normalized_subjects(manifest, document):
    for path, identity in manifest['files'].items():
        authority = identity['authority']
        if authority['kind'] in ('tool', 'derived-redis'):
            continue
        name = path.lstrip('/')
        if name not in document['files'] or {key: identity[key] for key in ('size', 'sha256')} != document['files'][name]:
            raise ValueError('Installed subject differs from the complete derived manifest')
        target = document['targets'].get(name)
        expected = {'kind': 'archive', 'member': name}
        if target is not None:
            expected = {'kind': 'normalized-archive', 'member': name, 'source_member': target['target'],
                'target_size': target['size'], 'target_sha256': target['sha256'],
                'target_metadata_sha256': bootstrap.sha256(normalization.canonical_json(target['metadata']))}
        if authority != expected:
            raise ValueError('Installed subject lost its original archive-target provenance')


def validate_runtime_receipt(report, plan):
    validate_image_tool(report)
    validate_installed_tuple(report["installed"], plan["request"]["inputs"]["php-version"])
    validate_configured(report["configured"])


def validate_image_tool(report):
    bootstrap.exact_keys(report["image"], {"ImageOS", "ImageVersion"})
    if any(not isinstance(value, str) or not 0 < len(value) <= 128 for value in report["image"].values()):
        raise ValueError("Hosted image identity is incomplete")
    host_tool = report["host_tool"]
    bootstrap.exact_keys(host_tool, {"node", "node_version", "node_sha256"})
    canonical_path(host_tool["node"])
    if (not re.fullmatch(r"v24\.\d+\.\d+", host_tool["node_version"])
            or not re.fullmatch(tools.SHA256_PATTERN, host_tool["node_sha256"])):
        raise ValueError("Producer Node identity is incomplete")


def validate_installed_tuple(installed, php):
    bootstrap.exact_keys(installed, {"binary", "extensions", "version", "zts", "debug"})
    if (not isinstance(installed["version"], str) or not installed["version"].startswith(php + ".")
            or any(type(installed[key]) is not int or installed[key] != 0 for key in ("zts", "debug"))
            or installed["extensions"] != {}):
        raise ValueError("Installed PHP tuple is not the initial NTS/release profile")
    bootstrap.exact_keys(installed["binary"], {"source", "size", "sha256"})


def validate_configured(configured):
    bootstrap.exact_keys(configured, {"loaded_extensions", "coverage"})
    loaded = configured["loaded_extensions"]
    if (configured["coverage"] != "none" or not isinstance(loaded, list)
            or not loaded or any(not isinstance(name, str) or not 0 < len(name) <= 100 for name in loaded)
            or loaded != sorted(set(loaded)) or set(loaded) & {"pcov", "xdebug"}):
        raise ValueError("Configured modules/coverage identity is incomplete")


def validate_source_receipts(report, state, plan, catalog):
    original = (bootstrap.ROOT / "qualification/vendor/php-ubuntu-713206915/install.sh").read_bytes()
    patched = bootstrap.no_apt_installer_source(original, catalog)
    if report["installer"] != dict(catalog["installer"], derived_sha256=bootstrap.sha256(patched)):
        raise ValueError("Installer receipt differs from its literal/derived identity")
    received = report["archive"]
    bootstrap.exact_keys(received, {*plan["archive"]["asset"], "effective"})
    if any(received[key] != value for key, value in plan["archive"]["asset"].items()):
        raise ValueError("Archive receipt differs from its literal selected asset")
    effective = received["effective"]
    bootstrap.exact_keys(effective, {"scheme", "host", "path", "url_sha256"})
    if (effective["scheme"] != "https" or effective["host"] not in bootstrap.REDIRECT_HOSTS
            or not isinstance(effective["path"], str) or not effective["path"].startswith("/")
            or not re.fullmatch(r"[a-f0-9]{64}", effective["url_sha256"])):
        raise ValueError("Archive receipt has no approved HTTPS handoff")
    expected_sources = {name: bootstrap.sha256(data) for name, data in
                        recipe.derive_source(recipe.verified_source(), state / "refusal").items()}
    if report["source_hashes"] != expected_sources:
        raise ValueError("Derived source closure differs from the original setup recipe")
    expected_tools = [{"target": TOOL_DIRECTORY + row["name"], **tools.identity(row)} for row in plan["tools"]]
    if report["tools"] != expected_tools:
        raise ValueError("Installed tool receipts differ from both literal catalogs")


def object_identity(metadata):
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid, metadata.st_nlink,
            metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns)


def require_receipt_metadata(metadata):
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= MAX_RECEIPT):
        raise ValueError("Action-output receipt has invalid ownership/type/size")


@contextmanager
def capture_receipt(path, runner_temp):
    """Use the exact action output, retaining its original object and sealed bytes."""
    checked_state(path, runner_temp)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        metadata = os.fstat(descriptor)
        require_receipt_metadata(metadata)
        raw = os.read(descriptor, MAX_RECEIPT + 1)
        identity = {"size": len(raw), "digest": "sha256:" + hashlib.sha256(raw).hexdigest()}
        if len(raw) != metadata.st_size or object_identity(os.fstat(descriptor)) != object_identity(metadata):
            raise ValueError("Receipt changed during capture")
        report = json.loads(raw, object_pairs_hook=unique_mapping)
        with bootstrap.hold_bytes(io.BytesIO(raw), identity,
                {"device": metadata.st_dev, "inode": metadata.st_ino}) as held:
            yield report, held, lambda: unchanged_receipt(path, descriptor, metadata, raw)
    finally:
        os.close(descriptor)


def checked_state(path, runner_temp):
    if path is None:
        raise ValueError("Exact steps.setup output receipt is missing; no discovery/fallback")
    state = path.parent
    if (not runner_temp.is_absolute() or runner_temp.is_symlink() or not runner_temp.is_dir()
            or path.name != setup.RECEIPT_NAME or state.parent != runner_temp
            or not state.name.startswith("dw-php-setup-")):
        raise ValueError("Receipt is not the exact owned setup-state output")
    setup.checked_root(state)
    return state


def unchanged_receipt(path, descriptor, metadata, raw):
    if (object_identity(path.lstat()) != object_identity(metadata)
            or object_identity(os.fstat(descriptor)) != object_identity(metadata)
            or os.pread(descriptor, MAX_RECEIPT + 1, 0) != raw):
        raise ValueError("Original setup receipt object or bytes changed after capture")


def revalidate_subjects(report, plan, *, capture=archive.capture_subjects, append=tools.append_subject,
                        enabled=archive.verify_enabled, normalization_targets=None):
    files = {path.lstrip("/"): {key: identity[key] for key in ("size", "sha256")}
             for path, identity in report["subjects"]["files"].items()
             if identity["authority"]["kind"] != "tool"}
    php = plan["request"]["inputs"]["php-version"]
    options = {} if normalization_targets is None else {'normalization_targets': normalization_targets}
    installed, manifest = capture(files, php, plan["required_extensions"], **options)
    for row in plan["tools"]:
        append(manifest, row)
    if installed != report["installed"] or manifest != report["subjects"]:
        raise ValueError("Installed PHP/configuration/module/PHAR subjects changed")
    if enabled(files, php, plan["required_extensions"], "none") != report["configured"]:
        raise ValueError("Configured PHP modules changed")


def run_probes(plan, environment, execute=subprocess.run):
    binary = "/usr/bin/php" + plan["request"]["inputs"]["php-version"]
    observations = []
    for row in plan["tools"]:
        arguments = [binary, TOOL_DIRECTORY + row["name"]]
        if row["name"] == "composer":
            arguments += ["--no-plugins", "--no-scripts", "--version", "--no-ansi", "--no-interaction"]
        else:
            arguments += ["--version"]
        result = execute(arguments, env=dict(environment, COMPOSER_DISABLE_NETWORK="1"),
            cwd=environment["HOME"], capture_output=True, text=True, timeout=10, check=True)
        prefix = ("Composer version " if row["name"] == "composer" else "PHPUnit ") + row["version"] + " "
        if len(result.stdout.encode()) > 65536 or not result.stdout.startswith(prefix):
            raise ValueError("Installed PHAR version probe did not match its exact tuple")
        observations.append({"name": row["name"], "version": row["version"],
            "stdout_sha256": bootstrap.sha256(result.stdout.encode()),
            "first_line": result.stdout.splitlines()[0][:512]})
    return observations


def pip_ownership(data, runner_temp):
    if data is None:
        return None
    bootstrap.exact_keys(data, {"receipt", "root_identity", "receipt_identity", "created"})
    if data["created"] != "true":
        raise ValueError("Initial qualification requires its newly created exact private pip state")
    state = private_pip.producer_state(data["receipt"], data["root_identity"], runner_temp)
    return {"state": state, "receipt_identity": data["receipt_identity"]}


def producer_receipt_identity(raw):
    if not isinstance(raw, str) or len(raw) > 4096:
        raise ValueError("Private pip producer receipt identity exceeds its bound")
    identity = json.loads(raw, object_pairs_hook=unique_mapping)
    fields = {"device", "inode", "mode", "owner", "links", "size", "mtime_ns", "ctime_ns", "sha256"}
    bootstrap.exact_keys(identity, fields)
    if (any(type(identity[name]) is not int or identity[name] < 0 for name in fields - {"sha256"})
            or identity["owner"] != os.getuid() or identity["mode"] != 0o600 or identity["links"] != 1
            or not 0 < identity["size"] <= private_pip.MAX_FILE
            or not isinstance(identity["sha256"], str) or re.fullmatch(r"[a-f0-9]{64}", identity["sha256"]) is None):
        raise ValueError("Private pip producer receipt identity is invalid")
    return identity


@contextmanager
def capture_private_pip(owned, runner_temp):
    if owned is None:
        yield None
        return
    state = owned["state"]
    expected_identity = producer_receipt_identity(owned["receipt_identity"])
    summary = {}
    try:
        with private_pip.held_file(state.receipt, owned=True) as (_raw, identity):
            if identity != expected_identity:
                raise ValueError("Private pip receipt differs from its pre-product producer object/bytes")
            report, subjects = private_pip.verify_runtime(state.receipt, runner_temp, require_trust=True)
            if report["root_identity"] != state.identity:
                raise ValueError("Private pip root differs from its exact producer allocation")
            if not isinstance(subjects, dict) or not subjects:
                raise ValueError("Private pip has no wheel-derived installed subject inventory")
            summary.update(schema="durable-workflow.private-pip-terminal/v1", receipt_sha256=identity["sha256"],
                receipt_object=identity, root_identity=state.identity, pip_version=private_pip.VERSION,
                python_version=report["interpreter"]["version"], wheel_sha256=private_pip.WHEEL_SHA256,
                ca_sha256=private_pip.CA_SHA256, subject_count=len(subjects), revalidated=False)
            try:
                yield summary
            finally:
                current, current_subjects = private_pip.verify_runtime(state.receipt, runner_temp, require_trust=True)
                if current != report or current_subjects != subjects:
                    raise ValueError("Private pip receipt or wheel-derived installed subjects changed after probes")
                summary["revalidated"] = True
    except BaseException:
        summary["revalidated"] = False
        raise


def qualify(path, runner_temp, environment, publish, *, validate=validate_success,
            subjects=revalidate_subjects, probes=run_probes, pip_state=None,
            alternatives=php_linux_alternatives.verify):
    if (environment != bootstrap.clean_environment(environment, environment.get("HOME", ""))
            or dict(os.environ) != environment):
        raise ValueError("Qualification requires a closed parent environment")
    owned_pip = None
    state, state_identity = None, None
    evidence = {"schema": "durable-workflow.php-linux-terminal/v1", "outcome": "refused", "stage": "capture"}
    verified = False
    try:
        try:
            state = checked_state(path, runner_temp)
            state_identity = object_identity(state.lstat())[:4]
        finally:
            # A missing or unproven setup receipt must not strand the separately
            # proven pip allocation. Invalid pip data still leaves it unowned.
            owned_pip = pip_ownership(pip_state, runner_temp)
        with ExitStack() as normalization_custody, capture_private_pip(owned_pip, runner_temp) as pip_report, \
                capture_receipt(path, runner_temp) as (report, held, unchanged):
            if pip_report is not None:
                evidence["private_pip"] = pip_report
            evidence.update(receipt_sha256=held.identity["digest"], receipt_object=held.effective,
                            stage="validate")
            if isinstance(report, dict):
                evidence["producer_terminal"] = {
                    key: value for key, value in report.items()
                    if key in {"outcome", "stage", "failure_type", "cause_type", "http_status", "returncode"}
                    and (type(value) is int or isinstance(value, str) and len(value) <= 100)}
            plan = validate(report, state)
            normalized_unchanged = None
            normalized_held = None
            if report['schema'] == setup.NORMALIZED_RECEIPT_SCHEMA:
                document, normalized_held, normalized_unchanged = normalization_custody.enter_context(
                    normalization.capture_manifest(state, report['normalization_manifest']))
                normalization.validate_document(document, report['normalization'], plan['archive']['asset'])
                validate_normalized_subjects(report['subjects'], document)
                evidence['alternatives'] = dict(alternatives(document['files']), revalidated=False)
                evidence['normalization'] = {'schema': normalization.DOCUMENT_SCHEMA,
                    'manifest_object': normalized_held.effective, 'manifest_sha256': normalized_held.identity['digest'],
                    'derived': report['normalization']['derived'], 'revalidated': False}
            subject_options = {} if normalized_held is None else {'normalization_targets': document['targets']}
            subjects(report, plan, **subject_options)
            evidence["stage"] = "probes"
            try:
                evidence["probes"] = probes(plan, environment)
            finally:
                unchanged()
                held.assert_sealed()
                subjects(report, plan, **subject_options)
                if normalized_held is not None:
                    if alternatives(document['files']) != {
                            key: value for key, value in evidence['alternatives'].items() if key != 'revalidated'}:
                        raise ValueError('Installed alternatives authority changed after probes')
                    evidence['alternatives']['revalidated'] = True
                    normalized_unchanged()
                    normalized_held.assert_sealed()
                    evidence['normalization']['revalidated'] = True
            evidence["receipt"] = report
        verified = True
    except Exception as error:
        evidence.update(**setup.failure_details(error))
        raise
    finally:
        finish_terminal(state, state_identity, evidence, verified, publish, pip_state=owned_pip)


def cleanup_state(state, expected):
    if state is None or object_identity(state.lstat())[:4] != expected:
        raise ValueError("Exact owned setup state changed; cleanup refused")
    setup.checked_root(state)
    shutil.rmtree(state)
    if os.path.lexists(state):
        raise ValueError("Exact owned setup state remains after cleanup")


def cleanup_terminal_states(state, expected, pip_state):
    failures = {}
    if pip_state is not None:
        owned = pip_state["state"]
        try:
            private_pip.cleanup_runtime(owned.root, owned.root.parent, owned.identity)
        except Exception as error:
            failures["private_pip"] = error
    try:
        cleanup_state(state, expected)
    except Exception as error:
        failures["setup"] = error
    return failures


def finish_terminal(state, expected, evidence, verified, publish, *, pip_state=None):
    failures = cleanup_terminal_states(state, expected, pip_state)
    if pip_state is not None:
        evidence["private_pip_cleanup"] = "refused" if "private_pip" in failures else "pass"
    if failures:
        error = next(iter(failures.values()))
        evidence.update(outcome="refused", stage="cleanup", cleanup="refused",
                        cleanup_failure=setup.failure_details(error),
                        cleanup_failures={name: setup.failure_details(value) for name, value in failures.items()})
        publish(evidence)
        raise error
    evidence["cleanup"] = "pass"
    if "private_pip" in evidence:
        evidence["private_pip"]["cleanup"] = "pass"
    if verified:
        evidence.update(outcome="pass", stage="complete")
    publish(evidence)
