#!/usr/bin/env python3
"""Proposed shared setup entrypoint. No workflow invokes it before review.

The trusted first stage replaces itself with a closed-environment process.
The ordinary setup body then uses the exact source/data recipe. There is no
retry, fallback acquisition, background controller or credentialed parent.
"""

from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from urllib.error import HTTPError, URLError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts import php_linux_archive as archive
from scripts import php_linux_bootstrap as bootstrap
from scripts import php_linux_recipe as recipe
from scripts import php_linux_tools as tools


CA_SHA256 = "50f79f98dac192b20dbf73f35c56f0b0c557ab267ff5199d1117cc1180b70785"


def failure_details(error):
    """Keep native failure cause/status without URLs, commands or credentials."""
    cause = (error.reason if isinstance(error, URLError) and isinstance(error.reason, BaseException)
             else error.__cause__ or error)
    result = {"failure_type": type(error).__name__, "cause_type": type(cause).__name__}
    for name in ("errno", "verify_code", "verify_message", "returncode"):
        value = getattr(cause, name, None)
        if type(value) in (int, str):
            result[name] = value[:240] if isinstance(value, str) else value
    if isinstance(error, HTTPError):
        result["http_status"] = error.code
    if isinstance(error, ValueError):
        result["reason"] = str(error).replace("\r", " ").replace("\n", " ")[:300]
    return result


def initial_profile(plan, host):
    values = plan["request"]["inputs"]
    if (host != {"operating_system": "ubuntu", "release": "26.04", "architecture": "x86_64"}
            or values["php-version"] != "8.3" or values["extensions"] or values["coverage"] != "none"
            or {row["name"] for row in plan["tools"]} != {"composer", "phpunit"}):
        raise ValueError("Initial no-APT profile is Ubuntu26.04/x64 PHP8.3, both literal PHARs, coverage none and no extension override")


def checked_root(path: Path):
    metadata = path.lstat()
    if (not path.is_absolute() or path.is_symlink() or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise ValueError("Setup state must remain an owned private directory")
    return path


def reexec(parent: dict, execute=os.execve):
    request = recipe.capture_request(parent)
    runner_temp = Path(parent.get("RUNNER_TEMP", ""))
    if not runner_temp.is_absolute() or not runner_temp.is_dir() or runner_temp.is_symlink():
        raise ValueError("An existing absolute runner-owned temporary directory is required")
    node = Path(parent.get("DW_SETUP_NODE_BINARY", ""))
    if not node.is_absolute() or not parent.get("DW_SETUP_NODE_VERSION", "").startswith("v24."):
        raise ValueError("The existing runner action Node24 authority is required")
    os.umask(0o077)
    state = Path(tempfile.mkdtemp(prefix="dw-php-setup-", dir=runner_temp))
    for name in ("home", "tmp"):
        (state / name).mkdir(mode=0o700)
    request["host_tool"] = {"node": str(node), "node_version": parent["DW_SETUP_NODE_VERSION"],
                            "node_sha256": bootstrap.sha256(node.read_bytes())}
    (state / "request.json").write_text(json.dumps(request))
    environment = bootstrap.clean_environment(parent, str(state / "home"))
    execute("/usr/bin/python3", ["/usr/bin/python3", "-I", "-S", "-B", str(Path(__file__).resolve()), "setup", str(state)],
            environment)


def run_setup(state: Path, request: dict, node: dict, environment: dict, *,
              asset_fetch=bootstrap.download_held, tool_fetch=tools.download_held,
              inspect_archive=archive.inspect_held, install_php=bootstrap.run_held_installer,
              verify_php=archive.verify_installed, confirm_extensions=archive.verify_enabled,
              install_tool=tools.install_held, execute=subprocess.run):
    """Complete effect recipe; focused tests substitute all external effects."""
    if environment != bootstrap.clean_environment(environment, str(state / "home")) or dict(os.environ) != environment:
        raise ValueError("Setup requires an already closed parent environment before reading inputs")
    checked_root(state)
    catalog = json.loads(bootstrap.CATALOG.read_text())
    tool_catalog = json.loads(tools.CATALOG.read_text())
    host = bootstrap.observed_host()
    plan = recipe.validate_request(request, catalog, tool_catalog, host)
    initial_profile(plan, host)
    if environment.get("RUNNER_ENVIRONMENT") == "self-hosted" or not environment.get("ImageOS"):
        raise ValueError("Initial setup qualification requires an actual hosted runner image")
    files = recipe.verified_source()
    if environment.get("DW_CI_CA_SHA256") != CA_SHA256:
        raise ValueError("The authenticated shared bootstrap CA predecessor is missing or differs")
    context = bootstrap.explicit_trust(Path(environment.get("SSL_CERT_FILE", "")), CA_SHA256)
    if (not Path(environment.get("SSL_CERT_DIR", "")).is_dir()
            or Path(environment["SSL_CERT_DIR"]).is_symlink()
            or any(Path(environment["SSL_CERT_DIR"]).iterdir())):
        raise ValueError("The shared empty additional-root directory is missing or populated")
    refusal = state / "refusal"
    runtime = state / "upstream"
    derived = recipe.derive_source(files, refusal)
    source_hashes = recipe.write_runtime(runtime, derived)
    report = {"schema": "durable-workflow.php-linux-setup-receipt/v1", "outcome": "running",
              "host": host, "image": {key: environment.get(key) for key in ("ImageOS", "ImageVersion")},
              "apt": {"invoked": False, "profile": "no-apt"}, "ca_sha256": CA_SHA256,
              "request": request, "host_tool": node,
              "setup_php_commit": bootstrap.SOURCE_COMMIT, "source_hashes": source_hashes,
              "preinstalled_authority": False, "tools": []}
    try:
        with ExitStack() as stack:
            report["stage"] = "installer-read"
            original = stack.enter_context(asset_fetch(catalog["installer"], context))
            report["stage"] = "archive-read"
            held_archive = stack.enter_context(asset_fetch(plan["archive"]["asset"], context))
            report["stage"] = "tool-reads"
            held_tools = [(row, stack.enter_context(tool_fetch(row, context))) for row in plan["tools"]]
            original.assert_sealed()
            source = os.pread(original.descriptor, original.identity["size"], 0)
            patched = bootstrap.no_apt_installer_source(source, catalog)
            identity = dict(catalog["installer"], name="bound-install.sh", size=len(patched),
                            digest="sha256:" + bootstrap.sha256(patched))
            script = stack.enter_context(bootstrap.hold_bytes(io.BytesIO(patched), identity, original.effective))
            report["stage"] = "archive-inspection"
            members = inspect_archive(held_archive)
            report.update(installer=dict(original.identity, derived_sha256=bootstrap.sha256(patched)),
                          archive=dict(held_archive.identity, effective=held_archive.effective))
            # Always install the bound tuple before any product PHP probe.
            # An ambient preinstalled PHP binary is never an archive receipt.
            report["stage"] = "bound-installer"
            install_php(script, held_archive, (request["inputs"]["php-version"], "release", "nts"),
                        environment, catalog, no_apt=True)
            report["stage"] = "installed-file-binding"
            report["installed"] = verify_php(members, request["inputs"]["php-version"],
                                               plan["required_extensions"])
            if bootstrap.sha256(Path(node["node"]).read_bytes()) != node["node_sha256"]:
                raise ValueError("Runner action Node executable changed after the closed reexec")
            report["stage"] = "pinned-upstream"
            execute([node["node"], str(runtime / "dist/index.js")],
                    env=recipe.runtime_environment(plan, environment), cwd=state, timeout=120, check=True)
            if refusal.exists():
                raise ValueError("Pinned setup reached a refused acquisition/repair path")
            report["stage"] = "configured-extensions"
            report["configured"] = confirm_extensions(members, request["inputs"]["php-version"],
                plan["required_extensions"], request["inputs"]["coverage"])
            for row, held in held_tools:
                report["stage"] = "tool-install-" + row["name"]
                report["tools"].append(install_tool(held, row, environment))
            report.update(outcome="pass", stage="complete")
            return report
    except Exception as error:
        # Record all terminal failures, then propagate them. A library-format
        # error must not leave a receipt claiming the attempt is still running.
        report.update(outcome="refused", **failure_details(error))
        raise
    finally:
        (state / "receipt.json").write_text(json.dumps(report, sort_keys=True) + "\n")
        shutil.rmtree(runtime)


def main(arguments):
    if arguments == ["reexec"]:
        reexec(dict(os.environ))
        raise RuntimeError("Closed execve unexpectedly returned")
    if len(arguments) != 2 or arguments[0] != "setup":
        raise ValueError("Only the trusted closed reexec entrypoint is supported")
    state = checked_root(Path(arguments[1]))
    environment = dict(os.environ)
    if environment != bootstrap.clean_environment(environment, str(state / "home")):
        raise ValueError("Inherited environment is not closed; refusing before reading setup inputs")
    request_path = state / "request.json"
    if request_path.is_symlink() or request_path.stat().st_uid != os.getuid() or request_path.stat().st_size > 32768:
        raise ValueError("Setup request is not its private owned input")
    request = json.loads(request_path.read_text())
    node = request.pop("host_tool")
    try:
        run_setup(state, request, node, environment)
        with Path(environment["GITHUB_OUTPUT"]).open("a") as output:
            output.write(f"bootstrap-receipt={state / 'receipt.json'}\n")
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        if not (state / "receipt.json").exists():
            (state / "receipt.json").write_text(json.dumps({"outcome": "refused", "stage": "preflight",
                **failure_details(error)}) + "\n")
        raise
    finally:
        request_path.unlink()
        shutil.rmtree(state / "home")
        shutil.rmtree(state / "tmp")


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        print("Bound PHP setup refused: " + json.dumps(failure_details(error), sort_keys=True), file=sys.stderr)
        raise SystemExit(1)
