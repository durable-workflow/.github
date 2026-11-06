"""Inert input/source recipe for the Linux setup proposal on central issue 297.

No function in this module downloads data, executes PHP/setup, installs a tool
or performs a root operation. The adapter must separately bind the installed
PHP/module files to the held archive before running the derived upstream code.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shlex

from scripts import php_linux_bootstrap as bootstrap
from scripts import php_linux_tools as tools


UPSTREAM = bootstrap.ROOT / ".github/actions/setup-php-linux/vendor"
MANIFEST = bootstrap.ROOT / "qualification/setup-php-source.json"
INPUTS = ("php-version", "extensions", "ini-file", "ini-values", "coverage", "tools", "fail-fast")
CUSTOM_EXTENSIONS = frozenset(("relay", "blackfire", "pdo_cubrid", "cubrid", "couchbase", "event",
    "gearman", "geos", "ibm_db2", "pdo_ibm", "pdo_oci", "oci8", "http", "pecl_http",
    "pdo_firebird", "ioncube", "phalcon", "phalcon3", "phalcon4", "phalcon5", "sqlsrv",
    "pdo_sqlsrv", "zephir_parser"))
GUARDS = {
    "src/scripts/unix.sh": ("get", "run_script", "self_hosted_setup"),
    "src/scripts/linux.sh": ("self_hosted_helper", "install_packages", "fix_broken_packages",
        "add_extension_helper", "add_php", "add_pecl", "setup_php_builder", "add_packaged_php", "check_package"),
    "src/scripts/extensions/add_extensions.sh": ("configure_pecl", "pecl_install", "get_pecl_version",
        "add_pecl_extension", "add_unstable_extension", "enable_cache_extension_dependencies"),
    "src/scripts/extensions/source.sh": ("fetch_extension", "add_extension_from_source", "add_libs"),
    "src/scripts/tools/ppa.sh": ("update_lists", "update_lists_helper", "add_key", "add_list", "add_ppa",
        "update_ppa", "add_ppa_sp_mirror", "is_ubuntu_ppa_up"),
}


def upstream_env(environment: dict, name: str) -> str:
    # Exact candidate order from pinned utils.readEnv; core.getInput wins first.
    lower, upper = name.lower(), name.upper()
    return next((environment[key] for key in
                 (name, lower, upper, lower.replace("_", "-"), upper.replace("_", "-"))
                 if environment.get(key)), "")


def capture_request(environment: dict) -> dict:
    inputs, origins = {}, {}
    if environment.get("INPUT_GITHUB-TOKEN", "").strip() or upstream_env(environment, "github-token"):
        raise ValueError("This companion has no credential-bearing github-token input")
    if environment.get("INPUT_PHP-VERSION-FILE", "").strip() or upstream_env(environment, "php-version-file"):
        raise ValueError("Initial profile requires an explicit PHP minor instead of version-file discovery")
    for name in INPUTS:
        direct = environment.get("INPUT_" + name.upper(), "").strip()
        indirect = upstream_env(environment, name)
        inputs[name] = direct or indirect
        # INPUT_* also includes action metadata defaults. It cannot prove
        # that a caller explicitly wrote a with: field.
        origin = "omitted"
        if direct:
            origin = "input"
        elif indirect:
            origin = "env"
        origins[name] = origin
    overrides = {name: environment.get(name.lower()) or environment.get(name.upper()) or ""
                 for name in ("update", "debug", "phpts", "runner", "setup_php_tools_dir",
                              "setup_php_tool_cache_dir")}
    # setEnv overwrites lower-case fail_fast from getInput, but unix.read_env
    # still consults the separate uppercase shell fallback when it is empty.
    overrides["FAIL_FAST"] = environment.get("FAIL_FAST", "")
    return {"inputs": inputs, "origins": origins, "overrides": overrides}


def validate_request(request: dict, catalog: dict, tool_catalog: dict, host: dict) -> dict:
    bootstrap.exact_keys(request, {"inputs", "origins", "overrides"})
    bootstrap.exact_keys(request["inputs"], set(INPUTS))
    bootstrap.exact_keys(request["origins"], set(INPUTS))
    bootstrap.exact_keys(request["overrides"], {"update", "debug", "phpts", "runner",
                                               "setup_php_tools_dir", "setup_php_tool_cache_dir", "FAIL_FAST"})
    values = request["inputs"]
    if (any(not isinstance(value, str) or len(value) > 4096 or "\0" in value for value in values.values())
            or any(value not in ("input", "env", "omitted") for value in request["origins"].values())):
        raise ValueError("Unknown setup input representation")
    accepted = {"update": ("", "false"), "debug": ("", "false"), "phpts": ("", "nts"),
                "runner": ("", "github"), "setup_php_tools_dir": ("", "/usr/local/bin"),
                "setup_php_tool_cache_dir": ("",), "FAIL_FAST": ("", "true", "false")}
    if any(request["overrides"][name] not in allowed for name, allowed in accepted.items()):
        raise ValueError("Initial profile has no reviewed update/build/thread/cache/runner override")
    if values["ini-file"] not in ("", "production") or values["ini-values"]:
        raise ValueError("Initial profile supports production INI without additional ini-values")
    if values["fail-fast"] not in ("", "true", "false"):
        raise ValueError("Unsupported fail-fast input")
    if values["coverage"] not in ("", "none", "pcov", "xdebug"):
        raise ValueError("Coverage needs an exact archive-contained driver")
    extensions = []
    if values["extensions"]:
        extensions = [value.strip().lower() for value in values["extensions"].split(",")]
        if (any(not re.fullmatch(r"[a-z][a-z0-9_]*", value) or value in CUSTOM_EXTENSIONS
                or value == "none" for value in extensions) or len(set(extensions)) != len(extensions)):
            raise ValueError("Initial extension profile excludes custom/source/versioned acquisition paths")
    archive = bootstrap.select(catalog, **host, php=values["php-version"])
    selected_tools = tools.select_tools(tool_catalog, values["tools"], values["php-version"])
    required = set(extensions)
    if values["coverage"] in ("pcov", "xdebug"):
        required.add(values["coverage"])
    return {"request": request, "archive": archive, "tools": selected_tools,
            "required_extensions": sorted(required), "upstream_tools": "none"}


def verified_source(root: Path = UPSTREAM, manifest: Path = MANIFEST) -> dict[str, bytes]:
    record = json.loads(manifest.read_text())
    bootstrap.exact_keys(record, {"schema", "repository", "commit", "files"})
    if (record["schema"] != "durable-workflow.setup-php-source/v1"
            or record["repository"] != "shivammathur/setup-php"
            or record["commit"] != bootstrap.SOURCE_COMMIT or not isinstance(record["files"], dict)):
        raise ValueError("Unbound upstream setup source identity")
    paths = [path for path in root.rglob("*") if not path.is_dir() or path.is_symlink()]
    if (root.is_symlink() or any(path.is_symlink() or not path.is_file() for path in paths)
            or {path.relative_to(root).as_posix() for path in paths} != set(record["files"])):
        raise ValueError("Pinned setup source has missing/extra/nonregular members")
    result = {}
    for name, identity in record["files"].items():
        bootstrap.exact_keys(identity, {"size", "sha256", "git_blob"})
        if not re.fullmatch(r"(?:LICENSE|(?:src|dist)/[a-zA-Z0-9_.\-/]+)", name) or ".." in name.split("/"):
            raise ValueError("Unbound setup source member path")
        contents = (root / name).read_bytes()
        blob = hashlib.sha1(b"blob " + str(len(contents)).encode() + b"\0" + contents, usedforsecurity=False).hexdigest()
        if (len(contents) != identity["size"] or bootstrap.sha256(contents) != identity["sha256"]
                or blob != identity["git_blob"]):
            raise ValueError("Pinned setup source member differs from exact Git bytes")
        result[name] = contents
    if "dist/index.js" not in result or not all(name in result for name in GUARDS):
        raise ValueError("Pinned setup runtime closure is incomplete")
    return result


def replace_function(source: str, name: str, body: str) -> str:
    pattern = r"^" + re.escape(name) + r"\(\) \{\n.*?^\}\n"
    matches = list(re.finditer(pattern, source, re.M | re.S))
    if len(matches) != 1:
        raise ValueError("Exact upstream function patch is absent or ambiguous")
    match = matches[0]
    return source[:match.start()] + name + "() {\n" + body + "\n}\n" + source[match.end():]


def derive_source(files: dict[str, bytes], refusal: Path) -> dict[str, bytes]:
    if not refusal.is_absolute() or any(character in str(refusal) for character in "\r\n\0"):
        raise ValueError("A private absolute refusal marker is required")
    guard = ('  printf "%s\\n" "Bound setup refuses unqualified acquisition: $1" >> '
             + shlex.quote(str(refusal)) + '\n  return 78')
    derived = dict(files)
    for name, functions in GUARDS.items():
        source = files[name].decode()
        for function in functions:
            source = replace_function(source, function, f'  _dw_refuse {shlex.quote(function)}')
        if name == "src/scripts/unix.sh":
            # The bound archive is already installed. This no-APT profile has
            # no PPA discovery/update lane and accepts only update=false.
            start = source.index('  # Set Update to true if the ubuntu github image does not have PHP PPA.\n')
            finish = source.index('\n  export fail_fast', start)
            source = source[:start] + source[finish:]
            source = replace_function(source, "self_hosted_setup",
                '  if [ "$runner" = self-hosted ]; then _dw_refuse self_hosted_setup; fi')
            source = replace_function(source, "configure_php",
                '  : "CLI configuration is already installed from its held source recipe"')
            source = "_dw_refuse() {\n" + guard + "\n}\n" + source
        if name == "src/scripts/extensions/add_extensions.sh":
            source = replace_function(source, "enable_cache_extension_dependencies",
                '  if [ -d /tmp/extcache ]; then _dw_refuse cached_extension_dependencies; fi')
        if name == "src/scripts/linux.sh":
            source = replace_function(source, "add_sudo",
                '  [ -x /usr/bin/sudo ] || { printf "%s\\n" "sudo prerequisite missing" >&2; exit 78; }')
            source = bootstrap.replace_once(source, 'link_apt_fast >/dev/null 2>&1\n',
                                             ': "No APT setup or apt-fast link in the initial profile"\n')
            source = bootstrap.replace_once(source,
                '  mapfile -t ini_file < <(sudo find "$ini_dir/.." -name "php.ini" -exec readlink -m {} +)\n',
                '  ini_file=("$ini_dir/php.ini")\n')
            for function in ("add_php_config", "link_pecl_file"):
                source = replace_function(source, function,
                    '  : "Only the prebound CLI configuration is supported"')
            source = replace_function(source, "disable_extension_helper",
                '  case "$1" in xdebug|pcov) : "Bound coverage-none CLI recipe" ;;\n'
                '    *) _dw_refuse non_cli_coverage ;; esac')
            source = bootstrap.replace_once(source,
                '  sudo chmod 777 "${ini_file[@]}" "$pecl_file" "${tool_path_dir:?}"\n',
                '  sudo chmod 0644 "${ini_file[@]}" "$pecl_file"\n'
                '  sudo chmod 777 "${tool_path_dir:?}"\n')
        derived[name] = source.encode()
    return derived


def write_runtime(destination: Path, files: dict[str, bytes]) -> dict:
    if not destination.is_absolute() or destination.exists():
        raise ValueError("Derived runtime requires a new private directory")
    destination.mkdir(mode=0o700)
    for name, contents in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with target.open("xb") as stream:
            stream.write(contents)
        target.chmod(0o600)
    return {name: bootstrap.sha256(contents) for name, contents in files.items()}


def runtime_environment(plan: dict, closed: dict) -> dict:
    if closed != bootstrap.clean_environment(closed, closed.get("HOME", "")):
        raise ValueError("Pinned upstream requires an already closed environment")
    # Owned PHAR installation handles the original tools request separately.
    # Literal 'none' bypasses pinned upstream's mutable default tool dispatch.
    result = dict(closed)
    for name, value in plan["request"]["inputs"].items():
        result["INPUT_" + name.upper()] = "none" if name == "tools" else value
    result.update(plan["request"]["overrides"])
    return result
