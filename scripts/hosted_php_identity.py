"""Bind the PHP and package tools used by a hosted release job."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess


PATH = "/usr/local/bin:/usr/bin:/bin"
PHP_CONFIGURATION = r"""
if (PHP_SAPI !== 'cli' || PHP_VERSION_ID < 80337 || PHP_VERSION_ID >= 80400
    || extension_loaded('xdebug') || extension_loaded('pcov')) {
    exit(1);
}
echo json_encode([
    'version' => PHP_VERSION,
    'binary' => PHP_BINARY,
    'ini' => php_ini_loaded_file(),
    'scanned' => php_ini_scanned_files(),
    'extension_directory' => ini_get('extension_dir'),
    'extensions' => get_loaded_extensions(),
], JSON_THROW_ON_ERROR);
"""


def file_identity(path):
    subject = Path(path)
    if not subject.is_absolute():
        raise ValueError("Runtime subjects must have absolute paths")
    real = subject.resolve(strict=True)
    with real.open("rb") as source:
        return [str(subject), str(real), hashlib.file_digest(source, "sha256").hexdigest()]


def runtime_identity():
    tools = {name: shutil.which(name, path=PATH) for name in ("php", "composer", "phpunit")}
    if not all(tools.values()):
        raise ValueError("PHP, Composer and PHPUnit must be installed")
    environment = {"PATH": PATH, "LANG": "C.UTF-8"}
    configuration = json.loads(subprocess.check_output(
        [tools["php"], "-r", PHP_CONFIGURATION], env=environment, timeout=10,
    ))
    if Path(configuration["binary"]).resolve() != Path(tools["php"]).resolve():
        raise ValueError("PHP did not report the selected binary")
    scanned = (configuration["scanned"] or "").strip()
    ini_files = [configuration["ini"], *re.split(r",\s*", scanned)] if scanned else [configuration["ini"]]
    extensions = sorted(Path(configuration["extension_directory"]).glob("*.so"))
    return {
        "version": configuration["version"],
        "tools": {name: file_identity(path) for name, path in tools.items()},
        "ini": [file_identity(path) for path in ini_files],
        "extensions": sorted(configuration["extensions"]),
        "modules": [file_identity(path) for path in extensions],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expect")
    options = parser.parse_args()
    evidence = runtime_identity()
    encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(encoded).hexdigest()
    if options.expect is not None:
        if options.expect != digest:
            raise SystemExit("Hosted PHP runtime identity changed after the product checks")
        print(json.dumps({"php_version": evidence["version"], "sha256": digest, "revalidated": True}))
    else:
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
            print(f"sha256={digest}", file=output)
        print(json.dumps({"php_version": evidence["version"], "sha256": digest}))


if __name__ == "__main__":
    main()
