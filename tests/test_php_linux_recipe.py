"""Pinned-source and input controls; all shell operations are inert stubs."""

import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from scripts import php_linux_bootstrap as bootstrap
from scripts import php_linux_recipe as recipe
from scripts import php_linux_tools as tools


class PhpLinuxRecipeTest(unittest.TestCase):
    def setUp(self):
        self.catalog = json.loads(bootstrap.CATALOG.read_text())
        self.tools = json.loads(tools.CATALOG.read_text())
        self.host = dict(operating_system="ubuntu", release="26.04", architecture="x86_64")
        self.request = recipe.capture_request({"INPUT_PHP-VERSION": "8.3",
            "INPUT_TOOLS": "composer:2.10.3", "INPUT_COVERAGE": "none"})

    def test_with_and_env_precedence_omission_and_actual_effective_runner(self):
        request = recipe.capture_request({"INPUT_PHP-VERSION": " 8.3 ", "PHP-VERSION": "8.4",
            "INPUT_TOOLS": "composer:2.10.3", "COVERAGE": "none", "FAIL-FAST": "true"})
        self.assertEqual("8.3", request["inputs"]["php-version"])
        self.assertEqual("with", request["origins"]["php-version"])
        self.assertEqual("env", request["origins"]["coverage"])
        self.assertEqual("true", request["inputs"]["fail-fast"])
        omitted = recipe.capture_request({"INPUT_PHP-VERSION": "8.3", "INPUT_TOOLS": "composer:2.10.3"})
        self.assertEqual("omitted", omitted["origins"]["coverage"])
        self.assertEqual("", omitted["inputs"]["coverage"])
        plan = recipe.validate_request(request, self.catalog, self.tools, self.host)
        self.assertEqual("26.04", plan["archive"]["release"])
        self.assertNotEqual(plan, recipe.validate_request(omitted, self.catalog, self.tools, self.host))
        with self.assertRaises(ValueError):
            recipe.validate_request(request, self.catalog, self.tools, dict(self.host, release="latest"))

    def test_unqualified_tool_or_override_refuses_before_source_or_network_effect(self):
        changes = [("tools", ""), ("tools", "composer"), ("tools", "phpunit:10.5.0"),
                   ("ini-file", "development"), ("ini-values", "memory_limit=-1"),
                   ("coverage", "xdebug3"), ("extensions", "opentelemetry-1.4.2"),
                   ("extensions", "pdo_sqlsrv"), ("extensions", "redis-user/repo@main"),
                   ("extensions", "json;touch injected"), ("php-version", "8.3.36")]
        for name, value in changes:
            request = copy.deepcopy(self.request)
            request["inputs"][name] = value
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                recipe.validate_request(request, self.catalog, self.tools, self.host)
        for name, value in (("update", "true"), ("debug", "true"), ("phpts", "zts"),
                             ("runner", "self-hosted"), ("setup_php_tools_dir", "/tmp/unbound")):
            request = copy.deepcopy(self.request)
            request["overrides"][name] = value
            with self.subTest(name=name, value=value), self.assertRaises(ValueError):
                recipe.validate_request(request, self.catalog, self.tools, self.host)

    def test_explicit_token_input_refuses_and_inherited_credentials_are_not_forwarded(self):
        with self.assertRaises(ValueError):
            recipe.capture_request({"INPUT_GITHUB-TOKEN": "inert-input-token"})
        parent = dict(GH_TOKEN="inert", GITHUB_TOKEN="inert", AWS_SECRET_ACCESS_KEY="inert",
                      COMPOSER_AUTH="inert", BASH_ENV="inert", NODE_OPTIONS="inert")
        plan = recipe.validate_request(self.request, self.catalog, self.tools, self.host)
        environment = recipe.runtime_environment(plan, bootstrap.clean_environment(parent, "/tmp/inert-home"))
        self.assertFalse(set(parent) & set(environment))
        self.assertEqual("none", environment["INPUT_TOOLS"])
        self.assertEqual("composer:2.10.3", plan["request"]["inputs"]["tools"])
        self.assertEqual("none", environment["INPUT_COVERAGE"])
        request = recipe.capture_request({"INPUT_PHP-VERSION": "8.3", "INPUT_TOOLS": "none", "FAIL_FAST": "true"})
        plan = recipe.validate_request(request, self.catalog, self.tools, self.host)
        self.assertEqual("omitted", request["origins"]["fail-fast"])
        self.assertEqual("true", recipe.runtime_environment(plan,
                         bootstrap.clean_environment({}, "/tmp/inert-home"))["FAIL_FAST"])

    def test_exact_runtime_closure_refuses_extra_missing_modified_and_symlink_files(self):
        self.assertEqual(88, len(recipe.verified_source()))
        with tempfile.TemporaryDirectory(prefix="php-inert-source-") as directory:
            copy_root = Path(directory) / "upstream"
            shutil.copytree(recipe.UPSTREAM, copy_root)
            cases = ("extra", "missing", "modified", "symlink")
            target = copy_root / "LICENSE"
            original = target.read_bytes()
            for case in cases:
                with self.subTest(case=case):
                    if case == "extra":
                        (copy_root / "new.js").write_text("inert extra source")
                    elif case == "missing":
                        target.unlink()
                    elif case == "modified":
                        target.write_bytes(original + b"\n")
                    else:
                        target.unlink()
                        target.symlink_to(recipe.UPSTREAM / "LICENSE")
                    with self.assertRaises(ValueError):
                        recipe.verified_source(copy_root)
                    if (copy_root / "new.js").exists():
                        (copy_root / "new.js").unlink()
                    if target.is_symlink():
                        target.unlink()
                    target.write_bytes(original)

    def function(self, files, file, name):
        text = files[file].decode()
        start = text.index(name + "() {\n")
        return text[start:text.index("\n}\n", start) + 3]

    def shell(self, script):
        return subprocess.run(["/usr/bin/bash", "--noprofile", "--norc", "-c", script],
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            capture_output=True, text=True, timeout=3)

    def test_original_direct_ppa_request_is_admitted_and_derived_function_refuses(self):
        original = recipe.verified_source()
        with tempfile.TemporaryDirectory(prefix="php-inert-refusal-") as directory:
            marker = Path(directory) / "refusal"
            derived = recipe.derive_source(original, marker)
            file = "src/scripts/tools/ppa.sh"
            old = self.shell('lpc_ppa=https://example.invalid\nVERSION_CODENAME=inert\n'
                'curl() { printf "old-network-request\\n" >&2; }\n'
                + self.function(original, file, "is_ubuntu_ppa_up") + '\nis_ubuntu_ppa_up ondrej/php\n')
            self.assertEqual(0, old.returncode)
            self.assertIn("old-network-request", old.stderr)
            guard = self.function(derived, "src/scripts/unix.sh", "_dw_refuse")
            new = self.shell(guard + self.function(derived, file, "is_ubuntu_ppa_up")
                             + '\nis_ubuntu_ppa_up ondrej/php\n')
            self.assertEqual(78, new.returncode)
            self.assertIn("is_ubuntu_ppa_up", marker.read_text())
            self.assertNotIn("old-network-request", new.stderr)

    def test_all_derived_network_guards_record_refusal_even_if_a_caller_masks_status(self):
        original = recipe.verified_source()
        with tempfile.TemporaryDirectory(prefix="php-inert-guards-") as directory:
            marker = Path(directory) / "refusal"
            derived = recipe.derive_source(original, marker)
            guard = self.function(derived, "src/scripts/unix.sh", "_dw_refuse")
            for file, functions in recipe.GUARDS.items():
                for name in functions:
                    if name in ("self_hosted_setup", "enable_cache_extension_dependencies"):
                        continue
                    result = self.shell(guard + self.function(derived, file, name)
                                        + f'\n{name} || true\n')
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertIn(name, marker.read_text())
            source = self.function(derived, "src/scripts/unix.sh", "self_hosted_setup")
            self.assertEqual(0, self.shell(guard + source + '\nrunner=github\nself_hosted_setup\n').returncode)
            self.assertEqual(78, self.shell(guard + source + '\nrunner=self-hosted\nself_hosted_setup\n').returncode)

    def test_derived_source_is_deterministic_and_never_modifies_original_manifest_members(self):
        original = recipe.verified_source()
        with tempfile.TemporaryDirectory(prefix="php-inert-runtime-") as directory:
            root = Path(directory)
            one = recipe.derive_source(original, root / "refusal")
            two = recipe.derive_source(original, root / "refusal")
            self.assertEqual(one, two)
            self.assertEqual(set(recipe.GUARDS), {name for name in original if one[name] != original[name]})
            written = recipe.write_runtime(root / "runtime", one)
            self.assertEqual(88, len(written))
            self.assertEqual(original, recipe.verified_source())
            with self.assertRaises(ValueError):
                recipe.write_runtime(root / "runtime", one)
        with self.assertRaises(ValueError):
            recipe.replace_function("missing function", "get", "return 78")


if __name__ == "__main__":
    unittest.main()
