from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

# Keep the CI trust suite's existing entrypoint while collecting the isolated
# source boundary cases. These tests never invoke setup or package operations.
from tests import (test_fixed_apt, test_php_linux_bootstrap, test_php_linux_tools,
                   test_php_linux_recipe, test_php_linux_archive, test_setup_php_linux,
                   test_php_linux_qualification, test_php_linux_qualification_workflow,
                   test_bookworm_apt_source, test_private_pip_runtime,
                   test_php_linux_normalize, test_php_linux_archive_metadata, test_php_linux_alternatives)


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ci_trust", ROOT / ".github/actions/bootstrap-patched-pip/export-trust.py",
)
trust = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trust)
PUBLIC_BOUNDARY = ROOT / "scripts" / "check_public_boundary.py"
BOUNDARY_SPEC = importlib.util.spec_from_file_location("public_boundary", PUBLIC_BOUNDARY)
public_boundary = importlib.util.module_from_spec(BOUNDARY_SPEC)
BOUNDARY_SPEC.loader.exec_module(public_boundary)


def load_tests(loader, standard_tests, pattern):
    for module in (test_fixed_apt, test_php_linux_bootstrap, test_php_linux_tools,
                   test_php_linux_recipe, test_php_linux_archive, test_setup_php_linux,
                   test_php_linux_qualification, test_php_linux_qualification_workflow,
                   test_bookworm_apt_source, test_private_pip_runtime,
                   test_php_linux_normalize, test_php_linux_archive_metadata, test_php_linux_alternatives):
        standard_tests.addTests(loader.loadTestsFromModule(module))
    return standard_tests


class PublicBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.run_git("init", "--quiet")
        self.run_git("config", "user.name", "Public Boundary Test")
        self.run_git("config", "user.email", "public-boundary@example.invalid")
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        (self.root / ".gitignore").write_text(ignore, encoding="utf-8")
        self.run_git("add", ".gitignore")

    def run_git(self, *arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=check,
            capture_output=True,
            text=True,
        )

    def run_check(self, root: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-I", str(PUBLIC_BOUNDARY)],
            cwd=root or self.root,
            check=False,
            capture_output=True,
            text=True,
        )

    def write(self, relative: str, content: str = "canary-value-must-not-be-read") -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_current_repository_has_no_tracked_project_local_settings(self) -> None:
        stderr = io.StringIO()
        with patch("sys.stderr", stderr):
            result = public_boundary.main()
        self.assertEqual(0, result, stderr.getvalue())

    def test_tracked_root_settings_refuse_without_content(self) -> None:
        settings = self.write(".claude/settings.local.json")
        self.run_git("add", "-f", ".claude/settings.local.json")
        settings.chmod(0)

        result = self.run_check()

        self.assertEqual(1, result.returncode)
        self.assertIn(".claude/settings.local.json", result.stderr)
        self.assertNotIn("canary-value-must-not-be-read", result.stderr)
        stderr = io.StringIO()
        with patch.object(public_boundary, "git_output", side_effect=[
                (str(self.root) + "\n").encode(), b".claude/settings.local.json\0",
        ]), patch("sys.stderr", stderr):
            self.assertEqual(1, public_boundary.main())
        self.assertIn(".claude/settings.local.json", stderr.getvalue())

    def test_tracked_nested_settings_refuse_without_content(self) -> None:
        settings = self.write("component/.claude/settings.local.json")
        self.run_git("add", "-f", "component/.claude/settings.local.json")
        settings.chmod(0)

        result = self.run_check()

        self.assertEqual(1, result.returncode)
        self.assertIn("component/.claude/settings.local.json", result.stderr)
        self.assertNotIn("canary-value-must-not-be-read", result.stderr)

    def test_newline_path_is_escaped_in_the_refusal(self) -> None:
        relative = "line\nbreak/.claude/settings.local.json"
        self.write(relative)
        self.run_git("add", "-f", relative)

        result = self.run_check()

        self.assertEqual(1, result.returncode)
        self.assertIn("\\n", result.stderr)
        self.assertNotIn("line\nbreak", result.stderr)

    def test_untracked_settings_are_ignored_and_not_scanned(self) -> None:
        root_settings = self.write(".claude/settings.local.json")
        nested_settings = self.write("component/.claude/settings.local.json")

        self.run_git("check-ignore", "--quiet", str(root_settings.relative_to(self.root)))
        self.run_git("check-ignore", "--quiet", str(nested_settings.relative_to(self.root)))
        self.assertEqual(0, self.run_check().returncode)

    def test_near_names_remain_allowed(self) -> None:
        allowed = [
            ".claude/settings.json",
            ".claude/settings.local.json.example",
            "component/settings.local.json",
        ]
        for path in allowed:
            self.write(path)
        self.run_git("add", *allowed)

        result = self.run_check()

        self.assertEqual(0, result.returncode, result.stderr)

    def test_preexisting_tracked_copy_refuses_after_an_unrelated_commit(self) -> None:
        forbidden = self.write("legacy/.claude/settings.local.json")
        self.run_git("add", "-f", str(forbidden.relative_to(self.root)))
        self.run_git("commit", "--quiet", "-m", "Add historical tracked copy")
        self.write("README.md", "Unrelated change\n")
        self.run_git("add", "README.md")
        self.run_git("commit", "--quiet", "-m", "Unrelated change")

        result = self.run_check()

        self.assertEqual(1, result.returncode)
        self.assertIn("legacy/.claude/settings.local.json", result.stderr)


class CleanBundleTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory()
        cls.certificates = {}
        for index, name in enumerate(("CI test root", *trust.BLOCKED_SUBJECTS)):
            certificate = Path(cls.fixture.name) / f"root-{index}.pem"
            subprocess.run(
                ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                 "-subj", "/CN=" + name, "-days", "1", "-keyout",
                 str(certificate.with_suffix(".key")), "-out", str(certificate)],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            cls.certificates[name] = certificate

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.env_file = self.directory / "github-env"
        self.output_file = self.directory / "github-output"
        self.env_file.touch(mode=0o600)
        self.output_file.touch(mode=0o600)
        self.clean = self.certificates["CI test root"]

    def export(self, source=None, directory=None):
        return trust.export_bundle(
            source or self.clean, directory or self.directory,
            self.env_file, self.output_file,
            ("pip", "python", "composer", "curl", "git"),
        )

    def test_both_blocked_subjects_are_refused(self):
        for name in trust.BLOCKED_SUBJECTS:
            with self.subTest(subject=name), self.assertRaisesRegex(ValueError, "Blocked certificate"):
                self.export(self.certificates[name])
        self.assertEqual("", self.env_file.read_text())
        self.assertEqual("", self.output_file.read_text())

    def test_a_blocked_root_later_in_the_bundle_is_refused(self):
        combined = self.directory / "combined.pem"
        combined.write_bytes(self.clean.read_bytes() + self.certificates[trust.BLOCKED_SUBJECTS[1]].read_bytes())
        with self.assertRaisesRegex(ValueError, "Blocked certificate"):
            self.export(combined)

    def test_malformed_or_missing_certificates_are_refused(self):
        for data in (b"", b"not a certificate", b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----"):
            source = self.directory / "invalid.pem"
            source.write_bytes(data)
            with self.subTest(data=data), self.assertRaises(ValueError):
                self.export(source)
        with self.assertRaisesRegex(ValueError, "regular file"):
            self.export(self.directory)

    def test_all_clients_receive_one_stable_bundle_and_empty_extra_root_directory(self):
        variables = self.export()
        bundle = Path(variables["COMPOSER_CAFILE"])
        self.assertTrue(bundle.is_absolute())
        self.assertEqual(self.clean.read_bytes(), bundle.read_bytes())
        self.assertEqual(0o444, bundle.stat().st_mode & 0o777)
        self.assertEqual({str(bundle)}, {variables[name] for name in trust.FILE_VARIABLES})
        directories = {variables[name] for name in trust.DIRECTORY_VARIABLES}
        self.assertEqual(1, len(directories))
        self.assertEqual([], list(Path(next(iter(directories))).iterdir()))
        digest = hashlib.sha256(bundle.read_bytes()).hexdigest()
        self.assertEqual(digest, variables["DW_CI_CA_SHA256"])
        for name, value in variables.items():
            self.assertIn(f"{name}={value}\n", self.env_file.read_text())
        self.assertIn(f"ca-sha256={digest}\n", self.output_file.read_text())
        self.assertEqual(variables, self.export())

    def test_modified_existing_bundle_is_not_silently_reused(self):
        variables = self.export()
        bundle = Path(variables["COMPOSER_CAFILE"])
        bundle.chmod(0o644)
        bundle.write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "unexpected contents"):
            self.export()

    def test_additional_roots_or_redirected_output_are_refused(self):
        variables = self.export()
        directory = Path(variables["COMPOSER_CAPATH"])
        (directory / "extra.pem").write_bytes(self.clean.read_bytes())
        with self.assertRaisesRegex(ValueError, "must be empty"):
            self.export()
        (directory / "extra.pem").unlink()
        directory.rmdir()
        directory.symlink_to(self.directory, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.export()

    def test_environment_file_injection_is_refused(self):
        with self.assertRaisesRegex(ValueError, "line breaks"):
            self.export(directory=self.directory / "bad\nINJECTED=value")
        self.assertEqual("", self.env_file.read_text())

    def test_only_selected_clients_receive_overrides(self):
        variables = trust.export_bundle(self.clean, self.directory, self.env_file, self.output_file, ("composer", "curl", "git"))
        self.assertIn("COMPOSER_CAFILE", variables)
        self.assertIn("GIT_SSL_CAPATH", variables)
        self.assertNotIn("PIP_CERT", variables)
        self.assertNotIn("REQUESTS_CA_BUNDLE", variables)
        self.assertNotIn("NPM_CONFIG_CAFILE", variables)
        self.assertNotIn("CARGO_HTTP_CAINFO", variables)
        with self.assertRaisesRegex(ValueError, "supported CI trust clients"):
            trust.export_bundle(self.clean, self.directory, self.env_file, self.output_file, ("unknown",))
        with self.assertRaisesRegex(ValueError, "supported CI trust clients"):
            trust.export_bundle(self.clean, self.directory, self.env_file, self.output_file, ("go",))
        with self.assertRaises(ValueError):
            trust.export_bundle(self.clean, self.directory, self.env_file, self.output_file, ())

    def test_npm_and_cargo_bind_their_actual_package_clients_without_additive_node_roots(self):
        variables = trust.export_bundle(self.clean, self.directory, self.env_file, self.output_file, ("npm", "cargo"))
        self.assertEqual(variables["SSL_CERT_FILE"], variables["NPM_CONFIG_CAFILE"])
        self.assertEqual(variables["SSL_CERT_FILE"], variables["CARGO_HTTP_CAINFO"])
        self.assertNotIn("CARGO_HTTP_PROXY_CAINFO", variables)
        self.assertNotIn("NODE_EXTRA_CA_CERTS", variables)

    def test_main_uses_the_verified_private_certifi_object(self):
        variables = {
            "RUNNER_TEMP": str(self.directory), "GITHUB_ENV": str(self.env_file),
            "GITHUB_OUTPUT": str(self.output_file), "DW_CI_PIP_PYTHON": "/fixture/private/bin/python",
            "TRUST_CREATED": "false",
        }
        source = self.directory / "pip/_vendor/certifi/cacert.pem"
        source.parent.mkdir(parents=True)
        source.write_bytes(self.clean.read_bytes())
        with trust.runtime.held_file(source, owned=True) as (_contents, identity):
            pass
        receipt = str(self.directory / "runtime.json")
        report = {"purelib": str(self.directory), "root": str(self.directory)}
        with patch.dict(os.environ, variables), patch.object(trust.sys, "argv", ["export-trust", "--runtime", receipt]), \
                patch.object(trust.runtime, "verify_runtime", return_value=(report, {str(source): identity})) as verify, \
                patch.object(trust.runtime, "verify_active_origin") as active:
            trust.main()
        verify.assert_called_once_with(receipt, str(self.directory))
        active.assert_called_once_with(report, trust.shutil.which("python"))
        self.assertIn("PIP_CERT=", self.env_file.read_text())
        self.assertNotIn("COMPOSER_CAFILE=", self.env_file.read_text())
        self.env_file.write_text("")
        source.write_bytes(b"changed after private source verification")
        with patch.dict(os.environ, variables), patch.object(trust.sys, "argv", ["export-trust", "--runtime", receipt]), \
                patch.object(trust.runtime, "verify_runtime", return_value=(report, {str(source): identity})), \
                patch.object(trust.runtime, "verify_active_origin"), \
                self.assertRaisesRegex(ValueError, "object changed"):
            trust.main()
        self.assertEqual("", self.env_file.read_text())

    def test_main_has_no_ambient_pip_or_receipt_discovery_fallback(self):
        with patch.object(trust.sys, "argv", ["export-trust"]), \
                patch.object(trust.runtime, "verify_runtime") as verify, self.assertRaisesRegex(ValueError, "explicit"):
            trust.main()
        verify.assert_not_called()

    def test_ca_source_links_and_redirected_command_files_refuse_without_output(self):
        original = self.directory / "source.pem"
        original.write_bytes(self.clean.read_bytes())
        link = self.directory / "redirect.pem"
        link.symlink_to(original)
        with self.assertRaises((OSError, ValueError)):
            self.export(link)
        link.unlink()
        os.link(original, link)
        with self.assertRaisesRegex(ValueError, "link"):
            self.export(link)
        link.unlink()
        self.env_file.unlink()
        self.env_file.symlink_to(original)
        with self.assertRaises((OSError, ValueError)):
            self.export()
        self.assertEqual(self.clean.read_bytes(), original.read_bytes())
        self.assertEqual("", self.output_file.read_text())

    def test_ambient_openssl_executable_and_configuration_are_not_used(self):
        binary = self.directory / "openssl"
        marker = self.directory / "ambient-openssl-executed"
        binary.write_text("#!/bin/sh\nprintf bad > '" + str(marker) + "'\n")
        binary.chmod(0o700)
        with patch.dict(os.environ, {"PATH": str(self.directory), "OPENSSL_CONF": str(binary)}):
            self.export()
        self.assertFalse(marker.exists())

    def test_new_runtime_is_reclaimed_when_trust_validation_or_export_fails(self):
        runner = self.directory
        for stage in ("verify", "export"):
            state = trust.runtime._private_root(runner)
            root = state.root
            receipt = root / "runtime.json"
            receipt.write_text("{}")
            report = {"root": str(root), "purelib": str(root / "site-packages")}
            source = Path(report["purelib"]) / "pip/_vendor/certifi/cacert.pem"
            environment = {"RUNNER_TEMP": str(runner), "TRUST_CREATED": "true",
                           "TRUST_ROOT_IDENTITY": json.dumps(state.identity),
                           "GITHUB_ENV": str(self.env_file), "GITHUB_OUTPUT": str(self.output_file)}
            with self.subTest(stage=stage), patch.dict(os.environ, environment), \
                    patch.object(trust.sys, "argv", ["export-trust", "--runtime", str(receipt)]), \
                    patch.object(trust.runtime, "verify_runtime", side_effect=ValueError("inert verification") if stage == "verify" else None,
                                 return_value=(report, {str(source): {}})), \
                    patch.object(trust.runtime, "verify_active_origin"), \
                    patch.object(trust, "export_bundle", side_effect=ValueError("inert export")), \
                    self.assertRaisesRegex(ValueError, "inert"):
                trust.main()
            self.assertFalse(root.exists())

    def test_export_identity_lookup_failure_reclaims_only_new_producer_state(self):
        for created in ("true", "false"):
            state = trust.runtime._private_root(self.directory)
            environment = {"RUNNER_TEMP": str(self.directory), "TRUST_CREATED": created,
                           "TRUST_ROOT_IDENTITY": json.dumps(state.identity)}
            def verify(path, temp):
                return trust.runtime.runtime_root(path, temp)
            with self.subTest(created=created), patch.dict(os.environ, environment), \
                    patch.object(trust.sys, "argv", ["export-trust", "--runtime", str(state.receipt)]), \
                    patch.object(trust.runtime, "verify_runtime", side_effect=verify), \
                    patch.object(trust.runtime, "runtime_root", side_effect=OSError("inert export identity lookup")), \
                    self.assertRaisesRegex(OSError, "identity lookup"):
                trust.main()
            self.assertEqual(created == "false", state.root.exists())


if __name__ == "__main__":
    unittest.main()
