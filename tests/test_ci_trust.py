from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ci_trust", ROOT / ".github/actions/bootstrap-patched-pip/export-trust.py",
)
trust = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trust)


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
        self.assertFalse(self.env_file.exists())
        self.assertFalse(self.output_file.exists())

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
        self.assertFalse(self.env_file.exists())

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
        self.assertEqual(variables["SSL_CERT_FILE"], variables["CARGO_HTTP_PROXY_CAINFO"])
        self.assertNotIn("NODE_EXTRA_CA_CERTS", variables)

    def test_main_uses_the_authenticated_pip_distribution(self):
        variables = {
            "RUNNER_TEMP": str(self.directory), "GITHUB_ENV": str(self.env_file),
            "GITHUB_OUTPUT": str(self.output_file),
        }
        with patch.dict(os.environ, variables), patch("pip.__version__", "26.2.2"), patch("pip._vendor.certifi.where", return_value=str(self.clean)):
            trust.main()
        self.assertIn("PIP_CERT=", self.env_file.read_text())
        self.assertNotIn("COMPOSER_CAFILE=", self.env_file.read_text())
        with patch("pip.__version__", "25.0"), self.assertRaisesRegex(ValueError, "26.2.2"):
            trust.main()


if __name__ == "__main__":
    unittest.main()
