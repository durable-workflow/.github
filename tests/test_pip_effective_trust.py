"""Exercise actual pip against a synthetic compromised OpenSSL default store."""

from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "effective_trust", ROOT / ".github/actions/bootstrap-patched-pip/export-trust.py",
)
trust = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trust)


class QuietHandler(SimpleHTTPRequestHandler):
    def log_message(self, _format, *args):
        pass


@unittest.skipUnless(sys.platform == "linux", "This control exercises Linux OpenSSL defaults")
class PipEffectiveTrustTest(unittest.TestCase):
    def test_pip_cert_alone_is_additive_but_exported_file_and_empty_directory_refuse(self):
        import pip
        from pip._vendor import certifi

        self.assertEqual("26.2.2", pip.__version__)
        clean = Path(certifi.where())
        trust.inspect_bundle(clean)
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            roots = []
            for index, subject in enumerate(trust.BLOCKED_SUBJECTS):
                certificate = directory / f"root-{index}.pem"
                subprocess.run(
                    ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                     "-subj", "/CN=" + subject, "-days", "1", "-addext",
                     "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout",
                     str(certificate.with_suffix(".key")), "-out", str(certificate)],
                    check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                roots.append(certificate)
            affected = directory / "openssl-default.pem"
            affected.write_bytes(b"".join(path.read_bytes() for path in roots))
            with self.assertRaisesRegex(ValueError, "Blocked certificate"):
                trust.inspect_bundle(affected)
            extra = directory / "openssl-default-directory"
            extra.mkdir()
            variables = trust.export_bundle(
                clean, directory / "runner", directory / "env", directory / "output", ("pip",),
            )
            wheel = directory / "trust_probe-1.0-py3-none-any.whl"
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("trust_probe-1.0.dist-info/METADATA", "Metadata-Version: 2.1\nName: trust-probe\nVersion: 1.0\n")
                archive.writestr("trust_probe-1.0.dist-info/WHEEL", "Wheel-Version: 1.0\nGenerator: trust-control\nRoot-Is-Purelib: true\nTag: py3-none-any\n")
                archive.writestr("trust_probe-1.0.dist-info/RECORD", "")
            server = ThreadingHTTPServer(("127.0.0.1", 0), partial(QuietHandler, directory=temporary))
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(roots[1], roots[1].with_suffix(".key"))
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                self.check_downloads(directory, affected, extra, variables, server.server_port, wheel.name)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())

    def check_downloads(self, directory, affected, extra, variables, port, wheel_name):
        # Configure the child process's actual OpenSSL default paths. The host's
        # system store is never modified, and no public endpoint is contacted.
        environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith(("PIP_", "SSL_")) and key not in {"REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"}
        }
        environment.update({"SSL_CERT_FILE": str(affected), "SSL_CERT_DIR": str(extra), "PIP_CONFIG_FILE": os.devnull})
        cases = (("raw", {}, True), ("pip-cert-only", {"PIP_CERT": variables["PIP_CERT"]}, True), ("confined", variables, False))
        for name, changes, should_download in cases:
            destination = directory / name
            result = subprocess.run(
                [sys.executable, "-I", "-m", "pip", "--disable-pip-version-check", "download",
                 "--no-index", "--no-deps", "--no-cache-dir", "--retries", "0", "--timeout", "3",
                 "--dest", str(destination), f"https://localhost:{port}/{wheel_name}"],
                env=environment | changes, capture_output=True, text=True, timeout=20,
            )
            with self.subTest(client=name):
                if should_download:
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertEqual((directory / wheel_name).read_bytes(), (destination / wheel_name).read_bytes())
                else:
                    self.assertNotEqual(0, result.returncode)
                    self.assertIn("CERTIFICATE_VERIFY_FAILED", result.stdout + result.stderr)
                    self.assertFalse((destination / wheel_name).exists())


if __name__ == "__main__":
    unittest.main()
