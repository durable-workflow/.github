"""Exercise npm and Cargo against an additive synthetic OpenSSL root."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "effective_trust", ROOT / ".github/actions/bootstrap-patched-pip/export-trust.py",
)
trust = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(trust)


class RegistryHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *args):
        pass

    def do_GET(self):
        self.server.requests.append(self.path)
        origin = f"https://127.0.0.1:{self.server.server_port}"
        if self.path == "/config.json":
            body = {"dl": origin + "/api/v1/crates", "api": origin}
        elif self.path.startswith("/api/v1/crates"):
            body = {"crates": [], "meta": {"total": 0}}
        else:
            body = {
                "name": "trust-probe",
                "dist-tags": {"latest": "1.0.0"},
                "versions": {
                    "1.0.0": {
                        "name": "trust-probe",
                        "version": "1.0.0",
                        "dist": {
                            "tarball": origin + "/trust-probe-1.0.0.tgz",
                            "shasum": "0" * 40,
                        },
                    },
                },
            }
        encoded = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(encoded)


@unittest.skipUnless(sys.platform == "linux", "These controls exercise Linux OpenSSL defaults")
class CliEffectiveTrustTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = tempfile.TemporaryDirectory()
        cls.directory = Path(cls.fixture.name)
        if os.environ.get("SSL_CERT_FILE"):
            cls.clean = Path(os.environ["SSL_CERT_FILE"])
        else:
            from pip._vendor import certifi

            cls.clean = Path(certifi.where())
        trust.inspect_bundle(cls.clean)
        cls.root = cls.directory / "affected-root.pem"
        cls.root_key = cls.directory / "affected-root.key"
        cls.leaf = cls.directory / "localhost.pem"
        cls.leaf_key = cls.directory / "localhost.key"
        leaf_request = cls.directory / "localhost.csr"
        leaf_extensions = cls.directory / "localhost.ext"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-subj", "/CN=" + trust.BLOCKED_SUBJECTS[0], "-days", "1",
                "-addext", "basicConstraints=critical,CA:TRUE", "-keyout",
                str(cls.root_key), "-out", str(cls.root),
            ],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        subprocess.run(
            [
                "openssl", "req", "-new", "-newkey", "rsa:2048", "-nodes",
                "-subj", "/CN=localhost", "-keyout", str(cls.leaf_key),
                "-out", str(leaf_request),
            ],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        leaf_extensions.write_text(
            "subjectAltName=DNS:localhost,IP:127.0.0.1\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature,keyEncipherment\n"
            "extendedKeyUsage=serverAuth\n",
            encoding="utf-8",
        )
        subprocess.run(
            [
                "openssl", "x509", "-req", "-in", str(leaf_request),
                "-CA", str(cls.root), "-CAkey", str(cls.root_key),
                "-CAcreateserial", "-days", "1", "-extfile",
                str(leaf_extensions), "-out", str(cls.leaf),
            ],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        cls.affected_directory = cls.directory / "affected-roots"
        cls.affected_directory.mkdir()
        shutil.copy2(cls.root, cls.affected_directory / "affected-root.pem")
        subprocess.run(
            ["openssl", "rehash", str(cls.affected_directory)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )

    @classmethod
    def tearDownClass(cls):
        cls.fixture.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.case_directory = Path(self.temporary.name)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), RegistryHandler)
        self.server.requests = []
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.leaf, self.leaf_key)
        self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        self.assertFalse(self.thread.is_alive())

    @staticmethod
    def base_environment():
        removed_prefixes = ("CARGO_", "NPM_", "SSL_")
        removed_names = {
            "ALL_PROXY", "HTTPS_PROXY", "HTTP_PROXY", "NODE_EXTRA_CA_CERTS",
            "all_proxy", "https_proxy", "http_proxy",
        }
        environment = {
            key: value for key, value in os.environ.items()
            if not key.startswith(removed_prefixes) and key not in removed_names
        }
        environment.update({"NO_PROXY": "localhost,127.0.0.1", "no_proxy": "localhost,127.0.0.1"})
        return environment

    def exported(self, client):
        target = self.case_directory / (client + "-trust")
        return trust.export_bundle(
            self.clean, target, target / "github-env", target / "github-output", (client,),
        )

    def run_npm(self, name, changes):
        cache = self.case_directory / (name + "-npm-cache")
        environment = self.base_environment() | {
            "NPM_CONFIG_USERCONFIG": os.devnull,
            "NPM_CONFIG_UPDATE_NOTIFIER": "false",
            "NPM_CONFIG_AUDIT": "false",
            "NPM_CONFIG_FUND": "false",
        } | changes
        return subprocess.run(
            [
                "npm", "view", "trust-probe", "version", "--json",
                f"--registry=https://127.0.0.1:{self.server.server_port}",
                "--fetch-retries=0", "--fetch-timeout=3000", "--prefer-online",
                f"--cache={cache}",
            ],
            env=environment, capture_output=True, text=True, timeout=20,
        )

    @unittest.skipUnless(shutil.which("npm"), "npm is required for this control")
    def test_npm_cafile_excludes_an_additive_node_root(self):
        raw = self.run_npm("raw", {"NODE_EXTRA_CA_CERTS": str(self.root)})
        self.assertEqual(0, raw.returncode, raw.stderr)
        self.assertTrue(self.server.requests)

        self.server.requests.clear()
        confined = self.run_npm("confined", self.exported("npm"))
        self.assertNotEqual(0, confined.returncode)
        self.assertFalse(self.server.requests)
        self.assertRegex(
            confined.stdout + confined.stderr,
            r"(?i)(certificate|unable.to.verify|self.signed|unknown.ca)",
        )

    def run_cargo(self, name, variables):
        environment = self.base_environment() | variables | {
            "CARGO_HOME": str(self.case_directory / (name + "-cargo-home")),
            "CARGO_HTTP_MULTIPLEXING": "false",
            "CARGO_HTTP_TIMEOUT": "3",
            "CARGO_NET_RETRY": "0",
        }
        return subprocess.run(
            [
                "cargo", "search", "trust-probe", "--limit", "1", "--index",
                f"sparse+https://127.0.0.1:{self.server.server_port}/",
            ],
            env=environment, capture_output=True, text=True, timeout=20,
        )

    @unittest.skipUnless(shutil.which("cargo"), "Cargo is required for this control")
    def test_cargo_cainfo_requires_an_empty_openssl_directory(self):
        variables = self.exported("cargo")
        # Cargo 1.86 refuses proxy-cainfo unless http.proxy is configured. Keep
        # exercising direct TLS so this test proves both source obligations.
        proxy_cainfo = variables.pop("CARGO_HTTP_PROXY_CAINFO", None)
        additive = self.run_cargo(
            "additive", variables | {"SSL_CERT_DIR": str(self.affected_directory)},
        )
        self.assertTrue(self.server.requests, additive.stdout + additive.stderr)

        self.server.requests.clear()
        confined = self.run_cargo("confined", variables)
        self.assertNotEqual(0, confined.returncode)
        self.assertFalse(self.server.requests)
        self.assertRegex(
            confined.stdout + confined.stderr,
            r"(?i)(certificate|issuer|unknown.ca|unable.to.get.local)",
        )
        self.assertIsNone(
            proxy_cainfo,
            "CARGO_HTTP_PROXY_CAINFO must not be exported without a configured Cargo proxy",
        )


if __name__ == "__main__":
    unittest.main()
