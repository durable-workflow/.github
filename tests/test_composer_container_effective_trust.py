"""Exercise the actual container Composer client against a local TLS registry."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
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
IMAGE = "composer:2.10.3@sha256:da624c2c705d54e2f5a9bb77a5dc6c7d091711433ebefd7035672e84c2010fee"


class RegistryServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # Composer can abandon a TLS connection after certificate inspection.
        if isinstance(sys.exception(), (BrokenPipeError, ConnectionResetError)):
            return
        super().handle_error(request, client_address)


@unittest.skipUnless(sys.platform == "linux", "The controlled container network uses Linux loopback.")
class ContainerComposerEffectiveTrustTest(unittest.TestCase):
    def test_ambient_store_accepts_but_verified_clean_store_refuses_before_http(self):
        self.assertIsNotNone(shutil.which("docker"), "Docker is required for the actual-container control.")
        self.assertEqual("linux", subprocess.check_output(
            ["docker", "info", "--format", "{{.OSType}}"], text=True,
        ).strip())
        parent = os.environ.get("COMPOSER_CONTAINER_TEST_DIRECTORY")
        with tempfile.TemporaryDirectory(prefix="composer-container-control-", dir=parent) as temporary:
            directory = Path(temporary).resolve()
            affected = directory / "ambient.pem"
            clean = directory / "clean.pem"
            self.certificate(affected, "AAA Certificate Services")
            self.certificate(clean, "Unrelated clean fixture root")
            (directory / "empty").mkdir()
            os_store = directory / "ambient-store"
            os_store.mkdir()
            shutil.copyfile(affected, os_store / "ca-certificates.crt")
            shutil.copyfile(affected, os_store / "withdrawn.pem")
            subprocess.run(["openssl", "rehash", str(os_store)], check=True, capture_output=True)
            requests = []

            class Registry(BaseHTTPRequestHandler):
                def do_GET(self):
                    requests.append(self.path)
                    body = json.dumps({"packages": {"durable-workflow/workflow": {"2.15.12": {
                        "name": "durable-workflow/workflow", "version": "2.15.12", "type": "metapackage",
                    }}}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, _format, *args):
                    pass

            server = RegistryServer(("127.0.0.1", 0), Registry)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(affected, affected.with_suffix(".key"))
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                self.check_requests(directory, server.server_port, requests)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)
                self.assertFalse(thread.is_alive())

    @staticmethod
    def certificate(path, subject):
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
            "-subj", "/CN=" + subject, "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-keyout", str(path.with_suffix(".key")), "-out", str(path),
        ], check=True, capture_output=True)

    def check_requests(self, directory, port, requests):
        digest = hashlib.sha256((directory / "clean.pem").read_bytes()).hexdigest()
        common = {
            "COMPOSER_HOME": "/tmp/composer-home", "COMPOSER_CACHE_DIR": "/tmp/composer-cache",
            "SSL_CERT_FILE": "/fixture/ambient.pem", "SSL_CERT_DIR": "/etc/ssl/certs",
            "HTTP_PROXY": "", "HTTPS_PROXY": "", "ALL_PROXY": "", "NO_PROXY": "localhost,127.0.0.1",
        }
        clean = {
            name: "/fixture/clean.pem"
            for name in ("SSL_CERT_FILE", "CURL_CA_BUNDLE", "GIT_SSL_CAINFO", "COMPOSER_CAFILE")
        } | {
            name: "/fixture/empty"
            for name in ("SSL_CERT_DIR", "GIT_SSL_CAPATH", "COMPOSER_CAPATH")
        } | {"DW_CI_CA_SHA256": digest}
        command = ("composer update --no-dev --no-scripts "
                   "--no-autoloader --prefer-dist --no-interaction --no-progress --no-audit")
        cases = (
            ("ambient", {}, command, True, ""),
            ("clean", clean, "php /trust/verify.php /usr/bin/composer /project; " + command,
             False, r"(?i)(curl error 60|certificate verify failed|SSL certificate problem)"),
            ("wrong-digest", clean | {"DW_CI_CA_SHA256": "f" * 64},
             "php /trust/verify.php /usr/bin/composer /project; " + command,
             False, "differs from the authenticated"),
            ("extra-roots", clean | {"SSL_CERT_DIR": "/etc/ssl/certs"},
             "php /trust/verify.php /usr/bin/composer /project; " + command,
             False, "empty directory"),
            ("missing-hook", clean, "php /trust/missing.php /usr/bin/composer /project; " + command,
             False, "Could not open input file"),
        )
        for name, environment, script, succeeds, expected_error in cases:
            project = directory / name
            project.mkdir()
            (project / "composer.json").write_text(json.dumps({
                "name": "fixture/container-control", "require": {"durable-workflow/workflow": "2.15.12"},
                "repositories": [{"type": "composer", "url": f"https://localhost:{port}"},
                                 {"packagist.org": False}],
            }))
            arguments = [
                "docker", "run", "--rm", "--init", "--user", f"{os.getuid()}:{os.getgid()}", "--network", "host",
                "--cpus", "1", "--memory", "512m", "--memory-swap", "512m",
                "--label", "task=composer-container-trust-control", "--workdir", "/project",
                "--mount", f"type=bind,src={directory},dst=/fixture,readonly",
                "--mount", f"type=bind,src={directory / 'ambient-store'},dst=/etc/ssl/certs,readonly",
                "--mount", f"type=bind,src={project},dst=/project",
                "--mount", f"type=bind,src={ROOT / '.github/actions/verify-composer-trust/verify.php'},dst=/trust/verify.php,readonly",
            ]
            for key, value in (common | environment).items():
                arguments.extend(["--env", key + "=" + value])
            before = len(requests)
            result = subprocess.run(arguments + ["--entrypoint", "/bin/sh", IMAGE, "-ec", script],
                                    capture_output=True, text=True, timeout=90)
            with self.subTest(client=name):
                if succeeds:
                    self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                    self.assertGreater(len(requests), before)
                    packages = json.loads((project / "composer.lock").read_text())["packages"]
                    self.assertEqual("durable-workflow/workflow", packages[0]["name"])
                else:
                    self.assertNotEqual(0, result.returncode)
                    self.assertRegex(result.stdout + result.stderr, expected_error)
                    self.assertEqual(before, len(requests), "The refused client reached the registry's HTTP handler.")
                    self.assertFalse((project / "composer.lock").exists())


if __name__ == "__main__":
    unittest.main()
