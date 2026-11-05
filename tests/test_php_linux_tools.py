"""Inert PHAR boundary controls; no network, PHP, PHAR stub or installation."""

import copy
import io
import json
import os
from pathlib import Path
import ssl
import stat
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import php_linux_bootstrap as bootstrap
from scripts import php_linux_tools as tools


class PhpLinuxToolsTest(unittest.TestCase):
    def setUp(self):
        self.catalog = json.loads(tools.CATALOG.read_text())
        self.composer = tools.select_tools(self.catalog, "composer:2.10.3", "8.3")[0]

    def fixture(self):
        payload = b"inert PHAR bytes; never executed"
        row = dict(self.composer, size=len(payload), sha256=bootstrap.sha256(payload))
        return row, payload

    def test_real_captured_bytes_and_signature_authority_are_distinct(self):
        self.assertIs(self.catalog, tools.validate_catalog(self.catalog))
        self.assertEqual([], tools.select_tools(self.catalog, "none", "8.1"))
        self.assertEqual("composer", tools.select_tools(self.catalog, "composer:2.10.3", "8.1")[0]["name"])
        with self.assertRaisesRegex(ValueError, "authority is incomplete"):
            tools.select_tools(self.catalog, "composer:2.10.3, phpunit:11.5.57", "8.3")
        with self.assertRaisesRegex(ValueError, "PHP 8.1 remains unsupported"):
            tools.select_tools(self.catalog, "phpunit:11.5.57", "8.1")

    def test_omission_defaults_mutable_versions_duplicates_and_other_tools_refuse(self):
        for request in ("", "composer", "composer:2", "composer:latest", "composer:2.11.1",
                        "composer:2.10.3,composer:2.10.3", "none,composer:2.10.3", "phpunit",
                        "phpunit:10.5.0", "box:4.6.6", "composer:2.10.3; echo injected", ","):
            with self.subTest(request=request), self.assertRaises(ValueError):
                tools.select_tools(self.catalog, request, "8.3")

    def test_mutated_tool_or_publisher_evidence_cannot_qualify(self):
        for field, replacement in (("url", "https://example.com/composer.phar"),
                                   ("sha256", "0" * 64), ("size", 1), ("minimum_php", "8.1")):
            changed = copy.deepcopy(self.catalog)
            changed["tools"][0][field] = replacement
            with self.subTest(field=field), self.assertRaises(ValueError):
                tools.validate_catalog(changed)
        for change in ("receipt", "key", "state", "path"):
            changed = copy.deepcopy(self.catalog)
            row = changed["tools"][0]
            if change == "receipt":
                row["publisher_authority"]["receipt_sha256"] = "0" * 64
            elif change == "key":
                row["publisher_authority"]["public_key_sha256"] = "0" * 64
            elif change == "state":
                changed["tools"][1]["publisher_authority"]["state"] = "verified"
            else:
                row["evidence"]["digest"]["file"] = "qualification/php-tools/../../AGENTS.md"
            with self.subTest(change=change), self.assertRaises(ValueError):
                tools.validate_catalog(changed)

    def opener(self, row, payload, calls, status=200, final=None):
        class Response(io.BytesIO):
            def geturl(self):
                return row["url"] if final is None else final
        Response.status = status
        def factory(*handlers):
            self.assertEqual({}, handlers[0].proxies)
            self.assertIsInstance(handlers[-1], tools.NoRedirects)
            def open_request(request, **options):
                calls.append((request, options))
                return Response(payload)
            return SimpleNamespace(open=open_request)
        return factory

    def test_exact_tool_download_has_one_anonymous_request_and_seals_same_input(self):
        row, payload = self.fixture()
        calls = []
        context = SimpleNamespace(verify_mode=ssl.CERT_REQUIRED, check_hostname=True)
        with tools.download_held(row, context, self.opener(row, payload, calls)) as held:
            self.assertEqual(payload, os.pread(held.descriptor, len(payload), 0))
            held.assert_sealed()
        self.assertEqual(1, len(calls))
        request, options = calls[0]
        self.assertEqual(row["url"], request.full_url)
        self.assertNotIn("authorization", {name.lower() for name in request.headers})
        self.assertEqual({"timeout": 15}, options)

    def test_redirect_status_mutation_and_unqualified_publisher_refuse_without_fallback(self):
        row, payload = self.fixture()
        calls = []
        context = SimpleNamespace(verify_mode=ssl.CERT_REQUIRED, check_hostname=True)
        for options in ({"status": 403}, {"final": "https://example.com/changed.phar"},
                        {"payload": payload + b"changed"}):
            candidate = dict(payload=payload, **{key: value for key, value in options.items() if key != "payload"})
            candidate["payload"] = options.get("payload", payload)
            opener = self.opener(row, calls=calls, **candidate)
            with self.subTest(options=options), self.assertRaises(ValueError):
                with tools.download_held(row, context, opener):
                    self.fail("No replacement bytes should be held")
        self.assertEqual(3, len(calls))
        with self.assertRaises(ValueError):
            tools.NoRedirects().redirect_request(None, None, 302, "redirect", {}, row["url"])
        unqualified = dict(row, publisher_authority={"state": "missing-full-fingerprint-binding"})
        with self.assertRaises(ValueError):
            with tools.download_held(unqualified, context, self.opener(row, payload, calls)):
                self.fail("Unqualified publisher cannot fetch")
        self.assertEqual(3, len(calls))

    def test_fixed_install_command_reads_held_fd_and_checks_actual_target_before_returning(self):
        row, payload = self.fixture()
        environment = bootstrap.clean_environment({}, "/tmp/inert-private-home")
        calls = []
        def execute(command, **options):
            calls.append((command, options))
            self.assertEqual(payload, os.read(options["stdin"], len(payload)))
        def inspect(path):
            self.assertEqual(Path("/usr/local/bin/composer"), path)
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o755), payload
        with bootstrap.hold_bytes(io.BytesIO(payload), tools.identity(row), {"url": row["url"]}) as held:
            with patch.dict(os.environ, environment, clear=True):
                actual = tools.install_held(held, row, environment, execute, inspect)
            self.assertEqual("/usr/local/bin/composer", actual["target"])
            with self.assertRaises(ValueError):
                tools.install_held(held, row, dict(environment, GH_TOKEN="inert"), execute, inspect)
        self.assertEqual(1, len(calls))
        self.assertEqual(["/usr/bin/sudo", "/usr/bin/install", "-m", "0755", "/dev/stdin",
                          "/usr/local/bin/composer"], calls[0][0])

    def test_post_install_replacement_mode_or_symlink_does_not_become_execution_authority(self):
        row, payload = self.fixture()
        environment = bootstrap.clean_environment({}, "/tmp/inert-private-home")
        for mode, contents in ((stat.S_IFREG | 0o755, b"replaced"),
                               (stat.S_IFREG | 0o777, payload), (stat.S_IFLNK | 0o755, payload)):
            with self.subTest(mode=mode, contents=contents):
                with bootstrap.hold_bytes(io.BytesIO(payload), tools.identity(row), {}) as held:
                    with patch.dict(os.environ, environment, clear=True), self.assertRaises(ValueError):
                        tools.install_held(held, row, environment, lambda *args, **kw: None,
                            lambda path: (SimpleNamespace(st_mode=mode), contents))


if __name__ == "__main__":
    unittest.main()
