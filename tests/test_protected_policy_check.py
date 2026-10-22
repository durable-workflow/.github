import contextlib
import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import protected_policy_check as gate
from scripts.protected_policy_inputs import InputRefused
from tests import test_protected_policy_inputs as fixtures


class FakeCurl:
    def __init__(self):
        self.version = b"curl 8.5.0 test\n"
        self.body = b'{"ok":true}'
        self.status = b"200"
        self.exit_code = 0
        self.timeout = False
        self.calls = []
        self.after_request = lambda: None

    def __call__(self, command, **options):
        if "--version" in command:
            return subprocess.CompletedProcess(command, 0, self.version)
        self.calls.append((command, options))
        if self.timeout:
            raise subprocess.TimeoutExpired(command, options["timeout"])
        Path(command[command.index("--output") + 1]).write_bytes(self.body)
        self.after_request()
        return subprocess.CompletedProcess(command, self.exit_code, self.status)


class GitHubReadClientTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.bundle = self.directory / "reviewed.pem"
        # A synthetic digest fixture. No TLS or network connection is made here.
        self.bundle.write_bytes(b"synthetic reviewed bundle")
        self.digest = hashlib.sha256(self.bundle.read_bytes()).hexdigest()
        self.roots = self.directory / "no-additional-roots"
        self.roots.mkdir()
        self.curl = FakeCurl()
        self.now = 0.0

    def client(self, token=""):
        return gate.GitHubReadClient(self.bundle, self.roots, self.digest, token,
                                     run=self.curl, clock=lambda: self.now)

    def read(self, client=None):
        return (client or self.client())("/repos/durable-workflow/.github/pulls/7")

    def test_explicit_tls_and_data_only_get_use_no_redirect_or_decompression(self):
        self.assertEqual({"ok": True}, self.read())
        command, options = self.curl.calls[0]
        self.assertEqual(["/usr/bin/curl", "--disable"], command[:2])
        self.assertEqual("=https", command[command.index("--proto") + 1])
        self.assertEqual(str(self.bundle), command[command.index("--cacert") + 1])
        self.assertEqual(str(self.roots), command[command.index("--capath") + 1])
        self.assertEqual(str(gate.MAX_RESPONSE_BYTES), command[command.index("--max-filesize") + 1])
        self.assertIn("Accept-Encoding: identity", command)
        self.assertNotIn("--compressed", command)
        self.assertNotIn("--location", command)
        self.assertNotIn("--insecure", command)
        self.assertLessEqual(options["timeout"], gate.REQUEST_SECONDS)

    def test_read_token_is_passed_only_on_stdin_not_process_arguments(self):
        self.read(self.client("synthetic_read_token"))
        command, options = self.curl.calls[0]
        self.assertNotIn("synthetic_read_token", " ".join(command))
        self.assertEqual(b'header = "Authorization: Bearer synthetic_read_token"\n', options["input"])

    def test_unsafe_or_write_endpoints_refuse_before_any_http_call(self):
        client = self.client()
        for path in ("https://elsewhere.test/", "/repos/durable-workflow/.github/check-runs",
                     "/repos/../.github/pulls/7", "/repos/a/b/pulls/7?redirect=elsewhere",
                     "/repos/a/b/git/blobs/" + "a" * 39):
            with self.subTest(path=path), self.assertRaises(InputRefused):
                client(path)
        self.assertEqual([], self.curl.calls)

    def test_newline_or_quote_in_read_token_refuses(self):
        for token in ('bad"token', "bad\nheader", "bad\\config"):
            with self.subTest(token=token), self.assertRaises(InputRefused):
                self.client(token)

    def test_old_curl_cannot_claim_unknown_length_response_protection(self):
        for version in (b"curl 8.3.0\n", b"curl 7.88.1\n", b"unknown\n"):
            self.curl.version = version
            with self.subTest(version=version), self.assertRaises(InputRefused):
                self.client()

    def test_wrong_bundle_and_additive_roots_refuse_before_requests(self):
        self.bundle.write_bytes(b"different")
        with self.assertRaises(InputRefused):
            self.client()
        self.bundle.write_bytes(b"synthetic reviewed bundle")
        (self.roots / "extra.pem").write_bytes(b"extra")
        with self.assertRaises(InputRefused):
            self.client()

    def test_bundle_symlink_refuses(self):
        real = self.directory / "real.pem"
        self.bundle.rename(real)
        self.bundle.symlink_to(real)
        with self.assertRaises(InputRefused):
            self.client()

    def test_redirect_and_failed_status_never_qualify(self):
        for status, exit_code in ((b"302", 0), (b"404", 22), (b"500", 22)):
            self.curl.status, self.curl.exit_code = status, exit_code
            with self.subTest(status=status), self.assertRaises(InputRefused):
                self.read()

    def test_malformed_duplicate_and_nonfinite_json_refuse(self):
        for body in (b"not json", b'{"a":1,"a":2}', b'{"x":NaN}', b'{"x":Infinity}', b"\xff",
                     '{"ok":true}'.encode("utf-16"), b"[]",
                     b'{"nested":' + b"[" * 2000 + b"]" * 2000 + b"}"):
            self.curl.body = body
            with self.subTest(size=len(body), prefix=body[:32]), self.assertRaises(InputRefused):
                self.read()

    def test_json_collection_bound_is_independent_of_the_transfer_limit(self):
        self.curl.body = json.dumps({"items": list(range(100))}).encode()
        with patch.object(gate, "MAX_JSON_NODES", 32), self.assertRaises(InputRefused):
            self.read()

    def test_oversized_body_refuses_even_if_a_transport_ignores_its_limit(self):
        with patch.object(gate, "MAX_RESPONSE_BYTES", 64):
            self.curl.body = b"x" * 65
            with self.assertRaisesRegex(InputRefused, "byte bound"):
                self.read()

    def test_transport_timeout_is_a_refusal_without_echoing_credentials(self):
        self.curl.timeout = True
        with self.assertRaises(InputRefused) as error:
            self.read(self.client("synthetic_read_token"))
        self.assertNotIn("synthetic_read_token", str(error.exception))

    def test_total_deadline_and_request_count_do_not_start_another_transfer(self):
        client = self.client()
        self.now = gate.TOTAL_SECONDS + 1
        with self.assertRaises(InputRefused):
            self.read(client)
        self.assertEqual([], self.curl.calls)
        self.now = 0
        with patch.object(gate, "MAX_REQUESTS", 1):
            client = self.client()
            self.read(client)
            with self.assertRaises(InputRefused):
                self.read(client)
        self.assertEqual(1, len(self.curl.calls))

    def test_expiry_during_a_transfer_cannot_return_a_pass(self):
        client = self.client()
        self.curl.after_request = lambda: setattr(self, "now", gate.TOTAL_SECONDS)
        with self.assertRaisesRegex(InputRefused, "deadline"):
            self.read(client)

    def test_last_request_uses_only_the_remaining_time(self):
        client = self.client()
        self.now = gate.TOTAL_SECONDS - 0.5
        self.read(client)
        command, options = self.curl.calls[0]
        self.assertEqual(0.5, options["timeout"])
        self.assertEqual("0.5", command[command.index("--max-time") + 1])


SAFE_WORKFLOW = b"""name: Candidate
on:
  pull_request:
permissions:
  contents: read
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: python scripts/candidate.py
"""


class ProtectedPolicySnapshotTest(unittest.TestCase):
    def setUp(self):
        self.api = fixtures.ProtectedPolicyInputTest(methodName="runTest")
        self.api.setUp()
        self.api.pull()["base"]["repo"]["id"] = gate.PILOT_REPOSITORY_ID
        self.branch = {"name": "main", "protected": True, "commit": {"sha": fixtures.BASE}}
        self.api.records[f"/repos/{gate.PILOT_REPOSITORY}/branches/main"] = self.branch
        self.api.entries.clear()
        self.api.add_file(fixtures.WORKFLOW, SAFE_WORKFLOW)
        self.api.add_file("scripts/candidate.py", b"raise SystemExit('candidate must not execute')\n", "100755")

    def validate(self, **options):
        return gate.validate_snapshot(self.api.read, 7, fixtures.BASE, **options)

    def test_real_validator_reads_candidate_data_without_executing_it(self):
        report = self.validate()
        self.assertEqual(fixtures.HEAD, report["head_sha"])
        self.assertEqual(2, report["input_count"])
        self.assertEqual(gate.PILOT_REPOSITORY_ID, report["repository_id"])
        self.assertEqual(64, len(report["inputs_sha256"]))
        self.assertNotIn("candidate must not execute", json.dumps(report))

    def test_validator_gets_nonexecutable_files_and_temporary_data_is_retired(self):
        from scripts.qualification_policy import validate_local_action_references

        observed = []

        def inspect(policy, directory, target):
            observed.append(directory.parent.parent)
            helper = directory.parent.parent / "scripts/candidate.py"
            self.assertEqual(0o600, helper.stat().st_mode & 0o777)
            return validate_local_action_references(policy, directory, target)

        self.validate(validator=inspect)
        self.assertFalse(observed[0].exists())

    def test_forbidden_workflow_is_a_refusal_not_a_success_report(self):
        self.api.entries.clear()
        self.api.add_file(fixtures.WORKFLOW, SAFE_WORKFLOW.replace(b"pull_request:", b"pull_request_target:"))
        with self.assertRaisesRegex(InputRefused, "forbidden"):
            self.validate()

    def test_unprotected_main_refuses_before_candidate_blobs(self):
        self.branch["protected"] = False
        with self.assertRaises(InputRefused):
            self.validate()
        self.assertFalse(any("/git/blobs/" in request for request in self.api.requests))

    def test_base_or_head_movement_after_validation_refuses(self):
        def move_base(*_arguments):
            self.branch["commit"]["sha"] = "d" * 40
            return []

        with self.assertRaises(InputRefused):
            self.validate(validator=move_base)
        self.branch["commit"]["sha"] = fixtures.BASE

        def move_head(*_arguments):
            self.api.pull()["head"]["sha"] = "d" * 40
            return []

        with self.assertRaises(InputRefused):
            self.validate(validator=move_head)

    def test_wrong_immutable_repository_id_refuses(self):
        self.api.pull()["base"]["repo"]["id"] += 1
        with self.assertRaises(InputRefused):
            self.validate()

    def test_error_output_cannot_become_a_github_workflow_command(self):
        arguments = ["gate", "--pull-request", "7", "--base-sha", fixtures.BASE]
        environment = {"CURL_CA_BUNDLE": "synthetic", "SSL_CERT_DIR": "synthetic", "DW_CI_CA_SHA256": "synthetic"}
        output = io.StringIO()
        with patch.object(sys, "argv", arguments), patch.dict("os.environ", environment, clear=True):
            with patch.object(gate, "GitHubReadClient"), patch.object(gate, "validate_snapshot", side_effect=InputRefused("bad\n::error::candidate")):
                with contextlib.redirect_stderr(output):
                    self.assertEqual(1, gate.main())
        self.assertEqual(1, len(output.getvalue().splitlines()))
        self.assertEqual("bad\n::error::candidate", json.loads(output.getvalue())["policy_refused"])

    def test_isolated_cli_ignores_candidate_python_modules_in_its_working_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary) / "scripts"
            candidate.mkdir()
            (candidate / "__init__.py").write_text("raise SystemExit('candidate imported')\n")
            result = subprocess.run(
                [sys.executable, "-I", str(gate.ROOT / "scripts/protected_policy_check.py"), "--help"],
                cwd=temporary, capture_output=True, timeout=5, check=False,
            )
        self.assertEqual(0, result.returncode, result.stderr.decode())
        self.assertNotIn(b"candidate imported", result.stderr)

    def test_cli_does_not_offer_a_candidate_policy_override(self):
        arguments = ["gate", "--pull-request", "7", "--base-sha", fixtures.BASE, "--policy", "candidate.json"]
        with patch.object(sys, "argv", arguments), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as error:
                gate.main()
        self.assertEqual(2, error.exception.code)
