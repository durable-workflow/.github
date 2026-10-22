import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import protected_policy_issue as issue
from scripts.protected_policy_inputs import InputRefused
from tests import test_protected_policy_check as snapshot_fixtures
from tests.test_protected_policy_inputs import BASE, HEAD


APP_ID = 12345
CHECK_ID = 67890


class FakeIssuerCurl:
    """Only constructed HTTP responses. No App credential or network is used."""

    def __init__(self):
        self.calls = []
        self.app_id = APP_ID
        self.head = HEAD
        self.name = issue.CHECK_NAME
        self.status_override = None
        self.after_begin = lambda: None
        self.after_complete = lambda: None

    def __call__(self, command, **options):
        if "--version" in command:
            return subprocess.CompletedProcess(command, 0, b"curl 8.5.0 fixture\n")
        payload_file = command[command.index("--data-binary") + 1][1:]
        payload = json.loads(Path(payload_file).read_text())
        self.calls.append((command, options, payload))
        beginning = command[command.index("--request") + 1] == "POST"
        record = {
            "id": CHECK_ID, "name": self.name, "head_sha": self.head,
            "app": {"id": self.app_id}, "status": "in_progress" if beginning else "completed",
            "conclusion": None if beginning else "success",
        }
        Path(command[command.index("--output") + 1]).write_text(json.dumps(record))
        (self.after_begin if beginning else self.after_complete)()
        status = self.status_override or (b"201" if beginning else b"200")
        return subprocess.CompletedProcess(command, 0, status)


class ProtectedPolicyIssuerTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.bundle = root / "ca.pem"
        self.bundle.write_bytes(b"synthetic reviewed CA")
        self.digest = hashlib.sha256(self.bundle.read_bytes()).hexdigest()
        self.roots = root / "empty"
        self.roots.mkdir()
        self.curl = FakeIssuerCurl()
        self.now = 0.0
        self.issuer = issue.CheckRunIssuer(
            self.bundle, self.roots, self.digest, "synthetic_app_token",
            expected_app_id=APP_ID, run=self.curl, clock=lambda: self.now,
        )
        self.snapshot = snapshot_fixtures.ProtectedPolicySnapshotTest(methodName="runTest")
        self.snapshot.setUp()
        self.api = self.snapshot.api

    def run_gate(self, *, head=HEAD):
        return issue.qualify_and_issue(self.api.read, self.issuer, 7, BASE, head)

    def test_real_validator_then_app_check_then_final_identity_recheck(self):
        report = self.run_gate()
        self.assertEqual(APP_ID, report["app_id"])
        self.assertEqual(HEAD, report["head_sha"])
        self.assertEqual(2, len(self.curl.calls))
        self.assertEqual("in_progress", self.curl.calls[0][2]["status"])
        self.assertNotIn("conclusion", self.curl.calls[0][2])
        self.assertEqual("success", self.curl.calls[1][2]["conclusion"])
        self.assertNotIn("candidate must not execute", json.dumps(report))
        self.assertEqual(f"/repos/{issue.PILOT_REPOSITORY}/pulls/7", self.api.requests[-1])

    def test_check_write_endpoint_is_fixed_to_the_pilot(self):
        self.run_gate()
        urls = [command[command.index("--url") + 1] for command, _, _ in self.curl.calls]
        self.assertEqual([
            f"https://api.github.com/repos/{issue.PILOT_REPOSITORY}/check-runs",
            f"https://api.github.com/repos/{issue.PILOT_REPOSITORY}/check-runs/{CHECK_ID}",
        ], urls)

    def test_app_token_is_stdin_only_and_cannot_make_generic_reads(self):
        self.run_gate()
        for command, options, _ in self.curl.calls:
            self.assertNotIn("synthetic_app_token", " ".join(command))
            self.assertEqual(b'header = "Authorization: Bearer synthetic_app_token"\n', options["input"])
            self.assertIn("Accept-Encoding: identity", command)
            self.assertNotIn("--location", command)
            self.assertNotIn("--compressed", command)
        with self.assertRaises(InputRefused):
            self.issuer(f"/repos/{issue.PILOT_REPOSITORY}/pulls/7")

    def test_wrong_issuer_can_never_complete_a_success(self):
        self.curl.app_id = APP_ID + 1
        with self.assertRaisesRegex(InputRefused, "App issuer"):
            self.run_gate()
        self.assertEqual(1, len(self.curl.calls))
        self.assertNotIn("conclusion", self.curl.calls[0][2])

    def test_ordinary_actions_issuer_is_not_the_expected_app(self):
        self.curl.app_id = 15368
        with self.assertRaises(InputRefused):
            self.run_gate()
        self.assertEqual(1, len(self.curl.calls))

    def test_empty_installation_token_refuses(self):
        with self.assertRaises(InputRefused):
            issue.CheckRunIssuer(
                self.bundle, self.roots, self.digest, "", expected_app_id=APP_ID,
                run=self.curl, clock=lambda: self.now,
            )
        self.assertEqual([], self.curl.calls)

    def test_noninteger_app_id_is_not_accepted(self):
        self.curl.app_id = str(APP_ID)
        with self.assertRaises(InputRefused):
            self.run_gate()
        self.assertEqual(1, len(self.curl.calls))

    def test_wrong_returned_name_never_completes(self):
        self.curl.name = "unrelated"
        with self.assertRaises(InputRefused):
            self.run_gate()
        self.assertEqual(1, len(self.curl.calls))

    def test_wrong_returned_head_never_completes(self):
        self.curl.head = "d" * 40
        with self.assertRaises(InputRefused):
            self.run_gate()
        self.assertEqual(1, len(self.curl.calls))

    def test_head_changed_after_app_identity_refuses_success(self):
        self.curl.after_begin = lambda: self.api.pull()["head"].update(sha="d" * 40)
        with self.assertRaises(InputRefused):
            self.run_gate()
        self.assertEqual(1, len(self.curl.calls))

    def test_base_changed_after_app_identity_refuses_success(self):
        self.curl.after_begin = lambda: self.snapshot.branch["commit"].update(sha="d" * 40)
        with self.assertRaises(InputRefused):
            self.run_gate()
        self.assertEqual(1, len(self.curl.calls))

    def test_unprotected_base_after_app_identity_refuses_success(self):
        self.curl.after_begin = lambda: self.snapshot.branch.update(protected=False)
        with self.assertRaises(InputRefused):
            self.run_gate()
        self.assertEqual(1, len(self.curl.calls))

    def test_stale_event_never_reads_candidate_blobs_or_writes_checks(self):
        with self.assertRaises(InputRefused):
            self.run_gate(head="d" * 40)
        self.assertEqual([], self.curl.calls)
        self.assertFalse(any("/git/blobs/" in path for path in self.api.requests))

    def test_real_forbidden_policy_never_creates_a_check(self):
        self.api.entries.clear()
        self.api.add_file(".github/workflows/bad.yml", b"on:\n  pull_request_target:\njobs: {}\n")
        with self.assertRaisesRegex(InputRefused, "forbidden"):
            self.run_gate()
        self.assertEqual([], self.curl.calls)

    def test_http_redirect_is_not_a_verified_app_response(self):
        self.curl.status_override = b"302"
        with self.assertRaises(InputRefused):
            self.run_gate()
        self.assertEqual(1, len(self.curl.calls))

    def test_expired_transport_cannot_finish_the_pending_check(self):
        self.curl.after_begin = lambda: setattr(self, "now", 121.0)
        with self.assertRaises(InputRefused):
            self.run_gate()
        self.assertEqual(1, len(self.curl.calls))

    def test_completion_response_identity_is_still_verified(self):
        self.curl.after_begin = lambda: setattr(self.curl, "app_id", APP_ID + 1)
        with self.assertRaises(InputRefused):
            self.run_gate()

    def test_failed_completion_is_not_reported_as_a_success(self):
        self.curl.after_begin = lambda: setattr(self.curl, "status_override", b"500")
        with self.assertRaises(InputRefused):
            self.run_gate()

    def test_an_unbound_snapshot_report_cannot_create_a_check(self):
        report = issue.validate_snapshot(self.api.read, 7, BASE)
        report["head_repository_id"] += 1
        with patch.object(issue, "validate_snapshot", return_value=report), self.assertRaises(InputRefused):
            self.run_gate()
        self.assertEqual([], self.curl.calls)

    def test_issuer_cannot_be_reused(self):
        self.run_gate()
        with self.assertRaises(InputRefused):
            self.issuer.begin(HEAD)
        self.assertEqual(2, len(self.curl.calls))

    def test_completion_requires_matching_original_head(self):
        with self.assertRaises(InputRefused):
            self.issuer.complete({"head_sha": HEAD})
        self.issuer.begin(HEAD)
        with self.assertRaises(InputRefused):
            self.issuer.complete({"head_sha": "d" * 40})
        self.assertEqual(1, len(self.curl.calls))

    def test_valid_cli_wires_separate_clients_to_one_total_deadline(self):
        environment = {
            **ProtectedIssuerCallerTest("runTest").environment(),
            "CURL_CA_BUNDLE": str(self.bundle), "SSL_CERT_DIR": str(self.roots),
            "DW_CI_CA_SHA256": self.digest, "GITHUB_TOKEN": "synthetic_read_token",
            "POLICY_GATE_APP_ID": str(APP_ID), "POLICY_CHECKS_TOKEN": "synthetic_app_token",
        }
        read = Mock(side_effect=self.api.read)
        read.deadline = 80.0
        args = ["issuer", "--pull-request", "7", "--base-sha", BASE, "--expected-head", HEAD]
        output = io.StringIO()
        with patch.object(sys, "argv", args), patch.dict(os.environ, environment, clear=True):
            with patch.object(issue, "GitHubReadClient", return_value=read) as read_factory:
                with patch.object(issue, "CheckRunIssuer", return_value=self.issuer) as write_factory:
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(0, issue.main())
        self.assertEqual(80.0, self.issuer.deadline)
        self.assertEqual("synthetic_read_token", read_factory.call_args.args[3])
        self.assertEqual("synthetic_app_token", write_factory.call_args.args[3])
        self.assertEqual(HEAD, json.loads(output.getvalue())["head_sha"])
        self.assertNotIn("synthetic_", output.getvalue())


class ProtectedIssuerCallerTest(unittest.TestCase):
    def environment(self):
        return {
            "GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": issue.PILOT_REPOSITORY,
            "GITHUB_REPOSITORY_ID": str(issue.PILOT_REPOSITORY_ID), "GITHUB_REF": "refs/heads/main",
            "GITHUB_SHA": BASE, "GITHUB_EVENT_NAME": "pull_request_target",
            "GITHUB_WORKFLOW_REF": issue.WORKFLOW_REF,
        }

    def test_protected_caller_context_matches(self):
        issue.require_protected_execution(self.environment(), BASE)

    def test_each_missing_or_wrong_context_field_refuses(self):
        environment = self.environment()
        for name in environment:
            with self.subTest(name=name), self.assertRaises(InputRefused):
                issue.require_protected_execution({**environment, name: "wrong"}, BASE)
            with self.subTest(missing=name), self.assertRaises(InputRefused):
                issue.require_protected_execution({key: value for key, value in environment.items() if key != name}, BASE)

    def test_nonmain_execution_fails_before_credentials_or_clients(self):
        args = ["issuer", "--pull-request", "7", "--base-sha", BASE, "--expected-head", HEAD]
        output = io.StringIO()
        with patch.object(sys, "argv", args), patch.dict(os.environ, {}, clear=True):
            with patch.object(issue, "GitHubReadClient") as client, contextlib.redirect_stderr(output):
                self.assertEqual(1, issue.main())
        client.assert_not_called()
        self.assertIn("protected-main", json.loads(output.getvalue())["policy_refused"])

    def test_isolated_cli_does_not_import_candidate_python(self):
        with tempfile.TemporaryDirectory() as temporary:
            scripts = Path(temporary) / "scripts"
            scripts.mkdir()
            (scripts / "__init__.py").write_text("raise SystemExit('candidate imported')\n")
            result = subprocess.run(
                [sys.executable, "-I", str(issue.ROOT / "scripts/protected_policy_issue.py"), "--help"],
                cwd=temporary, capture_output=True, timeout=5, check=False,
            )
        self.assertEqual(0, result.returncode, result.stderr.decode())
        self.assertNotIn(b"candidate imported", result.stderr)

    def test_malformed_app_id_does_not_echo_its_value(self):
        environment = {**self.environment(), "CURL_CA_BUNDLE": "synthetic", "SSL_CERT_DIR": "synthetic",
                       "DW_CI_CA_SHA256": "synthetic", "GITHUB_TOKEN": "synthetic_read_token",
                       "POLICY_GATE_APP_ID": "invalid_sensitive_value"}
        args = ["issuer", "--pull-request", "7", "--base-sha", BASE, "--expected-head", HEAD]
        output = io.StringIO()
        with patch.object(sys, "argv", args), patch.dict(os.environ, environment, clear=True):
            with patch.object(issue, "GitHubReadClient"), patch.object(issue, "CheckRunIssuer") as issuer:
                with contextlib.redirect_stderr(output):
                    self.assertEqual(1, issue.main())
        issuer.assert_not_called()
        self.assertNotIn("invalid_sensitive_value", output.getvalue())
