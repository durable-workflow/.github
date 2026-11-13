from __future__ import annotations

import copy
import contextlib
import io
import hashlib
import json
import subprocess
import secrets
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import yaml
from unittest.mock import patch

from scripts.qualification_policy import (
    GitHubClient,
    PolicyError,
    audit_action_releases,
    _verify_action_policy_preflight,
    _verify_cloud_route_environment,
    scan_workflow_sources,
    validate_local_action_references,
    validate_policy,
    verify_workflow_source,
)

ROOT = Path(__file__).resolve().parents[1]


class GitHubRedirectBoundaryTest(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict("os.environ", {"NO_PROXY": "127.0.0.1,localhost"})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.token = "synthetic-" + secrets.token_hex(8)
        self.api, self.api_url = self.server()
        self.other, self.other_url = self.server()

    def server(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                authorization = self.headers.get("Authorization")
                self.server.seen.append((self.path, authorization))
                redirect = self.server.redirects.get(self.path)
                if redirect:
                    self.send_response(302)
                    self.send_header("Location", redirect)
                    self.end_headers()
                    return
                body = b'{"ok":true}'
                limited = self.path == "/fallback" and authorization is not None
                self.send_response(429 if limited else 200)
                if limited:
                    self.send_header("X-RateLimit-Remaining", "0")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_arguments):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.seen, server.redirects = [], {}
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()

        def close():
            server.shutdown()
            server.server_close()
            thread.join(timeout=1)

        self.addCleanup(close)
        return server, f"http://127.0.0.1:{server.server_port}"

    def client(self, token=None):
        return GitHubClient(token, self.api_url, max_attempts=1,
                            request_timeout_seconds=2, audit_timeout_seconds=5)

    def test_cross_origin_redirect_refuses_before_any_destination_request(self):
        self.api.redirects["/redirect"] = self.other_url + "/destination"
        client = self.client(self.token)
        with self.assertRaisesRegex(PolicyError, "redirect.*origin"):
            client.json("/redirect")
        self.assertEqual([], self.other.seen)

    def test_same_origin_redirect_retains_the_authenticated_api_request(self):
        self.api.redirects["/redirect"] = "/destination"
        self.assertEqual({"ok": True}, self.client(self.token).json("/redirect"))
        self.assertEqual([("/redirect", "Bearer " + self.token),
                          ("/destination", "Bearer " + self.token)], self.api.seen)

    def test_rate_limit_fallback_stays_on_the_selected_origin_without_credentials(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual({"ok": True}, self.client(self.token).json("/fallback"))
        self.assertEqual([("/fallback", "Bearer " + self.token), ("/fallback", None)], self.api.seen)


def policy_fixture() -> dict[str, object]:
    return json.loads((ROOT / "qualification/policy.json").read_text(encoding="utf-8"))


def workflow(*steps: str, trigger: str = "pull_request", permissions: str = "contents: read") -> str:
    rendered_steps = "\n".join(f"      {line}" for step in steps for line in step.splitlines())
    return f"""name: test
on:
  {trigger}:
permissions:
  {permissions}
jobs:
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    steps:
{rendered_steps}
"""


class QualificationPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = policy_fixture()

    def scan(self, source: str) -> dict[str, dict[str, object]]:
        return scan_workflow_sources(
            self.policy,
            "github-control-plane",
            {".github/workflows/test.yml": source},
        )

    def approved_action(self, repository: str) -> tuple[str, str]:
        releases = self.policy["action_runtime"]["allowed_releases"][repository]
        commit, version = next(iter(releases.items()))
        return commit, version

    def privileged_dispatch(self, condition: str) -> str:
        return workflow("- run: echo checked", trigger="workflow_dispatch").replace(
            "    runs-on:",
            f"    if: ${{{{ {condition} }}}}\n    permissions:\n      contents: write\n    runs-on:",
        )

    def test_dispatch_rejects_case_and_bare_negation_bypasses(self) -> None:
        for condition in (
            "github.event_name == 'WORKFLOW_DISPATCH'",
            "github.event_name == 'WorkFlow_Dispatch'",
            "!github.event_name != 'push'",
            "(!github.event_name != 'push') && github.ref != 'refs/heads/main'",
            "!github.ref != 'refs/heads/main'",
            "github.ref == 'refs/heads/main' || github.event_name == 'WORKFLOW_DISPATCH'",
            "!(github.ref == 'refs/heads/main')",
            "github.ref == 'refs/heads/other'",
            "success() || github.ref == 'refs/heads/main'",
            "!false",
            "github.event_name != 'workﬂow_dispatch'",
            "github.event_name != 'workflow_diſpatch'",
            "falſe",
        ):
            candidate = self.privileged_dispatch(condition)
            with self.subTest(condition=condition), self.assertRaisesRegex(
                PolicyError, "privileged workflow_dispatch.*outside"
            ):
                self.scan(candidate)

    def test_dispatch_retains_protected_ref_guards_and_boolean_composition(self) -> None:
        for condition in (
            "github.ref == 'refs/heads/main'",
            "!(github.ref != 'refs/heads/main')",
            "github.event_name == 'push' || github.ref == 'refs/heads/main'",
            "github.event_name != 'WORKFLOW_DISPATCH' || github.ref == 'refs/heads/main'",
            "github.event_name == 'WORKFLOW_DISPATCH' && github.ref == 'refs/heads/main'",
            "always() && github.ref == 'refs/heads/main'",
            "!true",
            "false",
        ):
            with self.subTest(condition=condition):
                self.scan(self.privileged_dispatch(condition))

    def test_checked_in_policy_is_valid_and_has_no_retired_consumers(self) -> None:
        validate_policy(self.policy)
        self.assertEqual(
            {},
            self.policy["workflow_trust"]["privileged_workflow_run_consumers"],
        )
        self.assertEqual(
            [{
                "matrix_independent": False,
                "path": "ci.yml",
                "required_check": "Shared contract tests",
            }],
            self.policy["targets"]["github-control-plane"]["workflows"],
        )

    def test_current_control_repository_workflows_satisfy_policy(self) -> None:
        actions = validate_local_action_references(
            self.policy,
            ROOT / ".github/workflows",
            "github-control-plane",
        )
        self.assertTrue(actions)
        self.assertTrue(all("@" in action for action in actions))

    def test_policy_preflight_accepts_binary_only_without_relaxing_dependency_command(self) -> None:
        checkout, _ = self.approved_action("actions/checkout")
        setup_python, _ = self.approved_action("actions/setup-python")
        jobs = {
            "action-policy": {
                "name": "Central action policy preflight",
                "runs-on": "ubuntu-latest",
                "timeout-minutes": "5",
                "steps": [
                    {"uses": f"actions/checkout@{checkout}", "with": {"persist-credentials": "false"}},
                    {
                        "uses": f"actions/checkout@{checkout}",
                        "with": {
                            "repository": "durable-workflow/.github",
                            "ref": "main",
                            "path": ".central-action-policy",
                            "persist-credentials": "false",
                        },
                    },
                    {"uses": f"actions/setup-python@{setup_python}", "with": {"python-version": "3.13"}},
                    {"run": "python -m pip install PyYAML==6.0.2"},
                    {"run": "python .central-action-policy/scripts/qualification_policy.py validate "
                     "--policy .central-action-policy/qualification/policy.json --target ai "
                     "--workflow-directory .github/workflows"},
                ],
            },
            "gate": {
                "needs": ["action-policy"],
                "if": "${{ always() }}",
                "steps": [{
                    "env": {"ACTION_POLICY_RESULT": "${{ needs.action-policy.result }}"},
                    "run": 'test "$ACTION_POLICY_RESULT" = success',
                }],
            },
        }
        for command in (
            "python -m pip install PyYAML==6.0.2",
            "python -m pip install --only-binary :all: PyYAML==6.0.2",
        ):
            with self.subTest(command=command):
                jobs["action-policy"]["steps"][3]["run"] = command
                _verify_action_policy_preflight("ai", "fixture", jobs, "gate")
        for suffix in ("==6.0.3", "==6.0.2 --extra-index-url https://example.com", "==6.0.2; echo unsafe"):
            with self.subTest(suffix=suffix), self.assertRaisesRegex(PolicyError, "reviewed policy dependency"):
                jobs["action-policy"]["steps"][3]["run"] = "python -m pip install --only-binary :all: PyYAML" + suffix
                _verify_action_policy_preflight("ai", "fixture", jobs, "gate")

        steps = jobs["action-policy"]["steps"]
        steps[3]["run"] = "python -m pip install PyYAML==6.0.2"
        bootstrap = {
            "name": "Bootstrap patched pip trust",
            "uses": "durable-workflow/.github/.github/actions/bootstrap-patched-pip@ff93e15dd3d3aa0b5ba8991fe5101a9e1be49c10",
        }
        steps.insert(3, bootstrap)
        _verify_action_policy_preflight("ai", "fixture", jobs, "gate")
        for revision, label in self.policy["action_runtime"]["allowed_releases"]["durable-workflow/.github"].items():
            if label == "clean-trust":
                steps[3] = {**bootstrap, "uses": bootstrap["uses"].rsplit("@", 1)[0] + "@" + revision}
                _verify_action_policy_preflight("ai", "fixture", jobs, "gate", {revision})
        for change in (
            {**bootstrap, "uses": bootstrap["uses"].replace("ff93e15", "0000000")},
            {**bootstrap, "if": "false"},
            {"run": "python -m pip install --upgrade pip"},
        ):
            with self.subTest(bootstrap=change), self.assertRaisesRegex(PolicyError, "unreviewed pip bootstrap"):
                steps[3] = change
                _verify_action_policy_preflight("ai", "fixture", jobs, "gate")
        steps[3] = bootstrap
        steps[3], steps[4] = steps[4], steps[3]
        with self.assertRaisesRegex(PolicyError, "unreviewed pip bootstrap"):
            _verify_action_policy_preflight("ai", "fixture", jobs, "gate")

    def pinned_policy_preflight(self):
        checkout, _ = self.approved_action("actions/checkout")
        setup_python, _ = self.approved_action("actions/setup-python")
        bootstrap = "75587fc33ff40c34f32ef777293dad56bb6f48c7"
        steps = [
            {"uses": f"actions/checkout@{checkout}", "with": {"persist-credentials": "false"}},
            {"uses": f"actions/checkout@{checkout}", "with": {
                "repository": "durable-workflow/.github", "ref": "main",
                "path": ".central-action-policy", "persist-credentials": "false"}},
            {"env": {"POLICY_CENTRAL_SHA": "58893e29b535d49cdbfd262c2cabf57b32212f6e"},
             "run": 'set -euo pipefail\n'
                    'test "$(git -C .central-action-policy rev-parse HEAD)" = "$POLICY_CENTRAL_SHA"'},
            {"uses": f"actions/setup-python@{setup_python}", "with": {"python-version": "3.13.18"}},
            {"uses": "durable-workflow/.github/.github/actions/bootstrap-patched-pip@" + bootstrap},
            {"run": "python -I -m pip --disable-pip-version-check install --require-hashes --no-deps "
                    "--only-binary=:all: -r .central-action-policy/qualification/requirements.lock"},
            {"run": "python -I -c 'import sys, yaml; assert sys.version_info[:3] == (3, 13, 18); "
                    'assert yaml.__version__ == "6.0.2"; print(sys.version.split()[0], yaml.__version__)\''},
            {"run": "python -I .central-action-policy/scripts/qualification_policy.py validate "
                    "--policy .central-action-policy/qualification/policy.json --target cloud "
                    "--workflow-directory .github/workflows"},
        ]
        return {
            "action-policy": {"name": "Central action policy preflight", "runs-on": "ubuntu-latest",
                              "timeout-minutes": "5", "steps": steps},
            "gate": {"needs": ["action-policy"], "if": "${{ always() }}",
                     "runs-on": "ubuntu-latest", "timeout-minutes": "5", "steps": [{
                "env": {"ACTION_POLICY_RESULT": "${{ needs.action-policy.result }}"},
                "run": 'test "$ACTION_POLICY_RESULT" = success'}]},
        }

    def test_pinned_preflight_accepts_only_the_complete_ordered_profile(self):
        jobs = self.pinned_policy_preflight()
        _verify_action_policy_preflight("cloud", "fixture", jobs, "gate")
        jobs["action-policy"]["steps"][4]["with"] = {"clients": "pip,python"}
        _verify_action_policy_preflight("cloud", "fixture", jobs, "gate",
                                        {"75587fc33ff40c34f32ef777293dad56bb6f48c7"})
        with self.assertRaisesRegex(PolicyError, "clean-trust"):
            _verify_action_policy_preflight("cloud", "fixture", jobs, "gate", set())

    def test_pinned_profile_is_checked_through_the_actual_workflow_source_parser(self):
        jobs = self.pinned_policy_preflight()
        jobs["gate"]["name"] = "Source qualification"
        prefix = "name: fixture\non:\n  push:\n    branches: [main]\n  pull_request:\n  workflow_dispatch:\npermissions:\n  contents: read\n"
        definition = {"path": "fixture.yml", "required_check": "Source qualification",
                      "matrix_independent": False, "action_policy_preflight": True}
        source = prefix + yaml.safe_dump({"jobs": jobs}, sort_keys=False)
        verify_workflow_source("cloud", "main", definition, source,
                               {"75587fc33ff40c34f32ef777293dad56bb6f48c7"})
        jobs["action-policy"]["steps"][3]["with"]["python-version"] = "3.13"
        changed = prefix + yaml.safe_dump({"jobs": jobs}, sort_keys=False)
        with self.assertRaisesRegex(PolicyError, "Python runtime"):
            verify_workflow_source("cloud", "main", definition, changed,
                                   {"75587fc33ff40c34f32ef777293dad56bb6f48c7"})

    def pinned_workflow_document(self):
        jobs = self.pinned_policy_preflight()
        jobs["gate"]["name"] = "Source qualification"
        return {"name": "fixture", "permissions": {"contents": "read"}, "jobs": jobs}

    def verify_pinned_document(self, document):
        triggers = "on:\n  push:\n    branches: [main]\n  pull_request:\n  workflow_dispatch:\n"
        definition = {"path": "fixture.yml", "required_check": "Source qualification",
                      "matrix_independent": False, "action_policy_preflight": True}
        verify_workflow_source("cloud", "main", definition,
            triggers + yaml.safe_dump(document, sort_keys=False),
            {"75587fc33ff40c34f32ef777293dad56bb6f48c7"})

    def pinned_context_mutations(self):
        changes = []
        for key, value in (
            ("env", {"BASH_ENV": "/tmp/foreign-startup"}),
            ("defaults", {"run": {"shell": "true {0}"}}),
            ("permissions", {"contents": "write"}),
            ("unreviewed", "context"),
        ):
            document = self.pinned_workflow_document()
            document[key] = value
            changes.append(document)
        for key, value in (
            ("env", {"BASH_ENV": "/tmp/foreign-startup"}),
            ("defaults", {"run": {"shell": "true {0}"}}),
            ("continue-on-error", True), ("container", "foreign"),
            ("services", {"foreign": {"image": "foreign"}}),
            ("permissions", {"contents": "write"}),
        ):
            document = self.pinned_workflow_document()
            document["jobs"]["gate"][key] = value
            changes.append(document)
        for condition in ("always() || true", "always() && false", "false || always()"):
            document = self.pinned_workflow_document()
            document["jobs"]["gate"]["if"] = condition
            changes.append(document)
        for key, value in (
            ("if", "false"), ("if", "github.server_url == 'https://github.com'"),
            ("continue-on-error", True), ("shell", "true {0}"),
            ("working-directory", "/tmp/foreign"), ("timeout-minutes", 1),
        ):
            document = self.pinned_workflow_document()
            document["jobs"]["gate"]["steps"][0][key] = value
            changes.append(document)
        return changes

    def test_pinned_workflow_and_result_gate_contexts_are_closed_through_actual_parser(self):
        self.verify_pinned_document(self.pinned_workflow_document())
        for index, document in enumerate(self.pinned_context_mutations()):
            with self.subTest(change=index), self.assertRaises(PolicyError):
                self.verify_pinned_document(document)

    def pinned_gate_mutations(self):
        changes = []
        for step in ({"run": "echo unreviewed"},
                     {"uses": "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"}):
            document = self.pinned_workflow_document()
            document["jobs"]["gate"]["steps"].insert(0, step)
            changes.append(document)
        for key, value in (("runs-on", "self-hosted"), ("runs-on", "ubuntu-24.04"),
                           ("timeout-minutes", "60"), ("timeout-minutes", None),
                           ("needs", ["action-policy", "foreign"]),
                           ("needs", ["action-policy", "action-policy"])):
            document = self.pinned_workflow_document()
            document["jobs"]["gate"][key] = value
            changes.append(document)
        return changes

    def test_pinned_gate_asserts_first_on_its_exact_runner_timeout_and_dependencies(self):
        document = self.pinned_workflow_document()
        document["jobs"]["gate"]["needs"] = "action-policy"
        self.verify_pinned_document(document)
        for index, document in enumerate(self.pinned_gate_mutations()):
            with self.subTest(change=index), self.assertRaises(PolicyError):
                self.verify_pinned_document(document)

    def cloud_profile_document(self):
        document = self.pinned_workflow_document()
        gate = document["jobs"].pop("gate")
        gate.update(name="Route Drift Guard", **{
            "if": "${{ always() && !inputs.hotfix_build }}", "timeout-minutes": "20",
            "env": {"APP_ENV": "testing", "APP_KEY": "synthetic-public-fixture",
                "BCRYPT_ROUNDS": "4", "BROADCAST_CONNECTION": "null", "CACHE_STORE": "array",
                "DB_CONNECTION": "sqlite", "DB_DATABASE": ":memory:", "MAIL_MAILER": "array",
                "QUEUE_CONNECTION": "sync", "SESSION_DRIVER": "array"}})
        document["jobs"]["route-drift-guard"] = gate
        document["jobs"]["hotfix-build"] = {
            "if": "${{ github.event_name == 'workflow_dispatch' && inputs.hotfix_build }}",
            "needs": "action-policy", "runs-on": "ubuntu-24.04", "timeout-minutes": "60",
            "steps": [{"run": "echo inert-public-fixture"}]}
        document["jobs"]["ordinary-source"] = {
            "if": "${{ !inputs.hotfix_build }}", "runs-on": "ubuntu-latest",
            "timeout-minutes": "5", "steps": [{"run": "echo inert-ordinary-source"}]}
        return document

    def cloud_environment_digest(self, document):
        environment = document["jobs"]["route-drift-guard"]["env"]
        return hashlib.sha256(json.dumps(environment, sort_keys=True, separators=(",", ":"),
                                         ensure_ascii=False).encode("utf-8")).hexdigest()

    def verify_cloud_document(self, document, target="cloud", required="Route Drift Guard"):
        definition = {"path": "ci.yml", "required_check": required,
                      "matrix_independent": False, "action_policy_preflight": True}
        triggers = "on:\n  push:\n    branches: [main]\n  pull_request:\n  workflow_dispatch:\n"
        verify_workflow_source(target, "main", definition,
            triggers + yaml.safe_dump(document, sort_keys=False),
            {"75587fc33ff40c34f32ef777293dad56bb6f48c7"})

    def test_cloud_profile_requires_the_exact_private_environment_authority(self):
        document = self.cloud_profile_document()
        with self.assertRaisesRegex(PolicyError, "exact reviewed mapping"):
            self.verify_cloud_document(document)
        digest = self.cloud_environment_digest(document)
        with patch("scripts.qualification_policy.CLOUD_ROUTE_ENV_SHA256", digest):
            self.verify_cloud_document(document)
            environment = document["jobs"]["route-drift-guard"]["env"]
            document["jobs"]["route-drift-guard"]["env"] = dict(reversed(list(environment.items())))
            self.verify_cloud_document(document)
            for key in environment:
                for kind in ("missing", "changed"):
                    changed = copy.deepcopy(environment)
                    if kind == "missing":
                        del changed[key]
                    else:
                        changed[key] += "changed"
                    document["jobs"]["route-drift-guard"]["env"] = changed
                    with self.subTest(key=key, kind=kind), self.assertRaises(PolicyError):
                        self.verify_cloud_document(document)
            environment["UNREVIEWED"] = "value"
            document["jobs"]["route-drift-guard"]["env"] = environment
            with self.assertRaises(PolicyError):
                self.verify_cloud_document(document)

    def test_cloud_environment_rejects_types_and_alternate_unicode_normalization(self):
        document = self.cloud_profile_document()
        environment = document["jobs"]["route-drift-guard"]["env"]
        environment["APP_ENV"] = "caf\u00e9"
        digest = self.cloud_environment_digest(document)
        with patch("scripts.qualification_policy.CLOUD_ROUTE_ENV_SHA256", digest):
            _verify_cloud_route_environment("fixture", environment)
            for value in (4, True, None, [], {}, "cafe\u0301"):
                changed = dict(environment, APP_ENV=value)
                with self.subTest(value=value), self.assertRaises(PolicyError):
                    _verify_cloud_route_environment("fixture", changed)

    def test_cloud_profile_refuses_target_job_and_required_check_substitution(self):
        document = self.cloud_profile_document()
        digest = self.cloud_environment_digest(document)
        with patch("scripts.qualification_policy.CLOUD_ROUTE_ENV_SHA256", digest):
            changed = copy.deepcopy(document)
            changed["jobs"]["action-policy"]["steps"][-1]["run"] = (
                changed["jobs"]["action-policy"]["steps"][-1]["run"].replace("--target cloud", "--target server"))
            with self.assertRaises(PolicyError):
                self.verify_cloud_document(changed, target="server")
            changed = copy.deepcopy(document)
            changed["jobs"]["other"] = changed["jobs"].pop("route-drift-guard")
            with self.assertRaises(PolicyError):
                self.verify_cloud_document(changed)
            document["jobs"]["route-drift-guard"]["name"] = "Other check"
            with self.assertRaises(PolicyError):
                self.verify_cloud_document(document, required="Other check")

    def test_cloud_profile_refuses_gate_drift_and_preassertion_execution(self):
        original = self.cloud_profile_document()
        digest = self.cloud_environment_digest(original)
        with patch("scripts.qualification_policy.CLOUD_ROUTE_ENV_SHA256", digest):
            for key, value in (("runs-on", "self-hosted"), ("timeout-minutes", "21"),
                ("if", "always()"), ("if", "always() || !inputs.hotfix_build"),
                ("needs", ["action-policy", "other"]), ("continue-on-error", True),
                ("defaults", {"run": {"shell": "true {0}"}})):
                document = copy.deepcopy(original)
                document["jobs"]["route-drift-guard"][key] = value
                with self.subTest(key=key, value=value), self.assertRaises(PolicyError):
                    self.verify_cloud_document(document)
            document = copy.deepcopy(original)
            document["jobs"]["route-drift-guard"]["steps"].insert(0, {"run": "echo unreviewed"})
            with self.assertRaises(PolicyError):
                self.verify_cloud_document(document)

    def test_cloud_profile_preserves_every_hotfix_policy_dependency(self):
        original = self.cloud_profile_document()
        digest = self.cloud_environment_digest(original)
        with patch("scripts.qualification_policy.CLOUD_ROUTE_ENV_SHA256", digest):
            for value in (None, [], "other", ["action-policy", "other"]):
                document = copy.deepcopy(original)
                document["jobs"]["hotfix-build"]["needs"] = value
                with self.subTest(needs=value), self.assertRaises(PolicyError):
                    self.verify_cloud_document(document)
            document = copy.deepcopy(original)
            document["jobs"]["extra-hotfix"] = copy.deepcopy(document["jobs"]["hotfix-build"])
            del document["jobs"]["extra-hotfix"]["needs"]
            with self.assertRaises(PolicyError):
                self.verify_cloud_document(document)
            document = copy.deepcopy(original)
            document["jobs"]["hotfix-build"]["if"] = "always()"
            with self.assertRaises(PolicyError):
                self.verify_cloud_document(document)

    def test_pinned_parser_refuses_duplicate_equivalent_mapping_keys(self):
        jobs = self.pinned_policy_preflight()
        jobs["gate"]["name"] = "Source qualification"
        prefix = "on:\n  push:\n    branches: [main]\n  pull_request:\n  workflow_dispatch:\n"
        source = prefix + yaml.safe_dump({"permissions": {"contents": "read"}, "jobs": jobs}, sort_keys=False)
        source = source.replace("contents: read", "contents: read\n  'contents': read")
        definition = {"path": "fixture.yml", "required_check": "Source qualification",
                      "matrix_independent": False, "action_policy_preflight": True}
        with self.assertRaisesRegex(PolicyError, "duplicate"):
            verify_workflow_source("cloud", "main", definition, source)

    def test_pinned_preflight_refuses_missing_malformed_late_and_collapsed_head_checks(self):
        changes = []
        for position in (2, 4, 6):
            jobs = self.pinned_policy_preflight()
            jobs["action-policy"]["steps"].pop(position)
            changes.append(jobs)
        for value in ("", "abc", "g" * 40, "${{ github.sha }}", "a" * 40 + "\n"):
            jobs = self.pinned_policy_preflight()
            jobs["action-policy"]["steps"][2]["env"]["POLICY_CENTRAL_SHA"] = value
            changes.append(jobs)
        for changed_run in (
            'set -euo pipefail test "$(git -C .central-action-policy rev-parse HEAD)" = "$POLICY_CENTRAL_SHA"',
            'set -euo pipefail\necho "$POLICY_CENTRAL_SHA"',
            'set -euo pipefail\ntest "$(git -C .central-action-policy rev-parse HEAD)" != "$POLICY_CENTRAL_SHA"',
        ):
            jobs = self.pinned_policy_preflight()
            jobs["action-policy"]["steps"][2]["run"] = changed_run
            changes.append(jobs)
        for index in range(7):
            jobs = self.pinned_policy_preflight()
            steps = jobs["action-policy"]["steps"]
            steps[index], steps[index + 1] = steps[index + 1], steps[index]
            changes.append(jobs)
        jobs = self.pinned_policy_preflight()
        jobs["action-policy"]["steps"].insert(2, {"run": "python .central-action-policy/unbound.py"})
        changes.append(jobs)
        for index, jobs in enumerate(changes):
            with self.subTest(change=index), self.assertRaises(PolicyError):
                _verify_action_policy_preflight("cloud", "fixture", jobs, "gate")

    def test_pinned_preflight_refuses_looser_source_runtime_dependency_and_readback(self):
        changes = []
        for key, value in (("repository", "other/policy"), ("ref", "a" * 40),
                           ("ref", "develop"), ("path", "other"), ("persist-credentials", "true")):
            jobs = self.pinned_policy_preflight()
            jobs["action-policy"]["steps"][1]["with"][key] = value
            changes.append(jobs)
        jobs = self.pinned_policy_preflight()
        jobs["action-policy"]["steps"][3]["with"]["python-version"] = "3.13"
        changes.append(jobs)
        for position, old, new in (
            (4, "75587fc33ff40c34f32ef777293dad56bb6f48c7", "ff93e15dd3d3aa0b5ba8991fe5101a9e1be49c10"),
            (5, " -I", ""), (5, "--require-hashes ", ""), (5, "--no-deps ", ""),
            (5, "--only-binary=:all: ", ""), (5, "requirements.lock", "requirements.txt"),
            (6, " -I", ""), (6, "(3, 13, 18)", "(3, 13)"), (6, "6.0.2", "6.0"),
            (7, " -I", ""), (7, "--target cloud", "--target ai"),
        ):
            jobs = self.pinned_policy_preflight()
            field = "uses" if position == 4 else "run"
            step = jobs["action-policy"]["steps"][position]
            step[field] = step[field].replace(old, new)
            changes.append(jobs)
        for index, jobs in enumerate(changes):
            with self.subTest(change=index), self.assertRaises(PolicyError):
                _verify_action_policy_preflight("cloud", "fixture", jobs, "gate")

    def test_pinned_preflight_does_not_allow_skips_context_changes_or_gate_bypass(self):
        for position in range(8):
            jobs = self.pinned_policy_preflight()
            jobs["action-policy"]["steps"][position]["if"] = "false"
            with self.subTest(step=position), self.assertRaises(PolicyError):
                _verify_action_policy_preflight("cloud", "fixture", jobs, "gate")
        for key, value in (("defaults", {"run": {"shell": "true {0}"}}),
                           ("continue-on-error", "true"), ("container", "unreviewed")):
            jobs = self.pinned_policy_preflight()
            jobs["action-policy"][key] = value
            with self.subTest(key=key), self.assertRaises(PolicyError):
                _verify_action_policy_preflight("cloud", "fixture", jobs, "gate")
        jobs = self.pinned_policy_preflight()
        jobs["gate"]["steps"][0]["run"] = "echo passed"
        with self.assertRaisesRegex(PolicyError, "closed unconditional"):
            _verify_action_policy_preflight("cloud", "fixture", jobs, "gate")

    def test_pinned_preflight_inline_head_check_refuses_actual_mismatch_before_following_code(self):
        with tempfile.TemporaryDirectory(prefix="policy-head-inert-") as directory:
            root = Path(directory)
            central = root / ".central-action-policy"
            environment = {"PATH": "/usr/bin:/bin", "GIT_CONFIG_GLOBAL": "/dev/null",
                           "GIT_CONFIG_SYSTEM": "/dev/null", "LC_ALL": "C"}
            subprocess.run(["/usr/bin/git", "init", "-q", str(central)], env=environment, check=True)
            subprocess.run(["/usr/bin/git", "-C", str(central), "-c", "user.name=Inert Test",
                "-c", "user.email=test@example.invalid", "-c", "core.hooksPath=/dev/null",
                "commit", "-q", "--allow-empty", "-m", "inert HEAD fixture"], env=environment, check=True)
            head = subprocess.check_output(["/usr/bin/git", "-C", str(central), "rev-parse", "HEAD"],
                                            env=environment, text=True).strip()
            step = self.pinned_policy_preflight()["action-policy"]["steps"][2]
            for expected, succeeds in ((head, True), ("0" * 40, False)):
                marker = root / "following-code"
                marker.unlink(missing_ok=True)
                result = subprocess.run(["/usr/bin/bash", "--noprofile", "--norc", "-c",
                    step["run"] + '\nprintf bound > following-code'], cwd=root,
                    env={**environment, "POLICY_CENTRAL_SHA": expected}, check=False)
                self.assertEqual(succeeds, result.returncode == 0)
                self.assertEqual(succeeds, marker.exists())

    def test_composer_scopes_require_closed_workflow_job_and_boolean_fields(self) -> None:
        selected = self.policy["targets"]["workflow"]["composer_trust_scopes"][0]
        self.assertEqual({"workflow": "release-verification.yml", "job": "published-package", "required": True}, selected)
        for field, value in (("workflow", "../release.yml"), ("job", "${{ inputs.job }}"),
                             ("required", "false"), ("extra", "field")):
            candidate = copy.deepcopy(self.policy)
            candidate["targets"]["workflow"]["composer_trust_scopes"][0][field] = value
            with self.subTest(field=field), self.assertRaises(PolicyError):
                validate_policy(candidate)
        for value in (None, {}, [None], [selected, selected]):
            candidate = copy.deepcopy(self.policy)
            candidate["targets"]["workflow"]["composer_trust_scopes"] = value
            with self.subTest(value=value), self.assertRaises(PolicyError):
                validate_policy(candidate)

    def test_a_scoped_migration_cannot_replace_whole_target_composer_enforcement(self) -> None:
        self.policy["targets"]["sdk-php"]["composer_trust_scopes"] = [
            {"workflow": "docs.yml", "job": "build", "required": False}]
        with self.assertRaisesRegex(PolicyError, "cannot be scoped down"):
            validate_policy(self.policy)

    def test_composer_enforcement_flags_require_boolean_values(self) -> None:
        self.policy["targets"]["sdk-php"]["composer_trust_required"] = "false"
        with self.assertRaisesRegex(PolicyError, "invalid Composer enforcement"):
            validate_policy(self.policy)

    def test_approved_immutable_action_with_version_comment_is_accepted(self) -> None:
        commit, version = self.approved_action("actions/checkout")
        evidence = self.scan(workflow(f"- uses: actions/checkout@{commit} # {version}"))
        self.assertEqual(
            [f"actions/checkout@{commit}"],
            evidence[".github/workflows/test.yml"]["external_actions"],
        )

    def test_mutable_and_unknown_action_references_are_rejected(self) -> None:
        for reference in ("main", "a" * 40):
            with self.subTest(reference=reference), self.assertRaises(PolicyError):
                self.scan(workflow(f"- uses: actions/checkout@{reference} # unknown"))

    def test_accepted_shared_apt_guard_pin_is_catalogued_without_mutable_fallback(self) -> None:
        action = "durable-workflow/.github/.github/actions/require-fixed-apt"
        commit = "18783be6bef737cc778e4c7282a8797e39daa61a"
        source = workflow(f"- uses: {action}@{commit} # fixed-apt")
        predecessor = copy.deepcopy(self.policy)
        del predecessor["action_runtime"]["allowed_releases"]["durable-workflow/.github"][commit]
        with self.assertRaisesRegex(PolicyError, "not centrally approved"):
            scan_workflow_sources(predecessor, "github-control-plane", {".github/workflows/test.yml": source})
        self.assertEqual([f"{action}@{commit}"], self.scan(source)[".github/workflows/test.yml"]["external_actions"])
        for ref in ("main", "a" * 40):
            with self.subTest(ref=ref), self.assertRaises(PolicyError):
                self.scan(workflow(f"- uses: {action}@{ref} # fixed-apt"))

    def test_accepted_private_pip_predecessor_has_only_its_literal_catalog_revision(self) -> None:
        action = "durable-workflow/.github/.github/actions/bootstrap-patched-pip"
        commit = "242c2a7fb23459db2e1ada5f84dbee6d61d9b1e5"
        source = workflow(f"- uses: {action}@{commit} # clean-trust")
        predecessor = copy.deepcopy(self.policy)
        del predecessor["action_runtime"]["allowed_releases"]["durable-workflow/.github"][commit]
        with self.assertRaisesRegex(PolicyError, "not centrally approved"):
            scan_workflow_sources(predecessor, "github-control-plane", {".github/workflows/test.yml": source})
        self.assertEqual([f"{action}@{commit}"], self.scan(source)[".github/workflows/test.yml"]["external_actions"])
        for ref in ("main", "a" * 40):
            candidate = workflow(f"- uses: {action}@{ref} # clean-trust")
            with self.subTest(ref=ref), self.assertRaises(PolicyError):
                self.scan(candidate)

    def test_server38_container_verifier_release_is_path_limited(self) -> None:
        commit = "d12a1e247ea28b89912cc87a8c0b596686d8c323"
        action = "durable-workflow/.github/.github/actions/verify-composer-container-trust"
        source = workflow(f"- uses: {action}@{commit} # composer-container-trust")
        predecessor = copy.deepcopy(self.policy)
        del predecessor["action_runtime"]["allowed_releases"]["durable-workflow/.github"][commit]
        with self.assertRaisesRegex(PolicyError, "not centrally approved"):
            scan_workflow_sources(predecessor, "github-control-plane", {"test.yml": source})
        self.assertEqual([f"{action}@{commit}"], self.scan(source)[".github/workflows/test.yml"]["external_actions"])
        for path in ("bootstrap-patched-pip", "setup-php-linux", "verify-composer-trust",
                     "verify-composer-container-trust/other"):
            changed = workflow(f"- uses: durable-workflow/.github/.github/actions/{path}@{commit} # composer-container-trust")
            with self.subTest(path=path), self.assertRaisesRegex(PolicyError, "only its verify-composer-container-trust"):
                self.scan(changed)
            with self.subTest(audit_path=path), self.assertRaisesRegex(PolicyError, "only its verify-composer-container-trust"):
                audit_action_releases(self.policy, None, {"test.yml": changed}, {})

    def test_bound_php_setup_pin_is_approved_only_for_its_exact_action_path(self) -> None:
        commit = "411a14ac07d32073eed6ab4977f2825eba4739a7"
        action = "durable-workflow/.github/.github/actions/setup-php-linux"
        source = workflow(f"- uses: {action}@{commit} # bound-linux-php")
        predecessor = copy.deepcopy(self.policy)
        del predecessor["action_runtime"]["allowed_releases"]["durable-workflow/.github"][commit]
        with self.assertRaisesRegex(PolicyError, "not centrally approved"):
            scan_workflow_sources(predecessor, "github-control-plane", {".github/workflows/test.yml": source})
        self.assertEqual([f"{action}@{commit}"], self.scan(source)[".github/workflows/test.yml"]["external_actions"])
        for path in ("bootstrap-patched-pip", "verify-composer-trust", "setup-php-linux/other"):
            changed = workflow(f"- uses: durable-workflow/.github/.github/actions/{path}@{commit} # bound-linux-php")
            with self.subTest(path=path), self.assertRaisesRegex(PolicyError, "only its setup-php-linux action path"):
                self.scan(changed)
            with self.subTest(audit_path=path), self.assertRaisesRegex(PolicyError, "only its setup-php-linux action path"):
                audit_action_releases(self.policy, None, {"test.yml": changed}, {})
        for retired in ("8ba5caae2546f3d5f41b7616c5722b9b337b8fc0", "ed15002a156725523b23eefb935a243cb1f84952"):
            with self.subTest(retired=retired), self.assertRaisesRegex(PolicyError, "not centrally approved"):
                self.scan(workflow(f"- uses: {action}@{retired} # bound-linux-php"))

    def test_complete_repository_workflow_set_accepts_the_exact_inert_private_pip_profile(self) -> None:
        sources = {str(path.relative_to(ROOT)): path.read_text()
                   for path in (ROOT / ".github/workflows").glob("*.y*ml")}
        target = ".github/workflows/qualify-linux-php-initial.yml"
        sources[target] = (ROOT / "tests/fixtures/qualify-linux-php-private-pip.yml").read_text()
        evidence = scan_workflow_sources(self.policy, "github-control-plane", sources)
        self.assertEqual(set(sources), set(evidence))
        self.assertIn("durable-workflow/.github/.github/actions/bootstrap-patched-pip@242c2a7fb23459db2e1ada5f84dbee6d61d9b1e5",
                      evidence[target]["external_actions"])

    def test_action_pin_requires_its_reviewed_version_comment(self) -> None:
        commit, _version = self.approved_action("actions/checkout")
        with self.assertRaisesRegex(PolicyError, "readable version comment"):
            self.scan(workflow(f"- uses: actions/checkout@{commit}"))

    def test_pull_request_workflows_cannot_request_write_access(self) -> None:
        with self.assertRaisesRegex(PolicyError, "top-level write permissions"):
            self.scan(workflow("- run: true", permissions="contents: write"))

    def test_pull_request_target_is_rejected(self) -> None:
        with self.assertRaisesRegex(PolicyError, "pull_request_target"):
            self.scan(workflow("- run: true", trigger="pull_request_target"))

    def test_pull_request_jobs_cannot_use_environments_or_secrets(self) -> None:
        source = workflow("- run: echo ${{ secrets.TOKEN }}")
        source = source.replace("    runs-on: ubuntu-latest", "    runs-on: ubuntu-latest\n    environment: production")
        with self.assertRaises(PolicyError):
            self.scan(source)

    def sonar_workflow(self) -> str:
        checkout, checkout_version = self.approved_action("actions/checkout")
        scanner, scanner_version = self.approved_action("sonarsource/sonarqube-scan-action")
        source = workflow(
            f"""- uses: actions/checkout@{checkout} # {checkout_version}
  with:
    fetch-depth: 0
    persist-credentials: false""",
            f"""- uses: SonarSource/sonarqube-scan-action@{scanner} # {scanner_version}
  env:
    SONAR_TOKEN: ${{{{ secrets.SONAR_TOKEN }}}}
  with:
    args: -Dsonar.qualitygate.wait=true -Dsonar.qualitygate.timeout=300""",
        )
        return source.replace(
            "    runs-on: ubuntu-latest\n    timeout-minutes: 5",
            "    if: github.event_name != 'pull_request' || "
            "github.event.pull_request.head.repo.full_name == github.repository\n"
            "    runs-on: ubuntu-latest\n    timeout-minutes: 15",
        )

    def test_isolated_same_repository_sonar_analysis_is_accepted(self) -> None:
        self.scan(self.sonar_workflow())

    def test_merge_queue_sonar_accepts_only_the_trusted_static_scanner(self) -> None:
        source = (ROOT / "tests/fixtures/merge-queue-sonar.yml").read_text(encoding="utf-8")
        policy = copy.deepcopy(self.policy)
        policy["workflow_trust"]["privileged_tag_dispatch_workflows"] = {}
        scan_workflow_sources(policy, "server", {".github/workflows/queue-sonar.yml": source})
        with self.assertRaises(PolicyError):
            scan_workflow_sources(policy, "sdk-php", {".github/workflows/queue-sonar.yml": source})
        with self.assertRaises(PolicyError):
            scan_workflow_sources(policy, "server", {".github/workflows/another-scanner.yml": source})

    def test_merge_queue_sonar_refuses_candidate_execution_and_privilege_expansion(self) -> None:
        source = (ROOT / "tests/fixtures/merge-queue-sonar.yml").read_text(encoding="utf-8")
        mutations = [
            source.replace("workflows: [PHPUnit Feature]", "workflows: [Other workflow]"),
            source.replace("types: [completed]", "types: [requested]"),
            source.replace("  workflow_run:", "  pull_request:\n  workflow_run:"),
            source.replace("event == 'merge_group'", "event == 'pull_request'"),
            source.replace("conclusion == 'success'", "conclusion != 'cancelled'"),
            source.replace("github.workflow_sha", "github.event.workflow_run.head_sha"),
            source.replace("steps.candidate.outputs.sha", "github.event.workflow_run.head_sha"),
            source.replace(".sonar-control/scripts/ci/merge-queue-sonar.mjs prepare", "./.sonar-candidate/install.sh"),
            source.replace(".sonar-control/scripts/ci/merge-queue-sonar.mjs validate", "echo trusted"),
            source.replace("persist-credentials: false", "persist-credentials: true"),
            source.replace("submodules: false", "submodules: true"),
            source.replace("lfs: false", "lfs: true"),
            source.replace("runs-on: ubuntu-latest", "runs-on: self-hosted"),
            source.replace("timeout-minutes: 20", "timeout-minutes: 120"),
            source.replace("SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}", "SONAR_TOKEN: ${{ secrets.PRODUCTION_TOKEN }}"),
            source.replace("steps:\n", "env:\n      TOKEN: ${{ secrets.SONAR_TOKEN }}\n    steps:\n"),
            source.replace("name: Check out trusted scanner controls", "name: ${{ secrets.SONAR_TOKEN }}"),
            source.replace("queue-sonar-work", ".sonar-candidate/.scannerwork"),
            source.replace("projectBaseDir: .sonar-candidate", "projectBaseDir: ."),
            source.replace("sonar.rust.clippy.enabled=false", "sonar.rust.clippy.enabled=true"),
            source.replace("qualitygate.wait=false", "qualitygate.wait=false -Dsonar.host.url=https://example.invalid"),
            source + "      - run: ./.sonar-candidate/after-scan.sh\n",
            source + "      - uses: ./candidate-action # local\n",
        ]
        for changed in mutations:
            self.assertNotEqual(source, changed)
            with self.subTest(source=changed), self.assertRaises(PolicyError):
                scan_workflow_sources(self.policy, "server", {".github/workflows/queue-sonar.yml": changed})

    def test_sonar_coverage_preparation_does_not_receive_analysis_credential(self) -> None:
        source = self.sonar_workflow().replace(
            "      - uses: SonarSource/",
            "      - run: python -m unittest\n      - uses: SonarSource/",
        )
        self.scan(source)
        leaked = source.replace("python -m unittest", "echo ${{ secrets.SONAR_TOKEN }}")
        with self.assertRaises(PolicyError):
            self.scan(leaked)

    def test_sonar_credential_exception_rejects_forks_and_unsafe_jobs(self) -> None:
        source = self.sonar_workflow()
        mutations = [
            source.replace("github.event.pull_request.head.repo.full_name == github.repository", "true"),
            source + "      - run: ./untrusted-script\n",
            source.replace("persist-credentials: false", "persist-credentials: true"),
            source.replace("fetch-depth: 0", "ref: ${{ github.event.pull_request.head.sha }}"),
            source.replace("secrets.SONAR_TOKEN", "secrets.PRODUCTION_TOKEN"),
            source.replace("qualitygate.timeout=300", "qualitygate.timeout=300 -Dsonar.host.url=https://example.com"),
            source.replace("    runs-on:", "    env:\n      TOKEN: ${{ secrets.TOKEN }}\n    runs-on:"),
            source.replace("    runs-on: ubuntu-latest", "    runs-on: self-hosted"),
            source.replace("timeout-minutes: 15", "timeout-minutes: 30"),
            source.replace("      - uses: actions/checkout@", "      - uses: actions/checkout/subdirectory@"),
            source.replace("      - uses: SonarSource/", "      - id: extra-state\n        uses: SonarSource/"),
            source.replace("      - uses: actions/checkout@", "      - id: extra-state\n        uses: actions/checkout@"),
            source.replace("    steps:\n", "    strategy: {}\n    steps:\n"),
            source.replace("    runs-on:", "    name: ${{ secrets.DEPLOY_TOKEN }}\n    runs-on:"),
            source.replace("      - uses: SonarSource/", "      - name: ${{ secrets.DEPLOY_TOKEN }}\n        uses: SonarSource/"),
            source.replace("      - uses: actions/checkout@", "      - name: ${{ secrets.DEPLOY_TOKEN }}\n        uses: actions/checkout@"),
            source.replace("args: -Dsonar.qualitygate.wait=true -Dsonar.qualitygate.timeout=300", "args: []"),
        ]
        for changed in mutations:
            with self.subTest(source=changed), self.assertRaises(PolicyError):
                self.scan(changed)

    def coverage_sonar_workflow(self) -> str:
        upload, upload_version = self.approved_action("actions/upload-artifact")
        download, download_version = self.approved_action("actions/download-artifact")
        source = self.sonar_workflow().replace(
            "  pull_request:\n",
            "  pull_request:\n  workflow_dispatch:\n",
        ).replace(
            "github.event_name != 'pull_request' || "
            "github.event.pull_request.head.repo.full_name == github.repository",
            "github.event_name != 'pull_request' && github.ref == 'refs/heads/main'",
        ).replace(
            "    runs-on: ubuntu-latest",
            "    needs: [coverage]\n    runs-on: ubuntu-latest",
        ).replace(
            "      - uses: SonarSource/",
            f"""      - uses: actions/download-artifact@{download} # {download_version}
        with:
          artifact-ids: ${{{{ needs.coverage.outputs.sonar_artifact_id }}}}
          path: .sonar-coverage
          digest-mismatch: error
      - uses: SonarSource/""",
        )
        return source.replace("jobs:\n", f"""jobs:
  coverage:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    outputs:
      sonar_artifact_id: ${{{{ steps.sonar_coverage.outputs.artifact-id }}}}
    steps:
      - uses: actions/upload-artifact@{upload} # {upload_version}
        id: sonar_coverage
        with:
          name: sonar-coverage
          path: |
            coverage.xml
            build/feature-coverage/mysql-shard-0-coverage.xml
          if-no-files-found: error
          retention-days: 1
""", 1)

    def test_main_sonar_import_accepts_the_same_run_report_producer(self) -> None:
        evidence = self.scan(self.coverage_sonar_workflow())
        self.assertEqual(["test"], evidence[".github/workflows/test.yml"]["privileged_jobs"])

    def test_standalone_scan_can_leave_missing_coverage_unmeasured(self) -> None:
        source = self.sonar_workflow().replace(
            "-Dsonar.qualitygate.timeout=300",
            "-Dsonar.qualitygate.timeout=300 -Dsonar.coverage.exclusions=**/*",
        )
        self.scan(source)
        measured = self.coverage_sonar_workflow().replace(
            "-Dsonar.qualitygate.timeout=300",
            "-Dsonar.qualitygate.timeout=300 -Dsonar.coverage.exclusions=**/*",
        )
        with self.assertRaises(PolicyError):
            self.scan(measured)

    def test_sonar_report_import_requires_bound_artifacts_and_isolated_data(self) -> None:
        source = self.coverage_sonar_workflow()
        mutations = [
            source.replace("needs: [coverage]", "needs: [other]"),
            source.replace("steps.sonar_coverage.outputs.artifact-id", "steps.other.outputs.artifact-id"),
            source.replace("id: sonar_coverage", "id: other"),
            source.replace("path: .sonar-coverage", "path: ."),
            source.replace("path: .sonar-coverage", "path: ../outside"),
            source.replace("digest-mismatch: error", "digest-mismatch: warn"),
            source.replace("retention-days: 1", "retention-days: 90"),
            source.replace("if-no-files-found: error", "if-no-files-found: ignore"),
            source.replace("name: sonar-coverage", "name: unrelated"),
            source.replace("build/feature-coverage/mysql-shard-0-coverage.xml", "build/../other-coverage.xml"),
            source.replace("build/feature-coverage/mysql-shard-0-coverage.xml", "build/script.php"),
            source.replace("          path: .sonar-coverage", "          run-id: 123\n          path: .sonar-coverage"),
            source.replace("      - uses: SonarSource/", "      - run: ./report-script\n      - uses: SonarSource/"),
        ]
        for changed in mutations:
            with self.subTest(source=changed), self.assertRaises(PolicyError):
                self.scan(changed)

    def test_sonar_report_import_preserves_the_main_branch_credential_boundary(self) -> None:
        source = self.coverage_sonar_workflow()
        for changed in (
            source.replace("refs/heads/main", "refs/heads/other"),
            source.replace("github.event_name != 'pull_request'", "true"),
            source.replace(" && github.ref == 'refs/heads/main'", ""),
            source.replace("secrets.SONAR_TOKEN", "secrets.OTHER_TOKEN"),
        ):
            with self.subTest(source=changed), self.assertRaises(PolicyError):
                self.scan(changed)

    def test_pull_request_cache_rejects_broad_paths(self) -> None:
        commit, version = self.approved_action("actions/cache")
        source = workflow(
            f"""- uses: actions/cache@{commit} # {version}
  with:
    path: .
    key: test-${{{{ github.event_name }}}}"""
        )
        with self.assertRaisesRegex(PolicyError, "unsafe cache path"):
            self.scan(source)

    TRUSTED_SAVE = "github.event_name == 'push' && github.ref == 'refs/heads/main'"
    TRUSTED_READ = "github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository"

    def trusted_main_cache(self) -> str:
        commit, version = self.approved_action("actions/cache")
        save_if = f"success() && {self.TRUSTED_SAVE} && steps.cache.outputs.cache-hit != 'true'"
        return workflow(
            f"""- id: cache
  if: ${{{{ {self.TRUSTED_READ} }}}}
  uses: actions/cache/restore@{commit} # {version}
  with:
    path: build-cache
    key: build-v1-${{{{ hashFiles('Cargo.lock') }}}}
- run: echo build
- if: ${{{{ {save_if} }}}}
  uses: actions/cache/save@{commit} # {version}
  with:
    path: build-cache
    key: ${{{{ steps.cache.outputs.cache-primary-key }}}}"""
        )

    def test_pull_request_cache_shares_an_exact_key_written_only_by_protected_pushes(self) -> None:
        source = self.trusted_main_cache()
        self.scan(source)
        # The same condition with its terms reordered and parenthesized.
        reordered = "github.ref == 'refs/heads/main' && (github.event_name == 'push')"
        self.scan(source.replace(self.TRUSTED_SAVE, reordered))

    def test_cache_restores_require_a_non_fork_guard_even_with_partitioned_keys(self) -> None:
        source = self.trusted_main_cache()
        guard = f"        if: ${{{{ {self.TRUSTED_READ} }}}}\n"
        for path in ("target/debug/deps", "vendor", "node_modules", "~/.cargo/registry/cache"):
            candidate = source.replace("path: build-cache", f"path: {path}")
            for partitioned in (False, True):
                changed = candidate.replace(guard, "")
                if partitioned:
                    changed = changed.replace("key: build-v1-", "key: build-${{ github.event_name }}-")
                with self.subTest(path=path, partitioned=partitioned), self.assertRaisesRegex(
                    PolicyError, "cache restore.*external fork"
                ):
                    self.scan(changed)

    def test_cache_restore_guard_rejects_fork_and_main_ref_bypasses(self) -> None:
        source = self.trusted_main_cache()
        same_repository = "github.event.pull_request.head.repo.full_name == github.repository"
        for condition in (
            "true",
            "github.ref == 'refs/heads/main'",
            "github.event_name == 'pull_request'",
            "github.event_name == 'PULL_REQUEST'",
            "github.event_name != 'workflow_dispatch'",
            f"{same_repository} || github.event_name == 'pull_request'",
            f"{same_repository} || github.ref == 'refs/heads/main'",
            f"{same_repository} || success()",
            f"!({same_repository})",
            "!github.event_name != 'push'",
            "!github.event.pull_request.head.repo.full_name != github.repository",
            "github.event_name == 'workflow_dispatch' || github.ref == 'refs/heads/main'",
            "github.event_name != 'pull_requeﬆ'",
            "!(github.event_name == 'pull_requeﬆ')",
            "falſe",
        ):
            candidate = source.replace(self.TRUSTED_READ, condition)
            with self.subTest(condition=condition), self.assertRaisesRegex(
                PolicyError, "cache restore.*external fork"
            ):
                self.scan(candidate)

    def test_cache_restore_guards_accept_protected_and_same_repository_contexts(self) -> None:
        source = self.trusted_main_cache()
        same_repository = "github.event.pull_request.head.repo.full_name == github.repository"
        for condition in (
            same_repository,
            "github.repository == github.event.pull_request.head.repo.full_name",
            "!(github.event.pull_request.head.repo.full_name != github.repository)",
            f"success() && ({same_repository})",
            f"({self.TRUSTED_SAVE}) || (github.event_name == 'pull_request' && {same_repository})",
            f"always() && ({self.TRUSTED_READ})",
            self.TRUSTED_SAVE,
            "false",
        ):
            with self.subTest(condition=condition):
                self.scan(source.replace(self.TRUSTED_READ, condition))

    def test_cache_restore_can_inherit_the_job_non_fork_guard(self) -> None:
        source = self.trusted_main_cache()
        source = source.replace(f"        if: ${{{{ {self.TRUSTED_READ} }}}}\n", "")
        source = source.replace("    runs-on:", f"    if: ${{{{ {self.TRUSTED_READ} }}}}\n    runs-on:")
        self.scan(source)
        candidate = source.replace(self.TRUSTED_READ, "github.ref == 'refs/heads/main'")
        with self.assertRaisesRegex(PolicyError, "cache restore.*external fork"):
            self.scan(candidate)

    def test_pull_request_cache_without_partition_refuses_untrusted_writes_and_prefixes(self) -> None:
        source = self.trusted_main_cache()
        key = "{{ hashFiles('Cargo.lock') }}"
        either = "github.event_name == 'push' || github.ref == 'refs/heads/main'"
        mutations = [
            # A broad restore prefix could substitute stale output.
            source.replace(key, key + "\n          restore-keys: build-v1-", 1),
            # A save any event, or any branch, can run.
            source.replace(f"success() && {self.TRUSTED_SAVE} && ", ""),
            source.replace("github.event_name == 'push' && ", ""),
            source.replace(" && github.ref == 'refs/heads/main'", ""),
            source.replace(self.TRUSTED_SAVE, either),
            source.replace("refs/heads/main", "refs/heads/other"),
            source.replace("github.event_name == 'push'", "github.event_name != 'pull_request'"),
            # The combined action restores and saves on every event.
            source.replace("actions/cache/restore@", "actions/cache@"),
        ]
        for changed in mutations:
            with (
                self.subTest(source=changed),
                self.assertRaisesRegex(PolicyError, "must partition trusted and untrusted events"),
            ):
                self.scan(changed)

    def test_policy_rejects_a_retired_javascript_runtime(self) -> None:
        candidate = copy.deepcopy(self.policy)
        candidate["action_runtime"]["supported_javascript_runtimes"] = ["node20"]
        with self.assertRaisesRegex(PolicyError, "supported JavaScript action runtimes"):
            validate_policy(candidate)

    def test_cli_validate_writes_no_repository_state(self) -> None:
        commit, version = self.approved_action("actions/checkout")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "ci.yml").write_text(
                workflow(f"- uses: actions/checkout@{commit} # {version}"),
                encoding="utf-8",
            )
            before = sorted(path.name for path in directory.iterdir())
            validate_local_action_references(self.policy, directory, "github-control-plane")
            self.assertEqual(before, sorted(path.name for path in directory.iterdir()))


TAG_GATE = "github.ref == format('refs/tags/{0}', inputs.tag)"
CHECKOUT_STEP = """      - name: Check out trusted release tooling
        uses: actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803  # v6
        with:
          ref: ${{ github.sha }}
          persist-credentials: false
"""
VERIFIER_STEP = """      - name: Require a dispatch from the release tag, at its commit, on main
        env:
          GH_TOKEN: ${{ github.token }}
          RELEASE_TAG: ${{ inputs.tag }}
          RELEASE_COMMIT: ${{ inputs.release_commit }}
          DISPATCH_REF: ${{ github.ref }}
          DISPATCH_SHA: ${{ github.sha }}
        run: scripts/ci/verify-native-release-dispatch.sh
"""
PLAN_STEPS = CHECKOUT_STEP + VERIFIER_STEP + """      - name: Choose registries
        run: echo dockerhub=true >> "$GITHUB_OUTPUT"
"""


def tag_dispatch_workflow(
    *,
    plan_extra: str = "",
    gate: str = TAG_GATE,
    trigger_extra: str = "",
    tag_required: str = "true",
    environment: str = "dockerhub-native",
    needs: str = "plan",
    extra_job: str = "",
    plan_steps: str | None = None,
    plan_job_extra: str = "",
    workflow_extra: str = "",
    job_extra: str = "",
) -> str:
    def publishing_job(name: str, condition: str) -> str:
        return f"""  {name}:
    needs: {needs}
    if: {condition}
    runs-on: ubuntu-latest
    timeout-minutes: 5
    environment: {environment}
{job_extra}    permissions:
      contents: read
      packages: write
    steps:
      - run: echo {name}
"""

    return f"""name: native release
on:
  workflow_dispatch:
    inputs:
      tag:
        required: {tag_required}
      release_commit:
        required: true
{trigger_extra}permissions:
  contents: read
{workflow_extra}jobs:
  plan:
{plan_extra}    runs-on: ubuntu-latest
    timeout-minutes: 5
{plan_job_extra}    permissions:
      contents: read
    steps:
{PLAN_STEPS if plan_steps is None else plan_steps}\
{"".join(publishing_job(name, gate) for name in ("build-amd64", "build-arm64", "publish"))}\
{publishing_job("aliases", gate + " && needs.plan.outputs.dockerhub == 'true'")}{extra_job}"""


def native_promotion_transition_policy() -> dict[str, object]:
    """Retain the legacy topology only in explicit transition controls."""
    policy = policy_fixture()
    bindings = policy["workflow_trust"]["privileged_tag_dispatch_workflows"]
    bindings["server/native-release.yml"]["jobs"].insert(0, "aliases")
    bindings["server/native-release.yml"]["optional_jobs"] = ["aliases"]
    bindings["server/native-alias-promotion.yml"]["optional"] = True
    return policy


class TagDispatchPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = native_promotion_transition_policy()

    def scan(self, source: str, policy: dict[str, object] | None = None) -> dict[str, dict[str, object]]:
        return scan_workflow_sources(
            policy or self.policy, "server", {".github/workflows/native-release.yml": source}
        )

    def assert_refused(self, source: str, message: str) -> None:
        with self.assertRaisesRegex(PolicyError, message):
            self.scan(source)

    def test_reviewed_tag_ref_release_workflow_is_admitted(self) -> None:
        evidence = self.scan(tag_dispatch_workflow())
        self.assertEqual(
            evidence[".github/workflows/native-release.yml"]["privileged_jobs"],
            ["aliases", "build-amd64", "build-arm64", "publish"],
        )

    def test_the_same_workflow_is_refused_without_its_binding(self) -> None:
        policy = copy.deepcopy(self.policy)
        policy["workflow_trust"]["privileged_tag_dispatch_workflows"] = {}
        with self.assertRaisesRegex(PolicyError, "can run outside refs/heads/main"):
            self.scan(tag_dispatch_workflow(), policy)

    def test_binding_does_not_transfer_to_another_workflow_or_target(self) -> None:
        with self.assertRaisesRegex(PolicyError, "can run outside refs/heads/main"):
            scan_workflow_sources(
                self.policy,
                "server",
                {
                    ".github/workflows/native-release.yml": tag_dispatch_workflow(),
                    ".github/workflows/other-release.yml": tag_dispatch_workflow(),
                },
            )
        with self.assertRaisesRegex(PolicyError, "can run outside refs/heads/main"):
            scan_workflow_sources(
                self.policy, "sdk-php", {".github/workflows/native-release.yml": tag_dispatch_workflow()}
            )

    def test_conditioned_plan_job_is_refused(self) -> None:
        self.assert_refused(
            tag_dispatch_workflow(plan_extra=f"    if: {TAG_GATE}\n"), "plan job must run unconditionally"
        )

    def test_privileged_plan_job_is_refused(self) -> None:
        self.assert_refused(
            tag_dispatch_workflow(plan_extra="    environment: dockerhub-native\n"),
            "job 'plan' can run outside refs/heads/main|plan job must not be privileged",
        )

    def test_loosened_or_missing_tag_ref_predicates_are_refused(self) -> None:
        for gate in (
            f"{TAG_GATE} || true",
            f"!({TAG_GATE})",
            "github.ref != 'refs/heads/main'",
            "startsWith(github.ref, 'refs/tags/')",
            "github.ref == format('refs/heads/{0}', inputs.tag)",
        ):
            with self.subTest(gate=gate):
                self.assert_refused(tag_dispatch_workflow(gate=gate), "can run outside refs/heads/main")

    def test_wrong_environment_or_missing_plan_dependency_is_refused(self) -> None:
        self.assert_refused(tag_dispatch_workflow(environment="production"), "can run outside refs/heads/main")
        self.assert_refused(tag_dispatch_workflow(needs="[]"), "can run outside refs/heads/main")

    def test_unlisted_privileged_job_is_refused_even_with_the_tag_predicate(self) -> None:
        extra = f"""  sign:
    needs: plan
    if: {TAG_GATE}
    runs-on: ubuntu-latest
    timeout-minutes: 5
    environment: dockerhub-native
    permissions:
      contents: write
    steps:
      - run: echo sign
"""
        self.assert_refused(tag_dispatch_workflow(extra_job=extra), "job 'sign' can run outside refs/heads/main")

    def test_other_triggers_and_optional_tag_input_are_refused(self) -> None:
        self.assert_refused(
            tag_dispatch_workflow(trigger_extra="  push:\n    tags: ['native-*']\n"),
            "triggered only by workflow_dispatch",
        )
        self.assert_refused(tag_dispatch_workflow(tag_required="false"), "must be a required string")

    def test_missing_bound_workflow_or_job_is_refused(self) -> None:
        with self.assertRaisesRegex(PolicyError, "missing policy-bound tag dispatch workflows"):
            scan_workflow_sources(self.policy, "server", {".github/workflows/ci.yml": workflow("- run: echo ok")})
        policy = copy.deepcopy(self.policy)
        binding = policy["workflow_trust"]["privileged_tag_dispatch_workflows"]["server/native-release.yml"]
        binding["jobs"] = sorted([*binding["jobs"], "verify"])
        with self.assertRaisesRegex(PolicyError, r"missing policy-bound tag dispatch jobs \['verify'\]"):
            self.scan(tag_dispatch_workflow(), policy)

    def test_status_functions_cannot_run_publishing_after_a_failed_plan(self) -> None:
        for gate in (
            f"always() && {TAG_GATE}",
            f"{TAG_GATE} && failure()",
            f"cancelled () && {TAG_GATE}",
            f"ALWAYS() && {TAG_GATE}",
            f"success() == false && {TAG_GATE}",
            f"${{{{ !success() && {TAG_GATE} }}}}",
            f"Success ( ) == false && {TAG_GATE}",
            f"{TAG_GATE} && success()",
        ):
            with self.subTest(gate=gate):
                self.assert_refused(tag_dispatch_workflow(gate=gate), "can run outside refs/heads/main")

    def test_plan_must_run_the_exact_verifier_after_the_checkout(self) -> None:
        echo = """      - name: Require a dispatch from the release tag, at its commit, on main
        run: echo skipped
"""
        tampered = VERIFIER_STEP.replace("RELEASE_TAG: ${{ inputs.tag }}", "RELEASE_TAG: native-9.9.9")
        cases = {
            "removed": CHECKOUT_STEP,
            "replaced": CHECKOUT_STEP + echo,
            "changed env": CHECKOUT_STEP + tampered,
            "conditional": CHECKOUT_STEP + VERIFIER_STEP.replace("        run:", "        if: false\n        run:"),
            "continue on error": CHECKOUT_STEP
            + VERIFIER_STEP.replace("        run:", "        continue-on-error: true\n        run:"),
            "custom shell": CHECKOUT_STEP
            + VERIFIER_STEP.replace("        run:", "        shell: true {0}\n        run:"),
            "step before verifier": CHECKOUT_STEP
            + "      - run: echo 'exit 0' > scripts/ci/verify-native-release-dispatch.sh\n"
            + VERIFIER_STEP,
            "no checkout": VERIFIER_STEP,
        }
        for case, steps in cases.items():
            with self.subTest(case=case):
                self.assert_refused(tag_dispatch_workflow(plan_steps=steps), "plan job must")

    def test_plan_and_publishing_jobs_cannot_continue_on_error_or_change_run_defaults(self) -> None:
        self.assert_refused(
            tag_dispatch_workflow(plan_job_extra="    continue-on-error: true\n"), "plan job must not continue on error"
        )
        self.assert_refused(
            tag_dispatch_workflow(job_extra="    continue-on-error: true\n"), "must not continue on error"
        )
        self.assert_refused(
            tag_dispatch_workflow(workflow_extra="defaults:\n  run:\n    shell: true {0}\n"),
            "must not override run defaults",
        )
        self.assert_refused(
            tag_dispatch_workflow(plan_job_extra="    defaults:\n      run:\n        working-directory: tmp\n"),
            "must not override run defaults",
        )

    def test_policy_refuses_a_loosened_or_incomplete_binding(self) -> None:
        cases = {
            "tag_ref_condition": "startsWith(github.ref, 'refs/tags/')",
            "jobs": ["publish", "aliases"],
            "plan_job": "publish",
            "environment": "",
            "plan_verifier": {"run": "scripts/ci/verify-native-release-dispatch.sh"},
        }
        for field, value in cases.items():
            with self.subTest(field=field):
                policy = copy.deepcopy(self.policy)
                bindings = policy["workflow_trust"]["privileged_tag_dispatch_workflows"]
                bindings["server/native-release.yml"][field] = value
                with self.assertRaises(PolicyError):
                    validate_policy(policy)
        policy = copy.deepcopy(self.policy)
        del policy["workflow_trust"]["privileged_tag_dispatch_workflows"]["server/native-release.yml"]["plan_job"]
        with self.assertRaisesRegex(PolicyError, "complete tag dispatch trust binding"):
            validate_policy(policy)



class NativePromotionTransitionTest(unittest.TestCase):
    """Presence exceptions cannot relax any present workflow's trust binding."""

    def setUp(self) -> None:
        self.policy = native_promotion_transition_policy()
        self.path = ".github/workflows/native-alias-promotion.yml"
        binding = self.policy["workflow_trust"]["privileged_tag_dispatch_workflows"]["server/native-alias-promotion.yml"]
        env = "\n".join(f"          {name}: {value}" for name, value in binding["plan_verifier"]["env"].items())
        self.promotion = f"""name: Native alias promotion
on:
  workflow_dispatch:
    inputs:
      tag:
        required: true
        type: string
      evidence:
        required: true
        type: string
permissions: {{}}
jobs:
  plan:
    runs-on: ubuntu-latest
    timeout-minutes: 5
    permissions:
      contents: read
    steps:
{CHECKOUT_STEP}      - name: Validate dispatch
        env:
{env}
        run: python3 scripts/ci/native_alias_promote.py plan
  promote:
    needs: plan
    if: {TAG_GATE}
    runs-on: ubuntu-latest
    timeout-minutes: 5
    environment: dockerhub-native
    permissions:
      packages: write
    steps:
      - run: echo synthetic-promotion
"""

    def sources(self, promotion: str | None, legacy_aliases: bool = True) -> dict[str, str]:
        release = tag_dispatch_workflow()
        if not legacy_aliases:
            release = release.split("  aliases:\n", 1)[0]
        sources = {".github/workflows/native-release.yml": release}
        if promotion is not None:
            sources[self.path] = promotion
        return sources

    def test_accepted_legacy_and_successor_topologies_share_one_policy(self) -> None:
        for promotion, legacy in ((None, True), (self.promotion, True), (self.promotion, False)):
            with self.subTest(promotion=promotion is not None, legacy=legacy):
                evidence = scan_workflow_sources(self.policy, "server", self.sources(promotion, legacy))
                if promotion is not None:
                    self.assertEqual(evidence[self.path]["privileged_jobs"], ["promote"])

    def test_optional_workflow_still_requires_exact_plan_ref_environment_and_jobs_when_present(self) -> None:
        for before, after in (
            (f"if: {TAG_GATE}", "if: github.ref == 'refs/heads/main' || true"),
            ("needs: plan", "needs: []"),
            ("environment: dockerhub-native", "environment: other"),
            ("native_alias_promote.py plan", "native_alias_promote.py promote"),
            ("  promote:\n", "  unregistered:\n"),
            ("  plan:\n", "  plan:\n    if: false\n"),
        ):
            source = self.promotion.replace(before, after)
            with self.subTest(after=after), self.assertRaises(PolicyError):
                scan_workflow_sources(self.policy, "server", self.sources(source, False))

    def test_optional_legacy_alias_job_is_fully_checked_if_present(self) -> None:
        sources = self.sources(None)
        path = ".github/workflows/native-release.yml"
        sources[path] = sources[path].replace("  aliases:\n", "  aliases:\n    continue-on-error: true\n")
        with self.assertRaisesRegex(PolicyError, "must not continue on error"):
            scan_workflow_sources(self.policy, "server", sources)

    def test_presence_exception_cannot_name_unregistered_jobs_or_nonboolean_flags(self) -> None:
        for field, value in (("optional", "true"), ("optional", 1), ("optional_jobs", ["unknown"]),
                             ("optional_jobs", ["aliases", "aliases"]), ("optional_jobs", "aliases")):
            policy = copy.deepcopy(self.policy)
            policy["workflow_trust"]["privileged_tag_dispatch_workflows"]["server/native-release.yml"][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(PolicyError):
                validate_policy(policy)

    def test_tightened_post_transition_policy_requires_promotion_and_refuses_legacy_aliases(self) -> None:
        policy = policy_fixture()
        scan_workflow_sources(policy, "server", self.sources(self.promotion, False))
        for promotion, legacy in ((None, False), (self.promotion, True)):
            with self.subTest(promotion=promotion is not None, legacy=legacy), self.assertRaises(PolicyError):
                scan_workflow_sources(policy, "server", self.sources(promotion, legacy))


if __name__ == "__main__":
    unittest.main()
