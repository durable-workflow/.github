from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from scripts.qualification_policy import (
    PolicyError,
    LOCKED_POLICY_BOOTSTRAP_REVISION,
    LOCKED_POLICY_INSTALL_COMMAND,
    _workflow_action_references,
    _references_secret_context,
    _string_values,
    _verify_action_policy_preflight,
    scan_workflow_sources,
    validate_local_action_references,
    validate_policy,
    verify_workflow_source,
)

ROOT = Path(__file__).resolve().parents[1]


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

    def preflight_jobs(self, target: str = "ai") -> dict:
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
                     f"--policy .central-action-policy/qualification/policy.json --target {target} "
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
        return jobs

    def test_policy_preflight_accepts_binary_only_without_relaxing_dependency_command(self) -> None:
        jobs = self.preflight_jobs()
        for command in (
            "python -m pip install PyYAML==6.0.2",
            "python -m pip install --only-binary :all: PyYAML==6.0.2",
            "python -I -m pip install PyYAML==6.0.2",
            "python -I -m pip install --only-binary :all: PyYAML==6.0.2",
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

    def test_server_requires_the_isolated_hash_locked_policy_install(self) -> None:
        jobs = self.preflight_jobs("server")
        steps = jobs["action-policy"]["steps"]
        steps.insert(3, {"uses": "durable-workflow/.github/.github/actions/bootstrap-patched-pip@" + LOCKED_POLICY_BOOTSTRAP_REVISION})
        steps[4]["run"] = LOCKED_POLICY_INSTALL_COMMAND
        revisions = {LOCKED_POLICY_BOOTSTRAP_REVISION}
        _verify_action_policy_preflight("server", "fixture", jobs, "gate", revisions, True)
        for flag in ("-I ", "--isolated ", "--require-hashes ", "--only-binary=:all: ", "--no-deps "):
            changed = copy.deepcopy(jobs)
            changed["action-policy"]["steps"][4]["run"] = LOCKED_POLICY_INSTALL_COMMAND.replace(flag, "")
            with self.subTest(removed=flag), self.assertRaisesRegex(PolicyError, "reviewed policy dependency"):
                _verify_action_policy_preflight("server", "fixture", changed, "gate", revisions, True)
        for command in (
            LOCKED_POLICY_INSTALL_COMMAND.replace("qualification/requirements.lock", "requirements.lock"),
            LOCKED_POLICY_INSTALL_COMMAND.replace(".central-action-policy/", ""),
            LOCKED_POLICY_INSTALL_COMMAND + " --extra-index-url https://example.com",
            LOCKED_POLICY_INSTALL_COMMAND + " --trusted-host example.com",
            "python -m pip install PyYAML==6.0.2",
        ):
            changed = copy.deepcopy(jobs)
            changed["action-policy"]["steps"][4]["run"] = command
            with self.subTest(command=command), self.assertRaisesRegex(PolicyError, "reviewed policy dependency"):
                _verify_action_policy_preflight("server", "fixture", changed, "gate", revisions, True)
        changed = copy.deepcopy(jobs)
        changed["action-policy"]["steps"].pop(3)
        with self.assertRaisesRegex(PolicyError, "locked-policy pip bootstrap"):
            _verify_action_policy_preflight("server", "fixture", changed, "gate", revisions, True)
        changed = copy.deepcopy(jobs)
        changed["action-policy"]["steps"][3]["uses"] = steps[3]["uses"].replace(LOCKED_POLICY_BOOTSTRAP_REVISION, "75587fc33ff40c34f32ef777293dad56bb6f48c7")
        with self.assertRaisesRegex(PolicyError, "locked-policy pip bootstrap"):
            _verify_action_policy_preflight("server", "fixture", changed, "gate", revisions | {"75587fc33ff40c34f32ef777293dad56bb6f48c7"}, True)
        self.assertTrue(self.policy["targets"]["server"]["workflows"][0]["locked_policy_dependency_required"])

    def locked_preflight_jobs(self) -> dict:
        jobs = self.preflight_jobs("server")
        jobs["action-policy"]["steps"].insert(3, {
            "uses": "durable-workflow/.github/.github/actions/bootstrap-patched-pip@" + LOCKED_POLICY_BOOTSTRAP_REVISION,
        })
        jobs["action-policy"]["steps"][4]["run"] = LOCKED_POLICY_INSTALL_COMMAND
        jobs["gate"]["name"] = "PHPUnit feature suite"
        return jobs

    def verify_server_preflight(self, jobs: dict, defaults: dict | None = None) -> None:
        document = {"jobs": jobs}
        if defaults is not None:
            document["defaults"] = defaults
        source = "on:\n  push:\n    branches: [main]\n  pull_request:\n  workflow_dispatch:\n"
        source += yaml.safe_dump(document, sort_keys=False)
        verify_workflow_source(
            "server", "main", self.policy["targets"]["server"]["workflows"][0],
            source, {LOCKED_POLICY_BOOTSTRAP_REVISION},
        )

    def test_preflight_refuses_redirected_install_and_validator_directories(self) -> None:
        for directory in ("alternate", "../other", "${{ github.workspace }}/alternate", "${{ inputs.directory }}", "$GITHUB_WORKSPACE", None):
            for scope in ("workflow", "job", "install", "validate"):
                jobs = self.locked_preflight_jobs()
                defaults = {"run": {"working-directory": directory}}
                workflow_defaults = None
                if scope == "workflow":
                    workflow_defaults = defaults
                elif scope == "job":
                    jobs["action-policy"]["defaults"] = defaults
                else:
                    index = 4 if scope == "install" else 5
                    jobs["action-policy"]["steps"][index]["working-directory"] = directory
                with self.subTest(scope=scope, directory=directory), self.assertRaisesRegex(PolicyError, "workspace root"):
                    self.verify_server_preflight(jobs, workflow_defaults)

    def test_preflight_accepts_explicit_workspace_root_directories(self) -> None:
        for directory in (".", "./", "${{ github.workspace }}", "${{github.workspace}}/.", "${{ github.workspace }}/"):
            for scope in ("workflow", "job", "step"):
                jobs = self.locked_preflight_jobs()
                defaults = {"run": {"working-directory": directory}}
                workflow_defaults = None
                if scope == "workflow":
                    workflow_defaults = defaults
                elif scope == "job":
                    jobs["action-policy"]["defaults"] = defaults
                else:
                    for step in jobs["action-policy"]["steps"][4:]:
                        step["working-directory"] = directory
                with self.subTest(scope=scope, directory=directory):
                    self.verify_server_preflight(jobs, workflow_defaults)

    def test_preflight_directory_uses_the_most_specific_run_setting(self) -> None:
        jobs = self.locked_preflight_jobs()
        jobs["action-policy"]["defaults"] = {"run": {"working-directory": "."}}
        self.verify_server_preflight(jobs, {"run": {"working-directory": "alternate"}})
        jobs["action-policy"]["defaults"]["run"]["working-directory"] = "alternate"
        for step in jobs["action-policy"]["steps"][4:]:
            step["working-directory"] = "${{ github.workspace }}"
        self.verify_server_preflight(jobs)
        del jobs["action-policy"]["steps"][5]["working-directory"]
        with self.assertRaisesRegex(PolicyError, "workspace root"):
            self.verify_server_preflight(jobs)

    def test_preflight_refuses_inherited_custom_shells(self) -> None:
        for scope in ("workflow", "job"):
            jobs = self.locked_preflight_jobs()
            defaults = {"run": {"shell": "bash -c true {0}"}}
            workflow_defaults = defaults if scope == "workflow" else None
            if scope == "job":
                jobs["action-policy"]["defaults"] = defaults
            with self.subTest(scope=scope), self.assertRaisesRegex(PolicyError, "reviewed shell"):
                self.verify_server_preflight(jobs, workflow_defaults)

    def test_preflight_refuses_custom_dynamic_and_non_shell_invocation(self) -> None:
        for shell in ("bash {0}", "${{ inputs.shell }}", "python", "", None):
            for index in (4, 5):
                jobs = self.locked_preflight_jobs()
                jobs["action-policy"]["steps"][index]["shell"] = shell
                with self.subTest(shell=shell, index=index), self.assertRaisesRegex(PolicyError, "reviewed shell"):
                    self.verify_server_preflight(jobs)

    def test_preflight_accepts_default_and_builtin_safe_shells(self) -> None:
        self.verify_server_preflight(self.locked_preflight_jobs())
        for shell in ("bash", "sh"):
            for scope in ("workflow", "job", "step"):
                jobs = self.locked_preflight_jobs()
                defaults = {"run": {"shell": shell}}
                workflow_defaults = defaults if scope == "workflow" else None
                if scope == "job":
                    jobs["action-policy"]["defaults"] = defaults
                elif scope == "step":
                    for step in jobs["action-policy"]["steps"][4:]:
                        step["shell"] = shell
                with self.subTest(shell=shell, scope=scope):
                    self.verify_server_preflight(jobs, workflow_defaults)

    def test_preflight_shell_uses_the_most_specific_safe_setting(self) -> None:
        jobs = self.locked_preflight_jobs()
        jobs["action-policy"]["defaults"] = {"run": {"shell": "bash"}}
        jobs["gate"]["defaults"] = {"run": {"shell": "sh"}}
        self.verify_server_preflight(jobs, {"run": {"shell": "bash -c true {0}"}})
        jobs["action-policy"]["defaults"]["run"]["shell"] = "bash -c true {0}"
        for step in jobs["action-policy"]["steps"][4:]:
            step["shell"] = "sh"
        self.verify_server_preflight(jobs)
        del jobs["action-policy"]["steps"][5]["shell"]
        with self.assertRaisesRegex(PolicyError, "reviewed shell"):
            self.verify_server_preflight(jobs)

    def test_preflight_result_gate_cannot_inherit_a_custom_shell(self) -> None:
        jobs = self.locked_preflight_jobs()
        jobs["gate"]["defaults"] = {"run": {"shell": "bash -c true {0}"}}
        with self.assertRaisesRegex(PolicyError, "fail closed"):
            self.verify_server_preflight(jobs)
        jobs["gate"]["steps"][0]["shell"] = "bash"
        self.verify_server_preflight(jobs)

    def test_preflight_result_gate_cannot_ignore_its_failure(self) -> None:
        jobs = self.locked_preflight_jobs()
        self.verify_server_preflight(jobs)
        for ignored in (False, "false"):
            jobs["gate"]["steps"][0]["continue-on-error"] = ignored
            with self.subTest(ignored=ignored):
                self.verify_server_preflight(jobs)
        for ignored in (True, "true", "${{ inputs.ignore }}", "${{ false }}"):
            jobs["gate"]["steps"][0]["continue-on-error"] = ignored
            with self.subTest(ignored=ignored), self.assertRaisesRegex(PolicyError, "fail closed"):
                self.verify_server_preflight(jobs)

    def verify_preflight_context(self, jobs: dict, workflow_document: dict | None = None) -> None:
        _verify_action_policy_preflight(
            "server", "source-only context fixture", jobs, "gate",
            {LOCKED_POLICY_BOOTSTRAP_REVISION}, True, workflow_document,
        )

    def test_preflight_job_rejects_unreviewed_execution_fields(self) -> None:
        for key, value in (
            ("container", "ubuntu:24.04"),
            ("services", {"sidecar": {"image": "busybox:latest"}}),
            ("strategy", {"matrix": {"candidate": ["one"]}}),
            ("environment", "unreviewed"),
            ("continue-on-error", True),
            ("concurrency", "unreviewed"),
            ("outputs", {"value": "unreviewed"}),
        ):
            jobs = self.locked_preflight_jobs()
            jobs["action-policy"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(PolicyError, "reviewed read-only shape"):
                self.verify_preflight_context(jobs)

    def test_preflight_actions_cannot_skip_or_change_the_reviewed_context(self) -> None:
        for index in range(4):
            for key, value in (("if", "false"), ("if", False), ("continue-on-error", True), ("working-directory", "alternate")):
                jobs = self.locked_preflight_jobs()
                jobs["action-policy"]["steps"][index][key] = value
                with self.subTest(index=index, key=key, value=value), self.assertRaises(PolicyError):
                    self.verify_preflight_context(jobs)

    def test_preflight_startup_bindings_are_data_only_and_refused(self) -> None:
        for name in ("BASH_ENV", "ENV", "LD_PRELOAD", "NODE_OPTIONS", "PYTHONPATH", "PATH", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "GIT_CONFIG_SYSTEM", "GIT_CONFIG_PARAMETERS", "UNREVIEWED_SETTING"):
            jobs = self.locked_preflight_jobs()
            document = {"env": {name: "candidate-controlled-placeholder"}}
            with self.subTest(name=name), self.assertRaisesRegex(PolicyError, "environment"):
                self.verify_preflight_context(jobs, document)

    def test_preflight_step_startup_bindings_refuse_without_running_them(self) -> None:
        for index in range(6):
            jobs = self.locked_preflight_jobs()
            jobs["action-policy"]["steps"][index]["env"] = {"LD_PRELOAD": "candidate-controlled-placeholder"}
            with self.subTest(index=index), self.assertRaisesRegex(PolicyError, "environment"):
                self.verify_preflight_context(jobs)

    def test_preflight_preserves_reviewed_diagnostics_and_literal_clears(self) -> None:
        jobs = self.locked_preflight_jobs()
        document = {"env": {"CI": "true", "CARGO_TERM_COLOR": "always", "RUST_BACKTRACE": "1"}}
        jobs["action-policy"]["env"] = {"PYTHONUNBUFFERED": "1"}
        for index, step in enumerate(jobs["action-policy"]["steps"]):
            step["env"] = {"FORCE_COLOR": "1"}
            if index < 4:
                step["id"] = f"reviewed_{index}"
                step["if"] = "${{ github.server_url == 'https://github.com' }}"
                step["continue-on-error"] = "false"
        self.verify_preflight_context(jobs, document)
        clears = {name: "" for name in ("BASH_ENV", "ENV", "LD_PRELOAD", "NODE_OPTIONS")}
        self.verify_preflight_context(self.locked_preflight_jobs(), {"env": clears})
        jobs = self.locked_preflight_jobs()
        jobs["action-policy"]["env"] = clears
        self.verify_preflight_context(jobs)

    def test_preflight_environment_is_closed_including_shadowed_bindings(self) -> None:
        jobs = self.locked_preflight_jobs()
        jobs["action-policy"]["env"] = {"BASH_ENV": ""}
        for document in (
            {"env": {"BASH_ENV": "candidate-controlled-placeholder"}},
            {"env": {"NODE_OPTIONS": "${{ inputs.options }}"}},
            {"env": {"GIT_CONFIG_COUNT": ""}},
            {"env": {"CI": ["not a scalar"]}},
            {"env": "not a mapping"},
        ):
            with self.subTest(document=document), self.assertRaisesRegex(PolicyError, "environment"):
                self.verify_preflight_context(jobs, document)

    def test_preflight_defaults_reject_unknown_execution_settings(self) -> None:
        for scope in ("workflow", "job"):
            jobs = self.locked_preflight_jobs()
            defaults = {"run": {"unreviewed": "value"}}
            document = {"defaults": defaults} if scope == "workflow" else None
            if scope == "job":
                jobs["action-policy"]["defaults"] = defaults
            with self.subTest(scope=scope), self.assertRaisesRegex(PolicyError, "defaults"):
                self.verify_preflight_context(jobs, document)
        self.verify_preflight_context(self.locked_preflight_jobs(), {"defaults": {"run": {}}})

    def test_preflight_shape_does_not_close_unrelated_test_jobs(self) -> None:
        jobs = self.locked_preflight_jobs()
        jobs["other"] = {"container": "ubuntu:24.04", "env": {"BASH_ENV": "other-job-placeholder"}}
        self.verify_preflight_context(jobs)

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

    def protected_workflow(self) -> str:
        return (ROOT / ".github/workflows/protected-policy.yml").read_text(encoding="utf-8")

    def test_only_exact_reviewed_protected_workflow_is_allowed(self) -> None:
        sources = {".github/workflows/protected-policy.yml": self.protected_workflow()}
        report = scan_workflow_sources(self.policy, "github-control-plane", sources)
        self.assertIn(".github/workflows/protected-policy.yml", report)

    def test_local_reviewed_workflow_keeps_its_original_lf_bytes(self) -> None:
        source = (ROOT / ".github/workflows/protected-policy.yml").read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / ".github/workflows"
            directory.mkdir(parents=True)
            (directory / "protected-policy.yml").write_bytes(source)

            validate_local_action_references(self.policy, directory)

    def test_local_workflow_line_endings_cannot_reuse_the_reviewed_hash(self) -> None:
        source = (ROOT / ".github/workflows/protected-policy.yml").read_bytes()
        for ending in (b"\r\n", b"\r"):
            changed = source.replace(b"\n", ending)
            self.assertNotEqual(source, changed)
            with self.subTest(ending=ending), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary) / ".github/workflows"
                directory.mkdir(parents=True)
                (directory / "protected-policy.yml").write_bytes(changed)

                with self.assertRaisesRegex(PolicyError, "pull_request_target"):
                    validate_local_action_references(self.policy, directory)

    def test_ordinary_local_workflows_keep_supported_line_endings(self) -> None:
        source = workflow("- run: true").encode("utf-8")
        for ending in (b"\n", b"\r\n", b"\r"):
            with self.subTest(ending=ending), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                (directory / "ci.yml").write_bytes(source.replace(b"\n", ending))

                validate_local_action_references(self.policy, directory)

    def test_shared_yaml_nodes_do_not_multiply_action_reference_work(self) -> None:
        visits = 0

        class CountedMapping(dict):
            def touch(self):
                nonlocal visits
                visits += 1
                if visits > 64:
                    raise AssertionError("Alias traversal exceeded the fixture's work budget")

            def items(self):
                self.touch()
                return super().items()

            def values(self):
                self.touch()
                return super().values()

        reference = "actions/checkout@" + self.approved_action("actions/checkout")[0]
        document = CountedMapping({"uses": reference})
        for _ in range(14):
            document = CountedMapping({"nested": [document, document]})

        with patch("scripts.qualification_policy._parse_yaml", return_value=document):
            self.assertEqual([reference], _workflow_action_references("", "shared graph"))

    def test_real_yaml_aliases_keep_all_distinct_action_references(self) -> None:
        first = "actions/checkout@" + self.approved_action("actions/checkout")[0]
        second = "actions/setup-python@" + self.approved_action("actions/setup-python")[0]
        source = f"shared: &shared [{{uses: {first}}}, {{uses: {second}}}]\n"
        previous = "shared"
        for index in range(8):
            name = f"level{index}"
            source += f"{name}: &{name} [*{previous}, *{previous}]\n"
            previous = name

        self.assertEqual({first, second}, set(_workflow_action_references(source, "real aliases")))

    def test_recursive_yaml_alias_keeps_the_existing_parser_refusal(self) -> None:
        reference = "actions/checkout@" + self.approved_action("actions/checkout")[0]
        source = f"cycle: &cycle [*cycle]\nstep: {{uses: {reference}}}\n"

        with self.assertRaisesRegex(PolicyError, "recursive node"):
            _workflow_action_references(source, "recursive alias")

    def test_secret_context_shared_graph_has_bounded_full_scan_work(self) -> None:
        visits = 0

        class CountedMapping(dict):
            def values(self):
                nonlocal visits
                visits += 1
                if visits > 64:
                    raise AssertionError("Secret-context alias traversal exceeded the fixture work budget")
                return super().values()

        shared = CountedMapping({"value": "ordinary text"})
        for _ in range(14):
            shared = CountedMapping({"nested": [shared, shared]})
        document = {
            "on": {"pull_request": None},
            "permissions": {"contents": "read"},
            "shared": shared,
            "jobs": {"test": {"runs-on": "ubuntu-latest", "steps": [{"run": "true"}]}},
        }
        with patch("scripts.qualification_policy._parse_yaml", return_value=document):
            self.scan("")
        self.assertLessEqual(visits, 64)

    def test_shared_alias_scan_keeps_secret_refusals_and_distinct_actions(self) -> None:
        first, first_version = self.approved_action("actions/checkout")
        second, second_version = self.approved_action("actions/setup-python")
        graph = "leaf: &leaf [ordinary text]\n"
        previous = "leaf"
        for index in range(8):
            name = f"level{index}"
            graph += f"{name}: &{name} [*{previous}, *{previous}]\n"
            previous = name
        source = graph + workflow(
            f"- uses: actions/checkout@{first} # {first_version}",
            f"- uses: actions/setup-python@{second} # {second_version}",
        )
        evidence = self.scan(source)[".github/workflows/test.yml"]
        self.assertEqual(2, len(evidence["external_actions"]))
        with self.assertRaisesRegex(PolicyError, "references a secret"):
            self.scan("late: ${{ secrets.EXAMPLE }}\n" + source)
        shared_secret_source = source.replace("ordinary text", '"${{ secrets.EXAMPLE }}"')
        with self.assertRaisesRegex(PolicyError, "references a secret"):
            self.scan(shared_secret_source)
        self.assertTrue(_references_secret_context({"nested": ["safe", "${{ secrets.EXAMPLE }}"]}))
        self.assertFalse(_references_secret_context({"nested": ["plain secrets.EXAMPLE"]}))

    def test_string_values_preserve_order_for_ordinary_yaml_trees(self) -> None:
        self.assertEqual(
            ["first", "second", "third"],
            _string_values({"a": ["first", ["second"]], "b": {"c": "third"}}),
        )

    def test_preceding_policy_still_refuses_the_protected_workflow(self) -> None:
        self.policy["workflow_trust"]["pull_request_target_exceptions"] = []
        sources = {".github/workflows/protected-policy.yml": self.protected_workflow()}
        with self.assertRaisesRegex(PolicyError, "pull_request_target"):
            scan_workflow_sources(self.policy, "github-control-plane", sources)

    def test_same_workflow_cannot_gain_authority_at_another_path_or_repository(self) -> None:
        source = self.protected_workflow()
        for target, path in (
            ("github-control-plane", ".github/workflows/copied.yml"),
            ("server", ".github/workflows/protected-policy.yml"),
        ):
            sources = {path: source}
            with self.subTest(target=target, path=path), self.assertRaisesRegex(PolicyError, "pull_request_target"):
                scan_workflow_sources(self.policy, target, sources)

    def test_protected_source_mutations_cannot_use_the_exception(self) -> None:
        source = self.protected_workflow()
        for before, after in (
            ("ref: ${{ github.sha }}", "ref: ${{ github.event.pull_request.head.sha }}"),
            ("environment: protected-policy-gate", "environment: production"),
            ("permission-checks: write", "permission-contents: write"),
            ("repositories: .github", "repositories: cloud"),
            ("NODE_OPTIONS: --use-openssl-ca", "NODE_OPTIONS: --use-bundled-ca"),
            ('--expected-head "$POLICY_HEAD_SHA"', '--expected-head "a"'),
        ):
            changed = source.replace(before, after)
            self.assertNotEqual(source, changed)
            sources = {".github/workflows/protected-policy.yml": changed}
            with self.subTest(before=before), self.assertRaisesRegex(PolicyError, "pull_request_target"):
                scan_workflow_sources(self.policy, "github-control-plane", sources)

    def test_modified_or_additional_exceptions_require_another_review(self) -> None:
        original = self.policy["workflow_trust"]["pull_request_target_exceptions"][0]
        for changed in (
            [{**original, "target": "server"}],
            [{**original, "path": ".github/workflows/copied.yml"}],
            [{**original, "sha256": "0" * 64}],
            [original, original],
        ):
            self.policy["workflow_trust"]["pull_request_target_exceptions"] = changed
            with self.subTest(changed=changed), self.assertRaisesRegex(PolicyError, "separately reviewed"):
                validate_policy(self.policy)

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


class TagDispatchPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = policy_fixture()

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


if __name__ == "__main__":
    unittest.main()
