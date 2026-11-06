from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import protected_policy_context as context
from scripts.protected_policy_inputs import InputRefused

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/example.yml"


def workflow(run="python scripts/candidate.py", *, top="", job="", step=""):
    return (f"name: Example\non:\n  pull_request:\n{top}jobs:\n  test:\n"
            f"    runs-on: ubuntu-latest\n{job}    steps:\n"
            f"      - run: {run}\n{step}").encode()


class ProtectedContextTest(unittest.TestCase):
    def validate(self, raw=None, **files):
        context.validate_context({WORKFLOW: raw or workflow(), **files})

    def test_current_control_workflows_have_supported_contexts(self):
        files = {path.relative_to(ROOT).as_posix(): path.read_bytes()
                 for path in (ROOT / ".github/workflows").glob("*.y*ml")}
        context.validate_context(files)

    def test_unknown_context_target_refuses_without_interpreting_a_workflow(self):
        with self.assertRaisesRegex(InputRefused, "context target"):
            context.validate_context({}, policy_target="elsewhere")

    def test_initial_qualification_is_only_the_exact_reviewed_future_workflow(self):
        path=".github/workflows/qualify-linux-php-initial.yml"
        raw=(ROOT/"tests/fixtures/qualify-linux-php-initial.yml").read_bytes()
        context.validate_context({path:raw})
        mutations=[
            raw+b"\n# changed workflow\n",
            raw.replace(b"test \"$EXPECTED_WORKFLOW_SHA\" = \"$GITHUB_SHA\"",b"true"),
            raw.replace(b"timeout-minutes: 15",b"timeout-minutes: 60"),
            raw.replace(b"workflow_dispatch:\n",b"push:\n"),
            raw.replace(b"1b194dd945b72019f701e94472134135f584f652",b"a"*40),
            raw.replace(b"steps.admission.outcome == 'success'",b"true"),
        ]
        for index,changed in enumerate(mutations):
            self.assertNotEqual(raw,changed)
            with self.subTest(change=index),self.assertRaises(InputRefused):
                context.validate_context({path:changed})
        with self.assertRaises(InputRefused):
            context.validate_context({WORKFLOW:raw})

    def test_updated_fixture_and_test_workflows_still_require_exact_reviewed_bytes(self):
        for path in (".github/workflows/ci.yml", ".github/workflows/sonar.yml",
                     ".github/workflows/cancellation-competitors.yml"):
            raw = (ROOT / path).read_bytes()
            with self.subTest(path=path):
                context.validate_context({path: raw})
                changed = raw + b"\n# not part of the reviewed workflow\n"
                with self.assertRaisesRegex(InputRefused, "closed literal"):
                    context.validate_context({path: changed})

    def test_private_pip_source_ci_successors_are_exact_inert_reviewed_workflows(self):
        for name in ("ci", "sonar"):
            path = f".github/workflows/{name}.yml"
            raw = (ROOT / f"tests/fixtures/{name}-private-pip-source.yml").read_bytes()
            current = (ROOT / path).read_bytes()
            expected = current.replace(b"uses: ./.github/actions/bootstrap-patched-pip # local",
                b"uses: durable-workflow/.github/.github/actions/bootstrap-patched-pip@75587fc33ff40c34f32ef777293dad56bb6f48c7 # clean-trust")
            self.assertEqual(expected, raw)
            with self.subTest(workflow=name):
                with patch.object(context, "REVIEWED_SOURCE_CI_SUCCESSORS", {}), self.assertRaises(InputRefused):
                    context.validate_context({path: raw})
                context.validate_context({path: raw})
                for changed in (raw + b"\n# unreviewed\n",
                                raw.replace(b"75587fc33ff40c34f32ef777293dad56bb6f48c7", b"a" * 40),
                                raw.replace(b"clients: pip,python,composer,curl,git,npm,cargo", b"clients: pip")):
                    self.assertNotEqual(raw, changed)
                    with self.assertRaises(InputRefused):
                        context.validate_context({path: changed})
                with self.assertRaises(InputRefused):
                    context.validate_context({WORKFLOW: raw})

    def test_private_pip_manual_successor_is_exact_and_keeps_php_and_control_sources_separate(self):
        path = ".github/workflows/qualify-linux-php-initial.yml"
        raw = (ROOT / "tests/fixtures/qualify-linux-php-private-pip.yml").read_bytes()
        with patch.object(context, "REVIEWED_INITIAL_PROFILE_SUCCESSORS", {}), self.assertRaises(InputRefused):
            context.validate_context({path: raw})
        context.validate_context({path: raw})
        with self.assertRaises(InputRefused):
            context.validate_context({path: raw}, policy_target="ai")
        mutations = [raw + b"\n# changed\n", raw.replace(b"workflow_dispatch:\n", b"push:\n"),
            raw.replace(b"timeout-minutes: 15", b"timeout-minutes: 60"),
            raw.replace(b"1b194dd945b72019f701e94472134135f584f652", b"a" * 40),
            raw.replace(b"242c2a7fb23459db2e1ada5f84dbee6d61d9b1e5", b"b" * 40),
            raw.replace(b"2ca775c1951c1e6a6a469f5a0db672c00479b337", b"c" * 40),
            raw.replace(b"GITHUB_RUN_ATTEMPT\" = 1", b"GITHUB_RUN_ATTEMPT\" = 2"),
            raw.replace(b"qualification.qualify(receipt,runner_temp,closed,publish,pip_state=pip_state)",
                        b"qualification.qualify(receipt,runner_temp,closed,publish)")]
        for index, changed in enumerate(mutations):
            self.assertNotEqual(raw, changed)
            with self.subTest(mutation=index), self.assertRaises(InputRefused):
                context.validate_context({path: changed})
        with self.assertRaises(InputRefused):
            context.validate_context({WORKFLOW: raw})

    def test_normalized_profile_requires_exact_coordinated_sources_and_control_plane_target(self):
        path = ".github/workflows/qualify-linux-php-initial.yml"
        raw = (ROOT / "tests/fixtures/qualify-linux-php-normalized.yml").read_bytes()
        with patch.object(context, "REVIEWED_NORMALIZED_PROFILE_SUCCESSORS", {}), self.assertRaises(InputRefused):
            context.validate_context({path: raw})
        context.validate_context({path: raw})
        with self.assertRaises(InputRefused):
            context.validate_context({path: raw}, policy_target="ai")
        with self.assertRaises(InputRefused):
            context.validate_context({WORKFLOW: raw})
        source = b"45a7863dbc425ecf19a5a4038a84a9443c23a9a9"
        changes = [raw + b"\n# drift\n", raw.replace(b"workflow_dispatch:\n", b"push:\n"),
            raw.replace(b"timeout-minutes: 15", b"timeout-minutes: 60"),
            raw.replace(source, b"a" * 40),
            raw.replace(b"ref: " + source, b"ref: 1b194dd945b72019f701e94472134135f584f652", 1),
            raw.replace(b".qualification-control", b".other-source"),
            raw.replace(b"242c2a7fb23459db2e1ada5f84dbee6d61d9b1e5", b"b" * 40),
            raw.replace(b"GITHUB_RUN_ATTEMPT\" = 1", b"GITHUB_RUN_ATTEMPT\" = 2"),
            raw.replace(b"pathlib.Path(receipt_text) if receipt_text else None", b"pathlib.Path('/unproven')"),
            raw.replace(b"qualification.qualify(receipt,runner_temp,closed,publish,pip_state=pip_state)",
                        b"qualification.qualify(receipt,runner_temp,closed,publish)")]
        for number, changed in enumerate(changes):
            self.assertNotEqual(raw, changed)
            with self.subTest(change=number), self.assertRaises(InputRefused):
                context.validate_context({path: changed})

    def test_normalized_profile_passes_the_real_inert_context_and_action_parser(self):
        from scripts.protected_policy_check import validate_files
        files = {'.github/workflows/qualify-linux-php-initial.yml':
            (ROOT / 'tests/fixtures/qualify-linux-php-normalized.yml').read_bytes()}
        for name in ('action.yml', 'bootstrap.js'):
            path = '.github/actions/setup-php-linux/' + name
            files[path] = (ROOT / path).read_bytes()
        report = validate_files(files)
        self.assertEqual(3, report['input_count'])
        self.assertEqual(2, report['approved_action_count'])
        self.assertEqual(64, len(report['inputs_sha256']))

    def test_plain_root_helper_and_literal_root_overrides_are_supported(self):
        for directory in (".", "./", "${{ github.workspace }}"):
            with self.subTest(directory=directory):
                self.validate(workflow(step=f"        working-directory: '{directory}'\n        shell: bash\n"))

    def test_workflow_job_and_step_directories_refuse_before_validator(self):
        for options in ({"top": "defaults:\n  run:\n    working-directory: other\n"},
                        {"job": "    defaults:\n      run:\n        working-directory: other\n"},
                        {"step": "        working-directory: other\n"}):
            raw = workflow(**options)
            with self.subTest(options=options), self.assertRaisesRegex(InputRefused, "workspace root"):
                self.validate(raw)

    def test_effective_root_override_is_explicit_and_supported(self):
        self.validate(workflow(top="defaults:\n  run:\n    working-directory: other\n",
                               step="        working-directory: .\n"))

    def test_custom_shell_and_startup_environment_refuse(self):
        for step in ("        shell: python\n", "        shell: 'bash --rcfile custom {0}'\n",
                     "        env:\n          BASH_ENV: scripts/startup.sh\n"):
            raw = workflow(step=step)
            with self.subTest(step=step), self.assertRaises(InputRefused):
                self.validate(raw)

    def test_directory_and_dynamic_shell_forms_are_deliberately_unsupported(self):
        for run in ("cd other; bash scripts/validate.sh", "pushd .; bash scripts/validate.sh",
                    "bash scripts/validate.sh; popd", "eval data; bash scripts/validate.sh",
                    "$(command -v bash) scripts/validate.sh", "`which bash` scripts/validate.sh",
                    "echo cd; bash scripts/validate.sh", "c\"\"d other; bash scripts/validate.sh",
                    ". scripts/startup.conf; bash scripts/validate.sh"):
            raw = workflow(run)
            with self.subTest(run=run), self.assertRaises(InputRefused):
                self.validate(raw)

    def test_source_flags_do_not_become_shell_builtins(self):
        self.validate(workflow("python scripts/validate.py --source=scripts --source-repository project"))

    def test_directory_changes_in_referenced_shell_closure_refuse(self):
        raw = workflow("bash scripts/validate.sh")
        with self.assertRaisesRegex(InputRefused, "helper"):
            self.validate(raw, **{
                "scripts/validate.sh": b"bash scripts/nested.sh\n",
                "scripts/nested.sh": b"cd other\ncomposer install\n",
            })

    def test_shell_construction_and_startup_bypasses_refuse_direct_and_nested(self):
        programs = (
            "x=cd; $x /tmp; python scripts/validate.py",
            "$'cd' /tmp; python scripts/validate.py",
            'x=c; y=d; "$x$y" /tmp; python scripts/validate.py',
            "bash -c 'cd /tmp; python scripts/validate.py'",
            "BASH_ENV=/tmp/startup bash scripts/validate.sh",
        )
        for program in programs:
            with self.subTest(program=program):
                raw = workflow("|") + ("          " + program + "\n").encode()
                with self.assertRaisesRegex(InputRefused, "closed literal"):
                    self.validate(raw)
                files = {"scripts/entry.sh": b"bash scripts/nested.py\n",
                         "scripts/nested.py": (program + "\n").encode()}
                nested_workflow = workflow("bash scripts/entry.sh")
                with self.assertRaisesRegex(InputRefused, "helper"):
                    self.validate(nested_workflow, **files)

    def test_indirect_hidden_helpers_and_evaluator_options_refuse(self):
        for run in ('bash "$SCRIPT"', '"$RUNNER" "$TARGET"',
                    "python -c 'print(1)'", "node --eval data", "env bash scripts/ok.sh",
                    "bash -O extglob scripts/ok.sh", "python scripts/ok.py > result",
                    "python scripts/ok.py && python scripts/other.py",
                    "python scripts/ok.py\\\n scripts/other.py"):
            raw = workflow(run)
            with self.subTest(run=run), self.assertRaises(InputRefused):
                self.validate(raw)

    def test_literal_multiple_commands_flags_and_nested_shell_helpers_pass(self):
        raw = workflow("|") + b"          python scripts/validate.py --source=scripts --source-repository project\n          bash scripts/entry.sh\n"
        self.validate(raw, **{"scripts/entry.sh": b"#!/bin/sh\n# source is data here\nbash scripts/nested.sh\n",
                              "scripts/nested.sh": b"composer install --no-interaction\n"})

    def test_exact_complex_workflow_binding_cannot_be_supplied_by_candidate(self):
        path = ".github/workflows/rust-docs-visual.yml"
        raw = (ROOT / path).read_bytes()
        context.validate_context({path: raw})
        changed = raw.replace(b"python visual-controller/scripts/visual_evidence.py classify",
                              b"x=cd; $x /tmp; python visual-controller/scripts/visual_evidence.py classify")
        with self.assertRaisesRegex(InputRefused, "closed literal"):
            context.validate_context({path: changed})
        with self.assertRaises(InputRefused):
            context.validate_context({WORKFLOW: raw})

    def test_exact_workflow_binding_does_not_exempt_changed_shell_helpers(self):
        path = ".github/workflows/protected-policy.yml"
        # The workflow is exact; the referenced Python file cannot disguise a
        # shell program behind its extension to inherit the workflow exception.
        files = {path: (ROOT / "tests/fixtures/retired-protected-policy.yml").read_bytes(),
                 "scripts/protected_policy_issue.py": b"#!/bin/bash\nx=cd; $x /tmp\n"}
        with self.assertRaisesRegex(InputRefused, "helper"):
            context.validate_context(files)

    def test_interpreter_startup_and_exported_functions_refuse(self):
        for name in ("BASH_ENV", "PATH", "CDPATH", "BASH_FUNC_python%%"):
            raw = workflow(step=f"        env:\n          {name}: injected\n")
            with self.subTest(name=name), self.assertRaises(InputRefused):
                self.validate(raw)
        raw = workflow("bash scripts/entry.sh")
        with self.assertRaises(InputRefused):
            self.validate(raw, **{"scripts/entry.sh": b"#!/usr/bin/env -S bash -c\ncomposer install\n"})

    def test_python_helper_text_is_data_and_not_a_shell_program(self):
        self.validate(**{"scripts/candidate.py": b"message = 'cd elsewhere'\n"})

    def test_alias_steps_are_inspected_and_recursive_aliases_refuse(self):
        raw = b"""name: Alias
on: {pull_request: null}
jobs:
  test:
    steps:
      - &step
        run: python scripts/candidate.py
        working-directory: elsewhere
      - *step
"""
        with self.assertRaises(InputRefused):
            self.validate(raw)
        with self.assertRaisesRegex(InputRefused, "recursive"):
            context.bounded_document("jobs: &jobs {test: *jobs}")

    def test_duplicate_and_merge_keys_refuse(self):
        for source in ("jobs: {}\njobs: {}", "jobs: {<<: {test: {}}}"):
            with self.subTest(source=source), self.assertRaises(InputRefused):
                context.bounded_document(source)

    def test_node_depth_and_alias_expansion_have_independent_bounds(self):
        with patch.object(context, "MAX_YAML_DEPTH", 4), self.assertRaises(InputRefused):
            context.bounded_document("jobs: [[[[[[]]]]]]")
        with patch.object(context, "MAX_YAML_NODES", 20), self.assertRaises(InputRefused):
            context.bounded_document("first: &a [x, y, z]\nsecond: &b [*a, *a, *a]\nthird: [*b, *b, *b]")

    def test_malformed_context_shapes_refuse(self):
        for raw in (b"[]", b"jobs: []", b"jobs: {test: {steps: {}}}",
                    workflow(step="        working-directory: [elsewhere]\n"),
                    workflow(job="    defaults: []\n")):
            with self.subTest(raw=raw), self.assertRaises(InputRefused):
                self.validate(raw)
