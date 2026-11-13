from pathlib import Path
import hashlib
import unittest
from unittest.mock import patch

import yaml

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

    def test_bound_php_source_ci_successor_preserves_checks_and_requires_exact_review(self):
        path = context.CI_WORKFLOW
        raw = (ROOT / "tests/fixtures/ci-bound-php-source.yml").read_bytes()
        previous = yaml.safe_load((ROOT / "tests/fixtures/ci-php-configuration-source.yml").read_text())
        job = previous["jobs"]["contracts"]
        job["runs-on"] = "ubuntu-24.04"
        job["steps"][0]["with"] = {"persist-credentials": False}
        setup = next(step for step in job["steps"] if step.get("uses", "").startswith("shivammathur/setup-php@"))
        index = job["steps"].index(setup)
        job["steps"].insert(index, {
            "name": "Disable APT download retries (CVE-2026-109518)",
            "run": "echo 'Acquire::Retries \"0\";' | sudo tee /etc/apt/apt.conf.d/99-no-retries >/dev/null",
        })
        setup["uses"] = "durable-workflow/.github/.github/actions/setup-php-linux@411a14ac07d32073eed6ab4977f2825eba4739a7"
        setup["with"]["ini-file"] = "production"
        setup["with"]["tools"] = "composer:2.10.3,phpunit:11.5.57"
        self.assertEqual(previous, yaml.safe_load(raw))
        self.assertEqual(context.REVIEWED_BOUND_PHP_SOURCE_CI_SUCCESSORS[path], hashlib.sha256(raw).hexdigest())
        with patch.object(context, "REVIEWED_BOUND_PHP_SOURCE_CI_SUCCESSORS", {}), self.assertRaises(InputRefused):
            context.validate_context({path: raw})
        context.validate_context({path: raw})
        for changed in (raw + b"\n# unreviewed\n",
                        raw.replace(b"411a14ac07d32073eed6ab4977f2825eba4739a7", b"a" * 40),
                        raw.replace(b"coverage: none", b"coverage: xdebug"),
                        raw.replace(b"tests.test_composer_trust_contract", b"tests.unreviewed")):
            self.assertNotEqual(raw, changed)
            with self.assertRaises(InputRefused):
                context.validate_context({path: changed})
        with self.assertRaises(InputRefused):
            context.validate_context({WORKFLOW: raw})
        with self.assertRaises(InputRefused):
            context.validate_context({path: raw}, policy_target="ai")

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
            # Historical fixture identity is independent of later live CI edits.
            self.assertEqual(context.REVIEWED_SOURCE_CI_SUCCESSORS[path], hashlib.sha256(raw).hexdigest())
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

    def test_php_configuration_source_ci_successors_require_exact_reviewed_bytes_and_target(self):
        modules = ('test_php_linux_bootstrap test_php_linux_archive test_php_linux_normalize '
                   'test_php_linux_recipe test_php_linux_tools test_php_linux_alternatives '
                   'test_setup_php_linux test_php_linux_qualification test_php_linux_qualification_workflow '
                   'test_php_linux_configuration').split()
        for name in ('ci', 'sonar'):
            path = f'.github/workflows/{name}.yml'
            raw = (ROOT / f'tests/fixtures/{name}-php-configuration-source.yml').read_bytes()
            previous = (ROOT / f'tests/fixtures/{name}-private-pip-source.yml').read_bytes()
            if name == 'ci':
                needle = b'          tests.test_composer_container_effective_trust\n'
                added = b''.join(('          tests.' + module + '\n').encode() for module in modules)
                expected = previous.replace(needle, needle + added, 1)
            else:
                needle = b' tests.test_composer_container_effective_trust\n'
                added = b' ' + b' '.join(('tests.' + module).encode() for module in modules) + b'\n'
                expected = previous.replace(needle, needle[:-1] + added, 1)
            self.assertEqual(1, previous.count(needle))
            self.assertEqual(expected, raw)
            self.assertEqual(context.REVIEWED_PHP_CONFIGURATION_SOURCE_CI_SUCCESSORS[path],
                             hashlib.sha256(raw).hexdigest())
            context.validate_context({path: raw})
            with patch.object(context, 'REVIEWED_PHP_CONFIGURATION_SOURCE_CI_SUCCESSORS', {}), \
                    self.assertRaises(InputRefused):
                context.validate_context({path: raw})
            mutations = (raw + b'\n# unreviewed\n',
                         raw.replace(b'tests.test_php_linux_configuration', b'tests.unreviewed', 1),
                         raw.replace(b'75587fc33ff40c34f32ef777293dad56bb6f48c7', b'a' * 40))
            for changed in mutations:
                self.assertNotEqual(raw, changed)
                with self.assertRaises(InputRefused):
                    context.validate_context({path: changed})
            with self.assertRaises(InputRefused):
                context.validate_context({WORKFLOW: raw})
            with self.assertRaises(InputRefused):
                context.validate_context({path: raw}, policy_target='ai')

    def test_configured_cli_manual_successor_remains_exact_inert_and_target_scoped(self):
        path = '.github/workflows/qualify-linux-php-initial.yml'
        raw = (ROOT / 'tests/fixtures/qualify-linux-php-configured-cli.yml').read_bytes()
        previous = (ROOT / 'tests/fixtures/qualify-linux-php-selected-alternatives.yml').read_bytes()
        old = b'fd390417973902bae3ac4847fb67ae778c854786'
        current = b'153f409e36002b2ae5f010f247a03b8830898e3c'
        self.assertEqual(6, previous.count(old))
        self.assertEqual(previous.replace(old, current), raw)
        self.assertEqual(context.REVIEWED_CONFIGURED_CLI_PROFILE_SUCCESSORS[path], hashlib.sha256(raw).hexdigest())
        context.validate_context({path:raw})
        with patch.object(context, 'REVIEWED_CONFIGURED_CLI_PROFILE_SUCCESSORS', {}), self.assertRaises(InputRefused):
            context.validate_context({path:raw})
        for changed in (raw + b'\n# drift\n', raw.replace(current, b'a' * 40, 1),
                        raw.replace(b'workflow_dispatch:\n', b'push:\n'),
                        raw.replace(b'timeout-minutes: 15', b'timeout-minutes: 60')):
            self.assertNotEqual(raw, changed)
            with self.assertRaises(InputRefused):
                context.validate_context({path:changed})
        with self.assertRaises(InputRefused):
            context.validate_context({WORKFLOW:raw})
        with self.assertRaises(InputRefused):
            context.validate_context({path:raw}, policy_target='ai')

    def test_subject_reference_successor_changes_only_six_literals_and_remains_target_scoped(self):
        raw = (ROOT / 'tests/fixtures/qualify-linux-php-subject-references.yml').read_bytes()
        old = (ROOT / 'tests/fixtures/qualify-linux-php-configured-cli.yml').read_bytes()
        previous = b'153f409e36002b2ae5f010f247a03b8830898e3c'
        current = b'140f937cf245f39a495467fe6bab2bd30f93a17a'
        self.assertEqual(6, old.count(previous))
        self.assertEqual(old.replace(previous, current), raw)
        self.assertEqual(7103, len(raw))
        self.assertEqual(context.REVIEWED_SUBJECT_REFERENCE_PROFILE_SUCCESSORS[
            '.github/workflows/qualify-linux-php-initial.yml'], hashlib.sha256(raw).hexdigest())
        self.checked_initial_profile('qualify-linux-php-subject-references.yml',
            'REVIEWED_SUBJECT_REFERENCE_PROFILE_SUCCESSORS', current)

    def test_retired_8ba5caae_ubuntu24_profile_bytes_are_refused_for_the_live_path(self):
        path = '.github/workflows/qualify-linux-php-ubuntu24.yml'
        raw = (ROOT / 'tests/fixtures/qualify-linux-php-ubuntu24.yml').read_bytes()
        self.assertEqual(6, raw.count(b'8ba5caae2546f3d5f41b7616c5722b9b337b8fc0'))
        self.assertEqual('46157beef7dd666b0cf7c2eb6f3d073587b01e7d6075d6f6dfda3c9005e976f7',
                         hashlib.sha256(raw).hexdigest())
        self.assertFalse(hasattr(context, 'REVIEWED_UBUNTU24_PROFILE_WORKFLOWS'))
        digests = set().union(*context.reviewed_context_hashes('github-control-plane').values())
        self.assertNotIn(hashlib.sha256(raw).hexdigest(), digests)
        for target in ('github-control-plane', 'ai'):
            with self.subTest(target=target), self.assertRaisesRegex(InputRefused, 'exact reviewed workflow bytes'):
                context.validate_context({path:raw}, policy_target=target)
        with self.assertRaises(InputRefused):
            context.validate_context({'.github/workflows/qualify-linux-php-initial.yml':raw})
        live = (ROOT / path).read_bytes()
        self.assertEqual((ROOT / 'tests/fixtures/qualify-linux-php-ubuntu24-repinned.yml').read_bytes(), live)
        context.validate_context({path:live})
        with self.assertRaises(InputRefused):
            context.validate_context({path:live, '.github/workflows/other.yml':raw})

    def test_repinned_ubuntu24_successor_changes_only_six_source_literals_and_remains_target_scoped(self):
        path = '.github/workflows/qualify-linux-php-ubuntu24.yml'
        raw = (ROOT / 'tests/fixtures/qualify-linux-php-ubuntu24-repinned.yml').read_bytes()
        old = (ROOT / 'tests/fixtures/qualify-linux-php-ubuntu24.yml').read_bytes()
        previous = b'8ba5caae2546f3d5f41b7616c5722b9b337b8fc0'
        current = b'411a14ac07d32073eed6ab4977f2825eba4739a7'
        self.assertEqual(6, old.count(previous))
        self.assertEqual(old.replace(previous, current), raw)
        self.assertEqual(7108, len(raw))
        self.assertEqual(context.REVIEWED_UBUNTU24_REPINNED_PROFILE_SUCCESSORS[path], hashlib.sha256(raw).hexdigest())
        self.assertEqual({path}, set(context.REVIEWED_UBUNTU24_REPINNED_PROFILE_SUCCESSORS))
        self.checked_initial_profile('qualify-linux-php-ubuntu24-repinned.yml',
            'REVIEWED_UBUNTU24_REPINNED_PROFILE_SUCCESSORS', current, path=path)
        # The retired predecessor is no longer accepted for the live file.
        with self.assertRaises(InputRefused):
            context.validate_context({path:old})
        with self.assertRaises(InputRefused):
            context.validate_context({'.github/workflows/qualify-linux-php-initial.yml':raw})
        for changed in (raw.replace(current, previous, 1), raw.replace(b'ubuntu-24.04', b'ubuntu-latest'),
                        raw.replace(b"release='24.04'", b"release='26.04'")):
            self.assertNotEqual(raw, changed)
            with self.assertRaises(InputRefused):
                context.validate_context({path:changed})

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

    def checked_initial_profile(self, fixture, registry, source,
                                *, path=".github/workflows/qualify-linux-php-initial.yml"):
        raw = (ROOT / "tests/fixtures" / fixture).read_bytes()
        with patch.object(context, registry, {}), self.assertRaises(InputRefused):
            context.validate_context({path: raw})
        context.validate_context({path: raw})
        with self.assertRaises(InputRefused):
            context.validate_context({path: raw}, policy_target="ai")
        with self.assertRaises(InputRefused):
            context.validate_context({WORKFLOW: raw})
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

        from scripts.protected_policy_check import validate_files
        files = {path: raw}
        for name in ('action.yml', 'bootstrap.js'):
            path = '.github/actions/setup-php-linux/' + name
            files[path] = (ROOT / path).read_bytes()
        report = validate_files(files)
        self.assertEqual(3, report['input_count'])
        self.assertEqual(2, report['approved_action_count'])
        self.assertEqual(64, len(report['inputs_sha256']))

    def test_normalized_profile_requires_exact_coordinated_sources_and_control_plane_target(self):
        self.checked_initial_profile('qualify-linux-php-normalized.yml',
            'REVIEWED_NORMALIZED_PROFILE_SUCCESSORS', b'45a7863dbc425ecf19a5a4038a84a9443c23a9a9')

    def test_alternatives_profile_requires_exact_accepted_sources_and_control_plane_target(self):
        self.checked_initial_profile('qualify-linux-php-alternatives.yml',
            'REVIEWED_ALTERNATIVES_PROFILE_SUCCESSORS', b'5f64e43d7dda8d30a7b0c5433f838bb3fe5f85ec')

    def test_selected_alternatives_profile_requires_accepted_sources_and_control_plane_target(self):
        self.checked_initial_profile('qualify-linux-php-selected-alternatives.yml',
            'REVIEWED_SELECTED_ALTERNATIVES_PROFILE_SUCCESSORS', b'fd390417973902bae3ac4847fb67ae778c854786')

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
