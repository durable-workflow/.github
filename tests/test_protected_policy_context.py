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
