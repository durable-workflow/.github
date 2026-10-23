from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

import yaml

from scripts.qualification_policy import PolicyError, verify_composer_network_sinks


REVISION = "a" * 40
PREFIX = "durable-workflow/.github/.github/actions/"


class ComposerNetworkContractTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.policy = {
            "targets": {"fixture": {"composer_trust_required": True}},
            "action_runtime": {"allowed_releases": {"durable-workflow/.github": {REVISION: "clean-trust", "b" * 40: "patched-pip"}}},
        }
        self.steps = [
            {"uses": PREFIX + "bootstrap-patched-pip@" + REVISION, "with": {"clients": "composer,curl,git"}},
            {"uses": "shivammathur/setup-php@" + "c" * 40, "with": {"tools": "composer:2.10.3"}},
            {"uses": PREFIX + "verify-composer-trust@" + REVISION},
            {"run": "composer install --prefer-dist"},
        ]

    def check(self, steps=None, jobs=None, defaults=None):
        jobs = jobs or {"test": {"steps": self.steps if steps is None else steps}}
        document = {"jobs": jobs}
        if defaults is not None:
            document["defaults"] = defaults
        source = yaml.safe_dump(document)
        return verify_composer_network_sinks(self.policy, "fixture", {"ci.yml": source}, self.root)

    def test_reviewed_order_is_enumerated(self):
        self.assertEqual(["ci.yml:test:step-4"], self.check())

    def test_an_omitted_job_is_not_hidden_by_a_safe_job(self):
        with self.assertRaisesRegex(PolicyError, "forgotten"):
            self.check(jobs={"safe": {"steps": self.steps}, "forgotten": {"steps": [{"run": "composer audit --locked"}]}})

    def test_every_guard_and_the_fixed_installer_are_required(self):
        for removed in (0, 1, 2):
            steps = deepcopy(self.steps)
            steps.pop(removed)
            with self.subTest(removed=removed), self.assertRaises(PolicyError):
                self.check(steps)
        for version in ("composer", "composer:v2", "composer:2.10.2"):
            steps = deepcopy(self.steps)
            steps[1]["with"]["tools"] = version
            with self.subTest(version=version), self.assertRaises(PolicyError):
                self.check(steps)

    def test_conditional_or_ignored_guards_cannot_authorize_requests(self):
        for index in (0, 1, 2):
            for field, value in (("if", "false"), ("continue-on-error", True)):
                steps = deepcopy(self.steps)
                steps[index][field] = value
                with self.subTest(index=index, field=field), self.assertRaises(PolicyError):
                    self.check(steps)

    def test_old_or_unreviewed_bootstraps_do_not_claim_clean_exported_trust(self):
        for revision in ("b" * 40, "0" * 40):
            steps = deepcopy(self.steps)
            steps[0]["uses"] = PREFIX + "bootstrap-patched-pip@" + revision
            with self.subTest(revision=revision), self.assertRaises(PolicyError):
                self.check(steps)

    def test_client_scope_and_setup_order_are_checked(self):
        steps = deepcopy(self.steps)
        steps[0]["with"]["clients"] = "pip"
        with self.assertRaises(PolicyError):
            self.check(steps)
        with self.assertRaises(PolicyError):
            self.check([self.steps[1], self.steps[0], *self.steps[2:]])
        with self.assertRaises(PolicyError):
            self.check([*self.steps[:3], self.steps[1], self.steps[3]])

    def test_shell_script_requests_are_enumerated_and_repository_bounded(self):
        (self.root / "scripts").mkdir()
        (self.root / "scripts/build.sh").write_text("composer require example/package\n")
        steps = [*self.steps[:3], {"run": "scripts/build.sh"}]
        self.assertEqual(["ci.yml:test:step-4"], self.check(steps))
        with self.assertRaises(PolicyError):
            self.check([steps[-1]])
        with self.assertRaisesRegex(PolicyError, "outside"):
            self.check([{"run": "scripts/../../outside.sh"}])

    def test_step_overrides_and_failure_conditions_cannot_bypass_refusal(self):
        for mutation in ({"if": "always()"}, {"env": {"COMPOSER_CAFILE": "/unverified"}}):
            steps = deepcopy(self.steps)
            steps[-1].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(PolicyError):
                self.check(steps)
        for change in ("export CURL_CA_BUNDLE=/unverified", "unset COMPOSER_CAFILE"):
            with self.subTest(change=change), self.assertRaises(PolicyError):
                self.check([*self.steps[:3], {"run": change}, self.steps[3]])

    def test_command_options_and_continuations_are_detected(self):
        for command in ("composer --working-dir example install", "composer install; composer audit", "composer \\\n install", "COMPOSER_MEMORY_LIMIT=-1 composer update"):
            with self.subTest(command=command):
                self.assertEqual(1, len(self.check([*self.steps[:3], {"run": command}])))

    def test_local_only_commands_and_quoted_examples_are_not_network_requests(self):
        self.assertEqual([], self.check([{"run": "composer --version\ncomposer help\ncomposer list\necho 'composer install'\nCOMPOSER_BINARY=$(command -v composer) phpunit"}]))

    def test_unknown_and_other_composer_commands_require_a_fresh_guard(self):
        for command in ("remove vendor/package", "reinstall vendor/package", "search package", "self-update", "diagnose", "show --all", "custom-script", "validate"):
            with self.subTest(command=command), self.assertRaises(PolicyError):
                self.check([{"run": "composer " + command}])
            self.assertEqual(1, len(self.check([*self.steps[:3], {"run": "composer " + command}])))

    def test_opaque_actions_and_other_steps_expire_verification(self):
        for intervening in ({"uses": "actions/cache@" + "c" * 40}, {"run": "pwd"}, self.steps[-1]):
            with self.subTest(intervening=intervening), self.assertRaises(PolicyError):
                self.check([*self.steps[:3], intervening, self.steps[-1]])
        self.assertEqual(2, len(self.check([*self.steps, self.steps[2], self.steps[-1]])))

    def test_helper_trust_mutations_cannot_inherit_a_previous_live_check(self):
        (self.root / "scripts").mkdir()
        (self.root / "scripts/build.sh").write_text("export COMPOSER_CAFILE=/unverified\ncomposer install\n")
        with self.assertRaisesRegex(PolicyError, "changes Composer trust"):
            self.check([*self.steps[:3], {"run": "scripts/build.sh"}])
        with self.assertRaisesRegex(PolicyError, "changes Composer trust"):
            self.check([*self.steps[:3], {"run": "composer config disable-tls true\ncomposer install"}])

    def test_extensionless_and_nested_repository_helpers_are_inspected(self):
        (self.root / "scripts").mkdir()
        (self.root / "scripts/build").write_text("#!/bin/sh\nscripts/inner\n")
        (self.root / "scripts/inner").write_text("#!/bin/sh\ncomposer install\n")
        with self.assertRaises(PolicyError):
            self.check([{"run": "scripts/build"}])
        self.assertEqual(1, len(self.check([*self.steps[:3], {"run": "scripts/build"}])))

    def relative_helper_fixture(self):
        (self.root / "scripts").mkdir()
        (self.root / "scripts/request.sh").write_text("#!/bin/sh\nprintf done\n")
        (self.root / "alternate/scripts").mkdir(parents=True)
        (self.root / "alternate/scripts/request.sh").write_text("#!/bin/sh\ncomposer install\n")

    def test_relative_helpers_cannot_be_redirected_by_run_directories(self):
        self.relative_helper_fixture()
        for scope in ("step", "job", "workflow"):
            step = {"run": "scripts/request.sh"}
            job = {"steps": [step]}
            defaults = {"run": {"working-directory": "alternate"}}
            workflow_defaults = None
            if scope == "step":
                step["working-directory"] = "alternate"
            elif scope == "job":
                job["defaults"] = defaults
            else:
                workflow_defaults = defaults
            with self.subTest(scope=scope), self.assertRaisesRegex(PolicyError, "workspace root"):
                self.check(jobs={"test": job}, defaults=workflow_defaults)

    def test_relative_helpers_refuse_directory_changes_in_shell_source(self):
        self.relative_helper_fixture()
        for command in (
            "cd alternate\nscripts/request.sh",
            "pushd alternate; scripts/request.sh",
            "builtin cd alternate && scripts/request.sh",
            "bash -c 'cd alternate; scripts/request.sh'",
        ):
            with self.subTest(command=command), self.assertRaisesRegex(PolicyError, "workspace root"):
                self.check([{"run": command}])
        (self.root / "scripts/outer.sh").write_text("cd alternate\nscripts/request.sh\n")
        with self.assertRaisesRegex(PolicyError, "workspace root"):
            self.check([{"run": "scripts/outer.sh"}])

    def test_explicit_workspace_roots_keep_guarded_helper_requests(self):
        (self.root / "scripts").mkdir()
        (self.root / "scripts/request.sh").write_text("composer install\n")
        for directory in (".", "./", "${{ github.workspace }}", "${{github.workspace}}/."):
            for scope in ("step", "job", "workflow"):
                step = {"run": "scripts/request.sh"}
                job = {"steps": [*self.steps[:3], step]}
                defaults = {"run": {"working-directory": directory}}
                workflow_defaults = None
                if scope == "step":
                    step["working-directory"] = directory
                elif scope == "job":
                    job["defaults"] = defaults
                else:
                    workflow_defaults = defaults
                with self.subTest(scope=scope, directory=directory):
                    self.assertEqual(1, len(self.check(jobs={"test": job}, defaults=workflow_defaults)))

    def test_helper_directory_uses_the_most_specific_run_setting(self):
        self.relative_helper_fixture()
        step = {"run": "scripts/request.sh", "working-directory": "."}
        job = {"steps": [step], "defaults": {"run": {"working-directory": "alternate"}}}
        self.assertEqual([], self.check(jobs={"test": job}))
        del step["working-directory"]
        job["defaults"]["run"]["working-directory"] = "${{ github.workspace }}"
        self.assertEqual([], self.check(jobs={"test": job}, defaults={"run": {"working-directory": "alternate"}}))

    def test_non_helper_commands_keep_their_existing_directory_behavior(self):
        self.assertEqual([], self.check([{"run": "cargo test", "working-directory": "alternate"}]))
        self.assertEqual([], self.check([{"run": "cd alternate\ncargo test"}]))

    def test_non_shell_programs_keep_their_existing_directory_behavior(self):
        for command in ("python3 scripts/check.py", "python -I scripts/check.py", "node scripts/check.mjs", "php scripts/check.php"):
            with self.subTest(command=command):
                self.assertEqual([], self.check([{"run": command, "working-directory": "alternate"}]))
        with self.assertRaisesRegex(PolicyError, "workspace root"):
            self.check([{"run": "python3 scripts/check.py; scripts/request.sh", "working-directory": "alternate"}])
        for command in ("custom-python3 scripts/request.sh", "scripts/python3 scripts/request.sh"):
            with self.subTest(command=command), self.assertRaisesRegex(PolicyError, "workspace root"):
                self.check([{"run": command, "working-directory": "alternate"}])

    def test_shell_invocation_keeps_helper_inspection_despite_its_extension(self):
        (self.root / "scripts").mkdir()
        (self.root / "scripts/request.py").write_text("composer install\n")
        with self.assertRaisesRegex(PolicyError, "workspace root"):
            self.check([{"run": "bash scripts/request.py", "working-directory": "alternate"}])
        with self.assertRaisesRegex(PolicyError, "lack the reviewed"):
            self.check([{"run": "bash scripts/request.py"}])
        self.assertEqual(1, len(self.check([*self.steps[:3], {"run": "bash scripts/request.py"}])))

    def test_relative_helpers_refuse_custom_shell_context(self):
        self.relative_helper_fixture()
        for scope in ("step", "job", "workflow"):
            step = {"run": "scripts/request.sh"}
            job = {"steps": [step]}
            shell = "bash -c 'cd alternate; bash {0}' ignored"
            defaults = {"run": {"shell": shell}}
            workflow_defaults = None
            if scope == "step":
                step["shell"] = shell
            elif scope == "job":
                job["defaults"] = defaults
            else:
                workflow_defaults = defaults
            with self.subTest(scope=scope), self.assertRaisesRegex(PolicyError, "reviewed shell"):
                self.check(jobs={"test": job}, defaults=workflow_defaults)

    def test_helper_shell_uses_the_most_specific_safe_setting(self):
        self.relative_helper_fixture()
        for shell in ("bash", "sh"):
            step = {"run": "scripts/request.sh", "shell": shell}
            job = {"steps": [step], "defaults": {"run": {"shell": "bash -c true {0}"}}}
            self.assertEqual([], self.check(jobs={"test": job}))
            del step["shell"]
            job["defaults"]["run"]["shell"] = shell
            self.assertEqual([], self.check(jobs={"test": job}, defaults={"run": {"shell": "bash -c true {0}"}}))

    def test_job_and_workflow_overrides_cannot_bypass_the_step_guards(self):
        with self.assertRaisesRegex(PolicyError, "job-level"):
            self.check(jobs={"test": {"env": {"GIT_SSL_NO_VERIFY": "1"}, "steps": self.steps}})
        source = yaml.safe_dump({"env": {"COMPOSER_CAFILE": "/unverified"}, "jobs": {"test": {"steps": self.steps}}})
        with self.assertRaisesRegex(PolicyError, "workflow-level"):
            verify_composer_network_sinks(self.policy, "fixture", {"ci.yml": source}, self.root)

    def test_environment_arguments_and_non_shell_fixture_sources_are_not_composer_invocations(self):
        self.assertEqual([], self.check([{"run": "docker run --env COMPOSER_HOME=/tmp/composer image composer --version"}]))
        (self.root / "scripts").mkdir()
        (self.root / "scripts/fixtures.py").write_text("example = 'composer remove vendor/package'\n")
        self.assertEqual([], self.check([{"run": "python scripts/fixtures.py"}]))


if __name__ == "__main__":
    unittest.main()
