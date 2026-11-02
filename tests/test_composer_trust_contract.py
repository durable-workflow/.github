from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

import yaml

from scripts.qualification_policy import PolicyError, verify_composer_container_callers, verify_composer_network_sinks


REVISION = "a" * 40
PREFIX = "durable-workflow/.github/.github/actions/"


class ComposerContainerCallerContractTest(unittest.TestCase):
    def setUp(self):
        self.guard = {"uses": PREFIX + "verify-composer-container-trust@" + REVISION, "id": "container-trust",
                      "with": {"request": "fixture", "source-directory": "server", "source-commit": "${{ inputs.server_commit }}",
                               "compose-directory": "sdk", "provenance": "sdk/provenance.json"}}
        self.command = "docker compose --env-file /dev/null up -d --build --wait --wait-timeout 300"
        bindings = {"DWF_COMPOSER_TRUST_CONTEXT": "context-directory", "COMPOSER_CAFILE": "ca-file",
                    "DW_CI_CA_SHA256": "ca-sha256", "DW_SERVER_SOURCE_COMMIT": "source-commit",
                    "DW_SERVER_DOCKERFILE_SHA256": "dockerfile-sha256", "COMPOSE_FILE": "compose-file"}
        self.build = {"run": self.command, "working-directory": "sdk",
                      "env": {name: "${{ steps.container-trust.outputs." + output + " }}" for name, output in bindings.items()}}
        self.catalog = {"requests": {"fixture": {"target": "fixture", "workflow": "ci.yml", "job": "connected", "command": self.command}}}

    def check(self, steps=None):
        source = yaml.safe_dump({"jobs": {"connected": {"steps": [self.guard, self.build] if steps is None else steps}}})
        return verify_composer_container_callers("fixture", {".github/workflows/ci.yml": source}, {REVISION}, self.catalog)

    def test_build_uses_every_output_from_its_fresh_registered_guard(self):
        self.assertEqual(["ci.yml:connected:container-fixture"], self.check())

    def test_missing_unreviewed_or_intervening_guard_refuses(self):
        with self.assertRaises(PolicyError):
            self.check([self.build])
        with self.assertRaises(PolicyError):
            self.check([self.guard, {"run": "echo intervening"}, self.build])
        self.guard["uses"] = PREFIX + "verify-composer-container-trust@" + "b" * 40
        with self.assertRaises(PolicyError):
            self.check()

    def test_conditional_ignored_duplicate_or_changed_build_refuses(self):
        for index in (0, 1):
            for field, value in (("if", "always()"), ("continue-on-error", True)):
                steps = deepcopy([self.guard, self.build])
                steps[index][field] = value
                with self.subTest(index=index, field=field), self.assertRaises(PolicyError):
                    self.check(steps)
        with self.assertRaises(PolicyError):
            self.check([self.guard, self.build, self.guard, self.build])
        self.build["run"] = "docker compose up --build"
        with self.assertRaises(PolicyError):
            self.check()

    def test_each_source_trust_and_compose_output_is_required(self):
        for name in self.build["env"]:
            steps = deepcopy([self.guard, self.build])
            steps[1]["env"][name] = "unverified"
            with self.subTest(name=name), self.assertRaises(PolicyError):
                self.check(steps)
        self.build["env"]["COMPOSER_HOME"] = "/unverified"
        with self.assertRaises(PolicyError):
            self.check()

    def test_request_and_actual_build_directory_cannot_change(self):
        for field in ("request", "source-directory", "source-commit", "compose-directory", "provenance"):
            steps = deepcopy([self.guard, self.build])
            steps[0]["with"][field] = ""
            with self.subTest(field=field), self.assertRaises(PolicyError):
                self.check(steps)
        self.build["working-directory"] = "another-directory"
        with self.assertRaises(PolicyError):
            self.check()

    def test_deleting_the_workflow_or_registered_job_does_not_hide_a_sink(self):
        for sources in ({}, {"ci.yml": "jobs: {}"}):
            with self.subTest(sources=sources), self.assertRaises(PolicyError):
                verify_composer_container_callers("fixture", sources, {REVISION}, self.catalog)


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

    def check(self, steps=None, jobs=None):
        jobs = jobs or {"test": {"steps": self.steps if steps is None else steps}}
        source = yaml.safe_dump({"jobs": jobs})
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
