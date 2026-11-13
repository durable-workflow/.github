from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml

from scripts.qualification_policy import PolicyError, verify_composer_container_callers, verify_composer_network_sinks


REVISION = "a" * 40
BOUND_REVISION = "d" * 40
PREFIX = "durable-workflow/.github/.github/actions/"


class ComposerContainerCallerContractTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.bootstrap = {"uses": PREFIX + "bootstrap-patched-pip@" + REVISION, "id": "clean-bootstrap"}
        self.guard = {"uses": PREFIX + "verify-composer-container-trust@" + REVISION, "id": "container-trust",
                      "with": {"request": "fixture", "source-directory": "server", "source-commit": "${{ inputs.server_commit }}",
                               "compose-directory": "sdk", "provenance": "sdk/provenance.json",
                               "ca-file": "${{ steps.clean-bootstrap.outputs.ca-file }}",
                               "ca-sha256": "${{ steps.clean-bootstrap.outputs.ca-sha256 }}"}}
        self.command = "docker compose --env-file /dev/null up -d --build --wait --wait-timeout 300"
        bindings = {"DWF_COMPOSER_TRUST_CONTEXT": "context-directory", "COMPOSER_CAFILE": "ca-file",
                    "DW_CI_CA_SHA256": "ca-sha256", "DW_SERVER_SOURCE_COMMIT": "source-commit",
                    "DW_SERVER_DOCKERFILE_SHA256": "dockerfile-sha256", "COMPOSE_FILE": "compose-file"}
        self.build = {"run": self.command, "working-directory": "sdk",
                      "env": {name: "${{ steps.container-trust.outputs." + output + " }}" for name, output in bindings.items()}}
        self.catalog = {"requests": {"fixture": {"target": "fixture", "workflow": "ci.yml", "job": "connected", "command": self.command}}}

    def check(self, steps=None):
        selected = [self.guard, self.build] if steps is None else steps
        source = yaml.safe_dump({"jobs": {"connected": {"steps": [self.bootstrap, *selected]}}})
        return verify_composer_container_callers("fixture", {".github/workflows/ci.yml": source}, {REVISION}, self.catalog, self.root)

    def test_build_uses_every_output_from_its_fresh_registered_guard(self):
        self.assertEqual(["ci.yml:connected:container-fixture"], self.check())

    def test_container_only_release_cannot_supply_the_clean_bootstrap(self):
        revision = "b" * 40
        policy = {"targets": {"fixture": {"composer_trust_required": True}}, "action_runtime": {
            "allowed_releases": {"durable-workflow/.github": {REVISION: "clean-trust"}}}}
        self.guard["uses"] = PREFIX + "verify-composer-container-trust@" + revision

        def verify():
            source = yaml.safe_dump({"jobs": {"connected": {"steps": [self.bootstrap, self.guard, self.build]}}})
            with mock.patch("scripts.qualification_policy._composer_container_catalog", return_value=self.catalog):
                return verify_composer_network_sinks(policy, "fixture", {"ci.yml": source}, self.root)

        with self.assertRaisesRegex(PolicyError, "preceding reviewed container verifier"):
            verify()
        policy["action_runtime"]["allowed_releases"]["durable-workflow/.github"][revision] = "composer-container-trust"
        self.assertEqual(["ci.yml:connected:container-fixture"], verify())
        self.bootstrap["uses"] = PREFIX + "bootstrap-patched-pip@" + revision
        with self.assertRaisesRegex(PolicyError, "reviewed unconditional clean bootstrap"):
            verify()

    def test_clean_trust_role_cannot_authorize_a_container_verifier(self):
        policy = {"targets": {"fixture": {"composer_trust_required": True}}, "action_runtime": {
            "allowed_releases": {"durable-workflow/.github": {REVISION: "clean-trust", "b" * 40: "composer-container-trust"}}}}

        def verify():
            source = yaml.safe_dump({"jobs": {"connected": {"steps": [self.bootstrap, self.guard, self.build]}}})
            with mock.patch("scripts.qualification_policy._composer_container_catalog", return_value=self.catalog):
                return verify_composer_network_sinks(policy, "fixture", {"ci.yml": source}, self.root)

        with self.assertRaisesRegex(PolicyError, "preceding reviewed container verifier"):
            verify()
        self.guard["uses"] = PREFIX + "verify-composer-container-trust@" + "b" * 40
        self.assertEqual(["ci.yml:connected:container-fixture"], verify())

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
                verify_composer_container_callers("fixture", sources, {REVISION}, self.catalog, self.root)

    def test_guard_ca_identity_must_come_from_the_reviewed_bootstrap_outputs(self):
        for field in ("ca-file", "ca-sha256"):
            steps = deepcopy([self.guard, self.build])
            steps[0]["with"][field] = "${{ env.UNVERIFIED }}"
            with self.subTest(field=field), self.assertRaises(PolicyError):
                self.check(steps)
        self.guard["env"] = {"COMPOSER_CAFILE": "/tmp/unverified.pem", "DW_CI_CA_SHA256": "f" * 64}
        with self.assertRaisesRegex(PolicyError, "overrides trust"):
            self.check()

    def test_prior_environment_mutation_cannot_supply_the_ca_identity(self):
        mutation = {"run": 'printf "COMPOSER_CAFILE=/tmp/unverified.pem\\nDW_CI_CA_SHA256=fake\\n" >> "$GITHUB_ENV"'}
        self.guard["with"]["ca-file"] = "${{ env.COMPOSER_CAFILE }}"
        self.guard["with"]["ca-sha256"] = "${{ env.DW_CI_CA_SHA256 }}"
        with self.assertRaises(PolicyError):
            self.check([mutation, self.guard, self.build])

    def test_missing_conditional_ignored_and_unreviewed_bootstraps_refuse(self):
        for mutation in ({"id": "different"}, {"if": "false"}, {"continue-on-error": True},
                         {"uses": PREFIX + "bootstrap-patched-pip@" + "b" * 40}):
            self.bootstrap.update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(PolicyError):
                self.check()
            self.bootstrap = {"uses": PREFIX + "bootstrap-patched-pip@" + REVISION, "id": "clean-bootstrap"}

    def test_no_extra_compose_direct_buildx_bake_action_or_helper_build_is_invisible(self):
        commands = ["docker compose build", "docker compose up --build", "docker-compose build", "docker build server",
                    "docker --context fixture build server", "docker buildx build server", "docker buildx bake",
                    "/usr/bin/docker compose -f alternate.yml build"]
        for command in commands:
            with self.subTest(command=command), self.assertRaisesRegex(PolicyError, "additional unguarded"):
                self.check([self.guard, self.build, {"run": command}])
        (self.root / "scripts").mkdir()
        (self.root / "scripts/build.sh").write_text("docker compose build\n")
        with self.assertRaises(PolicyError):
            self.check([self.guard, self.build, {"run": "scripts/build.sh"}])
        with self.assertRaises(PolicyError):
            self.check([self.guard, self.build, {"uses": "docker/build-push-action@" + REVISION}])


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

    def test_adopted_sample_app_cannot_remove_every_composer_guard(self):
        policy = json.loads((Path(__file__).resolve().parents[1] / "qualification/policy.json").read_text())
        source = yaml.safe_dump({"jobs": {"test": {"steps": [{"run": "composer install"}]}}})
        with self.assertRaisesRegex(PolicyError, "clean bootstrap and live verifier"):
            verify_composer_network_sinks(policy, "sample-app", {"ci.yml": source}, self.root)

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

class BoundPhpComposerContractTest(ComposerNetworkContractTest):
    def setUp(self):
        super().setUp()
        self.policy["action_runtime"]["allowed_releases"]["durable-workflow/.github"][BOUND_REVISION] = "bound-linux-php"
        self.steps[0]["with"]["clients"] = "python,composer,curl,git"
        self.steps[1] = {
            "uses": PREFIX + "setup-php-linux@" + BOUND_REVISION,
            "with": {"php-version": "8.3", "tools": "composer:2.10.3,phpunit:11.5.57", "coverage": "none"},
        }

    def test_only_the_literal_qualified_inputs_authorize_the_live_guard(self):
        mutations = {
            "php-version": ("8.2", "8.4", "${{ matrix.php }}"),
            "tools": ("composer", "composer:2.10.3", "composer:2.10.4,phpunit:11.5.57", "${{ inputs.tools }}"),
            "coverage": ("", "xdebug", "pcov", "${{ inputs.coverage }}"),
            "ini-file": ("development", ""),
            "extensions": ("redis", "xdebug"),
            "ini-values": ("memory_limit=-1",),
            "fail-fast": ("true", "false"),
            "unknown": ("input",),
        }
        for name, values in mutations.items():
            for value in values:
                steps = deepcopy(self.steps)
                steps[1]["with"][name] = value
                with self.subTest(name=name, value=value), self.assertRaises(PolicyError):
                    self.check(steps)
        for name in ("php-version", "tools", "coverage"):
            steps = deepcopy(self.steps)
            del steps[1]["with"][name]
            with self.subTest(missing=name), self.assertRaises(PolicyError):
                self.check(steps)

    def test_explicit_production_and_empty_overrides_preserve_the_same_profile(self):
        self.steps[1]["with"].update({"ini-file": "production", "extensions": "", "ini-values": ""})
        self.assertEqual(["ci.yml:test:step-4"], self.check())

    def test_a_literal_yaml_number_has_the_same_actions_input_value(self):
        self.steps[1]["with"]["php-version"] = 8.3
        self.assertEqual(["ci.yml:test:step-4"], self.check())

    def test_the_bound_setup_also_requires_the_python_trust_client(self):
        self.steps[0]["with"]["clients"] = "composer,curl,git"
        with self.assertRaises(PolicyError):
            self.check()

    def test_a_setup_pin_cannot_supply_the_bootstrap_or_verifier_role(self):
        for index in (0, 2):
            steps = deepcopy(self.steps)
            steps[index]["uses"] = steps[index]["uses"].replace(REVISION, BOUND_REVISION)
            with self.subTest(index=index), self.assertRaises(PolicyError):
                self.check(steps)

    def test_an_unregistered_setup_or_another_action_at_that_pin_refuses(self):
        for reference in (REVISION, "0" * 40, "main"):
            steps = deepcopy(self.steps)
            steps[1]["uses"] = PREFIX + "setup-php-linux@" + reference
            with self.subTest(reference=reference), self.assertRaises(PolicyError):
                self.check(steps)
        steps = deepcopy(self.steps)
        steps[1]["uses"] = PREFIX + "verify-composer-trust@" + BOUND_REVISION
        with self.assertRaises(PolicyError):
            self.check(steps)


class ComposerRuntimeSetupContractTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.policy = {
            "targets": {"fixture": {"composer_trust_required": True}},
            "action_runtime": {"allowed_releases": {"durable-workflow/.github": {REVISION: "clean-trust"}}},
        }
        files = {}
        for name, contents, mode in (
            ("scripts/setup.sh", "#!/bin/bash\nln -sf scripts/launch.sh runtime/composer\n", 0o755),
            ("scripts/launch.sh", "#!/bin/bash\nexec docker run sha256:fixture composer \"$@\"\n", 0o755),
            ("docker/php/Dockerfile", "FROM php@sha256:fixture\n", 0o644),
        ):
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents)
            path.chmod(mode)
            files[name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "mode": mode}
        self.command = 'bash "$GITHUB_WORKSPACE/scripts/setup.sh" "8.4"'
        self.recipe = {"target": "fixture", "workflows": {"ci.yml": ["test"]}, "commands": [self.command],
                       "environment": ["FIXTURE_PHP_IMAGE"], "files": files}
        self.catalog = {"requests": {}, "runtime_setups": {"fixture-php": self.recipe}}
        patched = mock.patch("scripts.qualification_policy._composer_container_catalog", return_value=self.catalog)
        patched.start()
        self.addCleanup(patched.stop)
        self.steps = [
            {"uses": PREFIX + "bootstrap-patched-pip@" + REVISION, "with": {"clients": "python,composer,curl,git"}},
            {"run": self.command},
            {"uses": PREFIX + "verify-composer-trust@" + REVISION},
            {"run": "composer install --prefer-dist"},
        ]

    def check(self, steps=None, *, target="fixture", filename="ci.yml", job="test", env=None, job_env=None, matrix=None):
        document = {"jobs": {job: {"steps": self.steps if steps is None else steps}}}
        if env is not None:
            document["env"] = env
        if job_env is not None:
            document["jobs"][job]["env"] = job_env
        if matrix is not None:
            document["jobs"][job]["strategy"] = {"matrix": matrix}
        policy = deepcopy(self.policy)
        policy["targets"][target] = policy["targets"]["fixture"]
        return verify_composer_network_sinks(policy, target, {filename: yaml.safe_dump(document)}, self.root)

    def test_exact_runtime_setup_still_needs_a_fresh_live_verifier(self):
        self.assertEqual(["ci.yml:test:step-4"], self.check())
        with self.assertRaises(PolicyError):
            self.check([*self.steps[:2], self.steps[-1]])
        with self.assertRaises(PolicyError):
            self.check([*self.steps[:3], {"run": "pwd"}, self.steps[-1]])

    def test_setup_does_not_supply_bootstrap_or_request_authority(self):
        for removed in (0, 1, 2):
            steps = deepcopy(self.steps)
            steps.pop(removed)
            with self.subTest(removed=removed), self.assertRaises(PolicyError):
                self.check(steps)
        for index in (0, 2):
            steps = deepcopy(self.steps)
            steps[index]["uses"] = steps[index]["uses"].replace(REVISION, "b" * 40)
            with self.subTest(index=index), self.assertRaises(PolicyError):
                self.check(steps)

    def test_recipe_is_confined_to_the_registered_target_workflow_and_job(self):
        for change in ({"target": "another"}, {"filename": "release.yml"}, {"job": "publish"}):
            with self.subTest(change=change), self.assertRaises(PolicyError):
                self.check(**change)

    def test_changed_missing_nonregular_and_mode_changed_inputs_refuse(self):
        for name in self.recipe["files"]:
            path = self.root / name
            contents, mode = path.read_bytes(), path.stat().st_mode & 0o777
            for change in ("bytes", "missing", "symlink", "mode"):
                if change == "bytes":
                    path.write_bytes(contents + b"\n# changed\n")
                elif change == "missing":
                    path.unlink()
                elif change == "symlink":
                    path.unlink()
                    path.symlink_to(self.root / "absent")
                else:
                    path.chmod(mode ^ 0o100)
                with self.subTest(name=name, change=change), self.assertRaises(PolicyError):
                    self.check()
                path.unlink(missing_ok=True)
                path.write_bytes(contents)
                path.chmod(mode)

    def test_conditional_ignored_or_overridden_runtime_setups_refuse(self):
        for field, value in (("if", "always()"), ("continue-on-error", True), ("env", {"ANY": "value"}),
                             ("working-directory", "another"), ("shell", "sh")):
            steps = deepcopy(self.steps)
            steps[1][field] = value
            with self.subTest(field=field), self.assertRaises(PolicyError):
                self.check(steps)
        steps = deepcopy(self.steps)
        steps[1]["run"] += "\ncomposer install"
        with self.assertRaises(PolicyError):
            self.check(steps)

    def test_runtime_selector_overrides_and_mutations_cannot_follow_setup(self):
        for index in (2, 3):
            steps = deepcopy(self.steps)
            steps[index]["env"] = {"FIXTURE_PHP_IMAGE": "unreviewed"}
            with self.subTest(index=index), self.assertRaises(PolicyError):
                self.check(steps)
        for command in ("export FIXTURE_PHP_IMAGE=unreviewed", "unset FIXTURE_PHP_IMAGE"):
            with self.subTest(command=command), self.assertRaises(PolicyError):
                self.check([*self.steps[:2], {"run": command}, *self.steps[2:]])
        for kwargs in ({"env": {"FIXTURE_PHP_IMAGE": "unreviewed"}},
                       {"job_env": {"FIXTURE_PHP_IMAGE": "unreviewed"}}):
            with self.subTest(kwargs=kwargs), self.assertRaises(PolicyError):
                self.check(**kwargs)

    def test_runtime_setup_requires_the_python_and_composer_trust_clients(self):
        for clients in ("composer,curl,git", "python,curl,git", "python,composer"):
            steps = deepcopy(self.steps)
            steps[0]["with"]["clients"] = clients
            with self.subTest(clients=clients), self.assertRaises(PolicyError):
                self.check(steps)

    def test_empty_or_escaping_source_recipes_refuse(self):
        original = self.recipe["files"]
        for files in ({}, {"../outside": next(iter(original.values()))},
                      {"/absolute": next(iter(original.values()))}):
            self.recipe["files"] = files
            with self.subTest(files=files), self.assertRaises(PolicyError):
                self.check()
        self.recipe["files"] = original

    def test_an_unreviewed_dockerfile_exclusion_file_refuses(self):
        self.recipe["absent_files"] = ["docker/php/Dockerfile.dockerignore"]
        self.assertEqual(["ci.yml:test:step-4"], self.check())
        (self.root / "docker/php/Dockerfile.dockerignore").write_text("*\n")
        with self.assertRaises(PolicyError):
            self.check()

    def test_interpolated_matrix_values_are_closed_to_the_reviewed_minors(self):
        command = self.command.replace('"8.4"', '"${{ matrix.php }}"')
        self.recipe["commands"] = [command]
        self.recipe["matrix"] = {"php": ["8.4", "8.5"]}
        self.steps[1]["run"] = command
        self.assertEqual(["ci.yml:test:step-4"], self.check(matrix={"php": ["8.4", "8.5"]}))
        for matrix in ({}, {"php": ["8.4"]}, {"php": ["8.4", "8.6"]},
                       {"php": ["8.4", '8.5"; composer install; #']},
                       {"php": ["8.4", "8.5"], "include": [{"php": "8.6"}]},
                       {"php": ["8.4", "8.5"], "exclude": [{"php": "8.5"}]}):
            with self.subTest(matrix=matrix), self.assertRaises(PolicyError):
                self.check(matrix=matrix)

    def test_ambiguous_recipes_do_not_authorize_a_runtime(self):
        self.catalog["runtime_setups"]["duplicate"] = deepcopy(self.recipe)
        with self.assertRaisesRegex(PolicyError, "ambiguous"):
            self.check()

    def test_sdk_unit_matrix_cannot_borrow_the_fixed_carbon_runtime_command(self):
        repository = Path(__file__).resolve().parents[1]
        catalog = json.loads((repository / "qualification/composer-container-trust.json").read_text())
        # This fixture is the two actual proposed SDK runtime jobs. File identity
        # has separate controls; this regression exercises only job/command scope.
        catalog["requests"] = {}
        document = yaml.safe_load((repository / "tests/fixtures/sdk-php-unit-runtime.yml").read_text())
        policy = json.loads((repository / "qualification/policy.json").read_text())

        def validate(candidate, recipes):
            with (mock.patch("scripts.qualification_policy._composer_container_catalog", return_value=recipes),
                  mock.patch("scripts.qualification_policy._require_composer_runtime_sources")):
                return verify_composer_network_sinks(policy, "sdk-php", {"ci.yml": yaml.safe_dump(candidate)}, self.root)

        self.assertTrue(validate(document, catalog))
        changed = deepcopy(document)
        setup = next(step for step in changed["jobs"]["test"]["steps"]
                     if "setup-php-container.sh" in step.get("run", ""))
        setup["run"] = catalog["runtime_setups"]["sdk-php-carbon-ci"]["commands"][0]
        predecessor = deepcopy(catalog)
        unit = predecessor["runtime_setups"]["sdk-php-unit-ci"]
        carbon = predecessor["runtime_setups"].pop("sdk-php-carbon-ci")
        unit["workflows"]["ci.yml"].append("carbon-2")
        unit["commands"].extend(carbon["commands"])
        self.assertTrue(validate(changed, predecessor), "The predecessor accepted the wrong runtime in the unit job.")
        with self.assertRaises(PolicyError):
            validate(changed, catalog)
        changed["jobs"]["test"]["strategy"]["matrix"]["php"] = ["8.2", "8.4"]
        self.assertTrue(validate(changed, predecessor), "The predecessor also lost the represented PHP8.1 cell.")
        with self.assertRaises(PolicyError):
            validate(changed, catalog)
        changed = deepcopy(document)
        changed["jobs"]["test"]["strategy"]["matrix"]["php"] = ["8.2", "8.4"]
        with self.assertRaises(PolicyError):
            validate(changed, catalog)

    def test_a_symlinked_build_input_directory_refuses_even_when_bytes_match(self):
        original = self.root / "docker/php"
        moved = self.root / "actual-build-input"
        original.rename(moved)
        original.symlink_to(moved, target_is_directory=True)
        with self.assertRaisesRegex(PolicyError, "symlinks"):
            self.check()

    def test_git_executability_is_portable_across_private_checkout_umasks(self):
        self.assertEqual(["ci.yml:test:step-4"], self.check())
        for name, expected in self.recipe["files"].items():
            (self.root / name).chmod(expected["mode"] & 0o700)
        self.assertEqual(["ci.yml:test:step-4"], self.check())

    def test_writable_and_special_permission_bits_refuse(self):
        path = self.root / "scripts/launch.sh"
        for mode in (0o777, 0o775, 0o4755, 0o2755, 0o1755):
            path.chmod(mode)
            with self.subTest(mode=mode), self.assertRaises(PolicyError):
                self.check()


class ScopedComposerMigrationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.scope = {"workflow": "release.yml", "job": "published", "required": False}
        self.policy = {
            "targets": {"fixture": {"composer_trust_scopes": [self.scope]}},
            "action_runtime": {"allowed_releases": {"durable-workflow/.github": {
                REVISION: "clean-trust", BOUND_REVISION: "bound-linux-php"}}},
        }
        self.steps = [
            {"uses": PREFIX + "bootstrap-patched-pip@" + REVISION, "with": {"clients": "python,composer,curl,git"}},
            {"uses": PREFIX + "setup-php-linux@" + BOUND_REVISION,
             "with": {"php-version": "8.3", "tools": "composer:2.10.3,phpunit:11.5.57", "coverage": "none"}},
            {"uses": PREFIX + "verify-composer-trust@" + REVISION},
            {"run": "composer install --prefer-dist"},
        ]
        self.legacy = {"steps": [{"run": "composer require legacy/package"}]}

    def sources(self, steps=None):
        return {".github/workflows/release.yml": yaml.safe_dump({"jobs": {
            "published": {"runs-on": "ubuntu-24.04", "steps": self.steps if steps is None else steps},
            "legacy": self.legacy,
        }})}

    def check(self, sources=None):
        return verify_composer_network_sinks(self.policy, "fixture", self.sources() if sources is None else sources, self.root)

    def test_only_the_registered_migrating_job_is_enumerated(self):
        original = deepcopy(self.legacy)
        self.assertEqual([".github/workflows/release.yml:published:step-4"], self.check())
        self.assertEqual(original, self.legacy)

    def test_scope_never_reduces_existing_whole_target_enforcement(self):
        self.policy["targets"]["fixture"]["composer_trust_required"] = True
        with self.assertRaisesRegex(PolicyError, "legacy"):
            self.check()

    def test_verifier_outside_the_selected_scope_preserves_whole_target_checks(self):
        self.legacy["steps"].insert(0, self.steps[2])
        with self.assertRaisesRegex(PolicyError, "legacy"):
            self.check()

    def test_removing_or_ignoring_a_guard_still_refuses_the_selected_requests(self):
        for index in (0, 1, 2):
            for field, value in (("if", "false"), ("continue-on-error", True)):
                steps = deepcopy(self.steps)
                steps[index][field] = value
                sources = self.sources(steps)
                with self.subTest(index=index, field=field), self.assertRaises(PolicyError):
                    self.check(sources)
        sources = self.sources([*self.steps[:2], self.steps[3]])
        with self.assertRaises(PolicyError):
            self.check(sources)

    def test_omitted_optional_scope_leaves_unmigrated_source_unqualified(self):
        self.assertEqual([], self.check({}))
        self.assertEqual([], self.check(self.sources(self.legacy["steps"])))

    def test_tightened_scope_requires_workflow_job_and_exact_bound_setup(self):
        self.scope["required"] = True
        missing = ({}, {"release.yml": "jobs: {}"}, self.sources(self.legacy["steps"]))
        for sources in missing:
            with self.subTest(sources=sources), self.assertRaises(PolicyError):
                self.check(sources)
        steps = deepcopy(self.steps)
        steps[1]["uses"] = PREFIX + "setup-php-linux@" + "e" * 40
        sources = self.sources(steps)
        with self.assertRaises(PolicyError):
            self.check(sources)

    def test_duplicate_workflow_identities_cannot_select_a_different_source(self):
        sources = self.sources()
        sources["release.yml"] = sources[".github/workflows/release.yml"]
        with self.assertRaisesRegex(PolicyError, "ambiguous"):
            self.check(sources)

    def test_a_selected_scope_cannot_hide_all_product_requests(self):
        sources = self.sources(self.steps[:3])
        with self.assertRaisesRegex(PolicyError, "no enumerated"):
            self.check(sources)

    def test_workflow_and_step_trust_overrides_still_refuse(self):
        sources = self.sources()
        document = yaml.safe_load(sources[".github/workflows/release.yml"])
        document["env"] = {"COMPOSER_CAFILE": "/unverified"}
        sources = {"release.yml": yaml.safe_dump(document)}
        with self.assertRaises(PolicyError):
            self.check(sources)
        steps = deepcopy(self.steps)
        steps[-1]["env"] = {"COMPOSER_HOME": "/unverified"}
        sources = self.sources(steps)
        with self.assertRaises(PolicyError):
            self.check(sources)

    def test_no_registered_scope_keeps_the_prior_all_job_verifier_rule(self):
        del self.policy["targets"]["fixture"]["composer_trust_scopes"]
        with self.assertRaisesRegex(PolicyError, "legacy"):
            self.check()



if __name__ == "__main__":
    unittest.main()
