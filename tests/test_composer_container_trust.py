from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import composer_container_trust as container_trust
from scripts.composer_container_trust import ContainerTrustRefused, prepare, provenance_destination, sha256, verify_compose_configuration


IMAGE = "composer:2.10.3@sha256:" + "a" * 64


class ComposerContainerSourceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.git("init", "--quiet")
        self.git("config", "user.name", "Fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("remote", "add", "origin", "https://github.com/durable-workflow/server.git")
        self.dockerfile = f"FROM {IMAGE} AS composer\nFROM php:fixture AS production\n"
        (self.source / "Dockerfile").write_text(self.dockerfile)
        (self.source / "prepare.php").write_text("<?php // reviewed preparation\n")
        (self.source / ".dockerignore").write_text(".git\n")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "fixture")
        self.commit = self.git("rev-parse", "HEAD")
        self.bundle = self.root / "ca.pem"
        self.bundle.write_bytes(b"authenticated bundle fixture")
        self.verifier = self.root / "verifier"
        self.verifier.mkdir()
        (self.verifier / "verify.php").write_text("<?php // trusted verifier fixture\n")
        self.environment = {
            "DW_CI_CA_SHA256": sha256(self.bundle.read_bytes()),
            "COMPOSER_CAFILE": str(self.bundle),
        }
        self.catalog = {
            "schema": "durable-workflow.composer-container-trust.v1",
            "requests": {"fixture": {
                "repository": "durable-workflow/server", "dockerfile": "Dockerfile",
                "stage": "production", "approved_recipes": [{
                    "files": {name: sha256((self.source / name).read_bytes())
                              for name in ("Dockerfile", "prepare.php", ".dockerignore")},
                    "composer_image": IMAGE, "composer_stage": "composer",
                }],
            }},
        }

    def git(self, *arguments):
        return subprocess.check_output(
            ["git", "-C", str(self.source), *arguments], stderr=subprocess.PIPE,
        ).decode().strip()

    def check(self, **overrides):
        arguments = {
            "source": self.source, "commit": self.commit, "request_id": "fixture",
            "catalog": self.catalog, "environment": self.environment,
            "verifier_directory": self.verifier,
        }
        arguments.update(overrides)
        return prepare(**arguments)

    def test_actual_checkout_and_bundle_produce_bounded_identity_without_credentials(self):
        outputs, evidence = self.check()
        self.assertEqual(self.commit, outputs["source-commit"])
        self.assertEqual(sha256(self.dockerfile.encode()), outputs["dockerfile-sha256"])
        self.assertEqual(self.environment["DW_CI_CA_SHA256"], outputs["ca-sha256"])
        self.assertEqual("durable-workflow/server", evidence["source_repository"])
        self.assertEqual(3, len(evidence["recipe_files"]))
        self.assertNotIn("environment", evidence)
        self.assertNotIn(str(self.root), str(evidence))

    def test_checkout_identity_cannot_be_replaced_by_a_claimed_commit_or_repository(self):
        for commit in ("main", "b" * 40, self.commit.upper()):
            with self.subTest(commit=commit), self.assertRaises(ContainerTrustRefused):
                self.check(commit=commit)
        self.git("remote", "set-url", "origin", "https://github.com/another/server.git")
        with self.assertRaisesRegex(ContainerTrustRefused, "different source repository"):
            self.check()

    def test_subdirectory_and_non_github_origin_cannot_claim_the_source(self):
        subdirectory = self.source / "subdirectory"
        subdirectory.mkdir()
        with self.assertRaises(ContainerTrustRefused):
            self.check(source=subdirectory)
        self.git("remote", "set-url", "origin", "https://example.invalid/server.git")
        with self.assertRaises(ContainerTrustRefused):
            self.check()

    def test_dirty_recipe_and_unreviewed_new_commit_fail_before_a_build(self):
        (self.source / "Dockerfile").write_text(self.dockerfile + "RUN composer update\n")
        with self.assertRaisesRegex(ContainerTrustRefused, "actual build context"):
            self.check()
        self.git("add", "Dockerfile")
        self.git("commit", "--quiet", "-m", "new unreviewed recipe")
        self.commit = self.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(ContainerTrustRefused, "no uniquely approved"):
            self.check()

    def test_other_pinned_recipe_files_cannot_change_under_the_same_dockerfile(self):
        (self.source / "prepare.php").write_text("<?php // changed preparation\n")
        self.git("add", "prepare.php")
        self.git("commit", "--quiet", "-m", "changed preparation")
        self.commit = self.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(ContainerTrustRefused, "reviewed recipe files"):
            self.check()

    def test_unrelated_product_source_can_advance_without_changing_the_recipe(self):
        (self.source / "runtime.txt").write_text("new product source\n")
        self.git("add", "runtime.txt")
        self.git("commit", "--quiet", "-m", "product source")
        self.commit = self.git("rev-parse", "HEAD")
        self.assertEqual(self.commit, self.check()[1]["source_commit"])

    def test_a_successor_recipe_binds_its_added_executed_helper(self):
        helper = self.source / "docker/apt/require-fixed-apt.sh"
        helper.parent.mkdir(parents=True)
        helper.write_text("#!/bin/sh\nexit 0\n")
        self.dockerfile += "COPY docker/apt/require-fixed-apt.sh /fixed-apt.sh\nRUN sh /fixed-apt.sh\n"
        (self.source / "Dockerfile").write_text(self.dockerfile)
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "successor with fixed APT prerequisite")
        self.commit = self.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(ContainerTrustRefused, "no uniquely approved"):
            self.check()

        successor = deepcopy(self.catalog["requests"]["fixture"]["approved_recipes"][0])
        successor["files"]["Dockerfile"] = sha256(self.dockerfile.encode())
        successor["files"]["docker/apt/require-fixed-apt.sh"] = sha256(helper.read_bytes())
        self.catalog["requests"]["fixture"]["approved_recipes"].append(successor)
        self.assertEqual(self.commit, self.check()[1]["source_commit"])

        helper.write_text("#!/bin/sh\nexit 1\n")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "changed helper without recipe review")
        self.commit = self.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(ContainerTrustRefused, "reviewed recipe files"):
            self.check()

        self.git("rm", "docker/apt/require-fixed-apt.sh")
        self.git("commit", "--quiet", "-m", "missing helper")
        self.commit = self.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(ContainerTrustRefused, "required recipe file is missing"):
            self.check()

    def test_a_new_dockerfile_specific_context_policy_requires_recipe_review(self):
        (self.source / "Dockerfile.dockerignore").write_text("# Changes the actual Docker context\n")
        self.git("add", "Dockerfile.dockerignore")
        self.git("commit", "--quiet", "-m", "new context policy")
        self.commit = self.git("rev-parse", "HEAD")
        with self.assertRaisesRegex(ContainerTrustRefused, "context exclusion"):
            self.check()

    def test_missing_unknown_duplicate_and_malformed_recipe_catalogs_refuse(self):
        for recipes in ([], [{"files": {}}], [None], "not a list"):
            catalog = deepcopy(self.catalog)
            catalog["requests"]["fixture"]["approved_recipes"] = recipes
            with self.subTest(recipes=recipes), self.assertRaises(ContainerTrustRefused):
                self.check(catalog=catalog)
        catalog = deepcopy(self.catalog)
        catalog["requests"]["fixture"]["approved_recipes"] *= 2
        with self.assertRaises(ContainerTrustRefused):
            self.check(catalog=catalog)
        with self.assertRaises(ContainerTrustRefused):
            self.check(request_id="unregistered")

    def test_stage_and_composer_image_metadata_cannot_disagree_with_recipe(self):
        for field, value in (("composer_stage", "different"), ("composer_image", "composer:latest"),
                             ("composer_image", "composer@sha256:" + "b" * 64)):
            catalog = deepcopy(self.catalog)
            catalog["requests"]["fixture"]["approved_recipes"][0][field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ContainerTrustRefused):
                self.check(catalog=catalog)

    def test_bundle_selection_and_authenticated_digest_are_both_required(self):
        for environment in ({}, {**self.environment, "DW_CI_CA_SHA256": "b" * 64},
                            {**self.environment, "DW_CI_CA_SHA256": "not a digest"}):
            with self.subTest(environment=environment), self.assertRaises(ContainerTrustRefused):
                self.check(environment=environment)
        self.bundle.write_bytes(b"changed CA bytes")
        with self.assertRaisesRegex(ContainerTrustRefused, "authenticated bootstrap"):
            self.check()

    def test_symlinked_recipe_and_missing_verifier_are_refused(self):
        dockerfile = self.source / "Dockerfile"
        dockerfile.unlink()
        dockerfile.symlink_to(self.source / "prepare.php")
        with self.assertRaises(ContainerTrustRefused):
            self.check()
        dockerfile.unlink()
        dockerfile.write_text(self.dockerfile)
        (self.verifier / "verify.php").unlink()
        with self.assertRaises(ContainerTrustRefused):
            self.check()

    def test_output_paths_cannot_inject_github_output_fields(self):
        bundle = self.root / "ca\nother-output=value.pem"
        bundle.write_bytes(self.bundle.read_bytes())
        with self.assertRaises(ContainerTrustRefused):
            self.check(environment={**self.environment, "COMPOSER_CAFILE": str(bundle)})

    def test_selected_ca_symlink_cannot_supply_staged_bytes(self):
        linked = self.root / "linked-ca.pem"
        linked.symlink_to(self.bundle)
        with self.assertRaisesRegex(ContainerTrustRefused, "symbolic link"):
            self.check(environment=self.environment | {"COMPOSER_CAFILE": str(linked)})

    def test_ca_staging_preserves_exact_authority_in_private_compose_state(self):
        outputs, _ = self.check()
        summary = container_trust.stage_compose_ca(outputs, self.root, self.source)
        selected = Path(outputs["ca-file"])
        self.assertEqual(self.bundle.read_bytes(), selected.read_bytes())
        self.assertEqual(self.root, selected.parent.parent)
        self.assertEqual(0o700, selected.parent.stat().st_mode & 0o777)
        self.assertEqual(0o400, selected.stat().st_mode & 0o777)
        self.assertEqual({"sha256": self.environment["DW_CI_CA_SHA256"], "size": self.bundle.stat().st_size,
                          "mode": 0o400}, summary)
        container_trust.cleanup_compose_ca(selected, self.root, outputs["ca-sha256"])
        self.assertFalse(selected.parent.exists())
        self.assertTrue(self.bundle.exists(), "The bootstrap's selected original is never removed.")

    def test_ca_changed_or_hardlinked_before_staging_refuses_without_copy(self):
        for mutation in ("changed", "hardlinked"):
            outputs, _ = self.check()
            if mutation == "changed":
                original = self.bundle.read_bytes()
                self.bundle.write_bytes(b"changed bytes")
            else:
                os.link(self.bundle, self.root / "ca-alias")
            with self.subTest(mutation=mutation), self.assertRaises(ContainerTrustRefused):
                container_trust.stage_compose_ca(outputs, self.root, self.source)
            self.assertEqual([], list(self.root.glob(".dw-composer-ca-*")))
            if mutation == "changed":
                self.bundle.write_bytes(original)

    def test_staged_ca_cleanup_refuses_other_files_and_changed_state(self):
        outputs, _ = self.check()
        with self.assertRaises(ContainerTrustRefused):
            container_trust.cleanup_compose_ca(self.bundle, self.root, outputs["ca-sha256"])
        container_trust.stage_compose_ca(outputs, self.root, self.source)
        selected = Path(outputs["ca-file"])
        selected.chmod(0o600)
        selected.write_bytes(b"changed copy")
        with self.assertRaises(ContainerTrustRefused):
            container_trust.cleanup_compose_ca(selected, self.root, outputs["ca-sha256"])
        self.assertTrue(selected.exists())
        selected.write_bytes(self.bundle.read_bytes())
        selected.chmod(0o400)
        extra = selected.parent / "unrelated"
        extra.write_text("preserve this file")
        with self.assertRaises(ContainerTrustRefused):
            container_trust.cleanup_compose_ca(selected, self.root, outputs["ca-sha256"])
        self.assertTrue(extra.exists())

    def test_ca_copy_cannot_enter_source_or_verifier_context_or_follow_a_directory_link(self):
        outputs, _ = self.check()
        for directory in (self.source, self.verifier):
            with self.subTest(directory=directory), self.assertRaises(ContainerTrustRefused):
                container_trust.stage_compose_ca(outputs.copy(), directory, self.source)
            self.assertEqual([], list(directory.glob(".dw-composer-ca-*")))
        linked = self.root / "linked-compose"
        linked.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(ContainerTrustRefused):
            container_trust.stage_compose_ca(outputs.copy(), linked, self.source)

    def test_nonregular_ca_source_refuses_without_blocking(self):
        fifo = self.root / "ca-fifo"
        os.mkfifo(fifo)
        with self.assertRaises(ContainerTrustRefused):
            container_trust.regular_ca_bytes(fifo, self.environment["DW_CI_CA_SHA256"])

    def test_actual_context_rejects_tracked_staged_untracked_and_ignored_bytes(self):
        runtime = self.source / "runtime.php"
        runtime.write_text("<?php // selected source\n")
        (self.source / ".gitignore").write_text("ignored/\n")
        self.git("add", ".")
        self.git("commit", "--quiet", "-m", "runtime")
        self.commit = self.git("rev-parse", "HEAD")
        for staged in (False, True):
            runtime.write_text("<?php // changed source\n")
            if staged:
                self.git("add", "runtime.php")
            with self.subTest(staged=staged), self.assertRaises(ContainerTrustRefused):
                self.check()
            self.git("restore", "--source=HEAD", "--staged", "--worktree", "runtime.php")
        for name in ("new.php", "ignored/new.php"):
            extra = self.source / name
            extra.parent.mkdir(exist_ok=True)
            extra.write_text("<?php // extra build context\n")
            with self.subTest(extra=name), self.assertRaises(ContainerTrustRefused):
                self.check()
            extra.unlink()
            if extra.parent != self.source:
                extra.parent.rmdir()
        self.assertEqual(self.commit, self.check()[1]["source_commit"])

    def test_assume_unchanged_index_flag_cannot_hide_changed_context_bytes(self):
        self.git("update-index", "--assume-unchanged", "prepare.php")
        (self.source / "prepare.php").write_text("<?php // hidden changed bytes\n")
        self.assertEqual("", self.git("status", "--porcelain"))
        with self.assertRaisesRegex(ContainerTrustRefused, "context bytes"):
            self.check()

    def test_provenance_refuses_outside_workspace_and_existing_destinations(self):
        environment = {"GITHUB_WORKSPACE": str(self.root)}
        self.assertEqual(self.root / "new.json", provenance_destination(self.root / "new.json", environment, self.source))
        for path in (self.source / "Dockerfile", self.source / "new.json", self.root.parent / "outside.json", self.bundle):
            with self.subTest(path=path), self.assertRaises(ContainerTrustRefused):
                provenance_destination(path, environment, self.source)
        (self.root / "link").symlink_to(self.root.parent, target_is_directory=True)
        with self.assertRaises(ContainerTrustRefused):
            provenance_destination(self.root / "link/outside.json", environment, self.source)

    def test_cli_records_the_real_binding_and_uses_the_actions_output_environment(self):
        control = self.root / "central"
        (control / "qualification").mkdir(parents=True)
        (control / "qualification/composer-container-trust.json").write_text(json.dumps(self.catalog))
        verifier = control / ".github/actions/verify-composer-trust"
        verifier.mkdir(parents=True)
        (verifier / "verify.php").write_text("<?php // reviewed verifier\n")
        record, output = self.root / "record.json", self.root / "output"
        environment = self.environment | {"GITHUB_WORKSPACE": str(self.root), "GITHUB_OUTPUT": str(output)}
        argv = ["container-trust", "--source-directory", str(self.source), "--source-commit", self.commit,
                "--compose-directory", str(self.root),
                "--request", "fixture", "--provenance", str(record)]
        with (patch.object(container_trust, "ROOT", control), patch.object(sys, "argv", argv),
              patch.dict(os.environ, environment), patch.object(container_trust, "inspect_compose", return_value=["server"])):
            self.assertEqual(0, container_trust.main())
            self.assertEqual(self.commit, json.loads(record.read_text())["source_commit"])
            self.assertIn("source-commit=" + self.commit, output.read_text())
            self.assertEqual(1, container_trust.main(), "A repeat must not clobber provenance.")
        values = dict(line.split("=", 1) for line in output.read_text().splitlines())
        selected = Path(values["ca-file"])
        self.assertEqual(self.root, selected.parent.parent)
        self.assertEqual(self.bundle.read_bytes(), selected.read_bytes())
        cleanup = ["container-trust", "cleanup-ca", "--ca-file", str(selected),
                   "--ca-sha256", values["ca-sha256"], "--compose-directory", str(self.root)]
        with patch.object(sys, "argv", cleanup):
            self.assertEqual(0, container_trust.main())
        self.assertFalse(selected.parent.exists())


class ComposerContainerComposeTest(unittest.TestCase):
    def setUp(self):
        self.source = Path("/fixture/server")
        self.outputs = {"source-commit": "a" * 40, "dockerfile-sha256": "b" * 64,
                        "ca-sha256": "c" * 64, "context-directory": "/fixture/verifier", "ca-file": "/fixture/clean.pem"}
        self.request = {"services": ["bootstrap", "server", "worker", "repair"], "dockerfile": "Dockerfile", "stage": "production"}
        self.build = {
            "context": str(self.source), "dockerfile": "Dockerfile", "target": "production",
            "additional_contexts": {"dwf_composer_trust": self.outputs["context-directory"]},
            "args": {"DW_CI_CA_SHA256": "c" * 64, "DW_SERVER_SOURCE_COMMIT": "a" * 40, "DW_SERVER_DOCKERFILE_SHA256": "b" * 64},
            "secrets": [{"source": "dwf_ci_ca", "target": "dwf_ci_ca"}],
        }
        self.document = {"services": {name: {"build": deepcopy(self.build)} for name in self.request["services"]},
                         "secrets": {"dwf_ci_ca": {"file": self.outputs["ca-file"]}}}

    def check(self, document=None):
        return verify_compose_configuration(self.document if document is None else document, self.source, self.request, self.outputs)

    def test_all_registered_builds_use_the_actual_source_verifier_and_ca_secret(self):
        self.assertEqual(sorted(self.request["services"]), self.check())
        for service in self.document["services"].values():
            if "build" in service:
                service["build"]["secrets"] = [{"source": "dwf_ci_ca"}]
        self.assertEqual(sorted(self.request["services"]), self.check(), "Compose omits the default secret target.")
        self.document["services"]["database"] = {"image": "fixture/database"}
        self.assertEqual(sorted(self.request["services"]), self.check())

    def test_any_missing_or_extra_build_requires_review(self):
        for name in self.request["services"]:
            document = deepcopy(self.document)
            del document["services"][name]["build"]
            with self.subTest(name=name), self.assertRaises(ContainerTrustRefused):
                self.check(document)
        self.document["services"]["new-build"] = {"build": self.build}
        with self.assertRaises(ContainerTrustRefused):
            self.check()

    def test_source_recipe_stage_context_and_secret_cannot_be_substituted(self):
        mutations = {"context": "/other/source", "dockerfile": "another.Dockerfile", "target": "unguarded",
                     "additional_contexts": {}, "secrets": [], "args": {}, "dockerfile_inline": "FROM fixture"}
        for field, value in mutations.items():
            document = deepcopy(self.document)
            document["services"]["worker"]["build"][field] = value
            with self.subTest(field=field), self.assertRaises(ContainerTrustRefused):
                self.check(document)

    def test_top_level_secret_must_be_the_authenticated_file(self):
        for secret in ({"file": "/other/bundle"}, {"environment": "UNVERIFIED_CA"}, {"external": True}, {}):
            document = deepcopy(self.document)
            document["secrets"]["dwf_ci_ca"] = secret
            with self.subTest(secret=secret), self.assertRaises(ContainerTrustRefused):
                self.check(document)

    def test_external_cache_keys_refuse_for_every_registered_service(self):
        # Secrets do not invalidate cached layers, so an imported layer could
        # bypass the request-time verifier. Even empty declarations fail closed.
        for name in self.request["services"]:
            for field in ("cache_from", "cache_to"):
                for value in ([], None, ["type=registry,ref=example.invalid/cache:fixture"]):
                    document = deepcopy(self.document)
                    document["services"][name]["build"][field] = value
                    with self.subTest(service=name, field=field, value=value):
                        with self.assertRaisesRegex(ContainerTrustRefused, "BuildKit caches"):
                            self.check(document)

    def test_renderer_uses_the_same_registered_files_and_verified_environment(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            files = ["base.yml", "trust.yml"]
            for name in files:
                (directory / name).write_text("services: {}\n")
            self.request["compose_files"] = [files]
            result = subprocess.CompletedProcess([], 0, json.dumps(self.document), "")
            with (patch.dict(os.environ, {"COMPOSE_FILE": os.pathsep.join(files)}),
                  patch.object(container_trust.subprocess, "run", return_value=result) as command):
                self.assertEqual(sorted(self.request["services"]), container_trust.inspect_compose(directory, self.source, self.request, self.outputs))
                self.assertEqual(["docker", "compose", "--env-file", "/dev/null", "config", "--format", "json"], command.call_args.args[0])
                self.assertEqual(directory, command.call_args.kwargs["cwd"])
                self.assertEqual(self.outputs["ca-file"], command.call_args.kwargs["env"]["COMPOSER_CAFILE"])
                self.assertEqual(os.pathsep.join(files), self.outputs["compose-file"])

    def test_unknown_files_or_renderer_failures_do_not_expose_configuration(self):
        self.request["compose_files"] = [["base.yml", "trust.yml"]]
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.dict(os.environ, {"COMPOSE_FILE": "https://example.invalid/unreviewed.yml"}):
                with self.assertRaises(ContainerTrustRefused):
                    container_trust.inspect_compose(directory, self.source, self.request, self.outputs)
            for name in self.request["compose_files"][0]:
                (directory / name).write_text("services: {}\n")
            error = subprocess.CalledProcessError(1, ["docker"], output="PRIVATE_FIXTURE_VALUE", stderr="PRIVATE_FIXTURE_VALUE")
            with (patch.dict(os.environ, {"COMPOSE_FILE": "base.yml:trust.yml"}),
                  patch.object(container_trust.subprocess, "run", side_effect=error)):
                with self.assertRaises(ContainerTrustRefused) as refusal:
                    container_trust.inspect_compose(directory, self.source, self.request, self.outputs)
                self.assertNotIn("PRIVATE_FIXTURE_VALUE", str(refusal.exception))


if __name__ == "__main__":
    unittest.main()
