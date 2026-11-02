from copy import deepcopy
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.composer_container_trust import ContainerTrustRefused, prepare, sha256


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
                              for name in ("Dockerfile", "prepare.php")},
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
        self.assertEqual(2, len(evidence["recipe_files"]))
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
        with self.assertRaisesRegex(ContainerTrustRefused, "Recipe bytes"):
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
        with self.assertRaisesRegex(ContainerTrustRefused, "symbolic links"):
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


if __name__ == "__main__":
    unittest.main()
