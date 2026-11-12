"""Inert source controls: no network, PHP setup, sudo or archive extraction."""

import copy
from contextlib import ExitStack, contextmanager
import errno
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.request import Request

from scripts import php_linux_bootstrap as bootstrap
from scripts import php_linux_normalize as normalization
from scripts import php_linux_alternatives as alternatives
from tests import test_php_linux_normalize as normalize_tests


# Inert mirror fixture URL; no request is made.
MIRROR_URL = "https://api.github.com/repos/durable-workflow/.github/releases/assets/900000001"


class PhpLinuxBootstrapTest(unittest.TestCase):
    def setUp(self):
        self.catalog = json.loads(bootstrap.CATALOG.read_text())
        self.original = (bootstrap.ROOT / "qualification/vendor/php-ubuntu-713206915/install.sh").read_bytes()
        self.row = bootstrap.select(self.catalog, operating_system="ubuntu", release="26.04",
                                    architecture="x86_64", php="8.3")

    def identity(self, name, contents, identifier=123):
        return {"id": identifier, "name": name, "size": len(contents),
                "digest": "sha256:" + bootstrap.sha256(contents)}

    def test_source_installer_is_sealed_without_a_network_request(self):
        with patch.object(bootstrap, "build_opener") as network:
            with bootstrap.hold_source_installer(self.catalog["installer"]) as held:
                held.assert_sealed()
                self.assertEqual(self.original, os.pread(held.descriptor, len(self.original), 0))
                self.assertEqual(bootstrap.installer_source_origin(self.catalog["installer"]), held.effective)
                descriptor = held.descriptor
            network.assert_not_called()
        with self.assertRaises(OSError):
            os.fstat(descriptor)

    def test_source_installer_refuses_changed_bytes_links_and_authority(self):
        identity = self.catalog["installer"]
        origin = bootstrap.installer_source_origin(identity)
        for kind in ("changed", "truncated", "link", "identity"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path = root / origin["path"]
                path.parent.mkdir(parents=True)
                path.write_bytes(self.original)
                selected = dict(identity)
                if kind == "changed":
                    path.write_bytes(b"X" + self.original[1:])
                elif kind == "truncated":
                    path.write_bytes(self.original[:-1])
                elif kind == "link":
                    path.rename(path.with_suffix(".original"))
                    path.symlink_to(path.with_suffix(".original"))
                else:
                    selected["id"] += 1
                with patch.object(bootstrap, "ROOT", root):
                    with self.assertRaises((OSError, ValueError)):
                        with bootstrap.hold_source_installer(selected):
                            pass

    def test_source_installer_refuses_a_change_during_sealing(self):
        identity = self.catalog["installer"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / bootstrap.installer_source_origin(identity)["path"]
            path.parent.mkdir(parents=True)
            path.write_bytes(self.original)
            seal = bootstrap.hold_bytes

            @contextmanager
            def changed(source, selected, origin):
                with seal(source, selected, origin) as held:
                    before = path.stat()
                    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000))
                    yield held

            with patch.object(bootstrap, "ROOT", root), patch.object(bootstrap, "hold_bytes", changed):
                with self.assertRaises(ValueError):
                    with bootstrap.hold_source_installer(identity):
                        pass

    def test_effect_uses_the_sealed_original_after_its_path_is_replaced(self):
        catalog = copy.deepcopy(self.catalog)
        row = next(value for value in catalog['archives'] if value == self.row)
        payload = b'inert archive, never extracted'
        row['asset'] = self.identity(row['asset']['name'], payload, row['asset']['id'])
        derived = bootstrap.no_apt_installer_source(self.original, catalog)
        script_id = self.identity('bound-install.sh', derived, catalog['installer']['id'])
        environment = bootstrap.clean_environment({}, '/tmp/inert-source-home')
        host = dict(operating_system='ubuntu', release='26.04', architecture='x86_64')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / bootstrap.installer_source_origin(catalog['installer'])['path']
            path.parent.mkdir(parents=True)
            path.write_bytes(self.original)
            policy = 'qualification/php-linux-initial-alternatives.json'
            (root / policy).write_bytes((bootstrap.ROOT / policy).read_bytes())
            replacement = root / 'replacement'
            replacement.write_bytes(b'changed path; must never be read by the effect verifier')
            calls = []

            def execute(_command, **options):
                calls.append(options)
                self.assertEqual(derived, os.pread(options['pass_fds'][0], len(derived), 0))

            with patch.object(bootstrap, 'ROOT', root), patch.dict(os.environ, environment, clear=True):
                with bootstrap.hold_source_installer(catalog['installer']) as installer, \
                        bootstrap.hold_bytes(io.BytesIO(derived), script_id, {}) as script, \
                        bootstrap.hold_bytes(io.BytesIO(payload), row['asset'], {}) as archive:
                    path.unlink()
                    path.symlink_to(replacement)
                    bootstrap.run_held_installer(script, archive, ('8.3', 'release', 'nts'),
                        environment, catalog, execute, host, no_apt=True, original_installer=installer)
            self.assertEqual(1, len(calls))

    def test_catalog_has_exact_distinct_current_asset_tuples(self):
        self.assertIs(self.catalog, bootstrap.validate_catalog(self.catalog))
        self.assertEqual(30, len(self.catalog["archives"]))
        self.assertEqual(713206915, self.catalog["installer"]["id"])
        for row in self.catalog["archives"]:
            self.assertEqual(row, bootstrap.select(self.catalog, operating_system=row["os"],
                release=row["release"], architecture=row["arch"], php=row["php"]))
            # Until the protected uploader's IDs are recorded, no row is
            # fetchable: the upstream ID is provenance, never a fallback.
            with self.assertRaisesRegex(ValueError, "never a fallback"):
                bootstrap.asset_url(row)

    def mirrored(self, release_id=4242):
        catalog = copy.deepcopy(self.catalog)
        catalog["mirror"] = {"repository": "durable-workflow/.github", "release_id": release_id,
                             "release_tag": "php-linux-archives"}
        for index, row in enumerate(catalog["archives"]):
            row["mirror"] = {"id": 800000000 + index}
        return catalog

    def test_mirror_rows_keep_upstream_identity_and_fetch_only_by_mirror_id(self):
        catalog = self.mirrored()
        with patch.object(bootstrap, "MIRROR_RELEASE_ID", 4242):
            self.assertIs(catalog, bootstrap.validate_catalog(catalog))
            row = bootstrap.select(catalog, operating_system="ubuntu", release="24.04",
                                   architecture="x86_64", php="8.3")
        self.assertEqual(739209532, row["asset"]["id"])
        url = bootstrap.asset_url(row)
        self.assertEqual(f"https://api.github.com/repos/durable-workflow/.github/releases/assets/{row['mirror']['id']}", url)
        self.assertNotIn(str(row["asset"]["id"]), url)
        self.assertNotIn(row["asset"]["name"], url)
        bootstrap.effective_url(url)
        self.assertEqual("{}-php_8.3-nts+ubuntu24.04.tar.zst".format(row["asset"]["digest"][7:]),
                         bootstrap.mirror_name(row["asset"]))

    def test_mirror_catalog_refuses_unpinned_foreign_duplicate_and_malformed_mirrors(self):
        def change(kind, catalog):
            rows = catalog["archives"]
            if kind == "unpinned-release":
                return None
            if kind == "no-authority":
                del catalog["mirror"]
            elif kind == "foreign-repository":
                catalog["mirror"]["repository"] = "shivammathur/php-ubuntu"
            elif kind == "other-release":
                catalog["mirror"]["release_id"] = 4243
            elif kind == "tag":
                catalog["mirror"]["release_tag"] = "builds"
            elif kind == "authority-extra":
                catalog["mirror"]["fallback"] = "https://github.com/shivammathur/php-ubuntu"
            elif kind == "duplicate-mirror":
                rows[1]["mirror"]["id"] = rows[0]["mirror"]["id"]
            elif kind == "upstream-as-mirror":
                rows[1]["mirror"]["id"] = rows[0]["asset"]["id"]
            elif kind == "own-upstream-as-mirror":
                rows[0]["mirror"]["id"] = rows[0]["asset"]["id"]
            elif kind == "zero":
                rows[0]["mirror"]["id"] = 0
            elif kind == "string":
                rows[0]["mirror"]["id"] = str(rows[0]["mirror"]["id"])
            elif kind == "bool":
                rows[0]["mirror"]["id"] = True
            elif kind == "name":
                rows[0]["mirror"]["name"] = "php_8.1-nts+ubuntu22.04_arm64.tar.zst"
            elif kind == "url":
                rows[0]["mirror"] = {"url": "https://github.com/durable-workflow/.github/releases/download/x/y"}
            return catalog

        kinds = ("unpinned-release", "no-authority", "foreign-repository", "other-release", "tag",
                 "authority-extra", "duplicate-mirror", "upstream-as-mirror", "own-upstream-as-mirror",
                 "zero", "string", "bool", "name", "url")
        for kind in kinds:
            candidate = change(kind, self.mirrored())
            release = None if candidate is None else 4242
            candidate = candidate or self.mirrored()
            with self.subTest(kind=kind), patch.object(bootstrap, "MIRROR_RELEASE_ID", release):
                with self.assertRaises(ValueError):
                    bootstrap.validate_catalog(candidate)

    def test_wrong_mirror_ids_fail_closed_on_bytes_and_identity(self):
        with self.assertRaises(ValueError):
            bootstrap.asset_url(dict(self.row, mirror={"id": -1}))
        with self.assertRaises(ValueError):
            bootstrap.asset_url(dict(self.row, mirror={"id": 1, "tag": "php-linux-archives"}))
        data = b"inert mirror payload"
        identity = self.identity("fixture.tar.zst", data)
        for served in (b"other bytes of a wrong mirror asset", data[:-1], data + b"!"):
            with self.subTest(served=served), ExitStack() as stack, self.assertRaises(ValueError):
                stack.enter_context(bootstrap.hold_verified(io.BytesIO(served), identity, MIRROR_URL))

    def test_labels_aliases_versions_and_builds_cannot_select_other_bytes(self):
        base = dict(operating_system="ubuntu", release="26.04", architecture="x86_64", php="8.3")
        self.assertEqual(self.row, bootstrap.select(self.catalog, **dict(base, architecture="amd64")))
        for changes in ({"release": "latest"}, {"release": "26.10"}, {"operating_system": "debian"},
                        {"architecture": "s390x"}, {"php": "latest"}, {"php": "8.3.36"},
                        {"thread_safety": "zts"}, {"build": "debug"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                bootstrap.select(self.catalog, **dict(base, **changes))

    def test_catalog_refuses_duplicate_missing_replaced_and_foreign_assets(self):
        for kind in ("duplicate-tuple", "duplicate-id", "name", "digest", "size", "source", "extra"):
            candidate = copy.deepcopy(self.catalog)
            if kind == "duplicate-tuple":
                candidate["archives"].append(candidate["archives"][0])
            elif kind == "duplicate-id":
                candidate["archives"][1]["asset"]["id"] = candidate["archives"][0]["asset"]["id"]
            elif kind == "source":
                candidate["setup_php_commit"] = "main"
            elif kind == "extra":
                candidate["fallback"] = "https://unreviewed.example/"
            else:
                candidate["archives"][0]["asset"][kind] = {"name": "install.sh", "digest": None, "size": 0}[kind]
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                bootstrap.validate_catalog(candidate)
        candidate = copy.deepcopy(self.catalog)
        candidate["archives"] = [row for row in candidate["archives"] if row != self.row]
        with self.assertRaises(ValueError):
            bootstrap.select(candidate, operating_system="ubuntu", release="26.04", architecture="x86_64", php="8.3")

    def test_redirects_are_closed_and_signed_queries_are_bound_without_disclosure(self):
        url = "https://release-assets.githubusercontent.com/example?signature=inert-fixture"
        result = bootstrap.effective_url(url)
        self.assertEqual("release-assets.githubusercontent.com", result["host"])
        self.assertEqual(bootstrap.sha256(url.encode()), result["url_sha256"])
        self.assertNotIn("signature", json.dumps(result))
        for target in (MIRROR_URL, "https://github.com/durable-workflow/.github/releases/download/php-linux-archives/x"):
            self.assertEqual(bootstrap.urlsplit(target).path, bootstrap.effective_url(target)["path"])
        for target in ("http://github.com/durable-workflow/.github/x", "https://cdn.jsdelivr.net/x",
                       "https://artifacts.php-ubuntu.setup-php.com/x", "https://example.com/x",
                       "https://github.com/foreign/repository/x", "https://api.github.com/repos/foreign/assets/1",
                       "https://user@github.com/durable-workflow/.github/x", "https://github.com:8443/x",
                       "https://uploads.github.com/repos/durable-workflow/.github/releases/1/assets",
                       # The previous upstream authority is replaced, not widened.
                       "https://api.github.com/repos/shivammathur/php-ubuntu/releases/assets/739209532",
                       "https://github.com/shivammathur/php-ubuntu/releases/download/builds/x",
                       # Foreign and look-alike repositories.
                       "https://api.github.com/repos/durable-workflow/workflow/releases/assets/1",
                       "https://api.github.com/repos/durable-workflow/.github-mirror/releases/assets/1",
                       "https://api.github.com/repos/durable-workflow/xgithub/releases/assets/1",
                       "https://api.github.com/repos/Durable-Workflow/.github/releases/assets/1",
                       "https://github.com/durable-workflow/.github-mirror/x",
                       "https://github.com/durable-workflow/xgithub/x",
                       # Tag, name, latest and malformed asset selectors.
                       "https://api.github.com/repos/durable-workflow/.github/releases/tags/php-linux-archives",
                       "https://api.github.com/repos/durable-workflow/.github/releases/latest",
                       "https://api.github.com/repos/durable-workflow/.github/releases/assets/0",
                       "https://api.github.com/repos/durable-workflow/.github/releases/assets/01",
                       "https://api.github.com/repos/durable-workflow/.github/releases/assets/1/x",
                       "https://api.github.com/repos/durable-workflow/.github/releases/assets/php_8.3.tar.zst",
                       "https://api.github.com/repos/durable-workflow/.github/releases/4242/assets"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                bootstrap.effective_url(target)

    def test_receipts_must_show_the_mirror_repository(self):
        for url in (MIRROR_URL, "https://github.com/durable-workflow/.github/releases/download/php-linux-archives/x",
                    "https://release-assets.githubusercontent.com/github-production-release-asset/575230056/uuid?sig=x"):
            with self.subTest(url=url):
                bootstrap.require_mirror_effective(bootstrap.effective_url(url))
        upstream = "https://api.github.com/repos/shivammathur/php-ubuntu/releases/assets/739209532"
        foreign = dict(bootstrap.effective_url(MIRROR_URL), path=bootstrap.urlsplit(upstream).path)
        for effective in (bootstrap.effective_url("https://release-assets.githubusercontent.com/github-production-release-asset/281550370/uuid"),
                          bootstrap.effective_url("https://release-assets.githubusercontent.com/example"),
                          foreign, dict(bootstrap.effective_url(MIRROR_URL), scheme="http"),
                          dict(bootstrap.effective_url(MIRROR_URL), extra=True)):
            with self.subTest(effective=effective), self.assertRaises(ValueError):
                bootstrap.require_mirror_effective(effective)

    def test_redirect_handler_refuses_before_requesting_a_fallback_authority(self):
        request = Request(MIRROR_URL)
        handler = bootstrap.ClosedRedirects()
        with self.assertRaises(ValueError):
            handler.redirect_request(request, None, 302, "redirect", {}, "https://cdn.jsdelivr.net/foreign")
        allowed = handler.redirect_request(request, None, 302, "redirect", {},
                                           "https://release-assets.githubusercontent.com/held?signature=inert")
        self.assertEqual("release-assets.githubusercontent.com", bootstrap.urlsplit(allowed.full_url).hostname)
        self.assertEqual(4, handler.max_redirections)

    def test_explicit_ca_loader_has_no_ambient_store_or_mutated_bundle_fallback(self):
        # This host public CA file is only a parser fixture; no network runs
        # and it is not adopted as production trust by this test.
        fixture = Path("/etc/ssl/certs/ca-certificates.crt").read_bytes()
        with tempfile.TemporaryDirectory(prefix="php-bound-ca-") as directory:
            bundle = Path(directory) / "fixture.pem"
            bundle.write_bytes(fixture)
            context = bootstrap.explicit_trust(bundle, bootstrap.sha256(fixture))
            self.assertEqual(ssl.CERT_REQUIRED, context.verify_mode)
            self.assertTrue(context.check_hostname)
            self.assertGreater(len(context.get_ca_certs()), 0)
            with self.assertRaises(ValueError):
                bootstrap.explicit_trust(bundle, "0" * 64)
            alias = Path(directory) / "alias.pem"
            alias.symlink_to(bundle)
            digest = bootstrap.sha256(fixture)
            with self.assertRaises(ValueError):
                bootstrap.explicit_trust(alias, digest)

    def test_inert_exact_id_download_has_no_auth_proxy_retry_or_name_lookup(self):
        data = b"inert downloader payload"
        identity = self.identity("fixture.tar.zst", data)
        calls = []
        class Response(io.BytesIO):
            status = 200
            def geturl(self):
                return "https://release-assets.githubusercontent.com/closed?signature=inert"
        def factory(*handlers):
            self.assertEqual({}, handlers[0].proxies)
            self.assertIsInstance(handlers[-1], bootstrap.ClosedRedirects)
            def open_request(request, **options):
                calls.append((request, options))
                return Response(data)
            return SimpleNamespace(open=open_request)
        context = SimpleNamespace(verify_mode=ssl.CERT_REQUIRED, check_hostname=True)
        row = {"asset": identity, "mirror": {"id": 900000001}}
        with bootstrap.download_held(row, context, factory) as held:
            self.assertEqual(data, os.pread(held.descriptor, len(data), 0))
            self.assertNotIn("signature", json.dumps(held.effective))
            self.assertEqual(identity, held.identity)
        self.assertEqual(1, len(calls))
        self.assertEqual(MIRROR_URL, calls[0][0].full_url)
        self.assertNotIn("authorization", {key.lower() for key in calls[0][0].headers})
        self.assertEqual({"timeout": 15}, calls[0][1])
        operation = bootstrap.download_held(dict(row, asset=dict(identity, digest="sha256:" + "0" * 64)),
                                            context, factory)
        with ExitStack() as stack, self.assertRaises(ValueError):
            stack.enter_context(operation)
        self.assertEqual(2, len(calls))
        unverified = SimpleNamespace(verify_mode=ssl.CERT_NONE, check_hostname=False)
        operation = bootstrap.download_held(row, unverified, factory)
        with ExitStack() as stack, self.assertRaises(ValueError):
            stack.enter_context(operation)
        # An unmirrored row refuses before any request; there is no upstream fallback.
        for unmirrored in ({"asset": identity}, {"asset": identity, "mirror": None}):
            with self.subTest(row=unmirrored), ExitStack() as stack, self.assertRaises(ValueError):
                stack.enter_context(bootstrap.download_held(unmirrored, context, factory))
        self.assertEqual(2, len(calls))

    def test_mirror_redirect_to_upstream_or_foreign_final_url_refuses(self):
        data = b"inert payload"
        identity = self.identity("fixture.tar.zst", data)
        context = SimpleNamespace(verify_mode=ssl.CERT_REQUIRED, check_hostname=True)
        for final in ("https://api.github.com/repos/shivammathur/php-ubuntu/releases/assets/739209532",
                      "https://github.com/shivammathur/php-ubuntu/releases/download/builds/x",
                      "https://objects.githubusercontent.com/x"):
            class Response(io.BytesIO):
                status = 200
                def geturl(self, final=final):
                    return final
            factory = lambda *handlers: SimpleNamespace(open=lambda request, **options: Response(data))
            with self.subTest(final=final), ExitStack() as stack, self.assertRaises(ValueError):
                stack.enter_context(bootstrap.download_held({"asset": identity, "mirror": {"id": 1}}, context, factory))

    def test_stream_deadline_refuses_without_another_read(self):
        source = SimpleNamespace(read=lambda size: self.fail("Deadline exhausted before source read"))
        bounded = bootstrap.DeadlineInput(source, 60, clock=lambda: 60)
        with self.assertRaises(ValueError):
            bounded.read(1)

    def test_real_sealed_descriptor_refuses_mutation_and_has_no_path_reopen(self):
        data = b"inert archive bytes; never extracted"
        identity = self.identity("fixture.tar.zst", data)
        with bootstrap.hold_verified(io.BytesIO(data), identity, MIRROR_URL) as held:
            held.assert_sealed()
            self.assertEqual(data, os.pread(held.descriptor, len(data), 0))
            with self.assertRaises(OSError) as error:
                os.write(held.descriptor, b"changed")
            self.assertEqual(errno.EPERM, error.exception.errno)
            with self.assertRaises(OSError):
                os.ftruncate(held.descriptor, 0)
            forged = bootstrap.HeldAsset(held.descriptor, dict(identity, digest="sha256:" + "0" * 64), held.effective)
            with self.assertRaises(ValueError):
                forged.assert_sealed()

    def test_installer_or_archive_mutation_refuses_before_any_executor(self):
        data = b"known inert input"
        identity = self.identity("fixture", data)
        for content in (data + b"x", data[:-1], b"different-input!"):
            operation = bootstrap.hold_verified(io.BytesIO(content), identity, MIRROR_URL)
            with self.subTest(content=content), ExitStack() as stack, self.assertRaises(ValueError):
                stack.enter_context(operation)
        with self.assertRaises(ValueError):
            bootstrap.installer_source(self.original + b"\n", self.catalog)

    def test_pinned_source_bytes_and_deterministic_derived_installer_are_bound(self):
        for name, expected in self.catalog["upstream_sources"].items():
            original = bootstrap.ROOT / "qualification/vendor/setup-php-f3e473d" / name
            self.assertEqual(expected, bootstrap.sha256(original.read_bytes()))
        derived = bootstrap.installer_source(self.original, self.catalog)
        self.assertEqual(derived, bootstrap.installer_source(self.original, self.catalog))
        self.assertNotEqual(self.original, derived)
        self.assertNotIn(b"https://", derived)
        self.assertNotIn(b'get /tmp/"$tar_file"', derived)
        self.assertIn(b'-xf - -C / <&"$DW_VERIFIED_ARCHIVE_FD"', derived)

    def shell_function(self, source, name):
        start = source.index(name + "() {\n")
        return source[start:source.index("\n}\n", start) + 3]

    def shell(self, source):
        # All transitive commands are shell functions below. No upstream setup
        # script is sourced and no actual installer, network or sudo runs.
        return subprocess.run(["/usr/bin/bash", "--noprofile", "--norc", "-c", source],
                              env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
                              capture_output=True, text=True, timeout=5)

    def test_exact_predecessor_run_script_admits_unbound_installer(self):
        source = (bootstrap.ROOT / "qualification/vendor/setup-php-f3e473d/unix.sh").read_text()
        function = self.shell_function(source, "run_script")
        result = self.shell("""set -eu
github=https://github.com/shivammathur
latest=releases/latest/download
jsdeliver=https://cdn.jsdelivr.net/gh/shivammathur
setup_php=https://setup-php.com
get() { DOWNLOADED_BYTES=changed; printf 'selector:%s\\n' "$4"; }
bash() { [ "$DOWNLOADED_BYTES" = changed ]; printf 'unbound-admission:%s\\n' "$1"; }
""" + function + '\nrun_script php-ubuntu 8.3 release nts\n')
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("releases/latest/download/install.sh", result.stdout)
        self.assertIn("unbound-admission:/tmp/install.sh", result.stdout)

    def test_exact_old_conditional_apt_branch_admits_network_and_new_branch_refuses(self):
        stub = """set -eu
sudo() {
 if [ "$1" = apt-get ] && [ "$2" = check ]; then return 1; fi
 printf 'network-admission:%s\\n' "$*"
}
"""
        old = self.shell(stub + self.shell_function(self.original.decode(), "fix_packages") + "\nfix_packages\n")
        new = self.shell(stub + self.shell_function(bootstrap.installer_source(self.original, self.catalog).decode(),
                                                    "fix_packages") + "\nfix_packages\n")
        self.assertEqual(0, old.returncode, old.stderr)
        self.assertIn("network-admission:apt --fix-broken install -y", old.stdout)
        self.assertEqual(78, new.returncode)
        self.assertNotIn("network-admission", new.stdout)
        self.assertIn("refuses network APT repair", new.stderr)

    def test_initial_profile_removes_package_repair_merge_and_service_phases(self):
        derived = bootstrap.no_apt_installer_source(self.original, self.catalog)
        self.assertNotIn(b'apt-get ', derived)
        self.assertNotIn(b'sudo apt --', derived)
        self.assertNotIn(b'sudo systemctl', derived)
        self.assertNotIn(b'sudo LC_ALL=', derived)
        self.assertNotIn(b'cp /var/lib/dpkg', derived)
        self.assertIn(b'--exclude=var/lib/dpkg', derived)
        self.assertIn(b'--exclude=./usr/sbin/merge_status', derived)
        self.assertIn(b'-xf - -C / <&"$DW_VERIFIED_ARCHIVE_FD"', derived)
        phases = ('install', 'fix_alternatives', 'fix_service', 'fix_list', 'fix_packages', 'fix_redis_linking')
        stubs = ''.join(name + '() { printf "%s\\n" ' + name + '; }\n' for name in phases)
        old_calls = self.original.decode().split('\ninstall\n', 1)[1]
        new_calls = derived.decode().split('\ninstall\n', 1)[1]
        old = self.shell(stubs + '\ninstall\n' + old_calls)
        new = self.shell(stubs + '\ninstall\n' + new_calls)
        self.assertEqual(list(phases), old.stdout.splitlines())
        self.assertEqual(['install', 'fix_alternatives', 'fix_redis_linking'], new.stdout.splitlines())

    def test_closed_environment_excludes_credentials_and_shell_injection(self):
        parent = dict(GITHUB_TOKEN="inert", GH_TOKEN="inert", ACTIONS_RUNTIME_TOKEN="inert", SONAR_TOKEN="inert",
                      AWS_SECRET_ACCESS_KEY="inert", COMPOSER_AUTH="inert", SSH_AUTH_SOCK="inert",
                      NPM_TOKEN="inert", SIGNING_KEY="inert", BASH_ENV="inert", LD_PRELOAD="inert",
                      GITHUB_OUTPUT="/tmp/owned-output", ImageOS="ubuntu26", ImageVersion="inert-image")
        actual = bootstrap.clean_environment(parent, "/tmp/private-home")
        self.assertEqual({"GITHUB_OUTPUT", "ImageOS", "ImageVersion"}, set(parent) & set(actual))
        self.assertEqual("/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", actual["PATH"])

    def test_effect_primitive_uses_exact_sealed_inputs_and_already_closed_parent(self):
        data = b"inert PHP archive; no extraction"
        catalog = copy.deepcopy(self.catalog)
        row = next(row for row in catalog["archives"] if row == self.row)
        row["asset"] = self.identity(row["asset"]["name"], data, row["asset"]["id"])
        derived = bootstrap.installer_source(self.original, catalog)
        script_id = self.identity("bound-install.sh", derived, catalog["installer"]["id"])
        environment = bootstrap.clean_environment({}, "/tmp/private-home")
        calls = []
        def execute(command, **options):
            calls.append((command, options))
            self.assertEqual(data, os.pread(options["pass_fds"][1], len(data), 0))
            self.assertEqual("/usr/bin/bash", command[0])
            self.assertTrue(command[1].startswith("/proc/self/fd/"))
            return "inert-executor"
        with bootstrap.hold_source_installer(catalog['installer']) as installer, \
                bootstrap.hold_verified(io.BytesIO(derived), script_id, MIRROR_URL) as script:
            with bootstrap.hold_verified(io.BytesIO(data), row["asset"], MIRROR_URL) as archive:
                host = dict(operating_system="ubuntu", release="26.04", architecture="x86_64")
                with patch.dict(os.environ, environment, clear=True):
                    result = bootstrap.run_held_installer(script, archive, ("8.3", "release", "nts"),
                                                        environment, catalog, execute, host, original_installer=installer)
                    self.assertEqual("inert-executor", result)
                    with self.assertRaises(ValueError):
                        bootstrap.run_held_installer(script, archive, ("8.4", "release", "nts"),
                                                    environment, catalog, execute, host, original_installer=installer)
                with self.assertRaises(ValueError):
                    bootstrap.run_held_installer(script, archive, ("8.3", "release", "nts"),
                                                dict(environment, GH_TOKEN="inert"), catalog, execute, host,
                                                original_installer=installer)
        self.assertEqual(1, len(calls))

    def test_normalized_effect_handoff_passes_only_the_sealed_derived_fd_to_an_inert_executor(self):
        payload, identity, selected_profile, _raw = normalize_tests.PhpLinuxNormalizeTest().fixture()
        catalog = copy.deepcopy(self.catalog)
        row = next(row for row in catalog['archives'] if row == self.row)
        row['asset'] = identity
        derived = bootstrap.no_apt_installer_source(self.original, catalog)
        script_id = self.identity('bound-install.sh', derived, catalog['installer']['id'])
        environment = bootstrap.clean_environment({}, '/tmp/inert-no-apt-home')
        host = dict(operating_system='ubuntu', release='26.04', architecture='x86_64')
        calls = []
        with bootstrap.hold_source_installer(catalog['installer']) as installer, \
                bootstrap.hold_bytes(io.BytesIO(derived), script_id, {}) as script, \
                bootstrap.hold_bytes(io.BytesIO(payload), identity, {}) as original, \
                patch.object(normalization, 'profile', return_value=selected_profile), normalization.normalize(original) as result:
            def execute(_command, **options):
                calls.append(options)
                self.assertEqual(result.held.descriptor, options['pass_fds'][1])
                self.assertEqual(str(result.held.descriptor), options['env']['DW_VERIFIED_ARCHIVE_FD'])
                self.assertNotEqual(original.descriptor, options['pass_fds'][1])
                self.assertEqual(result.files, normalization.archive.inspect_held(result.held))
            with patch.dict(os.environ, environment, clear=True), patch.object(alternatives, 'verify') as verify:
                bootstrap.run_held_installer(script, original, ('8.3', 'release', 'nts'), environment,
                    catalog, execute, host, no_apt=True, normalized=result, original_installer=installer)
                verify.assert_called_once_with(result.files, original=original.identity)
                forged = SimpleNamespace(held=result.held)
                with self.assertRaises(ValueError):
                    bootstrap.run_held_installer(script, original, ('8.3', 'release', 'nts'), environment,
                        catalog, execute, host, no_apt=True, normalized=forged, original_installer=installer)
                result.targets['usr/bin/alias']['sha256'] = '0' * 64
                with self.assertRaises(ValueError):
                    bootstrap.run_held_installer(script, original, ('8.3', 'release', 'nts'), environment,
                        catalog, execute, host, no_apt=True, normalized=result, original_installer=installer)
        self.assertEqual(1, len(calls))

    def test_initial_effect_primitive_requires_the_exact_no_apt_derived_bytes(self):
        data = b'inert first-profile archive; never extracted'
        catalog = copy.deepcopy(self.catalog)
        row = next(row for row in catalog['archives'] if row == self.row)
        row['asset'] = self.identity(row['asset']['name'], data, row['asset']['id'])
        derived = bootstrap.no_apt_installer_source(self.original, catalog)
        script_id = self.identity('bound-install.sh', derived, catalog['installer']['id'])
        environment = bootstrap.clean_environment({}, '/tmp/inert-no-apt-home')
        calls = []
        def execute(command, **options):
            calls.append(command)
            held_script = os.pread(options['pass_fds'][0], len(derived), 0)
            self.assertEqual(derived, held_script)
            self.assertNotIn(b'sudo apt', held_script)
        with bootstrap.hold_source_installer(catalog['installer']) as installer, \
                bootstrap.hold_bytes(io.BytesIO(derived), script_id, {}) as script:
            with bootstrap.hold_bytes(io.BytesIO(data), row['asset'], {}) as held_archive:
                with patch.dict(os.environ, environment, clear=True):
                    host = dict(operating_system='ubuntu', release='26.04', architecture='x86_64')
                    bootstrap.run_held_installer(script, held_archive, ('8.3','release','nts'),
                        environment, catalog, execute, host, no_apt=True, original_installer=installer)
                    with self.assertRaises(ValueError):
                        bootstrap.run_held_installer(script, held_archive, ('8.3','release','nts'),
                            environment, catalog, execute, host, no_apt=False, original_installer=installer)
        self.assertEqual(1, len(calls))



class PhpLinuxMirrorTest(unittest.TestCase):
    """Inert uploader controls: no network, credential, release or upload.

    Kept in this module because CI's exact reviewed ci.yml names its modules.
    """

    WORKFLOW = ".github/workflows/mirror-php-linux-archives.yml"
    SHA = "a" * 40

    def setUp(self):
        from scripts import php_linux_mirror as mirror
        self.mirror = mirror
        catalog = json.loads(bootstrap.CATALOG.read_text())
        self.payloads = {}
        rows = []
        for index, row in enumerate(catalog["archives"][:3]):
            data = f"inert archive {index}".encode() * (index + 1)
            row["asset"] = dict(row["asset"], size=len(data), digest="sha256:" + bootstrap.sha256(data))
            self.payloads[row["asset"]["id"]] = data
            rows.append(row)
        catalog["archives"] = rows
        self.catalog = catalog
        self.context = SimpleNamespace(verify_mode=ssl.CERT_REQUIRED, check_hostname=True)

    def environment(self, **changes):
        values = {"EXPECTED_WORKFLOW_SHA": self.SHA, "GITHUB_SHA": self.SHA, "GITHUB_WORKFLOW_SHA": self.SHA,
                  "GITHUB_REPOSITORY": "durable-workflow/.github", "GITHUB_REPOSITORY_ID": "575230056",
                  "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/main",
                  "GITHUB_WORKFLOW_REF": self.mirror.WORKFLOW_REF, "GITHUB_RUN_ATTEMPT": "1",
                  "RUNNER_ENVIRONMENT": "github-hosted"}
        values.update(changes)
        return values

    def test_admission_requires_the_exact_protected_main_dispatch(self):
        self.assertEqual(self.SHA, self.mirror.admit(self.environment(), self.SHA))
        with self.assertRaises(ValueError):
            self.mirror.admit(self.environment(), "b" * 40)
        for name, value in (("EXPECTED_WORKFLOW_SHA", "main"), ("GITHUB_SHA", "b" * 40),
                            ("GITHUB_WORKFLOW_SHA", "b" * 40), ("GITHUB_REPOSITORY", "durable-workflow/workflow"),
                            ("GITHUB_REPOSITORY_ID", "1"), ("GITHUB_EVENT_NAME", "push"),
                            ("GITHUB_REF", "refs/heads/feature"),
                            ("GITHUB_WORKFLOW_REF", self.mirror.WORKFLOW_REF.replace("main", "feature")),
                            ("GITHUB_RUN_ATTEMPT", "2"), ("RUNNER_ENVIRONMENT", "self-hosted")):
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.mirror.admit(self.environment(**{name: value}), self.SHA)

    def test_upload_source_authority_is_upstream_only_and_disjoint_from_setup(self):
        upstream = "https://api.github.com/repos/shivammathur/php-ubuntu/releases/assets/739209532"
        self.mirror.upstream_effective_url(upstream)
        self.mirror.upstream_effective_url("https://release-assets.githubusercontent.com/x?sig=inert")
        for target in (MIRROR_URL, "https://github.com/durable-workflow/.github/x", "https://example.com/x",
                       "https://api.github.com/repos/shivammathur/php-ubuntu/releases/tags/builds"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                self.mirror.upstream_effective_url(target)
        with self.assertRaises(ValueError):
            bootstrap.effective_url(upstream)
        row = self.catalog["archives"][0]
        data = self.payloads[row["asset"]["id"]]
        calls = []

        class Response(io.BytesIO):
            status = 200
            def geturl(self):
                return "https://release-assets.githubusercontent.com/upstream?signature=inert"

        def factory(*handlers):
            self.assertEqual({}, handlers[0].proxies)
            redirects = handlers[-1]
            self.assertIsInstance(redirects, bootstrap.ClosedRedirects)
            with self.assertRaises(ValueError):
                redirects.redirect_request(Request(upstream), None, 302, "redirect", {}, MIRROR_URL)
            return SimpleNamespace(open=lambda request, **options: calls.append(request) or Response(data))

        with self.mirror.fetch_upstream(row["asset"], self.context, factory) as held:
            held.assert_sealed()
        self.assertEqual([f"https://api.github.com/repos/shivammathur/php-ubuntu/releases/assets/{row['asset']['id']}"],
                         [request.full_url for request in calls])
        self.assertNotIn("authorization", {key.lower() for key in calls[0].headers})

    class Api:
        def __init__(self, test, assets=None, upload=None, record=None):
            self.test, self.calls, self.listing = test, [], dict(assets or {})
            self.upload_override, self.record_override = upload, record
            self.records, self.next_id = {}, 900000100
            for name, record in self.listing.items():
                self.records[record["id"]] = record

        def release(self, commit):
            self.calls.append(("release", commit))
            return {"id": 4242, "tag_name": "php-linux-archives", "draft": False}

        def assets(self, release_id):
            self.calls.append(("assets", release_id))
            return dict(self.listing)

        def upload(self, release_id, name, contents):
            self.calls.append(("upload", name, contents))
            identity = next(row["asset"] for row in self.test.catalog["archives"]
                            if bootstrap.mirror_name(row["asset"]) == name)
            record = {"id": self.next_id, "name": name, "size": len(contents), "state": "uploaded",
                      "digest": "sha256:" + bootstrap.sha256(contents),
                      "browser_download_url": "https://github.com/durable-workflow/.github/releases/download/"
                                              "php-linux-archives/" + name.replace("+", "%2B")}
            self.test.assertEqual(identity["size"], len(contents))
            self.next_id += 1
            if self.upload_override:
                record = dict(record, **self.upload_override)
            self.records[record["id"]] = record
            return record

        def asset(self, asset_id):
            self.calls.append(("asset", asset_id))
            return dict(self.records[asset_id], **(self.record_override or {}))

    def listed(self, row, asset_id, **changes):
        identity = row["asset"]
        name = bootstrap.mirror_name(identity)
        return {name: dict({"id": asset_id, "name": name, "size": identity["size"], "state": "uploaded",
                            "digest": identity["digest"],
                            "browser_download_url": "https://github.com/durable-workflow/.github/releases/download/"
                                                    "php-linux-archives/" + name}, **changes)}

    def run_mirror(self, api, served=None):
        fetched, read = [], []

        @contextmanager
        def fetch_source(identity, context):
            fetched.append(identity["id"])
            with bootstrap.hold_bytes(io.BytesIO(self.payloads[identity["id"]]), identity, {}) as held:
                yield held

        @contextmanager
        def fetch_mirror(row, context):
            read.append(row["mirror"]["id"])
            data = (served or {}).get(row["mirror"]["id"], self.payloads[row["asset"]["id"]])
            with bootstrap.hold_verified(io.BytesIO(data), row["asset"], bootstrap.asset_url(row)) as held:
                yield held

        summary = self.mirror.mirror(self.catalog, api, self.context, self.SHA, fetch_source, fetch_mirror)
        return summary, fetched, read

    def test_uploads_sealed_upstream_bytes_by_digest_name_and_reads_each_back(self):
        api = self.Api(self)
        summary, fetched, read = self.run_mirror(api)
        rows = self.catalog["archives"]
        self.assertEqual([row["asset"]["id"] for row in rows], fetched)
        uploads = [call for call in api.calls if call[0] == "upload"]
        self.assertEqual([(bootstrap.mirror_name(row["asset"]), self.payloads[row["asset"]["id"]]) for row in rows],
                         [call[1:] for call in uploads])
        self.assertTrue(all(call[1].startswith(row["asset"]["digest"][7:] + "-php_")
                            for call, row in zip(uploads, rows)))
        self.assertEqual([900000100, 900000101, 900000102], read)
        self.assertEqual({"release", "assets", "upload", "asset"}, {call[0] for call in api.calls})
        self.assertEqual(4242, summary["release_id"])
        self.assertEqual("durable-workflow/.github", summary["repository"])
        self.assertEqual([{"id": 900000100 + index} for index in range(3)],
                         [row["mirror"] for row in summary["archives"]])
        self.assertEqual([row["asset"]["id"] for row in rows], [row["upstream_id"] for row in summary["archives"]])
        self.assertEqual({"uploaded"}, {row["action"] for row in summary["archives"]})

    def test_existing_identical_asset_is_reused_and_different_bytes_refuse(self):
        row = self.catalog["archives"][0]
        api = self.Api(self, self.listed(row, 777))
        summary, fetched, _read = self.run_mirror(api)
        self.assertEqual("existing", summary["archives"][0]["action"])
        self.assertEqual({"id": 777}, summary["archives"][0]["mirror"])
        self.assertNotIn(row["asset"]["id"], fetched)
        for change in ({"digest": "sha256:" + "0" * 64}, {"size": row["asset"]["size"] + 1},
                       {"state": "starter"}, {"digest": None}):
            api = self.Api(self, self.listed(row, 777, **change))
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.run_mirror(api)
            self.assertNotIn("upload", {call[0] for call in api.calls})

    def test_recorded_rows_are_verified_never_reuploaded(self):
        row = self.catalog["archives"][0]
        with patch.object(bootstrap, "MIRROR_RELEASE_ID", 4242):
            self.catalog["mirror"] = {"repository": "durable-workflow/.github", "release_id": 4242,
                                      "release_tag": "php-linux-archives"}
            row["mirror"] = {"id": 777}
            api = self.Api(self, self.listed(row, 777))
            summary, fetched, read = self.run_mirror(api)
            self.assertEqual("verified", summary["archives"][0]["action"])
            self.assertNotIn(row["asset"]["id"], fetched)
            self.assertNotIn(777, read)
            self.assertIn(("asset", 777), api.calls)
            with self.assertRaises(ValueError):
                self.run_mirror(self.Api(self, self.listed(row, 777), record={"digest": "sha256:" + "0" * 64}))
            for listing in ({}, self.listed(row, 778)):
                api = self.Api(self, listing)
                with self.subTest(listing=listing), self.assertRaisesRegex(ValueError, "missing"):
                    self.run_mirror(api)
                self.assertNotIn(bootstrap.mirror_name(row["asset"]),
                                 [call[1] for call in api.calls if call[0] == "upload"])

    def test_renamed_truncated_or_unverifiable_uploads_refuse(self):
        for upload in ({"name": "php_8.1-nts+ubuntu22.04_arm64.tar.zst"}, {"size": 1}, {"id": None}):
            with self.subTest(upload=upload), self.assertRaises(ValueError):
                self.run_mirror(self.Api(self, upload=upload))
        for record in ({"digest": "sha256:" + "0" * 64}, {"digest": None}, {"state": "starter"},
                       {"browser_download_url": "https://github.com/durable-workflow/.github/releases/download/other/x"},
                       {"browser_download_url": "https://github.com/shivammathur/php-ubuntu/releases/download/builds/x"}):
            with self.subTest(record=record), self.assertRaises(ValueError):
                self.run_mirror(self.Api(self, record=record))
        # The anonymous read-back serves other bytes for the new asset ID.
        with self.assertRaises(ValueError):
            self.run_mirror(self.Api(self), served={900000100: b"replaced mirror bytes"})

    def test_api_client_is_confined_to_mirror_releases_without_redirects(self):
        calls = []

        class Response(io.BytesIO):
            status = 200

        def factory(*handlers):
            self.assertEqual({}, handlers[0].proxies)
            self.assertIsInstance(handlers[-1], self.mirror.NoRedirects)
            with self.assertRaises(ValueError):
                handlers[-1].redirect_request(None, None, 302, "redirect", {}, "https://example.com/")
            return SimpleNamespace(open=lambda request, **options: calls.append(request) or Response(b"[]"))

        token = "ghs_" + "x" * 36
        api = self.mirror.MirrorApi(token, self.context, factory)
        self.assertEqual({}, api.assets(4242))
        self.assertEqual("https://api.github.com/repos/durable-workflow/.github/releases/4242/assets?per_page=100&page=1",
                         calls[0].full_url)
        api.request("POST", "https://uploads.github.com/repos/durable-workflow/.github/releases/4242/assets?name=a%2Bb",
                    b"inert", "application/octet-stream", expected=200)
        for url in ("https://api.github.com/repos/shivammathur/php-ubuntu/releases/assets/1",
                    "https://api.github.com/repos/durable-workflow/.github/contents/x",
                    "https://api.github.com/repos/durable-workflow/.github-x/releases",
                    "https://uploads.github.com/repos/durable-workflow/workflow/releases/1/assets"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                api.request("GET", url)
        self.assertEqual(2, len(calls))
        self.assertNotIn(token, repr(api.__dict__.get("_client")))
        for malformed in ("", "token with spaces", "x" * 10):
            with self.subTest(token=malformed), self.assertRaises(ValueError):
                self.mirror.MirrorApi(malformed, self.context, factory)
        quoted = "https://uploads.github.com/repos/durable-workflow/.github/releases/7/assets?name="
        upload_calls = []
        api.request = lambda method, url, body=None, content_type=None, expected=200: upload_calls.append(url) or {}
        api.upload(7, "abc-php_8.3-nts+ubuntu24.04.tar.zst", b"inert")
        self.assertEqual([quoted + "abc-php_8.3-nts%2Bubuntu24.04.tar.zst"], upload_calls)

    def test_release_is_the_published_tag_and_is_created_only_when_absent(self):
        api = self.mirror.MirrorApi("ghs_" + "x" * 36, self.context, lambda *handlers: None)
        responses = []

        def request(method, url, body=None, content_type=None, expected=200):
            responses.append((method, url, body and json.loads(body)))
            if method == "GET":
                raise bootstrap.HTTPError(url, 404, "absent", None, None)
            return {"id": 4242, "tag_name": "php-linux-archives", "draft": False}

        api.request = request
        self.assertEqual(4242, api.release(self.SHA)["id"])
        self.assertEqual(("GET", self.mirror.API + "/releases/tags/php-linux-archives", None), responses[0])
        created = responses[1][2]
        self.assertEqual(("php-linux-archives", self.SHA, False, False, "false"),
                         (created["tag_name"], created["target_commitish"], created["draft"],
                          created["prerelease"], created["make_latest"]))
        for release in ({"id": 1, "tag_name": "builds", "draft": False},
                        {"id": 1, "tag_name": "php-linux-archives", "draft": True},
                        {"id": "1", "tag_name": "php-linux-archives", "draft": False}):
            api.request = lambda *arguments, release=release, **options: release
            with self.subTest(release=release), self.assertRaises(ValueError):
                api.release(self.SHA)
        api.request = lambda *arguments, **options: {"id": 4243, "tag_name": "php-linux-archives", "draft": False}
        with patch.object(bootstrap, "MIRROR_RELEASE_ID", 4242), self.assertRaises(ValueError):
            api.release(self.SHA)

    def test_entrypoint_admits_then_binds_the_shared_ca_before_any_request(self):
        summary = {"schema": "inert"}
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "summary.md"
            environment = self.environment(DW_CI_CA_SHA256=self.mirror.CA_SHA256, SSL_CERT_FILE="/inert/ca.pem",
                                           MIRROR_TOKEN="ghs_" + "x" * 36, GITHUB_STEP_SUMMARY=str(output))
            head = SimpleNamespace(stdout=self.SHA + "\n")
            with patch.dict(os.environ, environment, clear=True), \
                    patch.object(self.mirror.subprocess, "run", return_value=head), \
                    patch.object(bootstrap, "explicit_trust", return_value=self.context) as trust, \
                    patch.object(self.mirror, "mirror", return_value=summary) as run, \
                    patch("sys.stdout", new_callable=io.StringIO) as printed:
                self.assertEqual(0, self.mirror.main())
            trust.assert_called_once_with(Path("/inert/ca.pem"), self.mirror.CA_SHA256)
            self.assertEqual(self.SHA, run.call_args.args[3])
            self.assertIn('"schema": "inert"', output.read_text())
            self.assertNotIn("ghs_", printed.getvalue() + output.read_text())
            for changes in ({"DW_CI_CA_SHA256": "0" * 64}, {"GITHUB_REF": "refs/heads/other"}):
                with self.subTest(changes=changes), patch.dict(os.environ, dict(environment, **changes), clear=True), \
                        patch.object(self.mirror.subprocess, "run", return_value=head), \
                        patch.object(self.mirror, "mirror") as run, self.assertRaises(ValueError):
                    self.mirror.main()
                run.assert_not_called()

    def test_workflow_is_manual_main_only_protected_and_least_privilege(self):
        import yaml
        from scripts import protected_policy_context as policy_context
        from scripts.qualification_policy import load_policy, scan_workflow_sources
        raw = (bootstrap.ROOT / self.WORKFLOW).read_bytes()
        document = yaml.load(raw, Loader=yaml.BaseLoader)
        self.assertEqual({"workflow_dispatch"}, set(document["on"]))
        self.assertEqual({"expected_workflow_sha"}, set(document["on"]["workflow_dispatch"]["inputs"]))
        self.assertEqual({"contents": "read"}, document["permissions"])
        self.assertEqual("false", document["concurrency"]["cancel-in-progress"])
        self.assertEqual(["mirror"], list(document["jobs"]))
        job = document["jobs"]["mirror"]
        self.assertEqual("github.ref == 'refs/heads/main'", job["if"])
        self.assertEqual("php-archive-mirror", job["environment"])
        self.assertEqual({"contents": "write"}, job["permissions"])
        self.assertEqual({"GITHUB_TOKEN": "", "GH_TOKEN": ""}, job["env"])
        self.assertNotIn("secrets", raw.decode())
        steps = job["steps"]
        self.assertEqual("false", steps[0]["with"]["persist-credentials"])
        self.assertTrue(steps[1]["uses"].endswith("@242c2a7fb23459db2e1ada5f84dbee6d61d9b1e5"))
        self.assertEqual("python3 -I scripts/php_linux_mirror.py", steps[-1]["run"])
        self.assertEqual({"EXPECTED_WORKFLOW_SHA": "${{ inputs.expected_workflow_sha }}",
                          "MIRROR_TOKEN": "${{ github.token }}"}, steps[-1]["env"])
        self.assertEqual(1, raw.decode().count("github.token"))
        # Closed literal commands: no reviewed-bytes registry entry is needed.
        self.assertNotIn(self.WORKFLOW, policy_context.reviewed_context_hashes("github-control-plane"))
        policy_context.validate_context({self.WORKFLOW: raw})
        policy = load_policy(bootstrap.ROOT / "qualification/policy.json")
        evidence = scan_workflow_sources(policy, "github-control-plane", {self.WORKFLOW: raw.decode()})
        self.assertEqual(["mirror"], evidence[self.WORKFLOW]["privileged_jobs"])
        for before, after in (("    if: github.ref == 'refs/heads/main'\n", ""),
                              ("permissions:\n  contents: read", "permissions:\n  contents: write")):
            changed = raw.decode().replace(before, after)
            self.assertNotEqual(raw.decode(), changed)
            with self.subTest(before=before), self.assertRaises(Exception):
                scan_workflow_sources(policy, "github-control-plane", {self.WORKFLOW: changed})


if __name__ == "__main__":
    unittest.main()
