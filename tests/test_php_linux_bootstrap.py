"""Inert source controls: no network, PHP setup, sudo or archive extraction."""

import copy
from contextlib import ExitStack, contextmanager
import errno
import io
import json
import os
from pathlib import Path
import re
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
        # Only the setup-profile archives are pinned (setup_php_linux.HOST_ARCHIVES).
        self.assertEqual([("24.04", "x86_64", "8.3", 739209532), ("26.04", "x86_64", "8.3", 739711545)],
                         sorted((row["release"], row["arch"], row["php"], row["asset"]["id"])
                                for row in self.catalog["archives"]))
        self.assertEqual(713206915, self.catalog["installer"]["id"])
        for row in self.catalog["archives"]:
            self.assertEqual(row, bootstrap.select(self.catalog, operating_system=row["os"],
                release=row["release"], architecture=row["arch"], php=row["php"]))
            self.assertEqual(f"https://api.github.com/repos/shivammathur/php-ubuntu/releases/assets/{row['asset']['id']}",
                             bootstrap.asset_url(row["asset"]))

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
        for target in ("http://github.com/shivammathur/php-ubuntu/x", "https://cdn.jsdelivr.net/x",
                       "https://artifacts.php-ubuntu.setup-php.com/x", "https://example.com/x",
                       "https://github.com/foreign/repository/x", "https://api.github.com/repos/foreign/assets/1",
                       "https://user@github.com/shivammathur/php-ubuntu/x", "https://github.com:8443/x"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                bootstrap.effective_url(target)

    def test_redirect_handler_refuses_before_requesting_a_fallback_authority(self):
        request = Request(bootstrap.asset_url(self.catalog["installer"]))
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
        with bootstrap.download_held(identity, context, factory) as held:
            self.assertEqual(data, os.pread(held.descriptor, len(data), 0))
            self.assertNotIn("signature", json.dumps(held.effective))
        self.assertEqual(1, len(calls))
        self.assertEqual(bootstrap.asset_url(identity), calls[0][0].full_url)
        self.assertNotIn("authorization", {key.lower() for key in calls[0][0].headers})
        self.assertEqual({"timeout": 15}, calls[0][1])
        operation = bootstrap.download_held(dict(identity, digest="sha256:" + "0" * 64), context, factory)
        with ExitStack() as stack, self.assertRaises(ValueError):
            stack.enter_context(operation)
        self.assertEqual(2, len(calls))
        unverified = SimpleNamespace(verify_mode=ssl.CERT_NONE, check_hostname=False)
        operation = bootstrap.download_held(identity, unverified, factory)
        with ExitStack() as stack, self.assertRaises(ValueError):
            stack.enter_context(operation)
        self.assertEqual(2, len(calls))

    def test_stream_deadline_refuses_without_another_read(self):
        source = SimpleNamespace(read=lambda size: self.fail("Deadline exhausted before source read"))
        bounded = bootstrap.DeadlineInput(source, 60, clock=lambda: 60)
        with self.assertRaises(ValueError):
            bounded.read(1)

    def test_real_sealed_descriptor_refuses_mutation_and_has_no_path_reopen(self):
        data = b"inert archive bytes; never extracted"
        identity = self.identity("fixture.tar.zst", data)
        with bootstrap.hold_verified(io.BytesIO(data), identity, bootstrap.asset_url(identity)) as held:
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
            operation = bootstrap.hold_verified(io.BytesIO(content), identity, bootstrap.asset_url(identity))
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
                bootstrap.hold_verified(io.BytesIO(derived), script_id, bootstrap.asset_url(catalog["installer"])) as script:
            with bootstrap.hold_verified(io.BytesIO(data), row["asset"], bootstrap.asset_url(row["asset"])) as archive:
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


class PhpLinuxUpstreamPinsTest(unittest.TestCase):
    """Inert controls for the scheduled read-only upstream pin check."""

    WORKFLOW = ".github/workflows/php-linux-upstream-pins.yml"

    def setUp(self):
        from scripts import php_linux_upstream_pins as pins
        self.pins = pins
        self.catalog = json.loads(bootstrap.CATALOG.read_text())
        self.context = SimpleNamespace(verify_mode=ssl.CERT_REQUIRED, check_hostname=True)

    def published(self):
        records = [{"id": 1, "name": "php_7.4-nts+ubuntu20.04.tar.zst", "size": 1,
                    "digest": "sha256:" + "1" * 64, "state": "uploaded"}]
        for identity in [self.catalog["installer"]] + [row["asset"] for row in self.catalog["archives"]]:
            records.append(dict(identity, state="uploaded", updated_at="2026-11-12T12:00:00Z"))
        return records

    def replace(self, records, identity, **changes):
        records = [record for record in records if record["id"] != identity["id"]]
        records.append({**identity, "id": identity["id"] + 10**8, "state": "uploaded",
                        "updated_at": "2026-11-13T05:00:00Z", **changes})
        return records

    def test_unchanged_pins_pass(self):
        report = self.pins.check(self.catalog, self.published())
        self.assertEqual([], report["affected"])
        self.assertEqual(1 + len(self.catalog["archives"]), report["checked"])
        self.assertIn("unchanged", self.pins.summary_markdown(report))

    def test_replaced_archive_fails_with_its_candidate_and_profile_flag(self):
        profile = bootstrap.select(self.catalog, operating_system="ubuntu", release="24.04",
                                   architecture="x86_64", php="8.3")
        other = bootstrap.select(self.catalog, operating_system="ubuntu", release="26.04",
                                 architecture="x86_64", php="8.3")
        records = self.replace(self.published(), profile["asset"], size=profile["asset"]["size"] + 1,
                               digest="sha256:" + "2" * 64)
        records = self.replace(records, other["asset"])  # same bytes, new ID: setup still 404s
        report = self.pins.check(self.catalog, records)
        self.assertEqual({profile["asset"]["id"], other["asset"]["id"]},
                         {row["pinned"]["id"] for row in report["affected"]})
        row = next(row for row in report["affected"] if row["pinned"]["id"] == profile["asset"]["id"])
        self.assertEqual(("archive", "missing", True, "24.04", "8.3"),
                         (row["kind"], row["status"], row["setup_profile"], row["release"], row["php"]))
        self.assertEqual({"id": profile["asset"]["id"] + 10**8, "size": profile["asset"]["size"] + 1,
                          "digest": "sha256:" + "2" * 64, "updated_at": "2026-11-13T05:00:00Z"}, row["candidate"])
        self.assertTrue(all(row["setup_profile"] for row in report["affected"]))
        unprofiled = dict(self.catalog, archives=self.catalog["archives"] + [dict(
            self.catalog["archives"][0], release="22.04",
            asset=dict(self.catalog["archives"][0]["asset"], id=5, name="php_8.3-nts+ubuntu22.04.tar.zst"))])
        (row,) = self.pins.check(unprofiled, self.published())["affected"]
        self.assertFalse(row["setup_profile"])
        text = self.pins.summary_markdown(report)
        self.assertIn("replaced upstream", text)
        self.assertIn(str(profile["asset"]["id"] + 10**8), text)

    def test_changed_deleted_or_ambiguous_assets_fail(self):
        identity = self.catalog["archives"][-1]["asset"]
        for change in ({"digest": "sha256:" + "3" * 64}, {"size": 1}, {"name": "renamed.tar.zst"},
                       {"state": "starter"}):
            records = [dict(record, **change) if record["id"] == identity["id"] else record
                       for record in self.published()]
            with self.subTest(change=change):
                (row,) = self.pins.check(self.catalog, records)["affected"]
                self.assertEqual("changed", row["status"])
        deleted = [record for record in self.published() if record["id"] != identity["id"]]
        (row,) = self.pins.check(self.catalog, deleted)["affected"]
        self.assertEqual(("missing", None, 0), (row["status"], row["candidate"], row["same_name_assets"]))
        doubled = self.replace(self.published(), identity) + [dict(identity, id=7, state="uploaded")]
        doubled = [record for record in doubled if record["id"] != identity["id"]]
        (row,) = self.pins.check(self.catalog, doubled)["affected"]
        self.assertEqual((None, 2), (row["candidate"], row["same_name_assets"]))

    def test_installer_passes_only_for_identical_bytes_under_a_new_id(self):
        installer = self.catalog["installer"]
        same = self.replace(self.published(), installer)
        self.assertEqual([], self.pins.check(self.catalog, same)["affected"])
        for change in ({"digest": "sha256:" + "4" * 64}, {"size": installer["size"] + 1}):
            with self.subTest(change=change):
                (row,) = self.pins.check(self.catalog, self.replace(self.published(), installer, **change))["affected"]
                self.assertEqual(("installer", "missing"), (row["kind"], row["status"]))
        absent = [record for record in self.published() if record["name"] != "install.sh"]
        self.assertEqual(1, len(self.pins.check(self.catalog, absent)["affected"]))

    def test_upstream_free_text_never_reaches_the_report(self):
        identity = self.catalog["archives"][0]["asset"]
        records = self.replace(self.published(), identity, digest="@everyone <script>",
                               updated_at="@someone", body="@someone")
        report = self.pins.check(self.catalog, records)
        text = json.dumps(report) + self.pins.summary_markdown(report)
        self.assertNotIn("@", text)
        self.assertNotIn("<script>", text)
        self.assertTrue(report["affected"][0]["candidate"]["unverifiable"])
        records = self.replace(self.published(), identity, updated_at="@someone")
        self.assertIsNone(self.pins.check(self.catalog, records)["affected"][0]["candidate"]["updated_at"])

    def test_reader_is_get_only_confined_to_the_pinned_release_without_redirects(self):
        calls, pages = [], {}
        records = self.published()
        listing = records + [dict(records[0], id=index + 1000) for index in range(200 - len(records))]

        class Response(io.BytesIO):
            status = 200

        def respond(request, **options):
            calls.append((request.get_method(), request.full_url, dict(request.header_items()), options))
            if request.full_url == self.pins.RELEASE_URL:
                return Response(json.dumps({"id": 39619287, "tag_name": "builds"}).encode())
            page = int(request.full_url.rsplit("=", 1)[1])
            return Response(json.dumps(listing[(page - 1) * 100:page * 100]).encode())

        def factory(*handlers):
            self.assertEqual({}, handlers[0].proxies)
            self.assertIsInstance(handlers[-1], self.pins.NoRedirects)
            with self.assertRaises(ValueError):
                handlers[-1].redirect_request(None, None, 302, "redirect", {}, "https://example.com/")
            return SimpleNamespace(open=respond)

        token = "ghs_" + "r" * 36
        reader = self.pins.ReleaseReader(token, self.context, factory)
        self.assertEqual(listing, reader.assets())
        self.assertEqual({"GET"}, {call[0] for call in calls})
        self.assertEqual(4, len(calls))
        self.assertEqual("Bearer " + token, calls[0][2]["Authorization"])
        for url in ("https://api.github.com/repos/shivammathur/php-ubuntu/releases/1/assets?per_page=100&page=1",
                    "https://api.github.com/repos/durable-workflow/.github/releases/39619287",
                    "https://api.github.com/repos/shivammathur/php-ubuntu/releases/39619287/assets?per_page=100&page=1&x=1",
                    "https://example.com/repos/shivammathur/php-ubuntu/releases/39619287"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                reader.get(url)
        self.assertEqual(4, len(calls))
        wrong = self.pins.ReleaseReader(token, self.context, lambda *handlers: SimpleNamespace(
            open=lambda request, **options: Response(json.dumps({"id": 39619287, "tag_name": "latest"}).encode())))
        with self.assertRaises(ValueError):
            wrong.assets()
        for malformed in ("", "x" * 5, "token with space"):
            with self.subTest(token=malformed), self.assertRaises(ValueError):
                self.pins.ReleaseReader(malformed, self.context, factory)

    @staticmethod
    def stateless_token():
        """Inert stand-in shaped like the 2026 stateless installation token."""
        import base64
        def part(data):
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        header = part(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        payload = part(json.dumps({"iss": "123456", "inst": "7890123", "repo": "durable-workflow/.github",
                                   "perm": {"contents": "read", "metadata": "read"}, "exp": 1794000000,
                                   "jti": "inert-" + "x" * 160}).encode())
        signature = part(bytes(range(256)))
        return f"ghs_123456_{header}.{payload}.{signature}"

    def test_stateless_actions_token_is_accepted_without_disclosure(self):
        # Reproduces run 43292858903: the ~520-character stateless GITHUB_TOKEN
        # exceeded the old 255-character bound and refused before any request.
        token = self.stateless_token()
        self.assertGreater(len(token), 255)
        self.assertEqual(2, token.count("."))
        self.assertIsNone(re.fullmatch(r"[A-Za-z0-9_.-]{20,255}", token))
        calls = []

        class Response(io.BytesIO):
            status = 200

        def factory(*handlers):
            return SimpleNamespace(open=lambda request, **options: calls.append(request) or Response(
                json.dumps({"id": 39619287, "tag_name": "builds"}).encode()))

        reader = self.pins.ReleaseReader(token, self.context, factory)
        reader.get(self.pins.RELEASE_URL)
        self.assertEqual("Bearer " + token, calls[0].get_header("Authorization"))
        # The legacy 40-character form still works; header-unsafe input does not.
        self.pins.ReleaseReader("ghs_" + "a" * 36, self.context, factory)
        for malformed in (token + "\n", " " + token, token.replace(".", ":", 1), token + "\r\nX-Injected: 1",
                          "ghs_" + "a" * (self.pins.MAX_TOKEN + 1), "short"):
            with self.subTest(kind=len(malformed) > 255), self.assertRaisesRegex(ValueError, "missing or malformed") as raised:
                self.pins.ReleaseReader(malformed, self.context, factory)
            self.assertNotIn(token[4:], str(raised.exception))

    def test_entrypoint_fails_on_affected_pins_and_writes_the_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "summary.md"
            environment = {"DW_CI_CA_SHA256": self.pins.CA_SHA256, "SSL_CERT_FILE": "/inert/ca.pem",
                           "PINS_TOKEN": "ghs_" + "r" * 36, "GITHUB_STEP_SUMMARY": str(output)}
            published = self.published()
            replaced = self.replace(published, self.catalog["archives"][0]["asset"])
            for records, expected in ((published, 0), (replaced, 1)):
                with self.subTest(expected=expected), patch.dict(os.environ, environment, clear=True), \
                        patch.object(bootstrap, "explicit_trust", return_value=self.context) as trust, \
                        patch.object(self.pins.ReleaseReader, "assets", return_value=records), \
                        patch("sys.stdout", new_callable=io.StringIO) as printed:
                    self.assertEqual(expected, self.pins.main())
                trust.assert_called_once_with(Path("/inert/ca.pem"), self.pins.CA_SHA256)
                self.assertNotIn("ghs_", printed.getvalue())
            self.assertIn("replaced upstream", output.read_text())
            with patch.dict(os.environ, dict(environment, DW_CI_CA_SHA256="0" * 64), clear=True), \
                    self.assertRaises(ValueError):
                self.pins.main()

    def test_workflow_is_scheduled_read_only_and_policy_clean(self):
        import yaml
        from scripts import protected_policy_context as policy_context
        from scripts.qualification_policy import load_policy, scan_workflow_sources
        raw = (bootstrap.ROOT / self.WORKFLOW).read_bytes()
        document = yaml.load(raw, Loader=yaml.BaseLoader)
        self.assertEqual({"schedule", "workflow_dispatch"}, set(document["on"]))
        self.assertEqual([{"cron": "23 5 * * *"}], document["on"]["schedule"])
        self.assertEqual({"contents": "read"}, document["permissions"])
        job = document["jobs"]["check"]
        self.assertEqual({"contents": "read"}, job["permissions"])
        self.assertNotIn("environment", job)
        self.assertNotIn("secrets", raw.decode())
        self.assertNotIn(": write", raw.decode())
        self.assertEqual("false", job["steps"][0]["with"]["persist-credentials"])
        self.assertEqual("python3 -I scripts/php_linux_upstream_pins.py", job["steps"][-1]["run"])
        self.assertEqual({"PINS_TOKEN": "${{ github.token }}"}, job["steps"][-1]["env"])
        self.assertNotIn(self.WORKFLOW, policy_context.reviewed_context_hashes("github-control-plane"))
        policy_context.validate_context({self.WORKFLOW: raw})
        policy = load_policy(bootstrap.ROOT / "qualification/policy.json")
        evidence = scan_workflow_sources(policy, "github-control-plane", {self.WORKFLOW: raw.decode()})
        self.assertEqual([], evidence[self.WORKFLOW]["privileged_jobs"])


if __name__ == "__main__":
    unittest.main()
