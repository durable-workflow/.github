"""Controls for the fixed hosted /opt repair; never change the host's /opt."""

import importlib.util
import os
import io
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

from tests.test_private_pip_runtime import runtime


SOURCE = (Path(__file__).resolve().parents[1]
          / ".github/actions/bootstrap-patched-pip/protect-hosted-runtime.py")
SPEC = importlib.util.spec_from_file_location("protect_hosted_runtime", SOURCE)
protection = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(protection)


class HostedRuntimeParentTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name) / "opt"
        self.directory.mkdir()
        self.original_fstat = os.fstat
        self.original_stat = os.stat
        self.original_open = os.open
        self.runner_uid = os.getuid()
        self.identity = self.directory.stat()

    def root_metadata(self, metadata):
        if (metadata.st_dev, metadata.st_ino) == (self.identity.st_dev, self.identity.st_ino):
            fields = list(metadata)
            fields[4] = 0
            return os.stat_result(fields)
        return metadata

    def root_owned(self, descriptor):
        return self.root_metadata(self.original_fstat(descriptor))

    def root_stat(self, *arguments, **options):
        return self.root_metadata(self.original_stat(*arguments, **options))

    def test_writable_parent_is_refused_before_and_accepted_only_after_sticky_protection(self):
        self.directory.chmod(0o777)
        with patch.object(os, "fstat", side_effect=self.root_owned), \
                patch.object(os, "stat", side_effect=self.root_stat):
            with self.assertRaisesRegex(ValueError, "Runtime directory refused"):
                with runtime.BoundDirectory(self.directory):
                    pass
            protection.protect_directory(self.directory)
            self.assertEqual(0o1777, stat.S_IMODE(self.directory.stat().st_mode))
            with runtime.BoundDirectory(self.directory):
                pass

    def test_protected_directory_permissions_are_preserved_without_a_write(self):
        for mode in (0o755, 0o1777):
            with self.subTest(mode=mode):
                self.directory.chmod(mode)
                with patch.object(os, "fstat", side_effect=self.root_owned), \
                        patch.object(os, "fchmod") as change:
                    protection.protect_directory(self.directory)
                change.assert_not_called()
                self.assertEqual(mode, stat.S_IMODE(self.directory.stat().st_mode))

    def test_foreign_owner_and_special_modes_refuse_without_mutation(self):
        self.directory.chmod(0o777)
        with patch.object(os, "fchmod") as change:
            with self.assertRaisesRegex(ValueError, "root-owned"):
                protection.protect_directory(self.directory)
        change.assert_not_called()
        self.directory.chmod(0o2777)
        with patch.object(os, "fstat", side_effect=self.root_owned), \
                patch.object(os, "fchmod") as change:
            with self.assertRaisesRegex(ValueError, "root-owned"):
                protection.protect_directory(self.directory)
        change.assert_not_called()

    def test_link_and_regular_file_refuse_without_following_or_mutation(self):
        link = self.directory.parent / "link"
        link.symlink_to(self.directory)
        file = self.directory.parent / "file"
        file.touch()
        for path in (link, file):
            with self.subTest(path=path.name), patch.object(os, "fchmod") as change:
                with self.assertRaises(OSError):
                    protection.protect_directory(path)
                change.assert_not_called()

    def test_failed_or_ineffective_permission_change_cannot_pass(self):
        self.directory.chmod(0o777)
        with patch.object(os, "fstat", side_effect=self.root_owned):
            with patch.object(os, "fchmod", side_effect=PermissionError):
                with self.assertRaises(PermissionError):
                    protection.protect_directory(self.directory)
            with patch.object(os, "fchmod"):
                with self.assertRaisesRegex(ValueError, "not established"):
                    protection.protect_directory(self.directory)
            with self.assertRaisesRegex(ValueError, "Runtime directory refused"):
                with runtime.BoundDirectory(self.directory):
                    pass

    def test_selected_tree_preserves_contents_and_execute_bits_but_closes_writable_entries(self):
        library = self.directory / "lib"
        library.mkdir()
        binary = library / "python"
        binary.write_bytes(b"inert selected-runtime fixture")
        binary.chmod(0o777)
        library.chmod(0o777)
        self.directory.chmod(0o777)
        other = self.directory.parent / "other-version"
        other.mkdir()
        other.chmod(0o777)
        link = library / "outside"
        link.symlink_to(other, target_is_directory=True)
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            protection.seal_tree(descriptor, os.getuid())
        finally:
            os.close(descriptor)
        self.assertEqual(b"inert selected-runtime fixture", binary.read_bytes())
        for path in (self.directory, library, binary):
            self.assertEqual(0o755, stat.S_IMODE(path.stat().st_mode))
        self.assertTrue(link.is_symlink())
        self.assertEqual(0o777, stat.S_IMODE(other.stat().st_mode))

    def test_hardlinks_and_special_files_refuse_without_modifying_outside_contents(self):
        outside = self.directory.parent / "outside"
        outside.write_bytes(b"outside")
        outside.chmod(0o666)
        os.link(outside, self.directory / "hardlink")
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaisesRegex(ValueError, "private regular"):
                protection.seal_tree(descriptor, self.runner_uid)
        finally:
            os.close(descriptor)
        self.assertEqual(0o666, stat.S_IMODE(outside.stat().st_mode))
        (self.directory / "hardlink").unlink()
        os.mkfifo(self.directory / "fifo")
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaisesRegex(ValueError, "private regular"):
                protection.seal_tree(descriptor, self.runner_uid)
        finally:
            os.close(descriptor)

    def test_noncanonical_hosted_location_refuses_before_opening_any_path(self):
        for location in ("/tmp/python", "/opt/hostedtoolcache/Python/3.13.18/../../other",
                         "/opt/hostedtoolcache/Python/3.13.18/x86", "//opt/hostedtoolcache/Python/3.13.18/x64"):
            with self.subTest(location=location), patch.object(os, "open") as opened:
                with self.assertRaisesRegex(ValueError, "fixed hosted"):
                    protection.protect_hosted_python(location, self.runner_uid)
                opened.assert_not_called()

    def sandbox_open(self, path, flags, **options):
        if path == "/" and "dir_fd" not in options:
            path = self.directory.parent
        return self.original_open(path, flags, **options)

    def hosted_tree(self):
        selected = self.directory / "hostedtoolcache/Python/3.13.18/x64"
        selected.mkdir(parents=True)
        file = selected / "python"
        file.write_bytes(b"selected interpreter fixture")
        file.chmod(0o777)
        for directory in (selected, *selected.parents):
            if directory == self.directory.parent:
                break
            directory.chmod(0o777)
        return selected, file

    def test_complete_hosted_ancestry_and_selected_tree_are_protected_without_touching_other_versions(self):
        selected, file = self.hosted_tree()
        other = selected.parent / "arm64"
        other.mkdir(mode=0o777)
        other.chmod(0o777)
        with patch.object(os, "open", side_effect=self.sandbox_open):
            protection.protect_hosted_python("/opt/hostedtoolcache/Python/3.13.18/x64", self.runner_uid)
        self.assertEqual(b"selected interpreter fixture", file.read_bytes())
        for directory in (selected, *selected.parents):
            if directory == self.directory.parent:
                break
            self.assertEqual(0o755, stat.S_IMODE(directory.stat().st_mode))
        self.assertEqual(0o755, stat.S_IMODE(file.stat().st_mode))
        self.assertEqual(0o777, stat.S_IMODE(other.stat().st_mode))

    def test_linked_ancestry_refuses_before_traversing_selected_runtime(self):
        selected, file = self.hosted_tree()
        python = selected.parent.parent
        moved = python.with_name("other-python")
        python.rename(moved)
        python.symlink_to(moved, target_is_directory=True)
        with patch.object(os, "open", side_effect=self.sandbox_open):
            with self.assertRaises(OSError):
                protection.protect_hosted_python("/opt/hostedtoolcache/Python/3.13.18/x64", self.runner_uid)
        self.assertEqual(0o777, stat.S_IMODE(file.stat().st_mode))

    def test_metadata_limits_refuse_without_traversing_a_large_or_deep_tree(self):
        (self.directory / "file").touch()
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaisesRegex(ValueError, "walk limit"):
                protection.seal_tree(descriptor, self.runner_uid, [200000])
            with self.assertRaisesRegex(ValueError, "depth limit"):
                protection.seal_tree(descriptor, self.runner_uid, depth=65)
        finally:
            os.close(descriptor)

    def test_special_mode_and_ineffective_file_protection_refuse(self):
        file = self.directory / "file"
        file.touch()
        descriptor = os.open(file, os.O_RDONLY)
        try:
            file.chmod(0o4777)
            special = os.fstat(descriptor)
            with self.assertRaisesRegex(ValueError, "special mode"):
                protection.seal_file(descriptor, special)
            file.chmod(0o777)
            before = os.fstat(descriptor)
            with patch.object(os, "fchmod"):
                with self.assertRaisesRegex(ValueError, "not established"):
                    protection.seal_file(descriptor, before)
        finally:
            os.close(descriptor)

    def test_cli_requires_sudo_identity_and_passes_only_the_selected_location(self):
        location = "/opt/hostedtoolcache/Python/3.13.18/x64"
        for arguments, uid, sudo_uid in ((["tool"], 0, "1000"), (["tool", location], 1000, "1000"),
                                        (["tool", location], 0, ""), (["tool", location], 0, "0")):
            with self.subTest(arguments=arguments, uid=uid, sudo_uid=sudo_uid), \
                    patch.object(sys, "argv", arguments), patch.object(os, "geteuid", return_value=uid), \
                    patch.dict(os.environ, {"SUDO_UID": sudo_uid}), \
                    patch.object(protection, "protect_hosted_python") as protect:
                with self.assertRaises(SystemExit):
                    protection.main()
                protect.assert_not_called()
        with patch.object(sys, "argv", ["tool", location]), patch.object(os, "geteuid", return_value=0), \
                patch.dict(os.environ, {"SUDO_UID": "1000"}), \
                patch.object(protection, "protect_hosted_python") as protect, \
                patch("sys.stdout", new_callable=io.StringIO):
            protection.main()
        protect.assert_called_once_with(location, 1000)
