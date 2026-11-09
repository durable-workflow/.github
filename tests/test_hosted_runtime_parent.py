"""Controls for the fixed hosted /opt repair; never change the host's /opt."""

import importlib.util
import os
from pathlib import Path
import stat
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
                protection.seal_tree(descriptor, os.getuid())
        finally:
            os.close(descriptor)
        self.assertEqual(0o666, stat.S_IMODE(outside.stat().st_mode))
        (self.directory / "hardlink").unlink()
        os.mkfifo(self.directory / "fifo")
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            with self.assertRaisesRegex(ValueError, "private regular"):
                protection.seal_tree(descriptor, os.getuid())
        finally:
            os.close(descriptor)

    def test_noncanonical_hosted_location_refuses_before_opening_any_path(self):
        for location in ("/tmp/python", "/opt/hostedtoolcache/Python/3.13.18/../../other",
                         "/opt/hostedtoolcache/Python/3.13.18/x86", "//opt/hostedtoolcache/Python/3.13.18/x64"):
            with self.subTest(location=location), patch.object(os, "open") as opened:
                with self.assertRaisesRegex(ValueError, "fixed hosted"):
                    protection.protect_hosted_python(location, os.getuid())
                opened.assert_not_called()
