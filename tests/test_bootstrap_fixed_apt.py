import io
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import bootstrap_fixed_apt as bootstrap


class FixedAptBootstrapTest(unittest.TestCase):
    def test_exact_publisher_inputs_are_captured_before_any_root_command(self):
        rows = bootstrap.capture_packages(bootstrap.ROOT / "qualification/apt-resolute")
        self.assertEqual([row[0] for row in bootstrap.PACKAGES], [row[0] for row in rows])
        self.assertEqual([row[1] for row in bootstrap.PACKAGES], [len(row[1]) for row in rows])

    def test_changed_linked_or_hardlinked_package_input_refuses(self):
        source = bootstrap.ROOT / "qualification/apt-resolute"
        name = bootstrap.PACKAGES[0][0]
        for kind in ("changed", "symlink", "hardlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for filename, _, _ in bootstrap.PACKAGES:
                    shutil.copyfile(source / filename, root / filename)
                if kind == "changed":
                    with (root / name).open("r+b") as handle:
                        handle.write(b"changed")
                elif kind == "symlink":
                    (root / name).unlink()
                    (root / name).symlink_to(source / name)
                else:
                    (root / "alias").hardlink_to(root / name)
                with self.assertRaises((ValueError, OSError)):
                    bootstrap.capture_packages(root)

    def runner(self, *, wrong_hash=False, dry_failure=False):
        calls = []
        private = "/run/dw-fixed-apt.aB123456"
        rows = [("lib.deb", b"immutable-library", "a" * 64), ("apt.deb", b"immutable-apt", "b" * 64)]

        def run(arguments, **options):
            calls.append((arguments, options))
            output = b""
            if "/usr/bin/mktemp" in arguments:
                output = (private + "\n").encode()
            if "/usr/bin/sha256sum" in arguments:
                output = "".join(digest + "  " + private + "/" + name + "\n" for name, _, digest in rows).encode()
                if wrong_hash:
                    output = output.replace(b"a", b"c", 1)
            if dry_failure and "--no-act" in arguments:
                raise subprocess.CalledProcessError(1, arguments)
            return subprocess.CompletedProcess(arguments, 0, output, b"")
        return run, calls, rows

    def test_verified_bytes_are_staged_via_stdin_and_dpkg_has_no_network(self):
        run, calls, rows = self.runner()
        bootstrap.install(rows, run=run)
        writes = [(argv, options) for argv, options in calls if "/usr/bin/tee" in argv]
        self.assertEqual([row[1] for row in rows], [options["input"] for _, options in writes])
        installs = [argv for argv, _ in calls if "/usr/bin/dpkg" in argv]
        self.assertEqual(2, len(installs))
        self.assertIn("--no-act", installs[0])
        self.assertNotIn("--no-act", installs[1])
        for argv, options in calls:
            self.assertEqual(bootstrap.CLEAN_ENV, options["env"])
            self.assertTrue(options["check"])
            if "/usr/bin/dpkg" in argv:
                self.assertEqual(["/usr/bin/sudo", "-n", "/usr/bin/unshare", "--net", "--"], argv[:5])
            self.assertFalse(any("apt-get" in word for word in argv))
        self.assertIn("/usr/bin/rm", calls[-2][0])
        self.assertIn("/usr/bin/rmdir", calls[-1][0])

    def test_root_copy_substitution_refuses_before_dpkg_and_cleans_exact_files(self):
        run, calls, rows = self.runner(wrong_hash=True)
        with self.assertRaisesRegex(ValueError, "copy differs"):
            bootstrap.install(rows, run=run)
        self.assertFalse(any("/usr/bin/dpkg" in argv for argv, _ in calls))
        self.assertIn("/usr/bin/rm", calls[-2][0])

    def test_dependency_dry_run_failure_never_reaches_real_install(self):
        run, calls, rows = self.runner(dry_failure=True)
        with self.assertRaises(subprocess.CalledProcessError):
            bootstrap.install(rows, run=run)
        installs = [argv for argv, _ in calls if "/usr/bin/dpkg" in argv]
        self.assertEqual(1, len(installs))
        self.assertIn("--no-act", installs[0])

    def test_default_plan_has_no_root_effect(self):
        with patch.object(bootstrap.sys, "argv", ["bootstrap"]), \
                patch.object(bootstrap.sys, "stdout", io.StringIO()) as output, \
                patch.object(bootstrap, "install") as install:
            self.assertEqual(0, bootstrap.main())
        install.assert_not_called()
        self.assertIs(False, json.loads(output.getvalue())["installed"])

    def test_local_or_other_platform_installation_refuses(self):
        with patch.object(bootstrap.sys, "argv", ["bootstrap", "--install"]), \
                patch.dict(bootstrap.os.environ, {}, clear=True), \
                patch.object(bootstrap, "install") as install, \
                patch.object(bootstrap.sys, "stderr", io.StringIO()):
            self.assertEqual(1, bootstrap.main())
        install.assert_not_called()

    def test_unknown_arguments_refuse_before_capturing_inputs(self):
        with patch.object(bootstrap.sys, "argv", ["bootstrap", "--path=other"]), \
                patch.object(bootstrap, "capture_packages") as capture, \
                patch.object(bootstrap.sys, "stderr", io.StringIO()):
            self.assertEqual(1, bootstrap.main())
        capture.assert_not_called()


if __name__ == "__main__":
    unittest.main()
