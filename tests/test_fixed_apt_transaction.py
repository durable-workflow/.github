"""Exercise fencing and actual kernel lock contention without root effects."""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from scripts import fixed_apt_transaction as transaction


class FixedAptTransactionTest(unittest.TestCase):
    def unit_runner(self, *, active_service=False):
        calls = []
        masked = False

        def run(argv, **options):
            nonlocal masked
            calls.append((argv, options))
            output = b""
            if "daemon-reload" in argv:
                masked = True
            if "show" in argv:
                active = "active" if active_service and argv[-1] in transaction.SERVICES else "inactive"
                output = (f"LoadState={'masked' if masked else 'loaded'}\n"
                          f"ActiveState={active}\n"
                          f"UnitFileState={'masked-runtime' if masked else 'enabled'}\n").encode()
            return subprocess.CompletedProcess(argv, 0, output, b"")
        return run, calls

    def test_service_masks_precede_timer_stop_and_all_masks_remain(self):
        run, calls = self.unit_runner()
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            original, identities = transaction.fence_units(run=run, directory=directory)
            self.assertEqual(set(transaction.SERVICES + transaction.TIMERS), set(original))
            self.assertEqual(set(original), set(identities))
            self.assertTrue(all((directory / unit).is_symlink() for unit in identities))
            stops = [argv for argv, _ in calls if "stop" in argv]
            self.assertEqual([["/usr/bin/systemctl", "stop", *transaction.TIMERS]], stops)
            transaction.check_fence(identities, run=run, directory=directory)
            (directory / transaction.SERVICES[0]).unlink()
            (directory / transaction.SERVICES[0]).symlink_to("/foreign")
            with self.assertRaisesRegex(ValueError, "mask identity changed"):
                transaction.check_fence(identities, run=run, directory=directory)

    def test_active_package_service_is_never_stopped(self):
        run, calls = self.unit_runner(active_service=True)
        with tempfile.TemporaryDirectory() as root, self.assertRaisesRegex(ValueError, "active"):
            transaction.fence_units(run=run, directory=Path(root))
        self.assertFalse(any("stop" in argv for argv, _ in calls))

    def test_preexisting_mask_is_not_replaced(self):
        run, calls = self.unit_runner()
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / transaction.SERVICES[0]
            path.symlink_to("/existing-owner")
            with self.assertRaises(FileExistsError):
                transaction.fence_units(run=run, directory=Path(root))
            self.assertEqual("/existing-owner", os.readlink(path))
        self.assertFalse(any("stop" in argv for argv, _ in calls))

    def test_real_posix_contention_refuses_then_released_lock_succeeds(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "lock"
            path.touch()
            source = "import fcntl,sys; f=open(sys.argv[1],'r+'); fcntl.lockf(f,fcntl.LOCK_EX); print('locked',flush=True); sys.stdin.read(1)"
            with subprocess.Popen([sys.executable, "-I", "-S", "-c", source, str(path)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE) as holder:
                self.assertEqual(b"locked\n", holder.stdout.readline())
                with self.assertRaises(BlockingIOError):
                    transaction.acquire_lock(path, owner=os.getuid())
                holder.communicate(b"x", timeout=5)
            descriptor = transaction.acquire_lock(path, owner=os.getuid())
            os.close(descriptor)

    def test_linked_or_aliased_lock_refuses(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "lock"
            path.touch()
            alias = Path(root) / "alias"
            alias.hardlink_to(path)
            with self.assertRaisesRegex(ValueError, "identity"):
                transaction.acquire_lock(path, owner=os.getuid())
            alias.unlink()
            alias.symlink_to(path)
            with self.assertRaises(OSError):
                transaction.acquire_lock(alias, owner=os.getuid())

    def test_live_package_process_and_unknown_process_read_refuse(self):
        with tempfile.TemporaryDirectory() as root:
            process = Path(root) / "12"
            process.mkdir()
            (process / "comm").write_text("apt-get\n")
            with self.assertRaisesRegex(ValueError, "active"):
                transaction.check_processes(Path(root))
            (process / "comm").write_text("ordinary-process\n")
            transaction.check_processes(Path(root))
            with patch.object(Path, "read_text", side_effect=PermissionError), self.assertRaises(PermissionError):
                transaction.check_processes(Path(root))

    def transaction_runner(self, *, dry_failure=False, bad_pair=False):
        calls = []
        installed = False

        def run(argv, **options):
            nonlocal installed
            calls.append((argv, options))
            output = b""
            if "--no-act" in argv and dry_failure:
                raise subprocess.CalledProcessError(1, argv)
            if "/usr/bin/unshare" in argv and "--no-act" not in argv:
                installed = True
            if "/usr/bin/dpkg-query" in argv:
                version = "3.2.1ubuntu0.1" if installed else "3.2.0"
                output = f"apt install ok installed {version}\nlibapt-pkg7.0 install ok installed {version}\n".encode()
                if installed and bad_pair:
                    output = output.replace(b"libapt-pkg7.0 install ok", b"libapt-pkg7.0 hold ok")
            if "/usr/bin/apt-get" in argv:
                output = b"apt 3.2.1ubuntu0.1 (amd64)\n"
            return subprocess.CompletedProcess(argv, 0, output, b"")
        return run, calls

    def run_transaction(self, run):
        descriptors = [os.open(os.devnull, os.O_RDONLY) for _ in range(2)]
        masks = {unit: (1, 2) for unit in transaction.SERVICES + transaction.TIMERS}
        with patch.object(transaction, "verify_packages"), \
                patch.object(transaction, "acquire_lock", side_effect=descriptors), \
                patch.object(transaction, "check_processes"), \
                patch.object(transaction, "fence_units", return_value=({}, masks)), \
                patch.object(transaction, "check_fence"):
            return transaction.transact(Path("/run/dw-fixed-apt.aB123456"), run=run)

    def test_dry_run_refusal_never_starts_installation(self):
        run, calls = self.transaction_runner(dry_failure=True)
        with self.assertRaises(subprocess.CalledProcessError):
            self.run_transaction(run)
        dpkg = [argv for argv, _ in calls if "/usr/bin/unshare" in argv]
        self.assertEqual(1, len(dpkg))
        self.assertIn("--no-act", dpkg[0])

    def test_pair_failure_cannot_return_success_or_restore_acquisition(self):
        run, calls = self.transaction_runner(bad_pair=True)
        with self.assertRaisesRegex(ValueError, "pair differs"):
            self.run_transaction(run)
        self.assertFalse(any("unmask" in argv or "start" in argv for argv, _ in calls))

    def test_success_keeps_offline_dpkg_and_original_frontend_lock_semantics(self):
        run, calls = self.transaction_runner()
        receipt = self.run_transaction(run)
        self.assertIs(True, receipt["installed"])
        dpkg = [(argv, options) for argv, options in calls if "/usr/bin/unshare" in argv]
        self.assertEqual(2, len(dpkg))
        for argv, options in dpkg:
            self.assertEqual(["/usr/bin/unshare", "--net", "--", "/usr/bin/dpkg"], argv[:4])
            self.assertEqual("1", options["env"]["DPKG_FRONTEND_LOCKED"])
        self.assertEqual(sorted(transaction.SERVICES + transaction.TIMERS), receipt["runtime_masks_retained"])


if __name__ == "__main__":
    unittest.main()
