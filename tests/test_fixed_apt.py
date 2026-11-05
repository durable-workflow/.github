import io
import json
from contextlib import contextmanager
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml

from scripts import require_fixed_apt as guard

ROOT = Path(__file__).resolve().parents[1]
APT_ONLY = runpy.run_path(str(ROOT / "tests/fixtures/apt_only_predecessor.py"))["require_fixed_apt"]


class FixedAptTest(unittest.TestCase):
    @contextmanager
    def native_database(self, *, apt_status="install ok installed", library_status="install ok installed",
                        library_version="3.2.1ubuntu0.1", include_library=True,
                        apt_arch="amd64", library_arch="amd64"):
        with tempfile.TemporaryDirectory() as directory:
            rows = [("apt", apt_status, "3.2.1ubuntu0.1", apt_arch)]
            if include_library:
                rows.append(("libapt-pkg7.0", library_status, library_version, library_arch))
            status = "".join(f"Package: {name}\nStatus: {state}\nArchitecture: {architecture}\nVersion: {version}\n"
                             "Maintainer: Test <test@example.invalid>\nDescription: Synthetic package state\n\n"
                             for name, state, version, architecture in rows)
            (Path(directory) / "status").write_text(status)

            def run(argv, **options):
                if argv[0] == "/usr/bin/dpkg-query":
                    argv = [argv[0], "--admindir=" + directory, *argv[1:]]
                return subprocess.run(argv, **options)
            yield run

    def test_actual_predecessor_accepts_affected_or_missing_library_but_successor_refuses(self):
        release = {"ID": "ubuntu", "VERSION_ID": "26.04"}
        for values in ({"library_version": "3.2.0"}, {"include_library": False}):
            with self.subTest(values=values), self.native_database(**values) as run:
                self.assertIs(True, APT_ONLY(release, run)["fixed_apt"])
                with self.assertRaises(ValueError):
                    guard.require_fixed_apt(release, run)

    def test_native_full_status_closes_eight_actual_predecessor_admissions(self):
        release = {"ID": "ubuntu", "VERSION_ID": "26.04"}
        for field in ("apt_status", "library_status"):
            for state in ("install reinstreq installed", "deinstall ok installed", "purge ok installed", "hold ok installed"):
                with self.subTest(field=field, state=state), self.native_database(**{field: state}) as run:
                    self.assertIs(True, APT_ONLY(release, run)["fixed_apt"])
                    with self.assertRaises(ValueError):
                        guard.require_fixed_apt(release, run)

    def test_native_clean_pair_is_reported_completely(self):
        with self.native_database() as run:
            report = guard.require_fixed_apt({"ID": "ubuntu", "VERSION_ID": "26.04"}, run)
        self.assertEqual("3.2.1ubuntu0.1", report["apt"])
        self.assertEqual("3.2.1ubuntu0.1", report["libapt"])
        self.assertEqual("libapt-pkg7.0", report["libapt_package"])
        self.assertEqual("amd64", report["architecture"])

    def test_native_database_with_foreign_or_mixed_pair_refuses(self):
        release = {"ID": "ubuntu", "VERSION_ID": "26.04"}
        for values in ({"apt_arch": "arm64"}, {"library_arch": "arm64"},
                       {"apt_arch": "arm64", "library_arch": "arm64"}):
            with self.subTest(values=values), self.native_database(**values) as run:
                self.assertIs(True, APT_ONLY(release, run)["fixed_apt"])
                with self.assertRaisesRegex(ValueError, "architecture"):
                    guard.require_fixed_apt(release, run)

    def reader(self, version, status="install ok installed", library_version=None, architecture="amd64"):
        def run(argv, **options):
            if argv[0] == "/usr/bin/dpkg-query":
                library = argv[-1]
                return subprocess.CompletedProcess(argv, 0, f"apt\t{status}\t{version}\t{architecture}\n{library}\t{status}\t{library_version or version}\t{architecture}\n", "")
            if argv[1:] == ["--print-architecture"]:
                return subprocess.CompletedProcess(argv, 0, architecture + "\n", "")
            return subprocess.run(argv, **options)
        return run

    def test_exact_fixed_floors_and_later_security_revisions_pass(self):
        for (system, release), minimum in guard.FIXED.items():
            for version in (minimum, minimum + "+update1"):
                with self.subTest(system=system, release=release, version=version):
                    report = guard.require_fixed_apt({"ID": system, "VERSION_ID": release}, self.reader(version))
                    self.assertIs(True, report["fixed_apt"])
                    self.assertEqual(version, report["apt"])
                    self.assertEqual(version, report["libapt"])
                    self.assertEqual(guard.LIBRARIES[system, release], report["libapt_package"])

    def test_arm64_pair_passes_with_matching_native_architecture(self):
        report = guard.require_fixed_apt({"ID": "ubuntu", "VERSION_ID": "26.04"},
                                         self.reader("3.2.1ubuntu0.1", architecture="arm64"))
        self.assertEqual("arm64", report["architecture"])

    def test_known_affected_and_partial_ubuntu_versions_refuse(self):
        cases = (("ubuntu", "22.04", "2.4.14"), ("ubuntu", "24.04", "2.8.3"),
                 ("ubuntu", "26.04", "3.2.1"), ("ubuntu", "26.10", "3.3.3"),
                 ("debian", "13", "3.0.3"))
        for system, release, version in cases:
            read = self.reader(version)
            with self.subTest(system=system, release=release), self.assertRaisesRegex(ValueError, "fixed"):
                guard.require_fixed_apt({"ID": system, "VERSION_ID": release}, read)

    def test_unknown_release_refuses_before_any_package_command(self):
        run = Mock()
        for release in ({}, {"ID": "ubuntu", "VERSION_ID": "future"}, {"ID": "other", "VERSION_ID": "13"}):
            with self.subTest(release=release), self.assertRaises(ValueError):
                guard.require_fixed_apt(release, run)
        run.assert_not_called()

    def test_missing_ambiguous_or_not_installed_package_refuses(self):
        for raw in ("", "installed\t2.8.4ubuntu0.1\ninstalled\t2.8.4ubuntu0.1", "config-files\t2.8.4ubuntu0.1", "installed\tbad version"):
            run = Mock(return_value=subprocess.CompletedProcess([], 0, raw, ""))
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                guard.require_fixed_apt({"ID": "ubuntu", "VERSION_ID": "24.04"}, run)
            self.assertEqual(1, run.call_count)

    def test_native_commands_are_absolute_read_only_and_use_a_closed_environment(self):
        run = Mock(side_effect=[subprocess.CompletedProcess([], 0, "apt\tinstall ok installed\t2.8.4ubuntu0.1\tamd64\nlibapt-pkg6.0t64\tinstall ok installed\t2.8.4ubuntu0.1\tamd64\n", ""),
                                subprocess.CompletedProcess([], 0, "amd64\n", ""),
                                subprocess.CompletedProcess([], 0, "", ""),
                                subprocess.CompletedProcess([], 0, "", "")])
        guard.require_fixed_apt({"ID": "ubuntu", "VERSION_ID": "24.04"}, run)
        self.assertEqual(["/usr/bin/dpkg-query", "/usr/bin/dpkg", "/usr/bin/dpkg", "/usr/bin/dpkg"], [call.args[0][0] for call in run.call_args_list])
        for call in run.call_args_list:
            self.assertEqual({"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, call.kwargs["env"])
            self.assertEqual(10, call.kwargs["timeout"])

    def test_native_query_failure_or_comparison_error_cannot_pass(self):
        for first, second in ((1, 0), (0, 2)):
            run = Mock(side_effect=[subprocess.CompletedProcess([], first, "apt\tinstall ok installed\t2.8.4ubuntu0.1\tamd64\nlibapt-pkg6.0t64\tinstall ok installed\t2.8.4ubuntu0.1\tamd64\n", ""),
                                    subprocess.CompletedProcess([], 0, "amd64\n", ""),
                                    subprocess.CompletedProcess([], second, "", "")])
            with self.subTest(first=first, second=second), self.assertRaises(ValueError):
                guard.require_fixed_apt({"ID": "ubuntu", "VERSION_ID": "24.04"}, run)

    def test_command_reports_effective_version_and_refuses_overrides(self):
        report = {"os": "ubuntu", "release": "24.04", "apt": "2.8.4ubuntu0.1", "fixed_apt": True}
        with patch.object(guard.sys, "argv", ["require-fixed-apt"]), \
                patch.object(guard, "require_fixed_apt", return_value=report), \
                patch.object(guard.sys, "stdout", io.StringIO()) as output:
            self.assertEqual(0, guard.main())
        self.assertIs(True, json.loads(output.getvalue())["fixed_apt"])
        with patch.object(guard.sys, "argv", ["require-fixed-apt", "--version=override"]), \
                patch.object(guard, "require_fixed_apt") as require, \
                patch.object(guard.sys, "stderr", io.StringIO()) as errors:
            self.assertEqual(1, guard.main())
        require.assert_not_called()
        self.assertIs(False, json.loads(errors.getvalue())["fixed_apt"])

    def test_read_only_guard_is_not_a_blanket_source_ci_gate(self):
        for filename in ("ci.yml", "sonar.yml"):
            workflow = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
            for job in workflow["jobs"].values():
                for step in job.get("steps", []):
                    self.assertNotIn("require_fixed_apt.py", step.get("run", ""))
                    self.assertNotIn("require-fixed-apt", step.get("uses", ""))

    def test_reusable_action_uses_its_own_canonical_script_without_a_consumer_checkout(self):
        path = ROOT / ".github/actions/require-fixed-apt/action.yml"
        action = yaml.safe_load(path.read_text())
        self.assertNotIn("inputs", action)
        self.assertEqual("composite", action["runs"]["using"])
        step, = action["runs"]["steps"]
        self.assertEqual('/usr/bin/python3 -I -S -B "$FIXED_APT_PROGRAM"', step["run"])
        source = step["env"]["FIXED_APT_PROGRAM"]
        self.assertEqual("${{ github.action_path }}/../../../scripts/require_fixed_apt.py", source)
        self.assertEqual(ROOT / "scripts/require_fixed_apt.py",
                         (path.parent / "../../../scripts/require_fixed_apt.py").resolve())


if __name__ == "__main__":
    unittest.main()
