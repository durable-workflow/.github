import io
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import Mock, patch

import yaml

from scripts import require_fixed_apt as guard

ROOT = Path(__file__).resolve().parents[1]


class FixedAptTest(unittest.TestCase):
    def reader(self, version, status="installed"):
        def run(argv, **options):
            if argv[0] == "/usr/bin/dpkg-query":
                return subprocess.CompletedProcess(argv, 0, f"{status}\t{version}\n", "")
            return subprocess.run(argv, **options)
        return run

    def test_exact_fixed_floors_and_later_security_revisions_pass(self):
        for (system, release), minimum in guard.FIXED.items():
            for version in (minimum, minimum + "+update1"):
                with self.subTest(system=system, release=release, version=version):
                    report = guard.require_fixed_apt({"ID": system, "VERSION_ID": release}, self.reader(version))
                    self.assertIs(True, report["fixed_apt"])
                    self.assertEqual(version, report["apt"])

    def test_known_affected_and_partial_ubuntu_versions_refuse(self):
        cases = (("ubuntu", "22.04", "2.4.14"), ("ubuntu", "24.04", "2.8.3"),
                 ("ubuntu", "26.04", "3.2.1"), ("ubuntu", "26.10", "3.3.3"),
                 ("debian", "13", "3.0.3"))
        for system, release, version in cases:
            with self.subTest(system=system, release=release), self.assertRaisesRegex(ValueError, "fixed"):
                guard.require_fixed_apt({"ID": system, "VERSION_ID": release}, self.reader(version))

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
        run = Mock(side_effect=[subprocess.CompletedProcess([], 0, "installed\t2.8.4ubuntu0.1\n", ""),
                                subprocess.CompletedProcess([], 0, "", "")])
        guard.require_fixed_apt({"ID": "ubuntu", "VERSION_ID": "24.04"}, run)
        self.assertEqual(["/usr/bin/dpkg-query", "/usr/bin/dpkg"], [call.args[0][0] for call in run.call_args_list])
        for call in run.call_args_list:
            self.assertEqual({"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, call.kwargs["env"])
            self.assertEqual(10, call.kwargs["timeout"])

    def test_native_query_failure_or_comparison_error_cannot_pass(self):
        for first, second in ((1, 0), (0, 2)):
            run = Mock(side_effect=[subprocess.CompletedProcess([], first, "installed\t2.8.4ubuntu0.1\n", ""),
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

    def test_preflight_precedes_every_setup_action_in_affected_jobs(self):
        for filename in ("ci.yml", "sonar.yml"):
            workflow = yaml.safe_load((ROOT / ".github/workflows" / filename).read_text())
            job = workflow["jobs"]["contracts" if filename == "ci.yml" else "analysis"]
            steps = job["steps"]
            position = next(index for index, step in enumerate(steps) if step.get("run") == "/usr/bin/python3 -I scripts/require_fixed_apt.py")
            self.assertEqual(1, position)
            self.assertTrue(steps[0]["uses"].startswith("actions/checkout@"))
            self.assertNotIn("continue-on-error", steps[position])
            self.assertNotIn("if", steps[position])


if __name__ == "__main__":
    unittest.main()
