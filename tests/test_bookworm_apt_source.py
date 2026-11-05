"""Run the shared shell with inert release/package records, never APT or an image."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "docker/apt/require-fixed-bookworm-apt.sh"
RECORD = ROOT / "docker/apt/php-8.4.27-cli-bookworm.v1.json"


class BookwormAptSourceTest(unittest.TestCase):
    def run_guard(self, rows=None, release='ID=debian\nVERSION_ID="12"\n', native="amd64",
                  query_status=0, arguments=()):
        if rows is None:
            rows = ["apt|install ok installed|2.6.2|amd64",
                    "libapt-pkg6.0|install ok installed|2.6.2|amd64"]
        with tempfile.TemporaryDirectory(prefix="cli-bookworm-inert-") as temporary:
            directory = Path(temporary)
            (directory / "release").write_text(release)
            (directory / "rows").write_text("\n".join(rows) + "\n")
            (directory / "native").write_text(native + "\n")
            query = directory / "query"
            query.write_text("#!/bin/sh\nset -eu\n"
                "test -z \"${GITHUB_TOKEN+x}\"\n"
                "test -z \"${LD_PRELOAD+x}\"\n"
                "test \"$#\" -eq 4\n"
                f"/bin/cat {directory}/rows\nexit {query_status}\n")
            dpkg = directory / "dpkg"
            dpkg.write_text("#!/bin/sh\nset -eu\n"
                "test -z \"${GITHUB_TOKEN+x}\"\n"
                "if [ \"$#\" -eq 1 ] && [ \"$1\" = --print-architecture ]; then\n"
                f" /bin/cat {directory}/native\n"
                "else\n exec /usr/bin/dpkg \"$@\"\nfi\n")
            query.chmod(0o700)
            dpkg.chmod(0o700)
            source = SOURCE.read_text()
            for key, value in {"RELEASE": directory / "release", "QUERY": query, "DPKG": dpkg}.items():
                old = next(line for line in source.splitlines() if line.startswith(key + "="))
                source = source.replace(old, key + "=" + str(value), 1)
            program = directory / "guard.sh"
            program.write_text(source)
            return subprocess.run(["/bin/sh", str(program), *arguments],
                env={"PATH": "/no-tools-or-python", "LC_ALL": "C", "GITHUB_TOKEN": "inert-fixture"},
                capture_output=True, text=True, check=False, timeout=5)

    def test_fixed_pair_passes_both_native_architectures_without_python_or_path_tools(self):
        for arch in ("amd64", "arm64"):
            with self.subTest(arch=arch):
                rows = [f"{package}|install ok installed|2.6.2|{arch}"
                        for package in ("apt", "libapt-pkg6.0")]
                result = self.run_guard(rows, native=arch)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertIn("fixed_bookworm_apt=true", result.stdout)
                self.assertIn("architecture=" + arch, result.stdout)

    def test_original_parent_and_one_unfixed_member_refuse_before_any_network_operation(self):
        for apt, library in (("2.6.1", "2.6.1"), ("2.6.2", "2.6.1"), ("2.6.1", "2.6.2")):
            with self.subTest(apt=apt, library=library):
                result = self.run_guard([f"apt|install ok installed|{apt}|amd64",
                    f"libapt-pkg6.0|install ok installed|{library}|amd64"])
                self.assertNotEqual(0, result.returncode)
                self.assertNotIn("=true", result.stdout)

    def test_status_package_version_and_architecture_ambiguity_refuse(self):
        good = ["apt|install ok installed|2.6.2|amd64", "libapt-pkg6.0|install ok installed|2.6.2|amd64"]
        variants = [[], good[:1], good + good[:1], good + ["foreign|install ok installed|2.6.2|amd64"]]
        for index in (0, 1):
            for old, new in (("install ok installed", "deinstall ok config-files"),
                             ("2.6.2", ""), ("2.6.2", "not-a-version"), ("2.6.2", "2.6.2;false"),
                             ("2.6.2", "2" * 101), ("amd64", "arm64"), ("amd64", "all")):
                changed = good.copy()
                changed[index] = changed[index].replace(old, new)
                variants.append(changed)
        variants += [good[:1] + [""] + good[1:], [good[0] + "|extra", good[1]]]
        for rows in variants:
            with self.subTest(rows=rows):
                self.assertNotEqual(0, self.run_guard(rows).returncode)
        for native in ("arm64", "all", "amd64\narm64", ""):
            with self.subTest(native=native):
                self.assertNotEqual(0, self.run_guard(native=native).returncode)
        self.assertNotEqual(0, self.run_guard(query_status=1).returncode)

    def test_effective_release_is_read_as_data_with_no_overrides(self):
        for release in ('ID=ubuntu\nVERSION_ID="12"\n', 'ID=debian\nVERSION_ID="13"\n',
                        'ID=debian\n', 'ID=debian\nID=debian\nVERSION_ID=12\n',
                        'ID=debian\nVERSION_ID=12\nVERSION_ID=12\n',
                        'ID=$(false)\nVERSION_ID=12\n'):
            with self.subTest(release=release):
                self.assertNotEqual(0, self.run_guard(release=release).returncode)
        self.assertNotEqual(0, self.run_guard(arguments=("--version=2.6.2",)).returncode)

    def test_metadata_records_old_and_fixed_pairs_for_same_php_and_both_platforms(self):
        record = json.loads(RECORD.read_text())
        self.assertEqual("publisher-source-inventory-only", record["scope"])
        self.assertEqual("8.4.27", record["php_version"])
        self.assertEqual({"id": "debian", "version_id": "12"}, record["os"])
        self.assertFalse(any(record["inventory"].values()))
        for name, version in (("predecessor", "2.6.1"), ("candidate", "2.6.2")):
            parent = record["parents"][name]
            self.assertEqual({"linux/amd64", "linux/arm64"}, set(parent["platforms"]))
            for platform in parent["platforms"].values():
                self.assertEqual({"apt": version, "libapt-pkg6.0": version}, platform["packages"])
                for kind in ("child", "config", "attestation", "spdx"):
                    self.assertRegex(platform[kind]["digest"], r"^sha256:[0-9a-f]{64}$")
                    self.assertGreater(platform[kind]["size"], 0)


if __name__ == "__main__":
    unittest.main()
