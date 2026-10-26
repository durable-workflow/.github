"""Qualify the policy parser wheels in an isolated, task-owned Python venv."""

import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
REQUIREMENTS = ROOT / "qualification/requirements.lock"
RELATIVE_REQUIREMENTS = ".central-action-policy/qualification/requirements.lock"
INSTALL_FLAGS = ["--require-hashes", "--only-binary=:all:", "--no-deps"]


class PolicyDependencyInstallTest(unittest.TestCase):
    def setUp(self):
        import pip

        self.assertNotEqual(sys.prefix, sys.base_prefix, "Use a disposable venv")
        self.assertEqual("26.2.2", pip.__version__)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        self.environment = dict(os.environ)
        for name in ("PYTHONPATH", "PYTHONSAFEPATH", "PIP_EXTRA_INDEX_URL", "PIP_TRUSTED_HOST"):
            self.environment.pop(name, None)
        self.environment.update({
            "PIP_CONFIG_FILE": os.devnull,
            "PIP_INDEX_URL": "https://pypi.org/simple",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "PIP_RETRIES": "0",
            "PIP_DEFAULT_TIMEOUT": "15",
        })

    def pip(self, arguments, directory=None, isolated=True):
        return subprocess.run(
            [sys.executable, *(["-I"] if isolated else []), "-m", "pip",
             *(["--isolated"] if isolated else []), *arguments],
            cwd=directory or self.directory, env=self.environment,
            capture_output=True, text=True, timeout=60,
        )

    def test_actual_installer_ignores_both_working_directory_shadows(self):
        for kind in ("module", "package"):
            with self.subTest(shadow=kind):
                removed = self.pip(["uninstall", "--yes", "PyYAML"])
                self.assertEqual(0, removed.returncode, removed.stdout + removed.stderr)
                directory = self.directory / kind
                directory.mkdir()
                lock = directory / RELATIVE_REQUIREMENTS
                lock.parent.mkdir(parents=True)
                shutil.copyfile(REQUIREMENTS, lock)
                module = directory / "pip.py"
                if kind == "package":
                    module = directory / "pip/__init__.py"
                    module.parent.mkdir()
                module.write_text("from pathlib import Path\nPath('shadow-ran').write_text('executed')\nraise SystemExit(29)\n")
                raw = self.pip(["--version"], directory, isolated=False)
                self.assertEqual(29, raw.returncode, raw.stderr)
                marker = directory / "shadow-ran"
                self.assertTrue(marker.is_file())
                marker.unlink()
                installed = self.pip(["install", *INSTALL_FLAGS, "-r", RELATIVE_REQUIREMENTS], directory)
                self.assertEqual(0, installed.returncode, installed.stdout + installed.stderr)
                self.assertFalse(marker.exists())
                loaded = subprocess.run(
                    [sys.executable, "-I", "-c", "import sys,yaml; from pathlib import Path; assert yaml.__version__ == '6.0.2'; assert yaml.__with_libyaml__; assert Path(yaml.__file__).is_relative_to(sys.prefix)"],
                    cwd=directory, env=self.environment, capture_output=True, text=True, timeout=10,
                )
                self.assertEqual(0, loaded.returncode, loaded.stderr)

    def test_a_tampered_wheel_hash_cannot_download(self):
        lock = self.directory / "tampered.lock"
        lock.write_text(re.sub(r"sha256:[0-9a-f]{64}", "sha256:" + "0" * 64, REQUIREMENTS.read_text()))
        destination = self.directory / "rejected"
        result = self.pip(["download", *INSTALL_FLAGS, "--no-cache-dir", "--dest", str(destination), "-r", str(lock)])
        self.assertNotEqual(0, result.returncode)
        self.assertIn("DO NOT MATCH THE HASHES", result.stdout + result.stderr)
        self.assertEqual([], list(destination.glob("*.whl")))


if __name__ == "__main__":
    unittest.main()
