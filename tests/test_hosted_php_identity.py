import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from scripts import hosted_php_identity as identity


class HostedPhpIdentityTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.tools = {name: str(root / name) for name in ("php", "composer", "phpunit")}
        for path in self.tools.values():
            Path(path).write_text(Path(path).name)
        self.ini = root / "php.ini"
        self.ini.write_text("memory_limit=128M")
        scanned = root / "10-posix.ini"
        scanned.write_text("extension=posix")
        modules = root / "modules"
        modules.mkdir()
        (modules / "posix.so").write_bytes(b"module")
        self.configuration = {
            "version": "8.3.37", "binary": self.tools["php"], "ini": str(self.ini), "scanned": str(scanned),
            "extension_directory": str(modules), "extensions": ["standard", "posix"],
        }
        self.output = root / "output"

    def snapshot(self):
        with patch.object(identity.shutil, "which", side_effect=lambda name, *, path: self.tools.get(name)), \
             patch.object(identity.subprocess, "check_output", return_value=json.dumps(self.configuration)) as probe:
            result = identity.runtime_identity()
        probe.assert_called_once_with([self.tools["php"], "-r", identity.PHP_CONFIGURATION],
                                      env={"PATH": identity.PATH, "LANG": "C.UTF-8"}, timeout=10)
        return result

    def test_actual_paths_configuration_and_modules_are_bound(self):
        original = self.snapshot()
        self.assertEqual(["posix", "standard"], original["extensions"])
        self.assertEqual(list(self.tools), list(original["tools"]))
        self.assertEqual(2, len(original["ini"]))
        self.assertEqual(1, len(original["modules"]))
        self.ini.write_text("memory_limit=256M")
        changed = self.snapshot()
        self.assertNotEqual(original["ini"], changed["ini"])
        self.assertEqual(original["tools"], changed["tools"])

    def test_missing_tool_and_wrong_php_binary_refuse(self):
        with patch.object(identity.shutil, "which", return_value=None):
            with self.assertRaisesRegex(ValueError, "must be installed"):
                identity.runtime_identity()
        self.configuration["binary"] = self.tools["composer"]
        with self.assertRaisesRegex(ValueError, "did not report the selected binary"):
            self.snapshot()
        with self.assertRaisesRegex(ValueError, "absolute paths"):
            identity.file_identity("relative")

    def test_terminal_revalidation_rejects_a_changed_runtime(self):
        original = self.snapshot()
        output = io.StringIO()
        with patch.object(identity, "runtime_identity", return_value=original), redirect_stdout(output):
            with patch.dict(os.environ, {"GITHUB_OUTPUT": str(self.output)}), patch.object(sys, "argv", ["identity"]):
                identity.main()
            digest = self.output.read_text().strip().removeprefix("sha256=")
            with patch.object(sys, "argv", ["identity", "--expect", digest]):
                identity.main()
        self.assertEqual(digest, json.loads(output.getvalue().splitlines()[-1])["sha256"])
        self.assertTrue(json.loads(output.getvalue().splitlines()[-1])["revalidated"])
        with patch.object(identity, "runtime_identity", return_value={**original, "version": "8.3.38"}), \
             patch.object(sys, "argv", ["identity", "--expect", digest]):
            with self.assertRaisesRegex(SystemExit, "identity changed"):
                identity.main()


if __name__ == "__main__":
    unittest.main()
