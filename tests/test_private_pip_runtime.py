"""Offline stock-pip controls use inert wheels and owned disposable environments."""

import base64
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / ".github/actions/bootstrap-patched-pip/pip_runtime.py"
SPEC = importlib.util.spec_from_file_location("private_pip_runtime", SOURCE)
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


def inert_wheel(ca):
    files = {
        "pip/__init__.py": b"__version__ = '26.2.2'\n",
        "pip/_vendor/__init__.py": b"",
        "pip/_vendor/certifi/__init__.py": b"from pathlib import Path\ndef where(): return str(Path(__file__).with_name('cacert.pem'))\n",
        "pip/_vendor/certifi/cacert.pem": ca,
        "pip/_internal/__init__.py": b"",
        "pip/_internal/cli/__init__.py": b"",
        "pip/_internal/cli/main.py": b"def main(): return 0\n",
        "pip-26.2.2.dist-info/METADATA": b"Metadata-Version: 2.1\nName: pip\nVersion: 26.2.2\n",
        "pip-26.2.2.dist-info/WHEEL": b"Wheel-Version: 1.0\nGenerator: inert-source-control\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        "pip-26.2.2.dist-info/entry_points.txt": b"[console_scripts]\npip=pip._internal.cli.main:main\npip3=pip._internal.cli.main:main\n",
    }
    rows = []
    for name, contents in files.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(contents).digest()).decode().rstrip("=")
        rows.append([name, "sha256=" + digest, str(len(contents))])
    rows.append(["pip-26.2.2.dist-info/RECORD", "", ""])
    record = io.StringIO()
    csv.writer(record, lineterminator="\n").writerows(rows)
    files["pip-26.2.2.dist-info/RECORD"] = record.getvalue().encode()
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, contents in files.items():
            archive.writestr(name, contents)
    return output.getvalue()


class PrivatePipRuntimeTest(unittest.TestCase):
    def setUp(self):
        # The source fixture uses the absolute distro interpreter. A hosted
        # caller's toolcache selection is tested separately and never adopted.
        self.hosted_location = os.environ.get("pythonLocation", "")
        self.environment = patch.dict(os.environ, {"pythonLocation": ""})
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def test_full_private_bootstrap_and_read_only_reuse_have_no_ambient_or_network_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = Path(temporary)
            command_files = {name: runner / name.lower() for name in ("GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH")}
            for path in command_files.values():
                path.touch(mode=0o600)
            ca = b"inert CA data; exporter parsing has separate real certificate controls\n"
            contents = inert_wheel(ca)
            digest = hashlib.sha256(contents).hexdigest()
            calls = []
            def execute(arguments, **options):
                calls.append((arguments, options))
                if "download" in arguments:
                    destination = Path(arguments[arguments.index("--dest") + 1])
                    (destination / runtime.WHEEL_NAME).write_bytes(contents)
                    return subprocess.CompletedProcess(arguments, 0, "", "")
                return subprocess.run(arguments, **options)
            original_create = runtime.create_runtime
            environment = {name: str(path) for name, path in command_files.items()}
            environment.update({"RUNNER_TEMP": str(runner), "PATH": "/usr/bin:/bin", "pythonLocation": "",
                                "PYTHONPATH": "/ambient/ignored", "PIP_INDEX_URL": "https://invalid.invalid",
                                "PIP_CONFIG_FILE": "/ambient/ignored.conf", "LD_PRELOAD": "/ambient/ignored.so"})
            with patch.multiple(runtime, WHEEL_SHA256=digest, WHEEL_SIZE=len(contents),
                                CA_SHA256=hashlib.sha256(ca).hexdigest()), \
                    patch.dict(os.environ, environment, clear=True), \
                    patch.object(runtime, "create_runtime", side_effect=lambda selected, temp:
                                 original_create(selected, temp, execute=execute)), \
                    patch.object(runtime.sys, "argv", ["runtime", "bootstrap", "/usr/bin/python3"]):
                runtime.main()
                values = dict(line.split("=", 1) for line in command_files["GITHUB_ENV"].read_text().splitlines())
                receipt = Path(values["DW_CI_PIP_STATE"])
                report, _subjects = runtime.verify_runtime(receipt, runner)
                self.assertEqual("1", values["PYTHONDONTWRITEBYTECODE"])
                self.assertEqual("/dev/null", values["PIP_CONFIG_FILE"])
                self.assertIn("pip-state=" + str(receipt), command_files["GITHUB_OUTPUT"].read_text())
                self.assertEqual(1, sum("download" in args for args, _options in calls))
                for args, options in calls:
                    self.assertNotIn("LD_PRELOAD", options["env"])
                    self.assertNotIn("PYTHONPATH", options["env"])
                    self.assertNotIn("PIP_INDEX_URL", options["env"])
                    self.assertEqual(["-I", "-S", "-B"], args[1:4])
                root = Path(report["root"])
                trust = root / "durable-workflow-trust"
                trust.mkdir(mode=0o700)
                (trust / "no-additional-roots").mkdir(mode=0o700)
                (trust / (runtime.CA_SHA256 + ".pem")).write_bytes(ca)
                active = values | {"PATH": str(Path(report["python"]).parent) + ":/usr/bin:/bin"}
                with patch.dict(os.environ, active), \
                        patch.object(runtime.sys, "argv", ["runtime", "verify", report["python"]]), \
                        patch.object(runtime, "create_runtime") as create:
                    runtime.main()
                    create.assert_not_called()
                runtime.cleanup_runtime(root, runner, report["root_identity"])
                self.assertFalse(root.exists())

    def test_verification_requires_explicit_state_and_cleanup_rejects_a_changed_object(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = Path(temporary)
            environment = {"RUNNER_TEMP": str(runner)}
            for name in ("GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH"):
                path = runner / name
                path.touch(mode=0o600)
                environment[name] = str(path)
            with patch.dict(os.environ, environment, clear=True), \
                    patch.object(runtime.sys, "argv", ["runtime", "verify", "/usr/bin/python3"]), \
                    patch.object(runtime, "create_runtime") as create, self.assertRaisesRegex(ValueError, "explicit"):
                runtime.main()
            create.assert_not_called()
            root = runtime._private_root(runner).root
            identity = runtime.directory_identity(root.stat())
            moved = runner / "retained-original"
            root.rename(moved)
            root.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, "identity changed"):
                runtime.cleanup_runtime(root, runner, identity)
            self.assertTrue(root.exists())
            self.assertTrue(moved.exists())

    def test_stock_installer_reproduces_no_record_then_seeds_empty_private_target_without_manager_mutation(self):
        # The actual existing pip executable plans/installs only inert local
        # fixtures. No public wheel code, network, global install or uninstall.
        interpreter = runtime.selected_interpreter("/usr/bin/python3")
        before = runtime.manager_snapshot(interpreter)
        with tempfile.TemporaryDirectory(prefix="cli-pip-inert-") as temporary:
            runner_temp = Path(temporary)
            old = runtime._private_root(runner_temp).root
            new = runtime._private_root(runner_temp).root
            for directory in (old, new):
                subprocess.run([interpreter["executable"], "-I", "-S", "-B", "-m", "venv", "--without-pip",
                    "--symlinks", str(directory / "environment")], env=runtime.private_environment(directory),
                    capture_output=True, text=True, timeout=30, check=True)
            old_python, old_site = runtime.venv_layout(old, interpreter)
            (old_site / "pip").mkdir()
            (old_site / "pip/__init__.py").write_text("__version__ = '25.1.1'\n")
            distribution = old_site / "pip-25.1.1.dist-info"
            distribution.mkdir()
            (distribution / "METADATA").write_text("Metadata-Version: 2.1\nName: pip\nVersion: 25.1.1\n")
            (distribution / "INSTALLER").write_text("debian\n")
            old_contents = runtime._tree_files(old_site)
            ca = b"inert public CA data; no TLS operation occurs\n"
            contents = inert_wheel(ca)
            wheel = new / "downloads" / runtime.WHEEL_NAME
            wheel.write_bytes(contents)
            digest = hashlib.sha256(contents).hexdigest()
            requirement = "pip @ " + wheel.as_uri() + "#sha256=" + digest
            old_arguments = ["--python", str(old_python), "install", "--no-index", "--no-deps", "--no-compile", "--upgrade", requirement]
            old_environment = runtime.private_environment(old)
            with self.assertRaises(subprocess.CalledProcessError) as refused:
                runtime.manager_command(interpreter, before, old_arguments, old_environment)
            self.assertIn("uninstall-no-record-file", refused.exception.stderr)
            self.assertEqual(old_contents, runtime._tree_files(old_site))
            private_python, purelib = runtime.venv_layout(new, interpreter)
            runtime.manager_command(interpreter, before, ["--python", str(private_python), "install",
                "--no-index", "--no-deps", "--only-binary=:all:", "--no-compile", "--prefix",
                str(new / "environment"), requirement], runtime.private_environment(new))
            self.assertEqual(before, runtime.manager_snapshot(interpreter))
            with patch.multiple(runtime, WHEEL_SHA256=digest, WHEEL_SIZE=len(contents),
                                CA_SHA256=hashlib.sha256(ca).hexdigest()):
                files, wheel_identity = runtime.authenticated_wheel(wheel)
                subjects = runtime.validate_install(new, interpreter, files, initial=True)
                self.assertIn(str(purelib / "pip/__init__.py"), subjects)
                self.assertIn(str(private_python.parent / "pip"), subjects)
                report = {"schema": "durable-workflow.private-pip/v1", "root": str(new),
                    "root_identity": runtime.directory_identity(new.stat()),
                    "venv_baseline": runtime.venv_baseline(new, interpreter),
                    "interpreter": interpreter, "manager": before, "python": str(private_python),
                    "purelib": str(purelib), "wheel": str(wheel), "wheel_identity": wheel_identity}
                path = new / "runtime.json"
                path.write_text(json.dumps(report))
                runtime.verify_runtime(path, runner_temp, initial=True)
                for relative, changed in (
                    ("pip/__init__.py", b"__version__ = 'foreign'\n"),
                    ("pip-26.2.2.dist-info/INSTALLER", b"foreign\n"),
                    ("pip-26.2.2.dist-info/direct_url.json", b'{"url":"file:///foreign"}'),
                    ("pip-26.2.2.dist-info/RECORD", b"../../../../escape,,\n"),
                ):
                    subject = purelib / relative
                    original = subject.read_bytes()
                    with self.subTest(mutation=relative):
                        subject.write_bytes(changed)
                        with self.assertRaises(ValueError):
                            runtime.verify_runtime(path, runner_temp)
                        subject.write_bytes(original)
                for name in ("foreign.pth", "sitecustomize.py", "usercustomize.py"):
                    subject = purelib / name
                    marker = new / "startup-executed"
                    subject.write_text("from pathlib import Path; Path(" + repr(str(marker)) + ").touch()\n")
                    with self.subTest(startup=name), self.assertRaises(ValueError):
                        runtime.verify_runtime(path, runner_temp)
                    self.assertFalse(marker.exists())
                    subject.unlink()
                empty = purelib / "pip/unbound-empty-directory"
                empty.mkdir()
                with self.assertRaisesRegex(ValueError, "directory inventory"):
                    runtime.verify_runtime(path, runner_temp)
                empty.rmdir()
                module = purelib / "pip/__init__.py"
                original = module.read_bytes()
                outside = runner_temp / "foreign-module.py"
                outside.write_bytes(original)
                for kind in ("symlink", "hardlink", "fifo", "writable"):
                    module.unlink()
                    if kind == "symlink":
                        module.symlink_to(outside)
                    elif kind == "hardlink":
                        os.link(outside, module)
                    elif kind == "fifo":
                        os.mkfifo(module)
                    else:
                        module.write_bytes(original)
                        module.chmod(0o666)
                    with self.subTest(kind=kind), self.assertRaises((ValueError, OSError)):
                        runtime.verify_runtime(path, runner_temp)
                    module.unlink()
                    module.write_bytes(original)
                configuration = new / "environment/pyvenv.cfg"
                original = configuration.read_text()
                configuration.write_text(original.replace("include-system-site-packages = false", "include-system-site-packages = true"))
                with self.assertRaisesRegex(ValueError, "configuration"):
                    runtime.verify_runtime(path, runner_temp)
                configuration.write_text(original)
                report["venv_baseline"] = runtime.venv_baseline(new, interpreter)
                path.write_text(json.dumps(report))
                runtime.verify_runtime(path, runner_temp)
                runtime.freeze_pip(new, interpreter)
                runtime.verify_runtime(path, runner_temp)
                runtime.cleanup_runtime(new, runner_temp, report["root_identity"])
                self.assertFalse(new.exists())
                self.assertEqual(before, runtime.manager_snapshot(interpreter))

    def test_later_clients_refuse_path_home_module_and_loader_fallbacks(self):
        report = {"python": "/fixture/private/bin/python", "purelib": "/fixture/private/site-packages",
                  "interpreter": {"loader": None}}
        environment = {"PATH": "/fixture/private/bin", "PYTHONPATH": report["purelib"],
                       "PYTHONNOUSERSITE": "1"}
        def which(name):
            return "/fixture/private/bin/" + name
        with patch.dict(os.environ, environment, clear=True), patch.object(runtime.shutil, "which", side_effect=which):
            runtime.verify_active_origin(report, report["python"])
            for variable, value in (("PYTHONPATH", "/ambient"), ("PYTHONHOME", "/ambient"),
                                    ("PYTHONNOUSERSITE", "0"), ("LD_LIBRARY_PATH", "/ambient"),
                                    ("LD_PRELOAD", "/ambient.so"), ("LD_AUDIT", "/ambient.so")):
                with self.subTest(variable=variable), patch.dict(os.environ, {variable: value}), self.assertRaises(ValueError):
                    runtime.verify_active_origin(report, report["python"])
            with self.assertRaisesRegex(ValueError, "fell back"):
                runtime.verify_active_origin(report, "/usr/bin/python3")
            with patch.object(runtime.shutil, "which", return_value="/usr/bin/pip"), self.assertRaises(ValueError):
                runtime.verify_active_origin(report, report["python"])

    def test_seed_failure_removes_only_new_owned_state_and_does_not_retry(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = Path(temporary)
            unrelated = runner / "keep"
            unrelated.write_text("preserved")
            with patch.object(runtime, "selected_interpreter", return_value={}), \
                    patch.object(runtime, "manager_snapshot", return_value={}), \
                    patch.object(runtime, "_seed_runtime", side_effect=ValueError("inert seed refusal")) as seed, \
                    self.assertRaisesRegex(ValueError, "inert seed"):
                runtime.create_runtime("/fixture/python", runner)
            seed.assert_called_once()
            self.assertEqual([unrelated], list(runner.iterdir()))
            self.assertEqual("preserved", unrelated.read_text())

    def test_partial_allocation_is_reclaimed(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = Path(temporary)
            original_mkdir = runtime.os.mkdir
            def mkdir(name, *args, **kwargs):
                if name == "tmp" and "dir_fd" in kwargs:
                    raise OSError("inert partial allocation refusal")
                return original_mkdir(name, *args, **kwargs)
            with patch.object(runtime.os, "mkdir", side_effect=mkdir), self.assertRaisesRegex(OSError, "partial allocation"):
                runtime._private_root(runner)
            self.assertEqual([], list(runner.iterdir()))

    def test_first_allocation_identity_read_failure_is_reclaimed(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = Path(temporary)
            original_stat = runtime.os.stat
            failed = False
            def stat(path, *args, **kwargs):
                nonlocal failed
                if not failed and isinstance(path, str) and path.startswith("dw-pip-") and "dir_fd" in kwargs:
                    failed = True
                    raise OSError("inert first allocation identity failure")
                return original_stat(path, *args, **kwargs)
            with patch.object(runtime.os, "stat", side_effect=stat), self.assertRaisesRegex(OSError, "first allocation identity"):
                runtime._private_root(runner)
            self.assertTrue(failed)
            self.assertEqual([], list(runner.iterdir()))

    def test_persistent_first_metadata_failure_removes_empty_child_without_another_lookup(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = Path(temporary)
            original_stat, original_open = runtime.os.stat, runtime.os.open
            def stat(path, *args, **kwargs):
                if isinstance(path, str) and path.startswith("dw-pip-") and "dir_fd" in kwargs:
                    raise OSError("inert persistent allocation metadata refusal")
                return original_stat(path, *args, **kwargs)
            def open(path, *args, **kwargs):
                if isinstance(path, str) and path.startswith("dw-pip-"):
                    raise OSError("inert persistent recovery open refusal")
                return original_open(path, *args, **kwargs)
            with patch.object(runtime.os, "stat", side_effect=stat), patch.object(runtime.os, "open", side_effect=open), \
                    self.assertRaisesRegex(OSError, "persistent allocation metadata"):
                runtime._private_root(runner)
            self.assertEqual([], list(runner.iterdir()))

    def test_identity_handoff_failure_reclaims_created_state_but_not_reused_state(self):
        for reused in (False, True):
            with self.subTest(reused=reused), tempfile.TemporaryDirectory() as temporary:
                runner = Path(temporary)
                state = runtime._private_root(runner)
                environment = {"RUNNER_TEMP": str(runner)}
                for name in ("GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH"):
                    path = runner / name
                    path.touch(mode=0o600)
                    environment[name] = str(path)
                if reused:
                    environment["DW_CI_PIP_STATE"] = str(state.receipt)
                def verify(path, temp, **_options):
                    return runtime.runtime_root(path, temp)
                with patch.dict(os.environ, environment, clear=True), \
                        patch.object(runtime.sys, "argv", ["runtime", "bootstrap", "/usr/bin/python3"]), \
                        patch.object(runtime, "create_runtime", return_value=state), \
                        patch.object(runtime, "verify_runtime", side_effect=verify), \
                        patch.object(runtime, "runtime_root", side_effect=OSError("inert handoff lookup")), \
                        self.assertRaisesRegex(OSError, "handoff lookup"):
                    runtime.main()
                self.assertEqual(reused, state.root.exists())

    def test_post_seed_verification_and_command_append_failure_reclaim_new_state(self):
        for stage in ("verify", "append"):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory() as temporary:
                runner = Path(temporary)
                environment = {"RUNNER_TEMP": str(runner)}
                for name in ("GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH"):
                    path = runner / name
                    path.touch(mode=0o600)
                    environment[name] = str(path)
                created = []
                foreign = runner / "preserved"
                foreign.write_text("unchanged")
                def create(_selected, _temporary):
                    state = runtime._private_root(runner)
                    root = state.root
                    created.append(root)
                    report["root_identity"] = state.identity
                    if stage == "append":
                        output = Path(environment["GITHUB_OUTPUT"])
                        output.rename(runner / "held-output")
                        output.symlink_to(foreign)
                    return state
                report = {"python": "/fixture/private/python", "purelib": "/fixture/private/site-packages",
                          "interpreter": {"loader": None, "version": [3, 13, 18]}}
                with patch.dict(os.environ, environment, clear=True), \
                        patch.object(runtime.sys, "argv", ["runtime", "bootstrap", "/usr/bin/python3"]), \
                        patch.object(runtime, "create_runtime", side_effect=create), \
                        patch.object(runtime, "verify_runtime", return_value=(report, {}),
                                     side_effect=ValueError("inert post-seed verification") if stage == "verify" else None), \
                        self.assertRaises(ValueError):
                    runtime.main()
                self.assertEqual(1, len(created))
                self.assertFalse(created[0].exists())
                self.assertEqual("unchanged", foreign.read_text())

    def test_actual_hosted_custody_is_reported_and_never_relaxed(self):
        # This is a read-only source-CI observation, not execution of the new
        # action on toolcache Python or an installed qualification receipt.
        location = self.hosted_location
        if not location:
            self.skipTest("No hosted toolcache selection in this local source control")
        target = Path(location) / "lib"
        observations = []
        for path in reversed([target, *target.parents]):
            metadata = path.lstat()
            observations.append({"path": str(path), "uid": metadata.st_uid, "mode": format(metadata.st_mode & 0o7777, "04o")})
        print("Hosted Python custody (read-only): " + json.dumps(observations, sort_keys=True))
        unsafe = [entry for entry in observations if int(entry["mode"], 8) & 0o022 and not
                  (entry["uid"] == 0 and int(entry["mode"], 8) & 0o1000)]
        if unsafe:
            with self.assertRaisesRegex(ValueError, "Runtime directory refused: path=.*uid=.*mode="):
                runtime.selected_loader(location)

    def test_held_output_parent_and_object_redirects_refuse_before_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            runner = Path(temporary)
            output = runner / "output"
            foreign = runner / "foreign"
            output.touch(mode=0o600)
            foreign.write_text("preserved")
            with runtime.github_file(output, runner) as append:
                output.rename(runner / "held-original")
                output.symlink_to(foreign)
                with self.assertRaisesRegex(ValueError, "redirected"):
                    append("INJECTED=value\n")
            self.assertEqual("preserved", foreign.read_text())
            self.assertEqual("", (runner / "held-original").read_text())
            parent = runner / "parent"
            parent.mkdir()
            with runtime.BoundDirectory(parent) as held:
                parent.rename(runner / "old-parent")
                parent.mkdir()
                with self.assertRaisesRegex(ValueError, "identity"):
                    held.create("output", b"inert")
            self.assertFalse((parent / "output").exists())

    def test_hosted_loader_refuses_escape_and_writable_shared_objects(self):
        with tempfile.TemporaryDirectory() as temporary:
            location = Path(temporary)
            library = location / "lib"
            library.mkdir()
            binary = library / "libpython3.so"
            binary.write_bytes(b"inert shared object data, never executed")
            result = runtime.selected_loader(str(location))
            self.assertEqual(str(library), result["path"])
            binary.chmod(0o666)
            with self.assertRaisesRegex(ValueError, "regular file"):
                runtime.selected_loader(str(location))
            binary.unlink()
            foreign = location / "foreign.so"
            foreign.write_bytes(b"inert")
            binary.symlink_to(foreign)
            with self.assertRaisesRegex(ValueError, "escapes"):
                runtime.selected_loader(str(location))


if __name__ == "__main__":
    unittest.main()
