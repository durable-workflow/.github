"""In-memory tar and installed-file controls. No PHP or extraction runs."""

import io
import json
from pathlib import Path
import stat
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import php_linux_archive as archive
from scripts import php_linux_bootstrap as bootstrap


class PhpLinuxArchiveTest(unittest.TestCase):
    def tar(self, members):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w") as output:
            for name, data in members:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                output.addfile(member, io.BytesIO(data))
        stream.seek(0)
        return stream

    def test_stream_inventory_hashes_exact_regular_members_without_extraction(self):
        files = archive.inventory(self.tar([("./usr/bin/php8.3", b"inert PHP binary"),
            ("usr/bin/php-config8.3", b"inert config"), ("usr/lib/php/20230831/redis.so", b"inert module")]))
        self.assertEqual(3, len(files))
        self.assertEqual(bootstrap.sha256(b"inert module"), files["usr/lib/php/20230831/redis.so"]["sha256"])

    def test_ambiguous_and_escaping_member_paths_refuse_before_any_install(self):
        for members in ([('usr/bin/php8.3', b'one'), ('usr/bin/php8.3', b'two')],
                        [('/usr/bin/php8.3', b'absolute')], [('../outside', b'escape')]):
            with self.subTest(members=members), self.assertRaises(ValueError):
                archive.inventory(self.tar(members))

    def fixture(self):
        contents = {"usr/bin/php8.3": b"inert PHP", "usr/bin/php-config8.3": b"inert config",
                    "usr/lib/php/20230831/redis.so": b"inert module"}
        files = {name: {"size": len(data), "sha256": bootstrap.sha256(data)} for name, data in contents.items()}
        def read(path):
            return SimpleNamespace(st_mode=stat.S_IFREG | 0o755), contents[path.as_posix().lstrip('/')]
        def command(name):
            return Path(f"/usr/bin/{name}8.3")
        def probe(arguments, **options):
            self.assertEqual(["/usr/bin/php8.3", "-n", "-r"], arguments[:3])
            self.assertNotIn("HOME", options["env"])
            return SimpleNamespace(stdout=json.dumps({"builtins": ["Core", "json", "PDO"],
                                                     "extension_dir": "/usr/lib/php/20230831", "config_path": "/etc/php/8.3/cli", "scan_dir": "/etc/php/8.3/cli/conf.d",
                                                     "version": "8.3.0", "zts": 0, "debug": 0}))
        return contents, files, read, command, probe

    def test_bound_binary_builtin_and_shared_module_are_checked_before_upstream(self):
        _, files, read, command, probe = self.fixture()
        result = archive.verify_installed(files, "8.3", ["json", "redis"], probe, read=read,
            shared=[Path('/usr/lib/php/20230831/redis.so')], command_path=command, active_configs=[])
        self.assertEqual("usr/bin/php8.3", result["extensions"]["json"]["source"])
        self.assertEqual("usr/lib/php/20230831/redis.so", result["extensions"]["redis"]["source"])

    def test_modified_binary_or_default_path_refuses_before_the_php_probe(self):
        contents, files, read, command, _ = self.fixture()
        def forbidden(*args, **options):
            self.fail("Unbound binary cannot be probed")
        contents["usr/bin/php8.3"] = b"changed binary"
        with self.assertRaises(ValueError):
            archive.verify_installed(files, "8.3", [], forbidden, read=read, shared=[], command_path=command, active_configs=[])
        contents["usr/bin/php8.3"] = b"inert PHP"
        with self.assertRaises(ValueError):
            archive.verify_installed(files, "8.3", [], forbidden, read=read, shared=[],
                command_path=lambda name: Path('/usr/local/bin/unbound-php'), active_configs=[])

    def test_missing_or_changed_shared_module_cannot_trigger_a_download_fallback(self):
        contents, files, read, command, probe = self.fixture()
        with self.assertRaisesRegex(ValueError, "absent from the bound PHP archive"):
            archive.verify_installed(files, "8.3", ["missing"], probe, read=read, shared=[], command_path=command, active_configs=[])
        contents["usr/lib/php/20230831/redis.so"] = b"changed module"
        with self.assertRaises(ValueError):
            archive.verify_installed(files, "8.3", ["redis"], probe, read=read, shared=[], command_path=command, active_configs=[])
        with self.assertRaisesRegex(ValueError, "Ambient shared extension"):
            archive.verify_installed(files, "8.3", [], probe, read=read,
                shared=[Path('/usr/lib/php/20230831/ambient.so')], command_path=command, active_configs=[])

    def test_ambient_startup_config_and_bound_config_with_foreign_module_refuse(self):
        contents, files, read, command, probe = self.fixture()
        config = Path('/etc/php/8.3/cli/php.ini')
        with self.assertRaisesRegex(ValueError, "Ambient PHP startup configuration"):
            archive.verify_installed(files, "8.3", [], probe, read=read, shared=[], command_path=command,
                active_configs=[config], resolve=lambda path: path)
        for data, reason in ((b'extension=/opt/ambient.so\n', "Active startup module"),
                             (b'extension_dir=/opt/unbound\n', "extension_dir override")):
            contents[config.as_posix().lstrip('/')] = data
            files[config.as_posix().lstrip('/')] = {"size": len(data), "sha256": bootstrap.sha256(data)}
            with self.subTest(data=data), self.assertRaisesRegex(ValueError, reason):
                archive.verify_installed(files, "8.3", [], probe, read=read, shared=[], command_path=command,
                    active_configs=[config], resolve=lambda path: path)
        contents[config.as_posix().lstrip('/')] = b"changed ambient config"
        with self.assertRaises(ValueError):
            archive.verify_installed(files, "8.3", [], probe, read=read, shared=[], command_path=command,
                active_configs=[config], resolve=lambda path: path)

    def test_bound_startup_module_can_be_enabled_and_missing_effective_module_is_a_failure(self):
        contents, files, read, command, probe = self.fixture()
        config = Path('/etc/php/8.3/cli/php.ini')
        data = b'extension=redis.so\n'
        contents[config.as_posix().lstrip('/')] = data
        files[config.as_posix().lstrip('/')] = {"size": len(data), "sha256": bootstrap.sha256(data)}
        archive.verify_installed(files, "8.3", ['redis'], probe, read=read, shared=[], command_path=command,
            active_configs=[config], resolve=lambda path: path)
        for loaded, required, coverage, succeeds in ((["Core", "redis"], ["redis"], "", True),
                (["Core"], ["redis"], "", False), (["Core", "xdebug"], [], "none", False),
                ({"unexpected": "object"}, [], "none", False)):
            with self.subTest(loaded=loaded), patch.dict('os.environ', {'HOME': '/tmp/inert-home'}), \
                    patch.object(archive, 'verify_file') as binding:
                def execute(arguments, **options):
                    self.assertEqual(['/usr/bin/php8.3', '-r'], arguments[:2])
                    self.assertEqual(1, binding.call_count)
                    return SimpleNamespace(stdout=json.dumps(loaded))
                if succeeds:
                    archive.verify_enabled(files, '8.3', required, coverage, execute, lambda: Path('/usr/bin/php8.3'))
                else:
                    with self.assertRaises(ValueError):
                        archive.verify_enabled(files, '8.3', required, coverage, execute, lambda: Path('/usr/bin/php8.3'))

    def test_wrong_engine_minor_or_build_flag_refuses_before_configured_startup(self):
        _, files, read, command, probe = self.fixture()
        for field, value in (("version", "8.4.0"), ("zts", 1), ("debug", 1)):
            def wrong(*args, **options):
                result = json.loads(probe(*args, **options).stdout)
                result[field] = value
                return SimpleNamespace(stdout=json.dumps(result))
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "minor/NTS/release"):
                archive.verify_installed(files, '8.3', [], wrong, read=read, command_path=command,
                                         shared=[], active_configs=[])


if __name__ == "__main__":
    unittest.main()
