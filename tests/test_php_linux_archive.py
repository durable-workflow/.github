"""In-memory tar and installed-file controls. No PHP or extraction runs."""

import io
import importlib.util
import json
from pathlib import Path
import stat
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import php_linux_archive as archive
from scripts import php_linux_bootstrap as bootstrap
from scripts import php_linux_configuration as configuration


def initial_subject_shape(writer=archive.subject_record, schema=archive.NORMALIZED_SUBJECT_SCHEMA):
    """Fixed catalog names/sizes with inert hashes; no payload or installed claim."""
    metadata = json.loads((bootstrap.ROOT / 'qualification/php-linux-initial-archive.json').read_text())
    profile = json.loads((bootstrap.ROOT / 'qualification/php-linux-initial-normalization.json').read_text())
    files = {row[0].removeprefix('./'): {'size': row[3], 'sha256': '0' * 64}
        for row in metadata['members'] if row[1] == '0'}
    targets = {}
    for name, target in profile['materialize_regular_aliases']:
        files[name] = files[target]
        targets[name] = {'target': target, **files[target], 'metadata': {}}
    outputs = {configuration.CLI: {'size': 73769, 'sha256': '0' * 64},
               configuration.PECL: {'size': 64, 'sha256': '0' * 64},
               configuration.CURRENT: {'size': 11, 'sha256': '0' * 64}}
    configs = {name for name in files if name.startswith('etc/php/8.3/cli/conf.d/') and name.endswith('.ini')}
    configs.difference_update(configuration.removed_members(files))
    configs.update((configuration.CLI, configuration.PECL))
    plan = {'schema': configuration.SCHEMA, 'outputs': outputs, 'active': sorted(configs)}
    names = {name for name in files if name.startswith('usr/lib/php/20230831/') and name.endswith('.so')}
    names.update(('usr/bin/php8.3', 'usr/bin/php-config8.3', *configs, *outputs))
    expected = {**files, **outputs}
    manifest = {'schema': schema, 'files': {'/' + name: writer(name, expected[name], '8.3', plan, targets)
        for name in sorted(names)}, 'commands': {'php': '/usr/bin/php8.3', 'php-config': '/usr/bin/php-config8.3'},
        'configs': {'/' + name: '/' + name for name in sorted(configs)}}
    return manifest, {'files': files, 'targets': targets}, plan


class PhpLinuxArchiveTest(unittest.TestCase):
    def test_fixed_initial_inventory_refuses_v1_and_fits_v2_without_larger_limits_or_omissions(self):
        path = Path(__file__).parent / 'fixtures/php_subjects_153f.py'
        spec = importlib.util.spec_from_file_location('inert_subject_writer_153f', path)
        old = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(old)
        before, _, _ = initial_subject_shape(old.subject_record, archive.SUBJECT_SCHEMA)
        after, _, _ = initial_subject_shape()
        self.assertEqual(172, len(after['files']))
        self.assertEqual(69, len(after['configs']))
        self.assertEqual(63472, len(json.dumps(before, sort_keys=True).encode()))
        self.assertGreater(len(json.dumps(before, separators=(',', ':')).encode()), archive.MAX_SUBJECT_BYTES)
        self.assertEqual(old.MAX_SUBJECT_BYTES, archive.MAX_SUBJECT_BYTES)
        with self.assertRaisesRegex(ValueError, 'exceeds the bounded profile'):
            old.require_subject_bound(before)
        archive.require_subject_bound(after)
        self.assertEqual(before['commands'], after['commands'])
        self.assertEqual(before['configs'], after['configs'])
        self.assertEqual(set(before['files']), set(after['files']))
        for name in before['files']:
            self.assertEqual({key: before['files'][name][key] for key in ('type', 'size', 'sha256')},
                             {key: after['files'][name][key] for key in ('type', 'size', 'sha256')})

    def test_subject_count_and_bytes_still_refuse_at_the_original_bounds(self):
        manifest, _, _ = initial_subject_shape()
        manifest['files'].update({f'/inert/{n}': {} for n in range(257)})
        with self.assertRaisesRegex(ValueError, 'exceeds the bounded profile'):
            archive.require_subject_bound(manifest)
        manifest = {'files': {}, 'configs': {'/inert': 'x' * archive.MAX_SUBJECT_BYTES}}
        with self.assertRaisesRegex(ValueError, 'exceeds the bounded profile'):
            archive.require_subject_bound(manifest)

    def predecessor(self):
        path = Path(__file__).parent / 'fixtures/php_linux_archive_65753c1.py'
        spec = importlib.util.spec_from_file_location('inert_predecessor_inventory', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module.inventory

    def typed_tar(self, members):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.GNU_FORMAT) as output:
            for name, kind in members:
                item = tarfile.TarInfo(name)
                item.type = kind
                item.linkname = '../../inert-outside'
                output.addfile(item)
        return stream.getvalue()

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
            stream = self.tar(members)
            with self.subTest(members=members), self.assertRaises(ValueError):
                archive.inventory(stream)

    def test_exact_predecessor_accepts_links_special_and_sparse_while_successor_refuses(self):
        old = self.predecessor()
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE,
                     tarfile.BLKTYPE, tarfile.GNUTYPE_SPARSE, tarfile.CONTTYPE):
            payload = self.typed_tar([('usr/bin/inert',kind)])
            with self.subTest(kind=kind):
                old(io.BytesIO(payload))
                stream = io.BytesIO(payload)
                with self.assertRaisesRegex(ValueError, 'links/sparse/special'):
                    archive.inventory(stream)

    def test_exact_predecessor_collapses_aliases_and_accepts_parent_type_collisions(self):
        old = self.predecessor()
        cases = [
            [('usr//bin/php',tarfile.REGTYPE),('usr/bin/php',tarfile.REGTYPE)],
            [('usr/./bin/php',tarfile.REGTYPE)], [('././usr/bin/php',tarfile.REGTYPE)],
            [('usr/bin/php/',tarfile.REGTYPE)],
            [('usr',tarfile.REGTYPE),('usr/bin/php',tarfile.REGTYPE)],
            [('usr/bin/php',tarfile.REGTYPE),('usr',tarfile.REGTYPE)],
            [('usr',tarfile.DIRTYPE),('usr',tarfile.REGTYPE)],
            [('usr',tarfile.REGTYPE),('usr',tarfile.DIRTYPE)],
            [('usr',tarfile.DIRTYPE),('./usr',tarfile.DIRTYPE)],
        ]
        for members in cases:
            payload = self.typed_tar(members)
            with self.subTest(members=members):
                old(io.BytesIO(payload))
                stream = io.BytesIO(payload)
                with self.assertRaises(ValueError):
                    archive.inventory(stream)
        aliases = self.typed_tar(cases[0])
        self.assertEqual(['usr/bin/php'], list(old(io.BytesIO(aliases))))

    def test_canonical_parent_directories_can_be_explicit_or_implicit(self):
        for members in ([('.',tarfile.DIRTYPE),('usr',tarfile.DIRTYPE),('usr/bin',tarfile.DIRTYPE),
                         ('usr/bin/php',tarfile.REGTYPE)],
                        [('usr/bin/php',tarfile.REGTYPE),('usr',tarfile.DIRTYPE)]):
            payload = self.typed_tar(members)
            self.assertEqual(['usr/bin/php'],list(archive.inventory(io.BytesIO(payload))))

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

    def test_producer_manifest_derives_every_subject_from_the_archive(self):
        contents, files, read, command, probe = self.fixture()
        name = "etc/php/8.3/cli/php.ini"
        contents[name] = b"extension=redis.so\n"
        files[name] = {"size": len(contents[name]), "sha256": bootstrap.sha256(contents[name])}
        options = dict(execute=probe, read=read, command_path=command,
            shared=[Path("/usr/lib/php/20230831/redis.so")],
            active_configs=[Path("/" + name)], resolve=lambda path:path)
        _, manifest = archive.capture_subjects(files,"8.3",[],**options)
        self.assertEqual(archive.SUBJECT_SCHEMA,manifest["schema"])
        self.assertEqual({"/etc/php/8.3/cli/php.ini":"/etc/php/8.3/cli/php.ini"},manifest["configs"])
        self.assertEqual({"php":"/usr/bin/php8.3","php-config":"/usr/bin/php-config8.3"},manifest["commands"])
        for path, record in manifest["files"].items():
            self.assertEqual({"kind":"archive","member":path.lstrip("/")},record["authority"])
            self.assertEqual(files[path.lstrip("/")]["sha256"],record["sha256"])
        origin = {'target': 'etc/php/8.3/mods-available/inert.ini', **files[name], 'metadata': {'mode': 0o644}}
        _, normalized = archive.capture_subjects(files, '8.3', [], normalization_targets={name: origin}, **options)
        authority = normalized['files']['/' + name]['authority']
        self.assertEqual(archive.NORMALIZED_SUBJECT_SCHEMA, normalized['schema'])
        self.assertEqual({'kind': 'normalized-archive'}, authority)
        _, historical = archive.capture_subjects(files, '8.3', [], normalization_targets={name: origin},
            subject_schema=archive.SUBJECT_SCHEMA, **options)
        self.assertEqual(archive.SUBJECT_SCHEMA, historical['schema'])
        self.assertEqual(origin['target'], historical['files']['/' + name]['authority']['source_member'])
        self.assertEqual(bootstrap.sha256(json.dumps(origin['metadata'], sort_keys=True,
            separators=(',', ':')).encode()), historical['files']['/' + name]['authority']['target_metadata_sha256'])
        for schema in (archive.NORMALIZED_SUBJECT_SCHEMA, 'unknown', '', False, 0):
            with self.subTest(schema=schema), self.assertRaises(ValueError):
                archive.capture_subjects(files, '8.3', [], subject_schema=schema, **options)
        origin['size'] += 1
        with self.assertRaisesRegex(ValueError, 'original contained target'):
            archive.capture_subjects(files, '8.3', [], normalization_targets={name: origin}, **options)
        contents["usr/lib/php/20230831/redis.so"] = b"changed actual module"
        with self.assertRaises(ValueError):
            archive.capture_subjects(files,"8.3",[],**options)

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
