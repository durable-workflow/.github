"""Inert tar/zstd controls only; no public archive, installer or PHP executes."""
import copy
import errno
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from scripts import php_linux_archive as archive
from scripts import php_linux_bootstrap as bootstrap
from scripts import php_linux_normalize as normalization


class PhpLinuxNormalizeTest(unittest.TestCase):
    def fixture(self, *, pax=None, special=None):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode='w', format=tarfile.PAX_FORMAT if pax else tarfile.GNU_FORMAT) as output:
            for name in ('./usr', './usr/bin'):
                info = tarfile.TarInfo(name)
                info.type, info.mode = tarfile.DIRTYPE, 0o755
                output.addfile(info)
            info = tarfile.TarInfo('./usr/bin/target')
            info.size, info.mode, info.mtime = 5, 0o555, 123
            info.uid, info.gid, info.uname, info.gname = 11, 12, 'inert', 'fixture'
            if pax:
                info.pax_headers = pax
            output.addfile(info, io.BytesIO(b'inert'))
            for name, target in (('./usr/bin/alias', 'target'), ('./usr/bin/missing', 'absent'),
                                 ('./usr/bin/directory-alias', '.')):
                info = tarfile.TarInfo(name)
                info.type, info.linkname, info.mode, info.mtime = tarfile.SYMTYPE, target, 0o777, 999
                output.addfile(info)
            if special is not None:
                info = tarfile.TarInfo('./usr/bin/special')
                info.type = special
                output.addfile(info)
        source = raw.getvalue()
        compressed = subprocess.run(['/usr/bin/zstd', '--compress', '--stdout', '--quiet'],
            input=source, capture_output=True, check=True).stdout
        identity = {'id': 672923785, 'name': 'php_8.3-nts+ubuntu26.04.tar.zst',
                    'size': len(compressed), 'digest': 'sha256:' + bootstrap.sha256(compressed)}
        asset = {key: identity[key] for key in ('id', 'name', 'size')}
        asset['sha256'] = bootstrap.sha256(compressed)
        with tarfile.open(fileobj=io.BytesIO(source), mode='r|') as contents:
            rows = [normalization.header_row(member) for member in contents]
        metadata = {'asset': asset, 'members': rows, 'member_count': len(rows),
            'columns': ['name', 'type', 'linkname', 'size', 'offset', 'offset_data']}
        plan = {'asset': asset, 'materialize_regular_aliases': [['usr/bin/alias', 'usr/bin/target']],
            'omit_aliases': [['usr/bin/missing', 'unresolved', 'usr/bin/absent'],
                             ['usr/bin/directory-alias', 'directory', 'usr/bin']],
            'expected_regular_files': 2, 'expected_directories': 2, 'expected_members': 4, 'expected_links': 0}
        selected = normalization.Profile(metadata, plan, 'a' * 64, 'b' * 64)
        return compressed, identity, selected, source

    def held(self, compressed, identity):
        return bootstrap.hold_bytes(io.BytesIO(compressed), identity, {'fixture': True})

    def enter_derivation(self, held):
        with normalization.normalize(held):
            pass

    def enter_manifest(self, state, record):
        with normalization.capture_manifest(state, record):
            pass

    def temporary_descriptors(self):
        names = []
        for path in Path('/proc/self/fd').iterdir():
            try:
                target = os.readlink(path)
            except FileNotFoundError:
                continue
            if 'memfd:php-normalization' in target:
                names.append(target)
        return names

    def test_real_profile_has_only_its_reviewed_source_hashes_and_asset(self):
        selected = normalization.profile()
        self.assertEqual(672923785, selected.metadata['asset']['id'])
        self.assertEqual(3887, selected.plan['expected_members'])
        self.assertEqual(normalization.METADATA_SHA256, selected.metadata_sha256)
        self.assertEqual(normalization.PLAN_SHA256, selected.plan_sha256)

    def test_deterministic_sealed_output_uses_target_bytes_and_target_metadata(self):
        compressed, identity, selected, _ = self.fixture()
        outputs = []
        with self.held(compressed, identity) as held, patch.object(normalization, 'profile', return_value=selected):
            for _ in range(2):
                with normalization.normalize(held) as result:
                    outputs.append(os.pread(result.held.descriptor, result.held.identity['size'], 0))
                    self.assertEqual({'usr/bin/target', 'usr/bin/alias'}, set(result.files))
                    self.assertEqual(result.files['usr/bin/target'], result.files['usr/bin/alias'])
                    self.assertEqual(0o555, result.targets['usr/bin/alias']['metadata']['mode'])
                    self.assertEqual(123, result.targets['usr/bin/alias']['metadata']['mtime'])
                    self.assertEqual(11, result.targets['usr/bin/alias']['metadata']['uid'])
                    self.assertEqual('usr/bin/target', result.targets['usr/bin/alias']['target'])
                    self.assertEqual(result.files, archive.inspect_held(result.held))
                    self.assertEqual([], self.temporary_descriptors())
                    descriptor = result.held.descriptor
                    with self.assertRaises(OSError) as error:
                        os.write(descriptor, b'change')
                    self.assertEqual(errno.EPERM, error.exception.errno)
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
        self.assertEqual(outputs[0], outputs[1])
        self.assertEqual([], self.temporary_descriptors())

    def test_raw_input_links_still_refuse_in_the_unchanged_strict_inspector(self):
        _compressed, _identity, _selected, source = self.fixture()
        stream = io.BytesIO(source)
        with self.assertRaisesRegex(ValueError, 'links/sparse/special'):
            archive.inventory(stream)

    def test_manifest_is_captured_before_install_and_rejects_content_object_and_type_drift(self):
        compressed, identity, selected, _ = self.fixture()
        for change in ('none', 'bytes', 'replace', 'link', 'mode', 'hardlink', 'stamp'):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                state = Path(directory)
                state.chmod(0o700)
                with self.held(compressed, identity) as held, patch.object(normalization, 'profile', return_value=selected), \
                        normalization.normalize(held) as result:
                    record = normalization.write_manifest(state, result)
                    path = state / normalization.MANIFEST_NAME
                    self.assertEqual(0o400, stat.S_IMODE(path.stat().st_mode))
                    with normalization.capture_manifest(state, record) as (document, sealed, unchanged):
                        self.assertEqual(normalization.document(result), document)
                        sealed.assert_sealed()
                        if change == 'none':
                            unchanged()
                            continue
                        if change == 'bytes':
                            path.chmod(0o600)
                            path.write_bytes(b'{}')
                            path.chmod(0o400)
                        elif change in ('replace', 'link'):
                            original = path.read_bytes()
                            path.unlink()
                            if change == 'link':
                                path.symlink_to(state / 'absent')
                            else:
                                path.write_bytes(original)
                                path.chmod(0o400)
                        elif change == 'mode':
                            path.chmod(0o600)
                        elif change == 'hardlink':
                            os.link(path, state / 'alias')
                        else:
                            os.utime(path, ns=(1, 1))
                        with self.assertRaises((ValueError, FileNotFoundError)):
                            unchanged()
                    with self.assertRaises((ValueError, OSError)):
                        self.enter_manifest(state, record)

    def test_partial_manifest_write_cleans_only_its_new_file_and_never_replaces_existing_state(self):
        compressed, identity, selected, _ = self.fixture()
        with tempfile.TemporaryDirectory() as directory, self.held(compressed, identity) as held, \
                patch.object(normalization, 'profile', return_value=selected), normalization.normalize(held) as result:
            state = Path(directory)
            state.chmod(0o700)
            with patch.object(normalization, 'write_all', side_effect=OSError('inert disk refusal')):
                with self.assertRaises(OSError):
                    normalization.write_manifest(state, result)
            path = state / normalization.MANIFEST_NAME
            self.assertFalse(path.exists())
            path.write_bytes(b'prior state')
            with self.assertRaises(FileExistsError):
                normalization.write_manifest(state, result)
            self.assertEqual(b'prior state', path.read_bytes())

    def test_foreign_original_identity_refuses_before_any_codec(self):
        compressed, identity, selected, _ = self.fixture()
        identity = dict(identity, id=999)
        with self.held(compressed, identity) as held, patch.object(normalization, 'profile', return_value=selected), \
                patch.object(normalization, 'codec') as codec:
            with self.assertRaisesRegex(ValueError, 'exact independently bound'):
                self.enter_derivation(held)
            codec.assert_not_called()

    def test_changed_header_target_path_and_missing_rows_refuse_and_close_descriptors(self):
        compressed, identity, selected, _ = self.fixture()
        for change in ('name', 'target', 'missing'):
            candidate = copy.deepcopy(selected)
            if change == 'missing':
                candidate.metadata['members'].pop()
            else:
                candidate.metadata['members'][3][0 if change == 'name' else 2] = '../foreign'
            with self.subTest(change=change), self.held(compressed, identity) as held, \
                    patch.object(normalization, 'profile', return_value=candidate):
                with self.assertRaises(ValueError):
                    self.enter_derivation(held)
                self.assertEqual([], self.temporary_descriptors())

    def test_foreign_targets_unlisted_omissions_duplicates_and_wrong_counts_refuse(self):
        compressed, identity, selected, _ = self.fixture()
        for change in ('target', 'omission', 'duplicate', 'count'):
            candidate = copy.deepcopy(selected)
            if change == 'target':
                candidate.plan['materialize_regular_aliases'][0][1] = 'etc/passwd'
            elif change == 'omission':
                candidate.plan['omit_aliases'].pop()
            elif change == 'duplicate':
                candidate.plan['omit_aliases'].append(candidate.plan['omit_aliases'][0])
            else:
                candidate.plan['expected_members'] += 1
            with self.subTest(change=change), self.held(compressed, identity) as held, \
                    patch.object(normalization, 'profile', return_value=candidate):
                with self.assertRaises(ValueError):
                    self.enter_derivation(held)
                self.assertEqual([], self.temporary_descriptors())

    def test_special_and_unreviewed_pax_metadata_remain_refused(self):
        for options in ({'special': tarfile.FIFOTYPE}, {'pax': {'source.inert': 'value'}}):
            compressed, identity, selected, _ = self.fixture(**options)
            with self.subTest(options=options), self.held(compressed, identity) as held, \
                    patch.object(normalization, 'profile', return_value=selected):
                with self.assertRaisesRegex(ValueError, 'PAX/sparse/special'):
                    self.enter_derivation(held)

    def test_post_derivation_provenance_mutation_refuses(self):
        compressed, identity, selected, _ = self.fixture()
        with self.held(compressed, identity) as held, patch.object(normalization, 'profile', return_value=selected):
            with normalization.normalize(held) as result:
                result.targets['usr/bin/alias']['target'] = 'etc/passwd'
                with self.assertRaisesRegex(ValueError, 'provenance'):
                    result.assert_sealed()

    def test_complete_document_refuses_missing_foreign_type_count_and_metadata_mutations(self):
        compressed, identity, selected, _ = self.fixture()
        with self.held(compressed, identity) as held, patch.object(normalization, 'profile', return_value=selected), \
                normalization.normalize(held) as result:
            for mutation in ('missing', 'foreign', 'size', 'hash', 'target', 'metadata', 'counts', 'original', 'derived', 'schema'):
                value = copy.deepcopy(normalization.document(result))
                if mutation == 'missing':
                    del value['files']['usr/bin/target']
                elif mutation == 'foreign':
                    value['targets']['foreign'] = value['targets']['usr/bin/alias']
                elif mutation in ('size', 'hash'):
                    value['files']['usr/bin/target']['size' if mutation == 'size' else 'sha256'] = True
                elif mutation == 'target':
                    value['targets']['usr/bin/alias']['target'] = 'etc/passwd'
                elif mutation == 'metadata':
                    value['targets']['usr/bin/alias']['metadata']['mode'] = True
                elif mutation == 'counts':
                    value['proof']['materialized'] = True
                elif mutation == 'original':
                    value['proof']['original']['id'] = 999
                elif mutation == 'derived':
                    value['proof']['derived']['size'] = True
                else:
                    value['schema'] = 'foreign'
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    normalization.validate_document(value, value['proof'], identity)

    def test_codec_and_aggregate_staging_bounds_refuse_and_reclaim_all_temporary_descriptors(self):
        compressed, identity, selected, _ = self.fixture()
        for setting in (('DURATION', -1), ('MAX_STAGED', 32), ('MAX_STAGED', 15000)):
            with self.subTest(setting=setting), self.held(compressed, identity) as held, \
                    patch.object(normalization, 'profile', return_value=selected), patch.object(normalization, *setting):
                with self.assertRaises(ValueError):
                    self.enter_derivation(held)
                self.assertEqual([], self.temporary_descriptors())

    def test_original_index_refuses_canonical_parent_type_and_duplicate_collisions(self):
        for first_name, second_name, kind in (
                ('usr/bin', 'usr/bin', tarfile.REGTYPE),
                ('usr/bin', 'usr/bin/php', tarfile.REGTYPE),
                ('usr/bin/php', 'usr/bin', tarfile.REGTYPE),
                ('usr', '../host', tarfile.DIRTYPE),
                ('usr', 'usr//bin', tarfile.DIRTYPE)):
            first = tarfile.TarInfo(first_name)
            first.type = kind
            second = tarfile.TarInfo(second_name)
            index, parents = {}, set()
            normalization.index_member(first, index, parents)
            with self.subTest(second_name=second_name), self.assertRaises(ValueError):
                normalization.index_member(second, index, parents)

    def test_resolution_is_archive_local_and_refuses_cycles_depth_and_escape(self):
        target = tarfile.TarInfo('usr/bin/target')
        alias = tarfile.TarInfo('usr/bin/alias')
        alias.type, alias.linkname = tarfile.SYMTYPE, '/usr/bin/target'
        index = {'usr/bin/alias': alias, 'usr/bin/target': target}
        self.assertEqual(('regular', 'usr/bin/target'), normalization.resolve(index, 'usr/bin/alias'))
        for link in ('alias', '../../../host'):
            alias.linkname = link
            with self.subTest(link=link), self.assertRaises(ValueError):
                normalization.resolve(index, 'usr/bin/alias')
        alias.linkname = 'target'
        seen = tuple(str(number) for number in range(128))
        with self.assertRaises(ValueError):
            normalization.resolve(index, 'usr/bin/alias', seen)

    def test_source_record_links_and_byte_changes_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / 'record.json'
            source.write_text('{}')
            linked = root / 'linked.json'
            linked.symlink_to(source)
            digest = bootstrap.sha256(b'{}')
            with self.assertRaises(OSError):
                normalization.pinned_json(linked, digest)
            with self.assertRaisesRegex(ValueError, 'reviewed bytes'):
                normalization.pinned_json(source, '0' * 64)

    def test_forced_alternatives_replace_regular_copies_only_inside_owned_fixture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            alternatives, admin = root / 'alternatives', root / 'admin'
            alternatives.mkdir()
            admin.mkdir()
            for name in ('php', 'php-config'):
                versioned = root / (name + '8.3')
                alias = root / name
                versioned.write_bytes(b'inert subject, never executed')
                alias.write_bytes(versioned.read_bytes())
                result = subprocess.run(['/usr/bin/update-alternatives', '--force',
                    '--altdir', str(alternatives), '--admindir', str(admin), '--log', str(root / 'log'),
                    '--install', str(alias), name, str(versioned), '83'],
                    capture_output=True, text=True, timeout=10, check=True)
                self.assertEqual(0, result.returncode)
                self.assertTrue(alias.is_symlink())
                self.assertEqual(versioned, alias.resolve())
                self.assertEqual(versioned.read_bytes(), alias.read_bytes())

    def test_pinned_coverage_disable_removes_regular_ini_copy_and_preserves_source_ini(self):
        source = (bootstrap.ROOT / '.github/actions/setup-php-linux/vendor/src/scripts/linux.sh').read_text()
        command = next(line for line in source.splitlines()
            if line.startswith('  sudo find "$ini_dir"/.. -name "*-$extension.ini"'))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cli, mods = root / 'cli', root / 'mods-available'
            (cli / 'conf.d').mkdir(parents=True)
            mods.mkdir()
            original = mods / 'xdebug.ini'
            original.write_text('zend_extension=xdebug.so\n')
            configured = cli / 'conf.d/20-xdebug.ini'
            configured.write_bytes(original.read_bytes())
            keep = cli / 'conf.d/20-phar.ini'
            keep.write_text('extension=phar.so\n')
            script = 'sudo() { "$@"; }\nini_dir="$OWNED_CLI"\nextension=xdebug\n' + command
            subprocess.run(['/usr/bin/bash', '--noprofile', '--norc', '-c', script],
                env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'OWNED_CLI': str(cli)},
                capture_output=True, timeout=10, check=True)
            self.assertFalse(configured.exists())
            self.assertTrue(original.exists())
            self.assertTrue(keep.exists())


if __name__ == '__main__':
    unittest.main()
