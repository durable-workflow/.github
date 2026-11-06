"""Stock tar/updater controls in temporary paths; no PHP/setup/root executes."""
import io
import json
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import tempfile
import unittest

from scripts import php_linux_alternatives as alternatives
from scripts import php_linux_bootstrap as bootstrap
from scripts import php_linux_normalize as normalization


class PhpLinuxAlternativesTest(unittest.TestCase):
    def setUp(self):
        self.record = alternatives.inventory()
        self.original = (bootstrap.ROOT / 'qualification/vendor/php-ubuntu-713206915/install.sh').read_text()
        self.catalog = json.loads(bootstrap.CATALOG.read_text())

    def contents(self):
        files = {}
        for row in self.record['managed']:
            value = ('inert regular subject ' + row['archive_member']).encode()
            for path in (row['target'], row['command'], row['path']):
                files[path] = value
        for row in self.record['retained_regular']:
            files[row['path']] = ('inert retained alias ' + row['target']).encode()
        return files

    def extract(self, root, installer):
        contents = self.contents()
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode='w') as output:
            for path, value in contents.items():
                member = tarfile.TarInfo('./' + path)
                member.size, member.mode = len(value), 0o600
                output.addfile(member, io.BytesIO(value))
        excludes = [word for word in shlex.split(installer) if word.startswith('--exclude=')]
        subprocess.run(['/usr/bin/tar', *excludes, '-xf', '-', '-C', str(root)],
            input=stream.getvalue(), capture_output=True, timeout=5, check=True)
        return {path: {'size': len(value), 'sha256': bootstrap.sha256(value)}
                for path, value in contents.items()}

    def stock(self, root, *arguments):
        (root / 'admin').mkdir(exist_ok=True)
        (root / 'etc/alternatives').mkdir(parents=True, exist_ok=True)
        return subprocess.run(['/usr/bin/update-alternatives', '--altdir', str(root / 'etc/alternatives'),
            '--admindir', str(root / 'admin'), '--log', str(root / 'log'), *arguments],
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'}, capture_output=True, text=True, timeout=5, check=True)

    def existing_choices(self, root, mode):
        version = {'auto-higher': '8.5', 'manual-other': '8.2', 'preselected-held': '8.3'}[mode]
        for row in self.record['managed']:
            # The actual refused host had no competing FPM choice.
            if mode == 'auto-higher' and row['group'] == 'php-fpm':
                continue
            target = root / row['target'].replace('8.3', version)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b'inert provider option, never executed')
            command = root / row['command']
            command.parent.mkdir(parents=True, exist_ok=True)
            self.stock(root, '--install', str(command), row['group'], str(target), version.replace('.', ''))
            if mode != 'auto-higher':
                self.stock(root, '--set', row['group'], str(target))
        return version

    def update(self, root, installer=None, refusal=''):
        # Consume the complete fixed upstream function, including its parallel
        # masters, seven .gz slave operations and unresolved socket operation.
        function = re.search(r'^fix_alternatives\(\) \{\n.*?^\}',
            self.successor() if installer is None else installer, re.M | re.S)[0]
        # Route only the literal stock-tool calls into the same private
        # link/admin/log namespace; every subject path is below this fixture.
        function = function.replace('/usr/bin/sudo /usr/bin/update-alternatives', 'sudo update-alternatives')
        function = function.replace('/usr/', shlex.quote(str(root)) + '/usr/')
        function = function.replace('/run/', shlex.quote(str(root)) + '/run/')
        (root / 'admin').mkdir(exist_ok=True)
        (root / 'etc/alternatives').mkdir(parents=True, exist_ok=True)
        script = '''sudo() {
  test "$1" = update-alternatives || return 79
  shift
  if [ "$1" = --set ] && [ "$2" = "$REFUSE_GROUP" ]; then return 2; fi
  /usr/bin/update-alternatives --altdir "$OWNED_ROOT/etc/alternatives" \\
    --admindir "$OWNED_ROOT/admin" --log "$OWNED_ROOT/log" "$@"
}
version=8.3
''' + function + '\nfix_alternatives\n'
        return subprocess.run(['/usr/bin/bash', '--noprofile', '--norc', '-c', script],
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'OWNED_ROOT': str(root), 'REFUSE_GROUP': refusal},
            capture_output=True, text=True, timeout=10)

    def successor(self):
        return bootstrap.no_apt_installer_source(self.original.encode(), self.catalog).decode()

    def test_inventory_classifies_real_writers_without_conflating_plain_and_gzip_manpages(self):
        plan = json.loads((bootstrap.ROOT / 'qualification/php-linux-initial-normalization.json').read_text())
        aliases = dict(plan['materialize_regular_aliases'])
        managed, retained = self.record['managed'], self.record['retained_regular']
        self.assertEqual(9, len(managed))
        self.assertEqual(8, len(retained))
        self.assertEqual({name for name in aliases if name.startswith('etc/alternatives/')},
            {row['path'] for row in managed + retained})
        for row in managed:
            self.assertEqual(aliases[row['path']], row['archive_member'])
            self.assertEqual(aliases.get(row['target'], row['target']), row['archive_member'])
        self.assertEqual(7, len(self.record['slave_writers']))
        self.assertTrue(all(not row['target_in_regular_archive'] for row in self.record['slave_writers']))
        self.assertNotIn(self.record['socket_writer']['alternative'], alternatives.exclusions())
        self.assertEqual(bootstrap.sha256(self.original.encode()), self.record['installer_sha256'])

    def test_ubuntu24_inventory_binds_its_own_archive_and_the_same_nine_stock_writers(self):
        asset = normalization.reviewed_profile(672921837).metadata['asset']
        original = {**{key:asset[key] for key in ('id', 'name', 'size')}, 'digest':'sha256:'+asset['sha256']}
        previous = self.record
        self.record, digest = alternatives.inventory_source(original)
        self.assertNotEqual(alternatives.INVENTORY_SHA256, digest)
        self.assertEqual({key:value for key,value in previous.items() if key != 'archive_metadata_sha256'},
                         {key:value for key,value in self.record.items() if key != 'archive_metadata_sha256'})
        self.assertEqual(normalization.profile(original).metadata_sha256, self.record['archive_metadata_sha256'])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.existing_choices(root, 'auto-higher')
            files = self.extract(root, self.successor())
            result = self.update(root)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual({'inventory_sha256':digest, 'count':9},
                             alternatives.verify(files, root, original=original))
        foreign = dict(original, digest='sha256:'+'f'*64)
        with self.assertRaises(ValueError):
            alternatives.inventory(foreign)

    def test_exact_predecessor_retains_regular_alternatives_and_successor_restores_nine_canonical_edges(self):
        previous = (bootstrap.ROOT / 'tests/fixtures/php_initial_installer_45a7863.sh').read_text()
        self.assertEqual('aa8ae569228c9206845a2a0322a01f8076d3773f215c192cfec15455dddb57e3',
            bootstrap.sha256(previous.encode()))
        for old, installer in ((True, previous), (False, self.successor())):
            with self.subTest(predecessor=old), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                files = self.extract(root, installer)
                for row in self.record['managed']:
                    self.assertEqual(old, (root / row['path']).exists())
                result = self.update(root, installer)
                if old:
                    self.assertGreaterEqual(result.stderr.count('Invalid argument'), 9)
                    with self.assertRaisesRegex(ValueError, 'Alternative php-cgi-bin: alternative edge'):
                        alternatives.verify(files, root)
                else:
                    self.assertEqual(0, result.returncode, result.stderr)
                    self.assertNotIn('Invalid argument', result.stderr)
                    self.assertEqual({'inventory_sha256': alternatives.INVENTORY_SHA256, 'count': 9},
                        alternatives.verify(files, root))
                    for name in ('php', 'php-config'):
                        self.assertEqual(root / ('usr/bin/' + name + '8.3'), (root / ('usr/bin/' + name)).resolve())
                for row in self.record['retained_regular']:
                    self.assertTrue((root / row['path']).is_file())
                    self.assertFalse((root / row['path']).is_symlink())

    def test_real_registration_predecessor_retains_existing_choice_and_successor_selects_only_held_targets(self):
        previous = (bootstrap.ROOT / 'tests/fixtures/php_initial_installer_5f64e43.sh').read_text()
        self.assertEqual('c2530ef6938c0fd0d2944d2080e09ec7cd3f7cb2d46e6c9336efb683d98166b5',
            bootstrap.sha256(previous.encode()))
        for mode in ('auto-higher', 'manual-other', 'preselected-held'):
            for old, installer in ((True, previous), (False, self.successor())):
                with self.subTest(mode=mode, predecessor=old), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    version = self.existing_choices(root, mode)
                    foreign = root / 'usr/bin/unrelated42'
                    foreign.write_bytes(b'inert unrelated option')
                    command = root / 'usr/bin/unrelated'
                    self.stock(root, '--install', str(command), 'unrelated', str(foreign), '42')
                    self.stock(root, '--set', 'unrelated', str(foreign))
                    state = (root / 'admin/unrelated').read_bytes()
                    files = self.extract(root, installer)
                    result = self.update(root, installer)
                    self.assertEqual(0, result.returncode, result.stderr)
                    if old and mode != 'preselected-held':
                        with self.assertRaisesRegex(ValueError, 'Alternative php-cgi-bin: alternative edge'):
                            alternatives.verify(files, root)
                        row = self.record['managed'][0]
                        self.assertEqual(root / row['target'].replace('8.3', version),
                            (root / row['command']).resolve())
                    else:
                        self.assertEqual(9, alternatives.verify(files, root)['count'])
                    for row in self.record['managed']:
                        if mode == 'auto-higher' and row['group'] == 'php-fpm':
                            continue
                        options = self.stock(root, '--list', row['group']).stdout.splitlines()
                        self.assertIn(str(root / row['target'].replace('8.3', version)), options)
                        self.assertIn(str(root / row['target']), options)
                    self.assertEqual(state, (root / 'admin/unrelated').read_bytes())
                    self.assertEqual(foreign, command.resolve())

    def test_native_selection_refusal_exits_without_accepting_an_unheld_choice(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.existing_choices(root, 'auto-higher')
            files = self.extract(root, self.successor())
            result = self.update(root, refusal='php-cgi-bin')
            self.assertEqual(2, result.returncode)
            with self.assertRaisesRegex(ValueError, 'Alternative php-cgi-bin: alternative edge'):
                alternatives.verify(files, root)

    def test_foreign_target_missing_authority_and_wrong_edge_type_refuse(self):
        for mutation in ('foreign-alternative', 'foreign-command', 'regular-alternative', 'missing-authority', 'changed-target'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                files = self.extract(root, self.successor())
                self.update(root)
                row = self.record['managed'][0]
                if mutation == 'missing-authority':
                    del files[row['target']]
                elif mutation == 'changed-target':
                    (root / row['target']).write_bytes(b'foreign bytes')
                else:
                    path = root / row['command' if mutation == 'foreign-command' else 'path']
                    path.unlink()
                    if mutation == 'regular-alternative':
                        path.write_bytes(b'copied bytes are not a canonical edge')
                    else:
                        path.symlink_to(root / 'unproved-target')
                with self.assertRaisesRegex(ValueError, 'Alternative php-cgi-bin:'):
                    alternatives.verify(files, root)

    def test_extraction_excludes_only_the_nine_bound_master_paths_and_preserves_no_apt_order(self):
        source = self.successor()
        before = source.index('\nfix_alternatives\n')
        self.assertLess(source.index('\ninstall\n'), before)
        self.assertLess(before, source.index('\nfix_redis_linking\n'))
        expected = {'--exclude=' + prefix + name for name in alternatives.exclusions() for prefix in ('', './')}
        self.assertEqual(expected, {word for word in shlex.split(source)
            if word.startswith('--exclude=etc/alternatives/') or word.startswith('--exclude=./etc/alternatives/')})
        self.assertNotIn('apt-get ', source)
        self.assertNotIn('sudo apt ', source)
        self.assertNotIn('rm -', source)


if __name__ == '__main__':
    unittest.main()
