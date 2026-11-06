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

    def update(self, root):
        # Consume the complete fixed upstream function, including its parallel
        # masters, seven .gz slave operations and unresolved socket operation.
        function = re.search(r'^fix_alternatives\(\) \{\n.*?^\}', self.original, re.M | re.S)[0]
        function = function.replace('/usr/', shlex.quote(str(root)) + '/usr/')
        function = function.replace('/run/', shlex.quote(str(root)) + '/run/')
        (root / 'admin').mkdir()
        (root / 'etc/alternatives').mkdir(parents=True, exist_ok=True)
        script = '''sudo() {
  test "$1" = update-alternatives || return 79
  shift
  /usr/bin/update-alternatives --altdir "$OWNED_ROOT/etc/alternatives" \\
    --admindir "$OWNED_ROOT/admin" --log "$OWNED_ROOT/log" "$@"
}
version=8.3
''' + function + '\nfix_alternatives\n'
        return subprocess.run(['/usr/bin/bash', '--noprofile', '--norc', '-c', script],
            env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'OWNED_ROOT': str(root)},
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
                result = self.update(root)
                if old:
                    self.assertGreaterEqual(result.stderr.count('Invalid argument'), 9)
                    with self.assertRaisesRegex(ValueError, 'alternatives edge'):
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
                with self.assertRaises((ValueError, FileNotFoundError)):
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
