"""Static publisher input and proposed normalization, never installer authority."""
import io
import hashlib
import json
from pathlib import Path
import posixpath
import tarfile
import unittest

from scripts import php_linux_archive as archive

ROOT = Path(__file__).resolve().parents[1]


class InitialArchiveMetadataTest(unittest.TestCase):
    def setUp(self):
        self.metadata = json.loads((ROOT / 'qualification/php-linux-initial-archive.json').read_text())
        self.plan = json.loads((ROOT / 'qualification/php-linux-initial-normalization.json').read_text())
        self.rows = [dict(zip(self.metadata['columns'], values)) for values in self.metadata['members']]
        self.members = {row['name'].removeprefix('./').rstrip('/'): row for row in self.rows}

    def test_static_record_binds_the_selected_publisher_object_and_complete_types(self):
        self.assertEqual({'id': 672923785, 'name': 'php_8.3-nts+ubuntu26.04.tar.zst', 'size': 41840918,
            'sha256': '846f69bcf56fc25f672ab888415c12d40122b684c8fb9f1de87b7ddb64fa4272'}, self.metadata['asset'])
        self.assertEqual(self.metadata['asset'], self.plan['asset'])
        raw = (ROOT / 'qualification/php-linux-initial-archive.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), self.plan['metadata_sha256'])
        self.assertEqual(3975, len(self.rows))
        self.assertEqual(len(self.rows), len(self.members))
        self.assertEqual({'0': 2821, '2': 764, '5': 390},
            {kind: sum(row['type'] == kind for row in self.rows) for kind in ('0', '2', '5')})
        self.assertEqual(0, self.metadata['pax_headers'])
        self.assertEqual(0, self.metadata['sparse_members'])

    def test_minimal_observed_header_still_refuses_in_the_product_parser(self):
        observed = self.metadata['first_refusal']
        self.assertEqual(21, observed['number'])
        self.assertEqual('./etc/rcS.d/S01x11-common', observed['name'])
        self.assertEqual('../init.d/x11-common', observed['linkname'])
        member = tarfile.TarInfo(observed['name'])
        member.type = observed['type'].encode()
        member.linkname = observed['linkname']
        fixture = io.BytesIO()
        with tarfile.open(fileobj=fixture, mode='w') as output:
            output.addfile(member)
        fixture.seek(0)
        with self.assertRaisesRegex(ValueError, 'links/sparse/special'):
            archive.inventory(fixture)

    def resolve(self, name, seen=()):
        row = self.members.get(name)
        if row is None:
            return 'unresolved', name
        if row['type'] != '2':
            return ('regular' if row['type'] == '0' else 'directory'), name
        self.assertNotIn(name, seen)
        value = row['linkname']
        target = posixpath.normpath(value.lstrip('/') if value.startswith('/')
            else posixpath.join(posixpath.dirname(name), value))
        self.assertFalse(target == '..' or target.startswith('../'))
        return self.resolve(target, (*seen, name))

    def test_proposal_covers_only_exact_links_with_contained_regular_targets_or_explicit_omissions(self):
        aliases = self.plan['materialize_regular_aliases']
        omitted = self.plan['omit_aliases']
        links = {name for name, row in self.members.items() if row['type'] == '2'}
        self.assertEqual(676, len(aliases))
        self.assertEqual(88, len(omitted))
        self.assertEqual(links, {name for name, _target in aliases} | {name for name, _kind, _target in omitted})
        self.assertEqual(764, len({name for name, *_ in aliases + omitted}))
        for name, target in aliases:
            with self.subTest(name=name):
                self.assertEqual(('regular', target), self.resolve(name))
        for name, kind, target in omitted:
            with self.subTest(name=name):
                self.assertIn(kind, ('directory', 'unresolved'))
                self.assertEqual((kind, target), self.resolve(name))
        self.assertEqual(2821 + len(aliases), self.plan['expected_regular_files'])
        self.assertEqual(390, self.plan['expected_directories'])
        self.assertEqual(self.plan['expected_regular_files'] + 390, self.plan['expected_members'])
        self.assertEqual(0, self.plan['expected_links'])

    def test_proposed_alias_paths_cannot_parent_other_archive_members(self):
        for name, _target in self.plan['materialize_regular_aliases']:
            with self.subTest(name=name):
                self.assertFalse(any(other.startswith(name + '/') for other in self.members))


if __name__ == '__main__':
    unittest.main()
