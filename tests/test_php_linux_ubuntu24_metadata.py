"""Pinned metadata controls; no public payload, installer or PHP executes."""
import copy
from collections import Counter
import hashlib
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import php_linux_alternatives as alternatives
from scripts import php_linux_bootstrap as bootstrap
from scripts import php_linux_normalize as normalization
from scripts import setup_php_linux as setup


ASSET = {'id': 672921837, 'name': 'php_8.3-nts+ubuntu24.04.tar.zst', 'size': 43691699,
         'digest': 'sha256:58a7c29b7fcb00e884e947aaae8276a09c9bca18d39fd2a50efd88c5f860ee76'}


class Ubuntu24ArchiveMetadataTest(unittest.TestCase):
    def setUp(self):
        self.selected = normalization.profile(ASSET)
        self.metadata, self.plan = self.selected.metadata, self.selected.plan
        self.index = {}
        parents = set()
        for values in self.metadata['members']:
            row = dict(zip(self.metadata['columns'], values))
            member = tarfile.TarInfo(row['name'])
            member.type, member.linkname, member.size = row['type'].encode(), row['linkname'], row['size']
            normalization.index_member(member, self.index, parents)

    def test_complete_asset_and_observed_inventory_are_independently_pinned(self):
        asset = {key: ASSET[key] for key in ('id', 'name', 'size')}
        asset['sha256'] = ASSET['digest'].removeprefix('sha256:')
        self.assertEqual(asset, self.metadata['asset'])
        self.assertEqual(asset, self.plan['asset'])
        self.assertEqual(3625, len(self.index))
        self.assertEqual({'0': 2569, '2': 684, '5': 372}, self.metadata['type_counts'])
        self.assertEqual(self.metadata['type_counts'],
                         dict(Counter(member.type.decode() for member in self.index.values())))
        self.assertEqual(0, self.metadata['pax_headers'])
        self.assertEqual(0, self.metadata['sparse_members'])
        self.assertEqual('5dc78662912017ae9ed64b548655c4804adf479996055d4dd7765700b0e6ef32',
                         self.metadata['raw_inventory_sha256'])
        raw = (bootstrap.ROOT / 'qualification/php-linux-ubuntu24-archive.json').read_bytes()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), self.plan['metadata_sha256'])

    def test_every_link_has_exact_regular_authority_or_an_explicit_nonregular_omission(self):
        aliases, omitted = normalization.checked_plan(self.index, self.plan)
        self.assertEqual(634, len(aliases))
        self.assertEqual(50, len(omitted))
        self.assertEqual(6, sum(row[1] == 'directory' for row in self.plan['omit_aliases']))
        self.assertEqual(44, sum(row[1] == 'unresolved' for row in self.plan['omit_aliases']))
        files, expected_aliases = normalization.expected_subjects(self.selected)
        self.assertEqual(aliases, expected_aliases)
        self.assertEqual(3203, len(files))
        self.assertEqual(3575, self.plan['expected_members'])
        for name, target in aliases.items():
            with self.subTest(alias=name):
                self.assertEqual(files[target], files[name])
                self.assertFalse(any(other.startswith(name + '/') for other in self.index))

    def test_installer_managed_targets_are_contained_but_do_not_gain_installed_authority(self):
        for row in alternatives.inventory()['managed']:
            with self.subTest(group=row['group']):
                expected = ('regular', row['archive_member'])
                self.assertEqual(expected, normalization.resolve(self.index, row['path']))
                self.assertEqual(expected, normalization.resolve(self.index, row['target']))
        request = {'request': {'inputs': {'php-version': '8.3', 'extensions': [], 'coverage': 'none'}},
                   'tools': [{'name': 'composer'}, {'name': 'phpunit'}]}
        with self.assertRaisesRegex(ValueError, 'Initial no-APT profile'):
            setup.initial_profile(request, {'operating_system': 'ubuntu', 'release': '24.04',
                                            'architecture': 'x86_64'})

    def test_incomplete_foreign_and_cross_profile_identities_refuse_before_codec(self):
        candidates = [None, {}, [], dict(ASSET, id=True), dict(ASSET, id=672923785),
                      dict(ASSET, id=999), dict(ASSET, path='caller-map.json')]
        for key in ('name', 'size', 'digest'):
            candidate = dict(ASSET)
            candidate[key] = 'foreign'
            candidates.append(candidate)
            candidate = dict(ASSET)
            del candidate[key]
            candidates.append(candidate)
        with patch.object(normalization, 'codec') as codec:
            for candidate in candidates:
                with self.subTest(identity=candidate), self.assertRaises(ValueError):
                    held = SimpleNamespace(identity=candidate, assert_sealed=lambda: None)
                    with normalization.normalize(held):
                        self.fail('Foreign input reached derivation')
            codec.assert_not_called()
        self.assertEqual(672923785, normalization.profile().metadata['asset']['id'])

    def test_missing_duplicate_and_changed_target_treatments_refuse(self):
        for mutation in ('missing', 'duplicate', 'target', 'omission'):
            candidate = copy.deepcopy(self.plan)
            if mutation == 'missing':
                candidate['materialize_regular_aliases'].pop()
            elif mutation == 'duplicate':
                candidate['omit_aliases'].append(candidate['omit_aliases'][0])
            elif mutation == 'target':
                candidate['materialize_regular_aliases'][0][1] = 'etc/passwd'
            else:
                candidate['omit_aliases'][0][1] = 'regular'
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                normalization.checked_plan(self.index, candidate)


if __name__ == '__main__':
    unittest.main()
