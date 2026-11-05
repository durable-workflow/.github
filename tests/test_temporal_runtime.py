import contextlib
import hashlib
import io
import importlib.util
import json
import os
import stat
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock


START_RUNTIME = (
    Path(__file__).resolve().parents[1]
    / 'conformance/cancellation/temporal/start-runtime.py'
)


class TemporalRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.temporary_parent = self.root / 'temporary'
        self.temporary_parent.mkdir(mode=0o700)
        self.enterContext(mock.patch.object(tempfile, 'tempdir', str(self.temporary_parent)))
        self.enterContext(contextlib.chdir(self.root))
        self.binary = b'verified fixture executable, never executed'
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode='w:gz') as bundle:
            entry = tarfile.TarInfo('temporal')
            entry.size = len(self.binary)
            bundle.addfile(entry, io.BytesIO(self.binary))
        self.archive = archive.getvalue()
        spec = importlib.util.spec_from_file_location('temporal_runtime', START_RUNTIME)
        self.runtime = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.runtime)
        self.enterContext(mock.patch.object(self.runtime, 'ARCHIVE_SHA256', hashlib.sha256(self.archive).hexdigest()))
        self.enterContext(mock.patch.object(self.runtime, 'ARCHIVE_SIZE', len(self.archive)))
        self.versions = self.runtime.expected_versions()
        self.final_url = self.runtime.ARCHIVE_URL
        self.open = mock.Mock(side_effect=self.response)
        self.enterContext(mock.patch(
            'urllib.request.build_opener', return_value=mock.Mock(open=self.open),
        ))
        self.execute = self.enterContext(mock.patch('os.execv'))

    def launch(self):
        self.execute.reset_mock()
        (self.root / 'versions.json').write_text(json.dumps(self.versions))
        self.runtime.main()
        self.execute.assert_called_once()
        executable, arguments = self.execute.call_args.args
        database = Path(arguments[arguments.index('--db-filename') + 1])
        return Path(executable), database

    def response(self, *_args, **_kwargs):
        response = io.BytesIO(self.archive)
        response.geturl = lambda: self.final_url
        return response

    def test_binary_and_database_use_a_private_directory(self):
        executable, database = self.launch()
        self.assertTrue(executable.is_relative_to(self.temporary_parent))
        self.assertEqual(executable.parent, database.parent)
        self.assertEqual(stat.S_IMODE(executable.parent.stat().st_mode), 0o700)
        self.assertEqual(executable.read_bytes(), self.binary)
        self.assertTrue(os.access(executable, os.X_OK))
        self.assertFalse(database.exists())

    def test_each_launch_has_distinct_executable_and_database_paths(self):
        first = self.launch()
        second = self.launch()
        self.assertNotEqual(first[0], second[0])
        self.assertNotEqual(first[1], second[1])

    def test_archive_checksum_mismatch_refuses_execution(self):
        self.archive = self.archive[:-1] + bytes([self.archive[-1] ^ 1])
        with self.assertRaisesRegex(RuntimeError, 'checksum mismatch'):
            self.launch()
        self.execute.assert_not_called()
        self.assertEqual(list(self.temporary_parent.iterdir()), [])

    def test_candidate_archive_url_or_digest_cannot_select_runtime_authority(self):
        for field, value in (('archive', 'https://example.invalid/replacement.tar.gz'),
                             ('sha256', '0' * 64), ('cli', 'unreviewed')):
            with self.subTest(field=field):
                self.versions = {**self.runtime.expected_versions(), field: value}
                with self.assertRaisesRegex(RuntimeError, 'reviewed runtime policy'):
                    self.launch()
                self.open.assert_not_called()
                self.execute.assert_not_called()

    def test_unexpected_final_authority_refuses_before_execution(self):
        self.final_url = 'https://example.invalid/asset'
        with self.assertRaisesRegex(RuntimeError, 'final URL'):
            self.launch()
        self.execute.assert_not_called()
        self.assertEqual([], list(self.temporary_parent.iterdir()))

    def test_oversized_archive_refuses_before_execution(self):
        self.archive += b'extra bytes'
        with self.assertRaisesRegex(RuntimeError, 'checksum mismatch'):
            self.launch()
        self.execute.assert_not_called()

    def test_only_the_reviewed_public_asset_redirect_is_allowed_once(self):
        handler = self.runtime.PublishedAssetRedirect()
        request = self.runtime.urllib.request.Request(self.runtime.ARCHIVE_URL)
        asset = 'https://release-assets.githubusercontent.com' + self.runtime.ASSET_PATH + '?signed=example'
        result = handler.redirect_request(request, None, 302, 'Found', {}, asset)
        self.assertEqual(asset, result.full_url)
        with self.assertRaisesRegex(RuntimeError, 'redirect'):
            handler.redirect_request(result, None, 302, 'Found', {}, asset)

    def test_redirect_origin_credentials_port_and_path_drift_refuse(self):
        path = self.runtime.ASSET_PATH
        for url in ('http://release-assets.githubusercontent.com' + path,
                    'https://example.invalid' + path,
                    'https://release-assets.githubusercontent.com:444' + path,
                    'https://user@release-assets.githubusercontent.com' + path,
                    'https://release-assets.githubusercontent.com/other-asset',
                    'https://release-assets.githubusercontent.com' + path + '#fragment'):
            handler = self.runtime.PublishedAssetRedirect()
            request = self.runtime.urllib.request.Request(self.runtime.ARCHIVE_URL)
            with self.subTest(url=url), self.assertRaisesRegex(RuntimeError, 'redirect'):
                handler.redirect_request(request, None, 302, 'Found', {}, url)
