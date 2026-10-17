import contextlib
import hashlib
import io
import json
import os
import runpy
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
        self.versions = {
            'archive': 'https://example.invalid/temporal.tar.gz',
            'sha256': hashlib.sha256(self.archive).hexdigest(),
        }
        self.enterContext(mock.patch(
            'urllib.request.urlopen',
            side_effect=lambda *args, **kwargs: io.BytesIO(self.archive),
        ))
        self.execute = self.enterContext(mock.patch('os.execv'))

    def launch(self):
        self.execute.reset_mock()
        (self.root / 'versions.json').write_text(json.dumps(self.versions))
        runpy.run_path(str(START_RUNTIME))
        self.execute.assert_called_once()
        executable, arguments = self.execute.call_args.args
        database = Path(arguments[arguments.index('--db-filename') + 1])
        return Path(executable), database

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
        self.versions['sha256'] = '0' * 64
        with self.assertRaisesRegex(RuntimeError, 'checksum mismatch'):
            self.launch()
        self.execute.assert_not_called()
        self.assertEqual(list(self.temporary_parent.iterdir()), [])
