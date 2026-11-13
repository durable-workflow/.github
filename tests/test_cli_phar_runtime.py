"""The PHAR recipe admits one caller without weakening whole-target trust."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import yaml

from scripts.qualification_policy import PolicyError, verify_composer_network_sinks


class CliPharRuntimeTests(unittest.TestCase):
    def setUp(self):
        repository = Path(__file__).resolve().parents[1]
        self.policy = json.loads((repository/'qualification/policy.json').read_text())
        self.catalog = json.loads((repository/'qualification/composer-container-trust.json').read_text())
        self.document = yaml.safe_load((repository/'tests/fixtures/cli-php-phar-smoke.yml').read_text())
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.recipe = self.catalog['runtime_setups']['cli-php-phar-smoke']
        # Inert bodies test the actual catalog selectors/refusals. Independent
        # source review binds the public consumer's real blobs and Git modes.
        for name, expected in self.recipe['files'].items():
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('# inert reviewed input\n')
            path.chmod(expected['mode'])
            expected['sha256'] = hashlib.sha256(path.read_bytes()).hexdigest()

    def check(self, document=None, filename='build.yml'):
        sources = {filename:yaml.safe_dump(self.document if document is None else document)}
        with mock.patch('scripts.qualification_policy._composer_container_catalog', return_value=self.catalog):
            return verify_composer_network_sinks(self.policy, 'cli', sources, self.root)

    def test_exact_proposed_caller_uses_the_registered_setup_and_actual_guard(self):
        self.assertEqual('ubuntu-24.04', self.document['jobs']['build-phar']['runs-on'])
        self.assertEqual(1, len(self.check()))

    def test_wrong_job_workflow_or_unguarded_extra_job_cannot_borrow_admission(self):
        moved = deepcopy(self.document)
        moved['jobs']['other'] = moved['jobs'].pop('build-phar')
        with self.assertRaises(PolicyError):
            self.check(moved)
        with self.assertRaises(PolicyError):
            self.check(filename='other.yml')
        extra = deepcopy(self.document)
        extra['jobs']['unguarded'] = {'steps':[{'run':'composer install --no-interaction'}]}
        with self.assertRaises(PolicyError):
            self.check(extra)

    def test_every_bound_file_and_absence_is_required(self):
        for name in self.recipe['files']:
            with self.subTest(file=name):
                path = self.root/name
                before = path.read_bytes()
                path.write_bytes(before+b'# changed\n')
                with self.assertRaises(PolicyError):
                    self.check()
                path.write_bytes(before)
        for name in self.recipe['absent_files']:
            with self.subTest(absence=name):
                path = self.root/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch()
                with self.assertRaises(PolicyError):
                    self.check()
                path.unlink()

    def test_setup_overrides_or_all_verifier_deletion_fail_closed(self):
        for field, value in (('if','false'), ('continue-on-error',True), ('env',{'CLI_PHP_CI_IMAGE':'unreviewed'})):
            altered = deepcopy(self.document)
            setup = next(step for step in altered['jobs']['build-phar']['steps']
                         if step.get('run') == self.recipe['commands'][0])
            setup[field] = value
            with self.subTest(field=field), self.assertRaises(PolicyError):
                self.check(altered)
        altered = deepcopy(self.document)
        steps = altered['jobs']['build-phar']['steps']
        steps[:] = [step for step in steps if 'verify-composer-trust@' not in step.get('uses','')]
        with self.assertRaises(PolicyError):
            self.check(altered)
        altered = deepcopy(self.document)
        altered['jobs']['build-phar']['env'] = {'CLI_PHP_CI_STATE':'unreviewed'}
        with self.assertRaises(PolicyError):
            self.check(altered)


if __name__ == '__main__':
    unittest.main()
