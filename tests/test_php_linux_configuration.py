import copy
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import php_linux_bootstrap as bootstrap
from scripts import php_linux_archive as archive
from scripts import php_linux_configuration as configuration
from scripts import php_linux_recipe as recipe


class CliConfigurationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = recipe.verified_source()

    def fixture(self):
        template = b'; held inert production template\ndisplay_errors=Off\nextension=xdebug\n'
        files = {configuration.TEMPLATE: configuration.identity(template),
                 'etc/php/8.3/cli/conf.d/20-xdebug.ini': configuration.identity(b'zend_extension=xdebug.so\n'),
                 'etc/php/8.3/cli/conf.d/20-pcov.ini': configuration.identity(b'extension=pcov.so\n'),
                 'etc/php/8.3/fpm/conf.d/20-xdebug.ini': configuration.identity(b'foreign SAPI\n')}
        document, outputs = configuration.derive(template, files, self.source)
        return template, files, document, outputs

    def test_derivation_uses_held_template_and_pinned_components(self):
        template, files, document, outputs = self.fixture()
        self.assertEqual(outputs, configuration.validate(document, files))
        self.assertEqual(b'production\n', outputs[configuration.CURRENT])
        self.assertEqual(b'\n' + self.source['src/configs/ini/jit.ini'], outputs[configuration.PECL])
        self.assertEqual(
            b'; held inert production template\ndisplay_errors=Off\n'
            + self.source['src/configs/ini/php.ini'] + self.source['src/configs/ini/xdebug.ini'],
            outputs[configuration.CLI])
        self.assertNotIn('etc/php/8.3/fpm/conf.d/20-xdebug.ini', document['removed'])
        self.assertEqual(configuration.identity(template), files[configuration.TEMPLATE])

    def test_coverage_filter_matches_actual_stock_sed(self):
        lines = [b'extension=xdebug', b'zend_extension="/tmp/xdebug.so"', b'extension=pcov.so',
                 b';extension=xdebug', b'extension=xdebugXso', b'xdebug.mode=coverage',
                 b'extension=xdebug.so ; retained comment', b'extension=redis.so',
                 b'extension=xdebug\r', b'extension=xdebug\rstill here', b'\x00extension=pcov']
        for ending in (b'', b'\n'):
            raw = b'\n'.join(lines) + ending
            actual = subprocess.run(['/usr/bin/sed', '-E',
                '-e', r'/=(.*\/)?"?xdebug(.so)?"?$/d',
                '-e', r'/=(.*\/)?"?pcov(.so)?"?$/d'], input=raw,
                capture_output=True, check=True, timeout=5).stdout
            self.assertEqual(actual, configuration.without_coverage(raw))

    def test_pinned_configuration_function_reproduces_archive_capture_refusal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            contents = {'usr/bin/php8.3': b'inert binary', 'usr/bin/php-config8.3': b'inert config',
                        configuration.CLI: b'; inert production template\n', configuration.PECL: b'\n'}
            for name, raw in contents.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            files = {name: configuration.identity(raw) for name, raw in contents.items()}
            def probe(*_args, **_options):
                return SimpleNamespace(stdout=json.dumps({'builtins':['Core','json'],
                    'extension_dir':'/usr/lib/php/20230831','config_path':'/etc/php/8.3/cli',
                    'scan_dir':'/etc/php/8.3/cli/conf.d','version':'8.3.0','zts':0,'debug':0}))
            options = {'root':root, 'execute':probe, 'shared':[],
                       'command_path':lambda name:root / ('usr/bin/' + name + '8.3'),
                       'active_configs':[root / configuration.CLI, root / configuration.PECL]}
            archive.capture_subjects(files, '8.3', [], **options)
            function = re.search(r'^configure_php\(\) \{\n.*?^\}\n',
                                 self.source['src/scripts/unix.sh'].decode(), re.M | re.S).group()
            prelude = '''set -eu
sudo() { [ "$1" = tee ] || return 78; shift; for p in "$@"; do case "$p" in -a|"$INI"|"$PECL") ;; *) return 78 ;; esac; done; /usr/bin/tee "$@"; }
add_php_config() { :; }
'''
            setup = '''
src=$1; INI=$2; PECL=$3; version=8.3; xdebug3_versions='8.3'; jit_versions='8.3';
pecl_file=$PECL; ini_file=("$INI"); configure_php
'''
            subprocess.run(['/usr/bin/bash', '--noprofile', '--norc', '-c', prelude + function + setup,
                'inert-config-control', str(recipe.UPSTREAM / 'src'),
                str(root / configuration.CLI), str(root / configuration.PECL)],
                check=True, timeout=5, env={'PATH':'/usr/bin:/bin','LC_ALL':'C'})
            with self.assertRaisesRegex(ValueError, 'does not match its held archive member'):
                archive.capture_subjects(files, '8.3', [], **options)

    def test_terminal_recomputation_refuses_changed_inputs_outputs_or_recipe(self):
        _, files, document, _ = self.fixture()
        mutations = [lambda d:d.update(profile='other'),
                     lambda d:d['input'].update(base64='YQ=='),
                     lambda d:d['input'].update(sha256='0' * 64),
                     lambda d:d['outputs'][configuration.CLI].update(sha256='0' * 64),
                     lambda d:d['components']['src/configs/ini/php.ini'].update(size=1),
                     lambda d:d['removed'].append('etc/php/8.3/fpm/conf.d/20-xdebug.ini'),
                     lambda d:d['outputs'].update({'etc/php/8.3/fpm/php.ini': {'size':1,'sha256':'0'*64}})]
        for mutate in mutations:
            candidate = copy.deepcopy(document)
            mutate(candidate)
            with self.assertRaises(ValueError):
                configuration.validate(candidate, files)

    def test_template_capture_rejects_aliases_and_changed_bytes(self):
        template, files, _, _ = self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / configuration.TEMPLATE
            target.parent.mkdir(parents=True)
            target.write_bytes(template)
            self.assertEqual(template, configuration.capture_template(files, root))
            os.link(target, target.with_suffix('.hardlink'))
            with self.assertRaises(ValueError):
                configuration.capture_template(files, root)
            target.with_suffix('.hardlink').unlink()
            target.write_bytes(b'changed template')
            with self.assertRaises(ValueError):
                configuration.capture_template(files, root)
            target.unlink()
            target.symlink_to('/not-a-template')
            with self.assertRaises(OSError):
                configuration.capture_template(files, root)

    def test_stock_writer_has_only_literal_cli_effects_and_held_removals(self):
        _, files, document, outputs = self.fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for member in outputs:
                path = root / member
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(b'ambient prior value')
            for member, raw in [('etc/php/8.3/cli/conf.d/20-xdebug.ini', b'zend_extension=xdebug.so\n'),
                                ('etc/php/8.3/cli/conf.d/20-pcov.ini', b'extension=pcov.so\n'),
                                ('etc/php/8.3/fpm/conf.d/20-xdebug.ini', b'foreign SAPI\n')]:
                path = root / member
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
            home = root / 'home'
            home.mkdir()
            (root / 'tmp').mkdir()
            environment = bootstrap.clean_environment({'PATH':'/usr/bin:/bin'}, str(home))
            calls = []
            def execute(arguments, **options):
                self.assertEqual('/usr/bin/sudo', arguments[0])
                self.assertTrue(Path(arguments[-1]).is_relative_to(root))
                self.assertIn(arguments[1], ('/usr/bin/tee', '/usr/bin/chmod', '/usr/bin/rm'))
                calls.append(arguments)
                return subprocess.run(arguments[1:], **options)
            with mock.patch.dict(os.environ, environment, clear=True):
                actual = configuration.apply(document, files, environment, root=root, execute=execute)
            self.assertEqual(outputs, actual)
            self.assertEqual(8, len(calls))
            for member, raw in outputs.items():
                self.assertEqual(raw, (root / member).read_bytes())
            self.assertEqual(b'foreign SAPI\n', (root / 'etc/php/8.3/fpm/conf.d/20-xdebug.ini').read_bytes())
            self.assertTrue(all(not (root / member).exists() for member in document['removed']))

    def test_native_writer_failure_is_not_suppressed_or_repeated(self):
        _, files, document, _ = self.fixture()
        environment = bootstrap.clean_environment({'PATH':'/usr/bin:/bin'}, '/tmp/inert-configuration-home')
        failure = subprocess.CalledProcessError(7, ['inert refused install'])
        with mock.patch.dict(os.environ, environment, clear=True), \
                mock.patch('subprocess.run', side_effect=failure) as forbidden:
            with self.assertRaises(subprocess.CalledProcessError):
                configuration.apply(document, files, environment, execute=forbidden)
            self.assertEqual(1, forbidden.call_count)


if __name__ == '__main__':
    unittest.main()
