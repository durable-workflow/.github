"""Read-only source/inline admission controls; the manual job never runs here."""
from pathlib import Path
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

import yaml
from unittest.mock import patch

from scripts import php_linux_qualification as qualification
from scripts import php_linux_normalize as normalization
from tests import test_php_linux_qualification


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / "tests/fixtures/qualify-linux-php-initial.yml"
SOURCE = "1b194dd945b72019f701e94472134135f584f652"


class PhpLinuxQualificationWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.document = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        self.job = self.document["jobs"]["qualify-initial-linux-php"]

    def test_only_the_original_manual_profile_exists_and_has_no_automatic_follower(self):
        self.assertEqual({"workflow_dispatch"},set(self.document["on"]))
        self.assertEqual({"expected_workflow_sha":{"description":"Full reviewed workflow commit selected for this original run",
                                                 "required":"true","type":"string"}},
                         self.document["on"]["workflow_dispatch"]["inputs"])
        self.assertEqual(["qualify-initial-linux-php"],list(self.document["jobs"]))
        self.assertEqual("15",self.job["timeout-minutes"])
        self.assertEqual("ubuntu-latest",self.job["runs-on"])
        self.assertEqual({"contents":"read"},self.document["permissions"])
        self.assertEqual({"contents":"read"},self.job["permissions"])
        self.assertEqual({key:"" for key in ("GITHUB_TOKEN","GH_TOKEN","GITHUB_ENTERPRISE_TOKEN",
                                          "GH_ENTERPRISE_TOKEN")},self.job["env"])
        self.assertEqual(6,len(self.job["steps"]))

    def test_source_is_immutable_and_tuple_cannot_be_selected_by_the_caller(self):
        steps=self.job["steps"]
        self.assertNotIn("uses",steps[0])
        self.assertEqual("admission",steps[0]["id"])
        self.assertEqual({"repository":"durable-workflow/.github","ref":SOURCE,
                          "persist-credentials":"false"},steps[1]["with"])
        self.assertIn(SOURCE,steps[2]["run"])
        self.assertEqual({"php-version":"8.3","tools":"composer:2.10.3,phpunit:11.5.57",
                          "coverage":"none"},steps[4]["with"])
        self.assertEqual("setup",steps[4]["id"])
        self.assertEqual("./.github/actions/setup-php-linux",steps[4]["uses"])
        terminal=steps[5]
        self.assertEqual("${{ always() && steps.admission.outcome == 'success' && (steps.setup.outcome == 'success' || steps.setup.outcome == 'failure') }}",terminal["if"])
        self.assertEqual({"SETUP_RECEIPT":"${{ steps.setup.outputs.bootstrap-receipt }}"},terminal["env"])
        self.assertIn("qualification.qualify(receipt,runner_temp,closed,publish)",terminal["run"])
        self.assertNotIn("glob(",terminal["run"])
        self.assertIn("os.environ.clear()",terminal["run"])
        self.assertIn("'source']='"+SOURCE+"'",terminal["run"])

    def test_actual_inline_gate_refuses_wrong_head_ref_event_repo_or_rerun_before_following_code(self):
        script=self.job["steps"][0]["run"]
        environment={"PATH":"/usr/bin:/bin","LC_ALL":"C","EXPECTED_WORKFLOW_SHA":"a"*40,
            "GITHUB_SHA":"a"*40,"GITHUB_WORKFLOW_SHA":"a"*40,"GITHUB_REPOSITORY":"durable-workflow/.github",
            "GITHUB_EVENT_NAME":"workflow_dispatch","GITHUB_REF":"refs/heads/main","GITHUB_RUN_ATTEMPT":"1",
            "GITHUB_WORKFLOW_REF":getattr(self, 'workflow_ref',
                "durable-workflow/.github/.github/workflows/qualify-linux-php-initial.yml@refs/heads/main")}
        variants=[({},True)]
        variants += [({key:value},False) for key,value in (
            ("EXPECTED_WORKFLOW_SHA",""),("EXPECTED_WORKFLOW_SHA","bad"),("EXPECTED_WORKFLOW_SHA","b"*40),
            ("GITHUB_SHA","b"*40),("GITHUB_WORKFLOW_SHA","b"*40),("GITHUB_REPOSITORY","other/repo"),
            ("GITHUB_EVENT_NAME","push"),("GITHUB_REF","refs/heads/unreviewed"),("GITHUB_RUN_ATTEMPT","2"),
            ("GITHUB_WORKFLOW_REF","other/workflow@refs/heads/main"))]
        with tempfile.TemporaryDirectory() as directory:
            marker=Path(directory)/"following-effect"
            for changes,success in variants:
                marker.unlink(missing_ok=True)
                result=subprocess.run(["/usr/bin/bash","--noprofile","--norc","-c",
                    script+"\nprintf inert > following-effect"],cwd=directory,
                    env=dict(environment,**changes),capture_output=True,check=False)
                with self.subTest(changes=changes):
                    self.assertEqual(success,result.returncode==0)
                    self.assertEqual(success,marker.exists())


class PrivatePipQualificationWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.document = yaml.load((ROOT / "tests/fixtures/qualify-linux-php-private-pip.yml").read_text(), Loader=yaml.BaseLoader)
        self.job = self.document["jobs"]["qualify-initial-linux-php"]
        self.previous = yaml.load(WORKFLOW.read_text(), Loader=yaml.BaseLoader)
        self.previous_job = self.previous["jobs"]["qualify-initial-linux-php"]
        self.control_source = "2ca775c1951c1e6a6a469f5a0db672c00479b337"
        self.pip_source = "242c2a7fb23459db2e1ada5f84dbee6d61d9b1e5"

    def test_event_profile_tokens_and_all_job_bounds_are_preserved(self):
        self.assertEqual(self.previous["on"], self.document["on"])
        self.assertEqual(self.previous["permissions"], self.document["permissions"])
        self.assertEqual(list(self.previous["jobs"]), list(self.document["jobs"]))
        self.assertEqual({key: value for key, value in self.previous_job.items() if key != "steps"},
                         {key: value for key, value in self.job.items() if key != "steps"})
        self.assertEqual(7, len(self.job["steps"]))
        self.assertEqual(self.previous_job["steps"][0], self.job["steps"][0])
        self.assertEqual(self.previous_job["steps"][4], self.job["steps"][5])

    def test_php_helper_and_private_control_are_separate_immutable_checkouts_before_code(self):
        steps = self.job["steps"]
        self.assertEqual(self.previous_job["steps"][1], steps[1])
        self.assertEqual({"repository": "durable-workflow/.github", "ref": self.control_source,
                          "path": ".qualification-control", "persist-credentials": "false"}, steps[2]["with"])
        self.assertEqual(steps[1]["uses"], steps[2]["uses"])
        preflight = steps[3]["run"]
        self.assertLess(preflight.index("test \"$(/usr/bin/git rev-parse HEAD)\" = " + SOURCE),
                        preflight.index("/usr/bin/python3 -I -S -B"))
        self.assertLess(preflight.index("test \"$(/usr/bin/git -C .qualification-control rev-parse HEAD)\" = " + self.control_source),
                        preflight.index("/usr/bin/python3 -I -S -B"))
        self.assertEqual("pip_trust", steps[4]["id"])
        self.assertEqual("durable-workflow/.github/.github/actions/bootstrap-patched-pip@" + self.pip_source, steps[4]["uses"])
        self.assertEqual({"clients": "python"}, steps[4]["with"])
        self.assertFalse(any("setup-python" in step.get("uses", "") for step in steps))

    def test_terminal_consumes_only_exact_producer_outputs_and_keeps_both_source_identities(self):
        terminal = self.job["steps"][6]
        self.assertEqual(self.previous_job["steps"][5]["if"], terminal["if"])
        self.assertEqual({"SETUP_RECEIPT": "${{ steps.setup.outputs.bootstrap-receipt }}",
            "PIP_RECEIPT": "${{ steps.pip_trust.outputs.pip-state }}",
            "PIP_CREATED": "${{ steps.pip_trust.outputs.pip-created }}",
            "PIP_ROOT_IDENTITY": "${{ steps.pip_trust.outputs.pip-root-identity }}",
            "PIP_RECEIPT_IDENTITY": "${{ steps.pip_trust.outputs.pip-receipt-identity }}"}, terminal["env"])
        script = terminal["run"]
        self.assertIn("sys.path.insert(0,str(pathlib.Path.cwd()/'.qualification-control'))", script)
        self.assertIn("qualification.qualify(receipt,runner_temp,closed,publish,pip_state=pip_state)", script)
        self.assertLess(script.index("pip_state={"), script.index("os.environ.clear()"))
        self.assertLess(script.index("pip_state={"), script.index("receipt_text="))
        self.assertIn("pathlib.Path(receipt_text) if receipt_text else None", script)
        self.assertNotIn("if not receipt_text:", script)
        self.assertIn("evidence['php_helper_source']='" + SOURCE + "'", script)
        self.assertIn("evidence['pip_predecessor_source']='" + self.pip_source + "'", script)
        self.assertIn("evidence['source']='" + self.control_source + "'", script)
        self.assertNotIn("glob(", script)
        self.assertNotIn("DW_CI_PIP_STATE", script)

    def test_actual_terminal_with_missing_setup_output_cleans_only_proven_pip_and_publishes_bounded_refusal(self):
        script = self.job["steps"][6]["run"].split("<<'PYCODE'\n", 1)[1].rsplit("\nPYCODE", 1)[0]
        fixture = test_php_linux_qualification.PhpLinuxQualificationTest()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            setup_receipt, _, _, _ = fixture.fixture(root)
            pip_state, data, _, _ = fixture.pip_fixture(root)
            summary = root / "summary"
            environment = {"RUNNER_TEMP": str(root), "GITHUB_STEP_SUMMARY": str(summary),
                "SETUP_RECEIPT": "", "PIP_RECEIPT": data["receipt"], "PIP_CREATED": data["created"],
                "PIP_ROOT_IDENTITY": data["root_identity"], "PIP_RECEIPT_IDENTITY": data["receipt_identity"],
                "GITHUB_REPOSITORY": "durable-workflow/.github", "GITHUB_WORKFLOW_SHA": "a" * 40,
                "GITHUB_SHA": "a" * 40, "GITHUB_REF": "refs/heads/main", "GITHUB_EVENT_NAME": "workflow_dispatch",
                "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
            probes = []
            original = qualification.qualify
            def qualify(*args, **options):
                self.assertIsNone(args[0])
                self.assertEqual(data, options["pip_state"])
                options["probes"] = lambda *_: probes.append("unexpected")
                return original(*args, **options)
            output = io.StringIO()
            code = compile(script, "inert-private-pip-terminal", "exec")
            with patch.dict(os.environ, environment, clear=True), patch.object(sys, "path", list(sys.path)), \
                    patch.object(qualification, "qualify", side_effect=qualify), \
                    contextlib.chdir(root), contextlib.redirect_stdout(output), self.assertRaises(ValueError):
                exec(code, {})
            records = [json.loads(line) for line in output.getvalue().splitlines()]
            refusals = [record for record in records if record.get("schema") == "durable-workflow.php-linux-terminal/v1"]
            self.assertEqual(1, len(refusals))
            self.assertEqual("refused", refusals[0]["outcome"])
            self.assertEqual("pass", refusals[0]["private_pip_cleanup"])
            self.assertLessEqual(len(output.getvalue().encode()), 65536)
            self.assertEqual([], probes)
            self.assertFalse(pip_state.root.exists())
            self.assertTrue(setup_receipt.parent.exists())
            self.assertNotIn('"outcome": "pass"', summary.read_text())

    test_actual_inline_gate_refuses_wrong_head_ref_event_repo_or_rerun_before_following_code = (
        PhpLinuxQualificationWorkflowTest.test_actual_inline_gate_refuses_wrong_head_ref_event_repo_or_rerun_before_following_code)


class NormalizedQualificationWorkflowTest(unittest.TestCase):
    fixture = "qualify-linux-php-normalized.yml"
    source = '45a7863dbc425ecf19a5a4038a84a9443c23a9a9'
    configured_receipt = False
    expected_subject_schema = None

    def setUp(self):
        self.raw = (ROOT / "tests/fixtures" / self.fixture).read_bytes()
        self.document = yaml.load(self.raw, Loader=yaml.BaseLoader)
        self.job = self.document['jobs']['qualify-initial-linux-php']

    def test_only_the_two_coordinated_source_identities_change_from_consumed_profile(self):
        previous = (ROOT / 'tests/fixtures/qualify-linux-php-private-pip.yml').read_bytes()
        for source in (SOURCE, '2ca775c1951c1e6a6a469f5a0db672c00479b337'):
            self.assertEqual(3, previous.count(source.encode()))
            previous = previous.replace(source.encode(), self.source.encode())
        self.assertEqual(previous, self.raw)
        steps = self.job['steps']
        self.assertEqual(7, len(steps))
        for step in steps[1:3]:
            self.assertEqual(self.source, step['with']['ref'])
            self.assertEqual('durable-workflow/.github', step['with']['repository'])
            self.assertEqual('false', step['with']['persist-credentials'])
        preflight = steps[3]['run']
        self.assertEqual(2, preflight[:preflight.index('/usr/bin/python3')].count(self.source))
        self.assertEqual('durable-workflow/.github/.github/actions/bootstrap-patched-pip@'
            '242c2a7fb23459db2e1ada5f84dbee6d61d9b1e5', steps[4]['uses'])
        self.assertEqual({'clients': 'python'}, steps[4]['with'])
        terminal = steps[6]['run']
        self.assertIn("evidence['source']='" + self.source + "'", terminal)
        self.assertIn("evidence['php_helper_source']='" + self.source + "'", terminal)

    def terminal_receipt(self, fixture, root, mutation):
        receipt, _, _, _, profile = fixture.normalized_fixture(root,
            configured=self.configured_receipt and mutation != 'legacy-schema')
        if mutation in ('manifest-bytes', 'configuration-bytes'):
            name = 'cli-configuration.json' if mutation == 'configuration-bytes' else normalization.MANIFEST_NAME
            manifest = receipt.parent / name
            manifest.chmod(0o600)
            manifest.write_bytes(b'{}')
            manifest.chmod(0o400)
        if mutation == 'legacy-subject-schema':
            report = json.loads(receipt.read_bytes())
            report['subjects']['schema'] = 'durable-workflow.php-linux-subjects/v1'
            receipt.write_text(json.dumps(report))
        return receipt, profile

    def reader_options(self):
        # Old fixtures replay their historical source reader; v4 uses the live default.
        if self.configured_receipt:
            return {}
        return {'required_schema': None}

    def test_actual_normalized_terminal_revalidates_document_and_cleans_both_proven_states(self):
        script = self.job['steps'][6]['run'].split("<<'PYCODE'\n", 1)[1].rsplit('\nPYCODE', 1)[0]
        code = compile(script, 'inert-normalized-terminal', 'exec')
        fixture = test_php_linux_qualification.PhpLinuxQualificationTest()
        mutations = ('none', 'manifest-bytes', 'configuration-bytes', 'legacy-schema') if self.configured_receipt else ('none', 'manifest-bytes')
        if self.expected_subject_schema is not None:
            mutations += ('legacy-subject-schema',)
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                receipt, profile = self.terminal_receipt(fixture, root, mutation)
                pip_state, pip_data, pip_report, pip_subjects = fixture.pip_fixture(root)
                summary = root / 'summary'
                environment = {'RUNNER_TEMP': str(root), 'GITHUB_STEP_SUMMARY': str(summary),
                    'SETUP_RECEIPT': str(receipt), 'PIP_RECEIPT': pip_data['receipt'],
                    'PIP_CREATED': pip_data['created'], 'PIP_ROOT_IDENTITY': pip_data['root_identity'],
                    'PIP_RECEIPT_IDENTITY': pip_data['receipt_identity'],
                    'GITHUB_REPOSITORY': 'durable-workflow/.github', 'GITHUB_WORKFLOW_SHA': 'a' * 40,
                    'GITHUB_SHA': 'a' * 40, 'GITHUB_REF': 'refs/heads/main', 'GITHUB_EVENT_NAME': 'workflow_dispatch',
                    'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1'}
                probes = []
                original = qualification.qualify
                def qualify(*args, **options):
                    options.update(self.reader_options())
                    options['subjects'] = lambda *_args, **_options: None
                    options['alternatives'] = lambda _files, **_options: {'count': 9, 'inventory_sha256': 'a' * 64}
                    options['probes'] = lambda *_args: probes.append('inert PHAR substitute')
                    return original(*args, **options)
                output = io.StringIO()
                expectation = contextlib.nullcontext() if mutation == 'none' else self.assertRaises(ValueError)
                with patch.dict(os.environ, environment, clear=True), patch.object(sys, 'path', list(sys.path)), \
                        patch.object(normalization, 'profile', return_value=profile), \
                        patch.object(qualification.private_pip, 'verify_runtime', return_value=(pip_report, pip_subjects)), \
                        patch.object(qualification, 'qualify', side_effect=qualify), contextlib.chdir(root), \
                        contextlib.redirect_stdout(output), expectation:
                    exec(code, {})
                records = [json.loads(line) for line in output.getvalue().splitlines()]
                terminal = next(row for row in records if row.get('schema') == 'durable-workflow.php-linux-terminal/v1')
                self.assertEqual('pass' if mutation == 'none' else 'refused', terminal['outcome'])
                self.assertEqual(self.source, terminal['source'])
                self.assertEqual(self.source, terminal['php_helper_source'])
                self.assertEqual('pass', terminal['cleanup'])
                self.assertEqual('pass', terminal['private_pip_cleanup'])
                if self.configured_receipt and mutation == 'none':
                    self.assertTrue(terminal['configuration']['revalidated'])
                if self.expected_subject_schema is not None and mutation == 'none':
                    self.assertEqual(self.expected_subject_schema, terminal['receipt']['subjects']['schema'])
                self.assertEqual(['inert PHAR substitute'] if mutation == 'none' else [], probes)
                self.assertFalse(receipt.parent.exists())
                self.assertFalse(pip_state.root.exists())
                self.assertLessEqual(len(output.getvalue().encode()), 65536)

    test_actual_terminal_with_missing_setup_output_cleans_only_proven_pip_and_publishes_bounded_refusal = (
        PrivatePipQualificationWorkflowTest.test_actual_terminal_with_missing_setup_output_cleans_only_proven_pip_and_publishes_bounded_refusal)
    test_actual_inline_gate_refuses_wrong_head_ref_event_repo_or_rerun_before_following_code = (
        PhpLinuxQualificationWorkflowTest.test_actual_inline_gate_refuses_wrong_head_ref_event_repo_or_rerun_before_following_code)


class AlternativesQualificationWorkflowTest(NormalizedQualificationWorkflowTest):
    fixture = 'qualify-linux-php-alternatives.yml'
    source = '5f64e43d7dda8d30a7b0c5433f838bb3fe5f85ec'
    predecessor_fixture = 'qualify-linux-php-normalized.yml'
    predecessor_source = NormalizedQualificationWorkflowTest.source

    def test_exact_consumed_normalized_fixture_changes_only_six_source_literals(self):
        old = (ROOT / 'tests/fixtures' / self.predecessor_fixture).read_bytes()
        previous = self.predecessor_source.encode()
        self.assertEqual(6, old.count(previous))
        self.assertEqual(old.replace(previous, self.source.encode()), self.raw)


class SelectedAlternativesQualificationWorkflowTest(AlternativesQualificationWorkflowTest):
    fixture = 'qualify-linux-php-selected-alternatives.yml'
    source = 'fd390417973902bae3ac4847fb67ae778c854786'
    predecessor_fixture = AlternativesQualificationWorkflowTest.fixture
    predecessor_source = AlternativesQualificationWorkflowTest.source


class ConfiguredCliQualificationWorkflowTest(SelectedAlternativesQualificationWorkflowTest):
    fixture = 'qualify-linux-php-configured-cli.yml'
    source = '153f409e36002b2ae5f010f247a03b8830898e3c'
    predecessor_fixture = SelectedAlternativesQualificationWorkflowTest.fixture
    predecessor_source = SelectedAlternativesQualificationWorkflowTest.source
    configured_receipt = True


class ReferencedSubjectsQualificationWorkflowTest(ConfiguredCliQualificationWorkflowTest):
    fixture = 'qualify-linux-php-subject-references.yml'
    source = '140f937cf245f39a495467fe6bab2bd30f93a17a'
    predecessor_fixture = ConfiguredCliQualificationWorkflowTest.fixture
    predecessor_source = ConfiguredCliQualificationWorkflowTest.source
    expected_subject_schema = 'durable-workflow.php-linux-subjects/v2'


class Ubuntu24QualificationWorkflowTest(unittest.TestCase):
    def setUp(self):
        self.raw = (ROOT / 'tests/fixtures/qualify-linux-php-ubuntu24.yml').read_bytes()
        self.document = yaml.load(self.raw, Loader=yaml.BaseLoader)
        self.job = self.document['jobs']['qualify-initial-linux-php']
        self.workflow_ref = 'durable-workflow/.github/.github/workflows/qualify-linux-php-ubuntu24.yml@refs/heads/main'

    def test_only_closed_host_path_labels_and_six_source_literals_differ_from_accepted_initial_profile(self):
        previous = (ROOT / 'tests/fixtures/qualify-linux-php-subject-references.yml').read_bytes()
        self.assertEqual(6, previous.count(b'140f937cf245f39a495467fe6bab2bd30f93a17a'))
        changes = (
            (b'140f937cf245f39a495467fe6bab2bd30f93a17a', b'8ba5caae2546f3d5f41b7616c5722b9b337b8fc0'),
            (b'name: Qualify initial bound Linux PHP setup', b'name: Qualify bound Ubuntu 24 Linux PHP setup'),
            (b'group: initial-bound-linux-php', b'group: bound-ubuntu24-linux-php'),
            (b'name: Original initial Linux PHP setup qualification', b'name: Original Ubuntu 24 Linux PHP setup qualification'),
            (b'runs-on: ubuntu-latest', b'runs-on: ubuntu-24.04'),
            (b'.github/workflows/qualify-linux-php-initial.yml@refs/heads/main',
             b'.github/workflows/qualify-linux-php-ubuntu24.yml@refs/heads/main'),
            (b"release='26.04'", b"release='24.04'"),
            (b"'host':'ubuntu26.04/x86_64'", b"'host':'ubuntu24.04/x86_64'"))
        for old, new in changes:
            previous = previous.replace(old, new)
        self.assertEqual(previous, self.raw)
        self.assertEqual({'workflow_dispatch'}, set(self.document['on']))
        self.assertEqual('ubuntu-24.04', self.job['runs-on'])
        self.assertEqual('15', self.job['timeout-minutes'])
        self.assertEqual({'contents':'read'}, self.job['permissions'])
        self.assertEqual('242c2a7fb23459db2e1ada5f84dbee6d61d9b1e5',
                         self.job['steps'][4]['uses'].rsplit('@', 1)[1])

    def test_actual_inline_gate_keeps_exact_original_admission_for_the_new_path(self):
        PhpLinuxQualificationWorkflowTest.test_actual_inline_gate_refuses_wrong_head_ref_event_repo_or_rerun_before_following_code(self)


class RepinnedUbuntu24QualificationWorkflowTest(unittest.TestCase):
    """The Ubuntu 24 profile re-pointed to the re-pinned setup source (#359)."""

    previous_source = b'8ba5caae2546f3d5f41b7616c5722b9b337b8fc0'
    source = b'411a14ac07d32073eed6ab4977f2825eba4739a7'

    def setUp(self):
        self.raw = (ROOT / 'tests/fixtures/qualify-linux-php-ubuntu24-repinned.yml').read_bytes()
        self.document = yaml.load(self.raw, Loader=yaml.BaseLoader)
        self.job = self.document['jobs']['qualify-initial-linux-php']
        self.workflow_ref = 'durable-workflow/.github/.github/workflows/qualify-linux-php-ubuntu24.yml@refs/heads/main'

    def test_only_the_six_source_literals_differ_from_the_accepted_ubuntu24_profile(self):
        previous = (ROOT / 'tests/fixtures/qualify-linux-php-ubuntu24.yml').read_bytes()
        self.assertEqual(6, previous.count(self.previous_source))
        self.assertEqual(previous.replace(self.previous_source, self.source), self.raw)
        self.assertNotIn(self.previous_source, self.raw)
        self.assertEqual(6, self.raw.count(self.source))

    def test_helper_and_control_checkouts_bind_the_repinned_source_before_code(self):
        steps = self.job['steps']
        source = self.source.decode()
        self.assertEqual({'repository': 'durable-workflow/.github', 'ref': source,
                          'persist-credentials': 'false'}, steps[1]['with'])
        self.assertEqual({'repository': 'durable-workflow/.github', 'ref': source,
                          'path': '.qualification-control', 'persist-credentials': 'false'}, steps[2]['with'])
        preflight = steps[3]['run']
        for check in ('test "$(/usr/bin/git rev-parse HEAD)" = ' + source,
                      'test "$(/usr/bin/git -C .qualification-control rev-parse HEAD)" = ' + source):
            self.assertLess(preflight.index(check), preflight.index('/usr/bin/python3 -I -S -B'))
        self.assertEqual('./.github/actions/setup-php-linux', steps[5]['uses'])
        terminal = steps[6]['run']
        self.assertIn("evidence['source']='" + source + "'", terminal)
        self.assertIn("evidence['php_helper_source']='" + source + "'", terminal)
        self.assertEqual('242c2a7fb23459db2e1ada5f84dbee6d61d9b1e5', steps[4]['uses'].rsplit('@', 1)[1])
        self.assertEqual('ubuntu-24.04', self.job['runs-on'])
        self.assertEqual({'workflow_dispatch'}, set(self.document['on']))

    def test_actual_inline_gate_keeps_exact_original_admission_for_the_new_path(self):
        PhpLinuxQualificationWorkflowTest.test_actual_inline_gate_refuses_wrong_head_ref_event_repo_or_rerun_before_following_code(self)


class ArchiveRepairQualificationWorkflowTest(unittest.TestCase):
    def test_both_original_profiles_change_only_six_immutable_source_literals(self):
        from scripts import protected_policy_context as context
        from scripts.protected_policy_inputs import InputRefused

        source = b'5c1ddbff59bcfad8a686a72a9b09804b359c382a'
        profiles = (
            ('initial', 'qualify-linux-php-subject-references.yml',
             b'140f937cf245f39a495467fe6bab2bd30f93a17a'),
            ('ubuntu24', 'qualify-linux-php-ubuntu24-repinned.yml',
             b'411a14ac07d32073eed6ab4977f2825eba4739a7'),
        )
        for name, previous_name, previous_source in profiles:
            path = f'.github/workflows/qualify-linux-php-{name}.yml'
            previous = (ROOT / 'tests/fixtures' / previous_name).read_bytes()
            raw = (ROOT / f'tests/fixtures/qualify-linux-php-{name}-archive-repair.yml').read_bytes()
            with self.subTest(profile=name):
                self.assertEqual(6, previous.count(previous_source))
                self.assertEqual(previous.replace(previous_source, source), raw)
                self.assertEqual(raw, (ROOT / path).read_bytes())
                context.validate_context({path: raw})
                with patch.object(context, 'REVIEWED_PHP_ARCHIVE_REPAIR_PROFILE_SUCCESSORS', {}), \
                        self.assertRaises(InputRefused):
                    context.validate_context({path: raw})
                self.document = yaml.load(raw, Loader=yaml.BaseLoader)
                self.job = self.document['jobs']['qualify-initial-linux-php']
                self.workflow_ref = f'durable-workflow/.github/{path}@refs/heads/main'
                PhpLinuxQualificationWorkflowTest.test_actual_inline_gate_refuses_wrong_head_ref_event_repo_or_rerun_before_following_code(self)
