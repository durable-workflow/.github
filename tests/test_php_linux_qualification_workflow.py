"""Read-only source/inline admission controls; the manual job never runs here."""
from pathlib import Path
import subprocess
import tempfile
import unittest

import yaml


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
            "GITHUB_WORKFLOW_REF":"durable-workflow/.github/.github/workflows/qualify-linux-php-initial.yml@refs/heads/main"}
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
        self.control_source = "242c2a7fb23459db2e1ada5f84dbee6d61d9b1e5"

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
        self.assertEqual("durable-workflow/.github/.github/actions/bootstrap-patched-pip@" + self.control_source, steps[4]["uses"])
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
        self.assertIn("evidence['php_helper_source']='" + SOURCE + "'", script)
        self.assertIn("evidence['pip_predecessor_source']='" + self.control_source + "'", script)
        self.assertNotIn("glob(", script)
        self.assertNotIn("DW_CI_PIP_STATE", script)

    test_actual_inline_gate_refuses_wrong_head_ref_event_repo_or_rerun_before_following_code = (
        PhpLinuxQualificationWorkflowTest.test_actual_inline_gate_refuses_wrong_head_ref_event_repo_or_rerun_before_following_code)
