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
