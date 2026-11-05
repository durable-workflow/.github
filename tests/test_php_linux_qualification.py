"""Terminal custody controls with inert files/probes; no PHP/root/setup executes."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import php_linux_archive as archive
from scripts import php_linux_bootstrap as bootstrap
from scripts import php_linux_recipe as recipe
from scripts import php_linux_tools as tools
from scripts import php_linux_qualification as qualification
from scripts import setup_php_linux as setup


class PhpLinuxQualificationTest(unittest.TestCase):
    def closed_qualify(self, path, root, environment, publish, **options):
        with patch.dict(os.environ, environment, clear=True):
            return qualification.qualify(path, root, environment, publish, **options)

    def fixture(self, root):
        state = root / "dw-php-setup-inert"
        state.mkdir(mode=0o700)
        catalog = json.loads(bootstrap.CATALOG.read_text())
        tool_catalog = json.loads(tools.CATALOG.read_text())
        host = {"operating_system": "ubuntu", "release": "26.04", "architecture": "x86_64"}
        request = recipe.capture_request({"INPUT_PHP-VERSION": "8.3",
            "INPUT_TOOLS": "composer:2.10.3,phpunit:11.5.57", "INPUT_COVERAGE": "none"})
        plan = recipe.validate_request(request, catalog, tool_catalog, host)
        data = {"usr/bin/php8.3": b"inert PHP", "usr/bin/php-config8.3": b"inert config",
                "etc/php/8.3/cli/php.ini": b"; inert archive configuration\n"}
        subjects = {"schema": archive.SUBJECT_SCHEMA, "files": {
            "/" + name: {"type": "regular", "size": len(value), "sha256": bootstrap.sha256(value),
                        "authority": {"kind": "archive", "member": name}} for name, value in data.items()},
            "commands": {"php": "/usr/bin/php8.3", "php-config": "/usr/bin/php-config8.3"},
            "configs": {"/etc/php/8.3/cli/php.ini": "/etc/php/8.3/cli/php.ini"}}
        for row in plan["tools"]:
            subjects["files"]["/usr/local/bin/" + row["name"]] = {
                "type": "regular", "size": row["size"], "sha256": row["sha256"],
                "authority": {"kind": "tool", "name": row["name"]}}
        binary = subjects["files"]["/usr/bin/php8.3"]
        original = (bootstrap.ROOT / "qualification/vendor/php-ubuntu-713206915/install.sh").read_bytes()
        url = bootstrap.asset_url(plan["archive"]["asset"])
        report = {"schema": setup.RECEIPT_SCHEMA, "outcome": "pass", "stage": "complete",
            "host": host, "image": {"ImageOS": "ubuntu26", "ImageVersion": "inert-image"},
            "apt": {"invoked": False, "profile": "no-apt"}, "ca_sha256": setup.CA_SHA256,
            "request": request, "host_tool": {"node": "/usr/bin/node", "node_version": "v24.22.1",
                                            "node_sha256": "a" * 64},
            "setup_php_commit": bootstrap.SOURCE_COMMIT,
            "source_hashes": {name: bootstrap.sha256(value) for name, value in
                recipe.derive_source(recipe.verified_source(), state / "refusal").items()},
            "preinstalled_authority": False,
            "tools": [{"target": "/usr/local/bin/" + row["name"], **tools.identity(row)} for row in plan["tools"]],
            "installer": dict(catalog["installer"],
                derived_sha256=bootstrap.sha256(bootstrap.no_apt_installer_source(original, catalog))),
            "archive": dict(plan["archive"]["asset"], effective=bootstrap.effective_url(url)),
            "installed": {"binary": {"source": "usr/bin/php8.3", "size": binary["size"], "sha256": binary["sha256"]},
                          "extensions": {}, "version": "8.3.36", "zts": 0, "debug": 0},
            "configured": {"loaded_extensions": ["core", "json"], "coverage": "none"},
            "subjects": subjects}
        path = state / setup.RECEIPT_NAME
        path.write_text(json.dumps(report))
        path.chmod(0o600)
        environment = bootstrap.clean_environment({}, str(root / "private-home"))
        return path, report, plan, environment

    def test_exact_complete_producer_receipt_is_required_before_any_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            path, report, _, _ = self.fixture(Path(directory))
            qualification.validate_success(report, path.parent)
            for name in qualification.PASS_FIELDS:
                changed = copy.deepcopy(report)
                del changed[name]
                with self.subTest(missing=name), self.assertRaises(ValueError):
                    qualification.validate_success(changed, path.parent)
            for key, value in (("outcome", "running"), ("stage", "tool-install-phpunit"),
                               ("schema", "durable-workflow.php-linux-setup-receipt/v1"),
                               ("preinstalled_authority", True), ("subjects", {})):
                changed = dict(report, **{key: value})
                with self.subTest(key=key), self.assertRaises(ValueError):
                    qualification.validate_success(changed, path.parent)

    def test_literal_identity_source_and_manifest_drift_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            path, report, _, _ = self.fixture(Path(directory))
            changes = []
            for key in ("installer", "archive"):
                changed = copy.deepcopy(report); changed[key]["digest"] = "sha256:" + "0" * 64
                changes.append(changed)
            changed = copy.deepcopy(report); changed["source_hashes"]["dist/index.js"] = "0" * 64
            changes.append(changed)
            changed = copy.deepcopy(report); changed["subjects"]["files"]["/usr/local/bin/phpunit"]["sha256"] = "0" * 64
            changes.append(changed)
            changed = copy.deepcopy(report); changed["subjects"]["configs"]["/etc/php/8.3/cli/php.ini"] = "/foreign"
            changes.append(changed)
            changed = copy.deepcopy(report); changed["image"] = {}
            changes.append(changed)
            for index, changed in enumerate(changes):
                with self.subTest(change=index), self.assertRaises(ValueError):
                    qualification.validate_success(changed, path.parent)

    def test_noncanonical_subjects_and_incomplete_runtime_identities_refuse(self):
        for value in ("relative", "/usr//bin/php", "/usr/../bin/php", "/usr/bin/php\n"):
            with self.subTest(path=value), self.assertRaises(ValueError):
                qualification.canonical_path(value)
        with tempfile.TemporaryDirectory() as directory:
            path,report,_,_=self.fixture(Path(directory))
            changes=[]
            for key,value in (("version","8.4.27"),("debug",True),("zts",1),("extensions",{"unknown":{}})):
                item=copy.deepcopy(report);item["installed"][key]=value;changes.append(item)
            for key,value in (("coverage","xdebug"),("loaded_extensions",["xdebug"]),("loaded_extensions",[])):
                item=copy.deepcopy(report);item["configured"][key]=value;changes.append(item)
            item=copy.deepcopy(report);item["host_tool"]["node_version"]="v22.1.0";changes.append(item)
            item=copy.deepcopy(report);item["image"]["ImageVersion"]="";changes.append(item)
            for index,item in enumerate(changes):
                with self.subTest(change=index),self.assertRaises(ValueError):
                    qualification.validate_success(item,path.parent)

    def test_producer_custody_seals_bytes_and_refuses_writes_replacements_and_aliases(self):
        for mutation in ("write", "replace", "alias"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                path, _, _, _ = self.fixture(Path(directory))
                with qualification.capture_receipt(path, Path(directory)) as (_, held, unchanged):
                    held.assert_sealed()
                    if mutation == "write":
                        path.write_text("{}")
                    else:
                        original = path.read_bytes()
                        path.unlink()
                        if mutation == "alias":
                            target = path.parent / "other.json"; target.write_bytes(original)
                            path.symlink_to(target)
                        else:
                            path.write_bytes(original); path.chmod(0o600)
                    with self.assertRaises(ValueError):
                        unchanged()

    def test_empty_receipt_is_not_reduced_to_apparent_terminal_evidence(self):
        # The exact original c191 collector accepts {}; its replacement must
        # refuse it before either installed PHAR callback and clean exact state.
        fixture = Path(__file__).parent / "fixtures/php_terminal_collector_c191.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path, _, _, environment = self.fixture(root)
            path.write_text("{}")
            summary = root / "old-summary"; outputs = io.StringIO()
            with patch.dict(os.environ, {"RUNNER_TEMP": directory, "GITHUB_STEP_SUMMARY": str(summary)}), \
                    contextlib.redirect_stdout(outputs):
                exec(compile(fixture.read_bytes(), str(fixture), "exec"), {})
            self.assertIn("receipt_sha256", outputs.getvalue())
            self.assertNotIn('"outcome"', outputs.getvalue())
            probes, evidence = [], []
            with self.assertRaises(ValueError):
                self.closed_qualify(path, root, environment, evidence.append,
                    probes=lambda *_: probes.append("unexpected"))
            self.assertEqual([], probes)
            self.assertEqual("refused", evidence[0]["outcome"])
            self.assertFalse(path.parent.exists())

    def test_post_probe_object_and_installed_subject_checks_precede_evidence_and_cleanup(self):
        for mutation in ("none", "receipt-write", "receipt-replace", "subject"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root=Path(directory);path, _, _, environment=self.fixture(root)
                events=[];changed=False
                def subjects(*_):
                    events.append("subjects")
                    if changed:
                        raise ValueError("Inert installed subject changed")
                def probes(*_):
                    nonlocal changed
                    events.append("probes")
                    if mutation=="receipt-write":
                        path.write_text("{}")
                    elif mutation=="receipt-replace":
                        raw=path.read_bytes();path.unlink();path.write_bytes(raw);path.chmod(0o600)
                    elif mutation=="subject":
                        changed=True
                def publish(evidence):
                    self.assertFalse(path.parent.exists())
                    events.append("publish-"+evidence["outcome"])
                if mutation=="none":
                    self.closed_qualify(path,root,environment,publish,subjects=subjects,probes=probes)
                    self.assertEqual(["subjects","probes","subjects","publish-pass"],events)
                else:
                    with self.assertRaises(ValueError):
                        self.closed_qualify(path,root,environment,publish,subjects=subjects,probes=probes)
                    self.assertEqual("publish-refused",events[-1])
                self.assertFalse(path.parent.exists())

    def test_receipt_path_type_owner_mode_and_duplicate_fields_refuse(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path, report, _, _=self.fixture(root)
            path.chmod(0o644)
            operation=qualification.capture_receipt(path,root)
            with self.assertRaises(ValueError):
                operation.__enter__()

            path.chmod(0o600)
            path.write_text('{"outcome":"pass","outcome":"refused"}')
            operation=qualification.capture_receipt(path,root)
            with self.assertRaises(ValueError):
                operation.__enter__()
            path.write_text(json.dumps(report))
            alias=path.parent/"alias.json";alias.symlink_to(path)
            operation=qualification.capture_receipt(alias,root)
            with self.assertRaises(ValueError):
                operation.__enter__()

    def test_parent_environment_must_already_be_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path, _, _, environment=self.fixture(Path(directory))
            with patch.dict(os.environ, dict(environment, GH_TOKEN="inert-test-value"), clear=True):
                with self.assertRaisesRegex(ValueError,"closed parent"):
                    qualification.qualify(path,Path(directory),environment,lambda _:None)

    def test_publishing_failure_still_cleans_the_exact_owned_state(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);path,_,_,environment=self.fixture(root)
            def publish(_):
                raise ValueError("Inert evidence sink failed")
            with self.assertRaisesRegex(ValueError,"evidence sink"):
                self.closed_qualify(path,root,environment,publish,subjects=lambda *_:None,probes=lambda *_:[])
            self.assertFalse(path.parent.exists())

    def test_exact_predecessor_publishes_pass_before_cleanup_refusal_and_successor_never_does(self):
        fixture=Path(__file__).parent/"fixtures/php_terminal_qualify_682e8da.py"
        namespace=dict(vars(qualification))
        exec(compile(fixture.read_bytes(),str(fixture),"exec"),namespace)
        predecessor=namespace["qualify"]
        for old in (True,False):
            with self.subTest(predecessor=old),tempfile.TemporaryDirectory() as directory:
                root=Path(directory);path,_,_,environment=self.fixture(root);published=[]
                function=predecessor if old else qualification.qualify
                with patch.dict(os.environ,environment,clear=True), \
                        patch.object(qualification.shutil,"rmtree",side_effect=OSError("Inert cleanup refusal")):
                    with self.assertRaises(OSError):
                        function(path,root,environment,lambda evidence:published.append(copy.deepcopy(evidence)),
                                 subjects=lambda *_:None,probes=lambda *_:[])
                self.assertTrue(path.parent.exists())
                self.assertEqual("pass" if old else "refused",published[0]["outcome"])
                if not old:
                    self.assertEqual("cleanup",published[0]["stage"])

    def test_native_probe_argv_and_outputs_are_bounded_without_executing_php(self):
        with tempfile.TemporaryDirectory() as directory:
            _,report,plan,environment=self.fixture(Path(directory))
            calls=[]
            def execute(arguments,**options):
                calls.append((arguments,options))
                name=Path(arguments[1]).name
                prefix="Composer version 2.10.3 " if name=="composer" else "PHPUnit 11.5.57 "
                return SimpleNamespace(stdout=prefix+"inert source control\n")
            result=qualification.run_probes(plan,environment,execute)
            self.assertEqual(["composer","phpunit"],[item["name"] for item in result])
            self.assertEqual(2,len(calls))
            for arguments,options in calls:
                self.assertEqual("/usr/bin/php8.3",arguments[0])
                self.assertEqual(environment["HOME"],options["cwd"])
                self.assertEqual(10,options["timeout"])
                self.assertNotIn("GH_TOKEN",options["env"])
                self.assertEqual("1",options["env"]["COMPOSER_DISABLE_NETWORK"])
            def wrong(*_args,**_options):
                return SimpleNamespace(stdout="wrong installed version")
            with self.assertRaises(ValueError):
                qualification.run_probes(plan,environment,wrong)

    def test_revalidation_compares_the_same_producer_manifest_and_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            _,report,plan,_=self.fixture(Path(directory))
            def capture(*_):
                manifest=copy.deepcopy(report["subjects"])
                manifest["files"]={path:row for path,row in manifest["files"].items()
                                   if row["authority"]["kind"]!="tool"}
                return report["installed"],manifest
            def append(manifest,row):
                path="/usr/local/bin/"+row["name"]
                manifest["files"][path]=report["subjects"]["files"][path]
            enabled=lambda *_:report["configured"]
            qualification.revalidate_subjects(report,plan,capture=capture,append=append,enabled=enabled)
            def changed(*_):
                installed,manifest=capture()
                manifest["configs"]["/etc/php/8.3/cli/php.ini"]="/foreign"
                return installed,manifest
            with self.assertRaises(ValueError):
                qualification.revalidate_subjects(report,plan,capture=changed,append=append,enabled=enabled)
