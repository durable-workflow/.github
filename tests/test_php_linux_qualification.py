"""Terminal custody controls with inert files/probes; no PHP/root/setup executes."""

import contextlib
import copy
import io
import json
import os
from pathlib import Path
import tempfile
import tarfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import php_linux_archive as archive
from scripts import php_linux_bootstrap as bootstrap
from scripts import php_linux_recipe as recipe
from scripts import php_linux_tools as tools
from scripts import php_linux_qualification as qualification
from scripts import setup_php_linux as setup
from scripts import php_linux_normalize as normalization


class PhpLinuxQualificationTest(unittest.TestCase):
    def closed_qualify(self, path, root, environment, publish, **options):
        options.setdefault('alternatives', lambda _files: {'count': 9, 'inventory_sha256': 'a' * 64})
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

    def pip_fixture(self, root):
        runtime = qualification.private_pip
        state = runtime._private_root(root)
        state.receipt.write_text('{"inert-public-pip-receipt":true}')
        state.receipt.chmod(0o600)
        with runtime.held_file(state.receipt, owned=True) as (_raw, identity):
            self.assertTrue(_raw)
        data = {"receipt": str(state.receipt), "root_identity": json.dumps(state.identity),
                "receipt_identity": json.dumps(identity), "created": "true"}
        report = {"root_identity": state.identity, "interpreter": {"version": [3, 14, 4]}}
        return state, data, report, {"inert-module": identity}

    def normalized_fixture(self, root):
        path, report, plan, environment = self.fixture(root)
        files = {name.lstrip('/'): {key: value[key] for key in ('size', 'sha256')}
            for name, value in report['subjects']['files'].items() if value['authority']['kind'] == 'archive'}
        alias = 'etc/php/8.3/cli/php.ini'
        target = 'etc/php/8.3/mods-available/inert.ini'
        files[target] = dict(files[alias])
        info = tarfile.TarInfo('./' + target)
        info.size = files[target]['size']
        metadata = {key: value.decode('ascii') if isinstance(value, bytes) else value
            for key, value in info.get_info().items()}
        targets = {alias: {'target': target, **files[target], 'metadata': metadata}}
        asset = plan['archive']['asset']
        original = {key: asset[key] for key in ('id', 'name', 'size')}
        original['sha256'] = asset['digest'].removeprefix('sha256:')
        rows = [['./' + name, '0', '', identity['size'], 0, 512]
            for name, identity in files.items() if name != alias]
        selected = normalization.Profile({'asset': original, 'members': rows,
            'columns': ['name', 'type', 'linkname', 'size', 'offset', 'offset_data']},
            {'materialize_regular_aliases': [[alias, target]], 'omit_aliases': [],
             'expected_regular_files': len(files), 'expected_directories': 0,
             'expected_members': len(files), 'expected_links': 0}, 'a' * 64, 'b' * 64)
        proof = {'schema': normalization.SCHEMA, 'original': dict(asset),
            'derived': {'name': 'php-initial-regular-only.tar.zst', 'size': 17, 'digest': 'sha256:' + 'c' * 64},
            'metadata_sha256': selected.metadata_sha256, 'plan_sha256': selected.plan_sha256,
            'file_manifest_sha256': bootstrap.sha256(normalization.canonical_json(files)),
            'target_manifest_sha256': bootstrap.sha256(normalization.canonical_json(targets)),
            'regular_files': len(files), 'directories': 0, 'members': len(files), 'materialized': 1, 'omitted': 0}
        document = {'schema': normalization.DOCUMENT_SCHEMA, 'proof': proof, 'files': files, 'targets': targets}
        result = SimpleNamespace(files=files, targets=targets, proof=proof,
            assert_valid=lambda: normalization.validate_document(document, proof, asset))
        with patch.object(normalization, 'profile', return_value=selected):
            record = normalization.write_manifest(path.parent, result)
        report.update(schema=setup.NORMALIZED_RECEIPT_SCHEMA, normalization=proof, normalization_manifest=record)
        report['subjects']['files']['/' + alias]['authority'] = {'kind': 'normalized-archive', 'member': alias,
            'source_member': target, 'target_size': files[target]['size'], 'target_sha256': files[target]['sha256'],
            'target_metadata_sha256': bootstrap.sha256(normalization.canonical_json(metadata))}
        path.write_text(json.dumps(report))
        return path, report, plan, environment, selected

    def test_normalized_alternatives_refusal_before_or_after_probes_cleans_without_pass(self):
        for mutation in ('none', 'before', 'after', 'authority-drift'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path, _report, _plan, environment, selected = self.normalized_fixture(root)
                evidence, calls, probes = [], [], []
                def alternatives(_files):
                    calls.append('verify')
                    if (mutation == 'before' or mutation == 'after' and len(calls) == 2):
                        raise ValueError('inert alternatives refusal')
                    return {'count': 9, 'inventory_sha256':
                        ('b' if mutation == 'authority-drift' and len(calls) == 2 else 'a') * 64}
                expectation = contextlib.nullcontext() if mutation == 'none' else self.assertRaises(ValueError)
                with patch.object(normalization, 'profile', return_value=selected), expectation:
                    self.closed_qualify(path, root, environment, evidence.append,
                        alternatives=alternatives, subjects=lambda *_args, **_options: None,
                        probes=lambda *_args: probes.append('inert probe'))
                self.assertEqual([] if mutation == 'before' else ['inert probe'], probes)
                self.assertEqual(1 if mutation == 'before' else 2, len(calls))
                self.assertEqual('pass' if mutation == 'none' else 'refused', evidence[0]['outcome'])
                if mutation == 'none':
                    self.assertTrue(evidence[0]['alternatives']['revalidated'])
                self.assertEqual('pass', evidence[0]['cleanup'])
                self.assertFalse(path.parent.exists())

    def test_normalized_receipt_binds_original_target_manifest_before_and_after_probes_and_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, report, _plan, environment, selected = self.normalized_fixture(root)
            calls, evidence = [], []
            def subjects(_report, _plan, **options):
                self.assertEqual({'etc/php/8.3/cli/php.ini'}, set(options['normalization_targets']))
                calls.append('subjects')
            def probes(*_args):
                self.assertTrue((path.parent / normalization.MANIFEST_NAME).is_file())
                calls.append('probes')
                return []
            with patch.object(normalization, 'profile', return_value=selected):
                self.closed_qualify(path, root, environment, evidence.append, subjects=subjects, probes=probes)
            self.assertEqual(['subjects', 'probes', 'subjects'], calls)
            self.assertEqual('pass', evidence[0]['outcome'])
            self.assertTrue(evidence[0]['normalization']['revalidated'])
            self.assertEqual(report['normalization']['derived'], evidence[0]['normalization']['derived'])
            self.assertFalse(path.parent.exists())

    def test_normalized_missing_changed_or_foreign_provenance_refuses_before_probes_and_cleans(self):
        for mutation in ('missing', 'bytes', 'object', 'hash', 'authority', 'schema'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path, report, _plan, environment, selected = self.normalized_fixture(root)
                manifest = path.parent / normalization.MANIFEST_NAME
                if mutation == 'missing':
                    manifest.unlink()
                elif mutation in ('bytes', 'object'):
                    raw = manifest.read_bytes()
                    manifest.unlink()
                    manifest.write_bytes(raw if mutation == 'object' else b'{}')
                    manifest.chmod(0o400)
                elif mutation == 'hash':
                    report['normalization']['target_manifest_sha256'] = '0' * 64
                elif mutation == 'authority':
                    report['subjects']['files']['/etc/php/8.3/cli/php.ini']['authority']['source_member'] = 'foreign'
                else:
                    report['schema'] = setup.RECEIPT_SCHEMA
                path.write_text(json.dumps(report))
                evidence, calls = [], []
                with patch.object(normalization, 'profile', return_value=selected), self.assertRaises((ValueError, OSError)):
                    self.closed_qualify(path, root, environment, evidence.append, subjects=lambda *_args, **_kw: None,
                        probes=lambda *_args: calls.append('probe'))
                self.assertEqual([], calls)
                self.assertEqual('refused', evidence[0]['outcome'])
                self.assertFalse(path.parent.exists())

    def test_post_probe_normalization_mutation_refuses_before_pass_and_cleans(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, _report, _plan, environment, selected = self.normalized_fixture(root)
            def probes(*_args):
                manifest = path.parent / normalization.MANIFEST_NAME
                manifest.chmod(0o600)
                manifest.write_bytes(b'{}')
                manifest.chmod(0o400)
                return []
            evidence = []
            with patch.object(normalization, 'profile', return_value=selected), self.assertRaises(ValueError):
                self.closed_qualify(path, root, environment, evidence.append,
                    subjects=lambda *_args, **_kw: None, probes=probes)
            self.assertEqual('refused', evidence[0]['outcome'])
            self.assertFalse(path.parent.exists())

    def test_private_pip_receipt_and_subjects_bind_before_and_after_probes_and_both_states_clean_before_pass(self):
        for mutation in ("none", "receipt-write", "receipt-replace", "subject"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path, _, _, environment = self.fixture(root)
                pip_state, data, report, subjects = self.pip_fixture(root)
                observations, evidence = [], []
                changed = False
                def verify(*_args, **_options):
                    observations.append("pip-subjects")
                    return report, {"changed": {}} if changed else subjects
                def probes(*_):
                    nonlocal changed
                    observations.append("probes")
                    if mutation == "receipt-write":
                        pip_state.receipt.write_text("{}")
                    elif mutation == "receipt-replace":
                        raw = pip_state.receipt.read_bytes()
                        pip_state.receipt.unlink()
                        pip_state.receipt.write_bytes(raw)
                        pip_state.receipt.chmod(0o600)
                    elif mutation == "subject":
                        changed = True
                    return []
                def publish(value):
                    self.assertFalse(path.parent.exists())
                    self.assertFalse(pip_state.root.exists())
                    observations.append("publish-" + value["outcome"])
                    evidence.append(copy.deepcopy(value))
                with patch.object(qualification.private_pip, "verify_runtime", side_effect=verify):
                    if mutation == "none":
                        self.closed_qualify(path, root, environment, publish,
                            pip_state=data, subjects=lambda *_: None, probes=probes)
                        self.assertEqual(["pip-subjects", "probes", "pip-subjects", "publish-pass"], observations)
                        self.assertTrue(evidence[0]["private_pip"]["revalidated"])
                        self.assertEqual("pass", evidence[0]["private_pip"]["cleanup"])
                    else:
                        with self.assertRaises(ValueError):
                            self.closed_qualify(path, root, environment, publish,
                                pip_state=data, subjects=lambda *_: None, probes=probes)
                        self.assertEqual("publish-refused", observations[-1])

    def test_foreign_pre_product_receipt_identity_refuses_before_any_pip_import_or_phar_probe(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, _, _, environment = self.fixture(root)
            pip_state, data, _, _ = self.pip_fixture(root)
            identity = json.loads(data["receipt_identity"])
            identity["sha256"] = "0" * 64
            data["receipt_identity"] = json.dumps(identity)
            probes, evidence = [], []
            with patch.object(qualification.private_pip, "verify_runtime") as verify, self.assertRaises(ValueError):
                self.closed_qualify(path, root, environment, evidence.append,
                    pip_state=data, probes=lambda *_: probes.append("unexpected"))
            verify.assert_not_called()
            self.assertEqual([], probes)
            self.assertEqual("refused", evidence[0]["outcome"])
            self.assertFalse(path.parent.exists())
            self.assertFalse(pip_state.root.exists())

    def test_malformed_receipt_stamp_refuses_after_ownership_registration_and_cleans_both_states(self):
        for stamp in ("not-json", "{}", '{"owner":0,"owner":0}'):
            with self.subTest(stamp=stamp), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path, _, _, environment = self.fixture(root)
                pip_state, data, _, _ = self.pip_fixture(root)
                data["receipt_identity"] = stamp
                evidence = []
                with self.assertRaises(ValueError):
                    self.closed_qualify(path, root, environment, evidence.append, pip_state=data)
                self.assertFalse(pip_state.root.exists())
                self.assertFalse(path.parent.exists())
                self.assertEqual("refused", evidence[0]["outcome"])

    def test_private_pip_cleanup_failure_still_cleans_setup_and_never_publishes_pass(self):
        for failure in ("exception", "no-op"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path, _, _, environment = self.fixture(root)
                pip_state, data, report, subjects = self.pip_fixture(root)
                evidence = []
                original = qualification.shutil.rmtree
                def remove(path, *args, **options):
                    if isinstance(path, str) and path.startswith("dw-pip-"):
                        if failure == "exception":
                            raise OSError("inert pip cleanup refusal")
                        return None
                    return original(path, *args, **options)
                with patch.object(qualification.private_pip, "verify_runtime", return_value=(report, subjects)), \
                        patch.object(qualification.shutil, "rmtree", side_effect=remove), self.assertRaises((ValueError, OSError)):
                    self.closed_qualify(path, root, environment, evidence.append,
                        pip_state=data, subjects=lambda *_: None, probes=lambda *_: [])
                self.assertEqual("refused", evidence[0]["outcome"])
                self.assertEqual("cleanup", evidence[0]["stage"])
                self.assertIn("private_pip", evidence[0]["cleanup_failures"])
                self.assertFalse(path.parent.exists())
                self.assertTrue(pip_state.root.exists())

    def test_reused_private_pip_state_is_not_reclaimed_or_accepted_as_this_original_profile(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path, _, _, environment = self.fixture(root)
            pip_state, data, _, _ = self.pip_fixture(root)
            data["created"] = "false"
            evidence, probes = [], []
            with self.assertRaisesRegex(ValueError, "newly created"):
                self.closed_qualify(path, root, environment, evidence.append,
                    pip_state=data, probes=lambda *_: probes.append("unexpected"))
            self.assertEqual([], probes)
            self.assertEqual("refused", evidence[0]["outcome"])
            self.assertFalse(path.parent.exists())
            self.assertTrue(pip_state.root.exists())

    def test_unbound_pip_descriptor_still_finalizes_owned_setup_and_publishes_refusal(self):
        for mutation in ("missing-field", "malformed-root", "foreign-root"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path, _, _, environment = self.fixture(root)
                pip_state, data, _, _ = self.pip_fixture(root)
                if mutation == "missing-field":
                    del data["receipt_identity"]
                elif mutation == "malformed-root":
                    data["root_identity"] = "not-json"
                else:
                    identity = json.loads(data["root_identity"])
                    identity["mode"] = 0o777
                    data["root_identity"] = json.dumps(identity)
                evidence, probes = [], []
                with self.assertRaises(ValueError):
                    self.closed_qualify(path, root, environment, evidence.append,
                        pip_state=data, probes=lambda *_: probes.append("unexpected"))
                self.assertEqual([], probes)
                self.assertEqual("refused", evidence[0]["outcome"])
                self.assertFalse(path.parent.exists())
                self.assertTrue(pip_state.root.exists())

    def test_missing_or_unproven_setup_receipt_still_finalizes_proven_pip_and_publishes_refusal(self):
        for mutation in ("empty-output", "foreign-output", "missing-file", "missing-state"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                path, _, _, environment = self.fixture(root)
                pip_state, data, report, subjects = self.pip_fixture(root)
                setup_state = path.parent
                if mutation == "empty-output":
                    path = None
                elif mutation == "foreign-output":
                    path = root / "unproven.json"
                    path.write_text("{}")
                elif mutation == "missing-file":
                    path.unlink()
                else:
                    qualification.shutil.rmtree(setup_state)
                evidence, probes = [], []
                with patch.object(qualification.private_pip, "verify_runtime", return_value=(report, subjects)), \
                        self.assertRaises((ValueError, FileNotFoundError)):
                    self.closed_qualify(path, root, environment, evidence.append,
                        pip_state=data, probes=lambda *_: probes.append("unexpected"))
                self.assertEqual([], probes)
                self.assertEqual("refused", evidence[0]["outcome"])
                self.assertFalse(pip_state.root.exists())
                self.assertEqual("pass", evidence[0]["private_pip_cleanup"])
                if mutation in {"empty-output", "foreign-output"}:
                    self.assertTrue(setup_state.exists())
                else:
                    self.assertFalse(setup_state.exists())

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
