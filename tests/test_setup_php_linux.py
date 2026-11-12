"""Complete source recipe controls with inert network/PHP/root executors."""

import ast
from contextlib import contextmanager
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import ssl
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.error import HTTPError, URLError

from scripts import php_linux_bootstrap as bootstrap
from scripts import php_linux_recipe as recipe
from scripts import php_linux_normalize as normalization
from scripts import setup_php_linux as setup
from tests import test_php_linux_normalize as normalize_tests


# Inert mirror fixture URL; no request is made.
MIRROR_URL = "https://api.github.com/repos/durable-workflow/.github/releases/assets/900000001"


class SetupPhpLinuxTest(unittest.TestCase):
    def fixture(self, root):
        state = root / "state"
        state.mkdir(mode=0o700)
        (state / "home").mkdir(mode=0o700)
        (state / "tmp").mkdir(mode=0o700)
        roots = root / "empty-roots"
        roots.mkdir()
        node_path = root / "inert-node"
        node_path.write_bytes(b"inert host-tool identity, not executed")
        node = {"node": str(node_path), "node_version": "v24.inert",
                "node_sha256": bootstrap.sha256(node_path.read_bytes())}
        environment = bootstrap.clean_environment({"ImageOS": "inert-ubuntu26", "ImageVersion": "inert-image",
            "DW_CI_CA_SHA256": setup.CA_SHA256, "SSL_CERT_FILE": str(root / "inert-ca"),
            "SSL_CERT_DIR": str(roots)}, str(state / "home"))
        request = recipe.capture_request({"INPUT_PHP-VERSION": "8.3",
            "INPUT_TOOLS": "composer:2.10.3,phpunit:11.5.57", "INPUT_COVERAGE": "none"})
        catalog = json.loads(bootstrap.CATALOG.read_text())
        host = dict(operating_system="ubuntu", release="26.04", architecture="x86_64")
        archive = bootstrap.select(catalog, **host, php="8.3")["asset"]
        archive_bytes, _identity, selected_profile, _raw = normalize_tests.PhpLinuxNormalizeTest().fixture()
        archive.update(size=len(archive_bytes), digest="sha256:" + bootstrap.sha256(archive_bytes))
        catalog_path = root / "catalog.json"
        catalog_path.write_text(json.dumps(catalog))
        calls = []

        @contextmanager
        def fetch(row, context):
            identity = row["asset"]
            self.assertNotEqual("install.sh", identity["name"])
            calls.append("read-archive")
            with bootstrap.hold_verified(io.BytesIO(archive_bytes), identity, MIRROR_URL) as held:
                yield held

        source_installer = bootstrap.hold_source_installer

        @contextmanager
        def installer_fetch(identity):
            calls.append("read-installer")
            with source_installer(identity) as held:
                yield held

        @contextmanager
        def tool_fetch(row, context):
            calls.append("read-" + row["name"])
            # The PHAR stream binding itself is exercised with real sealed
            # descriptors in test_php_linux_tools. No binary is in this repo.
            yield SimpleNamespace(name=row["name"])

        def inspect(held):
            calls.append("inspect-archive")
            held.assert_sealed()
            return setup.archive.inspect_held(held)

        derive_archive = normalization.normalize
        @contextmanager
        def derive(held):
            with patch.object(normalization, 'profile', return_value=selected_profile), derive_archive(held) as result:
                yield result

        def install(script, held, arguments, child, selected, *, no_apt, normalized, original_installer):
            calls.append("install-php")
            script.assert_sealed()
            held.assert_sealed()
            self.assertEqual(("8.3", "release", "nts"), arguments)
            self.assertIs(True, no_apt)
            original_installer.assert_sealed()
            self.assertEqual(selected['installer'], original_installer.identity)
            self.assertEqual(environment, child)
            normalized.assert_valid()
            self.assertIs(normalized.original, held)
            self.assertTrue((state / normalization.MANIFEST_NAME).is_file())
            self.assertNotIn(b"https://", os.pread(script.descriptor, script.identity["size"], 0))

        def verify(files, php, required):
            calls.append("verify-installed")
            self.assertEqual("8.3", php)
            return {"source": "inert verified-file substitute"}

        def execute(command, **options):
            calls.append("upstream")
            self.assertEqual(str(state / "upstream/dist/index.js"), command[1])
            self.assertEqual("none", options["env"]["INPUT_TOOLS"])
            self.assertNotIn("GITHUB_TOKEN", options["env"])
            self.assertNotIn("GH_TOKEN", options["env"])
            return SimpleNamespace(returncode=0)

        def confirm_extensions(*args):
            calls.append("confirm-extensions")
            return {"extensions": "inert enabled-module substitute"}

        def install_tool(held, row, child):
            calls.append("install-" + row["name"])
            self.assertEqual(held.name, row["name"])
            self.assertEqual(environment, child)
            return {"name": row["name"], "executor": "inert"}

        def configure(*_arguments, **options):
            calls.append('configure-cli')
            self.assertEqual(archive, options['original'])
            return {'inert':'configuration'}, {'name':'cli-configuration.json'}, {'inert':'configuration-plan'}

        @contextmanager
        def capture_configuration(*_arguments, **options):
            self.assertEqual(archive, options['original'])
            yield {'inert':'configuration'}, {}, None, lambda:None

        def capture_subjects(members, php, required, selected_tools, *, normalization_targets, configuration):
            calls.append("capture-subjects")
            calls.extend("subject-" + row["name"] for row in selected_tools)
            self.assertEqual({'usr/bin/alias'}, set(normalization_targets))
            self.assertEqual({'inert':'configuration-plan'}, configuration)
            return {"source": "inert verified-file substitute"}, {"files": {}}

        effects = dict(installer_fetch=installer_fetch, asset_fetch=fetch,
            tool_fetch=tool_fetch, inspect_archive=inspect,
            install_php=install, verify_php=verify, confirm_extensions=confirm_extensions,
            install_tool=install_tool, execute=execute, capture_subjects=capture_subjects, derive_archive=derive,
            configure=configure, capture_configuration=capture_configuration)
        return state, node, environment, request, host, catalog_path, calls, effects

    def run_fixture(self, data):
        state, node, environment, request, host, catalog_path, calls, effects = data
        options = dict(effects)
        installer_fetch = options.pop('installer_fetch')
        derive = options.pop('derive_archive')
        capture_configuration = options.pop('capture_configuration')
        configure = options.pop('configure')
        with patch.dict(os.environ, environment, clear=True), patch.object(bootstrap, "CATALOG", catalog_path), \
                patch.object(bootstrap, "observed_host", return_value=host), \
                patch.object(bootstrap, "explicit_trust", return_value=object()), \
                patch.object(bootstrap, 'hold_source_installer', side_effect=installer_fetch), \
                patch.object(normalization, 'profile', return_value=normalize_tests.PhpLinuxNormalizeTest().fixture()[2]), \
                patch.object(normalization, 'normalize', side_effect=derive), \
                patch.object(setup, 'configure_cli', side_effect=configure), \
                patch.object(setup.configuration, 'capture_manifest', side_effect=capture_configuration):
            return setup.run_setup(state, request, node, environment, **options)

    def test_real_producer_manifest_glue_binds_both_tools_before_returning(self):
        manifest={"files":{}}
        installed={"binary":"inert"}
        rows=[{"name":"composer"},{"name":"phpunit"}]
        with patch.object(setup.archive,"capture_subjects",return_value=(installed,manifest)) as capture, \
                patch.object(setup.tools,"append_subject") as append:
            result=setup.capture_setup_subjects({},"8.3",[],rows)
        self.assertEqual((installed,manifest),result)
        capture.assert_called_once_with({},"8.3",[])
        self.assertEqual(rows,[call.args[1] for call in append.call_args_list])

    def test_all_reads_precede_the_first_install_and_pinned_setup_precedes_bound_tools(self):
        with tempfile.TemporaryDirectory(prefix="php-inert-composed-") as directory:
            data = self.fixture(Path(directory))
            report = self.run_fixture(data)
            self.assertEqual(["read-installer", "read-archive", "read-composer", "read-phpunit",
                "inspect-archive", "install-php", "verify-installed", "configure-cli", "upstream", "confirm-extensions",
                "install-composer", "install-phpunit", "capture-subjects", "subject-composer",
                "subject-phpunit"], data[6])
            self.assertEqual("pass", report["outcome"])
            self.assertIs(False, report["preinstalled_authority"])
            self.assertEqual("complete", json.loads((data[0] / "receipt.json").read_text())["stage"])
            self.assertFalse((data[0] / "upstream").exists())

    def test_wrong_ca_or_unsupported_initial_profile_makes_zero_asset_requests(self):
        for failure in ("profile", "ca"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory(prefix="php-inert-preflight-") as directory:
                data = self.fixture(Path(directory))
                if failure == "profile":
                    data[3]["inputs"]["coverage"] = ""
                else:
                    data[2]["DW_CI_CA_SHA256"] = "0" * 64
                with self.assertRaises(ValueError):
                    self.run_fixture(data)
                self.assertFalse(any(call.startswith("read-") for call in data[6]))

    def test_initial_profile_refuses_other_distro_arch_php_coverage_tools_and_extensions(self):
        from scripts import php_linux_tools as tools
        catalog = json.loads(bootstrap.CATALOG.read_text())
        tool_catalog = json.loads(tools.CATALOG.read_text())
        host = dict(operating_system="ubuntu", release="26.04", architecture="x86_64")
        request = recipe.capture_request({'INPUT_PHP-VERSION':'8.3', 'INPUT_TOOLS':'composer:2.10.3,phpunit:11.5.57',
                                          'INPUT_COVERAGE':'none'})
        candidates = [(dict(host, release='22.04'), request), (dict(host, architecture='aarch64'), request)]
        for name, value in (('php-version','8.4'), ('extensions','json'), ('coverage',''),
                            ('coverage','xdebug'), ('tools','composer:2.10.3'), ('tools','none')):
            changed = copy.deepcopy(request)
            changed['inputs'][name] = value
            candidates.append((host, changed))
        for actual_host, actual_request in candidates:
            plan = recipe.validate_request(actual_request, catalog, tool_catalog, actual_host)
            with self.subTest(host=actual_host, inputs=actual_request['inputs']), self.assertRaises(ValueError):
                setup.initial_profile(plan, actual_host)

    def test_host_profile_requires_the_complete_matching_pinned_archive_identity(self):
        from scripts import php_linux_tools as tools
        catalog = json.loads(bootstrap.CATALOG.read_text())
        tool_catalog = json.loads(tools.CATALOG.read_text())
        request = recipe.capture_request({'INPUT_PHP-VERSION':'8.3',
            'INPUT_TOOLS':'composer:2.10.3,phpunit:11.5.57', 'INPUT_COVERAGE':'none'})
        for release in ('24.04', '26.04'):
            host = dict(operating_system='ubuntu', release=release, architecture='x86_64')
            plan = recipe.validate_request(request, catalog, tool_catalog, host)
            setup.initial_profile(plan, host)
            for field in ('id', 'name', 'size', 'digest'):
                changed = copy.deepcopy(plan)
                changed['archive']['asset'][field] = 'foreign'
                with self.subTest(release=release, field=field), self.assertRaises(ValueError):
                    setup.initial_profile(changed, host)
            foreign_host = dict(host, release='26.04' if release == '24.04' else '24.04')
            with self.assertRaises(ValueError):
                setup.initial_profile(plan, foreign_host)

    def test_masked_upstream_refusal_keeps_original_failed_stage_and_never_installs_tools(self):
        with tempfile.TemporaryDirectory(prefix="php-inert-masked-") as directory:
            data = self.fixture(Path(directory))
            def masked(command, **options):
                data[6].append("upstream-masked-refusal")
                (data[0] / "refusal").write_text("inert refused get; caller masked its exit status\n")
                return SimpleNamespace(returncode=0)
            data[7]["execute"] = masked
            with self.assertRaisesRegex(ValueError, "refused acquisition"):
                self.run_fixture(data)
            report = json.loads((data[0] / "receipt.json").read_text())
            self.assertEqual(("refused", "pinned-upstream"), (report["outcome"], report["stage"]))
            self.assertFalse(any(call in ("install-composer", "install-phpunit") for call in data[6]))
            self.assertFalse((data[0] / "upstream").exists())

    def test_changed_installed_file_stops_before_pinned_php_setup_and_tools(self):
        with tempfile.TemporaryDirectory(prefix="php-inert-file-refusal-") as directory:
            data = self.fixture(Path(directory))
            def refuse(*args):
                raise ValueError("Inert changed installed binary")
            data[7]["verify_php"] = refuse
            with self.assertRaises(ValueError):
                self.run_fixture(data)
            self.assertNotIn("upstream", data[6])
            self.assertFalse(any(call in ("install-composer", "install-phpunit") for call in data[6]))
            self.assertEqual("installed-file-binding", json.loads((data[0] / "receipt.json").read_text())["stage"])

    def test_invalid_tar_refuses_terminally_with_original_cause_before_any_root_executor(self):
        from scripts import php_linux_archive as archive
        with tempfile.TemporaryDirectory(prefix='php-inert-invalid-tar-') as directory:
            data = self.fixture(Path(directory))
            data[7]['inspect_archive'] = lambda held: archive.inventory(io.BytesIO(b'inert invalid tar'))
            with self.assertRaises(ValueError):
                self.run_fixture(data)
            report = json.loads((data[0]/'receipt.json').read_text())
            self.assertEqual(('refused','archive-inspection','ReadError'),
                             (report['outcome'],report['stage'],report['cause_type']))
            self.assertNotIn('install-php',data[6])
            self.assertFalse((data[0]/'upstream').exists())
        with tempfile.TemporaryDirectory(prefix='php-inert-library-error-') as directory:
            data = self.fixture(Path(directory))
            def malformed_header(held):
                raise KeyError('inert malformed extended-header field')
            data[7]['inspect_archive'] = malformed_header
            with self.assertRaises(KeyError):
                self.run_fixture(data)
            report=json.loads((data[0]/'receipt.json').read_text())
            self.assertEqual(('refused','archive-inspection','KeyError'),
                             (report['outcome'],report['stage'],report['failure_type']))
            self.assertNotIn('install-php',data[6])

    def test_native_network_cause_is_recorded_without_signed_url_or_credentials(self):
        http = HTTPError('https://example.invalid/?signature=inert-sensitive-query',403,'Forbidden',{},None)
        tls = ssl.SSLCertVerificationError(1,'inert TLS refusal')
        tls.verify_code = 20
        tls.verify_message = 'unable to get local issuer certificate'
        report = setup.failure_details(http)
        self.assertEqual(403,report['http_status'])
        self.assertNotIn('signature',json.dumps(report))
        http.close()
        report = setup.failure_details(URLError(tls))
        self.assertEqual(('URLError','SSLCertVerificationError',20),
                         (report['failure_type'],report['cause_type'],report['verify_code']))

    def test_both_source_transitions_use_absolute_isolated_no_site_no_bytecode_python(self):
        root = bootstrap.ROOT
        probe = "import sys; seen='site' in sys.modules; import json; print(json.dumps({'site':seen,'isolated':sys.flags.isolated,'no_site':sys.flags.no_site,'no_bytecode':sys.flags.dont_write_bytecode}))"
        # Execute the exact wrapper sources in a Node VM with execve replaced
        # by a native Python flag probe. No setup target is executed. The local
        # Node version is not claimed as a native Node24 qualification.
        javascript = '''
const fs=require('node:fs'),vm=require('node:vm'),child=require('node:child_process');
const [source,dir,probe]=process.argv.slice(1);
const fake={platform:'linux',version:'v24.inert',execPath:process.execPath,env:{GITHUB_TOKEN:'inert'},
 execve:(binary,args,env)=>{
  if(binary!=='/usr/bin/python3')throw Error('non-absolute interpreter');
  const flags=args.slice(1,args.findIndex(x=>x.endsWith('setup_php_linux.py')));
  const r=child.spawnSync(binary,[...flags,'-c',probe],{env,encoding:'utf8'});
  if(r.status!==0)throw Error(r.stderr); process.stdout.write(r.stdout);
 }};
vm.runInNewContext(fs.readFileSync(source,'utf8'),{require,process:fake,__dirname:dir});
'''
        current = root/'.github/actions/setup-php-linux/bootstrap.js'
        old = root/'tests/fixtures/php_linux_bootstrap_65753c1.js'
        results = []
        for source in (old,current):
            result = subprocess.run(['node','-e',javascript,str(source),str(current.parent),probe],
                env={'PATH':'/usr/bin:/usr/local/bin:/bin'},capture_output=True,text=True,timeout=5,check=True)
            results.append(json.loads(result.stdout))
        self.assertEqual({'site':True,'isolated':1,'no_site':0,'no_bytecode':0},results[0])
        self.assertEqual({'site':False,'isolated':1,'no_site':1,'no_bytecode':1},results[1])
        with tempfile.TemporaryDirectory(prefix='php-inert-startup-') as directory:
            state=Path(directory)
            node=state/'inert-node';node.write_bytes(b'inert identity')
            parent={'RUNNER_TEMP':str(state),'DW_SETUP_NODE_BINARY':str(node),'DW_SETUP_NODE_VERSION':'v24.inert'}
            calls=[]
            def execute(binary,args,environment):
                self.assertEqual('/usr/bin/python3',binary)
                flags=args[1:args.index(str(Path(setup.__file__).resolve()))]
                result=subprocess.run([binary,*flags,'-c',probe],env=environment,
                    capture_output=True,text=True,timeout=5,check=True)
                calls.append(json.loads(result.stdout))
            setup.reexec(parent,execute)
            self.assertEqual([results[1]],calls)

    def test_inherited_parent_token_refuses_before_request_file_is_read(self):
        with tempfile.TemporaryDirectory(prefix="php-inert-parent-") as directory:
            state = Path(directory)
            state.chmod(0o700)
            (state / "request.json").write_text("inert deliberately invalid JSON; must not be read")
            environment = dict(bootstrap.clean_environment({}, str(state / "home")), GITHUB_TOKEN="inert")
            result = subprocess.run(["/usr/bin/python3", "-I", "-S", "-B", str(Path(setup.__file__)), "setup", str(state)],
                env=environment, capture_output=True, text=True, timeout=5)
            self.assertEqual(1, result.returncode)
            self.assertIn("Inherited environment is not closed", result.stderr)
            self.assertNotIn("JSON", result.stderr)
            self.assertTrue((state / "request.json").exists())

    def test_real_execve_replaces_the_credential_bearing_python_stage(self):
        with tempfile.TemporaryDirectory(prefix="php-inert-execve-") as directory:
            root = Path(directory)
            node = root / "inert-node"
            node.write_bytes(b"inert node identity, not executable")
            probe = "import os,json; print(json.dumps({'pid':os.getpid(),'credential_names':[k for k in os.environ if k in ('GH_TOKEN','GITHUB_TOKEN','COMPOSER_AUTH','AWS_SECRET_ACCESS_KEY')]}))"
            program = f'''import os,sys
sys.path.insert(0,{str(bootstrap.ROOT)!r})
from scripts import setup_php_linux as setup
print(os.getpid(),flush=True)
def execute(binary,args,environment):
 os.execve('/usr/bin/python3',['/usr/bin/python3','-I','-S','-B','-c',{probe!r}],environment)
setup.reexec(dict(os.environ),execute)
'''
            environment = {"PATH": "/usr/bin:/bin", "RUNNER_TEMP": str(root), "INPUT_PHP-VERSION": "8.3",
                "INPUT_TOOLS": "none", "DW_SETUP_NODE_BINARY": str(node), "DW_SETUP_NODE_VERSION": "v24.inert",
                "GH_TOKEN": "inert", "GITHUB_TOKEN": "inert", "COMPOSER_AUTH": "inert", "AWS_SECRET_ACCESS_KEY": "inert"}
            result = subprocess.run(["/usr/bin/python3", "-I", "-c", program], env=environment,
                capture_output=True, text=True, timeout=5, check=True)
            before, after = result.stdout.strip().splitlines()
            actual = json.loads(after)
            self.assertEqual(int(before), actual["pid"])
            self.assertEqual([], actual["credential_names"])



class SetupImportBoundaryTest(unittest.TestCase):
    """Static check: setup can never reach the uploader's upstream authority.

    The action runs scripts/setup_php_linux.py (bootstrap.js). Walk every
    import in that graph, including function-level imports, from source text.
    """

    ENTRY = ("setup_php_linux", "php_linux_bootstrap")
    FORBIDDEN_MODULE = "php_linux_mirror"
    FORBIDDEN_NAMES = {"UPSTREAM_ASSET_PATH", "UPSTREAM_REDIRECT_PREFIX", "upstream_effective_url",
                       "upstream_url", "fetch_upstream"}
    FORBIDDEN_TEXT = ("/shivammathur/php-ubuntu", "repos/shivammathur", "shivammathur/php-ubuntu/")

    @staticmethod
    def imports(tree):
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    parts = alias.name.split(".")
                    if parts[0] == "scripts":
                        found.add(parts[1] if len(parts) > 1 else "")
                    found.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if node.level:
                    raise AssertionError("Relative imports are outside the reviewed setup graph")
                if module == "scripts":
                    found.update(alias.name for alias in node.names)
                elif module.startswith("scripts."):
                    found.add(module.split(".")[1])
                found.add(module)
            elif (isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute))
                  and (getattr(node.func, "id", None) or getattr(node.func, "attr", None))
                  in {"__import__", "import_module", "spec_from_file_location", "run_path"}):
                raise AssertionError("Dynamic imports are outside the reviewed setup graph")
        return found

    def graph(self, sources):
        seen, pending = set(), list(self.ENTRY)
        while pending:
            name = pending.pop()
            if name in seen:
                continue
            seen.add(name)
            tree = ast.parse(sources[name], filename=name + ".py")
            pending.extend(module for module in self.imports(tree) if module in sources)
        return seen

    def violations(self, sources, graph):
        found = []
        if self.FORBIDDEN_MODULE in graph:
            found.append(self.FORBIDDEN_MODULE)
        for name in sorted(graph):
            tree = ast.parse(sources[name])
            if any(module.endswith(self.FORBIDDEN_MODULE) for module in self.imports(tree)):
                found.append(f"{name} imports {self.FORBIDDEN_MODULE}")
            for node in ast.walk(tree):
                identifier = node.id if isinstance(node, ast.Name) else getattr(node, "attr", None)
                if identifier in self.FORBIDDEN_NAMES:
                    found.append(f"{name} names {identifier}")
                if isinstance(node, ast.alias) and node.name in self.FORBIDDEN_NAMES:
                    found.append(f"{name} imports {node.name}")
                if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                        and any(text in node.value for text in self.FORBIDDEN_TEXT)):
                    found.append(f"{name} has an upstream fetch rule literal")
        return found

    def sources(self):
        return {path.stem: path.read_text() for path in (bootstrap.ROOT / "scripts").glob("*.py")}

    def test_setup_import_graph_never_reaches_the_uploader_or_its_upstream_rules(self):
        action = (bootstrap.ROOT / ".github/actions/setup-php-linux/bootstrap.js").read_text()
        self.assertIn("'../../../scripts/setup_php_linux.py'", action)
        sources = self.sources()
        graph = self.graph(sources)
        # Guard against a rename silently shrinking the checked graph.
        self.assertEqual({"setup_php_linux", "php_linux_bootstrap", "php_linux_archive", "php_linux_recipe",
                          "php_linux_tools", "php_linux_normalize", "php_linux_configuration",
                          "php_linux_alternatives"}, graph)
        self.assertEqual([], self.violations(sources, graph))
        # The uploader really holds those rules, so the names checked are live.
        mirror = ast.parse(sources[self.FORBIDDEN_MODULE])
        defined = {node.name for node in ast.walk(mirror) if isinstance(node, ast.FunctionDef)}
        defined |= {target.id for node in ast.walk(mirror) if isinstance(node, ast.Assign)
                    for target in node.targets if isinstance(target, ast.Name)}
        self.assertLessEqual(self.FORBIDDEN_NAMES, defined)

    def test_boundary_check_detects_each_kind_of_leak(self):
        base = self.sources()
        leaks = {
            "module": "from scripts import php_linux_mirror as mirror\n",
            "dotted": "import scripts.php_linux_mirror\n",
            "from-dotted": "from scripts.php_linux_mirror import fetch_upstream\n",
            "lazy": "def later():\n    from scripts import php_linux_mirror\n",
            "transitive": "from scripts import leaky_helper\n",
            "name": "x = UPSTREAM_ASSET_PATH\n",
            "attribute": "x = something.upstream_effective_url\n",
            "literal": "x = r'/repos/shivammathur/php-ubuntu/releases/assets/1'\n",
        }
        for kind, text in leaks.items():
            sources = dict(base)
            target = "php_linux_tools"
            if kind == "transitive":
                sources["leaky_helper"] = "from scripts import php_linux_mirror\n"
            sources[target] = sources[target] + "\n" + text
            with self.subTest(kind=kind):
                self.assertNotEqual([], self.violations(sources, self.graph(sources)))
        for text in ("import importlib\nimportlib.import_module('scripts.php_linux_mirror')\n",
                     "__import__('scripts.php_linux_mirror')\n"):
            sources = dict(base, php_linux_tools=base["php_linux_tools"] + "\n" + text)
            with self.subTest(text=text), self.assertRaises(AssertionError):
                self.graph(sources)


if __name__ == "__main__":
    unittest.main()
