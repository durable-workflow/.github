import pathlib
import unittest

from tests.test_private_pip_runtime import runtime


ROOT = pathlib.Path(__file__).resolve().parents[1]


class TrustBootstrapTest(unittest.TestCase):
    def test_pip_bootstrap_is_content_verified_and_checks_the_result(self) -> None:
        action = (ROOT / ".github/actions/bootstrap-patched-pip/action.yml").read_text()

        self.assertEqual("pip-26.2.2-py3-none-any.whl", runtime.WHEEL_NAME)
        self.assertEqual(
            "fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70",
            runtime.WHEEL_SHA256,
        )
        self.assertIn('/usr/bin/python3 -I -S -B "$GITHUB_ACTION_PATH/pip_runtime.py"', action)
        self.assertIn('/usr/bin/python3 -I -S -B "$GITHUB_ACTION_PATH/export-trust.py" --runtime', action)
        self.assertNotIn("--upgrade", action)

    def test_networked_python_installs_bootstrap_pip_first(self) -> None:
        for workflow_name in ("ci.yml", "sonar.yml"):
            workflow = (ROOT / ".github/workflows" / workflow_name).read_text()
            bootstrap = workflow.index("uses: durable-workflow/.github/.github/actions/bootstrap-patched-pip@75587fc33ff40c34f32ef777293dad56bb6f48c7")
            install = workflow.index("python -m pip install")
            self.assertLess(bootstrap, install, workflow_name)

    def test_node_network_installs_use_a_fixed_release(self) -> None:
        workflow = (ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn("node-version: 24.22.1", workflow)


if __name__ == "__main__":
    unittest.main()
