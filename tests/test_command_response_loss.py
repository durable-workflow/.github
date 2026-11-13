"""Include the shared socket controls in repository checks and real coverage."""
import importlib.util
from pathlib import Path


def load_tests(loader, _tests, _pattern):
    source = Path(__file__).resolve().parents[1] / 'conformance/command-keys/test_committed_response_loss.py'
    spec = importlib.util.spec_from_file_location('command_response_loss_controls', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return loader.loadTestsFromTestCase(module.CommittedResponseLossTest)
