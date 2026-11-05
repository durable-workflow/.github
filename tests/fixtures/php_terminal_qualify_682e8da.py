"""Exact 682e8da qualify body; only its imports are supplied for inert controls."""
import os
import shutil
from scripts import php_linux_bootstrap as bootstrap
from scripts import setup_php_linux as setup
from scripts.php_linux_qualification import (
    capture_receipt, checked_state, object_identity, revalidate_subjects, run_probes, validate_success,
)


def qualify(path, runner_temp, environment, publish, *, validate=validate_success,
            subjects=revalidate_subjects, probes=run_probes):
    if (environment != bootstrap.clean_environment(environment, environment.get("HOME", ""))
            or dict(os.environ) != environment):
        raise ValueError("Qualification requires a closed parent environment")
    state = checked_state(path, runner_temp)
    state_identity = object_identity(state.lstat())[:4]
    evidence = {"schema": "durable-workflow.php-linux-terminal/v1", "outcome": "refused", "stage": "capture"}
    try:
        with capture_receipt(path, runner_temp) as (report, held, unchanged):
            evidence["stage"] = "validate"
            plan = validate(report, state)
            subjects(report, plan)
            evidence.update(receipt_sha256=held.identity["digest"], receipt_object=held.effective,
                            stage="probes")
            try:
                evidence["probes"] = probes(plan, environment)
            finally:
                unchanged()
                held.assert_sealed()
                subjects(report, plan)
            evidence.update(outcome="pass", stage="complete", receipt=report)
    except Exception as error:
        evidence.update(**setup.failure_details(error))
        raise
    finally:
        try:
            publish(evidence)
        finally:
            if object_identity(state.lstat())[:4] != state_identity:
                raise ValueError("Exact owned setup state changed; cleanup refused")
            setup.checked_root(state)
            shutil.rmtree(state)
