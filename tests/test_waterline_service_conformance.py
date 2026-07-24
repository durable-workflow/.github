from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.waterline_service_conformance import (
    ServiceConformanceError,
    distribution_identity,
    write_result,
)


class WaterlineServiceConformanceTest(unittest.TestCase):
    def test_distribution_identity_retains_exact_manifest(self) -> None:
        digest = "a" * 64
        self.assertEqual(
            {
                "kind": "oci",
                "locator": "oci:docker.io/durableworkflow/waterline@2.0.0-beta.10",
                "artifacts": [{"name": "manifest", "sha256": digest}],
            },
            distribution_identity(
                f"docker.io/durableworkflow/waterline@sha256:{digest}",
                "2.0.0-beta.10",
            ),
        )

        with self.assertRaises(ServiceConformanceError):
            distribution_identity("docker.io/durableworkflow/waterline:latest", "2.0.0-beta.10")

    def test_result_retains_service_and_standalone_versions(self) -> None:
        environment = {
            "DW_SERVER_VERSION": "2.0.0-beta.10",
            "DW_WATERLINE_VERSION": "2.0.0-beta.10",
        }
        identity = distribution_identity(
            f"docker.io/durableworkflow/waterline@sha256:{'b' * 64}",
            "2.0.0-beta.10",
        )
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            write_result(
                directory,
                environment,
                "2026-07-22T00:00:00Z",
                status="pass",
                runner_blocked=False,
                identity=identity,
            )
            result = json.loads((directory / "waterline-service-conformance-result.json").read_bytes())

        self.assertEqual(
            {"server": "2.0.0-beta.10", "waterline-service": "2.0.0-beta.10"},
            result["artifact_versions"],
        )
        self.assertEqual({"waterline-service": identity}, result["executed_distribution_identities"])
        self.assertEqual("pass", result["scenario_results"]["service_image_php_sdk_standalone"]["status"])


if __name__ == "__main__":
    unittest.main()
