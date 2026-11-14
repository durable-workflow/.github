from __future__ import annotations

import base64
import hashlib
import json
import re
import struct
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_ROOT = ROOT / "conformance" / "payload-protection"


def load(name: str) -> dict[str, object]:
    return json.loads((CONTRACT_ROOT / name).read_text(encoding="utf-8"))


def lp(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack(">I", len(encoded)) + encoded


def aad(*, algorithm: str, key_id: str, namespace: str, boundary_kind: str) -> bytes:
    return b"".join(
        (
            b"durable-workflow.payload-protection\0",
            b"\x01",
            lp(algorithm),
            lp(key_id),
            lp(namespace),
            lp(boundary_kind),
        )
    )


class PayloadProtectionContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema = load("protected-value-v1.avsc")
        cls.vectors = load("vectors-v1.json")
        cls.call_sites = load("call-sites-v1.json")

    def test_schema_is_the_closed_protected_value_record(self) -> None:
        self.assertEqual("record", self.schema["type"])
        self.assertEqual("ProtectedValue", self.schema["name"])
        self.assertEqual("durable_workflow.protocol", self.schema["namespace"])
        self.assertEqual(
            [
                ("dw_protected", "int"),
                ("alg", "string"),
                ("key_id", "string"),
                ("nonce", "bytes"),
                ("ciphertext", "bytes"),
            ],
            [(field["name"], field["type"]) for field in self.schema["fields"]],
        )
        self.assertNotEqual(
            self.vectors["protected_value_schema_fingerprint_hex"],
            self.vectors["plain_value_schema_fingerprint_hex"],
        )

    def test_canonical_aad_and_lengths(self) -> None:
        vector = self.vectors["vectors"][0]
        actual = aad(
            algorithm=self.vectors["algorithm"],
            key_id=vector["key_id"],
            namespace=vector["namespace"],
            boundary_kind=vector["boundary_kind"],
        )
        self.assertEqual(vector["aad_hex"], actual.hex())
        self.assertEqual(self.vectors["aad_prefix_hex"], actual[:36].hex())
        self.assertEqual(32, len(bytes.fromhex(vector["key_hex"])))
        self.assertEqual(24, len(bytes.fromhex(vector["nonce_hex"])))
        self.assertGreaterEqual(len(bytes.fromhex(vector["ciphertext_and_tag_hex"])), 16)
        self.assertRegex(vector["key_id"], re.compile(self.vectors["key_id_pattern"]))

    def test_outer_object_and_external_identity_are_exact(self) -> None:
        vector = self.vectors["vectors"][0]
        outer_ascii = vector["outer_single_object_base64"].encode("ascii")
        outer = base64.b64decode(outer_ascii, validate=True)

        self.assertEqual(vector["external_object_ascii_bytes"], len(outer_ascii))
        self.assertEqual(
            vector["external_object_sha256"], hashlib.sha256(outer_ascii).hexdigest()
        )
        self.assertEqual(b"\xc3\x01", outer[:2])
        self.assertEqual(
            bytes.fromhex(self.vectors["protected_value_schema_fingerprint_hex"]),
            outer[2:10],
        )
        self.assertIn(bytes.fromhex(vector["nonce_hex"]), outer)
        self.assertTrue(outer.endswith(bytes.fromhex(vector["ciphertext_and_tag_hex"])))

    def test_inner_plain_value_uses_the_existing_fingerprint(self) -> None:
        vector = self.vectors["vectors"][0]
        inner = bytes.fromhex(vector["inner_plain_value_hex"])
        self.assertEqual(b"\xc3\x01", inner[:2])
        self.assertEqual(
            bytes.fromhex(self.vectors["plain_value_schema_fingerprint_hex"]),
            inner[2:10],
        )
        self.assertEqual(
            -9223372036854775808,
            vector["value_json"]["i"],
        )
        self.assertEqual("Iñtërnâtiônàlizætiøn ☃ 𐍈", vector["value_json"]["u"])

    def test_negative_cases_cover_recognition_context_and_precedence(self) -> None:
        cases = {
            case["name"]: case["result"]
            for case in self.vectors["required_negative_cases"]
        }
        self.assertEqual("plain_value", cases["ordinary-map-with-protection-like-keys"])
        self.assertEqual(
            "payload_envelope_unsupported", cases["protected-version-not-one"]
        )
        self.assertEqual("payload_key_unavailable", cases["unknown-key-id"])
        self.assertEqual(
            "payload_authentication_failed", cases["namespace-substitution"]
        )
        self.assertEqual(
            "payload_authentication_failed", cases["boundary-kind-substitution"]
        )
        self.assertEqual(
            "payload_plaintext_invalid",
            cases["authenticated-inner-value-with-wrong-fingerprint"],
        )
        self.assertEqual(
            "payload_protection_required",
            cases["plain-value-at-strict-enabled-boundary"],
        )
        self.assertEqual(13, len(cases))

    def test_call_site_inventory_is_closed_and_source_bound(self) -> None:
        self.assertEqual(
            {"sdk-python", "sdk-php", "sdk-rust", "workflow", "server"},
            set(self.call_sites["source_revisions"]),
        )
        for name, revision in self.call_sites["source_revisions"].items():
            with self.subTest(name=name):
                self.assertRegex(revision, r"^[0-9a-f]{40}$")

        boundaries = self.call_sites["boundaries"]
        names = [boundary["name"] for boundary in boundaries]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(
            {"protected", "unsupported_refuse"},
            {boundary["status"] for boundary in boundaries},
        )

        supported = {
            boundary["boundary_kind"]
            for boundary in boundaries
            if boundary["status"] == "protected"
            and boundary["boundary_kind"] != "inherited"
        }
        self.assertEqual(
            {
                "workflow_input",
                "workflow_result",
                "activity_input",
                "activity_result",
                "signal_input",
                "update_input",
                "update_result",
                "query_input",
                "query_result",
                "side_effect_result",
            },
            supported,
        )

        unsupported = {
            boundary["name"]
            for boundary in boundaries
            if boundary["status"] == "unsupported_refuse"
        }
        self.assertTrue(
            {
                "activity heartbeat details",
                "workflow message stream item",
                "Nexus request or result",
                "local or prepared activity payload",
                "failure details",
                "raw JSON or generic binary payload",
            }.issubset(unsupported)
        )
        self.assertTrue(self.call_sites["plaintext_metadata"])


if __name__ == "__main__":
    unittest.main()
