from __future__ import annotations

import base64
import copy
import hashlib
import http.client
import io
import json
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from scripts.beta_candidate import (
    CLI_ASSETS,
    COMPONENTS,
    LEGACY_VERIFICATION_SCHEMA,
    SCHEMA,
    CandidateError,
    PublicClient,
    PublicInfrastructureError,
    canonical_cli_embedded_identity,
    canonical_json,
    canonical_pypi_version,
    check_candidate_compatibility,
    inspect_cli_phar_identity,
    load_verification,
    manifest_digest,
    parse_checksums,
    record_candidate,
    revalidate_verification,
    validate_manifest,
    validate_recorded_verification,
    validate_verification,
    verify_composer,
    verify_github_release,
    verify_pypi,
    verify_python_archive_identity,
)
from tests.verification_fixture import (
    candidate_verification,
    legacy_beta_one_candidate_manifest,
    legacy_candidate_manifest,
    legacy_candidate_verification,
    legacy_completed_candidate_manifests,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def write_build_info_phar(path: Path, version: str, commit: str) -> None:
    generated = f"""<?php
declare(strict_types=1);
namespace DurableWorkflow\\Cli;
final class GeneratedBuildInfo
{{
    public const VERSION = '{version}';
    public const COMMIT = '{commit}';
    public const BUILD_DATE = '2026-07-21T00:00:00Z';
}}
""".encode()
    script = (
        "$archive = new Phar($argv[1]); "
        "$archive->addFromString('src/GeneratedBuildInfo.php', base64_decode($argv[2], true));"
    )
    subprocess.run(
        [
            "php",
            "-d",
            "phar.readonly=0",
            "-r",
            script,
            "--",
            str(path),
            base64.b64encode(generated).decode(),
        ],
        check=True,
        text=True,
        capture_output=True,
    )


def http_error(status: int, body: bytes = b"error", **headers: str) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        "https://api.github.com/repos/durable-workflow/.github/releases",
        status,
        "request failed",
        headers,
        io.BytesIO(body),
    )


def manifest() -> dict[str, object]:
    return {
        "schema": SCHEMA,
        "candidate": "beta-test-1",
        "components": {
            name: {"version": f"1.2.{index}", "commit": f"{index + 1:040x}"} for index, name in enumerate(COMPONENTS)
        },
    }


def verification(candidate: dict[str, object]) -> dict[str, object]:
    return candidate_verification(candidate, verified_at="2026-07-16T00:00:00Z")


class ManifestTest(unittest.TestCase):
    def test_python_registry_normalizes_every_supported_prerelease_channel(self) -> None:
        self.assertEqual("2.0.0a7", canonical_pypi_version("2.0.0-alpha.7"))
        self.assertEqual("2.0.0b21", canonical_pypi_version("2.0.0-beta.21"))
        self.assertEqual("2.0.0rc5", canonical_pypi_version("2.0.0-rc.5"))
        self.assertEqual("2.0.0", canonical_pypi_version("2.0.0"))

    def test_python_release_lookup_uses_pep_440_rc_identity(self) -> None:
        component = COMPONENTS["sdk-python"]
        commit = "a" * 40

        class FixtureClient:
            requested_url = ""

            def json(self, url: str) -> dict[str, object]:
                self.requested_url = url
                return {
                    "info": {
                        "version": "2.0.0rc5",
                        "project_urls": {"Repository": "https://github.com/durable-workflow/sdk-python"},
                    },
                    "urls": [],
                }

        client = FixtureClient()
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(
                CandidateError,
                "wheel and source archive",
            ),
        ):
            verify_pypi(
                client,
                component,
                "2.0.0-rc.5",
                commit,
                Path(temporary),
            )
        self.assertEqual(
            "https://pypi.org/pypi/durable-workflow/2.0.0rc5/json",
            client.requested_url,
        )

    def test_python_evidence_accepts_only_exact_semver_or_pep_440_registry_urls(self) -> None:
        candidate = manifest()
        candidate["components"]["sdk-python"]["version"] = "2.0.0-rc.5"
        result = verification(candidate)
        registry = result["components"]["sdk-python"]["distribution"]
        semver_url = "https://pypi.org/pypi/durable-workflow/2.0.0-rc.5/json"
        pep_440_url = "https://pypi.org/pypi/durable-workflow/2.0.0rc5/json"

        self.assertEqual(semver_url, registry["registry"])
        validate_verification(result, candidate)

        registry["registry"] = pep_440_url
        validate_verification(result, candidate)

        registry["registry"] = "https://pypi.org/pypi/durable-workflow/2.0.0rc05/json"
        with self.assertRaisesRegex(CandidateError, "planned PyPI package identity"):
            validate_verification(result, candidate)

    def test_waterline_alpha_139_expands_minified_metadata_and_checks_effective_provenance(self) -> None:
        component = COMPONENTS["waterline"]
        commit = "a" * 40
        dist_url = "https://api.github.com/repos/durable-workflow/waterline/zipball/commit"
        payload = {
            "minified": "composer/2.0",
            "packages": {
                component.package: [
                    {
                        "name": component.package,
                        "version": "2.0.0-alpha.140",
                        "source": {
                            "type": "git",
                            "url": "https://github.com/durable-workflow/waterline",
                            "reference": commit,
                        },
                        "dist": {"type": "zip", "url": dist_url, "reference": commit},
                    },
                    {"version": "2.0.0-alpha.139"},
                ]
            },
        }
        client = mock.Mock()
        client.json.return_value = payload
        client.download.return_value = {"url": dist_url, "size": 1, "sha256": "b" * 64}

        with tempfile.TemporaryDirectory() as temporary:
            result = verify_composer(client, component, "2.0.0-alpha.139", commit, Path(temporary))

        self.assertEqual(commit, result["source_reference"])
        self.assertEqual(commit, result["dist_reference"])
        client.download.assert_called_once()

        payload["packages"][component.package][1]["source"] = {
            "type": "git",
            "url": "https://github.com/durable-workflow/waterline",
            "reference": "c" * 40,
        }
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(CandidateError, "source identity.*does not match"),
        ):
            verify_composer(client, component, "2.0.0-alpha.139", commit, Path(temporary))

        payload["packages"][component.package][1]["source"] = "__unset"
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(CandidateError, "source identity.*does not match"),
        ):
            verify_composer(client, component, "2.0.0-alpha.139", commit, Path(temporary))

        del payload["packages"][component.package][1]["source"]
        payload["packages"][component.package][0]["source"]["reference"] = "c" * 40
        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(CandidateError, "source identity.*does not match"),
        ):
            verify_composer(client, component, "2.0.0-alpha.139", commit, Path(temporary))

    def test_composer_verification_does_not_inherit_unmarked_or_unsupported_metadata(self) -> None:
        component = COMPONENTS["workflow"]
        commit = "a" * 40
        first = {
            "version": "2.0.0-alpha.2",
            "source": {"reference": commit},
            "dist": {"url": "https://example.test/package.zip", "reference": commit},
        }
        client = mock.Mock()

        cases = (
            (None, "source identity.*does not match"),
            ("composer/3.0", "unsupported minified format"),
        )
        for marker, error in cases:
            with self.subTest(marker=marker):
                payload = {"packages": {component.package: [first, {"version": "2.0.0-alpha.1"}]}}
                if marker is not None:
                    payload["minified"] = marker
                client.json.return_value = payload
                with (
                    tempfile.TemporaryDirectory() as temporary,
                    self.assertRaisesRegex(CandidateError, error),
                ):
                    verify_composer(client, component, "2.0.0-alpha.1", commit, Path(temporary))

    def test_composer_verification_rejects_invalid_compact_identity_and_order(self) -> None:
        component = COMPONENTS["waterline"]
        commit = "a" * 40
        dist_url = "https://example.test/package.zip"
        first = {
            "version": "2.0.0-alpha.139",
            "source": {"reference": commit},
            "dist": {"url": dist_url, "reference": commit},
        }
        client = mock.Mock()

        cases = (
            ([first, {"version": "2.0.0-alpha.140"}], "strictly descending"),
            ([first, {"version": "2.0.0-alpha.138"}, {"source": {"reference": commit}}], "declare a version"),
        )
        for versions, error in cases:
            with self.subTest(error=error):
                client.json.return_value = {
                    "minified": "composer/2.0",
                    "packages": {component.package: versions},
                }
                with (
                    tempfile.TemporaryDirectory() as temporary,
                    self.assertRaisesRegex(CandidateError, error),
                ):
                    verify_composer(client, component, "2.0.0-alpha.139", commit, Path(temporary))

    def test_composer_verification_rejects_ambiguous_exact_version_before_provenance(self) -> None:
        component = COMPONENTS["workflow"]
        commit = "a" * 40
        client = mock.Mock()
        client.json.return_value = {
            "packages": {
                component.package: [
                    {
                        "version": "2.0.0-alpha.1",
                        "source": {"reference": commit},
                        "dist": {"url": "https://example.test/package.zip", "reference": commit},
                    },
                    {
                        "version": "v2.0.0-alpha.1",
                        "source": {"reference": "b" * 40},
                        "dist": {"url": "https://example.test/drifted.zip", "reference": "b" * 40},
                    },
                ]
            }
        }

        with (
            tempfile.TemporaryDirectory() as temporary,
            self.assertRaisesRegex(CandidateError, "multiple records"),
        ):
            verify_composer(client, component, "2.0.0-alpha.1", commit, Path(temporary))

        client.download.assert_not_called()

    def test_verification_schema_and_runtime_reject_unknown_or_missing_nested_evidence(self) -> None:
        candidate = manifest()
        result = verification(candidate)
        schema = json.loads((REPOSITORY_ROOT / "candidates" / "verification-schema.json").read_bytes())
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(result)
        validate_verification(result, candidate)

        for path in ("top-level", "nested"):
            with self.subTest(path=path):
                tampered = copy.deepcopy(result)
                if path == "top-level":
                    tampered["injected"] = "same-user-process"
                else:
                    tampered["components"]["workflow"]["distribution"]["injected"] = True
                with self.assertRaisesRegex(CandidateError, "keys must be exactly"):
                    validate_verification(tampered, candidate)

        missing = copy.deepcopy(result)
        del missing["components"]["server"]["distribution"]["configs"]
        with self.assertRaisesRegex(CandidateError, "keys must be exactly"):
            validate_verification(missing, candidate)

    def test_waterline_verification_requires_both_matching_distributions(self) -> None:
        candidate = manifest()
        result = verification(candidate)
        schema = json.loads((REPOSITORY_ROOT / "candidates" / "verification-schema.json").read_bytes())

        missing = copy.deepcopy(result)
        del missing["components"]["waterline"]["distributions"]["service"]
        with self.assertRaises(ValidationError):
            Draft202012Validator(schema).validate(missing)
        with self.assertRaisesRegex(CandidateError, "keys must be exactly"):
            validate_verification(missing, candidate)

        mismatches = {
            "version": lambda value: value["components"]["waterline"]["distributions"]["service"].update(
                {"image": "docker.io/durableworkflow/waterline:9.9.9"}
            ),
            "source": lambda value: value["components"]["waterline"]["distributions"]["embedded"].update(
                {"source_reference": "f" * 40}
            ),
            "labels": lambda value: value["components"]["waterline"]["distributions"]["service"]["configs"][0][
                "labels"
            ].update({"org.opencontainers.image.revision": "f" * 40}),
        }
        for mismatch, mutate in mismatches.items():
            with self.subTest(mismatch=mismatch):
                tampered = copy.deepcopy(result)
                mutate(tampered)
                with self.assertRaises(CandidateError):
                    validate_verification(tampered, candidate)

        partial = copy.deepcopy(result)
        partial["components"]["waterline"]["distributions"]["service"]["configs"].pop()
        with self.assertRaises(ValidationError):
            Draft202012Validator(schema).validate(partial)
        with self.assertRaises(CandidateError):
            validate_verification(partial, candidate)

    def test_historical_pre_service_verification_remains_readable_but_cannot_verify_a_new_candidate(self) -> None:
        historical_candidate = legacy_candidate_manifest()
        historical = legacy_candidate_verification(historical_candidate)

        self.assertEqual(LEGACY_VERIFICATION_SCHEMA, historical["schema"])
        validate_recorded_verification(historical, historical_candidate)

        candidate = manifest()
        with self.assertRaisesRegex(CandidateError, "does not prove this exact candidate manifest"):
            validate_recorded_verification(legacy_candidate_verification(candidate), candidate)
        with self.assertRaisesRegex(CandidateError, "does not prove this exact candidate manifest"):
            validate_verification(legacy_candidate_verification(candidate), candidate)

        unrecorded = copy.deepcopy(historical_candidate)
        unrecorded["candidate"] = "unrecorded-pre-service-candidate"
        with self.assertRaisesRegex(CandidateError, "not an exact recorded historical contract"):
            validate_recorded_verification(legacy_candidate_verification(unrecorded), unrecorded)

        missing = copy.deepcopy(historical)
        del missing["components"]["waterline"]["distribution"]
        with self.assertRaisesRegex(CandidateError, "not successful"):
            validate_recorded_verification(missing, historical_candidate)

    def test_exact_tagged_and_completed_pre_service_candidates_remain_readable(self) -> None:
        candidates = [
            (
                "5e083e07e6abecbb0547466812f866a3650039b210dbe1d486ca98528479cd29",
                legacy_beta_one_candidate_manifest(),
            ),
            *zip(
                (
                    "dd5e8d3bb248c2b1b292b5badf29376cc5c5b6fa73dedfb343e33987a2b6d7a2",
                    "43243594ba34ff220365d9c514e6a54b93789788676ca8b1d678b679afa6c1c5",
                    "2fbeda4e3368edf7cda7bcc749359d4bcdf7fcccca289e32316782613a84b4a6",
                ),
                legacy_completed_candidate_manifests(),
                strict=True,
            ),
        ]

        for expected_digest, candidate in candidates:
            with self.subTest(candidate=candidate["candidate"]):
                self.assertEqual(expected_digest, manifest_digest(candidate))
                validate_recorded_verification(legacy_candidate_verification(candidate), candidate)

                unrecorded = copy.deepcopy(candidate)
                unrecorded["candidate"] += "-replacement"
                with self.assertRaisesRegex(CandidateError, "not an exact recorded historical contract"):
                    validate_recorded_verification(legacy_candidate_verification(unrecorded), unrecorded)

    def test_fresh_writer_independently_rejects_shape_valid_fabricated_distribution_evidence(self) -> None:
        candidate = manifest()
        trusted = verification(candidate)
        tampered = copy.deepcopy(trusted)
        tampered["components"]["workflow"]["distribution"]["dist"]["sha256"] = "f" * 64
        validate_verification(tampered, candidate)

        sources = {COMPONENTS[name].repository: result["source"] for name, result in trusted["components"].items()}

        def composer_verifier(
            _client: object, component: object, _version: str, _commit: str, _directory: Path
        ) -> dict[str, object]:
            name = next(name for name, expected in COMPONENTS.items() if expected == component)
            return trusted["components"][name]["distribution"]

        with (
            mock.patch(
                "scripts.beta_candidate.resolve_github_tag", side_effect=lambda _client, repo, _version: sources[repo]
            ),
            mock.patch.dict("scripts.beta_candidate.VERIFIERS", {"composer": composer_verifier}),
            self.assertRaisesRegex(CandidateError, "differs from the isolated verification handoff"),
        ):
            revalidate_verification(tampered, candidate, mock.Mock())

    def test_fresh_writer_rejects_a_fabricated_cli_identity_suffix(self) -> None:
        candidate = manifest()
        tampered = verification(candidate)
        identity = tampered["components"]["cli"]["distribution"]["package_source"]
        identity["embedded_phar_identity"] = f"{identity['embedded_phar_identity']} verifier-controlled"

        with self.assertRaisesRegex(CandidateError, "package_source does not bind the planned CLI source"):
            revalidate_verification(tampered, candidate, mock.Mock())

    def test_non_executing_phar_inspection_binds_the_full_embedded_source_commit(self) -> None:
        version = "0.1.94"
        commit = "3" * 40
        with tempfile.TemporaryDirectory() as temporary:
            phar = Path(temporary) / "dw.phar"
            write_build_info_phar(phar, version, commit)

            self.assertEqual(
                canonical_cli_embedded_identity(version, commit),
                inspect_cli_phar_identity(phar, version, commit),
            )
            with self.assertRaisesRegex(CandidateError, "does not embed planned source commit"):
                inspect_cli_phar_identity(phar, version, "f" * 40)

    def test_verification_loader_rejects_oversized_handoff_before_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "verification.json"
            path.write_bytes(b" " * (256 * 1024 + 1))
            with self.assertRaisesRegex(CandidateError, "exceeds the 256 KiB limit"):
                load_verification(path, manifest())

    def test_public_client_preserves_explicit_github_api_version(self) -> None:
        client = PublicClient("fixture-token")
        with mock.patch("scripts.beta_candidate.urllib.request.urlopen", return_value=object()) as open_url:
            client.request(
                "https://api.github.com/repos/durable-workflow/.github/actions/runs/1/approvals",
                headers={"X-GitHub-Api-Version": "2026-03-10"},
            )
        request = open_url.call_args.args[0]
        self.assertEqual("2026-03-10", request.get_header("X-github-api-version"))
        self.assertEqual("Bearer fixture-token", request.get_header("Authorization"))

    def test_public_client_retries_github_service_and_body_read_interruptions(self) -> None:
        class InterruptedResponse(io.BytesIO):
            def read(self, _size: int = -1) -> bytes:
                raise http.client.IncompleteRead(b"partial")

        sleeps: list[float] = []
        client = PublicClient(max_attempts=4, retry_base_seconds=1, sleep=sleeps.append)
        responses = [
            http_error(503, b"service unavailable", **{"Retry-After": "3"}),
            InterruptedResponse(),
            io.BytesIO(b'{"tag_name":"release-plan/current"}'),
        ]

        with mock.patch("scripts.beta_candidate.urllib.request.urlopen", side_effect=responses) as open_url:
            result = client.json("https://api.github.com/repos/durable-workflow/.github/releases?per_page=100")

        self.assertEqual({"tag_name": "release-plan/current"}, result)
        self.assertEqual([3, 2], sleeps)
        self.assertEqual(3, open_url.call_count)

    def test_public_client_honors_explicit_rate_limit_guidance(self) -> None:
        sleeps: list[float] = []
        client = PublicClient(
            max_attempts=3,
            retry_base_seconds=1,
            sleep=sleeps.append,
            now=lambda: 100,
        )
        responses = [
            http_error(
                403,
                b"API rate limit exceeded",
                **{"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "112"},
            ),
            http_error(429, **{"Retry-After": "20"}),
            io.BytesIO(b"[]"),
        ]

        with mock.patch("scripts.beta_candidate.urllib.request.urlopen", side_effect=responses):
            self.assertEqual(
                [],
                client.json("https://api.github.com/repos/durable-workflow/.github/releases?per_page=100"),
            )

        self.assertEqual([12, 20], sleeps)

    def test_public_client_never_retries_authentication_with_rate_limit_guidance(self) -> None:
        sleeps: list[float] = []
        client = PublicClient(max_attempts=3, retry_base_seconds=1, sleep=sleeps.append)
        error = http_error(
            401,
            b"Bad credentials: API rate limit exceeded",
            **{"Retry-After": "20", "X-RateLimit-Remaining": "0"},
        )

        with (
            mock.patch("scripts.beta_candidate.urllib.request.urlopen", side_effect=error) as open_url,
            self.assertRaisesRegex(CandidateError, r"public request failed \(401\)"),
        ):
            client.json("https://api.github.com/repos/durable-workflow/.github/releases?per_page=100")

        self.assertEqual([], sleeps)
        self.assertEqual(1, open_url.call_count)

    def test_public_client_reports_bounded_transient_infrastructure_without_url_or_token(self) -> None:
        client = PublicClient(
            "fixture-secret",
            max_attempts=3,
            retry_base_seconds=1,
            sleep=lambda _delay: None,
        )

        with (
            mock.patch(
                "scripts.beta_candidate.urllib.request.urlopen",
                side_effect=[http_error(503), http_error(502), http_error(503)],
            ) as open_url,
            self.assertRaisesRegex(
                PublicInfrastructureError,
                r"classification=github-read-transient, endpoint_class=releases-api, "
                r"attempts=3, reason=retry-exhausted, status=503",
            ) as raised,
        ):
            client.json("https://api.github.com/repos/durable-workflow/.github/releases?per_page=100")

        self.assertEqual(3, open_url.call_count)
        self.assertNotIn("fixture-secret", str(raised.exception))
        self.assertNotIn("api.github.com", str(raised.exception))

    def test_public_client_stops_before_retry_guidance_exceeds_the_workflow_budget(self) -> None:
        clock = [0.0]
        sleeps: list[float] = []

        def sleep(delay: float) -> None:
            sleeps.append(delay)
            clock[0] += delay

        client = PublicClient(
            max_attempts=5,
            retry_base_seconds=2,
            deadline_seconds=5,
            sleep=sleep,
            monotonic=lambda: clock[0],
        )
        responses = [
            http_error(503),
            http_error(503, **{"Retry-After": "10"}),
        ]

        with (
            mock.patch("scripts.beta_candidate.urllib.request.urlopen", side_effect=responses) as open_url,
            self.assertRaisesRegex(
                PublicInfrastructureError,
                r"endpoint_class=releases-api, attempts=2, reason=workflow-deadline, status=503",
            ),
        ):
            client.json("https://api.github.com/repos/durable-workflow/.github/releases?per_page=100")

        self.assertEqual([2], sleeps)
        self.assertEqual(2, open_url.call_count)

    def test_public_client_does_not_retry_deterministic_http_or_data_failures(self) -> None:
        client = PublicClient(max_attempts=3, sleep=lambda _delay: self.fail("deterministic failure was retried"))
        for status in (401, 403, 404):
            with self.subTest(status=status):
                with (
                    mock.patch(
                        "scripts.beta_candidate.urllib.request.urlopen",
                        side_effect=http_error(status, b"Resource not accessible"),
                    ) as open_url,
                    self.assertRaisesRegex(CandidateError, rf"public request failed \({status}\)"),
                ):
                    client.json("https://api.github.com/repos/durable-workflow/.github/releases?per_page=100")
                self.assertEqual(1, open_url.call_count)

        with (
            mock.patch(
                "scripts.beta_candidate.urllib.request.urlopen",
                return_value=io.BytesIO(b"<html>not JSON</html>"),
            ) as open_url,
            self.assertRaisesRegex(CandidateError, "did not return valid JSON"),
        ):
            client.json("https://api.github.com/repos/durable-workflow/.github/releases?per_page=100")
        self.assertEqual(1, open_url.call_count)

    def test_public_client_does_not_retry_non_github_service_failures(self) -> None:
        client = PublicClient(max_attempts=3, sleep=lambda _delay: self.fail("registry failure was retried"))
        error = urllib.error.HTTPError(
            "https://pypi.org/pypi/durable-workflow/json",
            503,
            "request failed",
            {},
            io.BytesIO(b"service unavailable"),
        )

        with (
            mock.patch("scripts.beta_candidate.urllib.request.urlopen", side_effect=error) as open_url,
            self.assertRaisesRegex(CandidateError, r"public request failed \(503\)"),
        ):
            client.json("https://pypi.org/pypi/durable-workflow/json")

        self.assertEqual(1, open_url.call_count)

    def test_manifest_is_canonical_and_stable(self) -> None:
        candidate = manifest()
        validate_manifest(candidate)
        self.assertEqual(hashlib.sha256(canonical_json(candidate)).hexdigest(), manifest_digest(candidate))
        self.assertEqual("docker.io/durableworkflow/server", COMPONENTS["server"].package)

    def test_manifest_rejects_missing_component(self) -> None:
        candidate = manifest()
        del candidate["components"]["sdk-rust"]
        with self.assertRaisesRegex(CandidateError, "components must be exactly"):
            validate_manifest(candidate)

    def test_manifest_rejects_unowned_fields(self) -> None:
        candidate = manifest()
        candidate["components"]["server"]["token"] = "do-not-store"
        with self.assertRaisesRegex(CandidateError, "only version and commit"):
            validate_manifest(candidate)

    def test_manifest_rejects_abbreviated_commit(self) -> None:
        candidate = manifest()
        candidate["components"]["workflow"]["commit"] = "abc123"
        with self.assertRaisesRegex(CandidateError, "full lowercase Git commit"):
            validate_manifest(candidate)

    def test_checksum_parser_accepts_common_sha256_formats(self) -> None:
        digest_a = "a" * 64
        digest_b = "b" * 64
        parsed = parse_checksums(f"{digest_a}  first\n{digest_b} *second.exe\n".encode())
        self.assertEqual({"first": digest_a, "second.exe": digest_b}, parsed)

    def test_cli_release_rejects_same_repository_attestation_from_wrong_commit(self) -> None:
        attested_commit = "a" * 40
        declared_commit = "b" * 40
        version = "1.2.3"

        class FixtureClient:
            contents = {name: f"fixture {name}\n".encode() for name in CLI_ASSETS - {"SHA256SUMS"}}
            checksums = "".join(
                f"{hashlib.sha256(content).hexdigest()}  {name}\n" for name, content in sorted(contents.items())
            ).encode()

            def json(self, _url: str) -> dict[str, object]:
                return {
                    "id": 123,
                    "tag_name": version,
                    "draft": False,
                    "html_url": f"https://github.com/durable-workflow/cli/releases/tag/{version}",
                    "assets": [
                        {
                            "id": index,
                            "name": name,
                            "browser_download_url": f"https://example.invalid/{name}",
                        }
                        for index, name in enumerate(sorted(CLI_ASSETS), start=1)
                    ],
                }

            def bytes(self, _url: str) -> bytes:
                return self.checksums

            def download(self, url: str, path: Path, *, expected_sha256: str) -> dict[str, object]:
                content = self.contents[url.rsplit("/", 1)[-1]]
                if expected_sha256 != hashlib.sha256(content).hexdigest():
                    raise AssertionError("fixture download checksum mismatch")
                path.write_bytes(content)
                return {"url": url, "size": len(content), "sha256": expected_sha256}

        def verify_attestation(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
            self.assertEqual("durable-workflow/cli", command[command.index("--repo") + 1])
            if "--source-digest" not in command:
                return subprocess.CompletedProcess(command, 1, stdout="", stderr="workflow authority does not match")
            source_digest = command[command.index("--source-digest") + 1]
            return subprocess.CompletedProcess(
                command,
                0 if source_digest == attested_commit else 1,
                stdout="",
                stderr="source digest does not match the attested build",
            )

        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch("scripts.beta_candidate.shutil.which", return_value="/usr/bin/gh"),
            mock.patch("scripts.beta_candidate.subprocess.run", side_effect=verify_attestation),
            self.assertRaisesRegex(CandidateError, "build attestation failed"),
        ):
            verify_github_release(FixtureClient(), COMPONENTS["cli"], version, declared_commit, Path(temporary))

    def test_python_registry_archives_match_the_declared_source(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            source = directory / "source-fixture.tar.gz"
            sdist = directory / "package.tar.gz"
            wheel = directory / "package.whl"
            source_files = {
                "pyproject.toml": b"[project]\nname='durable-workflow'\n",
                "src/durable_workflow/__init__.py": b"VERSION = '1.0.0'\n",
            }
            self.write_tar(source, "source-commit", source_files)
            self.write_tar(
                sdist,
                "durable_workflow-1.0.0",
                {
                    **source_files,
                    "PKG-INFO": b"generated metadata",
                    "setup.cfg": b"[egg_info]\ntag_build =\n",
                    "src/durable_workflow.egg-info/PKG-INFO": b"generated metadata",
                },
            )
            with zipfile.ZipFile(wheel, "w") as archive:
                archive.writestr("durable_workflow/__init__.py", source_files["src/durable_workflow/__init__.py"])
                archive.writestr("durable_workflow-1.0.0.dist-info/METADATA", b"generated metadata")

            class FixtureClient:
                def download(self, _url: str, path: Path) -> dict[str, object]:
                    shutil.copyfile(source, path)
                    return {"url": "fixture", "size": path.stat().st_size, "sha256": "a" * 64}

            component = COMPONENTS["sdk-python"]
            result = verify_python_archive_identity(FixtureClient(), component, "1" * 40, sdist, [wheel], directory)
            self.assertEqual(2, result["source_files_compared"])
            self.assertEqual(1, result["wheel_files_compared"])

    @staticmethod
    def write_tar(path: Path, root: str, files: dict[str, bytes]) -> None:
        with tarfile.open(path, "w:gz") as archive:
            for name, content in files.items():
                member = tarfile.TarInfo(f"{root}/{name}")
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))


class RecordTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        root = Path(self.temporary.name)
        self.root = root
        self.repository = root / "work"
        self.remote = root / "remote.git"
        subprocess.run(["git", "init", "--bare", str(self.remote)], check=True, capture_output=True)
        subprocess.run(["git", "init", str(self.repository)], check=True, capture_output=True)
        self.manifest_path = root / "candidate.json"
        self.verification_path = root / "verification.json"
        self.authoritative_path = root / "authoritative.json"
        self.revalidation_patcher = mock.patch("scripts.beta_candidate.revalidate_verification")
        self.revalidate = self.revalidation_patcher.start()
        self.revalidate.side_effect = lambda verification, _manifest, _client: verification

    def tearDown(self) -> None:
        self.revalidation_patcher.stop()
        self.temporary.cleanup()

    def write_request(self, candidate: dict[str, object]) -> None:
        self.manifest_path.write_bytes(canonical_json(candidate))
        self.verification_path.write_bytes(canonical_json(verification(candidate)))

    def test_first_record_and_idempotent_recovery_keep_one_commit(self) -> None:
        candidate = manifest()
        self.write_request(candidate)
        created = record_candidate(
            self.repository,
            self.manifest_path,
            self.verification_path,
            remote=str(self.remote),
            authoritative_verification=self.authoritative_path,
            client=mock.Mock(),
        )
        repeated = record_candidate(
            self.repository,
            self.manifest_path,
            self.verification_path,
            remote=str(self.remote),
            authoritative_verification=self.authoritative_path,
            client=mock.Mock(),
        )
        self.assertEqual("created", created["status"])
        self.assertEqual("existing", repeated["status"])
        self.assertEqual(created["commit"], repeated["commit"])
        self.assertEqual(1, self.revalidate.call_count)
        record_files = subprocess.run(
            ["git", "--git-dir", str(self.remote), "ls-tree", "-r", "--name-only", created["commit"]],
            check=True,
            text=True,
            capture_output=True,
        ).stdout.splitlines()
        self.assertEqual(["candidate.json", "verification.json"], record_files)
        self.assertEqual(canonical_json(verification(candidate)), self.authoritative_path.read_bytes())
        compatibility = check_candidate_compatibility(self.repository, self.manifest_path, remote=str(self.remote))
        self.assertEqual("existing", compatibility["status"])
        self.assertEqual(created["commit"], compatibility["commit"])

    def test_existing_candidate_rejects_tuple_mutation(self) -> None:
        candidate = manifest()
        self.write_request(candidate)
        record_candidate(
            self.repository,
            self.manifest_path,
            self.verification_path,
            remote=str(self.remote),
            authoritative_verification=self.authoritative_path,
            client=mock.Mock(),
        )
        changed = copy.deepcopy(candidate)
        changed["components"]["cli"]["version"] = "1.2.99"
        changed["components"]["cli"]["commit"] = "f" * 40
        self.write_request(changed)
        with self.assertRaisesRegex(CandidateError, "immutable"):
            check_candidate_compatibility(self.repository, self.manifest_path, remote=str(self.remote))
        with self.assertRaisesRegex(CandidateError, "immutable"):
            record_candidate(
                self.repository,
                self.manifest_path,
                self.verification_path,
                remote=str(self.remote),
                authoritative_verification=self.authoritative_path,
                client=mock.Mock(),
            )

    def test_record_rejects_incomplete_verification(self) -> None:
        candidate = manifest()
        result = verification(candidate)
        del result["components"]["server"]
        self.manifest_path.write_bytes(canonical_json(candidate))
        self.verification_path.write_bytes(canonical_json(result))
        with self.assertRaisesRegex(CandidateError, "every candidate component"):
            record_candidate(
                self.repository,
                self.manifest_path,
                self.verification_path,
                remote=str(self.remote),
                authoritative_verification=self.authoritative_path,
                client=mock.Mock(),
            )

    def test_same_user_downloaded_process_tampering_fails_before_first_git_write(self) -> None:
        candidate = manifest()
        self.write_request(candidate)
        result = json.loads(self.verification_path.read_bytes())
        result["components"]["workflow"]["distribution"]["dist"]["sha256"] = "f" * 64
        self.verification_path.write_bytes(canonical_json(result))
        self.revalidate.side_effect = CandidateError("independent public evidence differs")

        with self.assertRaisesRegex(CandidateError, "independent public evidence differs"):
            record_candidate(
                self.repository,
                self.manifest_path,
                self.verification_path,
                remote=str(self.remote),
                authoritative_verification=self.authoritative_path,
                client=mock.Mock(),
            )

        refs = subprocess.run(
            ["git", "--git-dir", str(self.remote), "show-ref"],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual("", refs.stdout)

    def test_cli_identity_suffix_tampering_fails_before_first_git_write(self) -> None:
        candidate = manifest()
        self.write_request(candidate)
        result = json.loads(self.verification_path.read_bytes())
        cli = result["components"]["cli"]
        cli["distribution"]["package_source"]["embedded_phar_identity"] = (
            f"{canonical_cli_embedded_identity(cli['version'], cli['commit'])} fabricated-suffix"
        )
        self.verification_path.write_bytes(canonical_json(result))

        with self.assertRaisesRegex(CandidateError, "package_source does not bind the planned CLI source"):
            record_candidate(
                self.repository,
                self.manifest_path,
                self.verification_path,
                remote=str(self.remote),
                authoritative_verification=self.authoritative_path,
                client=mock.Mock(),
            )

        self.revalidate.assert_not_called()
        refs = subprocess.run(
            ["git", "--git-dir", str(self.remote), "show-ref"],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual("", refs.stdout)

    def test_canonical_cli_handoff_for_other_source_bytes_fails_before_first_git_write(self) -> None:
        candidate = manifest()
        self.write_request(candidate)
        submitted = verification(candidate)
        cli_identity = candidate["components"]["cli"]
        wrong_phar = self.root / "wrong-source.phar"
        write_build_info_phar(wrong_phar, cli_identity["version"], "f" * 40)
        sources = {COMPONENTS[name].repository: result["source"] for name, result in submitted["components"].items()}

        def distribution_verifier(
            _client: object,
            component: object,
            _version: str,
            _commit: str,
            _directory: Path,
        ) -> dict[str, object]:
            name = next(name for name, expected in COMPONENTS.items() if expected == component)
            return submitted["components"][name]["distribution"]

        def cli_verifier(
            _client: object,
            _component: object,
            version: str,
            commit: str,
            directory: Path,
        ) -> dict[str, object]:
            phar = directory / "dw.phar"
            shutil.copyfile(wrong_phar, phar)
            inspect_cli_phar_identity(phar, version, commit)
            self.fail("other-source PHAR bytes unexpectedly matched the planned source")

        self.revalidate.side_effect = lambda handoff, selected, client: revalidate_verification(
            handoff, selected, client
        )
        verifier_replacements = {component.distribution: distribution_verifier for component in COMPONENTS.values()}
        with (
            mock.patch(
                "scripts.beta_candidate.resolve_github_tag",
                side_effect=lambda _client, repository, _version: sources[repository],
            ),
            mock.patch.dict("scripts.beta_candidate.VERIFIERS", verifier_replacements),
            mock.patch(
                "scripts.beta_candidate.verify_composer",
                return_value=submitted["components"]["waterline"]["distributions"]["embedded"],
            ),
            mock.patch(
                "scripts.beta_candidate.verify_oci",
                return_value=submitted["components"]["waterline"]["distributions"]["service"],
            ),
            mock.patch("scripts.beta_candidate.verify_github_release", side_effect=cli_verifier),
            self.assertRaisesRegex(CandidateError, "does not embed planned source commit"),
        ):
            record_candidate(
                self.repository,
                self.manifest_path,
                self.verification_path,
                remote=str(self.remote),
                authoritative_verification=self.authoritative_path,
                client=mock.Mock(),
            )

        refs = subprocess.run(
            ["git", "--git-dir", str(self.remote), "show-ref"],
            check=False,
            text=True,
            capture_output=True,
        )
        self.assertEqual("", refs.stdout)


if __name__ == "__main__":
    unittest.main()
