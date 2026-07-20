from __future__ import annotations

import copy
import hashlib
import http.client
import io
import shutil
import subprocess
import tarfile
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest import mock

from scripts.beta_candidate import (
    CLI_ASSETS,
    COMPONENTS,
    SCHEMA,
    VERIFICATION_SCHEMA,
    CandidateError,
    PublicClient,
    PublicInfrastructureError,
    canonical_json,
    check_candidate_compatibility,
    manifest_digest,
    parse_checksums,
    record_candidate,
    validate_manifest,
    verify_github_release,
    verify_python_archive_identity,
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
    identities = candidate["components"]
    assert isinstance(identities, dict)
    return {
        "schema": VERIFICATION_SCHEMA,
        "candidate": candidate["candidate"],
        "manifest_sha256": manifest_digest(candidate),
        "verified_at": "2026-07-16T00:00:00Z",
        "outcome": "verified",
        "components": {
            name: {
                "version": identity["version"],
                "commit": identity["commit"],
                "source": {},
                "distribution": {},
                "outcome": "verified",
            }
            for name, identity in identities.items()
        },
    }


class ManifestTest(unittest.TestCase):
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
                return subprocess.CompletedProcess(
                    command, 1, stdout="", stderr="workflow authority does not match"
                )
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
        self.repository = root / "work"
        self.remote = root / "remote.git"
        subprocess.run(["git", "init", "--bare", str(self.remote)], check=True, capture_output=True)
        subprocess.run(["git", "init", str(self.repository)], check=True, capture_output=True)
        self.manifest_path = root / "candidate.json"
        self.verification_path = root / "verification.json"
        self.authoritative_path = root / "authoritative.json"

    def tearDown(self) -> None:
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
        )
        repeated = record_candidate(
            self.repository,
            self.manifest_path,
            self.verification_path,
            remote=str(self.remote),
            authoritative_verification=self.authoritative_path,
        )
        self.assertEqual("created", created["status"])
        self.assertEqual("existing", repeated["status"])
        self.assertEqual(created["commit"], repeated["commit"])
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
            )


if __name__ == "__main__":
    unittest.main()
