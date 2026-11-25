"""Mirrored PHP archives: immutable mirror download, bounded retry, fail-closed absence and mirror tooling.

CI runs these through tests.test_php_linux_bootstrap, which imports them.
"""

from contextlib import ExitStack
import hashlib
import io
import json
import os
from pathlib import Path
import ssl
import tempfile
from types import SimpleNamespace
import unittest
from urllib.error import HTTPError, URLError

from scripts import php_archive_mirror as mirror
from scripts import php_linux_bootstrap as bootstrap
from scripts import protected_policy_data as data
from tests import test_protected_policy_data as scenario

CONTEXT = SimpleNamespace(verify_mode=ssl.CERT_REQUIRED, check_hostname=True)
STORAGE = f"https://release-assets.githubusercontent.com/github-production-release-asset/{bootstrap.MIRROR_REPOSITORY_ID}"
MIRROR_DOWNLOAD = (f"https://github.com/{bootstrap.MIRROR_REPOSITORY}/releases/download/"
                   "php-sha256-0123456789abcdef/php_8.3-nts+ubuntu26.04.tar.zst")


def mirrored_catalog(payload: bytes, *, mirror_id=900000101):
    catalog = bootstrap.load_catalog()
    row = catalog["archives"][1]
    row["asset"] = {"id": 900000001, "name": row["asset"]["name"], "size": len(payload),
                    "digest": "sha256:" + hashlib.sha256(payload).hexdigest()}
    row["mirror"] = {"repository": bootstrap.MIRROR_REPOSITORY, "release_tag": "php-sha256-0123456789abcdef",
                     "id": mirror_id, **{key: row["asset"][key] for key in ("name", "size", "digest")}}
    return bootstrap.validate_catalog(catalog), row


class Opener:
    """Inert transport. `outcomes` scripts earlier attempts: an exception to raise or bytes to serve."""

    def __init__(self, payload=None, final=STORAGE + "/closed?sig=x", status=None, outcomes=()):
        self.payload, self.final, self.status, self.urls = payload, final, status, []
        self.outcomes = list(outcomes)

    def __call__(self, *handlers):
        self.handlers = handlers

        def open_request(request, **_options):
            self.urls.append(request.full_url)
            if self.status is not None:
                raise HTTPError(request.full_url, self.status, "absent", None, None)
            outcome = self.outcomes.pop(0) if self.outcomes else self.payload
            if isinstance(outcome, BaseException):
                raise outcome
            redirects = handlers[-1]
            redirects.redirect_request(request, None, 302, "Found", {}, self.final)
            response = io.BytesIO(outcome)
            response.status, response.geturl = 200, lambda: self.final
            return response
        return SimpleNamespace(open=open_request)


class MirrorFetchTest(unittest.TestCase):
    def test_cataloged_mirror_is_the_only_fetch_location_and_keeps_the_upstream_identity(self):
        payload = b"mirrored archive bytes"
        catalog, row = mirrored_catalog(payload)
        opener = Opener(payload)
        with bootstrap.download_held(row["asset"], CONTEXT, opener, catalog=catalog) as held:
            held.assert_sealed()
            self.assertEqual(payload, os.pread(held.descriptor, len(payload), 0))
            self.assertEqual(row["asset"], held.identity)
        # The immutable release download path, never the rate-limited anonymous REST endpoint.
        self.assertEqual([MIRROR_DOWNLOAD], opener.urls)

    def test_missing_mirror_asset_fails_closed_without_upstream_fallback(self):
        payload = b"mirrored archive bytes"
        catalog, row = mirrored_catalog(payload)
        opener = Opener(status=404)
        with ExitStack() as stack, self.assertRaises(HTTPError):
            stack.enter_context(bootstrap.download_held(row["asset"], CONTEXT, opener, catalog=catalog))
        self.assertEqual(1, len(opener.urls))
        self.assertNotIn("shivammathur", opener.urls[0])

    def test_mirror_with_different_bytes_or_a_foreign_redirect_refuses(self):
        payload = b"mirrored archive bytes"
        catalog, row = mirrored_catalog(payload)
        for opener in (Opener(b"substituted bytes!!!!!"),
                       Opener(payload, final="https://github.com/shivammathur/php-ubuntu/releases/download/x"),
                       Opener(payload, final="https://example.com/archive"),
                       Opener(payload, final="https://release-assets.githubusercontent.com/closed?sig=x"),
                       Opener(payload, final="https://release-assets.githubusercontent.com/"
                                             "github-production-release-asset/39619287/upstream?sig=x")):
            with self.subTest(final=opener.final), ExitStack() as stack, self.assertRaises(ValueError):
                stack.enter_context(bootstrap.download_held(row["asset"], CONTEXT, opener, catalog=catalog,
                                                            sleep=self.fail))
            self.assertEqual(1, len(opener.urls))

    def test_unmirrored_rows_keep_the_exact_upstream_fetch(self):
        catalog = bootstrap.load_catalog()
        row = catalog["archives"][0]
        row["mirror"] = None
        catalog = bootstrap.validate_catalog(catalog)
        self.assertEqual((bootstrap.REPOSITORY, row["asset"]), bootstrap.fetch_location(row["asset"], catalog))

    def test_committed_setup_rows_fetch_only_their_immutable_mirror_release(self):
        catalog = bootstrap.load_catalog()
        for release, row in bootstrap.setup_rows(catalog).items():
            mirrored = row["mirror"]
            with self.subTest(release=release):
                self.assertEqual(mirror.release_tag(row), mirrored["release_tag"])
                self.assertEqual({key: row["asset"][key] for key in ("name", "size", "digest")},
                                 {key: mirrored[key] for key in ("name", "size", "digest")})
                self.assertNotEqual(row["asset"]["id"], mirrored["id"])
                self.assertEqual((bootstrap.MIRROR_REPOSITORY, {key: mirrored[key] for key in ("id", "name", "size", "digest")}),
                                 bootstrap.fetch_location(row["asset"], catalog))

    def test_catalog_refuses_a_mirror_that_differs_from_its_upstream_bytes(self):
        catalog, row = mirrored_catalog(b"bytes")
        for field, value in (("digest", "sha256:" + "0" * 64), ("size", 6), ("name", "other.tar.zst"),
                             ("repository", "someone/else"), ("release_tag", "latest")):
            broken = json.loads(json.dumps(catalog))
            broken["archives"][1]["mirror"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                bootstrap.validate_catalog(broken)
        broken = json.loads(json.dumps(catalog))
        broken["archives"][1]["mirror"]["id"] = broken["archives"][0]["asset"]["id"]
        with self.assertRaises(ValueError):
            bootstrap.validate_catalog(broken)


def http_error(status, retry_after=None):
    headers = {} if retry_after is None else {"Retry-After": retry_after}
    return HTTPError(MIRROR_DOWNLOAD, status, "transient", headers, None)


class MirrorRetryTest(unittest.TestCase):
    """Transient failures repeat the same mirror request; nothing unverified is ever held."""

    def setUp(self):
        self.payload = b"mirrored archive bytes"
        self.catalog, self.row = mirrored_catalog(self.payload)
        self.sleeps, self.notices = [], []

    def fetch(self, opener):
        notice = self.notices.append
        original = bootstrap.retry_notice
        bootstrap.retry_notice = notice
        try:
            stack = ExitStack()
            with stack:
                held = stack.enter_context(bootstrap.download_held(
                    self.row["asset"], CONTEXT, opener, catalog=self.catalog, sleep=self.sleeps.append))
                held.assert_sealed()
                return os.pread(held.descriptor, len(self.payload), 0)
        finally:
            bootstrap.retry_notice = original

    def test_rate_limit_and_server_errors_are_retried_against_the_same_mirror_url(self):
        opener = Opener(self.payload, outcomes=[http_error(403), http_error(429, "7"), http_error(503)])
        self.assertEqual(self.payload, self.fetch(opener))
        self.assertEqual([MIRROR_DOWNLOAD] * 4, opener.urls)
        self.assertEqual([2, 7, 10], self.sleeps)
        self.assertEqual([403, 429, 503], [item["http_status"] for item in self.notices])
        self.assertNotIn("http", json.dumps(self.notices).replace("http_status", ""))

    def test_transport_failures_and_truncated_streams_are_retried(self):
        for outcome in (URLError(TimeoutError("timed out")), URLError(ConnectionResetError()),
                        URLError(OSError(101, "Network is unreachable")), ConnectionResetError(),
                        self.payload[:5]):
            with self.subTest(outcome=outcome):
                self.sleeps.clear()
                opener = Opener(self.payload, outcomes=[outcome])
                self.assertEqual(self.payload, self.fetch(opener))
                self.assertEqual(2, len(opener.urls))
                self.assertEqual([2], self.sleeps)

    def test_attempts_are_bounded_and_the_last_failure_is_kept(self):
        opener = Opener(self.payload, outcomes=[http_error(503)] * 5)
        with self.assertRaises(HTTPError) as caught:
            self.fetch(opener)
        self.assertEqual(503, caught.exception.code)
        self.assertEqual(bootstrap.FETCH_ATTEMPTS, len(opener.urls))
        self.assertEqual(list(bootstrap.RETRY_DELAYS), self.sleeps)

    def test_retry_after_is_capped_and_the_total_wait_is_bounded(self):
        opener = Opener(self.payload, outcomes=[http_error(429, "3600")] * 5)
        with self.assertRaises(HTTPError):
            self.fetch(opener)
        self.assertEqual([bootstrap.MAX_RETRY_AFTER] * 2, self.sleeps)
        self.assertLessEqual(sum(self.sleeps), bootstrap.MAX_RETRY_WAIT)
        self.assertEqual(3, len(opener.urls))

    def test_absence_trust_redirect_and_byte_differences_are_never_retried(self):
        for outcome in (http_error(404), http_error(401), URLError(ssl.SSLCertVerificationError("untrusted")),
                        b"substituted bytes!!!!!", self.payload + b"x", URLError("unknown url type"),
                        URLError(OSError(13, "Permission denied")),
                        ValueError("Bootstrap redirect/fallback authority refused")):
            with self.subTest(outcome=outcome):
                opener = Opener(self.payload, outcomes=[outcome])
                with self.assertRaises((HTTPError, URLError, ValueError)):
                    self.fetch(opener)
                self.assertEqual(1, len(opener.urls))
                self.assertEqual([], self.sleeps)

    def test_failures_inside_the_held_scope_are_not_retried(self):
        opener = Opener(self.payload)
        with self.assertRaisesRegex(RuntimeError, "caller"), bootstrap.download_held(
                self.row["asset"], CONTEXT, opener, catalog=self.catalog, sleep=self.sleeps.append):
            raise RuntimeError("caller")
        self.assertEqual(1, len(opener.urls))
        self.assertEqual([], self.sleeps)

    def test_retry_after_accepts_only_short_delay_seconds(self):
        for value, expected in (("7", 7), ("0", 2), ("0030", 30), ("9999", bootstrap.MAX_RETRY_AFTER)):
            with self.subTest(value=value):
                self.assertEqual(expected, bootstrap.retry_delay(1, http_error(429, value)))
        for value in ("12345", " 7", "7 ", "+7", "-1", "7.5", "0x10", "\u00b2", "\u0667",
                      "Wed, 25 Nov 2026 07:28:00 GMT", ""):
            with self.subTest(value=value):
                self.assertEqual(bootstrap.RETRY_DELAYS[0], bootstrap.retry_delay(1, http_error(429, value)))

    def test_redirect_and_final_paths_must_be_canonical(self):
        storage = f"/github-production-release-asset/{bootstrap.MIRROR_REPOSITORY_ID}"
        accepted = f"https://release-assets.githubusercontent.com{storage}/0cff91d6-82a2-4d51-ba6a-4480091bb280?sig=x"
        self.assertEqual("release-assets.githubusercontent.com",
                         bootstrap.effective_url(accepted, bootstrap.MIRROR_REPOSITORY)["host"])
        self.assertEqual("github.com", bootstrap.effective_url(MIRROR_DOWNLOAD, bootstrap.MIRROR_REPOSITORY)["host"])
        mirror_path = f"/{bootstrap.MIRROR_REPOSITORY}/releases/download"
        for target in (
                f"https://release-assets.githubusercontent.com{storage}/../39619287/upstream",
                f"https://release-assets.githubusercontent.com{storage}/./held",
                f"https://release-assets.githubusercontent.com{storage}/%2e%2e/39619287/upstream",
                f"https://release-assets.githubusercontent.com{storage}/held/extra",
                f"https://release-assets.githubusercontent.com{storage}/",
                f"https://release-assets.githubusercontent.com{storage}//held",
                f"https://release-assets.githubusercontent.com{storage}/held\\..\\x",
                f"https://github.com{mirror_path}/../../../../shivammathur/php-ubuntu/releases/download/builds/x",
                f"https://github.com{mirror_path}/%2e%2e/x",
                f"https://github.com{mirror_path}/./tag/name",
                f"https://api.github.com/repos/{bootstrap.MIRROR_REPOSITORY}/releases/assets/1/..",
        ):
            with self.subTest(target=target), self.assertRaises(ValueError):
                bootstrap.effective_url(target, bootstrap.MIRROR_REPOSITORY)
            with self.subTest(handler=target), self.assertRaises(ValueError):
                handler = bootstrap.ClosedRedirects()
                handler.repository = bootstrap.MIRROR_REPOSITORY
                handler.redirect_request(bootstrap.Request(MIRROR_DOWNLOAD), None, 302, "Found", {}, target)

    def test_mirror_url_is_built_only_from_a_reviewed_mirror_record(self):
        self.assertEqual(MIRROR_DOWNLOAD, bootstrap.mirror_url(self.row["mirror"]))
        for field, value in (("repository", "shivammathur/php-ubuntu"), ("release_tag", "latest"),
                             ("release_tag", "php-x/../../other"), ("name", "install.sh"),
                             ("name", "php_8.3-nts+ubuntu26.04.tar.zst?x=1")):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                bootstrap.mirror_url(dict(self.row["mirror"], **{field: value}))

    def test_committed_setup_rows_download_from_their_immutable_release(self):
        catalog = bootstrap.load_catalog()
        for release, row in bootstrap.setup_rows(catalog).items():
            with self.subTest(release=release):
                self.assertEqual(
                    (bootstrap.MIRROR_REPOSITORY, f"https://github.com/{bootstrap.MIRROR_REPOSITORY}/releases/download/"
                                                  f"{row['mirror']['release_tag']}/{row['asset']['name']}"),
                    bootstrap.fetch_url(row["asset"], catalog))


class MirrorToolTest(unittest.TestCase):
    def test_plan_is_a_dry_run_that_inspects_exact_local_bytes(self):
        compressed = scenario.fake_archive("8.3.99")
        files, row = scenario.archive_update(scenario.repository_files(), "26.04", compressed, 900000001, 900000101)
        catalog = json.loads(files[data.CATALOG_PATH])
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as downloads:
            for path, raw in files.items():
                if path.startswith("qualification/php-linux-"):
                    (Path(root) / path).parent.mkdir(parents=True, exist_ok=True)
                    (Path(root) / path).write_bytes(raw)
            archive = Path(downloads) / row["asset"]["name"]
            archive.write_bytes(compressed)
            result = mirror.plan(Path(downloads), catalog, Path(root), releases=["26.04"])
            archive.write_bytes(compressed + b"x")
            with self.assertRaisesRegex(ValueError, "cataloged size"):
                mirror.plan(Path(downloads), catalog, Path(root), releases=["26.04"])
            archive.write_bytes(scenario.fake_archive("8.3.98")[:len(compressed)].ljust(len(compressed), b"\0"))
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                mirror.plan(Path(downloads), catalog, Path(root), releases=["26.04"])
        self.assertTrue(result["dry_run"])
        (planned,) = result["archives"]
        self.assertEqual(900000001, planned["inspected"]["asset_id"])
        self.assertIsNone(planned["planned_mirror"]["id"])
        self.assertEqual(row["asset"]["digest"], planned["planned_mirror"]["digest"])
        self.assertTrue(planned["upload_command"].startswith("gh release create php-sha256-"))

    def test_adopt_binds_only_a_published_immutable_release_with_identical_assets(self):
        catalog = bootstrap.load_catalog()
        for unbound in catalog["archives"]:
            unbound["mirror"] = None
        row = catalog["archives"][1]
        tag = mirror.release_tag(row)
        release = {"tag_name": tag, "draft": False, "immutable": True, "assets": [
            {"id": 812345678, "name": row["asset"]["name"], "size": row["asset"]["size"],
             "digest": row["asset"]["digest"], "state": "uploaded"}]}
        adopted = mirror.adopt(catalog, release)
        self.assertEqual({"repository": bootstrap.MIRROR_REPOSITORY, "release_tag": tag, "id": 812345678,
                          **{key: row["asset"][key] for key in ("name", "size", "digest")}},
                         adopted["archives"][1]["mirror"])
        self.assertIsNone(adopted["archives"][0]["mirror"])
        for change in ({"immutable": False}, {"draft": True},
                       {"assets": [dict(release["assets"][0], digest="sha256:" + "0" * 64)]},
                       {"assets": [dict(release["assets"][0], size=1)]}, {"tag_name": "php-sha256-ffffffffffffffff"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                mirror.adopt(catalog, {**release, **change})


if __name__ == "__main__":
    unittest.main()
