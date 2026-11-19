"""Mirrored PHP archives: exact-ID mirror fetch, fail-closed absence and mirror tooling.

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
from urllib.error import HTTPError

from scripts import php_archive_mirror as mirror
from scripts import php_linux_bootstrap as bootstrap
from scripts import protected_policy_data as data
from tests import test_protected_policy_data as scenario

CONTEXT = SimpleNamespace(verify_mode=ssl.CERT_REQUIRED, check_hostname=True)


def mirrored_catalog(payload: bytes, *, mirror_id=900000101):
    catalog = bootstrap.load_catalog()
    row = catalog["archives"][1]
    row["asset"] = {"id": 900000001, "name": row["asset"]["name"], "size": len(payload),
                    "digest": "sha256:" + hashlib.sha256(payload).hexdigest()}
    row["mirror"] = {"repository": bootstrap.MIRROR_REPOSITORY, "release_tag": "php-sha256-0123456789abcdef",
                     "id": mirror_id, **{key: row["asset"][key] for key in ("name", "size", "digest")}}
    return bootstrap.validate_catalog(catalog), row


class Opener:
    def __init__(self, payload=None, final="https://release-assets.githubusercontent.com/closed?sig=x", status=None):
        self.payload, self.final, self.status, self.urls = payload, final, status, []

    def __call__(self, *handlers):
        self.handlers = handlers

        def open_request(request, **_options):
            self.urls.append(request.full_url)
            if self.status is not None:
                raise HTTPError(request.full_url, self.status, "absent", None, None)
            redirects = handlers[-1]
            redirects.redirect_request(request, None, 302, "Found", {}, self.final)
            response = io.BytesIO(self.payload)
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
        self.assertEqual([f"https://api.github.com/repos/{bootstrap.MIRROR_REPOSITORY}/releases/assets/900000101"],
                         opener.urls)

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
                       Opener(payload, final="https://example.com/archive")):
            with self.subTest(final=opener.final), ExitStack() as stack, self.assertRaises(ValueError):
                stack.enter_context(bootstrap.download_held(row["asset"], CONTEXT, opener, catalog=catalog))

    def test_unmirrored_rows_keep_the_exact_upstream_fetch(self):
        catalog = bootstrap.load_catalog()
        row = catalog["archives"][0]
        self.assertIsNone(row["mirror"])
        self.assertEqual((bootstrap.REPOSITORY, row["asset"]), bootstrap.fetch_location(row["asset"], catalog))

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
