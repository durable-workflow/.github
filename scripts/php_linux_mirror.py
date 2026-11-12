#!/usr/bin/env python3
"""Protected uploader for the durable-workflow PHP archive mirror (issue 358).

Only `.github/workflows/mirror-php-linux-archives.yml` runs this, on `main`, in
the protected `php-archive-mirror` environment with `contents: write`. For each
catalog row without a mirror ID it fetches the pinned upstream asset ID through
the shared sealed fetch (explicit CA, closed upstream-only redirects, size and
SHA-256 checked before sealing), uploads those sealed bytes under the
content-addressed name, then reads the asset back by ID: API name/size/digest
and an anonymous download through setup's own mirror-only fetch. It never
deletes or replaces an asset. It prints a row-to-mirror-ID summary for a
separately reviewed catalog PR.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from scripts import php_linux_bootstrap as bootstrap  # noqa: E402

# The shared authenticated clean-store predecessor (bootstrap-patched-pip).
CA_SHA256 = "50f79f98dac192b20dbf73f35c56f0b0c557ab267ff5199d1117cc1180b70785"
WORKFLOW_REF = ("durable-workflow/.github/.github/workflows/mirror-php-linux-archives.yml"
                "@refs/heads/main")
API = f"https://api.github.com/repos/{bootstrap.MIRROR_REPOSITORY}"
UPLOADS = f"https://uploads.github.com/repos/{bootstrap.MIRROR_REPOSITORY}"
# Upload-only source authority. Setup's effective_url never accepts it.
UPSTREAM_ASSET_PATH = re.compile(r"/repos/shivammathur/php-ubuntu/releases/assets/[1-9]\d*")
UPSTREAM_REDIRECT_PREFIX = "/shivammathur/php-ubuntu/"
MAX_METADATA = 1024 * 1024
MAX_PAGES = 10
TUPLE = ("os", "release", "arch", "php", "thread_safety", "build")


def upstream_effective_url(url: str) -> dict:
    return bootstrap.bound_url(url, UPSTREAM_ASSET_PATH, UPSTREAM_REDIRECT_PREFIX)


def upstream_url(identity: dict) -> str:
    return f"https://api.github.com/repos/{bootstrap.REPOSITORY}/releases/assets/{identity['id']}"


@contextmanager
def fetch_upstream(identity: dict, context, opener_factory=build_opener):
    """The pinned upstream ID under the upstream-only authority; no fallback."""
    with bootstrap.fetch_held(upstream_url(identity), identity, context, upstream_effective_url,
                              opener_factory) as held:
        yield held


def admit(environment: dict, head: str) -> str:
    """Same exact original-dispatch admission as the qualification workflows."""
    expected = environment.get("EXPECTED_WORKFLOW_SHA", "")
    if (not re.fullmatch(r"[0-9a-f]{40}", expected) or head != expected
            or environment.get("GITHUB_SHA") != expected
            or environment.get("GITHUB_WORKFLOW_SHA") != expected
            or environment.get("GITHUB_REPOSITORY") != bootstrap.MIRROR_REPOSITORY
            or environment.get("GITHUB_REPOSITORY_ID") != str(bootstrap.MIRROR_REPOSITORY_ID)
            or environment.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or environment.get("GITHUB_REF") != "refs/heads/main"
            or environment.get("GITHUB_WORKFLOW_REF") != WORKFLOW_REF
            or environment.get("GITHUB_RUN_ATTEMPT") != "1"
            or environment.get("RUNNER_ENVIRONMENT") != "github-hosted"):
        raise ValueError("Mirror upload requires the exact protected main workflow dispatch")
    return expected


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, target):
        raise ValueError("Mirror API redirects are refused")


class MirrorApi:
    """Authenticated writes/reads of exactly the mirror repository's release API."""

    def __init__(self, token: str, context, opener_factory=build_opener):
        if not re.fullmatch(r"[A-Za-z0-9_.-]{20,255}", token):
            raise ValueError("The mirror write credential is missing or malformed")
        self._token = token
        self._client = opener_factory(ProxyHandler({}), HTTPSHandler(context=context), NoRedirects())

    def request(self, method: str, url: str, body: bytes | None = None,
                content_type: str = "application/json", expected: int = 200):
        if not (url.startswith(API + "/releases") or url.startswith(UPLOADS + "/releases/")):
            raise ValueError("Mirror API request outside the mirror repository releases")
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "durable-workflow-php-mirror",
                   "Authorization": f"Bearer {self._token}"}
        if body is not None:
            headers["Content-Type"] = content_type
        request = Request(url, data=body, method=method, headers=headers)
        with self._client.open(request, timeout=60) as response:
            if response.status != expected:
                raise ValueError(f"Mirror API {method} returned HTTP {response.status}")
            raw = response.read(MAX_METADATA + 1)
        if len(raw) > MAX_METADATA:
            raise ValueError("Mirror API response exceeds its byte bound")
        return json.loads(raw)

    def release(self, commit: str) -> dict:
        if bootstrap.MIRROR_RELEASE_ID is not None:
            release = self.request("GET", f"{API}/releases/{bootstrap.MIRROR_RELEASE_ID}")
        else:
            try:
                release = self.request("GET", f"{API}/releases/tags/{bootstrap.MIRROR_RELEASE_TAG}")
            except HTTPError as error:
                if error.code != 404:
                    raise
                body = json.dumps({
                    "tag_name": bootstrap.MIRROR_RELEASE_TAG, "target_commitish": commit,
                    "name": "Verified Linux PHP archives",
                    "body": ("Content-addressed copies of the reviewed php-ubuntu archives in "
                             "qualification/php-linux-bootstrap.json (issue 358). Assets are "
                             "never replaced or deleted; setup verifies size and SHA-256."),
                    "draft": False, "prerelease": False, "make_latest": "false",
                }).encode()
                release = self.request("POST", f"{API}/releases", body, expected=201)
        if (type(release.get("id")) is not int or release.get("tag_name") != bootstrap.MIRROR_RELEASE_TAG
                or release.get("draft") is not False
                or bootstrap.MIRROR_RELEASE_ID not in (None, release["id"])):
            raise ValueError("The mirror release is not the reviewed published release")
        return release

    def assets(self, release_id: int) -> dict[str, dict]:
        named: dict[str, dict] = {}
        for page in range(1, MAX_PAGES + 1):
            records = self.request("GET", f"{API}/releases/{release_id}/assets?per_page=100&page={page}")
            if not isinstance(records, list):
                raise ValueError("Mirror release asset listing is not a list")
            for record in records:
                if record.get("name") in named:
                    raise ValueError("Mirror release lists one asset name twice")
                named[record.get("name")] = record
            if len(records) < 100:
                return named
        raise ValueError("Mirror release asset listing exceeds its page bound")

    def upload(self, release_id: int, name: str, contents: bytes) -> dict:
        url = f"{UPLOADS}/releases/{release_id}/assets?name={quote(name, safe='')}"
        return self.request("POST", url, contents, "application/octet-stream", expected=201)

    def asset(self, asset_id: int) -> dict:
        return self.request("GET", f"{API}/releases/assets/{asset_id}")


def require_asset(record: dict, identity: dict) -> int:
    """The API record is exactly the content-addressed copy of the pinned bytes."""
    name = bootstrap.mirror_name(identity)
    if (type(record.get("id")) is not int or record["id"] < 1 or record.get("name") != name
            or record.get("size") != identity["size"] or record.get("state") != "uploaded"
            or record.get("digest") != identity["digest"]):
        raise ValueError(f"Mirror asset {name} differs from its pinned upstream bytes")
    return record["id"]


def read_back(api: MirrorApi, row: dict, asset_id: int, context, fetch_mirror) -> dict:
    record = api.asset(asset_id)
    require_asset(record, row["asset"])
    expected_url = (f"https://github.com/{bootstrap.MIRROR_REPOSITORY}/releases/download/"
                    f"{bootstrap.MIRROR_RELEASE_TAG}/{quote(record['name'], safe='')}")
    if record.get("browser_download_url") not in (expected_url, expected_url.replace("%2B", "+")):
        raise ValueError("Mirror asset is not in the reviewed release")
    mirrored = dict(row, mirror={"id": asset_id})
    # Setup's own anonymous mirror-only fetch, with size/SHA-256 before sealing.
    with fetch_mirror(mirrored, context) as held:
        held.assert_sealed()
        effective = held.effective
    return {"id": asset_id, "name": record["name"], "effective_host": effective["host"]}


def mirror(catalog: dict, api: MirrorApi, context, commit: str,
           fetch_source=fetch_upstream, fetch_mirror=bootstrap.download_held) -> dict:
    bootstrap.validate_catalog(catalog)
    release = api.release(commit)
    assets = api.assets(release["id"])
    rows = []
    for row in catalog["archives"]:
        identity = row["asset"]
        name = bootstrap.mirror_name(identity)
        existing = assets.get(name)
        if "mirror" in row:
            # Recorded rows are only verified. A missing or changed recorded
            # asset is an incident for review, never a silent re-upload.
            if existing is None or existing.get("id") != row["mirror"]["id"]:
                raise ValueError(f"Recorded mirror asset {name} is missing from the release")
            action, asset_id = "verified", row["mirror"]["id"]
        elif existing is not None:
            # A previous partial run already uploaded it; refuse other bytes.
            action, asset_id = "existing", require_asset(existing, identity)
        else:
            with fetch_source(identity, context) as held:
                held.assert_sealed()
                contents = os.pread(held.descriptor, identity["size"], 0)
                if len(contents) != identity["size"] or "sha256:" + bootstrap.sha256(contents) != identity["digest"]:
                    raise ValueError("Sealed upstream bytes changed before upload")
                uploaded = api.upload(release["id"], name, contents)
            if uploaded.get("name") != name or uploaded.get("size") != identity["size"]:
                raise ValueError(f"Mirror upload of {name} was renamed or truncated")
            action, asset_id = "uploaded", uploaded.get("id")
            if type(asset_id) is not int or asset_id < 1:
                raise ValueError("Mirror upload returned no asset ID")
        result = read_back(api, row, asset_id, context, fetch_mirror)
        rows.append({**{key: row[key] for key in TUPLE}, "upstream_id": identity["id"],
                     "action": action, "mirror": {"id": result["id"]}, "name": result["name"]})
    return {"schema": "durable-workflow.php-linux-mirror/v1",
            "repository": bootstrap.MIRROR_REPOSITORY, "release_id": release["id"],
            "release_tag": release["tag_name"], "workflow_sha": commit, "archives": rows}


def main() -> int:
    environment = dict(os.environ)
    head = subprocess.run(["/usr/bin/git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
                          stdout=subprocess.PIPE, text=True, timeout=10).stdout.strip()
    commit = admit(environment, head)
    if environment.get("DW_CI_CA_SHA256") != CA_SHA256:
        raise ValueError("The authenticated shared bootstrap CA predecessor is missing or differs")
    context = bootstrap.explicit_trust(Path(environment.get("SSL_CERT_FILE", "")), CA_SHA256)
    api = MirrorApi(environment.get("MIRROR_TOKEN", ""), context)
    catalog = json.loads(bootstrap.CATALOG.read_text())
    summary = json.dumps(mirror(catalog, api, context, commit), indent=2, sort_keys=True)
    print(summary)
    with open(environment["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
        output.write("PHP archive mirror\n\n```json\n" + summary + "\n```\n")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, HTTPError, subprocess.SubprocessError) as error:
        # Never echo request headers; the error text carries no credential.
        print("PHP archive mirror refused: " + type(error).__name__ + ": " + str(error)[:500], file=sys.stderr)
        raise SystemExit(1)
