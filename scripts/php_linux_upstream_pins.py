#!/usr/bin/env python3
"""Read-only early warning for replaced php-ubuntu pins (issue 358).

`shivammathur/php-ubuntu` replaces `builds` release assets in place; a replaced
asset ID returns 404 and bound setup refuses. The scheduled
`.github/workflows/php-linux-upstream-pins.yml` runs this check so the
catalog can be re-pinned (see qualification/README.md) before consumers break.

It reads the complete asset listing of the pinned release with the
workflow's read-only token. Each archive row must still be published under
its pinned ID with the same name, size and digest. Setup seals the installer
from its committed snapshot, so the installer passes when the pinned ID is
unchanged or `install.sh` still has exactly the same size and digest under a
new ID; any other installer change fails. The report lists every affected
row with the current same-name candidate. The job only fails; it writes
nothing.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import sys
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ""}:
    sys.path.insert(0, str(ROOT))

from scripts import php_linux_bootstrap as bootstrap  # noqa: E402
from scripts.setup_php_linux import HOST_ARCHIVES  # noqa: E402

# The shared authenticated clean-store predecessor (bootstrap-patched-pip).
CA_SHA256 = "50f79f98dac192b20dbf73f35c56f0b0c557ab267ff5199d1117cc1180b70785"
RELEASE_ID = 39619287
RELEASE_URL = f"https://api.github.com/repos/{bootstrap.REPOSITORY}/releases/{RELEASE_ID}"
MAX_PAGES = 30
MAX_RESPONSE = 4 * 1024 * 1024
MAX_TOKEN = 4096
TUPLE = ("os", "release", "arch", "php", "thread_safety", "build")
TIMESTAMP = re.compile(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ")


class NoRedirects(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, target):
        raise ValueError("Upstream metadata redirects are refused")


class ReleaseReader:
    """GET-only reader of the pinned upstream release metadata."""

    def __init__(self, token: str, context, opener_factory=build_opener):
        # Actions GITHUB_TOKEN is a GitHub App installation token. Since the
        # 2026 rollout it is a stateless `ghs_<app id>_<JWT>` of about 520
        # characters whose length varies; older tokens were 40 characters.
        # Bound the length only to keep the header sane, and keep the
        # header-safe character set (base64url and the JWT dots).
        if not re.fullmatch(r"[A-Za-z0-9_.-]{20,%d}" % MAX_TOKEN, token):
            raise ValueError("The read-only workflow token is missing or malformed")
        self._token = token
        self._client = opener_factory(ProxyHandler({}), HTTPSHandler(context=context), NoRedirects())

    def get(self, url: str):
        if url != RELEASE_URL and not re.fullmatch(re.escape(RELEASE_URL) + r"/assets\?per_page=100&page=[1-9]\d?", url):
            raise ValueError("Upstream metadata request outside the pinned release")
        request = Request(url, method="GET", headers={
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "durable-workflow-php-pin-check", "Authorization": f"Bearer {self._token}"})
        with self._client.open(request, timeout=30) as response:
            if response.status != 200:
                raise ValueError(f"Upstream metadata returned HTTP {response.status}")
            raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ValueError("Upstream metadata exceeds its byte bound")
        return json.loads(raw)

    def assets(self) -> list[dict]:
        release = self.get(RELEASE_URL)
        if release.get("id") != RELEASE_ID or release.get("tag_name") != "builds":
            raise ValueError("The pinned upstream release is not the reviewed builds release")
        records = []
        for page in range(1, MAX_PAGES + 1):
            batch = self.get(f"{RELEASE_URL}/assets?per_page=100&page={page}")
            if not isinstance(batch, list):
                raise ValueError("Upstream asset listing is not a list")
            records.extend(batch)
            if len(batch) < 100:
                return records
        raise ValueError("Upstream asset listing exceeds its page bound")


def candidate(record: dict | None) -> dict | None:
    """Only typed identity fields; no upstream free text reaches the report."""
    if record is None:
        return None
    if (type(record.get("id")) is not int or type(record.get("size")) is not int
            or not isinstance(record.get("digest"), str)
            or not re.fullmatch(r"sha256:[a-f0-9]{64}", record["digest"])):
        return {"id": record.get("id") if type(record.get("id")) is int else None, "unverifiable": True}
    updated = record.get("updated_at")
    return {"id": record["id"], "size": record["size"], "digest": record["digest"],
            "updated_at": updated if isinstance(updated, str) and TIMESTAMP.fullmatch(updated) else None}


def same(record: dict | None, identity: dict, *, by_id: bool) -> bool:
    return (record is not None and record.get("name") == identity["name"]
            and record.get("size") == identity["size"] and record.get("digest") == identity["digest"]
            and record.get("state") == "uploaded" and (not by_id or record.get("id") == identity["id"]))


def check(catalog: dict, records: list[dict]) -> dict:
    bootstrap.validate_catalog(catalog)
    if catalog["repository"] != bootstrap.REPOSITORY or catalog["release_id"] != RELEASE_ID:
        raise ValueError("Catalog is not pinned to the reviewed upstream release")
    by_id, by_name = {}, {}
    for record in records:
        if not isinstance(record, dict):
            raise ValueError("Upstream asset record is not an object")
        by_id[record.get("id")] = record
        by_name.setdefault(record.get("name"), []).append(record)
    affected, checked = [], 0
    rows = [("installer", {}, catalog["installer"])] + [
        ("archive", {key: row[key] for key in TUPLE}, row["asset"]) for row in catalog["archives"]]
    for kind, selector, identity in rows:
        checked += 1
        pinned = by_id.get(identity["id"])
        if same(pinned, identity, by_id=True):
            continue
        named = by_name.get(identity["name"], [])
        current = named[0] if len(named) == 1 else None
        if kind == "installer" and same(current, identity, by_id=False):
            # The committed snapshot is the setup input; identical bytes
            # republished under a new ID do not affect setup.
            continue
        status = "missing" if pinned is None else "changed"
        affected.append({"kind": kind, **selector, "pinned": dict(identity), "status": status,
                         "setup_profile": identity["id"] in HOST_ARCHIVES.values(),
                         "same_name_assets": len(named), "candidate": candidate(current)})
    return {"schema": "durable-workflow.php-linux-upstream-pins/v1", "repository": bootstrap.REPOSITORY,
            "release_id": RELEASE_ID, "checked": checked, "listed": len(records), "affected": affected}


def summary_markdown(report: dict) -> str:
    lines = ["PHP setup pins replaced upstream" if report["affected"] else "PHP setup pins unchanged upstream",
             "", f"Checked {report['checked']} pins against {report['listed']} assets of "
             f"{report['repository']} release {report['release_id']}.", ""]
    if report["affected"]:
        lines += ["| Pin | Setup profile | Pinned id | Status | Candidate id | Candidate size | Candidate digest |",
                  "|---|---|---|---|---|---|---|"]
        for row in report["affected"]:
            label = row["pinned"]["name"]
            found = row["candidate"] or {}
            lines.append(f"| `{label}` | {'yes' if row['setup_profile'] else 'no'} | {row['pinned']['id']} | "
                         f"{row['status']} | {found.get('id', '-')} | "
                         f"{found.get('size', '-')} | `{found.get('digest', '-')}` |")
        lines += ["", "Re-pin as described in qualification/README.md (Upstream asset replacement)."]
    return "\n".join(lines) + "\n"


def main() -> int:
    environment = dict(os.environ)
    if environment.get("DW_CI_CA_SHA256") != CA_SHA256:
        raise ValueError("The authenticated shared bootstrap CA predecessor is missing or differs")
    context = bootstrap.explicit_trust(Path(environment.get("SSL_CERT_FILE", "")), CA_SHA256)
    reader = ReleaseReader(environment.get("PINS_TOKEN", ""), context)
    report = check(json.loads(bootstrap.CATALOG.read_text()), reader.assets())
    print(json.dumps(report, indent=2, sort_keys=True))
    with open(environment["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as output:
        output.write(summary_markdown(report))
    return 1 if report["affected"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError) as error:
        print("PHP upstream pin check refused: " + type(error).__name__ + ": " + str(error)[:500], file=sys.stderr)
        raise SystemExit(1)
