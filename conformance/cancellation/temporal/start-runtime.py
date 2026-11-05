"""Run the source-pinned published CLI's isolated development server."""

import hashlib
import io
import json
import os
import tarfile
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

# Runtime authority belongs to reviewed source, never candidate versions.json.
CLI_VERSION = '1.9.1'
SERVER_VERSION = '1.32.0'
ARCHIVE_URL = 'https://github.com/temporalio/cli/releases/download/v1.9.1/temporal_cli_1.9.1_linux_amd64.tar.gz'
ARCHIVE_SHA256 = '09a0326a51db84d02735e53542b9ebd8c4758daf47482a9ab0abce15844e60d5'
ARCHIVE_SIZE = 45298806
# Public asset 564294919's accepted redirect path; signed query values vary.
ASSET_PATH = '/github-production-release-asset/559700601/ae434382-1307-437e-880b-e75792ec3f93'


def expected_versions():
    return {'cli': CLI_VERSION, 'server': SERVER_VERSION,
            'archive': ARCHIVE_URL, 'sha256': ARCHIVE_SHA256}


def accepted_asset_url(url):
    try:
        value = urllib.parse.urlsplit(url)
        return (value.scheme == 'https' and value.hostname == 'release-assets.githubusercontent.com'
                and value.port in (None, 443) and value.username is None and value.password is None
                and value.path == ASSET_PATH and not value.fragment)
    except ValueError:
        return False


class PublishedAssetRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        self.followed = False

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if self.followed or req.full_url != ARCHIVE_URL or not accepted_asset_url(newurl):
            raise RuntimeError('Published Temporal CLI redirect is outside the accepted asset')
        self.followed = True
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def published_archive():
    versions = json.loads(Path('versions.json').read_text())
    if versions != expected_versions():
        raise RuntimeError('Candidate Temporal versions differ from the reviewed runtime policy')
    opener = urllib.request.build_opener(PublishedAssetRedirect())
    with opener.open(ARCHIVE_URL, timeout=60) as response:
        if response.geturl() != ARCHIVE_URL and not accepted_asset_url(response.geturl()):
            raise RuntimeError('Published Temporal CLI final URL is outside the accepted asset')
        archive = response.read(ARCHIVE_SIZE + 1)
    if len(archive) != ARCHIVE_SIZE or hashlib.sha256(archive).hexdigest() != ARCHIVE_SHA256:
        raise RuntimeError('Published Temporal CLI archive checksum mismatch')
    return archive


def main():
    archive = published_archive()
    with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as bundle:
        binary = bundle.getmember('temporal')
        if not binary.isfile() or not 0 < binary.size <= 256 * 1024 * 1024:
            raise RuntimeError('Missing or oversized Temporal CLI binary')
        source = bundle.extractfile(binary)
        if source is None:
            raise RuntimeError('Unreadable Temporal CLI binary')
        # The fixture's tmpfs owns cleanup after exec replaces this process.
        runtime_directory = Path(tempfile.mkdtemp(prefix='temporal-runtime-'))
        executable = runtime_directory / 'temporal'
        executable.write_bytes(source.read())
    executable.chmod(0o755)
    os.execv(str(executable), ['temporal', 'server', 'start-dev', '--ip', '0.0.0.0',
                             '--db-filename', str(runtime_directory / 'temporal.sqlite'),
                             '--log-level', 'error'])


if __name__ == '__main__':
    main()
