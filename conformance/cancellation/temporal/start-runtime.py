"""Run the verified published CLI's isolated development server."""

import hashlib
import io
import json
import os
import tarfile
import tempfile
import urllib.request
from pathlib import Path

versions = json.loads(Path('versions.json').read_text())
with urllib.request.urlopen(versions['archive'], timeout=60) as response:
    archive = response.read()
if hashlib.sha256(archive).hexdigest() != versions['sha256']:
    raise RuntimeError('Published Temporal CLI archive checksum mismatch')
with tarfile.open(fileobj=io.BytesIO(archive), mode='r:gz') as bundle:
    binary = bundle.getmember('temporal')
    if not binary.isfile():
        raise RuntimeError('Missing Temporal CLI binary')
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
