"""Inert exact v1 subject writer/bound from accepted153f409e.

Source file SHA256: 03dceca98a382991443c5414b50c5304494c7dc34ea185b9e1c8b859a13461ce
Only these two unchanged functions and their constants/imports are loaded.
No archive, installed file, PHP or subprocess is accessed.
"""
import json
from scripts import php_linux_bootstrap as bootstrap
MAX_SUBJECT_BYTES = 48 * 1024

def subject_record(name, expected, php, configuration, normalization_targets):
    authority = ({"kind": "derived-redis", "member": name}
                 if name == f"etc/php/{php}/mods-available/redis.ini"
                 else {"kind": "archive", "member": name})
    if configuration is not None and name in configuration['outputs']:
        authority = {'kind': 'derived-cli-configuration', 'member': name,
                     'recipe': configuration['schema']}
    elif normalization_targets is not None and name in normalization_targets:
        origin = normalization_targets[name]
        if expected != {key: origin[key] for key in ('size', 'sha256')}:
            raise ValueError('Normalized subject differs from its original contained target')
        authority = {'kind': 'normalized-archive', 'member': name,
            'source_member': origin['target'], 'target_size': origin['size'],
            'target_sha256': origin['sha256'],
            'target_metadata_sha256': bootstrap.sha256(json.dumps(origin['metadata'], sort_keys=True,
                separators=(',', ':')).encode())}
    return {"type": "regular", **expected, "authority": authority}


def require_subject_bound(manifest):
    if len(manifest["files"]) > 256 or len(json.dumps(manifest, sort_keys=True).encode()) > MAX_SUBJECT_BYTES:
        raise ValueError("Installed subject manifest exceeds the bounded profile")
