"""Finite initial-profile updater handoff; no command executes in this module."""
import os
from pathlib import Path
import stat

from scripts import php_linux_archive as archive
from scripts import php_linux_normalize as normalization

INVENTORY_SHA256 = '108dcf7b7e95ad83154ca6e7832e551a8388be594f3eb59c828f9cb7a6516d26'


def inventory():
    return normalization.pinned_json(
        archive.bootstrap.ROOT / 'qualification/php-linux-initial-alternatives.json', INVENTORY_SHA256)


def exclusions():
    # The other eight regular aliases have no writer in fix_alternatives.
    # Exclusion preserves existing host links for the stock updater and avoids
    # deleting an unproven host subject or extracting a raw archive link.
    return tuple(row['path'] for row in inventory()['managed'])


def verify(files, root=Path('/')):
    rows = inventory()['managed']
    for row in rows:
        target = root / row['target']
        if row['target'] not in files:
            raise ValueError('Alternatives target has no held regular archive authority')
        archive.verify_file(target, files[row['target']])
        for path, destination in ((row['path'], target), (row['command'], root / row['path'])):
            alias = root / path
            if (not stat.S_ISLNK(alias.lstat().st_mode) or os.readlink(alias) != str(destination)
                    or alias.resolve() != target.resolve()):
                raise ValueError('Installed alternatives edge differs from its exact updater target')
    return {'inventory_sha256': INVENTORY_SHA256, 'count': len(rows)}
