"""Finite initial-profile updater handoff; no command executes in this module."""
import os
from pathlib import Path
import shlex
import stat

from scripts import php_linux_archive as archive
from scripts import php_linux_normalize as normalization

INVENTORY_SHA256 = '6dac97b30a2cbd1a2b9d340f44df8ed3dd80b7ad0bc439526d2f39fb78f3af8e'
INVENTORIES = {
    768113262: ('initial', INVENTORY_SHA256),
    768105765: ('ubuntu24', '240fba4596736ec5a5736a7d7ded31b575a85f8fb061565649a09205d36eb3ed'),
}


def inventory_source(original):
    if original is None:
        return normalization.pinned_json(archive.bootstrap.ROOT /
            'qualification/php-linux-initial-alternatives.json', INVENTORY_SHA256), INVENTORY_SHA256
    selected = normalization.profile(original)
    name, digest = INVENTORIES[selected.metadata['asset']['id']]
    record = normalization.pinned_json(
        archive.bootstrap.ROOT / 'qualification' / ('php-linux-' + name + '-alternatives.json'), digest)
    if record['archive_metadata_sha256'] != selected.metadata_sha256:
        raise ValueError('Alternatives inventory differs from its exact archive profile')
    return record, digest


def inventory(original=None):
    return inventory_source(original)[0]


def exclusions():
    # The other eight regular aliases have no writer in fix_alternatives.
    # Exclusion preserves existing host links for the stock updater and avoids
    # deleting an unproven host subject or extracting a raw archive link.
    return tuple(row['path'] for row in inventory()['managed'])


def selection_source():
    # Registration preserves a higher-priority automatic or an existing manual
    # choice. Select only the already registered, held versioned targets before
    # the caller can execute any PHP through the default commands.
    return '\n'.join('  /usr/bin/sudo /usr/bin/update-alternatives --set '
        + shlex.quote(row['group']) + ' ' + shlex.quote('/' + row['target']) + ' || exit "$?"'
        for row in inventory()['managed'])


def verify_edge(group, kind, alias, destination, target):
    try:
        valid = (stat.S_ISLNK(alias.lstat().st_mode) and os.readlink(alias) == str(destination)
                 and alias.resolve() == target.resolve())
    except OSError as error:
        raise ValueError(f'Alternative {group}: {kind} edge could not be bound') from error
    if not valid:
        raise ValueError(f'Alternative {group}: {kind} edge differs from its exact target')


def verify(files, root=Path('/'), *, original=None):
    record, digest = inventory_source(original)
    rows = record['managed']
    for row in rows:
        target = root / row['target']
        if row['target'] not in files:
            raise ValueError(f"Alternative {row['group']}: target has no held regular archive authority")
        try:
            archive.verify_file(target, files[row['target']])
        except (OSError, ValueError) as error:
            raise ValueError(f"Alternative {row['group']}: held target binding refused") from error
        for kind, path, destination in (('alternative', row['path'], target),
                                        ('command', row['command'], root / row['path'])):
            verify_edge(row['group'], kind, root / path, destination, target)
    return {'inventory_sha256': digest, 'count': len(rows)}
