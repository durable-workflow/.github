"""Finite regular-only derivation; no installation or archive-subject execution."""
from contextlib import contextmanager, ExitStack
import copy
from dataclasses import dataclass
import fcntl
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import subprocess
import tarfile
import time

from scripts import php_linux_archive as archive
from scripts import php_linux_bootstrap as bootstrap

METADATA_SHA256 = '038fe8c777dda939ba3f2d6c12f6977ca9dd09c65de7d62fe734c60e71135d0a'
PLAN_SHA256 = 'd02b0008c58c94e52688d9d7154a806c2a172d9e5f67241274c17341aae2c76d'
SCHEMA = 'durable-workflow.php-linux-normalization/v1'
DOCUMENT_SCHEMA = 'durable-workflow.php-linux-normalized-subjects/v1'
MANIFEST_NAME = 'normalization.json'
MAX_MANIFEST = 2 * 1024**2
MAX_STAGED = archive.MAX_UNPACKED
DURATION = 120
# Materialized library aliases can repeat targets farther apart than the
# default window. Match the held input's observed 128 MiB window without a
# worker buffer or any increase to the output, staging or process bounds.
COMPRESSOR_ARGS = ('--compress', '--stdout', '--quiet', '--single-thread', '--long=27')


@dataclass(frozen=True)
class Profile:
    metadata: dict
    plan: dict
    metadata_sha256: str
    plan_sha256: str


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def pinned_json(path, digest):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_mode & 0o022
                or info.st_uid not in (0, os.getuid()) or not 0 < info.st_size <= 1024**2):
            raise ValueError('Normalization source record is not a bound regular file')
        raw = os.read(descriptor, info.st_size + 1)
        if len(raw) != info.st_size or bootstrap.sha256(raw) != digest:
            raise ValueError('Normalization source record differs from its reviewed bytes')
        return json.loads(raw)
    finally:
        os.close(descriptor)


def profile():
    metadata = pinned_json(bootstrap.ROOT / 'qualification/php-linux-initial-archive.json', METADATA_SHA256)
    plan = pinned_json(bootstrap.ROOT / 'qualification/php-linux-initial-normalization.json', PLAN_SHA256)
    if (metadata['schema'] != 'durable-workflow.php-linux-archive-metadata/v1'
            or plan['schema'] != 'durable-workflow.php-linux-normalization-proposal/v1'
            or plan['metadata_sha256'] != METADATA_SHA256 or plan['asset'] != metadata['asset']
            or plan['expected_members'] != 3887 or plan['expected_regular_files'] != 3497
            or plan['expected_directories'] != 390 or plan['expected_links'] != 0):
        raise ValueError('No exact reviewed normalization profile')
    return Profile(metadata, plan, METADATA_SHA256, PLAN_SHA256)


def remaining(deadline):
    duration = deadline - time.monotonic()
    if duration <= 0:
        raise ValueError('Normalization deadline exhausted')
    return min(duration, 60)


@contextmanager
def memory_file(name):
    descriptor = os.memfd_create(name, os.MFD_ALLOW_SEALING | os.MFD_CLOEXEC)
    try:
        yield descriptor
    finally:
        os.close(descriptor)


def write_all(descriptor, data):
    view = memoryview(data)
    while view:
        count = os.write(descriptor, view)
        if count <= 0:
            raise ValueError('Normalization output made no write progress')
        view = view[count:]


@contextmanager
def codec(arguments, source, maximum, deadline):
    """Run one stock codec with bounded stdout and retained failure diagnostics."""
    with memory_file('php-normalization-codec') as output, memory_file('php-normalization-diagnostic') as diagnostic:
        child = None
        size, digest = 0, hashlib.sha256()
        try:
            os.lseek(source, 0, os.SEEK_SET)
            child = subprocess.Popen(['/usr/bin/zstd', *arguments], stdin=source,
                stdout=subprocess.PIPE, stderr=diagnostic, env={'PATH': '/usr/bin:/bin', 'LC_ALL': 'C'})
            with io.BufferedReader(archive.BoundedPipe(child.stdout, maximum, remaining(deadline))) as stream:
                while chunk := stream.read(65536):
                    write_all(output, chunk)
                    size += len(chunk)
                    digest.update(chunk)
            status = child.wait(timeout=min(5, remaining(deadline)))
            message = os.pread(diagnostic, 65537, 0)
            if status != 0 or len(message) > 65536:
                raise ValueError('Normalization codec refused: ' + message[:4096].decode(errors='replace'))
            fcntl.fcntl(output, fcntl.F_ADD_SEALS, bootstrap.SEALS)
            os.lseek(output, 0, os.SEEK_SET)
            yield output, size, digest.hexdigest()
        finally:
            if child is not None:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                child.stdout.close()


class DescriptorReader(io.RawIOBase):
    def __init__(self, descriptor, offset, size, deadline):
        self.descriptor, self.offset, self.size, self.deadline = descriptor, offset, size, deadline

    def readable(self):
        return True

    def readinto(self, buffer):
        remaining(self.deadline)
        data = os.pread(self.descriptor, min(len(buffer), self.size), self.offset)
        if not data and self.size:
            raise ValueError('Normalization source member is truncated')
        self.offset += len(data)
        self.size -= len(data)
        buffer[:len(data)] = data
        return len(data)


class DescriptorWriter(io.RawIOBase):
    def __init__(self, descriptor, maximum, deadline):
        self.descriptor, self.maximum, self.deadline, self.size = descriptor, maximum, deadline, 0

    def write(self, data):
        remaining(self.deadline)
        if self.size + len(data) > self.maximum:
            raise ValueError('Normalization aggregate staging bound exceeded')
        write_all(self.descriptor, data)
        self.size += len(data)
        return len(data)

    def writable(self):
        return True


def header_row(member):
    return [member.name, member.type.decode('ascii'), member.linkname, member.size,
            member.offset, member.offset_data]


def index_member(member, index, parents):
    if member.pax_headers or member.issparse() or member.type not in (tarfile.REGTYPE, tarfile.DIRTYPE, tarfile.SYMTYPE):
        raise ValueError('Normalization refuses PAX/sparse/special members')
    name = archive.canonical_member(member)
    ancestors = {p.as_posix() for p in PurePosixPath(name).parents if p.as_posix() != '.'}
    if (name in index or any(index[p].type != tarfile.DIRTYPE for p in ancestors if p in index)
            or (member.type != tarfile.DIRTYPE and name in parents)):
        raise ValueError('Normalization member/parent/type collision')
    index[name] = copy.copy(member)
    parents.update(ancestors)
    if len(index) + len(parents) > archive.MAX_MEMBERS:
        raise ValueError('Normalization explicit/implicit member bound exceeded')
    return name


def index_original(descriptor, size, metadata, deadline):
    expected = metadata['members']
    if metadata['columns'] != ['name', 'type', 'linkname', 'size', 'offset', 'offset_data']:
        raise ValueError('Normalization metadata columns differ')
    index, hashes, parents = {}, {}, set()
    with io.BufferedReader(DescriptorReader(descriptor, 0, size, deadline)) as reader, \
            tarfile.open(fileobj=reader, mode='r|') as source:
        count = 0
        for count, member in enumerate(source, 1):
            if count > archive.MAX_MEMBERS or count > len(expected) or header_row(member) != expected[count - 1]:
                raise ValueError('Original archive metadata differs from its frozen record')
            name = index_member(member, index, parents)
            if member.type == tarfile.REGTYPE:
                hashes[name] = archive.member_identity(source.extractfile(member), member.size)
        if count != len(expected) or count != metadata['member_count']:
            raise ValueError('Original archive has missing recorded members')
    return index, hashes


def resolve(index, name, seen=()):
    if name not in index:
        return 'unresolved', name
    member = index[name]
    if member.type != tarfile.SYMTYPE:
        return ('regular' if member.type == tarfile.REGTYPE else 'directory'), name
    if name in seen or len(seen) >= 128:
        raise ValueError('Normalization link cycle/depth refused')
    value = member.linkname
    target = posixpath.normpath(value.lstrip('/') if value.startswith('/')
        else posixpath.join(posixpath.dirname(name), value))
    if target == '..' or target.startswith('../'):
        raise ValueError('Normalization link escape refused')
    return resolve(index, target, (*seen, name))


def checked_plan(index, plan):
    aliases, omitted = plan['materialize_regular_aliases'], plan['omit_aliases']
    names = [name for name, *_ in aliases + omitted]
    links = {name for name, member in index.items() if member.type == tarfile.SYMTYPE}
    if len(names) != len(set(names)) or set(names) != links:
        raise ValueError('Normalization has an unlisted or duplicate link treatment')
    for name, target in aliases:
        if resolve(index, name) != ('regular', target):
            raise ValueError('Normalization target is not the exact contained regular member')
    for name, kind, target in omitted:
        if kind not in ('directory', 'unresolved') or resolve(index, name) != (kind, target):
            raise ValueError('Normalization omission differs from its exact approved target')
    return dict(aliases), {name for name, *_ in omitted}


def build_regular_tar(source, output, source_size, index, hashes, aliases, omitted, plan, deadline):
    expected = dict(hashes)
    expected.update({name: hashes[target] for name, target in aliases.items()})
    writer = DescriptorWriter(output, MAX_STAGED - source_size, deadline)
    directories, targets = 0, {}
    with io.BufferedWriter(writer) as buffered, \
            tarfile.open(fileobj=buffered, mode='w|', format=tarfile.GNU_FORMAT) as destination:
        for name, original in index.items():
            if name in omitted:
                continue
            target = aliases.get(name, name)
            info = copy.copy(index[target])
            info.name = name or '.'
            info.linkname, info.pax_headers = '', {}
            if original.type == tarfile.SYMTYPE:
                info.type = tarfile.REGTYPE
                target_metadata = {key: value.decode('ascii') if isinstance(value, bytes) else value
                                   for key, value in index[target].get_info().items()}
                targets[name] = {'target': target, **hashes[target], 'metadata': target_metadata}
            if info.type == tarfile.DIRTYPE:
                destination.addfile(info)
                directories += 1
            else:
                with io.BufferedReader(DescriptorReader(source, index[target].offset_data, info.size, deadline)) as member:
                    destination.addfile(info, member)
    if (len(expected) != plan['expected_regular_files'] or directories != plan['expected_directories']
            or len(expected) + directories != plan['expected_members'] or plan['expected_links'] != 0):
        raise ValueError('Derived archive member counts differ from the reviewed plan')
    fcntl.fcntl(output, fcntl.F_ADD_SEALS, bootstrap.SEALS)
    return expected, targets


class CountedArchive:
    def __init__(self, source):
        self.source, self.counts = source, {'files': 0, 'directories': 0, 'members': 0}

    def __iter__(self):
        for member in self.source:
            self.counts['members'] += 1
            key = 'directories' if member.isdir() else 'files'
            self.counts[key] += 1
            yield member

    def extractfile(self, member):
        return self.source.extractfile(member)


def strict_manifest(descriptor, size, expected, plan, deadline):
    with io.BufferedReader(DescriptorReader(descriptor, 0, size, deadline)) as reader, \
            tarfile.open(fileobj=reader, mode='r|') as source:
        counted = CountedArchive(source)
        actual = archive.inventory_members(counted)
        if actual != expected or counted.counts != {'files': plan['expected_regular_files'],
                'directories': plan['expected_directories'], 'members': plan['expected_members']}:
            raise ValueError('Complete derived strict inventory differs')


@dataclass(frozen=True)
class NormalizedInput:
    original: bootstrap.HeldAsset
    held: bootstrap.HeldAsset
    files: dict
    targets: dict
    proof_bytes: bytes

    @property
    def proof(self):
        return json.loads(self.proof_bytes)

    def assert_sealed(self):
        self.original.assert_sealed()
        self.held.assert_sealed()
        proof = self.proof
        if (proof['original'] != self.original.identity or proof['derived'] != self.held.identity
                or proof['file_manifest_sha256'] != bootstrap.sha256(canonical_json(self.files))
                or proof['target_manifest_sha256'] != bootstrap.sha256(canonical_json(self.targets))):
            raise ValueError('Normalization provenance or subject manifest changed')

    def assert_valid(self):
        self.assert_sealed()
        validate_document({'schema': DOCUMENT_SCHEMA, 'proof': self.proof,
            'files': self.files, 'targets': self.targets}, self.proof, self.original.identity)


def document(result):
    result.assert_valid()
    return {'schema': DOCUMENT_SCHEMA, 'proof': result.proof, 'files': result.files, 'targets': result.targets}


def stamp(metadata, raw):
    return {'device': metadata.st_dev, 'inode': metadata.st_ino, 'mode': stat.S_IMODE(metadata.st_mode),
        'owner': metadata.st_uid, 'links': metadata.st_nlink, 'size': metadata.st_size,
        'mtime_ns': metadata.st_mtime_ns, 'ctime_ns': metadata.st_ctime_ns,
        'sha256': bootstrap.sha256(raw)}


def write_manifest(state, result):
    """Capture the archive-derived document before any installer/PHP effect."""
    return write_document(state, MANIFEST_NAME, document(result), MAX_MANIFEST)


def document_parameters(name, limit):
    if (not isinstance(name, str) or re.fullmatch(r'[a-z][a-z0-9_-]*\.json', name) is None
            or type(limit) is not int or not 0 < limit <= MAX_MANIFEST):
        raise ValueError('Invalid bounded producer document name or limit')


def write_document(state, name, value, limit):
    document_parameters(name, limit)
    raw = canonical_json(value) + b'\n'
    if not 0 < len(raw) <= limit:
        raise ValueError('Normalization manifest exceeds its fixed bound')
    parent = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    descriptor, created, complete = None, False, False
    try:
        directory = os.fstat(parent)
        if directory.st_uid != os.getuid() or stat.S_IMODE(directory.st_mode) != 0o700:
            raise ValueError('Normalization manifest requires the exact private setup state')
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        created = True
        write_all(descriptor, raw)
        os.fsync(descriptor)
        os.fchmod(descriptor, 0o400)
        metadata = os.fstat(descriptor)
        if metadata.st_size != len(raw) or os.pread(descriptor, len(raw) + 1, 0) != raw:
            raise ValueError('Normalization manifest changed during its producer write')
        observed = os.stat(state, follow_symlinks=False)
        if (observed.st_dev, observed.st_ino) != (directory.st_dev, directory.st_ino):
            raise ValueError('Normalization state changed during the producer handoff')
        complete = True
        return {'name': name, 'object': stamp(metadata, raw)}
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if created and not complete:
            os.unlink(name, dir_fd=parent)
        os.close(parent)


def manifest_metadata(metadata):
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o400 or metadata.st_nlink != 1
            or not 0 < metadata.st_size <= MAX_MANIFEST):
        raise ValueError('Normalization manifest type/ownership/size differs')


def validate_stamp(value):
    fields = {'device', 'inode', 'mode', 'owner', 'links', 'size', 'mtime_ns', 'ctime_ns', 'sha256'}
    bootstrap.exact_keys(value, fields)
    if (any(type(value[key]) is not int or value[key] < 0 for key in fields - {'sha256'})
            or value['owner'] != os.getuid() or value['mode'] != 0o400 or value['links'] != 1
            or not 0 < value['size'] <= MAX_MANIFEST or not isinstance(value['sha256'], str)
            or not re.fullmatch(r'[a-f0-9]{64}', value['sha256'])):
        raise ValueError('Normalization producer object identity is invalid')


@contextmanager
def capture_manifest(state, record):
    with capture_document(state, record, MANIFEST_NAME, MAX_MANIFEST) as captured:
        yield captured


@contextmanager
def capture_document(state, record, name, limit):
    document_parameters(name, limit)
    bootstrap.exact_keys(record, {'name', 'object'})
    if record['name'] != name:
        raise ValueError('Only the exact producer normalization manifest is supported')
    validate_stamp(record['object'])
    path = state / name
    parent = os.open(state, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    descriptor = None
    try:
        directory = os.fstat(parent)
        if directory.st_uid != os.getuid() or stat.S_IMODE(directory.st_mode) != 0o700:
            raise ValueError('Normalization manifest parent is not the private setup root')
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        metadata = os.fstat(descriptor)
        manifest_metadata(metadata)
        raw = os.read(descriptor, limit + 1)
        original = stamp(metadata, raw)
        if len(raw) > limit or len(raw) != metadata.st_size or record['object'] != original:
            raise ValueError('Normalization manifest differs from its pre-install producer identity')
        def unchanged():
            current = os.fstat(descriptor)
            located = os.stat(path, follow_symlinks=False)
            current_parent = os.stat(state, follow_symlinks=False)
            manifest_metadata(current)
            manifest_metadata(located)
            contents = os.pread(descriptor, limit + 1, 0)
            if ((current_parent.st_dev, current_parent.st_ino, current_parent.st_mode, current_parent.st_uid)
                    != (directory.st_dev, directory.st_ino, directory.st_mode, directory.st_uid)
                    or stamp(current, contents) != original or stamp(located, contents) != original or contents != raw):
                raise ValueError('Normalization manifest object/bytes changed')
        unchanged()
        value = json.loads(raw)
        if raw != canonical_json(value) + b'\n':
            raise ValueError('Normalization manifest is not the exact canonical producer document')
        identity = {'size': len(raw), 'digest': bootstrap.SHA256_PREFIX + bootstrap.sha256(raw)}
        with bootstrap.hold_bytes(io.BytesIO(raw), identity, original) as sealed:
            yield value, sealed, unchanged
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent)


def validate_document(value, proof, original):
    selected = profile()
    bootstrap.exact_keys(value, {'schema', 'proof', 'files', 'targets'})
    if value['schema'] != DOCUMENT_SCHEMA or value['proof'] != proof:
        raise ValueError('Normalization document differs from its producer proof')
    validate_proof(proof, original, selected)
    files, targets = value['files'], value['targets']
    expected_files, aliases = expected_subjects(selected)
    if (not isinstance(files, dict) or set(files) != set(expected_files)
            or not isinstance(targets, dict) or set(targets) != set(aliases)):
        raise ValueError('Normalization document has missing or foreign subjects')
    validate_files(files, expected_files)
    validate_targets(targets, aliases, files)
    if (proof['file_manifest_sha256'] != bootstrap.sha256(canonical_json(files))
            or proof['target_manifest_sha256'] != bootstrap.sha256(canonical_json(targets))):
        raise ValueError('Normalization content/target manifest hash differs')
    return value


def validate_proof(proof, original, selected):
    expected_asset = {key: selected.metadata['asset'][key] for key in ('id', 'name', 'size')}
    expected_asset['digest'] = bootstrap.SHA256_PREFIX + selected.metadata['asset']['sha256']
    expected_keys = {'schema', 'original', 'derived', 'metadata_sha256', 'plan_sha256',
        'file_manifest_sha256', 'target_manifest_sha256', 'regular_files', 'directories',
        'members', 'materialized', 'omitted'}
    bootstrap.exact_keys(proof, expected_keys)
    if (proof['schema'] != SCHEMA or proof['original'] != expected_asset or original != expected_asset
            or proof['metadata_sha256'] != selected.metadata_sha256 or proof['plan_sha256'] != selected.plan_sha256):
        raise ValueError('Normalization original/source authority differs')
    bootstrap.exact_keys(proof['derived'], {'name', 'size', 'digest'})
    if (proof['derived']['name'] != 'php-initial-regular-only.tar.zst'
            or type(proof['derived']['size']) is not int or not 0 < proof['derived']['size'] <= bootstrap.MAX_ARCHIVE
            or not isinstance(proof['derived']['digest'], str)
            or not re.fullmatch(r'sha256:[a-f0-9]{64}', proof['derived']['digest'])):
        raise ValueError('Normalization derived identity is invalid')
    plan = selected.plan
    expected_counts = {'regular_files': plan['expected_regular_files'], 'directories': plan['expected_directories'],
        'members': plan['expected_members'], 'materialized': len(plan['materialize_regular_aliases']),
        'omitted': len(plan['omit_aliases'])}
    if any(type(proof[key]) is not int or proof[key] != expected for key, expected in expected_counts.items()):
        raise ValueError('Normalization complete member counts differ')


def expected_subjects(selected):
    rows = [dict(zip(selected.metadata['columns'], row)) for row in selected.metadata['members']]
    raw_files = {row['name'].removeprefix('./'): row['size'] for row in rows if row['type'] == '0'}
    aliases = dict(selected.plan['materialize_regular_aliases'])
    expected_files = dict(raw_files)
    expected_files.update({name: raw_files[target] for name, target in aliases.items()})
    return expected_files, aliases


def validate_files(files, expected_files):
    for name, expected_size in expected_files.items():
        identity = files[name]
        bootstrap.exact_keys(identity, {'size', 'sha256'})
        if (type(identity['size']) is not int or identity['size'] != expected_size
                or not isinstance(identity['sha256'], str)
                or not re.fullmatch(r'[a-f0-9]{64}', identity['sha256'])):
            raise ValueError('Normalization subject identity differs')


def validate_targets(targets, aliases, files):
    for name, target in aliases.items():
        entry = targets[name]
        bootstrap.exact_keys(entry, {'target', 'size', 'sha256', 'metadata'})
        if (entry['target'] != target or files[name] != files[target] or type(entry['size']) is not int
                or entry['size'] != files[target]['size'] or entry['sha256'] != files[target]['sha256']):
            raise ValueError('Normalization alias lacks exact contained-target authority')
        validate_target_metadata(entry['metadata'], target, entry['size'])


def validate_target_metadata(info, target, size):
    bootstrap.exact_keys(info, {'name', 'mode', 'uid', 'gid', 'size', 'mtime',
        'chksum', 'type', 'linkname', 'uname', 'gname', 'devmajor', 'devminor'})
    if (info['name'] != './' + target or info['type'] != '0' or info['linkname'] != '' or info['size'] != size
            or any(type(info[key]) is not int for key in ('mode', 'uid', 'gid', 'size', 'mtime', 'chksum', 'devmajor', 'devminor'))
            or any(not isinstance(info[key], str) or len(info[key]) > 256 for key in ('uname', 'gname'))):
        raise ValueError('Normalization target metadata is incomplete or foreign')


@contextmanager
def normalize(held):
    """Derive only the fixed asset; the caller may not supply a map or path."""
    selected = profile()
    metadata, plan = selected.metadata, selected.plan
    asset = metadata['asset']
    expected_input = {key: asset[key] for key in ('id', 'name', 'size')}
    expected_input['digest'] = bootstrap.SHA256_PREFIX + asset['sha256']
    held.assert_sealed()
    if held.identity != expected_input:
        raise ValueError('Normalization requires the exact independently bound original asset')
    deadline = time.monotonic() + DURATION
    with ExitStack() as output:
        with memory_file('php-normalization-tar') as regular:
            with codec(['--decompress', '--stdout', '--quiet'], held.descriptor, MAX_STAGED, deadline) as decoded:
                original, original_size, _ = decoded
                index, hashes = index_original(original, original_size, metadata, deadline)
                aliases, omitted = checked_plan(index, plan)
                files, targets = build_regular_tar(original, regular, original_size, index, hashes,
                    aliases, omitted, plan, deadline)
            with codec(COMPRESSOR_ARGS, regular, bootstrap.MAX_ARCHIVE, deadline) as encoded:
                compressed, size, digest = encoded
                identity = {'name': 'php-initial-regular-only.tar.zst', 'size': size, 'digest': bootstrap.SHA256_PREFIX + digest}
                with io.BufferedReader(DescriptorReader(compressed, 0, size, deadline)) as reader:
                    derived = output.enter_context(bootstrap.hold_bytes(reader, identity, {'kind': SCHEMA}))
                with codec(['--decompress', '--stdout', '--quiet'], derived.descriptor,
                        MAX_STAGED - os.fstat(regular).st_size, deadline) as decoded_again:
                    strict_manifest(decoded_again[0], decoded_again[1], files, plan, deadline)
        held.assert_sealed()
        derived.assert_sealed()
        proof = {'schema': SCHEMA, 'original': dict(held.identity), 'derived': dict(derived.identity),
            'metadata_sha256': selected.metadata_sha256, 'plan_sha256': selected.plan_sha256,
            'file_manifest_sha256': bootstrap.sha256(canonical_json(files)),
            'target_manifest_sha256': bootstrap.sha256(canonical_json(targets)),
            'regular_files': len(files), 'directories': plan['expected_directories'],
            'members': plan['expected_members'], 'materialized': len(aliases), 'omitted': len(omitted)}
        result = NormalizedInput(held, derived, files, targets, canonical_json(proof))
        result.assert_valid()
        yield result
