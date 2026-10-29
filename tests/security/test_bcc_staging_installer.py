"""Pinned staging installation accepts data, never archive path capabilities."""
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import tarfile
import types

import pytest


@pytest.fixture
def installer():
    source = (Path(__file__).parents[2] / 'scripts/bcc-staging-installer.py.in').read_text()
    source = source.replace('@@SOURCE@@', repr('/home/yeli/repos/AgentPorter/artifacts/fixture'))
    source = source.replace('@@INPUTS@@', repr({'version': 'fixture'})).replace('@@CREDENTIALS@@', '[]')
    module = types.ModuleType('bcc_stage_installer_fixture')
    exec(compile(source, 'bcc-staging-installer.py.in', 'exec'), module.__dict__)
    return module


def bundle(path, entries):
    with tarfile.open(path, 'w:gz') as archive:
        for member, content in entries:
            archive.addfile(member, io.BytesIO(content) if content is not None else None)


def regular(name, content):
    member = tarfile.TarInfo(name)
    member.size = len(content)
    member.mode = 0o644
    return member, content


def test_manifest_verified_and_release_sealed_without_executing_payload(installer, tmp_path):
    contents = b'raise AssertionError("release code must never execute in installer")\n'
    manifest = {'version': 'fixture', 'files': {'venv/module.py': {
        'sha256': hashlib.sha256(contents).hexdigest()}}}
    archive = tmp_path / 'release.tgz'
    bundle(archive, [regular('venv/module.py', contents),
                     regular('RELEASE.json', json.dumps(manifest).encode())])
    destination = tmp_path / 'installed'
    destination.mkdir()
    installer.extract_release(archive, destination)
    assert (destination / 'venv/module.py').read_bytes() == contents
    assert destination.stat().st_mode & 0o222 == 0
    assert (destination / 'venv/module.py').stat().st_mode & 0o222 == 0


@pytest.mark.parametrize('kind', ['traversal', 'absolute', 'symlink', 'hardlink', 'fifo',
                                 'duplicate', 'oversized', 'symlink_child'])
def test_archive_cannot_escape_or_introduce_special_files(installer, tmp_path, kind):
    if kind == 'traversal':
        entries = [regular('../escaped', b'bad')]
    elif kind == 'absolute':
        entries = [regular('/escaped', b'bad')]
    elif kind == 'duplicate':
        entries = [regular('venv/a', b'one'), regular('venv/a', b'two')]
    elif kind == 'symlink_child':
        member = tarfile.TarInfo('venv/lib64')
        member.type = tarfile.SYMTYPE
        member.linkname = 'lib'
        entries = [(member, None), regular('venv/lib64/escaped', b'bad')]
    else:
        member = tarfile.TarInfo('venv/unsafe')
        if kind == 'symlink':
            member.type = tarfile.SYMTYPE
            member.linkname = '/etc'
        elif kind == 'hardlink':
            member.type = tarfile.LNKTYPE
            member.linkname = '/etc/passwd'
        elif kind == 'fifo':
            member.type = tarfile.FIFOTYPE
        else:
            member.size = 513 * 1024**2
        entries = [(member, None)]
    archive = tmp_path / 'unsafe.tgz'
    if kind == 'oversized':
        # A header alone exercises the size rejection without a 513 MiB fixture.
        with gzip.open(archive, 'wb') as stream:
            stream.write(entries[0][0].tobuf() + b'\0' * 1024)
    else:
        bundle(archive, entries)
    destination = tmp_path / 'destination'
    destination.mkdir()
    with pytest.raises(PermissionError):
        installer.extract_release(archive, destination)
    assert not (tmp_path / 'escaped').exists()


def test_manifest_tamper_is_rejected(installer, tmp_path):
    manifest = {'version': 'fixture', 'files': {'venv/a': {'sha256': '0' * 64}}}
    archive = tmp_path / 'tampered.tgz'
    bundle(archive, [regular('venv/a', b'changed'), regular('RELEASE.json', json.dumps(manifest).encode())])
    destination = tmp_path / 'destination'
    destination.mkdir()
    with pytest.raises(PermissionError, match='manifest mismatch'):
        installer.extract_release(archive, destination)


def test_pinned_copy_mismatch_stays_private(installer, tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.write_bytes(b'synthetic private input')
    monkeypatch.setattr(installer, 'source_fd', lambda path, limit: os.open(path, os.O_RDONLY))
    target = tmp_path / 'private-copy'
    with pytest.raises(PermissionError, match='checksum mismatch'):
        installer.copy_source(source, target, 1024, expected='0' * 64)
    assert target.stat().st_mode & 0o777 == 0o600


def test_source_symlink_is_not_followed(installer, tmp_path):
    target = tmp_path / 'secret'
    target.write_bytes(b'synthetic')
    source = tmp_path / 'link'
    source.symlink_to(target)
    with pytest.raises((PermissionError, OSError)):
        installer.source_fd(source, 1024)
