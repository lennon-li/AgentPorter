"""Synthetic durable receipt publication; no real network, policy or dataset writes."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import stat
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest

from agentporter import https_download as acquisition


DIRECTORY = 'data-raw/cran-history/reports/2026-10-21-authorized-acquisition/downloads'
URL = 'https://packagemanager.posit.co/cran/2021-06-30/src/contrib/PACKAGES.gz'
BODY = b'\x1f\x8b\x00\xff-synthetic-historical-index'
SHA = hashlib.sha256(BODY).hexdigest()
TIME = '2026-10-21T23:15:16.123456+00:00'


def worker_receipt(expected=None):
    return {'http_status': 200, 'bytes': len(BODY), 'sha256': SHA,
            'expected_sha256_verified': expected is not None,
            'headers': {'content-type': 'application/x-gzip'}, 'retrieved_at': TIME}


def durable_receipt(name='PACKAGES.gz', expected=None):
    return {**worker_receipt(expected), 'schema_version': 1, 'workspace_id': 'cranary',
            'source_url': URL, 'path': DIRECTORY + '/' + name, 'expected_sha256': expected,
            'training_eligible': False, 'historical_identity_verified': False,
            'file_integrity_status': 'sha256_verified', 'historical_validation_status': 'not_verified'}


@pytest.fixture
def tool(tmp_path, monkeypatch):
    root = tmp_path / 'workspace'
    root.mkdir()
    workspace = SimpleNamespace(path=str(root), writable=True, allow_execute=True)
    registry = SimpleNamespace(get=lambda name: workspace)
    policy = SimpleNamespace(config_dir=tmp_path,
        authorize_download=lambda workspace_id, url: ('packagemanager.posit.co', '', {
            'directory': DIRECTORY, 'max_response_bytes': 16 * 1024 * 1024, 'timeout_seconds': 60}))
    seen = {}
    def run(command, **kwargs):
        seen.update(command=command, kwargs=kwargs)
        os.write(kwargs['pass_fds'][0], BODY)
        expected = '--expected-sha256' in command
        return SimpleNamespace(returncode=0, stdout=json.dumps(worker_receipt(SHA if expected else None)).encode(), stderr=b'')
    monkeypatch.setattr(acquisition.subprocess, 'run', run)
    return acquisition.create_https_download_tool(registry, policy, tmp_path), root, seen


@pytest.mark.parametrize('expected', [None, SHA])
def test_download_persists_bounded_verifiable_receipt_without_historical_claim(tool, expected):
    call, root, seen = tool
    result = call('cranary', URL, 'PACKAGES.gz', expected)
    path = root / result['path']
    receipt = root / result['receipt_path']
    saved = receipt.read_bytes()
    document = json.loads(saved)
    assert path.read_bytes() == BODY
    assert result['receipt_path'] == result['path'] + '.receipt.json'
    assert result['receipt_sha256'] == hashlib.sha256(saved).hexdigest()
    assert len(saved) <= acquisition.MAX_RECEIPT_BYTES
    assert document == durable_receipt(expected=expected)
    assert 'receipt_sha256' not in document and 'receipt_path' not in document
    assert result['historical_identity_verified'] is False and result['training_eligible'] is False
    assert document['expected_sha256_verified'] is (expected is not None)
    assert document['expected_sha256'] == expected
    assert stat.S_IMODE(path.stat().st_mode) == stat.S_IMODE(receipt.stat().st_mode) == 0o600
    assert seen['kwargs']['timeout'] == 60
    assert '--max-bytes' in seen['command'] and str(16 * 1024 * 1024) in seen['command']
    assert not list(receipt.parent.glob('.acquire-*'))


@pytest.mark.parametrize('filename', ['PACKAGES.gz.receipt.json', 'x' * 129, '../x', '.env'])
def test_receipt_namespace_and_invalid_filenames_rejected_before_worker(tool, filename):
    call, root, seen = tool
    with pytest.raises(ValueError):
        call('cranary', URL, filename)
    assert not seen and not list(root.iterdir())


def test_full_128_character_filename_has_a_valid_separate_sidecar(tool):
    call, root, _ = tool
    name = 'a' * 125 + '.gz'
    result = call('cranary', URL, name)
    assert len(name) == 128 and len(Path(result['receipt_path']).name) == 141
    assert (root / result['path']).read_bytes() == BODY
    assert (root / result['receipt_path']).is_file()


@pytest.mark.parametrize('target', ['artifact', 'receipt'])
@pytest.mark.parametrize('kind', ['regular', 'symlink', 'directory'])
def test_existing_artifact_or_receipt_is_never_overwritten(tmp_path, target, kind):
    root = tmp_path / 'workspace'
    directory = root / DIRECTORY
    directory.mkdir(parents=True)
    path = directory / ('PACKAGES.gz' + ('.receipt.json' if target == 'receipt' else ''))
    outside = tmp_path / 'original'
    outside.write_bytes(b'ORIGINAL_DO_NOT_REPLACE')
    if kind == 'regular':
        path.write_bytes(outside.read_bytes())
    elif kind == 'symlink':
        path.symlink_to(outside)
    else:
        path.mkdir()
    with pytest.raises(FileExistsError):
        acquisition.publish(root, DIRECTORY, 'PACKAGES.gz', io.BytesIO(BODY),
                            worker_receipt(), receipt=durable_receipt())
    assert outside.read_bytes() == b'ORIGINAL_DO_NOT_REPLACE'
    assert path.is_dir() if kind == 'directory' else path.read_bytes() == b'ORIGINAL_DO_NOT_REPLACE'
    assert not list(directory.glob('.acquire-*'))
    assert len(list(directory.iterdir())) == 1


def test_dangling_receipt_symlink_remains_untouched(tmp_path):
    directory = tmp_path / DIRECTORY
    directory.mkdir(parents=True)
    sidecar = directory / 'PACKAGES.gz.receipt.json'
    sidecar.symlink_to(tmp_path / 'missing')
    with pytest.raises(FileExistsError):
        acquisition.publish(tmp_path, DIRECTORY, 'PACKAGES.gz', io.BytesIO(BODY),
                            worker_receipt(), receipt=durable_receipt())
    assert sidecar.is_symlink() and not (tmp_path / 'missing').exists()
    assert not (directory / 'PACKAGES.gz').exists()


@pytest.mark.parametrize('destination', ['artifact', 'receipt'])
@pytest.mark.parametrize('symlink', [False, True])
def test_publication_race_conflict_preserves_prior_contents(tmp_path, monkeypatch, destination, symlink):
    directory = tmp_path / DIRECTORY
    directory.mkdir(parents=True)
    outside = tmp_path / 'original'
    outside.write_bytes(b'PRIOR_CONTENT')
    real_link = acquisition.os.link
    target = 'PACKAGES.gz' + ('.receipt.json' if destination == 'receipt' else '')
    links = []
    def racing_link(source, name, **kwargs):
        links.append(name)
        if name == target:
            conflict = directory / name
            if symlink:
                conflict.symlink_to(outside)
            else:
                conflict.write_bytes(b'PRIOR_CONTENT')
        return real_link(source, name, **kwargs)
    monkeypatch.setattr(acquisition.os, 'link', racing_link)
    error = OSError if destination == 'artifact' else FileExistsError
    with pytest.raises(error):
        acquisition.publish(tmp_path, DIRECTORY, 'PACKAGES.gz', io.BytesIO(BODY),
                            worker_receipt(), receipt=durable_receipt())
    assert (directory / target).read_bytes() == outside.read_bytes() == b'PRIOR_CONTENT'
    assert links[0] == 'PACKAGES.gz.receipt.json'
    # If the artifact link loses the race, retain the already-published receipt.
    assert len(list(directory.iterdir())) == (2 if destination == 'artifact' else 1)


@pytest.mark.parametrize('kind,number', [('file', 1), ('file', 2), ('directory', 1)])
def test_fsync_failure_preserves_published_pair_and_reports_failure(tmp_path, monkeypatch, kind, number):
    directory = tmp_path / DIRECTORY
    directory.mkdir(parents=True)
    real_sync = acquisition.os.fsync
    counts = {'file': 0, 'directory': 0}
    def fail(fd):
        category = 'directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file'
        counts[category] += 1
        if category == kind and counts[category] == number:
            raise OSError('synthetic fsync failure')
        return real_sync(fd)
    monkeypatch.setattr(acquisition.os, 'fsync', fail)
    message = 'inspect preserved paths' if kind == 'directory' else 'synthetic fsync failure'
    with pytest.raises(OSError, match=message):
        acquisition.publish(tmp_path, DIRECTORY, 'PACKAGES.gz', io.BytesIO(BODY),
                            worker_receipt(), receipt=durable_receipt())
    if kind == 'directory':
        assert (directory / 'PACKAGES.gz').read_bytes() == BODY
        assert json.loads((directory / 'PACKAGES.gz.receipt.json').read_bytes()) == durable_receipt()
    else:
        assert not list(directory.iterdir())


def test_anonymous_staging_never_unlinks_mutable_workspace_names(tmp_path, monkeypatch):
    directory = tmp_path / DIRECTORY
    directory.mkdir(parents=True)
    def forbidden_unlink(*args, **kwargs):
        pytest.fail('Publication must never unlink a workspace pathname')
    monkeypatch.setattr(acquisition.os, 'unlink', forbidden_unlink)
    acquisition.publish(tmp_path, DIRECTORY, 'PACKAGES.gz', io.BytesIO(BODY),
                        worker_receipt(), receipt=durable_receipt())
    assert (directory / 'PACKAGES.gz').read_bytes() == BODY
    assert not list(directory.glob('.acquire-*'))


def test_failed_publication_never_unlinks_public_paths(tmp_path, monkeypatch):
    directory = tmp_path / DIRECTORY
    directory.mkdir(parents=True)
    real_unlink = acquisition.os.unlink
    real_sync = acquisition.os.fsync
    attempted = []

    def fail_commit(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError('synthetic commit failure')
        return real_sync(fd)

    def replace_before_unlink(name, **kwargs):
        if name in {'PACKAGES.gz', 'PACKAGES.gz.receipt.json'}:
            attempted.append(name)
            replacement = tmp_path / 'replacement'
            replacement.write_bytes(b'NEWER_OWNER_CONTENT')
            os.replace(replacement, directory / name)
        return real_unlink(name, **kwargs)

    monkeypatch.setattr(acquisition.os, 'fsync', fail_commit)
    monkeypatch.setattr(acquisition.os, 'unlink', replace_before_unlink)
    with pytest.raises(OSError):
        acquisition.publish(tmp_path, DIRECTORY, 'PACKAGES.gz', io.BytesIO(BODY),
                            worker_receipt(), receipt=durable_receipt())
    assert not attempted, 'Published paths must never be unlinked during failure cleanup'
    assert (directory / 'PACKAGES.gz').read_bytes() == BODY
    assert json.loads((directory / 'PACKAGES.gz.receipt.json').read_bytes()) == durable_receipt()


def test_competing_publishers_leave_one_matching_artifact_receipt_pair(tmp_path, monkeypatch):
    directory = tmp_path / DIRECTORY
    directory.mkdir(parents=True)
    ready = Barrier(2)
    real_link = acquisition.os.link

    def synchronized_link(source, name, **kwargs):
        if name.endswith('.receipt.json'):
            ready.wait(timeout=5)
        return real_link(source, name, **kwargs)

    monkeypatch.setattr(acquisition.os, 'link', synchronized_link)

    def run(body):
        expected = {**worker_receipt(), 'bytes': len(body),
                    'sha256': hashlib.sha256(body).hexdigest()}
        receipt = {**durable_receipt(), **expected}
        try:
            acquisition.publish(tmp_path, DIRECTORY, 'PACKAGES.gz', io.BytesIO(body),
                                expected, receipt=receipt)
        except FileExistsError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(run, [BODY, b'other concurrent acquisition']))
    assert sorted(results) == [False, True]
    saved = (directory / 'PACKAGES.gz').read_bytes()
    receipt = json.loads((directory / 'PACKAGES.gz.receipt.json').read_bytes())
    assert receipt['sha256'] == hashlib.sha256(saved).hexdigest()
    assert receipt['bytes'] == len(saved)
    assert len(list(directory.iterdir())) == 2


def test_rollback_preserves_replaced_artifact_and_does_not_claim_success(tmp_path, monkeypatch):
    directory = tmp_path / DIRECTORY
    directory.mkdir(parents=True)
    real_sync = acquisition.os.fsync
    replaced = False
    def replace_then_fail(fd):
        nonlocal replaced
        if stat.S_ISDIR(os.fstat(fd).st_mode) and not replaced:
            replaced = True
            artifact = directory / 'PACKAGES.gz'
            artifact.unlink()
            artifact.write_bytes(b'NEWER_OWNER_CONTENT')
            raise OSError('synthetic publication race')
        return real_sync(fd)
    monkeypatch.setattr(acquisition.os, 'fsync', replace_then_fail)
    with pytest.raises(OSError, match='inspect preserved paths'):
        acquisition.publish(tmp_path, DIRECTORY, 'PACKAGES.gz', io.BytesIO(BODY),
                            worker_receipt(), receipt=durable_receipt())
    assert (directory / 'PACKAGES.gz').read_bytes() == b'NEWER_OWNER_CONTENT'
    assert json.loads((directory / 'PACKAGES.gz.receipt.json').read_bytes()) == durable_receipt()
    assert not list(directory.glob('.acquire-*'))


@pytest.mark.parametrize('mutation', [
    {'unexpected': 'not accepted'}, {'bytes': True}, {'http_status': 200.0},
    {'headers': {'set-cookie': 'secret'}}, {'headers': {'etag': 'x\nunsafe'}},
    {'headers': {'etag': 'x' * 513}}, {'headers': []}, {'retrieved_at': '2026-10-21'},
    {'retrieved_at': '2026-10-21T22:00:00+01:00'}, {'retrieved_at': 12},
    {'historical_identity_verified': True}, {'expected_sha256_verified': True},
])
def test_unexpected_or_unsafe_worker_metadata_never_published(tool, monkeypatch, mutation):
    call, root, _ = tool
    data = worker_receipt()
    data.update(mutation)
    def run(*args, **kwargs):
        os.write(kwargs['pass_fds'][0], BODY)
        return SimpleNamespace(returncode=0, stdout=json.dumps(data).encode(), stderr=b'')
    monkeypatch.setattr(acquisition.subprocess, 'run', run)
    with pytest.raises(ValueError):
        call('cranary', URL, 'PACKAGES.gz')
    assert not list(root.iterdir())


def test_duplicate_worker_metadata_keys_rejected_before_publication(tool, monkeypatch):
    call, root, _ = tool
    body = json.dumps(worker_receipt())[:-1] + ',"bytes":0}'
    monkeypatch.setattr(acquisition.subprocess, 'run', lambda *args, **kwargs:
        SimpleNamespace(returncode=0, stdout=body.encode(), stderr=b''))
    with pytest.raises(ValueError, match='Duplicate'):
        call('cranary', URL, 'PACKAGES.gz')
    assert not list(root.iterdir())


@pytest.mark.parametrize('mutation', [
    {'historical_identity_verified': True}, {'training_eligible': True},
    {'historical_validation_status': 'verified'}, {'receipt_sha256': SHA},
    {'path': '../wrong'}, {'source_url': 'http://insecure.example/'},
    {'expected_sha256': '0' * 64}, {'schema_version': True},
])
def test_invalid_durable_metadata_rejected_before_directory_creation(tmp_path, mutation):
    receipt = durable_receipt()
    receipt.update(mutation)
    with pytest.raises(ValueError):
        acquisition.publish(tmp_path, DIRECTORY, 'PACKAGES.gz', io.BytesIO(BODY),
                            worker_receipt(), receipt=receipt)
    assert not list(tmp_path.iterdir())


def test_encoded_receipt_size_is_bounded_before_publication(tmp_path):
    receipt = durable_receipt()
    receipt['source_url'] = 'https://' + '\U0001f680' * 2040
    with pytest.raises(ValueError, match='bounded metadata budget'):
        acquisition.publish(tmp_path, DIRECTORY, 'PACKAGES.gz', io.BytesIO(BODY),
                            worker_receipt(), receipt=receipt)
    assert not list(tmp_path.iterdir())


def test_bad_spool_does_not_publish_receipt_or_artifact(tmp_path):
    with pytest.raises(ValueError, match='Spool'):
        acquisition.publish(tmp_path, DIRECTORY, 'PACKAGES.gz', io.BytesIO(b'bad'),
                            worker_receipt(), receipt=durable_receipt())
    assert not list((tmp_path / DIRECTORY).iterdir())


def test_receipt_publication_never_follows_directory_symlink(tmp_path):
    outside = tmp_path / 'outside'
    outside.mkdir()
    root = tmp_path / 'workspace'
    root.mkdir()
    (root / 'data-raw').symlink_to(outside, target_is_directory=True)
    with pytest.raises(OSError):
        acquisition.publish(root, DIRECTORY, 'PACKAGES.gz', io.BytesIO(BODY),
                            worker_receipt(), receipt=durable_receipt())
    assert not list(outside.iterdir())
