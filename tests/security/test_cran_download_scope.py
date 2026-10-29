"""Owner opt-in for the exact CRAN host; synthetic transport only."""
import hashlib
import io
import json

import pytest
import yaml

from agentporter.https_download import stream_download, publish
from agentporter.scoped_https import ScopedPublicHTTPSPolicy
from tests.security.test_https_acquisition import policy, connection, Response, DIRECTORY

CRAN = 'https://cran.r-project.org'
POSIT = 'https://packagemanager.posit.co/cran/2025-06-30/src/contrib/staticryptR_0.1.0.tar.gz'

def test_posit_redirect_diagnostic_exposes_destination_without_query(tmp_path, caplog):
    location = 'https://cdn.posit.co/cran/staticryptR_0.1.0.tar.gz?signature=private-token#fragment'
    factory, _ = connection(Response(status=307, headers=[('Location', location)]))
    with pytest.raises(PermissionError):
        stream_download(approved(tmp_path), 'cranary', POSIT, io.BytesIO(), connection_factory=factory)
    events = [json.loads(record.message) for record in caplog.records if 'download_http_rejected' in record.message]
    assert events[-1]['redirect_target'] == 'https://cdn.posit.co/cran/staticryptR_0.1.0.tar.gz'
    assert 'private-token' not in caplog.text

@pytest.mark.parametrize('location', [
    'http://cdn.posit.co/package.tar.gz',
    'https://user:secret@cdn.posit.co/package.tar.gz',
    'https://cdn.posit.co:444/package.tar.gz',
    'https://cdn.posit.co/package.tar.gz\r\nforged: value',
])
def test_posit_redirect_diagnostic_hides_unsafe_destination(tmp_path, caplog, location):
    factory, _ = connection(Response(status=307, headers=[('Location', location)]))
    with pytest.raises(PermissionError):
        stream_download(approved(tmp_path), 'cranary', POSIT, io.BytesIO(), connection_factory=factory)
    events = [json.loads(record.message) for record in caplog.records if 'download_http_rejected' in record.message]
    assert 'redirect_target' not in events[-1]


def approved(tmp_path, value=True):
    p = policy(tmp_path)
    path = p.config_dir / 'public-https.yaml'
    doc = yaml.safe_load(path.read_text())
    doc['workspaces']['cranary']['downloads']['cran_all_paths'] = value
    path.write_text(yaml.safe_dump(doc))
    return ScopedPublicHTTPSPolicy(p.config_dir)


@pytest.mark.parametrize('path', ['/src/contrib/staticryptR_0.1.0.tar.gz',
    '/src/contrib/Archive/TCIU/TCIU_1.1.0.tar.gz', '/doc/manuals/r-release/R-intro.pdf', '/'])
def test_all_cran_paths_require_explicit_owner_opt_in(tmp_path, path):
    url = CRAN + path
    if '/Archive/' not in path:
        with pytest.raises(PermissionError):
            policy(tmp_path).authorize_download('cranary', url)
    else:
        policy(tmp_path)
    p = ScopedPublicHTTPSPolicy(tmp_path / 'config')
    config = p.config_dir / 'public-https.yaml'
    doc = yaml.safe_load(config.read_text())
    doc['workspaces']['cranary']['downloads']['cran_all_paths'] = True
    config.write_text(yaml.safe_dump(doc))
    assert ScopedPublicHTTPSPolicy(p.config_dir).authorize_download('cranary', url)[0] == 'cran.r-project.org'


@pytest.mark.parametrize('value', ['true', 1, None, [], {}])
def test_opt_in_requires_boolean(tmp_path, value):
    with pytest.raises(ValueError):
        approved(tmp_path, value)


def test_false_preserves_current_cran_denial(tmp_path):
    with pytest.raises(PermissionError):
        approved(tmp_path, False).authorize_download('cranary', CRAN + '/src/contrib/staticryptR_0.1.0.tar.gz')


@pytest.mark.parametrize('url', [
    'http://cran.r-project.org/x', 'https://cran.r-project.org.evil.example/x',
    'https://cran.r-project.org:444/x', 'https://user@cran.r-project.org/x',
    'https://127.0.0.1/x', CRAN + '/x?download=1', CRAN + '/x#fragment',
    'https://packagemanager.posit.co/cran/latest/src/contrib/Foo_1.tar.gz',
    'https://packagemanager.posit.co/admin',
])
def test_opt_in_does_not_expand_other_hosts_or_transport(tmp_path, url):
    with pytest.raises((PermissionError, ValueError)):
        approved(tmp_path).authorize_download('cranary', url)


@pytest.mark.parametrize('url', [POSIT, CRAN + '/src/contrib/staticryptR_0.1.0.tar.gz',
    'https://packagemanager.posit.co/cran/2021-06-30/src/contrib/PACKAGES.gz',
    CRAN + '/src/contrib/Archive/TCIU/TCIU_1.1.0.tar.gz'])
def test_download_integrity_and_durable_receipt(tmp_path, url):
    p = approved(tmp_path)
    body = b'\x1f\x8b\0synthetic-source'
    sha = hashlib.sha256(body).hexdigest()
    factory, _ = connection(Response(body))
    spool = io.BytesIO()
    result = stream_download(p, 'cranary', url, spool, expected_sha256=sha, connection_factory=factory)
    assert result['http_status'] == 200 and result['sha256'] == sha
    root = tmp_path / 'workspace'; root.mkdir()
    name = 'source.tar.gz'
    receipt = dict(result, schema_version=1, workspace_id='cranary', source_url=url,
        path=DIRECTORY + '/' + name, expected_sha256=sha, training_eligible=False,
        historical_identity_verified=False, file_integrity_status='sha256_verified',
        historical_validation_status='not_verified')
    publish(root, DIRECTORY, name, spool, result, receipt=receipt)
    saved = root / DIRECTORY / name
    assert hashlib.sha256(saved.read_bytes()).hexdigest() == sha
    assert json.loads(saved.with_name(name + '.receipt.json').read_text()) == receipt
    with pytest.raises(FileExistsError):
        publish(root, DIRECTORY, name, spool, result, receipt=receipt)


@pytest.mark.parametrize('status', [301, 302, 303, 307, 308])
def test_posit_redirect_never_retried_or_published(tmp_path, status):
    factory, conn = connection(Response(status=status, headers=[('Location', CRAN + '/x')]))
    spool = io.BytesIO()
    with pytest.raises(PermissionError):
        stream_download(approved(tmp_path), 'cranary', POSIT, spool, connection_factory=factory)
    assert not spool.getvalue()
    factory.assert_called_once()
    conn.request.assert_called_once()


@pytest.mark.parametrize('limit,timeout', [(16777217, 60), (16777216, 61)])
def test_opt_in_preserves_hard_caps(tmp_path, limit, timeout):
    factory, _ = connection(Response())
    with pytest.raises(ValueError):
        stream_download(approved(tmp_path), 'cranary', CRAN + '/x', io.BytesIO(),
            max_bytes=limit, timeout_seconds=timeout, connection_factory=factory)
    factory.assert_not_called()
