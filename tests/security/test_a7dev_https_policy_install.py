"""Synthetic policy-install safety tests; never sudo, restart, or use network."""
import importlib.util
import os
from pathlib import Path
import stat

import pytest

script = Path(__file__).resolve().parents[2] / 'scripts/authorize-a7dev-cranary-https.py'
spec = importlib.util.spec_from_file_location('a7dev_https_operator', script)
operator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(operator)


@pytest.fixture
def installer(tmp_path):
    namespace = {'__name__': 'operator_bootstrap_review'}
    exec(compile(operator.BOOTSTRAP, '<fixed-operator-bootstrap>', 'exec'), namespace)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield namespace, fd, tmp_path
    finally:
        os.close(fd)


def test_proposal_does_not_invoke_privileged_commands(monkeypatch, capsys):
    monkeypatch.setattr('sys.argv', [str(script)])
    monkeypatch.setattr(operator.subprocess, 'run', lambda *a, **k: pytest.fail('Proposal invoked a subprocess'))
    operator.main()
    assert 'No policy installed; no service restarted' in capsys.readouterr().out


def test_installs_exact_private_policy_and_is_idempotent(installer):
    code, fd, root = installer
    created, identity = code['install_policy'](fd, os.getuid(), os.getgid())
    path = root / 'public-https.yaml'
    assert created and path.read_bytes() == operator.POLICY.encode()
    info = path.stat()
    assert (info.st_dev, info.st_ino) == identity
    assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (os.getuid(), os.getgid(), 0o600)
    assert code['install_policy'](fd, os.getuid(), os.getgid()) == (False, identity)
    assert list(root.iterdir()) == [path]


def test_different_existing_policy_is_preserved(installer):
    code, fd, root = installer
    path = root / 'public-https.yaml'
    content = operator.POLICY.encode().replace(b'GET', b'PUT')
    path.write_bytes(content)
    path.chmod(0o600)
    with pytest.raises(PermissionError, match='content differs'):
        code['install_policy'](fd, os.getuid(), os.getgid())
    assert path.read_bytes() == content


def test_policy_symlink_cannot_write_another_file(installer):
    code, fd, root = installer
    target = root / 'unrelated'
    target.write_text('preserve')
    (root / 'public-https.yaml').symlink_to(target)
    with pytest.raises(OSError):
        code['install_policy'](fd, os.getuid(), os.getgid())
    assert target.read_text() == 'preserve'


@pytest.mark.parametrize('mode', [0o644, 0o640, 0o660])
def test_unsafe_existing_permissions_are_not_silently_repaired(installer, mode):
    code, fd, root = installer
    path = root / 'public-https.yaml'
    path.write_text(operator.POLICY)
    path.chmod(mode)
    with pytest.raises(PermissionError, match='metadata differs'):
        code['install_policy'](fd, os.getuid(), os.getgid())
    assert stat.S_IMODE(path.stat().st_mode) == mode


def test_fifo_policy_is_rejected_without_blocking(installer):
    code, fd, root = installer
    path = root / 'public-https.yaml'
    os.mkfifo(path, 0o600)
    with pytest.raises(PermissionError, match='metadata differs'):
        code['install_policy'](fd, os.getuid(), os.getgid())
    assert stat.S_ISFIFO(path.stat().st_mode)


def test_racing_policy_is_not_overwritten_and_temporary_is_removed(installer, monkeypatch):
    code, fd, root = installer
    real_link = os.link
    def race(*args, **kwargs):
        (root / 'public-https.yaml').write_text('independent concurrent operator change')
        return real_link(*args, **kwargs)
    monkeypatch.setattr(os, 'link', race)
    with pytest.raises(FileExistsError):
        code['install_policy'](fd, os.getuid(), os.getgid())
    assert (root / 'public-https.yaml').read_text() == 'independent concurrent operator change'
    assert len(list(root.iterdir())) == 1
