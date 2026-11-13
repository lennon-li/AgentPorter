"""The quota collector must execute only the sealed machine selection."""
import json
from pathlib import Path
import stat
from types import SimpleNamespace

import pytest

from agentporter import shared_cli


@pytest.fixture
def selection(tmp_path,monkeypatch):
    root=tmp_path/'store'
    release=root/'releases/20261113T161430Z-168a733f'
    binary=release/'node_modules/@openai/codex/vendor/target/bin/codex'
    binary.parent.mkdir(parents=True)
    binary.write_bytes(b'\x7fELFtest-codex')
    binary.chmod(0o555)
    (root/'current').symlink_to(release)
    manifest={'schema':1,'account_data_included':False,
        'providers':{'codex':{'binary':str(binary.relative_to(release)),'version':'0.169.0'}},
        'files':{str(binary.relative_to(release)):{'size':binary.stat().st_size,
            'sha256':shared_cli.sha256(binary.read_bytes()).hexdigest()}}}
    (release/'MANIFEST.json').write_text(json.dumps(manifest))
    original=Path.lstat
    overrides={}
    def lstat(path,*args,**kwargs):
        real=original(path,*args,**kwargs)
        values={name:getattr(real,name) for name in ('st_mode','st_uid','st_size')}
        # Model the root-owned immutable store in an unprivileged test tree.
        values.update(st_uid=0,st_mode=real.st_mode&~0o022)
        values.update(overrides.get(path,{}))
        return SimpleNamespace(**values)
    monkeypatch.setattr(shared_cli,'ROOT',root)
    monkeypatch.setattr(Path,'lstat',lstat)
    # fstat checks manifest custody too; only that descriptor needs the model.
    real_fstat=shared_cli.os.fstat
    def fstat(fd):
        value=real_fstat(fd)
        if value.st_ino==(release/'MANIFEST.json').stat().st_ino:
            return SimpleNamespace(st_uid=0,st_mode=stat.S_IFREG|0o444,st_size=value.st_size)
        return value
    monkeypatch.setattr(shared_cli.os,'fstat',fstat)
    return root,release,binary,manifest,overrides


def test_selected_bytes_and_version(selection):
    _,_,binary,_,_=selection
    assert shared_cli.selected_codex()==(binary,'0.169.0')


def test_tampered_binary_is_not_a_quota_source(selection):
    _,_,binary,_,_=selection
    binary.chmod(0o755)
    binary.write_bytes(b'\x7fELFfake-codex')
    with pytest.raises(PermissionError):
        shared_cli.selected_codex()


def test_user_owned_selection_is_rejected(selection):
    root,_,_,_,overrides=selection
    overrides[root/'current']={'st_uid':12345}
    with pytest.raises(PermissionError):
        shared_cli.selected_codex()


def test_external_current_target_is_rejected(selection,tmp_path):
    root,_,_,_,_=selection
    (root/'current').unlink()
    (root/'current').symlink_to(tmp_path)
    with pytest.raises(PermissionError):
        shared_cli.selected_codex()


def test_writable_binary_ancestor_is_rejected(selection):
    _,_,binary,_,overrides=selection
    overrides[binary.parent]={'st_mode':stat.S_IFDIR|0o777}
    with pytest.raises(PermissionError):
        shared_cli.selected_codex()


def test_deadline_is_enforced_before_hashing(selection):
    with pytest.raises(TimeoutError):
        shared_cli.selected_codex(deadline=0)
