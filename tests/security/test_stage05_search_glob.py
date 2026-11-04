"""Actual rg workspace-relative globs; no root or actual cross-UID claim."""
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from agentporter.tools import files
from agentporter.workspaces import bounded
from tests.security.test_foreign_workspace_file_api import foreign


def search(root):
    return files.create_file_tools(SimpleNamespace(get=lambda _: SimpleNamespace(path=str(root), writable=False)))[1]


@pytest.mark.parametrize('glob,expected', [
    ('folder/**', ['folder/colon:name.txt', 'folder/deep/nested.txt', 'folder/newline\nname.txt', 'folder/probe.txt']),
    ('folder/*.txt', ['folder/colon:name.txt', 'folder/newline\nname.txt', 'folder/probe.txt']),
    ('folder/deep/**', ['folder/deep/nested.txt']),
    ('*.txt', ['elsewhere/other.txt', 'folder/colon:name.txt', 'folder/deep/nested.txt', 'folder/newline\nname.txt', 'folder/probe.txt']),
])
def test_native_globs_are_workspace_relative_with_exact_structured_names(tmp_path, glob, expected):
    (tmp_path/'folder/deep').mkdir(parents=True);(tmp_path/'elsewhere').mkdir()
    for name in ['folder/probe.txt', 'folder/colon:name.txt', 'folder/newline\nname.txt', 'folder/deep/nested.txt', 'elsewhere/other.txt']:
        (tmp_path/name).write_text('MARKER\n')
    before = os.getcwd()
    assert sorted(search(tmp_path)('p', 'MARKER', glob=glob), key=lambda row: row['path']) == [
        {'path': name, 'line': 1, 'text': 'MARKER'} for name in expected]
    assert os.getcwd() == before


def test_relative_glob_on_verified_foreign_projection_fd(foreign):
    root, tools, seen = foreign
    assert tools[1]('project', 'needle', glob='child/**') == [
        {'path': 'child/nested.txt', 'line': 1, 'text': 'needle ordinary'}]
    for fd in seen:
        with pytest.raises(OSError): os.fstat(fd)


def test_relative_glob_keeps_masks_and_hardlink_alias_denials(tmp_path):
    (tmp_path/'folder').mkdir();private=tmp_path/'folder/secrets.env';private.write_text('PRIVATE_MARKER\n')
    os.link(private, tmp_path/'folder/visible:alias.txt')
    (tmp_path/'folder/symlink.txt').symlink_to(private)
    assert search(tmp_path)('p', 'PRIVATE_MARKER', glob='folder/**') == []


def test_same_held_root_used_when_canonical_directory_is_replaced(tmp_path, monkeypatch):
    root=tmp_path/'project';(root/'folder').mkdir(parents=True);(root/'folder/one.txt').write_text('ORIGINAL\n')
    original=files.capture_bounded
    def replaced(*args, **kwargs):
        root.rename(tmp_path/'retained');(root/'folder').mkdir(parents=True)
        (root/'folder/one.txt').write_text('UNRELATED_NEW_ROOT\n')
        return original(*args, **kwargs)
    monkeypatch.setattr(files,'capture_bounded',replaced)
    assert search(root)('p','ORIGINAL',glob='folder/**') == [{'path':'folder/one.txt','line':1,'text':'ORIGINAL'}]


def test_glob_result_still_revalidates_atomic_file_replacement(tmp_path, monkeypatch):
    (tmp_path/'folder').mkdir();target=tmp_path/'folder/one.txt';target.write_text('ORIGINAL\n')
    original=files.capture_bounded
    def replaced(*args, **kwargs):
        result=original(*args, **kwargs);new=tmp_path/'new';new.write_text('UNRELATED\n');os.replace(new,target);return result
    monkeypatch.setattr(files,'capture_bounded',replaced)
    assert search(tmp_path)('p','ORIGINAL',glob='folder/**') == []


def test_relative_capture_requires_closed_validated_directory_capability(tmp_path):
    with pytest.raises(ValueError, match='pinned'):
        bounded.capture_bounded(['rg','needle','.'],workspace_relative=True)
    fd=os.open(tmp_path,os.O_RDONLY|os.O_DIRECTORY)
    try:
        with pytest.raises(ValueError,match='descriptor'):
            bounded.capture_bounded(['rg','needle','.'],workspace_fd=fd,workspace_relative=True)
        with pytest.raises(ValueError,match='descriptor'):
            bounded.capture_bounded(['python3','-c','pass',f'/proc/self/fd/{fd}/.'],workspace_fd=fd,workspace_relative=True)
    finally:os.close(fd)


def test_relative_host_path_cannot_select_workspace_executable(tmp_path, monkeypatch):
    host=tmp_path/'host';(host/'host-bin').mkdir(parents=True)
    (host/'host-bin/rg').symlink_to('/usr/bin/rg')
    root=tmp_path/'workspace';(root/'folder').mkdir(parents=True);(root/'folder/one.txt').write_text('SAFE_MARKER\n')
    (root/'host-bin').mkdir();evil=root/'host-bin/rg';evil.write_text('#!/bin/sh\ntouch WORKSPACE_EXECUTED\n');evil.chmod(0o700)
    monkeypatch.chdir(host);monkeypatch.setenv('PATH','host-bin')
    assert search(root)('p','SAFE_MARKER',glob='folder/**') == [{'path':'folder/one.txt','line':1,'text':'SAFE_MARKER'}]
    assert not (root/'WORKSPACE_EXECUTED').exists()
