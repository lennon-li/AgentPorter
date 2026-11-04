import hashlib
import errno
import os
import sys

import pytest
from agentporter.workspaces import bounded
from agentporter.tools.files import create_file_tools, MAX_HASH_READ_BYTES


def test_sparse_file_rejected_before_hashing(workspace_registry, monkeypatch):
    root = workspace_registry.get('test-ws').path
    with open(root+'/sparse.txt','wb') as handle: handle.truncate(2**32)
    read = create_file_tools(workspace_registry)[2]
    monkeypatch.setattr(hashlib,'sha256',lambda *a:pytest.fail('Hashed oversized file'))
    for options in ({},{'start_line':1,'end_line':1}):
        with pytest.raises(ValueError,match='budget'): read('test-ws','sparse.txt',**options)


def test_long_line_output_is_bounded(workspace_registry):
    root = workspace_registry.get('test-ws').path
    with open(root+'/long.txt','wb') as handle: handle.write(b'X'*(2*1024**2))
    with pytest.raises(ValueError,match='output budget'):
        create_file_tools(workspace_registry)[2]('test-ws','long.txt',start_line=1,end_line=1)


def test_fifo_and_hardlink_do_not_create_unbounded_or_alias_reads(tmp_path):
    os.mkfifo(tmp_path/'pipe')
    with pytest.raises(ValueError,match='regular file'): bounded.read_regular(tmp_path,'pipe',1024)
    (tmp_path/'first').write_text('synthetic')
    os.link(tmp_path/'first',tmp_path/'alias')
    with pytest.raises(ValueError,match='hardlink'): bounded.read_regular(tmp_path,'alias',1024)


def test_traversal_budget_includes_empty_directories(tmp_path,monkeypatch):
    monkeypatch.setattr(bounded,'MAX_SCAN_ENTRIES',4)
    for i in range(5): (tmp_path/str(i)).mkdir()
    with pytest.raises(ValueError,match='entry budget'): list(bounded.walk_files(tmp_path,depth=0))
    with pytest.raises(ValueError,match='depth'): list(bounded.walk_files(tmp_path,depth=100))


def test_search_capture_stops_output_flood():
    with pytest.raises(ValueError,match='output budget'):
        bounded.capture_bounded([sys.executable,'-I','-c','import os\nwhile True:os.write(1,b"X"*65536)'],limit=1024,timeout=1)


def test_listing_skips_unreadable_child_but_explicit_private_root_stays_denied(tmp_path, monkeypatch, caplog):
    private = tmp_path / 'private'
    private.mkdir()
    (private / 'hidden.txt').write_text('private fixture')
    (tmp_path / 'visible.txt').write_text('public fixture')
    original_open = os.open

    def denied_private(path, flags, *args, **kwargs):
        if os.fspath(path).rstrip('/').split('/')[-1] == 'private':
            raise PermissionError(errno.EACCES, 'synthetic private directory', os.fspath(path))
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(bounded.os, 'open', denied_private)
    assert list(bounded.walk_files(tmp_path, depth=1)) == ['visible.txt']
    assert 'Skipping unreadable workspace directory: private' in caplog.text
    with pytest.raises(PermissionError):
        list(bounded.walk_files(tmp_path, path='private', depth=1))
    # Skipped directories still consume the global traversal budget.
    monkeypatch.setattr(bounded, 'MAX_SCAN_ENTRIES', 1)
    with pytest.raises(ValueError, match='entry budget'):
        list(bounded.walk_files(tmp_path, depth=1))


def test_listing_does_not_swallow_symlink_race_or_unrelated_io_errors(tmp_path, monkeypatch):
    (tmp_path / 'child').mkdir()
    original_open = os.open

    def raced_child(path, flags, *args, **kwargs):
        if os.fspath(path) == 'child':
            raise OSError(errno.ELOOP, 'synthetic directory symlink race', 'child')
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(bounded.os, 'open', raced_child)
    with pytest.raises(OSError) as error:
        list(bounded.walk_files(tmp_path, depth=1))
    assert error.value.errno == errno.ELOOP
