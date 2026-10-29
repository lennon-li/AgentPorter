"""Retain descriptor-based process control on hosts with older glibc."""
import errno
from unittest.mock import Mock

import pytest

from agentporter import process_handles


def test_python_pidfd_apis_do_not_require_glibc_symbols(monkeypatch):
    opener = Mock(return_value=42)
    sender = Mock()
    monkeypatch.setattr(process_handles.os, 'pidfd_open', opener, raising=False)
    monkeypatch.setattr(process_handles.signals, 'pidfd_send_signal', sender, raising=False)
    monkeypatch.setattr(process_handles.ctypes, 'CDLL', Mock(side_effect=AssertionError('libc accessed')))

    assert process_handles.open_handle(123) == 42
    process_handles.signal_handle(42, 9)

    opener.assert_called_once_with(123, 0)
    sender.assert_called_once_with(42, 9, None, 0)


def test_python_pidfd_error_is_not_downgraded(monkeypatch):
    monkeypatch.setattr(process_handles.os, 'pidfd_open', Mock(side_effect=OSError(errno.ENOSYS, 'unsupported')), raising=False)
    monkeypatch.setattr(process_handles.ctypes, 'CDLL', Mock(side_effect=AssertionError('fallback attempted')))
    with pytest.raises(OSError) as error:
        process_handles.open_handle(123)
    assert error.value.errno == errno.ENOSYS


def test_libc_fallback_remains_available_for_python_without_pidfd(monkeypatch):
    monkeypatch.delattr(process_handles.os, 'pidfd_open', raising=False)
    monkeypatch.delattr(process_handles.signals, 'pidfd_send_signal', raising=False)
    call = Mock(return_value=42)
    monkeypatch.setattr(process_handles, '_call', call)

    assert process_handles.open_handle(123) == 42
    process_handles.signal_handle(42, 9)
    assert [entry.args[:2] for entry in call.call_args_list] == [
        ('pidfd_open', (123, 0)), ('pidfd_send_signal', (42, 9, None, 0))]
