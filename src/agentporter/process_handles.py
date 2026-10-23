"""Linux pidfd wrappers, including portable Python builds lacking os.pidfd_open."""
import ctypes
import os


def _call(name, arguments, types):
    library = ctypes.CDLL(None, use_errno=True)
    try:
        function = getattr(library, name)
    except AttributeError as error:
        raise PermissionError('Kernel process-handle support is required') from error
    function.argtypes = types
    function.restype = ctypes.c_int
    result = function(*arguments)
    if result < 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return result


def open_handle(pid):
    return _call('pidfd_open', (pid, 0), [ctypes.c_int, ctypes.c_uint])


def signal_handle(fd, signal):
    _call('pidfd_send_signal', (fd, signal, None, 0),
          [ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint])
