"""Failure injection for trusted A7Dev release helpers."""

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def load_script(name):
    path = ROOT / 'scripts' / name
    spec = importlib.util.spec_from_file_location(path.stem.replace('-', '_'), path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


INSTALLER = load_script('install-development-artifact.py')
RUNTIME_GATE = load_script('verify-a7dev-runtime-install-gate.py')


@pytest.mark.parametrize('failure_point', [
    'runtime_before', 'runtime_after', 'pointer_before', 'pointer_after', 'activation',
])
def test_installer_compensates_every_switch_failure(tmp_path, monkeypatch, failure_point):
    base_path = tmp_path / 'releases'
    base_path.mkdir()
    old = base_path / 'versions' / '20261022T224004.423620Z'
    new = base_path / 'versions' / '20261023T000000.000000Z'
    old.parent.mkdir()
    old.mkdir()
    new.mkdir()
    (base_path / 'current').symlink_to(old)
    config_path = tmp_path / 'config'
    config_path.mkdir()
    runtime_path = config_path / 'development-runtime.yaml'
    runtime_path.write_bytes(b'old-runtime\n')
    import os
    base_fd = os.open(base_path, os.O_RDONLY | os.O_DIRECTORY)
    config_fd = os.open(config_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        real_write = INSTALLER.private_write
        real_pointer = INSTALLER.replace_symlink
        writes = 0
        pointers = 0

        def injected_write(*args, **kwargs):
            nonlocal writes
            writes += 1
            if failure_point == 'runtime_before' and writes == 1:
                raise OSError('injected runtime write failure')
            result = real_write(*args, **kwargs)
            if failure_point == 'runtime_after' and writes == 1:
                raise OSError('injected post-write failure')
            return result

        def injected_pointer(*args, **kwargs):
            nonlocal pointers
            pointers += 1
            if failure_point == 'pointer_before' and pointers == 1:
                raise OSError('injected pointer failure')
            result = real_pointer(*args, **kwargs)
            if failure_point == 'pointer_after' and pointers == 1:
                raise OSError('injected post-pointer failure')
            return result

        monkeypatch.setattr(INSTALLER, 'private_write', injected_write)
        monkeypatch.setattr(INSTALLER, 'replace_symlink', injected_pointer)

        def fail_activation():
            raise RuntimeError('injected activation failure')

        with pytest.raises((OSError, RuntimeError)):
            INSTALLER.switch_pair(
                base_fd, config_fd, new, b'new-runtime\n', old,
                b'old-runtime\n', 12345, 12345,
                activate=fail_activation if failure_point == 'activation' else None,
            )
        assert (base_path / 'current').resolve() == old
        assert runtime_path.read_bytes() == b'old-runtime\n'
    finally:
        __import__('os').close(config_fd)
        __import__('os').close(base_fd)


def test_runtime_yaml_parser_does_not_echo_protected_source():
    marker = 'PRIVATE_RUNTIME_MARKER_7c9a'
    with pytest.raises(ValueError) as error:
        RUNTIME_GATE.parse_runtime(f'profile: development\nprivate: [{marker}\n'.encode())
    assert str(error.value) == 'Protected A7Dev runtime YAML is invalid'
    assert marker not in str(error.value)
    assert error.value.__cause__ is None
    assert marker not in repr(error.value.__context__)

