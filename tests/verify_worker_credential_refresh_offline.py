"""Offline safety tests of root-installed credential refresh helper; no actual credentials."""
from __future__ import annotations
from pathlib import Path
import importlib.util
import os
import stat
import tempfile

script = Path(__file__).resolve().parents[1] / "scripts/refresh-development-worker-credentials.py"
spec = importlib.util.spec_from_file_location("credential_refresh", script)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
with tempfile.TemporaryDirectory() as td:
    base = Path(td)
    private = base / "private"
    private.mkdir(mode=0o700)
    source = private / "source"
    value = b"TEST-SYNTHETIC-NOT-A-REAL-TOKEN"
    source.write_bytes(value)
    source.chmod(0o600)
    uid, gid = os.getuid(), os.getgid()
    assert mod._validated_secret(source, uid, allow_absent=False) == value
    source.chmod(0o644)
    try:
        mod._validated_secret(source, uid, allow_absent=False)
        raise AssertionError("Accepted public-readable credential")
    except PermissionError:
        pass
    assert mod._validated_secret(source, uid, allow_absent=False, allow_public_read=True) == value
    source.chmod(0o600)
    target = private / "auth.json"
    mod._install_secret(target, value, uid, gid, staging_dir=private, staging_uid=uid)
    assert mod._validated_secret(target, uid, allow_absent=False) == value
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert not list(private.glob(".credential-refresh-*"))
    symlink = private / "linked"
    symlink.symlink_to(target)
    try:
        mod._validated_secret(symlink, uid, allow_absent=False)
        raise AssertionError("Accepted credential symlink")
    except OSError:
        pass
    # Adversarial rename immediately before fd-relative publish: the helper
    # must never follow a newly installed symlink to another destination.
    stage = base / "stage"
    stage.mkdir(mode=0o700)
    target_root = base / "target"
    target_root.mkdir(mode=0o700)
    redirect = base / "redirect"
    redirect.mkdir(mode=0o700)
    fixed = target_root / "auth.json"
    original_rename = mod.os.rename

    def swap_ancestor(source_name, dest_name, *, src_dir_fd, dst_dir_fd):
        original_rename(str(target_root), str(base / "pinned-original"))
        target_root.symlink_to(redirect, target_is_directory=True)
        return original_rename(source_name, dest_name,
                               src_dir_fd=src_dir_fd, dst_dir_fd=dst_dir_fd)

    mod.os.rename = swap_ancestor
    try:
        mod._install_secret(fixed, value, uid, gid, staging_dir=stage, staging_uid=uid)
    finally:
        mod.os.rename = original_rename
    assert (base / "pinned-original" / "auth.json").read_bytes() == value
    assert not (redirect / "auth.json").exists()
    try:
        mod._validated_secret(fixed, uid, allow_absent=False)
        raise AssertionError("Followed a symlinked credential ancestor")
    except OSError:
        pass
    print("PASS: path swap cannot redirect a pinned privileged credential write")

    private.chmod(0o777)
    try:
        mod._install_secret(target, value, uid, gid, staging_dir=private, staging_uid=uid)
        raise AssertionError("Installed credential into writable directory")
    except PermissionError:
        pass
print("PASS: credential refresh preserves owner/mode, atomicity and symlink rejection")
