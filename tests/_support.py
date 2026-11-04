"""Test-environment capability probes."""

import os
import shutil
import subprocess


def bwrap_usable() -> bool:
    exe = shutil.which("bwrap")
    if not exe:
        return False
    try:
        mounts = []
        # Dynamically linked /bin/true needs its loader and libraries.
        for root in ("/usr", "/bin", "/lib", "/lib64"):
            if os.path.exists(root):
                mounts.extend(["--ro-bind", root, root])
        res = subprocess.run(
            [exe, "--unshare-all", "--unshare-net", "--die-with-parent",
             "--clearenv", *mounts, "--", "/bin/true"],
            capture_output=True, text=True, timeout=5,
            env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"},
            stdin=subprocess.DEVNULL,
        )
        return res.returncode == 0
    except Exception:
        return False


BWRAP_USABLE = bwrap_usable()
