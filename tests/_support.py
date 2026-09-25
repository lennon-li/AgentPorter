"""Test-environment capability probes."""

import shutil
import subprocess


def bwrap_usable() -> bool:
    exe = shutil.which("bwrap")
    if not exe:
        return False
    try:
        res = subprocess.run(
            [
                exe,
                "--unshare-all",
                "--unshare-net",
                "--ro-bind", "/", "/",
                "--",
                "/bin/true",
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return res.returncode == 0
    except Exception:
        return False


BWRAP_USABLE = bwrap_usable()
