"""Fixed pre-exec cgroup join; launched only by the trusted gateway."""
import os
from pathlib import Path
import re
import sys


def main():
    if len(sys.argv) < 5 or sys.argv[1] != '--cgroup' or sys.argv[3] != '--':
        raise SystemExit('Invalid resource launcher arguments')
    path = Path(sys.argv[2])
    if (not path.is_absolute() or not path.is_relative_to('/sys/fs/cgroup')
            or not re.fullmatch(r'apj_[0-9a-f]{32}', path.name)
            or path.is_symlink() or path.stat().st_uid != os.getuid()):
        raise SystemExit('Untrusted resource envelope')
    (path / 'cgroup.procs').write_text(str(os.getpid()))
    current = Path('/proc/self/cgroup').read_text().strip()
    if current != '0::/' + str(path.relative_to('/sys/fs/cgroup')):
        raise SystemExit('Resource envelope join failed')
    os.execv(sys.argv[4], sys.argv[4:])


if __name__ == '__main__':
    main()
