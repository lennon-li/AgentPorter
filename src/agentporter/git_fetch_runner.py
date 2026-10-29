"""Fixed sandbox-internal resource limiter; never accepts shell command strings."""
import os
import resource
import sys
import importlib.util


def main():
    proxy = len(sys.argv) > 2 and sys.argv[2] == '--proxy'
    args = sys.argv[3:] if proxy else sys.argv[2:]
    if not args or args[0] != '/usr/bin/git':
        raise SystemExit(2)
    limit = int(sys.argv[1])
    if not 1024 <= limit <= 512 * 1024**2:
        raise SystemExit(2)
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
    resource.setrlimit(resource.RLIMIT_CPU, (300, 300))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    if proxy:
        spec = importlib.util.spec_from_file_location('git_egress', '/work/repo/egress.py')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.bridge('/work/repo/egress.sock', 0, args)
    else:
        os.execve('/usr/bin/git', args, dict(os.environ))


if __name__ == '__main__':
    main()
