#!/usr/bin/python3
"""Operator-only credential freshness and scoped refresh for the Asgard production worker.

Install root-owned at /usr/local/libexec/agentporter/ next to
refresh-development-worker-credentials.py and run with `/usr/bin/python3 -I` as root.
It reuses the audited pinned-directory, validation and atomic-publish primitives of
that helper but is bound to the independent agentporter-worker identity and its own
credential root. The identity, data root and source map are fixed here, never taken
from arguments or the environment. Provider routing stays explicit: provider config
files (config.toml) are never copied, and agents listed in PAUSED are refused unless
named in --allow-paused. Never prints or emits credentials or their fingerprints.
"""
from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import stat
import sys

BASE_PATH = Path(__file__).resolve().with_name('refresh-development-worker-credentials.py')
TRUSTED = Path('/usr/local/libexec/agentporter/refresh-asgard-worker-credentials.py')
ACCOUNT = 'agentporter-worker'
DATA = Path('/var/lib/agentporter-worker/credentials')
SOURCES = {
    'jax': {'.codex/auth.json': '/home/operator/.codex/auth.json',
            '.codex/config.toml': '/home/operator/.codex/config.toml'},
    'liz': {'.codex/auth.json': '/home/operator/.codex-liz/auth.json',
            '.codex/config.toml': '/home/operator/.codex-liz/config.toml'},
    'prof': {'.codex/auth.json': '/home/operator/.codex-prof/auth.json',
             '.codex/config.toml': '/home/operator/.codex-prof/config.toml'},
    'ming': {'.claude/.credentials.json': '/home/operator/.claude/.credentials.json'},
    'phil': {'.copilot-phil/config.json': '/home/operator/.copilot-phil/config.json'},
    'wei': {'.config/opencode/wei-key': '/home/operator/.config/opencode/go-key'},
    'argie': {'.gemini/antigravity-cli/antigravity-oauth-token':
              '/home/operator/.gemini/antigravity-cli/antigravity-oauth-token'},
}
PAUSED = frozenset({'wei'})
DEFAULT_AGENTS = tuple(name for name in SOURCES if name not in PAUSED)


def load_base():
    spec = importlib.util.spec_from_file_location('refresh_development_worker_credentials', BASE_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ACCOUNT = ACCOUNT
    module.DATA = DATA
    module.SOURCES = SOURCES
    return module


def trusted_program():
    path = Path(__file__)
    if path != TRUSTED or os.geteuid() != 0 or not sys.flags.isolated:
        raise PermissionError('Use the immutable installed helper with /usr/bin/python3 -I as root')
    for item in (path, BASE_PATH, *path.parents):
        info = item.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError('Helper, base helper and ancestors must be root-owned and non-writable')


def select_agents(requested, allow_paused):
    agents = list(requested)
    if not agents or len(set(agents)) != len(agents) or any(name not in SOURCES for name in agents):
        raise PermissionError('Unknown or duplicate agent identity')
    paused = [name for name in agents if name in PAUSED and name not in allow_paused]
    if paused or any(name not in PAUSED for name in allow_paused):
        raise PermissionError('Paused agent requires explicit --allow-paused: ' + ','.join(paused or allow_paused))
    return agents


def run(*, apply, agents, routes=False):
    base = load_base()
    base._run(apply=apply, agents=agents)
    if routes:
        for agent in agents:
            base._describe_codex_route(agent)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check', action='store_true')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--routes', action='store_true', help='Report provider hostnames, not credentials')
    parser.add_argument('--agents', default=','.join(DEFAULT_AGENTS))
    parser.add_argument('--allow-paused', default='')
    args = parser.parse_args()
    if args.check == args.apply:
        parser.error('Choose exactly one of --check or --apply')
    if Path(sys.executable).resolve() != Path('/usr/bin/python3').resolve():
        raise SystemExit('Use /usr/bin/python3 -I to invoke the installed helper')
    trusted_program()
    allow = [name for name in args.allow_paused.split(',') if name]
    run(apply=args.apply, agents=select_agents(args.agents.split(','), allow), routes=args.routes)


if __name__ == '__main__':
    main()
