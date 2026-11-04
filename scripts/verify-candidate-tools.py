#!/usr/bin/python3
"""Execute required tools in a real offline bubblewrap namespace, no credentials.

Uses a synthetic writable project, private HOME, and the candidate's read-only
toolkit. Results establish executable/dependency behavior, not provider access.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile


def verify(toolkit, output):
    cases = {
        'rg': (['rg', 'needle', 'fixture.txt'], (0,)),
        'fd': (['fd', 'fixture'], (0,)),
        'bat': (['bat', '--plain', '--color=never', 'fixture.txt'], (0,)),
        'jq': (['jq', '.x', 'fixture.json'], (0,)),
        'yq': (['yq', '.x', 'fixture.json'], (0,)),
        'git': (['git', 'status', '--short'], (0,)),
        'delta': (['delta', '--paging=never', 'old.txt', 'new.txt'], (0, 1)),
        'hyperfine': (['hyperfine', '--runs', '1', '/usr/bin/true'], (0,)),
        'duckdb': (['duckdb', '-c', 'SELECT 42;'], (0,)),
        'just': (['just', '--list'], (0,)),
        'direnv': (['direnv', 'status'], (0,)),
        'ast-grep': (['ast-grep', '--pattern', 'print($A)', 'sample.py'], (0,)),
        'rga': (['rga', 'needle', 'fixture.txt'], (0,)),
        'dust': (['dust', '.'], (0,)),
        'eza': (['eza', '--all', '.'], (0,)),
        'difft': (['difft', 'old.txt', 'new.txt'], (0, 1)),
        'gh': (['gh', 'help', 'repo'], (0,)),
        'uv': (['uv', '--offline', 'python', 'find'], (0,)),
        'nox': (['nox', '-l', '-f', 'noxfile.py'], (0,)),
        'tox': (['tox', 'list', '-c', 'tox.ini'], (0,)),
        'Rscript': (['Rscript', '--vanilla', '-e', 'stopifnot(sum(1:3)==6); cat("R_OK\\n")'], (0,)),
        'quarto': (['quarto', 'render', 'sample.md', '--to', 'html'], (0,)),
        'node': (['node', '-p', '1+1'], (0,)),
        'npm': (['npm', '--version'], (0,)),
        'repomix': (['repomix', '--stdout', '--include', 'sample.py', '.'], (0,)),
        'code2prompt': (['code2prompt', '--output-format', 'json', '.'], (0,)),
        'codegraph': (['codegraph', 'init', '/workspace'], (0,)),
        'rtk': (['rtk', 'ls', '/workspace'], (0,)),
        'tldr': (['tldr', '--version'], (0,)),
        'scc': (['scc', '.'], (0,)),
        'ccache': (['ccache', '--show-stats'], (0,)),
        'shellcheck': (['shellcheck', 'sample.sh'], (0,)),
        'pandoc': (['pandoc', 'sample.md', '-t', 'plain'], (0,)),
        'air': (['air', 'format', '--check', 'sample.R'], (0,)),
        'lychee': (['lychee', '--offline', 'sample.md'], (0,)),
        'typos': (['typos', 'fixture.txt'], (0,)),
        'gitleaks': (['gitleaks', 'detect', '--no-git', '--source', '.', '--no-banner'], (0,)),
        'run-quiet': (['run-quiet', '/usr/bin/true'], (0,)),
    }
    policy = json.loads((toolkit.parent / 'obsidian/tools/agent-tool-policy.json').read_text())
    required = policy['tools']['required']
    if set(required) != set(cases):
        raise ValueError('Smoke cases must cover the exact canonical tool set')
    results = {}
    with tempfile.TemporaryDirectory(prefix='agentporter-tool-proof-', dir='/tmp') as directory:
        base = Path(directory)
        project, home = base / 'project', base / 'home'
        project.mkdir(); home.mkdir(mode=0o700)
        fixtures = {'fixture.txt': 'needle\n', 'fixture.json': '{"x": 42}\n',
                    'old.txt': 'before\n', 'new.txt': 'after\n', 'sample.py': 'print(42)\n',
                    'sample.R': 'x <- 1\n', 'sample.sh': '#!/bin/sh\necho ok\n',
                    'sample.md': '# Sample\n\nText.\n', 'justfile': 'hello:\n    echo hello\n',
                    'noxfile.py': 'import nox\n@nox.session\ndef test(session):\n    pass\n',
                    'tox.ini': '[tox]\nenv_list = py\n[testenv]\ncommands = python -V\n'}
        for name, content in fixtures.items():
            (project / name).write_text(content)
        subprocess.run(['/usr/bin/git','init','--quiet',str(project)], check=True)
        bwrap = ['/usr/bin/bwrap','--unshare-all','--unshare-user','--disable-userns','--assert-userns-disabled',
                 '--cap-drop','ALL','--new-session','--die-with-parent','--clearenv']
        for path in ('/usr','/lib','/lib64','/bin','/sbin','/etc/alternatives','/etc/ssl/certs'):
            if Path(path).exists():
                bwrap += ['--ro-bind',path,path]
        bwrap += ['--proc','/proc','--dev','/dev','--tmpfs','/tmp',
                  '--bind',str(project),'/workspace','--bind',str(home),'/home/worker',
                  '--ro-bind',str(toolkit),'/opt/agentporter/tools']
        if (toolkit / 'packages/Rscript').is_dir():
            bwrap += ['--ro-bind',str(toolkit / 'packages/Rscript'),'/etc/R']
        for key,value in {'HOME':'/home/worker','PATH':'/opt/agentporter/tools/bin:/usr/local/bin:/usr/bin:/bin',
                          'LANG':'C.UTF-8','LC_ALL':'C.UTF-8','GIT_OPTIONAL_LOCKS':'0','NO_COLOR':'1'}.items():
            bwrap += ['--setenv',key,value]
        bwrap += ['--chdir','/workspace','--']
        probe = subprocess.run(bwrap + ['/usr/bin/true'], capture_output=True, text=True, timeout=10)
        if probe.returncode:
            raise RuntimeError('Namespace setup failed: ' + probe.stderr[:500])
        for name in required:
            command, accepted = cases[name]
            try:
                found = subprocess.run(bwrap + ['/bin/sh','-c','command -v "$1"','tool-discovery',name],
                                       capture_output=True, text=True, timeout=10)
                if found.returncode:
                    results[name] = {'state':'missing','command':command,'reason':'No executable in sandbox PATH'}
                    print(name + ': missing', flush=True)
                    continue
                result = subprocess.run(bwrap + command, capture_output=True, text=True,
                                        timeout=90 if name in {'quarto','codegraph'} else 20,
                                        env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8'})
                success = result.returncode in accepted and not result.stderr.startswith('bwrap:')
                results[name] = {'state': 'runnable' if success else 'blocked',
                                 'command': command, 'exit_code': result.returncode,
                                 'evidence': (result.stdout + result.stderr)[:1800]}
            except (OSError, subprocess.TimeoutExpired) as error:
                results[name] = {'state':'blocked','command':command,'reason':type(error).__name__}
            print(name + ': ' + results[name]['state'], flush=True)
    output.write_text(json.dumps({'namespace':'bubblewrap --unshare-all; offline; no credentials',
                                 'toolkit':str(toolkit),'results':results}, indent=2) + '\n')
    print(f'Runnable: {sum(v["state"] == "runnable" for v in results.values())}/{len(required)}')


if __name__ == '__main__':
    if os.geteuid() == 0:
        raise SystemExit('Run tool verification unprivileged')
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--toolkit', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    verify(args.toolkit.resolve(strict=True), args.output)
