#!/usr/bin/env python3
"""Recoverably retire inactive CLI trees without changing selected code."""
from pathlib import Path
import datetime
import fcntl
import hashlib
import json
import os
import subprocess

assert os.getuid() == 0
BASE = Path('/opt/agentporter-bcc')
ROOT = Path('/var/lib/agent-clis')
PROTECTED = tuple(f'consolidation-20261113-{generation}-{role}'
                  for generation in ('15', '16') for role in ('gateway', 'worker'))
UNITS = ('agentporter-bcc-gateway.service', 'agentporter-bcc-worker.service',
         'agentporter-bcc-project-views.service',
         'agentporter-bcc-credential-broker.service', 'agentporter-qman.service')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def services():
    result = {}
    for unit in UNITS:
        raw = subprocess.check_output(['systemctl', 'show', unit, '-p',
                                      'MainPID,ActiveState,SubState,Type'], text=True)
        values = dict(line.split('=', 1) for line in raw.splitlines() if '=' in line)
        assert values['ActiveState'] == 'active', unit
        assert int(values['MainPID']) > 0 or (values['Type'] == 'oneshot'
                                              and values['SubState'] == 'exited'), unit
        result[unit] = values
    return result


RESTORE = r'''#!/usr/bin/env python3
from pathlib import Path
import fcntl,json,os
assert os.getuid()==0
base=Path(__file__).resolve().parent
record=json.loads((base/'RETIREMENT.json').read_text())
assert record['phase']=='retired'
with open('/run/lock/bcc-shared-cli.lock','a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 for row in record['entries']:
  source=Path(row['source']);archived=Path(row['archive'])
  assert source.is_relative_to('/opt/agentporter-bcc') and archived.is_relative_to(base/'code')
  assert not source.exists() and archived.is_dir() and archived.lstat().st_ino==row['identity'][1]
 for row in record['entries']:
  source=Path(row['source']);source.parent.mkdir(parents=True,exist_ok=True)
  os.rename(row['archive'],source)
 record['phase']='restored'
 (base/'RETIREMENT.json').write_text(json.dumps(record,sort_keys=True,indent=2)+'\n')
 print('Retired CLI directories restored; shared CLI selection unchanged.')
'''


with open('/run/lock/bcc-shared-cli.lock', 'a') as lock:
    fcntl.flock(lock, fcntl.LOCK_EX)
    selected = Path('/opt/agent-clis/current').resolve(strict=True)
    selected_digest = digest(selected / 'MANIFEST.json')
    manifests = {name: digest(BASE / 'releases' / name / 'RELEASE.json') for name in PROTECTED}
    service_before = services()
    sources = sorted(p / 'cli' for p in (BASE / 'releases').iterdir()
                     if p.is_dir() and (p / 'cli').is_dir())
    legacy = BASE / 'shared-cli/codex-0.167.2'
    if legacy.exists():
        sources.append(legacy)
    assert len(sources) == 46, 'Retirement inventory changed; inspect before continuing'
    for path in sources:
        info = path.lstat()
        assert path.is_dir() and not path.is_symlink() and info.st_uid == 0
        assert not info.st_mode & 0o022 and info.st_dev == ROOT.stat().st_dev
        assert not any(path.is_relative_to(BASE / 'releases' / name) for name in PROTECTED)
    excluded, pid = set(), os.getpid()
    while pid > 0 and pid not in excluded:
        excluded.add(pid)
        try:
            pid = int(Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()[1])
        except (OSError, ValueError):
            break
    for proc in Path('/proc').iterdir():
        if not proc.name.isdigit() or int(proc.name) in excluded:
            continue
        for field in ('cmdline', 'environ', 'maps'):
            try:
                raw = (proc / field).read_bytes()
            except OSError:
                continue
            assert not any(str(path).encode() in raw for path in sources), 'Live CLI reference retained'
        for field in ('exe', 'cwd', 'root'):
            try:
                value = os.readlink(proc / field)
            except OSError:
                continue
            assert not any(value == str(path) or value.startswith(str(path) + '/')
                           for path in sources), 'Live CLI executable/root retained'
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    archive = ROOT / ('retired-agentporter-cli-' + stamp)
    archive.mkdir(mode=0o700)
    entries = []
    for path in sources:
        info = path.lstat()
        manifest = path.parent / 'RELEASE.json' if path.name == 'cli' else None
        entries.append({'source': str(path), 'archive': str(archive / 'code' / path.relative_to(BASE)),
                        'identity': [info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode],
                        'historical_manifest': str(manifest) if manifest and manifest.exists() else None,
                        'historical_manifest_sha256': digest(manifest) if manifest and manifest.exists() else None})
    record = {'phase': 'prepared', 'archive': str(archive), 'entries': entries, 'moved': [],
              'selected_cli': str(selected), 'selected_manifest_sha256': selected_digest,
              'protected_release_manifests': manifests, 'service_state_before': service_before,
              'recovery_limit': 'Older historical releases require archived CLI restoration before replay; generation15/16 and current shared CLI are unchanged.'}

    def save():
        pending = archive / 'RETIREMENT.pending'
        pending.write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
        pending.chmod(0o600)
        os.replace(pending, archive / 'RETIREMENT.json')

    (archive / 'RESTORE.py').write_text(RESTORE)
    (archive / 'RESTORE.py').chmod(0o500)
    save()
    try:
        for entry in entries:
            source, destination = Path(entry['source']), Path(entry['archive'])
            destination.parent.mkdir(parents=True, exist_ok=True)
            assert not destination.exists()
            os.rename(source, destination)
            assert destination.lstat().st_ino == entry['identity'][1]
            record['moved'].append(entry['source'])
            save()
        assert all(not Path(e['source']).exists() and Path(e['archive']).is_dir() for e in entries)
        assert Path('/opt/agent-clis/current').resolve(strict=True) == selected
        assert digest(selected / 'MANIFEST.json') == selected_digest
        assert all(digest(BASE / 'releases' / name / 'RELEASE.json') == value for name, value in manifests.items())
        assert services() == service_before
        assert all(digest(Path(e['historical_manifest'])) == e['historical_manifest_sha256']
                   for e in entries if e['historical_manifest'])
        record.update(phase='retired', retired_count=len(entries), selected_cli_unchanged=True,
                      protected_releases_unchanged=True, services_unchanged=True)
        save()
    except BaseException:
        for entry in reversed(entries):
            source, destination = Path(entry['source']), Path(entry['archive'])
            if not source.exists() and destination.exists():
                os.rename(destination, source)
        record['phase'] = 'rolled_back'
        save()
        raise
    print(json.dumps({'phase': record['phase'], 'retired_directories': len(entries),
                      'archive': str(archive), 'selected_cli_unchanged': True,
                      'generation15_16_unchanged': True, 'services_unchanged': True,
                      'actual_update_triggered': False,
                      'historical_recovery_requires_cli_restoration': True,
                      'restore_command': 'sudo /usr/bin/python3 -I -B ' + str(archive / 'RESTORE.py')}, indent=2))
