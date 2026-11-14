#!/usr/bin/env python3
"""Prepare a minimal, hash-pinned generation 17 candidate; never deploy it."""
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

REPO = Path(__file__).resolve().parents[1]
ARTIFACTS = REPO / 'artifacts/bcc-production-repair-20261114'
OVERLAY = ARTIFACTS / 'candidate-overlay.json'
OUT = ARTIFACTS / 'candidate17'
ROLLOUT = REPO / 'scripts/bcc-production-busy-rollout.py'
OLD = {role: Path(f'/opt/agentporter-bcc/releases/consolidation-20261113-16-{role}')
       for role in ('gateway', 'worker')}
SITE = Path('venv/lib/python3.13/site-packages')
CHANGED = (
    'policy_errors.py',
    'rest/routers/exec.py',
    'rest/schemas.py',
    'sandbox/workspace_transactions.py',
    'server.py',
)
EXPECTED_BASELINE_JSON_SHA256 = {
    'gateway': '3b7ca1eb64fd7fcdbc547c69a6ab2c6d13cdeaba3df4b4d78e23f41f96bf5f87',
    'worker': 'd5d87eef9c940923022ca8fc3e06a1d1fe05ab20febdd272ba45483ebbba36ba',
}
EXPECTED_OVERLAY_SHA256 = 'df4ea702c133447e61352280b09c16cc462b97418351efe9444cdd63de95343d'
EXPECTED_AFTER_SHA256 = {
    'gateway': {
        'policy_errors.py': 'e771211ee1e114a3a404e54a74a85c12758940863d929757caead2879bb97a7e',
        'rest/routers/exec.py': '9c8074622b37b7cf605321f2843ae5a159496ffded462e7465f33dac530c5c81',
        'rest/schemas.py': '144cf53dacd6979f6414919aceb46ce7511d6127cbfad245e5f1e2ff6aa87d58',
        'sandbox/workspace_transactions.py': '7d8b13b923a626ceb193946a10c19845c2188d7566183376037fae85bf0300e7',
        'server.py': '0658504ac1d5155b9fd5c4fb8f7bd41de836c534cbd525b684a91b08827ab67b',
    },
    'worker': {
        'policy_errors.py': 'e771211ee1e114a3a404e54a74a85c12758940863d929757caead2879bb97a7e',
        'rest/routers/exec.py': '9c8074622b37b7cf605321f2843ae5a159496ffded462e7465f33dac530c5c81',
        'rest/schemas.py': '144cf53dacd6979f6414919aceb46ce7511d6127cbfad245e5f1e2ff6aa87d58',
        'sandbox/workspace_transactions.py': '7d8b13b923a626ceb193946a10c19845c2188d7566183376037fae85bf0300e7',
        'server.py': 'c839fb8d15b80b2229dd60aae104e612af7927ac5517109b11d0b20a6ad8b491',
    },
}
EXPECTED_OVERLAY = [
    {
        'role': role,
        'changed_python_files': list(CHANGED),
        'existing_schema_and_server_code_ast_unchanged': True,
        'queued_admission_and_jobmanager_bytes_preserved': True,
        'production_changed': False,
    }
    for role in ('gateway', 'worker')
]
MANIFEST_MARKER = b'PARENT_SEALS_MANIFEST_SHA'
BOOTSTRAP_MARKER = b'PARENT_SEALS_BOOTSTRAP_SHA'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def require_real_path(path):
    """Reject symlinks at every candidate/release path component."""
    path = Path(path)
    for item in (path, *path.parents):
        info = item.lstat()
        if item.is_symlink():
            raise PermissionError(f'refusing symlink path: {item}')
        if item == path and not item.exists():
            raise FileNotFoundError(item)
    return path


def check_overlay():
    require_real_path(OVERLAY)
    raw = OVERLAY.read_bytes()
    if sha(raw) != EXPECTED_OVERLAY_SHA256:
        raise ValueError('candidate overlay evidence hash changed')
    if json.loads(raw) != EXPECTED_OVERLAY:
        raise ValueError('candidate overlay evidence does not match the exact generation 17 allowlist')


def baseline_files(role):
    path = ARTIFACTS / f'deployed-baseline-{role}.json'
    require_real_path(path)
    raw = path.read_bytes()
    if sha(raw) != EXPECTED_BASELINE_JSON_SHA256[role]:
        raise ValueError(f'{role}: deployed baseline evidence hash changed')
    value = json.loads(raw)
    if not isinstance(value, dict) or any(not isinstance(k, str) or not re.fullmatch(r'[A-Za-z0-9_./-]+', k)
                                           or not isinstance(v, str) or not re.fullmatch(r'[0-9a-f]{64}', v)
                                           for k, v in value.items()):
        raise ValueError(f'{role}: malformed deployed baseline evidence')
    return value


def current_release(role, baseline):
    release = OLD[role]
    require_real_path(release / 'RELEASE.json')
    release_info = (release / 'RELEASE.json').lstat()
    if release_info.st_uid != 0 or release_info.st_mode & 0o022:
        raise PermissionError(f'{role}: current release manifest custody changed')
    raw = (release / 'RELEASE.json').read_bytes()
    value = json.loads(raw)
    prefix = 'venv/lib/python3.13/site-packages/agentporter/'
    package_files = {
        path[len(prefix):]: item.get('sha256')
        for path, item in value.get('files', {}).items()
        if path.startswith(prefix) and isinstance(item, dict)
    }
    if value.get('version') != release.name or package_files != baseline:
        raise ValueError(f'{role}: current release no longer matches saved deployed baseline')
    package = release / SITE
    for relative in CHANGED:
        key = relative
        path = package / 'agentporter' / relative
        require_real_path(path)
        info = path.lstat()
        if info.st_uid != 0 or info.st_mode & 0o022:
            raise PermissionError(f'{role}/{relative}: deployed preimage custody changed')
        if sha(path.read_bytes()) != baseline.get(key):
            raise ValueError(f'{role}/{relative}: current preimage differs from saved baseline')
    return raw


def desired_bytes(role):
    source_root = ARTIFACTS / f'candidate-{role}-v2/src/agentporter'
    require_real_path(source_root)
    result = {}
    for relative in CHANGED:
        source = source_root / relative
        require_real_path(source)
        raw = source.read_bytes()
        if sha(raw) != EXPECTED_AFTER_SHA256[role][relative]:
            raise ValueError(f'{role}/{relative}: candidate afterimage hash changed')
        compile(raw, str(source), 'exec')
        result['agentporter/' + relative] = raw
    return result


def make_manifest_and_files():
    check_overlay()
    files_by_role = {}
    manifest = {'generation': 17, 'roles': {}}
    for role in OLD:
        baseline = baseline_files(role)
        base_raw = current_release(role, baseline)
        expected_files = desired_bytes(role)
        changes = {}
        for key, after in expected_files.items():
            before_sha = baseline.get(key.removeprefix('agentporter/'))
            after_sha = sha(after)
            if before_sha is None or before_sha == after_sha:
                raise ValueError(f'{role}/{key}: expected a real change from the deployed preimage')
            changes[key] = {'before_sha256': before_sha, 'after_sha256': after_sha}
        if set(changes) != {'agentporter/' + name for name in CHANGED}:
            raise ValueError(f'{role}: candidate delta is not the exact five-module allowlist')
        manifest['roles'][role] = {'base_manifest_sha256': sha(base_raw), 'files': changes}
        files_by_role[role] = expected_files
    body = (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
    files = {'MANIFEST.json': body}
    for role, modules in files_by_role.items():
        for relative, raw in modules.items():
            files[f'{role}/{relative}'] = raw
    return body, files


def ensure_candidate(files):
    if OUT.exists():
        require_real_path(OUT)
        observed = {}
        for path in OUT.rglob('*'):
            if path.is_symlink():
                raise PermissionError(f'refusing symlink in prepared candidate: {path}')
            if path.is_file():
                observed[path.relative_to(OUT).as_posix()] = path.read_bytes()
        if observed.keys() != files.keys() or any(observed[k] != v for k, v in files.items()):
            raise FileExistsError('prepared generation 17 candidate exists with different bytes')
        return
    OUT.mkdir(parents=True, mode=0o755)
    try:
        for relative, raw in files.items():
            target = OUT / relative
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            target.write_bytes(raw)
            target.chmod(0o644)
        for directory, _, _ in os.walk(OUT, topdown=False):
            Path(directory).chmod(0o755)
    except BaseException:
        # Remove only the candidate directory created by this invocation.
        import shutil
        shutil.rmtree(OUT)
        raise


def rollout_template():
    require_real_path(ROLLOUT)
    raw = ROLLOUT.read_bytes()
    if (b"MANIFEST_SHA='PARENT_SEALS_MANIFEST_SHA'" in raw
            and b"BOOTSTRAP_SHA='PARENT_SEALS_BOOTSTRAP_SHA'" in raw):
        template = raw
    else:
        manifest_match = re.search(rb"(?m)^MANIFEST_SHA='([0-9a-f]{64})'$", raw)
        bootstrap_match = re.search(rb"(?m)^BOOTSTRAP_SHA='([0-9a-f]{64})'$", raw)
        if not manifest_match or not bootstrap_match:
            raise ValueError('rollout script is neither the expected template nor sealed form')
        manifest_value = manifest_match.group(1).decode()
        bootstrap_value = bootstrap_match.group(1).decode()
        template = re.sub(
            rb"(?m)^MANIFEST_SHA='[0-9a-f]{64}'$",
            b"MANIFEST_SHA='PARENT_SEALS_MANIFEST_SHA'", raw, count=1,
        )
        template = re.sub(
            rb"(?m)^BOOTSTRAP_SHA='[0-9a-f]{64}'$",
            b"BOOTSTRAP_SHA='PARENT_SEALS_BOOTSTRAP_SHA'", template, count=1,
        )
        if sha(template) != bootstrap_value:
            raise ValueError('sealed rollout bootstrap hash does not verify')
        return template, manifest_value, bootstrap_value
    if raw.count(MANIFEST_MARKER) < 2 or raw.count(BOOTSTRAP_MARKER) < 2:
        raise ValueError('rollout template is missing self-seal markers')
    return template, None, sha(template)


def seal_rollout(manifest_raw):
    template, previous_manifest, bootstrap_sha = rollout_template()
    manifest_sha = sha(manifest_raw)
    if previous_manifest is not None and previous_manifest != manifest_sha:
        raise ValueError('sealed rollout is bound to a different candidate manifest')
    sealed = re.sub(
        rb"(?m)^MANIFEST_SHA='PARENT_SEALS_MANIFEST_SHA'$",
        f"MANIFEST_SHA='{manifest_sha}'".encode(), template, count=1,
    )
    sealed = re.sub(
        rb"(?m)^BOOTSTRAP_SHA='PARENT_SEALS_BOOTSTRAP_SHA'$",
        f"BOOTSTRAP_SHA='{bootstrap_sha}'".encode(), sealed, count=1,
    )
    if (b"MANIFEST_SHA='" + manifest_sha.encode() + b"'") not in sealed or (
            b"BOOTSTRAP_SHA='" + bootstrap_sha.encode() + b"'") not in sealed:
        raise ValueError('failed to stamp rollout self-seal')
    # Check that removing the two generated constants restores the pinned template.
    check = re.sub(
        rb"(?m)^MANIFEST_SHA='[0-9a-f]{64}'$",
        b"MANIFEST_SHA='PARENT_SEALS_MANIFEST_SHA'", sealed, count=1,
    )
    check = re.sub(
        rb"(?m)^BOOTSTRAP_SHA='[0-9a-f]{64}'$",
        b"BOOTSTRAP_SHA='PARENT_SEALS_BOOTSTRAP_SHA'", check, count=1,
    )
    if check != template or sha(check) != bootstrap_sha:
        raise ValueError('generated rollout self-seal failed verification')
    compile(sealed, str(ROLLOUT), 'exec')
    if ROLLOUT.read_bytes() != sealed:
        mode = ROLLOUT.stat().st_mode & 0o777
        fd, temporary = tempfile.mkstemp(prefix='.bcc-production-busy-', dir=ROLLOUT.parent)
        try:
            with os.fdopen(fd, 'wb') as output:
                output.write(sealed)
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, mode)
            os.replace(temporary, ROLLOUT)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
    return manifest_sha, bootstrap_sha


def main():
    if os.getuid() == 0:
        raise PermissionError('preparer must run unprivileged; root activation is a separate reviewed step')
    manifest_raw, files = make_manifest_and_files()
    ensure_candidate(files)
    manifest_sha, bootstrap_sha = seal_rollout(manifest_raw)
    print(json.dumps({
        'candidate': str(OUT),
        'manifest_sha256': manifest_sha,
        'bootstrap_sha256': bootstrap_sha,
        'generation': 17,
        'modules_per_role': len(CHANGED),
        'roles': list(OLD),
        'production_mutated': False,
    }, sort_keys=True))


if __name__ == '__main__':
    main()
