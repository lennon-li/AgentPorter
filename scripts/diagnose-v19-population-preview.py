#!/usr/bin/python3
"""Read-only diagnosis of the saved v19 acquisition/consumer attempt.

No requests, credentials, package execution, file publication or source edits.
Read only the bounded verifier log and its two quarantined downloaded files.
"""
import collections
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import pwd
import re
import stat

EVIDENCE = Path('/tmp/a7dev-cranary-acquisition-verification-cma155n3/results.json')
WORKSPACE = Path('/home/operator/repos/cranary')
DOWNLOADS = WORKSPACE / 'data-raw/cran-history/reports/2026-10-21-authorized-acquisition/downloads'
LIMIT = 16 * 1024**2
EXPANDED = 64 * 1024**2


def read_file(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        assert stat.S_ISREG(info.st_mode) and info.st_size <= limit
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            body = stream.read(limit + 1)
        assert len(body) <= limit
        return body
    finally:
        os.close(fd)


def parse_dcf(raw):
    text = raw.decode('utf-8')
    assert '\x00' not in text
    records, record, previous = [], {}, None
    for line in (text.replace('\r\n', '\n') + '\n\n').split('\n'):
        if not line.strip():
            if record:
                records.append(record)
            record, previous = {}, None
        elif line.startswith((' ', '\t')):
            assert previous, 'Orphan DCF continuation'
            record[previous] += '\n' + line.strip()
        else:
            assert ':' in line
            field, value = line.split(':', 1)
            assert re.fullmatch(r'[A-Za-z][A-Za-z0-9/._-]*', field)
            assert field not in record, 'Duplicate DCF field'
            record[field] = value.strip()
            previous = field
    return records


def main():
    assert os.geteuid() == pwd.getpwnam('agentporter-dev').pw_uid
    calls = json.loads(read_file(EVIDENCE, 8 * 1024**2))
    downloads = [r['data'] for r in calls if r['tool'] == 'https_download' and not r['is_error']]
    assert len(downloads) == 2
    for row in downloads:
        path = WORKSPACE / row['path']
        assert path.parent == DOWNLOADS and path.resolve().parent == DOWNLOADS.resolve()
        body = read_file(path, LIMIT)
        assert len(body) == row['bytes']
        assert hashlib.sha256(body).hexdigest() == row['sha256']
        if row['source_url'].startswith('https://packagemanager.posit.co/'):
            with gzip.GzipFile(fileobj=io.BytesIO(body)) as stream:
                expanded = stream.read(EXPANDED + 1)
            assert len(expanded) <= EXPANDED
        else:
            assert row['expected_sha256_verified']
            assert row['sha256'] == 'f9859ceb56997d30041c90f45073e59afd32f8ba985e0c6d500a6f49a2d98a42'
    records = parse_dcf(expanded)
    groups = collections.defaultdict(list)
    for row in records:
        name, version = row.get('Package', ''), row.get('Version', '')
        assert re.fullmatch(r'[A-Za-z][A-Za-z0-9.]*', name)
        assert re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.+_-]*', version)
        groups[name.casefold()].append({'package': name, 'version': version})
    collisions = {k: rows for k, rows in groups.items() if len(rows) > 1}
    preview = WORKSPACE / 'data-raw/cran-history/reports/2026-10-19-laya-dataset-source-research/preview_historical_cran_population.py'
    deployments = [r['data'] for r in calls if r['tool'] == 'server_deploy_info' and not r['is_error']]
    summary = {'evidence': str(EVIDENCE), 'downloads_saved_bytes_verified': True,
        'downloads': downloads, 'package_records': len(records), 'normalized_families': len(groups),
        'collision_family_count': len(collisions),
        'collision_sample': dict(list(sorted(collisions.items()))[:100]),
        'expanded_sha256': hashlib.sha256(expanded).hexdigest(),
        'consumer_sha256': hashlib.sha256(read_file(preview, 1024**2)).hexdigest(),
        'deployments': [{k: d[k] for k in ('pid','loaded_fingerprint','disk_fingerprint','stale')} for d in deployments],
        'denied_calls_recorded': sum(r['is_error'] for r in calls),
        'research_files_changed': False, 'network_requests': 0}
    print(json.dumps(summary, indent=2))


if __name__ == '__main__':
    main()
