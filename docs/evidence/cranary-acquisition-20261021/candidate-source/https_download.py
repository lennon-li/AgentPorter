"""Fixed-purpose, owner-approved binary acquisition, never shell networking.

The trusted worker reopens the private approval, writes a passed private spool
descriptor and returns only bounded metadata. Publication is no-overwrite,
descriptor-relative and restricted to the owner's research receipt directory.
"""
from __future__ import annotations

import argparse
from contextlib import nullcontext
import datetime
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import threading

from agentporter.scoped_https import ScopedPublicHTTPSPolicy, _PinnedPublicHTTPS

LOG = logging.getLogger("agentporter.https_download")


def checksum(value):
    if value is not None and (not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value)):
        raise ValueError("Expected SHA256 must be 64 lowercase hexadecimal characters")
    return value


def stream_download(policy, workspace_id, url, output, *, expected_sha256=None,
                    max_bytes=16 * 1024 * 1024, timeout_seconds=60,
                    connection_factory=_PinnedPublicHTTPS):
    checksum(expected_sha256)
    host, target, grant = policy.authorize_download(workspace_id, url)
    if type(max_bytes) is not int or not 1 <= max_bytes <= grant['max_response_bytes']:
        raise ValueError("Requested byte limit exceeds owner download approval")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= grant['timeout_seconds']:
        raise ValueError("Requested timeout exceeds owner download approval")
    digest = hashlib.sha256(); size = 0
    connection = connection_factory(host, timeout=timeout_seconds)
    try:
        connection.request("GET", target, headers={
            "User-Agent": "AgentPorter-Acquisition/1.0", "Accept": "application/octet-stream, */*",
            "Accept-Encoding": "identity", "Connection": "close"})
        response = connection.getresponse()
        # No redirects, partial responses, automatic decompression or credentials.
        if response.status != 200:
            LOG.warning(json.dumps({'event': 'download_http_rejected', 'host': host,
                                    'http_status': response.status}))
            raise PermissionError("Acquisition requires HTTP 200; redirects/partial responses denied")
        headers = response.getheaders()
        encodings = [v.lower().strip() for k, v in headers if k.lower() == 'content-encoding']
        if encodings and encodings != ['identity']:
            raise ValueError("Encoded transfer body is not permitted")
        lengths = [v for k, v in headers if k.lower() == 'content-length']
        transfers = [v.lower().strip() for k, v in headers if k.lower() == 'transfer-encoding']
        if (len(lengths) > 1 or lengths and not re.fullmatch('[0-9]{1,12}', lengths[0])
                or lengths and transfers or transfers and transfers != ['chunked']):
            raise ValueError("Ambiguous response framing")
        declared = int(lengths[0]) if lengths else None
        if declared is not None and declared > max_bytes:
            raise ValueError("Declared download size exceeds byte budget")
        while True:
            block = response.read(min(65536, max_bytes - size + 1))
            if not block:
                break
            size += len(block)
            if size > max_bytes:
                raise ValueError("Download exceeds byte budget")
            digest.update(block); output.write(block)
        if declared is not None and size != declared:
            raise ValueError("Incomplete download body")
        actual = digest.hexdigest()
        if expected_sha256 is not None and not hmac.compare_digest(expected_sha256, actual):
            raise ValueError("Download SHA256 differs from independently supplied expected digest")
        safe = {}
        for name, value in headers:
            name = name.lower()
            if name in {'content-type', 'content-length', 'etag', 'last-modified'}:
                if len(value.encode('utf-8')) > 512 or any(ord(c) < 32 or ord(c) == 127 for c in value):
                    raise ValueError("Unsafe download receipt header")
                if name in safe:
                    raise ValueError("Duplicate download receipt header")
                safe[name] = value
        output.flush()
        return {'http_status': 200, 'bytes': size, 'sha256': actual,
                'expected_sha256_verified': expected_sha256 is not None,
                'headers': safe, 'retrieved_at': datetime.datetime.now(datetime.timezone.utc).isoformat()}
    finally:
        connection.close()


def publish(workspace_path, directory, name, source, expected):
    if not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', name):
        raise ValueError("Destination must be a simple non-hidden filename")
    # Directory comes only from the independently loaded owner approval.
    if not re.fullmatch(r'data-raw/cran-history/reports/[A-Za-z0-9][A-Za-z0-9._-]{0,100}/downloads', directory):
        raise PermissionError("Unapproved acquisition destination")
    directory_fd = os.open(workspace_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    temporary = '.acquire-' + secrets.token_hex(16)
    created = False
    try:
        for component in directory.split('/'):
            try:
                os.mkdir(component, mode=0o755, dir_fd=directory_fd)
            except FileExistsError:
                pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            os.close(directory_fd); directory_fd = child
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
        created = True
        try:
            digest = hashlib.sha256(); size = 0; source.seek(0)
            with os.fdopen(fd, 'wb', closefd=False) as target:
                while block := source.read(65536):
                    size += len(block)
                    if size > expected['bytes']:
                        raise ValueError("Spool size differs from worker receipt")
                    digest.update(block); target.write(block)
                if size != expected['bytes'] or digest.hexdigest() != expected['sha256']:
                    raise ValueError("Spool checksum differs from worker receipt")
                target.flush(); os.fsync(fd)
            # Atomic, no replacement, no following existing destination links.
            os.link(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
            os.fsync(directory_fd)
        finally:
            os.close(fd)
        return directory + '/' + name
    finally:
        if created:
            os.unlink(temporary, dir_fd=directory_fd)
        os.close(directory_fd)


def create_https_download_tool(registry, policy, state_dir, *, resources=None, slot=None):
    concurrent = threading.BoundedSemaphore(1)

    def https_download(workspace_id, url, filename, expected_sha256=None,
                       max_bytes=16 * 1024 * 1024, timeout_seconds=60):
        ws = registry.get(workspace_id)
        if not ws.writable or not ws.allow_execute:
            raise PermissionError("Workspace does not allow acquisition")
        host, _, grant = policy.authorize_download(workspace_id, url)
        checksum(expected_sha256)
        if not isinstance(filename, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', filename):
            raise ValueError("Destination must be a simple non-hidden filename")
        if type(max_bytes) is not int or not 1 <= max_bytes <= grant['max_response_bytes']:
            raise ValueError("Invalid download byte budget")
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= grant['timeout_seconds']:
            raise ValueError("Invalid download time budget")
        if not concurrent.acquire(blocking=False):
            raise PermissionError("Acquisition capacity exhausted")
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        LOG.info(json.dumps({'event': 'download_start', 'workspace_id': workspace_id,
                             'host': host, 'url_sha256': url_hash, 'max_bytes': max_bytes}))
        try:
            with slot() if slot is not None else nullcontext():
                with tempfile.TemporaryFile(dir=state_dir) as spool:
                    cmd = [sys.executable, '-I', '-m', 'agentporter.https_download',
                           '--config-dir', str(policy.config_dir), '--workspace-id', workspace_id,
                           '--url', url, '--output-fd', str(spool.fileno()),
                           '--max-bytes', str(max_bytes), '--timeout', str(timeout_seconds)]
                    if expected_sha256 is not None:
                        cmd += ['--expected-sha256', expected_sha256]
                    lease = resources.create() if resources is not None else None
                    try:
                        result = subprocess.run(lease.command(cmd) if lease else cmd, cwd='/',
                            env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'HOME': '/nonexistent'},
                            pass_fds=(spool.fileno(),), stdin=subprocess.DEVNULL,
                            capture_output=True, timeout=timeout_seconds, check=False)
                    finally:
                        if lease is not None:
                            lease.close()
                    if result.returncode or len(result.stdout) > 4096 or len(result.stderr) > 4096:
                        LOG.warning(json.dumps({'event': 'download_worker_rejected',
                            'workspace_id': workspace_id, 'host': host, 'url_sha256': url_hash,
                            'returncode': result.returncode,
                            'diagnostic': result.stderr[:4096].decode('utf-8', errors='replace')}))
                        raise ValueError('Scoped acquisition failed; inspect bounded audit log')
                    receipt = json.loads(result.stdout)
                    if (not isinstance(receipt, dict) or type(receipt.get('bytes')) is not int
                            or not 0 <= receipt['bytes'] <= max_bytes
                            or receipt.get('http_status') != 200
                            or receipt.get('expected_sha256_verified') is not (expected_sha256 is not None)):
                        raise ValueError('Invalid worker acquisition receipt')
                    checksum(receipt.get('sha256'))
                    if receipt.get('sha256') is None or expected_sha256 is not None and receipt['sha256'] != expected_sha256:
                        raise ValueError('Invalid worker checksum receipt')
                    relative = publish(ws.path, grant['directory'], filename, spool, receipt)
                    receipt.update(workspace_id=workspace_id, path=relative, source_url=url,
                                   training_eligible=False, historical_identity_verified=False)
                    LOG.info(json.dumps({'event': 'download_result', 'workspace_id': workspace_id,
                        'host': host, 'url_sha256': url_hash, 'sha256': receipt['sha256'], 'bytes': receipt['bytes']}))
                    return receipt
        except BaseException as exc:
            LOG.warning(json.dumps({'event': 'download_failed', 'workspace_id': workspace_id,
                                   'host': host, 'url_sha256': url_hash, 'error_type': type(exc).__name__}))
            raise
        finally:
            concurrent.release()
    return https_download


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    for name in ('config-dir', 'workspace-id', 'url'):
        parser.add_argument('--' + name, required=True)
    for name in ('output-fd', 'max-bytes', 'timeout'):
        parser.add_argument('--' + name, required=True, type=int)
    parser.add_argument('--expected-sha256')
    args = parser.parse_args()
    try:
        if args.output_fd < 3 or not stat.S_ISREG(os.fstat(args.output_fd).st_mode):
            raise ValueError('Private spool descriptor required')
        policy = ScopedPublicHTTPSPolicy(args.config_dir)
        with os.fdopen(args.output_fd, 'wb', closefd=False) as output:
            result = stream_download(policy, args.workspace_id, args.url, output,
                expected_sha256=args.expected_sha256, max_bytes=args.max_bytes, timeout_seconds=args.timeout)
        sys.stdout.write(json.dumps(result) + '\n')
        return 0
    except Exception as exc:
        sys.stderr.write('Scoped acquisition denied: ' + type(exc).__name__ + '\n')
        return 77


if __name__ == '__main__':
    raise SystemExit(main())
