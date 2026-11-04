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
import stat
import subprocess
import sys
import tempfile
import threading
from urllib.parse import urljoin, urlsplit, urlunsplit

from agentporter.scoped_https import ScopedPublicHTTPSPolicy, _PinnedPublicHTTPS

LOG = logging.getLogger("agentporter.https_download")
RECEIPT_SUFFIX = '.receipt.json'
MAX_RECEIPT_BYTES = 8192
MAX_DOWNLOAD_BYTES = 16 * 1024 * 1024
SAFE_RECEIPT_HEADERS = {'content-type', 'content-length', 'etag', 'last-modified'}


def _safe_redirect_target(source_url, location):
    """Return a credential- and query-free HTTPS target suitable for diagnostics."""
    if not isinstance(location, str) or not location or len(location) > 2048:
        return None
    if any(ord(character) < 0x21 or ord(character) > 0x7e for character in location):
        return None
    try:
        target = urlsplit(urljoin(source_url, location))
        host = target.hostname
        port = target.port
    except (TypeError, ValueError):
        return None
    if target.scheme.lower() != 'https' or not host or target.username or target.password:
        return None
    if port not in (None, 443):
        return None
    return urlunsplit(('https', host.lower(), target.path or '/', '', ''))


def checksum(value):
    if value is not None and (not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value)):
        raise ValueError("Expected SHA256 must be 64 lowercase hexadecimal characters")
    return value


def _filename(name):
    if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', name)
            or name.endswith(RECEIPT_SUFFIX)):
        raise ValueError('Destination must be a simple non-hidden filename without the reserved receipt suffix')
    return name


def _unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate acquisition receipt key')
        result[key] = value
    return result


def _worker_receipt(value, max_bytes, expected_sha256):
    required = {'http_status', 'bytes', 'sha256', 'expected_sha256_verified'}
    if (not isinstance(value, dict) or not required <= set(value)
            or set(value) - required - {'headers', 'retrieved_at'}
            or type(value.get('bytes')) is not int or not 0 <= value['bytes'] <= max_bytes
            or type(value.get('http_status')) is not int or value['http_status'] != 200
            or value.get('expected_sha256_verified') is not (expected_sha256 is not None)):
        raise ValueError('Invalid worker acquisition receipt')
    actual = checksum(value.get('sha256'))
    if actual is None or expected_sha256 is not None and not hmac.compare_digest(actual, expected_sha256):
        raise ValueError('Invalid worker checksum receipt')
    headers = value.get('headers', {})
    if (not isinstance(headers, dict) or set(headers) - SAFE_RECEIPT_HEADERS
            or any(not isinstance(text, str) or len(text.encode('utf-8')) > 512
                   or any(ord(c) < 32 or ord(c) == 127 for c in text) for text in headers.values())):
        raise ValueError('Invalid worker acquisition receipt headers')
    timestamp = value.get('retrieved_at', datetime.datetime.now(datetime.timezone.utc).isoformat())
    if not isinstance(timestamp, str) or not 1 <= len(timestamp) <= 64:
        raise ValueError('Invalid worker acquisition receipt timestamp')
    try:
        parsed = datetime.datetime.fromisoformat(timestamp)
    except ValueError as exc:
        raise ValueError('Invalid worker acquisition receipt timestamp') from exc
    if parsed.utcoffset() != datetime.timedelta(0):
        raise ValueError('Acquisition receipt timestamp must include UTC timezone')
    return {**value, 'headers': dict(headers), 'retrieved_at': timestamp}


def _receipt_bytes(receipt, directory, name, expected):
    fields = {'schema_version', 'workspace_id', 'source_url', 'path', 'http_status', 'bytes', 'sha256',
              'expected_sha256', 'expected_sha256_verified', 'headers', 'retrieved_at',
              'training_eligible', 'historical_identity_verified', 'file_integrity_status',
              'historical_validation_status'}
    if (not isinstance(receipt, dict) or set(receipt) != fields
            or type(receipt.get('schema_version')) is not int or receipt['schema_version'] != 1
            or not isinstance(receipt.get('workspace_id'), str)
            or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}', receipt['workspace_id'])
            or not isinstance(receipt.get('source_url'), str) or not 1 <= len(receipt['source_url']) <= 2048
            or not receipt['source_url'].startswith('https://')
            or any(ord(c) < 32 or ord(c) == 127 for c in receipt['source_url'])
            or receipt.get('path') != directory + '/' + name
            or receipt.get('training_eligible') is not False
            or receipt.get('historical_identity_verified') is not False
            or receipt.get('file_integrity_status') != 'sha256_verified'
            or receipt.get('historical_validation_status') != 'not_verified'):
        raise ValueError('Invalid durable acquisition receipt')
    external = checksum(receipt['expected_sha256'])
    metadata = _worker_receipt({key: receipt[key] for key in (
        'http_status', 'bytes', 'sha256', 'expected_sha256_verified', 'headers', 'retrieved_at')},
        MAX_DOWNLOAD_BYTES, external)
    if metadata['bytes'] != expected['bytes'] or metadata['sha256'] != expected['sha256']:
        raise ValueError('Durable receipt differs from acquired artifact')
    body = (json.dumps(receipt, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')
    if len(body) > MAX_RECEIPT_BYTES:
        raise ValueError('Acquisition receipt exceeds bounded metadata budget')
    return body


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
            event = {'event': 'download_http_rejected', 'host': host, 'http_status': response.status}
            if host == 'packagemanager.posit.co' and 300 <= response.status < 400:
                locations = [value for key, value in response.getheaders() if key.lower() == 'location']
                if len(locations) == 1:
                    target = _safe_redirect_target(url, locations[0])
                    if target is not None:
                        event['redirect_target'] = target
            LOG.warning(json.dumps(event))
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
            raise ValueError("Download SHA256 differs from caller-supplied expected digest")
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


def publish(workspace_path, directory, name, source, expected, *, receipt=None):
    """Publish verified bytes and optionally their durable receipt without replacement.

    Both anonymous files are synced before linking; the receipt is linked first.
    Success requires both links and a synced
    directory. A process/power failure between links can leave an orphan receipt;
    it describes the intended artifact, not a publication or historical verdict.
    Caught failures preserve published names for inspection; staging is closed
    without unlinking any mutable workspace pathname.
    """
    _filename(name)
    # Directory comes only from the independently loaded owner approval.
    if not re.fullmatch(r'data-raw/cran-history/reports/[A-Za-z0-9][A-Za-z0-9._-]{0,100}/downloads', directory):
        raise PermissionError("Unapproved acquisition destination")
    if (not isinstance(expected, dict) or type(expected.get('bytes')) is not int
            or not 0 <= expected['bytes'] <= MAX_DOWNLOAD_BYTES
            or checksum(expected.get('sha256')) is None):
        raise ValueError('Invalid acquired artifact size/checksum')
    receipt_body = None if receipt is None else _receipt_bytes(receipt, directory, name, expected)
    receipt_name = name + RECEIPT_SUFFIX
    directory_fd = os.open(workspace_path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    staged = []
    linked = []
    committed = False

    def stage():
        # Anonymous inodes require no pathname cleanup, even if a workspace
        # writer races publication. Unsupported filesystems fail closed.
        fd = os.open('.', os.O_RDWR | os.O_TMPFILE, 0o600, dir_fd=directory_fd)
        staged.append(fd)
        return fd

    try:
        for component in directory.split('/'):
            try:
                os.mkdir(component, mode=0o755, dir_fd=directory_fd)
            except FileExistsError:
                pass
            else:
                os.fsync(directory_fd)
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory_fd)
            os.close(directory_fd); directory_fd = child
        if max(len(name), len(receipt_name) if receipt_body is not None else 0) > os.fpathconf(directory_fd, 'PC_NAME_MAX'):
            raise ValueError('Acquisition filename exceeds filesystem name limit')
        # Refuse even dangling symlinks before spooling. Atomic link() below
        # repeats this no-overwrite guarantee against concurrent publishers.
        for filename in (name, receipt_name) if receipt_body is not None else (name,):
            try:
                os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise FileExistsError('Acquisition destination already exists: ' + filename)
        fd = stage()
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
        publications = [(fd, name)]
        if receipt_body is not None:
            receipt_fd = stage()
            with os.fdopen(receipt_fd, 'wb', closefd=False) as target:
                target.write(receipt_body)
                target.flush()
                os.fsync(receipt_fd)
            publications.insert(0, (receipt_fd, receipt_name))
        for fd, filename in publications:
            # linkat follows only our process-owned descriptor source. The
            # destination remains atomic and no-overwrite, including symlinks.
            os.link('/proc/self/fd/' + str(fd), filename,
                    src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=True)
            linked.append(filename)
        os.fsync(directory_fd)
        committed = True
        relative = directory + '/' + name
        if receipt_body is None:
            return relative
        return {'path': relative, 'receipt_path': directory + '/' + receipt_name,
                'receipt_sha256': hashlib.sha256(receipt_body).hexdigest()}
    finally:
        try:
            if not committed and linked:
                # No stat/unlink sequence can conditionally delete an inode
                # atomically. Preserve published names rather than risk deleting
                # a newer owner's file. A partial pair is never success.
                LOG.error('Acquisition publication incomplete; preserved paths: %s', linked)
                raise OSError('Acquisition publication failed; inspect preserved paths and audit log')
        finally:
            for fd in staged:
                os.close(fd)
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
        _filename(filename)
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
                    receipt = _worker_receipt(json.loads(result.stdout, object_pairs_hook=_unique_json),
                                              max_bytes, expected_sha256)
                    receipt.update(schema_version=1, workspace_id=workspace_id,
                                   path=grant['directory'] + '/' + filename, source_url=url,
                                   expected_sha256=expected_sha256, training_eligible=False,
                                   historical_identity_verified=False, file_integrity_status='sha256_verified',
                                   historical_validation_status='not_verified')
                    publication = publish(ws.path, grant['directory'], filename, spool, receipt, receipt=receipt)
                    receipt.update(publication)
                    LOG.info(json.dumps({'event': 'download_result', 'workspace_id': workspace_id,
                        'host': host, 'url_sha256': url_hash, 'sha256': receipt['sha256'], 'bytes': receipt['bytes'],
                        'receipt_path': receipt['receipt_path'], 'receipt_sha256': receipt['receipt_sha256']}))
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
