"""Operator-scoped public HTTPS metadata fetcher for read-only research.

No network namespace escape is granted to arbitrary shell commands.
An independent owner installs the 0600 policy outside agent workspaces.
The gateway never inherits host HTTP proxy settings or client credentials.
"""
from __future__ import annotations

import hashlib
import datetime
import http.client
import ipaddress
import json
import logging
import os
import socket
import ssl
import subprocess
import sys
import stat
import re
from pathlib import Path
from urllib.parse import urlsplit, unquote

import yaml
from yaml.events import AliasEvent
from agentporter.action_policy import _UniqueKeysLoader


class _NoAliasOwnerPolicyLoader(_UniqueKeysLoader):
    """Operator approval data must contain explicit unique scalar mappings.

    YAML anchors/aliases are unnecessary and can expand a tiny policy file
    into a large in-memory object. Deny them before constructing nodes.
    """

    def compose_node(self, parent, index):
        if self.check_event(AliasEvent):
            raise ValueError("Operator HTTPS approval must not use YAML aliases")
        return super().compose_node(parent, index)


logger = logging.getLogger("agentporter.scoped_https")

PROPOSED_CRANARY_HOSTS = frozenset({
    "api.github.com",
    "cran.r-project.org",
    "cran-archive.r-project.org",
    "bioconductor.org",
})
REVIEWED_PUBLIC_HTTPS_HOSTS = PROPOSED_CRANARY_HOSTS | {"packagemanager.posit.co"}
MAX_BYTES_CAP = 1024 * 1024
TIMEOUT_CAP = 20
DOWNLOAD_BYTES_CAP = 16 * 1024 * 1024
DOWNLOAD_TIMEOUT_CAP = 60
SUPPORTED_METHODS = frozenset({"GET", "HEAD"})


def _download_target(host, target, *, cran_all_paths=False):
    """Historical paths by default; broader CRAN paths need owner opt-in."""
    if host == "cran.r-project.org" and cran_all_paths is True:
        if target.startswith('/') and '?' not in target:
            return
        raise PermissionError("CRAN acquisition query strings are not approved")
    if host == "packagemanager.posit.co":
        match = re.fullmatch(r"/cran/(\d{4}-\d{2}-\d{2})/src/contrib/(PACKAGES(?:\.gz)?|[A-Za-z][A-Za-z0-9.]*_[A-Za-z0-9.+_-]+\.tar\.gz)", target)
        if match:
            datetime.date.fromisoformat(match[1])
            return
    elif host == "cran.r-project.org":
        match = re.fullmatch(r"/src/contrib/Archive/([A-Za-z][A-Za-z0-9.]*)/([A-Za-z][A-Za-z0-9.]*)_[A-Za-z0-9.+_-]+\.tar\.gz", target)
        if match and match[1] == match[2]:
            return
    raise PermissionError("Download URL outside reviewed historical source paths")


def _url_parts(url: str):
    if not isinstance(url, str) or not url or len(url) > 2048:
        raise PermissionError("HTTPS URL must be nonempty and <= 2048 characters")
    if any(ord(c) < 33 or ord(c) == 127 or c == "\\" for c in url):
        raise PermissionError("Control characters and backslashes forbidden in HTTPS URL")
    try:
        parts = urlsplit(url)
        hostname = parts.hostname
    except ValueError as exc:
        raise PermissionError("Invalid HTTPS URL authority") from exc
    if (parts.scheme != "https" or not hostname
            or parts.username is not None or parts.password is not None
            or parts.fragment or parts.hostname.endswith(".")):
        raise PermissionError("Only absolute HTTPS URLs without credentials/fragments are permitted")
    try:
        if parts.port not in (None, 443):
            raise PermissionError("Only HTTPS port 443 is permitted")
    except ValueError as exc:
        raise PermissionError("Invalid HTTPS port") from exc
    host = parts.hostname.lower()
    if not host.isascii() or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for c in host):
        raise PermissionError("Invalid HTTPS hostname")
    if parts.netloc.split("@")[-1].startswith("[") or "%" in parts.netloc:
        raise PermissionError("Literal IP and encoded authority unsupported")
    if parts.query:
        forbidden = {"token", "access_token", "apikey", "api_key", "secret", "password", "auth"}
        # Decode parameter names; do not trust raw percent-encoded spelling.
        for component in parts.query.split("&"):
            raw_name = component.partition("=")[0]
            decoded = unquote(raw_name, errors="strict").lower()
            if decoded in forbidden or any(c in decoded for c in "&;="):
                raise PermissionError("URL query credentials or ambiguous encoded keys forbidden")
    target = parts.path or "/"
    if parts.query:
        target += "?" + parts.query
    return host, target


def _resolve_public_addresses(host: str, resolver=socket.getaddrinfo):
    addresses = resolver(host, 443, type=socket.SOCK_STREAM)
    if not addresses:
        raise PermissionError("Approved hostname failed DNS resolution")
    for family, socktype, proto, canon, sockaddr in addresses:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise PermissionError("Unsupported DNS address family")
        if (socktype != socket.SOCK_STREAM
                or not isinstance(sockaddr, tuple)
                or len(sockaddr) < 2
                or sockaddr[1] != 443):
            raise PermissionError("DNS result violates HTTPS TCP port 443 scope")
        literal = sockaddr[0]
        if "%" in literal:
            raise PermissionError("Scoped IPv6 address is forbidden")
        ip = ipaddress.ip_address(literal)
        if not ip.is_global:
            raise PermissionError("DNS answer is not a public IP address")
        if isinstance(ip, ipaddress.IPv6Address):
            # Even a globally assigned IPv6 address can embed a private v4
            # destination (6to4, mapped, Teredo or NAT64); reject tunnels.
            if (ip.ipv4_mapped is not None or ip.sixtofour is not None
                    or ip.teredo is not None
                    or ip in ipaddress.IPv6Network("64:ff9b::/96")
                    or ip in ipaddress.IPv6Network("64:ff9b:1::/48")):
                raise PermissionError("Embedded or translated IPv4 DNS answer forbidden")
    return addresses


class _PinnedPublicHTTPS(http.client.HTTPSConnection):
    """TLS SNI/certificate uses approved hostname; TCP connects to vetted IP."""

    def __init__(self, host: str, timeout: float, resolver=socket.getaddrinfo):
        super().__init__(host, 443, timeout=timeout, context=ssl.create_default_context())
        self._resolver = resolver

    def connect(self):
        addresses = _resolve_public_addresses(self.host, self._resolver)
        last_exc = None
        for family, socktype, proto, _, sockaddr in addresses:
            sock = socket.socket(family, socktype, proto)
            try:
                sock.settimeout(self.timeout)
                sock.connect(sockaddr)
                self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
                return
            except OSError as exc:
                last_exc = exc
                sock.close()
        if last_exc:
            raise last_exc
        raise PermissionError("No public address available")


class ScopedPublicHTTPSPolicy:
    """Load only explicitly owner-installed allowlists; missing means disabled."""

    def __init__(self, config_dir, workspace_roots=()):
        config_dir = Path(os.path.abspath(config_dir))
        for root in workspace_roots:
            root = Path(root).resolve()
            if root == config_dir or root in config_dir.parents:
                raise PermissionError("HTTPS operator policy must not be inside an agent workspace")
        directory_fd = self._open_trusted_directory(config_dir)
        if directory_fd is None:
            # Missing optional operator config means HTTPS is disabled.
            self.config_dir = config_dir
            self.scopes = {}
            return
        self.config_dir = config_dir
        try:
            self.scopes = self._read_policy(directory_fd)
        finally:
            os.close(directory_fd)

    @staticmethod
    def _open_trusted_directory(path):
        """Pin every directory component and reject writable/symlink ancestors."""
        directory_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            components = path.parts[1:]
            for index, component in enumerate(components):
                current = os.fstat(directory_fd)
                # Root-owned sticky /tmp-like directories prevent one user
                # renaming another user's entries despite mode 1777.
                sticky_root = (current.st_uid == 0
                               and bool(current.st_mode & stat.S_ISVTX))
                if (current.st_uid not in (os.getuid(), 0)
                        or (current.st_mode & 0o022 and not sticky_root)):
                    raise PermissionError("HTTPS operator policy has untrusted ancestor directory")
                try:
                    next_fd = os.open(
                        component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                        dir_fd=directory_fd)
                except FileNotFoundError:
                    if index == len(components) - 1:
                        return None
                    raise PermissionError("HTTPS operator policy ancestor is missing")
                os.close(directory_fd)
                directory_fd = next_fd
            current = os.fstat(directory_fd)
            if (current.st_uid not in (os.getuid(), 0)
                    or current.st_mode & 0o022):
                raise PermissionError("HTTPS operator config directory must be owner-owned, not group/world-writable")
            result = directory_fd
            directory_fd = -1
            return result
        finally:
            if directory_fd >= 0:
                os.close(directory_fd)

    def _read_policy(self, directory_fd):
        try:
            fd = os.open("public-https.yaml", os.O_RDONLY | os.O_NOFOLLOW,
                         dir_fd=directory_fd)
        except FileNotFoundError:
            return {}
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid not in (os.getuid(), 0)
                    or st.st_mode & 0o077):
                raise PermissionError("Public HTTPS policy must be owner-owned mode 0600")
            if st.st_size > 16_384:
                raise ValueError("Public HTTPS policy exceeds 16 KiB")
            with os.fdopen(fd, encoding="utf-8") as file:
                fd = -1
                document = yaml.load(file, Loader=_NoAliasOwnerPolicyLoader)
        finally:
            if fd >= 0:
                os.close(fd)
        if not isinstance(document, dict) or set(document) != {"version", "workspaces"}:
            raise ValueError("Public HTTPS policy requires version and workspaces")
        if type(document["version"]) is not int or document["version"] not in (1, 2):
            raise ValueError("Invalid Public HTTPS policy version")
        scopes = document["workspaces"]
        if not isinstance(scopes, dict):
            raise ValueError("Public HTTPS workspaces must be a mapping")
        if set(scopes) != {"cranary"}:
            raise ValueError("HTTPS policy must name only the cranary workspace")
        validated = {}
        for workspace, spec in scopes.items():
            keys = {"hosts", "methods", "max_response_bytes", "timeout_seconds"}
            if document["version"] == 2:
                keys.add("downloads")
            if (not isinstance(workspace, str) or not workspace
                    or not isinstance(spec, dict) or set(spec) != keys):
                raise ValueError("Invalid scoped HTTPS policy entry")
            hosts = spec["hosts"]
            methods = spec["methods"]
            if (not isinstance(hosts, list) or not hosts
                    or not all(isinstance(h, str) for h in hosts)):
                raise ValueError("HTTPS host list must contain strings")
            if len(set(hosts)) != len(hosts):
                raise ValueError("HTTPS host list must be nonempty and unique")
            if any(not isinstance(h, str) or h not in REVIEWED_PUBLIC_HTTPS_HOSTS for h in hosts):
                raise ValueError("Public HTTPS site outside reviewed R-research catalog")
            if workspace != "cranary":
                raise ValueError("Public HTTPS approval scope limited to cranary")
            if (not isinstance(methods, list) or not methods
                    or not all(isinstance(m, str) for m in methods)
                    or len(set(methods)) != len(methods)
                    or set(methods) - SUPPORTED_METHODS):
                raise ValueError("Public HTTPS methods restricted to unique GET and HEAD")
            limit = spec["max_response_bytes"]
            timeout = spec["timeout_seconds"]
            if type(limit) is not int or not 1 <= limit <= MAX_BYTES_CAP:
                raise ValueError("Public HTTPS response budget invalid")
            if type(timeout) is not int or not 1 <= timeout <= TIMEOUT_CAP:
                raise ValueError("Public HTTPS timeout invalid")
            validated[workspace] = {
                "hosts": frozenset(hosts), "methods": frozenset(methods),
                "max_response_bytes": limit, "timeout_seconds": timeout,
            }
            if document["version"] == 2:
                downloads = spec["downloads"]
                if (not isinstance(downloads, dict) or set(downloads) not in (
                        {"hosts", "directory", "max_response_bytes", "timeout_seconds"},
                        {"hosts", "directory", "max_response_bytes", "timeout_seconds", "cran_all_paths"})
                        or ('cran_all_paths' in downloads and type(downloads['cran_all_paths']) is not bool)
                        or not isinstance(downloads["hosts"], list)
                        or not downloads["hosts"]
                        or not all(isinstance(h, str) and h in hosts and h in {
                            "cran.r-project.org", "packagemanager.posit.co"} for h in downloads["hosts"])
                        or len(set(downloads["hosts"])) != len(downloads["hosts"])
                        or type(downloads["max_response_bytes"]) is not int
                        or not 1 <= downloads["max_response_bytes"] <= DOWNLOAD_BYTES_CAP
                        or type(downloads["timeout_seconds"]) is not int
                        or not 1 <= downloads["timeout_seconds"] <= DOWNLOAD_TIMEOUT_CAP):
                    raise ValueError("Invalid owner-approved download budgets/hosts")
                directory = downloads["directory"]
                # A narrow research receipt subtree, never an executable/config path.
                if (not isinstance(directory, str) or not re.fullmatch(
                        r"data-raw/cran-history/reports/[A-Za-z0-9][A-Za-z0-9._-]{0,100}/downloads", directory)):
                    raise ValueError("Download destination must be a research receipt subtree")
                validated[workspace]["downloads"] = dict(downloads)
        return validated

    def authorize(self, workspace_id, method, url):
        host, target = _url_parts(url)
        scope = self.scopes.get(workspace_id)
        if not scope or host not in scope["hosts"] or method not in scope["methods"]:
            raise PermissionError("Public HTTPS request not owner-approved for workspace, method and host")
        if host == "packagemanager.posit.co":
            _download_target(host, target)
        return host, target, scope

    def authorize_download(self, workspace_id, url):
        host, target, scope = self.authorize(workspace_id, "GET", url)
        grant = scope.get("downloads")
        if not grant or host not in grant["hosts"]:
            raise PermissionError("Binary acquisition has no independent owner approval")
        _download_target(host, target, cran_all_paths=grant.get('cran_all_paths', False))
        return host, target, grant


def _parse_curl(argv):
    """Only fixed, non-redirecting, credential-free syntax is recognized."""
    if not isinstance(argv, list) or len(argv) != 3 or argv[0] != "curl":
        raise PermissionError("Network use requires a single approved curl metadata command")
    if argv[1] == "-fsS":
        return "GET", argv[2]
    if argv[1] == "-sSI":
        return "HEAD", argv[2]
    raise PermissionError("Only curl -fsS URL or curl -sSI URL is permitted")


class ScopedPublicHTTPS:
    def __init__(self, policy, connection_factory=_PinnedPublicHTTPS):
        self.policy = policy
        self.connection_factory = connection_factory
        self.resources = None

    def run_bounded(self, workspace_id, argv, timeout_seconds=30, cwd=""):
        """Bound DNS, TCP and response wall time with an isolated fixed worker.

        The service process never waits indefinitely on system DNS resolution,
        and the subprocess has no inherited credentials, proxies or HOME.
        """
        if cwd:
            raise PermissionError("Network HTTPS cannot use custom working directory")
        method, url = _parse_curl(argv)
        host, target, scope = self.policy.authorize(workspace_id, method, url)
        timeout = min(max(1, int(timeout_seconds)), scope["timeout_seconds"])
        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
        logger.info(json.dumps({
            "event": "public_https_sync_start", "workspace_id": workspace_id,
            "host": host, "method": method, "url_sha256_prefix": url_hash,
            "timeout_seconds": timeout,
        }))
        cmd = [
            sys.executable, "-I", "-m", "agentporter.scoped_https_worker",
            "--config-dir", str(self.policy.config_dir),
            "--workspace-id", workspace_id,
            "--method", method, "--url", url, "--timeout", str(timeout),
        ]
        lease = self.resources.create() if self.resources is not None else None
        try:
            result = subprocess.run(
                lease.command(cmd) if lease else cmd, cwd="/", capture_output=True, text=True,
                timeout=timeout,
                check=False,
                env={
                    "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8", "HOME": "/nonexistent",
                },
            )
        except subprocess.TimeoutExpired:
            logger.warning(json.dumps({
                "event": "public_https_timeout", "host": host,
                "workspace_id": workspace_id, "method": method,
                "url_sha256_prefix": url_hash,
            }))
            return {"exit_code": 124, "stdout": "", "stderr": "Public HTTPS request timed out",
                    "timeout": True, "workspace_id": workspace_id}
        finally:
            if lease is not None:
                lease.close()
        logger.info(json.dumps({
            "event": "public_https_sync_result", "workspace_id": workspace_id,
            "host": host, "method": method, "url_sha256_prefix": url_hash,
            "exit_code": result.returncode,
            "stdout_bytes": len(result.stdout.encode("utf-8")),
        }))
        return {
            "exit_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr[:4096],
            "timeout": False,
            "workspace_id": workspace_id,
        }

    def run(self, workspace_id, argv, timeout_seconds=30, cwd=""):
        if cwd:
            raise PermissionError("Network HTTP broker does not accept arbitrary working directories")
        method, url = _parse_curl(argv)
        host, target, scope = self.policy.authorize(workspace_id, method, url)
        timeout = min(max(1, int(timeout_seconds)), scope["timeout_seconds"])
        limit = scope["max_response_bytes"]
        url_digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
        logger.info(json.dumps({
            "event": "public_https_attempt", "workspace_id": workspace_id,
            "host": host, "method": method, "url_sha256_prefix": url_digest,
        }))
        connection = None
        try:
            connection = self.connection_factory(host, timeout=timeout)
            connection.request(method, target, headers={
                "User-Agent": "AgentPorter-Metadata/1.0",
                "Accept": "application/json, text/html, text/plain, application/octet-stream, */*",
                "Accept-Encoding": "identity",
                "Connection": "close",
            })
            response = connection.getresponse()
            status = response.status
            if 300 <= status < 400:
                raise PermissionError("HTTP redirects not permitted; destination must be approved separately")
            if method == "HEAD":
                body = b""
            else:
                if response.length is not None and response.length > limit:
                    raise ValueError("Public HTTPS response Content-Length exceeds budget")
                body = response.read(limit + 1)
                if len(body) > limit:
                    raise ValueError("Public HTTPS response exceeds byte budget")
            if method == "HEAD":
                safe_headers = ("content-type", "content-length", "etag", "last-modified")
                # Status code is trusted numeric metadata; upstream reason
                # phrase is not. Do not reflect it into the output.
                lines = [f"HTTP/1.1 {status}"]
                remaining = limit - len(lines[0].encode("utf-8")) - 4
                if remaining < 0:
                    raise ValueError("Public HTTPS HEAD metadata exceeds byte budget")
                for key, value in response.getheaders():
                    if key.lower() not in safe_headers:
                        continue
                    if any(ord(c) < 32 or ord(c) == 127 for c in value):
                        raise ValueError("Public HTTPS HEAD metadata contains control characters")
                    line = f"{key}: {value[:512]}"
                    remaining -= len(line.encode("utf-8")) + 2
                    if remaining < 0:
                        raise ValueError("Public HTTPS HEAD metadata exceeds byte budget")
                    lines.append(line)
                stdout = "\r\n".join(lines) + "\r\n\r\n"
            else:
                stdout = body.decode("utf-8", errors="replace")
            # Malformed binary/text may expand when replacement Unicode code
            # points are re-encoded by MCP or persisted in async job logs.
            # Apply the same budget to the actual returned text bytes.
            if len(stdout.encode("utf-8")) > limit:
                raise ValueError("Public HTTPS decoded response exceeds byte budget")
            logger.info(json.dumps({
                "event": "public_https_result", "workspace_id": workspace_id,
                "host": host, "method": method, "status": status, "bytes": len(body),
            }))
            return {
                "stdout": stdout, "stderr": "" if status < 400 else f"HTTP {status}",
                "exit_code": 0 if 200 <= status < 300 else 22,
                "http_status": status, "bytes_returned": len(body),
                "timeout": False, "workspace_id": workspace_id,
            }
        except Exception as exc:
            logger.warning(json.dumps({
                "event": "public_https_denied_or_error", "workspace_id": workspace_id,
                "host": host, "method": method, "error_type": type(exc).__name__,
            }))
            raise
        finally:
            if connection is not None:
                connection.close()
