"""Archive-free transfer protocol; this trusted stdlib-only module runs over SSH."""

import ctypes
import hashlib
import io
import json
import os
import re
import signal
import stat
import sys

SOURCE_ROOT = "/home/operator/repos/cranary/data-raw/cran-history/cache/mechanical-v1-ready"
DESTINATION_ROOT = "/home/operator/laya-training/transfers"
DATA_FILES = frozenset({"dataset.jsonl", "inputs.jsonl", "manifest.json"})
ALLOWED_FILES = DATA_FILES | {"synthetic-test.txt"}
MAX_FILES = 3
MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_HEADER_BYTES = 4096


def validate_names(names, *, source="workspace"):
    allowed = DATA_FILES if source == "asgard_laya" else ALLOWED_FILES
    if (not isinstance(names, list) or not 1 <= len(names) <= MAX_FILES
            or any(not isinstance(name, str) or name not in allowed for name in names)
            or len(set(names)) != len(names)):
        raise ValueError("Invalid approved file list")


def validate_id(transfer_id):
    if not isinstance(transfer_id, str) or not re.fullmatch(r"[a-f0-9]{32}", transfer_id):
        raise ValueError("Invalid transfer ID")


def open_directory(path, *, create=False, allow_group_write=False):
    """Walk descriptors with O_NOFOLLOW: no symlink component may be followed."""
    if not os.path.isabs(path) or any(part in {".", ".."} for part in path.split("/")):
        raise ValueError("Invalid directory")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.split("/")[1:]:
            if not part:
                raise ValueError("Invalid directory")
            if create:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            info = os.fstat(child)
            unsafe_write = info.st_mode & (0o002 if allow_group_write else 0o022)
            if info.st_uid not in {0, os.getuid()} or (
                unsafe_write and not (info.st_uid == 0 and info.st_mode & stat.S_ISVTX)
            ):
                os.close(child)
                raise PermissionError("Unsafe directory ownership or permissions")
            os.close(fd)
            fd = child
        return fd
    except BaseException:
        os.close(fd)
        raise


def build_payload(root, names, transfer_id, *, source="workspace"):
    validate_names(names, source=source)
    validate_id(transfer_id)
    # Existing source repositories may be group writable; never allow world-writable source components.
    directory = open_directory(root, allow_group_write=True)
    files, chunks, total = [], [], 0
    try:
        for name in names:
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
            with os.fdopen(fd, "rb") as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_uid != os.getuid():
                    raise ValueError("Source must be a user-owned regular file, not a link")
                if before.st_size > MAX_FILE_BYTES or total + before.st_size > MAX_TOTAL_BYTES:
                    raise ValueError("Transfer byte limit exceeded")
                data = stream.read(MAX_FILE_BYTES + 1)
                after = os.fstat(stream.fileno())
                if len(data) != before.st_size or (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError("Source changed during transfer")
                total += len(data)
                files.append({"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
                chunks.append(data)
    finally:
        os.close(directory)
    header = {"version": 1, "transfer_id": transfer_id, "files": files}
    return json.dumps(header, separators=(",", ":")).encode() + b"\n" + b"".join(chunks)


def read_header(stream):
    line = stream.readline(MAX_HEADER_BYTES + 1)
    if len(line) > MAX_HEADER_BYTES or not line.endswith(b"\n"):
        raise ValueError("Invalid transfer header")
    header = json.loads(line)
    if not isinstance(header, dict) or set(header) != {"version", "transfer_id", "files"} or header["version"] != 1:
        raise ValueError("Invalid transfer header")
    validate_id(header["transfer_id"])
    files = header["files"]
    if not isinstance(files, list) or any(not isinstance(item, dict) for item in files):
        raise ValueError("Invalid file metadata")
    validate_names([item.get("name") for item in files])
    total = 0
    for item in files:
        if (set(item) != {"name", "bytes", "sha256"} or type(item["bytes"]) is not int
                or not 0 <= item["bytes"] <= MAX_FILE_BYTES
                or not isinstance(item["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])):
            raise ValueError("Invalid file metadata")
        total += item["bytes"]
    if total > MAX_TOTAL_BYTES:
        raise ValueError("Transfer byte limit exceeded")
    return header


def validate_payload(payload):
    stream = io.BytesIO(payload)
    header = read_header(stream)
    for item in header["files"]:
        data = stream.read(item["bytes"])
        if len(data) != item["bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("Transfer content or checksum mismatch")
    if stream.read(1):
        raise ValueError("Unexpected transfer content")
    return header


def rename_noreplace(parent, source, destination):
    # Linux renameat2 atomically publishes the complete batch without clobbering a race winner.
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.renameat2(parent, source.encode(), parent, destination.encode(), 1) != 0:
        error = ctypes.get_errno()
        raise OSError(error, "Atomic no-overwrite publication failed")


def receive_payload(stream, root=DESTINATION_ROOT):
    header = read_header(stream)
    directory = open_directory(root, create=True)
    info = os.fstat(directory)
    if info.st_uid != os.getuid() or info.st_mode & 0o022:
        os.close(directory)
        raise PermissionError("Destination must be user-owned")
    batch = header["transfer_id"]
    stage = "." + batch + ".partial"
    stage_fd = None
    created = False
    published = False
    try:
        try:
            os.stat(batch, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("Destination exists; overwrite is not supported")
        os.mkdir(stage, mode=0o700, dir_fd=directory)
        created = True
        stage_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
        for item in header["files"]:
            fd = os.open(item["name"], os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=stage_fd)
            with os.fdopen(fd, "w+b") as target:
                left = item["bytes"]
                while left:
                    chunk = stream.read(min(left, 65536))
                    if not chunk:
                        raise ValueError("Interrupted transfer")
                    target.write(chunk)
                    left -= len(chunk)
                target.flush()
                os.fsync(target.fileno())
                target.seek(0)
                digest = hashlib.sha256()
                for chunk in iter(lambda: target.read(65536), b""):
                    digest.update(chunk)
                if digest.hexdigest() != item["sha256"]:
                    raise ValueError("Destination checksum mismatch")
        if stream.read(1):
            raise ValueError("Unexpected transfer content")
        os.fsync(stage_fd)
        rename_noreplace(directory, stage, batch)
        published = True
        os.fsync(directory)
        return {"success": True, "target": "venkata", "transfer_id": batch,
                "total_bytes": sum(item["bytes"] for item in header["files"]),
                "files": [{**item, "destination": root + "/" + batch + "/" + item["name"]}
                          for item in header["files"]]}
    finally:
        try:
            if created and not published:
                if stage_fd is not None:
                    for item in header["files"]:
                        try:
                            os.unlink(item["name"], dir_fd=stage_fd)
                        except FileNotFoundError:
                            pass
                os.rmdir(stage, dir_fd=directory)
        finally:
            if stage_fd is not None:
                os.close(stage_fd)
            os.close(directory)


def main():
    def interrupted(signum, frame):
        raise TimeoutError("Transfer interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        if sys.argv[1:] == ["source"]:
            request = json.loads(sys.stdin.buffer.read(MAX_HEADER_BYTES + 1))
            if not isinstance(request, dict) or set(request) != {"files", "transfer_id"}:
                raise ValueError("Invalid source request")
            sys.stdout.buffer.write(build_payload(SOURCE_ROOT, request["files"], request["transfer_id"], source="asgard_laya"))
        elif sys.argv[1:] == ["receive"]:
            print(json.dumps(receive_payload(sys.stdin.buffer)))
        else:
            raise ValueError("Invalid operation")
    except Exception:
        # Neither dataset contents nor raw SSH/Python exception text is a result channel.
        print(json.dumps({"success": False, "error": "remote_transfer_rejected"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
