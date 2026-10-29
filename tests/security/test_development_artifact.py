"""Adversarial, synthetic-only tests of the data-only artifact boundary."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
from types import SimpleNamespace

import pytest


@pytest.fixture
def installer():
    path = Path(__file__).resolve().parents[2] / "scripts/install-development-artifact.py"
    spec = importlib.util.spec_from_file_location("artifact_security_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def builder():
    path = Path(__file__).resolve().parents[2] / "scripts/build-development-candidate.py"
    spec = importlib.util.spec_from_file_location("artifact_builder_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def repacker():
    path = Path(__file__).resolve().parents[2] / "scripts/repack-development-candidate.py"
    spec = importlib.util.spec_from_file_location("artifact_repacker_fixture", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def archive(members):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w:gz") as stream:
        for name, kind, payload in members:
            entry = tarfile.TarInfo(name)
            entry.mode = 0o7777
            entry.type = kind
            if kind == tarfile.REGTYPE:
                entry.size = len(payload)
                stream.addfile(entry, io.BytesIO(payload))
            else:
                entry.linkname = payload
                stream.addfile(entry)
    result.seek(0)
    return result


def metadata():
    return [("release", tarfile.DIRTYPE, "")] + [
        (name, tarfile.REGTYPE, b"{}")
        for name in ("runtime.json", "release-metadata.json", "release-files.json")
    ]


def unpack(installer, root, members):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
    try:
        installer.extract(archive(members), fd)
    finally:
        os.close(fd)


@pytest.mark.parametrize("name", ["/tmp/escape", "release/../escape", "release/./same", "release//same", "other"])
def test_archive_rejects_noncanonical_or_unapproved_paths(installer, tmp_path, name):
    with pytest.raises(ValueError):
        unpack(installer, tmp_path, metadata() + [(name, tarfile.REGTYPE, b"synthetic")])


@pytest.mark.parametrize("kind", [tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE])
def test_archive_rejects_hardlinks_and_special_files(installer, tmp_path, kind):
    with pytest.raises(ValueError):
        unpack(installer, tmp_path, metadata() + [("release/unsafe", kind, "release/target")])


@pytest.mark.parametrize("target", ["/etc/passwd", "../../outside", "../outside"])
def test_archive_rejects_escaping_symlink(installer, tmp_path, target):
    with pytest.raises(ValueError):
        unpack(installer, tmp_path, metadata() + [("release/link", tarfile.SYMTYPE, target)])


def test_archive_cannot_traverse_previously_extracted_symlink(installer, tmp_path):
    members = metadata() + [
        ("release/real", tarfile.DIRTYPE, ""),
        ("release/link", tarfile.SYMTYPE, "real"),
        ("release/link/payload", tarfile.REGTYPE, b"synthetic"),
    ]
    with pytest.raises(OSError):
        unpack(installer, tmp_path, members)
    assert not (tmp_path / "release/real/payload").exists()


def test_archive_rejects_duplicate_regular_member(installer, tmp_path):
    member = ("release/file", tarfile.REGTYPE, b"synthetic")
    with pytest.raises(ValueError):
        unpack(installer, tmp_path, metadata() + [member, member])


def test_archive_member_limit_is_enforced(installer, tmp_path, monkeypatch):
    monkeypatch.setattr(installer, "FILE_LIMIT", 3)
    with pytest.raises(ValueError):
        unpack(installer, tmp_path, metadata() + [("release/file", tarfile.REGTYPE, b"four")])


def test_archive_metadata_is_mandatory(installer, tmp_path):
    with pytest.raises(ValueError, match="metadata missing"):
        unpack(installer, tmp_path, [("release", tarfile.DIRTYPE, "")])


def test_archive_strips_privileged_modes_and_verifies_exact_contents(installer, tmp_path):
    payload = b"synthetic executable"
    unpack(installer, tmp_path, metadata() + [
        ("release/bin", tarfile.DIRTYPE, ""),
        ("release/bin/tool", tarfile.REGTYPE, payload),
        ("release/link", tarfile.SYMTYPE, "bin/tool"),
    ])
    tool = tmp_path / "release/bin/tool"
    assert tool.stat().st_mode & 0o7777 == 0o555
    expected = {
        "bin/tool": {"sha256": hashlib.sha256(payload).hexdigest(), "executable": True},
        "link": {"link": "bin/tool"},
    }
    try:
        installer.verify_release(tmp_path / "release", expected)
        assert (tmp_path / "release").stat().st_mode & 0o777 == 0o555
        assert (tmp_path / "release/bin").stat().st_mode & 0o777 == 0o555
    finally:
        for path in (tmp_path / "release", tmp_path / "release/bin"):
            path.chmod(0o700)


@pytest.mark.parametrize("change", ["digest", "extra", "missing", "execute"])
def test_release_verification_rejects_unapproved_contents(installer, tmp_path, change):
    release = tmp_path / "release"
    release.mkdir()
    path = release / "tool"
    path.write_bytes(b"synthetic")
    expected = {"tool": {"sha256": hashlib.sha256(b"synthetic").hexdigest(), "executable": False}}
    if change == "digest":
        path.write_bytes(b"substitution")
    elif change == "extra":
        (release / "unlisted").write_bytes(b"extra")
    elif change == "missing":
        path.unlink()
    elif change == "execute":
        path.chmod(0o700)
    try:
        with pytest.raises(ValueError):
            installer.verify_release(release, expected)
    finally:
        release.chmod(0o700)


def test_directory_pin_rejects_symlinked_ancestor(installer, tmp_path, monkeypatch):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)
    # Isolate O_NOFOLLOW from this runner's synthetic ancestor ownership.
    # The actual syscall must reach the symlink, not fail an earlier check.
    original_fstat, original_open = os.fstat, os.open
    attempted = []

    def trusted_ancestors(fd):
        fields = list(original_fstat(fd))
        fields[4] = 0
        fields[0] &= ~0o022
        return os.stat_result(fields)

    def record_open(path, flags, *args, **kwargs):
        attempted.append(str(path))
        return original_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(installer.os, "fstat", trusted_ancestors)
    monkeypatch.setattr(installer.os, "open", record_open)
    with pytest.raises(OSError):
        installer.directory(link, os.getuid())
    assert "link" in attempted


def test_directory_pin_rejects_untrusted_intermediate_owner(installer, tmp_path, monkeypatch):
    original = os.fstat

    def untrusted_ancestor(fd):
        fields = list(original(fd))
        fields[4] = 12345
        fields[0] &= ~0o022
        return os.stat_result(fields)

    monkeypatch.setattr(installer.os, "fstat", untrusted_ancestor)
    with pytest.raises(PermissionError, match="ancestor"):
        installer.directory(tmp_path, os.getuid())


@pytest.fixture
def synthetic_install_destination(installer, tmp_path, monkeypatch):
    install = tmp_path / "install"
    (install / "versions").mkdir(parents=True)
    monkeypatch.setattr(installer, "INSTALL", install)
    account = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
    monkeypatch.setattr(installer.pwd, "getpwnam", lambda name: account)
    # These tests exercise source admission, before destination trust matters.
    # No root code runs; actual destination capability pinning is tested above.
    monkeypatch.setattr(installer, "directory", lambda path, owner=0: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
    monkeypatch.setattr(installer, "extract", lambda *_: pytest.fail("Unapproved artifact reached extraction"))
    return install


def test_unapproved_archive_hash_is_rejected_before_extraction(installer, tmp_path, synthetic_install_destination):
    artifact = tmp_path / "synthetic.tgz"
    artifact.write_bytes(b"unapproved synthetic data")
    artifact.chmod(0o600)
    with pytest.raises(ValueError, match="approved SHA256"):
        installer.install(artifact, "0" * 64)
    assert not list((synthetic_install_destination / "versions").iterdir())


def test_input_fifo_is_opened_nonblocking_then_rejected(installer, tmp_path, synthetic_install_destination, monkeypatch):
    artifact = tmp_path / "synthetic-fifo"
    os.mkfifo(artifact, 0o600)
    original = os.open
    source_opened = []

    def nonblocking_source(path, flags, *args, **kwargs):
        if Path(path) == artifact:
            assert flags & os.O_NONBLOCK
            assert flags & os.O_NOFOLLOW
            source_opened.append(True)
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(installer.os, "open", nonblocking_source)
    with pytest.raises(PermissionError, match="regular file"):
        installer.install(artifact, "0" * 64)
    assert source_opened == [True]
    assert not list((synthetic_install_destination / "versions").iterdir())


@pytest.fixture
def rollback_pair(installer, tmp_path, monkeypatch):
    import json

    install, data = tmp_path / "install", tmp_path / "data"
    previous = install / "versions/20261020T010203.000001Z"
    candidate = install / "versions/20261020T010204.000002Z"
    previous.mkdir(parents=True)
    candidate.mkdir()
    (install / "current").symlink_to(candidate)
    config = data / "config"
    config.mkdir(parents=True)
    (config / "development-runtime.yaml").write_bytes(b"candidate synthetic runtime")
    evidence = install / (".candidate-" + "a" * 32)
    evidence.mkdir()
    (evidence / "previous-runtime.yaml").write_bytes(b"previous synthetic runtime")
    record = {"release": str(previous), "candidate": candidate.name}
    (evidence / "rollback.json").write_text(json.dumps(record))
    monkeypatch.setattr(installer, "INSTALL", install)
    monkeypatch.setattr(installer, "DATA", data)
    monkeypatch.setattr(installer, "directory", lambda path, owner=0: os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
    monkeypatch.setattr(installer.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid()))
    return install, config, evidence, previous, candidate, record


def test_rollback_restores_exact_pair_and_only_restarts_development(installer, rollback_pair, monkeypatch):
    install, config, evidence, previous, _, _ = rollback_pair
    calls = []
    monkeypatch.setattr(installer.subprocess, "run", lambda *args, **kwargs: calls.append((args, kwargs)))
    installer.rollback(evidence.name, activate=True)
    assert (install / "current").readlink() == previous
    assert (config / "development-runtime.yaml").read_bytes() == b"previous synthetic runtime"
    assert (config / "development-runtime.yaml").stat().st_mode & 0o777 == 0o600
    assert len(calls) == 1
    assert calls[0][0][0] == ["/usr/bin/systemctl", "restart", "agentporter-development.service"]
    assert calls[0][1]["check"] is True


@pytest.mark.parametrize("mutation", ["stale", "outside_release"])
def test_rollback_rejects_stale_or_external_pairs_before_changes(installer, rollback_pair, mutation):
    import json

    install, config, evidence, previous, candidate, record = rollback_pair
    if mutation == "stale":
        record["candidate"] = previous.name
    else:
        record["release"] = str(install / "outside")
    (evidence / "rollback.json").write_text(json.dumps(record))
    with pytest.raises(ValueError):
        installer.rollback(evidence.name)
    assert (install / "current").readlink() == candidate
    assert (config / "development-runtime.yaml").read_bytes() == b"candidate synthetic runtime"


def test_builder_archive_extract_install_and_rollback_round_trip(builder, installer, tmp_path, monkeypatch):
    """Use real packing, extraction, verification, install and rollback logic.

    Snapshot inputs are inert synthetic files. Only privileged ownership and
    systemd effects are simulated; destination capability pinning stays real.
    """
    import stat
    import yaml

    install, data = tmp_path / "install", tmp_path / "data"
    previous = install / "versions/20261020T010203.000001Z"
    previous.mkdir(parents=True)
    (install / "current").symlink_to(previous)
    config = data / "config"
    config.mkdir(parents=True)
    previous_runtime = b"previous: exact synthetic runtime\n"
    (config / "development-runtime.yaml").write_bytes(previous_runtime)
    stage = tmp_path / "stage"
    stage.mkdir()
    workers = {name: {} for name in ("jax", "liz", "prof", "ming", "wei", "phil", "argie")}
    runtime = {"profile": "development", "gateway_user": "agentporter-dev",
               "production_uid": os.getuid(), "workers": workers}
    (stage / "development-runtime.yaml").write_text(yaml.safe_dump(runtime))
    admitted_workspaces = {'workspaces': {'fixture': {'path': str(tmp_path), 'writable': False, 'allow_agent_dispatch': True}}}
    (stage / "workspaces.yaml").write_text(yaml.safe_dump(admitted_workspaces))
    provision = SimpleNamespace(STAGE=stage)

    def synthetic_snapshot(runtime, python_root, version, *, approvals, workspaces):
        assert workspaces == admitted_workspaces
        release = provision.INSTALL / "versions" / version
        (release / "venv/lib/python3.13/site-packages").mkdir(parents=True)
        for relative in ("venv/pyvenv.cfg", "venv/lib/python3.13/site-packages/agentporter_development.pth"):
            (release / relative).write_text(str(release))
        (release / "shared/toolkit").mkdir(parents=True)
        (release / "shared/toolkit/manifest.json").write_text('{"bundled_scripts":{},"not_bundled":[]}')
        (release / "python/lib/__pycache__/nested").mkdir(parents=True)
        (release / "python/lib/__pycache__/nested/unreviewed.pyc").write_bytes(b"synthetic cached bytecode; never execute")
        (release / "python/lib/module.py").write_bytes(b"synthetic module; never execute")
        (release / "python/lib/standalone.pyc").write_bytes(b"admitted standalone bytecode; never execute")
        (release / "bin").mkdir()
        (release / "bin/tool").write_bytes(b"synthetic executable; never execute")
        (release / "bin/tool").chmod(0o755)
        (release / "tool-link").symlink_to("bin/tool")
        runtime = dict(runtime, allowed_workspace_roots=[{'path': str(tmp_path), 'writable': False}],
                       shared_obsidian=str(release / "shared/obsidian"),
                       shared_toolkit=str(release / "shared/toolkit"))
        return release, runtime

    provision.snapshot = synthetic_snapshot
    admissions = {"worker_executables": workers}
    artifact = tmp_path / "synthetic.tgz"
    monkeypatch.setattr(builder, "INSTALL", install)
    # Only replace the external snapshot dependency; build() itself runs whole.
    with monkeypatch.context() as loader:
        loader.setattr(builder.importlib.util, "spec_from_file_location", lambda *_: SimpleNamespace(loader=SimpleNamespace(exec_module=lambda _: None)))
        loader.setattr(builder.importlib.util, "module_from_spec", lambda _: provision)
        builder.build(admissions, artifact)
    artifact.chmod(0o600)
    with tarfile.open(artifact, "r:gz") as archive_stream:
        expected = json.load(archive_stream.extractfile("release-files.json"))
        metadata = json.load(archive_stream.extractfile("release-metadata.json"))
        members = archive_stream.getmembers()
        assert {member.name.removeprefix("release/") for member in members
                if member.name.startswith("release/") and not member.isdir()} == set(expected)
        assert not any("__pycache__" in Path(member.name).parts for member in members)
        assert "python/lib/standalone.pyc" in expected

    # A second actual extraction+verification proves builder/installer agreement
    # independently of install() before exercising the remaining transition.
    extracted = tmp_path / "extracted"
    extracted.mkdir()
    fd = os.open(extracted, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with artifact.open("rb") as stream:
            installer.extract(stream, fd)
    finally:
        os.close(fd)
    installer.verify_release(extracted / "release", expected)

    monkeypatch.setattr(installer, "INSTALL", install)
    monkeypatch.setattr(installer, "DATA", data)
    operator = SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
    account = SimpleNamespace(pw_uid=42424, pw_gid=42424)
    monkeypatch.setattr(installer.pwd, "getpwnam", lambda name: operator if name == "yeli" else account)
    original_fstat = os.fstat

    def synthetic_ownership(fd):
        info = original_fstat(fd)
        if not stat.S_ISDIR(info.st_mode):
            return info
        fields = list(info)
        fields[4] = account.pw_uid if Path(os.readlink(f"/proc/self/fd/{fd}")) == config else 0
        fields[0] &= ~0o022
        return os.stat_result(fields)

    monkeypatch.setattr(installer.os, "fstat", synthetic_ownership)
    original_rename = os.rename

    def root_directory_rename(source, destination, *args, **kwargs):
        # Root can update '..' when moving an immutable directory. Model that
        # DAC override only, while keeping the real rename and final mode.
        source = Path(source)
        if source.is_absolute() and source.is_dir() and not source.is_symlink():
            mode = source.stat().st_mode & 0o777
            source.chmod(mode | 0o200)
            try:
                result = original_rename(source, destination, *args, **kwargs)
            except BaseException:
                source.chmod(mode)
                raise
            os.chmod(destination, mode, dir_fd=kwargs.get("dst_dir_fd"))
            return result
        return original_rename(source, destination, *args, **kwargs)

    monkeypatch.setattr(installer.os, "rename", root_directory_rename)
    ownership_changes, service_calls = [], []
    monkeypatch.setattr(installer.os, "fchown", lambda fd, uid, gid: ownership_changes.append((uid, gid)))
    monkeypatch.setattr(installer.subprocess, "run", lambda *args, **kwargs: service_calls.append((args, kwargs)))
    try:
        installer.install(artifact, hashlib.sha256(artifact.read_bytes()).hexdigest(), activate=True)
        final = install / "versions" / metadata["version"]
        assert (install / "current").readlink() == final
        installed_runtime = (config / "development-runtime.yaml").read_bytes()
        assert json.loads(installed_runtime)["shared_toolkit"] == str(final / "shared/toolkit")
        assert (final / "bin/tool").stat().st_mode & 0o777 == 0o555
        assert (final / "python/lib/module.py").stat().st_mode & 0o777 == 0o444
        assert (final / "tool-link").readlink() == Path("bin/tool")
        assert not (final / "python/lib/__pycache__").exists()
        installer.verify_release(final, expected)
        evidence, = install.glob(".candidate-*")
        assert (evidence / "previous-runtime.yaml").read_bytes() == previous_runtime
        installer.rollback(evidence.name, activate=True)
        assert (install / "current").readlink() == previous
        assert (config / "development-runtime.yaml").read_bytes() == previous_runtime
        assert ownership_changes == [(account.pw_uid, account.pw_gid)] * 2
        assert [call[0][0] for call in service_calls] == [["/usr/bin/systemctl", "restart", "agentporter-development.service"]] * 2
        assert all(call[1]["check"] is True for call in service_calls)
    finally:
        for location, _, _ in os.walk(tmp_path):
            Path(location).chmod(0o700)


@pytest.mark.parametrize("mutation", ["extra", "digest", "execute", "missing"])
def test_packer_rejects_release_changed_after_manifest(builder, tmp_path, mutation):
    release = tmp_path / "release"
    release.mkdir()
    payload = release / "payload"
    payload.write_bytes(b"synthetic")
    (tmp_path / "release-files.json").write_text(json.dumps(builder.entries(release)))
    if mutation == "extra":
        (release / "unlisted").write_bytes(b"unlisted")
    elif mutation == "digest":
        payload.write_bytes(b"replacement")
    elif mutation == "execute":
        payload.chmod(0o755)
    else:
        payload.unlink()
    with pytest.raises(ValueError, match="differs from reviewed manifest"):
        builder.write_artifact(release, tmp_path, tmp_path / "candidate.tgz")


@pytest.mark.parametrize("extra_kind", ["cache", "noncache", "cache_symlink"])
def test_repacker_preserves_reviewed_data_and_rejects_other_extras(repacker, installer, tmp_path, extra_kind):
    payload = b"synthetic reviewed payload"
    reviewed = {"tool": {"sha256": hashlib.sha256(payload).hexdigest(), "executable": True}}
    metadata_bytes = {"runtime.json": b'{"synthetic": "runtime"}\n',
                      "release-metadata.json": b'{"synthetic": "metadata"}\n',
                      "release-files.json": json.dumps(reviewed).encode() + b"\n"}
    members = [("release", tarfile.DIRTYPE, ""), ("release/tool", tarfile.REGTYPE, payload)]
    members.extend((name, tarfile.REGTYPE, content) for name, content in metadata_bytes.items())
    if extra_kind == "cache":
        members.append(("release/__pycache__/tool.pyc", tarfile.REGTYPE, b"unreviewed synthetic cache"))
    elif extra_kind == "noncache":
        members.append(("release/unlisted", tarfile.REGTYPE, b"unreviewed synthetic extra"))
    else:
        members.append(("release/__pycache__/tool.pyc", tarfile.SYMTYPE, "../tool"))
    original = tmp_path / "original.tgz"
    original.write_bytes(archive(members).getvalue())
    original.chmod(0o600)
    original_digest = hashlib.sha256(original.read_bytes()).hexdigest()
    output = tmp_path / "corrected.tgz"
    if extra_kind != "cache":
        with pytest.raises(ValueError, match="non-cache archive member"):
            repacker.repack(original, original_digest, output)
        assert not output.exists()
        return
    result = repacker.repack(original, original_digest, output)
    assert hashlib.sha256(original.read_bytes()).hexdigest() == original_digest
    assert result["removed_cache_files"] == 1
    assert result["manifest_entries"] == 1
    assert result["preserved_metadata_sha256"] == {name: hashlib.sha256(content).hexdigest() for name, content in metadata_bytes.items()}
    assert output.stat().st_mode & 0o777 == 0o400
    with tarfile.open(output, "r:gz") as stream:
        assert not any("__pycache__" in item.name for item in stream.getmembers())
        assert stream.extractfile("release/tool").read() == payload
        for name, content in metadata_bytes.items():
            assert stream.extractfile(name).read() == content


def test_repacker_requires_original_digest_before_extraction(repacker, tmp_path):
    original = tmp_path / "original.tgz"
    original.write_bytes(b"unapproved synthetic archive")
    original.chmod(0o600)
    with pytest.raises(ValueError, match="approved SHA256"):
        repacker.repack(original, "0" * 64, tmp_path / "corrected.tgz")


@pytest.mark.parametrize("target", ["__pycache__/module.pyc", "__pycache__", "__pycache__/../retained", "__pycache__/intermediate"])
def test_packer_rejects_links_depending_on_omitted_cache(builder, tmp_path, target):
    release = tmp_path / "release"
    (release / "__pycache__").mkdir(parents=True)
    (release / "__pycache__/module.pyc").write_bytes(b"synthetic cache")
    (release / "retained").write_bytes(b"synthetic admitted payload")
    (release / "__pycache__/intermediate").symlink_to("../retained")
    (release / "cached-link").symlink_to(target)
    (tmp_path / "release-files.json").write_text(json.dumps(builder.entries(release)))
    with pytest.raises(ValueError, match="depends on omitted cache"):
        builder.write_artifact(release, tmp_path, tmp_path / "candidate.tgz")


def test_packer_keeps_admitted_regular_file_named_pycache(builder, tmp_path):
    release = tmp_path / "release"
    release.mkdir()
    (release / "__pycache__").write_bytes(b"admitted regular file")
    (release / "link").symlink_to("__pycache__")
    (tmp_path / "release-files.json").write_text(json.dumps(builder.entries(release)))
    for name in ("runtime.json", "release-metadata.json"):
        (tmp_path / name).write_text("{}")
    output = tmp_path / "candidate.tgz"
    builder.write_artifact(release, tmp_path, output)
    with tarfile.open(output, "r:gz") as stream:
        assert stream.extractfile("release/__pycache__").read() == b"admitted regular file"
        assert stream.getmember("release/link").linkname == "__pycache__"


def test_packer_rejects_link_through_omitted_cache_directory_alias(builder, tmp_path):
    release = tmp_path / "release"
    (release / "retained-directory").mkdir(parents=True)
    (release / "retained-directory/payload").write_bytes(b"admitted synthetic payload")
    (release / "__pycache__").symlink_to("retained-directory", target_is_directory=True)
    (release / "link").symlink_to("__pycache__")
    (tmp_path / "release-files.json").write_text(json.dumps(builder.entries(release)))
    with pytest.raises(ValueError, match="depends on omitted cache"):
        builder.write_artifact(release, tmp_path, tmp_path / "candidate.tgz")


@pytest.mark.parametrize("valid_digest", [True, False])
def test_repacker_restores_real_caller_umask_on_success_and_error(repacker, tmp_path, valid_digest):
    payload = b"synthetic admitted payload"
    manifest = {"tool": {"sha256": hashlib.sha256(payload).hexdigest(), "executable": True}}
    members = [("release", tarfile.DIRTYPE, ""), ("release/tool", tarfile.REGTYPE, payload),
               ("release/__pycache__/tool.pyc", tarfile.REGTYPE, b"synthetic omitted cache"),
               ("release-files.json", tarfile.REGTYPE, json.dumps(manifest).encode()),
               ("runtime.json", tarfile.REGTYPE, b"{}"),
               ("release-metadata.json", tarfile.REGTYPE, b"{}")]
    original = tmp_path / "original.tgz"
    original.write_bytes(archive(members).getvalue())
    original.chmod(0o600)
    digest = hashlib.sha256(original.read_bytes()).hexdigest() if valid_digest else "0" * 64
    previous = os.umask(0o002)
    try:
        if valid_digest:
            repacker.repack(original, digest, tmp_path / "corrected.tgz")
        else:
            with pytest.raises(ValueError, match="approved SHA256"):
                repacker.repack(original, digest, tmp_path / "corrected.tgz")
        assert os.umask(0o002) == 0o002
    finally:
        os.umask(previous)
