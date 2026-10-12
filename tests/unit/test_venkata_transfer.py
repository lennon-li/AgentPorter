import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from agentporter.rest.routers.venkata import router
from agentporter.tools import venkata_transfer_protocol as p
from agentporter.tools.venkata import run_host_bytes
from agentporter.tools.venkata_transfer import create_venkata_transfer_tool, remote_command
from agentporter.workspaces.registry import WorkspaceRegistry


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "venkata-transfer"
        self.source.mkdir()
        self.destination = self.root / "training"
        self.data = b"synthetic training-artifact transfer check\n"
        (self.source / "synthetic-test.txt").write_bytes(self.data)
        self.id = "a" * 32

    def payload(self):
        return p.build_payload(str(self.source), ["synthetic-test.txt"], self.id)

    def test_success_sha_and_permissions(self):
        result = p.receive_payload(io.BytesIO(self.payload()), str(self.destination))
        target = Path(result["files"][0]["destination"])
        self.assertEqual(target.read_bytes(), self.data)
        self.assertEqual(result["files"][0]["sha256"], hashlib.sha256(target.read_bytes()).hexdigest())
        self.assertEqual(result["total_bytes"], len(self.data))
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        self.assertEqual(target.parent.stat().st_mode & 0o777, 0o700)

    def test_existing_destination_never_overwritten(self):
        payload = self.payload()
        p.receive_payload(io.BytesIO(payload), str(self.destination))
        with self.assertRaises(FileExistsError):
            p.receive_payload(io.BytesIO(payload), str(self.destination))
        self.assertEqual((self.destination / self.id / "synthetic-test.txt").read_bytes(), self.data)

    def test_atomic_publish_race_does_not_clobber(self):
        self.destination.mkdir()
        (self.destination / "stage").mkdir()
        (self.destination / "existing").mkdir()
        fd = p.open_directory(str(self.destination))
        try:
            with self.assertRaises(FileExistsError):
                p.rename_noreplace(fd, "stage", "existing")
        finally:
            os.close(fd)

    def test_paths_archives_and_duplicate_files_rejected(self):
        for names in (["../dataset.jsonl"], ["/etc/passwd"], ["nested/dataset.jsonl"],
                      ["data.tar.gz"], ["payload.zip"], ["dataset.jsonl;id"],
                      ["dataset.jsonl", "dataset.jsonl"], ["secrets.env"], []):
            with self.subTest(names=names), self.assertRaises(ValueError):
                p.validate_names(names)
        with self.assertRaises(ValueError):
            p.validate_names(["synthetic-test.txt"], source="asgard_laya")

    def test_symlink_and_hardlink_source_rejected(self):
        source_file = self.source / "synthetic-test.txt"
        source_file.unlink()
        outside = self.root / "outside"
        outside.write_bytes(b"not approved")
        source_file.symlink_to(outside)
        with self.assertRaises(OSError):
            self.payload()
        source_file.unlink()
        os.link(outside, source_file)
        with self.assertRaises(ValueError):
            self.payload()

    def test_symlink_directory_source_and_destination_rejected(self):
        alias = self.root / "alias"
        alias.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(OSError):
            p.build_payload(str(alias), ["synthetic-test.txt"], self.id)
        self.destination.symlink_to(self.source, target_is_directory=True)
        with self.assertRaises(OSError):
            p.receive_payload(io.BytesIO(self.payload()), str(self.destination))

    def test_file_count_file_size_and_total_size(self):
        with self.assertRaises(ValueError):
            p.validate_names(list(p.ALLOWED_FILES))
        with patch.object(p, "MAX_FILE_BYTES", 1), self.assertRaises(ValueError):
            self.payload()
        with patch.object(p, "MAX_TOTAL_BYTES", 1), self.assertRaises(ValueError):
            self.payload()

    def test_source_group_write_preserved_but_world_write_rejected(self):
        self.source.chmod(0o775)
        self.assertTrue(p.validate_payload(self.payload()))
        self.source.chmod(0o777)
        with self.assertRaises(PermissionError):
            self.payload()
        self.source.chmod(0o755)
        self.destination.mkdir(mode=0o775)
        self.destination.chmod(0o775)
        with self.assertRaises(PermissionError):
            p.receive_payload(io.BytesIO(self.payload()), str(self.destination))

    def test_truncated_mismatched_and_trailing_payload_cleaned(self):
        payload = self.payload()
        for damaged in (payload[:-1], payload[:-1] + b"x", payload + b"extra"):
            with self.subTest(damaged=damaged[-8:]), self.assertRaises(ValueError):
                p.receive_payload(io.BytesIO(damaged), str(self.destination))
            self.assertEqual(list(self.destination.iterdir()), [])

    def test_unsafe_header(self):
        header = p.read_header(io.BytesIO(self.payload()))
        for name in ("../escape", "/home/yeli/.ssh/id_rsa", "payload.tar"):
            header["files"][0]["name"] = name
            with self.assertRaises(ValueError):
                p.receive_payload(io.BytesIO(json.dumps(header).encode() + b"\n"), str(self.destination))

    def test_remote_cli_errors_do_not_disclose_content(self):
        script = Path(p.__file__).read_text()
        result = subprocess.run([sys.executable, "-I", "-c", script, "receive"],
                                input=b"sensitive-synthetic-marker", capture_output=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn(b"sensitive-synthetic-marker", result.stdout + result.stderr)
        self.assertEqual(result.stderr, b"")

    def test_binary_runner_bounds_and_input(self):
        result = run_host_bytes([sys.executable, "-I", "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"],
                                str(self.root), input_bytes=b"binary\x00test")
        self.assertEqual(result["stdout"], b"binary\x00test")
        result = run_host_bytes([sys.executable, "-I", "-c", "print('x'*1000)"], str(self.root), max_output=20)
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["stdout"]), 20)

    def registry(self, enabled=True):
        return WorkspaceRegistry({"test": {"path": str(self.root), "allow_venkata_ssh": True,
                                           "allow_venkata_transfer": enabled}})

    def test_service_receipt_and_remote_failure_redaction(self):
        tool = create_venkata_transfer_tool(self.registry())
        user = SimpleNamespace(pw_dir=str(self.root))
        def transport(argv, home, **kw):
            header = p.validate_payload(kw["input_bytes"])
            receipt = {"success": True, "target": "venkata", "transfer_id": header["transfer_id"],
                       "total_bytes": sum(i["bytes"] for i in header["files"]),
                       "files": [{**i, "destination": p.DESTINATION_ROOT + "/" + header["transfer_id"] + "/" + i["name"]}
                                 for i in header["files"]]}
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertEqual(argv[-2], "venkata")
            return {"exit_code": 0, "timed_out": False, "truncated": False, "stdout": json.dumps(receipt).encode()}
        with patch("agentporter.tools.venkata_transfer.host_identity", return_value=user), patch("agentporter.tools.venkata_transfer.run_host_bytes", side_effect=transport):
            result = tool("test", "workspace", ["synthetic-test.txt"])
            self.assertTrue(result["success"])
        failed = {"exit_code": 255, "timed_out": False, "truncated": False,
                  "stdout": b"", "stderr": b"token-synthetic-secret"}
        with patch("agentporter.tools.venkata_transfer.host_identity", return_value=user), patch("agentporter.tools.venkata_transfer.run_host_bytes", return_value=failed):
            result = tool("test", "workspace", ["synthetic-test.txt"])
            self.assertFalse(result["success"])
            self.assertNotIn("token-synthetic-secret", json.dumps(result))

    def test_asgard_source_authentication_and_receipt_integrity(self):
        (self.source / "dataset.jsonl").write_bytes(b"synthetic dataset")
        tool = create_venkata_transfer_tool(self.registry())
        def transport(argv, home, **kw):
            if argv[-2] == "asgard":
                request = json.loads(kw["input_bytes"])
                payload = p.build_payload(str(self.source), request["files"], request["transfer_id"], source="asgard_laya")
                return {"exit_code": 0, "timed_out": False, "truncated": False, "stdout": payload}
            return {"exit_code": 0, "timed_out": False, "truncated": False, "stdout": b'{"success":true}'}
        with patch("agentporter.tools.venkata_transfer.host_identity", return_value=SimpleNamespace(pw_dir=str(self.root))), patch("agentporter.tools.venkata_transfer.run_host_bytes", side_effect=transport) as run:
            self.assertFalse(tool("test", "asgard_laya", ["dataset.jsonl"])["success"])
            self.assertEqual(run.call_count, 2)

    def test_permission_destination_and_no_arbitrary_overwrite(self):
        user = SimpleNamespace(pw_dir=str(self.root))
        with patch("agentporter.tools.venkata_transfer.host_identity", return_value=user):
            with self.assertRaises(PermissionError):
                create_venkata_transfer_tool(self.registry(False))("test", "workspace", ["synthetic-test.txt"])
            with self.assertRaises(ValueError):
                create_venkata_transfer_tool(self.registry())("test", "workspace", ["synthetic-test.txt"], "/tmp")
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")
        app.state.tools = {"venkata_transfer": create_venkata_transfer_tool(self.registry())}
        client = TestClient(app)
        for body in ({"source": "workspace", "files": ["synthetic-test.txt"], "destination": "/tmp"},
                     {"source": "workspace", "files": ["synthetic-test.txt"], "overwrite": True},
                     {"source": "scp", "files": ["synthetic-test.txt"]}):
            self.assertEqual(client.post("/api/v1/workspaces/test/venkata/transfer", json=body).status_code, 422)

    def test_remote_modes_are_fixed(self):
        with self.assertRaises(ValueError):
            remote_command("sh")


if __name__ == "__main__":
    unittest.main()
