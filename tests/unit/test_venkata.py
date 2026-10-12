"""Venkata command, permission, output and Action boundary checks."""

import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from agentporter.rest.routers.venkata import router
from agentporter.tools.venkata import access_enabled, create_venkata_tool, remote_argv, run_bounded
from agentporter.workspaces.registry import WorkspaceRegistry


class VenkataTests(unittest.TestCase):
    def test_fixed_commands(self):
        for name in ("hostname", "nproc", "free", "df", "cuda_version", "torch_status"):
            self.assertTrue(remote_argv(name, [])[0].startswith("/"))
            with self.assertRaises(ValueError):
                remote_argv(name, ["; id"])

    def test_query(self):
        args = ["--query-gpu=index,name,memory.total,memory.used,memory.free,utilization.gpu,driver_version",
                "--format=csv,noheader"]
        self.assertEqual(remote_argv("nvidia-smi", args)[1:], args)
        self.assertEqual(remote_argv("nvidia-smi", args + ["--id=0,1"])[-1], "--id=0,1")

    def test_reject_injection_and_mutation(self):
        for command, args in [
            ("sh", []), ("hostname; id", []), ("python3", ["-c", "print(1)"]),
            ("nvidia-smi", ["--gpu-reset"]), ("nvidia-smi", ["--loop=1"]),
            ("nvidia-smi", ["--query-gpu=index;id", "--format=csv"]),
            ("nvidia-smi", ["--query-gpu=index", "--format=csv", "--id=0$(id)"]),
            ("nvidia-smi", ["--query-gpu=index", "--format=csv", "--format=csv"]),
            ("nvidia-smi", ["--query-gpu=index", "--format=csv\nsh"]),
            ("hostname", "hostname"), ("hostname", [""]), ("hostname", [None]),
        ]:
            with self.subTest(command=command, args=args), self.assertRaises(ValueError):
                remote_argv(command, args)

    def test_permissions_identity_and_safe_ssh(self):
        registry = WorkspaceRegistry({"test": {"path": "/tmp"}})
        tool = create_venkata_tool(registry)
        with patch("agentporter.tools.venkata.run_bounded") as run:
            with self.assertRaises(PermissionError):
                tool("test", "hostname")
            registry.get("test").allow_venkata_ssh = True
            registry.get("test").allow_execute = False
            with self.assertRaises(PermissionError):
                tool("test", "hostname")
            registry.get("test").allow_execute = True
            with patch("agentporter.tools.venkata.pwd.getpwuid", return_value=SimpleNamespace(pw_name="root", pw_dir="/root")):
                with self.assertRaises(PermissionError):
                    tool("test", "hostname")
            run.assert_not_called()
            with patch("agentporter.tools.venkata.pwd.getpwuid", return_value=SimpleNamespace(pw_name="yeli", pw_dir="/home/yeli")), patch("agentporter.tools.venkata.socket.gethostname", return_value="bcc"), patch("agentporter.tools.venkata.access_enabled", return_value=True):
                tool("test", "hostname")
            argv, home = run.call_args.args
            self.assertIn("StrictHostKeyChecking=yes", argv)
            self.assertIn("ForwardAgent=no", argv)
            self.assertEqual(argv[-2:], ["venkata", "/usr/bin/timeout 25s /usr/bin/hostname"])
            self.assertEqual(home, "/home/yeli")

    def test_switch_fail_closed_and_dynamic(self):
        from pathlib import Path
        with tempfile.TemporaryDirectory() as root:
            marker = Path(root, ".config", "agentporter", "venkata-access.enabled")
            marker.parent.mkdir(parents=True)
            self.assertFalse(access_enabled(root))
            marker.touch(mode=0o600)
            self.assertTrue(access_enabled(root))
            marker.chmod(0o666)
            self.assertFalse(access_enabled(root))
            marker.unlink()
            marker.symlink_to("/dev/null")
            self.assertFalse(access_enabled(root))
            registry = WorkspaceRegistry({"test": {"path": root, "allow_venkata_ssh": True}})
            with patch("agentporter.tools.venkata.pwd.getpwuid", return_value=SimpleNamespace(pw_name="yeli", pw_dir=root)), patch("agentporter.tools.venkata.socket.gethostname", return_value="bcc"), patch("agentporter.tools.venkata.run_bounded") as run:
                with self.assertRaises(PermissionError):
                    create_venkata_tool(registry)("test", "hostname")
                run.assert_not_called()

    def test_permission_not_inherited_by_discovered_projects(self):
        with tempfile.TemporaryDirectory() as root:
            from pathlib import Path
            Path(root, "child").mkdir()
            registry = WorkspaceRegistry({"parent": {"path": root, "auto_discover": True, "allow_venkata_ssh": True}})
            self.assertFalse(registry.get("child").allow_venkata_ssh)

    def test_bounded_output_and_timeout(self):
        with tempfile.TemporaryDirectory() as root:
            result = run_bounded([sys.executable, "-I", "-c", "print('ok')"], root)
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["stdout"], "ok\n")
            result = run_bounded([sys.executable, "-I", "-c", "print('x'*1000000)"], root)
            self.assertTrue(result["truncated"])
            self.assertLessEqual(len(result["stdout"].encode()) + len(result["stderr"].encode()), 65536)
            with patch("agentporter.tools.venkata.TIMEOUT", 0.05):
                result = run_bounded([sys.executable, "-I", "-c", "import time; time.sleep(10)"], root)
            self.assertTrue(result["timed_out"])

    def test_action_schema_and_validation(self):
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")
        app.state.tools = {"venkata_diagnostic": lambda **kw: {"stdout": "phl-hpcdl-011\n"}}
        client = TestClient(app)
        url = "/api/v1/workspaces/test/venkata/diagnostic"
        self.assertEqual(client.post(url, json={"command": "hostname"}).json()["stdout"], "phl-hpcdl-011\n")
        for body in ({"command": "sh"}, {"command": "hostname", "target": "other"}, {"command": "hostname", "args": "id"}):
            self.assertEqual(client.post(url, json=body).status_code, 422)
        app.state.tools = {"venkata_diagnostic": create_venkata_tool(WorkspaceRegistry({"test": {"path": "/tmp"}}))}
        self.assertEqual(client.post(url, json={"command": "hostname"}).status_code, 403)

    def test_full_gateway_auth_and_bcc_schema(self):
        from pathlib import Path
        from agentporter.config import ServerSettings, SandboxSettings, SecuritySettings
        from agentporter.server import create_asgi_app
        with tempfile.TemporaryDirectory() as root:
            cfg = SimpleNamespace(
                state_dir=Path(root), workspaces={"test": {"path": root}},
                server=ServerSettings(action_prefix="bcc"), sandbox=SandboxSettings(),
                security=SecuritySettings(allowed_hosts=["testserver"]), api_key="synthetic-test-key")
            app = create_asgi_app(cfg)
            with TestClient(app) as client:
                schema = client.get("/openapi.json").json()
                url = "/api/v1/workspaces/test/venkata/diagnostic"
                operation = schema["paths"]["/api/v1/workspaces/{workspace_id}/venkata/diagnostic"]["post"]
                self.assertEqual(operation["operationId"], "bcc_venkata_diagnostic")
                transfer = "/api/v1/workspaces/test/venkata/transfer"
                self.assertEqual(schema["paths"]["/api/v1/workspaces/{workspace_id}/venkata/transfer"]["post"]["operationId"],
                                 "bcc_venkata_transfer")
                body = {"source": "asgard_laya", "files": ["dataset.jsonl"]}
                self.assertEqual(client.post(transfer, json=body).status_code, 401)
                self.assertEqual(client.post(transfer, json=body,
                                 headers={"Authorization": "Bearer synthetic-test-key"}).status_code, 403)
                self.assertLessEqual(sum(len(v) for v in schema["paths"].values()), 30)
                self.assertEqual(client.post(url, json={"command": "hostname"}).status_code, 401)
                self.assertEqual(client.post(url, json={"command": "hostname"},
                                 headers={"Authorization": "Bearer synthetic-test-key"}).status_code, 403)


if __name__ == "__main__":
    unittest.main()
