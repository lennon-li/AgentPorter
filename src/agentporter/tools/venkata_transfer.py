"""Fixed-source, fixed-destination training-artifact transfer over trusted host SSH."""

import json
from pathlib import Path
import threading
from typing import Literal
import uuid

from agentporter.tools.venkata import host_identity, run_host_bytes, ssh_argv
from agentporter.tools import venkata_transfer_protocol as protocol

TransferSource = Literal["asgard_laya", "workspace"]
TransferDestination = Literal["laya-training"]
TRANSFER_LOCK = threading.Lock()


def remote_command(mode):
    if mode not in {"source", "receive"}:
        raise ValueError("Invalid transfer mode")
    script = Path(protocol.__file__).read_text(encoding="utf-8")
    return ["/usr/bin/timeout", "55s", "/usr/bin/python3", "-I", "-c", script, mode]


def create_venkata_transfer_tool(registry):
    def venkata_transfer(workspace_id: str, source: TransferSource, files: list[str],
                         destination: TransferDestination = "laya-training") -> dict:
        user = host_identity(registry, workspace_id)
        ws = registry.get(workspace_id)
        if not ws.allow_venkata_transfer or not ws.allow_artifacts:
            raise PermissionError("Venkata transfer requires explicit workspace opt-in and artifact permission")
        if source not in {"asgard_laya", "workspace"} or destination != "laya-training":
            raise ValueError("Source or destination is not approved")
        protocol.validate_names(files, source=source)
        if not TRANSFER_LOCK.acquire(blocking=False):
            return {"success": False, "target": "venkata", "error": "transfer_busy", "files": []}
        stage = "source"
        try:
            transfer_id = uuid.uuid4().hex
            if source == "workspace":
                payload = protocol.build_payload(str(Path(ws.path) / "venkata-transfer"), files, transfer_id)
            else:
                request = json.dumps({"files": files, "transfer_id": transfer_id}).encode()
                result = run_host_bytes(ssh_argv("asgard", remote_command("source")), user.pw_dir,
                                        input_bytes=request, max_output=protocol.MAX_TOTAL_BYTES + 8192, timeout=60)
                if result["exit_code"] or result["timed_out"] or result["truncated"]:
                    return {"success": False, "target": "venkata", "error": "source_ssh_failed", "files": []}
                payload = result["stdout"]
            header = protocol.validate_payload(payload)
            if header["transfer_id"] != transfer_id or [item["name"] for item in header["files"]] != files:
                raise ValueError("Unexpected source response")
            host_identity(registry, workspace_id)
            stage = "destination"
            result = run_host_bytes(ssh_argv("venkata", remote_command("receive")), user.pw_dir,
                                    input_bytes=payload, max_output=8192, timeout=60)
            if result["exit_code"] or result["timed_out"] or result["truncated"]:
                return {"success": False, "target": "venkata", "transfer_id": transfer_id,
                        "error": "destination_failed_check_transfer_id_before_retry", "files": []}
            receipt = json.loads(result["stdout"])
            expected = [{**item, "destination": protocol.DESTINATION_ROOT + "/" + transfer_id + "/" + item["name"]}
                        for item in header["files"]]
            if (not isinstance(receipt, dict) or receipt.get("success") is not True
                    or receipt.get("transfer_id") != transfer_id or receipt.get("target") != "venkata"
                    or receipt.get("files") != expected
                    or receipt.get("total_bytes") != sum(item["bytes"] for item in header["files"])):
                raise ValueError("Invalid destination receipt")
            return receipt
        except (OSError, ValueError, TypeError, KeyError):
            return {"success": False, "target": "venkata", "transfer_id": transfer_id,
                    "error": stage + "_transfer_failed", "files": []}
        finally:
            TRANSFER_LOCK.release()
    return venkata_transfer
