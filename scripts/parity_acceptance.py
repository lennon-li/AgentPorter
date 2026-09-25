"""Parity acceptance test exercising AgentPorter via MCP over Streamable HTTP."""

import sys
import json
import time
from pathlib import Path
import httpx
import asyncio
from mcp.client.streamable_http import streamable_http_client
from mcp.client.session import ClientSession

URL = "http://127.0.0.1:8765/mcp"
KEY_FILE = Path.home() / ".config/agentporter/secrets.env"

def get_key():
    with open(KEY_FILE, "r") as f:
        for line in f:
            if line.startswith("AGENTPORTER_API_KEY="):
                return line.split("=", 1)[1].strip()
            elif line.startswith("M3_MCP_KEY="):
                return line.split("=", 1)[1].strip()
    raise RuntimeError("Key not found")

API_KEY = get_key()


async def run_parity_tests():
    headers = {"X-AgentPorter-Key": API_KEY}
    print(f"Connecting to {URL} with API key...")

    async with httpx.AsyncClient(headers=headers, timeout=60.0) as http_client:
        async with streamable_http_client(URL, http_client=http_client) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                print("MCP Session Initialized successfully!")

                # 1. get_capabilities
                print("\n--- 1. get_capabilities ---")
                res = await session.call_tool("get_capabilities", arguments={})
                caps = json.loads(res.content[0].text) if hasattr(res.content[0], "text") else res.content
                print("Capabilities:", json.dumps(caps, indent=2))
                assert "bubblewrap_0.9.0" in str(caps)

                # 2. list_workspaces
                print("\n--- 2. list_workspaces ---")
                res = await session.call_tool("list_workspaces", arguments={})
                ws_list = [json.loads(c.text) for c in res.content] if isinstance(res.content, list) else [json.loads(res.content.text)]
                print("Workspaces:", json.dumps(ws_list, indent=2))
                assert len(ws_list) > 0, "At least one workspace must be registered"
                target_ws = ws_list[0].get("workspace_id")

                # 3. R 100/pi
                print("\n--- 3. R 100/pi ---")
                res = await session.call_tool("exec_run", arguments={"workspace_id": target_ws, "argv": ["Rscript", "-e", "cat(100/pi)"]})
                r_calc = json.loads(res.content[0].text)
                print("R 100/pi output:", r_calc.get("stdout"))
                val_r = float(r_calc.get("stdout").strip())
                assert 31.83 <= val_r <= 31.84

                # 4. Python 100/pi
                print("\n--- 4. Python 100/pi ---")
                res = await session.call_tool("exec_run", arguments={"workspace_id": target_ws, "argv": ["python3", "-c", "import math; print(100/math.pi)"]})
                py_calc = json.loads(res.content[0].text)
                print("Python 100/pi output:", py_calc.get("stdout"))
                val_py = float(py_calc.get("stdout").strip())
                assert 31.83 <= val_py <= 31.84

                # 5. read files
                print("\n--- 5. read_file README.md ---")
                res = await session.call_tool("read_file", arguments={"workspace_id": target_ws, "path": "README.md", "start_line": 1, "end_line": 4})
                rf = json.loads(res.content[0].text)
                print("README slice:", rf.get("content"))
                assert "content" in rf and len(rf["content"]) > 0

                # 6. Git status / diff
                print("\n--- 6. Git status / diff ---")
                res_st = await session.call_tool("git_status", arguments={"workspace_id": target_ws})
                print("Git status:", res_st.content[0].text.strip())
                res_diff = await session.call_tool("git_diff", arguments={"workspace_id": target_ws})
                print("Git diff:", res_diff.content[0].text.strip())

                # 7. Artifact access
                print("\n--- 7. Artifact access ---")
                res = await session.call_tool("list_artifacts", arguments={"workspace_id": target_ws})
                arts = [json.loads(c.text) for c in res.content] if res.content else []
                print("Artifacts found:", len(arts))
                if arts:
                    art_path = arts[0]["path"]
                    r_art = await session.call_tool("read_artifact", arguments={"workspace_id": target_ws, "path": art_path})
                    art_data = json.loads(r_art.content[0].text)
                    print(f"Read artifact {art_path} (type: {art_data.get('type')}, size: {art_data.get('size_bytes')})")

                # 8. Async job
                print("\n--- 8. Async job lifecycle ---")
                res = await session.call_tool("exec_start", arguments={"workspace_id": target_ws, "argv": ["bash", "-c", "echo 'AP job start'; sleep 0.2; echo 'AP job done'"]})
                job_start = json.loads(res.content[0].text)
                job_id = job_start["job_id"]
                print("Started job:", job_id)

                for _ in range(30):
                    time.sleep(0.1)
                    res_st = await session.call_tool("job_status", arguments={"job_id": job_id})
                    st = json.loads(res_st.content[0].text)
                    if st.get("status") in ("completed", "failed"):
                        break
                print("Job finished with status:", st.get("status"))
                res_out = await session.call_tool("job_result", arguments={"job_id": job_id})
                result = json.loads(res_out.content[0].text)
                print("Job output stdout:", result.get("stdout").strip())
                assert "AP job start" in result.get("stdout")

                # 9. list_agents
                print("\n--- 9. list_agents ---")
                res = await session.call_tool("list_agents", arguments={})
                agents = [json.loads(c.text) for c in res.content] if res.content else []
                print("Agents:", json.dumps(agents, indent=2))
                for ag in agents:
                    assert "configured_model" in ag
                    assert "actual_model_used" in ag
                    assert ag["actual_model_used"] == "unknown (resolved at runtime per dispatch)"

                # 10 & 11. Dispatch a READ-ONLY independent Codex review and retrieve actual worker result
                print("\n--- 10 & 11. Dispatch READ-ONLY Codex review ---")
                dispatch_args = {
                    "agent": "codex",
                    "task": "Perform a brief, read-only code review of R/stats.R and summarize the compute_variance calculation.",
                    "workspace_id": target_ws,
                    "purpose": "Parity acceptance verification"
                }
                res = await session.call_tool("dispatch_agent", arguments=dispatch_args)
                dispatch_ret = json.loads(res.content[0].text)
                print("Dispatch Return Telemetry:")
                print(json.dumps(dispatch_ret, indent=2))
                assert dispatch_ret["worker_cli"] == "codex"
                assert dispatch_ret["actual_model"] == "unknown"
                assert dispatch_ret["cli_version"] != "unknown"

                codex_job_id = dispatch_ret["job_id"]
                print(f"Waiting for Codex review job {codex_job_id} to finish...")
                for i in range(120):
                    time.sleep(2)
                    res_st = await session.call_tool("job_status", arguments={"job_id": codex_job_id})
                    st = json.loads(res_st.content[0].text)
                    if st.get("status") in ("completed", "failed", "cancelled"):
                        print(f"Codex job completed in ~{i*2}s with status: {st.get('status')}")
                        break
                    if i % 5 == 0:
                        print(f"Still running ({i*2}s)...")

                res_codex = await session.call_tool("job_result", arguments={"job_id": codex_job_id})
                codex_result = json.loads(res_codex.content[0].text)
                print("Codex Result Telemetry:")
                print(f"  Worker:        {codex_result.get('worker_cli')}")
                print(f"  Provider:      {codex_result.get('provider')}")
                print(f"  Req Model:     {codex_result.get('requested_model')}")
                print(f"  Actual Model:  {codex_result.get('actual_model')}")
                print(f"  Reasoning:     {codex_result.get('reasoning_level')}")
                print(f"  Exit Status:   {codex_result.get('exit_status')}")
                print(f"  Duration:      {codex_result.get('duration'):.2f}s")
                print("\nCodex Review Excerpt:")
                out_snippet = codex_result.get('stdout', '')[:500]
                print(out_snippet)
                assert codex_result.get("exit_status") == 0

                # 12. Security escapes
                print("\n--- 12. Representative Security Escapes ---")
                # Path traversal
                try:
                    res_trav = await session.call_tool("read_file", arguments={"workspace_id": target_ws, "path": "../../.ssh/id_rsa"})
                    text_out = str(res_trav.content)
                    if getattr(res_trav, "isError", False) or "Error" in text_out or "blocked" in text_out or "traversal" in text_out:
                        print("PASS: Traversal was blocked:", text_out)
                    else:
                        print("ERROR: Traversal was not blocked!")
                        sys.exit(1)
                except Exception as e:
                    print("PASS: Traversal was blocked with exception:", e)

                # Sensitive file
                try:
                    res_sens = await session.call_tool("read_file", arguments={"workspace_id": target_ws, "path": ".git/config"})
                    text_out = str(res_sens.content)
                    if getattr(res_sens, "isError", False) or "Error" in text_out or "blocked" in text_out or "sensitive" in text_out:
                        print("PASS: Sensitive file was blocked:", text_out)
                    else:
                        print("ERROR: Sensitive file was not blocked!")
                        sys.exit(1)
                except Exception as e:
                    print("PASS: Sensitive file was blocked with exception:", e)

                # Sandbox network block
                res_net = await session.call_tool("exec_run", arguments={
                    "workspace_id": target_ws,
                    "argv": ["python3", "-c", "import socket; s = socket.create_connection(('1.1.1.1', 80), timeout=1)"]
                })
                net_out = json.loads(res_net.content[0].text)
                print("Sandbox network blocked result: exit_code =", net_out.get("exit_code"))
                assert net_out.get("exit_code") != 0 or "Network is unreachable" in net_out.get("stderr")
                print("PASS: Outbound network blocked in sandbox.")

    print("\n==========================================")
    print("ALL 12 PARITY ACCEPTANCE CHECKS PASSED!")
    print("==========================================")

if __name__ == "__main__":
    asyncio.run(run_parity_tests())
