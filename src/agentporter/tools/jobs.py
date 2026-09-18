"""Asynchronous job execution, SQLite tracking, log tailing, and cancellation."""

import os
import time
import json
import uuid
import signal
import sqlite3
import logging
import threading
import subprocess
from pathlib import Path
from typing import Optional
from agentporter.provenance import extract_actual_model

logger = logging.getLogger("agentporter.tools.jobs")


class JobManager:
    """Manages asynchronous command and agent jobs with SQLite persistence."""

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.jobs_dir = state_dir / "jobs"
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = state_dir / "jobs.db"
        self.active_processes: dict[str, subprocess.Popen] = {}
        self.lock = threading.Lock()
        self._init_db()

    def _get_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        conn = self._get_db()
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS jobs (
                    job_id TEXT PRIMARY KEY,
                    workspace_id TEXT,
                    argv TEXT,
                    cwd TEXT,
                    pid INTEGER,
                    pgid INTEGER,
                    status TEXT,
                    created_at REAL,
                    started_at REAL,
                    finished_at REAL,
                    duration REAL,
                    exit_code INTEGER,
                    stdout_path TEXT,
                    stderr_path TEXT,
                    agent TEXT,
                    provider TEXT,
                    model TEXT,
                    requested_model TEXT,
                    actual_model TEXT,
                    reasoning_level TEXT,
                    cli_version TEXT
                )
                """
            )
            # Schema migrations if columns are missing
            cursor = conn.execute("PRAGMA table_info(jobs)")
            existing_cols = {row["name"] for row in cursor.fetchall()}
            for col, col_type in [
                ("requested_model", "TEXT"),
                ("actual_model", "TEXT"),
                ("reasoning_level", "TEXT"),
                ("cli_version", "TEXT"),
            ]:
                if col not in existing_cols:
                    try:
                        conn.execute(f"ALTER TABLE jobs ADD COLUMN {col} {col_type}")
                    except Exception:
                        pass
        conn.close()

    def start_raw_job(
        self,
        workspace_id: str,
        workspace_path: str,
        cmd: list[str],
        agent: str = "",
        provider: str = "",
        model: str = "",
        requested_model: str = "",
        reasoning_level: str = "",
        cli_version: str = "",
        timeout_seconds: int = 300,
        env: Optional[dict] = None,
    ) -> str:
        job_id = f"job_{uuid.uuid4().hex[:24]}"
        stdout_path = str(self.jobs_dir / f"{job_id}.stdout.log")
        stderr_path = str(self.jobs_dir / f"{job_id}.stderr.log")

        stdout_f = open(stdout_path, "wb")
        stderr_f = open(stderr_path, "wb")
        now = time.time()

        proc = subprocess.Popen(
            cmd,
            cwd=workspace_path,
            stdout=stdout_f,
            stderr=stderr_f,
            env=env,
            process_group=0  # Safe in multi-threaded Python >= 3.11
        )

        pgid = os.getpgid(proc.pid)
        with self.lock:
            self.active_processes[job_id] = proc

        req_model = requested_model or model
        conn = self._get_db()
        with conn:
            conn.execute(
                """
                INSERT INTO jobs (
                    job_id, workspace_id, argv, cwd, pid, pgid,
                    status, created_at, started_at, stdout_path, stderr_path,
                    agent, provider, model, requested_model, actual_model,
                    reasoning_level, cli_version
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job_id, workspace_id, json.dumps(cmd), workspace_path, proc.pid, pgid,
                    "running", now, now, stdout_path, stderr_path,
                    agent, provider, req_model, req_model, "unknown",
                    reasoning_level, cli_version
                )
            )
        conn.close()

        thread = threading.Thread(
            target=self._monitor_proc,
            args=(job_id, proc, stdout_f, stderr_f, timeout_seconds, now),
            daemon=True
        )
        thread.start()
        return job_id

    def _monitor_proc(self, job_id: str, proc: subprocess.Popen, stdout_f, stderr_f, timeout_seconds: int, start_time: float):
        status = "completed"
        exit_code = None

        try:
            exit_code = proc.wait(timeout=timeout_seconds)
            if exit_code != 0:
                status = "failed"
        except subprocess.TimeoutExpired:
            status = "timed_out"
            exit_code = 124
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                pass
            proc.wait()
        except Exception as e:
            status = "failed"
            exit_code = 1
            logger.error("Job %s monitor error: %s", job_id, e)
        finally:
            try:
                stdout_f.close()
                stderr_f.close()
            except Exception:
                pass

            finished_at = time.time()
            duration = finished_at - start_time
            stdout_path = str(self.jobs_dir / f"{job_id}.stdout.log")
            stderr_path = str(self.jobs_dir / f"{job_id}.stderr.log")
            actual_model = extract_actual_model(stdout_path, stderr_path)

            with self.lock:
                self.active_processes.pop(job_id, None)

            conn = self._get_db()
            with conn:
                row = conn.execute("SELECT status, actual_model FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
                existing_actual = row["actual_model"] if row and row["actual_model"] else "unknown"
                resolved_actual = actual_model if actual_model != "unknown" else existing_actual
                if row and row["status"] == "cancelled":
                    conn.execute(
                        "UPDATE jobs SET finished_at = ?, duration = ?, exit_code = ?, actual_model = ? WHERE job_id = ?",
                        (finished_at, duration, exit_code, resolved_actual, job_id)
                    )
                else:
                    conn.execute(
                        """
                        UPDATE jobs SET
                            status = ?, exit_code = ?, finished_at = ?, duration = ?, actual_model = ?
                        WHERE job_id = ?
                        """,
                        (status, exit_code, finished_at, duration, resolved_actual, job_id)
                    )
            conn.close()

    def get_status(self, job_id: str) -> dict:
        conn = self._get_db()
        row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        conn.close()
        if not row:
            raise KeyError(f"Job not found: {job_id}")

        row_keys = row.keys()
        actual_model = row["actual_model"] if "actual_model" in row_keys and row["actual_model"] else "unknown"
        requested_model = row["requested_model"] if "requested_model" in row_keys and row["requested_model"] else row["model"]
        reasoning_level = row["reasoning_level"] if "reasoning_level" in row_keys and row["reasoning_level"] else ""
        cli_version = row["cli_version"] if "cli_version" in row_keys and row["cli_version"] else ""
        exit_code = row["exit_code"]

        return {
            "job_id": row["job_id"],
            "workspace_id": row["workspace_id"],
            "worker_cli": row["agent"] or "",
            "agent": row["agent"] or "",
            "provider": row["provider"] or "",
            "requested_model": requested_model or "",
            "actual_model": actual_model,
            "reasoning_level": reasoning_level,
            "cli_version": cli_version,
            "status": row["status"],
            "exit_status": exit_code,
            "exit_code": exit_code,
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "duration": row["duration"] if row["duration"] is not None else (time.time() - row["started_at"] if row["started_at"] else 0.0),
            "model": requested_model or "",
        }

    def get_output(self, job_id: str, cursor: int = 0, max_bytes: int = 65536) -> dict:
        conn = self._get_db()
        row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        conn.close()
        if not row:
            raise KeyError(f"Job not found: {job_id}")

        stdout_path = row["stdout_path"]
        stderr_path = row["stderr_path"]
        stdout_chunk = ""
        stderr_chunk = ""
        next_cursor = cursor

        if os.path.exists(stdout_path):
            with open(stdout_path, "rb") as f:
                f.seek(cursor)
                data = f.read(max_bytes)
                next_cursor = f.tell()
                stdout_chunk = data.decode("utf-8", errors="replace")

        if os.path.exists(stderr_path):
            with open(stderr_path, "rb") as f:
                stderr_chunk = f.read(max_bytes).decode("utf-8", errors="replace")

        return {
            "job_id": job_id,
            "status": row["status"],
            "exit_code": row["exit_code"],
            "cursor": cursor,
            "next_cursor": next_cursor,
            "stdout": stdout_chunk,
            "stderr": stderr_chunk,
        }

    def get_result(self, job_id: str, cursor: int = 0, max_bytes: int = 65536) -> dict:
        status_info = self.get_status(job_id)
        output_info = self.get_output(job_id, cursor=cursor, max_bytes=max_bytes)
        return {
            **status_info,
            "cursor": output_info["cursor"],
            "next_cursor": output_info["next_cursor"],
            "stdout": output_info["stdout"],
            "stderr": output_info["stderr"],
        }

    def cancel(self, job_id: str) -> dict:
        conn = self._get_db()
        row = conn.execute("SELECT pid, pgid, status FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        if not row:
            conn.close()
            raise KeyError(f"Job not found: {job_id}")

        if row["status"] != "running":
            conn.close()
            return {"job_id": job_id, "status": row["status"], "message": "Job is not running"}

        pgid = row["pgid"]
        pid = row["pid"]

        try:
            if pgid:
                os.killpg(pgid, signal.SIGTERM)
                time.sleep(0.1)
                os.killpg(pgid, signal.SIGKILL)
            elif pid:
                os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception as e:
            logger.warning("Error signalling job %s: %s", job_id, e)

        with conn:
            conn.execute(
                "UPDATE jobs SET status = 'cancelled', exit_code = 130, finished_at = ? WHERE job_id = ?",
                (time.time(), job_id)
            )
        conn.close()

        with self.lock:
            self.active_processes.pop(job_id, None)

        return {"job_id": job_id, "status": "cancelled", "message": "Job cancelled"}
