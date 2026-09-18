"""Asynchronous job execution, SQLite tracking, bounded log capture, and cancellation."""

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

    def __init__(self, state_dir: Path, max_log_bytes: int = 10 * 1024 * 1024):
        self.state_dir = Path(state_dir)
        self.max_log_bytes = max(1024, int(max_log_bytes))
        self.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.jobs_dir = self.state_dir / "jobs"
        self.jobs_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        for p in (self.state_dir, self.jobs_dir):
            try:
                os.chmod(p, 0o700)
            except OSError:
                pass

        self.db_path = self.state_dir / "jobs.db"
        self.active_processes: dict[str, subprocess.Popen] = {}
        self.lock = threading.Lock()
        self._init_db()

    def _get_db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            os.chmod(self.db_path, 0o600)
        except OSError:
            pass
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
            cursor = conn.execute("PRAGMA table_info(jobs)")
            existing_cols = {row["name"] for row in cursor.fetchall()}
            for col, col_type in [
                ("requested_model", "TEXT"),
                ("actual_model", "TEXT"),
                ("reasoning_level", "TEXT"),
                ("cli_version", "TEXT"),
            ]:
                if col not in existing_cols:
                    conn.execute(f"ALTER TABLE jobs ADD COLUMN {col} {col_type}")
        conn.close()

    @staticmethod
    def _open_private_log(path: str):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        return os.fdopen(fd, "wb")

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
        if not cmd or not all(isinstance(x, str) and x for x in cmd):
            raise ValueError("cmd must be a non-empty list of non-empty strings")
        timeout_seconds = max(1, int(timeout_seconds))

        job_id = f"job_{uuid.uuid4().hex[:24]}"
        stdout_path = str(self.jobs_dir / f"{job_id}.stdout.log")
        stderr_path = str(self.jobs_dir / f"{job_id}.stderr.log")
        stdout_f = self._open_private_log(stdout_path)
        stderr_f = self._open_private_log(stderr_path)
        now = time.time()

        try:
            proc = subprocess.Popen(
                cmd,
                cwd=workspace_path,
                stdout=stdout_f,
                stderr=stderr_f,
                env=env,
                process_group=0,
            )
        except Exception:
            stdout_f.close()
            stderr_f.close()
            raise

        pgid = os.getpgid(proc.pid)
        with self.lock:
            self.active_processes[job_id] = proc

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
                    job_id,
                    workspace_id,
                    json.dumps(cmd),
                    workspace_path,
                    proc.pid,
                    pgid,
                    "running",
                    now,
                    now,
                    stdout_path,
                    stderr_path,
                    agent,
                    provider,
                    model,
                    requested_model,
                    "unknown",
                    reasoning_level,
                    cli_version,
                ),
            )
        conn.close()

        threading.Thread(
            target=self._monitor_proc,
            args=(
                job_id,
                proc,
                stdout_f,
                stderr_f,
                stdout_path,
                stderr_path,
                timeout_seconds,
                now,
            ),
            daemon=True,
        ).start()
        return job_id

    @staticmethod
    def _kill_process_group(proc: subprocess.Popen) -> None:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _monitor_proc(
        self,
        job_id: str,
        proc: subprocess.Popen,
        stdout_f,
        stderr_f,
        stdout_path: str,
        stderr_path: str,
        timeout_seconds: int,
        start_time: float,
    ):
        status = "completed"
        exit_code = None
        deadline = start_time + timeout_seconds

        try:
            while proc.poll() is None:
                now = time.time()
                if now >= deadline:
                    status = "timed_out"
                    exit_code = 124
                    self._kill_process_group(proc)
                    break

                try:
                    stdout_size = os.path.getsize(stdout_path)
                    stderr_size = os.path.getsize(stderr_path)
                except OSError:
                    stdout_size = stderr_size = 0

                if stdout_size > self.max_log_bytes or stderr_size > self.max_log_bytes:
                    status = "output_limit_exceeded"
                    exit_code = 125
                    self._kill_process_group(proc)
                    break
                time.sleep(0.1)

            if proc.poll() is None:
                proc.wait(timeout=5)
            else:
                proc.wait()

            if exit_code is None:
                exit_code = proc.returncode
                if exit_code != 0:
                    status = "failed"
        except Exception as e:
            status = "failed"
            exit_code = 1
            logger.error("Job %s monitor error: %s", job_id, e)
            self._kill_process_group(proc)
        finally:
            try:
                stdout_f.close()
                stderr_f.close()
            except Exception:
                pass

            finished_at = time.time()
            duration = finished_at - start_time
            actual_model = extract_actual_model(stdout_path, stderr_path)

            with self.lock:
                self.active_processes.pop(job_id, None)

            conn = self._get_db()
            with conn:
                row = conn.execute(
                    "SELECT status, actual_model FROM jobs WHERE job_id = ?", (job_id,)
                ).fetchone()
                existing_actual = row["actual_model"] if row and row["actual_model"] else "unknown"
                resolved_actual = actual_model if actual_model != "unknown" else existing_actual
                if row and row["status"] == "cancelled":
                    conn.execute(
                        "UPDATE jobs SET finished_at = ?, duration = ?, actual_model = ? WHERE job_id = ?",
                        (finished_at, duration, resolved_actual, job_id),
                    )
                else:
                    conn.execute(
                        """
                        UPDATE jobs SET
                            status = ?, exit_code = ?, finished_at = ?, duration = ?, actual_model = ?
                        WHERE job_id = ?
                        """,
                        (status, exit_code, finished_at, duration, resolved_actual, job_id),
                    )
            conn.close()

    def get_status(self, job_id: str) -> dict:
        conn = self._get_db()
        row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        conn.close()
        if not row:
            raise KeyError(f"Job not found: {job_id}")

        actual_model = row["actual_model"] or "unknown"
        configured_model = row["model"] or ""
        requested_model = row["requested_model"] or ""
        reasoning_level = row["reasoning_level"] or ""
        cli_version = row["cli_version"] or ""
        exit_code = row["exit_code"]

        return {
            "job_id": row["job_id"],
            "workspace_id": row["workspace_id"],
            "worker_cli": row["agent"] or "",
            "agent": row["agent"] or "",
            "provider": row["provider"] or "",
            "configured_model": configured_model,
            "requested_model": requested_model,
            "actual_model": actual_model,
            "reasoning_level": reasoning_level,
            "cli_version": cli_version,
            "status": row["status"],
            "exit_status": exit_code,
            "exit_code": exit_code,
            "created_at": row["created_at"],
            "started_at": row["started_at"],
            "finished_at": row["finished_at"],
            "duration": (
                row["duration"]
                if row["duration"] is not None
                else (time.time() - row["started_at"] if row["started_at"] else 0.0)
            ),
            "model": configured_model,
        }

    def get_output(self, job_id: str, cursor: int = 0, max_bytes: int = 65536) -> dict:
        conn = self._get_db()
        row = conn.execute("SELECT * FROM jobs WHERE job_id = ?", (job_id,)).fetchone()
        conn.close()
        if not row:
            raise KeyError(f"Job not found: {job_id}")

        cursor = max(0, int(cursor))
        max_bytes = max(1, min(int(max_bytes), 256 * 1024))
        stdout_chunk = ""
        stderr_chunk = ""
        next_cursor = cursor

        if os.path.exists(row["stdout_path"]):
            with open(row["stdout_path"], "rb") as f:
                f.seek(cursor)
                data = f.read(max_bytes)
                next_cursor = f.tell()
                stdout_chunk = data.decode("utf-8", errors="replace")

        if os.path.exists(row["stderr_path"]):
            with open(row["stderr_path"], "rb") as f:
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
        return {
            **self.get_status(job_id),
            **{
                k: v
                for k, v in self.get_output(job_id, cursor=cursor, max_bytes=max_bytes).items()
                if k in {"cursor", "next_cursor", "stdout", "stderr"}
            },
        }

    def cancel(self, job_id: str) -> dict:
        conn = self._get_db()
        row = conn.execute(
            "SELECT pid, pgid, status, started_at FROM jobs WHERE job_id = ?", (job_id,)
        ).fetchone()
        if not row:
            conn.close()
            raise KeyError(f"Job not found: {job_id}")

        if row["status"] != "running":
            conn.close()
            return {"job_id": job_id, "status": row["status"], "message": "Job is not running"}

        try:
            if row["pgid"]:
                os.killpg(row["pgid"], signal.SIGTERM)
                time.sleep(0.1)
                os.killpg(row["pgid"], signal.SIGKILL)
            elif row["pid"]:
                os.kill(row["pid"], signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception as e:
            logger.warning("Error signalling job %s: %s", job_id, e)

        finished_at = time.time()
        duration = finished_at - row["started_at"] if row["started_at"] else 0.0
        with conn:
            conn.execute(
                """
                UPDATE jobs SET status = 'cancelled', exit_code = 130,
                    finished_at = ?, duration = ?
                WHERE job_id = ?
                """,
                (finished_at, duration, job_id),
            )
        conn.close()

        with self.lock:
            self.active_processes.pop(job_id, None)

        return {"job_id": job_id, "status": "cancelled", "message": "Job cancelled"}
