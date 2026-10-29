"""Asynchronous job execution, SQLite tracking, bounded log capture, and cancellation."""

import os
import stat
import time
import json
import uuid
import signal
import sqlite3
import logging
import threading
import subprocess
import hashlib
import selectors
import shutil
import sys
import fcntl
from pathlib import Path
from typing import Optional
from agentporter.provenance import extract_actual_model
from agentporter.admission import admitted_job, execution_slot, release
from agentporter.resources import ResourceCleanupError
from agentporter.process_handles import open_handle, signal_handle

logger = logging.getLogger("agentporter.tools.jobs")


class JobManager:
    """Manages asynchronous command and agent jobs with SQLite persistence."""

    def __init__(self, state_dir: Path, max_log_bytes: int = 10 * 1024 * 1024, max_active_jobs: int = 3):
        self.state_dir = Path(state_dir)
        self.max_log_bytes = max(1024, int(max_log_bytes))
        if type(max_active_jobs) is not int or not 1 <= max_active_jobs <= 16:
            raise ValueError('Invalid gateway active-job limit')
        self.max_active_jobs = max_active_jobs
        self.resources = None
        self._resource_leases = {}
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
        self.development_runtime = None
        self._job_cleanups: dict[str, object] = {}
        self._job_finalizers: dict[str, object] = {}
        self._job_model_evidence: dict[str, object] = {}
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
            conn.execute('CREATE TABLE IF NOT EXISTS job_admissions (token TEXT PRIMARY KEY, job_id TEXT, owner_pid INTEGER, created_at REAL)')
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
                ("runtime_profile", "TEXT"),
            ]:
                if col not in existing_cols:
                    conn.execute(f"ALTER TABLE jobs ADD COLUMN {col} {col_type}")
            conn.execute("""INSERT OR IGNORE INTO job_admissions
                SELECT 'legacy_' || job_id,job_id,0,created_at FROM jobs
                WHERE status IN ('running','cancelling','queued','cleanup_failed')
                AND job_id NOT IN (SELECT job_id FROM job_admissions WHERE job_id IS NOT NULL)""")
        conn.close()

    @staticmethod
    def _open_private_log(path: str):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        return os.fdopen(fd, "wb")

    @staticmethod
    def _validate_sandbox_command(cmd: list[str], workspace_path: str, *, workspace_descriptor=None) -> str:
        """Raw async jobs may only launch an offline Bubblewrap process.

        Do not treat an absent agent label as proof of authorization.
        This is a defense for the sole trusted internal exec_start call
        site, NOT a general command-classification/shell-policy scheme.
        """
        executable = shutil.which("bwrap")
        if not executable or not cmd or cmd[0] != "bwrap":
            raise PermissionError("Raw host process execution is forbidden; Bubblewrap required")
        required = {"--unshare-all", "--unshare-net", "--clearenv", "--die-with-parent"}
        try:
            boundary = cmd.index("--")
        except ValueError as exc:
            raise PermissionError("Malformed sandbox command: missing command boundary") from exc
        launcher_args = cmd[:boundary]
        if not required.issubset(launcher_args) or "--share-net" in launcher_args:
            raise PermissionError("Untrusted sandbox invocation or network permissions")
        if workspace_descriptor is not None:
            if type(workspace_descriptor) is not int or not stat.S_ISDIR(os.fstat(workspace_descriptor).st_mode):
                raise PermissionError('Invalid prepared workspace descriptor')
            real_path = f'/proc/self/fd/{workspace_descriptor}'
            if workspace_path != real_path:
                raise PermissionError('Prepared workspace descriptor mismatch')
        else:
            real_path = os.path.realpath(workspace_path)
        if not any(
            launcher_args[i:i+3] == [flag, real_path, "/workspace"]
            for flag in ("--bind", "--ro-bind")
            for i in range(len(launcher_args)-2)
        ):
            raise PermissionError("Sandbox command does not bind the authorized workspace")
        if any("SSH_AUTH_SOCK" in arg or "/.ssh" in arg or "/.config/gh" in arg
               for arg in launcher_args):
            raise PermissionError("Sandbox command attempts credential access")
        # Keep the Bwrap executable path resolved by the trusted host lookup.
        # The launch environment below deliberately strips the host's PATH;
        # looking up the literal 'bwrap' again would fail for /usr/local or Nix.
        return os.path.realpath(executable)

    def _popen(self, command, **kwargs):
        lease = self.resources.create() if self.resources is not None else None
        try:
            proc = subprocess.Popen(lease.command(command) if lease else command, **kwargs)
            proc._agentporter_stop = threading.Event()
            try:
                proc._agentporter_pidfd = open_handle(proc.pid)
            except BaseException:
                proc.kill()
                proc.wait(timeout=2)
                raise
        except BaseException:
            if lease: lease.close()
            raise
        if lease:
            with self.lock:
                self._resource_leases[proc] = lease
        return proc

    def _close_pidfd(self, proc):
        with self.lock:
            fd = getattr(proc, '_agentporter_pidfd', None)
            proc._agentporter_pidfd = None
            if fd is not None:
                os.close(fd)

    def _drop_lease(self, proc):
        with self.lock:
            lease = self._resource_leases.pop(proc, None)
        if lease:
            try:
                lease.close()
            except Exception as error:
                raise ResourceCleanupError('Job envelope cleanup remains unverified') from error

    def _start_process_job(self, *, command, workspace_id, workspace_path, receipt,
                           timeout_seconds, provider='', model='', requested_model='',
                           reasoning_level='', cli_version='', finalize=None, cleanup=None, pass_fds=()):
        job_id = f'job_{uuid.uuid4().hex[:24]}'
        stdout_path = str(self.jobs_dir / f'{job_id}.stdout.log')
        stderr_path = str(self.jobs_dir / f'{job_id}.stderr.log')
        stdout_f = stderr_f = proc = None
        now = time.time()
        try:
            stdout_f = self._open_private_log(stdout_path)
            stderr_f = self._open_private_log(stderr_path)
            proc = self._popen(command, cwd='/', stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                env={'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8', 'HOME': '/nonexistent'},
                process_group=0, **({'pass_fds': pass_fds} if pass_fds else {}))
            db = self._get_db()
            try:
                with db:
                    db.execute('''INSERT INTO jobs (job_id,workspace_id,argv,cwd,pid,pgid,status,
                        created_at,started_at,stdout_path,stderr_path,agent,provider,model,
                        requested_model,actual_model,reasoning_level,cli_version)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
                        (job_id,workspace_id,json.dumps(receipt),workspace_path,proc.pid,proc.pid,'running',
                         now,now,stdout_path,stderr_path,'',provider,model,requested_model,'unknown',reasoning_level,cli_version))
            finally:
                db.close()
            with self.lock:
                self.active_processes[job_id] = proc
                self._job_finalizers[job_id] = finalize
                self._job_cleanups[job_id] = cleanup
            threading.Thread(target=self._monitor_proc,
                args=(job_id,proc,stdout_f,stderr_f,stdout_path,stderr_path,timeout_seconds,now),daemon=True).start()
            return job_id
        except BaseException:
            try:
                if proc is not None:
                    self._terminate_process_tree(proc)
                    proc.wait(timeout=2)
                    for pipe in (proc.stdout, proc.stderr):
                        if pipe: pipe.close()
                    self._drop_lease(proc)
                    self._close_pidfd(proc)
            finally:
                for stream in (stdout_f, stderr_f):
                    if stream: stream.close()
                with self.lock:
                    self.active_processes.pop(job_id, None)
                    self._job_finalizers.pop(job_id, None)
                    self._job_cleanups.pop(job_id, None)
                try:
                    if finalize is not None:
                        finalize(False)
                finally:
                    if cleanup is not None:
                        cleanup()
            db = self._get_db()
            try:
                with db:
                    db.execute("UPDATE jobs SET status='failed',exit_code=1,finished_at=? WHERE job_id=?", (time.time(),job_id))
            finally:
                db.close()
            raise

    def configure_resources(self, resources):
        """Exclusive startup recovery; never signal a PID loaded from SQLite."""
        fd = os.open(self.state_dir / 'job-supervisor.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            resources.recover()
            db = self._get_db()
            try:
                with db:
                    now=time.time()
                    db.execute("""UPDATE jobs SET status='interrupted',exit_code=130,finished_at=?,
                        duration=MAX(0,?-COALESCE(started_at,created_at,?))
                        WHERE status IN ('running','cancelling','queued','cleanup_failed')""", (now,now,now))
                    db.execute('DELETE FROM job_admissions')
            finally:
                db.close()
        except BaseException:
            os.close(fd)
            raise
        self._supervisor_lock = fd
        self.resources = resources

    @admitted_job
    def start_confined_agent_job(
        self,
        workspace_id: str,
        workspace_path: str,
        cmd: list[str],
        agent: str,
        provider: str = "",
        model: str = "",
        requested_model: str = "",
        reasoning_level: str = "",
        cli_version: str = "",
        timeout_seconds: int = 900,
        env: Optional[dict] = None,
        policy=None,
    ) -> str:
        """Launch an agent only through the verified development OS boundary.

        The raw sandbox launcher deliberately rejects network access. Development
        delegation is a separate, broker-owned boundary with private credentials;
        its verified runtime constructs the entire Bubblewrap invocation.
        """
        runtime = self.development_runtime
        if runtime is None:
            raise PermissionError("Delegated execution blocked_pending_os_confinement: OS-confined agent launcher not installed")
        status = runtime.status(agent, None, None)
        if not status.get("delegatable"):
            raise PermissionError(status.get("availability_reason") or "Development confinement unavailable")
        if policy is None or policy.git_commit or policy.git_push:
            raise PermissionError("Confined development workers cannot publish Git changes")
        if not cmd or not all(isinstance(arg, str) and arg for arg in cmd):
            raise ValueError("cmd must be a non-empty list of non-empty strings")
        timeout_seconds = max(1, min(900, int(timeout_seconds)))
        prepared = runtime.prepare(agent, workspace_path, policy.workspace_write, cmd, env)
        job_id = f"job_{uuid.uuid4().hex[:24]}"
        stdout_path = str(self.jobs_dir / f"{job_id}.stdout.log")
        stderr_path = str(self.jobs_dir / f"{job_id}.stderr.log")
        stdout_f = stderr_f = proc = None
        recorded = False
        now = time.time()
        try:
            command = prepared.command
            # Never accept an executable selected from an agent-controlled PATH.
            bwrap = shutil.which("bwrap", path="/usr/bin:/bin")
            if not bwrap or not command or os.path.realpath(command[0]) != os.path.realpath(bwrap):
                raise PermissionError("Development runtime did not return a trusted Bubblewrap launch")
            stdout_f = self._open_private_log(stdout_path)
            stderr_f = self._open_private_log(stderr_path)
            proc = self._popen(
                command,
                cwd="/",
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
                pass_fds=getattr(prepared, "pass_fds", ()),
                process_group=0,
            )
            conn = self._get_db()
            try:
                with conn:
                    conn.execute(
                        """INSERT INTO jobs (
                            job_id, workspace_id, argv, cwd, pid, pgid, status,
                            created_at, started_at, stdout_path, stderr_path,
                            agent, provider, model, requested_model, actual_model,
                            reasoning_level, cli_version, runtime_profile
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (job_id, workspace_id, json.dumps(["confined-development-worker", agent]),
                         workspace_path, proc.pid, proc.pid, "running", now, now,
                         stdout_path, stderr_path, agent, provider, model,
                         requested_model, "unknown", reasoning_level, cli_version,
                         status.get("runtime_profile", "development-bubblewrap")),
                    )
                recorded = True
            finally:
                conn.close()
            with self.lock:
                self.active_processes[job_id] = proc
                self._job_cleanups[job_id] = prepared.cleanup
                self._job_finalizers[job_id] = getattr(prepared, "finalize", None)
                self._job_model_evidence[job_id] = getattr(prepared, "model_evidence", None)
            threading.Thread(
                target=self._monitor_proc,
                args=(job_id, proc, stdout_f, stderr_f, stdout_path, stderr_path,
                      timeout_seconds, now),
                daemon=True,
            ).start()
            return job_id
        except BaseException:
            try:
                if proc is not None:
                    self._terminate_process_tree(proc)
                    proc.wait()
                    for pipe in (proc.stdout, proc.stderr):
                        if pipe is not None:
                            pipe.close()
                    self._drop_lease(proc)
                    self._close_pidfd(proc)
            finally:
                for stream in (stdout_f, stderr_f):
                    if stream is not None:
                        stream.close()
                with self.lock:
                    self.active_processes.pop(job_id, None)
                    self._job_cleanups.pop(job_id, None)
                    self._job_finalizers.pop(job_id, None)
                    self._job_model_evidence.pop(job_id, None)
                try:
                    try:
                        if getattr(prepared, "finalize", None) is not None:
                            prepared.finalize(False)
                    finally:
                        prepared.cleanup()
                finally:
                    if recorded:
                        conn = self._get_db()
                        try:
                            with conn:
                                conn.execute(
                                    "UPDATE jobs SET status = 'failed', exit_code = 1, finished_at = ?, duration = ? WHERE job_id = ?",
                                    (time.time(), time.time() - now, job_id),
                                )
                        finally:
                            conn.close()
            raise

    @admitted_job
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
        finalize=None,
        cleanup=None,
        workspace_descriptor=None,
    ) -> str:
        if agent:
            raise PermissionError(
                "Agent worker cannot launch through unconfined start_raw_job"
            )
        if not cmd or not all(isinstance(x, str) and x for x in cmd):
            raise ValueError("cmd must be a non-empty list of non-empty strings")
        trusted_bwrap = self._validate_sandbox_command(cmd, workspace_path,
            **({'workspace_descriptor': workspace_descriptor} if workspace_descriptor is not None else {}))
        timeout_seconds = max(1, int(timeout_seconds))

        return self._start_process_job(command=[trusted_bwrap, *cmd[1:]],
            workspace_id=workspace_id, workspace_path=workspace_path, receipt=cmd,
            timeout_seconds=min(900, timeout_seconds), provider=provider, model=model,
            requested_model=requested_model, reasoning_level=reasoning_level, cli_version=cli_version,
            finalize=finalize, cleanup=cleanup,
            **({'pass_fds': (workspace_descriptor,)} if workspace_descriptor is not None else {}))

    @admitted_job
    def start_scoped_https_job(
        self,
        workspace_id: str,
        workspace_path: str,
        config_dir: str,
        method: str,
        url: str,
        timeout_seconds: int,
    ) -> str:
        """Launch only the installed, fixed-function HTTPS fetch worker.

        This is intentionally not start_raw_job: no caller-selectable binary,
        shell, environment, command flags, or network namespace permission.
        The parent broker must validate the registered workspace and exact
        allowlist, while the child reloads the operator policy independently.
        """
        from agentporter.scoped_https import _url_parts, SUPPORTED_METHODS

        if workspace_id != "cranary" or method not in SUPPORTED_METHODS:
            raise PermissionError("Scoped HTTPS worker is approved only for cranary GET/HEAD")
        host, _ = _url_parts(url)
        url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
        if not 1 <= int(timeout_seconds) <= 20:
            raise ValueError("Scoped HTTPS job timeout must be <= 20 seconds")
        ws = os.path.realpath(workspace_path)
        policy_dir = os.path.realpath(config_dir)
        if policy_dir == ws or policy_dir.startswith(ws + os.sep):
            raise PermissionError("Owner policy must not reside in workspace")
        # The source is the installed signed-off release, not the workspace.
        cmd = [
            sys.executable, "-I", "-m", "agentporter.scoped_https_worker",
            "--config-dir", policy_dir,
            "--workspace-id", workspace_id,
            "--method", method,
            "--url", url,
            "--timeout", str(int(timeout_seconds)),
        ]
        job_id = self._start_process_job(command=cmd, workspace_id=workspace_id,
            workspace_path=ws, receipt=['scoped-public-https', method, host],
            timeout_seconds=timeout_seconds)
        logger.info(json.dumps({'event':'public_https_async_start','job_id':job_id,
            'workspace_id':workspace_id,'host':host,'method':method,
            'url_sha256_prefix':url_hash,'timeout_seconds':timeout_seconds}))
        return job_id

    def _terminate_process_tree(self, proc: subprocess.Popen) -> None:
        """Terminate an owned job tree, never a numeric process group.

        A pidfd identifies only the launcher. Kill its cgroup before waiting on
        output EOF: descendants can hold pipes or start new sessions. Offline
        legacy test profiles without resources rely on Bubblewrap's PID namespace.
        """
        with self.lock:
            fd = getattr(proc, '_agentporter_pidfd', None)
            owned_fd = os.dup(fd) if fd is not None else None
            lease = self._resource_leases.get(proc)
        if owned_fd is None:
            raise PermissionError('Missing owned process handle')
        try:
            try:
                if lease is not None:
                    lease.terminate()
            finally:
                try:
                    signal_handle(owned_fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        finally:
            os.close(owned_fd)

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
        """Drain child pipes with a strict per-stream disk budget.

        Unlike redirecting child output straight to log files and periodically
        checking file sizes, pipe backpressure means a child cannot write
        unbounded logs between monitor ticks. Continue watching until *pipe
        EOF*, not merely until the leader exits, since descendants may retain
        inherited stdout/stderr descriptors.
        """
        status = "completed"
        exit_code = None
        # Convert wall-clock start age to a monotonic deadline.
        remaining = max(0.0, timeout_seconds - (time.time() - start_time))
        deadline = time.monotonic() + remaining
        selector = selectors.DefaultSelector()
        usage = {"stdout": 0, "stderr": 0}
        leader_reaped = False

        try:
            for name, pipe, log in (
                ("stdout", proc.stdout, stdout_f),
                ("stderr", proc.stderr, stderr_f),
            ):
                if pipe is None:
                    raise RuntimeError(f"Missing {name} pipe")
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, (name, log))

            while selector.get_map():
                if proc._agentporter_stop.is_set():
                    status, exit_code = 'cancelled', 130
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    status = "timed_out"
                    exit_code = 124
                    break

                for key, _ in selector.select(min(remaining, 0.2)):
                    pipe = key.fileobj
                    name, log = key.data
                    try:
                        chunk = os.read(pipe.fileno(), 64 * 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(pipe)
                        pipe.close()
                        continue

                    budget = self.max_log_bytes - usage[name]
                    saved = chunk[:budget]
                    if saved:
                        log.write(saved)
                        log.flush()
                        usage[name] += len(saved)

                    if len(chunk) > budget:
                        status = "output_limit_exceeded"
                        exit_code = 125
                        break

                if exit_code is not None:
                    break

            if exit_code is not None:
                # Kill the owned cgroup even if the launcher has already exited.
                self._terminate_process_tree(proc)
                proc.wait(timeout=2)
            else:
                # Pipe EOF does not establish process exit. Keep cancellation
                # responsive even for a process that closes both output streams.
                while proc.poll() is None:
                    if proc._agentporter_stop.is_set() or time.monotonic() >= deadline:
                        status, exit_code = ('cancelled', 130) if proc._agentporter_stop.is_set() else ('timed_out', 124)
                        self._terminate_process_tree(proc)
                        proc.wait(timeout=2)
                        break
                    try:
                        proc.wait(timeout=min(.2, max(.01, deadline-time.monotonic())))
                    except subprocess.TimeoutExpired:
                        pass
            leader_reaped = True

            if exit_code is None:
                exit_code = proc.returncode
                if exit_code != 0:
                    status = "failed"
        except Exception as e:
            status = "failed"
            exit_code = 1
            logger.error("Job %s monitor error: %s", job_id, e)
            try:
                self._terminate_process_tree(proc)
                proc.wait(timeout=2)
                leader_reaped = True
            except Exception:
                logger.exception('Job %s termination remains unverified', job_id)
        finally:
            selector.close()
            self._close_pidfd(proc)
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None and not pipe.closed:
                    pipe.close()
            for log in (stdout_f, stderr_f):
                try:
                    log.close()
                except Exception:
                    pass
            cleanup_ok = leader_reaped
            if not cleanup_ok:
                status, exit_code = 'cleanup_failed', 1
            with self.lock:
                lease = self._resource_leases.pop(proc, None)
            if lease is not None:
                try:
                    lease.close()
                except Exception:
                    cleanup_ok = False
                    status, exit_code = 'cleanup_failed', 1
                    logger.exception('Resource cleanup failed for %s', job_id)
            # Serialize publication with cancellation's conditional state transition.
            # A cancelled request must never publish; a finalizer that already owns
            # this write transaction completes before cancellation can be accepted.
            conn = None
            with self.lock:
                finalizer = self._job_finalizers.pop(job_id, None)
            if finalizer is not None:
                conn = self._get_db()
                conn.execute("BEGIN IMMEDIATE")
                row = conn.execute("SELECT status FROM jobs WHERE job_id=?", (job_id,)).fetchone()
                success = (cleanup_ok and lease is not None and status == "completed"
                           and exit_code == 0 and not proc._agentporter_stop.is_set()
                           and row is not None and row["status"] == "running")
                try:
                    finalizer(success)
                    if not success and status == "completed" and exit_code == 0:
                        status, exit_code = "failed", 1
                except Exception:
                    # Validation/publication failure is terminal after verified OS
                    # cleanup. It must not strand capacity as cleanup_failed.
                    status, exit_code = ("failed" if cleanup_ok else "cleanup_failed"), 1
                    logger.exception("Workspace publication failed for %s", job_id)
            with self.lock:
                cleanup = self._job_cleanups.pop(job_id, None)
            if cleanup is not None:
                try:
                    cleanup()
                except Exception:
                    cleanup_ok = False
                    status, exit_code = 'cleanup_failed', 1
                    logger.exception("Confined worker cleanup failed for %s", job_id)

            finished_at = time.time()
            duration = finished_at - start_time
            with self.lock:
                model_evidence = self._job_model_evidence.pop(job_id, None)
            actual_model = extract_actual_model(stdout_path, stderr_path, evidence=model_evidence)

            with self.lock:
                self.active_processes.pop(job_id, None)

            if conn is None:
                conn = self._get_db()
            with conn:
                row = conn.execute(
                    "SELECT status, actual_model FROM jobs WHERE job_id = ?", (job_id,)
                ).fetchone()
                existing_actual = row["actual_model"] if row and row["actual_model"] else "unknown"
                resolved_actual = actual_model if actual_model != "unknown" else existing_actual
                if row and row["status"] in {'cancelled','cancelling'} and cleanup_ok:
                    status, exit_code = 'cancelled', 130
                    conn.execute(
                        "UPDATE jobs SET status='cancelled',exit_code=130,finished_at = ?, duration = ?, actual_model = ? WHERE job_id = ?",
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
            if cleanup_ok:
                release(self, job_id=job_id)
            logger.info(json.dumps({
                "event": "async_job_result",
                "job_id": job_id,
                "status": status,
                "exit_code": exit_code,
                "duration_seconds": round(duration, 3),
            }))

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
            "runtime_profile": row["runtime_profile"],
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

        with self.lock:
            proc = self.active_processes.get(job_id)
            fd = getattr(proc, '_agentporter_pidfd', None) if proc is not None else None
            owned_fd = os.dup(fd) if fd is not None else None
            lease = self._resource_leases.get(proc) if proc is not None else None
        if proc is None or proc.pid != row['pid'] or owned_fd is None:
            if owned_fd is not None: os.close(owned_fd)
            conn.close()
            raise PermissionError('Cancellation requires a currently owned live process handle; restart recovery is separate')

        try:
            with conn:
                changed = conn.execute("""UPDATE jobs SET status='cancelling',exit_code=NULL
                    WHERE job_id=? AND status='running'""", (job_id,))
            if changed.rowcount == 0:
                return {"job_id": job_id, "status": self.get_status(job_id)['status'],
                        "message": "Job finished while cancellation was requested"}
            proc._agentporter_stop.set()
            try:
                if lease is not None:
                    lease.terminate()
            finally:
                signal_handle(owned_fd, signal.SIGKILL)
        except ProcessLookupError:
            pass
        except Exception as e:
            logger.warning("Error signalling job %s: %s", job_id, e)
            with conn:
                conn.execute("UPDATE jobs SET status='cleanup_failed',exit_code=1 WHERE job_id=? AND status='cancelling'",(job_id,))
            raise
        finally:
            os.close(owned_fd)
            conn.close()

        # A cancellation reply is not cleanup proof. Wait briefly for the
        # monitor, then preserve a nonterminal state if cleanup is still busy.
        deadline=time.monotonic()+3
        while self.get_status(job_id)['status']=='cancelling' and time.monotonic()<deadline:
            time.sleep(.01)
        return {"job_id": job_id, "status": self.get_status(job_id)['status'],
                "message": "Cancellation requested; cleanup is tracked by job status"}
