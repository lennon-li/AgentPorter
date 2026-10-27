"""Development-only, cache-only Qman consultation. No routing authority.

The fixed host-user path deliberately fails closed for a different UID. A host
bridge is not installed or implicitly authorized by this module.
"""
from __future__ import annotations

import json
import logging
import math
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import time
from datetime import datetime, timezone
from uuid import uuid4

ROOT = Path("/home/yeli/repos/Qman")
DATABASE = ROOT / "qman.db"
PYTHON = ROOT / ".venv/bin/python"
MAX_BYTES = 512 * 1024
TIMEOUT = 5.0
logger = logging.getLogger("agentporter.qman")
PROVIDERS = {"all", "codex", "claude", "agy", "copilot"}
CANDIDATES = {
    "jax": ("codex", "jax"), "liz": ("codex", "liz"),
    "prof": ("codex", "prof"), "phil": ("copilot", "phil"),
    "claude": ("claude", "ming"), "agy": ("agy", "agy"),
}


def _error(code):
    return {"mode": "consultation_unavailable", "error": code,
            "execution_authorized": False, "dispatch_enabled": False}


def _identifier(value, limit=128):
    return isinstance(value, str) and bool(re.fullmatch(r"[A-Za-z0-9_.:/+ -]{1,%d}" % limit, value))


def _read(argv):
    proc = subprocess.Popen(argv, cwd=ROOT, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, start_new_session=True,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": "/nonexistent",
             "PYTHONDONTWRITEBYTECODE": "1"})
    output = bytearray()
    deadline = time.monotonic() + TIMEOUT
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                left = deadline - time.monotonic()
                if left <= 0:
                    raise TimeoutError
                for key, _ in selector.select(min(left, 0.1)):
                    chunk = os.read(key.fileobj.fileno(), min(65536, MAX_BYTES + 1 - len(output)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        output.extend(chunk)
                        if len(output) > MAX_BYTES:
                            raise ValueError
        if proc.wait(timeout=max(0.001, deadline-time.monotonic())) != 0:
            raise RuntimeError
        return bytes(output)
    finally:
        # Always terminate descendants, including after leader exit.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait()
        proc.stdout.close()


def qman_consult(provider="all", profile=None, model=None):
    """Return Qman's existing JSON unchanged; never collect or authorize execution."""
    if not isinstance(provider, str) or provider not in PROVIDERS or (profile is not None and not _identifier(profile, 64)) or (model is not None and not _identifier(model)):
        return _error("invalid_scope")
    try:
        info = DATABASE.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            return _error("owner_only_database_unavailable")
        argv = [str(PYTHON), "-I", "-B", "-c",
            "import runpy,sys;sys.path.insert(0,'/home/yeli/repos/Qman/src');runpy.run_module('qman.cli',run_name='__main__')",
            "--db", str(DATABASE), "consult", "--provider", provider, "--format", "json"]
        if profile is not None:
            argv += ["--profile", profile]
        if model is not None:
            argv += ["--model", model]
        raw = _read(argv)
        result = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if (not isinstance(result, dict) or result.get("mode") != "consultation"
                or result.get("execution_authorized") is not False
                or result.get("dispatch_enabled") is not False
                or not isinstance(result.get("resources"), list)):
            return _error("invalid_response")
        return result
    except (OSError, ValueError, RuntimeError, RecursionError, TimeoutError, subprocess.TimeoutExpired):
        return _error("qman_unavailable")


def shadow_consult(agent, model):
    """Attempt advisory evidence only when explicitly enabled; never choose a route."""
    if os.environ.get("QMAN_PREFLIGHT_MODE", "off") != "shadow":
        return None
    started = time.monotonic()
    candidate = CANDIDATES.get(agent)
    result = qman_consult(*candidate, model=model) if candidate else _error("candidate_mapping_unknown")
    event = {
        "event": "qman_shadow", "trial_id": uuid4().hex,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "proposed_worker": agent if agent in CANDIDATES else "unmapped",
        "proposed_model": model if _identifier(model) else "unknown",
        "consultation_outcome": "ok" if result.get("mode") == "consultation" else "unavailable",
        "error": result.get("error"), "latency_ms": round((time.monotonic()-started)*1000, 3),
        "observations": [], "existing_policy_decision": "allowed_to_attempt_launch",
        "would_change_decision": None,
        "comparison": "no_qman_routing_policy_authorized", "actual_dispatched_worker": None,
        "runtime_outcome": "not_started", "job_id": None,
    }
    # No raw JSON, billing principals, prompts, identity digests or transcripts in logs.
    for resource in result.get("resources", [])[:16]:
        if not isinstance(resource, dict):
            continue
        windows = resource.get("windows", [])
        if not isinstance(windows, list):
            continue
        for window in windows[:16]:
            if not isinstance(window, dict):
                continue
            row = {"provider": candidate[0] if candidate else None,
                   "profile": candidate[1] if candidate else None,
                   "identity_bound": resource.get("identity_bound") is True,
                   "observation_fresh": window.get("observation_fresh") is True}
            for key in ("duration_minutes", "observed_at_utc_epoch", "fresh_until_utc_epoch",
                        "remaining_percent_at_observation", "remaining_percent_current", "resets_at_utc_epoch",
                        "remaining_units_reported", "limit_units_reported", "used_units_reported"):
                value = window.get(key)
                row[key] = value if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 1e15 else None
            for key in ("bucket_id", "window", "evidence_status", "quality_reported"):
                value = window.get(key)
                row[key] = value if _identifier(value, 128) else None
            row["unlimited_entitlement_reported"] = window.get("unlimited_entitlement_reported") if type(window.get("unlimited_entitlement_reported")) is bool else None
            event["observations"].append(row)
    return event


def record_shadow(event, *, job_id=None, launched=False):
    if event is None:
        return
    event.update(job_id=job_id, runtime_outcome="launch_accepted" if launched else "launch_failed",
                 actual_dispatched_worker=event["proposed_worker"] if launched else None)
    try:
        logger.info(json.dumps(event, allow_nan=False))
    except (ValueError, TypeError, OSError):
        # Logging cannot weaken an existing dispatch gate or redirect a worker.
        pass
