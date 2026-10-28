"""Development-only Qman consultation. No routing authority."""
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
_SAFE_VALUES = {
    "quota_state": frozenset(("unknown", "headroom_reported", "exhausted_observed",
        "permission_denied", "client_reported_unverified", "billing_reports_multiple",
        "user_billing_reported", "org_billing_reported", "local_observation_unverified")),
    "quota_reason": frozenset(("fresh_recovery_required", "quota_only_not_execution_authorization",
        "quota_unbound_stale_or_failed", "copilot_sdk_identity_not_bound",
        "local_native_client_statusline_not_account_bound", "billing_report_not_remaining_quota",
        "provider_collector_not_integrated", "local_observation_not_provider_verified")),
    "quota_status": frozenset(("unknown", "available", "low", "exhausted")),
    "evidence_status": frozenset(("native_codex_bound", "native_client_report_unverified",
        "copilot_sdk_client_report_unverified", "local_record_unverified")),
    "quality_reported": frozenset(("unknown", "client_reported")),
    "source": frozenset(("copilot_sdk_account_quota",)),
}
_NUMBER_FIELDS = frozenset(("duration_minutes", "used_percent_observed",
    "remaining_percent_at_observation", "remaining_percent_current", "observed_at_utc_epoch",
    "fresh_until_utc_epoch", "resets_at_utc_epoch", "seconds_until_reset_hint",
    "remaining_units_reported", "limit_units_reported", "used_units_reported"))


def _workspace_paths(registry):
    """Resolve every configured workspace or refuse to consult Qman."""
    if registry is None or not callable(getattr(registry, "list_all", None)):
        raise ValueError("workspace registry unavailable")
    rows = registry.list_all()
    if not isinstance(rows, list) or not rows:
        raise ValueError("workspace registry unavailable")
    paths = []
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("path"), str) or not row["path"].strip():
            raise ValueError("invalid registered workspace")
        paths.append(Path(row["path"]).expanduser().resolve(strict=True))
    return paths


def _safe_source(registry):
    """Refuse mutable Qman code or interpreter paths overlapping any workspace."""
    workspaces = _workspace_paths(registry)
    paths = [Path(ROOT).expanduser().resolve(strict=True),
             Path(PYTHON).expanduser().resolve(strict=True),
             (Path(ROOT) / "src").expanduser().resolve(strict=True)]
    for source in paths:
        for workspace in workspaces:
            if source == workspace or source.is_relative_to(workspace) or workspace.is_relative_to(source):
                return False
    return True


def _error(code):
    return {"mode": "consultation_unavailable", "error": code,
            "execution_authorized": False, "dispatch_enabled": False}


def _identifier(value, limit=128):
    return isinstance(value, str) and not value.startswith("-") and bool(re.fullmatch(r"[A-Za-z0-9_.:/+ -]{1,%d}" % limit, value))


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


def _bounded_projection(result):
    """Expose bounded quota evidence only; never pass through arbitrary Qman fields."""
    projection = {"mode": "consultation", "execution_authorized": False,
                  "dispatch_enabled": False, "resources": []}
    if type(result.get("as_of_utc_epoch")) in (int, float) and math.isfinite(result["as_of_utc_epoch"]):
        projection["as_of_utc_epoch"] = min(max(result["as_of_utc_epoch"], 0), 32503680000)
    for resource in result["resources"][:16]:
        if type(resource) is not dict:
            continue
        row = {}
        if resource.get("provider") in PROVIDERS - {"all"}:
            row["provider"] = resource["provider"]
        for key in ("quota_state", "quota_reason"):
            value = resource.get(key)
            if type(value) is str and value in _SAFE_VALUES[key]:
                row[key] = value
        for key in ("identity_bound", "quota_read_current", "ordinary_usage_allowed"):
            value = resource.get(key)
            if type(value) is bool:
                row[key] = value
        windows = []
        raw_windows = resource.get("windows")
        if type(raw_windows) is list:
            for window in raw_windows[:16]:
                if type(window) is not dict:
                    continue
                safe = {}
                for key in _NUMBER_FIELDS:
                    value = window.get(key)
                    if type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 32503680000:
                        safe[key] = value
                for key in ("observation_fresh", "unlimited_entitlement_reported"):
                    if type(window.get(key)) is bool:
                        safe[key] = window[key]
                for key, allowed in _SAFE_VALUES.items():
                    value = window.get(key)
                    if type(value) is str and value in allowed:
                        safe[key] = value
                windows.append(safe)
        row["windows"] = windows
        projection["resources"].append(row)
    return projection


def qman_consult(provider="all", profile=None, model=None, *, workspace_registry=None):
    """Return a bounded advisory projection, never execution authority."""
    if not isinstance(provider, str) or provider not in PROVIDERS or (profile is not None and not _identifier(profile, 64)) or (model is not None and not _identifier(model)):
        return _error("invalid_scope")
    try:
        if not _safe_source(workspace_registry):
            return _error("qman_source_overlaps_workspace")
        info = DATABASE.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            return _error("owner_only_database_unavailable")
        source = str((Path(ROOT) / "src").resolve(strict=True))
        argv = [str(Path(PYTHON).resolve(strict=True)), "-I", "-B", "-c",
            "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('qman.cli',run_name='__main__')", source,
            "--db", str(DATABASE), "consult", "--provider", provider, "--format", "json"]
        if profile is not None:
            argv += ["--profile=" + profile]
        if model is not None:
            argv += ["--model=" + model]
        raw = _read(argv)
        result = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if (not isinstance(result, dict) or result.get("mode") != "consultation"
                or result.get("execution_authorized") is not False
                or result.get("dispatch_enabled") is not False
                or not isinstance(result.get("resources"), list)):
            return _error("invalid_response")
        return _bounded_projection(result)
    except (OSError, ValueError, RuntimeError, RecursionError, TimeoutError, subprocess.TimeoutExpired, TypeError):
        return _error("qman_unavailable")


def shadow_consult(agent, model, workspace_registry=None):
    """Attempt advisory evidence only when explicitly enabled; never choose a route."""
    if os.environ.get("QMAN_PREFLIGHT_MODE", "off") != "shadow":
        return None
    started = time.monotonic()
    candidate = CANDIDATES.get(agent)
    try:
        result = qman_consult(*candidate, model=model, workspace_registry=workspace_registry) if candidate else _error("candidate_mapping_unknown")
    except Exception:
        # Advisory integration is never allowed to deny an otherwise valid dispatch.
        try:
            logger.warning("Qman shadow consultation unavailable")
        except Exception:
            # A broken logging handler must not turn advisory evidence into a launch gate.
            pass
        result = _error("qman_unavailable")
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
