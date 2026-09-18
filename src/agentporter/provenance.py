"""Provenance and runtime telemetry extraction for AgentPorter jobs and agents."""

import os
import re
import json
import logging
from typing import Optional

logger = logging.getLogger("agentporter.provenance")


def extract_actual_model(stdout_path: str, stderr_path: str) -> str:
    """Inspect execution outputs for explicit model declarations.
    
    CRITICAL INVARIANT: If the actual/resolved model cannot be reliably verified
    from process output, return 'unknown'. Never infer from configuration or defaults.
    """
    candidates = []
    for log_path in (stdout_path, stderr_path):
        if not os.path.exists(log_path):
            continue
        try:
            with open(log_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()[-150:]  # Read tail
            for line in lines:
                line_str = line.strip()
                # Check for structured JSON output containing model declarations
                if line_str.startswith("{") and line_str.endswith("}"):
                    try:
                        data = json.loads(line_str)
                        if isinstance(data, dict):
                            for key in ("model", "actual_model", "resolved_model", "model_name"):
                                if key in data and isinstance(data[key], str) and data[key].strip():
                                    candidates.append(data[key].strip())
                            if "usage" in data and isinstance(data["usage"], dict):
                                u = data["usage"]
                                if "model" in u and isinstance(u["model"], str) and u["model"].strip():
                                    candidates.append(u["model"].strip())
                    except Exception:
                        pass

                # Check explicit CLI output logs: e.g. "Model: gpt-5.6-luna", "Resolved model: claude-3-7-sonnet"
                m = re.search(
                    r'\b(?:actual[-_ ]model|resolved[-_ ]model|using model|model used|selected model|model)[:=]\s*([a-zA-Z0-9\.\-_/]+)',
                    line_str,
                    re.IGNORECASE
                )
                if m:
                    candidates.append(m.group(1))
        except Exception as e:
            logger.debug("Failed reading %s for model provenance: %s", log_path, e)

    if candidates:
        return candidates[-1]

    return "unknown"
