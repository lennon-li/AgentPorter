"""Trusted runtime provenance helpers for AgentPorter.

Agent stdout/stderr are untrusted content. A worker can mention arbitrary model
names in normal prose, so AgentPorter must not infer runtime provenance from
those streams. Adapters may add a trusted side-channel in the future; until
then the actual model is reported as "unknown".
"""

import logging

logger = logging.getLogger("agentporter.provenance")


def extract_actual_model(stdout_path: str, stderr_path: str) -> str:
    """Return verified runtime model metadata, or unknown when unavailable.

    stdout_path/stderr_path are intentionally ignored for model detection because
    worker-generated text is not a trustworthy provenance source.
    """
    return "unknown"
