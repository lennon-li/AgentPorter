"""Shell command guard for agent CLIs whose own deny rules are unreliable.

Used as a Claude Code PreToolUse hook: reads the hook JSON on stdin and exits
2 (block) when the Bash command starts a denied prefix. This is a prefix
matcher over common shell separators, not a sandbox; obfuscated invocations
(scripts, aliases, eval) can still evade it.
"""

import json
import re
import sys

_SEGMENT_START = r"(?:^|[;&|`(\n]|\$\(|\b(?:bash|sh|zsh)\s+-c\s+[\"']?|\b(?:env|command|exec|nohup|time)\s+)\s*"


def _normalize(command: str) -> str:
    # `git -C <dir> push` and `git -c k=v push` still run `git push`.
    return re.sub(r"\bgit(\s+-[Cc]\s+\S+)+", "git", command)


def find_denied(command: str, denied: list[str]) -> str | None:
    text = _normalize(command)
    for prefix in denied:
        if re.search(_SEGMENT_START + re.escape(prefix) + r"(?=\s|$|[;&|)`'\"])", text):
            return prefix
    return None


def main() -> int:
    denied = json.loads(sys.argv[1])
    try:
        event = json.load(sys.stdin)
    except ValueError:
        return 0
    command = (event.get("tool_input") or {}).get("command") or ""
    hit = find_denied(command, denied)
    if hit:
        print(
            f"AgentPorter execution policy blocks `{hit}` for delegated agents. "
            "Report that this step needs explicit human confirmation (git commit/push are "
            "enabled per dispatch via allow_commit/allow_push) and continue with the rest.",
            file=sys.stderr,
        )
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
