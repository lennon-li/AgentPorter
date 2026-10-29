#!/usr/bin/env python3
"""Print bounded, allowlisted provider diagnostics from stdin; never log raw input."""
import json
import sys
from collections import deque
AGENTS = {'liz', 'prof', 'jax', 'argie', 'wei', 'ming', 'phil'}
ORIGINS = {'daily-cloudcode-pa.googleapis.com', 'api.github.com', 'www.googleapis.com', 'api.business.githubcopilot.com', 'api.githubcopilot.com', 'api.individual.githubcopilot.com', 'chatgpt.com', 'oauth2.googleapis.com', 'auth.openai.com', 'api.openai.com', 'api.enterprise.githubcopilot.com', 'lh3.googleusercontent.com', 'cloudcode-pa.googleapis.com', 'platform.claude.com', 'opencode.ai', 'api.anthropic.com', 'unlisted'}
OPERATIONS = {'POST /backend-api/codex/responses', 'POST /v1/chat/completions', 'POST /inference/openai/v1/chat/completions', 'POST /v1internal:fetchUserInfo', 'GET /backend-api/wham/accounts/check', 'POST /v1internal:fetchAvailableModels', 'POST /token', 'GET /copilot_internal/user', 'POST /v1internal:retrieveUserQuotaSummary', 'POST /chat/completions', 'POST /v1internal:listExperiments', 'GET /oauth2/v2/userinfo', 'POST /responses', 'POST /v1/oauth/token', 'POST /v1internal:generateContent', 'POST /v1/responses', 'POST /v1internal:streamGenerateContent', 'POST /v1/messages/count_tokens', 'POST /v1internal:onboardUser', 'GET /models', 'GET /v1/models', 'POST /v1/messages', 'POST /oauth/token', 'POST /v1internal:countTokens', 'GET /copilot_internal/v2/token', 'GET /backend-api/codex/models', 'POST /v1internal:fetchAdminControls', 'POST /v1internal:loadCodeAssist', 'POST /zen/v1/chat/completions', 'unlisted'}
REASONS = {'chunk_count', 'chunk_delimiter', 'request_line', 'OSError', 'hosted_anthropic_tool', 'header_bound', 'chunk_deadline', 'SSLError', 'body_encoding', 'body_length', 'BrokenPipeError', 'TimeoutError', 'truncated_body', 'opaque_state', 'chunk_size', 'excess_body', 'header_syntax', 'body_framing', 'ValueError', 'PermissionError', 'unexpected_body', 'chunk_body_bound', 'free_model_scope', 'duplicate_header', 'incomplete_header', 'chunk_trailer', 'connect_scope', 'ConnectionResetError', 'hosted_google_tool', 'operation_scope', 'chunk_truncated', 'connection_metadata', 'authority_mismatch'}
PHASES = {'connect', 'request', 'payload', 'upstream', 'response'}

def filtered(line):
    if len(line) > 65536:
        return None
    try:
        item = json.loads(line)
        if isinstance(item, dict) and isinstance(item.get('event'), dict):
            item = item['event']
        if not isinstance(item, dict):
            return None
        event = item.get('event')
        if event not in ('provider_egress_failure', 'provider_upstream_status'):
            return None
        out = {'event': event}
        for field, allowed in [('agent', AGENTS), ('origin', ORIGINS), ('operation', OPERATIONS)]:
            value = item.get(field)
            out[field] = value if isinstance(value, str) and value in allowed else 'unlisted'
        if event == 'provider_egress_failure':
            for field, allowed in [('phase', PHASES), ('reason', REASONS)]:
                value = item.get(field)
                out[field] = value if isinstance(value, str) and value in allowed else 'unlisted'
        else:
            value = item.get('status')
            out['status'] = value if type(value) is int and 100 <= value <= 599 else None
        return out
    except (ValueError, TypeError):
        return None

def main():
    records = deque(maxlen=30)
    # Bounded readline avoids retaining unexpectedly large private log records.
    while True:
        line = sys.stdin.readline(65537)
        if not line:
            break
        if not line.endswith('\n') and len(line) > 65536:
            while line and not line.endswith('\n'):
                line = sys.stdin.readline(65537)
            continue
        record = filtered(line)
        if record is not None:
            records.append(record)
    for record in records:
        print(json.dumps(record, sort_keys=True))

if __name__ == '__main__':
    main()
