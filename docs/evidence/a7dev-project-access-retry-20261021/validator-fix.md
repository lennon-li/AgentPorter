# Corrected external project access acceptance

Source validator corrected; 19 synthetic tests passed. No gateway/artifact/config/ACL changes.

The three confirmed protected traverse-only roots (`agentporter`, `AgentPorter`, `repos`) must reject root directory listing. Their evidence retains read:false and records listing_denied_expected:true. Unexpected listing success fails acceptance.

The other two protected roots (`obsidian`, `asgard-hermes-review`) still require directory listing. All protected roots must reject execution. All 41 ordinary projects still require listing, successful offline Python execution, exact /workspace cwd, and read/write/remove probe. Missing/incomplete inventory fails.

A pure summarize_workspace_access function produces classified summary and failure reasons. Expected protected listing denials no longer abort acceptance before list_agents or live Jax tasks. Existing public dispatch denial checks, generic-network/host/method/redirect restrictions, provider challenges, fingerprint checks and public/local matching checks are unchanged.

Command: `.venv/bin/python -m pytest -q tests/security/test_project_access_acceptance.py`
Result: 19 passed.

No installed immutable script modified. Owner should run this exact hash-pinned external source validator under service UID using the approved post-install procedure.

- scripts/verify-a7dev-project-access.py: `0c85c0548797076ef71faba9a8c276abefcb6c659c9d1d693be69fa79c49c39b`
- tests/security/test_project_access_acceptance.py: `b8e29cfd325004eaaf30b56a5cbfbe17c51f6a1b1d900bf5e30c55de6d72522f`
