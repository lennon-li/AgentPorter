# AgentPorter Security Model

See the repository-level [SECURITY.md](../SECURITY.md) for the normative trust-boundary description.

## Threat matrix

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| DNS rebinding / unintended hostnames | Localhost-only default Host allowlist; explicit remote hostname configuration | Reverse proxy/tunnel must still be configured correctly |
| API-key guessing/timing | High-entropy generated key, constant-time comparison, rate limiting | Shared API key is bearer authentication; protect it |
| Oversized HTTP bodies | Content-Length check plus actual ASGI body-byte counting | Application-level DoS is reduced, not eliminated |
| Filesystem traversal/symlink escape | Registered workspace IDs, relative-path validation, canonical-path checks | Registered workspace itself is trusted |
| Sensitive-file disclosure | Sensitive components blocked in reads/writes **and search** | Novel secret filenames not covered by denylist remain workspace data |
| Arbitrary direct code | Bubblewrap mount/network/environment isolation | No cgroup CPU/memory quotas yet |
| Runaway async output | Timeout and per-stream log-size limit | Host disk/resource pressure remains possible below limits |
| Worker-agent overreach | Per-workspace dispatch permission; adapter capability checks; enforceable read-only required for RO workspaces | Worker CLIs run as host user and are not kernel-isolated by AgentPorter |
| Loopback service access | Per-workspace exact-port allowlist; redirects disabled | Allowed loopback service is trusted |
| Malicious Git helpers | Global/system config disabled; external diff/fsmonitor/pagers suppressed; output bounded | Repository-local Git config is still present |
| Model provenance spoofing | Worker prose/stdout is not trusted as provenance | Actual model remains `unknown` unless a trusted adapter channel is added |

## Boundary summary

```text
MCP client
   |
   v
AgentPorter ingress
   |
   +--> workspace file/Git/artifact tools
   |
   +--> Bubblewrap direct execution
   |       - no network
   |       - scrubbed environment
   |       - workspace RW/RO
   |
   +--> loopback HTTP (explicit port allowlist, host-side)
   |
   +--> worker CLI delegation (host-user boundary)
```

The worker-agent path is intentionally a different trust boundary from direct
execution. AgentPorter does not claim that host-level coding-agent CLIs are
sandboxed merely because they were dispatched through the MCP gateway.
