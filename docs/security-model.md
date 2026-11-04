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
| Arbitrary direct code | Bubblewrap mount/network/environment isolation | Resource enforcement depends on the installed supervisor; required profiles fail closed when unavailable |
| Runaway async output | Timeout and per-stream log-size limit | Host disk/resource pressure remains possible below limits |
| Worker-agent overreach | Read-only by default; per-workspace grants; verified isolated runtime; separate credentials; bounded provider egress; controlled publication | Provider responses remain untrusted; runtime and owner-policy provisioning must be verified |
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
   +--> worker CLI delegation (verified confined runtime and scoped provider egress)
```

Worker availability is separate from delegation readiness. Dispatch requires
verified kernel confinement and explicit scope; installing a CLI or registering
a profile does not permit host-user execution.
