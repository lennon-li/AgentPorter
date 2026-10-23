# Cranary / Laya public HTTPS egress — proposed owner approval

For the current A7Dev v12 service, see [the 2026-10-21 diagnosis and successful live acceptance](a7dev-cranary-https-authorization-20261021.md). Its owner-installed policy at `/var/lib/agentporter-dev/config/public-https.yaml`, owned by `agentporter-dev`, mode `0600`, is active. Public MCP GitHub/CRAN and negative security checks passed. The user-service paths and staging status below are historical.

**Status (2026-10-19): STAGED ONLY; owner approval NOT recorded; runtime NOT updated.**
This file is implementation/design evidence, not permission to fetch Laya data.

## Scope

- Workspace: registered \`cranary\`, currently \`/home/yeli/repos/cranary\` on Asgard.
- Service execution principal: \`yeli\` (AgentPorter process). General shell
  execution is still confined inside Bubblewrap; the new fixed-purpose HTTPS
  helper runs with Python import isolation (\`-I\`) and a stripped environment
  as the service identity. It is **not** an independently confined Linux UID
  or container, and its provider-agnostic code must be reviewed accordingly.
- Allowed schemes/methods: \`https://\`, TCP 443, GET and HEAD.
- Exact hosts only (not suffix or wildcard matches):
  - \`api.github.com\` — rOpenSci software-review public issues.
  - \`cran.r-project.org\` — CRAN metadata and package catalog.
  - \`cran-archive.r-project.org\` — historical CRAN checks.
  - \`bioconductor.org\` — Bioconductor metadata.
- Per-response limit: 262144 bytes (256 KiB). Per-request deadline: 15 sec.
- Redirects: always denied, including redirects to an allowlisted host.
- Credentials/cookies/proxies: not inherited, no auth headers, URL userinfo
  and recognized query-string credential tokens refused.
- DNS: resolve host; all answers must be public IPs; connect directly to a
  vetted address; retain TLS SNI and cert hostname verification. Public DNS
  rebinding to RFC1918, localhost, link-local or reserved space is denied.
  IPv4-mapped, 6to4, Teredo and common NAT64 embedding prefixes are rejected.
- Unknown workspace, host, method or command: reject before any outbound call.
- Logging: parent service records workspace, host, method, redacted URL hash,
  start/end and job status; request bodies and raw URL query values are not
  logged. Existing API access logging remains in force.

## How execution works (candidate)

Generic \`exec_run\`/\`exec_start\` remain offline. Only with
\`network_access=true\` **and** the protected owner allowlist installed are
these exact command forms interpreted as metadata requests:

\`\`\`
exec_run(workspace_id="cranary", network_access=true,
         argv=["curl", "-fsS",
               "https://api.github.com/repos/ropensci/software-review/issues/1"])

exec_start(workspace_id="cranary", network_access=true,
           argv=["curl", "-sSI", "https://cran.r-project.org/"])
\`\`\`

\`-fsS\` maps to bounded GET; \`-sSI\` maps to HEAD; no other flags, shell,
Python/network-capable scripts, POST, authentication, redirect following or
output-file option. It is NOT a general curl subprocess or public-internet
exception: the URL is revalidated and a fixed-purpose code-only HTTPS worker
executes as a credential-scrubbed subprocess. \`exec_start\` tracks the PID in
the existing job manager for status, bounded logs, timeout and cancel.

Response content is returned as UTF-8 text with replacement for non-UTF8
bytes. The 256 KiB cap is suitable for public issues and small metadata,
**not** whole CRAN package catalogs, larger archives or binary RDS ingestion.
Those require a separately audited stream-to-file workflow with larger budgets
and digest-verified artifacts; they are not authorized by this change.

## Independent approval / activation

The existing deployed AgentPorter currently has **no trusted independent
receipt issuer for outbound generic execution**. The existing operator action
matrix is not an authorization receipt. Therefore this candidate **never
changes \`sandbox.network=false\` and does not treat \`network_access=true\`
as evidence of user approval**.

Owner control is implemented as a protected, separate file:
\`~/.config/agentporter/public-https.yaml\`. Only an operator can install it,
as 0600 owner-owned data outside any registered agent-writable workspace.
The example \`docs/examples/cranary-scoped-https.yaml\` is inert and is not
loaded from the repository. The service loads only the operator-installed file
at startup; missing file means no outbound request can be authorized.

**Before production activation, obtain independent operator signoff for the
exact file digest and reviewed release commit; record it in an independently
controlled channel, then use the owner-only immutable release deployment
process.** Creating an agent-writable approval YAML or a caller-supplied
\`approved=true\` does not meet that requirement.

No protected policy file has been installed, signed or approved by this
implementation session. No service restart, data acquisition, git commit/push,
or remote publication was performed.

## Offline acceptance

Available offline regression tests cover:

- Four exact hosts and cranary-only scope; rejects unrelated workspaces.
- Valid GET/HEAD arguments; rejects POST, arbitrary shell/program, flags,
  unknown query credentials and unauthorized redirects.
- URL confusion/credential tricks and redirects.
- Mixed public/private DNS answers, private-only DNS, IPv4 embedding
  and translated DNS records.
- TLS request headers lack Authorization/Cookie.
- Bounded response size (including UTF-8 replacement expansion)
  and request deadlines.
- Missing/invalid/duplicate-key/unsafe owner policy.
- Asynchronous trusted worker executable and scrubbed environment.
- Ordinary offline execution remains unchanged.

**Verified locally:** 65 offline HTTPS security cases and offline execution
integration smoke. No network traffic was generated. The owner-policy file
has not been installed.

**Not yet verified:** installed-release Python 3.13 full test suite, actual
networked HTTP 200 acceptance, negative network connection trace, and a real
async completion/cancel. A separate review must inspect the narrow host-side
worker privilege and public DNS/TLS behavior before deployment.

The [release readiness record](cranary-https-readiness.md) identifies
independent audit, full Python 3.13 CI, and operator approval as blockers.

## Cranary handoff after operator activation

1. Call \`exec_run\` in \`cranary\` using the fixed GET shape above and
   \`network_access=true\`. Expect a JSON \`HTTP 200\` body.
2. Try \`https://example.com/\` with the same command shape. It must return a
   permission error before a socket is opened.
3. Run ordinary \`exec_run\` with \`network_access=false\` to confirm no change.
4. Continue the **existing frozen 10-package quality-control protocol**.
   No labels or datasets are added simply because network access became
   available.

Research artifacts: \`data-raw/cran-history/reports/2026-10-19-laya-dataset-source-research/\`.
