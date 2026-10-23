# Cranary HTTPS metadata broker — release readiness record

Current A7Dev update: the owner installed and activated the v12 broker's scoped Cranary authorization. Public/local MCP capabilities match; GitHub/CRAN positives and nine post-grant denials passed. See [the verified 2026-10-21 diagnosis and live acceptance](a7dev-cranary-https-authorization-20261021.md). This A7Dev grant does not clear the historical production activation gates below.

Date: 2026-10-20
Status: **NOT READY FOR PRODUCTION — NO INDEPENDENT REVIEW OR OPERATOR APPROVAL**
Source base: \`65dbf445bcd16f8e6961a5d5eef4d9f76c084cf8\`

## Purpose and exact permission

Permit a registered \`cranary\` workspace to request a read-only public
R-package metadata resource by using precisely \`curl -fsS URL\` (GET) or
\`curl -sSI URL\` (HEAD) through existing \`exec_run\` or \`exec_start\`.
Only \`network_access=true\` requests using an independent owner-installed
allowlist for those sites can reach the fixed-function HTTPS broker.
Generic shell/Bubblewrap networking remains permanently unavailable.

Exact allowed hosts (TLS to TCP/443): \`api.github.com\`,
\`cran.r-project.org\`, \`cran-archive.r-project.org\`, \`bioconductor.org\`.
No redirects, client credentials, inherited proxy settings, arbitrary
destinations, POST/PUT/DELETE, or model-provider network access.
A 256 KiB output/response cap and 15-second operator-configured timeout
apply to the proposed scope.

## Test evidence

- 65 isolated offline cases passed, including four-host scoping, URL
  confusion, malformed operator policies, YAML aliases, private-address DNS,
  IPv4-in-IPv6 tunnels, port substitution, TLS SNI preservation, redirect
  rejection, output growth, and sensitive-header stripping.
- Both \`exec_run\` and \`exec_start\` offline routing smoke tests pass with
  fake HTTPS subprocesses and no network sockets.
- All staged Python files AST-parse successfully; checked-in JSON parses.
- The 53-row README operation table remains intact.
- A checked SHA-256 source inventory and review archive have been generated.

## Required release gates (not yet satisfied)

1. Independent security review of host-side HTTP broker and environment,
   including malicious public web responses and OS privilege boundaries.
2. Full project unit, integration, and security suite under the proper
   isolated Python 3.13 release environment. The installed venv is not
   available inside the current offline AgentPorter Bubblewrap workspace.
3. Owner confirmation of the **exact** four-host policy digest; operator
   installs the owner-owned 0600 file under the protected config directory
   independently of any agent workspace. No existing signed receipt issuer
   for generic outbound access is claimed.
4. Explicit owner permission to commit, push, or publish. None has been
   granted in this handoff. Source is staged only.
5. Immutable owner-run release deployment after CI, with live PID, loaded
   fingerprint, and rollback gate. No service restarts by agents.
6. Bounded live verification under the newly approved service:
   positive HTTP 200 valid JSON response for the rOpenSci issue URL,
   negative HTTP request for an unapproved host (zero network connects),
   and regression offline \`exec_run\`. Do **not** execute Cranary's data
   acquisition or alter training-label artifacts during this acceptance.

## Residual caveats

- A fixed-purpose host service subprocess, even under \`python -I\` with
  stripped environment, is **not** OS/container isolation or a distinct
  Unix identity. Its only inputs should be checked URLs/methods and the
  operator-owned policy, not a general shell.
- The 256 KiB response limit is for small metadata, not complete CRAN
  catalogs, R source archives, large historical check files or model
  training datasets. A separate reviewed streaming-to-artifact path is
  required before large downloads.
- The private allowlist is a preapproved operator scope, **not** a signed
  per-invocation authorization receipt. Do not present an MCP flag or
  conversation as proof of human approval.
- HTTP GET and HEAD are suitable for unauthenticated public metadata here;
  the broker intentionally does not confer a blanket assertion that
  arbitrary GET endpoints on other websites are side-effect-free.

## Current operation changes

Only an inert staging directory and local review archive under the
AgentPorter registered workspace were created. No local branch, commit,
GitHub push, release activation, operating-system change, protected policy
installation, or Cranary acquisition occurred.
