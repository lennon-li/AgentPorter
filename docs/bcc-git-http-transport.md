# Scoped Git smart-HTTP transport — internal candidate

`agentporter.git_smart_http` implements bounded Git protocol-v0 discovery,
single-branch receive-pack requests, and upload-pack acquisition. It is a wire
primitive, not an approval/publisher backend. No public API uses it yet, and
push/fetch/pull remain locked. No real remote or credential was contacted by
its tests. Protocol references: [Git HTTP transport](https://git-scm.com/docs/gitprotocol-http)
and [Git pack protocol](https://git-scm.com/docs/gitprotocol-pack).

A protected backend supplies one canonical HTTPS repository URL and, when
needed, a private token file and fixed username. The URL cannot contain user
credentials, query/fragment data, alternate ports, path traversal, or encoded
path components. The broker uses the existing public-address-pinned HTTPS
connection with certificate/hostname validation, without inherited proxies,
cookie state, transport helpers, or redirect following. Each operation targets
only that repository's `info/refs` or exact upload/receive service endpoint.

Credential files require trusted ancestors, current-owner private modes,
single-link regular files, and no symlinks. When a protected backend supplies
its complete workspace root catalog, credential placement inside those roots
is refused. The token is raw printable ASCII with no whitespace or trailing
newline, at most 4096 bytes. HTTP Basic credentials exist only in the trusted
broker; they are not passed to Git subprocesses or delegated workers. Requests
use identity encoding and fixed Git MIME types. Framing ambiguity, duplicate
critical headers, compressed bodies, wrong types, oversize/truncated results,
redirects, and socket errors fail closed with sanitized errors.

The codec validates bounded pkt-line framing, exact service banners, unique
references, capability placement, object format, and full SHA1/SHA256 IDs.
Discovery is capped at 8 MiB and protocol records are bounded. RPC bodies and
fetch results are capped at 64 MiB including framing; packs have bounded
object counts and checked trailers. These checks are wire integrity and
resource bounds, not Git object-graph or authorization validation.

Receive-pack encoding permits exactly one non-deleting `refs/heads/` update,
with explicit old/new IDs and `report-status`. Discovery must still match the
expected old ID before POST, and the remote Git server performs its own atomic
old-ID check. Confirmation must report successful unpacking and exactly that
one branch. Transport errors or ambiguous acknowledgments after publication
may have begun produce retained cleanup uncertainty and are never retried.
This primitive does not independently prove fast-forward ancestry: a protected
backend must do that before calling it unless a separately reviewed policy
explicitly supports another publication operation.

Upload-pack acquisition requests one exact currently advertised branch object,
does not negotiate sidebands or thin packs, and returns a checked raw pack.
It does not install local objects, change tracking refs, or modify worktree
files. The future backend must index it in private quarantine under supervision,
verify requested objects and graph integrity, and only then apply approved
local metadata changes. Native fixture tests run `index-pack --strict` against
the returned pack; this is not yet an application-level fetch implementation.

Before exposing network Git:

1. Load immutable owner remote/credential/ref policy outside all exposed roots;
   pass the complete workspace catalog into transport credential checks.
2. Prepare and independently sign requests binding exact repository identity,
   remote URL, remote ref/tip, local state, operation, and relevant payloads.
   Extend the owner-device interface with operation-specific review; it currently
   refuses push/fetch/pull proposals.
3. Validate local graph/ancestry and generate packs only from approved objects
   through fixed supervised commands with clean configuration and no credentials.
4. Retain durable operation/admission state around remote publication; implement
   owner reconciliation of old/new/conflicting remote state after uncertainty.
5. Connect authenticated MCP/REST scope and signed execution. Pull must validate
   both fetched history and any eligible worktree delta before application.
6. Exercise actual approved remote credentials and frozen live acceptance against
   the exact installed release. Do not infer success from local fixture transport.

Native compatibility tests use disposable repositories and `git-http-backend`
on loopback. Only these fixtures replace the production pinned TLS connection
with a local HTTP connection. SHA1 and SHA256 push, stale discovery rejection,
fetch/quarantine indexing, and concurrent owner ref deletion are covered.
No public transport, remote force behavior, live TLS authentication, signed
network operation, or BCC production acceptance is certified by those tests.
