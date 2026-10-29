# Independent owner-device approval — candidate

The candidate includes a static, device-side commit approval interface under
`src/agentporter/owner_approval/`. It is not served by AgentPorter and has not
been publicly installed or enrolled on the owner's phone. It performs no
backend requests. Its four assets are included in the wheel and in the
prepared standalone asset bundle with a SHA256 manifest.

The owner must host the audited assets on an independently controlled HTTPS
origin, outside AgentPorter's origin and all agent-writable roots. Use a normal
external browser window on the owner device, not an embedded frame or a private
browsing session. Bookmark the independently verified owner URL. Never serve
this interface from a writable project directory, an uploaded artifact route,
or an agent-controlled host. The deployed issuer assets must match the audited
manifest. Do not replace this requirement with trust in the page's title.

Hosting must provide the correct JavaScript MIME type for `.mjs` and these
headers in addition to the page's embedded content policy:

```text
Content-Security-Policy: frame-ancestors 'none'
X-Content-Type-Options: nosniff
Cache-Control: no-store
Referrer-Policy: no-referrer
```

The page's content policy allows only its same-origin scripts/styles and
denies connections, images, objects, base changes, and forms. It uses no
third-party scripts, fonts, analytics, service workers, request transport, or
message-based signing interface. Proposal fields are rendered as text, with
explicit JSON escapes so invisible characters cannot conceal signed details.
Opening in a frame or without a secure browser context refuses key setup.

Enrollment, after independent hosting is verified:

1. On the owner device, open the trusted URL and select **Set up this device**.
   The browser creates a non-exportable Ed25519 private `CryptoKey` and stores
   it with the public key in IndexedDB. Another tab cannot silently replace an
   existing key. Reloading the page loads the same pair and verifies that it
   matches before showing the public key.
2. Copy only the public verification key into the owner-controlled BCC policy
   installation process described in `bcc-approved-git-api.md`. Initialize the
   private claim ledger through that owner setup and restart the audited
   backend. Do not copy browser profiles or signing-key storage to BCC.
3. Verify the public key on the device matches the installed policy before
   treating any subsequent signature as accepted deployment evidence.

Non-exportable means the Web Crypto export/wrap API cannot export the private
key; it is not a promise of hardware-backed storage or protection against a
compromised device, browser, or same-origin script. The owner origin and its
release process are therefore part of the protected approval boundary. Browser
storage deletion, eviction, profile loss, or device loss can require a new
device key and explicit owner policy rotation. No silent key replacement or
private-key backup/export function is provided. Browser capability reference:
[Web Crypto key generation](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/generateKey).

Normal commit flow:

1. Review the scoped edit, tests, and diff in ChatGPT, then request the exact
   unsigned proposal from `git_commit(prepare_only=true)`.
2. Paste the complete proposal into the independent owner page and select
   **Review proposal**. The page requires the exact supported commit schema,
   rejects duplicate fields and unsafe numbers, preserves 64-bit filesystem
   identifiers, and checks the domain-separated request digest.
3. Review every displayed field: repository/path/identity, branch, HEAD, staged
   tree, author/committer, timestamp, message, and digest. Select the explicit
   acknowledgment, then **Sign this exact commit**. Key creation and signing
   require trusted browser click events. No proposal signs itself.
4. Copy the signed receipt back to ChatGPT, retaining the original proposal's
   message and exact timestamp. Submit it through the existing authenticated
   commit API. The receipt lasts five minutes, is single-use, and cannot
   authorize a changed request. Keep the device clock accurate.

Editing the proposal invalidates review, acknowledgment, approval availability,
and any displayed receipt. Async review/signing results from an older input
are discarded. The interface validates and displays operation-specific commit,
fetch, and push proposals. Pull proposals remain refused.

Fetch review displays the protected remote identity and URL, exact source
branch/object, exact local tracking ref and prior tip, pack digest/size, policy
fingerprint, and request digest. The owner signs only that exact fetch request.
The public client also needs the separate `git_fetch` scope; `git_read` and
`git_write` do not grant fetch invocation. Protected remote policy and the
single-use owner receipt remain mandatory. See `docs/bcc-approved-git-fetch.md`.

Push review displays the exact destination ref, old/new tip, immutable pack
digest/size, and policy fingerprint. Public `git_push` scope and an exact owner
receipt are required; see `docs/bcc-git-approved-push.md`.

Native evidence uses a fresh synthetic Chrome profile with Chrome's OS sandbox
enabled and no existing user account/browser data. Tests validate persisted
key reload, failed private-key export, trusted versus synthetic clicks, text
rendering against HTML injection, stale-proposal invalidation, and no outbound
page requests. An actual browser-generated receipt successfully executes a
staged disposable-repository commit through the protected Python backend.
Cross-runtime tests also cover exact Unicode/newline serialization, 64-bit
identities, digest mismatches, duplicates, unsupported operations, and replay.

This evidence does not establish the owner's actual phone/browser behavior,
independent HTTPS hosting, real key enrollment, cgroup enforcement (the commit
test uses a recording provider), provider calls, or frozen AP-01–AP-06 live
acceptance. Those remain deployment/independent-audit gates.
