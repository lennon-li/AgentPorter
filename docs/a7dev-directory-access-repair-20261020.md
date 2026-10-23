# A7Dev private-directory access repair — 2026-10-20

## Cause and bounded repair

After v8 installation, A7Dev failed during startup when
`ScopedPublicHTTPSPolicy._open_trusted_directory()` opened
`/var/lib/agentporter-dev` with `O_RDONLY | O_DIRECTORY | O_NOFOLLOW`.
The directory is root-owned, service-private group `agentporter-dev` (GID 981),
mode `0710`. Service UID 994 can traverse it, but cannot obtain the read-capable
directory descriptor required by the installed policy opener.

The prepared repair changes exactly that existing directory from `0710` to
`0750`. It adds read permission only to the exclusive service group, preserves
root ownership and all write restrictions, and leaves the installed release,
archives, source code, policies and credential contents unchanged.

An `O_PATH` policy-opener change could retain execute-only ancestor access, but
would require a new reviewed source/release deployment and policy-opener
compatibility validation. The private-group read addition directly satisfies
the existing immutable implementation and is restricted to the sole service
identity already entitled to access the directory's contents.

## Prepared files and guards

- `scripts/repair-a7dev-directory-access.py` is an ordinary-user launcher. Its
  caller must pin its reviewed SHA256 before execution. Sudo receives fixed
  isolated Python bootstrap code using only the standard library; root never
  imports mutable repository or installed application Python.
- The bootstrap checks the private service account and exclusive group, pins
  every root-owned ancestor with descriptor-relative `O_NOFOLLOW` directory
  opens, accepts only exact directory modes `0710`/`0750`, and rejects an access
  ACL. Only the validated directory descriptor can receive `fchmod(0750)`.
- It checks that `current` still names admitted release
  `20261020T223443.649130Z` and that the installed interpreter and relevant
  directories remain immutable root-owned paths within that release.
- Before changing mode or stopping the service, it requires an existing
  service-owned private config directory and regular `0600` `secrets.env`.
  The key check uses `O_PATH | O_NOFOLLOW` and metadata only; it never reads or
  prints the key. This prevents the normal configuration constructor from
  generating a new key when the file is missing.
- It stops only `agentporter-development.service`, applies the permission
  repair, and uses `runuser -u agentporter-dev` with the installed v8 interpreter
  to construct `create_asgi_app(Config(...))`. This exercises the complete
  startup chain, including the HTTPS policy opener, without binding a server
  or dispatching provider tasks. HOME, cwd, PATH, private umask `0077` and
  bytecode suppression match the unit's relevant process context. Normal
  service startup may update private state/logs and idempotently enforce the
  existing key file's `0600` mode; credential contents are never copied or
  exposed. Probe stdout/stderr are discarded.
- After successful preflight it restarts only the development unit. A fixed
  loopback health endpoint is checked with proxies and redirects disabled.
  Three consecutive checks must report exactly `{"status":"healthy"}` and
  an active unit with unchanged positive MainPID and unchanged NRestarts.
  Polling has a 30-second deadline, 2-second HTTP timeout, and 5-second unit
  status timeout; stop, preflight and restart each have a 30-second timeout.
- On a post-stop failure the bootstrap requests a development-only stop,
  reports if that stop cannot be confirmed, retains the non-writable `0750`
  permission repair, and fails. It never automatically rolls back a release
  or reinstates the startup-breaking `0710` mode.

## Verification and admission

**Unit test / executed locally:**

```text
.venv/bin/python -m pytest tests/security/test_a7dev_directory_access_repair.py tests/unit/test_scoped_https.py -q
104 passed in 2.03s
```

This successful run used the real unprivileged host user so security tests see
actual root-owned ancestors. A preceding sandbox run passed all 19 new tests
but existing HTTPS tests rejected namespace-mapped ancestor ownership; no
policy guard was weakened to accommodate that mapping.

The new permission regression exercises the real installed-style policy
opener against a synthetic directory: execute-only permission permits path
traversal but `O_RDONLY` fails; adding read permits the opener. It simulates
trusted ownership metadata, while kernel permission checks remain real.
Other synthetic tests cover wrong owners/groups/modes, unexpected ACLs,
nonexclusive group membership, metadata-only key validation, exact fixed sudo
arguments, sole directory-mode mutation, full service-UID startup arguments,
development-only stop/restart calls, failure stop, and health stability.

| File | SHA256 |
| --- | --- |
| `scripts/repair-a7dev-directory-access.py` | `981a1cb99da7360bd65c9d57e9194a0aa141a714e7c09d4959d8188b767949c3` |
| `tests/security/test_a7dev_directory_access_repair.py` | `cf0123e855f5136c03922c1e8917f7b4e4f6124764e2f82fc2642ca96e829d87` |

**NOT verified:** privileged directory mutation, actual service-UID full-app
preflight, development restart and live health. They require the local pinned
launcher invocation; this implementation worker has not executed it. No sudo,
installed permission change, service action, archive/source modification,
credential inspection, or git write was performed while preparing this repair.
