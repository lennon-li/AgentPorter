# A7Dev archive/manifest repair — 2026-10-20

## Diagnosis

The frozen `/tmp/agentporter-development-candidate-v7.tgz` has SHA256
`58db31a16a80a3147808d41bf0d7febcfcf27d378de203d4c6db634f385451b8`.
Its release manifest admits 26,344 files/links. The archive also contains 1,047
unlisted regular `.pyc` files under 136 `__pycache__` directories. The first
unlisted entry is
`python/lib/python3.13/__pycache__/__future__.cpython-313.pyc`.
Independent full archive review found no missing manifest members and no digest,
execute-bit, or symlink-target differences among admitted members.

`entries()` deliberately excludes `__pycache__` directories, but the previous
builder's recursive `tarfile.add()` included them. The strict installer correctly
rejected the first unlisted file. Credential refresh had succeeded before this
separate installation failure.

## Changes

- `scripts/build-development-candidate.py`: adds reusable `write_artifact()`;
  checks staged contents against the existing manifest, applies the same cache
  exclusion during recursive packing, rejects other unlisted members, and checks
  emitted membership exactly. Normal builds use this helper. An `INSTALL`
  constant permits an isolated destination in integration tests. A link guard
  rejects targets that require omitted cache files/directories, including raw
  `__pycache__/../` traversal and chains through excluded cache symlinks.
- `scripts/repack-development-candidate.py`: unprivileged, data-only repair of a
  digest-pinned original into a new filename. It freezes the input before digest
  verification, uses the real installer extractor, permits only unlisted regular
  `.pyc` files inside cache directories, validates every admitted member, preserves
  all metadata bytes, and requires a fresh extraction plus strict installer
  verification before publishing the corrected archive. Publication uses a new
  hardlink name and never replaces an existing output. The reusable entry point
  restores its caller's umask on success and failure; actual process-umask
  regressions prevent a private staging mask from affecting later operations.
- `tests/security/test_development_artifact.py`: exercises the complete builder
  with an inert synthetic snapshot, actual archive extraction and manifest
  verification, install, evidence capture, and exact-pair rollback. Only owner
  identities, root DAC override for directory moves, ownership changes, and
  systemd calls are simulated. The actual destination-capability function,
  private writes, renames, hashes, modes, links, config transition and rollback
  run. Tests also reject changed/missing/extra content and malicious non-cache
  repack additions.

The installed helper source remains byte-identical, SHA256
`84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58`.
No installer verification rule was relaxed.

## Verification

- **Unit test:** `.venv/bin/python -m pytest tests/security/test_development_artifact.py tests/unit/test_development_provisioning.py -q`
  — **56 passed**, including 45 artifact tests and the provisioning regressions.
- **Executed locally:** metadata SHA256 values read from the original archive's
  actual unprivileged extraction:

  | Document | Original SHA256 |
  | --- | --- |
  | `runtime.json` | `51bc724c9b301fbb9d5ce8051446f16c2e5619eaa4f954b3c5c75f62dedc7984` |
  | `release-metadata.json` | `d3a5540ed58a13998e2f717ca6786a4f527084db125ba07c9d0d74a4be210906` |
  | `release-files.json` | `b826b44ba1af70be192d6a12d8e36ad56a8158a188ea5b0dca55f01e766ea272` |

- **Executed locally:** repaired archive
  `/tmp/agentporter-development-candidate-v8.tgz`, SHA256
  `e9b9919f27b9a01e11b8f1274811e035a7d85ecbb809474e83eb6a0a7a89d929`,
  size 1,386,254,545 bytes, mode `0400`. The pinned original was copied and
  extracted without executing any payload, all 26,344 admitted entries matched,
  exactly 1,047 unlisted cache files were excluded, and a complete second
  extraction passed the unchanged installer's strict `verify_release()`.
  All three metadata documents were compared byte for byte successfully.
  The release version remains `20261020T223443.649130Z`.
- The original archive and v7 launcher remain unchanged. A new
  `scripts/install-approved-a7dev-v8.py` changes only the artifact filename,
  approved artifact SHA256, and final display label; all four helper/unit pins
  are unchanged. The launcher has not been executed by this repair worker.
- **Executed locally, independent review:** the actual v8 archive contains zero
  cache paths and all 1,066 symlinks resolve strictly inside its extracted tree.
  This stronger actual invariant verifies the link guard's requirement for the
  candidate created before that guard was added. Negative and positive generic
  packer regressions also pass.
- **Executed locally, parent validation:** the actual v8 archive passed the full
  install and exact-pair rollback path in private `/tmp` storage. Root identity,
  DAC override and systemd effects were simulated; original canonical runtime
  paths were checked before rebasing to the temporary installation. Evidence:
  `/tmp/agentporter-v8-full-install-preflight.json` and `.log`.

## Later installation steps and limits

The synthetic round trip reaches every later installation step: immutable
release verification, unique-version promotion, bounded previous-runtime capture,
rollback evidence, private config replacement, current-link replacement, and
the development-only restart request. It then restores the exact previous
runtime and release. A non-root test needs to model root's DAC override when
moving a read-only directory between parents; the resulting release mode stays
`0555`.

The real `/var/lib/agentporter-dev` ancestor is root-owned `0710`, consistent
with the unchanged capability checks. Config/account trust and successful real
systemd activation still require the privileged installation; these tests do
not claim to execute that installation. If activation itself fails after the
config/link switch, the retained rollback pair is the recovery mechanism.
No account, credentials, gateway, installed release, or service was changed by
this repair work. No commit or deployment was performed.
