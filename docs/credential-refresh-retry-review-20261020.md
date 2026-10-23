# Independent credential refresh retry review — 2026-10-20

**Verdict: no remaining identified code or digest blocker for the exact corrected A7Dev-v7 retry below. Privileged activation and live acceptance remain pending.** This review is code/admission evidence, not authorization to run sudo, proof of credential synchronization, or production clearance.

## Scope and exact inputs

Reviewed the current refresh helper, fixed bootstrap launcher, orchestration unit tests and offline credential verifier at checkout HEAD `65dbf445bcd16f8e6961a5d5eef4d9f76c084cf8` (detached, with extensive preexisting dirty/untracked work). Independently verified that the files exist and that the launcher pins the actual helper bytes. Reviewed the unchanged artifact installer and service/timer as bootstrap dependencies. The archive was read only to verify its complete SHA256; this review does not replace the earlier archive-content admission in `docs/production-security-review-20261020.md`.

| Input | Independently verified SHA256 |
| --- | --- |
| `scripts/install-approved-a7dev-v7.py` | `69b5cce204c8c72e5c170d72e196edc8c45252f568a1b8a3e91264139421c254` |
| `scripts/refresh-development-worker-credentials.py` | `18b96a4112d460c10c25d34377cc9bb06f21e4aa4c1b27dcce0ebd969bf97811` |
| `scripts/install-development-artifact.py` | `84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58` |
| `scripts/agentporter-dev-credential-sync.service` | `30bd3a3a9e26f5733d3efd4520c1645a735eddcebb4c0ae55e470b4519922bca` |
| `scripts/agentporter-dev-credential-sync.timer` | `43b7a2200c0a0521e400adb01da93abf759f7ebdb685e4529234b9aa4f3738c2` |
| `/tmp/agentporter-development-candidate-v7.tgz` | `58db31a16a80a3147808d41bf0d7febcfcf27d378de203d4c6db634f385451b8` |
| `tests/unit/test_worker_credential_refresh.py` | `24fe6a954f708ceeb65a13c38cad369afbacdbedb4f1f82fa5b4828732b34856` |
| `tests/verify_worker_credential_refresh_offline.py` | `2bdabb339e3c279964715409abe5a8e3956d159661251e6dd211c55c147cbdd6` |

The new refresh/launcher hashes supersede their prior review hashes for this retry. The trusted artifact installer, service, timer and exact v7 archive still match their previously admitted pins.

## Findings

1. **The observed missing-function defect is corrected in the reviewed bytes.** `_is_private_destination_dir` now exists, uses `_pinned_directory`, checks the opened directory descriptor for the exact service UID and private permissions, and closes it. The complete `_run` path reaches this function in the successful synthetic tests. This establishes coverage beyond importing or compiling the helper.
2. **The preliminary check does not become a privileged pathname-write capability.** `_install_secret` independently opens and validates the destination again, stages bytes under the root-controlled parent, opens the temporary file exclusively without following symlinks, writes/chowns through its descriptor, and renames through pinned source and destination directory descriptors. A concurrent rename/symlink replacement of a service-owned destination ancestor cannot redirect that publication into the replacement tree. Source reads walk ancestors with `O_NOFOLLOW`, open the leaf nonblocking without following symlinks, and check the opened regular file's owner, mode, bounded size and metadata before/after reading. The initial path-based DATA checks are additional guards; subsequent credential reads and writes retain descriptor-based checks.
3. **The retry preserves the narrow immutable bootstrap boundary.** The launcher invokes only fixed code through `/usr/bin/sudo /usr/bin/python3 -I -c`. The bootstrap reads all four bounded regular source files as data, verifies their exact digests before publishing any of them, and installs through trusted root-owned parent descriptors using exclusive temporary files and atomic rename. It executes the installed refresh helper first, then the unchanged trusted installer with the exact v7 archive SHA256, then reloads systemd and enables the development credential timer. Each subprocess has `check=True`; a failed refresh prevents the artifact installer and later commands from running. No repository Python is imported under root.
4. **The credential operation remains scoped.** Seven named identities retain separate canonical sources and destinations. Codex `config.toml` is checked but is explicitly not automatically overwritten during apply. Existing provider routes are therefore preserved by the refresh operation. The helper emits status classifications rather than credential values or hashes. The fixed timer invocation excludes optional route reporting.
5. **No rollback or retry success is implied.** Bootstrap helper/unit installation precedes refresh, so a refresh failure can leave those trusted files updated even though artifact activation and timer enablement were not reached. A repeated artifact installation refuses an already existing version. This retry review does not authorize deleting an existing version or bypassing that refusal. The parent reports that the earlier attempt stopped at the missing-function error and old live fingerprints remain active; this reviewer did not independently probe services.

## Executed verification

- **Executed locally, unprivileged host:** `.venv/bin/python -m pytest -q tests/unit/test_worker_credential_refresh.py` — **2 passed**. Exercises all seven synthetic credential copies, check before apply, rotation of one identity, mode 0600, absence of secret values in output, route preservation, and rejection of a nonprivate destination before write.
- **Executed locally, unprivileged host:** `.venv/bin/python tests/verify_worker_credential_refresh_offline.py` — **PASS** for bounded private-file validation, public-read config exception, symlink rejection, owner/mode and atomic publication, temporary cleanup, writable-directory rejection, and the actual destination-ancestor rename/symlink swap immediately before fd-relative publication. These are synthetic files only.
- **Executed locally, synthetic/static:** parsed and compiled the embedded bootstrap without executing it; independently compared all four embedded helper/unit hashes and the complete archive digest; verified the four fixed subprocess argument vectors, their order and `check=True`; executed the ordinary launcher with `subprocess.run` stubbed and asserted the sole captured call was the exact isolated sudo/bootstrap argument vector. No sudo or bootstrap mutation ran.
- The first restricted-runner executions correctly failed the ancestor trust check because `/` and `/tmp` appear as UID 65534 in that filesystem view. The exact tests above were then rerun on the actual host without sudo and passed; no test or implementation normalization was used.
- The parent separately reports **1,113 passed, 24 subtests**, all standalone verifiers passing and a clean `git diff --check`, with one upstream Starlette/AnyIO deprecation warning. That wider run was not independently rerun by this reviewer.

## Remaining gates and limits

The operator's local sudo execution remains required for the actual retry. The caller must pin the launcher digest above and execute those same verified launcher bytes as the ordinary user; running a mutable repository pathname directly under sudo is outside this review. Any changed reviewed input needs renewed digest admission.

Credential freshness, installed helper hashes, active release/runtime fingerprints, timer behavior, provider authentication, Headroom behavior and isolation after activation remain **NOT verified** by these synthetic checks. Production relay/publication restrictions remain subject to the separate production review and are not cleared here.

This review read no real auth/config/credential contents, performed no sudo, install, service change, provider request, AgentPorter delegation or git write, and changed only this report. No implementation modification was made.
