# A7Dev Argie shared-skill policy repair — 2026-10-21

Status: implementation tests pass; native permission matcher acceptance remains required before activation.

The v11 Argie generated permission allowlist admitted four individual shared documents, excluding canonical skill bodies. The repaired policy admits `read_file(/opt/agentporter/shared/obsidian)` when the existing vetted immutable shared snapshot is configured. Without a snapshot, only `read_file(/workspace)` is admitted. The existing shared-source validation and sandbox read-only mount remain the admission and immutability boundaries. No host Obsidian directory is newly mounted. Skill instructions are not automatically executed.

The explicit command, write, URL, MCP, authentication-directory, config-directory and local-share denials remain unchanged. Credentials, provider model/routing, launch arguments and services are untouched.

Verification:

- `.venv/bin/pytest -q tests/security/test_development_runtime.py -k 'argie and not real'`: 7 passed, 57 deselected.
- `.venv/bin/pytest -q tests/security/test_development_runtime.py -k 'not real'`: 54 passed, 10 deselected.
- Snapshot-present fixture now includes an actual `Toolbox/claude-skills/synthetic-skill/SKILL.md`; snapshot-absent fixture confirms no shared allow rule is emitted.
- `agy permissions --help` advertises only generic usage, with no permission-inspection or offline tool-invocation subcommand. No provider invocation was performed during this repair.

These tests prove generated policy and launch configuration, not native CLI matcher semantics. A workspace symlink can alias `/home/worker/.gemini/antigravity-cli`; existing masks do not reject every arbitrarily named symlink. Consequently path normalization, deny precedence and credential-alias behavior remain explicit release blockers until black-box verification.

Required native acceptance canary (synthetic credentials only):

1. Launch the exact installed Argie executable through the existing confined runtime in a throwaway approved workspace, with a synthetic non-auth canary in each denied directory. Never use production credentials for adversarial read tests. Arrange test authentication separately through the approved provider flow without placing real secrets in observable test fixtures.
2. Request each read explicitly and capture native tool decisions: normal workspace file; nested synthetic shared skill; direct denied file; `..` traversal into a denied directory; workspace symlink to denied file; workspace symlink to denied directory; nested symlink chain; symlink plus `..`; similarly prefixed directory such as `/workspace-other`; URL and command attempts.
3. Allowed reads must return only synthetic expected contents; every denied or alias read must fail before content reaches model/output. Verify absence of canary bytes in captured tool results. A refused model request alone is insufficient; the native permission engine must report rejection of the attempted tool call.
4. If native normalization or deny precedence fails, stop activation and repair that boundary. Do not interpret JSON assertions or ordinary filesystem `readlink` tests as proof. Replacing host secrets with synthetic canaries avoids credential disclosure during this investigation.
5. After independent review clears the matcher boundary, run one ordinary authenticated delegation that reads a canonical skill and workspace file with the release candidate, then verify real read-only mounts independently. Record installed executable/release fingerprints with the results.

No broader symlink masking change is included: masking an arbitrary symlink path with a bubblewrap bind can itself dereference an unintended target, and a correct race-resistant alias boundary needs separate review. This bounded repair does not claim that unresolved native permission isolation has been established.


Native acceptance update, 2026-10-21: independent review cleared bounded policy source repair after two synthetic authenticated model-backed canaries. Final evidence: `/tmp/argie-native-policy-result-m3_yqjvz/`. Two allowed reads returned actual 1-line/56-byte output. Direct .config/.gemini paths, configuration file/directory symlinks, chained alias, credential-directory file/directory aliases, and existing sub/../alias received native explicit canonical-path denials. Relative paths were rejected as nonabsolute and sibling-prefix access explicitly denied. The older ENOENT case is excluded from permission evidence. No real authentication file was requested by model tools; only synthetic nonsecret markers were used. Temporary credential copy was scoped to native CLI authentication in disposable private home.

Observed canonical Argie bootstrap hosts were daily-cloudcode-pa.googleapis.com, www.googleapis.com (userinfo), and lh3.googleusercontent.com (profile image). Initial proposed host list omitted these; it is not production-validated. Diagnostic-only grants were independently reviewed. No production host-policy expansion is cleared by this test.

Complete host verification: 1,250 tests and 24 subtests passed, plus all six standalone verifiers; one upstream warning. Log `/tmp/agentporter-resume-full-verification-host-20261021.log`. Initial sandbox run failed provenance checks because managed sandbox remaps root-owned ancestors to UID65534; no security checks were weakened. The successful run was unprivileged on actual host. Final diagnostic fixture changes subsequently passed both focused tests.

A7Dev live fingerprint remains 38ead25120fc363fde47b363d34e3d8bea364283a3b3d3ebb594e051a426c5ea, PID3421685, release20261021T020503.171884Z, loaded=disk, stale=false. Production live fingerprint remains 8de423283d3db8938a226719650a6c3b8fb325c534154992636bb6c51bf490a8, PID664960, release65dbf445bcd16f8e6961a5d5eef4d9f76c084cf8, loaded=disk, stale=false. Both independently queried during resumed work.

Production remains on HOLD: actual receiving-side application-origin/publication controls must be resolved and tested before activation. This source clearance does not lift that separate security gate.

Frozen A7Dev-only derivative prepared:

- Version: `20261021T132836.936455Z`
- Archive: `/tmp/agentporter-development-candidate-v12.tgz`
- SHA256: `e35b83635f96feb97b533709bbad1c7b5c4054bf6f9c8bcc7d51af8dacd664a5`
- Exactly 3 release-file changes: bounded `development.py` policy repair and two required venv release-path relocation files. All other release entries, approved resource manifests, credentials/routes, tools and skills retained from v11; 26,344 entries verified.
- Activation launcher: `scripts/install-approved-a7dev-v12.py`, SHA256 `9c830da5083a6648285bafa4a84e4fc291d65bac72a9cd0da21185eb18fb82e8`; active v10 baseline enforced; exact release/runtime rollback retained.
- Synthetic activation coverage expanded to v11/v12: 76 tests passed (`/tmp/agentporter-v12-activation-tests.log`). Full final host verification and independent archive/launcher review pending at time of this entry.
- No sudo authentication available to agent tools. This candidate has NOT been installed; current running release remains v10.

Final frozen verification: **1,286 tests and 24 subtests PASS**, one upstream warning; every standalone verifier PASS. Log `/tmp/agentporter-v12-final-verification-20261021.log`. Independent stream verification `/tmp/v12-independent-archive-verification.json` confirms all26,344 entries against both actual manifests and exactly the3 intended file changes; resource manifest digest unchanged. Await final reviewer decision before local activation.
