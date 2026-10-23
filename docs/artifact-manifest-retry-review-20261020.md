# Independent artifact manifest retry review — 2026-10-20

**Verdict: no remaining identified code or admission blocker for the exact corrected A7Dev-v8 archive and launcher pinned below.** Privileged retry, activation and live acceptance remain **NOT verified**. This review does not grant execution permission or production clearance. The parent's final full host gate is a separate acceptance requirement.

## Independently confirmed failure

The original builder's `entries(release)` prunes `__pycache__` directories, while its original recursive `tarfile.add(release)` had no equivalent filter. The installer correctly rejects any file absent from the reviewed manifest. This explains the reported v7 `File differs from reviewed manifest` failure; relaxing installer verification would weaken the boundary and is not part of this repair.

An independent streaming metadata scan of all **30,427** original v7 archive members found **26,344** manifest entries and **27,391** release nondirectory members. Every one of the **1,047** extras is a regular `.pyc` file beneath `__pycache__`; no other extra, missing manifest member, duplicate archive name, symlink-target mismatch or executable-mode mismatch was found. There are 136 cache directories. The extra range starts at `python/lib/python3.13/__pycache__/__future__.cpython-313.pyc` and ends at `venv/lib/python3.13/site-packages/yaml/__pycache__/tokens.cpython-313.pyc`. The parent separately hashed all 26,344 original manifest payloads and reported all matched; this reviewer did not repeat that original payload hashing.

The original archive stays frozen at SHA256 `58db31a16a80a3147808d41bf0d7febcfcf27d378de203d4c6db634f385451b8`. This is a content-preserving repack of that admitted release, with unadmitted cache files excluded, rather than a build from the later dirty checkout. Release version remains `20261020T223443.649130Z`.

## Implementation review

`write_artifact` checks the release against the manifest before packing, prunes cache directories during tar recursion, rejects unlisted noncache nondirectories, and requires the packed nondirectory set to equal the manifest. The production installation root remains `/opt/agentporter-development`; the added constant permits synthetic test injection.

The unprivileged repacker opens the original without following a leaf symlink, admits a bounded operator-owned regular file, copies it privately and verifies the complete original archive digest before extraction. It uses the unchanged installer's strict extractor, admits only unlisted regular `.pyc` files under cache directories as removable extras, verifies all admitted contents, and uses the repaired packer. It then extracts and verifies the candidate using the real strict installer and compares all three metadata files byte-for-byte with the original. Publication uses a hard link into a new output name without replacement; the result is mode 0400. No original archive or live release is modified.

**Review findings corrected:** an independent synthetic reproduction showed that an admitted symlink could depend on an omitted cache file while strict manifest agreement still passed. The final packer now rejects cache-dependent links, including raw `__pycache__/../` traversal, intermediate cache symlinks and a cache-named directory alias whose final resolved target has an ordinary name. It still accepts an admitted regular file literally named `__pycache__`. Negative and positive tests cover those shapes. The parent's wider gate also caught the repacker leaking process-global umask 077; the final wrapper restores the caller's previous umask in `finally`, with actual success/error-path regression coverage. Neither finding requires installer relaxation or a change to the frozen admitted release payloads.

## Exact reviewed digests

| Input | SHA256 |
| --- | --- |
| `/tmp/agentporter-development-candidate-v8.tgz` | `e9b9919f27b9a01e11b8f1274811e035a7d85ecbb809474e83eb6a0a7a89d929` |
| `scripts/install-approved-a7dev-v8.py` | `06bf14c048255528103d07fbf773ef1745a250c8b3338b13b32f02fc4dc9d08a` |
| `scripts/build-development-candidate.py` | `41085734f1b386bf64bbcdae5f79f308b401728ba22eeafccd573cca588f41a1` |
| `scripts/repack-development-candidate.py` | `16e79d6f8e873a152158f70a4cd1b6d2e690df5b4cf74cd18a9080a74ef766e7` |
| `tests/security/test_development_artifact.py` | `c7bc8784e3a5fa44379b4740afb6288fac21833d29e071d740d0c8568c33eafd` |
| Unchanged `scripts/install-development-artifact.py` | `84a53fbfcfe55668a2edda208b0990acf5fd98a6a105a73fb90cc51252e01c58` |
| Unchanged `scripts/refresh-development-worker-credentials.py` | `18b96a4112d460c10c25d34377cc9bb06f21e4aa4c1b27dcce0ebd969bf97811` |
| Unchanged `scripts/agentporter-dev-credential-sync.service` | `30bd3a3a9e26f5733d3efd4520c1645a735eddcebb4c0ae55e470b4519922bca` |
| Unchanged `scripts/agentporter-dev-credential-sync.timer` | `43b7a2200c0a0521e400adb01da93abf759f7ebdb685e4529234b9aa4f3738c2` |

## Executed synthetic evidence

`.venv/bin/python -m pytest -q tests/security/test_development_artifact.py tests/unit/test_development_provisioning.py` — **56 passed** (45 artifact, 11 provisioning), independently executed locally against the final code. This includes real build/packing/extraction/hash verification, exact manifest agreement, executable and symlink preservation, synthetic installation and exact rollback, as well as negative tests for changed/missing/extra files, execute-bit changes, wrong source digests, noncache extras, cache symlinks, omitted-target link shapes and caller-umask restoration. Snapshot inputs are inert fixtures. UID/chown, root's directory-move DAC override and systemd effects are explicitly simulated; actual directory pinning, file operations and renames execute. This is not privileged installation or live rollback evidence.

## Independent complete actual-archive verification

The reviewer opened the finished mode-0400 v8 archive without following a leaf symlink and independently computed the complete SHA256 above. Using the unchanged hash-pinned installer, the reviewer extracted the **entire actual archive** into a private temporary directory, then ran its strict `verify_release` against the extracted manifest: all **26,344** entries passed. All **1,066** symlinks resolved with `strict=True` inside the extracted release. There were **zero cache paths**, all three metadata SHA256 values matched the original references below, and the release version remained `20261020T223443.649130Z`. Source archive size/mtime/ctime remained stable during the check. Extraction took 36.37 seconds; strict verification and complete link/metadata checks finished by 57.64 seconds. The private extraction tree was then cleaned; no payload was executed.

This actual-archive check ran before the final generic link guard was added, but establishes the stronger relevant artifact invariant directly: every link successfully resolves inside a tree containing no cache directory. A link requiring a removed cache directory, including raw cache/../ traversal, would fail that strict resolution. The final guard itself is separately exercised by the final synthetic suite. The final umask restoration affects only caller-process hygiene and does not change the frozen archive payload.

The parent additionally executed a full **actual-archive** install/rollback harness. This reviewer inspected `/tmp/agentporter-preflight-full-artifact-install.py` and `/tmp/agentporter-v8-full-install-preflight.json`: the helper and archive are hash-pinned; canonical original shared-resource paths are checked before runtime paths are rebased into a private temporary installation root; real extraction, strict manifest checks, stage promotion, previous-runtime capture, config/current swaps and exact rollback run. Root directory ownership/DAC and systemctl calls are simulated, and the evidence explicitly records `sudo: false`, `payload_execution: false`, `service_changes: false`. Installer output reporting `service_restarted: true` represents the supplied activation flag and stubbed call, not a real restart. The actual-archive harness was parent-executed and reviewer-inspected, rather than independently rerun by this reviewer.

## Metadata identity reference

The author supplied these SHA256 values from the admitted original archive's extracted metadata. The reviewer independently matched every corrected extracted metadata file to these values:

| Metadata | Original SHA256 |
| --- | --- |
| `runtime.json` | `51bc724c9b301fbb9d5ce8051446f16c2e5619eaa4f954b3c5c75f62dedc7984` |
| `release-metadata.json` | `d3a5540ed58a13998e2f717ca6786a4f527084db125ba07c9d0d74a4be210906` |
| `release-files.json` | `b826b44ba1af70be192d6a12d8e36ad56a8158a188ea5b0dca55f01e766ea272` |

## Launcher review

The reviewer independently proved the v8 launcher bytes equal the previously reviewed v7 launcher (`69b5cce204c8c72e5c170d72e196edc8c45252f568a1b8a3e91264139421c254`) after exactly three one-occurrence substitutions: artifact filename, artifact SHA256, and printed v8 label. No helper/unit pin or bootstrap behavior changed. All four embedded helper/unit hashes match current source bytes. The embedded bootstrap compiles, retains its four fixed subprocess commands with `check=True`, and passes the exact v8 archive path/hash to the unchanged installed artifact installer. An independent launcher execution with `subprocess.run` stubbed captured exactly `/usr/bin/sudo /usr/bin/python3 -I -c <fixed bootstrap>` and no other call; no sudo was executed. The earlier descriptor-based trusted-bootstrap review remains applicable to the unchanged code.

## Remaining gates and limits

The parent's final full host suite must pass after the frozen guard/umask changes; this bounded review does not claim its outcome. Privileged retry and activation, installed hashes and active fingerprints, provider authentication, actual timer/credential behavior, actual runtime rollback and production acceptance remain separate **NOT verified** gates. The caller must verify the exact launcher digest and execute those same verified bytes as the ordinary user; executing a mutable repository pathname directly under sudo is outside this review. Changed input bytes require renewed admission.

No real credentials, sudo, live service changes, provider calls, AgentPorter delegation or git writes were used for this review. No implementation or frozen archive was modified by the reviewer. The only durable reviewer-created file is this report; temporary synthetic/extraction state was cleaned.
