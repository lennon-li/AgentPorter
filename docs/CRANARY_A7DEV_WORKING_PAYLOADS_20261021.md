# Cranary acquisition through public A7Dev

Current release: v19, fingerprint `2a41380b67529e5bb27fa3e00d7a84ced0946989879b3948a97c25f5eeee6ac7`.

**Permission repair applied and live verified.** The current public-client policy excludes ordinary offline execution and all but two project workspaces. The owner's requested restoration is `scripts/restore-a7dev-workspace-access.py`, SHA256 `59afe7cf5c925f016fdd3694aa353cee93ae1a361f9dda795d286924d9ac1703`. It restores ordinary project access across the existing 46-workspace registry, preserves protected roots as read-only, and leaves HTTPS/provider/resource controls in place. It changes only the owner policy, with a private backup and guarded rollback; no release deployment is required. Actual new policy SHA256 must be `97fbbeb9abfb896f4022647218dbc77f80fbfa2bbb3bfea25101756dd4b92043`.

## Offline commands after the policy repair

Call `a7dev.exec_run`:

```json
{"workspace_id":"cranary","argv":["python3","-V"],"timeout_seconds":15,"network_access":false}
```

```json
{"workspace_id":"cranary","argv":["git","-c","safe.directory=/workspace","status","--short"],"timeout_seconds":15,"network_access":false}
```

The command-local safe-directory setting accommodates the separate service UID without modifying global Git configuration. The dedicated `git_status` tool is also available through the restored Git-read scope. Protected Git metadata and publishing restrictions remain enforced.

IRVRI uses the same offline payloads with `workspace_id:"IRVRI"`; `pwd` returns `/workspace`. `workspace_info` takes only `{"workspace_id":"IRVRI"}`. Ordinary project files can be read/written using the existing scoped file tools; no caller receives host execution or networking.

## Frozen GitHub evidence — already live verified

Call `a7dev.exec_run` with each payload:

```json
{"workspace_id":"cranary","argv":["curl","-fsS","https://api.github.com/repos/ropensci-archive/rrlite/commits/b390ba0afb5f1613572ba4ce3d5d733987edd0bd"],"timeout_seconds":15,"network_access":true}
```

```json
{"workspace_id":"cranary","argv":["curl","-fsS","https://api.github.com/repos/ropensci-archive/rrlite/contents/src/rrlite.c?ref=b390ba0afb5f1613572ba4ce3d5d733987edd0bd"],"timeout_seconds":15,"network_access":true}
```

Use `-sSI` in place of `-fsS` for HEAD. GET commit identity and base64 source content were verified through the actual public tunnel. Source: 4,271 bytes; Git blob SHA1 `bba6bf7f836a0ebdc52f2554ab32b8bd7410ed1d`; SHA256 `015761af6d0374967c6eb563b211eab208b3b9572673176e659c74fb1d107007`. Evidence: `docs/evidence/v19-final-closeout-20261021/github-canonical-live.json`.

There is no repository-path allowlist in the installed GitHub authorization; its host and GET/HEAD are already approved. The legacy `ropensci/rrlite` URL reproduced exit 77, while the canonical `ropensci-archive/rrlite` URLs succeeded. A redirect is the likely explanation, but the worker's redacted error does not establish the exact legacy response status. Direct canonical URLs avoid requiring redirects. No GitHub permission expansion is needed; do not use `-L`.

After the file scope is restored, save the exact returned JSON stdout with `write_file` under a fresh filename in the acquisition report directory, decode the source base64 offline, and record both the API-response checksum and decoded source checksum. Do not claim a reserialized JSON checksum is the checksum of the original response bytes.

## Bounded binary acquisition — already live verified

Call **`a7dev.https_download`**, not shell `curl -o`:

```json
{"workspace_id":"cranary","url":"https://packagemanager.posit.co/cran/2021-06-30/src/contrib/PACKAGES.gz","filename":"PACKAGES-2021-06-30-research01.gz","max_bytes":16777216,"timeout_seconds":60}
```

The directory is fixed by owner policy:
`data-raw/cran-history/reports/2026-10-21-authorized-acquisition/downloads/`.
Choose a fresh simple filename each time; existing files are never replaced. The result contains the saved relative `path`, HTTP status, byte count, retrieval time and SHA256. First-fetch `expected_sha256_verified:false` means a checksum was recorded, not independently supplied beforehand. To enforce byte identity with the existing receipt, supply `expected_sha256:"a069c3138f2b49c339d5f500f8beff8872d95a125e61a01b8307a7a6eba214fd"`; a mismatch must remain an error.

CRAN checksum-verification example, same tool:

```json
{"workspace_id":"cranary","url":"https://cran.r-project.org/src/contrib/Archive/TCIU/TCIU_1.1.0.tar.gz","filename":"TCIU-1.1.0-research01.tar.gz","expected_sha256":"f9859ceb56997d30041c90f45073e59afd32f8ba985e0c6d500a6f49a2d98a42","max_bytes":16777216,"timeout_seconds":60}
```

Both requests returned HTTP 200 through public A7Dev: Posit 710,490 bytes, SHA256 `a069c3138f2b49c339d5f500f8beff8872d95a125e61a01b8307a7a6eba214fd`; TCIU 4,257,339 bytes, SHA256 as above, supplied-checksum verification true. Existing filenames are `PACKAGES-06e171b7eb0fa6ad.gz` and `TCIU-1.1.0-06e171b7eb0fa6ad.tar.gz`. Private per-call receipts: `/tmp/a7dev-cranary-acquisition-verification-cma155n3/results.json`; the owner diagnostic independently rehashed both saved files.

## Offline decompression and checksum verification

After the permission repair, call `exec_run` with `network_access:false`, timeout 15, and argv `python3`, `-I`, `-c`, followed by this code as the fourth argument:

```python
import gzip, hashlib, io, json
from pathlib import Path
p = Path('data-raw/cran-history/reports/2026-10-21-authorized-acquisition/downloads/PACKAGES-06e171b7eb0fa6ad.gz')
assert p.stat().st_size <= 16 * 1024**2
raw = p.read_bytes()
assert hashlib.sha256(raw).hexdigest() == 'a069c3138f2b49c339d5f500f8beff8872d95a125e61a01b8307a7a6eba214fd'
with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
    expanded = stream.read(64 * 1024**2 + 1)
assert len(expanded) <= 64 * 1024**2
assert hashlib.sha256(expanded).hexdigest() == '2b70321658ff7c6bd3159b62ed8f28708d3544d1b6dce8aa7ce443dc17296280'
print(json.dumps({'compressed_bytes': len(raw), 'expanded_bytes': len(expanded), 'sha256': hashlib.sha256(raw).hexdigest(), 'expanded_sha256': hashlib.sha256(expanded).hexdigest()}))
```

No package is extracted or executed. The snapshot has 17,802 records / 17,785 case-insensitive families. Seventeen families repeat; RODBC has versions 1.3-17 and 1.3-16, XML 3.99-0.6 and 3.99-0.3. The existing population preview correctly refuses this ambiguity. Do not drop rows or choose versions merely to pass a test. No training/evaluation eligibility, rights clearance or exact historical completeness is asserted.

## Denials and remaining gate

Live tests rejected unauthorized host/workspace/scheme/port/IP/path/query, excessive bytes/time, POST, `-L`, shell network commands and bad checksum. HTTPS is still Cranary-only, GET/HEAD over public HTTPS/443, no redirects, with fixed metadata and binary limits. Generic offline Python remains in a network-isolated sandbox after restoration. The owner applied the policy and all six public Cranary acceptance requirements passed. Qman and IRVRI workspace-info, pwd, Python and Git also passed. Exact results and fresh download/source receipts are in `docs/evidence/v19-final-closeout-20261021/restored-workspace-acceptance.json`.
