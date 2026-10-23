# A7Dev Cranary HTTPS authorization — 2026-10-21

Status: **owner installed and activated the scoped policy; live public-connector acceptance passed**. ChatGPT may resume bounded Cranary metadata acquisition under this exact grant. No further approval is pending for this scope.

## Follow-up: enabled policy but exec_run rejected — 12:44 EDT

The reported post-activation failures were investigated against the actual service journal. At **12:43:00.497 and 12:43:12.566 EDT**, PID `4102155` rejected Cranary `exec_run(network_access=true)` inside `_parse_curl()`, installed `scoped_https.py:276`, with **`Network use requires a single approved curl metadata command`**. This branch checks that argv is a list of exactly three entries with first entry exactly `curl`; it runs before URL authorization or worker creation. The journal does not retain argv, so it establishes the rejection stage but not the exact malformed argument. A shell wrapper, an executable path such as `/usr/bin/curl`, or extra arguments would reach this branch. No broker start event accompanies those two failures.

The installed server constructs `ScopedPublicHTTPSPolicy(config.config_dir)`, passes its broker to `create_execution_tools()`, and routes network requests to `run_bounded()`. There is no missing connection to an enabled network sandbox: approved requests deliberately use the fixed HTTPS worker, while ordinary Bubblewrap networking stays disabled.

Re-running `.venv/bin/python scripts/verify-a7dev-cranary-https.py --after` at **12:44 EDT** passed through the public MCP endpoint. Public and local endpoints still report PID `4102155`, matching loaded/disk v12 fingerprints, `stale=false`, and the exact enabled owner grant. GitHub HEAD and CRAN HEAD returned HTTP 200; GitHub GET returned valid issue 1 JSON (7,091 text bytes). All nine negative cases and offline workspace isolation passed again. Journal broker start/result events corroborate all three successful calls at 12:44:32–35 EDT.

Evidence:

- `/tmp/a7dev-cranary-https-verification-g706xous/results.json`
- `/tmp/a7dev-https-validation-rejection-20261021.log`
- `/tmp/a7dev-https-revalidation-20261021.log`

The caller should submit this exact tool argument object; omit `cwd` or use the empty string, and do not put timeout flags into argv:

```json
{"workspace_id":"cranary","argv":["curl","-sSI","https://api.github.com/repos/ropensci/software-review/issues/1"],"timeout_seconds":15,"network_access":true}
```

For GET, replace only `-sSI` with `-fsS`. These are fixed broker request tokens, not a general curl command line. The client-visible generic exception hides the useful validation reason. No service restart, policy change, application deployment, or authorization expansion was needed for this follow-up. If a ChatGPT retry with the exact object still fails, its timestamp and submitted argument object are needed to correlate that distinct request; successful public SDK calls alone do not prove what that UI submitted.

## Post-activation acceptance — executed locally

The owner ran the pinned operator command and approved the A7Dev-only restart. Installer output confirms a newly created policy, service UID `994`, mode `0600`, and policy SHA256 `0baf0e14d3b1e1641e86c9c28d9510cc6682853267dbc3a1b16135b0f45f4ff7`. This also resolves the earlier disk-presence uncertainty: the target policy did not exist when the operator installed it.

`agentporter-development.service` is active as `agentporter-dev`, new PID **4102155**, `NRestarts=0`. Public and local MCP sessions report this same PID, the unchanged v12 loaded/disk fingerprint below, and `stale=false`. Both expose `scoped_public_https.enabled=true`, workspace `cranary` only, exactly the four approved hosts, GET/HEAD only, and `generic_shell_network=false`.

The exact post-activation command passed:

```bash
.venv/bin/python scripts/verify-a7dev-cranary-https.py --after
```

Private evidence: `/tmp/a7dev-cranary-https-verification-f5hpkcnw/results.json`; command log: `/tmp/a7dev-cranary-https-after-20261021.log`.

- Frozen GitHub issue HEAD: **HTTP 200**, exit 0.
- CRAN `https://cran.r-project.org/` HEAD: **HTTP 200**, exit 0.
- Frozen GitHub issue GET: exit 0, valid issue JSON, number `1`, issue ID `60586132`, 7,091 response-text bytes.
- **Nine live post-grant denials passed:** unapproved host, localhost, metadata IP, wrong port, HTTP instead of HTTPS, POST syntax, redirect-following flag, shell wrapper, and the `agentporter-dev` workspace.
- Ordinary Cranary execution still reports cwd `/workspace`; protected config and production checkout remain invisible. Generic shell networking remains disabled.
- Audit start/result records exist for all three successful requests under the new service PID, recording workspace, host, method, URL hash, timeout, exit code and byte counts. Evidence: `/tmp/a7dev-cranary-https-positive-audit-20261021.log`; denied request audit evidence: `/tmp/a7dev-cranary-https-after-audit-20261021.log`.
- Production remains active with unchanged PID **664960**. No production configuration, application release, research dataset, or training pipeline was modified; no commit or push occurred.

Unauthorized redirect Location handling remains independently covered by the synthetic redirect unit/security tests; the live test also rejects `-L` before any redirect can be followed. No external redirect test host was added to the grant.

## Pre-activation diagnosis and actual gateway

The public connector endpoint `https://1xs4h6qn-8876.use.devtunnels.ms/mcp` and local `http://127.0.0.1:8876/mcp` were both queried using the existing A7Dev key, without emitting the key. They report the same service PID `3769995`, v12 package `/opt/agentporter-development/versions/20261021T132836.936455Z/src/agentporter`, matching loaded/disk fingerprint `04a978d2746a88afe79c56af673e6d19850ef24aca9b382becc14426fa8a4fcd`, and `stale=false`.

`systemctl show agentporter-development.service --property=User,Group,ExecStart,WorkingDirectory,ActiveState,MainPID` identifies the active system service as `agentporter-dev:agentporter-dev`, using `--config-dir /var/lib/agentporter-dev/config`, on loopback port 8876. The development tunnel unit routes its public URL to that port. Production port 8765 and its configuration were not changed.

Two rejection points are verified:

1. The gateway holds an empty scoped HTTPS policy. A correctly shaped `curl -sSI` request reaches `ScopedPublicHTTPSPolicy.authorize()` and fails with `Public HTTPS request not owner-approved for workspace, method and host`. Capabilities consequently report `enabled=false`, empty workspaces/hosts/methods, and `generic_shell_network=false`.
2. The earlier connector failures shown in service logs fail sooner in `_parse_curl()`: `Network use requires a single approved curl metadata command`. Only a three-element argument list `['curl','-fsS',URL]` or `['curl','-sSI',URL]` is recognized. Extra curl timeout flags or a shell wrapper are rejected. The MCP SDK wraps these exceptions as `Error executing tool exec_run`, explaining the unhelpful client-visible error.

Before approval, the protected on-disk file could not be read as `yeli`; its directory is private. At that point only missing loaded authorization was established. The subsequent operator installation reported `created=true`, confirming the target file was absent. Malformed policy at startup would raise rather than produce a running gateway with this empty valid scope. The installer refuses a conflicting existing policy.

## Supported authorization mechanism

The current immutable release already contains the fixed-purpose HTTPS broker. It loads only `<active config-dir>/public-https.yaml` at gateway startup. For this A7Dev instance that is **`/var/lib/agentporter-dev/config/public-https.yaml`**, not the production user's `~/.config/agentporter/public-https.yaml` and not a YAML file in the agent workspace.

The file must be readable by the service principal and owned privately: **`agentporter-dev:agentporter-dev`, mode `0600`**. A root-owned `0600` file would be unreadable by this service. The private config directory remains `0700`; no directory permissions or sandbox settings need changing.

This is an independently owner-installed, preapproved scope. It is not a caller boolean, signed per-request receipt, generic shell grant, or approval inferred from repository content. Operator sudo authorization and installation outside worker-visible namespaces preserve the existing approval boundary. Gateway tool audit logs and broker start/result/error events remain in force; URLs are represented by redacted hashes in broker audit events.

No new HTTP tool or application release is required. The existing `exec_run` interface recognizes the two exact command forms and routes them to an isolated Python HTTPS worker. **It does not execute caller-selected curl or shell code with networking.** `exec_start` supports the same broker through tracked jobs. A dedicated tool could improve discoverability later but is not needed to activate this reviewed interface.

## Exact proposed change

The complete policy is [the inert example](examples/a7dev-cranary-public-https.yaml):

```yaml
version: 1
workspaces:
  cranary:
    hosts:
      - api.github.com
      - cran.r-project.org
      - cran-archive.r-project.org
      - bioconductor.org
    methods: [GET, HEAD]
    max_response_bytes: 262144
    timeout_seconds: 15
```

Policy SHA256: `0baf0e14d3b1e1641e86c9c28d9510cc6682853267dbc3a1b16135b0f45f4ff7`.

HTTPS/TCP 443 is enforced in code, with exact host matching, public-only DNS answers, pinned destination addresses, original-host TLS certificate verification, no inherited credentials/proxies, and rejection of **all redirects**. Bounds cover response text/HEAD metadata and the parent worker's total wall time. Only small text/metadata acquisition is covered; bulk catalogs, binary archives, training, and research-data changes are not included.

The installed implementations are byte-identical to current source:

- `scoped_https.py`: `2c51714f5e12deb92cc8536df1cc7aa36a0baef08b4529505a3ca27253e8ee56`
- `scoped_https_worker.py`: `d02745df9e18f0e412c12a4b6b85290aefa98e33f62fadcb70d01decca7886bb`
- `tools/execution.py`: `10f7d529c9901e195430f3f37803bf7210389404bd297cdf08eff5dedfc49b9c`

## Preparation files and applied operator change

- [Human-run installer](../scripts/authorize-a7dev-cranary-https.py): default is a read-only proposal. `--apply-policy` requires yeli's local terminal and operator sudo authorization. Root runs fixed stdlib bytes, checks the exact v12 release/service/config/code pins, and installs the fixed policy without following links or overwriting a different policy. It validates the policy with the immutable release **as the service UID**, not as root. It never restarts a service. Existing differing, unsafe, or racing policy files are preserved for operator review.
- [Reproducible MCP verifier](../scripts/verify-a7dev-cranary-https.py): default checks current denials and isolation. `--after` first requires the exact approved capability on the public/local gateway, then tests bounded live GitHub/CRAN requests and negative cases. Evidence is written under private `/tmp` directories only.
- [Installer safety tests](../tests/security/test_a7dev_https_policy_install.py) cover dry-run behavior, private creation, idempotence, refusal to replace differing policies, symlink/FIFO handling, unsafe modes, and publish races.

The agent's preparation did not install a policy, invoke sudo, or restart services. The owner subsequently installed the exact policy and restarted A7Dev using the command below. The agent then performed the read-only public/local acceptance checks above. Production configuration and Cranary research files remain untouched; no commit/push or Laya training occurred.

## Exact operator action — performed by the owner

Review the policy and installer above. This action installs only that policy, then restarts **`agentporter-development.service` only**. Run when A7Dev is idle because the restart can interrupt active requests or worker jobs. Do not run the repository script itself under sudo.

```bash
/usr/bin/python3 -I -c 'import hashlib,pathlib; p=pathlib.Path("/home/yeli/agent-work/agentporter-dev/scripts/authorize-a7dev-cranary-https.py"); b=p.read_bytes(); assert hashlib.sha256(b).hexdigest()=="0e266daaa841706bbc98fd03d527295eef1e88923e3960a2263d70f89e58413e", "Installer changed: stop"; exec(compile(b,str(p),"exec"))' --apply-policy &&
sudo /usr/bin/systemctl restart agentporter-development.service
```

If installation refuses an existing different policy or a changed baseline, stop and review its reported condition. Do not overwrite, loosen metadata checks, or activate another prepared runtime artifact.

Installing the file alone does not update cached gateway capabilities. Restart is deliberately separate and requires the operator's approval. Afterward, perform live acceptance with:

```bash
cd /home/yeli/agent-work/agentporter-dev
.venv/bin/python scripts/verify-a7dev-cranary-https.py --after
```

The verifier reads the existing private A7Dev key from `/tmp/agentporter-development-asgard/config/secrets.env`; it does not print or modify it. If that staging key file has been removed, resolve a trusted private credential source rather than pasting credentials into chat.

## Validation results

| Check | Result / evidence |
|---|---|
| Actual public/local MCP instance and policy agree | **executed locally: PASS**; `/tmp/a7dev-cranary-https-verification-2wjyow_7/results.json` |
| Correct frozen GitHub HEAD before approval | **executed locally: denied**; no upstream response code, MCP returns an error envelope. Journal at 11:13:01 EDT records the exact authorization rejection. |
| Malformed command before approval | **executed locally: denied** at parser; same journal timestamp records the different rejection reason. |
| Unapproved host, localhost, metadata IP, wrong port, HTTP, POST syntax, `-L`, shell wrapper, other workspace | **executed locally: all denied** over public MCP, before approval. These pre-grant denials do not replace post-grant checks. |
| Cranary ordinary execution and isolation | **executed locally: PASS**; cwd `/workspace`, protected config invisible, production checkout invisible, no general shell networking enabled. |
| Policy, DNS/TLS, redirects, bounds, routing, audit, installer safety | **unit test: 95 passed**; `/tmp/a7dev-scoped-https-operator-tests-20261021.log` |
| Offline adversarial HTTP cases | **executed locally: 65 passed; no outbound connections**; `/tmp/a7dev-scoped-https-offline-20261021.log` |
| Offline integration and additional audit regressions | **executed locally: PASS**; `/tmp/a7dev-scoped-https-integration-20261021.log`, `/tmp/a7dev-scoped-https-audit-20261021.log` |
| Unauthorized redirect Location | **unit test: PASS** with a synthetic redirect; no connection to its target. Live redirect-following syntax is denied. No allowlist expansion was made to host an external redirect test server. |
| Enabled capabilities through public and local MCP | **executed locally: PASS**; exact cranary-only four-host GET/HEAD grant; PID 4102155 and matching v12 fingerprints. |
| Live frozen GitHub HEAD/GET and live CRAN HEAD | **executed locally: PASS**; both HEAD responses HTTP 200; GET yielded valid issue 1 JSON. |
| Post-grant negative checks, offline isolation, audit events | **executed locally: PASS**; nine public MCP denials, protected paths invisible, positive/negative audit records verified. |

Commands executed for verification:

```bash
.venv/bin/python -m pytest -q tests/security/test_a7dev_https_policy_install.py tests/unit/test_scoped_https.py tests/unit/test_offline_execution_defaults.py
.venv/bin/python tests/verify_scoped_https_offline.py
.venv/bin/python tests/verify_https_integration_offline.py
.venv/bin/python tests/verify_https_audit_regressions.py
.venv/bin/python scripts/authorize-a7dev-cranary-https.py
.venv/bin/python scripts/verify-a7dev-cranary-https.py
git diff --check
```

No direct host curl result was used as success evidence. Operator action and live acceptance have passed. ChatGPT may resume **bounded scoped metadata acquisition**, using exactly:

```json
{"workspace_id":"cranary","argv":["curl","-sSI","https://api.github.com/repos/ropensci/software-review/issues/1"],"timeout_seconds":15,"network_access":true}
```

Use `-fsS` instead of `-sSI` for GET. Do not add curl flags; timeout is the separate tool argument. No further human approval is required for requests within this activated scope. Larger/binary acquisition remains outside this metadata grant.
