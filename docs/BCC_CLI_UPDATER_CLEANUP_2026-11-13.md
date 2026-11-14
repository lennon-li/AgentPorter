# BCC shared CLI updater and obsolete installation cleanup

The installed BCC `updateCLI` command and its daily timer use only the shared
CLI installation under `/opt/agent-clis/current`. This cleanup retired 46
unused AgentPorter CLI directories from their installation paths. The selected
CLI release, production services, native account data, generation 16 packages,
and the generation 15 application rollback were unchanged.

## Command and schedule

Both `/home/yeli/.local/bin/updateCLI` and `/usr/local/bin/updateCLI` resolve to
the protected `/usr/local/bin/updateCLI-bcc` wrapper. It invokes
`/usr/local/libexec/bcc-shared-cli.py`; it does not update CLI files inside
AgentPorter application packages. `updateCLI --status` is inspection only.

`bcc-shared-cli-update.timer` is the single scheduled CLI update path. It runs
at 02:00 America/New_York with up to five minutes of randomized delay. Its
existing credential exclusion, unprivileged staging, protected import and
atomic selection controls were retained. The audit found no CLI update entry
in user/system crontabs, cron directories or anacron configuration, including
cron symlink targets. The unrelated Fury memory-sync cron job was preserved.
The command and schedule already had this shared-only configuration; this
cleanup did not need to replace either one or trigger an actual CLI update.

## Retired code and recovery

The one-time procedure is
[`bcc-retire-legacy-cli-20261113.py`](../scripts/bcc-retire-legacy-cli-20261113.py).
It requires root, takes the shared-updater lock, refuses live process references,
checks directory ownership/device identity, and preserves the selected CLI,
generation 15/16 manifest hashes and service states. It was executed with
isolated Python and bytecode writing disabled. Its fixed 46-directory preimage
check means it must not be replayed as a general-purpose cleanup command.

The retired trees comprise 45 historical `releases/*/cli` directories and
`/opt/agentporter-bcc/shared-cli/codex-0.167.2`. None remained at those installed
paths after cleanup. They were moved, without copying or rewriting their
contents, into this root-only recovery archive:

```text
/var/lib/agent-clis/retired-agentporter-cli-20261114T035651Z/
```

`RETIREMENT.json` records each source/archive path and original inode/ownership,
along with the unchanged selected CLI and protected release manifests.
`RESTORE.py` checks those identities and refuses overwriting existing paths.
If restoration is needed, the owner can run:

```sh
sudo /usr/bin/python3 -I -B \
  /var/lib/agent-clis/retired-agentporter-cli-20261114T035651Z/RESTORE.py
```

Historical release manifests were not rewritten to hide missing CLI files.
Consequently, an older retired release requires restoring its archived CLI
tree before its complete original seal can verify or its rollout can be
replayed. Generation 16 and its generation 15 application rollback have no
embedded CLI trees and remain intact. The project-view service's existing
Python interpreter and application code were also left in place.

## Verification and remaining source patch

Fresh post-cleanup host verification passed for selected executable hashes,
terminal/worker/native-daemon inode parity, enrolled account separation,
gateway/worker release seals and loaded/disk fingerprints, shared updater
configuration, and all 38 registered workspace paths. Service states and PIDs
were unchanged. Restore-script syntax and JSON-line termination were checked;
no restoration, model job, vendor update or service restart was performed.

Machine receipts are in
`artifacts/bcc-updater-cleanup-20261113/post-cleanup-verification.json` and
`cleanup-summary.json`; the root archive contains the protected retirement
record. These are host observations, not a new external ChatGPT audit.

An older, currently unselected script in the separate Obsidian repository still
contains the obsolete AgentPorter release-tree updater. A patch removing that
code and routing direct BCC invocations to the shared updater is prepared at
`artifacts/bcc-updater-cleanup-20261113/obsidian-updateCLI.patch`. Six isolated
routing cases passed without npm, sudo or network calls. **That source patch
has not been applied or committed:** explicit Obsidian scope authorization is
still pending under the session's cross-project write rule. Existing dirty
Obsidian work was preserved. This AgentPorter commit records only the completed
BCC installation cleanup and its reproducible procedure.
