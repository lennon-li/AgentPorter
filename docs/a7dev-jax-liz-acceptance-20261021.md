# A7Dev Jax and Liz acceptance — 2026-10-21

Existing v10 A7Dev release remains active. No privileged changes in this verification.

Jax job `job_c09f3c3e996545d0a23ada9d` and Liz job `job_1cdc206c948a453a937a5b76` completed real delegated tasks in agentporter-dev and cranary respectively. Both reported `/workspace`, expected README and canonical skill SHA256 values, nonwritable skills, RTK 0.43.0 and ripgrep 14.1.0. Verified records are in `/tmp/agentporter-acceptance-20261021/`. These successful retries supersede their earlier quota failures.

A separate bounded Jax Headroom probe returned the expected nonce `cc7da5aade31`, 180 records and only `healthy` status. No parent model requests occurred during the probe interval. Sanitized before/after metrics and result are in `/tmp/agentporter-headroom-measure-20261021/`.

Headroom recorded 2 new requests: 35,545 original input tokens; 31,680 optimized; 3,865 saved (10.87%). Both report exact, complete token accounting. The larger request used smart_crusher on tool output plus schema compaction. Attribution is based on the isolated measurement interval; shared service counters alone are not treated as per-job evidence.

Provider readiness: Jax, Liz, Prof and Ming have real successful model-backed evidence. Argie native file-policy acceptance is pending. Wei expired OpenCode key and Phil exhausted Copilot quota remain external conditions; neither route was substituted. Production remains inactive pending receiving-side egress/publication enforcement and independent acceptance.
