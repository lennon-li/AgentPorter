# A7Dev activation preflight correction — 2026-10-20

The operator's v9 install failed its service-UID preflight and reported exact
v8 release/runtime rollback with verified health. The candidate-only diagnostic
then demonstrated successful application initialization in both runuser and
NoNewPrivileges=1 contexts. Its inventory lookup raised AttributeError.

Installed v9 server source confirms that create_asgi_app returns
SecurityMiddleware, whose app property holds FastAPI. The frozen v9 activation
launcher and original diagnostic incorrectly read app.state.tools. Correct
access is app.app.state.tools. No installed application code change is needed
for this error.

After correcting the diagnostic, the operator supplied successful real
service-UID results in both contexts: seven exact named workers available,
delegatable, and verified_development_bwrap; all eight approved roots canonical
and readable/searchable. Inventory took 16.733 and 16.482 seconds. This proves
CLI/confinement readiness, not provider authentication/quota or model responses.
The reason classifier emits unclassified_failure for empty availability reasons;
that field is not a failure when the worker flags and inventory phase pass.

V9 remains frozen. The unchanged installer refuses an existing release version,
so a fresh v10 derivative is built from the same frozen v8 and exact two source
pins using prepare-development-overlay.py, overriding only output/report paths.
The builder verifies full base/candidate extraction, exact four-entry release
delta, unchanged tool/resource content, and explicit eight-root authority.
The new launcher preserves v9's installation lock, exact rollback pair,
helper/archive digest checks and service-health gates, with corrected wrapper
access and fresh archive/version pins.

Regression coverage uses real SecurityMiddleware in diagnostic phase tests and
real FastAPI plus SecurityMiddleware when executing the v10 STARTUP_PROBE.
Activation/recovery tests cover both frozen v9 and v10 launchers.

Live v10 installation and provider acceptance remain NOT verified until the
operator executes the pinned launcher and live acceptance is checked.

## Frozen candidate pins

- Release: `20261021T020503.171884Z`.
- Archive: `/tmp/agentporter-development-candidate-v10.tgz`.
- Archive SHA256: `52f718755a8e0072e193a27127e7dec884195271b01d6ddb248e7d284cc09383`.
- Launcher: `scripts/install-approved-a7dev-v10.py`.
- Launcher SHA256: `374a1c774f8be7a060e3064c0f9748ee11d3262c39e676bb4b1ca6c0ea77792d`.
- Build report: `/tmp/agentporter-development-candidate-v10-review.json`.

Parent comparison confirms v9/v10 source digests, toolkit digest, eight-root
allowlist, manifest count and base archive pin match. Launcher diff contains
only fresh version/archive pins, v10 labels and the wrapper access correction.
**Unit test:** 70 focused tests passed against the finalized launcher.

The broad gate must run outside the sandbox: sandbox /tmp appears owned by
nobody and intentionally fails trusted-ancestor checks. A synthetic toolkit
fixture also previously included live /tmp directory timestamps in its model
of immutable deployment ancestors, causing concurrent host writes to trigger
fail-closed validation. The fixture now stabilizes only synthetic ancestor
directory size/timestamps; actual file revisions and toolkit metadata remain
real. No application cache validation was weakened.

**Unit test / executed locally:** the final host-only full gate passed with
1,247 tests and 24 subtests, followed by all six standalone offline verification
scripts. The only warning is the existing Starlette/AnyIO BlockingPortal alias
deprecation. Evidence: `/tmp/agentporter-prof-pickup-v10-host-verification.log`.
No v10 deployment or provider dispatch was executed while preparing this change.
