#!/usr/bin/env bash
# Credential-only transient unit; does not change gateway/config/ACLs.
set -euo pipefail
exec sudo /usr/bin/systemd-run --wait --pipe --collect \
  --unit=agentporter-dev-credential-probe \
  -p User=root -p Group=root -p ProtectSystem=strict \
  -p ProtectHome=read-only -p PrivateTmp=true -p PrivateDevices=true \
  -p ProtectKernelTunables=true -p ProtectKernelModules=true \
  -p ProtectKernelLogs=true -p ProtectControlGroups=true \
  -p ProtectClock=true -p ProtectHostname=true \
  '-pRestrictAddressFamilies=AF_UNIX AF_INET' \
  -p IPAddressDeny=any -p IPAddressAllow=127.0.0.1/32 \
  -p NoNewPrivileges=true -p LockPersonality=true \
  -p RestrictRealtime=true -p RestrictSUIDSGID=true \
  -p AmbientCapabilities=CAP_SETUID \
  '-pCapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_FOWNER CAP_CHOWN CAP_SETUID CAP_SETGID CAP_KILL' \
  /usr/bin/python3 -I -c '
import os, pwd, subprocess, sys
a = pwd.getpwnam("agentporter-dev")
for line in open("/proc/self/status"):
    if line.startswith(("Cap", "NoNewPrivs", "Seccomp")):
        print(line.strip(), flush=True)
print("subprocess credential launch", flush=True)
try:
    p = subprocess.run(["/usr/bin/python3", "-I", "-c", "import os; print(os.getuid(), os.getgid(), os.getgroups())"], user=a.pw_uid, group=a.pw_gid, extra_groups=[], check=True)
except Exception as e:
    print(type(e).__name__, str(e), flush=True)
for name, args in (("setgroups", ([],)), ("setregid", (a.pw_gid, a.pw_gid)), ("setreuid", (a.pw_uid, a.pw_uid))):
    print("trying", name, flush=True)
    try:
        getattr(os, name)(*args)
    except OSError as e:
        print(name, "FAILED", repr(e), flush=True)
        sys.exit(1)
    print(name, "OK", flush=True)
print("credential probe complete", flush=True)
'
