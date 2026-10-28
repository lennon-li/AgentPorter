# Development credential-sync repair — source candidate only

The confirmed failure is orchestration, not proof that host Ming authentication is broken. Parent inspected only source metadata: Jax route config is owner1000/mode0664, while Ming/Phil/Argie credential files are regular owner1000/mode0600. Original apply code validates the never-refreshed Codex route before its explicit skip, so unrelated Jax metadata rejection aborts the entire timer batch before Ming.

This candidate skips unpublished route configuration before opening/validating it on --apply, retains all checks on --check and --routes, contains a profile failure so later independent identities can proceed, reports fixed profile/stage/reason codes without exception text, and preserves an overall nonzero result if any profile fails. Missing auth sources are explicitly failures. Strict source/destination UID/mode/inode/path checks and atomic publish are unchanged. No authentication renewal or login is added.

Only synthetic fixture credential bytes were used. The installed root-private helper could not be read/hash-matched by the worker; equivalence to the reference script is NOT independently established. The reference source baseline and candidate hashes are in manifest.json. No installed helper, service, credentials, permission, account or routing setting was changed.

Existing scoped operator action (no helper upgrade needed) avoids unrelated Jax entirely:

```
sudo /usr/bin/python3 -I /usr/local/libexec/agentporter/refresh-development-worker-credentials.py --apply --agents ming,phil,argie
```

This must be run only by the authorized operator after approving scoped synchronization. It consumes the existing canonical per-profile credentials through the trusted installed helper; it does not log in or grant scopes. No service restart is required. The agent did not execute this command.

Tests: 10 pytest fixtures passed; copied existing offline owner/mode/atomicity/symlink/path-swap security checks passed. Reproducer reconstructs the frozen original source only with synthetic stores and demonstrates mode0664 Jax route prevents Ming update; fixed apply updates all valid auth identities while leaving route bytes/mode unchanged. --check and explicit --routes still reject writable route metadata.
