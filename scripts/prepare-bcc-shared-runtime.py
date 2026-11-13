#!/usr/bin/env python3
"""Freeze the small shared-CLI delta on the currently sealed BCC packages."""
import hashlib
import json
from pathlib import Path

REPO=Path('/home/yeli/repos/AgentPorter')
OUT=REPO/'artifacts/bcc-consolidation-20261112/shared-runtime-v06'
SITE=Path('venv/lib/python3.13/site-packages')


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def once(raw,before,after):
    assert raw.count(before)==1
    return raw.replace(before,after)


def main():
    OUT.mkdir(exist_ok=True)
    assert not any(OUT.iterdir()), 'Retain an existing nonempty candidate'
    manifest={'schema':1,'roles':{}}
    for role in ('gateway','worker'):
        root=Path('/opt/agentporter-bcc/releases/consolidation-20261113-05-'+role)
        files={}
        def save(relative,after):
            original=root/SITE/relative
            before=original.read_bytes() if original.exists() else None
            target=OUT/role/relative
            target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(after)
            files[relative]={'before_sha256':sha(before) if before is not None else None,'after_sha256':sha(after)}
        raw=(root/SITE/'agentporter/agents/development.py').read_bytes()
        marker=b'            if agent == "phil":\n'
        extra=(b'            # Use shared installed code without per-job self-updates.\n'
               b'            environment.update(DISABLE_AUTOUPDATER="1", COPILOT_AUTO_UPDATE="false",\n'
               b'                               OPENCODE_DISABLE_AUTOUPDATE="true", AGY_CLI_DISABLE_AUTO_UPDATE="true")\n')
        save('agentporter/agents/development.py',once(raw,marker,extra+marker))
        save('agentporter/shared_cli.py',(REPO/'src/agentporter/shared_cli.py').read_bytes())
        if role=='gateway':
            raw=(root/SITE/'qman/codex_collector.py').read_bytes()
            raw=once(raw,b'VERSION = "0.163.0"',b'VERSION = "shared"\nfrom agentporter.shared_cli import selected_codex')
            first=raw.index(b'def _binary(deadline=None):')
            last=raw.index(b'\n\n@contextmanager',first)
            replacement=b'''def _binary(deadline=None):
    global VERSION
    try:
        executable, VERSION = selected_codex(deadline=deadline)
        return executable
    except TimeoutError:
        raise CollectionError("timeout", "transport") from None
    except (OSError, ValueError, KeyError, TypeError):
        raise CollectionError("unsupported_binary") from None
'''
            raw=raw[:first]+replacement+raw[last:]
            raw=once(raw,b'"reviewed_cli_version": VERSION',b'"reviewed_cli_version": VERSION, "cli_selection": "root_managed_shared_manifest"')
            raw=once(raw,b'source="codex_app_server_0.163.0"',b'source="codex_app_server_"+VERSION')
            save('qman/codex_collector.py',raw)
            raw=(root/SITE/'qman/copilot_collector.py').read_bytes()
            raw=once(raw,b'VERSION = "1.0.103"',b'VERSION = "shared"\nfrom agentporter.shared_cli import selected_cli')
            first=raw.index(b'    # Keep Phil\'s identity guard')
            last=raw.index(b'    return env',first)
            raw=raw[:first]+b'''    # The identity guard remains native; its CLI is the machine selection.
    env["PATH"] = "/opt/agent-clis/current/bin:" + str(Path.home()/".local/bin") + os.pathsep + env.get("PATH",os.defpath)
'''+raw[last:]
            first=raw.index(b'def _find_sdk(')
            last=raw.index(b'\n\ndef _capture',first)
            raw=raw[:first]+b'''def _find_sdk(version=VERSION):
    try:
        sdk, selected = selected_cli("copilot",file_field="sdk",deadline=time.monotonic()+3)
        if selected != version:
            raise ValueError("native_copilot_version_failed")
        return sdk
    except (OSError,KeyError,TypeError):
        raise ValueError("native_copilot_unavailable") from None
'''+raw[last:]
            raw=once(raw,b'version=match[1].decode();sdk=_find_sdk(version)',b'''version=match[1].decode();sdk=_find_sdk(version)
    # Exact SDK/runtime version is checked by getStatus before account/quota.
    # Unsupported protocol or flags produce a classified unavailable response.
    flags=['--no-custom-instructions','--disable-builtin-mcps','--disable-client-telemetry','--sync-session=off']''')
            raw=once(raw,b'json.dumps(NATIVE_FLAGS[version])',b'json.dumps(flags)')
            save('qman/copilot_collector.py',raw)
        manifest['roles'][role]={'base_manifest_sha256':sha((root/'RELEASE.json').read_bytes()),'files':files}
    path=OUT/'MANIFEST.json'
    path.write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'candidate':str(OUT),'manifest_sha256':sha(path.read_bytes())}))


if __name__=='__main__':
    main()
