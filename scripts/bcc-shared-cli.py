#!/usr/bin/env python3
"""Stage, verify and atomically select BCC's shared, account-free CLI code.

Preparation runs as the owner. Installation runs only from the installed,
root-owned copy. No provider program or package lifecycle script runs as root.
Native account homes are deliberately outside this code store.
"""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import tempfile

ROOT = Path('/opt/agent-clis')
OWNER = 2056259175
TARGET = 'x86_64-unknown-linux-musl'
NVM = Path('/home/yeli/.nvm/versions/node/v22.23.0')
PACKAGES = {'codex':'@openai/codex', 'claude':'@anthropic-ai/claude-code',
            'copilot':'@github/copilot', 'opencode':'opencode-ai'}
DISABLE = {'DISABLE_AUTOUPDATER':'1', 'COPILOT_AUTO_UPDATE':'false',
           'OPENCODE_DISABLE_AUTOUPDATE':'true', 'AGY_CLI_DISABLE_AUTO_UPDATE':'true'}


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def run(argv, **kwargs):
    return subprocess.run([str(a) for a in argv], check=True, timeout=600, **kwargs)


def inventory(root):
    files, links = {}, {}
    for directory, dirs, names in os.walk(root, followlinks=False):
        for name in dirs + names:
            path = Path(directory)/name
            relative = path.relative_to(root).as_posix()
            if relative == 'MANIFEST.json':
                continue
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode):
                target = path.resolve(strict=True)
                if not target.is_relative_to(root.resolve()):
                    raise PermissionError('Shared code contains an external link')
                links[relative] = os.readlink(path)
            elif stat.S_ISREG(info.st_mode):
                files[relative] = {'sha256':digest(path), 'size':info.st_size,
                                   'executable':bool(info.st_mode & 0o111)}
            elif not stat.S_ISDIR(info.st_mode):
                raise PermissionError('Shared code contains a special file')
    return files, links


def native_candidate(package, patterns):
    for pattern in patterns:
        candidates = sorted(package.glob(pattern))
        for candidate in candidates:
            if candidate.is_file() and not candidate.is_symlink():
                with candidate.open('rb') as stream:
                    if stream.read(4) == b'\x7fELF':
                        return candidate
    raise PermissionError('Required native package executable is absent')


def prepare(output, latest=False):
    assert os.getuid() == OWNER, 'Prepare as the BCC owner, never root'
    output = output.resolve()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    release = output/'release'
    release.mkdir()
    (release/'bin').mkdir()
    providers = {}
    with tempfile.TemporaryDirectory(prefix='bcc-cli-build-') as temporary:
        scratch = Path(temporary)
        for provider, name in PACKAGES.items():
            package = release/'node_modules'/name
            package.parent.mkdir(parents=True, exist_ok=True)
            if latest:
                prefix = scratch/provider
                run([NVM/'bin/node',NVM/'lib/node_modules/npm/bin/npm-cli.js',
                     'install','--global','--prefix',prefix,'--ignore-scripts',
                     '--no-audit','--no-fund',name+'@latest'], stdout=subprocess.DEVNULL)
                source = prefix/'lib/node_modules'/name
            elif provider == 'codex':
                source = scratch/'codex-main'
                source.mkdir()
                archive = Path('/tmp/bcc-shared-cli-npm-20261113/openai-codex-0.169.0.tgz')
                with tarfile.open(archive) as tar:
                    for member in tar.getmembers():
                        relative = Path(member.name)
                        if relative.parts[:1] != ('package',) or '..' in relative.parts or not (member.isfile() or member.isdir()):
                            raise PermissionError('Unexpected official npm archive member')
                    tar.extractall(source)
                source = source/'package'
            else:
                source = NVM/'lib/node_modules'/name
            shutil.copytree(source, package, symlinks=True)
            version = json.loads((package/'package.json').read_text())['version']
            if provider == 'codex':
                if latest:
                    installer = scratch/'install-codex.sh'
                    run(['/usr/bin/curl','--fail','--silent','--show-error','--location',
                         'https://chatgpt.com/codex/install.sh','--output',installer])
                    home = scratch/'codex-home'
                    env = {k:v for k,v in os.environ.items() if k in ('PATH','LANG','SSL_CERT_FILE','SSL_CERT_DIR')}
                    env.update(HOME=str(scratch),CODEX_HOME=str(home),CODEX_INSTALL_DIR=str(scratch/'codex-bin'),
                               CODEX_RELEASE=version,CODEX_NON_INTERACTIVE='true')
                    run(['/bin/sh',installer],env=env,stdout=subprocess.DEVNULL)
                    bundle = (home/'packages/standalone/current').resolve(strict=True)
                else:
                    bundle = Path('/home/yeli/.codex-prof/packages/app-server-daemon/current').resolve(strict=True)
                descriptor = json.loads((bundle/'codex-package.json').read_text())
                assert descriptor['version'] == version and descriptor['target'] == TARGET
                vendor = package/'vendor'/TARGET
                if vendor.exists():
                    shutil.rmtree(vendor)
                vendor.parent.mkdir(exist_ok=True)
                shutil.copytree(bundle,vendor,symlinks=True)
                # The genuine npm entrypoint supports this vendor fallback.
                # Retire its duplicate optional native package after importing
                # the complete official bundle, including exec-server.
                optional = package/'node_modules/@openai'
                if optional.exists():
                    shutil.rmtree(optional)
                binary = vendor/'bin/codex'
                providers[provider] = {'version':version,'package_root':str(package.relative_to(release)),
                    'binary':str(binary.relative_to(release)),'bundle':str(vendor.relative_to(release)),
                    'helper':str((vendor/'bin/codex-code-mode-host').relative_to(release)),
                    'provenance':'official npm entrypoint and complete official native bundle'}
            else:
                patterns = {'claude':['bin/claude.exe','node_modules/@anthropic-ai/claude-code-linux-x64/claude'],
                    'copilot':['node_modules/@github/copilot-linux-x64/copilot'],
                    'opencode':['bin/opencode.exe','node_modules/opencode-linux-x64/bin/opencode']}
                binary = native_candidate(package,patterns[provider])
                providers[provider] = {'version':version,'package_root':str(package.relative_to(release)),
                    'binary':str(binary.relative_to(release)),'provenance':'official npm package'}
        agy = release/'native/agy/agy'
        agy.parent.mkdir(parents=True)
        source = ROOT/'current/native/agy/agy' if (ROOT/'current').exists() else Path('/home/yeli/.local/bin/agy')
        shutil.copy2(source,agy)
        if latest:
            isolated = scratch/'agy-home'
            isolated.mkdir()
            env = {'HOME':str(isolated),'PATH':'/usr/bin:/bin','LANG':'C.UTF-8',
                   'ANTIGRAVITY_APP_DATA_DIR':str(isolated/'data'),**DISABLE}
            run([agy,'update'],env=env,cwd=isolated,stdout=subprocess.DEVNULL)
        result=run([agy,'--version'],env={**os.environ,**DISABLE},capture_output=True,text=True)
        match=re.search(r'\b(\d+\.\d+\.\d+)\b',result.stdout)
        assert match, 'Agy did not return a version'
        providers['agy']={'version':match[1],'package_root':'native/agy','binary':'native/agy/agy',
                          'provenance':'existing native CLI; vendor self-update in isolated staging for updates'}
    for provider,row in providers.items():
        (release/'bin'/provider).symlink_to('../'+row['binary'])
        # Exercise exactly the selected executable, without authentication or a turn.
        result=run([release/row['binary'],'--version'],env={**os.environ,**DISABLE},capture_output=True,text=True)
        assert row['version'] in result.stdout, (provider,'version mismatch')
    # This SDK is extracted by the same native Copilot executable on --version.
    # Keep the version-matched, credential-free SDK with its shared code instead
    # of maintaining a second Qman CLI installation.
    copilot=providers['copilot']
    sdk_source=Path.home()/'.cache/copilot/pkg/linux-x64'/copilot['version']/'copilot-sdk'
    assert (sdk_source/'index.js').is_file(), 'Matching bundled Copilot SDK was not extracted'
    sdk_target=release/copilot['package_root']/'runtime-sdk/copilot-sdk'
    sdk_target.parent.mkdir(parents=True)
    shutil.copytree(sdk_source,sdk_target,symlinks=True)
    copilot['sdk']=str((sdk_target/'index.js').relative_to(release))
    files,links=inventory(release)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+secrets.token_hex(4)
    manifest={'schema':1,'release':stamp,'providers':providers,'files':files,'links':links,
              'account_data_included':False,'automatic_provider_updates':False}
    (release/'MANIFEST.json').write_text(json.dumps(manifest,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'stage':str(release),'manifest_sha256':digest(release/'MANIFEST.json'),
                      'providers':{k:v['version'] for k,v in providers.items()}}))


def install(source,expected):
    assert os.getuid()==0, 'Selection requires machine administrator access'
    assert Path(__file__).resolve()==Path('/usr/local/libexec/bcc-shared-cli.py'), 'Use the installed controller'
    source=source.resolve(strict=True)
    assert source.is_relative_to(Path('/home/yeli/.cache/bcc-shared-cli-staging'))
    assert source.stat().st_uid==OWNER and not source.stat().st_mode&0o022
    manifest_path=source/'MANIFEST.json'
    assert manifest_path.stat().st_size<8*1024**2 and digest(manifest_path)==expected
    manifest=json.loads(manifest_path.read_text())
    assert manifest['schema']==1 and manifest['account_data_included'] is False
    assert set(manifest['providers'])=={*PACKAGES,'agy'}
    assert re.fullmatch(r'\d{8}T\d{6}Z-[a-f0-9]{8}',manifest['release'])
    assert inventory(source)==(manifest['files'],manifest['links'])
    for row in manifest['providers'].values():
        p=Path(row['binary'])
        assert not p.is_absolute() and '..' not in p.parts and p.as_posix() in manifest['files']
    ROOT.mkdir(mode=0o755,exist_ok=True)
    (ROOT/'releases').mkdir(mode=0o755,exist_ok=True)
    lock=os.open('/run/lock/bcc-shared-cli.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    with os.fdopen(lock,'w') as handle:
        fcntl.flock(handle,fcntl.LOCK_EX)
        destination=ROOT/'releases'/manifest['release']
        assert not destination.exists()
        shutil.copytree(source,destination,symlinks=True)
        assert inventory(destination)==(manifest['files'],manifest['links'])
        # Identical code retains one physical inode across selections. This
        # also preserves running same-version native daemon/helper identities.
        existing={}
        if (ROOT/'current').is_symlink():
            previous=(ROOT/'current').resolve(strict=True)
            old=json.loads((previous/'MANIFEST.json').read_text())
            for relative,row in old['files'].items():
                path=previous/relative
                info=path.lstat()
                if (stat.S_ISREG(info.st_mode) and info.st_uid==0 and not info.st_mode&0o022
                        and digest(path)==row['sha256']):
                    existing[(row['sha256'],row['size'],row['executable'])]=path
        for relative,row in manifest['files'].items():
            path=destination/relative
            key=(row['sha256'],row['size'],row['executable'])
            if key in existing:
                path.unlink();os.link(existing[key],path)
            else:
                existing[key]=path
        for directory,dirs,names in os.walk(destination,topdown=False,followlinks=False):
            for name in names:
                path=Path(directory)/name
                if not path.is_symlink():
                    os.chown(path,0,0);path.chmod(0o555 if path.stat().st_mode&0o111 else 0o444)
            os.chown(directory,0,0);Path(directory).chmod(0o555)
        before=os.readlink(ROOT/'current') if (ROOT/'current').is_symlink() else None
        if before:
            pending=ROOT/('.previous-'+secrets.token_hex(4));pending.symlink_to(before);os.replace(pending,ROOT/'previous')
        pending=ROOT/('.current-'+secrets.token_hex(4));pending.symlink_to(destination);os.replace(pending,ROOT/'current')
        print(json.dumps({'selected':str(destination),'previous':before,'providers':{k:v['version'] for k,v in manifest['providers'].items()}}))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--prepare',type=Path)
    group.add_argument('--install',type=Path)
    group.add_argument('--status',action='store_true')
    parser.add_argument('--latest',action='store_true')
    parser.add_argument('--manifest-sha256')
    args=parser.parse_args()
    if args.prepare:
        prepare(args.prepare,args.latest)
    elif args.install:
        install(args.install,args.manifest_sha256)
    else:
        value=json.loads((ROOT/'current/MANIFEST.json').read_text())
        print(json.dumps({'selected':str((ROOT/'current').resolve()),'providers':{
            k:{'version':v['version'],'binary':str((ROOT/'current'/v['binary']).resolve())}
            for k,v in value['providers'].items()}},indent=2))


if __name__=='__main__':
    main()
