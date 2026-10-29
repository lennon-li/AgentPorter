#!/usr/bin/python3
"""Owner-authorized v19 workspace access restoration; service UID only.

No release, credential, registry, network, production, or account changes.
Public project execution stays inside offline Bubblewrap/resource envelopes.
Obsidian, production-source roots and their umbrella stay read-only.
"""
import argparse,hashlib,json,os,pwd,secrets,sqlite3,stat
from pathlib import Path
import yaml
EXPECTED_ROOTS = {'m3-poc': '/home/yeli/m3-agent-poc', 'insider': '/home/yeli/repos/insider', 'PAGe': '/home/yeli/repos/PAGe', 'm3': '/home/yeli/repos/m3', 'obsidian': '/home/yeli/repos/obsidian', 'shiny': '/home/yeli/repos/shiny', 'cranary': '/home/yeli/repos/cranary', 'agentporter-dev': '/home/yeli/agent-work/agentporter-dev', 'agentporter': '/home/yeli/repos/AgentPorter', 'repos': '/home/yeli/repos', 'asgard-hermes-review': '/home/yeli/repos/AgentPorter/runtime/asgard-hermes-exposure', 'opcc': '/home/yeli/repos/opcc', 'RangeAhead': '/home/yeli/repos/RangeAhead', 'HMA': '/home/yeli/repos/HMA', 'dataganger': '/home/yeli/repos/dataganger', 'epiweave': '/home/yeli/repos/epiweave', 'ALL': '/home/yeli/repos/ALL', 'careDX': '/home/yeli/repos/careDX', 'cranary-jax-wt': '/home/yeli/repos/cranary-jax-wt', 'scinet-home': '/home/yeli/repos/scinet-home', 'clientAgent': '/home/yeli/repos/clientAgent', 'courieR': '/home/yeli/repos/courieR', 'hermes-jev-acceptance-20261018': '/home/yeli/repos/hermes-jev-acceptance-20261018', 'node-which': '/home/yeli/repos/node-which', 'IRVRI': '/home/yeli/repos/IRVRI', 'dogfooding': '/home/yeli/repos/dogfooding', 'ONgeoR': '/home/yeli/repos/ONgeoR', 'covid-positivity-forecasting': '/home/yeli/repos/covid-positivity-forecasting', 'gambling': '/home/yeli/repos/gambling', 'which': '/home/yeli/repos/which', 'legionella': '/home/yeli/repos/legionella', 'IPD': '/home/yeli/repos/IPD', 'hermes-jev-bcc-package-20261018': '/home/yeli/repos/hermes-jev-bcc-package-20261018', 'Qman': '/home/yeli/repos/Qman', 'biostats.ai': '/home/yeli/repos/biostats.ai', 'preview-jqtrwy87': '/home/yeli/repos/preview-jqtrwy87', 'ONgeoRapp': '/home/yeli/repos/ONgeoRapp', 'AgentPorter': '/home/yeli/repos/AgentPorter', 'agent-web-search': '/home/yeli/repos/agent-web-search', 'IRVRI.Rcheck': '/home/yeli/repos/shiny/IRVRI.Rcheck', 'compliance': '/home/yeli/repos/shiny/compliance', 'EasyMaps': '/home/yeli/repos/shiny/EasyMaps', 'EasyMap2.1': '/home/yeli/repos/shiny/EasyMap2.1', 'CTLOD.Rcheck': '/home/yeli/repos/shiny/CTLOD.Rcheck', 'CTLOD': '/home/yeli/repos/shiny/CTLOD', 'CUSUM': '/home/yeli/repos/shiny/CUSUM'}
CONFIG=Path('/var/lib/agentporter-dev/config')
STATE=Path('/var/lib/agentporter-dev/state')
POLICY='public-client-policy.yaml'
BACKUP='public-client-policy.before-workspace-restore.yaml'
OLD='c96097f5ecac13a4186fe2b0e8f0294a33cab054c9f4dde7439decec261e3210'

def transformed(rows):
    roots={k:os.path.realpath(v['path']) for k,v in rows.items()}
    assert roots==EXPECTED_ROOTS, 'Registry changed: stop and reconcile exact roots'
    assert rows['IRVRI'].get('allow_execute',True), 'IRVRI registry execution disabled'
    protected=[Path('/home/yeli/repos/AgentPorter').resolve(),Path('/home/yeli/repos/obsidian').resolve(),Path('/home/yeli/obsidian').resolve()]
    result={}
    for name in EXPECTED_ROOTS:
        row=rows[name]
        path=Path(roots[name])
        assert path.is_absolute() and (path==Path('/home/yeli/repos') or path.is_relative_to('/home/yeli/repos') or path in (Path('/home/yeli/m3-agent-poc'),Path('/home/yeli/agent-work/agentporter-dev')))
        restricted=any(path==p or path.is_relative_to(p) or p.is_relative_to(path) for p in protected)
        operations=['read']
        if row.get('allow_git',True):operations.append('git_read')
        if not restricted:
            if row.get('writable',True):operations.append('write')
            if row.get('allow_execute',True):operations.append('exec')
        if name in ('cranary','agentporter-dev'):operations.append('dispatch')
        if name=='cranary':operations.append('https')
        result[name]={'path':str(path),'operations':operations}
    return {'version':1,'workspaces':result}

def private_read(name,uid):
    fd=os.open(CONFIG/name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    try:
        s=os.fstat(fd);assert stat.S_ISREG(s.st_mode) and s.st_uid==uid and not s.st_mode&0o077 and s.st_nlink==1 and s.st_size<=1024**2
        body=os.read(fd,1024**2+1);assert len(body)<=1024**2;return body
    finally:os.close(fd)

def publish(name,body,exclusive=False):
    if exclusive:
        fd=os.open(CONFIG/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        try:
            with os.fdopen(fd,'wb',closefd=False) as f:f.write(body);f.flush();os.fsync(fd)
        finally:os.close(fd)
        return
    temporary='.workspace-policy-'+secrets.token_hex(12)
    publish(temporary,body,True)
    try:os.replace(CONFIG/temporary,CONFIG/name)
    finally:(CONFIG/temporary).unlink(missing_ok=True)
    fd=os.open(CONFIG,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--apply',action='store_true');parser.add_argument('--rollback',action='store_true');args=parser.parse_args();assert not(args.apply and args.rollback)
    uid=pwd.getpwnam('agentporter-dev').pw_uid;assert os.geteuid()==uid and uid!=0
    s=CONFIG.lstat();assert stat.S_ISDIR(s.st_mode) and s.st_uid==uid and not s.st_mode&0o077
    rows=yaml.safe_load(private_read('workspaces.yaml',uid))['workspaces']
    proposal=transformed(rows);new=yaml.safe_dump(proposal,sort_keys=False).encode();newsha=hashlib.sha256(new).hexdigest()
    assert newsha=='97fbbeb9abfb896f4022647218dbc77f80fbfa2bbb3bfea25101756dd4b92043','Registry permissions differ from reviewed proposal: stop'
    current=private_read(POLICY,uid);current_sha=hashlib.sha256(current).hexdigest()
    if args.rollback:
        if current_sha==OLD:print(json.dumps({'restored':True,'already_original':True}));return
        assert current_sha==newsha,'Unexpected policy: refuse rollback'
        previous=private_read(BACKUP,uid);assert hashlib.sha256(previous).hexdigest()==OLD
        publish(POLICY,previous);print(json.dumps({'restored':True,'sha256':OLD}));return
    assert current_sha==OLD,'Unexpected current policy: stop'
    with sqlite3.connect('file:'+str(STATE/'jobs.db')+'?mode=ro',uri=True) as db:
        assert db.execute("SELECT count(*) FROM jobs WHERE status IN ('running','cancelling','queued','cleanup_failed')").fetchone()[0]==0,'Active/unresolved jobs; wait without stopping work'
        tables={r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if 'job_admissions' in tables:assert db.execute('SELECT count(*) FROM job_admissions').fetchone()[0]==0,'Unresolved admissions'
    if args.apply:
        assert not Path('/sys/fs/cgroup/system.slice/agentporter-development.service').exists(),'Stop A7Dev after quiet preflight before applying'
        publish(BACKUP,current,True);publish(POLICY,new)
    readonly=[k for k,v in proposal['workspaces'].items() if 'exec' not in v['operations']]
    print(json.dumps({'applied':args.apply,'workspaces':len(rows),'IRVRI':proposal['workspaces']['IRVRI'],'read_only_workspaces':readonly,'https_workspaces':['cranary'],'generic_shell_network':False,'sha256':newsha,'backup':str(CONFIG/BACKUP),'production_changed':False}))
if __name__=='__main__':main()
