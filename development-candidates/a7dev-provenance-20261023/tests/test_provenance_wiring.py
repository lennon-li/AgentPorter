"""Offline per-job callback storage and byte-preserving existing relay test."""
import importlib.util
import json
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[1]
ACTIVE=Path('/opt/agentporter-development/current/src')
# Dependencies remain the exact active development implementation; only owned
# overlay modules are loaded. No gateway/runtime/credential configuration opens.
sys.path.insert(0,str(ACTIVE))
import agentporter
agentporter.__path__.insert(0,str(ACTIVE / "agentporter"))

def load(name,path):
    spec=importlib.util.spec_from_file_location(name,path)
    m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m)
    return m

p=load('agentporter.provenance',ROOT/'src/agentporter/provenance.py')
egress=load('agentporter.agents.development_egress',ROOT/'src/agentporter/agents/development_egress.py')
jobs=load('candidate_jobs',ROOT/'src/agentporter/tools/jobs.py')


def wire(model):
    body=b'data: '+json.dumps({'type':'response.completed','response':{'status':'completed','model':model}}).encode()+b'\n\n'
    return b'HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: '+str(len(body)).encode()+b'\r\n\r\n'+body


def test_existing_headroom_relay_preserves_bytes_and_records_evidence():
    relayclient,client=socket.socketpair(); relayupstream,server=socket.socketpair()
    evidence=p.ProviderModelEvidence(); observer=evidence.response(); stop=threading.Event()
    thread=threading.Thread(target=egress._headroom_response,args=(relayclient,relayupstream,stop,observer))
    thread.start()
    try:
        expected=wire('upstream-model')
        server.sendall(expected);server.shutdown(socket.SHUT_WR)
        client.settimeout(2)
        actual=bytearray()
        while len(actual)<len(expected):actual.extend(client.recv(4096))
        thread.join(timeout=2)
        assert not thread.is_alive()
        assert bytes(actual)==expected
        assert evidence.actual_model()=='upstream-model'
    finally:
        stop.set()
        for s in (relayclient,client,relayupstream,server):s.close()
        thread.join(timeout=2)


def test_actual_job_monitor_stores_only_own_provider_evidence(tmp_path):
    manager=jobs.JobManager(tmp_path/'state')
    for index,reported in enumerate(('reported-other-model',None)):
        job_id=f'job_fixture_{index}'
        evidence=p.ProviderModelEvidence()
        if reported:
            observer=evidence.response();observer.feed(wire(reported));observer.finish()
        stdout_path=str(tmp_path/f'{index}.stdout');stderr_path=str(tmp_path/f'{index}.stderr')
        stdout=manager._open_private_log(stdout_path);stderr=manager._open_private_log(stderr_path)
        # Final provider launch replaced only by a local non-network print fixture.
        proc=manager._popen([sys.executable,'-c','print(\'{"model":"spoofed-worker-model"}\')'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,process_group=0)
        with manager._get_db() as db:
            db.execute('INSERT INTO jobs(job_id,status,started_at,agent,model,requested_model) VALUES(?,?,?,?,?,?)',
                       (job_id,'running',time.time(),'jax','configured-model','requested-model'))
        manager._job_model_evidence[job_id]=evidence
        manager.active_processes[job_id]=proc
        manager._monitor_proc(job_id,proc,stdout,stderr,stdout_path,stderr_path,3,time.time())
        status=manager.get_status(job_id)
        assert status['status']=='completed' and status['exit_code']==0
        assert status['actual_model']==(reported or 'unknown')
        assert status['configured_model']=='configured-model'
        assert status['requested_model']=='requested-model'
        assert job_id not in manager._job_model_evidence


def test_prepared_launch_receipt_attaches_host_observer_without_worker_file():
    text=(ROOT/'src/agentporter/agents/development.py').read_text()
    assert 'return PreparedLaunch(args, cleanup, tuple(descriptors), model_evidence)' in text
    assert text.count('model_evidence=model_evidence')==2
    assert 'model_evidence' not in '\n'.join(line for line in text.splitlines() if '--setenv' in line or '--ro-bind' in line)
    text=(ROOT/'src/agentporter/tools/jobs.py').read_text()
    assert 'self._job_model_evidence[job_id] = getattr(prepared, "model_evidence", None)' in text
    assert 'extract_actual_model(stdout_path, stderr_path, evidence=model_evidence)' in text
