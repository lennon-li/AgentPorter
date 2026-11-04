"""Per-job runtime binding and fixed, standard-library worker Git client.

This file can be mounted alone into a worker and executed with Python -I -S.
It contains no signing authority. Protected workspace policy authorizes exact
scoped operations; requests remain bound to this live job and transaction.
"""
import json
import array
import secrets
import struct
import stat
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import time

CLIENT_PATH = '/opt/agentporter/worker-git.py'
CONTEXT_PATH = '/run/agentporter-git-context.json'
SOCKET_PATH = '/run/agentporter-git.sock'
BOOTSTRAP_PATH = '/run/agentporter-git-bootstrap.sock'


def _client_main():
    context = json.loads(Path(CONTEXT_PATH).read_bytes())
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536:
        raise ValueError('Worker Git request too large')
    data = json.loads(raw)
    clone=data.get('op') in {'clone_prepare','clone','wait_clone'} if isinstance(data,dict) else False
    fields={'op','remote','ref','branch'} if clone else {'op','remote','ref'} if isinstance(data,dict) and data.get('op')=='fetch' else {'op','remote','ref','mode'}
    if not isinstance(data, dict) or data.get('op') not in {'prepare','pull','push','wait','clone_prepare','clone','wait_clone','fetch'}:
        raise ValueError('Invalid worker Git operation')
    if data['op'] in {'pull','clone'}:
        fields |= {'request_sha256','approval_receipt'} & set(data)
    if data['op'] in {'wait','wait_clone'}:
        fields |= {'request_sha256'}
    if 'repository' in data:
        fields.add('repository')
        if data['repository'] not in context.get('allowed_repositories',[context['identity']['repository']]):
            raise ValueError('Repository is outside the server-issued catalog')
    if set(data) != fields:
        raise ValueError('Only exact worker Git operation fields are accepted')
    payload = {**context['identity'], **data, 'version': 1}
    body = json.dumps(payload, sort_keys=True, allow_nan=False).encode()
    if len(body) > 65536:
        raise ValueError('Worker Git request too large')
    def receive(connection, size):
        result = bytearray()
        while len(result) < size:
            chunk = connection.recv(size - len(result))
            if not chunk:
                raise EOFError('Incomplete worker Git reply')
            result.extend(chunk)
        return bytes(result)
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(300)
        connection.connect(SOCKET_PATH)
        connection.sendall(struct.pack('>I', len(body)) + body)
        size, = struct.unpack('>I', receive(connection, 4))
        if size > 1048576:
            raise ValueError('Worker Git reply too large')
        response = json.loads(receive(connection, size))
    print(json.dumps(response, sort_keys=True))


def _bootstrap_main():
    """Only the release-owned bootstrap executes this before provider code."""
    context=json.loads(Path(CONTEXT_PATH).read_bytes())
    descriptor=os.open('/workspace',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
    namespaces=[os.open('/proc/self/ns/user',os.O_RDONLY|os.O_CLOEXEC),
                os.open('/proc/self/ns/mnt',os.O_RDONLY|os.O_CLOEXEC),
                os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)]
    try:
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as channel:
            channel.settimeout(15);channel.connect(BOOTSTRAP_PATH)
            message=json.dumps({'version':1,'job_id':context['identity']['job_id'],
                                'token':context['bootstrap_token']}).encode()
            channel.sendmsg([message],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[descriptor,*namespaces]))])
            if channel.recv(1)!=b'1':raise PermissionError('Trusted workspace bootstrap was refused')
    finally:
        os.close(descriptor)
        for fd in namespaces:os.close(fd)
    for item in os.listdir('/proc/self/fd'):
        number=int(item)
        if number>2:
            try:os.close(number)
            except OSError:pass
    os.execvpe(sys.argv[2],sys.argv[2:],os.environ)


class WorkerGitService:
    """Own a single socket and reuse only this live job's held transaction."""
    def __init__(self, backend, manager, job_id, agent, workspace_id, *, expires_at):
        from agentporter.worker_git_rpc import WorkerGitRPC, WorkerGitGrant, MODES
        from agentporter.worker_git_transport import WorkerGitSocket
        self.backend, self.manager = backend, manager
        self.job_id, self.agent, self.workspace_id = job_id, agent, workspace_id
        self._operation = threading.Lock()
        self._closed = False
        self._adapter = None
        self._clone_adapter=None
        self._fetch_adapter=None
        self._bootstrap_token=secrets.token_hex(32)
        self._bootstrap_ready=threading.Event()
        self._bootstrap_error=None
        self.bootstrap_path=None
        self._bootstrap_listener=None
        self._bootstrap_channel=None
        self._bootstrap_thread=None
        workspace = backend.registry.get(workspace_id)
        catalog={};clone_catalog={};fetch_catalog={}
        for grant in backend.authority.catalog():
            if grant.workspace_id!=workspace_id:continue
            if 'pull' in grant.operations:
                catalog.setdefault(grant.repository_relative,set()).update((grant.remote_id,grant.ref,mode) for mode in MODES)
            if 'fetch' in grant.operations:
                fetch_catalog.setdefault(grant.repository_relative,set()).add((grant.remote_id,grant.ref))
            if 'clone' in grant.operations:
                clone_catalog.setdefault(grant.repository_relative,set()).add((grant.remote_id,grant.ref))
        repositories=set(catalog)|set(clone_catalog)|set(fetch_catalog)
        if not repositories or not workspace.writable or not workspace.allow_git:
            raise PermissionError('No owner-approved worker Git scope')
        self._repository_catalog={relative:frozenset(catalog.get(relative,())) for relative in repositories}
        self._clone_catalog={relative:frozenset(clone_catalog.get(relative,())) for relative in repositories}
        self._fetch_catalog={relative:frozenset(fetch_catalog.get(relative,())) for relative in repositories}
        self.directory = manager.state_dir / 'worker-git' / job_id
        self.directory.mkdir(parents=True, mode=0o700)
        os.chmod(self.directory.parent, 0o700)
        self.context_path = self.directory / 'context.json'
        self.repository='.' if '.' in repositories else sorted(repositories)[0]
        identity = {'job_id': job_id, 'agent': agent, 'workspace_id': workspace_id,
                    'repository': self.repository}
        fd = os.open(self.context_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        with os.fdopen(fd, 'w') as output:
            json.dump({'identity': identity, 'allowed': sorted(self._repository_catalog[self.repository]),'allowed_repositories':sorted(repositories),'repositories':{relative:{'pull':sorted(self._repository_catalog[relative]),'clone':sorted(self._clone_catalog[relative]),'fetch':sorted(self._fetch_catalog[relative])} for relative in sorted(repositories)},'bootstrap_token':self._bootstrap_token}, output)
        self.client_path = Path(__file__).resolve()
        self.rpc = WorkerGitRPC(self, self._is_live)
        grants={relative:WorkerGitGrant(job_id,agent,workspace_id,relative,
            str(Path(workspace.path).resolve()/relative),frozenset({'read','write'}),allowed,expires_at,clone_allowed=self._clone_catalog[relative],fetch_allowed=self._fetch_catalog[relative])
            for relative,allowed in self._repository_catalog.items()}
        from dataclasses import replace
        primary=replace(grants[self.repository],alternates=tuple(grant for relative,grant in grants.items() if relative!=self.repository))
        self.rpc.issue_grant(primary)
        self.transport = WorkerGitSocket(self.rpc, job_id, str(self.directory)).start()
        self.bootstrap_path=self.directory/'bootstrap.sock'
        parent=os.open(self.directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            listener=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
            listener.bind(f'/proc/self/fd/{parent}/bootstrap.sock');listener.listen(1);listener.settimeout(.25)
            os.chmod(self.bootstrap_path,0o600)
            self._bootstrap_listener=listener
        finally:os.close(parent)
        self._bootstrap_thread=threading.Thread(target=self._receive_runtime_view,daemon=True)
        self._bootstrap_thread.start()

    def _receive_runtime_view(self):
        descriptors=[];channel=None
        try:
            deadline=time.monotonic()+30
            while not self._closed:
                try:
                    channel,_=self._bootstrap_listener.accept();self._bootstrap_channel=channel;break
                except socket.timeout:
                    if time.monotonic()>deadline:raise TimeoutError('Workspace bootstrap did not arrive')
            if channel is None:return
            channel.settimeout(5)
            peer=channel.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12)
            if struct.unpack('3i',peer)[1]!=os.geteuid():raise PermissionError('Workspace bootstrap peer identity differs')
            raw,ancillary,flags,_=channel.recvmsg(1024,socket.CMSG_SPACE(16))
            for level,kind,data in ancillary:
                if level!=socket.SOL_SOCKET or kind!=socket.SCM_RIGHTS:raise PermissionError('Unexpected workspace bootstrap capability')
                values=array.array('i');values.frombytes(data[:len(data)-len(data)%values.itemsize]);descriptors.extend(values)
            if flags or len(descriptors)!=4:raise PermissionError('Workspace bootstrap requires exactly one capability')
            from agentporter.worker_git_rpc import _strict
            message=_strict(raw,1024)
            if message!={'version':1,'job_id':self.job_id,'token':self._bootstrap_token}:
                raise PermissionError('Workspace bootstrap is not bound to this job')
            # Close ingress before ACK/exec. Untrusted provider code cannot send
            # a second capability or impersonate its predecessor bootstrap.
            self._bootstrap_listener.close()
            with self._operation:
                if self._closed or not self._is_live(self.job_id,self.agent,self.workspace_id):
                    raise PermissionError('Workspace bootstrap job is not live')
                with self.manager.lock:
                    process=self.manager.active_processes.get(self.job_id)
                    transaction=self.manager._job_transactions.get(self.job_id)
                if process is None or process.poll() is not None or transaction is None:
                    raise PermissionError('Workspace bootstrap lost owned process/transaction')
                peer_pid=struct.unpack('3i',peer)[0]
                ancestor=peer_pid
                for _ in range(64):
                    if ancestor==process.pid:break
                    status=Path(f'/proc/{ancestor}/status').read_text()
                    ancestor=int(next(line.split(':',1)[1] for line in status.splitlines() if line.startswith('PPid:')))
                    if ancestor<=1:raise PermissionError('Bootstrap is outside the owned job process tree')
                else:raise PermissionError('Bootstrap process ancestry exceeds bound')
                for descriptor,path in zip(descriptors[1:],('ns/user','ns/mnt','root')):
                    actual=os.stat(f'/proc/{peer_pid}/{path}')
                    pinned=os.fstat(descriptor)
                    if (actual.st_dev,actual.st_ino)!=(pinned.st_dev,pinned.st_ino):
                        raise PermissionError('Bootstrap namespace/root capability does not belong to its peer')
                actual=os.stat(f'/proc/{peer_pid}/root/workspace')
                pinned=os.fstat(descriptors[0])
                if (actual.st_dev,actual.st_ino)!=(pinned.st_dev,pinned.st_ino):
                    raise PermissionError('Bootstrap workspace capability does not belong to its peer')
                transaction._attach_runtime_view(descriptors[0],descriptors[1:])
                self._bootstrap_ready.set()
                channel.send(b'1')
        except Exception:
            self._bootstrap_error='Trusted workspace bootstrap unavailable'
        finally:
            for descriptor in descriptors:os.close(descriptor)
            if channel is not None:channel.close()
            self._bootstrap_channel=None
            if self._bootstrap_listener is not None:self._bootstrap_listener.close()


    @property
    def requires_receipt(self):
        return getattr(self.backend,'requires_receipt',True) is not False

    @property
    def host_path(self):
        return self.transport.host_path

    def _is_live(self, job_id, agent, workspace_id):
        if self._closed or (job_id, agent, workspace_id) != (self.job_id, self.agent, self.workspace_id):
            return False
        database = self.manager._get_db()
        try:
            row = database.execute('SELECT status,agent,workspace_id FROM jobs WHERE job_id=?', (job_id,)).fetchone()
        finally:
            database.close()
        # Launching allows the service-owned socket to bind before bwrap starts.
        # Backend dispatch below additionally requires running + owned process.
        return (row is not None and row['agent'] == agent and row['workspace_id'] == workspace_id
                and row['status'] in {'launching', 'running'})

    def _bound(self, workspace_id,repository=None):
        from agentporter.git_pulls import JobBoundGitPulls
        if workspace_id != self.workspace_id or self._closed or not self._bootstrap_ready.is_set() or self._bootstrap_error is not None:
            raise PermissionError('Worker Git job scope is unavailable')
        with self.manager.lock:
            process = self.manager.active_processes.get(self.job_id)
        if process is None or process.poll() is not None:
            raise PermissionError('Worker Git requires its currently owned live process')
        repository=self.repository if repository is None else repository
        if repository not in self._repository_catalog:raise PermissionError('Repository is outside the server catalog')
        if self._adapter is None:
            self._adapter = JobBoundGitPulls(self.backend,self.job_id,workspace_id,self.agent,repository=repository)
        elif self._adapter.repository!=repository:raise PermissionError('Job is already bound to another repository')
        return self._adapter

    def prepare(self, workspace_id, remote, ref, mode):
        with self._operation:
            return self._bound(workspace_id).prepare(remote, ref, mode)

    def pull(self, workspace_id, remote, ref, receipt, mode):
        with self._operation:
            return self._bound(workspace_id).pull(remote, ref, receipt, mode)

    def prepare_repository(self,workspace_id,repository,remote,ref,mode):
        with self._operation:return self._bound(workspace_id,repository).prepare(remote,ref,mode)

    def pull_repository(self,workspace_id,repository,remote,ref,receipt,mode):
        with self._operation:return self._bound(workspace_id,repository).pull(remote,ref,receipt,mode)

    def _bound_clone(self,workspace_id,repository):
        if (workspace_id!=self.workspace_id or repository not in self._clone_catalog
                or not self._clone_catalog[repository] or self._closed or not self._bootstrap_ready.is_set()
                or self._bootstrap_error is not None):raise PermissionError('Clone job scope is unavailable')
        backend=getattr(self.manager,'approved_git_clones',None)
        if backend is None:raise PermissionError('Authoritative clone backend is unavailable')
        if self._clone_adapter is None:
            self._clone_adapter=backend.bind_job(workspace_id,self.job_id,self.agent,repository=repository)
            self._clone_repository=repository
        elif self._clone_repository!=repository:raise PermissionError('Clone job is bound elsewhere')
        return self._clone_adapter

    def _bound_fetch(self,workspace_id,repository):
        if (workspace_id!=self.workspace_id or not self._fetch_catalog.get(repository)
                or self._closed or not self._bootstrap_ready.is_set() or self._bootstrap_error is not None):
            raise PermissionError('Fetch job scope is unavailable')
        backend=getattr(self.manager,'approved_git_fetches',None)
        if backend is None or getattr(backend,'requires_receipt',True) is not False:
            raise PermissionError('Workspace-authorized fetch backend is unavailable')
        if self._fetch_adapter is None:
            self._fetch_adapter=backend.bind_job(workspace_id,self.job_id,self.agent,repository=repository)
            self._fetch_repository=repository
        elif self._fetch_repository!=repository:raise PermissionError('Fetch job is bound elsewhere')
        return self._fetch_adapter

    def prepare_fetch_repository(self,workspace_id,repository,remote,ref):
        with self._operation:return self._bound_fetch(workspace_id,repository).prepare(remote,ref)

    def fetch_repository(self,workspace_id,repository,remote,ref,receipt):
        with self._operation:return self._bound_fetch(workspace_id,repository).fetch(remote,ref,receipt)

    def prepare_clone_repository(self,workspace_id,repository,remote,ref,branch):
        with self._operation:return self._bound_clone(workspace_id,repository).prepare(remote,ref,branch)

    def clone_repository(self,workspace_id,repository,remote,ref,branch,digest,receipt):
        with self._operation:
            # RPC's immutable prepared record binds remote/ref/local branch to
            # this digest; the typed backend rechecks its protected cache and
            # exact operation before consuming the receipt. Never re-prepare.
            return self._bound_clone(workspace_id,repository).execute(digest,receipt)

    def owner_request(self,workspace_id,remote,ref,mode,*,prepare_only,request_sha256='',approval_receipt='',operation='pull',local_branch=None,repository=None):
        if workspace_id != self.workspace_id or self._closed:
            raise PermissionError('Job is outside the selected worker workspace')
        payload = {'version':1,'job_id':self.job_id,'agent':self.agent,'workspace_id':workspace_id,
                   'repository':repository if repository is not None else self.rpc.selected_repository(self.job_id) or self.repository,'remote':remote,'ref':ref,'mode':mode,
                   'op':'prepare' if prepare_only else 'pull'}
        if operation=='clone':
            payload.pop('mode');payload['branch']=local_branch
            payload['op']='clone_prepare' if prepare_only else 'clone'
        elif operation!='pull':raise PermissionError('Unknown job Git operation')
        if not prepare_only:
            if request_sha256:payload['request_sha256']=request_sha256
            if approval_receipt or self.requires_receipt:payload['approval_receipt']=approval_receipt
        return self.rpc.channel(self.job_id).handle(json.dumps(payload))

    def close(self):
        # Revoke first, then drain any admitted backend operation. Transport.close
        # alone joins only briefly and therefore cannot prove backend quiescence.
        self._closed = True
        self.rpc.revoke(self.job_id)
        with self._operation:
            self.transport.close()
        if self._bootstrap_listener is not None:self._bootstrap_listener.close()
        channel=self._bootstrap_channel
        if channel is not None:
            try:channel.shutdown(socket.SHUT_RDWR)
            except OSError:pass
            channel.close()
        if self._bootstrap_thread is not None:
            self._bootstrap_thread.join(1)
            if self._bootstrap_thread.is_alive():
                from agentporter.resources import ResourceCleanupError
                raise ResourceCleanupError('Trusted workspace bootstrap cleanup remains unverified')


if __name__ == '__main__':
    if len(sys.argv)>1 and sys.argv[1]=='bootstrap':_bootstrap_main()
    else:_client_main()
