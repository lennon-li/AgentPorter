"""Concurrent protected-owner SQL changes cannot be overwritten by clone recovery."""
import os,sqlite3
from pathlib import Path
import pytest
from agentporter.git_approvals import GitApprovalRequest
import agentporter.git_clone_recovery as recovery

@pytest.fixture
def binding(tmp_path):
 state=tmp_path;transaction=state/'transaction';guard=state/'guard';job='job_'+'a'*24;token='b'*32
 request=GitApprovalRequest.from_payload({'operation':'clone','workspace_id':'repo','repository_path':'/fixture','repository_device':1,'repository_inode':2,'expected_head':None,'expected_tree':'4b825dc642cb6eb9a060e54bf8d69288fbee4904','branch':'refs/heads/main','parameters':{'job_context':{'job_id':job,'agent':'codex_impl','admission_token':token}}})
 path=state/'jobs.db'
 with sqlite3.connect(path) as db:
  db.execute('CREATE TABLE jobs(job_id TEXT,workspace_id TEXT,agent TEXT,workspace_transaction TEXT,status TEXT,exit_code INTEGER)')
  db.execute('CREATE TABLE job_admissions(token TEXT,job_id TEXT)');db.execute('CREATE TABLE git_admissions(token TEXT,request_sha256 TEXT,guard_path TEXT,status TEXT)')
  db.execute('INSERT INTO jobs VALUES(?,?,?,?,?,?)',(job,'repo','codex_impl',str(transaction),'cleanup_failed',1))
  db.execute('INSERT INTO job_admissions VALUES(?,?)',(token,job));db.execute('INSERT INTO git_admissions VALUES(?,?,?,?)',(token,request.digest,str(guard),'active'))
 path.chmod(0o600)
 return state,request,transaction,guard,path,job,token


def test_owner_change_before_writer_lock_is_refused_without_capacity_mutation(binding,monkeypatch):
 state,request,transaction,guard,path,job,token=binding;original=recovery._recovery_database
 class Connection:
  def __init__(self):self.db=original(state,write=True)
  @property
  def in_transaction(self):return self.db.in_transaction
  def execute(self,sql,args=()):
   if sql=='BEGIN IMMEDIATE':
    with sqlite3.connect(path) as owner:owner.execute("UPDATE jobs SET workspace_id='owner-other',agent='codex_review',status='cancelled' WHERE job_id=?",(job,))
   return self.db.execute(sql,args)
  def rollback(self):self.db.rollback()
  def commit(self):self.db.commit()
  def close(self):self.db.close()
 monkeypatch.setattr(recovery,'_recovery_database',lambda *a,**k:Connection())
 with pytest.raises(PermissionError):recovery._binding(state,request,transaction,guard,resolve=True)
 with sqlite3.connect(path) as db:
  assert db.execute('SELECT workspace_id,agent,status FROM jobs').fetchone()==('owner-other','codex_review','cancelled')
  assert db.execute('SELECT token,job_id FROM job_admissions').fetchone()==(token,job)
  assert db.execute('SELECT status FROM git_admissions').fetchone()==('active',)


def test_writer_lock_precedes_all_validating_reads(binding,monkeypatch):
 state,request,transaction,guard,path,job,token=binding;original=recovery._recovery_database;blocked=[]
 class Cursor:
  def __init__(self,cursor):self.cursor=cursor
  def fetchone(self):
   row=self.cursor.fetchone()
   with sqlite3.connect(path,timeout=.01) as owner:
    with pytest.raises(sqlite3.OperationalError,match='locked'):owner.execute("UPDATE jobs SET status='cancelled' WHERE job_id=?",(job,))
   blocked.append(True);return row
 class Connection:
  def __init__(self):self.db=original(state,write=True)
  @property
  def in_transaction(self):return self.db.in_transaction
  def execute(self,sql,args=()):
   cursor=self.db.execute(sql,args)
   return Cursor(cursor) if sql.startswith('SELECT request_sha256,guard_path,status') else cursor
  def rollback(self):self.db.rollback()
  def commit(self):self.db.commit()
  def close(self):self.db.close()
 monkeypatch.setattr(recovery,'_recovery_database',lambda *a,**k:Connection())
 recovery._binding(state,request,transaction,guard,resolve=True)
 assert blocked==[True]
 with sqlite3.connect(path) as db:
  assert db.execute('SELECT status FROM jobs').fetchone()==('recovered',)
  assert db.execute('SELECT count(*) FROM job_admissions').fetchone()==(0,)
  assert db.execute('SELECT status FROM git_admissions').fetchone()==('resolved',)
