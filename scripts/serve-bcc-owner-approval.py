#!/usr/bin/python3
"""Serve only a root-sealed static approval bundle; signing stays on the device."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from urllib.parse import urlsplit

FILES = {'index.html':'text/html; charset=utf-8','app.mjs':'application/javascript; charset=utf-8',
         'protocol.mjs':'application/javascript; charset=utf-8','style.css':'text/css; charset=utf-8'}
MAX_FILE = 512 * 1024
CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'; img-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"


def trusted(info):
    if info.st_uid != 0 or info.st_mode & 0o022:
        raise PermissionError('Approval assets require protected root ownership')


def read_file(directory, name):
    fd = os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=directory)
    try:
        before = os.fstat(fd); trusted(before)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > MAX_FILE:
            raise PermissionError('Invalid approval asset')
        chunks=[]; size=0
        while True:
            block=os.read(fd,min(65536,MAX_FILE+1-size))
            if not block: break
            chunks.append(block);size+=len(block)
            if size > MAX_FILE: raise PermissionError('Oversized approval asset')
        after=os.fstat(fd)
        if (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns) != (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns):
            raise PermissionError('Approval asset changed while loading')
        return b''.join(chunks)
    finally: os.close(fd)


def unique(pairs):
    result={}
    for key,value in pairs:
        if key in result: raise ValueError('Duplicate approval manifest key')
        result[key]=value
    return result


def load_assets(path):
    path=Path(path)
    if not path.is_absolute(): raise PermissionError('Absolute asset directory required')
    flags=os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC
    directory=os.open('/',flags)
    try:
        for part in path.parts[1:]:
            child=os.open(part,flags,dir_fd=directory)
            os.close(directory);directory=child;trusted(os.fstat(directory))
        manifest=json.loads(read_file(directory,'MANIFEST.json'),object_pairs_hook=unique)
        if set(manifest) != set(FILES) or any(not isinstance(v,str) or not re.fullmatch('[0-9a-f]{64}',v) for v in manifest.values()):
            raise PermissionError('Invalid approval manifest')
        assets={}
        for name in FILES:
            body=read_file(directory,name)
            if hashlib.sha256(body).hexdigest() != manifest[name]: raise PermissionError('Approval asset hash mismatch')
            assets[name]=body
        return assets
    finally: os.close(directory)


def make_handler(assets,host='bcc.tail7d013a.ts.net:8443'):
    snapshot=MappingProxyType(dict(assets))
    if set(snapshot) != set(FILES): raise ValueError('Exact approval bundle required')
    class Handler(BaseHTTPRequestHandler):
        server_version='BCCOwnerApproval'
        sys_version=''
        protocol_version='HTTP/1.1'
        def log_message(self,*args): pass
        def send(self,status,body,mime='text/plain; charset=utf-8',head=False):
            self.send_response(status)
            for key,value in {'Content-Type':mime,'Content-Length':str(len(body)),
                'Cache-Control':'no-store','Referrer-Policy':'no-referrer',
                'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY',
                'Content-Security-Policy':CSP,'Connection':'close'}.items(): self.send_header(key,value)
            self.end_headers();self.close_connection=True
            if not head: self.wfile.write(body)
        def serve(self,head=False):
            hosts=self.headers.get_all('Host',[])
            local='127.0.0.1:'+str(self.server.server_address[1])
            if len(hosts)!=1 or hosts[0].lower() not in {host,local}:
                self.send(403,b'Invalid origin\n',head=head);return
            try: parsed=urlsplit(self.path)
            except ValueError:
                self.send(400,b'Invalid path\n',head=head);return
            if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment or '%' in parsed.path or '\\' in parsed.path:
                self.send(400,b'Invalid path\n',head=head);return
            if parsed.path=='/health': self.send(200,b'healthy\n',head=head);return
            name='index.html' if parsed.path=='/' else parsed.path.removeprefix('/')
            if name not in snapshot or parsed.path not in {'/','/'+name}:
                self.send(404,b'Not found\n',head=head);return
            self.send(200,snapshot[name],FILES[name],head)
        def do_GET(self): self.serve()
        def do_HEAD(self): self.serve(True)
        def do_POST(self): self.send(405,b'No signing or upload API\n')
        def do_PUT(self): self.send(405,b'No signing or upload API\n')
        def do_DELETE(self): self.send(405,b'No signing or upload API\n')
    return Handler


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--assets',default='/opt/agentporter-bcc/owner-approval/assets')
    parser.add_argument('--port',type=int,default=18879)
    args=parser.parse_args()
    assets=load_assets(args.assets)
    server=ThreadingHTTPServer(('127.0.0.1',args.port),make_handler(assets))
    server.daemon_threads=True
    server.serve_forever()


if __name__=='__main__': main()
