import importlib.util
import http.client
import json
from pathlib import Path
import threading
from types import SimpleNamespace
import pytest

SCRIPT=Path(__file__).resolve().parents[2]/'scripts/serve-bcc-owner-approval.py'
spec=importlib.util.spec_from_file_location('owner_host',SCRIPT)
host=importlib.util.module_from_spec(spec);spec.loader.exec_module(host)

@pytest.fixture
def server():
    root=SCRIPT.parents[1]/'src/agentporter/owner_approval'
    assets={name:(root/name).read_bytes() for name in host.FILES}
    service=host.ThreadingHTTPServer(('127.0.0.1',0),host.make_handler(assets))
    thread=threading.Thread(target=service.serve_forever,daemon=True);thread.start()
    yield service
    service.shutdown();service.server_close();thread.join(2)


def request(server,path,method='GET',headers=None,body=None):
    connection=http.client.HTTPConnection(*server.server_address,timeout=3)
    connection.request(method,path,body=body,headers=headers or {})
    response=connection.getresponse();data=response.read();result=(response.status,dict(response.getheaders()),data)
    connection.close();return result


def test_only_static_bundle_is_served_with_browser_security_headers(server):
    status,headers,body=request(server,'/')
    assert status==200 and b'BCC owner approval' in body
    assert headers['Cache-Control']=='no-store'
    assert headers['X-Content-Type-Options']=='nosniff'
    assert headers['Referrer-Policy']=='no-referrer'
    assert "frame-ancestors 'none'" in headers['Content-Security-Policy']
    assert "connect-src 'none'" in headers['Content-Security-Policy']
    assert headers['X-Frame-Options']=='DENY'
    status,headers,_=request(server,'/app.mjs')
    assert status==200 and headers['Content-Type'].startswith('application/javascript')


@pytest.mark.parametrize('path',['/../secrets.env','/assets/','/%2e%2e/secrets.env','/app.mjs?proposal=secret','/MANIFEST.json'])
def test_traversal_listing_and_proposal_urls_are_rejected(server,path):
    status,_,body=request(server,path)
    assert status in {400,404}
    assert b'secret' not in body


@pytest.mark.parametrize('method',['POST','PUT','DELETE'])
def test_server_has_no_signing_or_upload_operation(server,method):
    status,_,_=request(server,'/sign',method,body=b'SYNTHETIC-PROPOSAL')
    assert status==405


def test_unrelated_host_cannot_serve_approval_page(server):
    assert request(server,'/',headers={'Host':'unrelated.example'})[0]==403
    assert request(server,'/',headers={'Host':'bcc.tail7d013a.ts.net:8443'})[0]==200


def test_head_has_no_body(server):
    status,headers,body=request(server,'/app.mjs','HEAD')
    assert status==200 and int(headers['Content-Length'])>0 and body==b''


@pytest.mark.parametrize('uid,mode',[(997,0o444),(0,0o664),(0,0o646)])
def test_agent_owned_or_writable_assets_are_rejected(uid,mode):
    with pytest.raises(PermissionError):host.trusted(SimpleNamespace(st_uid=uid,st_mode=mode))


def test_duplicate_manifest_fields_are_refused():
    with pytest.raises(ValueError):json.loads('{"app.mjs":"one","app.mjs":"two"}',object_pairs_hook=host.unique)


def test_malformed_absolute_url_is_rejected_by_server(server):
    connection=http.client.HTTPConnection(*server.server_address,timeout=3)
    connection.putrequest('GET','http://[',skip_host=True)
    connection.putheader('Host','127.0.0.1:'+str(server.server_address[1]))
    connection.endheaders()
    response=connection.getresponse()
    assert response.status==400
    response.read()
    connection.close()
