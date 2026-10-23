import ast,hashlib,importlib.util,json,os
from pathlib import Path
root=Path('/home/yeli/agent-work/agentporter-dev')
def load(name):
 p=root/'scripts'/(name+'.py');s=importlib.util.spec_from_file_location(name,p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
builder=load('build-development-candidate');overlay=load('prepare-development-overlay');canonical=load('prepare-closeout-candidate');installer=load('install-development-artifact')
report=json.loads(Path('/tmp/jax-acquisition-repair-build.json').read_text())
assert builder.digest(Path(report['artifact']),installer.LIMIT)==report['sha256']
stage=Path('/tmp/jax-acquisition-repair-candidate');release=stage/'release'
manifest=json.loads((stage/'release-files.json').read_text())
for n in ['venv/pyvenv.cfg','venv/lib/python3.13/site-packages/agentporter_development.pth']:
 body=(release/n).read_bytes().replace(str(release).encode(),('/opt/agentporter-development/versions/'+report['version']).encode())
 assert hashlib.sha256(body).hexdigest()==manifest[n]['sha256']
 overlay.replace_file(release/n,body)
assert builder.entries(release)==manifest
name='src/agentporter/https_download.py'
before=(release/name).read_bytes();after=(root/name).read_bytes()
class NoDocs(ast.NodeTransformer):
 def generic_visit(self,node):
  super().generic_visit(node)
  if isinstance(node,(ast.Module,ast.ClassDef,ast.FunctionDef,ast.AsyncFunctionDef)) and node.body and isinstance(node.body[0],ast.Expr) and isinstance(node.body[0].value,ast.Constant) and isinstance(node.body[0].value.value,str):node.body.pop(0)
  return node
assert ast.dump(NoDocs().visit(ast.parse(before)))==ast.dump(NoDocs().visit(ast.parse(after)))
assert hashlib.sha256(before).hexdigest()==report['source_pins'][name]
overlay.replace_file(release/name,after)
manifest[name]['sha256']=hashlib.sha256(after).hexdigest()
assert builder.entries(release)==manifest
overlay.replace_file(stage/'release-files.json',json.dumps(manifest,sort_keys=True).encode()+b'\n')
report['source_pins'][name]=manifest[name]['sha256']
for n,digest in report['source_pins'].items():assert hashlib.sha256((root/n).read_bytes()).hexdigest()==digest
fingerprint=hashlib.sha256();package=release/'src/agentporter'
for p in sorted(p for p in package.rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc'):fingerprint.update(str(p.relative_to(package)).encode()+b'\0'+p.read_bytes()+b'\0')
output=Path('/tmp/a7dev-acquisition-repair-final.tgz');extracted=Path('/tmp/jax-acquisition-repair-final-candidate')
assert not output.exists() and not extracted.exists()
print('Packing docstring-only amendment; executable AST unchanged',flush=True)
canonical.pack_canonical(builder,release,stage,output,manifest)
print('Extracting final archive with real installer and verifying full manifest',flush=True)
overlay.extract(installer,output,extracted);installer.verify_release(extracted/'release',manifest)
report.update(artifact=str(output),sha256=builder.digest(output,installer.LIMIT),fingerprint=fingerprint.hexdigest(),docstring_only_amendment_of=report['sha256'],executable_ast_unchanged=True)
output.chmod(0o400)
Path('/tmp/jax-acquisition-repair-final-build.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report),flush=True)
