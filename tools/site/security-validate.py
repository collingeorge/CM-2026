import hashlib
import importlib.util
import json
import pathlib
import shutil

# Security note: used only with fixed argument lists, never a shell
import subprocess  # nosec B404
import sys
from html.parser import HTMLParser

root=pathlib.Path(__file__).parent
NODE=shutil.which('node') or 'node'
def node_check(path):
 # Security note: fixed argv, no shell; path is a file produced by this build
 return subprocess.run([NODE,'--check',str(path)],capture_output=True,text=True,check=False)  # nosec
# Parse-only syntax check of many files in one Node process, mirroring `node --check`:
# CommonJS is compiled as a function wrapper, ES modules as vm.SourceTextModule (never linked
# or evaluated), and files with no declared type try CommonJS then module syntax.
JS_CHECK=r'''
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const kind=f=>{if(f.endsWith('.mjs'))return 'module';if(f.endsWith('.cjs'))return 'commonjs';
 for(let d=path.dirname(f);;d=path.dirname(d)){const p=path.join(d,'package.json');
  if(fs.existsSync(p)){const t=JSON.parse(fs.readFileSync(p,'utf8')).type;return t==='module'?'module':t==='commonjs'?'commonjs':'auto';}
  if(path.dirname(d)===d)return 'auto';}};
const cjs=(s,f)=>vm.compileFunction(s,['exports','require','module','__filename','__dirname'],{filename:f});
const esm=(s,f)=>new vm.SourceTextModule(s,{identifier:f});
const errors=[];
for(const f of process.argv.slice(1)){const s=fs.readFileSync(f,'utf8').replace(/^#!.*/,'');const k=kind(f);
 try{if(k==='module')esm(s,f);else if(k==='commonjs')cjs(s,f);else{try{cjs(s,f);}catch{esm(s,f);}}}
 catch(e){errors.push(f+': '+String(e&&e.message||e));}}
process.stdout.write(JSON.stringify({checked:process.argv.length-1,errors}));
'''
def node_check_all(paths):
 # Security note: fixed argv, no shell; the script is a constant above and paths are files produced by this build
 proc=subprocess.run([NODE,'--experimental-vm-modules','--no-warnings','-e',JS_CHECK,*map(str,paths)],capture_output=True,text=True,check=False)  # nosec
 try:result=json.loads(proc.stdout)
 except ValueError:result=None
 if proc.returncode or not isinstance(result,dict) or result.get('checked')!=len(paths):
  # Batch checker unavailable on this Node: fall back to one `node --check` per file.
  return [r.stderr for r in map(node_check,paths) if r.returncode]
 return result['errors']
spec=importlib.util.spec_from_file_location('sanitizer',root/'sanitize-html.py')
if spec is None or spec.loader is None:raise ImportError('cannot load sanitize-html.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
errors=[];checks=0
payloads=['<img src=x onerror=alert(1)>','<a href="jav&#x61;script:alert(1)">x</a>','<svg><script>alert(1)</script></svg>','<iframe srcdoc="x"></iframe>','<a href="java\nscript:alert(1)">x</a>','<base href="https://evil.invalid/">','<meta http-equiv="refresh" content="0;url=x">','<form action="https://evil.invalid/"><input></form>']
class Audit(HTMLParser):
 def handle_starttag(self,t,attrs):
  if t in {'script','iframe','object','embed','form','base','meta','svg','math','input'}:errors.append('unsafe tag in sanitizer '+t)
  for k,v in attrs:
   if k.startswith('on') or k=='srcdoc':errors.append('unsafe attribute '+k)
   if k in ('href','src') and not m.safe_url(v):errors.append('unsafe URL')
for p in payloads:Audit().feed(m.sanitize(p));checks+=1
# Site CSP is img-src 'self' data:, so only relative image sources may survive sanitizing.
for p in ['<img src="https://img.shields.io/x.svg" alt="badge">','<img src="//evil.invalid/x.png" alt="badge">','<img src="http://evil.invalid/x.png" alt="badge">','<img src=" https://evil.invalid/x.png" alt="badge">','<img src="/x.png" alt="badge">','<img src="data:image/png;base64,AA" alt="badge">']:
 out=m.sanitize(p)
 if '<img' in out or out!='<span class="img-alt">badge</span>':errors.append('external image not replaced by alt text: '+p)
 checks+=1
if m.sanitize('<img src="figures/a.png" alt="a">')!='<img src="figures/a.png" alt="a">':errors.append('relative image removed')
checks+=1
class ImgAudit(HTMLParser):
 def __init__(self,name):super().__init__();self.name=name
 def handle_starttag(self,t,attrs):
  src=dict(attrs).get('src')
  if t=='img' and src is not None and not m.same_site_url(src):errors.append('external image in built page '+self.name+': '+src)
for f in sorted((root/'dist').rglob('*.html')):
 rel=f.relative_to(root/'dist')
 if rel.parts[0] in ('downloads','study'):continue
 ImgAudit(str(rel)).feed(f.read_text(encoding='utf-8'));checks+=1
for e in json.loads((root/'source-integrity.json').read_text()):
 f=root/'dist'/'downloads'/e['repo']/e['path']
 if hashlib.sha256(f.read_bytes()).hexdigest()!=e['sha256']:errors.append('source changed '+str(f))
 checks+=1
scripts=[f for f in sorted((root/'dist').rglob('*.js')) if f.name!='mermaid.min.js' and 'downloads' not in f.parts]
errors.extend(node_check_all(scripts));checks+=len(scripts)
headers=(root/'dist'/'_headers').read_text()
for required in ['Strict-Transport-Security: max-age=31536000','X-Content-Type-Options: nosniff',"frame-ancestors 'none'","object-src 'none'","base-uri 'none'",'Permissions-Policy:']:
 if required not in headers:errors.append('missing '+required)
 checks+=1
report={'checks':checks,'errors':errors,'warnings':['MCAT inline handlers require unsafe-inline in its scoped CSP; no unsafe-eval enabled.','HSTS preload and includeSubDomains are intentionally off; unrelated subdomain HTTPS has not been established.','This scoped review is not an independent penetration test or proof of absence of vulnerabilities.']}
(root/'security-validation.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));sys.exit(bool(errors))
