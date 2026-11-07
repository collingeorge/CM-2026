import hashlib
import importlib.util
import json
import pathlib
import re
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
# Duplicate src: browsers use the FIRST value, so an external first src must not survive (05l final review).
for p in ['<img src="https://evil.invalid/a.png" src="ok.png" alt="badge">','<img src="ok.png" src="https://evil.invalid/a.png" alt="badge">']:
 out=m.sanitize(p)
 if 'evil.invalid' in out or out!='<span class="img-alt">badge</span>':errors.append('duplicate-src image not replaced by alt text: '+p)
 checks+=1
# Duplicate attributes on any tag keep only the first value (what the browser renders).
if m.sanitize('<a href="https://ok.example/" href="javascript:alert(1)">x</a>')!='<a href="https://ok.example/" rel="noopener noreferrer">x</a>':errors.append('duplicate attribute not reduced to the first value')
checks+=1
# Batch input must be well-formed and every failure must name its document.
for bad,expect in [('{}','JSON array'),('[{"name":"d1"}]','d1: each item needs a string "html" field'),('[{"name":"d2","html":5}]','d2: each item'),('[{"name":"d3","html":"<style>x"}]','d3: unclosed blocked element')]:
 try:m.sanitize_batch(json.loads(bad));errors.append('malformed batch accepted: '+bad)
 except (ValueError,TypeError) as err:
  if expect not in str(err):errors.append('batch error does not name the document: '+str(err))
 checks+=1
if m.sanitize_batch([{'name':'u','html':'<p>café — ✓</p>'}])!=['<p>café — ✓</p>']:errors.append('batch sanitizer changed non-ASCII text')
checks+=1
class ImgAudit(HTMLParser):
 def __init__(self,name):super().__init__();self.name=name
 def handle_starttag(self,t,attrs):
  if t!='img':return
  srcs=[v or '' for k,v in attrs if k=='src']
  if len(srcs)>1:errors.append('duplicate src on image in built page '+self.name)
  for src in srcs:
   if not m.same_site_url(src):errors.append('external image in built page '+self.name+': '+src)
for f in sorted((root/'dist').rglob('*.html')):
 rel=f.relative_to(root/'dist')
 if rel.parts[0]=='downloads':continue
 ImgAudit(str(rel)).feed(f.read_text(encoding='utf-8'));checks+=1
# Repositories pinned with "downloads": false are rendered as reading pages only; their files are not republished.
unpublished={p['name'] for p in json.loads((root/'source-pins.json').read_text()) if p.get('downloads') is False}
for name in sorted(unpublished):
 if (root/'dist'/'downloads'/name).exists():errors.append('unpublished source republished under downloads/'+name)
 checks+=1
# Mermaid must load before reading.js (both deferred, so document order is execution order); otherwise
# reading.js finds no window.mermaid, the site's strict configuration is never applied, and Mermaid
# renders on its own defaults.
for f in sorted((root/'dist').rglob('*.html')):
 if 'downloads' in f.relative_to(root/'dist').parts:continue
 t=f.read_text(encoding='utf-8')
 if 'class="mermaid"' in t:
  i=t.find('assets/vendor/mermaid.min.js');j=t.find('assets/reading.js')
  if i<0 or j<0 or i>j:errors.append('Mermaid must load before reading.js: '+str(f.relative_to(root/'dist')))
  checks+=1
for e in json.loads((root/'source-integrity.json').read_text()):
 if e['repo'] in unpublished:continue
 f=root/'dist'/'downloads'/e['repo']/e['path']
 if hashlib.sha256(f.read_bytes()).hexdigest()!=e['sha256']:errors.append('source changed '+str(f))
 checks+=1
scripts=[f for f in sorted((root/'dist').rglob('*.js')) if f.name!='mermaid.min.js' and 'downloads' not in f.parts]
errors.extend(node_check_all(scripts));checks+=len(scripts)
headers=(root/'dist'/'_headers').read_text()
for required in ['Strict-Transport-Security: max-age=31536000','X-Content-Type-Options: nosniff',"frame-ancestors 'none'","object-src 'none'","base-uri 'none'",'Permissions-Policy:']:
 if required not in headers:errors.append('missing '+required)
 checks+=1
# Parse _headers the way Cloudflare applies it: every rule whose path pattern matches contributes its headers,
# and a header set by several matching rules is merged into one comma-joined value.
rules:list[tuple[re.Pattern[str],list[tuple[str,str]]]]=[]
for line in headers.splitlines():
 if not line.strip() or line.lstrip().startswith('#'):continue
 if not line[0].isspace():rules.append((re.compile('^'+re.escape(line.strip()).replace(r'\*','.*')+'$'),[]))
 else:
  name,_,value=line.strip().partition(':')
  rules[-1][1].append((name.strip().lower(),value.strip()))
def served_headers(path:str)->dict[str,str]:
 merged:dict[str,list[str]]={}
 for pattern,values in rules:
  if pattern.match(path):
   for name,value in values:merged.setdefault(name,[]).append(value)
 return {name:', '.join(values) for name,values in merged.items()}
IMMUTABLE='public, max-age=31536000, immutable'
REVALIDATE='public, max-age=0, must-revalidate'
hashed=['/assets/portfolio.css','/assets/portfolio.js','/assets/reading.css','/assets/reading.js','/assets/vendor/mermaid.min.js']
for path,want in [*[(p,IMMUTABLE) for p in hashed],*[(p,REVALIDATE) for p in ['/','/library','/projects/smart-noa/','/projects/smart-noa/LICENSE','/pages/README','/simulator/','/search-index.json','/sitemap.xml']]]:
 got=served_headers(path).get('cache-control')
 if got!=want:errors.append('Cache-Control for '+path+' is '+repr(got)+', expected '+repr(want))
 checks+=1
for pattern,values in rules:
 for name,value in values:
  if name=='content-security-policy' and re.search(r"script-src[^;]*'unsafe-inline'",value):errors.append('script-src allows unsafe-inline for '+pattern.pattern)
 if 'study' in pattern.pattern:errors.append('retired /study/ rule in _headers: '+pattern.pattern)
 checks+=1
report={'checks':checks,'errors':errors,'warnings':['HSTS preload and includeSubDomains are intentionally off; unrelated subdomain HTTPS has not been established.','This scoped review is not an independent penetration test or proof of absence of vulnerabilities.']}
(root/'security-validation.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));sys.exit(bool(errors))
