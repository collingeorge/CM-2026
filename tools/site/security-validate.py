import pathlib,sys,hashlib,json,subprocess,re,importlib.util
from html.parser import HTMLParser
root=pathlib.Path(__file__).parent
spec=importlib.util.spec_from_file_location('sanitizer',root/'sanitize-html.py');m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
errors=[];checks=0
payloads=['<img src=x onerror=alert(1)>','<a href="jav&#x61;script:alert(1)">x</a>','<svg><script>alert(1)</script></svg>','<iframe srcdoc="x"></iframe>','<a href="java\nscript:alert(1)">x</a>','<base href="https://evil.invalid/">','<meta http-equiv="refresh" content="0;url=x">','<form action="https://evil.invalid/"><input></form>']
class Audit(HTMLParser):
 def handle_starttag(self,t,attrs):
  a=dict(attrs)
  if t in {'script','iframe','object','embed','form','base','meta','svg','math','input'}:errors.append('unsafe tag in sanitizer '+t)
  for k,v in attrs:
   if k.startswith('on') or k=='srcdoc':errors.append('unsafe attribute '+k)
   if k in ('href','src') and not m.safe_url(v):errors.append('unsafe URL')
for p in payloads:Audit().feed(m.sanitize(p));checks+=1
for e in json.loads((root/'source-integrity.json').read_text()):
 f=root/'dist'/'downloads'/e['repo']/e['path']
 if hashlib.sha256(f.read_bytes()).hexdigest()!=e['sha256']:errors.append('source changed '+str(f))
 checks+=1
for f in (root/'dist').rglob('*.js'):
 if f.name=='mermaid.min.js' or 'downloads' in f.parts:continue
 p=subprocess.run(['node','--check',str(f)],capture_output=True,text=True)
 if p.returncode:errors.append(p.stderr)
 checks+=1
headers=(root/'dist'/'_headers').read_text()
for required in ['Strict-Transport-Security: max-age=31536000','X-Content-Type-Options: nosniff',"frame-ancestors 'none'","object-src 'none'","base-uri 'none'",'Permissions-Policy:']:
 if required not in headers:errors.append('missing '+required)
 checks+=1
report={'checks':checks,'errors':errors,'warnings':['MCAT inline handlers require unsafe-inline in its scoped CSP; no unsafe-eval enabled.','HSTS preload and includeSubDomains are intentionally off; unrelated subdomain HTTPS has not been established.','This scoped review is not an independent penetration test or proof of absence of vulnerabilities.']}
(root/'security-validation.json').write_text(json.dumps(report,indent=2));print(json.dumps(report,indent=2));sys.exit(bool(errors))
