from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlsplit,unquote
import json,re
root=Path(__file__).parent/'dist'
class Page(HTMLParser):
 def __init__(self):super().__init__();self.links=[];self.ids=[];self.h1=0
 def handle_starttag(self,tag,attrs):
  a=dict(attrs)
  if 'id' in a:self.ids.append(a['id'])
  if tag=='h1':self.h1+=1
  for k in ['href','src']:
   if k in a:self.links.append((tag,a[k]))
pages={}
for f in root.rglob('*.html'):
 if 'downloads' in f.relative_to(root).parts or 'study' in f.relative_to(root).parts:continue
 p=Page();p.feed(f.read_text(encoding='utf-8'));pages[f.resolve()]=p
errors=[];anchors=[];duplicate=[]
for f,p in pages.items():
 if len(p.ids)!=len(set(p.ids)):duplicate.append(str(f.relative_to(root)))
 for tag,url in p.links:
  u=urlsplit(url)
  if u.scheme or u.netloc:continue
  target=(f.parent/unquote(u.path)).resolve() if u.path else f
  if target.is_dir():target=target/'index.html'
  if not target.exists():errors.append({'page':str(f.relative_to(root)),'url':url})
  elif u.fragment and target in pages and unquote(u.fragment) not in pages[target].ids:anchors.append({'page':str(f.relative_to(root)),'url':url})
report={'pages':len(pages),'missingFiles':errors,'missingAnchors':anchors,'duplicateIds':duplicate}
(Path(__file__).parent/'link-report.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report,indent=2))
if errors or duplicate:raise SystemExit(1)
