import json
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

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
site=urlsplit(json.loads((Path(__file__).parent/'site-config.json').read_text())['siteUrl'])
errors=[];anchors=[];duplicate=[];malformed=[]
for f,p in pages.items():
 if len(p.ids)!=len(set(p.ids)):duplicate.append(str(f.relative_to(root)))
 for tag,url in p.links:
  u=urlsplit(url)
  if u.scheme or u.netloc:
   # Absolute URLs are not fetched, but dot segments mean a relative path was mangled into one.
   dot=unquote(u.path)+'/'
   if '/../' in dot or '/./' in dot:malformed.append({'page':str(f.relative_to(root)),'url':url});continue
   if u.netloc.lower()!=site.netloc.lower() or u.scheme not in ('http','https'):continue
   # Absolute link to this site: it must exist in dist.
   target=(root/unquote(u.path).lstrip('/')).resolve()
   if not target.is_relative_to(root.resolve()):malformed.append({'page':str(f.relative_to(root)),'url':url});continue
  else:target=(f.parent/unquote(u.path)).resolve() if u.path else f
  if target.is_dir():target=target/'index.html'
  if not target.exists():errors.append({'page':str(f.relative_to(root)),'url':url})
  elif u.fragment and target in pages and unquote(u.fragment) not in pages[target].ids:anchors.append({'page':str(f.relative_to(root)),'url':url})
report={'pages':len(pages),'missingFiles':errors,'malformedUrls':malformed,'missingAnchors':anchors,'duplicateIds':duplicate}
(Path(__file__).parent/'link-report.json').write_text(json.dumps(report,indent=2))
print(json.dumps(report,indent=2))
if errors or duplicate or malformed:raise SystemExit(1)
