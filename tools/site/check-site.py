import hashlib
import json
import posixpath
import re
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit

here=Path(__file__).parent
root=here/'dist'
HEADING=re.compile(r'h[1-6]')
class Page(HTMLParser):
 def __init__(self):super().__init__();self.links=[];self.ids=[];self.headings=[];self.images=[];self.canonical=[]
 def handle_starttag(self,tag,attrs):
  a=dict(attrs)
  if 'id' in a:self.ids.append(a['id'])
  if HEADING.fullmatch(tag):self.headings.append(int(tag[1]))
  if tag=='img':self.images.append(a)
  if tag=='link' and a.get('rel')=='canonical':self.canonical.append(a.get('href') or '')
  for k in ['href','src']:
   if k in a:self.links.append((k,a[k] or ''))
def local(p):return p.relative_to(root).as_posix()
def downloads(path):return path=='downloads' or path.startswith('downloads/')
def serve(path):
 """File a URL path (relative to the site root) is served from under Cloudflare static assets
 html_handling 'auto-trailing-slash' without a redirect; None if it would 404 or redirect."""
 base=root.joinpath(*[x for x in path.split('/') if x])
 if path=='' or path.endswith('/'):
  index=base/'index.html'
  return index if index.is_file() else None
 # Cloudflare redirects any request ending in .html; only literal downloads/ files are linked that way.
 if path.endswith('.html') and not downloads(path):return None
 if base.is_file():return base
 if base.is_dir():return None  # directory without its trailing slash: redirected
 html=base.with_name(base.name+'.html')
 return html if html.is_file() else None
site=urlsplit(json.loads((here/'site-config.json').read_text())['siteUrl'])
def same_site(u):
 # Same site = this host (or www.), any default port, http(s) or protocol-relative (//host/...); None if malformed.
 try:port=u.port
 except ValueError:return None
 host=(u.hostname or '').lower().removeprefix('www.')
 return host==(site.hostname or '').lower().removeprefix('www.') and u.scheme in ('','http','https') and port in (None,80,443)
pages={}
for f in sorted(root.rglob('*.html')):
 if downloads(local(f)):continue
 p=Page();p.feed(f.read_text(encoding='utf-8'));pages[f.resolve()]=p
errors:list=[];anchors:list=[];duplicate:list=[];malformed:list=[];html_links:list=[];headings:list=[];images:list=[]
canonicals:list=[];sitemap:list=[];search:list=[];versions:list=[];stale:list=[]
def problem(kind,f,url,why=''):kind.append({'page':local(f),'url':url,**({'reason':why} if why else {})})
for f,p in pages.items():
 page_dir=posixpath.dirname(local(f))
 if len(p.ids)!=len(set(p.ids)):duplicate.append(local(f))
 for attr,url in p.links:
  u=urlsplit(url)
  if u.scheme or u.netloc:
   # Absolute URLs are not fetched, but dot segments mean a relative path was mangled into one.
   dot=unquote(u.path)+'/'
   if '/../' in dot or '/./' in dot:problem(malformed,f,url);continue
   if u.scheme in ('http','https') and not u.netloc:problem(malformed,f,url);continue
   same=same_site(u)
   if same is None:problem(malformed,f,url);continue
   if not same:continue
   path=unquote(u.path)
  elif u.path.startswith('/'):path=unquote(u.path)
  elif u.path:path=posixpath.join(page_dir,unquote(u.path))
  else:path='/'+local(f)
  # URL directories match file directories under clean URLs, so relative paths resolve from the file's folder.
  trailing=path.endswith('/') or posixpath.basename(path) in ('','.','..')
  norm=posixpath.normpath('/'+path.lstrip('/'))
  if norm.startswith('/..'):problem(malformed,f,url,'escapes the site root');continue
  path=norm.lstrip('/')+('/' if trailing and norm!='/' else '')
  # Pages are linked by clean URL: an internal href ending in .html would be answered with a redirect.
  if attr=='href' and u.path.endswith('.html') and not downloads(path):html_links.append({'page':local(f),'url':url})
  target=serve(path) if u.path else f
  if target is None:problem(errors,f,url,'no file is served at this URL without a redirect');continue
  target=target.resolve()
  if u.fragment and target in pages and unquote(u.fragment) not in pages[target].ids:problem(anchors,f,url)
  # Long-cached assets must carry ?v= equal to the first 8 hex digits of the published file's sha256.
  if re.match(r'assets/.*\.(css|js)$',path):
   want='v='+hashlib.sha256(target.read_bytes()).hexdigest()[:8]
   if u.query!=want:problem(versions,f,url,'expected ?'+want)
 # Heading structure on reading pages (everything this builder renders; the simulator app ships its own markup).
 if not local(f).startswith('simulator/'):
  levels=p.headings
  if levels.count(1)!=1:headings.append({'page':local(f),'problem':str(levels.count(1))+' h1 elements'})
  for prev,cur in zip([0,*levels],levels):
   if cur>prev+1:
    headings.append({'page':local(f),'problem':'h'+str(prev)+' followed by h'+str(cur)})
    break
 for img in p.images:
  if not img.get('width') or not img.get('height'):images.append({'page':local(f),'src':img.get('src')})
 # Canonical: exactly one absolute https same-site URL, served (without a redirect) by this very page.
 if local(f)!='404.html' and not local(f).startswith('simulator/'):
  if len(p.canonical)!=1:problem(canonicals,f,str(p.canonical),'expected exactly one canonical link')
  else:
   cu=urlsplit(p.canonical[0])
   served=serve(unquote(cu.path).lstrip('/')) if same_site(cu) and cu.scheme=='https' else None
   if served is None or served.resolve()!=f:problem(canonicals,f,p.canonical[0],'canonical does not serve this page')
# Every sitemap URL must be served (by clean URL, without a redirect) from an existing file.
locs=re.findall(r'<loc>([^<]*)</loc>',(root/'sitemap.xml').read_text(encoding='utf-8'))
for loc in locs:
 lu=urlsplit(loc.replace('&amp;','&'))
 if not same_site(lu) or lu.scheme!='https' or serve(unquote(lu.path).lstrip('/')) is None:sitemap.append(loc)
# Search results are links relative to the library page at the site root.
for item in json.loads((root/'search-index.json').read_text(encoding='utf-8')):
 if item['url'].endswith('.html') or serve(unquote(item['url'])) is None:search.append(item['url'])
# The MCAT app is served by its own Worker (mcat.collinbgeorge.com); the build must not host or link the retired copy.
# Every HTML file is scanned here, downloads/ included, for an href or src into the old /study/ path.
if (root/'study').exists():stale.append('study/')
STUDY=re.compile(r'''(?:href|src)\s*=\s*["']?(?:https?://(?:www\.)?collinbgeorge\.com)?(?:/|(?:\.\./)*)study/''',re.IGNORECASE)
for f in sorted(root.rglob('*.html')):
 if STUDY.search(f.read_text(encoding='utf-8',errors='replace')):stale.append(local(f))
report={'pages':len(pages),'sitemapUrls':len(locs),'missingFiles':errors,'malformedUrls':malformed,'missingAnchors':anchors,'duplicateIds':duplicate,'htmlHrefs':html_links,'headingProblems':headings,'imagesWithoutSize':images,'badCanonicals':canonicals,'badSitemapUrls':sitemap,'badSearchUrls':search,'badAssetVersions':versions,'staleMcatCopies':stale}
(here/'link-report.json').write_text(json.dumps(report,indent=2))
print(json.dumps({k:len(v) if isinstance(v,list) else v for k,v in report.items()},indent=2))
failed={k:v for k,v in report.items() if isinstance(v,list) and v and k!='missingAnchors'}
if failed:
 print(json.dumps({k:v[:10] for k,v in failed.items()},indent=2))
 raise SystemExit(1)
