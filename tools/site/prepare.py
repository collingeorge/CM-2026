import pathlib,json,urllib.request,zipfile,io,hashlib,base64,tarfile,concurrent.futures
root=pathlib.Path(__file__).parent
pins=json.loads((root/'source-pins.json').read_text())
expected=json.loads((root/'source-integrity.json').read_text())
def fetch(url):
 return urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'collinbgeorge-portfolio-build'}),timeout=180).read()
def source(p):
 data=fetch('https://codeload.github.com/collingeorge/'+p['name']+'/zip/'+p['sha'])
 dest=root/'sources'/p['name'];dest.mkdir(parents=True,exist_ok=True)
 with zipfile.ZipFile(io.BytesIO(data)) as z:
  for f in z.infolist():
   rel=pathlib.PurePosixPath(*pathlib.PurePosixPath(f.filename).parts[1:])
   if str(rel)=='.' or f.is_dir():continue
   target=dest.joinpath(*rel.parts)
   if not target.resolve().is_relative_to(dest.resolve()):raise ValueError('unsafe source path')
   target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(z.read(f))
 for e in [e for e in expected if e['repo']==p['name']]:
  b=(dest/e['path']).read_bytes()
  if hashlib.sha256(b).hexdigest()!=e['sha256']:raise ValueError('source integrity failed: '+p['name']+'/'+e['path'])
 return p['name']
with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
 for name in pool.map(source,pins):print('Verified '+name,flush=True)
for p in json.loads((root/'dependency-pins.json').read_text()):
 b=fetch(p['url'])
 if 'sha512-'+base64.b64encode(hashlib.sha512(b).digest()).decode()!=p['integrity']:raise ValueError('dependency integrity failed')
 with tarfile.open(fileobj=io.BytesIO(b),mode='r:gz') as t:
  for source_name,target_name in p['files'].items():
   target=root/'vendor'/target_name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(t.extractfile(source_name).read())
 print('Verified '+p['name']+' '+p['version'],flush=True)
cname=root.parent.parent/'CNAME'
if cname.exists():
 domain=cname.read_text().strip()
 if domain!='collinbgeorge.com':raise ValueError('unexpected publication domain')
 (root/'site-config.json').write_text(json.dumps({'siteUrl':'https://'+domain}))
