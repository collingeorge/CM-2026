import base64
import concurrent.futures
import hashlib
import io
import json
import pathlib
import shutil

# Security note: used only with fixed argument lists, never a shell
import subprocess  # nosec B404
import tarfile
import urllib.request
import zipfile

root=pathlib.Path(__file__).parent
pins=json.loads((root/'source-pins.json').read_text())
expected=json.loads((root/'source-integrity.json').read_text())
def fetch(url):
 if not url.startswith('https://'):raise ValueError('only https sources are allowed: '+url)
 # Security note: scheme checked above; content is sha256-verified
 return urllib.request.urlopen(urllib.request.Request(url,headers={'User-Agent':'collinbgeorge-portfolio-build'}),timeout=180).read()  # nosec B310
def source(p):
 if p['name']=='CM-2026':
  # Security note: fixed argv, no shell; sha comes from the pinned source-pins.json
  data=subprocess.check_output(['git','archive','--format=zip','--prefix=source/',p['sha']],cwd=root.parent.parent)  # nosec B603 B607
 else:
  data=fetch('https://codeload.github.com/collingeorge/'+p['name']+'/zip/'+p['sha'])
 dest=root/'sources'/p['name']
 if dest.exists():shutil.rmtree(dest)
 dest.mkdir(parents=True)
 extracted=set()
 with zipfile.ZipFile(io.BytesIO(data)) as z:
  for f in z.infolist():
   rel=pathlib.PurePosixPath(*pathlib.PurePosixPath(f.filename).parts[1:])
   if str(rel)=='.' or f.is_dir():continue
   target=dest.joinpath(*rel.parts)
   if not target.resolve().is_relative_to(dest.resolve()):raise ValueError('unsafe source path')
   target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(z.read(f));extracted.add(rel.as_posix())
 entries=[e for e in expected if e['repo']==p['name']]
 # Every extracted file must be pinned, and every pinned file must be present: nothing is published unverified.
 listed={e['path'] for e in entries}
 extra=sorted(extracted-listed);missing=sorted(listed-extracted)
 if extra or missing or len(listed)!=len(entries):
  raise ValueError('source file set mismatch for '+p['name']+': '+str(len(extra))+' unlisted '+str(extra[:10])+', '+str(len(missing))+' missing '+str(missing[:10])+', '+str(len(entries)-len(listed))+' duplicate manifest entries')
 for e in entries:
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
   target=root/'vendor'/target_name;target.parent.mkdir(parents=True,exist_ok=True);member=t.extractfile(source_name)
   if member is None:raise ValueError('dependency member missing: '+source_name)
   target.write_bytes(member.read())
 print('Verified '+p['name']+' '+p['version'],flush=True)
cname=root.parent.parent/'CNAME'
if cname.exists():
 domain=cname.read_text().strip()
 if domain!='collinbgeorge.com':raise ValueError('unexpected publication domain')
 (root/'site-config.json').write_text(json.dumps({'siteUrl':'https://'+domain}))
