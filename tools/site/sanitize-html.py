import json
import re
import sys
from html import escape
from html.parser import HTMLParser
from urllib.parse import urlsplit

ALLOWED={'a', 'abbr', 'article', 'aside', 'b', 'blockquote', 'br', 'caption', 'code', 'col', 'colgroup', 'dd', 'del', 'details', 'div', 'dl', 'dt', 'em', 'figcaption', 'figure', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'hr', 'i', 'img', 'kbd', 'li', 'main', 'mark', 'ol', 'p', 'pre', 's', 'section', 'small', 'span', 'strong', 'sub', 'summary', 'sup', 'table', 'tbody', 'td', 'th', 'thead', 'tr', 'u', 'ul'}
VOID={'br','hr','img','col'}
BLOCK={'script','style','iframe','object','embed','template','svg','math','textarea','noscript'}
ATTRS={'id','class','title','role','aria-label','aria-hidden','tabindex','open','colspan','rowspan','scope','alt','width','height','href','src','download','target','rel'}
def safe_url(value):
 clean=re.sub(r'[\x00-\x20\x7f]','',value)
 if clean.startswith(('//','\\')):return False
 try:return urlsplit(clean).scheme.lower() in ('','https','mailto')
 except ValueError:return False
def same_site_url(value):
 # Images must load under the site CSP (img-src 'self'): relative URLs only.
 clean=re.sub(r'[\x00-\x20\x7f]','',value)
 if not clean or clean.startswith(('/','\\')):return False
 try:u=urlsplit(clean)
 except ValueError:return False
 return not u.scheme and not u.netloc
class Sanitizer(HTMLParser):
 def __init__(self):super().__init__(convert_charrefs=True);self.out=[];self.block=[]
 def handle_starttag(self,tag,attrs):
  if self.block:
   if tag in BLOCK:self.block.append(tag)
   return
  if tag in BLOCK:self.block.append(tag);return
  if tag not in ALLOWED:return
  if tag=='img':
   a=dict(attrs)
   if not same_site_url(a.get('src') or ''):
    # External or missing image source: keep only the alternative text.
    alt=(a.get('alt') or '').strip()
    if alt:self.out.append('<span class="img-alt">'+escape(alt,quote=False)+'</span>')
    return
  safe=[]
  for k,v in attrs:
   if k not in ATTRS:continue
   v=v or ''
   if k in ('href','src') and not safe_url(v):continue
   if k=='target' and v!='_blank':continue
   if k=='rel':continue
   safe.append(' '+k+'="'+escape(v,quote=True)+'"')
  if tag=='a':safe.append(' rel="noopener noreferrer"')
  self.out.append('<'+tag+''.join(safe)+'>')
 def handle_startendtag(self,tag,attrs):
  if tag in BLOCK:return
  self.handle_starttag(tag,attrs)
  if tag not in VOID:self.handle_endtag(tag)
 def handle_endtag(self,tag):
  if self.block:
   if tag==self.block[-1]:self.block.pop()
   return
  if tag in ALLOWED and tag not in VOID:self.out.append('</'+tag+'>')
 def handle_data(self,data):
  if not self.block:self.out.append(escape(data,quote=False))
def sanitize(value):
 parser=Sanitizer();parser.feed(value);parser.close()
 if parser.block:raise ValueError('unclosed blocked element <'+parser.block[0]+'>: content after it would be dropped')
 return ''.join(parser.out)
def sanitize_batch(items):
 # Input: JSON array of {"name": str, "html": str}; output: array of sanitized strings.
 out=[]
 for item in items:
  try:out.append(sanitize(item['html']))
  except ValueError as e:raise ValueError(str(item.get('name','document'))+': '+str(e)) from e
 return out
def main(argv):
 if argv[1:]==['--batch']:
  try:result=sanitize_batch(json.loads(sys.stdin.read()))
  except ValueError as e:
   sys.stderr.write('sanitize-html: '+str(e)+'\n');return 1
  sys.stdout.write(json.dumps(result));return 0
 if argv[1:]:
  sys.stderr.write('usage: sanitize-html.py [--batch]\n');return 2
 sys.stdout.write(sanitize(sys.stdin.read()));return 0
if __name__=='__main__':sys.exit(main(sys.argv))
