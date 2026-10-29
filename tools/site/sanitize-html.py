from html.parser import HTMLParser
from html import escape
from urllib.parse import urlsplit
import sys,re
ALLOWED=set('a abbr article aside b blockquote br caption code col colgroup dd del details div dl dt em figcaption figure h1 h2 h3 h4 h5 h6 hr i img kbd li main mark ol p pre s section small span strong sub summary sup table tbody td th thead tr u ul'.split())
VOID={'br','hr','img','col'}
BLOCK={'script','style','iframe','object','embed','template','svg','math','textarea','noscript'}
ATTRS={'id','class','title','role','aria-label','aria-hidden','tabindex','open','colspan','rowspan','scope','alt','width','height','href','src','download','target','rel'}
def safe_url(value):
 clean=re.sub(r'[\x00-\x20\x7f]','',value)
 if clean.startswith(('//','\\')):return False
 try:return urlsplit(clean).scheme.lower() in ('','https','mailto')
 except ValueError:return False
class Sanitizer(HTMLParser):
 def __init__(self):super().__init__(convert_charrefs=True);self.out=[];self.block=[]
 def handle_starttag(self,tag,attrs):
  if self.block:
   if tag in BLOCK:self.block.append(tag)
   return
  if tag in BLOCK:self.block.append(tag);return
  if tag not in ALLOWED:return
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
 parser=Sanitizer();parser.feed(value);parser.close();return ''.join(parser.out)
if __name__=='__main__':sys.stdout.write(sanitize(sys.stdin.read()))
