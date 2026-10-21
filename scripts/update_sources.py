#!/usr/bin/env python3
"""情報漏洩チェック: public-source monitor. Author mofu, copyright 2026 mofu.
No LLM, paid API, leaked personal data, or automatic claims about affected people.
"""
from __future__ import annotations
import concurrent.futures, datetime as dt, hashlib, html, json, os, re, sys, urllib.error, urllib.parse, urllib.request
from html.parser import HTMLParser
from bs4 import BeautifulSoup
from news_discovery import run as discover_news, public_url, decode_html, KEY
from tdnet_discovery import run as discover_disclosures
from candidate_triage import classify, markdown as triage_markdown
from pathlib import Path
from source_summary import apply as summarize_sources
from ai_summary import run as ai_summaries
from source_recovery import run as recover_sources, markdown as recovery_markdown, permitted as permitted_recovery, REVIEWED as SOURCE_MIRRORS
from pdf_reading import run as read_image_pdfs
from news_discovery import scoped_date
from pypdf import PdfReader
import io
ROOT=Path(__file__).resolve().parents[1]
UTC=dt.timezone.utc
NOW=dt.datetime.now(UTC)
STAMP=NOW.isoformat(timespec='seconds')
KEYWORDS=KEY
NEWS=re.compile(r'ニュース|お知らせ|プレスリリース|重要な|news|press',re.I)
EXCLUDE_PATH=re.compile(r'/login|/signin|/signup|/search|/contact|/form|/privacy/?$|/policy/?$',re.I)

def read(path,default):
 try:return json.loads(path.read_text(encoding='utf-8-sig'))
 except FileNotFoundError:return default

def write(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 tmp=path.with_suffix(path.suffix+'.tmp')
 tmp.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 tmp.replace(path)

def digest(value):return hashlib.sha256(value if isinstance(value,bytes) else value.encode('utf-8')).hexdigest()
def clean(value):return re.sub(r'\s+',' ',html.unescape(value)).strip()
def host(url):return (urllib.parse.urlsplit(url).hostname or '').lower()
def normalize_url(url):
 p=urllib.parse.urlsplit(url);return urllib.parse.urlunsplit((p.scheme.lower(),p.netloc.lower(),p.path.rstrip('/'),p.query,''))

def canonicalize_announcements(items):
 """Collapse repeated discoveries of the same source URL into one announcement."""
 result={}
 for raw_url,announcement in items.items():
  source=announcement.get('source') or raw_url
  key=normalize_url(source)
  current=result.get(key)
  if current is None:
   result[key]=announcement
   continue
  # Keep the newest metadata and preserve all news references gathered for this URL.
  merged=dict(current)
  if announcement.get('fetchedAt','') >= current.get('fetchedAt',''):
   merged.update(announcement)
  news_sources=list(dict.fromkeys(current.get('newsSources',[])+announcement.get('newsSources',[])))
  if news_sources:merged['newsSources']=news_sources
  result[key]=merged
 return result

def safe_url(url,allowed):
 p=urllib.parse.urlsplit(url)
 if p.scheme!='https' or p.username or p.password or p.port not in (None,443):return False
 return host(url) in allowed

class RedirectGuard(urllib.request.HTTPRedirectHandler):
 def __init__(self,allowed):super().__init__();self.allowed=allowed
 def redirect_request(self,req,fp,code,msg,headers,newurl):
  public_url(newurl)
  if not safe_url(newurl,self.allowed):raise ValueError('Redirect to an unregistered host')
  return super().redirect_request(req,fp,code,msg,headers,newurl)

class Page(HTMLParser):
 def __init__(self):
  super().__init__(convert_charrefs=True);self.skip=0;self.title=[];self.h1=[];self.text=[];self.links=[];self.title_depth=0;self.h1_depth=0;self.anchor=None;self.dates=[];self.modified_dates=[];self.main_depth=0;self.main=[]
 def handle_starttag(self,tag,attrs):
  a=dict(attrs)
  if tag in ('script','style','nav','footer','noscript'):self.skip+=1
  if tag=='title':self.title_depth+=1
  if tag=='h1':self.h1_depth+=1
  if tag in ('main','article'):self.main_depth+=1
  if tag=='a':self.anchor={'href':a.get('href',''),'text':[]}
  if tag=='time' and a.get('datetime') and ('published' in a.get('class','').lower() or a.get('itemprop')=='datePublished'):self.dates.append(a['datetime'])
  if tag=='meta' and a.get('property','').lower()=='article:published_time':self.dates.append(a.get('content',''))
  if tag=='meta' and a.get('property','').lower()=='article:modified_time':self.modified_dates.append(a.get('content',''))
 def handle_endtag(self,tag):
  if tag in ('script','style','nav','footer','noscript') and self.skip:self.skip-=1
  if tag=='title':self.title_depth=max(0,self.title_depth-1)
  if tag=='h1':self.h1_depth=max(0,self.h1_depth-1)
  if tag in ('main','article'):self.main_depth=max(0,self.main_depth-1)
  if tag=='a' and self.anchor:self.links.append((self.anchor['href'],clean(' '.join(self.anchor['text']))));self.anchor=None
 def handle_data(self,value):
  if self.title_depth:self.title.append(value)
  if self.h1_depth:self.h1.append(value)
  if self.anchor:self.anchor['text'].append(value)
  if not self.skip:
   self.text.append(value)
   if self.main_depth:self.main.append(value)
 @property
 def heading(self):return clean(' '.join(self.h1)) or clean(' '.join(self.title))
 @property
 def content(self):return clean(' '.join(self.main or self.text))
 def date(self):
  candidates=self.dates
  for value in candidates:
   m=re.search(r'(20\d\d)[年/.-]\s*(\d{1,2})[月/.-]\s*(\d{1,2})',value)
   if m:
    try:return dt.date(*map(int,m.groups()))
    except ValueError:pass
  return None


def fetch(url,allowed):
 public_url(url)
 if not safe_url(url,allowed):raise ValueError('Unregistered URL')
 req=urllib.request.Request(url,headers={'User-Agent':'Mofu-Information-LeakCheck/1.0','Accept':'text/html,application/pdf,application/json;q=0.9'})
 with urllib.request.build_opener(RedirectGuard(allowed)).open(req,timeout=18) as response:
  length=response.headers.get('Content-Length')
  if length and int(length)>12_000_000:raise ValueError('Source exceeds size limit')
  data=response.read(12_000_001)
  if len(data)>12_000_000:raise ValueError('Source exceeds size limit')
  ctype=response.headers.get('Content-Type','');charset=response.headers.get_content_charset()
  if 'pdf' in ctype or data.startswith(b'%PDF'):
   result={'url':response.url,'hash':digest(data),'page':None,'http':response.status}
   try:
    pdf=PdfReader(io.BytesIO(data))
    if pdf.is_encrypted and not pdf.decrypt(''):
     result['pdfProtected']=True
     raise ValueError('Password-protected PDF requires review')
    result['pdfPages']=len(pdf.pages)
    if len(pdf.pages)>50:raise ValueError('PDF exceeds summary limits')
    parts=[];size=0
    for pdf_page in pdf.pages:
     text=pdf_page.extract_text() or '';size+=len(text)
     if size>250_000:raise ValueError('PDF text exceeds summary limits')
     parts.append(text)
    result['summaryText']='\n'.join(parts)
    if len(clean(result['summaryText']))<100:
     result['summaryReadError']=True
     result['pdfBytes']=data
   except Exception:
    result['summaryReadError']=True
    if not result.get('pdfProtected'):result['pdfBytes']=data
   return result
  if 'json' in ctype:return {'url':response.url,'json':json.loads(data.decode('utf-8-sig')),'http':response.status}
  if not charset:
   m=re.search(br'charset\s*=\s*["\']?([a-zA-Z0-9_-]+)',data[:4096]);charset=m.group(1).decode('ascii') if m else 'utf-8'
  decoded=decode_html(data,charset)
  page=Page();page.feed(decoded)
  soup=BeautifulSoup(decoded,'html.parser')
  # Restrict publication dates to metadata or the exact article's own news card.
  dates=[m.get('content','') for m in soup.select('meta[property="article:published_time"]')]
  for card in soup.select('article.item'):
   if any(normalize_url(urllib.parse.urljoin(response.url,a.get('href','')))==normalize_url(response.url) for a in card.select('a[href]')):
    date_node=card.select_one('.date')
    if date_node:dates.append(date_node.get_text(' ',strip=True))
  page.dates=dates
  body=soup.select_one('article#article') or soup.select_one('main') or soup.select_one('article')
  if body:
   for element in body.select('script,style,nav,footer,aside,.news_meta,.news_list'):
    element.decompose()
   page.main=[body.get_text(' ',strip=True)]
  if len(page.content)<80 or re.search(r'just a moment|access denied|enable javascript',page.heading,re.I):raise ValueError('Source body could not be read')
  publication=scoped_date(soup,body or soup)
  return {'url':response.url,'hash':digest(page.content),'page':page,'http':response.status,
          'summaryText':body.get_text('\n',strip=True) if body else page.content,
          'summaryPublished':publication.isoformat() if publication else None}


def main():
 news_result=discover_news()
 tdnet_result=discover_disclosures()
 news_result['confirmed'].update(tdnet_result['confirmed'])
 news_result['confirmedOfficialAnnouncements']=len(news_result['confirmed'])
 news_result['tdnet']={k:v for k,v in tdnet_result.items() if k not in ('pages','candidates','confirmed','errors')}
 news_result['errors'].extend(tdnet_result['errors'])
 config=read(ROOT/'data/monitor-sources.json',{})
 reviewed=read(ROOT/'data/reviewed-incidents.json',{})
 if not reviewed.get('incidents'):raise ValueError('Reviewed seed data is required')
 sources=list(config['documents']);indexes=config['indexes']
 # Revisit every outstanding published source, not only sources rediscovered in
 # today's RSS window. Reusing the normal fetch cache avoids duplicate requests.
 prior=read(ROOT/'data/source-state.json',{'announcements':{}})
 outstanding=list(prior.get('announcements',{}).values())+reviewed['incidents']
 seen_sources={x['url'] for x in sources}
 for record in outstanding:
  if record.get('sourceType')!='official':continue
  for source_url in [record['source']]+record.get('additionalSources',[]):
   if source_url not in seen_sources:
    sources.append({'company':record['company'],'url':source_url,'kind':'document'})
    seen_sources.add(source_url)

 # Fetch accepted alternate evidence on every run too. Relationships are
 # revalidated against the original page or reviewed title/date below.
 prior_recovery=read(ROOT/'data/source-recovery-state.json',{}).get('entries',{})
 known_originals={r.get('source') for r in outstanding}
 alternatives=[(u,e.get('selected'),e.get('company')) for u,e in prior_recovery.items() if e.get('state')=='recovered']
 alternatives.extend((u,e['url'],e['company']) for u,e in SOURCE_MIRRORS.items())
 for original,alternative,company in alternatives:
  if original in known_originals and alternative and alternative not in seen_sources and permitted_recovery(original,alternative):
   sources.append({'company':company,'url':alternative,'kind':'document'});seen_sources.add(alternative)

 for x in news_result.get('confirmed',{}).values():
  if x['source'] not in {r['url'] for r in sources}:sources.append({'company':x['company'],'url':x['source'],'kind':'document'})
 allowed={host(x['url']) for x in sources+indexes}|{'haveibeenpwned.com'}
 allowed|={('www.'+h if not h.startswith('www.') else h[4:]) for h in list(allowed) if h!='haveibeenpwned.com'}
 previous=read(ROOT/'data/source-state.json',{'documents':{},'announcements':{},'hibp':{}})
 approvals=read(ROOT/'data/reviewed-source-hashes.json',{})
 previous_docs=previous.get('documents',{})
 documents=dict(previous_docs);announcements=canonicalize_announcements({u:a for u,a in previous.get('announcements',{}).items() if a.get('dateSource')=='scoped-publication-date-v2'});errors=list(news_result.get('errors',[]));success=0;changes=0;cache={}
 def get(source):
  try:return source,fetch(source['url'],allowed),None
  except Exception as error:return source,None,str(error)[:160]
 # One attempt per source. 429 and access restrictions are recorded without bypass/retry.
 unique={x['url']:x for x in sources+indexes}
 with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
  for source,result,error in pool.map(get,unique.values()):
   url=source['url']
   if error:
    errors.append({'url':url,'error':error});continue
   success+=1;cache[url]=result
   if source.get('kind')!='document':continue
   old=previous_docs.get(url,{})
   baseline=approvals.get(url) or old.get('baselineHash') or result['hash']
   changed=result['hash']!=baseline
   if changed:changes+=1
   documents[url]={'baselineHash':baseline,'currentHash':result['hash'],'changed':changed,'lastCheckedAt':STAMP,'url':result['url']}
 # Discover related official announcements from the configured corporate sites.
 # A title match only creates an announcement, never a confirmed breach claim.
 candidates={}
 index_candidates={}
 for src in indexes:
  page=(cache.get(src['url']) or {}).get('page')
  if not page:continue
  for href,text in page.links:
   u=urllib.parse.urldefrag(urllib.parse.urljoin(src['url'],href))[0]
   if not safe_url(u,allowed) or host(u)!=host(src['url']) or EXCLUDE_PATH.search(urllib.parse.urlsplit(u).path):continue
   if KEYWORDS.search(text) and len(text)>8:candidates[u]={'url':u,'company':src['company'],'title':text}
   elif NEWS.search(text) and 1<len(text)<45 and u!=src['url'] and not index_candidates.get(src['url']):index_candidates[src['url']]={'url':u,'company':src['company']}
 for src in list(index_candidates.values())[:40]:
  try:
   result=cache.get(src['url']) or fetch(src['url'],allowed);page=result.get('page')
   if not page:continue
   for href,text in page.links:
    u=urllib.parse.urldefrag(urllib.parse.urljoin(src['url'],href))[0]
    if safe_url(u,allowed) and host(u)==host(src['url']) and KEYWORDS.search(text) and len(text)>8 and not EXCLUDE_PATH.search(urllib.parse.urlsplit(u).path):candidates[u]={'url':u,'company':src['company'],'title':text}
  except Exception as error:errors.append({'url':src['url'],'error':str(error)[:160]})
 cutoff=NOW.date()-dt.timedelta(days=config.get('discoveryMaxAgeDays',90))
 reviewed_urls={normalize_url(u) for r in reviewed['incidents'] for u in [r['source']]+r.get('additionalSources',[])}
 for src in list(candidates.values())[:35]:
  if src.get('kind')=='reference' or normalize_url(src['url']) in reviewed_urls:continue
  try:
   result=cache.get(src['url']) or fetch(src['url'],allowed);page=result.get('page')
   if not page or not KEYWORDS.search(page.heading) or normalize_url(result['url']) in reviewed_urls:continue
   date=page.date()
   if not date or not cutoff<=date<=NOW.date():continue
   announcement={'id':'auto-'+digest(normalize_url(result['url']))[:14],'company':src['company'],'service':page.heading[:240],'category':'公式発表・未整理','published':date.isoformat(),'updated':date.isoformat(),'status':'announcement','audience':'対象となる登録・利用条件は、出典の公式発表本文をご確認ください。自動取得では条件の整理・確認を完了していません。','items':[],'scale':'自動取得では確認していません。','note':'登録した監視先から、関連する公式発表のタイトル・URL・日付を自動取得しました。漏洩の有無、対象範囲、件数を推測して生成していません。','excluded':'対象外の情報も、自動では判断していません。','source':result['url'],'sourceType':'official','region':'国内企業','aliases':src['company'],'verifiedAt':None,'fetchedAt':STAMP,'automaticallyCollected':True,'dateSource':'scoped-publication-date-v2'}
   announcements[normalize_url(result['url'])]=canonicalize_announcements({**announcements,normalize_url(result['url']):announcement})[normalize_url(result['url'])]
  except Exception as error:errors.append({'url':src['url'],'error':str(error)[:160]})
 foreign=read(ROOT/'data/hibp-selected.json',[]);foreign_old={x['Name']:x for x in foreign}
 foreign_domains={x['Domain'] for x in foreign};foreign_changes={}
 try:
  all_hibp=fetch('https://haveibeenpwned.com/api/v3/breaches',allowed)['json']
  if not isinstance(all_hibp,list):raise ValueError('Invalid HIBP payload')
  selected=[x for x in all_hibp if x.get('Domain') in foreign_domains and x.get('IsVerified') is True and not any(x.get(k) for k in ['IsFabricated','IsSpamList','IsMalware','IsStealerLog','IsRetired'])]
  for x in selected:
   old=foreign_old.get(x['Name']);keys=['Description','DataClasses','BreachDate','PwnCount']
   if old and any(old.get(k)!=x.get(k) for k in keys):foreign_changes[x['Name']]=x
  selected_names={x['Name'] for x in selected}
  for name,old in foreign_old.items():
   if name not in selected_names:foreign_changes[name]=dict(old,Description='The source no longer passes the selected verification criteria. Review the current source before relying on the old summary.')
  foreign=selected;success+=1
 except Exception as error:errors.append({'url':'https://haveibeenpwned.com/api/v3/breaches','error':str(error)[:160]})
 for x in news_result.get('confirmed',{}).values():
  if normalize_url(x['source']) in reviewed_urls:continue
  announcement={'id':'news-'+digest(normalize_url(x['source']))[:14],'company':x['company'],'service':x['title'],'category':'公式発表・未整理','published':x['published'],'updated':x['published'],'status':'announcement','audience':'ニュースを手がかりに公式発表を確認しました。対象となる登録・利用条件の要約は未整理です。公式発表の本文をご確認ください。','items':[],'scale':'自動取得では確認していません。','note':'発表元の表示、本文、日付をニュースの参照先と照合しました。漏洩の有無・対象範囲・件数を自動で判定するものではありません。','excluded':'対象外の情報は推測していません。','source':x['source'],'sourceType':'official','region':'国内向け報道から発見','aliases':x['company'],'verifiedAt':None,'fetchedAt':x['lastCheckedAt'],'automaticallyCollected':True,'dateSource':'scoped-publication-date-v2','discoveredViaNews':x.get('discoverySource')!='TDnet','discoverySource':x.get('discoverySource','news'),'newsSources':x['newsSources']}
  key=normalize_url(x['source'])
  announcements[key]=canonicalize_announcements({**announcements,key:announcement})[key]

 for a in announcements.values():
  if a.get('discoverySource')=='TDnet':
   a['audience']='公式の適時開示で関連発表を確認しました。対象となる登録・利用条件の要約は未整理です。公式資料の本文をご確認ください。'
   a['note']='適時開示一覧の発表企業・見出し・日付とPDFを照合しました。漏洩の有無・対象範囲・件数の自動判定はしていません。'
   a['region']='国内の適時開示から発見'
 records=[]
 for source_record in reviewed['incidents']:
  r=dict(source_record)
  if r['sourceType']=='official':
   doc=documents.get(r['source'],{})
   related=[a for a in announcements.values() if a['company']==r['company'] and a['published']>r['updated']]
   changed=any(documents.get(u,{}).get('changed') for u in [r['source']]+r.get('additionalSources',[]))
   if changed or related:
    r.update(status='needsReview',audience='掲載後に出典の内容変更を検知しました。旧対象条件の表示を一時停止しています。最新の公式発表本文を確認してください。',items=[],scale='出典更新のため再確認が必要です。',note='変更を検知したことだけでは、漏洩の確認・否定や対象範囲の変更を判断できません。古い要約は、再確認が完了するまで表示していません。',excluded='',sourceChanged=True)
   if related:r['additionalSources']=list(dict.fromkeys(r.get('additionalSources',[])+[a['source'] for a in related]))
   r['sourceCheckedAt']=doc.get('lastCheckedAt')
  elif r['id'].removeprefix('hibp-') in foreign_changes:
   x=foreign_changes[r['id'].removeprefix('hibp-')]
   r.update(status='needsReview',audience='HIBPの原データが更新されました。旧要約の表示を一時停止しています。出典の最新原文を確認してください。',items=[],scale='元データ更新のため再確認が必要です。',note='自動取得で日本の対象者を判定していません。',excluded='',originalDescription=clean(re.sub('<[^>]+>',' ',x['Description'])),sourceChanged=True)
  records.append(r)
 existing={normalize_url(u) for r in records for u in [r['source']]+r.get('additionalSources',[])}
 records.extend(a for u,a in announcements.items() if normalize_url(a['source']) not in existing)
 # Retain only the last three calendar years; HIBP import dates do not make old incidents recent.
 jst_today=NOW.astimezone(dt.timezone(dt.timedelta(hours=9))).date()
 try:retention_start=jst_today.replace(year=jst_today.year-3)
 except ValueError:retention_start=jst_today.replace(year=jst_today.year-3,day=28)
 records=[r for r in records if (r.get('eventDate','') if r['sourceType']=='hibp' else r.get('updated',r['published']))>=retention_start.isoformat()]
 recovery_state=read(ROOT/'data/source-recovery-state.json',{})
 recovery_stats,recovery_report=recover_sources(records,cache,indexes,recovery_state,fetch,allowed,STAMP,
  blocked_hosts={host(e.get('url','')) for e in errors if '429' in e.get('error','')})
 ocr_state=read(ROOT/'data/pdf-reading-state.json',{})
 ocr_stats,ocr_report=read_image_pdfs(cache,ocr_state,STAMP)
 summary_stats=summarize_sources(records,cache,STAMP)
 ai_state=read(ROOT/'data/ai-summary-state.json',{})
 ai_stats=ai_summaries(records,cache,ai_state,STAMP)
 # Recalculate extraction coverage after AI supplements; never change incident status.
 summary_stats.update({key:sum(r.get('automaticSummary',{}).get('state')==key for r in records) for key in ('ready','partial','pending')})
 write(ROOT/'data/source-recovery-state.json',recovery_state)
 write(ROOT/'data/pdf-reading-state.json',ocr_state)
 write(ROOT/'data/ai-summary-state.json',ai_state)
 write(ROOT/'data/source-recovery-report.json',{'checkedAt':STAMP,'recovery':recovery_report,'ocr':ocr_report})
 (ROOT/'data/source-recovery-report.md').write_text(recovery_markdown(recovery_report,ocr_report,STAMP),encoding='utf-8')
 status='complete' if not errors else ('partial' if success else 'failed')
 old_status=read(ROOT/'dist/update-status.json',{})
 update={'status':status,'lastAttemptAt':STAMP,'lastSuccessAt':STAMP if status=='complete' else old_status.get('lastSuccessAt'),'lastPartialSuccessAt':STAMP if status=='partial' else old_status.get('lastPartialSuccessAt'),'successfulFetches':success,'failedFetches':len(errors),'changedReviewedSources':changes,'automaticAnnouncements':sum(r.get('automaticallyCollected',False) for r in records),'watchedDocumentCount':len(sources),'watchedIndexCount':len(indexes),'schedule':'毎時（GitHub Actionsの遅延・停止があり得ます）','errors':errors,'fullyComprehensive':False,'summaryReviewedAt':reviewed.get('checkedAt'),'cloudRun':os.environ.get('GITHUB_ACTIONS')=='true','retentionStart':retention_start.isoformat(),'newsDiscovery':{k:v for k,v in news_result.items() if k not in ('queue','confirmed','errors','archiveProgress')}}
 update['automaticSummaries']=summary_stats
 update['aiSummary']=ai_stats
 update['sourceRecovery']={**recovery_stats,'report':'data/source-recovery-report.md','ocr':ocr_stats}
 write(ROOT/'data/source-state.json',{'documents':documents,'announcements':announcements,'hibp':{x['Name']:digest(json.dumps(x,sort_keys=True)) for x in foreign},'lastAttemptAt':STAMP})
 followups=[{'newsSource':u,'title':q.get('title',''),'reportedDate':q['published'],'publisher':q['publisher'],'firstSeenAt':q.get('firstSeenAt'),'lastCheckedAt':q.get('lastCheckedAt'),'attempts':q.get('attempts',0),'reasons':q['pending']} for u,q in news_result.get('queue',{}).items() if q.get('pending')]

 followups.extend({'newsSource':u,'title':q['title'],'reportedDate':q['published'],'publisher':'TDnet','firstSeenAt':q['firstSeenAt'],'lastCheckedAt':q.get('lastCheckedAt'),'reasons':[{'url':u,'reason':q.get('error','Deferred: disclosure PDF has not been checked yet')}]} for u,q in tdnet_result['candidates'].items() if q.get('error') or not q.get('lastCheckedAt'))

 decisions=read(ROOT/'data/candidate-review-decisions.json',{}).get('reviews',{})
 all_candidates={x['newsSource']:x for x in followups}
 for u,q in news_result.get('queue',{}).items():
  if u in decisions and u not in all_candidates:
   all_candidates[u]={'newsSource':u,'title':q.get('title',''),'reportedDate':q['published'],'publisher':q['publisher'],'firstSeenAt':q.get('firstSeenAt'),'lastCheckedAt':q.get('lastCheckedAt'),'reasons':q.get('pending',[])}
 triaged,triage_counts,followups=classify(list(all_candidates.values()),decisions,records,documents)
 baseline=read(ROOT/'data/candidate-review-baseline.json',{}).get('candidates',[])
 baseline_rows,baseline_counts,baseline_active=classify(baseline,decisions,records,documents)
 (ROOT/'data/coverage-review.md').write_text(triage_markdown(triaged,triage_counts,STAMP),encoding='utf-8')
 report={'checkedAt':STAMP,'fullyComprehensive':False,'completeHistoricalBackfill':False,'retentionStart':retention_start.isoformat(),'discovery':{k:v for k,v in news_result.items() if k not in ('queue','confirmed','errors','archiveProgress')},'sourceErrors':errors,'candidateTriageCounts':triage_counts,'baselineReview':{'candidateCount':len(baseline),'counts':baseline_counts,'unresolved':len(baseline_active)},'candidateTriage':triaged,'followupNewsCandidates':followups,'note':'候補記事は未確認・重複・事故以外の記事を含みます。候補数を未掲載事故数とは扱いません。RSS外になった候補と処理上限による保留も再確認します。3年分の全事案を収集済みとするものではありません。'}
 write(ROOT/'data/coverage-report.json',report)
 update['coverageReport']='data/coverage-report.json'
 update['candidateTriageCounts']=triage_counts
 update['reviewBoard']='data/coverage-review.md'
 update['unresolvedNewsCandidates']=len(followups)
 update['deferredNewsCandidates']=sum(x['classification']=='deferred' for x in followups)
 if os.environ.get('GITHUB_ACTIONS')=='true' and (errors or followups):
  print(f"::warning title=収集確認が必要です::取得エラー {len(errors)} 件、未着手の記事 {update['deferredNewsCandidates']} 件、追跡が必要な記事 {len(followups)} 件。data/coverage-report.json を確認してください。候補記事数は事故数ではありません。")

 tdnet_summary=f"TDnet: 一覧 {tdnet_result['listPagesChecked']} ページ確認、未取得一覧 {tdnet_result['pendingListPages']} ページ、確認待ち資料 {tdnet_result['pendingDocuments']} 件。"
 summary=os.environ.get('GITHUB_STEP_SUMMARY')
 if summary:
  with open(summary,'a',encoding='utf-8') as f:
   f.write(f"## 収集状況（網羅性の保証ではありません）\n\n{tdnet_summary}\n\nRSS: {news_result.get('successfulFeeds',0)}/{news_result.get('feedCount',0)}、月別記事ページ: {news_result.get('successfulArchivePages',0)}\n\n記事候補: {news_result.get('newsCandidates',0)}、今回確認: {news_result.get('newsArticlesChecked',0)}、未着手: {update['deferredNewsCandidates']}、追跡が必要な記事: {len(followups)}\n\n公式資料の取得失敗等: {len(errors)}。追跡理由は data/coverage-report.json を参照してください。候補記事数は事故数ではありません。\n")
 # Retain the editorial HIBP baseline. Raw updates must not silently approve a Japanese summary.
 write(ROOT/'dist/incidents.json',{**reviewed,'version':reviewed.get('version','1.3.4'),'incidents':records,'automaticUpdateStatus':status,'automaticLastAttemptAt':STAMP})
 write(ROOT/'dist/update-status.json',update)
 print(json.dumps({k:v for k,v in update.items() if k!='errors'},ensure_ascii=False))
 if ai_stats['status'] in ('not_configured','paused'):
  print('::warning title=AI補助の状態::'+ai_stats['status']+'。本文の通常抽出は継続します。設定手順は README.md を参照してください。')
 if not success:raise SystemExit(1)

if __name__=='__main__':main()

