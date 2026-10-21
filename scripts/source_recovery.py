"""Conservative official-document recovery. mofu / Copyright 2026 mofu."""
from __future__ import annotations
import datetime as dt, hashlib, re, time, urllib.parse, json
from pathlib import Path
from source_summary import normalized, INCIDENT, NON_PRIMARY, extract

CDN={'data.swcms.net','ssl4.eir-parts.net','www.release.tdnet.info','release.tdnet.info'}
try:REVIEWED=json.loads((Path(__file__).resolve().parents[1]/'data/official-source-alternatives.json').read_text(encoding='utf-8')).get('alternatives',{})
except FileNotFoundError:REVIEWED={}

def host(url):return (urllib.parse.urlsplit(url).hostname or '').lower()
def site(url):return host(url).removeprefix('www.')
def permitted(original,candidate):
 try:
  p=urllib.parse.urlsplit(candidate)
  return p.scheme=='https' and not p.username and not p.password and p.port in (None,443) and (site(original)==site(candidate) or host(candidate) in CDN or REVIEWED.get(original,{}).get('url')==candidate)
 except ValueError:return False
def title(text):return re.sub(r'[\W_]+','',normalized(text))

def linked_pdfs(original,page):
 if not page or not INCIDENT.search(page.heading):return []
 found=[]
 for href,label in page.links:
  url=urllib.parse.urldefrag(urllib.parse.urljoin(original,href))[0]
  if not urllib.parse.urlsplit(url).path.lower().endswith('.pdf') or not permitted(original,url):continue
  if re.search(r'決算|有価証券|保護方針|プライバシーポリシー|採用案内',label):continue
  found.append((url,label))
 unique={u:t for u,t in found}
 japanese=[u for u,t in unique.items() if '日本語' in t]
 if len(japanese)==1 and all(re.search(r'日本語|英語|English|韓国語|中国語',t,re.I) for t in unique.values()):return japanese
 return [u for u,t in unique.items() if INCIDENT.search(t) or (len(unique)==1 and re.search(r'PDF|詳細|こちら|お知らせ|ご報告',t,re.I))][:2]

def run(records,cache,indexes,state,fetch,allowed,checked_at,max_fetches=8,seconds=90,blocked_hosts=None):
 blocked_hosts=blocked_hosts or set()
 timestamp=dt.datetime.fromisoformat(checked_at).timestamp();deadline=time.monotonic()+seconds
 entries=state.setdefault('entries',{});stats={'fetches':0,'linkedDocuments':0,'matchedAlternatives':0,'pending':0,'failed':0}
 reports=[];seen=set();work=[]
 for r in records:
  source=r.get('source','')
  if r.get('sourceType')!='official' or source in seen or not (r.get('automaticallyCollected') or r.get('sourceChanged')):continue
  seen.add(source)
  if any(host(source)==h or host(source).endswith('.'+h) for h in NON_PRIMARY):continue
  doc=cache.get(source);page=(doc or {}).get('page')
  if doc and not page:continue
  pdfs=linked_pdfs(source,page)
  old=entries.get(source,{})
  if not doc or pdfs or source in REVIEWED:work.append((old.get('lastAttemptAt',''),r,doc,pdfs,old))
 # Round robin separately for failures and linked-document pages.
 work.sort(key=lambda x:(x[0],x[1]['source']))
 counts={'failed':0,'linked':0}
 def get(url,original):
  if url in cache:return cache[url]
  if stats['fetches']>=max_fetches or time.monotonic()>=deadline:return None
  if not permitted(original,url):return None
  if host(url) in blocked_hosts:return None
  stats['fetches']+=1
  try:
   result=fetch(url,allowed|{host(url)})
   if result.get('hash'):cache[url]=result
   return result
  except Exception:return None
 for _,r,doc,pdfs,old in work:
  source=r['source'];bucket='linked' if doc else 'failed'
  if counts[bucket]>=2 or stats['fetches']>=max_fetches or time.monotonic()>=deadline:continue
  entry={'source':source,'company':r['company'],'lastAttemptAt':checked_at,'state':'pending','candidates':[],'selected':None}
  if host(source) in blocked_hosts:
   entry.update(state='rate_limited',retryAfter=timestamp+6*3600);entries[source]=entry;reports.append(entry);continue
  if not doc and timestamp<float(old.get('retryAfter',0)):
   entry.update(old);reports.append(entry);continue
  counts[bucket]+=1
  if not doc and old.get('selected') and old.get('method')=='direct_official_pdf':
   pdfs=[old['selected']]
  selected=None;method=None
  mirror=REVIEWED.get(source,{})
  if mirror.get('company')==r['company'] and mirror.get('published')==r.get('published'):
   candidate_doc=get(mirror['url'],source)
   page=(candidate_doc or {}).get('page')
   if page and title(page.heading)==title(r['service']) and candidate_doc.get('summaryPublished')==r['published']:
    selected=(mirror['url'],candidate_doc);method='reviewed_official_mirror'
  for candidate in pdfs:
   if selected:break
   candidate_doc=get(candidate,source)
   text=(candidate_doc or {}).get('summaryText','')
   if candidate_doc and len(normalized(text))>=100 and INCIDENT.search(normalized(text)):
    selected=(candidate,candidate_doc);method=old.get('method') if not doc else 'direct_official_pdf';break
   entry['candidates'].append({'url':candidate,'reason':'linked_document_unreadable'})
  if not doc and not selected:
   parents=[x['url'] for x in indexes if site(x['url'])==site(source)]
   p=urllib.parse.urlsplit(source)
   parents.extend([urllib.parse.urlunsplit((p.scheme,p.netloc,p.path.rpartition('/')[0]+'/', '', '')),urllib.parse.urlunsplit((p.scheme,p.netloc,'/','',''))])
   candidates={}
   for index in dict.fromkeys(parents):
    if index==source:continue
    index_doc=get(index,source);page=(index_doc or {}).get('page')
    if not page:continue
    for href,label in page.links:
     url=urllib.parse.urldefrag(urllib.parse.urljoin(index,href))[0]
     if url!=source and permitted(source,url) and site(url)==site(source) and INCIDENT.search(label):candidates[url]=label
    if candidates:break
   # Discovery is not approval. Only one exact heading AND publication-date
   # match on the same official site can be used as a replacement.
   matches=[]
   for candidate,label in list(candidates.items())[:5]:
    entry['candidates'].append({'url':candidate,'reason':'official_candidate_needs_matching'})
    if title(label)!=title(r['service']):continue
    candidate_doc=get(candidate,source);page=(candidate_doc or {}).get('page')
    date=(candidate_doc or {}).get('summaryPublished')
    if page and title(page.heading)==title(r['service']) and date==r.get('published'):matches.append((candidate,candidate_doc))
   if len(matches)==1:selected=matches[0];method='same_title_and_date'
  if selected:
   url,replacement=selected
   # Do not replace the record or approve a new population. Evidence is attached
   # separately, and its own hash is used by both extractors.
   if not doc:
    doc={'url':source,'hash':None,'page':None};cache[source]=doc
   doc['summaryDocument']=replacement;doc['summaryEvidence']={'url':url,'linkedFrom':source,'method':method}
   entry.update(state='recovered',selected=url,method=method,documentHash=replacement['hash'])
   stats['linkedDocuments' if method=='direct_official_pdf' else 'matchedAlternatives']+=1
  else:
   entry['retryAfter']=timestamp+6*3600
   stats['pending']+=1
   if not doc:stats['failed']+=1
  entries[source]=entry;reports.append(entry)
 # Include all unresolved records in the report, even when work is deferred.
 report_sources={x['source'] for x in reports}
 for _,r,doc,pdfs,old in work:
  if r['source'] not in report_sources:
   reports.append(old or {'source':r['source'],'company':r['company'],'state':'deferred','selected':None,'candidates':[]})
 state['lastAttemptAt']=checked_at
 return stats,reports

def markdown(reports,ocr,checked_at):
 labels={'recovered':'公式資料を確認し、要約の根拠に採用','pending':'資料の照合・確認が必要','deferred':'次回以降に確認','rate_limited':'取得制限のため待機',
         'ocr_tools_not_available':'文字起こしの準備待ち','page_limit_requires_review':'ページ数が多いため手動確認が必要','ocr_requires_human_review':'文字起こし済み・原本との目視確認が必要','ocr_read_failed':'文字起こしに失敗'}
 lines=['# 公式資料の取得・再確認','',f'最終実行：{checked_at}','',
        '候補リンクは同じ事故と確認済みではありません。候補の件数は未掲載事故数ではありません。',
        '自動差し替えは、直接リンクされた公式PDF、同じ公式サイトの見出し・公表日が一致する資料、または事前確認した同一発表の公式掲載先に限定します。','']
 for entry in reports:
  lines.extend(['## '+entry.get('company','発表元'),'', '* 状態：'+labels.get(entry['state'],entry['state']),'* この資料の確認日時：'+entry.get('lastAttemptAt','未実行'),'* 元の出典：'+entry['source']])
  if entry.get('selected'):lines.append('* 要約に使った公式資料：'+entry['selected'])
  for c in entry.get('candidates',[]):lines.append('* 要確認の公式候補：'+c['url']+'（'+('リンク先本文を取得できませんでした' if c['reason']=='linked_document_unreadable' else '同じ事案か照合が必要')+'）')
  lines.append('')
 if ocr:
  lines.extend(['## 画像PDFの読取候補','', '以下はOCRによる確認補助です。誤読の可能性があるため、サイトの要約・件数には自動採用していません。',''])
  for e in ocr:
   lines.extend(['* '+e['source']+'：'+labels.get(e['state'],e['state'])])
   for p in e.get('passages',[]):lines.append('  * '+p['kind']+'：'+p['quote'])
 return '\n'.join(lines)+'\n'
