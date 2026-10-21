# mofu / Copyright 2026 mofu
from pathlib import Path
import json,urllib.parse
root=Path(__file__).resolve().parents[1]
data=json.loads((root/'dist/incidents.json').read_text(encoding='utf-8-sig'))
records=data['incidents'];ids=set();known={'confirmed','possible','mixed','access','denied','catalogue','announcement','needsReview'}
for r in records:
 assert r['id'] not in ids,'Duplicate incident ID';ids.add(r['id'])
 assert r['status'] in known,'Unknown status'
 assert urllib.parse.urlsplit(r['source']).scheme=='https','Invalid source'
 assert isinstance(r['items'],list) and r['company'] and r['audience'],'Missing fields'
 if r.get('automaticallyCollected'):
  assert r['status']=='announcement' and not r.get('verifiedAt'),'Automatic source must not claim editorial verification'
  assert not r['items'],'Unreviewed announcement cannot invent exposed data'
 if r.get('sourceChanged'):assert r['status']=='needsReview' and not r['items'],'Changed source must withdraw old assertions'
 if 'automaticSummary' in r:
  from source_summary import SENSITIVE, VERSION
  import datetime,re
  summary=r['automaticSummary']
  assert summary['version']==VERSION and summary['source']==r['source'],'Summary evidence must match this official source'
  assert r['sourceType']=='official' and (r.get('automaticallyCollected') or r.get('sourceChanged'))
  datetime.datetime.fromisoformat(summary['checkedAt'])
  if summary.get('evidenceSource'):
   from source_recovery import permitted
   assert permitted(r['source'],summary['evidenceSource']) and summary['linkedFrom']==r['source']
   assert summary['evidenceRelation'] in ('direct_official_pdf','same_title_and_date','reviewed_official_mirror')
  if summary.get('ai'):
   from ai_summary import MODEL,VERSION as AI_VERSION
   assert summary['ai']['provider']=='Gemini' and summary['ai']['model']==MODEL and summary['ai']['version']==AI_VERSION
   assert set(summary['ai']['kinds'])<=set(p['kind'] for p in summary['passages'])

  assert summary['state'] in ('ready','partial','pending')
  passages=summary['passages'];kinds=set()
  for p in passages:
   assert p['kind'] in ('audience','items','scale') and p['kind'] not in kinds
   kinds.add(p['kind'])
   assert isinstance(p['quote'],str) and 15<=len(p['quote'])<=240 and not SENSITIVE.search(p['quote'])
  assert len(kinds)==(3 if summary['state']=='ready' else 0 if summary['state']=='pending' else len(kinds))
  if summary['state']=='partial':assert 0<len(kinds)<3
  if passages:assert re.fullmatch('[a-f0-9]{64}',summary['documentHash']) and summary['reason'] is None
for name in ('index.html','app.js','style.css','help.html','about.html','update-status.json'):
 assert (root/'dist'/name).is_file(),f'Missing asset {name}'
status=json.loads((root/'dist/update-status.json').read_text(encoding='utf-8-sig'))
assert status['status'] in ('complete','partial','failed')
assert status['fullyComprehensive'] is False
assert (status['status']=='complete') == (status['failedFetches']==0)
print(f'Validated {len(records)} records; source check: {status["status"]}')

service_names=json.loads((root/'dist/service-names.json').read_text(encoding='utf-8-sig'))
assert service_names.get('author')=='mofu'
for key in ('byId','bySource'):
 assert isinstance(service_names.get(key),dict),'Invalid service name index'
 for reference,entry in service_names[key].items():
  assert isinstance(reference,str) and reference,'Missing service reference'
  if key=='bySource':assert urllib.parse.urlsplit(reference).scheme=='https','Invalid service source'
  assert isinstance(entry.get('names'),list) and all(isinstance(x,str) and 0<len(x)<=100 for x in entry['names']),'Invalid service names'
  assert isinstance(entry.get('scope'),str) and len(entry['scope'])<=400,'Invalid service scope'
  assert entry.get('evidence') and all(urllib.parse.urlsplit(u).scheme=='https' for u in entry['evidence']),'Missing official service evidence'
print('Validated source-scoped service names and registration scopes')
