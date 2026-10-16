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
for name in ('index.html','app.js','style.css','help.html','about.html','update-status.json'):
 assert (root/'dist'/name).is_file(),f'Missing asset {name}'
status=json.loads((root/'dist/update-status.json').read_text(encoding='utf-8-sig'))
assert status['status'] in ('complete','partial','failed')
assert status['fullyComprehensive'] is False
assert (status['status']=='complete') == (status['failedFetches']==0)
print(f'Validated {len(records)} records; source check: {status["status"]}')
