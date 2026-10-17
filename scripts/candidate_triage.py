"""Editorial candidate decisions with explicit evidence. Copyright 2026 mofu."""
from collections import Counter
import urllib.parse

CLOSED = {'covered', 'duplicate', 'out_of_scope'}
LABELS = {'covered':'掲載済み', 'duplicate':'同一事案の別記事', 'out_of_scope':'掲載対象外', 'fetch_failed':'取得失敗', 'needs_source_lookup':'公式発表の発見待ち', 'needs_review':'内容確認が必要', 'deferred':'未処理', 'reopened':'再確認が必要'}


def decision_for(candidate, decisions, records, documents):
    rule = decisions.get(candidate['newsSource'])
    by_id = {r['id']:r for r in records}
    if rule and rule.get('classification') in CLOSED:
        # An edited article or official correction must reopen the decision.
        same = candidate.get('title','') == rule.get('titleAtReview','') and candidate.get('reportedDate') == rule.get('reportedDateAtReview')
        ids = rule.get('recordIds', [])
        valid_records = all(i in by_id and by_id[i].get('verifiedAt') and by_id[i].get('status') not in ('announcement','needsReview') and not by_id[i].get('sourceChanged') for i in ids)
        evidence_current = all(not documents.get(u,{}).get('changed') for u in rule.get('evidenceUrls',[]))
        if same and valid_records and evidence_current and (ids or rule['classification']=='out_of_scope'):
            return {'classification':rule['classification'],'reason':rule['reason'],'recordIds':ids,'evidenceUrls':rule.get('evidenceUrls',[]),'reviewedAt':rule['reviewedAt']}
        return {'classification':'reopened','reason':'記事の見出し・日付または確認済み資料の状態が変わったため、過去の判断を適用していません。','recordIds':ids}
    reasons = ' '.join(x.get('reason','') for x in candidate.get('reasons',[]))
    if not candidate.get('lastCheckedAt') or reasons.startswith('Deferred:'):
        kind = 'deferred'
    elif any(x in reasons for x in ['HTTPError','URLError','OSError','TimeoutError','SSL','ConnectionReset']):
        kind = 'fetch_failed'
    elif 'No direct official announcement link found' in reasons:
        kind = 'needs_source_lookup'
    else:
        kind = 'needs_review'
    return {'classification':kind,'reason':'自動取得の結果による作業分類です。内容確認・掲載不要の判断は完了していません。','recordIds':[]}


def classify(candidates, decisions, records, documents):
    rows = [{**c, **decision_for(c, decisions, records, documents)} for c in candidates]
    counts = dict(Counter(x['classification'] for x in rows))
    active = [x for x in rows if x['classification'] not in CLOSED]
    return rows, counts, active


def markdown(rows, counts, stamp):
    def esc(s):
        return str(s).replace('\\','\\\\').replace('`','\\`').replace('[','\\[').replace(']','\\]').replace('\n',' ')
    lines = ['# 収集候補の確認状況', '', '確認日時: '+stamp, '', '記事単位の件数です。未掲載事故数・企業数ではありません。元の候補と理由は削除せず保存します。', '']
    for key, label in LABELS.items():
        lines.append(f'- {label}: {counts.get(key,0)}件')
    lines += ['', '## 確認待ち', '']
    for row in sorted(rows, key=lambda x:x.get('reportedDate',''), reverse=True):
        if row['classification'] in CLOSED:
            continue
        lines += ['### '+esc(row.get('title') or row['newsSource']), '', LABELS[row['classification']]+' / 報道・公表日: '+esc(row.get('reportedDate','')), '', '<'+urllib.parse.quote(row['newsSource'], safe=':/?=&%#')+'>', '', esc(row['reason']), '']
        for detail in row.get('reasons', []):
            lines += ['- 取得結果: '+esc(detail.get('reason',''))+' / <'+urllib.parse.quote(detail.get('url',row['newsSource']), safe=':/?=&%#')+'>']
        lines.append('')
    lines += ['## 判断を記録した候補', '']
    for row in rows:
        if row['classification'] not in CLOSED:
            continue
        lines += ['- '+LABELS[row['classification']]+' / '+esc(row.get('title',''))+' / '+esc(row['reason'])]
        lines += ['  - 元記事: <'+urllib.parse.quote(row['newsSource'],safe=':/?=&%#')+'>']
        lines += ['  - 根拠: <'+urllib.parse.quote(u,safe=':/?=&%#')+'>' for u in row.get('evidenceUrls',[])]
    return '\n'.join(lines)+'\n'
