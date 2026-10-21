"""Source-bound extractive summaries; mofu / Copyright 2026 mofu.

Never infer exposure, sum counts, or promote an announcement to confirmed.
Quotes are bounded, normalized source passages, not generated assertions.
"""
from __future__ import annotations
import hashlib, re, unicodedata
from urllib.parse import urlsplit

VERSION = 'extractive-v1'
NON_PRIMARY = ('hatenadiary.jp', 'oricon.co.jp', 'rocket-boys.co.jp', 'lac.co.jp', 'cscloud.co.jp')
INCIDENT = re.compile(r'漏[え洩い]|流出|不正アクセス|不正ログイン|閲覧された|窃取')
PERSON = re.compile(r'お客[様さま]|お客様|利用者|ユーザー|会員|従業員|社員|応募者|契約者|寄附者|寄付者|取引先|患者|登録者|申込者')
ITEM = re.compile(r'氏名|住所|電話番号|メールアドレス|生年月日|パスワード|口座|カード番号|決済情報|購入履歴|寄附履歴|寄付履歴|性別|郵便番号')
COUNT = re.compile(r'(?:約|最大|延べ|のべ|計|合計)?\s*[0-9][0-9,]*(?:億[0-9,]*)?(?:万[0-9,]*)?\s*(?:件|名|人|アカウント|口)(?![年月日])')
SENSITIVE = re.compile(r'[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}|(?:0\d{1,4}[-ー－]\d{1,4}[-ー－]\d{3,4})|https?://|\b(?:\d[ -]?){13,19}\b')

def scale_passage(sentence):
    if re.search(r'二次被害|なりすましメール|不審メール|送信され|メール送信|送信件数|攻撃回数|アクセス回数|試行回数|検知件数|問い合わせ件数|1\s*人と\s*して|1\s*人とし|社員\s*1\s*名.*(?:ID|アカウント)',sentence):return False
    matches=list(COUNT.finditer(sentence))
    if not matches:return False
    if re.search(r'対象件数|対象人数|漏[え洩い]対象データ数|漏[え洩い]したアカウント数|対象\s*[:：]|(?:件数|人数)\s*[:：]',sentence):return True
    # Count must be near a leak statement or a quantity of personal information;
    # a count in a secondary-damage explanation is not the incident's scale.
    return any(re.search(r'漏[え洩い]|流出|個人情報',sentence[max(0,m.start()-40):min(len(sentence),m.end()+40)]) for m in matches)

def normalized(text):
    return re.sub(r'\s+', ' ', unicodedata.normalize('NFKC', text)).strip()

def audience_passage(text):
    return bool(re.search(r'対象者|対象とな(?:る|った)(?:お客|会員|方|人|利用)|対象範囲|対象期間|対象サービス|登録|ご利用|利用された|利用されて|予約|宿泊|契約|応募|保有する|管理する|お預かり',text)) and not re.search(r'ご連絡|ご説明|お詫び|通知いた|ご案内いた|お問い合わせ',text)

def extract(text, source, checked_at, document_hash):
    """Return only short, verbatim (NFKC/whitespace-normalized) source excerpts."""
    host=(urlsplit(source).hostname or '').lower()
    result={'version':VERSION,'source':source,'checkedAt':checked_at,
            'documentHash':document_hash,'state':'pending','reason':'matching_passage_not_found','passages':[]}
    if any(host==h or host.endswith('.'+h) for h in NON_PRIMARY):
        result['reason']='primary_source_required';return result
    body=normalized(text)
    if len(body)<100 or len(body)>250_000 or not INCIDENT.search(body):
        result['reason']='readable_incident_body_required';return result
    # Preserve complete sentences and their qualifiers. Long sentences/tables are
    # withheld instead of cutting a negation, number, or multiple population apart.
    sentences=[x.strip() for x in re.findall(r'[^。！？!?]+[。！？!?]?',body)]
    candidates=[]
    for pos,sentence in enumerate(sentences):
        if not 15<=len(sentence)<=240 or SENSITIVE.search(sentence):continue
        # Exclude contact, navigation, general guidance and third-party claims.
        if re.search(r'お問い合わせ|問合せ窓口|電話受付|受付時間|報道による|報道によれば|例えば|一般的に|被害を防ぐ|対策セミナー|ご注意ください|ご迷惑|ご心配|お詫び申し上げ|この記事をシェア|PDFをご参照',sentence):continue
        local=' '.join(sentences[max(0,pos-1):pos+1])
        if not INCIDENT.search(local):continue
        candidates.append((pos,sentence,local))
    used=set()
    rules=(
      ('audience',lambda s,c:PERSON.search(s) and audience_passage(s)),
      ('items',lambda s,c:ITEM.search(s) and re.search(r'情報|データ|項目|内容|漏[え洩い]|流出',s)),
      ('scale',lambda s,c:scale_passage(s)),
    )
    for kind,match in rules:
        # A field may share the same evidence as another field. Keep field labels
        # separate; the UI deduplicates repeated quotation text in its overview.
        matching=[s for _,s,c in candidates if match(s,c)]
        def rank(s):
            label={'audience':r'対象者|対象とな|対象範囲|対象のお客|登録された',
                   'items':r'漏[え洩い]した情報|情報項目|情報の項目|漏[え洩い]した.*(?:氏名|住所)',
                   'scale':r'対象件数|対象人数|漏[え洩い]件数|漏[え洩い]した.*[0-9]'}[kind]
            return (bool(re.search(label,s)),bool(INCIDENT.search(s)),-len(s))
        found=max(matching,key=rank) if matching else None
        if found:
            result['passages'].append({'kind':kind,'quote':found})
    if result['passages']:
        result['state']='ready' if len(result['passages'])==3 else 'partial'
        result['reason']=None
    return result

def apply(records, cache, checked_at):
    stats={'ready':0,'partial':0,'pending':0,'fetchFailed':0}
    # Called on every update, even for unchanged documents. Never carry a stale
    # excerpt over a failed fetch or replace an editorially reviewed assertion.
    for record in records:
        if record.get('sourceType')!='official' or not (record.get('automaticallyCollected') or record.get('sourceChanged')):continue
        record.pop('automaticSummary',None)
        doc=cache.get(record['source'])
        if not doc:
            result={'version':VERSION,'source':record['source'],'checkedAt':checked_at,'documentHash':None,
                    'state':'pending','reason':'source_fetch_failed','passages':[]}
            stats['fetchFailed']+=1
        else:
            effective=doc.get('summaryDocument') or doc
            page=effective.get('page')
            text=effective.get('summaryText') or (page.content if page else '')
            result=extract(text,record['source'],checked_at,effective.get('hash'))
            if effective.get('summaryReadError'):result['reason']='document_text_unreadable'
            if doc.get('summaryEvidence'):
                result['evidenceSource']=doc['summaryEvidence']['url']
                result['evidenceRelation']=doc['summaryEvidence']['method']
                result['linkedFrom']=doc['summaryEvidence']['linkedFrom']
        record['automaticSummary']=result
        stats[result['state']]+=1
    return stats
