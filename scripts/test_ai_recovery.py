"""mofu © 2026: grounded AI, quotas, safe recovery and OCR review boundaries."""
import datetime as dt, unittest
from types import SimpleNamespace
from unittest.mock import patch
import ai_summary as ai
import source_recovery as recovery
from source_summary import apply
import pdf_reading

STAMP='2026-10-21T12:00:00+00:00'
BODY='当社の不正アクセスにより、2026年までに登録された会員情報が流出した可能性があります。対象件数:最大で延べ120人の個人情報です。漏えいした情報項目は氏名、住所です。本件の調査を継続しております。今後判明した内容は公式サイトでお知らせします。'
QUOTES=[{'kind':'scale','quote':'対象件数:最大で延べ120人の個人情報です。'}]
def record(source='https://example.com/notice'):
 return {'id':source,'sourceType':'official','source':source,'automaticallyCollected':True,'status':'announcement','verifiedAt':None,'items':[],'company':'テスト株式会社','service':'不正アクセスのお知らせ','published':'2026-10-21','automaticSummary':{'source':source,'passages':[],'state':'pending','reason':'matching_passage_not_found'}}
def document(text=BODY):return {'hash':'a'*64,'summaryText':text,'page':None}
ENV={'GEMINI_API_KEY':'synthetic-test-value','GEMINI_FREE_TIER_CONFIRMED':'true'}

class AI(unittest.TestCase):
 def test_missing_key_or_free_confirmation_never_calls(self):
  for env in ({},{'GEMINI_API_KEY':'test'}):
   def no_call(*args):self.fail('API must not be invoked')
   self.assertEqual(ai.run([record()],{}, {},STAMP,no_call,env)['status'],'not_configured')
 def test_exact_evidence_only(self):
  self.assertEqual(ai.validate({'passages':QUOTES},BODY),QUOTES)
  for quote in ['対象件数:最大で延べ999人の個人情報です。','対象件数:最大で延べ1200人の個人情報です。']:
   with self.assertRaises(ai.AIError):ai.validate({'passages':[{'kind':'scale','quote':quote}]},BODY)
  with self.assertRaises(ai.AIError):ai.validate({'passages':[{'kind':'scale','quote':'なりすましメール約9000件が送信されました。'}]},BODY+'なりすましメール約9000件が送信されました。')
 def test_redaction_keeps_boundaries(self):
  body=ai.safe_body(BODY+'\n担当者名 田中太郎\n連絡先test@example.com 電話03-1234-5678\n'+BODY)
  self.assertNotIn('田中太郎',body);self.assertNotIn('@example.com',body);self.assertNotIn('03-1234',body)
  with self.assertRaises(ai.AIError):ai.validate({'passages':[{'kind':'items','quote':'漏えいした情報項目は氏名、住所です。[連絡先等を削除]'}]},body)
 def test_cache_and_no_incident_promotion(self):
  r=record();state={};calls=[]
  def call(body,key):calls.append(1);return QUOTES
  result=ai.run([r],{r['source']:document()},state,STAMP,call,ENV)
  self.assertEqual(result['acceptedSources'],1);self.assertEqual(len(calls),1)
  second=record();ai.run([second],{second['source']:document()},state,STAMP,call,ENV)
  self.assertEqual(len(calls),1);self.assertEqual(second['automaticSummary']['passages'],QUOTES)
  self.assertEqual(second['status'],'announcement');self.assertIsNone(second['verifiedAt']);self.assertEqual(second['items'],[])
 def test_budget_and_quota_stop(self):
  rs=[record('https://example.com/'+str(i)) for i in range(4)];cache={r['source']:document() for r in rs};calls=[]
  def call(*args):calls.append(1);return QUOTES
  x=ai.run(rs,cache,{},STAMP,call,ENV);self.assertEqual(len(calls),2);self.assertEqual(x['deferredSources'],2)
  calls.clear();state={'requestTimes':[dt.datetime.fromisoformat(STAMP).timestamp()]*15}
  ai.run([record()],cache,state,STAMP,call,ENV);self.assertFalse(calls)
  def quota(*args):calls.append(1);raise ai.AIError('quota_exhausted')
  state={};x=ai.run(rs,cache,state,STAMP,quota,ENV)
  self.assertEqual(x['status'],'paused');self.assertEqual(len(calls),1)
  ai.run(rs,cache,state,STAMP,quota,ENV);self.assertEqual(len(calls),1)

class Recovery(unittest.TestCase):
 def test_link_requires_official_relation(self):
  page=SimpleNamespace(heading='不正アクセスのお知らせ',links=[('/notice.pdf','詳細PDF'),('https://evil.example/steal.pdf','不正アクセスのお知らせ')])
  self.assertEqual(recovery.linked_pdfs('https://example.com/notice',page),['https://example.com/notice.pdf'])
  self.assertFalse(recovery.permitted('https://example.com/a','https://example.com@evil.example/a.pdf'))
  self.assertFalse(recovery.permitted('https://example.com/a','http://example.com/a.pdf'))
  page.links=[('/a_ja.pdf','【PDF】日本語'),('/a_en.pdf','【PDF】英語 (English)')]
  self.assertEqual(recovery.linked_pdfs('https://example.com/notice',page),['https://example.com/a_ja.pdf'])
 def test_direct_linked_pdf_is_separate_evidence(self):
  r=record();page=SimpleNamespace(heading=r['service'],links=[('/notice.pdf','詳細PDF')],content='不正アクセスのお知らせ 詳細はPDFをご参照ください。')
  cache={r['source']:{'hash':'b'*64,'page':page}}
  stats,reports=recovery.run([r],cache,[],{},lambda url,allowed:document(),{'example.com'},STAMP)
  self.assertEqual(stats['linkedDocuments'],1)
  apply([r],cache,STAMP)
  self.assertEqual(r['automaticSummary']['evidenceSource'],'https://example.com/notice.pdf')
  self.assertEqual(r['automaticSummary']['documentHash'],'a'*64)
  self.assertEqual(r['status'],'announcement')
 def test_same_heading_wrong_date_not_accepted(self):
  r=record();index=SimpleNamespace(heading='お知らせ',links=[('/other','不正アクセスのお知らせ')])
  candidate=SimpleNamespace(heading=r['service'],content=BODY,links=[])
  def fetch(url,allowed):
   if url.endswith('/other'):return {'hash':'c'*64,'page':candidate,'summaryPublished':'2026-10-20'}
   return {'hash':'b'*64,'page':index}
  stats,reports=recovery.run([r],{},[],{},fetch,{'example.com'},STAMP)
  self.assertIsNone(reports[0]['selected']);self.assertEqual(stats['matchedAlternatives'],0)
 def test_429_and_backoff_do_not_retry(self):
  r=record();calls=[]
  recovery.run([r],{},[],{},lambda *args:calls.append(1),{'example.com'},STAMP,blocked_hosts={'example.com'})
  self.assertFalse(calls)
  state={'entries':{r['source']:{'source':r['source'],'company':r['company'],'state':'pending','retryAfter':9999999999,'candidates':[]}}}
  recovery.run([r],{},[],state,lambda *args:calls.append(1),{'example.com'},STAMP)
  self.assertFalse(calls)
 def test_ocr_never_populates_public_summary(self):
  r=record();cache={r['source']:{'hash':'d'*64,'page':None,'summaryReadError':True,'pdfBytes':b'%PDF','pdfPages':1}}
  with patch('pdf_reading.shutil.which',return_value=None):
   stats,report=pdf_reading.run(cache,{},STAMP)
  self.assertEqual(report[0]['state'],'ocr_tools_not_available')
  apply([r],cache,STAMP);self.assertEqual(r['automaticSummary']['passages'],[])

if __name__=='__main__':unittest.main()
