"""mofu / Copyright 2026 mofu: regression checks for source-bound summaries."""
import unittest
from source_summary import extract, apply, normalized, scale_passage

class SummaryChecks(unittest.TestCase):
 def summary(self,body):
  return extract('不正アクセスに関するお知らせ。'+body+'本件の調査を継続しております。'*8,'https://example.com/notice','2026-10-21T00:00:00Z','a'*64)
 def test_qualifiers_and_denial_preserved(self):
  text='漏えいした可能性のある対象件数:最大で延べ8,853,839件の個人情報です。'
  x=self.summary(text)
  self.assertEqual(next(p['quote'] for p in x['passages'] if p['kind']=='scale'),text)
  denied='パスワードは漏えいしていないことを確認しました。'
  self.assertIn(denied,[p['quote'] for p in self.summary(denied)['passages']])
 def test_contact_and_secondary_counts_withheld(self):
  for text in ['なりすましメール約9000件が送信されました。','二次被害は会員様1名のアカウントへの不正ログインです。','漏えい対象者数は同一の会員を1人として集計した人数です。','社員1名のIDが不正利用され、個人情報流出の可能性があります。']:
   self.assertFalse(scale_passage(text),text)
  x=self.summary('漏えい対象者10名の問い合わせ先はtest@example.comです。')
  self.assertFalse(x['passages'])
 def test_not_invented_or_promoted(self):
  body='2026年までに登録された会員情報が流出した可能性があります。漏えい対象者:最大120人です。漏えいした情報項目は氏名、住所です。'
  x=self.summary(body)
  self.assertEqual({p['kind'] for p in x['passages']},{'audience','items','scale'})
  for p in x['passages']:self.assertIn(p['quote'],normalized('不正アクセスに関するお知らせ。'+body+'本件の調査を継続しております。'*8))
  r={'sourceType':'official','automaticallyCollected':True,'status':'announcement','items':[],'verifiedAt':None,'source':'https://example.com/notice','automaticSummary':x}
  stats=apply([r],{},'new-attempt')
  self.assertEqual(r['automaticSummary']['passages'],[])
  self.assertEqual(r['automaticSummary']['reason'],'source_fetch_failed')
  self.assertEqual(r['status'],'announcement');self.assertEqual(r['items'],[])
  self.assertEqual(stats['fetchFailed'],1)
 def test_aggregator_not_official_evidence(self):
  x=extract('個人情報が漏えいした対象者は100人です。'*10,'https://piyolog.hatenadiary.jp/entry/1','now','a'*64)
  self.assertEqual(x['reason'],'primary_source_required');self.assertFalse(x['passages'])

if __name__=='__main__':unittest.main()
