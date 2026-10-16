"""Regression checks for real discovery omissions. Copyright 2026 mofu."""
import contextlib
import datetime as dt
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from bs4 import BeautifulSoup
import news_discovery as discovery


class DiscoveryRegression(unittest.TestCase):
    def test_japanese_charset_and_real_body_selector_priority(self):
        html = '<meta charset="shift_jis"><div class="inner">見出し</div><div id="cmsBody">' + '会員情報の漏えいについて。' * 15 + '<a href="https://issuer.example/notice.pdf">公式発表</a></div>'
        decoded = discovery.decode_html(html.encode('cp932'), 'utf-8')
        soup = BeautifulSoup(decoded, 'html.parser')
        body = discovery.news_body(soup, '.p-article-body, #cmsBody, .inner')
        self.assertIn('会員情報', body.get_text())
        self.assertEqual(body.select_one('a')['href'], 'https://issuer.example/notice.pdf')

    def test_deferred_articles_survive_feed_expiry_and_fetch_failure(self):
        today = dt.datetime.now(dt.timezone(dt.timedelta(hours=9))).date().isoformat()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'data').mkdir()
            config = {'feeds': [{'name': 'Regression', 'url': 'https://media.example/feed', 'articleHosts': ['media.example'], 'bodySelector': 'main'}], 'articleMaxAgeDays': 90, 'maxArticlesPerRun': 1, 'maxOfficialFetchesPerRun': 5}
            (root / 'data/news-sources.json').write_text(json.dumps(config), encoding='utf-8')
            (root / 'data/monitor-sources.json').write_text('{"documents":[],"indexes":[]}', encoding='utf-8')
            expired = False
            attempted = []

            def fetch(url, hosts=None):
                if url.endswith('/feed'):
                    entries = '' if expired else ''.join(f'<item><title>個人情報漏えい {i}</title><link>https://media.example/article?id={i}</link><pubDate>{today}</pubDate></item>' for i in (1, 2))
                    return url, f'<rss><channel>{entries}<item><title>一般ニュース</title></item></channel></rss>'.encode(), 'utf-8'
                attempted.append(url)
                raise OSError('temporary network failure')

            with patch.object(discovery, 'ROOT', root), patch.object(discovery, 'fetch', fetch), contextlib.redirect_stdout(io.StringIO()):
                first = discovery.run()
                self.assertEqual(len(first['queue']), 2)
                self.assertEqual(first['deferredNewsArticles'], 1)
                self.assertEqual(first['confirmed'], {})
                expired = True
                second = discovery.run()
                self.assertEqual(len(second['queue']), 2)
                self.assertEqual(second['deferredNewsArticles'], 0)
                self.assertEqual(len(set(attempted)), 2)
                self.assertEqual(second['pendingNewsArticles'], 2)
                self.assertEqual(second['confirmed'], {})

    def test_lost_customer_media_headlines_are_discovery_candidates(self):
        for title in ['お客さま情報を保存した外部記憶媒体の所在不明について', '顧客情報入りSSDを紛失', '患者情報を含むUSBメモリの紛失']:
            self.assertIsNotNone(discovery.KEY.search(title), title)
        self.assertIsNone(discovery.KEY.search('工事用工具の紛失について'))

    def test_archive_pagination_is_not_prematurely_completed(self):
        today = dt.datetime.now(dt.timezone(dt.timedelta(hours=9))).date().isoformat()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'data').mkdir()
            archive = {'name': 'archive', 'urlTemplate': 'https://media.example/{year}/{month:02d}', 'months': 2, 'maxPagesPerRun': 2, 'articleHosts': ['media.example'], 'bodySelector': 'main'}
            config = {'feeds': [], 'archives': [archive], 'articleMaxAgeDays': 1098, 'maxArticlesPerRun': 0, 'maxOfficialFetchesPerRun': 0}
            (root / 'data/news-sources.json').write_text(json.dumps(config), encoding='utf-8')
            (root / 'data/monitor-sources.json').write_text('{"documents":[],"indexes":[]}', encoding='utf-8')
            seen = []
            def fetch(url, hosts=None):
                seen.append(url)
                if '/page/2' in url:
                    title, pagination = '顧客情報入りSSDを紛失', ''
                else:
                    title, pagination = '一般ニュース', f'<a href="{url}/page/2">次へ</a>'
                return url, f'<dl><dt>{today}</dt><dd><a href="https://media.example/incident">{title}</a></dd></dl>{pagination}'.encode(), 'utf-8'
            with patch.object(discovery, 'ROOT', root), patch.object(discovery, 'fetch', fetch), contextlib.redirect_stdout(io.StringIO()):
                first = discovery.run()
                self.assertEqual(first['archiveCursors']['archive'], [])
                self.assertTrue(any(m['pending'] for m in first['archiveProgress']['archive'].values()))
                second = discovery.run()
                self.assertIn('https://media.example/incident', second['queue'])
                third = discovery.run()
                self.assertEqual(len(third['archiveCursors']['archive']), 1)
                old_key = third['archiveCursors']['archive'][0]
                old_base = third['archiveProgress']['archive'][old_key]['base']
                fourth = discovery.run()
                self.assertEqual(seen.count(old_base), 1)
                self.assertEqual(seen.count(old_base + '/page/2'), 1)
                self.assertEqual(fourth['successfulArchivePages'], 1)

    def test_new_suffix_company_identity(self):
        soup = BeautifulSoup('<main><h2>不正アクセスに関するお知らせ</h2><p>当社のサービスを運営する試験運輸株式会社は調査を行いました。</p></main>', 'html.parser')
        self.assertEqual(discovery.identity(soup, soup.main, '試験運輸の情報漏えい', None), '試験運輸株式会社')


if __name__ == '__main__':
    unittest.main()
