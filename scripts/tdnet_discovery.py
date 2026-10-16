"""Read public TDnet disclosures, preserving pagination/backlog. Copyright 2026 mofu."""
import datetime as dt
import hashlib
import json
import re
import time
import urllib.parse as urls
from pathlib import Path
from bs4 import BeautifulSoup
from news_discovery import fetch, decode_html, KEY, pdf_announcement
ROOT = Path(__file__).resolve().parents[1]
HOST = 'www.release.tdnet.info'
HOME = 'https://www.release.tdnet.info/inbs/I_main_00.html'


def parse_list(raw, url):
    soup = BeautifulSoup(decode_html(raw), 'html.parser')
    match = re.search(r'I_list_\d{3}_(20\d{6})\.html$', url)
    if not match:
        raise ValueError('Unrecognized disclosure date URL')
    day = dt.datetime.strptime(match[1], '%Y%m%d').date().isoformat()
    if not soup.select_one('#main-list-table') and '開示された情報はありません' not in soup.get_text():
        raise ValueError('Disclosure list format needs review')
    rows = []
    for row in soup.select('#main-list-table tr'):
        title, company = row.select_one('.kjTitle a[href]'), row.select_one('.kjName')
        if title is None or company is None or not KEY.search(title.get_text(' ', strip=True)):
            continue
        source = urls.urljoin(url, title['href'])
        if urls.urlsplit(source).hostname != HOST or not urls.urlsplit(source).path.endswith('.pdf'):
            continue
        rows.append({'company': company.get_text(' ', strip=True), 'title': title.get_text(' ', strip=True), 'published': day, 'source': source, 'indexSource': url})
    pages = list(dict.fromkeys(urls.urljoin(url, x) for x in re.findall(r'I_list_\d{3}_' + day.replace('-', '') + r'\.html', str(soup))))
    return rows, pages


def run():
    path = ROOT / 'data/tdnet-discovery-state.json'
    old = json.loads(path.read_text(encoding='utf-8')) if path.exists() else {}
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')
    pages, candidates, confirmed = old.get('pages', {}), old.get('candidates', {}), old.get('confirmed', {})
    errors, checked, documents = [], 0, 0
    deadline = time.monotonic() + 100
    try:
        _, raw, charset = fetch(HOME, [HOST])
        soup = BeautifulSoup(decode_html(raw, charset), 'html.parser')
        dates = [urls.urljoin(HOME, x['value']) for x in soup.select('option[value]') if re.fullmatch(r'I_list_001_20\d{6}\.html', x['value'])]
        if not dates:
            raise ValueError('Disclosure date selector unavailable')
        for url in dates:
            pages.setdefault(url, {})
        # Refresh the latest two dates; older successful pages are one-time backfill.
        fresh_dates = {re.search(r'_(20\d{6})\.html$', u)[1] for u in dates[:2]}
        work = sorted(pages, key=lambda u: (-int(re.search(r'_(20\d{6})\.html$', u)[1]), u))
        work = [u for u in work if not pages[u].get('lastSuccessAt') or any(d in u for d in fresh_dates)]
        seen = set()
        while work and checked < 16 and time.monotonic() < deadline:
            url = work.pop(0)
            if url in seen:
                continue
            seen.add(url)
            checked += 1
            try:
                _, raw, _ = fetch(url, [HOST])
                rows, more = parse_list(raw, url)
                for row in rows:
                    candidates[row['source']] = {**row, **{k:v for k,v in candidates.get(row['source'], {}).items() if k in ('firstSeenAt','lastCheckedAt','error')}, 'firstSeenAt': candidates.get(row['source'], {}).get('firstSeenAt', stamp)}
                for child in more:
                    pages.setdefault(child, {})
                    if child not in seen and child not in work and (not pages[child].get('lastSuccessAt') or any(d in child for d in fresh_dates)):
                        work.insert(0, child)
                pages[url] = {'lastSuccessAt': stamp}
            except Exception as error:
                pages[url]['error'] = str(error)[:150]
                errors.append({'url': url, 'error': str(error)[:150]})
    except Exception as error:
        errors.append({'url': HOME, 'error': str(error)[:150]})
    for url, row in sorted(candidates.items(), key=lambda x: (bool(x[1].get('lastCheckedAt')), x[1].get('lastCheckedAt',''), x[0])):
        if documents >= 20 or time.monotonic() >= deadline:
            break
        documents += 1
        row['lastCheckedAt'] = stamp
        try:
            _, raw, _ = fetch(url, [HOST])
            company, date, title, text = pdf_announcement(raw, row['company'] + row['title'], row['company'])
            if date.isoformat() != row['published']:
                raise ValueError('PDF publication date differs from disclosure date')
            confirmed[url] = {'company': company, 'title': row['title'], 'source': url, 'published': row['published'], 'newsSources': [row['indexSource']], 'firstSeenAt': row['firstSeenAt'], 'lastCheckedAt': stamp, 'bodyHash': hashlib.sha256(text.encode()).hexdigest(), 'format': 'pdf', 'discoverySource': 'TDnet'}
            row.pop('error', None)
        except Exception as error:
            row['error'] = str(error)[:150]
    result = {'lastAttemptAt': stamp, 'listPagesChecked': checked, 'documentsChecked': documents, 'pendingListPages': sum(not x.get('lastSuccessAt') or bool(x.get('error')) for x in pages.values()), 'pendingDocuments': sum(bool(x.get('error')) or not x.get('lastCheckedAt') for x in candidates.values()), 'pages': pages, 'candidates': candidates, 'confirmed': confirmed, 'errors': errors}
    path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    return result
