"""News discovery -> first-party announcement checks. Copyright 2026 mofu.

No news-body republication, AI API, credentials, or invented incident summaries.
Uncertain publisher identity/date/content stays in the review queue.
"""
import time
import datetime as dt
import email.utils
import hashlib
import ipaddress
import json
import io
import unicodedata
import re
import socket
import urllib.parse as urlparse
import urllib.request as request
import xml.etree.ElementTree as ET
from pathlib import Path
from bs4 import BeautifulSoup
from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
KEY = re.compile(r'漏えい|漏洩|情報流出|個人情報.{0,12}流出|不正アクセス|第三者.{0,12}閲覧|誤送信|誤交付|誤表示|不正持ち出し')
SELF = re.compile(r'当社|弊社|当法人|当院|本学|当行|当組合|当財団|当協会|当機構|弊会|当町|当市|当県')
BLOCK = re.compile(r'(^|\.)(?:google|youtube|facebook|twitter|instagram|linkedin|amazon|doubleclick)\.|(^|\.)(?:t\.co|x\.com|prtimes\.jp|value-press\.com|b\.hatena\.ne\.jp|news\.yahoo\.co\.jp)$')
EXCLUDE = re.compile(r'/login|/signin|/contact|/privacy|/policy|/terms|/recruit|/search|/tag/')


def norm(u):
    p = urlparse.urlsplit(u)
    return urlparse.urlunsplit((p.scheme.lower(), p.netloc.lower(), p.path.rstrip('/'), p.query, ''))


def public_url(u):
    p = urlparse.urlsplit(u)
    if p.scheme != 'https' or not p.hostname or p.username or p.password or p.port not in (None, 443):
        raise ValueError('Only public HTTPS sources are allowed')
    if BLOCK.search(p.hostname) or p.hostname.endswith(('.local', '.localhost', '.internal')):
        raise ValueError('Not an eligible first-party source')
    addresses = socket.getaddrinfo(p.hostname, 443, type=socket.SOCK_STREAM)
    if not addresses or any(not ipaddress.ip_address(x[4][0]).is_global for x in addresses):
        raise ValueError('Non-public destination blocked')
    return p.hostname


class Guard(request.HTTPRedirectHandler):
    def __init__(self, hosts):
        self.hosts = hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        host = public_url(newurl)
        if host not in self.hosts:
            raise ValueError('Cross-domain redirect requires review')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(u, hosts=None):
    hostname = public_url(u)
    allowed = set(hosts or [hostname, hostname.removeprefix('www.'), 'www.' + hostname.removeprefix('www.')])
    if hostname not in allowed:
        raise ValueError('Unregistered publisher host')
    req = request.Request(u, headers={'User-Agent': 'Mofu-LeakCheck-NewsDiscovery/1.2', 'Accept': 'text/html,application/rss+xml,application/xml'})
    with request.build_opener(Guard(allowed)).open(req, timeout=15) as r:
        data = r.read(2_000_001)
        if len(data) > 2_000_000:
            raise ValueError('Source exceeds discovery size limit')
        charset = r.headers.get_content_charset() or 'utf-8'
        return r.url, data, charset


def decode_html(raw, hint='utf-8'):
    """Do not silently destroy Japanese when an HTTP charset is missing/wrong."""
    meta = re.search(br'charset\s*=\s*["\x27]?([a-zA-Z0-9_-]+)', raw[:8192], re.I)
    candidates = ['utf-8-sig', meta.group(1).decode('ascii') if meta else '', hint, 'cp932', 'euc_jp', 'iso2022_jp']
    for encoding in dict.fromkeys(candidates):
        if not encoding:
            continue
        try:
            return raw.decode(encoding, errors='strict')
        except (UnicodeError, LookupError):
            pass
    raise ValueError('Article encoding could not be read reliably')


def news_body(soup, selectors):
    # Selector priority matters: .inner may be the heading before #cmsBody.
    for selector in selectors.split(','):
        node = soup.select_one(selector.strip())
        if node is not None and len(node.get_text(' ', strip=True)) >= 100:
            return node
    return soup.find('main') or soup.find('article')


def compact(value):
    return re.sub(r'[\s　・･]', '', unicodedata.normalize('NFKC', value))


def pdf_announcement(raw, news_text, known=None):
    """Only metadata is admitted automatically; affected fields remain unreviewed."""
    reader = PdfReader(io.BytesIO(raw))
    if reader.is_encrypted or not 1 <= len(reader.pages) <= 8:
        raise ValueError('Encrypted/large PDF requires editorial review')
    text = '\n'.join(page.extract_text() or '' for page in reader.pages)
    if not 100 <= len(text) <= 200000:
        raise ValueError('Scanned or unreadable PDF requires editorial review')
    lines = [re.sub(r'\s+', ' ', line).strip() for line in text.splitlines() if line.strip()]
    company = known
    if not company:
        for line in lines[:20]:
            if re.fullmatch(r'(?:株式会社|有限会社|合同会社)[\wァ-ヶー一-龥＆&]{2,45}', compact(line)):
                short = re.sub(r'株式会社|有限会社|合同会社', '', compact(line))
                if len(short) >= 3 and short in compact(news_text):
                    company = re.sub(r'\s+', '', line)
                    break
    # A header date only; narrative incident dates cannot become publication dates.
    dates = [date_value(re.sub(r'\s', '', line)) for line in lines[:15] if re.fullmatch(r'20\d\d\s*[年./-]\s*\d{1,2}\s*[月./-]\s*\d{1,2}\s*日?', line)]
    title = next((line for line in lines if KEY.search(line) and re.search(r'お詫び|お知らせ|ご報告|調査結果|について|に関する', line)), '')
    if not company or not dates or not dates[0] or not title or not SELF.search(text):
        raise ValueError(f'PDF metadata needs review: publisher={bool(company)}, date={bool(dates and dates[0])}, title={bool(title)}')
    return company, dates[0], title, text


def date_value(value):
    m = re.search(r'(20\d\d)[年./-]\s*(\d{1,2})[月./-]\s*(\d{1,2})', str(value))
    if m:
        try:
            return dt.date(*map(int, m.groups()))
        except ValueError:
            return None
    try:
        return email.utils.parsedate_to_datetime(value).date()
    except (ValueError, TypeError, AttributeError):
        return None


def scoped_date(soup, body):
    values = [x.get('content', '') for x in soup.select('meta[property="article:published_time"]')]
    for node in body.select('time[datetime], [itemprop="datePublished"]'):
        values.append(node.get('datetime') or node.get('content') or node.get_text(' ', strip=True))
    # JSON-LD dates only belong to the actual article, not arbitrary navigation.
    for node in soup.select('script[type="application/ld+json"]'):
        try:
            objects = json.loads(node.string or '')
            objects = objects if isinstance(objects, list) else [objects]
            for obj in objects:
                if isinstance(obj, dict) and obj.get('@type') in ('Article', 'NewsArticle', 'BlogPosting'):
                    values.append(obj.get('datePublished', ''))
        except (ValueError, TypeError):
            pass
    # First short date node in the announcement header/body, never a date buried in a paragraph.
    for node in body.select('p,div,span,dd'):
        value = node.get_text(' ', strip=True)
        if len(value) < 35 and re.fullmatch(r'\s*(?:公表日[：:]?\s*|公開日[：:]?\s*)?20\d\d[年./-]\s*\d{1,2}[月./-]\s*\d{1,2}日?(?:\s*\([月火水木金土日]\))?\s*', value):
            values.append(value)
            break
    for value in values:
        d = date_value(value)
        if d:
            return d
    return None


def identity(soup, body, news_text, known):
    # Known domains retain their reviewed company identity. New domains require a
    # legal-name/site identity present both on the announcement and in the news.
    if known:
        return known
    candidates = []
    for node in soup.select('meta[property="og:site_name"]'):
        candidates.append(node.get('content', ''))
    for node in soup.select('script[type="application/ld+json"]'):
        try:
            obj = json.loads(node.string or '')
            objects = obj if isinstance(obj, list) else [obj]
            for obj in objects:
                if not isinstance(obj, dict):
                    continue
                objects2 = obj.get('@graph', [obj])
                for item in objects2:
                    if isinstance(item, dict) and item.get('@type') in ('Organization', 'Corporation', 'LocalBusiness', 'GovernmentOrganization', 'EducationalOrganization'):
                        candidates.append(item.get('name', ''))
        except (ValueError, TypeError):
            pass
    text = body.get_text(' ', strip=True)
    # Legal-name strings only; not an arbitrary heading or a media's guessed entity.
    candidates += re.findall(r'(?:株式会社|有限会社|合同会社)[\wァ-ヶー一-龥・＆&]{2,35}', text)
    candidates += re.findall(r'[\wァ-ヶー一-龥・＆&]{2,35}(?:株式会社|有限会社|合同会社)', text)
    for value in candidates:
        name = re.split(r'[|｜]', str(value))[0].strip()
        name = re.split(r'[（(]', name)[0].strip()
        short = re.sub(r'株式会社|有限会社|合同会社|公式サイト|公式ホームページ|オフィシャルサイト', '', name).strip(' 　・-')
        if 3 <= len(short) <= 35 and short in news_text and short in text:
            return name[:80]
        # Japanese text has no word spaces: a suffix legal name may follow a clause.
        # Only accept an exact, longest substring also present in the news body.
        if re.search(r'(?:株式会社|有限会社|合同会社)$', name):
            for start in range(len(name)):
                legal = name[start:]
                short = re.sub(r'株式会社|有限会社|合同会社', '', legal)
                if 3 <= len(short) <= 35 and short in news_text:
                    return legal
    return None


def run():
    deadline = time.monotonic()+240
    config = json.loads((ROOT / 'data/news-sources.json').read_text(encoding='utf-8'))
    monitor = json.loads((ROOT / 'data/monitor-sources.json').read_text(encoding='utf-8'))
    known = {urlparse.urlsplit(s['url']).hostname: s['company'] for s in monitor['documents'] + monitor['indexes']}
    today = dt.datetime.now(dt.timezone(dt.timedelta(hours=9))).date()
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')
    state_path = ROOT / 'data/news-discovery-state.json'
    previous = json.loads(state_path.read_text(encoding='utf-8')) if state_path.exists() else {}
    archive_cursors = previous.get('archiveCursors', {})
    try:
        retention_start = today.replace(year=today.year-3)
    except ValueError:
        retention_start = today.replace(year=today.year-3, day=28)
    queue = {u:q for u,q in previous.get('queue', {}).items() if not urlparse.urlsplit(u).query}
    for q in queue.values():q['pending']=[p for p in q.get('pending',[]) if not urlparse.urlsplit(p['url']).query and not BLOCK.search(urlparse.urlsplit(p['url']).hostname or '')]
    confirmed = previous.get('confirmed', {})
    errors, articles = [], {}
    feed_ok = 0
    for feed in config['feeds']:
        try:
            _, raw, _ = fetch(feed['url'])
            if b'<!DOCTYPE' in raw.upper() or b'<!ENTITY' in raw.upper():
                raise ValueError('DTD/entity declarations are not supported')
            tree = ET.fromstring(raw)
            count = 0
            for item in tree.iter():
                if item.tag.split('}')[-1] not in ('item', 'entry'):
                    continue
                fields = {x.tag.split('}')[-1]: x.text or x.get('href', '') for x in item}
                title = fields.get('title', '')
                date = date_value(fields.get('pubDate') or fields.get('date') or fields.get('published') or fields.get('updated'))
                link = fields.get('link', '')
                if KEY.search(title) and date and today - dt.timedelta(days=config['articleMaxAgeDays']) <= date <= today:
                    if urlparse.urlsplit(link).hostname in feed['articleHosts']:
                        articles[link] = dict(url=link, date=date.isoformat(), title=title[:200], feed=feed)
                count += 1
            if not count:
                raise ValueError('Feed has no parseable items')
            feed_ok += 1
        except Exception as error:
            errors.append({'url': feed['url'], 'error': type(error).__name__ + ': ' + str(error)[:100]})
    # Monthly archives recover articles that have already fallen out of short RSS feeds.
    archive_ok = 0
    for archive in config.get('archives', []):
        months = archive.get('months', 1)
        per_run = min(months, archive.get('maxPagesPerRun', months))
        completed = set(archive_cursors.get(archive['name'], []))
        historic = []
        for offset in range(1, months):
            month = today.year * 12 + today.month - 1 - offset
            key = f'{month // 12:04d}-{month % 12 + 1:02d}'
            if key not in completed:
                historic.append(offset)
        offsets = [0] + historic[:max(0, per_run-1)]
        for offset in offsets:
            month = today.year * 12 + today.month - 1 - offset
            url = archive['urlTemplate'].format(year=month // 12, month=month % 12 + 1)
            try:
                _, raw, charset = fetch(url)
                soup = BeautifulSoup(decode_html(raw, charset), 'html.parser')
                found = 0
                for dl in soup.select('dl'):
                    date = None
                    for node in dl.find_all(['dt', 'dd'], recursive=False):
                        if node.name == 'dt':
                            date = date_value(node.get_text(' ', strip=True))
                            continue
                        if not date or not today - dt.timedelta(days=config['articleMaxAgeDays']) <= date <= today:
                            continue
                        for anchor in node.select('a[href]'):
                            title = anchor.get_text(' ', strip=True)
                            link = urlparse.urljoin(url, anchor['href'])
                            if KEY.search(title) and urlparse.urlsplit(link).hostname in archive['articleHosts']:
                                articles.setdefault(link, dict(url=link, date=date.isoformat(), title=title[:200], feed=archive))
                                found += 1
                if not found:
                    raise ValueError('Archive has no dated incident candidates')
                archive_ok += 1
                if offset:
                    completed.add(f'{month // 12:04d}-{month % 12 + 1:02d}')
            except Exception as error:
                errors.append({'url': url, 'error': type(error).__name__ + ': ' + str(error)[:100]})
        archive_cursors[archive['name']] = sorted(completed)
    # Save every candidate before applying work/time limits. Retry even after it leaves RSS.
    sources_by_name = {f['name']: f for f in config['feeds'] + config.get('archives', [])}
    for article in articles.values():
        old = queue.get(article['url'], {})
        queue[article['url']] = {**old, 'newsSource': article['url'], 'publisher': article['feed']['name'], 'published': article['date'], 'title': article.get('title', old.get('title', '')), 'firstSeenAt': old.get('firstSeenAt', stamp), 'pending': old.get('pending', [{'url': article['url'], 'reason': 'Deferred: article has not been checked yet'}])}
    for url, item in queue.items():
        feed = sources_by_name.get(item.get('publisher'))
        if feed and urlparse.urlsplit(url).hostname in feed['articleHosts'] and item['published'] >= retention_start.isoformat():
            articles.setdefault(url, dict(url=url, date=item['published'], title=item.get('title', ''), feed=feed))
    official_fetches, scanned = 0, 0
    all_media_hosts = {h for f in config['feeds'] for h in f['articleHosts']}
    for article in sorted(articles.values(), key=lambda x: (bool(queue.get(x['url'],{}).get('lastCheckedAt')), queue.get(x['url'],{}).get('lastCheckedAt',''), -dt.date.fromisoformat(x['date']).toordinal()))[:config['maxArticlesPerRun']]:
        if time.monotonic()>=deadline:break
        media = article['url']
        try:
            _, raw, charset = fetch(media, article['feed']['articleHosts'])
            soup = BeautifulSoup(decode_html(raw, charset), 'html.parser')
            body = news_body(soup, article['feed']['bodySelector'])
            if body is None:
                raise ValueError('News article body could not be isolated')
            for x in body.select('nav,aside,footer,script,style,.related,.recommend'):
                x.decompose()
            news_text = body.get_text(' ', strip=True)
            scanned += 1
            links = []
            for anchor in body.select('a[href]'):
                u = urlparse.urljoin(media, anchor['href'])
                p = urlparse.urlsplit(u)
                if p.scheme == 'https' and p.hostname not in all_media_hosts and not any((p.hostname or '').endswith('.'+h.removeprefix('www.')) or p.hostname==h for h in all_media_hosts) and not p.query and not BLOCK.search(p.hostname or '') and not EXCLUDE.search(p.path):
                    links.append(u)
            links = list(dict.fromkeys(links))
            # Rotate bounded checks so later reference links cannot starve forever.
            if links:
                start = (queue[media].get('attempts', 0) * 5) % len(links)
                links = links[start:] + links[:start]
            pending = []
            visited=set()
            per_article=0
            while links and official_fetches < config['maxOfficialFetchesPerRun'] and time.monotonic()<deadline:
                u = links.pop(0)
                if norm(u) in visited:continue
                if per_article>=5:
                    links.insert(0,u);break
                visited.add(norm(u));per_article+=1
                if norm(u) in confirmed:
                    # Do not silently keep stale confirmed source content after a fetch failure.
                    pass
                official_fetches += 1
                try:
                    final, raw, charset = fetch(u)
                    if raw.startswith(b'%PDF'):
                        company, date, title, text = pdf_announcement(raw, news_text, known.get(urlparse.urlsplit(final).hostname))
                        official = section = None
                    else:
                        official = BeautifulSoup(decode_html(raw, charset), 'html.parser')
                        section = official.select_one('article#article') or official.find('main') or official.find('article') or official.find('body')
                    if official is not None:
                        if section is None:
                            raise ValueError('Announcement body unavailable')
                        if urlparse.urlsplit(final).path in ('', '/'):
                            for a in section.select('a[href]'):
                                target = urlparse.urljoin(final, a['href'])
                                if KEY.search(a.get_text(' ', strip=True)) and urlparse.urlsplit(target).hostname == urlparse.urlsplit(final).hostname:
                                    if target not in links and norm(target) not in visited and not urlparse.urlsplit(target).query:
                                        links.insert(0,target)
                            continue
                        company = identity(official, section, news_text, known.get(urlparse.urlsplit(final).hostname))
                        date = scoped_date(official, section)
                        heading = next((h for h in section.select('h1,h2,h3') if KEY.search(h.get_text(' ',strip=True))), None)
                        title = heading.get_text(' ', strip=True) if heading else ''
                        text = section.get_text(' ', strip=True)
                    if not company or not date or not KEY.search(title) or not SELF.search(text):
                        raise ValueError('Publisher identity, scoped date or first-party announcement could not be confirmed')
                    if not today - dt.timedelta(days=3*366) <= date <= today or abs((date - dt.date.fromisoformat(article['date'])).days) > 120:
                        raise ValueError('Announcement date does not match the news time window')
                    if section is not None:
                        for x in section.select('script,style,nav,aside,footer'):
                            x.decompose()
                        text = section.get_text(' ', strip=True)
                    body_hash = hashlib.sha256(text.encode()).hexdigest()
                    key = norm(final)
                    old = confirmed.get(key)
                    citations = list(dict.fromkeys((old or {}).get('newsSources', []) + [media]))
                    confirmed[key] = {'company': company, 'title': title[:200], 'source': final, 'published': date.isoformat(), 'newsSources': citations, 'firstSeenAt': (old or {}).get('firstSeenAt',stamp), 'lastCheckedAt': stamp, 'bodyHash': body_hash, 'format': 'pdf' if raw.startswith(b'%PDF') else 'html'}
                except Exception as error:
                    pending.append({'url': u, 'reason': type(error).__name__ + ': ' + str(error)[:100]})
            if links:pending.append({'url':media,'reason':'Remaining official links deferred by the per-run/per-article limit'})
            if not visited:pending.append({'url':media,'reason':'No direct official announcement link found'})
            queue[media] = {**queue[media], 'lastCheckedAt': stamp, 'pending': pending, 'hasDirectLinks': bool(visited), 'attempts': queue[media].get('attempts', 0)+1}
        except Exception as error:
            errors.append({'url': media, 'error': type(error).__name__ + ': ' + str(error)[:100]})
            queue[media] = {**queue[media], 'lastCheckedAt': stamp, 'pending': [{'url':media,'reason': type(error).__name__+': '+str(error)[:100]}], 'attempts':queue[media].get('attempts',0)+1}
    # News text and unverified claims never enter the public incident catalogue.
    queue = {u: q for u, q in queue.items() if q['published'] >= retention_start.isoformat()}
    result = {'lastAttemptAt': stamp, 'feedCount': len(config['feeds']), 'successfulFeeds': feed_ok, 'successfulArchivePages': archive_ok, 'newsCandidates': len(articles), 'newsArticlesChecked': scanned, 'deferredNewsArticles': sum(not q.get('lastCheckedAt') for q in queue.values()), 'officialFetches': official_fetches, 'confirmedOfficialAnnouncements': len(confirmed), 'pendingNewsArticles': sum(bool(q['pending']) for q in queue.values()), 'errors': errors, 'queue': queue, 'confirmed': confirmed}
    result['archiveCursors'] = archive_cursors
    state_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k not in ('queue', 'confirmed', 'errors')}, ensure_ascii=False))
    return result


if __name__ == '__main__':
    run()
