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
import re
import socket
import urllib.parse as urlparse
import urllib.request as request
import xml.etree.ElementTree as ET
from pathlib import Path
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parents[1]
KEY = re.compile(r'漏えい|漏洩|情報流出|個人情報.{0,12}流出|不正アクセス')
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
        if data.startswith(b'%PDF'):
            raise ValueError('PDF announcement requires editorial review')
        charset = r.headers.get_content_charset() or 'utf-8'
        return r.url, data, charset


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
    for value in candidates:
        name = re.split(r'[|｜]', str(value))[0].strip()
        name = re.split(r'[（(]', name)[0].strip()
        short = re.sub(r'株式会社|有限会社|合同会社|公式サイト|公式ホームページ|オフィシャルサイト', '', name).strip(' 　・-')
        if 3 <= len(short) <= 35 and short in news_text and short in text:
            return name[:80]
    return None


def run():
    deadline = time.monotonic()+180
    config = json.loads((ROOT / 'data/news-sources.json').read_text(encoding='utf-8'))
    monitor = json.loads((ROOT / 'data/monitor-sources.json').read_text(encoding='utf-8'))
    known = {urlparse.urlsplit(s['url']).hostname: s['company'] for s in monitor['documents'] + monitor['indexes']}
    today = dt.datetime.now(dt.timezone(dt.timedelta(hours=9))).date()
    stamp = dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds')
    state_path = ROOT / 'data/news-discovery-state.json'
    previous = json.loads(state_path.read_text(encoding='utf-8')) if state_path.exists() else {}
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
                        articles[link] = dict(url=link, date=date.isoformat(), feed=feed)
                count += 1
            if not count:
                raise ValueError('Feed has no parseable items')
            feed_ok += 1
        except Exception as error:
            errors.append({'url': feed['url'], 'error': type(error).__name__ + ': ' + str(error)[:100]})
    official_fetches, scanned = 0, 0
    all_media_hosts = {h for f in config['feeds'] for h in f['articleHosts']}
    for article in sorted(articles.values(), key=lambda x: (x['url'] in queue, queue.get(x['url'],{}).get('lastCheckedAt',''), -dt.date.fromisoformat(x['date']).toordinal()))[:config['maxArticlesPerRun']]:
        if time.monotonic()>=deadline:break
        media = article['url']
        try:
            _, raw, charset = fetch(media, article['feed']['articleHosts'])
            soup = BeautifulSoup(raw.decode(charset, errors='replace'), 'html.parser')
            body = soup.select_one(article['feed']['bodySelector']) or soup.find('main') or soup.find('article')
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
            links = list(dict.fromkeys(links))[:8]
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
                    official = BeautifulSoup(raw.decode(charset, errors='replace'), 'html.parser')
                    section = official.select_one('article#article') or official.find('main') or official.find('article') or official.find('body')
                    if not section:
                        raise ValueError('Announcement body unavailable')
                    # A corporate homepage may lead one level deeper to its actual notice.
                    if urlparse.urlsplit(final).path in ('', '/'):
                        for a in section.select('a[href]'):
                            target = urlparse.urljoin(final, a['href'])
                            if KEY.search(a.get_text(' ', strip=True)) and urlparse.urlsplit(target).hostname == urlparse.urlsplit(final).hostname:
                                if target not in links and norm(target) not in visited and not urlparse.urlsplit(target).query:
                                    links.insert(0,target)
                        continue
                    company = identity(official, section, news_text, known.get(urlparse.urlsplit(final).hostname))
                    date = scoped_date(official, section)
                    heading = section.find('h1') or official.find('h1')
                    title = heading.get_text(' ', strip=True) if heading else ''
                    text = section.get_text(' ', strip=True)
                    if not company or not date or not KEY.search(title) or not SELF.search(text):
                        raise ValueError('Publisher identity, scoped date or first-party announcement could not be confirmed')
                    if not today - dt.timedelta(days=3*366) <= date <= today or abs((date - dt.date.fromisoformat(article['date'])).days) > 120:
                        raise ValueError('Announcement date does not match the news time window')
                    for x in section.select('script,style,nav,aside,footer'):
                        x.decompose()
                    body_hash = hashlib.sha256(section.get_text(' ', strip=True).encode()).hexdigest()
                    key = norm(final)
                    old = confirmed.get(key)
                    citations = list(dict.fromkeys((old or {}).get('newsSources', []) + [media]))
                    confirmed[key] = {'company': company, 'title': title[:200], 'source': final, 'published': date.isoformat(), 'newsSources': citations, 'lastCheckedAt': stamp, 'bodyHash': body_hash}
                except Exception as error:
                    pending.append({'url': u, 'reason': type(error).__name__ + ': ' + str(error)[:100]})
            if links:pending.append({'url':media,'reason':'Remaining official links deferred by the per-run/per-article limit'})
            if not visited:pending.append({'url':media,'reason':'No direct official announcement link found'})
            queue[media] = {'newsSource': media, 'publisher': article['feed']['name'], 'published': article['date'], 'lastCheckedAt': stamp, 'pending': pending, 'hasDirectLinks': bool(links or pending)}
        except Exception as error:
            errors.append({'url': media, 'error': type(error).__name__ + ': ' + str(error)[:100]})
    # News text and unverified claims never enter the public incident catalogue.
    queue = {u: q for u, q in queue.items() if q['published'] >= (today - dt.timedelta(days=90)).isoformat()}
    result = {'lastAttemptAt': stamp, 'feedCount': len(config['feeds']), 'successfulFeeds': feed_ok, 'newsCandidates': len(articles), 'newsArticlesChecked': scanned, 'officialFetches': official_fetches, 'confirmedOfficialAnnouncements': len(confirmed), 'pendingNewsArticles': sum(bool(q['pending']) for q in queue.values()), 'errors': errors, 'queue': queue, 'confirmed': confirmed}
    state_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({k: v for k, v in result.items() if k not in ('queue', 'confirmed', 'errors')}, ensure_ascii=False))
    return result


if __name__ == '__main__':
    run()
