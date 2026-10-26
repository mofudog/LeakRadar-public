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

from candidate_triage import decision_for, CLOSED



ROOT = Path(__file__).resolve().parents[1]

KEY = re.compile(r'漏えい|漏洩|情報流出|個人情報.{0,12}流出|不正アクセス|第三者.{0,12}閲覧|誤送信|誤交付|誤表示|不正持ち出し|(?:個人情報|顧客情報|お客さま情報|患者情報).{0,30}(?:紛失|所在不明)|(?:紛失|所在不明).{0,30}(?:個人情報|顧客情報|お客さま情報|患者情報)')

SELF = re.compile(r'当社|弊社|当法人|当院|本学|当行|当組合|当財団|当協会|当機構|弊会|当町|当市|当県')

BLOCK = re.compile(r'(^|\.)(?:google|youtube|facebook|twitter|instagram|linkedin|amazon|doubleclick)\.|(^|\.)(?:t\.co|x\.com|prtimes\.jp|value-press\.com|b\.hatena\.ne\.jp|news\.yahoo\.co\.jp)$')

EXCLUDE = re.compile(r'/login|/signin|/contact|/privacy|/policy|/terms|/recruit|/search|/tag/')
BLOG_HOST_SUFFIXES = ('hatenadiary.jp', 'note.com', 'ameblo.jp', 'blogspot.com', 'wordpress.com', 'substack.com', 'livedoor.blog', 'fc2.com', 'seesaa.net', 'exblog.jp', 'goo.ne.jp', 'tumblr.com', 'medium.com', 'sankei.com', 'oricon.co.jp', 'rocket-boys.co.jp')
BLOG_TITLE = re.compile(r'まとめてみた|まとめてみました|解説してみた|調べてみた|考察してみた|考えてみた|ブログ全文|社長ブログ|ブログ記事|全文公開')

def is_unofficial_publisher(host):
    host = (host or '').lower().rstrip('.')
    return any(host == suffix or host.endswith('.' + suffix) for suffix in BLOG_HOST_SUFFIXES)





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

    if reader.is_encrypted and not reader.decrypt(''):

        raise ValueError('Password-protected PDF requires editorial review')

    if not 1 <= len(reader.pages) <= 8:

        raise ValueError('Encrypted/large PDF requires editorial review')

    text = '\n'.join(page.extract_text() or '' for page in reader.pages)

    if not 100 <= len(text) <= 200000:

        raise ValueError('Scanned or unreadable PDF requires editorial review')

    lines = [re.sub(r'\s+', ' ', line).strip() for line in text.splitlines() if line.strip()]

    company = known

    if not company:

        for line in lines[:20]:

            if re.fullmatch(r'(?:(?:株式会社|有限会社|合同会社)[\wァ-ヶー一-龥＆&]{2,45}|[\wァ-ヶー一-龥＆&]{2,45}(?:株式会社|有限会社|合同会社))', compact(line)):

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





def prioritize_articles(articles, queue, today, limit):

    def key(article):

        q = queue.get(article['url'], {})

        last = q.get('lastOfficialAttemptAt') or (q.get('lastCheckedAt', '') if not q.get('hasDirectLinks') else '')

        return (bool(last), last, -dt.date.fromisoformat(article['date']).toordinal())

    recent = sorted((a for a in articles if dt.date.fromisoformat(a['date']) >= today-dt.timedelta(days=30)), key=key)

    history = sorted((a for a in articles if dt.date.fromisoformat(a['date']) < today-dt.timedelta(days=30)), key=key)

    recent_quota = max(1, (limit*4)//5) if limit else 0

    selected = recent[:recent_quota] + history[:max(0, limit-recent_quota)]

    used = {a['url'] for a in selected}

    selected += [a for a in recent+history if a['url'] not in used][:max(0,limit-len(selected))]

    return selected





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

    queue = dict(previous.get('queue', {}))

    for q in queue.values():q['pending']=[p for p in q.get('pending',[]) if not BLOCK.search(urlparse.urlsplit(p['url']).hostname or '')]

    confirmed = {u: x for u, x in previous.get('confirmed', {}).items()
                 if not is_unofficial_publisher(urlparse.urlsplit(x.get('source', u)).hostname)}

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

    # Persist every monthly pagination URL; a first page is never a completed month.

    archive_ok = 0

    archive_progress = previous.get('archiveProgress', {})

    for archive in config.get('archives', []):

        progress = archive_progress.setdefault(archive['name'], {})

        months = archive.get('months', 1)

        month_keys = []

        for offset in range(months):

            number = today.year * 12 + today.month - 1 - offset

            key = f'{number // 12:04d}-{number % 12 + 1:02d}'

            base = archive['urlTemplate'].format(year=number // 12, month=number % 12 + 1)

            month_keys.append(key)

            progress.setdefault(key, {'base': base, 'pending': [base], 'visited': []})

        progress = {k: progress[k] for k in month_keys}

        archive_progress[archive['name']] = progress

        current = progress[month_keys[0]]

        # Re-read current-month first page for new posts, then resume saved pages.

        work = [(month_keys[0], current['base'])]

        work.extend((k, u) for k in month_keys for u in progress[k]['pending'] if (k, u) not in work)

        done_this_run = set()

        limit = archive.get('maxPagesPerRun', 4)

        while work and len(done_this_run) < limit and time.monotonic() < deadline:

            key, url = work.pop(0)

            if url in done_this_run:

                continue

            done_this_run.add(url)

            month_state = progress[key]

            try:

                _, raw, charset = fetch(url, archive['articleHosts'])

                soup = BeautifulSoup(decode_html(raw, charset), 'html.parser')

                dated = 0

                for dl in soup.select('dl'):

                    date = None

                    for node in dl.find_all(['dt', 'dd'], recursive=False):

                        if node.name == 'dt':

                            date = date_value(node.get_text(' ', strip=True))

                            continue

                        if not date:

                            continue

                        for anchor in node.select('a[href]'):

                            title = anchor.get_text(' ', strip=True)

                            link = urlparse.urljoin(url, anchor['href'])

                            if urlparse.urlsplit(link).hostname not in archive['articleHosts']:

                                continue

                            dated += 1

                            if KEY.search(title) and retention_start <= date <= today:

                                articles.setdefault(link, dict(url=link, date=date.isoformat(), title=title[:200], feed=archive))

                if not dated:

                    raise ValueError('Archive has no dated articles; page remains pending')

                base_parts = urlparse.urlsplit(month_state['base'])

                for anchor in soup.select('a[href]'):

                    link = urlparse.urljoin(url, anchor['href']).split('#')[0]

                    parts = urlparse.urlsplit(link)

                    suffix = parts.path.removeprefix(base_parts.path.rstrip('/'))

                    if parts.scheme == 'https' and parts.hostname == base_parts.hostname and not parts.query and re.fullmatch(r'/page/[1-9][0-9]{0,2}/?', suffix):

                        if link not in month_state['visited'] and link not in month_state['pending']:

                            month_state['pending'].append(link)

                            work.append((key, link))

                month_state['visited'] = list(dict.fromkeys(month_state['visited'] + [url]))

                month_state['pending'] = [u for u in month_state['pending'] if u != url]

                month_state['lastSuccessAt'] = stamp

                month_state.pop('error', None)

                archive_ok += 1

            except Exception as error:

                message = type(error).__name__ + ': ' + str(error)[:100]

                month_state['error'] = message

                if url not in month_state['pending']:

                    month_state['pending'].append(url)

                errors.append({'url': url, 'error': message})

        archive_cursors[archive['name']] = [k for k in month_keys[1:] if progress[k]['visited'] and not progress[k]['pending']]

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

    decisions_path = ROOT/'data/candidate-review-decisions.json'

    seed_path = ROOT/'data/reviewed-incidents.json'

    sources_path = ROOT/'data/source-state.json'

    decisions = json.loads(decisions_path.read_text(encoding='utf-8')).get('reviews', {}) if decisions_path.exists() else {}

    records = json.loads(seed_path.read_text(encoding='utf-8')).get('incidents', []) if seed_path.exists() else []

    documents = json.loads(sources_path.read_text(encoding='utf-8')).get('documents', {}) if sources_path.exists() else {}

    closed = {u for u,q in queue.items() if decision_for({'newsSource':u,'title':q.get('title',''),'reportedDate':q['published']}, decisions, records, documents)['classification'] in CLOSED}

    work = prioritize_articles([a for a in articles.values() if a['url'] not in closed], queue, today, config['maxArticlesPerRun'])

    for article in work:

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

                if p.scheme == 'https' and p.hostname not in all_media_hosts and not any((p.hostname or '').endswith('.'+h.removeprefix('www.')) or p.hostname==h for h in all_media_hosts) and not BLOCK.search(p.hostname or '') and not is_unofficial_publisher(p.hostname) and not EXCLUDE.search(p.path):

                    links.append(u)

            links = list(dict.fromkeys(links))

            # Rotate bounded checks so later reference links cannot starve forever.

            if links:

                start = (queue[media].get('attempts', 0) * 5) % len(links)

                links = links[start:] + links[:start]

            had_links = bool(links)

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
                    if is_unofficial_publisher(urlparse.urlsplit(final).hostname):
                        raise ValueError('Hosted blog pages are discovery leads, not first-party announcements')

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

                                    if target not in links and norm(target) not in visited:

                                        links.insert(0,target)

                            continue

                        company = identity(official, section, news_text, known.get(urlparse.urlsplit(final).hostname))

                        date = scoped_date(official, section)

                        heading = next((h for h in section.select('h1,h2,h3') if KEY.search(h.get_text(' ',strip=True))), None)

                        title = heading.get_text(' ', strip=True) if heading else ''

                        text = section.get_text(' ', strip=True)

                    if BLOG_TITLE.search(title):
                        raise ValueError('Commentary-style article is not an official announcement')

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

            if not had_links:pending.append({'url':media,'reason':'No direct official announcement link found'})

            queue[media] = {**queue[media], 'lastCheckedAt': stamp, 'pending': pending, 'hasDirectLinks': had_links, 'lastOfficialAttemptAt': stamp if visited else queue[media].get('lastOfficialAttemptAt'), 'attempts': queue[media].get('attempts', 0)+bool(visited)}

        except Exception as error:

            errors.append({'url': media, 'error': type(error).__name__ + ': ' + str(error)[:100]})

            queue[media] = {**queue[media], 'lastCheckedAt': stamp, 'pending': [{'url':media,'reason': type(error).__name__+': '+str(error)[:100]}], 'attempts':queue[media].get('attempts',0)+1}

    # News text and unverified claims never enter the public incident catalogue.

    queue = {u: q for u, q in queue.items() if q['published'] >= retention_start.isoformat()}

    result = {'lastAttemptAt': stamp, 'feedCount': len(config['feeds']), 'successfulFeeds': feed_ok, 'successfulArchivePages': archive_ok, 'newsCandidates': len(articles), 'newsArticlesChecked': scanned, 'deferredNewsArticles': sum(not q.get('lastCheckedAt') for q in queue.values()), 'officialFetches': official_fetches, 'confirmedOfficialAnnouncements': len(confirmed), 'pendingNewsArticles': sum(bool(q['pending']) for q in queue.values()), 'errors': errors, 'queue': queue, 'confirmed': confirmed}

    result['skippedReviewedArticles'] = len(closed)

    result['archiveCursors'] = archive_cursors

    result['archiveProgress'] = archive_progress

    state_path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')

    print(json.dumps({k: v for k, v in result.items() if k not in ('queue', 'confirmed', 'errors', 'archiveProgress')}, ensure_ascii=False))

    return result





if __name__ == '__main__':

    run()

