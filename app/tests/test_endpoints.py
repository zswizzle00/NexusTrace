"""Integration smoke tests for every HTTP surface NexusTrace exposes.

Requires a running server (default http://localhost:5050, override with
NEXUSTRACE_BASE_URL).

Ground rules, because breaking any makes the suite useless or destructive: no API keys
assumed, so assert HTTP status and page identity rather than enrichment content (only
/api/ip/check_ip's status genuinely depends on a key); nothing here starts a
Playwright/Chromium scan (30s+ and live network); CSRF is satisfied, never disabled, and
/api/enrich/* uses X-API-Key instead; only files this run created under data/ are deleted.

Deliberately NOT covered: POST /url_scan and scanner-bound domain/URL indicators (no
Chromium); the authenticated /api/enrich/* success path (needs a provisioned key in
data/api_keys.json, so only the 401/403 gates are asserted); the /api/ip/check_ips
success path (no usable rows without provider keys).
"""
import hashlib
import os
import re
import sys
import uuid
from urllib.parse import urlparse

import requests

BASE_URL = os.getenv('NEXUSTRACE_BASE_URL', 'http://localhost:5050').rstrip('/')
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASSED = []
FAILED = []
SKIPPED = []
KNOWN_ISSUES = []

# Only ever appended to for files this run itself created; removed in cleanup().
CREATED_FILES = []


def check(name, ok, detail=''):
    if ok:
        PASSED.append(name)
        print(f"  PASS  {name}")
    else:
        FAILED.append((name, detail))
        print(f"  FAIL  {name}  {detail}")


def skip(name, why):
    SKIPPED.append((name, why))
    print(f"  SKIP  {name}  ({why})")


def known_issue(name, detail):
    """An app bug observed and recorded, deliberately not failing the suite.
    Fix the app, then promote these to real checks."""
    KNOWN_ISSUES.append((name, detail))
    print(f"  BUG   {name}  {detail}")


def title_of(html):
    m = re.search(r'<title>(.*?)</title>', html, re.S)
    return m.group(1).strip() if m else ''


def session_with_csrf():
    """Session cookie plus the token scraped from base.html's <meta name="csrf-token">."""
    s = requests.Session()
    r = s.get(f'{BASE_URL}/', timeout=30)
    r.raise_for_status()
    m = re.search(r'name="csrf-token" content="([^"]+)"', r.text)
    if not m:
        raise RuntimeError('Could not scrape a CSRF token from the home page')
    return s, m.group(1)


def test_pages(s):
    print('\nBrowser pages (GET):')
    # (path, status, marker). A marker is matched against <title> only where the
    # template sets {% block title %}, because base.html's shared nav repeats most
    # page names in the body and would match anywhere.
    pages = [
        ('/',                    200, None, 'A tool for analyzing IP addresses'),
        ('/ip_search',           200, None, 'IP Address Analysis'),
        ('/domain_search',       200, None, 'Domain/URL Analysis'),
        ('/hash_analysis',       200, None, 'Hash Analysis'),
        ('/ad_event_search',     200, None, 'Windows Event ID and AD Event Search'),
        ('/azure_error_search',  200, None, 'Azure Error Code Search'),
        ('/user_agent_search',   200, None, 'User Agent Analysis'),
        ('/url_scan',            200, 'URL Scan | NexusTrace', None),
        ('/email_analysis',      200, 'E-mail Analysis | NexusTrace', None),
        ('/cyberchef',           200, 'CyberChef | NexusTrace', None),
        ('/no_results',          200, 'No Results Found', None),
    ]
    for path, status, want_title, want_body in pages:
        r = s.get(BASE_URL + path, timeout=30)
        check(f'GET {path} -> {status}', r.status_code == status,
              f'got {r.status_code}')
        if want_title is not None:
            check(f'GET {path} renders the right page', want_title in title_of(r.text),
                  f'title={title_of(r.text)!r}')
        else:
            check(f'GET {path} renders the right page', want_body in r.text,
                  f'marker {want_body!r} missing')

    r = s.get(f'{BASE_URL}/sw.js', timeout=30)
    check('GET /sw.js -> 200 javascript',
          r.status_code == 200 and 'javascript' in r.headers.get('content-type', ''),
          f'{r.status_code} {r.headers.get("content-type")}')

    r = s.get(f'{BASE_URL}/cyberchef_app/', timeout=30)
    check('GET /cyberchef_app/ -> 200', r.status_code == 200, f'got {r.status_code}')

    r = s.get(f'{BASE_URL}/definitely/not/a/route', timeout=30)
    check('unknown path -> 404', r.status_code == 404, f'got {r.status_code}')

    r = s.get(f'{BASE_URL}/favicon.ico', timeout=30)
    if r.status_code == 404:
        known_issue('GET /favicon.ico',
                    'route points at app/static (nonexistent); no favicon.ico in repo -> 404')
    else:
        check('GET /favicon.ico -> 200', r.status_code == 200, f'got {r.status_code}')


def test_health(s):
    print('\nHealth:')
    r = s.get(f'{BASE_URL}/api/health', timeout=30)
    check('GET /api/health -> 200', r.status_code == 200, f'got {r.status_code}')
    body = r.json()
    check('health reports a status', 'status' in body, f'keys={sorted(body)}')
    check('health reports api key configuration',
          'configured_integrations' in body, f'keys={sorted(body)}')


def test_ip_api(s, tok):
    print('\nIP API:')
    h = {'X-CSRFToken': tok}

    r = s.post(f'{BASE_URL}/api/ip/check_ip', json={}, headers=h, timeout=60)
    check('POST /api/ip/check_ip {} -> 400', r.status_code == 400, f'got {r.status_code}')

    r = s.post(f'{BASE_URL}/api/ip/check_ip', json={'ip': 'not-an-ip'}, headers=h, timeout=60)
    check('POST /api/ip/check_ip invalid -> 400', r.status_code == 400, f'got {r.status_code}')

    # VPNapi is the primary source and the handler hard-fails without its key, so a
    # keyless 500 here is correct behavior, not a regression.
    r = s.post(f'{BASE_URL}/api/ip/check_ip', json={'ip': '8.8.8.8'}, headers=h, timeout=60)
    ok = (r.status_code == 200) or (r.status_code == 500 and 'error' in r.json())
    check('POST /api/ip/check_ip valid -> 200, or 500+error with no VPNAPI_KEY',
          ok, f'got {r.status_code} {r.text[:120]}')

    r = s.post(f'{BASE_URL}/api/ip/check_ips', files={'file': ('x.pdf', b'x')},
               data={'csrf_token': tok}, timeout=60)
    check('POST /api/ip/check_ips bad extension -> 400', r.status_code == 400,
          f'got {r.status_code}')

    r = s.post(f'{BASE_URL}/api/ip/check_ips', files={'file': ('ips.csv', b'ip\nnot-an-ip\n')},
               data={'csrf_token': tok}, timeout=120)
    check('POST /api/ip/check_ips no valid IPs -> 400', r.status_code == 400,
          f'got {r.status_code}')
    skip('POST /api/ip/check_ips CSV report',
         'batch enrichment yields no rows without provider keys')


def test_domain_api(s, tok):
    print('\nDomain API:')
    h = {'X-CSRFToken': tok}

    r = s.post(f'{BASE_URL}/api/domain/check_domain', json={}, headers=h, timeout=60)
    check('POST /api/domain/check_domain {} -> 400', r.status_code == 400, f'got {r.status_code}')

    r = s.post(f'{BASE_URL}/api/domain/check_domain', json={'domain': 'not a domain'},
               headers=h, timeout=60)
    check('POST /api/domain/check_domain invalid -> 400', r.status_code == 400,
          f'got {r.status_code}')

    # DNS/SSL/crt.sh need no key, so this one is expected to succeed keyless.
    r = s.post(f'{BASE_URL}/api/domain/check_domain', json={'domain': 'example.com'},
               headers=h, timeout=90)
    check('POST /api/domain/check_domain valid -> 200', r.status_code == 200,
          f'got {r.status_code} {r.text[:120]}')
    if r.status_code == 200:
        check('check_domain returns a keyless section',
              any(k in r.json() for k in ('dns_records', 'ssl_info', 'whois')),
              f'keys={sorted(r.json())[:8]}')

    r = s.post(f'{BASE_URL}/api/domain/analyze_url', json={}, headers=h, timeout=60)
    check('POST /api/domain/analyze_url {} -> 400', r.status_code == 400, f'got {r.status_code}')

    r = s.post(f'{BASE_URL}/api/domain/analyze_url', json={'url': 'https://example.com'},
               headers=h, timeout=90)
    check('POST /api/domain/analyze_url valid -> 200', r.status_code == 200,
          f'got {r.status_code} {r.text[:120]}')
    if r.status_code == 200:
        check('analyze_url returns url_analysis', 'url_analysis' in r.json(),
              f'keys={sorted(r.json())[:8]}')

    # The API-aggregation path (WHOIS+DNS+SSL+OTX), not the scanner path /analyze
    # uses for domains. POST only; see the GET known issue below.
    r = s.post(f'{BASE_URL}/api/domain/analyze', data={'indicator': 'example.com',
                                                       'csrf_token': tok}, timeout=120)
    check('POST /api/domain/analyze -> 200', r.status_code == 200, f'got {r.status_code}')
    check('POST /api/domain/analyze renders a result or no-results page',
          'Threat Intelligence Report' in r.text or 'No Results Found' in r.text,
          f'title={title_of(r.text)!r}')

    r = s.get(f'{BASE_URL}/api/domain/analyze', timeout=60)
    if r.status_code == 500:
        known_issue('GET /api/domain/analyze',
                    "500 UnboundLocalError: `indicator` is only bound in the POST branch "
                    "(domain_routes.py:94). GET /domain_search's redirect lands here.")
    else:
        check('GET /api/domain/analyze -> 200', r.status_code == 200, f'got {r.status_code}')


def test_hash_api(s, tok):
    print('\nHash API:')
    h = {'X-CSRFToken': tok}

    r = s.post(f'{BASE_URL}/api/hash/check_hash', json={'hash': ''}, headers=h, timeout=60)
    check('POST /api/hash/check_hash empty -> 400', r.status_code == 400, f'got {r.status_code}')

    r = s.post(f'{BASE_URL}/api/hash/check_hash',
               json={'hash': 'd41d8cd98f00b204e9800998ecf8427e'}, headers=h, timeout=90)
    check('POST /api/hash/check_hash -> 200', r.status_code == 200,
          f'got {r.status_code} {r.text[:120]}')
    if r.status_code == 200:
        check('check_hash echoes the hash it was given',
              r.json().get('hash') == 'd41d8cd98f00b204e9800998ecf8427e',
              f'got {r.json().get("hash")!r}')

    r = s.get(f'{BASE_URL}/api/hash/analyze', timeout=60)
    check('GET /api/hash/analyze -> 200', r.status_code == 200, f'got {r.status_code}')
    check('GET /api/hash/analyze renders the hash page', 'Hash Analysis' in r.text,
          f'title={title_of(r.text)!r}')

    r = s.post(f'{BASE_URL}/api/hash/analyze',
               data={'hash': 'd41d8cd98f00b204e9800998ecf8427e', 'csrf_token': tok}, timeout=90)
    check('POST /api/hash/analyze -> 200', r.status_code == 200, f'got {r.status_code}')
    check('POST /api/hash/analyze renders the hash page', 'Hash Analysis' in r.text,
          f'title={title_of(r.text)!r}')


def test_file_api(s, tok):
    print('\nFile API:')
    r = s.post(f'{BASE_URL}/api/file/analyze_file', data={'csrf_token': tok}, timeout=60)
    check('POST /api/file/analyze_file no file -> 400', r.status_code == 400,
          f'got {r.status_code}')

    r = s.post(f'{BASE_URL}/api/file/analyze_file',
               files={'file': ('notes.txt', b'x')}, data={'csrf_token': tok}, timeout=60)
    check('POST /api/file/analyze_file disallowed extension -> 400', r.status_code == 400,
          f'got {r.status_code}')

    # The SHA-256 is computed locally, so this asserts a real value with no key.
    payload = b'nexustrace-endpoint-selftest'
    expected = hashlib.sha256(payload).hexdigest()
    r = s.post(f'{BASE_URL}/api/file/analyze_file',
               files={'file': ('probe.bin', payload)}, data={'csrf_token': tok}, timeout=90)
    check('POST /api/file/analyze_file -> 200', r.status_code == 200,
          f'got {r.status_code} {r.text[:120]}')
    if r.status_code == 200:
        body = r.json()
        check('analyze_file returns the correct SHA-256', body.get('sha256') == expected,
              f'got {body.get("sha256")}')
        check('analyze_file echoes the filename', body.get('original_filename') == 'probe.bin',
              f'got {body.get("original_filename")!r}')


def test_lookup_apis(s, tok):
    print('\nEvent / Azure error APIs (form-encoded):')
    r = s.post(f'{BASE_URL}/api/event/search', data={'event_id': 'abc', 'csrf_token': tok},
               timeout=60)
    check('POST /api/event/search non-numeric -> 400', r.status_code == 400, f'got {r.status_code}')

    r = s.post(f'{BASE_URL}/api/event/search', data={'event_id': '4625', 'csrf_token': tok},
               timeout=90)
    check('POST /api/event/search -> 200 JSON',
          r.status_code == 200 and isinstance(r.json(), dict), f'got {r.status_code}')

    r = s.post(f'{BASE_URL}/api/azure_error/search', data={'error_code': '', 'csrf_token': tok},
               timeout=60)
    check('POST /api/azure_error/search empty -> 400', r.status_code == 400, f'got {r.status_code}')

    r = s.post(f'{BASE_URL}/api/azure_error/search', data={'error_code': 'zzz', 'csrf_token': tok},
               timeout=60)
    check('POST /api/azure_error/search malformed -> 400', r.status_code == 400,
          f'got {r.status_code}')

    r = s.post(f'{BASE_URL}/api/azure_error/search',
               data={'error_code': 'AADSTS50011', 'csrf_token': tok}, timeout=90)
    check('POST /api/azure_error/search -> 200 JSON',
          r.status_code == 200 and isinstance(r.json(), dict), f'got {r.status_code}')


# Domain/URL indicators are absent on purpose: they route into the Playwright
# scanner (home_routes._run_analysis).
CHROME_UA = ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
             '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36')

# (label, indicator, any-one-of markers). 'No Results Found' is acceptable
# everywhere: with no keys it is the correct outcome.
ANALYSIS_CASES = [
    ('ip',          '8.8.8.8',                          ['Threat Intelligence Report', 'No Results Found']),
    ('hash',        'd41d8cd98f00b204e9800998ecf8427e',  ['Hash Analysis', 'No Results Found']),
    ('azure_error', 'AADSTS50011',                       ['Azure Error', 'No Results Found']),
    ('ad_code',     '4625',                              ['Windows Event / AD Event Analysis', 'No Results Found']),
    ('user_agent',  CHROME_UA,                           ['User Agent Analysis', 'No Results Found']),
]


def test_unified_analysis(s, tok):
    print('\nUnified analysis (POST /analyze):')
    for label, indicator, markers in ANALYSIS_CASES:
        r = s.post(f'{BASE_URL}/analyze', data={'indicator': indicator, 'csrf_token': tok},
                   timeout=120, allow_redirects=False)
        check(f'POST /analyze {label} -> 200', r.status_code == 200, f'got {r.status_code}')
        check(f'POST /analyze {label} renders a known page',
              any(m in r.text for m in markers), f'title={title_of(r.text)!r}')

    r = s.post(f'{BASE_URL}/analyze', data={'indicator': '', 'csrf_token': tok},
               timeout=60, allow_redirects=False)
    check('POST /analyze empty -> redirect home',
          r.status_code in (302, 303) and r.headers.get('Location', '').endswith('/'),
          f'got {r.status_code} {r.headers.get("Location")}')

    print('\nDeep links (GET /i/<indicator>):')
    for label, indicator, markers in ANALYSIS_CASES:
        r = s.get(f'{BASE_URL}/i/{requests.utils.quote(indicator, safe="")}',
                  timeout=120, allow_redirects=False)
        check(f'GET /i/ {label} -> 200', r.status_code == 200, f'got {r.status_code}')
        check(f'GET /i/ {label} renders a known page',
              any(m in r.text for m in markers), f'title={title_of(r.text)!r}')

    skip('domain and URL indicators via /analyze and /i/',
         'they run a real Playwright scan; excluded by design')


def test_search_forms(s, tok):
    print('\nSearch form posts:')
    r = s.post(f'{BASE_URL}/ip_search', data={'ip': '8.8.8.8', 'csrf_token': tok}, timeout=60)
    check('POST /ip_search -> 200', r.status_code == 200, f'got {r.status_code}')
    check('POST /ip_search stays on the IP page', 'IP Address Analysis' in r.text,
          f'title={title_of(r.text)!r}')

    r = s.post(f'{BASE_URL}/domain_search', data={'indicator': 'example.com', 'csrf_token': tok},
               timeout=60, allow_redirects=False)
    check('POST /domain_search -> redirect to /api/domain/analyze',
          r.status_code in (302, 303)
          and '/api/domain/analyze' in r.headers.get('Location', ''),
          f'got {r.status_code} {r.headers.get("Location")}')


# GET surfaces and pre-browser rejections only - never a real scan.
def test_scanner_get_surfaces(s, tok):
    print('\nURL scanner (no scan is ever started):')
    r = s.get(f'{BASE_URL}/url_scan', timeout=30)
    check('GET /url_scan -> 200', r.status_code == 200, f'got {r.status_code}')

    missing = str(uuid.uuid4())
    check('GET /url_scan/<unknown> -> 404',
          s.get(f'{BASE_URL}/url_scan/{missing}', timeout=30).status_code == 404)
    check('GET /url_scan/screenshot/<unknown> -> 404',
          s.get(f'{BASE_URL}/url_scan/screenshot/{missing}', timeout=30).status_code == 404)

    # These are rejected before run_scan() is reached, so no browser launches.
    r = s.post(f'{BASE_URL}/url_scan', data={'url': '', 'csrf_token': tok},
               timeout=30, allow_redirects=False)
    check('POST /url_scan empty URL -> redirect to the form (no scan)',
          r.status_code in (302, 303) and r.headers.get('Location', '').endswith('/url_scan'),
          f'got {r.status_code} {r.headers.get("Location")}')

    for blocked in ('http://127.0.0.1/', 'http://localhost/', 'http://169.254.169.254/',
                    'file:///etc/passwd'):
        r = s.post(f'{BASE_URL}/url_scan', data={'url': blocked, 'csrf_token': tok},
                   timeout=30, allow_redirects=False)
        check(f'POST /url_scan {blocked} blocked by the guard (no scan)',
              r.status_code in (302, 303)
              and r.headers.get('Location', '').endswith('/url_scan'),
              f'got {r.status_code} {r.headers.get("Location")}')

    # Read-only, and only if the environment happens to already have a stored scan.
    ids = re.findall(r'/url_scan/([0-9a-f-]{36})',
                     s.get(f'{BASE_URL}/url_scan', timeout=30).text)
    if not ids:
        skip('GET /url_scan/<id> and its screenshot', 'no stored scans in data/scans')
        return
    scan_id = ids[0]
    r = s.get(f'{BASE_URL}/url_scan/{scan_id}', timeout=60)
    check('GET /url_scan/<stored id> -> 200', r.status_code == 200, f'got {r.status_code}')

    r = s.get(f'{BASE_URL}/url_scan/screenshot/{scan_id}', timeout=60)
    check('GET screenshot of a stored scan -> 200 PNG (or 404 if the file was pruned)',
          (r.status_code == 200 and r.headers.get('content-type') == 'image/png')
          or r.status_code == 404,
          f'got {r.status_code} {r.headers.get("content-type")}')

    r = s.get(f'{BASE_URL}/url_scan/screenshot/{scan_id}?stage=../../etc/passwd', timeout=30)
    check('screenshot ?stage is whitelisted -> 404', r.status_code == 404, f'got {r.status_code}')


# E-mail analysis creates one record per submission, deleted in cleanup(). Kept
# header-only so enrichment stays cheap.
SELFTEST_EML = (
    b"From: Alice <alice@example.com>\r\n"
    b"To: bob@example.org\r\n"
    b"Subject: NexusTrace endpoint selftest\r\n"
    b"Date: Tue, 28 Jul 2026 10:00:00 +0000\r\n"
    b"Message-ID: <endpoint-selftest@example.com>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Hello, this is an endpoint self-test message.\r\n"
)


def _track_analysis(location):
    analysis_id = (location or '').rstrip('/').rsplit('/', 1)[-1]
    if re.fullmatch(r'[0-9a-f-]{36}', analysis_id):
        CREATED_FILES.append(os.path.join(REPO_ROOT, 'data', 'analyses', f'{analysis_id}.json'))
    return analysis_id


def test_email_analysis(s, tok):
    print('\nE-mail analysis:')
    r = s.get(f'{BASE_URL}/email_analysis', timeout=30)
    check('GET /email_analysis -> 200', r.status_code == 200, f'got {r.status_code}')

    check('GET /email_analysis/<unknown> -> 404',
          s.get(f'{BASE_URL}/email_analysis/{uuid.uuid4()}', timeout=30).status_code == 404)

    r = s.post(f'{BASE_URL}/email_analysis', data={'csrf_token': tok},
               timeout=30, allow_redirects=False)
    check('POST /email_analysis with nothing -> redirect to the form',
          r.status_code in (302, 303)
          and r.headers.get('Location', '').endswith('/email_analysis'),
          f'got {r.status_code} {r.headers.get("Location")}')

    r = s.post(f'{BASE_URL}/email_analysis',
               files={'file': ('selftest.eml', SELFTEST_EML)},
               data={'csrf_token': tok}, timeout=120, allow_redirects=False)
    check('POST /email_analysis upload -> redirect to a result',
          r.status_code in (302, 303) and '/email_analysis/' in r.headers.get('Location', ''),
          f'got {r.status_code} {r.headers.get("Location")}')
    upload_id = _track_analysis(r.headers.get('Location'))
    if upload_id:
        rr = s.get(f'{BASE_URL}/email_analysis/{upload_id}', timeout=60)
        check('GET the uploaded analysis -> 200', rr.status_code == 200, f'got {rr.status_code}')
        check('the result page is the parsed message',
              'NexusTrace endpoint selftest' in title_of(rr.text),
              f'title={title_of(rr.text)!r}')

    r = s.post(f'{BASE_URL}/email_analysis',
               data={'raw': SELFTEST_EML.decode(), 'csrf_token': tok},
               timeout=120, allow_redirects=False)
    check('POST /email_analysis paste -> redirect to a result',
          r.status_code in (302, 303) and '/email_analysis/' in r.headers.get('Location', ''),
          f'got {r.status_code} {r.headers.get("Location")}')
    _track_analysis(r.headers.get('Location'))


# Creates one file under data/cyberchef_recipes, deleted in cleanup().
RECIPE_NAME = 'nexustrace_endpoint_selftest'


def test_cyberchef_api(s, tok):
    print('\nCyberChef API:')
    h = {'X-CSRFToken': tok}

    r = s.post(f'{BASE_URL}/api/cyberchef/run', json={'input': 'abc', 'recipe': []},
               headers=h, timeout=30)
    check('POST /api/cyberchef/run echoes its input',
          r.status_code == 200 and r.json().get('input') == 'abc',
          f'got {r.status_code} {r.text[:100]}')

    r = s.get(f'{BASE_URL}/api/cyberchef/recipes', timeout=30)
    check('GET /api/cyberchef/recipes -> 200 list',
          r.status_code == 200 and isinstance(r.json(), list), f'got {r.status_code}')

    r = s.post(f'{BASE_URL}/api/cyberchef/recipes', json={'description': 'no name'},
               headers=h, timeout=30)
    check('POST recipe without a name -> 400', r.status_code == 400, f'got {r.status_code}')

    r = s.post(f'{BASE_URL}/api/cyberchef/recipes', json={'name': 'bad name!'},
               headers=h, timeout=30)
    check('POST recipe with illegal characters -> 400', r.status_code == 400,
          f'got {r.status_code}')

    r = s.post(f'{BASE_URL}/api/cyberchef/recipes',
               json={'name': RECIPE_NAME, 'description': 'temp', 'recipe': []},
               headers=h, timeout=30)
    check('POST a valid recipe -> 200', r.status_code == 200, f'got {r.status_code} {r.text[:100]}')
    if r.status_code == 200:
        CREATED_FILES.append(os.path.join(REPO_ROOT, 'data', 'cyberchef_recipes',
                                          f'{RECIPE_NAME}.json'))
        rr = s.get(f'{BASE_URL}/api/cyberchef/recipes/{RECIPE_NAME}.json', timeout=30)
        check('GET the saved recipe -> 200 with its name',
              rr.status_code == 200 and rr.json().get('name') == RECIPE_NAME,
              f'got {rr.status_code} {rr.text[:100]}')

    r = s.get(f'{BASE_URL}/api/cyberchef/recipes/no_such_recipe_xyz.json', timeout=30)
    check('GET an unknown recipe -> 404', r.status_code == 404, f'got {r.status_code}')

    r = s.get(f'{BASE_URL}/api/cyberchef/recipes/..%2F..%2Fapi_keys.json', timeout=30)
    check('recipe traversal attempt is refused',
          r.status_code in (400, 404), f'got {r.status_code} {r.text[:100]}')


def test_enrichment_auth():
    print('\nEnrichment API auth (csrf-exempt, X-API-Key):')
    bodies = {'/api/enrich/ip': {'ip': '8.8.8.8'},
              '/api/enrich/domain': {'indicator': 'example.com'},
              '/api/enrich/batch': {'indicators': ['8.8.8.8']}}
    for path, body in bodies.items():
        r = requests.post(BASE_URL + path, json=body, timeout=30)
        check(f'POST {path} without a key -> 401',
              r.status_code == 401 and 'X-API-Key' in r.text, f'got {r.status_code}')

        r = requests.post(BASE_URL + path, json=body,
                          headers={'X-API-Key': 'not-a-real-key'}, timeout=30)
        check(f'POST {path} with an invalid key -> 403', r.status_code == 403,
              f'got {r.status_code}')
    skip('authenticated /api/enrich/* responses',
         'requires a provisioned key in data/api_keys.json')


def _redirects_home(r):
    """Flask emits a relative Location, so compare the path, not the whole URL."""
    if r.status_code not in (302, 303):
        return False
    return urlparse(r.headers.get('Location', '')).path == '/'


def test_csrf_enforced():
    print('\nCSRF enforcement (tokenless POSTs):')
    # The CSRFError handler 303s to home rather than returning 400 - even for the
    # JSON API endpoints.
    for path, body in [('/api/ip/check_ip', {'ip': '8.8.8.8'}),
                       ('/api/domain/check_domain', {'domain': 'example.com'}),
                       ('/api/hash/check_hash', {'hash': 'd41d8cd98f00b204e9800998ecf8427e'}),
                       ('/api/cyberchef/recipes', {'name': 'should_never_be_written'})]:
        r = requests.post(BASE_URL + path, json=body, timeout=30, allow_redirects=False)
        check(f'POST {path} without a CSRF token -> redirect home',
              _redirects_home(r), f'got {r.status_code} {r.headers.get("Location")}')

    for path, data in [('/analyze', {'indicator': '8.8.8.8'}),
                       ('/url_scan', {'url': 'https://example.com'}),
                       ('/email_analysis', {'raw': 'From: a@b.c\r\n\r\nx'})]:
        r = requests.post(BASE_URL + path, data=data, timeout=30, allow_redirects=False)
        check(f'POST {path} without a CSRF token -> redirect home',
              _redirects_home(r), f'got {r.status_code} {r.headers.get("Location")}')


def test_security_headers(s):
    print('\nSecurity headers:')
    r = s.get(f'{BASE_URL}/', timeout=30)
    check('Content-Security-Policy present', 'Content-Security-Policy' in r.headers)
    check('X-Content-Type-Options: nosniff',
          r.headers.get('X-Content-Type-Options') == 'nosniff',
          f'got {r.headers.get("X-Content-Type-Options")!r}')
    check('HTML is sent no-store so CSRF tokens are never stale',
          'no-store' in r.headers.get('Cache-Control', ''),
          f'got {r.headers.get("Cache-Control")!r}')


def cleanup():
    """Remove only what this run created."""
    print('\nCleanup:')
    if not CREATED_FILES:
        print('  nothing to remove')
        return
    for path in CREATED_FILES:
        try:
            os.remove(path)
            print(f'  removed {os.path.relpath(path, REPO_ROOT)}')
        except FileNotFoundError:
            print(f'  already gone {os.path.relpath(path, REPO_ROOT)}')
        except OSError as e:
            print(f'  COULD NOT REMOVE {path}: {e}')


def main():
    print(f'NexusTrace endpoint tests against {BASE_URL}')
    try:
        s, tok = session_with_csrf()
    except requests.exceptions.ConnectionError:
        print(f'\nError: no server at {BASE_URL}. Start one with ./start.sh '
              f'(or set NEXUSTRACE_BASE_URL).')
        return 2

    try:
        test_pages(s)
        test_health(s)
        test_security_headers(s)
        test_ip_api(s, tok)
        test_domain_api(s, tok)
        test_hash_api(s, tok)
        test_file_api(s, tok)
        test_lookup_apis(s, tok)
        test_unified_analysis(s, tok)
        test_search_forms(s, tok)
        test_scanner_get_surfaces(s, tok)
        test_email_analysis(s, tok)
        test_cyberchef_api(s, tok)
        test_enrichment_auth()
        test_csrf_enforced()
    finally:
        cleanup()

    print(f'\n{len(PASSED)} passed, {len(FAILED)} failed, '
          f'{len(SKIPPED)} skipped, {len(KNOWN_ISSUES)} known issues')
    if KNOWN_ISSUES:
        print('Known issues (app bugs, not test failures):')
        for name, detail in KNOWN_ISSUES:
            print(f'  - {name}: {detail}')
    if FAILED:
        print('Failures:')
        for name, detail in FAILED:
            print(f'  - {name}  {detail}')
    return 1 if FAILED else 0


if __name__ == '__main__':
    sys.exit(main())
