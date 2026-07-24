"""URL scanner service — headless Chromium scan with DNS/TLS/ASN/tech enrichment."""
import json
import logging
import re
import socket
import ssl
import uuid
import ipaddress
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

import dns.resolver
import dns.reversename
import dns.exception

logger = logging.getLogger(__name__)

_BASE = Path(__file__).resolve().parent.parent.parent
SCAN_DIR = _BASE / 'data' / 'scans'
SCREENSHOT_DIR = _BASE / 'data' / 'screenshots'

SCAN_DIR.mkdir(parents=True, exist_ok=True)
SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

MOBILE_UA = (
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) '
    'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
)


# ---------------------------------------------------------------------------
# SSRF guard
# ---------------------------------------------------------------------------

def is_scannable(url: str) -> bool:
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url if re.match(r'^https?://', url, re.I) else f'http://{url}')
    except Exception:
        return False
    if parsed.scheme not in ('http', 'https'):
        return False
    host = parsed.hostname or ''
    if not host:
        return False
    # Reject obviously-internal targets by hostname pattern.
    if host in ('localhost',) or host.endswith('.localhost'):
        return False
    if host.endswith('.internal') or host.endswith('.local'):
        return False
    private_patterns = [
        r'^127\.', r'^10\.', r'^192\.168\.', r'^169\.254\.', r'^0\.',
        r'^172\.(1[6-9]|2\d|3[01])\.',
    ]
    for pat in private_patterns:
        if re.match(pat, host):
            return False
    if host in ('::1',) or re.match(r'^f[cd][0-9a-f]{2}:', host) or host.startswith('fe80'):
        return False
    # Also resolve and check IPs for hostname-based SSRF.
    try:
        for _fam, _type, _proto, _canon, sockaddr in socket.getaddrinfo(host, None):
            ip = ipaddress.ip_address(sockaddr[0])
            if not ip.is_global:
                return False
    except (socket.gaierror, ValueError):
        return False
    return True


# ---------------------------------------------------------------------------
# Storage
# ---------------------------------------------------------------------------

def save_scan(scan: dict) -> None:
    path = SCAN_DIR / f"{scan['id']}.json"
    path.write_text(json.dumps(scan, default=str), encoding='utf-8')


def get_scan(scan_id: str) -> dict | None:
    path = SCAN_DIR / f"{scan_id}.json"
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return None


def list_scans(limit: int = 100) -> list:
    files = sorted(SCAN_DIR.glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True)
    result = []
    for f in files[:limit]:
        try:
            data = json.loads(f.read_text(encoding='utf-8'))
            sid = data.get('id', '')
            result.append({
                'id': sid,
                'url': data.get('url'),
                'created_at': data.get('created_at'),
                'status': data.get('status'),
                'http_status': data.get('page', {}).get('status'),
                'main_ip': data.get('main_ip'),
                'asn': (data.get('asn') or {}).get('asn'),
                'title': data.get('page', {}).get('title'),
                'has_screenshot': screenshot_path(sid).exists() if sid else False,
            })
        except Exception:
            continue
    return result


def screenshot_path(scan_id: str) -> Path:
    return SCREENSHOT_DIR / f"{scan_id}.png"


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

_RECORD_TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA', 'CAA']

def resolve_all(host: str) -> dict:
    result = {}
    res = dns.resolver.Resolver()
    res.lifetime = 5
    for rtype in _RECORD_TYPES:
        try:
            answers = res.resolve(host, rtype)
            vals = []
            for rdata in answers:
                if rtype == 'MX':
                    vals.append({'exchange': str(rdata.exchange).rstrip('.'), 'priority': rdata.preference})
                elif rtype == 'SOA':
                    vals.append({
                        'mname': str(rdata.mname).rstrip('.'),
                        'rname': str(rdata.rname).rstrip('.'),
                        'serial': rdata.serial,
                    })
                else:
                    vals.append(str(rdata).rstrip('"').lstrip('"').rstrip('.'))
            result[rtype] = vals
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout,
                dns.resolver.NoNameservers, Exception):
            pass
    return result


def reverse_ptr(ip: str) -> list:
    try:
        rev = dns.reversename.from_address(ip)
        res = dns.resolver.Resolver()
        res.lifetime = 3
        answers = res.resolve(rev, 'PTR')
        return [str(r).rstrip('.') for r in answers]
    except Exception:
        return []


def lookup_asn(ip: str) -> dict | None:
    try:
        # Team Cymru DNS-based ASN lookup — no API key needed
        parts = ip.split('.')
        if len(parts) == 4:
            query = '.'.join(reversed(parts)) + '.origin.asn.cymru.com'
        else:
            # IPv6 — skip for now
            return None
        res = dns.resolver.Resolver()
        res.lifetime = 4
        answers = res.resolve(query, 'TXT')
        for rdata in answers:
            txt = ''.join(
                (s.decode('utf-8') if isinstance(s, bytes) else str(s)).strip('"')
                for s in rdata.strings
            )
            # Format: "ASN | prefix | country | registry | date"
            parts_txt = [p.strip() for p in txt.split('|')]
            if len(parts_txt) >= 3:
                asn_raw = parts_txt[0].strip()
                asn = f"AS{asn_raw}" if not asn_raw.upper().startswith('AS') else asn_raw
                # Cymru name lookup
                name = _cymru_asn_name(asn_raw)
                return {
                    'asn': asn,
                    'name': name,
                    'prefix': parts_txt[1].strip() if len(parts_txt) > 1 else None,
                    'country': parts_txt[2].strip() if len(parts_txt) > 2 else None,
                    'registry': parts_txt[3].strip() if len(parts_txt) > 3 else None,
                }
    except Exception:
        pass
    return None


def _cymru_asn_name(asn_number: str) -> str | None:
    try:
        query = f'AS{asn_number}.asn.cymru.com'
        res = dns.resolver.Resolver()
        res.lifetime = 3
        answers = res.resolve(query, 'TXT')
        for rdata in answers:
            txt = ''.join(
                (s.decode('utf-8') if isinstance(s, bytes) else str(s)).strip('"')
                for s in rdata.strings
            )
            parts = [p.strip() for p in txt.split('|')]
            if len(parts) >= 5:
                return parts[4].strip()
    except Exception:
        pass
    return None


# ---------------------------------------------------------------------------
# TLS inspection
# ---------------------------------------------------------------------------

def inspect_certificate(host: str, port: int = 443) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL
        with socket.create_connection((host, port), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                authorized = bool(cert)
                # Check if cert is actually verified (not just available)
                try:
                    ctx2 = ssl.create_default_context()
                    with socket.create_connection((host, port), timeout=8) as raw2:
                        with ctx2.wrap_socket(raw2, server_hostname=host) as sock2:
                            authorized = True
                except ssl.SSLCertVerificationError:
                    authorized = False
                except Exception:
                    authorized = False

                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))
                sans = cert.get('subjectAltName', [])
                san_str = ', '.join(f'{t}:{v}' for t, v in sans) if sans else None
                cipher = sock.cipher()
                return {
                    'subject': subject.get('commonName') or subject.get('organizationName'),
                    'issuer': issuer.get('commonName') or issuer.get('organizationName'),
                    'valid_from': cert.get('notBefore'),
                    'valid_to': cert.get('notAfter'),
                    'serial_number': cert.get('serialNumber'),
                    'protocol': sock.version(),
                    'cipher': cipher[0] if cipher else None,
                    'subject_alt_name': san_str,
                    'authorized': authorized,
                }
    except Exception as e:
        logger.debug('TLS inspection failed for %s: %s', host, e)
        return None


# ---------------------------------------------------------------------------
# Security header grading
# ---------------------------------------------------------------------------

_SECURITY_RULES = [
    {
        'name': 'HSTS',
        'header': 'strict-transport-security',
        'weak': re.compile(r'max-age=([0-9]+)'),
        'weak_threshold': 2592000,  # 30 days in seconds
    },
    {'name': 'Content Security Policy', 'header': 'content-security-policy'},
    {'name': 'X-Frame-Options', 'header': 'x-frame-options'},
    {'name': 'X-Content-Type-Options', 'header': 'x-content-type-options'},
    {'name': 'Referrer-Policy', 'header': 'referrer-policy'},
    {'name': 'Permissions-Policy', 'header': 'permissions-policy'},
    {'name': 'Cross-Origin-Resource-Policy', 'header': 'cross-origin-resource-policy'},
    {'name': 'Cross-Origin-Opener-Policy', 'header': 'cross-origin-opener-policy'},
]


def analyze_security_headers(headers: dict) -> dict:
    lower = {k.lower(): v for k, v in headers.items()}
    results = []
    score = 0
    for rule in _SECURITY_RULES:
        h = rule['header']
        val = lower.get(h)
        if val is None:
            results.append({'name': rule['name'], 'header': h, 'status': 'missing', 'value': None})
        elif 'weak' in rule:
            m = rule['weak'].search(val)
            if m and int(m.group(1)) < rule['weak_threshold']:
                results.append({'name': rule['name'], 'header': h, 'status': 'weak', 'value': val[:120]})
            else:
                results.append({'name': rule['name'], 'header': h, 'status': 'ok', 'value': val[:120]})
                score += 1
        else:
            results.append({'name': rule['name'], 'header': h, 'status': 'ok', 'value': val[:120]})
            score += 1
    return {'results': results, 'score': score, 'total': len(_SECURITY_RULES)}


# ---------------------------------------------------------------------------
# Technology fingerprinting
# ---------------------------------------------------------------------------

_TECH_RULES = [
    # CDN / edge
    {'name': 'Cloudflare', 'category': 'CDN', 'headers': {'server': r'cloudflare', 'cf-ray': r'.+'}},
    {'name': 'Amazon CloudFront', 'category': 'CDN', 'headers': {'server': r'cloudfront', 'x-amz-cf-id': r'.+'}},
    {'name': 'Fastly', 'category': 'CDN', 'headers': {'x-served-by': r'cache-', 'x-fastly-request-id': r'.+'}},
    {'name': 'Akamai', 'category': 'CDN', 'headers': {'server': r'akamai', 'x-akamai-transformed': r'.+'}},
    {'name': 'Varnish', 'category': 'Caching', 'headers': {'x-varnish': r'.+', 'via': r'varnish'}},
    # Web servers
    {'name': 'nginx', 'category': 'Web server', 'headers': {'server': r'nginx'}},
    {'name': 'Apache', 'category': 'Web server', 'headers': {'server': r'apache'}},
    {'name': 'Microsoft IIS', 'category': 'Web server', 'headers': {'server': r'iis|microsoft-httpapi'}},
    {'name': 'Envoy', 'category': 'Web server', 'headers': {'server': r'envoy'}},
    {'name': 'LiteSpeed', 'category': 'Web server', 'headers': {'server': r'litespeed'}},
    {'name': 'Caddy', 'category': 'Web server', 'headers': {'server': r'caddy'}},
    # Hosting
    {'name': 'Vercel', 'category': 'Hosting', 'headers': {'server': r'vercel', 'x-vercel-id': r'.+'}},
    {'name': 'Netlify', 'category': 'Hosting', 'headers': {'server': r'netlify', 'x-nf-request-id': r'.+'}},
    {'name': 'GitHub Pages', 'category': 'Hosting', 'headers': {'server': r'github\.com'}},
    # Languages / frameworks
    {'name': 'PHP', 'category': 'Language', 'headers': {'x-powered-by': r'php'}, 'cookies': ['PHPSESSID']},
    {'name': 'Express', 'category': 'Framework', 'headers': {'x-powered-by': r'express'}},
    {'name': 'ASP.NET', 'category': 'Framework', 'headers': {'x-powered-by': r'asp\.net', 'x-aspnet-version': r'.+'},
     'cookies': ['ASP.NET_SessionId']},
    {'name': 'Ruby on Rails', 'category': 'Framework', 'cookies': ['_rails_session'],
     'headers': {'x-powered-by': r'phusion passenger'}},
    {'name': 'Laravel', 'category': 'Framework', 'cookies': ['laravel_session', 'XSRF-TOKEN']},
    {'name': 'Django', 'category': 'Framework', 'cookies': ['csrftoken', 'sessionid']},
    # CMS / ecommerce
    {'name': 'WordPress', 'category': 'CMS', 'html': r'wp-content|wp-includes',
     'meta': {'generator': r'wordpress'}},
    {'name': 'Drupal', 'category': 'CMS', 'html': r'sites/(all|default)/',
     'meta': {'generator': r'drupal'}, 'headers': {'x-generator': r'drupal'}},
    {'name': 'Joomla', 'category': 'CMS', 'meta': {'generator': r'joomla'}},
    {'name': 'Ghost', 'category': 'CMS', 'meta': {'generator': r'ghost'}},
    {'name': 'Wix', 'category': 'CMS', 'meta': {'generator': r'wix\.com'},
     'headers': {'x-wix-request-id': r'.+'}},
    {'name': 'Squarespace', 'category': 'CMS', 'html': r'static1\.squarespace\.com'},
    {'name': 'Shopify', 'category': 'Ecommerce', 'headers': {'x-shopify-stage': r'.+'},
     'html': r'cdn\.shopify\.com'},
    # JS frameworks / libraries
    {'name': 'React', 'category': 'JS framework',
     'html': r'data-reactroot|__reactContainer',
     'scripts': r'react(?:-dom)?(?:\.production)?(?:\.min)?\.js'},
    {'name': 'Next.js', 'category': 'JS framework',
     'html': r'_next/static|__NEXT_DATA__',
     'headers': {'x-powered-by': r'next\.js'}},
    {'name': 'Vue.js', 'category': 'JS framework',
     'html': r'data-v-[0-9a-f]{8}|__vue__',
     'scripts': r'vue(?:\.runtime)?(?:\.global)?(?:\.min)?\.js'},
    {'name': 'Nuxt.js', 'category': 'JS framework', 'html': r'__NUXT__|/_nuxt/'},
    {'name': 'Angular', 'category': 'JS framework', 'html': r'ng-version=|_nghost-'},
    {'name': 'Svelte', 'category': 'JS framework', 'html': r'svelte-[0-9a-z]{6}'},
    {'name': 'jQuery', 'category': 'JS library',
     'scripts': r'jquery(?:-\d[\d.]*)?(?:\.slim)?(?:\.min)?\.js'},
    {'name': 'Bootstrap', 'category': 'UI framework',
     'html': r'bootstrap(?:\.min)?\.(?:css|js)'},
    {'name': 'Tailwind CSS', 'category': 'UI framework', 'html': r'--tw-[a-z-]+:'},
    # Analytics
    {'name': 'Google Analytics', 'category': 'Analytics',
     'scripts': r'google-analytics\.com/(?:analytics|ga)\.js|gtag/js',
     'html': r'GoogleAnalyticsObject'},
    {'name': 'Google Tag Manager', 'category': 'Tag manager',
     'scripts': r'googletagmanager\.com/gtm\.js'},
    {'name': 'Cloudflare Insights', 'category': 'Analytics',
     'scripts': r'static\.cloudflareinsights\.com'},
    {'name': 'HubSpot', 'category': 'Marketing', 'scripts': r'js\.hs-scripts\.com'},
    # Fonts / misc
    {'name': 'Google Fonts', 'category': 'Font', 'html': r'fonts\.googleapis\.com'},
    {'name': 'Font Awesome', 'category': 'Font', 'html': r'font-?awesome'},
    {'name': 'reCAPTCHA', 'category': 'Security',
     'scripts': r'(?:google\.com|gstatic\.com)/recaptcha'},
    {'name': 'Stripe', 'category': 'Payments', 'scripts': r'js\.stripe\.com'},
]

# Pre-compile all regexes
for _rule in _TECH_RULES:
    if 'headers' in _rule:
        _rule['_headers_re'] = {h: re.compile(p, re.I) for h, p in _rule['headers'].items()}
    if 'html' in _rule:
        _rule['_html_re'] = re.compile(_rule['html'], re.I)
    if 'scripts' in _rule:
        _rule['_scripts_re'] = re.compile(_rule['scripts'], re.I)
    if 'meta' in _rule:
        _rule['_meta_re'] = {k: re.compile(p, re.I) for k, p in _rule['meta'].items()}


def detect_technologies(headers: dict, cookies: list, html: str, scripts: list) -> list:
    lower_headers = {k.lower(): str(v) for k, v in headers.items()}
    cookie_names = [c['name'].lower() for c in cookies]
    script_str = '\n'.join(scripts)
    found = []
    seen = set()

    for rule in _TECH_RULES:
        hit = False
        if '_headers_re' in rule:
            # Any single header match counts as a hit
            if any(lower_headers.get(h) and rx.search(lower_headers[h])
                   for h, rx in rule['_headers_re'].items()):
                hit = True
        if not hit and 'cookies' in rule:
            if any(c.lower() in cookie_names for c in rule['cookies']):
                hit = True
        if not hit and '_html_re' in rule and rule['_html_re'].search(html):
            hit = True
        if not hit and '_scripts_re' in rule and rule['_scripts_re'].search(script_str):
            hit = True
        if not hit and '_meta_re' in rule:
            for meta_name, rx in rule['_meta_re'].items():
                pat = re.compile(
                    rf'<meta[^>]+name=["\']?{re.escape(meta_name)}["\']?[^>]+content=["\']([^"\']*)["\']',
                    re.I,
                )
                m = pat.search(html)
                if m and rx.search(m.group(1)):
                    hit = True
                    break
        if hit and rule['name'] not in seen:
            seen.add(rule['name'])
            found.append({'name': rule['name'], 'category': rule['category']})

    return found


# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------

def compute_verdict(scan: dict) -> dict:
    signals = []
    tls = scan.get('tls')
    if tls and tls.get('authorized') is False:
        signals.append('TLS certificate is not trusted')
    try:
        final_host = urlparse(scan.get('page', {}).get('final_url', '')).hostname
        orig_host = urlparse(scan.get('url', '')).hostname
        if final_host and orig_host and final_host != orig_host:
            signals.append('Redirects to a different domain')
    except Exception:
        pass
    sec = scan.get('security') or {}
    if sec.get('score', 0) <= 1:
        signals.append('Few or no security headers present')
    if len(scan.get('domains', [])) >= 25:
        signals.append('Contacts a large number of third-party domains')
    return {'level': 'informational', 'signals': signals}


# ---------------------------------------------------------------------------
# Main scan pipeline (sync Playwright)
# ---------------------------------------------------------------------------

def _safe_hostname(url: str) -> str | None:
    try:
        return urlparse(url).hostname
    except Exception:
        return None


def run_scan(raw_url: str, device: str = 'desktop') -> dict:
    from playwright.sync_api import sync_playwright

    scan_id = str(uuid.uuid4())
    url = raw_url.strip()
    if not re.match(r'^https?://', url, re.I):
        url = f'http://{url}'

    scan = {
        'id': scan_id,
        'url': url,
        'device': device,
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'status': 'running',
        'error': None,
        'user_agent': None,
        'page': {},
        'transactions': [],
        'redirects': [],
        'console': [],
        'cookies': [],
        'technologies': [],
        'dns': {},
        'tls': None,
        'asn': None,
        'ptr': [],
        'main_ip': None,
        'domains': [],
        'ips': [],
        'links': [],
        'verdict': None,
        'security': None,
        'whois': None,
    }

    is_mobile = device == 'mobile'

    with sync_playwright() as pw:
        browser = pw.chromium.launch(args=['--no-sandbox', '--disable-dev-shm-usage'])
        try:
            context = browser.new_context(
                viewport={'width': 390, 'height': 844} if is_mobile else {'width': 1366, 'height': 768},
                user_agent=MOBILE_UA if is_mobile else None,
                device_scale_factor=3 if is_mobile else 1,
                ignore_https_errors=True,
            )
            page = context.new_page()
            scan['user_agent'] = page.evaluate('navigator.userAgent')

            transactions = []

            def on_response(res):
                try:
                    req = res.request
                    try:
                        size = len(res.body())
                    except Exception:
                        size = None
                    try:
                        sa = res.server_addr()
                        server_ip = sa['ipAddress'] if sa else None
                    except Exception:
                        server_ip = None
                    transactions.append({
                        'url': req.url,
                        'method': req.method,
                        'resource_type': req.resource_type,
                        'status': res.status,
                        'status_text': res.status_text,
                        'mime_type': (res.headers.get('content-type') or '').split(';')[0].strip() or None,
                        'size_bytes': size,
                        'server_ip': server_ip,
                        'response_headers': dict(res.headers),
                    })
                except Exception:
                    pass

            page.on('response', on_response)

            console_msgs = []
            def on_console(msg):
                if len(console_msgs) < 200:
                    console_msgs.append({'type': msg.type, 'text': msg.text[:500]})
            page.on('console', on_console)

            main_response = None
            try:
                main_response = page.goto(url, wait_until='networkidle', timeout=30000)
            except Exception:
                try:
                    main_response = page.goto(url, wait_until='domcontentloaded', timeout=30000)
                except Exception as e:
                    scan['error'] = f'Navigation failed: {e}'

            page.wait_for_timeout(1500)

            # Redirect chain
            if main_response:
                chain = []
                stack = []
                cur = main_response.request
                while cur:
                    stack.insert(0, cur)
                    cur = cur.redirected_from
                for rq in stack:
                    try:
                        resp = rq.response()
                        chain.append({
                            'url': rq.url,
                            'status': resp.status if resp else None,
                            'location': resp.headers.get('location') if resp else None,
                        })
                    except Exception:
                        chain.append({'url': rq.url, 'status': None, 'location': None})
                scan['redirects'] = chain

            # In-page metadata
            meta = page.evaluate('''() => {
                const attr = (sel, a) => { const el = document.querySelector(sel); return el ? el.getAttribute(a) : null; };
                const icon = document.querySelector('link[rel~="icon"]');
                return {
                    title: document.title || null,
                    description: attr('meta[name="description"]', 'content'),
                    lang: document.documentElement.lang || null,
                    favicon: icon ? icon.href : null,
                    scripts: Array.from(document.querySelectorAll('script[src]')).map(s => s.src),
                    links: Array.from(document.querySelectorAll('a[href]')).map(a => a.href),
                    html: document.documentElement.outerHTML.slice(0, 500000),
                };
            }''')

            final_url = page.url
            scan['page'] = {
                'final_url': final_url,
                'title': meta.get('title'),
                'description': meta.get('description'),
                'lang': meta.get('lang'),
                'favicon': meta.get('favicon'),
                'status': main_response.status if main_response else None,
                'status_text': main_response.status_text if main_response else None,
                'response_headers': dict(main_response.headers) if main_response else {},
                'screenshot_url': None,
            }

            # Screenshot
            try:
                shot_bytes = page.screenshot(full_page=True, type='png')
                screenshot_path(scan_id).write_bytes(shot_bytes)
                scan['page']['screenshot_url'] = f'/url_scan/screenshot/{scan_id}'
            except Exception:
                pass

            # Cookies
            scan['cookies'] = [
                {
                    'name': c['name'],
                    'domain': c['domain'],
                    'path': c['path'],
                    'secure': c['secure'],
                    'http_only': c['httpOnly'],
                    'same_site': c.get('sameSite'),
                    'session': c.get('expires', -1) == -1,
                    'expires': c.get('expires'),
                }
                for c in context.cookies()
            ]

            scan['transactions'] = transactions
            scan['console'] = console_msgs

            # Aggregate domains + IPs
            domain_map: dict = {}
            ip_set: set = set()
            for t in transactions:
                host = _safe_hostname(t['url'])
                if host:
                    domain_map.setdefault(host, set())
                    if t.get('server_ip'):
                        domain_map[host].add(t['server_ip'])
                if t.get('server_ip'):
                    ip_set.add(t['server_ip'])

            scan['domains'] = sorted(
                [{'domain': d, 'ips': sorted(ips)} for d, ips in domain_map.items()],
                key=lambda x: x['domain'],
            )
            scan['ips'] = sorted(ip_set)
            scan['links'] = list(dict.fromkeys(meta.get('links') or []))[:500]

            # Tech + security
            scan['technologies'] = detect_technologies(
                headers=scan['page']['response_headers'],
                cookies=scan['cookies'],
                html=meta.get('html') or '',
                scripts=meta.get('scripts') or [],
            )
            scan['security'] = analyze_security_headers(scan['page']['response_headers'])

            # DNS / TLS / ASN
            primary_host = _safe_hostname(final_url) or _safe_hostname(url)
            if primary_host:
                try:
                    import ipaddress as _ipa
                    _ipa.ip_address(primary_host)
                    is_ip_literal = True
                except ValueError:
                    is_ip_literal = False

                if not is_ip_literal:
                    scan['dns'] = resolve_all(primary_host)
                    if final_url.startswith('https'):
                        scan['tls'] = inspect_certificate(primary_host)

            # Determine main IP
            primary_txn = next(
                (t for t in transactions if _safe_hostname(t['url']) == primary_host and t.get('server_ip')),
                None,
            )
            main_ip = (
                (primary_txn or {}).get('server_ip')
                or (scan['ips'][0] if scan['ips'] else None)
                or (scan['dns'].get('A') or [None])[0]
            )
            if main_ip:
                scan['main_ip'] = main_ip
                scan['asn'] = lookup_asn(main_ip)
                scan['ptr'] = reverse_ptr(main_ip)

            # WHOIS enrichment for the primary host
            if primary_host and not is_ip_literal:
                try:
                    from app.services.domain_service import get_whois_info
                    scan['whois'] = get_whois_info(primary_host)
                except Exception as e:
                    logger.debug('WHOIS lookup failed for %s: %s', primary_host, e)

            scan['verdict'] = compute_verdict(scan)
            scan['status'] = 'error' if scan['error'] else 'done'

        except Exception as e:
            scan['status'] = 'error'
            scan['error'] = str(e)
            logger.exception('Scan failed for %s', url)
        finally:
            browser.close()

    return scan
