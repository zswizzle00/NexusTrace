"""URL scanner service — headless Chromium scan with DNS/TLS/ASN/tech enrichment."""
import json
import logging
import ipaddress
import re
import socket
import ssl
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin

import dns.resolver
import dns.reversename
import dns.exception

from ..utils.url_guard import UnsafeURLError, caching_resolver, is_scannable, validate_target

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


# Cap the blocked-request log so a hostile page cannot bloat the stored scan.
MAX_BLOCKED_REQUESTS = 50

# Defends against a redirect loop the guard itself would otherwise chase forever.
MAX_REDIRECT_HOPS = 20

_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

# Round 1 review, Finding 5: `context.route_web_socket` needs its own scheme
# check because `validate_target`/`normalize` are scoped to http(s) - see
# `_validate_ws_target`.
_WS_SCHEME_MAP = {'ws': 'http', 'wss': 'https'}


def _record_block(scan: dict, seen: set, url: str, reason: str, kind: str = 'blocked') -> None:
    """Append one entry to ``scan['blocked_requests']``.

    Round 1 review, Finding 8: deduped on ``(url, reason)`` - `page.goto`'s
    internal retry (see `run_scan`) re-walks and re-validates the whole chain
    on the same URL, which used to double every entry.

    Round 1 review, Finding 7: ``kind`` distinguishes an actual security block
    (``'blocked'``) from a transport failure (``'network_error'`` - DNS,
    connection refused, TLS, per-hop timeout) so the two are not presented to
    the analyst as the same thing. Additive field; does not change the shape
    Task 2's brief specified (``{'url', 'reason'}``) for existing consumers.
    ``reason`` is capped independently of ``url`` - an exception message can
    be arbitrarily long where a URL is naturally bounded.
    """
    url = (url or '')[:500]
    reason = (reason or '')[:300]
    key = (url, reason, kind)
    if key in seen:
        return
    seen.add(key)
    if len(scan['blocked_requests']) < MAX_BLOCKED_REQUESTS:
        scan['blocked_requests'].append({'url': url, 'reason': reason, 'kind': kind})
    if kind == 'blocked':
        logger.warning('Blocked unsafe request to %s: %s', url[:200], reason)
    else:
        logger.info('Network error on %s: %s', url[:200], reason)


def _same_origin(url_a: str, url_b: str) -> bool:
    pa, pb = urlparse(url_a), urlparse(url_b)
    return (pa.scheme, pa.hostname, pa.port) == (pb.scheme, pb.hostname, pb.port)


def _strip_cross_origin_secrets(headers: dict | None, from_url: str, to_url: str) -> dict | None:
    """Round 1 review, Finding 9: a browser drops ``Authorization``/``Cookie``
    when a redirect crosses origins; Playwright's ``Route.fetch`` /
    ``APIRequestContext.fetch`` do not - by default they forward whatever
    headers were passed (or the original request's headers, verbatim) to
    *any* URL we hand them, including a different origin. Do the stripping
    ourselves rather than rely on that.
    """
    if not headers or _same_origin(from_url, to_url):
        return headers
    return {k: v for k, v in headers.items() if k.lower() not in ('authorization', 'cookie')}


def _resolve_display_ip(host: str | None, resolver) -> str | None:
    """Best-effort: the address ``validate_target`` actually judged ``host``
    by. Round 1 review, Finding 2: a fulfilled response has no
    ``server_addr()``, so this is the only way left to know the main
    document's real IP. ``resolver`` is the per-scan ``caching_resolver``, so
    for any host that was just validated this is a memoized lookup - no extra
    DNS round trip, and no new DNS dependency.
    """
    if not host:
        return None
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    try:
        addresses = resolver(host)
        return str(addresses[0]) if addresses else None
    except Exception:
        return None


def _is_main_frame_navigation(request) -> bool:
    """Round 1 review, Finding 1 (Critical): an iframe's main document request
    also has ``resource_type == 'document'``, so without this check a hostile
    ``<iframe src="...">`` that itself redirects would overwrite ``nav_state``
    with the *iframe's* final URL/chain - and through ``primary_host``,
    falsify the page's reported DNS/TLS/ASN/PTR/WHOIS to whatever the iframe
    points at. ``request.frame`` raises for service-worker requests (which
    are never ``'document'`` type in practice, but this stays defensive
    regardless); treat any failure to determine main-frame-ness as "not main
    frame" so it fails toward *not* touching `nav_state`, never toward
    falsely claiming main-frame status.
    """
    try:
        return request.is_navigation_request() and request.frame.parent_frame is None
    except Exception:
        return False


def _chase_redirects(fetch_one, start_url: str, resolver, *, method='GET', headers=None, post_data=None):
    """Validate and follow a redirect chain one hop at a time, so every
    ``Location`` is checked *before* it is ever handed to Chromium.

    This is deliberately the single implementation of "validate every hop" -
    round 1 review's redesign recommendation (see ``run_scan``'s pre-flight
    and ``_install_fetch_guard``'s in-handler backstop, both of which call
    this instead of duplicating the loop).

    ``fetch_one(url, method, headers, post_data)`` must perform one hop with
    redirects disabled and return a Playwright response-like object exposing
    ``.status`` (int) and ``.headers`` (a ``str -> str`` mapping with
    ``.get``). Both ``Route.fetch`` and ``APIRequestContext.fetch`` satisfy
    this through a small adapter closure at each call site, since their own
    parameter names/positions differ.

    Redirect semantics (round 1 review, Finding 9): a 301/302/303 downgrades
    the method to GET and drops the body, matching what a real browser does
    on those three codes (307/308 preserve both, by design). Headers are
    stripped of ``Authorization``/``Cookie`` on any hop that crosses origins
    (see ``_strip_cross_origin_secrets``) - browsers do this on every
    redirect; Playwright's fetch does not do it for us.

    Returns ``(outcome, payload)``:

    - ``('ok', {'final_url', 'final_response', 'chain', 'final_ip'})`` - the
      final, non-redirect response, plus every hop walked to reach it.
    - ``('blocked', {'url', 'reason', 'chain'})`` - a hop failed SSRF
      validation, the hop cap was hit, or a redirect status carried no
      ``Location`` to follow (round 1 review, Finding 6: this used to be
      misreported as ``'too many redirects'`` after silently `break`-ing out
      of the loop; it now gets its own accurate reason and the comment
      matches the code - both abort, so the earlier bug was mislabeled, not
      unsafe).
    - ``('error', {'url', 'reason', 'chain'})`` - a hop transport-failed (DNS,
      connection refused, TLS, per-hop timeout). Round 1 review, Finding 7:
      deliberately a distinct outcome from ``'blocked'`` so callers do not
      present "the site was unreachable" as "this target is unsafe".
    """
    current_url = start_url
    current_method = method
    current_headers = headers
    current_post_data = post_data
    chain: list = []

    for _ in range(MAX_REDIRECT_HOPS):
        try:
            response = fetch_one(current_url, current_method, current_headers, current_post_data)
        except Exception as exc:
            return 'error', {'url': current_url, 'reason': f'fetch failed: {exc}', 'chain': chain}

        if response.status in _REDIRECT_STATUSES:
            location = response.headers.get('location')
            chain.append({'url': current_url, 'status': response.status, 'location': location})
            if not location:
                return 'blocked', {
                    'url': current_url,
                    'reason': 'redirect with no Location header',
                    'chain': chain,
                }
            next_url = urljoin(current_url, location)
            try:
                validate_target(next_url, resolver=resolver)
            except UnsafeURLError as exc:
                return 'blocked', {'url': next_url, 'reason': str(exc), 'chain': chain}

            if response.status in (301, 302, 303):
                current_method = 'GET'
                current_post_data = None
            current_headers = _strip_cross_origin_secrets(current_headers, current_url, next_url)
            current_url = next_url
            continue

        chain.append({'url': current_url, 'status': response.status, 'location': None})
        final_ip = _resolve_display_ip(_safe_hostname(current_url), resolver)
        return 'ok', {
            'final_url': current_url,
            'final_response': response,
            'chain': chain,
            'final_ip': final_ip,
        }

    return 'blocked', {'url': current_url, 'reason': 'too many redirects', 'chain': chain}


def _install_fetch_guard(context, scan: dict, resolver, seen_blocks: set) -> dict:
    """Re-validate every request Chromium makes, not just the URL we were given.

    Two vectors this closes:

    1. **Redirects.** ``is_scannable`` vets the submitted URL; Chromium then
       follows the redirect chain itself, so a redirect to 127.0.0.1 or
       169.254.169.254 was previously fetched.
    2. **Subresources.** ``on_response`` records each response's status and
       ``server_ip`` into ``scan['transactions']``, which is rendered to the
       user - so an ``<img src="http://10.0.0.5:8080/">`` on a hostile page
       leaked internal service liveness into the report.

    Cost: every request round-trips to Python. ``resolver`` is the per-scan
    caching resolver, so the repeated hosts on a real page resolve once each.

    **Why navigations are chased manually (`_chase_redirects`), not
    `route.continue_()`.** `route.continue_()` only ever invokes this handler
    once per *request object*: when the response to a routed request is
    itself a redirect, Chromium follows it internally and the redirected URL
    never reaches this handler again (verified against Playwright 1.61 /
    Chromium 149 - matches the behavior tracked upstream in
    microsoft/playwright#34994 and #13817; independently reproduced by a
    second reviewer too). Re-emitting the redirect response verbatim via
    `route.fulfill()` instead of chasing it was also tried and rejected: it
    keeps `page.url` correct, but Chromium follows *that* redirect the same
    unrouted way, so the target is never revalidated.

    **Why `run_scan` pre-flights the chain and only uses this handler as a
    backstop (round 1 review's redesign, addressing Finding 3).** Fulfilling
    the *original* request with a *later* hop's body left `page.url`,
    `document.baseURI`, the page's origin/secure-context, relative
    subresource resolution, and `Secure` cookies all pinned to the
    pre-redirect URL - wrong for the common case of a bare-domain scan that
    redirects to https. `run_scan` now walks the chain itself (via
    `context.request`, before `page.goto`) and navigates straight to the
    validated final URL, so in the ordinary case this handler's chase is a
    single hop that fulfills at the *correct* URL. This handler is not
    simplified away, though: if the real navigation redirects again (a
    server can vary redirects by cookie, UA, or time - the pre-flight is not
    an invariant), this is what still catches and validates it, degrading to
    today's origin-mismatch behavior for that one scan rather than to an
    unvalidated fetch.

    **Iframes (round 1 review, Finding 1 - Critical).** A subframe's main
    document request is also `resource_type == 'document'`, so it runs the
    same chase-and-fulfill path (its own safety still matters), but only a
    *main-frame* navigation is allowed to write `nav_state` - see
    `_is_main_frame_navigation`. Without that check, a page embedding
    `<iframe src="...">` could make the guard report the iframe's URL as the
    page's own, and, through `primary_host`, falsify the page's DNS/TLS/ASN/
    PTR/WHOIS to whatever the iframe points at.

    Non-document resource types (image/script/xhr/...) keep the simpler
    validate-then-`continue_()` path: their *own* URL is still validated, so
    a direct `<img src="http://10.0.0.5:8080/">` is blocked, but a subresource
    whose URL redirects to a blocked target is not re-validated on the
    redirect hop, for the same upstream reason above (round 1 review, Finding
    4). That gap is closed separately, at the persistence boundary in
    `run_scan`, by filtering `transactions`/`domains`/`ips` before they are
    stored - see the comment there. This function does not attempt to fetch/
    fulfill every subresource itself; doing so would double-buffer every
    asset on every scan and would spread Finding 3's origin problem to each
    of them.

    **WebSockets are not covered here at all (round 1 review, Finding 5).**
    `context.route`/`Route.fetch` never see a WebSocket handshake - verified:
    a page's own `new WebSocket('ws://internal-host/')` reaches the target
    without this handler ever running. `_install_websocket_guard`, installed
    alongside this function in `run_scan`, uses Playwright's separate
    `BrowserContext.route_web_socket` (available in 1.61) to close the same
    hole for `ws(s)://`.
    """
    nav_state = {'final_url': None, 'chain': [], 'final_ip': None}

    def handler(route):
        request = route.request
        try:
            validate_target(request.url, resolver=resolver)
        except UnsafeURLError as exc:
            _record_block(scan, seen_blocks, request.url, str(exc))
            try:
                route.abort('blockedbyclient')
            except Exception:
                pass
            return

        if request.resource_type != 'document':
            try:
                route.continue_()
            except Exception:
                # The page may have navigated away before we resumed this
                # route; a dead route is not an error worth failing the scan.
                pass
            return

        def fetch_one(hop_url, hop_method, hop_headers, hop_post_data):
            return route.fetch(
                url=hop_url, method=hop_method, headers=hop_headers,
                post_data=hop_post_data, max_redirects=0,
            )

        outcome, payload = _chase_redirects(
            fetch_one, request.url, resolver,
            method=request.method, headers=dict(request.headers), post_data=request.post_data,
        )

        if outcome == 'blocked':
            _record_block(scan, seen_blocks, payload['url'], payload['reason'], kind='blocked')
            try:
                route.abort('blockedbyclient')
            except Exception:
                pass
            return
        if outcome == 'error':
            _record_block(scan, seen_blocks, payload['url'], payload['reason'], kind='network_error')
            try:
                route.abort('failed')
            except Exception:
                pass
            return

        if _is_main_frame_navigation(request):
            nav_state['final_url'] = payload['final_url']
            nav_state['chain'] = payload['chain']
            nav_state['final_ip'] = payload['final_ip']
        try:
            route.fulfill(response=payload['final_response'])
        except Exception:
            pass

    context.route('**/*', handler)
    return nav_state


def _validate_ws_target(url: str, resolver) -> None:
    """Validate a WebSocket URL's host/port with the same SSRF rules as
    `validate_target`, without `url_guard`'s http(s)-only scheme gate - that
    module is deliberately scoped to http(s) (see its module docstring), so
    calling `validate_target` on a `ws(s)://` URL directly would reject every
    WebSocket outright on scheme alone, regardless of host/port safety.
    Remapping `ws`->`http` and `wss`->`https` reuses the exact same host/IP
    logic without touching `url_guard`.
    """
    scheme, sep, rest = (url or '').partition('://')
    mapped = _WS_SCHEME_MAP.get(scheme.lower())
    if not sep or not mapped:
        raise UnsafeURLError(f'unsupported WebSocket URL {url!r}')
    validate_target(f'{mapped}://{rest}', resolver=resolver)


def _install_websocket_guard(context, scan: dict, resolver, seen_blocks: set) -> None:
    """Round 1 review, Finding 5: close the WebSocket gap `_install_fetch_guard`
    cannot reach (see its docstring). Blocking means never calling
    `connect_to_server()` - the outbound connection to the target is only
    made once that is called, so an unsafe target is never dialed at all.
    """
    def ws_handler(ws_route):
        try:
            _validate_ws_target(ws_route.url, resolver)
        except UnsafeURLError as exc:
            _record_block(scan, seen_blocks, ws_route.url, str(exc))
            try:
                ws_route.close(code=1008, reason='blocked')
            except Exception:
                pass
            return
        try:
            ws_route.connect_to_server()
        except Exception:
            pass

    context.route_web_socket('**/*', ws_handler)


def run_scan(raw_url: str, device: str = 'desktop') -> dict:
    from playwright.sync_api import sync_playwright

    scan_id = str(uuid.uuid4())
    created_at = datetime.utcnow().isoformat() + 'Z'

    # Full scaffold up front (not just id/created_at) so templates that render
    # an early error scan (never reached playwright) see the same empty-but-
    # present shape as a scan that failed mid-flight further down.
    scan = {
        'id': scan_id,
        'url': raw_url.strip(),
        'device': device,
        'created_at': created_at,
        'status': 'running',
        'error': None,
        'user_agent': None,
        'page': {},
        'transactions': [],
        'redirects': [],
        'console': [],
        'blocked_requests': [],
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

    try:
        target = validate_target(raw_url.strip())
    except UnsafeURLError as exc:
        scan['status'] = 'error'
        scan['error'] = str(exc)
        return scan

    # Store the canonical, normalized form - not the raw user input - so
    # everything downstream (navigation, hostname extraction, rendering)
    # agrees on one URL.
    scan['url'] = target.url
    url = target.url

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
            # One resolver per scan: hosts resolve once, and the cache dies with the scan.
            guard_resolver = caching_resolver()
            # Shared across the fetch guard, the WebSocket guard, and the
            # pre-flight below so a retried navigation (see the page.goto
            # retry further down) does not double every blocked_requests entry.
            seen_blocks: set = set()
            nav_state = _install_fetch_guard(context, scan, guard_resolver, seen_blocks)
            _install_websocket_guard(context, scan, guard_resolver, seen_blocks)

            # Pre-flight: validate and follow the redirect chain via the
            # context's own request API - no page/frame involved yet - so
            # page.goto() below navigates straight to the real, validated
            # final URL instead of the pre-redirect one. See
            # _install_fetch_guard's docstring for why this fixes the origin/
            # baseURI mismatch a fulfilled-under-the-original-URL response
            # otherwise leaves, and why the in-handler chase stays installed
            # as the enforcement backstop rather than being simplified away.
            def preflight_fetch_one(hop_url, hop_method, hop_headers, hop_post_data):
                return context.request.fetch(
                    hop_url, method=hop_method, headers=hop_headers,
                    data=hop_post_data, max_redirects=0,
                )

            preflight_outcome, preflight_payload = _chase_redirects(preflight_fetch_one, url, guard_resolver)

            if preflight_outcome == 'blocked':
                _record_block(
                    scan, seen_blocks, preflight_payload['url'], preflight_payload['reason'], kind='blocked',
                )
                scan['status'] = 'error'
                scan['error'] = f"Blocked: {preflight_payload['reason']}"
                return scan
            if preflight_outcome == 'error':
                scan['status'] = 'error'
                scan['error'] = f"Navigation failed: {preflight_payload['reason']}"
                return scan

            goto_url = preflight_payload['final_url']
            preflight_chain = preflight_payload['chain']
            preflight_final_ip = preflight_payload['final_ip']

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
                main_response = page.goto(goto_url, wait_until='networkidle', timeout=30000)
            except Exception:
                try:
                    main_response = page.goto(goto_url, wait_until='domcontentloaded', timeout=30000)
                except Exception as e:
                    scan['error'] = f'Navigation failed: {e}'

            page.wait_for_timeout(1500)

            # Redirect chain: the pre-flight above already walked (and
            # validated) every hop from the original input to `goto_url`, so
            # start from that. `nav_state['chain']` is populated by the
            # in-handler backstop on the *real* navigation - in the ordinary
            # case that's a single, non-redirecting hop at `goto_url`
            # (replacing the pre-flight's own terminal entry for the same
            # URL, which is exactly what `[:-1] + nav_state['chain']` does);
            # if the real navigation redirected *again* (the backstop case
            # `_install_fetch_guard` exists for), `nav_state['chain']` starts
            # at `goto_url` and correctly extends past it.
            if nav_state.get('chain'):
                scan['redirects'] = preflight_chain[:-1] + nav_state['chain']
            else:
                scan['redirects'] = preflight_chain

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

            # Same reasoning as the redirect chain above: the pre-flight/
            # backstop's own validated URL is what was actually navigated to
            # and rendered; page.url is only a fallback for the (should not
            # happen) case where neither ever ran.
            final_url = nav_state.get('final_url') or goto_url or page.url
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

            # Filter out any transaction whose own URL, or resolved server IP,
            # would not pass the guard (round 1 review, Finding 4). A
            # subresource redirect is not re-validated on its own hop by the
            # per-request guard (see _install_fetch_guard's docstring) - the
            # connection to the unrouted target has already happened by the
            # time it reaches on_response, but its status/server_ip was still
            # landing in this rendered report, turning the scanner into an
            # internal port/liveness oracle. This does not stop the
            # connection (nothing short of egress control does); it stops
            # the report from repeating the answer.
            def _passes_report_guard(txn: dict) -> bool:
                if not is_scannable(txn.get('url'), resolver=guard_resolver):
                    return False
                ip = txn.get('server_ip')
                if ip and not is_scannable(f'http://{ip}/', resolver=guard_resolver):
                    return False
                return True

            kept_transactions = []
            for t in transactions:
                if _passes_report_guard(t):
                    kept_transactions.append(t)
                else:
                    _record_block(
                        scan, seen_blocks, t.get('url') or '',
                        'unrouted response filtered from report', kind='blocked',
                    )
            transactions = kept_transactions

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
                    ipaddress.ip_address(primary_host)
                    is_ip_literal = True
                except ValueError:
                    is_ip_literal = False

                if not is_ip_literal:
                    scan['dns'] = resolve_all(primary_host)
                    if final_url.startswith('https'):
                        scan['tls'] = inspect_certificate(primary_host)

            # Determine main IP. Prefer the address the guard itself
            # validated for the final hop (round 1 review, Finding 2): a
            # fulfilled response has no server_addr(), so transactions[0] for
            # the main document now carries server_ip=None on every scan, and
            # without this the old fallback below silently picked the lowest-
            # sorted *subresource* IP (a CDN, an analytics host) instead -
            # then computed ASN/PTR from that wrong address. The old
            # fallbacks stay, in order, for the cases nav_state/pre-flight
            # didn't populate (e.g. an IP-literal target, or a scan that
            # errored before either ran).
            primary_txn = next(
                (t for t in transactions if _safe_hostname(t['url']) == primary_host and t.get('server_ip')),
                None,
            )
            main_ip = (
                nav_state.get('final_ip')
                or preflight_final_ip
                or (primary_txn or {}).get('server_ip')
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
