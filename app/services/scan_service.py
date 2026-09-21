"""URL scanner service - headless Chromium scan with DNS/TLS/ASN/tech enrichment."""
import hashlib
import json
import logging
import ipaddress
import re
import socket
import ssl
import uuid
from datetime import datetime
from urllib.parse import urlparse, urljoin

import dns.resolver
import dns.reversename
import dns.exception

from ..utils.iocs import extract_iocs
from ..utils.storage import store
from ..utils.url_guard import UnsafeURLError, caching_resolver, is_scannable, validate_target
from .scan_rules import score as score_scan

logger = logging.getLogger(__name__)

MOBILE_UA = (
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) '
    'AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
)

# Deliberately narrow: one click to dismiss a consent wall, not page exploration.
_CONSENT_NAME = re.compile(r'accept|agree|consent|allow|got it|i understand', re.I)


def _scan_key(scan_id: str) -> str:
    return f'{scan_id}.json'


def save_scan(scan: dict) -> None:
    store('scans').write_text(_scan_key(scan['id']), json.dumps(scan, default=str))


def get_scan(scan_id: str) -> dict | None:
    try:
        raw = store('scans').read_text(_scan_key(scan_id))
    except ValueError:
        # scan_id comes off the URL path: a rejected key is a miss, not a 500.
        return None
    if raw is None:
        return None
    try:
        data = json.loads(raw)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    # Normalised here, not at each of a dozen `scan.page.get(...)` template reads.
    page = data.get('page')
    data['page'] = page if isinstance(page, dict) else {}
    return data



def screenshot_key(scan_id: str, label: str | None = None) -> str:
    """``label=None`` is the full-page shot and keeps the original ``<id>.png`` name, so
    scans recorded before staged capture existed still resolve to their screenshot."""
    if label:
        return f'{scan_id}-{label}.png'
    return f'{scan_id}.png'


def screenshot_local_path(scan_id: str, label: str | None = None):
    """None when the key is absent *or* the backend is not local."""
    try:
        return store('screenshots').local_path(screenshot_key(scan_id, label))
    except ValueError:
        return None


def screenshot_stream(scan_id: str, label: str | None = None):
    try:
        return store('screenshots').open_stream(screenshot_key(scan_id, label))
    except ValueError:
        return None


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
        parts = ip.split('.')
        if len(parts) == 4:
            query = '.'.join(reversed(parts)) + '.origin.asn.cymru.com'
        else:
            # Cymru's origin zone is IPv4-only.
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


def inspect_certificate(host: str, port: int = 443) -> dict | None:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_OPTIONAL
        with socket.create_connection((host, port), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as sock:
                cert = sock.getpeercert()
                authorized = bool(cert)
                # A second, verifying connection: the first proves only that a cert
                # was *offered*, not that it validates.
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


# An *absent* content type is deliberately NOT a payload - too many misconfigured
# servers omit it. Inline-rendered benign formats are excluded too: including
# application/pdf made every site hosting one read as "suspicious". A genuinely malicious
# download is still caught by the browser download path.
_PAYLOAD_CONTENT_TYPES = (
    'application/octet-stream',
    'application/x-msdownload',
    'application/x-msdos-program',
    'application/vnd.microsoft.portable-executable',
    'application/x-executable',
    'application/x-dosexec',
    'application/zip',
    'application/x-zip-compressed',
    'application/x-rar-compressed',
    'application/x-7z-compressed',
    'application/java-archive',
    'application/vnd.ms-excel',
    'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'application/x-msi',
    'application/x-apple-diskimage',
)


def _is_payload_content_type(content_type: str | None) -> bool:
    if not content_type:
        return False
    base = content_type.split(';')[0].strip().lower()
    return base in _PAYLOAD_CONTENT_TYPES


# The body arrives as one bytes object (Playwright's APIResponse has no streaming read)
# at a size the target chooses, so without a cap one hostile multi-GB zip can OOM the
# single-worker process serving every scan. Above it sha256 stays None: a missing hash
# beats a dead server.
MAX_PAYLOAD_HASH_BYTES = 25 * 1024 * 1024

# A dropper navigation legitimately raises in page.goto(): Chromium turns it into a
# download and aborts. These markers separate that expected abort from a real
# failure (timeout, DNS, TLS), so a genuine failure is not erased by a download.
_DOWNLOAD_ABORT_MARKERS = (
    'download is starting',
    'net::err_aborted',
)


def _is_download_abort(exc) -> bool:
    text = str(exc or '').lower()
    return any(marker in text for marker in _DOWNLOAD_ABORT_MARKERS)


def _declared_content_length(headers: dict) -> int | None:
    raw = (headers or {}).get('content-length')
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return None
    return value if value >= 0 else None


def _hash_response_body(response, headers: dict, label: str):
    """``(sha256, size_bytes)``; never raises, ``sha256=None`` above the cap.

    The declared ``content-length`` is checked *first*, so a hostile multi-gigabyte
    body is never pulled into memory at all; ``len(body)`` is re-checked as a backstop
    for chunked responses, which declare no length.
    """
    declared = _declared_content_length(headers)
    if declared is not None and declared > MAX_PAYLOAD_HASH_BYTES:
        logger.info(
            'Skipping payload hash for %s: declared %d bytes exceeds the %d byte cap',
            label, declared, MAX_PAYLOAD_HASH_BYTES,
        )
        return None, declared

    size_bytes = declared
    try:
        body = response.body()
    except Exception as exc:
        logger.debug('Could not read main response body for %s: %s', label, exc)
        return None, size_bytes

    size_bytes = len(body)
    if size_bytes > MAX_PAYLOAD_HASH_BYTES:
        logger.info(
            'Skipping payload hash for %s: %d bytes exceeds the %d byte cap',
            label, size_bytes, MAX_PAYLOAD_HASH_BYTES,
        )
        return None, size_bytes
    try:
        return hashlib.sha256(body).hexdigest(), size_bytes
    except Exception as exc:
        logger.debug('Could not hash main response body for %s: %s', label, exc)
        return None, size_bytes


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


_TECH_RULES = [
    {'name': 'Cloudflare', 'category': 'CDN', 'headers': {'server': r'cloudflare', 'cf-ray': r'.+'}},
    {'name': 'Amazon CloudFront', 'category': 'CDN', 'headers': {'server': r'cloudfront', 'x-amz-cf-id': r'.+'}},
    {'name': 'Fastly', 'category': 'CDN', 'headers': {'x-served-by': r'cache-', 'x-fastly-request-id': r'.+'}},
    {'name': 'Akamai', 'category': 'CDN', 'headers': {'server': r'akamai', 'x-akamai-transformed': r'.+'}},
    {'name': 'Varnish', 'category': 'Caching', 'headers': {'x-varnish': r'.+', 'via': r'varnish'}},
    {'name': 'nginx', 'category': 'Web server', 'headers': {'server': r'nginx'}},
    {'name': 'Apache', 'category': 'Web server', 'headers': {'server': r'apache'}},
    {'name': 'Microsoft IIS', 'category': 'Web server', 'headers': {'server': r'iis|microsoft-httpapi'}},
    {'name': 'Envoy', 'category': 'Web server', 'headers': {'server': r'envoy'}},
    {'name': 'LiteSpeed', 'category': 'Web server', 'headers': {'server': r'litespeed'}},
    {'name': 'Caddy', 'category': 'Web server', 'headers': {'server': r'caddy'}},
    {'name': 'Vercel', 'category': 'Hosting', 'headers': {'server': r'vercel', 'x-vercel-id': r'.+'}},
    {'name': 'Netlify', 'category': 'Hosting', 'headers': {'server': r'netlify', 'x-nf-request-id': r'.+'}},
    {'name': 'GitHub Pages', 'category': 'Hosting', 'headers': {'server': r'github\.com'}},
    {'name': 'PHP', 'category': 'Language', 'headers': {'x-powered-by': r'php'}, 'cookies': ['PHPSESSID']},
    {'name': 'Express', 'category': 'Framework', 'headers': {'x-powered-by': r'express'}},
    {'name': 'ASP.NET', 'category': 'Framework', 'headers': {'x-powered-by': r'asp\.net', 'x-aspnet-version': r'.+'},
     'cookies': ['ASP.NET_SessionId']},
    {'name': 'Ruby on Rails', 'category': 'Framework', 'cookies': ['_rails_session'],
     'headers': {'x-powered-by': r'phusion passenger'}},
    {'name': 'Laravel', 'category': 'Framework', 'cookies': ['laravel_session', 'XSRF-TOKEN']},
    {'name': 'Django', 'category': 'Framework', 'cookies': ['csrftoken', 'sessionid']},
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
    {'name': 'Google Analytics', 'category': 'Analytics',
     'scripts': r'google-analytics\.com/(?:analytics|ga)\.js|gtag/js',
     'html': r'GoogleAnalyticsObject'},
    {'name': 'Google Tag Manager', 'category': 'Tag manager',
     'scripts': r'googletagmanager\.com/gtm\.js'},
    {'name': 'Cloudflare Insights', 'category': 'Analytics',
     'scripts': r'static\.cloudflareinsights\.com'},
    {'name': 'HubSpot', 'category': 'Marketing', 'scripts': r'js\.hs-scripts\.com'},
    {'name': 'Google Fonts', 'category': 'Font', 'html': r'fonts\.googleapis\.com'},
    {'name': 'Font Awesome', 'category': 'Font', 'html': r'font-?awesome'},
    {'name': 'reCAPTCHA', 'category': 'Security',
     'scripts': r'(?:google\.com|gstatic\.com)/recaptcha'},
    {'name': 'Stripe', 'category': 'Payments', 'scripts': r'js\.stripe\.com'},
]

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

_WS_SCHEME_MAP = {'ws': 'http', 'wss': 'https'}


def _record_block(scan: dict, seen: set, url: str, reason: str, kind: str = 'blocked') -> None:
    """Deduped because `page.goto`'s retry re-walks and re-validates the whole chain on
    the same URL, which would otherwise double every entry.

    ``kind`` separates a security block from a transport failure (``'network_error'``) so
    the two are not shown to the analyst as the same thing. ``reason`` is capped
    independently of ``url``: an exception message can be arbitrarily long.
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
    """A browser drops ``Authorization``/``Cookie`` when a redirect crosses origins;
    Playwright's ``Route.fetch``/``APIRequestContext.fetch`` do not - they forward the
    original request's headers verbatim to *any* URL handed to them.
    """
    if not headers or _same_origin(from_url, to_url):
        return headers
    return {k: v for k, v in headers.items() if k.lower() not in ('authorization', 'cookie')}


def _resolve_display_ip(host: str | None, resolver) -> str | None:
    """The address ``validate_target`` actually judged ``host`` by. A fulfilled
    response has no ``server_addr()``, so this is the only way left to know the main
    document's real IP; ``resolver`` is the per-scan cache, so it is a memoized lookup.
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


def _is_main_frame_navigation(request, page) -> bool:
    """Only the frame we actually drive may write ``nav_state``. Two confirmed bypasses,
    both falsifying the page's reported DNS/TLS/ASN/PTR/WHOIS (and the
    ``cross_domain_redirect`` signal) by pointing ``primary_host`` at an attacker's host:

    * a hostile ``<iframe src="...">`` - its document request is also
      ``resource_type == 'document'``;
    * a ``window.open`` popup - its main frame also has ``parent_frame is None``, so a
      parent check alone lets a popup that navigates itself, or one opened at
      ``about:blank`` and then steered by its opener, write ``nav_state``.

    Identity against the driven page's main frame is what separates them. Fails closed: a
    missing ``page`` or any raising attribute (service-worker requests, popup navigations
    issued before their frame exists) means "not main frame".
    """
    try:
        if page is None or not request.is_navigation_request():
            return False
        return request.frame is page.main_frame
    except Exception:
        return False


def _chase_redirects(fetch_one, start_url: str, resolver, *, method='GET', headers=None, post_data=None):
    """Follow a redirect chain one hop at a time so every ``Location`` is validated
    *before* it is handed to Chromium. Deliberately the single implementation of "validate
    every hop": ``run_scan``'s pre-flight and ``_install_fetch_guard``'s backstop both
    call this rather than duplicating it.

    ``fetch_one(url, method, headers, post_data)`` performs one hop with redirects
    disabled, returning an object with ``.status`` and ``.headers``; ``Route.fetch`` and
    ``APIRequestContext.fetch`` each satisfy it via an adapter closure, their parameter
    names differing. A 301/302/303 downgrades the method to GET and drops the body,
    matching a browser (307/308 preserve both), and ``Authorization``/``Cookie`` are
    stripped on any origin-crossing hop - browsers always do this, Playwright's fetch
    does not.

    Returns ``(outcome, payload)``: ``('ok', {'final_url', 'final_response', 'chain',
    'final_ip'})``; ``('blocked', {'url', 'reason', 'chain'})`` for failed SSRF
    validation, the hop cap, or a redirect with no ``Location``; or ``('error', ...)`` for
    a transport failure - deliberately distinct from ``'blocked'`` so callers do not
    present "unreachable" as "unsafe".
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


def _install_fetch_guard(context, scan: dict, resolver, seen_blocks: set, page_ref: dict) -> dict:
    """Re-validate every request Chromium makes, not just the URL we were given. Closes
    two vectors: a **redirect** to 127.0.0.1 or 169.254.169.254, which Chromium follows
    itself after ``is_scannable`` vetted only the submitted URL; and **subresources** like
    ``<img src="http://10.0.0.5:8080/">``, whose status and ``server_ip`` ``on_response``
    records into the rendered ``scan['transactions']``, leaking internal liveness.

    ``page_ref`` is a holder the caller fills with ``{'page': page}`` after
    ``context.new_page()``: the guard installs before the page exists, but
    ``_is_main_frame_navigation`` needs page identity. Until filled it fails closed.

    **Why navigations are chased manually (`_chase_redirects`), not `route.continue_()`.**
    `route.continue_()` invokes this handler once per *request object*: when a routed
    request's response is itself a redirect, Chromium follows it internally and the
    redirected URL never reaches the handler again (verified against Playwright 1.61 /
    Chromium 149; tracked upstream in microsoft/playwright#34994 and #13817). Re-emitting
    the redirect verbatim via `route.fulfill()` was tried and rejected: `page.url` stays
    correct, but Chromium follows *that* redirect the same unrouted way, so the target is
    never revalidated.

    **Why `run_scan` pre-flights the chain and this handler is only a backstop.**
    Fulfilling the *original* request with a *later* hop's body pinned `page.url`,
    `document.baseURI`, the page's origin/secure-context, relative subresource resolution
    and `Secure` cookies to the pre-redirect URL - wrong for the common bare-domain scan
    that redirects to https. `run_scan` walks the chain itself (via `context.request`,
    before `page.goto`) and navigates straight to the validated final URL. Still not
    simplified away: a server can vary redirects by cookie, UA or time, and this is what
    catches and validates a second redirect.

    A subframe's *and* a popup's main document request are also `resource_type ==
    'document'`, so both run the chase-and-fulfill path (their own safety matters), but
    only the driven page's own main frame may write `nav_state` - see
    `_is_main_frame_navigation` for what that check prevents.

    Non-document resource types keep the simpler validate-then-`continue_()` path: their
    *own* URL is validated, but a subresource whose URL redirects to a blocked target is
    not re-validated on that hop, for the same upstream reason above. That gap is closed
    at the persistence boundary in `run_scan`, by filtering `transactions`/`domains`/`ips`
    before they are stored. Fetching every subresource here instead would double-buffer
    every asset and spread the origin problem above to each of them.

    **WebSockets are not covered here at all.** `context.route`/`Route.fetch` never see a
    WebSocket handshake - verified: a page's own `new WebSocket('ws://internal-host/')`
    reaches the target without this handler running. `_install_websocket_guard` uses
    Playwright's separate `BrowserContext.route_web_socket` for `ws(s)://`.
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
                # The page may have navigated away; a dead route is not worth failing on.
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

        if _is_main_frame_navigation(request, page_ref.get('page')):
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
    """Same SSRF rules as `validate_target`, minus `url_guard`'s http(s)-only scheme
    gate: that module is deliberately scoped to http(s), so passing a `ws(s)://` URL
    straight in would reject every WebSocket on scheme alone regardless of host/port
    safety. Remapping the scheme reuses the same host/IP logic untouched.
    """
    scheme, sep, rest = (url or '').partition('://')
    mapped = _WS_SCHEME_MAP.get(scheme.lower())
    if not sep or not mapped:
        raise UnsafeURLError(f'unsupported WebSocket URL {url!r}')
    validate_target(f'{mapped}://{rest}', resolver=resolver)


def _install_websocket_guard(context, scan: dict, resolver, seen_blocks: set) -> None:
    """Close the WebSocket gap `_install_fetch_guard` cannot reach. Blocking means never
    calling `connect_to_server()` - the outbound connection is made only once that is
    called, so an unsafe target is never dialed.
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

    # Full scaffold up front so a scan that errored before playwright renders with the
    # same shape as a mid-flight failure.
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
        'forms': [],
        'payload': None,
        'visible_text': '',
        'screenshots': [],
        'technologies': [],
        'dns': {},
        'tls': None,
        'asn': None,
        'ptr': [],
        'main_ip': None,
        'domains': [],
        'ips': [],
        'links': [],
        'iocs': [],
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

    # Normalized, not raw, so navigation/hostname/rendering all agree on one URL.
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
                accept_downloads=True,
            )
            # One resolver per scan: hosts resolve once, and the cache dies with the scan.
            guard_resolver = caching_resolver()
            # Shared by both guards and the pre-flight so a retried navigation does not
            # double every blocked_requests entry.
            seen_blocks: set = set()
            # Filled right after new_page(); the guard installs first and fails closed.
            page_ref: dict = {}
            nav_state = _install_fetch_guard(context, scan, guard_resolver, seen_blocks, page_ref)
            _install_websocket_guard(context, scan, guard_resolver, seen_blocks)

            # Pre-flight via the context's own request API - no page/frame yet - so
            # page.goto() navigates straight to the validated final URL; see below.
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
            # Unlike main_response below, never None: a dropper navigation makes
            # page.goto() raise "Download is starting", leaving main_response None for
            # exactly the case payload capture exists for. So content-type, body and
            # sha256 are sourced from here, not from main_response.
            preflight_final_response = preflight_payload['final_response']

            page = context.new_page()
            page_ref['page'] = page
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

            # A dropper never renders (page.goto raises); its hash is the evidence.
            downloads = []

            def on_download(download):
                record = {'filename': download.suggested_filename, 'sha256': None,
                          'size_bytes': None}
                try:
                    path = download.path()
                    if path:
                        digest = hashlib.sha256()
                        size = 0
                        with open(path, 'rb') as handle:
                            for chunk in iter(lambda: handle.read(65536), b''):
                                digest.update(chunk)
                                size += len(chunk)
                        record['sha256'] = digest.hexdigest()
                        record['size_bytes'] = size
                except Exception as exc:
                    logger.debug('Could not hash download %s: %s',
                                 download.suggested_filename, exc)
                downloads.append(record)

            page.on('download', on_download)

            main_response = None
            nav_error = None
            try:
                main_response = page.goto(goto_url, wait_until='networkidle', timeout=30000)
            except Exception:
                try:
                    main_response = page.goto(goto_url, wait_until='domcontentloaded', timeout=30000)
                except Exception as e:
                    nav_error = e
                    scan['error'] = f'Navigation failed: {e}'

            page.wait_for_timeout(1500)

            # Use only the snapshot from here on: the guard keeps mutating nav_state for
            # the life of the page, including during the staged screenshots below. A late
            # main-frame navigation would leave main_ip/ASN/PTR on host B while
            # final_url/DNS/TLS/WHOIS describe host A.
            nav_snapshot = {
                'final_url': nav_state.get('final_url'),
                'final_ip': nav_state.get('final_ip'),
                'chain': list(nav_state.get('chain') or []),
            }

            # `nav_snapshot['chain']` is the backstop's view of the real navigation:
            # ordinarily one non-redirecting hop at `goto_url`, replacing the pre-flight's
            # terminal entry for the same URL - hence `[:-1] + chain`. A second redirect
            # correctly extends past it.
            if nav_snapshot['chain']:
                scan['redirects'] = preflight_chain[:-1] + nav_snapshot['chain']
            else:
                scan['redirects'] = preflight_chain

            # Deliberately *before* the in-page extraction below: extracting meta first
            # computed the verdict, forms and IOCs from the consent wall rather than the
            # page it hid, and a consent-click download never became a payload.
            def _capture(label, full_page=False):
                try:
                    shot = page.screenshot(full_page=full_page, type='png')
                    store('screenshots').write_bytes(screenshot_key(scan_id, label), shot)
                    scan['screenshots'].append({
                        'label': label,
                        'url': f'/url_scan/screenshot/{scan_id}?stage={label}',
                    })
                except Exception as exc:
                    logger.debug('Screenshot %s failed: %s', label, exc)

            _capture('load')

            try:
                page.evaluate('() => window.scrollTo(0, document.body.scrollHeight)')
                page.wait_for_timeout(800)
                _capture('after-scroll')
                page.evaluate('() => window.scrollTo(0, 0)')
            except Exception as exc:
                logger.debug('Scroll stage failed: %s', exc)

            try:
                button = page.get_by_role('button', name=_CONSENT_NAME).first
                button.click(timeout=2000)
                page.wait_for_timeout(1000)
                _capture('after-consent')
            except Exception:
                # No consent wall, or it did not yield to one narrow click. Fine.
                pass

            # Last, and unlabeled, so the result template keeps working unchanged.
            full_page_screenshot_url = None
            try:
                shot_bytes = page.screenshot(full_page=True, type='png')
                store('screenshots').write_bytes(screenshot_key(scan_id), shot_bytes)
                full_page_screenshot_url = f'/url_scan/screenshot/{scan_id}'
            except Exception as exc:
                logger.debug('Full-page screenshot failed: %s', exc)

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
                    forms: Array.from(document.querySelectorAll('form')).slice(0, 25).map(f => ({
                        action: f.getAttribute('action'),
                        method: (f.getAttribute('method') || 'get').toLowerCase(),
                        field_types: Array.from(f.querySelectorAll('input, select, textarea'))
                            .slice(0, 40)
                            .map(i => (i.getAttribute('type') || i.tagName.toLowerCase())),
                    })),
                    html: document.documentElement.outerHTML.slice(0, 500000),
                    visible_text: (document.body ? document.body.innerText : '').slice(0, 20000),
                };
            }''')

            # The validated URL is what was navigated to and rendered; page.url is only
            # a fallback for the should-not-happen case where neither guard ran.
            final_url = nav_snapshot['final_url'] or goto_url or page.url
            # A download navigation leaves main_response None, which made header-derived
            # analysis (security grading, tech fingerprinting) report "no security
            # headers" and zero technologies for every dropper URL. Fall back to these.
            preflight_headers = dict(preflight_final_response.headers or {})
            scan['page'] = {
                'final_url': final_url,
                'title': meta.get('title'),
                'description': meta.get('description'),
                'lang': meta.get('lang'),
                'favicon': meta.get('favicon'),
                'status': main_response.status if main_response else None,
                'status_text': main_response.status_text if main_response else None,
                'response_headers': (
                    dict(main_response.headers) if main_response else preflight_headers
                ),
                'screenshot_url': full_page_screenshot_url,
            }

            # Brand-impersonation evidence, capped so a giant page cannot bloat the scan.
            scan['visible_text'] = (meta.get('visible_text') or '')[:20000]

            # Sourced from the pre-flight's final_response, not main_response: a genuine
            # dropper makes page.goto() raise, leaving main_response None in exactly the
            # case this exists for, while the pre-flight response was already fetched.
            main_content_type = preflight_headers.get('content-type')

            payload = None
            if downloads:
                first = downloads[0]
                payload = {
                    'content_type': main_content_type,
                    'sha256': first['sha256'],
                    'size_bytes': first['size_bytes'],
                    'filename': first['filename'],
                    'is_payload': True,
                }
                # Clear *only* a download abort: blanket-clearing scan['error'] whenever
                # a download appeared reported a coincident double-timeout as 'done'.
                if nav_error is not None and _is_download_abort(nav_error):
                    scan['error'] = None
            elif _is_payload_content_type(main_content_type):
                sha256, size_bytes = _hash_response_body(
                    preflight_final_response, preflight_headers, goto_url,
                )
                payload = {
                    'content_type': main_content_type,
                    'sha256': sha256,
                    'size_bytes': size_bytes,
                    'filename': None,
                    'is_payload': True,
                }
            scan['payload'] = payload

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

            scan['forms'] = [
                {
                    'action': (f.get('action') or None),
                    'method': (f.get('method') or 'get'),
                    'field_types': [str(t).lower() for t in (f.get('field_types') or [])],
                    'has_password': any(
                        str(t).lower() == 'password' for t in (f.get('field_types') or [])
                    ),
                }
                for f in (meta.get('forms') or [])
            ]

            # A subresource redirect is not re-validated on its own hop by the
            # per-request guard (see _install_fetch_guard) - the connection has already
            # happened by the time it reaches on_response, but its status/server_ip still
            # landed in the report, making the scanner an internal port/liveness oracle.
            # This does not stop the connection (nothing short of egress control does); it
            # stops the report repeating the answer.
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

            scan['technologies'] = detect_technologies(
                headers=scan['page']['response_headers'],
                cookies=scan['cookies'],
                html=meta.get('html') or '',
                scripts=meta.get('scripts') or [],
            )
            scan['security'] = analyze_security_headers(scan['page']['response_headers'])

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

            # Prefer the address the guard validated for the final hop: a fulfilled
            # response has no server_addr(), so the main document's transaction carries
            # server_ip=None on every scan, and the fallbacks would silently pick the
            # lowest-sorted *subresource* IP (a CDN) and compute ASN/PTR from it. They stay,
            # in order, for what nav_state/pre-flight cannot populate (an IP literal).
            primary_txn = next(
                (t for t in transactions if _safe_hostname(t['url']) == primary_host and t.get('server_ip')),
                None,
            )
            main_ip = (
                nav_snapshot['final_ip']
                or preflight_final_ip
                or (primary_txn or {}).get('server_ip')
                or (scan['ips'][0] if scan['ips'] else None)
                or (scan['dns'].get('A') or [None])[0]
            )
            if main_ip:
                scan['main_ip'] = main_ip
                scan['asn'] = lookup_asn(main_ip)
                scan['ptr'] = reverse_ptr(main_ip)

            if primary_host and not is_ip_literal:
                try:
                    from app.services.domain_service import get_whois_info
                    scan['whois'] = get_whois_info(primary_host)
                except Exception as e:
                    logger.debug('WHOIS lookup failed for %s: %s', primary_host, e)

            scan['verdict'] = score_scan(scan)

            # Order matters: extract_iocs takes each type in the order it appears, so the
            # small, high-value set of hosts actually *contacted* must lead, ahead of the
            # potentially hundreds of links merely advertised.
            ioc_corpus = '\n'.join(
                [d['domain'] for d in (scan.get('domains') or [])]
                + (scan.get('ips') or [])
                + [scan.get('visible_text') or '']
                + (scan.get('links') or [])
            )
            scan['iocs'] = extract_iocs(ioc_corpus)

            scan['status'] = 'error' if scan['error'] else 'done'

        except Exception as e:
            scan['status'] = 'error'
            scan['error'] = str(e)
            logger.exception('Scan failed for %s', url)
        finally:
            browser.close()

    return scan
