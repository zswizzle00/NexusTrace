import os
import socket
import ssl
import dns.resolver
import logging
import requests
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError, as_completed
from bs4 import BeautifulSoup
import re
from urllib.parse import urlparse
from datetime import datetime, timedelta, timezone
from ..utils.rate_limiter import RateLimiter
from ..utils.cache import timed_lru_cache
from ..utils.constants import TIMEOUT_SHORT, TIMEOUT_MEDIUM, TIMEOUT_LONG

logger = logging.getLogger(__name__)

ip2whois_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))

dns_resolver = dns.resolver.Resolver()
dns_resolver.timeout = TIMEOUT_SHORT
dns_resolver.lifetime = TIMEOUT_MEDIUM


def setup_domain_services(app):
    pass


def safe_execute(func, *args, default=None, timeout=TIMEOUT_MEDIUM, **kwargs):
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(func, *args, **kwargs)
            return future.result(timeout=timeout)
    except FuturesTimeoutError:
        logger.warning(f"{func.__name__} timed out after {timeout}s")
        return default
    except Exception as e:
        logger.error(f"{func.__name__} failed: {str(e)}")
        return default


@timed_lru_cache(seconds=1800, maxsize=500)
def get_whois_info(domain):
    try:
        ip2whois_key = os.getenv('IP2WHOIS_KEY')
        if not ip2whois_key:
            logger.warning("IP2WHOIS_KEY not configured")
            return None
        ip2whois_limiter.acquire()
        response = requests.get(
            'https://api.ip2whois.com/v2',
            params={'key': ip2whois_key, 'domain': domain},
            timeout=TIMEOUT_MEDIUM
        )
        response.raise_for_status()
        return response.json()
    except _LookupUnavailable:
        raise
    except requests.Timeout:
        logger.warning(f"WHOIS lookup timed out for {domain}")
        return None
    except Exception as e:
        logger.error(f"Error fetching WHOIS information: {str(e)}")
        return None



@timed_lru_cache(seconds=900, maxsize=500)
def get_dns_records(domain):
    records = {}
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']

    def fetch_record(record_type):
        try:
            answers = dns_resolver.resolve(domain, record_type)
            return record_type, [str(rdata) for rdata in answers]
        except dns.resolver.NXDOMAIN:
            return record_type, []
        except dns.resolver.NoAnswer:
            return record_type, []
        except dns.resolver.Timeout:
            logger.debug(f"DNS {record_type} lookup timed out for {domain}")
            return record_type, []
        except Exception as e:
            logger.debug(f"Could not fetch {record_type} records: {str(e)}")
            return record_type, []

    with ThreadPoolExecutor(max_workers=len(record_types)) as executor:
        futures = {executor.submit(fetch_record, rt): rt for rt in record_types}
        for future in as_completed(futures, timeout=TIMEOUT_MEDIUM):
            try:
                record_type, values = future.result()
                records[record_type] = values
            except Exception:
                records[futures[future]] = []

    return records


@timed_lru_cache(seconds=1800, maxsize=500)
def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT_SHORT) as sock:
            sock.settimeout(TIMEOUT_SHORT)
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return {
                    'issuer': dict(x[0] for x in cert['issuer']),
                    'subject': dict(x[0] for x in cert['subject']),
                    'version': cert['version'],
                    'serial_number': cert['serialNumber'],
                    'not_before': cert['notBefore'],
                    'not_after': cert['notAfter'],
                    'cipher': ssock.cipher()
                }
    except socket.timeout:
        logger.warning(f"SSL connection timed out for {domain}")
        return None
    except Exception as e:
        logger.debug(f"Error fetching SSL information: {str(e)}")
        return None


@timed_lru_cache(seconds=1800, maxsize=500)
def get_reverse_ip_domains(ip):
    """Get domains sharing the same IP using hackertarget.com."""
    if not ip:
        return []
    try:
        resp = requests.get(
            f'https://api.hackertarget.com/reverseiplookup/?q={ip}',
            timeout=TIMEOUT_SHORT
        )
        if resp.status_code == 200 and 'No records' not in resp.text and 'error' not in resp.text.lower():
            domains = [d.strip() for d in resp.text.splitlines() if d.strip()]
            return domains[:50]
    except _LookupUnavailable:
        raise
    except requests.Timeout:
        logger.warning(f"Reverse IP lookup timed out for {ip}")
    except Exception as e:
        logger.error(f"Error in reverse IP lookup: {str(e)}")
    return []


@timed_lru_cache(seconds=3600, maxsize=500)
def get_subdomains_crtsh(domain):
    """Get subdomains from crt.sh (certificate transparency logs)."""
    try:
        # crt.sh is often slow; keep the timeout short rather than stall the caller.
        resp = requests.get(
            f'https://crt.sh/?q=%25.{domain}&output=json',
            timeout=TIMEOUT_SHORT,
            headers={'User-Agent': 'NexusTrace/1.0'}
        )
        if resp.status_code == 200:
            data = resp.json()
            subdomains = set()
            for entry in data[:500]:
                name = entry.get('name_value')
                if name:
                    for sub in name.split('\n'):
                        sub = sub.strip().lower()
                        if sub.endswith(domain.lower()) and '*' not in sub:
                            subdomains.add(sub)
            return sorted(subdomains)[:100]
    except _LookupUnavailable:
        raise
    except requests.Timeout:
        logger.warning(f"crt.sh lookup timed out for {domain}")
    except Exception as e:
        logger.debug(f"Error in crt.sh subdomain lookup: {str(e)}")
    return []


def parse_spf_dkim_dmarc(txt_records):
    spf = [r for r in txt_records if 'v=spf1' in r.lower()]
    dkim = [r for r in txt_records if 'dkim' in r.lower()]
    dmarc = [r for r in txt_records if 'v=dmarc1' in r.lower()]
    return {'spf': spf, 'dkim': dkim, 'dmarc': dmarc}


@timed_lru_cache(seconds=3600, maxsize=500)
def get_dmarc_record(domain):
    try:
        answers = dns_resolver.resolve(f'_dmarc.{domain}', 'TXT')
        return [str(rdata) for rdata in answers]
    except Exception:
        return []


def extract_domain_for_phishtank(indicator):
    try:
        if indicator.lower().startswith(('http://', 'https://')):
            return urlparse(indicator).netloc
        elif re.match(r'^\d+\.\d+\.\d+\.\d+$', indicator):
            return None
        else:
            return indicator
    except Exception:
        return indicator


def check_phishtank(indicator):
    """Generate PhishTank search URL."""
    domain = extract_domain_for_phishtank(indicator)
    if domain:
        return f'https://phishtank.org/search.php?valid=y&active=y&Search={domain}'
    return None


@timed_lru_cache(seconds=1800, maxsize=500)
def get_talos_reputation(domain):
    """Generate Talos lookup URL (avoid scraping which is unreliable)."""
    return {
        'talos_url': f'https://talosintelligence.com/reputation_center/lookup?search={domain}',
        'verdict': None,
        'category': None
    }


@timed_lru_cache(seconds=900, maxsize=500)
def get_domain_info(domain):
    results = {
        'domain': domain,
        'whois': None,
        'dns_records': {},
        'ssl_info': None,
        'ip_address': None,
        'reverse_domains': [],
        'subdomains': [],
        'email_security': {'spf': [], 'dkim': [], 'dmarc': []},
        'phishtank_url': None,
        'talos_reputation': None,
        'errors': []
    }

    try:
        # Phase 1: fast, essential lookups.
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(get_whois_info, domain): 'whois_api',
                executor.submit(get_dns_records, domain): 'dns',
                executor.submit(get_ssl_info, domain): 'ssl',
                executor.submit(lambda: socket.gethostbyname(domain)): 'ip',
            }

            for future in as_completed(futures, timeout=TIMEOUT_LONG):
                key = futures[future]
                try:
                    result = future.result(timeout=TIMEOUT_SHORT)
                    if key == 'whois_api':
                        results['whois'] = result
                    elif key == 'dns':
                        results['dns_records'] = result or {}
                    elif key == 'ssl':
                        results['ssl_info'] = result
                    elif key == 'ip':
                        results['ip_address'] = result
                except Exception as e:
                    results['errors'].append(f"{key}: {str(e)}")
                    logger.debug(f"Phase 1 {key} failed: {str(e)}")

        txt_records = results['dns_records'].get('TXT', [])
        results['email_security'] = parse_spf_dkim_dmarc(txt_records)

        if not results['email_security']['dmarc']:
            dmarc = get_dmarc_record(domain)
            if dmarc:
                results['email_security']['dmarc'] = dmarc

        results['phishtank_url'] = check_phishtank(domain)
        results['talos_reputation'] = get_talos_reputation(domain)

        # Phase 2: slower, optional enrichment.
        ip_address = results['ip_address']
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {}

            if ip_address:
                futures[executor.submit(get_reverse_ip_domains, ip_address)] = 'reverse_ip'

            futures[executor.submit(get_subdomains_crtsh, domain)] = 'subdomains'

            for future in as_completed(futures, timeout=TIMEOUT_LONG):
                key = futures[future]
                try:
                    result = future.result(timeout=TIMEOUT_MEDIUM)
                    if key == 'reverse_ip':
                        results['reverse_domains'] = result or []
                    elif key == 'subdomains':
                        results['subdomains'] = result or []
                except Exception as e:
                    results['errors'].append(f"{key}: timed out or failed")
                    logger.debug(f"Phase 2 {key} failed: {str(e)}")

        if not results['errors']:
            del results['errors']

        return results

    except Exception as e:
        logger.error(f"Error getting domain information for {domain}: {str(e)}")
        results['errors'].append(f"Fatal error: {str(e)}")
        return results


@timed_lru_cache(seconds=600, maxsize=500)
def get_domain_info_quick(domain):
    results = {
        'domain': domain,
        'dns_records': {},
        'ssl_info': None,
        'ip_address': None,
        'email_security': {'spf': [], 'dkim': [], 'dmarc': []},
    }

    try:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                executor.submit(get_dns_records, domain): 'dns',
                executor.submit(get_ssl_info, domain): 'ssl',
                executor.submit(lambda: socket.gethostbyname(domain)): 'ip',
            }

            for future in as_completed(futures, timeout=TIMEOUT_MEDIUM):
                key = futures[future]
                try:
                    result = future.result(timeout=TIMEOUT_SHORT)
                    if key == 'dns':
                        results['dns_records'] = result or {}
                    elif key == 'ssl':
                        results['ssl_info'] = result
                    elif key == 'ip':
                        results['ip_address'] = result
                except Exception as e:
                    logger.debug(f"Domain sub-lookup task failed: {e}")

        txt_records = results['dns_records'].get('TXT', [])
        results['email_security'] = parse_spf_dkim_dmarc(txt_records)

        return results

    except Exception as e:
        logger.error(f"Quick domain lookup failed for {domain}: {str(e)}")
        return results


RDAP_URL = 'https://rdap.org/domain/{domain}'
WAYBACK_CDX_URL = 'https://web.archive.org/cdx/search/cdx'

# rdap.org is a bootstrap service: it 302s to the authoritative registry for the TLD, so
# the final host varies per domain and is not known ahead of time. Redirects are followed
# because that is how the protocol works, but the count is bounded and the scheme is
# checked, because the redirect target is chosen by a third party.
RDAP_MAX_REDIRECTS = 4

rdap_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))
wayback_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))


class _LookupUnavailable(Exception):
    """Raised rather than returned so `timed_lru_cache` cannot memoize a transient
    failure. Same reasoning as `hash_service._QuotaExhausted`: a 10-second stall at
    web.archive.org must not become an hour of cached "no archive history", because
    "we could not check" and "there is nothing there" are different claims and only
    one of them is a signal.
    """


def _rdap_event(events, action):
    for event in events if isinstance(events, list) else []:
        if isinstance(event, dict) and event.get('eventAction') == action:
            return event.get('eventDate')
    return None


def _rdap_registrar(entities):
    """The registrar's name lives in a jCard, which is a nested array format: each
    property is [name, params, type, value], and we want the 'fn' (formatted name)."""
    for entity in entities if isinstance(entities, list) else []:
        if not isinstance(entity, dict):
            continue
        vcard = entity.get('vcardArray')
        if not (isinstance(vcard, list) and len(vcard) > 1 and isinstance(vcard[1], list)):
            continue
        for prop in vcard[1]:
            if isinstance(prop, list) and len(prop) >= 4 and prop[0] == 'fn':
                return prop[3]
    return None


def _age_days(registered):
    if not registered:
        return None
    try:
        stamp = datetime.fromisoformat(str(registered).replace('Z', '+00:00'))
    except ValueError:
        return None
    if stamp.tzinfo is None:
        stamp = stamp.replace(tzinfo=timezone.utc)
    return max((datetime.now(timezone.utc) - stamp).days, 0)


def map_rdap_response(payload):
    """Registration facts from an RDAP record, or None when there is nothing usable.

    `age_days` is the reason this source is here. A domain registered days ago that
    claims to be a bank is the strongest single signal in phishing triage, and RDAP
    makes it keyless: IP2WHOIS answers the same question but needs a key, so it is
    skipped on any deployment that has not configured one.
    """
    if not isinstance(payload, dict):
        return None
    events = payload.get('events')
    registered = _rdap_event(events, 'registration')
    status = payload.get('status')
    record = {
        'registered': registered,
        'expires': _rdap_event(events, 'expiration'),
        'last_changed': _rdap_event(events, 'last changed'),
        'age_days': _age_days(registered),
        'registrar': _rdap_registrar(payload.get('entities')),
        # Registry lock states such as clientDeleteProhibited. Their absence on an
        # established domain is mildly interesting; their presence is normal.
        'status': [s for s in status if isinstance(s, str)] if isinstance(status, list) else [],
    }
    return record if any((record['registered'], record['expires'], record['registrar'])) else None


# A registration date does not change. An hour is conservative, and it keeps the
# bootstrap redirect off the wire for repeat lookups of the same domain.
@timed_lru_cache(seconds=3600, maxsize=500)
def _get_rdap_info(domain, transport=None):
    """Cached inner lookup. Raises _LookupUnavailable rather than returning None on
    a transient failure, so nothing memoizes it. Callers use get_rdap_info."""
    if not rdap_limiter.try_acquire():
        logger.debug('RDAP rate limit reached for %s', domain)
        raise _LookupUnavailable()
    try:
        response = (transport or requests.get)(
            RDAP_URL.format(domain=domain),
            timeout=TIMEOUT_SHORT,
            allow_redirects=True,
            headers={'User-Agent': 'NexusTrace/1.0', 'Accept': 'application/rdap+json'},
        )
        if len(getattr(response, 'history', []) or []) > RDAP_MAX_REDIRECTS:
            logger.debug('RDAP exceeded %s redirects for %s', RDAP_MAX_REDIRECTS, domain)
            raise _LookupUnavailable()
        if not str(getattr(response, 'url', '') or '').startswith('https://'):
            logger.debug('RDAP redirected off HTTPS for %s', domain)
            raise _LookupUnavailable()
        if response.status_code != 200:
            raise _LookupUnavailable()
        return map_rdap_response(response.json())
    except _LookupUnavailable:
        raise
    except requests.Timeout:
        logger.warning('RDAP lookup timed out for %s', domain)
    except Exception as exc:
        logger.debug('RDAP lookup failed for %s: %s', domain, exc)
    raise _LookupUnavailable()


def map_wayback_response(rows):
    """First archived capture from a CDX response.

    The first row is a HEADER, not data: the API returns
    `[["timestamp","original"], ["20080514210148","http://github.com/"], ...]`.
    Counting it as a capture would report history for a domain that has none.

    Only the FIRST capture is requested. `collapse=timestamp:6`, which would have given
    a per-month snapshot count, makes the API scan the whole index and it timed out at
    25 seconds on github.com; the same query without it answers instantly. First-seen is
    also the signal that matters for triage, so the count is not worth a second request.

    What this buys: an independent second opinion on age. RDAP registration dates get
    reset by drops and transfers, so a domain can look old to RDAP and still have no
    history anywhere. Nothing archived before last week is the tell.
    """
    if not isinstance(rows, list) or len(rows) < 2:
        return {'archived': False, 'first_seen': None}
    for row in rows[1:]:
        if isinstance(row, list) and row and str(row[0]).isdigit():
            return {'archived': True, 'first_seen': _wayback_date(str(row[0]))}
    return {'archived': False, 'first_seen': None}


def _wayback_date(stamp):
    """CDX timestamps are YYYYMMDDhhmmss. Render the date only; the time is noise."""
    return f'{stamp[0:4]}-{stamp[4:6]}-{stamp[6:8]}' if len(stamp) >= 8 else None


# Caching earns its keep here more than anywhere else in this module: the CDX API's
# latency was measured swinging between 2s and 10s for the SAME request seconds apart,
# so a cached success rides out the next slow window.
@timed_lru_cache(seconds=3600, maxsize=500)
def _get_wayback_history(target, transport=None):
    """Cached inner lookup. Raises _LookupUnavailable rather than returning None on
    a transient failure, so nothing memoizes it. Callers use get_wayback_history."""
    if not wayback_limiter.try_acquire():
        logger.debug('Wayback rate limit reached for %s', target)
        raise _LookupUnavailable()
    try:
        response = (transport or requests.get)(
            WAYBACK_CDX_URL,
            params={
                'url': target,
                'output': 'json',
                'fl': 'timestamp',
                # The oldest capture only. See map_wayback_response for why there is no
                # collapse parameter here.
                'limit': 1,
            },
            # MEDIUM, not SHORT: web.archive.org is slow and TIMEOUT_SHORT (5s) was
            # measured failing on github.com at 5.15s while the same request succeeded
            # in under a second on a warm connection. A source that intermittently
            # reports "no history" for a 2008 domain is worse than no source.
            timeout=TIMEOUT_MEDIUM,
            headers={'User-Agent': 'NexusTrace/1.0'},
        )
        if response.status_code != 200:
            raise _LookupUnavailable()
        return map_wayback_response(response.json())
    except _LookupUnavailable:
        raise
    except requests.Timeout:
        logger.warning('Wayback lookup timed out for %s', target)
    except Exception as exc:
        logger.debug('Wayback lookup failed for %s: %s', target, exc)
    raise _LookupUnavailable()


def get_rdap_info(*args, **kwargs):
    """Uncached wrapper. The cached inner function raises on a transient failure so the
    failure is never memoized; see _LookupUnavailable."""
    try:
        return _get_rdap_info(*args, **kwargs)
    except _LookupUnavailable:
        return None


def get_wayback_history(*args, **kwargs):
    """Uncached wrapper. The cached inner function raises on a transient failure so the
    failure is never memoized; see _LookupUnavailable."""
    try:
        return _get_wayback_history(*args, **kwargs)
    except _LookupUnavailable:
        return None
