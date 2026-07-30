"""E-mail analysis orchestration: parse, enrich, score, persist.

The parsing and scoring live in pure modules (`app/utils/email_parse.py`,
`app/services/email_rules.py`); this module owns only the parts that can fail
for environmental reasons - network lookups and the filesystem.

**Nothing here may persist message content.** ``_assemble`` is an explicit
allowlist: the body, the raw message, and attachment bytes have no path into
the stored record. Attachment payloads are hashed inside
``attachment_metadata`` and never leave it.
"""

import ipaddress
import json
import logging
import uuid
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import datetime, timezone

import dns.exception
import dns.resolver

from ..utils.email_parse import (
    EmailParseError,
    attachment_metadata,
    check_spoofing,
    extract_urls,
    find_suspicious_headers,
    header_summary,
    parse_auth_results,
    parse_message,
    public_ips_from_received,
    received_chain,
    sender_domain,
)
from ..utils.iocs import defang, extract_iocs
from ..utils.storage import store
from ..utils.url_guard import is_scannable
from . import email_rules

logger = logging.getLogger(__name__)

# Enrichment caps. A phishing mail can carry dozens of indicators; enriching all
# of them would exhaust VirusTotal's 4-req/min free tier and take tens of
# seconds. Body URLs are never auto-enriched - they get pivot links instead.
MAX_ENRICH_IPS = 5
# Do NOT raise this above 3. `hash_service.virustotal_limiter` is a process-wide
# RateLimiter(max_requests=4, time_window=1 minute) whose acquire() *blocks* in
# time.sleep rather than failing fast. At 4 hashes the whole free-tier minute is
# consumed by one e-mail; at 5 the fifth task sleeps ~60s, which blows past
# ENRICH_DEADLINE (20s), so `attachment_known_malware` - the only signal that
# reaches `malicious` alone - silently misses. 3 leaves one slot per minute for
# concurrent /hash_analysis and /api/file/analyze_file users.
MAX_ENRICH_HASHES = 3
ENRICH_WORKERS = 8

# Overall deadline for the whole enrichment fan-out. Individual sources have
# their own per-request timeouts, but those bound a single HTTP call, not the
# thread that runs it - a hung DNS resolution or a socket stuck in a half-open
# state can still tie up a worker indefinitely. This is a second, outer bound:
# any future not done by the deadline is treated as a failed source rather than
# letting analyze_email() (and the Flask request it runs inside) block forever.
ENRICH_DEADLINE = 20.0

_DNSBL_PROVIDERS = ('zen.spamhaus.org', 'bl.spamcop.net', 'b.barracudacentral.org')
_DNSBL_TIMEOUT = 3.0


def _now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def dnsbl_lookup(ip):
    """Query a small set of DNSBLs for an IPv4 address.

    A provider that does not answer is a miss, not an error - blocklists are often
    rate-limited or slow, and one unavailable provider must not fail the analysis.

    IPv6 is skipped rather than queried: these providers publish reverse-octet IPv4
    zones only, so a nibble-reversed IPv6 query is a guaranteed NXDOMAIN dressed up
    as a clean result.
    """
    try:
        parsed = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        return {'listed': False, 'providers': []}
    if parsed.version != 4:
        logger.debug('DNSBL skipped for IPv6 address %s (providers are IPv4-only)', ip)
        return {'listed': False, 'providers': []}
    octets = str(parsed).split('.')
    reversed_ip = '.'.join(reversed(octets))
    listed = []
    for provider in _DNSBL_PROVIDERS:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = _DNSBL_TIMEOUT
        try:
            resolver.resolve(f'{reversed_ip}.{provider}', 'A')
            listed.append(provider)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                dns.resolver.NoNameservers, dns.exception.Timeout):
            continue
        except Exception as exc:
            logger.debug('DNSBL %s failed for %s: %s', provider, ip, exc)
            continue
    return {'listed': bool(listed), 'providers': listed}


def is_enrichable_host(host):
    """True when a hostname derived from message content may be looked up.

    **Every host reachable from message content must pass through here first.**
    The sender domain comes from an attacker-controlled ``From`` header, and
    ``domain_service.get_domain_info_quick`` resolves it, queries internal DNS for
    it, and opens ``socket.create_connection((domain, 443))`` to it - a blind SSRF
    with an internal-liveness timing oracle whose answers get persisted. So it is
    gated by the same choke point the URL scanner uses,
    :func:`app.utils.url_guard.is_scannable`.

    A host that fails the guard is simply **not enriched**; it must never fail the
    analysis - parsing, scoring and the verdict all still apply.
    """
    if not host or not isinstance(host, str):
        return False
    try:
        return is_scannable(f'https://{host}')
    except Exception:  # is_scannable is non-raising, but never trust that here
        return False


def _enrich(domain, ips, hashes):
    """Fan out to the existing services concurrently. Never raises: a failing source
    is logged and comes back None.

    Bounded by ``ENRICH_DEADLINE`` overall - a source that has not finished by then
    is treated the same as one that raised, so a single hung lookup degrades this to
    a null result instead of blocking the request indefinitely.
    """
    from .domain_service import get_domain_info_quick, get_whois_info
    from .hash_service import get_hash_info_quick
    from .ip_service import check_abuseipdb, get_alienvault_data, get_vpn_data

    tasks = {}
    if domain and is_enrichable_host(domain):
        tasks[('sender_domain', domain)] = lambda d=domain: get_domain_info_quick(d)
        # WHOIS is fetched separately because get_domain_info_quick does not return
        # it, which leaves `young_sender_domain` (and its executable combo)
        # permanently unreachable. Grafted onto sender_domain['whois'] below.
        tasks[('sender_whois', domain)] = lambda d=domain: get_whois_info(d)
    elif domain:
        logger.debug('Sender domain %r not enrichable (failed the SSRF guard)', domain)
    # `ips` is already filtered to globally-routable addresses by
    # email_parse.public_ips_from_received. Hashes are locally computed digests sent
    # as query parameters, not hosts - no fetch target is derived from them.
    for ip in (ips or [])[:MAX_ENRICH_IPS]:
        tasks[('ip', ip)] = lambda i=ip: {
            'vpnapi': get_vpn_data(i),
            'abuseipdb': check_abuseipdb(i),
            'alienvault': get_alienvault_data(i),
        }
    for digest in (hashes or [])[:MAX_ENRICH_HASHES]:
        tasks[('hash', digest)] = lambda h=digest: get_hash_info_quick(h)
    first_ip = (ips or [None])[0]
    if first_ip:
        tasks[('dnsbl', first_ip)] = lambda i=first_ip: dnsbl_lookup(i)

    results = {}
    if not tasks:
        return {'sender_domain': None, 'ips': {}, 'hashes': {}, 'dnsbl': None}

    executor = ThreadPoolExecutor(max_workers=min(ENRICH_WORKERS, len(tasks)))
    try:
        futures = {executor.submit(fn): key for key, fn in tasks.items()}
        done, not_done = wait(futures, timeout=ENRICH_DEADLINE)
        for future in done:
            kind, ident = futures[future]
            try:
                results[(kind, ident)] = future.result()
            except Exception as exc:
                logger.warning('E-mail enrichment %s/%s failed: %s', kind, ident, exc)
                results[(kind, ident)] = None
        for future in not_done:
            kind, ident = futures[future]
            logger.warning(
                'E-mail enrichment %s/%s did not finish within %.0fs; treating as failed',
                kind, ident, ENRICH_DEADLINE,
            )
            results[(kind, ident)] = None
            future.cancel()
    finally:
        # Do not block shutdown on stragglers past the deadline - the threads
        # backing `not_done` futures may still be running (Python cannot force
        # a thread to stop); let them finish in the background and detach.
        executor.shutdown(wait=False)

    # Graft WHOIS onto the domain record so email_rules can read
    # enrichment['sender_domain']['whois']['create_date'] without knowing two
    # services produced it. Built even when the domain lookup failed, so a
    # WHOIS-only result still feeds the age signal.
    sender = results.get(('sender_domain', domain))
    whois = results.get(('sender_whois', domain))
    if whois:
        sender = dict(sender or {})
        sender['whois'] = whois

    return {
        'sender_domain': sender,
        'ips': {ident: value for (kind, ident), value in results.items() if kind == 'ip'},
        'hashes': {ident: value for (kind, ident), value in results.items() if kind == 'hash'},
        'dnsbl': results.get(('dnsbl', first_ip)),
    }


def _assemble(analysis_id, source, status, error, headers, domain, auth, spoofing,
              ambient, chain, ips, urls, attachments, iocs, enrichment, verdict):
    """Build the persisted record. The ONLY place a record is shaped, naming every
    field explicitly so message content cannot leak into storage by accident."""
    return {
        'id': analysis_id,
        'created_at': _now(),
        'source': source,
        'status': status,
        'error': error,
        'headers': headers,
        'sender_domain': domain,
        'authentication': auth,
        'spoofing': spoofing,
        'suspicious_headers': ambient,
        'received_chain': chain,
        'received_public_ips': ips,
        'urls': urls,
        'attachments': attachments,
        'iocs': iocs,
        'enrichment': enrichment,
        'verdict': verdict,
    }


def analyze_email(raw, source='upload'):
    """Parse, enrich, score and assemble. Never raises for bad input: an unparseable
    message returns status='error' with an 'unknown' verdict, still savable and
    renderable."""
    analysis_id = str(uuid.uuid4())

    try:
        msg = parse_message(raw)
    except EmailParseError as exc:
        return _assemble(
            analysis_id, source, 'error', str(exc), {}, None,
            {'spf': None, 'dkim': None, 'dmarc': None}, [], [], [], [], [], [], [],
            {'sender_domain': None, 'ips': {}, 'hashes': {}, 'dnsbl': None},
            email_rules.score({'parsed_ok': False}),
        )

    headers = header_summary(msg)
    domain = sender_domain(msg)
    auth = parse_auth_results(msg)
    spoofing = check_spoofing(msg)
    ambient = find_suspicious_headers(msg)
    chain = received_chain(msg)
    ips = public_ips_from_received(msg)
    live_urls = extract_urls(msg)
    attachments = attachment_metadata(msg)

    enrichment = _enrich(domain, ips, [a['sha256'] for a in attachments])

    verdict = email_rules.score({
        'parsed_ok': True,
        'authentication': auth,
        'spoofing': spoofing,
        'suspicious_headers': ambient,
        'urls': live_urls,
        'attachments': attachments,
        'enrichment': enrichment,
    })

    # Defang on the way into storage: nothing live is ever persisted or rendered.
    stored_urls = [
        {
            'url': defang(item['url']),
            'anchor_text': item.get('anchor_text'),
            'display_mismatch': item.get('display_mismatch', False),
        }
        for item in live_urls
    ]

    # Sender domain and Received IPs lead so they survive extract_iocs' budget
    # ahead of the potentially hundreds of body URLs.
    corpus = '\n'.join(
        ([domain] if domain else []) + ips + [item['url'] for item in live_urls]
    )
    iocs = extract_iocs(corpus)

    return _assemble(
        analysis_id, source, 'done', None, headers, domain, auth, spoofing, ambient,
        chain, ips, stored_urls, attachments, iocs, enrichment, verdict,
    )


def save_analysis(analysis):
    store('analyses').write_text(f"{analysis['id']}.json",
                                 json.dumps(analysis, default=str))


def get_analysis(analysis_id):
    try:
        uuid.UUID(str(analysis_id))
    except (ValueError, AttributeError, TypeError):
        return None
    raw = store('analyses').read_text(f'{analysis_id}.json')
    if raw is None:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def list_analyses(limit=100):
    analyses = store('analyses')
    results = []
    for entry in analyses.list(suffix='.json', limit=limit):
        try:
            data = json.loads(analyses.read_text(entry['key']) or '')
        except Exception:
            continue
        results.append({
            # The key, not data['id']: a stored id disagreeing with its record
            # name would produce links that 404.
            'id': entry['key'][:-len('.json')],
            'created_at': data.get('created_at'),
            'subject': (data.get('headers') or {}).get('subject'),
            'from': (data.get('headers') or {}).get('from'),
            'level': (data.get('verdict') or {}).get('level'),
            'attachment_count': len(data.get('attachments') or []),
        })
    return results
