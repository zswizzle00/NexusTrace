import os
import re
import requests
import logging
from typing import Dict, List, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

import dns.exception
import dns.resolver

from . import abusech
from ..utils import hash_reputation
from ..utils.cache import timed_lru_cache
from ..utils.rate_limiter import RateLimiter
from ..utils.constants import TIMEOUT_SHORT, TIMEOUT_MEDIUM
from datetime import timedelta

logger = logging.getLogger(__name__)

virustotal_limiter = RateLimiter(max_requests=4, time_window=timedelta(minutes=1))  # VT free tier: 4/min

# The two keyless sources. Both are free community services, so both get a limiter even
# though neither publishes a limit.
circl_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))
mhr_limiter = RateLimiter(max_requests=4, time_window=timedelta(seconds=1))

CIRCL_LOOKUP_BASE = 'https://hashlookup.circl.lu/lookup'
MHR_ZONE = 'malware.hash.cymru.com'
MHR_REFERENCE = 'https://team-cymru.com/community-services/mhr/'

CIRCL_SOURCE = hash_reputation.CIRCL_SOURCE
MHR_SOURCE = hash_reputation.MHR_SOURCE

# Reported beside the four reputation sources but never among them: see get_hash_info.
ADVISORY_SOURCES = (CIRCL_SOURCE, MHR_SOURCE)

# NXDOMAIN and an empty answer set both mean "no record" at MHR. A timeout or a dead
# resolver does not, and must not be flattened into one.
_DNS_MISS = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)


class _QuotaExhausted(Exception):
    """VirusTotal's per-minute quota is spent. Raised rather than returned so
    `timed_lru_cache` cannot memoize the outcome; see get_virustotal_report."""


def _get(url, headers=None, timeout=TIMEOUT_MEDIUM):
    """This module's only outbound HTTP call. Tests pass a fake in as `transport=`."""
    return requests.get(url, headers=headers, timeout=timeout)


def _resolve_txt(name, lifetime=TIMEOUT_SHORT) -> List[str]:
    """This module's only outbound DNS call, shaped like scan_service's Cymru lookups.
    Tests pass a fake in as `resolver=`."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = lifetime
    return [
        ''.join((s.decode('utf-8', 'replace') if isinstance(s, bytes) else str(s))
                for s in rdata.strings)
        for rdata in resolver.resolve(name, 'TXT')
    ]


def identify_hash_type(hash_value: str) -> Tuple[Optional[str], Optional[str]]:
    """Returns (hash_type, error_message)."""
    hash_value = hash_value.lower().strip()

    if re.match(r'^[a-f0-9]{32}$', hash_value):
        return 'MD5', None

    if re.match(r'^[a-f0-9]{40}$', hash_value):
        return 'SHA1', None

    if re.match(r'^[a-f0-9]{64}$', hash_value):
        return 'SHA256', None

    if re.match(r'^[a-f0-9]{128}$', hash_value):
        return 'SHA512', None

    return None, 'Invalid hash format. Supported: MD5 (32), SHA1 (40), SHA256 (64), SHA512 (128)'


def reference_links(hash_value: str) -> Dict[str, str]:
    """Outbound per-hash search URLs, defined here and nowhere else, so routes and
    templates never build provider URLs themselves."""
    return {
        'virustotal': f"https://www.virustotal.com/gui/search/{hash_value}",
        'malwarebazaar': f"https://bazaar.abuse.ch/browse.php?search=sha256:{hash_value}",
        # ThreatFox indexes every IOC type under one 'ioc:' search term, not
        # per-algorithm like MalwareBazaar's 'sha256:'.
        'threatfox': f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{hash_value}",
        'alienvault_otx': f"https://otx.alienvault.com/indicator/file/{hash_value}",
        'hybrid_analysis': f"https://www.hybrid-analysis.com/search?query={hash_value}",
        'any_run': f"https://any.run/report/{hash_value}",
        'joesandbox': f"https://www.joesandbox.com/search?q={hash_value}"
    }


@timed_lru_cache(seconds=1800, maxsize=500)
def _virustotal_report(hash_value: str, transport=None) -> Optional[Dict]:
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        logger.debug("VIRUSTOTAL_API_KEY not configured")
        return None

    # try_acquire, not acquire: the window is a whole minute, so blocking here parks a
    # gunicorn worker thread for up to 60s and eight such lookups wedge the server. The
    # raise is deliberate, because lru_cache does not memoize exceptions: a `rate_limited`
    # answer must not be cached for the 30-minute TTL, or the hash would keep reporting
    # `rate_limited` long after the quota freed. It also means a cache *hit* never reaches
    # the limiter, so a repeated lookup does not burn a token.
    if not virustotal_limiter.try_acquire():
        raise _QuotaExhausted()

    try:
        response = (transport or _get)(
            f'https://www.virustotal.com/api/v3/files/{hash_value}',
            headers={'x-apikey': api_key},
            timeout=TIMEOUT_MEDIUM
        )

        if response.status_code == 404:
            return {'status': 'not_found', 'message': 'Hash not found in VirusTotal'}

        if response.status_code == 429:
            logger.warning("VirusTotal rate limit exceeded")
            return {'status': 'rate_limited', 'message': 'Rate limit exceeded'}

        response.raise_for_status()
        data = response.json().get('data', {})
        attributes = data.get('attributes', {})

        stats = attributes.get('last_analysis_stats', {})
        total_engines = sum(stats.values())
        malicious = stats.get('malicious', 0)
        suspicious = stats.get('suspicious', 0)

        results = attributes.get('last_analysis_results', {})
        detections = []
        for engine, result in results.items():
            if result.get('category') in ['malicious', 'suspicious']:
                detections.append({
                    'engine': engine,
                    'category': result.get('category'),
                    'result': result.get('result')
                })

        return {
            'status': 'found',
            'hash': hash_value,
            'sha256': attributes.get('sha256'),
            'sha1': attributes.get('sha1'),
            'md5': attributes.get('md5'),
            'file_size': attributes.get('size'),
            'file_type': attributes.get('type_description'),
            'file_names': attributes.get('names', [])[:10],
            'first_seen': attributes.get('first_submission_date'),
            'last_seen': attributes.get('last_analysis_date'),
            'detection_stats': {
                'malicious': malicious,
                'suspicious': suspicious,
                'undetected': stats.get('undetected', 0),
                'total': total_engines,
                'detection_ratio': f"{malicious + suspicious}/{total_engines}"
            },
            'detections': detections[:20],
            'tags': attributes.get('tags', []),
            'signature_info': attributes.get('signature_info'),
            'vt_link': f"https://www.virustotal.com/gui/file/{attributes.get('sha256', hash_value)}"
        }

    except requests.Timeout:
        logger.warning(f"VirusTotal request timed out for {hash_value}")
        return {'status': 'timeout', 'message': 'Request timed out'}
    except requests.RequestException as e:
        logger.error(f"VirusTotal API error: {str(e)}")
        return {'status': 'error', 'message': str(e)}
    except Exception as e:
        logger.error(f"Error getting VirusTotal report: {str(e)}")
        return None


def get_virustotal_report(hash_value: str, transport=None) -> Optional[Dict]:
    """`rate_limited` is a fifth state alongside `found` / `no_record` / `skipped` /
    `unavailable`, and is deliberately none of them: `skipped` means no key and no request,
    which says nothing about the hash, whereas this means the key exists and the quota for
    this minute is spent, so the answer is available and will arrive on a retry.
    """
    try:
        return _virustotal_report(hash_value, transport)
    except _QuotaExhausted:
        logger.info("VirusTotal per-minute quota spent; not querying %s", hash_value)
        return {'status': 'rate_limited',
                'message': 'VirusTotal quota for this minute is spent; retry shortly'}


@timed_lru_cache(seconds=1800, maxsize=500)
def get_circl_hashlookup(hash_value: str, transport=None) -> Dict:
    """CIRCL hashlookup: keyless, and the only one of the two new sources that accepts a
    sha256, which is the digest every upload and most pasted indicators carry.

    A `found` record proves nothing good. EICAR is in NSRL *and* flagged
    `KnownMalicious`, so only `summary['known_malicious']` may raise a verdict;
    `nsrl_present` is context. See app/utils/hash_reputation.py.
    """
    value = (hash_value or '').strip().lower()
    hash_type = (identify_hash_type(value)[0] or '').lower()
    reference = f'{CIRCL_LOOKUP_BASE}/{hash_type}/{value}'

    if hash_type not in hash_reputation.CIRCL_HASH_TYPES:
        # No reference either: there is no per-hash URL for an algorithm the service does
        # not index, and a row must not draw a link that 404s.
        return hash_reputation.circl_result(hash_type, None, None, None)

    try:
        with circl_limiter:
            response = (transport or _get)(reference,
                                          headers={'Accept': 'application/json'},
                                          timeout=TIMEOUT_MEDIUM)
    except requests.Timeout:
        logger.warning("CIRCL hashlookup timed out for %s", value)
        return hash_reputation.envelope(CIRCL_SOURCE, hash_reputation.STATE_UNAVAILABLE,
                                       reference=reference, raw={'error': 'timeout'})
    except requests.RequestException as exc:
        logger.warning("CIRCL hashlookup request failed: %s", exc)
        return hash_reputation.envelope(CIRCL_SOURCE, hash_reputation.STATE_UNAVAILABLE,
                                       reference=reference, raw={'error': 'request_error'})
    except Exception as exc:
        logger.error("CIRCL hashlookup transport error: %s", exc)
        return hash_reputation.envelope(CIRCL_SOURCE, hash_reputation.STATE_UNAVAILABLE,
                                       reference=reference, raw={'error': 'transport_error'})

    return hash_reputation.circl_result(hash_type,
                                       getattr(response, 'status_code', None),
                                       getattr(response, 'text', None), reference)


@timed_lru_cache(seconds=1800, maxsize=500)
def get_cymru_mhr(hash_value: str, resolver=None) -> Dict:
    """Team Cymru Malware Hash Registry over DNS TXT. Keyless, md5 and sha1 only.

    The detection percentage never reaches a verdict: MHR answers `"1445018789 91"` for
    the empty-file MD5, so it is noisy on ubiquitous artifacts. It is surfaced as its own
    source for the analyst instead.
    """
    value = (hash_value or '').strip().lower()
    hash_type = (identify_hash_type(value)[0] or '').lower()

    if hash_type not in hash_reputation.MHR_HASH_TYPES:
        return hash_reputation.mhr_result(hash_type, None, MHR_REFERENCE)

    try:
        with mhr_limiter:
            answers = (resolver or _resolve_txt)(f'{value}.{MHR_ZONE}')
    except _DNS_MISS:
        answers = []
    except (dns.exception.DNSException, OSError) as exc:
        logger.warning("Cymru MHR lookup failed for %s: %s", value, exc)
        return hash_reputation.envelope(MHR_SOURCE, hash_reputation.STATE_UNAVAILABLE,
                                       reference=MHR_REFERENCE,
                                       raw={'error': 'resolver_error'})
    except Exception as exc:
        logger.error("Cymru MHR transport error: %s", exc)
        return hash_reputation.envelope(MHR_SOURCE, hash_reputation.STATE_UNAVAILABLE,
                                       reference=MHR_REFERENCE,
                                       raw={'error': 'transport_error'})

    return hash_reputation.mhr_result(hash_type, answers, MHR_REFERENCE)


def _abusech_failure(envelope: Dict) -> Dict:
    """Map an `unavailable` abuse.ch envelope onto this module's legacy status shape."""
    raw = envelope.get('raw') or {}
    if raw.get('error') == 'timeout':
        return {'status': 'timeout'}
    return {'status': 'error', 'message': raw.get('query_status') or raw.get('error')}


@timed_lru_cache(seconds=1800, maxsize=500)
def get_malwarebazaar_report(hash_value: str) -> Optional[Dict]:
    """abuse.ch made `Auth-Key` mandatory, so this is no longer keyless: with no
    ABUSECH_AUTH_KEY the request is not made at all and this returns None, which
    unknown_hash_report() renders as 'skipped' rather than as a failed query.
    """
    envelope = abusech.malwarebazaar_hash(hash_value)
    state = envelope['state']

    if state == 'skipped':
        return None
    if state == 'no_record':
        return {'status': 'not_found'}
    if state == 'unavailable':
        return _abusech_failure(envelope)

    info = (abusech.records(envelope['raw'].get('data')) or [{}])[0]
    return {
        'status': 'found',
        'sha256': info.get('sha256_hash'),
        'sha1': info.get('sha1_hash'),
        'md5': info.get('md5_hash'),
        'file_type': info.get('file_type'),
        'file_name': info.get('file_name'),
        'file_size': info.get('file_size'),
        'signature': info.get('signature'),
        'first_seen': info.get('first_seen'),
        'last_seen': info.get('last_seen'),
        'reporter': info.get('reporter'),
        'tags': info.get('tags', []),
        'delivery_method': info.get('delivery_method'),
        'intelligence': info.get('intelligence', {}),
        'mb_link': f"https://bazaar.abuse.ch/sample/{info.get('sha256_hash', hash_value)}/"
    }


@timed_lru_cache(seconds=1800, maxsize=500)
def get_threatfox_iocs(hash_value: str) -> Optional[Dict]:
    """Search ThreatFox for IOCs related to a hash. Same mandatory key as MalwareBazaar."""
    envelope = abusech.threatfox_hash(hash_value)
    state = envelope['state']

    if state == 'skipped':
        return None
    if state == 'no_record':
        return {'status': 'not_found'}
    if state == 'unavailable':
        return _abusech_failure(envelope)

    iocs = abusech.records(envelope['raw'].get('data'))
    return {
        'status': 'found',
        'ioc_count': len(iocs),
        'iocs': [{
            'id': ioc.get('id'),
            'ioc_type': ioc.get('ioc_type'),
            'threat_type': ioc.get('threat_type'),
            'malware': ioc.get('malware'),
            'confidence': ioc.get('confidence_level'),
            'first_seen': ioc.get('first_seen_utc'),
            'tags': ioc.get('tags', [])
        } for ioc in iocs[:10]]
    }


@timed_lru_cache(seconds=1800, maxsize=500)
def get_hash_info(hash_value: str, deep_scan: bool = False,
                  md5: Optional[str] = None) -> Dict:
    """`deep_scan` waits for every source; otherwise shorter timeouts apply.

    `md5` exists only for Cymru MHR, whose zone has no sha256 records: an uploaded file
    already has all three digests, so passing the md5 alongside the sha256 is what makes
    that source usable at all (`file_service` does this).

    CIRCL and MHR land in `advisory`, never in `sources`. That separation is load-bearing:
    `file_rules._reputation_answered` walks `sources` to decide whether `benign` is even
    reachable, and neither of these may clear a file. MHR scores the empty-file MD5 at 91%,
    and EICAR is in NSRL, so an answer from either is not evidence of good. CIRCL's
    `KnownMalicious` still raises the verdict, through `summary['is_malicious']`.
    """
    hash_value = hash_value.lower().strip()
    hash_type, error = identify_hash_type(hash_value)

    if error:
        return {'error': error}

    result = {
        'hash': hash_value,
        'type': hash_type,
        'sources': {},
        'summary': {
            'is_malicious': False,
            'detection_count': 0,
            'total_engines': 0,
            'malware_names': set(),
            'tags': set()
        }
    }

    mhr_target = hash_value
    if hash_type not in ('MD5', 'SHA1'):
        mhr_target = (md5 or '').strip().lower() or hash_value

    advisory = {}

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {
            executor.submit(get_virustotal_report, hash_value): 'virustotal',
            executor.submit(get_malwarebazaar_report, hash_value): 'malwarebazaar',
            executor.submit(get_threatfox_iocs, hash_value): 'threatfox',
            executor.submit(get_circl_hashlookup, hash_value): CIRCL_SOURCE,
            executor.submit(get_cymru_mhr, mhr_target): MHR_SOURCE,
        }

        timeout = TIMEOUT_MEDIUM if deep_scan else TIMEOUT_SHORT

        for future in as_completed(futures, timeout=timeout + 5):
            source = futures[future]
            try:
                data = future.result(timeout=timeout)

                if source in ADVISORY_SOURCES:
                    advisory[source] = data
                    summary = (data or {}).get('summary') or {}
                    if source == CIRCL_SOURCE and summary.get('known_malicious'):
                        result['summary']['is_malicious'] = True
                        result['summary']['malware_names'].add(
                            f"CIRCL KnownMalicious ({summary['known_malicious']})")
                    continue

                if data:
                    result['sources'][source] = data

                    if data.get('status') == 'found':
                        if source == 'virustotal':
                            stats = data.get('detection_stats', {})
                            malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
                            if malicious > 0:
                                result['summary']['is_malicious'] = True
                                result['summary']['detection_count'] = malicious
                                result['summary']['total_engines'] = stats.get('total', 0)
                            result['summary']['tags'].update(data.get('tags', []))

                        if source == 'malwarebazaar':
                            result['summary']['is_malicious'] = True
                            if data.get('signature'):
                                result['summary']['malware_names'].add(data['signature'])
                            result['summary']['tags'].update(data.get('tags', []))

                        if source == 'threatfox':
                            result['summary']['is_malicious'] = True
                            for ioc in data.get('iocs', []):
                                if ioc.get('malware'):
                                    result['summary']['malware_names'].add(ioc['malware'])

            except Exception as e:
                logger.debug(f"Hash lookup {source} failed: {str(e)}")
                if source in ADVISORY_SOURCES:
                    advisory[source] = hash_reputation.envelope(
                        source, hash_reputation.STATE_UNAVAILABLE,
                        raw={'error': 'lookup_failed'})
                else:
                    result['sources'][source] = {'status': 'error', 'message': str(e)}

    # Sets are not JSON-serializable.
    result['summary']['malware_names'] = list(result['summary']['malware_names'])
    result['summary']['tags'] = list(result['summary']['tags'])

    result['advisory'] = advisory_rows(advisory)
    result['reference_links'] = reference_links(hash_value)

    return result


def get_hash_info_quick(hash_value: str, md5: Optional[str] = None) -> Dict:
    return get_hash_info(hash_value, deep_scan=False, md5=md5)


def get_hash_info_deep(hash_value: str, md5: Optional[str] = None) -> Dict:
    return get_hash_info(hash_value, deep_scan=True, md5=md5)


# Shared by every hash entry point (GET /i/<hash>, POST /analyze,
# POST /api/hash/analyze) so one hash renders one page whichever route you arrived
# through. Here rather than in a route because it is entirely about these sources.

# OTX is keyed off three different env-var names; all three are accepted, so all
# three count as "configured".
OTX_KEY_ENV = ('ALIENVAULT_KEY', 'ALIENVAULT', 'OTX_API_KEY')


def _otx_pulse_count(alienvault_raw) -> int:
    return (alienvault_raw or {}).get('general', {}).get('pulse_info', {}).get('count', 0)


def has_reputation_record(hash_info: Optional[Dict], alienvault_raw) -> bool:
    """False is the "nobody has seen it" case - a finding in its own right rather than
    an error; see unknown_hash_report().

    CIRCL and MHR are deliberately not consulted here. CIRCL reaches
    `summary['is_malicious']` when it reports `KnownMalicious`, which is caught by the
    first clause; merely being present in NSRL must not flip this page to a record, since
    EICAR is in NSRL. MHR's percentage never counts, having scored the empty file at 91%.
    """
    hash_info = hash_info or {}
    sources = hash_info.get('sources') or {}
    return bool(
        hash_info.get('summary', {}).get('is_malicious')
        or (sources.get('virustotal') or {}).get('status') == 'found'
        or (sources.get('malwarebazaar') or {}).get('status') == 'found'
        or _otx_pulse_count(alienvault_raw) > 0
    )


def source_state(configured: bool, status: Optional[str]) -> str:
    """'skipped' (no API key, never queried) is deliberately distinct from 'no_record':
    a source that was never asked says nothing about the hash. 'rate_limited' is distinct
    from both: the key is present and the answer exists, it is the per-minute quota that
    is spent, so a retry will produce it.
    """
    if not configured:
        return 'skipped'
    if status == 'found':
        return 'found'
    if status == 'not_found':
        return 'no_record'
    if status == 'rate_limited':
        return 'rate_limited'
    return 'unavailable'


STATES = ('found', 'no_record', 'rate_limited', 'skipped', 'unavailable')


def _advisory_detail(envelope: Dict) -> Optional[str]:
    """The one line that tells an analyst what a keyless source actually said. Both are
    scored by nothing, so the detail is all they contribute."""
    state = envelope.get('state')
    summary = envelope.get('summary') or {}
    raw = envelope.get('raw') or {}

    if raw.get('error') == 'unsupported_hash_type':
        return 'not supported for this hash type'
    if state != 'found':
        return None

    if envelope.get('source') == MHR_SOURCE:
        parts = [f"{summary.get('detection_pct')}% of engines at last scan"]
        if summary.get('last_seen_utc'):
            parts.append(f"last seen {summary['last_seen_utc']}")
        return ', '.join(parts)

    if summary.get('known_malicious'):
        return f"flagged malicious by {summary['known_malicious']}"
    if summary.get('nsrl_present'):
        name = summary.get('product_name') or summary.get('file_name')
        return f"present in NSRL{f' ({name})' if name else ''}, which is not a clean verdict"
    return 'known to CIRCL'


def advisory_rows(envelopes: Optional[Dict]) -> List[Dict]:
    """One display row per keyless source, always both, in a fixed order. A source that
    never returned an envelope is 'unavailable', never silently absent.
    """
    envelopes = envelopes if isinstance(envelopes, dict) else {}
    rows = []
    for source, name in ((CIRCL_SOURCE, 'CIRCL hashlookup'), (MHR_SOURCE, 'Team Cymru MHR')):
        envelope = envelopes.get(source)
        envelope = envelope if isinstance(envelope, dict) else {}
        rows.append({
            'name': name,
            # Keyless, so there is no key_env and 'skipped' can never apply.
            'key_env': None,
            'url': envelope.get('reference'),
            'state': envelope.get('state') or 'unavailable',
            'detail': _advisory_detail(envelope),
            'data': envelope or None,
        })
    return rows


def unknown_hash_report(hash_value: str, hash_info: Optional[Dict], alienvault_raw) -> Dict:
    """Per-source accounting for a hash that no source has a record of."""
    hash_info = hash_info or {}
    provider = hash_info.get('sources') or {}
    # hash_info is absent exactly when every lookup failed, which is when the
    # manual pivots matter most, so rebuild the links rather than skip them.
    links = hash_info.get('reference_links') or reference_links(hash_value)

    def status_of(name):
        return (provider.get(name) or {}).get('status')

    otx_status = None
    if alienvault_raw is not None:
        otx_status = 'found' if _otx_pulse_count(alienvault_raw) else 'not_found'

    sources = [
        {'name': 'VirusTotal', 'key_env': 'VIRUSTOTAL_API_KEY', 'url': links.get('virustotal'),
         'state': source_state(bool(os.getenv('VIRUSTOTAL_API_KEY')), status_of('virustotal')),
         'detail': None},
        # Both are abuse.ch and share one mandatory key, so both are 'skipped' (not
        # 'unavailable') when it is missing.
        {'name': 'MalwareBazaar', 'key_env': abusech.AUTH_ENV, 'url': links.get('malwarebazaar'),
         'state': source_state(bool(abusech.auth_key()), status_of('malwarebazaar')),
         'detail': None},
        {'name': 'ThreatFox', 'key_env': abusech.AUTH_ENV, 'url': links.get('threatfox'),
         'state': source_state(bool(abusech.auth_key()), status_of('threatfox')),
         'detail': None},
        {'name': 'AlienVault OTX', 'key_env': 'ALIENVAULT_KEY', 'url': links.get('alienvault_otx'),
         'state': source_state(any(os.getenv(k) for k in OTX_KEY_ENV), otx_status),
         'detail': None},
    ]
    advisory = hash_info.get('advisory')
    advisory = advisory if isinstance(advisory, list) else advisory_rows(None)
    return {
        'hash': hash_value,
        'type': hash_info.get('type') or identify_hash_type(hash_value)[0],
        'sources': sources,
        # Kept out of `sources` and out of `counts` for the same reason get_hash_info keeps
        # them out of `sources`: an answer from either is not evidence the file is good.
        'advisory': advisory,
        'counts': {state: sum(1 for s in sources if s['state'] == state)
                   for state in STATES},
        'reference_links': links,
    }
