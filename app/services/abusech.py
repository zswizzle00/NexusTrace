"""Client for every abuse.ch service behind their unified Auth-Key.

MalwareBazaar, ThreatFox, URLhaus and the Hunting API all authenticate with one key
from https://auth.abuse.ch/, sent as the `Auth-Key` header, and that header is
mandatory on all of them - an unauthenticated MalwareBazaar request is a flat 401,
not a public read.

Every public lookup returns the same envelope, never raises and never returns None:

    {'source': 'threatfox'|'urlhaus'|'malwarebazaar'|'hunting',
     'state': 'found'|'no_record'|'skipped'|'unavailable',
     'summary': {...},
     'reference': str|None,
     'raw': {...}}

The four states are the vocabulary `hash_service.source_state` already uses, and the
distinction between three of them is the point of this module:

- `skipped`     no key configured, no request issued - says nothing about the indicator.
- `no_record`   asked, and abuse.ch has nothing.
- `unavailable` transport failure, non-200, unparseable body, or a rejected key
                (`no_api_key`) - also says nothing about the indicator.

`raw` is the decoded provider body when there was one, otherwise a small diagnostic
dict (`{'error': 'timeout'}`, `{'error': 'http_401'}`, ...).

Submissions (`submit_ioc`, `upload_sample`) return the same five keys but a different
`state` vocabulary, because "we looked and found nothing" has no meaning when you are
writing rather than reading:

- `submitted`   abuse.ch accepted it.
- `duplicate`   abuse.ch already has it (`file_already_known`, an all-duplicate batch).
- `rejected`    refused - either locally, before any request, or by the provider
                (`user_blacklisted`, `file_expected`, an illegal enum or tag).
- `skipped`     no key configured, no request issued.
- `unavailable` transport failure, non-200, unparseable body, or `no_api_key`.
"""
import hashlib
import json
import logging
import os
import re
from datetime import timedelta
from typing import Dict, List, Optional
from urllib.parse import quote

import requests

from ..utils.cache import timed_lru_cache
from ..utils.constants import TIMEOUT_MEDIUM
from ..utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

AUTH_ENV = 'ABUSECH_AUTH_KEY'

MALWAREBAZAAR_API = 'https://mb-api.abuse.ch/api/v1/'
THREATFOX_API = 'https://threatfox-api.abuse.ch/api/v1/'
URLHAUS_API = 'https://urlhaus-api.abuse.ch/v1/'
HUNTING_API = 'https://hunting-api.abuse.ch/api/v1/'

# abuse.ch documents no published rate limit. One limiter covers all four APIs
# because they are one provider behind one account.
abusech_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))

# A sample upload is a body transfer, not a lookup: TIMEOUT_MEDIUM (10s) is a fine
# bound on "answer a question about a hash" but will abort a multi-megabyte POST on an
# ordinary uplink, and an aborted upload is indistinguishable to us from a refusal.
UPLOAD_TIMEOUT = 60

STATE_FOUND = 'found'
STATE_NO_RECORD = 'no_record'
STATE_SKIPPED = 'skipped'
STATE_UNAVAILABLE = 'unavailable'

STATE_SUBMITTED = 'submitted'
STATE_DUPLICATE = 'duplicate'
STATE_REJECTED = 'rejected'

# Every abuse.ch "we looked, there is nothing" status across the four APIs. Anything
# else that is not 'ok' (illegal_hash, invalid_url, no_api_key, ...) is a failed
# query, not an empty result.
_NO_RECORD_STATUSES = frozenset({'no_results', 'no_result', 'hash_not_found'})

# Submission outcomes. ThreatFox answers 'ok', MalwareBazaar 'inserted'. Everything
# that is not accepted, duplicate, absent or `no_api_key` is the provider refusing the
# submission (`user_blacklisted`, `file_expected`, `http_post_expected`, `illegal_*`),
# which is a `rejected`, not an `unavailable` - resending it unchanged will not help.
_SUBMIT_ACCEPTED_STATUSES = frozenset({'ok', 'inserted'})
_SUBMIT_DUPLICATE_STATUSES = frozenset({'file_already_known'})
_SUBMIT_UNAVAILABLE_STATUSES = frozenset({'no_api_key'})

DELIVERY_METHODS = frozenset({'email_attachment', 'email_link', 'web_download',
                              'web_drive-by', 'multiple', 'other'})
REFERENCE_KEYS = frozenset({'urlhaus', 'any_run', 'joe_sandbox', 'malpedia', 'twitter',
                            'links'})
CONTEXT_KEYS = frozenset({'dropped_by_md5', 'dropped_by_sha256', 'dropped_by_malware',
                          'dropping_md5', 'dropping_sha256', 'dropping_malware',
                          'comment'})

# Both submission APIs document the tag charset as [A-Za-z0-9.- ]; the '-' is escaped
# because '.' to ' ' is a reversed, invalid range inside a character class.
_TAG_RE = re.compile(r'^[A-Za-z0-9.\- ]+$')


def auth_key() -> Optional[str]:
    """The one abuse.ch key, or None when it is not configured."""
    return (os.getenv(AUTH_ENV) or '').strip() or None


def _post(url, data=None, json_payload=None, headers=None, timeout=TIMEOUT_MEDIUM,
          files=None):
    """The module's only outbound call. Tests replace this attribute with a fake."""
    with abusech_limiter:
        return requests.post(url, data=data, json=json_payload, files=files,
                             headers=headers, timeout=timeout)


def _envelope(source, state, summary=None, reference=None, raw=None) -> Dict:
    return {
        'source': source,
        'state': state,
        'summary': summary if isinstance(summary, dict) else {},
        'reference': reference,
        'raw': raw if isinstance(raw, dict) else {},
    }


def records(value) -> List[Dict]:
    """Provider list fields as a list of dicts, tolerant of a single dict or an
    absent/odd value. Public because hash_service reshapes `raw` itself."""
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _strings(value) -> List[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item not in (None, '')]
    return []


def _distinct(values) -> List[str]:
    return sorted({str(v) for v in values if v not in (None, '')})


def _as_int(value) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_bool(value) -> Optional[bool]:
    """URLhaus reports `larted` as the string 'true'/'false', which is truthy either way."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ('true', 'yes', '1'):
            return True
        if lowered in ('false', 'no', '0'):
            return False
    return None


def _pick(record, *names):
    for name in names:
        value = record.get(name)
        if value not in (None, ''):
            return value
    return None


def _query(source, url, reference, data=None, json_payload=None, allow_list_body=False):
    """Issue one authenticated request. Returns (body, envelope): exactly one is None.

    A non-None envelope is terminal - the caller returns it unchanged.
    """
    key = auth_key()
    if not key:
        logger.debug("%s not configured; skipping %s lookup", AUTH_ENV, source)
        return None, _envelope(source, STATE_SKIPPED, reference=reference)

    try:
        response = _post(url, data=data, json_payload=json_payload,
                         headers={'Auth-Key': key}, timeout=TIMEOUT_MEDIUM)
    except requests.Timeout:
        logger.warning("abuse.ch %s request timed out", source)
        return None, _envelope(source, STATE_UNAVAILABLE, reference=reference,
                               raw={'error': 'timeout'})
    except requests.RequestException as exc:
        logger.warning("abuse.ch %s request failed: %s", source, exc)
        return None, _envelope(source, STATE_UNAVAILABLE, reference=reference,
                               raw={'error': 'request_error'})
    except Exception as exc:
        logger.error("abuse.ch %s transport error: %s", source, exc)
        return None, _envelope(source, STATE_UNAVAILABLE, reference=reference,
                               raw={'error': 'transport_error'})

    status_code = getattr(response, 'status_code', None)
    if status_code != 200:
        logger.warning("abuse.ch %s returned HTTP %s", source, status_code)
        return None, _envelope(source, STATE_UNAVAILABLE, reference=reference,
                               raw={'error': f'http_{status_code}'})

    try:
        body = response.json()
    except Exception:
        logger.warning("abuse.ch %s returned an unparseable body", source)
        return None, _envelope(source, STATE_UNAVAILABLE, reference=reference,
                               raw={'error': 'unparseable_body'})

    if allow_list_body and isinstance(body, list):
        body = {'query_status': 'ok', 'data': body}

    if not isinstance(body, dict):
        logger.warning("abuse.ch %s returned a %s body", source, type(body).__name__)
        return None, _envelope(source, STATE_UNAVAILABLE, reference=reference,
                               raw={'error': 'unexpected_body'})

    query_status = body.get('query_status')
    if query_status == 'ok':
        return body, None
    if query_status in _NO_RECORD_STATUSES:
        return None, _envelope(source, STATE_NO_RECORD, reference=reference, raw=body)

    logger.warning("abuse.ch %s returned query_status=%r", source, query_status)
    return None, _envelope(source, STATE_UNAVAILABLE, reference=reference,
                           raw=body if query_status else {'error': 'missing_query_status'})


def _threatfox_reference(term) -> str:
    return f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{quote(str(term), safe='')}"


def _urlhaus_reference(term) -> str:
    return f"https://urlhaus.abuse.ch/browse.php?search={quote(str(term), safe='')}"


def _threatfox_summary(items) -> Dict:
    first_seen = [_pick(i, 'first_seen', 'first_seen_utc') for i in items]
    last_seen = [_pick(i, 'last_seen', 'last_seen_utc') for i in items]
    confidences = [c for c in (_as_int(i.get('confidence_level')) for i in items)
                   if c is not None]
    first_seen = [str(v) for v in first_seen if v]
    last_seen = [str(v) for v in last_seen if v]
    return {
        'count': len(items),
        'malware': _distinct(i.get('malware_printable') for i in items),
        'threat_types': _distinct(i.get('threat_type') for i in items),
        'confidence_max': max(confidences) if confidences else None,
        'first_seen': min(first_seen) if first_seen else None,
        'last_seen': max(last_seen) if last_seen else None,
        'tags': _distinct(tag for i in items for tag in _strings(i.get('tags'))),
    }


def _threatfox_result(body, reference) -> Dict:
    items = records(body.get('data'))
    if not items:
        return _envelope('threatfox', STATE_NO_RECORD, reference=reference, raw=body)
    return _envelope('threatfox', STATE_FOUND, summary=_threatfox_summary(items),
                     reference=reference, raw=body)


@timed_lru_cache(seconds=1800, maxsize=500)
def threatfox_lookup(search_term: str, exact_match: bool = True) -> Dict:
    """ThreatFox IOC search. Accepts a domain, IP, IP:port or URL."""
    term = (search_term or '').strip()
    reference = _threatfox_reference(term)
    if not term:
        return _envelope('threatfox', STATE_UNAVAILABLE, raw={'error': 'empty_search_term'})

    body, envelope = _query(
        'threatfox', THREATFOX_API, reference,
        json_payload={'query': 'search_ioc', 'search_term': term,
                      'exact_match': bool(exact_match)})
    return envelope if envelope else _threatfox_result(body, reference)


@timed_lru_cache(seconds=1800, maxsize=500)
def threatfox_hash(hash_value: str) -> Dict:
    """ThreatFox lookup for an MD5 or SHA-256 payload hash."""
    value = (hash_value or '').strip().lower()
    reference = _threatfox_reference(value)
    if not value:
        return _envelope('threatfox', STATE_UNAVAILABLE, raw={'error': 'empty_hash'})

    body, envelope = _query('threatfox', THREATFOX_API, reference,
                            json_payload={'query': 'search_hash', 'hash': value})
    return envelope if envelope else _threatfox_result(body, reference)


@timed_lru_cache(seconds=1800, maxsize=500)
def urlhaus_host(host: str) -> Dict:
    """URLhaus records for an IPv4, hostname or domain."""
    value = (host or '').strip()
    reference = _urlhaus_reference(value)
    if not value:
        return _envelope('urlhaus', STATE_UNAVAILABLE, raw={'error': 'empty_host'})

    body, envelope = _query('urlhaus', URLHAUS_API + 'host/', reference,
                            data={'host': value})
    if envelope:
        return envelope

    urls = records(body.get('urls'))
    blacklists = body.get('blacklists')
    blacklists = blacklists if isinstance(blacklists, dict) else {}
    url_count = _as_int(body.get('url_count'))
    summary = {
        'url_count': len(urls) if url_count is None else url_count,
        'firstseen': body.get('firstseen'),
        'online_url_count': sum(1 for u in urls
                                if str(u.get('url_status') or '').lower() == 'online'),
        'blacklists': {
            'spamhaus_dbl': blacklists.get('spamhaus_dbl'),
            'surbl': blacklists.get('surbl'),
        },
        'threats': _distinct(u.get('threat') for u in urls),
    }
    return _envelope('urlhaus', STATE_FOUND, summary=summary,
                     reference=body.get('urlhaus_reference') or reference, raw=body)


@timed_lru_cache(seconds=1800, maxsize=500)
def urlhaus_url(url: str) -> Dict:
    """URLhaus record for one exact URL."""
    value = (url or '').strip()
    reference = _urlhaus_reference(value)
    if not value:
        return _envelope('urlhaus', STATE_UNAVAILABLE, raw={'error': 'empty_url'})

    body, envelope = _query('urlhaus', URLHAUS_API + 'url/', reference,
                            data={'url': value})
    if envelope:
        return envelope

    summary = {
        'url_status': body.get('url_status'),
        'threat': body.get('threat'),
        'date_added': body.get('date_added'),
        'tags': _strings(body.get('tags')),
        'larted': _as_bool(body.get('larted')),
    }
    return _envelope('urlhaus', STATE_FOUND, summary=summary,
                     reference=body.get('urlhaus_reference') or reference, raw=body)


@timed_lru_cache(seconds=1800, maxsize=500)
def urlhaus_payload(sha256: Optional[str] = None, md5: Optional[str] = None) -> Dict:
    """URLhaus payload record for a SHA-256 or MD5 hash. SHA-256 wins if both are given."""
    digest = (sha256 or '').strip().lower()
    field = 'sha256_hash'
    if not digest:
        digest = (md5 or '').strip().lower()
        field = 'md5_hash'
    if not digest:
        return _envelope('urlhaus', STATE_UNAVAILABLE, raw={'error': 'no_hash_supplied'})

    reference = _urlhaus_reference(digest)
    body, envelope = _query('urlhaus', URLHAUS_API + 'payload/', reference,
                            data={field: digest})
    if envelope:
        return envelope

    url_count = _as_int(body.get('url_count'))
    summary = {
        'file_type': body.get('file_type'),
        'signature': body.get('signature'),
        'firstseen': body.get('firstseen'),
        'url_count': 0 if url_count is None else url_count,
    }
    return _envelope('urlhaus', STATE_FOUND, summary=summary,
                     reference=body.get('urlhaus_reference') or reference, raw=body)


@timed_lru_cache(seconds=1800, maxsize=500)
def malwarebazaar_hash(hash_value: str) -> Dict:
    """MalwareBazaar sample record for an MD5, SHA-1 or SHA-256 hash."""
    value = (hash_value or '').strip().lower()
    if not value:
        return _envelope('malwarebazaar', STATE_UNAVAILABLE, raw={'error': 'empty_hash'})

    reference = f"https://bazaar.abuse.ch/browse.php?search={quote(value, safe='')}"
    body, envelope = _query('malwarebazaar', MALWAREBAZAAR_API, reference,
                            data={'query': 'get_info', 'hash': value})
    if envelope:
        return envelope

    samples = records(body.get('data'))
    if not samples:
        return _envelope('malwarebazaar', STATE_NO_RECORD, reference=reference, raw=body)

    record = samples[0]
    summary = {
        'file_name': record.get('file_name'),
        'file_type': record.get('file_type'),
        'signature': record.get('signature'),
        'tags': _strings(record.get('tags')),
        'first_seen': record.get('first_seen'),
        'delivery_method': record.get('delivery_method'),
    }
    sha256 = record.get('sha256_hash')
    if sha256:
        reference = f"https://bazaar.abuse.ch/sample/{quote(str(sha256), safe='')}/"
    return _envelope('malwarebazaar', STATE_FOUND, summary=summary,
                     reference=reference, raw=body)


@timed_lru_cache(seconds=1800, maxsize=2)
def hunting_fplist() -> Dict:
    """The abuse.ch Hunting API false-positive list.

    Nothing in the app calls this yet, and no route should: the Hunting API has no
    per-indicator lookup - its whole surface is `get_fplist` and `create_collection`
    - so there is no analysis page it can enrich. It is implemented here so the
    client covers the account's full API surface when a consumer does appear.
    """
    body, envelope = _query('hunting', HUNTING_API, 'https://hunting.abuse.ch/',
                            json_payload={'query': 'get_fplist', 'format': 'json'},
                            allow_list_body=True)
    if envelope:
        return envelope

    entries = records(body.get('fplist')) or records(body.get('data'))
    if not entries:
        return _envelope('hunting', STATE_NO_RECORD,
                         reference='https://hunting.abuse.ch/', raw=body)
    return _envelope('hunting', STATE_FOUND, summary={'count': len(entries)},
                     reference='https://hunting.abuse.ch/', raw=body)


# --- submissions -------------------------------------------------------------------
#
# `submit_ioc` and `upload_sample` are deliberately NOT wrapped in @timed_lru_cache,
# and that omission is the design, not an oversight - every other entry point above is
# cached. Caching a write is wrong in both directions: a cached 'submitted' turns an
# analyst's deliberate retry into a silent no-op that reports success without sending
# anything, and a cached failure blocks a legitimate resend for the whole TTL. They
# must also stay out of the clear_caches() list in app/utils/cache.py for the same
# reason. Two calls means two requests; app/tests/test_abusech.py asserts it.
#
# Neither function ever logs `data` or the assembled request body. A submitted sample
# is live malware that may carry customer content, and an IOC batch can carry internal
# hostnames; only the filename, byte count and SHA-256 are ever written to the log.


def _size(value) -> int:
    return len(value) if isinstance(value, (list, tuple, set, dict)) else 0


def _rejected(source, reason, detail=None, reference=None) -> Dict:
    raw = {'error': reason}
    if detail is not None:
        raw['detail'] = str(detail)[:120]
    return _envelope(source, STATE_REJECTED, reference=reference, raw=raw)


def _clean_tags(value):
    """Returns (tags, reason). Out-of-charset tags are refused here rather than sent:
    abuse.ch rejects the whole submission over one bad tag, so a local check turns a
    wasted round trip into an actionable reason."""
    if value in (None, '', [], ()):
        return [], None
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple, set)):
        return None, 'tags_not_a_list'
    tags = []
    for item in value:
        if not isinstance(item, str):
            return None, 'tag_not_a_string'
        tag = item.strip()
        if not tag:
            return None, 'empty_tag'
        if not _TAG_RE.match(tag):
            return None, 'illegal_tag_charset'
        tags.append(tag)
    return tags, None


def _clean_mapping(value, allowed, listify):
    """Validate a MalwareBazaar `references`/`context` map. Returns (clean, reason, key).

    An unknown key is refused rather than dropped: abuse.ch would silently ignore it,
    and the analyst would believe the context was recorded when it was not.
    """
    if value in (None, {}):
        return {}, None, None
    if not isinstance(value, dict):
        return None, 'not_a_mapping', None
    cleaned = {}
    for key, item in value.items():
        if key not in allowed:
            return None, 'unknown_key', key
        if item in (None, '', [], {}):
            continue
        if listify:
            items = _strings(item)
            if not items:
                return None, 'empty_value', key
            cleaned[key] = items
        else:
            text = str(item).strip()
            if not text:
                return None, 'empty_value', key
            cleaned[key] = text
    return cleaned, None, None


def _safe_filename(value) -> Optional[str]:
    """Basename only. A caller-supplied path or control character has no business in a
    multipart filename header."""
    if not isinstance(value, str):
        return None
    name = value.replace('\\', '/').split('/')[-1]
    name = ''.join(ch for ch in name if ch.isprintable()).strip().strip('.')
    return name[:255] or None


def _submit(source, url, reference, summary, json_payload=None, files=None,
            timeout=TIMEOUT_MEDIUM):
    """Issue one authenticated submission. Returns (body, envelope): exactly one is None.

    A non-None envelope is terminal. `summary` is caller-side metadata about what was
    sent, so it rides along on every outcome - knowing which SHA-256 was skipped for a
    missing key is exactly what makes a `skipped` actionable.
    """
    key = auth_key()
    if not key:
        logger.debug("%s not configured; not submitting to %s", AUTH_ENV, source)
        return None, _envelope(source, STATE_SKIPPED, summary=summary, reference=reference)

    try:
        response = _post(url, json_payload=json_payload, files=files,
                         headers={'Auth-Key': key}, timeout=timeout)
    except requests.Timeout:
        logger.warning("abuse.ch %s submission timed out", source)
        return None, _envelope(source, STATE_UNAVAILABLE, summary=summary,
                               reference=reference, raw={'error': 'timeout'})
    except requests.RequestException as exc:
        logger.warning("abuse.ch %s submission failed: %s", source, exc)
        return None, _envelope(source, STATE_UNAVAILABLE, summary=summary,
                               reference=reference, raw={'error': 'request_error'})
    except Exception as exc:
        logger.error("abuse.ch %s submission transport error: %s", source, exc)
        return None, _envelope(source, STATE_UNAVAILABLE, summary=summary,
                               reference=reference, raw={'error': 'transport_error'})

    status_code = getattr(response, 'status_code', None)
    if status_code != 200:
        logger.warning("abuse.ch %s submission returned HTTP %s", source, status_code)
        return None, _envelope(source, STATE_UNAVAILABLE, summary=summary,
                               reference=reference, raw={'error': f'http_{status_code}'})

    try:
        body = response.json()
    except Exception:
        logger.warning("abuse.ch %s submission returned an unparseable body", source)
        return None, _envelope(source, STATE_UNAVAILABLE, summary=summary,
                               reference=reference, raw={'error': 'unparseable_body'})

    if not isinstance(body, dict):
        logger.warning("abuse.ch %s submission returned a %s body", source,
                       type(body).__name__)
        return None, _envelope(source, STATE_UNAVAILABLE, summary=summary,
                               reference=reference, raw={'error': 'unexpected_body'})

    status = body.get('query_status')
    if status in _SUBMIT_ACCEPTED_STATUSES:
        return body, None
    if status in _SUBMIT_DUPLICATE_STATUSES:
        return None, _envelope(source, STATE_DUPLICATE, summary=summary,
                               reference=reference, raw=body)
    if not status:
        logger.warning("abuse.ch %s submission returned no query_status", source)
        return None, _envelope(source, STATE_UNAVAILABLE, summary=summary,
                               reference=reference, raw={'error': 'missing_query_status'})
    if status in _SUBMIT_UNAVAILABLE_STATUSES:
        logger.warning("abuse.ch %s submission returned query_status=%r", source, status)
        return None, _envelope(source, STATE_UNAVAILABLE, summary=summary,
                               reference=reference, raw=body)

    logger.warning("abuse.ch %s refused the submission: query_status=%r", source, status)
    return None, _envelope(source, STATE_REJECTED, summary=summary, reference=reference,
                           raw=body)


def _threatfox_submit_outcome(body, ioc_count):
    """ThreatFox answers `data: {ok, ignored, duplicated, reward}`. A batch abuse.ch
    already holds is a `duplicate`, not a submission, and one it discarded outright is
    a `rejected` - only `ok` entries actually landed."""
    data = body.get('data')
    counts = {'accepted': ioc_count, 'duplicated': 0, 'ignored': 0, 'reward': None}
    if not isinstance(data, dict):
        return STATE_SUBMITTED, counts
    if not any(name in data for name in ('ok', 'duplicated', 'ignored')):
        counts['reward'] = _as_int(data.get('reward'))
        return STATE_SUBMITTED, counts

    accepted = _size(data.get('ok'))
    duplicated = _size(data.get('duplicated'))
    ignored = _size(data.get('ignored'))
    counts = {'accepted': accepted, 'duplicated': duplicated, 'ignored': ignored,
              'reward': _as_int(data.get('reward'))}
    if accepted:
        return STATE_SUBMITTED, counts
    if duplicated:
        return STATE_DUPLICATE, counts
    if ignored:
        return STATE_REJECTED, counts
    return STATE_SUBMITTED, counts


def submit_ioc(iocs, threat_type, ioc_type, malware, *, confidence_level=50,
               is_compromised=False, reference=None, tags=None, comment=None,
               anonymous=True) -> Dict:
    """Submit IOCs to ThreatFox. `malware` is a Malpedia name, e.g. `win.zloader`.

    `anonymous` defaults to True so attribution is opt-in: an analyst has to decide to
    put the account's name on a public record, never inherit it from a default.

    Not cached - see the section note above. Never raises.
    """
    source = 'threatfox'

    if isinstance(iocs, str) or not isinstance(iocs, (list, tuple)):
        return _rejected(source, 'iocs_not_a_list')
    cleaned = []
    for item in iocs:
        if not isinstance(item, str):
            return _rejected(source, 'ioc_not_a_string')
        value = item.strip()
        if not value:
            return _rejected(source, 'empty_ioc')
        cleaned.append(value)
    if not cleaned:
        return _rejected(source, 'no_iocs_supplied')

    fields = {}
    for name, value in (('threat_type', threat_type), ('ioc_type', ioc_type),
                        ('malware', malware)):
        text = value.strip() if isinstance(value, str) else ''
        if not text:
            return _rejected(source, f'missing_{name}')
        fields[name] = text

    confidence = _as_int(confidence_level)
    if confidence is None or not 0 <= confidence <= 100:
        return _rejected(source, 'illegal_confidence_level')

    link = ''
    if reference not in (None, ''):
        if not isinstance(reference, str):
            return _rejected(source, 'illegal_reference')
        link = reference.strip()
        if not link.lower().startswith(('http://', 'https://')):
            return _rejected(source, 'illegal_reference')

    note = ''
    if comment not in (None, ''):
        if not isinstance(comment, str):
            return _rejected(source, 'illegal_comment')
        note = comment.strip()

    tag_list, reason = _clean_tags(tags)
    if reason:
        return _rejected(source, reason)

    payload = {
        'query': 'submit_ioc',
        'threat_type': fields['threat_type'],
        'ioc_type': fields['ioc_type'],
        'malware': fields['malware'],
        'iocs': cleaned,
        'confidence_level': confidence,
        'is_compromised': 'True' if is_compromised else 'False',
        'anonymous': 1 if anonymous else 0,
    }
    if link:
        payload['reference'] = link
    if tag_list:
        payload['tags'] = tag_list
    if note:
        payload['comment'] = note

    summary = {
        'ioc_count': len(cleaned),
        'ioc_type': fields['ioc_type'],
        'threat_type': fields['threat_type'],
        'malware': fields['malware'],
        'confidence_level': confidence,
        'anonymous': bool(anonymous),
        'tags': tag_list,
    }
    logger.info("submitting %d IOC(s) to ThreatFox: ioc_type=%s malware=%s anonymous=%s",
                len(cleaned), fields['ioc_type'], fields['malware'], bool(anonymous))

    ref = _threatfox_reference(cleaned[0])
    body, envelope = _submit(source, THREATFOX_API, ref, summary, json_payload=payload)
    if envelope:
        return envelope

    state, counts = _threatfox_submit_outcome(body, len(cleaned))
    summary.update(counts)
    return _envelope(source, state, summary=summary, reference=ref, raw=body)


def upload_sample(data, filename, *, tags=None, references=None, context=None,
                  delivery_method=None, anonymous=True) -> Dict:
    """Upload a sample to MalwareBazaar. `data` is the raw bytes of the file.

    `anonymous` defaults to True so attribution is opt-in.

    Not cached - see the section note above. `data` is never logged. Never raises.
    """
    source = 'malwarebazaar'

    if isinstance(data, (bytearray, memoryview)):
        data = bytes(data)
    if not isinstance(data, bytes):
        return _rejected(source, 'data_not_bytes')
    if not data:
        return _rejected(source, 'empty_data')

    safe_name = _safe_filename(filename)
    if not safe_name:
        return _rejected(source, 'missing_filename')

    tag_list, reason = _clean_tags(tags)
    if reason:
        return _rejected(source, reason)

    refs, reason, bad_key = _clean_mapping(references, REFERENCE_KEYS, listify=True)
    if reason:
        return _rejected(source, f'references_{reason}', detail=bad_key)

    ctx, reason, bad_key = _clean_mapping(context, CONTEXT_KEYS, listify=False)
    if reason:
        return _rejected(source, f'context_{reason}', detail=bad_key)

    delivery = ''
    if delivery_method not in (None, ''):
        if not isinstance(delivery_method, str):
            return _rejected(source, 'illegal_delivery_method')
        delivery = delivery_method.strip()
        if delivery not in DELIVERY_METHODS:
            return _rejected(source, 'illegal_delivery_method', detail=delivery)

    digest = hashlib.sha256(data).hexdigest()
    meta = {'anonymous': 1 if anonymous else 0}
    if tag_list:
        meta['tags'] = tag_list
    if refs:
        meta['references'] = refs
    if ctx:
        meta['context'] = ctx
    if delivery:
        meta['delivery_method'] = delivery

    files = {
        'json_data': (None, json.dumps(meta), 'application/json'),
        'file': (safe_name, data, 'application/octet-stream'),
    }

    summary = {
        'filename': safe_name,
        'size': len(data),
        'sha256': digest,
        'anonymous': bool(anonymous),
        'delivery_method': delivery or None,
        'tags': tag_list,
    }
    logger.info("uploading sample to MalwareBazaar: name=%s size=%d sha256=%s anonymous=%s",
                safe_name, len(data), digest, bool(anonymous))

    ref = f"https://bazaar.abuse.ch/sample/{digest}/"
    body, envelope = _submit(source, MALWAREBAZAAR_API, ref, summary, files=files,
                             timeout=UPLOAD_TIMEOUT)
    if envelope:
        return envelope
    return _envelope(source, STATE_SUBMITTED, summary=summary, reference=ref, raw=body)
