"""Keyless live phone sources: LocalCallingGuide and SkipCalls.

Both are free, need no account, and both are best-effort. Neither publishes a rate limit
or an SLA, so the rate limiters here are deliberately conservative and every failure path
returns None: a source that is down removes its card and never breaks the page.

LocalCallingGuide is what makes a US lookup worth doing at all. libphonenumber ships no
NANP carrier data and classifies every US number as FIXED_LINE_OR_MOBILE, so its
``company-type`` field (ILEC / CLEC / wireless) is the only free signal separating a
landline from a mobile or a VOIP reseller.

SkipCalls is a crowd-report database, and its output is NOT a verdict. It flags
legitimate high-volume corporate lines: the measured example is Apple's published
support line, which comes back is_spam=true. Everything here maps it to a *report* with
its category, and the template is required to render it that way.
"""

import json
import logging
import xml.etree.ElementTree as ET
from datetime import timedelta

import requests

from ..utils.cache import timed_lru_cache
from ..utils.phone_parse import analyze
from ..utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

PREFIX_URL = 'https://localcallingguide.com/xmlprefix.php'
SPAM_URL = 'https://spam.skipcalls.com/check'

# Neither service publishes a limit. These are courtesy limits for free endpoints run
# without funding, not values derived from a documented quota.
prefix_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))
spam_limiter = RateLimiter(max_requests=1, time_window=timedelta(seconds=1))

TIMEOUT = 8

# The real document is under 6 KB. The cap bounds what reaches the XML parser from a
# third party nobody here controls, in a process that runs ONE gunicorn worker: an
# unbounded read plus a parse is how a single bad response takes down every other
# request on the box.
MAX_RESPONSE_BYTES = 256 * 1024

# Number-range allocations change on the order of months, so this is cached far longer
# than the app's 30-minute default. Note timed_lru_cache's TTL is per-function, not
# per-key: one expiry flushes every cached prefix at once. That is fine for a lookup
# this cheap to repeat.
PREFIX_CACHE_SECONDS = 24 * 60 * 60

COMPANY_TYPES = {
    'I': 'ILEC',
    'C': 'CLEC',
    'W': 'wireless',
}

# The XML element names LocalCallingGuide returns, mapped to our own snake_case keys.
_PREFIX_FIELDS = {
    'npa': 'npa',
    'nxx': 'nxx',
    'ocn': 'ocn',
    'company-name': 'company_name',
    'company-type': 'company_type',
    'ilec-name': 'ilec_name',
    'rc': 'rate_center',
    'region': 'region',
    'lata': 'lata',
    'switch': 'switch',
    'switchname': 'switch_name',
    'udate': 'updated',
}


def _http_get(url, timeout=None):
    return requests.get(url, timeout=timeout or TIMEOUT,
                        headers={'User-Agent': 'NexusTrace/1.0 (+phone number lookup)'})


def _read_capped(response, source):
    """The response body as text, or None when it is absent, not a 200, or over the cap.

    ONE implementation for both sources on purpose. The first version of this module
    applied the cap inline in one fetch path and forgot it in the other two, which is
    the failure mode a shared helper removes rather than documents.
    """
    if getattr(response, 'status_code', None) != 200:
        return None
    body = getattr(response, 'content', b'') or b''
    if len(body) > MAX_RESPONSE_BYTES:
        logger.warning('%s returned %d bytes, over the %d byte cap',
                       source, len(body), MAX_RESPONSE_BYTES)
        return None
    return getattr(response, 'text', '') or ''


def parse_prefix_xml(text):
    """One ``<prefixdata>`` record as a dict, or None when there is no record.

    Returns None rather than raising for unparseable input: the caller's contract is
    "a card or no card", and a malformed response from a best-effort source is a
    no-card, not an error.

    The live document declares ~96 HTML entities in a DOCTYPE internal subset before the
    payload, so the fixture in the tests keeps that shape: a parser written against a
    trimmed document works in tests and fails in production.

    **On the XML parser choice, which was measured rather than assumed.** This uses the
    stdlib parser deliberately, and defusedxml would be wrong here:

    * defusedxml's defaults REJECT this exact document with EntitiesForbidden, because
      of those entity declarations. Swapping it in "for safety" breaks the feature, and
      breaks it silently, since an unparseable response fails soft to no card.
    * Making defusedxml accept it requires forbid_entities=False, which disables the
      protection it is being added for. That reads as a mistake to the next person, who
      "fixes" it and silently removes the card again.
    * The two real risks are both already closed. External entities are never fetched:
      the stdlib parser errors with "undefined entity" rather than reading the file, so
      XXE is not a live vector. Entity-expansion amplification is refused by expat with
      a ParseError, which this function maps to None like any other malformed response.

    test_phone_sources.py pins all three behaviours, so they are contractual rather than
    incidental to a parser version.
    """
    if not text:
        return None
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return None

    record = root.find('prefixdata')
    if record is None:
        return None

    parsed = {}
    for element_name, key in _PREFIX_FIELDS.items():
        found = record.find(element_name)
        parsed[key] = (found.text or '').strip() if found is not None else ''

    parsed['company_type_label'] = COMPANY_TYPES.get(parsed['company_type'], '')
    return parsed


@timed_lru_cache(PREFIX_CACHE_SECONDS)
def _prefix_lookup_cached(npa, nxx):
    # Deliberately NOT registered in app/utils/cache.py:clear_caches(). That helper is
    # a hand-maintained list swept periodically, and a function it does not name keeps
    # its own TTL. Registering this one would collapse the 24-hour TTL to the sweep
    # interval, which is the opposite of what a table of number-range allocations
    # needs. If you came here to "fix" the omission, this comment is the reason not to.
    prefix_limiter.acquire()
    try:
        text = _read_capped(_http_get(f'{PREFIX_URL}?npa={npa}&nxx={nxx}'),
                            'LocalCallingGuide')
    except Exception:
        logger.debug('LocalCallingGuide unreachable', exc_info=True)
        return None
    return parse_prefix_xml(text)


def prefix_lookup(national_number, *, fetch=None):
    """NANP allocation data for a number's NPA-NXX, or None.

    ``fetch`` exists for the tests, which inject a fake and make no network call. It
    also bypasses the cache, so a test cannot be polluted by a previous case.
    """
    digits = ''.join(c for c in (national_number or '') if c.isdigit())
    if len(digits) < 6:
        return None
    npa, nxx = digits[:3], digits[3:6]

    if fetch is not None:
        try:
            text = _read_capped(fetch(f'{PREFIX_URL}?npa={npa}&nxx={nxx}',
                                      timeout=TIMEOUT), 'LocalCallingGuide')
        except Exception:
            return None
        return parse_prefix_xml(text)

    return _prefix_lookup_cached(npa, nxx)


def map_spam_response(payload):
    """A SkipCalls response as a *report*, never a verdict.

    is_spam=true means the number appears in a crowd-report database. It does not mean
    the number is malicious: the database flags legitimate corporate support lines. No
    key in the returned dict may contain a verdict word, and the test asserts that.
    """
    payload = payload or {}
    reported = bool(payload.get('is_spam'))
    return {
        'number': payload.get('number', ''),
        'reported': reported,
        'category': (payload.get('status_description') or '') if reported else '',
        'source': 'SkipCalls community reports',
    }


def spam_lookup(national_number, *, fetch=None):
    """Crowd-reported spam status for a US number, or None when unreachable."""
    digits = ''.join(c for c in (national_number or '') if c.isdigit())
    if not digits:
        return None

    getter = fetch or _http_get
    if fetch is None:
        # Sub-second window, so block briefly rather than dropping the lookup.
        # Skipped entirely when a test injects `fetch`.
        spam_limiter.acquire()

    try:
        text = _read_capped(getter(f'{SPAM_URL}/{digits}', timeout=TIMEOUT),
                            'SkipCalls')
    except Exception:
        logger.debug('SkipCalls unreachable', exc_info=True)
        return None
    if text is None:
        return None
    try:
        return map_spam_response(json.loads(text))
    except Exception:
        logger.debug('SkipCalls returned an unreadable body', exc_info=True)
        return None


def build_report(raw, default_region=None, live=True):
    """Offline metadata, plus the two keyless sources when ``live``.

    Lives here rather than in the route because two routes need it: the dedicated page
    and /analyze's E.164 branch. A route importing another route would invert this
    project's layering.

    ``live=False`` is how the tests exercise the offline tier with no network call. It is
    also the honest shape of the feature: the offline tier is the product and the live
    sources are enrichment that may simply be absent.
    """
    offline = analyze(raw, default_region)
    report = {'offline': offline, 'prefix': None, 'spam': None}
    if not offline.get('ok') or not offline.get('valid') or not live:
        return report

    # Both live sources are NANP-only, so a non-NANP number skips them rather than
    # sending the number to somewhere that cannot answer for it.
    if offline.get('is_nanp'):
        report['prefix'] = prefix_lookup(offline['national_number'])
        report['spam'] = spam_lookup(offline['national_number'])
    return report
