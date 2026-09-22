"""Hudson Rock infostealer exposure, called directly rather than through user-scanner.

user-scanner ships core/hudson.py, but run_hudson_scan() prints to stdout and returns
None, so there is no structured value to consume. It also gates on an interactive
input() prompt that would hang a request thread.

Calling the public endpoint here is better for a second reason: the hostname becomes a
string literal in app/services/, which is exactly what test_disclosure.py walks, so this
lookup cannot ship without appearing in the acceptable-use notice.
"""

import logging
from datetime import timedelta

import requests

from ..utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

BASE_URL = 'https://cavalier.hudsonrock.com/api/json/v2/osint-tools'

# No published limit. Conservative, in the style of the other free sources here.
hudson_limiter = RateLimiter(max_requests=2, time_window=timedelta(seconds=1))

TIMEOUT = 10


def _http_get(url, **kwargs):
    return requests.get(url, timeout=TIMEOUT,
                        headers={'User-Agent': 'NexusTrace/1.0'}, **kwargs)


# Bounds on values copied out of a third-party feed. The mapping cannot content-scan
# the fields it keeps, so it guarantees their SHAPE instead: a short plain string,
# never a nested structure that would reach a template as a repr.
MAX_FIELD_CHARS = 200
MAX_ANTIVIRUSES = 20


def _text(value, limit=MAX_FIELD_CHARS):
    """One third-party value as a bounded plain string.

    Coercion is the point, not tidiness: `antiviruses` arrives as a list whose
    element types nobody here controls, and a dict copied straight through would
    reach a template and render as its repr.
    """
    if value is None:
        return ''
    if not isinstance(value, str):
        value = str(value)
    return value.strip()[:limit]


def map_response(payload):
    """A Cavalier response as an exposure summary.

    **What this guarantees, and what it does not.** The output is built from an
    explicit list of keys, so any field Hudson Rock adds is dropped by default,
    including `top_logins`, which carries credentials harvested from an infected
    machine and frequently belonging to third parties who are not the subject of the
    lookup. It does NOT content-scan the fields it keeps: a credential pasted into
    `computer_name` upstream would still come through, and detecting that reliably is
    not feasible. What it does enforce is shape, every kept value being a bounded
    plain string, so nothing nested or unbounded from an external feed reaches a
    template.

    Defensive about its own input as well as the network's, because it is part of
    this module's public interface and not only reachable through `lookup()`.
    """
    empty = {'exposed': False, 'count': 0, 'infections': [], 'source': 'Hudson Rock'}
    if not isinstance(payload, dict):
        return empty

    stealers = payload.get('stealers')
    if not isinstance(stealers, (list, tuple)):
        return empty

    infections = []
    for entry in stealers:
        if not isinstance(entry, dict):
            continue
        antiviruses = entry.get('antiviruses')
        if not isinstance(antiviruses, (list, tuple)):
            antiviruses = ()
        names = [_text(name) for name in list(antiviruses)[:MAX_ANTIVIRUSES]]
        infections.append({
            'family': _text(entry.get('stealer_family')) or 'unknown',
            'date': _text(entry.get('date_compromised')),
            'operating_system': _text(entry.get('operating_system')),
            'computer_name': _text(entry.get('computer_name')),
            'antiviruses': [name for name in names if name],
        })

    return {
        'exposed': bool(infections),
        'count': len(infections),
        'infections': infections,
        'source': 'Hudson Rock',
    }


def lookup(target, is_email=False, *, fetch=None):
    """Exposure for one identifier, or None when the source is unusable.

    A 404 means Hudson Rock has never seen the identifier. That is a finding, not a
    failure, so it maps to an empty result rather than None.
    """
    target = (target or '').strip()
    if not target:
        return None

    endpoint = 'search-by-email' if is_email else 'search-by-username'
    param = 'email' if is_email else 'username'
    url = f'{BASE_URL}/{endpoint}'

    getter = fetch or _http_get
    if fetch is None:
        hudson_limiter.acquire()

    try:
        response = getter(url, params={param: target})
    except Exception:
        logger.debug('Hudson Rock unreachable', exc_info=True)
        return None

    status = getattr(response, 'status_code', None)
    if status == 404:
        return map_response({'stealers': []})
    if status != 200:
        return None

    try:
        return map_response(response.json())
    except Exception:
        logger.debug('Hudson Rock returned an unreadable body', exc_info=True)
        return None
