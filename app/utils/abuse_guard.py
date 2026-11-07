"""Inbound abuse guard for the public process: probe-path blocking, a temporary ban list
and a per-IP request-rate ceiling.

Scanner probes (`/.env`, `/cred.txt`, ...) and single-IP floods otherwise travel the whole
Flask stack, hit the activity log and render a 404 page, and nothing pushes back on a
client that keeps going.

Behaviour, in order, per request on the public role:
  1. A banned IP gets a bare 403 (429 for rate bans) with `Retry-After`; nothing else runs.
  2. A path matching a known scanner probe gets a bare 404 and a strike. `PROBE_STRIKES`
     strikes inside `STRIKE_WINDOW` ban the IP for `BAN_SECONDS`.
  3. Any IP above `MAX_REQUESTS_PER_WINDOW` requests in `RATE_WINDOW` seconds is banned
     for `RATE_BAN_SECONDS`. Static assets are exempt so a page load is never throttled.

Limits and honesty about them.
  * State is per process and in memory, like `rate_limiter.py`; a restart clears bans.
    the single gunicorn worker (`--workers 1` in the Dockerfile) keeps that coherent;
    raising the worker count would split the counters per worker.
  * The IP is `activity.client_ip()`, i.e. `CF-Connecting-IP` first. That header is only
    trustworthy when the origin is reachable solely through the tunnel/Cloudflare. If
    port 5050 is also exposed on the LAN, a LAN host can forge it; the worst outcome is
    banning someone else's IP for `BAN_SECONDS`, never a bypass of authentication.
  * This is a backstop. The efficient place to drop this traffic is Cloudflare's edge
    (see docs/cloudflare-waf.md), which also stops it counting against the tunnel.
  * Memory is bounded: tracked IPs are capped at `MAX_TRACKED_IPS` and expired entries are
    swept, so spraying spoofed addresses cannot grow the process without limit.

Set `ABUSE_GUARD=off` to disable (tests, local debugging).
"""

import logging
import os
import re
import threading
import time
from collections import deque

from flask import Response

from . import activity

logger = logging.getLogger(__name__)

PROBE_STRIKES = 5
STRIKE_WINDOW = 600           # seconds
BAN_SECONDS = 3600            # probe ban

MAX_REQUESTS_PER_WINDOW = 240
RATE_WINDOW = 60              # seconds
RATE_BAN_SECONDS = 600

MAX_TRACKED_IPS = 10_000

# Paths nothing legitimate here ever requests. Matched case-insensitively on the path only.
_PROBE_RE = re.compile(
    r'(?:^|/)(?:'
    r'\.env(?:\.[\w.-]+)?'              # .env, .env.production, .env.bak
    r'|\.git(?:/|$)|\.svn(?:/|$)|\.hg(?:/|$)|\.aws(?:/|$)|\.ssh(?:/|$)|\.docker(?:/|$)'
    r'|\.ds_store|\.htaccess|\.htpasswd|\.npmrc|\.pypirc'
    r'|wp-admin|wp-login\.php|wp-content|wp-includes|xmlrpc\.php'
    r'|phpmyadmin|pma|adminer(?:\.php)?|phpinfo\.php|info\.php'
    r'|cgi-bin|vendor/phpunit|actuator(?:/|$)|server-status|boaform|hnap1'
    r'|cred(?:s|entials?)?\.(?:txt|json|ya?ml)|secrets?\.(?:txt|json|ya?ml)'
    r'|config\.(?:json|ya?ml|php|bak)|docker-compose\.ya?ml|id_rsa|credentials'
    r'|backup\.(?:sql|zip|tar(?:\.gz)?)|dump\.sql|database\.sql'
    r')',
    re.IGNORECASE,
)

# A page load is dozens of these; counting them would ban real users.
_RATE_EXEMPT_PREFIXES = ('/static/', '/cyberchef_app/assets/', '/cyberchef_app/images/',
                         '/cyberchef_app/modules/')
_RATE_EXEMPT_PATHS = frozenset({'/favicon.ico', '/sw.js', '/robots.txt', '/api/health'})

_lock = threading.Lock()
_strikes = {}     # ip -> deque[float]
_hits = {}        # ip -> deque[float]
_bans = {}        # ip -> (expires_at, kind)


def _enabled():
    return os.environ.get('ABUSE_GUARD', 'on').strip().lower() not in ('off', '0', 'false')


def is_probe(path):
    return bool(_PROBE_RE.search(path or ''))


def _prune(table, cutoff):
    for ip in [k for k, q in table.items() if not q or q[-1] < cutoff]:
        del table[ip]


def _sweep(now):
    """Expire stale state and enforce the size cap. Called under the lock."""
    for ip in [k for k, (until, _) in _bans.items() if until <= now]:
        del _bans[ip]
    _prune(_strikes, now - STRIKE_WINDOW)
    _prune(_hits, now - RATE_WINDOW)
    for table in (_strikes, _hits):
        while len(table) > MAX_TRACKED_IPS:
            table.pop(next(iter(table)))


def _record(table, ip, now, window):
    q = table.get(ip)
    if q is None:
        q = table[ip] = deque()
    q.append(now)
    while q and q[0] < now - window:
        q.popleft()
    return len(q)


def banned(ip, now=None):
    """(kind, seconds_left) while `ip` is banned, else None."""
    now = time.monotonic() if now is None else now
    with _lock:
        entry = _bans.get(ip)
        if not entry:
            return None
        until, kind = entry
        if until <= now:
            del _bans[ip]
            return None
        return kind, max(1, int(until - now))


def evaluate(ip, path, now=None):
    """Pure decision for one request: None to allow, else (status, kind, retry_after).
    Separated from the Flask hook so it is testable without a clock or an app."""
    now = time.monotonic() if now is None else now
    if not ip:
        return None

    current = banned(ip, now)
    if current:
        kind, left = current
        return (429 if kind == 'rate' else 403), kind, left

    with _lock:
        if len(_strikes) + len(_hits) > MAX_TRACKED_IPS:
            _sweep(now)

        if is_probe(path):
            strikes = _record(_strikes, ip, now, STRIKE_WINDOW)
            tripped = strikes >= PROBE_STRIKES
            if tripped:
                _bans[ip] = (now + BAN_SECONDS, 'probe')
                _strikes.pop(ip, None)
            result = (404, 'probe', 0)
        else:
            tripped = False
            result = None

        exempt = path in _RATE_EXEMPT_PATHS or (path or '').startswith(_RATE_EXEMPT_PREFIXES)
        if not exempt and result is None:
            count = _record(_hits, ip, now, RATE_WINDOW)
            if count > MAX_REQUESTS_PER_WINDOW:
                _bans[ip] = (now + RATE_BAN_SECONDS, 'rate')
                _hits.pop(ip, None)
                logger.warning('abuse_guard: banned %s for %ds (rate)', ip, RATE_BAN_SECONDS)
                return 429, 'rate', RATE_BAN_SECONDS

    if tripped:
        logger.warning('abuse_guard: banned %s for %ds (probe)', ip, BAN_SECONDS)
    return result


def reset():
    with _lock:
        _strikes.clear()
        _hits.clear()
        _bans.clear()


def install(app):
    """Wire the before_request hook. Public role only: the admin process is bound to
    loopback behind a token, and throttling the operator there helps nobody."""
    from flask import request

    @app.before_request
    def _abuse_guard():
        if not _enabled():
            return None
        try:
            decision = evaluate(activity.client_ip(request), request.path)
        except Exception:
            # A guard bug must never take the site down.
            logger.warning('abuse_guard: evaluation failed', exc_info=False)
            return None
        if not decision:
            return None
        status, _kind, retry = decision
        response = Response('', status=status, mimetype='text/plain')
        if retry:
            response.headers['Retry-After'] = str(retry)
        response.headers['Cache-Control'] = 'no-store'
        return response

    # Must be installed before activity.install(): Flask runs this hook first, and the
    # short-circuited response still reaches activity's after_request, so blocked requests
    # stay in the log without rendering a template
    return app
