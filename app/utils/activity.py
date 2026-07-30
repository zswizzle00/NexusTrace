"""Append-only request activity log for the publicly reachable deployment.

cloud.nexustrace.net is served out of a homelab through a Cloudflare Tunnel with no
authentication on any browser route, so the only answer to "who is using this, from
where, and what did they do" is a log the app writes itself.

**Sensitivity.** These records are analyst-adjacent data, not ordinary web logs. They
tie a real client IP and country to a timeline of investigative actions, and the
`rid` field points straight at a scan/analysis record. Treat `data/activity/` exactly
like `data/scans/` and `data/analyses/`: gitignored, never exported, and covered by
the same retention/purge policy - there is no separate, laxer obligation because it
happens to be a log file.

What is deliberately NOT recorded: request bodies, uploaded bytes, form fields, query
strings, cookies, and headers wholesale. Only the named fields below are written, and
the writer is an explicit dict literal rather than a filtered copy of anything, so
there is no code path by which request content reaches disk.

Record schema, one JSON object per line, `data/activity/YYYY-MM-DD.jsonl`:

    ts        str   '2026-07-30T14:03:21.184Z', UTC, millisecond, sortable
    method    str   'GET'
    path      str   the matched Flask route RULE, e.g. '/i/<path:indicator>' - see
                    "Path sensitivity" below; the sanitised raw path when nothing
                    matched
    matched   bool  False when no route matched (a 404 probe); `path` is then raw
    rid       str   optional - the request's UUID-shaped view arg, when it has one
    endpoint  str   'home.analyze_deeplink', or '' when unmatched
    status    int   HTTP status of the response
    ms        float wall duration of the request, milliseconds, 1dp
    ip        str   the true client IP (see `client_ip`), '' when undeterminable
    country   str   two-letter CF-IPCountry, '' when absent
    ua        str   User-Agent, truncated to MAX_UA_CHARS
    user      str   optional - Cf-Access-Authenticated-User-Email, when Access is on
    upload    bool  the request carried a multipart body
    bytes_in  int   Content-Length, 0 when absent

**Path sensitivity - the route rule is stored, not the URL.** `/i/<indicator>`
embeds whatever the user looked up, which on this deployment is routinely a customer
domain, employee e-mail address, or internal hostname. Logging it would quietly turn
a usage log into a second copy of the analysis corpus, with none of the review that
went into deciding what `data/analyses/` may hold. The route rule answers the actual
question ("this person ran an indicator lookup") without answering a question nobody
asked ("on what"). Two deliberate exceptions:

  * `rid` carries a dynamic segment's value when, and only when, it is UUID-shaped.
    Those are ids this app generated for its own records (`/url_scan/<uuid>`,
    `/email_analysis/<uuid>`); they are opaque, contain no user input, and being able
    to ask "who else opened this scan" is the difference between a usage counter and
    something usable in an incident.
  * When no route matched, the raw path is stored (sanitised to printable ASCII and
    truncated). An unmatched path was never interpreted as an indicator - it is a
    scanner probing `/.env` or `/wp-login.php`, and on a public endpoint that is the
    single most valuable line in the file. The residual risk is a mistyped indicator
    landing on a 404; it is bounded by the truncation and accepted.

Query strings are never stored, matched or not.

**Bounds.** Both caps below exist because this is an unauthenticated public endpoint:
an attacker who can make requests can otherwise make the app fill its own disk.

Storage is local-filesystem only, on purpose: this does not go through
`app/utils/storage.py`, because a per-request object write against the GCS backend
would add a network round trip to every single response.
"""

import ipaddress
import json
import logging
import os
import re
import threading
import time
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

_BASE = Path(__file__).resolve().parent.parent.parent

# Read on every access rather than captured at import, so tests can repoint the whole
# tree at a temp directory (see app/tests/test_activity.py). NEXUSTRACE_ACTIVITY_DIR
# is the deployment escape hatch for putting it on a different volume.
ACTIVITY_DIR = Path(os.environ.get('NEXUSTRACE_ACTIVITY_DIR') or (_BASE / 'data' / 'activity'))

# ~13 MB/day at the ~260-byte typical line this schema produces, and 100 MB/day in the
# pathological case where every line is padded to MAX_LINE_BYTES. That is the ceiling a
# hostile client can force onto the homelab's disk in one day, and it is small enough
# to survive a week of abuse unnoticed. Past the cap the day's file simply stops
# growing and one warning is logged; dropping records is the correct failure mode when
# the alternative is filling the disk out from under the app.
MAX_ENTRIES_PER_DAY = 50_000

# A hard backstop on one line. Every variable-length field is already truncated at
# construction (`ua`, `path`), so a line only reaches this if something unforeseen is
# long - and an unbounded line is both a disk-exhaustion vector and a way to make the
# reader allocate arbitrarily. Over the limit, the record is dropped, not truncated:
# half a JSON object is not parseable and would poison every later read.
MAX_LINE_BYTES = 2000

MAX_UA_CHARS = 200

# Only reached for unmatched (404) paths, where the value is attacker-controlled.
MAX_PATH_CHARS = 120

# Upper bound on how much the admin view will parse in one request, across all days in
# its window. Three days at the daily cap; enough that the 24h summary is never
# truncated in practice, low enough that /admin cannot be turned into a CPU sink.
MAX_READ_ENTRIES = 150_000

# Static assets are excluded: they are dozens of requests per page view, carry no
# information about what an analyst did, and would be ~90% of the file.
_SKIP_ENDPOINTS = frozenset({'static'})
_SKIP_PREFIXES = ('/static/', '/cyberchef_app/assets/', '/cyberchef_app/images/',
                  '/cyberchef_app/modules/')
_SKIP_PATHS = frozenset({'/favicon.ico', '/sw.js', '/robots.txt'})

_UUID_RE = re.compile(
    r'\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z')

# Anything outside printable ASCII becomes '.', so a raw 404 path can never inject a
# newline (which would forge a second record) or terminal escapes into the file.
_NON_PRINTABLE_RE = re.compile(r'[^\x20-\x7e]')

_COUNTRY_RE = re.compile(r'\A[A-Za-z0-9]{2}\Z')

_lock = threading.Lock()
_state = {'day': None, 'count': 0, 'warned': False}


def _now():
    return datetime.now(timezone.utc)


def _stamp(moment):
    return moment.strftime('%Y-%m-%dT%H:%M:%S.') + f'{moment.microsecond // 1000:03d}Z'


def _day_of(stamp):
    return stamp[:10]


def _file_for(day):
    return Path(ACTIVITY_DIR) / f'{day}.jsonl'


def _clean(value, limit):
    if not value:
        return ''
    text = _NON_PRINTABLE_RE.sub('.', str(value))
    return text[:limit]


def client_ip(request):
    """The visitor's IP, not the tunnel's.

    Behind cloudflared, `remote_addr` is the loopback address the tunnel connects
    from and carries no information at all, so the order here is not a preference so
    much as a correctness requirement: `CF-Connecting-IP` is set by the Cloudflare
    edge on every proxied request and is the only field guaranteed to hold the client.
    `X-Forwarded-For`'s first hop and `remote_addr` are fallbacks for running this app
    without the tunnel (direct dev, plain nginx).

    Each candidate must parse as an IP address; a header a client can forge is not
    written to the log verbatim.
    """
    candidates = [
        request.headers.get('CF-Connecting-IP'),
        (request.headers.get('X-Forwarded-For') or '').split(',')[0],
        request.remote_addr,
    ]
    for candidate in candidates:
        text = (candidate or '').strip()
        if not text:
            continue
        # A bracketed IPv6 literal is legal in a forwarded-for element.
        if text.startswith('[') and ']' in text:
            text = text[1:text.index(']')]
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            continue
    return ''


def client_country(request):
    code = (request.headers.get('CF-IPCountry') or '').strip()
    return code.upper() if _COUNTRY_RE.match(code) else ''


def authenticated_user(request):
    """The Cloudflare Access identity, when Access is enabled.

    Access is not switched on yet, so this is empty in production today. It is read
    anyway so the log is already correct on the day it is turned on, rather than
    needing a schema change then.
    """
    return _clean(request.headers.get('Cf-Access-Authenticated-User-Email'), 254)


def should_skip(request):
    if getattr(request, 'endpoint', None) in _SKIP_ENDPOINTS:
        return True
    path = request.path or ''
    return path in _SKIP_PATHS or path.startswith(_SKIP_PREFIXES)


def describe_path(request):
    """(path, matched, rid) - see "Path sensitivity" in the module docstring."""
    rule = getattr(getattr(request, 'url_rule', None), 'rule', None)
    if not rule:
        return _clean(request.path, MAX_PATH_CHARS), False, ''
    rid = ''
    for value in (getattr(request, 'view_args', None) or {}).values():
        if isinstance(value, str) and _UUID_RE.match(value):
            rid = value
            break
    return _clean(rule, MAX_PATH_CHARS * 2), True, rid


def build_entry(request, status, duration_ms, moment=None):
    """The one place a record is constructed. Every persisted field is named here."""
    path, matched, rid = describe_path(request)
    content_type = (request.content_type or '').lower()
    length = request.content_length or 0
    entry = {
        'ts': _stamp(moment or _now()),
        'method': _clean(request.method, 10),
        'path': path,
        'matched': matched,
        'endpoint': _clean(getattr(request, 'endpoint', None), 80),
        'status': int(status),
        'ms': round(float(duration_ms), 1),
        'ip': client_ip(request),
        'country': client_country(request),
        'ua': _clean(request.headers.get('User-Agent'), MAX_UA_CHARS),
        'upload': content_type.startswith('multipart/form-data') and length > 0,
        'bytes_in': int(length),
    }
    if rid:
        entry['rid'] = rid
    user = authenticated_user(request)
    if user:
        entry['user'] = user
    return entry


def _count_lines(path):
    total = 0
    try:
        with open(path, 'rb') as handle:
            while True:
                chunk = handle.read(1 << 20)
                if not chunk:
                    break
                total += chunk.count(b'\n')
    except FileNotFoundError:
        return 0
    except OSError:
        logger.warning('Activity log: cannot count %s, assuming empty', path)
        return 0
    return total


def append(entry):
    """Append one record. Returns True when written.

    Raises on I/O failure - callers in the request path must wrap it. Keeping the
    raise here means `append()` stays testable for the failure case.
    """
    line = json.dumps(entry, separators=(',', ':'), ensure_ascii=True)
    if len(line) > MAX_LINE_BYTES:
        logger.warning('Activity log: dropped a %d-byte record for %s',
                       len(line), entry.get('path'))
        return False

    day = _day_of(entry['ts'])
    target = _file_for(day)
    with _lock:
        if _state['day'] != day:
            # Rollover, including the first write of a process: recover the day's
            # count from the file so a restart cannot reset the cap.
            _state['day'] = day
            _state['count'] = _count_lines(target)
            _state['warned'] = False
        if _state['count'] >= MAX_ENTRIES_PER_DAY:
            if not _state['warned']:
                logger.warning('Activity log: %s hit the %d-entry daily cap; '
                               'further records are dropped', day, MAX_ENTRIES_PER_DAY)
                _state['warned'] = True
            return False
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, 'a', encoding='utf-8') as handle:
            handle.write(line + '\n')
        _state['count'] += 1
    return True


def reset_state():
    """Forget the cached day/count. Only needed after repointing ACTIVITY_DIR, which
    in practice means tests."""
    with _lock:
        _state.update({'day': None, 'count': 0, 'warned': False})


def _iter_days(days):
    today = _now().date()
    for offset in range(max(1, int(days))):
        yield (today - timedelta(days=offset)).isoformat()


def read_entries(days=1, since=None):
    """Records from the last `days` UTC day-files, newest first.

    `since` is an ISO stamp; records older than it are skipped. Malformed lines are
    ignored rather than fatal - the file is append-only from one writer, but a
    truncated final line after a hard kill should not break the admin view.
    """
    entries = []
    for day in _iter_days(days):
        if since and day < _day_of(since):
            continue
        try:
            with open(_file_for(day), 'r', encoding='utf-8', errors='replace') as handle:
                lines = handle.readlines()
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            logger.warning('Activity log: cannot read %s', day)
            continue
        for line in reversed(lines):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            if not isinstance(record, dict):
                continue
            if since and str(record.get('ts', '')) < since:
                continue
            entries.append(record)
            if len(entries) >= MAX_READ_ENTRIES:
                return entries
    return entries


def summarize(entries):
    """Aggregate counts over an already-filtered list of records."""
    total = len(entries)
    uploads = 0
    errors = 0
    ips = Counter()
    paths = Counter()
    countries = Counter()
    for record in entries:
        if record.get('upload'):
            uploads += 1
        try:
            status = int(record.get('status') or 0)
        except (TypeError, ValueError):
            status = 0
        if status >= 400:
            errors += 1
        if record.get('ip'):
            ips[record['ip']] += 1
        if record.get('path'):
            paths[record['path']] += 1
        if record.get('country'):
            countries[record['country']] += 1
    return {
        'total': total,
        'uploads': uploads,
        'unique_ips': len(ips),
        'errors': errors,
        'error_rate': round(100.0 * errors / total, 1) if total else 0.0,
        'top_paths': paths.most_common(10),
        'top_ips': ips.most_common(10),
        'top_countries': countries.most_common(10),
    }


def window_start(hours):
    """The ISO stamp `hours` ago, for comparing against a record's `ts`."""
    return _stamp(_now() - timedelta(hours=hours))


def summary(hours=24):
    """The `hours`-window summary the admin page shows."""
    cutoff = window_start(hours)
    # A 24h window straddles at most two UTC day-files; +1 covers a longer window.
    days = int(hours // 24) + 2
    return summarize(read_entries(days=days, since=cutoff)), cutoff


def log_request(request, status, duration_ms):
    """Best-effort single-record write. Never raises."""
    try:
        if should_skip(request):
            return
        append(build_entry(request, status, duration_ms))
    except Exception:
        # A logging failure must never become a 500. Logged at warning, not exception,
        # because a full disk would otherwise write a traceback per request.
        logger.warning('Activity log: failed to record a request', exc_info=False)


def install(app):
    """Wire the request hooks. Called from create_app()."""
    from flask import g, request

    def _finish(status):
        if getattr(g, '_activity_done', False):
            return
        g._activity_done = True
        # A missing start marker means a before_request registered ahead of ours
        # short-circuited the request - CSRFProtect.protect() is the one that does,
        # on every rejected form POST. Those are worth seeing, so the record is
        # written with an unknown duration rather than dropped.
        started = getattr(g, '_activity_t0', None)
        elapsed = 0.0 if started is None else (time.perf_counter() - started) * 1000.0
        log_request(request, status, elapsed)

    @app.before_request
    def _activity_start():
        g._activity_t0 = time.perf_counter()
        g._activity_done = False

    @app.after_request
    def _activity_after(response):
        try:
            _finish(response.status_code)
        except Exception:
            logger.warning('Activity log: after_request hook failed', exc_info=False)
        return response

    @app.teardown_request
    def _activity_teardown(exc):
        # after_request is skipped when an exception propagates out of the view, which
        # is exactly the case worth seeing. `_finish` is idempotent per request, so a
        # normally-completed response is never counted twice.
        if exc is None:
            return
        try:
            _finish(500)
        except Exception:
            logger.warning('Activity log: teardown hook failed', exc_info=False)

    return app
