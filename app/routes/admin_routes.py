"""Read-only activity dashboard for the public deployment.

Fails closed. With neither ADMIN_TOKEN nor ADMIN_EMAILS configured the route does not
answer at all - it 404s, the same as any unrouted path, so a scanner sweeping the site
learns nothing about whether an admin panel exists. There is no default credential and
no "disabled but visible" state.

The token is never accepted from the query string. A `?token=` would land in browser
history, in any referrer the page leaks, and in this app's own activity log if the log
ever started recording query strings. It is taken from a POST form field (exchanged
once for a signed session cookie) or from an `X-Admin-Token` header for curl.
"""

import hashlib
import hmac
import logging
import os
import time

from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   session, url_for)

from ..utils import activity

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__)

# A token exchanged for a session cookie stays valid this long. The cookie is already
# a browser-session cookie, so this only bounds a long-lived tab.
SESSION_MAX_AGE = 12 * 60 * 60

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

# The admin view parses every record in its window; 7 days is the useful default and
# 30 is the ceiling, both bounded again by activity.MAX_READ_ENTRIES.
DEFAULT_DAYS = 7
MAX_DAYS = 30

_SESSION_KEY = 'nt_admin'


def _admin_token():
    return (os.environ.get('ADMIN_TOKEN') or '').strip()


def _admin_emails():
    raw = os.environ.get('ADMIN_EMAILS') or ''
    return {part.strip().lower() for part in raw.split(',') if part.strip()}


def _enabled():
    return bool(_admin_token() or _admin_emails())


def _fingerprint(token):
    """Identifies which token a session was issued against, without storing it. Rotating
    ADMIN_TOKEN therefore invalidates every outstanding admin session."""
    return hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]


def _token_matches(candidate):
    token = _admin_token()
    if not token or not candidate:
        return False
    return hmac.compare_digest(candidate.encode('utf-8'), token.encode('utf-8'))


def _access_email_allowed():
    allow = _admin_emails()
    if not allow:
        return False
    email = (request.headers.get('Cf-Access-Authenticated-User-Email') or '').strip().lower()
    return bool(email) and email in allow


def _session_valid():
    state = session.get(_SESSION_KEY)
    if not isinstance(state, dict):
        return False
    token = _admin_token()
    if not token or state.get('fp') != _fingerprint(token):
        return False
    try:
        issued = float(state.get('at') or 0)
    except (TypeError, ValueError):
        return False
    return (time.time() - issued) < SESSION_MAX_AGE


def _authorized():
    if _access_email_allowed():
        return True
    if _token_matches((request.headers.get('X-Admin-Token') or '').strip()):
        return True
    return _session_valid()


def _int_arg(name, default, low, high):
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


def _sign_in_page(status):
    """The token form. Reads nothing: an unauthenticated caller must not be able to
    make the server parse up to MAX_READ_ENTRIES records just by hitting /admin."""
    return render_template('admin.html', authorized=False, entries=[], total=0,
                           page=1, pages=1, per_page=DEFAULT_PAGE_SIZE, days=0,
                           summary=activity.summarize([]), cutoff=''), status


def _dashboard():
    days = _int_arg('days', DEFAULT_DAYS, 1, MAX_DAYS)
    per_page = _int_arg('per', DEFAULT_PAGE_SIZE, 10, MAX_PAGE_SIZE)
    page = _int_arg('page', 1, 1, 100_000)

    # One read serves both the table and the 24h summary. read_entries() is
    # newest-first and truncates at the oldest end, so the summary window is never the
    # part that gets cut.
    entries = activity.read_entries(days=days)
    cutoff = activity.window_start(24)
    window = activity.summarize([e for e in entries if str(e.get('ts', '')) >= cutoff])

    total = len(entries)
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, pages)
    start = (page - 1) * per_page

    return render_template(
        'admin.html',
        authorized=True,
        entries=entries[start:start + per_page],
        total=total,
        page=page,
        pages=pages,
        per_page=per_page,
        days=days,
        summary=window,
        cutoff=cutoff,
    ), 200


@admin_bp.route('/admin', methods=['GET'])
def admin_dashboard():
    if not _enabled():
        abort(404)
    if not _authorized():
        # 403 rather than 404: the panel is configured, so its existence is not the
        # secret - the token is. A 404 here would leave the owner no way to sign in.
        return _sign_in_page(403)
    return _dashboard()


@admin_bp.route('/admin', methods=['POST'])
def admin_login():
    if not _enabled():
        abort(404)
    token = (request.form.get('token') or '').strip()
    if not _token_matches(token):
        logger.warning('Admin login rejected from %s', activity.client_ip(request))
        flash('Invalid token.', 'error')
        return _sign_in_page(403)
    session[_SESSION_KEY] = {'fp': _fingerprint(_admin_token()), 'at': time.time()}
    return redirect(url_for('admin.admin_dashboard'), 303)


@admin_bp.route('/admin/logout', methods=['POST'])
def admin_logout():
    if not _enabled():
        abort(404)
    session.pop(_SESSION_KEY, None)
    return redirect(url_for('admin.admin_dashboard'), 303)
