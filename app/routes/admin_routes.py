"""Read-only activity dashboard for the public deployment.

Fails closed. With neither ADMIN_TOKEN nor ADMIN_EMAILS configured the route 404s, the
same as any unrouted path, so a scanner learns nothing about whether an admin panel
exists. There is no default credential and no "disabled but visible" state. The token is
never accepted from the query string - a `?token=` would land in browser history, in any
referrer the page leaks, and in this app's own activity log - so it comes from a POST form
field (exchanged once for a signed session cookie) or an `X-Admin-Token` header for curl.

Cloudflare Access, when configured (`CF_ACCESS_TEAM_DOMAIN` + `CF_ACCESS_AUD`), becomes
the *only* credential: the signed JWT is verified by `utils.cf_access` and `ADMIN_EMAILS`
is applied to the verified `email` claim. Neither `ADMIN_TOKEN` nor the plaintext
`Cf-Access-Authenticated-User-Email` header is accepted in that mode, because anything
reaching this origin without passing through Cloudflare (any host on the homelab LAN) can
set that header at will but cannot forge the signature.
"""

import hashlib
import hmac
import logging
import os
import time

from flask import (Blueprint, abort, flash, redirect, render_template, request,
                   session, url_for)

from ..utils import activity, cf_access

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__)

# The cookie is already a browser-session cookie, so this only bounds a long-lived tab.
SESSION_MAX_AGE = 12 * 60 * 60

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200

# The admin view parses every record in its window; both are bounded again by
# activity.MAX_READ_ENTRIES.
DEFAULT_DAYS = 7
MAX_DAYS = 30

_SESSION_KEY = 'nt_admin'


def _admin_token():
    return (os.environ.get('ADMIN_TOKEN') or '').strip()


def _admin_emails():
    raw = os.environ.get('ADMIN_EMAILS') or ''
    return {part.strip().lower() for part in raw.split(',') if part.strip()}


def _enabled():
    return bool(_admin_token() or _admin_emails() or cf_access.is_configured())


def _fingerprint(token):
    """Identifies which token a session was issued against, without storing it, so rotating
    ADMIN_TOKEN invalidates every outstanding admin session."""
    return hashlib.sha256(token.encode('utf-8')).hexdigest()[:16]


def _token_matches(candidate):
    token = _admin_token()
    if not token or not candidate:
        return False
    return hmac.compare_digest(candidate.encode('utf-8'), token.encode('utf-8'))


def _verified_access_allowed():
    """Access mode: the verified `email` claim, checked against ADMIN_EMAILS."""
    allow = _admin_emails()
    if not allow:
        logger.error('Cloudflare Access is configured but ADMIN_EMAILS is empty; '
                     'every Access identity will be denied.')
        return False
    try:
        email = cf_access.identity_from_request(request)
    except cf_access.AccessDenied as denied:
        logger.warning('Admin denied (%s) from %s', denied.reason, activity.client_ip(request))
        return False
    if email not in allow:
        logger.warning('Admin denied (not_allowlisted) for %s from %s',
                       email, activity.client_ip(request))
        return False
    return True


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
    # Access mode is exclusive: no falling back to the token or an already-issued session
    # when the JWT is missing, expired, or forged.
    #
    # `Cf-Access-Authenticated-User-Email` is never an authorization input, in either
    # mode. It is plaintext, so anything that can reach the origin directly can set it -
    # on a homelab LAN, every host on the network. ADMIN_TOKEN holds the door before
    # Access is configured; a signed JWT holds it after.
    if cf_access.is_configured():
        return _verified_access_allowed()
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
    """The token form. Reads nothing: an unauthenticated caller must not be able to make the
    server parse up to MAX_READ_ENTRIES records just by hitting /admin."""
    return render_template('admin.html', authorized=False, entries=[], total=0,
                           page=1, pages=1, per_page=DEFAULT_PAGE_SIZE, days=0,
                           summary=activity.summarize([]), cutoff=''), status


def _dashboard():
    days = _int_arg('days', DEFAULT_DAYS, 1, MAX_DAYS)
    per_page = _int_arg('per', DEFAULT_PAGE_SIZE, 10, MAX_PAGE_SIZE)
    page = _int_arg('page', 1, 1, 100_000)

    # One read serves both the table and the 24h summary. read_entries() is newest-first
    # and truncates at the oldest end, so the summary window is never what gets cut.
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
        # secret; the token is. A 404 here would leave the owner no way to sign in.
        return _sign_in_page(403)
    return _dashboard()


@admin_bp.route('/admin', methods=['POST'])
def admin_login():
    if not _enabled():
        abort(404)
    if cf_access.is_configured():
        logger.warning('Admin token login refused from %s: Access mode is active',
                       activity.client_ip(request))
        flash('Sign in through Cloudflare Access.', 'error')
        return _sign_in_page(403)
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
