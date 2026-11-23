"""Operator console: activity, accounts, intelligence sources and system status.

Fails closed. With neither ADMIN_TOKEN nor ADMIN_EMAILS configured every route 404s, the
same as any unrouted path, so a scanner learns nothing about whether an admin panel
exists. There is no default credential and no "disabled but visible" state. The token is
never accepted from the query string - a `?token=` would land in browser history, in any
referrer the page leaks, and in this app's own activity log - so it comes from a POST form
field (exchanged once for a signed session cookie) or an `X-Admin-Token` header for curl.

Two access modes:

- LAN mode (the default: Cloudflare Access not configured). The console answers only a
  request that arrives directly from a private, loopback or Tailscale address
  (ADMIN_NETWORKS) and carries no proxy or Cloudflare headers. Everything else gets the
  same 404 as an unrouted path, so even a reverse-proxy route added by mistake does not
  expose it. The peer address is read from before ProxyFix: ProxyFix rewrites
  `remote_addr` from X-Forwarded-For, which any client can set.
- Access mode (`CF_ACCESS_TEAM_DOMAIN` + `CF_ACCESS_AUD`). The signed JWT is verified by
  `utils.cf_access` and `ADMIN_EMAILS` is applied to the verified `email` claim. Neither
  `ADMIN_TOKEN` nor the plaintext `Cf-Access-Authenticated-User-Email` header is accepted
  in that mode, because anything reaching this origin without passing through Cloudflare
  (any host on the homelab LAN) can set that header at will but cannot forge the
  signature.
"""

import hashlib
import hmac
import ipaddress
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (Blueprint, abort, current_app, flash, redirect, render_template,
                   request, session, url_for)

from ..utils import accounts, activity, cf_access, oauth, storage

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

NETWORKS_ENV = 'ADMIN_NETWORKS'
# Private ranges, loopback, and Tailscale's 100.64.0.0/10 and fd7a:115c:a1e0::/48 (inside
# fc00::/7). Docker's bridge gateways fall inside 172.16.0.0/12.
DEFAULT_NETWORKS = ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10',
                    '127.0.0.0/8', '::1/128', 'fc00::/7')
# Present on anything that came through Cloudflare or a reverse proxy. Cloudflare always
# adds CF-Connecting-IP and CF-Ray; nginx in this stack adds X-Real-IP and X-Forwarded-For.
_PROXY_HEADERS = ('X-Forwarded-For', 'X-Real-IP', 'Forwarded', 'CF-Connecting-IP', 'CF-Ray')

# (name, what it feeds, environment variables, any one of which configures it)
SOURCES = (
    ('IPinfo', 'IP geolocation and ASN', ('IPINFO_TOKEN',)),
    ('IP2Location', 'IP geolocation', ('IP2LOCATION_KEY',)),
    ('VPNapi', 'VPN, proxy and Tor detection', ('VPNAPI_KEY',)),
    ('ProxyCheck', 'Proxy and VPN detection', ('PROXYCHECK_KEY',)),
    ('Shodan', 'Open ports and service banners', ('SHODAN_KEY',)),
    ('AbuseIPDB', 'IP abuse reports', ('ABUSEIPDB_KEY',)),
    ('AlienVault OTX', 'Threat pulses for IPs, domains and hashes',
     ('ALIENVAULT_KEY', 'ALIENVAULT', 'OTX_API_KEY')),
    ('abuse.ch', 'MalwareBazaar, ThreatFox and URLhaus', ('ABUSECH_AUTH_KEY',)),
    ('VirusTotal', 'Hash, file and URL reputation (shared key)', ('VIRUSTOTAL_API_KEY',)),
    ('IP2WHOIS', 'Domain WHOIS', ('IP2WHOIS_KEY',)),
    ('urlscan.io', 'URL scan submissions', ('URLSCAN_API_KEY',)),
)


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


def _allowed_networks():
    raw = os.environ.get(NETWORKS_ENV)
    parts = [p.strip() for p in raw.split(',') if p.strip()] if raw else DEFAULT_NETWORKS
    networks = []
    for part in parts:
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            logger.error('Ignoring invalid %s entry %r', NETWORKS_ENV, part)
    return networks


def _peer_address():
    """The address of whatever opened the TCP connection, from before ProxyFix."""
    original = request.environ.get('werkzeug.proxy_fix.orig') or {}
    return original.get('REMOTE_ADDR') or request.environ.get('REMOTE_ADDR') or ''


def _direct_from_allowed_network():
    if any(request.headers.get(name) for name in _PROXY_HEADERS):
        return False
    try:
        peer = ipaddress.ip_address(_peer_address())
    except ValueError:
        return False
    if getattr(peer, 'ipv4_mapped', None):
        peer = peer.ipv4_mapped
    return any(peer in network for network in _allowed_networks())


@admin_bp.before_request
def _gate():
    if not _enabled():
        abort(404)
    if not cf_access.is_configured() and not _direct_from_allowed_network():
        logger.warning('Admin refused: %s is not a direct request from an allowed network',
                       _peer_address())
        abort(404)


def _sign_in_page(status):
    """The token form. Reads nothing: an unauthenticated caller must not be able to make the
    server parse up to MAX_READ_ENTRIES records just by hitting /admin."""
    return render_template('admin/sign_in.html',
                           access_mode=cf_access.is_configured()), status


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not _authorized():
            # 403 rather than 404: the panel is configured, so its existence is not the
            # secret; the token is. A 404 here would leave the owner no way to sign in.
            return _sign_in_page(403)
        return view(*args, **kwargs)
    return wrapper


def _hourly_buckets(entries):
    """24-slot request/error counts for the last 24 hours, oldest-first."""
    now = datetime.now(timezone.utc)
    slots = {}
    for i in range(23, -1, -1):
        dt = now - timedelta(hours=i)
        key = dt.strftime('%Y-%m-%dT%H')
        slots[key] = {'label': dt.strftime('%H:00'), 'count': 0, 'errors': 0}
    for e in entries:
        ts = str(e.get('ts', ''))
        if len(ts) >= 13:
            key = ts[:13]
            if key in slots:
                slots[key]['count'] += 1
                try:
                    if int(e.get('status') or 0) >= 400:
                        slots[key]['errors'] += 1
                except (TypeError, ValueError):
                    pass
    return list(slots.values())


def _int_arg(name, default, low, high):
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


@admin_bp.route('/admin', methods=['GET'])
@admin_required
def admin_dashboard():
    days = _int_arg('days', DEFAULT_DAYS, 1, MAX_DAYS)
    per_page = _int_arg('per', DEFAULT_PAGE_SIZE, 10, MAX_PAGE_SIZE)
    page = _int_arg('page', 1, 1, 100_000)

    # One read serves both the table and the 24h summary. read_entries() is newest-first
    # and truncates at the oldest end, so the summary window is never what gets cut.
    entries = activity.read_entries(days=days)
    cutoff = activity.window_start(24)
    window_entries = [e for e in entries if str(e.get('ts', '')) >= cutoff]

    total = len(entries)
    pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, pages)
    start = (page - 1) * per_page

    return render_template(
        'admin/activity.html',
        section='activity',
        entries=entries[start:start + per_page],
        total=total,
        page=page,
        pages=pages,
        per_page=per_page,
        days=days,
        summary=activity.summarize(window_entries),
        hours_data=_hourly_buckets(window_entries),
    )


@admin_bp.route('/admin', methods=['POST'])
def admin_login():
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
    session.pop(_SESSION_KEY, None)
    return redirect(url_for('admin.admin_dashboard'), 303)


def _accounts_configuration():
    return {
        'enabled': accounts.enabled(),
        'encryption_key': accounts.encryption_configured(),
        'providers': [label for _, label in oauth.configured_providers()],
        'redirect_base': oauth.redirect_base(),
        'max_users': accounts.max_users(),
        'shared_key_policy': accounts.shared_key_policy(),
    }


@admin_bp.route('/admin/accounts', methods=['GET'])
@admin_required
def admin_accounts():
    config = _accounts_configuration()
    # Listing only an existing database: opening one creates the file, and a deployment
    # that never turned accounts on should not grow an empty accounts.db from a page view.
    users = accounts.list_users() if os.path.exists(accounts.DB_PATH) else []
    return render_template('admin/accounts.html', section='accounts', config=config,
                           users=users,
                           active=sum(1 for u in users if not u.get('disabled')))


@admin_bp.route('/admin/accounts/<int:user_id>/<action>', methods=['POST'])
@admin_required
def admin_account_action(user_id, action):
    if action not in ('disable', 'enable', 'delete'):
        abort(404)
    if not os.path.exists(accounts.DB_PATH):
        abort(404)
    if action == 'delete':
        if request.form.get('confirm') != str(user_id):
            flash('Type the account ID to confirm the deletion.', 'error')
            return redirect(url_for('admin.admin_accounts'), 303)
        accounts.delete_user(user_id)
        logger.info('Admin deleted account %s', user_id)
        flash(f'Account {user_id} and its saved keys are deleted.', 'success')
    else:
        if not accounts.set_disabled(user_id, action == 'disable'):
            flash(f'There is no account {user_id}.', 'error')
        else:
            logger.info('Admin %sd account %s', action, user_id)
            flash(f'Account {user_id} is {action}d.', 'success')
    return redirect(url_for('admin.admin_accounts'), 303)


@admin_bp.route('/admin/sources', methods=['GET'])
@admin_required
def admin_sources():
    rows = []
    for name, purpose, env_names in SOURCES:
        configured = next((env for env in env_names if (os.environ.get(env) or '').strip()),
                          None)
        rows.append({'name': name, 'purpose': purpose, 'variables': env_names,
                     'configured': configured})
    return render_template('admin/sources.html', section='sources', sources=rows,
                           configured=sum(1 for r in rows if r['configured']))


def _store_summary(name):
    try:
        entries = storage.store(name).list()
    except Exception as exc:  # a broken bucket or directory must not take the page down
        logger.warning('Admin could not list store %s: %s', name, type(exc).__name__)
        return {'name': name, 'error': True}
    newest = max((e['modified'] for e in entries), default=None)
    return {
        'name': name,
        'count': len(entries),
        'bytes': sum(e.get('size') or 0 for e in entries),
        'newest': (datetime.fromtimestamp(newest, timezone.utc).strftime('%Y-%m-%d %H:%M UTC')
                   if newest else None),
    }


@admin_bp.route('/admin/system', methods=['GET'])
@admin_required
def admin_system():
    settings = [
        ('Role', current_app.config.get('NEXUSTRACE_ROLE')),
        ('Admin access', 'Cloudflare Access' if cf_access.is_configured()
         else 'LAN and Tailscale only'),
        ('Storage backend', storage.backend_name()),
        ('Public session cookies HTTPS-only',
         'yes' if (os.environ.get('SECURE_COOKIES') or '').lower() == 'true' else 'no'),
        ('Accounts', 'on' if accounts.enabled() else 'off'),
        ('Abuse guard', (os.environ.get('ABUSE_GUARD') or 'default').strip()),
    ]
    return render_template('admin/system.html', section='system', settings=settings,
                           stores=[_store_summary(name) for name in storage.STORES],
                           networks=[str(n) for n in _allowed_networks()])
