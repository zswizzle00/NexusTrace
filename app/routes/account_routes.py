"""Sign-in with GitHub or Google, and the page where a user saves their own API keys.

Every route 404s while accounts are off (see `accounts.enabled`), so a deployment that
never configures them exposes nothing new.
"""
import logging
import re
import threading
from collections import OrderedDict
from datetime import timedelta

from flask import (Blueprint, abort, flash, redirect, render_template, request, session,
                   url_for)

from ..services.hash_service import verify_virustotal_key
from ..utils import accounts, oauth
from ..utils.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)

account_bp = Blueprint('account', __name__)

PENDING_KEY = 'oauth_pending'
VIRUSTOTAL_KEY_PATTERN = re.compile(r'^[0-9a-f]{64}$')

# Each save asks VirusTotal whether the key works, so without a cap a signed-in account
# could use this page to test stolen keys in bulk.
_verify_limiters = OrderedDict()
_verify_lock = threading.Lock()
MAX_VERIFY_LIMITERS = 1000


def _may_verify(user_id):
    with _verify_lock:
        limiter = _verify_limiters.get(user_id)
        if limiter is None:
            limiter = RateLimiter(max_requests=5, time_window=timedelta(minutes=15))
            _verify_limiters[user_id] = limiter
            while len(_verify_limiters) > MAX_VERIFY_LIMITERS:
                _verify_limiters.popitem(last=False)
    return limiter.try_acquire()


@account_bp.before_request
def _require_accounts():
    if not accounts.enabled():
        abort(404)


def _redirect_uri(provider):
    path = url_for('account.callback', provider=provider)
    base = oauth.redirect_base()
    return f'{base}{path}' if base else url_for('account.callback', provider=provider,
                                               _external=True)


def _signed_in_or_redirect():
    user = accounts.current_user()
    if user is None:
        flash('Please sign in first.', 'warning')
    return user


@account_bp.route('/account', methods=['GET'])
def account():
    user = accounts.current_user()
    if user is None:
        return render_template('account_login.html', providers=oauth.configured_providers())
    return render_template('account.html', user=user,
                           keys=accounts.key_summary(user['id']),
                           shared_policy=accounts.shared_key_policy())


@account_bp.route('/account/login/<provider>', methods=['GET'])
def login(provider):
    try:
        url, pending = oauth.begin(provider, _redirect_uri(provider))
    except oauth.OAuthError as exc:
        flash(str(exc), 'error')
        return redirect(url_for('account.account'))
    session[PENDING_KEY] = pending
    return redirect(url, 302)


@account_bp.route('/account/callback/<provider>', methods=['GET'])
def callback(provider):
    pending = session.pop(PENDING_KEY, None)
    try:
        identity = oauth.complete(provider, request.args, pending, _redirect_uri(provider))
        user = accounts.sign_in(provider, identity['subject'], identity['login'])
    except oauth.OAuthError as exc:
        flash(str(exc), 'error')
        return redirect(url_for('account.account'))
    except accounts.SignupClosed:
        flash('New sign-ups are closed for now. Existing accounts can still sign in.', 'error')
        return redirect(url_for('account.account'))
    except accounts.AccountDisabled:
        flash('This account is disabled.', 'error')
        return redirect(url_for('account.account'))

    accounts.start_session(user)
    logger.info('Account %s signed in with %s', user['id'], provider)
    return redirect(url_for('account.account'), 303)


@account_bp.route('/account/logout', methods=['POST'])
def logout():
    accounts.end_session()
    flash('You are signed out.', 'success')
    return redirect(url_for('account.account'), 303)


@account_bp.route('/account/keys/virustotal', methods=['POST'])
def save_virustotal_key():
    user = _signed_in_or_redirect()
    if user is None:
        return redirect(url_for('account.account'), 303)

    value = (request.form.get('api_key') or '').strip().lower()
    if not VIRUSTOTAL_KEY_PATTERN.match(value):
        flash('That does not look like a VirusTotal API key (64 hexadecimal characters).',
              'error')
        return redirect(url_for('account.account'), 303)

    if not _may_verify(user['id']):
        flash('Too many keys checked. Wait 15 minutes and try again.', 'error')
        return redirect(url_for('account.account'), 303)

    result = verify_virustotal_key(value)
    if result == 'invalid':
        flash('VirusTotal rejected that key. Check it and try again.', 'error')
        return redirect(url_for('account.account'), 303)
    if result == 'unavailable':
        flash('VirusTotal did not answer, so the key was not checked or saved. '
              'Try again in a minute.', 'error')
        return redirect(url_for('account.account'), 303)

    accounts.save_key(user['id'], accounts.VIRUSTOTAL, value)
    logger.info('Account %s saved a VirusTotal key', user['id'])
    flash('Your VirusTotal key is saved. Lookups now use your own quota.', 'success')
    return redirect(url_for('account.account'), 303)


@account_bp.route('/account/keys/virustotal/delete', methods=['POST'])
def delete_virustotal_key():
    user = _signed_in_or_redirect()
    if user is not None:
        accounts.delete_key(user['id'], accounts.VIRUSTOTAL)
        logger.info('Account %s removed its VirusTotal key', user['id'])
        flash('Your VirusTotal key is removed.', 'success')
    return redirect(url_for('account.account'), 303)


@account_bp.route('/account/delete', methods=['POST'])
def delete_account():
    user = _signed_in_or_redirect()
    if user is not None:
        accounts.delete_user(user['id'])
        accounts.end_session()
        logger.info('Account %s deleted itself', user['id'])
        flash('Your account and saved keys are deleted.', 'success')
    return redirect(url_for('account.account'), 303)
