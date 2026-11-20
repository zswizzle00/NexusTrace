"""Signed-in accounts and the API keys their owners bring.

An account is only a GitHub or Google identity (provider plus that provider's stable user
ID) and the keys its owner saved. There are no passwords here and no e-mail addresses:
sign-in is delegated to the provider (`app/utils/oauth.py`), so there is nothing to reset,
leak or verify.

Keys are encrypted with Fernet before they touch the database. The encryption key lives
only in the environment (`ACCOUNTS_ENCRYPTION_KEY`), never in the database, so a copy of
`data/accounts.db` alone yields no usable key. Losing the environment key makes every
stored key unreadable, so back it up separately from the database.

Accounts are off unless both an encryption key and at least one sign-in provider are
configured; without them every page behaves as it did before accounts existed.
"""
import hashlib
import logging
import os
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import lru_cache

logger = logging.getLogger(__name__)

_BASE = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DB_PATH = os.environ.get('NEXUSTRACE_ACCOUNTS_DB') or os.path.join(_BASE, 'data', 'accounts.db')

ENCRYPTION_ENV = 'ACCOUNTS_ENCRYPTION_KEY'
MAX_USERS_ENV = 'ACCOUNTS_MAX_USERS'
DEFAULT_MAX_USERS = 50

SHARED_KEY_ENV = 'VIRUSTOTAL_SHARED_KEY'
# Who may spend the operator's VIRUSTOTAL_API_KEY. 'everyone' is the behaviour from before
# accounts existed; 'accounts' limits it to signed-in users without a key of their own;
# 'nobody' makes every VirusTotal lookup use the signed-in user's own key.
SHARED_KEY_POLICIES = ('everyone', 'accounts', 'nobody')

VIRUSTOTAL = 'virustotal'
SERVICES = (VIRUSTOTAL,)

SESSION_KEY = 'account_id'

# The default `vt_key` of every lookup function: the operator's VIRUSTOTAL_API_KEY,
# exactly as before accounts. Routes pass virustotal_key() instead, which may be a user's
# key or None (no VirusTotal lookup), so None cannot double as "use the default".
SHARED_KEY = object()

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS users (
    id             INTEGER PRIMARY KEY,
    provider       TEXT NOT NULL,
    subject        TEXT NOT NULL,
    -- Display only. The provider's login or name can change; `subject` cannot.
    login          TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    last_login_at  TEXT NOT NULL,
    disabled       INTEGER NOT NULL DEFAULT 0,
    UNIQUE (provider, subject)
);
CREATE TABLE IF NOT EXISTS api_keys (
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service      TEXT NOT NULL,
    ciphertext   TEXT NOT NULL,
    -- The last four characters, so the owner can tell which key is saved without the
    -- page ever showing the key again.
    hint         TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    PRIMARY KEY (user_id, service)
);
"""


class SignupClosed(Exception):
    """The account cap is reached; existing accounts can still sign in."""


class AccountDisabled(Exception):
    """The operator disabled this account."""


class ProviderKey:
    """An API key on its way to a provider.

    Hashable on a fingerprint, so `timed_lru_cache` keys results per key without the
    plaintext appearing in the cache key, a repr, a log line or a traceback. `owner` is
    'shared' for the operator's environment key and 'user' for a signed-in user's own.
    """
    __slots__ = ('value', 'owner', 'fingerprint')

    def __init__(self, value, owner):
        self.value = value
        self.owner = owner
        self.fingerprint = hashlib.sha256(value.encode('utf-8')).hexdigest()

    def __eq__(self, other):
        return isinstance(other, ProviderKey) and other.fingerprint == self.fingerprint

    def __hash__(self):
        return hash(self.fingerprint)

    def __repr__(self):
        return f'<ProviderKey {self.owner} {self.fingerprint[:8]}>'

    __str__ = __repr__


def _now():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def _fernet():
    """A MultiFernet over every key in ACCOUNTS_ENCRYPTION_KEY (comma-separated, newest
    first, so a key can be rotated without losing what the old one encrypted), or None
    when it is unset or malformed."""
    return _build_fernet(os.environ.get(ENCRYPTION_ENV, ''))


# Keyed on the raw setting, so the context processor's per-request enabled() does not
# rebuild the ciphers (or repeat the malformed-key error) while a changed setting still
# takes effect.
@lru_cache(maxsize=4)
def _build_fernet(raw):
    keys = [k.strip() for k in raw.split(',') if k.strip()]
    if not keys:
        return None
    from cryptography.fernet import Fernet, MultiFernet
    try:
        return MultiFernet([Fernet(k) for k in keys])
    except (ValueError, TypeError):
        logger.error('%s is not a valid Fernet key; accounts are disabled', ENCRYPTION_ENV)
        return None


def enabled():
    from . import oauth
    return _fernet() is not None and bool(oauth.configured_providers())


def max_users():
    try:
        return max(0, int(os.environ.get(MAX_USERS_ENV, DEFAULT_MAX_USERS)))
    except ValueError:
        return DEFAULT_MAX_USERS


def shared_key_policy():
    policy = (os.environ.get(SHARED_KEY_ENV) or 'everyone').strip().lower()
    if policy not in SHARED_KEY_POLICIES:
        logger.warning('Unknown %s %r; treating it as nobody', SHARED_KEY_ENV, policy)
        return 'nobody'
    return policy


_initialised = set()
_init_lock = threading.Lock()


def _initialise(connection, target):
    # Once per file: concurrent first connections each switching to WAL make SQLite
    # answer "database is locked" at once, without waiting out the busy timeout.
    with _init_lock:
        if target in _initialised and os.path.exists(target):
            return
        connection.executescript(SCHEMA)
        connection.execute('PRAGMA journal_mode = WAL')
        _initialised.add(target)


def connect(path=None):
    target = path or DB_PATH
    os.makedirs(os.path.dirname(target) or '.', exist_ok=True)
    # Create the file private before SQLite does: it gives the -wal and -shm sidecars the
    # main file's mode, so this one call covers all three with no world-readable window.
    os.close(os.open(target, os.O_CREAT | os.O_WRONLY, 0o600))
    connection = sqlite3.connect(target, timeout=10)
    connection.row_factory = sqlite3.Row
    _initialise(connection, target)
    connection.execute('PRAGMA foreign_keys = ON')
    return connection


@contextmanager
def _session(path=None):
    """A connection that commits on success, rolls back on error, and always closes;
    sqlite3's own context manager does the first two but never closes."""
    connection = connect(path)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def sign_in(provider, subject, login, path=None):
    """The account for this identity, created when new. Raises SignupClosed for a new
    identity past the cap, and AccountDisabled for a disabled one."""
    subject = str(subject)
    with _session(path) as db:
        # Take the write lock before counting, or two workers can both see room under the
        # cap and both insert.
        db.execute('BEGIN IMMEDIATE')
        row = db.execute('SELECT * FROM users WHERE provider = ? AND subject = ?',
                         (provider, subject)).fetchone()
        if row is not None:
            if row['disabled']:
                raise AccountDisabled()
            db.execute('UPDATE users SET login = ?, last_login_at = ? WHERE id = ?',
                       (login, _now(), row['id']))
            return dict(row, login=login)

        count = db.execute('SELECT COUNT(*) FROM users').fetchone()[0]
        if count >= max_users():
            raise SignupClosed()
        now = _now()
        cursor = db.execute(
            'INSERT INTO users (provider, subject, login, created_at, last_login_at) '
            'VALUES (?, ?, ?, ?, ?)', (provider, subject, login, now, now))
        return {'id': cursor.lastrowid, 'provider': provider, 'subject': subject,
                'login': login, 'created_at': now, 'last_login_at': now, 'disabled': 0}


def get_user(user_id, path=None):
    """The enabled account with this ID, or None."""
    with _session(path) as db:
        row = db.execute('SELECT * FROM users WHERE id = ? AND disabled = 0',
                         (user_id,)).fetchone()
    return dict(row) if row else None


def list_users(path=None):
    """Every account, disabled ones included, oldest first, with the services it has keys
    saved for. For the operator tool; never carries a key or its hint."""
    with _session(path) as db:
        users = db.execute('SELECT * FROM users ORDER BY id').fetchall()
        saved = db.execute('SELECT user_id, service FROM api_keys ORDER BY service').fetchall()
    services = {}
    for row in saved:
        services.setdefault(row['user_id'], []).append(row['service'])
    return [dict(user, services=services.get(user['id'], [])) for user in users]


def set_disabled(user_id, disabled, path=None):
    """Disables or re-enables an account. False when there is no such account."""
    with _session(path) as db:
        cursor = db.execute('UPDATE users SET disabled = ? WHERE id = ?',
                            (1 if disabled else 0, user_id))
    return cursor.rowcount > 0


def delete_user(user_id, path=None):
    """Removes the account and, through the foreign key, every key it saved."""
    with _session(path) as db:
        db.execute('DELETE FROM users WHERE id = ?', (user_id,))


def save_key(user_id, service, plaintext, path=None):
    fernet = _fernet()
    if fernet is None:
        raise RuntimeError(f'{ENCRYPTION_ENV} is not configured')
    if service not in SERVICES:
        raise ValueError(f'unknown service {service!r}')
    ciphertext = fernet.encrypt(plaintext.encode('utf-8')).decode('ascii')
    with _session(path) as db:
        db.execute(
            'INSERT INTO api_keys (user_id, service, ciphertext, hint, created_at) '
            'VALUES (?, ?, ?, ?, ?) ON CONFLICT (user_id, service) DO UPDATE SET '
            'ciphertext = excluded.ciphertext, hint = excluded.hint, '
            'created_at = excluded.created_at',
            (user_id, service, ciphertext, plaintext[-4:], _now()))


def load_key(user_id, service, path=None):
    """The plaintext key, or None when there is none or it cannot be decrypted."""
    fernet = _fernet()
    if fernet is None:
        return None
    with _session(path) as db:
        row = db.execute('SELECT ciphertext FROM api_keys WHERE user_id = ? AND service = ?',
                         (user_id, service)).fetchone()
    if row is None:
        return None
    from cryptography.fernet import InvalidToken
    try:
        return fernet.decrypt(row['ciphertext'].encode('ascii')).decode('utf-8')
    except InvalidToken:
        # Encrypted under a key no longer in ACCOUNTS_ENCRYPTION_KEY.
        logger.error('Saved %s key for account %s cannot be decrypted', service, user_id)
        return None


def key_summary(user_id, path=None):
    """{service: {'hint', 'created_at'}} for the keys this account saved; never the key."""
    with _session(path) as db:
        rows = db.execute('SELECT service, hint, created_at FROM api_keys WHERE user_id = ?',
                          (user_id,)).fetchall()
    return {row['service']: {'hint': row['hint'], 'created_at': row['created_at']}
            for row in rows}


def delete_key(user_id, service, path=None):
    with _session(path) as db:
        db.execute('DELETE FROM api_keys WHERE user_id = ? AND service = ?',
                   (user_id, service))


# Request helpers. Imported lazily from Flask so the store above runs in tests without an
# application.

def current_user():
    """The signed-in account for this request, or None. Cached on `g` for the request."""
    from flask import g, has_request_context, session
    if not has_request_context() or not enabled():
        return None
    if 'account' not in g:
        user_id = session.get(SESSION_KEY)
        g.account = get_user(user_id) if user_id is not None else None
        if user_id is not None and g.account is None:
            # Deleted or disabled since the cookie was issued.
            session.pop(SESSION_KEY, None)
    return g.account


def start_session(user):
    from flask import session
    # A fresh session, so nothing from before sign-in (an OAuth state, a stale account)
    # carries over into the signed-in one.
    session.clear()
    session[SESSION_KEY] = user['id']
    session.permanent = True


def end_session():
    from flask import g, session
    session.clear()
    g.pop('account', None)


def shared_virustotal_key():
    value = (os.environ.get('VIRUSTOTAL_API_KEY') or '').strip()
    return ProviderKey(value, 'shared') if value else None


def virustotal_key():
    """The VirusTotal key this request may use: the signed-in user's own when saved, else
    the operator's shared key when VIRUSTOTAL_SHARED_KEY allows it, else None.

    Resolve this in the request thread and pass it down: the lookups run in thread pools,
    where there is no request context to read the session from.
    """
    user = current_user()
    if user is not None:
        own = load_key(user['id'], VIRUSTOTAL)
        if own:
            shared = shared_virustotal_key()
            # The operator's own key saved by a user is still one quota: keep it on the
            # shared limiter instead of giving the same key a second 4-per-minute budget.
            if shared is not None and shared.fingerprint == hashlib.sha256(
                    own.encode('utf-8')).hexdigest():
                return shared
            return ProviderKey(own, 'user')

    if not enabled():
        return shared_virustotal_key()
    policy = shared_key_policy()
    if policy == 'everyone' or (policy == 'accounts' and user is not None):
        return shared_virustotal_key()
    return None
