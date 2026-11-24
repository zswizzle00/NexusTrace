"""Accounts, GitHub/Google sign-in, and per-user VirusTotal keys.

No network: the providers and VirusTotal are fakes passed through the `transport=` seams
or patched onto the module, and the database is a temp file. The properties that matter
most are the ones a mistake would break silently: a forged callback must not sign anyone
in, a saved key must never sit in the database as plaintext, and one user's VirusTotal
quota or cached results must never leak into another request.
"""
import os
import shutil
import sqlite3
import sys
import tempfile
from datetime import timedelta
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from cryptography.fernet import Fernet

from app import create_app
from app.services import hash_service
from app.utils import accounts, activity, oauth
from app.utils.accounts import ProviderKey
from app.utils.rate_limiter import RateLimiter

VT_KEY = 'a' * 64
OTHER_VT_KEY = 'b' * 64

ENV_NAMES = ('ACCOUNTS_ENCRYPTION_KEY', 'ACCOUNTS_MAX_USERS', 'VIRUSTOTAL_SHARED_KEY',
             'VIRUSTOTAL_API_KEY', 'OAUTH_REDIRECT_BASE', 'GITHUB_CLIENT_ID',
             'GITHUB_CLIENT_SECRET', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET',
             'NEXUSTRACE_ROLE')

failures = []
cases = 0


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


def set_env(**values):
    for name, value in values.items():
        if value:
            os.environ[name] = value
        else:
            os.environ.pop(name, None)


class Sandbox:
    """A temp accounts database, a temp activity dir, and accounts switched on."""

    def __init__(self, **env):
        self.env = {'ACCOUNTS_ENCRYPTION_KEY': Fernet.generate_key().decode(),
                    'GITHUB_CLIENT_ID': 'gh-id', 'GITHUB_CLIENT_SECRET': 'gh-secret',
                    'GOOGLE_CLIENT_ID': 'g-id', 'GOOGLE_CLIENT_SECRET': 'g-secret',
                    'OAUTH_REDIRECT_BASE': 'https://nexustrace.example'}
        self.env.update(env)

    def __enter__(self):
        self.saved_env = {name: os.environ.get(name) for name in ENV_NAMES}
        self.saved_db = accounts.DB_PATH
        self.saved_activity = activity.ACTIVITY_DIR
        self.dir = tempfile.mkdtemp(prefix='nt-accounts-')
        accounts.DB_PATH = os.path.join(self.dir, 'accounts.db')
        activity.ACTIVITY_DIR = os.path.join(self.dir, 'activity')
        activity.reset_state()
        set_env(**{name: None for name in ENV_NAMES})
        set_env(**self.env)
        return self

    def __exit__(self, *exc):
        accounts.DB_PATH = self.saved_db
        activity.ACTIVITY_DIR = self.saved_activity
        activity.reset_state()
        set_env(**self.saved_env)
        shutil.rmtree(self.dir, ignore_errors=True)
        return False

    def app(self):
        app = create_app()
        app.config['WTF_CSRF_ENABLED'] = False
        app.config['TESTING'] = True
        return app


class FakeResponse:
    def __init__(self, status, payload=None):
        self.status_code = status
        self.ok = 200 <= status < 300
        self._payload = payload

    def json(self):
        if self._payload is None:
            raise ValueError('no JSON')
        return self._payload


class FakeProvider:
    """Stands in for `requests` in oauth.complete: one token answer, one profile."""

    def __init__(self, token=None, profile=None, token_status=200, profile_status=200):
        self.token = {'access_token': 'provider-token'} if token is None else token
        self.profile = profile or {}
        self.token_status = token_status
        self.profile_status = profile_status
        self.posts = []

    def post(self, url, data=None, headers=None, timeout=None):
        self.posts.append((url, dict(data or {})))
        return FakeResponse(self.token_status, self.token)

    def get(self, url, headers=None, timeout=None):
        return FakeResponse(self.profile_status, self.profile)


def test_provider_key_never_shows_the_key():
    key = ProviderKey(VT_KEY, 'user')
    check(VT_KEY not in repr(key) and VT_KEY not in str(key), 'repr leaks the key')
    check(key == ProviderKey(VT_KEY, 'user') and hash(key) == hash(ProviderKey(VT_KEY, 'user')),
          'equal keys are not equal or hash differently')
    check(key != ProviderKey(OTHER_VT_KEY, 'user'), 'different keys compare equal')


def test_accounts_are_off_without_configuration():
    with Sandbox(ACCOUNTS_ENCRYPTION_KEY=None):
        check(not accounts.enabled(), 'enabled with no encryption key')
    with Sandbox(GITHUB_CLIENT_ID=None, GOOGLE_CLIENT_ID=None):
        check(not accounts.enabled(), 'enabled with no provider')
    with Sandbox(ACCOUNTS_ENCRYPTION_KEY='not-a-fernet-key'):
        check(not accounts.enabled(), 'enabled with a malformed encryption key')
    with Sandbox(GOOGLE_CLIENT_ID=None):
        check(accounts.enabled(), 'not enabled with GitHub alone')
        check([name for name, _ in oauth.configured_providers()] == ['github'],
              'a provider without a client ID is offered')


def test_store():
    with Sandbox(ACCOUNTS_MAX_USERS='2'):
        first = accounts.sign_in('github', 101, 'octo')
        again = accounts.sign_in('github', '101', 'octo-renamed')
        check(first['id'] == again['id'], 'the same identity got a second account')
        check(accounts.get_user(first['id'])['login'] == 'octo-renamed',
              'the display name did not follow the provider')
        accounts.sign_in('google', '101', 'Same Number')
        try:
            accounts.sign_in('github', 999, 'third')
            check(False, 'a third account was created past ACCOUNTS_MAX_USERS=2')
        except accounts.SignupClosed:
            pass
        check(accounts.sign_in('github', 101, 'octo')['id'] == first['id'],
              'an existing account cannot sign in once the cap is reached')

        accounts.save_key(first['id'], accounts.VIRUSTOTAL, VT_KEY)
        check(accounts.load_key(first['id'], accounts.VIRUSTOTAL) == VT_KEY,
              'the saved key does not round-trip')
        check(accounts.key_summary(first['id']).get('virustotal', {}).get('hint') == VT_KEY[-4:],
              'the summary does not carry the last four characters')
        with open(accounts.DB_PATH, 'rb') as handle:
            raw = handle.read()
        if os.path.exists(accounts.DB_PATH + '-wal'):
            with open(accounts.DB_PATH + '-wal', 'rb') as handle:
                raw += handle.read()
        check(VT_KEY.encode() not in raw, 'the key is stored in plaintext')
        check(oct(os.stat(accounts.DB_PATH).st_mode & 0o777) == '0o600',
              'the database is readable by other users')

        old_key = os.environ['ACCOUNTS_ENCRYPTION_KEY']
        new_key = Fernet.generate_key().decode()
        os.environ['ACCOUNTS_ENCRYPTION_KEY'] = f'{new_key},{old_key}'
        check(accounts.load_key(first['id'], accounts.VIRUSTOTAL) == VT_KEY,
              'a rotated key list cannot read what the old key encrypted')
        os.environ['ACCOUNTS_ENCRYPTION_KEY'] = new_key
        check(accounts.load_key(first['id'], accounts.VIRUSTOTAL) is None,
              'a key encrypted under a dropped encryption key did not come back None')
        os.environ['ACCOUNTS_ENCRYPTION_KEY'] = old_key

        with sqlite3.connect(accounts.DB_PATH) as db:
            db.execute('UPDATE users SET disabled = 1 WHERE id = ?', (first['id'],))
        try:
            accounts.sign_in('github', 101, 'octo')
            check(False, 'a disabled account signed in')
        except accounts.AccountDisabled:
            pass
        check(accounts.get_user(first['id']) is None, 'get_user returns a disabled account')

        accounts.delete_user(first['id'])
        with sqlite3.connect(accounts.DB_PATH) as db:
            left = db.execute('SELECT COUNT(*) FROM api_keys WHERE user_id = ?',
                              (first['id'],)).fetchone()[0]
        check(left == 0, 'deleting an account left its keys behind')


def _run_tool(*argv, stdin=None):
    import contextlib
    import importlib.util
    import io
    spec = importlib.util.spec_from_file_location(
        'manage_accounts', os.path.join(os.path.dirname(__file__), '..', '..', 'scripts',
                                        'manage_accounts.py'))
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)
    out, err = io.StringIO(), io.StringIO()
    saved_stdin = sys.stdin
    sys.stdin = io.StringIO(stdin or '')
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = tool.main(list(argv))
    finally:
        sys.stdin = saved_stdin
    return code, out.getvalue(), err.getvalue()


def test_operator_tool():
    with Sandbox():
        user = accounts.sign_in('google', 'sub-1', 'Ada')
        accounts.sign_in('google', 'sub-2', 'Ada')
        accounts.save_key(user['id'], accounts.VIRUSTOTAL, VT_KEY)

        code, out, _ = _run_tool('list')
        check(code == 0 and out.count('Ada') == 2, 'list does not show both same-named accounts')
        check('sub-1' in out and 'sub-2' in out, 'list does not show the provider subject')
        check(VT_KEY not in out and VT_KEY[-4:] not in out, 'list leaks a saved key')
        check('virustotal' in out, 'list does not say which keys are saved')

        check(_run_tool('disable', str(user['id']))[0] == 0, 'disable failed')
        check(accounts.get_user(user['id']) is None, 'a disabled account is still served')
        try:
            accounts.sign_in('google', 'sub-1', 'Ada')
            check(False, 'a disabled account signed in')
        except accounts.AccountDisabled:
            pass
        check('disabled' in _run_tool('list')[1], 'list does not show the disabled state')
        check(accounts.load_key(user['id'], accounts.VIRUSTOTAL) == VT_KEY,
              'disabling removed the saved key')
        check(_run_tool('enable', str(user['id']))[0] == 0, 'enable failed')
        check(accounts.get_user(user['id']) is not None, 'an enabled account is not served')

        check(_run_tool('disable', '999')[0] == 2, 'a missing account did not exit 2')
        check(_run_tool('delete', str(user['id']), stdin='no\n')[0] == 3
              and accounts.get_user(user['id']) is not None, 'delete went ahead without yes')
        check(_run_tool('delete', str(user['id']), '--yes')[0] == 0
              and accounts.get_user(user['id']) is None, 'delete --yes did not delete')
        check(accounts.key_summary(user['id']) == {}, 'delete left the saved keys behind')


def test_users_own_copy_of_the_shared_key_uses_the_shared_limiter():
    with Sandbox(VIRUSTOTAL_API_KEY=VT_KEY):
        user = accounts.sign_in('github', 7, 'octo')
        accounts.save_key(user['id'], accounts.VIRUSTOTAL, VT_KEY)
        saved_current_user = accounts.current_user
        accounts.current_user = lambda: accounts.get_user(user['id'])
        try:
            key = accounts.virustotal_key()
        finally:
            accounts.current_user = saved_current_user
        check(key is not None and key.owner == 'shared',
              'the operator key saved by a user got its own limiter')


def test_database_files_are_private():
    with Sandbox():
        db = accounts.connect()
        try:
            db.execute("INSERT INTO users (provider, subject, login, created_at, last_login_at) "
                       "VALUES ('github', '1', 'a', 'now', 'now')")
            db.commit()
            for suffix in ('', '-wal', '-shm'):
                path = accounts.DB_PATH + suffix
                if os.path.exists(path):
                    mode = oct(os.stat(path).st_mode & 0o777)
                    check(mode == '0o600', f'{os.path.basename(path)} is {mode}, not 0o600')
        finally:
            db.close()


def test_signup_cap_holds_under_concurrency():
    import threading
    with Sandbox(ACCOUNTS_MAX_USERS='3'):
        barrier = threading.Barrier(10)
        outcomes = []

        def attempt(n):
            barrier.wait()
            try:
                accounts.sign_in('github', 1000 + n, f'user{n}')
                outcomes.append('in')
            except accounts.SignupClosed:
                outcomes.append('closed')

        threads = [threading.Thread(target=attempt, args=(n,)) for n in range(10)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        check(outcomes.count('in') == 3 and outcomes.count('closed') == 7,
              f'a cap of 3 gave {outcomes}')


def test_oauth_begin():
    with Sandbox():
        url, pending = oauth.begin('google', 'https://nexustrace.example/account/callback/google')
        query = parse_qs(urlparse(url).query)
        check(urlparse(url).netloc == 'accounts.google.com', 'Google URL has the wrong host')
        check(query['state'] == [pending['state']], 'the state is not in the URL')
        check(query['code_challenge_method'] == ['S256'] and 'verifier' in pending,
              'Google is not using PKCE')
        check(query['scope'] == ['openid profile'], 'Google asks for more than openid profile')
        check(pending['verifier'] not in url, 'the PKCE verifier is in the URL')

        url, pending = oauth.begin('github', 'https://nexustrace.example/account/callback/github')
        query = parse_qs(urlparse(url).query)
        check('scope' not in query, 'GitHub is asked for scopes')
        check(query['client_id'] == ['gh-id'], 'GitHub client ID missing')
        try:
            oauth.begin('gitlab', 'x')
            check(False, 'an unknown provider was accepted')
        except oauth.OAuthError:
            pass


def test_oauth_complete():
    redirect = 'https://nexustrace.example/account/callback/github'
    with Sandbox():
        _, pending = oauth.begin('github', redirect)
        good = {'state': pending['state'], 'code': 'abc'}

        fake = FakeProvider(profile={'id': 42, 'login': 'octo'})
        identity = oauth.complete('github', good, pending, redirect, transport=fake)
        check(identity == {'subject': '42', 'login': 'octo'}, f'GitHub identity: {identity}')
        check(fake.posts[0][1].get('client_secret') == 'gh-secret', 'the secret was not sent')

        for label, args, state in (
                ('a forged state', {'state': 'forged', 'code': 'abc'}, pending),
                ('no pending sign-in', good, None),
                ('a pending sign-in for another provider', good, dict(pending, provider='google')),
                ('a cancelled sign-in', {'error': 'access_denied', 'state': pending['state']}, pending),
                ('no code', {'state': pending['state']}, pending)):
            exploding = FakeProvider()
            try:
                oauth.complete('github', args, state, redirect, transport=exploding)
                check(False, f'{label} signed someone in')
            except oauth.OAuthError:
                check(not exploding.posts, f'{label} still exchanged the code')

        for label, fake in (('a refused token', FakeProvider(token={'error': 'bad_verification_code'})),
                            ('a failed profile', FakeProvider(profile_status=401)),
                            ('a profile with no ID', FakeProvider(profile={'login': 'x'})),
                            ('a token answer that is a list', FakeProvider(token=['x'])),
                            ('a profile that is a list', FakeProvider(profile=['x']))):
            try:
                oauth.complete('github', good, pending, redirect, transport=fake)
                check(False, f'{label} signed someone in')
            except oauth.OAuthError:
                pass

        _, gpending = oauth.begin('google', redirect)
        fake = FakeProvider(profile={'sub': '1234567890', 'name': 'Ada'})
        identity = oauth.complete('google', {'state': gpending['state'], 'code': 'c'},
                                  gpending, redirect, transport=fake)
        check(identity == {'subject': '1234567890', 'login': 'Ada'}, f'Google identity: {identity}')
        check(fake.posts[0][1].get('code_verifier') == gpending['verifier'],
              'the PKCE verifier was not sent to Google')


def test_key_policy():
    with Sandbox(VIRUSTOTAL_API_KEY='c' * 64) as box:
        app = box.app()
        user = accounts.sign_in('github', 7, 'octo')

        def resolve(signed_in, policy):
            os.environ['VIRUSTOTAL_SHARED_KEY'] = policy
            with app.test_request_context('/'):
                from flask import session
                if signed_in:
                    accounts.start_session(user)
                return accounts.virustotal_key()

        for policy, anonymous, member in (('everyone', 'shared', 'shared'),
                                          ('accounts', None, 'shared'),
                                          ('nobody', None, None),
                                          ('typo', None, None)):
            got = resolve(False, policy)
            check((got.owner if got else None) == anonymous,
                  f'{policy}: anonymous got {got!r}, wanted {anonymous}')
            got = resolve(True, policy)
            check((got.owner if got else None) == member,
                  f'{policy}: a member without a key got {got!r}, wanted {member}')

        accounts.save_key(user['id'], accounts.VIRUSTOTAL, VT_KEY)
        for policy in ('everyone', 'nobody'):
            got = resolve(True, policy)
            check(got == ProviderKey(VT_KEY, 'user') and got.owner == 'user',
                  f'{policy}: a member with a key did not get their own')

    with Sandbox(ACCOUNTS_ENCRYPTION_KEY=None, VIRUSTOTAL_API_KEY='c' * 64,
                 VIRUSTOTAL_SHARED_KEY='nobody') as box:
        with box.app().test_request_context('/'):
            got = accounts.virustotal_key()
        check(got is not None and got.owner == 'shared',
              'with accounts off, the shared key policy still applied')


def test_virustotal_quota_and_cache_per_key():
    calls = []

    def transport(url, headers=None, timeout=None):
        calls.append(headers['x-apikey'])
        return FakeResponse(404, {})

    saved_limiter = hash_service.virustotal_limiter
    try:
        hash_service._virustotal_report.cache_clear()
        hash_service._user_limiters.clear()
        hash_service.virustotal_limiter = RateLimiter(max_requests=1,
                                                      time_window=timedelta(minutes=1))
        hash_service.virustotal_limiter.try_acquire()

        shared = ProviderKey('c' * 64, 'shared')
        user = ProviderKey(VT_KEY, 'user')
        other = ProviderKey(OTHER_VT_KEY, 'user')
        check(hash_service.get_virustotal_report('1' * 64, transport, shared)['status']
              == 'rate_limited', 'the spent shared limiter let a lookup through')
        check(hash_service.get_virustotal_report('1' * 64, transport, user)['status']
              == 'not_found', 'a user key was throttled by the shared limiter')
        check(calls == [VT_KEY], f'the wrong key reached VirusTotal: {calls}')

        hash_service.get_virustotal_report('1' * 64, transport, other)
        check(calls == [VT_KEY, OTHER_VT_KEY],
              'a second user was served the first user\'s cached answer')
        check(hash_service.get_virustotal_report('1' * 64, transport, None) is None and
              len(calls) == 2, 'no key still reached VirusTotal or a cached answer')

        for _ in range(3):
            hash_service.get_virustotal_report(f'{_ + 2}' * 64, transport, user)
        check(hash_service.get_virustotal_report('9' * 64, transport, user)['status']
              == 'rate_limited', 'a user key is not held to 4 lookups a minute')
        check(hash_service.get_virustotal_report('9' * 64, transport, other)['status']
              == 'not_found', 'one user spent another user\'s quota')
    finally:
        hash_service.virustotal_limiter = saved_limiter
        hash_service._virustotal_report.cache_clear()
        hash_service._user_limiters.clear()

    report = hash_service.unknown_hash_report('1' * 64, {'virustotal_configured': True,
                                                          'sources': {}}, None)
    check(report['sources'][0]['state'] == 'unavailable',
          'a lookup made with a user key reports VirusTotal as skipped')
    report = hash_service.unknown_hash_report('1' * 64, {'virustotal_configured': False,
                                                          'sources': {}}, None)
    check(report['sources'][0]['state'] == 'skipped', 'a lookup with no key is not skipped')


def test_unknown_hash_report_without_hash_info_follows_the_key_policy():
    def vt_state(vt_key):
        report = hash_service.unknown_hash_report('1' * 64, None, None, vt_key=vt_key)
        return report['sources'][0]['state']

    with Sandbox(VIRUSTOTAL_API_KEY='c' * 64, VIRUSTOTAL_SHARED_KEY='nobody'):
        check(vt_state(None) == 'skipped',
              'a request with no usable key reports VirusTotal as queried')
        check(vt_state(accounts.ProviderKey('d' * 64, 'user')) == 'unavailable',
              "a request with the user's own key reports VirusTotal as skipped")
    with Sandbox(VIRUSTOTAL_API_KEY=None):
        check(vt_state(hash_service.SHARED_KEY) == 'skipped',
              'no shared key configured, yet VirusTotal reads as queried')


def test_warns_when_the_redirect_base_is_missing():
    import logging

    class Capture(logging.Handler):
        def __init__(self):
            super().__init__()
            self.messages = []

        def emit(self, record):
            self.messages.append(record.getMessage())

    def warnings_for(**env):
        handler = Capture()
        logging.getLogger('app').addHandler(handler)
        try:
            with Sandbox(**env) as box:
                box.app()
        finally:
            logging.getLogger('app').removeHandler(handler)
        return [m for m in handler.messages if 'OAUTH_REDIRECT_BASE' in m]

    check(warnings_for(OAUTH_REDIRECT_BASE=None), 'no warning with accounts on and no base')
    check(not warnings_for(), 'a warning with the base set')
    check(not warnings_for(OAUTH_REDIRECT_BASE=None, ACCOUNTS_ENCRYPTION_KEY=None),
          'a warning with accounts off')


def test_verify_virustotal_key():
    for status, want in ((200, 'ok'), (404, 'ok'), (401, 'invalid'), (403, 'invalid'),
                         (429, 'unavailable'), (500, 'unavailable')):
        got = hash_service.verify_virustotal_key(VT_KEY, lambda *a, **k: FakeResponse(status, {}))
        check(got == want, f'HTTP {status} read as {got}, wanted {want}')

    seen = []
    hash_service.verify_virustotal_key(
        VT_KEY, lambda url, **k: seen.append((url, k)) or FakeResponse(404, {}))
    check(VT_KEY not in seen[0][0], 'the key is in the request URL')
    check(seen[0][1]['headers'] == {'x-apikey': VT_KEY}, 'the key is not sent as a header')


def test_routes():
    with Sandbox(ACCOUNTS_ENCRYPTION_KEY=None) as box:
        client = box.app().test_client()
        check(client.get('/account').status_code == 404, '/account is served with accounts off')
        check(b'/account' not in client.get('/').data, 'the nav links to accounts while off')

    with Sandbox() as box:
        app = box.app()
        client = app.test_client()
        page = client.get('/account')
        check(page.status_code == 200 and b'Continue with GitHub' in page.data,
              'the sign-in page is missing')

        start = client.get('/account/login/github')
        query = parse_qs(urlparse(start.headers['Location']).query)
        check(start.status_code == 302 and query['redirect_uri'] ==
              ['https://nexustrace.example/account/callback/github'],
              f'login redirect: {start.status_code} {start.headers.get("Location")}')

        saved_requests = oauth.requests
        oauth.requests = FakeProvider(profile={'id': 42, 'login': 'octo'})
        try:
            forged = client.get('/account/callback/github?state=forged&code=x')
            check(forged.status_code == 302, 'a forged callback did not bounce')
            check(b'octo' not in client.get('/account').data, 'a forged callback signed in')

            client.get('/account/login/github')
            with client.session_transaction() as session:
                state = session['oauth_pending']['state']
            done = client.get(f'/account/callback/github?state={state}&code=x')
            check(done.status_code == 303, f'callback status {done.status_code}')
            with client.session_transaction() as session:
                check('oauth_pending' not in session, 'the OAuth state outlived the sign-in')
            page = client.get('/account')
            check(b'octo' in page.data and b'Check and save' in page.data,
                  'the account page did not render after sign-in')
        finally:
            oauth.requests = saved_requests

        client.post('/account/keys/virustotal', data={'api_key': 'too-short'})
        check(not accounts.key_summary(1), 'a malformed key was saved')

        from app.routes import account_routes
        saved_verify = account_routes.verify_virustotal_key
        try:
            account_routes.verify_virustotal_key = lambda value: 'invalid'
            client.post('/account/keys/virustotal', data={'api_key': VT_KEY})
            check(not accounts.key_summary(1), 'a key VirusTotal rejected was saved')

            account_routes.verify_virustotal_key = lambda value: 'ok'
            client.post('/account/keys/virustotal', data={'api_key': VT_KEY.upper()})
            check(accounts.load_key(1, accounts.VIRUSTOTAL) == VT_KEY, 'the key was not saved')
            page = client.get('/account')
            check(VT_KEY.encode() not in page.data, 'the account page shows the saved key')
            check(VT_KEY[-4:].encode() in page.data, 'the account page lacks the key hint')
        finally:
            account_routes.verify_virustotal_key = saved_verify

        client.post('/account/keys/virustotal/delete')
        check(not accounts.key_summary(1), 'removing the key did not remove it')

        checked = []
        try:
            account_routes.verify_virustotal_key = lambda value: checked.append(value) or 'invalid'
            for _ in range(8):
                client.post('/account/keys/virustotal', data={'api_key': OTHER_VT_KEY})
            check(len(checked) == 3, f'{len(checked)} keys checked; the cap is 5 per 15 minutes '
                  'and 2 were already used')
        finally:
            account_routes.verify_virustotal_key = saved_verify

        check(app.permanent_session_lifetime.total_seconds() == 24 * 60 * 60,
              'the signed-in session cookie does not last 24 hours')
        import time
        with client.session_transaction() as session:
            signed_in_at = session[accounts.SIGNED_IN_AT_KEY]
            session[accounts.SIGNED_IN_AT_KEY] = time.time() - 23 * 60 * 60
        check(b'Check and save' in client.get('/account').data,
              'a 23-hour-old sign-in was ended early')
        with client.session_transaction() as session:
            session[accounts.SIGNED_IN_AT_KEY] = time.time() - 24 * 60 * 60 - 1
        check(b'Continue with GitHub' in client.get('/account').data,
              'a sign-in older than 24 hours was still accepted')
        with client.session_transaction() as session:
            session[accounts.SESSION_KEY] = 1
            session.pop(accounts.SIGNED_IN_AT_KEY, None)
        check(b'Continue with GitHub' in client.get('/account').data,
              'a session with no sign-in time (issued before the limit) was accepted')
        with client.session_transaction() as session:
            session[accounts.SESSION_KEY] = 1
            session[accounts.SIGNED_IN_AT_KEY] = signed_in_at

        client.post('/account/logout')
        check(b'Continue with GitHub' in client.get('/account').data, 'sign-out did not sign out')

        anonymous = app.test_client()
        anonymous.post('/account/keys/virustotal', data={'api_key': VT_KEY})
        check(accounts.load_key(1, accounts.VIRUSTOTAL) is None,
              'a signed-out visitor saved a key')


TESTS = [
    test_provider_key_never_shows_the_key,
    test_accounts_are_off_without_configuration,
    test_store,
    test_operator_tool,
    test_users_own_copy_of_the_shared_key_uses_the_shared_limiter,
    test_database_files_are_private,
    test_signup_cap_holds_under_concurrency,
    test_oauth_begin,
    test_oauth_complete,
    test_key_policy,
    test_virustotal_quota_and_cache_per_key,
    test_unknown_hash_report_without_hash_info_follows_the_key_policy,
    test_warns_when_the_redirect_base_is_missing,
    test_verify_virustotal_key,
    test_routes,
]


def main():
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - an escaping exception IS a failure
            import traceback
            failures.append(f'{test.__name__} raised {exc!r}\n'
                            + ''.join(traceback.format_tb(exc.__traceback__)))
    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} account cases')


if __name__ == '__main__':
    main()
