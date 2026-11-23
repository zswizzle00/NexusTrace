"""Tests for the operator console on the admin role: the LAN-only network guard, the
pages behind sign-in, account actions, and the admin session cookie.

No network and no real data/: activity, storage and the accounts database are repointed
at a temp tree for every case.
"""
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app import create_app
from app.utils import accounts, activity, storage

RIGHT_TOKEN = 'correct-horse-battery-staple'
SECRET_VALUE = 'abuseipdb-secret-value-0123456789'
TOKEN_HEADER = {'X-Admin-Token': RIGHT_TOKEN}

failures = []
cases = 0


def case(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


def set_env(**values):
    for name, value in values.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


class Sandbox:
    """Admin role with a token, temp data directories, and no Cloudflare Access."""

    def __init__(self, **env):
        self.env = {'NEXUSTRACE_ROLE': 'admin', 'ADMIN_TOKEN': RIGHT_TOKEN,
                    'ADMIN_EMAILS': None, 'CF_ACCESS_TEAM_DOMAIN': None,
                    'CF_ACCESS_AUD': None, 'ADMIN_NETWORKS': None, **env}

    def __enter__(self):
        self.saved_env = {name: os.environ.get(name) for name in self.env}
        set_env(**self.env)
        self.dir = tempfile.mkdtemp(prefix='nt-admin-')
        self.saved = (activity.ACTIVITY_DIR, storage.LOCAL_ROOT, accounts.DB_PATH)
        activity.ACTIVITY_DIR = os.path.join(self.dir, 'activity')
        storage.LOCAL_ROOT = Path(self.dir) / 'data'
        storage.reset_cache()
        accounts.DB_PATH = os.path.join(self.dir, 'accounts.db')
        activity.reset_state()
        return self

    def __exit__(self, *exc):
        activity.ACTIVITY_DIR, storage.LOCAL_ROOT, accounts.DB_PATH = self.saved
        storage.reset_cache()
        activity.reset_state()
        set_env(**self.saved_env)
        shutil.rmtree(self.dir, ignore_errors=True)
        return False


def client():
    app = create_app()
    app.config['WTF_CSRF_ENABLED'] = False
    return app.test_client()


def get(path, remote='127.0.0.1', headers=None):
    return client().get(path, headers=headers or {}, environ_base={'REMOTE_ADDR': remote})


def test_direct_lan_requests_reach_the_console():
    with Sandbox():
        case(get('/admin', headers=TOKEN_HEADER).status_code == 200,
             'a direct loopback request with the token was not served')
        case(get('/admin', remote='192.168.1.41').status_code == 403,
             'a LAN address did not get the sign-in page')
        case(get('/admin', remote='100.100.1.10').status_code == 403,
             'a Tailscale address did not get the sign-in page')
        case(get('/admin', remote='fd7a:115c:a1e0::1').status_code == 403,
             'a Tailscale IPv6 address did not get the sign-in page')


def test_anything_else_gets_a_404():
    with Sandbox():
        case(get('/admin', remote='203.0.113.9', headers=TOKEN_HEADER).status_code == 404,
             'a public address reached the console')
        case(get('/admin', headers={**TOKEN_HEADER, 'X-Forwarded-For': '10.0.0.5'}).status_code == 404,
             'a proxied request (X-Forwarded-For) reached the console')
        case(get('/admin', headers={**TOKEN_HEADER, 'CF-Ray': '8a1b2c3d4e5f-LAX'}).status_code == 404,
             'a request through Cloudflare (CF-Ray) reached the console')
        case(get('/admin', headers={**TOKEN_HEADER, 'CF-Connecting-IP': '198.51.100.4'}).status_code == 404,
             'a request through Cloudflare (CF-Connecting-IP) reached the console')
        # ProxyFix would turn this into remote_addr 10.0.0.5; the guard must not believe it.
        spoofed = get('/admin', remote='203.0.113.9',
                      headers={**TOKEN_HEADER, 'X-Forwarded-For': '10.0.0.5'})
        case(spoofed.status_code == 404, 'a spoofed X-Forwarded-For let a public peer in')
        case(b'Admin' not in get('/admin', remote='203.0.113.9').data,
             'the 404 for a public address mentions the console')


def test_admin_networks_narrows_the_allow_list():
    with Sandbox(ADMIN_NETWORKS='192.168.1.0/24'):
        case(get('/admin', remote='192.168.1.41').status_code == 403,
             'an address inside ADMIN_NETWORKS was refused')
        case(get('/admin', remote='100.100.1.10').status_code == 404,
             'an address outside ADMIN_NETWORKS was let through')


def test_every_page_needs_sign_in():
    with Sandbox():
        for path in ('/admin', '/admin/accounts', '/admin/sources', '/admin/system'):
            anonymous = get(path)
            case(anonymous.status_code == 403, f'anonymous GET {path} returned {anonymous.status_code}')
            case(b'Configuration' not in anonymous.data and b'Stored data' not in anonymous.data,
                 f'anonymous GET {path} leaked console content')
            signed_in = get(path, headers=TOKEN_HEADER)
            case(signed_in.status_code == 200, f'signed-in GET {path} returned {signed_in.status_code}')
        storage.store('analyses').write_text('sample.json', '{}')
        system = get('/admin/system', headers=TOKEN_HEADER).get_data(as_text=True)
        case('Could not be read' not in system, 'the system page could not list a store')


def test_sources_never_show_a_key():
    with Sandbox(ABUSEIPDB_KEY=SECRET_VALUE):
        body = get('/admin/sources', headers=TOKEN_HEADER).get_data(as_text=True)
        case('ABUSEIPDB_KEY' in body and 'configured' in body,
             'the sources page did not report AbuseIPDB as configured')
        case(SECRET_VALUE not in body, 'the sources page shows an API key value')
    set_env(ABUSEIPDB_KEY=None)


def test_account_actions():
    with Sandbox():
        user = accounts.sign_in('github', '583231', 'octocat')
        test_client = client()

        def act(action, **form):
            return test_client.post(f'/admin/accounts/{user["id"]}/{action}', headers=TOKEN_HEADER,
                                    data=form, environ_base={'REMOTE_ADDR': '127.0.0.1'})

        page = test_client.get('/admin/accounts', headers=TOKEN_HEADER,
                               environ_base={'REMOTE_ADDR': '127.0.0.1'}).get_data(as_text=True)
        case('octocat' in page, 'the accounts page does not list the account')

        case(act('disable').status_code == 303, 'disable did not redirect')
        case(accounts.get_user(user['id']) is None, 'disable left the account enabled')
        act('enable')
        case(accounts.get_user(user['id']) is not None, 'enable left the account disabled')

        act('delete', confirm='999')
        case(accounts.get_user(user['id']) is not None, 'delete ran without the right confirmation')
        act('delete', confirm=str(user['id']))
        case(not accounts.list_users(), 'a confirmed delete left the account')

        case(act('promote').status_code == 404, 'an unknown action was not a 404')
        anonymous = test_client.post(f'/admin/accounts/{user["id"]}/disable',
                                     environ_base={'REMOTE_ADDR': '127.0.0.1'})
        case(anonymous.status_code == 403, 'an anonymous account action was not refused')


def test_accounts_page_does_not_create_a_database():
    with Sandbox():
        case(get('/admin/accounts', headers=TOKEN_HEADER).status_code == 200,
             'the accounts page failed without a database')
        case(not os.path.exists(accounts.DB_PATH), 'viewing the accounts page created accounts.db')


def test_admin_cookie_is_its_own():
    with Sandbox(SECURE_COOKIES='true'):
        admin_app = create_app()
        case(admin_app.config['SESSION_COOKIE_NAME'] == 'nexustrace_admin',
             'the admin role shares the public session cookie name')
        case(admin_app.config['SESSION_COOKIE_SECURE'] is False,
             'the admin cookie is HTTPS-only, so plain-HTTP LAN sign-in would fail')
    with Sandbox(SECURE_COOKIES='true', ADMIN_SECURE_COOKIES='true'):
        case(create_app().config['SESSION_COOKIE_SECURE'] is True,
             'ADMIN_SECURE_COOKIES=true did not make the admin cookie HTTPS-only')
    with Sandbox(NEXUSTRACE_ROLE='public', SECURE_COOKIES='true'):
        public_app = create_app()
        case(public_app.config['SESSION_COOKIE_NAME'] == 'session',
             'the public role changed its cookie name')
        case(public_app.config['SESSION_COOKIE_SECURE'] is True,
             'the public role stopped honouring SECURE_COOKIES')
    set_env(SECURE_COOKIES=None, ADMIN_SECURE_COOKIES=None)


TESTS = [
    test_direct_lan_requests_reach_the_console,
    test_anything_else_gets_a_404,
    test_admin_networks_narrows_the_allow_list,
    test_every_page_needs_sign_in,
    test_sources_never_show_a_key,
    test_account_actions,
    test_accounts_page_does_not_create_a_database,
    test_admin_cookie_is_its_own,
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
    print(f'PASS: {cases} admin console cases')


if __name__ == '__main__':
    main()
