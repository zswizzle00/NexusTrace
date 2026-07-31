"""Tests for the NEXUSTRACE_ROLE split that keeps /admin off the public process.

The property under test is absence, not refusal: on the public role there must be no
/admin rule in the url_map, so nothing exists to probe or get wrong. A 404 is a weaker
claim than the routing table having no such rule, so both are asserted and the url_map
assertion is the one that matters.

The /admin rules are matched here by open-coded string comparison rather than by calling
app.routes.admin_rules(), on purpose: create_app()'s startup guard uses that helper, and
a test sharing the helper would share its bugs.

No network, no browser, no real data/: activity.ACTIVITY_DIR and storage.LOCAL_ROOT are
repointed at a temp tree for every case.
"""
import json
import os
import shutil
import sys
import tempfile
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from werkzeug.exceptions import NotFound

from app import create_app
from app.routes import (ENV_ROLE, ROLE_ADMIN, ROLE_PUBLIC, admin_rules,
                        resolve_role)
from app.utils import activity, storage

RIGHT_TOKEN = 'correct-horse-battery-staple'
WRONG_TOKEN = 'correct-horse-battery-stapl3'
ADMIN_EMAILS = 'owner@example.com, analyst@example.com'

ADMIN_REQUESTS = (('get', '/admin'), ('post', '/admin'), ('post', '/admin/logout'))

PUBLIC_PAGES = ('/', '/ip_search', '/url_scan', '/hash_analysis', '/file_analysis',
                '/email_analysis', '/user_agent_search', '/ad_event_search',
                '/azure_error_search', '/api/health')

DELETE_ENDPOINTS = (
    ('/url_scan/<scan_id>/delete', 'scan.url_scan_delete_confirm', 'scan.url_scan_delete'),
    ('/email_analysis/<analysis_id>/delete', 'email.email_analysis_delete_confirm',
     'email.email_analysis_delete'),
)

failures = []
cases = 0


def check(condition, message):
    if not condition:
        failures.append(message)
    return bool(condition)


def case(condition, message):
    global cases
    cases += 1
    return check(condition, message)


class Sandbox:
    """Fresh activity dir + storage root + a clean role/admin env, all restored."""

    def __enter__(self):
        self.previous_activity = activity.ACTIVITY_DIR
        self.previous_root = storage.LOCAL_ROOT
        self.previous_env = {name: os.environ.get(name) for name in
                             (ENV_ROLE, 'ADMIN_TOKEN', 'ADMIN_EMAILS',
                              'CF_ACCESS_TEAM_DOMAIN', 'CF_ACCESS_AUD')}
        self.dir = tempfile.mkdtemp(prefix='nt-role-')
        activity.ACTIVITY_DIR = os.path.join(self.dir, 'activity')
        activity.reset_state()
        storage.LOCAL_ROOT = os.path.join(self.dir, 'data')
        storage.reset_cache()
        set_env(**{name: None for name in self.previous_env})
        return self

    def __exit__(self, *exc):
        activity.ACTIVITY_DIR = self.previous_activity
        activity.reset_state()
        storage.LOCAL_ROOT = self.previous_root
        storage.reset_cache()
        set_env(**self.previous_env)
        shutil.rmtree(self.dir, ignore_errors=True)
        return False

    def seed_scan(self):
        scan_id = str(uuid.uuid4())
        storage.store('scans').write_text(
            f'{scan_id}.json',
            json.dumps({'id': scan_id, 'url': 'https://example.com/',
                        'status': 'done', 'created_at': '2026-07-29T00:00:00Z'}))
        return scan_id

    def seed_analysis(self):
        analysis_id = str(uuid.uuid4())
        storage.store('analyses').write_text(
            f'{analysis_id}.json',
            json.dumps({'id': analysis_id, 'created_at': '2026-07-29T00:00:00Z',
                        'headers': {'subject': 'Invoice attached'},
                        'verdict': {'level': 'suspicious', 'score': 0.4, 'signals': []}}))
        return analysis_id


def set_env(**values):
    for name, value in values.items():
        if value:
            os.environ[name] = value
        else:
            os.environ.pop(name, None)


def build(role=None, token=None, emails=None):
    set_env(**{ENV_ROLE: role, 'ADMIN_TOKEN': token, 'ADMIN_EMAILS': emails})
    app = create_app()
    app.config['WTF_CSRF_ENABLED'] = False
    return app


def rule_paths(app):
    return {str(rule) for rule in app.url_map.iter_rules()}


def admin_paths(app):
    return {path for path in rule_paths(app)
            if path == '/admin' or path.startswith('/admin/')}


def matched_endpoint(app, path, method='GET'):
    """Distinguishes "no such rule" from "the handler chose to 404", which a status
    code alone cannot do. None means nothing in the url_map matched."""
    try:
        return app.url_map.bind('localhost').match(path, method=method)[0]
    except NotFound:
        return None
    except Exception:
        return None


def test_resolve_role_defaults_to_public():
    for label, env in (('unset', {}),
                       ('empty', {ENV_ROLE: ''}),
                       ('whitespace', {ENV_ROLE: '   '})):
        case(resolve_role(env) == ROLE_PUBLIC,
             f'a {label} {ENV_ROLE} did not resolve to {ROLE_PUBLIC!r}')

    for raw, expected in (('public', ROLE_PUBLIC), ('PUBLIC', ROLE_PUBLIC),
                          (' Public ', ROLE_PUBLIC), ('admin', ROLE_ADMIN),
                          ('ADMIN', ROLE_ADMIN), ('  Admin\n', ROLE_ADMIN)):
        case(resolve_role({ENV_ROLE: raw}) == expected,
             f'{ENV_ROLE}={raw!r} resolved to {resolve_role({ENV_ROLE: raw})!r}, '
             f'expected {expected!r}')


def test_bogus_role_raises_rather_than_defaulting():
    bogus = ['adminn', 'admn', 'Administrator', 'root', 'pubic', 'public,admin',
             'admin;public', '1', 'true', 'none', 'default', 'admin ui']
    for raw in bogus:
        try:
            resolved = resolve_role({ENV_ROLE: raw})
        except ValueError as exc:
            case(ENV_ROLE in str(exc),
                 f'the error for {raw!r} does not name {ENV_ROLE}: {exc}')
            continue
        case(False, f'{ENV_ROLE}={raw!r} silently resolved to {resolved!r} instead of '
                    'refusing to start')


def test_bogus_role_fails_app_startup():
    with Sandbox():
        for raw in ('adminn', 'Administrator', 'true'):
            set_env(**{ENV_ROLE: raw})
            try:
                create_app()
            except ValueError as exc:
                case(ENV_ROLE in str(exc),
                     f'create_app() refused {raw!r} without naming {ENV_ROLE}: {exc}')
                continue
            case(False, f'create_app() started with {ENV_ROLE}={raw!r} instead of '
                        'refusing')


def test_public_role_has_no_admin_rule():
    for label, role in (('unset', None), ('=public', ROLE_PUBLIC),
                        ('=PUBLIC', 'PUBLIC')):
        with Sandbox():
            # Configured credentials are the real assertion here: a token must not
            # resurrect a route that was never registered.
            app = build(role=role, token=RIGHT_TOKEN, emails=ADMIN_EMAILS)

            found = admin_paths(app)
            case(found == set(),
                 f'{ENV_ROLE} {label}: url_map carries admin rules {sorted(found)}')
            case('admin' not in app.blueprints,
                 f'{ENV_ROLE} {label}: the admin blueprint is registered')
            endpoints = {rule.endpoint for rule in app.url_map.iter_rules()}
            case(not any(name.startswith('admin.') for name in endpoints),
                 f'{ENV_ROLE} {label}: admin.* endpoints exist')
            case(app.config['NEXUSTRACE_ROLE'] == ROLE_PUBLIC,
                 f'{ENV_ROLE} {label}: role recorded as '
                 f'{app.config["NEXUSTRACE_ROLE"]!r}')

            for method, path in ADMIN_REQUESTS:
                case(matched_endpoint(app, path, method.upper()) is None,
                     f'{ENV_ROLE} {label}: {method.upper()} {path} still resolves to a '
                     'rule, so the 404 comes from a handler rather than from absence')

            client = app.test_client()
            for method, path in ADMIN_REQUESTS:
                response = getattr(client, method)(path)
                case(response.status_code == 404,
                     f'{ENV_ROLE} {label}: {method.upper()} {path} returned '
                     f'{response.status_code}, expected 404')
                body = response.data.decode('utf-8', 'replace')
                case('Admin token' not in body and 'Last 24 hours' not in body,
                     f'{ENV_ROLE} {label}: {method.upper()} {path} leaked the panel')

            for headers in ({'X-Admin-Token': RIGHT_TOKEN},
                            {'Cf-Access-Authenticated-User-Email': 'owner@example.com'}):
                response = app.test_client().get('/admin', headers=headers)
                case(response.status_code == 404,
                     f'{ENV_ROLE} {label}: a credentialed GET /admin returned '
                     f'{response.status_code}, expected 404')
            response = app.test_client().post('/admin', data={'token': RIGHT_TOKEN})
            case(response.status_code == 404,
                 f'{ENV_ROLE} {label}: a form login returned {response.status_code}, '
                 'expected 404')


def test_building_the_admin_app_does_not_leak_into_a_public_app():
    """Importing admin_routes is a one-time module load. Once the admin role has done it
    in this process, a public app built afterwards must still have no admin rule."""
    with Sandbox():
        admin_app = build(role=ROLE_ADMIN, token=RIGHT_TOKEN)
        case('/admin' in rule_paths(admin_app),
             'the admin role did not register /admin, so this case proves nothing')

        public_app = build(role=ROLE_PUBLIC, token=RIGHT_TOKEN)
        found = admin_paths(public_app)
        case(found == set(),
             f'a public app built after an admin app carries admin rules {sorted(found)}')
        case(public_app.test_client().get('/admin').status_code == 404,
             'a public app built after an admin app answered GET /admin')


def test_startup_guard_detects_a_smuggled_admin_route():
    """The invariant create_app() checks. A rogue rule added after the fact stands in for
    a future admin route attached to some other blueprint."""
    with Sandbox():
        app = build(role=ROLE_PUBLIC)
        case(admin_rules(app) == [], 'a clean public app already reports admin rules')

        app.add_url_rule('/admin/secret', 'rogue_admin', lambda: 'x')
        case(admin_rules(app) == ['/admin/secret'],
             f'the guard did not see a smuggled rule: {admin_rules(app)}')


def test_startup_guard_refuses_to_start_the_public_app():
    """And the guard is wired: a public build that somehow gains an admin rule must
    raise out of create_app() rather than serve it."""
    import app.routes as routes_module

    with Sandbox():
        set_env(**{ENV_ROLE: ROLE_PUBLIC})
        real = routes_module.register_routes

        def register_with_a_rogue_admin_route(flask_app):
            real(flask_app)
            flask_app.add_url_rule('/admin/secret', 'rogue_admin', lambda: 'x')

        routes_module.register_routes = register_with_a_rogue_admin_route
        try:
            create_app()
        except RuntimeError as exc:
            case('/admin/secret' in str(exc),
                 f'the startup guard raised without naming the rule: {exc}')
        else:
            case(False, 'the public app started with an /admin rule registered')
        finally:
            routes_module.register_routes = real

        set_env(**{ENV_ROLE: ROLE_ADMIN, 'ADMIN_TOKEN': RIGHT_TOKEN})
        routes_module.register_routes = register_with_a_rogue_admin_route
        try:
            admin_app = create_app()
            case('/admin/secret' in rule_paths(admin_app),
                 'the admin role dropped the extra admin rule')
        except RuntimeError as exc:
            case(False, f'the guard fired on the admin role: {exc}')
        finally:
            routes_module.register_routes = real


def test_admin_role_registers_the_admin_surface():
    with Sandbox():
        app = build(role=ROLE_ADMIN, token=RIGHT_TOKEN)
        case(admin_paths(app) == {'/admin', '/admin/logout'},
             f'the admin role registered {sorted(admin_paths(app))}')
        case(app.config['NEXUSTRACE_ROLE'] == ROLE_ADMIN,
             f'role recorded as {app.config["NEXUSTRACE_ROLE"]!r}')
        for method, path in ADMIN_REQUESTS:
            case(matched_endpoint(app, path, method.upper()) is not None,
                 f'{method.upper()} {path} does not resolve on the admin role')


def test_admin_role_also_registers_the_public_blueprints():
    """templates/admin.html extends base.html, and create_app()'s CSRFError handler
    redirects to url_for('home.home'), so the admin process needs the public routes."""
    with Sandbox():
        app = build(role=ROLE_ADMIN, token=RIGHT_TOKEN)
        paths = rule_paths(app)
        missing = [path for path in PUBLIC_PAGES if path not in paths]
        case(not missing, f'the admin role is missing public rules {missing}')

        client = app.test_client()
        for path in PUBLIC_PAGES:
            response = client.get(path)
            case(response.status_code == 200,
                 f'admin role: GET {path} returned {response.status_code}, expected 200')

        with app.test_request_context('/admin'):
            from flask import url_for
            case(url_for('home.home') == '/',
                 'url_for("home.home") does not build on the admin role')


def test_admin_role_auth_is_unchanged():
    with Sandbox():
        app = build(role=ROLE_ADMIN)
        case(app.test_client().get('/admin').status_code == 404,
             'an unconfigured /admin did not 404 on the admin role')
        case(matched_endpoint(app, '/admin') == 'admin.admin_dashboard',
             'the unconfigured 404 came from routing rather than from the handler')

    with Sandbox():
        app = build(role=ROLE_ADMIN, token=RIGHT_TOKEN)
        client = app.test_client()
        case(client.get('/admin').status_code == 403,
             'an anonymous GET /admin was not 403 on the admin role')
        case(client.get('/admin', headers={'X-Admin-Token': WRONG_TOKEN}).status_code == 403,
             'a wrong header token was not 403')
        case(client.get('/admin', headers={'X-Admin-Token': RIGHT_TOKEN}).status_code == 200,
             'the right header token was not accepted on the admin role')
        case(client.get(f'/admin?token={RIGHT_TOKEN}').status_code == 403,
             'a query-string token was accepted')
        case(client.post('/admin', data={'token': RIGHT_TOKEN}).status_code == 303,
             'the token sign-in form did not work on the admin role')

    with Sandbox():
        app = build(role=ROLE_ADMIN, emails=ADMIN_EMAILS)
        response = app.test_client().get(
            '/admin', headers={'Cf-Access-Authenticated-User-Email': 'owner@example.com'})
        case(response.status_code == 403,
             f'the plaintext Access header authorized /admin ({response.status_code})')


def test_public_role_serves_the_public_pages():
    with Sandbox():
        app = build(role=ROLE_PUBLIC)
        client = app.test_client()
        for path in PUBLIC_PAGES:
            response = client.get(path)
            case(response.status_code == 200,
                 f'public role: GET {path} returned {response.status_code}, expected 200')


def test_public_role_still_serves_the_delete_endpoints():
    """User-facing erasure lives in the scan and e-mail blueprints, not the admin one,
    and must survive the split."""
    with Sandbox() as box:
        app = build(role=ROLE_PUBLIC)
        paths = rule_paths(app)
        for rule, confirm_endpoint, delete_endpoint in DELETE_ENDPOINTS:
            case(rule in paths, f'public role lost the delete rule {rule}')
            live = rule.replace('<scan_id>', 'x').replace('<analysis_id>', 'x')
            case(matched_endpoint(app, live, 'GET') == confirm_endpoint,
                 f'GET {live} resolves to {matched_endpoint(app, live, "GET")!r}, '
                 f'expected {confirm_endpoint!r}')
            case(matched_endpoint(app, live, 'POST') == delete_endpoint,
                 f'POST {live} resolves to {matched_endpoint(app, live, "POST")!r}, '
                 f'expected {delete_endpoint!r}')

        # Served, not merely routed: a seeded record renders its confirmation page and
        # the POST actually erases it.
        client = app.test_client()

        scan_id = box.seed_scan()
        response = client.get(f'/url_scan/{scan_id}/delete')
        case(response.status_code == 200,
             f'public role: the scan delete confirmation returned {response.status_code}')
        case(b'example.com' in response.data,
             'the scan delete confirmation did not render the record')
        case(client.post(f'/url_scan/{scan_id}/delete').status_code == 302,
             'public role: deleting a scan did not redirect')
        case(storage.store('scans').read_text(f'{scan_id}.json') is None,
             'public role: the scan record survived its delete')

        analysis_id = box.seed_analysis()
        response = client.get(f'/email_analysis/{analysis_id}/delete')
        case(response.status_code == 200,
             'public role: the e-mail delete confirmation returned '
             f'{response.status_code}')
        case(client.post(f'/email_analysis/{analysis_id}/delete').status_code == 302,
             'public role: deleting an e-mail analysis did not redirect')
        case(storage.store('analyses').read_text(f'{analysis_id}.json') is None,
             'public role: the analysis record survived its delete')


TESTS = [
    test_resolve_role_defaults_to_public,
    test_bogus_role_raises_rather_than_defaulting,
    test_bogus_role_fails_app_startup,
    test_public_role_has_no_admin_rule,
    test_building_the_admin_app_does_not_leak_into_a_public_app,
    test_startup_guard_detects_a_smuggled_admin_route,
    test_startup_guard_refuses_to_start_the_public_app,
    test_admin_role_registers_the_admin_surface,
    test_admin_role_also_registers_the_public_blueprints,
    test_admin_role_auth_is_unchanged,
    test_public_role_serves_the_public_pages,
    test_public_role_still_serves_the_delete_endpoints,
]


def main():
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - an escaping exception IS a failure
            import traceback
            failures.append(f'{test.__name__} raised {exc!r}\n'
                            + ''.join(traceback.format_tb(exc.__traceback__)))
    set_env(**{ENV_ROLE: None, 'ADMIN_TOKEN': None, 'ADMIN_EMAILS': None})

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} role-split cases')


if __name__ == '__main__':
    main()
