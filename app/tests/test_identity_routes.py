"""Route-level cases for the identity scan surface.

The absence case is the point: there is no listing route, by requirement. The e-mail and
scanner listings were removed precisely because anyone could browse other people's
submissions, and this surface enumerates a named person's accounts, so it must not
reintroduce the pattern.

No vendor engine runs: run_identity_scan is patched.
"""
import json
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app import create_app
from app.routes import identity_routes
from app.utils import activity, storage

failures = []
cases = 0


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


class Sandbox:
    def __enter__(self):
        self.previous_activity = activity.ACTIVITY_DIR
        self.previous_root = storage.LOCAL_ROOT
        self.dir = tempfile.mkdtemp(prefix='nt-identity-')
        activity.ACTIVITY_DIR = os.path.join(self.dir, 'activity')
        activity.reset_state()
        storage.LOCAL_ROOT = os.path.join(self.dir, 'data')
        storage.reset_cache()
        return self

    def __exit__(self, *exc):
        activity.ACTIVITY_DIR = self.previous_activity
        activity.reset_state()
        storage.LOCAL_ROOT = self.previous_root
        storage.reset_cache()
        shutil.rmtree(self.dir, ignore_errors=True)
        return False

    def seed(self, scan_id='11111111-1111-1111-1111-111111111111'):
        storage.store('identity').write_text(f'{scan_id}.json', json.dumps({
            'id': scan_id, 'target': 'alice', 'mode': 'username',
            'created_at': '2026-09-21T00:00:00Z', 'timed_out': False, 'error': None,
            'findings': [{'site': 'GitHub', 'url': 'https://github.com/alice',
                          'status': 'found', 'engines': ['sherlock', 'user-scanner'],
                          'category': 'dev', 'metadata': {}, 'reason': None}],
            'engines': {'sherlock': 'ok', 'user-scanner': 'ok'},
            'breach': None,
            'summary': {'checked': 1, 'found': 1, 'corroborated': 1, 'blocked': 0,
                        'unknown': 0},
        }))
        return scan_id

    def seed_record(self, scan_id, findings, summary=None):
        storage.store('identity').write_text(f'{scan_id}.json', json.dumps({
            'id': scan_id, 'target': 'alice', 'mode': 'username',
            'created_at': '2026-09-21T00:00:00Z', 'timed_out': False, 'error': None,
            'findings': findings,
            'engines': {'sherlock': 'ok', 'user-scanner': 'ok'},
            'breach': None,
            'summary': summary or {'checked': len(findings), 'found': 0,
                                   'corroborated': 0, 'blocked': 0, 'unknown': 0},
        }))
        return scan_id


def build():
    app = create_app()
    app.config['WTF_CSRF_ENABLED'] = False
    return app


def test_form_renders():
    with Sandbox():
        response = build().test_client().get('/identity_scan')
        check(response.status_code == 200,
              f'GET /identity_scan returned {response.status_code}')


def test_result_renders_and_shows_corroboration():
    with Sandbox() as box:
        scan_id = box.seed()
        response = build().test_client().get(f'/identity_scan/{scan_id}')
        body = response.get_data(as_text=True)
        check(response.status_code == 200,
              f'GET /identity_scan/<id> returned {response.status_code}')
        check('GitHub' in body, 'the result page does not render its finding')


def test_bad_id_is_404_not_500():
    with Sandbox():
        client = build().test_client()
        for bad in ('../../etc/passwd', 'nope', 'a' * 300):
            status = client.get(f'/identity_scan/{bad}').status_code
            check(status == 404, f'GET /identity_scan/{bad[:20]} returned {status}')


def test_there_is_no_listing_route():
    """A requirement, not an omission."""
    app = build()
    paths = {str(rule) for rule in app.url_map.iter_rules()}
    for path in paths:
        if path.startswith('/identity_scan'):
            check(path in ('/identity_scan', '/identity_scan/<scan_id>',
                           '/identity_scan/<scan_id>/delete'),
                  f'unexpected identity route {path!r}; no listing route may exist')


def test_delete_removes_the_record():
    with Sandbox() as box:
        scan_id = box.seed()
        client = build().test_client()
        check(client.post(f'/identity_scan/{scan_id}/delete').status_code in (302, 303),
              'delete did not redirect')
        check(client.get(f'/identity_scan/{scan_id}').status_code == 404,
              'the record survived deletion')


def test_dissent_is_not_rendered_as_corroboration():
    """A row where one engine found an account and the other did not must not carry the
    corroboration badge, and the dissent must be visible rather than silently dropped."""
    with Sandbox() as box:
        scan_id = box.seed_record('22222222-2222-2222-2222-222222222222', [{
            'site': 'GitHub', 'url': 'https://github.com/alice', 'status': 'found',
            'engines': ['sherlock', 'user-scanner'],
            'claims': {'sherlock': 'found', 'user-scanner': 'not_found'},
            'agreeing': ['sherlock'], 'category': 'dev', 'metadata': {},
            'reason': 'user-scanner reported not_found',
        }], summary={'checked': 1, 'found': 1, 'corroborated': 0, 'blocked': 0,
                     'unknown': 0})
        response = build().test_client().get(f'/identity_scan/{scan_id}')
        body = response.get_data(as_text=True)
        check(response.status_code == 200,
              f'GET /identity_scan/<id> returned {response.status_code}')
        check('corroborated: ' not in body,
              'a disagreeing row still rendered the corroboration badge')
        check('user-scanner reported not_found' in body,
              'the dissent text was not rendered on the row')


def test_unsafe_url_is_reguarded_on_read():
    """The result template trusts every writer normalised its URLs, but a record written
    before the scheme allowlist landed, or written by any future second writer, must not
    reach the page unguarded."""
    with Sandbox() as box:
        scan_id = box.seed_record('33333333-3333-3333-3333-333333333333', [{
            'site': 'Evil', 'url': 'javascript:alert(1)', 'status': 'found',
            'engines': ['sherlock'], 'category': None, 'metadata': {}, 'reason': None,
        }], summary={'checked': 1, 'found': 1, 'corroborated': 0, 'blocked': 0,
                     'unknown': 0})
        response = build().test_client().get(f'/identity_scan/{scan_id}')
        body = response.get_data(as_text=True)
        check(response.status_code == 200,
              f'GET /identity_scan/<id> returned {response.status_code}')
        check('href="javascript:' not in body,
              'an unsafe URL scheme already on disk reached the rendered page')


def test_busy_scanner_flashes_rather_than_500():
    with Sandbox():
        original = identity_routes.run_identity_scan

        def busy(*args, **kwargs):
            raise identity_routes.ScannerBusy('busy')

        identity_routes.run_identity_scan = busy
        try:
            response = build().test_client().post('/identity_scan',
                                                  data={'target': 'alice',
                                                        'mode': 'username'})
            check(response.status_code in (302, 303),
                  f'a busy scanner returned {response.status_code}, expected a redirect')
        finally:
            identity_routes.run_identity_scan = original


def main():
    test_form_renders()
    test_result_renders_and_shows_corroboration()
    test_bad_id_is_404_not_500()
    test_there_is_no_listing_route()
    test_delete_removes_the_record()
    test_dissent_is_not_rendered_as_corroboration()
    test_unsafe_url_is_reguarded_on_read()
    test_busy_scanner_flashes_rather_than_500()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
