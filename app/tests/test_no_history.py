"""Pins the absence of the public recent-items listings.

The property under test is non-disclosure, not markup. Asserting that the template no
longer contains a "Recent Analyses" heading would still pass if a rewritten listing
leaked the same records under a different heading, so every case seeds a real record and
asserts that the record's own identifying fields never appear in the response body.

The direct-link cases are as important as the absence cases: the requirement was to stop
visitors browsing other people's submissions, NOT to stop an analyst reopening their own
result, so a change that 404'd the result pages would satisfy the absence assertions and
still be wrong.

No network, no browser, no real data/: storage.LOCAL_ROOT and activity.ACTIVITY_DIR are
repointed at a temp tree for every case.
"""
import base64
import json
import os
import shutil
import sys
import tempfile
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app import create_app
from app.utils import activity, storage

# A real 1x1 PNG. It makes has_screenshot true, so the assertion that no screenshot URL
# appears in the form page genuinely tests the fix, not just an absent image. It is a
# valid PNG so the fixture cannot be the reason a future image-touching assertion fails.
PNG_1PX = base64.b64decode(
    b'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8AAAAMBAQAY'
    b'3Y2wAAAAAElFTkSuQmCC')

failures = []
cases = 0


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


class Sandbox:
    """Fresh activity dir + storage root, both restored on exit."""

    def __enter__(self):
        self.previous_activity = activity.ACTIVITY_DIR
        self.previous_root = storage.LOCAL_ROOT
        self.dir = tempfile.mkdtemp(prefix='nt-nohistory-')
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

    def seed_analysis(self, subject, sender):
        analysis_id = str(uuid.uuid4())
        storage.store('analyses').write_text(
            f'{analysis_id}.json',
            json.dumps({'id': analysis_id, 'created_at': '2026-09-20T00:00:00Z',
                        'headers': {'subject': subject, 'from': sender},
                        'attachments': [],
                        'verdict': {'level': 'suspicious', 'score': 0.4, 'signals': []}}))
        return analysis_id

    def seed_scan(self, url):
        """Seeds a screenshot as well as the record, and that is load-bearing. The old
        grid emitted an <img> only when has_screenshot was true, so a scan with no
        stored image would make the screenshot-URL assertion pass before the listing
        was removed, testing nothing."""
        scan_id = str(uuid.uuid4())
        storage.store('scans').write_text(
            f'{scan_id}.json',
            json.dumps({'id': scan_id, 'url': url, 'status': 'done',
                        'created_at': '2026-09-20T00:00:00Z',
                        'page': {'title': 'Seeded Page Title', 'status': 200}}))
        storage.store('screenshots').write_bytes(f'{scan_id}.png', PNG_1PX)
        return scan_id


def build():
    app = create_app()
    app.config['WTF_CSRF_ENABLED'] = False
    return app


def test_email_form_lists_nothing():
    with Sandbox() as box:
        first = box.seed_analysis('Invoice attached', 'billing@partner.test')
        second = box.seed_analysis('Payroll update', 'hr@partner.test')
        client = build().test_client()

        response = client.get('/email_analysis')
        body = response.get_data(as_text=True)

        check(response.status_code == 200,
              f'GET /email_analysis returned {response.status_code}, expected 200')
        for leaked in (first, second, 'Invoice attached', 'Payroll update',
                       'billing@partner.test', 'hr@partner.test'):
            check(leaked not in body,
                  f'GET /email_analysis leaked {leaked!r} from a stored record')


def test_email_direct_link_still_works():
    with Sandbox() as box:
        analysis_id = box.seed_analysis('Invoice attached', 'billing@partner.test')
        client = build().test_client()

        response = client.get(f'/email_analysis/{analysis_id}')

        check(response.status_code == 200,
              f'GET /email_analysis/<id> returned {response.status_code}, expected 200')
        check('Invoice attached' in response.get_data(as_text=True),
              'the e-mail result page no longer renders its own record')


def test_scan_form_lists_nothing():
    """The scanner listing was a thumbnail grid, so it rendered screenshots of pages
    other people scanned. The screenshot URL is asserted separately from the record id:
    a grid that dropped the link but kept the <img> would still publish the image."""
    with Sandbox() as box:
        first = box.seed_scan('https://one.example.test/')
        second = box.seed_scan('https://two.example.test/')
        client = build().test_client()

        response = client.get('/url_scan')
        body = response.get_data(as_text=True)

        check(response.status_code == 200,
              f'GET /url_scan returned {response.status_code}, expected 200')
        for leaked in (first, second, 'https://one.example.test/',
                       'https://two.example.test/', 'Seeded Page Title'):
            check(leaked not in body,
                  f'GET /url_scan leaked {leaked!r} from a stored record')
        check('/url_scan/screenshot/' not in body,
              'GET /url_scan still emits a screenshot URL for a stored scan')


def test_scan_direct_link_still_works():
    with Sandbox() as box:
        scan_id = box.seed_scan('https://one.example.test/')
        client = build().test_client()

        response = client.get(f'/url_scan/{scan_id}')

        check(response.status_code == 200,
              f'GET /url_scan/<id> returned {response.status_code}, expected 200')
        check('https://one.example.test/' in response.get_data(as_text=True),
              'the scan result page no longer renders its own record')


def test_listing_helpers_are_gone():
    """Dead code, not just an unused import: both functions existed only to feed the
    listings, so leaving them behind invites the next change to re-add a listing."""
    from app.services import email_service, scan_service
    check(not hasattr(email_service, 'list_analyses'),
          'email_service.list_analyses still exists; it is dead once the listing is gone')
    check(not hasattr(scan_service, 'list_scans'),
          'scan_service.list_scans still exists; it is dead once the listing is gone')


def main():
    test_email_form_lists_nothing()
    test_email_direct_link_still_works()
    test_scan_form_lists_nothing()
    test_scan_direct_link_still_works()
    test_listing_helpers_are_gone()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
