"""Acceptable-use notice and record deletion, driven through the Flask test client.

No server, no browser, no network. `storage.LOCAL_ROOT` is repointed at a temp tree
before `create_app()` so nothing here can see or touch the real `data/`
(`check_isolation` refuses to run otherwise), and the scan/analysis fixtures are
written through the store rather than with open().

Run: uv run python app/tests/test_governance.py
"""
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-governance')

from app.utils import storage                    # noqa: E402

_REAL_LOCAL_ROOT = storage.LOCAL_ROOT
_TEMP_ROOT = Path(tempfile.mkdtemp(prefix='nexustrace-governance-'))
storage.LOCAL_ROOT = _TEMP_ROOT
storage.reset_cache()

import json                                      # noqa: E402

from app import create_app                       # noqa: E402
from app.utils import disclosure                 # noqa: E402


def check_isolation():
    real = (Path(storage.__file__).resolve().parent.parent.parent / 'data').resolve()
    root = Path(storage.LOCAL_ROOT).resolve()
    if root == real or real in root.parents:
        raise SystemExit(f'REFUSING TO RUN: {root} is inside the real data store')


CASES = 0
FAILURES = []

SCAN_ID = 'aaaaaaaa-1111-2222-3333-444444444444'
ANALYSIS_ID = 'bbbbbbbb-1111-2222-3333-555555555555'
STAGES = ('load', 'after-scroll', 'after-consent')
XSS = '"><script>alert(1)</script>'


def ok(condition, label, detail=''):
    global CASES
    CASES += 1
    if not condition:
        FAILURES.append(f'{label}: {detail}' if detail else label)


def seed_scan():
    record = {
        'id': SCAN_ID,
        'url': f'https://evil.example/{XSS}',
        'status': 'done',
        'created_at': '2026-07-30T00:00:00Z',
        'page': {'final_url': 'https://evil.example/', 'status': 200, 'title': 'x'},
        'transactions': [], 'redirects': [], 'cookies': [], 'console': [],
        'technologies': [], 'forms': [], 'screenshots': [], 'blocked_requests': [],
        'domains': [], 'ips': [], 'iocs': [],
        'verdict': {'level': 'benign', 'score': 0.0, 'signals': []},
    }
    store('scans').write_text(f'{SCAN_ID}.json', json.dumps(record))
    shots = store('screenshots')
    shots.write_bytes(f'{SCAN_ID}.png', b'\x89PNG-full')
    for stage in STAGES:
        shots.write_bytes(f'{SCAN_ID}-{stage}.png', b'\x89PNG-' + stage.encode())


def seed_analysis():
    record = {
        'id': ANALYSIS_ID,
        'status': 'done',
        'created_at': '2026-07-30T00:00:00Z',
        'headers': {'from': 'ceo@evil.example', 'subject': XSS},
        'sender_domain': 'evil.example',
        'received_chain': [], 'received_public_ips': [], 'attachments': [],
        'urls': [], 'iocs': [], 'authentication': {}, 'spoofing': [],
        'suspicious_headers': [], 'enrichment': {},
        'verdict': {'level': 'benign', 'score': 0.0, 'signals': []},
    }
    store('analyses').write_text(f'{ANALYSIS_ID}.json', json.dumps(record))


def store(name):
    return storage.store(name)


def keys(name, prefix):
    return sorted(e['key'] for e in store(name).list()
                  if e['key'].startswith(prefix))


def csrf_token(client):
    body = client.get('/').get_data(as_text=True)
    match = re.search(r'name="csrf-token" content="([^"]+)"', body)
    assert match, 'no CSRF token in base.html'
    return match.group(1)


def notice_block(client, path):
    """Just the disclosure paragraphs, so a nav link elsewhere on the page cannot
    make a negative assertion pass or fail by accident."""
    html = client.get(path).get_data(as_text=True)
    start = html.index('Sent to third parties:')
    return html[start:html.index('</div>', start)]


def test_notice_on_upload_pages(client):
    print('\nAcceptable-use notice:')
    pages = {'/url_scan': 'url_scan', '/email_analysis': 'email',
             '/file_analysis': 'file'}
    for path, surface in pages.items():
        response = client.get(path)
        html = response.get_data(as_text=True)
        ok(response.status_code == 200, f'{path} renders', response.status_code)
        ok('Do not submit anything you are not authorised to share' in html,
           f'{path} carries the acceptable-use line')
        ok('anyone with the link can read any result' in html,
           f'{path} states there is no login')
        ok('Sent to third parties:' in html, f'{path} discloses third parties')
        data = disclosure.for_template(surface)
        missing = [n for n in data['always'] + data['on_click'] if n not in html]
        ok(not missing, f'{path} names every disclosed service', missing)
        ok('Kept:' in html, f'{path} states what is retained')
        ok(data['sends'] in html,
           f'{path} states what is transmitted', data['sends'])
        if data['retention']:
            ok('30 days' in html, f'{path} states the retention period')
        print(f'  PASS  {path:16s} {len(data["always"])} destinations, '
              f'{len(data["on_click"])} pivot targets, all named')

    # base.html's nav links out to VirusTotal and friends, so the negative check has
    # to look at the notice block itself, not the whole page.
    ok('VirusTotal' in notice_block(client, '/file_analysis'),
       'the file notice names VirusTotal')
    ok('AbuseIPDB' in notice_block(client, '/email_analysis'),
       'the e-mail notice names AbuseIPDB')
    scan_notice = notice_block(client, '/url_scan')
    ok('Team Cymru' in scan_notice, 'the scan notice names Team Cymru')
    ok('VirusTotal' not in scan_notice,
       'the scan notice does not claim a provider the scan path never calls')
    print('  PASS  disclosure differs per surface and matches the registry')


def test_result_pages_and_controls(client):
    print('\nResult pages:')
    response = client.get(f'/url_scan/{SCAN_ID}')
    html = response.get_data(as_text=True)
    ok(response.status_code == 200, 'scan result page 200', response.status_code)
    ok(f'/url_scan/{SCAN_ID}/delete' in html, 'scan page links to the delete step')
    ok('Delete this scan' in html, 'scan page shows the delete control')
    ok(XSS not in html, 'scan page escapes the attacker-controlled URL')

    response = client.get(f'/email_analysis/{ANALYSIS_ID}')
    html = response.get_data(as_text=True)
    ok(response.status_code == 200, 'e-mail result page 200', response.status_code)
    ok(f'/email_analysis/{ANALYSIS_ID}/delete' in html,
       'e-mail page links to the delete step')
    ok('Delete this analysis' in html, 'e-mail page shows the delete control')
    ok(XSS not in html, 'e-mail page escapes the attacker-controlled subject')
    print('  PASS  both result pages render 200 with an escaped delete control')

    for path, needle in ((f'/url_scan/{SCAN_ID}/delete', 'Delete this scan?'),
                         (f'/email_analysis/{ANALYSIS_ID}/delete',
                          'Delete this e-mail analysis?')):
        response = client.get(path)
        html = response.get_data(as_text=True)
        ok(response.status_code == 200, f'GET {path} 200', response.status_code)
        ok(needle in html, f'GET {path} asks for confirmation')
        ok('name="csrf_token"' in html, f'GET {path} form carries a CSRF token')
        ok(f'method="POST" action="{path}"' in html,
           f'GET {path} confirms via POST to itself')
        ok(XSS not in html, f'GET {path} escapes the record summary')
    print('  PASS  both confirmation pages are POST forms with CSRF')


def test_csrf_required(client):
    print('\nCSRF:')
    response = client.post(f'/url_scan/{SCAN_ID}/delete')
    ok(response.status_code == 303, 'tokenless scan delete is rejected',
       response.status_code)
    ok(store('scans').exists(f'{SCAN_ID}.json'), 'tokenless delete kept the record')
    ok(len(keys('screenshots', SCAN_ID)) == 4,
       'tokenless delete kept the screenshots', keys('screenshots', SCAN_ID))

    response = client.post(f'/email_analysis/{ANALYSIS_ID}/delete')
    ok(response.status_code == 303, 'tokenless analysis delete is rejected',
       response.status_code)
    ok(store('analyses').exists(f'{ANALYSIS_ID}.json'),
       'tokenless delete kept the analysis')
    print('  PASS  both deletes bounce to the CSRF handler and change nothing')


def test_bad_ids(client):
    print('\nRejected ids:')
    bad = ['..', '../../etc/passwd', '..%2f..%2fetc%2fpasswd', '.hidden',
           'a' * 300, '%2e%2e%2f%2e%2e%2fetc%2fpasswd', 'no-such-scan']
    token = csrf_token(client)
    for raw in bad:
        for base in ('/url_scan/{}/delete', '/email_analysis/{}/delete'):
            path = base.format(raw)
            get = client.get(path)
            post = client.post(path, data={'csrf_token': token})
            ok(get.status_code in (301, 308, 404),
               f'GET {path} is not an error page', get.status_code)
            ok(post.status_code in (301, 308, 404),
               f'POST {path} is not an error page', post.status_code)
            ok(get.status_code != 500 and post.status_code != 500,
               f'{path} never 500s')
    ok(client.post(f'/url_scan/{"c" * 36}/delete',
                   data={'csrf_token': token}).status_code == 404,
       'deleting a nonexistent scan 404s')
    ok(client.post(f'/email_analysis/{"d" * 36}/delete',
                   data={'csrf_token': token}).status_code == 404,
       'deleting a nonexistent analysis 404s')
    print(f'  PASS  {len(bad)} malformed ids x 2 routes, all 404/redirect, no 500')


def test_delete_removes_everything(client):
    print('\nDeletion:')
    token = csrf_token(client)
    ok(len(keys('screenshots', SCAN_ID)) == 4,
       'four screenshots seeded', keys('screenshots', SCAN_ID))

    response = client.post(f'/url_scan/{SCAN_ID}/delete', data={'csrf_token': token})
    ok(response.status_code == 302, 'scan delete redirects', response.status_code)
    ok(response.headers.get('Location', '').endswith('/url_scan'),
       'scan delete returns to the scan form', response.headers.get('Location'))
    ok(not store('scans').exists(f'{SCAN_ID}.json'), 'the scan record is gone')
    remaining = keys('screenshots', SCAN_ID)
    ok(remaining == [], 'every staged screenshot is gone', remaining)
    ok(client.get(f'/url_scan/{SCAN_ID}').status_code == 404,
       'the scan result page now 404s')
    ok(client.get(f'/url_scan/screenshot/{SCAN_ID}').status_code == 404,
       'the screenshot endpoint now 404s')
    print('  PASS  scan record + full-page + 3 staged screenshots removed')

    response = client.post(f'/email_analysis/{ANALYSIS_ID}/delete',
                           data={'csrf_token': token})
    ok(response.status_code == 302, 'analysis delete redirects', response.status_code)
    ok(not store('analyses').exists(f'{ANALYSIS_ID}.json'),
       'the analysis record is gone')
    ok(client.get(f'/email_analysis/{ANALYSIS_ID}').status_code == 404,
       'the analysis result page now 404s')
    print('  PASS  e-mail analysis record removed')

    token = csrf_token(client)
    ok(client.post(f'/url_scan/{SCAN_ID}/delete',
                   data={'csrf_token': token}).status_code == 404,
       'deleting the same scan twice 404s')
    ok(client.post(f'/email_analysis/{ANALYSIS_ID}/delete',
                   data={'csrf_token': token}).status_code == 404,
       'deleting the same analysis twice 404s')
    print('  PASS  a second delete is a 404, not a 500')


def main():
    check_isolation()
    app = create_app()
    app.config['WTF_CSRF_ENABLED'] = True
    try:
        seed_scan()
        seed_analysis()
        with app.test_client() as client:
            test_notice_on_upload_pages(client)
            test_result_pages_and_controls(client)
            test_csrf_required(client)
            test_bad_ids(client)
            test_delete_removes_everything(client)
    finally:
        shutil.rmtree(_TEMP_ROOT, ignore_errors=True)
        storage.LOCAL_ROOT = _REAL_LOCAL_ROOT
        storage.reset_cache()

    if FAILURES:
        print('\nFAIL:')
        for line in FAILURES:
            print('  ' + line)
        sys.exit(1)
    print(f'\nPASS: {CASES} cases')


if __name__ == '__main__':
    main()
