"""Tests for the request activity log and the /admin dashboard.

Runs the real `create_app()` through Flask's test client with `activity.ACTIVITY_DIR`
repointed at a fresh temp directory for every case - nothing here ever reads or writes
the real `data/`. No network, no browser: every route exercised is either a static
page, a 404, or a test-only echo route added to the app before the first request.
"""
import io
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app import create_app
from app.utils import activity

RIGHT_TOKEN = 'correct-horse-battery-staple'
WRONG_TOKEN = 'correct-horse-battery-stapl3'

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)
    return bool(condition)


class Sandbox:
    """A fresh activity directory, restored on exit."""

    def __enter__(self):
        self.previous = activity.ACTIVITY_DIR
        self.dir = tempfile.mkdtemp(prefix='nt-activity-')
        activity.ACTIVITY_DIR = self.dir
        activity.reset_state()
        return self

    def __exit__(self, *exc):
        activity.ACTIVITY_DIR = self.previous
        activity.reset_state()
        shutil.rmtree(self.dir, ignore_errors=True)
        return False

    def lines(self):
        out = []
        for name in sorted(os.listdir(self.dir)):
            with open(os.path.join(self.dir, name), 'r', encoding='utf-8') as handle:
                out.extend([line for line in handle.read().splitlines() if line.strip()])
        return out

    def records(self):
        return [json.loads(line) for line in self.lines()]

    def seed(self, records):
        """Write each record into the day-file its own timestamp belongs to, oldest
        first within the file - the shape an append-only writer produces."""
        for record in sorted(records, key=lambda r: r['ts']):
            day = activity._day_of(record['ts'])
            with open(os.path.join(self.dir, f'{day}.jsonl'), 'a', encoding='utf-8') as handle:
                handle.write(json.dumps(record) + '\n')


def build_app():
    app = create_app()
    # The dashboard's own POSTs are the only forms here; the CSRF machinery is not
    # what these cases are testing.
    app.config['WTF_CSRF_ENABLED'] = False

    @app.route('/t/echo', methods=['POST'])
    def _echo():
        return 'ok'

    return app


APP = build_app()


def client():
    return APP.test_client()


def set_admin(token='', emails=''):
    for name, value in (('ADMIN_TOKEN', token), ('ADMIN_EMAILS', emails)):
        if value:
            os.environ[name] = value
        else:
            os.environ.pop(name, None)


# --- one request, one record, expected shape -------------------------------------

def test_single_record_shape():
    with Sandbox() as box:
        set_admin()
        response = client().get('/url_scan', headers={'User-Agent': 'pytest-ua/1.0'})
        check(response.status_code == 200, f'GET /url_scan returned {response.status_code}')

        lines = box.lines()
        if not check(len(lines) == 1, f'expected exactly 1 log line, got {len(lines)}'):
            return
        record = json.loads(lines[0])

        expected_keys = {'ts', 'method', 'path', 'matched', 'endpoint', 'status', 'ms',
                         'ip', 'country', 'ua', 'upload', 'bytes_in'}
        missing = expected_keys - set(record)
        check(not missing, f'record is missing fields: {sorted(missing)}')
        unexpected = set(record) - expected_keys - {'rid', 'user'}
        check(not unexpected, f'record has unexpected fields: {sorted(unexpected)}')

        check(record['method'] == 'GET', f'method={record["method"]!r}')
        check(record['path'] == '/url_scan', f'path={record["path"]!r}')
        check(record['matched'] is True, 'matched should be True for a routed request')
        check(record['endpoint'] == 'scan.url_scan_form', f'endpoint={record["endpoint"]!r}')
        check(record['status'] == 200, f'status={record["status"]!r}')
        check(isinstance(record['ms'], float) and record['ms'] >= 0, f'ms={record["ms"]!r}')
        check(record['ua'] == 'pytest-ua/1.0', f'ua={record["ua"]!r}')
        check(record['upload'] is False, 'a GET must not be flagged as an upload')
        check(record['bytes_in'] == 0, f'bytes_in={record["bytes_in"]!r}')
        check(record['ts'].endswith('Z') and len(record['ts']) == 24, f'ts={record["ts"]!r}')
        check('user' not in record, 'user must be absent without Cloudflare Access')


def test_static_assets_are_skipped():
    with Sandbox() as box:
        set_admin()
        client().get('/static/css/app.css')
        check(box.lines() == [], f'static asset was logged: {box.lines()!r}')


# --- client identity through the tunnel -------------------------------------------

def one_request_ip(headers, environ=None):
    with Sandbox() as box:
        set_admin()
        client().get('/url_scan', headers=headers, environ_overrides=(environ or {}))
        records = box.records()
        return records[0] if records else {}


def test_client_identity():
    record = one_request_ip({'CF-Connecting-IP': '203.0.113.9',
                             'X-Forwarded-For': '198.51.100.7, 10.0.0.1',
                             'CF-IPCountry': 'de'},
                            {'REMOTE_ADDR': '172.17.0.1'})
    check(record.get('ip') == '203.0.113.9',
          f'CF-Connecting-IP must win, got {record.get("ip")!r}')
    check(record.get('country') == 'DE', f'country={record.get("country")!r}')

    # No CF header: the first X-Forwarded-For hop, NOT the tunnel-side last hop that
    # ProxyFix put into remote_addr.
    record = one_request_ip({'X-Forwarded-For': '198.51.100.7, 10.0.0.1'},
                            {'REMOTE_ADDR': '172.17.0.1'})
    check(record.get('ip') == '198.51.100.7',
          f'XFF first hop expected, got {record.get("ip")!r}')

    record = one_request_ip({}, {'REMOTE_ADDR': '192.0.2.55'})
    check(record.get('ip') == '192.0.2.55',
          f'remote_addr fallback expected, got {record.get("ip")!r}')

    # Unparseable values are dropped, not written through.
    record = one_request_ip({'CF-Connecting-IP': 'not-an-ip; DROP TABLE',
                             'CF-IPCountry': '<script>'},
                            {'REMOTE_ADDR': '192.0.2.55'})
    check(record.get('ip') == '192.0.2.55',
          f'a junk CF-Connecting-IP must fall through, got {record.get("ip")!r}')
    check(record.get('country') == '', f'a junk country must be dropped, got {record.get("country")!r}')

    record = one_request_ip({'Cf-Access-Authenticated-User-Email': 'analyst@example.com'})
    check(record.get('user') == 'analyst@example.com',
          f'Access identity not recorded, got {record.get("user")!r}')


# --- path sensitivity --------------------------------------------------------------

def test_path_is_the_route_rule():
    with Sandbox() as box:
        set_admin()
        client().get('/i/customer-secret.example.com')
        records = box.records()
        if not check(len(records) == 1, f'expected 1 record, got {len(records)}'):
            return
        record = records[0]
        check(record['path'] == '/i/<path:indicator>',
              f'the route rule must be stored, got {record["path"]!r}')
        check('customer-secret' not in json.dumps(record),
              'the looked-up indicator leaked into the record')
        check('rid' not in record, 'a non-UUID segment must not become rid')


def test_uuid_segment_is_kept_as_rid():
    with Sandbox() as box:
        set_admin()
        uuid = '0f8fad5b-d9cb-469f-a165-70867728950e'
        client().get(f'/url_scan/{uuid}')
        records = box.records()
        if not check(len(records) == 1, f'expected 1 record, got {len(records)}'):
            return
        check(records[0].get('rid') == uuid, f'rid={records[0].get("rid")!r}')
        check(records[0]['path'] == '/url_scan/<scan_id>', f'path={records[0]["path"]!r}')


def test_unmatched_path_is_sanitized():
    with Sandbox() as box:
        set_admin()
        client().get('/wp-login.php')
        records = box.records()
        if not check(len(records) == 1, f'expected 1 record, got {len(records)}'):
            return
        record = records[0]
        check(record['matched'] is False, 'an unrouted path must be marked unmatched')
        check(record['path'] == '/wp-login.php', f'path={record["path"]!r}')
        check(record['status'] == 404, f'status={record["status"]!r}')

    # Control characters cannot forge a second record.
    with Sandbox() as box:
        client().get('/probe%0a{"ts":"forged"}')
        lines = box.lines()
        check(len(lines) == 1, f'a newline in the path produced {len(lines)} lines')
        check('forged' not in lines[0] or '\\n' not in lines[0],
              'a raw newline survived into the log line')
        check('\n' not in lines[0], 'a raw newline survived into the log line')

    # Query strings are never stored.
    with Sandbox() as box:
        client().get('/nope?token=SUPERSECRET&q=customer.example.com')
        check('SUPERSECRET' not in ''.join(box.lines()), 'a query string was logged')


# --- no request content ever reaches the log ---------------------------------------

def test_no_body_or_form_content_is_logged():
    with Sandbox() as box:
        set_admin()
        marker = 'MARKER-DO-NOT-LOG-9f3a'
        client().post(
            '/t/echo',
            data={'field': marker,
                  'file': (io.BytesIO(marker.encode()), f'{marker}.eml')},
            content_type='multipart/form-data',
            headers={'Cookie': f'session_secret={marker}',
                     'Authorization': f'Bearer {marker}'},
        )
        blob = ''.join(box.lines())
        check(marker not in blob, 'request content (form/file/cookie/header) reached the log')
        records = box.records()
        if check(len(records) == 1, f'expected 1 record, got {len(records)}'):
            check(records[0]['upload'] is True, 'a multipart POST must be flagged as an upload')
            check(records[0]['bytes_in'] > 0, 'bytes_in should carry the Content-Length')


# --- bounds -------------------------------------------------------------------------

def test_csrf_rejection_is_logged():
    """CSRFProtect registers its before_request ahead of ours and aborts the request,
    so the start marker is never set. A rejected POST is exactly the kind of thing the
    log exists for, so it must still produce a record."""
    with Sandbox() as box:
        set_admin()
        APP.config['WTF_CSRF_ENABLED'] = True
        try:
            response = client().post('/t/echo', data={'field': 'x'})
        finally:
            APP.config['WTF_CSRF_ENABLED'] = False
        check(response.status_code in (302, 303, 400),
              f'a token-less POST returned {response.status_code}')
        records = box.records()
        if check(len(records) == 1, f'a CSRF-rejected POST logged {len(records)} records'):
            check(records[0]['path'] == '/t/echo', f'path={records[0]["path"]!r}')
            check(records[0]['ms'] == 0.0,
                  f'expected an unknown duration, got {records[0]["ms"]!r}')


def test_daily_cap_is_enforced():
    with Sandbox() as box:
        set_admin()
        original = activity.MAX_ENTRIES_PER_DAY
        activity.MAX_ENTRIES_PER_DAY = 3
        try:
            test_client = client()
            for _ in range(8):
                test_client.get('/url_scan')
            check(len(box.lines()) == 3,
                  f'cap of 3 produced {len(box.lines())} lines')
            # The cap survives a process restart: the count is recovered from the file.
            activity.reset_state()
            test_client.get('/url_scan')
            check(len(box.lines()) == 3,
                  f'cap leaked after a state reset: {len(box.lines())} lines')
        finally:
            activity.MAX_ENTRIES_PER_DAY = original


def test_oversize_line_is_dropped_not_truncated():
    with Sandbox() as box:
        original = activity.MAX_LINE_BYTES
        activity.MAX_LINE_BYTES = 80
        try:
            written = activity.append({'ts': activity._stamp(activity._now()),
                                       'path': 'x' * 500})
            check(written is False, 'an oversize record was written')
            check(box.lines() == [], f'an oversize record left {box.lines()!r} behind')
        finally:
            activity.MAX_LINE_BYTES = original


def test_user_agent_is_truncated():
    with Sandbox() as box:
        set_admin()
        client().get('/url_scan', headers={'User-Agent': 'A' * 4000})
        records = box.records()
        if check(len(records) == 1, f'expected 1 record, got {len(records)}'):
            check(len(records[0]['ua']) == activity.MAX_UA_CHARS,
                  f'ua length {len(records[0]["ua"])}, expected {activity.MAX_UA_CHARS}')


# --- a logging failure must not break the response -----------------------------------

def test_write_failure_does_not_break_the_request():
    with Sandbox() as box:
        set_admin()
        original = activity.append

        def exploding(entry):
            raise OSError('No space left on device')

        activity.append = exploding
        try:
            response = client().get('/url_scan')
            check(response.status_code == 200,
                  f'a failing log write broke the response: {response.status_code}')
            check(box.lines() == [], 'the exploding writer somehow wrote')
        finally:
            activity.append = original

    # The same via a genuinely unusable directory, exercising the real open() path.
    previous = activity.ACTIVITY_DIR
    handle, blocker = tempfile.mkstemp(prefix='nt-activity-blocker-')
    os.close(handle)
    activity.ACTIVITY_DIR = os.path.join(blocker, 'activity')
    activity.reset_state()
    try:
        response = client().get('/url_scan')
        check(response.status_code == 200,
              f'an unwritable activity dir broke the response: {response.status_code}')
    finally:
        activity.ACTIVITY_DIR = previous
        activity.reset_state()
        os.unlink(blocker)


# --- summary aggregation ---------------------------------------------------------------

def sample(minutes_ago, **overrides):
    moment = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    record = {
        'ts': activity._stamp(moment), 'method': 'GET', 'path': '/url_scan',
        'matched': True, 'endpoint': 'scan.url_scan_form', 'status': 200, 'ms': 1.0,
        'ip': '203.0.113.1', 'country': 'US', 'ua': 'ua', 'upload': False, 'bytes_in': 0,
    }
    record.update(overrides)
    return record


def test_summary_counts():
    with Sandbox() as box:
        box.seed([
            sample(1, ip='203.0.113.1', country='US', path='/url_scan'),
            sample(2, ip='203.0.113.1', country='US', path='/url_scan'),
            sample(3, ip='198.51.100.2', country='DE', path='/email_analysis',
                   upload=True, status=302),
            sample(4, ip='198.51.100.2', country='DE', path='/nope', matched=False,
                   status=404),
            sample(5, ip='192.0.2.3', country='GB', path='/url_scan', status=500),
            # Outside the 24h window - must not be counted.
            sample(60 * 30, ip='198.51.100.99', country='FR', path='/url_scan'),
        ])
        result, cutoff = activity.summary(hours=24)

        check(result['total'] == 5, f'total={result["total"]}, expected 5')
        check(result['uploads'] == 1, f'uploads={result["uploads"]}, expected 1')
        check(result['unique_ips'] == 3, f'unique_ips={result["unique_ips"]}, expected 3')
        check(result['errors'] == 2, f'errors={result["errors"]}, expected 2')
        check(result['error_rate'] == 40.0, f'error_rate={result["error_rate"]}, expected 40.0')
        check(result['top_paths'][0] == ('/url_scan', 3),
              f'top_paths[0]={result["top_paths"][0]!r}')
        check(dict(result['top_ips']) == {'203.0.113.1': 2, '198.51.100.2': 2, '192.0.2.3': 1},
              f'top_ips={result["top_ips"]!r}')
        check(dict(result['top_countries']) == {'US': 2, 'DE': 2, 'GB': 1},
              f'top_countries={result["top_countries"]!r}')
        check(cutoff < activity._stamp(activity._now()), 'cutoff is not in the past')

        # Newest first, and malformed lines are skipped rather than fatal.
        with open(os.path.join(box.dir, f'{activity._day_of(sample(1)["ts"])}.jsonl'),
                  'a', encoding='utf-8') as handle:
            handle.write('{not json\n')
        entries = activity.read_entries(days=2)
        check(len(entries) == 6, f'read_entries returned {len(entries)}, expected 6')
        check(entries[0]['ts'] >= entries[-1]['ts'], 'read_entries is not newest-first')


# --- /admin --------------------------------------------------------------------------

def test_admin_disabled_is_a_404():
    with Sandbox():
        set_admin()
        for method, path in (('get', '/admin'), ('post', '/admin'), ('post', '/admin/logout')):
            response = getattr(client(), method)(path)
            check(response.status_code == 404,
                  f'{method.upper()} {path} with no token returned '
                  f'{response.status_code}, expected 404')
            check(b'Activity' not in response.data,
                  f'{method.upper()} {path} leaked the panel while disabled')


def test_admin_rejects_a_wrong_token():
    with Sandbox() as box:
        set_admin(token=RIGHT_TOKEN)
        box.seed([sample(1, ip='203.0.113.201')])

        attempts = [
            ('anonymous GET', client().get('/admin')),
            ('a wrong header token', client().get('/admin', headers={'X-Admin-Token': WRONG_TOKEN})),
            ('a wrong form token', client().post('/admin', data={'token': WRONG_TOKEN})),
        ]
        for label, response in attempts:
            check(response.status_code == 403,
                  f'{label} returned {response.status_code}, expected 403')
            body = response.data.decode('utf-8', 'replace')
            check('203.0.113.201' not in body,
                  f'{label} leaked a log record to an unauthenticated caller')
            check('Last 24 hours' not in body,
                  f'{label} rendered the dashboard to an unauthenticated caller')


def test_admin_accepts_the_right_token():
    with Sandbox() as box:
        set_admin(token=RIGHT_TOKEN)
        box.seed([sample(1, ip='203.0.113.77', country='NL')])

        response = client().get('/admin', headers={'X-Admin-Token': RIGHT_TOKEN})
        check(response.status_code == 200,
              f'the right header token returned {response.status_code}, expected 200')
        body = response.data.decode('utf-8', 'replace')
        check('203.0.113.77' in body, 'the dashboard did not render a seeded record')
        check('Last 24 hours' in body, 'the dashboard did not render the summary')

        # Form login exchanges the token for a session cookie; the token itself is
        # never placed in a URL.
        session_client = client()
        response = session_client.post('/admin', data={'token': RIGHT_TOKEN})
        check(response.status_code == 303,
              f'a correct form login returned {response.status_code}, expected 303')
        check(RIGHT_TOKEN not in response.headers.get('Location', ''),
              'the token was echoed into the redirect target')
        response = session_client.get('/admin')
        check(response.status_code == 200,
              f'the session did not carry: {response.status_code}')

        # A query-string token is not an accepted credential.
        response = client().get(f'/admin?token={RIGHT_TOKEN}')
        check(response.status_code == 403,
              f'a query-string token was accepted ({response.status_code})')

        # Rotating the token invalidates the outstanding session.
        set_admin(token=RIGHT_TOKEN + '-rotated')
        response = session_client.get('/admin')
        check(response.status_code == 403,
              f'the session survived a token rotation ({response.status_code})')

        response = session_client.post('/admin/logout')
        check(response.status_code == 303,
              f'logout returned {response.status_code}, expected 303')


def test_admin_honours_the_access_allowlist():
    with Sandbox():
        set_admin(emails='analyst@example.com, boss@example.com')
        header = {'Cf-Access-Authenticated-User-Email': 'BOSS@example.com'}
        response = client().get('/admin', headers=header)
        check(response.status_code == 200,
              f'an allowlisted Access identity returned {response.status_code}')

        response = client().get(
            '/admin', headers={'Cf-Access-Authenticated-User-Email': 'nobody@example.com'})
        check(response.status_code == 403,
              f'a non-allowlisted Access identity returned {response.status_code}')


def test_admin_paging():
    with Sandbox() as box:
        set_admin(token=RIGHT_TOKEN)
        box.seed([sample(i + 1, ip=f'203.0.113.{i + 1}') for i in range(25)])
        auth = {'X-Admin-Token': RIGHT_TOKEN}

        first = client().get('/admin?per=10&page=1', headers=auth)
        second = client().get('/admin?per=10&page=2', headers=auth)
        check(first.status_code == 200 and second.status_code == 200,
              'paged requests did not both return 200')
        check(b'Page 1 of 3' in first.data, 'page 1 of 3 not rendered')
        check(b'Page 2 of 3' in second.data, 'page 2 of 3 not rendered')
        check(first.data != second.data, 'page 2 rendered identically to page 1')

        # Out-of-range and junk paging arguments are clamped, not fatal.
        for query in ('page=9999', 'page=-4', 'per=99999', 'per=abc', 'days=0', 'days=999'):
            response = client().get(f'/admin?{query}', headers=auth)
            check(response.status_code == 200,
                  f'/admin?{query} returned {response.status_code}, expected 200')


TESTS = [
    test_single_record_shape,
    test_static_assets_are_skipped,
    test_client_identity,
    test_path_is_the_route_rule,
    test_uuid_segment_is_kept_as_rid,
    test_unmatched_path_is_sanitized,
    test_no_body_or_form_content_is_logged,
    test_csrf_rejection_is_logged,
    test_daily_cap_is_enforced,
    test_oversize_line_is_dropped_not_truncated,
    test_user_agent_is_truncated,
    test_write_failure_does_not_break_the_request,
    test_summary_counts,
    test_admin_disabled_is_a_404,
    test_admin_rejects_a_wrong_token,
    test_admin_accepts_the_right_token,
    test_admin_honours_the_access_allowlist,
    test_admin_paging,
]


def main():
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - an escaping exception IS a failure
            import traceback
            failures.append(f'{test.__name__} raised {exc!r}\n'
                            + ''.join(traceback.format_tb(exc.__traceback__)))
    set_admin()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {len(TESTS)} cases')


if __name__ == '__main__':
    main()
