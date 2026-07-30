"""Tests for the abuse.ch submission-queue routes and result-page forms.

Pure Flask test client: no server, no browser, no network, no filesystem writes.
The scan/e-mail record lookups are stubbed in the route modules that own them, and
`app.services.submissions` is stubbed in `submission_routes` itself - that module
is built separately, and these tests must pass whether or not it exists yet.

The load-bearing assertion is the negative one: queueing calls the queue and
nothing else. `test_no_transmission_path` greps the route module for any abuse.ch
transmit function.

Run: uv run python app/tests/test_submission_routes.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-submission-routes')

from app import create_app                       # noqa: E402
from app.routes import email_routes, scan_routes, submission_routes  # noqa: E402
from flask import render_template                # noqa: E402

CASES = 0

XSS = '"><script>alert(1)</script>'


def ok(condition, label, detail=''):
    global CASES
    CASES += 1
    assert condition, f'{label}: {detail}'


class FakeQueue:
    """Stand-in for submissions.queue_ioc / queue_sample. Records, never sends."""

    def __init__(self, prefix):
        self.calls = []
        self.prefix = prefix

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        return {'id': f'{self.prefix}-0001', 'status': 'pending'}


def fake_scan():
    return {
        'id': 'scan-abc123',
        'url': f'https://evil.example/{XSS}',
        'status': 'done',
        'device': 'desktop',
        'main_ip': '203.0.113.9',
        'ips': ['203.0.113.9', '198.51.100.4'],
        'domains': [{'domain': 'evil.example', 'ips': ['203.0.113.9']}],
        'page': {'final_url': f'https://evil.example/{XSS}', 'status': 200,
                 'title': XSS, 'status_text': 'OK'},
        'transactions': [], 'redirects': [], 'cookies': [], 'console': [],
        'technologies': [], 'forms': [], 'screenshots': [], 'blocked_requests': [],
        'iocs': [{'type': 'domain', 'value': 'evil[.]example'},
                 {'type': 'ipv4', 'value': '198[.]51[.]100[.]4'}],
        'payload': {'is_payload': True, 'sha256': 'a' * 64, 'filename': 'inv.exe'},
        'verdict': {'level': 'malicious', 'score': 0.9, 'signals': ['password_form']},
    }


def fake_email():
    return {
        'id': 'mail-abc123',
        'status': 'done',
        'headers': {'from': 'ceo@evil.example', 'subject': XSS},
        'sender_domain': 'evil.example',
        'received_public_ips': ['198.51.100.7'],
        'received_chain': [], 'attachments': [{'sha256': 'b' * 64, 'filename': 'x.doc'}],
        'urls': [{'url': 'hxxps://evil[.]example/login', 'anchor_text': XSS}],
        'iocs': [{'type': 'url', 'value': 'hxxps://evil[.]example/login'}],
        'authentication': {}, 'spoofing': [], 'suspicious_headers': [],
        'enrichment': {},
        'verdict': {'level': 'malicious', 'score': 0.9, 'signals': []},
    }


def fake_file():
    return {
        'filename': XSS,
        'size_bytes': 1024,
        'magic_type': 'PE32 executable',
        'digests': {'md5': 'c' * 32, 'sha1': 'd' * 40, 'sha256': 'e' * 64},
        'reputation': {}, 'iocs': [{'type': 'domain', 'value': 'evil[.]example'}],
        'verdict': {'level': 'malicious', 'score': 0.9, 'signals': []},
        'strings_sample': [], 'embedded_executables': [], 'entropy': 7.9,
    }


def csrf_token(client):
    body = client.get('/').get_data(as_text=True)
    match = re.search(r'name="csrf-token" content="([^"]+)"', body)
    assert match, 'no CSRF token in base.html'
    return match.group(1)


def base_ioc_form(token):
    return {
        'csrf_token': token,
        'indicators': 'https://evil.example/a\nhttps://evil.example/b',
        'threat_type': 'payload_delivery',
        'ioc_type': 'url',
        'malware': 'win.zloader',
        'confidence_level': '75',
        'tags': 'phishing, credential theft',
        'reference': 'https://example.org/case/1',
        'comment': 'seen in a scan',
        'source_analysis': 'scan-abc123',
        'anonymous_choice': '1',
        'anonymous': 'yes',
    }


def test_pages_render(app, client):
    print('\nResult pages:')

    scan_routes.get_scan = lambda scan_id: fake_scan()
    email_routes.get_analysis = lambda analysis_id: fake_email()

    response = client.get('/url_scan/scan-abc123')
    scan_html = response.get_data(as_text=True)
    ok(response.status_code == 200, 'scan result page 200', response.status_code)
    ok('Report indicators to abuse.ch' in scan_html, 'scan page shows the queue form')
    ok('action="/submit/queue"' in scan_html, 'scan form posts to /submit/queue')
    print('  PASS  scan result page renders the queue form')

    response = client.get('/email_analysis/mail-abc123')
    email_html = response.get_data(as_text=True)
    ok(response.status_code == 200, 'email result page 200', response.status_code)
    ok('Report indicators to abuse.ch' in email_html, 'email page shows the queue form')
    print('  PASS  e-mail result page renders the queue form')

    response = client.get('/file_analysis')
    ok(response.status_code == 200, 'file analysis form page 200', response.status_code)
    empty_html = response.get_data(as_text=True)
    ok('Report indicators to abuse.ch' not in empty_html,
       'no queue form before a file has been analysed')

    # The file result page is a POST render (analyze_file would hash and hit the
    # network), so the template is rendered directly with a fixture record.
    with app.test_request_context('/api/file/analyze'):
        file_html = render_template('file_analysis.html', analysis=fake_file(),
                                    submit_url='/api/file/analyze')
    ok('Report indicators to abuse.ch' in file_html, 'file page shows the queue form')
    ok('Submit this sample to MalwareBazaar' in file_html, 'file page shows the sample form')
    ok('action="/submit/sample"' in file_html, 'sample form posts to /submit/sample')
    ok('enctype="multipart/form-data"' in file_html, 'sample form is multipart')
    ok('Submit this sample' not in scan_html and 'Submit this sample' not in email_html,
       'sample submission is confined to the file page')
    print('  PASS  file analysis page renders both forms; sample form only there')

    for name, html in (('scan', scan_html), ('email', email_html), ('file', file_html)):
        ok('Nothing is sent to abuse.ch now' in html, f'{name} page states nothing is sent')
        ok('csrf_token' in html or 'name="csrf_token"' in html, f'{name} form carries CSRF')
    print('  PASS  every form states the operator-review guarantee and carries CSRF')

    return scan_html, email_html, file_html


def test_prefill_and_escaping(scan_html, email_html, file_html):
    print('\nPre-fill and escaping:')

    ok(XSS not in scan_html, 'raw XSS payload absent from the scan page')
    ok(XSS not in email_html, 'raw XSS payload absent from the e-mail page')
    ok(XSS not in file_html, 'raw XSS payload absent from the file page')
    ok('<script>alert(1)</script>' not in scan_html, 'no injected script element')
    print('  PASS  the attacker-controlled payload never appears unescaped')

    # The comment input is an attribute context and is pre-filled from the scanned
    # URL, so this is the value="..." breakout case.
    match = re.search(r'id="scanq-comment"[^>]*value="([^"]*)"', scan_html)
    ok(match is not None, 'scan comment field is pre-filled')
    ok('&#34;' in match.group(1) or '&quot;' in match.group(1),
       'the double quote is entity-encoded inside value="..."', match.group(1))
    ok('<' not in match.group(1) and '>' not in match.group(1),
       'no raw angle brackets inside value="..."', match.group(1))
    print('  PASS  value="..." pre-fill is escaped and does not break out')

    textarea = re.search(r'id="scanq-indicators"[^>]*>(.*?)</textarea>', scan_html, re.S)
    ok(textarea is not None, 'scan indicators textarea rendered')
    body = textarea.group(1)
    ok('&lt;script&gt;' in body, 'textarea pre-fill is escaped', body[:120])
    ok('https://evil.example/' in body, 'textarea pre-fill carries the scanned URL')
    print('  PASS  textarea pre-fill is escaped')

    ok('evil.example' in scan_html, 'scan host is offered as a candidate indicator')
    ok('198.51.100.4' in scan_html, 'defanged scan IOC was refanged for the prefill')
    ok('a' * 64 in scan_html, 'dropper hash is offered as a candidate indicator')
    ok('198.51.100.7' in email_html, 'received-chain IP is offered')
    ok('https://evil.example/login' in email_html, 'defanged body URL was refanged')
    ok('e' * 64 in file_html, 'file SHA-256 is offered')
    print('  PASS  indicators are pre-filled and refanged from each record')

    ok('<a href="https://evil.example/login"' not in email_html,
       'no indicator was turned into a live anchor')
    ok('|safe' not in scan_html, 'no |safe leaked into output')
    print('  PASS  no indicator became a live anchor')


def test_queue_success(client, queue):
    print('\nPOST /submit/queue (valid):')
    token = csrf_token(client)
    response = client.post('/submit/queue', data=base_ioc_form(token))
    html = response.get_data(as_text=True)

    ok(response.status_code == 200, 'valid queue POST returns 200', response.status_code)
    ok(len(queue.calls) == 1, 'queue_ioc called exactly once', len(queue.calls))
    args, kwargs = queue.calls[0]
    ok(args[0] == ['https://evil.example/a', 'https://evil.example/b'],
       'indicators forwarded in order', args[0])
    ok(args[1] == 'payload_delivery' and args[2] == 'url' and args[3] == 'win.zloader',
       'threat/ioc/malware forwarded', args[1:])
    ok(kwargs['confidence_level'] == 75, 'confidence forwarded', kwargs['confidence_level'])
    ok(kwargs['tags'] == ['phishing', 'credential theft'], 'tags parsed', kwargs['tags'])
    ok(kwargs['reference'] == 'https://example.org/case/1', 'reference forwarded')
    ok(kwargs['source_analysis'] == 'scan-abc123', 'source analysis forwarded')
    ok(kwargs['anonymous'] is True, 'anonymous forwarded')
    ok('ioc-0001' in html, 'submission id shown to the analyst')
    ok('pending' in html, 'pending status shown')
    ok('Nothing has been sent to abuse.ch' in html, 'confirmation says nothing was sent')
    print('  PASS  a valid submission queues once and reports its id as pending')


def test_rejections(client, queue, samples):
    print('\nServer-side validation:')
    token = csrf_token(client)
    before = len(queue.calls)

    def reject(label, overrides, expect=400):
        form = base_ioc_form(token)
        form.update(overrides)
        response = client.post('/submit/queue', data=form)
        ok(response.status_code == expect, f'{label} rejected', response.status_code)
        ok(len(queue.calls) == before, f'{label} did not reach the service')
        print(f'  PASS  {label}')

    reject('unknown threat_type', {'threat_type': 'ransomware'})
    reject('unknown ioc_type', {'ioc_type': 'yara_rule'})
    reject('empty threat_type', {'threat_type': ''})
    reject('over-long indicator', {'indicators': 'https://x/' + 'a' * 2100})
    reject('too many indicators',
           {'indicators': '\n'.join(f'https://evil.example/{i}' for i in range(26))})
    reject('no indicators', {'indicators': '   \n  '})
    reject('indicator with whitespace', {'indicators': 'https://evil.example/a b'})
    reject('bad tag charset', {'tags': 'phishing;drop table'})
    reject('over-long tag', {'tags': 'x' * 40})
    reject('non-http reference', {'reference': 'javascript:alert(1)'})
    reject('empty malware family', {'malware': ''})
    reject('bad malware charset', {'malware': 'win.zloader; rm -rf'})

    response = client.post('/submit/sample', data={
        'csrf_token': token, 'delivery_method': 'carrier_pigeon',
        'sample': (open(__file__, 'rb'), 'x.bin'),
    }, content_type='multipart/form-data')
    ok(response.status_code == 400, 'unknown delivery_method rejected', response.status_code)
    ok(not samples.calls, 'unknown delivery_method did not reach the service')
    print('  PASS  unknown delivery_method')


def test_clamping_and_defaults(client, queue):
    print('\nClamping and defaults:')
    token = csrf_token(client)

    def post_exact(form):
        queue.calls.clear()
        response = client.post('/submit/queue', data=form)
        ok(response.status_code == 200, 'accepted', response.status_code)
        return queue.calls[0][1]

    def post(overrides):
        form = base_ioc_form(token)
        form.update(overrides)
        return post_exact(form)

    ok(post({'confidence_level': '999'})['confidence_level'] == 100, 'confidence clamped high')
    ok(post({'confidence_level': '-5'})['confidence_level'] == 0, 'confidence clamped low')
    ok(post({'confidence_level': 'abc'})['confidence_level'] == 50, 'confidence defaulted')
    ok(post({'confidence_level': ''})['confidence_level'] == 50, 'blank confidence defaulted')
    print('  PASS  confidence_level clamped to 0-100')

    form = base_ioc_form(token)
    form.pop('anonymous')
    form.pop('anonymous_choice')
    ok(post_exact(form)['anonymous'] is True, 'anonymous defaults to true when absent')

    form = base_ioc_form(token)
    form.pop('anonymous')
    ok(post_exact(form)['anonymous'] is False,
       'the form marker lets an unchecked box mean not-anonymous')
    print('  PASS  anonymous defaults to true; the checkbox can still be switched off')

    kwargs = post({'reference': '', 'comment': '', 'tags': '', 'source_analysis': 'x y'})
    ok(kwargs['reference'] is None, 'blank reference becomes None')
    ok(kwargs['comment'] is None, 'blank comment becomes None')
    ok(kwargs['tags'] == [], 'blank tags become an empty list')
    ok(kwargs['source_analysis'] is None, 'malformed source_analysis is dropped')

    kwargs = post({'indicators': 'hxxps://evil[.]example/a\nhxxps://evil[.]example/a'})
    ok(kwargs is not None and queue.calls[0][0][0] == ['https://evil.example/a'],
       'defanged input is refanged and deduped', queue.calls[0][0][0])
    print('  PASS  optional fields normalise; indicators refang and dedupe')


def test_sample_success(client, samples):
    print('\nPOST /submit/sample (valid):')
    token = csrf_token(client)
    samples.calls.clear()
    response = client.post('/submit/sample', data={
        'csrf_token': token,
        'delivery_method': 'email_attachment',
        'tags': 'loader',
        'references': 'https://example.org/case/2',
        'context': 'from a phishing mail',
        'sample': (__import__('io').BytesIO(b'MZ\x90\x00fake'), 'dropper.exe'),
        'anonymous_choice': '1',
    }, content_type='multipart/form-data')
    html = response.get_data(as_text=True)

    ok(response.status_code == 200, 'valid sample POST returns 200', response.status_code)
    ok(len(samples.calls) == 1, 'queue_sample called exactly once', len(samples.calls))
    args, kwargs = samples.calls[0]
    ok(args[0] == b'MZ\x90\x00fake', 'sample bytes forwarded')
    ok(args[1] == 'dropper.exe', 'filename forwarded', args[1])
    ok(kwargs['delivery_method'] == 'email_attachment', 'delivery method forwarded')
    ok(kwargs['references'] == ['https://example.org/case/2'], 'references parsed')
    ok(kwargs['anonymous'] is False, 'unchecked anonymous honoured with the marker')
    ok('sample-0001' in html and 'pending' in html, 'sample id and status shown')
    ok('Nothing has been sent to abuse.ch' in html, 'confirmation says nothing was sent')
    print('  PASS  a valid sample queues once and reports its id as pending')

    samples.calls.clear()
    response = client.post('/submit/sample', data={
        'csrf_token': token, 'delivery_method': 'other',
    }, content_type='multipart/form-data')
    ok(response.status_code == 400, 'missing file rejected', response.status_code)
    ok(not samples.calls, 'missing file did not reach the service')

    response = client.post('/submit/sample', data={
        'csrf_token': token, 'delivery_method': 'other',
        'sample': (__import__('io').BytesIO(b''), 'empty.bin'),
    }, content_type='multipart/form-data')
    ok(response.status_code == 400, 'empty file rejected', response.status_code)
    ok(not samples.calls, 'empty file did not reach the service')
    print('  PASS  a missing or empty attachment is rejected')


def test_csrf(client, queue, samples):
    print('\nCSRF:')
    queue.calls.clear()
    samples.calls.clear()
    form = base_ioc_form('')
    form.pop('csrf_token')
    response = client.post('/submit/queue', data=form)
    ok(response.status_code in (302, 303, 400),
       'tokenless POST is rejected', response.status_code)
    ok(not queue.calls, 'tokenless POST never reached the service')

    response = client.post('/submit/sample', data={'delivery_method': 'other'},
                           content_type='multipart/form-data')
    ok(response.status_code in (302, 303, 400),
       'tokenless sample POST is rejected', response.status_code)
    ok(not samples.calls, 'tokenless sample POST never reached the service')
    print('  PASS  both routes are behind global CSRF protection')


def test_service_absent(app, client):
    print('\nQueue store absent:')
    saved = (submission_routes.queue_ioc, submission_routes.queue_sample)
    submission_routes.queue_ioc = None
    submission_routes.queue_sample = None
    try:
        with app.test_request_context('/url_scan/scan-abc123'):
            html = render_template('scan_result.html', scan=fake_scan())
        ok('Report indicators to abuse.ch' not in html,
           'the form is hidden when the queue store is unavailable')
        token = csrf_token(client)
        response = client.post('/submit/queue', data=base_ioc_form(token))
        ok(response.status_code == 503, 'the route answers 503, not a traceback',
           response.status_code)
    finally:
        submission_routes.queue_ioc, submission_routes.queue_sample = saved
    print('  PASS  a missing queue store hides the buttons and 503s the route')


def test_no_transmission_path():
    print('\nNo transmission path:')
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        'routes', 'submission_routes.py')
    with open(path) as handle:
        source = handle.read()
    body = '\n'.join(line for line in source.splitlines()
                     if not line.strip().startswith('#'))
    for banned in ('submit_ioc', 'upload_sample', 'abusech', 'requests',
                   'urlopen', 'httpx'):
        # The module docstring names two of these to state the guarantee; strip it.
        stripped = body.split('"""', 2)[-1]
        ok(banned not in stripped, f'{banned} is unreachable from the route module')
    print('  PASS  no abuse.ch client or HTTP library is reachable from the routes')

    for name in ('scan_result.html', 'email_result.html', 'file_analysis.html',
                 '_submit_form.html', 'submit_queued.html'):
        template = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))), 'templates', name)
        with open(template) as handle:
            markup = handle.read()
        ok('abuse.ch/api' not in markup and 'mb-api' not in markup,
           f'{name} posts to no abuse.ch endpoint')
        ok('action="https' not in markup, f'{name} has no off-site form action')
    print('  PASS  no template posts anywhere but this app')


def main():
    app = create_app()
    app.config['SERVER_NAME'] = None
    client = app.test_client()

    queue = FakeQueue('ioc')
    samples = FakeQueue('sample')
    submission_routes.queue_ioc = queue
    submission_routes.queue_sample = samples

    scan_html, email_html, file_html = test_pages_render(app, client)
    test_prefill_and_escaping(scan_html, email_html, file_html)
    test_queue_success(client, queue)
    test_rejections(client, queue, samples)
    test_clamping_and_defaults(client, queue)
    test_sample_success(client, samples)
    test_csrf(client, queue, samples)
    test_service_absent(app, client)
    test_no_transmission_path()

    print(f'\nPASS: {CASES} cases')


if __name__ == '__main__':
    main()
