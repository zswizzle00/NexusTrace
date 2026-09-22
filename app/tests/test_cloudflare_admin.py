"""Tests for scripts/cloudflare_admin.py, with the HTTP layer replaced by a fake.

No live Cloudflare call is ever made: the script's module-level ``HTTP`` seam is swapped
for a router that answers from recorded-shape payloads and records every request. That is
what lets the mutating commands be asserted at all - the point of most cases is what was
NOT sent: a dry run issues zero mutating requests, ``--apply`` issues exactly the expected
ones, and the API token never reaches stdout.

NOT asserted: that Cloudflare accepts these payloads. The response shapes are recorded
from the documented API, not captured from the wire.
"""
import contextlib
import importlib.util
import io
import os
import sys

import requests

_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TOKEN = 'cf-test-token-0123456789abcdefDONOTPRINT'
ACCOUNT = 'acct-456'
ZONE = 'zone-123'

os.environ['CF_API_TOKEN'] = TOKEN
os.environ['CF_ZONE_ID'] = ZONE
os.environ['CF_ACCOUNT_ID'] = ACCOUNT
os.environ['CF_BASE_DOMAIN'] = 'nexustrace.net'
os.environ['CF_SUBDOMAIN'] = 'cloud'

_SUBJECT = os.path.join(_ROOT, 'scripts', 'cloudflare_admin.py')
if not os.path.exists(_SUBJECT):
    # The subject is internal-only and gitignored (see .gitignore), so it is absent
    # from any clone. The test stays useful for whoever has it locally rather than
    # failing for everyone who does not.
    print('SKIP: scripts/cloudflare_admin.py is not present (internal-only script)')
    raise SystemExit(0)

_spec = importlib.util.spec_from_file_location(
    'cloudflare_admin_under_test',
    _SUBJECT,
)
cfa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cfa)

APPS = f'/accounts/{ACCOUNT}/access/apps'
ORG = f'/accounts/{ACCOUNT}/access/organizations'
DNS = f'/zones/{ZONE}/dns_records'

MUTATING = ('POST', 'PUT', 'PATCH', 'DELETE')

APP = {
    'id': 'app-1',
    'aud': '0d9b4f3e2c1a7b6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d',
    'name': 'NexusTrace Admin',
    'domain': 'cloud.nexustrace.net/admin',
    'type': 'self_hosted',
    'session_duration': '24h',
    'created_at': '2026-07-01T00:00:00Z',
}
POLICY = {
    'id': 'pol-1',
    'name': 'NexusTrace Admin - allowed operators',
    'decision': 'allow',
    'precedence': 1,
    'include': [{'email': {'email': 'owner@example.com'}}],
}


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else ''

    def json(self):
        if self._payload is None:
            raise ValueError('no json')
        return self._payload


def ok(result):
    return FakeResponse(200, {'success': True, 'errors': [], 'messages': [],
                              'result': result})


def envelope_failure(code, message):
    """HTTP 200 carrying success: false - Cloudflare really does this."""
    return FakeResponse(200, {'success': False, 'result': None, 'messages': [],
                              'errors': [{'code': code, 'message': message}]})


def http_error(status, code, message):
    return FakeResponse(status, {'success': False, 'result': None, 'messages': [],
                                 'errors': [{'code': code, 'message': message}]})


class Boom:
    """Marker routing value: raise a transport error instead of answering."""

    def __init__(self, exc):
        self.exc = exc


class FakeHTTP:
    """Routes {(method, key): response}. key is the API path for Cloudflare URLs
    and the full URL otherwise. A value may be a list, consumed one per call."""

    def __init__(self, routes):
        self.routes = dict(routes)
        self.calls = []

    def request(self, method, url, headers=None, json=None, params=None, timeout=None):
        key = url[len(cfa.BASE_URL):] if url.startswith(cfa.BASE_URL) else url
        self.calls.append({'method': method, 'path': key, 'json': json,
                           'params': params, 'headers': headers})
        entry = self.routes.get((method, key))
        if entry is None:
            raise AssertionError(f'unrouted request: {method} {key}')
        if isinstance(entry, list):
            entry = entry.pop(0)
        if isinstance(entry, Boom):
            raise entry.exc
        return entry

    def get(self, url, timeout=None, **kwargs):
        return self.request('GET', url, timeout=timeout)

    def mutating(self):
        return [c for c in self.calls if c['method'] in MUTATING]


def run(argv, routes):
    """Drive main() with a fake HTTP layer. Returns (exit_code, stdout, http)."""
    http = FakeHTTP(routes)
    saved_http, saved_argv = cfa.HTTP, sys.argv
    cfa.HTTP = http
    sys.argv = ['cloudflare_admin.py'] + argv
    out = io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            cfa.main()
    except SystemExit as exc:
        if exc.code is None:
            code = 0
        elif isinstance(exc.code, int):
            code = exc.code
        else:
            # sys.exit("message") prints to stderr and exits 1; fold the message
            # into the captured output so assertions can read it.
            code = 1
            out.write(str(exc.code))
    finally:
        cfa.HTTP, sys.argv = saved_http, saved_argv
    return code, out.getvalue(), http


def main():
    failures = []
    cases = 0

    def check(condition, message):
        nonlocal cases
        cases += 1
        if not condition:
            failures.append(message)

    def check_clean(out, label):
        check(TOKEN not in out, f'{label}: API token leaked into output')

    code, out, http = run(['access', 'show'], {
        ('GET', APPS): ok([APP]),
        ('GET', ORG): ok({'auth_domain': 'nexustrace.cloudflareaccess.com'}),
        ('GET', f'{APPS}/app-1/policies'): ok([POLICY]),
    })
    check(code == 0, f'access show: exit {code}, expected 0')
    check(APP['aud'] in out, 'access show: AUD tag not printed')
    check('nexustrace.cloudflareaccess.com' in out, 'access show: team domain not printed')
    check('owner@example.com' in out, 'access show: policy include not printed')
    check(http.mutating() == [], 'access show: sent a mutating request')
    check_clean(out, 'access show')

    # The AUD must sit alone on its line so it can be copied without editing.
    check(any(ln.strip() == APP['aud'] for ln in out.splitlines()),
          'access show: AUD tag is not on a line of its own')

    code, out, http = run(['access', 'show'], {('GET', APPS): ok([])})
    check(code == 0, f'access show empty: exit {code}, expected 0')
    check('No Access application' in out, 'access show empty: no clear message')
    check('ADMIN_TOKEN' in out, 'access show empty: does not say what still gates /admin')
    check(http.mutating() == [], 'access show empty: sent a mutating request')
    check_clean(out, 'access show empty')

    code, out, http = run(['access', 'show'], {
        ('GET', APPS): ok([APP]),
        ('GET', ORG): ok({'auth_domain': 'nexustrace.cloudflareaccess.com'}),
        ('GET', f'{APPS}/app-1/policies'):
            http_error(404, 12109, 'Access application not found'),
    })
    check(code != 0, 'access show 404: expected non-zero exit')
    check('404' in out and 'Access application not found' in out,
          'access show 404: error not surfaced cleanly')
    check('Traceback' not in out, 'access show 404: traceback leaked')
    check_clean(out, 'access show 404')

    code, out, http = run(['access', 'setup', '--email', 'owner@example.com'],
                          {('GET', APPS): ok([])})
    check(code == 0, f'setup dry run: exit {code}, expected 0')
    check(http.mutating() == [], 'setup dry run: issued a mutating request')
    check('DRY RUN' in out, 'setup dry run: not labelled as a dry run')
    check(f'POST {cfa.BASE_URL}{APPS}' in out, 'setup dry run: did not print the request')
    check('"domain": "cloud.nexustrace.net/admin"' in out,
          'setup dry run: did not print the body it would send')
    check('--apply' in out, 'setup dry run: does not say how to apply')
    check_clean(out, 'setup dry run')

    code, out, http = run(['access', 'setup', '--email', 'owner@example.com'], {
        ('GET', APPS): ok([APP]),
        ('GET', f'{APPS}/app-1/policies'): ok([POLICY]),
    })
    check(code == 0, f'setup dry run (existing): exit {code}, expected 0')
    check(http.mutating() == [], 'setup dry run (existing): issued a mutating request')
    check(f'PUT {cfa.BASE_URL}{APPS}/app-1' in out,
          'setup dry run (existing): did not plan an app update')
    check(f'PUT {cfa.BASE_URL}{APPS}/app-1/policies/pol-1' in out,
          'setup dry run (existing): did not plan a policy update')
    check_clean(out, 'setup dry run (existing)')

    code, out, http = run(
        ['access', 'setup', '--email', 'owner@example.com',
         '--email', 'second@example.com', '--apply'],
        {
            ('GET', APPS): ok([]),
            ('POST', APPS): ok(APP),
            ('POST', f'{APPS}/app-1/policies'): ok(POLICY),
            ('GET', ORG): ok({'auth_domain': 'nexustrace.cloudflareaccess.com'}),
        })
    check(code == 0, f'setup apply: exit {code}, expected 0')
    sent = [(c['method'], c['path']) for c in http.mutating()]
    check(sent == [('POST', APPS), ('POST', f'{APPS}/app-1/policies')],
          f'setup apply: unexpected mutating requests {sent}')
    body = http.mutating()[0]['json']
    check(body['domain'] == 'cloud.nexustrace.net/admin',
          f"setup apply: wrong app domain {body.get('domain')!r}")
    check(body['type'] == 'self_hosted', 'setup apply: app type is not self_hosted')
    check(body['session_duration'] == '24h', 'setup apply: wrong default session duration')
    policy_body = http.mutating()[1]['json']
    check(policy_body['decision'] == 'allow', 'setup apply: policy is not an allow')
    check(policy_body['include'] == [{'email': {'email': 'owner@example.com'}},
                                     {'email': {'email': 'second@example.com'}}],
          f"setup apply: wrong include rules {policy_body['include']}")
    check(APP['aud'] in out, 'setup apply: AUD tag not printed after creation')
    check('access delete' in out, 'setup apply: no lockout-recovery pointer')
    check_clean(out, 'setup apply')

    code, out, http = run(
        ['access', 'setup', '--email-domain', 'example.com',
         '--session-duration', '8h', '--apply'],
        {
            ('GET', APPS): ok([APP]),
            ('GET', f'{APPS}/app-1/policies'): ok([POLICY]),
            ('PUT', f'{APPS}/app-1'): ok(APP),
            ('PUT', f'{APPS}/app-1/policies/pol-1'): ok(POLICY),
            ('GET', ORG): ok({'auth_domain': 'nexustrace.cloudflareaccess.com'}),
        })
    check(code == 0, f'setup apply (existing): exit {code}, expected 0')
    sent = [(c['method'], c['path']) for c in http.mutating()]
    check(sent == [('PUT', f'{APPS}/app-1'), ('PUT', f'{APPS}/app-1/policies/pol-1')],
          f'setup apply (existing): unexpected mutating requests {sent}')
    check(http.mutating()[0]['json']['session_duration'] == '8h',
          'setup apply (existing): --session-duration not honoured')
    check(http.mutating()[1]['json']['include'] ==
          [{'email_domain': {'domain': 'example.com'}}],
          'setup apply (existing): --email-domain not translated')
    check_clean(out, 'setup apply (existing)')

    code, out, http = run(['access', 'setup', '--email', 'owner@example.com', '--apply'], {
        ('GET', APPS): ok([]),
        ('POST', APPS): envelope_failure(12130, 'access.api.error.duplicate_app'),
    })
    check(code != 0, 'setup success:false: expected non-zero exit')
    check('12130' in out and 'duplicate_app' in out,
          'setup success:false: error envelope not surfaced')
    check('Traceback' not in out, 'setup success:false: traceback leaked')
    check_clean(out, 'setup success:false')

    code, out, http = run(['access', 'show'], {
        ('GET', APPS): http_error(403, 10000, 'Authentication error'),
    })
    check(code != 0, '403: expected non-zero exit')
    check('Cloudflare Access: Apps and Policies' in out,
          '403: does not name the Access scope needed')
    check('403' in out, '403: does not mention the status code')
    check('Traceback' not in out, '403: traceback leaked')
    check_clean(out, '403')

    # A zone command's 403 must not send the operator after an Access scope.
    code, out, _ = run(['dns', 'list'], {
        ('GET', DNS): http_error(403, 10000, 'Authentication error'),
    })
    check(code != 0, 'zone 403: expected non-zero exit')
    check('Cloudflare Access' not in out, 'zone 403: names the wrong permission')
    check('Zone Settings' in out, 'zone 403: does not name the zone permissions')
    check_clean(out, 'zone 403')

    code, out, http = run(['access', 'show'], {
        ('GET', APPS): Boom(requests.ConnectionError('name resolution failed')),
    })
    check(code != 0, 'network error: expected non-zero exit')
    check('Could not reach the Cloudflare API' in out, 'network error: no clear message')
    check('Traceback' not in out, 'network error: traceback leaked')
    check_clean(out, 'network error')

    code, out, http = run(['access', 'setup'], {})
    check(code != 0, 'setup with no principals: expected non-zero exit')
    check('--email' in out, 'setup with no principals: no guidance')
    check(http.calls == [], 'setup with no principals: made a request anyway')

    code, out, _ = run(['access', 'setup', '--email', 'not-an-email'], {})
    check(code != 0, 'setup with a bad address: expected non-zero exit')

    code, out, _ = run(['access', 'setup', '--email', 'a@b.co',
                        '--session-duration', 'forever'], {})
    check(code != 0, 'setup with a bad duration: expected non-zero exit')
    check('--session-duration' in out, 'bad duration: message does not name the flag')

    saved_account = cfa.CF_ACCOUNT_ID
    cfa.CF_ACCOUNT_ID = ''
    code, out, http = run(['access', 'show'], {})
    cfa.CF_ACCOUNT_ID = saved_account
    check(code != 0, 'missing account id: expected non-zero exit')
    check('CF_ACCOUNT_ID is not set' in out, 'missing account id: unclear message')
    check('account-scoped' in out,
          'missing account id: does not explain why the zone id is not enough')
    check(http.calls == [], 'missing account id: made a request anyway')

    code, out, http = run(['access', 'delete'], {('GET', APPS): ok([APP])})
    check(code == 0, f'delete dry run: exit {code}, expected 0')
    check(http.mutating() == [], 'delete dry run: issued a mutating request')
    check(f'DELETE {cfa.BASE_URL}{APPS}/app-1' in out,
          'delete dry run: did not print the request')
    check('ADMIN_TOKEN' in out, 'delete dry run: no fallback warning')
    check_clean(out, 'delete dry run')

    code, out, http = run(['access', 'delete', '--apply'], {
        ('GET', APPS): ok([APP]),
        ('DELETE', f'{APPS}/app-1'): ok({'id': 'app-1'}),
    })
    check(code == 0, f'delete apply: exit {code}, expected 0')
    sent = [(c['method'], c['path']) for c in http.mutating()]
    check(sent == [('DELETE', f'{APPS}/app-1')],
          f'delete apply: unexpected mutating requests {sent}')
    check_clean(out, 'delete apply')

    code, out, http = run(['access', 'delete', '--apply'], {('GET', APPS): ok([])})
    check(code != 0, 'delete missing: expected non-zero exit')
    check(http.mutating() == [], 'delete missing: issued a mutating request')
    check('No Access application to delete' in out, 'delete missing: unclear message')

    code, out, http = run(['access', 'delete', '--apply'], {
        ('GET', APPS): ok([APP, dict(APP, id='app-2')]),
    })
    check(code != 0, 'delete ambiguous: expected non-zero exit')
    check(http.mutating() == [], 'delete ambiguous: deleted something anyway')
    check('--app-id' in out, 'delete ambiguous: does not say how to disambiguate')

    code, out, http = run(['access', 'delete', '--app-id', 'app-2', '--apply'], {
        ('GET', APPS): ok([APP, dict(APP, id='app-2')]),
        ('DELETE', f'{APPS}/app-2'): ok({'id': 'app-2'}),
    })
    check(code == 0, f'delete by id: exit {code}, expected 0')
    check([(c['method'], c['path']) for c in http.mutating()] ==
          [('DELETE', f'{APPS}/app-2')], 'delete by id: deleted the wrong application')

    code, out, http = run(['access', 'setup', '--path', 'ops/', '--email', 'a@b.co'],
                          {('GET', APPS): ok([])})
    check(code == 0, f'custom path: exit {code}, expected 0')
    check('cloud.nexustrace.net/ops' in out, 'custom path: not normalised into the target')

    # --- pre-existing commands still work through the rewritten helpers -----
    code, out, http = run(['status'], {
        ('GET', f'/zones/{ZONE}'): ok({
            'id': ZONE, 'name': 'nexustrace.net', 'status': 'active',
            'plan': {'name': 'Free'}, 'name_servers': ['a.ns.cloudflare.com'],
        }),
        ('GET', f'/zones/{ZONE}/settings'): ok([
            {'id': 'security_level', 'value': 'medium'},
            {'id': 'ssl', 'value': 'full'},
        ]),
    })
    check(code == 0, f'status: exit {code}, expected 0')
    check('nexustrace.net' in out and 'medium' in out, 'status: did not render the zone')
    check(http.mutating() == [], 'status: sent a mutating request')
    check_clean(out, 'status')

    code, out, http = run(['dns', 'list'], {
        ('GET', DNS): ok([{'type': 'A', 'name': 'cloud.nexustrace.net',
                           'content': '203.0.113.10', 'proxied': True, 'ttl': 1}]),
    })
    check(code == 0, f'dns list: exit {code}, expected 0')
    check('203.0.113.10' in out, 'dns list: record not rendered')
    check_clean(out, 'dns list')

    code, out, http = run(['dns', 'sync'], {
        ('GET', 'https://api4.my-ip.io/ip'): FakeResponse(200, None, '203.0.113.42'),
        ('GET', DNS): ok([{'id': 'rec-1', 'type': 'A', 'name': 'cloud.nexustrace.net',
                           'content': '203.0.113.10', 'proxied': True, 'ttl': 1}]),
        ('PATCH', f'{DNS}/rec-1'): ok({'name': 'cloud.nexustrace.net',
                                       'content': '203.0.113.42'}),
    })
    check(code == 0, f'dns sync: exit {code}, expected 0')
    check([(c['method'], c['path']) for c in http.mutating()] ==
          [('PATCH', f'{DNS}/rec-1')], 'dns sync: unexpected mutating requests')
    check('203.0.113.42' in out, 'dns sync: new IP not reported')
    check_clean(out, 'dns sync')

    code, out, http = run(['dns', 'sync'], {
        ('GET', 'https://api4.my-ip.io/ip'): FakeResponse(200, None, '203.0.113.42'),
        ('GET', DNS): ok([]),
        ('POST', DNS): ok({'name': 'cloud.nexustrace.net', 'content': '203.0.113.42',
                           'proxied': True}),
    })
    check(code == 0, f'dns sync create: exit {code}, expected 0')
    check([(c['method'], c['path']) for c in http.mutating()] == [('POST', DNS)],
          'dns sync create: unexpected mutating requests')

    code, out, http = run(['security', 'high'], {
        ('PATCH', f'/zones/{ZONE}/settings/security_level'): ok({'value': 'high'}),
    })
    check(code == 0, f'security: exit {code}, expected 0')
    check('high' in out, 'security: level not reported')
    check_clean(out, 'security')

    code, out, http = run(['waf', 'setup-api'], {
        ('GET', f'/zones/{ZONE}/firewall/rules'): ok([]),
        ('POST', f'/zones/{ZONE}/filters'): ok([{'id': 'flt-1'}]),
        ('POST', f'/zones/{ZONE}/firewall/rules'): ok([{'id': 'rule-1', 'action': 'allow',
                                                        'description': 'x'}]),
    })
    check(code == 0, f'waf setup-api: exit {code}, expected 0')
    check('flt-1' in out and 'rule-1' in out, 'waf setup-api: did not report what it made')
    check_clean(out, 'waf setup-api')

    # The Free-plan branch depends on _allow_codes surviving the helper rewrite.
    code, out, http = run(['ratelimit', 'setup'], {
        ('GET', f'/zones/{ZONE}/rate_limits'): ok([]),
        ('POST', f'/zones/{ZONE}/rate_limits'):
            FakeResponse(400, {'success': False, 'result': None,
                               'errors': [{'code': 10021, 'message': 'not available'}]}),
    })
    check(code == 0, f'ratelimit free plan: exit {code}, expected 0')
    check('Free plan' in out, 'ratelimit free plan: 10021 not translated')
    check_clean(out, 'ratelimit free plan')

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
