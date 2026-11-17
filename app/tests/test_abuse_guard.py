"""Tests for app/utils/abuse_guard.py. No network; the pure `evaluate()` is driven with a
fake clock, and one case goes through the real app to prove the hook is wired."""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.utils import abuse_guard as ag

failures = []


def check(condition, message):
    if not condition:
        failures.append(message)
    return bool(condition)


def test_probe_paths():
    for path in ('/.env', '/deployment/.env', '/mobile/.env.production', '/cred.txt',
                 '/.git/config', '/wp-login.php', '/phpmyadmin/', '/CRED.TXT',
                 '/backup.sql', '/actuator/health'):
        check(ag.is_probe(path), f'{path} should be a probe')
    for path in ('/', '/analyze', '/i/example.com', '/url_scan', '/robots.txt',
                 '/static/js/mobile.js', '/api/health', '/environment', '/credits'):
        check(not ag.is_probe(path), f'{path} must not be a probe')


def test_probe_ban():
    ag.reset()
    t = 1000.0
    for i in range(ag.PROBE_STRIKES - 1):
        check(ag.evaluate('1.2.3.4', '/.env', t + i) == (404, 'probe', 0), 'probe -> 404')
    check(ag.banned('1.2.3.4', t + 10) is None, 'not banned before the last strike')
    ag.evaluate('1.2.3.4', '/.env', t + 20)
    check(ag.banned('1.2.3.4', t + 21) is not None, 'banned at PROBE_STRIKES')
    decision = ag.evaluate('1.2.3.4', '/', t + 22)
    check(decision and decision[0] == 403, 'banned IP gets 403 even for a clean path')
    check(ag.evaluate('9.9.9.9', '/', t + 22) is None, 'other IPs unaffected')
    check(ag.evaluate('1.2.3.4', '/', t + 20 + ag.BAN_SECONDS + 1) is None, 'ban expires')


def test_strikes_expire():
    ag.reset()
    for i in range(ag.PROBE_STRIKES - 1):
        ag.evaluate('5.5.5.5', '/.env', 100.0 + i)
    ag.evaluate('5.5.5.5', '/.env', 100.0 + ag.STRIKE_WINDOW + 50)
    check(ag.banned('5.5.5.5', 100.0 + ag.STRIKE_WINDOW + 51) is None,
          'old strikes age out of the window')


def test_rate_ban():
    ag.reset()
    t = 5000.0
    last = None
    for i in range(ag.MAX_REQUESTS_PER_WINDOW + 1):
        last = ag.evaluate('7.7.7.7', '/analyze', t + i * 0.01)
    check(last and last[:2] == (429, 'rate'), 'over the ceiling -> 429 rate ban')
    check(ag.evaluate('7.7.7.7', '/', t + 5)[0] == 429, 'rate ban persists')


def test_static_exempt():
    ag.reset()
    for i in range(ag.MAX_REQUESTS_PER_WINDOW * 3):
        r = ag.evaluate('8.8.8.8', '/static/css/app.css', 10.0 + i * 0.001)
        check(r is None, 'static assets are never throttled')
        if r:
            return


def test_bounded_memory():
    ag.reset()
    for i in range(ag.MAX_TRACKED_IPS + 500):
        ag.evaluate(f'10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}', '/x', 1.0)
    check(len(ag._hits) <= ag.MAX_TRACKED_IPS + 1, 'tracked IPs are capped')


def test_wired_into_app():
    os.environ['NEXUSTRACE_ACTIVITY_DIR'] = tempfile.mkdtemp(prefix='nt-abuse-')
    os.environ['ABUSE_GUARD'] = 'on'
    from app import create_app
    ag.reset()
    client = create_app().test_client()
    hdr = {'CF-Connecting-IP': '203.0.113.9'}
    for _ in range(ag.PROBE_STRIKES):
        resp = client.get('/.env', headers=hdr)
        check(resp.status_code == 404 and resp.data == b'', 'probe is a bare 404')
    resp = client.get('/', headers=hdr)
    check(resp.status_code == 403 and 'Retry-After' in resp.headers, 'ban enforced via hook')
    check(client.get('/', headers={'CF-Connecting-IP': '203.0.113.10'}).status_code != 403,
          'a different client still gets the site')
    os.environ['ABUSE_GUARD'] = 'off'
    check(client.get('/', headers=hdr).status_code != 403, 'ABUSE_GUARD=off disables it')
    os.environ['ABUSE_GUARD'] = 'on'


if __name__ == '__main__':
    for name, fn in list(globals().items()):
        if name.startswith('test_') and callable(fn):
            fn()
    if failures:
        print('FAILED:')
        for f in failures:
            print(' -', f)
        sys.exit(1)
    print('abuse_guard: all checks passed')
