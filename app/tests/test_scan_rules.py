"""Pins app/services/scan_rules.py:score(), the scanner's heuristic rule engine.

Pure function over a scan dict - no browser, no network. Each case builds a
minimal scan via make_scan(**overrides).
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.services.scan_rules import registrable_domain, score

# Computed relative to *now*, never hard-coded: a literal date stops being "young"
# once YOUNG_DOMAIN_MAX_DAYS elapses, and the malicious case then silently degrades
# to suspicious, failing on a date nobody predicted.
YOUNG_DOMAIN_DATE =(datetime.now(timezone.utc) - timedelta(days=3)).strftime('%Y-%m-%d')
OLD_DOMAIN_DATE = (datetime.now(timezone.utc) - timedelta(days=4000)).strftime('%Y-%m-%d')
OLD_CERT_DATE = (datetime.now(timezone.utc) - timedelta(days=400)).strftime(
    '%b %d %H:%M:%S %Y GMT'
)


def make_scan(**overrides):
    """A benign baseline scan: trusted TLS, good headers, no forms, no payload."""
    scan = {
        'url': 'https://example.com/',
        'status': 'done',
        'page': {
            'final_url': 'https://example.com/',
            'title': 'Example Domain',
            'status': 200,
        },
        'visible_text': 'Example Domain. This domain is for use in documentation.',
        'tls': {'authorized': True, 'valid_from': OLD_CERT_DATE},
        'security': {'score': 7, 'total': 8},
        'domains': [{'domain': 'example.com', 'ips': ['93.184.216.34']}],
        'forms': [],
        'payload': None,
        'whois': {'create_date': OLD_DOMAIN_DATE},
        'dns': {'A': ['93.184.216.34']},
    }
    scan.update(overrides)
    return scan


PASSWORD_FORM = [{'action': '/login', 'method': 'post',
                  'field_types': ['text', 'password'], 'has_password': True}]

# (name, scan, expected_level, must_contain_signals)
CASES = [
    ('clean page', make_scan(), 'benign', []),
    (
        'untrusted TLS',
        make_scan(tls={'authorized': False, 'valid_from': OLD_CERT_DATE}),
        'suspicious',
        ['untrusted_tls'],
    ),
    (
        'password form alone is not enough',
        make_scan(forms=PASSWORD_FORM),
        'benign',
        ['password_form'],
    ),
    (
        'password form on a young domain',
        make_scan(forms=PASSWORD_FORM, whois={'create_date': YOUNG_DOMAIN_DATE}),
        'suspicious',
        ['password_form', 'young_domain', 'password_form+young_domain'],
    ),
    (
        'brand impersonation with credential harvest on a young domain',
        make_scan(
            forms=PASSWORD_FORM,
            whois={'create_date': YOUNG_DOMAIN_DATE},
            page={'final_url': 'https://microsoft-login.verify-account.test/',
                  'title': 'Sign in to your Microsoft account', 'status': 200},
            url='https://microsoft-login.verify-account.test/',
            visible_text='Sign in to your Microsoft account to continue',
            security={'score': 0, 'total': 8},
        ),
        'malicious',
        ['brand_domain_mismatch', 'password_form', 'young_domain',
         'brand_domain_mismatch+password_form', 'password_form+young_domain'],
    ),
    (
        # Established domain with good headers: worth a look, not a conclusion.
        'brand impersonation with credential harvest, nothing else',
        make_scan(
            forms=PASSWORD_FORM,
            page={'final_url': 'https://paypal-secure.verify-account.test/',
                  'title': 'Log in to PayPal', 'status': 200},
            url='https://paypal-secure.verify-account.test/',
            visible_text='Log in to your PayPal account',
        ),
        'suspicious',
        ['brand_domain_mismatch', 'password_form',
         'brand_domain_mismatch+password_form'],
    ),
    (
        # 'purchase' contains 'chase': a substring test read every ecommerce page
        # as brand impersonation.
        'brand token embedded in an ordinary word is not a brand mention',
        make_scan(visible_text='Complete your purchase today',
                  page={'final_url': 'https://shop.example/', 'title': 'Checkout',
                        'status': 200},
                  url='https://shop.example/'),
        'benign',
        [],
    ),
    (
        'brand mentioned in prose without a credential form is not a signal',
        make_scan(visible_text='apple pie recipe',
                  page={'final_url': 'https://recipes.example/', 'title': 'Apple pie',
                        'status': 200},
                  url='https://recipes.example/'),
        'benign',
        [],
    ),
    (
        # This pair describes a large share of the ordinary web, which is the whole
        # reason SUSPICIOUS_THRESHOLD sits above their combined weight.
        'weak headers plus a fresh certificate is not suspicious on its own',
        make_scan(
            security={'score': 0, 'total': 8},
            tls={'authorized': True,
                 'valid_from': (datetime.now(timezone.utc) - timedelta(days=2))
                 .strftime('%b %d %H:%M:%S %Y GMT')},
        ),
        'benign',
        ['fresh_cert', 'no_security_headers'],
    ),
    (
        'dropper on a young domain',
        make_scan(
            payload={'content_type': 'application/octet-stream', 'sha256': 'a' * 64,
                     'size_bytes': 1024, 'filename': 'invoice.exe', 'is_payload': True},
            whois={'create_date': YOUNG_DOMAIN_DATE},
            security={'score': 0, 'total': 8},
        ),
        'suspicious',
        ['payload_download', 'young_domain', 'payload_download+young_domain'],
    ),
    (
        'www subdomain redirect is NOT a cross-domain redirect',
        make_scan(url='https://example.com/',
                  page={'final_url': 'https://www.example.com/', 'title': 'Example',
                        'status': 200}),
        'benign',
        [],
    ),
    (
        'redirect to a genuinely different domain',
        make_scan(url='https://example.com/',
                  page={'final_url': 'https://elsewhere.test/', 'title': 'Elsewhere',
                        'status': 200}),
        'benign',
        ['cross_domain_redirect'],
    ),
    (
        'failed scan with nothing to judge',
        make_scan(status='error', tls=None, security=None, domains=[], page={},
                  whois=None, dns={}),
        'unknown',
        [],
    ),
]

# case name -> signals that must NOT appear. CASES only asserts presence, so it
# cannot express "this must not be treated as brand impersonation".
MUST_NOT_CONTAIN = {
    'brand token embedded in an ordinary word is not a brand mention': [
        'brand_domain_mismatch', 'brand_domain_mismatch+password_form',
    ],
    'brand mentioned in prose without a credential form is not a signal': [
        'brand_domain_mismatch', 'brand_domain_mismatch+password_form',
    ],
    'password form alone is not enough': ['brand_domain_mismatch'],
    'clean page': ['brand_domain_mismatch', 'young_domain', 'fresh_cert'],
}

# (final_url_host, expected_registrable_domain)
DOMAIN_CASES = [
    ('www.example.com', 'example.com'),
    ('example.com', 'example.com'),
    ('a.b.c.example.com', 'example.com'),
    ('example.co.uk', 'example.co.uk'),
    ('www.example.co.uk', 'example.co.uk'),
    ('localhost', 'localhost'),
    ('', ''),
]


def main():
    failures = []

    for name, scan, expected_level, must_contain in CASES:
        result = score(scan)
        if result['level'] != expected_level:
            failures.append(
                f'{name}: level -> {result["level"]!r} (score {result["score"]}), '
                f'expected {expected_level!r}; signals={result["signals"]}'
            )
        for signal in must_contain:
            if signal not in result['signals']:
                failures.append(f'{name}: expected signal {signal!r} in {result["signals"]}')
        for signal in MUST_NOT_CONTAIN.get(name, []):
            if signal in result['signals']:
                failures.append(f'{name}: unexpected signal {signal!r} in {result["signals"]}')
        if not 0.0 <= result['score'] <= 1.0:
            failures.append(f'{name}: score {result["score"]} out of range')

    for host, expected in DOMAIN_CASES:
        got = registrable_domain(host)
        if got != expected:
            failures.append(f'registrable_domain({host!r}) -> {got!r}, expected {expected!r}')

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {len(CASES)} scoring + {len(DOMAIN_CASES)} domain cases')


if __name__ == '__main__':
    main()
