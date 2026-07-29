"""Pins app/utils/validators.py. Pure functions - no server, network, or browser.

registrable_domain() is the reason this file exists: the scanner's rule engine and
.eml spoofing detection both compare its output, so a wrong answer here produces a
wrong *verdict* in two features, in both directions.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.utils.validators import (
    is_valid_domain,
    is_valid_ip,
    is_valid_url,
    registrable_domain,
)

# The suffix set the old hardcoded implementation carried; each must still resolve
# identically now that a real PSL backs the function (no-regression contract).
LEGACY_MULTI_LABEL_SUFFIXES = [
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.jp', 'co.nz', 'co.za', 'com.au',
    'net.au', 'org.au', 'com.br', 'com.mx', 'com.cn', 'com.tr', 'co.in',
]

# (host, expected_registrable_domain)
DOMAIN_CASES = [
    # The core invariant: a www redirect is not a cross-domain redirect.
    ('www.example.com', 'example.com'),
    ('example.com', 'example.com'),
    ('a.b.c.d.example.com', 'example.com'),

    # Multi-label ICANN suffixes, including ones the old hardcoded set missed.
    ('www.bbc.co.uk', 'bbc.co.uk'),
    ('a.b.c.co.uk', 'c.co.uk'),
    ('www.city.kobe.jp', 'city.kobe.jp'),
    ('shop.example.com.au', 'example.com.au'),
    ('www.example.pvt.k12.ma.us', 'example.pvt.k12.ma.us'),
    ('www.dvla.gov.uk', 'dvla.gov.uk'),
    ('www.gov.uk', 'www.gov.uk'),
    # service.gov.uk is itself a PSL entry, so its subdomains are separate sites.
    ('service.gov.uk', 'service.gov.uk'),
    ('www.service.gov.uk', 'www.service.gov.uk'),

    # Bare public suffix: no registrable part exists. Contract returns the host,
    # NOT '' - callers treat '' as "no opinion" and would skip the check entirely.
    ('com', 'com'),
    ('co.uk', 'co.uk'),
    ('gov.uk', 'gov.uk'),
    ('kobe.jp', 'kobe.jp'),

    # Wildcard rule (*.ck): the suffix is foo.ck, so the eTLD+1 has three labels.
    ('www.foo.ck', 'www.foo.ck'),
    ('foo.ck', 'foo.ck'),
    # Exception rule (!www.ck) overrides the wildcard: the suffix is just 'ck'.
    ('www.ck', 'www.ck'),
    ('abc.www.ck', 'www.ck'),

    # Single-label host - must not raise, must not become ''.
    ('localhost', 'localhost'),
    ('intranet', 'intranet'),

    # IP literals: returned normalized, not label-sliced. The old slicing made
    # 1.2.3.4 and 9.9.3.4 both '3.4', i.e. two different hosts compared equal.
    ('8.8.8.8', '8.8.8.8'),
    ('1.2.3.4', '1.2.3.4'),
    ('9.9.3.4', '9.9.3.4'),
    ('2001:db8::1', '2001:db8::1'),
    ('2001:DB8::0:1', '2001:db8::1'),
    ('[2001:db8::1]', '2001:db8::1'),
    ('127.0.0.1', '127.0.0.1'),

    ('example.com.', 'example.com'),
    ('WWW.EXAMPLE.COM', 'example.com'),
    ('  www.Example.COM.  ', 'example.com'),

    # Punycode matches the PSL as-is; Unicode hosts use the PSL's Unicode rules.
    ('xn--80ak6aa92e.com', 'xn--80ak6aa92e.com'),
    ('www.xn--80ak6aa92e.com', 'xn--80ak6aa92e.com'),
    ('www.日本.jp', '日本.jp'),
    ('a.b.例え.テスト', '例え.テスト'),

    # Unknown TLD: the PSL's implicit '*' rule makes the last label the suffix.
    ('foo.invalidtldxyz', 'foo.invalidtldxyz'),
    ('a.b.foo.invalidtldxyz', 'foo.invalidtldxyz'),

    # Junk must fail soft, never raise.
    ('', ''),
    ('   ', ''),
    (None, ''),
    ('.', ''),
    ('...', ''),
    ('a..b.com', 'a..b.com'),
    ('-bad-.com', '-bad-.com'),
    (12345, ''),
    (b'example.com', ''),
    (['example.com'], ''),

    # PSL PRIVATE section is deliberately honored: the old code collapsed every
    # *.github.io to 'github.io', so a phishing page matched its victim's page.
    ('evil.github.io', 'evil.github.io'),
    ('victim.github.io', 'victim.github.io'),
    ('sub.evil.github.io', 'evil.github.io'),
    ('login-paypal.azurewebsites.net', 'login-paypal.azurewebsites.net'),
    ('secure-chase.azurewebsites.net', 'secure-chase.azurewebsites.net'),
    ('a.blogspot.com', 'a.blogspot.com'),
    ('bucket.s3.amazonaws.com', 'bucket.s3.amazonaws.com'),
    # A private suffix with nothing registered under it has no eTLD+1 either.
    ('s3.amazonaws.com', 's3.amazonaws.com'),
]

# (label, host_a, host_b, should_compare_equal). scan_rules.score() flags
# cross_domain_redirect when these differ; email_parse flags spoofing the same way.
CONSUMER_CASES = [
    # Must NOT flag: same owner.
    ('www redirect', 'example.com', 'www.example.com', True),
    ('www redirect on co.uk', 'bbc.co.uk', 'www.bbc.co.uk', True),
    ('deep subdomain', 'login.microsoftonline.com', 'microsoftonline.com', True),
    ('cdn subdomain', 'example.com', 'static.cdn.example.com', True),
    ('trailing dot only', 'example.com', 'example.com.', True),
    ('case only', 'example.com', 'EXAMPLE.COM', True),
    ('idn punycode host', 'xn--80ak6aa92e.com', 'www.xn--80ak6aa92e.com', True),

    # Must flag: different owner.
    ('lookalike tld swap', 'paypal.com', 'paypal.com.co', False),
    ('lookalike sub-as-domain', 'paypal.com', 'paypal.com.evil.ru', False),
    ('reply-to elsewhere', 'chase.com', 'chase-secure.net', False),
    ('two github pages users', 'evil.github.io', 'victim.github.io', False),
    ('two azure sites', 'a.azurewebsites.net', 'b.azurewebsites.net', False),
    ('sibling co.uk registrants', 'a.co.uk', 'b.co.uk', False),
    ('different ips', '1.2.3.4', '9.9.3.4', False),
    ('ip vs host', '1.2.3.4', 'example.com', False),
]

# (value, expected_normalized_or_None)
IP_CASES = [
    ('8.8.8.8', '8.8.8.8'),
    ('  8.8.8.8  ', '8.8.8.8'),
    ('0.0.0.0', '0.0.0.0'),
    ('255.255.255.255', '255.255.255.255'),
    ('2001:DB8::0:1', '2001:db8::1'),
    ('::1', '::1'),
    ('::ffff:8.8.8.8', '::ffff:8.8.8.8'),
    ('256.1.1.1', None),
    ('8.8.8', None),
    ('8.8.8.8/32', None),
    ('8.8.8.8:80', None),
    ('example.com', None),
    ('', None),
    (None, None),
    (12345, None),
    # Leading zeros are rejected by ipaddress (ambiguous octal).
    ('010.1.1.1', None),
]

# (domain, allow_single_label, expected_bool)
DOMAIN_VALIDITY_CASES = [
    ('example.com', False, True),
    ('EXAMPLE.COM', False, True),
    ('  example.com  ', False, True),
    ('a.b.c.example.com', False, True),
    ('xn--80ak6aa92e.com', False, True),
    ('example-site.co.uk', False, True),
    ('localhost', False, False),
    ('localhost', True, True),
    ('example', True, True),
    ('example.', False, False),
    ('.example.com', False, False),
    ('exa..mple.com', False, False),
    ('-example.com', False, False),
    ('example.c', False, False),
    ('example.123', False, False),
    ('a' * 64 + '.com', False, False),
    ('a' * 63 + '.com', False, True),
    (('a' * 63 + '.') * 4 + 'com', False, False),  # over 253 chars
    ('', False, False),
    (None, False, False),
    (12345, False, False),
    ('has space.com', False, False),
    ('under_score.com', False, False),
]

# (url, expected_bool)
URL_CASES = [
    ('https://example.com', True),
    ('http://example.com', True),
    ('https://example.com:8443/a/b?c=d#e', True),
    ('http://1.2.3.4/', True),
    ('https://[2001:db8::1]/', True),
    ('ftp://example.com', False),
    ('file:///etc/passwd', False),
    ('javascript:alert(1)', False),
    ('mailto:a@example.com', False),
    ('//example.com', False),
    ('example.com', False),
    ('https://', False),
    ('', False),
    (None, False),
    (12345, False),
    # urlparse raises ValueError on .netloc here; is_valid_url must swallow it.
    ('https://[not-an-ipv6/', False),
]


def main():
    failures = []

    for host, expected in DOMAIN_CASES:
        try:
            got = registrable_domain(host)
        except Exception as exc:  # the fail-soft contract
            failures.append(f'registrable_domain({host!r}) raised {exc!r}')
            continue
        if got != expected:
            failures.append(
                f'registrable_domain({host!r}) -> {got!r}, expected {expected!r}'
            )

    for suffix in LEGACY_MULTI_LABEL_SUFFIXES:
        expected = f'acme.{suffix}'
        for host in (expected, f'www.{expected}', f'a.b.www.{expected}'):
            got = registrable_domain(host)
            if got != expected:
                failures.append(
                    f'legacy suffix {suffix!r}: registrable_domain({host!r}) -> '
                    f'{got!r}, expected {expected!r}'
                )

    for label, host_a, host_b, should_match in CONSUMER_CASES:
        a, b = registrable_domain(host_a), registrable_domain(host_b)
        if (a == b) != should_match:
            verb = 'differ' if should_match else 'match'
            failures.append(
                f'{label}: {host_a!r} -> {a!r} and {host_b!r} -> {b!r} '
                f'unexpectedly {verb}'
            )
        # A falsy result makes both consumers skip their check: a silently
        # disabled rule, so assert no real host ever produces one.
        for host, value in ((host_a, a), (host_b, b)):
            if not value:
                failures.append(f'{label}: registrable_domain({host!r}) -> {value!r}')

    for value, expected in IP_CASES:
        got = is_valid_ip(value)
        if got != expected:
            failures.append(f'is_valid_ip({value!r}) -> {got!r}, expected {expected!r}')

    for domain, allow_single, expected in DOMAIN_VALIDITY_CASES:
        got = is_valid_domain(domain, allow_single_label=allow_single)
        if got != expected:
            failures.append(
                f'is_valid_domain({domain!r}, allow_single_label={allow_single}) -> '
                f'{got!r}, expected {expected!r}'
            )

    for url, expected in URL_CASES:
        try:
            got = is_valid_url(url)
        except Exception as exc:
            failures.append(f'is_valid_url({url!r}) raised {exc!r}')
            continue
        if got != expected:
            failures.append(f'is_valid_url({url!r}) -> {got!r}, expected {expected!r}')

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    legacy_count = len(LEGACY_MULTI_LABEL_SUFFIXES) * 3
    print(
        f'PASS: {len(DOMAIN_CASES)} registrable + {legacy_count} legacy-suffix + '
        f'{len(CONSUMER_CASES)} consumer + {len(IP_CASES)} ip + '
        f'{len(DOMAIN_VALIDITY_CASES)} domain + {len(URL_CASES)} url cases'
    )


if __name__ == '__main__':
    main()
