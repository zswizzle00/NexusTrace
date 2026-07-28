"""SSRF / target-safety tests for app/utils/url_guard.py.

The resolver is injected, so none of these cases touch the network. Cases marked
"NEW" are ones the previous scan_service.is_scannable() did not catch.

Run: uv run python app/tests/test_url_guard.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.utils.url_guard import (
    UnsafeURLError,
    caching_resolver,
    is_scannable,
    normalize,
    validate_target,
)

PUBLIC = ['93.184.216.34']


def resolver_for(mapping):
    """Build a fake resolver from {host: [addrs]}; unknown hosts raise OSError."""
    def resolve(host):
        if host not in mapping:
            raise OSError(f'no such host {host!r}')
        return mapping[host]
    return resolve


# (url, resolver_mapping, expect_safe, note)
GUARD_CASES = [
    ('http://example.com/', {'example.com': PUBLIC}, True, 'plain http'),
    ('https://example.com/a?b=c', {'example.com': PUBLIC}, True, 'https with query'),
    ('example.com', {'example.com': PUBLIC}, True, 'bare host defaults to http'),
    ('ftp://example.com/', {}, False, 'disallowed scheme'),
    ('file:///etc/passwd', {}, False, 'disallowed scheme'),
    ('http://localhost/', {}, False, 'localhost'),
    ('http://foo.localhost/', {}, False, 'localhost suffix'),
    ('http://svc.internal/', {}, False, 'internal suffix'),
    ('http://printer.local/', {}, False, 'mdns local suffix'),
    ('http://metadata.google.internal/', {}, False, 'cloud metadata host'),
    ('http://127.0.0.1/', {}, False, 'loopback literal'),
    ('http://10.0.0.5/', {}, False, 'rfc1918 literal'),
    ('http://192.168.1.1/', {}, False, 'rfc1918 literal'),
    ('http://172.16.0.1/', {}, False, 'rfc1918 literal'),
    ('http://169.254.169.254/', {}, False, 'link-local metadata literal'),
    ('http://100.64.0.1/', {}, False, 'NEW: CGNAT literal'),
    ('http://0.0.0.0/', {}, False, 'unspecified literal'),
    ('http://[::1]/', {}, False, 'ipv6 loopback literal'),
    ('http://[fd00::1]/', {}, False, 'ipv6 ULA literal'),
    ('http://[::ffff:127.0.0.1]/', {}, False, 'NEW: ipv4-mapped ipv6 loopback'),
    ('http://8.8.8.8/', {}, True, 'global literal needs no DNS'),
    ('http://rebind.test/', {'rebind.test': ['93.184.216.34', '127.0.0.1']}, False,
     'NEW: rebinding - ANY non-global resolved address is fatal'),
    ('http://nxdomain.test/', {}, False, 'DNS failure'),
    ('http://empty.test/', {'empty.test': []}, False, 'resolves to nothing'),
]

# (raw, expected_canonical_url)
NORMALIZE_CASES = [
    ('HTTP://EXAMPLE.COM/x', 'http://example.com/x'),
    ('http://example.com:80/x', 'http://example.com/x'),
    ('https://example.com:443/', 'https://example.com/'),
    ('https://example.com:8443/', 'https://example.com:8443/'),
    ('http://user:pass@example.com/x', 'http://example.com/x'),
    ('http://example.com', 'http://example.com/'),
    ('http://example.com/x#frag', 'http://example.com/x'),
    ('example.com/x', 'http://example.com/x'),
    ('//example.com/x', 'http://example.com/x'),
]


def main():
    failures = []

    for url, mapping, expect_safe, note in GUARD_CASES:
        resolve = resolver_for(mapping)
        got_safe = is_scannable(url, resolver=resolve)
        if got_safe != expect_safe:
            failures.append(
                f'is_scannable({url!r}) -> {got_safe}, expected {expect_safe}  [{note}]'
            )
        # validate_target must agree with is_scannable and raise the typed error.
        try:
            validate_target(url, resolver=resolve)
            raised = False
        except UnsafeURLError:
            raised = True
        if raised == expect_safe:
            failures.append(
                f'validate_target({url!r}) raised={raised}, expected raised={not expect_safe}  [{note}]'
            )

    for raw, expected in NORMALIZE_CASES:
        got = normalize(raw).url
        if got != expected:
            failures.append(f'normalize({raw!r}).url -> {got!r}, expected {expected!r}')

    # A caching resolver must hit the network once per host, not once per call.
    calls = []

    def counting(host):
        calls.append(host)
        return PUBLIC

    cached = caching_resolver(counting)
    for _ in range(5):
        cached('example.com')
    cached('other.com')
    if calls != ['example.com', 'other.com']:
        failures.append(f'caching_resolver made calls {calls!r}, expected one per host')

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {len(GUARD_CASES)} guard + {len(NORMALIZE_CASES)} normalize + 1 cache case')


if __name__ == '__main__':
    main()
