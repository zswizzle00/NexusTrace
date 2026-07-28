"""SSRF / target-safety tests for app/utils/url_guard.py.

The resolver is injected, so none of these cases touch the network. Cases marked
"NEW" are ones the previous scan_service.is_scannable() did not catch. Cases
marked "R1" are regression cases added after a security review of the first
implementation found real defects (see task-1-review.md); each is paired with
the finding number it covers.

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

    # R1 Finding 1 (Critical): backslash in the authority is a parser-differential
    # SSRF bypass - urlsplit splits userinfo at the last '@', giving host
    # 'example.com', while Chromium's WHATWG parser treats '\' as '/' and
    # terminates the authority at 127.0.0.1. Must be rejected outright.
    ('http://127.0.0.1\\@example.com/', {'example.com': PUBLIC}, False,
     'R1 Finding1: backslash-ambiguous authority must be rejected, not parsed as example.com'),
    ('http://localhost\\@example.com/', {'example.com': PUBLIC}, False,
     'R1 Finding1: backslash-ambiguous authority, localhost variant'),

    # R1 Finding 2 (Critical): malformed input must yield UnsafeURLError / False,
    # never an uncaught ValueError/UnicodeError. resolver_mapping is irrelevant -
    # these must fail during parsing/normalization, before any resolution.
    ('http://[::1/', {}, False, 'R1 Finding2: unbalanced IPv6 bracket must not crash (bare ValueError from urlsplit)'),
    ('http://a..b/', {}, False, 'R1 Finding2: empty DNS label must not crash (UnicodeError from IDNA)'),
    ('http://' + 'a' * 64 + '.com/', {}, False, 'R1 Finding2: over-long DNS label must not crash (UnicodeError from IDNA)'),

    # R1 Finding 3 (Important): a trailing dot must not bypass the hostname
    # denylist. Resolver maps the fqdn to a PUBLIC address so the only thing
    # that can be blocking it is the denylist, not DNS failure.
    ('http://localhost./', {'localhost.': PUBLIC}, False,
     'R1 Finding3: trailing dot must not bypass the localhost denylist even though it resolves globally'),
    ('http://metadata.google.internal./', {'metadata.google.internal.': PUBLIC}, False,
     'R1 Finding3: trailing dot must not bypass the metadata denylist even though it resolves globally'),

    # R1 Finding 4 (Important): IDNA/UTS-46 mapping must run before the IP-literal
    # and denylist checks so a lookalike unicode host is judged as what it really
    # is. No resolver mapping needed - IDNA turns this into an IP literal.
    ('http://１２７．０．０．１/', {}, False,
     'R1 Finding4: fullwidth-digit IDN must IDNA-normalize to the loopback literal 127.0.0.1'),

    # R1 Finding 5 (Important): a bare host:port (no scheme) must default to
    # http://, matching the old scan_service.is_scannable behavior, not be
    # misparsed as scheme='example.com'.
    ('example.com:8080/x', {'example.com': PUBLIC}, True,
     'R1 Finding5: bare host:port must default to http://, not be read as a scheme'),

    # R1 Finding 7 (promoted minor): is_global does not exclude multicast, IPv6
    # site-local, or NAT64's well-known prefix (which embeds an IPv4 target).
    ('http://224.0.0.1/', {}, False, 'R1 Finding7: IPv4 multicast literal'),
    ('http://[ff02::1]/', {}, False, 'R1 Finding7: IPv6 multicast literal'),
    ('http://[fec0::1]/', {}, False, 'R1 Finding7: deprecated IPv6 site-local literal'),
    ('http://[64:ff9b::7f00:1]/', {}, False,
     'R1 Finding7: NAT64 well-known-prefix literal embedding 127.0.0.1'),
]

# (raw, expected_url, expected_scheme, expected_host, expected_port)
NORMALIZE_CASES = [
    ('HTTP://EXAMPLE.COM/x', 'http://example.com/x', 'http', 'example.com', 80),
    ('http://example.com:80/x', 'http://example.com/x', 'http', 'example.com', 80),
    ('https://example.com:443/', 'https://example.com/', 'https', 'example.com', 443),
    ('https://example.com:8443/', 'https://example.com:8443/', 'https', 'example.com', 8443),
    ('http://user:pass@example.com/x', 'http://example.com/x', 'http', 'example.com', 80),
    ('http://example.com', 'http://example.com/', 'http', 'example.com', 80),
    ('http://example.com/x#frag', 'http://example.com/x', 'http', 'example.com', 80),
    ('example.com/x', 'http://example.com/x', 'http', 'example.com', 80),
    ('//example.com/x', 'http://example.com/x', 'http', 'example.com', 80),
    # R1 Finding 5: host:port must be recognized as host+port, not scheme.
    ('example.com:8080/x', 'http://example.com:8080/x', 'http', 'example.com', 8080),
    # R1 Finding 4: a genuine unicode hostname must come out IDNA/punycode-encoded
    # so .host matches what Chromium and getaddrinfo actually use on the wire.
    ('http://café.example/', 'http://xn--caf-dma.example/', 'http', 'xn--caf-dma.example', 80),
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
        # validate_target must agree with is_scannable and raise the typed error
        # (and ONLY the typed error - anything else propagating out of this call
        # is itself a failure, uncaught, which is exactly the point).
        try:
            validate_target(url, resolver=resolve)
            raised = False
        except UnsafeURLError:
            raised = True
        if raised == expect_safe:
            failures.append(
                f'validate_target({url!r}) raised={raised}, expected raised={not expect_safe}  [{note}]'
            )

    for raw, expected_url, expected_scheme, expected_host, expected_port in NORMALIZE_CASES:
        got = normalize(raw)
        if got.url != expected_url:
            failures.append(f'normalize({raw!r}).url -> {got.url!r}, expected {expected_url!r}')
        if got.scheme != expected_scheme:
            failures.append(f'normalize({raw!r}).scheme -> {got.scheme!r}, expected {expected_scheme!r}')
        if got.host != expected_host:
            failures.append(f'normalize({raw!r}).host -> {got.host!r}, expected {expected_host!r}')
        if got.port != expected_port:
            failures.append(f'normalize({raw!r}).port -> {got.port!r}, expected {expected_port!r}')

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

    # R1 Finding 8: a caching resolver must NOT memoize a transient failure - the
    # host must be retried on the next call, not permanently blocked.
    flaky_calls = []

    def flaky(host):
        flaky_calls.append(host)
        if len(flaky_calls) == 1:
            raise OSError('transient DNS failure')
        return PUBLIC

    flaky_cached = caching_resolver(flaky)
    try:
        flaky_cached('flaky.test')
        failures.append('caching_resolver(flaky) first call should have raised OSError but did not')
    except OSError:
        pass
    try:
        second = flaky_cached('flaky.test')
        if second != PUBLIC:
            failures.append(f'caching_resolver(flaky) second call -> {second!r}, expected {PUBLIC!r}')
    except OSError:
        failures.append('caching_resolver(flaky) second call replayed the cached failure instead of retrying')
    if flaky_calls != ['flaky.test', 'flaky.test']:
        failures.append(f'caching_resolver(flaky) made calls {flaky_calls!r}, expected one retry per call')

    # R1 Finding 2: is_scannable must never raise, for any input, including
    # non-str values (validate_target's contract only covers str input).
    for value in (None, 123, 3.14, [], {}, b'http://example.com/'):
        try:
            got = is_scannable(value)
        except Exception as exc:  # noqa: BLE001 - this IS the assertion
            failures.append(f'is_scannable({value!r}) raised {exc!r}, expected False with no exception')
        else:
            if got is not False:
                failures.append(f'is_scannable({value!r}) -> {got!r}, expected False')

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(
        f'PASS: {len(GUARD_CASES)} guard + {len(NORMALIZE_CASES)} normalize '
        f'+ 2 cache + 6 non-str cases'
    )


if __name__ == '__main__':
    main()
