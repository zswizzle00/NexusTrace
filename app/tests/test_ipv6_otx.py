"""Regression tests: IPv6 handling in the IP lookup services (NexusTrace bug report).

1. otx_indicator_type(): an IPv4-only regex used to send IPv6 addresses to the OTX
   'domain' endpoint, so IPv6 lookups returned no data (appeared "broken") while IPv4
   worked. It now routes IPv4 / IPv6 / domain correctly.
2. proxycheck_ip_data(): ProxyCheck keys its response by IP, but can return an IPv6 in a
   normalized (compressed) form that differs from the queried string; an exact key lookup
   silently missed. It now matches by address equality.

Run: uv run python app/tests/test_ipv6_otx.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.services.ip_service import otx_indicator_type, proxycheck_ip_data

OTX_CASES = {
    # The two IPv6 addresses from the original bug report
    '2a0a:d683:d986:4b89:ebea:518e:3b4f:b4b6': 'IPv6',
    '2a0a:d683:d90c:506c:7488:4a66:490c:d371': 'IPv6',
    '2001:4860:4860::8888': 'IPv6',   # compressed IPv6
    '::1': 'IPv6',                     # loopback
    '8.8.8.8': 'IPv4',
    '1.1.1.1': 'IPv4',
    'github.com': 'domain',
    'sub.example.co.uk': 'domain',
}

# (response_data, queried_ip, expected_block)
PROXYCHECK_CASES = [
    ({'status': 'ok', '8.8.8.8': {'risk': 0, 'type': 'Business'}}, '8.8.8.8', {'risk': 0, 'type': 'Business'}),
    # exact IPv6 key
    ({'2a0a:d683:d986:4b89:ebea:518e:3b4f:b4b6': {'type': 'VPN'}}, '2a0a:d683:d986:4b89:ebea:518e:3b4f:b4b6', {'type': 'VPN'}),
    # queried expanded, response compressed -> must still match by address equality
    ({'status': 'ok', '2001:4860:4860::8888': {'type': 'OK'}}, '2001:4860:4860:0:0:0:0:8888', {'type': 'OK'}),
    # no per-IP block present
    ({'status': 'error', 'message': 'nope'}, '8.8.8.8', {}),
]


def main():
    failures = []
    for indicator, expected in OTX_CASES.items():
        got = otx_indicator_type(indicator)
        if got != expected:
            failures.append(f"otx_indicator_type({indicator!r}) -> {got!r}, expected {expected!r}")

    for data, ip, expected in PROXYCHECK_CASES:
        got = proxycheck_ip_data(data, ip)
        if got != expected:
            failures.append(f"proxycheck_ip_data(..., {ip!r}) -> {got!r}, expected {expected!r}")

    if failures:
        print("FAIL:")
        for line in failures:
            print("  " + line)
        sys.exit(1)
    print(f"PASS: {len(OTX_CASES)} OTX routing + {len(PROXYCHECK_CASES)} ProxyCheck extraction cases")


if __name__ == '__main__':
    main()
