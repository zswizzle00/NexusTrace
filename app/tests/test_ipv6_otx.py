"""Regression tests: IPv6 handling in the IP lookup services. Pure, no network.

Two shipped bugs, both silent:
1. otx_indicator_type() had an IPv4-only regex, so IPv6 went to OTX's 'domain'
   endpoint and returned no data while IPv4 worked.
2. proxycheck_ip_data() looked its per-IP block up by exact key, so a response
   that compressed the queried IPv6 differently missed entirely.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.services.ip_service import otx_indicator_type, proxycheck_ip_data

OTX_CASES = {
    # The two IPv6 addresses from the original bug report
    '2a0a:d683:d986:4b89:ebea:518e:3b4f:b4b6': 'IPv6',
    '2a0a:d683:d90c:506c:7488:4a66:490c:d371': 'IPv6',
    '2001:4860:4860::8888': 'IPv6',   # compressed form
    '::1': 'IPv6',
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
