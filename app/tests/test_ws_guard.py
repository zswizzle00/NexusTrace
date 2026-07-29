"""SSRF tests for the scanner's WebSocket guard (scan_service).

`context.route`/`Route.fetch` never see a WebSocket handshake, so `ws(s)://` is
guarded separately by `_install_websocket_guard`. Asserts two layers: the pure
decision (`_validate_ws_target`) and the handler acting on it. NOT asserted:
that Playwright actually dispatches to the handler - the route is a fake, so no
Chromium and no network are involved. Case taxonomy mirrors test_url_guard.py.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.services.scan_service import _install_websocket_guard, _validate_ws_target
from app.utils.url_guard import UnsafeURLError

PUBLIC = ['93.184.216.34']


def resolver_for(mapping):
    """Build a fake resolver from {host: [addrs]}; unknown hosts raise OSError."""
    def resolve(host):
        if host not in mapping:
            raise OSError(f'no such host {host!r}')
        return mapping[host]
    return resolve


# (url, resolver_mapping, expect_allowed, note)
WS_CASES = [
    ('wss://example.com/socket', {'example.com': PUBLIC}, True, 'wss to a public host'),
    ('ws://example.com/socket', {'example.com': PUBLIC}, True, 'ws to a public host'),
    ('WSS://EXAMPLE.COM/socket', {'example.com': PUBLIC}, True, 'scheme/host case is normalized'),
    ('wss://example.com:8443/socket', {'example.com': PUBLIC}, True, 'non-default port on a public host'),
    ('wss://8.8.8.8/socket', {}, True, 'global literal needs no DNS'),

    ('ws://localhost/socket', {}, False, 'localhost'),
    ('ws://localhost:3000/socket', {}, False, 'localhost with a port'),
    ('ws://foo.localhost/socket', {}, False, 'localhost suffix'),
    # Resolves globally, so only the denylist can be blocking it.
    ('ws://localhost./socket', {'localhost.': PUBLIC}, False, 'trailing dot must not bypass the denylist'),
    ('ws://svc.internal/socket', {}, False, 'internal suffix'),
    ('ws://printer.local/socket', {}, False, 'mdns local suffix'),
    ('ws://metadata.google.internal/socket', {}, False, 'cloud metadata host'),

    ('ws://127.0.0.1/socket', {}, False, 'loopback literal'),
    ('ws://127.0.0.1:8080/socket', {}, False, 'loopback literal with a port'),
    ('ws://10.0.0.5/socket', {}, False, 'rfc1918 literal'),
    ('ws://192.168.1.1/socket', {}, False, 'rfc1918 literal'),
    ('ws://169.254.169.254/latest/meta-data/', {}, False, 'link-local metadata literal'),
    ('ws://100.64.0.1/socket', {}, False, 'CGNAT literal'),
    ('ws://0.0.0.0/socket', {}, False, 'unspecified literal'),
    ('ws://224.0.0.1/socket', {}, False, 'IPv4 multicast literal'),
    ('ws://[::1]/socket', {}, False, 'ipv6 loopback literal'),
    ('ws://[fe80::1]/socket', {}, False, 'ipv6 link-local literal'),
    ('ws://[fd00::1]/socket', {}, False, 'ipv6 ULA literal'),
    ('ws://[::ffff:127.0.0.1]/socket', {}, False, 'ipv4-mapped ipv6 loopback'),
    ('ws://[64:ff9b::7f00:1]/socket', {}, False, 'NAT64 well-known prefix embedding 127.0.0.1'),

    ('ws://internal.test/socket', {'internal.test': ['10.1.2.3']}, False,
     'hostname that resolves to a private address'),
    ('ws://rebind.test/socket', {'rebind.test': ['93.184.216.34', '127.0.0.1']}, False,
     'ANY non-global resolved address is fatal'),
    ('ws://nxdomain.test/socket', {}, False, 'DNS failure'),
    ('ws://empty.test/socket', {'empty.test': []}, False, 'resolves to nothing'),

    ('http://example.com/', {'example.com': PUBLIC}, False, 'non-ws scheme is not a WebSocket URL'),
    ('ftp://example.com/', {}, False, 'non-ws scheme'),
    ('javascript:x@evil.com', {}, False, 'opaque non-ws scheme'),
    ('ws:/example.com/socket', {'example.com': PUBLIC}, False, 'missing :// separator'),
    ('example.com/socket', {'example.com': PUBLIC}, False, 'no scheme at all'),
    ('', {}, False, 'empty string'),
    ('ws://', {}, False, 'no host'),
    # Parser-differential: urlsplit reads host example.com, Chromium stops at 127.0.0.1.
    ('ws://127.0.0.1\\@example.com/', {'example.com': PUBLIC}, False, 'backslash-ambiguous authority'),
    ('ws://[::1/socket', {}, False, 'unbalanced ipv6 bracket must not crash'),
    ('ws://a..b/socket', {}, False, 'empty DNS label must not crash'),
    ('ws://１２７．０．０．１/socket', {}, False, 'fullwidth-digit IDN normalizes to the loopback literal'),
]


class FakeWebSocketRoute:
    def __init__(self, url):
        self.url = url
        self.connected = False
        self.closed = None

    def connect_to_server(self):
        self.connected = True

    def close(self, code=None, reason=None):
        self.closed = (code, reason)


class FakeContext:
    """Captures the handler `_install_websocket_guard` registers."""

    def __init__(self):
        self.handler = None
        self.pattern = None

    def route_web_socket(self, pattern, handler):
        self.pattern = pattern
        self.handler = handler


def main():
    failures = []

    for url, mapping, expect_allowed, note in WS_CASES:
        resolve = resolver_for(mapping)
        try:
            _validate_ws_target(url, resolve)
            raised = False
        except UnsafeURLError:
            raised = True
        except Exception as exc:  # noqa: BLE001 - escaping as any other type IS the failure
            failures.append(f'_validate_ws_target({url!r}) raised {exc!r}, expected UnsafeURLError  [{note}]')
            continue
        if raised == expect_allowed:
            failures.append(
                f'_validate_ws_target({url!r}) raised={raised}, '
                f'expected raised={not expect_allowed}  [{note}]'
            )

    # Same table through the installed handler: connect_to_server is what actually
    # opens the connection, so a blocked target must never reach it.
    for url, mapping, expect_allowed, note in WS_CASES:
        scan = {'blocked_requests': []}
        context = FakeContext()
        _install_websocket_guard(context, scan, resolver_for(mapping), set())
        if context.handler is None:
            failures.append('_install_websocket_guard registered no route_web_socket handler')
            break
        ws_route = FakeWebSocketRoute(url)
        context.handler(ws_route)

        if expect_allowed:
            if not ws_route.connected:
                failures.append(f'handler({url!r}) did not connect_to_server  [{note}]')
            if ws_route.closed is not None:
                failures.append(f'handler({url!r}) closed an allowed route  [{note}]')
            if scan['blocked_requests']:
                failures.append(f'handler({url!r}) logged a block for an allowed route  [{note}]')
        else:
            if ws_route.connected:
                failures.append(f'handler({url!r}) DIALED a blocked target  [{note}]')
            if ws_route.closed is None:
                failures.append(f'handler({url!r}) did not close a blocked route  [{note}]')
            if len(scan['blocked_requests']) != 1:
                failures.append(
                    f'handler({url!r}) recorded {scan["blocked_requests"]!r}, expected one block  [{note}]'
                )
            else:
                entry = scan['blocked_requests'][0]
                if entry.get('kind') != 'blocked':
                    failures.append(f'handler({url!r}) recorded kind={entry.get("kind")!r}, expected "blocked"')

    # A raising route must not propagate out of the handler into Playwright.
    class ExplodingRoute(FakeWebSocketRoute):
        def connect_to_server(self):
            raise RuntimeError('socket already gone')

        def close(self, code=None, reason=None):
            raise RuntimeError('socket already gone')

    for url in ('wss://example.com/socket', 'ws://127.0.0.1/socket'):
        scan = {'blocked_requests': []}
        context = FakeContext()
        _install_websocket_guard(context, scan, resolver_for({'example.com': PUBLIC}), set())
        try:
            context.handler(ExplodingRoute(url))
        except Exception as exc:  # noqa: BLE001 - this IS the assertion
            failures.append(f'handler({url!r}) propagated {exc!r} from a dead route')

    # Deduped on the shared seen-set: a page retrying the same unsafe socket must
    # not flood blocked_requests.
    scan = {'blocked_requests': []}
    context = FakeContext()
    _install_websocket_guard(context, scan, resolver_for({}), set())
    for _ in range(3):
        context.handler(FakeWebSocketRoute('ws://127.0.0.1/socket'))
    if len(scan['blocked_requests']) != 1:
        failures.append(
            f'repeated blocks recorded {len(scan["blocked_requests"])} entries, expected 1 (deduped)'
        )

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(
        f'PASS: {len(WS_CASES)} ws validation + {len(WS_CASES)} ws handler '
        f'+ 2 dead-route + 1 dedupe cases'
    )


if __name__ == '__main__':
    main()
