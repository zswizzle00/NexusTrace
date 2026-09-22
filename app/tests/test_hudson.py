"""Pins app/services/hudson.py. No network: every case injects a fake fetch.

Written against the endpoint rather than user-scanner's wrapper, because that wrapper
(core/hudson.py:run_hudson_scan) only prints to stdout and returns None, so there is no
structured value to consume. Implementing it here also puts the hostname in the service
layer as a string literal, which is what test_disclosure.py walks, so the breach lookup
cannot ship undisclosed.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.services.hudson import lookup, map_response

failures = []
cases = 0


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=''):
        self.status_code = status_code
        self._payload = payload
        self.text = text
        self.content = text.encode()

    def json(self):
        if self._payload is None:
            raise ValueError('no json')
        return self._payload


STEALER_PAYLOAD = {
    'stealers': [
        {'stealer_family': 'RedLine', 'date_compromised': '2025-04-02',
         'operating_system': 'Windows 10', 'computer_name': 'DESKTOP-ABC',
         'antiviruses': ['Defender'], 'top_logins': ['a@b.test', 'c@d.test']},
    ]
}


def test_maps_a_stealer_hit():
    mapped = map_response(STEALER_PAYLOAD)
    check(mapped['exposed'] is True, 'a stealer record did not map to exposed=True')
    check(mapped['count'] == 1, f'count={mapped["count"]!r}, expected 1')
    first = mapped['infections'][0]
    check(first['family'] == 'RedLine', f'family={first["family"]!r}')
    check(first['date'] == '2025-04-02', f'date={first["date"]!r}')


def test_maps_no_hit():
    mapped = map_response({'stealers': []})
    check(mapped['exposed'] is False, 'an empty stealer list did not map to exposed=False')
    check(mapped['count'] == 0, f'count={mapped["count"]!r}, expected 0')


def test_404_is_not_an_error():
    """Hudson Rock returns 404 for an identifier it has never seen. That is a finding,
    not a failure, and must not surface as a broken source."""
    result = lookup('alice', fetch=lambda url, **kw: FakeResponse(status_code=404))
    check(result is not None, 'a 404 was treated as an unreachable source')
    check(result.get('exposed') is False,
          f'a 404 mapped to exposed={result.get("exposed")!r}, expected False')


def test_unreachable_returns_none():
    def boom(url, **kwargs):
        raise OSError('connection refused')

    check(lookup('alice', fetch=boom) is None,
          'an unreachable source did not return None')


def test_server_error_returns_none():
    check(lookup('alice', fetch=lambda url, **kw: FakeResponse(status_code=503)) is None,
          'a 503 did not return None')


def test_unreadable_body_returns_none():
    check(lookup('alice', fetch=lambda url, **kw: FakeResponse(payload=None)) is None,
          'an unparseable body did not return None')


def test_email_and_username_use_different_endpoints():
    seen = []

    def capture(url, **kwargs):
        seen.append(url)
        return FakeResponse(payload={'stealers': []})

    lookup('alice', is_email=False, fetch=capture)
    lookup('a@b.test', is_email=True, fetch=capture)
    check(any('search-by-username' in u for u in seen),
          f'no username endpoint was called: {seen}')
    check(any('search-by-email' in u for u in seen),
          f'no e-mail endpoint was called: {seen}')


def test_no_credentials_are_returned():
    """top_logins can contain other people's addresses. The mapping keeps the count and
    the family, not the logins: this surface reports exposure, it does not redistribute
    the contents of a stealer log."""
    mapped = map_response(STEALER_PAYLOAD)
    rendered = repr(mapped)
    for leaked in ('a@b.test', 'c@d.test', 'top_logins'):
        check(leaked not in rendered,
              f'map_response leaked {leaked!r} from the stealer log')


def test_kept_fields_are_bounded_plain_strings():
    """Cavalier is a third-party feed. The mapping cannot know whether a value it
    keeps holds something sensitive, but it can guarantee the value is a short plain
    string rather than a nested object that reaches a template as its repr."""
    payload = {'stealers': [{
        'stealer_family': 'RedLine',
        'date_compromised': '2025-04-02',
        'operating_system': 'x' * 5000,
        'computer_name': {'password': 'hunter2'},
        'antiviruses': ['Defender', {'cc': '4111111111111111'},
                        ['nested', 'list'], None, 'y' * 5000],
    }]}
    infection = map_response(payload)['infections'][0]

    for field in ('family', 'date', 'operating_system', 'computer_name'):
        value = infection[field]
        check(isinstance(value, str),
              f'{field} came through as {type(value).__name__}, expected str')
        check(len(value) <= 200,
              f'{field} is {len(value)} chars, expected a bounded value')

    for name in infection['antiviruses']:
        check(isinstance(name, str),
              f'an antivirus entry came through as {type(name).__name__}')
        check(len(name) <= 200, f'an antivirus entry is {len(name)} chars')
    check(len(infection['antiviruses']) <= 20,
          f'{len(infection["antiviruses"])} antivirus entries, expected a capped list')


def test_map_response_is_defensive_about_its_own_input():
    """Public interface, so it must not rely on lookup()'s try/except to be safe."""
    for junk in (None, 'a string', 42, [], {'stealers': 'not a list'},
                 {'stealers': ['a string', None, 7]}, {'stealers': [{}]}):
        try:
            result = map_response(junk)
        except Exception as exc:  # noqa: BLE001 - the point of the case
            failures.append(f'map_response({junk!r}) raised {exc!r}')
            continue
        check(isinstance(result, dict) and 'exposed' in result,
              f'map_response({junk!r}) returned {result!r}')


def main():
    test_maps_a_stealer_hit()
    test_maps_no_hit()
    test_404_is_not_an_error()
    test_unreachable_returns_none()
    test_server_error_returns_none()
    test_unreadable_body_returns_none()
    test_email_and_username_use_different_endpoints()
    test_no_credentials_are_returned()
    test_kept_fields_are_bounded_plain_strings()
    test_map_response_is_defensive_about_its_own_input()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
