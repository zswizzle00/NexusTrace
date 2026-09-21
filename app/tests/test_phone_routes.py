"""Route-level cases for the phone lookup surface.

The no-verdict case is the one that matters. Every other NexusTrace analysis surface
renders a verdict banner, so the likeliest future regression is someone adding one here
to match. Account presence and allocation data are not a threat signal, and the spec
forbids it.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app import create_app
from app.services.phone_service import build_report

failures = []
cases = 0


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


def build():
    app = create_app()
    app.config['WTF_CSRF_ENABLED'] = False
    return app


def test_form_renders():
    client = build().test_client()
    response = client.get('/phone_analysis')
    check(response.status_code == 200,
          f'GET /phone_analysis returned {response.status_code}, expected 200')


def test_offline_report_needs_no_network():
    """build_report with both live sources disabled must still produce the offline
    tier. This is the promise that a deployment configuring nothing is still useful."""
    report = build_report('+33612345678', live=False)
    check(report['offline']['ok'] is True, 'the offline tier failed for a valid number')
    check(report['offline']['e164'] == '+33612345678',
          f'e164={report["offline"]["e164"]!r}, expected +33612345678')
    check(report['prefix'] is None, 'prefix data was fetched with live=False')
    check(report['spam'] is None, 'spam data was fetched with live=False')


def test_no_verdict_key_anywhere():
    report = build_report('+12127363100', live=False)
    check('verdict' not in report,
          'build_report produced a verdict key; this surface renders no verdict')
    check('score' not in report,
          'build_report produced a score key; this surface renders no score')


def test_the_page_is_reachable_from_the_nav():
    """The feature shipped once with a working route and no nav entry, so it was only
    reachable by typing the URL. Asserting the link exists is what makes "built" and
    "reachable" the same claim."""
    client = build().test_client()
    for path in ('/', '/phone_analysis'):
        body = client.get(path).get_data(as_text=True)
        check('href="/phone_analysis"' in body,
              f'GET {path} renders no nav link to /phone_analysis')


def test_unparseable_input_renders_an_error_not_a_500():
    client = build().test_client()
    response = client.post('/phone_analysis', data={'number': 'not a number'})
    check(response.status_code in (200, 302),
          f'POST with junk returned {response.status_code}, expected 200 or a redirect')


def main():
    test_form_renders()
    test_offline_report_needs_no_network()
    test_no_verdict_key_anywhere()
    test_the_page_is_reachable_from_the_nav()
    test_unparseable_input_renders_an_error_not_a_500()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
