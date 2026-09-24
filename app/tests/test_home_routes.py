"""The landing page must name what the app can actually do.

This exists because the same bug shipped twice. The phone feature went out with a
working route, a working template and passing tests, and no nav entry, so it was
reachable only by typing the URL. Then phone and identity both shipped without being
named in the landing-page copy or the search placeholder, so an analyst had no way to
learn the app accepted them.

"Built" and "discoverable" are different claims, and the tests only covered the first.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app import create_app

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


def _hero_text(body):
    """Just the hero blurb, not the whole document.

    Scoping matters: a body-wide search passes on almost any copy, because the nav
    already links to /phone_analysis and /email_analysis, so the words 'phone' and
    'email' are present whatever the blurb says. Checked against the pre-fix page, the
    unscoped version of this test passed while the blurb named neither.
    """
    heading = body.find('</h1>')
    if heading == -1:
        return ''
    start = body.find('<p', heading)
    end = body.find('</p>', start)
    return body[start:end].lower() if start != -1 and end != -1 else ''


def test_the_landing_page_names_every_routed_indicator():
    """`POST /analyze` auto-detects each of these and routes it. A type the router
    handles but the blurb never mentions is a feature nobody can find."""
    hero = _hero_text(build().test_client().get('/').get_data(as_text=True))
    check(hero, 'the hero blurb was not found; the selector in _hero_text is stale')
    for term in ('ip address', 'domain', 'url', 'hash', 'phone', 'email', 'user-agent'):
        check(term in hero,
              f'the landing-page blurb never mentions {term!r}, which /analyze routes')


def test_the_search_placeholder_names_the_less_obvious_types():
    """IP and domain are guessable. Phone and e-mail are not, and the placeholder is
    the only place an analyst is told to try them."""
    body = build().test_client().get('/').get_data(as_text=True)
    start = body.find('indicator-input')
    check(start != -1, 'the indicator input was not found on the landing page')
    window = body[max(0, start - 600):start + 600].lower()
    for term in ('phone', 'email'):
        check(term in window,
              f'the search placeholder does not mention {term!r}')


def main():
    test_the_landing_page_names_every_routed_indicator()
    test_the_search_placeholder_names_the_less_obvious_types()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
