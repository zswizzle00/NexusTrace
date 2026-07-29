"""Regression tests for `_is_main_frame_navigation`.

Only the driven page's own main frame may write `nav_state`: `primary_host` comes
from `nav_state['final_url']`, so an iframe or popup that gets through falsifies
the report's DNS/TLS/ASN/PTR/WHOIS.

Fake request/frame/page objects - no Playwright, no Chromium. Playwright's own
frame semantics were verified separately against real Chromium; this pins only
that the gate reads them correctly and fails closed.
"""

import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))

from app.services.scan_service import _is_main_frame_navigation


class Frame:
    def __init__(self, parent=None):
        self.parent_frame = parent


class Page:
    def __init__(self, main_frame):
        self.main_frame = main_frame


class Request:
    def __init__(self, frame, is_nav=True):
        self._frame = frame
        self._is_nav = is_nav

    def is_navigation_request(self):
        return self._is_nav

    @property
    def frame(self):
        if isinstance(self._frame, Exception):
            raise self._frame
        return self._frame


class RaisingPage:
    @property
    def main_frame(self):
        raise RuntimeError('page closed')


def main():
    main_frame = Frame()
    page = Page(main_frame)
    cases = []

    def check(label, request, target_page, expected):
        got = _is_main_frame_navigation(request, target_page)
        assert got is expected, f'{label}: got {got}, expected {expected}'
        cases.append(label)

    check('driven main frame navigation', Request(main_frame), page, True)
    check('same frame, not a navigation', Request(main_frame, is_nav=False), page, False)

    check('iframe document request', Request(Frame(parent=main_frame)), page, False)

    # parent_frame is None for these too, so frame identity - not depth - is the
    # only thing that can discriminate a popup from the driven page.
    check('popup main frame', Request(Frame()), page, False)
    check('popup nested iframe', Request(Frame(parent=Frame())), page, False)

    # Fail-closed paths.
    check('page not yet created', Request(main_frame), None, False)
    check('frame raises', Request(RuntimeError('no frame yet')), page, False)
    check('page.main_frame raises', Request(main_frame), RaisingPage(), False)

    print(f'PASS: {len(cases)} nav-gate cases')


if __name__ == '__main__':
    main()
