"""PDF structure inspection.

Every case here came from running a real PDF engine (Apple PDFKit/CoreGraphics and
pypdf) against a constructed file, not from reading the PDF specification. The
normalization cases in particular encode behaviour that a plausible-looking
implementation gets wrong in a way that invents findings.
"""
import json
import os
import re
import sys
import tempfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.utils import pdf_inspect

# Unfiltered reference lexer for test_prefilter_agrees_with_a_full_scan. Deliberately a
# separate copy: comparing the prefilter against itself would prove nothing.
_REFERENCE_NAME = re.compile(rb'/([^\x00\t\n\x0c\r ()<>\[\]{}/%]*)')

failures = []
cases = 0


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


def test_name_normalization_is_a_single_pass():
    """A `while '#' in s` loop would turn `J#2361vaScript` into `JavaScript`, which no
    reader does. CoreGraphics resolves `/Ti#2323le` to `Ti#23le`: the output of a
    decode is never re-scanned."""
    for raw, want in (
        (b'Ti#74le', b'Title'),
        (b'#54#69#74#6C#65', b'Title'),
        (b'Ti#74#6ce', b'Title'),          # hex digits are case-insensitive
        (b'Ti#74#6Ce', b'Title'),
        (b'Ti#2Fle', b'Ti/le'),            # a decoded '/' does not split the name
        (b'Ti#2323le', b'Ti#23le'),        # THE single-pass regression
        (b'J#2361vaScript', b'J#61vaScript'),
        (b'Title#20', b'Title '),          # trailing space is retained
        (b'Title#', b'Title#'),            # lone '#' is literal
        (b'Ti#zzle', b'Ti#zzle'),          # invalid hex stays literal
        (b'JavaScript', b'JavaScript'),    # no '#' at all
    ):
        got = pdf_inspect._normalize_name(raw)
        check(got == want,
              f'_normalize_name({raw!r}) -> {got!r}, expected {want!r}')


def build_pdf(body, header=b'%PDF-1.7\n', trailer=True):
    """A minimal syntactically-plausible PDF. Not valid enough for a reader, valid
    enough for byte-level detection, which is all this module does."""
    out = [header, body]
    if trailer:
        out.append(b'\ntrailer\n<< /Size 1 >>\nstartxref\n0\n%%EOF\n')
    return b''.join(out)


def counts_for(data):
    return pdf_inspect.count_names(data)


def test_prefix_collisions_do_not_count():
    """`/JSX` is not `/JS`. Substring matching produced five false positives on this
    exact input."""
    data = build_pdf(b'1 0 obj << /JSX 1 /AAA 2 /Launcher 3 /URIs 4 /EmbeddedFiles 5 >> endobj')
    got = counts_for(data)
    for name in (b'JS', b'AA', b'Launch', b'URI', b'EmbeddedFile'):
        check(got.get(name, {}).get('total', 0) == 0,
              f'{name!r} was counted from a longer name that merely starts with it')


def test_font_subset_tag_is_not_an_auto_action():
    """The highest-frequency real-world false positive: every subsetted font carries a
    six-uppercase-letter prefix and many begin AAAAAA. This fired on 38% of benign
    files under substring matching."""
    data = build_pdf(b'1 0 obj << /BaseFont /AAAAAA+Lato-Heavy >> endobj')
    check(counts_for(data).get(b'AA', {}).get('total', 0) == 0,
          'a font subset tag was counted as /AA')


def test_hex_obfuscated_keywords_are_found_and_flagged():
    data = build_pdf(b'1 0 obj << /J#61vaScript 1 /OpenActio#6E 2 >> endobj')
    got = counts_for(data)
    check(got.get(b'JavaScript', {}).get('total') == 1,
          'a hex-escaped /JavaScript was not detected')
    check(got.get(b'JavaScript', {}).get('hex') == 1,
          'a hex-escaped /JavaScript was not flagged as obfuscated')
    check(got.get(b'OpenAction', {}).get('total') == 1,
          'a hex-escaped /OpenAction was not detected')


def test_keywords_in_body_text_still_count():
    """This is deliberate, not a bug. Suppressing hits by context is a one-byte
    evasion: see the module docstring. A hit in body text is a hit."""
    data = build_pdf(b'1 0 obj << /Type /Page >> stream\n(The word /JavaScript appears here)\nendstream endobj')
    check(counts_for(data).get(b'JavaScript', {}).get('total', 0) >= 1,
          'a keyword inside a stream body was suppressed; context must not hide counts')


def test_prefilter_agrees_with_a_full_scan():
    """The prefilter exists for speed and is a correctness surface: an off-by-one in
    it silently dropped 8 of 11 signals during design while passing a casual eyeball.
    This compares it against an unfiltered reference scan over adversarial input."""
    data = build_pdf(
        b'1 0 obj << /J#61vaScript 1 /OpenActio#6E 2 /Laun#63h 3 /#41#41 4 '
        b'/E#6DbeddedFile 5 /Ri#63hMedia 6 /U#52I 7 /AcroFor#6D 8 /X#46A 9 '
        b'/En#63rypt 10 /Ob#6AStm 11 >> endobj')

    reference = {}
    for match in _REFERENCE_NAME.finditer(data):
        name = pdf_inspect._normalize_name(match.group(1))
        if name in pdf_inspect.KEYWORDS:
            reference[name] = reference.get(name, 0) + 1

    fast = {k: v['total'] for k, v in pdf_inspect.count_names(data).items()}
    check(fast == reference,
          f'prefiltered scan {fast} disagrees with reference scan {reference}')
    check(len(reference) == 11,
          f'the fixture should carry 11 distinct keywords, reference found {len(reference)}')


def test_prefilter_length_bound_admits_a_fully_escaped_name():
    """The exact off-by-one the design hit. `_MAX_NAME` is 3x the longest keyword
    because every byte of a name may be written as `#XX`, so a fully escaped
    /ASCIIHexDecode is the longest name that can still be a keyword. It sits ON the
    bound, which is where a `>=` would silently drop it.

    The second half proves the fast path is really being taken: names the prefilter
    rejects must be exactly the names the reference scan also discards."""
    longest = max(pdf_inspect.KEYWORDS, key=len)
    escaped = b''.join(b'#%02X' % byte for byte in longest)
    check(len(escaped) == pdf_inspect._MAX_NAME,
          f'fixture is wrong: {len(escaped)} bytes is not the _MAX_NAME bound')

    data = build_pdf(b'1 0 obj << /' + escaped + b' 1 /Type /Page /Contents 3 0 R '
                     b'/' + escaped + b'ZZZ 4 >> endobj')
    got = pdf_inspect.count_names(data)
    check(got.get(longest, {}).get('total') == 1,
          f'a fully hex-escaped /{longest.decode()} was dropped by the length bound')
    check(got.get(longest, {}).get('hex') == 1,
          'a fully hex-escaped name was not flagged as obfuscated')

    reference = {}
    for match in _REFERENCE_NAME.finditer(data):
        name = pdf_inspect._normalize_name(match.group(1))
        if name in pdf_inspect.KEYWORDS:
            reference[name] = reference.get(name, 0) + 1
    check({k: v['total'] for k, v in got.items()} == reference,
          f'prefiltered scan {got} disagrees with reference scan {reference}')


def main():
    test_name_normalization_is_a_single_pass()
    test_prefix_collisions_do_not_count()
    test_font_subset_tag_is_not_an_auto_action()
    test_hex_obfuscated_keywords_are_found_and_flagged()
    test_keywords_in_body_text_still_count()
    test_prefilter_agrees_with_a_full_scan()
    test_prefilter_length_bound_admits_a_fully_escaped_name()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
