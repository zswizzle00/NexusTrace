"""Pins app/utils/phone_parse.py. Pure functions: no network, no Flask.

The NANP cases are the reason most of this file exists. libphonenumber ships no carrier
data for the North American Numbering Plan and cannot separate mobile from fixed line
there, so every US and Canadian number comes back FIXED_LINE_OR_MOBILE with an empty
carrier. That is upstream behaviour, not a bug here, and these cases assert it on
purpose: if a future change starts reporting a confident US line type, something is
fabricating it.

The range_holder cases pin the other trap. libphonenumber's carrier lookup returns the
ORIGINAL range holder, not the current carrier, which is wrong for any ported number.
The field is named range_holder here so no caller can render it as "carrier" by
accident, and `range_holder_is_portable` marks the regions where the distinction bites.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.utils.phone_parse import analyze

failures = []
cases = 0


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


# (raw, default_region, expected_e164, expected_region, expected_number_type)
VALID_CASES = [
    ('+12127363100', None, '+12127363100', 'US', 'fixed line or mobile'),
    ('+1 212 736 3100', None, '+12127363100', 'US', 'fixed line or mobile'),
    ('2127363100', 'US', '+12127363100', 'US', 'fixed line or mobile'),
    ('+18002752273', None, '+18002752273', 'US', 'toll free'),
    ('+33612345678', None, '+33612345678', 'FR', 'mobile'),
    ('+4915112345678', None, '+4915112345678', 'DE', 'mobile'),
    ('+442079460958', None, '+442079460958', 'GB', 'fixed line'),
]

# Numbers that parse fine but are not valid allocations. All three were confirmed
# against libphonenumber 9.0.39: each returns is_valid_number() False and
# is_possible_number() True, which is exactly the distinction this surface must show.
INVALID_CASES = [
    ('+1212736310', None),        # one digit short for NANP
    ('+11112223333', None),       # well-formed, but 111 is not an allocated US area code
    ('+441111111111', None),      # same idea outside the NANP
]

# Input that cannot be parsed at all, so analyze() returns ok=False.
UNPARSEABLE_CASES = [
    ('', None),
    ('not a number', None),
    ('2127363100', None),         # national format with no region to resolve it
    # Raises INVALID_COUNTRY_CODE rather than parsing: there is no country calling code
    # 999, so libphonenumber cannot interpret the digits after the plus sign at all.
    ('+999999999999', None),
]


def test_valid_numbers():
    for raw, region, e164, expected_region, expected_type in VALID_CASES:
        result = analyze(raw, region)
        label = f'analyze({raw!r}, {region!r})'
        if not check(result.get('ok'), f'{label} returned ok=False: {result.get("error")!r}'):
            continue
        check(result['valid'] is True, f'{label} reported valid={result["valid"]!r}')
        check(result['e164'] == e164,
              f'{label} e164={result["e164"]!r}, expected {e164!r}')
        check(result['region'] == expected_region,
              f'{label} region={result["region"]!r}, expected {expected_region!r}')
        check(result['number_type'] == expected_type,
              f'{label} number_type={result["number_type"]!r}, expected {expected_type!r}')


def test_nanp_line_type_is_not_resolvable():
    """The load-bearing honesty case. A US number must report that its line type could
    not be resolved offline, so the template renders that rather than an empty field
    a reader would take for 'landline'."""
    result = analyze('+12127363100')
    check(result['line_type_resolvable'] is False,
          'a US number claimed its line type was resolvable offline')
    check(result['range_holder'] == '',
          f'a US number returned range_holder={result["range_holder"]!r}; '
          'libphonenumber ships no NANP carrier data, so this must be empty')
    check(result['range_holder_unavailable_reason'] != '',
          'a US number gave no reason for the missing range holder')

    french = analyze('+33612345678')
    check(french['line_type_resolvable'] is True,
          'a French mobile claimed its line type was unresolvable')
    check(french['range_holder'] != '',
          'a French mobile returned an empty range holder')


def test_range_holder_portability_is_flagged():
    """Every developed market has number portability, so the range holder is routinely
    NOT the current carrier. The flag is what lets the template caveat it."""
    for raw in ('+33612345678', '+4915112345678'):
        result = analyze(raw)
        check(result['range_holder_is_portable'] is True,
              f'analyze({raw!r}) did not flag the range holder as portability-affected')


def test_invalid_numbers():
    for raw, region in INVALID_CASES:
        result = analyze(raw, region)
        label = f'analyze({raw!r}, {region!r})'
        check(result.get('ok') is True, f'{label} should parse, even though invalid')
        check(result.get('valid') is False,
              f'{label} reported valid={result.get("valid")!r}, expected False')


def test_unparseable_input():
    for raw, region in UNPARSEABLE_CASES:
        result = analyze(raw, region)
        label = f'analyze({raw!r}, {region!r})'
        check(result.get('ok') is False,
              f'{label} returned ok=True for input that cannot be parsed')
        check(bool(result.get('error')), f'{label} returned ok=False with no error text')


def test_no_exception_escapes():
    """This feeds a web route, so a hostile string must produce a result dict, never a
    traceback."""
    for raw in ('+' * 200, '\x00\x01', 'a' * 5000, '++1', '+-+-+'):
        try:
            result = analyze(raw)
        except Exception as exc:  # noqa: BLE001 - the point of the case
            failures.append(f'analyze({raw[:20]!r}...) raised {exc!r}')
            continue
        check(isinstance(result, dict), f'analyze({raw[:20]!r}...) did not return a dict')


def main():
    test_valid_numbers()
    test_nanp_line_type_is_not_resolvable()
    test_range_holder_portability_is_flagged()
    test_invalid_numbers()
    test_unparseable_input()
    test_no_exception_escapes()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
