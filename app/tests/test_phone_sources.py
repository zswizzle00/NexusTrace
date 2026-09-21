"""Pins app/services/phone_service.py response handling. No network: every case drives
the parser directly or injects a fake fetch.

The SkipCalls cases carry the important judgement. Its database flags legitimate
high-volume corporate lines, so a true `is_spam` means only "this number appears in a
crowd-report database". map_spam_response() must therefore never emit a verdict word,
and the reported-only case asserts exactly that.

The LocalCallingGuide fixture keeps its real DTD preamble. The live endpoint returns
about 250 lines of HTML entity declarations before the payload, and a parser written
against a trimmed fixture would work in tests and fail in production.
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.services.phone_service import (map_spam_response, parse_prefix_xml,
                                        prefix_lookup, spam_lookup)

failures = []
cases = 0


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


# Trimmed to two entities, but the shape is the real one: an XML declaration, a DOCTYPE
# with an internal subset, then the payload.
PREFIX_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY Aacute           "&#x000C1;" >
<!ENTITY aacute           "&#x000E1;" >
]>
<root>
<prefixdata>
<npa>212</npa>
<nxx>736</nxx>
<x>A</x>
<exch>136090</exch>
<rc>New York City Zone 01</rc>
<region>NY</region>
<switch>NYCMNY36DS1</switch>
<switchname>MANHATTAN 36TH ST</switchname>
<switchtype>5E</switchtype>
<ocn>9104</ocn>
<company-name>VERIZON NEW YORK, INC.</company-name>
<company-type>I</company-type>
<ilec-ocn>9104</ilec-ocn>
<ilec-name>VERIZON NEW YORK, INC.</ilec-name>
<lata>132</lata>
<lir></lir>
<rc-lat>40.739362</rc-lat>
<rc-lon>-73.991043</rc-lon>
<effdate></effdate>
<discdate></discdate>
<udate>2024-01-14 02:49:04</udate>
</prefixdata>
</root>
'''

# An unassigned prefix: well-formed, with no <prefixdata> at all.
PREFIX_XML_EMPTY = '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY Aacute           "&#x000C1;" >
]>
<root>
</root>
'''


def test_prefix_xml_parses_the_real_shape():
    parsed = parse_prefix_xml(PREFIX_XML)
    if not check(parsed is not None, 'parse_prefix_xml returned None for a real record'):
        return
    expected = {
        'npa': '212', 'nxx': '736', 'ocn': '9104',
        'company_name': 'VERIZON NEW YORK, INC.',
        'company_type': 'I',
        'company_type_label': 'ILEC',
        'rate_center': 'New York City Zone 01',
        'region': 'NY',
        'lata': '132',
        'switch': 'NYCMNY36DS1',
    }
    for key, want in expected.items():
        check(parsed.get(key) == want,
              f'parse_prefix_xml {key}={parsed.get(key)!r}, expected {want!r}')


def test_prefix_xml_company_type_labels():
    """company-type is the field that gives NANP the mobile/VOIP/landline signal
    libphonenumber cannot. A wrong label here is wrong intel, not cosmetics."""
    for code, want in (('I', 'ILEC'), ('C', 'CLEC'), ('W', 'wireless')):
        xml = PREFIX_XML.replace('<company-type>I</company-type>',
                                 f'<company-type>{code}</company-type>')
        parsed = parse_prefix_xml(xml)
        check(parsed and parsed.get('company_type_label') == want,
              f'company-type {code!r} labelled '
              f'{(parsed or {}).get("company_type_label")!r}, expected {want!r}')

    xml = PREFIX_XML.replace('<company-type>I</company-type>',
                             '<company-type>Z</company-type>')
    parsed = parse_prefix_xml(xml)
    check(parsed and parsed.get('company_type_label') == '',
          'an unknown company-type was given a label instead of being left blank')


def test_prefix_xml_unassigned_returns_none():
    check(parse_prefix_xml(PREFIX_XML_EMPTY) is None,
          'an unassigned prefix did not return None')


def test_prefix_xml_garbage_returns_none():
    for text in ('', 'not xml', '<root><unclosed>'):
        check(parse_prefix_xml(text) is None,
              f'parse_prefix_xml({text[:20]!r}) did not return None for unparseable input')


def test_prefix_xml_never_fetches_external_entities():
    """XXE. The parser must not read a local file named by an external entity. The
    stdlib parser does not resolve external references at all, and this case is what
    keeps that true across parser versions rather than leaving it incidental."""
    xxe = ('<?xml version="1.0"?>\n<!DOCTYPE root [\n'
           '<!ENTITY x SYSTEM "file:///etc/passwd">\n]>\n'
           '<root><prefixdata><rc>&x;</rc></prefixdata></root>')
    parsed = parse_prefix_xml(xxe)
    if parsed is None:
        check(True, 'external entity document rejected')
        return
    check('root:' not in (parsed.get('rate_center') or ''),
          'parse_prefix_xml resolved an external entity and leaked file contents')


def test_prefix_xml_refuses_entity_expansion():
    """Billion laughs. A few hundred bytes must not become megabytes in a process that
    runs one gunicorn worker. Asserts the OUTCOME: no giant string reaches the caller."""
    bomb = '<?xml version="1.0"?>\n<!DOCTYPE root [\n<!ENTITY a0 "AAAAAAAAAA">\n'
    for i in range(1, 7):
        bomb += '<!ENTITY a%d "%s">\n' % (i, ''.join('&a%d;' % (i - 1) for _ in range(10)))
    bomb += ']>\n<root><prefixdata><rc>&a6;</rc></prefixdata></root>'

    parsed = parse_prefix_xml(bomb)
    expanded = (parsed or {}).get('rate_center') or ''
    check(len(expanded) < 10000,
          f'entity expansion produced {len(expanded)} chars from {len(bomb)} bytes of input')


def test_prefix_lookup_fails_soft():
    """A dead source must remove the card, never raise."""
    def boom(url, timeout=None):
        raise OSError('connection refused')

    check(prefix_lookup('2127363100', fetch=boom) is None,
          'prefix_lookup raised or returned a value when the source was unreachable')


def test_spam_response_is_reported_not_a_verdict():
    """Measured false positive: SkipCalls flags Apple's real support line. The mapping
    must therefore describe a report, and must not emit a verdict word."""
    mapped = map_spam_response({'number': '8002752273', 'is_spam': True,
                                'status_code': 181, 'status_description': 'unknown'})
    check(mapped['reported'] is True, 'a flagged number did not map to reported=True')
    check(mapped['category'] == 'unknown',
          f'category={mapped["category"]!r}, expected the source status_description')
    rendered = ' '.join(str(v) for v in mapped.values()).lower()
    for banned in ('malicious', 'verdict', 'threat', 'dangerous'):
        check(banned not in rendered,
              f'map_spam_response emitted the verdict word {banned!r}')


def test_spam_response_clean():
    mapped = map_spam_response({'number': '4084961000', 'is_spam': False})
    check(mapped['reported'] is False, 'an unflagged number did not map to reported=False')
    check(mapped['category'] == '', 'an unflagged number was given a category')


def test_spam_lookup_fails_soft():
    def boom(url, timeout=None):
        raise OSError('connection refused')

    check(spam_lookup('2127363100', fetch=boom) is None,
          'spam_lookup raised or returned a value when the source was unreachable')


class FakeResponse:
    def __init__(self, status_code=200, text='', content=None):
        self.status_code = status_code
        self.text = text
        self.content = content if content is not None else text.encode()


def test_oversized_responses_are_refused():
    """One gunicorn worker serves every request, so a single huge third-party body
    must never be parsed. Both bodies below are VALID and parse into a real result
    when the cap is removed: that is what makes this a test rather than a coincidence.
    An earlier version padded with junk that failed to parse anyway, so it passed
    with the cap absent and proved nothing.
    """
    padding = 'x' * (300 * 1024)

    big_xml = PREFIX_XML.replace('New York City Zone 01', padding)
    check(prefix_lookup('2127363100',
                        fetch=lambda u, timeout=None: FakeResponse(text=big_xml)) is None,
          'prefix_lookup parsed a valid but oversized XML body')

    big_json = json.dumps({'number': '2127363100', 'is_spam': True,
                           'status_description': padding})
    check(spam_lookup('2127363100',
                      fetch=lambda u, timeout=None: FakeResponse(text=big_json)) is None,
          'spam_lookup parsed a valid but oversized JSON body')


def test_malformed_response_objects_do_not_raise():
    """A response lacking the attributes we read must yield no card, not an exception."""
    class Nothing:
        pass

    for name, fn in (('prefix_lookup', prefix_lookup), ('spam_lookup', spam_lookup)):
        try:
            result = fn('2127363100', fetch=lambda u, timeout=None: Nothing())
        except Exception as exc:  # noqa: BLE001 - the point of the case
            failures.append(f'{name} raised {exc!r} on a malformed response object')
            continue
        check(result is None, f'{name} returned {result!r} for a malformed response')


def main():
    test_prefix_xml_parses_the_real_shape()
    test_prefix_xml_company_type_labels()
    test_prefix_xml_unassigned_returns_none()
    test_prefix_xml_garbage_returns_none()
    test_prefix_xml_never_fetches_external_entities()
    test_prefix_xml_refuses_entity_expansion()
    test_prefix_lookup_fails_soft()
    test_spam_response_is_reported_not_a_verdict()
    test_spam_response_clean()
    test_spam_lookup_fails_soft()
    test_oversized_responses_are_refused()
    test_malformed_response_objects_do_not_raise()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
