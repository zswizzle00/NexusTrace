"""Gating and record shape for the file-analysis pipeline.

The gates are the point. Each document analyser is expensive and at least one of them
is actively dangerous on the wrong input: olevba's Text fallback treats a NUL-free blob
as VBA source and reports a macro for it, so an extension must never be able to promote
a file into a parser. Sniffed magic decides; the extension only narrows.

These are service-level, not route-level: no server, no client, no CSRF.
"""
import json
import os
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.services import file_service

failures = []
cases = 0

PDF_BYTES = b'%PDF-1.7\n1 0 obj << /JS 1 /OpenAction 2 >> endobj\ntrailer\n%%EOF\n'


def check(condition, message):
    global cases
    cases += 1
    if not condition:
        failures.append(message)
    return bool(condition)


def write(box, name, blob):
    path = os.path.join(box, name)
    with open(path, 'wb') as handle:
        handle.write(blob)
    return path


def make_zip(box, name):
    path = os.path.join(box, name)
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('x.txt', 'hi')
    return path


def test_an_extension_cannot_promote_a_file_into_an_analyser():
    with tempfile.TemporaryDirectory() as box:
        record = file_service.analyze_file(write(box, 'invoice.docm', PDF_BYTES),
                                           'invoice.docm')
        check(record['pdf'] is not None,
              'a file whose bytes are a PDF was not analysed as one')
        check(record['office'] is None,
              'a .docm extension promoted a PDF into the Office analyser')

        record = file_service.analyze_file(make_zip(box, 'report.pdf'), 'report.pdf')
        check(record['pdf'] is None,
              'a .pdf extension promoted a ZIP into the PDF analyser')


def test_a_bare_zip_is_not_handed_to_the_office_parser():
    """ZIP is also every .jar, .apk and .zip an analyst uploads. Running a VBA parser
    over each of those costs time and buys nothing."""
    with tempfile.TemporaryDirectory() as box:
        record = file_service.analyze_file(make_zip(box, 'archive.zip'), 'archive.zip')
        check(record['office'] is None, 'a plain .zip reached the Office analyser')


def test_the_record_always_carries_the_three_fields():
    """A plain text file fires no gate. The template tests these fields directly, so
    they must exist as None rather than be absent."""
    with tempfile.TemporaryDirectory() as box:
        record = file_service.analyze_file(write(box, 'notes.txt', b'plain text\n'),
                                           'notes.txt')
        for field in ('office', 'pdf', 'yara'):
            check(field in record, f'{field!r} is missing from the record entirely')
            check(record[field] is None, f'{field!r} ran for a plain text file')


def test_the_record_is_json_serializable():
    """Records are written to data/ as JSON. pdf_inspect counts by bytes keys and YARA
    matched_data is bytes, so both have to be converted before they get here."""
    with tempfile.TemporaryDirectory() as box:
        record = file_service.analyze_file(write(box, 'doc.pdf', PDF_BYTES), 'doc.pdf')
        try:
            json.dumps(record)
        except TypeError as exc:
            failures.append(f'the file record is not JSON-serializable: {exc}')
        check(True, 'json.dumps ran')


def test_pdf_findings_reach_the_verdict():
    """The whole point of the wiring. /JS plus /OpenAction is 0.25 + 0.25, over the
    0.30 floor, so a PDF that runs script on open must not render as benign."""
    with tempfile.TemporaryDirectory() as box:
        record = file_service.analyze_file(write(box, 'doc.pdf', PDF_BYTES), 'doc.pdf')
        level = (record.get('verdict') or {}).get('level') or record.get('level')
        check(level == 'suspicious',
              f'a PDF with automatic JavaScript scored {level!r}, expected suspicious')


def test_an_unreadable_file_still_returns_the_three_fields():
    """The early-error path builds its own record and is easy to forget."""
    record = file_service.analyze_file('/nonexistent/nope.pdf', 'nope.pdf')
    for field in ('office', 'pdf', 'yara'):
        check(field in record, f'the error path drops {field!r} from the record')


def test_operator_rule_metadata_is_escaped_on_the_page():
    """Rule names, authors and tags come from rule files an operator fetched from a
    third party. They are untrusted text that reaches the result page, and the YARA
    card renders all three (the author because DRL 1.1 requires it)."""
    from app import create_app
    app = create_app()
    record = {
        'filename': 'x.bin', 'size_bytes': 3, 'digests': {'md5': '', 'sha1': '', 'sha256': ''},
        'magic_type': None, 'is_executable': False, 'is_archive': False, 'entropy': 0.0,
        'embedded_executables': [], 'strings_sample': [], 'lnk': None, 'iocs': [],
        'reputation': {}, 'truncated': False, 'error': None, 'office': None, 'pdf': None,
        'yara': {'rules_loaded': 1, 'error': None, 'signals': [],
                 'matches': [{'rule': '<script>alert(1)</script>', 'namespace': 'a.yar',
                              'tags': ['<img src=x onerror=alert(2)>'],
                              'author': '<b>evil</b>', 'meta': {}, 'strings': []}]},
        'verdict': {'level': 'unknown', 'score': 0.0, 'signals': []},
    }
    # test_request_context, not app_context: the template calls url_for.
    with app.test_request_context('/file_analysis'):
        body = app.jinja_env.get_template('file_analysis.html').render(
            analysis=record, post_url='/api/file/analyze', submit_url='/api/file/analyze')
    check('<script>alert(1)</script>' not in body,
          'a YARA rule name reached the page unescaped')
    # Assert on the unescaped angle bracket, not on the payload text. A correctly
    # escaped `&lt;img src=x onerror=alert(2)&gt;` still contains the substring
    # "onerror=alert(2)", so checking for that passes on safe and unsafe output alike.
    check('<img src=x' not in body,
          'a YARA tag reached the page unescaped')
    check('&lt;script&gt;' in body,
          'the rule name was dropped rather than escaped; the assertions above would '
          'pass vacuously if the card never rendered')


def main():
    test_an_extension_cannot_promote_a_file_into_an_analyser()
    test_a_bare_zip_is_not_handed_to_the_office_parser()
    test_the_record_always_carries_the_three_fields()
    test_the_record_is_json_serializable()
    test_pdf_findings_reach_the_verdict()
    test_an_unreadable_file_still_returns_the_three_fields()
    test_operator_rule_metadata_is_escaped_on_the_page()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
