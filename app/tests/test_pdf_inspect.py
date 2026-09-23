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
    data = build_pdf(b'1 0 obj << /Type /Page >> stream\n'
                     b'(The word /JavaScript appears here)\nendstream endobj')
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


def test_structure_counts_tolerate_binary_noise():
    """Counting bare `obj` mismatched on 3 of 60 benign real PDFs, because the byte
    sequence `obj` occurs inside compressed image data. Anchoring to `<num> <num> obj`
    dropped that to zero while still catching genuinely broken files."""
    data = build_pdf(b'1 0 obj << /Type /Catalog >> endobj\n'
                     b'2 0 obj << /Len 4 >> stream\n\xa2obj\xb3E\nendstream endobj')
    structure = pdf_inspect.count_structure(data)
    check(structure['obj'] == structure['endobj'],
          f"binary noise produced a false obj mismatch: {structure}")


def test_structure_mismatch_is_detected_when_real():
    data = build_pdf(b'1 0 obj << /A 1 >> endobj\n2 0 obj << /B 2 >>\n3 0 obj << /C 3 >>')
    structure = pdf_inspect.count_structure(data)
    check(structure['obj'] > structure['endobj'],
          f'a genuine obj/endobj mismatch was not detected: {structure}')


def test_missing_trailer_is_not_malformed():
    """PDF 1.5 cross-reference streams produce zero `xref` and zero `trailer`, and
    occurred in 5 of 60 real files. Zero is normal, not a defect."""
    data = build_pdf(b'1 0 obj << /Type /XRef >> endobj', trailer=False)
    structure = pdf_inspect.count_structure(data)
    check(structure['trailer'] == 0, 'fixture should have no trailer')
    result = pdf_inspect.analyze_pdf_bytes(data)
    keys = {s['key'] for s in result['signals']}
    check('pdf_structure_mismatch' not in keys,
          'a missing trailer was reported as a structural defect')


def test_flate_streams_reveal_hidden_keywords():
    """Object streams hide objects from raw-byte scanning entirely. Bounded inflation
    recovered every hidden signal in the design corpus while adding exactly one benign
    keyword across 60 real files."""
    hidden = zlib.compress(b'<< /Type /Action /S /JavaScript /JS (app.alert\\(1\\)) >>')
    data = build_pdf(b'1 0 obj << /Type /ObjStm /Filter /FlateDecode >> stream\n'
                     + hidden + b'\nendstream endobj')
    check(pdf_inspect.count_names(data).get(b'JavaScript') is None,
          'fixture is wrong: the keyword should be invisible in the raw bytes')
    result = pdf_inspect.analyze_pdf_bytes(data)
    check(result['keywords'].get('JavaScript', {}).get('total', 0) >= 1,
          'bounded inflation did not recover a keyword hidden in a Flate stream')


def test_object_stream_is_a_coverage_note_not_a_finding():
    """/ObjStm appeared in 5 of 60 ordinary benign PDFs. Reporting it as suspicious
    would be an 8% false-positive rate on normal documents."""
    data = build_pdf(b'1 0 obj << /Type /ObjStm >> endobj')
    signals = {s['key']: s for s in pdf_inspect.analyze_pdf_bytes(data)['signals']}
    check('pdf_object_stream' in signals,
          '/ObjStm was not reported at all; the coverage limit must be visible')
    check(pdf_inspect.SIGNAL_LABELS['pdf_object_stream'].lower().find('incomplete') >= 0,
          'the /ObjStm label should describe a coverage limit, not a finding')


def test_a_decompression_bomb_is_capped():
    """Deflate expands at 1029:1 and is flat across sizes, so 1 MB of stream yields
    1 GB. A bare zlib.decompress() here is a trivial memory kill.

    The bomb has to expand past the budget for this to test anything: a payload that
    fits inside MAX_TOTAL_INFLATE passes whether or not the cap is applied."""
    bomb = zlib.compress(b'\x00' * (64 * 1024 * 1024))
    data = build_pdf(b'1 0 obj << /Filter /FlateDecode >> stream\n' + bomb
                     + b'\nendstream endobj')
    result = pdf_inspect.analyze_pdf_bytes(data)
    check(result['error'] is None, f'a compressed-zeros stream errored: {result["error"]}')
    check(result['inflated_bytes'] <= pdf_inspect.MAX_INFLATE_PER_STREAM,
          f'one stream inflated past its own budget: {result["inflated_bytes"]}')


def test_many_bombs_share_one_total_budget():
    """Per-stream capping alone is not a bound: 2048 streams at 4 MB each is 8 GB.
    The total budget has to stop the walk, and stop it BEFORE the next inflation."""
    bomb = zlib.compress(b'\x00' * (8 * 1024 * 1024))
    stream = b'1 0 obj << /Filter /FlateDecode >> stream\n' + bomb + b'\nendstream endobj\n'
    result = pdf_inspect.analyze_pdf_bytes(build_pdf(stream * 24))
    check(result['error'] is None, f'a multi-stream document errored: {result["error"]}')
    check(result['inflated_bytes'] <= pdf_inspect.MAX_TOTAL_INFLATE,
          f'inflation exceeded the total budget: {result["inflated_bytes"]}')


def write_blob(box, name, blob):
    path = os.path.join(box, name)
    with open(path, 'wb') as handle:
        handle.write(blob)
    return path


def test_degenerate_and_boundary_sizes():
    with tempfile.TemporaryDirectory() as box:
        for name, blob, expect_skip in (
            ('empty.pdf', b'', False),
            ('header_only.pdf', b'%PDF-1.7\n', False),
            ('at_cap.pdf', b'%PDF-1.7\n' + b'a' * (pdf_inspect.MAX_BYTES - 9), False),
            ('over_cap.pdf', b'%PDF-1.7\n' + b'a' * pdf_inspect.MAX_BYTES, True),
        ):
            result = pdf_inspect.analyze_pdf(write_blob(box, name, blob))
            keys = {s['key'] for s in result['signals']}
            check(result['error'] is None, f'{name} produced an error: {result["error"]}')
            if expect_skip:
                check(result['truncated'] is True,
                      f'{name} is over the cap but was not marked truncated')
            else:
                check('analysis_skipped_too_large' not in keys,
                      f'{name} is within the cap but was skipped')


def test_a_capped_read_keeps_the_tail():
    """Head-only truncation lost `startxref` and `trailer` on all five oversized files
    in the design corpus, and a signal on four of them. PDFs put the xref, the trailer
    and the /Encrypt reference at the end."""
    filler = b'%PDF-1.7\n' + b'0' * (pdf_inspect.MAX_BYTES * 2)
    with tempfile.TemporaryDirectory() as box:
        path = write_blob(box, 'big.pdf',
                          filler + b'\n1 0 obj << /J#61vaScript 1 >> endobj\ntrailer\n')
        result = pdf_inspect.analyze_pdf(path)
    check(result['truncated'] is True, 'an oversized file was not marked truncated')
    check(result['keywords'].get('JavaScript', {}).get('total', 0) >= 1,
          'a keyword in the last megabytes was lost; the read must keep the tail')
    check(result['structure']['trailer'] >= 1,
          'the trailer at the end of an oversized file was not seen')


def test_malformed_input_never_raises():
    """A file that is not a PDF, or is a broken one, must produce a record rather than
    an exception. The analyzer runs inside a request."""
    blobs = {
        'random.pdf': b'%PDF-1.7\n' + bytes(range(256)) * 80,
        'no_eof.pdf': b'%PDF-1.7\n1 0 obj << /A 1 >> endobj',
        'unbalanced.pdf': b'%PDF-1.7\n1 0 obj << /JS 1 >> stream\nnever closed',
        'nul.pdf': b'%PDF-1.7\n' + b'\x00' * 4096,
        'not_pdf.pdf': b'GIF89a' + b'\xff' * 512,
    }
    with tempfile.TemporaryDirectory() as box:
        for name, blob in blobs.items():
            path = write_blob(box, name, blob)
            try:
                result = pdf_inspect.analyze_pdf(path)
            except Exception as exc:                      # noqa: BLE001 - that is the point
                failures.append(f'{name} raised {type(exc).__name__}: {exc}')
                continue
            check(isinstance(result, dict), f'{name} did not return a record')

    # An unterminated stream must still yield its keyword: suppressing by context is
    # a one-byte evasion.
    data = b'%PDF-1.7\n1 0 obj << /JS 1 >> stream\nnever closed'
    check(pdf_inspect.count_names(data).get(b'JS', {}).get('total', 0) >= 1,
          'an unterminated stream hid a keyword from counting')


def test_a_missing_file_is_a_record_not_an_exception():
    absent = os.path.join(tempfile.gettempdir(), 'nexustrace-absent.pdf')
    result = pdf_inspect.analyze_pdf(absent)
    check(result['error'] is not None, 'an unreadable path reported no error')
    check({s['key'] for s in result['signals']} == {'analysis_error'},
          f'an unreadable path did not emit analysis_error: {result["signals"]}')


def test_the_record_is_json_serializable():
    """The record is written to data/ as a JSON analysis file. count_names keys are
    bytes, and json.dumps raises TypeError on a bytes key, so analyze_pdf_bytes must
    decode them at its boundary."""
    data = build_pdf(b'1 0 obj << /J#61vaScript 1 /Launch 2 /LZWDecode 3 '
                     b'/ObjStm 4 >> endobj')
    with tempfile.TemporaryDirectory() as box:
        path = write_blob(box, 'record.pdf', data)
        try:
            encoded = json.dumps(pdf_inspect.analyze_pdf(path))
        except TypeError as exc:
            failures.append(f'the record is not JSON-serializable: {exc}')
            return
    check('JavaScript' in json.loads(encoded)['keywords'],
          'the serialized record lost its keyword names')


def test_record_is_bounded():
    """Review Focus 2: the record is written to data/ as JSON and rendered. 5000
    objects each carrying /JavaScript must not produce a 5000-entry structure."""
    body = b''.join(b'%d 0 obj << /JavaScript %d >> endobj\n' % (i, i) for i in range(5000))
    result = pdf_inspect.analyze_pdf_bytes(b'%PDF-1.7\n' + body)
    check(result['keywords']['JavaScript']['total'] == 5000,
          'the count itself should be accurate')
    check(len(result['signals']) < 50,
          f'signal list grew with input size: {len(result["signals"])} entries')


def test_every_signal_has_a_label():
    """`_signal` falls back to the bare key, which would render an identifier to an
    analyst. Every key this module can emit needs a label."""
    for key in ('pdf_javascript', 'pdf_auto_action', 'pdf_launch_action',
                'pdf_embedded_file', 'pdf_obfuscated_name', 'pdf_encrypted',
                'pdf_object_stream', 'pdf_structure_mismatch', 'pdf_unhandled_filter',
                'analysis_skipped_too_large', 'analysis_error'):
        check(pdf_inspect.SIGNAL_LABELS.get(key, key) != key,
              f'{key} has no label in SIGNAL_LABELS')


def test_encryption_is_reported_from_the_raw_bytes():
    """An encrypted PDF is opaque to every downstream content scanner, which is why it
    is a known evasion, and `/Encrypt` is visible without decrypting anything.

    This replaces a `pdf_encrypted_no_password` signal that the plan specified and
    weighted but that nothing could ever emit: deciding "no password" needs the
    /Encrypt dictionary and the trailer /ID, so it needs xref resolution. A weight
    nothing can trigger is worse than no weight.
    """
    data = build_pdf(b'1 0 obj << /Filter /Standard /V 1 /R 2 >> endobj\n'
                     b'trailer\n<< /Encrypt 1 0 R /ID [<aa><bb>] >>')
    keys = {s['key'] for s in pdf_inspect.analyze_pdf_bytes(data)['signals']}
    check('pdf_encrypted' in keys, 'a PDF declaring /Encrypt was not reported')
    check('pdf_encrypted_no_password' not in keys,
          'the undeliverable no-password signal is still being emitted')

    clean = build_pdf(b'1 0 obj << /Type /Catalog >> endobj')
    clean_keys = {s['key'] for s in pdf_inspect.analyze_pdf_bytes(clean)['signals']}
    check('pdf_encrypted' not in clean_keys,
          'an unencrypted PDF was reported as encrypted')


def main():
    test_encryption_is_reported_from_the_raw_bytes()
    test_name_normalization_is_a_single_pass()
    test_prefix_collisions_do_not_count()
    test_font_subset_tag_is_not_an_auto_action()
    test_hex_obfuscated_keywords_are_found_and_flagged()
    test_keywords_in_body_text_still_count()
    test_prefilter_agrees_with_a_full_scan()
    test_prefilter_length_bound_admits_a_fully_escaped_name()
    test_structure_counts_tolerate_binary_noise()
    test_structure_mismatch_is_detected_when_real()
    test_missing_trailer_is_not_malformed()
    test_flate_streams_reveal_hidden_keywords()
    test_object_stream_is_a_coverage_note_not_a_finding()
    test_a_decompression_bomb_is_capped()
    test_many_bombs_share_one_total_budget()
    test_degenerate_and_boundary_sizes()
    test_a_capped_read_keeps_the_tail()
    test_malformed_input_never_raises()
    test_a_missing_file_is_a_record_not_an_exception()
    test_the_record_is_json_serializable()
    test_record_is_bounded()
    test_every_signal_has_a_label()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
