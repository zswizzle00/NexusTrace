"""Office document inspection: container type, encryption, and VBA macro signals.

Pure module, no Flask import, so ``app/tests/test_office_inspect.py`` runs it with no
server. Five things here are not stylistic:

1. ``disable_pcode=True`` on every VBA_Parser. oletools is BSD but its mandatory
   dependency pcodedmp is GPLv3, and the default ``analyze_macros()`` path imports and
   executes it. With the flag it never enters ``sys.modules``, and results are identical.

2. Signals gate on ``parser.type`` BEFORE anything else. ``detect_vba_macros()`` returns
   True for a NUL-free binary blob renamed ``.docm``: olevba falls back to ``TYPE_TEXT``
   and treats the whole file as VBA source, yielding one "macro" that is the file. A blob
   that does contain NULs is refused outright with ``FileOpenError``, which is the same
   fact and renders the same way.

3. ``analyze_macros()`` returns None, not [], when there is no VBA code. Iterating it
   directly raises TypeError in production.

4. A bare ``except Exception`` is required. Malformed OLE escapes as a builtins
   AttributeError from olefile via ppt_parser, so ``except OlevbaBaseException`` is not
   enough.

5. The decompression budget runs BEFORE VBA_Parser is constructed, not after. The 4 MB
   input cap applies to the compressed upload and does not bound what parsing expands it
   into.

The counters (``nb_macros``, ``nb_suspicious``) are deliberately unused: ``nb_suspicious``
reported 20 while 18 rows were emitted. Counts come from the returned list.
"""
import logging
import os
import threading
import zipfile

logger = logging.getLogger(__name__)

MAX_BYTES = 4 * 1024 * 1024

# A 93 KB .docm carrying a valid OLE object padded with zeros drove a 304 MB peak RSS
# and completed with NO exception: ~3250x on-disk amplification. The input cap does not
# bound this, because the cap applies to the compressed upload. This does.
MAX_DECOMPRESSED_BYTES = 64 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200

# The measured worst case is ~5.2 s of CPU at the 4 MB cap, and signal.alarm does not
# fire on gunicorn worker threads, so the cap is the time bound. This stops N
# concurrent uploads from multiplying the memory budget by N.
MAX_CONCURRENT = 2
_slots = threading.BoundedSemaphore(MAX_CONCURRENT)

OFFICE_TYPES = ('OLE', 'OpenXML', 'Word2003_XML', 'FlatOPC_XML', 'MHTML', 'PPT', 'SLK')

SIGNAL_LABELS = {
    'office_has_macro': 'Document contains a VBA macro',
    'office_autoexec_macro': 'Macro runs automatically when the document opens',
    'office_obfuscated_vba': 'Macro hides strings behind hex, base64 or character maths',
    'office_download_cradle': 'Macro downloads a file from the internet',
    'office_shell_execution': 'Macro runs a program or system command',
    'office_encrypted': 'Document is encrypted, so its contents could not be examined',
    'office_not_office_container': 'File is named as an Office document but is not one',
    'analysis_skipped_too_large': 'File was too large to examine',
    'analysis_busy': 'Analysis was skipped because the analyser was saturated',
    'analysis_error': 'Analysis failed',
}

# Verified literal descriptions from olevba's SUSPICIOUS_KEYWORDS table.
_SHELL_DESCRIPTIONS = frozenset((
    'May run an executable file or a system command',
    'May run PowerShell commands',
    'May run an executable file or a system command using PowerShell',
    'May run an executable file or a system command on a Mac',
    'May run a dll',
    'May run code from a DLL',
    'May run code from a library on a Mac',
    'May execute file or a system command through WMI',
))
_OBFUSCATION_ITEMS = frozenset(('Hex Strings', 'Base64 Strings', 'VBA obfuscated Strings'))


def _signal(key, detail=None):
    return {'key': key, 'label': SIGNAL_LABELS.get(key, key), 'detail': detail}


def _empty(**overrides):
    record = {'container': None, 'encrypted': False, 'has_macro': False,
              'modules': [], 'signals': [], 'error': None}
    record.update(overrides)
    return record


def _zip_budget_ok(path):
    """`(ok, detail)`. Reject before parsing on total decompressed size or per-entry
    ratio. Not a ZIP at all is fine: OLE documents are not zipped."""
    try:
        with zipfile.ZipFile(path) as archive:
            total = 0
            for info in archive.infolist():
                total += info.file_size
                if total > MAX_DECOMPRESSED_BYTES:
                    return False, f'decompressed size exceeds {MAX_DECOMPRESSED_BYTES} bytes'
                if info.compress_size and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO:
                    return False, f'entry {info.filename!r} expands more than {MAX_COMPRESSION_RATIO}x'
    except (zipfile.BadZipFile, OSError):
        return True, None
    return True, None


def _signals_from_results(results):
    """`results` rows are `(kind, item, desc)`, all plain strings with inconsistent
    casing. Match on `kind` and on description prefixes, never on the keyword lists:
    olevba appends an obfuscation suffix to descriptions when deobfuscation runs."""
    signals = []
    kinds = {kind for kind, _item, _desc in results}

    if 'AutoExec' in kinds:
        triggers = sorted({item for kind, item, _ in results if kind == 'AutoExec'})
        signals.append(_signal('office_autoexec_macro', ', '.join(triggers)))

    suspicious = [(item, desc) for kind, item, desc in results if kind == 'Suspicious']

    if any(item in _OBFUSCATION_ITEMS or desc.startswith('May attempt to obfuscate')
           for item, desc in suspicious):
        signals.append(_signal('office_obfuscated_vba'))

    if any(desc.startswith('May download files from the Internet') for _item, desc in suspicious):
        signals.append(_signal('office_download_cradle'))

    shell = sorted({item for item, desc in suspicious if desc in _SHELL_DESCRIPTIONS})
    if shell:
        signals.append(_signal('office_shell_execution', ', '.join(shell)))

    return signals


def analyze_office(path):
    """Never raises. Returns a record whose `signals` say what happened, including
    when nothing was examined: "we did not look" and "we looked and found nothing" are
    different claims and must not render the same."""
    from oletools.olevba import FileOpenError, OlevbaBaseException, VBA_Parser
    import oletools.crypto as olecrypto

    try:
        if os.path.getsize(path) > MAX_BYTES:
            # Reject, never truncate: the ZIP central directory is at the end of the
            # file, so a trimmed .docm raises FileOpenError instead of parsing.
            return _empty(signals=[_signal('analysis_skipped_too_large',
                                           f'over {MAX_BYTES // (1024 * 1024)} MB')])
    except OSError as exc:
        return _empty(error=str(exc), signals=[_signal('analysis_error', str(exc))])

    ok, detail = _zip_budget_ok(path)
    if not ok:
        return _empty(signals=[_signal('analysis_skipped_too_large', detail)])

    if not _slots.acquire(blocking=False):
        return _empty(signals=[_signal('analysis_busy')])

    record = _empty()
    parser = None
    try:
        try:
            record['encrypted'] = bool(olecrypto.is_encrypted(path))
        except Exception as exc:  # noqa: BLE001
            logger.debug('is_encrypted failed for %s: %s', path, exc)

        parser = VBA_Parser(path, relaxed=True, disable_pcode=True)
        record['container'] = parser.type

        if parser.type not in OFFICE_TYPES:
            record['signals'].append(_signal('office_not_office_container', parser.type))
            return record
        if record['encrypted']:
            record['signals'].append(_signal('office_encrypted'))
            return record
        if not parser.detect_vba_macros():
            return record

        for _container, stream, name, code in parser.extract_all_macros():
            if code and code.strip():
                record['has_macro'] = True
                record['modules'].append({'stream': stream, 'filename': name,
                                          'code_len': len(code)})
        if not record['has_macro']:
            return record
        record['signals'].append(_signal('office_has_macro',
                                         f'{len(record["modules"])} module(s)'))

        # `or []`: analyze_macros() returns None when there is no VBA code.
        # deobfuscate=True costs ~18.5 us/byte, about 74 s on 4 MB. Never here.
        results = parser.analyze_macros(show_decoded_strings=False, deobfuscate=False) or []
        record['signals'].extend(_signals_from_results(results))
    except FileOpenError:
        # olevba refuses a file that matches no known format outright, and the Text
        # fallback only engages when the file has no NUL byte. A renamed PNG therefore
        # lands here rather than on the parser.type gate. Same fact, same signal: the
        # message carries the local path, so it is not the detail.
        record['signals'].append(_signal('office_not_office_container', 'unrecognised'))
    except OlevbaBaseException as exc:
        record['error'] = f'{type(exc).__name__}: {exc}'
        record['signals'].append(_signal('analysis_error', record['error']))
    except Exception as exc:  # noqa: BLE001 - olefile leaks a bare AttributeError
        record['error'] = f'{type(exc).__name__}: {exc}'
        record['signals'].append(_signal('analysis_error', record['error']))
    finally:
        if parser is not None:
            try:
                parser.close()
            except Exception as exc:  # noqa: BLE001
                logger.debug('VBA_Parser.close failed: %s', exc)
        _slots.release()
    return record
