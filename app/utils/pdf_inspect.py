"""PDF structure inspection: keyword and structure detection, no PDF parsing.

Pure module, no Flask import, so `app/tests/test_pdf_inspect.py` runs it with no
server. It answers "what does this document declare it will do when opened", not
"what is in it": there is no xref resolution and no object graph.

Two decisions here are load-bearing and were both established by running a real PDF
engine against constructed files. Read them before changing anything:

1. Names are normalized in ONE left-to-right pass. PDF allows `/J#61vaScript`, which
   readers resolve to `/JavaScript`, so substring matching misses real attacks. But
   CoreGraphics resolves `/Ti#2323le` to `Ti#23le`, never to `Ti#le`: a decoded byte
   is part of the name and is never re-lexed. A loop here reads `J#2361vaScript` as
   `JavaScript` and reports a finding no reader would ever act on.

2. Counting reads the RAW byte stream. A context-aware version that skipped stream
   bodies, strings and comments removed the body-text false positives perfectly and
   cost nothing on clean files, and it also lost every signal in three test files:
   one missing `endstream`, or one missing `)`, makes the rest of the document
   invisible to it. That is a one-byte evasion. Context may annotate a hit; it must
   never suppress a count.
"""
import os
import re
import zlib

# A name runs from '/' to the first whitespace or delimiter (ISO 32000-1 7.3.5).
_NAME = re.compile(rb'/([^\x00\t\n\x0c\r ()<>\[\]{}/%]*)')
_HEX_ESCAPE = re.compile(rb'#([0-9A-Fa-f]{2})')


def _normalize_name(raw):
    """Decode `#XX` escapes in a PDF name, one left-to-right pass.

    `raw` is the bytes after '/', already delimited by the caller.
    """
    if b'#' not in raw:
        return raw
    return _HEX_ESCAPE.sub(lambda m: bytes((int(m.group(1), 16),)), raw)


# The names worth counting. Each is a distinct fact, so /EmbeddedFile and
# /EmbeddedFiles (the name-tree key) are tracked separately rather than merged.
KEYWORDS = frozenset((
    b'JS', b'JavaScript', b'OpenAction', b'AA', b'Launch', b'EmbeddedFile',
    b'EmbeddedFiles', b'RichMedia', b'Flash', b'URI', b'AcroForm', b'XFA',
    b'Encrypt', b'ObjStm', b'FlateDecode', b'LZWDecode', b'ASCIIHexDecode',
    b'ASCII85Decode', b'DCTDecode',
))

# A prefilter is a correctness surface, not just an optimization: during design an
# off-by-one here silently dropped 8 of 11 signals while looking like it worked.
# test_prefilter_agrees_with_a_full_scan pins it.
_FIRST_BYTES = frozenset(k[:1] for k in KEYWORDS) | {b'#'}
_MAX_NAME = max(len(k) for k in KEYWORDS) * 3  # every byte may be a #XX escape


def count_names(data):
    """`{name: {'total': int, 'hex': int}}` for the KEYWORDS present in `data`.

    Keys are bytes, which is the natural type for byte scanning. `analyze_pdf_bytes`
    decodes them at its boundary, because the record it returns is serialized to JSON
    and `json.dumps` refuses a bytes key.

    `hex` counts how many of those occurrences were written with a `#XX` escape,
    which is strictly more suspicious than a plain one and is free to report.
    """
    found = {}
    for match in _NAME.finditer(data):
        raw = match.group(1)
        if not raw or raw[:1] not in _FIRST_BYTES or len(raw) > _MAX_NAME:
            continue
        name = _normalize_name(raw)
        if name not in KEYWORDS:
            continue
        entry = found.setdefault(name, {'total': 0, 'hex': 0})
        entry['total'] += 1
        if b'#' in raw:
            entry['hex'] += 1
    return found


# Anchored forms. `obj` must follow two integers, and `stream` must be followed by an
# end-of-line, which is what distinguishes a real keyword from the same bytes landing
# inside compressed image data.
#
# The lookbehind and possessive quantifiers are a CPU bound, not style. Plain
# `\d+\s+\d+` retries from every digit of a long run and backtracks each time, so 8 KB
# of digits took 0.4 s and 16 MB would take days, holding the GIL throughout. Neither
# changes what matches: a match can only start where a digit run starts, and giving
# back a digit or a space can never let the next token match.
_ANCHORED_OBJ = re.compile(rb'(?<!\d)\d++\s++\d++\s++obj\b')
_ANCHORED_STREAM = re.compile(rb'stream(?:\r\n|\r|\n)')


def count_structure(data):
    """Object and stream counts, plus `xref`/`trailer` presence.

    Two-tier on purpose. The cheap `bytes.count` runs at ~269 MB/s and is right for
    the overwhelming majority of files; the anchored regexes cost 4x and only run when
    the cheap counts disagree, which was 3 of 60 real files. A mismatch is
    informational: it never drives a verdict on its own.
    """
    obj = data.count(b'obj') - data.count(b'endobj')
    endobj = data.count(b'endobj')
    stream = data.count(b'stream') - data.count(b'endstream')
    endstream = data.count(b'endstream')

    if obj != endobj:
        obj = len(_ANCHORED_OBJ.findall(data))
    if stream != endstream:
        stream = len(_ANCHORED_STREAM.findall(data))

    return {
        'obj': obj,
        'endobj': endobj,
        'stream': stream,
        'endstream': endstream,
        'xref': data.count(b'xref'),
        # Zero is normal: PDF 1.5 cross-reference streams carry no trailer keyword.
        'trailer': data.count(b'trailer'),
    }


MAX_INFLATE_PER_STREAM = 4 * 1024 * 1024
MAX_TOTAL_INFLATE = 32 * 1024 * 1024
MAX_STREAMS = 2048


def _stream_bodies(data):
    """Each `stream` EOL ... `endstream` body, non-overlapping, left to right.

    Not a `stream...(.*?)endstream` regex: with no `endstream` after it, every `stream`
    marker rescans to the end of the input, so 16,000 markers in a 374 KB file took
    45 s. Stopping at the first unterminated body keeps this linear, and loses
    nothing, since no later body could be terminated either.
    """
    pos = 0
    while True:
        start = _ANCHORED_STREAM.search(data, pos)
        if start is None:
            return
        end = data.find(b'endstream', start.end())
        if end < 0:
            return
        yield data[start.end():end]
        pos = end + len(b'endstream')


def _inflate_streams(data):
    """`(recovered_bytes, total_inflated)` for the Flate stream bodies in `data`.

    Bodies are located by scanning `stream` to `endstream`, never by trusting
    `/Length`: that is frequently an indirect reference like `/Length 12 0 R`, and
    resolving it means implementing xref lookup, which this module deliberately does
    not do.

    `decompressobj().decompress(data, max_length)` caps OUTPUT exactly and cheaply.
    Bare `zlib.decompress()` on a 1 MB bomb produced 1074 MB in 415 ms.
    """
    recovered = []
    total = 0
    for index, body in enumerate(_stream_bodies(data)):
        if index >= MAX_STREAMS or total >= MAX_TOTAL_INFLATE:
            break
        budget = min(MAX_INFLATE_PER_STREAM, MAX_TOTAL_INFLATE - total)
        for wbits in (15, -15):  # zlib header, then raw deflate
            try:
                out = zlib.decompressobj(wbits).decompress(body, budget)
            except zlib.error:
                continue
            if out:
                recovered.append(out)
                total += len(out)
                break
    return b'\n'.join(recovered), total


MAX_BYTES = 16 * 1024 * 1024
_HALF = MAX_BYTES // 2

SIGNAL_LABELS = {
    'pdf_javascript': 'PDF contains JavaScript',
    'pdf_auto_action': 'PDF runs an action automatically when opened',
    'pdf_launch_action': 'PDF launches an external program',
    'pdf_embedded_file': 'PDF carries an embedded file',
    'pdf_obfuscated_name': 'PDF hides a keyword behind hex escapes',
    # `/Encrypt` present is detectable from the raw bytes and is a real fact: an
    # encrypted document is opaque to every downstream content scanner, which is why
    # it is a known evasion. Whether it opens WITHOUT a password is the more damning
    # variant and is deliberately not decided here: it needs the /Encrypt dictionary
    # and the trailer /ID, so it needs xref resolution, which this module does not do.
    'pdf_encrypted': 'PDF is encrypted, so its contents could not be examined',
    'pdf_object_stream': ('PDF stores objects in compressed object streams, so counts '
                          'may be incomplete'),
    'pdf_structure_mismatch': 'PDF object or stream markers do not balance',
    'pdf_unhandled_filter': 'PDF uses a stream filter this analyser does not decode',
    'analysis_skipped_too_large': 'File was too large to examine in full',
    'analysis_error': 'Analysis failed',
}

_SIGNAL_FROM_KEYWORD = (
    ('pdf_javascript', (b'JS', b'JavaScript')),
    ('pdf_auto_action', (b'OpenAction', b'AA')),
    ('pdf_launch_action', (b'Launch',)),
    ('pdf_embedded_file', (b'EmbeddedFile',)),
)


def _read_capped(path):
    """`(data, truncated)`. Over the cap, read the first and last halves and join them.

    Head-only truncation is wrong and was measured: at a 2 MB cap it lost a signal on
    4 of 5 oversized files and lost `startxref` and `trailer` on all five. PDFs put
    the xref, the trailer and the `/Encrypt` reference at the end, and incremental
    updates append new objects there too.
    """
    size = os.path.getsize(path)
    with open(path, 'rb') as handle:
        if size <= MAX_BYTES:
            return handle.read(), False
        head = handle.read(_HALF)
        handle.seek(-_HALF, os.SEEK_END)
        return head + handle.read(_HALF), True


def _signal(key, detail=None):
    return {'key': key, 'label': SIGNAL_LABELS.get(key, key), 'detail': detail}


def _error_record(detail, truncated=False):
    return {'keywords': {}, 'structure': {}, 'inflated_bytes': 0, 'truncated': truncated,
            'signals': [_signal('analysis_error', detail)], 'error': detail}


def analyze_pdf_bytes(data):
    """The pure core, so tests can drive it without a file on disk."""
    recovered, inflated = _inflate_streams(data)
    keywords = count_names(data)
    for name, entry in count_names(recovered).items():
        target = keywords.setdefault(name, {'total': 0, 'hex': 0})
        target['total'] += entry['total']
        target['hex'] += entry['hex']

    structure = count_structure(data)
    signals = []

    for key, names in _SIGNAL_FROM_KEYWORD:
        hits = sum(keywords.get(name, {}).get('total', 0) for name in names)
        if hits:
            signals.append(_signal(key, f'{hits} occurrence(s)'))

    if any(entry.get('hex') for entry in keywords.values()):
        obfuscated = sorted(name.decode('latin-1')
                            for name, entry in keywords.items() if entry.get('hex'))
        signals.append(_signal('pdf_obfuscated_name', ', '.join(obfuscated)))

    if keywords.get(b'Encrypt'):
        signals.append(_signal('pdf_encrypted'))
    if keywords.get(b'ObjStm'):
        signals.append(_signal('pdf_object_stream'))
    if (structure['obj'] != structure['endobj']
            or structure['stream'] != structure['endstream']):
        signals.append(_signal('pdf_structure_mismatch', str(structure)))
    for filter_name in (b'LZWDecode', b'DCTDecode'):
        if keywords.get(filter_name):
            signals.append(_signal('pdf_unhandled_filter', filter_name.decode('latin-1')))

    return {
        # Decoded here, at the boundary, and not earlier: scanning wants bytes, and the
        # caller writes this record to data/ as JSON, where a bytes key is a TypeError.
        # Keys are always members of KEYWORDS, so the decode cannot fail.
        'keywords': {name.decode('latin-1'): entry for name, entry in keywords.items()},
        'structure': structure,
        'signals': signals,
        'inflated_bytes': inflated,
        'truncated': False,
        'error': None,
    }


def analyze_pdf(path):
    """Never raises. An unreadable or hostile file returns a record with `error` set."""
    try:
        data, truncated = _read_capped(path)
    except OSError as exc:
        return _error_record(str(exc))

    try:
        result = analyze_pdf_bytes(data)
    except Exception as exc:  # noqa: BLE001 - a hostile document must not 500 the page
        return _error_record(f'{type(exc).__name__}: {exc}', truncated=truncated)

    result['truncated'] = truncated
    if truncated:
        result['signals'].append(
            _signal('analysis_skipped_too_large',
                    f'only the first and last {_HALF // (1024 * 1024)} MB were examined'))
    return result
