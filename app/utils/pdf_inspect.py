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
