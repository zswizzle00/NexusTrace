"""Pure binary inspection primitives. stdlib only, no network, no filesystem, no
subprocess.

Every function is ``bytes``-in / plain-data-out and **never retains or returns the
payload** - callers hand over a buffer and get back names, offsets, digests, and
numbers. That property is what lets both the upload path and
:func:`app.utils.email_parse.attachment_metadata` share this module while still
guaranteeing attachment content has no code path into storage or a response.

:func:`extract_strings` replaces the ``strings`` binary, which is not installed in
the Docker image. Shelling out to it would also be wrong here: a filename-
interpolated ``shell=True`` command is injectable, and redirecting to a temp file
in the process CWD corrupts concurrent uploads under ``gunicorn --threads 8``.

Nothing here raises on bad input. A triage helper handed ``None``, a ``str``, or a
truncated buffer must degrade to an empty/zero answer, not 500 an upload route.
"""

import hashlib
import math
import re
from collections import Counter
from functools import lru_cache

# Per-string and total caps on :func:`extract_strings`. A 50 MB upload of printable
# bytes would otherwise produce either one 50 MB string or ~12M four-byte ones.
# 2000 x 512 bounds the worst case at ~1 MB, which is the same order as the
# persisted-record budget email_parse already caps itself to; 512 chars is longer
# than any URL, path, or registry key worth triaging, and a high-entropy blob is
# better characterised by :func:`shannon_entropy` than by its truncated text.
MIN_STRING_LENGTH = 4
MAX_STRING_LENGTH = 512
MAX_STRINGS = 2000

# 32 hits is far past the point where "this file has executables appended to it" is
# established. The candidate cap bounds the scan itself: ``MZ`` is two ordinary
# ASCII letters, so a 50 MB buffer can hold ~25M candidate offsets, and iterating
# them all in Python takes seconds. Honest tradeoff: a real embedded PE sitting
# after 100,000 bogus ``MZ`` candidates is missed.
MAX_EMBEDDED_HITS = 32
MAX_EMBEDDED_CANDIDATES = 100_000

# A PE header cannot start before 0x40 - e_lfanew itself lives at 0x3c.
_PE_LFANEW_OFFSET = 0x3C
_PE_MIN_HEADER_OFFSET = 0x40


def _as_bytes(data):
    """``bytes`` for any bytes-like input, ``b''`` for anything else. ``bytes`` is
    the zero-copy path; ``bytearray``/``memoryview`` are copied so downstream
    slice comparisons against byte literals behave."""
    if isinstance(data, bytes):
        return data
    if isinstance(data, (bytearray, memoryview)):
        return bytes(data)
    return b''


# Byte-signature comparison, not a libmagic binding, so this adds no dependency.
# Entries are ``(offset, signature, name)`` and are tested in declared order, so a
# more specific signature must be declared before one it shares a prefix with.
#
# Two deliberate limits of prefix sniffing, stated so nobody "fixes" them:
#   - OOXML (docx/xlsx/pptx) is a ZIP container and reports as ``ZIP``. The bytes
#     that would discriminate it (local-header version/flags) vary by producer, so
#     a prefix rule would both misreport real documents and silently change the
#     persisted ``magic_type``/``is_archive`` of every existing e-mail record.
#     Legacy Office is genuinely distinguishable and reports as ``OLE``.
#   - ``CAFEBABE`` is both a Mach-O fat binary and a Java ``.class``; it reports as
#     ``MACHO``, matching the pre-existing behaviour this table replaced.
MAGIC_SIGNATURES = (
    (0, b'MZ', 'PE'),
    (0, b'\x7fELF', 'ELF'),
    (0, b'%PDF', 'PDF'),
    (0, b'PK\x03\x04', 'ZIP'),
    (0, b'Rar!\x1a\x07', 'RAR'),
    (0, b'7z\xbc\xaf\x27\x1c', '7Z'),
    (0, b'\xd0\xcf\x11\xe0', 'OLE'),
    (0, b'\xca\xfe\xba\xbe', 'MACHO'),
    (0, b'\xcf\xfa\xed\xfe', 'MACHO'),
    (0, b'\xfe\xed\xfa\xce', 'MACHO'),
    (0, b'\xce\xfa\xed\xfe', 'MACHO'),
    (0, b'\xfe\xed\xfa\xcf', 'MACHO'),
    (0, b'\xbe\xba\xfe\xca', 'MACHO'),
    (0, b'\x1f\x8b', 'GZIP'),
    (0, b'\xfd7zXZ\x00', 'XZ'),
    (0, b'BZh', 'BZIP2'),
    (0, b'MSCF', 'CAB'),
    (0, b'{\\rtf1', 'RTF'),
    (0, b'L\x00\x00\x00\x01\x14\x02\x00', 'LNK'),
    (0, b'dex\n', 'DEX'),
    (0, b'\x89PNG\r\n\x1a\n', 'PNG'),
    (0, b'\xff\xd8\xff', 'JPEG'),
    (0, b'GIF87a', 'GIF'),
    (0, b'GIF89a', 'GIF'),
    (0, b'#!', 'SCRIPT'),
    # Not prefixes: ustar sits in the tar header, and ISO 9660 puts its volume
    # descriptor after a 32 KB system area.
    (257, b'ustar', 'TAR'),
    (0x8001, b'CD001', 'ISO'),
)

# How much of the buffer sniffing needs, from the deepest offset above.
_MAGIC_WINDOW = 0x8001 + 5

# All six Mach-O magics are listed. The last three (MH_MAGIC ``ce fa ed fe`` -
# 32-bit LE and the most common - MH_CIGAM_64, FAT_CIGAM) were missing before
# 2026-07-30, so a Mach-O attachment was not classified executable and scored as an
# ordinary document. Enabling them raises `is_executable`, which changes
# `email_rules` scoring for *new* analyses only: verdicts are computed once in
# `analyze_email` and persisted, and the result route reads the stored record rather
# than re-scoring.

# Classification sets. Kept narrow on purpose: widening either one changes the
# persisted ``is_executable``/``is_archive`` of existing records, so a new
# MAGIC_SIGNATURES entry is a *reporting* improvement only until that is a
# deliberate, separately-verified decision.
EXECUTABLE_MAGIC = frozenset({'PE', 'ELF', 'MACHO'})
ARCHIVE_MAGIC = frozenset({'ZIP', 'RAR', '7Z', 'GZIP'})

EXECUTABLE_EXTENSIONS = frozenset(
    'exe com scr pif bat cmd ps1 vbs vbe js jse wsf wsh hta jar msi dll lnk'.split()
)
ARCHIVE_EXTENSIONS = frozenset('zip rar 7z tar gz cab iso img'.split())


def sniff_magic(data):
    """Format name from a byte signature, or None when nothing matches."""
    head = _as_bytes(data)[:_MAGIC_WINDOW]
    if not head:
        return None
    for offset, signature, name in MAGIC_SIGNATURES:
        if head[offset:offset + len(signature)] == signature:
            return name
    return None


def file_extension(filename):
    """Lowercased extension without the dot, or ``''`` when there is none."""
    name = str(filename or '')
    if '.' not in name:
        return ''
    return name.rsplit('.', 1)[-1].lower().strip('. ')


def is_executable(magic_type=None, filename=None):
    """True when either the sniffed format or the extension says executable."""
    return magic_type in EXECUTABLE_MAGIC or file_extension(filename) in EXECUTABLE_EXTENSIONS


def is_archive(magic_type=None, filename=None):
    """True when either the sniffed format or the extension says archive."""
    return magic_type in ARCHIVE_MAGIC or file_extension(filename) in ARCHIVE_EXTENSIONS


def file_digests(data):
    """md5 + sha1 + sha256 hex digests of one in-memory buffer.

    Three digests from a single buffer, with no filesystem access and no printing:
    the callers that need all three must not re-read the source three times.
    """
    buf = _as_bytes(data)
    return {
        'md5': hashlib.md5(buf).hexdigest(),
        'sha1': hashlib.sha1(buf).hexdigest(),
        'sha256': hashlib.sha256(buf).hexdigest(),
    }


def shannon_entropy(data):
    """Byte-level Shannon entropy in bits, 0.0 to 8.0. Empty input is 0.0.

    Single pass; ``Counter`` over ``bytes`` tallies in C. Slice the buffer if you
    only want a sample of a very large file.
    """
    buf = _as_bytes(data)
    if not buf:
        return 0.0
    total = len(buf)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in Counter(buf).values()
    )


@lru_cache(maxsize=16)
def _string_patterns(min_length):
    """(ascii, utf16le) run patterns for ``min_length``.

    The UTF-16LE pattern matches only NUL-padded ASCII - the ``strings -e l`` case
    that surfaces Windows wide-char URLs, paths, and registry keys. Genuine
    non-Latin UTF-16 is out of scope for a triage listing.

    Matching is byte-wise, **not** 2-byte aligned, exactly as ``strings -e l`` is:
    a wide run preceded by a single printable byte absorbs it (``d`` + ``W\\0I\\0``
    reads as ``dWI``). Anchoring to even offsets would instead miss every wide run
    that starts at an odd offset, which is the more damaging failure.
    """
    return (
        re.compile(b'[\x20-\x7e]{%d,}' % min_length),
        re.compile(b'(?:[\x20-\x7e]\x00){%d,}' % min_length),
    )


def _collect(pattern, buf, cap, wide):
    runs = []
    for match in pattern.finditer(buf):
        if len(runs) >= cap:
            break
        raw = match.group(0)
        if wide:
            raw = raw[::2]
        runs.append(raw[:MAX_STRING_LENGTH].decode('ascii'))
    return runs


def extract_strings(data, min_length=MIN_STRING_LENGTH, limit=MAX_STRINGS):
    """Printable ASCII and UTF-16LE runs of at least ``min_length`` characters.

    Returns at most ``limit`` strings, each truncated to ``MAX_STRING_LENGTH``, in
    offset order within each encoding (ASCII first, then UTF-16LE). Duplicates are
    kept - this is the ``strings`` primitive, so de-duplication is the caller's
    call.

    ``limit`` is shared round-robin between the two encodings. Filling it
    encoding-by-encoding would let an ASCII-heavy binary drop every wide string,
    which on Windows malware is where the interesting text usually is.
    """
    buf = _as_bytes(data)
    limit = max(int(limit), 0)
    if not buf or not limit:
        return []

    ascii_re, utf16_re = _string_patterns(max(int(min_length), 1))
    groups = (
        _collect(ascii_re, buf, limit, wide=False),
        _collect(utf16_re, buf, limit, wide=True),
    )

    taken = [0, 0]
    remaining = limit
    while remaining > 0:
        progressed = False
        for index, group in enumerate(groups):
            if remaining <= 0:
                break
            if taken[index] < len(group):
                taken[index] += 1
                remaining -= 1
                progressed = True
        if not progressed:
            break
    return groups[0][:taken[0]] + groups[1][:taken[1]]


# One alternation so hits come out in a single offset-ordered pass and share one
# candidate budget.
_EMBEDDED_MAGIC_RE = re.compile(b'MZ|\x7fELF')


def _confirms_pe(buf, offset):
    """True when ``MZ`` at ``offset`` is followed by a reachable ``PE\\0\\0``.

    A bare ``MZ`` is not evidence of anything - it is two common ASCII letters and
    occurs constantly in text and compressed data. Following e_lfanew is what makes
    this a signal rather than noise.
    """
    field = offset + _PE_LFANEW_OFFSET
    if field + 4 > len(buf):
        return False
    lfanew = int.from_bytes(buf[field:field + 4], 'little')
    if lfanew < _PE_MIN_HEADER_OFFSET:
        return False
    start = offset + lfanew
    return buf[start:start + 4] == b'PE\x00\x00'


def _confirms_elf(buf, offset):
    """True when EI_CLASS and EI_DATA after ``\\x7fELF`` are both defined values."""
    if offset + 6 > len(buf):
        return False
    return buf[offset + 4] in (1, 2) and buf[offset + 5] in (1, 2)


def find_embedded_executables(data, limit=MAX_EMBEDDED_HITS):
    """PE and ELF headers at **nonzero** offsets - appended or padded droppers.

    Returns up to ``limit`` ``{'offset': int, 'signature': 'PE'|'ELF'}`` in
    ascending offset order. Offset 0 is excluded by definition: that is the file's
    own format, which :func:`sniff_magic` already reports.
    """
    buf = _as_bytes(data)
    limit = max(int(limit), 0)
    if not buf or not limit:
        return []

    hits = []
    candidates = 0
    for match in _EMBEDDED_MAGIC_RE.finditer(buf):
        offset = match.start()
        if offset == 0:
            continue
        candidates += 1
        if candidates > MAX_EMBEDDED_CANDIDATES:
            break
        if match.group(0) == b'MZ':
            if _confirms_pe(buf, offset):
                hits.append({'offset': offset, 'signature': 'PE'})
        elif _confirms_elf(buf, offset):
            hits.append({'offset': offset, 'signature': 'ELF'})
        if len(hits) >= limit:
            break
    return hits
