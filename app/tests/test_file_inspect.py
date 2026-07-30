"""Pins app/utils/file_inspect.py - magic sniffing, strings, entropy, embedded
executables, digests. Pure, no network, no fixture files."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.utils.file_inspect import (
    ARCHIVE_MAGIC,
    EXECUTABLE_MAGIC,
    MAGIC_SIGNATURES,
    MAX_EMBEDDED_HITS,
    MAX_STRING_LENGTH,
    MAX_STRINGS,
    extract_strings,
    file_digests,
    file_extension,
    find_embedded_executables,
    is_archive,
    is_executable,
    shannon_entropy,
    sniff_magic,
)
from app.utils.file_inspect import _MAGIC_WINDOW

# (prefix, expected_name) for every signature email_parse.py carried before this
# module existed. A widened table must not reclassify any of them: these values are
# already persisted in data/analyses/*.json.
LEGACY_MAGIC_CASES = [
    (b'MZ', 'PE'),
    (b'\x7fELF', 'ELF'),
    (b'%PDF', 'PDF'),
    (b'PK\x03\x04', 'ZIP'),
    (b'Rar!\x1a\x07', 'RAR'),
    (b'7z\xbc\xaf\x27\x1c', '7Z'),
    (b'\xd0\xcf\x11\xe0', 'OLE'),
    (b'\xca\xfe\xba\xbe', 'MACHO'),
    (b'\xcf\xfa\xed\xfe', 'MACHO'),
    (b'\xfe\xed\xfa\xce', 'MACHO'),
    (b'\x1f\x8b', 'GZIP'),
]

# (sample_bytes, expected_name) - realistic headers, one per format in the table.
MAGIC_CASES = [
    (b'MZ\x90\x00\x03\x00\x00\x00', 'PE'),
    (b'\x7fELF\x02\x01\x01\x00', 'ELF'),
    (b'%PDF-1.7\n%\xe2\xe3\xcf\xd3', 'PDF'),
    (b'PK\x03\x04\x14\x00\x00\x08', 'ZIP'),
    # OOXML is a ZIP container and is documented to report as ZIP, not DOCX.
    (b'PK\x03\x04\x14\x00\x06\x00[Content_Types].xml', 'ZIP'),
    (b'Rar!\x1a\x07\x01\x00', 'RAR'),
    (b'Rar!\x1a\x07\x00', 'RAR'),
    (b'7z\xbc\xaf\x27\x1c\x00\x04', '7Z'),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'OLE'),
    (b'\xca\xfe\xba\xbe\x00\x00\x00\x02', 'MACHO'),
    (b'\xcf\xfa\xed\xfe\x0c\x00\x00\x01', 'MACHO'),
    (b'\xfe\xed\xfa\xce\x00\x00\x00\x12', 'MACHO'),
    (b'\x1f\x8b\x08\x00\x00\x00\x00\x00', 'GZIP'),
    (b'\xfd7zXZ\x00\x00\x04\xe6\xd6\xb4F', 'XZ'),
    (b'BZh91AY&SY', 'BZIP2'),
    (b'MSCF\x00\x00\x00\x00\x1c\x03\x00\x00', 'CAB'),
    (b'{\\rtf1\\ansi\\ansicpg1252', 'RTF'),
    (b'L\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00', 'LNK'),
    (b'dex\n035\x00', 'DEX'),
    (b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR', 'PNG'),
    (b'\xff\xd8\xff\xe0\x00\x10JFIF\x00', 'JPEG'),
    (b'GIF87a\x01\x00\x01\x00', 'GIF'),
    (b'GIF89a\x01\x00\x01\x00', 'GIF'),
    (b'#!/bin/sh\nid\n', 'SCRIPT'),
    (b'#!/usr/bin/env python3\n', 'SCRIPT'),
    # Not prefixes: ustar lives in the tar header, ISO after a 32 KB system area.
    (b'payload.txt'.ljust(257, b'\x00') + b'ustar\x0000', 'TAR'),
    (b'\x00' * 0x8001 + b'CD001\x01', 'ISO'),
    # Truncated, tiny, and empty input must all be a clean None, not an exception.
    (b'M', None),
    (b'\x7fEL', None),
    (b'{\\rt', None),
    (b'', None),
    (b'hello world, plain text\n', None),
]

# (magic_type, filename, expect_executable, expect_archive) - the classification
# semantics attachment_metadata relied on, including that the widened signature
# table does NOT reclassify anything.
CLASSIFY_CASES = [
    ('PE', 'invoice.exe', True, False),
    ('PE', 'renamed.bin', True, False),
    (None, 'invoice.exe', True, False),
    (None, 'macro.VBS', True, False),
    (None, 'shortcut.lnk', True, False),
    ('ELF', 'noextension', True, False),
    ('MACHO', 'app', True, False),
    ('ZIP', 'docs.zip', False, True),
    ('ZIP', 'report.docx', False, True),
    (None, 'backup.TAR', False, True),
    (None, 'letter.pdf', False, False),
    (None, 'noextension', False, False),
    (None, None, False, False),
    # New signature names must stay out of both sets.
    ('SCRIPT', 'run.sh', False, False),
    ('CAB', 'renamed.bin', False, False),
    ('CAB', 'setup.cab', False, True),
    ('LNK', 'renamed.bin', False, False),
    ('RTF', 'letter.rtf', False, False),
    ('ISO', 'renamed.bin', False, False),
]

# The three Mach-O magics that were missing until 2026-07-30. A Mach-O attachment
# used to classify as a document; these must sniff as MACHO *and* be executable, or
# macOS payloads score as benign attachments again.
MACHO_MAGIC_CASES = [
    (b'\xce\xfa\xed\xfe\x07\x00\x00\x00', 'MH_MAGIC 32-bit LE'),
    (b'\xfe\xed\xfa\xcf\x01\x00\x00\x07', 'MH_CIGAM_64'),
    (b'\xbe\xba\xfe\xca\x00\x00\x00\x02', 'FAT_CIGAM'),
]

DIGEST_CASES = [
    (b'', 'd41d8cd98f00b204e9800998ecf8427e',
     'da39a3ee5e6b4b0d3255bfef95601890afd80709',
     'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
    (b'abc', '900150983cd24fb0d6963f7d28e17f72',
     'a9993e364706816aba3e25717850c26c9cd0d89d',
     'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'),
]

NON_BYTES_INPUTS = [None, 'a string', 123, 4.5, [1, 2, 3], {'a': 1}, object()]


def pe_blob(pad=0, lfanew=0x40):
    """A minimal but structurally valid MZ/PE header, optionally preceded by
    ``pad`` filler bytes so the PE starts at a nonzero offset."""
    dos = bytearray(b'MZ' + b'\x00' * (lfanew - 2))
    dos[0x3C:0x40] = lfanew.to_bytes(4, 'little')
    return b'\x00' * pad + bytes(dos) + b'PE\x00\x00' + b'\x00' * 16


def elf_blob(pad=0):
    return b'\x00' * pad + b'\x7fELF\x02\x01\x01\x00' + b'\x00' * 24


def check_magic(failures):
    for prefix, expected in LEGACY_MAGIC_CASES:
        got = sniff_magic(prefix + b'\x00' * 64)
        if got != expected:
            failures.append(
                f'legacy signature {prefix!r} -> {got!r}, must stay {expected!r}'
            )

    for sample, expected in MAGIC_CASES:
        got = sniff_magic(sample)
        if got != expected:
            failures.append(f'sniff_magic({sample[:12]!r}...) -> {got!r}, expected {expected!r}')

    for sample, label in MACHO_MAGIC_CASES:
        got = sniff_magic(sample)
        if got != 'MACHO':
            failures.append(f'{label} -> {got!r}, expected MACHO')
        elif not is_executable(magic_type=got):
            failures.append(f'{label} sniffs as MACHO but is not classified executable')

    if sniff_magic(bytearray(b'%PDF-1.4')) != 'PDF':
        failures.append('sniff_magic must accept bytearray')
    if sniff_magic(memoryview(b'%PDF-1.4')) != 'PDF':
        failures.append('sniff_magic must accept memoryview')

    # The table is tested in declared order, so an entry that shadows a later one
    # with a different name silently wins. Nothing may be reachable-but-shadowed.
    for i, (off_a, sig_a, name_a) in enumerate(MAGIC_SIGNATURES):
        for off_b, sig_b, name_b in MAGIC_SIGNATURES[i + 1:]:
            if off_a == off_b and sig_b.startswith(sig_a) and name_a != name_b:
                failures.append(
                    f'{sig_b!r} ({name_b}) is unreachable: {sig_a!r} ({name_a}) '
                    'is declared earlier and shadows it'
                )

    # Every offset the table needs must be inside the window sniff_magic slices.
    deepest = max(offset + len(sig) for offset, sig, _ in MAGIC_SIGNATURES)
    if deepest > _MAGIC_WINDOW:
        failures.append(f'_MAGIC_WINDOW {_MAGIC_WINDOW} is short of the deepest signature {deepest}')


def check_classification(failures):
    for magic, name, want_exe, want_arc in CLASSIFY_CASES:
        got_exe = is_executable(magic, name)
        got_arc = is_archive(magic, name)
        if got_exe != want_exe:
            failures.append(
                f'is_executable({magic!r}, {name!r}) -> {got_exe}, expected {want_exe}'
            )
        if got_arc != want_arc:
            failures.append(
                f'is_archive({magic!r}, {name!r}) -> {got_arc}, expected {want_arc}'
            )

    if EXECUTABLE_MAGIC != frozenset({'PE', 'ELF', 'MACHO'}):
        failures.append(f'EXECUTABLE_MAGIC widened to {sorted(EXECUTABLE_MAGIC)}')
    if ARCHIVE_MAGIC != frozenset({'ZIP', 'RAR', '7Z', 'GZIP'}):
        failures.append(f'ARCHIVE_MAGIC widened to {sorted(ARCHIVE_MAGIC)}')

    for name, expected in (
        ('invoice.exe', 'exe'), ('Archive.TAR', 'tar'), ('noext', ''),
        ('two.dots.gz', 'gz'), ('trailing.exe ', 'exe'), ('', ''), (None, ''),
    ):
        got = file_extension(name)
        if got != expected:
            failures.append(f'file_extension({name!r}) -> {got!r}, expected {expected!r}')


def check_strings(failures):
    found = extract_strings(b'\x00\x01hello world\x00\xffab\x00trailing')
    if 'hello world' not in found:
        failures.append(f'ASCII run not extracted; got {found}')
    if 'ab' in found:
        failures.append('a 2-char run must not clear the default 4-char minimum')
    if 'trailing' not in found:
        failures.append('a run ending at the buffer end must still be extracted')

    short = extract_strings(b'\x00ab\x00abcd\x00', min_length=2)
    if short != ['ab', 'abcd']:
        failures.append(f'min_length=2 -> {short}, expected [ab, abcd]')

    wide = b'\x00\x00' + 'C:\\Users\\victim\\run.exe'.encode('utf-16-le') + b'\x00\x00'
    got = extract_strings(wide)
    if 'C:\\Users\\victim\\run.exe' not in got:
        failures.append(f'UTF-16LE run not extracted; got {got}')

    # A wide run must not also surface as a pile of ASCII fragments.
    if any(len(s) >= 4 and '\x00' not in s and s.startswith('C:') and s != 'C:\\Users\\victim\\run.exe'
           for s in got):
        failures.append(f'UTF-16LE run double-reported as ASCII fragments: {got}')

    # No chunking in this implementation, so a run cannot straddle a read boundary;
    # a run far into a large buffer must still come out whole.
    deep = b'\x00' * 200_000 + b'deep-marker-string' + b'\x00' * 200_000
    if 'deep-marker-string' not in extract_strings(deep):
        failures.append('a run late in a large buffer was missed')

    long_run = extract_strings(b'\x00' + b'A' * (MAX_STRING_LENGTH + 500) + b'\x00')
    if len(long_run) != 1 or len(long_run[0]) != MAX_STRING_LENGTH:
        failures.append(
            f'per-string cap not enforced: {len(long_run)} run(s), '
            f'first is {len(long_run[0]) if long_run else 0} chars'
        )

    flood = b'\x00'.join(b'abcd' for _ in range(MAX_STRINGS + 500))
    capped = extract_strings(flood)
    if len(capped) != MAX_STRINGS:
        failures.append(f'total cap not enforced: {len(capped)} strings, expected {MAX_STRINGS}')

    if len(extract_strings(flood, limit=7)) != 7:
        failures.append('explicit limit not honoured')
    if extract_strings(flood, limit=0) != []:
        failures.append('limit=0 must yield no strings')

    # Fair share: an ASCII flood must not starve the wide strings entirely.
    mixed = flood + b'\x00\x00' + 'WIDE-ONLY-MARKER'.encode('utf-16-le')
    if 'WIDE-ONLY-MARKER' not in extract_strings(mixed):
        failures.append('an ASCII flood starved the UTF-16LE strings')

    # Matching is byte-wise, not 2-byte aligned, like `strings -e l`: a printable
    # byte plus a NUL immediately before a wide run reads as another wide character
    # and is absorbed. Pinned so the quirk stays a documented choice, not a surprise.
    unaligned = extract_strings(b'd\x00' + 'WIDE'.encode('utf-16-le'))
    if 'dWIDE' not in unaligned:
        failures.append(f'unaligned UTF-16LE matching changed; got {unaligned}')

    for tiny in (b'', b'A', b'AB', b'ABC'):
        if extract_strings(tiny) != []:
            failures.append(f'extract_strings({tiny!r}) must be empty below min_length')

    if extract_strings(bytearray(b'\x00bytearray-run\x00')) != ['bytearray-run']:
        failures.append('extract_strings must accept bytearray')


def check_entropy(failures):
    for data, expected, label in (
        (b'', 0.0, 'empty'),
        (b'A', 0.0, 'single byte'),
        (b'\x00' * 4096, 0.0, 'all zeros'),
        (b'\x00' * 512 + b'\x01' * 512, 1.0, 'two equally frequent bytes'),
        (bytes(range(256)), 8.0, 'every byte once'),
        (bytes(range(256)) * 32, 8.0, 'uniform distribution'),
    ):
        got = shannon_entropy(data)
        if abs(got - expected) > 1e-9:
            failures.append(f'shannon_entropy({label}) -> {got}, expected {expected}')

    # A high-entropy-looking buffer must land inside the theoretical range and above
    # plain English text.
    pseudo = bytes((i * 167 + 13) % 256 for i in range(8192))
    text = b'the quick brown fox jumps over the lazy dog. ' * 200
    high, low = shannon_entropy(pseudo), shannon_entropy(text)
    if not 0.0 <= low < high <= 8.0:
        failures.append(f'entropy ordering wrong: text={low}, pseudo-random={high}')

    if shannon_entropy(bytearray(b'\x00' * 100)) != 0.0:
        failures.append('shannon_entropy must accept bytearray')


def check_embedded(failures):
    if find_embedded_executables(pe_blob()) != []:
        failures.append('a PE at offset 0 is the file itself, not an embedded one')
    if find_embedded_executables(b'MZ' + b'garbage' * 40) != []:
        failures.append('a bare MZ at offset 0 must not be reported')
    if find_embedded_executables(b'X' * 512 + b'MZ' + b'garbage' * 40) != []:
        failures.append('a bare MZ with no reachable PE header must not be reported')
    if find_embedded_executables(elf_blob()) != []:
        failures.append('an ELF at offset 0 must not be reported')
    if find_embedded_executables(b'\x00' * 64 + b'\x7fELF\x09\x09\x09\x09') != []:
        failures.append('\\x7fELF with undefined EI_CLASS/EI_DATA must not be reported')

    appended = b'%PDF-1.7\n' + b'\x00' * 500 + pe_blob()
    hits = find_embedded_executables(appended)
    if hits != [{'offset': 509, 'signature': 'PE'}]:
        failures.append(f'appended PE dropper -> {hits}, expected one PE hit at 509')

    hits = find_embedded_executables(b'\x00' * 32 + elf_blob())
    if hits != [{'offset': 32, 'signature': 'ELF'}]:
        failures.append(f'embedded ELF -> {hits}, expected one ELF hit at 32')

    both = b'\x00' * 16 + elf_blob() + pe_blob(pad=8)
    hits = find_embedded_executables(both)
    offsets = [h['offset'] for h in hits]
    if [h['signature'] for h in hits] != ['ELF', 'PE'] or offsets != sorted(offsets):
        failures.append(f'mixed PE+ELF must come out offset-ordered; got {hits}')

    flood = b'\x00' * 8 + pe_blob() * (MAX_EMBEDDED_HITS + 20)
    hits = find_embedded_executables(flood)
    if len(hits) != MAX_EMBEDDED_HITS:
        failures.append(f'hit cap not enforced: {len(hits)} hits, expected {MAX_EMBEDDED_HITS}')
    if len(find_embedded_executables(flood, limit=3)) != 3:
        failures.append('explicit embedded limit not honoured')
    if find_embedded_executables(flood, limit=0) != []:
        failures.append('embedded limit=0 must yield no hits')

    if find_embedded_executables(bytearray(b'\x00' * 64 + pe_blob())) == []:
        failures.append('find_embedded_executables must accept bytearray')


def check_digests(failures):
    for data, md5, sha1, sha256 in DIGEST_CASES:
        got = file_digests(data)
        if (got['md5'], got['sha1'], got['sha256']) != (md5, sha1, sha256):
            failures.append(f'file_digests({data!r}) -> {got}')
    if set(file_digests(b'x')) != {'md5', 'sha1', 'sha256'}:
        failures.append('file_digests must return exactly md5/sha1/sha256')
    if file_digests(bytearray(b'abc'))['sha1'] != DIGEST_CASES[1][2]:
        failures.append('file_digests must accept bytearray')


def check_non_bytes(failures):
    """Nothing here may raise: these helpers run on an unauthenticated upload path
    and a wrong-typed argument must degrade, not 500."""
    for value in NON_BYTES_INPUTS:
        label = type(value).__name__
        try:
            if extract_strings(value) != []:
                failures.append(f'extract_strings({label}) must be empty')
            if shannon_entropy(value) != 0.0:
                failures.append(f'shannon_entropy({label}) must be 0.0')
            if sniff_magic(value) is not None:
                failures.append(f'sniff_magic({label}) must be None')
            if find_embedded_executables(value) != []:
                failures.append(f'find_embedded_executables({label}) must be empty')
            if file_digests(value)['sha256'] != DIGEST_CASES[0][3]:
                failures.append(f'file_digests({label}) must digest the empty buffer')
        except Exception as exc:
            failures.append(f'{label} input raised {type(exc).__name__}: {exc}')


def check_no_payload_retention(failures):
    """No helper may hand back the buffer it was given - the attachment path
    guarantees content cannot reach storage or a response."""
    secret = b'MZ' + b'SENSITIVE-PAYLOAD-CONTENT' * 8
    for name, result in (
        ('file_digests', file_digests(secret)),
        ('find_embedded_executables', find_embedded_executables(secret)),
        ('sniff_magic', sniff_magic(secret)),
        ('shannon_entropy', shannon_entropy(secret)),
    ):
        if b'SENSITIVE' in repr(result).encode('utf-8', 'replace'):
            failures.append(f'{name} leaked payload bytes into its result')


def main():
    failures = []
    check_magic(failures)
    check_classification(failures)
    check_strings(failures)
    check_entropy(failures)
    check_embedded(failures)
    check_digests(failures)
    check_non_bytes(failures)
    check_no_payload_retention(failures)

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {len(LEGACY_MAGIC_CASES)} legacy-magic + {len(MAGIC_CASES)} magic + '
          f'{len(MACHO_MAGIC_CASES)} mach-o + 2 table-invariant + '
          f'{len(CLASSIFY_CASES)} classification + 7 extension + 15 strings + '
          f'8 entropy + 12 embedded + {len(DIGEST_CASES)} digest + '
          f'{len(NON_BYTES_INPUTS)} non-bytes + 4 no-retention cases')


if __name__ == '__main__':
    main()
