"""Uploaded-file triage: digest the whole file, inspect a bounded window, look up
reputation once.

The static inspection is pure and lives in `app/utils/file_inspect.py` and
`app/utils/lnk_parse.py`; hash reputation lives in `hash_service`. This module owns
only the parts that can fail for environmental reasons - reading the temp file and
the network.

**Nothing here retains or returns sample bytes.** ``_assemble`` names every field
of the record explicitly, so file content has no path into a response the way it
has none into storage in `email_service`. There is no `data/` store for uploads at
all: the record is rendered synchronously and discarded with the temp file.
"""

import hashlib
import logging
import os
from datetime import datetime, timezone

from ..utils.cache import timed_lru_cache
from ..utils.file_inspect import (
    extract_strings,
    file_extension,
    find_embedded_executables,
    is_archive,
    is_executable,
    shannon_entropy,
    sniff_magic,
)
from ..utils.iocs import extract_iocs
from ..utils.lnk_parse import analyze_lnk
from .hash_service import (
    get_hash_info_quick,
    reference_links,
    unknown_hash_report,
)
from OTXv2 import OTXv2, IndicatorTypes

try:
    from .file_rules import score as _score_file
except ImportError:  # scorer not present yet - records simply carry no 'verdict'
    _score_file = None

logger = logging.getLogger(__name__)

# Streaming chunk for the digest pass. Large enough that a 50 MB upload is ~50
# reads, small enough that eight concurrent uploads hold 8 MB of chunks, not 400.
HASH_CHUNK_BYTES = 1024 * 1024

# How much of the file the *inspection* primitives see. Digests always cover the
# whole file; strings, entropy, the embedded-executable scan and the .lnk parse see
# only this prefix, and `truncated` says so.
#
# Why 4 MiB and not the whole file: MAX_CONTENT_LENGTH is 50 MB and the production
# server is `--threads 8` on a 2-core/8 GiB box, so a full read is 8 x 50 MB = 400 MB
# of resident buffers before any derived allocation - and `extract_strings` /
# `find_embedded_executables` allocate match objects and a Counter over whatever
# they are handed. 4 MiB caps the inspection buffers at 32 MiB across all threads,
# and the derived work is already bounded by file_inspect's own MAX_STRINGS (2000 x
# 512 chars) and MAX_EMBEDDED_CANDIDATES (100k) caps.
#
# Why 4 MiB is enough to be useful: it covers the entire file for every format where
# the tail matters to triage - a .lnk large enough to be truncated is already
# ~80x past lnk_parse.OVERSIZED_LNK_BYTES and flagged for it - and for a large
# binary the headers, imports, and embedded-dropper padding that this scan looks for
# sit in the first megabytes. A prefix that large is also a statistically sound
# entropy sample.
ANALYSIS_WINDOW_BYTES = 4 * 1024 * 1024

# Display cap on the strings listing. IOC extraction runs over the full
# `extract_strings` result; only the rendered listing is trimmed to this.
STRINGS_SAMPLE_LIMIT = 400

# Bound on the text handed to `extract_iocs`. The strings result can be ~1 MB
# (MAX_STRINGS x MAX_STRING_LENGTH) and three regexes over that is wasted work for a
# triage listing capped at 200 IOCs.
MAX_IOC_TEXT_BYTES = 256 * 1024

# Maps hash_service.unknown_hash_report's display names onto the provider keys
# hash_info['sources'] and reference_links() use, so the record has one vocabulary.
_SOURCE_KEYS = {
    'VirusTotal': 'virustotal',
    'MalwareBazaar': 'malwarebazaar',
    'ThreatFox': 'threatfox',
    'AlienVault OTX': 'alienvault_otx',
}


def setup_file_services(app):
    """Setup file-related services."""
    pass


def _now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def stream_digests(file_path, window_bytes=ANALYSIS_WINDOW_BYTES):
    """One pass over the file: full md5/sha1/sha256, plus the leading window.

    Returns ``(digests, window_bytes_buffer, size_bytes)``. ``size_bytes`` is the
    true size on disk, not the window length.

    `file_inspect.file_digests` is the in-memory equivalent and is deliberately not
    used here: it takes a whole buffer, which is the allocation this function exists
    to avoid.
    """
    digests = {
        'md5': hashlib.md5(),
        'sha1': hashlib.sha1(),
        'sha256': hashlib.sha256(),
    }
    window = bytearray()
    window_cap = max(int(window_bytes), 0)
    size = 0

    with open(file_path, 'rb') as handle:
        while True:
            chunk = handle.read(HASH_CHUNK_BYTES)
            if not chunk:
                break
            size += len(chunk)
            for digest in digests.values():
                digest.update(chunk)
            if len(window) < window_cap:
                window += chunk[:window_cap - len(window)]

    return ({name: digest.hexdigest() for name, digest in digests.items()},
            bytes(window), size)


def get_alienvault_analysis(file_hash):
    """Analyze a file hash using AlienVault OTX API."""
    otx_api_key = os.getenv('ALIENVAULT_KEY') or os.getenv('ALIENVAULT') or os.getenv('OTX_API_KEY')
    if not otx_api_key:
        logger.debug("AlienVault API key not configured (ALIENVAULT_KEY)")
        return None
    try:
        otx = OTXv2(otx_api_key)
        result = otx.get_indicator_details(IndicatorTypes.FILE_HASH_MD5, file_hash)
        if not result or 'general' not in result:
            result = otx.get_indicator_details(IndicatorTypes.FILE_HASH_SHA1, file_hash)
        if not result or 'general' not in result:
            result = otx.get_indicator_details(IndicatorTypes.FILE_HASH_SHA256, file_hash)
        return result
    except Exception as e:
        logger.error(f"AlienVault OTX analysis failed: {str(e)}")
        return None


@timed_lru_cache(seconds=1800)
def get_combined_file_analysis(file_path=None, file_hash=None):
    """Hash-only reputation lookup, kept for callers that already have a hash.

    Registered in `cache.clear_caches()` by name, so renaming or removing it stops
    every other cached function in that list from being cleared.
    """
    if file_path and not file_hash:
        try:
            file_hash = stream_digests(file_path, window_bytes=0)[0]['sha256']
        except OSError as e:
            logger.error(f"Could not read file for hashing: {str(e)}")
            return None
    otx_result = get_alienvault_analysis(file_hash) if file_hash else None
    return {
        'sha256': file_hash,
        'alienvault_otx': otx_result,
    }


def static_inspection(window, filename):
    """Pure inspection of the analysis window. No network, no filesystem."""
    magic_type = sniff_magic(window)
    strings = extract_strings(window)
    return {
        'magic_type': magic_type,
        'is_executable': is_executable(magic_type=magic_type, filename=filename),
        'is_archive': is_archive(magic_type=magic_type, filename=filename),
        'entropy': round(shannon_entropy(window), 4),
        'embedded_executables': find_embedded_executables(window),
        'strings': strings,
        'strings_sample': strings[:STRINGS_SAMPLE_LIMIT],
    }


def looks_like_lnk(magic_type, filename):
    """True when the shell-link parser should run.

    The extension counts even when the magic does not match: `parse_lnk` reports the
    mismatch as `parsed_ok: False` with an error, which is a finding about a file
    named `.lnk`, not a failure.
    """
    return magic_type == 'LNK' or file_extension(filename) == 'lnk'


def reputation_report(sha256):
    """One bounded reputation lookup for the file's SHA-256.

    Exactly one `get_hash_info_quick` call (VirusTotal + MalwareBazaar + ThreatFox)
    plus OTX. Embedded executables are **not** looked up: `virustotal_limiter` is a
    process-wide 4-per-minute limiter whose acquire() blocks in time.sleep, so a
    per-hit loop would stall the request and starve concurrent /hash_analysis users
    (see the MAX_ENRICH_HASHES note in email_service.py).

    Per-source state uses `hash_service.source_state`'s vocabulary, so 'skipped'
    (never queried, no API key) stays distinct from 'no_record' (queried, nothing
    known) and 'unavailable' (queried, source failed).
    """
    try:
        hash_info = get_hash_info_quick(sha256) or {}
    except Exception as exc:
        logger.warning('Hash reputation lookup failed for %s: %s', sha256, exc)
        hash_info = {}
    otx_raw = get_alienvault_analysis(sha256)

    report = unknown_hash_report(sha256, hash_info, otx_raw)
    provider_data = hash_info.get('sources') or {}
    sources = {}
    for entry in report['sources']:
        key = _SOURCE_KEYS[entry['name']]
        sources[key] = {
            'name': entry['name'],
            'state': entry['state'],
            'key_env': entry['key_env'],
            'url': entry['url'],
            'data': provider_data.get(key),
        }

    # OTX 'found' means unknown_hash_report saw a nonzero pulse count. On a file
    # hash that is a malware report, so it counts - unlike a VirusTotal record with
    # zero detections, which is 'found' but means the file is known and clean.
    known_malware = bool(
        (hash_info.get('summary') or {}).get('is_malicious')
        or sources['alienvault_otx']['state'] == 'found'
    )

    return {
        'sources': sources,
        'known_malware': known_malware,
        'links': report.get('reference_links') or reference_links(sha256),
    }


def _assemble(filename, size_bytes, digests, inspection, lnk, iocs, reputation,
              truncated, error):
    """Build the analysis record. The ONLY place a record is shaped, naming every
    field explicitly so file content cannot reach a response by accident."""
    return {
        'filename': filename,
        'size_bytes': size_bytes,
        'digests': digests,
        'magic_type': inspection['magic_type'],
        'is_executable': inspection['is_executable'],
        'is_archive': inspection['is_archive'],
        'entropy': inspection['entropy'],
        'embedded_executables': inspection['embedded_executables'],
        'strings_sample': inspection['strings_sample'],
        'lnk': lnk,
        'iocs': iocs,
        'reputation': reputation,
        'analyzed_at': _now(),
        'truncated': truncated,
        'error': error,
    }


def _empty_inspection():
    return {
        'magic_type': None,
        'is_executable': False,
        'is_archive': False,
        'entropy': 0.0,
        'embedded_executables': [],
        'strings': [],
        'strings_sample': [],
    }


def _empty_reputation(sha256=''):
    """Reputation shape for a file that was never hashed, so never looked up."""
    return {
        'sources': {},
        'known_malware': False,
        'links': reference_links(sha256) if sha256 else {},
    }


def _scored(record):
    """Attach `file_rules.score`'s verdict when the scorer module exists.

    A scorer failure must not fail an upload: the static findings are the analysis,
    the verdict is a summary of them.
    """
    if _score_file is None:
        return record
    try:
        record['verdict'] = _score_file(record)
    except Exception:
        logger.exception('file_rules.score failed; record returned without a verdict')
    return record


def analyze_file(file_path, filename):
    """Digest, inspect, look up reputation, and return one file-analysis record.

    Never raises for a bad or unreadable file: an unreadable upload comes back with
    `error` set and every other field at its empty value, so the result page renders
    the same as any other analysis.
    """
    try:
        digests, window, size_bytes = stream_digests(file_path)
    except OSError as exc:
        logger.error('Could not read uploaded file %r: %s', filename, exc)
        return _scored(_assemble(
            filename, 0, {'md5': None, 'sha1': None, 'sha256': None},
            _empty_inspection(), None, [], _empty_reputation(),
            False, f'Could not read the uploaded file: {exc.strerror or exc}',
        ))

    inspection = static_inspection(window, filename)

    lnk = None
    if looks_like_lnk(inspection['magic_type'], filename):
        lnk = analyze_lnk(window)

    # The shortcut's own IOCs lead the corpus so they survive extract_iocs' budget
    # ahead of thousands of incidental strings, the way email_service leads with the
    # sender domain.
    corpus = []
    if lnk:
        corpus.extend(item['value'] for item in lnk['iocs'])
    corpus.extend(inspection['strings'])
    iocs = extract_iocs('\n'.join(corpus)[:MAX_IOC_TEXT_BYTES])

    return _scored(_assemble(
        filename, size_bytes, digests, inspection, lnk, iocs,
        reputation_report(digests['sha256']),
        len(window) < size_bytes, None,
    ))
