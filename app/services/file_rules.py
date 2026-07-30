"""Heuristic scoring for an inspected file upload. Pure; no network, no I/O.

Additive weights over named boolean signals, clamped to [0, 1], then banded.
Combos add on top of their constituents because the combination is the tell, not
either half - an obfuscated string-execution primitive is a code smell, an
obfuscated string-execution primitive *next to a download cradle* is a stager.

**This is a structural prior over static observations, not a reputation verdict.**
The only non-structural input is `known_malware_hash`; everything else is derived
from bytes the analyst uploaded. Weights are per-signal booleans, never
`weight * occurrence_count` - a packed binary that mentions `curl` forty times is
not forty times more suspicious than one that mentions it once, and an unbounded
count-scaled total cannot be banded at all.

Derez's `apple_analyzer._RISK_WEIGHTS` supplied the signal *vocabulary*
(c2_artifact, reverse_shell, anti_analysis, privilege_escalation, persistence,
download_staging, base64_blob, crypto_address) and none of its model. Its
`unsigned`, `dangerous_entitlement`, `suspicious_dylib`, and `yara_match` signals
are deliberately **absent** rather than faked: this record carries no code
signature, no entitlement list, no dylib table, and no YARA result, and inventing
a value for a field nothing populates would score absence.

**Absence never scores, and never reads as clean.** `no_reputation_data`,
`analysis_truncated`, and `analysis_error` are weighted at exactly 0.0 - they are
reported so the analyst can see *why* a verdict is thin, and they move the total
by nothing. `benign` additionally requires that a reputation source actually
answered: static inspection alone can raise a verdict but can never clear one, so
a file whose every lookup was skipped for want of an API key is `unknown`, not
`benign`. (MalwareBazaar and ThreatFox need no key, so `benign` stays reachable in
a normally-configured deployment.) Unlike `email_rules`, `unknown` keeps its score
and signals: weak-but-real observations plus "we could not check reputation" is a
more honest report than a zeroed one.

**The ambient-floor property.** Two profiles describe ordinary, harmless files,
and both must stay below `SUSPICIOUS_THRESHOLD`:

* *A legitimate packed installer* is an executable (0.05), is compressed and
  therefore high-entropy (0.05), fetches components over HTTP (0.05), and carries
  a long base64 run in its resources (0.05) - **0.20**. A signed `setup.exe` must
  not read as suspicious merely for being a packed executable, which is this
  engine's single most important false-positive anchor.
* *An ordinary per-user shortcut* (VS Code, Teams, Chrome all install to
  `%LOCALAPPDATA%`) is executable-by-extension (0.05), targets a user-writable
  path outside Program Files (0.05), names a UNC path or URL (0.05), records a
  size inconsistency or is unusually large (0.05), and requests elevation (0.05) -
  **0.25**.

The property is stated per named profile, not as a global cap over the 0.05 tier
(all eight ambient signals sum to 0.40). A file would have to be simultaneously a
`.lnk`, high-entropy, and carrying both a base64 blob and fetch-API strings to
collect them all, and a base64 blob in a shortcut's arguments fires
`lnk_encoded_command` (0.30, over the floor by itself), so that composite is never
an ambient-only file.

**Threshold derivation.** Both bands are pinned by the case table in
`app/tests/test_file_rules.py`, not chosen independently of it:

* the per-user-shortcut ambient profile (0.25) must be `benign`, which puts
  `SUSPICIOUS_THRESHOLD` above 0.25;
* a lone `embedded_executable_at_offset` (0.30) - a PE appended to a file that is
  not one - must clear `suspicious`, which puts it at or below 0.30.

  Those two together pin `SUSPICIOUS_THRESHOLD` to exactly **0.30**. Moving any
  0.05 ambient weight, or `embedded_executable_at_offset`, re-opens the derivation.

* a PDF carrying an appended PE (0.30 + 0.25 + 0.05 = 0.60) must stay
  `suspicious`, and a `.pdf`-named PE (0.45 + 0.05 + 0.05 = 0.55) must too, which
  puts `MALICIOUS_THRESHOLD` above 0.60;
* a packed PE carrying C2 framework strings, sandbox-evasion strings, and
  credential-dumper strings (0.25 + 0.25 + 0.30 + 0.10 = 0.90) must reach
  `malicious`, which puts it at or below 0.90.

  Within (0.60, 0.90], **0.85** is chosen so that `known_malware_hash` - weighted
  at exactly `MALICIOUS_THRESHOLD`, mirroring `email_rules.attachment_known_malware`
  - reaches `malicious` on its own, including for a malicious *document* that earns
  no structural weight at all.

Every field is read defensively. The record is assembled from attacker-controlled
bytes by helpers that are documented to degrade rather than raise, so it may be
partial, and a malformed record must produce a verdict dict rather than 500 an
upload route.
"""

import logging
import re

from ..utils.file_inspect import (
    ARCHIVE_MAGIC,
    EXECUTABLE_EXTENSIONS,
    EXECUTABLE_MAGIC,
    file_extension,
)
from ..utils.lnk_parse import SIGNAL_LABELS as LNK_SIGNAL_LABELS

logger = logging.getLogger(__name__)

WEIGHTS = {
    # Reputation - the only non-structural input.
    'known_malware_hash': 0.85,
    # Strong: the file is actively lying about what it is, or carries a second
    # program, or names a primitive that has no benign reading.
    'executable_masquerading_as_document': 0.45,
    'credential_theft': 0.30,
    'embedded_executable_at_offset': 0.30,
    'filename_masquerade': 0.30,
    'lnk_encoded_command': 0.30,
    'reverse_shell': 0.30,
    # Moderate: notable, but each has a legitimate reading often enough that none
    # may reach a verdict without company.
    'anti_analysis': 0.25,
    'c2_artifact': 0.25,
    'download_cradle': 0.25,
    'embedded_executable_in_document': 0.25,
    'encoded_command': 0.25,
    'lnk_appended_data': 0.25,
    'lnk_download_cradle': 0.25,
    'lnk_masquerade': 0.25,
    'archive_containing_executable': 0.15,
    'lnk_defense_evasion': 0.15,
    'lnk_hidden_window': 0.15,
    'lnk_lolbas_target': 0.15,
    'lnk_persistence': 0.15,
    'privilege_escalation': 0.15,
    'crypto_address': 0.10,
    'persistence': 0.10,
    # Ambient - individually meaningless. See the ambient-floor property above.
    'base64_blob': 0.05,
    'download_staging': 0.05,
    'executable_file': 0.05,
    'high_entropy': 0.05,
    'lnk_elevation_request': 0.05,
    'lnk_network_indicator': 0.05,
    'lnk_structural_anomaly': 0.05,
    'lnk_suspicious_target_path': 0.05,
    # Combos: both constituents present.
    'encoded_command+download_cradle': 0.20,
    'lnk_encoded_command+lnk_download_cradle': 0.20,
    'lnk_lolbas_target+lnk_hidden_window': 0.15,
    'persistence+download_staging': 0.15,
    # Reported, never scored. Absence of evidence is not evidence.
    'analysis_error': 0.0,
    'analysis_truncated': 0.0,
    'no_reputation_data': 0.0,
}

MALICIOUS_THRESHOLD = 0.85
SUSPICIOUS_THRESHOLD = 0.30

SIGNAL_LABELS = {
    'known_malware_hash': 'Hash is known malware',
    'executable_masquerading_as_document': 'Executable disguised as a document',
    'credential_theft': 'Credential-theft tooling or artifact paths',
    'embedded_executable_at_offset': 'Executable embedded at a nonzero offset',
    'filename_masquerade': 'Filename disguises the real extension',
    'lnk_encoded_command': 'Shortcut runs an encoded or obfuscated command',
    'reverse_shell': 'Reverse-shell primitive',
    'anti_analysis': 'Sandbox, VM, or debugger evasion',
    'c2_artifact': 'Command-and-control framework artifact',
    'download_cradle': 'Download cradle',
    'embedded_executable_in_document': 'Document carries an embedded executable',
    'encoded_command': 'Encoded or obfuscated command string',
    'lnk_appended_data': 'Data appended after the shortcut structures',
    'lnk_download_cradle': 'Shortcut arguments contain a download cradle',
    'lnk_masquerade': 'Shortcut disguised as a document',
    'archive_containing_executable': 'Archive contains an executable',
    'lnk_defense_evasion': 'Shortcut requests defense evasion',
    'lnk_hidden_window': 'Shortcut hides its execution window',
    'lnk_lolbas_target': 'Shortcut invokes a living-off-the-land binary',
    'lnk_persistence': 'Shortcut runs a persistence command',
    'privilege_escalation': 'Privilege-escalation primitive',
    'crypto_address': 'Cryptocurrency address',
    'persistence': 'Persistence mechanism',
    'base64_blob': 'Long base64 run',
    'download_staging': 'HTTP download API or tool',
    'executable_file': 'File is executable',
    'high_entropy': 'High entropy (packed or compressed)',
    'lnk_elevation_request': 'Shortcut requests elevation',
    'lnk_network_indicator': 'Shortcut references a network location',
    'lnk_structural_anomaly': 'Shortcut structure is inconsistent',
    'lnk_suspicious_target_path': 'Shortcut target is in an unusual location',
    'encoded_command+download_cradle': 'Obfuscated command plus a download cradle',
    'lnk_encoded_command+lnk_download_cradle':
        'Shortcut combines an encoded command with a download cradle',
    'lnk_lolbas_target+lnk_hidden_window':
        'Shortcut runs a living-off-the-land binary with a hidden window',
    'persistence+download_staging': 'Persistence plus network staging',
    'analysis_error': 'Inspection reported an error',
    'analysis_truncated': 'Inspection window was truncated',
    'no_reputation_data': 'No reputation source answered',
}

# Whole-file entropy at or above this is "packed or compressed". 7.5 rather than
# the more common 7.0: an ordinary PDF full of Flate streams and any ZIP sit in
# the 7.0-7.5 band, and this is an ambient signal, so precision matters more than
# recall. Below MIN_ENTROPY_SIZE the measurement is meaningless - a 300-byte file
# cannot distribute 256 symbols evenly enough to say anything.
HIGH_ENTROPY_MIN = 7.5
MIN_ENTROPY_SIZE = 4096

# Upper bound on the text the content rules run over. `extract_strings` already
# caps itself at 2000 x 512 chars (~1 MB); scanning a megabyte with ~15 compiled
# alternations per request is wasteful when the interesting strings are dense.
MAX_STRINGS_TEXT = 400_000

# Extensions whose presence on an executable payload is a lie. Media and
# text/office formats only - never an extension that legitimately holds code.
DOCUMENT_EXTENSIONS = frozenset(
    'pdf doc docx dot dotx xls xlsx xlsm ppt pptx rtf txt csv tsv odt ods odp '
    'pages numbers key one pub eml msg ics vcf log md xml json yaml yml html htm '
    'jpg jpeg png gif bmp tif tiff webp svg ico heic mp3 wav m4a flac mp4 m4v '
    'mov avi mkv webm'.split()
)

# Executable formats for the masquerade test. LNK is included on top of
# file_inspect.EXECUTABLE_MAGIC because a shortcut named `report.pdf` is exactly
# the same lie as a PE named `report.pdf`; file_inspect keeps its own set narrow
# on purpose because widening it would change persisted records.
_EXECUTABLE_LIKE_MAGIC = frozenset(EXECUTABLE_MAGIC) | {'LNK'}

# Archive-member extensions that indicate a packaged executable. Narrower than
# file_inspect.EXECUTABLE_EXTENSIONS on purpose: `.js` and `.dll` appear in the
# manifest of practically every legitimate software distribution and web-project
# archive, so including them would make this signal fire on almost everything.
_ARCHIVED_EXECUTABLE_EXTENSIONS = (
    'exe', 'scr', 'pif', 'com', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'wsf', 'wsh',
    'hta', 'msi', 'lnk', 'jar',
)

# Bidirectional-override code points. `invoice\u202Egpj.exe` renders as
# `invoicexe.jpg` in every Windows file listing.
_BIDI_OVERRIDES = ('\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
                   '\u200e', '\u200f', '\u2066', '\u2067', '\u2068', '\u2069')

# Content rules: signal -> alternation over the joined strings sample. Patterns
# are matched case-insensitively and must never cross a newline, because the
# sample is joined with newlines and a match spanning two unrelated strings is a
# coincidence, not an observation.
_CONTENT_RULES = (
    ('reverse_shell', (
        r'/dev/(?:tcp|udp)/',
        r'\bn(?:c|cat|etcat)(?:\.exe)?\s+-[a-z]{0,4}e\b',
        r'\b(?:ba|z)?sh\s+-i\s*>&',
        r'\bmkfifo\s+/(?:tmp|var/tmp|dev/shm)/',
        r'\bsocat\b[^\n]{0,80}\bexec:',
        r'\bexec\s+\d+<>\s*/dev/tcp/',
    )),
    ('credential_theft', (
        r'\bmimikatz\b',
        r'\b(?:sekurlsa|lsadump|kerberos|crypto)::',
        r'\bprivilege::debug\b',
        r'\bsignons\.sqlite\b',
        r'\blogins\.json\b',
        r'\bkey[34]\.db\b',
        r'\bwallet\.dat\b',
        r'user data\\[^\n]{0,40}login data',
    )),
    ('c2_artifact', (
        r'\bmeterpreter\b',
        r'\bcobalt[ _-]?strike\b',
        r'\breflectiveloader\b',
        r'\bbeacon(?:\.x(?:64|86))?\.dll\b',
        r'\bmsf(?:venom|console)\b',
        r'\bstratum\+(?:tcp|ssl)://',
        r'\bxmrig\b',
        r'/gate\.php\b',
    )),
    # `IsDebuggerPresent` is deliberately NOT here. The MSVC CRT imports it, so a
    # large share of legitimately-built Windows binaries carry the string, and at
    # 0.25 plus the two ambient signals every packed installer already earns it
    # would push ordinary software over the suspicious floor. Every token below is
    # one that ordinary software has no reason to reference.
    ('anti_analysis', (
        r'\bcheckremotedebuggerpresent\b',
        r'\bntglobalflag\b',
        r'\bbeingdebugged\b',
        r'\bptrace_traceme\b',
        r'\bsbiedll(?:\.dll)?\b',
        r'\bsandboxie\b',
        r'\bvbox(?:guest|service|tray|sf|video)\b',
        r'\bvm(?:toolsd|wareuser|waretray|check)\b',
        r'\bfrida[-_](?:agent|gadget)\b',
        r'\bcuckoomon\b',
        r'\bwine_get_version\b',
    )),
    ('download_cradle', (
        r'\bcertutil(?:\.exe)?[^\n]{0,40}-urlcache',
        r'\bbitsadmin(?:\.exe)?[^\n]{0,40}/transfer',
        r'\bstart-bitstransfer\b',
        r'\bmshta(?:\.exe)?\s+(?:https?://|vbscript:|javascript:)',
        r'\bregsvr32(?:\.exe)?[^\n]{0,40}/i:\s*(?:https?://|scrobj)',
        r'\bmsiexec(?:\.exe)?[^\n]{0,20}/i\s+https?://',
        r'webclient\)?\s*\)?\.download(?:string|file|data)',
        r'\binvoke-webrequest\b[^\n]{0,80}-outfile',
        r'\b(?:curl|wget)\b[^\n]{0,120}\|\s*(?:ba|z)?sh\b',
    )),
    ('encoded_command', (
        r'-e(?:nc|ncodedcommand)\b',
        r'\bpowershell(?:\.exe)?[^\n]{0,60}\s-e[a-z]{0,13}\s+[A-Za-z0-9+/=]{40,}',
        r'\bfrombase64string\b',
        r'\bcertutil(?:\.exe)?[^\n]{0,40}-decode',
        r'\binvoke-expression\b',
        r'\biex\s*[\(\$]',
        r'\[char\]\s*\d+\s*[,+]',
        r'\[convert\]::from',
    )),
    ('privilege_escalation', (
        r'\bsedebugprivilege\b',
        r'\bauthorizationexecutewithprivileges\b',
        r'\bstprivilegedtask\b',
        r'\bchmod\s+[ugoa]?\+s\b',
        r'/(?:private/)?etc/sudoers\b',
        r'\bfodhelper(?:\.exe)?\b',
        r'\bcomputerdefaults\.exe\b',
        r'\bbypassuac\b',
    )),
    ('persistence', (
        r'currentversion\\run(?:once)?\b',
        r'\bschtasks(?:\.exe)?[^\n]{0,40}/create\b',
        r'\bregisterscheduledtask\b',
        r'\bcrontab\s+-',
        r'/library/launch(?:agents|daemons)/',
        r'\bnew-service\b',
        r'\bsc(?:\.exe)?\s+create\b',
        r'winlogon\\shell\b',
        r'\buserinit\b',
    )),
    # No trailing \b on the Win32 API names: they ship as ANSI/wide pairs
    # (`URLDownloadToFileW`, `InternetOpenUrlA`), and a word boundary after the
    # base name matches neither variant.
    ('download_staging', (
        r'\burldownloadtofile',
        r'\bwebclient\b',
        r'\b(?:curl|wget)\s+-{1,2}[a-z]',
        r'\binvoke-webrequest\b',
        r'\bnsurldownload\b',
        r'\burlsessiondownloadtask\b',
        r'\binternet(?:openurl|readfile)',
        r'\bwinhttp(?:openrequest|sendrequest)',
        r'\bhttpsendrequest',
    )),
)

_CONTENT_PATTERNS = tuple(
    (signal, re.compile('|'.join(patterns), re.IGNORECASE))
    for signal, patterns in _CONTENT_RULES
)

# A base64 run long enough to hold a payload. Checked with finditer rather than
# search because a pure-hex run of the same length (a SHA-256/512 digest, a GUID
# table) matches the same character class and is not a blob.
_BASE64_RUN_RE = re.compile(r'[A-Za-z0-9+/]{60,}={0,2}')
_HEX_ONLY_RE = re.compile(r'[0-9a-fA-F]+\Z')

# Wallet addresses, anchored so they cannot be carved out of the middle of a
# longer alphanumeric run. Without the boundaries the Base58 alternation matches
# constantly inside packed/high-entropy data, which is exactly the population
# where this signal would do the most damage. `+`, `/`, and `=` are in the
# boundary class as well as the alphanumerics: a base64 blob is one long run
# punctuated by exactly those three characters, so leaving them out would let a
# certificate or resource blob be carved into a "Base58 address" at every `/`.
_CRYPTO_ADDRESS_RE = re.compile(
    r'(?<![A-Za-z0-9+/=])(?:'
    r'bc1[ac-hj-np-z02-9]{11,71}'
    r'|[13][a-km-zA-HJ-NP-Z1-9]{25,34}'
    r'|0x[a-fA-F0-9]{40}'
    r'|4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}'
    r')(?![A-Za-z0-9+/=])'
)

_ARCHIVED_EXECUTABLE_RE = re.compile(
    r'[\w\-. ()\[\]{}~$@#]{1,80}\.(?:%s)(?![\w])'
    % '|'.join(_ARCHIVED_EXECUTABLE_EXTENSIONS),
    re.IGNORECASE,
)

# .lnk signal key -> rollup signal. lnk_parse owns the 30 key names; they are
# imported rather than retyped so a rename there cannot silently stop matching
# here. app/tests/test_file_rules.py asserts this is a total partition of
# lnk_parse.SIGNAL_LABELS, which forces a weighting decision when a key is added.
LNK_ROLLUPS = {
    'lnk_encoded_command': frozenset({
        'encoded_powershell_command', 'base64_blob_in_arguments',
        'frombase64string', 'invoke_expression', 'char_code_obfuscation',
        'env_var_obfuscation',
    }),
    'lnk_appended_data': frozenset({'appended_data_after_structures'}),
    'lnk_download_cradle': frozenset({'download_cradle'}),
    'lnk_masquerade': frozenset({
        'document_icon_masquerade', 'document_extension_masquerade',
    }),
    'lnk_defense_evasion': frozenset({
        'execution_policy_bypass', 'no_profile_argument', 'defender_tamper',
    }),
    'lnk_hidden_window': frozenset({
        'hidden_window_argument', 'hidden_window_show_command',
        'hidden_window_with_network_indicator',
    }),
    'lnk_lolbas_target': frozenset({'lolbas_target', 'lolbas_in_arguments'}),
    'lnk_persistence': frozenset({'persistence_command'}),
    'lnk_elevation_request': frozenset({'run_as_user'}),
    'lnk_network_indicator': frozenset({
        'unc_path_in_arguments', 'embedded_url', 'embedded_ip',
        'network_share_target',
    }),
    'lnk_structural_anomaly': frozenset({
        'excessive_argument_length', 'target_size_mismatch', 'oversized_lnk_file',
        'malformed_header_size',
    }),
    'lnk_suspicious_target_path': frozenset({
        'target_outside_program_locations', 'target_in_user_writable_path',
    }),
}

# Per-source statuses that mean a reputation provider gave an actual answer.
# 'skipped' (no API key), 'error', and 'unavailable' are all *not* answers - a
# source that was never asked, or that failed, says nothing about the file.
_ANSWERED_STATUSES = frozenset({'found', 'not_found', 'no_record', 'clean', 'ok'})


def _as_dict(value):
    return value if isinstance(value, dict) else {}


def _as_list(value):
    return value if isinstance(value, (list, tuple)) else ()


def _as_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _as_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _strings_text(record):
    """The strings sample as one newline-joined, length-bounded blob."""
    parts = []
    total = 0
    for item in _as_list(record.get('strings_sample')):
        text = item if isinstance(item, str) else str(item)
        parts.append(text)
        total += len(text) + 1
        if total >= MAX_STRINGS_TEXT:
            break
    return '\n'.join(parts)[:MAX_STRINGS_TEXT]


def _has_base64_blob(text):
    for match in _BASE64_RUN_RE.finditer(text):
        if not _HEX_ONLY_RE.match(match.group(0)):
            return True
    return False


def _lnk_signal_keys(record):
    """The set of lnk_parse signal keys present on this record, if any."""
    lnk = _as_dict(record.get('lnk'))
    keys = set()
    for entry in _as_list(lnk.get('signals')):
        if isinstance(entry, dict):
            key = entry.get('key')
        else:
            key = entry
        if isinstance(key, str):
            keys.add(key)
    return keys


def _embedded_count(record):
    return sum(
        1 for entry in _as_list(record.get('embedded_executables'))
        if _as_int(_as_dict(entry).get('offset')) > 0
    )


def _reputation_answered(reputation):
    """True when at least one reputation source actually returned an answer.

    Accepts the shapes `hash_service` produces (`sources[name]['status']`), the
    per-source accounting shape (`sources[name]['state']`), and an explicit
    `answered` override, so the orchestrating service can be unambiguous. Anything
    unrecognised counts as *not* answered - failing closed here is what keeps a
    keyless deployment from reporting `benign`.
    """
    if reputation.get('answered') is not None:
        return bool(reputation.get('answered'))
    if reputation.get('known_malware'):
        return True
    for value in _as_dict(reputation.get('sources')).values():
        source = _as_dict(value)
        for field in ('status', 'state'):
            if str(source.get(field) or '').lower() in _ANSWERED_STATUSES:
                return True
    return False


def _known_malware(reputation):
    """True when a reputation source calls this file malicious."""
    if reputation.get('known_malware'):
        return True
    for value in _as_dict(reputation.get('sources')).values():
        source = _as_dict(value)
        if source.get('is_malicious') or _as_dict(source.get('summary')).get('is_malicious'):
            return True
    return False


def _filename_masquerade(filename):
    """A filename engineered to display an extension the file does not have."""
    name = filename if isinstance(filename, str) else str(filename or '')
    if any(marker in name for marker in _BIDI_OVERRIDES):
        return True
    parts = [part.strip() for part in name.split('.')]
    if len(parts) < 3:
        return False
    return (
        parts[-1].lower() in EXECUTABLE_EXTENSIONS
        and parts[-2].lower() in DOCUMENT_EXTENSIONS
    )


def score(record):
    """Score an inspected file. Pure; no I/O. Never raises on a bad record.

    Returns ``{'level', 'score', 'signals'}``. ``level`` is ``unknown`` when no
    reputation source answered and nothing structural reached a band - never a
    false ``benign``.
    """
    record = record if isinstance(record, dict) else {}

    magic = str(record.get('magic_type') or '').upper()
    extension = file_extension(record.get('filename'))
    reputation = _as_dict(record.get('reputation'))
    lnk_keys = _lnk_signal_keys(record)
    text = _strings_text(record)

    content = {
        signal: bool(pattern.search(text))
        for signal, pattern in _CONTENT_PATTERNS
    }

    executable = bool(
        record.get('is_executable')
        or magic in EXECUTABLE_MAGIC
        or extension in EXECUTABLE_EXTENSIONS
    )
    archive = bool(
        record.get('is_archive')
        or magic in ARCHIVE_MAGIC
        or extension in ('zip', 'rar', '7z', 'tar', 'gz', 'cab', 'iso', 'img')
    )
    embedded = _embedded_count(record) > 0
    # A container that is neither an executable nor an archive: a PDF, an RTF, a
    # legacy Office document, an image. A second program inside one of those has
    # no benign explanation the way an installer's payload does.
    document_container = not executable and not archive and bool(
        magic in ('PDF', 'OLE', 'RTF') or extension in DOCUMENT_EXTENSIONS
    )

    encoded = content['encoded_command']
    cradle = content['download_cradle']
    persistence = content['persistence']
    staging = content['download_staging']

    lnk_present = {
        rollup: bool(lnk_keys & keys) for rollup, keys in LNK_ROLLUPS.items()
    }

    present = {
        'known_malware_hash': _known_malware(reputation),
        'executable_masquerading_as_document': bool(
            extension in DOCUMENT_EXTENSIONS and magic in _EXECUTABLE_LIKE_MAGIC
        ),
        'credential_theft': content['credential_theft'],
        'embedded_executable_at_offset': embedded,
        'filename_masquerade': _filename_masquerade(record.get('filename')),
        'reverse_shell': content['reverse_shell'],
        'anti_analysis': content['anti_analysis'],
        'c2_artifact': content['c2_artifact'],
        'download_cradle': cradle,
        'embedded_executable_in_document': embedded and document_container,
        'encoded_command': encoded,
        'archive_containing_executable': archive and bool(
            embedded or _ARCHIVED_EXECUTABLE_RE.search(text)
        ),
        'privilege_escalation': content['privilege_escalation'],
        'crypto_address': bool(_CRYPTO_ADDRESS_RE.search(text)),
        'persistence': persistence,
        'base64_blob': _has_base64_blob(text),
        'download_staging': staging,
        'executable_file': executable,
        'high_entropy': bool(
            _as_float(record.get('entropy')) >= HIGH_ENTROPY_MIN
            and _as_int(record.get('size_bytes')) >= MIN_ENTROPY_SIZE
        ),
        'encoded_command+download_cradle': encoded and cradle,
        'persistence+download_staging': persistence and staging,
        'analysis_error': bool(record.get('error')),
        'analysis_truncated': bool(record.get('truncated')),
        'no_reputation_data': not _reputation_answered(reputation),
    }
    present.update(lnk_present)
    present['lnk_encoded_command+lnk_download_cradle'] = (
        lnk_present['lnk_encoded_command'] and lnk_present['lnk_download_cradle']
    )
    present['lnk_lolbas_target+lnk_hidden_window'] = (
        lnk_present['lnk_lolbas_target'] and lnk_present['lnk_hidden_window']
    )

    signals = [name for name in WEIGHTS if present.get(name)]
    total = min(sum(WEIGHTS[name] for name in signals), 1.0)

    if total >= MALICIOUS_THRESHOLD:
        level = 'malicious'
    elif total >= SUSPICIOUS_THRESHOLD:
        level = 'suspicious'
    elif _reputation_answered(reputation):
        level = 'benign'
    else:
        level = 'unknown'

    return {'level': level, 'score': round(total, 3), 'signals': signals}
