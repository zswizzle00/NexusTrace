"""The two keyless hash reputation sources, and the non-blocking VirusTotal limiter.

Pure: no server, no network, no browser. The HTTP transport and the DNS resolver are
injected, and the rate-limiter cases use short windows rather than the real minute.

The cases that matter most are the two that stop a later "improvement" from turning either
new source into a verdict:

* `test_mhr_empty_file_regression` pins the real observed answer for the empty-file MD5
  (`"1445018789 91"`) and asserts nothing in that path reaches `malicious` or fires
  `known_malware_hash`.
* `test_circl_nsrl_does_not_clear` pins that CIRCL answering, including with full NSRL
  provenance, leaves `file_rules`' `benign` gate shut. EICAR is in NSRL.
"""
import os
import sys
import time
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))))

import dns.exception  # noqa: E402
import dns.resolver  # noqa: E402

from app.services import file_rules, hash_service  # noqa: E402
from app.utils import hash_reputation  # noqa: E402
from app.utils.rate_limiter import RateLimiter  # noqa: E402

REPO = Path(__file__).resolve().parent.parent.parent

EMPTY_FILE_MD5 = 'd41d8cd98f00b204e9800998ecf8427e'
EMPTY_FILE_MHR = '1445018789 91'
EICAR_MD5 = '44d88612fea8a8f36de82e1278abb02f'
EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
UNKNOWN_SHA256 = 'a' * 64

REFERENCE = 'https://example.test/reference'

# The shape CIRCL actually returns for EICAR, trimmed of the ~15 KB `parents` array.
CIRCL_EICAR = (
    '{"CRC32": "6851CF3C", "FileName": "eicar.com", "FileSize": "68",'
    ' "KnownMalicious": "malshare.com", "MD5": "44D88612FEA8A8F36DE82E1278ABB02F",'
    ' "ProductCode": {"ProductName": "Gentoo Linux 2005.0 Ubuntu 5.04"},'
    ' "RDS:package_id": "304063",'
    ' "SHA-256": "275A021BBFB6489E54D471899F7DB9D1663FC695EC2FE2A2C4538AABF651FD0F",'
    ' "db": "nsrl_legacy", "hashlookup:trust": 100}'
)

# The same record with the malicious flag removed: NSRL provenance and nothing else.
CIRCL_NSRL_ONLY = (
    '{"FileName": "kernel32.dll", "FileSize": "1024",'
    ' "MD5": "00000000000000000000000000000000",'
    ' "ProductCode": {"ProductName": "Windows 10"},'
    ' "RDS:package_id": "999", "OpSystemCode": {"OpSystemName": "Windows"},'
    ' "db": "nsrl", "hashlookup:trust": 100}'
)

CASES = 0
FAILURES = []


def ok(condition, label, detail=''):
    global CASES
    CASES += 1
    if not condition:
        FAILURES.append(f'{label}: {detail}' if detail else label)


def eq(actual, expected, label):
    ok(actual == expected, label, f'expected {expected!r}, got {actual!r}')


class FakeResponse:
    def __init__(self, status_code, text=''):
        self.status_code = status_code
        self.text = text


class CountingTransport:
    def __init__(self, response):
        self.response = response
        self.calls = 0

    def __call__(self, url, headers=None, timeout=None):
        self.calls += 1
        self.url = url
        return self.response


def exploding_transport(*args, **kwargs):
    raise AssertionError('an HTTP request was issued when none was permitted')


def exploding_resolver(*args, **kwargs):
    raise AssertionError('a DNS query was issued when none was permitted')


def test_mhr_parsing():
    print('\nMHR TXT parsing:')
    well_formed, reason = hash_reputation.parse_mhr_txt([EMPTY_FILE_MHR])
    eq(reason, None, 'well-formed answer has no reason')
    eq(well_formed['last_seen'], 1445018789, 'well-formed epoch')
    eq(well_formed['detection_pct'], 91, 'well-formed percentage')
    ok(well_formed['last_seen_utc'].endswith('Z'), 'epoch is rendered as UTC',
       well_formed['last_seen_utc'])

    padded, reason = hash_reputation.parse_mhr_txt(['   1445018789    91   '])
    eq(reason, None, 'extra whitespace parses')
    eq(padded['detection_pct'], 91, 'extra whitespace keeps the percentage')

    quoted, reason = hash_reputation.parse_mhr_txt(['"1445018789 91"'])
    eq(reason, None, 'a quoted answer parses')
    eq(quoted['last_seen'], 1445018789, 'a quoted answer keeps the epoch')

    for label, value in (('bytes', b'1445018789 91'),
                         ('bytearray', bytearray(b'1445018789 91')),
                         ('bare str', '1445018789 91')):
        summary, reason = hash_reputation.parse_mhr_txt(value)
        eq(reason, None, f'{label} answer parses')
        eq(summary['detection_pct'], 91, f'{label} answer keeps the percentage')

    mixed, reason = hash_reputation.parse_mhr_txt([b'1445018789 91', '999 1'])
    eq(reason, None, 'a bytes answer in a list parses')
    eq(mixed['last_seen'], 1445018789, 'the first parseable record wins')

    multiple, reason = hash_reputation.parse_mhr_txt(['not a record', '1445018789 91'])
    eq(reason, None, 'a later parseable record is used')
    eq(multiple['detection_pct'], 91, 'multiple TXT records pick the parseable one')

    for label, value in (('empty list', []),
                         ('tuple of blanks', ('', '   ')),
                         ('None', None),
                         ('an int', 7),
                         ('a dict', {'a': 1}),
                         ('empty string', '')):
        summary, reason = hash_reputation.parse_mhr_txt(value)
        eq(summary, None, f'{label} yields no summary')
        eq(reason, 'no_answer', f'{label} is no_answer')

    for label, value in (('garbage', 'garbage'),
                         ('one field', '1445018789'),
                         ('three fields', '1445018789 91 extra'),
                         ('non-integer percentage', '1445018789 ninety'),
                         ('non-integer epoch', 'yesterday 91'),
                         ('percentage above 100', '1445018789 101'),
                         ('negative percentage', '1445018789 -1'),
                         ('negative epoch', '-5 50'),
                         ('float percentage', '1445018789 91.5')):
        summary, reason = hash_reputation.parse_mhr_txt([value])
        eq(summary, None, f'{label} yields no summary')
        eq(reason, 'malformed_answer', f'{label} is malformed_answer')

    boundary_low, reason = hash_reputation.parse_mhr_txt(['0 0'])
    eq(reason, None, 'a zero percentage is a valid answer')
    eq(boundary_low['detection_pct'], 0, 'zero percentage is kept')
    boundary_high, reason = hash_reputation.parse_mhr_txt(['1445018789 100'])
    eq(reason, None, '100 percent is a valid answer')
    eq(boundary_high['detection_pct'], 100, '100 percent is kept')

    print(f'  PASS  parsing cases, malformed is distinct from no_answer')


def test_mhr_envelope():
    print('\nMHR envelopes:')
    found = hash_reputation.mhr_result('md5', [EMPTY_FILE_MHR], REFERENCE)
    eq(found['state'], 'found', 'a parseable answer is found')
    eq(found['source'], 'cymru_mhr', 'source name')
    eq(sorted(found), ['raw', 'reference', 'source', 'state', 'summary'],
       'envelope has the five abuse.ch keys')
    eq(found['reference'], REFERENCE, 'the reference is passed through')

    no_record = hash_reputation.mhr_result('sha1', [], REFERENCE)
    eq(no_record['state'], 'no_record', 'an empty answer set is no_record')
    eq(no_record['summary'], {}, 'no_record carries no summary')

    unavailable = hash_reputation.mhr_result('md5', ['nonsense'], REFERENCE)
    eq(unavailable['state'], 'unavailable', 'a malformed answer is unavailable')
    eq(unavailable['raw']['error'], 'malformed_answer', 'the reason is reported')

    for hash_type in ('sha256', 'sha512', '', None, 'MD5X'):
        envelope = hash_reputation.mhr_result(hash_type, [EMPTY_FILE_MHR], REFERENCE)
        eq(envelope['state'], 'unavailable', f'{hash_type!r} is unavailable at MHR')
        eq(envelope['raw']['error'], 'unsupported_hash_type',
           f'{hash_type!r} reports the unsupported type')

    for hash_type in ('md5', 'MD5', 'sha1', 'SHA1'):
        envelope = hash_reputation.mhr_result(hash_type, [EMPTY_FILE_MHR], REFERENCE)
        eq(envelope['state'], 'found', f'{hash_type!r} is supported at MHR')

    eq(hash_reputation.MHR_HASH_TYPES, ('md5', 'sha1'),
       'MHR supports md5 and sha1 only, with no sha256 lookup to invent')
    print('  PASS  found / no_record / unavailable, sha256 refused rather than queried')


def test_mhr_empty_file_regression():
    """MHR answered "1445018789 91" for the empty file. It must inform, never decide."""
    print('\nMHR noise regression (empty-file MD5 at 91%):')
    envelope = hash_reputation.mhr_result('md5', [EMPTY_FILE_MHR], REFERENCE)
    eq(envelope['state'], 'found', 'the empty file is a found record at MHR')
    eq(envelope['summary']['detection_pct'], 91, 'the observed 91% is reported')

    ok('known_malicious' not in envelope['summary'],
       'MHR never reports a malicious flag', envelope['summary'])
    ok(not envelope['summary'].get('is_malicious'),
       'MHR never sets is_malicious')

    for key in ('cymru_mhr', 'mhr_detection', 'detection_pct', 'mhr'):
        ok(key not in file_rules.WEIGHTS, f'file_rules has no {key} weight')

    rows = hash_service.advisory_rows({hash_reputation.MHR_SOURCE: envelope})
    reputation = {'sources': {}, 'advisory': rows, 'known_malware': False,
                  'links': {}}
    ok(not file_rules._known_malware(reputation),
       'an MHR hit alone is not known malware')
    ok(not file_rules._reputation_answered(reputation),
       'an MHR hit alone does not satisfy the benign gate')

    verdict = file_rules.score({'filename': 'empty.txt', 'size_bytes': 0,
                                'reputation': reputation})
    ok(verdict['level'] != 'malicious', 'an MHR hit alone is not malicious',
       verdict)
    ok(verdict['level'] != 'benign', 'an MHR hit alone does not clear the file',
       verdict)
    eq(verdict['level'], 'unknown', 'an MHR hit alone leaves the file unknown')
    ok('known_malware_hash' not in verdict['signals'],
       'an MHR hit never fires known_malware_hash', verdict['signals'])

    detail = hash_service._advisory_detail(envelope)
    ok('91%' in detail, 'the analyst still sees the percentage', detail)
    print('  PASS  91% is surfaced, and reaches neither known_malware_hash nor a band')


def test_circl_mapping():
    print('\nCIRCL hashlookup mapping:')
    found = hash_reputation.circl_result('sha256', 200, CIRCL_EICAR, REFERENCE)
    eq(found['state'], 'found', 'a KnownMalicious record is found')
    eq(found['summary']['known_malicious'], 'malshare.com', 'the flagging source is kept')
    eq(found['summary']['nsrl_present'], True, 'EICAR is reported as present in NSRL')
    eq(found['summary']['file_name'], 'eicar.com', 'the file name is kept')
    eq(found['summary']['package_id'], '304063', 'the RDS package id is kept')
    eq(sorted(found), ['raw', 'reference', 'source', 'state', 'summary'],
       'envelope has the five abuse.ch keys')
    ok('parents' not in found['raw'],
       'the parents array is not carried into raw', sorted(found['raw']))

    nsrl = hash_reputation.circl_result('sha1', 200, CIRCL_NSRL_ONLY, REFERENCE)
    eq(nsrl['state'], 'found', 'an NSRL-only record is still found')
    eq(nsrl['summary']['known_malicious'], None, 'an NSRL-only record has no flag')
    eq(nsrl['summary']['nsrl_present'], True, 'an NSRL-only record is present in NSRL')
    eq(nsrl['summary']['product_name'], 'Windows 10', 'the product name is kept')

    missing = hash_reputation.circl_result(
        'sha256', 404, '{"message": "Non existing SHA-256", "query": "aaa"}', REFERENCE)
    eq(missing['state'], 'no_record', 'a 404 is no_record, not an error')
    eq(missing['raw']['http_status'], 404, 'the status is recorded')

    for status in (500, 502, 429, 403, None):
        envelope = hash_reputation.circl_result('md5', status, '{}', REFERENCE)
        eq(envelope['state'], 'unavailable', f'HTTP {status} is unavailable')
        eq(envelope['raw']['error'], f'http_{status}', f'HTTP {status} names itself')

    malformed = hash_reputation.circl_result('md5', 200, '{not json', REFERENCE)
    eq(malformed['state'], 'unavailable', 'malformed JSON is unavailable')
    eq(malformed['raw']['error'], 'unparseable_body', 'malformed JSON names itself')

    for label, body in (('a JSON list', '[]'), ('a JSON string', '"hello"'),
                        ('a JSON number', '12')):
        envelope = hash_reputation.circl_result('md5', 200, body, REFERENCE)
        eq(envelope['state'], 'unavailable', f'{label} is unavailable')
        eq(envelope['raw']['error'], 'unexpected_body', f'{label} names itself')

    message_200 = hash_reputation.circl_result(
        'md5', 200, '{"message": "Non existing MD5"}', REFERENCE)
    eq(message_200['state'], 'no_record',
       'a 200 that identifies nothing is no_record, not a record')

    for hash_type in ('sha512', '', None, 'ssdeep'):
        envelope = hash_reputation.circl_result(hash_type, 200, CIRCL_EICAR, REFERENCE)
        eq(envelope['state'], 'unavailable', f'{hash_type!r} is unavailable at CIRCL')
        eq(envelope['raw']['error'], 'unsupported_hash_type',
           f'{hash_type!r} reports the unsupported type')

    eq(hash_reputation.CIRCL_HASH_TYPES, ('md5', 'sha1', 'sha256'),
       'CIRCL accepts a pasted sha256, which is why it carries the upload case')
    print('  PASS  KnownMalicious, NSRL-only, 404, 5xx, malformed, unsupported')


def test_circl_nsrl_does_not_clear():
    """EICAR is in NSRL, so presence in NSRL can never lower a verdict."""
    print('\nCIRCL cannot clear a file:')
    nsrl = hash_reputation.circl_result('sha256', 200, CIRCL_NSRL_ONLY, REFERENCE)
    rows = hash_service.advisory_rows({hash_reputation.CIRCL_SOURCE: nsrl})
    reputation = {'sources': {}, 'advisory': rows, 'known_malware': False, 'links': {}}

    ok(not file_rules._reputation_answered(reputation),
       'NSRL presence does not satisfy the benign gate')
    ok(not file_rules._known_malware(reputation),
       'NSRL presence is not known malware')

    verdict = file_rules.score({'filename': 'kernel32.dll', 'size_bytes': 1024,
                                'reputation': reputation})
    eq(verdict['level'], 'unknown', 'an NSRL-only answer leaves the file unknown')
    ok('no_reputation_data' in verdict['signals'],
       'the thin verdict is still reported as thin', verdict['signals'])

    detail = hash_service._advisory_detail(nsrl)
    ok('not a clean verdict' in detail,
       'the NSRL row says so in words too', detail)

    # A structural pin on the split: the two new sources are reported beside `sources`,
    # never inside it, because `sources` is what the benign gate walks.
    eq(hash_service.ADVISORY_SOURCES, ('circl_hashlookup', 'cymru_mhr'),
       'both new sources are declared advisory')
    for name in hash_service.ADVISORY_SOURCES:
        ok(name not in file_rules._ANSWERED_STATUSES,
           f'{name} is not smuggled into the answered-status vocabulary')

    # KnownMalicious is the one thing that may raise a verdict, and it does so through
    # the existing known_malware_hash signal rather than a new weight.
    malicious_rep = {'sources': {}, 'advisory': [], 'known_malware': True, 'links': {}}
    malicious = file_rules.score({'filename': 'eicar.com', 'size_bytes': 68,
                                  'reputation': malicious_rep})
    eq(malicious['level'], 'malicious', 'a KnownMalicious hit still reaches malicious')
    ok('known_malware_hash' in malicious['signals'],
       'it does so through the existing signal', malicious['signals'])
    eq(file_rules.WEIGHTS['known_malware_hash'], file_rules.MALICIOUS_THRESHOLD,
       'the existing weight and threshold are untouched')
    eq(file_rules.SUSPICIOUS_THRESHOLD, 0.30, 'SUSPICIOUS_THRESHOLD is untouched')
    print('  PASS  NSRL never clears; KnownMalicious raises via the existing signal')


def test_advisory_rows():
    print('\nAdvisory row assembly:')
    rows = hash_service.advisory_rows(None)
    eq(len(rows), 2, 'both sources always get a row')
    eq([r['name'] for r in rows], ['CIRCL hashlookup', 'Team Cymru MHR'],
       'the order is fixed')
    for row in rows:
        eq(row['state'], 'unavailable', f"{row['name']} with no envelope is unavailable")
        eq(row['key_env'], None, f"{row['name']} is keyless, so it has no key_env")
        ok(row['state'] != 'skipped',
           f"{row['name']} is never 'skipped', which means no key configured")

    unsupported = hash_reputation.mhr_result('sha256', None, REFERENCE)
    rows = hash_service.advisory_rows({hash_reputation.MHR_SOURCE: unsupported})
    detail = rows[1]['detail']
    ok('not supported' in detail, 'a sha256 says MHR cannot answer', detail)
    print('  PASS  both rows always present, keyless never reads as not-configured')


def test_service_mhr_dns():
    print('\nMHR service layer (injected resolver):')
    hash_service.get_cymru_mhr.cache_clear()

    def answering(name, lifetime=None):
        answering.name = name
        return [EMPTY_FILE_MHR]

    envelope = hash_service.get_cymru_mhr(EMPTY_FILE_MD5, answering)
    eq(envelope['state'], 'found', 'a TXT answer is found')
    eq(answering.name, f'{EMPTY_FILE_MD5}.{hash_service.MHR_ZONE}',
       'the query name is the hash under the MHR zone')

    def nxdomain(name, lifetime=None):
        raise dns.resolver.NXDOMAIN()

    eq(hash_service.get_cymru_mhr(UNKNOWN_SHA256[:32], nxdomain)['state'], 'no_record',
       'NXDOMAIN is no_record')

    def no_answer(name, lifetime=None):
        raise dns.resolver.NoAnswer()

    eq(hash_service.get_cymru_mhr('b' * 32, no_answer)['state'], 'no_record',
       'an empty answer set is no_record')

    def timeout(name, lifetime=None):
        raise dns.exception.Timeout()

    timed_out = hash_service.get_cymru_mhr('c' * 32, timeout)
    eq(timed_out['state'], 'unavailable', 'a resolver timeout is unavailable, not no_record')
    eq(timed_out['raw']['error'], 'resolver_error', 'the failure is named')

    def exploding(name, lifetime=None):
        raise RuntimeError('boom')

    eq(hash_service.get_cymru_mhr('d' * 32, exploding)['state'], 'unavailable',
       'an unexpected resolver error never propagates')

    # The point of the md5/sha1-only limitation: a sha256 must not be queried at all.
    sha256_result = hash_service.get_cymru_mhr(EICAR_SHA256, exploding_resolver)
    eq(sha256_result['state'], 'unavailable', 'a sha256 is unavailable at MHR')
    eq(sha256_result['raw']['error'], 'unsupported_hash_type',
       'a sha256 reports the unsupported type rather than a fabricated lookup')
    print('  PASS  NXDOMAIN and empty answer are no_record; sha256 issues no query')


def test_service_circl_http():
    print('\nCIRCL service layer (injected transport):')
    hash_service.get_circl_hashlookup.cache_clear()

    transport = CountingTransport(FakeResponse(200, CIRCL_EICAR))
    envelope = hash_service.get_circl_hashlookup(EICAR_SHA256, transport)
    eq(envelope['state'], 'found', 'a 200 with a record is found')
    eq(transport.calls, 1, 'exactly one request per lookup')
    eq(transport.url, f'{hash_service.CIRCL_LOOKUP_BASE}/sha256/{EICAR_SHA256}',
       'the URL names the algorithm and the hash')

    md5_transport = CountingTransport(FakeResponse(200, CIRCL_EICAR))
    hash_service.get_circl_hashlookup(EICAR_MD5, md5_transport)
    eq(md5_transport.url, f'{hash_service.CIRCL_LOOKUP_BASE}/md5/{EICAR_MD5}',
       'an md5 uses the md5 path')

    missing = CountingTransport(FakeResponse(404, '{"message": "Non existing SHA-256"}'))
    eq(hash_service.get_circl_hashlookup(UNKNOWN_SHA256, missing)['state'], 'no_record',
       'a 404 from the service layer is no_record')

    class Failing:
        def __call__(self, url, headers=None, timeout=None):
            import requests
            raise requests.Timeout()

    timed_out = hash_service.get_circl_hashlookup('e' * 64, Failing())
    eq(timed_out['state'], 'unavailable', 'a timeout is unavailable')
    eq(timed_out['raw']['error'], 'timeout', 'the failure is named')

    unsupported = hash_service.get_circl_hashlookup('f' * 128, exploding_transport)
    eq(unsupported['state'], 'unavailable', 'a sha512 is unavailable at CIRCL')
    eq(unsupported['raw']['error'], 'unsupported_hash_type',
       'a sha512 issues no request')
    print('  PASS  found / no_record / timeout, unsupported type issues no request')


def test_try_acquire():
    print('\nRateLimiter.try_acquire:')
    limiter = RateLimiter(max_requests=3, time_window=timedelta(minutes=1))

    started = time.monotonic()
    granted = [limiter.try_acquire() for _ in range(3)]
    eq(granted, [True, True, True], 'tokens are granted up to the cap')
    refused = limiter.try_acquire()
    eq(refused, False, 'the call past the cap is refused')
    elapsed = time.monotonic() - started
    ok(elapsed < 0.25, 'try_acquire never sleeps, even on a one-minute window',
       f'{elapsed:.3f}s elapsed')

    eq(len(limiter.requests), 3, 'a refused call consumes no token')
    eq(limiter.try_acquire(), False, 'a second refusal is still a refusal')
    eq(len(limiter.requests), 3, 'repeated refusals still consume nothing')

    short = RateLimiter(max_requests=1, time_window=timedelta(seconds=0.15))
    eq(short.try_acquire(), True, 'the first token on a short window is granted')
    eq(short.try_acquire(), False, 'the second is refused while the window holds')
    time.sleep(0.2)
    eq(short.try_acquire(), True, 'a token is available again after the window')

    # acquire() must stay blocking: every sub-second limiter in the app depends on it.
    blocking = RateLimiter(max_requests=1, time_window=timedelta(seconds=0.15))
    ok(blocking.acquire() is True, 'acquire still returns True')
    started = time.monotonic()
    blocking.acquire()
    waited = time.monotonic() - started
    ok(waited >= 0.1, 'acquire still waits for a token rather than failing',
       f'{waited:.3f}s waited')

    with RateLimiter(max_requests=1, time_window=timedelta(seconds=0.01)) as entered:
        ok(entered is not None, 'the context manager still yields the limiter')
    print('  PASS  non-blocking refusal, window recovery, acquire unchanged')


def test_virustotal_rate_limited():
    print('\nVirusTotal rate_limited path:')
    saved_limiter = hash_service.virustotal_limiter
    saved_key = os.environ.get('VIRUSTOTAL_API_KEY')
    os.environ['VIRUSTOTAL_API_KEY'] = 'test-key-not-used'
    try:
        hash_service._virustotal_report.cache_clear()
        hash_service.virustotal_limiter = RateLimiter(
            max_requests=1, time_window=timedelta(seconds=0.2))

        # Spend the only token, then assert the next lookup makes no request at all.
        ok(hash_service.virustotal_limiter.try_acquire(), 'the token is spent by the test')
        started = time.monotonic()
        throttled = hash_service.get_virustotal_report('1' * 64, exploding_transport)
        elapsed = time.monotonic() - started
        eq(throttled['status'], 'rate_limited',
           'a spent quota reports rate_limited, not skipped and not an error')
        ok('quota' in throttled['message'], 'the message says why', throttled)
        ok(elapsed < 0.15, 'nothing sleeps waiting for the window',
           f'{elapsed:.3f}s elapsed')

        # rate_limited must not be memoized, or the hash would report it for the whole
        # 30-minute TTL after the quota freed.
        time.sleep(0.25)
        transport = CountingTransport(FakeResponse(404))
        retried = hash_service.get_virustotal_report('1' * 64, transport)
        eq(retried['status'], 'not_found', 'the same hash is retried once the quota frees')
        eq(transport.calls, 1, 'the retry issues exactly one request')

        # A cache hit must not burn a token.
        tokens_before = len(hash_service.virustotal_limiter.requests)
        again = hash_service.get_virustotal_report('1' * 64, transport)
        eq(again['status'], 'not_found', 'the cached answer is returned')
        eq(transport.calls, 1, 'a cache hit issues no request')
        eq(len(hash_service.virustotal_limiter.requests), tokens_before,
           'a cache hit consumes no quota')

        # 'rate_limited' is a distinct state from 'skipped' in the shared vocabulary.
        eq(hash_service.source_state(True, 'rate_limited'), 'rate_limited',
           'a configured but throttled source is rate_limited')
        eq(hash_service.source_state(False, 'rate_limited'), 'skipped',
           'no key still means skipped, whatever the status says')
        eq(hash_service.source_state(True, 'not_found'), 'no_record',
           'no_record is unchanged')
        eq(hash_service.source_state(True, 'timeout'), 'unavailable',
           'unavailable is unchanged')
        ok('rate_limited' in hash_service.STATES and 'skipped' in hash_service.STATES,
           'both states are counted separately', hash_service.STATES)
    finally:
        hash_service.virustotal_limiter = saved_limiter
        hash_service._virustotal_report.cache_clear()
        if saved_key is None:
            os.environ.pop('VIRUSTOTAL_API_KEY', None)
        else:
            os.environ['VIRUSTOTAL_API_KEY'] = saved_key
    print('  PASS  zero requests when throttled, not cached, distinct from skipped')


def test_no_key_is_still_skipped():
    print('\nVirusTotal with no key:')
    saved_key = os.environ.pop('VIRUSTOTAL_API_KEY', None)
    saved_limiter = hash_service.virustotal_limiter
    try:
        hash_service._virustotal_report.cache_clear()
        hash_service.virustotal_limiter = RateLimiter(
            max_requests=1, time_window=timedelta(minutes=1))
        hash_service.virustotal_limiter.try_acquire()
        result = hash_service.get_virustotal_report('2' * 64, exploding_transport)
        eq(result, None, 'no key returns None, which renders as skipped')
        eq(len(hash_service.virustotal_limiter.requests), 1,
           'the missing key is checked before the limiter, so no token is spent')
    finally:
        hash_service.virustotal_limiter = saved_limiter
        hash_service._virustotal_report.cache_clear()
        if saved_key is not None:
            os.environ['VIRUSTOTAL_API_KEY'] = saved_key
    print('  PASS  no key short-circuits before the quota check')


def test_state_is_rendered():
    """A new state that no template names falls through to 'Unknown', which is the
    failure mode this guards."""
    print('\nTemplates name the new state:')
    for name in ('templates/hash_analysis.html', 'templates/file_analysis.html'):
        text = (REPO / name).read_text(encoding='utf-8')
        ok('rate_limited' in text, f'{name} names rate_limited')
        ok('Rate limited' in text, f'{name} gives rate_limited a label')
        ok('advisory' in text, f'{name} renders the keyless sources')
    print('  PASS  both hash-bearing templates label rate_limited')


def test_cache_registration():
    print('\nCache registration:')
    import inspect

    from app.utils import cache
    source = inspect.getsource(cache.clear_caches)
    for name in ('_virustotal_report', 'get_circl_hashlookup', 'get_cymru_mhr'):
        ok(f'hash_service.{name}' in source, f'{name} is in clear_caches()')
        ok(hasattr(getattr(hash_service, name), 'cache_clear'),
           f'{name} is actually cached, so the entry is not a silent no-op')
    ok('hash_service.get_virustotal_report,' not in source,
       'the uncached wrapper is not listed, which would be a silent no-op')
    cache.clear_caches()
    ok(True, 'clear_caches() runs without raising')
    print('  PASS  both new caches registered, no dead entry')


def main():
    test_mhr_parsing()
    test_mhr_envelope()
    test_mhr_empty_file_regression()
    test_circl_mapping()
    test_circl_nsrl_does_not_clear()
    test_advisory_rows()
    test_service_mhr_dns()
    test_service_circl_http()
    test_try_acquire()
    test_virustotal_rate_limited()
    test_no_key_is_still_skipped()
    test_state_is_rendered()
    test_cache_registration()

    if FAILURES:
        print('\nFAIL:')
        for line in FAILURES:
            print('  ' + line)
        sys.exit(1)
    print(f'\nPASS: {CASES} cases')


if __name__ == '__main__':
    main()
