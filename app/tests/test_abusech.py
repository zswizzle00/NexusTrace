"""Pins app/services/abusech.py - the unified abuse.ch client. No network, no key.

The transport (`abusech._post`) is replaced with a recording fake, so every case asserts
on the envelope the client builds, not on abuse.ch. The lookups are `timed_lru_cache`d,
so each case clears the caches first - otherwise case N would be answered from case
N-1's fake response.

The submission half (`submit_ioc`, `upload_sample`) is where the fake earns its keep:
several cases assert that *no* request was issued - for a missing key and for every local
validation failure - and that the two functions are not cached, because a cached
submission would turn a retry into a silent no-op.
"""
import hashlib
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import requests

from app.services import abusech

# Most cases here are deliberate failures, and the client logs each one at WARNING.
logging.disable(logging.CRITICAL)

ENVELOPE_KEYS = {'source', 'state', 'summary', 'reference', 'raw'}
STATES = {'found', 'no_record', 'skipped', 'unavailable'}
SUBMIT_STATES = {'submitted', 'duplicate', 'rejected', 'skipped', 'unavailable'}

CACHED = (
    abusech.threatfox_lookup,
    abusech.threatfox_hash,
    abusech.urlhaus_host,
    abusech.urlhaus_url,
    abusech.urlhaus_payload,
    abusech.malwarebazaar_hash,
    abusech.hunting_fplist,
)


class FakeResponse:
    def __init__(self, payload, status_code=200, text=None):
        self.status_code = status_code
        self._payload = payload
        self.text = text if text is not None else json.dumps(payload)

    def json(self):
        if isinstance(self._payload, str):
            raise ValueError('No JSON object could be decoded')
        return self._payload


class FakeTransport:
    """Stands in for abusech._post and records every call it receives."""

    def __init__(self, result):
        self.result = result
        self.calls = []

    def __call__(self, url, data=None, json_payload=None, headers=None, timeout=None,
                 files=None):
        self.calls.append({'url': url, 'data': data, 'json': json_payload,
                           'headers': headers, 'timeout': timeout, 'files': files})
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _reset():
    for func in CACHED:
        func.cache_clear()


def run(result, call, key='test-key'):
    """Run one lookup against a fake transport. Returns (envelope, transport)."""
    _reset()
    transport = FakeTransport(result)
    real_post = abusech._post
    previous_key = os.environ.get(abusech.AUTH_ENV)
    abusech._post = transport
    if key is None:
        os.environ.pop(abusech.AUTH_ENV, None)
    else:
        os.environ[abusech.AUTH_ENV] = key
    try:
        return call(), transport
    finally:
        abusech._post = real_post
        if previous_key is None:
            os.environ.pop(abusech.AUTH_ENV, None)
        else:
            os.environ[abusech.AUTH_ENV] = previous_key
        _reset()


THREATFOX_OK = {
    'query_status': 'ok',
    'data': [
        {'ioc': '203.0.113.10:443', 'ioc_type': 'ip:port', 'threat_type': 'botnet_cc',
         'malware_printable': 'Cobalt Strike', 'confidence_level': 100,
         'first_seen': '2026-01-02 10:00:00 UTC', 'last_seen': '2026-03-04 11:00:00 UTC',
         'tags': ['cobaltstrike', 'c2'], 'reference': 'https://example.test/report'},
        {'ioc': '203.0.113.10:443', 'ioc_type': 'ip:port', 'threat_type': 'payload_delivery',
         'malware_printable': 'Emotet', 'confidence_level': 75,
         'first_seen': '2025-12-01 09:00:00 UTC', 'last_seen': '2026-05-06 12:00:00 UTC',
         'tags': ['emotet']},
    ],
}

URLHAUS_HOST_OK = {
    'query_status': 'ok',
    'urlhaus_reference': 'https://urlhaus.abuse.ch/host/bad.test/',
    'host': 'bad.test',
    'firstseen': '2026-02-01 08:00:00 UTC',
    'url_count': '3',
    'blacklists': {'spamhaus_dbl': 'abused_legit_malware', 'surbl': 'not listed'},
    'urls': [
        {'url': 'http://bad.test/a', 'url_status': 'online', 'threat': 'malware_download',
         'date_added': '2026-02-01 08:00:00 UTC', 'tags': ['exe']},
        {'url': 'http://bad.test/b', 'url_status': 'offline', 'threat': 'malware_download',
         'date_added': '2026-02-02 08:00:00 UTC', 'tags': None},
        {'url': 'http://bad.test/c', 'url_status': 'online', 'threat': 'phishing',
         'date_added': '2026-02-03 08:00:00 UTC'},
    ],
}

URLHAUS_URL_OK = {
    'query_status': 'ok',
    'urlhaus_reference': 'https://urlhaus.abuse.ch/url/123456/',
    'url': 'http://bad.test/a',
    'url_status': 'online',
    'threat': 'malware_download',
    'date_added': '2026-02-01 08:00:00 UTC',
    'larted': 'false',
    'tags': ['exe', 'emotet'],
}

URLHAUS_PAYLOAD_OK = {
    'query_status': 'ok',
    'md5_hash': '0' * 32,
    'sha256_hash': 'a' * 64,
    'file_type': 'exe',
    'file_size': '123456',
    'signature': 'Emotet',
    'firstseen': '2026-02-01',
    'url_count': '7',
}

MALWAREBAZAAR_OK = {
    'query_status': 'ok',
    'data': [{
        'sha256_hash': 'b' * 64, 'sha1_hash': 'c' * 40, 'md5_hash': 'd' * 32,
        'file_name': 'invoice.exe', 'file_type': 'exe', 'file_size': 98765,
        'signature': 'AgentTesla', 'first_seen': '2026-04-01 07:00:00',
        'last_seen': '2026-04-02 07:00:00', 'reporter': 'abuse_ch',
        'tags': ['exe', 'AgentTesla'], 'delivery_method': 'email_attachment',
        'intelligence': {'downloads': '12'},
    }],
}

HUNTING_OK = {'query_status': 'ok', 'fplist': [{'ioc': 'good.test'}, {'ioc': '198.51.100.1'}]}

# (label, callable, ok_payload) - one representative "found" case per endpoint.
OK_CASES = [
    ('threatfox_lookup', lambda: abusech.threatfox_lookup('203.0.113.10:443'), THREATFOX_OK),
    ('threatfox_hash', lambda: abusech.threatfox_hash('e' * 64), THREATFOX_OK),
    ('urlhaus_host', lambda: abusech.urlhaus_host('bad.test'), URLHAUS_HOST_OK),
    ('urlhaus_url', lambda: abusech.urlhaus_url('http://bad.test/a'), URLHAUS_URL_OK),
    ('urlhaus_payload', lambda: abusech.urlhaus_payload(sha256='a' * 64), URLHAUS_PAYLOAD_OK),
    ('malwarebazaar_hash', lambda: abusech.malwarebazaar_hash('b' * 64), MALWAREBAZAAR_OK),
    ('hunting_fplist', abusech.hunting_fplist, HUNTING_OK),
]

# query_status values that mean "we asked and there is nothing".
NO_RECORD_STATUSES = ['no_results', 'no_result', 'hash_not_found']

# query_status values that are failures, not empty results.
FAILURE_STATUSES = ['no_api_key', 'illegal_hash', 'invalid_url', 'invalid_host',
                    'invalid_md5', 'invalid_sha256', 'http_post_expected']

failures = []
checks = 0


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


def check_envelope(label, envelope, source, state):
    check(isinstance(envelope, dict), f'{label}: envelope is not a dict')
    check(set(envelope) == ENVELOPE_KEYS,
          f'{label}: envelope keys {sorted(envelope)} != {sorted(ENVELOPE_KEYS)}')
    check(envelope['state'] in STATES, f'{label}: state {envelope["state"]!r} not in vocabulary')
    check(envelope['state'] == state,
          f'{label}: expected state {state}, got {envelope["state"]}')
    check(envelope['source'] == source,
          f'{label}: expected source {source}, got {envelope["source"]}')
    check(isinstance(envelope['summary'], dict), f'{label}: summary is not a dict')
    check(isinstance(envelope['raw'], dict), f'{label}: raw is not a dict')
    check(envelope['reference'] is None or isinstance(envelope['reference'], str),
          f'{label}: reference is neither str nor None')


SOURCE_OF = {
    'threatfox_lookup': 'threatfox', 'threatfox_hash': 'threatfox',
    'urlhaus_host': 'urlhaus', 'urlhaus_url': 'urlhaus', 'urlhaus_payload': 'urlhaus',
    'malwarebazaar_hash': 'malwarebazaar', 'hunting_fplist': 'hunting',
}


def test_found_envelopes():
    for label, call, payload in OK_CASES:
        envelope, transport = run(FakeResponse(payload), call)
        check_envelope(label, envelope, SOURCE_OF[label], 'found')
        check(len(transport.calls) == 1, f'{label}: expected 1 request, got {len(transport.calls)}')
        check(transport.calls[0]['headers'] == {'Auth-Key': 'test-key'},
              f'{label}: Auth-Key header missing, got {transport.calls[0]["headers"]}')
        check(envelope['raw'] == payload, f'{label}: raw is not the provider body')
        check(envelope['reference'], f'{label}: found envelope has no reference link')


def test_request_shapes():
    """The wire format differs per API: form vs JSON, and URLhaus uses sub-paths."""
    _, transport = run(FakeResponse(MALWAREBAZAAR_OK),
                       lambda: abusech.malwarebazaar_hash('B' * 64))
    call = transport.calls[0]
    check(call['url'] == abusech.MALWAREBAZAAR_API, 'malwarebazaar: wrong endpoint')
    check(call['data'] == {'query': 'get_info', 'hash': 'b' * 64},
          f'malwarebazaar: wrong form body {call["data"]}')
    check(call['json'] is None, 'malwarebazaar: must post a form, not JSON')

    _, transport = run(FakeResponse(THREATFOX_OK),
                       lambda: abusech.threatfox_lookup('bad.test', exact_match=False))
    call = transport.calls[0]
    check(call['url'] == abusech.THREATFOX_API, 'threatfox: wrong endpoint')
    check(call['json'] == {'query': 'search_ioc', 'search_term': 'bad.test',
                           'exact_match': False},
          f'threatfox: wrong JSON body {call["json"]}')
    check(call['data'] is None, 'threatfox: must post JSON, not a form')

    _, transport = run(FakeResponse(THREATFOX_OK), lambda: abusech.threatfox_hash('E' * 64))
    check(transport.calls[0]['json'] == {'query': 'search_hash', 'hash': 'e' * 64},
          f'threatfox_hash: wrong JSON body {transport.calls[0]["json"]}')

    _, transport = run(FakeResponse(URLHAUS_HOST_OK), lambda: abusech.urlhaus_host('bad.test'))
    call = transport.calls[0]
    check(call['url'] == abusech.URLHAUS_API + 'host/', f'urlhaus host: wrong path {call["url"]}')
    check(call['data'] == {'host': 'bad.test'}, f'urlhaus host: wrong form {call["data"]}')

    _, transport = run(FakeResponse(URLHAUS_URL_OK),
                       lambda: abusech.urlhaus_url('http://bad.test/a'))
    call = transport.calls[0]
    check(call['url'] == abusech.URLHAUS_API + 'url/', f'urlhaus url: wrong path {call["url"]}')
    check(call['data'] == {'url': 'http://bad.test/a'}, f'urlhaus url: wrong form {call["data"]}')

    _, transport = run(FakeResponse(URLHAUS_PAYLOAD_OK),
                       lambda: abusech.urlhaus_payload(sha256='A' * 64))
    call = transport.calls[0]
    check(call['url'] == abusech.URLHAUS_API + 'payload/',
          f'urlhaus payload: wrong path {call["url"]}')
    check(call['data'] == {'sha256_hash': 'a' * 64},
          f'urlhaus payload: wrong form {call["data"]}')

    _, transport = run(FakeResponse(URLHAUS_PAYLOAD_OK),
                       lambda: abusech.urlhaus_payload(md5='0' * 32))
    check(transport.calls[0]['data'] == {'md5_hash': '0' * 32},
          'urlhaus payload: md5 must be sent as md5_hash')

    _, transport = run(FakeResponse(URLHAUS_PAYLOAD_OK),
                       lambda: abusech.urlhaus_payload(sha256='a' * 64, md5='0' * 32))
    check(transport.calls[0]['data'] == {'sha256_hash': 'a' * 64},
          'urlhaus payload: sha256 must win when both are supplied')

    _, transport = run(FakeResponse(HUNTING_OK), abusech.hunting_fplist)
    call = transport.calls[0]
    check(call['url'] == abusech.HUNTING_API, 'hunting: wrong endpoint')
    check(call['json'] == {'query': 'get_fplist', 'format': 'json'},
          f'hunting: wrong JSON body {call["json"]}')


def test_summaries():
    envelope, _ = run(FakeResponse(THREATFOX_OK),
                      lambda: abusech.threatfox_lookup('203.0.113.10:443'))
    summary = envelope['summary']
    expected = {
        'count': 2,
        'malware': ['Cobalt Strike', 'Emotet'],
        'threat_types': ['botnet_cc', 'payload_delivery'],
        'confidence_max': 100,
        'first_seen': '2025-12-01 09:00:00 UTC',
        'last_seen': '2026-05-06 12:00:00 UTC',
        'tags': ['c2', 'cobaltstrike', 'emotet'],
    }
    check(summary == expected, f'threatfox summary {summary} != {expected}')

    envelope, _ = run(FakeResponse(URLHAUS_HOST_OK), lambda: abusech.urlhaus_host('bad.test'))
    summary = envelope['summary']
    expected = {
        'url_count': 3,
        'firstseen': '2026-02-01 08:00:00 UTC',
        'online_url_count': 2,
        'blacklists': {'spamhaus_dbl': 'abused_legit_malware', 'surbl': 'not listed'},
        'threats': ['malware_download', 'phishing'],
    }
    check(summary == expected, f'urlhaus host summary {summary} != {expected}')
    check(envelope['reference'] == URLHAUS_HOST_OK['urlhaus_reference'],
          'urlhaus host: provider reference should win')

    envelope, _ = run(FakeResponse(URLHAUS_URL_OK),
                      lambda: abusech.urlhaus_url('http://bad.test/a'))
    expected = {'url_status': 'online', 'threat': 'malware_download',
                'date_added': '2026-02-01 08:00:00 UTC', 'tags': ['exe', 'emotet'],
                'larted': False}
    check(envelope['summary'] == expected, f'urlhaus url summary {envelope["summary"]} != {expected}')

    envelope, _ = run(FakeResponse(URLHAUS_PAYLOAD_OK),
                      lambda: abusech.urlhaus_payload(sha256='a' * 64))
    expected = {'file_type': 'exe', 'signature': 'Emotet', 'firstseen': '2026-02-01',
                'url_count': 7}
    check(envelope['summary'] == expected,
          f'urlhaus payload summary {envelope["summary"]} != {expected}')

    envelope, _ = run(FakeResponse(MALWAREBAZAAR_OK),
                      lambda: abusech.malwarebazaar_hash('b' * 64))
    expected = {'file_name': 'invoice.exe', 'file_type': 'exe', 'signature': 'AgentTesla',
                'tags': ['exe', 'AgentTesla'], 'first_seen': '2026-04-01 07:00:00',
                'delivery_method': 'email_attachment'}
    check(envelope['summary'] == expected,
          f'malwarebazaar summary {envelope["summary"]} != {expected}')
    check(envelope['reference'] == f"https://bazaar.abuse.ch/sample/{'b' * 64}/",
          f'malwarebazaar reference {envelope["reference"]}')

    envelope, _ = run(FakeResponse(HUNTING_OK), abusech.hunting_fplist)
    check(envelope['summary'] == {'count': 2}, f'hunting summary {envelope["summary"]}')


def test_sparse_fields():
    """Missing / None / wrongly-typed provider fields must degrade, not raise."""
    sparse_tf = {'query_status': 'ok',
                 'data': [{'ioc': 'bad.test'}, {'malware_printable': None, 'tags': None,
                                                'confidence_level': 'high'}]}
    envelope, _ = run(FakeResponse(sparse_tf), lambda: abusech.threatfox_lookup('bad.test'))
    check_envelope('threatfox sparse', envelope, 'threatfox', 'found')
    check(envelope['summary'] == {'count': 2, 'malware': [], 'threat_types': [],
                                  'confidence_max': None, 'first_seen': None,
                                  'last_seen': None, 'tags': []},
          f'threatfox sparse summary {envelope["summary"]}')

    dict_data = {'query_status': 'ok', 'data': {'ioc': 'bad.test',
                                                'malware_printable': 'Emotet',
                                                'confidence_level': '50',
                                                'first_seen_utc': '2026-01-01 00:00:00 UTC'}}
    envelope, _ = run(FakeResponse(dict_data), lambda: abusech.threatfox_lookup('bad.test'))
    check_envelope('threatfox dict data', envelope, 'threatfox', 'found')
    check(envelope['summary']['count'] == 1, 'threatfox: a dict `data` should count as one IOC')
    check(envelope['summary']['confidence_max'] == 50,
          'threatfox: a string confidence_level should still parse')
    check(envelope['summary']['first_seen'] == '2026-01-01 00:00:00 UTC',
          'threatfox: first_seen_utc should be accepted as first_seen')

    envelope, _ = run(FakeResponse({'query_status': 'ok', 'data': []}),
                      lambda: abusech.malwarebazaar_hash('b' * 64))
    check_envelope('malwarebazaar empty data', envelope, 'malwarebazaar', 'no_record')

    envelope, _ = run(FakeResponse({'query_status': 'ok', 'data': 'nonsense'}),
                      lambda: abusech.threatfox_lookup('bad.test'))
    check_envelope('threatfox junk data', envelope, 'threatfox', 'no_record')

    thin_host = {'query_status': 'ok', 'urls': ['not-a-dict']}
    envelope, _ = run(FakeResponse(thin_host), lambda: abusech.urlhaus_host('bad.test'))
    check_envelope('urlhaus thin host', envelope, 'urlhaus', 'found')
    check(envelope['summary']['blacklists'] == {'spamhaus_dbl': None, 'surbl': None},
          f'urlhaus thin host blacklists {envelope["summary"]["blacklists"]}')
    check(envelope['summary']['url_count'] == 0,
          f'urlhaus thin host url_count {envelope["summary"]["url_count"]}')
    check(envelope['reference'], 'urlhaus thin host: should fall back to a search link')

    odd_host = dict(URLHAUS_HOST_OK, blacklists='not listed')
    envelope, _ = run(FakeResponse(odd_host), lambda: abusech.urlhaus_host('bad.test'))
    check(envelope['summary']['blacklists'] == {'spamhaus_dbl': None, 'surbl': None},
          'urlhaus: a non-dict blacklists must not raise')

    envelope, _ = run(FakeResponse({'query_status': 'ok'}),
                      lambda: abusech.urlhaus_url('http://bad.test/a'))
    check(envelope['summary'] == {'url_status': None, 'threat': None, 'date_added': None,
                                  'tags': [], 'larted': None},
          f'urlhaus url sparse summary {envelope["summary"]}')

    envelope, _ = run(FakeResponse({'query_status': 'ok'}),
                      lambda: abusech.urlhaus_payload(sha256='a' * 64))
    check(envelope['summary'] == {'file_type': None, 'signature': None, 'firstseen': None,
                                  'url_count': 0},
          f'urlhaus payload sparse summary {envelope["summary"]}')

    # A bare-list Hunting body is accepted; an unexpected scalar is not.
    envelope, _ = run(FakeResponse([{'ioc': 'good.test'}]), abusech.hunting_fplist)
    check_envelope('hunting list body', envelope, 'hunting', 'found')
    check(envelope['summary'] == {'count': 1}, f'hunting list summary {envelope["summary"]}')
    envelope, _ = run(FakeResponse({'query_status': 'ok'}), abusech.hunting_fplist)
    check_envelope('hunting empty fplist', envelope, 'hunting', 'no_record')


def test_no_record():
    for status in NO_RECORD_STATUSES:
        for label, call, _ in OK_CASES:
            envelope, transport = run(FakeResponse({'query_status': status}), call)
            check_envelope(f'{label}/{status}', envelope, SOURCE_OF[label], 'no_record')
            check(len(transport.calls) == 1, f'{label}/{status}: expected exactly 1 request')


def test_failure_statuses():
    for status in FAILURE_STATUSES:
        for label, call, _ in OK_CASES:
            envelope, _ = run(FakeResponse({'query_status': status}), call)
            check_envelope(f'{label}/{status}', envelope, SOURCE_OF[label], 'unavailable')
            check(envelope['raw'].get('query_status') == status,
                  f'{label}/{status}: raw should carry the provider status')
            check(envelope['summary'] == {}, f'{label}/{status}: summary should be empty')

    # A body with no query_status at all is also a failure, not an empty result.
    for label, call, _ in OK_CASES:
        envelope, _ = run(FakeResponse({'some': 'thing'}), call)
        check_envelope(f'{label}/no-status', envelope, SOURCE_OF[label], 'unavailable')


def test_http_errors():
    for status_code in (401, 403, 429, 500, 503):
        for label, call, payload in OK_CASES:
            envelope, transport = run(FakeResponse(payload, status_code=status_code), call)
            check_envelope(f'{label}/http{status_code}', envelope, SOURCE_OF[label],
                           'unavailable')
            check(envelope['raw'] == {'error': f'http_{status_code}'},
                  f'{label}/http{status_code}: raw {envelope["raw"]}')
            check(len(transport.calls) == 1,
                  f'{label}/http{status_code}: expected exactly 1 request')


def test_transport_errors():
    cases = [
        (requests.Timeout('timed out'), 'timeout'),
        (requests.ConnectionError('refused'), 'request_error'),
        (requests.RequestException('boom'), 'request_error'),
        (RuntimeError('unexpected'), 'transport_error'),
    ]
    for exc, expected in cases:
        for label, call, _ in OK_CASES:
            envelope, _ = run(exc, call)
            check_envelope(f'{label}/{expected}', envelope, SOURCE_OF[label], 'unavailable')
            check(envelope['raw'] == {'error': expected},
                  f'{label}/{expected}: raw {envelope["raw"]}')


def test_malformed_body():
    for label, call, _ in OK_CASES:
        envelope, _ = run(FakeResponse('<html>502 Bad Gateway</html>'), call)
        check_envelope(f'{label}/non-json', envelope, SOURCE_OF[label], 'unavailable')
        check(envelope['raw'] == {'error': 'unparseable_body'},
              f'{label}/non-json: raw {envelope["raw"]}')

    for label, call, _ in OK_CASES:
        if label == 'hunting_fplist':
            continue
        envelope, _ = run(FakeResponse(['unexpected', 'list']), call)
        check_envelope(f'{label}/list-body', envelope, SOURCE_OF[label], 'unavailable')

    envelope, _ = run(FakeResponse(42), abusech.hunting_fplist)
    check_envelope('hunting/scalar-body', envelope, 'hunting', 'unavailable')


def test_skipped_without_key():
    for label, call, payload in OK_CASES:
        envelope, transport = run(FakeResponse(payload), call, key=None)
        check_envelope(f'{label}/no-key', envelope, SOURCE_OF[label], 'skipped')
        check(transport.calls == [],
              f'{label}/no-key: issued {len(transport.calls)} request(s) without a key')
        check(envelope['summary'] == {}, f'{label}/no-key: summary should be empty')
        check(envelope['raw'] == {}, f'{label}/no-key: raw should be empty')

    envelope, transport = run(FakeResponse(THREATFOX_OK),
                              lambda: abusech.threatfox_lookup('bad.test'), key='   ')
    check_envelope('threatfox/blank-key', envelope, 'threatfox', 'skipped')
    check(transport.calls == [], 'blank key: no request may be issued')


def test_empty_input():
    cases = [
        ('threatfox_lookup', lambda: abusech.threatfox_lookup('   '), 'threatfox'),
        ('threatfox_hash', lambda: abusech.threatfox_hash(None), 'threatfox'),
        ('urlhaus_host', lambda: abusech.urlhaus_host(''), 'urlhaus'),
        ('urlhaus_url', lambda: abusech.urlhaus_url(None), 'urlhaus'),
        ('urlhaus_payload', abusech.urlhaus_payload, 'urlhaus'),
    ]
    for label, call, source in cases:
        envelope, transport = run(FakeResponse({'query_status': 'ok'}), call)
        check_envelope(f'{label}/empty-input', envelope, source, 'unavailable')
        check(transport.calls == [], f'{label}/empty-input: should not issue a request')


def test_auth_key():
    previous = os.environ.get(abusech.AUTH_ENV)
    try:
        os.environ.pop(abusech.AUTH_ENV, None)
        check(abusech.auth_key() is None, 'auth_key() should be None when unset')
        os.environ[abusech.AUTH_ENV] = '  '
        check(abusech.auth_key() is None, 'auth_key() should be None when blank')
        os.environ[abusech.AUTH_ENV] = ' abc '
        check(abusech.auth_key() == 'abc', 'auth_key() should strip whitespace')
    finally:
        if previous is None:
            os.environ.pop(abusech.AUTH_ENV, None)
        else:
            os.environ[abusech.AUTH_ENV] = previous


def test_hash_service_bridge():
    """hash_service's legacy shapes must survive the move onto this client."""
    from app.services import hash_service

    def bridged(result, key='test-key'):
        _reset()
        hash_service.get_malwarebazaar_report.cache_clear()
        hash_service.get_threatfox_iocs.cache_clear()
        transport = FakeTransport(result)
        real_post = abusech._post
        previous = os.environ.get(abusech.AUTH_ENV)
        abusech._post = transport
        if key is None:
            os.environ.pop(abusech.AUTH_ENV, None)
        else:
            os.environ[abusech.AUTH_ENV] = key
        try:
            return (hash_service.get_malwarebazaar_report('b' * 64),
                    hash_service.get_threatfox_iocs('e' * 64), transport)
        finally:
            abusech._post = real_post
            if previous is None:
                os.environ.pop(abusech.AUTH_ENV, None)
            else:
                os.environ[abusech.AUTH_ENV] = previous
            _reset()
            hash_service.get_malwarebazaar_report.cache_clear()
            hash_service.get_threatfox_iocs.cache_clear()

    mb, _tf, transport = bridged(FakeResponse(MALWAREBAZAAR_OK))
    check(transport.calls[0]['headers'] == {'Auth-Key': 'test-key'},
          'hash_service: MalwareBazaar request must carry Auth-Key')
    check(mb['status'] == 'found', f'hash_service malwarebazaar status {mb["status"]}')
    check(mb['sha256'] == 'b' * 64 and mb['signature'] == 'AgentTesla'
          and mb['file_name'] == 'invoice.exe' and mb['tags'] == ['exe', 'AgentTesla']
          and mb['delivery_method'] == 'email_attachment'
          and mb['intelligence'] == {'downloads': '12'}
          and mb['mb_link'] == f"https://bazaar.abuse.ch/sample/{'b' * 64}/",
          f'hash_service malwarebazaar legacy shape drifted: {mb}')

    _mb, tf, _ = bridged(FakeResponse({'query_status': 'ok', 'data': [
        {'id': '9', 'ioc_type': 'sha256_hash', 'threat_type': 'payload',
         'malware': 'win.emotet', 'confidence_level': 80,
         'first_seen_utc': '2026-01-01 00:00:00 UTC', 'tags': ['emotet']}]}))
    check(tf['status'] == 'found' and tf['ioc_count'] == 1, f'hash_service threatfox {tf}')
    check(tf['iocs'][0] == {'id': '9', 'ioc_type': 'sha256_hash', 'threat_type': 'payload',
                            'malware': 'win.emotet', 'confidence': 80,
                            'first_seen': '2026-01-01 00:00:00 UTC', 'tags': ['emotet']},
          f'hash_service threatfox ioc shape drifted: {tf["iocs"][0]}')

    mb, tf, _ = bridged(FakeResponse({'query_status': 'hash_not_found'}))
    check(mb == {'status': 'not_found'}, f'hash_service malwarebazaar no_record {mb}')
    check(tf == {'status': 'not_found'}, f'hash_service threatfox no_record {tf}')

    mb, tf, _ = bridged(FakeResponse({'query_status': 'no_api_key'}, status_code=401))
    check(mb == {'status': 'error', 'message': 'http_401'},
          f'hash_service malwarebazaar 401 {mb}')
    check(tf == {'status': 'error', 'message': 'http_401'}, f'hash_service threatfox 401 {tf}')

    mb, _tf, _ = bridged(requests.Timeout('slow'))
    check(mb == {'status': 'timeout'}, f'hash_service malwarebazaar timeout {mb}')

    mb, tf, transport = bridged(FakeResponse(MALWAREBAZAAR_OK), key=None)
    check(mb is None and tf is None,
          'hash_service: an unconfigured key must return None, not an error dict')
    check(transport.calls == [], 'hash_service: no request may be issued without a key')

    # The unknown-hash page must attribute the missing key, not report a failed query.
    previous = os.environ.get(abusech.AUTH_ENV)
    try:
        os.environ.pop(abusech.AUTH_ENV, None)
        report = hash_service.unknown_hash_report('b' * 64, {'sources': {}}, None)
        states = {s['name']: s for s in report['sources']}
        for name in ('MalwareBazaar', 'ThreatFox'):
            check(states[name]['state'] == 'skipped',
                  f'unknown_hash_report: {name} should be skipped without a key')
            check(states[name]['key_env'] == 'ABUSECH_AUTH_KEY',
                  f'unknown_hash_report: {name} should name ABUSECH_AUTH_KEY')
        os.environ[abusech.AUTH_ENV] = 'test-key'
        report = hash_service.unknown_hash_report(
            'b' * 64, {'sources': {'malwarebazaar': {'status': 'not_found'}}}, None)
        states = {s['name']: s for s in report['sources']}
        check(states['MalwareBazaar']['state'] == 'no_record',
              'unknown_hash_report: a queried-and-empty MalwareBazaar is no_record')
    finally:
        if previous is None:
            os.environ.pop(abusech.AUTH_ENV, None)
        else:
            os.environ[abusech.AUTH_ENV] = previous


def test_cache_registration():
    """clear_caches() builds its list eagerly: one wrong name silently disables it all."""
    from app.utils.cache import clear_caches

    _reset()
    transport = FakeTransport(FakeResponse(THREATFOX_OK))
    real_post = abusech._post
    previous = os.environ.get(abusech.AUTH_ENV)
    abusech._post = transport
    os.environ[abusech.AUTH_ENV] = 'test-key'
    try:
        abusech.threatfox_lookup('bad.test')
        abusech.threatfox_lookup('bad.test')
        check(len(transport.calls) == 1, 'threatfox_lookup is not actually cached')
        clear_caches()
        abusech.threatfox_lookup('bad.test')
        check(len(transport.calls) == 2,
              'clear_caches() did not clear threatfox_lookup - check its registration')
    finally:
        abusech._post = real_post
        if previous is None:
            os.environ.pop(abusech.AUTH_ENV, None)
        else:
            os.environ[abusech.AUTH_ENV] = previous
        _reset()


SAMPLE = b'MZ\x90\x00this-is-not-really-malware'
SAMPLE_SHA256 = hashlib.sha256(SAMPLE).hexdigest()

IOCS = ['203.0.113.10:443', 'bad.test']


POSITIONAL_IOC = ('iocs', 'threat_type', 'ioc_type', 'malware')
POSITIONAL_UPLOAD = ('data', 'filename')


def _factory(func, defaults, positional, overrides):
    params = dict(defaults, **overrides)
    args = [params[name] for name in positional]
    options = {k: v for k, v in params.items() if k not in positional}
    return lambda: func(*args, **options)


def submit_ioc(**overrides):
    return _factory(abusech.submit_ioc,
                    {'iocs': IOCS, 'threat_type': 'botnet_cc', 'ioc_type': 'ip:port',
                     'malware': 'win.zloader'},
                    POSITIONAL_IOC, overrides)


def upload_sample(**overrides):
    return _factory(abusech.upload_sample,
                    {'data': SAMPLE, 'filename': 'sample.bin'},
                    POSITIONAL_UPLOAD, overrides)


def check_submit_envelope(label, envelope, source, state):
    check(isinstance(envelope, dict), f'{label}: envelope is not a dict')
    check(set(envelope) == ENVELOPE_KEYS,
          f'{label}: envelope keys {sorted(envelope)} != {sorted(ENVELOPE_KEYS)}')
    check(envelope['state'] in SUBMIT_STATES,
          f'{label}: state {envelope["state"]!r} not in the submission vocabulary')
    check(envelope['state'] == state,
          f'{label}: expected state {state}, got {envelope["state"]}')
    check(envelope['source'] == source,
          f'{label}: expected source {source}, got {envelope["source"]}')
    check(isinstance(envelope['summary'], dict), f'{label}: summary is not a dict')
    check(isinstance(envelope['raw'], dict), f'{label}: raw is not a dict')
    check(envelope['reference'] is None or isinstance(envelope['reference'], str),
          f'{label}: reference is neither str nor None')


TF_SUBMIT_OK = {'query_status': 'ok',
                'data': {'ok': IOCS, 'ignored': [], 'duplicated': [], 'reward': 2}}
TF_SUBMIT_DUP = {'query_status': 'ok',
                 'data': {'ok': [], 'ignored': [], 'duplicated': IOCS, 'reward': 0}}
TF_SUBMIT_IGNORED = {'query_status': 'ok',
                     'data': {'ok': [], 'ignored': IOCS, 'duplicated': [], 'reward': 0}}
MB_UPLOAD_OK = {'query_status': 'inserted'}


def test_submit_ioc_success():
    envelope, transport = run(FakeResponse(TF_SUBMIT_OK), submit_ioc())
    check_submit_envelope('submit_ioc/ok', envelope, 'threatfox', 'submitted')
    check(len(transport.calls) == 1, f'submit_ioc: expected 1 request, got {len(transport.calls)}')
    call = transport.calls[0]
    check(call['url'] == abusech.THREATFOX_API, f'submit_ioc: wrong endpoint {call["url"]}')
    check(call['headers'] == {'Auth-Key': 'test-key'}, 'submit_ioc: Auth-Key header missing')
    check(call['data'] is None and call['files'] is None,
          'submit_ioc: must post JSON, not a form or multipart')
    check(call['json'] == {
        'query': 'submit_ioc', 'threat_type': 'botnet_cc', 'ioc_type': 'ip:port',
        'malware': 'win.zloader', 'iocs': IOCS, 'confidence_level': 50,
        'is_compromised': 'False', 'anonymous': 1,
    }, f'submit_ioc: wrong JSON body {call["json"]}')
    check(envelope['raw'] == TF_SUBMIT_OK, 'submit_ioc: raw is not the provider body')
    check(envelope['reference'] and IOCS[0].replace(':', '%3A') in envelope['reference'],
          f'submit_ioc: reference {envelope["reference"]}')
    check(envelope['summary'] == {
        'ioc_count': 2, 'ioc_type': 'ip:port', 'threat_type': 'botnet_cc',
        'malware': 'win.zloader', 'confidence_level': 50, 'anonymous': True, 'tags': [],
        'accepted': 2, 'duplicated': 0, 'ignored': 0, 'reward': 2,
    }, f'submit_ioc summary {envelope["summary"]}')

    # Optional fields are only sent when supplied, and each lands under its documented key.
    _, transport = run(FakeResponse(TF_SUBMIT_OK), submit_ioc(
        confidence_level=90, is_compromised=True, reference='https://example.test/r',
        tags=['zloader', 'c2'], comment='seen in a phish', anonymous=False))
    body = transport.calls[0]['json']
    check(body['confidence_level'] == 90, f'submit_ioc: confidence {body["confidence_level"]}')
    check(body['is_compromised'] == 'True',
          f'submit_ioc: is_compromised must be the string "True", got {body["is_compromised"]!r}')
    check(body['reference'] == 'https://example.test/r', 'submit_ioc: reference not sent')
    check(body['tags'] == ['zloader', 'c2'], f'submit_ioc: tags {body.get("tags")}')
    check(body['comment'] == 'seen in a phish', 'submit_ioc: comment not sent')

    _, transport = run(FakeResponse(TF_SUBMIT_OK), submit_ioc(iocs=[' bad.test ']))
    check(transport.calls[0]['json']['iocs'] == ['bad.test'], 'submit_ioc: iocs not trimmed')


def test_submit_ioc_outcomes():
    envelope, _ = run(FakeResponse(TF_SUBMIT_DUP), submit_ioc())
    check_submit_envelope('submit_ioc/duplicated', envelope, 'threatfox', 'duplicate')
    check(envelope['summary']['duplicated'] == 2 and envelope['summary']['accepted'] == 0,
          f'submit_ioc duplicate counts {envelope["summary"]}')

    envelope, _ = run(FakeResponse(TF_SUBMIT_IGNORED), submit_ioc())
    check_submit_envelope('submit_ioc/ignored', envelope, 'threatfox', 'rejected')

    # A partial batch still landed something, so it is a submission.
    partial = {'query_status': 'ok',
               'data': {'ok': [IOCS[0]], 'ignored': [], 'duplicated': [IOCS[1]], 'reward': 1}}
    envelope, _ = run(FakeResponse(partial), submit_ioc())
    check_submit_envelope('submit_ioc/partial', envelope, 'threatfox', 'submitted')
    check(envelope['summary']['accepted'] == 1 and envelope['summary']['duplicated'] == 1,
          f'submit_ioc partial counts {envelope["summary"]}')

    # No per-IOC breakdown at all: trust query_status=ok and credit the whole batch.
    envelope, _ = run(FakeResponse({'query_status': 'ok'}), submit_ioc())
    check_submit_envelope('submit_ioc/no-breakdown', envelope, 'threatfox', 'submitted')
    check(envelope['summary']['accepted'] == 2,
          f'submit_ioc no-breakdown accepted {envelope["summary"]["accepted"]}')

    envelope, _ = run(FakeResponse({'query_status': 'ok', 'data': 'nonsense'}), submit_ioc())
    check_submit_envelope('submit_ioc/junk-data', envelope, 'threatfox', 'submitted')


def test_upload_sample_success():
    envelope, transport = run(FakeResponse(MB_UPLOAD_OK), upload_sample(
        tags=['exe', 'zloader'], delivery_method='email_attachment',
        references={'urlhaus': ['https://urlhaus.abuse.ch/url/1/'],
                    'twitter': 'https://x.test/status/1'},
        context={'dropped_by_malware': 'Emotet', 'comment': 'from a phish'}))
    check_submit_envelope('upload_sample/ok', envelope, 'malwarebazaar', 'submitted')
    check(len(transport.calls) == 1,
          f'upload_sample: expected 1 request, got {len(transport.calls)}')
    call = transport.calls[0]
    check(call['url'] == abusech.MALWAREBAZAAR_API, f'upload_sample: wrong endpoint {call["url"]}')
    check(call['headers'] == {'Auth-Key': 'test-key'}, 'upload_sample: Auth-Key header missing')
    check(call['json'] is None and call['data'] is None,
          'upload_sample: must post multipart, not JSON or a plain form')

    files = call['files']
    check(isinstance(files, dict) and set(files) == {'file', 'json_data'},
          f'upload_sample: multipart parts {sorted(files) if isinstance(files, dict) else files}')
    name, blob, ctype = files['file']
    check(name == 'sample.bin', f'upload_sample: multipart filename {name}')
    check(blob == SAMPLE, 'upload_sample: multipart body does not carry the sample bytes')
    check(ctype == 'application/octet-stream', f'upload_sample: file part content type {ctype}')
    check(files['json_data'][0] is None and files['json_data'][2] == 'application/json',
          f'upload_sample: json_data part shape {files["json_data"][0]!r}/{files["json_data"][2]!r}')

    meta = json.loads(files['json_data'][1])
    check(meta['anonymous'] == 1, f'upload_sample: anonymous {meta["anonymous"]}')
    check(meta['tags'] == ['exe', 'zloader'], f'upload_sample: tags {meta.get("tags")}')
    check(meta['delivery_method'] == 'email_attachment',
          f'upload_sample: delivery_method {meta.get("delivery_method")}')
    check(meta['references'] == {'urlhaus': ['https://urlhaus.abuse.ch/url/1/'],
                                 'twitter': ['https://x.test/status/1']},
          f'upload_sample: references {meta.get("references")}')
    check(meta['context'] == {'dropped_by_malware': 'Emotet', 'comment': 'from a phish'},
          f'upload_sample: context {meta.get("context")}')

    check(call['timeout'] == abusech.UPLOAD_TIMEOUT,
          f'upload_sample: timeout {call["timeout"]} should be UPLOAD_TIMEOUT')
    check(abusech.UPLOAD_TIMEOUT > abusech.TIMEOUT_MEDIUM,
          'upload_sample: UPLOAD_TIMEOUT must exceed TIMEOUT_MEDIUM')

    check(envelope['summary'] == {
        'filename': 'sample.bin', 'size': len(SAMPLE), 'sha256': SAMPLE_SHA256,
        'anonymous': True, 'delivery_method': 'email_attachment',
        'tags': ['exe', 'zloader'],
    }, f'upload_sample summary {envelope["summary"]}')
    check(envelope['reference'] == f'https://bazaar.abuse.ch/sample/{SAMPLE_SHA256}/',
          f'upload_sample reference {envelope["reference"]}')
    check(envelope['raw'] == MB_UPLOAD_OK, 'upload_sample: raw is not the provider body')

    # Optional metadata is omitted, not sent empty.
    _, transport = run(FakeResponse(MB_UPLOAD_OK), upload_sample())
    meta = json.loads(transport.calls[0]['files']['json_data'][1])
    check(meta == {'anonymous': 1}, f'upload_sample: bare metadata {meta}')

    # A caller-supplied path never reaches the multipart filename header.
    _, transport = run(FakeResponse(MB_UPLOAD_OK),
                       upload_sample(filename='../../etc/cron.d/evil'))
    check(transport.calls[0]['files']['file'][0] == 'evil',
          f'upload_sample: filename not reduced to a basename '
          f'({transport.calls[0]["files"]["file"][0]})')

    envelope, _ = run(FakeResponse(MB_UPLOAD_OK), upload_sample(data=bytearray(SAMPLE)))
    check_submit_envelope('upload_sample/bytearray', envelope, 'malwarebazaar', 'submitted')
    check(envelope['summary']['sha256'] == SAMPLE_SHA256,
          'upload_sample: a bytearray should hash the same as bytes')


def test_upload_sample_duplicate():
    envelope, transport = run(FakeResponse({'query_status': 'file_already_known'}),
                              upload_sample())
    check_submit_envelope('upload_sample/duplicate', envelope, 'malwarebazaar', 'duplicate')
    check(len(transport.calls) == 1, 'upload_sample duplicate: expected exactly 1 request')
    check(envelope['summary']['sha256'] == SAMPLE_SHA256,
          'upload_sample duplicate: summary must still identify the sample')
    check(envelope['raw'] == {'query_status': 'file_already_known'},
          f'upload_sample duplicate raw {envelope["raw"]}')
    check(envelope['reference'] == f'https://bazaar.abuse.ch/sample/{SAMPLE_SHA256}/',
          'upload_sample duplicate: reference should point at the known sample')


def test_submission_provider_statuses():
    # (status, expected state). `no_api_key` is a configuration failure, not a refusal
    # of the content, so it stays `unavailable` exactly as it does for lookups.
    cases = [
        ('user_blacklisted', 'rejected'),
        ('file_expected', 'rejected'),
        ('http_post_expected', 'rejected'),
        ('illegal_threat_type', 'rejected'),
        ('illegal_ioc_type', 'rejected'),
        ('illegal_malware', 'rejected'),
        ('illegal_confidence_level', 'rejected'),
        ('illegal_tags', 'rejected'),
        ('illegal_reference', 'rejected'),
        ('illegal_comment', 'rejected'),
        ('illegal_anonymous', 'rejected'),
        ('no_ioc_supplied', 'rejected'),
        ('no_api_key', 'unavailable'),
    ]
    for status, expected in cases:
        for label, factory, source in (('submit_ioc', submit_ioc, 'threatfox'),
                                       ('upload_sample', upload_sample, 'malwarebazaar')):
            envelope, transport = run(FakeResponse({'query_status': status}), factory())
            check_submit_envelope(f'{label}/{status}', envelope, source, expected)
            check(len(transport.calls) == 1, f'{label}/{status}: expected exactly 1 request')
            check(envelope['raw'].get('query_status') == status,
                  f'{label}/{status}: raw should carry the provider status')

    # A 200 with no query_status is unparseable, not a refusal.
    for label, factory, source in (('submit_ioc', submit_ioc, 'threatfox'),
                                   ('upload_sample', upload_sample, 'malwarebazaar')):
        envelope, _ = run(FakeResponse({'some': 'thing'}), factory())
        check_submit_envelope(f'{label}/no-status', envelope, source, 'unavailable')
        check(envelope['raw'] == {'error': 'missing_query_status'},
              f'{label}/no-status: raw {envelope["raw"]}')

    # ThreatFox's 'ok' and MalwareBazaar's 'inserted' are both acceptances.
    envelope, _ = run(FakeResponse({'query_status': 'inserted'}), submit_ioc())
    check_submit_envelope('submit_ioc/inserted', envelope, 'threatfox', 'submitted')
    envelope, _ = run(FakeResponse({'query_status': 'ok'}), upload_sample())
    check_submit_envelope('upload_sample/ok-status', envelope, 'malwarebazaar', 'submitted')


def test_submission_http_errors():
    for status_code in (401, 403, 429, 500, 503):
        for label, factory, source in (('submit_ioc', submit_ioc, 'threatfox'),
                                       ('upload_sample', upload_sample, 'malwarebazaar')):
            envelope, transport = run(
                FakeResponse({'query_status': 'ok'}, status_code=status_code), factory())
            check_submit_envelope(f'{label}/http{status_code}', envelope, source, 'unavailable')
            check(envelope['raw'] == {'error': f'http_{status_code}'},
                  f'{label}/http{status_code}: raw {envelope["raw"]}')
            check(len(transport.calls) == 1,
                  f'{label}/http{status_code}: expected exactly 1 request')


def test_submission_transport_errors():
    cases = [
        (requests.Timeout('timed out'), 'timeout'),
        (requests.ConnectionError('refused'), 'request_error'),
        (requests.RequestException('boom'), 'request_error'),
        (RuntimeError('unexpected'), 'transport_error'),
    ]
    for exc, expected in cases:
        for label, factory, source in (('submit_ioc', submit_ioc, 'threatfox'),
                                       ('upload_sample', upload_sample, 'malwarebazaar')):
            envelope, _ = run(exc, factory())
            check_submit_envelope(f'{label}/{expected}', envelope, source, 'unavailable')
            check(envelope['raw'] == {'error': expected},
                  f'{label}/{expected}: raw {envelope["raw"]}')


def test_submission_malformed_body():
    for label, factory, source in (('submit_ioc', submit_ioc, 'threatfox'),
                                   ('upload_sample', upload_sample, 'malwarebazaar')):
        envelope, _ = run(FakeResponse('<html>502 Bad Gateway</html>'), factory())
        check_submit_envelope(f'{label}/non-json', envelope, source, 'unavailable')
        check(envelope['raw'] == {'error': 'unparseable_body'},
              f'{label}/non-json: raw {envelope["raw"]}')

        envelope, _ = run(FakeResponse(['unexpected', 'list']), factory())
        check_submit_envelope(f'{label}/list-body', envelope, source, 'unavailable')
        check(envelope['raw'] == {'error': 'unexpected_body'},
              f'{label}/list-body: raw {envelope["raw"]}')


def test_submission_skipped_without_key():
    for label, factory, source in (('submit_ioc', submit_ioc, 'threatfox'),
                                   ('upload_sample', upload_sample, 'malwarebazaar')):
        envelope, transport = run(FakeResponse(TF_SUBMIT_OK), factory(), key=None)
        check_submit_envelope(f'{label}/no-key', envelope, source, 'skipped')
        check(transport.calls == [],
              f'{label}/no-key: issued {len(transport.calls)} request(s) without a key')
        check(envelope['raw'] == {}, f'{label}/no-key: raw should be empty')
        check(envelope['summary'], f'{label}/no-key: summary should say what was not sent')

        envelope, transport = run(FakeResponse(TF_SUBMIT_OK), factory(), key='   ')
        check_submit_envelope(f'{label}/blank-key', envelope, source, 'skipped')
        check(transport.calls == [], f'{label}/blank-key: no request may be issued')

    envelope, _ = run(FakeResponse(TF_SUBMIT_OK), upload_sample(), key=None)
    check(envelope['summary']['sha256'] == SAMPLE_SHA256,
          'upload_sample/no-key: the skipped envelope should still name the sample')


def test_local_validation_issues_no_request():
    """Every local refusal is a `rejected` envelope and, crucially, zero traffic."""
    cases = [
        ('iocs-not-a-list', submit_ioc(iocs='bad.test'), 'threatfox', 'iocs_not_a_list'),
        ('iocs-empty-list', submit_ioc(iocs=[]), 'threatfox', 'no_iocs_supplied'),
        ('iocs-none', submit_ioc(iocs=None), 'threatfox', 'iocs_not_a_list'),
        ('ioc-not-a-string', submit_ioc(iocs=['ok.test', 42]), 'threatfox',
         'ioc_not_a_string'),
        ('ioc-blank', submit_ioc(iocs=['ok.test', '   ']), 'threatfox', 'empty_ioc'),
        ('missing-threat-type', submit_ioc(threat_type='  '), 'threatfox',
         'missing_threat_type'),
        ('missing-ioc-type', submit_ioc(ioc_type=None), 'threatfox', 'missing_ioc_type'),
        ('missing-malware', submit_ioc(malware=''), 'threatfox', 'missing_malware'),
        ('confidence-high', submit_ioc(confidence_level=101), 'threatfox',
         'illegal_confidence_level'),
        ('confidence-negative', submit_ioc(confidence_level=-1), 'threatfox',
         'illegal_confidence_level'),
        ('confidence-junk', submit_ioc(confidence_level='high'), 'threatfox',
         'illegal_confidence_level'),
        ('reference-scheme', submit_ioc(reference='javascript:alert(1)'), 'threatfox',
         'illegal_reference'),
        ('reference-type', submit_ioc(reference=42), 'threatfox', 'illegal_reference'),
        ('comment-type', submit_ioc(comment=42), 'threatfox', 'illegal_comment'),
        ('tf-tag-charset', submit_ioc(tags=['bad/tag']), 'threatfox',
         'illegal_tag_charset'),
        ('tf-tag-type', submit_ioc(tags=[42]), 'threatfox', 'tag_not_a_string'),
        ('tf-tag-blank', submit_ioc(tags=['ok', ' ']), 'threatfox', 'empty_tag'),
        ('tf-tags-scalar', submit_ioc(tags=42), 'threatfox', 'tags_not_a_list'),

        ('data-is-str', upload_sample(data='MZ'), 'malwarebazaar', 'data_not_bytes'),
        ('data-is-none', upload_sample(data=None), 'malwarebazaar', 'data_not_bytes'),
        ('data-empty', upload_sample(data=b''), 'malwarebazaar', 'empty_data'),
        ('filename-blank', upload_sample(filename='   '), 'malwarebazaar',
         'missing_filename'),
        ('filename-dots', upload_sample(filename='../..'), 'malwarebazaar',
         'missing_filename'),
        ('filename-type', upload_sample(filename=None), 'malwarebazaar',
         'missing_filename'),
        ('mb-tag-charset', upload_sample(tags=['drop_me']), 'malwarebazaar',
         'illegal_tag_charset'),
        ('delivery-unknown', upload_sample(delivery_method='carrier_pigeon'),
         'malwarebazaar', 'illegal_delivery_method'),
        ('delivery-type', upload_sample(delivery_method=7), 'malwarebazaar',
         'illegal_delivery_method'),
        ('references-unknown-key', upload_sample(references={'pastebin': ['x']}),
         'malwarebazaar', 'references_unknown_key'),
        ('references-not-a-map', upload_sample(references=['x']), 'malwarebazaar',
         'references_not_a_mapping'),
        ('context-unknown-key', upload_sample(context={'notes': 'x'}), 'malwarebazaar',
         'context_unknown_key'),
        ('context-not-a-map', upload_sample(context='x'), 'malwarebazaar',
         'context_not_a_mapping'),
    ]
    for label, call, source, reason in cases:
        envelope, transport = run(FakeResponse(TF_SUBMIT_OK), call)
        check_submit_envelope(f'validation/{label}', envelope, source, 'rejected')
        check(transport.calls == [],
              f'validation/{label}: issued {len(transport.calls)} request(s) before validating')
        check(envelope['raw'].get('error') == reason,
              f'validation/{label}: expected reason {reason}, got {envelope["raw"]}')
        check(envelope['summary'] == {}, f'validation/{label}: summary should be empty')

    # The offending key is reported back, so the caller can fix it.
    envelope, _ = run(FakeResponse(TF_SUBMIT_OK),
                      upload_sample(references={'pastebin': ['x']}))
    check(envelope['raw'].get('detail') == 'pastebin',
          f'validation: unknown reference key not named ({envelope["raw"]})')

    # Legal enums and tags are accepted, so the guards are not blanket refusals.
    for method in sorted(abusech.DELIVERY_METHODS):
        envelope, transport = run(FakeResponse(MB_UPLOAD_OK),
                                  upload_sample(delivery_method=method))
        check_submit_envelope(f'delivery/{method}', envelope, 'malwarebazaar', 'submitted')
        check(len(transport.calls) == 1, f'delivery/{method}: should have been sent')
    envelope, _ = run(FakeResponse(TF_SUBMIT_OK), submit_ioc(tags=['a.b-c 1', 'Zloader']))
    check_submit_envelope('tags/legal-charset', envelope, 'threatfox', 'submitted')


def test_anonymous_defaults_to_opt_out():
    """Attribution must be opt-in: the default is anonymous on both endpoints."""
    _, transport = run(FakeResponse(TF_SUBMIT_OK), submit_ioc())
    check(transport.calls[0]['json']['anonymous'] == 1,
          f'submit_ioc: anonymous must default to 1, got '
          f'{transport.calls[0]["json"]["anonymous"]!r}')

    _, transport = run(FakeResponse(MB_UPLOAD_OK), upload_sample())
    meta = json.loads(transport.calls[0]['files']['json_data'][1])
    check(meta['anonymous'] == 1,
          f'upload_sample: anonymous must default to 1, got {meta["anonymous"]!r}')

    envelope, transport = run(FakeResponse(TF_SUBMIT_OK), submit_ioc(anonymous=False))
    check(transport.calls[0]['json']['anonymous'] == 0,
          'submit_ioc: anonymous=False must map to 0')
    check(envelope['summary']['anonymous'] is False,
          'submit_ioc: summary should record the attribution choice')

    envelope, transport = run(FakeResponse(MB_UPLOAD_OK), upload_sample(anonymous=False))
    meta = json.loads(transport.calls[0]['files']['json_data'][1])
    check(meta['anonymous'] == 0, 'upload_sample: anonymous=False must map to 0')
    check(envelope['summary']['anonymous'] is False,
          'upload_sample: summary should record the attribution choice')

    # The flag is a boolean decision, not a passthrough: 0/1 ints work the same way.
    _, transport = run(FakeResponse(TF_SUBMIT_OK), submit_ioc(anonymous=0))
    check(transport.calls[0]['json']['anonymous'] == 0, 'submit_ioc: anonymous=0 must map to 0')
    _, transport = run(FakeResponse(TF_SUBMIT_OK), submit_ioc(anonymous=1))
    check(transport.calls[0]['json']['anonymous'] == 1, 'submit_ioc: anonymous=1 must map to 1')


def test_submissions_are_not_cached():
    """A cached submission would turn a retry into a silent no-op. Two calls, two requests."""
    for label, func in (('submit_ioc', abusech.submit_ioc),
                        ('upload_sample', abusech.upload_sample)):
        check(not hasattr(func, 'cache_clear'),
              f'{label} is wrapped in a cache - submissions must never be cached')

    def twice_ioc():
        return [abusech.submit_ioc(IOCS, 'botnet_cc', 'ip:port', 'win.zloader'),
                abusech.submit_ioc(IOCS, 'botnet_cc', 'ip:port', 'win.zloader')]

    results, transport = run(FakeResponse(TF_SUBMIT_OK), twice_ioc)
    check(len(transport.calls) == 2,
          f'submit_ioc: 2 identical calls issued {len(transport.calls)} request(s)')
    check(all(r['state'] == 'submitted' for r in results),
          'submit_ioc: both calls should report submitted')

    def twice_upload():
        return [abusech.upload_sample(SAMPLE, 'sample.bin'),
                abusech.upload_sample(SAMPLE, 'sample.bin')]

    results, transport = run(FakeResponse(MB_UPLOAD_OK), twice_upload)
    check(len(transport.calls) == 2,
          f'upload_sample: 2 identical calls issued {len(transport.calls)} request(s)')
    check(all(r['state'] == 'submitted' for r in results),
          'upload_sample: both calls should report submitted')

    # ...and a failure must not be cached either, or a legitimate resend is blocked.
    def failed_then_retried():
        return [abusech.submit_ioc(IOCS, 'botnet_cc', 'ip:port', 'win.zloader'),
                abusech.submit_ioc(IOCS, 'botnet_cc', 'ip:port', 'win.zloader')]

    _, transport = run(requests.Timeout('slow'), failed_then_retried)
    check(len(transport.calls) == 2,
          f'submit_ioc: a timeout was cached ({len(transport.calls)} request(s) for 2 calls)')


def main():
    test_found_envelopes()
    test_request_shapes()
    test_summaries()
    test_sparse_fields()
    test_no_record()
    test_failure_statuses()
    test_http_errors()
    test_transport_errors()
    test_malformed_body()
    test_skipped_without_key()
    test_empty_input()
    test_auth_key()
    test_hash_service_bridge()
    test_cache_registration()
    test_submit_ioc_success()
    test_submit_ioc_outcomes()
    test_upload_sample_success()
    test_upload_sample_duplicate()
    test_submission_provider_statuses()
    test_submission_http_errors()
    test_submission_transport_errors()
    test_submission_malformed_body()
    test_submission_skipped_without_key()
    test_local_validation_issues_no_request()
    test_anonymous_defaults_to_opt_out()
    test_submissions_are_not_cached()

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {checks} abuse.ch client cases')


if __name__ == '__main__':
    main()
