"""Pins app/services/submissions.py - the abuse.ch submission approval queue.

No network, no abuse.ch client: `submissions.PROVIDER` is replaced with a recording fake,
so every case asserts on the record the queue builds and on *how many times the provider
was called*. The call count is the whole point - this module exists so that nothing
reaches abuse.ch without an operator's approve().

`storage.LOCAL_ROOT` - and with it both stores this module writes to, plus
`submissions.SUBMISSION_DIR` / `QUARANTINE_DIR`, the local paths the operator CLI reads -
is repointed at a temp tree for the entire run; `check_isolation` refuses to proceed
otherwise, and checks the store roots themselves, not just the two module constants. The
real `data/` holds live records and live malware.
"""
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import logging

from app.services import submissions
from app.utils import storage

# Most failure cases here log at WARNING/ERROR on purpose.
logging.disable(logging.CRITICAL)

failures = []
checks = 0

SAMPLE = b'MZ\x90\x00nexustrace-test-sample-bytes-DO-NOT-LEAK'
SAMPLE_SHA256 = hashlib.sha256(SAMPLE).hexdigest()


def check(condition, message):
    global checks
    checks += 1
    if not condition:
        failures.append(message)


def envelope(state, source='threatfox', raw=None):
    return {'source': source, 'state': state, 'summary': {},
            'reference': 'https://example.invalid/ref', 'raw': raw or {}}


class FakeProvider:
    """Stands in for app.services.abusech and counts every transmission."""

    def __init__(self, ioc_result=None, sample_result=None, fplist=None, delay=0.0):
        self.ioc_result = ioc_result if ioc_result is not None else envelope('submitted')
        self.sample_result = (sample_result if sample_result is not None
                              else envelope('submitted', 'malwarebazaar'))
        self.fplist = fplist
        self.delay = delay
        self.submit_calls = []
        self.upload_calls = []
        self.fp_calls = 0

    @property
    def transmissions(self):
        return len(self.submit_calls) + len(self.upload_calls)

    def submit_ioc(self, iocs, threat_type, ioc_type, malware, *, confidence_level=50,
                   is_compromised=False, reference=None, tags=None, comment=None,
                   anonymous=True):
        self.submit_calls.append({
            'iocs': iocs, 'threat_type': threat_type, 'ioc_type': ioc_type,
            'malware': malware, 'confidence_level': confidence_level,
            'is_compromised': is_compromised, 'reference': reference, 'tags': tags,
            'comment': comment, 'anonymous': anonymous,
        })
        if self.delay:
            time.sleep(self.delay)
        if isinstance(self.ioc_result, Exception):
            raise self.ioc_result
        return self.ioc_result

    def upload_sample(self, data, filename, *, tags=None, references=None,
                      context=None, delivery_method=None, anonymous=True):
        self.upload_calls.append({
            'data': data, 'filename': filename, 'tags': tags,
            'references': references, 'context': context,
            'delivery_method': delivery_method, 'anonymous': anonymous,
        })
        if self.delay:
            time.sleep(self.delay)
        if isinstance(self.sample_result, Exception):
            raise self.sample_result
        return self.sample_result

    def hunting_fplist(self):
        self.fp_calls += 1
        if isinstance(self.fplist, Exception):
            raise self.fplist
        return self.fplist if self.fplist is not None else envelope('no_record', 'hunting')


class BrokenProvider:
    """A client that has no submit functions yet - the parallel-development case."""

    def hunting_fplist(self):
        return envelope('no_record', 'hunting')


def fplist_with(*values):
    return {'source': 'hunting', 'state': 'found', 'summary': {'count': len(values)},
            'reference': None,
            'raw': {'fplist': [{'ioc': v, 'reason': 'known good'} for v in values]}}


def use(provider):
    submissions.PROVIDER = provider
    return provider


def reset_store():
    for directory in (submissions.SUBMISSION_DIR, submissions.QUARANTINE_DIR):
        if directory.is_dir():
            shutil.rmtree(directory)
    submissions._ensure_dirs()


def quarantine_files():
    return sorted(p.name for p in submissions.QUARANTINE_DIR.iterdir())


def queue_a_sample(provider=None, filename='invoice.doc.exe', **kwargs):
    use(provider or FakeProvider())
    return submissions.queue_sample(SAMPLE, filename, **kwargs)


def check_isolation():
    """Refuse to run against the real data directory under any circumstances.

    Checks the store roots the module writes through as well as the two local-path
    constants: repointing only one would send half the I/O into the real `data/`.
    """
    if storage.backend_name() != 'local':
        raise SystemExit('REFUSING TO RUN: these cases assert local-filesystem '
                         'behaviour; unset STORAGE_BACKEND')
    real = Path(submissions.__file__).resolve().parent.parent.parent / 'data'
    for directory in (submissions.SUBMISSION_DIR, submissions.QUARANTINE_DIR,
                      storage.LOCAL_ROOT):
        resolved = Path(directory).resolve()
        if real in resolved.parents or resolved == real:
            raise SystemExit(f'REFUSING TO RUN: {directory} is inside the real data store')


def test_queue_never_transmits():
    """Invariant 1: no queue path may reach the provider."""
    reset_store()
    provider = use(FakeProvider(fplist=fplist_with('safe.example.com')))

    ioc = submissions.queue_ioc(['evil.example.com', 'evil2.example.com'],
                                'botnet_cc', 'domain', 'Cobalt Strike',
                                source_analysis='scan-1', tags=['t1'],
                                comment='seen in scan', queued_by='analyst@example.com')
    sample = submissions.queue_sample(SAMPLE, 'dropper.exe', queued_by='analyst')

    check(provider.transmissions == 0,
          f'queue_* transmitted {provider.transmissions} time(s); it must never transmit')
    check(ioc['status'] == 'pending', f"queued IOC status is {ioc['status']!r}, want 'pending'")
    check(sample['status'] == 'pending', f"queued sample status is {sample['status']!r}")
    check(ioc['destination'] == 'threatfox', 'IOC destination should be threatfox')
    check(sample['destination'] == 'malwarebazaar', 'sample destination should be malwarebazaar')
    check(ioc['attempts'] == 0 and sample['attempts'] == 0, 'a queued record has no attempts')
    check(ioc['result'] is None and sample['result'] is None,
          'a queued record has no provider result')
    check(provider.fp_calls >= 2, 'each queue call should run the FP pre-check')


def test_readers_never_transmit():
    """Invariant 2: only approve() transmits."""
    reset_store()
    provider = use(FakeProvider())
    ioc = submissions.queue_ioc(['a.example.com'], 'payload_delivery', 'domain', 'Emotet')
    sample = submissions.queue_sample(SAMPLE, 'x.bin')

    submissions.list_submissions()
    submissions.list_submissions(status='pending')
    submissions.get_submission(ioc['id'])
    submissions.get_submission(sample['id'])
    submissions.purge_quarantine(0, apply=False)
    submissions.purge_quarantine(0, apply=True)
    submissions.reject(ioc['id'], 'false positive')

    check(provider.transmissions == 0,
          f'non-approve functions transmitted {provider.transmissions} time(s)')


def test_ioc_lifecycle():
    reset_store()
    provider = use(FakeProvider())
    record = submissions.queue_ioc(' evil.example.com ', 'botnet_cc', 'domain',
                                   'Qakbot', confidence_level=175,
                                   reference='https://ref.example.invalid',
                                   tags=['phish', 'phish'], comment='c2',
                                   source_analysis='scan-9', queued_by='ana')

    check(record['payload']['iocs'] == ['evil.example.com'], 'IOC should be trimmed')
    check(record['payload']['confidence_level'] == 100,
          'confidence_level should clamp into 0..100')
    check(record['payload']['tags'] == ['phish'], 'tags should be de-duplicated')

    sent = submissions.approve(record['id'])
    check(sent['status'] == 'sent', f"approved IOC status is {sent['status']!r}, want 'sent'")
    check(sent['attempts'] == 1, 'a successful approve records one attempt')
    check(sent['sent_at'] and sent['approved_at'], 'approve stamps approved_at and sent_at')
    check(sent['result']['state'] == 'submitted', 'the provider envelope is kept on the record')
    check(sent['error'] is None, 'a sent record carries no error')

    call = provider.submit_calls[0]
    check(call['iocs'] == ['evil.example.com'], f"submitted iocs were {call['iocs']}")
    check(call['threat_type'] == 'botnet_cc' and call['ioc_type'] == 'domain',
          'threat/ioc type must reach the provider unchanged')
    check(call['malware'] == 'Qakbot', 'malware must reach the provider unchanged')
    check(call['confidence_level'] == 100, 'clamped confidence is what gets submitted')
    check(call['comment'] == 'c2' and call['reference'] == 'https://ref.example.invalid',
          'comment and reference must reach the provider')

    stored = submissions.get_submission(record['id'])
    check(stored['status'] == 'sent', 'the sent status is persisted, not just returned')
    listed = submissions.list_submissions(status='sent')
    check([r['id'] for r in listed] == [record['id']], 'status filter should find the sent record')


def test_sample_lifecycle():
    reset_store()
    provider = FakeProvider()
    record = queue_a_sample(provider, tags=['dropper'], references=['https://r.invalid'],
                            context='e-mail attachment', delivery_method='email_attachment')

    check(record['quarantine']['sha256'] == SAMPLE_SHA256,
          'the record must carry the digest this module computed')
    check(record['quarantine']['size'] == len(SAMPLE), 'quarantine size should be recorded')
    check(record['quarantine']['stored'] is True, 'a freshly queued sample is stored')
    check(quarantine_files() == [f'{SAMPLE_SHA256}-{record["id"]}.bin'],
          f'unexpected quarantine contents: {quarantine_files()}')

    sent = submissions.approve(record['id'])
    check(sent['status'] == 'sent', f"approved sample status is {sent['status']!r}")
    upload = provider.upload_calls[0]
    check(upload['data'] == SAMPLE, 'the exact quarantined bytes must be uploaded')
    check(upload['filename'] == 'invoice.doc.exe', 'the display filename reaches the provider')
    check(upload['delivery_method'] == 'email_attachment', 'delivery_method must be passed')
    check(upload['references'] == ['https://r.invalid'], 'references must be passed')

    check(quarantine_files() == [],
          f'quarantine must be emptied after a successful send: {quarantine_files()}')
    check(sent['quarantine']['stored'] is False, 'the record must show the sample is gone')
    check(sent['quarantine']['removed_reason'] == 'sent', 'removal reason should be recorded')


def test_quarantine_permissions_and_naming():
    """Invariant 4: 0600, self-derived name, no traversal from the caller's filename."""
    reset_store()
    hostile = '../../../../etc/nexustrace-pwned'
    record = queue_a_sample(filename=hostile)

    names = quarantine_files()
    check(names == [f'{SAMPLE_SHA256}-{record["id"]}.bin'],
          f'quarantine name must be derived from our own digest, got {names}')
    path = submissions.QUARANTINE_DIR / names[0]
    mode = stat.S_IMODE(path.lstat().st_mode)
    check(mode == 0o600, f'quarantine file mode is {oct(mode)}, want 0o600')
    check(path.read_bytes() == SAMPLE, 'quarantined bytes must round-trip exactly')

    escaped = submissions.QUARANTINE_DIR.parent / 'etc'
    check(not escaped.exists(), 'a traversal filename must not create anything outside')
    check(record['payload']['filename'] == hostile,
          'the caller filename is still shown to the operator, just never used as a path')

    # Same bytes queued twice must not share one file - approving either would
    # otherwise delete the other one's sample.
    second = queue_a_sample(filename='other.bin')
    check(len(quarantine_files()) == 2,
          'two records with identical bytes must have their own quarantine files')
    submissions.approve(second['id'])
    check(quarantine_files() == [f'{SAMPLE_SHA256}-{record["id"]}.bin'],
          'approving one record must not delete another record\'s sample')


def test_quarantine_never_returned():
    """Invariant 4: bytes never come back out through an accessor."""
    reset_store()
    record = queue_a_sample()
    for view, label in ((submissions.get_submission(record['id']), 'get_submission'),
                        (record, 'queue_sample'),
                        (submissions.list_submissions()[0], 'list_submissions')):
        blob = json.dumps(view, default=str)
        check('DO-NOT-LEAK' not in blob, f'{label} leaked sample bytes')
        check(str(submissions.QUARANTINE_DIR) not in blob,
              f'{label} leaked the quarantine path')
        for key in ('data', 'bytes', 'content', 'path', 'quarantine_path'):
            check(key not in view, f'{label} exposed a {key!r} key')

    # Defence in depth: a hand-edited record carrying a private key is still stripped.
    raw = submissions._load(record['id'])
    raw['quarantine_path'] = '/tmp/leak'
    raw['data'] = 'AAAA'
    raw['quarantine']['path'] = '/tmp/leak'
    submissions._save(raw)
    view = submissions.get_submission(record['id'])
    check('quarantine_path' not in view and 'data' not in view,
          'private keys must be stripped on read')
    check('path' not in view['quarantine'], 'private keys must be stripped from quarantine')


def test_state_mapping():
    """Each provider state must land the record in the right status."""
    cases = [
        ('submitted', 'sent'),
        ('duplicate', 'sent'),
        ('rejected', 'failed'),
        ('skipped', 'failed'),
        ('unavailable', 'failed'),
    ]
    for state, expected in cases:
        reset_store()
        use(FakeProvider(ioc_result=envelope(state, raw={'error': state})))
        record = submissions.queue_ioc(['x.example.com'], 'botnet_cc', 'domain', 'M')
        result = submissions.approve(record['id'])
        check(result['status'] == expected,
              f"provider state {state!r} produced status {result['status']!r}, want {expected!r}")
        check(result['result']['state'] == state,
              f'the {state!r} envelope must be kept for diagnosis')
        if expected == 'failed':
            check(result['error'], f'a failed {state!r} record needs a readable error')

    # A duplicate is a success, so its sample is released like any other send.
    reset_store()
    provider = FakeProvider(sample_result=envelope('duplicate', 'malwarebazaar'))
    record = queue_a_sample(provider)
    result = submissions.approve(record['id'])
    check(result['status'] == 'sent', 'a duplicate sample submission counts as sent')
    check(quarantine_files() == [], 'a duplicate must still release the quarantined sample')


def test_provider_failures():
    reset_store()
    use(FakeProvider(ioc_result=RuntimeError('connection reset')))
    record = submissions.queue_ioc(['x.example.com'], 'botnet_cc', 'domain', 'M')
    result = submissions.approve(record['id'])
    check(result['status'] == 'failed', 'a raising provider must produce failed, not a crash')
    check('submitter_raised' in json.dumps(result['result']),
          'the raise must be diagnosable from the record')

    reset_store()
    use(FakeProvider(ioc_result='not an envelope'))
    record = submissions.queue_ioc(['x.example.com'], 'botnet_cc', 'domain', 'M')
    result = submissions.approve(record['id'])
    check(result['status'] == 'failed', 'a malformed provider response must produce failed')

    reset_store()
    use(BrokenProvider())
    record = submissions.queue_ioc(['x.example.com'], 'botnet_cc', 'domain', 'M')
    result = submissions.approve(record['id'])
    check(result['status'] == 'failed', 'a client without submit_ioc must produce failed')
    check('submitter_unavailable' in json.dumps(result['result']),
          'a missing submit function must be named in the record')


def test_retry_after_failure():
    reset_store()
    provider = use(FakeProvider(ioc_result=envelope('unavailable', raw={'error': 'timeout'})))
    record = submissions.queue_ioc(['x.example.com'], 'botnet_cc', 'domain', 'M')
    first = submissions.approve(record['id'])
    check(first['status'] == 'failed', 'the first attempt should fail')

    provider.ioc_result = envelope('submitted')
    second = submissions.approve(record['id'])
    check(second['status'] == 'sent', 'a failed record must be retryable')
    check(second['attempts'] == 2, f"attempts is {second['attempts']}, want 2")
    check(provider.transmissions == 2, 'a retry is one more transmission, not more')
    check(second['error'] is None, 'a successful retry clears the previous error')


def test_double_approve():
    """Invariant 3: an already-sent or rejected record is never re-sent."""
    reset_store()
    provider = use(FakeProvider())
    record = submissions.queue_ioc(['x.example.com'], 'botnet_cc', 'domain', 'M')
    first = submissions.approve(record['id'])
    second = submissions.approve(record['id'])
    check(provider.transmissions == 1,
          f'approving twice transmitted {provider.transmissions} time(s)')
    check(first == second, 'a second approve must return the record unchanged')

    rejected = submissions.queue_ioc(['y.example.com'], 'botnet_cc', 'domain', 'M')
    submissions.reject(rejected['id'], 'benign')
    before = submissions.get_submission(rejected['id'])
    after = submissions.approve(rejected['id'])
    check(provider.transmissions == 1, 'approving a rejected record must not transmit')
    check(before == after, 'approving a rejected record must not change it')


def test_concurrent_double_approve():
    reset_store()
    provider = use(FakeProvider(delay=0.05))
    record = submissions.queue_ioc(['x.example.com'], 'botnet_cc', 'domain', 'M')

    barrier = threading.Barrier(4)
    results = []
    errors = []

    def worker():
        barrier.wait()
        try:
            results.append(submissions.approve(record['id']))
        except Exception as exc:  # a crashed worker must not read as a pass
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    check(provider.transmissions == 1,
          f'{len(threads)} concurrent approves transmitted {provider.transmissions} time(s)')
    check(not errors, f'concurrent approve raised: {errors}')
    check(len(results) == len(threads) and all(r['status'] == 'sent' for r in results),
          'every concurrent caller should see the sent record')


def test_reject():
    reset_store()
    provider = use(FakeProvider())
    record = queue_a_sample(provider)
    rejected = submissions.reject(record['id'], 'internal test artefact')

    check(rejected['status'] == 'rejected', f"reject produced {rejected['status']!r}")
    check(rejected['reject_reason'] == 'internal test artefact', 'the reason is recorded')
    check(rejected['rejected_at'], 'reject stamps rejected_at')
    check(quarantine_files() == [], 'reject must delete the quarantined sample')
    check(provider.transmissions == 0, 'reject must never transmit')

    again = submissions.reject(record['id'], 'changed my mind')
    check(again['reject_reason'] == 'internal test artefact',
          'a second reject must leave the record unchanged')

    sent = submissions.queue_ioc(['x.example.com'], 'botnet_cc', 'domain', 'M')
    submissions.approve(sent['id'])
    after = submissions.reject(sent['id'], 'too late')
    check(after['status'] == 'sent', 'a sent record cannot be retro-rejected')


def test_missing_quarantine_file():
    """Invariant 7: a vanished sample fails cleanly instead of raising."""
    reset_store()
    provider = FakeProvider()
    record = queue_a_sample(provider)
    (submissions.QUARANTINE_DIR / f'{SAMPLE_SHA256}-{record["id"]}.bin').unlink()

    result = submissions.approve(record['id'])
    check(result['status'] == 'failed', f"missing sample produced {result['status']!r}")
    check('quarantined_sample_missing' in json.dumps(result['result']),
          'the reason must name the missing sample')
    check(provider.transmissions == 0, 'a missing sample must not reach the provider')

    reset_store()
    provider = FakeProvider()
    record = queue_a_sample(provider)
    raw = submissions._load(record['id'])
    raw['quarantine']['stored'] = False
    submissions._save(raw)
    result = submissions.approve(record['id'])
    check(result['status'] == 'failed', 'a record that says its sample is gone must fail')
    check(provider.transmissions == 0, 'no upload for a released sample')


def test_fp_precheck():
    """Invariant 5: the FP list is surfaced, never a blocker."""
    reset_store()
    use(FakeProvider(fplist=fplist_with('good.example.com', 'other.example.com')))
    hit = submissions.queue_ioc(['GOOD.example.com'], 'botnet_cc', 'domain', 'M')
    check(hit['fp_listed'] is True, 'a listed indicator must be flagged')
    check(hit['fp_checked'] is True, 'a successful list check is recorded')
    check(hit['fp_matches'] and hit['fp_matches'][0].get('ioc') == 'good.example.com',
          'the matching FP entry must be attached for the operator')
    check(hit['status'] == 'pending', 'an FP hit must not block queuing')
    check(submissions.list_submissions()[0]['fp_listed'] is True,
          'the FP flag must be visible in the listing')

    miss = submissions.queue_ioc(['bad.example.com'], 'botnet_cc', 'domain', 'M')
    check(miss['fp_listed'] is False and miss['fp_matches'] == [],
          'an unlisted indicator must not be flagged')

    for label, fplist in (('unavailable', envelope('unavailable', 'hunting')),
                          ('empty', envelope('no_record', 'hunting')),
                          ('raising', RuntimeError('hunting api down')),
                          ('garbage', 'not a dict')):
        reset_store()
        use(FakeProvider(fplist=fplist))
        record = submissions.queue_ioc(['z.example.com'], 'botnet_cc', 'domain', 'M')
        check(record['status'] == 'pending', f'a {label} FP list must not block queuing')
        check(record['fp_listed'] is False and record['fp_checked'] is False,
              f'a {label} FP list must not claim a clean check')

    reset_store()
    use(FakeProvider(fplist=fplist_with(SAMPLE_SHA256)))
    sample = submissions.queue_sample(SAMPLE, 'a.bin')
    check(sample['fp_listed'] is True, 'a sample digest on the FP list must be flagged')

    reset_store()
    use(BrokenProvider())
    record = submissions.queue_ioc(['z.example.com'], 'botnet_cc', 'domain', 'M')
    check(record['fp_listed'] is False, 'a client without hunting_fplist must still queue')


def test_anonymous_default():
    """Invariant 6: anonymous is True unless the caller says otherwise."""
    reset_store()
    provider = use(FakeProvider())
    ioc = submissions.queue_ioc(['x.example.com'], 'botnet_cc', 'domain', 'M')
    sample = submissions.queue_sample(SAMPLE, 'a.bin')
    check(ioc['anonymous'] is True and sample['anonymous'] is True,
          'records default to anonymous')
    submissions.approve(ioc['id'])
    submissions.approve(sample['id'])
    check(provider.submit_calls[0]['anonymous'] is True,
          'submit_ioc must be called anonymous by default')
    check(provider.upload_calls[0]['anonymous'] is True,
          'upload_sample must be called anonymous by default')

    reset_store()
    provider = use(FakeProvider())
    attributed = submissions.queue_ioc(['x.example.com'], 'botnet_cc', 'domain', 'M',
                                       anonymous=False)
    check(attributed['anonymous'] is False, 'anonymous=False must be recorded')
    submissions.approve(attributed['id'])
    check(provider.submit_calls[0]['anonymous'] is False,
          'anonymous=False must reach the provider')

    # A record that predates the field (or lost it) must still go out anonymously -
    # the fallback has to be True, not Python's falsy default.
    reset_store()
    provider = use(FakeProvider())
    legacy = submissions.queue_ioc(['x.example.com'], 'botnet_cc', 'domain', 'M')
    raw = submissions._load(legacy['id'])
    del raw['anonymous']
    submissions._save(raw)
    submissions.approve(legacy['id'])
    check(provider.submit_calls[0]['anonymous'] is True,
          'a record with no anonymous field must default to anonymous on the wire')


def test_missing_and_corrupt_records():
    reset_store()
    provider = use(FakeProvider())
    check(submissions.get_submission(str(uuid.uuid4())) is None, 'unknown id reads as None')
    check(submissions.approve(str(uuid.uuid4())) is None, 'approving an unknown id is None')
    check(submissions.approve('not-a-uuid') is None, 'approving a bad id is None')
    check(submissions.approve('../../etc/passwd') is None, 'a traversal id is None')
    check(submissions.reject(str(uuid.uuid4()), 'x') is None, 'rejecting an unknown id is None')
    check(submissions.get_submission(None) is None, 'a None id reads as None')

    corrupt = submissions.SUBMISSION_DIR / f'{uuid.uuid4()}.json'
    corrupt.write_text('{"id": "truncated"', encoding='utf-8')
    listed = submissions.SUBMISSION_DIR / f'{uuid.uuid4()}.json'
    listed.write_text('["not", "an", "object"]', encoding='utf-8')
    partial_id = str(uuid.uuid4())
    (submissions.SUBMISSION_DIR / f'{partial_id}.json').write_text('{}', encoding='utf-8')

    check(submissions.list_submissions() == [] or
          [r['id'] for r in submissions.list_submissions()] == [partial_id],
          'unreadable records are skipped by the listing, partial ones survive')
    check(submissions.get_submission(corrupt.stem) is None, 'a corrupt record reads as None')
    check(submissions.approve(corrupt.stem) is None, 'approving a corrupt record is None')

    result = submissions.approve(partial_id)
    check(result is not None and result['status'] == 'failed',
          'a partial record must fail cleanly, not raise')
    check('unknown_submission_kind' in json.dumps(result['result']),
          'a kindless record must say why it failed')
    check(provider.transmissions == 0, 'a partial record must not transmit')

    check(submissions.reject(partial_id, 'junk')['status'] == 'rejected',
          'a partial record can still be rejected')


def test_listing():
    reset_store()
    use(FakeProvider())
    ids = []
    for index in range(3):
        record = submissions.queue_ioc([f'{index}.example.com'], 'botnet_cc', 'domain', 'M')
        ids.append(record['id'])
        path = submissions.SUBMISSION_DIR / f"{record['id']}.json"
        os.utime(path, (1_700_000_000 + index * 60, 1_700_000_000 + index * 60))

    listed = [r['id'] for r in submissions.list_submissions()]
    check(listed == list(reversed(ids)), f'listing must be newest-first by mtime, got {listed}')
    check(len(submissions.list_submissions(limit=2)) == 2, 'limit must be honoured')
    check(submissions.list_submissions(limit=0) == [], 'limit=0 returns nothing')
    check(submissions.list_submissions(status='sent') == [], 'nothing is sent yet')
    check(len(submissions.list_submissions(status=['pending', 'sent'])) == 3,
          'a status collection filters on any of them')

    submissions.approve(ids[0])
    check(len(submissions.list_submissions(status='pending')) == 2,
          'an approved record leaves the pending list')


def test_input_validation():
    global checks
    reset_store()
    use(FakeProvider())
    bad_iocs = [
        ([], 'empty list'), ('', 'empty string'), (None, 'None'),
        (['  ', ''], 'blank strings'),
    ]
    for value, label in bad_iocs:
        try:
            submissions.queue_ioc(value, 'botnet_cc', 'domain', 'M')
            failures.append(f'queue_ioc accepted {label} as an IOC list')
        except ValueError:
            pass
        checks += 1

    for kwargs, label in (({'threat_type': ''}, 'threat_type'),
                          ({'ioc_type': None}, 'ioc_type'),
                          ({'malware': '  '}, 'malware')):
        args = {'threat_type': 'botnet_cc', 'ioc_type': 'domain', 'malware': 'M'}
        args.update(kwargs)
        try:
            submissions.queue_ioc(['x.example.com'], **args)
            failures.append(f'queue_ioc accepted a missing {label}')
        except ValueError:
            pass
        checks += 1

    for value, exc, label in ((b'', ValueError, 'empty bytes'),
                              ('a string', TypeError, 'str data'),
                              (None, TypeError, 'None data')):
        try:
            submissions.queue_sample(value, 'a.bin')
            failures.append(f'queue_sample accepted {label}')
        except exc:
            pass
        checks += 1

    check(quarantine_files() == [], 'a rejected input must leave nothing in quarantine')
    check(submissions.list_submissions() == [], 'a rejected input must persist no record')

    record = submissions.queue_sample(bytearray(SAMPLE), 'a.bin')
    check(record['quarantine']['sha256'] == SAMPLE_SHA256, 'a bytearray sample is accepted')


def test_purge_quarantine():
    reset_store()
    provider = use(FakeProvider())
    old = queue_a_sample(provider, filename='old.bin')
    fresh = submissions.queue_sample(SAMPLE + b'-fresh', 'fresh.bin')

    old_path = submissions.QUARANTINE_DIR / f'{SAMPLE_SHA256}-{old["id"]}.bin'
    aged = time.time() - 40 * 86400
    os.utime(old_path, (aged, aged))
    stray = submissions.QUARANTINE_DIR / 'not-ours.txt'
    stray.write_text('operator note', encoding='utf-8')
    os.utime(stray, (aged, aged))

    dry = submissions.purge_quarantine(30, apply=False)
    check(dry['matched'] == 1 and dry['removed'] == 0,
          f"dry run reported matched={dry['matched']} removed={dry['removed']}")
    check(old_path.is_file(), 'a dry run must delete nothing')
    check(dry['bytes'] == len(SAMPLE), 'the dry run reports the reclaimable bytes')
    check(stray.name in dry['unexpected'], 'an unrecognised file is reported, not purged')

    applied = submissions.purge_quarantine(30, apply=True)
    check(applied['removed'] == 1, f"apply removed {applied['removed']} file(s), want 1")
    check(not old_path.is_file(), 'the aged sample must be gone')
    check(stray.is_file(), 'an unrecognised file must survive a purge')
    check(quarantine_files() == sorted([stray.name,
                                        f'{hashlib.sha256(SAMPLE + b"-fresh").hexdigest()}'
                                        f'-{fresh["id"]}.bin']),
          f'only the aged sample should have gone: {quarantine_files()}')

    marked = submissions.get_submission(old['id'])
    check(marked['quarantine']['stored'] is False,
          'a purged record must no longer claim to hold a sample')
    check(marked['quarantine']['removed_reason'] == 'purged', 'the purge is recorded')
    check(provider.transmissions == 0, 'purge must never transmit')

    result = submissions.approve(old['id'])
    check(result['status'] == 'failed', 'approving a purged sample fails cleanly')
    check(provider.transmissions == 0, 'a purged sample must not reach the provider')


def main():
    root = Path(tempfile.mkdtemp(prefix='nexustrace-submissions-'))
    real_local_root = storage.LOCAL_ROOT
    real_submission_dir = submissions.SUBMISSION_DIR
    real_quarantine_dir = submissions.QUARANTINE_DIR
    # The store roots and the module's local-path constants must move together -
    # the cases read both. reset_cache() drops Stores memoised against the old root.
    storage.LOCAL_ROOT = root
    storage.reset_cache()
    submissions.SUBMISSION_DIR = root / 'submissions'
    submissions.QUARANTINE_DIR = root / 'quarantine'
    check_isolation()

    try:
        submissions._ensure_dirs()
        test_queue_never_transmits()
        test_readers_never_transmit()
        test_ioc_lifecycle()
        test_sample_lifecycle()
        test_quarantine_permissions_and_naming()
        test_quarantine_never_returned()
        test_state_mapping()
        test_provider_failures()
        test_retry_after_failure()
        test_double_approve()
        test_concurrent_double_approve()
        test_reject()
        test_missing_quarantine_file()
        test_fp_precheck()
        test_anonymous_default()
        test_missing_and_corrupt_records()
        test_listing()
        test_input_validation()
        test_purge_quarantine()
    finally:
        submissions.PROVIDER = None
        submissions.SUBMISSION_DIR = real_submission_dir
        submissions.QUARANTINE_DIR = real_quarantine_dir
        storage.LOCAL_ROOT = real_local_root
        storage.reset_cache()
        shutil.rmtree(root, ignore_errors=True)

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {checks} submission-queue cases')


if __name__ == '__main__':
    main()
