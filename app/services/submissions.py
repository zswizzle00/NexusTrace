"""Two-person-rule queue for abuse.ch submissions: an analyst *proposes*, an operator
approves. The point of the module is a single, auditable choke point:

    **:func:`approve` is the only function in the app that transmits to abuse.ch.**

``queue_ioc``/``queue_sample`` write a record and nothing else; ``reject``,
``list_submissions``, ``get_submission`` and ``purge_quarantine`` never reach the
provider at all. Every outbound call goes through :func:`_provider`, so there is
exactly one place to audit and one place for tests to intercept - do not add a second
`from .abusech import submit_ioc` anywhere in this file.

Storage mirrors ``scan_service``/``email_service``: ``<uuid>.json`` in the
``submissions`` store, newest-first by mtime, tolerant reads.

Sample bytes live in the ``quarantine`` store - they are live malware. Written
exclusively and owner-only (``0600`` locally), named from a digest this module computes
itself, deleted as soon as the record reaches a terminal state, and never returned by
any accessor.
"""

import hashlib
import json
import logging
import re
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..utils import storage
from ..utils.storage import store

logger = logging.getLogger(__name__)

# Every read/write here goes through `store()`; these exist for the operator tools
# that are local-disk by design (manage_submissions.py, purge_data.py) and must be
# repointed together with `storage.LOCAL_ROOT`, never on their own.
SUBMISSION_DIR = Path(storage.LOCAL_ROOT) / 'submissions'
QUARANTINE_DIR = Path(storage.LOCAL_ROOT) / 'quarantine'

STATUS_PENDING = 'pending'
STATUS_APPROVED = 'approved'
STATUS_REJECTED = 'rejected'
STATUS_SENT = 'sent'
STATUS_FAILED = 'failed'

# Already published (or refused): approve()/reject() return the record unchanged,
# which is what stops a double-click or retried POST double-publishing.
TERMINAL_STATUSES = frozenset({STATUS_SENT, STATUS_REJECTED})

KIND_IOC = 'ioc'
KIND_SAMPLE = 'sample'
DESTINATIONS = {KIND_IOC: 'threatfox', KIND_SAMPLE: 'malwarebazaar'}

# `duplicate` is a success: abuse.ch has it, so the decision is discharged.
SENT_STATES = frozenset({'submitted', 'duplicate'})

# A second bound so a caller that is not a Flask route cannot fill the store.
MAX_SAMPLE_BYTES = 50 * 1024 * 1024

_SHA256_RE = re.compile(r'^[0-9a-f]{64}$')
_UUID_RE = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-'
                      r'[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
_QUARANTINE_RE = re.compile(r'^[0-9a-f]{64}-[0-9a-fA-F-]{36}\.bin$')

# Keys that must never leave this module. Records are never written with them, but
# a hand-edited or future-version file could carry one; every accessor strips them.
_PRIVATE_KEYS = ('data', 'bytes', 'content', 'raw_bytes', 'quarantine_path', 'path')

# Set to a module-like object in tests. When None the real abuse.ch client is used.
PROVIDER = None

# Serialises approve()'s whole read-decide-send-write cycle, held across the network
# call on purpose: releasing it after the status flip would let a second approve() of
# the same record start a second send while the first is in flight. Approvals are
# rare, so this costs nothing. Per-process only - it does not defend against two
# gunicorn workers, which is one more reason the production CMD runs a single worker.
_SEND_LOCK = threading.RLock()


def _now():
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')


def _ensure_dirs():
    """Reads the module globals every time so tests can repoint them at a temp tree.
    The store creates its own root on write anyway; this only makes the directories
    visible to an operator before the first record exists."""
    if storage.backend_name() != 'local':
        return
    SUBMISSION_DIR.mkdir(parents=True, exist_ok=True)
    QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)


def _provider():
    """Imported lazily and defensively: a missing submit function must degrade to a
    diagnosable ``failed`` record rather than an ImportError at app start.
    """
    if PROVIDER is not None:
        return PROVIDER
    try:
        from . import abusech
    except Exception as exc:
        logger.error('abuse.ch client unavailable: %s', exc)
        return None
    return abusech


def _provider_call(name):
    provider = _provider()
    fn = getattr(provider, name, None) if provider is not None else None
    return fn if callable(fn) else None


def _strings(value):
    if value in (None, ''):
        return []
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, (list, tuple, set, frozenset)):
        out = []
        for item in value:
            text = str(item).strip()
            if text and text not in out:
                out.append(text)
        return out
    text = str(value).strip()
    return [text] if text else []


def _text(value):
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _confidence(value):
    try:
        level = int(value)
    except (TypeError, ValueError):
        return 50
    return max(0, min(100, level))


def _public(record):
    """The outward-facing view of a record: never the sample bytes, never a path."""
    if not isinstance(record, dict):
        return None
    clean = {k: v for k, v in record.items() if k not in _PRIVATE_KEYS}
    quarantine = clean.get('quarantine')
    if isinstance(quarantine, dict):
        clean['quarantine'] = {k: v for k, v in quarantine.items()
                               if k not in _PRIVATE_KEYS}
    return clean


def _record_key(sid):
    return f'{sid}.json'


def _save(record):
    """Atomic (``write_text`` is temp-and-replace locally, one object generation on
    GCS): an unreadable record for an in-flight send is an untrackable transmission."""
    sid = record.get('id')
    store('submissions').write_text(_record_key(sid), json.dumps(record, default=str))
    return record


def _load(sid):
    """None for a missing, unreadable or non-object record; a partial record comes back
    as-is, and every reader uses .get()."""
    if not sid or not _UUID_RE.match(str(sid)):
        return None
    raw = store('submissions').read_text(_record_key(sid))
    if raw is None:
        return None
    try:
        record = json.loads(raw)
    except Exception:
        logger.warning('Submission %s is unreadable', sid)
        return None
    if not isinstance(record, dict):
        return None
    # The key wins: a record whose id disagrees with it would produce links and
    # follow-up calls that hit a different record.
    record['id'] = str(sid)
    return record


def _touch(record, status):
    record['status'] = status
    record['updated_at'] = _now()
    history = record.get('history')
    if not isinstance(history, list):
        history = []
    history.append({'at': record['updated_at'], 'status': status})
    record['history'] = history
    return record


def _quarantine_key(sha256, sid):
    """Flat, self-derived store key: ``<sha256>-<record-id>.bin``.

    Both halves are generated here - the digest from the bytes themselves, the id from
    ``uuid4`` - so nothing the caller supplied reaches the filesystem. The uploaded
    filename is attacker-controlled and is kept for display only.

    The id is in the name even though the digest alone is unique per content: two
    records may queue the same bytes, and a shared file would let the first one
    approved delete the second one's sample.
    """
    digest = str(sha256 or '').lower()
    if not _SHA256_RE.match(digest) or not _UUID_RE.match(str(sid or '')):
        return None
    return f'{digest}-{sid}.bin'


def _write_quarantine(data, sha256, sid):
    key = _quarantine_key(sha256, sid)
    if key is None:
        raise ValueError('refusing to quarantine under a non-derived filename')
    # exclusive is deliberate: a pre-existing object under a name only this module can
    # produce means something is wrong, and overwriting it would destroy a sample.
    store('quarantine').write_bytes(key, data, exclusive=True, private=True)
    return key


def _drop_quarantine(record, why):
    """Called on every terminal transition: a queue that keeps malware around after the
    decision is made is a liability, not a feature."""
    quarantine = record.get('quarantine')
    if not isinstance(quarantine, dict) or not quarantine.get('stored'):
        return
    key = _quarantine_key(quarantine.get('sha256'), record.get('id'))
    if key is not None:
        # delete() reports absence rather than raising; still marked removed below.
        try:
            store('quarantine').delete(key)
        except Exception as exc:
            logger.error('Could not remove quarantined sample for %s: %s',
                         record.get('id'), exc)
            return
    quarantine['stored'] = False
    quarantine['removed_at'] = _now()
    quarantine['removed_reason'] = why


def _fp_indicator_values(entry):
    """The Hunting API's field naming is not contractual, so known keys are tried first
    and every string value is a fallback. An over-broad match costs a warning banner; a
    missed one costs a false-positive submission, so the bias is deliberate.
    """
    if not isinstance(entry, dict):
        return [str(entry).strip().lower()] if entry else []
    known = ('ioc', 'ioc_value', 'value', 'fp_ioc', 'indicator', 'sha256_hash',
             'md5_hash', 'sha1_hash', 'url', 'domain', 'host', 'ip_address', 'ip')
    values = [str(entry[k]).strip().lower() for k in known
              if entry.get(k) not in (None, '')]
    if values:
        return values
    return [str(v).strip().lower() for v in entry.values()
            if isinstance(v, str) and v.strip()]


def _fp_check(indicators):
    """Advisory only: a missing key, a transport failure or an empty list must never
    block queuing - the operator still sees the record, just without the warning.
    """
    wanted = {str(i).strip().lower() for i in indicators if str(i).strip()}
    result = {'fp_checked': False, 'fp_listed': False, 'fp_matches': []}
    if not wanted:
        return result

    fn = _provider_call('hunting_fplist')
    if fn is None:
        return result
    try:
        envelope = fn()
    except Exception as exc:
        logger.warning('abuse.ch FP-list check failed: %s', exc)
        return result
    if not isinstance(envelope, dict) or envelope.get('state') != 'found':
        return result

    raw = envelope.get('raw')
    raw = raw if isinstance(raw, dict) else {}
    entries = raw.get('fplist')
    if not isinstance(entries, list):
        entries = raw.get('data')
    if not isinstance(entries, list):
        return result

    result['fp_checked'] = True
    for entry in entries:
        if wanted.intersection(_fp_indicator_values(entry)):
            result['fp_matches'].append(entry if isinstance(entry, dict)
                                        else {'value': str(entry)})
    result['fp_listed'] = bool(result['fp_matches'])
    return result


def _new_record(kind, payload, indicators, source_analysis, anonymous, queued_by):
    sid = str(uuid.uuid4())
    now = _now()
    record = {
        'id': sid,
        'created_at': now,
        'updated_at': now,
        'kind': kind,
        'status': STATUS_PENDING,
        'destination': DESTINATIONS.get(kind),
        'anonymous': bool(anonymous),
        'source_analysis': _text(source_analysis),
        'queued_by': _text(queued_by),
        'indicators': indicators,
        'payload': payload,
        'quarantine': None,
        'attempts': 0,
        'result': None,
        'error': None,
        'approved_at': None,
        'rejected_at': None,
        'reject_reason': None,
        'sent_at': None,
        'history': [{'at': now, 'status': STATUS_PENDING}],
    }
    record.update(_fp_check(indicators))
    return record


def queue_ioc(iocs, threat_type, ioc_type, malware, *, source_analysis=None,
              confidence_level=50, reference=None, tags=None, comment=None,
              anonymous=True, queued_by=None):
    """Queue an IOC submission for approval. **Transmits nothing.** Raises ValueError
    when there is nothing to submit; every other input is normalised, not rejected.
    """
    values = _strings(iocs)
    if not values:
        raise ValueError('at least one IOC is required')
    if not _text(threat_type) or not _text(ioc_type) or not _text(malware):
        raise ValueError('threat_type, ioc_type and malware are required')

    payload = {
        'iocs': values,
        'threat_type': _text(threat_type),
        'ioc_type': _text(ioc_type),
        'malware': _text(malware),
        'confidence_level': _confidence(confidence_level),
        'reference': _text(reference),
        'tags': _strings(tags),
        'comment': _text(comment),
    }
    record = _new_record(KIND_IOC, payload, values, source_analysis, anonymous,
                         queued_by)
    _save(record)
    logger.info('Queued IOC submission %s (%d indicator(s)), pending approval',
                record['id'], len(values))
    return _public(record)


def queue_sample(data, filename, *, source_analysis=None, tags=None, references=None,
                 context=None, delivery_method=None, anonymous=True, queued_by=None):
    """Quarantine a sample and queue it for approval. **Transmits nothing.** ``filename``
    is recorded for the operator to read and is never used to build a path; the
    quarantine name comes from the SHA-256 computed here.
    """
    if isinstance(data, (bytearray, memoryview)):
        data = bytes(data)
    if not isinstance(data, bytes):
        raise TypeError('sample data must be bytes')
    if not data:
        raise ValueError('sample is empty')
    if len(data) > MAX_SAMPLE_BYTES:
        raise ValueError(f'sample exceeds {MAX_SAMPLE_BYTES} bytes')

    sha256 = hashlib.sha256(data).hexdigest()
    payload = {
        'filename': _text(filename) or 'sample.bin',
        'tags': _strings(tags),
        'references': _strings(references),
        'context': _text(context),
        'delivery_method': _text(delivery_method),
    }
    record = _new_record(KIND_SAMPLE, payload, [sha256], source_analysis, anonymous,
                         queued_by)
    record['quarantine'] = {
        'sha256': sha256,
        'size': len(data),
        'stored': True,
        'stored_at': record['created_at'],
        'removed_at': None,
        'removed_reason': None,
    }
    try:
        _write_quarantine(data, sha256, record['id'])
    except Exception as exc:
        logger.error('Could not quarantine sample for %s: %s', record['id'], exc)
        record['quarantine']['stored'] = False
        record['quarantine']['removed_reason'] = 'quarantine_write_failed'
        record['error'] = f'quarantine_write_failed: {exc}'
    _save(record)
    logger.info('Queued sample submission %s (%s), pending approval',
                record['id'], sha256[:12])
    return _public(record)


def list_submissions(status=None, limit=100):
    """Newest-first summaries. Reads only; issues no provider call."""
    wanted = None
    if status:
        wanted = {status} if isinstance(status, str) else set(status)

    try:
        limit = max(0, int(limit))
    except (TypeError, ValueError):
        limit = 100

    records = store('submissions')
    out = []
    # `limit` bounds returned summaries, not records examined, so a status filter
    # still finds `limit` matches behind newer non-matching records.
    for entry in records.list(suffix='.json'):
        if len(out) >= limit:
            break
        try:
            record = json.loads(records.read_text(entry['key']) or '')
        except Exception:
            continue
        if not isinstance(record, dict):
            continue
        if wanted is not None and record.get('status') not in wanted:
            continue
        payload = record.get('payload')
        payload = payload if isinstance(payload, dict) else {}
        quarantine = record.get('quarantine')
        quarantine = quarantine if isinstance(quarantine, dict) else {}
        out.append({
            'id': entry['key'][:-len('.json')],
            'created_at': record.get('created_at'),
            'updated_at': record.get('updated_at'),
            'kind': record.get('kind'),
            'status': record.get('status'),
            'destination': record.get('destination'),
            'anonymous': record.get('anonymous'),
            'queued_by': record.get('queued_by'),
            'source_analysis': record.get('source_analysis'),
            'indicators': record.get('indicators') or [],
            'malware': payload.get('malware'),
            'filename': payload.get('filename'),
            'sha256': quarantine.get('sha256'),
            'fp_listed': bool(record.get('fp_listed')),
            'error': record.get('error'),
        })
    return out


def get_submission(sid):
    """One record, or None. Reads only; issues no provider call."""
    return _public(_load(sid))


def _envelope_failure(reason, detail=None):
    raw = {'error': reason}
    if detail:
        raw['detail'] = str(detail)[:500]
    return {'source': 'abusech', 'state': 'unavailable', 'summary': {},
            'reference': None, 'raw': raw}


def _send(record):
    """Never raises: a provider that is missing, uncallable or throwing becomes an
    ``unavailable`` envelope, so the record lands in ``failed`` with the reason attached
    and can be approved again later.
    """
    kind = record.get('kind')
    payload = record.get('payload')
    payload = payload if isinstance(payload, dict) else {}

    if kind == KIND_IOC:
        fn = _provider_call('submit_ioc')
        if fn is None:
            return _envelope_failure('submitter_unavailable')
        return fn(
            payload.get('iocs') or record.get('indicators') or [],
            payload.get('threat_type'),
            payload.get('ioc_type'),
            payload.get('malware'),
            confidence_level=payload.get('confidence_level', 50),
            reference=payload.get('reference'),
            tags=payload.get('tags'),
            comment=payload.get('comment'),
            anonymous=bool(record.get('anonymous', True)),
        )

    if kind == KIND_SAMPLE:
        quarantine = record.get('quarantine')
        quarantine = quarantine if isinstance(quarantine, dict) else {}
        key = _quarantine_key(quarantine.get('sha256'), record.get('id'))
        if key is None or not quarantine.get('stored'):
            return _envelope_failure('quarantined_sample_missing')
        try:
            data = store('quarantine').read_bytes(key)
        except Exception as exc:
            return _envelope_failure('quarantined_sample_unreadable', exc)
        if data is None:
            return _envelope_failure('quarantined_sample_missing')
        fn = _provider_call('upload_sample')
        if fn is None:
            return _envelope_failure('submitter_unavailable')
        return fn(
            data,
            payload.get('filename') or 'sample.bin',
            tags=payload.get('tags'),
            references=payload.get('references'),
            context=payload.get('context'),
            delivery_method=payload.get('delivery_method'),
            anonymous=bool(record.get('anonymous', True)),
        )

    return _envelope_failure('unknown_submission_kind', kind)


def approve(sid):
    """Approve and transmit. **The only function in the app that transmits.**

    Idempotent by status: an already ``sent`` or ``rejected`` record is returned
    untouched, so a double-click or retried POST cannot publish twice. A ``failed``
    record may be approved again - that is the retry path, and the previous envelope
    stays in ``result`` until replaced.
    """
    with _SEND_LOCK:
        record = _load(sid)
        if record is None:
            return None
        if record.get('status') in TERMINAL_STATUSES:
            return _public(record)

        record['approved_at'] = record.get('approved_at') or _now()
        _touch(record, STATUS_APPROVED)
        # Durable intent before the wire: a crash mid-send leaves an `approved` record
        # an operator can see and retry, not a silent transmission.
        _save(record)

        try:
            envelope = _send(record)
        except Exception as exc:
            logger.error('Submission %s raised during send: %s', record['id'], exc)
            envelope = _envelope_failure('submitter_raised', exc)
        if not isinstance(envelope, dict):
            envelope = _envelope_failure('malformed_provider_response')

        record['attempts'] = (record.get('attempts') or 0) + 1
        record['result'] = envelope
        state = envelope.get('state')

        if state in SENT_STATES:
            record['sent_at'] = _now()
            record['error'] = None
            _touch(record, STATUS_SENT)
            _drop_quarantine(record, 'sent')
            logger.info('Submission %s %s to %s', record['id'], state,
                        record.get('destination'))
        else:
            raw = envelope.get('raw')
            detail = (raw or {}).get('error') if isinstance(raw, dict) else None
            record['error'] = f"{state or 'no_state'}: {detail}" if detail else \
                str(state or 'no_state')
            _touch(record, STATUS_FAILED)
            logger.warning('Submission %s failed (%s)', record['id'], record['error'])

        _save(record)
        return _public(record)


def reject(sid, reason):
    """Transmits nothing, ever. A ``sent`` record cannot be un-published and an
    already-rejected one is left alone; both come back unchanged.
    """
    with _SEND_LOCK:
        record = _load(sid)
        if record is None:
            return None
        if record.get('status') in TERMINAL_STATUSES:
            return _public(record)
        record['rejected_at'] = _now()
        record['reject_reason'] = _text(reason)
        _touch(record, STATUS_REJECTED)
        _drop_quarantine(record, 'rejected')
        _save(record)
        logger.info('Submission %s rejected', record['id'])
        return _public(record)


def purge_quarantine(max_age_days, apply=False):
    """Reports by default; deletes only with apply=True.

    Only this module's own ``<sha256>-<uuid>.bin`` naming is considered - anything else is
    reported and left alone rather than assumed junk. Age comes from the object's mtime,
    never a field inside a record, so a malformed record cannot make its sample immortal.
    ``list()`` never yields anything the store could not itself have written: locally a
    symlink or out-of-allowlist name is skipped, and either way never deleted.
    """
    stats = {'apply': bool(apply), 'max_age_days': max_age_days, 'checked': 0,
             'matched': 0, 'removed': 0, 'bytes': 0, 'errors': 0,
             'files': [], 'unexpected': []}
    try:
        cutoff = (datetime.now(timezone.utc)
                  - timedelta(days=float(max_age_days))).timestamp()
    except (TypeError, ValueError):
        raise ValueError('max_age_days must be a number')

    quarantine = store('quarantine')
    # By name, not newest-first: a stable ordering makes two reports comparable.
    for entry in sorted(quarantine.list(), key=lambda e: e['key']):
        name = entry['key']
        stats['checked'] += 1
        if not _QUARANTINE_RE.match(name):
            stats['unexpected'].append(name)
            continue
        if entry['modified'] > cutoff:
            continue
        stats['matched'] += 1
        stats['bytes'] += entry['size']
        stats['files'].append(name)
        if not apply:
            continue
        try:
            quarantine.delete(name)
        except Exception as exc:
            logger.error('Could not purge %s: %s', name, exc)
            stats['errors'] += 1
            continue
        stats['removed'] += 1
        _mark_purged(name)
    return stats


def _mark_purged(name):
    """Best-effort bookkeeping so a record does not still claim it has a sample."""
    sid = name[65:-4]
    record = _load(sid)
    if record is None:
        return
    quarantine = record.get('quarantine')
    if not isinstance(quarantine, dict) or not quarantine.get('stored'):
        return
    quarantine['stored'] = False
    quarantine['removed_at'] = _now()
    quarantine['removed_reason'] = 'purged'
    try:
        _save(record)
    except Exception as exc:
        logger.warning('Could not update %s after purge: %s', sid, exc)


try:
    _ensure_dirs()
except Exception as exc:  # a read-only checkout must not break app import
    logger.warning('Could not create submission stores: %s', exc)
