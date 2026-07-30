"""Queue abuse.ch submissions for operator approval.

Nothing in this module transmits. Both routes write a *pending* record through
``app.services.submissions`` and stop; publishing is a separate, deliberate act an
operator performs with ``scripts/manage_submissions.py``. No abuse.ch client
function is imported, referenced, or reachable from here - grep this file for
``submit_ioc`` / ``upload_sample`` and you will find nothing.

Registered without a URL prefix, like ``scan_bp`` and ``email_bp``.
"""
import logging
import re
from urllib.parse import urlsplit

from flask import Blueprint, render_template, request
from werkzeug.utils import secure_filename

from ..utils.iocs import refang

logger = logging.getLogger(__name__)

submission_bp = Blueprint('submission', __name__)

# The store is built separately. When it is absent the buttons must not render at
# all (a control that 500s is worse than no control), which is what the
# `submissions_enabled` template global below gates on.
try:
    from ..services.submissions import queue_ioc, queue_sample
except Exception:
    queue_ioc = None
    queue_sample = None

MAX_INDICATORS = 25
MAX_INDICATOR_LENGTH = 2048
MAX_TAGS = 10
MAX_TAG_LENGTH = 32
MAX_REFERENCES = 5
MAX_REFERENCE_LENGTH = 512
MAX_COMMENT_LENGTH = 2000
MAX_MALWARE_LENGTH = 64
MAX_FILENAME_LENGTH = 255
DEFAULT_CONFIDENCE = 50

# Closed vocabularies. An unknown value is rejected rather than forwarded: the
# store is a queue for a third party's API, and a value it will not accept is
# better caught here than by an operator at approval time.
THREAT_TYPES = ('payload_delivery', 'payload', 'botnet_cc', 'unknown')
IOC_TYPES = ('url', 'domain', 'ip:port', 'md5_hash', 'sha1_hash', 'sha256_hash',
             'email')
DELIVERY_METHODS = ('email_attachment', 'email_link', 'web_download',
                    'web_drive-by', 'multiple', 'other')

_TAG_RE = re.compile(r'^[A-Za-z0-9.\- ]+$')
_MALWARE_RE = re.compile(r'^[A-Za-z0-9._\-]+$')
_SOURCE_RE = re.compile(r'^[A-Za-z0-9._:\-]{1,64}$')
_CONTROL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


class _Rejected(Exception):
    """A form value failed validation. Carries the analyst-facing reason."""


@submission_bp.app_template_global()
def submissions_enabled():
    """False when the queue store is unavailable, so templates hide the buttons."""
    return queue_ioc is not None and queue_sample is not None


def _text(value, limit, field):
    """A single-line string, control characters stripped, length enforced."""
    text = _CONTROL_RE.sub('', str(value or '')).strip()
    if len(text) > limit:
        raise _Rejected(f'{field} is longer than {limit} characters.')
    return text


def _one_of(value, allowed, field):
    text = (str(value or '')).strip()
    if text not in allowed:
        raise _Rejected(f'{field} must be one of: {", ".join(allowed)}.')
    return text


def _indicators(raw):
    """One indicator per line, refanged, deduped, capped, and vetted.

    Whitespace inside an indicator is rejected outright: no value in any of the
    allowed ioc_types contains a space, so a line that has one is a paste error or
    an attempt to smuggle a second value past the count cap.
    """
    seen = []
    for line in str(raw or '').splitlines():
        candidate = refang(_CONTROL_RE.sub('', line).strip())
        if not candidate:
            continue
        if len(candidate) > MAX_INDICATOR_LENGTH:
            raise _Rejected(
                f'An indicator is longer than {MAX_INDICATOR_LENGTH} characters.')
        if re.search(r'\s', candidate):
            raise _Rejected('An indicator contains whitespace. One per line.')
        if candidate not in seen:
            seen.append(candidate)
        if len(seen) > MAX_INDICATORS:
            raise _Rejected(f'No more than {MAX_INDICATORS} indicators per submission.')
    if not seen:
        raise _Rejected('No indicators were supplied.')
    return seen


def _tags(raw):
    """Comma-separated tags. The charset allows spaces, so commas are the only
    separator - splitting on whitespace would shred a legitimate two-word tag."""
    tags = []
    for chunk in str(raw or '').split(','):
        tag = _CONTROL_RE.sub('', chunk).strip()
        if not tag:
            continue
        if len(tag) > MAX_TAG_LENGTH:
            raise _Rejected(f'A tag is longer than {MAX_TAG_LENGTH} characters.')
        if not _TAG_RE.match(tag):
            raise _Rejected('Tags may contain only letters, digits, dot, hyphen, and space.')
        if tag not in tags:
            tags.append(tag)
        if len(tags) > MAX_TAGS:
            raise _Rejected(f'No more than {MAX_TAGS} tags.')
    return tags


def _reference(raw, field='Reference'):
    ref = _text(raw, MAX_REFERENCE_LENGTH, field)
    if not ref:
        return None
    if not ref.lower().startswith(('http://', 'https://')):
        raise _Rejected(f'{field} must be an http(s) URL.')
    return ref


def _references(raw):
    refs = []
    for chunk in str(raw or '').splitlines():
        ref = _reference(chunk, 'A reference')
        if ref and ref not in refs:
            refs.append(ref)
        if len(refs) > MAX_REFERENCES:
            raise _Rejected(f'No more than {MAX_REFERENCES} references.')
    return refs


def _confidence(raw):
    """Clamped, never rejected: a slider value is not worth failing a submission
    over, and the operator sees the stored number before anything is published."""
    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        return DEFAULT_CONFIDENCE
    return max(0, min(100, value))


def _malware(raw):
    name = _text(raw, MAX_MALWARE_LENGTH, 'Malware family')
    if not name:
        raise _Rejected('A malware family is required (for example win.zloader).')
    if not _MALWARE_RE.match(name):
        raise _Rejected('Malware family may contain only letters, digits, dot, '
                        'underscore, and hyphen.')
    return name


def _source_analysis(raw):
    value = _text(raw, 64, 'Source analysis')
    return value if value and _SOURCE_RE.match(value) else None


def _anonymous(form):
    """Absent means anonymous.

    An unchecked HTML checkbox sends nothing, so absence cannot by itself mean
    "not anonymous" without making the control impossible to switch off. The form
    therefore always submits `anonymous_choice=1`; when that marker is present the
    checkbox's presence decides, and when it is absent - any programmatic POST -
    the answer is the safe default, True.
    """
    if form.get('anonymous_choice'):
        return form.get('anonymous') is not None
    return True


def _record_view(record):
    """Normalize whatever the store returned into {id, status} for the template."""
    if isinstance(record, dict):
        return {'id': record.get('id'), 'status': record.get('status') or 'pending'}
    return {'id': getattr(record, 'id', None),
            'status': getattr(record, 'status', None) or 'pending'}


def _error(reason, status=400):
    return render_template('submit_queued.html', error=reason, record=None), status


@submission_bp.route('/submit/queue', methods=['POST'])
def submit_queue():
    """Queue indicators. Writes a pending record; sends nothing."""
    if queue_ioc is None:
        return _error('The submission queue is unavailable on this deployment.', 503)

    try:
        indicators = _indicators(request.form.get('indicators'))
        threat_type = _one_of(request.form.get('threat_type'), THREAT_TYPES, 'Threat type')
        ioc_type = _one_of(request.form.get('ioc_type'), IOC_TYPES, 'IOC type')
        malware = _malware(request.form.get('malware'))
        tags = _tags(request.form.get('tags'))
        reference = _reference(request.form.get('reference'))
        comment = _text(request.form.get('comment'), MAX_COMMENT_LENGTH, 'Comment') or None
        confidence = _confidence(request.form.get('confidence_level'))
        source = _source_analysis(request.form.get('source_analysis'))
    except _Rejected as exc:
        return _error(str(exc))

    try:
        record = queue_ioc(
            indicators, threat_type, ioc_type, malware,
            source_analysis=source,
            confidence_level=confidence,
            reference=reference,
            tags=tags,
            comment=comment,
            anonymous=_anonymous(request.form),
        )
    except Exception:
        logger.exception('Failed to queue an IOC submission')
        return _error('The submission could not be queued. Nothing was sent.', 500)

    return render_template('submit_queued.html', record=_record_view(record),
                           kind='ioc', count=len(indicators), error=None)


@submission_bp.route('/submit/sample', methods=['POST'])
def submit_sample():
    """Queue a re-attached sample. Writes a pending record; sends nothing.

    The analyst re-attaches the file deliberately because no analysis path retains
    sample bytes: uploads are unlinked in a `finally`, e-mail attachments are
    hashed and dropped, and the scanner keeps only a dropper's digest.
    """
    if queue_sample is None:
        return _error('The submission queue is unavailable on this deployment.', 503)

    uploaded = request.files.get('sample')
    if uploaded is None or not uploaded.filename:
        return _error('Attach the sample you want to queue.')

    try:
        delivery = _one_of(request.form.get('delivery_method'), DELIVERY_METHODS,
                           'Delivery method')
        tags = _tags(request.form.get('tags'))
        references = _references(request.form.get('references'))
        context = _text(request.form.get('context'), MAX_COMMENT_LENGTH, 'Context') or None
        source = _source_analysis(request.form.get('source_analysis'))
    except _Rejected as exc:
        return _error(str(exc))

    filename = (secure_filename(uploaded.filename) or 'sample.bin')[:MAX_FILENAME_LENGTH]
    data = uploaded.read()
    if not data:
        return _error('That file is empty.')

    try:
        record = queue_sample(
            data, filename,
            source_analysis=source,
            tags=tags,
            references=references,
            context=context,
            delivery_method=delivery,
            anonymous=_anonymous(request.form),
        )
    except Exception:
        logger.exception('Failed to queue a sample submission')
        return _error('The submission could not be queued. Nothing was sent.', 500)

    return render_template('submit_queued.html', record=_record_view(record),
                           kind='sample', filename=filename,
                           size_bytes=len(data), error=None)


def _uniq(values, limit=MAX_INDICATORS):
    out = []
    for value in values:
        if not isinstance(value, str):
            continue
        text = refang(value).strip()
        if not text or re.search(r'\s', text) or len(text) > MAX_INDICATOR_LENGTH:
            continue
        if text not in out:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _ioc_values(iocs, wanted):
    out = []
    for ioc in iocs or []:
        if isinstance(ioc, dict) and ioc.get('type') in wanted:
            out.append(ioc.get('value'))
    return out


def _group(label, ioc_type, threat_type, values, hint=None):
    values = _uniq(values)
    if not values:
        return None
    # Keyed 'indicators', not 'values': Jinja resolves `g.values` to dict.values.
    return {'label': label, 'ioc_type': ioc_type, 'threat_type': threat_type,
            'indicators': values, 'hint': hint}


_IP_HINT = 'abuse.ch expects host:port - append the port before queueing.'


def _scan_prefill(scan):
    page = scan.get('page') if isinstance(scan.get('page'), dict) else {}
    final_url = page.get('final_url') or scan.get('url')
    host = urlsplit(final_url).hostname if isinstance(final_url, str) else None
    iocs = scan.get('iocs')
    payload = scan.get('payload') if isinstance(scan.get('payload'), dict) else {}

    domains = [d.get('domain') for d in (scan.get('domains') or [])
               if isinstance(d, dict)]
    ips = [ip for ip in (scan.get('ips') or []) if isinstance(ip, str)]

    groups = [
        _group('Scanned URL(s)', 'url', 'payload_delivery',
               [final_url] + _ioc_values(iocs, ('url',))),
        _group('Host / domains', 'domain', 'payload_delivery',
               [host] + domains + _ioc_values(iocs, ('domain',))),
        _group('Server IPs', 'ip:port', 'botnet_cc',
               [scan.get('main_ip')] + ips + _ioc_values(iocs, ('ipv4', 'ipv6')),
               hint=_IP_HINT),
        _group('Dropped payload hash', 'sha256_hash', 'payload',
               [payload.get('sha256')]),
    ]
    return {
        'source_analysis': scan.get('id'),
        'groups': [g for g in groups if g],
        'comment': f'Observed by NexusTrace URL scan of {final_url}' if final_url else '',
    }


def _email_prefill(analysis):
    headers = analysis.get('headers') if isinstance(analysis.get('headers'), dict) else {}
    urls = [u.get('url') for u in (analysis.get('urls') or []) if isinstance(u, dict)]
    attachments = [a.get('sha256') for a in (analysis.get('attachments') or [])
                   if isinstance(a, dict)]

    groups = [
        _group('Body URLs', 'url', 'payload_delivery',
               urls + _ioc_values(analysis.get('iocs'), ('url',))),
        _group('Sender domain', 'domain', 'payload_delivery',
               [analysis.get('sender_domain')]
               + _ioc_values(analysis.get('iocs'), ('domain',))),
        _group('Received-chain IPs', 'ip:port', 'botnet_cc',
               list(analysis.get('received_public_ips') or [])
               + _ioc_values(analysis.get('iocs'), ('ipv4', 'ipv6')),
               hint=_IP_HINT),
        _group('Attachment hashes', 'sha256_hash', 'payload', attachments),
    ]
    subject = headers.get('subject') or '(no subject)'
    return {
        'source_analysis': analysis.get('id'),
        'groups': [g for g in groups if g],
        'comment': f'Observed in phishing e-mail, subject: {subject}',
    }


def _file_prefill(analysis):
    digests = analysis.get('digests') if isinstance(analysis.get('digests'), dict) else {}
    iocs = analysis.get('iocs')

    groups = [
        _group('SHA-256', 'sha256_hash', 'payload', [digests.get('sha256')]),
        _group('MD5', 'md5_hash', 'payload', [digests.get('md5')]),
        _group('SHA-1', 'sha1_hash', 'payload', [digests.get('sha1')]),
        _group('Extracted URLs', 'url', 'payload_delivery', _ioc_values(iocs, ('url',))),
        _group('Extracted domains', 'domain', 'botnet_cc', _ioc_values(iocs, ('domain',))),
        _group('Extracted IPs', 'ip:port', 'botnet_cc',
               _ioc_values(iocs, ('ipv4', 'ipv6')), hint=_IP_HINT),
    ]
    return {
        'source_analysis': None,
        'groups': [g for g in groups if g],
        'comment': f"Static triage of {analysis.get('filename') or 'an uploaded sample'}",
    }


_PREFILL = {'scan': _scan_prefill, 'email': _email_prefill, 'file': _file_prefill}


@submission_bp.app_template_global()
def submission_prefill(kind, record):
    """Candidate indicators for a result page's queue form.

    Every value here came out of a scanned page, an e-mail, or an uploaded file, so
    it is attacker-controlled: the templates put it in form *values* and in a
    tojson blob read by `.value =` assignment, never into markup.
    """
    builder = _PREFILL.get(kind)
    if builder is None or not isinstance(record, dict):
        return None
    try:
        prefill = builder(record)
    except Exception:
        logger.exception('Failed to build submission prefill for %s', kind)
        return None
    if not prefill['groups']:
        return None
    prefill['default'] = 0
    return prefill
