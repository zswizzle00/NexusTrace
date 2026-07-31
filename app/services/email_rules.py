"""Heuristic scoring for a parsed e-mail. Pure; no network, no I/O.

Additive weights over named signals, clamped to [0, 1], then banded. Combos add on top
of their constituents because the combination is the tell, not either half: a brand
name in a display line is nothing, a brand name plus a reply-to on someone else's
domain is business e-mail compromise.

**The band floor is the important design property.** The four ambient header signals
sum to 0.20, below the 0.30 suspicious floor, so no combination of weak header quirks
can produce a verdict on its own. The URL scanner's engine shipped without that
property and flagged ordinary sites whose only sins were thin security headers and a
recently-renewed certificate.

`attachment_known_malware` is weighted at exactly MALICIOUS_THRESHOLD: a positive
hash-reputation hit must reach `malicious` alone, including for a malicious *document*,
which earns no `executable_attachment` weight.
"""

import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

WEIGHTS = {
    # Strong
    'attachment_known_malware': 0.75,
    'dmarc_fail': 0.35,
    'display_name_impersonation': 0.30,
    'executable_attachment': 0.30,
    'sender_ip_blacklisted': 0.30,
    'url_display_mismatch': 0.25,
    # Moderate
    'spf_fail': 0.20,
    'reply_to_mismatch': 0.20,
    'young_sender_domain': 0.20,
    'dkim_fail': 0.15,
    'return_path_mismatch': 0.10,
    'archive_attachment': 0.10,
    # Ambient: individually meaningless, and capped below the band floor
    'missing_message_id': 0.05,
    'missing_mime_version': 0.05,
    'date_anomaly': 0.05,
    'suspicious_mailer': 0.05,
    # Combos: both constituents present
    'display_name_impersonation+reply_to_mismatch': 0.25,
    'display_name_impersonation+url_display_mismatch': 0.25,
    'executable_attachment+dmarc_fail': 0.25,
    'executable_attachment+young_sender_domain': 0.20,
}

SUSPICIOUS_THRESHOLD = 0.30
MALICIOUS_THRESHOLD = 0.75

YOUNG_DOMAIN_MAX_DAYS = 30

# 'softfail' counts; 'none' and the temp/perm errors do not - an absent or broken SPF
# record is not evidence.
_SPF_FAIL_VERDICTS = frozenset({'fail', 'softfail'})

_DATE_FORMATS = (
    '%Y-%m-%d',
    '%Y-%m-%dT%H:%M:%S',
    '%Y-%m-%dT%H:%M:%SZ',
    '%Y-%m-%d %H:%M:%S',
)


def _age_days(value):
    if not value:
        return None
    text = str(value).strip()
    for fmt in _DATE_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        return (datetime.now(timezone.utc) - parsed).total_seconds() / 86400.0
    return None


def _known_malware(attachments, hashes):
    for attachment in attachments or []:
        digest = (attachment or {}).get('sha256')
        if not digest:
            continue
        report = (hashes or {}).get(digest) or {}
        if (report.get('summary') or {}).get('is_malicious'):
            return True
    return False


def score(findings):
    auth = findings.get('authentication') or {}
    spoofing = set(findings.get('spoofing') or [])
    ambient = set(findings.get('suspicious_headers') or [])
    urls = findings.get('urls') or []
    attachments = findings.get('attachments') or []
    enrichment = findings.get('enrichment') or {}

    sender = enrichment.get('sender_domain') or {}
    whois = sender.get('whois') or {}
    domain_age = _age_days(whois.get('create_date') or whois.get('created'))

    dnsbl = enrichment.get('dnsbl') or {}

    executable = any((a or {}).get('is_executable') for a in attachments)
    # A garbage or future creation date yields a negative age; that is a broken
    # WHOIS record, not a newly registered domain, so it must not score.
    young = domain_age is not None and 0 <= domain_age <= YOUNG_DOMAIN_MAX_DAYS
    dmarc_fail = (auth.get('dmarc') or '').lower() == 'fail'
    impersonation = 'display_name_impersonation' in spoofing
    url_mismatch = any((u or {}).get('display_mismatch') for u in urls)
    reply_mismatch = 'reply_to_mismatch' in spoofing

    present = {
        'attachment_known_malware': _known_malware(attachments, enrichment.get('hashes')),
        'dmarc_fail': dmarc_fail,
        'display_name_impersonation': impersonation,
        'executable_attachment': executable,
        'sender_ip_blacklisted': bool(dnsbl.get('listed')),
        'url_display_mismatch': url_mismatch,
        'spf_fail': (auth.get('spf') or '').lower() in _SPF_FAIL_VERDICTS,
        'reply_to_mismatch': reply_mismatch,
        'young_sender_domain': young,
        'dkim_fail': (auth.get('dkim') or '').lower() == 'fail',
        'return_path_mismatch': 'return_path_mismatch' in spoofing,
        'archive_attachment': any((a or {}).get('is_archive') for a in attachments),
        'missing_message_id': 'missing_message_id' in ambient,
        'missing_mime_version': 'missing_mime_version' in ambient,
        'date_anomaly': 'date_anomaly' in ambient,
        'suspicious_mailer': 'suspicious_mailer' in ambient,
        'display_name_impersonation+reply_to_mismatch': impersonation and reply_mismatch,
        'display_name_impersonation+url_display_mismatch': impersonation and url_mismatch,
        'executable_attachment+dmarc_fail': executable and dmarc_fail,
        'executable_attachment+young_sender_domain': executable and young,
    }

    signals = [name for name in WEIGHTS if present[name]]
    total = min(sum(WEIGHTS[name] for name in signals), 1.0)

    if not findings.get('parsed_ok'):
        level = 'unknown'
        total = 0.0
        signals = []
    elif total >= MALICIOUS_THRESHOLD:
        level = 'malicious'
    elif total >= SUSPICIOUS_THRESHOLD:
        level = 'suspicious'
    else:
        level = 'benign'

    return {'level': level, 'score': round(total, 3), 'signals': signals}
