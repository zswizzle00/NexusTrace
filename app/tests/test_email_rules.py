"""Pins app/services/email_rules.py — pure weighted scoring, no network.

Covers the benign rows as deliberately as the malicious ones. The forwarded-mail
row matters most: forwarding breaks SPF routinely, and an engine that calls every
forwarded message suspicious is useless.
"""
import os
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.services.email_rules import (
    MALICIOUS_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    WEIGHTS,
    score,
)

AMBIENT = ['missing_message_id', 'missing_mime_version', 'date_anomaly', 'suspicious_mailer']


def recent_date(days_ago):
    """Relative, never a literal — a hard-coded date is a time bomb."""
    return (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime('%Y-%m-%d')


def future_date(days_ahead):
    return (datetime.now(timezone.utc) + timedelta(days=days_ahead)).strftime('%Y-%m-%d')


def findings(auth=None, spoofing=None, headers=None, urls=None, attachments=None,
             sender_whois=None, hashes=None, dnsbl=None, parsed_ok=True):
    return {
        'parsed_ok': parsed_ok,
        'authentication': auth or {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass'},
        'spoofing': spoofing or [],
        'suspicious_headers': headers or [],
        'urls': urls or [],
        'attachments': attachments or [],
        'enrichment': {
            'sender_domain': {'whois': {'create_date': sender_whois}} if sender_whois else None,
            'hashes': hashes or {},
            'dnsbl': dnsbl,
        },
    }


EXE = {'sha256': 'a' * 64, 'is_executable': True, 'is_archive': False}
DOC = {'sha256': 'b' * 64, 'is_executable': False, 'is_archive': False}
ZIP = {'sha256': 'c' * 64, 'is_executable': False, 'is_archive': True}
MISMATCH_URL = {'url': 'https://evil.test/x', 'display_mismatch': True}
FAIL_ALL = {'spf': 'fail', 'dkim': 'fail', 'dmarc': 'fail'}

# (name, findings, expected_score, expected_level)
CASES = [
    ('internal mail, all pass', findings(), 0.00, 'benign'),
    ('newsletter with odd X-Mailer', findings(headers=['suspicious_mailer']), 0.05, 'benign'),
    # THE false-positive guard: forwarding breaks SPF.
    ('FORWARDED legit mail, spf fail only',
     findings(auth={'spf': 'fail', 'dkim': 'pass', 'dmarc': 'pass'}), 0.20, 'benign'),
    ('spf softfail counts as spf_fail',
     findings(auth={'spf': 'softfail', 'dkim': 'pass', 'dmarc': 'pass'}), 0.20, 'benign'),
    ('spf and dkim both fail',
     findings(auth={'spf': 'fail', 'dkim': 'fail', 'dmarc': 'pass'}), 0.35, 'suspicious'),
    ('dmarc fail alone',
     findings(auth={'spf': 'pass', 'dkim': 'pass', 'dmarc': 'fail'}), 0.35, 'suspicious'),
    ('lone executable attachment', findings(attachments=[EXE]), 0.30, 'suspicious'),
    ('lone archive attachment', findings(attachments=[ZIP]), 0.10, 'benign'),
    ('url display mismatch alone', findings(urls=[MISMATCH_URL]), 0.25, 'benign'),
    ('BEC: impersonation + reply-to mismatch',
     findings(spoofing=['display_name_impersonation', 'reply_to_mismatch']), 0.75, 'malicious'),
    ('brand phish: impersonation + url mismatch + dmarc fail',
     findings(auth=FAIL_ALL, spoofing=['display_name_impersonation'], urls=[MISMATCH_URL]),
     1.00, 'malicious'),
    ('known-malware DOCUMENT attachment, no other signal',
     findings(attachments=[DOC], hashes={'b' * 64: {'summary': {'is_malicious': True}}}),
     0.75, 'malicious'),
    ('known-malware EXECUTABLE attachment',
     findings(attachments=[EXE], hashes={'a' * 64: {'summary': {'is_malicious': True}}}),
     1.00, 'malicious'),
    ('clean hash lookup adds nothing',
     findings(attachments=[DOC], hashes={'b' * 64: {'summary': {'is_malicious': False}}}),
     0.00, 'benign'),
    ('dnsbl listed', findings(dnsbl={'listed': True, 'providers': ['zen']}), 0.30, 'suspicious'),
    ('dnsbl clean adds nothing', findings(dnsbl={'listed': False, 'providers': []}), 0.00, 'benign'),
    ('young sender domain alone', findings(sender_whois=recent_date(3)), 0.20, 'benign'),
    ('old sender domain is not young', findings(sender_whois='2001-01-01'), 0.00, 'benign'),
    ('exe from a young domain',
     findings(attachments=[EXE], sender_whois=recent_date(3)), 0.70, 'suspicious'),
    # A future WHOIS creation date is a broken record, not a fresh registration.
    ('future create_date is not a young domain',
     findings(sender_whois=future_date(400)), 0.00, 'benign'),
    ('unparseable message', findings(parsed_ok=False), 0.00, 'unknown'),
]

# Built from the REAL email_parse functions, not a hand-written findings dict: the
# point is that the parse layer and the rule engine agree. Lists rewrite
# Return-Path, point Reply-To at the list, and break the original SPF - without the
# list-mail suppression this scores 0.20 + 0.10 + 0.20 = 0.50.
LIST_MAIL = (
    b'Return-Path: <devs-bounces+bob=corp.test@lists.python.org>\r\n'
    b'From: Alice Developer <alice@example.com>\r\n'
    b'Reply-To: devs@lists.python.org\r\n'
    b'To: devs@lists.python.org\r\n'
    b'Subject: Re: [devs] patch review\r\n'
    b'Date: Mon, 27 Jul 2026 10:00:00 +0000\r\n'
    b'Message-ID: <20260727100000.abc@example.com>\r\n'
    b'MIME-Version: 1.0\r\n'
    b'List-Id: Dev discussion <devs.lists.python.org>\r\n'
    b'List-Unsubscribe: <https://lists.python.org/options/devs>\r\n'
    b'Precedence: list\r\n'
    b'Authentication-Results: mx.corp.test; spf=fail smtp.mailfrom=example.com; '
    b'dkim=pass header.d=lists.python.org; dmarc=pass header.from=example.com\r\n'
    b'Content-Type: text/plain; charset="utf-8"\r\n'
    b'\r\n'
    b'Looks good to me, see https://lists.python.org/archives/thread/abc\r\n'
)


def list_mail_findings():
    from app.utils.email_parse import (attachment_metadata, check_spoofing,
                                       extract_urls, find_suspicious_headers,
                                       parse_auth_results, parse_message)
    m = parse_message(LIST_MAIL)
    return {
        'parsed_ok': True,
        'authentication': parse_auth_results(m),
        'spoofing': check_spoofing(m),
        'suspicious_headers': find_suspicious_headers(m),
        'urls': extract_urls(m),
        'attachments': attachment_metadata(m),
        'enrichment': {'sender_domain': None, 'ips': {}, 'hashes': {}, 'dnsbl': None},
    }


def main():
    failures = []

    for name, data, expected_score, expected_level in CASES:
        result = score(data)
        if abs(result['score'] - expected_score) > 1e-9:
            failures.append(f'{name}: score {result["score"]}, expected {expected_score}'
                            f' (signals {result["signals"]})')
        if result['level'] != expected_level:
            failures.append(f'{name}: level {result["level"]!r}, expected {expected_level!r}'
                            f' (score {result["score"]}, signals {result["signals"]})')
        if not 0.0 <= result['score'] <= 1.0:
            failures.append(f'{name}: score {result["score"]} out of range')

    # The property the URL scanner's engine lacks: no combination of ambient header
    # quirks may produce a verdict on its own.
    ambient_only = score(findings(headers=AMBIENT))
    ceiling = sum(WEIGHTS[s] for s in AMBIENT)
    if ambient_only['level'] != 'benign':
        failures.append(f'all four ambient signals -> {ambient_only["level"]!r}, must be benign')
    if ceiling >= SUSPICIOUS_THRESHOLD:
        failures.append(f'ambient ceiling {ceiling} must stay below '
                        f'SUSPICIOUS_THRESHOLD {SUSPICIOUS_THRESHOLD}')

    # A known-malware hit must reach malicious with no help from other signals.
    if WEIGHTS['attachment_known_malware'] < MALICIOUS_THRESHOLD:
        failures.append('attachment_known_malware must alone reach MALICIOUS_THRESHOLD')

    list_result = score(list_mail_findings())
    if list_result['level'] != 'benign':
        failures.append(f'realistic mailing-list mail -> {list_result!r}, must be benign')
    if 'reply_to_mismatch' in list_result['signals'] or \
            'return_path_mismatch' in list_result['signals']:
        failures.append(f'list mail must not score the rewritten Reply-To/Return-Path: '
                        f'{list_result["signals"]}')

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f"PASS: {len(CASES)} scoring cases + 5 invariants")


if __name__ == '__main__':
    main()
