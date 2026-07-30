"""Pins app/utils/email_parse.py - pure e-mail parsing and detection.

No network, no server, no fixture files: every case is an inline message string.
"""
import os
import sys
import time
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.utils.email_parse import (
    MAX_ATTACHMENTS,
    MAX_RECEIVED_HOPS,
    EmailParseError,
    attachment_metadata,
    check_spoofing,
    extract_urls,
    find_suspicious_headers,
    header_summary,
    is_list_mail,
    parse_auth_results,
    parse_message,
    public_ips_from_received,
    received_chain,
    sender_domain,
)


def msg(headers, body='Hello.\n'):
    """Build a raw message from a dict-ish list of (name, value) pairs."""
    head = '\r\n'.join(f'{k}: {v}' for k, v in headers)
    return (head + '\r\n\r\n' + body).encode('utf-8')


BENIGN = [
    ('From', 'Alice <alice@example.com>'),
    ('To', 'bob@corp.test'),
    ('Subject', 'Quarterly numbers'),
    ('Date', 'Mon, 27 Jul 2026 10:00:00 +0000'),
    ('Message-ID', '<abc@example.com>'),
    ('MIME-Version', '1.0'),
    ('Authentication-Results', 'mx.corp.test; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com'),
]

# (name, headers, expected_auth_dict)
AUTH_CASES = [
    ('all pass', BENIGN, {'spf': 'pass', 'dkim': 'pass', 'dmarc': 'pass'}),
    ('dmarc fail', BENIGN[:-1] + [
        ('Authentication-Results', 'mx; spf=fail smtp.mailfrom=x.test; dkim=fail; dmarc=fail')],
     {'spf': 'fail', 'dkim': 'fail', 'dmarc': 'fail'}),
    ('softfail', BENIGN[:-1] + [('Authentication-Results', 'mx; spf=softfail')],
     {'spf': 'softfail', 'dkim': None, 'dmarc': None}),
    ('no auth headers at all', BENIGN[:-1], {'spf': None, 'dkim': None, 'dmarc': None}),
    ('Received-SPF fallback only', BENIGN[:-1] + [('Received-SPF', 'fail (domain of x.test does not designate)')],
     {'spf': 'fail', 'dkim': None, 'dmarc': None}),
]

# (name, headers, expected_spoofing_signals_as_set)
SPOOF_CASES = [
    ('clean', BENIGN, set()),
    ('reply-to on a different domain', BENIGN + [('Reply-To', 'attacker@evil.test')],
     {'reply_to_mismatch'}),
    ('reply-to same registrable domain is fine', BENIGN + [('Reply-To', 'alice@mail.example.com')],
     set()),
    ('return-path mismatch', BENIGN + [('Return-Path', '<bounce@evil.test>')],
     {'return_path_mismatch'}),
    ('display name claims another domain',
     [('From', '"paypal.com Security" <noreply@evil.test>')] + BENIGN[1:],
     {'display_name_impersonation'}),
    ('display name claims a brand',
     [('From', 'Microsoft Account Team <no-reply@evil.test>')] + BENIGN[1:],
     {'display_name_impersonation'}),
    ('brand in display name AND in domain is fine',
     [('From', 'Microsoft Account <no-reply@microsoft.com>')] + BENIGN[1:],
     set()),
    # The shipped brand check was a bare substring match: 'chase' hit 'purchase'.
    ('substring is not a brand match: purchase',
     [('From', 'Your purchase receipt <sales@shop.test>')] + BENIGN[1:],
     set()),
    ('substring is not a brand match: applesauce',
     [('From', 'Applesauce Weekly <news@food.test>')] + BENIGN[1:],
     set()),
    ('BEC: brand display name plus reply-to elsewhere',
     [('From', 'DocuSign <dse@evil.test>'), ('Reply-To', 'cfo@other.test')] + BENIGN[1:],
     {'display_name_impersonation', 'reply_to_mismatch'}),
    # Lists and ESPs legitimately rewrite Return-Path to their bounce domain and
    # point Reply-To at the list, so both must be suppressed on list mail.
    ('mailing list: List-Id suppresses reply-to and return-path mismatch',
     [('From', 'Alice <alice@example.com>'),
      ('Reply-To', 'devs@lists.other.test'),
      ('Return-Path', '<bounce-1234@lists.other.test>'),
      ('List-Id', 'Dev list <devs.lists.other.test>'),
      ('List-Unsubscribe', '<https://lists.other.test/unsub>')] + BENIGN[1:],
     set()),
    ('bulk mail: Precedence: bulk suppresses the same two',
     [('From', 'Store <news@shop.test>'),
      ('Return-Path', '<bounce@esp.test>'),
      ('Precedence', 'bulk')] + BENIGN[1:],
     set()),
    ('list headers do NOT excuse display-name impersonation',
     [('From', 'Microsoft Account Team <no-reply@evil.test>'),
      ('Return-Path', '<bounce@evil-esp.test>'),
      ('List-Id', '<promo.evil.test>')] + BENIGN[1:],
     {'display_name_impersonation'}),
]

NOW = datetime(2026, 7, 29, 12, 0, 0, tzinfo=timezone.utc)

# (name, headers, expected_suspicious_header_signals_as_set)
HEADER_CASES = [
    ('clean', BENIGN, set()),
    ('missing message-id', [h for h in BENIGN if h[0] != 'Message-ID'], {'missing_message_id'}),
    ('missing mime-version', [h for h in BENIGN if h[0] != 'MIME-Version'], {'missing_mime_version'}),
    ('suspicious mailer', BENIGN + [('X-Mailer', 'PHPMailer 5.2')], {'suspicious_mailer'}),
    ('date far in the future',
     [h for h in BENIGN if h[0] != 'Date'] + [('Date', 'Mon, 10 Aug 2026 10:00:00 +0000')],
     {'date_anomaly'}),
    ('date far in the past',
     [h for h in BENIGN if h[0] != 'Date'] + [('Date', 'Mon, 01 Jan 2020 10:00:00 +0000')],
     {'date_anomaly'}),
    ('unparseable date is not an anomaly',
     [h for h in BENIGN if h[0] != 'Date'] + [('Date', 'not a date')], set()),
]

SENDER_DOMAIN_CASES = [
    (BENIGN, 'example.com'),
    ([('From', 'x <a@mail.corp.example.co.uk>')] + BENIGN[1:], 'example.co.uk'),
    ([('From', 'garbage-with-no-address')] + BENIGN[1:], None),
]


MULTIPART = (
    b'From: Alice <alice@example.com>\r\n'
    b'Subject: Invoice\r\n'
    b'MIME-Version: 1.0\r\n'
    b'Content-Type: multipart/mixed; boundary="BOUND"\r\n'
    b'\r\n'
    b'--BOUND\r\n'
    b'Content-Type: text/html; charset="utf-8"\r\n'
    b'\r\n'
    b'<p>Click <a href="https://evil.test/login">paypal.com</a> now,'
    b' or visit https://plain.test/x</p>\r\n'
    b'--BOUND\r\n'
    b'Content-Type: application/octet-stream\r\n'
    b'Content-Disposition: attachment; filename="invoice.exe"\r\n'
    b'Content-Transfer-Encoding: base64\r\n'
    b'\r\n'
    b'TVqQAAMAAAAEAAAA\r\n'
    b'--BOUND\r\n'
    b'Content-Type: application/zip\r\n'
    b'Content-Disposition: attachment; filename="docs.zip"\r\n'
    b'Content-Transfer-Encoding: base64\r\n'
    b'\r\n'
    b'UEsDBAoAAAAAAA==\r\n'
    b'--BOUND--\r\n'
)

# The "global" hop must be a genuinely public address. RFC 5737 TEST-NET ranges
# (203.0.113.0/24 etc.) are non-global to ipaddress.is_global, so using one here
# would make this case unsatisfiable rather than testing anything.
RECEIVED = msg([
    ('Received', 'from relay.corp.test (relay.corp.test [10.0.0.9]) by mx.corp.test; '
                 'Mon, 27 Jul 2026 10:00:02 +0000'),
    ('Received', 'from sender.evil.test (sender.evil.test [93.184.216.34]) by relay.corp.test; '
                 'Mon, 27 Jul 2026 10:00:01 +0000'),
    ('From', 'a@example.com'),
    ('Subject', 'x'),
])


def check_content(failures):
    m = parse_message(MULTIPART)

    urls = extract_urls(m)
    by_url = {u['url']: u for u in urls}
    if 'https://evil.test/login' not in by_url:
        failures.append(f'extract_urls missed the href; got {sorted(by_url)}')
    elif not by_url['https://evil.test/login']['display_mismatch']:
        failures.append('anchor text "paypal.com" over href evil.test must be a display_mismatch')
    if 'https://plain.test/x' not in by_url:
        failures.append('extract_urls missed the plaintext URL')
    elif by_url['https://plain.test/x']['display_mismatch']:
        failures.append('a URL with no anchor text must not be a display_mismatch')

    atts = {a['filename']: a for a in attachment_metadata(m)}
    if set(atts) != {'invoice.exe', 'docs.zip'}:
        failures.append(f'attachment_metadata -> {sorted(atts)}, expected invoice.exe + docs.zip')
        return
    exe = atts['invoice.exe']
    if exe['magic_type'] != 'PE':
        failures.append(f"invoice.exe magic_type {exe['magic_type']!r}, expected 'PE'")
    if not exe['is_executable']:
        failures.append('invoice.exe must be is_executable')
    if len(exe['sha256']) != 64 or len(exe['md5']) != 32:
        failures.append('attachment digests must be 64-hex sha256 and 32-hex md5')
    if 'payload' in exe or 'bytes' in exe or 'content' in exe:
        failures.append('attachment_metadata must never return raw bytes')
    zipatt = atts['docs.zip']
    if not zipatt['is_archive'] or zipatt['is_executable']:
        failures.append('docs.zip must be is_archive and not is_executable')

    chain = received_chain(parse_message(RECEIVED))
    if len(chain) != 2:
        failures.append(f'received_chain -> {len(chain)} hops, expected 2')
    elif chain[0]['ip'] != '93.184.216.34':
        failures.append(f"received_chain must be oldest-first; hop0 ip {chain[0]['ip']!r}")
    ips = public_ips_from_received(parse_message(RECEIVED))
    if ips != ['93.184.216.34']:
        failures.append(f'public_ips_from_received -> {ips}, expected only the global address')


def html_msg(body):
    return (b'From: a@example.com\r\nSubject: x\r\nMIME-Version: 1.0\r\n'
            b'Content-Type: text/html; charset="utf-8"\r\n\r\n' + body.encode('utf-8'))


def received_msg(*values):
    head = ''.join(f'Received: {v}\r\n' for v in values)
    return (head + 'From: a@example.com\r\nSubject: x\r\n\r\nhi\r\n').encode('utf-8')


def check_url_extraction(failures):
    """Anchor extraction must be linear and must not need a closing </a>.

    The regex this replaced returned ZERO urls on unclosed anchors and grew ~4-8x
    per doubling, so a ~86 KB body meant minutes of GIL-held CPU on an
    unauthenticated route. Truncated phishing HTML routinely ends mid-anchor.
    """
    unclosed = ('<a href="https://evil.test/login">paypal.com verify\n'
                '<a href="https://evil2.test/x">click here\n')
    urls = extract_urls(parse_message(html_msg(unclosed)))
    by_url = {u['url']: u for u in urls}
    if 'https://evil.test/login' not in by_url or 'https://evil2.test/x' not in by_url:
        failures.append(f'unclosed anchors must still yield both hrefs; got {sorted(by_url)}')
    elif not by_url['https://evil.test/login']['display_mismatch']:
        failures.append('display_mismatch must still fire on an unclosed anchor')

    nested = '<a href="https://evil.test/x"><b>secure</b> <span>paypal.com</span></a>'
    nested_urls = extract_urls(parse_message(html_msg(nested)))
    if not nested_urls or not nested_urls[0]['display_mismatch']:
        failures.append(f'nested anchor markup broke extraction: {nested_urls}')

    variants = ('<A HREF=\'https://a.test/1\'>one</A>'
                '<a href=https://b.test/2 target=_blank>two</a>'
                '<a href="https://c.test/3"/>')
    got = {u['url'] for u in extract_urls(parse_message(html_msg(variants)))}
    if not {'https://a.test/1', 'https://b.test/2', 'https://c.test/3'} <= got:
        failures.append(f'href variants missed: {sorted(got)}')

    long_text = '<a href="https://evil.test/x">' + ('paypal.com ' * 60) + '</a>'
    long_urls = extract_urls(parse_message(html_msg(long_text)))
    if not long_urls or len(long_urls[0]['anchor_text']) != 200:
        failures.append('anchor_text must be truncated to exactly 200 chars')
    many = ''.join(f'<a href="https://e{i}.test/x">t\n' for i in range(400))
    if len(extract_urls(parse_message(html_msg(many)))) != 200:
        failures.append('the 200-URL cap must still hold')

    # Scaling: 100 KB of unclosed anchors must be fast, not minutes.
    unit = '<a href="https://evil.test/login?tok=aaaaaaaaaaaaaaaaaaaa">paypal.com verify\n'
    big = (unit * (100_000 // len(unit) + 1))[:100_000]
    start = time.perf_counter()
    extract_urls(parse_message(html_msg(big)))
    elapsed = time.perf_counter() - start
    if elapsed > 1.0:
        failures.append(f'100 KB of unclosed anchors took {elapsed:.3f}s; extraction is not linear')


def check_tag_regex_scaling(failures):
    """`_TAG_RE` must stay linear on a body of unclosed tags - no `>` anywhere.

    An unbounded `[^>]+` re-scans to end-of-input from every `<`, which is O(n^2):
    3.14s at 540,000 chars and 12.62s at 1,080,000, vs. ~2x growth for the bounded
    `{0,4096}` version. Guards that bound against being "simplified" back away.
    """
    body = '<a href="https://x.test/a" ' * 20000  # 540,000 chars, no '>' anywhere
    start = time.perf_counter()
    extract_urls(parse_message(html_msg(body)))
    elapsed = time.perf_counter() - start
    if elapsed > 2.0:
        failures.append(f'540 KB of unclosed tags took {elapsed:.3f}s; _TAG_RE is not linear')


def check_received(failures):
    """IPv6 hops, from-clause anchoring, per-header failure isolation, caps."""
    # With and without Postfix's RFC 5321 `IPv6:` prefix. Gmail/M365 inbound is
    # routinely IPv6, so IPv4-only matching left sender_ip_blacklisted unreachable.
    v6 = received_msg(
        'from relay.corp.test (relay.corp.test [10.0.0.9]) by mbox.corp.test; '
        'Mon, 27 Jul 2026 10:00:02 +0000',
        'from mail.google.com (mail.google.com [IPv6:2607:f8b0:4864:20::22f]) '
        'by mx.corp.test; Mon, 27 Jul 2026 10:00:01 +0000',
    )
    if public_ips_from_received(parse_message(v6)) != ['2607:f8b0:4864:20::22f']:
        failures.append('an IPv6-only sender hop must produce a public IP, '
                        f'got {public_ips_from_received(parse_message(v6))}')
    plain_v6 = received_msg('from x.test (x.test [2001:4860:4860::8888]) by mx.test; '
                            'Mon, 27 Jul 2026 10:00:01 +0000')
    if public_ips_from_received(parse_message(plain_v6)) != ['2001:4860:4860::8888']:
        failures.append('a bracketed IPv6 literal without the IPv6: prefix must be found')
    private_v6 = received_msg('from x.test (x.test [fd00::1]) by mx.test; '
                              'Mon, 27 Jul 2026 10:00:01 +0000')
    if public_ips_from_received(parse_message(private_v6)) != []:
        failures.append('a non-global IPv6 hop must never reach enrichment')

    # The `by` clause must not win over the `from` clause.
    mixed = received_msg('by 10.0.0.5 with SMTP id abc from relay.evil.test (93.184.216.34); '
                         'Mon, 27 Jul 2026 10:00:01 +0000')
    hop_ip = received_chain(parse_message(mixed))[0]['ip']
    if hop_ip != '93.184.216.34':
        failures.append(f'hop ip {hop_ip!r} came from the `by` clause; want the `from` address')

    # One unreadable header degrades that hop only, not the whole chain.
    class BadHeader:
        def __str__(self):
            raise ValueError('hostile header')

    good = parse_message(received_msg('from a.test (a.test [93.184.216.34]) by mx.test; '
                                      'Mon, 27 Jul 2026 10:00:01 +0000'))

    class OneBadHeader:
        def get_all(self, name):
            return [BadHeader(), *good.get_all('Received')]

    salvaged = received_chain(OneBadHeader())
    if len(salvaged) != 1 or salvaged[0]['ip'] != '93.184.216.34':
        failures.append(f'one malformed Received header discarded the chain: {salvaged}')

    # Caps: uncapped, 20k hops produced 2.3 MB of persisted JSON.
    hop = 'from h{}.test (h{}.test [93.184.216.34]) by mx.test; Mon, 27 Jul 2026 10:00:01 +0000'
    flood = received_msg(*[hop.format(i, i) for i in range(MAX_RECEIVED_HOPS * 4)])
    capped = received_chain(parse_message(flood))
    if len(capped) != MAX_RECEIVED_HOPS:
        failures.append(f'received_chain returned {len(capped)} hops, cap is {MAX_RECEIVED_HOPS}')
    elif capped[0]['from_host'] != f'h{MAX_RECEIVED_HOPS * 4 - 1}.test':
        failures.append('the cap must keep the OLDEST hops (closest to the originator)')

    part = (b'--B\r\nContent-Type: application/octet-stream\r\n'
            b'Content-Disposition: attachment; filename="f%d.bin"\r\n'
            b'Content-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAAE\r\n')
    flood_atts = (b'From: a@example.com\r\nSubject: x\r\nMIME-Version: 1.0\r\n'
                  b'Content-Type: multipart/mixed; boundary="B"\r\n\r\n'
                  + b''.join(part % i for i in range(MAX_ATTACHMENTS * 4))
                  + b'--B--\r\n')
    capped_atts = attachment_metadata(parse_message(flood_atts))
    if len(capped_atts) != MAX_ATTACHMENTS:
        failures.append(f'attachment_metadata returned {len(capped_atts)}, cap is {MAX_ATTACHMENTS}')


def main():
    failures = []

    for name, headers, expected in AUTH_CASES:
        got = parse_auth_results(parse_message(msg(headers)))
        if got != expected:
            failures.append(f'auth[{name}] -> {got!r}, expected {expected!r}')

    for name, headers, expected in SPOOF_CASES:
        got = set(check_spoofing(parse_message(msg(headers))))
        if got != expected:
            failures.append(f'spoof[{name}] -> {sorted(got)}, expected {sorted(expected)}')

    for name, headers, expected in HEADER_CASES:
        got = set(find_suspicious_headers(parse_message(msg(headers)), now=NOW))
        if got != expected:
            failures.append(f'headers[{name}] -> {sorted(got)}, expected {sorted(expected)}')

    for headers, expected in SENDER_DOMAIN_CASES:
        got = sender_domain(parse_message(msg(headers)))
        if got != expected:
            failures.append(f'sender_domain -> {got!r}, expected {expected!r}')

    # parse_message must reject what it truly cannot parse, and only that.
    for bad in (b'', b'   ', b'\r\n\r\n'):
        try:
            parse_message(bad)
            failures.append(f'parse_message({bad!r}) should have raised EmailParseError')
        except EmailParseError:
            pass
        except Exception as exc:
            failures.append(f'parse_message({bad!r}) raised {type(exc).__name__}, want EmailParseError')

    # A message with headers but no body is valid, not an error.
    try:
        parse_message(b'From: a@b.test\r\nSubject: x\r\n\r\n')
    except Exception as exc:
        failures.append(f'headers-only message should parse, raised {type(exc).__name__}')

    # header_summary must expose exactly the spec's allowlisted keys.
    expected_keys = {'from', 'from_display', 'to', 'subject', 'date', 'message_id',
                     'reply_to', 'return_path', 'x_mailer'}
    got_keys = set(header_summary(parse_message(msg(BENIGN))).keys())
    if got_keys != expected_keys:
        failures.append(f'header_summary keys {sorted(got_keys)}, expected {sorted(expected_keys)}')

    # is_list_mail must key off the list/bulk markers and nothing else.
    for headers, expected in (
        (BENIGN, False),
        (BENIGN + [('List-Id', '<a.b.test>')], True),
        (BENIGN + [('List-Unsubscribe', '<https://b.test/u>')], True),
        (BENIGN + [('Precedence', 'list')], True),
        (BENIGN + [('Precedence', 'Bulk')], True),
        (BENIGN + [('Precedence', 'urgent')], False),
    ):
        got = is_list_mail(parse_message(msg(headers)))
        if got != expected:
            failures.append(f'is_list_mail({headers[-1]!r}) -> {got}, expected {expected}')

    check_content(failures)
    check_url_extraction(failures)
    check_tag_regex_scaling(failures)
    check_received(failures)

    total = len(AUTH_CASES) + len(SPOOF_CASES) + len(HEADER_CASES) + len(SENDER_DOMAIN_CASES)
    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {total} header-level cases + 6 list-mail + 5 parse/summary '
          f'+ 11 content + 6 url-extraction + 1 tag-regex-scaling + 7 received cases')


if __name__ == '__main__':
    main()
