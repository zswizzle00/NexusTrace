"""Pure e-mail parsing and detection. stdlib only, no network, no I/O.

Two deliberate choices: **header access never raises** (``policy.default`` builds header
objects that raise on malformed input, and hostile mail is malformed on purpose, so all
reads go through :func:`header`), and **brand matching is word-boundary anchored**, so
``'chase' in 'purchase'`` cannot make an ordinary sender look like phishing.
"""

import ipaddress
import logging
import re
from datetime import datetime, timedelta, timezone
from email import message_from_bytes, policy
from email.utils import parseaddr, parsedate_to_datetime
from html.parser import HTMLParser

from .file_inspect import file_digests, is_archive, is_executable, sniff_magic
from .validators import registrable_domain

logger = logging.getLogger(__name__)

# A Date this far ahead of now, or this far behind, is anomalous.
DATE_FUTURE_TOLERANCE = timedelta(hours=24)
DATE_STALE_TOLERANCE = timedelta(days=180)

# A hostile message must not bloat the persisted record (20,000 Received headers produced
# 2.3 MB of JSON) or the unpaginated tables that render it. The chain is oldest-first, so
# keeping the first N keeps the hops closest to the originator.
MAX_RECEIVED_HOPS = 50
MAX_ATTACHMENTS = 25

# Defence in depth: extraction is linear (see :class:`_AnchorCollector`), but there is
# no analytic value in the tail of a multi-megabyte body and the route is unauthenticated.
MAX_URL_SCAN_CHARS = 1024 * 1024

_AUTH_RE = re.compile(
    r'\b(spf|dkim|dmarc)\s*=\s*'
    r'(pass|fail|softfail|neutral|none|temperror|permerror)\b',
    re.I,
)
_SPF_VERDICT_RE = re.compile(
    r'\b(pass|fail|softfail|neutral|none|temperror|permerror)\b', re.I
)

# Mailers that legitimate bulk senders essentially never use.
_SUSPICIOUS_MAILERS = ('phpmailer', 'the bat', 'libwww-perl', 'mass mailer', 'bulk mailer')

# Conservative brand list. The point is a cheap prior, not coverage.
_BRAND_TOKENS = (
    'microsoft', 'office365', 'outlook', 'apple', 'icloud', 'google', 'paypal',
    'amazon', 'netflix', 'facebook', 'instagram', 'linkedin', 'chase',
    'wellsfargo', 'bankofamerica', 'docusign', 'adobe', 'coinbase', 'dropbox',
    'dhl', 'fedex', 'ups', 'irs', 'hmrc',
)
_BRAND_RES = tuple(
    (token, re.compile(rf'\b{re.escape(token)}\b', re.I)) for token in _BRAND_TOKENS
)

# A hostname-looking token, used to spot a display name claiming a domain.
_DOMAINISH_RE = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b', re.I
)


class EmailParseError(ValueError):
    """The bytes could not be parsed as an e-mail message at all."""


def parse_message(raw):
    """Parse raw message bytes. Raises :class:`EmailParseError` only when nothing
    usable can be recovered; a message with headers and no body is valid."""
    if isinstance(raw, str):
        raw = raw.encode('utf-8', 'replace')
    if not raw or not raw.strip():
        raise EmailParseError('empty message')
    try:
        msg = message_from_bytes(raw, policy=policy.default)
    except Exception as exc:
        raise EmailParseError(f'could not parse message: {exc}') from exc
    try:
        has_headers = bool(msg.keys())
    except Exception:
        has_headers = False
    if not has_headers:
        raise EmailParseError('message has no headers')
    return msg


def header(msg, name, default=None):
    """Read a header as a plain string. Never raises, whatever the input."""
    try:
        value = msg.get(name)
    except Exception:
        return default
    if value is None:
        return default
    try:
        return str(value)
    except Exception:
        return default


def _addr(header_value):
    """The bare address from a header value ('A B <a@b.test>' -> 'a@b.test')."""
    if not header_value:
        return ''
    try:
        return (parseaddr(header_value)[1] or '').strip().lower()
    except Exception:
        return ''


def _display(header_value):
    if not header_value:
        return ''
    try:
        return (parseaddr(header_value)[0] or '').strip()
    except Exception:
        return ''


def _domain_of(addr):
    return addr.rsplit('@', 1)[-1].strip().lower() if '@' in (addr or '') else ''


def sender_domain(msg):
    domain = registrable_domain(_domain_of(_addr(header(msg, 'From'))))
    return domain or None


def header_summary(msg):
    """Exactly the header subset that may be persisted."""
    from_raw = header(msg, 'From')
    return {
        'from': _addr(from_raw) or None,
        'from_display': _display(from_raw) or None,
        'to': header(msg, 'To'),
        'subject': header(msg, 'Subject'),
        'date': header(msg, 'Date'),
        'message_id': header(msg, 'Message-ID'),
        'reply_to': _addr(header(msg, 'Reply-To')) or None,
        'return_path': _addr(header(msg, 'Return-Path')) or None,
        'x_mailer': header(msg, 'X-Mailer'),
    }


def parse_auth_results(msg):
    """SPF/DKIM/DMARC verdicts from Authentication-Results, falling back to
    Received-SPF for SPF alone. Values are the raw verdict tokens or None."""
    result = {'spf': None, 'dkim': None, 'dmarc': None}
    blob = ' '.join(
        part for part in (
            header(msg, 'Authentication-Results'),
            header(msg, 'ARC-Authentication-Results'),
        ) if part
    )
    for mechanism, verdict in _AUTH_RE.findall(blob):
        key = mechanism.lower()
        if result.get(key) is None:
            result[key] = verdict.lower()
    if result['spf'] is None:
        received_spf = header(msg, 'Received-SPF')
        if received_spf:
            match = _SPF_VERDICT_RE.search(received_spf)
            if match:
                result['spf'] = match.group(1).lower()
    return result


def _display_name_impersonates(display, from_domain):
    """True when a display name claims an identity the From domain contradicts: it spells
    out a domain that is not the sender's, or names a well-known brand absent from the
    sender's domain (word-boundary anchored, so 'purchase' is not a 'chase' hit)."""
    if not display or not from_domain:
        return False
    for match in _DOMAINISH_RE.finditer(display):
        claimed = registrable_domain(match.group(0))
        if claimed and claimed != from_domain:
            return True
    for token, pattern in _BRAND_RES:
        if pattern.search(display) and token not in from_domain:
            return True
    return False


# Headers that only mailing lists and bulk senders set. RFC 2919 / RFC 2369.
_LIST_HEADERS = ('List-Id', 'List-Unsubscribe', 'List-Post', 'List-Help')
_BULK_PRECEDENCE = frozenset({'list', 'bulk'})


def is_list_mail(msg):
    """A false-positive guard, not a detection: lists and ESPs rewrite ``Return-Path`` and
    point ``Reply-To`` at the list, so those "mismatches" are the normal shape on real list
    traffic. Without this suppression ordinary list mail scores 0.30-0.50 and lands in
    ``suspicious``."""
    for name in _LIST_HEADERS:
        if header(msg, name):
            return True
    return (header(msg, 'Precedence') or '').strip().lower() in _BULK_PRECEDENCE


def check_spoofing(msg):
    """``Reply-To`` / ``Return-Path`` mismatches are suppressed for list and bulk mail (see
    :func:`is_list_mail`); display-name impersonation is not, because a list does not
    explain a display name claiming someone else's brand."""
    signals = []
    from_raw = header(msg, 'From')
    from_domain = registrable_domain(_domain_of(_addr(from_raw)))
    list_mail = is_list_mail(msg)

    reply_to = _addr(header(msg, 'Reply-To'))
    if reply_to and from_domain and not list_mail:
        reply_domain = registrable_domain(_domain_of(reply_to))
        if reply_domain and reply_domain != from_domain:
            signals.append('reply_to_mismatch')

    return_path = _addr(header(msg, 'Return-Path'))
    if return_path and from_domain and not list_mail:
        return_domain = registrable_domain(_domain_of(return_path))
        if return_domain and return_domain != from_domain:
            signals.append('return_path_mismatch')

    if _display_name_impersonates(_display(from_raw), from_domain):
        signals.append('display_name_impersonation')

    return signals


def _date_anomalous(raw, now=None):
    if not raw:
        return False
    try:
        parsed = parsedate_to_datetime(raw)
    except Exception:
        return False
    if parsed is None:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    moment = now or datetime.now(timezone.utc)
    if parsed - moment > DATE_FUTURE_TOLERANCE:
        return True
    return moment - parsed > DATE_STALE_TOLERANCE


def find_suspicious_headers(msg, now=None):
    """Weak, ambient header quirks, weighted by the rule engine so no combination of them
    alone produces a verdict. ``now`` is injectable so tests never time-bomb."""
    signals = []
    if not header(msg, 'Message-ID'):
        signals.append('missing_message_id')
    if not header(msg, 'MIME-Version'):
        signals.append('missing_mime_version')
    mailer = (header(msg, 'X-Mailer') or '').lower()
    if any(bad in mailer for bad in _SUSPICIOUS_MAILERS):
        signals.append('suspicious_mailer')
    if _date_anomalous(header(msg, 'Date'), now=now):
        signals.append('date_anomaly')
    return signals


# Deliberately loose: every candidate is validated with :mod:`ipaddress`, which is the real
# filter. Both shapes occur in the wild - a bracketed literal (Postfix writes the RFC 5321
# `IPv6:` prefix) and a bare dotted quad in a parenthesised comment. Matching IPv4 only
# made `sender_ip_blacklisted` unreachable for Gmail / Microsoft 365 inbound mail, which is
# routinely delivered over IPv6.
_RECEIVED_ADDR_RE = re.compile(
    r'\[\s*(?:ipv6:)?([0-9A-Fa-f:.]{2,45})\s*\]'
    r'|\b((?:\d{1,3}\.){3}\d{1,3})\b',
    re.I,
)
_RECEIVED_FROM_RE = re.compile(r'\bfrom\s+([A-Za-z0-9._-]+)', re.I)
_RECEIVED_BY_RE = re.compile(r'\bby\s+([A-Za-z0-9._-]+)', re.I)
# The `from` clause, bounded by the next `by` token. Lazy, but with no nested
# quantifier, so it stays linear in the header length.
_RECEIVED_FROM_CLAUSE_RE = re.compile(r'\bfrom\s+(.*?)(?=\bby\b|$)', re.I | re.S)


def _first_address(text):
    """The first syntactically valid IP literal in ``text``, normalized, or None."""
    for match in _RECEIVED_ADDR_RE.finditer(text or ''):
        candidate = (match.group(1) or match.group(2) or '').strip()
        if not candidate:
            continue
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
    return None


def _hop_address(collapsed):
    """The originating address of a hop, preferring the ``from`` clause: the first literal
    anywhere in the header mis-attributes hops, so ``by 10.0.0.5 ... from relay.test
    (203.0.113.9)`` would credit the receiver. Falls back to a whole-header search."""
    from_clause = _RECEIVED_FROM_CLAUSE_RE.search(collapsed)
    if from_clause:
        found = _first_address(from_clause.group(1))
        if found:
            return found
    return _first_address(collapsed)


def received_chain(msg, limit=MAX_RECEIVED_HOPS):
    """Received hops, **oldest first**: index 0 is the hop that injected the message.
    Bounded by ``limit`` (oldest kept). A malformed header degrades that one hop, not the
    whole chain; losing every hop would silently take out IP enrichment, the DNSBL lookup,
    and ``sender_ip_blacklisted`` with it."""
    try:
        raw_values = list(msg.get_all('Received') or [])
    except Exception:
        return []
    hops = []
    skipped = 0
    for raw in reversed(raw_values):
        if len(hops) >= limit:
            break
        try:
            collapsed = ' '.join(str(raw).split())
        except Exception:
            skipped += 1
            continue
        from_match = _RECEIVED_FROM_RE.search(collapsed)
        by_match = _RECEIVED_BY_RE.search(collapsed)
        hops.append({
            'from_host': from_match.group(1) if from_match else None,
            'by_host': by_match.group(1) if by_match else None,
            'ip': _hop_address(collapsed),
            'timestamp': collapsed.rsplit(';', 1)[-1].strip() if ';' in collapsed else None,
        })
    if skipped:
        logger.debug('received_chain skipped %d unreadable Received header(s)', skipped)
    if len(raw_values) > limit:
        logger.warning(
            'received_chain truncated: %d Received headers present, keeping the oldest %d',
            len(raw_values), limit,
        )
    return hops


def public_ips_from_received(msg):
    """Globally-routable addresses (IPv4 **and** IPv6) from the Received chain, oldest
    first, deduped. Private and reserved addresses are internal relay hops, not the sender,
    and must never reach an external enrichment service."""
    found = []
    seen = set()
    for hop in received_chain(msg):
        candidate = hop.get('ip')
        if not candidate or candidate in seen:
            continue
        try:
            if not ipaddress.ip_address(candidate).is_global:
                continue
        except ValueError:
            continue
        seen.add(candidate)
        found.append(candidate)
    return found


_PLAIN_URL_RE = re.compile(r'https?://[^\s<>"\'()\[\]]+', re.I)
# Bounded deliberately: an unbounded `[^>]+` is quadratic on a body of unclosed
# tags (every `<` re-scans to end-of-input for a `>` that never comes). 4096 is
# far longer than any real HTML tag, so well-formed markup is unaffected.
_TAG_RE = re.compile(r'<[^>]{0,4096}>')
_URL_TRAILING = '.,;:!?)\'"]>'


class _AnchorCollector(HTMLParser):
    """**Replaces a regex on purpose; do not go back.** A ``(.*?)</a>`` pairing backtracks
    catastrophically on unclosed anchors (the normal shape of phishing HTML) - ~7.8x growth
    per input doubling, so an 86 KB body became minutes of GIL-held CPU on an
    unauthenticated route, stalling all gunicorn threads."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.pairs = []
        self._href = None
        self._text = []

    def _flush(self):
        if self._href is not None:
            self.pairs.append((self._href, ''.join(self._text)))
        self._href = None
        self._text = []

    def handle_starttag(self, tag, attrs):
        if tag == 'a':
            # A second <a> before the first closed ends it, as browsers pair them.
            self._flush()
            for name, value in attrs:
                if name == 'href' and value:
                    self._href = value
                    break
        elif self._href is not None:
            # A nested tag is a word break in the visible text, not a join.
            self._text.append(' ')

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag == 'a':
            self._flush()

    def handle_endtag(self, tag):
        if tag == 'a':
            self._flush()
        elif self._href is not None:
            self._text.append(' ')

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def collected(self):
        """Every pair found, **including** an anchor whose ``</a>`` never arrived."""
        self._flush()
        return self.pairs


def _anchor_pairs(html_text):
    """``(href, text)`` for each anchor in ``html_text``. Never raises: a parse error yields
    the pairs collected so far rather than losing the whole body."""
    collector = _AnchorCollector()
    try:
        collector.feed(html_text)
        collector.close()
    except Exception as exc:
        logger.debug('anchor extraction stopped early: %s', exc)
    try:
        return collector.collected()
    except Exception:
        return []


def _text_bodies(msg):
    """(subtype, text) for each non-attachment text part. Never touches attachments."""
    bodies = []
    try:
        parts = list(msg.walk()) if msg.is_multipart() else [msg]
    except Exception:
        return bodies
    for part in parts:
        try:
            if part.get_content_maintype() != 'text':
                continue
            if (part.get_content_disposition() or '') == 'attachment':
                continue
            content = part.get_content()
        except Exception:
            continue
        if isinstance(content, str):
            bodies.append((part.get_content_subtype(), content))
    return bodies


def _display_mismatch(url, anchor_text):
    """True when the anchor text names a registrable domain the href contradicts."""
    if not anchor_text:
        return False
    from urllib.parse import urlparse

    try:
        target = registrable_domain(urlparse(url).hostname or '')
    except ValueError:
        return False
    if not target:
        return False
    for match in _DOMAINISH_RE.finditer(anchor_text):
        claimed = registrable_domain(match.group(0))
        if claimed and claimed != target:
            return True
    return False


def extract_urls(msg, limit=200):
    """URLs from hrefs and plaintext, display-vs-target mismatch flagged. Returns **live**
    URLs; the caller defangs for storage and display."""
    results = []
    seen = set()

    def add(url, anchor_text):
        url = (url or '').strip().rstrip(_URL_TRAILING)
        if not url.lower().startswith(('http://', 'https://')):
            return
        if url in seen or len(results) >= limit:
            return
        seen.add(url)
        results.append({
            'url': url,
            'anchor_text': (anchor_text or '').strip()[:200] or None,
            'display_mismatch': _display_mismatch(url, anchor_text),
        })

    for subtype, body in _text_bodies(msg):
        if len(body) > MAX_URL_SCAN_CHARS:
            logger.warning(
                'URL extraction truncated a %s body: %d chars present, scanning %d',
                subtype, len(body), MAX_URL_SCAN_CHARS,
            )
            body = body[:MAX_URL_SCAN_CHARS]
        if subtype == 'html':
            for href, inner in _anchor_pairs(body):
                add(href, inner)
            stripped = _TAG_RE.sub(' ', body)
        else:
            stripped = body
        for match in _PLAIN_URL_RE.finditer(stripped):
            add(match.group(0), '')

    return results


def attachment_metadata(msg, limit=MAX_ATTACHMENTS):
    """Per-attachment metadata and digests. **Returns metadata only, never bytes**: each
    payload is hashed and goes out of scope immediately, so no code path can persist or
    serve attachment content."""
    results = []
    seen = 0
    try:
        parts = list(msg.walk()) if msg.is_multipart() else []
    except Exception:
        return results
    for part in parts:
        try:
            disposition = part.get_content_disposition() or ''
            filename = part.get_filename()
            if disposition != 'attachment' and not filename:
                continue
            seen += 1
            if len(results) >= limit:
                continue
            payload = part.get_payload(decode=True)
            content_type = part.get_content_type()
        except Exception:
            continue
        if payload is None:
            continue
        name = str(filename or '(unnamed)')[:255]
        magic = sniff_magic(payload)
        digests = file_digests(payload)
        results.append({
            'filename': name,
            'content_type': content_type or None,
            'size_bytes': len(payload),
            'md5': digests['md5'],
            'sha256': digests['sha256'],
            'magic_type': magic,
            'is_executable': is_executable(magic, name),
            'is_archive': is_archive(magic, name),
        })
    if seen > limit:
        logger.warning(
            'attachment_metadata truncated: %d attachment parts present, keeping %d',
            seen, limit,
        )
    return results
