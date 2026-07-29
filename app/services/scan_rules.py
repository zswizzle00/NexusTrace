"""Heuristic rule scoring for a completed URL scan. Pure; no network, no I/O.

Scoring is additive over the weight table below, clamped to [0, 1], then banded.
Combos ("a password form *on a young domain*") add on top of their constituents
because the combination is the tell, not either half alone.

**This is a structural prior, not a reputation verdict.** The scan path collects
no reputation data, so the two signals that would dominate a real verdict -
Google Web Risk and VirusTotal - are absent, and the bands are calibrated
accordingly. Present it to analysts as a heuristic. Adding OTX or VirusTotal to
the scan path is what would earn a stronger claim.

**Threshold calibration note.** ``SUSPICIOUS_THRESHOLD`` and
``MALICIOUS_THRESHOLD`` are anchored to the case table in
``app/tests/test_scan_rules.py``, not chosen independently of it:

* a single ``untrusted_tls`` (0.25) must clear the suspicious band while a lone
  ``password_form`` (0.15) must not, which pins ``SUSPICIOUS_THRESHOLD`` to
  (0.15, 0.25];
* a payload download on a young domain with a zero security-header score
  (0.30 + 0.20 + 0.20 combo + 0.10 = 0.80) must land in "suspicious", not
  "malicious", which pins ``MALICIOUS_THRESHOLD`` above 0.80.

``SUSPICIOUS_THRESHOLD`` is set at the *top* of its permitted range (0.25)
rather than the bottom. At the previous 0.20, the two weakest and most common
signals on the open web - a thin security-header score (0.10) and a freshly
minted (i.e. Let's Encrypt) certificate (0.10) - summed to exactly the floor,
so a large fraction of ordinary, harmless sites read as "suspicious". 0.25
requires either one genuinely notable signal (``untrusted_tls``) or a
combination that includes something stronger than "modern free TLS", while
still satisfying every mandated case. 0.25 / 0.85 satisfy the whole table; see
that file for the full derivation.
"""

import logging
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..utils.validators import registrable_domain

logger = logging.getLogger(__name__)

# Signal -> weight. Additive, clamped to [0, 1]. This order is also the order
# signals are reported in.
WEIGHTS = {
    'brand_domain_mismatch': 0.30,
    'payload_download': 0.30,
    'untrusted_tls': 0.25,
    'young_domain': 0.20,
    'password_form': 0.15,
    'cross_domain_redirect': 0.15,
    'fresh_cert': 0.10,
    'no_security_headers': 0.10,
    'many_third_party_domains': 0.05,
    # Combos: both constituents present. The combination is the signal.
    'brand_domain_mismatch+password_form': 0.30,
    'password_form+young_domain': 0.25,
    'payload_download+young_domain': 0.20,
}

MALICIOUS_THRESHOLD = 0.85
SUSPICIOUS_THRESHOLD = 0.25

# A domain registered within this window is "young".
YOUNG_DOMAIN_MAX_DAYS = 30
# A leaf cert minted within this window is "fresh".
FRESH_CERT_MAX_DAYS = 14
# Contacting at least this many distinct third-party domains is mildly notable.
MANY_DOMAINS_MIN = 25
# At or below this security-header score, the site has essentially none.
NO_HEADERS_MAX = 1

# Conservative brand list. The point is a cheap prior, not coverage.
_BRAND_TOKENS = (
    'microsoft', 'office365', 'outlook', 'apple', 'icloud', 'google', 'paypal',
    'amazon', 'netflix', 'facebook', 'instagram', 'linkedin', 'chase',
    'wellsfargo', 'bankofamerica', 'docusign', 'adobe', 'coinbase', 'dropbox',
)

# Word-boundary matchers for the tokens above, compiled once. A bare substring
# test is useless here: "chase" is in "purchase", "apple" is in "applesauce",
# and every page containing either read as suspicious.
_BRAND_TOKEN_PATTERNS = tuple(
    (token, re.compile(rf'\b{re.escape(token)}\b', re.IGNORECASE))
    for token in _BRAND_TOKENS
)

def _host_of(url):
    try:
        return (urlparse(url or '').hostname or '').lower()
    except ValueError:
        return ''


def _parse_date(value):
    """Parse the assorted date shapes WHOIS and OpenSSL hand us. None on failure."""
    if not value:
        return None
    text = str(value).strip()
    formats = (
        '%Y-%m-%d',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%d %H:%M:%S',
        '%b %d %H:%M:%S %Y %Z',   # OpenSSL notBefore
        '%b  %d %H:%M:%S %Y %Z',  # OpenSSL single-digit day
    )
    for fmt in formats:
        try:
            return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _age_days(value):
    parsed = _parse_date(value)
    if parsed is None:
        return None
    return (datetime.now(timezone.utc) - parsed).total_seconds() / 86400.0


def _brand_domain_mismatch(scan, has_password: bool) -> bool:
    """A well-known brand named on a *credential-soliciting* page whose token is
    absent from the page's *registrable* domain.

    Two deliberate constraints, both learned the hard way:

    1. **Word boundaries, not substrings.** ``'chase' in 'purchase'`` and
       ``'apple' in 'apple pie recipe'`` are both true, so a bare substring test
       scored "Complete your purchase today" as brand impersonation.
    2. **A brand mention alone is never a signal.** Naming a brand is what
       ordinary pages do all day; naming one next to a password box is the tell.
       Hence the ``has_password`` gate, with the heavy lifting left to the
       ``brand_domain_mismatch+password_form`` combo weight.

    Matching the *registrable* domain rather than the full host is what catches
    the target case: ``microsoft-login.verify-account.test`` hides "microsoft" in
    a subdomain label, while a legitimate ``login.microsoftonline.com`` keeps it
    in its registrable domain and is correctly not flagged.
    """
    if not has_password:
        return False
    page = scan.get('page') or {}
    host = _host_of(page.get('final_url') or scan.get('url'))
    domain = registrable_domain(host)
    haystack = f"{page.get('title') or ''} {scan.get('visible_text') or ''}"
    return any(
        pattern.search(haystack) and token not in domain
        for token, pattern in _BRAND_TOKEN_PATTERNS
    )


def _has_any_evidence(scan) -> bool:
    return bool(
        (scan.get('page') or {}).get('status')
        or scan.get('tls')
        or scan.get('dns')
        or scan.get('domains')
        or scan.get('payload')
    )


def score(scan: dict) -> dict:
    """Score a completed scan. Pure; no I/O.

    Returns ``{'level', 'score', 'signals'}``. ``level`` is ``unknown`` when the
    scan gathered no usable evidence - never a false ``benign``.
    """
    page = scan.get('page') or {}
    tls = scan.get('tls') or {}
    security = scan.get('security') or {}
    payload = scan.get('payload') or {}
    whois = scan.get('whois') or {}

    has_password = any(
        (form or {}).get('has_password') for form in (scan.get('forms') or [])
    )
    brand_mismatch = _brand_domain_mismatch(scan, has_password)

    domain_age = _age_days(whois.get('create_date') or whois.get('created'))
    young_domain = domain_age is not None and domain_age <= YOUNG_DOMAIN_MAX_DAYS

    cert_age = _age_days(tls.get('valid_from'))
    fresh_cert = cert_age is not None and cert_age <= FRESH_CERT_MAX_DAYS

    is_payload = bool(payload.get('is_payload'))

    origin = registrable_domain(_host_of(scan.get('url')))
    final = registrable_domain(_host_of(page.get('final_url')))
    cross_domain = bool(origin and final and origin != final)

    present = {
        'brand_domain_mismatch': brand_mismatch,
        'payload_download': is_payload,
        'untrusted_tls': tls.get('authorized') is False,
        'young_domain': young_domain,
        'password_form': has_password,
        'cross_domain_redirect': cross_domain,
        'fresh_cert': fresh_cert,
        'no_security_headers': bool(security) and security.get('score', 0) <= NO_HEADERS_MAX,
        'many_third_party_domains': len(scan.get('domains') or []) >= MANY_DOMAINS_MIN,
        'brand_domain_mismatch+password_form': brand_mismatch and has_password,
        'password_form+young_domain': has_password and young_domain,
        'payload_download+young_domain': is_payload and young_domain,
    }

    signals = [name for name in WEIGHTS if present[name]]
    total = min(sum(WEIGHTS[name] for name in signals), 1.0)

    if not _has_any_evidence(scan):
        level = 'unknown'
    elif total >= MALICIOUS_THRESHOLD:
        level = 'malicious'
    elif total >= SUSPICIOUS_THRESHOLD:
        level = 'suspicious'
    else:
        level = 'benign'

    return {'level': level, 'score': round(total, 3), 'signals': signals}
