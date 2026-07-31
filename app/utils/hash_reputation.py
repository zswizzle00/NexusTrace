"""Pure response mapping for the two keyless hash reputation sources. Stdlib only: no
network, no I/O, so `app/tests/test_hash_reputation.py` drives every branch from literals.

Both produce the same five-key envelope `app/services/abusech.py` returns, and reuse its
state vocabulary, so `hash_service` and the templates treat all sources alike. Neither
function knows a hostname: `hash_service` owns the destinations and passes `reference` in,
which is also what keeps `app/tests/test_disclosure.py` able to police them.

Two observations from querying both services are the reason neither source may decide a
verdict by merely answering:

* Team Cymru MHR returns `"1445018789 91"` for the empty-file MD5
  (`d41d8cd98f00b204e9800998ecf8427e`), so it scores ubiquitous and degenerate artifacts
  highly. `detection_pct` is analyst context; it never feeds `file_rules`'
  `known_malware_hash`.
* EICAR is present in NSRL (`RDS:package_id 304063`, shipped on a Linux distribution ISO)
  and simultaneously carries `KnownMalicious`. NSRL provenance therefore cannot clear a
  file. Only `KnownMalicious` sets `known_malicious`, and `nsrl_present` is reported for
  context alone.

MHR is md5 and sha1 only; its zone holds no sha256 records at all. A sha256 is reported
`unavailable` with `unsupported_hash_type` rather than queried, because an empty answer
from a zone that could never have held the record would read as `no_record`, which is a
claim about the file.
"""

import json
from datetime import datetime, timezone

CIRCL_SOURCE = 'circl_hashlookup'
MHR_SOURCE = 'cymru_mhr'

STATE_FOUND = 'found'
STATE_NO_RECORD = 'no_record'
STATE_UNAVAILABLE = 'unavailable'

MHR_HASH_TYPES = ('md5', 'sha1')
CIRCL_HASH_TYPES = ('md5', 'sha1', 'sha256')

# CIRCL's found body carries a `parents` array that ran to ~15 KB of unrelated package
# metadata and third-party mirror URLs for EICAR. Only these are kept in `raw`, so a
# report cannot balloon and cannot quietly acquire hostnames nothing disclosed.
_CIRCL_RAW_KEYS = (
    'KnownMalicious', 'FileName', 'FileSize', 'MD5', 'SHA-1', 'SHA-256',
    'RDS:package_id', 'SpecialCode', 'db', 'source', 'mimetype',
    'hashlookup:trust', 'hashlookup:parent-total',
)

# Any one of these means the record came out of an NSRL RDS set.
_NSRL_KEYS = ('RDS:package_id', 'ProductCode', 'OpSystemCode', 'nsrl-sha256')

# A 200 carrying none of these identifies no file, which is the `{"message": ...}` shape.
_IDENTIFYING_KEYS = ('SHA-256', 'SHA-1', 'MD5', 'FileName', 'TLSH', 'SSDEEP')


def envelope(source, state, summary=None, reference=None, raw=None):
    return {
        'source': source,
        'state': state,
        'summary': summary if isinstance(summary, dict) else {},
        'reference': reference,
        'raw': raw if isinstance(raw, dict) else {},
    }


def _text(value):
    """A TXT rdata string as clean text. dnspython hands back bytes, a fake hands back
    str, and either may still be quoted."""
    if isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode('utf-8', 'replace')
    elif not isinstance(value, str):
        return ''
    return value.strip().strip('"').strip()


def _epoch_utc(seconds):
    try:
        return datetime.fromtimestamp(seconds, timezone.utc).strftime('%Y-%m-%d %H:%M:%SZ')
    except (OverflowError, OSError, ValueError):
        return None


def parse_mhr_txt(answers):
    """(summary, reason); exactly one is None.

    `reason` is `no_answer` when the zone said nothing (an empty answer set or NXDOMAIN,
    which the caller has already flattened to an empty list) and `malformed_answer` when
    something came back that is not two plausible integers. The two are different
    outcomes: the first is the service reporting no record, the second is a contract
    change this parser must not read as one.
    """
    if isinstance(answers, (str, bytes, bytearray)):
        answers = [answers]
    if not isinstance(answers, (list, tuple)):
        answers = ()

    saw_text = False
    for answer in answers:
        text = _text(answer)
        if not text:
            continue
        saw_text = True

        parts = text.split()
        if len(parts) != 2:
            continue
        try:
            last_seen = int(parts[0])
            detection_pct = int(parts[1])
        except ValueError:
            continue
        if last_seen < 0 or not 0 <= detection_pct <= 100:
            continue

        return {
            'last_seen': last_seen,
            'last_seen_utc': _epoch_utc(last_seen),
            'detection_pct': detection_pct,
        }, None

    return None, 'malformed_answer' if saw_text else 'no_answer'


def mhr_result(hash_type, answers, reference):
    """Envelope for one MHR lookup. `answers` is the list of TXT strings, empty for an
    empty answer set or NXDOMAIN."""
    lowered = str(hash_type or '').lower()
    if lowered not in MHR_HASH_TYPES:
        return envelope(MHR_SOURCE, STATE_UNAVAILABLE, reference=reference,
                        raw={'error': 'unsupported_hash_type', 'hash_type': lowered or None})

    summary, reason = parse_mhr_txt(answers)
    if summary is None:
        state = STATE_NO_RECORD if reason == 'no_answer' else STATE_UNAVAILABLE
        return envelope(MHR_SOURCE, state, reference=reference, raw={'error': reason})

    return envelope(MHR_SOURCE, STATE_FOUND, summary=summary, reference=reference,
                    raw={'last_seen': summary['last_seen'],
                         'detection_pct': summary['detection_pct']})


def circl_result(hash_type, status_code, body, reference):
    """Envelope for one CIRCL hashlookup. `body` is the raw response text (or an
    already-decoded object); 404 is `no_record`, because that is how the service reports a
    hash it has never seen."""
    lowered = str(hash_type or '').lower()
    if lowered not in CIRCL_HASH_TYPES:
        return envelope(CIRCL_SOURCE, STATE_UNAVAILABLE, reference=reference,
                        raw={'error': 'unsupported_hash_type', 'hash_type': lowered or None})

    if status_code == 404:
        return envelope(CIRCL_SOURCE, STATE_NO_RECORD, reference=reference,
                        raw={'http_status': 404})
    if status_code != 200:
        return envelope(CIRCL_SOURCE, STATE_UNAVAILABLE, reference=reference,
                        raw={'error': f'http_{status_code}'})

    if isinstance(body, (str, bytes, bytearray)):
        try:
            body = json.loads(body)
        except (ValueError, TypeError):
            return envelope(CIRCL_SOURCE, STATE_UNAVAILABLE, reference=reference,
                            raw={'error': 'unparseable_body'})
    if not isinstance(body, dict):
        return envelope(CIRCL_SOURCE, STATE_UNAVAILABLE, reference=reference,
                        raw={'error': 'unexpected_body'})

    known = body.get('KnownMalicious')
    known = known.strip() if isinstance(known, str) else None
    nsrl_present = any(body.get(key) not in (None, '', {}, []) for key in _NSRL_KEYS)

    identified = any(body.get(key) not in (None, '', {}, []) for key in _IDENTIFYING_KEYS)
    if not known and not nsrl_present and not identified:
        return envelope(CIRCL_SOURCE, STATE_NO_RECORD, reference=reference,
                        raw={'http_status': 200})

    product = body.get('ProductCode')
    product = product if isinstance(product, dict) else {}

    summary = {
        'known_malicious': known or None,
        'nsrl_present': nsrl_present,
        'file_name': body.get('FileName') or None,
        'file_size': body.get('FileSize') or None,
        'product_name': product.get('ProductName') or None,
        'package_id': body.get('RDS:package_id') or None,
        'trust': body.get('hashlookup:trust'),
    }
    raw = {key: body[key] for key in _CIRCL_RAW_KEYS if key in body}
    return envelope(CIRCL_SOURCE, STATE_FOUND, summary=summary, reference=reference,
                    raw=raw)
