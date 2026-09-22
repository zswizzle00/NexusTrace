"""Normalize and merge the two identity engines' results. Pure: no network, no Flask.

Sherlock and user-scanner overlap heavily on sites but report different vocabularies and
different shapes. This module is the single place that reconciles them, and it is pure so
it can be tested without spawning either engine.

**Corroboration is surfaced, never collapsed.** Two independent engines agreeing that a
handle exists is a stronger claim than either alone, so the merged row records which
engines contributed and the page marks the overlap.

**"Not covered" is not "not found".** Most sites are checked by only one engine. A row
that one engine never looked at must not read as a negative from that engine, so the
engine list is per-row and the page renders the difference.
"""

from urllib.parse import urlsplit

from .validators import registrable_domain

STATUSES = ('found', 'blocked', 'unknown', 'not_found', 'not_applicable')

# Higher wins a conflict. `found` outranks everything because a positive from either
# engine is a lead worth showing; `not_applicable` loses to everything because it means
# the site could never answer for this target, which is the weakest possible claim.
STATUS_RANK = {name: len(STATUSES) - i for i, name in enumerate(STATUSES)}

# Sherlock's QueryStatus, lowercased. Verified against sherlock-project 0.16.2.
_SHERLOCK_STATUS = {
    'claimed': 'found',
    'available': 'not_found',
    'waf': 'blocked',
    'unknown': 'unknown',
    'illegal': 'not_applicable',
}

# user-scanner's Status. Verified against user-scanner 1.5.2.
_USER_SCANNER_STATUS = {
    'taken': 'found',
    'available': 'not_found',
    'error': 'unknown',
    'skipped': 'not_applicable',
}


# The only schemes we will put in an href. A vendor's site list is third-party data
# we do not control, and a `javascript:` or `data:` URL in it would render as a live
# link, so the allowlist sits at the data boundary rather than in the template.
# app/utils/url_guard.py is not reusable here: it resolves DNS, and this module is
# pure by contract.
SAFE_URL_SCHEMES = ('http', 'https')


def safe_url(url):
    """A vendor URL, or None when its scheme is not one we will render as a link.

    Jinja's autoescaping does not cover this: it escapes HTML metacharacters, not URI
    schemes. A protocol-relative `//host/path` is rejected as well, because its scheme
    is empty and the browser would inherit the page's own.

    Public: the route layer also calls this, when a stored record is loaded for
    rendering, so a record already on disk before this allowlist landed (or written by
    any future second writer) is still guarded. Every writer normalising its own output
    is not an enforced invariant; this is the one choke point that is.
    """
    if not isinstance(url, str):
        return None
    url = url.strip()
    if not url:
        return None
    try:
        scheme = urlsplit(url).scheme
    except ValueError:
        return None
    return url if scheme.lower() in SAFE_URL_SCHEMES else None


def _blank(site, url, status, engine, category=None, metadata=None, reason=None):
    return {
        'site': site or '',
        'url': url or None,
        'status': status,
        'engines': [engine],
        'category': category or None,
        'metadata': metadata or {},
        'reason': reason,
    }


def normalize_sherlock(site_name, entry):
    """One Sherlock result as a normalized finding.

    An unrecognised status becomes `unknown`, never a negative: a vendor version that
    adds a status must degrade into "we do not know" rather than silently assert the
    account does not exist.
    """
    entry = entry or {}
    raw = str(entry.get('status') or '').strip().lower()
    return _blank(
        site=site_name,
        url=safe_url(entry.get('url_user') or entry.get('url')),
        status=_SHERLOCK_STATUS.get(raw, 'unknown'),
        engine='sherlock',
        reason=entry.get('context') or None,
    )


def normalize_user_scanner(entry):
    """One user-scanner Result dict as a normalized finding. Same unknown-status rule."""
    entry = entry or {}
    raw = str(entry.get('status') or '').strip().lower()
    metadata = {}
    for key in ('extra', 'media'):
        value = entry.get(key)
        if value:
            metadata[key] = value
    return _blank(
        site=entry.get('site_name'),
        url=safe_url(entry.get('url')),
        status=_USER_SCANNER_STATUS.get(raw, 'unknown'),
        engine='user-scanner',
        category=entry.get('category'),
        metadata=metadata,
        reason=entry.get('reason') or None,
    )


def _site_slug(name):
    """A site name reduced to its comparable core: lowercase alphanumerics only.

    Tolerates the two engines spelling one site differently ("GitHub" vs "Github") while
    still separating genuinely different services on a shared domain.
    """
    return ''.join(ch for ch in str(name or '').lower() if ch.isalnum())


def _host_key(url):
    """The registrable domain of a URL, or None. Tolerates a missing scheme, and
    normalises an IDN host to punycode so one engine's Unicode URL and another's encoded
    form do not become separate rows."""
    if not url:
        return None
    candidate = url if '//' in url else f'//{url}'
    try:
        host = urlsplit(candidate).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.lower()
    try:
        host = host.encode('idna').decode('ascii')
    except Exception:
        pass
    return registrable_domain(host) or host


def _key(finding):
    """The identity of a site: its registrable domain AND its name.

    Domain alone is not enough, and the failure is not hypothetical: Sherlock's bundled
    list has 10 registrable domains carrying 20 distinct sites, including Steam Community
    (User) and Steam Community (Group). Keyed on domain alone they merge, the merge takes
    the stronger status, and a `found` on one invents an account on the other.

    Including the name costs a corroboration whenever the engines spell a site
    differently. That is the safe direction to fail: understating corroboration shows a
    row credited to one engine, while overstating it invents an account.
    """
    slug = _site_slug(finding.get('site'))
    host = _host_key(finding.get('url'))
    if host:
        return ('domain', host, slug)
    return ('name', slug)


def merge(findings):
    """Merged rows, one per site, in first-seen order.

    Each engine's own claim is recorded against its name, and the row's status and its
    dissent text are derived from those claims ONCE, at the end. Accumulating them
    incrementally is what made an earlier version credit an engine with a status it
    never reported, as soon as a third claim arrived for the same site. `reason` is
    derived purely from `claims`, so any vendor-supplied reason text does not survive
    the merge; the worker does not emit Sherlock's `context` field today, so nothing is
    lost in practice.
    """
    merged = {}
    order = []

    for finding in findings or ():
        if not isinstance(finding, dict):
            continue
        finding = {'site': '', 'url': None, 'status': 'unknown', 'engines': [],
                   'category': None, 'metadata': {}, 'reason': None, **finding}
        if finding['status'] not in STATUS_RANK:
            finding['status'] = 'unknown'
        # A row with neither a site nor a URL carries no information and would otherwise
        # collide with every other such row under one empty key.
        if not finding.get('site') and not finding.get('url'):
            continue

        key = _key(finding)
        row = merged.get(key)
        if row is None:
            row = {**finding, 'engines': [], 'claims': {}}
            merged[key] = row
            order.append(key)

        for engine in {e for e in (finding.get('engines') or []) if e}:
            # One engine can report a site more than once. Keep its strongest claim, so
            # its attribution stays its own rather than the row's.
            previous = row['claims'].get(engine)
            if previous is None or STATUS_RANK[finding['status']] > STATUS_RANK[previous]:
                row['claims'][engine] = finding['status']

        row['url'] = row.get('url') or finding.get('url')
        row['category'] = row.get('category') or finding.get('category')
        row['site'] = row.get('site') or finding.get('site')
        # First reporter of a metadata key wins. Deterministic for a given input order,
        # and the engines do not contest the same keys in practice.
        row['metadata'] = {**finding.get('metadata', {}), **row.get('metadata', {})}

    result = []
    for key in order:
        row = merged[key]
        claims = row['claims']
        row['engines'] = sorted(claims)
        if claims:
            row['status'] = max(claims.values(), key=lambda status: STATUS_RANK[status])
        # Derived from the claims themselves, so the text cannot depend on arrival order
        # and can never credit an engine with a claim it did not make.
        row['reason'] = '; '.join(
            f'{engine} reported {status}'
            for engine, status in sorted(claims.items())
            if status != row['status']
        ) or None
        # The engines that actually AGREE with the row's status. `engines` lists everyone
        # who reported on the site, including dissenters, so it is the wrong basis for a
        # corroboration badge: one engine finding an account and another not finding it
        # would otherwise render as confirmed by both.
        row['agreeing'] = sorted(engine for engine, claim in claims.items()
                                 if claim == row['status'])
        result.append(row)

    return result


def summarize(merged):
    """Counts for the exposure summary. Deliberately no verdict, score or level: account
    presence is not a threat signal, and naming it one would be a claim the data does not
    support."""
    merged = list(merged or ())
    return {
        'checked': len(merged),
        'found': sum(1 for row in merged if row.get('status') == 'found'),
        'corroborated': sum(1 for row in merged
                            if row.get('status') == 'found'
                            and len(row.get('agreeing') or []) > 1),
        'blocked': sum(1 for row in merged if row.get('status') == 'blocked'),
        'unknown': sum(1 for row in merged if row.get('status') == 'unknown'),
    }
