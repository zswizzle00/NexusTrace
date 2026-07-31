"""IOC extraction and defanging. Pure functions, stdlib only, no network.

:func:`defang` / :func:`refang` convert an indicator between its live form and its
report-safe form (``hxxp://evil[.]com``); defanging is idempotent because it refangs
to a canonical form first. :func:`extract_iocs` errs toward precision over recall:
prose ("e.g."), filenames ("index.html"), and version strings ("1.2.3.4.5") must not
become indicators.
"""

import ipaddress
import re

_REFANG_SUBS = (
    (re.compile(r'h[x*]{2}p', re.IGNORECASE), 'http'),      # hxxp/hXXp/h**p (also hxxps)
    (re.compile(r'\[\s*(?:\.|dot)\s*\]', re.IGNORECASE), '.'),
    (re.compile(r'\(\s*(?:\.|dot)\s*\)', re.IGNORECASE), '.'),
    (re.compile(r'\{\s*(?:\.|dot)\s*\}', re.IGNORECASE), '.'),
    (re.compile(r'\[\s*://\s*\]'), '://'),
    (re.compile(r'\[\s*:\s*\]'), ':'),
)


def refang(value: str) -> str:
    """Normalize an indicator to its live form, reversing common defang styles."""
    out = value or ''
    for pattern, replacement in _REFANG_SUBS:
        out = pattern.sub(replacement, out)
    return out


def defang(value: str) -> str:
    """Render an indicator safe to display. Idempotent."""
    live = refang(value or '')
    live = re.sub(r'(?i)^https', 'hxxps', live)
    live = re.sub(r'(?i)^http(?![s])', 'hxxp', live)
    return live.replace('.', '[.]')


_URL_RE = re.compile(r'''https?://[^\s<>"'()\[\]{}]+''', re.IGNORECASE)

_DOMAIN_RE = re.compile(
    r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b',
    re.IGNORECASE,
)

# Dotted quad not embedded in a longer dotted-number run, which rejects version
# strings like 1.2.3.4.5 and 10.0.19041.1. Octet ranges validated in code.
_IPV4_RE = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?!\.?\d)')

# Final labels that are almost always file extensions, not TLDs.
_FILE_EXT_TLDS = frozenset({
    'html', 'htm', 'php', 'asp', 'aspx', 'jsp', 'js', 'mjs', 'css', 'json',
    'xml', 'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'svg', 'webp', 'ico',
    'zip', 'gz', 'tar', 'exe', 'dll', 'msi', 'doc', 'docx', 'xls', 'xlsx',
    'ppt', 'pptx', 'py', 'sh', 'rb', 'go', 'md', 'yml', 'yaml', 'woff',
    'woff2', 'ttf', 'map', 'log',
})

# Prose abbreviations that look like two-label domains.
_PROSE_TOKENS = frozenset({'e.g', 'i.e', 'etc.al', 'vs.no'})

_TRAILING_PUNCT = '.,;:!?\'")]}>'


def _valid_domain(candidate: str) -> bool:
    lowered = candidate.lower().strip('.')
    if lowered in _PROSE_TOKENS:
        return False
    labels = lowered.split('.')
    if len(labels) < 2:
        return False
    if labels[-1] in _FILE_EXT_TLDS:
        return False
    # A bare dotted-quad is an IP, handled separately.
    if all(label.isdigit() for label in labels):
        return False
    return True


def _valid_ipv4(candidate: str) -> bool:
    try:
        ipaddress.IPv4Address(candidate)
        return True
    except ValueError:
        return False


# Output order, and the round-robin order the budget is shared in.
_IOC_TYPES = ('url', 'ipv4', 'domain')


def extract_iocs(text: str, *, limit: int = 200) -> list:
    """URLs, domains and IPv4 addresses from ``text``, refanged first so already-defanged
    text is still recognized; at most ``limit`` deduped, defanged ``{type, value}`` items.
    ``limit`` is shared round-robin between the types: filling it type-by-type let a page
    with 250 links yield 200 URLs and zero domains or IPs, dropping the contacted C2."""
    if not text:
        return []

    live = refang(text)
    candidates = {kind: [] for kind in _IOC_TYPES}
    seen = set()

    def add(kind, value):
        key = (kind, value.lower())
        if key in seen:
            return
        seen.add(key)
        candidates[kind].append(value)

    for match in _URL_RE.finditer(live):
        add('url', match.group(0).rstrip(_TRAILING_PUNCT))

    for match in _IPV4_RE.finditer(live):
        candidate = match.group(0)
        if _valid_ipv4(candidate):
            add('ipv4', candidate)

    for match in _DOMAIN_RE.finditer(live):
        candidate = match.group(0).rstrip(_TRAILING_PUNCT)
        if _valid_domain(candidate):
            add('domain', candidate)

    taken = {kind: 0 for kind in _IOC_TYPES}
    remaining = max(int(limit), 0)
    while remaining > 0:
        progressed = False
        for kind in _IOC_TYPES:
            if remaining <= 0:
                break
            if taken[kind] < len(candidates[kind]):
                taken[kind] += 1
                remaining -= 1
                progressed = True
        if not progressed:
            break

    return [
        {'type': kind, 'value': defang(value)}
        for kind in _IOC_TYPES
        for value in candidates[kind][:taken[kind]]
    ]
