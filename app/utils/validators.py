import ipaddress
import re
from urllib.parse import urlparse

from publicsuffixlist import PublicSuffixList

_MAX_DOMAIN_LENGTH = 253
_MAX_LABEL_LENGTH = 63

_DOMAIN_PATTERN = re.compile(
    r'^(?!-)'
    r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    r'\.[a-zA-Z]{2,}$'
)

_SINGLE_LABEL_PATTERN = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$')


def is_valid_ip(ip_str):
    """Return the normalized IP address string, or None if invalid (IPv4 or IPv6)."""
    if not ip_str or not isinstance(ip_str, str):
        return None
    try:
        return str(ipaddress.ip_address(ip_str.strip()))
    except ValueError:
        return None


def is_valid_domain(domain, allow_single_label=False):
    """RFC 1035 domain validation. Returns bool."""
    if not domain or not isinstance(domain, str):
        return False
    domain = domain.strip().lower()
    if len(domain) > _MAX_DOMAIN_LENGTH:
        return False
    for label in domain.split('.'):
        if len(label) > _MAX_LABEL_LENGTH or len(label) == 0:
            return False
    if _DOMAIN_PATTERN.match(domain):
        return True
    if allow_single_label and _SINGLE_LABEL_PATTERN.match(domain):
        return True
    return False


def is_valid_url(url):
    """Return True if url has a valid http/https scheme and netloc."""
    if not url or not isinstance(url, str):
        return False
    try:
        result = urlparse(url)
        return result.scheme in ('http', 'https') and bool(result.netloc)
    except ValueError:
        return False


# Mozilla's PSL via the `publicsuffixlist` package, which ships a dated snapshot
# and never touches the network at import or call time - registrable_domain()
# runs inside URL scans and .eml parsing. Refreshing the list is a deliberate
# version bump; see the note in pyproject.toml. Built once at import and then
# immutable, so it is safe to share across gunicorn's worker threads.
#
# The PRIVATE section is included (privatesuffix, not publicsuffix): both callers
# are ownership-boundary detectors, so `evil.github.io` and `victim.github.io`
# must not collapse to one domain.
_PSL = PublicSuffixList()


def registrable_domain(host):
    """Best-effort eTLD+1 for a hostname. Never raises; junk in, junk out.

    Inputs with no registrable part - a bare public suffix (``com``, ``co.uk``),
    a single-label host (``localhost``), an unknown TLD's suffix - return the
    normalized host itself, NOT ``''``. Callers treat ``''`` as "no opinion" and
    skip their check, so collapsing these to empty would silently disable the
    comparison instead of making it. An IP literal is returned normalized.
    """
    if not isinstance(host, str):
        return ''
    host = host.strip().lower().rstrip('.')
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    if not host:
        return ''
    normalized_ip = is_valid_ip(host)
    if normalized_ip:
        return normalized_ip
    try:
        return _PSL.privatesuffix(host) or host
    except Exception:
        return host
