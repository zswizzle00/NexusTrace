import ipaddress
import re
from urllib.parse import urlparse

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
