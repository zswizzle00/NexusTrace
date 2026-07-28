"""URL normalization and SSRF / target-safety validation for the URL scanner.

``validate_target`` is the single choke point every scanner fetch path must call.
It rejects anything that is not a globally-routable http(s) target: disallowed
schemes, blocked hostnames, IP literals outside the global ranges, and hostnames
that *resolve* into those ranges (the DNS-rebinding defense).

Two design notes:

* **The resolver is injectable.** Tests pass a fake so no case touches the
  network, and ``caching_resolver`` lets one scan memoize its lookups — a page
  makes many requests to the same handful of hosts and re-resolving each one
  would add a DNS round-trip per subresource.
* **Checking once is not enough.** This module replaces a pre-flight-only check.
  Chromium follows redirects and loads subresources on its own, so the guard has
  to be called per request (see ``scan_service._install_fetch_guard``), not once
  against the URL a user typed.
"""

import ipaddress
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

_ALLOWED_SCHEMES = frozenset({'http', 'https'})
_DEFAULT_PORTS = {'http': 80, 'https': 443}

# Hostnames that must never be fetched regardless of what they resolve to.
_BLOCKED_HOSTNAMES = frozenset({'localhost', 'metadata', 'metadata.google.internal'})
# Suffixes that only ever name internal infrastructure.
_BLOCKED_SUFFIXES = ('.localhost', '.internal', '.local')

Resolver = Callable[[str], Iterable[str]]


class UnsafeURLError(ValueError):
    """A URL must not be fetched (SSRF / target safety)."""


@dataclass(frozen=True)
class NormalizedTarget:
    """A canonicalized URL and its validated parts."""

    url: str
    scheme: str
    host: str
    port: int


def _default_resolver(host: str) -> list[str]:
    return [str(info[4][0]) for info in socket.getaddrinfo(host, None)]


def caching_resolver(resolver: Resolver | None = None) -> Resolver:
    """Wrap ``resolver`` so each host is resolved at most once.

    Scope the returned callable to a single scan: it is a cache with no
    invalidation, which is exactly what we want for the duration of one page load
    and exactly what we do not want to share between scans.
    """
    inner = resolver if resolver is not None else _default_resolver
    memo: dict[str, list[str]] = {}
    errors: dict[str, OSError] = {}

    def resolve(host: str) -> list[str]:
        if host in errors:
            raise errors[host]
        if host not in memo:
            try:
                memo[host] = list(inner(host))
            except OSError as exc:
                errors[host] = exc
                raise
        return memo[host]

    return resolve


def normalize(raw: str) -> NormalizedTarget:
    """Canonicalize a URL: lowercase scheme+host, strip credentials and fragment,
    drop default ports, default a bare host to ``http://``, ensure a path.

    Performs no safety checks - call :func:`validate_target` for that.
    """
    stripped = (raw or '').strip()
    parts = urlsplit(stripped)
    if not parts.scheme:
        stripped = ('http:' if stripped.startswith('//') else 'http://') + stripped
        parts = urlsplit(stripped)

    scheme = parts.scheme.lower()
    # .hostname drops any user:pass@ and lowercases for us.
    host = (parts.hostname or '').lower()
    try:
        port = parts.port if parts.port is not None else _DEFAULT_PORTS.get(scheme, 0)
    except ValueError:  # non-numeric port
        raise UnsafeURLError(f'invalid port in {raw!r}')
    path = parts.path or '/'

    netloc = f'[{host}]' if ':' in host else host
    if port and port != _DEFAULT_PORTS.get(scheme):
        netloc = f'{netloc}:{port}'

    canonical = urlunsplit((scheme, netloc, path, parts.query, ''))
    return NormalizedTarget(url=canonical, scheme=scheme, host=host, port=port)


def _blocked_ip(ip) -> bool:
    # An IPv4-mapped IPv6 address (::ffff:127.0.0.1) must be judged on the
    # embedded v4 address, not on the v6 wrapper.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    # Only globally-routable addresses are safe. is_global excludes loopback,
    # RFC1918, link-local (169.254.169.254), CGNAT, reserved, unspecified,
    # and multicast in one check.
    return not ip.is_global


def _parse_ip_literal(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def validate_target(raw: str, *, resolver: Resolver | None = None) -> NormalizedTarget:
    """Normalize ``raw`` and raise :class:`UnsafeURLError` if it must not be fetched."""
    target = normalize(raw)

    if target.scheme not in _ALLOWED_SCHEMES:
        raise UnsafeURLError(f'scheme {target.scheme!r} is not allowed')

    host = target.host
    if not host:
        raise UnsafeURLError('URL has no host')
    if host in _BLOCKED_HOSTNAMES or host.endswith(_BLOCKED_SUFFIXES):
        raise UnsafeURLError(f'host {host!r} is blocked')

    literal = _parse_ip_literal(host)
    if literal is not None:
        if _blocked_ip(literal):
            raise UnsafeURLError(f'IP {host!r} is not globally routable')
        return target

    resolve = resolver if resolver is not None else _default_resolver
    try:
        addresses = list(resolve(host))
    except OSError as exc:
        raise UnsafeURLError(f'DNS resolution failed for {host!r}') from exc
    if not addresses:
        raise UnsafeURLError(f'no addresses resolved for {host!r}')

    # Rebinding defense: one non-global answer poisons the whole host.
    for address in addresses:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError as exc:
            raise UnsafeURLError(f'unparseable resolved address {address!r}') from exc
        if _blocked_ip(ip):
            raise UnsafeURLError(f'host {host!r} resolves to non-routable {address}')

    return target


def is_scannable(url: str, *, resolver: Resolver | None = None) -> bool:
    """Non-raising form of :func:`validate_target`. Same contract as the
    ``scan_service.is_scannable`` this replaces, so existing callers are unchanged."""
    if not url or not isinstance(url, str):
        return False
    try:
        validate_target(url, resolver=resolver)
        return True
    except UnsafeURLError:
        return False
