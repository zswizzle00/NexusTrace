"""URL normalization and SSRF / target-safety validation for the URL scanner.

``validate_target`` is the single choke point every scanner fetch path must call.
It rejects anything that is not a globally-routable http(s) target: disallowed
schemes, blocked hostnames, IP literals outside the global ranges, and hostnames
that *resolve* into those ranges at validation time. Checking once is not enough —
Chromium follows redirects and loads subresources on its own, so the guard runs
per request (see ``scan_service._install_fetch_guard``).

**What the resolved-address check does NOT provide.** Validation and the actual
fetch are separate events with separate DNS resolutions: this module rejects a
host if *any* answer is non-routable, but it cannot pin Chromium's later,
independent resolution to the address it just checked. That narrows the
DNS-rebinding window (an attacker must win the race) but does not close it.
Closing it requires resolve-and-pin at the network layer (e.g. Chromium
``--host-resolver-rules``) or egress restriction on the scanner host/container;
neither is available to a stdlib-only leaf module.
"""

import ipaddress
import re
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

_ALLOWED_SCHEMES = frozenset({'http', 'https'})
_DEFAULT_PORTS = {'http': 80, 'https': 443}

# Never fetched regardless of what they resolve to. Matched after stripping a
# trailing dot ('localhost.' is the same DNS name as 'localhost').
_BLOCKED_HOSTNAMES = frozenset({'localhost', 'metadata', 'metadata.google.internal'})
_BLOCKED_SUFFIXES = ('.localhost', '.internal', '.local')

# NAT64's well-known prefix embeds an arbitrary IPv4 destination in its low 32
# bits; a NAT64 gateway translates the request to that IPv4 address, so the
# embedded address is what must be judged.
_NAT64_WELL_KNOWN_PREFIX = ipaddress.IPv6Network('64:ff9b::/96')
# Deprecated IPv6 site-local range (RFC 3879) — ``is_global`` does not exclude it.
_IPV6_SITE_LOCAL = ipaddress.IPv6Network('fec0::/10')

# Text after "scheme:" that is a bare port and nothing else — i.e. the input was
# really "host:port", not a scheme.
_PORT_ONLY_RE = re.compile(r'^\d+(?:[/?#].*)?$')

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
    """Wrap ``resolver`` so each host is resolved at most once *on success*. Scope
    the result to a single scan — it is a cache with no invalidation. Failures are
    deliberately not memoized, so a transient DNS error on the first subresource
    does not mark the host unfetchable for the rest of the scan.
    """
    inner = resolver if resolver is not None else _default_resolver
    memo: dict[str, list[str]] = {}

    def resolve(host: str) -> list[str]:
        if host not in memo:
            memo[host] = list(inner(host))
        return memo[host]

    return resolve


def _has_ambiguous_authority(netloc: str) -> bool:
    """True if ``netloc`` contains a character that makes host parsing ambiguous.

    Parser differential: a backslash, ASCII whitespace, or control character makes
    ``urlsplit``'s userinfo/host split disagree with Chromium's WHATWG parser,
    which treats ``\\`` as ``/`` and ends the authority before ``@`` — so
    ``http://127.0.0.1\\@example.com/`` is 127.0.0.1 to Chromium and example.com to
    ``urlsplit``. Reject rather than emulate WHATWG parsing here.
    """
    for ch in netloc:
        if ch == '\\' or ord(ch) <= 0x20 or ord(ch) == 0x7f:
            return True
    return False


def normalize(raw: str) -> NormalizedTarget:
    """Canonicalize a URL: lowercase scheme+host, strip credentials and fragment,
    drop default ports, default a bare host to ``http://``, ensure a path, and
    IDNA-encode the host. Raises :class:`UnsafeURLError` on input that cannot be
    unambiguously parsed; performs no *safety* checks — see :func:`validate_target`.
    """
    stripped = (raw or '').strip()
    parts = urlsplit(stripped)

    # Classify by shape, not by a scheme allowlist/registry:
    if '://' in stripped:
        pass  # real scheme; validate_target decides whether it's allowed
    elif stripped.startswith('//'):
        stripped = 'http:' + stripped
        parts = urlsplit(stripped)
    elif parts.scheme:
        # "scheme:" with no '://'. Schemes may contain '.', so 'example.com:8080/x'
        # parses with scheme 'example.com'. What follows the colon disambiguates:
        # a bare port means it was 'host:port'; anything else is a real opaque
        # scheme ('mailto:', 'javascript:x@evil.com') that must be rejected, not
        # rewritten to http.
        after_colon = stripped[len(parts.scheme) + 1:]
        if _PORT_ONLY_RE.match(after_colon):
            stripped = 'http://' + stripped
            parts = urlsplit(stripped)
        else:
            raise UnsafeURLError(f'scheme {parts.scheme.lower()!r} is not allowed')
    else:
        stripped = 'http://' + stripped  # bare host
        parts = urlsplit(stripped)

    if _has_ambiguous_authority(parts.netloc):
        raise UnsafeURLError(f'ambiguous authority in {raw!r}')

    scheme = parts.scheme.lower()
    host = (parts.hostname or '').lower()  # .hostname drops any user:pass@
    if host and _parse_ip_literal(host) is None:
        # IDNA-encode so this module's host matches what Chromium and getaddrinfo
        # actually resolve (e.g. fullwidth digits). IP literals are left as-is.
        try:
            host = host.encode('idna').decode('ascii')
        except UnicodeError as exc:
            raise UnsafeURLError(f'invalid hostname in {raw!r}') from exc
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


def _is_blocked_hostname(host: str) -> bool:
    # A trailing dot must not bypass the denylist — 'localhost.' and 'localhost'
    # are one name to a resolver. The canonical .url keeps the dot.
    bare = host.rstrip('.')
    return bare in _BLOCKED_HOSTNAMES or bare.endswith(_BLOCKED_SUFFIXES)


def _blocked_ip(ip) -> bool:
    """True if ``ip`` must not be treated as a safe fetch target. ``is_global``
    alone excludes neither multicast, the IETF-reserved ranges, the deprecated IPv6
    site-local range, nor NAT64's prefix; each branch below closed a real bypass, so
    do not simplify them away."""
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped  # ::ffff:127.0.0.1 — judge the embedded v4 address
    elif isinstance(ip, ipaddress.IPv6Address) and ip in _NAT64_WELL_KNOWN_PREFIX:
        # 64:ff9b::7f00:1 — a NAT64 gateway would translate this to 127.0.0.1.
        ip = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    elif isinstance(ip, ipaddress.IPv6Address) and ip in _IPV6_SITE_LOCAL:
        return True

    return not ip.is_global or ip.is_multicast or ip.is_reserved


def _parse_ip_literal(host: str):
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def validate_target(raw: str, *, resolver: Resolver | None = None) -> NormalizedTarget:
    """Normalize ``raw`` and raise :class:`UnsafeURLError` if it must not be fetched.
    Raises **only** that type for any ``str`` input, so callers need one ``except``."""
    try:
        target = normalize(raw)

        if target.scheme not in _ALLOWED_SCHEMES:
            raise UnsafeURLError(f'scheme {target.scheme!r} is not allowed')

        host = target.host
        if not host:
            raise UnsafeURLError('URL has no host')
        if _is_blocked_hostname(host):
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

        # One non-global answer poisons the whole host, for this resolution only
        # — see the module docstring on why this is not a full rebinding defense.
        for address in addresses:
            try:
                ip = ipaddress.ip_address(address)
            except ValueError as exc:
                raise UnsafeURLError(f'unparseable resolved address {address!r}') from exc
            if _blocked_ip(ip):
                raise UnsafeURLError(f'host {host!r} resolves to non-routable {address}')

        return target
    except UnsafeURLError:
        raise
    except Exception as exc:
        # Fail closed as the typed error rather than escaping as whatever was
        # raised (e.g. urlsplit's ValueError on an unbalanced IPv6 bracket).
        raise UnsafeURLError(f'could not validate {raw!r}: {exc}') from exc


def is_scannable(url: str, *, resolver: Resolver | None = None) -> bool:
    """Non-raising form of :func:`validate_target`. Never raises, for any input,
    including non-``str``."""
    if not url or not isinstance(url, str):
        return False
    try:
        validate_target(url, resolver=resolver)
        return True
    except Exception:
        return False
