"""Cloudflare Access identity, established by verifying the signed Access JWT.

Why this exists instead of reading `Cf-Access-Authenticated-User-Email`: that header is
only as trustworthy as the guarantee that *every* path to the app goes through Cloudflare,
and this deployment cannot make it. The origin is a homelab box whose only internet
ingress is a Cloudflare Tunnel, but the tunnel does not isolate the LAN - anything on the
home network can talk to gunicorn directly and send whatever headers it likes, and
Cloudflare cannot strip a header on a request it never sees.

The Access JWT is not forgeable the same way: it is RS256-signed by the team's Access
keys. Verification covers signature (team JWKS, matched on `kid`), `iss`, `aud`,
`exp`/`iat`, and the algorithm; identity comes from the verified `email` claim.

Do not "simplify" this back to reading the plaintext header. That is the bypass.
"""

import json
import logging
import os
import threading
import time

import jwt
from jwt.algorithms import RSAAlgorithm

logger = logging.getLogger(__name__)

ENV_TEAM_DOMAIN = 'CF_ACCESS_TEAM_DOMAIN'
ENV_AUD = 'CF_ACCESS_AUD'

TOKEN_HEADER = 'Cf-Access-Jwt-Assertion'
TOKEN_COOKIE = 'CF_Authorization'

# Access rotates its signing keys, so the JWKS is cached rather than pinned.
JWKS_TTL = 900.0
# An unknown `kid` is the rotation signal, and also what an attacker would send to make
# the app fetch on demand. One refetch is allowed, then no more until this many seconds
# have passed since the last attempt; a flood of junk `kid`s costs Cloudflare nothing.
JWKS_MIN_REFETCH_INTERVAL = 60.0
JWKS_TIMEOUT = 5.0

# Access issues short-lived tokens; this only absorbs origin/edge clock drift.
CLOCK_SKEW_LEEWAY = 60.0

_ALGORITHM = 'RS256'

_lock = threading.Lock()
_cache = {'url': None, 'keys': {}, 'loaded_at': 0.0, 'attempted_at': 0.0}


class AccessDenied(Exception):
    """A request carried no usable Access identity. `reason` is for logs, not users."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def team_domain():
    """The Access team domain as a bare host, e.g. `acme.cloudflareaccess.com`."""
    raw = (os.environ.get(ENV_TEAM_DOMAIN) or '').strip().rstrip('/')
    if not raw:
        return ''
    for prefix in ('https://', 'http://'):
        if raw.lower().startswith(prefix):
            raw = raw[len(prefix):]
            break
    return raw.strip('/').lower()


def audience():
    return (os.environ.get(ENV_AUD) or '').strip()


def is_configured():
    """True once the operator has begun configuring Access. Deliberately an OR:
    half-configured is a misconfiguration, and the fail-closed reading of it is "Access
    is on and broken", not "Access is off"."""
    return bool(team_domain() or audience())


def issuer():
    domain = team_domain()
    return f'https://{domain}' if domain else ''


def certs_url():
    base = issuer()
    return f'{base}/cdn-cgi/access/certs' if base else ''


def reset_cache():
    with _lock:
        _cache.update(url=None, keys={}, loaded_at=0.0, attempted_at=0.0)


def _default_fetcher(url):
    import requests
    response = requests.get(url, timeout=JWKS_TIMEOUT)
    response.raise_for_status()
    return response.json()


def _parse_jwks(raw):
    keys = {}
    for entry in (raw or {}).get('keys') or []:
        if not isinstance(entry, dict):
            continue
        kid = entry.get('kid')
        if not kid or entry.get('kty') != 'RSA':
            continue
        if entry.get('alg') and entry.get('alg') != _ALGORITHM:
            continue
        try:
            keys[kid] = RSAAlgorithm.from_jwk(json.dumps(entry))
        except Exception:
            logger.warning('Skipping unparseable Access JWKS entry kid=%s', kid)
    return keys


def _load(url, fetcher, now):
    """Replace the cached key set. Caller holds `_lock`."""
    _cache['attempted_at'] = now
    keys = _parse_jwks(fetcher(url))
    if not keys:
        raise ValueError(f'no usable RSA keys in the JWKS at {url}')
    _cache.update(url=url, keys=keys, loaded_at=now)


def _public_key(kid, fetcher, now):
    url = certs_url()
    with _lock:
        if _cache['url'] != url:
            _cache.update(url=url, keys={}, loaded_at=0.0, attempted_at=0.0)

        if not _cache['keys'] or (now - _cache['loaded_at']) >= JWKS_TTL:
            try:
                _load(url, fetcher, now)
            except Exception:
                logger.exception('Cloudflare Access JWKS fetch failed: %s', url)
                raise AccessDenied('jwks_unavailable')

        key = _cache['keys'].get(kid)
        if key is None and (now - _cache['attempted_at']) >= JWKS_MIN_REFETCH_INTERVAL:
            try:
                _load(url, fetcher, now)
            except Exception:
                logger.exception('Cloudflare Access JWKS refetch failed: %s', url)
                raise AccessDenied('jwks_unavailable')
            key = _cache['keys'].get(kid)

        if key is None:
            raise AccessDenied('unknown_kid')
        return key


_REASONS = (
    (jwt.ExpiredSignatureError, 'expired'),
    (jwt.InvalidAudienceError, 'aud_mismatch'),
    (jwt.InvalidIssuerError, 'iss_mismatch'),
    (jwt.InvalidAlgorithmError, 'bad_algorithm'),
    (jwt.MissingRequiredClaimError, 'missing_claim'),
    (jwt.InvalidSignatureError, 'bad_signature'),
    (jwt.DecodeError, 'malformed_token'),
)


def _reason_for(exc):
    for exc_type, reason in _REASONS:
        if isinstance(exc, exc_type):
            return reason
    return 'invalid_token'


def verify_token(token, fetcher=None, now=None):
    """Return the verified claims, or raise `AccessDenied`. Never returns on doubt."""
    if not is_configured():
        raise AccessDenied('not_configured')
    if not team_domain() or not audience():
        logger.error('Cloudflare Access is half-configured: set both %s and %s',
                     ENV_TEAM_DOMAIN, ENV_AUD)
        raise AccessDenied('incomplete_config')

    token = (token or '').strip()
    if not token:
        raise AccessDenied('missing_token')

    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        raise AccessDenied('malformed_token')

    # Checked before the key lookup as well as by `algorithms=` below: an `alg` the
    # caller chose is the algorithm-confusion primitive (`none`, or HS256 keyed with
    # the RSA public key), and it must never reach a verifier.
    if header.get('alg') != _ALGORITHM:
        raise AccessDenied('bad_algorithm')
    kid = header.get('kid')
    if not kid:
        raise AccessDenied('missing_kid')

    key = _public_key(kid, fetcher or _default_fetcher, time.time() if now is None else now)

    try:
        claims = jwt.decode(
            token,
            key=key,
            algorithms=[_ALGORITHM],
            audience=audience(),
            issuer=issuer(),
            leeway=CLOCK_SKEW_LEEWAY,
            options={'require': ['exp', 'iat', 'iss', 'aud']},
        )
    except jwt.PyJWTError as exc:
        raise AccessDenied(_reason_for(exc))

    email = str(claims.get('email') or '').strip().lower()
    if not email:
        raise AccessDenied('missing_email')
    claims['email'] = email
    return claims


def token_from_request(request):
    token = (request.headers.get(TOKEN_HEADER) or '').strip()
    if not token:
        token = (request.cookies.get(TOKEN_COOKIE) or '').strip()
    return token


def identity_from_request(request, fetcher=None, now=None):
    """The verified e-mail address behind this request, or raise `AccessDenied`."""
    return verify_token(token_from_request(request), fetcher=fetcher, now=now)['email']
