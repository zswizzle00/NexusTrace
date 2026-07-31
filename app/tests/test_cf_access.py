"""Cloudflare Access JWT verification and the /admin authorization matrix.

No network and no Cloudflare: an RSA keypair is generated in-process, the JWKS is served
through the injected fetcher seam (`cf_access._default_fetcher` for the route cases), and
every token is signed here - including the forged ones. The point of most of these cases
is a token that a request reaching the origin *outside* the tunnel could produce; if any
of them is ever accepted, the LAN bypass this module exists to close is back.
"""
import base64
import hashlib
import hmac
import json
import os
import shutil
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app import create_app
from app.utils import activity, cf_access

TEAM = 'nexustrace.cloudflareaccess.com'
ISSUER = f'https://{TEAM}'
AUD = 'a' * 64
ALLOWED = 'owner@example.com'

failures = []
cases = 0


def check(condition, message):
    if not condition:
        failures.append(message)
    return bool(condition)


def case(condition, message):
    global cases
    cases += 1
    return check(condition, message)


def b64u(raw):
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')


class Key:
    def __init__(self, kid):
        self.kid = kid
        self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.private_pem = self.private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.public_pem = self.private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def jwk(self):
        numbers = self.private.public_key().public_numbers()
        size = (numbers.n.bit_length() + 7) // 8
        return {
            'kty': 'RSA',
            'alg': 'RS256',
            'use': 'sig',
            'kid': self.kid,
            'n': b64u(numbers.n.to_bytes(size, 'big')),
            'e': b64u(numbers.e.to_bytes(3, 'big')),
        }


GOOD = Key('kid-good')
OTHER = Key('kid-other')
ROTATED = Key('kid-rotated')


def claims(**overrides):
    now = int(time.time())
    payload = {
        'iss': ISSUER,
        'aud': [AUD],
        'email': ALLOWED,
        'sub': 'user-1',
        'iat': now - 10,
        'exp': now + 600,
    }
    payload.update(overrides)
    return {k: v for k, v in payload.items() if v is not None}


def sign(key=GOOD, kid=None, **overrides):
    return jwt.encode(claims(**overrides), key.private_pem, algorithm='RS256',
                      headers={'kid': kid or key.kid})


def sign_alg_none(kid=GOOD.kid):
    """Hand-rolled: the classic unsigned forgery, with a kid that would otherwise resolve."""
    header = b64u(json.dumps({'alg': 'none', 'typ': 'JWT', 'kid': kid}).encode())
    payload = b64u(json.dumps(claims()).encode())
    return f'{header}.{payload}.'


def sign_hs256_with_public_key(kid=GOOD.kid):
    """Algorithm confusion: HMAC the token with the RSA *public* key as the shared secret.

    Hand-rolled because PyJWT refuses to encode this shape at all - the attacker has no
    such scruples, so the defence has to be on the verifying side.
    """
    header = b64u(json.dumps({'alg': 'HS256', 'typ': 'JWT', 'kid': kid}).encode())
    payload = b64u(json.dumps(claims()).encode())
    signing_input = f'{header}.{payload}'.encode('ascii')
    mac = hmac.new(GOOD.public_pem, signing_input, hashlib.sha256).digest()
    return f'{header}.{payload}.{b64u(mac)}'


class Fetcher:
    """Counts calls so cache reuse and refetch policy are observable."""

    def __init__(self, keys=(GOOD,), error=None):
        self.keys = list(keys)
        self.error = error
        self.calls = 0

    def __call__(self, url):
        self.calls += 1
        if self.error:
            raise self.error
        return {'keys': [k.jwk() for k in self.keys]}


def configure(team=TEAM, aud=AUD, token=None, emails=None):
    for name, value in ((cf_access.ENV_TEAM_DOMAIN, team), (cf_access.ENV_AUD, aud),
                        ('ADMIN_TOKEN', token), ('ADMIN_EMAILS', emails)):
        if value:
            os.environ[name] = value
        else:
            os.environ.pop(name, None)
    cf_access.reset_cache()


def denied_reason(token, fetcher=None, now=None):
    """Return the AccessDenied reason, or None if the token was accepted."""
    try:
        cf_access.verify_token(token, fetcher=fetcher or Fetcher(), now=now)
        return None
    except cf_access.AccessDenied as exc:
        return exc.reason


def test_valid_token():
    configure()
    fetcher = Fetcher()
    verified = cf_access.verify_token(sign(), fetcher=fetcher)
    case(verified['email'] == ALLOWED, f'valid token yielded email={verified.get("email")!r}')
    case(verified['iss'] == ISSUER, 'verified claims lost the issuer')

    verified = cf_access.verify_token(sign(email='OWNER@Example.COM'), fetcher=Fetcher())
    case(verified['email'] == ALLOWED,
         f'claim e-mail was not lowercased: {verified.get("email")!r}')


def test_rejected_tokens():
    configure()
    now = int(time.time())
    rejects = [
        ('expired', sign(exp=now - 60, iat=now - 600), 'expired'),
        ('aud mismatch', sign(aud=['b' * 64]), 'aud_mismatch'),
        ('aud absent', sign(aud=None), None),
        ('iss mismatch', sign(iss='https://attacker.cloudflareaccess.com'), 'iss_mismatch'),
        ('signed by the wrong key', sign(key=OTHER, kid=GOOD.kid), 'bad_signature'),
        ('alg: none', sign_alg_none(), 'bad_algorithm'),
        ('HS256 keyed with the RSA public key', sign_hs256_with_public_key(), 'bad_algorithm'),
        ('truncated', sign()[:-12], None),
        ('malformed', 'not-a-jwt', 'malformed_token'),
        ('empty', '', 'missing_token'),
        ('None', None, 'missing_token'),
        ('header only', sign().split('.')[0], None),
        ('no kid', jwt.encode(claims(), GOOD.private_pem, algorithm='RS256'), 'missing_kid'),
        ('no exp', sign(exp=None), 'missing_claim'),
        ('no iat', sign(iat=None), 'missing_claim'),
        ('no email claim', sign(email=None), 'missing_email'),
        ('empty email claim', sign(email='   '), 'missing_email'),
    ]
    for label, token, expected in rejects:
        reason = denied_reason(token)
        if not case(reason is not None, f'{label} was ACCEPTED'):
            continue
        case(expected is None or reason == expected,
             f'{label} was denied as {reason!r}, expected {expected!r}')


def test_configuration_states():
    configure(team=None, aud=None)
    case(cf_access.is_configured() is False, 'is_configured() true with nothing set')
    case(denied_reason(sign()) == 'not_configured',
         'an unconfigured verifier did not deny with not_configured')

    configure(aud=None)
    case(cf_access.is_configured() is True,
         'half configuration must read as configured, so it fails closed')
    case(denied_reason(sign()) == 'incomplete_config',
         'half configuration did not deny with incomplete_config')

    configure(team=None)
    case(cf_access.is_configured() is True, 'AUD alone did not read as configured')
    case(denied_reason(sign()) == 'incomplete_config',
         'AUD without a team domain did not deny with incomplete_config')

    configure(team=f'https://{TEAM}/')
    case(cf_access.team_domain() == TEAM, f'team domain not normalized: {cf_access.team_domain()!r}')
    case(cf_access.certs_url() == f'{ISSUER}/cdn-cgi/access/certs',
         f'certs URL is {cf_access.certs_url()!r}')
    case(cf_access.verify_token(sign(), fetcher=Fetcher())['email'] == ALLOWED,
         'a scheme-prefixed team domain broke verification')


def test_jwks_cache_is_reused():
    configure()
    fetcher = Fetcher()
    start = time.time()
    for offset in (0, 1, 60, cf_access.JWKS_TTL - 1):
        cf_access.verify_token(sign(), fetcher=fetcher, now=start + offset)
    case(fetcher.calls == 1, f'JWKS was fetched {fetcher.calls} times inside the TTL, expected 1')

    cf_access.verify_token(sign(), fetcher=fetcher, now=start + cf_access.JWKS_TTL + 1)
    case(fetcher.calls == 2, f'JWKS was not refetched after the TTL ({fetcher.calls} calls)')


def test_unknown_kid_refetches_once():
    configure()
    fetcher = Fetcher()
    start = time.time()
    cf_access.verify_token(sign(), fetcher=fetcher, now=start)
    case(fetcher.calls == 1, f'priming the cache took {fetcher.calls} fetches')

    # Past the floor: rotation is plausible, so exactly one refetch is spent on it.
    unknown = sign(key=ROTATED)
    after = start + cf_access.JWKS_MIN_REFETCH_INTERVAL + 1
    case(denied_reason(unknown, fetcher, after) == 'unknown_kid',
         'an unknown kid was not denied')
    case(fetcher.calls == 2, f'an unknown kid caused {fetcher.calls - 1} refetches, expected 1')

    # Inside the floor: further unknown kids are free for Cloudflare.
    for step in range(1, 4):
        case(denied_reason(unknown, fetcher, after + step) == 'unknown_kid',
             'a repeated unknown kid was not denied')
    case(fetcher.calls == 2,
         f'unknown kids inside the floor hammered the JWKS endpoint ({fetcher.calls} calls)')

    # Rotation actually resolving: the refetch after the floor picks up the new key.
    fetcher.keys = [GOOD, ROTATED]
    later = after + cf_access.JWKS_MIN_REFETCH_INTERVAL + 1
    case(cf_access.verify_token(unknown, fetcher=fetcher, now=later)['email'] == ALLOWED,
         'a rotated key was not picked up by the refetch')
    case(fetcher.calls == 3, f'rotation pickup took {fetcher.calls} total fetches, expected 3')


def test_jwks_failure_denies():
    configure()
    for label, fetcher in (
        ('raising fetcher', Fetcher(error=RuntimeError('connection refused'))),
        ('empty key set', Fetcher(keys=[])),
    ):
        case(denied_reason(sign(), fetcher) == 'jwks_unavailable',
             f'{label}: verification did not deny with jwks_unavailable')

    # A failure at refresh time denies too - no serving from a stale cache.
    fetcher = Fetcher()
    start = time.time()
    cf_access.verify_token(sign(), fetcher=fetcher, now=start)
    fetcher.error = RuntimeError('connection refused')
    case(denied_reason(sign(), fetcher, start + cf_access.JWKS_TTL + 1) == 'jwks_unavailable',
         'a failed refresh fell back to stale keys instead of denying')


class Sandbox:
    """Temp activity dir + a patched JWKS fetcher; both restored on exit."""

    def __init__(self, fetcher=None):
        self.fetcher = fetcher or Fetcher()

    def __enter__(self):
        self.previous_dir = activity.ACTIVITY_DIR
        self.previous_fetcher = cf_access._default_fetcher
        self.dir = tempfile.mkdtemp(prefix='nt-cfaccess-')
        activity.ACTIVITY_DIR = self.dir
        activity.reset_state()
        cf_access._default_fetcher = self.fetcher
        return self

    def __exit__(self, *exc):
        activity.ACTIVITY_DIR = self.previous_dir
        activity.reset_state()
        cf_access._default_fetcher = self.previous_fetcher
        shutil.rmtree(self.dir, ignore_errors=True)
        configure(team=None, aud=None)
        return False


def client():
    # /admin is registered on the admin role only, so these cases build the admin app.
    # The split itself is covered by app/tests/test_role_split.py.
    os.environ['NEXUSTRACE_ROLE'] = 'admin'
    app = create_app()
    app.config['WTF_CSRF_ENABLED'] = False
    return app.test_client()


def status(headers=None, cookies=None, method='get', **kwargs):
    test_client = client()
    for name, value in (cookies or {}).items():
        test_client.set_cookie(name, value, domain='localhost')
    return getattr(test_client, method)('/admin', headers=headers or {}, **kwargs).status_code


def test_admin_unconfigured_is_404():
    with Sandbox():
        configure(team=None, aud=None)
        case(status() == 404, 'an entirely unconfigured /admin did not 404')
        case(status(headers={'Cf-Access-Jwt-Assertion': sign()}) == 404,
             'an unconfigured /admin answered a request carrying an Access token')


def test_admin_token_mode_is_unchanged():
    with Sandbox():
        configure(team=None, aud=None, token='right-token')
        case(status(headers={'X-Admin-Token': 'right-token'}) == 200,
             'ADMIN_TOKEN mode stopped accepting the right token')
        case(status(headers={'X-Admin-Token': 'wrong-token'}) == 403,
             'ADMIN_TOKEN mode accepted the wrong token')
        case(status(method='post', data={'token': 'right-token'}) == 303,
             'the token sign-in form stopped working')


def test_admin_access_mode_accepts_a_verified_token():
    with Sandbox():
        configure(emails=f'other@example.com, {ALLOWED.upper()}')
        case(status(headers={'Cf-Access-Jwt-Assertion': sign()}) == 200,
             'a valid Access token was not accepted at /admin')
        case(status(cookies={cf_access.TOKEN_COOKIE: sign()}) == 200,
             'a valid Access token in the CF_Authorization cookie was not accepted')
        case(status(headers={'Cf-Access-Jwt-Assertion': sign(email='stranger@example.com')}) == 403,
             'a verified but non-allowlisted identity was let in')


def test_admin_access_mode_denies_bad_tokens():
    with Sandbox():
        configure(emails=ALLOWED)
        now = int(time.time())
        bad = {
            'no token at all': {},
            'expired': {'Cf-Access-Jwt-Assertion': sign(exp=now - 60, iat=now - 600)},
            'wrong signer': {'Cf-Access-Jwt-Assertion': sign(key=OTHER, kid=GOOD.kid)},
            'alg none': {'Cf-Access-Jwt-Assertion': sign_alg_none()},
            'hs256 confusion': {'Cf-Access-Jwt-Assertion': sign_hs256_with_public_key()},
            'garbage': {'Cf-Access-Jwt-Assertion': 'not-a-jwt'},
            'wrong aud': {'Cf-Access-Jwt-Assertion': sign(aud=['b' * 64])},
        }
        for label, headers in bad.items():
            case(status(headers=headers) == 403, f'/admin accepted a token that was {label}')


def test_admin_ignores_the_plaintext_header_in_access_mode():
    """The LAN bypass. Anything that can reach gunicorn directly can send this header."""
    with Sandbox():
        configure(emails=ALLOWED)
        forged = {'Cf-Access-Authenticated-User-Email': ALLOWED}
        case(status(headers=forged) == 403,
             'the plaintext Access e-mail header authorized /admin - the bypass is open')

        forged['Cf-Access-Jwt-Assertion'] = 'not-a-jwt'
        case(status(headers=forged) == 403,
             'a forged e-mail header rescued an invalid Access token')


def test_admin_access_mode_ignores_admin_token():
    with Sandbox():
        configure(token='right-token', emails=ALLOWED)
        case(status(headers={'X-Admin-Token': 'right-token'}) == 403,
             'ADMIN_TOKEN still worked while Access verification was enabled')
        case(status(method='post', data={'token': 'right-token'}) == 403,
             'the token sign-in form still worked while Access verification was enabled')
        case(status(headers={'Cf-Access-Jwt-Assertion': sign()}) == 200,
             'Access mode denied a valid token while ADMIN_TOKEN was also set')


def test_admin_access_mode_without_an_allowlist_denies():
    with Sandbox():
        configure(emails=None)
        case(status(headers={'Cf-Access-Jwt-Assertion': sign()}) == 403,
             'Access mode with an empty ADMIN_EMAILS admitted a verified identity')


def test_admin_jwks_failure_denies():
    with Sandbox(fetcher=Fetcher(error=RuntimeError('connection refused'))):
        configure(emails=ALLOWED)
        case(status(headers={'Cf-Access-Jwt-Assertion': sign()}) == 403,
             'an unreachable JWKS endpoint fell open at /admin')


TESTS = [
    test_valid_token,
    test_rejected_tokens,
    test_configuration_states,
    test_jwks_cache_is_reused,
    test_unknown_kid_refetches_once,
    test_jwks_failure_denies,
    test_admin_unconfigured_is_404,
    test_admin_token_mode_is_unchanged,
    test_admin_access_mode_accepts_a_verified_token,
    test_admin_access_mode_denies_bad_tokens,
    test_admin_ignores_the_plaintext_header_in_access_mode,
    test_admin_access_mode_ignores_admin_token,
    test_admin_access_mode_without_an_allowlist_denies,
    test_admin_jwks_failure_denies,
]


def main():
    for test in TESTS:
        try:
            test()
        except Exception as exc:  # noqa: BLE001 - an escaping exception IS a failure
            import traceback
            failures.append(f'{test.__name__} raised {exc!r}\n'
                            + ''.join(traceback.format_tb(exc.__traceback__)))
    configure(team=None, aud=None)
    cf_access.reset_cache()
    os.environ.pop('NEXUSTRACE_ROLE', None)

    if failures:
        print('FAIL:')
        for line in failures:
            print('  ' + line)
        sys.exit(1)
    print(f'PASS: {cases} cases')


if __name__ == '__main__':
    main()
