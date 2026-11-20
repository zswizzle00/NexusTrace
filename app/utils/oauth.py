"""Sign-in with GitHub or Google (OAuth 2.0 authorization code flow).

Written against `requests` rather than an OAuth library because the flow is three fixed
HTTPS calls per provider and the app already depends on `requests`. Only the provider's
stable user ID and a display name are read: GitHub is asked for no scopes at all (public
profile only), and Google for `openid profile`, so no e-mail address is ever requested.

Every request goes to a fixed provider host, never to a URL derived from user input.
`transport=` is the test seam, shaped like the `requests` module.
"""
import base64
import hashlib
import logging
import os
import secrets
from urllib.parse import urlencode

import requests

from .constants import TIMEOUT_MEDIUM

logger = logging.getLogger(__name__)

PROVIDERS = {
    'github': {
        'label': 'GitHub',
        'id_env': 'GITHUB_CLIENT_ID',
        'secret_env': 'GITHUB_CLIENT_SECRET',
        'authorize_url': 'https://github.com/login/oauth/authorize',
        'token_url': 'https://github.com/login/oauth/access_token',
        'user_url': 'https://api.github.com/user',
        'scope': '',
        'pkce': False,
    },
    'google': {
        'label': 'Google',
        'id_env': 'GOOGLE_CLIENT_ID',
        'secret_env': 'GOOGLE_CLIENT_SECRET',
        'authorize_url': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_url': 'https://oauth2.googleapis.com/token',
        'user_url': 'https://openidconnect.googleapis.com/v1/userinfo',
        'scope': 'openid profile',
        'pkce': True,
    },
}

REDIRECT_BASE_ENV = 'OAUTH_REDIRECT_BASE'


class OAuthError(Exception):
    """Sign-in failed. The message is safe to show; details go to the log."""


def _credentials(provider):
    spec = PROVIDERS.get(provider)
    if spec is None:
        return None
    client_id = (os.environ.get(spec['id_env']) or '').strip()
    client_secret = (os.environ.get(spec['secret_env']) or '').strip()
    if not client_id or not client_secret:
        return None
    return client_id, client_secret


def configured_providers():
    """[(name, label)] for each provider with both a client ID and a secret."""
    return [(name, spec['label']) for name, spec in PROVIDERS.items() if _credentials(name)]


def redirect_base():
    """The public origin the providers redirect back to, e.g. https://nexustrace.example.

    Set explicitly because the app sits behind cloudflared and nginx, which talk plain
    HTTP to it: a URL built from the request would say http://, and the providers reject
    a redirect URI that differs from the registered one by so much as the scheme.
    """
    return (os.environ.get(REDIRECT_BASE_ENV) or '').strip().rstrip('/')


def _pkce_challenge(verifier):
    digest = hashlib.sha256(verifier.encode('ascii')).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b'=').decode('ascii')


def begin(provider, redirect_uri):
    """(authorize URL, pending) where `pending` must be kept in the session and handed
    back to complete(). Raises OAuthError for an unconfigured provider."""
    credentials = _credentials(provider)
    if credentials is None:
        raise OAuthError('That sign-in option is not available.')
    spec = PROVIDERS[provider]
    pending = {'provider': provider, 'state': secrets.token_urlsafe(32)}
    params = {
        'client_id': credentials[0],
        'redirect_uri': redirect_uri,
        'state': pending['state'],
        'response_type': 'code',
    }
    if spec['scope']:
        params['scope'] = spec['scope']
    if spec['pkce']:
        pending['verifier'] = secrets.token_urlsafe(64)
        params['code_challenge'] = _pkce_challenge(pending['verifier'])
        params['code_challenge_method'] = 'S256'
    if provider == 'google':
        params['prompt'] = 'select_account'
    return f"{spec['authorize_url']}?{urlencode(params)}", pending


def complete(provider, args, pending, redirect_uri, transport=None):
    """{'subject', 'login'} for the identity that just signed in.

    `args` is the callback's query string and `pending` what begin() returned. The state
    comparison is what stops a forged callback from signing the visitor into someone
    else's account.
    """
    http = transport or requests
    if not pending or pending.get('provider') != provider:
        raise OAuthError('That sign-in attempt expired. Please try again.')
    if args.get('error'):
        raise OAuthError('Sign-in was cancelled.')
    state = args.get('state') or ''
    if not secrets.compare_digest(state, pending.get('state') or ''):
        raise OAuthError('That sign-in attempt expired. Please try again.')
    code = args.get('code')
    if not code:
        raise OAuthError('The provider did not return a sign-in code.')

    credentials = _credentials(provider)
    if credentials is None:
        raise OAuthError('That sign-in option is not available.')
    spec = PROVIDERS[provider]
    form = {
        'client_id': credentials[0],
        'client_secret': credentials[1],
        'code': code,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code',
    }
    if spec['pkce']:
        form['code_verifier'] = pending.get('verifier') or ''

    try:
        token_response = http.post(spec['token_url'], data=form,
                                   headers={'Accept': 'application/json'},
                                   timeout=TIMEOUT_MEDIUM)
        token = token_response.json() if token_response.ok else {}
        if not isinstance(token, dict):
            token = {}
        access_token = token.get('access_token')
        if not access_token:
            logger.warning('%s token exchange failed: HTTP %s %s', provider,
                           token_response.status_code, token.get('error'))
            raise OAuthError('Sign-in failed. Please try again.')

        user_response = http.get(spec['user_url'], timeout=TIMEOUT_MEDIUM, headers={
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json',
        })
        if not user_response.ok:
            logger.warning('%s user lookup failed: HTTP %s', provider,
                           user_response.status_code)
            raise OAuthError('Sign-in failed. Please try again.')
        profile = user_response.json()
        if not isinstance(profile, dict):
            raise OAuthError('Sign-in failed. Please try again.')
    except requests.RequestException as exc:
        logger.warning('%s sign-in request failed: %s', provider, type(exc).__name__)
        raise OAuthError('Could not reach the sign-in provider. Please try again.') from None
    except ValueError:
        logger.warning('%s returned a response that is not JSON', provider)
        raise OAuthError('Sign-in failed. Please try again.') from None

    if provider == 'github':
        subject, login = profile.get('id'), profile.get('login')
    else:
        subject, login = profile.get('sub'), profile.get('name')
    if subject in (None, ''):
        raise OAuthError('Sign-in failed. Please try again.')
    return {'subject': str(subject), 'login': str(login or f'{spec["label"]} user')[:100]}
