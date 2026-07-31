import logging
import os

from flask import Blueprint
from .home_routes import home_bp
from .ip_routes import ip_bp
from .domain_routes import domain_bp
from .file_routes import file_bp
from .health_routes import health_bp
from .hash_routes import hash_bp
from .event_routes import event_bp
from .azure_error_routes import azure_error_bp
from .cyberchef_routes import register_cyberchef_routes
from .cyberchef_api import cyberchef_api
from .user_agent_routes import user_agent_bp
from .enrichment_routes import enrichment_bp
from .scan_routes import scan_bp
from .email_routes import email_bp
from .submission_routes import submission_bp

logger = logging.getLogger(__name__)

ENV_ROLE = 'NEXUSTRACE_ROLE'
ROLE_PUBLIC = 'public'
ROLE_ADMIN = 'admin'
ROLES = (ROLE_PUBLIC, ROLE_ADMIN)

ADMIN_PREFIX = '/admin'


def resolve_role(env=None):
    """'public' (the default) or 'admin'. Raising on an unrecognised value rather than
    falling back is the security property: the public process is internet-facing through
    the Cloudflare Tunnel, and the only thing keeping the admin panel off it is that the
    blueprint is never registered, so a typo that quietly resolved to 'admin' would
    publish the panel again. Absent is the one safe default - it can only mean 'public'."""
    env = os.environ if env is None else env
    raw = (env.get(ENV_ROLE) or '').strip().lower()
    if not raw:
        return ROLE_PUBLIC
    if raw not in ROLES:
        raise ValueError(f'unknown {ENV_ROLE} {raw!r}; expected one of '
                         f'{", ".join(ROLES)}')
    return raw


def admin_rules(app):
    """Every rule in the built url_map under /admin. The invariant check in create_app()
    reads this, so "the admin surface" has one definition rather than a pattern repeated
    wherever something has to recognise it."""
    found = set()
    for rule in app.url_map.iter_rules():
        path = str(rule)
        if path == ADMIN_PREFIX or path.startswith(ADMIN_PREFIX + '/'):
            found.add(path)
    return sorted(found)


def register_routes(app):
    """Register the blueprints this process's role is allowed to serve."""
    role = resolve_role()
    app.config['NEXUSTRACE_ROLE'] = role

    app.register_blueprint(home_bp)

    app.register_blueprint(ip_bp, url_prefix='/api/ip')
    app.register_blueprint(domain_bp, url_prefix='/api/domain')
    app.register_blueprint(file_bp, url_prefix='/api/file')
    app.register_blueprint(health_bp, url_prefix='/api/health')
    app.register_blueprint(hash_bp, url_prefix='/api/hash')
    app.register_blueprint(enrichment_bp, url_prefix='/api/enrich')

    # These encode their full paths in the route decorators, so no url_prefix.
    app.register_blueprint(event_bp)
    app.register_blueprint(azure_error_bp)
    app.register_blueprint(user_agent_bp)
    app.register_blueprint(scan_bp)
    app.register_blueprint(email_bp)
    app.register_blueprint(submission_bp)

    if role == ROLE_ADMIN:
        # Imported inside the branch, not at module scope: on the public role the admin
        # module is never loaded, so /admin is absent from url_map rather than present
        # and guarded - no route to probe, no token to brute-force, no verification
        # logic that can be got wrong.
        #
        # The admin role also serves every public blueprint above, so it is a second copy
        # of the whole app: create_app()'s CSRFError handler redirects to
        # url_for('home.home'), so an expired admin login form would 500 without home_bp.
        from .admin_routes import admin_bp
        app.register_blueprint(admin_bp)

    register_cyberchef_routes(app)
    app.register_blueprint(cyberchef_api)

    logger.info('%s=%s: admin UI %s', ENV_ROLE, role,
                'registered' if role == ROLE_ADMIN else 'NOT registered')
