from flask import Flask
from dotenv import load_dotenv
import os
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

load_dotenv()


def create_app():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = Flask(
        __name__,
        static_folder=os.path.join(project_root, 'static'),
        static_url_path='/static',
        template_folder=os.path.join(project_root, 'templates')
    )

    # Trust exactly one upstream hop (nginx). Without this, client IPs, HTTPS
    # detection, and external URL generation are wrong behind the proxy; harmless
    # in direct dev runs, which send no forwarded headers.
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

    secret_key = os.getenv('SECRET_KEY')
    if not secret_key or secret_key == 'your-secret-key-here':
        logger.warning(
            'SECRET_KEY is not set or is the default placeholder. '
            'Sessions will break on restart. Set SECRET_KEY in your .env file.'
        )
        secret_key = os.urandom(32).hex()
    app.config['SECRET_KEY'] = secret_key

    secure_cookies = os.getenv('SECURE_COOKIES', 'false').lower() == 'true'

    app.config['SESSION_COOKIE_SECURE'] = secure_cookies
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
    app.config['SESSION_REFRESH_EACH_REQUEST'] = True

    app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB max upload
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 31536000  # 1 year
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour

    from flask_wtf.csrf import CSRFProtect
    csrf = CSRFProtect(app)

    from flask_talisman import Talisman

    csp = {
        'default-src': "'self'",
        'script-src': [
            "'self'",
            "'unsafe-inline'",  # Required: the app uses inline <script> blocks across templates
            "'unsafe-eval'",  # Required for CyberChef
            "blob:",  # Required for CyberChef web workers
        ],
        'style-src': [
            "'self'",
            "'unsafe-inline'",  # Required: inline <style> blocks + style attributes
        ],
        'img-src': [
            "'self'",
            "data:",
            "blob:",  # Required for CyberChef image processing
            "https:",
        ],
        'font-src': [
            "'self'",
            "data:",  # fonts are now self-hosted under /static/fonts
        ],
        'connect-src': [
            "'self'",
            "blob:",  # Required for CyberChef
            "https://api.ipinfo.io",
            "https://api.abuseipdb.com",
            "https://api.shodan.io",
            "https://otx.alienvault.com",
            "https://vpnapi.io",
        ],
        'worker-src': ["'self'", "blob:"],  # Required for CyberChef web workers
        'child-src': ["'self'", "blob:"],  # Required for CyberChef workers
        'frame-ancestors': "'self'",  # Allow same-origin framing for embedded CyberChef
        'form-action': "'self'",
    }

    Talisman(
        app,
        force_https=False,  # Set to True in production with HTTPS
        strict_transport_security=False,
        content_security_policy=csp,
        # Deliberately NO nonce directive: a nonce in script-src makes browsers
        # IGNORE 'unsafe-inline', which would block this app's many inline
        # <script> blocks. Hardening path is external JS files, then nonces.
        referrer_policy='strict-origin-when-cross-origin',
        permissions_policy={
            'geolocation': '()',
            'microphone': '()',
            'camera': '()',
        },
        x_content_type_options=True,
        x_xss_protection=True,
        session_cookie_secure=secure_cookies,
        session_cookie_http_only=True,
    )

    from app.routes import register_routes
    register_routes(app)

    # The enrichment API authenticates with X-API-Key instead of CSRF.
    from app.routes.enrichment_routes import enrichment_bp
    csrf.exempt(enrichment_bp)

    from app.services import setup_services
    setup_services(app)

    from app.utils import setup_utils
    setup_utils(app)

    app.csrf = csrf

    # Request activity log. There is no authentication on the browser routes and the
    # deployment is publicly reachable through a Cloudflare Tunnel, so this is the only
    # record of who used the app and what they did. Imported and installed defensively:
    # visibility is worth having, but never at the cost of serving traffic.
    try:
        from app.utils import activity
        activity.install(app)
    except Exception:
        logger.exception('Activity logging is disabled: install failed')

    # Static files are served with a 1-year cache, so templates append
    # ?v={{ asset_v }}; the version changes on any CSS/JS edit and forces a fresh
    # fetch in both the browser and the service worker.
    @app.context_processor
    def inject_asset_version():
        bust_files = [
            os.path.join(project_root, 'static', 'css', 'tailwind.css'),
            os.path.join(project_root, 'static', 'css', 'styles.css'),
            os.path.join(project_root, 'static', 'css', 'app.css'),
            os.path.join(project_root, 'static', 'js', 'mobile.js'),
        ]
        try:
            version = str(int(max(os.path.getmtime(f) for f in bust_files if os.path.exists(f))))
        except (OSError, ValueError):
            version = '1'
        return {'asset_v': version}

    # Prevent HTML pages from being cached so CSRF tokens are never served stale
    @app.after_request
    def set_cache_control(response):
        if 'text/html' in response.content_type:
            response.cache_control.no_store = True
            response.cache_control.no_cache = True
            response.cache_control.private = True
        return response

    from flask_wtf.csrf import CSRFError
    from flask import redirect, url_for, flash

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        logger.warning('CSRF validation failed: %s', e.description)
        flash('Your session expired. Please try again.', 'warning')
        return redirect(url_for('home.home'), 303)

    return app
