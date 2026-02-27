from flask import Flask
from dotenv import load_dotenv
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()


def create_app():
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    app = Flask(
        __name__,
        static_folder=os.path.join(project_root, 'static'),
        static_url_path='/static',
        template_folder=os.path.join(project_root, 'templates')
    )

    # Secret key for session and CSRF (required)
    secret_key = os.getenv('SECRET_KEY')
    if not secret_key or secret_key == 'your-secret-key-here':
        logger.warning(
            'SECRET_KEY is not set or is the default placeholder. '
            'Sessions will break on restart. Set SECRET_KEY in your .env file.'
        )
        # Fall back to a per-process random key — sessions won't survive restarts
        secret_key = os.urandom(32).hex()
    app.config['SECRET_KEY'] = secret_key

    # Only mark cookies as secure when running behind HTTPS (set SECURE_COOKIES=true in .env)
    secure_cookies = os.getenv('SECURE_COOKIES', 'false').lower() == 'true'

    # Configure Flask app
    app.config['SESSION_COOKIE_SECURE'] = secure_cookies
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
    app.config['SESSION_REFRESH_EACH_REQUEST'] = True

    # File upload security
    app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB max upload

    # Configure static file serving
    app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 31536000  # 1 year

    # CSRF Protection
    app.config['WTF_CSRF_ENABLED'] = True
    app.config['WTF_CSRF_TIME_LIMIT'] = 3600  # 1 hour

    # Initialize CSRF protection
    from flask_wtf.csrf import CSRFProtect
    csrf = CSRFProtect(app)

    # Security Headers via Flask-Talisman
    from flask_talisman import Talisman

    # Content Security Policy
    csp = {
        'default-src': "'self'",
        'script-src': [
            "'self'",
            "'unsafe-inline'",  # Required for some inline scripts
            "'unsafe-eval'",  # Required for CyberChef and Tailwind
            "blob:",  # Required for CyberChef web workers
            "https://cdn.tailwindcss.com",
            "https://cdnjs.cloudflare.com",
        ],
        'style-src': [
            "'self'",
            "'unsafe-inline'",  # Required for inline styles
            "https://fonts.googleapis.com",
            "https://cdn.tailwindcss.com",
        ],
        'img-src': [
            "'self'",
            "data:",
            "blob:",  # Required for CyberChef image processing
            "https:",
        ],
        'font-src': [
            "'self'",
            "data:",
            "https://fonts.gstatic.com",
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

    # Initialize Talisman with security headers
    Talisman(
        app,
        force_https=False,  # Set to True in production with HTTPS
        strict_transport_security=False,
        content_security_policy=csp,
        content_security_policy_nonce_in=['script-src'],
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

    # Register blueprints
    from app.routes import register_routes
    register_routes(app)

    # CSRF-exempt the enrichment API (uses X-API-Key auth instead)
    from app.routes.enrichment_routes import enrichment_bp
    csrf.exempt(enrichment_bp)

    # Setup services
    from app.services import setup_services
    setup_services(app)

    # Setup utilities
    from app.utils import setup_utils
    setup_utils(app)

    # Store CSRF instance for use in templates
    app.csrf = csrf

    # Prevent HTML pages from being cached so CSRF tokens are never served stale
    @app.after_request
    def set_cache_control(response):
        if 'text/html' in response.content_type:
            response.cache_control.no_store = True
            response.cache_control.no_cache = True
            response.cache_control.private = True
        return response

    # Graceful CSRF error handling — redirect to homepage with a user-friendly message
    from flask_wtf.csrf import CSRFError
    from flask import redirect, url_for, flash

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        logger.warning('CSRF validation failed: %s', e.description)
        flash('Your session expired. Please try again.', 'warning')
        return redirect(url_for('home.home'), 303)

    return app
