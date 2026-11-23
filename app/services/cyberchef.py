import os
from flask import send_from_directory, Blueprint

# CyberChef needs eval and blob: workers, which the rest of the app's policy forbids.
# Set per view through Talisman: a plain after_request header is overwritten by
# Talisman's own, which runs later.
CYBERCHEF_CSP = {
    'default-src': "'self'",
    'script-src': ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'blob:'],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", 'data:', 'blob:', 'https:'],
    'font-src': ["'self'", 'data:'],
    'connect-src': ["'self'", 'blob:'],
    'worker-src': ["'self'", 'blob:'],
    'child-src': ["'self'", 'blob:'],
    'object-src': "'none'",
    'base-uri': "'self'",
    'frame-ancestors': "'self'",
    'form-action': "'self'",
}


def setup_cyberchef(app):
    own_policy = app.talisman(content_security_policy=CYBERCHEF_CSP)
    cyberchef_bp = Blueprint('cyberchef', __name__, url_prefix='/cyberchef_app')

    cyberchef_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
                                'CyberChef_v11.6.0')

    @cyberchef_bp.route('/')
    @own_policy
    def serve_cyberchef():
        return send_from_directory(cyberchef_path, 'CyberChef_v11.6.0.html')
    
    @cyberchef_bp.route('/assets/<path:filename>')
    @own_policy
    def serve_assets(filename):
        return send_from_directory(os.path.join(cyberchef_path, 'assets'), filename)
    
    @cyberchef_bp.route('/images/<path:filename>')
    @own_policy
    def serve_images(filename):
        return send_from_directory(os.path.join(cyberchef_path, 'images'), filename)
    
    @cyberchef_bp.route('/modules/<path:filename>')
    @own_policy
    def serve_modules(filename):
        return send_from_directory(os.path.join(cyberchef_path, 'modules'), filename)

    app.register_blueprint(cyberchef_bp)