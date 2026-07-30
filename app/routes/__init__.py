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
from .admin_routes import admin_bp

def register_routes(app):
    """Register all route blueprints with the Flask application."""
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
    app.register_blueprint(admin_bp)

    register_cyberchef_routes(app)
    app.register_blueprint(cyberchef_api)