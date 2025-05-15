from flask import Blueprint
from .home_routes import home_bp
from .ip_routes import ip_bp
from .domain_routes import domain_bp
from .url_routes import url_bp
from .file_routes import file_bp
from .health_routes import health_bp

def register_routes(app):
    """Register all route blueprints with the Flask application."""
    app.register_blueprint(home_bp)
    app.register_blueprint(ip_bp, url_prefix='/api/ip')
    app.register_blueprint(domain_bp, url_prefix='/api/domain')
    app.register_blueprint(url_bp, url_prefix='/api/url')
    app.register_blueprint(file_bp, url_prefix='/api/file')
    app.register_blueprint(health_bp, url_prefix='/api/health') 