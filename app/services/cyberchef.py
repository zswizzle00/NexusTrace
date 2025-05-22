import os
from flask import send_from_directory, Blueprint

def setup_cyberchef(app):
    """
    Setup CyberChef integration with the Flask application.
    This will serve the CyberChef interface and handle its assets.
    """
    # Create a blueprint for CyberChef
    cyberchef_bp = Blueprint('cyberchef', __name__, url_prefix='/cyberchef')
    
    # Get the path to CyberChef files
    cyberchef_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), 
                                'CyberChef_v10.19.4')
    
    @cyberchef_bp.route('/')
    def serve_cyberchef():
        """Serve the main CyberChef interface"""
        return send_from_directory(cyberchef_path, 'CyberChef_v10.19.4.html')
    
    @cyberchef_bp.route('/assets/<path:filename>')
    def serve_assets(filename):
        """Serve CyberChef assets"""
        return send_from_directory(os.path.join(cyberchef_path, 'assets'), filename)
    
    @cyberchef_bp.route('/images/<path:filename>')
    def serve_images(filename):
        """Serve CyberChef images"""
        return send_from_directory(os.path.join(cyberchef_path, 'images'), filename)
    
    @cyberchef_bp.route('/modules/<path:filename>')
    def serve_modules(filename):
        """Serve CyberChef modules"""
        return send_from_directory(os.path.join(cyberchef_path, 'modules'), filename)
    
    # Register the blueprint
    app.register_blueprint(cyberchef_bp) 