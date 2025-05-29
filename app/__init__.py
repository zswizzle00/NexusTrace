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
    root_dir = os.path.dirname(os.path.dirname(__file__))
    app = Flask(
        __name__,
        static_folder=os.path.join(root_dir, 'static'),
        static_url_path='/static',
        template_folder=os.path.join(root_dir, 'templates')
    )
    
    # Configure Flask app
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
    app.config['SESSION_REFRESH_EACH_REQUEST'] = True
    
    # Register blueprints
    from app.routes import register_routes
    register_routes(app)
    
    # Setup services
    from app.services import setup_services
    setup_services(app)
    
    # Setup utilities
    from app.utils import setup_utils
    setup_utils(app)
    
    return app
