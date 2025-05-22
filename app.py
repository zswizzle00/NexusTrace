from flask import Flask
from app.routes import register_routes
from app.services import setup_services
from app.utils import setup_utils
from app.services.cyberchef import setup_cyberchef

# Configure Flask app
app = Flask(__name__)
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutes
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# Register routes
register_routes(app)

# Setup services (API clients, cache, etc.)
setup_services(app)

# Setup CyberChef
setup_cyberchef(app)

# Setup utilities (logging, etc.)
setup_utils(app)

if __name__ == '__main__':
    app.run(debug=True) 