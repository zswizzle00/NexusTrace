from .ip_service import setup_ip_services
from .domain_service import setup_domain_services
from .url_service import setup_url_services
from .file_service import setup_file_services
from .health_service import setup_health_services
from .cyberchef import setup_cyberchef

def setup_services(app):
    """Setup all services for the application."""
    setup_ip_services(app)
    setup_domain_services(app)
    setup_url_services(app)
    setup_file_services(app)
    setup_health_services(app)
    setup_cyberchef(app) 