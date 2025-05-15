import os
import logging
import requests
import socket

# Configure logging
logger = logging.getLogger(__name__)

def setup_health_services(app):
    """Setup health check services."""
    pass  # Add any necessary setup code here

def get_server_ip():
    """Get the server's IP address."""
    try:
        # Try to get public IP
        response = requests.get('https://api.ipify.org?format=json', timeout=5)
        if response.status_code == 200:
            return response.json()['ip']
    except Exception as e:
        logger.warning(f"Could not get public IP: {str(e)}")
    
    try:
        # Fallback to local IP
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        return local_ip
    except Exception as e:
        logger.error(f"Could not get local IP: {str(e)}")
        return "127.0.0.1"

def check_health():
    """Perform health checks for the application."""
    health_status = {
        'status': 'healthy',
        'checks': {
            'server_ip': False,
            'api_keys': False,
            'database': False
        }
    }
    
    try:
        # Check server IP
        server_ip = get_server_ip()
        if server_ip and server_ip != "127.0.0.1":
            health_status['checks']['server_ip'] = True
        
        # Check essential API keys
        required_keys = ['VPNAPI_KEY', 'IPINFO_TOKEN', 'SHODAN_KEY']
        missing_keys = [key for key in required_keys if not os.getenv(key)]
        if not missing_keys:
            health_status['checks']['api_keys'] = True
        
        return health_status
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        health_status['status'] = 'unhealthy'
        health_status['error'] = str(e)
        return health_status 