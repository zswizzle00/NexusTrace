import os
import logging

logger = logging.getLogger(__name__)

def setup_health_services(app):
    """Setup health check services."""
    pass

def check_health():
    """Liveness check polled by orchestrators / load balancers.

    Must stay fast and self-contained: no external network calls, and no failing on
    optional config. Every API key is optional, so configured integrations are
    informational only and never flip the status to unhealthy.
    """
    optional_keys = [
        'VPNAPI_KEY', 'IPINFO_TOKEN', 'SHODAN_KEY', 'ABUSEIPDB_KEY',
        'IP2WHOIS_KEY', 'VIRUSTOTAL_API_KEY', 'PROXYCHECK_KEY',
    ]
    return {
        'status': 'healthy',
        'configured_integrations': {key: bool(os.getenv(key)) for key in optional_keys},
    } 