import os
import logging

# Configure logging
logger = logging.getLogger(__name__)

def setup_health_services(app):
    """Setup health check services."""
    pass  # Add any necessary setup code here

def check_health():
    """Liveness check: confirms the app process is up and able to serve requests.

    This is what container orchestrators / load balancers poll, so it must be fast and
    self-contained: NO external network calls, and it must NOT fail on optional config.
    All API keys are optional (the app degrades gracefully per service), so configured
    integrations are reported as informational diagnostics only - they never flip the
    status to unhealthy.
    """
    optional_keys = [
        'VPNAPI_KEY', 'IPINFO_TOKEN', 'SHODAN_KEY', 'ABUSEIPDB_KEY',
        'IP2WHOIS_KEY', 'VIRUSTOTAL_API_KEY', 'PROXYCHECK_KEY',
    ]
    return {
        'status': 'healthy',
        'configured_integrations': {key: bool(os.getenv(key)) for key in optional_keys},
    } 